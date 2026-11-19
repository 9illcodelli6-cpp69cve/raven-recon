"""GOLDEN / characterization tests — egress security funnel (Wave 3 oracle).

These lock the CURRENT, verified behaviour of the single outbound funnel
`server.do_send`/`_send_in_context` (+ `_pick_public_ip` / `_Pinned*`) BEFORE the
Wave 3 refactor migrates it verbatim into a `SenderService`. They are the
regression oracle for RUNTIME_ARCHITECTURE.md §10 / CANONICAL_ARCHITECTURE §8
risks 2 & 3 (egress/transport regression). Nothing here may change when the code
merely MOVES.

Locked invariants (the tripwires a refactor must not trip):
  * scope allow vs deny, enforced BEFORE any DNS resolution;
  * resolve-then-pin SSRF/DNS-rebind guard (`_pick_public_ip`), enforced BEFORE
    the scheduler admission gate;
  * caller request headers stripped of framing/credential headers; the forced
    workspace search headers + User-Agent injected and WINNING over caller values;
  * accept-encoding=identity / connection=close forced;
  * redirects never auto-followed (the 3xx is surfaced);
  * every real send passes through SCHEDULER.admit_request (admission gate),
    and a fired Emergency Stop fails the send closed.

All targets are loopback/mock — no external host is ever contacted.

Run:  python -m pytest tests/test_golden_egress.py -q
"""
import json
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from raven.api import server
from raven.scope import Scope

REAL_GETADDRINFO = socket.getaddrinfo


def fake_getaddrinfo(addrs):
    """A getaddrinfo stub resolving every host to the given address list."""
    def _stub(host, port, *a, **k):
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                 socket.SOCK_STREAM, 6, "", (ip, port or 0)) for ip in addrs]
    return _stub


class _EchoHTTP:
    """Loopback target that echoes the request headers it received, as JSON."""
    class _H(BaseHTTPRequestHandler):
        def _echo(self):
            received = {k.lower(): v for k, v in self.headers.items()}
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "/secret")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/secret":
                body = b"SECRET-DATA"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = json.dumps(received).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _echo
        do_POST = _echo

        def log_message(self, *a):
            pass

    def __enter__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


class GoldenEgressBase(unittest.TestCase):
    def setUp(self):
        self._saved_state = dict(server.STATE)

    def tearDown(self):
        socket.getaddrinfo = REAL_GETADDRINFO
        # restore any admit_request shadow an individual test installed
        try:
            del server.SCHEDULER.admit_request
        except AttributeError:
            pass
        try:
            server.SCHEDULER.clear_stop()
        except Exception:
            pass
        server.STATE.clear()
        server.STATE.update(self._saved_state)


class ScopeGate(GoldenEgressBase):
    def test_in_scope_url_is_allowed_and_reaches_loopback(self):
        with _EchoHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/"})
            self.assertTrue(r.get("ok"), r)
            self.assertEqual(r["status"], 200)

    def test_out_of_scope_url_is_denied_before_any_dns(self):
        # Scope rejection MUST precede resolution: the DNS spy must never fire.
        calls = []
        socket.getaddrinfo = lambda *a, **k: calls.append(a) or REAL_GETADDRINFO(*a, **k)
        server.STATE["scope"] = Scope(include=["example.com"], exclude=[], ports=[80, 443])
        r = server.do_send({"method": "GET", "url": "https://out-of-scope.test/"})
        self.assertTrue(r.get("blocked"))
        self.assertEqual(calls, [], "DNS was resolved before the scope check")


class ResolveThenPin(GoldenEgressBase):
    """The DNS-rebind IP-pin guard: resolve, reject any non-public address, pin."""

    def test_rebind_to_loopback_blocked(self):
        server.STATE["scope"] = Scope(include=["evil.test"], exclude=[], ports=[80, 443])
        server.STATE["allow_private"] = False
        socket.getaddrinfo = fake_getaddrinfo(["127.0.0.1"])
        r = server.do_send({"method": "GET", "url": "http://evil.test/"})
        self.assertTrue(r.get("blocked"))
        self.assertIn("Non-public", r.get("error", ""))

    def test_rebind_to_metadata_ip_blocked(self):
        server.STATE["scope"] = Scope(include=["evil.test"], exclude=[], ports=[80, 443])
        server.STATE["allow_private"] = False
        socket.getaddrinfo = fake_getaddrinfo(["169.254.169.254"])
        self.assertTrue(server.do_send({"method": "GET", "url": "http://evil.test/"}).get("blocked"))

    def test_ipv4_mapped_v6_loopback_blocked(self):
        server.STATE["scope"] = Scope(include=["evil.test"], exclude=[], ports=[80, 443])
        server.STATE["allow_private"] = False
        socket.getaddrinfo = fake_getaddrinfo(["::ffff:127.0.0.1"])
        self.assertTrue(server.do_send({"method": "GET", "url": "http://evil.test/"}).get("blocked"))

    def test_any_non_public_in_resolved_set_blocks(self):
        server.STATE["scope"] = Scope(include=["evil.test"], exclude=[], ports=[80, 443])
        server.STATE["allow_private"] = False
        socket.getaddrinfo = fake_getaddrinfo(["93.184.216.34", "127.0.0.1"])
        self.assertTrue(server.do_send({"method": "GET", "url": "http://evil.test/"}).get("blocked"))

    def test_pin_connects_to_resolved_ip_not_the_name(self):
        # Host resolves (via the stub) to loopback; allow_private lets it through the
        # public check; the pinned connection must then reach the loopback echo server.
        with _EchoHTTP() as srv:
            server.STATE["scope"] = Scope(include=["pinned.test"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            socket.getaddrinfo = fake_getaddrinfo(["127.0.0.1"])
            r = server.do_send({"method": "GET", "url": f"http://pinned.test:{srv.port}/"})
            self.assertTrue(r.get("ok"), r)
            self.assertEqual(r["status"], 200)

    def test_pin_is_checked_before_admission(self):
        # A non-public resolved address must be rejected BEFORE SCHEDULER.admit_request.
        admit_calls = []
        server.SCHEDULER.admit_request = lambda *a, **k: admit_calls.append((a, k))
        server.STATE["scope"] = Scope(include=["evil.test"], exclude=[], ports=[80, 443])
        server.STATE["allow_private"] = False
        socket.getaddrinfo = fake_getaddrinfo(["10.0.0.1"])
        r = server.do_send({"method": "GET", "url": "http://evil.test/"})
        self.assertTrue(r.get("blocked"))
        self.assertEqual(admit_calls, [], "admission ran before the SSRF pin check")


class HeaderHandling(GoldenEgressBase):
    SENTINEL_UA = "RAVEN-GOLDEN-UA/1.0"

    def _send_through_echo(self, payload_headers):
        with _EchoHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            server.STATE["search_headers"] = {"X-Request-Purpose": "Research"}
            server.STATE["user_agent"] = self.SENTINEL_UA
            r = server.do_send({"method": "GET",
                                "url": f"http://127.0.0.1:{srv.port}/",
                                "headers": payload_headers})
            self.assertTrue(r.get("ok"), r)
            return json.loads(r["body"])

    def test_forced_search_header_and_ua_win_over_caller(self):
        received = self._send_through_echo({
            "X-Request-Purpose": "attacker-supplied",   # must be overwritten
            "User-Agent": "caller-ua",                   # must be overwritten
            "X-Custom": "kept",                          # benign passthrough
        })
        self.assertEqual(received.get("x-request-purpose"), "Research")
        self.assertEqual(received.get("user-agent"), self.SENTINEL_UA)
        self.assertEqual(received.get("x-custom"), "kept")

    def test_framing_and_credential_headers_are_stripped(self):
        received = self._send_through_echo({
            "X-RAVEN-Token": "leak-me",
            "Proxy-Authorization": "Basic Zm9v",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
        })
        self.assertNotIn("x-raven-token", received)
        self.assertNotIn("proxy-authorization", received)
        self.assertNotIn("transfer-encoding", received)
        # Connection is forced to close (caller's keep-alive is discarded).
        self.assertEqual(received.get("connection"), "close")
        # Host is the real pinned target, never a caller-smuggled value.
        self.assertNotIn("evil", received.get("host", ""))

    def test_accept_encoding_forced_identity(self):
        received = self._send_through_echo({})
        self.assertEqual(received.get("accept-encoding"), "identity")


class RedirectAndAdmission(GoldenEgressBase):
    def test_redirects_are_not_followed(self):
        with _EchoHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/redir"})
            self.assertTrue(r.get("ok"))
            self.assertEqual(r["status"], 302)            # the 3xx is surfaced...
            self.assertNotIn("SECRET-DATA", r.get("body", ""))  # ...never auto-followed

    def test_send_goes_through_admission_gate(self):
        admit_calls = []
        real = server.SCHEDULER.admit_request

        def spy(workspace_key, host, *a, **k):
            admit_calls.append(host)
            return real(workspace_key, host, *a, **k)

        server.SCHEDULER.admit_request = spy
        with _EchoHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/"})
            self.assertTrue(r.get("ok"), r)
        self.assertEqual(admit_calls, ["127.0.0.1"])

    def test_emergency_stop_fails_the_send_closed(self):
        with _EchoHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            server.SCHEDULER.emergency_stop()
            try:
                r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/"})
            finally:
                server.SCHEDULER.clear_stop()
            self.assertTrue(r.get("blocked"))
            self.assertNotIn("ok", r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
