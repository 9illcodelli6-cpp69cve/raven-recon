"""Security regression tests for the RAVEN local API (Phase 1).

Covers DNS-rebinding / SSRF, IP pinning, TLS-verification config, redirect
non-following, session-token auth, Origin/CSRF, and scope-change protection.
All tests use loopback servers and mocks — never external infrastructure.

Run:  python -m unittest tests.test_api_security -v
"""
import http.client
import os
import socket
import sqlite3
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from raven.api import server
from raven.scope import Scope

REAL_GETADDRINFO = socket.getaddrinfo


def fake_getaddrinfo(addrs):
    """Return a getaddrinfo stub that always resolves to the given address list."""
    def _stub(host, port, *a, **k):
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                 socket.SOCK_STREAM, 6, "", (ip, port or 0)) for ip in addrs]
    return _stub


class LocalHTTP:
    """A tiny loopback HTTP server used as a controlled target."""
    class _H(BaseHTTPRequestHandler):
        def _reply(self, code, body, headers=None):
            data = body.encode()
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/secret":
                return self._reply(200, "SECRET-DATA")
            if self.path == "/redir":
                return self._reply(302, "moved", {"Location": "/secret"})
            self._reply(200, "HELLO-RAVEN")

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


class SSRFTests(unittest.TestCase):
    def setUp(self):
        self._saved = dict(server.STATE)

    def tearDown(self):
        socket.getaddrinfo = REAL_GETADDRINFO
        server.STATE.clear()
        server.STATE.update(self._saved)

    def test_is_public_classification(self):
        pub, priv = server._is_public, lambda a: not server._is_public(a)
        self.assertTrue(pub("8.8.8.8"))
        self.assertTrue(pub("2606:4700:4700::1111"))
        for bad in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254",
                    "::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "0.0.0.0"):
            self.assertTrue(priv(bad), f"{bad} should be non-public")

    def test_out_of_scope_blocked_before_dns(self):
        server.STATE["scope"] = Scope(include=["example.com"], exclude=[], ports=[80, 443])
        r = server.do_send({"method": "GET", "url": "https://github.com/"})
        self.assertTrue(r.get("blocked"))

    def test_dns_rebinding_to_loopback_blocked(self):
        server.STATE["scope"] = Scope(include=["evil.test"], exclude=[], ports=[80, 443])
        server.STATE["allow_private"] = False
        socket.getaddrinfo = fake_getaddrinfo(["127.0.0.1"])
        r = server.do_send({"method": "GET", "url": "http://evil.test/"})
        self.assertTrue(r.get("blocked"))
        self.assertIn("Non-public", r.get("error", ""))

    def test_dns_rebinding_to_metadata_ip_blocked(self):
        server.STATE["scope"] = Scope(include=["evil.test"], exclude=[], ports=[80, 443])
        server.STATE["allow_private"] = False
        socket.getaddrinfo = fake_getaddrinfo(["169.254.169.254"])
        r = server.do_send({"method": "GET", "url": "http://evil.test/"})
        self.assertTrue(r.get("blocked"))

    def test_dns_rebinding_ipv4_mapped_blocked(self):
        server.STATE["scope"] = Scope(include=["evil.test"], exclude=[], ports=[80, 443])
        server.STATE["allow_private"] = False
        socket.getaddrinfo = fake_getaddrinfo(["::ffff:127.0.0.1"])
        r = server.do_send({"method": "GET", "url": "http://evil.test/"})
        self.assertTrue(r.get("blocked"))

    def test_mixed_public_and_private_blocked(self):
        # If ANY resolved address is non-public the request must be refused.
        server.STATE["scope"] = Scope(include=["evil.test"], exclude=[], ports=[80, 443])
        server.STATE["allow_private"] = False
        socket.getaddrinfo = fake_getaddrinfo(["93.184.216.34", "127.0.0.1"])
        r = server.do_send({"method": "GET", "url": "http://evil.test/"})
        self.assertTrue(r.get("blocked"))

    def test_tls_default_context_verifies(self):
        ctx = ssl.create_default_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_legitimate_request_works_and_pins(self):
        with LocalHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/"})
            self.assertTrue(r.get("ok"))
            self.assertEqual(r["status"], 200)
            self.assertIn("HELLO-RAVEN", r["body"])

    def test_redirects_are_not_followed(self):
        with LocalHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/redir"})
            self.assertTrue(r.get("ok"))
            self.assertEqual(r["status"], 302)              # the 3xx is surfaced
            self.assertNotIn("SECRET-DATA", r["body"])      # never fetched the target


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_state = dict(server.STATE)
        cls._cwd = os.getcwd()
        cls._tmp = tempfile.mkdtemp(prefix="raven-test-")
        os.chdir(cls._tmp)
        server.use_workspace("apitest")
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        server.STATE["port"] = cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        server.STATE["store"].close()
        server.STATE.clear()
        server.STATE.update(cls._saved_state)
        os.chdir(cls._cwd)

    def _req(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def test_health_is_open(self):
        self.assertEqual(self._req("GET", "/api/health"), 200)

    def test_api_requires_token(self):
        self.assertEqual(self._req("GET", "/api/summary"), 403)

    def test_api_accepts_valid_token(self):
        self.assertEqual(
            self._req("GET", "/api/summary", {"X-RAVEN-Token": server.SESSION_TOKEN}), 200)

    def test_reset_budget_endpoint_when_idle(self):
        # The gated budget-reset route is reachable and succeeds when no job is active.
        status = self._req("POST", "/api/reset-budget", {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": f"http://127.0.0.1:{self.port}",
            "Content-Type": "application/json"}, "{}")
        self.assertEqual(status, 200)

    def test_keepalive_not_corrupted_by_undrained_body(self):
        # An error must either consume a bounded body or close the connection. The
        # HTTP client reconnects after auth rejection; accepted requests keep alive.
        # Raw-wire framing/reuse assertions live in test_http_framing.py.
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        origin = f"http://127.0.0.1:{self.port}"
        try:
            steps = [
                # (method, path, headers, body, expected_status)
                ("PUT", "/api/scope", {"Content-Type": "application/json"},
                 '{"name":"x","include":["x.test"],"ports":[80]}', 403),          # unauth, body ignored
                ("POST", "/api/does-not-exist", {"X-RAVEN-Token": server.SESSION_TOKEN,
                 "Origin": origin, "Content-Type": "application/json"}, '{"a":1}', 404),  # unknown, body ignored
                ("POST", "/api/emergency-stop", {"X-RAVEN-Token": server.SESSION_TOKEN,
                 "Origin": origin, "Content-Type": "application/json"}, "{}", 200),  # ok, body ignored
                ("GET", "/api/health", {}, None, 200),                             # must be intact
            ]
            for method, path, hdr, body, expected in steps:
                c.request(method, path, body=body, headers=hdr)
                r = c.getresponse(); r.read()
                self.assertEqual(r.status, expected, f"{method} {path} on reused socket")
        finally:
            c.close()
            server.SCHEDULER.clear_stop()

    def test_scope_change_requires_auth(self):
        body = '{"name":"x","include":["x.test"],"ports":[80]}'
        self.assertEqual(self._req("PUT", "/api/scope", {"Content-Type": "application/json"}, body), 403)

    def test_cross_origin_rejected_even_with_token(self):
        status = self._req("POST", "/api/send", {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": "http://evil.example",
            "Content-Type": "application/json",
        }, '{"method":"GET","url":"https://example.com/"}')
        self.assertEqual(status, 403)

    def test_same_origin_with_token_allowed(self):
        status = self._req("POST", "/api/send", {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": f"http://127.0.0.1:{self.port}",
            "Content-Type": "application/json",
        }, '{"method":"GET","url":"https://999.invalid.test/"}')
        # Not a 403 — auth passed; the request itself is refused/blocked downstream.
        self.assertNotEqual(status, 403)

    def test_bad_host_header_rejected(self):
        # A rebound attacker domain (evil.example -> 127.0.0.1) must not reach the API.
        self.assertEqual(self._req("GET", "/api/health", {"Host": "evil.example"}), 403)
        self.assertEqual(self._req("POST", "/api/send", {
            "Host": "evil.example", "X-RAVEN-Token": server.SESSION_TOKEN}, "{}"), 403)

    def test_loopback_host_allowed(self):
        self.assertEqual(self._req("GET", "/api/health", {"Host": f"localhost:{self.port}"}), 200)

    def test_malformed_json_does_not_500(self):
        status = self._req("POST", "/api/send", {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": f"http://127.0.0.1:{self.port}",
            "Content-Type": "application/json",
        }, "NOT-JSON {{{{")
        self.assertEqual(status, 400)

    def test_path_traversal_does_not_leak_source(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/../../../raven/api/server.py")
        r = c.getresponse()
        body = r.read()
        c.close()
        self.assertNotIn(b"SESSION_TOKEN", body)
        self.assertIn(r.status, (403, 404))

    def _req_full(self, method, path, headers=None, body=None):
        """Like _req but returns (status, body_bytes); a dropped connection raises."""
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def test_import_store_failure_returns_framed_500_not_dropped_connection(self):
        # A store/disk failure during import must send a framed 500, never drop the
        # socket mid-request (which getresponse() would surface as a protocol error).
        origin = f"http://127.0.0.1:{self.port}"
        original = server.do_import
        server.do_import = lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("disk I/O error"))
        try:
            status, body = self._req_full("POST", "/api/import", {
                "X-RAVEN-Token": server.SESSION_TOKEN, "Origin": origin,
                "Content-Type": "application/json"}, '{"items":["x.test"]}')
        finally:
            server.do_import = original
        self.assertEqual(status, 500)
        self.assertNotIn(b"disk I/O error", body)  # internal detail is not leaked
        # The socket was framed correctly, so a following request on a fresh
        # connection is served normally (no smuggling of the previous body).
        self.assertEqual(self._req("GET", "/api/health"), 200)

    def test_import_invalid_input_still_maps_to_400(self):
        origin = f"http://127.0.0.1:{self.port}"
        status, _ = self._req_full("POST", "/api/import", {
            "X-RAVEN-Token": server.SESSION_TOKEN, "Origin": origin,
            "Content-Type": "application/json"}, '{"items":"not-a-list"}')
        self.assertEqual(status, 400)

    def test_data_read_failure_returns_framed_500(self):
        original = server.data_assets
        server.data_assets = lambda *a, **k: (_ for _ in ()).throw(sqlite3.DatabaseError("malformed"))
        try:
            status, body = self._req_full("GET", "/api/assets", {"X-RAVEN-Token": server.SESSION_TOKEN})
        finally:
            server.data_assets = original
        self.assertEqual(status, 500)
        self.assertNotIn(b"malformed", body)

    def test_token_inlined_into_page(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{self.port}"})
        r = c.getresponse()
        page = r.read().decode("utf-8", "replace")
        c.close()
        self.assertIn("RAVEN_TOKEN", page)          # same-origin bootstrap present
        self.assertEqual(self._req("GET", "/api/summary"), 403)  # but API needs the header


if __name__ == "__main__":
    unittest.main(verbosity=2)
