"""Acceptance tests for the V4 identity/admission unification directive.

Proves, against a REAL local receiving HTTP server (never just grepping source for
strings) that:
  * The workspace's configured search headers (e.g. X-Request-Purpose: Research) and
    User-Agent reach the target from EVERY real send path: Repeater/curl (/api/send),
    Intruder (looped /api/send), Access Control (every identity + the anonymous
    baseline), and the XSS Lab.
  * A search header WINS over whatever a caller supplied for the same name (can't be
    silently dropped by editing a request or changing URL/method).
  * Cookie/Authorization never leak between ACL identities, and search headers never
    reach the passive crt.sh lookup (which never gets any of the target's own headers).
  * The default User-Agent is a real, documented browser profile, never the tool name.
  * Emergency Stop blocks new target requests from EVERY tool, not just Collection —
    and does so BEFORE any byte reaches the network.
  * Out-of-scope requests never reach the network.
  * /api/reset-budget tells an invalid VALUE (400) apart from a BUSY workspace (409).

All servers are loopback-only; no external target is touched.
Run:  python -m unittest tests.test_identity_and_admission -v
"""
import http.client
import json
import threading
import tempfile
import time
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from raven.api import server
from raven.scope import Scope


class CapturingHTTP:
    """A tiny loopback HTTP server that records every request's headers/path/method,
    so tests can assert on what ACTUALLY arrived — not on what the code merely claims
    to send. Optionally stalls each response to create an observable in-flight window."""

    def __init__(self, stall=0.0):
        self.received = []
        self._stall = stall

    def __enter__(self):
        received, stall = self.received, self._stall

        class _H(BaseHTTPRequestHandler):
            def _reply(self):
                received.append({"path": self.path, "method": self.command,
                                  "headers": dict(self.headers)})
                if stall:
                    time.sleep(stall)
                body = b"OK"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _reply

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def _header(captured, name):
    return next((v for k, v in captured["headers"].items() if k.lower() == name.lower()), None)


class SendPathIdentityTests(unittest.TestCase):
    """Every REAL send path must carry the configured search headers + UA."""

    def setUp(self):
        self._saved = dict(server.STATE)
        self._identity_dir = tempfile.TemporaryDirectory()
        # Persistence failures must remain visible in production. Each test gets
        # a real temporary identity directory, independent of other test classes.
        server.STATE["ws_dir"] = Path(self._identity_dir.name)
        server.STATE["search_headers"] = {}
        server.STATE["user_agent_key"], server.STATE["user_agent"] = "chrome-windows", \
            server.UA_CATALOG["chrome-windows"][1]

    def tearDown(self):
        server.SCHEDULER.clear_stop()
        server.STATE.clear()
        server.STATE.update(self._saved)
        self._identity_dir.cleanup()

    def _scope_local(self, srv):
        server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
        server.STATE["allow_private"] = True

    def test_search_header_reaches_target_via_send(self):
        with CapturingHTTP() as srv:
            self._scope_local(srv)
            server.set_identity({"search_headers": {"X-Request-Purpose": "Research"}})
            r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/"})
            self.assertTrue(r.get("ok"), r)
            self.assertEqual(_header(srv.received[0], "X-Request-Purpose"), "Research")

    def test_search_header_wins_over_caller_supplied_value(self):
        # A required header must not be droppable by whatever a Repeater edit sends.
        with CapturingHTTP() as srv:
            self._scope_local(srv)
            server.set_identity({"search_headers": {"X-Request-Purpose": "Research"}})
            r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/",
                                 "headers": {"X-Request-Purpose": "something-else"}})
            self.assertTrue(r.get("ok"), r)
            self.assertEqual(_header(srv.received[0], "X-Request-Purpose"), "Research")

    def test_search_headers_reach_acl_every_identity_and_anonymous(self):
        with CapturingHTTP() as srv:
            self._scope_local(srv)
            server.set_identity({"search_headers": {"X-Request-Purpose": "Research"}})
            url = f"http://127.0.0.1:{srv.port}/res"
            result = server.do_access_check({
                "method": "GET", "url": url, "anonymous_baseline": True,
                "sessions": [{"label": "owner", "cookies": "session=A"},
                             {"label": "other", "cookies": "session=B"}],
            })
            self.assertTrue(result.get("results"))
            self.assertEqual(len(srv.received), 3, "owner + other + anonymous = 3 requests")
            for captured in srv.received:
                self.assertEqual(_header(captured, "X-Request-Purpose"), "Research")

    def test_acl_credentials_never_cross_identities_or_reach_anonymous(self):
        with CapturingHTTP() as srv:
            self._scope_local(srv)
            url = f"http://127.0.0.1:{srv.port}/res"
            server.do_access_check({
                "method": "GET", "url": url, "anonymous_baseline": True,
                "sessions": [{"label": "owner", "cookies": "session=OWNER-SECRET"},
                             {"label": "other", "cookies": "session=OTHER-SECRET"}],
            })
            self.assertEqual(len(srv.received), 3)
            cookies = [_header(c, "Cookie") for c in srv.received]
            self.assertIn("session=OWNER-SECRET", cookies)
            self.assertIn("session=OTHER-SECRET", cookies)
            # Neither identity's cookie leaked into the other's or the anonymous request.
            self.assertEqual(cookies.count("session=OWNER-SECRET"), 1)
            self.assertEqual(cookies.count("session=OTHER-SECRET"), 1)
            self.assertIn(None, cookies, "the anonymous baseline must carry NO cookie")

    def test_search_headers_reach_xss_lab(self):
        with CapturingHTTP() as srv:
            self._scope_local(srv)
            server.set_identity({"search_headers": {"X-Request-Purpose": "Research"}})
            result = server.do_xss_check({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/?q=x",
                                           "param": "q"})
            self.assertFalse(result.get("blocked"), result)
            self.assertEqual(_header(srv.received[0], "X-Request-Purpose"), "Research")

    def test_search_headers_never_reach_crtsh(self):
        # _passive_crtsh must NEVER carry the workspace's target search headers (or
        # any target credential) — it talks to a third-party OSINT source, not the
        # target. Mocked locally; crt.sh itself is never contacted by this test.
        server.set_identity({"search_headers": {"X-Request-Purpose": "Research"}})
        captured = {}

        class _FakeResp:
            def read(self, *_a):
                return b"[]"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_open(request, timeout=None):
            captured["headers"] = dict(request.header_items())
            return _FakeResp()

        original = server._OPENER.open
        server._OPENER.open = fake_open
        try:
            server._passive_crtsh("example.test")
        finally:
            server._OPENER.open = original
        self.assertNotIn("X-Request-Purpose", captured.get("headers", {}))
        self.assertNotIn("Cookie", captured.get("headers", {}))

    def test_configured_user_agent_reaches_target(self):
        with CapturingHTTP() as srv:
            self._scope_local(srv)
            server.set_identity({"user_agent_key": "firefox-linux"})
            r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/"})
            self.assertTrue(r.get("ok"), r)
            self.assertEqual(_header(srv.received[0], "User-Agent"),
                              server.UA_CATALOG["firefox-linux"][1])

    def test_default_user_agent_is_a_real_browser_not_the_tool_name(self):
        default_ua = server.UA_CATALOG[server.DEFAULT_UA_KEY][1]
        self.assertIn("Mozilla/5.0", default_ua)
        self.assertNotIn("Raven", default_ua)
        self.assertNotIn("raven", default_ua.lower())

    def test_custom_user_agent_rejects_crlf(self):
        with self.assertRaises(ValueError):
            server.set_identity({"user_agent_key": "custom", "user_agent_custom": "evil\r\nX-Injected: 1"})

    def test_search_header_rejects_crlf_and_credential_names(self):
        with self.assertRaises(ValueError):
            server.set_identity({"search_headers": {"X-Bad": "line1\r\nX-Injected: 1"}})
        with self.assertRaises(ValueError):
            server.set_identity({"search_headers": {"Cookie": "session=x"}})
        with self.assertRaises(ValueError):
            server.set_identity({"search_headers": {"Authorization": "Bearer x"}})

    def test_search_headers_case_insensitive_dedupe(self):
        result = server.set_identity({"search_headers": {"X-Request-Purpose": "first",
                                                           "x-request-purpose": "second"}})
        self.assertEqual(len(result["search_headers"]), 1)
        self.assertEqual(list(result["search_headers"].values())[0], "second")


class EmergencyStopCoversEveryToolTests(unittest.TestCase):
    """Emergency Stop must block NEW target requests from every tool, before any
    network byte is sent — not just Collection."""

    def setUp(self):
        self._saved = dict(server.STATE)

    def tearDown(self):
        server.SCHEDULER.clear_stop()
        server.STATE.clear()
        server.STATE.update(self._saved)

    def test_send_blocked_with_zero_network_activity(self):
        with CapturingHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            server.SCHEDULER.emergency_stop()
            r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/"})
            self.assertTrue(r.get("blocked"), r)
            self.assertEqual(srv.received, [], "Emergency Stop let a request reach the network")

    def test_access_check_blocked_with_zero_network_activity(self):
        with CapturingHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            server.SCHEDULER.emergency_stop()
            server.do_access_check({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/",
                                     "sessions": [{"label": "owner"}]})
            self.assertEqual(srv.received, [], "Emergency Stop did not cover Access Control")

    def test_xss_check_blocked_with_zero_network_activity(self):
        with CapturingHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            server.SCHEDULER.emergency_stop()
            server.do_xss_check({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/?q=x", "param": "q"})
            self.assertEqual(srv.received, [], "Emergency Stop did not cover the XSS Lab")

    def test_out_of_scope_never_reaches_network(self):
        with CapturingHTTP() as srv:
            server.STATE["scope"] = Scope(include=["not-this-host.test"], exclude=[], ports=[80, 443])
            r = server.do_send({"method": "GET", "url": f"http://127.0.0.1:{srv.port}/"})
            self.assertTrue(r.get("blocked"), r)
            self.assertEqual(srv.received, [])


class ResetBudgetHttpTests(unittest.TestCase):
    """Live HTTP-level proof that /api/reset-budget tells an invalid value apart
    from a busy workspace (distinct status codes and messages)."""

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        server.STATE["port"] = cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def tearDown(self):
        server.SCHEDULER.clear_stop()

    def _post(self, path, payload):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = json.dumps(payload)
        c.request("POST", path, body=body, headers={
            "X-RAVEN-Token": server.SESSION_TOKEN, "Content-Type": "application/json",
            "Origin": f"http://127.0.0.1:{self.port}"})
        r = c.getresponse()
        data = json.loads(r.read() or b"{}")
        c.close()
        return r.status, data

    def test_invalid_budget_value_is_400(self):
        status, data = self._post("/api/reset-budget", {"budget": -5})
        self.assertEqual(status, 400)
        self.assertIn("invalid budget value", data.get("error", "").lower())

    def test_busy_workspace_is_409_and_distinct_from_invalid_value(self):
        with CapturingHTTP(stall=0.6) as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            worker = threading.Thread(target=lambda: server.do_send(
                {"method": "GET", "url": f"http://127.0.0.1:{srv.port}/"}))
            worker.start()
            time.sleep(0.15)  # request is admitted and in flight (stalled server)
            status, data = self._post("/api/reset-budget", {"budget": 10})
            worker.join(timeout=5)
            self.assertEqual(status, 409)
            self.assertNotIn("invalid budget value", data.get("error", "").lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
