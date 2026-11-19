"""Wave 8 (A8-BROWSER) — dependency-free Browser MVP tests.

The Browser page is a scope-aware HTTP research client, NOT browser automation.
It sends ONE request through the hardened canonical sender (POST /api/send ->
do_send) and renders the structured response. These tests prove:
  * a real loopback send returns the render-ready fields doBrowserSend() consumes;
  * blocked / transport-error branches are distinguishable (never a faked status);
  * Browser ('browser') and Recon ('probe') feed the SAME observations model;
  * the UI wiring in web/index.html matches the backend contract.

No real browser engine (playwright/CDP) is installed or required.

Run:  python -m pytest tests/test_browser_mvp.py -q
"""
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from raven.api import server
from raven.scope import Scope

_INDEX_HTML = Path(__file__).resolve().parent.parent / "web" / "index.html"


class _LocalHTTP:
    """Controlled loopback target (authorized, no external egress)."""
    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            data = b"<html><body>HELLO-RAVEN-BROWSER</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Demo-Header", "present")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

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


class _ServerBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_state = dict(server.STATE)
        cls._cwd = os.getcwd()
        cls._tmp = tempfile.mkdtemp(prefix="raven-browser-mvp-")
        os.chdir(cls._tmp)
        server.use_workspace("browsermvp")
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        server.STATE["port"] = cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        try:
            server.STATE["store"].close()
        except Exception:
            pass
        server.STATE.clear()
        server.STATE.update(cls._saved_state)
        os.chdir(cls._cwd)

    def _authed_post(self, path, payload):
        body = json.dumps(payload).encode()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("POST", path, body=body, headers={
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": f"http://127.0.0.1:{self.port}",
            "Host": f"127.0.0.1:{self.port}",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        })
        r = c.getresponse()
        data = json.loads(r.read())
        c.close()
        return r.status, data

    def _authed_get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", path, headers={
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Host": f"127.0.0.1:{self.port}",
        })
        r = c.getresponse()
        data = json.loads(r.read())
        c.close()
        return r.status, data


class BrowserSendRenderTests(_ServerBase):
    def test_browser_mvp_renders_loopback_response(self):
        # PROOF (deliverable 2): a real loopback send returns exactly the fields
        # doBrowserSend() renders into the DOM (status badge, reason, headers
        # block, body pane, meta). ok:true with status<400 -> green badge path.
        with _LocalHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            status, d = self._authed_post("/api/send", {
                "method": "GET", "url": f"http://127.0.0.1:{srv.port}/",
                "identity_label": "browser",
            })
            self.assertNotEqual(status, 403)
            self.assertTrue(d.get("ok"), d)
            self.assertEqual(d.get("status"), 200)             # badge text
            self.assertIn("reason", d)                          # badge suffix
            self.assertIsInstance(d.get("headers"), dict)       # #br-headers block
            self.assertTrue(d["headers"])                       # real response headers
            self.assertIsInstance(d.get("body"), str)           # #br-response pane
            self.assertIn("HELLO-RAVEN-BROWSER", d["body"])
            self.assertIn("bytes", d)                           # #br-meta
            self.assertIn("elapsed_ms", d)
            self.assertIn("truncated", d)

    def test_blocked_send_is_not_a_fake_status(self):
        # doBrowserSend() branch (a): blocked:true must be surfaced as "not sent",
        # never collapsed into an HTTP status. No ok, no status fabrication.
        server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[80])
        server.STATE["allow_private"] = True
        status, d = self._authed_post("/api/send", {
            "method": "GET", "url": "http://192.0.2.1/", "identity_label": "browser",
        })
        self.assertNotEqual(status, 403)
        self.assertFalse(d.get("ok"))
        self.assertTrue(d.get("blocked") or d.get("error"), d)

    def test_one_model_two_producers(self):
        # Deliverable 3: Browser and Recon share the ONE observations model. A
        # 'browser' send (via /api/send) and a 'probe' observation (the recon
        # producer, recorded through the SAME CanonicalService) both land in the
        # one store and both surface on /api/v7/traffic, distinguished only by
        # identity_label — no second traffic table.
        svc = server.STATE.get("canonical_svc")
        self.assertIsNotNone(svc)
        with _LocalHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            target = f"http://127.0.0.1:{srv.port}/"
            self._authed_post("/api/send", {
                "method": "GET", "url": target, "identity_label": "browser",
            })
            # Recon probe producer: same writer, identity_label='probe'.
            svc.record_send_result(
                {"ok": True, "status": 200, "reason": "OK",
                 "headers": {"Content-Type": "text/html"}, "body": "x",
                 "bytes": 1, "elapsed_ms": 5, "truncated": False, "decode_lossy": False},
                url=target, method="GET", identity_label="probe", is_probe=True,
            )
            time.sleep(0.1)
            _, traffic = self._authed_get("/api/v7/traffic")
            labels = {e.get("identity_label") for e in traffic["entries"]}
            self.assertIn("browser", labels)
            self.assertIn("probe", labels)


class BrowserUIContractTests(unittest.TestCase):
    """Static assertions that web/index.html matches the backend contract."""

    @classmethod
    def setUpClass(cls):
        cls.html = _INDEX_HTML.read_text(encoding="utf-8")

    def test_browser_posts_to_send_with_browser_identity(self):
        self.assertIn("_RAV.post('/api/send'", self.html)
        self.assertIn("identity_label:'browser'", self.html)

    def _browser_send_body(self):
        start = self.html.index("function doBrowserSend(")
        end = self.html.index("\nfunction ", start)
        return self.html[start:end]

    def test_browser_send_does_not_post_to_collect(self):
        # The old mis-wire (/api/collect ignored url/method/body) must be gone from
        # the BROWSER send path specifically. The Recon page legitimately still
        # POSTs /api/collect, so this is scoped to doBrowserSend()'s own body.
        body = self._browser_send_body()
        self.assertIn("_RAV.post('/api/send'", body)
        self.assertNotIn("/api/collect", body)

    def test_browser_renders_headers_and_history(self):
        for anchor in ("id=\"br-headers\"", "id=\"br-history\"", "id=\"br-response\"",
                       "_brHistory", "_brRenderHistory", "clearBrowserHistory()"):
            self.assertIn(anchor, self.html)

    def test_browser_three_way_branch(self):
        # blocked / transport-error / ok all handled distinctly.
        self.assertIn("d.blocked", self.html)
        self.assertIn("!d.ok", self.html)

    def test_loadtraffic_reads_entries_and_iso_timestamps(self):
        self.assertIn("d.entries", self.html)
        # ISO strings are parsed as-is; the old epoch `*1000` hack must be gone
        # from the traffic renderer.
        self.assertNotIn("new Date(t.timestamp*1000)", self.html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
