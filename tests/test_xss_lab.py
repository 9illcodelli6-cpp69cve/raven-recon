"""XSS Lab tests against a LOCAL synthetic app with known-safe and known-unsafe
reflection contexts. Proves: reflection + context detection, encoded vs raw
classification, that NO script is ever injected, and that the tool never claims
verified execution (that needs an isolated browser, not built here).

No external targets. Run:  python -m unittest tests.test_xss_lab -v
"""
import html
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from raven.api import server
from raven.scope import Scope


class XSSLab(BaseHTTPRequestHandler):
    last_q = ""

    def _html(self, s):
        b = s.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        parts = urlsplit(self.path)
        q = parse_qs(parts.query, keep_blank_values=True).get("q", [""])[0]
        XSSLab.last_q = q
        if parts.path == "/reflect/html":       # UNSAFE: raw into element text
            return self._html(f"<html><body><div>{q}</div></body></html>")
        if parts.path == "/reflect/attr":       # UNSAFE: raw into a quoted attribute
            return self._html(f'<html><body><input value="{q}"></body></html>')
        if parts.path == "/reflect/safe":       # SAFE: HTML-escaped
            return self._html(f"<html><body><div>{html.escape(q)}</div></body></html>")
        if parts.path == "/noreflect":          # not reflected at all
            return self._html("<html><body><div>static</div></body></html>")
        self._html("<html><body>404</body></html>")

    def log_message(self, *a):
        pass


class XSSLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._cwd = os.getcwd()
        cls._tmp = tempfile.mkdtemp(prefix="raven-xss-")
        os.chdir(cls._tmp)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), XSSLab)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        os.chdir(cls._cwd)

    def setUp(self):
        self._saved = dict(server.STATE)
        server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[self.port])
        server.STATE["allow_private"] = True

    def tearDown(self):
        server.STATE.clear()
        server.STATE.update(self._saved)

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_unescaped_html_is_potentially_unsafe(self):
        out = server.do_xss_check({"url": self._url("/reflect/html"), "param": "q"})
        self.assertEqual(out["verdict"], "REFLECTED IN POTENTIALLY UNSAFE CONTEXT")
        self.assertTrue(any(r["context"] == "html-text" for r in out["reflections"]))

    def test_attribute_context_is_potentially_unsafe(self):
        out = server.do_xss_check({"url": self._url("/reflect/attr"), "param": "q"})
        self.assertEqual(out["verdict"], "REFLECTED IN POTENTIALLY UNSAFE CONTEXT")
        self.assertTrue(any("attribute" in r["context"] for r in out["reflections"]))

    def test_escaped_reflection_is_encoded(self):
        out = server.do_xss_check({"url": self._url("/reflect/safe"), "param": "q"})
        self.assertEqual(out["verdict"], "REFLECTED ENCODED")

    def test_not_reflected(self):
        out = server.do_xss_check({"url": self._url("/noreflect"), "param": "q"})
        self.assertEqual(out["verdict"], "NOT REFLECTED")

    def test_never_claims_execution(self):
        out = server.do_xss_check({"url": self._url("/reflect/html"), "param": "q"})
        self.assertNotEqual(out["verdict"], "VERIFIED EXECUTION")
        self.assertNotIn("verified execution", str(out).lower().replace("not verified", ""))

    def test_no_script_is_injected(self):
        server.do_xss_check({"url": self._url("/reflect/html"), "param": "q"})
        self.assertNotIn("<script", XSSLab.last_q.lower())
        self.assertNotIn("javascript:", XSSLab.last_q.lower())

    def test_evidence_fingerprint_present(self):
        out = server.do_xss_check({"url": self._url("/reflect/html"), "param": "q"})
        self.assertEqual(len(out["evidence_sha256"]), 64)

    def test_out_of_scope_blocked(self):
        out = server.do_xss_check({"url": "https://not-in-scope.example/?q=1", "param": "q"})
        self.assertTrue(out.get("blocked"))

    def test_confirmation_is_refused_before_any_send(self):
        with patch.object(server, 'do_send') as send, \
             patch.object(server.xss_executor, 'verify_confirmation') as executor:
            result = server.do_xss_check({'url': self._url('/reflect/html'),
                                          'param': 'q', 'confirm_execution': True})
        self.assertIn('refused', result)
        self.assertFalse(result['execution_confirmation']['attempted'])
        send.assert_not_called()
        executor.assert_not_called()

    def test_stale_isolation_success_cannot_enable_execution(self):
        with patch.dict(server._XSS_ISOLATION_STATE, {'ok': True}), \
             patch.object(server, 'do_send') as send:
            result = server.do_xss_check({'url': self._url('/reflect/html'),
                                          'confirm_execution': True})
        self.assertTrue(result['execution_confirmation']['disabled'])
        send.assert_not_called()

    def test_status_remains_disabled_after_cached_state_changes(self):
        with patch.dict(server._XSS_ISOLATION_STATE, {'ok': True}):
            status = server.do_xss_verify_isolation()
        self.assertFalse(status['ok'])
        self.assertTrue(status['disabled'])


if __name__ == "__main__":
    unittest.main(verbosity=2)
