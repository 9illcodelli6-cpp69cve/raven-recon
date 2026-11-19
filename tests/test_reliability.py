"""Reliability / robustness tests: workspace-name safety, workspace isolation,
hostile-import handling, and — critically — the dynamic port-fallback behaviour
(startup when the preferred port is occupied, no attachment to a foreign process,
session-token isolation, Origin binding to the actual port, clean restart).

All tests use loopback servers and mocks. No external targets.

Run:  python -m unittest tests.test_reliability -v
"""
import http.client
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from raven.api import server
from raven.scope import Scope


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-rel-")
        os.chdir(self._tmp)
        self._saved = dict(server.STATE)

    def tearDown(self):
        os.chdir(self._cwd)
        server.STATE.clear()
        server.STATE.update(self._saved)

    def test_slug_blocks_traversal_invariant(self):
        # Assert the real security invariant, not an arbitrary output string:
        # no ".." token, no path separators, and the resolved dir stays under
        # ./workspaces — for every hostile input.
        base = os.path.abspath("workspaces")
        for hostile in ["..", "../..", "../../etc/passwd", "....//....//x",
                        r"..\..\x", ".", "...", "   ", "/etc/passwd", "..%2f.."]:
            s = server._slug(hostile)
            self.assertNotIn("..", s, f"{hostile!r} -> {s!r} still has ..")
            self.assertNotIn("/", s)
            self.assertNotIn("\\", s)
            target = os.path.abspath(os.path.join("workspaces", s))
            self.assertTrue(target == base or target.startswith(base + os.sep),
                            f"{hostile!r} -> {s!r} escaped workspaces")

    def test_slug_preserves_legitimate_names(self):
        self.assertEqual(server._slug("Shopify-Corp"), "shopify-corp")
        self.assertEqual(server._slug("my-app.example.com"), "my-app.example.com")
        self.assertEqual(server._slug("prog_2024"), "prog_2024")

    def test_workspace_isolation(self):
        server.STATE["scope"] = Scope(include=["a.test"], exclude=[], ports=[80, 443])
        server.use_workspace("alpha")
        rid = server.STATE["store"].start("t", {})
        server.STATE["store"].host("only-in-alpha.a.test", "test", rid)
        server.use_workspace("beta")
        hosts = [a["host"] for a in server.STATE["store"].assets()]
        self.assertNotIn("only-in-alpha.a.test", hosts)

    def test_import_rejects_hostile_and_out_of_scope(self):
        server.STATE["scope"] = Scope(include=["good.test", "*.good.test"], exclude=[], ports=[80, 443])
        server.use_workspace("imp")
        result = server.do_import([
            "sub.good.test", "evil.com", "javascript:alert(1)",
            "http://127.0.0.1/", "../../etc/passwd", "",
        ])
        self.assertEqual(result["added"], 1)


class PortFallbackTests(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-port-")
        os.chdir(self._tmp)
        self._saved = dict(server.STATE)
        self._servers = []

    def tearDown(self):
        for h in self._servers:
            try:
                h.shutdown()
                h.server_close()
            except Exception:
                pass
        os.chdir(self._cwd)
        server.STATE.clear()
        server.STATE.update(self._saved)

    def _foreign_server(self):
        class Foreign(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"FOREIGN-NOT-RAVEN"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        h = ThreadingHTTPServer(("127.0.0.1", 0), Foreign)
        self._servers.append(h)
        threading.Thread(target=h.serve_forever, daemon=True).start()
        return h.server_address[1]

    def _get(self, port, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        body = r.read().decode("utf-8", "replace")
        c.close()
        return body

    def _status(self, method, port, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def test_startup_when_preferred_port_occupied(self):
        foreign_port = self._foreign_server()
        httpd, port = server.start_background(port=foreign_port)
        self._servers.append(httpd)
        self.assertNotEqual(port, foreign_port)                 # fell back
        self.assertEqual(server.STATE["port"], port)            # auth/origin use the real port
        # RAVEN serves its own token-bearing page on the bound port ...
        page = self._get(port, "/")
        self.assertIn("RAVEN_TOKEN", page)
        # ... and never attached to / leaked the token into the foreign process.
        foreign = self._get(foreign_port, "/")
        self.assertIn("FOREIGN-NOT-RAVEN", foreign)
        self.assertNotIn("RAVEN_TOKEN", foreign)

    def test_origin_binds_to_actual_port(self):
        foreign_port = self._foreign_server()
        httpd, port = server.start_background(port=foreign_port)
        self._servers.append(httpd)
        good = self._status("POST", port, "/api/send", {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": f"http://127.0.0.1:{port}",
            "Content-Type": "application/json",
        }, '{"method":"GET","url":"https://x.invalid.test/"}')
        self.assertNotEqual(good, 403)                          # actual-port Origin accepted
        bad = self._status("POST", port, "/api/send", {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": f"http://127.0.0.1:{foreign_port}",       # the *other* port
            "Content-Type": "application/json",
        }, "{}")
        self.assertEqual(bad, 403)                              # mismatched Origin rejected

    def test_clean_shutdown_and_immediate_restart(self):
        base = _free_port()
        httpd, port = server.start_background(port=base)
        self.assertEqual(port, base)
        self.assertEqual(self._status("GET", port, "/api/health"), 200)
        httpd.shutdown()
        httpd.server_close()
        # Immediate restart on the same preferred port must succeed (no crash / no
        # attachment to a stale socket).
        httpd2, port2 = server.start_background(port=base)
        self._servers.append(httpd2)
        self.assertEqual(self._status("GET", port2, "/api/health"), 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
