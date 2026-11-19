"""GOLDEN / characterization tests — stable JSON payload SHAPES (Wave 3 oracle).

Locks the CURRENT top-level envelope (and the server-owned nesting) of the V7
status/traffic/terminal/tasks/workspace endpoints. Wave 3's decomposition is
behaviour-preserving (RUNTIME_ARCHITECTURE.md §7 "UI contracts"), so these key
sets must survive the refactor unchanged. Deliberate contract FIXES land in a
later wave with their own tests.

Known intentional-fix exception (RUNTIME_ARCHITECTURE.md §1.6 / §10): in
`api_comprehensive_status`/`api_tasks_list`, `recon_jobs` is always `[]` because
of the `SCHEDULER.list() if "SCHEDULER" in dir()` bug — `dir()` with no args never
contains a module global. We therefore lock only that the `recon_jobs` KEY exists,
NOT that it equals `[]` (locking the bug would block its fix).

Network/shell inputs are stubbed so the shape is hermetic and deterministic; the
key sets asserted are produced by server.py's own builders regardless of input.

Run:  python -m pytest tests/test_golden_payload_shapes.py -q
"""
import json
import http.client
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from raven.api import server


class _FakeTerminal:
    """Avoids spawning real powershell/bash (fast, no console flash, deterministic)."""
    def is_available(self, shell="powershell"):
        return False


_STUB_AI = {"configured": False, "available": False, "display": "Not configured",
            "provider": None, "provider_display": None, "model": None}


class _ShapeBase(unittest.TestCase):
    """Isolate the module-global subsystem singletons against a temp data root."""
    _SINGLETONS = ("_TERMINAL_TOOL", "_WORKSPACE_MGR", "_TASK_REGISTRY",
                   "_PLUGIN_REGISTRY", "_KB", "_EG")

    def setUp(self):
        self._saved_state = dict(server.STATE)
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-golden-shape-")
        os.chdir(self._tmp)
        self._saved_singletons = {n: getattr(server, n) for n in self._SINGLETONS}
        for n in self._SINGLETONS:
            setattr(server, n, None)
        self._saved_ensure_terminal = server._ensure_terminal
        self._saved_ai_status = server._ai_status_dict
        server._ensure_terminal = lambda: _FakeTerminal()
        server._ai_status_dict = lambda: dict(_STUB_AI)
        server.use_workspace("goldenshape")  # gives STATE["store"] for traffic

    def tearDown(self):
        store = server.STATE.get("store")
        if store is not None:
            try:
                store.close()
            except Exception:
                pass
        server._ensure_terminal = self._saved_ensure_terminal
        server._ai_status_dict = self._saved_ai_status
        for n, v in self._saved_singletons.items():
            setattr(server, n, v)
        server.STATE.clear()
        server.STATE.update(self._saved_state)
        os.chdir(self._cwd)


class DirectBuilderShapes(_ShapeBase):
    def test_status_shape(self):
        s = server.api_comprehensive_status()
        self.assertEqual(set(s), {"ai", "terminal", "proxy", "workspace",
                                  "scheduler", "runtime"})
        self.assertEqual(set(s["ai"]), {"system", "configured", "available",
                                        "foundation_model", "provider",
                                        "provider_display", "display"})
        self.assertEqual(set(s["terminal"]), {"available", "shells"})
        self.assertEqual(set(s["proxy"]), {"active", "port"})
        self.assertEqual(set(s["workspace"]), {"name", "active"})
        self.assertIsInstance(s["scheduler"], dict)
        self.assertEqual(s["runtime"], "RAVEN V7")

    def test_terminal_status_shape(self):
        t = server.api_terminal_status()
        self.assertEqual(set(t), {"available", "shells", "default_shell", "history_count"})
        self.assertEqual(set(t["shells"]), {"powershell", "bash", "cmd"})

    def test_traffic_shape(self):
        # CONTRACT FIX (Wave 8, A8-BROWSER): /api/v7/traffic now returns canonical
        # observations projected as TrafficEntry[] under key `entries` (with
        # `total` + `workspace_id`), NOT the recon asset-URL inventory under the
        # dead `requests` key. The UI's loadTraffic() has always read `entries`
        # (index.html), so the old `requests` key left the Traffic tab empty — the
        # audit's documented "entries vs requests" mismatch. See
        # reconstruction/BROWSER_TRAFFIC_ARCHITECTURE.md §1.4/§3.3. This is the ONE
        # intentional traffic payload-shape assertion change; egress/transport/
        # terminal/status/tasks/workspace golden assertions are untouched.
        data, code = server.api_traffic_list()
        self.assertEqual(code, 200)
        self.assertTrue({"entries", "total", "workspace_id"} <= set(data))
        self.assertIsInstance(data["entries"], list)
        self.assertIsInstance(data["total"], int)
        self.assertNotIn("requests", data)

    def test_tasks_shape(self):
        data, code = server.api_tasks_list()
        self.assertEqual(code, 200)
        self.assertEqual(set(data), {"tasks", "recon_jobs"})
        self.assertIsInstance(data["tasks"], list)
        # NOTE: do NOT assert data["recon_jobs"] == []  (that is the dir() bug,
        # fixed in Wave 3). Only the key's presence is the preserved contract.

    def test_workspace_list_shape(self):
        data, code = server.api_workspace_list()
        self.assertEqual(code, 200)
        self.assertEqual(set(data), {"workspaces", "current_id"})
        self.assertIsInstance(data["workspaces"], list)
        self.assertTrue(data["workspaces"], "a Default workspace should be seeded")
        entry = data["workspaces"][0]
        # The frontend join keys the refactor must preserve.
        self.assertIn("workspace_id", entry)
        self.assertIn("name", entry)


class RouteWiringShapes(_ShapeBase):
    """The same envelopes must arrive over the real Handler route table — this locks
    the route -> builder wiring that Wave 3 rewrites into RUNTIME.<service> calls."""

    def setUp(self):
        super().setUp()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        server.STATE["port"] = self.port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(2)
        super().tearDown()

    def _get_json(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("GET", path, headers={"X-RAVEN-Token": server.SESSION_TOKEN})
            r = c.getresponse()
            body = r.read()
            return r.status, json.loads(body)
        finally:
            c.close()

    def test_routes_return_expected_top_level_keys(self):
        cases = {
            "/api/v7/status": {"ai", "terminal", "proxy", "workspace", "scheduler", "runtime"},
            "/api/v7/terminal/status": {"available", "shells", "default_shell", "history_count"},
            "/api/v7/tasks": {"tasks", "recon_jobs"},
            "/api/v7/workspace": {"workspaces", "current_id"},
        }
        for path, keys in cases.items():
            with self.subTest(path=path):
                status, data = self._get_json(path)
                self.assertEqual(status, 200)
                self.assertEqual(set(data), keys)

    def test_traffic_route_has_entries_and_total(self):
        # CONTRACT FIX (Wave 8, A8-BROWSER): same intentional traffic-shape change
        # as DirectBuilderShapes.test_traffic_shape, asserted here over the real
        # Handler route wiring. Key is now `entries` (canonical TrafficEntry[]),
        # not `requests`. See BROWSER_TRAFFIC_ARCHITECTURE.md §1.4/§3.3 and the
        # audit's "entries vs requests" finding.
        status, data = self._get_json("/api/v7/traffic")
        self.assertEqual(status, 200)
        self.assertTrue({"entries", "total", "workspace_id"} <= set(data))
        self.assertNotIn("requests", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
