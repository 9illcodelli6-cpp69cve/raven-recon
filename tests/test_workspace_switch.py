"""Wave 5 (A5-WS) — workspace SWITCH rebinds recon + CREATE yields a usable workspace.

The ONE intended behaviour change of this wave: switching the workspace in the UI now
drives the canonical System-A context engine (`set_scope`/`use_workspace`) instead of
relabelling only. These tests prove the real subsystems follow the selected workspace.

Loopback/in-memory only; every workspace is materialized under a temp DATA_ROOT (the
server resolves DATA_ROOT as Path('.'), so chdir isolates it). No network, no Ollama.

Run:  python -m pytest tests/test_workspace_switch.py -q
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from raven.api import server


class _WSBase(unittest.TestCase):
    _SINGLETONS = ("_WORKSPACE_MGR", "_KB", "_EG")

    def setUp(self):
        self._saved_state = dict(server.STATE)
        self._saved_active = server._ACTIVE_WORKSPACE_ID
        self._saved_singletons = {n: getattr(server, n) for n in self._SINGLETONS}
        for n in self._SINGLETONS:
            setattr(server, n, None)
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-ws-switch-")
        os.chdir(self._tmp)

    def tearDown(self):
        store = server.STATE.get("store")
        if store is not None:
            try:
                store.close()
            except Exception:
                pass
        mgr = server._WORKSPACE_MGR
        if mgr is not None:
            try:
                mgr._db.close()
            except Exception:
                pass
        for n, v in self._saved_singletons.items():
            setattr(server, n, v)
        server._ACTIVE_WORKSPACE_ID = self._saved_active
        server.STATE.clear()
        server.STATE.update(self._saved_state)
        os.chdir(self._cwd)

    def _create(self, name, include):
        data, code = server.api_workspace_create({"name": name, "include": include})
        self.assertEqual(code, 200, data)
        self.assertTrue(data["created"])
        return data["workspace"]


class CreateMaterializes(_WSBase):
    def test_create_yields_usable_active_workspace(self):
        ws = self._create("gamma", ["g.example.com"])
        wid = ws["workspace_id"]
        # real on-disk workspace, not a ghost DB row
        self.assertTrue(Path("workspaces/gamma/recon.db").is_file())
        self.assertTrue(Path("workspaces/gamma/scope.json").is_file())
        # it became the active System-A context
        self.assertEqual(server.STATE["name"], "gamma")
        self.assertEqual(server.STATE["workspace_id"], wid)   # registry id == recon uuid
        self.assertIsNotNone(server.STATE.get("store"))
        self.assertIsNotNone(server.STATE.get("canonical_svc"))
        # derived mirror aligned to the canonical recon id
        self.assertEqual(server._ACTIVE_WORKSPACE_ID, wid)

    def test_create_requires_name(self):
        data, code = server.api_workspace_create({"name": "   "})
        self.assertEqual(code, 400)
        self.assertIn("error", data)

    def test_create_defaults_scope_to_name_when_omitted(self):
        data, code = server.api_workspace_create({"name": "delta"})
        self.assertEqual(code, 200, data)
        saved = json.loads(Path("workspaces/delta/scope.json").read_text())
        self.assertEqual(saved["include"], ["delta"])


class SwitchRebindsRecon(_WSBase):
    def test_switch_rebinds_store_scope_and_workspace_id(self):
        a = self._create("alpha", ["a.example.com"])
        store_a = server.STATE["store"]
        wid_a = server.STATE["workspace_id"]
        b = self._create("beta", ["b.example.com"])
        store_b = server.STATE["store"]
        wid_b = server.STATE["workspace_id"]
        self.assertIsNot(store_a, store_b)
        self.assertNotEqual(wid_a, wid_b)

        res, code = server.api_workspace_switch({"workspace_id": a["workspace_id"]})
        self.assertEqual(code, 200, res)
        self.assertTrue(res["switched"])
        # every data-bearing binding followed the selected workspace
        self.assertIsNot(server.STATE["store"], store_b)
        self.assertEqual(Path(server.STATE["ws_dir"]).name, "alpha")
        self.assertEqual(server.STATE["workspace_id"], wid_a)
        self.assertEqual(server.STATE["scope"].include, ["a.example.com"])
        self.assertIsNotNone(server.STATE.get("canonical_svc"))
        # cross-restart pointer + derived mirror
        ptr = json.loads(Path("active-workspace.json").read_text())
        self.assertEqual(ptr["name"], "alpha")
        self.assertEqual(server._ACTIVE_WORKSPACE_ID, server.STATE["workspace_id"])
        self.assertEqual(res["workspace"]["workspace_id"], wid_a)

    def test_switch_is_not_label_only(self):
        """Regression for the server.py switch bug: STATE must not change the label
        while the store stays pinned to the old workspace."""
        a = self._create("alpha", ["a.example.com"])
        self._create("beta", ["b.example.com"])
        store_before = server.STATE["store"]
        server.api_workspace_switch({"workspace_id": a["workspace_id"]})
        self.assertIsNot(server.STATE["store"], store_before)
        self.assertEqual(server.STATE["store"].workspace, Path(server.STATE["ws_dir"]))

    def test_switch_unknown_id_404(self):
        self._create("alpha", ["a.example.com"])
        res, code = server.api_workspace_switch({"workspace_id": "deadbeef" * 4})
        self.assertEqual(code, 404)

    def test_switch_requires_id(self):
        res, code = server.api_workspace_switch({})
        self.assertEqual(code, 400)

    def test_scopeless_registry_row_returns_409_without_touching_state(self):
        self._create("alpha", ["a.example.com"])
        before = {k: server.STATE.get(k) for k in ("store", "ws_dir", "workspace_id", "name")}
        mgr = server._ensure_workspace_mgr()
        ghost = mgr.create("Ghostly", root_path=".")   # registry row, no scope.json on disk
        res, code = server.api_workspace_switch({"workspace_id": ghost.workspace_id})
        self.assertEqual(code, 409, res)
        self.assertIn("scope", res["error"].lower())
        after = {k: server.STATE.get(k) for k in ("store", "ws_dir", "workspace_id", "name")}
        self.assertEqual(before, after)   # fail-closed: no half-switch


class CanonicalKeyUnified(_WSBase):
    def test_knowledge_and_evidence_key_on_canonical_workspace_id(self):
        captured = {}

        class _FakeKB:
            def search(self, q, workspace_id=None, limit=50):
                captured["kb"] = workspace_id
                return []
            def count(self):
                return 0

        class _FakeEG:
            def list_nodes(self, workspace_id=None, limit=50):
                captured["eg"] = workspace_id
                return []
            def count_nodes(self):
                return 0

        a = self._create("alpha", ["a.example.com"])
        server.api_workspace_switch({"workspace_id": a["workspace_id"]})
        server._KB, server._EG = _FakeKB(), _FakeEG()
        server.api_knowledge_list()
        server.api_evidence_list()
        self.assertEqual(captured["kb"], server.STATE["workspace_id"])
        self.assertEqual(captured["eg"], server.STATE["workspace_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
