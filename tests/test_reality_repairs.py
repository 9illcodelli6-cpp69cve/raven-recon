"""P6-REALITY-REPAIR — regression tests for the product-reality-sweep repairs.

Each test pins ONE demonstrable defect the sweeps documented, now fixed in an
additive, in-architecture way (no wire-contract shape change, no new dependency,
no network):

  * Settings durable persistence (sweep B §7)   — Save survives a restart.
  * Native-model selection persistence (P6 §1)  — survives restart; a stale/missing
                                                   checkpoint is NOT restored (honest).
  * System-Status Proxy row (sweep B §10)       — no fabricated :8080 port.
  * Tasks page (sweep A §2)                      — durable tasks render; the UI reads
                                                   the real fields (title / recon_jobs)
                                                   and does NOT *1000 an epoch-ms time.
  * Honest placeholders (directive §4/§5)        — Scripts / Experiments / Learning are
                                                   shown NOT_IMPLEMENTED / not-wired;
                                                   the dead "Configure via Settings"
                                                   pointer is gone.

Offline, DB-seeded, no app / no Ollama / no network.
Run:  python -m pytest tests/test_reality_repairs.py -q
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from raven.api import server

_INDEX_HTML = Path(__file__).resolve().parent.parent / "web" / "index.html"


class _IsolatedServer(unittest.TestCase):
    """chdir into a temp dir so DATA_ROOT (Path('.')) resolves there, reset the lazy
    singletons, keep the optional external provider OFF (no network)."""

    _SINGLETONS = ("_TERMINAL_TOOL", "_WORKSPACE_MGR", "_TASK_REGISTRY",
                   "_PLUGIN_REGISTRY", "_KB", "_EG")

    def setUp(self):
        self._saved_state = dict(server.STATE)
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-p6-")
        os.chdir(self._tmp)
        self._saved_singletons = {n: getattr(server, n) for n in self._SINGLETONS}
        for n in self._SINGLETONS:
            setattr(server, n, None)
        self._saved_ai_svc = server._AI_SVC
        self._saved_sessions = dict(server._CHAT_SESSIONS)
        self._saved_native = server._NATIVE_SELECTED_MODEL_ID
        self._saved_settings = dict(server._RAVEN_SETTINGS)
        self._saved_enable = server._RAVEN_SETTINGS.get("enable_external_llm")
        self._saved_env = os.environ.get("RAVEN_ENABLE_OLLAMA")
        with server._CHAT_LOCK:
            server._AI_SVC = None
            server._CHAT_SESSIONS.clear()
            server._NATIVE_SELECTED_MODEL_ID = None
        server._RAVEN_SETTINGS["enable_external_llm"] = False
        os.environ.pop("RAVEN_ENABLE_OLLAMA", None)

    def tearDown(self):
        store = server.STATE.get("store")
        if store is not None:
            try:
                store.close()
            except Exception:
                pass
        for n, v in self._saved_singletons.items():
            setattr(server, n, v)
        with server._CHAT_LOCK:
            server._AI_SVC = self._saved_ai_svc
            server._CHAT_SESSIONS.clear()
            server._CHAT_SESSIONS.update(self._saved_sessions)
            server._NATIVE_SELECTED_MODEL_ID = self._saved_native
        server._RAVEN_SETTINGS.clear()
        server._RAVEN_SETTINGS.update(self._saved_settings)
        if self._saved_env is None:
            os.environ.pop("RAVEN_ENABLE_OLLAMA", None)
        else:
            os.environ["RAVEN_ENABLE_OLLAMA"] = self._saved_env
        server.STATE.clear()
        server.STATE.update(self._saved_state)
        os.chdir(self._cwd)


class SettingsPersistence(_IsolatedServer):
    def test_settings_update_round_trips_through_disk(self):
        # Save some distinctive non-default values.
        out, code = server.api_settings_update({
            "model_id": "qwen2.5-coder:latest",
            "ollama_url": "http://localhost:9999",
            "enable_external_llm": True,
            "language": "fr",
        })
        self.assertEqual(code, 200)
        self.assertTrue(out.get("updated"))
        marker = server.DATA_ROOT / server._SETTINGS_FILENAME
        self.assertTrue(marker.exists(), "api_settings_update must persist to disk")

        # Simulate a fresh process: wipe the in-memory dict back to defaults, reload.
        with server._SETTINGS_LOCK:
            server._RAVEN_SETTINGS.update({
                "model_id": None, "ollama_url": "http://localhost:11434",
                "enable_external_llm": False, "language": None,
            })
        server._load_settings()
        self.assertEqual(server._RAVEN_SETTINGS["model_id"], "qwen2.5-coder:latest")
        self.assertEqual(server._RAVEN_SETTINGS["ollama_url"], "http://localhost:9999")
        self.assertTrue(server._RAVEN_SETTINGS["enable_external_llm"])
        self.assertEqual(server._RAVEN_SETTINGS["language"], "fr")

    def test_contract_shape_unchanged_after_update(self):
        # The additive persistence must not change the /api/v7/settings wire shape.
        out, code = server.api_settings_update({"language": "de"})
        self.assertEqual(code, 200)
        self.assertEqual(set(out), {"updated", "settings"})

    def test_corrupt_settings_file_is_ignored(self):
        (server.DATA_ROOT / server._SETTINGS_FILENAME).write_text(
            "{ this is not json", encoding="utf-8")
        before = dict(server._RAVEN_SETTINGS)
        server._load_settings()  # must not raise, must not widen
        self.assertEqual(server._RAVEN_SETTINGS["enable_external_llm"],
                         before["enable_external_llm"])


class NativeSelectionPersistence(_IsolatedServer):
    def test_persist_writes_native_selection(self):
        with server._CHAT_LOCK:
            server._NATIVE_SELECTED_MODEL_ID = "raven-lm-example-id"
        server._persist_settings()
        data = json.loads(
            (server.DATA_ROOT / server._SETTINGS_FILENAME).read_text(encoding="utf-8"))
        self.assertEqual(data.get("native_selected_model_id"), "raven-lm-example-id")

    def test_missing_checkpoint_is_not_restored(self):
        # A persisted selection whose checkpoint no longer resolves must NOT be
        # restored — chat then honestly reports the native model unavailable.
        (server.DATA_ROOT / server._SETTINGS_FILENAME).write_text(json.dumps({
            "version": 1, "settings": {},
            "native_selected_model_id": "does-not-exist-anywhere",
        }), encoding="utf-8")
        with server._CHAT_LOCK:
            server._NATIVE_SELECTED_MODEL_ID = None
        server._load_settings()
        self.assertIsNone(server._NATIVE_SELECTED_MODEL_ID)


class StatusTruthful(_IsolatedServer):
    def test_status_proxy_port_not_fabricated(self):
        s = server.api_comprehensive_status()
        # Keys are golden-frozen; only the fabricated 8080 value is removed.
        self.assertEqual(set(s["proxy"]), {"active", "port"})
        self.assertIsNone(s["proxy"]["port"],
                          "no proxy binds a port; the :8080 chip was fabricated")
        self.assertNotEqual(s["proxy"]["port"], 8080)


class TasksRenderDurable(_IsolatedServer):
    def test_durable_task_appears_in_tasks_list(self):
        reg = server._ensure_task_registry()
        reg.create(title="P6 repair durable task", objective="obj", workspace_id="w1")
        data, code = server.api_tasks_list()
        self.assertEqual(code, 200)
        self.assertIn("tasks", data)
        titles = [t.get("title") for t in data["tasks"]]
        self.assertIn("P6 repair durable task", titles,
                      "a durable task must render in /api/v7/tasks tasks[]")


class UiReality(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _INDEX_HTML.read_text(encoding="utf-8")

    def _fn_body(self, name):
        start = self.html.index("function " + name + "(")
        return self.html[start:self.html.index("\nfunction ", start)]

    # ── System Status rows ────────────────────────────────────────────────────
    def test_browser_row_is_not_an_unconditional_literal(self):
        # The old always-green chip `_setSysRow('Browser','READY',true)` is gone.
        self.assertNotIn("_setSysRow('Browser','READY',true)", self.html)
        # Driven from the real nested signal instead.
        self.assertIn("_setSysRow('Browser',proxy.active", self.html)

    def test_proxy_port_8080_is_not_fabricated_in_ui(self):
        self.assertNotIn("proxy.port||8080", self.html)
        self.assertNotIn("Listening :", self.html)
        self.assertNotIn("String(proxyPort||8080)", self.html)

    # ── Tasks page ────────────────────────────────────────────────────────────
    def test_tasks_created_at_is_not_multiplied(self):
        body = self._fn_body("loadTasks")
        self.assertNotIn("created_at*1000", body)

    def test_tasks_renders_title_and_recon_jobs(self):
        body = self._fn_body("loadTasks")
        self.assertIn("t.title", body)
        self.assertIn("d.recon_jobs", body)

    # ── Honest placeholders / no dead pointer ─────────────────────────────────
    def test_scripts_and_experiments_are_not_implemented(self):
        self.assertIn('view-scripts', self.html)
        # both placeholder pages carry the honest marker
        self.assertGreaterEqual(self.html.count("Not implemented"), 2)
        self.assertIn("not implemented in this build", self.html)

    def test_learning_is_wired_and_honest(self):
        # Superseded (post-Linux-port): the "Not wired" placeholder was replaced by a
        # live page over GET /api/v7/learning (tests/test_learning_live.py). The
        # honesty requirement carries over: authority NONE + the no-exam caveat.
        self.assertNotIn("not wired to this page", self.html)
        self.assertIn("learning:loadLearning", self.html)
        self.assertIn("Security authority:", self.html)
        self.assertIn("have no exam yet", self.html)

    def test_dead_configure_via_settings_pointer_removed(self):
        self.assertNotIn("Configure via Settings", self.html)
        self.assertNotIn(">Configure Settings<", self.html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
