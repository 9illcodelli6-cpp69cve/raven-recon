"""Contract-conformance suite (Wave 14, A14-FRONTEND).

Locks the UI <-> server wire contracts so the audit's D1-D8 field-mismatch class
of bug cannot silently return:

  * schema source      — raven/api/contracts.py declares every endpoint the live
                         UI calls, with a valid honest status vocabulary.
  * handler shape       — each stable read handler emits exactly the declared keys.
  * UI field map        — every field web/index.html reads
                         (tests/contracts/ui_field_map.json) resolves to a declared
                         contract field (a future drift fails HERE).
  * semantic / honesty  — the Browser page sends to /api/send; Recon starts a real
                         /api/collect; the formerly-broken reads
                         (proxy_active / available_shells / 1.2 MB/s placeholder)
                         are gone and the corrected nested reads are present; dead
                         controls are visibly DISABLED; a handler internal error
                         surfaces an `error` (never a silent empty).

Offline, DB-seeded, no app / no Ollama / no network — campaign-rule conformant.

Run:  python -m pytest tests/test_api_contracts.py -q
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from raven.api import server
from raven.api import contracts


_INDEX_HTML = Path(__file__).resolve().parent.parent / "web" / "index.html"
_FIELD_MAP = Path(__file__).resolve().parent / "contracts" / "ui_field_map.json"


# ── Schema-source + vocabulary ──────────────────────────────────────────────
class SchemaSourceTests(unittest.TestCase):
    def test_status_vocabulary_is_the_honest_set(self):
        self.assertEqual(
            contracts.STATUS_VOCABULARY,
            {"READY", "DEGRADED", "UNAVAILABLE", "DISABLED", "BROKEN",
             "LOADING", "DENIED", "EMPTY"},
        )

    def test_every_ui_endpoint_is_declared(self):
        data = json.loads(_FIELD_MAP.read_text(encoding="utf-8"))
        for reader in data["readers"]:
            with self.subTest(ui=reader["ui"]):
                self.assertIn(reader["endpoint"], contracts.CONTRACTS,
                              f"{reader['endpoint']} is read by the UI but not declared in contracts.py")

    def test_declares_at_least_the_18_live_routes(self):
        # RAVEN_API_MAP §7: the live UI calls 18 distinct endpoints.
        self.assertGreaterEqual(len(contracts.CONTRACTS), 18)


# ── UI field-map drift tripwire ─────────────────────────────────────────────
class UiFieldMapTests(unittest.TestCase):
    def test_every_ui_read_resolves_to_a_declared_field(self):
        data = json.loads(_FIELD_MAP.read_text(encoding="utf-8"))
        for reader in data["readers"]:
            ep = reader["endpoint"]
            for path in reader["reads"]:
                with self.subTest(endpoint=ep, read=path):
                    self.assertTrue(
                        contracts.resolve(ep, path),
                        f"UI reads {ep} field {path!r} which is NOT declared in "
                        f"contracts.py — contract drift (an audit-D-class bug).",
                    )

    def test_resolver_rejects_the_old_broken_fields(self):
        # The exact drifts the audit documented must NOT resolve.
        self.assertFalse(contracts.resolve("GET /api/v7/status", "proxy_active"))
        self.assertFalse(contracts.resolve("GET /api/v7/status", "terminal.available_shells"))
        self.assertFalse(contracts.resolve("GET /api/v7/terminal/status", "available_shells"))
        self.assertFalse(contracts.resolve("GET /api/v7/traffic", "requests"))


# ── Handler-shape conformance (isolated, like the golden suite) ─────────────
class _HandlerBase(unittest.TestCase):
    _SINGLETONS = ("_TERMINAL_TOOL", "_WORKSPACE_MGR", "_TASK_REGISTRY",
                   "_PLUGIN_REGISTRY", "_KB", "_EG")

    def setUp(self):
        self._saved_state = dict(server.STATE)
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-contract-")
        os.chdir(self._tmp)
        self._saved_singletons = {n: getattr(server, n) for n in self._SINGLETONS}
        for n in self._SINGLETONS:
            setattr(server, n, None)
        self._saved_ai_svc = server._AI_SVC
        server._AI_SVC = None
        # Keep the optional external provider OFF (default) so nothing touches the
        # network; _ai_status_dict then honestly reports DISABLED.
        self._saved_enable = server._RAVEN_SETTINGS.get("enable_external_llm")
        server._RAVEN_SETTINGS["enable_external_llm"] = False
        os.environ.pop("RAVEN_ENABLE_OLLAMA", None)
        server.use_workspace("contractshape")

    def tearDown(self):
        store = server.STATE.get("store")
        if store is not None:
            try:
                store.close()
            except Exception:
                pass
        for n, v in self._saved_singletons.items():
            setattr(server, n, v)
        server._AI_SVC = self._saved_ai_svc
        server._RAVEN_SETTINGS["enable_external_llm"] = self._saved_enable
        server.STATE.clear()
        server.STATE.update(self._saved_state)
        os.chdir(self._cwd)

    def _assert_conforms(self, endpoint, data):
        c = contracts.CONTRACTS[endpoint]
        keys = set(data)
        missing = set(c["required"]) - keys
        self.assertFalse(missing, f"{endpoint}: missing required keys {missing}")
        extra = keys - set(c["required"]) - set(c["optional"])
        self.assertFalse(extra, f"{endpoint}: undeclared keys {extra}")
        for sub, subc in c["nested"].items():
            if sub in data and isinstance(data[sub], dict):
                sub_missing = set(subc["required"]) - set(data[sub])
                self.assertFalse(sub_missing,
                                 f"{endpoint}.{sub}: missing {sub_missing}")


class HandlerShapeTests(_HandlerBase):
    def test_ai_status(self):
        self._assert_conforms("GET /api/ai/status", server._ai_status_dict())

    def test_comprehensive_status(self):
        self._assert_conforms("GET /api/v7/status", server.api_comprehensive_status())

    def test_terminal_status(self):
        self._assert_conforms("GET /api/v7/terminal/status", server.api_terminal_status())

    def test_tasks(self):
        data, code = server.api_tasks_list()
        self.assertEqual(code, 200)
        self._assert_conforms("GET /api/v7/tasks", data)

    def test_workspace(self):
        data, code = server.api_workspace_list()
        self.assertEqual(code, 200)
        self._assert_conforms("GET /api/v7/workspace", data)

    def test_traffic(self):
        data, code = server.api_traffic_list()
        self.assertEqual(code, 200)
        self._assert_conforms("GET /api/v7/traffic", data)

    def test_evidence(self):
        data, code = server.api_evidence_list()
        self.assertEqual(code, 200)
        self._assert_conforms("GET /api/v7/evidence", data)

    def test_knowledge(self):
        data, code = server.api_knowledge_list()
        self.assertEqual(code, 200)
        self._assert_conforms("GET /api/v7/knowledge", data)

    def test_plugins(self):
        data, code = server.api_plugins_list()
        self.assertEqual(code, 200)
        self._assert_conforms("GET /api/v7/plugins", data)

    def test_settings(self):
        data, code = server.api_settings_get()
        self.assertEqual(code, 200)
        self._assert_conforms("GET /api/v7/settings", data)

    def test_system_resources_has_available_and_net_rate_when_present(self):
        data = server.api_system_resources()
        self._assert_conforms("GET /api/v7/system/resources", data)
        self.assertIn("available", data)
        if data.get("available"):
            # D5 fix: the per-second network RATE field the UI's Network row reads.
            self.assertIn("net_bytes_sent_ps", data)
            self.assertIn("net_bytes_recv_ps", data)


# ── Honesty: a handler internal error surfaces, never a silent empty ────────
class HonestyTests(_HandlerBase):
    def test_evidence_internal_error_is_surfaced_not_silent(self):
        def _boom(ws_id):
            raise RuntimeError("seeded failure")
        saved = server._evidence_read_source
        server._evidence_read_source = _boom
        try:
            data, code = server.api_evidence_list()
        finally:
            server._evidence_read_source = saved
        self.assertEqual(code, 200)
        self.assertEqual(data["nodes"], [])
        self.assertTrue(data.get("error"),
                        "an internal error must surface an `error`, not a silent empty list")

    def test_ai_status_value_is_in_the_honest_vocabulary(self):
        st = server._ai_status_dict().get("status")
        self.assertIn(st, contracts.STATUS_VOCABULARY)


# ── Static UI semantics (index.html matches the backend contract) ───────────
class UiSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _INDEX_HTML.read_text(encoding="utf-8")

    def test_browser_send_targets_api_send(self):
        self.assertIn("_RAV.post('/api/send'", self.html)

    def test_recon_start_posts_collect(self):
        start = self.html.index("function startRecon(")
        body = self.html[start:self.html.index("\nfunction ", start)]
        self.assertIn("_RAV.post('/api/collect'", body)

    def test_proxy_read_is_nested_not_flat(self):
        # D4: read proxy.active, never the flat proxy_active the server never sends.
        self.assertIn("proxy.active", self.html)
        self.assertNotIn("d.proxy_active", self.html)

    def test_terminal_read_is_shells_dict_not_available_shells(self):
        # D2/D3: derive from the shells{} dict; the available_shells array is gone.
        self.assertIn("d.terminal&&d.terminal.shells", self.html)
        self.assertIn("d.shells||{}", self.html)
        self.assertNotIn(".available_shells", self.html)

    def test_network_rate_field_and_no_placeholder(self):
        # D5: the Network row reads the derived rate; the fake "1.2 MB/s" is gone.
        self.assertIn("net_bytes_sent_ps", self.html)
        self.assertNotIn("1.2 MB/s", self.html)

    def test_emergency_stop_reads_stopped(self):
        self.assertIn("d.stopped", self.html)

    def test_research_and_tools_tabs_open_real_pages(self):
        # v7.1: no dead tabs — Research opens the AI Agent (trusted-source research),
        # Tools opens the Terminal.
        self.assertNotIn('data-tab="research" disabled', self.html)
        self.assertNotIn('data-tab="tools" disabled', self.html)
        self.assertIn("research:'ravensec'", self.html)
        self.assertIn("tools:'terminal'", self.html)

    def test_no_dead_chrome(self):
        # Controls without a backend were removed instead of shipped as inert buttons;
        # "New Task" now starts an AI Agent task.
        for marker in ("Voice input — not implemented",
                       "Task creation is not implemented",
                       "Add attachment — not implemented",
                       "Attach file — not implemented",
                       'class="chat-mic"'):
            self.assertNotIn(marker, self.html)
        self.assertIn('class="btn-new-task" onclick="newAgentTask()"', self.html)
        self.assertIn("newAgentTask:newAgentTask", self.html)

    def test_window_buttons_are_wired(self):
        # Title-bar buttons call the pywebview js_api (launch._WindowApi) and are
        # hidden in a plain browser, where they could not work.
        for name in ("'minimize'", "'toggle_maximize'", "'close_window'"):
            self.assertIn(name, self.html)
        self.assertIn(".has-native-window .wbtns", self.html)

    def test_gear_is_wired_to_settings(self):
        self.assertIn("class=\"btn-gear\" onclick=\"navigateTo('settings')\"", self.html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
