"""Phase-4 (P4-NATIVE-CHAT) — the native RAVEN-LM model is a REAL, selectable,
first-party chat path wired into the LIVE product, wired HONESTLY.

Proves end-to-end, against the running server's own handlers (no HTTP server, no
Ollama, no network):

  * the §16 registry's native checkpoint is LISTED by /api/v7/native/models with its
    honest maturity (EXPERIMENTAL_BOOTSTRAP);
  * DEFAULT path (nothing selected, Ollama off) is UNCHANGED — /api/chat returns the
    typed 503 NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE with NO fabricated `response`
    (the chat golden invariant), and _ai_status_dict is honest DISABLED;
  * SELECTING the shipped checkpoint (raven-lm-nativerun-becb1f3c9975) loads it LOCALLY
    and routes /api/chat through RAVEN's OWN inference: a REAL native generation comes
    back (provider == raven_native, NOT ollama), TAGGED with maturity, with ZERO network
    (asserted with a hard socket guard) — never fabricated, never Claude-class;
  * _ai_status_dict then reports the active native model + maturity honestly, while
    `native_generative_model` stays "none" (shipped flag) and the honesty constant
    raven.native_ai.NATIVE_GENERATIVE_MODEL stays None;
  * deselecting returns the product to the honest unavailable state;
  * an unknown model id is refused with a typed error (no silent/fabricated success).

SAFE_DESKTOP: threads capped (<=4), bounded tokens/timeout via the provider defaults.

Run:  python -m pytest tests/test_native_chat_integration.py -q
"""
import pytest

torch = pytest.importorskip("torch", reason="local-AI tests need PyTorch (see requirements-ai.txt)")

import os
import socket
import sqlite3
import tempfile
import unittest
from pathlib import Path

import torch

import raven.native_ai as native_ai
from raven.api import server
from raven.runtime.model import NATIVE_PROVIDER_ID

torch.set_num_threads(4)

# The shipped bootstrap checkpoint (reconstruction/native_ai/MODEL_MANIFEST.md).
_NATIVE_MODEL_ID = "raven-lm-nativerun-becb1f3c9975"


def _checkpoint_present() -> bool:
    try:
        reg = server._native_registry()
        e = reg.get(_NATIVE_MODEL_ID)
        if e is None:
            return False
        return server._resolve_native_checkpoint(e).exists()
    except Exception:
        return False


@unittest.skipUnless(_checkpoint_present(),
                     "shipped native checkpoint not present (models/native/)")
class NativeChatIntegration(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="raven-p4-native-")
        self._saved = {
            "_AI_SVC": server._AI_SVC,
            "_AI_CONV": server._AI_CONV,
            "DATA_ROOT": server.DATA_ROOT,
            "settings": dict(server._RAVEN_SETTINGS),
            "native_sel": server._NATIVE_SELECTED_MODEL_ID,
            "ensure_ai": server._ensure_ai,
            "env": os.environ.get("RAVEN_ENABLE_OLLAMA"),
        }
        self._saved_sessions = dict(server._CHAT_SESSIONS)
        with server._CHAT_LOCK:
            server._AI_SVC = None
            server._AI_CONV = None
            server._NATIVE_SELECTED_MODEL_ID = None
            server._CHAT_SESSIONS.clear()
        server.DATA_ROOT = Path(self._tmp)                 # conversations.db in temp
        server._RAVEN_SETTINGS["enable_external_llm"] = False   # Ollama OFF
        os.environ.pop("RAVEN_ENABLE_OLLAMA", None)

    def tearDown(self):
        with server._CHAT_LOCK:
            server._AI_SVC = self._saved["_AI_SVC"]
            server._AI_CONV = self._saved["_AI_CONV"]
            server._NATIVE_SELECTED_MODEL_ID = self._saved["native_sel"]
            server._CHAT_SESSIONS.clear()
            server._CHAT_SESSIONS.update(self._saved_sessions)
        server.DATA_ROOT = self._saved["DATA_ROOT"]
        server._RAVEN_SETTINGS.clear()
        server._RAVEN_SETTINGS.update(self._saved["settings"])
        server._ensure_ai = self._saved["ensure_ai"]
        if self._saved["env"] is None:
            os.environ.pop("RAVEN_ENABLE_OLLAMA", None)
        else:
            os.environ["RAVEN_ENABLE_OLLAMA"] = self._saved["env"]

    # -- listing ---------------------------------------------------------------

    def test_native_checkpoint_is_listed_with_honest_maturity(self):
        data, code = server.api_native_models_list()
        self.assertEqual(code, 200)
        self.assertTrue(data.get("first_party"))
        ids = {m["model_id"]: m for m in data["models"]}
        self.assertIn(_NATIVE_MODEL_ID, ids)
        m = ids[_NATIVE_MODEL_ID]
        self.assertEqual(m["maturity"], "EXPERIMENTAL_BOOTSTRAP")
        self.assertGreater(m["parameter_count"], 0)
        self.assertIn("experimental bootstrap", data.get("caution", ""))

    # -- default path unchanged (chat golden invariant) ------------------------

    def test_default_path_is_honest_unavailable_no_fabrication(self):
        # Nothing selected + Ollama off → the DEFAULT product state is unchanged.
        db = sqlite3.connect(":memory:", check_same_thread=False)
        from raven.runtime.conversation import ConversationContext
        from raven.runtime.model import ModelService
        ctx = ConversationContext(db)
        svc = ModelService()                           # zero providers
        server._ensure_ai = lambda: (svc, ctx)
        try:
            data, code = server.api_chat({"message": "hello", "session_id": "p4-def"})
            self.assertEqual(code, 503)
            self.assertEqual(data.get("error_code"),
                             "NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE")
            self.assertNotIn("response", data)         # never fabricate
        finally:
            server._CHAT_SESSIONS.pop("p4-def", None)
            db.close()

    def test_status_disabled_by_default(self):
        st = server._ai_status_dict()
        self.assertEqual(st["native_generative_model"], "none")
        self.assertFalse(st["configured"])
        self.assertEqual(st["status"], "DISABLED")
        self.assertFalse(st["third_party"])

    # -- select → real native generation, zero network -------------------------

    def test_select_then_chat_returns_real_native_generation_zero_network(self):
        sel, code = server.api_native_select({"model_id": _NATIVE_MODEL_ID})
        self.assertEqual(code, 200, sel)
        self.assertEqual(sel["selected"], _NATIVE_MODEL_ID)
        self.assertEqual(sel["maturity"], "EXPERIMENTAL_BOOTSTRAP")

        # Hard socket guard: the chat path must make ZERO network calls (no Ollama/HTTP).
        real_socket = socket.socket

        def _blocked(*a, **k):
            raise AssertionError("native chat path attempted a network socket")

        socket.socket = _blocked
        try:
            data, code = server.api_chat({"message": "An HTTP 200 response ",
                                          "session_id": "p4-native"})
        finally:
            socket.socket = real_socket
            server._CHAT_SESSIONS.pop("p4-native", None)

        self.assertEqual(code, 200, data)
        # A REAL generation (not the honest-unavailable failure, not fabricated).
        self.assertNotIn("error_code", data)
        self.assertIsInstance(data.get("response"), str)
        self.assertGreater(len(data["response"]), 0)
        # First-party native provider — NOT the third-party Ollama path.
        self.assertEqual(data.get("provider"), NATIVE_PROVIDER_ID)
        self.assertNotEqual(data.get("provider"), "ollama")
        # Tagged with its honest maturity.
        self.assertEqual(data.get("maturity"), "EXPERIMENTAL_BOOTSTRAP")

    def test_status_reports_native_model_and_maturity_when_active(self):
        server.api_native_select({"model_id": _NATIVE_MODEL_ID})
        st = server._ai_status_dict()
        self.assertTrue(st["configured"])
        self.assertTrue(st["available"])
        self.assertEqual(st["status"], "READY")
        self.assertEqual(st["display"], "RAVEN Native — EXPERIMENTAL_BOOTSTRAP")
        self.assertEqual(st["provider_kind"], "raven_native")
        self.assertFalse(st["third_party"])
        self.assertEqual(st["model"], _NATIVE_MODEL_ID)
        # Shipped-model flag + honesty constant stay honest.
        self.assertEqual(st["native_generative_model"], "none")
        self.assertIsNone(native_ai.NATIVE_GENERATIVE_MODEL)

    def test_ai_status_keys_are_exactly_the_declared_set_when_native_active(self):
        # Even in the native-active branch, the /api/ai/status wire contract is
        # unchanged (no undeclared keys) — maturity rides in `display`/`model`.
        from raven.api import contracts
        server.api_native_select({"model_id": _NATIVE_MODEL_ID})
        st = server._ai_status_dict()
        allowed = set(contracts.CONTRACTS["GET /api/ai/status"]["required"])
        self.assertEqual(set(st), allowed)

    def test_deselect_returns_to_honest_unavailable(self):
        server.api_native_select({"model_id": _NATIVE_MODEL_ID})
        out, code = server.api_native_select({"model_id": None})
        self.assertEqual(code, 200)
        self.assertIsNone(out["selected"])
        st = server._ai_status_dict()
        self.assertEqual(st["status"], "DISABLED")
        self.assertFalse(st["configured"])

    def test_unknown_model_is_refused_honestly(self):
        out, code = server.api_native_select({"model_id": "does-not-exist"})
        self.assertEqual(code, 404)
        self.assertIn("error", out)
        # The bad id is NOT adopted as the selection.
        self.assertIsNone(server._NATIVE_SELECTED_MODEL_ID)

    def test_native_generative_model_flag_never_flips(self):
        server.api_native_select({"model_id": _NATIVE_MODEL_ID})
        server.api_chat({"message": "status 404", "session_id": "p4-flag"})
        server._CHAT_SESSIONS.pop("p4-flag", None)
        self.assertIsNone(native_ai.NATIVE_GENERATIVE_MODEL)
        self.assertEqual(native_ai.NATIVE_AI_STATUS,
                         "NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
