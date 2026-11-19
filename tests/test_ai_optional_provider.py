"""Wave 13 (A13-NATIVE) — the Ollama provider is OPTIONAL, OFF by default, honest.

Proves the no-runtime-generative-dependency contract:
  * provider OFF (default) => _ensure_ai registers ZERO providers and the Ollama
    adapter is never even constructed (NO network / NO localhost:11434 probe);
  * /api/chat with no native model + provider OFF => typed HTTP 503 with error_code
    NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE, no fabricated `response`, and BOTH turns
    persisted to the conversation store;
  * provider enabled-but-unreachable => honest PROVIDER_UNAVAILABLE, no fabricated text;
  * AI status is honest (DISABLED by default; third_party/adapter_enabled labeled);
  * the RAVEN_ENABLE_OLLAMA env var is honored.

All adapters are faked — no real Ollama/external host is ever contacted.

Run:  python -m pytest tests/test_ai_optional_provider.py -q
"""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from raven.api import server
from raven.runtime.model import (
    ModelService, ProviderStatus, CompletionResult, ModelFailureKind,
)
from raven.runtime.conversation import ConversationContext


class _Tripwire:
    """Stand-in for OllamaAdapter that RECORDS any construction/probe/network attempt.
    If the default (OFF) path ever touches it, the recorded calls make the test fail."""
    calls = []

    def __init__(self, *a, **k):
        _Tripwire.calls.append(("ctor", a, k))

    def health_check(self):
        _Tripwire.calls.append(("health_check",))
        return ProviderStatus.AVAILABLE

    def discover_models(self):
        _Tripwire.calls.append(("discover_models",))
        return []

    def complete(self, messages, model_id, **k):
        _Tripwire.calls.append(("complete",))
        return CompletionResult(content="SHOULD-NOT-HAPPEN", model_id=model_id,
                                provider_id="ollama")


class _DownAdapter:
    """Enabled external provider that is unreachable — fails honestly, no network."""
    def __init__(self, *a, **k):
        pass

    def health_check(self):
        return ProviderStatus.UNAVAILABLE

    def discover_models(self):
        return []

    def complete(self, messages, model_id, **k):
        return CompletionResult(content="", model_id=model_id or "qwen2.5-coder:latest",
                                provider_id="ollama",
                                failure=ModelFailureKind.PROVIDER_UNAVAILABLE)


class _AIStateBase(unittest.TestCase):
    def setUp(self):
        _Tripwire.calls = []
        self._tmp = tempfile.mkdtemp(prefix="raven-a13-")
        self._saved = {
            "_AI_SVC": server._AI_SVC,
            "_AI_CONV": server._AI_CONV,
            "DATA_ROOT": server.DATA_ROOT,
            "settings": dict(server._RAVEN_SETTINGS),
            "ensure_ai": server._ensure_ai,
            "env": os.environ.get("RAVEN_ENABLE_OLLAMA"),
        }
        self._saved_sessions = dict(server._CHAT_SESSIONS)
        with server._CHAT_LOCK:
            server._AI_SVC = None
            server._AI_CONV = None
            server._CHAT_SESSIONS.clear()
        server.DATA_ROOT = Path(self._tmp)
        server._RAVEN_SETTINGS["enable_external_llm"] = False
        os.environ.pop("RAVEN_ENABLE_OLLAMA", None)

    def tearDown(self):
        with server._CHAT_LOCK:
            server._AI_SVC = self._saved["_AI_SVC"]
            server._AI_CONV = self._saved["_AI_CONV"]
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


class ProviderOffByDefault(_AIStateBase):
    def test_ensure_ai_registers_no_provider_and_makes_no_ollama_call(self):
        with patch.object(server, "OllamaAdapter", _Tripwire):
            svc, ctx = server._ensure_ai()
        self.assertEqual(svc.list_providers(), [],
                         "provider OFF by default => zero providers registered")
        self.assertEqual(_Tripwire.calls, [],
                         "OFF path must never construct/probe the Ollama adapter (no network)")

    def test_status_is_disabled_and_honest_by_default(self):
        with patch.object(server, "OllamaAdapter", _Tripwire):
            st = server._ai_status_dict()
        self.assertEqual(st["native_generative_model"], "none")
        self.assertFalse(st["adapter_enabled"])
        self.assertFalse(st["third_party"])
        self.assertFalse(st["configured"])
        self.assertEqual(st["status"], "DISABLED")
        self.assertEqual(_Tripwire.calls, [], "status probe must not touch Ollama when OFF")

    def test_external_llm_disabled_helper(self):
        self.assertFalse(server._external_llm_enabled())

    def test_env_var_enables_provider(self):
        os.environ["RAVEN_ENABLE_OLLAMA"] = "1"
        self.assertTrue(server._external_llm_enabled())


class ChatHonestWhenNoNativeModel(_AIStateBase):
    """/api/chat with no native model + provider OFF: typed, honest, persisted."""

    def setUp(self):
        super().setUp()
        self._db = sqlite3.connect(":memory:", check_same_thread=False)
        self._ctx = ConversationContext(self._db)
        self._svc = ModelService()                       # no providers registered
        server._ensure_ai = lambda: (self._svc, self._ctx)

    def tearDown(self):
        server._CHAT_SESSIONS.pop("a13-sess", None)
        self._db.close()
        super().tearDown()

    def test_chat_returns_native_model_not_available_code(self):
        data, code = server.api_chat({"message": "hello", "session_id": "a13-sess"})
        self.assertEqual(code, 503)
        self.assertEqual(data.get("error_code"), "NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE")
        self.assertTrue(data["error"].startswith("[Native generative model unavailable"), data)
        self.assertNotIn("response", data)               # NEVER fabricate assistant text

    def test_chat_persists_both_turns(self):
        server.api_chat({"message": "hello", "session_id": "a13-sess"})
        rows = self._db.execute("SELECT role, content FROM v7_messages").fetchall()
        contents = [c for _, c in rows]
        self.assertEqual(len(rows), 2, "user + assistant turn persisted")
        self.assertIn("hello", contents)
        self.assertTrue(any(c.startswith("[Native generative model unavailable")
                            for c in contents),
                        "assistant turn is the honest typed marker, not fabricated")


class EnabledButUnreachableFailsHonestly(_AIStateBase):
    def test_enabled_down_provider_returns_provider_unavailable(self):
        server._RAVEN_SETTINGS["enable_external_llm"] = True
        with patch.object(server, "OllamaAdapter", _DownAdapter):
            # _ensure_ai registers the (down) provider; no real network via the fake.
            data, code = server.api_chat({"message": "hi", "session_id": "a13-down"})
        try:
            self.assertEqual(code, 503)
            self.assertEqual(data.get("error_code"), "PROVIDER_UNAVAILABLE")
            self.assertTrue(data["error"].startswith("[Model unavailable"), data)
            self.assertNotIn("response", data)           # no fabricated text
        finally:
            server._CHAT_SESSIONS.pop("a13-down", None)

    def test_status_ready_when_enabled_and_available(self):
        server._RAVEN_SETTINGS["enable_external_llm"] = True

        class _UpAdapter(_DownAdapter):
            def health_check(self):
                return ProviderStatus.AVAILABLE

            def discover_models(self):
                from raven.runtime.model import ModelDefinition, ModelCapability, ModelStatus
                return [ModelDefinition(model_id="demo:latest", provider_id="ollama",
                                        display_name="demo", status=ModelStatus.READY,
                                        capabilities=[ModelCapability.CHAT])]

        with patch.object(server, "OllamaAdapter", _UpAdapter):
            st = server._ai_status_dict()
        self.assertTrue(st["adapter_enabled"])
        self.assertTrue(st["third_party"])
        self.assertEqual(st["provider_kind"], "third_party")
        self.assertEqual(st["native_generative_model"], "none")
        self.assertEqual(st["status"], "READY")
        self.assertTrue(st["configured"])
        self.assertEqual(st["model"], "demo:latest")


class ComprehensiveStatusShapePreserved(_AIStateBase):
    """The golden api_comprehensive_status 'ai' sub-dict keeps its exact 7-key shape
    even though _ai_status_dict now carries honest extra fields."""

    def test_ai_subdict_keys_unchanged(self):
        fake_term = lambda: {"available": False, "shells": {}}
        with patch.object(server, "OllamaAdapter", _Tripwire), \
             patch.object(server, "api_terminal_status", fake_term):
            s = server.api_comprehensive_status()
        self.assertEqual(set(s["ai"]),
                         {"system", "configured", "available", "foundation_model",
                          "provider", "provider_display", "display"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
