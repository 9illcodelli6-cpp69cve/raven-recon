"""RAVEN V7 Part 03 — Local AI Chat Tests."""
import sqlite3
import pytest


def fresh_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db


# ── Language Detector ────────────────────────────────────────────────────────

class TestLanguageDetector:
    def test_detect_english(self):
        from raven.ai.multilingual import LanguageDetector, SupportedLanguage
        d = LanguageDetector()
        assert d.detect("Hello, how are you today?") == SupportedLanguage.ENGLISH

    def test_detect_arabic(self):
        from raven.ai.multilingual import LanguageDetector, SupportedLanguage
        d = LanguageDetector()
        assert d.detect("مرحبا، كيف حالك؟") == SupportedLanguage.ARABIC

    def test_detect_arabic_mixed(self):
        from raven.ai.multilingual import LanguageDetector, SupportedLanguage
        d = LanguageDetector()
        assert d.detect("كمل يا RAVEN") == SupportedLanguage.ARABIC

    def test_detect_empty_returns_default(self):
        from raven.ai.multilingual import LanguageDetector, SupportedLanguage
        d = LanguageDetector()
        assert d.detect("") == SupportedLanguage.ENGLISH

    def test_system_prompt_suffix_arabic(self):
        from raven.ai.multilingual import LanguageDetector, SupportedLanguage
        d = LanguageDetector()
        suffix = d.get_system_prompt_suffix(SupportedLanguage.ARABIC)
        assert "العربية" in suffix

    def test_system_prompt_suffix_english_empty(self):
        from raven.ai.multilingual import LanguageDetector, SupportedLanguage
        d = LanguageDetector()
        assert d.get_system_prompt_suffix(SupportedLanguage.ENGLISH) == ""


# ── Self Corrector ────────────────────────────────────────────────────────────

class TestSelfCorrector:
    def test_no_issues_passthrough(self):
        from raven.ai.corrector import SelfCorrector
        c = SelfCorrector(add_disclaimer=False)
        r = c.correct("The endpoint responds with 200 OK.")
        assert not r.was_modified
        assert r.corrections == 0

    def test_overclaim_corrected(self):
        from raven.ai.corrector import SelfCorrector
        c = SelfCorrector(add_disclaimer=False)
        r = c.correct("I confirmed this is vulnerable to SQL injection.")
        assert r.was_modified
        assert r.corrections >= 1
        assert "advisory" in r.corrected.lower() or "human verification" in r.corrected.lower()

    def test_disclaimer_added(self):
        from raven.ai.corrector import SelfCorrector
        c = SelfCorrector(add_disclaimer=True)
        r = c.correct("Some analysis text here.")
        assert "Advisory" in r.corrected or "advisory" in r.corrected

    def test_is_advisory_always_true(self):
        from raven.ai.corrector import CorrectionResult
        cr = CorrectionResult(original="x", corrected="x", is_advisory=False)
        assert cr.is_advisory is True  # __post_init__ enforces it

    def test_needs_correction_detection(self):
        from raven.ai.corrector import SelfCorrector
        c = SelfCorrector()
        assert c.needs_correction("I exploited the endpoint successfully.")
        assert not c.needs_correction("The request returned status 200.")


# ── Memory Manager ────────────────────────────────────────────────────────────

class TestMemoryManager:
    def test_store_and_recall(self):
        from raven.ai.memory import MemoryManager, MemoryEntry
        db = fresh_db()
        mm = MemoryManager(db=db)
        entry = MemoryEntry(
            workspace_id="ws1",
            kind="fact",
            content="Target uses JWT tokens",
            importance=0.8,
        )
        mid = mm.store(entry)
        assert mid == entry.memory_id

        results = mm.recall(workspace_id="ws1")
        assert len(results) == 1
        assert results[0].content == "Target uses JWT tokens"

    def test_recall_by_kind(self):
        from raven.ai.memory import MemoryManager, MemoryEntry
        db = fresh_db()
        mm = MemoryManager(db=db)
        mm.store(MemoryEntry(workspace_id="ws1", kind="fact", content="fact1"))
        mm.store(MemoryEntry(workspace_id="ws1", kind="preference", content="pref1"))

        facts = mm.recall(workspace_id="ws1", kind="fact")
        assert all(m.kind == "fact" for m in facts)

    def test_forget(self):
        from raven.ai.memory import MemoryManager, MemoryEntry
        db = fresh_db()
        mm = MemoryManager(db=db)
        entry = MemoryEntry(workspace_id="ws1", content="temp")
        mm.store(entry)
        assert mm.count(workspace_id="ws1") == 1
        mm.forget(entry.memory_id)
        assert mm.count(workspace_id="ws1") == 0

    def test_count(self):
        from raven.ai.memory import MemoryManager, MemoryEntry
        db = fresh_db()
        mm = MemoryManager(db=db)
        for i in range(5):
            mm.store(MemoryEntry(workspace_id="ws1", content=f"entry {i}"))
        assert mm.count(workspace_id="ws1") == 5
        assert mm.count() == 5


# ── Chat Session ──────────────────────────────────────────────────────────────

class TestChatSession:
    def _make_session(self, response_text="[advisory response]"):
        from raven.ai.chat import ChatSession, ChatConfig
        from raven.runtime.model import ModelService, MockModelAdapter, ModelProvider, ProviderType
        from raven.runtime.conversation import ConversationContext
        db = fresh_db()
        ctx = ConversationContext(db=db)
        model = ModelService()
        model.register_provider(
            ModelProvider(provider_id="mock", provider_type=ProviderType.MOCK, display_name="Mock"),
            MockModelAdapter(fixed_response=response_text),
        )
        cfg = ChatConfig(workspace_id="test-ws")
        return ChatSession(model_service=model, conversation_context=ctx, config=cfg)

    def test_send_returns_response(self):
        session = self._make_session()
        resp = session.send("What is BOLA?")
        assert resp.content
        assert resp.turn == 1
        assert resp.is_advisory is True

    def test_is_advisory_immutable_on_response(self):
        from raven.ai.chat import ChatResponse
        cr = ChatResponse(content="x", session_id="s1", is_advisory=False)
        assert cr.is_advisory is True

    def test_history_grows(self):
        session = self._make_session()
        session.send("Hello")
        session.send("Second message")
        assert len(session.history) == 4  # 2 user + 2 assistant
        assert session.turn == 2

    def test_clear_resets(self):
        session = self._make_session()
        session.send("Hello")
        session.clear()
        assert len(session.history) == 0
        assert session.turn == 0

    def test_model_unavailable_returns_error_message(self):
        from raven.ai.chat import ChatSession, ChatConfig
        from raven.runtime.model import ModelService
        from raven.runtime.conversation import ConversationContext
        db = fresh_db()
        ctx = ConversationContext(db=db)
        model = ModelService()  # no providers
        session = ChatSession(model_service=model, conversation_context=ctx)
        resp = session.send("test")
        assert "unavailable" in resp.content.lower() or "Model" in resp.content
        assert resp.is_advisory is True

    def test_on_response_callback(self):
        collected = []
        from raven.ai.chat import ChatSession, ChatConfig
        from raven.runtime.model import ModelService, MockModelAdapter, ModelProvider, ProviderType
        from raven.runtime.conversation import ConversationContext
        db = fresh_db()
        ctx = ConversationContext(db=db)
        model = ModelService()
        model.register_provider(
            ModelProvider(provider_id="mock", provider_type=ProviderType.MOCK, display_name="Mock"),
            MockModelAdapter(),
        )
        session = ChatSession(
            model_service=model, conversation_context=ctx,
            on_response=lambda r: collected.append(r),
        )
        session.send("ping")
        assert len(collected) == 1
        assert collected[0].is_advisory is True

    def test_get_context_messages(self):
        session = self._make_session()
        session.send("Hello")
        msgs = session.get_context_messages()
        assert len(msgs) == 2
        assert msgs[0]["role"] == "user"
        assert msgs[1]["role"] == "assistant"
