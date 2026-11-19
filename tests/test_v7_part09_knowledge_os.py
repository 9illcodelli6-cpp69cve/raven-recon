"""Part 09 — Knowledge OS / Self-Learning tests."""
import pytest
import sqlite3
from raven.knowledge_os import (
    KnowledgeBase, KnowledgeEntry, KnowledgeKind,
    LearningEngine, Lesson,
    TechniqueLibrary, Technique, TechniqueCategory,
    register_knowledge_tools,
)
from raven.runtime.tools import ToolRegistry


# ── helpers ────────────────────────────────────────────────────────────────

def _db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


# ══════════════════════════════════════════════════════════════════════════
# KnowledgeEntry invariants
# ══════════════════════════════════════════════════════════════════════════

class TestKnowledgeEntryInvariants:
    def test_human_reviewed_labels_always_zero(self):
        entry = KnowledgeEntry()
        assert entry.human_reviewed_labels == 0

    def test_human_reviewed_labels_immutable(self):
        entry = KnowledgeEntry()
        with pytest.raises(AttributeError):
            entry.human_reviewed_labels = 1

    def test_human_reviewed_labels_immutable_zero_assignment(self):
        entry = KnowledgeEntry()
        with pytest.raises(AttributeError):
            entry.human_reviewed_labels = 0

    def test_to_dict_always_zero(self):
        entry = KnowledgeEntry(title="test", body="body")
        d = entry.to_dict()
        assert d["human_reviewed_labels"] == 0

    def test_defaults_sensible(self):
        e = KnowledgeEntry(title="T", body="B")
        assert e.kind == KnowledgeKind.CONCEPT
        assert e.source == "ai_derived"
        assert 0.0 <= e.confidence <= 1.0


# ══════════════════════════════════════════════════════════════════════════
# KnowledgeBase
# ══════════════════════════════════════════════════════════════════════════

class TestKnowledgeBase:
    def test_store_and_count(self):
        kb = KnowledgeBase(_db())
        kb.store(KnowledgeEntry(title="A", body="body A"))
        kb.store(KnowledgeEntry(title="B", body="body B"))
        assert kb.count() == 2

    def test_search_by_query(self):
        kb = KnowledgeBase(_db())
        kb.store(KnowledgeEntry(title="JWT bypass", body="Signature not verified"))
        kb.store(KnowledgeEntry(title="IDOR pattern", body="Object ID enumeration"))
        results = kb.search(query="JWT")
        assert len(results) == 1
        assert results[0].title == "JWT bypass"

    def test_search_by_kind(self):
        kb = KnowledgeBase(_db())
        kb.store(KnowledgeEntry(title="T1", body="b", kind=KnowledgeKind.TECHNIQUE))
        kb.store(KnowledgeEntry(title="T2", body="b", kind=KnowledgeKind.CONCEPT))
        results = kb.search(kind=KnowledgeKind.TECHNIQUE)
        assert len(results) == 1
        assert results[0].title == "T1"

    def test_search_by_workspace(self):
        kb = KnowledgeBase(_db())
        kb.store(KnowledgeEntry(title="W1", body="b", workspace_id="ws1"))
        kb.store(KnowledgeEntry(title="W2", body="b", workspace_id="ws2"))
        results = kb.search(workspace_id="ws1")
        assert len(results) == 1

    def test_empty_search_returns_all(self):
        kb = KnowledgeBase(_db())
        for i in range(5):
            kb.store(KnowledgeEntry(title=f"E{i}", body=f"body{i}"))
        assert len(kb.search()) == 5

    def test_count_by_workspace(self):
        kb = KnowledgeBase(_db())
        kb.store(KnowledgeEntry(title="A", body="b", workspace_id="ws-x"))
        kb.store(KnowledgeEntry(title="B", body="b", workspace_id="ws-y"))
        assert kb.count("ws-x") == 1
        assert kb.count("ws-y") == 1
        assert kb.count() == 2

    def test_store_returns_entry_id(self):
        kb = KnowledgeBase(_db())
        e = KnowledgeEntry(title="X", body="Y")
        eid = kb.store(e)
        assert eid == e.entry_id

    def test_search_returns_knowledge_entry_objects(self):
        kb = KnowledgeBase(_db())
        kb.store(KnowledgeEntry(title="test entry", body="content", tags=["a", "b"]))
        results = kb.search(query="test")
        assert isinstance(results[0], KnowledgeEntry)
        assert results[0].human_reviewed_labels == 0

    def test_upsert_replaces(self):
        kb = KnowledgeBase(_db())
        e = KnowledgeEntry(title="orig", body="body")
        kb.store(e)
        e2 = KnowledgeEntry(entry_id=e.entry_id, title="updated", body="new")
        kb.store(e2)
        results = kb.search(query="updated")
        assert len(results) == 1
        assert kb.count() == 1


# ══════════════════════════════════════════════════════════════════════════
# Lesson invariants
# ══════════════════════════════════════════════════════════════════════════

class TestLessonInvariants:
    def test_is_advisory_always_true(self):
        lesson = Lesson()
        assert lesson.is_advisory is True

    def test_is_advisory_not_settable(self):
        lesson = Lesson()
        with pytest.raises((AttributeError, TypeError)):
            lesson.is_advisory = False


# ══════════════════════════════════════════════════════════════════════════
# LearningEngine
# ══════════════════════════════════════════════════════════════════════════

class TestLearningEngine:
    def test_record_lesson_persists(self):
        kb = KnowledgeBase(_db())
        engine = LearningEngine(kb)
        lesson = Lesson(title="IDOR pattern found", summary="Two users, different IDs")
        engine.record_lesson(lesson)
        assert kb.count() == 1

    def test_synthesize_from_empty_findings(self):
        kb = KnowledgeBase(_db())
        engine = LearningEngine(kb)
        lesson = engine.synthesize_from_findings([])
        assert lesson.confidence == 0.0
        assert lesson.is_advisory is True

    def test_synthesize_from_findings(self):
        kb = KnowledgeBase(_db())
        engine = LearningEngine(kb)
        findings = [
            {"finding_id": "f1", "category": "ACCESS_CONTROL"},
            {"finding_id": "f2", "category": "AUTH"},
        ]
        lesson = engine.synthesize_from_findings(findings)
        assert lesson.is_advisory is True
        assert "2" in lesson.title
        assert len(lesson.source_ids) == 2

    def test_recall_relevant(self):
        kb = KnowledgeBase(_db())
        engine = LearningEngine(kb)
        lesson = Lesson(title="BOLA pattern", summary="Object ID in path parameter")
        engine.record_lesson(lesson)
        results = engine.recall_relevant("BOLA")
        assert len(results) >= 1

    def test_synthesized_lesson_tags_include_categories(self):
        kb = KnowledgeBase(_db())
        engine = LearningEngine(kb)
        findings = [{"finding_id": "f1", "category": "INJECTION"}]
        lesson = engine.synthesize_from_findings(findings)
        assert "INJECTION" in lesson.tags


# ══════════════════════════════════════════════════════════════════════════
# TechniqueLibrary
# ══════════════════════════════════════════════════════════════════════════

class TestTechniqueLibrary:
    def test_builtin_techniques_loaded(self):
        lib = TechniqueLibrary()
        assert lib.count() >= 4

    def test_builtin_all_advisory(self):
        lib = TechniqueLibrary()
        for t in lib.search():
            assert t.is_advisory is True

    def test_get_by_id(self):
        lib = TechniqueLibrary()
        t = lib.get("AC-001")
        assert t is not None
        assert t.category == TechniqueCategory.ACCESS_CONTROL

    def test_search_by_query(self):
        lib = TechniqueLibrary()
        results = lib.search(query="JWT")
        assert len(results) >= 1
        assert results[0].tech_id == "AUTH-001"

    def test_search_by_category(self):
        lib = TechniqueLibrary()
        results = lib.search(category=TechniqueCategory.RECON)
        assert len(results) >= 1
        for t in results:
            assert t.category == TechniqueCategory.RECON

    def test_add_custom_technique(self):
        lib = TechniqueLibrary()
        before = lib.count()
        t = Technique(
            tech_id="CUSTOM-001",
            name="Custom Test",
            category=TechniqueCategory.CONFIG,
            description="Test technique",
        )
        lib.add(t)
        assert lib.count() == before + 1
        assert lib.get("CUSTOM-001") is t

    def test_technique_to_dict(self):
        lib = TechniqueLibrary()
        d = lib.get("RECON-001").to_dict()
        assert d["is_advisory"] is True
        assert "tech_id" in d

    def test_get_nonexistent_returns_none(self):
        lib = TechniqueLibrary()
        assert lib.get("FAKE-999") is None


# ══════════════════════════════════════════════════════════════════════════
# Tool Registry integration
# ══════════════════════════════════════════════════════════════════════════

class TestKnowledgeToolRegistry:
    def test_registers_tools(self):
        registry = ToolRegistry()
        count = register_knowledge_tools(registry)
        assert count == 4

    def test_all_tools_listed(self):
        registry = ToolRegistry()
        register_knowledge_tools(registry)
        ids = {t.tool_id for t in registry.list_all()}
        assert "knowledge.search" in ids
        assert "knowledge.store" in ids
        assert "knowledge.technique.search" in ids
        assert "knowledge.lesson.synthesize" in ids

    def test_registered_tools_have_schemas(self):
        registry = ToolRegistry()
        register_knowledge_tools(registry)
        for t in registry.list_all():
            if t.tool_id.startswith("knowledge"):
                assert t.input_schema is not None


# ══════════════════════════════════════════════════════════════════════════
# Security invariants across module
# ══════════════════════════════════════════════════════════════════════════

class TestKnowledgeOsSecurityInvariants:
    def test_knowledge_entry_cannot_be_marked_human_reviewed(self):
        e = KnowledgeEntry(source="ai_derived")
        with pytest.raises(AttributeError):
            e.human_reviewed_labels = 5

    def test_lesson_output_always_advisory(self):
        lessons = [
            Lesson(title="L1", summary="s"),
            Lesson(confidence=0.99),
            Lesson(title="perfect result", summary="no error found"),
        ]
        for lesson in lessons:
            assert lesson.is_advisory is True

    def test_technique_always_advisory(self):
        lib = TechniqueLibrary()
        for t in lib.search():
            assert t.is_advisory is True
        custom = Technique(
            tech_id="TEST-SEC",
            name="Security test",
            category=TechniqueCategory.INJECTION,
            description="Test",
        )
        assert custom.is_advisory is True

    def test_ai_derived_entries_not_treated_as_ground_truth(self):
        kb = KnowledgeBase(_db())
        e = KnowledgeEntry(
            title="AI finding",
            body="Possible BOLA",
            source="ai_derived",
            confidence=0.9,
        )
        kb.store(e)
        results = kb.search(query="BOLA")
        assert results[0].human_reviewed_labels == 0
        assert results[0].source == "ai_derived"
