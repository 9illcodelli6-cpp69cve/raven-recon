"""Part 12 — Full Integration / Adversarial Review tests.

Cross-module security invariant verification and end-to-end pipeline test.
"""
import sqlite3
import pytest

# ── runtime ──────────────────────────────────────────────────────────────
from raven.runtime.model import CompletionResult
from raven.runtime.tasks import TaskBudget
from raven.runtime.tools import ToolRegistry

# ── parts 03-05 ──────────────────────────────────────────────────────────
from raven.ai import ChatSession, MemoryManager

# ── part 06 ──────────────────────────────────────────────────────────────
from raven.source_intel import DnsResult, CertRecord

# ── part 07 ──────────────────────────────────────────────────────────────
from raven.research_engine import CandidateFinding, FindingCategory

# ── part 08 ──────────────────────────────────────────────────────────────
from raven.program_agent import ProgramPolicy, ProgramScope

# ── part 09 ──────────────────────────────────────────────────────────────
from raven.knowledge_os import (
    KnowledgeEntry, KnowledgeBase, KnowledgeKind,
    LearningEngine, Lesson, TechniqueLibrary,
    register_knowledge_tools,
)

# ── part 10 ──────────────────────────────────────────────────────────────
from raven.evidence_os import (
    EvidenceNode, EvidenceGraph, EvidenceNodeKind,
    PoCEntry, PoCBuilder,
    ReportEngine, ReportFormat,
    register_evidence_tools,
)


def _db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


# ══════════════════════════════════════════════════════════════════════════
# Adversarial review: attempt to break every security invariant
# ══════════════════════════════════════════════════════════════════════════

class TestAdversarialInvariants:
    """Attempt to violate each invariant — every attempt must fail."""

    # CompletionResult
    def test_completion_result_is_advisory_immutable(self):
        r = CompletionResult(content="X", model_id="m", provider_id="test")
        assert r.is_advisory is True
        with pytest.raises(AttributeError):
            r.is_advisory = False

    # CandidateFinding
    def test_finding_human_verification_required_immutable(self):
        f = CandidateFinding(title="T", category=FindingCategory.OTHER, description="D")
        assert f.human_verification_required is True
        with pytest.raises(AttributeError):
            f.human_verification_required = False

    def test_finding_security_authority_immutable(self):
        f = CandidateFinding(title="T", category=FindingCategory.OTHER, description="D")
        assert f.security_authority == "NONE"
        with pytest.raises(AttributeError):
            f.security_authority = "RESEARCHER"

    def test_finding_is_verified_immutable(self):
        f = CandidateFinding(title="T", category=FindingCategory.OTHER, description="D")
        assert f.is_verified is False
        with pytest.raises(AttributeError):
            f.is_verified = True

    # ProgramPolicy
    def test_program_policy_external_targets_immutable(self):
        p = ProgramPolicy(program_id="p1", name="Test")
        assert p.external_targets == 0
        with pytest.raises(AttributeError):
            p.external_targets = 1

    # KnowledgeEntry
    def test_knowledge_entry_human_reviewed_labels_immutable(self):
        e = KnowledgeEntry()
        assert e.human_reviewed_labels == 0
        with pytest.raises(AttributeError):
            e.human_reviewed_labels = 1

    # Lesson
    def test_lesson_is_advisory_immutable(self):
        lesson = Lesson()
        assert lesson.is_advisory is True
        with pytest.raises(AttributeError):
            lesson.is_advisory = False

    # EvidenceNode
    def test_evidence_node_is_advisory_immutable(self):
        n = EvidenceNode()
        assert n.is_advisory is True
        with pytest.raises(AttributeError):
            n.is_advisory = False

    # PoCEntry
    def test_poc_is_advisory_immutable(self):
        poc = PoCEntry()
        assert poc.is_advisory is True
        with pytest.raises(AttributeError):
            poc.is_advisory = False

    # ReportOutput
    def test_report_is_advisory_immutable(self):
        from raven.evidence_os.report import ReportOutput
        r = ReportOutput()
        assert r.is_advisory is True
        with pytest.raises(AttributeError):
            r.is_advisory = False

    # Technique
    def test_technique_is_advisory_always_true(self):
        from raven.knowledge_os.technique import Technique, TechniqueCategory
        t = Technique(
            tech_id="ADV-001", name="Adversarial Test",
            category=TechniqueCategory.INJECTION, description="Test",
        )
        assert t.is_advisory is True

    # Try forging human-reviewed label via subclass
    def test_cannot_forge_human_reviewed_via_subclass(self):
        class BadEntry(KnowledgeEntry):
            pass
        e = BadEntry()
        assert e.human_reviewed_labels == 0
        with pytest.raises(AttributeError):
            e.human_reviewed_labels = 99

    # Try forging is_advisory via subclass
    def test_cannot_forge_is_advisory_via_subclass(self):
        class BadNode(EvidenceNode):
            pass
        n = BadNode()
        assert n.is_advisory is True
        with pytest.raises(AttributeError):
            n.is_advisory = False


# ══════════════════════════════════════════════════════════════════════════
# End-to-end pipeline: source intel → finding → evidence → report
# ══════════════════════════════════════════════════════════════════════════

class TestEndToEndPipeline:
    def test_full_research_pipeline(self):
        """
        Simulate a complete RAVEN V7 research session:
        1. Simulate DNS / cert results (source intel)
        2. Create a candidate finding (research engine)
        3. Add it to the evidence graph (evidence OS)
        4. Build a PoC entry
        5. Synthesize a lesson (knowledge OS)
        6. Generate a report
        7. Verify all advisory invariants throughout
        """
        # Step 1: Source intel (simulated — no real network)
        dns = DnsResult(domain="api.example.com")
        assert dns is not None

        # Step 2: Candidate finding
        finding = CandidateFinding(
            title="BOLA Candidate",
            category=FindingCategory.BOLA,
            description="User A can access User B resources by changing ID in path",
            endpoint="https://api.example.com/v1/users/123",
        )
        assert finding.human_verification_required is True
        assert finding.is_verified is False
        assert finding.security_authority == "NONE"

        # Step 3: Evidence graph
        graph = EvidenceGraph(_db())
        request_node = EvidenceNode(
            kind=EvidenceNodeKind.REQUEST,
            label="GET /v1/users/456 as user_a",
            data={"url": "https://api.example.com/v1/users/456", "method": "GET"},
        )
        finding_node = EvidenceNode(
            kind=EvidenceNodeKind.FINDING,
            label=f"BOLA Candidate: {finding.finding_id}",
        )
        graph.add_node(request_node)
        graph.add_node(finding_node)
        from raven.evidence_os.graph import EvidenceEdge
        graph.add_edge(EvidenceEdge(
            src_id=finding_node.node_id, dst_id=request_node.node_id, relation="supports"
        ))
        assert graph.count_nodes() == 2
        assert graph.count_edges() == 1
        # All nodes advisory
        for n in graph.list_nodes():
            assert n.is_advisory is True

        # Step 4: PoC
        builder = PoCBuilder()
        poc = builder.create(
            finding_id=finding.finding_id,
            title="BOLA PoC — Manual Test Steps",
            summary="Authenticate as User A, then attempt to GET /v1/users/<user_b_id>",
        )
        assert poc.is_advisory is True

        # Step 5: Knowledge synthesis
        kb = KnowledgeBase(_db())
        engine = LearningEngine(kb)
        lesson = engine.synthesize_from_findings([
            {
                "finding_id": finding.finding_id,
                "category": finding.category.value,
                "title": finding.title,
            }
        ])
        assert lesson.is_advisory is True
        engine.record_lesson(lesson)
        assert kb.count() == 1

        # Step 6: Report
        report_engine = ReportEngine()
        report = report_engine.generate_from_findings(
            findings=[{
                "finding_id": finding.finding_id,
                "category": finding.category.value,
                "title": finding.title,
                "description": finding.description,
            }],
            title="Test Session Report",
            fmt=ReportFormat.MARKDOWN,
        )
        rendered = report.render()
        assert report.is_advisory is True
        assert "ADVISORY" in rendered or "advisory" in rendered.lower()
        assert "human verification" in rendered.lower()

        # Step 7: Verify no false confirmation anywhere
        assert finding.is_verified is False
        assert finding.human_verification_required is True

    def test_tool_registry_integration(self):
        """All V7 tools register without error."""
        from raven.knowledge_os.registry import register_knowledge_tools
        from raven.evidence_os.registry import register_evidence_tools

        registry = ToolRegistry()
        k = register_knowledge_tools(registry)
        e = register_evidence_tools(registry)
        assert k == 4
        assert e == 5
        all_ids = {t.tool_id for t in registry.list_all()}
        assert "knowledge.search" in all_ids
        assert "knowledge.store" in all_ids
        assert "evidence.node.add" in all_ids
        assert "evidence.report.generate" in all_ids


# ══════════════════════════════════════════════════════════════════════════
# Security regression: confirm no module bypasses invariants
# ══════════════════════════════════════════════════════════════════════════

class TestSecurityRegression:
    def test_all_dataclass_objects_have_is_advisory_true(self):
        objects = [
            CompletionResult(content="x", model_id="m", provider_id="p"),
            Lesson(),
            EvidenceNode(),
            PoCEntry(),
        ]
        for obj in objects:
            assert obj.is_advisory is True, f"{type(obj).__name__}.is_advisory is not True"

    def test_zero_human_reviewed_labels_across_modules(self):
        e = KnowledgeEntry()
        assert e.human_reviewed_labels == 0

    def test_findings_never_verified_by_default(self):
        for _ in range(5):
            f = CandidateFinding(title="T", category=FindingCategory.OTHER, description="D")
            assert f.is_verified is False

    def test_program_policy_external_targets_always_zero(self):
        p = ProgramPolicy(program_id="p", name="P")
        assert p.external_targets == 0

    def test_scope_empty_denies_all(self):
        scope = ProgramScope()   # no items → denies all
        assert scope.is_in_scope("https://example.com") is False
