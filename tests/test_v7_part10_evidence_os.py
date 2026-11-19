"""Part 10 — Evidence Graph / PoC / Reporting tests."""
import json
import pytest
import sqlite3
from raven.evidence_os import (
    EvidenceGraph, EvidenceNode, EvidenceEdge, EvidenceNodeKind,
    PoCBuilder, PoCEntry, PoCStatus,
    ReportEngine, ReportSection, ReportOutput, ReportFormat,
    register_evidence_tools,
)
from raven.evidence_os.poc import PoCStep
from raven.runtime.tools import ToolRegistry


def _db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


# ══════════════════════════════════════════════════════════════════════════
# EvidenceNode invariants
# ══════════════════════════════════════════════════════════════════════════

class TestEvidenceNodeInvariants:
    def test_is_advisory_always_true(self):
        n = EvidenceNode()
        assert n.is_advisory is True

    def test_is_advisory_immutable(self):
        n = EvidenceNode()
        with pytest.raises(AttributeError):
            n.is_advisory = False

    def test_to_dict_advisory(self):
        n = EvidenceNode(label="test")
        assert n.to_dict()["is_advisory"] is True


# ══════════════════════════════════════════════════════════════════════════
# EvidenceGraph
# ══════════════════════════════════════════════════════════════════════════

class TestEvidenceGraph:
    def test_add_and_get_node(self):
        g = EvidenceGraph(_db())
        n = EvidenceNode(kind=EvidenceNodeKind.REQUEST, label="GET /api/users")
        g.add_node(n)
        retrieved = g.get_node(n.node_id)
        assert retrieved is not None
        assert retrieved.label == "GET /api/users"

    def test_count_nodes(self):
        g = EvidenceGraph(_db())
        g.add_node(EvidenceNode(label="A"))
        g.add_node(EvidenceNode(label="B"))
        assert g.count_nodes() == 2

    def test_count_nodes_by_workspace(self):
        g = EvidenceGraph(_db())
        g.add_node(EvidenceNode(label="A", workspace_id="ws1"))
        g.add_node(EvidenceNode(label="B", workspace_id="ws2"))
        assert g.count_nodes("ws1") == 1

    def test_add_edge_and_get_neighbors(self):
        g = EvidenceGraph(_db())
        req  = EvidenceNode(kind=EvidenceNodeKind.REQUEST, label="REQ")
        resp = EvidenceNode(kind=EvidenceNodeKind.RESPONSE, label="RESP")
        g.add_node(req)
        g.add_node(resp)
        g.add_edge(EvidenceEdge(src_id=req.node_id, dst_id=resp.node_id, relation="follows"))
        neighbors = g.get_neighbors(req.node_id)
        assert len(neighbors) == 1
        assert neighbors[0].node_id == resp.node_id

    def test_get_neighbors_by_relation(self):
        g = EvidenceGraph(_db())
        n1 = EvidenceNode(label="N1"); n2 = EvidenceNode(label="N2"); n3 = EvidenceNode(label="N3")
        g.add_node(n1); g.add_node(n2); g.add_node(n3)
        g.add_edge(EvidenceEdge(src_id=n1.node_id, dst_id=n2.node_id, relation="supports"))
        g.add_edge(EvidenceEdge(src_id=n1.node_id, dst_id=n3.node_id, relation="contradicts"))
        supports = g.get_neighbors(n1.node_id, relation="supports")
        assert len(supports) == 1
        assert supports[0].node_id == n2.node_id

    def test_count_edges(self):
        g = EvidenceGraph(_db())
        n1 = EvidenceNode(label="N1"); n2 = EvidenceNode(label="N2")
        g.add_node(n1); g.add_node(n2)
        g.add_edge(EvidenceEdge(src_id=n1.node_id, dst_id=n2.node_id))
        assert g.count_edges() == 1

    def test_list_nodes_by_kind(self):
        g = EvidenceGraph(_db())
        g.add_node(EvidenceNode(kind=EvidenceNodeKind.FINDING, label="F"))
        g.add_node(EvidenceNode(kind=EvidenceNodeKind.NOTE, label="N"))
        findings = g.list_nodes(kind=EvidenceNodeKind.FINDING)
        assert len(findings) == 1
        assert findings[0].label == "F"

    def test_get_node_returns_none_for_missing(self):
        g = EvidenceGraph(_db())
        assert g.get_node("nonexistent") is None

    def test_nodes_have_is_advisory_true_after_roundtrip(self):
        g = EvidenceGraph(_db())
        n = EvidenceNode(label="test")
        g.add_node(n)
        retrieved = g.get_node(n.node_id)
        assert retrieved.is_advisory is True


# ══════════════════════════════════════════════════════════════════════════
# PoCEntry invariants
# ══════════════════════════════════════════════════════════════════════════

class TestPoCEntryInvariants:
    def test_is_advisory_always_true(self):
        poc = PoCEntry()
        assert poc.is_advisory is True

    def test_is_advisory_immutable(self):
        poc = PoCEntry()
        with pytest.raises(AttributeError):
            poc.is_advisory = False

    def test_to_dict_advisory(self):
        poc = PoCEntry(title="test")
        assert poc.to_dict()["is_advisory"] is True

    def test_default_status_draft(self):
        poc = PoCEntry()
        assert poc.status == PoCStatus.DRAFT


# ══════════════════════════════════════════════════════════════════════════
# PoCBuilder
# ══════════════════════════════════════════════════════════════════════════

class TestPoCBuilder:
    def test_create_returns_poc(self):
        builder = PoCBuilder()
        poc = builder.create("f1", "Test PoC", "Summary")
        assert poc is not None
        assert poc.is_advisory is True
        assert poc.finding_id == "f1"

    def test_get_poc(self):
        builder = PoCBuilder()
        poc = builder.create("f1", "T", "S")
        retrieved = builder.get(poc.poc_id)
        assert retrieved is poc

    def test_list_for_finding(self):
        builder = PoCBuilder()
        builder.create("f1", "T1", "S1")
        builder.create("f1", "T2", "S2")
        builder.create("f2", "T3", "S3")
        results = builder.list_for_finding("f1")
        assert len(results) == 2

    def test_add_step(self):
        builder = PoCBuilder()
        poc = builder.create("f1", "T", "S")
        step = PoCStep(step_num=1, description="Navigate to /admin", expected="403")
        builder.add_step(poc.poc_id, step)
        assert len(poc.steps) == 1

    def test_add_step_unknown_poc_returns_false(self):
        builder = PoCBuilder()
        assert builder.add_step("nonexistent", PoCStep()) is False

    def test_count(self):
        builder = PoCBuilder()
        builder.create("f1", "T1", "S1")
        builder.create("f2", "T2", "S2")
        assert builder.count() == 2

    def test_list_all_by_workspace(self):
        builder = PoCBuilder()
        builder.create("f1", "T1", "S1", workspace_id="ws1")
        builder.create("f2", "T2", "S2", workspace_id="ws2")
        assert len(builder.list_all("ws1")) == 1
        assert len(builder.list_all()) == 2


# ══════════════════════════════════════════════════════════════════════════
# ReportOutput invariants
# ══════════════════════════════════════════════════════════════════════════

class TestReportOutputInvariants:
    def test_is_advisory_always_true(self):
        r = ReportOutput()
        assert r.is_advisory is True

    def test_is_advisory_immutable(self):
        r = ReportOutput()
        with pytest.raises(AttributeError):
            r.is_advisory = False


# ══════════════════════════════════════════════════════════════════════════
# ReportEngine
# ══════════════════════════════════════════════════════════════════════════

class TestReportEngine:
    def test_generate_empty_findings(self):
        engine = ReportEngine()
        report = engine.generate_from_findings([])
        assert report.is_advisory is True
        assert engine.count() == 1

    def test_generate_with_findings(self):
        engine = ReportEngine()
        findings = [
            {"finding_id": "f1", "category": "ACCESS_CONTROL",
             "title": "BOLA candidate", "description": "Object ID enumerable"},
            {"finding_id": "f2", "category": "AUTH",
             "title": "JWT weak", "description": "alg:none accepted"},
        ]
        report = engine.generate_from_findings(findings)
        assert len(report.sections) >= 3  # summary + 2 findings + disclaimer
        assert report.is_advisory is True

    def test_render_markdown_contains_advisory_warning(self):
        engine = ReportEngine()
        report = engine.generate_from_findings(
            [{"finding_id": "f1", "category": "X", "title": "T", "description": "D"}],
            fmt=ReportFormat.MARKDOWN,
        )
        rendered = report.render()
        assert "ADVISORY" in rendered or "advisory" in rendered.lower()
        assert "human verification" in rendered.lower()

    def test_render_json_is_valid(self):
        engine = ReportEngine()
        report = engine.generate_from_findings([], fmt=ReportFormat.JSON)
        parsed = json.loads(report.render())
        assert parsed["is_advisory"] is True

    def test_render_text_format(self):
        engine = ReportEngine()
        report = engine.generate_from_findings([], fmt=ReportFormat.TEXT)
        text = report.render()
        assert "ADVISORY" in text

    def test_get_report_by_id(self):
        engine = ReportEngine()
        report = engine.generate_from_findings([])
        retrieved = engine.get(report.report_id)
        assert retrieved is report

    def test_list_all_by_workspace(self):
        engine = ReportEngine()
        engine.generate_from_findings([], workspace_id="ws1")
        engine.generate_from_findings([], workspace_id="ws2")
        assert len(engine.list_all("ws1")) == 1
        assert len(engine.list_all()) == 2

    def test_disclaimer_section_present(self):
        engine = ReportEngine()
        report = engine.generate_from_findings([])
        kinds = [s.kind for s in report.sections]
        assert "general" in kinds


# ══════════════════════════════════════════════════════════════════════════
# Tool registry integration
# ══════════════════════════════════════════════════════════════════════════

class TestEvidenceToolRegistry:
    def test_registers_tools(self):
        registry = ToolRegistry()
        count = register_evidence_tools(registry)
        assert count == 5

    def test_all_tools_listed(self):
        registry = ToolRegistry()
        register_evidence_tools(registry)
        ids = {t.tool_id for t in registry.list_all()}
        assert "evidence.node.add" in ids
        assert "evidence.node.list" in ids
        assert "evidence.edge.add" in ids
        assert "evidence.poc.create" in ids
        assert "evidence.report.generate" in ids

    def test_registered_tools_have_schemas(self):
        registry = ToolRegistry()
        register_evidence_tools(registry)
        for t in registry.list_all():
            if t.tool_id.startswith("evidence"):
                assert t.input_schema is not None


# ══════════════════════════════════════════════════════════════════════════
# Security invariants
# ══════════════════════════════════════════════════════════════════════════

class TestEvidenceOsSecurityInvariants:
    def test_evidence_node_never_auto_confirms_finding(self):
        n = EvidenceNode(kind=EvidenceNodeKind.FINDING, label="BOLA candidate")
        assert n.is_advisory is True
        with pytest.raises(AttributeError):
            n.is_advisory = False

    def test_poc_always_advisory_regardless_of_steps(self):
        builder = PoCBuilder()
        poc = builder.create("f1", "BOLA PoC", "Detailed steps")
        for i in range(5):
            builder.add_step(poc.poc_id, PoCStep(step_num=i, description=f"Step {i}"))
        assert poc.is_advisory is True

    def test_report_never_confirms_vulnerability(self):
        engine = ReportEngine()
        findings = [
            {"finding_id": "f1", "category": "ACCESS_CONTROL",
             "title": "BOLA", "description": "User A accesses User B data"},
        ]
        report = engine.generate_from_findings(findings)
        rendered = report.render()
        assert "confirmed" not in rendered.lower() or "unverified" in rendered.lower() or "candidate" in rendered.lower()
        assert report.is_advisory is True
