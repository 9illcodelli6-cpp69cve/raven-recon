"""Wave 9 (A9-EVKNOW) — canonical evidence + knowledge write/read paths.

Proves:
- The evidence list no longer TypeErrors: the V7 graph ``list_nodes`` accepts
  ``limit=``, and the canonical ``EvidenceReadModel`` projects real ``recon.db``
  evidence (observations+findings+evidence) into typed nodes + edges.
- Knowledge POST -> GET round-trips SCOPED to the workspace (count agrees).
- A candidate can NOT be auto-verified; adding a NOTE never changes a finding's
  verification status; the only verify path is human (non-automated) ReviewWorkflow.
- ``human_reviewed_labels`` stays the immutable 0 (even when the payload tries to
  set it); source is derived from the ACTOR (AI can't self-claim human_authored);
  AGENT confidence is capped at 0.9.
- ``is_advisory`` is immutable on projected evidence nodes and on lessons.
- The registry handlers are REAL (never ``not_dispatched``); gated writes deny
  when the capability is missing.
"""
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from raven.store import Store
from raven.canonical_service import CanonicalService
from raven.evidence_graph import VALID_RELATIONS
from raven.evidence_os.read_model import EvidenceReadModel
from raven.evidence_os.graph import (
    EvidenceGraph as V7Graph, EvidenceNode, EvidenceNodeKind,
)
from raven.evidence_os.canonical_registry import (
    register_evidence_tools as register_canonical_evidence_tools,
)
from raven.knowledge_os.knowledge_base import KnowledgeBase, KnowledgeKind
from raven.knowledge_os.learning import LearningEngine, Lesson
from raven.knowledge_os.technique import TechniqueLibrary
from raven.knowledge_os.registry import register_knowledge_tools
from raven.runtime.tools import ToolRegistry
from raven.runtime.execution import ActorKind
from raven.runtime.capabilities import CapabilityGate
from raven.security.policy_gate import PolicyGate
from raven.api import evidence_knowledge_handlers as H


def _kb_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


class _Base(unittest.TestCase):
    def setUp(self):
        PolicyGate._reset_emergency_stop_for_test()
        self._tmp = tempfile.mkdtemp()
        self.store = Store(Path(self._tmp))
        # A fresh store has no workspace record yet; mint a canonical id exactly
        # as use_workspace() does (store.get_workspace_id() or uuid4().hex), then
        # CanonicalService.__init__ persists it via ensure_workspace_record.
        self.wid = self.store.get_workspace_id() or uuid.uuid4().hex
        self.svc = CanonicalService(self.store, self.wid, "testws")
        self.kb = KnowledgeBase(_kb_conn())
        self.gate = H.build_evknow_gate(self.wid)

    def tearDown(self):
        try:
            self.store.close()
        except Exception:
            pass


# ── Evidence: limit= fix + read model ─────────────────────────────────────────
class TestEvidenceReadPath(_Base):
    def test_v7_graph_list_nodes_accepts_limit_no_typeerror(self):
        g = V7Graph(_kb_conn())
        g.add_node(EvidenceNode(kind=EvidenceNodeKind.NOTE, label="n1", workspace_id="w"))
        g.add_node(EvidenceNode(kind=EvidenceNodeKind.FINDING, label="f1", workspace_id="w"))
        # The exact call api_evidence_list makes — previously a hard TypeError.
        nodes = g.list_nodes(workspace_id="w", limit=50)
        self.assertEqual(len(nodes), 2)
        # kind= path (Part-10 contract) still works, and limit bounds the result.
        self.assertEqual(len(g.list_nodes(kind=EvidenceNodeKind.FINDING)), 1)
        self.assertEqual(len(g.list_nodes(limit=1)), 1)

    def test_read_model_empty_workspace(self):
        rm = EvidenceReadModel(self.store, self.wid)
        self.assertEqual(rm.list_nodes(), [])
        self.assertEqual(rm.count_nodes(), 0)
        self.assertEqual(rm.list_edges(), [])

    def test_read_model_projects_real_recon_db(self):
        # Seed a real observation so the evidence FK (observation_id ->
        # observations(id)) is satisfied and all four canonical tables are
        # exercised: observation + finding + evidence + relationship.
        obs_id = self.svc.record_send_result(
            {"ok": True, "status": 200, "headers": {}, "body": "x",
             "bytes": 1, "elapsed_ms": 5},
            url="https://example.com/x", method="GET")
        self.assertIsNotNone(obs_id)
        self.svc.record_note_evidence("free-text note", actor="RESEARCHER")
        fid = self.svc.create_candidate_xss_reflection(
            "https://example.com/x", "html", observation_id=obs_id,
        )
        self.assertIsNotNone(fid)
        rm = EvidenceReadModel(self.store, self.wid)
        nodes = rm.list_nodes(limit=50)
        # 2 evidence (note + xss_reflection) + 1 finding + 1 observation
        self.assertEqual(rm.count_nodes(), 4)
        self.assertEqual(len(nodes), 4)
        # Every projected node is advisory and immutable.
        for n in nodes:
            d = n.to_dict()
            self.assertIs(d["is_advisory"], True)
            with self.assertRaises(AttributeError):
                n.is_advisory = False
        kinds = {n.kind.value for n in nodes}
        self.assertIn("finding", kinds)
        self.assertIn("note", kinds)
        # Edges come from the validated V5 relationships (closed vocab, conf in [0,1]).
        edges = rm.list_edges()
        self.assertGreaterEqual(len(edges), 1)
        for e in edges:
            self.assertIn(e["relation"], VALID_RELATIONS)
            self.assertGreaterEqual(e["confidence"], 0.0)
            self.assertLessEqual(e["confidence"], 1.0)

    def test_evidence_list_handler_returns_not_errors(self):
        self.svc.record_note_evidence("n", actor="RESEARCHER")
        res = H.handle_evidence_list({}, workspace_id=self.wid,
                                     store=self.store, gate=self.gate)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["total"], 1)
        self.assertNotIn("error", res)

    def test_record_note_evidence_insert_only(self):
        ev_id = self.svc.record_note_evidence("note once", actor="RESEARCHER")
        self.assertIsNotNone(ev_id)
        # Re-inserting the SAME id is a no-op (INSERT OR IGNORE) — immutability.
        row = {"id": ev_id, "workspace_id": self.wid, "finding_id": None,
               "observation_id": None, "kind": "note", "raw": None,
               "summary": "TAMPERED", "source_engine": "X", "source_version": "0",
               "timestamp": "2020-01-01T00:00:00+00:00"}
        self.store.save_evidence(row)
        cnt = self.store.db.execute(
            "SELECT COUNT(*) FROM evidence WHERE id=?", (ev_id,)).fetchone()[0]
        self.assertEqual(cnt, 1)
        summary = self.store.db.execute(
            "SELECT summary FROM evidence WHERE id=?", (ev_id,)).fetchone()[0]
        self.assertEqual(summary, "note once")   # original row not overwritten


# ── Knowledge: provenance + scoping + round-trip ──────────────────────────────
class TestKnowledgeWritePath(_Base):
    def test_source_derived_from_actor(self):
        self.assertEqual(H.source_for_actor(ActorKind.RESEARCHER), "human_authored")
        self.assertEqual(H.source_for_actor(ActorKind.RAVEN_AGENT), "ai_derived")
        self.assertEqual(H.source_for_actor(ActorKind.PROGRAM_AGENT), "ai_derived")
        self.assertEqual(H.source_for_actor(ActorKind.SYSTEM), "imported")

    def test_agent_confidence_capped_and_cannot_claim_human(self):
        res = H.handle_knowledge_store(
            {"title": "t", "body": "b", "confidence": 1.0,
             "source": "human_authored",          # spoof attempt — must be ignored
             "human_reviewed_labels": 7},          # must be ignored (immutable 0)
            actor=ActorKind.RAVEN_AGENT, workspace_id=self.wid,
            kb=self.kb, gate=self.gate,
        )
        self.assertEqual(res["status"], "stored")
        entry = res["entry"]
        self.assertEqual(entry["source"], "ai_derived")      # NOT human_authored
        self.assertLessEqual(entry["confidence"], 0.9)        # capped
        self.assertEqual(entry["human_reviewed_labels"], 0)   # immutable

    def test_researcher_may_author_full_confidence(self):
        res = H.handle_knowledge_store(
            {"title": "t", "body": "b", "confidence": 1.0},
            actor=ActorKind.RESEARCHER, workspace_id=self.wid,
            kb=self.kb, gate=self.gate,
        )
        self.assertEqual(res["entry"]["source"], "human_authored")
        self.assertEqual(res["entry"]["confidence"], 1.0)

    def test_store_then_search_round_trip_scoped(self):
        H.handle_knowledge_store(
            {"title": "IDOR", "body": "pattern"},
            actor=ActorKind.RESEARCHER, workspace_id=self.wid,
            kb=self.kb, gate=self.gate,
        )
        # Same workspace -> returned; count scoped agrees with list.
        got = H.handle_knowledge_search({}, workspace_id=self.wid, kb=self.kb, gate=self.gate)
        self.assertEqual(len(got["entries"]), 1)
        self.assertEqual(self.kb.count(workspace_id=self.wid), 1)
        # A DIFFERENT workspace never sees it (scoping fix).
        other = H.handle_knowledge_search({}, workspace_id="other-ws", kb=self.kb, gate=self.gate)
        self.assertEqual(len(other["entries"]), 0)
        self.assertEqual(self.kb.count(workspace_id="other-ws"), 0)

    def test_human_reviewed_labels_stays_zero_in_store(self):
        res = H.handle_knowledge_store(
            {"title": "t", "body": "b"},
            actor=ActorKind.RESEARCHER, workspace_id=self.wid,
            kb=self.kb, gate=self.gate,
        )
        back = self.kb.search("", workspace_id=self.wid, limit=10)[0]
        self.assertEqual(back.human_reviewed_labels, 0)
        with self.assertRaises(AttributeError):
            back.human_reviewed_labels = 1

    def test_metadata_round_trips(self):
        from raven.knowledge_os.knowledge_base import KnowledgeEntry
        e = KnowledgeEntry(title="m", body="b", workspace_id=self.wid,
                           metadata={"k": "v", "n": 2})
        self.kb.store(e)
        back = self.kb.search("m", workspace_id=self.wid)[0]
        self.assertEqual(back.metadata, {"k": "v", "n": 2})  # previously dropped

    def test_gate_denies_write_without_capability(self):
        bare = CapabilityGate(workspace_id=self.wid, granted_capabilities=set())
        res = H.handle_knowledge_store(
            {"title": "t", "body": "b"},
            actor=ActorKind.RAVEN_AGENT, workspace_id=self.wid,
            kb=self.kb, gate=bare,
        )
        self.assertEqual(res["status"], "denied")
        self.assertEqual(self.kb.count(workspace_id=self.wid), 0)


# ── Candidate != Verified / ModelInference != Verification ────────────────────
class TestCandidateNotVerified(_Base):
    def test_note_does_not_verify_finding(self):
        fid = self.svc.create_candidate_xss_reflection(
            "https://example.com/x", "html", observation_id=None)
        before = self.store.get_finding(fid, self.wid)
        self.assertEqual(before["verification_status"], "unverified")
        # Adding advisory NOTE evidence through the handler must not verify.
        res = H.handle_evidence_note(
            {"summary": "looks interesting", "finding_id": fid},
            actor=ActorKind.RESEARCHER, workspace_id=self.wid,
            canonical_svc=self.svc, gate=self.gate)
        self.assertEqual(res["status"], "recorded")
        after = self.store.get_finding(fid, self.wid)
        self.assertEqual(after["verification_status"], "unverified")
        self.assertEqual(after["review_status"], "new")

    def test_automated_confirm_is_refused(self):
        from raven.review_workflow import ReviewWorkflow, FindingReviewState, WorkflowError
        wf = ReviewWorkflow()
        state = FindingReviewState(finding_id="f", review_status="new",
                                   verification_status="unverified")
        with self.assertRaises(WorkflowError):
            wf.transition(state, "confirmed", actor="agent", is_automated=True)
        self.assertEqual(state.verification_status, "unverified")

    def test_candidate_finding_is_verified_immutable(self):
        from raven.research_engine.finding import CandidateFinding
        c = CandidateFinding()
        self.assertFalse(c.is_verified)
        self.assertTrue(c.human_verification_required)
        with self.assertRaises(AttributeError):
            c.is_verified = True
        with self.assertRaises(AttributeError):
            c.human_verification_required = False

    def test_lesson_is_advisory_immutable(self):
        les = Lesson(title="L", summary="s")
        self.assertIs(les.is_advisory, True)
        with self.assertRaises(AttributeError):
            les.is_advisory = False


# ── Registry: real handlers (never not_dispatched) ────────────────────────────
class TestRealToolHandlers(_Base):
    def test_knowledge_registry_real_handlers(self):
        reg = ToolRegistry()
        deps = H.HandlerDeps(
            kb=self.kb, learning=LearningEngine(self.kb),
            techniques=TechniqueLibrary(), store=self.store,
            actor=ActorKind.RESEARCHER, workspace_id=self.wid, gate=self.gate,
        )
        n = register_knowledge_tools(reg, deps)
        self.assertEqual(n, 4)
        store_h = reg.get_handler("knowledge.store")
        out = store_h({"title": "t", "body": "b"})
        self.assertEqual(out["status"], "stored")
        self.assertNotEqual(out["status"], "not_dispatched")
        search_h = reg.get_handler("knowledge.search")
        got = search_h({})
        self.assertEqual(len(got["entries"]), 1)
        tech_h = reg.get_handler("knowledge.technique.search")
        self.assertGreaterEqual(len(tech_h({})["techniques"]), 1)

    def test_knowledge_registry_without_deps_is_unavailable_not_noop(self):
        reg = ToolRegistry()
        register_knowledge_tools(reg)   # one-arg legacy signature preserved
        out = reg.get_handler("knowledge.store")({"title": "t", "body": "b"})
        self.assertEqual(out["status"], "unavailable")
        self.assertNotEqual(out.get("status"), "not_dispatched")

    def test_canonical_evidence_registry_real_handlers(self):
        reg = ToolRegistry()
        deps = H.HandlerDeps(
            canonical_svc=self.svc, store=self.store,
            actor=ActorKind.RESEARCHER, workspace_id=self.wid, gate=self.gate,
        )
        n = register_canonical_evidence_tools(reg, deps)
        self.assertEqual(n, 3)
        note_h = reg.get_handler("evidence.note.add")
        out = note_h({"summary": "a note"})
        self.assertEqual(out["status"], "recorded")
        list_h = reg.get_handler("evidence.node.list")
        self.assertEqual(list_h({})["total"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
