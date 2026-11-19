"""Shared, dispatcher-ready evidence/knowledge write+read handlers (Wave 9).

ONE implementation, two entry points: the interim HTTP routes
(``api_knowledge_store`` / ``api_evidence_note`` / the list routes in
``server.py``) AND the ToolDispatcher-bound registry handlers
(``knowledge_os/registry.py``, ``evidence_os/canonical_registry.py``) both call
these functions. There is no parallel write path — the HTTP route becomes a thin
pass-through once ``RavenRuntime``/``ToolDispatcher`` is constructed.

Security / provenance rules enforced HERE (not in the UI, not from the request
body):
- **Source is derived from the authenticated ACTOR**, never from the payload. A
  RESEARCHER route may produce ``source="human_authored"``; an AGENT
  (RAVEN_AGENT / PROGRAM_AGENT) route is forced ``source="ai_derived"``; anything
  else is ``"imported"``. The payload can never claim ``human_authored``.
- **AGENT/imported confidence is capped at 0.9** — AI output cannot masquerade as
  certainty. Only a human-authored entry may reach 1.0.
- **``human_reviewed_labels`` is never accepted from input** — it stays the
  immutable 0 of ``KnowledgeEntry`` (candidate ≠ verified; AI can't self-label as
  human-reviewed).
- **Evidence notes are advisory, INSERT-only** and never set a verification
  verdict (only the human ``ReviewWorkflow`` can; see ``CanonicalService``).
- Every write is gated: the interim HTTP path passes a boundary-seeded
  ``CapabilityGate``; the dispatcher path pre-gates on the descriptor capability
  (then may pass ``gate=None`` to avoid double-gating).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..runtime.capabilities import CapabilityGate
from ..runtime.execution import ActorKind
from ..security.policy_gate import Capability
from ..knowledge_os.knowledge_base import KnowledgeEntry, KnowledgeKind

# AGENT / non-human confidence ceiling (§4 — AGENT confidence ≤ 0.9).
AGENT_CONFIDENCE_CAP = 0.9

# Local workspace file R/W grants for the evidence/knowledge plane. These tools
# are LOCAL_READ/LOCAL_WRITE (no network, no target traffic); they are NOT in the
# terminal/send/recon LIVE_WORKSPACE_GRANTS set, so this is the boundary seed for
# this plane — authority still resolves through the one PolicyGate and nothing is
# derived from the request body.
_EVKNOW_LOCAL_GRANTS = frozenset({
    Capability.FILE_READ_WORKSPACE,
    Capability.FILE_WRITE_WORKSPACE,
})


def build_evknow_gate(workspace_id: str) -> CapabilityGate:
    """Boundary-seeded CapabilityGate for local evidence/knowledge file R/W."""
    return CapabilityGate(
        workspace_id=workspace_id,
        granted_capabilities=set(_EVKNOW_LOCAL_GRANTS),
    )


@dataclass
class HandlerDeps:
    """Live dependencies the dispatcher-bound registry handlers close over.

    Supplied when the registry is wired to real subsystems; left ``None`` makes a
    tool report ``unavailable`` (NEVER a silent ``not_dispatched``).
    """
    kb: object = None               # KnowledgeBase
    learning: object = None         # LearningEngine
    techniques: object = None       # TechniqueLibrary
    canonical_svc: object = None    # CanonicalService (evidence writer)
    store: object = None            # workspace Store (evidence read model)
    actor: object = ActorKind.RAVEN_AGENT
    workspace_id: Optional[str] = None
    gate: object = None             # CapabilityGate, or None to skip (pre-gated)


# ── provenance / confidence policy ───────────────────────────────────────────
def _actor_name(actor) -> Optional[str]:
    if actor is None:
        return None
    return getattr(actor, "value", actor)


def source_for_actor(actor) -> str:
    name = _actor_name(actor)
    if name == ActorKind.RESEARCHER.value:
        return "human_authored"
    if name in (ActorKind.RAVEN_AGENT.value, ActorKind.PROGRAM_AGENT.value):
        return "ai_derived"
    return "imported"   # SYSTEM / import origin — never "human_authored"


def clamp_confidence(value, source: str) -> float:
    try:
        c = float(value)
    except (TypeError, ValueError):
        c = 0.5
    c = max(0.0, min(1.0, c))
    if source != "human_authored":
        c = min(c, AGENT_CONFIDENCE_CAP)
    return c


def _gate_ok(gate, capability: str, risk_class: str):
    if gate is None:
        return True, ""   # dispatcher pre-gated on the descriptor capability
    res = gate.check(capability, context={
        "destination": "local",
        "method": "LOCAL",
        "reason": f"evidence/knowledge tool: {capability}",
        "risk_class": risk_class,
    })
    return res.is_allowed(), (res.message or res.reason or "denied")


# ── knowledge ─────────────────────────────────────────────────────────────────
def handle_knowledge_store(args: dict, *, actor, workspace_id: str,
                           kb, gate=None) -> dict:
    """Store a KnowledgeEntry. Source from actor, confidence clamped, workspace
    from the active workspace (not the body); human_reviewed_labels stays 0."""
    args = args or {}
    if not workspace_id or not str(workspace_id).strip():
        return {"status": "invalid", "error": "workspace_id required"}
    if _actor_name(actor) is None:
        return {"status": "invalid", "error": "actor required"}
    title = args.get("title") or ""
    body = args.get("body") or ""
    if not title or not body:
        return {"status": "invalid", "error": "title and body are required"}
    allowed, why = _gate_ok(gate, "FileWriteWorkspace", "LowRiskStateChange")
    if not allowed:
        return {"status": "denied", "error": f"knowledge.store denied: {why}"}

    source = source_for_actor(actor)
    confidence = clamp_confidence(args.get("confidence", 0.5), source)
    try:
        kind = KnowledgeKind(args["kind"]) if args.get("kind") else KnowledgeKind.CONCEPT
    except ValueError:
        kind = KnowledgeKind.CONCEPT
    tags = args.get("tags") or []
    if not isinstance(tags, list):
        tags = []

    # NOTE: source / workspace_id / human_reviewed_labels from `args` are IGNORED
    # on purpose — provenance is set by the server boundary, not the caller.
    entry = KnowledgeEntry(
        kind=kind,
        title=str(title),
        body=str(body),
        tags=[str(t) for t in tags],
        source=source,
        confidence=confidence,
        workspace_id=str(workspace_id),
    )
    entry_id = kb.store(entry)
    return {"status": "stored", "entry_id": entry_id, "entry": entry.to_dict()}


def handle_knowledge_search(args: dict, *, workspace_id: str, kb, gate=None) -> dict:
    args = args or {}
    allowed, why = _gate_ok(gate, "FileReadWorkspace", "SafeReadOnly")
    if not allowed:
        return {"status": "denied", "error": f"knowledge.search denied: {why}"}
    query = str(args.get("query") or "")
    kind = None
    if args.get("kind"):
        try:
            kind = KnowledgeKind(args["kind"])
        except ValueError:
            kind = None
    try:
        limit = int(args.get("limit") or 50)
    except (TypeError, ValueError):
        limit = 50
    entries = kb.search(query, kind=kind, workspace_id=workspace_id, limit=limit)
    return {"status": "ok", "entries": [e.to_dict() for e in entries]}


def handle_technique_search(args: dict, *, techniques, gate=None) -> dict:
    args = args or {}
    allowed, why = _gate_ok(gate, "FileReadWorkspace", "SafeReadOnly")
    if not allowed:
        return {"status": "denied", "error": f"knowledge.technique.search denied: {why}"}
    query = str(args.get("query") or "")
    category = None
    if args.get("category"):
        from ..knowledge_os.technique import TechniqueCategory
        try:
            category = TechniqueCategory(args["category"])
        except ValueError:
            category = None
    results = techniques.search(query, category=category)
    return {"status": "ok", "techniques": [t.to_dict() for t in results]}


def handle_lesson_synthesize(args: dict, *, actor, workspace_id: str,
                             learning, store=None, gate=None) -> dict:
    """Synthesize an advisory lesson from findings and persist it (ai_derived)."""
    args = args or {}
    allowed, why = _gate_ok(gate, "FileWriteWorkspace", "LowRiskStateChange")
    if not allowed:
        return {"status": "denied", "error": f"knowledge.lesson.synthesize denied: {why}"}
    ids = args.get("finding_ids") or []
    findings = []
    for fid in ids:
        f = None
        if store is not None and workspace_id:
            try:
                f = store.get_finding(str(fid), workspace_id)
            except Exception:
                f = None
        findings.append(f or {"finding_id": str(fid)})
    ws = workspace_id or "global"
    lesson = learning.synthesize_from_findings(findings, workspace_id=ws)
    entry_id = learning.record_lesson(lesson, workspace_id=ws)
    return {"status": "stored", "entry_id": entry_id, "lesson_id": lesson.lesson_id}


# ── evidence ──────────────────────────────────────────────────────────────────
def handle_evidence_note(args: dict, *, actor, workspace_id: str,
                         canonical_svc, gate=None) -> dict:
    """Record a researcher/agent NOTE evidence row (advisory, INSERT-only)."""
    args = args or {}
    if not workspace_id or not str(workspace_id).strip():
        return {"status": "invalid", "error": "workspace_id required"}
    if _actor_name(actor) is None:
        return {"status": "invalid", "error": "actor required"}
    summary = args.get("summary") or args.get("label") or ""
    if not summary:
        return {"status": "invalid", "error": "summary is required"}
    if canonical_svc is None:
        return {"status": "unavailable", "error": "canonical evidence service offline"}
    allowed, why = _gate_ok(gate, "FileWriteWorkspace", "LowRiskStateChange")
    if not allowed:
        return {"status": "denied", "error": f"evidence.note.add denied: {why}"}
    ev_id = canonical_svc.record_note_evidence(
        str(summary),
        observation_id=args.get("observation_id"),
        finding_id=args.get("finding_id"),
        actor=_actor_name(actor),
    )
    if not ev_id:
        return {"status": "error", "error": "evidence note persistence failed"}
    return {"status": "recorded", "evidence_id": ev_id}


def handle_evidence_list(args: dict, *, workspace_id: str, store, gate=None) -> dict:
    args = args or {}
    allowed, why = _gate_ok(gate, "FileReadWorkspace", "SafeReadOnly")
    if not allowed:
        return {"status": "denied", "error": f"evidence.node.list denied: {why}"}
    from ..evidence_os.read_model import EvidenceReadModel
    try:
        limit = int(args.get("limit") or 50)
    except (TypeError, ValueError):
        limit = 50
    rm = EvidenceReadModel(store, workspace_id)
    nodes = rm.list_nodes(workspace_id=workspace_id, limit=limit)
    return {
        "status": "ok",
        "nodes": [n.to_dict() for n in nodes],
        "total": rm.count_nodes(workspace_id=workspace_id),
    }


def handle_evidence_edges(args: dict, *, workspace_id: str, store, gate=None) -> dict:
    args = args or {}
    allowed, why = _gate_ok(gate, "FileReadWorkspace", "SafeReadOnly")
    if not allowed:
        return {"status": "denied", "error": f"evidence.edge.list denied: {why}"}
    from ..evidence_os.read_model import EvidenceReadModel
    rm = EvidenceReadModel(store, workspace_id)
    return {"status": "ok", "edges": rm.list_edges(workspace_id=workspace_id)}
