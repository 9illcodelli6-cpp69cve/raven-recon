"""Canonical evidence tool registry (Wave 9, A9-EVKNOW).

Replaces the DEPRECATED ``evidence_os/registry.py`` placeholder (5 descriptors
all bound to ``_noop -> {"status":"not_dispatched"}``, kept only for the existing
Part-10/12 tests) with REAL handlers bound to the canonical evidence store:
- ``evidence.note.add``  -> CanonicalService.record_note_evidence (INSERT-only, advisory)
- ``evidence.node.list`` -> EvidenceReadModel over recon.db (observations+findings+evidence)
- ``evidence.edge.list`` -> EvidenceReadModel edges (relationships)

These bind to the SAME shared handler functions the interim HTTP routes call
(``raven.api.evidence_knowledge_handlers``) — one implementation, two entry
points. ``deps`` carries the live CanonicalService / Store + actor/workspace;
absent deps makes a tool report ``unavailable`` (never a silent ``not_dispatched``).
"""
from __future__ import annotations

from ..runtime.tools import ToolDescriptor, ToolRegistry, SideEffectClass


def _descriptors():
    return [
        ToolDescriptor(
            tool_id="evidence.note.add",
            name="Add Evidence Note",
            description="Record an advisory, INSERT-only NOTE evidence row (never a verdict).",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["summary"],
                "properties": {
                    "summary":        {"type": "string"},
                    "observation_id": {"type": "string"},
                    "finding_id":     {"type": "string"},
                },
            },
            metadata={"risk_class": "LowRiskStateChange"},
        ),
        ToolDescriptor(
            tool_id="evidence.node.list",
            name="List Evidence Nodes",
            description="List evidence nodes projected read-only from the canonical recon.db.",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.LOCAL_READ,
            input_schema={
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                    "limit":        {"type": "integer"},
                },
            },
            metadata={"risk_class": "SafeReadOnly"},
        ),
        ToolDescriptor(
            tool_id="evidence.edge.list",
            name="List Evidence Edges",
            description="List evidence relationship edges (closed vocab, conf in [0,1]).",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.LOCAL_READ,
            input_schema={
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                },
            },
            metadata={"risk_class": "SafeReadOnly"},
        ),
    ]


def register_evidence_tools(registry: ToolRegistry, deps=None) -> int:
    """Register the canonical evidence tools with REAL handlers.

    (Distinct from the deprecated ``evidence_os.registry.register_evidence_tools``,
    which is kept inert for the legacy Part-10/12 tests.)
    """
    from raven.api.evidence_knowledge_handlers import (
        handle_evidence_note,
        handle_evidence_list,
        handle_evidence_edges,
    )
    tools = _descriptors()

    def _unavailable(reason: str):
        def _h(args: dict) -> dict:
            return {"status": "unavailable", "reason": reason}
        return _h

    if deps is None:
        handlers = {t.tool_id: _unavailable(
            "evidence tools not bound to a live CanonicalService/Store (no deps)")
            for t in tools}
    else:
        handlers = {
            "evidence.note.add": lambda a: handle_evidence_note(
                a, actor=deps.actor, workspace_id=deps.workspace_id,
                canonical_svc=deps.canonical_svc, gate=deps.gate),
            "evidence.node.list": lambda a: handle_evidence_list(
                a, workspace_id=deps.workspace_id, store=deps.store, gate=deps.gate),
            "evidence.edge.list": lambda a: handle_evidence_edges(
                a, workspace_id=deps.workspace_id, store=deps.store, gate=deps.gate),
        }

    for t in tools:
        registry.register(t, handlers[t.tool_id])
    return len(tools)
