"""RAVEN Agent — PlannerBackend seam (Wave 10, A10-AGENT).

A ``PlannerBackend`` turns a goal + context into a typed :class:`~raven.agent.plan.Plan`
of :class:`~raven.agent.plan.PlanStep`. The **default is deterministic** — no
generative model participates (AGENT_ARCHITECTURE §3.2; CANONICAL §6):

* :class:`DeterministicPlanner` (default) composes ``ActionProposal`` objects from
  typed intents (a ``PlanRequest``) or from ``Planner.propose_from_knowledge`` over
  the in-scope hosts. It fabricates **no** natural-language reasoning.
* :class:`ManualPlanner` turns an explicit, researcher-supplied typed step list into
  a plan (``PlanSource.MANUAL``).
* :class:`ModelPlannerAdapter` is the single plug-in seam for a *future* RAVEN
  generative planner. It is **OPTIONAL, OFF by default, third-party-labeled** and
  raises :class:`PlannerUnavailable` unless explicitly enabled. When a model backend
  is absent or fails, planning degrades to the deterministic backend — it never
  degrades to unplanned / ungoverned action. A model-produced step would still be a
  typed ``ActionProposal`` that passes the binder + capability/policy + approval; the
  model can never authorize execution (the ``is_advisory`` invariant, ``ai/chat.py``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from raven.planner.planner import ActionProposal, Planner, PlannerContext
from raven.runtime.tools import SideEffectClass

from .plan import Plan, PlanSource, PlanStep


class PlanIntent(str, Enum):
    """Typed, deterministic goal kinds — NOT parsed from free text."""
    RECORD_KNOWLEDGE_NOTE  = "record_knowledge_note"
    KNOWLEDGE_DRIVEN_PROBE = "knowledge_driven_probe"
    MANUAL                 = "manual"


@dataclass
class PlanRequest:
    """The typed plan input. The executor passes this; it is never inferred from
    the objective string, so there is no natural-language parsing anywhere."""
    intent:          PlanIntent = PlanIntent.KNOWLEDGE_DRIVEN_PROBE
    # RECORD_KNOWLEDGE_NOTE
    note_title:      str = ""
    note_body:       str = ""
    note_kind:       str = "concept"
    note_tags:       List[str] = field(default_factory=list)
    note_confidence: float = 0.5
    # KNOWLEDGE_DRIVEN_PROBE
    knowledge_id:    str = ""
    # MANUAL
    manual_steps:    List[PlanStep] = field(default_factory=list)


class PlannerUnavailable(Exception):
    """Raised by an optional/OFF model backend that produced no plan."""


def side_effect_for_proposal(proposal: ActionProposal) -> SideEffectClass:
    """Deterministically derive the intended side-effect class from a proposal's
    typed capability/method. Used when composing steps from knowledge proposals."""
    cap = proposal.required_capability
    method = (proposal.method or "GET").upper()
    if cap in ("HttpRead", "http_read", "research_fetch", "target_readonly"):
        return SideEffectClass.NETWORK_READ
    if cap in ("HttpStateChange", "http_state_change", "target_statechange"):
        return SideEffectClass.NETWORK_STATE_CHANGE
    if cap in ("ProcessAnalyzer", "process_exec"):
        return SideEffectClass.PROCESS_EXECUTION
    if cap in ("FileWriteWorkspace", "local_write"):
        return SideEffectClass.LOCAL_WRITE
    if cap in ("FileReadWorkspace", "local_read"):
        return SideEffectClass.LOCAL_READ
    if cap in ("ScopeRead", "scope_read", "ScopeWrite", "scope_write"):
        return SideEffectClass.PURE
    # Unknown capability → PURE (the binder still fail-closes if unmapped).
    return SideEffectClass.PURE


class PlannerBackend:
    """Interface. ``plan`` is required; ``next_step`` is optional (default: None)."""
    name: str = "backend"

    def plan(self, context: PlannerContext,
             request: Optional[PlanRequest] = None) -> Plan:
        raise NotImplementedError

    def next_step(self, context: PlannerContext,
                  observations: list) -> Optional[PlanStep]:
        """Observation-driven extension hook. The deterministic default returns None
        (the up-front plan is complete); a model backend may override."""
        return None


class DeterministicPlanner(PlannerBackend):
    """Default backend — turns a typed ``PlanRequest`` into concrete proposals using
    the existing ``Planner`` / knowledge taxonomy. No generative model."""
    name = "deterministic"

    def __init__(self, planner: Optional[Planner] = None):
        self._planner = planner or Planner()

    def plan(self, context: PlannerContext,
             request: Optional[PlanRequest] = None) -> Plan:
        request = request or PlanRequest(intent=PlanIntent.KNOWLEDGE_DRIVEN_PROBE)
        steps: List[PlanStep] = []

        if request.intent == PlanIntent.RECORD_KNOWLEDGE_NOTE:
            steps.append(self._record_note_step(context, request))
        elif request.intent == PlanIntent.KNOWLEDGE_DRIVEN_PROBE:
            steps.extend(self._knowledge_steps(context, request))
        elif request.intent == PlanIntent.MANUAL:
            steps = list(request.manual_steps)

        return Plan(steps=steps, task_id=context.workspace_id and None)

    # -- intent builders -------------------------------------------------------

    def _record_note_step(self, context: PlannerContext,
                          request: PlanRequest) -> PlanStep:
        """A harmless, auto-runnable LOCAL_WRITE step that records a knowledge note.

        The proposal is typed; ``human_approval_required=False`` because a local,
        advisory, confidence-capped knowledge note is LowRiskStateChange, not a
        network/sensitive action."""
        proposal = ActionProposal(
            reason=request.note_title or "agent knowledge note",
            required_capability="FileWriteWorkspace",
            risk_class="LowRiskStateChange",
            destination="local",
            method="LOCAL",
            expected_evidence=request.note_body,
            budget_requests=0,
            scope_label=context.workspace_id,
            human_approval_required=False,
        )
        return PlanStep(
            proposal=proposal,
            side_effect=SideEffectClass.LOCAL_WRITE,
            source=PlanSource.DETERMINISTIC_KNOWLEDGE,
            arg_overrides={
                "title": request.note_title or "agent knowledge note",
                "body": request.note_body,
                "kind": request.note_kind,
                "tags": list(request.note_tags),
                "confidence": request.note_confidence,
            },
        )

    def _knowledge_steps(self, context: PlannerContext,
                        request: PlanRequest) -> List[PlanStep]:
        knowledge_id = request.knowledge_id or (
            context.knowledge_ids[0] if context.knowledge_ids else "")
        if not knowledge_id:
            return []
        proposals = self._planner.propose_from_knowledge(context, knowledge_id)
        if context.scope_hosts:
            proposals = self._planner.filter_by_scope(proposals, context.scope_hosts)
        proposals = self._planner.rank_proposals(proposals)
        return [
            PlanStep(
                proposal=p,
                side_effect=side_effect_for_proposal(p),
                source=PlanSource.DETERMINISTIC_KNOWLEDGE,
            )
            for p in proposals
        ]


class ManualPlanner(PlannerBackend):
    """Turns an explicit, typed step list into a plan (researcher-supplied)."""
    name = "manual"

    def __init__(self, steps: List[PlanStep]):
        self._steps = list(steps)

    def plan(self, context: PlannerContext,
             request: Optional[PlanRequest] = None) -> Plan:
        if request and request.intent == PlanIntent.MANUAL and request.manual_steps:
            return Plan(steps=list(request.manual_steps))
        return Plan(steps=list(self._steps))


class ModelPlannerAdapter(PlannerBackend):
    """OPTIONAL / OFF-by-default / third-party model planner seam.

    Never authorizes execution. With no model or when disabled it degrades to the
    ``fallback`` deterministic backend; if there is no fallback it raises
    :class:`PlannerUnavailable` — it never returns a free / unplanned plan.
    """
    name = "model(third-party,OFF)"

    def __init__(self, model=None, *, enabled: bool = False,
                 fallback: Optional[PlannerBackend] = None):
        self._model = model
        self._enabled = bool(enabled)
        self._fallback = fallback

    @property
    def is_enabled(self) -> bool:
        return self._enabled and self._model is not None

    def plan(self, context: PlannerContext,
             request: Optional[PlanRequest] = None) -> Plan:
        if not self.is_enabled:
            if self._fallback is not None:
                return self._fallback.plan(context, request)
            raise PlannerUnavailable(
                "generative planner is OPTIONAL and OFF (third-party); "
                "no deterministic fallback configured")
        # A real model backend would still emit TYPED ActionProposals that pass the
        # binder + capability/policy + approval. Not implemented here — the default
        # build ships no generative model and simulates none.
        raise PlannerUnavailable(
            "no RAVEN generative planner is implemented; model output is advisory "
            "only and can never authorize execution")
