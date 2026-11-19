"""RAVEN Agent — Plan / PlanStep (Wave 10, A10-AGENT).

A ``Plan`` is the ordered, typed program the :class:`~raven.agent.executor.AgentExecutor`
drives. It is produced by a :class:`~raven.agent.planner_backend.PlannerBackend`
(the ``DeterministicPlanner`` by default — no generative model). Each step wraps a
proposal-only :class:`~raven.planner.planner.ActionProposal` (the planner module is
NOT edited — its invariants stay intact) plus the *typed* metadata the
``ProposalBinder`` needs to resolve a concrete ``tool_id``:

* ``side_effect`` — the :class:`~raven.runtime.tools.SideEffectClass` the step
  intends. ``ActionProposal`` carries ``required_capability``/``method`` but NOT a
  side-effect class, so the planner (which knows the intent) stamps it on the step.
  This is the missing third element of the ``(capability, side_effect, method)``
  binder tuple — sourced from the planner, never from the goal text.
* ``arg_overrides`` — tool-specific, *typed* arguments the planner computed (e.g. a
  knowledge note's title/body). They are whitelisted against the tool's own
  ``input_schema`` by the binder and re-validated by the dispatcher; they are never
  free-form shell/NL.

``PlanSource`` records provenance of each step (manual, deterministic-knowledge, or
model-advisory) so a mixed plan stays auditable.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from raven.planner.planner import ActionProposal
from raven.runtime.tools import SideEffectClass


class PlanSource(str, Enum):
    """Provenance of a single plan step."""
    MANUAL                  = "manual"                   # researcher-supplied typed step
    DETERMINISTIC_KNOWLEDGE = "deterministic_knowledge"  # DeterministicPlanner / knowledge
    MODEL_ADVISORY          = "model_advisory"           # optional model backend (still gated)


@dataclass
class PlanStep:
    """One typed step: a proposal + the metadata the binder needs."""
    proposal:     ActionProposal
    side_effect:  SideEffectClass
    source:       PlanSource = PlanSource.DETERMINISTIC_KNOWLEDGE
    step_id:      str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    depends_on:   List[str] = field(default_factory=list)
    # Typed, planner-produced tool args (whitelisted + re-validated downstream).
    arg_overrides: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "proposal_id": self.proposal.proposal_id,
            "required_capability": self.proposal.required_capability,
            "side_effect": self.side_effect.value,
            "method": self.proposal.method,
            "risk_class": self.proposal.risk_class,
            "source": self.source.value,
            "human_approval_required": self.proposal.human_approval_required,
            "depends_on": list(self.depends_on),
        }


@dataclass
class Plan:
    """An ordered list of typed :class:`PlanStep`."""
    steps:      List[PlanStep] = field(default_factory=list)
    plan_id:    str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    task_id:    Optional[str] = None
    created_by: Optional[str] = None   # ActorKind value of the initiating boundary actor

    def __len__(self) -> int:
        return len(self.steps)

    def __iter__(self):
        return iter(self.steps)

    def __bool__(self) -> bool:
        return bool(self.steps)

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "task_id": self.task_id,
            "created_by": self.created_by,
            "steps": [s.to_dict() for s in self.steps],
        }
