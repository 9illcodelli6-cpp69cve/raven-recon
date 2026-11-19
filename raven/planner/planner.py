"""RAVEN Action Planner — typed proposal interface.

INVARIANTS:
- Planner never calls the scheduler or network directly.
- Planner never executes actions.
- Every proposal has explicit human_approval_required field.
- Proposals are schema-typed; they are not raw shell commands.
- Model signals inform proposals but never authorize them.
- Policy must approve before any execution.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class ProposalStatus(str, Enum):
    PENDING   = "pending"          # not yet reviewed
    APPROVED  = "approved"         # researcher approved; policy must still allow
    DENIED    = "denied"           # researcher denied
    CANCELLED = "cancelled"        # withdrawn before review
    EXPIRED   = "expired"          # approval window passed


@dataclass
class ActionProposal:
    """Typed action proposal produced by the planner.

    The planner creates these; it does NOT execute them.
    Execution requires: researcher approval (if required) + PolicyGate.allow().
    """
    proposal_id:            str = field(default_factory=lambda: str(uuid.uuid4()))
    reason:                 str = ""
    knowledge_reference:    Optional[str] = None   # e.g. "AC-001"
    required_capability:    str = ""               # Capability enum value
    risk_class:             str = ""               # RiskClass enum value
    destination:            str = ""               # scoped HTTP target or "local"
    method:                 str = "GET"
    expected_evidence:      str = ""
    budget_requests:        int = 1
    scope_label:            str = ""
    human_approval_required: bool = True           # default: always require approval
    status:                 ProposalStatus = ProposalStatus.PENDING
    created_at:             str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    model_signal_score:     Optional[float] = None  # advisory only; never authorizes

    def approve(self, approver: str) -> None:
        """Record researcher approval — does NOT execute the action."""
        if self.status != ProposalStatus.PENDING:
            raise ValueError(f"Cannot approve proposal in state {self.status}")
        if not approver or not approver.strip():
            raise ValueError("approver must be a non-empty researcher identifier")
        self.status = ProposalStatus.APPROVED

    def deny(self, approver: str) -> None:
        """Researcher denies the proposal."""
        if self.status != ProposalStatus.PENDING:
            raise ValueError(f"Cannot deny proposal in state {self.status}")
        self.status = ProposalStatus.DENIED


@dataclass
class PlannerContext:
    """Input context for planner decisions.

    Planner uses knowledge + observations + model signals + workspace context.
    It does NOT use live network connections, shell, or raw tool handles.
    """
    workspace_id:       str
    scope_hosts:        List[str] = field(default_factory=list)
    knowledge_ids:      List[str] = field(default_factory=list)
    model_signals:      dict      = field(default_factory=dict)   # task→score, advisory only
    observation_count:  int       = 0
    candidate_count:    int       = 0


class Planner:
    """Generates typed ActionProposals from context.

    CANNOT: execute actions, call scheduler, open sockets, run shell, bypass policy.
    CAN:    read knowledge, read observations, read model signals, propose experiments.
    """

    def propose_from_knowledge(
        self,
        context: PlannerContext,
        knowledge_id: str,
    ) -> List[ActionProposal]:
        """Generate proposals for a knowledge entry given current context.

        Returns a ranked list of proposals. Each requires policy approval
        and (if human_approval_required=True) researcher sign-off before execution.
        All proposals default to human_approval_required=True.
        """
        from raven.knowledge.taxonomy import VULNERABILITY_FAMILIES
        entry = VULNERABILITY_FAMILIES.get(knowledge_id)
        if entry is None:
            return []

        proposals = []
        # Each required capability from the knowledge entry becomes a proposal
        for cap in entry.required_capabilities:
            for scope_host in context.scope_hosts:
                p = ActionProposal(
                    reason=f"Knowledge-driven proposal: {entry.name} ({knowledge_id})",
                    knowledge_reference=knowledge_id,
                    required_capability=cap,
                    risk_class=entry.risk_class,
                    destination=f"https://{scope_host}/",
                    expected_evidence="; ".join(entry.evidence_requirements[:2]),
                    budget_requests=1,
                    scope_label=scope_host,
                    human_approval_required=True,
                    model_signal_score=context.model_signals.get(knowledge_id),
                )
                proposals.append(p)

        return proposals

    def rank_proposals(
        self,
        proposals: List[ActionProposal],
        model_signals: Optional[dict] = None,
    ) -> List[ActionProposal]:
        """Rank proposals — higher model signal score first (advisory only).

        Ranking by model signal does NOT authorize higher-ranked proposals.
        All still require the same policy evaluation.
        """
        signals = model_signals or {}

        def _score(p: ActionProposal) -> float:
            if p.model_signal_score is not None:
                return p.model_signal_score
            return signals.get(p.knowledge_reference, 0.0)

        return sorted(proposals, key=_score, reverse=True)

    def filter_by_scope(
        self,
        proposals: List[ActionProposal],
        allowed_scope_hosts: List[str],
    ) -> List[ActionProposal]:
        """Remove proposals whose destination is out of scope.

        Planner-level scope check. PolicyGate also checks independently.
        """
        allowed = set(allowed_scope_hosts)
        result = []
        for p in proposals:
            dest = p.destination.lower()
            in_scope = False
            for host in allowed:
                if f"://{host}/" in dest or f"://{host}" == dest.rstrip("/"):
                    in_scope = True
                    break
                if dest.startswith(("http://", "https://")):
                    # subdomain check
                    after = dest.split("://", 1)[1].split("/")[0]
                    if after == host or after.endswith("." + host):
                        in_scope = True
                        break
            if in_scope:
                result.append(p)
        return result
