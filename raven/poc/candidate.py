"""RAVEN PoC Candidate data model (Gate 27-28).

Represents a candidate finding with structured evidence.
Does NOT contain or execute arbitrary code.
Scientific reasoning: Hypothesis -> Preconditions -> Experiment ->
Control -> Observation -> Alternative Explanations -> Negative Control ->
Evidence -> Candidate Conclusion -> Human Verification.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional


class PoCStatus(str, enum.Enum):
    HYPOTHESIS          = "hypothesis"       # initial claim, not yet tested
    PRECONDITIONS_MET   = "preconditions_met"
    EXPERIMENT_PENDING  = "experiment_pending"
    CONTROLS_RUNNING    = "controls_running"
    EVIDENCE_COLLECTED  = "evidence_collected"
    CANDIDATE_CONCLUSION = "candidate_conclusion"
    AWAITING_HUMAN_REVIEW = "awaiting_human_review"  # mandatory before any promotion
    HUMAN_VERIFIED      = "human_verified"    # researcher explicitly confirmed
    HUMAN_REJECTED      = "human_rejected"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


@dataclass
class PoCObservation:
    """A single observation within the PoC experiment."""
    observation_id:  str
    step:            str    # e.g. "baseline", "experiment", "negative_control"
    request_summary: str    # method + path only, no raw data
    status_code:     int
    response_size:   int
    evidence_notes:  str
    is_control:      bool


@dataclass
class PoCCandidate:
    """Candidate vulnerability finding with structured evidence.

    GATE 27 DATA MODEL — represents a claim, not executable exploit code.
    Human verification is required before any promotion.

    Gate 28 scientific reasoning fields:
      hypothesis -> preconditions -> experiment -> control ->
      observations -> alternative_explanations -> negative_controls ->
      evidence_refs -> candidate_conclusion -> human_verification_required
    """
    # Identity
    candidate_id:       str = field(default_factory=lambda: str(uuid.uuid4()))
    knowledge_ref:      str = ""    # links to VulnerabilityKnowledge.knowledge_id
    target_endpoint:    str = ""    # in-scope endpoint only

    # Gate 28 — Scientific reasoning chain
    hypothesis:         str = ""    # "We believe endpoint X allows IDOR because..."
    preconditions:      List[str] = field(default_factory=list)
    experiment_plan:    str = ""    # minimal safe experiment description
    control_plan:       str = ""    # what the negative control tests

    observations:       List[PoCObservation] = field(default_factory=list)
    alternative_explanations: List[str] = field(default_factory=list)
    negative_controls:  List[PoCObservation] = field(default_factory=list)

    evidence_refs:      List[str] = field(default_factory=list)   # IDs only, not raw data
    candidate_conclusion: str = ""
    limitations:        str = ""
    reproduction_outline: str = ""  # high-level steps only

    # Status tracking
    status: PoCStatus = PoCStatus.HYPOTHESIS

    # Human verification — AUTHORITATIVE
    human_verification_required: bool = True    # always True; never auto-bypass
    human_verified_by:           Optional[str]  = None
    human_verdict:               Optional[str]  = None  # "confirmed" | "rejected" | "needs_more_evidence"
    human_notes:                 str = ""

    def advance_to(self, new_status: PoCStatus) -> None:
        """Advance status, enforcing that HUMAN_VERIFIED requires human action."""
        if new_status == PoCStatus.HUMAN_VERIFIED:
            if not self.human_verified_by:
                raise ValueError(
                    "Cannot set HUMAN_VERIFIED without human_verified_by. "
                    "Human verification is AUTHORITATIVE."
                )
        self.status = new_status

    def can_be_promoted(self) -> bool:
        """A candidate may only be promoted if a human has verified it."""
        return self.status == PoCStatus.HUMAN_VERIFIED

    def is_advisory_only(self) -> bool:
        return not self.can_be_promoted()

    def summary(self) -> Dict:
        return {
            "candidate_id":              self.candidate_id,
            "knowledge_ref":             self.knowledge_ref,
            "target_endpoint":           self.target_endpoint,
            "status":                    self.status.value,
            "hypothesis":                self.hypothesis[:200],
            "observations_count":        len(self.observations),
            "alternative_explanations":  self.alternative_explanations,
            "candidate_conclusion":      self.candidate_conclusion[:200],
            "human_verification_required": self.human_verification_required,
            "human_verified_by":         self.human_verified_by,
            "human_verdict":             self.human_verdict,
            "can_be_promoted":           self.can_be_promoted(),
        }
