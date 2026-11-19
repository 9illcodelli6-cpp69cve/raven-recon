"""RAVEN Phase III — CandidateAuthorizationFinding.

A candidate (unverified) finding about a potential authorization scenario.
Follows the same scientific reasoning chain as PoCCandidate from Phase I/II.

INVARIANTS:
  - human_verification_required is ALWAYS True — cannot be set to False
  - candidate_conclusion != confirmed vulnerability
  - candidate_conclusion != security finding
  - security_authority = NONE
  - CandidateAuthorizationFinding never triggers automated verification
  - No network execution occurs from this module
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from raven.access_control.taxonomy3 import (
    AuthorizationExperimentQuality, AuthorizationViolationType,
)
from raven.access_control.access_tuple import AccessTuple


# ── Candidate finding ─────────────────────────────────────────────────────────

@dataclass
class CandidateAuthorizationFinding:
    """A candidate (unverified) finding about a potential authorization issue.

    Follows the same scientific reasoning chain as PoCCandidate:
      hypothesis → preconditions → sec_a_quality → observations_summary →
      alternative_explanations → negative_controls → evidence_refs →
      candidate_conclusion → human_verification_required (always True)

    CRITICAL:
      This is a CANDIDATE only.  It has not been verified.
      candidate_conclusion is an educational label, not a security verdict.
      human_verification_required is ALWAYS True and cannot be changed.
      Security authority: NONE.

    Attributes:
        finding_id: Unique identifier for this candidate.
        control_tuple: The baseline/reference access tuple.
        test_tuple: The experimental access tuple.
        hypothesis: The stated hypothesis this experiment tests.
        preconditions: List of conditions that must hold for hypothesis to apply.
        sec_a_quality: Quality of the authorization experiment (SEC-A).
        observations_summary: Concise description of what was observed.
        alternative_explanations: Plausible non-violation explanations.
        negative_controls: Controls that, if tested, should NOT show the pattern.
        evidence_refs: IDs of evidence nodes in the EvidenceGraph.
        candidate_conclusion: Educational label for the observed pattern.
        violation_type: Conceptual classification (BOLA, BFLA, etc.).
        human_verification_required: ALWAYS True — invariant.
    """

    finding_id: str
    control_tuple: AccessTuple
    test_tuple: AccessTuple

    # Scientific reasoning chain
    hypothesis: str = ""
    preconditions: list[str] = field(default_factory=list)
    observations_summary: str = ""
    alternative_explanations: list[str] = field(default_factory=list)
    negative_controls: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    candidate_conclusion: str = ""

    # Classification
    violation_type: AuthorizationViolationType = AuthorizationViolationType.UNKNOWN
    sec_a_quality: AuthorizationExperimentQuality = AuthorizationExperimentQuality.UNKNOWN

    # HTTP evidence (synthetic response data — no real targets)
    control_http_status: Optional[int] = None
    test_http_status: Optional[int] = None
    control_response_summary: str = ""
    test_response_summary: str = ""

    data_source: str = "EDUCATIONAL_SYNTHETIC"

    # Invariant: ALWAYS True
    human_verification_required: bool = True

    def __post_init__(self) -> None:
        if not self.finding_id:
            raise ValueError("finding_id must not be empty")
        # Enforce invariant
        object.__setattr__(self, "human_verification_required", True)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "human_verification_required":
            if value is not True:
                raise AttributeError(
                    "CandidateAuthorizationFinding.human_verification_required "
                    "is an invariant and must always be True")
        super().__setattr__(name, value)

    @property
    def is_inconclusive(self) -> bool:
        """True if the experiment quality is too low to support the hypothesis."""
        return self.sec_a_quality in (
            AuthorizationExperimentQuality.CONFOUNDED,
            AuthorizationExperimentQuality.INSUFFICIENT_CONTEXT,
            AuthorizationExperimentQuality.UNKNOWN,
        )

    @property
    def requires_additional_experiment(self) -> bool:
        """True if the experiment quality suggests more investigation is needed."""
        return self.sec_a_quality == AuthorizationExperimentQuality.CONFOUNDED

    def to_summary_dict(self) -> dict:
        """Return a flat summary for logging/reporting."""
        return {
            "finding_id": self.finding_id,
            "violation_type": self.violation_type.value,
            "sec_a_quality": self.sec_a_quality.value,
            "control_principal": self.control_tuple.principal.identity,
            "test_principal": self.test_tuple.principal.identity,
            "resource": self.control_tuple.resource.resource_id,
            "action": self.control_tuple.action.action_id,
            "control_http_status": self.control_http_status,
            "test_http_status": self.test_http_status,
            "candidate_conclusion": self.candidate_conclusion,
            "human_verification_required": self.human_verification_required,
            "data_source": self.data_source,
        }
