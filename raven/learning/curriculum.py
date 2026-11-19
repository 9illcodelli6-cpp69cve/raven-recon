"""RAVEN Phase III — Self-directed learning curriculum loop.

Implements the self-study cycle: identify gaps → study → test → update mastery.
Drives autonomous but bounded educational improvement cycles.

CRITICAL:
  - Self-directed learning operates on EDUCATIONAL_SYNTHETIC data only
  - Learning cycles do NOT contact external targets
  - Curriculum decisions are based on mastery gaps, not security findings
  - Security authority: NONE
  - Learning cycles do NOT grant security authority
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from raven.learning.mastery import (
    DomainMastery, KnowledgeDomain, KnowledgeGap,
    MasteryLevel, SecurityMasteryMatrix,
)


# ── Study cycle state ─────────────────────────────────────────────────────────

class StudyCycleState(str, Enum):
    IDLE          = "IDLE"
    IDENTIFYING   = "IDENTIFYING"   # scanning mastery matrix for gaps
    STUDYING      = "STUDYING"      # reviewing educational content
    TESTING       = "TESTING"       # running exam on the gap domain
    UPDATING      = "UPDATING"      # recording exam results in matrix
    GRADUATED     = "GRADUATED"     # all required domains above threshold
    PAUSED        = "PAUSED"        # waiting for resource availability


@dataclass
class StudyCycleResult:
    """Result of one self-directed study cycle iteration."""
    cycle_id: int
    domain_studied: Optional[KnowledgeDomain]
    n_pass: int
    n_total: int
    accuracy: float
    mastery_level: MasteryLevel
    gaps_remaining: int
    state_after: StudyCycleState
    notes: str = ""


@dataclass
class StudyResource:
    """A reference to an educational resource for a given knowledge domain."""
    resource_id: str
    domain: KnowledgeDomain
    title: str
    description: str
    study_approach: str  # how to study this resource
    data_source: str = "EDUCATIONAL_SYNTHETIC"


# ── Study resource catalogue ──────────────────────────────────────────────────

STUDY_RESOURCES: list[StudyResource] = [
    StudyResource(
        "sr_phase1", KnowledgeDomain.PROTOCOL_CLASSIFICATION,
        "Phase I Network Fundamentals",
        "Review Phase I taxonomy: NET-A/B/C/D classifications",
        "Run raven.network_fundamentals.exam.run_all_exams() and review failures",
    ),
    StudyResource(
        "sr_net_e", KnowledgeDomain.STATE_TRANSITION,
        "NET-E: State Transition Reasoning",
        "Review StateTransitionClass and rule_net_e priority logic",
        "Review rules2.rule_net_e with session/auth/cache/redirect scenarios",
    ),
    StudyResource(
        "sr_net_f", KnowledgeDomain.EXPERIMENT_QUALITY,
        "NET-F: Experiment Quality",
        "Review ExperimentQualityClass and ControlledExperiment.classify()",
        "Focus on CONFOUNDED vs CONTROLLED_SINGLE_VARIABLE distinction",
    ),
    StudyResource(
        "sr_sec_a", KnowledgeDomain.AUTHORIZATION_EXPERIMENT,
        "SEC-A: Authorization Experiment Quality",
        "Review AuthorizationExperimentQuality and rule_sec_a",
        "Study principal/action/resource dimension counting",
    ),
    StudyResource(
        "sr_bola", KnowledgeDomain.BOLA_BFLA_CONCEPTS,
        "BOLA/BFLA Conceptual Models",
        "Review BOLA (Broken Object Level Auth) and BFLA (Broken Function Level Auth) concepts",
        "Study access_control.lab3 fixtures: acl2_bola_candidate and acl3_bfla_candidate",
    ),
    StudyResource(
        "sr_fp", KnowledgeDomain.FALSE_POSITIVE_REJECTION,
        "False Positive Rejection",
        "Review scenarios where BOLA/BFLA do NOT apply",
        "Study acl6_false_positive and adversarial_shortcut fixtures",
    ),
    StudyResource(
        "sr_candidate", KnowledgeDomain.CANDIDATE_REASONING,
        "Candidate Reasoning Chain",
        "Review scientific reasoning chain in CandidateAuthorizationFinding",
        "Study hypothesis/preconditions/alternatives/negative_controls structure",
    ),
    StudyResource(
        "sr_script", KnowledgeDomain.SCRIPT_WORKSHOP,
        "Script Workshop Profiles",
        "Review ExecutionProfile hierarchy and safety review patterns",
        "Study ExecutionProfile.requires_human_approval() and safety review rules",
    ),
    StudyResource(
        "sr_provenance", KnowledgeDomain.SOURCE_PROVENANCE,
        "Source Provenance",
        "Review SourceTrustLevel hierarchy and SourceProvenance tracking",
        "Study classify_source_trust() and KnowledgeItem structure",
    ),
    StudyResource(
        "sr_injection", KnowledgeDomain.PROMPT_INJECTION_RESISTANCE,
        "Prompt Injection Resistance",
        "Review injection detection and content quarantine principles",
        "Study detect_prompt_injection() and gateway safety constraints",
    ),
]

_RESOURCES_BY_DOMAIN: dict[KnowledgeDomain, list[StudyResource]] = {}
for _sr in STUDY_RESOURCES:
    _RESOURCES_BY_DOMAIN.setdefault(_sr.domain, []).append(_sr)


# ── Domain → exam mapping (single source of truth) ────────────────────────────
#
# exam_id -> (module, function, title). Every exam is an in-process run over
# EDUCATIONAL_SYNTHETIC fixtures (no sockets). Several domains share one exam
# category; that is recorded honestly (they receive the same score).
EXAMS: dict[str, tuple[str, str, str]] = {
    "sec_a_basic": ("raven.access_control.exam3", "run_sec_a_basic",
                    "SEC-A authorization experiment quality"),
    "bola_bfla_conceptual": ("raven.access_control.exam3", "run_bola_bfla_conceptual",
                             "BOLA / BFLA conceptual models"),
    "false_positive_rejection": ("raven.access_control.exam3", "run_false_positive_rejection",
                                 "False-positive rejection"),
    "candidate_invariants": ("raven.access_control.exam3", "run_candidate_invariants",
                             "Candidate reasoning invariants"),
    "network_phase2_graduation": ("raven.network_phase2.exam2", "run_graduation_exam",
                                  "Network Phase II graduation exam"),
    "phase2_retention": ("raven.access_control.exam3", "run_phase2_retention",
                         "Phase I/II retention"),
}

DOMAIN_EXAMS: dict[KnowledgeDomain, str] = {
    KnowledgeDomain.AUTHORIZATION_EXPERIMENT: "sec_a_basic",
    KnowledgeDomain.BOLA_BFLA_CONCEPTS: "bola_bfla_conceptual",
    KnowledgeDomain.FALSE_POSITIVE_REJECTION: "false_positive_rejection",
    KnowledgeDomain.CANDIDATE_REASONING: "candidate_invariants",
    KnowledgeDomain.STATE_TRANSITION: "network_phase2_graduation",
    KnowledgeDomain.EXPERIMENT_QUALITY: "network_phase2_graduation",
    KnowledgeDomain.CAUSAL_SUPPORT: "network_phase2_graduation",
    KnowledgeDomain.NEXT_OBSERVATION: "network_phase2_graduation",
    KnowledgeDomain.PROTOCOL_CLASSIFICATION: "phase2_retention",
    KnowledgeDomain.RESPONSE_DIFFERENCE: "phase2_retention",
    KnowledgeDomain.SESSION_STATE: "phase2_retention",
    KnowledgeDomain.AUTH_CONTEXT: "phase2_retention",
}

# Domains with NO exam yet (script workshop, provenance, prompt injection). They
# are reported as such — never given a score. (Previously run_domain_exam returned
# a fabricated 8/10 "placeholder" for them, i.e. a fake 80% / DEVELOPING level.)
DOMAINS_WITHOUT_EXAM: frozenset = frozenset(
    d for d in KnowledgeDomain if d not in DOMAIN_EXAMS)


def has_exam(domain: KnowledgeDomain) -> bool:
    return domain in DOMAIN_EXAMS


def run_exam(exam_id: str):
    """Run one exam category by id; returns its ExamCategory (n_pass, results)."""
    import importlib
    module_name, func_name, _title = EXAMS[exam_id]
    return getattr(importlib.import_module(module_name), func_name)()


# ── Self-study loop ───────────────────────────────────────────────────────────

class SelfStudyLoop:
    """Autonomous but bounded self-directed learning loop.

    Cycle:
      1. Scan mastery matrix for gaps (domains below threshold)
      2. Select highest-priority gap domain
      3. Look up study resources for that domain
      4. Run domain-specific exam to test current knowledge
      5. Update mastery matrix with results
      6. Repeat until no gaps remain or max_cycles reached

    CRITICAL: This loop uses EDUCATIONAL_SYNTHETIC data only.
      It does NOT contact external targets.
      It does NOT grant security authority.
      Security authority: NONE.
    """

    def __init__(
        self,
        mastery_matrix: SecurityMasteryMatrix,
        threshold: float = 0.85,
        max_cycles: int = 20,
    ) -> None:
        self.mastery_matrix = mastery_matrix
        self.threshold = threshold
        self.max_cycles = max_cycles
        self.cycle_count = 0
        self.state = StudyCycleState.IDLE
        self.history: list[StudyCycleResult] = []

    def get_study_resources(self, domain: KnowledgeDomain) -> list[StudyResource]:
        return _RESOURCES_BY_DOMAIN.get(domain, [])

    def run_domain_exam(
        self, domain: KnowledgeDomain
    ) -> tuple[int, int]:
        """Run the exam for a specific domain and return (n_pass, n_total).

        Dispatches through :data:`DOMAIN_EXAMS`. A domain with no exam returns
        ``(0, 0)`` — "not evaluated" — instead of the fabricated 8/10 it used to
        get; ``update_domain`` ignores a zero total, so it stays unevaluated.
        """
        exam_id = DOMAIN_EXAMS.get(domain)
        if exam_id is None:
            return 0, 0
        try:
            cat = run_exam(exam_id)
            return cat.n_pass, len(cat.results)
        except Exception:
            return 0, 1  # failure to run exam

    def run_one_cycle(self) -> Optional[StudyCycleResult]:
        """Run one study cycle: identify → study → test → update."""
        if self.cycle_count >= self.max_cycles:
            self.state = StudyCycleState.PAUSED
            return None

        self.cycle_count += 1
        self.state = StudyCycleState.IDENTIFYING

        # Find highest-priority gap — below-threshold evaluated domains first,
        # then unevaluated domains (unknown accuracy = must test before graduation)
        gaps = self.mastery_matrix.identify_gaps(self.threshold)
        unevaluated = [d for d in self.mastery_matrix.unevaluated_domains() if has_exam(d)]
        if not gaps and not unevaluated:
            untestable = [d for d in self.mastery_matrix.unevaluated_domains()
                          if not has_exam(d)]
            if untestable:
                # Honest stop: graduation needs every domain evaluated, and these
                # have no exam yet — do not claim GRADUATED, do not invent scores.
                self.state = StudyCycleState.PAUSED
                return StudyCycleResult(
                    cycle_id=self.cycle_count,
                    domain_studied=None,
                    n_pass=0, n_total=0, accuracy=0.0,
                    mastery_level=MasteryLevel.NOVICE,
                    gaps_remaining=len(untestable),
                    state_after=StudyCycleState.PAUSED,
                    notes=("No exam exists yet for: "
                           + ", ".join(d.value for d in untestable)),
                )
            self.state = StudyCycleState.GRADUATED
            return StudyCycleResult(
                cycle_id=self.cycle_count,
                domain_studied=None,
                n_pass=0, n_total=0, accuracy=1.0,
                mastery_level=MasteryLevel.EXPERT,
                gaps_remaining=0,
                state_after=StudyCycleState.GRADUATED,
                notes="All evaluated domains above threshold — GRADUATED",
            )

        # Pick highest priority gap, or the first unevaluated domain
        if gaps:
            domain = gaps[0].domain
        else:
            domain = unevaluated[0]

        self.state = StudyCycleState.STUDYING
        # (In a real impl, study resources would be reviewed here)

        self.state = StudyCycleState.TESTING
        n_pass, n_total = self.run_domain_exam(domain)
        accuracy = n_pass / n_total if n_total > 0 else 0.0

        self.state = StudyCycleState.UPDATING
        self.mastery_matrix.update_domain(
            domain, n_pass, n_total,
            evaluated_at_ms=int(time.time() * 1000),
        )

        gaps_after = self.mastery_matrix.identify_gaps(self.threshold)
        remaining = self.mastery_matrix.unevaluated_domains()
        # GRADUATED only when nothing is below threshold AND nothing is untested.
        # (Previously "no gaps" alone graduated the loop after its FIRST exam, with
        # every other domain still unevaluated.) Untestable leftovers → PAUSED.
        if gaps_after or any(has_exam(d) for d in remaining):
            state_after = StudyCycleState.IDLE
        elif remaining:
            state_after = StudyCycleState.PAUSED
        else:
            state_after = StudyCycleState.GRADUATED
        self.state = state_after

        result = StudyCycleResult(
            cycle_id=self.cycle_count,
            domain_studied=domain,
            n_pass=n_pass,
            n_total=n_total,
            accuracy=accuracy,
            mastery_level=MasteryLevel.from_accuracy(accuracy),
            gaps_remaining=len(gaps_after),
            state_after=state_after,
            notes=f"Studied {domain.value}; accuracy={accuracy:.0%}",
        )
        self.history.append(result)
        return result

    def run_until_graduation(self) -> list[StudyCycleResult]:
        """Run cycles until graduation or max_cycles reached."""
        results: list[StudyCycleResult] = []
        while (self.state not in (StudyCycleState.GRADUATED, StudyCycleState.PAUSED)
               and self.cycle_count < self.max_cycles):
            result = self.run_one_cycle()
            if result:
                results.append(result)
            if self.state == StudyCycleState.GRADUATED:
                break
        return results
