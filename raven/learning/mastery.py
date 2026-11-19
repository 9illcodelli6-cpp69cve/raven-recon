"""RAVEN Phase III — Knowledge gaps and Security Mastery Matrix.

Tracks educational progress across security concept domains.
Identifies knowledge gaps and measures mastery through exam performance.

CRITICAL:
  Mastery scores measure EDUCATIONAL ACCURACY on synthetic exam cases.
  High mastery ≠ security authority.
  Mastery does NOT authorize automated vulnerability verification.
  Security authority: NONE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Knowledge domains ─────────────────────────────────────────────────────────

class KnowledgeDomain(str, Enum):
    """Security knowledge domains tracked in the Mastery Matrix."""
    # Phase I
    PROTOCOL_CLASSIFICATION     = "PROTOCOL_CLASSIFICATION"
    RESPONSE_DIFFERENCE         = "RESPONSE_DIFFERENCE"
    SESSION_STATE               = "SESSION_STATE"
    AUTH_CONTEXT                = "AUTH_CONTEXT"
    # Phase II
    STATE_TRANSITION            = "STATE_TRANSITION"
    EXPERIMENT_QUALITY          = "EXPERIMENT_QUALITY"
    CAUSAL_SUPPORT              = "CAUSAL_SUPPORT"
    NEXT_OBSERVATION            = "NEXT_OBSERVATION"
    # Phase III
    AUTHORIZATION_EXPERIMENT    = "AUTHORIZATION_EXPERIMENT"
    BOLA_BFLA_CONCEPTS          = "BOLA_BFLA_CONCEPTS"
    FALSE_POSITIVE_REJECTION    = "FALSE_POSITIVE_REJECTION"
    CANDIDATE_REASONING         = "CANDIDATE_REASONING"
    SCRIPT_WORKSHOP             = "SCRIPT_WORKSHOP"
    SOURCE_PROVENANCE           = "SOURCE_PROVENANCE"
    PROMPT_INJECTION_RESISTANCE = "PROMPT_INJECTION_RESISTANCE"

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]


class MasteryLevel(str, Enum):
    """Qualitative mastery level based on exam accuracy."""
    NOVICE      = "NOVICE"       # < 50% accuracy
    DEVELOPING  = "DEVELOPING"   # 50–70%
    COMPETENT   = "COMPETENT"    # 70–85%
    PROFICIENT  = "PROFICIENT"   # 85–95%
    EXPERT      = "EXPERT"       # ≥ 95%

    @classmethod
    def from_accuracy(cls, accuracy: float) -> "MasteryLevel":
        if accuracy < 0.50:
            return cls.NOVICE
        if accuracy < 0.70:
            return cls.DEVELOPING
        if accuracy < 0.85:
            return cls.COMPETENT
        if accuracy < 0.95:
            return cls.PROFICIENT
        return cls.EXPERT


# ── Knowledge gap ─────────────────────────────────────────────────────────────

@dataclass
class KnowledgeGap:
    """A specific gap in educational understanding within a domain."""
    gap_id: str
    domain: KnowledgeDomain
    description: str
    observed_accuracy: float        # 0.0 to 1.0
    example_failures: list[str] = field(default_factory=list)
    suggested_study: list[str] = field(default_factory=list)
    priority: str = "MEDIUM"        # HIGH, MEDIUM, LOW
    resolved: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.observed_accuracy <= 1.0:
            raise ValueError(
                f"observed_accuracy must be in [0, 1], got {self.observed_accuracy}")

    @property
    def mastery_level(self) -> MasteryLevel:
        return MasteryLevel.from_accuracy(self.observed_accuracy)

    @property
    def needs_study(self) -> bool:
        return self.observed_accuracy < 0.85 and not self.resolved


# ── Domain mastery record ─────────────────────────────────────────────────────

@dataclass
class DomainMastery:
    """Mastery record for a single knowledge domain."""
    domain: KnowledgeDomain
    accuracy: float = 0.0
    n_evaluated: int = 0
    n_correct: int = 0
    last_evaluated_at_ms: int = 0
    exam_history: list[float] = field(default_factory=list)  # accuracy per exam cycle

    def update(self, n_pass: int, n_total: int, evaluated_at_ms: int = 0) -> None:
        """Update with results from an exam cycle."""
        if n_total > 0:
            self.n_evaluated += n_total
            self.n_correct += n_pass
            self.accuracy = self.n_correct / self.n_evaluated
            self.exam_history.append(n_pass / n_total)
            self.last_evaluated_at_ms = evaluated_at_ms

    @property
    def mastery_level(self) -> MasteryLevel:
        return MasteryLevel.from_accuracy(self.accuracy)

    @property
    def is_graduated(self) -> bool:
        return self.mastery_level in (MasteryLevel.PROFICIENT, MasteryLevel.EXPERT)


# ── Security mastery matrix ───────────────────────────────────────────────────

class SecurityMasteryMatrix:
    """Tracks educational mastery across all security knowledge domains.

    Updated by running exam categories and recording pass/fail results.
    Identifies knowledge gaps for self-directed study.

    CRITICAL:
      Mastery scores measure educational exam performance only.
      They do NOT grant security authority or verified competency.
      A domain being EXPERT means 95%+ accuracy on SYNTHETIC EDUCATIONAL EXAMS.
      Security authority: NONE.
    """

    def __init__(self) -> None:
        self._domains: dict[KnowledgeDomain, DomainMastery] = {
            d: DomainMastery(domain=d) for d in KnowledgeDomain
        }

    def update_domain(
        self,
        domain: KnowledgeDomain,
        n_pass: int,
        n_total: int,
        evaluated_at_ms: int = 0,
    ) -> None:
        """Record exam results for a domain."""
        self._domains[domain].update(n_pass, n_total, evaluated_at_ms)

    def get_domain(self, domain: KnowledgeDomain) -> DomainMastery:
        return self._domains[domain]

    def identify_gaps(self, threshold: float = 0.85) -> list[KnowledgeGap]:
        """Return knowledge gaps for domains below threshold accuracy."""
        gaps: list[KnowledgeGap] = []
        for domain, mastery in self._domains.items():
            if mastery.n_evaluated > 0 and mastery.accuracy < threshold:
                gap = KnowledgeGap(
                    gap_id=f"gap_{domain.value.lower()}",
                    domain=domain,
                    description=(
                        f"Domain {domain.value}: accuracy {mastery.accuracy:.0%} "
                        f"< threshold {threshold:.0%}"
                    ),
                    observed_accuracy=mastery.accuracy,
                    priority="HIGH" if mastery.accuracy < 0.60 else "MEDIUM",
                )
                gaps.append(gap)
        return sorted(gaps, key=lambda g: g.observed_accuracy)

    def unevaluated_domains(self) -> list[KnowledgeDomain]:
        """Return domains that have never been tested."""
        return [d for d, m in self._domains.items() if m.n_evaluated == 0]

    def graduation_ready(self, required_domains: Optional[list[KnowledgeDomain]] = None,
                         threshold: float = 0.85) -> bool:
        """True if all required domains meet the accuracy threshold."""
        domains_to_check = required_domains or list(KnowledgeDomain)
        for domain in domains_to_check:
            mastery = self._domains.get(domain)
            if mastery is None or mastery.n_evaluated == 0:
                return False
            if mastery.accuracy < threshold:
                return False
        return True

    def summary(self) -> dict:
        """Return a summary of all domain mastery levels."""
        return {
            d.value: {
                "accuracy": f"{m.accuracy:.0%}",
                "mastery_level": m.mastery_level.value,
                "n_evaluated": m.n_evaluated,
                "is_graduated": m.is_graduated,
            }
            for d, m in self._domains.items()
            if m.n_evaluated > 0
        }
