"""RAVEN V7 Scientific Critic — Part 07.

Reviews experiment results and candidate findings for quality.
All critique outputs are ADVISORY — the critic never confirms vulnerabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .finding import CandidateFinding
from .experiment import ExperimentResult, ExperimentStatus


@dataclass
class CritiqueResult:
    target_id:    str
    score:        float      # 0–1; higher = better evidence quality
    concerns:     List[str] = field(default_factory=list)
    suggestions:  List[str] = field(default_factory=list)
    is_advisory:  bool = True    # ALWAYS True

    def __post_init__(self):
        object.__setattr__(self, "is_advisory", True)

    @property
    def quality(self) -> str:
        if self.score >= 0.8:
            return "HIGH"
        if self.score >= 0.5:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "target_id": self.target_id,
            "score": self.score,
            "quality": self.quality,
            "concerns": self.concerns,
            "suggestions": self.suggestions,
            "is_advisory": True,
        }


class ScientificCritic:
    """Reviews findings and experiment results for methodological soundness."""

    def critique_finding(self, finding: CandidateFinding) -> CritiqueResult:
        concerns: List[str] = []
        suggestions: List[str] = []
        score = 1.0

        if not finding.title:
            concerns.append("Finding has no title")
            score -= 0.2

        if not finding.description:
            concerns.append("Finding has no description — reproducibility unclear")
            score -= 0.2

        if not finding.endpoint:
            concerns.append("No endpoint specified — finding is not reproducible")
            score -= 0.3

        if not finding.evidence_ref:
            concerns.append("No evidence references — assertion not backed by data")
            suggestions.append("Attach traffic entries or screenshots as evidence")
            score -= 0.2

        if finding.severity.value == "UNKNOWN":
            suggestions.append("Assign a severity to aid prioritization")
            score -= 0.1

        return CritiqueResult(
            target_id=finding.finding_id,
            score=max(0.0, score),
            concerns=concerns,
            suggestions=suggestions,
        )

    def critique_experiment(self, result: ExperimentResult) -> CritiqueResult:
        concerns: List[str] = []
        suggestions: List[str] = []
        score = 1.0

        if result.status == ExperimentStatus.FAILED:
            concerns.append("Experiment failed — results are incomplete")
            score -= 0.5

        if not result.steps:
            concerns.append("No steps recorded — experiment has no evidence trail")
            score -= 0.4

        failed_steps = [s for s in result.steps if s.passed is False]
        total_steps  = len(result.steps)
        if total_steps > 0:
            pass_rate = (total_steps - len(failed_steps)) / total_steps
            score = score * pass_rate

        if not result.observation:
            suggestions.append("Add a human-readable observation summarizing findings")

        return CritiqueResult(
            target_id=result.experiment_id,
            score=max(0.0, score),
            concerns=concerns,
            suggestions=suggestions,
        )
