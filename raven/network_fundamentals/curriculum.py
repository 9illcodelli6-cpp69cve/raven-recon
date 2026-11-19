"""RAVEN Network Fundamentals — Curriculum Runner.

Implements the autonomous curriculum loop:
  TEACH → GENERATE SAFE LOCAL SCENARIOS → EXAM → ADVERSARIAL EXAM →
  SCORE → ERROR ANALYSIS → IDENTIFY KNOWLEDGE GAP → IMPROVE →
  RETRAIN ONLY IF JUSTIFIED → HOLDOUT EXAM → REGRESSION → NEXT CURRICULUM

INVARIANTS:
  - No external network targets
  - No live HTTP calls
  - Human-reviewed labels = 0 always
  - ML does not verify findings
  - Rule default: failure → DENY, never fallback to permissive
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from raven.network_fundamentals.exam import (
    run_exam, ExamSession, CriticReport, rule_student, ml_student,
    CurriculumTeacher, CurriculumExaminer, CurriculumCritic,
)
from raven.network_fundamentals.lab import LocalNetworkLab, Fixture
from raven.network_fundamentals.train import (
    _rule_net_a, _rule_net_b, _rule_net_c, _rule_net_d,
    apply_rule_baseline, compute_metrics,
)


_RULE_FNS = {
    "net_a": _rule_net_a,
    "net_b": _rule_net_b,
    "net_c": _rule_net_c,
    "net_d": _rule_net_d,
}

_LABEL_FIELD = {
    "net_a": "protocol_label",
    "net_b": "difference_label",
    "net_c": "session_label",
    "net_d": "auth_label",
}


@dataclass
class CurriculumLevel:
    level_id: int
    name: str
    description: str
    tasks: list[str]              # which tasks are exercised
    difficulty: str = "standard"  # "standard" | "adversarial"


@dataclass
class CurriculumCycleResult:
    level: CurriculumLevel
    task_sessions: dict[str, ExamSession] = field(default_factory=dict)
    task_reports: dict[str, CriticReport] = field(default_factory=dict)
    duration_s: float = 0.0
    retrained: bool = False
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"CYCLE {self.level.level_id} — {self.level.name}"]
        for task, session in sorted(self.task_sessions.items()):
            lines.append(
                f"  [{task}] {session.n_correct}/{session.n_total} = {session.accuracy:.4f}"
                f"{'  ← PERFECT' if session.accuracy == 1.0 else ''}"
            )
            if self.task_reports.get(task) and self.task_reports[task].top_gap:
                lines.append(f"    gap: {self.task_reports[task].top_gap}")
        if self.retrained:
            lines.append("  [retrained]")
        return "\n".join(lines)


class CurriculumRunner:
    """Runs one or more curriculum cycles using local lab fixtures.

    Exam type: the student is a rule-based classifier by default.
    ML student can be used for the ML path exam.

    This runner NEVER:
    - Contacts external hosts
    - Generates labels autonomously
    - Uses ML output as ground truth
    - Retrains without justification
    """

    def __init__(self, lab: Optional[LocalNetworkLab] = None):
        self.lab      = lab or LocalNetworkLab()
        self.teacher  = CurriculumTeacher()
        self.examiner = CurriculumExaminer()
        self.critic   = CurriculumCritic()

    def _get_fixtures(self, task: str) -> list[Fixture]:
        if task == "net_a":
            return self.lab.generate_protocol_fixtures()
        elif task == "net_b":
            return self.lab.generate_difference_fixtures()
        elif task == "net_c":
            return self.lab.generate_session_fixtures()
        elif task == "net_d":
            return self.lab.generate_auth_fixtures()
        else:
            raise ValueError(f"Unknown task: {task}")

    def run_rule_cycle(self, level: CurriculumLevel) -> CurriculumCycleResult:
        """Run a full curriculum cycle using the rule-based student."""
        t0 = time.monotonic()
        result = CurriculumCycleResult(level=level)

        for task in level.tasks:
            fixtures = self._get_fixtures(task)
            rule_fn  = _RULE_FNS[task]
            student  = rule_student(rule_fn)
            session, report = run_exam(fixtures, task, student, level.difficulty)
            result.task_sessions[task] = session
            result.task_reports[task]  = report

        result.duration_s = time.monotonic() - t0
        return result

    def run_ml_cycle(
        self,
        level: CurriculumLevel,
        models: dict[str, object],   # {task: fitted_sklearn_pipeline}
        task_labels: dict[str, list[str]],
    ) -> CurriculumCycleResult:
        """Run a full curriculum cycle using the ML student."""
        t0 = time.monotonic()
        result = CurriculumCycleResult(level=level)

        for task in level.tasks:
            model = models.get(task)
            if model is None:
                result.notes.append(f"[{task}] No ML model available — skipped")
                continue
            labels    = task_labels.get(task, [])
            fixtures  = self._get_fixtures(task)
            student   = ml_student(model, labels)
            session, report = run_exam(fixtures, task, student, level.difficulty)
            result.task_sessions[task] = session
            result.task_reports[task]  = report

        result.duration_s = time.monotonic() - t0
        return result


# ── Predefined curriculum levels ──────────────────────────────────────────────

CURRICULUM_LEVELS = {
    2: CurriculumLevel(2, "HTTP Request/Response Semantics",
                       "Status codes, method semantics, error classes", ["net_a"]),
    6: CurriculumLevel(6, "Cache Semantics",
                       "ETag/304/If-None-Match/Last-Modified; EXPECTED_CHANGE vs CONTENT_CHANGE",
                       ["net_b"]),
    7: CurriculumLevel(7, "Content Negotiation",
                       "Accept/Content-Type headers; text/html vs application/json vs text/plain",
                       ["net_b", "net_a"]),
    8: CurriculumLevel(8, "Session Lifecycle",
                       "ANONYMOUS→AUTHENTICATED→EXPIRED→ROTATED→INVALID transitions",
                       ["net_c"]),
    9: CurriculumLevel(9, "Auth Context",
                       "PUBLIC/APPLICATION_AUTHENTICATED/USER_AUTHENTICATED/AUTH_REQUIRED",
                       ["net_d"]),
    21: CurriculumLevel(21, "Rate Limiting",
                        "429/Retry-After; RATE_LIMITED vs CLIENT_ERROR", ["net_a"]),
    31: CurriculumLevel(31, "Rule vs ML Competition",
                        "Adversarial exam: find cases where rule and ML disagree",
                        ["net_b"], "adversarial"),
    32: CurriculumLevel(32, "Shortcut Detection",
                        "Feature ablation: remove one feature, verify no class collapses",
                        ["net_b", "net_a"]),
}
