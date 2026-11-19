"""RAVEN Network Fundamentals — Exam Infrastructure.

Teacher/Student/Examiner/Critic separation:
  - Teacher: generates ExamScenario (knows correct label, withholds it from student)
  - Student: receives ExamQuestion (observation only, no label), produces ExamResponse
  - Examiner: scores ExamResponse against withheld label, produces ExamResult
  - Critic: aggregates ExamResults, identifies error patterns, suggests curriculum changes

INVARIANTS:
  - Student model NEVER sees correct labels before producing predictions
  - No ML model output is used as ground truth
  - All scenarios are LOCAL (no external network calls)
  - Labels come from EDUCATIONAL_SYNTHETIC fixtures only
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from raven.network_fundamentals.observation import NetworkObservation
from raven.network_fundamentals.features import NetworkFeaturePipeline, NetworkFeatureVector
from raven.network_fundamentals.lab import Fixture


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class ExamScenario:
    """A question + answer pair. Teacher holds this; label is withheld from student."""
    scenario_id: str
    observation: NetworkObservation
    correct_label: str            # withheld from student
    task: str                     # "net_a" | "net_b" | "net_c" | "net_d"
    fixture_family: str = ""
    difficulty: str = "standard"  # "standard" | "adversarial" | "mutation"


@dataclass
class ExamQuestion:
    """What the student sees: observation only, no label, no family name."""
    scenario_id: str
    observation: NetworkObservation
    task: str

    @classmethod
    def from_scenario(cls, s: ExamScenario) -> "ExamQuestion":
        """Strip the label to give to the student."""
        return cls(scenario_id=s.scenario_id, observation=s.observation, task=s.task)


@dataclass
class ExamResponse:
    """Student's answer."""
    scenario_id: str
    predicted_label: str
    confidence: float = -1.0      # optional; -1.0 = not reported


@dataclass
class ExamResult:
    """Single question result after examiner scores it."""
    scenario_id: str
    task: str
    correct_label: str
    predicted_label: str
    is_correct: bool
    fixture_family: str = ""
    difficulty: str = "standard"
    confidence: float = -1.0

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "task": self.task,
            "correct": self.correct_label,
            "predicted": self.predicted_label,
            "is_correct": self.is_correct,
            "family": self.fixture_family,
            "difficulty": self.difficulty,
        }


@dataclass
class ExamSession:
    """Aggregate results for one exam session."""
    task: str
    results: list[ExamResult] = field(default_factory=list)

    @property
    def n_total(self) -> int:
        return len(self.results)

    @property
    def n_correct(self) -> int:
        return sum(1 for r in self.results if r.is_correct)

    @property
    def accuracy(self) -> float:
        return self.n_correct / self.n_total if self.n_total else 0.0

    def per_class_accuracy(self) -> dict[str, dict]:
        by_class: dict[str, list[ExamResult]] = {}
        for r in self.results:
            by_class.setdefault(r.correct_label, []).append(r)
        out = {}
        for cls, items in sorted(by_class.items()):
            correct = sum(1 for r in items if r.is_correct)
            out[cls] = {
                "correct": correct,
                "total": len(items),
                "accuracy": correct / len(items),
            }
        return out

    def errors(self) -> list[ExamResult]:
        return [r for r in self.results if not r.is_correct]

    def error_summary(self) -> list[dict]:
        """List of {true, predicted, count} sorted by frequency."""
        counts: dict[tuple, int] = {}
        for r in self.errors():
            key = (r.correct_label, r.predicted_label)
            counts[key] = counts.get(key, 0) + 1
        return sorted(
            [{"true": k[0], "predicted": k[1], "count": v} for k, v in counts.items()],
            key=lambda x: -x["count"],
        )


# ── Teacher ───────────────────────────────────────────────────────────────────

class CurriculumTeacher:
    """Generates exam scenarios from labeled fixtures.

    Teacher knows correct labels; student never sees them until after answering.
    """

    def make_scenarios(
        self,
        fixtures: list[Fixture],
        task: str,
        difficulty: str = "standard",
    ) -> list[ExamScenario]:
        label_field = {
            "net_a": "protocol_label",
            "net_b": "difference_label",
            "net_c": "session_label",
            "net_d": "auth_label",
        }[task]
        out = []
        for fix in fixtures:
            label = getattr(fix.observation, label_field, "UNKNOWN")
            if label == "UNKNOWN":
                continue
            out.append(ExamScenario(
                scenario_id=fix.fixture_id,
                observation=fix.observation,
                correct_label=label,
                task=task,
                fixture_family=fix.observation.fixture_family,
                difficulty=difficulty,
            ))
        return out


# ── Student ───────────────────────────────────────────────────────────────────

StudentFn = Callable[[ExamQuestion], ExamResponse]


def rule_student(rule_fn: Callable[[list[float]], str]) -> StudentFn:
    """Student backed by a deterministic rule classifier."""
    pipeline = NetworkFeaturePipeline()

    def _student(q: ExamQuestion) -> ExamResponse:
        fv = pipeline.extract(q.observation).to_list()
        pred = rule_fn(fv)
        return ExamResponse(scenario_id=q.scenario_id, predicted_label=pred)

    return _student


def ml_student(model, task_labels: list[str]) -> StudentFn:
    """Student backed by an ML model (sklearn Pipeline).

    IMPORTANT: model must be already trained; it is never retrained here.
    """
    pipeline = NetworkFeaturePipeline()

    def _student(q: ExamQuestion) -> ExamResponse:
        fv = pipeline.extract(q.observation).to_list()
        import numpy as np
        X = np.array([fv])
        pred_arr = model.predict(X)
        pred = str(pred_arr[0])
        confidence = -1.0
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X)[0]
            confidence = float(max(proba))
        return ExamResponse(
            scenario_id=q.scenario_id,
            predicted_label=pred,
            confidence=confidence,
        )

    return _student


# ── Examiner ──────────────────────────────────────────────────────────────────

class CurriculumExaminer:
    """Scores student responses against the withheld correct labels.

    Teacher provides correct labels; Examiner compares without giving them to Student.
    """

    def score(
        self,
        scenarios: list[ExamScenario],
        responses: list[ExamResponse],
    ) -> ExamSession:
        if not scenarios:
            raise ValueError("No scenarios to score")

        task = scenarios[0].task
        response_map = {r.scenario_id: r for r in responses}
        results = []
        for s in scenarios:
            resp = response_map.get(s.scenario_id)
            if resp is None:
                pred = "NO_ANSWER"
                conf = -1.0
            else:
                pred = resp.predicted_label
                conf = resp.confidence
            results.append(ExamResult(
                scenario_id=s.scenario_id,
                task=task,
                correct_label=s.correct_label,
                predicted_label=pred,
                is_correct=(pred == s.correct_label),
                fixture_family=s.fixture_family,
                difficulty=s.difficulty,
                confidence=conf,
            ))
        session = ExamSession(task=task, results=results)
        return session


# ── Critic ────────────────────────────────────────────────────────────────────

@dataclass
class CriticReport:
    task: str
    accuracy: float
    n_total: int
    n_correct: int
    per_class: dict[str, dict]
    error_summary: list[dict]
    top_gap: Optional[str]        # class with highest error rate
    recommendation: str           # human-readable curriculum recommendation


class CurriculumCritic:
    """Analyzes exam session results and recommends next curriculum steps.

    IMPORTANT: Critic can suggest curriculum improvements but CANNOT:
    - Modify labels
    - Retrain models autonomously
    - Access raw socket or network
    """

    def analyze(self, session: ExamSession) -> CriticReport:
        pc = session.per_class_accuracy()
        errors = session.error_summary()

        # Find the class with highest error rate (= lowest accuracy)
        worst_class = None
        worst_acc = 1.0
        for cls, stats in pc.items():
            if stats["accuracy"] < worst_acc:
                worst_acc = stats["accuracy"]
                worst_class = cls

        # Build recommendation
        if session.accuracy >= 1.0:
            rec = (f"[{session.task}] Perfect score on {session.n_total} examples. "
                   "Consider increasing difficulty or moving to next curriculum level.")
        elif worst_class:
            wrong_preds = [e["predicted"] for e in errors if e["true"] == worst_class]
            confused_with = max(set(wrong_preds), key=wrong_preds.count) if wrong_preds else "?"
            rec = (f"[{session.task}] Weakest class: {worst_class} (acc={worst_acc:.2f}). "
                   f"Frequently confused with: {confused_with}. "
                   "Recommendation: add more training examples that distinguish these classes.")
        else:
            rec = f"[{session.task}] No clear weak class. Accuracy={session.accuracy:.4f}."

        return CriticReport(
            task=session.task,
            accuracy=session.accuracy,
            n_total=session.n_total,
            n_correct=session.n_correct,
            per_class=pc,
            error_summary=errors,
            top_gap=worst_class,
            recommendation=rec,
        )


# ── Convenience: full exam pipeline ──────────────────────────────────────────

def run_exam(
    fixtures: list[Fixture],
    task: str,
    student_fn: StudentFn,
    difficulty: str = "standard",
) -> tuple[ExamSession, CriticReport]:
    """Run full Teacher → Student → Examiner → Critic pipeline."""
    teacher  = CurriculumTeacher()
    examiner = CurriculumExaminer()
    critic   = CurriculumCritic()

    scenarios = teacher.make_scenarios(fixtures, task, difficulty)
    questions = [ExamQuestion.from_scenario(s) for s in scenarios]
    responses = [student_fn(q) for q in questions]
    session   = examiner.score(scenarios, responses)
    report    = critic.analyze(session)
    return session, report
