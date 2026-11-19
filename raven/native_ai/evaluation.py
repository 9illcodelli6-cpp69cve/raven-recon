"""EvaluationSuite — INTERFACE ONLY (no evaluation runs).

Forward contract for the real-holdout evaluation that ANY model (classical or native)
must pass before leaving DEVELOPMENT. It is the honest promotion gate and is intended
to align with ``raven/ml_readiness.py::ReadinessChecker`` and
``dataset_foundation.evaluate_dataset_gate`` — one honest "ready / evaluated" concept,
not two. No evaluation is performed here — every operational method raises
``NotImplementedError``. Nothing imports this at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass(frozen=True)
class EvaluationResult:
    """Immutable, ADVISORY evaluation result (never a verification verdict)."""
    suite_id: str
    passed: bool = False
    metrics: Dict = field(default_factory=dict)
    # Advisory boundary mirrors ml.inference.InferenceResult: evaluation never sets
    # verification status and never authorizes a promotion by itself.
    is_advisory: bool = True
    sets_verification_status: bool = False


class EvaluationSuite:
    """Interface for a real-holdout evaluation gate. NOT IMPLEMENTED."""

    def evaluate(self, artifact_id: str, dataset_snapshot_id: str) -> EvaluationResult:
        raise NotImplementedError("native_ai.EvaluationSuite is an interface only — no evaluation runs")

    def gate(self, result: EvaluationResult) -> bool:
        raise NotImplementedError("native_ai.EvaluationSuite is an interface only — no evaluation runs")

    def criteria(self) -> Dict:
        raise NotImplementedError("native_ai.EvaluationSuite is an interface only — no evaluation runs")
