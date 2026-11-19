"""ML Readiness Checker — Stage 11.

ReadinessChecker.evaluate_readiness() evaluates whether the system is ready
for ML training. At this stage, with no real labeled data, the expected result
is NOT_READY_FOR_TRAINING.

INVARIANTS:
- No model is trained here.
- ml_probability remains NULL (nothing in this module modifies it).
- Only returns READY_FOR_TRAINING when ALL qualitative gates pass.
- Synthetic-only datasets never pass the readiness check.
- The check is purely informational — it does NOT trigger training.

Design reference: blueprint Stage 11, ML Architecture amendments.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .dataset_foundation import (
    DatasetSnapshot,
    LabeledObservation,
    evaluate_dataset_gate,
    VALID_TASKS,
    MIN_LABELED_ROWS,
    MIN_UNIQUE_GROUPS,
)


class ReadinessStatus(Enum):
    READY_FOR_TRAINING = "ready_for_training"
    NOT_READY_FOR_TRAINING = "not_ready_for_training"


@dataclass
class ReadinessReport:
    """Result of a readiness evaluation — informational only, triggers nothing."""
    status: ReadinessStatus
    task: str
    checked_at: str
    gate_snapshot: Optional[DatasetSnapshot]
    reasons: list = field(default_factory=list)
    # Explicitly document that no model was trained and ml_probability is unchanged
    model_trained: bool = False
    ml_probability_modified: bool = False


class ReadinessChecker:
    """Evaluates ML readiness conditions.

    Returns NOT_READY_FOR_TRAINING when:
    - No labeled rows exist
    - Dataset gates fail (insufficient rows, groups, or qualitative review)
    - Dataset is synthetic-only

    Returns READY_FOR_TRAINING only when ALL gates pass.
    This method NEVER trains a model or modifies ml_probability.
    """

    def evaluate_readiness(
        self,
        task: str,
        labeled_rows: Optional[list] = None,
        qualitative_reviewed: bool = False,
    ) -> ReadinessReport:
        rows = labeled_rows or []
        now = datetime.now(tz=timezone.utc).isoformat()
        if task not in VALID_TASKS:
            return ReadinessReport(
                status=ReadinessStatus.NOT_READY_FOR_TRAINING,
                task=task,
                checked_at=now,
                gate_snapshot=None,
                reasons=[f"Unknown task: {task!r}"],
            )
        if not rows:
            return ReadinessReport(
                status=ReadinessStatus.NOT_READY_FOR_TRAINING,
                task=task,
                checked_at=now,
                gate_snapshot=None,
                reasons=["No labeled rows exist — dataset is empty"],
            )
        # Check for synthetic-only dataset
        real_rows = [r for r in rows if not (hasattr(r, "synthetic") and r.synthetic)]
        if not real_rows:
            return ReadinessReport(
                status=ReadinessStatus.NOT_READY_FOR_TRAINING,
                task=task,
                checked_at=now,
                gate_snapshot=None,
                reasons=["Dataset contains only synthetic rows — cannot train on synthetic data alone"],
            )
        snapshot = evaluate_dataset_gate(task, rows, qualitative_reviewed=qualitative_reviewed)
        if snapshot.gate_pass:
            status = ReadinessStatus.READY_FOR_TRAINING
            reasons = []
        else:
            status = ReadinessStatus.NOT_READY_FOR_TRAINING
            reasons = list(snapshot.gate_failures)
        return ReadinessReport(
            status=status,
            task=task,
            checked_at=now,
            gate_snapshot=snapshot,
            reasons=reasons,
            model_trained=False,
            ml_probability_modified=False,
        )
