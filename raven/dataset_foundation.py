"""Dataset / Label Foundation.

LabelStore: write labeled observations with group_key (computed at label time).
DatasetSnapshot: quality gate checks before any ML training is attempted.

INVARIANTS:
- group_key is computed at label time from (workspace_id, asset_id, host), NOT
  from the label value itself. Labels assigned to the same logical target must
  be kept together during train/test splits (group-aware splitting).
- Synthetic labels must never contaminate real validation/test evaluation.
- Task A (ResponseDifference) and Task B (AuthorizationSignificance) labels are
  stored under separate task keys — they are never mixed.
- ml_probability stays NULL until Stage 11. LabelStore never touches it.

Design reference: blueprint Stage 10, Category 9, amendments 7 and 8.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

# Canonical task names (from amendments)
TASK_A = "response_difference"        # Task A: structural measurement
TASK_B = "authorization_significance"  # Task B: authorization judgment
TASK_C = "finding_priority"            # Task C: research priority

VALID_TASKS = frozenset({TASK_A, TASK_B, TASK_C})

# Qualitative gates for DatasetSnapshot
MIN_LABELED_ROWS = 50
MIN_POSITIVE_RATE = 0.05   # at least 5% positives
MAX_POSITIVE_RATE = 0.95   # at most 95% positives
MIN_UNIQUE_GROUPS = 5      # at least 5 unique group_keys


class LabelError(Exception):
    """Raised when a label row fails validation."""


class DatasetGateError(Exception):
    """Raised when a dataset snapshot fails a qualitative gate."""


@dataclass
class LabeledObservation:
    """A single labeled row for ML training.

    group_key is computed from (workspace_id, asset_id) and is set
    at label time — never from the label value.
    synthetic=False by default; synthetic rows must not enter real eval sets.
    """
    id: str
    workspace_id: str
    observation_id: Optional[str]
    task: str
    label: str
    group_key: str
    labeler: str
    labeled_at: str
    note: str = ""
    synthetic: bool = False


def _compute_group_key(workspace_id: str, asset_id: str) -> str:
    """Deterministic group key from workspace + asset identity.

    Does NOT use the label value — ensures same target stays in same split group.
    """
    raw = f"{workspace_id}:{asset_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class LabelStore:
    """Write classified, grouped label rows for ML dataset construction.

    group_key is computed here at label time — callers must not supply it.
    """

    def write_label(
        self,
        workspace_id: str,
        task: str,
        label: str,
        labeler: str,
        observation_id: Optional[str] = None,
        asset_id: str = "",
        note: str = "",
        synthetic: bool = False,
    ) -> LabeledObservation:
        if not workspace_id:
            raise LabelError("workspace_id required")
        if task not in VALID_TASKS:
            raise LabelError(f"task must be one of {sorted(VALID_TASKS)}, got {task!r}")
        if not label or not label.strip():
            raise LabelError("label must not be empty")
        if not labeler or not labeler.strip():
            raise LabelError("labeler must not be empty")
        group_key = _compute_group_key(workspace_id, asset_id or "")
        return LabeledObservation(
            id=uuid.uuid4().hex,
            workspace_id=workspace_id,
            observation_id=observation_id,
            task=task,
            label=label.strip(),
            group_key=group_key,
            labeler=labeler.strip(),
            labeled_at=datetime.now(tz=timezone.utc).isoformat(),
            note=note,
            synthetic=synthetic,
        )

    def to_db_row(self, row: LabeledObservation) -> dict:
        return {
            "id": row.id,
            "workspace_id": row.workspace_id,
            "observation_id": row.observation_id,
            "task": row.task,
            "label": row.label,
            "group_key": row.group_key,
            "labeler": row.labeler,
            "labeled_at": row.labeled_at,
            "note": row.note,
            "synthetic": int(row.synthetic),
        }


@dataclass
class DatasetSnapshot:
    """Quality gate result for a dataset intended for training.

    gate_pass=True only if ALL qualitative checks pass.
    """
    id: str
    task: str
    snapshot_at: str
    row_count: int
    positive_count: int
    negative_count: int
    unique_groups: int
    synthetic_count: int
    gate_pass: bool
    gate_failures: list
    qualitative_reviewed: bool = False


def evaluate_dataset_gate(
    task: str,
    rows: list[LabeledObservation],
    qualitative_reviewed: bool = False,
) -> DatasetSnapshot:
    """Evaluate qualitative gates for a set of labeled rows.

    Returns a DatasetSnapshot whose gate_pass reflects all checks.
    Synthetic rows are excluded from positive/negative counts for gate evaluation.
    """
    if task not in VALID_TASKS:
        raise DatasetGateError(f"Unknown task: {task!r}")
    real_rows = [r for r in rows if not r.synthetic]
    total = len(real_rows)
    positives = sum(1 for r in real_rows if r.label == "1" or r.label == "positive" or r.label == "DIFFERENT")
    negatives = total - positives
    unique_groups = len({r.group_key for r in real_rows})
    synthetic_count = sum(1 for r in rows if r.synthetic)
    failures = []
    if total < MIN_LABELED_ROWS:
        failures.append(f"Insufficient rows: {total} < {MIN_LABELED_ROWS}")
    if total > 0:
        pos_rate = positives / total
        if pos_rate < MIN_POSITIVE_RATE:
            failures.append(f"Positive rate too low: {pos_rate:.3f} < {MIN_POSITIVE_RATE}")
        elif pos_rate > MAX_POSITIVE_RATE:
            failures.append(f"Positive rate too high: {pos_rate:.3f} > {MAX_POSITIVE_RATE}")
    if unique_groups < MIN_UNIQUE_GROUPS:
        failures.append(f"Insufficient unique groups: {unique_groups} < {MIN_UNIQUE_GROUPS}")
    if not qualitative_reviewed:
        failures.append("Dataset has not been qualitatively reviewed by a researcher")
    return DatasetSnapshot(
        id=uuid.uuid4().hex,
        task=task,
        snapshot_at=datetime.now(tz=timezone.utc).isoformat(),
        row_count=total,
        positive_count=positives,
        negative_count=negatives,
        unique_groups=unique_groups,
        synthetic_count=synthetic_count,
        gate_pass=(len(failures) == 0),
        gate_failures=failures,
        qualitative_reviewed=qualitative_reviewed,
    )
