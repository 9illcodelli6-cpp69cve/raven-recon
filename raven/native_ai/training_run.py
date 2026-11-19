"""TrainingRun — INTERFACE ONLY (NO TRAINER, no training is performed).

Forward contract describing a future native-model training run's config/metrics/status.
There is deliberately **no trainer** and no gradient loop: this campaign does not
design or perform any training run. Every operational method raises
``NotImplementedError``. Nothing imports this at runtime.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict


class TrainingRunStatus(str, enum.Enum):
    NOT_STARTED = "NOT_STARTED"
    RUNNING     = "RUNNING"
    COMPLETED   = "COMPLETED"
    FAILED      = "FAILED"
    CANCELLED   = "CANCELLED"


@dataclass(frozen=True)
class _TrainingRunDescriptor:
    run_id: str
    config: Dict = field(default_factory=dict)
    status: TrainingRunStatus = TrainingRunStatus.NOT_STARTED
    metrics: Dict = field(default_factory=dict)


class TrainingRun:
    """Interface describing a native-model training run. NOT IMPLEMENTED (no trainer)."""

    def descriptor(self) -> _TrainingRunDescriptor:
        raise NotImplementedError("native_ai.TrainingRun is an interface only — no trainer exists")

    def status(self) -> TrainingRunStatus:
        raise NotImplementedError("native_ai.TrainingRun is an interface only — no trainer exists")

    def start(self) -> None:
        # Intentionally never trains. RAVEN designs no training run in this campaign.
        raise NotImplementedError("native_ai.TrainingRun is an interface only — no training is performed")

    def metrics(self) -> Dict:
        raise NotImplementedError("native_ai.TrainingRun is an interface only — no trainer exists")
