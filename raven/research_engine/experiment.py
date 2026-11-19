"""RAVEN V7 Controlled Experiment — Part 07.

A controlled experiment is a structured, hypothesis-driven HTTP probe.
All experiments target only in-scope endpoints.
Results are observations, not confirmed vulnerabilities.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class ExperimentStatus(str, Enum):
    PENDING    = "PENDING"
    RUNNING    = "RUNNING"
    COMPLETED  = "COMPLETED"
    FAILED     = "FAILED"
    SKIPPED    = "SKIPPED"    # out of scope, etc.


@dataclass
class ExperimentStep:
    """One HTTP request + expected/actual response pair."""
    step_id:        str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    description:    str = ""
    url:            str = ""
    method:         str = "GET"
    headers:        Dict = field(default_factory=dict)
    body:           Optional[str] = None
    expected_status: Optional[int] = None
    actual_status:  Optional[int] = None
    actual_body_snippet: str = ""    # first 256 chars only
    passed:         Optional[bool] = None
    duration_ms:    int = 0


@dataclass
class ExperimentResult:
    """Outcome of a controlled experiment."""
    experiment_id: str
    status:        ExperimentStatus
    steps:         List[ExperimentStep] = field(default_factory=list)
    observation:   str = ""    # narrative, advisory
    duration_ms:   int = 0
    human_verification_required: bool = True

    def __post_init__(self):
        object.__setattr__(self, "human_verification_required", True)

    def to_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "status": self.status.value,
            "step_count": len(self.steps),
            "observation": self.observation,
            "human_verification_required": True,
        }


@dataclass
class Experiment:
    """A hypothesis-driven security probe."""
    experiment_id:  str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    title:          str = ""
    hypothesis:     str = ""
    target_url:     str = ""
    workspace_id:   str = "default"
    task_id:        Optional[str] = None
    steps:          List[ExperimentStep] = field(default_factory=list)
    status:         ExperimentStatus = ExperimentStatus.PENDING
    created_at:     int = field(default_factory=lambda: int(time.time() * 1000))
    result:         Optional[ExperimentResult] = None

    def add_step(self, step: ExperimentStep) -> None:
        self.steps.append(step)

    def to_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "title": self.title,
            "hypothesis": self.hypothesis,
            "target_url": self.target_url,
            "status": self.status.value,
            "step_count": len(self.steps),
        }
