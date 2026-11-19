"""Curriculum — INTERFACE ONLY (no learning, no execution).

Forward contract: ordered learning stages -> evaluation hooks for a future native
model. This MIRRORS the concept of the existing ``raven/learning/curriculum.py`` as a
contract; it does NOT replace or import it. Every operational method raises
``NotImplementedError``. Nothing imports this at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class CurriculumStage:
    """Descriptor of one ordered learning stage (metadata only)."""
    stage_id: str
    name: str
    order: int
    objective: str = ""
    dataset_snapshot_id: Optional[str] = None
    evaluation_suite_id: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


class Curriculum:
    """Interface for an ordered native-model learning curriculum. NOT IMPLEMENTED."""

    def stages(self) -> List[CurriculumStage]:
        raise NotImplementedError("native_ai.Curriculum is an interface only — no curriculum executes")

    def add_stage(self, stage: CurriculumStage) -> None:
        raise NotImplementedError("native_ai.Curriculum is an interface only — no curriculum executes")

    def next_stage(self, completed_stage_id: Optional[str] = None) -> CurriculumStage:
        raise NotImplementedError("native_ai.Curriculum is an interface only — no curriculum executes")

    def evaluation_hook(self, stage_id: str) -> str:
        raise NotImplementedError("native_ai.Curriculum is an interface only — no curriculum executes")
