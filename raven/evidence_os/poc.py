"""RAVEN V7 PoC Builder — Part 10.

Builds structured Proof-of-Concept documentation for candidate findings.
PoC entries are ADVISORY — they describe what a human tester should verify,
not automated exploitation.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class PoCStatus(str, Enum):
    DRAFT          = "draft"
    PENDING_REVIEW = "pending_review"
    HUMAN_VERIFIED = "human_verified"
    REJECTED       = "rejected"


@dataclass
class PoCStep:
    step_num:    int = 0
    description: str = ""
    expected:    str = ""
    actual:      str = ""   # filled in after manual execution
    evidence_node_ids: List[str] = field(default_factory=list)


@dataclass
class PoCEntry:
    poc_id:       str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    finding_id:   str = ""
    title:        str = ""
    summary:      str = ""
    steps:        List[PoCStep] = field(default_factory=list)
    status:       PoCStatus = PoCStatus.DRAFT
    workspace_id: str = "default"
    created_at:   int = field(default_factory=lambda: int(time.time() * 1000))
    is_advisory:  bool = True   # INVARIANT: always True — PoCs are not confirmed exploits

    def __post_init__(self):
        object.__setattr__(self, "is_advisory", True)

    def __setattr__(self, name: str, value):
        if name == "is_advisory" and "is_advisory" in self.__dict__:
            raise AttributeError("is_advisory is immutable — PoC is advisory until human-verified")
        object.__setattr__(self, name, value)

    def to_dict(self) -> dict:
        return {
            "poc_id": self.poc_id,
            "finding_id": self.finding_id,
            "title": self.title,
            "status": self.status.value,
            "is_advisory": True,
            "step_count": len(self.steps),
        }


class PoCBuilder:
    """Builds and stores PoC entries for candidate findings."""

    def __init__(self):
        self._pocs: dict[str, PoCEntry] = {}

    def create(
        self,
        finding_id: str,
        title: str,
        summary: str,
        steps: Optional[List[PoCStep]] = None,
        workspace_id: str = "default",
    ) -> PoCEntry:
        poc = PoCEntry(
            finding_id=finding_id,
            title=title,
            summary=summary,
            steps=steps or [],
            workspace_id=workspace_id,
        )
        self._pocs[poc.poc_id] = poc
        return poc

    def get(self, poc_id: str) -> Optional[PoCEntry]:
        return self._pocs.get(poc_id)

    def list_for_finding(self, finding_id: str) -> List[PoCEntry]:
        return [p for p in self._pocs.values() if p.finding_id == finding_id]

    def list_all(self, workspace_id: str = None) -> List[PoCEntry]:
        if workspace_id:
            return [p for p in self._pocs.values() if p.workspace_id == workspace_id]
        return list(self._pocs.values())

    def add_step(self, poc_id: str, step: PoCStep) -> bool:
        poc = self._pocs.get(poc_id)
        if poc is None:
            return False
        poc.steps.append(step)
        return True

    def count(self) -> int:
        return len(self._pocs)
