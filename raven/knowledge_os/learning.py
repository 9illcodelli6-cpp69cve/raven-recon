"""RAVEN V7 Learning Engine — Part 09.

Synthesizes lessons from completed research sessions.
All synthesized lessons are advisory and marked ai_derived.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

from .knowledge_base import KnowledgeBase, KnowledgeEntry, KnowledgeKind


@dataclass
class Lesson:
    lesson_id:   str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    title:       str = ""
    summary:     str = ""
    source_ids:  List[str] = field(default_factory=list)   # finding/experiment IDs
    tags:        List[str] = field(default_factory=list)
    confidence:  float = 0.5
    created_at:  int = field(default_factory=lambda: int(time.time() * 1000))
    is_advisory: bool = True   # ALWAYS True

    def __post_init__(self):
        object.__setattr__(self, "is_advisory", True)

    def __setattr__(self, name: str, value):
        if name == "is_advisory" and "is_advisory" in self.__dict__:
            raise AttributeError("is_advisory is immutable — lesson output is always advisory")
        object.__setattr__(self, name, value)


class LearningEngine:
    """Derives lessons from research activity and stores them in the KnowledgeBase."""

    def __init__(self, knowledge_base: KnowledgeBase):
        self._kb = knowledge_base

    def record_lesson(self, lesson: Lesson, workspace_id: str = "global") -> str:
        """Persist a lesson as a knowledge entry.

        ``workspace_id`` is now explicit so a synthesized lesson is scoped to the
        ACTIVE workspace (plumbed by the caller) instead of silently defaulting to
        ``"global"`` — which the server's per-workspace list query would never
        return (the §2.2 scoping mismatch). A lesson is always ``source="ai_derived"``
        and advisory; it never carries a human-review label.
        """
        entry = KnowledgeEntry(
            entry_id=lesson.lesson_id,
            kind=KnowledgeKind.LESSON,
            title=lesson.title,
            body=lesson.summary,
            tags=lesson.tags,
            source="ai_derived",
            confidence=lesson.confidence,
            workspace_id=workspace_id or "global",
        )
        return self._kb.store(entry)

    def synthesize_from_findings(
        self, findings: List[dict], workspace_id: str = "global",
    ) -> Lesson:
        """Create a lesson from a list of finding summaries. Output is advisory."""
        if not findings:
            return Lesson(
                title="No findings to synthesize",
                summary="No findings were provided.",
                confidence=0.0,
            )

        categories = list({f.get("category", "OTHER") for f in findings})
        count = len(findings)
        summary = (
            f"Session produced {count} candidate finding(s) "
            f"across categories: {', '.join(categories)}. "
            "All require human verification before action."
        )

        return Lesson(
            title=f"Research session: {count} candidates",
            summary=summary,
            tags=categories,
            confidence=0.5,
            source_ids=[f.get("finding_id", "") for f in findings],
        )

    def recall_relevant(self, query: str, limit: int = 5) -> List[KnowledgeEntry]:
        """Retrieve knowledge entries relevant to a query."""
        return self._kb.search(query=query, limit=limit)
