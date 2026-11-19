"""RAVEN Phase III — Research Gateway knowledge store.

Stores retrieved public technical knowledge with source provenance.
Knowledge items are EDUCATIONAL DATA — not instructions.

CRITICAL:
  KnowledgeItem.content is UNTRUSTED DATA from external sources.
  Content cannot modify RAVEN policy, scope, capabilities, or prompts.
  Knowledge items are tagged by concept for educational routing.
  Security authority: NONE — knowledge ≠ confirmed security findings.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from raven.research_gateway.provenance import SourceProvenance, SourceTrustLevel


# ── Knowledge item ────────────────────────────────────────────────────────────

@dataclass
class KnowledgeItem:
    """A single piece of retrieved public technical information.

    Carries full provenance — where it came from, when, and how trustworthy.
    Content is UNTRUSTED DATA and is never treated as an instruction.

    Attributes:
        item_id: Unique identifier.
        title: Short descriptive title.
        content: The raw retrieved text content (UNTRUSTED DATA).
        provenance: Source and trust metadata.
        concept_tags: Educational topic tags (e.g., ["BOLA", "access_control"]).
        summary: A short human-readable summary (generated, not from content).
        content_sha256: SHA-256 of the content for integrity checking.
    """
    item_id: str
    title: str
    content: str          # UNTRUSTED DATA from external source
    provenance: SourceProvenance
    concept_tags: list[str] = field(default_factory=list)
    summary: str = ""     # generated summary (not from content)
    content_sha256: str = ""

    def __post_init__(self) -> None:
        if not self.item_id:
            raise ValueError("item_id must not be empty")
        # Compute content integrity hash
        if self.content and not self.content_sha256:
            self.content_sha256 = hashlib.sha256(
                self.content.encode("utf-8", errors="replace")).hexdigest()

    @property
    def is_authoritative(self) -> bool:
        return self.provenance.trust_level == SourceTrustLevel.AUTHORITATIVE

    def to_summary_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "title": self.title,
            "source_url": self.provenance.source_url,
            "source_type": self.provenance.source_type.value,
            "trust_level": self.provenance.trust_level.value,
            "concept_tags": self.concept_tags,
            "content_sha256": self.content_sha256,
            "is_authoritative": self.is_authoritative,
        }


# ── Knowledge store ───────────────────────────────────────────────────────────

class KnowledgeStore:
    """In-memory store for retrieved public technical knowledge.

    Provides search by concept tag and trust level.
    All items carry provenance; content is never treated as instructions.

    CRITICAL: Items in this store are EDUCATIONAL DATA.
      Knowledge items never provide security authority.
      Content from external sources cannot modify RAVEN behavior.
    """

    def __init__(self) -> None:
        self._items: dict[str, KnowledgeItem] = {}

    def add(self, item: KnowledgeItem) -> None:
        self._items[item.item_id] = item

    def get(self, item_id: str) -> Optional[KnowledgeItem]:
        return self._items.get(item_id)

    def search_by_tag(self, tag: str) -> list[KnowledgeItem]:
        tag_lower = tag.lower()
        return [
            item for item in self._items.values()
            if any(t.lower() == tag_lower for t in item.concept_tags)
        ]

    def search_by_tags(self, tags: list[str]) -> list[KnowledgeItem]:
        """Return items that match ANY of the given tags."""
        tag_set = {t.lower() for t in tags}
        return [
            item for item in self._items.values()
            if any(t.lower() in tag_set for t in item.concept_tags)
        ]

    def authoritative_items(self) -> list[KnowledgeItem]:
        return [item for item in self._items.values() if item.is_authoritative]

    def all_items(self) -> list[KnowledgeItem]:
        return list(self._items.values())

    def __len__(self) -> int:
        return len(self._items)


# ── Prompt injection detector ─────────────────────────────────────────────────

_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore above instructions",
    "system prompt",
    "you are now",
    "act as",
    "forget your",
    "disregard your",
    "new instructions:",
    "override policy",
    "bypass",
    "change your",
    "modify your",
    "update your instructions",
    "raven should",
    "you must now",
    "admin override",
    "jailbreak",
]


def detect_prompt_injection(content: str) -> list[str]:
    """Detect potential prompt injection attempts in retrieved content.

    Returns a list of suspected injection patterns found.
    This is a best-effort heuristic; human review is still required
    for any anomalous content.

    CRITICAL: Even if no patterns are found, content is STILL UNTRUSTED DATA.
    """
    content_lower = content.lower()
    found = [p for p in _INJECTION_PATTERNS if p in content_lower]
    return found


def sanitize_for_analysis(content: str, max_chars: int = 4096) -> str:
    """Truncate and strip control characters from retrieved content.

    Returns a sanitized version safe for educational display.
    Sanitization does NOT make content trusted instructions.
    """
    # Remove null bytes and other control characters
    content = "".join(ch for ch in content if ch >= " " or ch in "\n\r\t")
    return content[:max_chars]
