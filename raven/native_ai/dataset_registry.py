"""DatasetRegistry — INTERFACE ONLY (no storage, no I/O).

Forward contract for registering/listing dataset snapshots + provenance for a future
native model. Lineage may REFERENCE the educational Network-Fundamentals corpus as a
*source* (by reference, never copied); this interface stores nothing today — every
operational method raises ``NotImplementedError``. Nothing imports it at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class DatasetSnapshot:
    """Immutable descriptor of a registered dataset snapshot (metadata only)."""
    snapshot_id: str
    name: str
    provenance: str                         # e.g. "EDUCATIONAL_SYNTHETIC (by reference)"
    created_utc: str = ""
    record_count: Optional[int] = None
    sources: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class DatasetRegistry:
    """Interface for a native-model dataset registry. NOT IMPLEMENTED."""

    def register(self, snapshot: DatasetSnapshot) -> str:
        raise NotImplementedError("native_ai.DatasetRegistry is an interface only — no dataset storage exists")

    def get(self, snapshot_id: str) -> DatasetSnapshot:
        raise NotImplementedError("native_ai.DatasetRegistry is an interface only — no dataset storage exists")

    def list_snapshots(self) -> List[DatasetSnapshot]:
        raise NotImplementedError("native_ai.DatasetRegistry is an interface only — no dataset storage exists")

    def provenance(self, snapshot_id: str) -> str:
        raise NotImplementedError("native_ai.DatasetRegistry is an interface only — no dataset storage exists")
