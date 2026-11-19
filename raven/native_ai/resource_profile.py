"""ResourceProfile — INTERFACE ONLY (declared envelope descriptors).

Forward contract: the declared CPU/RAM/VRAM/latency envelope a future native model
would commit to. Pure descriptor contract — it provisions nothing and measures nothing;
every operational method raises ``NotImplementedError``. Nothing imports this at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass(frozen=True)
class _ResourceEnvelope:
    profile_id: str
    cpu_cores: Optional[float] = None
    ram_mb: Optional[int] = None
    vram_mb: Optional[int] = None
    max_latency_ms: Optional[int] = None
    metadata: Dict = field(default_factory=dict)


class ResourceProfile:
    """Interface declaring a native-model resource envelope. NOT IMPLEMENTED."""

    def envelope(self) -> _ResourceEnvelope:
        raise NotImplementedError("native_ai.ResourceProfile is an interface only — no resources are provisioned")

    def fits(self, available: Dict) -> bool:
        raise NotImplementedError("native_ai.ResourceProfile is an interface only — no resources are provisioned")
