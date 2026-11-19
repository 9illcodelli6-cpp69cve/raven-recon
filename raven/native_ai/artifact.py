"""ModelArtifact + Checkpoint — INTERFACES ONLY (no weights, no files).

Forward contracts for a future native model's artifact + checkpoint identity. They
REUSE the lifecycle vocabulary of ``raven/ml/registry.py``
(DEVELOPMENT -> CANDIDATE -> PRODUCTION) rather than redefining it, so there is ONE
honest promotion concept. No weights, no serialized files, no loading — every
operational method raises ``NotImplementedError``. Nothing imports this at runtime.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, Optional


class ArtifactLifecycle(str, enum.Enum):
    """Same lifecycle vocabulary as ml/registry (not a second scheme)."""
    DEVELOPMENT = "DEVELOPMENT"
    CANDIDATE   = "CANDIDATE"
    PRODUCTION  = "PRODUCTION"
    ARCHIVED    = "ARCHIVED"


@dataclass(frozen=True)
class _ArtifactIdentity:
    artifact_id: str
    schema_version: str
    lifecycle: ArtifactLifecycle = ArtifactLifecycle.DEVELOPMENT
    provenance: str = ""
    resource_profile_id: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


class ModelArtifact:
    """Interface for a native-model artifact (identity/schema/provenance). NOT IMPLEMENTED."""

    def identity(self) -> _ArtifactIdentity:
        raise NotImplementedError("native_ai.ModelArtifact is an interface only — no artifact exists")

    def lifecycle_state(self) -> ArtifactLifecycle:
        raise NotImplementedError("native_ai.ModelArtifact is an interface only — no artifact exists")

    def resource_profile(self) -> str:
        raise NotImplementedError("native_ai.ModelArtifact is an interface only — no artifact exists")

    def load(self) -> object:
        # Never loads anything — RAVEN ships no native generative weights.
        raise NotImplementedError("native_ai.ModelArtifact is an interface only — no weights to load")


class Checkpoint:
    """Interface for a native-model training checkpoint. NOT IMPLEMENTED."""

    def identity(self) -> _ArtifactIdentity:
        raise NotImplementedError("native_ai.Checkpoint is an interface only — no checkpoint exists")

    def step(self) -> int:
        raise NotImplementedError("native_ai.Checkpoint is an interface only — no checkpoint exists")

    def save(self, path: str) -> str:
        raise NotImplementedError("native_ai.Checkpoint is an interface only — nothing is saved")

    def restore(self) -> object:
        raise NotImplementedError("native_ai.Checkpoint is an interface only — nothing to restore")
