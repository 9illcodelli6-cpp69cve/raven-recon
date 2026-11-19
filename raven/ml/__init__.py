"""RAVEN ML Platform (V6).

Real locally-trained machine learning for triage assistance.

INVARIANTS:
- Models never set verification_status.
- Model predictions never become ground truth (no self-labeling).
- All training is explicit (no background/silent retraining).
- CPU inference works without GPU.
- If model unavailable, RAVEN remains fully operational.

Task A: ResponseDifference — does this response differ meaningfully?
Task B: AuthorizationSignificance — is the difference authorization-relevant?
"""
from __future__ import annotations

from .features import FeaturePipeline
from .dataset import DatasetBuilder
from .registry import ModelRegistry, ModelStatus
from .inference import InferenceEngine

__all__ = [
    "FeaturePipeline",
    "DatasetBuilder",
    "ModelRegistry",
    "ModelStatus",
    "InferenceEngine",
]
