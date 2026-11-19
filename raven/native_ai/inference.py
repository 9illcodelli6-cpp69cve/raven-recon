"""Inference — INTERFACE ONLY for a native GENERATIVE model that does not exist.

NOTE (prevents a "third inference engine" misread): this is DISTINCT from
``raven/ml/inference.py::InferenceEngine``, which is the concrete, real classical-
classifier engine. THIS contract is for a hypothetical future native *generative* model
that RAVEN does not have. There is no model, no weights, and no generation here — every
operational method raises ``NotImplementedError``, and predictions (if ever produced)
are advisory-only. Nothing imports this at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class InferenceRequest:
    prompt: str
    max_tokens: int = 0
    metadata: Dict = field(default_factory=dict)


@dataclass(frozen=True)
class InferenceResult:
    """Immutable, ADVISORY generative result (never authorizes actions)."""
    text: str = ""
    tokens: List[int] = field(default_factory=list)
    # Advisory boundary mirrors the generative CompletionResult contract.
    is_advisory: bool = True
    sets_verification_status: bool = False


class Inference:
    """Interface for native generative inference. NOT IMPLEMENTED (no native model)."""

    def predict(self, request: InferenceRequest) -> InferenceResult:
        raise NotImplementedError("native_ai.Inference is an interface only — no native generative model exists")

    def is_ready(self) -> bool:
        # There is no native model; a real implementation would gate on an
        # EvaluationSuite pass + PRODUCTION lifecycle. Until then: not ready.
        raise NotImplementedError("native_ai.Inference is an interface only — no native generative model exists")
