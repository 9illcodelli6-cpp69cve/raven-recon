"""RAVEN native-AI foundation — FORWARD INTERFACES ONLY. No model ships here.

================================  HONESTY NOTICE  ================================
RAVEN ships **NO custom/native generative language model**, and none is simulated.
This package is the honest, inert *skeleton* of a hypothetical future RAVEN-owned
generative model — **interfaces (contracts) only**:

  * every operational method raises ``NotImplementedError``;
  * the module constant ``NATIVE_GENERATIVE_MODEL`` is ``None``;
  * there is **no** training code, **no** inference engine, **no** tokenizer vocab,
    **no** weights, **no** model download, and **no** network or SDK access;
  * nothing on RAVEN's live runtime/API path imports this package — it is entirely
    unwired. Importing it has no side effects.

RAVEN must NOT depend on any generative model at runtime. If a native model is ever
built, these contracts are what it would implement; until then they exist purely to
make the roadmap explicit and to make it **impossible to misread this as a shipped
model**. See reconstruction/NATIVE_AI_FOUNDATION.md §3.4 and
reconstruction/CANONICAL_ARCHITECTURE.md §1 row 23.

The classical-classifier engine (``raven/ml/inference.py``) and the educational
Network-Fundamentals lineage (``raven/network_fundamentals/*``) are SEPARATE, real,
DEVELOPMENT-only subsystems — this foundation does not replace or wrap them.
=================================================================================
"""
from __future__ import annotations

# The single, load-bearing honesty constant. There is no native generative model.
# This is never reassigned anywhere in RAVEN's runtime; it stays None.
NATIVE_GENERATIVE_MODEL = None

# A machine-readable restatement for any status surface that wants it.
NATIVE_AI_STATUS = "NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE"

from .dataset_registry import DatasetRegistry, DatasetSnapshot
from .curriculum import Curriculum, CurriculumStage
from .tokenizer import Tokenizer
from .artifact import ModelArtifact, Checkpoint, ArtifactLifecycle
from .training_run import TrainingRun, TrainingRunStatus
from .evaluation import EvaluationSuite, EvaluationResult
from .inference import Inference, InferenceRequest, InferenceResult
from .resource_profile import ResourceProfile

__all__ = [
    "NATIVE_GENERATIVE_MODEL",
    "NATIVE_AI_STATUS",
    "DatasetRegistry",
    "DatasetSnapshot",
    "Curriculum",
    "CurriculumStage",
    "Tokenizer",
    "ModelArtifact",
    "Checkpoint",
    "ArtifactLifecycle",
    "TrainingRun",
    "TrainingRunStatus",
    "EvaluationSuite",
    "EvaluationResult",
    "Inference",
    "InferenceRequest",
    "InferenceResult",
    "ResourceProfile",
]
