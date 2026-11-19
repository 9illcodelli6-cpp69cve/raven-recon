"""RAVEN ML Inference Engine (Phases 154-158).

Produces structured triage-assistance predictions from a trained model.

INVARIANTS:
- InferenceResult is immutable (frozen dataclass).
- Model predictions are ADVISORY ONLY — never set verification_status.
- Predicted triage class is a hint, not a determination.
- RAVEN remains fully operational when no model is loaded (returns None).
- CPU inference only; no GPU dependency.
- Model version and threshold stored with every result for auditability.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Any, Dict

from .features import FeatureVector
from .registry import ModelVersion, ModelRegistry

# The project's own model directory — the ONLY place a relocated artifact is looked
# up (joblib/torch loads are pickle-based, so never search cwd or arbitrary dirs).
_REPO_MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
_WINDOWS_ABS = re.compile(r"^[A-Za-z]:[\\/]")


def resolve_weights_path(raw: str) -> str:
    """Portable lookup for a registry ``weights_path`` (Linux port).

    ``models/registry.json`` was written on Windows: entries hold either a
    backslash-relative path (``models\\x.pkl``) or an absolute ``C:\\Users\\...``
    path. On POSIX neither resolves, so:

    1. an existing path is returned unchanged (no behaviour change on Windows);
    2. backslashes are normalised and the path is retried (relative to the repo);
    3. otherwise the artifact's FILE NAME is looked up in the project's
       ``models/`` directory only.

    If nothing matches, the original string is returned so the load error still
    names the registered path.
    """
    if not raw:
        return raw
    if os.path.exists(raw):
        return raw
    norm = raw.replace("\\", "/")
    if not _WINDOWS_ABS.match(norm):
        rel = Path(norm)
        for cand in (rel, _REPO_MODELS_DIR.parent / rel):
            if cand.is_file():
                return str(cand)
    name = norm.rstrip("/").rsplit("/", 1)[-1]
    if name:
        cand = _REPO_MODELS_DIR / name
        if cand.is_file():
            return str(cand)
    return raw


@dataclass(frozen=True)
class InferenceResult:
    """Immutable structured prediction for one observation.

    ALL fields are advisory only. None of these fields update
    verification_status or constitute a security determination.
    """
    task: str                         # "task_a" or "task_b"
    score: float                      # raw model output (logit or probability)
    probability: float                # calibrated [0, 1] probability
    threshold: float                  # decision threshold used
    predicted_positive: bool          # score >= threshold
    predicted_triage_class: str       # human-readable hint ("differs" / "does_not_differ" / ...)
    model_id: str
    model_version: str                # architecture identifier
    feature_schema_version: str
    inference_ms: int                 # wall-clock time for this inference

    # These are reminders to the consumer:
    is_advisory: bool = True
    sets_verification_status: bool = False


TASK_A_POSITIVE_LABEL = "response_differs_meaningfully"
TASK_A_NEGATIVE_LABEL = "response_does_not_differ_meaningfully"
TASK_B_POSITIVE_LABEL = "auth_relevant_difference"
TASK_B_NEGATIVE_LABEL = "difference_not_auth_relevant"


class InferenceEngine:
    """Run model inference on a FeatureVector.

    Loads a model by path and produces InferenceResult.
    Returns None if no model is available — RAVEN continues without ML.
    """

    DEFAULT_THRESHOLD = 0.5

    def __init__(self, model_version: ModelVersion, threshold: float = DEFAULT_THRESHOLD):
        self._version    = model_version
        self._threshold  = threshold
        self._model: Any = None
        self._load_model()

    @classmethod
    def from_registry(cls, registry: ModelRegistry, task: str,
                       threshold: float = DEFAULT_THRESHOLD) -> Optional["InferenceEngine"]:
        """Build engine from the current production model for a task.

        Returns None if no production model is registered — caller handles gracefully.
        """
        mv = registry.get_production_model(task)
        if mv is None:
            return None
        return cls(mv, threshold)

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def predict(self, fv: FeatureVector) -> InferenceResult:
        """Predict on a single FeatureVector.

        Returns an InferenceResult with is_advisory=True always.
        Raises ValueError on schema mismatch or invalid features.
        Raises RuntimeError if model failed to load.
        """
        if fv.schema_version != self._version.feature_schema_version:
            raise ValueError(
                f"Feature schema version mismatch: FeatureVector has "
                f"{fv.schema_version!r}, model expects "
                f"{self._version.feature_schema_version!r}"
            )
        fv.validate()
        if self._model is None:
            raise RuntimeError(
                f"Model {self._version.model_id} failed to load from "
                f"{self._version.weights_path}"
            )

        t0 = time.perf_counter_ns()
        score, prob, class_label = self._run_model(fv)
        elapsed_ms = max(0, int((time.perf_counter_ns() - t0) / 1_000_000))

        predicted_positive = prob >= self._threshold
        task = self._version.task

        if class_label is not None:
            # Multiclass advisory hint: the predicted class name. For multiclass
            # models `predicted_positive` is just "confidence >= threshold";
            # the real signal is this class label (a hint, not a determination).
            label = class_label
        elif task == "task_a":
            label = TASK_A_POSITIVE_LABEL if predicted_positive else TASK_A_NEGATIVE_LABEL
        elif task == "task_b":
            label = TASK_B_POSITIVE_LABEL if predicted_positive else TASK_B_NEGATIVE_LABEL
        else:
            label = "positive" if predicted_positive else "negative"

        return InferenceResult(
            task=task,
            score=score,
            probability=prob,
            threshold=self._threshold,
            predicted_positive=predicted_positive,
            predicted_triage_class=label,
            model_id=self._version.model_id,
            model_version=self._version.architecture,
            feature_schema_version=self._version.feature_schema_version,
            inference_ms=elapsed_ms,
            is_advisory=True,
            sets_verification_status=False,
        )

    def predict_batch(self, fvs: list) -> list:
        return [self.predict(fv) for fv in fvs]

    # ─────────────────────────────────────────────────────────────────────────
    # Model loading
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_sklearn_arch(arch: str) -> bool:
        """True for every sklearn-family architecture we can load with joblib.

        Covers the binary task-LR models (``logistic_regression``) AND the
        network-fundamentals multiclass classifiers whose arch metadata is
        ``logistic_regression_multiclass`` / ``random_forest_multiclass``
        (Bug A: these ``*_multiclass`` strings were previously rejected).
        """
        return arch.startswith("logistic_regression") or arch.startswith("random_forest")

    def _load_model(self) -> None:
        arch = self._version.architecture
        path = resolve_weights_path(self._version.weights_path)

        if self._is_sklearn_arch(arch):
            self._model = self._load_sklearn(path)
        elif arch.startswith("mlp"):
            self._model = self._load_pytorch(path)
        else:
            raise ValueError(f"Unknown architecture: {arch}")

    def _load_sklearn(self, path: str) -> Any:
        """Load a RAVEN-produced sklearn artifact (trusted; read-only).

        The loaded object may be any of:
          * a ``{"model": estimator, "scaler": StandardScaler}`` dict
            (binary task-LR artifacts — Bug B: the scaler must be applied
            at inference time, see ``_run_sklearn``);
          * a fitted ``Pipeline`` that carries its own preprocessing
            (net multiclass LR);
          * a bare fitted estimator (net multiclass RandomForest, or an
            early net LR saved without a scaler).
        Unwrapping/dispatch happens at inference time in ``_unwrap_sklearn``.
        """
        try:
            import joblib
            return joblib.load(path)
        except Exception as e:
            raise RuntimeError(f"Failed to load sklearn model from {path}: {e}") from e

    def _unwrap_sklearn(self):
        """Return ``(estimator, scaler)`` from the loaded sklearn artifact.

        Bug B: task-LR artifacts are stored as ``{"model", "scaler"}`` dicts;
        the estimator was fitted on scaled features, so the persisted scaler
        MUST be applied before ``predict_proba``. Pipelines and bare estimators
        carry (or need) no external scaler, so ``scaler`` is None for them.
        """
        obj = self._model
        if isinstance(obj, dict):
            estimator = obj.get("model")
            if estimator is None:
                raise RuntimeError(
                    f"sklearn artifact dict missing 'model' key; keys={list(obj.keys())}"
                )
            return estimator, obj.get("scaler")
        return obj, None

    def _load_pytorch(self, path: str) -> Any:
        """Load from state_dict checkpoint (safe — no arbitrary pickle objects)."""
        try:
            import torch
            from raven.ml.train import RavenMLP
            ckpt = torch.load(path, map_location="cpu", weights_only=True)
            model = RavenMLP(
                input_dim=ckpt.get("input_dim", 22),
                hidden_dim=ckpt.get("hidden_dim", 64),
                dropout=ckpt.get("dropout", 0.3),
            )
            model.load_state_dict(ckpt["state_dict"])
            model.eval()
            return model
        except Exception as e:
            raise RuntimeError(f"Failed to load PyTorch model from {path}: {e}") from e

    # ─────────────────────────────────────────────────────────────────────────
    # Inference
    # ─────────────────────────────────────────────────────────────────────────

    def _run_model(self, fv: FeatureVector):
        """Return ``(score, probability, class_label)``.

        ``class_label`` is None for binary models (the caller derives the
        human-readable triage hint from the task); for multiclass models it is
        the predicted class name, which is advisory ONLY — it ranks/classifies,
        it never verifies or authorizes.
        """
        arch = self._version.architecture
        x = [float(v) for v in fv.to_list()]

        if self._is_sklearn_arch(arch):
            return self._run_sklearn(x)
        elif arch.startswith("mlp"):
            return self._run_pytorch(x)
        else:
            raise ValueError(f"Unknown architecture: {arch}")

    def _run_sklearn(self, x: list):
        import numpy as np
        estimator, scaler = self._unwrap_sklearn()
        arr = np.array(x, dtype=float).reshape(1, -1)
        if scaler is not None:
            arr = scaler.transform(arr)      # Bug B: apply the persisted scaler
        proba = np.asarray(estimator.predict_proba(arr))[0]

        if self._version.architecture.endswith("_multiclass"):
            # Bug A: multiclass advisory output — confidence is the max class
            # probability; the predicted class name comes from the estimator's
            # own classes_ (never a verification verdict).
            best = int(np.argmax(proba))
            prob = float(proba[best])
            classes = getattr(estimator, "classes_", None)
            label = str(classes[best]) if classes is not None else f"class_{best}"
            return prob, prob, label

        # Binary: probability of the positive class (index 1).
        prob = float(proba[1]) if proba.shape[0] >= 2 else float(proba[0])
        return prob, prob, None

    def _run_pytorch(self, x: list):
        import torch
        import torch.nn.functional as F
        tensor = torch.tensor(x, dtype=torch.float32).unsqueeze(0)
        self._model.eval()
        with torch.no_grad():
            logit = self._model(tensor)
            if logit.shape[-1] == 1:
                logit = logit.squeeze(-1)
                prob  = float(torch.sigmoid(logit).item())
                score = float(logit.item())
            else:
                probs = F.softmax(logit, dim=-1)
                prob  = float(probs[0, 1].item())
                score = prob
        return score, prob, None
