"""RAVEN ML Model Registry (Phases 146-153).

Tracks model versions, lifecycle states, and metadata.

INVARIANTS:
- Predictions never become ground truth — registry stores metadata only.
- No model auto-promotes itself to PRODUCTION.
- Rollback always possible: prior champion is preserved.
- RAVEN operates without any registered model.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any


class ModelStatus(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"   # training complete; not yet validated
    CANDIDATE   = "CANDIDATE"     # passes validation; awaiting promotion decision
    PRODUCTION  = "PRODUCTION"    # current champion (at most one per task)
    RETIRED     = "RETIRED"       # superseded or manually retired


@dataclass
class ModelCard:
    """Human-readable record of what a model is and how it was built.

    Stores facts only. Predictions are not stored here.
    """
    model_id: str
    task: str                    # "task_a" or "task_b"
    architecture: str            # e.g. "logistic_regression", "mlp_v1"
    feature_schema_version: str
    n_train_examples: int
    n_val_examples: int
    n_test_examples: int
    contains_synthetic: bool     # True → DEVELOPMENT_ONLY data used
    val_roc_auc: float           # -1.0 if not evaluated
    val_accuracy: float
    val_precision: float
    val_recall: float
    test_roc_auc: float
    test_accuracy: float
    test_precision: float
    test_recall: float
    training_date_utc: str
    training_duration_s: float
    hyperparameters: Dict[str, Any]
    notes: str = ""
    status: ModelStatus = ModelStatus.DEVELOPMENT

    # IMPORTANT: test metrics are REPORTED, not certified
    # They describe performance on the held-out synthetic/dev set only.
    # They do NOT qualify this model for production security decisions.


@dataclass
class ModelVersion:
    model_id: str
    task: str
    architecture: str
    status: ModelStatus
    weights_path: str            # path to .pt or .pkl file
    feature_schema_version: str
    timestamp_utc: str
    card: Optional[ModelCard] = None
    promoted_by: Optional[str] = None    # "researcher" who promoted; never "model"
    promotion_notes: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ModelVersion":
        d = dict(d)
        d["status"] = ModelStatus(d["status"])
        card_data = d.pop("card", None)
        if card_data:
            card_data["status"] = ModelStatus(card_data.get("status", "DEVELOPMENT"))
            d["card"] = ModelCard(**card_data)
        return cls(**d)


class ModelRegistry:
    """Persistent model registry backed by a JSON file.

    Manages DEVELOPMENT → CANDIDATE → PRODUCTION lifecycle.
    No model self-promotes; all promotions are explicit researcher actions.
    """

    def __init__(self, registry_path: str):
        self._path = Path(registry_path)
        self._versions: Dict[str, ModelVersion] = {}
        self._load()

    # ─────────────────────────────────────────────────────────────────────────
    # Registration
    # ─────────────────────────────────────────────────────────────────────────

    def register(self, version: ModelVersion) -> None:
        """Register a new model version.  Status must be DEVELOPMENT."""
        if version.status != ModelStatus.DEVELOPMENT:
            raise ValueError(
                f"New registrations must have status=DEVELOPMENT; got {version.status}"
            )
        if version.model_id in self._versions:
            raise ValueError(f"Model ID already registered: {version.model_id}")
        self._versions[version.model_id] = version
        self._save()

    # ─────────────────────────────────────────────────────────────────────────
    # Lifecycle transitions (all explicit — no auto-promotion)
    # ─────────────────────────────────────────────────────────────────────────

    def advance_to_candidate(self, model_id: str) -> None:
        v = self._get(model_id)
        if v.status != ModelStatus.DEVELOPMENT:
            raise ValueError(f"{model_id} must be DEVELOPMENT to advance; has {v.status}")
        v.status = ModelStatus.CANDIDATE
        if v.card: v.card.status = ModelStatus.CANDIDATE
        self._save()

    def promote_to_production(self, model_id: str,
                               promoted_by: str = "researcher",
                               notes: str = "") -> Optional[str]:
        """Promote a CANDIDATE to PRODUCTION.

        Returns the previous champion's model_id (if any) — it is retired.
        No model may promote itself; promoted_by must be a human identifier.
        """
        v = self._get(model_id)
        if v.status != ModelStatus.CANDIDATE:
            raise ValueError(f"{model_id} must be CANDIDATE to promote; has {v.status}")

        previous_champion = self._get_production_id(v.task)

        if previous_champion:
            old = self._versions[previous_champion]
            old.status = ModelStatus.RETIRED
            if old.card: old.card.status = ModelStatus.RETIRED

        v.status           = ModelStatus.PRODUCTION
        v.promoted_by      = promoted_by
        v.promotion_notes  = notes
        if v.card: v.card.status = ModelStatus.PRODUCTION
        self._save()
        return previous_champion

    def retire(self, model_id: str) -> None:
        v = self._get(model_id)
        v.status = ModelStatus.RETIRED
        if v.card: v.card.status = ModelStatus.RETIRED
        self._save()

    # ─────────────────────────────────────────────────────────────────────────
    # Rollback
    # ─────────────────────────────────────────────────────────────────────────

    def rollback_production(self, task: str,
                              rollback_to_id: str,
                              initiated_by: str = "researcher") -> str:
        """Demote current production model and promote rollback_to_id instead.

        The current production model moves to RETIRED.
        rollback_to_id must already be in the registry (any status).
        Returns the model_id of the demoted model.
        """
        current = self._get_production_id(task)
        if current:
            self._versions[current].status = ModelStatus.RETIRED

        target = self._get(rollback_to_id)
        target.status           = ModelStatus.PRODUCTION
        target.promoted_by      = initiated_by
        target.promotion_notes  = "rollback"
        if target.card: target.card.status = ModelStatus.PRODUCTION
        self._save()
        return current or "(none)"

    # ─────────────────────────────────────────────────────────────────────────
    # Queries
    # ─────────────────────────────────────────────────────────────────────────

    def get_production_model(self, task: str) -> Optional[ModelVersion]:
        pid = self._get_production_id(task)
        return self._versions.get(pid) if pid else None

    def list_versions(self, task: Optional[str] = None,
                       status: Optional[ModelStatus] = None) -> List[ModelVersion]:
        result = list(self._versions.values())
        if task:   result = [v for v in result if v.task == task]
        if status: result = [v for v in result if v.status == status]
        # Deterministic ordering: (timestamp_utc, model_id). model_id breaks
        # ties so the order never depends on registry insertion/JSON order
        # (e.g. task_a/task_b LR versions that share a training timestamp).
        return sorted(result, key=lambda v: (v.timestamp_utc, v.model_id))

    def get(self, model_id: str) -> Optional[ModelVersion]:
        return self._versions.get(model_id)

    # ─────────────────────────────────────────────────────────────────────────
    # Persistence
    # ─────────────────────────────────────────────────────────────────────────

    def _get(self, model_id: str) -> ModelVersion:
        v = self._versions.get(model_id)
        if v is None:
            raise KeyError(f"Model not found in registry: {model_id}")
        return v

    def _get_production_id(self, task: str) -> Optional[str]:
        # Deterministic scan order (timestamp_utc, model_id) so the result never
        # depends on insertion order. Returns None when no PRODUCTION model is
        # registered — RAVEN never auto-promotes a DEVELOPMENT model, so with the
        # current registry (0 PRODUCTION) this always yields None.
        for v in sorted(self._versions.values(),
                        key=lambda v: (v.timestamp_utc, v.model_id)):
            if v.task == task and v.status == ModelStatus.PRODUCTION:
                return v.model_id
        return None

    def _load(self) -> None:
        if not self._path.exists():
            return
        with open(self._path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for entry in data.get("versions", []):
            v = ModelVersion.from_dict(entry)
            self._versions[v.model_id] = v

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {"versions": [v.to_dict() for v in self._versions.values()]}
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
