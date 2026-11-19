"""RAVEN Future Model Task Schemas (Gate 31).

Schema/interface definitions ONLY for specialist future ML tasks.
No fabricated training data. No implemented models.

Gate 32: Real Data Flywheel design.
Gate 33: Active Learning (researcher-review prioritization).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Gate 31 — Future task interfaces (schema only, no fabricated data)
# ─────────────────────────────────────────────────────────────────────────────

class FutureTaskType(str, enum.Enum):
    RESPONSE_DIFFERENCE     = "ResponseDifference"          # already implemented (Task A)
    AUTHORIZATION_SIGNIFICANCE = "AuthorizationSignificance" # already implemented (Task B)
    VULNERABILITY_ROUTING   = "VulnerabilityFamilyRouting"  # SCHEMA ONLY — no model
    ANOMALY_PRIORITIZATION  = "AnomalyPrioritization"       # SCHEMA ONLY — no model
    REFLECTION_CONTEXT      = "ReflectionContext"           # SCHEMA ONLY — no model
    ENDPOINT_SIMILARITY     = "EndpointSimilarity"          # SCHEMA ONLY — no model


@dataclass(frozen=True)
class FutureTaskSpec:
    """Interface specification for a future specialist ML task.

    SCHEMA ONLY — no model has been trained for unimplemented tasks.
    No fabricated training data exists or will be created for these.
    """
    task_type:           FutureTaskType
    description:         str
    input_schema:        str    # feature schema version required
    output_description:  str
    minimum_real_labels: int    # minimum human-labeled examples before training
    is_implemented:      bool   # True only if model code + training exists
    notes:               str    = ""


FUTURE_TASK_SPECS = {
    FutureTaskType.VULNERABILITY_ROUTING: FutureTaskSpec(
        task_type           = FutureTaskType.VULNERABILITY_ROUTING,
        description         = "Route an observation to the most likely vulnerability family.",
        input_schema        = "v1",
        output_description  = "Probability distribution over vulnerability families",
        minimum_real_labels = 500,
        is_implemented      = False,
        notes               = "Requires multi-class labeling from researcher review events.",
    ),
    FutureTaskType.ANOMALY_PRIORITIZATION: FutureTaskSpec(
        task_type           = FutureTaskType.ANOMALY_PRIORITIZATION,
        description         = "Rank observations by novelty/anomaly score for triage.",
        input_schema        = "v1",
        output_description  = "Anomaly score [0,1]; higher = more novel",
        minimum_real_labels = 0,   # unsupervised; but real data still required
        is_implemented      = False,
        notes               = "Unsupervised; needs real observation distribution to be meaningful.",
    ),
    FutureTaskType.REFLECTION_CONTEXT: FutureTaskSpec(
        task_type           = FutureTaskType.REFLECTION_CONTEXT,
        description         = "Classify whether input is reflected in output context (XSS precursor).",
        input_schema        = "v1",
        output_description  = "ReflectionClass: none | data_context | executable_context",
        minimum_real_labels = 200,
        is_implemented      = False,
        notes               = "Requires real reflection observations with researcher-labeled context.",
    ),
    FutureTaskType.ENDPOINT_SIMILARITY: FutureTaskSpec(
        task_type           = FutureTaskType.ENDPOINT_SIMILARITY,
        description         = "Measure similarity between two API endpoints for deduplication.",
        input_schema        = "v1",
        output_description  = "Similarity score [0,1]",
        minimum_real_labels = 0,   # can use structural similarity; real data improves calibration
        is_implemented      = False,
        notes               = "Structural heuristics available; ML calibration needs real endpoint data.",
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Gate 32 — Real Data Flywheel design
# ─────────────────────────────────────────────────────────────────────────────

class DataFlywheelStage(str, enum.Enum):
    OBSERVATION       = "observation"
    CANDIDATE         = "candidate"
    RESEARCHER_REVIEW = "researcher_review"
    REVIEW_EVENT      = "review_event"
    HUMAN_LABEL       = "human_label"
    DATASET_SNAPSHOT  = "dataset_snapshot"
    EXPLICIT_RETRAIN  = "explicit_retrain"
    CHALLENGER_MODEL  = "challenger_model"
    EVALUATION        = "evaluation"
    EXPLICIT_PROMOTION = "explicit_promotion"


FLYWHEEL_FORBIDDEN = [
    "prediction -> automatic_label -> retrain",
    "model sets verification_status",
    "inference result auto-promotes model",
    "synthetic_label treated as human_label",
]

FLYWHEEL_REQUIRED = [
    "observation -> candidate -> researcher_review -> review_event -> human_label",
    "human_label -> dataset_snapshot (explicit, versioned)",
    "dataset_snapshot -> explicit_retraining_command",
    "retrained_model -> challenger_model (DEVELOPMENT status)",
    "challenger_model -> evaluation (held-out real data)",
    "evaluation -> explicit_promotion_decision (human only)",
]


# ─────────────────────────────────────────────────────────────────────────────
# Gate 33 — Active Learning (researcher-review prioritization)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ActiveLearningQueue:
    """Prioritized queue for researcher review.

    Allowed: uncertain/high-information samples -> researcher queue.
    NOT allowed: uncertain sample -> model invents answer.

    Uncertainty is measured by prediction entropy or margin-of-confidence.
    The queue surfaces samples for HUMAN review, never auto-labels them.
    """
    max_queue_size:  int = 100
    _items:          list = field(default_factory=list)

    def add_uncertain(self, observation_ref: str, uncertainty_score: float,
                      model_id: str) -> None:
        """Add a high-uncertainty observation to the researcher review queue."""
        if len(self._items) >= self.max_queue_size:
            # Drop the least uncertain item
            self._items.sort(key=lambda x: x["uncertainty_score"], reverse=True)
            self._items = self._items[:self.max_queue_size - 1]
        self._items.append({
            "observation_ref":  observation_ref,
            "uncertainty_score": uncertainty_score,
            "model_id":         model_id,
            "auto_labeled":     False,   # NEVER True
            "requires_human_review": True,
        })

    def pop_for_review(self) -> Optional[dict]:
        if not self._items:
            return None
        self._items.sort(key=lambda x: x["uncertainty_score"], reverse=True)
        return self._items.pop(0)

    def size(self) -> int:
        return len(self._items)
