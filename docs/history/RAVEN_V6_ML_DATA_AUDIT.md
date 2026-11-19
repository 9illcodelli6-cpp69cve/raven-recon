# RAVEN V6 ML Data Audit

**Audit Date:** 2026-10-03  
**Auditor:** RAVEN V6 training pipeline (automated) + developer review  
**Spec Phase:** 64–68  

---

## Summary

| Item | Result |
|------|--------|
| Human-labeled observations (all workspaces) | **0** |
| Synthetic examples used | **600 (DEVELOPMENT_ONLY)** |
| Production-qualified training data | **0** |
| Acceptable data policy for this run | `DatasetPolicy.DEV_SYNTHETIC` |

---

## Workspace DB Audit

Three workspaces were inspected for labeled observations:

| Workspace | DB Path | `labeled_observations` table | Human-labeled rows |
|-----------|---------|-------------------------------|-------------------|
| `example` | `workspaces/example/raven.db` | absent (old schema) | 0 |
| `ws-a` | `workspaces/ws-a/raven.db` | absent (old schema) | 0 |
| `ws-b` | `workspaces/ws-b/raven.db` | absent (old schema) | 0 |

**Finding:** All existing workspaces pre-date the V6 ML schema. The `labeled_observations`,
`model_versions`, `model_inferences`, and `dataset_snapshots` tables are not present.

Fresh DBs created under V6 will have the full schema.

---

## Synthetic Data Policy

Per spec Phase 187, when no human-labeled data exists, the ML pipeline may be validated
with **DEVELOPMENT_ONLY** synthetic data, subject to the following restrictions:

1. All synthetic examples are flagged `synthetic=True` in `LabeledExample`.
2. All datasets built from synthetic data have `contains_synthetic=True`.
3. All model cards note: _"DEVELOPMENT_ONLY: trained on synthetic data for pipeline validation."_
4. No model trained on synthetic data is registered with status other than `DEVELOPMENT`.
5. Metrics from synthetic-data runs are reported truthfully but do NOT certify production readiness.
6. The policy gate `DatasetPolicy.REAL_ONLY` enforces rejection of synthetic data at split time.

---

## Data Used in 2026-10-03 Training Run

| Parameter | Value |
|-----------|-------|
| Policy | `DEV_SYNTHETIC` |
| Positive examples (Task A) | 300 |
| Negative examples (Task A) | 300 |
| Total | 600 |
| Deduplication | enabled |
| Split | 70/15/15 group-aware |
| Train / Val / Test | 420 / 120 / 60 |
| Seed | 42 |

---

## Feature Schema

| Version | Schema hash | Feature count |
|---------|-------------|---------------|
| `v1` | see `FeatureVector.schema_hash()` | 22 |

No label-derived features are included. No credential-bearing header values are included.
Excluded headers (never used as features): `authorization`, `cookie`, `set-cookie`,
`x-api-key`, `x-auth-token`.

---

## Training Results (synthetic dev set — not production-certified)

### Task A: ResponseDifference

| Split | Accuracy | Precision | Recall | ROC-AUC |
|-------|----------|-----------|--------|---------|
| Val   | 1.0000   | 1.0000    | 1.0000 | 1.0000  |
| Test  | 1.0000   | 1.0000    | 1.0000 | 1.0000  |

**Note:** Perfect metrics on synthetic data reflect that the synthetic feature generator
uses very distinct distributions for positive/negative classes. This does NOT indicate
the model will generalize to real observations.

### Task B: AuthorizationSignificance

| Split | Accuracy | Precision | Recall | ROC-AUC |
|-------|----------|-----------|--------|---------|
| Val   | 0.7583   | 0.5349    | 0.7188 | 0.8097  |
| Test  | 0.7833   | 0.6522    | 0.7500 | 0.8462  |

---

## Model Status

Both models registered as **`DEVELOPMENT`**. Neither is `CANDIDATE` or `PRODUCTION`.
Promotion to production requires explicit human action via `ModelRegistry.promote_to_production()`.

---

## What Must Happen Before Real Training

1. Researchers must label real observations (using the `labeled_observations` DB table).
2. A workspace DB migration must run to add the V6 ML schema.
3. `DatasetPolicy.REAL_ONLY` must be used.
4. Features must be extracted from real stored observations.
5. The model must be evaluated on a real held-out test set.
6. A researcher must manually promote to CANDIDATE → PRODUCTION.
