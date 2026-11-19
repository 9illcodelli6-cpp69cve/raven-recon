# RAVEN V6 — ML Architecture

## Overview

RAVEN's ML platform provides advisory-only triage assistance.
ML results NEVER set verification_status or auto-promote findings.

## Components

| Module | File | Purpose |
|---|---|---|
| Feature pipeline | `raven/ml/features.py` | 22-feature FeatureVector v1 |
| Dataset builder | `raven/ml/dataset.py` | Group-aware splits, synthetic/real policy |
| Model registry | `raven/ml/registry.py` | DEVELOPMENT→CANDIDATE→PRODUCTION lifecycle |
| Inference engine | `raven/ml/inference.py` | Frozen InferenceResult, is_advisory=True |
| Training CLI | `raven/ml/train.py` | RavenMLP, AdamW, BCEWithLogitsLoss, early stopping |
| Future tasks | `raven/ml/future_tasks.py` | Schema-only specs (no models yet) |

## Feature Schema v1 (22 features)

status_code, status_class, body_size, body_entropy, printable_ratio,
is_text_like, is_json, header_count, has_content_type, has_set_cookie,
has_location, elapsed_ms, body_similarity, simhash_similarity,
exact_body_match, normalized_body_match, header_added_count,
header_removed_count, header_changed_count, json_key_count,
json_diff_count, length_z_score

**Excluded (privacy):** Authorization, Cookie, Set-Cookie, X-API-Key, X-Auth-Token

## Implemented Tasks

| Task | Architecture | Status |
|---|---|---|
| Task A — ResponseDifference | RavenMLP (1,581 params) | DEVELOPMENT_ONLY_SYNTHETIC |
| Task B — AuthorizationSignificance | RavenMLP (1,581 params) | DEVELOPMENT_ONLY_SYNTHETIC |

## Unimplemented Tasks (schema only)

VulnerabilityFamilyRouting, AnomalyPrioritization, ReflectionContext, EndpointSimilarity
— schemas defined in `future_tasks.py`. No models. No fabricated training data.

## Data Flywheel

```
Observation → Candidate → Researcher Review → Review Event →
Human Label → Dataset Snapshot → Explicit Retrain → Challenger →
Evaluation → Explicit Promotion
```

**Forbidden:** prediction → automatic_label → retrain

## Active Learning

High-uncertainty observations surface to researcher review queue.
Queue items have `auto_labeled=False`, `requires_human_review=True` always.
Models never self-label uncertain samples.
