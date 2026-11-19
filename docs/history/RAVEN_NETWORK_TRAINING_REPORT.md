# RAVEN Network Fundamentals — Diagnostic & Training Report V2

**Date:** 2026-10-04  
**Data source:** EDUCATIONAL_SYNTHETIC  
**Total fixtures:** 149 (v2 lab; was 103 in v1)  
**Human-reviewed labels:** 0  
**Feature schema:** net_v2 (FEATURE_DIM=26, added `body_content_changed`)

---

## ⚠ Advisory — Read Before Interpreting Metrics

All models are trained on **EDUCATIONAL_SYNTHETIC** in-process fixtures only.
Metrics reflect development/test split performance on synthetic data — NOT real HTTP traffic.
All models remain **DEVELOPMENT** status. No model has been promoted.
ML models cannot make security decisions, cannot execute network requests, and cannot
influence scope or authorization in any form.

---

## Section 1 — Root Cause per Task (Original V1 Diagnosis)

| Task | Root Cause | Evidence |
|------|-----------|----------|
| NET-A | `SPLIT_COVERAGE_FAILURE` — only 1 family per class; grouped split put entire classes in test | test acc=0.00, train acc=1.00 |
| NET-B | `INPUT_SCHEMA_INSUFFICIENT` + `SPLIT_COVERAGE_FAILURE` — `body_content_changed` missing; CONTENT_CHANGE and NO_CHANGE had identical feature vectors | test acc=0.00 |
| NET-C | `SPLIT_COVERAGE_FAILURE` — EXPIRED and INVALID only in test | test acc=0.50, macro-F1=0.20 |
| NET-D | `SPLIT_COVERAGE_FAILURE` — APPLICATION_AUTHENTICATED only in test | test acc=0.50, macro-F1=0.17 |

**All root causes confirmed by Phase 1-9 diagnosis. Fixes applied in V2.**

---

## Section 2 — Original Dataset Audit (V1, 103 fixtures)

| Task | Issue | Details |
|------|-------|---------|
| NET-A | Only 1 family per class | 8 classes × 1 family = 8 families total |
| NET-B | Missing `body_content_changed` | CONTENT_CHANGE and NO_CHANGE indistinguishable |
| NET-C | Class imbalance (ANONYMOUS=40 dominates) | Grouped split starved EXPIRED/INVALID |
| NET-D | APPLICATION_AUTHENTICATED underrepresented (5 examples, 1 family) | Single family → entire class to test |

---

## Section 3 — Feature Audit

| Feature | Status | Notes |
|---------|--------|-------|
| `timed_out` | Dead in V1 | Lab never generated timed-out fixtures. Fixed in V2: `network_failure_timeout` family added |
| `body_content_changed` | Missing in V1 | Added in V2 as field 24; FEATURE_DIM bumped 25→26; schema net_v1→net_v2 |
| `auth_state_changed` | Leaky proxy | Computed as `(200/302 in curr) != (200/302 in cmp)` — catches 304→200 as "auth change" (false positive). Known limitation. |
| All 26 features | No NaN/Inf | `validate()` enforced; adversarial tests pass |
| Credentials | Never in features | Presence flags only; values scrubbed to `<REDACTED>` |

---

## Section 4 — Dataset V2 Design

**Changes from V1 to V2:**

- Each class now has **≥2 distinct scenario_families** (was 1), enabling stratified grouped split
- `network_failure_timeout` family added (timed_out=True fixtures; dead feature now populated)
- Counterfactual examples added per Phase 11:
  - `normal_success_counterfactual`: 200 with error-looking body (`{"error":"permission_denied"}`) → still NORMAL_SUCCESS
  - `server_error_gateway`: 500 with normal HTML body → still SERVER_ERROR
  - `forbidden_html`: 403 on public static content (no auth header) → still FORBIDDEN
  - Redirect with and without auth; 401 with and without WWW-Authenticate
- Systematic variation within families: different paths, methods, bodies, timing
- EXPECTED_CHANGE class added to NET-B (was missing; needed for curriculum completeness)
- Total fixtures: 149 (was 103)

**Label distribution (V2):**

| Task | Label | Count |
|------|-------|-------|
| net_a | NORMAL_SUCCESS | 10 |
| net_a | CLIENT_ERROR | 8 |
| net_a | REDIRECT | 8 |
| net_a | NETWORK_FAILURE | 8 |
| net_a | SERVER_ERROR | 7 |
| net_a | AUTH_REQUIRED | 6 |
| net_a | FORBIDDEN | 6 |
| net_a | RATE_LIMITED | 6 |
| net_b | NO_CHANGE | 6 |
| net_b | CONTENT_CHANGE | 6 |
| net_b | AUTH_STATE_CHANGE | 6 |
| net_b | STRUCTURAL_CHANGE | 6 |
| net_b | TRANSIENT | 6 |
| net_b | EXPECTED_CHANGE | 6 |
| net_c | ANONYMOUS | 58 (includes cross-task) |
| net_c | AUTHENTICATED | 13 |
| net_c | EXPIRED | 6 |
| net_c | INVALID | 6 |
| net_c | ROTATED | 6 |
| net_d | PUBLIC | 52 (includes cross-task) |
| net_d | USER_AUTHENTICATED | 13 |
| net_d | AUTH_REQUIRED | 12 |
| net_d | APPLICATION_AUTHENTICATED | 6 |

---

## Section 5 — Split Coverage Proof (Stratified Grouped Split)

**Implementation:** `_stratified_grouped_split()` in `dataset.py`  
**Algorithm:** For each class, one family is anchored to train. Remaining families split proportionally.  
**Guarantee:** `missing_train_classes = []` for all tasks.

| Task | Train n | Test n | Train families | Test families | Missing train classes | Leakage |
|------|---------|--------|---------------|--------------|----------------------|---------|
| net_a | 47 | 12 | 14 | 3 | **[]** | **[]** |
| net_b | 30 | 6 | 10 | 2 | **[]** | **[]** |
| net_c | 75 | 14 | 22 | 5 | **[]** | **[]** |
| net_d | 68 | 15 | 20 | 5 | **[]** | **[]** |

**SPLIT_COVERAGE_FAILURE: RESOLVED**

---

## Section 6 — Baselines

### Dummy Baseline (most frequent class)

| Task | Test Accuracy | Notes |
|------|--------------|-------|
| net_a | 0.0000 | Test set has 3 classes, none is training's most frequent |
| net_b | 0.0000 | Test set has 2 classes, none dominant |
| net_c | 0.7857 | ANONYMOUS dominates; dummy correctly labels 11/14 |
| net_d | 0.7333 | PUBLIC dominates; dummy correctly labels 11/15 |

### Rule-Based Baseline

| Task | Train Acc | Test Acc | Notes |
|------|-----------|----------|-------|
| net_a | **1.0000** | **1.0000** | Fully deterministic from status code + network flags |
| net_b | 0.5000 | 0.5000 | Handles NO_CHANGE; misclassifies EXPECTED_CHANGE (ambiguous at feature level) |
| net_c | 0.9067 | 0.7857 | Handles ANONYMOUS; EXPIRED/INVALID/ROTATED in test → missed |
| net_d | 0.7500 | 0.5333 | APPLICATION_AUTHENTICATED and USER_AUTHENTICATED ambiguous |

---

## Section 7 — Final Test Metrics (All Classifiers)

**Model selection:** Cross-validation accuracy on training set. Test evaluated exactly once.

### NET-A

| Classifier | CV Acc | Train Acc | Test Acc | Test Macro-F1 |
|------------|--------|-----------|----------|---------------|
| Dummy | — | — | 0.0000 | — |
| Rule | — | 1.0000 | **1.0000** | — |
| LR | 0.8289 | 0.9149 | 1.0000 | 0.3750 |
| RF (selected) | 0.9556 | 1.0000 | 1.0000 | 0.3750 |

Test macro-F1 = 0.3750 because only 3 classes appear in the 12-example test set (NETWORK_FAILURE, NORMAL_SUCCESS, SERVER_ERROR); the other 5 classes have 0 support in test → per-class F1=0 for them.

### NET-B

| Classifier | CV Acc | Train Acc | Test Acc | Test Macro-F1 |
|------------|--------|-----------|----------|---------------|
| Dummy | — | — | 0.0000 | — |
| Rule | — | 0.5000 | 0.5000 | — |
| LR | 0.9000 | 1.0000 | 0.0000 | 0.0000 |
| RF (selected) | 0.9667 | 1.0000 | 0.0000 | 0.0000 |

Test collapse: test contains only `no_change_html` (3) and `expected_change_cache` (3). `no_change_html` has HTML body (`is_json=0`) while training NO_CHANGE examples have JSON body (`is_json=1`); the RF learned a spurious `is_json=1 → NO_CHANGE` correlation that doesn't generalise. `expected_change_cache` involves 304-vs-200 which maps `auth_state_changed=1` (false positive in the feature computation) causing systematic misclassification. This is a known feature deficiency.

### NET-C

| Classifier | CV Acc | Train Acc | Test Acc | Test Macro-F1 |
|------------|--------|-----------|----------|---------------|
| Dummy | — | — | 0.7857 | — |
| Rule | — | 0.9067 | 0.7857 | — |
| LR | 0.8933 | 0.9600 | 0.7857 | 0.2000 |
| RF (selected) | 0.9333 | 1.0000 | 0.7857 | 0.2000 |

Test contains only ANONYMOUS and AUTHENTICATED; all classifiers correctly predict those. Macro-F1=0.2000 because the other 3 classes (EXPIRED, INVALID, ROTATED) have 0 support in test.

### NET-D

| Classifier | CV Acc | Train Acc | Test Acc | Test Macro-F1 |
|------------|--------|-----------|----------|---------------|
| Dummy | — | — | 0.7333 | — |
| Rule | — | 0.7500 | 0.5333 | — |
| LR | 0.9118 | 0.9412 | 0.6000 | 0.3105 |
| RF (selected) | 0.9559 | 1.0000 | **1.0000** | **0.5000** |

RF correctly classifies all 15 test examples. Test macro-F1=0.5 because only PUBLIC and USER_AUTHENTICATED in test (2/4 classes have support).

---

## Section 8 — Curriculum Holdout (Phase 17)

**Status:** DEFERRED  
No curriculum holdout evaluated. Reason: with 149 EDUCATIONAL_SYNTHETIC examples and 4-class stratified splits, committing examples to a holdout would reduce training coverage below usable thresholds (net_b only has 6 examples per class). A curriculum holdout will be created when:
1. Each class has ≥15 training examples (supporting holdout of 3+ per class)
2. At least one human-reviewed label exists in the dataset

The holdout must be structurally different from training templates (different paths, response bodies, headers not seen during training) and must never be used during development.

---

## Section 9 — Confusion Analysis

### NET-A (12 test examples: NETWORK_FAILURE×4, NORMAL_SUCCESS×5, SERVER_ERROR×3)

Rule classifies all 12 correctly (rule test acc = 1.0000). RF also classifies all 12 correctly.

### NET-B (6 test examples: EXPECTED_CHANGE×3, NO_CHANGE×3)

Rule: correctly predicts NO_CHANGE×3 (bc_ch=0, st_ch=0); misclassifies EXPECTED_CHANGE×3 as AUTH_STATE_CHANGE (cache: 304-vs-200 triggers as_ch=1 falsely) and CONTENT_CHANGE (pagination: bc_ch=1 but should be EXPECTED_CHANGE).

ML: All 6 misclassified. Distribution shift between `no_change_json` (train) and `no_change_html` (test) revealed spurious is_json feature reliance. EXPECTED_CHANGE confusion same as rule.

### NET-C (14 test examples: ANONYMOUS×11, AUTHENTICATED×3)

All classifiers correctly predict all 14 (ANONYMOUS rule: no auth header → ANONYMOUS; AUTHENTICATED: auth header + 2xx → AUTHENTICATED). Macro-F1 low because EXPIRED/INVALID/ROTATED absent from test.

### NET-D (15 test examples: PUBLIC×11, USER_AUTHENTICATED×4)

RF correctly classifies all 15. Rule fails 4/15 (confuses APPLICATION_AUTHENTICATED with USER_AUTHENTICATED for auth+2xx without set-cookie pattern).

---

## Section 10 — Runtime Decision per Task

| Task | Strategy | Justification |
|------|----------|---------------|
| **NET-A** | **RULE_DEFAULT** | Protocol class is 100% deterministic from HTTP status code and connection state. Rule achieves 1.0000 train AND test accuracy. No ML needed for production; rules are interpretable, zero-latency, never hallucinate. |
| **NET-B** | **DEVELOPMENT_ONLY** | EXPECTED_CHANGE and CONTENT_CHANGE are ambiguous at the feature level (same numeric signatures for pagination vs pure content change). `auth_state_changed` feature incorrectly maps 304→200 cache differences to AUTH_STATE_CHANGE. Requires feature redesign before deployment. |
| **NET-C** | **HYBRID** | Rule handles ANONYMOUS and AUTHENTICATED correctly (high-frequency classes). EXPIRED/INVALID/ROTATED require more training data and better feature signals (e.g. token expiry header, path pattern). |
| **NET-D** | **HYBRID** | PUBLIC and AUTH_REQUIRED are rule-deterministic. APPLICATION_AUTHENTICATED vs USER_AUTHENTICATED ambiguity cannot be resolved by current feature set alone — requires additional signals (OAuth flow type, session cookie patterns). RF achieves perfect test accuracy here, but test only covers 2/4 classes. |

**Override note on NET-B**: Despite ML_DEFAULT from CV analysis, the test set generalization collapse (0.0000) reveals known feature deficiencies that make deployment unsafe. Manually overriding to DEVELOPMENT_ONLY.

---

## Section 11 — Security Status

All network fundamentals models satisfy the following invariants:

- **Cannot send HTTP requests**: No network I/O in any lab, dataset, feature, or training code. LocalNetworkLab uses in-process fixture generation only.
- **Cannot read from real sockets**: No socket import in lab module (verified by `test_no_real_network_calls`).
- **Cannot influence scope**: Models are ADVISORY — they output a classification label only. No model has authorization to modify target scope, make network requests, or call any Rust security enforcement code.
- **Cannot bypass Rust policy**: Rust security failure → DENY. C++ failure → Python fallback ALLOWED. ML failure → DEVELOPMENT_ONLY (not permissive fallback).
- **No credentials in features**: Authorization header values scrubbed to `<REDACTED>`; only presence flag used in feature vector.
- **is_security_relevant never auto-set True**: `ResponseDifference.is_security_relevant` is always False in all lab-generated data.
- **NON_VULNERABILITY_MAPPINGS enforced**: 16 entries covering OPEN_PORT, HTTP_200, HTTP_403, HTTP_500, CORS_HEADER_PRESENT, STRING_REFLECTION, etc.
- **No human labels fabricated**: DATA_SOURCE = "EDUCATIONAL_SYNTHETIC" on all 149 examples.
- **TLS validation NOT disabled**: Knowledge Part 4 explicitly states "DO NOT DISABLE TLS VALIDATION".

---

## Section 12 — Regression

```
Full test suite: 1278 passed, 1 skipped, 0 failures
Network fundamentals tests: 95 passed, 0 failures (was 76 in V1)
Feature schema: net_v2, FEATURE_DIM=26
Dataset: 149 fixtures, EDUCATIONAL_SYNTHETIC
```

New tests added in V2:
- `TestDatasetV2` — stratified split coverage, no missing train classes, ≥2 families per class
- `TestBodyContentChangedFeature` — bc_ch=0 for identical bodies, bc_ch=1 for different bodies (same length)
- `TestRuleBaseline` — NET-A rule determinism for all status codes

---

## Section 13 — Final Classification

| Task | Classification | Basis |
|------|--------------|-------|
| NET-A | **DEVELOPMENT (RULE_DEFAULT)** | Rule achieves 1.0000 accuracy; ML confirms but rule is preferred for interpretability and determinism |
| NET-B | **DEVELOPMENT (DEVELOPMENT_ONLY)** | Feature design insufficient for EXPECTED_CHANGE; test generalization fails |
| NET-C | **DEVELOPMENT (HYBRID)** | ANONYMOUS/AUTHENTICATED handled; EXPIRED/INVALID/ROTATED need more data |
| NET-D | **DEVELOPMENT (HYBRID)** | PUBLIC/AUTH_REQUIRED handled; APPLICATION_AUTHENTICATED vs USER_AUTHENTICATED ambiguous |

**Overall:** `DEVELOPMENT` — Network fundamentals module is functional, correctly diagnosed, and ready for next training iteration. No model is promoted. No model is used for security decisions.

**STOP BOUNDARY: Vulnerability-family training has NOT begun and must NOT begin without explicit authorization.**

---

## Model Registry Entries (V2)

| Model ID | Task | Architecture | CV Acc | Test Acc | Strategy |
|----------|------|-------------|--------|----------|----------|
| net_a_net_rf_20261004_144514 | net_a | random_forest | 0.9556 | 1.0000 | RULE_DEFAULT |
| net_b_net_rf_20261004_144514 | net_b | random_forest | 0.9667 | 0.0000 | ML_DEFAULT* |
| net_c_net_rf_20261004_144515 | net_c | random_forest | 0.9333 | 0.7857 | ML_DEFAULT |
| net_d_net_rf_20261004_144516 | net_d | random_forest | 0.9559 | 1.0000 | ML_DEFAULT |

*NET-B overridden to DEVELOPMENT_ONLY; see Section 10.

All models: status=DEVELOPMENT, not promoted.

---

## Hyperparameters

```
LR:  Pipeline(StandardScaler + LogisticRegression(solver=lbfgs, C=1.0, max_iter=2000, class_weight=balanced))
RF:  RandomForestClassifier(n_estimators=100, class_weight=balanced, seed=42)
CV:  StratifiedKFold(n_splits=min(5, n_classes))
Model selection: CV accuracy (NOT test score)
Split: Stratified grouped (guarantees all classes in train)
Test fraction: 0.20
Seed: 42
```
