# RAVEN V6 — ML Training Report

**Date: 2026-10-03**
**Status: DEVELOPMENT_ONLY_SYNTHETIC — NOT production-qualified**

## Honest Statement

All training results below are on SYNTHETIC development data only.
REAL_HUMAN_LABEL_COUNT = 0.
Synthetic AUC=1.0 (Task A) is NOT evidence of real-world generalization.

## Architecture

**RavenMLP** (BatchNorm1d → Linear → ReLU → Dropout → Linear)

| Field | Value |
|---|---|
| Input dim | 22 (FeatureVector v1) |
| Hidden dim | 64 |
| Activation | ReLU |
| Normalization | BatchNorm1d(22) |
| Dropout | 0.3 |
| Output dim | 1 (BCEWithLogitsLoss) |
| Parameters | 1,581 |
| PyTorch | 2.14.1+cpu |
| Device | CPU |
| Optimizer | AdamW lr=3e-4 weight_decay=1e-4 |
| Loss | BCEWithLogitsLoss |

## Training Proof (Gate 2 — 15 items verified)

All 15 items verified at runtime:
1-9: instantiation, tensors, forward, logits, loss, backward, gradients, step, parameters changed.
10-15: epochs, validation, checkpoint selected, saved, reloaded into fresh model, CPU inference.

**Parameters changed: 9/9 tensors.** Total L1 delta: ~6.3M (Task A).

## Task A — ResponseDifference

| Field | Value |
|---|---|
| Dataset | DEV_SYNTHETIC |
| Train rows | 420 |
| Val rows | 120 |
| Test rows | 60 |
| Initial loss | 0.6746 |
| Best val loss | 0.0243 |
| Epochs | 40 |
| Best epoch | 40 |
| Val ROC-AUC | 1.0000 (SYNTHETIC) |
| Test ROC-AUC | 1.0000 (SYNTHETIC) |
| Model status | DEVELOPMENT_ONLY_SYNTHETIC |
| Artifact | models/task_a/v_gate2_a/weights.pt |
| SHA-256 | 410428f2743318a11c432b33f2b651d7a689768260f79d9fe883543f0d66316e |

## Task B — AuthorizationSignificance

| Field | Value |
|---|---|
| Dataset | DEV_SYNTHETIC |
| Train rows | 420 |
| Val rows | 120 |
| Test rows | 60 |
| Initial loss | 0.7084 |
| Best val loss | 0.3813 |
| Epochs | 40 |
| Best epoch | 39 |
| Val ROC-AUC | 0.8033 (SYNTHETIC) |
| Test ROC-AUC | 0.8575 (SYNTHETIC) |
| Model status | DEVELOPMENT_ONLY_SYNTHETIC |
| Artifact | models/task_b/v_gate2_b/weights.pt |
| SHA-256 | 53b061c471b904b9934aea225b6c0f4d69fb7d5830ea70a2bf40ec208ec844fa |

## LR vs MLP Comparison (Gate 6 — same splits)

| Model | Task A Val AUC | Task A Test AUC | Task B Val AUC | Task B Test AUC |
|---|---|---|---|---|
| LogisticRegression | 1.0000 | 1.0000 | 0.8097 | 0.8462 |
| RavenMLP | 1.0000 | 1.0000 | 0.8033 | 0.8575 |

Task A: LR >= MLP on synthetic data. Expected — simple linear task.
Task B: MLP slightly outperforms LR on test set (0.8575 vs 0.8462).
Neither is production-qualified. Both run on SYNTHETIC data only.

## Path to Real-Data Models

1. Real in-scope observations accumulated during authorized bug bounty research.
2. Researcher reviews observations and creates LabeledExamples with verified labels.
3. Explicit `python -m raven.ml.train --task task_a --arch mlp` invocation.
4. Challenger model registered with DEVELOPMENT status.
5. Evaluation on held-out real data.
6. Researcher explicitly promotes to CANDIDATE, then PRODUCTION.
7. Only then may status change from DEVELOPMENT_ONLY_SYNTHETIC.
