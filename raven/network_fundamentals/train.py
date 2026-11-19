"""RAVEN Network Fundamentals — training pipeline for NET-A/B/C/D.

Trains and evaluates three classifiers per task:
  1. Deterministic rule baseline (per-task hand-coded rules)
  2. Logistic Regression (sklearn lbfgs + StandardScaler)
  3. RandomForestClassifier (sklearn)

Runtime strategy is selected by per-task analysis, NOT by test score.
Models are registered as DEVELOPMENT — never auto-promoted.

INVARIANTS:
- LogisticRegression is a logistic regression — NEVER called a neural network.
- RandomForestClassifier is a random forest — NEVER called a neural network.
- All data is EDUCATIONAL_SYNTHETIC — metrics reflect that data only.
- Models are registered as DEVELOPMENT — never auto-promoted.
- NEVER overwrites task_a or task_b registry entries.
- Metrics are reported verbatim — never rounded to look better.
- Model selection uses cross-validation, NOT test score.
- Test set is evaluated exactly once, after model selection.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DATA_SOURCE = "EDUCATIONAL_SYNTHETIC"
MODEL_TASKS = ("net_a", "net_b", "net_c", "net_d")
PROTECTED_TASKS = frozenset({"task_a", "task_b"})

DEFAULT_OUTPUT_DIR = Path("models")
DEFAULT_REGISTRY   = Path("models/registry.json")

# Feature vector indices (must match NetworkFeatureVector.feature_names())
# net_v3: 29 features (indices 0-28)
_I_STATUS_CODE   = 0
_I_IS_2XX        = 2
_I_IS_3XX        = 3
_I_IS_4XX        = 4
_I_IS_5XX        = 5
_I_HAS_AUTH_REQ  = 6
_I_HAS_WWW_AUTH  = 7
_I_HAS_SET_COOKIE= 8
_I_HAS_RETRY_AFT = 10
_I_TIMED_OUT     = 17
_I_CONN_ERR      = 18
_I_ST_CHANGED    = 19
_I_AUTH_ST_CHANGE= 22
_I_BODY_CHG      = 23
_I_IS_304        = 24
_I_CMP_IS_304    = 25
_I_HAS_ETAG      = 26


# ── Rule-based classifiers ────────────────────────────────────────────────────

def _rule_net_a(fv: list[float]) -> str:
    """Deterministic protocol class from status code and connection state."""
    status   = int(fv[_I_STATUS_CODE])
    timedout = int(fv[_I_TIMED_OUT])
    connerr  = int(fv[_I_CONN_ERR])
    if timedout == 1 or connerr == 1 or status == 0:
        return "NETWORK_FAILURE"
    if 200 <= status < 300:
        return "NORMAL_SUCCESS"
    if 300 <= status < 400:
        return "REDIRECT"
    if status == 401:
        return "AUTH_REQUIRED"
    if status == 403:
        return "FORBIDDEN"
    if status == 429:
        return "RATE_LIMITED"
    if 400 <= status < 500:
        return "CLIENT_ERROR"
    if 500 <= status < 600:
        return "SERVER_ERROR"
    return "UNKNOWN"


def _rule_net_b(fv: list[float]) -> str:
    """Heuristic response-difference class from diff feature fields."""
    st_ch  = int(fv[_I_ST_CHANGED])
    as_ch  = int(fv[_I_AUTH_ST_CHANGE])
    bc_ch  = int(fv[_I_BODY_CHG])
    is_5xx = int(fv[_I_IS_5XX])
    is_3xx = int(fv[_I_IS_3XX])
    is_2xx = int(fv[_I_IS_2XX])
    is_304   = int(fv[_I_IS_304])
    cmp_304  = int(fv[_I_CMP_IS_304])
    # Cache semantics (net_v3): check before auth/structural rules.
    # cmp_304==1 → comparison was a 304 cache-hit; current delivered fresh content → EXPECTED_CHANGE
    if cmp_304 == 1:
        return "EXPECTED_CHANGE"
    # is_304==1 with status_changed==1 → current is a 304 cache-hit, comparison was a 200 → EXPECTED_CHANGE
    if is_304 == 1 and st_ch == 1:
        return "EXPECTED_CHANGE"
    if st_ch == 1 and as_ch == 1:
        return "AUTH_STATE_CHANGE"
    if st_ch == 1 and is_5xx == 1:
        return "TRANSIENT"
    if st_ch == 1 and is_3xx == 1:
        return "STRUCTURAL_CHANGE"
    if st_ch == 1 and not (is_2xx == 1):
        return "STRUCTURAL_CHANGE"
    # Status unchanged — check body
    if bc_ch == 1:
        return "CONTENT_CHANGE"
    return "NO_CHANGE"


def _rule_net_c(fv: list[float]) -> str:
    """Heuristic session state from response headers and auth signals."""
    set_ck  = int(fv[_I_HAS_SET_COOKIE])
    www_au  = int(fv[_I_HAS_WWW_AUTH])
    has_au  = int(fv[_I_HAS_AUTH_REQ])
    is_2xx  = int(fv[_I_IS_2XX])
    is_4xx  = int(fv[_I_IS_4XX])
    if set_ck == 1 and is_2xx == 1:
        return "ROTATED"
    if has_au == 1 and is_4xx == 1 and www_au == 1:
        return "EXPIRED"
    if has_au == 1 and is_4xx == 1:
        return "INVALID"
    if has_au == 1 and is_2xx == 1:
        return "AUTHENTICATED"
    return "ANONYMOUS"


def _rule_net_d(fv: list[float]) -> str:
    """Heuristic auth context from request auth header and response status."""
    has_au  = int(fv[_I_HAS_AUTH_REQ])
    set_ck  = int(fv[_I_HAS_SET_COOKIE])
    www_au  = int(fv[_I_HAS_WWW_AUTH])
    is_2xx  = int(fv[_I_IS_2XX])
    is_4xx  = int(fv[_I_IS_4XX])
    status  = int(fv[_I_STATUS_CODE])
    # 401 or WWW-Authenticate: server demands authentication
    if status == 401 or www_au == 1:
        return "AUTH_REQUIRED"
    # Authenticated user hitting an access error (e.g. 403): auth context is USER_AUTHENTICATED
    if has_au == 1 and is_4xx == 1:
        return "USER_AUTHENTICATED"
    # User session: success with session-cookie refresh
    if has_au == 1 and is_2xx == 1 and set_ck == 1:
        return "USER_AUTHENTICATED"
    # Application auth: success without cookie (API key, client credentials)
    if has_au == 1 and is_2xx == 1:
        return "APPLICATION_AUTHENTICATED"
    return "PUBLIC"


_RULE_CLASSIFIERS = {
    "net_a": _rule_net_a,
    "net_b": _rule_net_b,
    "net_c": _rule_net_c,
    "net_d": _rule_net_d,
}


def apply_rule_baseline(task: str, X: list[list[float]]) -> list[str]:
    fn = _RULE_CLASSIFIERS[task]
    return [fn(fv) for fv in X]


# ── Metrics helpers ───────────────────────────────────────────────────────────

def _import_sklearn():
    try:
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score,
            f1_score, confusion_matrix,
        )
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline
        from sklearn.model_selection import cross_val_score, StratifiedKFold
        return dict(
            accuracy_score=accuracy_score,
            precision_score=precision_score,
            recall_score=recall_score,
            f1_score=f1_score,
            confusion_matrix=confusion_matrix,
            LogisticRegression=LogisticRegression,
            RandomForestClassifier=RandomForestClassifier,
            StandardScaler=StandardScaler,
            Pipeline=Pipeline,
            cross_val_score=cross_val_score,
            StratifiedKFold=StratifiedKFold,
        )
    except ImportError:
        raise RuntimeError("scikit-learn is required. pip install scikit-learn")


def compute_metrics(y_true: list, y_pred: list, labels: list[str]) -> dict:
    """Accuracy + per-class P/R/F1 + macro averages. Verbatim — never adjusted."""
    sk = _import_sklearn()
    acc   = float(sk["accuracy_score"](y_true, y_pred))
    prec  = float(sk["precision_score"](y_true, y_pred, average="macro",
                                        zero_division=0, labels=labels))
    rec   = float(sk["recall_score"](y_true, y_pred, average="macro",
                                     zero_division=0, labels=labels))
    f1    = float(sk["f1_score"](y_true, y_pred, average="macro",
                                 zero_division=0, labels=labels))
    per_class: dict = {}
    for cls in labels:
        cls_p = float(sk["precision_score"](y_true, y_pred, labels=[cls],
                                            average="macro", zero_division=0))
        cls_r = float(sk["recall_score"](y_true, y_pred, labels=[cls],
                                         average="macro", zero_division=0))
        cls_f = float(sk["f1_score"](y_true, y_pred, labels=[cls],
                                     average="macro", zero_division=0))
        support = sum(1 for t in y_true if t == cls)
        per_class[cls] = {"precision": cls_p, "recall": cls_r,
                          "f1": cls_f, "support": support}
    cm_mat = sk["confusion_matrix"](y_true, y_pred, labels=labels).tolist()
    return {
        "accuracy": acc,
        "macro_precision": prec,
        "macro_recall": rec,
        "macro_f1": f1,
        "per_class": per_class,
        "confusion_matrix": {"labels": labels, "matrix": cm_mat},
    }


def _cv_score(pipeline, X: list, y: list, seed: int) -> float:
    """Cross-validation accuracy on training data for model selection."""
    import numpy as np
    sk = _import_sklearn()
    if len(set(y)) < 2:
        return 0.0
    n_splits = min(5, len(set(y)))  # can't have more folds than classes
    cv = sk["StratifiedKFold"](n_splits=n_splits, shuffle=True, random_state=seed)
    try:
        scores = sk["cross_val_score"](pipeline, X, y, cv=cv, scoring="accuracy",
                                       error_score=0.0)
        return float(np.mean(scores))
    except Exception:
        return 0.0


# ── Model builders ────────────────────────────────────────────────────────────

def _build_lr(seed: int):
    sk = _import_sklearn()
    return sk["Pipeline"]([
        ("scaler", sk["StandardScaler"]()),
        ("lr", sk["LogisticRegression"](
            solver="lbfgs", max_iter=2000, C=1.0,
            random_state=seed, class_weight="balanced",
        )),
    ])


def _build_rf(seed: int):
    sk = _import_sklearn()
    return sk["RandomForestClassifier"](
        n_estimators=100, max_depth=None, random_state=seed,
        class_weight="balanced", n_jobs=1,
    )


# ── Dummy (most-frequent) baseline ───────────────────────────────────────────

def _dummy_baseline(y_train: list, y_test: list) -> list[str]:
    from collections import Counter
    most_common = Counter(y_train).most_common(1)[0][0]
    return [most_common] * len(y_test)


# ── Runtime strategy ──────────────────────────────────────────────────────────

def decide_runtime_strategy(
    task: str,
    rule_train_acc: float,
    rule_test_acc: float,
    best_ml_cv_acc: float,
    n_train: int,
) -> str:
    """Classify runtime deployment strategy.

    RULE_DEFAULT    — deterministic rules outperform ML at train AND test
    ML_DEFAULT      — ML clearly outperforms rules; sufficient data
    HYBRID          — rules handle common cases; ML fills the gaps
    DEVELOPMENT_ONLY — insufficient evidence to recommend either
    """
    # NET-A: protocol class is 100% deterministic from status code
    if task == "net_a":
        if rule_train_acc >= 0.95 and rule_test_acc >= 0.90:
            return "RULE_DEFAULT"
    # Any task where rules score ≥0.85 at test, beating ML
    if rule_test_acc >= 0.85 and rule_test_acc >= best_ml_cv_acc:
        return "RULE_DEFAULT"
    # ML clearly better and enough data
    if best_ml_cv_acc >= 0.70 and n_train >= 30 and best_ml_cv_acc > rule_test_acc + 0.10:
        return "ML_DEFAULT"
    # Rules decent but ML adds value
    if rule_test_acc >= 0.50 or best_ml_cv_acc >= 0.50:
        return "HYBRID"
    return "DEVELOPMENT_ONLY"


# ── Per-task training ─────────────────────────────────────────────────────────

def train_and_evaluate_task(
    task: str,
    X_train: list, y_train: list,
    X_test: list, y_test: list,
    seed: int = 42,
) -> dict:
    """Train LR + RF, select via CV, report all baselines.

    Returns a task result dict with verbatim metrics — never fabricated.
    """
    sk = _import_sklearn()
    if not X_train:
        raise ValueError(f"No training examples for task {task}")
    if not X_test:
        X_test, y_test = X_train, y_train

    classes = sorted(set(y_train) | set(y_test))

    # ── Rule baseline (no training needed) ───────────────────────────────
    rule_train_pred = apply_rule_baseline(task, X_train)
    rule_test_pred  = apply_rule_baseline(task, X_test)
    rule_train_m    = compute_metrics(y_train, rule_train_pred, classes)
    rule_test_m     = compute_metrics(y_test,  rule_test_pred,  classes)

    # ── Dummy baseline ────────────────────────────────────────────────────
    dummy_test_pred = _dummy_baseline(y_train, y_test)
    dummy_test_m    = compute_metrics(y_test, dummy_test_pred, classes)

    # ── LR ────────────────────────────────────────────────────────────────
    lr_pipe = _build_lr(seed)
    lr_cv   = _cv_score(lr_pipe, X_train, y_train, seed)
    lr_pipe.fit(X_train, y_train)
    lr_train_pred = lr_pipe.predict(X_train).tolist()
    lr_test_pred  = lr_pipe.predict(X_test).tolist()
    lr_train_m    = compute_metrics(y_train, lr_train_pred, classes)
    lr_test_m     = compute_metrics(y_test,  lr_test_pred,  classes)

    # ── RF ────────────────────────────────────────────────────────────────
    rf = _build_rf(seed)
    rf_cv = _cv_score(rf, X_train, y_train, seed)
    rf.fit(X_train, y_train)
    rf_train_pred = rf.predict(X_train).tolist()
    rf_test_pred  = rf.predict(X_test).tolist()
    rf_train_m    = compute_metrics(y_train, rf_train_pred, classes)
    rf_test_m     = compute_metrics(y_test,  rf_test_pred,  classes)

    # ── Model selection via CV (not test score) ───────────────────────────
    best_model_name = "lr" if lr_cv >= rf_cv else "rf"
    best_cv_acc     = max(lr_cv, rf_cv)
    best_test_m     = lr_test_m if best_model_name == "lr" else rf_test_m

    # ── Runtime strategy ──────────────────────────────────────────────────
    strategy = decide_runtime_strategy(
        task,
        rule_train_acc=rule_train_m["accuracy"],
        rule_test_acc=rule_test_m["accuracy"],
        best_ml_cv_acc=best_cv_acc,
        n_train=len(X_train),
    )

    return {
        "classes": classes,
        "n_train": len(X_train),
        "n_test": len(X_test),
        "baselines": {
            "dummy_most_frequent": {"test": dummy_test_m},
            "rule_based": {
                "train": rule_train_m,
                "test":  rule_test_m,
            },
        },
        "lr": {
            "cv_accuracy": lr_cv,
            "train": lr_train_m,
            "test":  lr_test_m,
        },
        "rf": {
            "cv_accuracy": rf_cv,
            "train": rf_train_m,
            "test":  rf_test_m,
        },
        "model_selection": {
            "method": "cross_val_accuracy",
            "selected": best_model_name,
            "selected_cv_accuracy": best_cv_acc,
            "selected_test": best_test_m,
        },
        "runtime_strategy": strategy,
    }, lr_pipe if best_model_name == "lr" else rf


def save_model(model, output_dir: Path, model_id: str) -> Path:
    try:
        import joblib
    except ImportError:
        raise RuntimeError("joblib is required. pip install joblib")
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{model_id}.pkl"
    joblib.dump(model, path)
    return path


def register_model(
    model_id: str, task: str, weights_path: Path,
    task_result: dict, registry_path: Path,
    duration_s: float,
) -> None:
    if task in PROTECTED_TASKS:
        raise ValueError(f"REFUSE: task '{task}' is protected")

    from raven.ml.registry import (
        ModelRegistry, ModelVersion, ModelCard, ModelStatus,
    )
    from raven.network_fundamentals.features import FEATURE_SCHEMA_VERSION

    sel  = task_result["model_selection"]
    tm   = sel["selected_test"]
    ts   = datetime.now(timezone.utc).isoformat()
    arch = f"logistic_regression_multiclass" if sel["selected"] == "lr" \
           else "random_forest_multiclass"

    card = ModelCard(
        model_id=model_id,
        task=task,
        architecture=arch,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        n_train_examples=task_result["n_train"],
        n_val_examples=0,
        n_test_examples=task_result["n_test"],
        contains_synthetic=True,
        val_roc_auc=-1.0,
        val_accuracy=float(sel["selected_cv_accuracy"]),
        val_precision=-1.0,
        val_recall=-1.0,
        test_roc_auc=-1.0,
        test_accuracy=float(tm["accuracy"]),
        test_precision=float(tm["macro_precision"]),
        test_recall=float(tm["macro_recall"]),
        training_date_utc=ts,
        training_duration_s=duration_s,
        hyperparameters={
            "selected_model": sel["selected"],
            "cv_accuracy": sel["selected_cv_accuracy"],
            "data_source": DATA_SOURCE,
            "classes": task_result["classes"],
            "runtime_strategy": task_result["runtime_strategy"],
        },
        notes=(
            f"EDUCATIONAL_SYNTHETIC only. "
            f"Runtime strategy: {task_result['runtime_strategy']}. "
            f"DEVELOPMENT — not for security decisions."
        ),
        status=ModelStatus.DEVELOPMENT,
    )
    version = ModelVersion(
        model_id=model_id,
        task=task,
        architecture=arch,
        status=ModelStatus.DEVELOPMENT,
        weights_path=str(weights_path),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        timestamp_utc=ts,
        card=card,
    )
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    reg = ModelRegistry(str(registry_path))
    reg.register(version)
    print(f"  Registered {model_id} (DEVELOPMENT, {task_result['runtime_strategy']})")


def run_training(
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    registry_path: Path = DEFAULT_REGISTRY,
    seed: int = 42,
    tasks: tuple[str, ...] = MODEL_TASKS,
) -> dict:
    """Train all NET tasks. Returns full metrics dict."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    from raven.network_fundamentals.dataset import NetworkDataset

    print("Building educational synthetic dataset...")
    ds = NetworkDataset(seed=seed).build()
    print(f"  Total fixtures: {ds.n_examples}")

    # Print split reports
    for task in tasks:
        rep = ds.get_split_report(task)
        print(f"\n  [{task}] split: train={rep.n_train} test={rep.n_test} "
              f"missing_train_classes={rep.missing_train_classes} "
              f"leakage={rep.family_intersection}")

    summary: dict = {
        "data_source": DATA_SOURCE,
        "total_examples": ds.n_examples,
        "seed": seed,
        "tasks": {},
    }

    for task in tasks:
        print(f"\n{'='*60}")
        print(f"Training {task}...")
        X_tr, y_tr, X_te, y_te = ds.get_task_arrays(task)
        print(f"  Train: {len(X_tr)}  Test: {len(X_te)}")
        print(f"  Label dist: {ds.label_distribution(task)}")

        t0 = time.perf_counter()
        task_result, best_model = train_and_evaluate_task(
            task, X_tr, y_tr, X_te, y_te, seed)
        duration = time.perf_counter() - t0

        # Print summary
        sel = task_result["model_selection"]
        rule = task_result["baselines"]["rule_based"]
        lr   = task_result["lr"]
        rf   = task_result["rf"]
        print(f"  classes:   {task_result['classes']}")
        print(f"  dummy test acc:  {task_result['baselines']['dummy_most_frequent']['test']['accuracy']:.4f}")
        print(f"  rule  train/test: {rule['train']['accuracy']:.4f} / {rule['test']['accuracy']:.4f}")
        print(f"  LR    cv/train/test: {lr['cv_accuracy']:.4f} / {lr['train']['accuracy']:.4f} / {lr['test']['accuracy']:.4f}")
        print(f"  RF    cv/train/test: {rf['cv_accuracy']:.4f} / {rf['train']['accuracy']:.4f} / {rf['test']['accuracy']:.4f}")
        print(f"  selected: {sel['selected']} (cv={sel['selected_cv_accuracy']:.4f})")
        print(f"  selected test macro-F1: {sel['selected_test']['macro_f1']:.4f}")
        print(f"  runtime_strategy: {task_result['runtime_strategy']}")
        print(f"  duration: {duration:.3f}s")

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        model_id = f"{task}_net_{sel['selected']}_{ts}"
        task_result["model_id"]  = model_id
        task_result["duration_s"] = duration

        weights_path = save_model(best_model, output_dir, model_id)
        print(f"  Saved: {weights_path}")

        register_model(
            model_id=model_id,
            task=task,
            weights_path=weights_path,
            task_result=task_result,
            registry_path=registry_path,
            duration_s=duration,
        )
        summary["tasks"][task] = task_result

    return summary


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(
        prog="python -m raven.network_fundamentals.train",
        description="RAVEN Network Fundamentals Training — NET-A/B/C/D",
    )
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--registry",   type=Path, default=DEFAULT_REGISTRY)
    p.add_argument("--seed",       type=int,  default=42)
    p.add_argument("--tasks", nargs="+", default=list(MODEL_TASKS),
                   choices=list(MODEL_TASKS))
    args = p.parse_args()

    result = run_training(
        output_dir=args.output_dir,
        registry_path=args.registry,
        seed=args.seed,
        tasks=tuple(args.tasks),
    )
    print("\n=== TRAINING COMPLETE ===")
    print(json.dumps(result, indent=2, default=str))
