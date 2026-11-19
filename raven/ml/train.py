"""RAVEN ML Training CLI (Phases 85-130, 177).

Entry point:  python -m raven.ml.train [OPTIONS]

INVARIANTS:
- Training is always explicit (never silent background retraining).
- Model predictions are advisory; never promote model to PRODUCTION automatically.
- Synthetic data used here is DEVELOPMENT_ONLY: metrics reflect that data only.
- All metrics reported are from the held-out dev/test split.
- Never fabricate metrics. Never round to make numbers look better.
- model.eval() + torch.no_grad() for inference; never for weight-update.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_OUTPUT_DIR  = Path("models")
DEFAULT_REGISTRY    = Path("models/registry.json")
FEATURE_DIM         = 22   # must match FeatureVector.to_list() length


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m raven.ml.train",
        description="RAVEN ML Training CLI — trains triage-assistance models.",
    )
    p.add_argument("--task",        choices=["task_a", "task_b", "both"], default="both")
    p.add_argument("--arch",        choices=["logistic_regression", "mlp"], default="mlp")
    p.add_argument("--n-positive",  type=int, default=300,
                   help="Synthetic positive examples (DEVELOPMENT_ONLY)")
    p.add_argument("--n-negative",  type=int, default=300,
                   help="Synthetic negative examples (DEVELOPMENT_ONLY)")
    p.add_argument("--epochs",      type=int, default=40)
    p.add_argument("--lr",          type=float, default=3e-4)
    p.add_argument("--hidden",      type=int, default=64)
    p.add_argument("--dropout",     type=float, default=0.3)
    p.add_argument("--patience",    type=int, default=8,
                   help="Early stopping patience (val loss)")
    p.add_argument("--batch-size",  type=int, default=32)
    p.add_argument("--output-dir",  type=Path, default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--registry",    type=Path, default=DEFAULT_REGISTRY)
    p.add_argument("--seed",        type=int, default=42)
    return p.parse_args(argv)


# ─────────────────────────────────────────────────────────────────────────────
# PyTorch MLP definition (module-level so it can be pickled/saved)
# ─────────────────────────────────────────────────────────────────────────────

try:
    import torch
    import torch.nn as nn

    class RavenMLP(nn.Module):
        """Small auditable MLP: BatchNorm → Linear(input→hidden) → ReLU → Dropout → Linear(hidden→1)."""
        def __init__(self, input_dim: int = 22, hidden_dim: int = 64, dropout: float = 0.3):
            super().__init__()
            self.input_dim  = input_dim
            self.hidden_dim = hidden_dim
            self.dropout_p  = dropout
            self.net = nn.Sequential(
                nn.BatchNorm1d(input_dim),
                nn.Linear(input_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim, 1),
            )

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            return self.net(x).squeeze(-1)

        def parameter_count(self) -> int:
            return sum(p.numel() for p in self.parameters())

    _TORCH_AVAILABLE = True

except ImportError:
    RavenMLP = None  # type: ignore
    _TORCH_AVAILABLE = False


def build_mlp(input_dim: int, hidden_dim: int, dropout: float):
    """Instantiate RavenMLP if torch is available."""
    if not _TORCH_AVAILABLE or RavenMLP is None:
        return None
    return RavenMLP(input_dim=input_dim, hidden_dim=hidden_dim, dropout=dropout)


# ─────────────────────────────────────────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────────────────────────────────────────

def compute_metrics(y_true: list, y_prob: list, threshold: float = 0.5) -> dict:
    """Compute accuracy, precision, recall, ROC-AUC from lists."""
    if not y_true:
        return {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "roc_auc": 0.0, "n": 0}

    tp = fp = tn = fn = 0
    for yt, yp in zip(y_true, y_prob):
        pred = 1 if yp >= threshold else 0
        if yt == 1 and pred == 1: tp += 1
        elif yt == 0 and pred == 1: fp += 1
        elif yt == 0 and pred == 0: tn += 1
        else: fn += 1

    acc  = (tp + tn) / len(y_true) if y_true else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    # Simple trapezoidal AUC
    pairs = sorted(zip(y_prob, y_true), reverse=True)
    pos   = sum(y_true)
    neg   = len(y_true) - pos
    if pos == 0 or neg == 0:
        auc = 0.5
    else:
        tp_a = fp_a = 0
        prev_tpr = prev_fpr = 0.0
        auc = 0.0
        for prob, label in pairs:
            if label == 1: tp_a += 1
            else:          fp_a += 1
            tpr = tp_a / pos
            fpr = fp_a / neg
            auc += (fpr - prev_fpr) * (tpr + prev_tpr) / 2
            prev_tpr, prev_fpr = tpr, fpr

    return {
        "accuracy":  round(acc,  4),
        "precision": round(prec, 4),
        "recall":    round(rec,  4),
        "roc_auc":   round(auc,  4),
        "n":         len(y_true),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Training loops
# ─────────────────────────────────────────────────────────────────────────────

def train_logistic_regression(X_train, y_train, X_val, y_val, X_test, y_test,
                                seed: int) -> dict:
    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
        import numpy as np
    except ImportError:
        return {"error": "scikit-learn not installed"}

    scaler = StandardScaler()
    Xtr = scaler.fit_transform(np.array(X_train, dtype=float))
    Xvl = scaler.transform(np.array(X_val,   dtype=float))
    Xte = scaler.transform(np.array(X_test,  dtype=float))

    model = LogisticRegression(max_iter=1000, random_state=seed, C=1.0)
    model.fit(Xtr, y_train)

    val_prob  = model.predict_proba(Xvl)[:, 1].tolist()
    test_prob = model.predict_proba(Xte)[:, 1].tolist()

    return {
        "model":      model,
        "scaler":     scaler,
        "val_metrics": compute_metrics(y_val, val_prob),
        "test_metrics": compute_metrics(y_test, test_prob),
    }


def train_mlp(X_train, y_train, X_val, y_val, X_test, y_test,
               epochs: int, lr: float, hidden: int, dropout: float,
               batch_size: int, patience: int, seed: int) -> dict:
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
        import numpy as np
    except ImportError:
        return {"error": "torch not installed"}

    torch.manual_seed(seed)
    device = torch.device("cpu")

    def to_tensors(X, y):
        Xt = torch.tensor(np.array(X, dtype=float), dtype=torch.float32).to(device)
        yt = torch.tensor(y, dtype=torch.float32).to(device)
        return Xt, yt

    Xtr, ytr = to_tensors(X_train, y_train)
    Xvl, yvl = to_tensors(X_val,   y_val)
    Xte, yte = to_tensors(X_test,  y_test)

    model = build_mlp(Xtr.shape[1], hidden, dropout).to(device)
    n_params = model.parameter_count()
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    criterion = nn.BCEWithLogitsLoss()

    # Capture weights before training to prove they change
    weights_before = {k: v.clone() for k, v in model.state_dict().items()}

    train_loader = DataLoader(TensorDataset(Xtr, ytr), batch_size=batch_size, shuffle=True)

    best_val_loss   = float("inf")
    best_state_dict = None
    best_epoch      = 0
    no_improve      = 0
    history         = []
    initial_loss    = None

    for epoch in range(epochs):
        # ── Training step ────────────────────────────────────────────────
        model.train()
        epoch_loss = 0.0
        for Xb, yb in train_loader:
            optimizer.zero_grad()
            logits = model(Xb)
            loss   = criterion(logits, yb)
            loss.backward()        # real backward pass — weights actually update
            optimizer.step()
            epoch_loss += loss.item() * len(yb)
        epoch_loss /= len(ytr)
        if initial_loss is None:
            initial_loss = epoch_loss

        # ── Validation ───────────────────────────────────────────────────
        model.eval()
        with torch.no_grad():
            val_logits = model(Xvl)
            val_loss   = criterion(val_logits, yvl).item()
            val_prob   = torch.sigmoid(val_logits).cpu().numpy().tolist()

        val_metrics = compute_metrics(y_val, val_prob)
        history.append({"epoch": epoch+1, "train_loss": round(epoch_loss, 4),
                         "val_loss": round(val_loss, 4),
                         "val_acc": val_metrics["accuracy"]})

        if val_loss < best_val_loss:
            best_val_loss   = val_loss
            best_state_dict = {k: v.clone() for k, v in model.state_dict().items()}
            best_epoch      = epoch + 1
            no_improve      = 0
        else:
            no_improve += 1
            if no_improve >= patience:
                print(f"    Early stopping at epoch {epoch+1} (val_loss={val_loss:.4f})")
                break

    if best_state_dict is not None:
        model.load_state_dict(best_state_dict)

    model.eval()
    with torch.no_grad():
        val_prob  = torch.sigmoid(model(Xvl)).cpu().numpy().tolist()
        test_prob = torch.sigmoid(model(Xte)).cpu().numpy().tolist()

    # Prove weights changed
    weights_after = model.state_dict()
    any_changed = any(
        not torch.equal(weights_before[k], weights_after[k])
        for k in weights_before
    )

    return {
        "model":          model,
        "val_metrics":    compute_metrics(y_val,  val_prob),
        "test_metrics":   compute_metrics(y_test, test_prob),
        "history":        history,
        "initial_loss":   initial_loss,
        "final_loss":     history[-1]["train_loss"] if history else None,
        "best_val_loss":  best_val_loss,
        "best_epoch":     best_epoch,
        "n_epochs_run":   len(history),
        "weights_changed": any_changed,
        "n_params":       n_params,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main training orchestration
# ─────────────────────────────────────────────────────────────────────────────

def run_training(task: str, arch: str, args: argparse.Namespace) -> Optional[dict]:
    from .dataset import DatasetBuilder, DatasetPolicy, DatasetSplit
    from .registry import ModelRegistry, ModelVersion, ModelCard, ModelStatus
    from .features import FEATURE_SCHEMA_VERSION

    print(f"\n{'='*60}")
    print(f"RAVEN ML Training — task={task}, arch={arch}")
    print(f"DEVELOPMENT_ONLY: synthetic data, not certified for production")
    print(f"{'='*60}")

    # ── Build synthetic dataset ────────────────────────────────────────────
    builder = DatasetBuilder(policy=DatasetPolicy.DEV_SYNTHETIC, seed=args.seed)
    print(f"  Generating {args.n_positive} positive + {args.n_negative} negative examples...")
    examples = builder.build_synthetic_dev_set(
        n_positive=args.n_positive,
        n_negative=args.n_negative,
    )

    split = builder.build_from_examples(examples, temporal=False, deduplicate=True)
    print(f"  Split: {split.n_train} train / {split.n_val} val / {split.n_test} test")
    label_counts = split.task_a_label_counts()
    print(f"  Label counts (task_a proxy): {label_counts}")

    # ── Prepare arrays ─────────────────────────────────────────────────────
    def label_for(e, t):
        return e.label_task_a if t == "task_a" else e.label_task_b

    X_train = [e.feature_vector.to_list() for e in split.train]
    y_train = [label_for(e, task)         for e in split.train]
    X_val   = [e.feature_vector.to_list() for e in split.val]
    y_val   = [label_for(e, task)         for e in split.val]
    X_test  = [e.feature_vector.to_list() for e in split.test]
    y_test  = [label_for(e, task)         for e in split.test]

    if any(y == -1 for y in y_train + y_val + y_test):
        print("  WARNING: unlabeled examples present; filtering out")
        X_train, y_train = zip(*[(x,y) for x,y in zip(X_train, y_train) if y != -1]) or ([],[])
        X_val,   y_val   = zip(*[(x,y) for x,y in zip(X_val,   y_val)   if y != -1]) or ([],[])
        X_test,  y_test  = zip(*[(x,y) for x,y in zip(X_test,  y_test)  if y != -1]) or ([],[])
        X_train, y_train = list(X_train), list(y_train)
        X_val,   y_val   = list(X_val),   list(y_val)
        X_test,  y_test  = list(X_test),  list(y_test)

    # ── Train ──────────────────────────────────────────────────────────────
    t0 = time.time()
    if arch == "logistic_regression":
        result = train_logistic_regression(
            X_train, y_train, X_val, y_val, X_test, y_test, seed=args.seed)
    else:
        result = train_mlp(
            X_train, y_train, X_val, y_val, X_test, y_test,
            epochs=args.epochs, lr=args.lr, hidden=args.hidden,
            dropout=args.dropout, batch_size=args.batch_size,
            patience=args.patience, seed=args.seed,
        )
    training_duration = time.time() - t0

    if "error" in result:
        print(f"  TRAINING FAILED: {result['error']}")
        return None

    val_m  = result["val_metrics"]
    test_m = result["test_metrics"]
    print(f"  Val  — acc={val_m['accuracy']:.4f}  prec={val_m['precision']:.4f}"
          f"  rec={val_m['recall']:.4f}  auc={val_m['roc_auc']:.4f}")
    print(f"  Test — acc={test_m['accuracy']:.4f}  prec={test_m['precision']:.4f}"
          f"  rec={test_m['recall']:.4f}  auc={test_m['roc_auc']:.4f}")
    print(f"  Duration: {training_duration:.1f}s")
    if arch != "logistic_regression":
        print(f"  Parameters:   {result.get('n_params', 'N/A')}")
        print(f"  Initial loss: {result.get('initial_loss', 'N/A')}")
        print(f"  Final loss:   {result.get('final_loss', 'N/A')}")
        print(f"  Best epoch:   {result.get('best_epoch', 'N/A')} / {result.get('n_epochs_run', 'N/A')}")
        print(f"  Weights changed: {result.get('weights_changed', 'N/A')}")

    # ── Save weights ───────────────────────────────────────────────────────
    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    model_id = f"{task}_{arch}_{ts}"

    if arch == "logistic_regression":
        try:
            import joblib
            weights_path = args.output_dir / f"{model_id}.pkl"
            joblib.dump({"model": result["model"], "scaler": result.get("scaler")},
                        weights_path)
        except ImportError:
            import pickle
            weights_path = args.output_dir / f"{model_id}.pkl"
            with open(weights_path, "wb") as f:
                import pickle
                pickle.dump({"model": result["model"], "scaler": result.get("scaler")}, f)
    else:
        import torch
        weights_path = args.output_dir / f"{model_id}.pt"
        # Save state_dict + architecture config (NOT the full module object).
        # This avoids arbitrary pickle loading and is safer on load.
        torch.save({
            "state_dict": result["model"].state_dict(),
            "input_dim":  result["model"].input_dim,
            "hidden_dim": result["model"].hidden_dim,
            "dropout":    result["model"].dropout_p,
            "arch":       "mlp_v1",
        }, weights_path)

    print(f"  Weights saved: {weights_path}")

    # ── Register ───────────────────────────────────────────────────────────
    registry = ModelRegistry(str(args.registry))

    card = ModelCard(
        model_id=model_id,
        task=task,
        architecture=arch,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        n_train_examples=len(X_train),
        n_val_examples=len(X_val),
        n_test_examples=len(X_test),
        contains_synthetic=True,
        val_roc_auc=val_m["roc_auc"],
        val_accuracy=val_m["accuracy"],
        val_precision=val_m["precision"],
        val_recall=val_m["recall"],
        test_roc_auc=test_m["roc_auc"],
        test_accuracy=test_m["accuracy"],
        test_precision=test_m["precision"],
        test_recall=test_m["recall"],
        training_date_utc=ts,
        training_duration_s=round(training_duration, 2),
        hyperparameters={
            "arch":           arch,
            "epochs":         args.epochs if arch != "logistic_regression" else None,
            "lr":             args.lr     if arch != "logistic_regression" else None,
            "hidden":         args.hidden if arch != "logistic_regression" else None,
            "dropout":        args.dropout if arch != "logistic_regression" else None,
            "seed":           args.seed,
            "n_params":       result.get("n_params"),
            "initial_loss":   result.get("initial_loss"),
            "final_loss":     result.get("final_loss"),
            "best_epoch":     result.get("best_epoch"),
            "n_epochs_run":   result.get("n_epochs_run"),
            "weights_changed": result.get("weights_changed"),
        },
        notes=(
            "DEVELOPMENT_ONLY: trained on synthetic data for pipeline validation. "
            "Metrics describe performance on this synthetic dev set only. "
            "Not suitable for production security decisions."
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
    registry.register(version)
    print(f"  Registered: {model_id} (status=DEVELOPMENT)")

    # ── Model card file ────────────────────────────────────────────────────
    card_path = args.output_dir / f"{model_id}_card.json"
    with open(card_path, "w", encoding="utf-8") as f:
        import dataclasses
        json.dump(dataclasses.asdict(card), f, indent=2, default=str)
    print(f"  Model card: {card_path}")

    return {
        "model_id":     model_id,
        "task":         task,
        "arch":         arch,
        "val_metrics":  val_m,
        "test_metrics": test_m,
        "weights_path": str(weights_path),
        "card_path":    str(card_path),
    }


def main(argv=None):
    args = parse_args(argv)

    print("\nRAVEN ML Training CLI")
    print("======================")
    print("NOTICE: This run uses DEVELOPMENT_ONLY synthetic data.")
    print("Metrics are reported but do NOT certify production readiness.")
    print("Models start in DEVELOPMENT status; promotion is manual.\n")

    tasks = ["task_a", "task_b"] if args.task == "both" else [args.task]
    results = []

    for task in tasks:
        result = run_training(task=task, arch=args.arch, args=args)
        if result:
            results.append(result)

    if not results:
        print("\nNo models trained successfully.")
        sys.exit(1)

    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    for r in results:
        print(f"  {r['task']} ({r['arch']}): {r['model_id']}")
        print(f"    val_auc={r['val_metrics']['roc_auc']:.4f}  "
              f"test_auc={r['test_metrics']['roc_auc']:.4f}")

    print("\nAll models registered with status=DEVELOPMENT.")
    print("To promote: use ModelRegistry.advance_to_candidate() then .promote_to_production()")
    print("These are ADVISORY triage-assistance models only.")


if __name__ == "__main__":
    main()
