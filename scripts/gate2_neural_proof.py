"""RAVEN Gate 2 — Standalone Neural Network Runtime Proof.

Proves the 15 required items:
  1. model instantiated                9. parameters changed
  2. tensors constructed               10. multiple epochs executed
  3. forward pass executed             11. validation executed
  4. logits produced                   12. best checkpoint selected
  5. loss calculated                   13. checkpoint saved
  6. loss.backward() executed          14. checkpoint reloaded into fresh model
  7. non-zero/valid gradients          15. CPU inference from reloaded checkpoint
  8. optimizer.step() executed

Also: parameter-change proof (count of changed tensors + total L1 delta).

GATE 3 (data truth): explicit REAL/SYNTHETIC counts.
GATE 6: LR vs MLP comparison on same splits.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from raven.ml.train import RavenMLP, build_mlp, compute_metrics, train_logistic_regression
from raven.ml.dataset import DatasetBuilder, DatasetPolicy, LabeledExample
from raven.ml.features import FeatureVector

SEED = 42
torch.manual_seed(SEED)
np.random.seed(SEED)

# ------------------------------------------------------------
# GATE 3 — Data Truth
# ------------------------------------------------------------
REAL_HUMAN_LABEL_COUNT = 0
SYNTHETIC_LABEL_COUNT  = 600   # 300 pos + 300 neg (set below)
print(f"\n{'='*60}")
print("GATE 3 — TRAINING DATA TRUTH")
print(f"REAL_HUMAN_LABEL_COUNT  = {REAL_HUMAN_LABEL_COUNT}")
print(f"SYNTHETIC_LABEL_COUNT   = {SYNTHETIC_LABEL_COUNT}")
print("Model status will be:   DEVELOPMENT_ONLY_SYNTHETIC")
print("NOT:                    CANDIDATE / PRODUCTION / REAL-DATA MODEL")
print(f"{'='*60}\n")

# ------------------------------------------------------------
# Build synthetic dev dataset (same for both tasks)
# ------------------------------------------------------------
builder = DatasetBuilder(policy=DatasetPolicy.DEV_SYNTHETIC)
N_POS, N_NEG = 300, 300
examples = builder.build_synthetic_dev_set(
    n_positive=N_POS, n_negative=N_NEG
)
split = builder.build_from_examples(examples)

SYNTHETIC_LABEL_COUNT = len(split.train) + len(split.val) + len(split.test)

print(f"Dataset type:       DEV_SYNTHETIC (NOT real-world data)")
print(f"Train rows:         {len(split.train)}")
print(f"Val rows:           {len(split.val)}")
print(f"Test rows:          {len(split.test)}")
groups_tr = set(e.group_key for e in split.train)
groups_te = set(e.group_key for e in split.test)
print(f"Groups (train):     {len(groups_tr)}")
print(f"Groups (test):      {len(groups_te)}")
tr_pos = sum(e.label_task_a for e in split.train)
print(f"Train class dist:   {tr_pos} pos / {len(split.train)-tr_pos} neg")
print()

def to_xy(examples, task="a"):
    X = [e.feature_vector.to_list() for e in examples]
    y = [e.label_task_a if task == "a" else e.label_task_b for e in examples]
    return X, y

for task_name, task_key in [("Task A — ResponseDifference", "a"),
                              ("Task B — AuthorizationSignificance", "b")]:
    Xtr, ytr = to_xy(split.train, task_key)
    Xvl, yvl = to_xy(split.val,   task_key)
    Xte, yte  = to_xy(split.test,  task_key)

    print(f"{'='*60}")
    print(f"GATE 4/5 — {task_name}")
    print(f"{'='*60}")

    # -- MLP Architecture proof --------------------------------
    device = torch.device("cpu")
    model = build_mlp(22, 64, 0.3).to(device)
    n_params = model.parameter_count()

    print(f"\n-- MLP Architecture ----------------------------------")
    print(f"Model class:        RavenMLP")
    print(f"Input features:     {model.input_dim}")
    print(f"Hidden dim:         {model.hidden_dim}")
    print(f"Activation:         ReLU")
    print(f"Normalization:      BatchNorm1d({model.input_dim})")
    print(f"Dropout:            {model.dropout_p}")
    print(f"Output dim:         1 (BCEWithLogitsLoss → sigmoid → probability)")
    print(f"Parameter count:    {n_params}")
    print(f"\n-- Layers --------------------------------------------")
    for i, layer in enumerate(model.net):
        print(f"  [{i}] {layer}")

    # -- Gate 2 items 1-9 -------------------------------------
    print(f"\n-- Gate 2 Runtime Proof ------------------------------")

    # 1. Model instantiated
    assert model is not None
    print("1. model instantiated:              PASS")

    # 2. Tensors constructed
    Xt  = torch.tensor(np.array(Xtr[:4], dtype=float), dtype=torch.float32)
    yt  = torch.tensor(ytr[:4], dtype=torch.float32)
    assert Xt.shape == (4, 22)
    print("2. tensors constructed:             PASS")

    # 3. Forward pass
    model.train()
    logits = model(Xt)
    assert logits.shape == (4,)
    print("3. forward pass executed:           PASS")

    # 4. Logits produced
    assert not torch.isnan(logits).any()
    print(f"4. logits produced:                 PASS  {logits.tolist()[:3]}")

    # 5. Loss calculated
    criterion = nn.BCEWithLogitsLoss()
    loss = criterion(logits, yt)
    assert loss.item() > 0
    print(f"5. loss calculated:                 PASS  loss={loss.item():.4f}")

    # 6. loss.backward()
    loss.backward()
    print("6. loss.backward() executed:        PASS")

    # 7. Non-zero gradients
    has_grad = any(p.grad is not None and p.grad.abs().max().item() > 0
                   for p in model.parameters())
    assert has_grad, "No non-zero gradients found"
    max_grad = max(p.grad.abs().max().item() for p in model.parameters()
                   if p.grad is not None)
    print(f"7. non-zero/valid gradients:        PASS  max_grad={max_grad:.6f}")

    # 8. optimizer.step()
    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-4, weight_decay=1e-4)
    optimizer.zero_grad()
    # re-do forward/backward for clean step
    logits2 = model(Xt)
    loss2   = criterion(logits2, yt)
    loss2.backward()
    weights_before_step = {k: v.clone() for k, v in model.state_dict().items()}
    optimizer.step()
    print("8. optimizer.step() executed:       PASS")

    # 9. Parameters changed
    changed = sum(
        1 for k, v in model.state_dict().items()
        if not torch.equal(weights_before_step[k], v)
    )
    assert changed > 0, "No parameter tensors changed after optimizer.step()"
    print(f"9. model parameters changed:        PASS  {changed}/{len(weights_before_step)} tensors changed")

    # -- Full training loop (items 10-15) ---------------------
    # Re-build fresh model for full run
    torch.manual_seed(SEED)
    model2     = build_mlp(22, 64, 0.3).to(device)
    optimizer2 = torch.optim.AdamW(model2.parameters(), lr=3e-4, weight_decay=1e-4)
    weights_t0 = {k: v.clone() for k, v in model2.state_dict().items()}

    Xtr_t = torch.tensor(np.array(Xtr, dtype=float), dtype=torch.float32)
    ytr_t = torch.tensor(ytr, dtype=torch.float32)
    Xvl_t = torch.tensor(np.array(Xvl, dtype=float), dtype=torch.float32)
    yvl_t = torch.tensor(yvl, dtype=torch.float32)
    Xte_t = torch.tensor(np.array(Xte, dtype=float),  dtype=torch.float32)

    loader = DataLoader(TensorDataset(Xtr_t, ytr_t), batch_size=32, shuffle=True)

    EPOCHS   = 40
    PATIENCE = 8
    best_val_loss   = float("inf")
    best_state_dict = None
    best_epoch      = 0
    no_improve      = 0
    history         = []
    initial_loss    = None

    t0 = time.time()
    for epoch in range(EPOCHS):
        model2.train()
        epoch_loss = 0.0
        for Xb, yb in loader:
            optimizer2.zero_grad()
            logits_b = model2(Xb)
            loss_b   = criterion(logits_b, yb)
            loss_b.backward()
            optimizer2.step()
            epoch_loss += loss_b.item() * len(yb)
        epoch_loss /= len(ytr_t)
        if initial_loss is None:
            initial_loss = epoch_loss

        model2.eval()
        with torch.no_grad():
            vl = criterion(model2(Xvl_t), yvl_t).item()
        history.append({"epoch": epoch+1, "train_loss": epoch_loss, "val_loss": vl})

        if vl < best_val_loss:
            best_val_loss   = vl
            best_state_dict = {k: v.clone() for k, v in model2.state_dict().items()}
            best_epoch      = epoch + 1
            no_improve      = 0
        else:
            no_improve += 1
            if no_improve >= PATIENCE:
                break

    elapsed = time.time() - t0
    print(f"\n-- Training loop -------------------------------------")
    print(f"10. multiple epochs executed:       PASS  {len(history)} epochs in {elapsed:.1f}s")
    print(f"11. validation executed:            PASS  best_val_loss={best_val_loss:.4f}")
    print(f"12. best checkpoint selected:       PASS  epoch={best_epoch}")

    # Load best checkpoint
    model2.load_state_dict(best_state_dict)

    # 13. Save checkpoint
    ckpt_dir = Path(f"models/task_{task_key}/v_gate2_{task_key}")
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    weights_path = ckpt_dir / "weights.pt"
    torch.save({
        "state_dict": model2.state_dict(),
        "input_dim":  model2.input_dim,
        "hidden_dim": model2.hidden_dim,
        "dropout":    model2.dropout_p,
        "arch":       "mlp_v1",
        "task":       task_key,
        "seed":       SEED,
    }, weights_path)
    sha256 = hashlib.sha256(weights_path.read_bytes()).hexdigest()
    print(f"13. checkpoint saved:               PASS  {weights_path}")
    print(f"    SHA-256:                        {sha256}")

    # 14. Reload into fresh model
    ckpt   = torch.load(weights_path, map_location="cpu", weights_only=True)
    model3 = RavenMLP(
        input_dim  = ckpt["input_dim"],
        hidden_dim = ckpt["hidden_dim"],
        dropout    = ckpt["dropout"],
    )
    model3.load_state_dict(ckpt["state_dict"])
    model3.eval()
    print("14. checkpoint reloaded (fresh instance): PASS")

    # 15. CPU inference
    with torch.no_grad():
        sample    = Xte_t[:1]
        logit_out = model3(sample)
        prob_out  = torch.sigmoid(logit_out).item()
    print(f"15. CPU inference from reloaded ckpt:   PASS  prob={prob_out:.4f}")

    # -- Parameter-change proof --------------------------------
    changed_count = sum(
        1 for k, v in model2.state_dict().items()
        if not torch.equal(weights_t0[k], v)
    )
    total_delta = sum(
        (model2.state_dict()[k] - weights_t0[k]).abs().sum().item()
        for k in weights_t0
    )
    print(f"\n-- Parameter-change proof ----------------------------")
    print(f"Tensors changed:        {changed_count}/{len(weights_t0)}")
    print(f"Total L1 delta:         {total_delta:.4f}")
    assert changed_count > 0

    # -- Metrics -----------------------------------------------
    model2.eval()
    with torch.no_grad():
        val_prob  = torch.sigmoid(model2(Xvl_t)).cpu().numpy().tolist()
        test_prob = torch.sigmoid(model2(Xte_t)).cpu().numpy().tolist()

    val_m  = compute_metrics(list(yvl), val_prob)
    test_m = compute_metrics(list(yte),  test_prob)

    print(f"\n-- MLP Metrics (SYNTHETIC ONLY — not real-world performance) -")
    print(f"Initial loss:           {initial_loss:.4f}")
    print(f"Best val loss:          {best_val_loss:.4f}")
    print(f"Epochs executed:        {len(history)}")
    print(f"Best epoch:             {best_epoch}")
    print(f"Val  Accuracy:          {val_m['accuracy']}")
    print(f"Val  Precision:         {val_m['precision']}")
    print(f"Val  Recall:            {val_m['recall']}")
    print(f"Val  ROC-AUC:           {val_m['roc_auc']}")
    print(f"Test Accuracy:          {test_m['accuracy']}")
    print(f"Test Precision:         {test_m['precision']}")
    print(f"Test Recall:            {test_m['recall']}")
    print(f"Test ROC-AUC:           {test_m['roc_auc']}")
    print(f"\n  *** SYNTHETIC AUC is NOT evidence of real-world generalization ***")

    # -- GATE 6 — LR vs MLP comparison ------------------------
    print(f"\n-- Gate 6: LR vs MLP comparison (same splits) --------")
    lr_result = train_logistic_regression(Xtr, ytr, Xvl, yvl, Xte, yte, seed=SEED)
    lr_val   = lr_result["val_metrics"]
    lr_test  = lr_result["test_metrics"]
    print(f"{'Model':<22} {'Val AUC':>8} {'Test AUC':>10} {'Val Acc':>9} {'Test Acc':>10}")
    print(f"{'-'*62}")
    print(f"{'LogisticRegression':<22} {lr_val['roc_auc']:>8.4f} {lr_test['roc_auc']:>10.4f} "
          f"{lr_val['accuracy']:>9.4f} {lr_test['accuracy']:>10.4f}")
    print(f"{'MLP (RavenMLP)':<22} {val_m['roc_auc']:>8.4f} {test_m['roc_auc']:>10.4f} "
          f"{val_m['accuracy']:>9.4f} {test_m['accuracy']:>10.4f}")
    if lr_test["roc_auc"] >= test_m["roc_auc"]:
        print(f"  => On synthetic data, LR performs >= MLP. This is expected and noted.")
    else:
        print(f"  => On synthetic data, MLP outperforms LR. Pipeline validation passes.")
    print(f"  Note: comparison is on SYNTHETIC dev data only; neither is production-qualified.")

    # -- Model card --------------------------------------------
    model_card = {
        "model_id":              f"mlp_task_{task_key}_gate2",
        "task":                  task_name,
        "model_status":          "DEVELOPMENT_ONLY_SYNTHETIC",
        "architecture":          "mlp_v1",
        "input_dim":             model2.input_dim,
        "hidden_dim":            model2.hidden_dim,
        "dropout":               model2.dropout_p,
        "parameter_count":       n_params,
        "feature_schema_version":"v1",
        "dataset_type":          "DEV_SYNTHETIC",
        "real_human_labels":     REAL_HUMAN_LABEL_COUNT,
        "synthetic_labels":      SYNTHETIC_LABEL_COUNT,
        "train_rows":            len(split.train),
        "val_rows":              len(split.val),
        "test_rows":             len(split.test),
        "seed":                  SEED,
        "optimizer":             "AdamW lr=3e-4 weight_decay=1e-4",
        "loss_fn":               "BCEWithLogitsLoss",
        "epochs_run":            len(history),
        "best_epoch":            best_epoch,
        "initial_loss":          round(initial_loss, 6),
        "best_val_loss":         round(best_val_loss, 6),
        "val_metrics":           val_m,
        "test_metrics":          test_m,
        "pytorch_version":       torch.__version__,
        "artifact_sha256":       sha256,
        "weights_changed":       changed_count > 0,
        "changed_tensors":       changed_count,
        "total_l1_delta":        round(total_delta, 6),
        "qualification":         "DEVELOPMENT_ONLY_SYNTHETIC — NOT production-qualified",
    }
    card_path = ckpt_dir / "model_card.json"
    card_path.write_text(json.dumps(model_card, indent=2))
    print(f"\n  Model card written: {card_path}")

    # Feature schema
    from raven.ml.features import FeatureVector, FEATURE_SCHEMA_VERSION
    schema = {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": len(FeatureVector.feature_names()),
        "features": FeatureVector.feature_names(),
    }
    schema_path = ckpt_dir / "feature_schema.json"
    schema_path.write_text(json.dumps(schema, indent=2))

    metrics_path = ckpt_dir / "metrics.json"
    metrics_path.write_text(json.dumps({
        "val": val_m, "test": test_m,
        "lr_val": lr_val, "lr_test": lr_test,
    }, indent=2))

    print(f"\nModel artifact:     {weights_path}")
    print(f"Model status:       DEVELOPMENT_ONLY_SYNTHETIC")
    print()


print("\n" + "="*60)
print("GATE 2 — ALL 15 ITEMS: PASS")
print("GATE 3 — DATA TRUTH: REAL_HUMAN_LABEL_COUNT=0  SYNTHETIC_ONLY")
print("GATE 6 — LR vs MLP COMPARISON: COMPLETE")
print("="*60)
