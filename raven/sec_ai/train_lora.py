"""LoRA fine-tuning of the RAVEN-Sec base model on CPU (resumable, honest manifest).

    python -m raven.sec_ai.dataset --subset 3000                     # build data (fits --max-len)
    python -m raven.sec_ai.train_lora --data <ai>/dataset/train_3k.jsonl   # train (resumable)
    python -m raven.sec_ai.train_lora --bench 3                      # measure tokens/s only

* Loss only on assistant tokens (system/user/observation tokens are masked).
* Checkpoints (adapter + optimizer + position) every --save-every optimizer steps into
  <ai>/train-run/; re-running the same command resumes.
* At the end the adapter is merged into the base weights and saved to
  <ai>/raven-sec-0.5b/ with MODEL_CARD.md + manifest.json (base model, data, steps,
  loss curve, wall time). No auto-promotion: the app switches to it only because it is a
  fine-tune of the same base, and the evaluation numbers are recorded beside it.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import time
from pathlib import Path

from . import paths


def _encode(tok, messages, max_len):
    """input_ids + labels with every non-assistant token masked to -100."""
    ids, labels = [], []
    prev = []
    for i, m in enumerate(messages):
        if m["role"] != "assistant":
            continue
        prefix = tok.apply_chat_template(messages[:i], add_generation_prompt=True, tokenize=False)
        full = tok.apply_chat_template(messages[:i + 1], tokenize=False)
        p_ids = tok(prefix, add_special_tokens=False)["input_ids"]
        f_ids = tok(full, add_special_tokens=False)["input_ids"]
        # tokens before this assistant turn that we have not emitted yet → masked
        ids.extend(p_ids[len(prev):])
        labels.extend([-100] * (len(p_ids) - len(prev)))
        ids.extend(f_ids[len(p_ids):])
        labels.extend(f_ids[len(p_ids):])
        prev = f_ids
    return ids[:max_len], labels[:max_len]


def load_examples(path: Path, limit=None, seed=7):
    rows = [json.loads(line) for line in open(path, encoding="utf-8")]
    if limit:
        rows = rows[:limit]
    random.Random(seed).shuffle(rows)
    return rows


def _sha256(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _checkpoint_dir(run_dir: Path):
    """The last COMPLETE checkpoint (adapter + optimizer + state written together), or None.
    ``checkpoint.old`` covers a crash between the two renames of _save_checkpoint."""
    for name in ("checkpoint", "checkpoint.old"):
        d = run_dir / name
        if (d / "state.json").is_file() and (d / "adapter" / "adapter_config.json").is_file():
            return d
    return None


def _save_checkpoint(run_dir: Path, model, opt, state: dict, torch) -> None:
    """Atomic: write everything to checkpoint.tmp, then swap it in. A kill at any point
    leaves one complete, mutually consistent checkpoint (weights, optimizer, position)."""
    import shutil
    tmp, cur, old = run_dir / "checkpoint.tmp", run_dir / "checkpoint", run_dir / "checkpoint.old"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    model.save_pretrained(tmp / "adapter")
    torch.save(opt.state_dict(), tmp / "optim.pt")
    (tmp / "state.json").write_text(json.dumps(state))
    if old.exists():
        shutil.rmtree(old)
    if cur.exists():
        cur.rename(old)
    tmp.rename(cur)
    if old.exists():
        shutil.rmtree(old)


def main(argv=None):
    ap = argparse.ArgumentParser(description="RAVEN-Sec LoRA fine-tuning (CPU)")
    ap.add_argument("--max-examples", type=int, default=3000)
    ap.add_argument("--data", default=None, help="training JSONL (default <ai>/dataset/train.jsonl)")
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--threads", type=int, default=max(1, (os.cpu_count() or 4) - 2))
    ap.add_argument("--save-every", type=int, default=25)
    ap.add_argument("--bench", type=int, default=0, help="only time N micro-steps and exit")
    args = ap.parse_args(argv)

    import torch
    from peft import LoraConfig, PeftModel, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer

    torch.set_num_threads(args.threads)
    torch.manual_seed(7)
    base_dir = paths.base_model_dir()
    run_dir = paths.ai_dir() / "train-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    data_path = Path(args.data) if args.data else paths.dataset_dir() / "train.jsonl"
    data = load_examples(data_path, args.max_examples)
    # What a checkpoint is only valid for: resuming with another data file / window /
    # schedule silently skipped and repeated examples and jumped the LR schedule.
    run_config = {"data": str(data_path.resolve()), "data_sha256": _sha256(data_path),
                  "max_examples": args.max_examples, "max_len": args.max_len,
                  "epochs": args.epochs, "lr": args.lr, "rank": args.rank,
                  "grad_accum": args.grad_accum}

    tok = AutoTokenizer.from_pretrained(base_dir)
    model = AutoModelForCausalLM.from_pretrained(base_dir, dtype=torch.float32)
    model.config.use_cache = False
    # Memory: recompute activations in backward instead of keeping them (the laptop
    # this runs on shares ~15 GB with Burp, a VM and a browser).
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})  # noqa
    lora = LoraConfig(r=args.rank, lora_alpha=2 * args.rank, lora_dropout=0.05, bias="none",
                      task_type="CAUSAL_LM",
                      target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                      "gate_proj", "up_proj", "down_proj"])
    ckpt = _checkpoint_dir(run_dir)
    if ckpt is not None and not args.bench:
        state = json.loads((ckpt / "state.json").read_text())
        if state.get("config") != run_config:
            print("checkpoint in", ckpt, "was made with a different configuration:\n  saved:  ",
                  state.get("config"), "\n  now:    ", run_config,
                  "\nRe-run with the same arguments, or move", run_dir, "away to start over.",
                  file=sys.stderr, flush=True)
            return 2
        model = PeftModel.from_pretrained(model, ckpt / "adapter", is_trainable=True)
        print(f"resuming at example {state['pos']} (step {state['step']})", flush=True)
    else:
        model = get_peft_model(model, lora)
        state = {"pos": 0, "step": 0, "losses": [], "seconds": 0.0, "tokens": 0, "config": run_config}
    model.train()
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    print(f"trainable LoRA params {trainable/1e6:.2f}M of {total/1e6:.0f}M", flush=True)

    params = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(params, lr=args.lr, weight_decay=0.0)
    if ckpt is not None and (ckpt / "optim.pt").is_file() and state["step"] and not args.bench:
        opt.load_state_dict(torch.load(ckpt / "optim.pt"))
    n_total = int(len(data) * args.epochs)
    total_steps = max(1, math.ceil(n_total / args.grad_accum))
    warm = max(1, int(0.05 * total_steps))

    def lr_at(step):
        if step < warm:
            return args.lr * (step + 1) / warm
        prog = (step - warm) / max(1, total_steps - warm)
        return args.lr * (0.1 + 0.9 * 0.5 * (1 + math.cos(math.pi * prog)))

    core = model.get_base_model()  # the causal LM with LoRA layers injected

    def answer_loss(x, y):
        """Cross-entropy on assistant tokens only, projecting ONLY those positions to the
        151,936-word vocabulary (full-sequence logits alone cost >1 GB per example)."""
        h = core.model(input_ids=x).last_hidden_state[:, :-1, :]
        tgt = y[:, 1:]
        mask = tgt != -100
        logits = core.lm_head(h[mask])
        return torch.nn.functional.cross_entropy(logits.float(), tgt[mask])

    t0, acc_loss, acc_n = time.time(), 0.0, 0
    pos = state["pos"]
    micro = 0
    while pos < n_total:
        ex = data[pos % len(data)]
        ids, labels = _encode(tok, ex["messages"], args.max_len)
        pos += 1
        if not any(l != -100 for l in labels):
            continue
        x = torch.tensor([ids])
        y = torch.tensor([labels])
        loss_t = answer_loss(x, y)
        (loss_t / args.grad_accum).backward()
        acc_loss += float(loss_t.detach())
        acc_n += 1
        state["tokens"] += len(ids)
        micro += 1
        if args.bench and micro >= args.bench:
            dt = time.time() - t0
            print(f"BENCH {micro} examples, {state['tokens']} tokens in {dt:.1f}s → "
                  f"{state['tokens']/dt:.0f} tokens/s, {dt/micro:.1f}s/example", flush=True)
            return 0
        if acc_n % args.grad_accum == 0 or pos >= n_total:
            for g in opt.param_groups:
                g["lr"] = lr_at(state["step"])
            torch.nn.utils.clip_grad_norm_(params, 1.0)
            opt.step()
            opt.zero_grad(set_to_none=True)
            state["step"] += 1
            loss = acc_loss / acc_n
            state["losses"].append(round(loss, 4))
            acc_loss, acc_n = 0.0, 0
            elapsed = state["seconds"] + (time.time() - t0)
            eta = elapsed / max(1, pos - 0) * (n_total - pos) if pos else 0
            print(f"step {state['step']}/{total_steps} ex {pos}/{n_total} loss {loss:.4f} "
                  f"lr {lr_at(state['step']):.2e} elapsed {elapsed/60:.1f}m eta {eta/60:.0f}m", flush=True)
            if state["step"] % args.save_every == 0 or pos >= n_total:
                state["pos"] = pos
                state["seconds"] = elapsed
                t0 = time.time()
                _save_checkpoint(run_dir, model, opt, state, torch)
    # ── merge + save ───────────────────────────────────────────────────────────
    print("merging adapter into base weights…", flush=True)
    merged = model.merge_and_unload()
    out_dir = paths.tuned_model_dir()
    tmp = out_dir.with_name(out_dir.name + ".tmp")
    merged.to(torch.bfloat16).save_pretrained(tmp, safe_serialization=True)
    tok.save_pretrained(tmp)
    # Stats of the data ACTUALLY trained on (not the full train.jsonl's stats.json).
    from .dataset import dataset_stats
    stats = dataset_stats(data)
    stats["file"] = data_path.name
    manifest = {
        "model": "RAVEN-Sec 0.5B", "base_model": paths.BASE_MODEL_ID, "method": "LoRA (merged)",
        "lora_rank": args.rank, "trainable_params": trainable, "total_params": total,
        "examples_trained": n_total, "optimizer_steps": state["step"], "max_len": args.max_len,
        "tokens_seen": state["tokens"], "train_minutes": round(state["seconds"] / 60, 1),
        "final_loss": state["losses"][-1] if state["losses"] else None,
        "loss_curve": state["losses"], "dataset": stats,
        "sources": "MITRE CWE/CAPEC/ATT&CK (MITRE terms), OWASP WSTG + Cheat Sheets "
                   "(CC BY-SA 4.0), PayloadsAllTheThings (MIT)",
        "maturity": "FINE_TUNED_EXPERIMENTAL",
    }
    (tmp / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (tmp / "MODEL_CARD.md").write_text(
        "# RAVEN-Sec 0.5B\n\nLoRA fine-tune of Qwen2.5-Coder-0.5B-Instruct (Apache-2.0) for "
        "authorized penetration testing and security coding.\n\nTraining data: "
        f"{manifest['sources']}.\n\nAdvisory only — verify every finding by hand. Not trained "
        "from scratch.\n")
    if out_dir.exists():
        import shutil
        shutil.rmtree(out_dir)
    tmp.rename(out_dir)
    print(f"saved {out_dir}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
