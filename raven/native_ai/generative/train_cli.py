"""Bounded SAFE_DESKTOP bootstrap CLI for RAVEN-LM.

    python -m raven.native_ai.generative.train_cli [--steps N] [--wall-clock S] ...

Runs a REAL but strictly bounded training run from random RAVEN initialization on the
RAVEN-owned curriculum corpus, then writes a checkpoint + a reproducible manifest + the
tokenizer sidecar under ``models/native/`` and registers a sec 16 EXPERIMENTAL_BOOTSTRAP
entry. CPU-only, threads capped, every budget a hard ceiling. Defaults are tiny; the
orchestrator passes the real Nano caps.

This NEVER promotes to PRODUCTION, NEVER flips ``raven.native_ai.NATIVE_GENERATIVE_MODEL``
(stays ``None``), and touches no network / Ollama / engagement data.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Allow ``python scripts/..`` style invocation to find the package.
_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

import raven.native_ai as native_ai  # noqa: E402
from raven.native_ai.bpe_tokenizer import ByteLevelBPETokenizer  # noqa: E402
from raven.native_ai.curriculum_impl import build_curriculum_dataset  # noqa: E402
from raven.native_ai.generative.model import RavenLMConfig  # noqa: E402
from raven.native_ai.generative.trainer import (  # noqa: E402
    ResourceBudget, TrainConfig, Trainer,
)
from raven.native_ai.generative.registry_ext import (  # noqa: E402
    NativeModelRegistry, entry_from_manifest,
)

DEFAULT_OUT_DIR = str(_REPO / "models" / "native")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raven-native-train",
        description="Bounded SAFE_DESKTOP bootstrap trainer for RAVEN-LM (CPU-only).")
    p.add_argument("--steps", type=int, default=20, help="max optimizer steps (hard cap)")
    p.add_argument("--wall-clock", type=float, default=120.0, help="max wall-clock seconds")
    p.add_argument("--max-tokens", type=int, default=2_000_000, help="max tokens seen")
    p.add_argument("--batch-size", type=int, default=8)
    p.add_argument("--seq-len", type=int, default=128, help="<= context_length")
    p.add_argument("--grad-accum", type=int, default=1)
    p.add_argument("--checkpoint-interval", type=int, default=0,
                   help="0 = only the final checkpoint")
    p.add_argument("--threads", type=int, default=4, help="torch thread cap (SAFE_DESKTOP)")
    # architecture (defaults = RAVEN-Nano)
    p.add_argument("--vocab", type=int, default=4096)
    p.add_argument("--d-model", type=int, default=256)
    p.add_argument("--n-layers", type=int, default=4)
    p.add_argument("--n-heads", type=int, default=8)
    p.add_argument("--d-ff", type=int, default=704)
    p.add_argument("--context", type=int, default=256)
    # optimization
    p.add_argument("--lr", type=float, default=3e-4)
    p.add_argument("--warmup", type=int, default=5)
    p.add_argument("--val-interval", type=int, default=10)
    p.add_argument("--seed", type=int, default=1234)
    # io
    p.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    p.add_argument("--prefix", default="raven_nano")
    p.add_argument("--resume", default="", help="checkpoint path to resume from")
    return p


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    print("=" * 64)
    print("RAVEN-LM bootstrap trainer - SAFE_DESKTOP, CPU-only, BOUNDED")
    print("HONEST: random-init from-scratch training; maturity=EXPERIMENTAL_BOOTSTRAP;")
    print("        NOT production; NATIVE_GENERATIVE_MODEL stays None; no network/Ollama.")
    print("=" * 64)

    # 1) dataset + manifest
    dataset = build_curriculum_dataset()
    manifest = dataset.manifest()
    print(f"[data]   samples={manifest['n_samples']} "
          f"content_hash={manifest['content_hash'][:16]}...")
    splits = dataset.split(seed=args.seed)
    print(f"[data]   train={splits.n_train} val={splits.n_val} holdout={splits.n_holdout} "
          f"leak_free={splits.is_leak_free()}")

    # 2) tokenizer (trained on the full corpus; sidecar saved next to the checkpoint)
    tok = ByteLevelBPETokenizer().train(dataset.texts(), vocab_size=args.vocab)
    print(f"[token]  vocab={tok.vocab_size} version={tok.version} hash={tok.hash[:16]}...")

    # 3) model config (defaults = RAVEN-Nano) - model vocab >= tokenizer vocab
    model_vocab = max(args.vocab, tok.vocab_size)
    cfg = RavenLMConfig(vocab_size=model_vocab, d_model=args.d_model,
                        n_layers=args.n_layers, n_heads=args.n_heads, d_ff=args.d_ff,
                        context_length=args.context)

    budget = ResourceBudget(
        name="SAFE_DESKTOP", max_threads=args.threads, max_batch_size=args.batch_size,
        max_seq_len=args.seq_len, max_steps=args.steps, max_wall_clock_s=args.wall_clock,
        max_tokens=args.max_tokens, checkpoint_interval=args.checkpoint_interval,
        grad_accum_steps=args.grad_accum)
    tcfg = TrainConfig(seed=args.seed, lr=args.lr, warmup_steps=args.warmup,
                       val_interval=args.val_interval)

    trainer = Trainer(cfg, tok, [s.text for s in splits.train],
                      [s.text for s in splits.val], train_config=tcfg, budget=budget,
                      dataset_manifest_hash=manifest["content_hash"])
    print(f"[model]  params={trainer.model.parameter_count:,} "
          f"d_model={cfg.d_model} layers={cfg.n_layers} ctx={cfg.context_length}")

    if args.resume and os.path.isfile(args.resume):
        trainer.resume_from(args.resume)
        print(f"[resume] continued from {args.resume} at step {trainer.step}")

    # 4) train (bounded)
    result = trainer.train(checkpoint_dir=args.out_dir, checkpoint_prefix=args.prefix)
    print(f"[train]  steps={result.steps_completed} stop={result.stop_reason} "
          f"tokens={result.tokens_seen} wall={result.wall_clock_s:.1f}s")
    curve = result.loss_history
    if curve:
        head = ", ".join(f"{x:.3f}" for x in curve[:5])
        tail = ", ".join(f"{x:.3f}" for x in curve[-5:])
        print(f"[loss]   initial={result.initial_loss:.4f} final={result.final_loss:.4f} "
              f"decreased={result.loss_decreased}")
        print(f"[loss]   first=[{head}] last=[{tail}]")

    # 5) tokenizer sidecar + registry entry
    tok_path = os.path.splitext(result.checkpoint_path)[0] + ".tokenizer.json"
    tok.save(tok_path)
    print(f"[ckpt]   {result.checkpoint_path}")
    print(f"[ckpt]   sha256={result.checkpoint_hash[:16]}...  tokenizer={tok_path}")

    reg_path = os.path.join(args.out_dir, "native_registry.json")
    registry = NativeModelRegistry(reg_path)
    entry = entry_from_manifest(result.manifest, checkpoint_path=result.checkpoint_path,
                                checkpoint_hash=result.checkpoint_hash)
    try:
        registry.register(entry)
    except ValueError:
        pass  # already registered (same run_id) - fine for a re-run
    print(f"[reg]    {entry.model_id}  maturity={entry.maturity.value}  -> {reg_path}")

    print(f"[honest] NATIVE_GENERATIVE_MODEL = {native_ai.NATIVE_GENERATIVE_MODEL!r} "
          "(unchanged)")
    print("DONE - bootstrap checkpoint written. Promotion to PRODUCTION requires an "
          "explicit researcher action after an eval pass.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
