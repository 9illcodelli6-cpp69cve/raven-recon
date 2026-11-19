"""RAVEN-LM training engine — SAFE_DESKTOP, CPU-only, bounded, real backward pass.

This is the concrete training engine for the from-scratch decoder-only Transformer
defined in ``reconstruction/native_ai/ARCHITECTURE_DECISION.md`` §2/§3. It performs a
REAL optimization loop (fresh random init → forward → cross-entropy → ``loss.backward()``
→ AdamW ``step`` → weights change), with a warmup+cosine LR schedule, gradient
accumulation, gradient clipping, train/val-loss tracking, checkpoint SAVE + RESUME
(model + optimizer + scheduler + step + RNG state), optional early stopping, crash
recovery, and a reproducible checkpoint MANIFEST.

HONESTY + SAFETY invariants (binding — see §2/§8 of the decision doc):
  * **SAFE_DESKTOP budgets are NON-OPTIONAL.** Every run caps ``torch.set_num_threads``
    (default 4), batch size, sequence length (<= model context), optimizer steps,
    wall-clock seconds, tokens seen, and checkpoints at an interval — whichever bound
    fires first stops the run. CPU-only fp32; peak RAM stays well under the envelope.
  * **No fake "training complete" flag.** Completion is the real step/loss state: the
    result reports the number of optimizer steps actually taken and the real final
    train/val loss. A run that is cancelled / paused / budget-stopped says so truthfully.
  * **Injectable stop hooks** (mirrors ``ProcessExecutor``'s ``emergency_stop`` pattern):
    an ``emergency_stop`` predicate and a :class:`TrainingControl` (pause / resume /
    cancel) are consulted at every step boundary; the trainer never self-authorizes an
    unbounded run.
  * Building/running this does NOT flip ``raven.native_ai.NATIVE_GENERATIVE_MODEL``
    (stays ``None``) and nothing on the live path imports it. The produced checkpoint's
    maturity is ``EXPERIMENTAL_BOOTSTRAP`` — never PRODUCTION.

Kept under ``raven/native_ai/generative/`` (torch lives here) so the interfaces-only
guard over the top-level ``native_ai`` modules stays green.
"""
from __future__ import annotations

import hashlib
import math
import os
import random
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from .model import RavenLM, RavenLMConfig

ARCHITECTURE_VERSION = "raven-lm/1"
CHECKPOINT_SCHEMA = "raven-native-checkpoint/1"
MATURITY_BOOTSTRAP = "EXPERIMENTAL_BOOTSTRAP"


# ── resource budgets (SAFE_DESKTOP / BALANCED / DEDICATED_TRAINING) ───────────

@dataclass(frozen=True)
class ResourceBudget:
    """NON-OPTIONAL bounds for one training posture.

    Every field is a hard ceiling enforced by :class:`Trainer`. ``SAFE_DESKTOP`` is the
    default and the only posture the desktop bootstrap ever uses; ``BALANCED`` and
    ``DEDICATED_TRAINING`` are declared for the scaling path (Micro/Base) and are NOT
    used by the desktop CLI.
    """
    name: str = "SAFE_DESKTOP"
    max_threads: int = 4
    max_batch_size: int = 16
    max_seq_len: int = 256            # clamped to the model's context_length
    max_steps: int = 400
    max_wall_clock_s: float = 600.0
    max_tokens: Optional[int] = 3_000_000
    checkpoint_interval: int = 100    # 0 → only the final checkpoint
    grad_accum_steps: int = 1

    @classmethod
    def safe_desktop(cls) -> "ResourceBudget":
        return cls()

    @classmethod
    def balanced(cls) -> "ResourceBudget":
        return cls(name="BALANCED", max_threads=4, max_batch_size=32, max_seq_len=512,
                   max_steps=5_000, max_wall_clock_s=3_600.0, max_tokens=50_000_000,
                   checkpoint_interval=500, grad_accum_steps=2)

    @classmethod
    def dedicated_training(cls) -> "ResourceBudget":
        return cls(name="DEDICATED_TRAINING", max_threads=8, max_batch_size=64,
                   max_seq_len=1024, max_steps=200_000, max_wall_clock_s=86_400.0,
                   max_tokens=5_000_000_000, checkpoint_interval=2_000,
                   grad_accum_steps=4)

    def micro_test(self, **overrides) -> "ResourceBudget":
        """A tiny derivative for the pipeline tests — still SAFE_DESKTOP-bounded."""
        base = dict(name="SAFE_DESKTOP_MICRO", max_threads=self.max_threads,
                    max_batch_size=8, max_seq_len=64, max_steps=6, max_wall_clock_s=60.0,
                    max_tokens=200_000, checkpoint_interval=0, grad_accum_steps=1)
        base.update(overrides)
        return ResourceBudget(**base)


# ── optimizer / schedule config ───────────────────────────────────────────────

@dataclass(frozen=True)
class TrainConfig:
    seed: int = 1234
    lr: float = 3e-4
    weight_decay: float = 0.01
    beta1: float = 0.9
    beta2: float = 0.95
    eps: float = 1e-8
    warmup_steps: int = 10
    min_lr_ratio: float = 0.1          # cosine floor as a fraction of lr
    lr_total_steps: int = 0            # cosine horizon; 0 → use budget.max_steps
    grad_clip: float = 1.0
    val_interval: int = 20             # 0 → never validate mid-run
    early_stop_patience: int = 0       # 0 → disabled
    run_id: str = ""
    append_eos_between_samples: bool = True


# ── pause / resume / cancel control (injectable; mirrors emergency_stop) ──────

class TrainingControl:
    """Thread-safe pause / resume / cancel signalling consulted at step boundaries.

    A bounded trainer cannot block forever, so a *pause* takes effect by checkpointing
    and stopping with reason ``"paused"`` — the run is then resumable from that exact
    checkpoint. A *cancel* stops with reason ``"cancelled"``.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._paused = False
        self._cancelled = False

    def pause(self) -> None:
        with self._lock:
            self._paused = True

    def resume(self) -> None:
        with self._lock:
            self._paused = False

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True

    def should_pause(self) -> bool:
        with self._lock:
            return self._paused

    def should_cancel(self) -> bool:
        with self._lock:
            return self._cancelled


# ── result ────────────────────────────────────────────────────────────────────

@dataclass
class TrainingResult:
    run_id: str
    steps_completed: int
    initial_loss: float
    final_loss: float
    best_val_loss: float
    stop_reason: str                    # max_steps|wall_clock|max_tokens|early_stop|cancelled|emergency_stop|paused
    tokens_seen: int
    wall_clock_s: float
    loss_history: List[float] = field(default_factory=list)
    val_loss_history: List[Tuple[int, float]] = field(default_factory=list)
    checkpoint_path: Optional[str] = None
    checkpoint_hash: Optional[str] = None
    manifest: Dict = field(default_factory=dict)
    parameter_count: int = 0

    @property
    def loss_decreased(self) -> bool:
        return self.final_loss < self.initial_loss


# ── packing: text → fixed-length (x, y) next-token blocks ─────────────────────

def pack_token_blocks(token_streams: List[List[int]], seq_len: int,
                      eos_id: Optional[int], append_eos: bool) -> List[List[int]]:
    """Concatenate per-sample token streams (optionally EOS-joined) and chunk into
    blocks of length ``seq_len + 1`` (the +1 gives the shifted target).

    Returns a list of int lists each of length ``seq_len + 1``. A trailing remainder
    shorter than a full block is dropped (standard LM packing). Deterministic.
    """
    flat: List[int] = []
    for stream in token_streams:
        flat.extend(stream)
        if append_eos and eos_id is not None:
            flat.append(eos_id)
    block = seq_len + 1
    blocks = [flat[i:i + block] for i in range(0, len(flat) - block + 1, seq_len)]
    return [b for b in blocks if len(b) == block]


# ── the trainer ────────────────────────────────────────────────────────────────

class Trainer:
    """SAFE_DESKTOP CPU-only training engine for RAVEN-LM (real backward pass)."""

    def __init__(
        self,
        model_config: RavenLMConfig,
        tokenizer,
        train_texts: List[str],
        val_texts: Optional[List[str]] = None,
        *,
        train_config: Optional[TrainConfig] = None,
        budget: Optional[ResourceBudget] = None,
        emergency_stop: Optional[Callable[[], bool]] = None,
        control: Optional[TrainingControl] = None,
        dataset_manifest_hash: str = "",
    ) -> None:
        self.budget = budget or ResourceBudget.safe_desktop()
        self.cfg = train_config or TrainConfig()
        self._emergency_stop = emergency_stop or (lambda: False)
        self._control = control or TrainingControl()
        self._dataset_manifest_hash = dataset_manifest_hash

        # --- NON-OPTIONAL resource bounds ---------------------------------------
        torch.set_num_threads(max(1, int(self.budget.max_threads)))
        self._seq_len = min(int(self.budget.max_seq_len), int(model_config.context_length))
        self._batch_size = max(1, int(self.budget.max_batch_size))
        self._grad_accum = max(1, int(self.budget.grad_accum_steps))

        if tokenizer.vocab_size > model_config.vocab_size:
            raise ValueError(
                f"tokenizer vocab {tokenizer.vocab_size} exceeds model vocab "
                f"{model_config.vocab_size}; ids would be out of range"
            )
        self.model_config = model_config
        self.tokenizer = tokenizer

        # Deterministic, reproducible init.
        self._seed_everything(self.cfg.seed)
        self.model = RavenLM(model_config, seed=self.cfg.seed)
        self._pad_id = self._maybe_special("<pad>")
        self._eos_id = self._maybe_special("<eos>")

        self.optimizer = torch.optim.AdamW(
            self.model.parameters(), lr=self.cfg.lr,
            betas=(self.cfg.beta1, self.cfg.beta2), eps=self.cfg.eps,
            weight_decay=self.cfg.weight_decay,
        )
        self.scheduler = torch.optim.lr_scheduler.LambdaLR(
            self.optimizer, lr_lambda=self._lr_lambda)

        # Pack blocks (deterministic).
        self._train_blocks = self._pack(train_texts)
        self._val_blocks = self._pack(val_texts or [])
        if not self._train_blocks:
            raise ValueError(
                "no training blocks produced — corpus too short for seq_len "
                f"{self._seq_len}; shorten seq_len or add data"
            )

        self.step = 0
        self.tokens_seen = 0
        self.loss_history: List[float] = []
        self.val_loss_history: List[Tuple[int, float]] = []
        self.best_val_loss = float("inf")

    # -- helpers ---------------------------------------------------------------

    def _maybe_special(self, tok: str) -> Optional[int]:
        fn = getattr(self.tokenizer, "special_token_id", None)
        if fn is None:
            return None
        try:
            return int(fn(tok))
        except Exception:
            return None

    def _seed_everything(self, seed: int) -> None:
        random.seed(seed)
        np.random.seed(seed % (2 ** 32))
        torch.manual_seed(seed)

    def _lr_lambda(self, step: int) -> float:
        warmup = max(0, int(self.cfg.warmup_steps))
        total = max(1, int(self.cfg.lr_total_steps or self.budget.max_steps))
        if warmup and step < warmup:
            return float(step + 1) / float(warmup)
        progress = float(step - warmup) / float(max(1, total - warmup))
        progress = min(1.0, max(0.0, progress))
        cosine = 0.5 * (1.0 + math.cos(math.pi * progress))
        floor = float(self.cfg.min_lr_ratio)
        return floor + (1.0 - floor) * cosine

    def _pack(self, texts: List[str]) -> List[List[int]]:
        streams = [self.tokenizer.encode(t) for t in texts]
        return pack_token_blocks(streams, self._seq_len, self._eos_id,
                                 self.cfg.append_eos_between_samples)

    def _batch(self, blocks: List[List[int]], indices: List[int]) -> Tuple[torch.Tensor, torch.Tensor]:
        rows = [blocks[i] for i in indices]
        t = torch.tensor(rows, dtype=torch.long)
        return t[:, :-1].contiguous(), t[:, 1:].contiguous()

    def _loss_on(self, x: torch.Tensor, y: torch.Tensor) -> torch.Tensor:
        logits = self.model(x)
        ignore = self._pad_id if self._pad_id is not None else -100
        return F.cross_entropy(
            logits.view(-1, logits.size(-1)), y.reshape(-1), ignore_index=ignore)

    # -- validation ------------------------------------------------------------

    @torch.no_grad()
    def validate(self) -> Optional[float]:
        if not self._val_blocks:
            return None
        was_training = self.model.training
        self.model.eval()
        total, n = 0.0, 0
        bs = self._batch_size
        for i in range(0, len(self._val_blocks), bs):
            idx = list(range(i, min(i + bs, len(self._val_blocks))))
            x, y = self._batch(self._val_blocks, idx)
            total += float(self._loss_on(x, y)) * len(idx)
            n += len(idx)
        if was_training:
            self.model.train()
        return total / max(1, n)

    # -- the training loop -----------------------------------------------------

    def train(self, *, checkpoint_dir: Optional[str] = None,
              checkpoint_prefix: str = "raven_nano") -> TrainingResult:
        t0 = time.monotonic()
        n_blocks = len(self._train_blocks)
        self.model.train()

        initial_loss: Optional[float] = None
        stop_reason = "max_steps"
        last_ckpt_path: Optional[str] = None
        last_ckpt_hash: Optional[str] = None

        while self.step < self.budget.max_steps:
            # --- bound + control checks at the step boundary --------------------
            if self._emergency_stop():
                stop_reason = "emergency_stop"
                break
            if self._control.should_cancel():
                stop_reason = "cancelled"
                break
            if self._control.should_pause():
                stop_reason = "paused"
                break
            if (time.monotonic() - t0) >= self.budget.max_wall_clock_s:
                stop_reason = "wall_clock"
                break
            if self.budget.max_tokens is not None and self.tokens_seen >= self.budget.max_tokens:
                stop_reason = "max_tokens"
                break

            # --- one optimizer step with gradient accumulation ------------------
            self.optimizer.zero_grad(set_to_none=True)
            step_loss = 0.0
            for mb in range(self._grad_accum):
                # Batch selection is a PURE function of (seed, step, microbatch): this
                # makes training (and therefore resume) fully deterministic without
                # relying on stateful RNG — a checkpoint resumed at step N continues
                # byte-identically to an uninterrupted run.
                if n_blocks > self._batch_size:
                    mb_rng = random.Random(
                        self.cfg.seed * 1_000_003 + self.step * 131 + mb)
                    idx = [mb_rng.randrange(n_blocks) for _ in range(self._batch_size)]
                else:
                    idx = list(range(n_blocks))
                x, y = self._batch(self._train_blocks, idx)
                loss = self._loss_on(x, y) / self._grad_accum
                loss.backward()
                # Each microbatch loss is already divided by grad_accum, so summing the
                # detached scalars yields the mean microbatch loss for this step.
                step_loss += float(loss.detach())
                self.tokens_seen += int(x.numel())
            if self.cfg.grad_clip and self.cfg.grad_clip > 0:
                nn.utils.clip_grad_norm_(self.model.parameters(), self.cfg.grad_clip)
            self.optimizer.step()
            self.scheduler.step()

            self.loss_history.append(step_loss)
            if initial_loss is None:
                initial_loss = step_loss
            self.step += 1

            # --- validation + early stop ---------------------------------------
            if self.cfg.val_interval and self._val_blocks and \
                    self.step % self.cfg.val_interval == 0:
                vloss = self.validate()
                if vloss is not None:
                    self.val_loss_history.append((self.step, vloss))
                    if vloss < self.best_val_loss:
                        self.best_val_loss = vloss
                    elif self.cfg.early_stop_patience > 0:
                        recent = [v for _, v in self.val_loss_history[-(self.cfg.early_stop_patience + 1):]]
                        if len(recent) > self.cfg.early_stop_patience and \
                                min(recent[1:]) >= recent[0]:
                            stop_reason = "early_stop"
                            break

            # --- periodic checkpoint -------------------------------------------
            if checkpoint_dir and self.budget.checkpoint_interval and \
                    self.step % self.budget.checkpoint_interval == 0:
                last_ckpt_path = os.path.join(
                    checkpoint_dir, f"{checkpoint_prefix}_step{self.step}.pt")
                last_ckpt_hash = self.save_checkpoint(last_ckpt_path)

        wall = time.monotonic() - t0
        final_loss = self.loss_history[-1] if self.loss_history else float("nan")
        if initial_loss is None:
            initial_loss = final_loss

        # Always write a final checkpoint when a dir is given.
        if checkpoint_dir:
            last_ckpt_path = os.path.join(
                checkpoint_dir, f"{checkpoint_prefix}_final.pt")
            last_ckpt_hash = self.save_checkpoint(last_ckpt_path)

        manifest = self._build_manifest(final_loss=final_loss, stop_reason=stop_reason,
                                        wall=wall)
        return TrainingResult(
            run_id=self.cfg.run_id or self._default_run_id(),
            steps_completed=self.step,
            initial_loss=float(initial_loss),
            final_loss=float(final_loss),
            best_val_loss=float(self.best_val_loss),
            stop_reason=stop_reason,
            tokens_seen=self.tokens_seen,
            wall_clock_s=wall,
            loss_history=list(self.loss_history),
            val_loss_history=list(self.val_loss_history),
            checkpoint_path=last_ckpt_path,
            checkpoint_hash=last_ckpt_hash,
            manifest=manifest,
            parameter_count=self.model.parameter_count,
        )

    # -- manifest / checkpoint -------------------------------------------------

    def _default_run_id(self) -> str:
        h = hashlib.sha256(
            f"{self.cfg.seed}:{self._dataset_manifest_hash}:{self.budget.max_steps}"
            .encode("utf-8")).hexdigest()[:12]
        return f"nativerun-{h}"

    def _build_manifest(self, *, final_loss: float, stop_reason: str,
                        wall: float) -> Dict:
        return {
            "schema": CHECKPOINT_SCHEMA,
            "architecture_version": ARCHITECTURE_VERSION,
            "maturity": MATURITY_BOOTSTRAP,
            "run_id": self.cfg.run_id or self._default_run_id(),
            "config": asdict(self.model_config),
            "train_config": asdict(self.cfg),
            "budget": asdict(self.budget),
            "tokenizer_version": getattr(self.tokenizer, "version", ""),
            "tokenizer_hash": getattr(self.tokenizer, "hash", ""),
            "dataset_manifest_hash": self._dataset_manifest_hash,
            "seed": self.cfg.seed,
            "parameter_count": self.model.parameter_count,
            "context_window": self.model_config.context_length,
            "seq_len": self._seq_len,
            "steps": self.step,
            "tokens_seen": self.tokens_seen,
            "final_loss": float(final_loss),
            "best_val_loss": (None if self.best_val_loss == float("inf")
                              else float(self.best_val_loss)),
            "stop_reason": stop_reason,
            "wall_clock_s": wall,
            # Wall-clock timestamp is filled by the orchestrator at run time — kept a
            # placeholder here so the manifest stays a deterministic function of inputs.
            "timestamp": "",
        }

    def state_dict_blob(self) -> Dict:
        """The full resumable state (model + optimizer + scheduler + step + RNG)."""
        return {
            "schema": CHECKPOINT_SCHEMA,
            "model_state": self.model.state_dict(),
            "optimizer_state": self.optimizer.state_dict(),
            "scheduler_state": self.scheduler.state_dict(),
            "step": self.step,
            "tokens_seen": self.tokens_seen,
            "best_val_loss": self.best_val_loss,
            "loss_history": list(self.loss_history),
            "val_loss_history": list(self.val_loss_history),
            "config": asdict(self.model_config),
            "train_config": asdict(self.cfg),
            "budget": asdict(self.budget),
            "dataset_manifest_hash": self._dataset_manifest_hash,
            "rng_state": {
                "torch": torch.get_rng_state(),
                "python": random.getstate(),
                "numpy": np.random.get_state(),
            },
            "manifest": self._build_manifest(
                final_loss=(self.loss_history[-1] if self.loss_history else float("nan")),
                stop_reason="checkpoint", wall=0.0),
        }

    def save_checkpoint(self, path: str) -> str:
        """Atomically write a resumable checkpoint and return its content hash."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        blob = self.state_dict_blob()
        tmp = path + ".tmp"
        torch.save(blob, tmp)
        os.replace(tmp, path)
        return checkpoint_file_hash(path)

    def resume_from(self, path: str) -> None:
        """Restore model + optimizer + scheduler + step + RNG from a checkpoint.

        Enables crash recovery: a run interrupted by budget/pause/cancel/crash resumes
        from the exact saved state and continues deterministically.
        """
        blob = load_checkpoint(path)
        self.model.load_state_dict(blob["model_state"])
        self.optimizer.load_state_dict(blob["optimizer_state"])
        self.scheduler.load_state_dict(blob["scheduler_state"])
        self.step = int(blob.get("step", 0))
        self.tokens_seen = int(blob.get("tokens_seen", 0))
        self.best_val_loss = float(blob.get("best_val_loss", float("inf")))
        self.loss_history = list(blob.get("loss_history", []))
        self.val_loss_history = [tuple(v) for v in blob.get("val_loss_history", [])]
        rng = blob.get("rng_state")
        if rng:
            try:
                torch.set_rng_state(rng["torch"])
                random.setstate(rng["python"])
                np.random.set_state(rng["numpy"])
            except Exception:
                pass


# ── module-level checkpoint utilities (used by infer / registry / eval) ───────

def load_checkpoint(path: str) -> Dict:
    """Load a RAVEN native checkpoint blob. ``weights_only=False`` is required because
    the blob carries RNG/optimizer state saved by this trainer (a RAVEN-owned file)."""
    return torch.load(path, map_location="cpu", weights_only=False)


def checkpoint_file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rebuild_model_from_checkpoint(path: str) -> Tuple[RavenLM, Dict]:
    """Rebuild a ``RavenLM`` with weights loaded from ``path``. Returns (model, blob)."""
    blob = load_checkpoint(path)
    cfg = RavenLMConfig(**blob["config"])
    model = RavenLM(cfg)
    model.load_state_dict(blob["model_state"])
    model.eval()
    return model, blob
