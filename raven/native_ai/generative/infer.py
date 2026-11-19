"""Native inference for RAVEN-LM — local-only, bounded, advisory.

Loads a RAVEN-owned checkpoint written by :mod:`raven.native_ai.generative.trainer` and
runs autoregressive decoding entirely in-process on the CPU. Supports temperature,
top-k, top-p (nucleus), a hard max-token budget, EOS stopping, a wall-clock timeout, a
cancel / emergency-stop predicate, a deterministic (seeded / greedy) mode, and optional
token streaming.

ZERO network. ZERO Ollama. ZERO HTTP. This module imports only ``torch`` + the RAVEN
model/tokenizer/trainer — there is no ``urllib``, ``socket``, ``http``, ``requests`` or
``ollama`` import anywhere on this path, and it contacts no host. It loads RAVEN
checkpoints only (``torch`` tensors produced by the RAVEN trainer); it never downloads
or fetches weights. The pipeline test proves this with a socket guard.

Every result is ADVISORY (``InferenceResult.is_advisory=True``,
``sets_verification_status=False``): generated text never authorizes an action and never
becomes a verification verdict. Loading / running this does NOT flip
``raven.native_ai.NATIVE_GENERATIVE_MODEL`` (stays ``None``).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Iterator, List, Optional

import torch
import torch.nn.functional as F

from raven.native_ai.inference import Inference, InferenceRequest, InferenceResult

from .model import RavenLM, RavenLMConfig
from .trainer import rebuild_model_from_checkpoint, load_checkpoint

DEFAULT_MAX_THREADS = 4


@dataclass(frozen=True)
class GenerationConfig:
    """Bounded generation parameters. ``max_new_tokens`` is hard-clamped to context."""
    max_new_tokens: int = 64
    temperature: float = 0.8
    top_k: Optional[int] = 40
    top_p: Optional[float] = 0.95
    seed: Optional[int] = None
    deterministic: bool = False        # True → greedy (temperature ignored)
    timeout_s: float = 30.0
    stop_on_eos: bool = True
    max_threads: int = DEFAULT_MAX_THREADS


class NativeInferenceEngine(Inference):
    """Local autoregressive decoder over a RAVEN-LM checkpoint (advisory only)."""

    def __init__(self, model: RavenLM, tokenizer, *,
                 maturity: str = "EXPERIMENTAL_BOOTSTRAP",
                 emergency_stop: Optional[Callable[[], bool]] = None,
                 max_threads: int = DEFAULT_MAX_THREADS) -> None:
        torch.set_num_threads(max(1, int(max_threads)))
        self.model = model
        self.model.eval()
        self.tokenizer = tokenizer
        self.maturity = maturity
        self._emergency_stop = emergency_stop or (lambda: False)
        self._eos_id = self._maybe_special("<eos>")

    # -- construction ----------------------------------------------------------

    @classmethod
    def from_checkpoint(cls, checkpoint_path: str, *, tokenizer=None,
                        tokenizer_path: Optional[str] = None,
                        emergency_stop: Optional[Callable[[], bool]] = None,
                        max_threads: int = DEFAULT_MAX_THREADS) -> "NativeInferenceEngine":
        """Load a RAVEN checkpoint and its tokenizer. RAVEN checkpoints only — this
        never fetches or downloads anything."""
        torch.set_num_threads(max(1, int(max_threads)))
        model, blob = rebuild_model_from_checkpoint(checkpoint_path)
        tok = tokenizer
        if tok is None:
            path = tokenizer_path or _sidecar_tokenizer_path(checkpoint_path)
            if path is None:
                raise ValueError(
                    "no tokenizer supplied and no sidecar tokenizer found next to the "
                    "checkpoint; pass tokenizer= or tokenizer_path=")
            from raven.native_ai.bpe_tokenizer import ByteLevelBPETokenizer
            tok = ByteLevelBPETokenizer.load(path)
        maturity = str(blob.get("manifest", {}).get("maturity", "EXPERIMENTAL_BOOTSTRAP"))
        return cls(model, tok, maturity=maturity, emergency_stop=emergency_stop,
                   max_threads=max_threads)

    def _maybe_special(self, tok: str) -> Optional[int]:
        fn = getattr(self.tokenizer, "special_token_id", None)
        if fn is None:
            return None
        try:
            return int(fn(tok))
        except Exception:
            return None

    # -- core token sampling ---------------------------------------------------

    def _next_token(self, logits: torch.Tensor, cfg: GenerationConfig,
                    gen: Optional[torch.Generator]) -> torch.Tensor:
        if cfg.deterministic or cfg.temperature <= 0.0:
            return torch.argmax(logits, dim=-1, keepdim=True)
        logits = logits / cfg.temperature
        if cfg.top_k is not None and cfg.top_k > 0:
            k = min(int(cfg.top_k), logits.shape[-1])
            kth = torch.topk(logits, k, dim=-1).values[:, -1, None]
            logits = logits.masked_fill(logits < kth, float("-inf"))
        if cfg.top_p is not None and 0.0 < cfg.top_p < 1.0:
            sorted_logits, sorted_idx = torch.sort(logits, descending=True, dim=-1)
            probs = F.softmax(sorted_logits, dim=-1)
            cum = torch.cumsum(probs, dim=-1)
            remove = cum > cfg.top_p
            remove[:, 1:] = remove[:, :-1].clone()
            remove[:, 0] = False
            sorted_logits = sorted_logits.masked_fill(remove, float("-inf"))
            logits = torch.full_like(logits, float("-inf")).scatter(
                -1, sorted_idx, sorted_logits)
        probs = F.softmax(logits, dim=-1)
        return torch.multinomial(probs, num_samples=1, generator=gen)

    # -- generation ------------------------------------------------------------

    @torch.no_grad()
    def generate_tokens(self, prompt_ids: List[int],
                        cfg: Optional[GenerationConfig] = None) -> List[int]:
        """Return ONLY the newly generated token ids (bounded, local, advisory)."""
        cfg = cfg or GenerationConfig()
        ctx_len = self.model.cfg.context_length
        budget = max(0, min(int(cfg.max_new_tokens), ctx_len))
        gen = None
        if cfg.seed is not None and not cfg.deterministic:
            gen = torch.Generator().manual_seed(int(cfg.seed))

        ids = torch.tensor([list(prompt_ids)], dtype=torch.long)
        produced: List[int] = []
        t0 = time.monotonic()
        for _ in range(budget):
            if self._emergency_stop():
                break
            if (time.monotonic() - t0) >= cfg.timeout_s:
                break
            window = ids[:, -ctx_len:]
            logits = self.model(window)[:, -1, :]
            nxt = self._next_token(logits, cfg, gen)
            tok = int(nxt.item())
            produced.append(tok)
            ids = torch.cat([ids, nxt], dim=1)
            if cfg.stop_on_eos and self._eos_id is not None and tok == self._eos_id:
                break
        return produced

    def generate(self, prompt: str, cfg: Optional[GenerationConfig] = None) -> InferenceResult:
        """Generate from a text prompt → advisory :class:`InferenceResult`."""
        cfg = cfg or GenerationConfig()
        prompt_ids = self.tokenizer.encode(prompt)
        new_ids = self.generate_tokens(prompt_ids, cfg)
        text = self.tokenizer.decode(new_ids)
        return InferenceResult(text=text, tokens=new_ids)   # is_advisory enforced by dataclass default

    def stream(self, prompt: str, cfg: Optional[GenerationConfig] = None) -> Iterator[str]:
        """Yield decoded text incrementally as tokens are produced (local only)."""
        cfg = cfg or GenerationConfig()
        ctx_len = self.model.cfg.context_length
        budget = max(0, min(int(cfg.max_new_tokens), ctx_len))
        gen = None
        if cfg.seed is not None and not cfg.deterministic:
            gen = torch.Generator().manual_seed(int(cfg.seed))
        ids = torch.tensor([self.tokenizer.encode(prompt)], dtype=torch.long)
        emitted: List[int] = []
        t0 = time.monotonic()
        with torch.no_grad():
            for _ in range(budget):
                if self._emergency_stop() or (time.monotonic() - t0) >= cfg.timeout_s:
                    return
                logits = self.model(ids[:, -ctx_len:])[:, -1, :]
                nxt = self._next_token(logits, cfg, gen)
                tok = int(nxt.item())
                emitted.append(tok)
                ids = torch.cat([ids, nxt], dim=1)
                prev = self.tokenizer.decode(emitted[:-1])
                full = self.tokenizer.decode(emitted)
                if full.startswith(prev):
                    piece = full[len(prev):]
                    if piece:
                        yield piece
                if cfg.stop_on_eos and self._eos_id is not None and tok == self._eos_id:
                    return

    # -- Inference contract (advisory) -----------------------------------------

    def predict(self, request: InferenceRequest) -> InferenceResult:
        cfg = GenerationConfig(
            max_new_tokens=request.max_tokens or 64,
            temperature=float(request.metadata.get("temperature", 0.8)),
            top_k=request.metadata.get("top_k", 40),
            top_p=request.metadata.get("top_p", 0.95),
            seed=request.metadata.get("seed"),
            deterministic=bool(request.metadata.get("deterministic", False)),
            timeout_s=float(request.metadata.get("timeout_s", 30.0)),
        )
        return self.generate(request.prompt, cfg)

    def is_ready(self) -> bool:
        """A loaded engine can generate, but 'ready' for PRODUCTION routing requires an
        eval-gated promotion (handled by the registry). A bootstrap engine is loadable
        and runnable but is NOT production-ready."""
        return self.maturity == "PRODUCTION"


def _sidecar_tokenizer_path(checkpoint_path: str) -> Optional[str]:
    import os
    base = os.path.splitext(checkpoint_path)[0]
    for cand in (base + ".tokenizer.json", base + "_tokenizer.json",
                 os.path.join(os.path.dirname(checkpoint_path), "tokenizer.json")):
        if os.path.isfile(cand):
            return cand
    return None
