"""RAVEN-LM — decoder-only Transformer, trained from random RAVEN initialization.

Concrete implementation of the architecture decided in
``reconstruction/native_ai/ARCHITECTURE_DECISION.md`` §2/§3:

  * pre-norm **RMSNorm** (scale-only, no bias)
  * **RoPE** rotary positional encoding applied to Q/K per head (parameter-free)
  * **SwiGLU** feed-forward (gate / up / down, no bias)
  * **tied** input/output embeddings
  * **no biases** anywhere
  * plain causal scaled-dot-product attention (no flash — CPU-only)
  * **GPT-NeoX-style** init; residual projections scaled by ``0.02/sqrt(2*n_layers)``
  * fp32, dropout 0.0

The config is **tier-invariant**: RAVEN-Nano / Micro / Base differ only in the
``RavenLMConfig`` values, never in the module code. Nano is the first from-scratch
checkpoint target (≈4.26M params).

This is a real torch model object. It is NOT wired into any live path and building it
does not flip ``raven.native_ai.NATIVE_GENERATIVE_MODEL`` (which stays ``None``). No
training happens in this module — only the forward pass, parameter accounting and a
bounded autoregressive ``generate`` for the inference interface. Training is a later
phase (SAFE_DESKTOP trainer).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

import torch
import torch.nn as nn
import torch.nn.functional as F


# ── config ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RavenLMConfig:
    """Frozen architecture config. Tiers are config-only (see §6 of the decision doc)."""
    vocab_size: int = 4096
    d_model: int = 256
    n_layers: int = 4
    n_heads: int = 8
    d_ff: int = 704
    context_length: int = 256
    norm_eps: float = 1e-5
    rope_theta: float = 10000.0
    tie_embeddings: bool = True
    dropout: float = 0.0
    bias: bool = False
    init_std: float = 0.02

    def __post_init__(self) -> None:
        if self.d_model % self.n_heads != 0:
            raise ValueError("d_model must be divisible by n_heads")
        if (self.d_model // self.n_heads) % 2 != 0:
            raise ValueError("head_dim must be even for RoPE")

    @property
    def head_dim(self) -> int:
        return self.d_model // self.n_heads

    # --- tier presets (RAVEN-Nano / Micro / Base) -----------------------------
    @classmethod
    def nano(cls) -> "RavenLMConfig":
        return cls(vocab_size=4096, d_model=256, n_layers=4, n_heads=8,
                   d_ff=704, context_length=256)

    @classmethod
    def micro(cls) -> "RavenLMConfig":
        return cls(vocab_size=8192, d_model=512, n_layers=8, n_heads=8,
                   d_ff=1408, context_length=512)

    @classmethod
    def base(cls) -> "RavenLMConfig":
        return cls(vocab_size=16384, d_model=768, n_layers=12, n_heads=12,
                   d_ff=2048, context_length=1024)

    @staticmethod
    def expected_param_count(vocab_size: int, d_model: int, n_layers: int,
                             d_ff: int) -> int:
        """Closed-form trainable-param count for the tied-embedding design."""
        embed = vocab_size * d_model
        per_block = 4 * d_model * d_model + 3 * d_model * d_ff + 2 * d_model
        return embed + n_layers * per_block + d_model


# ── components ──────────────────────────────────────────────────────────────

class RMSNorm(nn.Module):
    def __init__(self, dim: int, eps: float = 1e-5) -> None:
        super().__init__()
        self.eps = eps
        self.weight = nn.Parameter(torch.ones(dim))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        norm = x * torch.rsqrt(x.pow(2).mean(dim=-1, keepdim=True) + self.eps)
        return norm * self.weight


def _rotate_half(x: torch.Tensor) -> torch.Tensor:
    half = x.shape[-1] // 2
    x1, x2 = x[..., :half], x[..., half:]
    return torch.cat((-x2, x1), dim=-1)


def _apply_rope(q: torch.Tensor, k: torch.Tensor,
                cos: torch.Tensor, sin: torch.Tensor) -> tuple:
    # q,k: (B, n_heads, T, head_dim); cos/sin: (T, head_dim)
    cos = cos.unsqueeze(0).unsqueeze(0)
    sin = sin.unsqueeze(0).unsqueeze(0)
    q_rot = q * cos + _rotate_half(q) * sin
    k_rot = k * cos + _rotate_half(k) * sin
    return q_rot, k_rot


class CausalSelfAttention(nn.Module):
    def __init__(self, cfg: RavenLMConfig) -> None:
        super().__init__()
        self.n_heads = cfg.n_heads
        self.head_dim = cfg.head_dim
        self.q_proj = nn.Linear(cfg.d_model, cfg.d_model, bias=cfg.bias)
        self.k_proj = nn.Linear(cfg.d_model, cfg.d_model, bias=cfg.bias)
        self.v_proj = nn.Linear(cfg.d_model, cfg.d_model, bias=cfg.bias)
        self.o_proj = nn.Linear(cfg.d_model, cfg.d_model, bias=cfg.bias)
        self.dropout = cfg.dropout

    def forward(self, x: torch.Tensor, cos: torch.Tensor, sin: torch.Tensor) -> torch.Tensor:
        B, T, _ = x.shape
        q = self.q_proj(x).view(B, T, self.n_heads, self.head_dim).transpose(1, 2)
        k = self.k_proj(x).view(B, T, self.n_heads, self.head_dim).transpose(1, 2)
        v = self.v_proj(x).view(B, T, self.n_heads, self.head_dim).transpose(1, 2)
        q, k = _apply_rope(q, k, cos[:T], sin[:T])
        # plain causal scaled-dot-product attention (math path; no flash on CPU)
        attn = F.scaled_dot_product_attention(
            q, k, v, is_causal=True,
            dropout_p=self.dropout if self.training else 0.0,
        )
        attn = attn.transpose(1, 2).contiguous().view(B, T, self.n_heads * self.head_dim)
        return self.o_proj(attn)


class SwiGLU(nn.Module):
    def __init__(self, cfg: RavenLMConfig) -> None:
        super().__init__()
        self.gate_proj = nn.Linear(cfg.d_model, cfg.d_ff, bias=cfg.bias)
        self.up_proj = nn.Linear(cfg.d_model, cfg.d_ff, bias=cfg.bias)
        self.down_proj = nn.Linear(cfg.d_ff, cfg.d_model, bias=cfg.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.down_proj(F.silu(self.gate_proj(x)) * self.up_proj(x))


class Block(nn.Module):
    def __init__(self, cfg: RavenLMConfig) -> None:
        super().__init__()
        self.attn_norm = RMSNorm(cfg.d_model, cfg.norm_eps)
        self.attn = CausalSelfAttention(cfg)
        self.ffn_norm = RMSNorm(cfg.d_model, cfg.norm_eps)
        self.ffn = SwiGLU(cfg)

    def forward(self, x: torch.Tensor, cos: torch.Tensor, sin: torch.Tensor) -> torch.Tensor:
        x = x + self.attn(self.attn_norm(x), cos, sin)
        x = x + self.ffn(self.ffn_norm(x))
        return x


# ── model ─────────────────────────────────────────────────────────────────

class RavenLM(nn.Module):
    """Decoder-only Transformer. Deterministic given ``seed``."""

    def __init__(self, cfg: RavenLMConfig, seed: Optional[int] = None) -> None:
        super().__init__()
        self.cfg = cfg
        if seed is not None:
            torch.manual_seed(seed)

        self.tok_emb = nn.Embedding(cfg.vocab_size, cfg.d_model)
        self.blocks = nn.ModuleList(Block(cfg) for _ in range(cfg.n_layers))
        self.final_norm = RMSNorm(cfg.d_model, cfg.norm_eps)
        # tied output head: logits computed from the embedding weight (no extra params)

        # RoPE tables as non-persistent buffers (parameter-free)
        cos, sin = self._build_rope(cfg)
        self.register_buffer("rope_cos", cos, persistent=False)
        self.register_buffer("rope_sin", sin, persistent=False)

        self.apply(self._init_weights)
        # GPT-NeoX residual-projection scaling
        scale = cfg.init_std / math.sqrt(2 * cfg.n_layers)
        for name, p in self.named_parameters():
            if name.endswith("o_proj.weight") or name.endswith("down_proj.weight"):
                nn.init.normal_(p, mean=0.0, std=scale)

    @staticmethod
    def _build_rope(cfg: RavenLMConfig) -> tuple:
        head_dim = cfg.head_dim
        inv_freq = 1.0 / (cfg.rope_theta ** (torch.arange(0, head_dim, 2).float() / head_dim))
        t = torch.arange(cfg.context_length).float()
        freqs = torch.outer(t, inv_freq)              # (T, head_dim/2)
        emb = torch.cat((freqs, freqs), dim=-1)       # (T, head_dim)
        return emb.cos(), emb.sin()

    def _init_weights(self, module: nn.Module) -> None:
        std = self.cfg.init_std
        if isinstance(module, nn.Linear):
            nn.init.normal_(module.weight, mean=0.0, std=std)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            nn.init.normal_(module.weight, mean=0.0, std=std)

    def forward(self, ids: torch.Tensor) -> torch.Tensor:
        """ids: (B, T) long -> logits (B, T, vocab_size)."""
        if ids.dim() != 2:
            raise ValueError("ids must be (batch, seq)")
        T = ids.shape[1]
        if T > self.cfg.context_length:
            raise ValueError(
                f"sequence length {T} exceeds context_length {self.cfg.context_length}"
            )
        x = self.tok_emb(ids)
        cos, sin = self.rope_cos, self.rope_sin
        for block in self.blocks:
            x = block(x, cos, sin)
        x = self.final_norm(x)
        return F.linear(x, self.tok_emb.weight)  # tied head

    @property
    def parameter_count(self) -> int:
        return sum(p.numel() for p in self.parameters())

    @torch.no_grad()
    def generate(self, ids: torch.Tensor, max_new_tokens: int = 20,
                 temperature: float = 1.0, top_k: Optional[int] = None,
                 seed: Optional[int] = None) -> torch.Tensor:
        """Bounded autoregressive decode (advisory; CPU-safe).

        Resource-safe: threads are capped and ``max_new_tokens`` is hard-bounded. This is
        a reference decoder for the P2b inference layer, not a training loop.
        """
        torch.set_num_threads(min(4, torch.get_num_threads()))
        max_new_tokens = max(0, min(int(max_new_tokens), self.cfg.context_length))
        gen = None
        if seed is not None:
            gen = torch.Generator(device=ids.device).manual_seed(seed)
        was_training = self.training
        self.eval()
        try:
            for _ in range(max_new_tokens):
                ctx = ids[:, -self.cfg.context_length:]
                logits = self.forward(ctx)[:, -1, :]
                if temperature <= 0.0:
                    nxt = torch.argmax(logits, dim=-1, keepdim=True)
                else:
                    logits = logits / temperature
                    if top_k is not None:
                        k = min(top_k, logits.shape[-1])
                        kth = torch.topk(logits, k, dim=-1).values[:, -1, None]
                        logits = logits.masked_fill(logits < kth, float("-inf"))
                    probs = F.softmax(logits, dim=-1)
                    nxt = torch.multinomial(probs, num_samples=1, generator=gen)
                ids = torch.cat([ids, nxt], dim=1)
        finally:
            if was_training:
                self.train()
        return ids
