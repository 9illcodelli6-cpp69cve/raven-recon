"""Tests for RAVEN-LM (decoder-only Transformer) at the RAVEN-Nano config.

Proves: builds at Nano config with ~4.26M params (exact 4,262,144); forward produces
correctly-shaped logits; deterministic given a seed; tied input/output embeddings (no
separate head params); bounded generate; tier param counts match the scaling table;
config validation. All tests use tiny tensors and no training — fast and CPU-safe.

Run:  python -m pytest tests/test_native_ai_model.py -q
"""
import pytest

torch = pytest.importorskip("torch", reason="local-AI tests need PyTorch (see requirements-ai.txt)")

import torch
import pytest

from raven.native_ai.generative.model import RavenLM, RavenLMConfig

torch.set_num_threads(4)

NANO_PARAMS = 4_262_144


def test_nano_param_count_exact():
    cfg = RavenLMConfig.nano()
    model = RavenLM(cfg, seed=0)
    assert model.parameter_count == NANO_PARAMS
    # closed-form matches instantiated count
    assert RavenLMConfig.expected_param_count(
        cfg.vocab_size, cfg.d_model, cfg.n_layers, cfg.d_ff) == NANO_PARAMS
    # ~4.26M
    assert abs(model.parameter_count / 1e6 - 4.26) < 0.01


def test_forward_logits_shape():
    cfg = RavenLMConfig.nano()
    model = RavenLM(cfg, seed=1)
    ids = torch.randint(0, cfg.vocab_size, (3, 16))
    logits = model(ids)
    assert logits.shape == (3, 16, cfg.vocab_size)
    assert logits.dtype == torch.float32
    assert torch.isfinite(logits).all()


def test_deterministic_with_seed():
    cfg = RavenLMConfig.nano()
    m1 = RavenLM(cfg, seed=1234)
    m2 = RavenLM(cfg, seed=1234)
    assert torch.allclose(m1.tok_emb.weight, m2.tok_emb.weight)
    ids = torch.randint(0, cfg.vocab_size, (2, 12))
    m1.eval(); m2.eval()
    with torch.no_grad():
        assert torch.allclose(m1(ids), m2(ids))


def test_embeddings_tied_no_separate_head():
    cfg = RavenLMConfig.nano()
    model = RavenLM(cfg, seed=2)
    names = [n for n, _ in model.named_parameters()]
    assert not any("lm_head" in n for n in names)
    # logits are produced from the embedding weight (tied head)
    ids = torch.randint(0, cfg.vocab_size, (1, 8))
    model.eval()
    with torch.no_grad():
        x = model.tok_emb(ids)
        for b in model.blocks:
            x = b(x, model.rope_cos, model.rope_sin)
        x = model.final_norm(x)
        manual = torch.nn.functional.linear(x, model.tok_emb.weight)
        assert torch.allclose(model(ids), manual)


def test_no_bias_params():
    model = RavenLM(RavenLMConfig.nano(), seed=3)
    bias_params = [n for n, _ in model.named_parameters() if n.endswith(".bias")]
    assert bias_params == []


def test_generate_is_bounded():
    cfg = RavenLMConfig.nano()
    model = RavenLM(cfg, seed=4)
    ids = torch.randint(0, cfg.vocab_size, (1, 4))
    out = model.generate(ids, max_new_tokens=5, temperature=0.8, top_k=20, seed=7)
    assert out.shape == (1, 9)
    # request beyond context length is clamped (no runaway)
    out2 = model.generate(ids, max_new_tokens=10_000, temperature=0.0)
    assert out2.shape[1] <= 4 + cfg.context_length


def test_generate_greedy_deterministic():
    cfg = RavenLMConfig.nano()
    model = RavenLM(cfg, seed=5)
    ids = torch.randint(0, cfg.vocab_size, (1, 4))
    a = model.generate(ids, max_new_tokens=4, temperature=0.0)
    b = model.generate(ids, max_new_tokens=4, temperature=0.0)
    assert torch.equal(a, b)


def test_context_length_enforced():
    cfg = RavenLMConfig.nano()
    model = RavenLM(cfg, seed=6)
    too_long = torch.zeros((1, cfg.context_length + 1), dtype=torch.long)
    with pytest.raises(ValueError):
        model(too_long)


def test_tier_param_counts_match_scaling_table():
    micro = RavenLMConfig.micro()
    base = RavenLMConfig.base()
    n_micro = RavenLMConfig.expected_param_count(
        micro.vocab_size, micro.d_model, micro.n_layers, micro.d_ff)
    n_base = RavenLMConfig.expected_param_count(
        base.vocab_size, base.d_model, base.n_layers, base.d_ff)
    assert abs(n_micro / 1e6 - 29.9) < 0.3     # ~29.9M
    assert abs(n_base / 1e6 - 97.5) < 0.5      # ~97.5M


def test_config_validation():
    with pytest.raises(ValueError):
        RavenLMConfig(d_model=100, n_heads=8)       # not divisible
    with pytest.raises(ValueError):
        RavenLMConfig(d_model=24, n_heads=8)        # head_dim=3 is odd → bad for RoPE
