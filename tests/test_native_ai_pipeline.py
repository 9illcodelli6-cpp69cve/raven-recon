"""P2b — native-AI TRAIN / INFER / EVAL / REGISTRY pipeline tests (MICRO, fast, CPU-only).

Proves the real, RAVEN-owned generative pipeline WITHOUT any long training:

  * a MICRO training run (a few steps on a handful of samples) makes the loss DECREASE
    and does a real backward pass (weights change);
  * a checkpoint SAVE -> RESUME round-trips to bit-identical weights, and a resumed run
    continues byte-identically to an uninterrupted run (optimizer + step + deterministic
    batching restored);
  * native inference generates bounded deterministic tokens and makes ZERO network calls
    (asserted with a hard socket guard) -- no Ollama / HTTP;
  * the §16 registry entry carries every required field and CANNOT auto-reach PRODUCTION
    (promotion needs an explicit human researcher identifier);
  * the chat provider is OFF by default and returns an honest typed "unavailable" result
    (never fabricated text) when no checkpoint is selected;
  * evaluation runs on the held-out split and stays advisory;
  * none of this flips ``raven.native_ai.NATIVE_GENERATIVE_MODEL`` (stays None).

SAFE_DESKTOP: threads capped, tiny tensors, tiny model, <~a few seconds total.

Run:  python -m pytest tests/test_native_ai_pipeline.py -q
"""
import pytest

torch = pytest.importorskip("torch", reason="local-AI tests need PyTorch (see requirements-ai.txt)")

import socket

import pytest
import torch

import raven.native_ai as native_ai
from raven.native_ai.bpe_tokenizer import ByteLevelBPETokenizer
from raven.native_ai.curriculum_impl import build_curriculum_dataset
from raven.native_ai.generative.model import RavenLMConfig
from raven.native_ai.generative.trainer import (
    ResourceBudget, TrainConfig, Trainer, load_checkpoint, checkpoint_file_hash,
)
from raven.native_ai.generative.infer import GenerationConfig, NativeInferenceEngine
from raven.native_ai.generative.eval_impl import NativeEvaluationSuite
from raven.native_ai.generative.registry_ext import (
    NativeModelRegistry, NativeMaturity, NativeModelEntry, entry_from_manifest,
    SECTION16_FIELDS,
)
from raven.native_ai.generative.chat_provider import NativeChatProvider
from raven.runtime.model import ModelFailureKind

torch.set_num_threads(4)

# A handful of tiny samples (all RAVEN-authored; no private data).
_MICRO_TEXTS = [
    "GET /api HTTP/1.1\r\nhost: example.test\r\n\r\n",
    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"ok\":true}",
    "A 200 OK is not a vulnerability by itself.",
    "<|user|>status 404<|raven|>NOT_FOUND<|endturn|>",
]


def _tiny_tokenizer(vocab=400):
    return ByteLevelBPETokenizer().train(_MICRO_TEXTS, vocab_size=vocab)


def _tiny_config(tok):
    # head_dim must be even for RoPE; d_model=32, n_heads=4 -> head_dim 8.
    return RavenLMConfig(vocab_size=max(vocab_floor(tok), tok.vocab_size), d_model=32,
                         n_layers=2, n_heads=4, d_ff=64, context_length=64)


def vocab_floor(tok):
    return tok.vocab_size


def _micro_budget(steps=6, batch=64, seq=32):
    # batch >= #blocks -> full-batch GD on a fixed set -> clean, monotonic-ish decrease.
    return ResourceBudget(name="SAFE_DESKTOP_MICRO", max_threads=4, max_batch_size=batch,
                          max_seq_len=seq, max_steps=steps, max_wall_clock_s=60.0,
                          max_tokens=200_000, checkpoint_interval=0)


def _make_trainer(tmp_seed=0, steps=6, lr_total=0):
    tok = _tiny_tokenizer()
    cfg = _tiny_config(tok)
    tcfg = TrainConfig(seed=1234, lr=5e-3, warmup_steps=0, val_interval=0,
                       lr_total_steps=lr_total)
    return Trainer(cfg, tok, _MICRO_TEXTS, _MICRO_TEXTS, train_config=tcfg,
                   budget=_micro_budget(steps=steps), dataset_manifest_hash="micro-hash")


# ── 1. micro-train: loss decreases + real backward pass -----------------------

def test_micro_train_loss_decreases_and_weights_change():
    trainer = _make_trainer(steps=8)
    before = trainer.model.tok_emb.weight.detach().clone()
    result = trainer.train()
    assert result.steps_completed == 8
    assert result.stop_reason == "max_steps"
    # real optimization: loss went down and weights actually moved
    assert result.final_loss < result.initial_loss, (result.initial_loss, result.final_loss)
    after = trainer.model.tok_emb.weight.detach()
    assert not torch.allclose(before, after), "weights must change (real backward pass)"
    assert native_ai.NATIVE_GENERATIVE_MODEL is None


# ── 2. checkpoint save -> resume round-trip (same weights) --------------------

def test_checkpoint_save_resume_roundtrips_same_weights(tmp_path):
    t = _make_trainer(steps=5)
    t.train()
    ckpt = str(tmp_path / "mid.pt")
    h = t.save_checkpoint(ckpt)
    assert h == checkpoint_file_hash(ckpt)

    # Fresh trainer resumes the saved state -> bit-identical weights + step + optimizer.
    fresh = _make_trainer(steps=5)
    fresh.resume_from(ckpt)
    assert fresh.step == t.step
    for (n1, p1), (n2, p2) in zip(t.model.named_parameters(),
                                  fresh.model.named_parameters()):
        assert n1 == n2
        assert torch.equal(p1.detach(), p2.detach()), f"weight mismatch at {n1}"


def test_resume_continues_byte_identically(tmp_path):
    # All three share the SAME cosine horizon (lr_total=10) so the early-stopped
    # checkpoint represents the identical state of an uninterrupted run at that step.
    full = _make_trainer(steps=10, lr_total=10)
    full.train()
    wfull = {n: p.detach().clone() for n, p in full.model.named_parameters()}

    # Interrupted run: 5 steps -> checkpoint -> resume -> continue to 10.
    part = _make_trainer(steps=5, lr_total=10)
    part.train()
    ckpt = str(tmp_path / "half.pt")
    part.save_checkpoint(ckpt)

    cont = _make_trainer(steps=10, lr_total=10)   # budget max_steps=10
    cont.resume_from(ckpt)                         # restores step=5, optimizer, etc.
    cont.train()                                   # continues 5 -> 10, deterministic
    for n, p in cont.model.named_parameters():
        assert torch.equal(p.detach(), wfull[n]), f"resume diverged at {n}"


# ── 3. inference: bounded, deterministic, ZERO network ------------------------

def _train_and_save(tmp_path):
    t = _make_trainer(steps=4)
    r = t.train(checkpoint_dir=str(tmp_path), checkpoint_prefix="inf")
    tok_path = str(tmp_path / "inf_final.tokenizer.json")
    t.tokenizer.save(tok_path)
    return r.checkpoint_path, tok_path, t.tokenizer


def test_inference_bounded_and_deterministic(tmp_path):
    ckpt, tok_path, _ = _train_and_save(tmp_path)
    eng = NativeInferenceEngine.from_checkpoint(ckpt, tokenizer_path=tok_path)
    cfg = GenerationConfig(max_new_tokens=12, deterministic=True, timeout_s=10.0)
    a = eng.generate_tokens(eng.tokenizer.encode("GET "), cfg)
    b = eng.generate_tokens(eng.tokenizer.encode("GET "), cfg)
    assert a == b                                  # greedy = deterministic
    assert 0 < len(a) <= 12                         # hard-bounded
    res = eng.generate("GET ", cfg)
    assert res.is_advisory and not res.sets_verification_status


def test_inference_makes_zero_network_calls(tmp_path):
    ckpt, tok_path, _ = _train_and_save(tmp_path)
    eng = NativeInferenceEngine.from_checkpoint(ckpt, tokenizer_path=tok_path)
    real = socket.socket

    def _blocked(*a, **k):
        raise AssertionError("native inference attempted a network socket")

    socket.socket = _blocked
    try:
        out = eng.generate("HTTP/1.1 ", GenerationConfig(
            max_new_tokens=10, deterministic=True, timeout_s=10.0))
        list(eng.stream("GET ", GenerationConfig(max_new_tokens=5, deterministic=True)))
    finally:
        socket.socket = real
    assert len(out.tokens) > 0


def test_infer_module_imports_no_network_stack():
    """Parse infer.py's AST and assert it imports no network / Ollama / HTTP module
    (docstring prose that merely names them does not count — only real imports do)."""
    import ast
    import raven.native_ai.generative.infer as infer_mod

    src = __import__("pathlib").Path(infer_mod.__file__).read_text(encoding="utf-8")
    forbidden_roots = {"socket", "urllib", "http", "requests", "ollama", "ssl",
                       "asyncio", "aiohttp", "httpx"}
    imported_roots = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported_roots.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
    leaks = forbidden_roots & imported_roots
    assert not leaks, f"infer.py must not import network/Ollama modules: {leaks}"


# ── 4. registry: §16 fields present + no auto-PRODUCTION ----------------------

def test_registry_entry_has_all_section16_fields(tmp_path):
    t = _make_trainer(steps=2)
    r = t.train(checkpoint_dir=str(tmp_path), checkpoint_prefix="reg")
    entry = entry_from_manifest(r.manifest, checkpoint_path=r.checkpoint_path,
                                checkpoint_hash=r.checkpoint_hash,
                                evaluation_summary={"val_perplexity": 123.0})
    for field in SECTION16_FIELDS:
        assert hasattr(entry, field), f"missing §16 field {field}"
    assert entry.parameter_count == t.model.parameter_count
    assert entry.maturity == NativeMaturity.EXPERIMENTAL_BOOTSTRAP
    assert entry.dataset_manifest_hash == "micro-hash"
    d = entry.to_dict()
    assert NativeModelEntry.from_dict(d).model_id == entry.model_id


def test_registry_cannot_auto_reach_production(tmp_path):
    reg = NativeModelRegistry(str(tmp_path / "reg.json"))
    e = NativeModelEntry(
        model_id="m1", family="RAVEN-LM", architecture_version="raven-lm/1",
        tokenizer_version="raven-bbpe/1", parameter_count=1, context_window=64,
        checkpoint_path="x.pt", checkpoint_hash="h", training_run_id="r1",
        dataset_manifest_hash="d", maturity=NativeMaturity.EXPERIMENTAL_BOOTSTRAP)
    reg.register(e)

    # Cannot register straight into PRODUCTION.
    with pytest.raises(ValueError):
        reg.register(NativeModelEntry(
            model_id="m2", family="RAVEN-LM", architecture_version="raven-lm/1",
            tokenizer_version="v", parameter_count=1, context_window=64,
            checkpoint_path="y.pt", checkpoint_hash="h", training_run_id="r2",
            dataset_manifest_hash="d", maturity=NativeMaturity.PRODUCTION))

    # Cannot skip straight from bootstrap to production.
    with pytest.raises(ValueError):
        reg.promote_to_production("m1", promoted_by="dr_researcher")

    # Walk the ladder; a model/automated identifier is refused at the gate.
    reg.advance_to_development("m1")
    reg.advance_to_candidate("m1")
    for bad in ("", "model", "auto", "self", "trainer"):
        with pytest.raises(PermissionError):
            reg.promote_to_production("m1", promoted_by=bad)
    assert reg.get("m1").maturity == NativeMaturity.CANDIDATE   # still not production
    assert reg.production_models() == []

    # Only an explicit human researcher promotes.
    reg.promote_to_production("m1", promoted_by="researcher_jane", notes="eval pass")
    assert reg.get("m1").maturity == NativeMaturity.PRODUCTION
    assert reg.get("m1").promoted_by == "researcher_jane"


# ── 5. chat provider: OFF by default, honest-unavailable ----------------------

def test_chat_provider_honest_unavailable_without_checkpoint():
    prov = NativeChatProvider()
    assert prov.is_available is False
    assert prov.discover_models() == []
    res = prov.complete([{"role": "user", "content": "hello"}], model_id="raven-native")
    assert res.failure == ModelFailureKind.NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE
    assert res.content == ""                      # never fabricates text
    assert res.is_advisory is True
    assert native_ai.NATIVE_GENERATIVE_MODEL is None


def test_chat_provider_serves_only_after_explicit_selection(tmp_path):
    ckpt, tok_path, _ = _train_and_save(tmp_path)
    prov = NativeChatProvider()
    assert prov.is_available is False
    prov.select_checkpoint(ckpt, tokenizer_path=tok_path)
    assert prov.is_available is True
    res = prov.complete([{"role": "user", "content": "GET "}],
                        generation=GenerationConfig(max_new_tokens=6, deterministic=True))
    assert res.failure is None
    assert res.is_advisory is True
    assert res.usage.get("maturity") == "EXPERIMENTAL_BOOTSTRAP"   # maturity surfaced
    assert native_ai.NATIVE_GENERATIVE_MODEL is None               # not flipped


# ── 6. eval runs on the held-out split ----------------------------------------

def test_eval_runs_on_holdout_and_is_advisory(tmp_path):
    ds = build_curriculum_dataset()
    splits = ds.split(seed=42)
    assert splits.n_holdout > 0
    tok = _tiny_tokenizer(vocab=600)
    t = Trainer(_tiny_config(tok), tok, [s.text for s in splits.train],
                [s.text for s in splits.val],
                train_config=TrainConfig(seed=1234, lr=5e-3, warmup_steps=0, val_interval=0),
                budget=_micro_budget(steps=3), dataset_manifest_hash=ds.manifest()["content_hash"])
    t.train()
    suite = NativeEvaluationSuite(t.model, tok, splits, seq_len=32)
    summary = suite.evaluation_summary()
    assert summary["holdout_perplexity"] is not None
    assert summary["val_perplexity"] is not None
    assert summary["tokenizer_coverage"]["coverage"] == 1.0
    assert summary["technical_token_preservation"]["roundtrip"] == 1.0
    # self-consistency probe is explicitly labelled (not independent accuracy)
    lsc = summary["label_self_consistency"]
    if lsc.get("applicable"):
        assert lsc["kind"] == "SELF_CONSISTENCY_NOT_INDEPENDENT_ACCURACY"
    result = suite.evaluate(artifact_id="a1", dataset_snapshot_id="d1")
    assert result.is_advisory and not result.sets_verification_status


# ── 7. honesty invariant: nothing here flips the constant ---------------------

def test_native_generative_model_constant_stays_none():
    assert native_ai.NATIVE_GENERATIVE_MODEL is None
    assert native_ai.NATIVE_AI_STATUS == "NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE"
