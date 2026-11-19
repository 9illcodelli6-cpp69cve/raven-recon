"""RAVEN native-AI bootstrap proof - the sec 39 ACCEPTANCE CHAIN (bounded, seconds).

Proves, end-to-end and locally, that RAVEN owns a real from-scratch generative pipeline:

  Stage 1  dataset manifest (DENY-guarded, leak-free split)
  Stage 2  RAVEN-owned byte-level BPE tokenizer trained from the corpus
  Stage 3  RAVEN-LM (Nano architecture) initialised from RANDOM RAVEN weights
  Stage 4  a SHORT, bounded, real training run (loss actually decreases)
  Stage 5  checkpoint written to disk + content hash
  Stage 6  inference loads that checkpoint (RAVEN checkpoint only)
  Stage 7  tokens generated LOCALLY (zero network / zero Ollama - socket-guarded)
  Stage 8  evaluation summary on the held-out split
  Stage 9  sec 16 registry entry (EXPERIMENTAL_BOOTSTRAP - never auto-PRODUCTION)

Bounded to a few seconds (tiny vocab + few steps). NOT the real bootstrap run - the
orchestrator runs that via the train CLI with the real Nano caps. NO Ollama, NO network,
NO engagement data. ``NATIVE_GENERATIVE_MODEL`` stays ``None`` throughout.

Run:  python scripts/native_ai_bootstrap_proof.py
"""
from __future__ import annotations

import socket
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

import raven.native_ai as native_ai
from raven.native_ai.bpe_tokenizer import ByteLevelBPETokenizer
from raven.native_ai.curriculum_impl import build_curriculum_dataset
from raven.native_ai.generative.model import RavenLMConfig
from raven.native_ai.generative.trainer import (
    ResourceBudget, TrainConfig, Trainer, checkpoint_file_hash,
)
from raven.native_ai.generative.infer import GenerationConfig, NativeInferenceEngine
from raven.native_ai.generative.eval_impl import NativeEvaluationSuite
from raven.native_ai.generative.registry_ext import (
    NativeModelRegistry, NativeMaturity, entry_from_manifest, SECTION16_FIELDS,
)


@contextmanager
def no_network_guard():
    """Make ANY socket construction raise - proves inference touches no network."""
    real = socket.socket

    def _blocked(*a, **k):
        raise AssertionError("network access attempted during native inference")

    socket.socket = _blocked  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket = real  # type: ignore[assignment]


def main() -> int:
    assert native_ai.NATIVE_GENERATIVE_MODEL is None, "constant must start None"
    print("=" * 66)
    print("RAVEN NATIVE-AI BOOTSTRAP PROOF - bounded acceptance chain (seconds)")
    print("=" * 66)

    with tempfile.TemporaryDirectory() as tmp:
        # Stage 1 - dataset manifest
        ds = build_curriculum_dataset()
        manifest = ds.manifest()
        splits = ds.split(seed=7)
        assert splits.is_leak_free()
        print(f"[1/9] dataset   : {manifest['n_samples']} samples, "
              f"content_hash={manifest['content_hash'][:16]}..., "
              f"train/val/holdout={splits.n_train}/{splits.n_val}/{splits.n_holdout}, "
              f"leak_free=True")

        # Stage 2 - tokenizer trained from the corpus
        tok = ByteLevelBPETokenizer().train(ds.texts(), vocab_size=1024)
        assert tok.decode(tok.encode("GET /x 200 مرحبا")) == "GET /x 200 مرحبا"
        print(f"[2/9] tokenizer : vocab={tok.vocab_size}, version={tok.version}, "
              f"hash={tok.hash[:16]}... (round-trip OK incl. Arabic)")

        # Stage 3 - RAVEN-LM (Nano arch) from RANDOM init
        cfg = RavenLMConfig(vocab_size=max(1024, tok.vocab_size), d_model=256,
                            n_layers=4, n_heads=8, d_ff=704, context_length=256)
        budget = ResourceBudget(name="SAFE_DESKTOP", max_threads=4, max_batch_size=8,
                                max_seq_len=64, max_steps=6, max_wall_clock_s=60.0,
                                max_tokens=200_000, checkpoint_interval=0)
        trainer = Trainer(cfg, tok, [s.text for s in splits.train],
                          [s.text for s in splits.val],
                          train_config=TrainConfig(seed=7, lr=1e-3, warmup_steps=1,
                                                   val_interval=0),
                          budget=budget, dataset_manifest_hash=manifest["content_hash"])
        print(f"[3/9] model     : RAVEN-LM Nano-arch, params={trainer.model.parameter_count:,}, "
              f"ctx={cfg.context_length}, random-init seed=7")

        # Stage 4 - short, bounded, REAL training
        result = trainer.train(checkpoint_dir=tmp, checkpoint_prefix="proof")
        assert result.loss_decreased, (result.initial_loss, result.final_loss)
        print(f"[4/9] train     : steps={result.steps_completed}, "
              f"loss {result.initial_loss:.4f} -> {result.final_loss:.4f} "
              f"(decreased), stop={result.stop_reason}")

        # Stage 5 - checkpoint on disk + hash
        ckpt = result.checkpoint_path
        assert ckpt and Path(ckpt).is_file()
        assert checkpoint_file_hash(ckpt) == result.checkpoint_hash
        tok_path = str(Path(ckpt).with_suffix("")) + ".tokenizer.json"
        tok.save(tok_path)
        print(f"[5/9] checkpoint: {Path(ckpt).name}, sha256={result.checkpoint_hash[:16]}...")

        # Stages 6+7 - inference loads checkpoint and generates LOCALLY (no network)
        with no_network_guard():
            engine = NativeInferenceEngine.from_checkpoint(ckpt, tokenizer_path=tok_path)
            out = engine.generate("HTTP/1.1 ", GenerationConfig(
                max_new_tokens=16, deterministic=True, timeout_s=10.0))
        assert isinstance(out.tokens, list) and 0 < len(out.tokens) <= 16
        assert out.is_advisory and not out.sets_verification_status
        print(f"[6/9] inference : checkpoint reloaded into a fresh RAVEN-LM (RAVEN ckpt only)")
        print(f"[7/9] generate  : {len(out.tokens)} tokens LOCALLY, zero network/Ollama "
              f"(socket-guarded), advisory=True")

        # Stage 8 - evaluation summary on held-out split
        suite = NativeEvaluationSuite(engine.model, tok, splits, seq_len=64)
        summary = suite.evaluation_summary()
        print(f"[8/9] eval      : val_ppl={summary['val_perplexity']}, "
              f"holdout_ppl={summary['holdout_perplexity']}, "
              f"tok_coverage={summary['tokenizer_coverage']['coverage']:.2f}, "
              f"tech_roundtrip={summary['technical_token_preservation']['roundtrip']:.2f}")

        # Stage 9 - sec 16 registry entry (never auto-PRODUCTION)
        reg = NativeModelRegistry(str(Path(tmp) / "native_registry.json"))
        entry = entry_from_manifest(result.manifest, checkpoint_path=ckpt,
                                    checkpoint_hash=result.checkpoint_hash,
                                    evaluation_summary=summary)
        reg.register(entry)
        missing = [f for f in SECTION16_FIELDS if not hasattr(entry, f)]
        assert not missing, missing
        assert entry.maturity == NativeMaturity.EXPERIMENTAL_BOOTSTRAP
        assert not reg.production_models(), "nothing may auto-reach PRODUCTION"
        print(f"[9/9] registry  : {entry.model_id}, maturity={entry.maturity.value}, "
              f"sec 16 fields complete, PRODUCTION count=0")

    assert native_ai.NATIVE_GENERATIVE_MODEL is None, "constant must remain None"
    print("-" * 66)
    print("PASS - RAVEN owns a real from-scratch generative pipeline "
          "(tokenizer+model+train+checkpoint+infer+eval+registry), all local, "
          "NATIVE_GENERATIVE_MODEL still None.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
