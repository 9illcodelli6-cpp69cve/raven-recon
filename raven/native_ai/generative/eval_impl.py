"""Native-model evaluation — INDEPENDENT of the trainer, held-out, advisory.

Concrete :class:`raven.native_ai.evaluation.EvaluationSuite` for RAVEN-LM. It evaluates
a model + tokenizer + dataset splits WITHOUT any dependency on an in-progress training
run (it re-packs its own eval tensors), so the same suite can grade any checkpoint.

Metrics produced (all gathered into an ``evaluation_summary`` dict):
  * ``val_loss`` / ``val_perplexity`` — next-token cross-entropy on the validation split.
  * ``holdout_loss`` / ``holdout_perplexity`` — on ``splits.holdout``: the EVALUATION
    families reserved globally to holdout and NEVER trained on (leak-free by the
    dataset's grouped-family splitter).
  * ``tokenizer_coverage`` — byte-level round-trip losslessness over an AR / EN / mixed /
    technical probe set (a total byte-level BPE should score 1.0).
  * ``ar_en_mixed_handling`` — per-language round-trip success (Arabic / English / mixed).
  * ``technical_token_preservation`` — HTTP methods / status codes / header names encode
    to a single atomic id and round-trip exactly.
  * ``completion_coherence`` — a basic, HONEST signal: fraction of short greedy
    completions that decode to valid (non-replacement) UTF-8 text. NOT a capability
    claim; a tiny bootstrap model is expected to be weak here.
  * ``label_self_consistency`` — EXPLICITLY labelled a self-consistency probe: greedy
    label-completion on held-out teacher observations compared to the deterministic
    teacher's own label. Because the gold labels come from the same rule that generated
    the training supervision, this is reported as self-consistency, NOT as independent
    accuracy (per the campaign rule against self-grading with the generating rules).
  * ``uncertainty`` — mean predictive entropy on an out-of-distribution probe (a crude
    hallucination/uncertainty signal; advisory only).

Every result is ADVISORY (``EvaluationResult.is_advisory=True``,
``sets_verification_status=False``) and a passing ``gate`` NEVER promotes a model to
PRODUCTION — promotion is an explicit researcher action in the registry.
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence

import torch
import torch.nn.functional as F

from raven.native_ai.evaluation import EvaluationResult, EvaluationSuite

from .model import RavenLM

SUITE_ID = "native_lm_holdout_v1"

# Multilingual round-trip probes (RAVEN-authored; no private/engagement data).
_AR_PROBES = ["مرحبا بالعالم", "طلب HTTP غير آمن", "رمز الحالة ٢٠٠"]
_EN_PROBES = ["The server returned a 200 OK response.", "Reflection is not execution."]
_MIXED_PROBES = ["status=200 يعني نجاح الطلب", "Authorization header مفقود"]
_TECH_PROBES = ["GET", "POST", "DELETE", "200", "401", "403", "404", "429", "500",
                "content-type", "authorization", "www-authenticate", "http://", "https://"]
_OOD_PROBES = ["zzzxqv portmanteau", "\x01\x02 raw bytes", "لا شيء هنا على الإطلاق"]


class NativeEvaluationSuite(EvaluationSuite):
    """Real-holdout evaluation gate for a native RAVEN-LM (advisory)."""

    def __init__(self, model: RavenLM, tokenizer, splits=None, *,
                 seq_len: Optional[int] = None, max_eval_blocks: int = 256,
                 batch_size: int = 8, max_threads: int = 4) -> None:
        torch.set_num_threads(max(1, int(max_threads)))
        self.model = model
        self.model.eval()
        self.tokenizer = tokenizer
        self.splits = splits
        self.seq_len = min(int(seq_len or model.cfg.context_length),
                           int(model.cfg.context_length))
        self.max_eval_blocks = int(max_eval_blocks)
        self.batch_size = int(batch_size)
        self._pad_id = self._special("<pad>")
        self._eos_id = self._special("<eos>")

    def _special(self, tok: str) -> Optional[int]:
        fn = getattr(self.tokenizer, "special_token_id", None)
        if fn is None:
            return None
        try:
            return int(fn(tok))
        except Exception:
            return None

    # -- packing (own copy — independent of the trainer) -----------------------

    def _pack(self, texts: Sequence[str]) -> List[List[int]]:
        flat: List[int] = []
        for t in texts:
            flat.extend(self.tokenizer.encode(t))
            if self._eos_id is not None:
                flat.append(self._eos_id)
        block = self.seq_len + 1
        out = [flat[i:i + block] for i in range(0, len(flat) - block + 1, self.seq_len)]
        out = [b for b in out if len(b) == block]
        return out[: self.max_eval_blocks]

    @torch.no_grad()
    def _mean_loss(self, texts: Sequence[str]) -> Optional[float]:
        blocks = self._pack(texts)
        if not blocks:
            return None
        ignore = self._pad_id if self._pad_id is not None else -100
        total, n = 0.0, 0
        for i in range(0, len(blocks), self.batch_size):
            rows = blocks[i:i + self.batch_size]
            t = torch.tensor(rows, dtype=torch.long)
            logits = self.model(t[:, :-1])
            loss = F.cross_entropy(logits.reshape(-1, logits.size(-1)),
                                   t[:, 1:].reshape(-1), ignore_index=ignore)
            total += float(loss) * len(rows)
            n += len(rows)
        return total / max(1, n)

    # -- tokenizer / multilingual / technical probes ---------------------------

    def _roundtrip_ok(self, text: str) -> bool:
        try:
            return self.tokenizer.decode(self.tokenizer.encode(text)) == text
        except Exception:
            return False

    def _tokenizer_coverage(self) -> Dict:
        probes = _AR_PROBES + _EN_PROBES + _MIXED_PROBES + _TECH_PROBES
        ok = sum(1 for p in probes if self._roundtrip_ok(p))
        return {
            "coverage": ok / max(1, len(probes)),
            "n_probes": len(probes),
            "ar": sum(1 for p in _AR_PROBES if self._roundtrip_ok(p)) / len(_AR_PROBES),
            "en": sum(1 for p in _EN_PROBES if self._roundtrip_ok(p)) / len(_EN_PROBES),
            "mixed": sum(1 for p in _MIXED_PROBES if self._roundtrip_ok(p)) / len(_MIXED_PROBES),
        }

    def _technical_preservation(self) -> Dict:
        single, rt = 0, 0
        for t in _TECH_PROBES:
            ids = self.tokenizer.encode(t)
            if len(ids) == 1:
                single += 1
            if self._roundtrip_ok(t):
                rt += 1
        return {
            "atomic_single_token": single / len(_TECH_PROBES),
            "roundtrip": rt / len(_TECH_PROBES),
            "n": len(_TECH_PROBES),
        }

    # -- generation-based probes (greedy; deterministic) -----------------------

    @torch.no_grad()
    def _greedy_continue(self, prompt_ids: List[int], max_new: int) -> List[int]:
        ctx = self.model.cfg.context_length
        ids = torch.tensor([prompt_ids], dtype=torch.long)
        out: List[int] = []
        for _ in range(max_new):
            logits = self.model(ids[:, -ctx:])[:, -1, :]
            nxt = int(torch.argmax(logits, dim=-1).item())
            out.append(nxt)
            ids = torch.cat([ids, torch.tensor([[nxt]], dtype=torch.long)], dim=1)
            if self._eos_id is not None and nxt == self._eos_id:
                break
        return out

    def _completion_coherence(self) -> Dict:
        prompts = [p for p in _EN_PROBES] + ["HTTP/1.1 ", "content-type: "]
        valid = 0
        for p in prompts:
            new = self._greedy_continue(self.tokenizer.encode(p), max_new=12)
            text = self.tokenizer.decode(new)
            if text and "�" not in text:
                valid += 1
        return {"valid_utf8_fraction": valid / max(1, len(prompts)),
                "n": len(prompts),
                "note": "basic validity signal, not a capability claim"}

    def _label_self_consistency(self) -> Dict:
        """SELF-CONSISTENCY probe on held-out teacher observations (explicitly labelled).

        The held-out observations were never trained on, but their gold labels come from
        the same deterministic teacher rule that produced the training supervision — so
        this is reported as *self-consistency*, not independent accuracy.
        """
        if self.splits is None:
            return {"applicable": False}
        samples = [s for s in getattr(self.splits, "holdout", [])
                   if getattr(s, "source_type", "") == "DETERMINISTIC_TEACHER"]
        if not samples:
            return {"applicable": False}
        raven_id = self._special("<|raven|>")
        end_id = self._special("<|endturn|>")
        hits, total = 0, 0
        for s in samples:
            text = s.text
            if "<|raven|>" not in text:
                continue
            prompt_text, gold = text.split("<|raven|>", 1)
            gold = gold.replace("<|endturn|>", "")
            prompt_ids = self.tokenizer.encode(prompt_text + "<|raven|>")
            new = self._greedy_continue(prompt_ids, max_new=8)
            gen = self.tokenizer.decode(new).replace("<|endturn|>", "").strip()
            total += 1
            if gen.startswith(gold.strip()) and gold.strip():
                hits += 1
        return {
            "applicable": True,
            "self_consistency": (hits / total) if total else 0.0,
            "n": total,
            "kind": "SELF_CONSISTENCY_NOT_INDEPENDENT_ACCURACY",
            "note": ("gold labels come from the same deterministic rule that made the "
                     "training data; reported as self-consistency only"),
        }

    @torch.no_grad()
    def _uncertainty(self) -> Dict:
        """Mean predictive entropy on OOD probes — a crude hallucination/uncertainty
        signal (advisory). Higher entropy ~ less confident."""
        ents: List[float] = []
        for p in _OOD_PROBES:
            ids = self.tokenizer.encode(p)
            if not ids:
                continue
            t = torch.tensor([ids[: self.model.cfg.context_length]], dtype=torch.long)
            logits = self.model(t)[:, -1, :]
            probs = F.softmax(logits, dim=-1)
            ent = float(-(probs * torch.log(probs + 1e-12)).sum(dim=-1).mean())
            ents.append(ent)
        max_ent = math.log(self.model.cfg.vocab_size)
        mean_ent = (sum(ents) / len(ents)) if ents else 0.0
        return {"mean_entropy_nats": mean_ent,
                "normalized": mean_ent / max_ent if max_ent else 0.0,
                "max_entropy_nats": max_ent}

    # -- public surface --------------------------------------------------------

    def evaluation_summary(self) -> Dict:
        val_loss = self._mean_loss([s.text for s in getattr(self.splits, "val", [])]) \
            if self.splits else None
        holdout_loss = self._mean_loss([s.text for s in getattr(self.splits, "holdout", [])]) \
            if self.splits else None

        def ppl(x: Optional[float]) -> Optional[float]:
            if x is None:
                return None
            return float(math.exp(min(x, 20.0)))

        return {
            "suite_id": SUITE_ID,
            "parameter_count": self.model.parameter_count,
            "context_window": self.model.cfg.context_length,
            "val_loss": val_loss,
            "val_perplexity": ppl(val_loss),
            "holdout_loss": holdout_loss,
            "holdout_perplexity": ppl(holdout_loss),
            "tokenizer_coverage": self._tokenizer_coverage(),
            "technical_token_preservation": self._technical_preservation(),
            "completion_coherence": self._completion_coherence(),
            "label_self_consistency": self._label_self_consistency(),
            "uncertainty": self._uncertainty(),
            "is_advisory": True,
            "sets_verification_status": False,
        }

    def criteria(self) -> Dict:
        """Honest, bootstrap-appropriate pass criteria. Passing the gate makes a model
        eligible for a researcher to CONSIDER advancing it — it never auto-promotes."""
        return {
            "tokenizer_coverage_min": 1.0,
            "technical_roundtrip_min": 1.0,
            "val_perplexity_finite": True,
            "note": "a pass is advisory; PRODUCTION requires explicit researcher action",
        }

    def evaluate(self, artifact_id: str = "", dataset_snapshot_id: str = "") -> EvaluationResult:
        summary = self.evaluation_summary()
        summary["artifact_id"] = artifact_id
        summary["dataset_snapshot_id"] = dataset_snapshot_id
        cov = summary["tokenizer_coverage"]["coverage"]
        tech = summary["technical_token_preservation"]["roundtrip"]
        vppl = summary["val_perplexity"]
        passed = (
            cov >= 1.0 and tech >= 1.0 and
            (vppl is None or (math.isfinite(vppl)))
        )
        return EvaluationResult(suite_id=SUITE_ID, passed=bool(passed), metrics=summary)

    def gate(self, result: EvaluationResult) -> bool:
        """Advisory gate — True means 'eligible for researcher review', NOT promotion."""
        return bool(result.passed)
