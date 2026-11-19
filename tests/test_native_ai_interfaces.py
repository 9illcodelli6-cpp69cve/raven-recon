"""Wave 13 (A13-NATIVE) — native_ai is an INTERFACE-ONLY, inert foundation.

Proves the honesty contract for the INTERFACE-ONLY top-level ``raven/native_ai/``:
  * importing the package exposes the interfaces + ``NATIVE_GENERATIVE_MODEL = None``;
  * EVERY operational method raises ``NotImplementedError``;
  * there is NO training / inference / tokenizer / download / network / torch code in
    the top-level interface modules;
  * the live runtime/API path references native_ai ONLY through the GATED,
    off-by-default Phase-4 generative provider layer (``native_ai.generative.*``) — see
    ``NativeLivePathIsGatedOptInOnly`` below.

The top-level interface package must be side-effect-free and must never be mistakable
for a shipped generative model. Loopback/in-memory only; no external host is contacted.

Phase-4 (P4-NATIVE-CHAT) note: the Wave-13 ``NotWiredIntoLivePath`` tripwire asserted
native_ai was *entirely unwired*. P4's mandate is to wire RAVEN's OWN from-scratch model
in as a selectable, first-party chat provider, so that structural assertion is
legitimately superseded (same sanctioned pattern as the Wave-13 chat-golden update). The
HONESTY SUBSTANCE it protected is UNCHANGED and still enforced: the shipped-model flag
stays ``None``, the native path is OFF by default + eval-gated, chat never fabricates,
and RAVEN has no runtime dependency on a generative model (default run = honest
unavailable). ``NativeLivePathIsGatedOptInOnly`` now locks that honest, gated reality.

Run:  python -m pytest tests/test_native_ai_interfaces.py -q
"""
import importlib
import pathlib
import unittest

import raven.native_ai as native_ai
from raven.native_ai import (
    NATIVE_GENERATIVE_MODEL,
    DatasetRegistry, DatasetSnapshot,
    Curriculum, CurriculumStage,
    Tokenizer,
    ModelArtifact, Checkpoint, ArtifactLifecycle,
    TrainingRun, TrainingRunStatus,
    EvaluationSuite, EvaluationResult,
    Inference, InferenceRequest, InferenceResult,
    ResourceProfile,
)

_NATIVE_AI_DIR = pathlib.Path(native_ai.__file__).resolve().parent
_MODULES = [
    "dataset_registry", "curriculum", "tokenizer", "artifact",
    "training_run", "evaluation", "inference", "resource_profile",
]


class NativeGenerativeModelConstant(unittest.TestCase):
    def test_constant_is_none(self):
        self.assertIsNone(NATIVE_GENERATIVE_MODEL)
        self.assertIsNone(native_ai.NATIVE_GENERATIVE_MODEL)

    def test_status_constant_is_honest(self):
        self.assertEqual(native_ai.NATIVE_AI_STATUS,
                         "NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE")


class AllModulesImportCleanly(unittest.TestCase):
    def test_every_module_imports(self):
        for name in _MODULES:
            mod = importlib.import_module(f"raven.native_ai.{name}")
            self.assertIsNotNone(mod)


class EveryOperationalMethodRaises(unittest.TestCase):
    """Each interface is instantiable but every operational method raises
    NotImplementedError — it is IMPOSSIBLE to accidentally run a native model."""

    def _assert_raises(self, fn):
        with self.assertRaises(NotImplementedError):
            fn()

    def test_dataset_registry(self):
        r = DatasetRegistry()
        snap = DatasetSnapshot(snapshot_id="s", name="n", provenance="ref")
        for fn in (lambda: r.register(snap), lambda: r.get("s"),
                   lambda: r.list_snapshots(), lambda: r.provenance("s")):
            self._assert_raises(fn)

    def test_curriculum(self):
        c = Curriculum()
        stage = CurriculumStage(stage_id="x", name="n", order=0)
        for fn in (lambda: c.stages(), lambda: c.add_stage(stage),
                   lambda: c.next_stage(), lambda: c.evaluation_hook("x")):
            self._assert_raises(fn)

    def test_tokenizer(self):
        t = Tokenizer()
        for fn in (lambda: t.encode("hi"), lambda: t.decode([1]),
                   lambda: t.vocab_size):           # property access must raise too
            self._assert_raises(fn)

    def test_model_artifact(self):
        a = ModelArtifact()
        for fn in (lambda: a.identity(), lambda: a.lifecycle_state(),
                   lambda: a.resource_profile(), lambda: a.load()):
            self._assert_raises(fn)

    def test_checkpoint(self):
        ck = Checkpoint()
        for fn in (lambda: ck.identity(), lambda: ck.step(),
                   lambda: ck.save("p"), lambda: ck.restore()):
            self._assert_raises(fn)

    def test_training_run_has_no_trainer(self):
        tr = TrainingRun()
        for fn in (lambda: tr.descriptor(), lambda: tr.status(),
                   lambda: tr.start(), lambda: tr.metrics()):
            self._assert_raises(fn)

    def test_evaluation_suite(self):
        e = EvaluationSuite()
        res = EvaluationResult(suite_id="s")
        for fn in (lambda: e.evaluate("a", "d"), lambda: e.gate(res),
                   lambda: e.criteria()):
            self._assert_raises(fn)

    def test_inference_has_no_native_model(self):
        inf = Inference()
        req = InferenceRequest(prompt="hi")
        for fn in (lambda: inf.predict(req), lambda: inf.is_ready()):
            self._assert_raises(fn)

    def test_resource_profile(self):
        rp = ResourceProfile()
        for fn in (lambda: rp.envelope(), lambda: rp.fits({})):
            self._assert_raises(fn)


class AdvisoryBoundaryHeld(unittest.TestCase):
    """Any result descriptor stays advisory and never sets verification status."""

    def test_evaluation_result_advisory(self):
        res = EvaluationResult(suite_id="s")
        self.assertTrue(res.is_advisory)
        self.assertFalse(res.sets_verification_status)

    def test_inference_result_advisory(self):
        res = InferenceResult()
        self.assertTrue(res.is_advisory)
        self.assertFalse(res.sets_verification_status)

    def test_lifecycle_vocabulary_reused(self):
        # Same vocabulary as ml/registry (DEVELOPMENT->CANDIDATE->PRODUCTION), not a
        # second scheme.
        self.assertEqual(
            {s.value for s in ArtifactLifecycle},
            {"DEVELOPMENT", "CANDIDATE", "PRODUCTION", "ARCHIVED"},
        )
        self.assertEqual(TrainingRunStatus.NOT_STARTED.value, "NOT_STARTED")


class NoForbiddenCodeOrDependencies(unittest.TestCase):
    """Static guard: no training/inference/download/network/torch machinery exists in
    the package source — it is interfaces only."""

    _FORBIDDEN = (
        "import torch", "import tensorflow", "import requests", "urllib.request",
        "urllib.error", "import socket", "subprocess", "http.client",
        "huggingface", "from ollama", "import ollama", "model_download", ".pt'", ".pt\"",
        "optimizer", "loss.backward", "state_dict",
    )

    def test_no_forbidden_tokens_in_sources(self):
        offenders = []
        for py in _NATIVE_AI_DIR.glob("*.py"):
            text = py.read_text(encoding="utf-8")
            for tok in self._FORBIDDEN:
                if tok in text:
                    offenders.append(f"{py.name}: {tok!r}")
        self.assertEqual(offenders, [], f"native_ai must stay interface-only: {offenders}")


class NativeLivePathIsGatedOptInOnly(unittest.TestCase):
    """Phase-4 (P4-NATIVE-CHAT): native_ai is wired in as a selectable, FIRST-PARTY chat
    provider — so it is no longer 'entirely unwired'. The honesty substance the Wave-13
    tripwire protected is UNCHANGED and still locked here + by the default-path suites
    (test_ai_optional_provider, test_golden_terminal_chat_workspace,
    test_native_chat_integration):

      * the live path references native_ai ONLY through the GATED generative provider
        layer (``native_ai.generative.*``), never a bare top-level import that could be
        misread as a shipped model;
      * ONLY the two sanctioned Phase-4 wiring modules may reference it — any other live
        module importing native_ai still fails here;
      * nothing on the live path reassigns ``NATIVE_GENERATIVE_MODEL`` (stays None —
        proven in NativeGenerativeModelConstant); the native path is OFF by default.

    raven/ai/chat.py and raven/runtime/conversation.py stay native_ai-free: chat routes
    through the generic ModelService provider abstraction, not a native import.
    """

    # The ONLY live modules allowed to reference native_ai, and why.
    _SANCTIONED = {
        "raven/api/server.py",      # lists/selects native checkpoints; registers provider
        "raven/runtime/model.py",   # build_native_provider(): lazy, gated adapter factory
    }
    _MUST_STAY_CLEAN = [
        "raven/ai/chat.py",
        "raven/runtime/conversation.py",
    ]
    _IMPORT_PATTERNS = ("import raven.native_ai", "from raven.native_ai",
                        "from ..native_ai", "from .native_ai")

    def test_only_sanctioned_live_modules_reference_native_ai(self):
        repo = pathlib.Path(__file__).resolve().parent.parent
        importers = set()
        for p in (repo / "raven").rglob("*.py"):
            if "native_ai" in p.parts:
                continue
            text = p.read_text(encoding="utf-8")
            if any(k in text for k in self._IMPORT_PATTERNS):
                importers.add(str(p.relative_to(repo)).replace("\\", "/"))
        self.assertEqual(
            importers, self._SANCTIONED,
            f"native_ai may be imported on the live path ONLY by the sanctioned Phase-4 "
            f"wiring {self._SANCTIONED}; found {importers}")

    def test_live_references_go_through_the_gated_generative_layer_only(self):
        repo = pathlib.Path(__file__).resolve().parent.parent
        for rel in self._SANCTIONED:
            for line in (repo / rel).read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s.startswith("#"):
                    continue
                if any(k in s for k in self._IMPORT_PATTERNS):
                    self.assertIn(
                        "native_ai.generative", s,
                        f"{rel}: a live native_ai import must target the gated generative "
                        f"provider layer, not the inert top-level package: {s!r}")

    def test_wiring_modules_never_reassign_the_honesty_flag(self):
        repo = pathlib.Path(__file__).resolve().parent.parent
        for rel in self._SANCTIONED:
            text = (repo / rel).read_text(encoding="utf-8")
            self.assertNotIn("NATIVE_GENERATIVE_MODEL =", text,
                             f"{rel} must never flip the shipped-model honesty flag")

    def test_chat_and_conversation_stay_native_ai_free(self):
        repo = pathlib.Path(__file__).resolve().parent.parent
        offenders = [rel for rel in self._MUST_STAY_CLEAN
                     if (repo / rel).is_file()
                     and "native_ai" in (repo / rel).read_text(encoding="utf-8")]
        self.assertEqual(offenders, [],
                         f"these live modules must not reference native_ai: {offenders}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
