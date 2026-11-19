"""RAVEN Wave 12 — ML loader repair tests (A12-ML).

Proves the two latent loader bugs are fixed by loading the project's REAL,
RAVEN-produced model artifacts from ``models/`` (read-only — nothing is
retrained, regenerated, or promoted):

  * Bug A (multiclass): ``InferenceEngine`` loads the NET-A/B/C/D classifiers
    whose arch metadata is ``logistic_regression_multiclass`` /
    ``random_forest_multiclass`` (previously rejected with "Unknown
    architecture") and runs predict/predict_proba to an advisory
    ``InferenceResult``.
  * Bug B (task-LR dict): the task_a/task_b LR artifacts stored as
    ``{"model", "scaler"}`` dicts load and apply the persisted scaler before
    the estimator.

Also locks the Wave 12 invariants:
  * registry ordering is deterministic ``(timestamp_utc, model_id)``;
  * ``get_production_model`` / ``from_registry`` return None with no PRODUCTION
    model (no synthetic DEVELOPMENT model is ever auto-promoted);
  * ``InferenceResult`` stays frozen / advisory-only — it can rank/classify/
    estimate but can NEVER set a verification status or authorize an action.

Loading these pickles executes code; they are trusted RAVEN artifacts loaded
read-only. No untrusted pickle is loaded here.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "models" / "registry.json"

try:
    import sklearn  # noqa: F401
    import numpy as np
    import joblib  # noqa: F401
    _SKLEARN = True
except Exception:  # pragma: no cover - env without sklearn
    _SKLEARN = False

_HAS_REGISTRY = REGISTRY_PATH.exists()


def _load_registry():
    from raven.ml.registry import ModelRegistry
    return ModelRegistry(str(REGISTRY_PATH))


def _abs_version(mv):
    """Resolve a registry entry's weights_path to an absolute path.

    Some entries store a path relative to the repo root; make the engine
    robust to the test's working directory without mutating the artifact.
    Linux port: the registry was written on Windows (``models\\x.pkl`` and
    ``C:\\Users\\...\\models\\x.pkl``), so resolve through the product's own
    portable resolver instead of ``os.path.isabs`` (which is False for a
    Windows path on POSIX).
    """
    from raven.ml.inference import resolve_weights_path
    resolved = resolve_weights_path(mv.weights_path)
    if not os.path.isabs(resolved):
        resolved = str(REPO_ROOT / resolved)
    mv.weights_path = resolved
    return mv


def _pick(versions, *, arch=None, task=None, schema=None):
    out = versions
    if arch:
        out = [v for v in out if v.architecture == arch]
    if task:
        out = [v for v in out if v.task == task]
    if schema:
        out = [v for v in out if v.feature_schema_version == schema]
    return out


@unittest.skipUnless(_SKLEARN, "scikit-learn / numpy / joblib not installed")
@unittest.skipUnless(_HAS_REGISTRY, "models/registry.json not present")
class BugAMulticlassLoaderTest(unittest.TestCase):
    """Bug A: *_multiclass architectures must load and run."""

    @classmethod
    def setUpClass(cls):
        cls.reg = _load_registry()
        cls.versions = cls.reg.list_versions()

    def _net_fv(self, **kw):
        from raven.network_fundamentals.features import NetworkFeatureVector
        return NetworkFeatureVector(**kw)

    def test_random_forest_multiclass_loads_and_predicts(self):
        from raven.ml.inference import InferenceEngine, InferenceResult
        cands = _pick(self.versions, arch="random_forest_multiclass", schema="net_v3")
        self.assertTrue(cands, "expected a net_v3 random_forest_multiclass artifact")
        mv = _abs_version(cands[0])
        engine = InferenceEngine(mv)
        self.assertIsNotNone(engine._model, "multiclass RF must load")
        # Direct predict_proba proof (multiclass → >2 columns).
        fv = self._net_fv(status_code=401, status_class=4, is_4xx=1,
                          has_auth_request=1, has_www_auth=1)
        proba = np.asarray(engine._model.predict_proba([fv.to_list()]))
        self.assertGreater(proba.shape[1], 2, "multiclass model should output >2 classes")
        # Engine predict → advisory InferenceResult with a real class label.
        result = engine.predict(fv)
        self.assertIsInstance(result, InferenceResult)
        self.assertIn(result.predicted_triage_class,
                      [str(c) for c in engine._model.classes_])
        self.assertTrue(0.0 <= result.probability <= 1.0)
        self.assertTrue(result.is_advisory)
        self.assertFalse(result.sets_verification_status)

    def test_logistic_regression_multiclass_pipeline_loads_and_predicts(self):
        from raven.ml.inference import InferenceEngine, InferenceResult
        cands = _pick(self.versions, arch="logistic_regression_multiclass", schema="net_v3")
        self.assertTrue(cands, "expected a net_v3 logistic_regression_multiclass artifact")
        mv = _abs_version(cands[0])
        engine = InferenceEngine(mv)
        self.assertIsNotNone(engine._model, "multiclass LR pipeline must load")
        fv = self._net_fv(status_code=200, status_class=2, is_2xx=1)
        result = engine.predict(fv)
        self.assertIsInstance(result, InferenceResult)
        self.assertIn(result.predicted_triage_class,
                      [str(c) for c in engine._model.classes_])
        self.assertTrue(0.0 <= result.probability <= 1.0)

    def test_all_multiclass_artifacts_load_without_error(self):
        """Every registered *_multiclass artifact must load (loader no longer rejects it)."""
        from raven.ml.inference import InferenceEngine
        multiclass = [v for v in self.versions if v.architecture.endswith("_multiclass")]
        self.assertGreaterEqual(len(multiclass), 30,
                                "expected the NET-A/B/C/D multiclass family")
        loaded = 0
        for v in multiclass:
            mv = _abs_version(v)
            if not os.path.exists(mv.weights_path):
                continue  # artifact file absent; skip (not a loader failure)
            engine = InferenceEngine(mv)       # would raise ValueError before Bug A fix
            self.assertIsNotNone(engine._model, f"{v.model_id} failed to load")
            loaded += 1
        self.assertGreater(loaded, 0, "no multiclass artifacts were available to load")


@unittest.skipUnless(_SKLEARN, "scikit-learn / numpy / joblib not installed")
@unittest.skipUnless(_HAS_REGISTRY, "models/registry.json not present")
class BugBTaskLRDictTest(unittest.TestCase):
    """Bug B: {model, scaler} dict artifacts load and apply the scaler."""

    @classmethod
    def setUpClass(cls):
        cls.reg = _load_registry()
        cls.versions = cls.reg.list_versions()

    def test_task_lr_dict_loads_and_scaler_is_applied(self):
        import joblib
        from raven.ml.inference import InferenceEngine, InferenceResult
        from raven.ml.features import FeatureVector

        cands = _pick(self.versions, arch="logistic_regression", task="task_a")
        self.assertTrue(cands, "expected a task_a logistic_regression artifact")
        mv = _abs_version(cands[0])
        if not os.path.exists(mv.weights_path):
            self.skipTest("task_a LR artifact file not present")

        # Artifact really is a {model, scaler} dict.
        raw = joblib.load(mv.weights_path)
        self.assertIsInstance(raw, dict)
        self.assertIn("model", raw)
        self.assertIn("scaler", raw)
        self.assertIsNotNone(raw["scaler"])

        engine = InferenceEngine(mv)
        fv = FeatureVector(status_code=200, status_class=2, body_size=500)
        result = engine.predict(fv)
        self.assertIsInstance(result, InferenceResult)
        self.assertTrue(0.0 <= result.probability <= 1.0)

        # Prove the engine applied scaler.transform BEFORE the estimator:
        x = np.array(fv.to_list(), dtype=float).reshape(1, -1)
        manual_scaled = float(raw["model"].predict_proba(raw["scaler"].transform(x))[0][1])
        manual_noscale = float(raw["model"].predict_proba(x)[0][1])
        self.assertAlmostEqual(result.probability, manual_scaled, places=9,
                               msg="engine must apply the persisted scaler")
        self.assertNotAlmostEqual(manual_scaled, manual_noscale, places=6,
                                  msg="scaled vs unscaled must differ (scaler is load-bearing)")

    def test_task_b_lr_dict_loads(self):
        from raven.ml.inference import InferenceEngine
        from raven.ml.features import FeatureVector
        cands = _pick(self.versions, arch="logistic_regression", task="task_b")
        if not cands or not os.path.exists(_abs_version(cands[0]).weights_path):
            self.skipTest("task_b LR artifact not present")
        engine = InferenceEngine(_abs_version(cands[0]))
        result = engine.predict(FeatureVector(status_code=403, status_class=4))
        self.assertTrue(0.0 <= result.probability <= 1.0)


@unittest.skipUnless(_SKLEARN, "scikit-learn / numpy / joblib not installed")
@unittest.skipUnless(_HAS_REGISTRY, "models/registry.json not present")
class AdvisoryInvariantTest(unittest.TestCase):
    """ML may rank/classify/estimate but can NEVER verify or authorize."""

    @classmethod
    def setUpClass(cls):
        cls.reg = _load_registry()
        cls.versions = cls.reg.list_versions()

    def _multiclass_result(self):
        from raven.ml.inference import InferenceEngine
        from raven.network_fundamentals.features import NetworkFeatureVector
        cands = _pick(self.versions, arch="random_forest_multiclass", schema="net_v3")
        mv = _abs_version(cands[0])
        if not os.path.exists(mv.weights_path):
            self.skipTest("multiclass artifact not present")
        engine = InferenceEngine(mv)
        return engine.predict(NetworkFeatureVector(status_code=200, status_class=2, is_2xx=1))

    def test_multiclass_result_is_advisory_only(self):
        r = self._multiclass_result()
        self.assertTrue(r.is_advisory)
        self.assertFalse(r.sets_verification_status)

    def test_result_cannot_verify_or_authorize(self):
        r = self._multiclass_result()
        # No field on an advisory result may carry a verification/authorization verdict.
        for forbidden in ("verification_status", "is_confirmed_vulnerability",
                          "ground_truth", "authorize", "authorized", "verified"):
            self.assertFalse(hasattr(r, forbidden),
                             f"InferenceResult must not expose {forbidden!r}")

    def test_result_is_frozen(self):
        r = self._multiclass_result()
        with self.assertRaises(Exception):
            r.sets_verification_status = True  # type: ignore[misc]
        with self.assertRaises(Exception):
            r.predicted_triage_class = "verified"  # type: ignore[misc]


@unittest.skipUnless(_HAS_REGISTRY, "models/registry.json not present")
class DeterministicRegistryOrderingTest(unittest.TestCase):
    """Registry versions are ordered deterministically; no auto-promotion."""

    def test_list_versions_is_deterministic_and_sorted(self):
        reg = _load_registry()
        once = [v.model_id for v in reg.list_versions()]
        twice = [v.model_id for v in _load_registry().list_versions()]
        self.assertEqual(once, twice, "ordering must be stable across loads")
        expected = sorted(reg.list_versions(),
                          key=lambda v: (v.timestamp_utc, v.model_id))
        self.assertEqual(once, [v.model_id for v in expected],
                         "must be sorted by (timestamp_utc, model_id)")

    def test_tie_break_by_model_id_regardless_of_insertion_order(self):
        from raven.ml.registry import ModelRegistry, ModelVersion, ModelStatus
        from raven.ml.features import FEATURE_SCHEMA_VERSION

        def mk(model_id):
            return ModelVersion(
                model_id=model_id, task="task_a", architecture="logistic_regression",
                status=ModelStatus.DEVELOPMENT, weights_path="fake.pkl",
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                timestamp_utc="2026-10-03T00:00:00Z",  # identical timestamps
            )

        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            r1 = ModelRegistry(os.path.join(d1, "reg.json"))
            for mid in ("m_c", "m_a", "m_b"):
                r1.register(mk(mid))
            r2 = ModelRegistry(os.path.join(d2, "reg.json"))
            for mid in ("m_a", "m_b", "m_c"):   # different insertion order
                r2.register(mk(mid))
            self.assertEqual([v.model_id for v in r1.list_versions()],
                             [v.model_id for v in r2.list_versions()])
            self.assertEqual([v.model_id for v in r1.list_versions()],
                             ["m_a", "m_b", "m_c"])

    def test_no_production_model_returns_none(self):
        """0 PRODUCTION in the real registry → get_production_model / from_registry None."""
        from raven.ml.inference import InferenceEngine
        reg = _load_registry()
        for task in ("task_a", "task_b", "net_a", "net_b", "net_c", "net_d"):
            self.assertIsNone(reg.get_production_model(task),
                              f"{task}: no DEVELOPMENT model may be auto-promoted")
            self.assertIsNone(InferenceEngine.from_registry(reg, task),
                              f"{task}: from_registry must be None without PRODUCTION")

    def test_all_registered_versions_remain_development(self):
        reg = _load_registry()
        from raven.ml.registry import ModelStatus
        versions = reg.list_versions()
        self.assertGreater(len(versions), 0)
        self.assertTrue(all(v.status == ModelStatus.DEVELOPMENT for v in versions),
                        "every registered version must stay DEVELOPMENT (0 PRODUCTION)")


if __name__ == "__main__":
    unittest.main()
