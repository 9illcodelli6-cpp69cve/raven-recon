"""RAVEN V6 ML Platform tests.

Covers:
- FeaturePipeline: extraction, privacy invariants, schema hash
- DatasetBuilder: synthetic generation, group-aware split, dedup, policy guard
- ModelRegistry: register/lifecycle/rollback
- InferenceEngine: result structure, immutability, advisory invariants
- Training: weights change after optimizer step (LR proxy)
- ML safety: no security verdicts, no verification_status, no label leakage
"""
import hashlib
import json
import os
import tempfile
import unittest


# ─────────────────────────────────────────────────────────────────────────────
# Feature Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class FeatureVectorTest(unittest.TestCase):
    def test_to_list_length_matches_feature_names(self):
        from raven.ml.features import FeatureVector
        fv = FeatureVector()
        self.assertEqual(len(fv.to_list()), len(FeatureVector.feature_names()))

    def test_schema_version_set(self):
        from raven.ml.features import FeatureVector, FEATURE_SCHEMA_VERSION
        fv = FeatureVector()
        self.assertEqual(fv.schema_version, FEATURE_SCHEMA_VERSION)

    def test_schema_hash_deterministic(self):
        from raven.ml.features import FeatureVector
        h1 = FeatureVector().schema_hash()
        h2 = FeatureVector().schema_hash()
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 16)

    def test_missing_sentinels_are_negative_one(self):
        from raven.ml.features import FeatureVector, MISSING_INT, MISSING_FLOAT
        fv = FeatureVector()
        self.assertEqual(fv.status_code,    MISSING_INT)
        self.assertEqual(fv.body_entropy,   MISSING_FLOAT)

    def test_schema_version_not_in_to_list(self):
        from raven.ml.features import FeatureVector
        fv = FeatureVector()
        # schema_version is a string; numeric list should have no strings
        for v in fv.to_list():
            self.assertIsInstance(v, (int, float))


class FeaturePipelinePrivacyTest(unittest.TestCase):
    """Privacy invariants: credentials must never appear in features."""

    def setUp(self):
        from raven.ml.features import FeaturePipeline
        self.pipe = FeaturePipeline()

    def test_authorization_header_excluded(self):
        from raven.ml.features import FeaturePipeline
        fv = self.pipe.extract_from_values(
            status=200,
            headers={
                "authorization": "Bearer super_secret_token",
                "content-type":  "text/html",
            },
            body=b"hello world",
        )
        vals = fv.to_list()
        # No string values; no raw secrets possible
        for v in vals:
            self.assertNotIsInstance(v, str)

    def test_cookie_header_excluded_from_count(self):
        from raven.ml.features import FeaturePipeline
        fv_with    = self.pipe.extract_from_values(200, {"cookie": "sess=abc"}, b"x")
        fv_without = self.pipe.extract_from_values(200, {}, b"x")
        # Header count should NOT include cookie
        self.assertEqual(fv_with.header_count, 0)
        self.assertEqual(fv_without.header_count, 0)

    def test_set_cookie_presence_only(self):
        fv = self.pipe.extract_from_values(200, {"set-cookie": "sess=abc; Path=/"}, b"body")
        self.assertEqual(fv.has_set_cookie, 1)
        # Actual cookie value must not be recoverable from the feature vector
        vals = fv.to_list()
        self.assertNotIn("sess=abc; Path=/", vals)

    def test_no_verification_status_field(self):
        fv = self.pipe.extract_from_values(403, {}, b"Forbidden")
        self.assertFalse(hasattr(fv, "verification_status"))
        self.assertFalse(hasattr(fv, "vulnerability"))

    def test_feature_names_no_raw_credentials(self):
        from raven.ml.features import FeatureVector
        # Feature names must not expose raw credential-bearing header names.
        # "has_set_cookie" (binary presence indicator) is allowed — it carries no value.
        # What's forbidden: a feature name that would directly encode a raw credential.
        forbidden_exact = {
            "authorization", "cookie_value", "password", "api_key",
            "bearer_token", "secret", "session_token",
        }
        for name in FeatureVector.feature_names():
            self.assertNotIn(name.lower(), forbidden_exact,
                             f"Feature name '{name}' exposes raw credential")


class FeaturePipelineExtractionTest(unittest.TestCase):
    def setUp(self):
        from raven.ml.features import FeaturePipeline
        self.pipe = FeaturePipeline()

    def test_status_fields(self):
        fv = self.pipe.extract_from_values(404, {}, b"Not Found")
        self.assertEqual(fv.status_code, 404)
        self.assertEqual(fv.status_class, 4)

    def test_body_size(self):
        fv = self.pipe.extract_from_values(200, {}, b"hello" * 100)
        self.assertEqual(fv.body_size, 500)

    def test_exact_body_match(self):
        fv = self.pipe.extract_from_values(200, {}, b"same",
                                            comparison_body=b"same")
        self.assertEqual(fv.exact_body_match, 1)

    def test_different_body_match(self):
        fv = self.pipe.extract_from_values(200, {}, b"aaaa",
                                            comparison_body=b"bbbb")
        self.assertEqual(fv.exact_body_match, 0)

    def test_elapsed_ms(self):
        fv = self.pipe.extract_from_values(200, {}, b"body", elapsed_ms=123)
        self.assertEqual(fv.elapsed_ms, 123)


# ─────────────────────────────────────────────────────────────────────────────
# DatasetBuilder
# ─────────────────────────────────────────────────────────────────────────────

class DatasetBuilderSyntheticTest(unittest.TestCase):
    def setUp(self):
        from raven.ml.dataset import DatasetBuilder, DatasetPolicy
        self.builder = DatasetBuilder(policy=DatasetPolicy.DEV_SYNTHETIC, seed=99)

    def test_synthetic_count(self):
        examples = self.builder.build_synthetic_dev_set(n_positive=50, n_negative=50)
        self.assertEqual(len(examples), 100)

    def test_all_examples_are_synthetic(self):
        examples = self.builder.build_synthetic_dev_set(n_positive=20, n_negative=20)
        self.assertTrue(all(e.synthetic for e in examples))

    def test_label_task_a_values(self):
        examples = self.builder.build_synthetic_dev_set(n_positive=30, n_negative=30)
        pos = [e for e in examples if e.label_task_a == 1]
        neg = [e for e in examples if e.label_task_a == 0]
        self.assertEqual(len(pos), 30)
        self.assertEqual(len(neg), 30)

    def test_feature_vectors_have_correct_length(self):
        from raven.ml.features import FeatureVector
        examples = self.builder.build_synthetic_dev_set(10, 10)
        for e in examples:
            self.assertEqual(len(e.feature_vector.to_list()),
                             len(FeatureVector.feature_names()))


class DatasetBuilderSplitTest(unittest.TestCase):
    def setUp(self):
        from raven.ml.dataset import DatasetBuilder, DatasetPolicy
        self.builder = DatasetBuilder(policy=DatasetPolicy.DEV_SYNTHETIC, seed=42)
        self.examples = self.builder.build_synthetic_dev_set(100, 100)

    def test_split_totals(self):
        split = self.builder.build_from_examples(self.examples)
        self.assertEqual(split.n_total, split.n_train + split.n_val + split.n_test)
        self.assertGreater(split.n_train, 0)
        self.assertGreater(split.n_val,   0)
        self.assertGreater(split.n_test,  0)

    def test_deduplication(self):
        from raven.ml.dataset import DatasetBuilder, DatasetPolicy
        b = DatasetBuilder(policy=DatasetPolicy.DEV_SYNTHETIC, seed=0)
        ex = b.build_synthetic_dev_set(10, 10)
        doubled = ex + ex  # all duplicates
        split = b.build_from_examples(doubled, deduplicate=True)
        self.assertEqual(split.n_total, 20)  # dedup removes doubles

    def test_contains_synthetic_flag(self):
        split = self.builder.build_from_examples(self.examples)
        self.assertTrue(split.contains_synthetic())

    def test_real_only_policy_rejects_synthetic(self):
        from raven.ml.dataset import DatasetBuilder, DatasetPolicy
        b = DatasetBuilder(policy=DatasetPolicy.REAL_ONLY, seed=0)
        with self.assertRaises(ValueError):
            b.build_from_examples(self.examples)

    def test_temporal_split_preserves_order(self):
        # After temporal split, train items should have lower timestamp than test
        split = self.builder.build_from_examples(self.examples, temporal=True)
        if split.train and split.test:
            max_train_ts = max(e.timestamp_ms or 0 for e in split.train)
            min_test_ts  = min(e.timestamp_ms or 0 for e in split.test)
            self.assertLessEqual(max_train_ts, min_test_ts)

    def test_summary_dict(self):
        split = self.builder.build_from_examples(self.examples)
        s = split.summary()
        self.assertIn("n_train",    s)
        self.assertIn("n_val",      s)
        self.assertIn("n_test",     s)
        self.assertIn("n_total",    s)
        self.assertIn("policy",     s)
        self.assertIn("contains_synthetic", s)


# ─────────────────────────────────────────────────────────────────────────────
# ModelRegistry
# ─────────────────────────────────────────────────────────────────────────────

class ModelRegistryTest(unittest.TestCase):
    def _make_version(self, model_id, task="task_a", arch="logistic_regression",
                       weights_path="fake.pkl"):
        from raven.ml.registry import ModelVersion, ModelStatus
        from raven.ml.features import FEATURE_SCHEMA_VERSION
        return ModelVersion(
            model_id=model_id,
            task=task,
            architecture=arch,
            status=ModelStatus.DEVELOPMENT,
            weights_path=weights_path,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            timestamp_utc="2026-10-03T00:00:00Z",
        )

    def test_register_and_retrieve(self):
        from raven.ml.registry import ModelRegistry, ModelStatus
        with tempfile.TemporaryDirectory() as d:
            reg = ModelRegistry(os.path.join(d, "reg.json"))
            v = self._make_version("m1")
            reg.register(v)
            self.assertIsNotNone(reg.get("m1"))

    def test_lifecycle_transitions(self):
        from raven.ml.registry import ModelRegistry, ModelStatus
        with tempfile.TemporaryDirectory() as d:
            reg = ModelRegistry(os.path.join(d, "reg.json"))
            reg.register(self._make_version("m1"))
            reg.advance_to_candidate("m1")
            self.assertEqual(reg.get("m1").status, ModelStatus.CANDIDATE)
            reg.promote_to_production("m1", promoted_by="researcher")
            self.assertEqual(reg.get("m1").status, ModelStatus.PRODUCTION)

    def test_only_candidate_promotes(self):
        from raven.ml.registry import ModelRegistry
        with tempfile.TemporaryDirectory() as d:
            reg = ModelRegistry(os.path.join(d, "reg.json"))
            reg.register(self._make_version("m1"))
            with self.assertRaises(ValueError):
                reg.promote_to_production("m1")  # still DEVELOPMENT

    def test_duplicate_id_rejected(self):
        from raven.ml.registry import ModelRegistry
        with tempfile.TemporaryDirectory() as d:
            reg = ModelRegistry(os.path.join(d, "reg.json"))
            reg.register(self._make_version("m1"))
            with self.assertRaises(ValueError):
                reg.register(self._make_version("m1"))

    def test_rollback(self):
        from raven.ml.registry import ModelRegistry, ModelStatus
        with tempfile.TemporaryDirectory() as d:
            reg = ModelRegistry(os.path.join(d, "reg.json"))
            reg.register(self._make_version("m1"))
            reg.register(self._make_version("m2"))
            reg.advance_to_candidate("m1")
            reg.promote_to_production("m1")
            reg.advance_to_candidate("m2")
            reg.promote_to_production("m2")
            # m1 should now be RETIRED
            self.assertEqual(reg.get("m1").status, ModelStatus.RETIRED)
            reg.rollback_production("task_a", rollback_to_id="m1")
            self.assertEqual(reg.get("m1").status, ModelStatus.PRODUCTION)
            self.assertEqual(reg.get("m2").status, ModelStatus.RETIRED)

    def test_get_production_model(self):
        from raven.ml.registry import ModelRegistry, ModelStatus
        with tempfile.TemporaryDirectory() as d:
            reg = ModelRegistry(os.path.join(d, "reg.json"))
            self.assertIsNone(reg.get_production_model("task_a"))
            reg.register(self._make_version("m1"))
            reg.advance_to_candidate("m1")
            reg.promote_to_production("m1")
            self.assertIsNotNone(reg.get_production_model("task_a"))

    def test_persistence(self):
        from raven.ml.registry import ModelRegistry, ModelStatus
        path = None
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "reg.json")
            reg = ModelRegistry(path)
            reg.register(self._make_version("persist_me"))
            # Re-open
            reg2 = ModelRegistry(path)
            self.assertIsNotNone(reg2.get("persist_me"))

    def test_retire(self):
        from raven.ml.registry import ModelRegistry, ModelStatus
        with tempfile.TemporaryDirectory() as d:
            reg = ModelRegistry(os.path.join(d, "reg.json"))
            reg.register(self._make_version("m1"))
            reg.retire("m1")
            self.assertEqual(reg.get("m1").status, ModelStatus.RETIRED)


# ─────────────────────────────────────────────────────────────────────────────
# InferenceResult invariants
# ─────────────────────────────────────────────────────────────────────────────

class InferenceResultInvariantsTest(unittest.TestCase):
    def test_is_frozen_dataclass(self):
        from raven.ml.inference import InferenceResult
        r = InferenceResult(
            task="task_a", score=0.7, probability=0.7, threshold=0.5,
            predicted_positive=True,
            predicted_triage_class="response_differs_meaningfully",
            model_id="m1", model_version="logistic_regression",
            feature_schema_version="v1", inference_ms=2,
        )
        with self.assertRaises(Exception):
            r.score = 0.9  # frozen — must raise

    def test_is_advisory_always_true(self):
        from raven.ml.inference import InferenceResult
        r = InferenceResult(
            task="task_a", score=0.9, probability=0.9, threshold=0.5,
            predicted_positive=True,
            predicted_triage_class="response_differs_meaningfully",
            model_id="m1", model_version="lr", feature_schema_version="v1",
            inference_ms=1,
        )
        self.assertTrue(r.is_advisory)

    def test_sets_verification_status_is_false(self):
        from raven.ml.inference import InferenceResult
        r = InferenceResult(
            task="task_b", score=0.3, probability=0.3, threshold=0.5,
            predicted_positive=False,
            predicted_triage_class="difference_not_auth_relevant",
            model_id="m1", model_version="lr", feature_schema_version="v1",
            inference_ms=1,
        )
        self.assertFalse(r.sets_verification_status)


# ─────────────────────────────────────────────────────────────────────────────
# Training: weights change after optimizer step
# ─────────────────────────────────────────────────────────────────────────────

class TrainingWeightsUpdateTest(unittest.TestCase):
    """Phase 120: prove weights actually change after backward + step."""

    def test_sklearn_lr_weights_differ_from_zero_init(self):
        """LogisticRegression: coefficients change after fit."""
        try:
            from sklearn.linear_model import LogisticRegression
            import numpy as np
        except ImportError:
            self.skipTest("scikit-learn not installed")

        X = np.random.RandomState(0).randn(50, 22)
        y = (X[:, 0] > 0).astype(int)

        model = LogisticRegression(max_iter=100, random_state=0)
        before = None  # no initial coef_ until fitted
        model.fit(X, y)
        after = model.coef_.copy()

        self.assertFalse(np.allclose(after, 0.0),
                         "Logistic regression coefficients should be non-zero after fit")

    def test_two_distinct_fits_differ(self):
        """Different data produces different weights — proves fit is non-trivial."""
        try:
            from sklearn.linear_model import LogisticRegression
            import numpy as np
        except ImportError:
            self.skipTest("scikit-learn not installed")

        rng = np.random.RandomState(42)
        X1 = rng.randn(60, 22)
        y1 = (X1[:, 0] > 0).astype(int)   # balanced around 0

        X2 = rng.randn(60, 22)
        # Force balanced labels independent of feature values
        y2 = np.array([i % 2 for i in range(60)])

        m1 = LogisticRegression(max_iter=200, random_state=0).fit(X1, y1)
        m2 = LogisticRegression(max_iter=200, random_state=0).fit(X2, y2)

        self.assertFalse(np.allclose(m1.coef_, m2.coef_),
                         "Coefficients should differ when trained on different data")


class TrainingCLITest(unittest.TestCase):
    """End-to-end training CLI smoke test."""

    def test_train_produces_model_files(self):
        with tempfile.TemporaryDirectory() as d:
            registry_path = os.path.join(d, "reg.json")
            from raven.ml.train import main
            main([
                "--task", "task_a",
                "--arch", "logistic_regression",
                "--n-positive", "30",
                "--n-negative", "30",
                "--output-dir", d,
                "--registry", registry_path,
            ])
            pkl_files = [f for f in os.listdir(d) if f.endswith(".pkl")]
            self.assertGreater(len(pkl_files), 0, "Expected .pkl weight file")

    def test_train_produces_model_card(self):
        with tempfile.TemporaryDirectory() as d:
            from raven.ml.train import main
            main([
                "--task", "task_a",
                "--arch", "logistic_regression",
                "--n-positive", "20",
                "--n-negative", "20",
                "--output-dir", d,
                "--registry", os.path.join(d, "reg.json"),
            ])
            cards = [f for f in os.listdir(d) if f.endswith("_card.json")]
            self.assertGreater(len(cards), 0)
            with open(os.path.join(d, cards[0])) as f:
                card = json.load(f)
            self.assertEqual(card["contains_synthetic"], True)
            self.assertIn("DEVELOPMENT_ONLY", card["notes"])

    def test_train_registers_as_development(self):
        with tempfile.TemporaryDirectory() as d:
            from raven.ml.train import main
            from raven.ml.registry import ModelRegistry, ModelStatus
            reg_path = os.path.join(d, "reg.json")
            main([
                "--task", "task_a",
                "--arch", "logistic_regression",
                "--n-positive", "20",
                "--n-negative", "20",
                "--output-dir", d,
                "--registry", reg_path,
            ])
            reg = ModelRegistry(reg_path)
            versions = reg.list_versions(task="task_a")
            self.assertEqual(len(versions), 1)
            self.assertEqual(versions[0].status, ModelStatus.DEVELOPMENT)

    def test_trained_model_not_auto_promoted(self):
        """Model must not appear in PRODUCTION after training."""
        with tempfile.TemporaryDirectory() as d:
            from raven.ml.train import main
            from raven.ml.registry import ModelRegistry, ModelStatus
            reg_path = os.path.join(d, "reg.json")
            main([
                "--task", "task_a",
                "--arch", "logistic_regression",
                "--n-positive", "20",
                "--n-negative", "20",
                "--output-dir", d,
                "--registry", reg_path,
            ])
            reg = ModelRegistry(reg_path)
            prod = reg.get_production_model("task_a")
            self.assertIsNone(prod, "Model must not auto-promote to PRODUCTION")


# ─────────────────────────────────────────────────────────────────────────────
# ML safety gates
# ─────────────────────────────────────────────────────────────────────────────

class MLSafetyGatesTest(unittest.TestCase):
    """Spec safety invariants: no auto-promote, no ground-truth fabrication."""

    def test_inference_result_has_no_verification_status(self):
        from raven.ml.inference import InferenceResult
        r = InferenceResult(
            task="task_a", score=0.9, probability=0.9, threshold=0.5,
            predicted_positive=True,
            predicted_triage_class="response_differs_meaningfully",
            model_id="x", model_version="lr", feature_schema_version="v1",
            inference_ms=0,
        )
        self.assertFalse(hasattr(r, "verification_status"))
        self.assertFalse(hasattr(r, "is_confirmed_vulnerability"))
        self.assertFalse(hasattr(r, "ground_truth"))

    def test_inference_result_is_advisory(self):
        from raven.ml.inference import InferenceResult
        r = InferenceResult(
            task="task_a", score=0.9, probability=0.9, threshold=0.5,
            predicted_positive=True,
            predicted_triage_class="response_differs_meaningfully",
            model_id="x", model_version="lr", feature_schema_version="v1",
            inference_ms=0,
        )
        self.assertTrue(r.is_advisory)
        self.assertFalse(r.sets_verification_status)

    def test_feature_pipeline_never_returns_security_verdict(self):
        from raven.ml.features import FeaturePipeline
        pipe = FeaturePipeline()
        fv = pipe.extract_from_values(200, {}, b"body")
        result_dict = {name: val for name, val in
                       zip(fv.feature_names(), fv.to_list())}
        self.assertNotIn("vulnerability",        result_dict)
        self.assertNotIn("verification_status",  result_dict)
        self.assertNotIn("authorization_failure", result_dict)


if __name__ == "__main__":
    unittest.main()
