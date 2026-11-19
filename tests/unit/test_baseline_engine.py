"""Stage 4: Baseline engine tests.

Tests Welford online statistics, AnomalyScorer, update_baseline, and the
stdev=0 → 0.8 (not 1.0) fix documented in the blueprint.
"""
import json
import math
import pytest

from raven.baseline_engine import (
    welford_update,
    welford_variance,
    z_score_anomaly,
    status_anomaly,
    header_anomaly,
    composite_anomaly,
    update_baseline,
    score_observation,
    AnomalyResult,
    ANOMALY_THRESHOLD,
    MIN_SAMPLES,
)
from raven.response_analysis import ResponseRepr


def _repr(status=200, body=b"hello", elapsed_ms=100, headers=None):
    h = headers or {"content-type": "text/html"}
    return ResponseRepr.from_raw(
        status=status, raw_headers=h, raw_body=body, elapsed_ms=elapsed_ms
    )


def _blank_baseline():
    return {
        "sample_count": 0,
        "body_len_mean": 0.0,
        "body_len_m2": 0.0,
        "timing_mean": 0.0,
        "timing_m2": 0.0,
        "status_counts": "{}",
        "header_fp_counts": "{}",
    }


class TestWelfordUpdate:

    def test_single_sample_mean(self):
        n, mean, m2 = welford_update(0, 0.0, 0.0, 10.0)
        assert n == 1
        assert mean == pytest.approx(10.0)
        assert m2 == pytest.approx(0.0)

    def test_two_samples_mean(self):
        n, mean, m2 = welford_update(0, 0.0, 0.0, 4.0)
        n, mean, m2 = welford_update(n, mean, m2, 8.0)
        assert n == 2
        assert mean == pytest.approx(6.0)

    def test_variance_two_samples(self):
        n, mean, m2 = welford_update(0, 0.0, 0.0, 2.0)
        n, mean, m2 = welford_update(n, mean, m2, 8.0)
        var = welford_variance(n, m2)
        assert var == pytest.approx(18.0)  # (2-5)^2 + (8-5)^2 / 1 = 18

    def test_variance_single_sample_is_none(self):
        n, mean, m2 = welford_update(0, 0.0, 0.0, 7.0)
        assert welford_variance(n, m2) is None

    def test_equal_samples_variance_zero(self):
        n, mean, m2 = 0, 0.0, 0.0
        for _ in range(5):
            n, mean, m2 = welford_update(n, mean, m2, 100.0)
        var = welford_variance(n, m2)
        assert var is not None and var < 1e-9

    def test_matches_numpy_variance(self):
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        n, mean, m2 = 0, 0.0, 0.0
        for v in values:
            n, mean, m2 = welford_update(n, mean, m2, v)
        var = welford_variance(n, m2)
        expected_var = sum((x - 30.0) ** 2 for x in values) / 4.0  # sample variance
        assert var == pytest.approx(expected_var)


class TestZScoreAnomaly:

    def test_insufficient_samples_returns_half(self):
        for n in range(MIN_SAMPLES):
            score = z_score_anomaly(999.0, 0.0, None, n)
            assert score == pytest.approx(0.5)

    def test_on_mean_returns_zero(self):
        score = z_score_anomaly(100.0, 100.0, 25.0, MIN_SAMPLES)
        assert score == pytest.approx(0.0)

    def test_stdev_zero_same_value_returns_zero(self):
        # Blueprint fix: stdev≈0, same value → 0.0
        score = z_score_anomaly(100.0, 100.0, 0.0, MIN_SAMPLES)
        assert score == pytest.approx(0.0)

    def test_stdev_zero_different_value_returns_0_8_not_1_0(self):
        # Critical blueprint fix: stdev≈0 + different value → 0.8 (not 1.0)
        score = z_score_anomaly(200.0, 100.0, 0.0, MIN_SAMPLES)
        assert score == pytest.approx(0.8)
        assert score != pytest.approx(1.0)

    def test_capped_at_one(self):
        # z-score of 100 should cap at 1.0
        score = z_score_anomaly(100000.0, 0.0, 1.0, MIN_SAMPLES)
        assert score == pytest.approx(1.0)

    def test_moderate_deviation(self):
        # value at 2 stdev → z=2, score = 2/4 = 0.5
        score = z_score_anomaly(20.0, 10.0, 25.0, MIN_SAMPLES)
        assert score == pytest.approx(0.5)


class TestStatusAnomaly:

    def test_insufficient_samples_returns_half(self):
        score = status_anomaly(200, {"200": 3}, MIN_SAMPLES - 1)
        assert score == pytest.approx(0.5)

    def test_always_seen_status_returns_zero(self):
        counts = {"200": MIN_SAMPLES}
        score = status_anomaly(200, counts, MIN_SAMPLES)
        assert score == pytest.approx(0.0)

    def test_never_seen_status_returns_one(self):
        counts = {"200": MIN_SAMPLES}
        score = status_anomaly(404, counts, MIN_SAMPLES)
        assert score == pytest.approx(1.0)

    def test_partial_seen(self):
        counts = {"200": 4, "500": 1}
        score = status_anomaly(200, counts, MIN_SAMPLES)
        assert 0.0 < score < 1.0


class TestHeaderAnomaly:

    def test_insufficient_samples_returns_half(self):
        fp = frozenset({"content-type:text/html"})
        score = header_anomaly(fp, {}, MIN_SAMPLES - 1)
        assert score == pytest.approx(0.5)

    def test_identical_headers_returns_zero(self):
        key = "content-type:text/html"
        fp = frozenset({key})
        counts = {key: MIN_SAMPLES}
        score = header_anomaly(fp, counts, MIN_SAMPLES)
        assert score == pytest.approx(0.0)

    def test_completely_new_headers_high_anomaly(self):
        key = "x-custom:value"
        fp = frozenset({key})
        counts = {}
        score = header_anomaly(fp, counts, MIN_SAMPLES)
        assert score > 0.5

    def test_empty_fp_and_empty_counts(self):
        score = header_anomaly(frozenset(), {}, MIN_SAMPLES)
        assert score == pytest.approx(0.0)


class TestCompositeAnomaly:

    def test_all_zero_gives_zero(self):
        assert composite_anomaly(0.0, 0.0, 0.0, 0.0) == pytest.approx(0.0)

    def test_all_one_gives_one(self):
        assert composite_anomaly(1.0, 1.0, 1.0, 1.0) == pytest.approx(1.0)

    def test_weights_sum_to_one(self):
        from raven.baseline_engine import WEIGHTS
        assert sum(WEIGHTS.values()) == pytest.approx(1.0)

    def test_body_weight_dominates(self):
        # body=1, rest=0 should give 0.40
        assert composite_anomaly(1.0, 0.0, 0.0, 0.0) == pytest.approx(0.40)


class TestUpdateBaseline:

    def test_first_update_increments_count(self):
        obs = _repr()
        b = update_baseline(_blank_baseline(), obs)
        assert b["sample_count"] == 1

    def test_body_len_mean_recorded(self):
        body = b"x" * 200
        obs = _repr(body=body)
        b = update_baseline(_blank_baseline(), obs)
        assert b["body_len_mean"] == pytest.approx(200.0)

    def test_timing_mean_recorded(self):
        obs = _repr(elapsed_ms=250)
        b = update_baseline(_blank_baseline(), obs)
        assert b["timing_mean"] == pytest.approx(250.0)

    def test_status_counts_updated(self):
        obs = _repr(status=200)
        b = update_baseline(_blank_baseline(), obs)
        counts = json.loads(b["status_counts"])
        assert counts["200"] == 1

    def test_two_different_bodies_mean(self):
        obs1 = _repr(body=b"x" * 100)
        obs2 = _repr(body=b"x" * 300)
        b = _blank_baseline()
        b = update_baseline(b, obs1)
        b = update_baseline(b, obs2)
        assert b["body_len_mean"] == pytest.approx(200.0)

    def test_variance_grows_with_spread(self):
        b = _blank_baseline()
        for val in [100, 200, 300, 400, 500]:
            b = update_baseline(b, _repr(body=b"x" * val))
        var = welford_variance(b["sample_count"], b["body_len_m2"])
        assert var is not None and var > 0

    def test_idempotent_baseline_dict_keys(self):
        obs = _repr()
        b = update_baseline(_blank_baseline(), obs)
        required = {"sample_count", "body_len_mean", "body_len_m2",
                    "timing_mean", "timing_m2", "status_counts", "header_fp_counts"}
        assert required.issubset(b.keys())


class TestScoreObservation:

    def _baseline_with_n(self, n, body_mean=100.0, timing_mean=100.0):
        b = _blank_baseline()
        for _ in range(n):
            b = update_baseline(b, _repr(body=b"x" * int(body_mean), elapsed_ms=int(timing_mean)))
        return b

    def test_returns_anomaly_result(self):
        b = self._baseline_with_n(MIN_SAMPLES)
        obs = _repr()
        r = score_observation(obs, b)
        assert isinstance(r, AnomalyResult)

    def test_normal_observation_not_anomalous(self):
        b = self._baseline_with_n(MIN_SAMPLES, body_mean=100, timing_mean=100)
        obs = _repr(body=b"x" * 100, elapsed_ms=100)
        r = score_observation(obs, b)
        assert r.is_anomalous is False

    def test_insufficient_samples_returns_half_scores(self):
        b = self._baseline_with_n(MIN_SAMPLES - 1)
        obs = _repr()
        r = score_observation(obs, b)
        # All sub-scores should be 0.5 (insufficient samples)
        assert r.body_score == pytest.approx(0.5)
        assert r.timing_score == pytest.approx(0.5)

    def test_wildly_different_body_len_is_anomalous(self):
        b = self._baseline_with_n(MIN_SAMPLES, body_mean=100)
        obs = _repr(body=b"x" * 50000, elapsed_ms=100)
        r = score_observation(obs, b)
        assert r.body_score > 0.5

    def test_composite_within_range(self):
        b = self._baseline_with_n(MIN_SAMPLES)
        obs = _repr()
        r = score_observation(obs, b)
        assert 0.0 <= r.composite <= 1.0

    def test_is_anomalous_threshold(self):
        # Verify is_anomalous respects ANOMALY_THRESHOLD
        b = self._baseline_with_n(MIN_SAMPLES)
        obs = _repr()
        r = score_observation(obs, b)
        expected = r.composite > ANOMALY_THRESHOLD
        assert r.is_anomalous == expected
