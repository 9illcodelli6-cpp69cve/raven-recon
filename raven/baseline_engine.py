"""Baseline engine: eligibility policy, Welford statistics, anomaly scoring.

Design reference: 06_RESPONSE_ANALYSIS_DESIGN.md (amendment 4)

INVARIANT: BaselineStore is updated ONLY for observations that pass
BaselineEligibilityPolicy.is_eligible().  Probe, ACL test, XSS test, and
anomalous observations are ALWAYS ineligible.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Optional

from .response_analysis import ResponseRepr

MIN_SAMPLES = 5


# ---------------------------------------------------------------------------
# Observation eligibility stub (schema fields; full model is in store.py)
# ---------------------------------------------------------------------------

@dataclass
class ObservationEligibility:
    """Minimal view of Observation fields required for eligibility check."""
    acquisition_mode: str = "collect"
    is_probe: bool = False
    is_anomalous: bool = False
    baseline_approved: bool = False


# ---------------------------------------------------------------------------
# BaselineEligibilityPolicy
# ---------------------------------------------------------------------------

class BaselineEligibilityPolicy:
    """Controls which Observation rows may be incorporated into a baseline.

    Eligible acquisition modes require explicit researcher authorization.
    Probe, anomalous, and unapproved observations are always ineligible.
    """

    ELIGIBLE_MODES = frozenset({"baseline_acquisition", "reference_observation"})

    def is_eligible(self, obs: ObservationEligibility) -> bool:
        return (
            obs.acquisition_mode in self.ELIGIBLE_MODES
            and not obs.is_probe
            and not obs.is_anomalous
            and obs.baseline_approved
        )


_POLICY = BaselineEligibilityPolicy()


# ---------------------------------------------------------------------------
# Welford online statistics
# ---------------------------------------------------------------------------

def welford_update(count: int, mean: float, m2: float, value: float):
    count += 1
    delta = value - mean
    mean += delta / count
    delta2 = value - mean
    m2 += delta * delta2
    return count, mean, m2


def welford_variance(count: int, m2: float) -> Optional[float]:
    return m2 / (count - 1) if count >= 2 else None


# ---------------------------------------------------------------------------
# AnomalyScorer
# ---------------------------------------------------------------------------

ANOMALY_THRESHOLD = 0.65  # composite score above this → is_anomalous=True

WEIGHTS = {"body_len": 0.40, "timing": 0.30, "status": 0.20, "headers": 0.10}


def z_score_anomaly(value: float, mean: float, variance: Optional[float], sample_count: int) -> float:
    if sample_count < MIN_SAMPLES:
        return 0.5
    if variance is None or variance < 1e-9:
        # stdev ≈ 0 — fixed per blueprint: return 0.8 not 1.0
        return 0.0 if abs(value - mean) < 1e-9 else 0.8
    z = abs(value - mean) / math.sqrt(variance)
    return min(1.0, z / 4.0)


def status_anomaly(status: int, status_counts: dict, sample_count: int) -> float:
    if sample_count < MIN_SAMPLES:
        return 0.5
    total = sum(status_counts.values())
    seen = status_counts.get(str(status), 0)
    rate = seen / total if total > 0 else 0.0
    return 1.0 - rate


def header_fingerprint(headers: dict) -> frozenset:
    skip = {"date", "set-cookie", "content-length"}
    return frozenset(
        f"{k.lower()}:{v.lower()[:64]}"
        for k, v in headers.items()
        if k.lower() not in skip
    )


def header_anomaly(obs_fp: frozenset, baseline_fp_counts: dict, sample_count: int) -> float:
    if sample_count < MIN_SAMPLES:
        return 0.5
    baseline_keys = frozenset(
        k for k, v in baseline_fp_counts.items()
        if sample_count > 0 and v / sample_count > 0.5
    )
    union = obs_fp | baseline_keys
    if not union:
        return 0.0
    return 1.0 - len(obs_fp & baseline_keys) / len(union)


def composite_anomaly(body_score: float, timing_score: float,
                      status_score: float, header_score: float) -> float:
    return (
        body_score * WEIGHTS["body_len"]
        + timing_score * WEIGHTS["timing"]
        + status_score * WEIGHTS["status"]
        + header_score * WEIGHTS["headers"]
    )


@dataclass
class AnomalyResult:
    body_score: float
    timing_score: float
    status_score: float
    header_score: float
    composite: float
    is_anomalous: bool


def score_observation(
    obs_repr: ResponseRepr,
    baseline: dict,
) -> AnomalyResult:
    """Score an observation against a stored baseline record.

    baseline is a dict from the baseline_store table.
    """
    n = baseline.get("sample_count", 0)
    body_var = welford_variance(n, baseline.get("body_len_m2") or 0.0)
    timing_var = welford_variance(n, baseline.get("timing_m2") or 0.0)
    status_counts = json.loads(baseline.get("status_counts") or "{}")
    hfp_counts = json.loads(baseline.get("header_fp_counts") or "{}")
    b = z_score_anomaly(obs_repr.body_len, baseline.get("body_len_mean") or 0.0, body_var, n)
    t = z_score_anomaly(
        obs_repr.elapsed_ms or 0,
        baseline.get("timing_mean") or 0.0,
        timing_var,
        n,
    )
    s = status_anomaly(obs_repr.status, status_counts, n)
    h = header_anomaly(obs_repr.header_fingerprint, hfp_counts, n)
    c = composite_anomaly(b, t, s, h)
    return AnomalyResult(
        body_score=b,
        timing_score=t,
        status_score=s,
        header_score=h,
        composite=c,
        is_anomalous=(c > ANOMALY_THRESHOLD),
    )


# ---------------------------------------------------------------------------
# BaselineEngine (in-memory update logic; persistence is in store layer)
# ---------------------------------------------------------------------------

def update_baseline(baseline: dict, obs_repr: ResponseRepr) -> dict:
    """Return an updated baseline dict after incorporating one eligible observation.

    Does NOT check eligibility — caller must verify via BaselineEligibilityPolicy first.
    """
    n = baseline.get("sample_count", 0)
    body_mean = baseline.get("body_len_mean") or 0.0
    body_m2 = baseline.get("body_len_m2") or 0.0
    timing_mean = baseline.get("timing_mean") or 0.0
    timing_m2 = baseline.get("timing_m2") or 0.0
    status_counts = json.loads(baseline.get("status_counts") or "{}")
    hfp_counts = json.loads(baseline.get("header_fp_counts") or "{}")
    n_old = n
    n, body_mean, body_m2 = welford_update(n_old, body_mean, body_m2, obs_repr.body_len)
    timing_val = obs_repr.elapsed_ms or 0
    _, timing_mean, timing_m2 = welford_update(n_old, timing_mean, timing_m2, timing_val)
    sk = str(obs_repr.status)
    status_counts[sk] = status_counts.get(sk, 0) + 1
    for key in obs_repr.header_fingerprint:
        hfp_counts[key] = hfp_counts.get(key, 0) + 1
    return {
        **baseline,
        "sample_count": n,
        "body_len_mean": body_mean,
        "body_len_m2": body_m2,
        "timing_mean": timing_mean,
        "timing_m2": timing_m2,
        "status_counts": json.dumps(status_counts),
        "header_fp_counts": json.dumps(hfp_counts),
    }
