"""RAVEN Network Phase II — Controlled experiment model and causal reasoning.

Implements ControlledExperiment, dimension counting, and the causal
hypothesis taxonomy.

CRITICAL:
  AUTHENTICATION_DEPENDENCY_SUPPORTED != AUTH_BYPASS.
  OWNER/NONOWNER difference != IDOR.
  Origin difference != CORS vulnerability.
  Security authority: NONE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from raven.network_fundamentals.observation import NetworkObservation
from raven.network_phase2.taxonomy2 import (
    CausalHypothesis, CausalSupportClass, ExperimentQualityClass,
    NextObservationType, REQUEST_DIMENSIONS,
)


# ── Changed-dimension detection ────────────────────────────────────────────────

@dataclass
class RequestDimensions:
    """Parsed observable request dimensions for comparison."""
    method: str
    path: str
    query: str
    has_auth: bool
    has_cookie: bool    # presence signal
    accept: str
    content_type: str
    language: str

    @classmethod
    def from_observation(cls, obs: NetworkObservation) -> "RequestDimensions":
        req_h = {k.lower(): v for k, v in obs.request_headers.items()}
        return cls(
            method       = obs.method.upper(),
            path         = obs.path,
            query        = obs.query_string,
            has_auth     = obs.has_auth_header,
            has_cookie   = "cookie" in req_h,
            accept       = req_h.get("accept", ""),
            content_type = req_h.get("content-type", ""),
            language     = req_h.get("accept-language", ""),
        )


def compute_changed_dimensions(control: NetworkObservation,
                                test: NetworkObservation) -> list[str]:
    """Compute which request dimensions changed between control and test.

    Returns a sorted list of changed dimension names from REQUEST_DIMENSIONS.
    Order is deterministic (sorted).
    """
    c = RequestDimensions.from_observation(control)
    t = RequestDimensions.from_observation(test)
    changed: list[str] = []
    if c.method       != t.method:       changed.append("method_changed")
    if c.path         != t.path:         changed.append("path_changed")
    if c.query        != t.query:        changed.append("query_changed")
    if c.has_auth     != t.has_auth:     changed.append("authorization_changed")
    if c.has_cookie   != t.has_cookie:   changed.append("cookie_changed")
    if c.accept       != t.accept:       changed.append("accept_changed")
    if c.content_type != t.content_type: changed.append("content_type_changed")
    if c.language     != t.language:     changed.append("language_changed")
    return sorted(changed)


# ── Controlled experiment ──────────────────────────────────────────────────────

@dataclass
class ControlledExperiment:
    """A comparison between a control and test observation.

    Classifies experiment quality (NET-F) and evaluates causal
    support for a stated hypothesis (NET-G).

    Critical: classification ≠ security claim.
    """
    experiment_id: str
    control: NetworkObservation
    test: NetworkObservation
    hypothesis: CausalHypothesis = CausalHypothesis.UNKNOWN
    scenario_family: str = ""
    data_source: str = "EDUCATIONAL_SYNTHETIC"

    # Derived (populated by classify())
    changed_dimensions:   list[str] = field(default_factory=list)
    unchanged_dimensions: list[str] = field(default_factory=list)
    quality:     ExperimentQualityClass  = ExperimentQualityClass.UNKNOWN
    support:     CausalSupportClass      = CausalSupportClass.UNKNOWN
    next_obs:    NextObservationType     = NextObservationType.UNKNOWN
    limitations: list[str]              = field(default_factory=list)

    # Phase II labels (set by lab2 for training)
    net_f_label: Optional[str] = None
    net_g_label: Optional[str] = None
    net_h_label: Optional[str] = None

    def classify(self) -> "ControlledExperiment":
        """Populate quality, support, next_obs from observations.
        Returns self for chaining.
        """
        self.changed_dimensions = compute_changed_dimensions(self.control, self.test)
        all_dims = set(REQUEST_DIMENSIONS)
        self.unchanged_dimensions = sorted(all_dims - set(self.changed_dimensions))

        n = len(self.changed_dimensions)
        c_resp = self.control.response
        t_resp = self.test.response

        # NET-F: Experiment quality
        if n == 0:
            if (c_resp and t_resp and c_resp.status == t_resp.status and
                    c_resp.body == t_resp.body):
                # Identical 2xx → well-designed but uninformative
                # Identical non-2xx → can't explain failure without more variation
                if 200 <= c_resp.status < 300:
                    self.quality = ExperimentQualityClass.NO_MEANINGFUL_CHANGE
                else:
                    self.quality = ExperimentQualityClass.INSUFFICIENT_CONTEXT
            else:
                self.quality = ExperimentQualityClass.INSUFFICIENT_CONTEXT
        elif n == 1:
            self.quality = ExperimentQualityClass.CONTROLLED_SINGLE_VARIABLE
        else:
            self.quality = ExperimentQualityClass.CONFOUNDED

        # NET-G: Causal support
        if self.quality == ExperimentQualityClass.CONFOUNDED:
            self.support = CausalSupportClass.CONFOUNDED
            self.limitations = [f"Changed: {', '.join(self.changed_dimensions)}"]
        elif self.quality == ExperimentQualityClass.NO_MEANINGFUL_CHANGE:
            self.support = CausalSupportClass.NOT_SUPPORTED
        elif self.quality == ExperimentQualityClass.INSUFFICIENT_CONTEXT:
            self.support = CausalSupportClass.INSUFFICIENT_EVIDENCE
        elif self.quality == ExperimentQualityClass.CONTROLLED_SINGLE_VARIABLE:
            self.support = _evaluate_single_variable_support(
                self.changed_dimensions[0], self.hypothesis, self.control, self.test)
        else:
            self.support = CausalSupportClass.UNKNOWN

        # NET-H: Next best observation
        self.next_obs = _recommend_next_observation(
            self.quality, self.changed_dimensions, self.hypothesis,
            self.control, self.test)

        return self


def _evaluate_single_variable_support(
    changed_dim: str,
    hypothesis: CausalHypothesis,
    control: NetworkObservation,
    test: NetworkObservation,
) -> CausalSupportClass:
    """Evaluate whether a single-variable change supports the stated hypothesis."""
    c_resp = control.response
    t_resp = test.response
    if c_resp is None or t_resp is None:
        return CausalSupportClass.INSUFFICIENT_EVIDENCE

    response_changed = (c_resp.status != t_resp.status or c_resp.body != t_resp.body)

    # authorization_changed covers both token-based auth and session tokens carried
    # in the Authorization header (e.g. Bearer), so it supports both hypotheses.
    dim_implied_hypotheses: dict[str, list[CausalHypothesis]] = {
        "authorization_changed": [
            CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
            CausalHypothesis.SESSION_DEPENDENCY_SUPPORTED,
        ],
        "cookie_changed":        [CausalHypothesis.SESSION_DEPENDENCY_SUPPORTED],
        "accept_changed":        [CausalHypothesis.CONTENT_NEGOTIATION_DEPENDENCY_SUPPORTED],
        "language_changed":      [CausalHypothesis.LOCALE_DEPENDENCY_SUPPORTED],
        "method_changed":        [CausalHypothesis.METHOD_DEPENDENCY_SUPPORTED],
        "path_changed":          [CausalHypothesis.RESOURCE_STATE_DEPENDENCY_SUPPORTED],
    }
    implied = dim_implied_hypotheses.get(changed_dim, [])

    if not response_changed:
        return CausalSupportClass.NOT_SUPPORTED

    if hypothesis == CausalHypothesis.UNKNOWN:
        return CausalSupportClass.WEAKLY_SUPPORTED

    if hypothesis in implied:
        return CausalSupportClass.SUPPORTED

    return CausalSupportClass.WEAKLY_SUPPORTED


def _recommend_next_observation(
    quality: ExperimentQualityClass,
    changed_dims: list[str],
    hypothesis: CausalHypothesis,
    control: NetworkObservation,
    test: NetworkObservation,
) -> NextObservationType:
    """Recommend the highest-information-gain safe next observation."""
    if quality == ExperimentQualityClass.CONTROLLED_SINGLE_VARIABLE:
        return NextObservationType.NO_OBSERVATION_NEEDED

    if quality == ExperimentQualityClass.NO_MEANINGFUL_CHANGE:
        return NextObservationType.REPEAT_SAME_OBSERVATION

    # Insufficient context (no dimensions changed, responses not identical):
    # pick the highest-information-gain safe observation.
    if quality == ExperimentQualityClass.INSUFFICIENT_CONTEXT and not changed_dims:
        c_resp = control.response
        t_resp = test.response
        # 304 → the conditional request header (If-None-Match) was the hidden variable
        if c_resp and t_resp and (c_resp.status == 304 or t_resp.status == 304):
            return NextObservationType.CHECK_CACHE_VALIDATOR
        return NextObservationType.COMPARE_WITH_AUTH_HEADER

    # Confounded: isolate the dimension most relevant to the stated hypothesis first.
    if len(changed_dims) > 1:
        if hypothesis == CausalHypothesis.METHOD_DEPENDENCY_SUPPORTED and \
                "method_changed" in changed_dims:
            return NextObservationType.ISOLATE_METHOD_VARIABLE
        if "authorization_changed" in changed_dims:
            return NextObservationType.COMPARE_WITHOUT_AUTH_HEADER
        if "cookie_changed" in changed_dims:
            return NextObservationType.ISOLATE_SESSION_VARIABLE
        if "method_changed" in changed_dims:
            return NextObservationType.ISOLATE_METHOD_VARIABLE

    c_resp = control.response
    t_resp = test.response
    if c_resp and t_resp:
        if c_resp.status in (301, 302, 303, 307, 308) or \
           t_resp.status in (301, 302, 303, 307, 308):
            return NextObservationType.CHECK_REDIRECT_CHAIN
        if c_resp.status == 304 or t_resp.status == 304:
            return NextObservationType.CHECK_CACHE_VALIDATOR

    return NextObservationType.KEEP_IDENTITY_CONSTANT
