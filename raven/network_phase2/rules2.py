"""RAVEN Network Phase II — Deterministic rule classifiers.

Rule-first approach: build deterministic rules before considering ML.
Rules encode protocol semantics, not pattern-matching on training labels.

INVARIANTS:
- Rules are deterministic — same input → same output.
- UNKNOWN is a valid and correct output when evidence is insufficient.
- Security authority: NONE — rules never produce security conclusions.
"""
from __future__ import annotations

from raven.network_fundamentals.observation import NetworkObservation
from raven.network_phase2.sequence import ObservationSequence
from raven.network_phase2.experiment import ControlledExperiment, compute_changed_dimensions
from raven.network_phase2.taxonomy2 import (
    StateTransitionClass, ExperimentQualityClass, CausalSupportClass,
    NextObservationType, CausalHypothesis,
)


# ── NET-E: State Transition Reasoning ─────────────────────────────────────────

def rule_net_e(seq: ObservationSequence) -> str:
    """Classify the primary state transition in an observation sequence.

    Uses the FIRST and LAST observations for the overall transition.
    For multi-step sequences, the dominant transition wins.
    Returns UNKNOWN when evidence is insufficient.
    """
    if len(seq) < 2:
        return StateTransitionClass.UNKNOWN.value

    first = seq.first()
    last  = seq.last()
    if first is None or last is None:
        return StateTransitionClass.UNKNOWN.value

    f_obs = first.observation
    l_obs = last.observation
    f_resp = f_obs.response
    l_resp = l_obs.response

    if f_resp is None or l_resp is None:
        return StateTransitionClass.UNKNOWN.value

    f_status = f_resp.status
    l_status = l_resp.status
    f_auth   = f_obs.has_auth_header
    l_auth   = l_obs.has_auth_header
    f_cookie = f_resp.has_set_cookie   # first response set-cookie
    l_cookie = l_resp.has_set_cookie   # last response set-cookie

    # ── 1. Error recovery (most specific, check first) ─────────────────────────
    if (f_status >= 500 or f_resp.timed_out or f_resp.connection_error) and 200 <= l_status < 300:
        return StateTransitionClass.TRANSIENT_RECOVERY.value

    if f_status == 429 and 200 <= l_status < 300:
        return StateTransitionClass.RATE_LIMIT_RECOVERY.value

    # ── 2. Cache transitions ────────────────────────────────────────────────────
    if l_status == 304:
        return StateTransitionClass.CACHE_VALIDATED.value

    if f_status == 304 and 200 <= l_status < 300:
        return StateTransitionClass.CACHE_INVALIDATED.value

    # ── 3. Session / auth transitions (before redirect: logins use 302) ────────

    # SESSION_CREATED: anonymous start (no auth, no first-response cookie) → new cookie
    if not f_auth and not f_cookie and l_cookie and 200 <= l_status < 300:
        return StateTransitionClass.SESSION_CREATED.value

    # SESSION_ROTATED: first response already carried a Set-Cookie, last also does
    if l_cookie and 200 <= l_status < 300:
        return StateTransitionClass.SESSION_ROTATED.value

    # AUTH_ESTABLISHED: 401 challenge → authenticated success on same path
    if f_status == 401 and l_auth and 200 <= l_status < 300 and f_obs.path == l_obs.path:
        return StateTransitionClass.AUTH_ESTABLISHED.value

    # AUTH_LOST / SESSION_EXPIRED: had auth+success, now 401
    if f_auth and 200 <= f_status < 300 and l_status == 401:
        for oo in seq.observations:
            if "logout" in oo.observation.path.lower():
                return StateTransitionClass.AUTH_LOST.value
        return StateTransitionClass.SESSION_EXPIRED.value

    # AUTH_LOST: auth disappeared without 401 (de-auth after explicit logout)
    if f_auth and not l_auth and 200 <= l_status < 300 and not l_cookie:
        return StateTransitionClass.AUTH_LOST.value

    # ── 4. Redirect transitions (after session/auth checks) ────────────────────
    if 300 <= f_status < 400 and 200 <= l_status < 300:
        return StateTransitionClass.REDIRECT_FOLLOWED.value

    # ── 5. Resource state changes ────────────────────────────────────────────────
    resource_created  = (f_status == 404 and 200 <= l_status < 300)
    resource_deleted  = (200 <= f_status < 300 and l_status == 404)
    resource_modified = (200 <= f_status < 300 and 200 <= l_status < 300 and
                         f_resp.body != l_resp.body and len(seq) >= 3)
    if resource_created or resource_deleted or resource_modified:
        return StateTransitionClass.RESOURCE_STATE_CHANGED.value

    # ── 6. No change ─────────────────────────────────────────────────────────────
    if f_status == l_status and f_resp.body == l_resp.body:
        return StateTransitionClass.NO_STATE_CHANGE.value

    return StateTransitionClass.UNKNOWN.value


# ── NET-F: Experiment Quality ──────────────────────────────────────────────────

def rule_net_f(exp: ControlledExperiment) -> str:
    """Classify experiment quality from a ControlledExperiment."""
    # Ensure dimensions computed
    if not exp.changed_dimensions and not exp.unchanged_dimensions:
        exp.classify()

    n = len(exp.changed_dimensions)
    c_resp = exp.control.response
    t_resp = exp.test.response

    if n == 0:
        if c_resp and t_resp and c_resp.status == t_resp.status and c_resp.body == t_resp.body:
            if 200 <= c_resp.status < 300:
                return ExperimentQualityClass.NO_MEANINGFUL_CHANGE.value
            return ExperimentQualityClass.INSUFFICIENT_CONTEXT.value
        return ExperimentQualityClass.INSUFFICIENT_CONTEXT.value
    if n == 1:
        return ExperimentQualityClass.CONTROLLED_SINGLE_VARIABLE.value
    return ExperimentQualityClass.CONFOUNDED.value


# ── NET-G: Causal Support ──────────────────────────────────────────────────────

def rule_net_g(exp: ControlledExperiment) -> str:
    """Classify causal support for the experiment's stated hypothesis."""
    if not exp.changed_dimensions and not exp.unchanged_dimensions:
        exp.classify()
    return exp.support.value if exp.support else CausalSupportClass.UNKNOWN.value


# ── NET-H: Next Best Observation ──────────────────────────────────────────────

def rule_net_h(exp: ControlledExperiment) -> str:
    """Recommend the next best safe observation to reduce uncertainty."""
    if not exp.changed_dimensions and not exp.unchanged_dimensions:
        exp.classify()
    return exp.next_obs.value if exp.next_obs else NextObservationType.UNKNOWN.value


# ── Convenience: apply rules to Phase2Fixture ─────────────────────────────────

def classify_fixture(fixture) -> dict[str, str]:
    """Apply all applicable rules to a Phase2Fixture.

    Returns dict with net_e/f/g/h predictions.
    """
    preds: dict[str, str] = {}
    if fixture.sequence is not None:
        preds["net_e"] = rule_net_e(fixture.sequence)
    if fixture.experiment is not None:
        preds["net_f"] = rule_net_f(fixture.experiment)
        preds["net_g"] = rule_net_g(fixture.experiment)
        preds["net_h"] = rule_net_h(fixture.experiment)
    return preds
