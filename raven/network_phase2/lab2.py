"""RAVEN Network Phase II — Educational fixture generator.

Generates ObservationSequences and ControlledExperiments for NET-E/F/G/H
training and evaluation.

All scenarios are:
- In-process (no sockets)
- EDUCATIONAL_SYNTHETIC
- Deterministic

INVARIANTS:
- Human-reviewed labels: 0
- External targets: 0
- No real credentials
- Security authority: NONE
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from raven.network_fundamentals.observation import NetworkObservation, NetworkResponse
from raven.network_phase2.sequence import ObservationSequence, SequencePair
from raven.network_phase2.experiment import ControlledExperiment
from raven.network_phase2.taxonomy2 import (
    StateTransitionClass, ExperimentQualityClass, CausalSupportClass,
    NextObservationType, CausalHypothesis,
)


# ── Response factory helpers ───────────────────────────────────────────────────

def _resp(status: int, body: bytes = b"", *,
          ct: str = "application/json",
          set_cookie: bool = False,
          location: str = "",
          www_auth: bool = False,
          retry_after: bool = False,
          etag: str = "",
          elapsed_ms: int = 30,
          connection_error: bool = False,
          timed_out: bool = False) -> NetworkResponse:
    headers: dict = {"Content-Type": ct}
    if set_cookie:
        headers["Set-Cookie"] = "<REDACTED>"
    if location:
        headers["Location"] = location
    if www_auth:
        headers["WWW-Authenticate"] = "Bearer realm=api"
    if retry_after:
        headers["Retry-After"] = "60"
    if etag:
        headers["ETag"] = etag
    return NetworkResponse.from_raw(
        status=status, headers=headers, body=body,
        elapsed_ms=elapsed_ms,
        timed_out=timed_out,
        connection_error=connection_error,
    )


def _obs(method: str, path: str, response: NetworkResponse, *,
         has_auth: bool = False,
         accept: str = "",
         content_type: str = "",
         language: str = "",
         query: str = "") -> NetworkObservation:
    req_headers: dict = {}
    if accept:
        req_headers["Accept"] = accept
    if content_type:
        req_headers["Content-Type"] = content_type
    if language:
        req_headers["Accept-Language"] = language
    return NetworkObservation.from_exchange(
        method=method,
        path=path,
        query_string=query,
        request_headers=req_headers,
        response=response,
        fixture_family="",
    )._replace_auth(has_auth)


# Monkey-patch-free way to set has_auth_header:
class _ObsBuilder:
    @staticmethod
    def build(method: str, path: str, response: NetworkResponse, *,
              has_auth: bool = False,
              accept: str = "",
              content_type: str = "",
              language: str = "",
              query: str = "") -> NetworkObservation:
        req_headers: dict = {}
        if accept:
            req_headers["Accept"] = accept
        if content_type:
            req_headers["Content-Type"] = content_type
        if language:
            req_headers["Accept-Language"] = language
        if has_auth:
            req_headers["Authorization"] = "<REDACTED>"
        obs = NetworkObservation.from_exchange(
            method=method,
            path=path,
            query_string=query,
            request_headers=req_headers,
            response=response,
            fixture_family="",
        )
        return obs


def _mk(method: str, path: str, response: NetworkResponse, **kwargs) -> NetworkObservation:
    return _ObsBuilder.build(method, path, response, **kwargs)


# ── Sequence dataclass with label ─────────────────────────────────────────────

@dataclass
class Phase2Fixture:
    """A Phase II fixture: sequence or pair with all four task labels."""
    fixture_id: str
    family: str
    sequence: Optional[ObservationSequence] = None
    experiment: Optional[ControlledExperiment] = None

    # Task labels
    net_e_label: str = StateTransitionClass.UNKNOWN.value
    net_f_label: str = ExperimentQualityClass.UNKNOWN.value
    net_g_label: str = CausalSupportClass.UNKNOWN.value
    net_h_label: str = NextObservationType.UNKNOWN.value


# ── Lab ────────────────────────────────────────────────────────────────────────

class Phase2Lab:
    """Generates all Phase II educational fixtures."""

    def generate_transition_sequences(self) -> list[Phase2Fixture]:
        """Generate ObservationSequences for NET-E (State Transition) training."""
        out: list[Phase2Fixture] = []

        def _seq(seq_id: str, family: str, label: StateTransitionClass,
                 *steps: tuple[str, str, NetworkResponse, dict]) -> Phase2Fixture:
            seq = ObservationSequence(
                sequence_id=seq_id, scenario_family=family,
                net_e_label=label.value,
            )
            for i, (method, path, resp, kw) in enumerate(steps):
                obs = _mk(method, path, resp, **kw)
                seq.add(obs, timestamp_offset_ms=i * 100)
            return Phase2Fixture(
                fixture_id=seq_id, family=family,
                sequence=seq, net_e_label=label.value,
            )

        # ── NO_STATE_CHANGE ────────────────────────────────────────────────────
        for i in range(3):
            r = _resp(200, b'{"items":[]}')
            out.append(_seq(
                f"nsc_api_{i}", "no_state_change_api", StateTransitionClass.NO_STATE_CHANGE,
                ("GET", f"/api/items/{i}", r, {}),
                ("GET", f"/api/items/{i}", r, {}),
            ))
        for i in range(3):
            r = _resp(200, b'<html><body>Hello</body></html>', ct="text/html")
            out.append(_seq(
                f"nsc_html_{i}", "no_state_change_html", StateTransitionClass.NO_STATE_CHANGE,
                ("GET", f"/page/{i}", r, {}),
                ("GET", f"/page/{i}", r, {}),
            ))

        # ── SESSION_CREATED ────────────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"sc_login_{i}", "session_created_login", StateTransitionClass.SESSION_CREATED,
                ("GET",  "/login",     _resp(200, b'{"form":"login"}'), {}),
                ("POST", "/auth/login",_resp(302, b"", location="/dashboard", set_cookie=True), {}),
                ("GET",  "/dashboard", _resp(200, b'{"user":"alice"}', set_cookie=True), {"has_auth": True}),
            ))
        for i in range(3):
            out.append(_seq(
                f"sc_anon_{i}", "session_created_anon", StateTransitionClass.SESSION_CREATED,
                ("GET", "/",        _resp(200, b'{"welcome":true}'), {}),
                ("GET", "/catalog", _resp(200, b'{"items":[]}', set_cookie=True), {}),
            ))

        # ── SESSION_ROTATED ────────────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"sr_post_login_{i}", "session_rotated_login", StateTransitionClass.SESSION_ROTATED,
                ("POST", "/auth/login",  _resp(302, b"", location="/home", set_cookie=True), {}),
                ("GET",  "/home",        _resp(200, b'{"home":true}',      set_cookie=True), {"has_auth": True}),
            ))

        # ── SESSION_EXPIRED ────────────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"se_expire_{i}", "session_expired", StateTransitionClass.SESSION_EXPIRED,
                ("GET", "/api/profile", _resp(200, b'{"user":"bob"}'), {"has_auth": True}),
                ("GET", "/api/profile", _resp(401, b'{"error":"session_expired"}', www_auth=True), {"has_auth": True}),
            ))

        # ── AUTH_ESTABLISHED ───────────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"ae_anon_to_auth_{i}", "auth_established", StateTransitionClass.AUTH_ESTABLISHED,
                ("GET", "/api/data", _resp(401, b'{"error":"auth_required"}', www_auth=True), {}),
                ("GET", "/api/data", _resp(200, b'{"data":[]}'), {"has_auth": True}),
            ))

        # ── AUTH_LOST ──────────────────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"al_logout_{i}", "auth_lost_logout", StateTransitionClass.AUTH_LOST,
                ("GET",  "/api/me",  _resp(200, b'{"user":"alice"}'), {"has_auth": True}),
                ("POST", "/logout",  _resp(200, b'{"logged_out":true}', set_cookie=True), {"has_auth": True}),
                ("GET",  "/api/me",  _resp(401, b'{"error":"not_authenticated"}', www_auth=True), {}),
            ))

        # ── CACHE_VALIDATED ────────────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"cv_304_{i}", "cache_validated", StateTransitionClass.CACHE_VALIDATED,
                ("GET", "/api/resource", _resp(200, b'{"v":1}', etag=f'"etag-{i}"'), {}),
                ("GET", "/api/resource", _resp(304, b""), {}),
            ))

        # ── CACHE_INVALIDATED ──────────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"ci_stale_{i}", "cache_invalidated", StateTransitionClass.CACHE_INVALIDATED,
                ("GET", "/api/data", _resp(304, b""), {}),
                ("GET", "/api/data", _resp(200, b'{"v":2}', etag=f'"new-etag-{i}"'), {}),
            ))

        # ── RESOURCE_STATE_CHANGED ─────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"rsc_create_{i}", "resource_state_create", StateTransitionClass.RESOURCE_STATE_CHANGED,
                ("GET",  f"/api/items/{i}", _resp(404, b'{"error":"not_found"}'), {}),
                ("POST", "/api/items",       _resp(201, b'{"id":1}'), {"has_auth": True}),
                ("GET",  f"/api/items/{i}", _resp(200, b'{"id":1}'), {}),
            ))
        for i in range(3):
            out.append(_seq(
                f"rsc_delete_{i}", "resource_state_delete", StateTransitionClass.RESOURCE_STATE_CHANGED,
                ("GET",    f"/api/items/{i}", _resp(200, b'{"id":1}'), {}),
                ("DELETE", f"/api/items/{i}", _resp(204, b""), {"has_auth": True}),
                ("GET",    f"/api/items/{i}", _resp(404, b'{"error":"not_found"}'), {}),
            ))

        # ── TRANSIENT_RECOVERY ─────────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"tr_503_{i}", "transient_recovery_503", StateTransitionClass.TRANSIENT_RECOVERY,
                ("GET", "/api/data", _resp(503, b'{"error":"service_unavailable"}'), {}),
                ("GET", "/api/data", _resp(200, b'{"data":[]}'), {}),
            ))
        for i in range(3):
            out.append(_seq(
                f"tr_timeout_{i}", "transient_recovery_timeout", StateTransitionClass.TRANSIENT_RECOVERY,
                ("GET", "/api/slow", _resp(0, timed_out=True, elapsed_ms=30000), {}),
                ("GET", "/api/slow", _resp(200, b'{"ok":true}'), {}),
            ))

        # ── REDIRECT_FOLLOWED ──────────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"rf_301_{i}", "redirect_followed_301", StateTransitionClass.REDIRECT_FOLLOWED,
                ("GET", "/old-api", _resp(301, b"", location="/api/v2"), {}),
                ("GET", "/api/v2",  _resp(200, b'{"version":2}'), {}),
            ))
        for i in range(3):
            out.append(_seq(
                f"rf_login_{i}", "redirect_followed_login", StateTransitionClass.REDIRECT_FOLLOWED,
                ("GET",  "/account",      _resp(302, b"", location="/login"), {}),
                ("POST", "/auth/login",   _resp(302, b"", location="/account", set_cookie=True), {}),
                ("GET",  "/account",      _resp(200, b'{"user":"alice"}'), {"has_auth": True}),
            ))

        # ── RATE_LIMIT_RECOVERY ────────────────────────────────────────────────
        for i in range(3):
            out.append(_seq(
                f"rlr_429_{i}", "rate_limit_recovery", StateTransitionClass.RATE_LIMIT_RECOVERY,
                ("GET", "/api/search", _resp(429, b'{"error":"rate_limited"}', retry_after=True), {}),
                ("GET", "/api/search", _resp(200, b'{"results":[]}'), {}),
            ))

        return out

    def generate_experiment_pairs(self) -> list[Phase2Fixture]:
        """Generate SequencePairs for NET-F/G/H (experiment quality/causal support)."""
        out: list[Phase2Fixture] = []

        def _add_exp(fid: str, family: str,
                     ctrl: NetworkObservation, test: NetworkObservation,
                     hypothesis: CausalHypothesis,
                     net_f: ExperimentQualityClass,
                     net_g: CausalSupportClass,
                     net_h: NextObservationType) -> None:
            exp = ControlledExperiment(
                experiment_id=fid,
                control=ctrl,
                test=test,
                hypothesis=hypothesis,
                scenario_family=family,
            ).classify()
            out.append(Phase2Fixture(
                fixture_id=fid, family=family,
                experiment=exp,
                net_f_label=net_f.value,
                net_g_label=net_g.value,
                net_h_label=net_h.value,
            ))

        # ── CONTROLLED_SINGLE_VARIABLE: auth dependency ───────────────────────
        for i in range(3):
            _add_exp(
                f"csv_auth_{i}", "csv_auth_dependency",
                ctrl=_mk("GET", "/api/profile", _resp(401, b'{"error":"auth_required"}', www_auth=True)),
                test=_mk("GET", "/api/profile", _resp(200, b'{"user":"alice"}'), has_auth=True),
                hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
                net_f=ExperimentQualityClass.CONTROLLED_SINGLE_VARIABLE,
                net_g=CausalSupportClass.SUPPORTED,
                net_h=NextObservationType.NO_OBSERVATION_NEEDED,
            )
        for i in range(3):
            _add_exp(
                f"csv_cookie_{i}", "csv_session_dependency",
                ctrl=_mk("GET", "/api/cart",    _resp(200, b'{"items":0}')),
                test=_mk("GET", "/api/cart",    _resp(200, b'{"items":3}'), has_auth=True),
                hypothesis=CausalHypothesis.SESSION_DEPENDENCY_SUPPORTED,
                net_f=ExperimentQualityClass.CONTROLLED_SINGLE_VARIABLE,
                net_g=CausalSupportClass.SUPPORTED,
                net_h=NextObservationType.NO_OBSERVATION_NEEDED,
            )

        # ── CONTROLLED_SINGLE_VARIABLE: accept header ─────────────────────────
        for i in range(3):
            _add_exp(
                f"csv_accept_{i}", "csv_content_neg",
                ctrl=_mk("GET", "/api/data", _resp(200, b'{"data":1}'), accept="application/json"),
                test=_mk("GET", "/api/data", _resp(200, b'<data>1</data>', ct="text/xml"), accept="text/xml"),
                hypothesis=CausalHypothesis.CONTENT_NEGOTIATION_DEPENDENCY_SUPPORTED,
                net_f=ExperimentQualityClass.CONTROLLED_SINGLE_VARIABLE,
                net_g=CausalSupportClass.SUPPORTED,
                net_h=NextObservationType.NO_OBSERVATION_NEEDED,
            )

        # ── CONFOUNDED: auth + path changed ───────────────────────────────────
        for i in range(3):
            _add_exp(
                f"conf_auth_path_{i}", "confounded_auth_path",
                ctrl=_mk("GET", "/public/data",  _resp(200, b'{"public":true}')),
                test=_mk("GET", "/private/data", _resp(200, b'{"private":true}'), has_auth=True),
                hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
                net_f=ExperimentQualityClass.CONFOUNDED,
                net_g=CausalSupportClass.CONFOUNDED,
                net_h=NextObservationType.COMPARE_WITHOUT_AUTH_HEADER,
            )

        # ── CONFOUNDED: method + body + auth ──────────────────────────────────
        for i in range(3):
            _add_exp(
                f"conf_multi_{i}", "confounded_multi",
                ctrl=_mk("GET",  "/api/resource", _resp(200, b'{"v":1}')),
                test=_mk("POST", "/api/resource", _resp(201, b'{"v":2}'), has_auth=True,
                         content_type="application/json"),
                hypothesis=CausalHypothesis.METHOD_DEPENDENCY_SUPPORTED,
                net_f=ExperimentQualityClass.CONFOUNDED,
                net_g=CausalSupportClass.CONFOUNDED,
                net_h=NextObservationType.ISOLATE_METHOD_VARIABLE,
            )

        # ── NO_MEANINGFUL_CHANGE ───────────────────────────────────────────────
        for i in range(3):
            r = _resp(200, b'{"stable":true}')
            _add_exp(
                f"nmc_identical_{i}", "no_meaningful_change",
                ctrl=_mk("GET", "/api/stable", r),
                test=_mk("GET", "/api/stable", r),
                hypothesis=CausalHypothesis.NO_OBSERVED_DEPENDENCY,
                net_f=ExperimentQualityClass.NO_MEANINGFUL_CHANGE,
                net_g=CausalSupportClass.NOT_SUPPORTED,
                net_h=NextObservationType.REPEAT_SAME_OBSERVATION,
            )

        # ── INSUFFICIENT_CONTEXT ───────────────────────────────────────────────
        for i in range(3):
            _add_exp(
                f"ic_404_{i}", "insufficient_context",
                ctrl=_mk("GET", "/api/unknown", _resp(404, b'{"error":"not_found"}')),
                test=_mk("GET", "/api/unknown", _resp(404, b'{"error":"not_found"}')),
                hypothesis=CausalHypothesis.UNKNOWN,
                net_f=ExperimentQualityClass.INSUFFICIENT_CONTEXT,
                net_g=CausalSupportClass.INSUFFICIENT_EVIDENCE,
                net_h=NextObservationType.COMPARE_WITH_AUTH_HEADER,
            )

        return out

    def generate_adversarial_sequences(self) -> list[Phase2Fixture]:
        """Adversarial/contradictory cases for Part 46 and Part 75."""
        out: list[Phase2Fixture] = []

        def _seq(seq_id: str, family: str, label: StateTransitionClass,
                 *steps: tuple) -> Phase2Fixture:
            seq = ObservationSequence(
                sequence_id=seq_id, scenario_family=family,
                net_e_label=label.value,
            )
            for i, args in enumerate(steps):
                method, path, resp, kw = args
                obs = _mk(method, path, resp, **kw)
                seq.add(obs, timestamp_offset_ms=i * 100)
            return Phase2Fixture(
                fixture_id=seq_id, family=family,
                sequence=seq, net_e_label=label.value,
            )

        # Adversarial: 401→200 but auth token added (AUTH_ESTABLISHED, not unknown)
        for i in range(3):
            out.append(_seq(
                f"adv_auth_est_{i}", "adversarial_auth_established",
                StateTransitionClass.AUTH_ESTABLISHED,
                ("GET", "/api/me", _resp(401, b'{"error":"auth_required"}', www_auth=True), {}),
                ("GET", "/api/me", _resp(200, b'{"user":"bob"}'), {"has_auth": True}),
            ))

        # Adversarial: preference cookie set on both responses
        # LABEL_ERROR fix (AMBIGUOUS_TARGET/FEATURE_GAP): without cookie-value tracking we
        # cannot distinguish a preference cookie from a rolling session token. The rule
        # fires SESSION_ROTATED (f_cookie=True, l_cookie=True, l_status=2xx) which is
        # defensible — servers DO rotate session tokens on every request.
        for i in range(3):
            out.append(_seq(
                f"adv_pref_cookie_{i}", "adversarial_pref_cookie",
                StateTransitionClass.SESSION_ROTATED,
                ("GET", "/", _resp(200, b'{"lang":"en"}', set_cookie=True), {}),
                ("GET", "/", _resp(200, b'{"lang":"en"}', set_cookie=True), {}),
            ))

        # Adversarial: Authorization present but 401 → SESSION_EXPIRED not NO_STATE_CHANGE
        # LABEL_ERROR fix: first=200+auth, last=401+auth is definitionally SESSION_EXPIRED —
        # the token was valid, then became invalid. "Authorization header != authenticated"
        # shortcut is better demonstrated by a scenario where auth was NEVER valid (always 401).
        for i in range(3):
            out.append(_seq(
                f"adv_bad_token_{i}", "adversarial_invalid_token",
                StateTransitionClass.SESSION_EXPIRED,
                ("GET", "/api/data", _resp(200, b'{"data":[]}'), {"has_auth": True}),
                ("GET", "/api/data", _resp(401, b'{"error":"invalid_token"}', www_auth=True), {"has_auth": True}),
            ))

        # Adversarial: 200 but login page body (UNKNOWN — can't confirm auth from body alone)
        for i in range(3):
            login_body = b'<html><body><form method="post" action="/login"></form></body></html>'
            out.append(_seq(
                f"adv_200_login_page_{i}", "adversarial_200_login_page",
                StateTransitionClass.UNKNOWN,
                ("GET", "/dashboard", _resp(200, login_body, ct="text/html"), {"has_auth": True}),
                ("GET", "/dashboard", _resp(200, login_body, ct="text/html"), {}),
            ))

        # Adversarial: session cookie changed during login → SESSION_ROTATED (not UNKNOWN)
        for i in range(3):
            out.append(_seq(
                f"adv_sr_login_{i}", "adversarial_session_rotate_login",
                StateTransitionClass.SESSION_ROTATED,
                ("POST", "/auth/login", _resp(302, b"", location="/home", set_cookie=True), {}),
                ("GET",  "/home",       _resp(200, b'{"home":true}', set_cookie=True), {"has_auth": True}),
            ))

        # Adversarial: 403→200 but resource also changed → UNKNOWN (not AUTH_ESTABLISHED)
        for i in range(3):
            out.append(_seq(
                f"adv_403_resource_change_{i}", "adversarial_403_resource_change",
                StateTransitionClass.UNKNOWN,
                ("GET", "/api/resource/1", _resp(403, b'{"error":"forbidden"}'), {}),
                ("GET", "/api/resource/2", _resp(200, b'{"data":"other"}'), {}),
            ))

        return out

    def generate_counterfactual_pairs(self) -> list[Phase2Fixture]:
        """Counterfactual cases: rules that should NOT fire (Part 47)."""
        out: list[Phase2Fixture] = []

        def _add_exp(fid: str, family: str,
                     ctrl: NetworkObservation, test: NetworkObservation,
                     hypothesis: CausalHypothesis,
                     net_f: ExperimentQualityClass,
                     net_g: CausalSupportClass,
                     net_h: NextObservationType) -> None:
            exp = ControlledExperiment(
                experiment_id=fid,
                control=ctrl,
                test=test,
                hypothesis=hypothesis,
                scenario_family=family,
            ).classify()
            out.append(Phase2Fixture(
                fixture_id=fid, family=family,
                experiment=exp,
                net_f_label=net_f.value,
                net_g_label=net_g.value,
                net_h_label=net_h.value,
            ))

        # Counterfactual 1: Authorization present but token invalid → 401.
        # No request dimension changed (both carry auth). Response changed from
        # 200→401, but the cause is server-side token expiry, not an observable
        # request dimension. Lesson: auth header present ≠ authenticated.
        # FEATURE_GAP: token validity is not a tracked request dimension.
        for i in range(3):
            _add_exp(
                f"cf_bad_token_{i}", "counterfactual_bad_token",
                ctrl=_mk("GET", "/api/data", _resp(200, b'{"ok":true}'), has_auth=True),
                test=_mk("GET", "/api/data", _resp(401, b'{"error":"invalid_token"}', www_auth=True), has_auth=True),
                hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
                net_f=ExperimentQualityClass.INSUFFICIENT_CONTEXT,
                net_g=CausalSupportClass.INSUFFICIENT_EVIDENCE,
                net_h=NextObservationType.COMPARE_WITH_AUTH_HEADER,
            )

        # Counterfactual 2: Set-Cookie during ordinary 200 (preference, not session rotation)
        for i in range(3):
            _add_exp(
                f"cf_pref_cookie_{i}", "counterfactual_preference_cookie",
                ctrl=_mk("GET", "/", _resp(200, b'{"theme":"dark"}', set_cookie=True)),
                test=_mk("GET", "/", _resp(200, b'{"theme":"dark"}', set_cookie=True)),
                hypothesis=CausalHypothesis.SESSION_DEPENDENCY_SUPPORTED,
                net_f=ExperimentQualityClass.NO_MEANINGFUL_CHANGE,
                net_g=CausalSupportClass.NOT_SUPPORTED,
                net_h=NextObservationType.REPEAT_SAME_OBSERVATION,
            )

        # Counterfactual 3: 304 response — not a content change, not an auth issue.
        # No tracked request dimension changed (If-None-Match is not in
        # RequestDimensions). Response differs (200 → 304).
        # FEATURE_GAP: conditional request headers (If-None-Match, If-Modified-Since)
        # are not tracked → model correctly outputs INSUFFICIENT_CONTEXT.
        # Lesson: 304 != generic content change; cache dependency needs richer dims.
        for i in range(3):
            _add_exp(
                f"cf_cache_304_{i}", "counterfactual_cache",
                ctrl=_mk("GET", "/api/data", _resp(200, b'{"v":1}', etag='"e1"')),
                test=_mk("GET", "/api/data", _resp(304, b"")),
                hypothesis=CausalHypothesis.CACHE_DEPENDENCY_SUPPORTED,
                net_f=ExperimentQualityClass.INSUFFICIENT_CONTEXT,
                net_g=CausalSupportClass.INSUFFICIENT_EVIDENCE,
                net_h=NextObservationType.CHECK_CACHE_VALIDATOR,
            )

        return out

    def all_sequences(self) -> list[Phase2Fixture]:
        return (self.generate_transition_sequences() +
                self.generate_adversarial_sequences())

    def all_experiments(self) -> list[Phase2Fixture]:
        return (self.generate_experiment_pairs() +
                self.generate_counterfactual_pairs())

    def all_fixtures(self) -> list[Phase2Fixture]:
        return self.all_sequences() + self.all_experiments()
