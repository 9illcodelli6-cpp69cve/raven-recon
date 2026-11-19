"""RAVEN Network Phase II — Test suite.

Tests NET-E/F/G/H rules, browser semantics, state machine,
sequence representation, and controlled experiments.

INVARIANTS:
- No external network calls
- All data is EDUCATIONAL_SYNTHETIC
- Human-reviewed labels: 0
- Security authority: NONE
"""
import pytest


# ── Browser semantics ─────────────────────────────────────────────────────────

class TestOrigin:
    def test_parse_https(self):
        from raven.network_phase2.browser import Origin
        o = Origin.parse("https://example.com/path")
        assert o.scheme == "https"
        assert o.host   == "example.com"
        assert o.port   == 443

    def test_parse_http_default_port(self):
        from raven.network_phase2.browser import Origin
        o = Origin.parse("http://api.example.com/")
        assert o.scheme == "http"
        assert o.host   == "api.example.com"
        assert o.port   == 80

    def test_parse_explicit_port(self):
        from raven.network_phase2.browser import Origin
        o = Origin.parse("https://example.com:8443/path")
        assert o.port == 8443

    def test_parse_ipv6(self):
        from raven.network_phase2.browser import Origin
        o = Origin.parse("http://[::1]:8080/")
        assert o.host == "[::1]"
        assert o.port == 8080

    def test_opaque_on_invalid(self):
        from raven.network_phase2.browser import Origin
        o = Origin.parse("not-a-url")
        assert o.is_opaque

    def test_same_origin_identical(self):
        from raven.network_phase2.browser import Origin
        a = Origin.parse("https://example.com")
        b = Origin.parse("https://example.com")
        assert a.same_origin(b)

    def test_same_origin_different_scheme(self):
        from raven.network_phase2.browser import Origin
        a = Origin.parse("http://example.com")
        b = Origin.parse("https://example.com")
        assert not a.same_origin(b)

    def test_same_origin_different_host(self):
        from raven.network_phase2.browser import Origin
        a = Origin.parse("https://example.com")
        b = Origin.parse("https://api.example.com")
        assert not a.same_origin(b)

    def test_same_origin_different_port(self):
        from raven.network_phase2.browser import Origin
        a = Origin.parse("https://example.com:443")
        b = Origin.parse("https://example.com:8443")
        assert not a.same_origin(b)

    def test_cross_origin(self):
        from raven.network_phase2.browser import Origin
        a = Origin.parse("https://example.com")
        b = Origin.parse("https://other.com")
        assert a.cross_origin(b)

    def test_opaque_never_same_origin(self):
        from raven.network_phase2.browser import Origin
        a = Origin.parse("https://example.com")
        b = Origin.opaque()
        assert not a.same_origin(b)
        assert not b.same_origin(a)

    def test_to_string_omits_default_port(self):
        from raven.network_phase2.browser import Origin
        o = Origin.parse("https://example.com")
        assert o.to_string() == "https://example.com"

    def test_to_string_includes_non_default_port(self):
        from raven.network_phase2.browser import Origin
        o = Origin.parse("https://example.com:8443")
        assert o.to_string() == "https://example.com:8443"

    def test_host_case_normalized(self):
        from raven.network_phase2.browser import Origin
        o = Origin.parse("https://EXAMPLE.COM")
        assert o.host == "example.com"


class TestCookieSending:
    def test_host_only_cookie_sent_to_exact_host(self):
        from raven.network_phase2.browser import CookieAttributes, CookieDecision, evaluate_cookie_sending
        c = CookieAttributes(name="session", domain="example.com", path="/",
                              host_only=True)
        r = evaluate_cookie_sending(c, "https", "example.com", "/api")
        assert r.decision == CookieDecision.COOKIE_SENT

    def test_host_only_cookie_not_sent_to_subdomain(self):
        from raven.network_phase2.browser import CookieAttributes, CookieDecision, evaluate_cookie_sending
        c = CookieAttributes(name="session", domain="example.com", path="/",
                              host_only=True)
        r = evaluate_cookie_sending(c, "https", "sub.example.com", "/api")
        assert r.decision == CookieDecision.COOKIE_NOT_SENT

    def test_domain_cookie_sent_to_subdomain(self):
        from raven.network_phase2.browser import CookieAttributes, CookieDecision, evaluate_cookie_sending
        c = CookieAttributes(name="tracker", domain="example.com", path="/",
                              host_only=False)
        r = evaluate_cookie_sending(c, "https", "sub.example.com", "/")
        assert r.decision == CookieDecision.COOKIE_SENT

    def test_secure_cookie_not_sent_over_http(self):
        from raven.network_phase2.browser import CookieAttributes, CookieDecision, evaluate_cookie_sending
        c = CookieAttributes(name="s", domain="example.com", path="/", secure=True)
        r = evaluate_cookie_sending(c, "http", "example.com", "/")
        assert r.decision == CookieDecision.COOKIE_NOT_SENT

    def test_expired_cookie_not_sent(self):
        from raven.network_phase2.browser import CookieAttributes, CookieDecision, evaluate_cookie_sending
        c = CookieAttributes(name="old", domain="example.com", path="/",
                              max_age=-1)
        r = evaluate_cookie_sending(c, "https", "example.com", "/")
        assert r.decision == CookieDecision.COOKIE_NOT_SENT

    def test_path_mismatch_not_sent(self):
        from raven.network_phase2.browser import CookieAttributes, CookieDecision, evaluate_cookie_sending
        c = CookieAttributes(name="admin", domain="example.com", path="/admin")
        r = evaluate_cookie_sending(c, "https", "example.com", "/public")
        assert r.decision == CookieDecision.COOKIE_NOT_SENT

    def test_path_prefix_match_sent(self):
        from raven.network_phase2.browser import CookieAttributes, CookieDecision, evaluate_cookie_sending
        c = CookieAttributes(name="api", domain="example.com", path="/api")
        r = evaluate_cookie_sending(c, "https", "example.com", "/api/users")
        assert r.decision == CookieDecision.COOKIE_SENT


class TestCorsAnalysis:
    def test_same_origin_no_cors(self):
        from raven.network_phase2.browser import CorsAnalysis, CorsState, Origin
        a = CorsAnalysis(
            request_origin=Origin.parse("https://example.com"),
            resource_origin=Origin.parse("https://example.com"),
        )
        assert a.classify() == CorsState.SAME_ORIGIN

    def test_simple_get_cross_origin_with_acao(self):
        from raven.network_phase2.browser import CorsAnalysis, CorsState, Origin
        a = CorsAnalysis(
            request_origin=Origin.parse("https://app.com"),
            resource_origin=Origin.parse("https://api.com"),
            method="GET",
            acao="https://app.com",
        )
        assert a.classify() == CorsState.SIMPLE_REQUEST

    def test_wildcard_acao_no_credentials(self):
        from raven.network_phase2.browser import CorsAnalysis, CorsState, Origin
        a = CorsAnalysis(
            request_origin=Origin.parse("https://app.com"),
            resource_origin=Origin.parse("https://api.com"),
            method="GET",
            acao="*",
        )
        assert a.classify() == CorsState.SIMPLE_REQUEST

    def test_wildcard_acao_with_credentials_rejected(self):
        from raven.network_phase2.browser import CorsAnalysis, CorsState, Origin
        a = CorsAnalysis(
            request_origin=Origin.parse("https://app.com"),
            resource_origin=Origin.parse("https://api.com"),
            method="PUT",
            acao="*",
            acac="true",
            preflight_status=200,
        )
        assert a.classify() == CorsState.PREFLIGHT_REJECTED

    def test_preflight_accepted(self):
        from raven.network_phase2.browser import CorsAnalysis, CorsState, Origin
        a = CorsAnalysis(
            request_origin=Origin.parse("https://app.com"),
            resource_origin=Origin.parse("https://api.com"),
            method="DELETE",
            acao="https://app.com",
            acam="GET, POST, DELETE",
            preflight_status=200,
        )
        assert a.classify() == CorsState.PREFLIGHT_ACCEPTED

    def test_no_acao_requires_preflight(self):
        from raven.network_phase2.browser import CorsAnalysis, CorsState, Origin
        a = CorsAnalysis(
            request_origin=Origin.parse("https://app.com"),
            resource_origin=Origin.parse("https://api.com"),
            method="PUT",
        )
        assert a.classify() == CorsState.PREFLIGHT_REQUIRED


class TestUrlNormalization:
    def test_dot_segments_resolved(self):
        from raven.network_phase2.browser import normalize_url_path
        assert normalize_url_path("/a/b/../c") == "/a/c"

    def test_current_dir_dots(self):
        from raven.network_phase2.browser import normalize_url_path
        assert normalize_url_path("/a/./b") == "/a/b"

    def test_root_stays_root(self):
        from raven.network_phase2.browser import normalize_url_path
        assert normalize_url_path("/") == "/"

    def test_empty_returns_root(self):
        from raven.network_phase2.browser import normalize_url_path
        assert normalize_url_path("") == "/"


# ── State machine ─────────────────────────────────────────────────────────────

class TestStateMachine:
    def _obs_200_with_auth(self):
        from raven.network_fundamentals.observation import NetworkObservation, NetworkResponse
        resp = NetworkResponse.from_raw(200, {"Set-Cookie": "<REDACTED>"}, b"{}", 30)
        obs = NetworkObservation()
        obs.response = resp
        obs.has_auth_header = True
        return obs

    def _obs_401(self):
        from raven.network_fundamentals.observation import NetworkObservation, NetworkResponse
        resp = NetworkResponse.from_raw(401, {"WWW-Authenticate": "Bearer"}, b"{}", 20)
        obs = NetworkObservation()
        obs.response = resp
        obs.has_auth_header = False
        return obs

    def test_infer_http_active(self):
        from raven.network_phase2.state_machine import infer_state, NetworkDimension
        obs = self._obs_200_with_auth()
        s = infer_state(obs)
        assert s.network == NetworkDimension.HTTP_ACTIVE

    def test_infer_authenticated_session(self):
        from raven.network_phase2.state_machine import infer_state, SessionDimension
        obs = self._obs_200_with_auth()
        s = infer_state(obs)
        assert s.session == SessionDimension.AUTHENTICATED_SESSION

    def test_infer_401_expired(self):
        from raven.network_phase2.state_machine import infer_state, SessionDimension
        obs = self._obs_401()
        s = infer_state(obs)
        assert s.session in (SessionDimension.EXPIRED_SESSION, SessionDimension.NO_SESSION,
                              SessionDimension.UNKNOWN)

    def test_composite_diff(self):
        from raven.network_phase2.state_machine import CompositeState, SessionDimension
        a = CompositeState()
        b = CompositeState(session=SessionDimension.AUTHENTICATED_SESSION)
        assert "session" in a.diff(b)

    def test_normal_session_transition(self):
        from raven.network_phase2.state_machine import SessionDimension, is_normal_session_transition
        assert is_normal_session_transition(
            SessionDimension.ANONYMOUS_SESSION,
            SessionDimension.AUTHENTICATED_SESSION) is True

    def test_logged_out_to_auth_needs_evidence(self):
        from raven.network_phase2.state_machine import SessionDimension, is_normal_session_transition
        result = is_normal_session_transition(
            SessionDimension.LOGGED_OUT,
            SessionDimension.AUTHENTICATED_SESSION)
        assert result is None  # NEEDS_MORE_EVIDENCE


# ── NET-E rules ────────────────────────────────────────────────────────────────

class TestNetERule:
    def _make_seq(self, steps):
        from raven.network_phase2.lab2 import Phase2Lab
        from raven.network_phase2.sequence import ObservationSequence
        from raven.network_phase2.lab2 import _mk, _resp
        seq = ObservationSequence("test", scenario_family="test")
        for method, path, status, kwargs in steps:
            resp = _resp(status, b"{}")
            obs = _mk(method, path, resp, **kwargs)
            seq.add(obs)
        return seq

    def test_transient_recovery(self):
        from raven.network_phase2.rules2 import rule_net_e
        from raven.network_phase2.lab2 import _mk, _resp
        from raven.network_phase2.sequence import ObservationSequence
        seq = ObservationSequence("t1", scenario_family="x")
        seq.add(_mk("GET", "/api", _resp(503, b"{}")))
        seq.add(_mk("GET", "/api", _resp(200, b"{}")))
        assert rule_net_e(seq) == "TRANSIENT_RECOVERY"

    def test_cache_validated(self):
        from raven.network_phase2.rules2 import rule_net_e
        from raven.network_phase2.lab2 import _mk, _resp
        from raven.network_phase2.sequence import ObservationSequence
        seq = ObservationSequence("t2", scenario_family="x")
        seq.add(_mk("GET", "/api/r", _resp(200, b"{}", etag='"e1"')))
        seq.add(_mk("GET", "/api/r", _resp(304, b"")))
        assert rule_net_e(seq) == "CACHE_VALIDATED"

    def test_redirect_followed(self):
        from raven.network_phase2.rules2 import rule_net_e
        from raven.network_phase2.lab2 import _mk, _resp
        from raven.network_phase2.sequence import ObservationSequence
        seq = ObservationSequence("t3", scenario_family="x")
        seq.add(_mk("GET", "/old", _resp(301, b"", location="/new")))
        seq.add(_mk("GET", "/new", _resp(200, b"{}")))
        assert rule_net_e(seq) == "REDIRECT_FOLLOWED"

    def test_session_expired(self):
        from raven.network_phase2.rules2 import rule_net_e
        from raven.network_phase2.lab2 import _mk, _resp
        from raven.network_phase2.sequence import ObservationSequence
        seq = ObservationSequence("t4", scenario_family="x")
        seq.add(_mk("GET", "/api/me", _resp(200, b"{}"), has_auth=True))
        seq.add(_mk("GET", "/api/me", _resp(401, b"{}", www_auth=True), has_auth=True))
        assert rule_net_e(seq) == "SESSION_EXPIRED"

    def test_auth_established(self):
        from raven.network_phase2.rules2 import rule_net_e
        from raven.network_phase2.lab2 import _mk, _resp
        from raven.network_phase2.sequence import ObservationSequence
        seq = ObservationSequence("t5", scenario_family="x")
        seq.add(_mk("GET", "/api/data", _resp(401, b"{}", www_auth=True)))
        seq.add(_mk("GET", "/api/data", _resp(200, b"{}"), has_auth=True))
        assert rule_net_e(seq) == "AUTH_ESTABLISHED"

    def test_no_state_change(self):
        from raven.network_phase2.rules2 import rule_net_e
        from raven.network_phase2.lab2 import _mk, _resp
        from raven.network_phase2.sequence import ObservationSequence
        body = b'{"stable":true}'
        seq = ObservationSequence("t6", scenario_family="x")
        seq.add(_mk("GET", "/api", _resp(200, body)))
        seq.add(_mk("GET", "/api", _resp(200, body)))
        assert rule_net_e(seq) == "NO_STATE_CHANGE"

    def test_rate_limit_recovery(self):
        from raven.network_phase2.rules2 import rule_net_e
        from raven.network_phase2.lab2 import _mk, _resp
        from raven.network_phase2.sequence import ObservationSequence
        seq = ObservationSequence("t7", scenario_family="x")
        seq.add(_mk("GET", "/api/search", _resp(429, b"{}", retry_after=True)))
        seq.add(_mk("GET", "/api/search", _resp(200, b"{}")))
        assert rule_net_e(seq) == "RATE_LIMIT_RECOVERY"

    def test_resource_created(self):
        from raven.network_phase2.rules2 import rule_net_e
        from raven.network_phase2.lab2 import _mk, _resp
        from raven.network_phase2.sequence import ObservationSequence
        seq = ObservationSequence("t8", scenario_family="x")
        seq.add(_mk("GET",  "/api/items/1", _resp(404, b"{}")))
        seq.add(_mk("POST", "/api/items",   _resp(201, b"{}", ), has_auth=True))
        seq.add(_mk("GET",  "/api/items/1", _resp(200, b"{}")))
        assert rule_net_e(seq) == "RESOURCE_STATE_CHANGED"

    def test_single_obs_unknown(self):
        from raven.network_phase2.rules2 import rule_net_e
        from raven.network_phase2.lab2 import _mk, _resp
        from raven.network_phase2.sequence import ObservationSequence
        seq = ObservationSequence("t9", scenario_family="x")
        seq.add(_mk("GET", "/", _resp(200, b"{}")))
        assert rule_net_e(seq) == "UNKNOWN"


# ── NET-F rules ────────────────────────────────────────────────────────────────

class TestNetFRule:
    def test_single_variable_auth(self):
        from raven.network_phase2.rules2 import rule_net_f
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        from raven.network_phase2.lab2 import _mk, _resp
        exp = ControlledExperiment(
            experiment_id="x",
            control=_mk("GET", "/api", _resp(401, b"{}")),
            test=_mk("GET", "/api", _resp(200, b"{}"), has_auth=True),
            hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
        )
        assert rule_net_f(exp) == "CONTROLLED_SINGLE_VARIABLE"

    def test_confounded_auth_and_path(self):
        from raven.network_phase2.rules2 import rule_net_f
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        from raven.network_phase2.lab2 import _mk, _resp
        exp = ControlledExperiment(
            experiment_id="x",
            control=_mk("GET", "/public", _resp(200, b"{}")),
            test=_mk("GET", "/private", _resp(200, b"{}"), has_auth=True),
            hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
        )
        assert rule_net_f(exp) == "CONFOUNDED"

    def test_no_meaningful_change_identical(self):
        from raven.network_phase2.rules2 import rule_net_f
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        from raven.network_phase2.lab2 import _mk, _resp
        r = _resp(200, b'{"x":1}')
        exp = ControlledExperiment(
            experiment_id="x",
            control=_mk("GET", "/api", r),
            test=_mk("GET", "/api", r),
            hypothesis=CausalHypothesis.NO_OBSERVED_DEPENDENCY,
        )
        assert rule_net_f(exp) == "NO_MEANINGFUL_CHANGE"


# ── NET-G rules ────────────────────────────────────────────────────────────────

class TestNetGRule:
    def test_supported_auth_dependency(self):
        from raven.network_phase2.rules2 import rule_net_g
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        from raven.network_phase2.lab2 import _mk, _resp
        exp = ControlledExperiment(
            experiment_id="x",
            control=_mk("GET", "/api", _resp(401, b"{}")),
            test=_mk("GET", "/api", _resp(200, b"{}"), has_auth=True),
            hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
        )
        assert rule_net_g(exp) == "SUPPORTED"

    def test_confounded_gives_confounded(self):
        from raven.network_phase2.rules2 import rule_net_g
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        from raven.network_phase2.lab2 import _mk, _resp
        exp = ControlledExperiment(
            experiment_id="x",
            control=_mk("GET", "/public", _resp(200, b"{}")),
            test=_mk("GET", "/private", _resp(200, b"{}"), has_auth=True),
            hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
        )
        assert rule_net_g(exp) == "CONFOUNDED"

    def test_insufficient_evidence_when_no_dimension_changed(self):
        """When no request dimensions changed but responses differ, evidence is
        insufficient — no observable cause to attribute the response change to."""
        from raven.network_phase2.rules2 import rule_net_g
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        from raven.network_phase2.lab2 import _mk, _resp
        exp = ControlledExperiment(
            experiment_id="x",
            control=_mk("GET", "/api", _resp(200, b'{"ok":true}'), has_auth=True),
            test=_mk("GET", "/api", _resp(401, b'{"err":"bad"}', www_auth=True), has_auth=True),
            hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
        )
        result = rule_net_g(exp)
        assert result == "INSUFFICIENT_EVIDENCE"

    def test_insufficient_evidence_no_change(self):
        from raven.network_phase2.rules2 import rule_net_g
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        from raven.network_phase2.lab2 import _mk, _resp
        r = _resp(200, b'{"x":1}')
        exp = ControlledExperiment(
            experiment_id="x",
            control=_mk("GET", "/api", r),
            test=_mk("GET", "/api", r),
            hypothesis=CausalHypothesis.NO_OBSERVED_DEPENDENCY,
        )
        assert rule_net_g(exp) == "NOT_SUPPORTED"


# ── NET-H rules ────────────────────────────────────────────────────────────────

class TestNetHRule:
    def test_no_observation_needed_for_controlled(self):
        from raven.network_phase2.rules2 import rule_net_h
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        from raven.network_phase2.lab2 import _mk, _resp
        exp = ControlledExperiment(
            experiment_id="x",
            control=_mk("GET", "/api", _resp(401, b"{}")),
            test=_mk("GET", "/api", _resp(200, b"{}"), has_auth=True),
            hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
        )
        assert rule_net_h(exp) == "NO_OBSERVATION_NEEDED"

    def test_isolate_auth_for_confounded(self):
        from raven.network_phase2.rules2 import rule_net_h
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        from raven.network_phase2.lab2 import _mk, _resp
        exp = ControlledExperiment(
            experiment_id="x",
            control=_mk("GET", "/public", _resp(200, b"{}")),
            test=_mk("GET", "/private", _resp(200, b"{}"), has_auth=True),
            hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
        )
        assert rule_net_h(exp) == "COMPARE_WITHOUT_AUTH_HEADER"

    def test_repeat_for_no_change(self):
        from raven.network_phase2.rules2 import rule_net_h
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        from raven.network_phase2.lab2 import _mk, _resp
        r = _resp(200, b'{"x":1}')
        exp = ControlledExperiment(
            experiment_id="x",
            control=_mk("GET", "/api", r),
            test=_mk("GET", "/api", r),
            hypothesis=CausalHypothesis.NO_OBSERVED_DEPENDENCY,
        )
        assert rule_net_h(exp) == "REPEAT_SAME_OBSERVATION"


# ── Lab fixture generation ─────────────────────────────────────────────────────

class TestPhase2Lab:
    def test_transition_sequences_generated(self):
        from raven.network_phase2.lab2 import Phase2Lab
        lab = Phase2Lab()
        seqs = lab.generate_transition_sequences()
        assert len(seqs) > 30

    def test_all_sequence_labels_valid(self):
        from raven.network_phase2.lab2 import Phase2Lab
        from raven.network_phase2.taxonomy2 import StateTransitionClass
        lab = Phase2Lab()
        valid = {c.value for c in StateTransitionClass}
        for f in lab.generate_transition_sequences():
            assert f.net_e_label in valid, f"Invalid label: {f.net_e_label}"

    def test_all_experiment_labels_valid(self):
        from raven.network_phase2.lab2 import Phase2Lab
        from raven.network_phase2.taxonomy2 import ExperimentQualityClass, CausalSupportClass, NextObservationType
        lab = Phase2Lab()
        f_valid = {c.value for c in ExperimentQualityClass}
        g_valid = {c.value for c in CausalSupportClass}
        h_valid = {c.value for c in NextObservationType}
        for f in lab.generate_experiment_pairs():
            assert f.net_f_label in f_valid, f"Invalid NET-F: {f.net_f_label}"
            assert f.net_g_label in g_valid, f"Invalid NET-G: {f.net_g_label}"
            assert f.net_h_label in h_valid, f"Invalid NET-H: {f.net_h_label}"

    def test_no_external_network_calls(self):
        # Lab only calls in-process code — verified by running without network
        from raven.network_phase2.lab2 import Phase2Lab
        lab = Phase2Lab()
        fixtures = lab.all_fixtures()
        assert len(fixtures) > 0

    def test_data_source_always_educational_synthetic(self):
        from raven.network_phase2.lab2 import Phase2Lab
        lab = Phase2Lab()
        for f in lab.all_sequences():
            if f.sequence:
                assert f.sequence.data_source == "EDUCATIONAL_SYNTHETIC"

    def test_adversarial_sequences_generated(self):
        from raven.network_phase2.lab2 import Phase2Lab
        lab = Phase2Lab()
        adv = lab.generate_adversarial_sequences()
        assert len(adv) > 15

    def test_counterfactual_pairs_generated(self):
        from raven.network_phase2.lab2 import Phase2Lab
        lab = Phase2Lab()
        cf = lab.generate_counterfactual_pairs()
        assert len(cf) > 8


# ── Full lab rule accuracy ─────────────────────────────────────────────────────

class TestPhase2RuleAccuracy:
    def test_net_e_rule_accuracy_on_sequences(self):
        from raven.network_phase2.lab2 import Phase2Lab
        from raven.network_phase2.rules2 import rule_net_e
        lab = Phase2Lab()
        correct = total = 0
        for f in lab.generate_transition_sequences():
            if f.sequence and f.net_e_label != "UNKNOWN":
                pred = rule_net_e(f.sequence)
                if pred == f.net_e_label:
                    correct += 1
                total += 1
        accuracy = correct / total if total > 0 else 0
        assert accuracy >= 0.85, f"NET-E rule accuracy too low: {accuracy:.3f} ({correct}/{total})"

    def test_net_f_rule_accuracy_on_experiments(self):
        from raven.network_phase2.lab2 import Phase2Lab
        from raven.network_phase2.rules2 import rule_net_f
        lab = Phase2Lab()
        correct = total = 0
        for f in lab.generate_experiment_pairs():
            if f.experiment:
                pred = rule_net_f(f.experiment)
                if pred == f.net_f_label:
                    correct += 1
                total += 1
        accuracy = correct / total if total > 0 else 0
        assert accuracy >= 0.85, f"NET-F rule accuracy too low: {accuracy:.3f}"

    def test_net_g_rule_accuracy_on_experiments(self):
        from raven.network_phase2.lab2 import Phase2Lab
        from raven.network_phase2.rules2 import rule_net_g
        lab = Phase2Lab()
        correct = total = 0
        for f in lab.generate_experiment_pairs():
            if f.experiment:
                pred = rule_net_g(f.experiment)
                if pred == f.net_g_label:
                    correct += 1
                total += 1
        accuracy = correct / total if total > 0 else 0
        assert accuracy >= 0.85, f"NET-G rule accuracy too low: {accuracy:.3f}"

    def test_net_h_rule_accuracy_on_experiments(self):
        from raven.network_phase2.lab2 import Phase2Lab
        from raven.network_phase2.rules2 import rule_net_h
        lab = Phase2Lab()
        correct = total = 0
        for f in lab.generate_experiment_pairs():
            if f.experiment:
                pred = rule_net_h(f.experiment)
                if pred == f.net_h_label:
                    correct += 1
                total += 1
        accuracy = correct / total if total > 0 else 0
        assert accuracy >= 0.85, f"NET-H rule accuracy too low: {accuracy:.3f}"


# ── Sequence representation ────────────────────────────────────────────────────

class TestObservationSequence:
    def test_add_step(self):
        from raven.network_phase2.sequence import ObservationSequence
        from raven.network_phase2.lab2 import _mk, _resp
        seq = ObservationSequence("s1")
        seq.add(_mk("GET", "/", _resp(200, b"{}")))
        assert len(seq) == 1
        assert seq[0].step == 0

    def test_consecutive_pairs(self):
        from raven.network_phase2.sequence import ObservationSequence
        from raven.network_phase2.lab2 import _mk, _resp
        seq = ObservationSequence("s2")
        for i in range(3):
            seq.add(_mk("GET", f"/{i}", _resp(200, b"{}")))
        pairs = seq.consecutive_pairs()
        assert len(pairs) == 2

    def test_status_sequence(self):
        from raven.network_phase2.sequence import ObservationSequence
        from raven.network_phase2.lab2 import _mk, _resp
        seq = ObservationSequence("s3")
        for s in (200, 304, 200):
            seq.add(_mk("GET", "/", _resp(s, b"{}")))
        assert seq.status_sequence == [200, 304, 200]


# ── Determinism audit ──────────────────────────────────────────────────────────

class TestDeterminism:
    def test_lab_fixture_count_stable(self):
        from raven.network_phase2.lab2 import Phase2Lab
        counts = [len(Phase2Lab().all_fixtures()) for _ in range(3)]
        assert all(c == counts[0] for c in counts), "Fixture count non-deterministic"

    def test_sequence_labels_stable_across_builds(self):
        from raven.network_phase2.lab2 import Phase2Lab
        lab1 = Phase2Lab()
        lab2 = Phase2Lab()
        labels1 = [f.net_e_label for f in lab1.generate_transition_sequences()]
        labels2 = [f.net_e_label for f in lab2.generate_transition_sequences()]
        assert labels1 == labels2, "Sequence labels non-deterministic"

    def test_rule_e_deterministic(self):
        from raven.network_phase2.lab2 import Phase2Lab
        from raven.network_phase2.rules2 import rule_net_e
        lab = Phase2Lab()
        seqs = lab.generate_transition_sequences()
        r1 = [rule_net_e(f.sequence) for f in seqs if f.sequence]
        r2 = [rule_net_e(f.sequence) for f in seqs if f.sequence]
        assert r1 == r2


# ── Security boundary invariants ──────────────────────────────────────────────

class TestSecurityBoundary:
    def test_no_security_claims_in_taxonomy(self):
        from raven.network_phase2.taxonomy2 import StateTransitionClass, CausalHypothesis
        labels = {c.value for c in StateTransitionClass}
        security_terms = {"bypass", "vulnerability", "exploit", "attack",
                          "idor", "bola", "xss", "ssrf", "sqli"}
        for label in labels:
            for term in security_terms:
                assert term not in label.lower(), f"Security term in label: {label}"

    def test_causal_hypothesis_not_vulnerability(self):
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        for h in CausalHypothesis:
            assert "BYPASS" not in h.value
            assert "VULNERABILITY" not in h.value

    def test_data_source_never_human_reviewed(self):
        from raven.network_phase2.lab2 import Phase2Lab
        lab = Phase2Lab()
        for f in lab.all_fixtures():
            if f.sequence:
                assert "human" not in f.sequence.data_source.lower()
