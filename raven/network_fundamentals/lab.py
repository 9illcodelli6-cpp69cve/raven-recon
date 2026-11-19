"""RAVEN Network Fundamentals — local in-process fixture lab (v3).

Changelog v3:
- Cache semantics families for NET-B (ETag/304 → EXPECTED_CHANGE)
- NO_CHANGE diversity: text/plain family prevents is_json shortcut
- Content-negotiation EXPECTED_CHANGE families
- ETag helper _resp_etag() and _resp_304()

Provides systematic synthetic HTTP exchange fixtures for training and testing.
ALL exchanges are fabricated in-process; NO real network I/O occurs.

Design principles (Phase 10-11):
- Each class has ≥2 scenario_families so stratified grouped splitting
  can put at least 1 family per class in training.
- Irrelevant properties vary within families (body content, path, timing)
  so the model cannot memorize templates.
- Counterfactual examples force the model away from naive proxies
  (e.g. body content != protocol class).
- timed_out and connection_error families cover both NETWORK_FAILURE variants.

INVARIANTS:
- No socket creation.
- No external HTTP requests.
- No user credentials.
- Fixtures labelled EDUCATIONAL_SYNTHETIC only.
- is_security_relevant never set True by lab code.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from raven.network_fundamentals.observation import NetworkObservation, NetworkResponse
from raven.network_fundamentals.taxonomy import (
    ProtocolClass, DifferenceClass, SessionState, AuthContext,
)

# ── Fixture dataclass ─────────────────────────────────────────────────────────

@dataclass
class Fixture:
    """A labelled in-process HTTP exchange for training."""
    observation: NetworkObservation
    protocol_label: str
    difference_label: str
    session_label: str
    auth_label: str
    fixture_id: str
    family: str    # scenario_family — unit of grouped splitting


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resp(status: int, body: bytes = b"", *,
          ct: str = "application/json",
          location: Optional[str] = None,
          www_auth: bool = False,
          set_cookie: bool = False,
          retry_after: bool = False,
          elapsed_ms: int = 40,
          timed_out: bool = False,
          connection_error: bool = False) -> NetworkResponse:
    if timed_out or connection_error:
        r = NetworkResponse.error(timed_out=timed_out, connection_error=connection_error)
        r.elapsed_ms = elapsed_ms
        return r
    headers: dict = {"content-type": ct}
    if location:
        headers["location"] = location
    if www_auth:
        headers["www-authenticate"] = 'Bearer realm="api"'
    if set_cookie:
        headers["set-cookie"] = "<REDACTED>"
    if retry_after:
        headers["retry-after"] = "60"
    return NetworkResponse.from_raw(status, headers, body, elapsed_ms=elapsed_ms)


def _resp_etag(status: int, body: bytes, etag: str, *,
               ct: str = "application/json", elapsed_ms: int = 30) -> NetworkResponse:
    """Create a response with an ETag header (cacheable resource)."""
    headers = {"content-type": ct, "etag": f'"{etag}"'}
    return NetworkResponse.from_raw(status, headers, body, elapsed_ms=elapsed_ms)


def _resp_304(etag: str = "") -> NetworkResponse:
    """Create a 304 Not Modified response (cache still valid, no body)."""
    headers = {"etag": f'"{etag}"'} if etag else {}
    return NetworkResponse.from_raw(304, headers, b"", elapsed_ms=5)


def _obs(method: str, path: str, resp: NetworkResponse, *,
         has_auth: bool = False,
         cmp: Optional[NetworkResponse] = None,
         family: str = "",
         if_none_match: str = "") -> NetworkObservation:
    req_h: dict = {"accept": "application/json"}
    if has_auth:
        req_h["authorization"] = "<REDACTED>"
    if if_none_match:
        req_h["if-none-match"] = f'"{if_none_match}"'
    return NetworkObservation.from_exchange(
        method=method, path=path, query_string="",
        request_headers=req_h,
        response=resp,
        comparison_response=cmp,
        fixture_family=family,
    )


# ── Body templates — varied so model can't memorize ──────────────────────────

_JSON_200_BODIES = [
    b'{"items":[]}',
    b'{"data":{"id":1,"name":"alice"}}',
    b'{"count":42,"results":[{"id":1}]}',
    b'{"status":"ok","timestamp":"2026-10-04T00:00:00Z"}',
    b'{"page":1,"total":100,"items":[{"key":"val"}]}',
]
_JSON_400_BODIES = [
    b'{"error":"bad_request","detail":"missing field"}',
    b'{"code":"VALIDATION_FAILED","errors":[]}',
    b'{"message":"invalid input","field":"email"}',
]
_JSON_401_BODIES = [
    b'{"error":"unauthorized","message":"Token required"}',
    b'{"code":"AUTH_REQUIRED","hint":"Provide Bearer token"}',
    b'{"status":"401","message":"Authentication required"}',
    b'{"error":"invalid_token"}',
]
_JSON_403_BODIES = [
    b'{"error":"forbidden","message":"Insufficient permissions"}',
    b'{"code":"ACCESS_DENIED","resource":"/admin"}',
    b'{"error":"forbidden"}',
    b'{"status":"403","detail":"Not authorized for this resource"}',
]
_JSON_500_BODIES = [
    b'{"error":"internal_server_error"}',
    b'{"code":"INTERNAL_ERROR","request_id":"abc123"}',
    b'{"message":"An unexpected error occurred"}',
]
_HTML_200 = b"<!DOCTYPE html><html><body><h1>Welcome</h1></body></html>"
_HTML_403 = b"<html><body><h1>403 Forbidden</h1></body></html>"
_HTML_500 = b"<html><body><h1>500 Internal Server Error</h1></body></html>"
_COUNTERFACTUAL_BODY_ERROR_IN_200 = b'{"error":"permission_denied","status":"error"}'
_COUNTERFACTUAL_BODY_NORMAL_IN_500 = b'<html><body>Hello World</body></html>'


# ── NET-A: Protocol Behavior ──────────────────────────────────────────────────

class LocalNetworkLab:
    """v2: Each class has ≥2 scenario_families for valid grouped splits.

    Counterfactual examples included per Phase 11 requirements.
    Irrelevant properties vary within families (body, path, timing, method).
    """

    def generate_protocol_fixtures(self) -> list[Fixture]:
        out: list[Fixture] = []

        def _add(fid: str, obs: NetworkObservation, proto: ProtocolClass,
                 sess: SessionState, auth: AuthContext, family: str) -> None:
            obs.fixture_family = family
            obs.protocol_label  = proto.value
            obs.session_label   = sess.value
            obs.auth_label      = auth.value
            obs.difference_label = DifferenceClass.UNKNOWN.value
            out.append(Fixture(
                observation=obs, protocol_label=proto.value,
                difference_label=DifferenceClass.UNKNOWN.value,
                session_label=sess.value, auth_label=auth.value,
                fixture_id=fid, family=family,
            ))

        # ── NORMAL_SUCCESS ────────────────────────────────────────────────────
        # Family A: standard JSON 200 responses (varied body/path/timing)
        for i, body in enumerate(_JSON_200_BODIES):
            _add(f"ns_json_{i}", _obs("GET", f"/api/resource/{i}",
                _resp(200, body, elapsed_ms=20 + i * 10)),
                ProtocolClass.NORMAL_SUCCESS, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "normal_success_json")
        # Family B: non-JSON, 201, 204 (vary content type, method, status)
        _add("ns_html", _obs("GET", "/index.html",
            _resp(200, _HTML_200, ct="text/html", elapsed_ms=30)),
            ProtocolClass.NORMAL_SUCCESS, SessionState.ANONYMOUS, AuthContext.PUBLIC,
            "normal_success_other")
        _add("ns_201", _obs("POST", "/api/items",
            _resp(201, b'{"id":42,"created":true}', elapsed_ms=55)),
            ProtocolClass.NORMAL_SUCCESS, SessionState.ANONYMOUS, AuthContext.PUBLIC,
            "normal_success_other")
        _add("ns_204", _obs("DELETE", "/api/items/1",
            _resp(204, b"", elapsed_ms=25), has_auth=True),
            ProtocolClass.NORMAL_SUCCESS, SessionState.AUTHENTICATED, AuthContext.USER_AUTHENTICATED,
            "normal_success_other")
        _add("ns_200_auth", _obs("GET", "/api/profile",
            _resp(200, b'{"name":"bob","role":"user"}', set_cookie=True, elapsed_ms=45),
            has_auth=True),
            ProtocolClass.NORMAL_SUCCESS, SessionState.AUTHENTICATED, AuthContext.USER_AUTHENTICATED,
            "normal_success_other")
        # Counterfactual: 200 with error-looking body (protocol class is still SUCCESS)
        _add("ns_cf_error_body", _obs("POST", "/api/submit",
            _resp(200, _COUNTERFACTUAL_BODY_ERROR_IN_200, elapsed_ms=35)),
            ProtocolClass.NORMAL_SUCCESS, SessionState.ANONYMOUS, AuthContext.PUBLIC,
            "normal_success_counterfactual")

        # ── REDIRECT ─────────────────────────────────────────────────────────
        # Family A: permanent redirects (301, 308)
        for status, fid in [(301, "redir_301_a"), (301, "redir_301_b"),
                             (308, "redir_308_a"), (308, "redir_308_b")]:
            _add(fid, _obs("GET", "/old-path",
                _resp(status, b"", location="https://app.example.test/new", elapsed_ms=15)),
                ProtocolClass.REDIRECT, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "redirect_permanent")
        # Family B: temporary redirects (302, 303, 307) + redirect without body
        for status, fid in [(302, "redir_302_a"), (302, "redir_302_b"),
                             (303, "redir_303"), (307, "redir_307")]:
            _add(fid, _obs("POST", "/login",
                _resp(status, b"", location="https://app.example.test/dashboard", elapsed_ms=25)),
                ProtocolClass.REDIRECT, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "redirect_temporary")

        # ── AUTH_REQUIRED ─────────────────────────────────────────────────────
        # Family A: 401 with WWW-Authenticate header
        for i, body in enumerate(_JSON_401_BODIES[:3]):
            _add(f"auth_req_www_{i}", _obs("GET", f"/api/endpoint/{i}",
                _resp(401, body, www_auth=True, elapsed_ms=20)),
                ProtocolClass.AUTH_REQUIRED, SessionState.ANONYMOUS, AuthContext.AUTH_REQUIRED,
                "auth_required_with_www_auth")
        # Family B: 401 without WWW-Authenticate (also AUTH_REQUIRED by protocol)
        for i, body in enumerate(_JSON_401_BODIES[1:]):
            _add(f"auth_req_no_www_{i}", _obs("GET", "/api/me",
                _resp(401, body, elapsed_ms=18)),
                ProtocolClass.AUTH_REQUIRED, SessionState.ANONYMOUS, AuthContext.AUTH_REQUIRED,
                "auth_required_no_www_auth")

        # ── FORBIDDEN ─────────────────────────────────────────────────────────
        # Family A: 403 JSON (authenticated user, insufficient permissions)
        for i, body in enumerate(_JSON_403_BODIES[:3]):
            _add(f"forbidden_json_{i}", _obs("GET", "/admin/users",
                _resp(403, body, elapsed_ms=22), has_auth=True),
                ProtocolClass.FORBIDDEN, SessionState.AUTHENTICATED, AuthContext.USER_AUTHENTICATED,
                "forbidden_json")
        # Family B: 403 HTML + counterfactual (403 on public static content)
        _add("forbidden_html_a", _obs("GET", "/admin",
            _resp(403, _HTML_403, ct="text/html", elapsed_ms=18), has_auth=True),
            ProtocolClass.FORBIDDEN, SessionState.AUTHENTICATED, AuthContext.USER_AUTHENTICATED,
            "forbidden_html")
        _add("forbidden_html_b", _obs("GET", "/secret.txt",
            _resp(403, _HTML_403, ct="text/html", elapsed_ms=20), has_auth=False),
            ProtocolClass.FORBIDDEN, SessionState.ANONYMOUS, AuthContext.PUBLIC,
            "forbidden_html")
        _add("forbidden_json_b", _obs("DELETE", "/api/items/1",
            _resp(403, _JSON_403_BODIES[3], elapsed_ms=24), has_auth=True),
            ProtocolClass.FORBIDDEN, SessionState.AUTHENTICATED, AuthContext.USER_AUTHENTICATED,
            "forbidden_json")

        # ── RATE_LIMITED ──────────────────────────────────────────────────────
        # Family A: 429 with Retry-After
        for i in range(3):
            _add(f"rate_with_retry_{i}", _obs("GET", "/api/items",
                _resp(429, b'{"error":"rate_limited","retry_after":60}',
                      retry_after=True, elapsed_ms=15)),
                ProtocolClass.RATE_LIMITED, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "rate_limited_with_retry")
        # Family B: 429 without Retry-After (also RATE_LIMITED by status code)
        for i in range(3):
            _add(f"rate_no_retry_{i}", _obs("POST", "/api/submit",
                _resp(429, b'{"error":"too_many_requests"}', elapsed_ms=12)),
                ProtocolClass.RATE_LIMITED, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "rate_limited_no_retry")

        # ── SERVER_ERROR ──────────────────────────────────────────────────────
        # Family A: direct server errors (500, 503)
        for status, fid in [(500, "srv_500_a"), (500, "srv_500_b"),
                             (503, "srv_503_a"), (503, "srv_503_b")]:
            _add(fid, _obs("GET", "/api/data",
                _resp(status, _JSON_500_BODIES[status % len(_JSON_500_BODIES)], elapsed_ms=120)),
                ProtocolClass.SERVER_ERROR, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "server_error_direct")
        # Family B: gateway errors (502, 504) + counterfactual (500 with normal-looking body)
        for status, fid in [(502, "srv_502"), (504, "srv_504")]:
            _add(fid, _obs("GET", "/api/data",
                _resp(status, b"Bad Gateway", ct="text/plain", elapsed_ms=5000)),
                ProtocolClass.SERVER_ERROR, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "server_error_gateway")
        _add("srv_cf_normal_body", _obs("GET", "/",
            _resp(500, _COUNTERFACTUAL_BODY_NORMAL_IN_500, ct="text/html", elapsed_ms=80)),
            ProtocolClass.SERVER_ERROR, SessionState.ANONYMOUS, AuthContext.PUBLIC,
            "server_error_gateway")

        # ── CLIENT_ERROR ──────────────────────────────────────────────────────
        # Family A: validation errors (400, 422)
        for status, fid in [(400, "ce_400_a"), (400, "ce_400_b"),
                             (422, "ce_422_a"), (422, "ce_422_b")]:
            _add(fid, _obs("POST", "/api/items",
                _resp(status, _JSON_400_BODIES[status % len(_JSON_400_BODIES)], elapsed_ms=30)),
                ProtocolClass.CLIENT_ERROR, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "client_error_validation")
        # Family B: resource/method errors (404, 405, 409, 415)
        for status, fid, path in [
            (404, "ce_404", "/api/items/999"),
            (405, "ce_405", "/api/items"),
            (409, "ce_409", "/api/users"),
            (415, "ce_415", "/api/upload"),
        ]:
            _add(fid, _obs("GET", path,
                _resp(status, b'{"error":"client_error"}', elapsed_ms=20)),
                ProtocolClass.CLIENT_ERROR, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "client_error_resource")

        # ── NETWORK_FAILURE ───────────────────────────────────────────────────
        # Family A: connection error (TCP refused/reset)
        for i in range(4):
            _add(f"net_connfail_{i}", _obs("GET", "/api/data",
                _resp(0, connection_error=True, elapsed_ms=10)),
                ProtocolClass.NETWORK_FAILURE, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "network_failure_connection")
        # Family B: timeout
        for i in range(4):
            _add(f"net_timeout_{i}", _obs("GET", "/api/slow",
                _resp(0, timed_out=True, elapsed_ms=30000)),
                ProtocolClass.NETWORK_FAILURE, SessionState.ANONYMOUS, AuthContext.PUBLIC,
                "network_failure_timeout")

        return out

    # ── NET-B: Response Difference ────────────────────────────────────────────

    def generate_difference_fixtures(self) -> list[Fixture]:
        out: list[Fixture] = []

        def _add(fid: str, obs: NetworkObservation,
                 diff: DifferenceClass, family: str) -> None:
            obs.fixture_family = family
            obs.difference_label = diff.value
            obs.protocol_label   = ProtocolClass.UNKNOWN.value
            obs.session_label    = SessionState.UNKNOWN.value
            obs.auth_label       = AuthContext.UNKNOWN.value
            out.append(Fixture(
                observation=obs, protocol_label=ProtocolClass.UNKNOWN.value,
                difference_label=diff.value, session_label=SessionState.UNKNOWN.value,
                auth_label=AuthContext.UNKNOWN.value, fixture_id=fid, family=family,
            ))

        # ── NO_CHANGE ─────────────────────────────────────────────────────────
        # Family A: JSON baseline identical to comparison
        for i, body in enumerate(_JSON_200_BODIES[:3]):
            r = _resp(200, body)
            _add(f"nc_json_{i}", _obs("GET", "/api/items", r, cmp=r),
                DifferenceClass.NO_CHANGE, "no_change_json")
        # Family B: HTML baseline identical to comparison
        r_html = _resp(200, _HTML_200, ct="text/html")
        for i in range(3):
            _add(f"nc_html_{i}", _obs("GET", "/index.html", r_html, cmp=r_html),
                DifferenceClass.NO_CHANGE, "no_change_html")
        # Family C: text/plain — prevents is_json shortcut
        for i in range(3):
            r_txt = _resp(200, f"key=value{i}\nother=data".encode(), ct="text/plain")
            _add(f"nc_text_{i}", _obs("GET", f"/api/config/{i}", r_txt, cmp=r_txt),
                DifferenceClass.NO_CHANGE, "no_change_text")

        # ── CONTENT_CHANGE ────────────────────────────────────────────────────
        # Family A: same-length JSON with different field values (bc_ch=1, bl_ch=0)
        for i in range(3):
            r_a = _resp(200, f'{{"count":{i},"page":1}}'.encode())
            r_b = _resp(200, f'{{"count":{i+10},"page":1}}'.encode())
            _add(f"cc_samelength_{i}", _obs("GET", "/api/count", r_a, cmp=r_b),
                DifferenceClass.CONTENT_CHANGE, "content_change_samelength")
        # Family B: dynamic data (timestamp/random values — different lengths)
        for i in range(3):
            r_a = _resp(200, f'{{"ts":"2026-10-0{i+1}T00:00:00Z","val":{i}}}'.encode())
            r_b = _resp(200, f'{{"ts":"2026-10-0{i+2}T00:00:00Z","val":{i+100}}}'.encode())
            _add(f"cc_dynamic_{i}", _obs("GET", "/api/snapshot", r_a, cmp=r_b),
                DifferenceClass.CONTENT_CHANGE, "content_change_dynamic")
        # Family C: HTML content changed (prevents JSON-only training bias)
        for i in range(3):
            r_a = _resp(200, f"<html><body>Version {i}</body></html>".encode(), ct="text/html")
            r_b = _resp(200, f"<html><body>Version {i+1}</body></html>".encode(), ct="text/html")
            _add(f"cc_html_{i}", _obs("GET", "/docs", r_a, cmp=r_b),
                DifferenceClass.CONTENT_CHANGE, "content_change_html")

        # ── AUTH_STATE_CHANGE ─────────────────────────────────────────────────
        # Family A: 200 → 401 (session expired)
        for i in range(3):
            r_ok   = _resp(200, _JSON_200_BODIES[i % len(_JSON_200_BODIES)])
            r_unau = _resp(401, _JSON_401_BODIES[i % len(_JSON_401_BODIES)], www_auth=True)
            _add(f"asc_401_{i}", _obs("GET", "/api/me", r_ok, cmp=r_unau, has_auth=True),
                DifferenceClass.AUTH_STATE_CHANGE, "auth_state_change_401")
        # Family B: 200 → 403 (authorization revoked)
        for i in range(3):
            r_ok  = _resp(200, b'{"admin":true}')
            r_for = _resp(403, _JSON_403_BODIES[i % len(_JSON_403_BODIES)])
            _add(f"asc_403_{i}", _obs("GET", "/admin/data", r_ok, cmp=r_for, has_auth=True),
                DifferenceClass.AUTH_STATE_CHANGE, "auth_state_change_403")

        # ── STRUCTURAL_CHANGE ─────────────────────────────────────────────────
        # Primary IS the structural-change response; comparison is prior working 200.
        # Rule: st_ch==1 and is_3xx==1 (redirect) or not is_2xx (404) fire on PRIMARY.
        # Family A: permanent redirect (current is 301, previous was 200 direct)
        for i in range(3):
            r_ok    = _resp(200, b'{"items":[]}')
            r_redir = _resp(301, b"", location="https://new.example.test/api")
            _add(f"sc_redirect_{i}", _obs("GET", "/old", r_redir, cmp=r_ok),
                DifferenceClass.STRUCTURAL_CHANGE, "structural_change_redirect")
        # Family B: resource gone (current is 404, previous was 200 — endpoint removed)
        for i in range(3):
            r_ok  = _resp(200, b'{"found":true}')
            r_404 = _resp(404, b'{"error":"not_found"}')
            _add(f"sc_404_{i}", _obs("GET", f"/api/items/{i}", r_404, cmp=r_ok),
                DifferenceClass.STRUCTURAL_CHANGE, "structural_change_status")

        # ── TRANSIENT ─────────────────────────────────────────────────────────
        # Primary IS the 5xx (current transient error); comparison is prior 200.
        # Rule: st_ch==1 and is_5xx==1 fires correctly on primary=5xx.
        # Family A: 503 (service temporarily unavailable) vs prior 200
        for i in range(3):
            r_ok  = _resp(200, b'{"ok":true}')
            r_503 = _resp(503, b'{"error":"service_unavailable"}')
            _add(f"tr_503_{i}", _obs("GET", "/api/items", r_503, cmp=r_ok),
                DifferenceClass.TRANSIENT, "transient_503")
        # Family B: 502 (bad gateway) vs prior 200
        for i in range(3):
            r_ok  = _resp(200, b'{"ok":true}')
            r_502 = _resp(502, b"Bad Gateway", ct="text/plain")
            _add(f"tr_502_{i}", _obs("GET", "/api/items", r_502, cmp=r_ok),
                DifferenceClass.TRANSIENT, "transient_502")

        # ── EXPECTED_CHANGE ───────────────────────────────────────────────────
        # NOTE: EXPECTED_CHANGE uses cache-semantics signals only.
        # Pagination-style (200→200 body diff) was REMOVED: it is indistinguishable
        # from CONTENT_CHANGE in the 29-feature schema (cmp_is_304=0, body_content_changed=1).
        # Family A: primary IS a 304 (is_304=1), comparison was a 200 (reversed cache perspective)
        for i in range(3):
            r_304 = _resp_304(f"rev{i}")
            r_200 = _resp_etag(200, _JSON_200_BODIES[i % len(_JSON_200_BODIES)], f"rev{i}")
            _add(f"ec_rev_{i}", _obs("GET", f"/api/res/v/{i}", r_304, cmp=r_200),
                DifferenceClass.EXPECTED_CHANGE, "expected_change_rev_cache")
        # Family B: ETag cache hit — 304 as comparison (cmp_is_304=1 signal)
        for i in range(3):
            etag  = f"abc{i}"
            r_200 = _resp_etag(200, _JSON_200_BODIES[i % len(_JSON_200_BODIES)], etag)
            r_304 = _resp_304(etag)
            _add(f"ec_etag_{i}", _obs("GET", f"/api/res/{i}", r_200, cmp=r_304,
                                       if_none_match=etag),
                DifferenceClass.EXPECTED_CHANGE, "expected_change_etag")
        # Family C: Last-Modified style cache validation (plain 304, no ETag)
        for i in range(3):
            r_200 = _resp(200, _JSON_200_BODIES[i % len(_JSON_200_BODIES)])
            r_304 = _resp_304()
            _add(f"ec_lm_{i}", _obs("GET", f"/api/cached/{i}", r_200, cmp=r_304),
                DifferenceClass.EXPECTED_CHANGE, "expected_change_last_modified")

        return out

    # ── NET-C: Session State ──────────────────────────────────────────────────

    def generate_session_fixtures(self) -> list[Fixture]:
        out: list[Fixture] = []

        def _add(fid: str, obs: NetworkObservation,
                 sess: SessionState, family: str) -> None:
            obs.fixture_family = family
            obs.session_label    = sess.value
            obs.protocol_label   = ProtocolClass.UNKNOWN.value
            obs.difference_label = DifferenceClass.UNKNOWN.value
            obs.auth_label       = AuthContext.UNKNOWN.value
            out.append(Fixture(
                observation=obs, protocol_label=ProtocolClass.UNKNOWN.value,
                difference_label=DifferenceClass.UNKNOWN.value,
                session_label=sess.value, auth_label=AuthContext.UNKNOWN.value,
                fixture_id=fid, family=family,
            ))

        # ── ANONYMOUS ─────────────────────────────────────────────────────────
        for i, body in enumerate(_JSON_200_BODIES[:3]):
            _add(f"anon_api_{i}", _obs("GET", f"/api/public/{i}", _resp(200, body)),
                SessionState.ANONYMOUS, "anonymous_public_api")
        for i in range(3):
            _add(f"anon_html_{i}", _obs("GET", f"/page/{i}",
                _resp(200, _HTML_200, ct="text/html")),
                SessionState.ANONYMOUS, "anonymous_html")

        # ── AUTHENTICATED ─────────────────────────────────────────────────────
        for i in range(3):
            _add(f"authed_get_{i}", _obs("GET", f"/api/profile/{i}",
                _resp(200, b'{"user":"alice","role":"user"}'),
                has_auth=True),
                SessionState.AUTHENTICATED, "authenticated_get")
        # POST creating a resource — does NOT set cookies (avoids ROTATED confusion)
        for i in range(3):
            _add(f"authed_post_{i}", _obs("POST", "/api/items",
                _resp(201, b'{"id":1,"created":true}'),
                has_auth=True),
                SessionState.AUTHENTICATED, "authenticated_post")

        # ── EXPIRED ───────────────────────────────────────────────────────────
        for i, body in enumerate(_JSON_401_BODIES[:3]):
            _add(f"expired_json_{i}", _obs("GET", "/api/me",
                _resp(401, body, www_auth=True), has_auth=True),
                SessionState.EXPIRED, "expired_json")
        for i in range(3):
            _add(f"expired_html_{i}", _obs("GET", "/dashboard",
                _resp(401, b"<html><body>Session expired</body></html>",
                      ct="text/html", www_auth=True),
                has_auth=True),
                SessionState.EXPIRED, "expired_html")

        # ── INVALID ────────────────────────────────────────────────────────────
        for i in range(3):
            _add(f"invalid_400_{i}", _obs("GET", "/api/items",
                _resp(400, b'{"error":"invalid_token","detail":"malformed JWT"}'),
                has_auth=True),
                SessionState.INVALID, "invalid_malformed")
        for i, body in enumerate(_JSON_401_BODIES[1:]):
            _add(f"invalid_401_{i}", _obs("GET", "/api/secure",
                _resp(401, body), has_auth=True),
                SessionState.INVALID, "invalid_rejected")

        # ── ROTATED ────────────────────────────────────────────────────────────
        for i in range(3):
            _add(f"rotated_login_{i}", _obs("POST", "/login",
                _resp(200, b'{"ok":true,"redirect":"/dashboard"}', set_cookie=True),
                has_auth=False),
                SessionState.ROTATED, "rotated_post_login")
        for i in range(3):
            _add(f"rotated_refresh_{i}", _obs("POST", "/api/token/refresh",
                _resp(200, b'{"token_refreshed":true}', set_cookie=True),
                has_auth=True),
                SessionState.ROTATED, "rotated_token_refresh")

        return out

    # ── NET-D: Authentication Context ────────────────────────────────────────

    def generate_auth_fixtures(self) -> list[Fixture]:
        out: list[Fixture] = []

        def _add(fid: str, obs: NetworkObservation,
                 auth: AuthContext, family: str) -> None:
            obs.fixture_family = family
            obs.auth_label       = auth.value
            obs.protocol_label   = ProtocolClass.UNKNOWN.value
            obs.difference_label = DifferenceClass.UNKNOWN.value
            obs.session_label    = SessionState.UNKNOWN.value
            out.append(Fixture(
                observation=obs, protocol_label=ProtocolClass.UNKNOWN.value,
                difference_label=DifferenceClass.UNKNOWN.value,
                session_label=SessionState.UNKNOWN.value,
                auth_label=auth.value, fixture_id=fid, family=family,
            ))

        # ── PUBLIC ─────────────────────────────────────────────────────────────
        for i, body in enumerate(_JSON_200_BODIES[:3]):
            _add(f"pub_api_{i}", _obs("GET", f"/api/public/{i}", _resp(200, body)),
                AuthContext.PUBLIC, "public_api")
        for i in range(3):
            _add(f"pub_html_{i}", _obs("GET", f"/{i}.html",
                _resp(200, _HTML_200, ct="text/html")),
                AuthContext.PUBLIC, "public_html")

        # ── APPLICATION_AUTHENTICATED ─────────────────────────────────────────
        for i in range(3):
            _add(f"app_apikey_{i}", _obs("GET", f"/api/v1/data/{i}",
                _resp(200, b'{"data":[]}'), has_auth=True),
                AuthContext.APPLICATION_AUTHENTICATED, "app_auth_apikey")
        for i in range(3):
            _add(f"app_client_{i}", _obs("POST", "/oauth/token",
                _resp(200, b'{"access_token":"xxx","token_type":"bearer"}'),
                has_auth=True),
                AuthContext.APPLICATION_AUTHENTICATED, "app_auth_client_creds")

        # ── USER_AUTHENTICATED ────────────────────────────────────────────────
        # Family A: bearer token user session — response refreshes session cookie
        # (Rule: has_au + is_2xx + set_ck → USER_AUTHENTICATED)
        for i in range(3):
            _add(f"user_bearer_{i}", _obs("GET", f"/api/profile/{i}",
                _resp(200, b'{"name":"alice"}', set_cookie=True),
                has_auth=True),
                AuthContext.USER_AUTHENTICATED, "user_auth_bearer")
        # Family B: session-cookie user auth (explicit cookie in response)
        for i in range(3):
            _add(f"user_session_{i}", _obs("GET", "/dashboard",
                _resp(200, b'{"user":"logged_in"}', set_cookie=True),
                has_auth=True),
                AuthContext.USER_AUTHENTICATED, "user_auth_session")
        # Family C: user POST (e.g. update profile) — cookie refresh on success
        for i in range(3):
            _add(f"user_post_{i}", _obs("POST", "/api/user/settings",
                _resp(200, b'{"updated":true}', set_cookie=True),
                has_auth=True),
                AuthContext.USER_AUTHENTICATED, "user_auth_post")
        # Family D: user GET /me endpoint — short-lived JWT refresh in cookie
        for i in range(3):
            _add(f"user_me_{i}", _obs("GET", "/api/me",
                _resp(200, b'{"id":1,"email":"alice@example.test"}', set_cookie=True),
                has_auth=True),
                AuthContext.USER_AUTHENTICATED, "user_auth_me")

        # ── AUTH_REQUIRED ─────────────────────────────────────────────────────
        for i, body in enumerate(_JSON_401_BODIES[:3]):
            _add(f"auth_req_challenge_{i}", _obs("GET", f"/api/secure/{i}",
                _resp(401, body, www_auth=True)),
                AuthContext.AUTH_REQUIRED, "auth_required_challenge")
        for i in range(3):
            _add(f"auth_req_implicit_{i}", _obs("GET", "/api/admin",
                _resp(401, b'{"error":"auth_required"}', www_auth=False)),
                AuthContext.AUTH_REQUIRED, "auth_required_implicit")

        return out

    def all_fixtures(self) -> list[Fixture]:
        return (
            self.generate_protocol_fixtures()
            + self.generate_difference_fixtures()
            + self.generate_session_fixtures()
            + self.generate_auth_fixtures()
        )
