"""RAVEN Network Fundamentals — feature extraction pipeline.

Produces a NetworkFeatureVector for each NetworkObservation.
Vector has 29 fields capturing protocol/application state signals.

CHANGELOG:
  net_v3 (FEATURE_DIM=29):
    - Fixed auth_state_changed: now fires only on 401/403 transitions,
      not on 304↔200 cache transitions (was incorrectly 0↔1 for cache hits)
    - Added is_304: current response is a cache hit (304 Not Modified)
    - Added cmp_is_304: comparison response is a 304 (cache was valid)
    - Added has_etag: response carries ETag header (cacheable resource)
  net_v2 (FEATURE_DIM=26):
    - Added body_content_changed (byte-level diff, catches same-length changes)

INVARIANTS:
- No credential values in features (presence flags only).
- No field auto-implies vulnerability.
- validate() rejects NaN/Inf before any model sees the vector.
- All fields have deterministic missing-value semantics (-1.0 / -1).
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Optional

from raven.network_fundamentals.observation import NetworkObservation
from raven.network_fundamentals.taxonomy import (
    ProtocolClass, DifferenceClass, ResponseDifference,
)

MISSING_F = -1.0
MISSING_I = -1

FEATURE_SCHEMA_VERSION = "net_v3"
FEATURE_DIM = 29


@dataclass
class NetworkFeatureVector:
    """Feature vector for network fundamentals classifiers (NET-A/B/C/D).

    All integer flags are 1/0/-1 (present/absent/unknown).
    All float fields use -1.0 as the missing-value sentinel.
    """
    schema_version: str = FEATURE_SCHEMA_VERSION

    # ── HTTP status ───────────────────────────────────────────────────────
    status_code:  int   = MISSING_I
    status_class: int   = MISSING_I
    is_2xx: int         = MISSING_I
    is_3xx: int         = MISSING_I
    is_4xx: int         = MISSING_I
    is_5xx: int         = MISSING_I

    # ── Auth signals ──────────────────────────────────────────────────────
    has_auth_request:   int = MISSING_I
    has_www_auth:       int = MISSING_I
    has_set_cookie:     int = MISSING_I
    has_location:       int = MISSING_I

    # ── Rate limiting ─────────────────────────────────────────────────────
    has_retry_after:    int = MISSING_I

    # ── Body ─────────────────────────────────────────────────────────────
    body_size:          int   = MISSING_I
    body_entropy:       float = MISSING_F
    is_json:            int   = MISSING_I

    # ── Headers ──────────────────────────────────────────────────────────
    header_count:       int   = MISSING_I
    has_content_type:   int   = MISSING_I

    # ── Timing ───────────────────────────────────────────────────────────
    elapsed_ms:         int   = MISSING_I

    # ── Network errors ───────────────────────────────────────────────────
    timed_out:          int   = MISSING_I
    connection_error:   int   = MISSING_I

    # ── Response difference (for NET-B) ──────────────────────────────────
    status_changed:       int = MISSING_I
    body_length_changed:  int = MISSING_I
    headers_changed:      int = MISSING_I
    # Fixed in net_v3: fires only on 401/403 transitions (not 304↔200)
    auth_state_changed:   int = MISSING_I
    body_content_changed: int = MISSING_I

    # ── Cache semantics (net_v3) ──────────────────────────────────────────
    is_304:              int  = MISSING_I   # primary response is 304 Not Modified
    cmp_is_304:          int  = MISSING_I   # comparison response was 304
    has_etag:            int  = MISSING_I   # response carries ETag (cacheable)

    # ── Path/Method ──────────────────────────────────────────────────────
    path_depth:          int  = MISSING_I
    is_read_method:      int  = MISSING_I

    def validate(self) -> None:
        for name in self.feature_names():
            val = getattr(self, name, None)
            if val is None:
                continue
            try:
                f = float(val)
            except (TypeError, ValueError):
                raise ValueError(f"Feature '{name}' cannot be cast to float: {val!r}")
            if math.isnan(f):
                raise ValueError(f"Feature '{name}' is NaN — rejected")
            if math.isinf(f):
                raise ValueError(f"Feature '{name}' is Inf — rejected")

    def to_list(self) -> list[float]:
        self.validate()
        return [
            self.status_code,
            self.status_class,
            self.is_2xx,
            self.is_3xx,
            self.is_4xx,
            self.is_5xx,
            self.has_auth_request,
            self.has_www_auth,
            self.has_set_cookie,
            self.has_location,
            self.has_retry_after,
            self.body_size,
            self.body_entropy,
            self.is_json,
            self.header_count,
            self.has_content_type,
            self.elapsed_ms,
            self.timed_out,
            self.connection_error,
            self.status_changed,
            self.body_length_changed,
            self.headers_changed,
            self.auth_state_changed,
            self.body_content_changed,
            self.is_304,
            self.cmp_is_304,
            self.has_etag,
            self.path_depth,
            self.is_read_method,
        ]

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "status_code", "status_class",
            "is_2xx", "is_3xx", "is_4xx", "is_5xx",
            "has_auth_request", "has_www_auth", "has_set_cookie", "has_location",
            "has_retry_after",
            "body_size", "body_entropy", "is_json",
            "header_count", "has_content_type",
            "elapsed_ms",
            "timed_out", "connection_error",
            "status_changed", "body_length_changed", "headers_changed",
            "auth_state_changed", "body_content_changed",
            "is_304", "cmp_is_304", "has_etag",
            "path_depth",
            "is_read_method",
        ]

    def schema_hash(self) -> str:
        return hashlib.sha256(
            "|".join(self.feature_names()).encode()
        ).hexdigest()[:16]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


class NetworkFeaturePipeline:
    """Extracts a NetworkFeatureVector from a NetworkObservation."""

    def extract(self, obs: NetworkObservation) -> NetworkFeatureVector:
        resp = obs.response
        if resp is None:
            return NetworkFeatureVector(
                timed_out=0, connection_error=1,
                status_code=0, status_class=MISSING_I,
            )

        body = resp.body or b""
        sc   = resp.status

        # Status class
        if 100 <= sc < 200: sclass = 1
        elif 200 <= sc < 300: sclass = 2
        elif 300 <= sc < 400: sclass = 3
        elif 400 <= sc < 500: sclass = 4
        elif 500 <= sc < 600: sclass = 5
        else: sclass = MISSING_I

        is_json = 0
        if body:
            stripped = body.lstrip()
            if stripped and stripped[0:1] in (b"{", b"["):
                is_json = 1
        ct_lower = resp.content_type.lower()
        has_ct   = int(bool(resp.content_type))
        if "json" in ct_lower:
            is_json = 1

        # Cache presence flags
        resp_keys_lower = {k.lower() for k in resp.headers}
        has_etag_f = int("etag" in resp_keys_lower)

        # Conditional request presence (not a credential — safe to check)
        req_keys_lower = {k.lower() for k in obs.request_headers}
        # Note: has_conditional_req not currently a feature but used in is_304 logic

        path_depth = len([p for p in obs.path.split("/") if p])
        is_read    = int(obs.method.upper() in ("GET", "HEAD", "OPTIONS"))

        # Diff vs comparison
        st_ch = bl_ch = hd_ch = as_ch = bc_ch = MISSING_I
        is_304_f  = int(sc == 304)
        cmp_304_f = MISSING_I

        if obs.comparison_response is not None:
            cmp      = obs.comparison_response
            cmp_body = cmp.body or b""
            st_ch    = int(sc != cmp.status)
            bl_ch    = int(len(body) != len(cmp_body))
            hd_ch    = int(resp.headers != cmp.headers)

            # FIXED in net_v3: auth_state_changed fires only on 401/403 transitions.
            # Previously used (sc in (200,302)) which incorrectly fired for 304↔200.
            as_ch    = int(
                (sc in (401, 403)) != (cmp.status in (401, 403))
            )
            bc_ch    = int(body != cmp_body)
            cmp_304_f = int(cmp.status == 304)

        return NetworkFeatureVector(
            status_code=sc,
            status_class=sclass,
            is_2xx=int(200 <= sc < 300),
            is_3xx=int(300 <= sc < 400),
            is_4xx=int(400 <= sc < 500),
            is_5xx=int(500 <= sc < 600),
            has_auth_request=int(obs.has_auth_header),
            has_www_auth=int(resp.has_www_auth),
            has_set_cookie=int(resp.has_set_cookie),
            has_location=int(resp.has_location),
            has_retry_after=int(resp.has_retry_after),
            body_size=len(body),
            body_entropy=round(_entropy(body), 4) if body else MISSING_F,
            is_json=is_json,
            header_count=len(resp.headers),
            has_content_type=has_ct,
            elapsed_ms=resp.elapsed_ms,
            timed_out=int(resp.timed_out),
            connection_error=int(resp.connection_error),
            status_changed=st_ch,
            body_length_changed=bl_ch,
            headers_changed=hd_ch,
            auth_state_changed=as_ch,
            body_content_changed=bc_ch,
            is_304=is_304_f,
            cmp_is_304=cmp_304_f,
            has_etag=has_etag_f,
            path_depth=path_depth,
            is_read_method=is_read,
        )
