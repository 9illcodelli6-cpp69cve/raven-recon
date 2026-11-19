"""RAVEN Network Fundamentals — observation data structures.

NetworkObservation records a single HTTP exchange for learning purposes.
NetworkResponse records the raw HTTP response side.

INVARIANTS:
- Credentials, Authorization values, Cookie values are NEVER stored.
- is_security_relevant is NEVER auto-set True by observation code.
- These structures are inputs to ML models, not security verdicts.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


EXCLUDED_REQUEST_HEADERS: frozenset[str] = frozenset({
    "authorization", "cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "proxy-authorization",
})

EXCLUDED_RESPONSE_HEADERS: frozenset[str] = frozenset({
    "set-cookie",
})


def _scrub_headers(headers: dict) -> dict:
    """Return a copy of headers with sensitive values replaced by <REDACTED>."""
    return {
        k: ("<REDACTED>" if k.lower() in EXCLUDED_REQUEST_HEADERS
            or k.lower() in EXCLUDED_RESPONSE_HEADERS else v)
        for k, v in headers.items()
    }


@dataclass
class NetworkResponse:
    """One HTTP response, sanitised for safe logging and feature extraction.

    Raw credential header values are never stored — only their presence.
    """
    status: int
    headers: dict = field(default_factory=dict)       # scrubbed — no Set-Cookie values
    body: bytes   = field(default_factory=bytes)
    elapsed_ms: int = 0

    # Derived convenience fields — populated by NetworkObservation.from_exchange()
    content_type: str  = ""
    has_set_cookie: bool = False
    has_location: bool   = False
    has_www_auth: bool   = False
    has_retry_after: bool = False
    timed_out: bool   = False
    connection_error: bool = False

    @classmethod
    def from_raw(cls, status: int, headers: dict, body: bytes,
                 elapsed_ms: int = 0, *,
                 timed_out: bool = False,
                 connection_error: bool = False) -> "NetworkResponse":
        scrubbed = _scrub_headers(headers)
        lower_h  = {k.lower(): v for k, v in headers.items()}
        return cls(
            status=status,
            headers=scrubbed,
            body=body,
            elapsed_ms=elapsed_ms,
            content_type=lower_h.get("content-type", ""),
            has_set_cookie="set-cookie" in lower_h,
            has_location="location" in lower_h,
            has_www_auth="www-authenticate" in lower_h,
            has_retry_after="retry-after" in lower_h,
            timed_out=timed_out,
            connection_error=connection_error,
        )

    @classmethod
    def error(cls, timed_out: bool = False,
              connection_error: bool = True) -> "NetworkResponse":
        return cls(
            status=0, headers={}, body=b"",
            elapsed_ms=0, timed_out=timed_out,
            connection_error=connection_error,
        )


@dataclass
class NetworkObservation:
    """A complete HTTP exchange: request context + response.

    Used as input to the network fundamentals feature pipeline.
    Not a security verdict; is_anomalous is never set by this class.
    """
    # Request context (scrubbed)
    method: str        = "GET"
    path: str          = "/"
    query_string: str  = ""
    request_headers: dict = field(default_factory=dict)   # scrubbed
    has_auth_header: bool = False   # presence only — never value

    # Response
    response: Optional[NetworkResponse] = None

    # Comparison response (for NET-B difference classification)
    comparison_response: Optional[NetworkResponse] = None

    # Labels (set externally — never by this class)
    protocol_label: Optional[str]    = None   # NET-A
    difference_label: Optional[str]  = None   # NET-B
    session_label: Optional[str]     = None   # NET-C
    auth_label: Optional[str]        = None   # NET-D

    # Metadata
    fixture_family: str = ""    # for grouped splitting — prevents leakage
    data_source: str    = "EDUCATIONAL_SYNTHETIC"  # NEVER "human_reviewed"

    @classmethod
    def from_exchange(cls, method: str, path: str, query_string: str,
                      request_headers: dict,
                      response: NetworkResponse,
                      comparison_response: Optional[NetworkResponse] = None,
                      fixture_family: str = "") -> "NetworkObservation":
        scrubbed_req = _scrub_headers(request_headers)
        lower_rh = {k.lower() for k in request_headers}
        has_auth = bool(lower_rh & {"authorization", "x-api-key",
                                    "x-auth-token", "cookie"})
        return cls(
            method=method,
            path=path,
            query_string=query_string,
            request_headers=scrubbed_req,
            has_auth_header=has_auth,
            response=response,
            comparison_response=comparison_response,
            fixture_family=fixture_family,
        )
