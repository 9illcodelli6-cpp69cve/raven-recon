"""RAVEN V7 HTTP Client — Part 05.

DEPRECATED / UNWIRED (see raven/browser_engine/__init__.py). This urllib-based
client bypasses the hardened path's DNS-pin, scheduler admission and workspace
identity injection. Nothing in production imports it. Canonical replacement:
raven.api.server.do_send / _send_in_context (POST /api/send). Kept importable for
the legacy test only; do NOT wire it in.

Scope-enforced HTTP request/response capture.
Uses urllib (stdlib only — no requests dependency required).
All responses are UNTRUSTED DATA.
"""
from __future__ import annotations

__deprecated__ = True
__canonical_replacement__ = "raven.api.server.do_send (POST /api/send)"

import time
import urllib.error
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .scope_guard import ScopeGuard, ScopeViolation

# Limit response body to 5MB
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
DEFAULT_TIMEOUT_S  = 15
USER_AGENT         = "RAVEN/7.0 Security Research Tool (authorized testing)"


@dataclass
class HttpRequest:
    url:      str
    method:   str = "GET"
    headers:  Dict[str, str] = field(default_factory=dict)
    body:     Optional[bytes] = None
    timeout_s: int = DEFAULT_TIMEOUT_S

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "headers": {k: v for k, v in self.headers.items()
                        if k.lower() not in ("authorization", "cookie")},
            "body_length": len(self.body) if self.body else 0,
        }


@dataclass
class HttpResponse:
    request:        HttpRequest
    status_code:    int = 0
    headers:        Dict[str, str] = field(default_factory=dict)
    body:           bytes = b""
    body_text:      str = ""
    duration_ms:    int = 0
    error:          Optional[str] = None
    scope_blocked:  bool = False

    @property
    def success(self) -> bool:
        return self.error is None and not self.scope_blocked and 200 <= self.status_code < 300

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", self.headers.get("content-type", ""))

    def to_dict(self) -> dict:
        return {
            "url": self.request.url,
            "method": self.request.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "body_length": len(self.body),
            "duration_ms": self.duration_ms,
            "error": self.error,
            "scope_blocked": self.scope_blocked,
        }


class HttpClient:
    """Scope-enforced HTTP client for authorized security research.

    All requests are validated against the ScopeGuard before sending.
    Responses are returned as data — never executed as code or instructions.
    """

    def __init__(
        self,
        scope_guard: ScopeGuard = None,
        default_headers: Dict[str, str] = None,
        timeout_s: int = DEFAULT_TIMEOUT_S,
    ):
        self._scope    = scope_guard
        self._headers  = {"User-Agent": USER_AGENT, **(default_headers or {})}
        self._timeout  = timeout_s

    def send(self, request: HttpRequest) -> HttpResponse:
        """Send an HTTP request, respecting scope. Returns HttpResponse."""
        # Scope check — out-of-scope is always blocked
        if self._scope is not None:
            try:
                self._scope.check(request.url)
            except ScopeViolation as e:
                return HttpResponse(
                    request=request,
                    scope_blocked=True,
                    error=str(e),
                )

        t0 = int(time.time() * 1000)
        try:
            headers = {**self._headers, **request.headers}
            req = urllib.request.Request(
                url=request.url,
                method=request.method.upper(),
                headers=headers,
                data=request.body,
            )
            with urllib.request.urlopen(req, timeout=request.timeout_s or self._timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES)
                resp_headers = dict(resp.headers)
                status = resp.status

            duration = int(time.time() * 1000) - t0
            try:
                body_text = raw.decode("utf-8", errors="replace")
            except Exception:
                body_text = ""

            return HttpResponse(
                request=request,
                status_code=status,
                headers=resp_headers,
                body=raw,
                body_text=body_text,
                duration_ms=duration,
            )

        except urllib.error.HTTPError as e:
            duration = int(time.time() * 1000) - t0
            try:
                raw = e.read(MAX_RESPONSE_BYTES) if e.fp else b""
            except Exception:
                raw = b""
            return HttpResponse(
                request=request,
                status_code=e.code,
                headers=dict(e.headers) if e.headers else {},
                body=raw,
                body_text=raw.decode("utf-8", errors="replace"),
                duration_ms=duration,
                error=f"HTTP {e.code}: {e.reason}",
            )

        except Exception as exc:
            duration = int(time.time() * 1000) - t0
            return HttpResponse(
                request=request,
                status_code=0,
                duration_ms=duration,
                error=str(exc),
            )

    def get(self, url: str, headers: Dict[str, str] = None) -> HttpResponse:
        return self.send(HttpRequest(url=url, method="GET", headers=headers or {}))

    def post(self, url: str, body: bytes, headers: Dict[str, str] = None) -> HttpResponse:
        return self.send(HttpRequest(url=url, method="POST", body=body, headers=headers or {}))
