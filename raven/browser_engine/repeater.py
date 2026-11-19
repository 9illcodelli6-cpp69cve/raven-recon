"""RAVEN V7 Repeater — Part 05.

DEPRECATED / UNWIRED (see raven/browser_engine/__init__.py). Wraps the deprecated
urllib HttpClient. A future Burp-style repeater must resend-with-edits THROUGH the
canonical sender (POST /api/send -> do_send) so scope/identity/admission are
enforced — never a second client. Kept importable for the legacy test; do NOT
wire it in.

Modify and resend captured HTTP requests for manual security testing.
Scope-validated before every send. All responses are untrusted data.
"""
from __future__ import annotations

__deprecated__ = True
__canonical_replacement__ = "resend through raven.api.server.do_send (POST /api/send)"

import copy
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .http_client import HttpClient, HttpRequest, HttpResponse


@dataclass
class RepeatResult:
    original_url:  str
    modified_url:  str
    response:      Optional[HttpResponse] = None
    modifications: List[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.response is not None and self.response.error is None

    def to_dict(self) -> dict:
        return {
            "original_url": self.original_url,
            "modified_url": self.modified_url,
            "status_code": self.response.status_code if self.response else None,
            "modifications": self.modifications,
            "success": self.success,
        }


class Repeater:
    """Modify captured requests and resend them (BurpSuite-style repeater).

    The repeater wraps the HttpClient — all scope validation still applies.
    """

    def __init__(self, client: HttpClient):
        self._client = client

    def repeat(
        self,
        request: HttpRequest,
        modify_url: str = None,
        modify_headers: Dict[str, str] = None,
        modify_body: bytes = None,
        remove_headers: List[str] = None,
    ) -> RepeatResult:
        """Repeat a request with optional modifications."""
        modifications = []
        # Deep copy to avoid mutating original
        new_headers = dict(request.headers)

        if modify_url and modify_url != request.url:
            modifications.append(f"URL changed: {request.url} → {modify_url}")

        if modify_headers:
            for k, v in modify_headers.items():
                new_headers[k] = v
                modifications.append(f"Header set: {k}")

        if remove_headers:
            for k in remove_headers:
                removed = new_headers.pop(k, None)
                if removed is not None:
                    modifications.append(f"Header removed: {k}")

        modified_request = HttpRequest(
            url=modify_url or request.url,
            method=request.method,
            headers=new_headers,
            body=modify_body if modify_body is not None else request.body,
            timeout_s=request.timeout_s,
        )

        response = self._client.send(modified_request)

        return RepeatResult(
            original_url=request.url,
            modified_url=modified_request.url,
            response=response,
            modifications=modifications,
        )

    def fuzz_parameter(
        self, base_url: str, param: str, payloads: List[str],
        method: str = "GET",
    ) -> List[RepeatResult]:
        """Send multiple requests varying one URL parameter. Results are data."""
        results = []
        for payload in payloads:
            # Build URL with injected parameter
            if "?" in base_url:
                url = f"{base_url}&{param}={payload}"
            else:
                url = f"{base_url}?{param}={payload}"
            req = HttpRequest(url=url, method=method)
            resp = self._client.send(req)
            results.append(RepeatResult(
                original_url=base_url,
                modified_url=url,
                response=resp,
                modifications=[f"Fuzz {param}={payload!r}"],
            ))
        return results
