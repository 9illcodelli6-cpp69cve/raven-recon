"""Response analysis: canonical representation, normalization, and Task A
ResponseDifference measurement.

Task A measures STRUCTURAL differences between two responses.
It does NOT judge authorization significance — that is Task B.

Design reference: 06_RESPONSE_ANALYSIS_DESIGN.md, 09_FEATURE_ENGINEERING_PLAN.md
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Optional


# Dynamic patterns that represent volatile but non-security-relevant content.
# Conservative: only strip what is clearly volatile.
_DYNAMIC_PATTERNS = [
    re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'),  # UUID
    re.compile(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b'),  # ISO timestamps
    re.compile(r'\bcsrf[_-]?token["\s]*:["\s]*[A-Za-z0-9+/=_-]{8,}\b', re.IGNORECASE),  # CSRF tokens
    re.compile(r'\bnonce["\s]*:["\s]*[A-Za-z0-9+/=_-]{8,}\b', re.IGNORECASE),  # Nonces
]

_SENSITIVE_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key",
    "x-auth-token", "x-csrf-token", "x-request-id",
})


@dataclass
class ResponseRepr:
    """Canonical, deterministic representation of an HTTP response.

    raw_body is NEVER stored — only digest and length.
    normalized_text is a sanitized excerpt for comparison.
    """
    status: int
    content_type: str
    body_len: int
    body_digest: str          # SHA-256 hex of raw body
    normalized_text: str      # dynamic-stripped excerpt (max 8192 chars)
    normalized_digest: str    # SHA-256 of normalized_text
    headers: dict             # non-sensitive headers only
    header_fingerprint: frozenset  # "name:value_prefix" set
    elapsed_ms: Optional[int] = None
    decode_lossy: bool = False
    identity_label: str = ""
    acquisition_mode: str = "collect"

    @classmethod
    def from_raw(
        cls,
        status: int,
        raw_headers: dict,
        raw_body: bytes,
        elapsed_ms: Optional[int] = None,
        identity_label: str = "",
        acquisition_mode: str = "collect",
    ) -> "ResponseRepr":
        safe_headers = {
            k.lower(): v for k, v in raw_headers.items()
            if k.lower() not in _SENSITIVE_HEADERS
        }
        content_type = safe_headers.get("content-type", "").split(";")[0].strip()
        body_len = len(raw_body)
        body_digest = hashlib.sha256(raw_body).hexdigest()
        decode_lossy = False
        try:
            body_text = raw_body.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            body_text = raw_body.decode("utf-8", errors="replace")
            decode_lossy = True
        normalized = normalize_body(body_text, content_type)[:8192]
        normalized_digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        header_fp = _header_fingerprint(safe_headers)
        return cls(
            status=status,
            content_type=content_type,
            body_len=body_len,
            body_digest=body_digest,
            normalized_text=normalized,
            normalized_digest=normalized_digest,
            headers=safe_headers,
            header_fingerprint=header_fp,
            elapsed_ms=elapsed_ms,
            decode_lossy=decode_lossy,
            identity_label=identity_label,
            acquisition_mode=acquisition_mode,
        )


def _header_fingerprint(headers: dict) -> frozenset:
    skip = {"date", "content-length", "x-request-id", "set-cookie"}
    return frozenset(
        f"{k}:{v[:64]}" for k, v in headers.items() if k not in skip
    )


def normalize_body(text: str, content_type: str) -> str:
    """Apply conservative normalization to strip volatile tokens.

    Never normalizes security-relevant differences away.
    Raw evidence must be preserved separately.
    """
    if "json" in content_type:
        try:
            obj = json.loads(text)
            return _normalize_json_obj(obj)
        except (json.JSONDecodeError, ValueError):
            pass
    result = text
    for pat in _DYNAMIC_PATTERNS:
        result = pat.sub("<DYNAMIC>", result)
    return result


def _normalize_json_obj(obj, _depth=0):
    if _depth > 20:
        return "<TRUNCATED>"
    if isinstance(obj, dict):
        return json.dumps(
            {k: _normalize_json_obj(v, _depth + 1) for k, v in sorted(obj.items())},
            ensure_ascii=False,
            separators=(",", ":"),
        )
    if isinstance(obj, list):
        return json.dumps(
            [_normalize_json_obj(v, _depth + 1) for v in obj],
            ensure_ascii=False,
            separators=(",", ":"),
        )
    if isinstance(obj, str):
        for pat in _DYNAMIC_PATTERNS:
            obj = pat.sub("<DYNAMIC>", obj)
        return obj
    return obj


# ---------------------------------------------------------------------------
# Task A: ResponseDifference (structural measurement only)
# ---------------------------------------------------------------------------

@dataclass
class ResponseDiff:
    """Structural difference between two responses for the same URL.

    This is Task A: ResponseDifference.
    A DIFFERENT result is EVIDENCE of structural change, NOT an authorization conclusion.
    Task B (AuthorizationSignificance) makes the authorization judgment separately.
    """
    status_match: bool
    content_type_match: bool
    body_len_ratio: float          # min/max ∈ [0,1]
    body_digest_match: bool
    normalized_digest_match: bool
    body_token_jaccard: float      # token overlap ∈ [0,1]
    header_jaccard: float          # header fingerprint overlap ∈ [0,1]
    composite_similarity: float    # weighted ∈ [0,1], higher = more similar
    label: str                     # "DIFFERENT" | "SIMILAR" | "IDENTICAL"
    components: dict = field(default_factory=dict)

    @property
    def is_different(self) -> bool:
        return self.label == "DIFFERENT"


def compare_responses(a: ResponseRepr, b: ResponseRepr) -> ResponseDiff:
    """Compute Task A structural difference between responses a and b.

    Weights follow 06_RESPONSE_ANALYSIS_DESIGN.md ResponseComparator.
    """
    status_match = (a.status == b.status)
    ct_match = (a.content_type == b.content_type)
    max_len = max(a.body_len, b.body_len, 1)
    min_len = min(a.body_len, b.body_len)
    len_ratio = min_len / max_len
    digest_match = (a.body_digest == b.body_digest)
    norm_digest_match = (a.normalized_digest == b.normalized_digest)
    jaccard = _token_jaccard(a.normalized_text, b.normalized_text)
    fp_a = a.header_fingerprint
    fp_b = b.header_fingerprint
    union = fp_a | fp_b
    h_jaccard = len(fp_a & fp_b) / len(union) if union else 1.0
    composite = (
        0.50 * jaccard
        + 0.25 * len_ratio
        + 0.15 * int(status_match)
        + 0.10 * h_jaccard
    )
    if digest_match:
        label = "IDENTICAL"
    elif composite >= 0.85:
        label = "SIMILAR"
    else:
        label = "DIFFERENT"
    return ResponseDiff(
        status_match=status_match,
        content_type_match=ct_match,
        body_len_ratio=len_ratio,
        body_digest_match=digest_match,
        normalized_digest_match=norm_digest_match,
        body_token_jaccard=jaccard,
        header_jaccard=h_jaccard,
        composite_similarity=composite,
        label=label,
        components={
            "status_match": status_match,
            "content_type_match": ct_match,
            "body_len_ratio": round(len_ratio, 4),
            "body_digest_match": digest_match,
            "normalized_digest_match": norm_digest_match,
            "body_token_jaccard": round(jaccard, 4),
            "header_jaccard": round(h_jaccard, 4),
            "composite_similarity": round(composite, 4),
        },
    )


def _token_jaccard(a: str, b: str) -> float:
    ta = set(a.lower().split())
    tb = set(b.lower().split())
    union = ta | tb
    return len(ta & tb) / len(union) if union else 1.0
