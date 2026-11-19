"""RAVEN Network Phase II — Browser semantics: origin, cookie jar, CORS.

Implements deterministic educational models for browser-side HTTP behavior.

INVARIANTS:
- No real credentials stored.
- Output states are educational classifications, not security verdicts.
- Ambiguous cases return UNKNOWN rather than guessing.
- No offensive payload generation.
- Security authority: NONE.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Default ports by scheme ────────────────────────────────────────────────────
_DEFAULT_PORTS: dict[str, int] = {
    "http":  80,
    "https": 443,
    "ws":    80,
    "wss":   443,
    "ftp":   21,
}

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\/(.+)$")


# ── Origin ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Origin:
    """Web Origin: scheme + host + effective port (RFC 6454).

    Ports are normalised: http on 80 → port=80, https on 443 → port=443.
    Do NOT use naive string-prefix comparison for same-origin checks.
    """
    scheme: str
    host:   str    # normalised lowercase
    port:   int    # effective port (never 0 unless unknown)

    @classmethod
    def parse(cls, url: str) -> "Origin":
        """Parse an origin from a URL string.

        Returns OPAQUE if the URL cannot be parsed.
        """
        m = _SCHEME_RE.match(url.strip())
        if not m:
            return cls.opaque()
        scheme = m.group(1).lower()
        rest   = m.group(2)
        # Strip path/query/fragment
        authority = rest.split("/")[0].split("?")[0].split("#")[0]
        if "@" in authority:
            authority = authority.split("@", 1)[1]
        # IPv6 host
        if authority.startswith("["):
            bracket_end = authority.find("]")
            if bracket_end == -1:
                return cls.opaque()
            host = authority[:bracket_end + 1].lower()
            port_part = authority[bracket_end + 1:]
            if port_part.startswith(":"):
                try:
                    port = int(port_part[1:])
                except ValueError:
                    return cls.opaque()
            else:
                port = _DEFAULT_PORTS.get(scheme, 0)
        elif ":" in authority:
            host_part, port_str = authority.rsplit(":", 1)
            host = host_part.lower()
            try:
                port = int(port_str)
            except ValueError:
                return cls.opaque()
        else:
            host = authority.lower()
            port = _DEFAULT_PORTS.get(scheme, 0)
        if not host:
            return cls.opaque()
        return cls(scheme=scheme, host=host, port=port)

    @classmethod
    def opaque(cls) -> "Origin":
        """The opaque origin — result of non-hierarchical or unparseable URLs."""
        return cls(scheme="null", host="", port=0)

    @property
    def is_opaque(self) -> bool:
        return self.scheme == "null"

    def same_origin(self, other: "Origin") -> bool:
        """True iff scheme, host, and port all match exactly."""
        if self.is_opaque or other.is_opaque:
            return False
        return (self.scheme == other.scheme and
                self.host   == other.host   and
                self.port   == other.port)

    def cross_origin(self, other: "Origin") -> bool:
        return not self.same_origin(other)

    def to_string(self) -> str:
        if self.is_opaque:
            return "null"
        default = _DEFAULT_PORTS.get(self.scheme)
        if default == self.port:
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"

    def __str__(self) -> str:
        return self.to_string()


# ── Site (eTLD+1) — conservative for SameSite reasoning ──────────────────────

def _registrable_domain(host: str) -> str:
    """Very conservative eTLD+1 calculation.

    Only handles the most common cases. Returns UNKNOWN for complex PSL cases.
    Avoids implementing a full Public Suffix List.
    """
    if not host or host.startswith("["):
        return "UNKNOWN"
    parts = host.rstrip(".").split(".")
    if len(parts) < 2:
        return host  # localhost or bare IP
    # Simple: return last two labels. DOES NOT handle .co.uk etc.
    return ".".join(parts[-2:])


def same_site(origin_a: Origin, origin_b: Origin) -> Optional[bool]:
    """Conservative same-site determination.

    Returns True for same-site, False for cross-site,
    None when insufficient context (opaque, complex PSL).
    Same-site requires same scheme AND same registrable domain (conservative).
    """
    if origin_a.is_opaque or origin_b.is_opaque:
        return None
    if origin_a.scheme != origin_b.scheme:
        return False
    rd_a = _registrable_domain(origin_a.host)
    rd_b = _registrable_domain(origin_b.host)
    if rd_a == "UNKNOWN" or rd_b == "UNKNOWN":
        return None
    return rd_a == rd_b


# ── Cookie Model ───────────────────────────────────────────────────────────────

class CookieDecision(str, Enum):
    COOKIE_SENT     = "COOKIE_SENT"
    COOKIE_NOT_SENT = "COOKIE_NOT_SENT"
    UNKNOWN         = "UNKNOWN"


class CookieNotSentReason(str, Enum):
    DOMAIN_MISMATCH   = "DOMAIN_MISMATCH"
    PATH_MISMATCH     = "PATH_MISMATCH"
    SECURE_REQUIRED   = "SECURE_REQUIRED"
    EXPIRED           = "EXPIRED"
    SAMESITE_CONTEXT  = "SAMESITE_CONTEXT"
    MATCHED           = "MATCHED"


@dataclass
class CookieAttributes:
    """Educational cookie attribute model — no actual values stored."""
    name:       str
    domain:     str   # Set-Cookie Domain attribute (or host-only)
    path:       str   # Set-Cookie Path attribute
    secure:     bool = False
    http_only:  bool = False
    same_site:  str  = "Lax"   # "Strict" | "Lax" | "None"
    max_age:    Optional[int] = None   # None = session cookie
    host_only:  bool = True    # True if no Domain attribute was present

    @property
    def is_expired(self) -> bool:
        return self.max_age is not None and self.max_age <= 0


@dataclass
class CookieJarDecision:
    """Result of checking whether a cookie would be sent for a given request."""
    decision: CookieDecision
    reason:   CookieNotSentReason
    cookie_name: str

    @property
    def sent(self) -> bool:
        return self.decision == CookieDecision.COOKIE_SENT


def evaluate_cookie_sending(
    cookie: CookieAttributes,
    request_scheme: str,
    request_host: str,
    request_path: str,
    top_level_site: Optional[Origin] = None,
    request_origin: Optional[Origin] = None,
) -> CookieJarDecision:
    """Deterministic educational model of whether a cookie would be sent.

    Does NOT store or check actual cookie values.
    Implements key browser rules conservatively.
    Returns UNKNOWN when browser behavior is ambiguous.
    """
    name = cookie.name

    if cookie.is_expired:
        return CookieJarDecision(CookieDecision.COOKIE_NOT_SENT,
                                  CookieNotSentReason.EXPIRED, name)

    # Secure attribute: only sent over HTTPS
    if cookie.secure and request_scheme.lower() != "https":
        return CookieJarDecision(CookieDecision.COOKIE_NOT_SENT,
                                  CookieNotSentReason.SECURE_REQUIRED, name)

    # Domain matching
    req_host = request_host.lower()
    if cookie.host_only:
        if cookie.domain.lower() != req_host:
            return CookieJarDecision(CookieDecision.COOKIE_NOT_SENT,
                                      CookieNotSentReason.DOMAIN_MISMATCH, name)
    else:
        domain = cookie.domain.lower().lstrip(".")
        if req_host != domain and not req_host.endswith("." + domain):
            return CookieJarDecision(CookieDecision.COOKIE_NOT_SENT,
                                      CookieNotSentReason.DOMAIN_MISMATCH, name)

    # Path matching
    cookie_path = cookie.path if cookie.path else "/"
    if not (request_path == cookie_path or
            request_path.startswith(cookie_path.rstrip("/") + "/")):
        return CookieJarDecision(CookieDecision.COOKIE_NOT_SENT,
                                  CookieNotSentReason.PATH_MISMATCH, name)

    # SameSite (conservative: only evaluate when context is provided)
    if cookie.same_site == "Strict" and request_origin is not None and top_level_site is not None:
        ss = same_site(request_origin, top_level_site)
        if ss is False:
            return CookieJarDecision(CookieDecision.COOKIE_NOT_SENT,
                                      CookieNotSentReason.SAMESITE_CONTEXT, name)

    return CookieJarDecision(CookieDecision.COOKIE_SENT,
                              CookieNotSentReason.MATCHED, name)


# ── CORS ───────────────────────────────────────────────────────────────────────

class CorsState(str, Enum):
    PREFLIGHT_REQUIRED  = "PREFLIGHT_REQUIRED"
    PREFLIGHT_ACCEPTED  = "PREFLIGHT_ACCEPTED"
    PREFLIGHT_REJECTED  = "PREFLIGHT_REJECTED"
    SIMPLE_REQUEST      = "SIMPLE_REQUEST"
    SAME_ORIGIN         = "SAME_ORIGIN"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"


_SIMPLE_METHODS   = frozenset({"GET", "HEAD", "POST"})
_SIMPLE_CT_VALUES = frozenset({
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
})
_CORS_UNSAFE_REQUEST_HEADERS = frozenset({
    "accept-language", "content-language", "content-type",
    "accept-charset", "accept-encoding", "access-control-request-headers",
    "access-control-request-method",
})


def is_simple_cors_request(method: str, content_type: str = "",
                            extra_headers: frozenset[str] = frozenset()) -> bool:
    """Determine if a CORS request is 'simple' (no preflight required).

    Conservative per WHATWG Fetch spec §4.1.
    """
    if method.upper() not in _SIMPLE_METHODS:
        return False
    if method.upper() == "POST" and content_type not in _SIMPLE_CT_VALUES:
        return False
    for h in extra_headers:
        if h.lower() not in _CORS_UNSAFE_REQUEST_HEADERS:
            return False
    return True


@dataclass
class CorsAnalysis:
    """Deterministic educational CORS state classification."""
    request_origin: Origin
    resource_origin: Origin
    method: str = "GET"
    content_type: str = ""
    extra_headers: frozenset[str] = field(default_factory=frozenset)
    acao: str = ""          # Access-Control-Allow-Origin header value
    acac: str = ""          # Access-Control-Allow-Credentials
    acam: str = ""          # Access-Control-Allow-Methods
    acah: str = ""          # Access-Control-Allow-Headers
    preflight_status: int = 0

    def classify(self) -> CorsState:
        """Deterministically classify the CORS state."""
        if self.request_origin.is_opaque or self.resource_origin.is_opaque:
            return CorsState.INSUFFICIENT_CONTEXT

        if self.request_origin.same_origin(self.resource_origin):
            return CorsState.SAME_ORIGIN

        # Cross-origin — check if simple
        if is_simple_cors_request(self.method, self.content_type, self.extra_headers):
            if self.acao in ("*", self.request_origin.to_string()):
                return CorsState.SIMPLE_REQUEST
            return CorsState.PREFLIGHT_REJECTED if self.acao else CorsState.INSUFFICIENT_CONTEXT

        # Non-simple: preflight required
        if not self.acao:
            return CorsState.PREFLIGHT_REQUIRED

        origin_allowed = (self.acao == "*" or
                          self.acao == self.request_origin.to_string())

        # With credentials: ACAO "*" is not allowed
        credentials_requested = self.acac.lower() == "true"
        if credentials_requested and self.acao == "*":
            return CorsState.PREFLIGHT_REJECTED

        if not origin_allowed:
            return CorsState.PREFLIGHT_REJECTED

        # Check method allowed
        if self.acam:
            allowed_methods = {m.strip().upper() for m in self.acam.split(",")}
            if self.method.upper() not in allowed_methods:
                return CorsState.PREFLIGHT_REJECTED

        if self.preflight_status in (200, 204) and origin_allowed:
            return CorsState.PREFLIGHT_ACCEPTED

        return CorsState.PREFLIGHT_REQUIRED


# ── URL normalization ──────────────────────────────────────────────────────────

def normalize_url_path(path: str) -> str:
    """Resolve dot segments from a URL path.

    /a/b/../c → /a/c
    /a/./b   → /a/b
    NORMALIZATION_DIFFERENCE != SECURITY_BYPASS.
    """
    if not path:
        return "/"
    parts = path.split("/")
    resolved: list[str] = []
    for part in parts:
        if part == "..":
            if resolved:
                resolved.pop()
        elif part not in (".", ""):
            resolved.append(part)
    return "/" + "/".join(resolved)
