"""RAVEN Network Fundamentals — classification taxonomies.

Defines class labels for NET-A/B/C/D training tasks and
the explicit non-vulnerability mappings (Part 36 of the program).

INVARIANT: No class here implies a confirmed vulnerability.
Classification is protocol/application state, not security verdict.
"""
from __future__ import annotations
from enum import Enum


# ── NET-A: Protocol behavior classification ───────────────────────────────────

class ProtocolClass(str, Enum):
    """Output classes for NET-A task.

    Classifies the protocol/application behavior of an HTTP response.
    NONE of these imply a vulnerability by themselves.
    """
    NORMAL_SUCCESS  = "NORMAL_SUCCESS"    # 2xx with expected content
    REDIRECT        = "REDIRECT"          # 3xx response
    CLIENT_ERROR    = "CLIENT_ERROR"      # 400/405/409/410/415/422
    AUTH_REQUIRED   = "AUTH_REQUIRED"     # 401
    FORBIDDEN       = "FORBIDDEN"         # 403
    RATE_LIMITED    = "RATE_LIMITED"      # 429
    SERVER_ERROR    = "SERVER_ERROR"      # 5xx
    NETWORK_FAILURE = "NETWORK_FAILURE"   # timeout/DNS/TCP connection error
    UNKNOWN         = "UNKNOWN"           # ambiguous / abstain

    @classmethod
    def from_status(cls, status: int, has_www_auth: bool = False,
                    has_retry_after: bool = False,
                    timed_out: bool = False,
                    connection_error: bool = False) -> "ProtocolClass":
        """Deterministic protocol classification from response metadata.

        This is NOT security classification. A 403 here means 'forbidden
        by application logic', not 'confirmed authorization bypass'.
        """
        if timed_out or connection_error:
            return cls.NETWORK_FAILURE
        if status == 0 or status < 100:
            return cls.UNKNOWN
        if 200 <= status < 300:
            return cls.NORMAL_SUCCESS
        if 300 <= status < 400:
            return cls.REDIRECT
        if status == 401:
            return cls.AUTH_REQUIRED
        if status == 403:
            return cls.FORBIDDEN
        if status == 429:
            return cls.RATE_LIMITED
        if 400 <= status < 500:
            return cls.CLIENT_ERROR
        if status >= 500:
            return cls.SERVER_ERROR
        return cls.UNKNOWN

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]

    @classmethod
    def label_index(cls) -> dict[str, int]:
        return {c.value: i for i, c in enumerate(cls)}


# ── NET-B: Response difference classification ─────────────────────────────────

class DifferenceClass(str, Enum):
    """Output classes for NET-B task.

    Classifies the nature of a difference between two observations.
    DIFFERENCE != VULNERABILITY.
    """
    NO_CHANGE        = "NO_CHANGE"         # Identical responses
    EXPECTED_CHANGE  = "EXPECTED_CHANGE"   # Predicted by protocol/app semantics
    STATE_DEPENDENT  = "STATE_DEPENDENT"   # Auth/session/locale/AB state difference
    STRUCTURAL_CHANGE = "STRUCTURAL_CHANGE" # JSON shape changed, HTML structure changed
    CONTENT_CHANGE   = "CONTENT_CHANGE"    # Same structure, different values
    AUTH_STATE_CHANGE = "AUTH_STATE_CHANGE" # Authentication state affected response
    TRANSIENT        = "TRANSIENT"         # Timing/cache/502/retry artifact
    UNKNOWN          = "UNKNOWN"           # Cannot classify with available evidence

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]

    @classmethod
    def label_index(cls) -> dict[str, int]:
        return {c.value: i for i, c in enumerate(cls)}


# ── NET-C: Session state classification ───────────────────────────────────────

class SessionState(str, Enum):
    """Output classes for NET-C task.

    Classifies the session/auth state visible in an HTTP exchange.
    Session ID != Session hijack. Anonymous session != attack.
    """
    ANONYMOUS      = "ANONYMOUS"      # No auth context — normal unauthenticated
    AUTHENTICATED  = "AUTHENTICATED"  # User/service session active
    EXPIRED        = "EXPIRED"        # Session was valid, now expired
    INVALID        = "INVALID"        # Malformed or rejected session token
    ROTATED        = "ROTATED"        # Session ID changed (post-login rotation)
    UNKNOWN        = "UNKNOWN"        # Cannot determine from available signals

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]

    @classmethod
    def label_index(cls) -> dict[str, int]:
        return {c.value: i for i, c in enumerate(cls)}


# ── NET-D: Authentication context classification ──────────────────────────────

class AuthContext(str, Enum):
    """Output classes for NET-D task.

    Classifies WHAT KIND of authentication is present.
    Authentication context != authorization verdict.
    """
    PUBLIC                  = "PUBLIC"                   # No auth required or present
    APPLICATION_AUTHENTICATED = "APPLICATION_AUTHENTICATED"  # client_id/client_secret — app identity
    USER_AUTHENTICATED      = "USER_AUTHENTICATED"       # Bearer/session — user identity
    AUTH_REQUIRED           = "AUTH_REQUIRED"            # Response demands authentication
    UNKNOWN                 = "UNKNOWN"

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]

    @classmethod
    def label_index(cls) -> dict[str, int]:
        return {c.value: i for i, c in enumerate(cls)}


# ── Response difference taxonomy (Part 19) ───────────────────────────────────

class ResponseDifference:
    """Structured taxonomy for response difference reasoning.

    Instances record what changed between two observations and
    the reasoning classification. Not a security verdict.
    """
    __slots__ = (
        "status_changed", "body_changed", "body_length_changed",
        "headers_changed", "redirect_changed", "json_shape_changed",
        "authentication_state_changed", "content_type_changed",
        "timing_changed", "classification", "is_security_relevant",
    )

    def __init__(self, **kwargs):
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot, False))

    def to_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}

    @classmethod
    def none(cls) -> "ResponseDifference":
        return cls(classification=DifferenceClass.NO_CHANGE.value)

    @classmethod
    def from_observations(cls, obs_a: dict, obs_b: dict) -> "ResponseDifference":
        """Compute difference between two observation dicts.

        Returns a ResponseDifference with classification.
        NEVER marks is_security_relevant=True automatically.
        """
        status_a = obs_a.get("status", 0)
        status_b = obs_b.get("status", 0)
        body_a   = obs_a.get("body_digest", "")
        body_b   = obs_b.get("body_digest", "")
        len_a    = obs_a.get("body_len", 0) or 0
        len_b    = obs_b.get("body_len", 0) or 0
        ct_a     = obs_a.get("content_type", "")
        ct_b     = obs_b.get("content_type", "")

        sc  = status_a != status_b
        bc  = body_a != body_b
        blc = len_a != len_b
        ctc = ct_a != ct_b
        hc  = obs_a.get("headers", {}) != obs_b.get("headers", {})
        rc  = obs_a.get("location", "") != obs_b.get("location", "")
        ac  = (status_a in (200, 302)) != (status_b in (200, 302))

        if not any([sc, bc, blc, ctc, hc]):
            klass = DifferenceClass.NO_CHANGE.value
        elif sc and status_a in (200, 302) and status_b in (401, 403):
            klass = DifferenceClass.AUTH_STATE_CHANGE.value
        elif sc or rc:
            klass = DifferenceClass.STRUCTURAL_CHANGE.value
        elif bc and not blc:
            klass = DifferenceClass.CONTENT_CHANGE.value
        elif blc:
            klass = DifferenceClass.STRUCTURAL_CHANGE.value
        else:
            klass = DifferenceClass.UNKNOWN.value

        return cls(
            status_changed=sc,
            body_changed=bc,
            body_length_changed=blc,
            headers_changed=hc,
            redirect_changed=rc,
            json_shape_changed=False,   # requires parsed JSON
            authentication_state_changed=ac,
            content_type_changed=ctc,
            timing_changed=False,       # requires timing data
            classification=klass,
            is_security_relevant=False, # NEVER auto-set True
        )


# ── Non-vulnerability mappings (Part 36) ─────────────────────────────────────

NON_VULNERABILITY_MAPPINGS: dict[str, str] = {
    "OPEN_PORT":                  "metadata only — open port is not a vulnerability",
    "HTTP_200":                   "normal success — not a vulnerability",
    "HTTP_500":                   "application error — requires demonstrated impact for security",
    "HTTP_403":                   "forbidden by app logic — not proof of authorization bypass",
    "RESPONSE_DIFFERENCE":        "difference requires context — not a vulnerability by itself",
    "SESSION_ID_PRESENT":         "anonymous session ID is not session hijack",
    "PUBLIC_API_KEY":             "key presence requires context — not automatically a secret",
    "CLIENT_SECRET_STRING":       "string presence requires context — impact depends on scope",
    "CORS_HEADER_PRESENT":        "CORS header presence requires browser semantics — not auto-vuln",
    "STRING_REFLECTION":          "reflection requires context — not automatically XSS",
    "URL_NORMALIZATION_DIFF":     "normalization difference is observation — not path traversal",
    "TLS_FAILURE":                "connection failure is not a vulnerability",
    "REDIRECT_DIFFERENCE":        "redirect change requires context — not auto open redirect",
    "UNUSUALLY_HIGH_ENTROPY":     "high entropy is observation — not automatically a secret",
    "STACK_TRACE_PRESENT":        "information disclosure indicator — not confirmed vulnerability",
    "INTERNAL_PATH_PRESENT":      "information disclosure indicator — not confirmed vulnerability",
}
