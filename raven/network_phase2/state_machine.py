"""RAVEN Network Phase II — Composable state machine dimensions.

Models orthogonal state dimensions rather than one monolithic enum.
Each dimension tracks one aspect of protocol/session/cache state.

INVARIANTS:
- States are protocol/application observations, not security verdicts.
- Transitions are classified, never exploited.
- Security authority: NONE.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from raven.network_fundamentals.observation import NetworkObservation


# ── State dimensions ──────────────────────────────────────────────────────────

class NetworkDimension(str, Enum):
    """Network/transport layer state."""
    UNRESOLVED  = "UNRESOLVED"    # Before any response
    CONNECTED   = "CONNECTED"     # TCP/TLS established
    HTTP_ACTIVE = "HTTP_ACTIVE"   # HTTP response received
    FAILED      = "FAILED"        # Connection/timeout error


class SessionDimension(str, Enum):
    """Session state visible from HTTP signals."""
    NO_SESSION           = "NO_SESSION"
    ANONYMOUS_SESSION    = "ANONYMOUS_SESSION"    # Cookie present, no auth
    AUTHENTICATED_SESSION = "AUTHENTICATED_SESSION"
    EXPIRED_SESSION      = "EXPIRED_SESSION"
    INVALID_SESSION      = "INVALID_SESSION"
    LOGGED_OUT           = "LOGGED_OUT"
    UNKNOWN              = "UNKNOWN"


class CacheDimension(str, Enum):
    """Cache state for a resource."""
    CACHE_UNKNOWN   = "CACHE_UNKNOWN"
    CACHE_FRESH     = "CACHE_FRESH"      # 200 with ETag/Last-Modified
    CACHE_VALIDATED = "CACHE_VALIDATED"  # 304: still fresh
    CACHE_STALE     = "CACHE_STALE"      # Validator failed, new 200
    CACHE_ABSENT    = "CACHE_ABSENT"     # No caching signals


class ResourceDimension(str, Enum):
    """Resource availability state."""
    UNKNOWN   = "UNKNOWN"
    EXISTS    = "EXISTS"       # 200/2xx
    ABSENT    = "ABSENT"       # 404/410
    FORBIDDEN = "FORBIDDEN"    # 403
    CREATED   = "CREATED"      # 201
    DELETED   = "DELETED"      # 204/404 after DELETE
    MOVED     = "MOVED"        # 301/308


# ── Composite state ───────────────────────────────────────────────────────────

@dataclass
class CompositeState:
    """The combined state of all dimensions at one point in time."""
    network:  NetworkDimension  = NetworkDimension.UNRESOLVED
    session:  SessionDimension  = SessionDimension.NO_SESSION
    cache:    CacheDimension    = CacheDimension.CACHE_UNKNOWN
    resource: ResourceDimension = ResourceDimension.UNKNOWN

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CompositeState):
            return NotImplemented
        return (self.network  == other.network  and
                self.session  == other.session  and
                self.cache    == other.cache    and
                self.resource == other.resource)

    def diff(self, other: "CompositeState") -> list[str]:
        """Return list of dimension names that changed."""
        changed = []
        if self.network  != other.network:  changed.append("network")
        if self.session  != other.session:  changed.append("session")
        if self.cache    != other.cache:    changed.append("cache")
        if self.resource != other.resource: changed.append("resource")
        return changed

    def copy(self) -> "CompositeState":
        return CompositeState(
            network=self.network,
            session=self.session,
            cache=self.cache,
            resource=self.resource,
        )


# ── State inference from single observation ───────────────────────────────────

def infer_state(obs: NetworkObservation) -> CompositeState:
    """Infer composite state from a single NetworkObservation.

    This is a best-effort inference from observable HTTP signals.
    Returns UNKNOWN dimensions when evidence is insufficient.
    """
    resp = obs.response
    if resp is None:
        return CompositeState(network=NetworkDimension.UNRESOLVED)

    # Network dimension
    if resp.connection_error or resp.timed_out:
        net = NetworkDimension.FAILED
    elif resp.status == 0:
        net = NetworkDimension.UNRESOLVED
    else:
        net = NetworkDimension.HTTP_ACTIVE

    # Session dimension
    status = resp.status
    has_auth = obs.has_auth_header
    has_cookie = resp.has_set_cookie

    if net == NetworkDimension.FAILED:
        sess = SessionDimension.UNKNOWN
    elif has_auth and has_cookie and 200 <= status < 300:
        sess = SessionDimension.AUTHENTICATED_SESSION
    elif has_auth and 200 <= status < 300:
        sess = SessionDimension.AUTHENTICATED_SESSION
    elif has_auth and status == 401 and resp.has_www_auth:
        sess = SessionDimension.EXPIRED_SESSION
    elif has_auth and status == 401:
        sess = SessionDimension.INVALID_SESSION
    elif has_cookie and 200 <= status < 300:
        sess = SessionDimension.ANONYMOUS_SESSION
    elif not has_auth and not has_cookie:
        sess = SessionDimension.NO_SESSION
    else:
        sess = SessionDimension.UNKNOWN

    # Cache dimension (from primary response signals)
    if status == 304:
        cache = CacheDimension.CACHE_VALIDATED
    elif 200 <= status < 300 and resp.headers.get("ETag") or resp.headers.get("etag"):
        cache = CacheDimension.CACHE_FRESH
    elif 200 <= status < 300:
        cache = CacheDimension.CACHE_ABSENT
    else:
        cache = CacheDimension.CACHE_UNKNOWN

    # Resource dimension
    if 200 <= status < 201:
        resource = ResourceDimension.EXISTS
    elif status == 201:
        resource = ResourceDimension.CREATED
    elif status in (204, 205):
        resource = ResourceDimension.EXISTS
    elif status == 301 or status == 308:
        resource = ResourceDimension.MOVED
    elif status in (404, 410):
        resource = ResourceDimension.ABSENT
    elif status == 403:
        resource = ResourceDimension.FORBIDDEN
    elif status == 304:
        resource = ResourceDimension.EXISTS
    else:
        resource = ResourceDimension.UNKNOWN

    return CompositeState(network=net, session=sess, cache=cache, resource=resource)


# ── Transition validation ─────────────────────────────────────────────────────

# Valid normal transitions: (from_session, to_session)
NORMAL_SESSION_TRANSITIONS: frozenset[tuple[str, str]] = frozenset({
    ("NO_SESSION",            "ANONYMOUS_SESSION"),
    ("NO_SESSION",            "AUTHENTICATED_SESSION"),
    ("ANONYMOUS_SESSION",     "AUTHENTICATED_SESSION"),  # login
    ("AUTHENTICATED_SESSION", "ANONYMOUS_SESSION"),      # logout to anon
    ("AUTHENTICATED_SESSION", "LOGGED_OUT"),             # explicit logout
    ("AUTHENTICATED_SESSION", "AUTHENTICATED_SESSION"),  # normal continuation
    ("AUTHENTICATED_SESSION", "EXPIRED_SESSION"),        # token expiry
    ("EXPIRED_SESSION",       "AUTHENTICATED_SESSION"),  # re-auth
    ("EXPIRED_SESSION",       "NO_SESSION"),             # session cleared
    ("INVALID_SESSION",       "NO_SESSION"),
    ("INVALID_SESSION",       "AUTHENTICATED_SESSION"),  # re-auth
    ("LOGGED_OUT",            "NO_SESSION"),
    ("LOGGED_OUT",            "ANONYMOUS_SESSION"),
    # NOTE: LOGGED_OUT → AUTHENTICATED_SESSION requires more evidence (re-login
    # step must be observable); handled by is_normal_session_transition → None.
    ("ANONYMOUS_SESSION",     "ANONYMOUS_SESSION"),
    ("NO_SESSION",            "NO_SESSION"),
})


def is_normal_session_transition(from_s: SessionDimension,
                                  to_s: SessionDimension) -> Optional[bool]:
    """Return True if transition is in known-normal set, False if anomalous,
    None if insufficient evidence."""
    key = (from_s.value, to_s.value)
    if key in NORMAL_SESSION_TRANSITIONS:
        return True
    # logged_out → authenticated content without re-login = needs more evidence
    if from_s == SessionDimension.LOGGED_OUT and to_s == SessionDimension.AUTHENTICATED_SESSION:
        return None  # NEEDS_MORE_EVIDENCE
    return False
