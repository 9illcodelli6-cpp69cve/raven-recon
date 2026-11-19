"""RAVEN actor-provenance resolver (canonical decision C-3).

Provenance is assigned at the TRUST BOUNDARY from authenticated transport
signals — NEVER from request bodies, caller-chosen headers, or model output.

This module defines NO enum. The single provenance vocabulary is
``raven.runtime.execution.ActorKind`` (RESEARCHER / RAVEN_AGENT / PROGRAM_AGENT /
SYSTEM / PLUGIN / SCRIPT). This resolver maps an authenticated request's
*boundary classification* onto one of those values; it is the one place that
decides provenance, so there is no competing enum and no second resolver.

Security invariants (enforced here, not merely documented):
- A request can never raise its own provenance. ``resolve_actor`` derives the
  ActorKind only from the server's trusted ``ActorSource`` classification and the
  transport auth result; any ``actor``/``provenance`` field in the request body
  is ignored (``resolve_actor_ignoring_body``) and can be flagged
  (``body_claims_provenance``).
- Fail-closed: an interactive request that is not authenticated is refused the
  RESEARCHER identity (``ProvenanceError``); callers must treat that as deny.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from raven.runtime.execution import ActorKind


class ActorSource(str, enum.Enum):
    """WHERE a request entered RAVEN — classified by the server at the transport
    boundary (which socket / which internal caller), never by the payload."""
    INTERACTIVE_UI = "INTERACTIVE_UI"   # loopback researcher UI, token-authenticated
    AGENT_LOOP     = "AGENT_LOOP"       # in-app RAVEN agent / task step
    PROGRAM_MODE   = "PROGRAM_MODE"     # autonomous Program Mode under a ProgramPolicy
    INTERNAL       = "INTERNAL"         # RAVEN's own collectors / migrations


# Body keys that must NEVER influence provenance if present on an untrusted body.
_FORBIDDEN_BODY_KEYS = ("actor", "actor_kind", "actorKind", "provenance")


class ProvenanceError(RuntimeError):
    """Raised when provenance cannot be assigned from trusted boundary signals.
    Callers MUST treat this as fail-closed (deny)."""


# Trusted source → ActorKind. INTERACTIVE_UI is handled separately because it is
# gated on the transport auth result.
_SOURCE_TO_ACTOR = {
    ActorSource.AGENT_LOOP:   ActorKind.RAVEN_AGENT,
    ActorSource.PROGRAM_MODE: ActorKind.PROGRAM_AGENT,
    ActorSource.INTERNAL:     ActorKind.SYSTEM,
}


def resolve_actor(source: ActorSource, *, authenticated: bool) -> ActorKind:
    """Map a trusted boundary classification to an ActorKind.

    ``source`` is determined by the server from transport state, NOT from the
    request body. ``authenticated`` is the transport auth result (loopback token,
    origin, host).

    Fail-closed: an INTERACTIVE_UI request that is not authenticated cannot be
    assigned RESEARCHER provenance.
    """
    if not isinstance(source, ActorSource):
        raise ProvenanceError(f"Unknown actor source: {source!r}")
    if source == ActorSource.INTERACTIVE_UI:
        if not authenticated:
            raise ProvenanceError(
                "Interactive request is not authenticated; refusing to assign "
                "RESEARCHER provenance (fail-closed)."
            )
        return ActorKind.RESEARCHER
    return _SOURCE_TO_ACTOR[source]


def resolve_actor_ignoring_body(
    source: ActorSource,
    *,
    authenticated: bool,
    request_body: Optional[Mapping[str, Any]] = None,
) -> ActorKind:
    """Resolve provenance while explicitly ignoring any provenance claimed in the
    (untrusted) request body. Request payloads and model output can never
    escalate provenance — ``request_body`` does not participate in the decision.
    """
    _ = request_body  # accepted only to document that it is NOT consulted
    return resolve_actor(source, authenticated=authenticated)


def body_claims_provenance(request_body: Optional[Mapping[str, Any]]) -> bool:
    """True if an untrusted body attempts to set its own provenance. The value is
    still ignored for the decision; this is only for auditing/flagging an attempt."""
    if not request_body:
        return False
    return any(key in request_body for key in _FORBIDDEN_BODY_KEYS)


@dataclass(frozen=True)
class ActorContext:
    """Immutable, boundary-assigned execution identity handed to the gate /
    executor. ``actor`` comes from ``resolve_actor``; it is never read back from a
    request body."""
    actor:                ActorKind
    workspace_id:         str
    granted_capabilities: frozenset = field(default_factory=frozenset)
    source:               Optional[ActorSource] = None

    @classmethod
    def at_boundary(
        cls,
        source: ActorSource,
        *,
        authenticated: bool,
        workspace_id: str,
        granted_capabilities=None,
        request_body: Optional[Mapping[str, Any]] = None,
    ) -> "ActorContext":
        """Build an ActorContext at the trust boundary. Any provenance in
        ``request_body`` is ignored; provenance is derived from ``source`` and
        the transport auth result alone."""
        actor = resolve_actor_ignoring_body(
            source, authenticated=authenticated, request_body=request_body,
        )
        return cls(
            actor=actor,
            workspace_id=workspace_id,
            granted_capabilities=frozenset(granted_capabilities or ()),
            source=source,
        )

    def to_dict(self) -> dict:
        return {
            "actor": self.actor.value,
            "workspace_id": self.workspace_id,
            "granted_capabilities": sorted(
                getattr(c, "value", str(c)) for c in self.granted_capabilities
            ),
            "source": self.source.value if self.source else None,
        }
