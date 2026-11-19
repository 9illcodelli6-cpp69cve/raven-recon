"""Safe Payload Registry.

PayloadRiskClass controls which payloads may be dispatched automatically.
EXFILTRATION and DESTRUCTIVE payloads MUST NEVER execute automatically —
this invariant is enforced both here and by the schema-level constraint.

Design reference: blueprint Stage 5 (Safe Payload Registry).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class PayloadRiskClass(enum.Enum):
    """Risk class for a payload.

    Only SAFE_MARKER and REFLECTION_PROBE may be dispatched automatically.
    HEADER_PROBE requires explicit opt-in per scan.
    STATE_MUTATE, EXFILTRATION, and DESTRUCTIVE are blocked from auto-dispatch.
    """
    SAFE_MARKER = "safe_marker"
    REFLECTION_PROBE = "reflection_probe"
    HEADER_PROBE = "header_probe"
    STATE_MUTATE = "state_mutate"
    EXFILTRATION = "exfiltration"
    DESTRUCTIVE = "destructive"


_BLOCKED_AUTO = frozenset({
    PayloadRiskClass.EXFILTRATION,
    PayloadRiskClass.DESTRUCTIVE,
    PayloadRiskClass.STATE_MUTATE,
})

_ALLOWED_AUTO = frozenset({
    PayloadRiskClass.SAFE_MARKER,
    PayloadRiskClass.REFLECTION_PROBE,
    PayloadRiskClass.HEADER_PROBE,
})


class ProbeError(Exception):
    """Raised when a blocked payload class is dispatched or validation fails."""


@dataclass(frozen=True)
class Payload:
    """A single classified payload entry.

    id: unique slug identifier (snake_case)
    risk_class: PayloadRiskClass
    value: the literal value injected or appended
    description: human-readable explanation
    tags: optional set of category tags
    """
    id: str
    risk_class: PayloadRiskClass
    value: str
    description: str
    tags: frozenset = field(default_factory=frozenset)

    def __post_init__(self):
        if not self.id or not self.id.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Payload id must be alphanumeric+underscores: {self.id!r}")
        if not isinstance(self.risk_class, PayloadRiskClass):
            raise TypeError(f"risk_class must be PayloadRiskClass, got {type(self.risk_class)}")


# ---------------------------------------------------------------------------
# Built-in SAFE_MARKER / REFLECTION_PROBE payloads (5 core entries)
# ---------------------------------------------------------------------------

BUILTIN_PAYLOADS: list[Payload] = [
    Payload(
        id="raven_canary_marker",
        risk_class=PayloadRiskClass.SAFE_MARKER,
        value="raven-canary-001",
        description="Plaintext canary marker; reflected in body signals echo point.",
        tags=frozenset({"canary", "reflection"}),
    ),
    Payload(
        id="raven_html_comment_probe",
        risk_class=PayloadRiskClass.REFLECTION_PROBE,
        value="<!--raven-probe-001-->",
        description="HTML comment probe; reflected comment indicates unescaped injection point.",
        tags=frozenset({"html", "reflection"}),
    ),
    Payload(
        id="raven_json_key_probe",
        risk_class=PayloadRiskClass.REFLECTION_PROBE,
        value='"raven-key-probe-001"',
        description="JSON-safe string probe for parameter reflection in JSON responses.",
        tags=frozenset({"json", "reflection"}),
    ),
    Payload(
        id="raven_header_trace_marker",
        risk_class=PayloadRiskClass.HEADER_PROBE,
        value="raven-trace-001",
        description="Header value probe; placed in X-Raven-Trace header to test header reflection.",
        tags=frozenset({"header", "reflection"}),
    ),
    Payload(
        id="raven_polyglot_canary",
        risk_class=PayloadRiskClass.SAFE_MARKER,
        value="raven’canary​002",
        description="Unicode canary with zero-width space; detects context-aware encoding differences.",
        tags=frozenset({"canary", "unicode", "reflection"}),
    ),
]


# ---------------------------------------------------------------------------
# PayloadDispatch
# ---------------------------------------------------------------------------

class PayloadDispatch:
    """Registry and dispatcher for classified payloads.

    EXFILTRATION and DESTRUCTIVE payloads may never be dispatched automatically.
    STATE_MUTATE is also blocked from auto-dispatch.
    """

    def __init__(self, extra_payloads: Optional[list[Payload]] = None):
        self._registry: dict[str, Payload] = {}
        for p in BUILTIN_PAYLOADS:
            self._registry[p.id] = p
        if extra_payloads:
            for p in extra_payloads:
                self.register(p)

    def register(self, payload: Payload) -> None:
        if payload.risk_class in (PayloadRiskClass.EXFILTRATION, PayloadRiskClass.DESTRUCTIVE):
            raise ProbeError(
                f"Cannot register {payload.risk_class.value!r} payload "
                f"'{payload.id}' — EXFILTRATION and DESTRUCTIVE payloads "
                f"must never be dispatched through this system."
            )
        if payload.id in self._registry:
            raise ValueError(f"Payload id {payload.id!r} already registered")
        self._registry[payload.id] = payload

    def get(self, payload_id: str) -> Payload:
        if payload_id not in self._registry:
            raise KeyError(f"Unknown payload id: {payload_id!r}")
        return self._registry[payload_id]

    def dispatch(self, payload_id: str) -> Payload:
        """Return payload for use in a scan, enforcing auto-dispatch safety.

        Raises ProbeError for EXFILTRATION, DESTRUCTIVE, or STATE_MUTATE.
        STATE_MUTATE requires explicit researcher approval outside this method.
        """
        p = self.get(payload_id)
        if p.risk_class in _BLOCKED_AUTO:
            raise ProbeError(
                f"Payload '{payload_id}' has risk class {p.risk_class.value!r} "
                f"which cannot be auto-dispatched. Manual researcher authorization required."
            )
        return p

    def list_by_class(self, risk_class: PayloadRiskClass) -> list[Payload]:
        return [p for p in self._registry.values() if p.risk_class == risk_class]

    def all_payloads(self) -> list[Payload]:
        return list(self._registry.values())

    def __len__(self) -> int:
        return len(self._registry)
