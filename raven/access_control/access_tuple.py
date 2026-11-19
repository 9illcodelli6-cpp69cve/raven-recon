"""RAVEN Phase III — AccessTuple, AccessContext, AuthorizationMatrix.

The central data structures for access control experiment analysis.

CRITICAL: AuthorizationMatrix describes EXPECTED authorization state for
  educational comparison. It is NOT a policy engine and does NOT grant or
  deny real access. Security authority: NONE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from raven.access_control.taxonomy3 import (
    AccessDecision, AuthorizationExperimentQuality,
    AUTHORIZATION_DIMENSIONS, AuthorizationViolationType,
    _PRINCIPAL_DIMS, _ACTION_DIMS, _RESOURCE_DIMS,
)
from raven.access_control.principals import Action, Principal, Resource


# ── Access context ────────────────────────────────────────────────────────────

@dataclass
class AccessContext:
    """Additional contextual parameters of an access request.

    Uses synthetic values only — no real IP addresses, sessions, or credentials.
    """
    session_id: Optional[str] = None       # e.g., "session_user_alice_1"
    ip_class: Optional[str] = None         # "INTERNAL", "EXTERNAL" (never real IPs)
    timestamp_offset_ms: int = 0           # relative to experiment epoch
    extra: dict = field(default_factory=dict)


# ── Access tuple ──────────────────────────────────────────────────────────────

@dataclass
class AccessTuple:
    """The (PRINCIPAL, ACTION, RESOURCE, CONTEXT) tuple of an access request.

    Central unit of analysis for authorization experiments.
    Answers: WHO is doing WHAT on WHAT under WHAT context?

    Attributes:
        principal: The entity making the request.
        action: The operation being attempted.
        resource: The resource being accessed.
        context: Additional context (session, IP class, time).
        expected_decision: The EXPECTED authorization outcome per policy.
        observed_decision: The OBSERVED outcome from the server response (if known).
    """
    principal: Principal
    action: Action
    resource: Resource
    context: AccessContext = field(default_factory=AccessContext)
    expected_decision: AccessDecision = AccessDecision.UNKNOWN
    observed_decision: AccessDecision = AccessDecision.UNKNOWN
    data_source: str = "EDUCATIONAL_SYNTHETIC"

    @property
    def key(self) -> tuple[str, str, str]:
        """Canonical key: (principal_id, action_id, resource_id)."""
        return (self.principal.principal_id,
                self.action.action_id,
                self.resource.resource_id)

    @property
    def decision_matches(self) -> Optional[bool]:
        """True if observed == expected; False if diverged; None if either is UNKNOWN."""
        if (self.expected_decision == AccessDecision.UNKNOWN or
                self.observed_decision == AccessDecision.UNKNOWN):
            return None
        return self.expected_decision == self.observed_decision


# ── Changed-dimension detection ───────────────────────────────────────────────

def compute_authorization_dimensions(
    control: AccessTuple,
    test: AccessTuple,
) -> list[str]:
    """Compute which authorization dimensions changed between control and test.

    Returns a sorted list of changed dimension names from AUTHORIZATION_DIMENSIONS.
    Based on differences in Principal / Action / Resource / Context components.
    """
    changed: list[str] = []

    cp, tp = control.principal, test.principal
    if cp.principal_id != tp.principal_id:
        changed.append("principal_id_changed")
    if cp.principal_type != tp.principal_type:
        changed.append("principal_type_changed")
    if set(cp.roles) != set(tp.roles):
        changed.append("principal_role_changed")

    ca, ta = control.action, test.action
    if ca.action_type != ta.action_type:
        changed.append("action_type_changed")
    if ca.http_method != ta.http_method:
        changed.append("http_method_changed")

    cr, tr = control.resource, test.resource
    if cr.resource_id != tr.resource_id:
        changed.append("resource_id_changed")
    if cr.resource_type != tr.resource_type:
        changed.append("resource_type_changed")
    # resource_owner_changed only fires when the resource_id stays the same
    # but ownership changes — an independent dimension (unusual but possible).
    if cr.resource_id == tr.resource_id and cr.owner_principal_id != tr.owner_principal_id:
        changed.append("resource_owner_changed")

    cc, tc = control.context, test.context
    if cc.session_id != tc.session_id:
        changed.append("session_changed")
    if cc.ip_class != tc.ip_class or cc.extra != tc.extra:
        changed.append("context_changed")

    return sorted(changed)


def classify_authorization_experiment(
    control: AccessTuple,
    test: AccessTuple,
    control_http_status: Optional[int] = None,
    test_http_status: Optional[int] = None,
    control_body: Optional[str] = None,
    test_body: Optional[str] = None,
) -> AuthorizationExperimentQuality:
    """SEC-A rule: classify the quality of an authorization comparison.

    This is the core SEC-A deterministic rule.  It examines how many
    authorization dimensions changed between the control and test requests
    and returns the appropriate quality class.

    Args:
        control: The baseline/reference access tuple.
        test: The experimental access tuple.
        control_http_status: HTTP status of the control observation (optional).
        test_http_status: HTTP status of the test observation (optional).
        control_body: Response body of the control observation (optional).
        test_body: Response body of the test observation (optional).

    CRITICAL: The result is an experiment quality label, NOT a security verdict.
    """
    changed = compute_authorization_dimensions(control, test)
    n = len(changed)

    if n == 0:
        # No authorization dimensions changed
        if (control_http_status is not None and test_http_status is not None
                and control_http_status == test_http_status
                and control_body == test_body):
            return AuthorizationExperimentQuality.NO_MEANINGFUL_CHANGE
        return AuthorizationExperimentQuality.INSUFFICIENT_CONTEXT

    # Treat correlated within-group changes as CONTROLLED_SINGLE_* for that group.
    # E.g. changing ActionType from READ→WRITE also changes http_method GET→PUT:
    # both are ACTION_DIMS, so it's still a single-variable experiment.
    changed_set = set(changed)

    if changed_set and changed_set <= _PRINCIPAL_DIMS:
        return AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL
    if changed_set and changed_set <= _ACTION_DIMS:
        return AuthorizationExperimentQuality.CONTROLLED_SINGLE_ACTION
    if changed_set and changed_set <= _RESOURCE_DIMS:
        return AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE

    # context-only change → INSUFFICIENT_CONTEXT (can't isolate from other factors)
    _CONTEXT_DIMS = frozenset({"session_changed", "context_changed"})
    if changed_set and changed_set <= _CONTEXT_DIMS:
        return AuthorizationExperimentQuality.INSUFFICIENT_CONTEXT

    # Mixed groups → CONFOUNDED
    return AuthorizationExperimentQuality.CONFOUNDED


# ── Authorization matrix ──────────────────────────────────────────────────────

@dataclass
class AuthorizationEntry:
    """One cell in an AuthorizationMatrix."""
    principal_id: str
    action_id: str
    resource_id: str
    decision: AccessDecision
    rationale: str = ""
    conditions: list[str] = field(default_factory=list)
    data_source: str = "EDUCATIONAL_SYNTHETIC"

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.principal_id, self.action_id, self.resource_id)


class AuthorizationMatrix:
    """An educational model of expected authorization decisions.

    Maps (principal_id, action_id, resource_id) tuples to AccessDecision values.
    Used to describe EXPECTED authorization state for comparison against
    observed server behavior.

    CRITICAL: AuthorizationMatrix is a CONCEPTUAL EDUCATIONAL MODEL.
      It is NOT a real access control policy.
      It does NOT grant or deny actual access.
      Security authority: NONE.
    """

    def __init__(self, matrix_id: str, description: str = "") -> None:
        self.matrix_id = matrix_id
        self.description = description
        self._entries: dict[tuple[str, str, str], AuthorizationEntry] = {}
        self.data_source = "EDUCATIONAL_SYNTHETIC"

    def add_entry(
        self,
        principal: Principal,
        action: Action,
        resource: Resource,
        decision: AccessDecision,
        rationale: str = "",
        conditions: Optional[list[str]] = None,
    ) -> "AuthorizationMatrix":
        key = (principal.principal_id, action.action_id, resource.resource_id)
        self._entries[key] = AuthorizationEntry(
            principal_id=principal.principal_id,
            action_id=action.action_id,
            resource_id=resource.resource_id,
            decision=decision,
            rationale=rationale,
            conditions=conditions or [],
        )
        return self

    def lookup(
        self,
        principal_id: str,
        action_id: str,
        resource_id: str,
    ) -> AccessDecision:
        """Look up the expected decision for a principal/action/resource triple."""
        entry = self._entries.get((principal_id, action_id, resource_id))
        return entry.decision if entry else AccessDecision.UNKNOWN

    def entries(self) -> list[AuthorizationEntry]:
        return list(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"AuthorizationMatrix({self.matrix_id!r}, entries={len(self)})"
