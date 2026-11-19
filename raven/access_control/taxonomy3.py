"""RAVEN Phase III — Access Control Academy taxonomy.

Defines enumeration types for SEC-A and authorization concepts.

INVARIANT: No class value here implies a confirmed vulnerability.
  AuthorizationViolationType is a CONCEPTUAL LABEL for educational
  classification only — not a security verdict.
  Security authority: NONE.
"""
from __future__ import annotations

from enum import Enum


# ── Principal taxonomy ────────────────────────────────────────────────────────

class PrincipalType(str, Enum):
    """The category of entity making an access request."""
    USER             = "USER"             # human end-user account
    SERVICE_ACCOUNT  = "SERVICE_ACCOUNT"  # non-interactive service identity
    ANONYMOUS        = "ANONYMOUS"        # no authenticated identity
    API_KEY          = "API_KEY"          # machine credential without session
    ADMIN            = "ADMIN"            # privileged administrative account

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]


# ── Resource taxonomy ─────────────────────────────────────────────────────────

class ResourceType(str, Enum):
    """The category of resource being accessed."""
    USER_OWNED_DATA  = "USER_OWNED_DATA"  # data scoped to a specific user
    SHARED_DATA      = "SHARED_DATA"       # data shared across multiple users
    ADMIN_RESOURCE   = "ADMIN_RESOURCE"    # admin-only endpoint or data
    PUBLIC_DATA      = "PUBLIC_DATA"       # no access control required
    SYSTEM_RESOURCE  = "SYSTEM_RESOURCE"   # internal system/infrastructure

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]


# ── Action taxonomy ───────────────────────────────────────────────────────────

class ActionType(str, Enum):
    """The category of operation a principal attempts."""
    READ    = "READ"    # retrieves data without modifying state
    WRITE   = "WRITE"   # creates or updates data
    DELETE  = "DELETE"  # removes data
    ADMIN   = "ADMIN"   # administrative operation
    LIST    = "LIST"    # enumerates resources

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]


# ── Access decision ───────────────────────────────────────────────────────────

class AccessDecision(str, Enum):
    """The authorization decision for a given AccessTuple."""
    ALLOWED     = "ALLOWED"      # access should be permitted
    DENIED      = "DENIED"       # access should be refused
    CONDITIONAL = "CONDITIONAL"  # permitted only under specific context conditions
    UNKNOWN     = "UNKNOWN"      # cannot determine without more information

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]


# ── Authorization violation type ──────────────────────────────────────────────

class AuthorizationViolationType(str, Enum):
    """Conceptual label for educational classification of authorization scenarios.

    CRITICAL: These are EDUCATIONAL LABELS for structured analysis only.
      AuthorizationViolationType != confirmed vulnerability.
      AuthorizationViolationType != security finding.
      Human verification is ALWAYS required before reaching any conclusion.
      Security authority: NONE.

    Vocabulary (conceptual definitions only):
      BOLA  — Broken Object Level Authorization: a principal accesses an
              object owned by another principal via a guessable/enumerable ID.
      BFLA  — Broken Function Level Authorization: a principal invokes a
              function (endpoint/action) that requires a higher privilege role.
      HORIZONTAL_PRIVILEGE_ESCALATION — same-tier principal accesses another's data.
      VERTICAL_PRIVILEGE_ESCALATION   — lower-tier principal accesses higher-tier function.
    """
    BOLA                           = "BOLA"
    BFLA                           = "BFLA"
    MISSING_FUNCTION_LEVEL_ACCESS  = "MISSING_FUNCTION_LEVEL_ACCESS"
    HORIZONTAL_PRIVILEGE_ESCALATION = "HORIZONTAL_PRIVILEGE_ESCALATION"
    VERTICAL_PRIVILEGE_ESCALATION  = "VERTICAL_PRIVILEGE_ESCALATION"
    NO_VIOLATION_EXPECTED          = "NO_VIOLATION_EXPECTED"
    INCONCLUSIVE                   = "INCONCLUSIVE"
    UNKNOWN                        = "UNKNOWN"

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]

    @classmethod
    def label_index(cls) -> dict[str, int]:
        return {c.value: i for i, c in enumerate(cls)}


# ── SEC-A: Authorization Experiment Quality ───────────────────────────────────

class AuthorizationExperimentQuality(str, Enum):
    """SEC-A output class.

    Classifies how well-controlled an access control comparison experiment is,
    based on how many authorization dimensions changed between the control and
    test requests.

    Analogous to ExperimentQualityClass (NET-F) but applied to the
    PRINCIPAL / ACTION / RESOURCE / CONTEXT dimensions of access control.

    CRITICAL: SEC-A classification ≠ vulnerability detection.
      A CONTROLLED_SINGLE_PRINCIPAL experiment might reveal nothing unusual.
      Security authority: NONE.
    """
    CONTROLLED_SINGLE_PRINCIPAL = "CONTROLLED_SINGLE_PRINCIPAL"  # only principal changed
    CONTROLLED_SINGLE_ACTION    = "CONTROLLED_SINGLE_ACTION"      # only action changed
    CONTROLLED_SINGLE_RESOURCE  = "CONTROLLED_SINGLE_RESOURCE"    # only resource changed
    CONFOUNDED                  = "CONFOUNDED"                     # multiple dimensions changed
    NO_MEANINGFUL_CHANGE        = "NO_MEANINGFUL_CHANGE"           # identical tuples, same response
    INSUFFICIENT_CONTEXT        = "INSUFFICIENT_CONTEXT"           # cannot determine changed dims
    UNKNOWN                     = "UNKNOWN"

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]

    @classmethod
    def label_index(cls) -> dict[str, int]:
        return {c.value: i for i, c in enumerate(cls)}


# ── Authorization dimension vocabulary ───────────────────────────────────────

AUTHORIZATION_DIMENSIONS: tuple[str, ...] = (
    # Principal dimensions (who is making the request)
    "principal_id_changed",    # different user/service identity
    "principal_type_changed",  # PrincipalType changed (USER → ADMIN)
    "principal_role_changed",  # role/group membership changed
    # Action dimensions (what operation)
    "action_type_changed",     # ActionType changed (READ → DELETE)
    "http_method_changed",     # HTTP method changed (GET → POST)
    # Resource dimensions (what is being accessed)
    "resource_id_changed",     # different resource instance (BOLA-relevant)
    "resource_type_changed",   # ResourceType changed
    "resource_owner_changed",  # resource's owner principal changed
    # Context dimensions (under what conditions)
    "session_changed",         # session identity changed
    "context_changed",         # other context (IP, time) changed
)

# Dimension groups for SEC-A single-variable classification
_PRINCIPAL_DIMS = frozenset({
    "principal_id_changed",
    "principal_type_changed",
    "principal_role_changed",
})
_ACTION_DIMS = frozenset({
    "action_type_changed",
    "http_method_changed",
})
_RESOURCE_DIMS = frozenset({
    "resource_id_changed",
    "resource_type_changed",
    "resource_owner_changed",
})
