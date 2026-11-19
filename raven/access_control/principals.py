"""RAVEN Phase III — Principal, Resource, Action data models.

Educational models for the entities in an access control experiment.
These are pure data classes — they contain no network execution logic.

CRITICAL: These models describe SYNTHETIC EDUCATIONAL scenarios.
  Security authority: NONE. External targets contacted: 0.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from raven.access_control.taxonomy3 import (
    ActionType, PrincipalType, ResourceType,
)


# ── Principal ─────────────────────────────────────────────────────────────────

@dataclass
class Principal:
    """An entity that makes access requests in a controlled experiment.

    Attributes:
        principal_id: Unique identifier within the experiment.
        principal_type: Category (USER, ADMIN, ANONYMOUS, etc.).
        identity: Human-readable label (synthetic: "user_alice", "svc_payments").
        roles: Role/group memberships at experiment time.
        is_resource_owner: True if this principal owns the target resource.
    """
    principal_id: str
    principal_type: PrincipalType
    identity: str
    roles: list[str] = field(default_factory=list)
    is_resource_owner: bool = False
    data_source: str = "EDUCATIONAL_SYNTHETIC"

    def __post_init__(self) -> None:
        if not self.principal_id:
            raise ValueError("principal_id must not be empty")
        if not self.identity:
            raise ValueError("identity must not be empty")


# ── Resource ──────────────────────────────────────────────────────────────────

@dataclass
class Resource:
    """A resource that principals request access to in a controlled experiment.

    Attributes:
        resource_id: Unique identifier within the experiment.
        resource_type: Category (USER_OWNED_DATA, ADMIN_RESOURCE, etc.).
        path: URL path template or concrete path (synthetic only).
        owner_principal_id: The principal_id that owns this resource, or None.
        sensitivity: Qualitative data sensitivity ("HIGH", "MEDIUM", "LOW").
    """
    resource_id: str
    resource_type: ResourceType
    path: str
    owner_principal_id: Optional[str] = None
    sensitivity: str = "MEDIUM"
    data_source: str = "EDUCATIONAL_SYNTHETIC"

    def __post_init__(self) -> None:
        if not self.resource_id:
            raise ValueError("resource_id must not be empty")
        if not self.path:
            raise ValueError("path must not be empty")
        valid_sensitivity = {"HIGH", "MEDIUM", "LOW"}
        if self.sensitivity not in valid_sensitivity:
            raise ValueError(
                f"sensitivity must be one of {valid_sensitivity}, got {self.sensitivity!r}")

    @property
    def is_publicly_accessible(self) -> bool:
        return self.resource_type == ResourceType.PUBLIC_DATA


# ── Action ────────────────────────────────────────────────────────────────────

@dataclass
class Action:
    """An operation a principal attempts on a resource.

    Attributes:
        action_id: Unique identifier within the experiment.
        action_type: Category (READ, WRITE, DELETE, ADMIN, LIST).
        http_method: The HTTP method (GET, POST, PUT, DELETE, PATCH).
        requires_ownership: True if this action should only succeed for the owner.
        requires_admin_role: True if this action requires an admin role.
    """
    action_id: str
    action_type: ActionType
    http_method: str
    requires_ownership: bool = False
    requires_admin_role: bool = False
    data_source: str = "EDUCATIONAL_SYNTHETIC"

    _VALID_HTTP_METHODS: frozenset[str] = frozenset(
        {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})

    def __post_init__(self) -> None:
        if not self.action_id:
            raise ValueError("action_id must not be empty")
        self.http_method = self.http_method.upper()
        if self.http_method not in self._VALID_HTTP_METHODS:
            raise ValueError(f"invalid http_method: {self.http_method!r}")

    @property
    def is_mutating(self) -> bool:
        return self.http_method in {"POST", "PUT", "DELETE", "PATCH"}
