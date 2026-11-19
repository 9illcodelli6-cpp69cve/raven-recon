"""RAVEN V7 Runtime Error Taxonomy.

All V7 runtime failures use typed categories (§135-136).
Subsystem-specific errors may subclass RuntimeError.
"""
from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional


class ErrorCategory(str, enum.Enum):
    CONFIGURATION   = "CONFIGURATION_ERROR"
    VALIDATION      = "VALIDATION_ERROR"
    POLICY_DENIED   = "POLICY_DENIED"
    CAPABILITY_DENIED = "CAPABILITY_DENIED"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    MODEL_ERROR     = "MODEL_ERROR"
    NETWORK_ERROR   = "NETWORK_ERROR"
    PROCESS_ERROR   = "PROCESS_ERROR"
    FILESYSTEM_ERROR = "FILESYSTEM_ERROR"
    PERSISTENCE_ERROR = "PERSISTENCE_ERROR"
    TIMEOUT         = "TIMEOUT"
    CANCELLED       = "CANCELLED"
    RESOURCE_LIMIT  = "RESOURCE_LIMIT"
    INTERNAL_ERROR  = "INTERNAL_ERROR"
    UNKNOWN         = "UNKNOWN_ERROR"


@dataclass
class RuntimeError(Exception):
    """Typed runtime error with category, recoverability, and diagnostic refs."""
    category:   ErrorCategory
    code:       str
    message:    str
    task_id:    Optional[str] = None
    tool_id:    Optional[str] = None
    recoverable: bool = False
    retryable:  bool = False
    error_id:   str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp:  int = field(default_factory=lambda: int(time.time() * 1000))
    diagnostic_refs: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"[{self.category.value}/{self.code}] {self.message}"

    def to_dict(self) -> dict:
        return {
            "error_id": self.error_id,
            "category": self.category.value,
            "code": self.code,
            "message": self.message,
            "task_id": self.task_id,
            "tool_id": self.tool_id,
            "recoverable": self.recoverable,
            "retryable": self.retryable,
            "timestamp": self.timestamp,
        }


class PolicyDeniedError(RuntimeError):
    def __init__(self, message: str, *, task_id: str = None, tool_id: str = None):
        super().__init__(
            category=ErrorCategory.POLICY_DENIED,
            code="POLICY_DENIED",
            message=message,
            task_id=task_id,
            tool_id=tool_id,
            recoverable=False,
            retryable=False,
        )


class CapabilityDeniedError(RuntimeError):
    def __init__(self, capability: str, reason: str, *, task_id: str = None, tool_id: str = None):
        super().__init__(
            category=ErrorCategory.CAPABILITY_DENIED,
            code="CAPABILITY_DENIED",
            message=f"Capability '{capability}' denied: {reason}",
            task_id=task_id,
            tool_id=tool_id,
            recoverable=False,
            retryable=False,
        )


class ToolUnavailableError(RuntimeError):
    def __init__(self, tool_id: str, message: str = ""):
        super().__init__(
            category=ErrorCategory.TOOL_UNAVAILABLE,
            code="TOOL_UNAVAILABLE",
            message=message or f"Tool '{tool_id}' is unavailable",
            tool_id=tool_id,
            recoverable=True,
            retryable=False,
        )


class InvalidTaskTransitionError(RuntimeError):
    def __init__(self, from_state: str, to_state: str, task_id: str = None):
        super().__init__(
            category=ErrorCategory.VALIDATION,
            code="INVALID_TASK_TRANSITION",
            message=f"Invalid task state transition: {from_state} → {to_state}",
            task_id=task_id,
            recoverable=False,
            retryable=False,
        )


class WorkspaceNotFoundError(RuntimeError):
    def __init__(self, workspace_id: str):
        super().__init__(
            category=ErrorCategory.VALIDATION,
            code="WORKSPACE_NOT_FOUND",
            message=f"Workspace '{workspace_id}' not found",
            recoverable=False,
            retryable=False,
        )


# Alias so runtime.py can import by a name that doesn't shadow the builtin
RavenRuntimeError = RuntimeError
