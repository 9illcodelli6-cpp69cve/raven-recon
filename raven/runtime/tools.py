"""RAVEN V7 Tool Registry and Dispatcher.

Every agent-usable capability is exposed through a common tool contract (§98-102).
Tools cannot self-grant authority — all invocations route through CapabilityGate.
Tool arguments from model output are UNTRUSTED INPUT and must be schema-validated (§168).
"""
from __future__ import annotations

import enum
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .execution import ActorKind, ExecutionRecord, ToolResult, ToolStatus


class SideEffectClass(str, enum.Enum):
    """Tool side-effect classification (§99)."""
    PURE              = "PURE"
    LOCAL_READ        = "LOCAL_READ"
    LOCAL_WRITE       = "LOCAL_WRITE"
    NETWORK_READ      = "NETWORK_READ"
    NETWORK_STATE_CHANGE = "NETWORK_STATE_CHANGE"
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    RESEARCH          = "RESEARCH"
    REPORT_EXPORT     = "REPORT_EXPORT"


@dataclass
class ToolDescriptor:
    """Complete tool definition (§98)."""
    tool_id:              str
    name:                 str
    description:          str
    version:              str = "1.0.0"
    required_capability:  str = "local_read"
    side_effect_class:    SideEffectClass = SideEffectClass.PURE
    input_schema:         Dict = field(default_factory=dict)
    output_schema:        Dict = field(default_factory=dict)
    execution_profile:    str = "PURE_LOCAL"
    timeout_ms:           int = 30_000
    cancellation_support: bool = False
    availability:         str = "AVAILABLE"   # AVAILABLE / UNAVAILABLE / DEGRADED
    metadata:             Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "required_capability": self.required_capability,
            "side_effect_class": self.side_effect_class.value,
            "execution_profile": self.execution_profile,
            "timeout_ms": self.timeout_ms,
            "cancellation_support": self.cancellation_support,
            "availability": self.availability,
        }


# The task a tool handler is running for (set around the handler call), so a process
# it spawns can be tagged and killed when that agent run is cancelled.
from contextvars import ContextVar as _ContextVar
CURRENT_TASK_ID: "_ContextVar[Optional[str]]" = _ContextVar("raven_tool_task_id", default=None)

@dataclass
class ToolInvocation:
    """Structured tool invocation from task/agent (§101)."""
    invocation_id:        str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    task_id:              Optional[str] = None
    agent_session_id:     Optional[str] = None
    tool_id:              str = ""
    arguments:            Dict = field(default_factory=dict)
    requested_capability: str = ""
    execution_profile:    str = "PURE_LOCAL"
    workspace_id:         Optional[str] = None
    actor:                ActorKind = ActorKind.RAVEN_AGENT
    correlation_id:       Optional[str] = None


def _validate_against_schema(arguments: dict, schema: dict) -> Optional[str]:
    """Simple JSON Schema subset validation (type, required, properties).
    Returns error message if invalid, None if valid.
    Model output is UNTRUSTED INPUT — we always validate (§168).
    """
    if not schema:
        return None
    required = schema.get("required", [])
    for key in required:
        if key not in arguments:
            return f"Missing required argument: '{key}'"
    props = schema.get("properties", {})
    for key, val in arguments.items():
        if key in props:
            expected_type = props[key].get("type")
            if expected_type == "string" and not isinstance(val, str):
                return f"Argument '{key}' must be a string"
            elif expected_type == "integer" and not isinstance(val, int):
                return f"Argument '{key}' must be an integer"
            elif expected_type == "boolean" and not isinstance(val, bool):
                return f"Argument '{key}' must be a boolean"
    return None


# Handler-reported outcome -> ToolStatus. Handlers (env/fs/knowledge/evidence/program
# and the ProcessExecutor-backed terminal) report refusals and errors in their output
# instead of raising; the dispatcher must not record those as SUCCESS.
_HANDLER_STATUS_MAP: Dict[str, ToolStatus] = {
    # success
    "ok": ToolStatus.SUCCESS, "success": ToolStatus.SUCCESS,
    "succeeded": ToolStatus.SUCCESS, "completed": ToolStatus.SUCCESS,
    "done": ToolStatus.SUCCESS, "stored": ToolStatus.SUCCESS,
    "recorded": ToolStatus.SUCCESS, "created": ToolStatus.SUCCESS,
    "partial": ToolStatus.PARTIAL,
    # refusals
    "denied": ToolStatus.DENIED, "blocked": ToolStatus.DENIED,
    "forbidden": ToolStatus.DENIED, "no_program_policy": ToolStatus.DENIED,
    # failures
    "error": ToolStatus.FAILED, "failed": ToolStatus.FAILED,
    "failure": ToolStatus.FAILED,
    "invalid": ToolStatus.INVALID_INPUT, "invalid_input": ToolStatus.INVALID_INPUT,
    "unavailable": ToolStatus.UNAVAILABLE, "not_dispatched": ToolStatus.UNAVAILABLE,
    "timed_out": ToolStatus.TIMED_OUT, "timeout": ToolStatus.TIMED_OUT,
    "cancelled": ToolStatus.CANCELLED, "canceled": ToolStatus.CANCELLED,
}


def classify_handler_output(output: Any) -> ToolStatus:
    """Map a handler's return value to the ToolStatus the dispatcher records.

    * a ``status`` string wins (case-insensitive; ToolStatus values such as
      ``"TIMED_OUT"`` from the ProcessExecutor map to themselves); an unrecognised
      status string is treated as a domain-specific success label;
    * otherwise ``ok: False`` or a non-empty ``error`` means FAILED;
    * anything else (including non-dict outputs) is SUCCESS.
    """
    if not isinstance(output, dict):
        return ToolStatus.SUCCESS
    status = output.get("status")
    if isinstance(status, ToolStatus):
        return status
    if isinstance(status, str) and status.strip():
        key = status.strip()
        try:
            return ToolStatus(key.upper())
        except ValueError:
            pass
        return _HANDLER_STATUS_MAP.get(key.lower(), ToolStatus.SUCCESS)
    if output.get("ok") is False:
        return ToolStatus.FAILED
    if output.get("error"):
        return ToolStatus.FAILED
    return ToolStatus.SUCCESS


def _handler_error_text(output: Any, status: ToolStatus) -> str:
    if isinstance(output, dict):
        for key in ("error", "reason", "message"):
            val = output.get(key)
            if val:
                return str(val)
        raw = output.get("status")
        if raw:
            return f"handler reported status '{raw}'"
    return f"handler reported {status.value}"


class ToolRegistry:
    """Owns discoverable tool definitions (§100).

    Tools must be registered with full descriptors.
    No globally-callable bare functions allowed.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._tools: Dict[str, ToolDescriptor] = {}
        self._handlers: Dict[str, Callable] = {}

    def register(self, descriptor: ToolDescriptor, handler: Callable) -> None:
        if not callable(handler):
            raise ValueError(f"handler for tool '{descriptor.tool_id}' must be callable")
        with self._lock:
            self._tools[descriptor.tool_id] = descriptor
            self._handlers[descriptor.tool_id] = handler

    def get(self, tool_id: str) -> Optional[ToolDescriptor]:
        with self._lock:
            return self._tools.get(tool_id)

    def list_all(self) -> List[ToolDescriptor]:
        with self._lock:
            return list(self._tools.values())

    def list_for_profile(self, profile: str) -> List[ToolDescriptor]:
        with self._lock:
            return [t for t in self._tools.values() if t.execution_profile == profile]

    def set_availability(self, tool_id: str, availability: str) -> None:
        with self._lock:
            if tool_id in self._tools:
                self._tools[tool_id].availability = availability

    def get_handler(self, tool_id: str) -> Optional[Callable]:
        with self._lock:
            return self._handlers.get(tool_id)

    def count(self) -> int:
        with self._lock:
            return len(self._tools)


class ToolDispatcher:
    """Routes tool invocations through validation, capability check, and execution (§101).

    Flow per §101:
      Invocation → Validate Schema → Resolve Tool → Capability Check →
      Policy Check → Budget Check → Execute → Capture Result →
      Publish Events → Persist Execution Record
    """

    def __init__(self, registry: ToolRegistry, capability_gate_factory: Callable,
                 execution_store=None, event_bus=None):
        self._registry = registry
        self._gate_factory = capability_gate_factory   # (workspace_id) -> CapabilityGate
        self._execution_store = execution_store
        self._event_bus = event_bus

    def invoke(self, invocation: ToolInvocation) -> tuple[ToolResult, ExecutionRecord]:
        """Execute a tool invocation. Returns (ToolResult, ExecutionRecord)."""
        rec = ExecutionRecord(
            task_id=invocation.task_id,
            agent_session_id=invocation.agent_session_id,
            tool_id=invocation.tool_id,
            actor=invocation.actor,
            workspace_id=invocation.workspace_id,
            execution_profile=invocation.execution_profile,
            correlation_id=invocation.correlation_id,
        )

        # Step 1: Resolve tool
        descriptor = self._registry.get(invocation.tool_id)
        if descriptor is None:
            rec.input_summary = f"tool_id={invocation.tool_id}"
            rec.finish(ToolStatus.UNAVAILABLE, f"Tool '{invocation.tool_id}' not registered")
            self._finalize(rec, event_type="tool.failed")
            return ToolResult(status=ToolStatus.UNAVAILABLE,
                              error=f"Tool '{invocation.tool_id}' is not registered"), rec

        if descriptor.availability != "AVAILABLE":
            rec.input_summary = f"tool_id={invocation.tool_id}"
            rec.finish(ToolStatus.UNAVAILABLE, f"Tool '{invocation.tool_id}' availability={descriptor.availability}")
            self._finalize(rec, event_type="tool.failed")
            return ToolResult(status=ToolStatus.UNAVAILABLE,
                              error=f"Tool '{invocation.tool_id}' is currently {descriptor.availability}"), rec

        rec.tool_version = descriptor.version
        rec.input_summary = f"tool={descriptor.name} args={list(invocation.arguments.keys())}"

        # Step 2: Validate schema (model args are UNTRUSTED INPUT)
        schema_error = _validate_against_schema(invocation.arguments, descriptor.input_schema)
        if schema_error:
            rec.finish(ToolStatus.INVALID_INPUT, schema_error)
            self._finalize(rec, event_type="tool.failed")
            return ToolResult(status=ToolStatus.INVALID_INPUT, error=schema_error), rec

        # Step 3: Capability check
        gate = self._gate_factory(invocation.workspace_id or "")
        cap_result = gate.check(
            descriptor.required_capability,
            context={
                "destination": invocation.arguments.get("destination", "local"),
                "method": invocation.arguments.get("method", "GET"),
                "reason": f"Tool execution: {descriptor.name}",
                "risk_class": descriptor.metadata.get("risk_class"),
            }
        )
        rec.capability_decision = cap_result.decision.value

        if not cap_result.is_allowed():
            msg = f"Capability '{descriptor.required_capability}' denied: {cap_result.reason}"
            rec.finish(ToolStatus.DENIED, msg)
            self._finalize(rec, event_type="tool.denied")
            return ToolResult(status=ToolStatus.DENIED, error=msg), rec

        # Step 4: Execute
        self._publish("tool.invoked", invocation, rec)
        handler = self._registry.get_handler(invocation.tool_id)
        task_token = CURRENT_TASK_ID.set(invocation.task_id)
        try:
            output = handler(invocation.arguments)
        except TimeoutError as exc:
            rec.finish(ToolStatus.TIMED_OUT, str(exc))
            self._finalize(rec, event_type="tool.failed")
            return ToolResult(status=ToolStatus.TIMED_OUT, error=str(exc)), rec
        except Exception as exc:  # noqa: BLE001
            msg = f"{type(exc).__name__}: {exc}"
            rec.finish(ToolStatus.FAILED, msg)
            self._finalize(rec, event_type="tool.failed")
            return ToolResult(status=ToolStatus.FAILED, error=msg), rec
        finally:
            CURRENT_TASK_ID.reset(task_token)

        # Step 5: Classify the handler-REPORTED outcome. A handler that refused or
        # failed (status denied/error/invalid/unavailable/TIMED_OUT, ok=False, error)
        # is recorded as such — never as SUCCESS.
        status = classify_handler_output(output)
        if status in (ToolStatus.SUCCESS, ToolStatus.PARTIAL):
            rec.finish(status)
            self._finalize(rec, event_type="tool.completed")
            return ToolResult(status=status, output=output), rec
        err = _handler_error_text(output, status)
        rec.finish(status, err)
        self._finalize(rec, event_type=("tool.denied" if status == ToolStatus.DENIED
                                        else "tool.failed"))
        return ToolResult(status=status, output=output, error=err), rec

    def _finalize(self, rec: ExecutionRecord, event_type: str) -> None:
        if self._execution_store:
            try:
                self._execution_store.save(rec)
            except Exception:
                pass
        self._publish(event_type, None, rec)

    def _publish(self, event_type: str, invocation: Optional[ToolInvocation],
                 rec: ExecutionRecord) -> None:
        if self._event_bus:
            payload = rec.to_dict()
            if invocation:
                payload["invocation_id"] = invocation.invocation_id
            try:
                self._event_bus.publish(
                    event_type, payload,
                    task_id=rec.task_id,
                    workspace_id=rec.workspace_id,
                    source="tool_dispatcher",
                )
            except Exception:
                pass
