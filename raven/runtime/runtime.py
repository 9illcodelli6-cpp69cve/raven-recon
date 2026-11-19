"""RAVEN V7 Runtime — Central Manager.

ONE shared runtime for all agent types (§73).
Different agent types are configurations, not separate runtimes.

Runtime state machine:
  STARTING → READY (all subsystems healthy)
           → DEGRADED (partial startup — optional subsystems failed)
  READY / DEGRADED → PAUSING → PAUSED
  PAUSED → READY / DEGRADED (resume)
  READY / DEGRADED / PAUSED → STOPPING → STOPPED
  * → FAILED (unrecoverable error during startup)
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from raven.runtime.capabilities import CapabilityGate
from raven.runtime.checkpoint import CheckpointEngine
from raven.runtime.conversation import ConversationContext
from raven.runtime.errors import RavenRuntimeError, ErrorCategory
from raven.runtime.events import EventBus, EventType
from raven.runtime.execution import ExecutionStore
from raven.runtime.model import ModelService
from raven.runtime.plugins import PluginRegistry
from raven.runtime.tasks import TaskRegistry, TaskStatus
from raven.runtime.tools import ToolDispatcher, ToolRegistry
from raven.runtime.workspace import WorkspaceManager
from raven.security.policy_gate import Capability, PolicyGate

logger = logging.getLogger(__name__)


class RuntimeState(str, Enum):
    STARTING  = "STARTING"
    READY     = "READY"
    DEGRADED  = "DEGRADED"
    PAUSING   = "PAUSING"
    PAUSED    = "PAUSED"
    STOPPING  = "STOPPING"
    STOPPED   = "STOPPED"
    FAILED    = "FAILED"


_LEGAL_TRANSITIONS: Dict[RuntimeState, frozenset] = {
    RuntimeState.STARTING:  frozenset({RuntimeState.READY, RuntimeState.DEGRADED, RuntimeState.FAILED}),
    RuntimeState.READY:     frozenset({RuntimeState.PAUSING, RuntimeState.STOPPING, RuntimeState.DEGRADED, RuntimeState.FAILED}),
    RuntimeState.DEGRADED:  frozenset({RuntimeState.READY, RuntimeState.PAUSING, RuntimeState.STOPPING, RuntimeState.FAILED}),
    RuntimeState.PAUSING:   frozenset({RuntimeState.PAUSED, RuntimeState.FAILED}),
    RuntimeState.PAUSED:    frozenset({RuntimeState.READY, RuntimeState.DEGRADED, RuntimeState.STOPPING, RuntimeState.FAILED}),
    RuntimeState.STOPPING:  frozenset({RuntimeState.STOPPED, RuntimeState.FAILED}),
    RuntimeState.STOPPED:   frozenset(),
    RuntimeState.FAILED:    frozenset({RuntimeState.STOPPED}),
}

# Default capabilities for the runtime's own workspace
_RUNTIME_DEFAULT_CAPS = frozenset({
    Capability.FILE_READ_WORKSPACE,
    Capability.FILE_WRITE_WORKSPACE,
    Capability.REPORT_EXPORT,
    Capability.SCOPE_READ,
    Capability.SCOPE_WRITE,
})


@dataclass
class SubsystemHealth:
    name:      str
    healthy:   bool
    required:  bool = True
    error:     Optional[str] = None


@dataclass
class RuntimeConfig:
    """Runtime configuration. All optional — safe defaults apply."""
    db_path:          str = ""
    workspace_id:     str = "runtime-bootstrap"
    max_task_turns:   int = 100
    conversation_max_turns: int = 100
    metadata:         Dict = field(default_factory=dict)


class RavenRuntime:
    """Central V7 runtime (§73, §B12).

    Owns the full subsystem lifecycle. Callers receive a started runtime via
    `RavenRuntime.start()` and shut down with `.shutdown()`.

    Usage:
        db = sqlite3.connect("raven.db", check_same_thread=False)
        db.row_factory = sqlite3.Row
        rt = RavenRuntime(db=db)
        rt.start()
        rt.shutdown()
    """

    def __init__(
        self,
        db: sqlite3.Connection,
        config: RuntimeConfig = None,
        gate_factory: Callable[[str], CapabilityGate] = None,
        model_service: ModelService = None,
    ):
        self.runtime_id: str = uuid.uuid4().hex[:16]
        self._config = config or RuntimeConfig()
        self._db = db

        self._state: RuntimeState = RuntimeState.STARTING
        self._state_lock = threading.RLock()
        self._health: List[SubsystemHealth] = []

        # Default capability gate factory — each workspace gets its own gate
        self._gate_factory: Callable[[str], CapabilityGate] = gate_factory or self._default_gate_factory

        # Runtime-level gate (for emergency stop queries, system operations)
        self.capabilities: CapabilityGate = self._gate_factory(
            self._config.workspace_id
        )

        # ── Subsystems ────────────────────────────────────────────────────────
        self.bus:           EventBus         = EventBus()
        self.tasks:         TaskRegistry     = TaskRegistry(
            db=db,
            event_callback=lambda et, t: self.bus.publish(
                et, {"task_id": t.task_id, "title": t.title}
            ),
        )
        self.tools:         ToolRegistry     = ToolRegistry()
        self.executions:    ExecutionStore   = ExecutionStore(db=db)
        self.dispatcher:    ToolDispatcher   = ToolDispatcher(
            registry=self.tools,
            capability_gate_factory=self._gate_factory,
            execution_store=self.executions,
            event_bus=self.bus,
        )
        self.model:         ModelService     = model_service or ModelService()
        self.workspaces:    WorkspaceManager = WorkspaceManager(db=db)
        self.conversations: ConversationContext = ConversationContext(
            db=db, max_turns=self._config.conversation_max_turns
        )
        self.checkpoints:   CheckpointEngine = CheckpointEngine(db=db)
        self.plugins:       PluginRegistry   = PluginRegistry()

    # ── Default gate factory ──────────────────────────────────────────────────

    def _default_gate_factory(self, workspace_id: str) -> CapabilityGate:
        ws = workspace_id or self._config.workspace_id
        return CapabilityGate(
            workspace_id=ws,
            granted_capabilities=set(_RUNTIME_DEFAULT_CAPS),
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> "RavenRuntime":
        """Start the runtime. Returns self for chaining."""
        with self._state_lock:
            if self._state not in (RuntimeState.STARTING,):
                raise RavenRuntimeError(
                    ErrorCategory.CONFIGURATION,
                    "RUNTIME_ALREADY_STARTED",
                    f"Cannot start: runtime is {self._state.value}",
                )

        degraded = False
        subsystems: List[SubsystemHealth] = []

        for name, fn, required in [
            ("tasks",         self._check_tasks,         True),
            ("executions",    self._check_executions,    True),
            ("workspaces",    self._check_workspaces,    True),
            ("conversations", self._check_conversations, True),
            ("checkpoints",   self._check_checkpoints,   True),
            ("capabilities",  self._check_capabilities,  True),
            ("tools",         self._check_tools,         True),
            ("model",         self._check_model,         False),
            ("plugins",       self._check_plugins,       False),
        ]:
            try:
                fn()
                subsystems.append(SubsystemHealth(name=name, healthy=True, required=required))
                logger.debug("V7 runtime subsystem OK: %s", name)
            except Exception as exc:  # noqa: BLE001
                subsystems.append(SubsystemHealth(name=name, healthy=False,
                                                   required=required, error=str(exc)))
                logger.warning("V7 runtime subsystem FAILED: %s — %s", name, exc)
                if required:
                    degraded = True

        self._health = subsystems

        # Crash-recovery: interrupted tasks
        try:
            self.tasks._restore_from_db()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Task recovery partial failure: %s", exc)

        if any(s.required and not s.healthy for s in subsystems):
            failed_required = [s.name for s in subsystems if s.required and not s.healthy]
            self._transition(RuntimeState.FAILED)
            raise RavenRuntimeError(
                ErrorCategory.CONFIGURATION,
                "RUNTIME_START_FAILED",
                f"Required subsystems failed: {failed_required}",
            )

        new_state = RuntimeState.DEGRADED if degraded else RuntimeState.READY
        self._transition(new_state)

        self.bus.publish(EventType.RUNTIME_STARTED,
                         {"runtime_id": self.runtime_id, "state": new_state.value})
        logger.info("RavenRuntime %s started — state=%s", self.runtime_id, new_state.value)
        return self

    def shutdown(self, cancel_tasks: bool = True, timeout_s: float = 10.0) -> None:
        """Graceful shutdown — cancel active tasks, emit stopped event."""
        with self._state_lock:
            if self._state in (RuntimeState.STOPPED, RuntimeState.STOPPING):
                return
            if self._state == RuntimeState.FAILED:
                self._state = RuntimeState.STOPPED
                return

        self._transition(RuntimeState.STOPPING)

        if cancel_tasks:
            active = self.tasks.list_active()
            for task in active:
                try:
                    self.tasks.transition(task.task_id, TaskStatus.CANCELLED)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Shutdown: could not cancel task %s: %s", task.task_id, exc)

        self.bus.publish(EventType.RUNTIME_STOPPED, {"runtime_id": self.runtime_id})
        self._transition(RuntimeState.STOPPED)
        logger.info("RavenRuntime %s stopped.", self.runtime_id)

    def pause(self) -> None:
        self._transition(RuntimeState.PAUSING)
        self.bus.publish(EventType.RUNTIME_STATE_CHANGED,
                         {"runtime_id": self.runtime_id, "state": RuntimeState.PAUSING.value})
        self._transition(RuntimeState.PAUSED)

    def resume(self) -> None:
        with self._state_lock:
            if self._state != RuntimeState.PAUSED:
                return
        health_ok = all(s.healthy for s in self._health if s.required)
        new_state = RuntimeState.READY if health_ok else RuntimeState.DEGRADED
        self._transition(new_state)
        self.bus.publish(EventType.RUNTIME_STATE_CHANGED,
                         {"runtime_id": self.runtime_id, "state": new_state.value})

    def trigger_emergency_stop(self) -> None:
        self.capabilities.trigger_emergency_stop()
        self.bus.publish(EventType.EMERGENCY_STOP,
                         {"runtime_id": self.runtime_id, "actor": "researcher"})
        logger.critical("EMERGENCY STOP triggered on runtime %s", self.runtime_id)

    # ── State machine ─────────────────────────────────────────────────────────

    def _transition(self, new_state: RuntimeState) -> None:
        with self._state_lock:
            allowed = _LEGAL_TRANSITIONS.get(self._state, frozenset())
            if new_state not in allowed:
                raise RavenRuntimeError(
                    ErrorCategory.INTERNAL_ERROR,
                    "INVALID_RUNTIME_TRANSITION",
                    f"Cannot transition {self._state.value} → {new_state.value}",
                )
            self._state = new_state

    @property
    def state(self) -> RuntimeState:
        with self._state_lock:
            return self._state

    @property
    def is_operational(self) -> bool:
        return self._state in (RuntimeState.READY, RuntimeState.DEGRADED)

    # ── Subsystem checks ──────────────────────────────────────────────────────

    def _check_tasks(self) -> None:
        self.tasks._migrate()

    def _check_executions(self) -> None:
        self.executions._migrate()

    def _check_workspaces(self) -> None:
        self.workspaces._extend_schema()

    def _check_conversations(self) -> None:
        self.conversations._migrate()

    def _check_checkpoints(self) -> None:
        self.checkpoints._migrate()

    def _check_capabilities(self) -> None:
        if PolicyGate.is_emergency_stop_active():
            raise RuntimeError("CapabilityGate is in emergency-stop state")

    def _check_tools(self) -> None:
        if self.dispatcher is None:
            raise RuntimeError("ToolDispatcher not wired")

    def _check_model(self) -> None:
        providers = self.model.list_providers()
        if len(providers) == 0:
            logger.debug("No model providers registered — model subsystem optional")

    def _check_plugins(self) -> None:
        pass

    # ── Health ────────────────────────────────────────────────────────────────

    def health_report(self) -> Dict[str, Any]:
        with self._state_lock:
            state = self._state.value
        return {
            "runtime_id": self.runtime_id,
            "state": state,
            "is_operational": self.is_operational,
            "emergency_stop": PolicyGate.is_emergency_stop_active(),
            "subsystems": [
                {"name": s.name, "healthy": s.healthy, "required": s.required, "error": s.error}
                for s in self._health
            ],
            "active_tasks": len(self.tasks.list_active()),
            "active_plugins": self.plugins.count(),
        }

    def __repr__(self) -> str:
        return f"RavenRuntime(id={self.runtime_id!r}, state={self._state.value})"
