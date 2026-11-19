"""RAVEN V7 Event Bus.

Single in-process publish/subscribe bus (§109-113).
- Events are synchronous in Phase 1
- One broken subscriber must not crash the runtime (§112)
- Not a database — transient delivery only; persistence done by owning subsystems
- Events are serializable RuntimeEvent envelopes (§110)
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

_log = logging.getLogger(__name__)


# ── Event types (§109) ──────────────────────────────────────────────────────

class EventType:
    # Runtime
    RUNTIME_STARTED        = "runtime.started"
    RUNTIME_STOPPED        = "runtime.stopped"
    RUNTIME_DEGRADED       = "runtime.degraded"
    RUNTIME_STATE_CHANGED  = "runtime.state_changed"

    # Tasks
    TASK_CREATED           = "task.created"
    TASK_STARTED           = "task.started"
    TASK_PAUSED            = "task.paused"
    TASK_RESUMED           = "task.resumed"
    TASK_COMPLETED         = "task.completed"
    TASK_FAILED            = "task.failed"
    TASK_CANCELLED         = "task.cancelled"
    TASK_INTERRUPTED       = "task.interrupted"
    TASK_CHECKPOINT        = "task.checkpoint"
    TASK_PROGRESS          = "task.progress"

    # Tools
    TOOL_INVOKED           = "tool.invoked"
    TOOL_COMPLETED         = "tool.completed"
    TOOL_FAILED            = "tool.failed"
    TOOL_DENIED            = "tool.denied"

    # Model
    MODEL_REQUESTED        = "model.requested"
    MODEL_COMPLETED        = "model.completed"
    MODEL_FAILED           = "model.failed"

    # Capability
    CAPABILITY_DENIED      = "capability.denied"
    CAPABILITY_ALLOWED     = "capability.allowed"

    # Workspace
    WORKSPACE_LOADED       = "workspace.loaded"
    WORKSPACE_CHANGED      = "workspace.changed"

    # Knowledge
    KNOWLEDGE_ADDED        = "knowledge.added"
    KNOWLEDGE_INVALIDATED  = "knowledge.invalidated"

    # Observation
    OBSERVATION_CREATED    = "observation.created"

    # Findings
    CANDIDATE_CREATED      = "candidate.created"
    CANDIDATE_REJECTED     = "candidate.rejected"

    # Research
    RESEARCH_SOURCE_RETRIEVED = "research.source_retrieved"

    # Plugin
    PLUGIN_LOADED          = "plugin.loaded"
    PLUGIN_FAILED          = "plugin.failed"

    # Researcher
    RESEARCHER_TAKEOVER_STARTED = "researcher.takeover_started"
    RESEARCHER_TAKEOVER_ENDED   = "researcher.takeover_ended"

    # Emergency
    EMERGENCY_STOP         = "emergency.stop"
    EMERGENCY_CLEAR        = "emergency.clear"


@dataclass
class RuntimeEvent:
    """Typed event envelope (§110). Serializable."""
    event_type:    str
    payload:       Dict[str, Any]
    event_id:      str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp:     int = field(default_factory=lambda: int(time.time() * 1000))
    runtime_id:    Optional[str] = None
    workspace_id:  Optional[str] = None
    task_id:       Optional[str] = None
    source:        str = "runtime"
    correlation_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "event_id":      self.event_id,
            "event_type":    self.event_type,
            "timestamp":     self.timestamp,
            "runtime_id":    self.runtime_id,
            "workspace_id":  self.workspace_id,
            "task_id":       self.task_id,
            "source":        self.source,
            "correlation_id": self.correlation_id,
            "payload":       self.payload,
        }


# ── EventBus ────────────────────────────────────────────────────────────────

class EventBus:
    """Synchronous in-process pub/sub (§109).

    Subscriber failures are isolated — a crashed handler gets logged but does
    not propagate to other subscribers or the publisher (§112).
    Subscription IDs are returned so callers can unsubscribe.
    """

    def __init__(self, runtime_id: str = ""):
        self._runtime_id = runtime_id
        self._lock = threading.RLock()
        self._subscribers: Dict[str, Dict[str, Callable[[RuntimeEvent], None]]] = {}
        # wildcard subscribers receive ALL events
        self._wildcard: Dict[str, Callable[[RuntimeEvent], None]] = {}

    def publish(self, event_type: str, payload: dict, *,
                workspace_id: str = None, task_id: str = None,
                source: str = "runtime", correlation_id: str = None) -> RuntimeEvent:
        """Publish an event; deliver synchronously to all matching subscribers."""
        event = RuntimeEvent(
            event_type=event_type,
            payload=payload,
            runtime_id=self._runtime_id,
            workspace_id=workspace_id,
            task_id=task_id,
            source=source,
            correlation_id=correlation_id,
        )
        with self._lock:
            handlers = list(self._subscribers.get(event_type, {}).values())
            handlers += list(self._wildcard.values())

        for handler in handlers:
            try:
                handler(event)
            except Exception:  # noqa: BLE001 — isolate subscriber failures
                _log.exception("EventBus subscriber error on %s", event_type)

        return event

    def subscribe(self, event_type: str, handler: Callable[[RuntimeEvent], None]) -> str:
        """Subscribe to an event type. Returns subscription ID for later unsubscribe.
        Use event_type='*' to subscribe to all events.
        """
        sub_id = uuid.uuid4().hex[:12]
        with self._lock:
            if event_type == "*":
                self._wildcard[sub_id] = handler
            else:
                if event_type not in self._subscribers:
                    self._subscribers[event_type] = {}
                self._subscribers[event_type][sub_id] = handler
        return sub_id

    def unsubscribe(self, sub_id: str) -> bool:
        with self._lock:
            if sub_id in self._wildcard:
                del self._wildcard[sub_id]
                return True
            for handlers in self._subscribers.values():
                if sub_id in handlers:
                    del handlers[sub_id]
                    return True
        return False

    def subscriber_count(self, event_type: str = None) -> int:
        with self._lock:
            wild = len(self._wildcard)
            if event_type is None:
                return sum(len(v) for v in self._subscribers.values()) + wild
            return len(self._subscribers.get(event_type, {})) + wild

    def clear(self) -> None:
        """Remove all subscriptions (used in tests)."""
        with self._lock:
            self._subscribers.clear()
            self._wildcard.clear()
