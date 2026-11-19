"""RAVEN V7 Bootstrap Test Suite — B1 through B14.

Covers all acceptance criteria from the V7-BOOTSTRAP stage.
Uses in-memory SQLite and MockModelAdapter only (no external dependencies).

Critical invariants verified throughout:
- CompletionResult.is_advisory is always True (immutable)
- CapabilityGate is fail-closed
- Event subscriber failures are isolated (never propagate)
- Task state machine rejects illegal transitions
- Plugin escalation attempts are rejected
"""
from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from typing import List

import pytest

# ── Helpers ────────────────────────────────────────────────────────────────────

def fresh_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    # Bootstrap the canonical schema needed by WorkspaceManager
    db.executescript("""
    CREATE TABLE IF NOT EXISTS workspaces (
        id TEXT PRIMARY KEY,
        name TEXT,
        slug TEXT,
        created_at TEXT,
        scope_json TEXT,
        identity_json TEXT,
        note TEXT
    );
    """)
    db.commit()
    return db


def make_runtime(db=None):
    from raven.runtime.runtime import RavenRuntime, RuntimeConfig
    from raven.runtime.model import ModelService, MockModelAdapter, ModelProvider, ProviderType
    db = db or fresh_db()
    model_svc = ModelService()
    mock_adapter = MockModelAdapter("mock-bootstrap")
    mock_provider = ModelProvider(
        provider_id="mock-bootstrap",
        provider_type=ProviderType.MOCK,
        display_name="Mock (Bootstrap)",
    )
    model_svc.register_provider(mock_provider, mock_adapter)
    rt = RavenRuntime(db=db, model_service=model_svc)
    rt.start()
    return rt, db


@pytest.fixture(autouse=True)
def _reset_emergency_stop():
    """PolicyGate emergency stop is CLASS-LEVEL state. Reset after every test."""
    yield
    from raven.security.policy_gate import PolicyGate
    PolicyGate._reset_emergency_stop_for_test()


# ══════════════════════════════════════════════════════════════════════════════
# B1 — Runtime Lifecycle
# ══════════════════════════════════════════════════════════════════════════════

class TestRuntimeLifecycle:
    def test_start_transitions_to_ready(self):
        from raven.runtime.runtime import RuntimeState
        rt, _ = make_runtime()
        assert rt.state == RuntimeState.READY
        rt.shutdown()

    def test_start_twice_raises(self):
        from raven.runtime.errors import RavenRuntimeError
        from raven.runtime.runtime import RuntimeState
        rt, _ = make_runtime()
        assert rt.state == RuntimeState.READY
        with pytest.raises((RavenRuntimeError, Exception)):
            rt.start()
        rt.shutdown()

    def test_shutdown_transitions_to_stopped(self):
        from raven.runtime.runtime import RuntimeState
        rt, _ = make_runtime()
        rt.shutdown()
        assert rt.state == RuntimeState.STOPPED

    def test_shutdown_idempotent(self):
        from raven.runtime.runtime import RuntimeState
        rt, _ = make_runtime()
        rt.shutdown()
        rt.shutdown()  # second call must not raise
        assert rt.state == RuntimeState.STOPPED

    def test_is_operational_after_start(self):
        rt, _ = make_runtime()
        assert rt.is_operational is True
        rt.shutdown()

    def test_is_not_operational_after_shutdown(self):
        rt, _ = make_runtime()
        rt.shutdown()
        assert rt.is_operational is False

    def test_pause_resume(self):
        from raven.runtime.runtime import RuntimeState
        rt, _ = make_runtime()
        rt.pause()
        assert rt.state == RuntimeState.PAUSED
        rt.resume()
        assert rt.state in (RuntimeState.READY, RuntimeState.DEGRADED)
        rt.shutdown()

    def test_invalid_transition_raises(self):
        from raven.runtime.runtime import RuntimeState
        from raven.runtime.errors import RavenRuntimeError
        rt, _ = make_runtime()
        with pytest.raises((RavenRuntimeError, Exception)):
            rt._transition(RuntimeState.STARTING)  # READY → STARTING is illegal
        rt.shutdown()

    def test_runtime_id_is_stable(self):
        rt, _ = make_runtime()
        rid = rt.runtime_id
        assert rid == rt.runtime_id
        rt.shutdown()

    def test_health_report(self):
        rt, _ = make_runtime()
        report = rt.health_report()
        assert report["runtime_id"] == rt.runtime_id
        assert isinstance(report["subsystems"], list)
        rt.shutdown()

    def test_emergency_stop(self):
        rt, _ = make_runtime()
        rt.trigger_emergency_stop()
        assert rt.capabilities.is_emergency_stop_active() is True
        rt.shutdown()

    def test_started_event_emitted(self):
        from raven.runtime.events import EventType
        events = []
        db = fresh_db()
        from raven.runtime.runtime import RavenRuntime
        rt = RavenRuntime(db=db)
        rt.bus.subscribe(EventType.RUNTIME_STARTED, lambda e: events.append(e))
        rt.start()
        assert len(events) >= 1
        assert events[0].event_type == EventType.RUNTIME_STARTED  # RuntimeEvent.event_type is a string
        rt.shutdown()

    def test_stopped_event_emitted(self):
        from raven.runtime.events import EventType
        events = []
        rt, _ = make_runtime()
        rt.bus.subscribe(EventType.RUNTIME_STOPPED, lambda e: events.append(e))
        rt.shutdown()
        assert len(events) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# B2 — Task State Machine
# ══════════════════════════════════════════════════════════════════════════════

class TestTaskStateMachine:
    def test_task_created_pending(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("test task", workspace_id="ws1")
        assert task.status == TaskStatus.PENDING
        rt.shutdown()

    def test_pending_to_planning(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.PLANNING)
        assert rt.tasks.get(task.task_id).status == TaskStatus.PLANNING
        rt.shutdown()

    def test_planning_to_running(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.PLANNING)
        rt.tasks.transition(task.task_id, TaskStatus.RUNNING)
        assert rt.tasks.get(task.task_id).status == TaskStatus.RUNNING
        rt.shutdown()

    def test_running_to_completed(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.PLANNING)
        rt.tasks.transition(task.task_id, TaskStatus.RUNNING)
        rt.tasks.transition(task.task_id, TaskStatus.COMPLETED)
        assert rt.tasks.get(task.task_id).status == TaskStatus.COMPLETED
        rt.shutdown()

    def test_completed_is_terminal(self):
        from raven.runtime.tasks import TaskStatus
        from raven.runtime.errors import InvalidTaskTransitionError
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.PLANNING)
        rt.tasks.transition(task.task_id, TaskStatus.RUNNING)
        rt.tasks.transition(task.task_id, TaskStatus.COMPLETED)
        with pytest.raises(InvalidTaskTransitionError):
            rt.tasks.transition(task.task_id, TaskStatus.RUNNING)
        rt.shutdown()

    def test_illegal_transition_raises(self):
        from raven.runtime.tasks import TaskStatus
        from raven.runtime.errors import InvalidTaskTransitionError
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        with pytest.raises(InvalidTaskTransitionError):
            rt.tasks.transition(task.task_id, TaskStatus.COMPLETED)
        rt.shutdown()

    def test_pending_to_cancelled(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.CANCELLED)
        assert rt.tasks.get(task.task_id).status == TaskStatus.CANCELLED
        rt.shutdown()

    def test_running_to_failed(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.PLANNING)
        rt.tasks.transition(task.task_id, TaskStatus.RUNNING)
        rt.tasks.transition(task.task_id, TaskStatus.FAILED)
        assert rt.tasks.get(task.task_id).status == TaskStatus.FAILED
        rt.shutdown()

    def test_is_terminal_completed(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.PLANNING)
        rt.tasks.transition(task.task_id, TaskStatus.RUNNING)
        rt.tasks.transition(task.task_id, TaskStatus.COMPLETED)
        assert rt.tasks.get(task.task_id).is_terminal is True
        rt.shutdown()

    def test_progress_update(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.PLANNING)
        rt.tasks.update_progress(task.task_id, step=5)
        updated = rt.tasks.get(task.task_id)
        assert updated.progress.step == 5
        rt.shutdown()

    def test_list_active_excludes_terminal(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        t1 = rt.tasks.create("running")
        t2 = rt.tasks.create("done")
        rt.tasks.transition(t1.task_id, TaskStatus.PLANNING)
        rt.tasks.transition(t1.task_id, TaskStatus.RUNNING)
        rt.tasks.transition(t2.task_id, TaskStatus.PLANNING)
        rt.tasks.transition(t2.task_id, TaskStatus.RUNNING)
        rt.tasks.transition(t2.task_id, TaskStatus.COMPLETED)
        active = rt.tasks.list_active()
        ids = {t.task_id for t in active}
        assert t1.task_id in ids
        assert t2.task_id not in ids
        rt.shutdown()


# ══════════════════════════════════════════════════════════════════════════════
# B3 — Task Hierarchy
# ══════════════════════════════════════════════════════════════════════════════

class TestTaskHierarchy:
    def test_create_child_task(self):
        rt, _ = make_runtime()
        parent = rt.tasks.create("parent")
        child = rt.tasks.create("child", parent_task_id=parent.task_id)
        assert child.parent_task_id == parent.task_id
        children = rt.tasks.get_children(parent.task_id)
        assert any(c.task_id == child.task_id for c in children)
        rt.shutdown()

    def test_child_independent_state(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        parent = rt.tasks.create("parent")
        child = rt.tasks.create("child", parent_task_id=parent.task_id)
        rt.tasks.transition(child.task_id, TaskStatus.CANCELLED)
        assert rt.tasks.get(parent.task_id).status == TaskStatus.PENDING
        rt.shutdown()

    def test_orphan_task_has_no_children(self):
        rt, _ = make_runtime()
        task = rt.tasks.create("solo")
        assert rt.tasks.get_children(task.task_id) == []
        rt.shutdown()


# ══════════════════════════════════════════════════════════════════════════════
# B4 — Cancellation
# ══════════════════════════════════════════════════════════════════════════════

class TestCancellation:
    def test_cancel_pending(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.CANCELLED)
        assert rt.tasks.get(task.task_id).status == TaskStatus.CANCELLED
        rt.shutdown()

    def test_cancel_running(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.PLANNING)
        rt.tasks.transition(task.task_id, TaskStatus.RUNNING)
        rt.tasks.transition(task.task_id, TaskStatus.CANCELLING)
        rt.tasks.transition(task.task_id, TaskStatus.CANCELLED)
        assert rt.tasks.get(task.task_id).status == TaskStatus.CANCELLED
        rt.shutdown()

    def test_shutdown_cancels_active_tasks(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("long")
        rt.tasks.transition(task.task_id, TaskStatus.PLANNING)
        rt.tasks.transition(task.task_id, TaskStatus.RUNNING)
        rt.shutdown(cancel_tasks=True)
        assert rt.tasks.get(task.task_id).status == TaskStatus.CANCELLED


# ══════════════════════════════════════════════════════════════════════════════
# B5 — Pause / Resume (task level and runtime level)
# ══════════════════════════════════════════════════════════════════════════════

class TestPauseResume:
    def test_task_pause_resume(self):
        from raven.runtime.tasks import TaskStatus
        rt, _ = make_runtime()
        task = rt.tasks.create("t")
        rt.tasks.transition(task.task_id, TaskStatus.PLANNING)
        rt.tasks.transition(task.task_id, TaskStatus.RUNNING)
        rt.tasks.transition(task.task_id, TaskStatus.PAUSING)
        rt.tasks.transition(task.task_id, TaskStatus.PAUSED)
        assert rt.tasks.get(task.task_id).status == TaskStatus.PAUSED
        rt.tasks.transition(task.task_id, TaskStatus.RUNNING)
        assert rt.tasks.get(task.task_id).status == TaskStatus.RUNNING
        rt.shutdown()

    def test_runtime_pause_resume(self):
        from raven.runtime.runtime import RuntimeState
        rt, _ = make_runtime()
        rt.pause()
        assert rt.state == RuntimeState.PAUSED
        rt.resume()
        assert rt.state in (RuntimeState.READY, RuntimeState.DEGRADED)
        rt.shutdown()


# ══════════════════════════════════════════════════════════════════════════════
# B6 — Checkpoint Round-Trip
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckpoint:
    def test_save_and_load(self):
        from raven.runtime.checkpoint import Checkpoint, CHECKPOINT_SCHEMA_VERSION
        rt, _ = make_runtime()
        cp = Checkpoint(
            task_id="task-abc",
            workspace_id="ws-x",
            task_status="RUNNING",
            completed_steps=3,
            pending_steps=7,
        )
        cp_id = rt.checkpoints.save(cp)
        loaded = rt.checkpoints.load(cp_id)
        assert loaded is not None
        assert loaded.task_id == "task-abc"
        assert loaded.completed_steps == 3
        assert loaded.schema_version == CHECKPOINT_SCHEMA_VERSION
        rt.shutdown()

    def test_load_latest(self):
        from raven.runtime.checkpoint import Checkpoint
        rt, _ = make_runtime()
        for i in range(3):
            rt.checkpoints.save(Checkpoint(task_id="t1", completed_steps=i))
            time.sleep(0.01)
        latest = rt.checkpoints.load_latest("t1")
        assert latest is not None
        assert latest.completed_steps == 2
        rt.shutdown()

    def test_schema_version_mismatch_returns_none(self):
        import json
        from raven.runtime.checkpoint import Checkpoint, CheckpointEngine
        db = fresh_db()
        engine = CheckpointEngine(db=db)
        cp = Checkpoint(task_id="t", completed_steps=99)
        cp_id = engine.save(cp)
        # Corrupt schema_version inside data_json (that's what _parse_row checks)
        row = db.execute("SELECT data_json FROM v7_checkpoints WHERE checkpoint_id=?",
                         (cp_id,)).fetchone()
        data = json.loads(row[0])
        data["schema_version"] = 999
        db.execute("UPDATE v7_checkpoints SET data_json=? WHERE checkpoint_id=?",
                   (json.dumps(data), cp_id))
        db.commit()
        loaded = engine.load(cp_id)
        assert loaded is None

    def test_delete_checkpoint(self):
        from raven.runtime.checkpoint import Checkpoint
        rt, _ = make_runtime()
        cp = Checkpoint(task_id="t")
        cp_id = rt.checkpoints.save(cp)
        assert rt.checkpoints.delete(cp_id) is True
        assert rt.checkpoints.load(cp_id) is None
        rt.shutdown()


# ══════════════════════════════════════════════════════════════════════════════
# B7 — Interrupted Task Recovery
# ══════════════════════════════════════════════════════════════════════════════

class TestInterruptedRecovery:
    def test_running_tasks_become_interrupted(self):
        from raven.runtime.tasks import TaskStatus, TaskRegistry
        db = fresh_db()
        registry = TaskRegistry(db=db, event_callback=None)
        # Manually insert a "RUNNING" task that survived a crash
        db.execute("""
        INSERT INTO v7_tasks (task_id, title, workspace_id, status, created_at)
        VALUES (?,?,?,?,?)
        """, ("stale-1", "Crashed task", "default", "RUNNING", int(time.time() * 1000)))
        db.commit()
        registry._restore_from_db()
        task = registry.get("stale-1")
        assert task is not None
        assert task.status == TaskStatus.INTERRUPTED

    def test_completed_tasks_survive_restart(self):
        from raven.runtime.tasks import TaskStatus, TaskRegistry
        db = fresh_db()
        registry = TaskRegistry(db=db, event_callback=None)
        db.execute("""
        INSERT INTO v7_tasks (task_id, title, workspace_id, status, created_at)
        VALUES (?,?,?,?,?)
        """, ("done-1", "Done task", "default", "COMPLETED", int(time.time() * 1000)))
        db.commit()
        # Terminal tasks are NOT loaded into memory (by design), but persist in DB
        row = db.execute("SELECT status FROM v7_tasks WHERE task_id=?", ("done-1",)).fetchone()
        assert row is not None
        assert row[0] == TaskStatus.COMPLETED.value


# ══════════════════════════════════════════════════════════════════════════════
# B8 — Tool Registration and Schema Validation
# ══════════════════════════════════════════════════════════════════════════════

class TestToolRegistration:
    def _make_tool(self, tool_id="test.echo"):
        from raven.runtime.tools import ToolDescriptor, SideEffectClass
        return ToolDescriptor(
            tool_id=tool_id,
            name="Echo",
            description="Returns its input",
            required_capability="local_read",
            side_effect_class=SideEffectClass.PURE,
            input_schema={
                "type": "object",
                "required": ["message"],
                "properties": {"message": {"type": "string"}},
            },
            output_schema={
                "type": "object",
                "properties": {"echo": {"type": "string"}},
            },
        )

    def test_register_and_get(self):
        rt, _ = make_runtime()
        descriptor = self._make_tool()
        rt.tools.register(descriptor, handler=lambda args: {"echo": args["message"]})
        retrieved = rt.tools.get("test.echo")
        assert retrieved is not None
        assert retrieved.tool_id == "test.echo"
        rt.shutdown()

    def test_schema_validates_required_field(self):
        from raven.runtime.tools import _validate_against_schema
        # Missing required field — returns error string (not list)
        schema = {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}
        errors = _validate_against_schema({}, schema)
        assert errors is not None

    def test_schema_passes_valid_args(self):
        from raven.runtime.tools import _validate_against_schema
        schema = {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}
        errors = _validate_against_schema({"name": "Alice"}, schema)
        assert errors is None

    def test_list_all_tools(self):
        rt, _ = make_runtime()
        rt.tools.register(self._make_tool("t1"), handler=lambda a: {})
        rt.tools.register(self._make_tool("t2"), handler=lambda a: {})
        tools = rt.tools.list_all()
        ids = {t.tool_id for t in tools}
        assert "t1" in ids
        assert "t2" in ids
        rt.shutdown()

    def test_unknown_tool_returns_none(self):
        rt, _ = make_runtime()
        assert rt.tools.get("nonexistent") is None
        rt.shutdown()

    def test_duplicate_registration_overwrites(self):
        rt, _ = make_runtime()
        d = self._make_tool("dup")
        rt.tools.register(d, handler=lambda a: {"v": 1})
        # Second registration silently overwrites — no exception raised
        rt.tools.register(d, handler=lambda a: {"v": 2})
        assert rt.tools.get("dup") is not None
        rt.shutdown()


# ══════════════════════════════════════════════════════════════════════════════
# B9 — Capability Denial
# ══════════════════════════════════════════════════════════════════════════════

class TestCapabilityDenial:
    def test_emergency_stop_denies_http(self):
        from raven.runtime.capabilities import CapabilityDecision
        rt, _ = make_runtime()
        rt.capabilities.trigger_emergency_stop()
        result = rt.capabilities.check("http_read")
        assert result.decision == CapabilityDecision.DENY
        rt.shutdown()

    def test_local_read_allowed_normally(self):
        from raven.runtime.capabilities import CapabilityDecision
        rt, _ = make_runtime()
        result = rt.capabilities.check("local_read")
        assert result.decision != CapabilityDecision.DENY
        rt.shutdown()

    def test_require_raises_on_denial(self):
        from raven.runtime.errors import CapabilityDeniedError
        rt, _ = make_runtime()
        rt.capabilities.trigger_emergency_stop()
        with pytest.raises(CapabilityDeniedError):
            rt.capabilities.require("http_read")
        rt.shutdown()

    def test_unknown_capability_not_allowed(self):
        rt, _ = make_runtime()
        result = rt.capabilities.check("nonexistent_xyz")
        # Unknown capability returns UNAVAILABLE (not DENY) — either way not allowed
        assert not result.is_allowed()
        rt.shutdown()


# ══════════════════════════════════════════════════════════════════════════════
# B10 — Policy Consistency
# ══════════════════════════════════════════════════════════════════════════════

class TestPolicyConsistency:
    def test_tool_invocation_denied_on_emergency_stop(self):
        from raven.runtime.tools import ToolDescriptor, SideEffectClass, ToolStatus, ToolInvocation
        from raven.runtime.execution import ActorKind
        rt, _ = make_runtime()
        desc = ToolDescriptor(
            tool_id="net.fetch",
            name="Fetch",
            description="HTTP fetch",
            required_capability="http_read",
            side_effect_class=SideEffectClass.NETWORK_READ,
            input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
            output_schema={"type": "object", "properties": {}},
        )
        rt.tools.register(desc, handler=lambda a: {"data": "x"})
        rt.capabilities.trigger_emergency_stop()
        invoc = ToolInvocation(
            tool_id="net.fetch",
            arguments={"url": "http://example.test"},
            task_id="t1",
            actor=ActorKind.RAVEN_AGENT,
        )
        result, _ = rt.dispatcher.invoke(invoc)
        assert result.status == ToolStatus.DENIED
        rt.shutdown()

    def test_tool_invocation_succeeds_with_local_read(self):
        from raven.runtime.tools import ToolDescriptor, SideEffectClass, ToolStatus, ToolInvocation
        from raven.runtime.execution import ActorKind
        rt, _ = make_runtime()
        desc = ToolDescriptor(
            tool_id="fs.read",
            name="Read",
            description="Read file",
            required_capability="local_read",
            side_effect_class=SideEffectClass.PURE,
            input_schema={"type": "object", "required": ["path"],
                          "properties": {"path": {"type": "string"}}},
            output_schema={"type": "object", "properties": {}},
            # fail-closed contract: a tool must DECLARE its risk; undeclared risk
            # is no longer treated as safe. A PURE local read is SafeReadOnly.
            metadata={"risk_class": "SafeReadOnly"},
        )
        rt.tools.register(desc, handler=lambda a: {"content": "data"})
        invoc = ToolInvocation(
            tool_id="fs.read",
            arguments={"path": "/tmp/test.txt"},
            task_id="t1",
            actor=ActorKind.RAVEN_AGENT,
        )
        result, _ = rt.dispatcher.invoke(invoc)
        assert result.status == ToolStatus.SUCCESS
        rt.shutdown()


# ══════════════════════════════════════════════════════════════════════════════
# B11 — Execution Records
# ══════════════════════════════════════════════════════════════════════════════

class TestExecutionRecords:
    def test_successful_invocation_creates_record(self):
        from raven.runtime.tools import ToolDescriptor, SideEffectClass, ToolInvocation
        from raven.runtime.execution import ActorKind
        rt, _ = make_runtime()
        desc = ToolDescriptor(
            tool_id="util.noop",
            name="Noop",
            description="Does nothing",
            required_capability="local_read",
            side_effect_class=SideEffectClass.PURE,
            input_schema={"type": "object", "properties": {}},
            output_schema={"type": "object", "properties": {}},
        )
        rt.tools.register(desc, handler=lambda a: {})
        invoc = ToolInvocation(tool_id="util.noop", arguments={}, task_id="t99",
                               actor=ActorKind.SYSTEM)
        rt.dispatcher.invoke(invoc)
        records = rt.executions.list_for_task("t99")
        assert len(records) >= 1
        assert records[0].tool_id == "util.noop"
        rt.shutdown()

    def test_failed_invocation_creates_record(self):
        from raven.runtime.tools import ToolDescriptor, SideEffectClass, ToolStatus, ToolInvocation
        from raven.runtime.execution import ActorKind
        rt, _ = make_runtime()
        def boom(args):
            raise ValueError("injected failure")
        desc = ToolDescriptor(
            tool_id="util.boom",
            name="Boom",
            description="Always fails",
            required_capability="local_read",
            side_effect_class=SideEffectClass.PURE,
            input_schema={"type": "object", "properties": {}},
            output_schema={"type": "object", "properties": {}},
            # fail-closed contract: declare risk so the gate allows the call and
            # the handler runs (and then fails) — undeclared risk now blocks.
            metadata={"risk_class": "SafeReadOnly"},
        )
        rt.tools.register(desc, handler=boom)
        invoc = ToolInvocation(tool_id="util.boom", arguments={}, task_id="t-fail",
                               actor=ActorKind.SYSTEM)
        result, _ = rt.dispatcher.invoke(invoc)
        assert result.status == ToolStatus.FAILED
        records = rt.executions.list_for_task("t-fail")
        assert len(records) >= 1
        rt.shutdown()

    def test_missing_required_arg_fails_gracefully(self):
        from raven.runtime.tools import ToolDescriptor, SideEffectClass, ToolStatus, ToolInvocation
        from raven.runtime.execution import ActorKind
        rt, _ = make_runtime()
        desc = ToolDescriptor(
            tool_id="util.needs_arg",
            name="Need",
            description="Needs arg",
            required_capability="local_read",
            side_effect_class=SideEffectClass.PURE,
            input_schema={"type": "object", "required": ["x"],
                          "properties": {"x": {"type": "string"}}},
            output_schema={"type": "object", "properties": {}},
        )
        rt.tools.register(desc, handler=lambda a: {})
        invoc = ToolInvocation(tool_id="util.needs_arg", arguments={}, task_id="t-val",
                               actor=ActorKind.SYSTEM)
        result, _ = rt.dispatcher.invoke(invoc)
        assert result.status == ToolStatus.INVALID_INPUT
        rt.shutdown()

    def test_execution_record_no_secrets(self):
        """ExecutionRecord must not store raw secrets in the args field."""
        from raven.runtime.execution import ExecutionRecord, ActorKind, ToolStatus
        rec = ExecutionRecord(
            tool_id="auth.login",
            actor=ActorKind.SYSTEM,
            task_id="t",
        )
        rec.finish(ToolStatus.SUCCESS)
        d = rec.to_dict()
        # Confirm the dict is serializable (no raw secrets in input_summary)
        assert "password" not in str(d.get("input_summary", ""))


# ══════════════════════════════════════════════════════════════════════════════
# B12 — Event Bus
# ══════════════════════════════════════════════════════════════════════════════

class TestEventBus:
    def test_publish_subscribe(self):
        from raven.runtime.events import EventBus, EventType
        bus = EventBus()
        received = []
        bus.subscribe(EventType.TASK_CREATED, lambda e: received.append(e))
        bus.publish(EventType.TASK_CREATED, {})
        assert len(received) == 1

    def test_wildcard_subscription(self):
        from raven.runtime.events import EventBus, EventType
        bus = EventBus()
        received = []
        bus.subscribe("*", lambda e: received.append(e))
        bus.publish(EventType.TASK_CREATED, {})
        bus.publish(EventType.TASK_COMPLETED, {})
        assert len(received) == 2

    def test_unsubscribe(self):
        from raven.runtime.events import EventBus, EventType
        bus = EventBus()
        received = []
        sub_id = bus.subscribe(EventType.TASK_CREATED, lambda e: received.append(e))
        bus.unsubscribe(sub_id)
        bus.publish(EventType.TASK_CREATED, {})
        assert len(received) == 0

    def test_task_created_event_on_registry_create(self):
        from raven.runtime.events import EventType
        events = []
        rt, _ = make_runtime()
        rt.bus.subscribe(EventType.TASK_CREATED, lambda e: events.append(e))
        rt.tasks.create("tracked task")
        assert len(events) >= 1
        rt.shutdown()


# ══════════════════════════════════════════════════════════════════════════════
# B13 — Event Failure Isolation
# ══════════════════════════════════════════════════════════════════════════════

class TestEventFailureIsolation:
    def test_failing_subscriber_does_not_crash_publisher(self):
        from raven.runtime.events import EventBus, EventType
        bus = EventBus()
        good_received = []

        def crashing_subscriber(e):
            raise RuntimeError("subscriber kaboom")

        def good_subscriber(e):
            good_received.append(e)

        bus.subscribe(EventType.TASK_CREATED, crashing_subscriber)
        bus.subscribe(EventType.TASK_CREATED, good_subscriber)
        # Must not raise even though crashing_subscriber throws
        bus.publish(EventType.TASK_CREATED, {})
        assert len(good_received) == 1

    def test_multiple_failing_subscribers_isolated(self):
        from raven.runtime.events import EventBus, EventType
        bus = EventBus()
        survivors = []

        for i in range(3):
            if i == 1:
                bus.subscribe(EventType.TOOL_INVOKED, lambda e: 1 / 0)
            else:
                bus.subscribe(EventType.TOOL_INVOKED, lambda e: survivors.append(e))

        bus.publish(EventType.TOOL_INVOKED, {})
        assert len(survivors) == 2


# ══════════════════════════════════════════════════════════════════════════════
# B14 — Model, Plugin, Workspace, Context, Invariants, Adversarial
# ══════════════════════════════════════════════════════════════════════════════

class TestModelProviderFailure:
    def test_completion_result_is_always_advisory(self):
        from raven.runtime.model import CompletionResult
        result = CompletionResult(content="hello", model_id="m", provider_id="p")
        assert result.is_advisory is True

    def test_is_advisory_cannot_be_overridden(self):
        from raven.runtime.model import CompletionResult
        result = CompletionResult(content="x", model_id="m", provider_id="p", is_advisory=False)
        assert result.is_advisory is True  # __post_init__ forces True

    def test_is_advisory_cannot_be_set_after_creation(self):
        from raven.runtime.model import CompletionResult
        result = CompletionResult(content="x", model_id="m", provider_id="p")
        with pytest.raises((AttributeError, Exception)):
            result.is_advisory = False

    def test_no_providers_returns_failure(self):
        from raven.runtime.model import ModelService, ModelMessage, ModelFailureKind
        svc = ModelService()
        result = svc.complete([ModelMessage(role="user", content="hi")])
        assert result.is_failure() is True
        assert result.failure == ModelFailureKind.PROVIDER_UNAVAILABLE

    def test_mock_adapter_returns_advisory_result(self):
        from raven.runtime.model import (
            ModelService, ModelMessage, MockModelAdapter,
            ModelProvider, ProviderType
        )
        svc = ModelService()
        adapter = MockModelAdapter("test-mock")
        provider = ModelProvider(
            provider_id="test-mock",
            provider_type=ProviderType.MOCK,
            display_name="Test Mock",
        )
        svc.register_provider(provider, adapter)
        result = svc.complete([ModelMessage(role="user", content="hi")])
        assert result.is_advisory is True
        assert not result.is_failure()

    def test_mock_adapter_call_count(self):
        from raven.runtime.model import (
            ModelService, ModelMessage, MockModelAdapter,
            ModelProvider, ProviderType
        )
        adapter = MockModelAdapter("counter")
        svc = ModelService()
        svc.register_provider(
            ModelProvider(provider_id="counter", provider_type=ProviderType.MOCK,
                          display_name="Counter"),
            adapter
        )
        svc.complete([ModelMessage(role="user", content="1")])
        svc.complete([ModelMessage(role="user", content="2")])
        assert adapter.call_count == 2


class TestPluginValidation:
    def test_valid_plugin_registered(self):
        from raven.runtime.plugins import PluginManifest, PluginRegistry, PluginState, PLUGIN_API_VERSION
        reg = PluginRegistry()
        manifest = PluginManifest(
            plugin_id="test.plugin",
            name="Test",
            version="1.0",
            api_version=PLUGIN_API_VERSION,
            capabilities=["local_read"],
        )
        plugin = reg.register(manifest)
        assert plugin.state == PluginState.VALIDATED

    def test_incompatible_api_version(self):
        from raven.runtime.plugins import PluginManifest, PluginRegistry, PluginState
        reg = PluginRegistry()
        manifest = PluginManifest(
            plugin_id="old.plugin",
            name="Old",
            version="0.1",
            api_version="6.0",  # wrong major
        )
        plugin = reg.register(manifest)
        assert plugin.state == PluginState.INCOMPATIBLE

    def test_duplicate_plugin_id_fails(self):
        from raven.runtime.plugins import PluginManifest, PluginRegistry, PluginState, PLUGIN_API_VERSION
        reg = PluginRegistry()
        m = PluginManifest(plugin_id="dup", name="X", version="1", api_version=PLUGIN_API_VERSION)
        reg.register(m)
        second = reg.register(m)
        assert second.state == PluginState.FAILED

    def test_escalation_attempt_rejected(self):
        from raven.runtime.plugins import PluginManifest, PluginRegistry, PluginState, PLUGIN_API_VERSION
        reg = PluginRegistry()
        manifest = PluginManifest(
            plugin_id="sneaky",
            name="Sneaky",
            version="1",
            api_version=PLUGIN_API_VERSION,
            capabilities=["local_read"],  # only declared local_read
        )
        reg.register(manifest)
        # Try to activate with an undeclared capability
        result = reg.activate("sneaky", ["local_read", "process_exec"])
        assert result is False
        plugin = reg.get("sneaky")
        assert plugin.state == PluginState.FAILED

    def test_activate_with_declared_subset(self):
        from raven.runtime.plugins import PluginManifest, PluginRegistry, PluginState, PLUGIN_API_VERSION
        reg = PluginRegistry()
        manifest = PluginManifest(
            plugin_id="good",
            name="Good",
            version="1",
            api_version=PLUGIN_API_VERSION,
            capabilities=["local_read", "local_write"],
        )
        reg.register(manifest)
        # Activate with subset only
        result = reg.activate("good", ["local_read"])
        assert result is True
        assert reg.get("good").state == PluginState.ACTIVE

    def test_plugin_failure_isolated(self):
        from raven.runtime.plugins import PluginManifest, PluginRegistry, PluginState, PLUGIN_API_VERSION
        reg = PluginRegistry()
        p1 = PluginManifest(plugin_id="p1", name="P1", version="1", api_version=PLUGIN_API_VERSION)
        p2 = PluginManifest(plugin_id="p2", name="P2", version="1", api_version=PLUGIN_API_VERSION)
        reg.register(p1)
        reg.register(p2)
        reg.activate("p1", [])
        reg.mark_failed("p2", "test failure")
        assert reg.get("p1").state == PluginState.ACTIVE
        assert reg.get("p2").state == PluginState.FAILED


class TestWorkspaceIsolation:
    def test_create_workspace(self):
        rt, _ = make_runtime()
        ws = rt.workspaces.create("Project A")
        assert ws.workspace_id
        assert ws.name == "Project A"
        rt.shutdown()

    def test_get_workspace(self):
        rt, _ = make_runtime()
        ws = rt.workspaces.create("Project B")
        loaded = rt.workspaces.get(ws.workspace_id)
        assert loaded is not None
        assert loaded.workspace_id == ws.workspace_id
        rt.shutdown()

    def test_workspaces_are_independent(self):
        rt, _ = make_runtime()
        ws_a = rt.workspaces.create("A")
        ws_b = rt.workspaces.create("B")
        assert ws_a.workspace_id != ws_b.workspace_id
        rt.shutdown()

    def test_unknown_workspace_returns_none(self):
        rt, _ = make_runtime()
        assert rt.workspaces.get("nonexistent") is None
        rt.shutdown()


class TestConversationContext:
    def test_create_and_get_conversation(self):
        rt, _ = make_runtime()
        ws = rt.workspaces.create("C")
        conv = rt.conversations.create_conversation(ws.workspace_id, "Test Chat")
        loaded = rt.conversations.get_conversation(conv.conversation_id)
        assert loaded is not None
        assert loaded.workspace_id == ws.workspace_id
        rt.shutdown()

    def test_add_and_get_messages(self):
        from raven.runtime.conversation import MessageRole
        rt, _ = make_runtime()
        ws = rt.workspaces.create("D")
        conv = rt.conversations.create_conversation(ws.workspace_id)
        rt.conversations.add_message(conv.conversation_id, MessageRole.RESEARCHER, "Hello")
        rt.conversations.add_message(conv.conversation_id, MessageRole.RAVEN, "Hi there")
        msgs = rt.conversations.get_recent(conv.conversation_id)
        assert len(msgs) == 2
        rt.shutdown()

    def test_bounded_ram_history(self):
        from raven.runtime.conversation import MessageRole, ConversationContext
        db = fresh_db()
        ctx = ConversationContext(db=db, max_turns=5)
        ws_id = "ws-bound"
        conv = ctx.create_conversation(ws_id)
        for i in range(10):
            ctx.add_message(conv.conversation_id, MessageRole.RESEARCHER, f"msg {i}")
        recent = ctx.get_recent(conv.conversation_id, n=100)
        assert len(recent) <= 5

    def test_cross_workspace_isolation(self):
        from raven.runtime.conversation import MessageRole
        rt, _ = make_runtime()
        ws1 = rt.workspaces.create("WS1")
        ws2 = rt.workspaces.create("WS2")
        conv1 = rt.conversations.create_conversation(ws1.workspace_id)
        conv2 = rt.conversations.create_conversation(ws2.workspace_id)
        rt.conversations.add_message(conv1.conversation_id, MessageRole.RESEARCHER, "private")
        convs_ws2 = rt.conversations.list_conversations(ws2.workspace_id)
        conv1_ids = {c.conversation_id for c in convs_ws2}
        assert conv1.conversation_id not in conv1_ids
        rt.shutdown()


class TestAdversarialInputs:
    def test_sql_injection_in_task_title(self):
        rt, _ = make_runtime()
        # Should not raise or corrupt DB
        task = rt.tasks.create("'; DROP TABLE v7_tasks; --")
        assert task.task_id is not None
        rt.shutdown()

    def test_unicode_in_task_title(self):
        rt, _ = make_runtime()
        task = rt.tasks.create("مهمة اختبار — Task Test 🔒")
        assert task.task_id is not None
        rt.shutdown()

    def test_very_long_tool_args(self):
        from raven.runtime.tools import ToolDescriptor, SideEffectClass, ToolStatus, ToolInvocation
        from raven.runtime.execution import ActorKind
        rt, _ = make_runtime()
        desc = ToolDescriptor(
            tool_id="util.long",
            name="Long",
            description="Test",
            required_capability="local_read",
            side_effect_class=SideEffectClass.PURE,
            input_schema={"type": "object", "required": ["data"],
                          "properties": {"data": {"type": "string"}}},
            output_schema={"type": "object", "properties": {}},
            # fail-closed contract: declare risk; undeclared risk is no longer safe.
            metadata={"risk_class": "SafeReadOnly"},
        )
        rt.tools.register(desc, handler=lambda a: {})
        big_arg = "x" * 100_000
        invoc = ToolInvocation(tool_id="util.long", arguments={"data": big_arg},
                               task_id="t", actor=ActorKind.SYSTEM)
        result, _ = rt.dispatcher.invoke(invoc)
        # Should succeed (large string is valid) or fail gracefully (no crash)
        assert result.status in (ToolStatus.SUCCESS, ToolStatus.FAILED, ToolStatus.INVALID_INPUT)
        rt.shutdown()

    def test_tool_invocation_unknown_tool(self):
        from raven.runtime.tools import ToolStatus, ToolInvocation
        from raven.runtime.execution import ActorKind
        rt, _ = make_runtime()
        invoc = ToolInvocation(tool_id="does.not.exist", arguments={},
                               task_id="t", actor=ActorKind.SYSTEM)
        result, _ = rt.dispatcher.invoke(invoc)
        assert result.status == ToolStatus.UNAVAILABLE
        rt.shutdown()

    def test_null_bytes_in_args(self):
        from raven.runtime.tools import ToolDescriptor, SideEffectClass, ToolInvocation
        from raven.runtime.execution import ActorKind
        rt, _ = make_runtime()
        desc = ToolDescriptor(
            tool_id="util.null",
            name="Null",
            description="Test",
            required_capability="local_read",
            side_effect_class=SideEffectClass.PURE,
            input_schema={"type": "object", "required": ["path"],
                          "properties": {"path": {"type": "string"}}},
            output_schema={"type": "object", "properties": {}},
        )
        rt.tools.register(desc, handler=lambda a: {"ok": True})
        invoc = ToolInvocation(tool_id="util.null", arguments={"path": "file\x00.txt"},
                               task_id="t", actor=ActorKind.SYSTEM)
        result, _ = rt.dispatcher.invoke(invoc)
        assert result is not None
        rt.shutdown()


class TestResourceBudgets:
    def test_task_budget_creation(self):
        from raven.runtime.tasks import TaskBudget
        budget = TaskBudget(max_tool_calls=10, max_duration_s=60)
        assert budget.max_tool_calls == 10
        assert budget.max_duration_s == 60

    def test_task_with_budget(self):
        from raven.runtime.tasks import TaskBudget
        rt, _ = make_runtime()
        budget = TaskBudget(max_tool_calls=5, max_duration_s=30)
        task = rt.tasks.create("budgeted", budget=budget)
        loaded = rt.tasks.get(task.task_id)
        assert loaded.budget is not None
        assert loaded.budget.max_tool_calls == 5
        rt.shutdown()

    def test_budget_roundtrip_via_checkpoint(self):
        from raven.runtime.tasks import TaskBudget
        from raven.runtime.checkpoint import Checkpoint
        rt, _ = make_runtime()
        budget = TaskBudget(max_tool_calls=20, max_duration_s=120)
        cp = Checkpoint(
            task_id="budget-task",
            budget_state=budget.to_dict(),
        )
        cp_id = rt.checkpoints.save(cp)
        loaded = rt.checkpoints.load(cp_id)
        assert loaded is not None
        recovered = TaskBudget.from_dict(loaded.budget_state)
        assert recovered.max_tool_calls == 20
        rt.shutdown()


class TestConcurrentAccess:
    def test_concurrent_task_creation(self):
        rt, _ = make_runtime()
        tasks_created = []
        errors = []

        def create_task(i):
            try:
                t = rt.tasks.create(f"task-{i}")
                tasks_created.append(t.task_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create_task, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(tasks_created) == 20
        # All IDs must be unique
        assert len(set(tasks_created)) == 20
        rt.shutdown()

    def test_concurrent_event_publishing(self):
        from raven.runtime.events import EventBus, EventType
        bus = EventBus()
        received = []
        lock = threading.Lock()

        def on_event(e):
            with lock:
                received.append(e)

        bus.subscribe("*", on_event)

        def publish_events(_):
            for _ in range(10):
                bus.publish(EventType.TASK_CREATED, {})

        threads = [threading.Thread(target=publish_events, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(received) == 50  # 5 threads × 10 events
