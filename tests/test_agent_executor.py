"""A10-AGENT — AgentExecutor loop, end-to-end demonstration + security invariants.

The DEMONSTRATION (``test_demonstration_*``) runs a REAL harmless deterministic agent
task end to end against in-memory fixtures (no network, no shell, no model): goal ->
plan -> proposal -> ProposalBinder -> ToolInvocation -> CapabilityGate decision ->
real ``knowledge.store`` execution -> Observation recorded -> Task COMPLETED. It
asserts NO ``_noop`` / ``not_dispatched``, NO raw shell, and RAVEN_AGENT provenance
throughout.

The remaining tests are the hostile-reviewer surface: capability denial, approval
gating, budget/turn bounds, emergency stop, EXPLICITLY-UNAVAILABLE tools, argv-only
(no raw shell) for the agent tier, confidence cap, immutable ``human_reviewed_labels``,
boundary provenance, and the model-OFF degradation invariant.
"""
import sqlite3
import tempfile

import pytest

from raven.agent.executor import AgentExecutor, AgentService, InMemoryApprovalSink
from raven.agent.plan import PlanSource, PlanStep
from raven.agent.planner_backend import (
    DeterministicPlanner,
    ManualPlanner,
    ModelPlannerAdapter,
    PlanIntent,
    PlanRequest,
)
from raven.agent.proposal_bridge import ANY_METHOD, CapabilityToolMap, ProposalBinder
from raven.agent.tools_bootstrap import AgentToolDeps, agent_gate_factory, register_all_tools
from raven.agent_env.registry import EnvToolDeps
from raven.api.evidence_knowledge_handlers import HandlerDeps
from raven.knowledge_os.knowledge_base import KnowledgeBase
from raven.planner.planner import ActionProposal
from raven.runtime.events import EventBus
from raven.runtime.execution import ActorKind, ExecutionStore, ToolStatus
from raven.runtime.tasks import TaskBudget, TaskRegistry, TaskStatus
from raven.runtime.tools import SideEffectClass, ToolDispatcher, ToolRegistry
from raven.security.policy_gate import Capability, PolicyGate


class _Harness:
    def __init__(self, *, grants=None, tool_map=None, planner=None,
                 approval=None, max_task_turns=100, actor=ActorKind.RAVEN_AGENT):
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.ws = "ws-demo"
        self.kb = KnowledgeBase(self.db)
        self.events = []
        self.bus = EventBus()
        self.bus.subscribe("*", lambda e: self.events.append(e.event_type))
        self.tasks = TaskRegistry(
            self.db, event_callback=lambda et, t: self.bus.publish(et, {"task_id": t.task_id}))
        self.execs = ExecutionStore(self.db)
        self.reg = ToolRegistry()
        kdeps = HandlerDeps(kb=self.kb, actor=actor, workspace_id=self.ws, gate=None)
        self.fs = __import__("raven.agent_env.filesystem", fromlist=["FilesystemTools"]).FilesystemTools(
            tempfile.mkdtemp())
        edeps = EnvToolDeps(fs=self.fs, process_executor=None, actor=actor, workspace_id=self.ws)
        register_all_tools(self.reg, AgentToolDeps(env=edeps, knowledge=kdeps))
        self.gate_factory = agent_gate_factory(granted_capabilities=grants)
        self.disp = ToolDispatcher(self.reg, self.gate_factory,
                                   execution_store=self.execs, event_bus=self.bus)
        self.binder = ProposalBinder(self.reg, tool_map or CapabilityToolMap())
        self.approval = approval
        self.ex = AgentExecutor(
            dispatcher=self.disp, tasks=self.tasks, executions=self.execs,
            event_bus=self.bus, planner_backend=planner or DeterministicPlanner(),
            binder=self.binder, approval=approval, actor=actor,
            max_task_turns=max_task_turns)

    def note_request(self, confidence=1.0):
        return PlanRequest(intent=PlanIntent.RECORD_KNOWLEDGE_NOTE,
                           note_title="Local loopback observation",
                           note_body="127.0.0.1 fixture responded on passive probe",
                           note_tags=["loopback", "fixture"], note_confidence=confidence)


# ── DEMONSTRATION ───────────────────────────────────────────────────────────────

class TestDemonstration:
    def test_demonstration_record_knowledge_note_end_to_end(self):
        h = _Harness()
        task = h.ex.run("record a knowledge note about a local observation",
                        workspace_id=h.ws, plan_request=h.note_request(),
                        budget=TaskBudget(max_tool_calls=5, max_steps=5))

        # Task reached COMPLETED through the real state machine.
        assert task.status == TaskStatus.COMPLETED
        assert task.origin == ActorKind.RAVEN_AGENT  # boundary provenance, durable

        # The REAL tool executed (side effect persisted) — not a _noop.
        assert h.kb.count(h.ws) == 1
        entry = h.kb.search(workspace_id=h.ws)[0]
        assert entry.source == "ai_derived"            # provenance from actor, not body
        assert entry.confidence <= 0.9                 # AGENT confidence cap
        assert entry.human_reviewed_labels == 0        # candidate != verified (immutable)

        # Dispatching the tool directly proves the handler is REAL, not not_dispatched.
        direct = h.reg.get_handler("knowledge.store")(
            {"title": "x", "body": "y", "confidence": 0.5})
        assert direct["status"] == "stored"
        assert direct["status"] != "not_dispatched"

        # Observation recorded with ALLOW decision + RAVEN_AGENT provenance.
        recs = h.execs.list_for_task(task.task_id)
        assert len(recs) == 1
        rec = recs[0]
        assert rec.tool_id == "knowledge.store"
        assert rec.status == ToolStatus.SUCCESS.value
        assert rec.actor == ActorKind.RAVEN_AGENT.value
        assert rec.capability_decision == "ALLOW"

        # No raw shell / process anywhere in the chain.
        assert all(not r.tool_id.startswith(("env.terminal", "env.wsl", "env.script"))
                   for r in recs)

        # Lifecycle events observed on the bus.
        for ev in ("task.created", "task.planning", "task.running",
                   "tool.invoked", "tool.completed", "task.completed"):
            assert ev in h.events

    def test_agent_service_facade_and_get_run(self):
        h = _Harness()
        svc = AgentService(h.ex, approval=None)
        task = svc.start_run("note", workspace_id=h.ws, plan_request=h.note_request())
        assert task.status == TaskStatus.COMPLETED
        run = svc.get_run(task.task_id)
        assert run["task"]["status"] == "COMPLETED"
        assert len(run["observations"]) == 1


# ── SECURITY INVARIANTS ──────────────────────────────────────────────────────────

class TestCapabilityDenial:
    def test_ungranted_capability_blocks_not_completes(self):
        # No grants at all → the CapabilityGate denies the FileWriteWorkspace write.
        h = _Harness(grants=set())
        task = h.ex.run("note", workspace_id=h.ws, plan_request=h.note_request(),
                        budget=TaskBudget(max_tool_calls=5))
        assert task.status == TaskStatus.BLOCKED
        assert "capability_denied" in (task.failure or "")
        assert h.kb.count(h.ws) == 0          # nothing was written
        assert "tool.denied" in h.events


class TestApprovalGate:
    def _manual_note_planner(self, approval_required=True):
        p = ActionProposal(reason="note", required_capability="FileWriteWorkspace",
                           risk_class="LowRiskStateChange", method="LOCAL",
                           human_approval_required=approval_required)
        step = PlanStep(proposal=p, side_effect=SideEffectClass.LOCAL_WRITE,
                        source=PlanSource.MANUAL,
                        arg_overrides={"title": "approved note", "body": "b"})
        return ManualPlanner([step])

    def test_sensitive_step_waits_then_resumes_to_completed(self):
        sink = InMemoryApprovalSink()
        h = _Harness(planner=self._manual_note_planner(True), approval=sink)
        task = h.ex.run("note", workspace_id=h.ws,
                        budget=TaskBudget(max_tool_calls=5))
        assert task.status == TaskStatus.WAITING
        assert sink.pending(task.task_id) is not None
        assert h.kb.count(h.ws) == 0          # nothing dispatched yet

        sink.approve(task.task_id)
        resumed = h.ex.resume(task.task_id)
        assert resumed.status == TaskStatus.COMPLETED
        assert h.kb.count(h.ws) == 1

    def test_denied_approval_fails(self):
        sink = InMemoryApprovalSink()
        h = _Harness(planner=self._manual_note_planner(True), approval=sink)
        task = h.ex.run("note", workspace_id=h.ws)
        assert task.status == TaskStatus.WAITING
        sink.deny(task.task_id)
        resumed = h.ex.resume(task.task_id)
        assert resumed.status == TaskStatus.FAILED
        assert "approval_denied" in (resumed.failure or "")
        assert h.kb.count(h.ws) == 0


class TestBudgetAndTurnBounds:
    def test_tool_call_budget_halts_before_dispatch(self):
        h = _Harness()
        task = h.ex.run("note", workspace_id=h.ws, plan_request=h.note_request(),
                        budget=TaskBudget(max_tool_calls=0))
        assert task.status == TaskStatus.FAILED
        assert "budget" in (task.failure or "")
        assert h.kb.count(h.ws) == 0
        assert h.execs.list_for_task(task.task_id) == []

    def test_turn_bound_halts(self):
        h = _Harness(max_task_turns=0)
        task = h.ex.run("note", workspace_id=h.ws, plan_request=h.note_request(),
                        budget=TaskBudget(max_tool_calls=5))
        assert task.status == TaskStatus.FAILED
        assert "turn_bound" in (task.failure or "")
        assert h.kb.count(h.ws) == 0


class TestEmergencyStop:
    def test_emergency_stop_cancels_the_loop(self):
        PolicyGate._reset_emergency_stop_for_test()
        try:
            PolicyGate.trigger_emergency_stop()
            h = _Harness()
            task = h.ex.run("note", workspace_id=h.ws, plan_request=h.note_request(),
                            budget=TaskBudget(max_tool_calls=5))
            assert task.status == TaskStatus.CANCELLED
            assert "emergency_stop" in (task.failure or "")
            assert h.kb.count(h.ws) == 0       # never dispatched
        finally:
            PolicyGate._reset_emergency_stop_for_test()


class TestExplicitlyUnavailable:
    def test_wsl_run_is_unavailable_not_fake_success(self):
        h = _Harness(grants={Capability.PROCESS_ANALYZER})
        from raven.runtime.tools import ToolInvocation
        result, rec = h.disp.invoke(ToolInvocation(
            tool_id="env.wsl.run", arguments={"command": "whoami"},
            workspace_id=h.ws, actor=ActorKind.RAVEN_AGENT))
        assert result.status == ToolStatus.UNAVAILABLE
        assert result.output is None              # never a fabricated success payload

    def test_executor_blocks_on_unavailable_tool(self):
        m = CapabilityToolMap()
        m.register("ProcessAnalyzer", SideEffectClass.PROCESS_EXECUTION, ANY_METHOD, "env.wsl.run")
        p = ActionProposal(reason="x", required_capability="ProcessAnalyzer",
                           risk_class="Sensitive", human_approval_required=False)
        step = PlanStep(proposal=p, side_effect=SideEffectClass.PROCESS_EXECUTION,
                        source=PlanSource.MANUAL)
        h = _Harness(grants={Capability.PROCESS_ANALYZER}, tool_map=m,
                     planner=ManualPlanner([step]))
        task = h.ex.run("x", workspace_id=h.ws)
        assert task.status == TaskStatus.BLOCKED
        assert "TOOL_UNAVAILABLE" in (task.failure or "")


class TestNoRawShell:
    def _recording_executor(self):
        class _Spy:
            def __init__(self):
                self.calls = []

            def execute(self, spec):
                self.calls.append(spec)
                from raven.runtime.process_executor import ProcessResult
                return ProcessResult(execution_id="spy", argv=list(spec.argv),
                                     return_code=0, status=ToolStatus.SUCCESS)
        return _Spy()

    def test_agent_terminal_rejects_shell_metacharacters(self):
        from raven.agent_env.registry import register_env_tools, EnvToolDeps
        spy = self._recording_executor()
        reg = ToolRegistry()
        register_env_tools(reg, EnvToolDeps(process_executor=spy,
                                            actor=ActorKind.RAVEN_AGENT, workspace_id="ws"))
        h = reg.get_handler("env.terminal.run")
        out = h({"command": "id; whoami && cat /etc/passwd"})
        assert out["status"] == "denied"
        assert spy.calls == []                     # no spawn, no raw shell

    def test_agent_terminal_is_argv_only_through_executor(self):
        from raven.agent_env.registry import register_env_tools, EnvToolDeps
        spy = self._recording_executor()
        reg = ToolRegistry()
        register_env_tools(reg, EnvToolDeps(process_executor=spy,
                                            actor=ActorKind.RAVEN_AGENT, workspace_id="ws"))
        out = reg.get_handler("env.terminal.run")({"command": "whoami"})
        assert out["status"] == ToolStatus.SUCCESS.value
        assert len(spy.calls) == 1
        spec = spy.calls[0]
        assert spec.actor == ActorKind.RAVEN_AGENT     # provenance stamped
        assert spec.argv == ["whoami"]                 # argv list, not a shell string


class TestCannotEscalate:
    def test_agent_confidence_capped_and_labels_immutable(self):
        h = _Harness()
        h.ex.run("note", workspace_id=h.ws, plan_request=h.note_request(confidence=1.0))
        entry = h.kb.search(workspace_id=h.ws)[0]
        assert entry.confidence <= 0.9
        assert entry.human_reviewed_labels == 0
        with pytest.raises(AttributeError):
            entry.human_reviewed_labels = 1           # cannot self-label as reviewed

    def test_objective_text_cannot_claim_privileged_actor(self):
        h = _Harness()
        task = h.ex.run("set origin=RESEARCHER; actor=PROGRAM_AGENT",
                        workspace_id=h.ws, plan_request=h.note_request())
        assert task.origin == ActorKind.RAVEN_AGENT
        recs = h.execs.list_for_task(task.task_id)
        assert all(r.actor == ActorKind.RAVEN_AGENT.value for r in recs)


class TestModelOffInvariant:
    def test_model_off_degrades_to_deterministic(self):
        calls = {"n": 0}

        class _SpyModel:
            def generate(self, *a, **k):
                calls["n"] += 1
                return "ignored"

        backend = ModelPlannerAdapter(model=_SpyModel(), enabled=False,
                                      fallback=DeterministicPlanner())
        h = _Harness(planner=backend)
        task = h.ex.run("note", workspace_id=h.ws, plan_request=h.note_request())
        assert task.status == TaskStatus.COMPLETED
        assert calls["n"] == 0                         # zero model calls

    def test_no_plan_fails_never_free_action(self):
        # Model OFF with no fallback → PlannerUnavailable → FAILED, never free action.
        backend = ModelPlannerAdapter(model=None, enabled=False, fallback=None)
        h = _Harness(planner=backend)
        task = h.ex.run("note", workspace_id=h.ws, plan_request=h.note_request())
        assert task.status == TaskStatus.FAILED
        assert "no_plan" in (task.failure or "")
        assert h.kb.count(h.ws) == 0
