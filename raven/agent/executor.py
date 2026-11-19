"""RAVEN Agent — the execution loop (Wave 10, A10-AGENT).

``AgentExecutor`` is the genuinely-missing loop:

    GOAL -> PLAN -> ActionProposal -> (ProposalBinder) -> ToolInvocation
         -> ToolDispatcher.invoke (CapabilityGate / PolicyGate)
         -> handler (REAL, bound to a live subsystem) -> Observation
         -> durable Task state update (+ ExecutionRecord) -> next step
         -> COMPLETED | BLOCKED | FAILED | CANCELLED | WAITING(approval)

It uses the SAME substrate as the rest of the system — the one ``ToolDispatcher``,
the one ``CapabilityGate`` behind it, the durable ``TaskRegistry`` /
``ExecutionStore``, and the ``EventBus``. There is **no private path** around the
dispatcher/gate and **no parallel loop**. Provenance is boundary-assigned
(``ActorKind.RAVEN_AGENT`` by default) and never taken from the goal text.

Safety properties enforced here (CANONICAL §6, AGENT_ARCHITECTURE §3.5):

* **Bounded.** Every run is bounded by ``max_task_turns`` AND the ``TaskBudget``
  (``max_steps`` / ``max_tool_calls`` / ``max_runtime_ms``). A bound hit halts the
  loop and FAILs the task with a budget reason — no extra dispatch.
* **Emergency stop.** Checked before every turn; an active stop CANCELs the task and
  halts (also, the dispatcher's own gate denies during an active stop).
* **Fail-closed binding.** A :class:`~raven.agent.proposal_bridge.BindError` BLOCKs
  the task with the surfaced reason — never a silent skip / ``not_dispatched``.
* **Capability denial** -> BLOCKED (not COMPLETED); **UNAVAILABLE** tool -> BLOCKED
  (never a fake success); **FAILED/INVALID/TIMED_OUT** -> FAILED.
* **Approval.** A step whose proposal requires human approval pauses the task to
  WAITING and raises an :class:`ApprovalRequest`; it resumes only on an explicit
  researcher decision. No auto-approval. A decision is bound to the exact
  ``(task_id, step_id)`` that was pending and is consumed when used, so one approval
  can never approve a later step (including steps appended by ``next_step``).
* **Cancellation.** The task's durable state is re-read before every turn; a task
  that was cancelled (or otherwise reached a terminal state) while a step was
  running stops the loop — no further step is bound or dispatched.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from raven.planner.planner import PlannerContext
from raven.runtime.execution import ActorKind, ToolStatus
from raven.runtime.tasks import TaskBudget, TaskStatus

from .plan import Plan, PlanStep
from .planner_backend import DeterministicPlanner, PlanIntent, PlanRequest, PlannerBackend, PlannerUnavailable
from .proposal_bridge import BindError, ProposalBinder


class AgentError(Exception):
    """Base for agent-loop errors."""


# ── approval ───────────────────────────────────────────────────────────────────

@dataclass
class ApprovalRequest:
    task_id:   str
    step_id:   str
    tool_hint: str
    reason:    str
    capability: str


class ApprovalSink:
    """Interface for researcher approval of a WAITING step. No auto-approval."""

    def request(self, approval: ApprovalRequest) -> None:  # pragma: no cover - iface
        raise NotImplementedError

    def decision(self, task_id: str, step_id: str) -> Optional[bool]:
        """Return True (approved), False (denied), or None (undecided) for exactly
        this ``(task_id, step_id)``. A decision is single-use: implementations should
        consume it when returning it, so it can never be applied to another step."""
        raise NotImplementedError


class InMemoryApprovalSink(ApprovalSink):
    """A simple in-memory approval sink for the server/UI and tests.

    Decisions are keyed by ``(task_id, step_id)``. ``approve``/``deny`` apply only to
    the step that is pending at that moment (recorded by :meth:`request`), and the
    loop consumes the decision when it reads it. Approving with nothing pending is a
    no-op, so a researcher can never pre-approve a future step.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._pending: Dict[str, ApprovalRequest] = {}
        self._decisions: Dict[tuple[str, str], bool] = {}

    def request(self, approval: ApprovalRequest) -> None:
        with self._lock:
            self._pending[approval.task_id] = approval

    def decision(self, task_id: str, step_id: str) -> Optional[bool]:
        """Return and CONSUME the decision recorded for exactly this step."""
        with self._lock:
            value = self._decisions.pop((task_id, step_id), None)
            if value is not None:
                pending = self._pending.get(task_id)
                if pending is not None and pending.step_id == step_id:
                    self._pending.pop(task_id, None)
            return value

    def _decide(self, task_id: str, step_id: Optional[str], value: bool) -> bool:
        with self._lock:
            pending = self._pending.get(task_id)
            if pending is None:
                return False          # nothing awaiting a decision -> no pre-approval
            if step_id is not None and step_id != pending.step_id:
                return False          # stale/mismatched step -> ignored
            self._decisions[(task_id, pending.step_id)] = value
            return True

    def approve(self, task_id: str, step_id: Optional[str] = None) -> bool:
        """Approve the step currently pending for ``task_id`` (and only that step).
        If ``step_id`` is given it must match the pending step. Returns True when a
        decision was recorded."""
        return self._decide(task_id, step_id, True)

    def deny(self, task_id: str, step_id: Optional[str] = None) -> bool:
        return self._decide(task_id, step_id, False)

    def pending(self, task_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            return self._pending.get(task_id)

    def clear(self, task_id: str) -> None:
        """Drop any pending request / unconsumed decision for a finished task."""
        with self._lock:
            self._pending.pop(task_id, None)
            for key in [k for k in self._decisions if k[0] == task_id]:
                self._decisions.pop(key, None)


# ── run state (resumable) ───────────────────────────────────────────────────────

@dataclass
class _RunState:
    plan:          Plan
    workspace_id:  str
    actor:         ActorKind
    budget:        TaskBudget
    cursor:        int = 0
    tool_calls:    int = 0
    turns:         int = 0
    started_ms:    int = field(default_factory=lambda: int(time.time() * 1000))
    agent_session_id: Optional[str] = None
    # Optional per-run binder (e.g. the program agent binds each run to the
    # ProgramPolicy resolved for that run's workspace). None -> the executor's own.
    binder:        Optional[object] = None


# ── executor ─────────────────────────────────────────────────────────────────

class AgentExecutor:
    """The one deterministic agent loop.

    Accepts the substrate components directly so it is testable and so INT-RUNTIME
    can wire it from a ``RavenRuntime`` without this module importing the runtime.
    Use :meth:`from_runtime` to build it from a started runtime.
    """

    def __init__(self, *, dispatcher, tasks, executions=None, event_bus=None,
                 planner_backend: Optional[PlannerBackend] = None,
                 binder: ProposalBinder,
                 approval: Optional[ApprovalSink] = None,
                 actor: ActorKind = ActorKind.RAVEN_AGENT,
                 max_task_turns: int = 100,
                 emergency_stop=None):
        self._dispatcher = dispatcher
        self._tasks = tasks
        self._executions = executions
        self._bus = event_bus
        self._planner = planner_backend or DeterministicPlanner()
        self._binder = binder
        self._approval = approval
        self._actor = actor
        self._max_turns = int(max_task_turns)
        if emergency_stop is not None:
            self._emergency_stop = emergency_stop
        else:
            from raven.security.policy_gate import PolicyGate
            self._emergency_stop = PolicyGate.is_emergency_stop_active
        self._runs: Dict[str, _RunState] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_runtime(cls, runtime, *, binder: ProposalBinder,
                     planner_backend: Optional[PlannerBackend] = None,
                     approval: Optional[ApprovalSink] = None,
                     actor: ActorKind = ActorKind.RAVEN_AGENT):
        return cls(
            dispatcher=runtime.dispatcher,
            tasks=runtime.tasks,
            executions=getattr(runtime, "executions", None),
            event_bus=getattr(runtime, "bus", None),
            planner_backend=planner_backend,
            binder=binder,
            approval=approval,
            actor=actor,
            max_task_turns=getattr(getattr(runtime, "_config", None), "max_task_turns", 100),
        )

    # -- public API ------------------------------------------------------------

    def run(self, objective: str, *, workspace_id: str,
            scope_hosts: Optional[List[str]] = None,
            knowledge_ids: Optional[List[str]] = None,
            plan_request: Optional[PlanRequest] = None,
            budget: Optional[TaskBudget] = None,
            actor: Optional[ActorKind] = None,
            title: Optional[str] = None,
            agent_session_id: Optional[str] = None,
            binder=None):
        """GOAL -> PLAN -> loop. Returns the durable Task (any terminal/WAITING state).

        ``actor`` provenance is boundary-assigned here; the ``objective`` string is a
        human-readable label only and can never set it. ``binder`` optionally
        overrides the executor's binder for this run only (kept on the run state, so a
        resumed run keeps using it).
        """
        actor = actor or self._actor
        budget = budget or TaskBudget()

        # 1. Durable Task of record (PENDING).
        task = self._tasks.create(
            title=title or (objective[:80] if objective else "agent run"),
            objective=objective or "",
            workspace_id=workspace_id,
            budget=budget,
            origin=actor,
            metadata={"planner": self._planner.name},
        )

        # 2. PLANNING.
        self._tasks.transition(task.task_id, TaskStatus.PLANNING)
        context = PlannerContext(
            workspace_id=workspace_id,
            scope_hosts=list(scope_hosts or []),
            knowledge_ids=list(knowledge_ids or []),
        )
        try:
            plan = self._planner.plan(context, plan_request)
        except PlannerUnavailable as exc:
            # Model-off / no-plan degradation: NEVER free action — fail the task.
            return self._terminate(task.task_id, TaskStatus.FAILED,
                                   failure=f"no_plan: {exc}")
        plan.task_id = task.task_id
        plan.created_by = actor.value

        if not plan or len(plan) == 0:
            return self._terminate(task.task_id, TaskStatus.FAILED,
                                   failure="no_plan: planner produced no actionable steps")

        # 3. RUNNING.
        self._tasks.transition(task.task_id, TaskStatus.RUNNING)
        self._tasks.update_progress(task.task_id, step=0, total=len(plan),
                                    message="plan ready")

        state = _RunState(plan=plan, workspace_id=workspace_id, actor=actor,
                          budget=budget, agent_session_id=agent_session_id,
                          binder=binder)
        with self._lock:
            self._runs[task.task_id] = state
        return self._drive(task.task_id)

    def resume(self, task_id: str):
        """Resume a WAITING task after a researcher decision."""
        task = self._tasks.get(task_id)
        if task is None:
            raise AgentError(f"task '{task_id}' not found")
        if task.status != TaskStatus.WAITING:
            return task
        self._tasks.transition(task_id, TaskStatus.RUNNING)
        return self._drive(task_id)

    def cancel(self, task_id: str):
        task = self._tasks.get(task_id)
        if task is None or task.is_terminal:
            return task
        return self._terminate(task_id, TaskStatus.CANCELLED,
                               failure="cancelled by researcher")

    # -- the loop --------------------------------------------------------------

    def _drive(self, task_id: str):
        with self._lock:
            state = self._runs.get(task_id)
        if state is None:
            raise AgentError(f"no run state for task '{task_id}'")
        plan = state.plan
        binder = state.binder if state.binder is not None else self._binder

        while state.cursor < len(plan):
            # Cancellation / external terminal transition — re-read the durable task
            # BEFORE every turn so a cancel issued while a step was running stops the
            # loop here instead of dispatching the remaining steps.
            current = self._tasks.get(task_id)
            if current is None or current.is_terminal:
                self._forget(task_id)
                return current

            # Turn + budget bounds (hard loop bounds).
            if state.turns >= self._max_turns:
                return self._terminate(task_id, TaskStatus.FAILED,
                                       failure=f"turn_bound: exceeded max_task_turns={self._max_turns}")
            bud_reason = self._budget_exceeded(state)
            if bud_reason:
                return self._terminate(task_id, TaskStatus.FAILED, failure=bud_reason)

            # Emergency stop — checked BEFORE binding/dispatch.
            if self._emergency_stop():
                return self._terminate(task_id, TaskStatus.CANCELLED,
                                       failure="emergency_stop: loop halted")

            step = plan.steps[state.cursor]
            state.turns += 1

            # Approval gate (pre-dispatch). No auto-approval.
            if step.proposal.human_approval_required:
                decision = (self._approval.decision(task_id, step.step_id)
                            if self._approval is not None else None)
                if decision is None:
                    try:
                        self._tasks.transition(task_id, TaskStatus.WAITING)
                    except Exception:
                        # Lost a race with cancel: never resurrect a terminal task.
                        current = self._tasks.get(task_id)
                        if current is None or current.is_terminal:
                            self._forget(task_id)
                            return current
                        raise
                    if self._approval is not None:
                        self._approval.request(ApprovalRequest(
                            task_id=task_id, step_id=step.step_id,
                            tool_hint=step.proposal.required_capability,
                            reason=step.proposal.reason,
                            capability=step.proposal.required_capability))
                    return self._tasks.get(task_id)   # paused (WAITING)
                if decision is False:
                    return self._terminate(task_id, TaskStatus.FAILED,
                                           failure="approval_denied by researcher")
                # decision True → fall through and dispatch.

            # Bind (fail-closed).
            try:
                invocation = binder.bind(
                    step, task_id=task_id, workspace_id=state.workspace_id,
                    actor=state.actor, agent_session_id=state.agent_session_id)
            except BindError as exc:
                return self._terminate(task_id, TaskStatus.BLOCKED,
                                       failure=f"bind_failed[{exc.reason}]: {exc.detail or exc.reason}")

            # Dispatch through the one dispatcher (gate + policy + execute + record).
            result, record = self._dispatcher.invoke(invocation)
            state.tool_calls += 1
            self._tasks.update_progress(
                task_id, step=state.cursor + 1, total=len(plan),
                message=f"{invocation.tool_id} -> {result.status.value}")

            # Observation-driven outcome handling.
            if result.status in (ToolStatus.SUCCESS, ToolStatus.PARTIAL):
                state.cursor += 1
                # Optional observation-driven extension.
                extra = self._planner.next_step(
                    PlannerContext(workspace_id=state.workspace_id),
                    self._observations(task_id))
                if extra is not None:
                    plan.steps.append(extra)
                continue
            if result.status == ToolStatus.DENIED:
                return self._terminate(task_id, TaskStatus.BLOCKED,
                                       failure=f"capability_denied: {result.error}")
            if result.status == ToolStatus.UNAVAILABLE:
                return self._terminate(task_id, TaskStatus.BLOCKED,
                                       failure=f"tool_unavailable: {result.error}")
            # INVALID_INPUT / FAILED / TIMED_OUT / CANCELLED
            return self._terminate(task_id, TaskStatus.FAILED,
                                   failure=f"tool_{result.status.value.lower()}: {result.error}")

        # Plan exhausted — all steps succeeded.
        observations = self._observations(task_id)
        return self._terminate(
            task_id, TaskStatus.COMPLETED,
            result={"steps": len(plan), "tool_calls": state.tool_calls,
                    "observations": len(observations), "planner": self._planner.name})

    # -- helpers ---------------------------------------------------------------

    def _budget_exceeded(self, state: _RunState) -> Optional[str]:
        b = state.budget
        if b.max_steps is not None and state.cursor >= b.max_steps:
            return f"budget: max_steps={b.max_steps} reached"
        if b.max_tool_calls is not None and state.tool_calls >= b.max_tool_calls:
            return f"budget: max_tool_calls={b.max_tool_calls} reached"
        runtime_cap = b.max_runtime_ms
        if runtime_cap is None and b.max_duration_s is not None:
            runtime_cap = b.max_duration_s * 1000
        if runtime_cap is not None and (int(time.time() * 1000) - state.started_ms) >= runtime_cap:
            return f"budget: max_runtime_ms={runtime_cap} reached"
        return None

    def _observations(self, task_id: str) -> list:
        if self._executions is None:
            return []
        try:
            return self._executions.list_for_task(task_id)
        except Exception:
            return []

    def _forget(self, task_id: str) -> None:
        """Drop the in-memory run state and any approval state for a finished run."""
        with self._lock:
            self._runs.pop(task_id, None)
        clear = getattr(self._approval, "clear", None)
        if callable(clear):
            try:
                clear(task_id)
            except Exception:
                pass

    def _terminate(self, task_id: str, status: TaskStatus, *,
                   result: dict = None, failure: str = None):
        self._forget(task_id)
        task = self._tasks.get(task_id)
        if task is None:
            return None
        if task.is_terminal:
            return task
        return self._tasks.transition(task_id, status, result=result, failure=failure)


# ── AgentService — the single façade the server calls ──────────────────────────

class AgentService:
    """Thin façade owned by the runtime; the ONLY agent entry point for the server.

    There is no private path to the dispatcher — every run goes through the one
    :class:`AgentExecutor`.
    """

    def __init__(self, executor: AgentExecutor, approval: Optional[ApprovalSink] = None):
        self._executor = executor
        self._approval = approval

    def start_run(self, objective: str, *, workspace_id: str,
                  plan_request: Optional[PlanRequest] = None,
                  scope_hosts: Optional[List[str]] = None,
                  knowledge_ids: Optional[List[str]] = None,
                  budget: Optional[TaskBudget] = None,
                  actor: ActorKind = ActorKind.RAVEN_AGENT):
        return self._executor.run(
            objective, workspace_id=workspace_id, plan_request=plan_request,
            scope_hosts=scope_hosts, knowledge_ids=knowledge_ids,
            budget=budget, actor=actor)

    def get_run(self, task_id: str):
        task = self._executor._tasks.get(task_id)
        if task is None:
            return None
        return {"task": task.to_dict(),
                "observations": [getattr(o, "__dict__", o)
                                 for o in self._executor._observations(task_id)]}

    def approve_step(self, task_id: str, step_id: Optional[str] = None):
        """Approve the ONE step currently pending for ``task_id`` (optionally pinned
        to ``step_id``), then resume. A later step needs its own approval."""
        _record_decision(self._approval, "approve", task_id, step_id)
        return self._executor.resume(task_id)

    def deny_step(self, task_id: str, step_id: Optional[str] = None):
        _record_decision(self._approval, "deny", task_id, step_id)
        return self._executor.resume(task_id)

    def cancel_run(self, task_id: str):
        return self._executor.cancel(task_id)


def _record_decision(sink, action: str, task_id: str, step_id: Optional[str]) -> None:
    """Record an approve/deny on ``sink`` for the pending step of ``task_id``.

    Passes ``step_id`` only when given, so sinks whose ``approve``/``deny`` take just
    ``task_id`` keep working."""
    fn = getattr(sink, action, None) if sink is not None else None
    if not callable(fn):
        return
    if step_id is None:
        fn(task_id)
    else:
        fn(task_id, step_id)
