"""RAVEN Program Agent — the Program Mode driver (Wave 11, A11-PROGRAM).

``ProgramAgentExecutor`` is a **stricter configuration of the one**
:class:`~raven.agent.executor.AgentExecutor` — NOT a second loop, NOT a private
execution path. It reuses the same dispatcher, the same CapabilityGate/PolicyGate
authority, the same durable TaskRegistry/ExecutionStore, and the same EventBus. The
only things it changes are the *envelope* around that one loop (CANONICAL §1 row 20,
§6; AGENT_ARCHITECTURE §3.7):

    ProgramPolicy → scope → identity(PROGRAM_AGENT) → allowed action
                  → rate/budget → capability → trusted execution

Strictness it layers on top of the base loop, all as configuration:

* **No ``ProgramPolicy`` ⇒ no autonomous execution.** :meth:`start_program_run`
  refuses with :class:`NoProgramPolicyError` when no active program with a loaded
  ``ProgramPolicy`` resolves for the workspace. No task is created; there is no
  default-permissive path.
* **ProgramPolicy scope authority, evaluated BEFORE the binder** — a network step
  whose destination is not ``ProgramPolicy.is_target_allowed`` is refused
  (fail-closed → the base loop turns it into BLOCKED), *in addition to* PolicyGate's
  own scope check and the live ``scope.Scope``. ``external_targets`` stays immutably 0
  (``policy.py`` is not edited); the program agent cannot add external targets — all
  validation is loopback/synthetic.
* **PROGRAM_AGENT provenance** is boundary-assigned on every invocation/record,
  distinct from RESEARCHER / RAVEN_AGENT. It is never taken from the objective text.
* **Never a raw/unrestricted host shell.** Stricter than the RESEARCHER terminal: the
  program agent's ``CapabilityToolMap`` carries **no** process/shell row, and the
  scope-binder additionally refuses any ``PROCESS_EXECUTION`` step outright — so a
  shell attempt fail-closes at bind (BLOCKED) and never reaches a ProcessExecutor,
  let alone a raw shell.
* **Tighter budget / turn bounds** than a researcher-driven run.
* **Submissions stay human-gated** — the program tools create only DRAFT submissions
  (``human_reviewed=False``); a researcher gates READY/SUBMITTED.
"""
from __future__ import annotations

from typing import List, Optional

from raven.agent.executor import AgentExecutor, ApprovalSink, _record_decision
from raven.agent.plan import PlanStep
from raven.agent.planner_backend import PlannerBackend
from raven.agent.proposal_bridge import (
    ANY_METHOD,
    BindError,
    CapabilityToolMap,
    ProposalBinder,
)
from raven.runtime.execution import ActorKind
from raven.runtime.tasks import TaskBudget
from raven.runtime.tools import SideEffectClass, ToolRegistry


class NoProgramPolicyError(Exception):
    """Raised when the program agent is asked to run with no loaded ``ProgramPolicy``.

    The refusal is the safety property: without a program policy there is no
    autonomous execution and no default-open path (CANONICAL §1 row 20).
    """


# ── the scope + no-shell binder (configuration of the one ProposalBinder) ────────

class _ProgramScopedBinder:
    """Wraps the one :class:`~raven.agent.proposal_bridge.ProposalBinder` with the
    ProgramPolicy scope authority and the no-shell guard.

    This is **configuration**, not a second code path: the one ``AgentExecutor`` loop
    still calls ``.bind()`` on this object through its normal binder seam. A scope or
    shell refusal raises :class:`~raven.agent.proposal_bridge.BindError`, which that
    one loop already turns into a surfaced BLOCKED task — never a silent skip.

    One instance is built PER RUN, closing over the ProgramPolicy resolved for that
    run's workspace (``policy_getter``), and handed to the one loop as that run's
    binder. Concurrent runs and later runs in another workspace therefore never see
    each other's policy.
    """

    _NETWORK = (SideEffectClass.NETWORK_READ, SideEffectClass.NETWORK_STATE_CHANGE)

    def __init__(self, inner: ProposalBinder, policy_getter):
        self._inner = inner
        self._policy_getter = policy_getter

    def bind(self, step: PlanStep, *, task_id, workspace_id, actor,
             agent_session_id=None):
        policy = self._policy_getter()
        if policy is None:
            # No autonomous execution without a loaded policy (defense in depth:
            # start_program_run already refuses, but the binder fail-closes too).
            raise BindError("NO_PROGRAM_POLICY",
                            "no loaded ProgramPolicy — program agent will not act")

        # 1. Never a raw/host shell for the program agent (stricter than researcher).
        if step.side_effect == SideEffectClass.PROCESS_EXECUTION:
            raise BindError(
                "PROGRAM_NO_SHELL",
                "program agent has no process/shell capability (argv-only, no raw shell)")

        # 2. ProgramPolicy scope authority — BEFORE the binder/dispatch, in addition
        #    to PolicyGate's own scope check. Network destinations must be in the
        #    loaded program scope. external_targets stays 0 (policy enforces it).
        if step.side_effect in self._NETWORK:
            dest = (step.proposal.destination or "").strip()
            if not dest or not policy.is_target_allowed(dest):
                raise BindError(
                    "OUT_OF_SCOPE",
                    f"target '{dest}' is not in the loaded program scope")

        return self._inner.bind(step, task_id=task_id, workspace_id=workspace_id,
                                actor=actor, agent_session_id=agent_session_id)


# ── the program agent driver (stricter config of the one AgentExecutor) ──────────

class ProgramAgentExecutor:
    """Program Mode = a stricter configuration of the one AgentExecutor loop."""

    # Tighter defaults than a researcher/agent run (whose default TaskBudget is
    # effectively unbounded and whose max_task_turns is 100).
    DEFAULT_MAX_TURNS = 20
    DEFAULT_BUDGET = TaskBudget(max_steps=10, max_tool_calls=10,
                                max_network_requests=20, max_runtime_ms=120_000)

    def __init__(self, *, dispatcher, tasks, registry: ToolRegistry,
                 executions=None, event_bus=None,
                 program_policy=None, program_store=None,
                 tool_map: Optional[CapabilityToolMap] = None,
                 planner_backend: Optional[PlannerBackend] = None,
                 approval: Optional[ApprovalSink] = None,
                 max_task_turns: Optional[int] = None,
                 default_budget: Optional[TaskBudget] = None,
                 emergency_stop=None):
        self._registry = registry
        self._program_store = program_store
        # A policy injected by the composer (explicit configuration). A policy
        # resolved from the store is NEVER written back here: it is bound to the one
        # run it was resolved for (see start_program_run).
        self._configured_policy = program_policy
        self._last_policy = program_policy        # informational only (active_policy)
        self._default_budget = default_budget or self.DEFAULT_BUDGET
        self._approval = approval

        # The program agent's stricter capability set: a CapabilityToolMap with NO
        # process/shell row (so a shell step cannot even resolve a tool_id).
        tool_map = tool_map or self._program_tool_map()
        self._inner_binder = ProposalBinder(self._registry, tool_map)
        # Default binder for any run that did not come through start_program_run:
        # it has no policy, so it fail-closes (NO_PROGRAM_POLICY).
        binder = _ProgramScopedBinder(self._inner_binder, lambda: None)

        # The ONE AgentExecutor, configured strictly. No subclassing of the loop, no
        # parallel loop — only a different binder, actor, and bounds.
        self._executor = AgentExecutor(
            dispatcher=dispatcher, tasks=tasks, executions=executions,
            event_bus=event_bus, planner_backend=planner_backend,
            binder=binder, approval=approval,
            actor=ActorKind.PROGRAM_AGENT,
            max_task_turns=int(max_task_turns if max_task_turns is not None
                               else self.DEFAULT_MAX_TURNS),
            emergency_stop=emergency_stop)
        self._tasks = tasks

    # -- stricter capability map (no shell) ------------------------------------

    @staticmethod
    def _program_tool_map() -> CapabilityToolMap:
        """The program agent's capability→tool map: the harmless scope/knowledge
        rows and the scheduler-gated HTTP rows, but **no** process/shell row. An
        attempt to run a shell therefore fail-closes at bind (UNMAPPED_ACTION), on top
        of the explicit PROGRAM_NO_SHELL guard in the scope binder."""
        m = CapabilityToolMap(seed_defaults=False)
        m.register("ScopeRead",          SideEffectClass.PURE,                 ANY_METHOD, "program.policy.check")
        m.register("FileWriteWorkspace", SideEffectClass.LOCAL_WRITE,          ANY_METHOD, "knowledge.store")
        m.register("FileReadWorkspace",  SideEffectClass.LOCAL_READ,           ANY_METHOD, "knowledge.search")
        m.register("HttpRead",           SideEffectClass.NETWORK_READ,         "GET",      "net.http.request")
        m.register("HttpStateChange",    SideEffectClass.NETWORK_STATE_CHANGE, "POST",     "net.http.request")
        return m

    # -- policy resolution -----------------------------------------------------

    def _resolve_policy(self, workspace_id: str, program_id: Optional[str]):
        """Resolve the ProgramPolicy for THIS run's workspace. A directly-configured
        (constructor) policy wins unless a specific ``program_id`` is requested;
        otherwise the first active program with a loaded policy in ``workspace_id`` is
        used — read fresh from the store on every run, never a policy cached from an
        earlier run (possibly in another workspace). None ⇒ no autonomous run."""
        if self._configured_policy is not None and program_id is None:
            return self._configured_policy
        if self._program_store is None:
            return self._configured_policy
        if not (workspace_id or "").strip():
            # list_active("") spans EVERY workspace — never borrow another
            # workspace's policy; no workspace => no autonomous run.
            return None
        try:
            programs = self._program_store.list_active(workspace_id)
        except Exception:
            return None
        for prog in programs:
            if getattr(prog, "workspace_id", workspace_id) != workspace_id:
                continue
            policy = getattr(prog, "policy", None)
            if policy is None:
                continue
            if (program_id is None
                    or getattr(prog, "program_id", None) == program_id
                    or getattr(policy, "program_id", None) == program_id):
                return policy
        return None

    # -- public API ------------------------------------------------------------

    def start_program_run(self, objective: str, *, workspace_id: str,
                          program_id: Optional[str] = None,
                          plan_request=None,
                          scope_hosts: Optional[List[str]] = None,
                          knowledge_ids: Optional[List[str]] = None,
                          budget: Optional[TaskBudget] = None):
        """Drive one program-agent run through the one AgentExecutor loop.

        Refuses with :class:`NoProgramPolicyError` (no task created) when no loaded
        ``ProgramPolicy`` resolves — the no-autonomous-execution invariant.
        """
        policy = self._resolve_policy(workspace_id, program_id)
        if policy is None:
            raise NoProgramPolicyError(
                f"no active BugBountyProgram with a loaded ProgramPolicy for "
                f"workspace '{workspace_id}' — the program agent will not run "
                f"autonomously (no default-permissive path)")
        self._last_policy = policy
        # Bind THIS run to the policy resolved for its own workspace (a per-run
        # binder kept on the run state, so a resumed run keeps the same policy).
        run_binder = _ProgramScopedBinder(self._inner_binder, lambda: policy)
        return self._executor.run(
            objective, workspace_id=workspace_id, plan_request=plan_request,
            scope_hosts=scope_hosts, knowledge_ids=knowledge_ids,
            budget=budget or self._default_budget,
            actor=ActorKind.PROGRAM_AGENT, binder=run_binder)

    def resume(self, task_id: str):
        """Resume a WAITING program task after an explicit researcher decision."""
        return self._executor.resume(task_id)

    def cancel(self, task_id: str):
        return self._executor.cancel(task_id)

    def approve_step(self, task_id: str, step_id: Optional[str] = None):
        """Approve only the step currently pending for ``task_id``, then resume."""
        _record_decision(self._approval, "approve", task_id, step_id)
        return self._executor.resume(task_id)

    def deny_step(self, task_id: str, step_id: Optional[str] = None):
        _record_decision(self._approval, "deny", task_id, step_id)
        return self._executor.resume(task_id)

    def get_run(self, task_id: str):
        task = self._tasks.get(task_id)
        if task is None:
            return None
        return {"task": task.to_dict(),
                "observations": [getattr(o, "__dict__", o)
                                 for o in self._executor._observations(task_id)]}

    @property
    def active_policy(self):
        """The policy most recently resolved by :meth:`start_program_run` (or the
        configured one). Informational only — no decision ever reads it."""
        return self._last_policy
