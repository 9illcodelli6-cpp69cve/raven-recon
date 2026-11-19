"""Composition-root bootstrap for the live server (Wave 3, step 2; Wave-P5 live runtime).

Builds the ONE runtime composition root the server holds as ``server.RUNTIME``.
Per RUNTIME_ARCHITECTURE.md §9 step 2 / CANONICAL_ARCHITECTURE §5 step 2, this is
the *behaviour-identical adoption* step: the composition root ADOPTS the server's
already-constructed subsystem singletons and the single ``SCHEDULER`` **by
reference**. Nothing already live is reconstructed, no new *control* DB file is
opened, and no observable behaviour of the existing routes changes — the server's
existing ``_ensure_*`` lazy singletons remain the one instance of each subsystem,
and ``SCHEDULER`` stays the one scheduler (``launch.py`` still imports it directly).
The runtime merely exposes them behind one object so route bodies can delegate to
``RUNTIME.<service>.<method>`` instead of calling module functions.

Everything is resolved lazily off the live ``server`` module, so a subsystem is
constructed only on first use (preserving today's lazy-init timing) and every
accessor reflects runtime rebinds (e.g. a test or a workspace switch replacing
``server.SCHEDULER`` or an ``_ensure_*`` singleton).

Wave-P5 (P5-LIVE-RUNTIME) — the live autonomy layer
---------------------------------------------------
The shim now additionally OWNS a real ``ToolDispatcher`` + ``CapabilityGate``
authority + ``ExecutionStore`` + an ``AgentService`` (one ``AgentExecutor``) and a
``ProgramAgentExecutor``, so the Agent / Program loops are reachable from the live
HTTP routes **through the canonical dispatcher/gate** — never an arbitrary shell,
never a ``_noop``/``not_dispatched``, never a fake completion. These are built by
ADOPTING the server's existing singletons:

* ``tasks``       → ``server._ensure_task_registry()`` (the SAME registry
  ``/api/v7/tasks`` reads — agent tasks and the UI task list share one store).
* ``executions``  → an ``ExecutionStore`` on a dedicated, Row-factory connection to
  the SAME ``tasks_v7.db`` control-DB file (not a new control DB; a distinct table,
  ``v7_executions``, isolated connection so existing task reads are untouched).
* tool handlers   → ``agent.tools_bootstrap.register_all_tools`` (env tools with the
  live terminal ``ProcessExecutor``; knowledge tools bound to the SAME shared
  ``evidence_knowledge_handlers`` the HTTP routes use) + ``program_agent.registry``
  (real program/policy/submission handlers). ``net.http.request`` stays EXPLICITLY
  ``UNAVAILABLE`` (the agent never opens its own sockets).
* capabilities    → ``agent.tools_bootstrap.agent_gate_factory`` seeded with the
  local evidence/knowledge plane grants only (file R/W + scope read). HTTP/process
  grants are never granted by default.

``RavenRuntime`` and ``tests/test_v7_bootstrap.py`` are untouched by this (those
tests never import ``bootstrap``/``server.RUNTIME``), and the whole live substrate is
lazy + cached, so importing ``server`` constructs nothing new until a route first
calls ``RUNTIME.agent`` / ``RUNTIME.program``. Fully collapsing onto a single live
``RavenRuntime`` (AGENT_ARCHITECTURE §4 item 1) remains a later, optional step.
"""
from __future__ import annotations

import threading


class ServerRuntime:
    """The live server composition root — adopts the server's singletons by ref."""

    def __init__(self, server_module):
        self._server = server_module
        self._sender = None
        # ── Wave-P5 live-autonomy lazy singletons (built on first use, cached) ──
        self._live_lock = threading.RLock()
        self._bus = None
        self._tools = None
        self._executions = None
        self._exec_db = None
        self._gate_factory = None
        self._dispatcher = None
        self._know_deps = None
        self._env_deps = None
        self._agent = None
        self._agent_approval = None
        self._program = None
        self._program_approval = None
        self._program_store = None
        self._program_db = None
        self._submission_store = None

    # ── Admission / rate / budget / emergency-stop (the ONE scheduler) ──────────
    @property
    def scheduler(self):
        # Read live so a rebound server.SCHEDULER (tests, future RUNTIME alias) wins.
        return self._server.SCHEDULER

    # ── Egress sender (C-5: the one hardened outbound funnel) ───────────────────
    @property
    def sender(self):
        if self._sender is None:
            from ..runtime.services.sender import SenderService
            self._sender = SenderService()
        return self._sender

    # ── Lazily-adopted subsystem singletons (by reference, via _ensure_*) ───────
    @property
    def terminal(self):
        return self._server._ensure_terminal()

    @property
    def workspaces(self):
        return self._server._ensure_workspace_mgr()

    @property
    def tasks(self):
        return self._server._ensure_task_registry()

    @property
    def plugins(self):
        return self._server._ensure_plugin_registry()

    @property
    def knowledge(self):
        return self._server._ensure_kb()

    @property
    def evidence(self):
        return self._server._ensure_evidence_graph()

    @property
    def ai(self):
        """(ModelService, ConversationContext) — the adopted chat/model singletons."""
        return self._server._ensure_ai()

    # ══════════════════════════════════════════════════════════════════════════
    # Wave-P5 — live autonomy substrate (one dispatcher / gate / executions)
    # ══════════════════════════════════════════════════════════════════════════

    @property
    def bus(self):
        """The one EventBus the dispatcher publishes tool.* events on."""
        if self._bus is None:
            with self._live_lock:
                if self._bus is None:
                    from ..runtime.events import EventBus
                    self._bus = EventBus()
        return self._bus

    @property
    def executions(self):
        """ExecutionStore on a dedicated Row-factory connection to the SAME
        ``tasks_v7.db`` control-DB file (distinct table ``v7_executions``). A second
        connection to the one file — NOT a second control DB — keeps execution reads
        correct (``sqlite3.Row``) without mutating the task registry's connection."""
        if self._executions is None:
            with self._live_lock:
                if self._executions is None:
                    import sqlite3
                    from ..runtime.execution import ExecutionStore
                    db_path = str(self._server.DATA_ROOT / "tasks_v7.db")
                    conn = sqlite3.connect(db_path, check_same_thread=False)
                    conn.row_factory = sqlite3.Row
                    self._exec_db = conn
                    self._executions = ExecutionStore(db=conn)
        return self._executions

    @property
    def capabilities(self):
        """The agent's ``(workspace_id) -> CapabilityGate`` factory.

        Seeded with the local evidence/knowledge plane grants only (file R/W + scope
        read). HTTP/process grants are a separate, explicit researcher action — never
        the default — so a live agent run cannot reach the network/process planes."""
        if self._gate_factory is None:
            with self._live_lock:
                if self._gate_factory is None:
                    from ..agent.tools_bootstrap import agent_gate_factory
                    self._gate_factory = agent_gate_factory()
        return self._gate_factory

    @property
    def programs(self):
        """The live ``ProgramStore`` (programs_v7.db). Local fixtures only; the
        program agent cannot add external targets (external_targets stays 0)."""
        if self._program_store is None:
            with self._live_lock:
                if self._program_store is None:
                    import sqlite3
                    from ..program_agent.program import ProgramStore
                    db_path = str(self._server.DATA_ROOT / "programs_v7.db")
                    conn = sqlite3.connect(db_path, check_same_thread=False)
                    conn.row_factory = sqlite3.Row
                    self._program_db = conn
                    self._program_store = ProgramStore(conn)
        return self._program_store

    @property
    def submissions(self):
        """The live ``SubmissionStore`` (submissions_v7.db) — DRAFT-only writes."""
        if self._submission_store is None:
            with self._live_lock:
                if self._submission_store is None:
                    import sqlite3
                    from ..program_agent.submission import SubmissionStore
                    db_path = str(self._server.DATA_ROOT / "submissions_v7.db")
                    conn = sqlite3.connect(db_path, check_same_thread=False)
                    conn.row_factory = sqlite3.Row
                    self._submission_store = SubmissionStore(conn)
        return self._submission_store

    def _build_tool_deps(self):
        """Build (and cache) the live tool dependencies the real handlers close over.

        * knowledge → the SAME ``KnowledgeBase`` (``_ensure_kb``) the HTTP
          ``/api/v7/knowledge`` route uses, with ``gate=None`` (the dispatcher already
          gates on the descriptor capability — no double-gate). ``actor`` is the
          agent tier (both RAVEN_AGENT and PROGRAM_AGENT map to ``ai_derived`` with
          the confidence cap). ``workspace_id`` is refreshed per run (see
          ``_sync_workspace``).
        * env → the live terminal ``ProcessExecutor`` (shell=False, argv-only, hidden
          window), workspace-jailed ``FilesystemTools``. env.terminal.run is REAL but
          fail-closed SENSITIVE for an un-granted agent; env.wsl/script stay
          EXPLICITLY UNAVAILABLE.
        """
        from ..agent_env.filesystem import FilesystemTools
        from ..agent_env.registry import EnvToolDeps
        from ..api.evidence_knowledge_handlers import HandlerDeps
        from ..runtime.execution import ActorKind

        srv = self._server
        ws_id = srv._ev_know_ws_id()
        if self._know_deps is None:
            self._know_deps = HandlerDeps(
                kb=srv._ensure_kb(), actor=ActorKind.RAVEN_AGENT,
                workspace_id=ws_id, gate=None)
        if self._env_deps is None:
            # The jail root is resolved on EVERY call from the ACTIVE workspace (a
            # workspace switch moves it), with no DATA_ROOT / temp-dir fallback: with no
            # workspace open, filesystem tools refuse.
            fs = FilesystemTools(srv._active_workspace_cwd)
            self._env_deps = EnvToolDeps(
                fs=fs, process_executor=srv._ensure_process_executor(),
                actor=ActorKind.RAVEN_AGENT, workspace_id=ws_id)
        return self._know_deps, self._env_deps

    @property
    def tools(self):
        """The one ToolRegistry the agent + program dispatch through.

        Populated once via ``register_all_tools`` (env/knowledge/evidence — all REAL
        handlers or EXPLICITLY unavailable, never ``_noop``) + the real program-agent
        handlers. ``net.http.request`` stays UNAVAILABLE."""
        if self._tools is None:
            with self._live_lock:
                if self._tools is None:
                    from ..runtime.tools import ToolRegistry
                    from ..agent.tools_bootstrap import AgentToolDeps, register_all_tools
                    from ..program_agent.registry import (
                        ProgramToolDeps, register_program_tools)
                    from ..runtime.execution import ActorKind
                    reg = ToolRegistry()
                    know_deps, env_deps = self._build_tool_deps()
                    register_all_tools(
                        reg, AgentToolDeps(env=env_deps, knowledge=know_deps))
                    # Real program-agent handlers (scope check / program & submission
                    # lists / DRAFT submission create). Resolve policy from the live
                    # ProgramStore so program.policy.check reflects a loaded program.
                    register_program_tools(reg, ProgramToolDeps(
                        program_store=self.programs,
                        submission_store=self.submissions,
                        workspace_id=self._server._ev_know_ws_id,  # resolved per call
                        actor=ActorKind.PROGRAM_AGENT))
                    self._tools = reg
        return self._tools

    @property
    def dispatcher(self):
        """The one ToolDispatcher — the SAME class the ~60 bootstrap tests exercise —
        wired to the one registry / gate factory / execution store / event bus."""
        if self._dispatcher is None:
            with self._live_lock:
                if self._dispatcher is None:
                    from ..runtime.tools import ToolDispatcher
                    self._dispatcher = ToolDispatcher(
                        registry=self.tools,
                        capability_gate_factory=self.capabilities,
                        execution_store=self.executions,
                        event_bus=self.bus)
        return self._dispatcher

    def _sync_workspace(self):
        """Refresh the per-run workspace id on the cached tool deps so an agent write
        lands in the currently-active workspace (boundary-resolved, never from the
        request body)."""
        try:
            ws_id = self._server._ev_know_ws_id()
            if self._know_deps is not None:
                self._know_deps.workspace_id = ws_id
            if self._env_deps is not None:
                self._env_deps.workspace_id = ws_id
        except Exception:
            pass

    @property
    def agent(self):
        """The one AgentService façade — the ONLY live agent entry point."""
        if self._agent is None:
            with self._live_lock:
                if self._agent is None:
                    from ..agent.executor import (
                        AgentExecutor, AgentService, InMemoryApprovalSink)
                    from ..agent.proposal_bridge import ProposalBinder
                    from ..runtime.execution import ActorKind
                    sink = InMemoryApprovalSink()
                    executor = AgentExecutor(
                        dispatcher=self.dispatcher,
                        tasks=self.tasks,
                        executions=self.executions,
                        event_bus=self.bus,
                        binder=ProposalBinder(self.tools),
                        approval=sink,
                        actor=ActorKind.RAVEN_AGENT)
                    self._agent_approval = sink
                    self._agent = AgentService(executor, approval=sink)
        self._sync_workspace()
        return self._agent

    @property
    def program(self):
        """The one ProgramAgentExecutor — Program Mode as a stricter configuration of
        the one AgentExecutor (no shell row, ProgramPolicy-required, PROGRAM_AGENT
        provenance), sharing the one dispatcher/registry/executions."""
        if self._program is None:
            with self._live_lock:
                if self._program is None:
                    from ..agent.executor import InMemoryApprovalSink
                    from ..program_agent.executor import ProgramAgentExecutor
                    sink = InMemoryApprovalSink()
                    self._program_approval = sink
                    self._program = ProgramAgentExecutor(
                        dispatcher=self.dispatcher,
                        tasks=self.tasks,
                        registry=self.tools,
                        executions=self.executions,
                        event_bus=self.bus,
                        program_store=self.programs,
                        approval=sink)
        self._sync_workspace()
        return self._program

    def _reset_live_cache_for_test(self):
        """TEST-ONLY: drop the cached live-autonomy singletons so a test that swaps the
        data root / subsystem singletons gets a fresh dispatcher/agent/program bound to
        the new fixtures. Never called on the live path."""
        with self._live_lock:
            for conn in (self._exec_db, self._program_db,
                         getattr(self._submission_store, "_db", None)):
                try:
                    if conn is not None:
                        conn.close()
                except Exception:
                    pass
            self._bus = None
            self._tools = None
            self._executions = None
            self._exec_db = None
            self._gate_factory = None
            self._dispatcher = None
            self._know_deps = None
            self._env_deps = None
            self._agent = None
            self._agent_approval = None
            self._program = None
            self._program_approval = None
            self._program_store = None
            self._program_db = None
            self._submission_store = None

    # ── Lifecycle ───────────────────────────────────────────────────────────────
    def shutdown(self, wait=True):
        """Refuse new outbound work before the HTTP server stops (launch.py order)."""
        try:
            self._server.shutdown_background_work(wait=wait)
        except Exception:
            pass


def build_runtime(server_module):
    """Build THE one composition root, adopting the server's singletons by reference."""
    return ServerRuntime(server_module)
