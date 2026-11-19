"""Regression tests for the runtime / agent bug-hunt findings #6, #7, #9-#15.

Each test class names the finding it pins. Everything runs on in-memory fixtures or
temp directories: no network, no app server, and (except the install.sh test, which
runs bash against a temp HOME/XDG_DATA_HOME) no real child processes.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

import pytest

from raven.agent.executor import AgentExecutor, AgentService, InMemoryApprovalSink
from raven.agent.plan import PlanSource, PlanStep
from raven.agent.planner_backend import ManualPlanner, PlanIntent, PlanRequest
from raven.agent.proposal_bridge import ProposalBinder
from raven.agent.tools_bootstrap import (
    AgentToolDeps,
    agent_gate_factory,
    register_all_tools,
)
from raven.agent_env.filesystem import FilesystemTools
from raven.agent_env.registry import EnvToolDeps, register_env_tools
from raven.planner.planner import ActionProposal
from raven.runtime.capabilities import CapabilityGate
from raven.runtime.execution import ActorKind, ToolStatus
from raven.runtime.tasks import TaskRegistry, TaskStatus
from raven.runtime.tools import (
    SideEffectClass,
    ToolDescriptor,
    ToolDispatcher,
    ToolInvocation,
    ToolRegistry,
    classify_handler_output,
)
from raven.security.policy_gate import Capability, PolicyGate, RiskClass

REPO = Path(__file__).resolve().parent.parent


# ── shared fixtures ──────────────────────────────────────────────────────────────

def _tasks():
    return TaskRegistry(sqlite3.connect(":memory:", check_same_thread=False))


def _note_registry(handler):
    reg = ToolRegistry()
    reg.register(ToolDescriptor(
        tool_id="knowledge.store", name="ks", description="",
        required_capability="FileWriteWorkspace",
        side_effect_class=SideEffectClass.LOCAL_WRITE,
        metadata={"risk_class": "LowRiskStateChange"}), handler)
    return reg


def _note_step(title, *, approval=False):
    p = ActionProposal(reason=title, required_capability="FileWriteWorkspace",
                       risk_class="LowRiskStateChange", destination="local",
                       method="LOCAL", human_approval_required=approval)
    return PlanStep(proposal=p, side_effect=SideEffectClass.LOCAL_WRITE,
                    source=PlanSource.MANUAL, arg_overrides={"title": title, "body": "b"})


def _manual(steps):
    return PlanRequest(intent=PlanIntent.MANUAL, manual_steps=list(steps))


class _SpyExecutor:
    """Stands in for ProcessExecutor: records the spec, spawns nothing."""

    def __init__(self, status=ToolStatus.SUCCESS):
        self.calls = []
        self._status = status

    def execute(self, spec):
        from raven.runtime.process_executor import ProcessResult
        self.calls.append(spec)
        return ProcessResult(execution_id="spy", argv=list(spec.argv),
                             return_code=0, status=self._status)


def _all_caps_gate(ws):
    return CapabilityGate(ws, set(Capability))


# ── #6 approval is per (task_id, step_id) and single-use ─────────────────────────

class TestFinding6ApprovalPerStep:
    def _service(self, planner=None):
        calls = []
        reg = _note_registry(lambda a: calls.append(a.get("title")) or {"status": "stored"})
        sink = InMemoryApprovalSink()
        ex = AgentExecutor(dispatcher=ToolDispatcher(reg, agent_gate_factory()),
                           tasks=_tasks(), binder=ProposalBinder(reg), approval=sink,
                           planner_backend=planner)
        return AgentService(ex, approval=sink), sink, calls

    def test_one_approval_dispatches_only_the_pending_step(self):
        svc, sink, calls = self._service()
        t = svc.start_run("x", workspace_id="ws1", plan_request=_manual(
            [_note_step("step-1", approval=True), _note_step("step-2", approval=True),
             _note_step("step-3", approval=True)]))
        assert t.status == TaskStatus.WAITING and calls == []
        first_pending = sink.pending(t.task_id).step_id

        t = svc.approve_step(t.task_id)
        assert calls == ["step-1"]                    # was: step-1, step-2, step-3
        assert t.status == TaskStatus.WAITING
        assert sink.pending(t.task_id).step_id != first_pending

        t = svc.approve_step(t.task_id)
        assert calls == ["step-1", "step-2"] and t.status == TaskStatus.WAITING
        t = svc.approve_step(t.task_id)
        assert calls == ["step-1", "step-2", "step-3"]
        assert t.status == TaskStatus.COMPLETED

    def test_step_appended_by_next_step_needs_its_own_approval(self):
        class _Extending(ManualPlanner):
            def __init__(self):
                super().__init__([_note_step("planned", approval=True)])
                self.extended = False

            def next_step(self, context, observations):
                if self.extended:
                    return None
                self.extended = True
                return _note_step("appended", approval=True)

        svc, _sink, calls = self._service(planner=_Extending())
        t = svc.start_run("x", workspace_id="ws1")
        t = svc.approve_step(t.task_id)
        assert calls == ["planned"]
        assert t.status == TaskStatus.WAITING          # appended step waits

    def test_no_pre_approval_and_stale_step_id_ignored(self):
        sink = InMemoryApprovalSink()
        assert sink.approve("task-x") is False          # nothing pending -> no-op
        assert sink.decision("task-x", "any") is None

        svc, sink, calls = self._service()
        t = svc.start_run("x", workspace_id="ws1", plan_request=_manual(
            [_note_step("a", approval=True)]))
        assert sink.approve(t.task_id, "not-the-pending-step") is False
        assert svc._executor.resume(t.task_id).status == TaskStatus.WAITING
        assert calls == []
        step_id = sink.pending(t.task_id).step_id
        t = svc.approve_step(t.task_id, step_id)
        assert t.status == TaskStatus.COMPLETED and calls == ["a"]

    def test_decision_is_consumed(self):
        sink = InMemoryApprovalSink()
        from raven.agent.executor import ApprovalRequest
        sink.request(ApprovalRequest("t", "s1", "cap", "r", "cap"))
        assert sink.approve("t") is True
        assert sink.decision("t", "s2") is None        # other step: never approved
        assert sink.decision("t", "s1") is True
        assert sink.decision("t", "s1") is None        # single use


# ── #7 env.fs.delete cannot take out the jail ────────────────────────────────────

class TestFinding7FsDelete:
    def _ws(self, tmp_path):
        root = tmp_path / "workspaces" / "example"
        root.mkdir(parents=True)
        (root / "recon.db").write_text("irreplaceable")
        (root / "scope.json").write_text("{}")
        return root

    @pytest.mark.parametrize("path", [".", "", "./", "sub/..", "sub/../.", None])
    def test_root_is_never_deleted(self, tmp_path, path):
        root = self._ws(tmp_path)
        (root / "sub").mkdir()
        fs = FilesystemTools(str(root))
        r = fs.remove(path, recursive=True)
        assert not r.deleted and r.refused
        assert fs.delete(path, recursive=True) is False
        assert (root / "recon.db").exists()

    def test_absolute_root_path_refused(self, tmp_path):
        root = self._ws(tmp_path)
        fs = FilesystemTools(str(root))
        assert fs.remove(str(root), recursive=True).refused
        assert fs.remove(str(root.parent), recursive=True).refused
        assert (root / "recon.db").exists()

    def test_directory_needs_explicit_recursive(self, tmp_path):
        root = self._ws(tmp_path)
        (root / "d").mkdir()
        (root / "d" / "f").write_text("x")
        fs = FilesystemTools(str(root))
        r = fs.remove("d")
        assert r.refused and (root / "d" / "f").exists()
        assert fs.remove("d", recursive=True).deleted
        assert not (root / "d").exists()

    def test_symlink_removed_as_link_not_followed(self, tmp_path):
        root = self._ws(tmp_path)
        (root / "keep").mkdir()
        (root / "keep" / "data").write_text("x")
        os.symlink(root / "keep", root / "link")
        os.symlink(root, root / "rootlink")
        fs = FilesystemTools(str(root))
        assert fs.remove("link", recursive=True).deleted
        assert (root / "keep" / "data").exists()
        assert fs.remove("rootlink", recursive=True).deleted
        assert (root / "recon.db").exists()

    def test_live_default_gate_requires_approval_for_delete(self, tmp_path):
        # The reviewer's t_fsdel.py: dispatched through agent_gate_factory().
        root = self._ws(tmp_path)
        reg = ToolRegistry()
        register_all_tools(reg, AgentToolDeps(env=EnvToolDeps(
            fs=FilesystemTools(str(root)), actor=ActorKind.RAVEN_AGENT)))
        d = ToolDispatcher(reg, agent_gate_factory())
        for p in (".", "", "recon.db"):
            res, rec = d.invoke(ToolInvocation(tool_id="env.fs.delete",
                                               arguments={"path": p}, workspace_id="ws1",
                                               actor=ActorKind.RAVEN_AGENT))
            assert res.status == ToolStatus.DENIED
            assert rec.capability_decision == "REQUIRE_RESEARCHER_APPROVAL"
        assert (root / "recon.db").exists()

    def test_handler_refuses_root_and_agent_recursive_even_if_gate_allows(self, tmp_path):
        root = self._ws(tmp_path)
        (root / "d").mkdir()
        reg = ToolRegistry()
        register_env_tools(reg, EnvToolDeps(fs=FilesystemTools(str(root)),
                                            actor=ActorKind.RAVEN_AGENT))
        reg.get("env.fs.delete").metadata["risk_class"] = "LowRiskStateChange"
        d = ToolDispatcher(reg, agent_gate_factory())

        def call(args):
            return d.invoke(ToolInvocation(tool_id="env.fs.delete", arguments=args,
                                           workspace_id="ws1",
                                           actor=ActorKind.RAVEN_AGENT))[0]

        assert call({"path": "."}).status == ToolStatus.DENIED
        assert call({"path": "", "recursive": True}).status == ToolStatus.DENIED
        assert call({"path": "d", "recursive": True}).status == ToolStatus.DENIED
        assert call({"path": "d"}).status == ToolStatus.DENIED     # dir, not recursive
        assert root.exists() and (root / "d").exists()
        assert call({"path": "scope.json"}).status == ToolStatus.SUCCESS
        assert not (root / "scope.json").exists()

    def test_researcher_or_opted_in_composer_may_delete_recursively(self, tmp_path):
        root = self._ws(tmp_path)
        (root / "d").mkdir()
        reg = ToolRegistry()
        register_env_tools(reg, EnvToolDeps(fs=FilesystemTools(str(root)),
                                            actor=ActorKind.RAVEN_AGENT,
                                            allow_agent_recursive_delete=True))
        out = reg.get_handler("env.fs.delete")({"path": "d", "recursive": True})
        assert out["status"] == "ok" and not (root / "d").exists()
        assert reg.get_handler("env.fs.delete")({"path": ".", "recursive": True})[
            "status"] == "denied"
        assert root.exists()

    def test_jail_follows_active_workspace_and_has_no_fallback(self, tmp_path):
        a = tmp_path / "workspaces" / "a"
        b = tmp_path / "workspaces" / "b"
        a.mkdir(parents=True)
        b.mkdir(parents=True)
        active = {"dir": str(a)}
        fs = FilesystemTools(lambda: active["dir"])
        assert fs.write("note.txt", "A").success
        active["dir"] = str(b)
        assert fs.write("note.txt", "B").success
        assert (a / "note.txt").read_text() == "A"
        assert (b / "note.txt").read_text() == "B"
        assert fs.root == str(b.resolve())

        active["dir"] = None                         # no workspace open
        assert fs.root is None
        assert not fs.write("x.txt", "y").success
        assert not fs.read("note.txt").success
        assert fs.list_dir(".") == []
        assert not fs.remove("note.txt").deleted
        assert not (Path.cwd() / "x.txt").exists()

    def test_resolver_errors_and_filesystem_root_disable_tools(self):
        def boom():
            raise RuntimeError("no state")
        assert FilesystemTools(boom).root is None
        assert FilesystemTools(lambda: "/").root is None
        assert FilesystemTools(lambda: "/definitely/not/here").root is None


# ── #9 cancelling a run stops the loop ───────────────────────────────────────────

class TestFinding9Cancel:
    def test_cancel_during_a_step_stops_remaining_steps(self):
        calls = []
        tasks = _tasks()
        holder = {}

        def handler(args):
            calls.append(args.get("title"))
            if len(calls) == 1:     # a researcher cancels while step s0 is running
                holder["svc"].cancel_run(tasks.list_all()[0].task_id)
            return {"status": "stored"}

        reg = _note_registry(handler)
        svc = AgentService(AgentExecutor(dispatcher=ToolDispatcher(reg, agent_gate_factory()),
                                         tasks=tasks, binder=ProposalBinder(reg)))
        holder["svc"] = svc
        t = svc.start_run("x", workspace_id="ws1",
                          plan_request=_manual([_note_step(f"s{i}") for i in range(5)]))
        assert t.status == TaskStatus.CANCELLED
        assert calls == ["s0"]                       # was: s0..s4 all dispatched

    def test_cancelled_waiting_run_cannot_be_resumed(self):
        reg = _note_registry(lambda a: {"status": "stored"})
        sink = InMemoryApprovalSink()
        svc = AgentService(AgentExecutor(dispatcher=ToolDispatcher(reg, agent_gate_factory()),
                                         tasks=_tasks(), binder=ProposalBinder(reg),
                                         approval=sink), approval=sink)
        t = svc.start_run("x", workspace_id="ws1",
                          plan_request=_manual([_note_step("a", approval=True)]))
        assert svc.cancel_run(t.task_id).status == TaskStatus.CANCELLED
        assert sink.pending(t.task_id) is None       # approval state cleared
        assert svc.approve_step(t.task_id).status == TaskStatus.CANCELLED


# ── #10 handler-reported failures are not SUCCESS; timeout_s honoured ────────────

class TestFinding10Status:
    @pytest.mark.parametrize("output,expected", [
        ({"status": "ok"}, ToolStatus.SUCCESS),
        ({"status": "stored"}, ToolStatus.SUCCESS),
        ({"status": "SUCCESS"}, ToolStatus.SUCCESS),
        ({"status": "PARTIAL"}, ToolStatus.PARTIAL),
        ({"status": "error", "error": "x"}, ToolStatus.FAILED),
        ({"status": "FAILED"}, ToolStatus.FAILED),
        ({"status": "denied"}, ToolStatus.DENIED),
        ({"status": "invalid"}, ToolStatus.INVALID_INPUT),
        ({"status": "unavailable"}, ToolStatus.UNAVAILABLE),
        ({"status": "TIMED_OUT"}, ToolStatus.TIMED_OUT),
        ({"status": "CANCELLED"}, ToolStatus.CANCELLED),
        ({"status": "no_program_policy"}, ToolStatus.DENIED),
        ({"ok": False}, ToolStatus.FAILED),
        ({"error": "boom"}, ToolStatus.FAILED),
        ({"ok": True, "error": None}, ToolStatus.SUCCESS),
        ({"status": "queued"}, ToolStatus.SUCCESS),   # domain label, not a failure
        ({}, ToolStatus.SUCCESS),
        ("text", ToolStatus.SUCCESS),
        (None, ToolStatus.SUCCESS),
    ])
    def test_classify(self, output, expected):
        assert classify_handler_output(output) == expected

    def _env_dispatcher(self, tmp_path, pexec=None):
        reg = ToolRegistry()
        register_env_tools(reg, EnvToolDeps(fs=FilesystemTools(str(tmp_path)),
                                            process_executor=pexec or _SpyExecutor()))
        reg.get("env.terminal.run").metadata["risk_class"] = "LowRiskStateChange"
        return ToolDispatcher(reg, _all_caps_gate), reg

    def _invoke(self, d, tool_id, args):
        return d.invoke(ToolInvocation(tool_id=tool_id, arguments=args,
                                       workspace_id="ws", actor=ActorKind.RAVEN_AGENT))

    def test_fs_traversal_is_failed_not_success(self, tmp_path):
        d, _ = self._env_dispatcher(tmp_path)
        res, rec = self._invoke(d, "env.fs.read", {"path": "../../etc/passwd"})
        assert res.status == ToolStatus.FAILED
        assert rec.status == ToolStatus.FAILED.value
        assert "blocked" in (res.error or "").lower()

    def test_metachar_terminal_is_denied_and_task_blocked(self, tmp_path):
        spy = _SpyExecutor()
        d, reg = self._env_dispatcher(tmp_path, spy)
        res, rec = self._invoke(d, "env.terminal.run", {"command": "id; whoami"})
        assert res.status == ToolStatus.DENIED and rec.status == ToolStatus.DENIED.value
        assert spy.calls == []

        p = ActionProposal(reason="t", required_capability="ProcessAnalyzer",
                           risk_class="LowRiskStateChange", method="EXEC",
                           human_approval_required=False)
        step = PlanStep(proposal=p, side_effect=SideEffectClass.PROCESS_EXECUTION,
                        source=PlanSource.MANUAL, arg_overrides={"command": "id; whoami"})
        ex = AgentExecutor(dispatcher=d, tasks=_tasks(), binder=ProposalBinder(reg))
        task = ex.run("t", workspace_id="ws", plan_request=_manual([step]))
        assert task.status == TaskStatus.BLOCKED       # was: COMPLETED

    def test_timed_out_process_is_timed_out(self, tmp_path):
        d, _ = self._env_dispatcher(tmp_path, _SpyExecutor(status=ToolStatus.TIMED_OUT))
        res, rec = self._invoke(d, "env.terminal.run", {"command": "sleep 3", "timeout_s": 1})
        assert res.status == ToolStatus.TIMED_OUT and rec.status == "TIMED_OUT"

    def test_timeout_s_is_passed_and_clamped(self, tmp_path):
        spy = _SpyExecutor()
        d, _ = self._env_dispatcher(tmp_path, spy)
        self._invoke(d, "env.terminal.run", {"command": "sleep 3", "timeout_s": 1})
        assert spy.calls[-1].timeout_s == 1.0           # was: ignored (None)
        self._invoke(d, "env.terminal.run", {"command": "sleep 3", "timeout_s": 10_000})
        assert spy.calls[-1].timeout_s <= 60.0
        self._invoke(d, "env.terminal.run", {"command": "sleep 3"})
        assert spy.calls[-1].timeout_s is None          # executor default applies

    @pytest.mark.parametrize("bad", [0, -5, True])
    def test_bad_timeout_is_invalid(self, tmp_path, bad):
        spy = _SpyExecutor()
        d, _ = self._env_dispatcher(tmp_path, spy)
        res, _ = self._invoke(d, "env.terminal.run", {"command": "sleep 1", "timeout_s": bad})
        assert res.status == ToolStatus.INVALID_INPUT and spy.calls == []


# ── #11 ProgramPolicy is resolved per run, per workspace ─────────────────────────

class TestFinding11ProgramPolicyPerRun:
    def _px(self, store, *, net=False, approval=None, hosts=()):
        from raven.program_agent.executor import ProgramAgentExecutor
        reg = _note_registry(lambda a: {"status": "stored"})
        if net:
            reg.register(ToolDescriptor(
                tool_id="net.http.request", name="loopback fixture", description="",
                required_capability="HttpRead", side_effect_class=SideEffectClass.NETWORK_READ,
                input_schema={"type": "object", "required": ["destination"],
                              "properties": {"destination": {"type": "string"},
                                             "method": {"type": "string"}}},
                execution_profile="NETWORK", metadata={"risk_class": "SafeReadOnly"}),
                lambda a: {"status": "ok", "fixture": True})
        gate = agent_gate_factory(
            granted_capabilities={Capability.FILE_WRITE_WORKSPACE, Capability.HTTP_READ,
                                  Capability.FILE_READ_WORKSPACE, Capability.SCOPE_READ},
            allowed_scope_hosts=set(hosts))
        return ProgramAgentExecutor(dispatcher=ToolDispatcher(reg, gate), tasks=_tasks(),
                                    registry=reg, program_store=store, approval=approval)

    def _store(self, programs):
        from raven.program_agent.policy import ProgramPolicy, ProgramScope, ScopeType
        from raven.program_agent.program import BugBountyProgram, ProgramStore
        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.row_factory = sqlite3.Row
        store = ProgramStore(db)
        for pid, ws, host in programs:
            scope = ProgramScope()
            if host:
                scope.add_in_scope(host, ScopeType.IP)
            store.save(BugBountyProgram(program_id=pid, workspace_id=ws, policy=ProgramPolicy(
                program_id=pid, name=pid, scope=scope)))
        return store

    def test_other_workspace_policy_is_not_reused(self):
        from raven.program_agent.executor import NoProgramPolicyError
        px = self._px(self._store([("pA", "wsA", None)]))
        note = PlanRequest(intent=PlanIntent.RECORD_KNOWLEDGE_NOTE, note_title="t",
                           note_body="b")
        assert px.start_program_run("x", workspace_id="wsA",
                                    plan_request=note).status == TaskStatus.COMPLETED
        with pytest.raises(NoProgramPolicyError):          # was: COMPLETED
            px.start_program_run("x", workspace_id="wsB", plan_request=note)

    def test_resumed_run_keeps_its_own_policy(self):
        store = self._store([("pA", "wsA", "127.0.0.1"), ("pB", "wsB", "127.0.0.2")])
        sink = InMemoryApprovalSink()
        px = self._px(store, net=True, approval=sink, hosts={"127.0.0.1", "127.0.0.2"})

        def probe(dest, approval):
            p = ActionProposal(reason="probe", required_capability="HttpRead",
                               risk_class="SafeReadOnly", destination=dest, method="GET",
                               human_approval_required=approval)
            return _manual([PlanStep(proposal=p, side_effect=SideEffectClass.NETWORK_READ,
                                     source=PlanSource.MANUAL)])

        a = px.start_program_run("a", workspace_id="wsA",
                                 plan_request=probe("https://127.0.0.1/", True))
        assert a.status == TaskStatus.WAITING
        b = px.start_program_run("b", workspace_id="wsB",
                                 plan_request=probe("https://127.0.0.1/", False))
        assert b.status == TaskStatus.BLOCKED               # wsB scope: 127.0.0.2 only
        a = px.approve_step(a.task_id)
        assert a.status == TaskStatus.COMPLETED, a.failure  # still wsA's policy

    def test_empty_workspace_never_borrows_a_policy(self):
        from raven.program_agent.executor import NoProgramPolicyError
        px = self._px(self._store([("pA", "wsA", None)]))
        note = PlanRequest(intent=PlanIntent.RECORD_KNOWLEDGE_NOTE, note_title="t",
                           note_body="b")
        with pytest.raises(NoProgramPolicyError):     # list_active("") spans all ws
            px.start_program_run("x", workspace_id="", plan_request=note)

    def test_policy_check_tool_follows_active_workspace(self):
        from raven.program_agent.registry import ProgramToolDeps, register_program_tools
        store = self._store([("pA", "wsA", "127.0.0.1")])
        active = {"ws": "wsA"}
        reg = ToolRegistry()
        register_program_tools(reg, ProgramToolDeps(program_store=store,
                                                    workspace_id=lambda: active["ws"]))
        check = reg.get_handler("program.policy.check")
        assert check({"target": "https://127.0.0.1/"})["in_scope"] is True
        active["ws"] = "wsB"                          # researcher switched workspace
        assert check({"target": "https://127.0.0.1/"})["status"] == "no_program_policy"
        active["ws"] = None
        assert check({"target": "https://127.0.0.1/"})["status"] == "no_program_policy"


# ── #12 PolicyGate host extraction ───────────────────────────────────────────────

class TestFinding12HostExtraction:
    def _allowed(self, url):
        g = PolicyGate("ws", {Capability.HTTP_READ}, {"target.com"})
        return g.evaluate(Capability.HTTP_READ, url, "GET", "r",
                          RiskClass.SAFE_READ_ONLY).allowed

    @pytest.mark.parametrize("url", [
        "https://target.com:443@evil.com/",
        "http://target.com:x@127.0.0.1:8765/api/emergency-stop",
        "https://user@target.com/",
        "https://user:pw@target.com/",
        "https://target.com\\@evil.com/",
        "https://target.com:notaport/",
        "https://target.com:99999/",
        "https://tar get.com/",
        "ftp://target.com/",
        "https://evil.com/",
    ])
    def test_denied(self, url):
        assert self._allowed(url) is False

    @pytest.mark.parametrize("url", [
        "https://target.com/", "HTTPS://Target.COM:8443/a?b#c", "http://api.target.com",
        "  https://target.com/x  ",
    ])
    def test_allowed(self, url):
        assert self._allowed(url) is True

    def test_real_host_reported(self):
        g = PolicyGate("ws", set(), set())
        assert g._extract_host("https://target.com:443@evil.com/") is None
        assert g._extract_host("https://[::1]:8080/") == "::1"


# ── #13 SQLite read-only URIs survive ? # % in the path ─────────────────────────

class TestFinding13SqliteUri:
    def _db(self, base, name):
        d = base / name
        d.mkdir()
        db = d / "recon.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE workspaces (id TEXT, created_at TEXT)")
        con.execute("INSERT INTO workspaces VALUES ('real-uuid', '1')")
        con.commit()
        con.close()
        return db

    @pytest.mark.parametrize("name", ["R#D", "a?b", "p%41q", "sp ace", "x&y=1;z"])
    def test_read_only_and_correct_path(self, tmp_path, name):
        from raven.runtime.workspace import _read_recon_workspace_id
        from raven.runtime.workspace_migration import integrity_check, table_row_counts
        db = self._db(tmp_path, name)
        before = sorted(str(p) for p in tmp_path.rglob("*"))
        assert _read_recon_workspace_id(db) == "real-uuid"     # was: None
        assert integrity_check(db) == "ok"
        assert table_row_counts(db) == {"workspaces": 1}
        assert sorted(str(p) for p in tmp_path.rglob("*")) == before   # no stray DB

    def test_uri_is_really_read_only(self, tmp_path):
        from raven.runtime.workspace import sqlite_uri
        db = self._db(tmp_path, "R#D")
        con = sqlite3.connect(sqlite_uri(db, "ro"), uri=True)
        try:
            with pytest.raises(sqlite3.OperationalError):
                con.execute("INSERT INTO workspaces VALUES ('x', '2')")
        finally:
            con.close()


# ── #14 agent-tier executable check ──────────────────────────────────────────────

class TestFinding14AgentExecutable:
    def _handler(self, tmp_path, actor=ActorKind.RAVEN_AGENT):
        spy = _SpyExecutor()
        reg = ToolRegistry()
        register_env_tools(reg, EnvToolDeps(fs=FilesystemTools(str(tmp_path)),
                                            process_executor=spy, actor=actor))
        return reg.get_handler("env.terminal.run"), spy

    @pytest.mark.parametrize("command", [
        "bash -c id", "sh -lc id", "setsid sh -c id", "env python3 -c 'import os'",
        "python3 -c 'print(1)'", "perl -e 'print 1'", "timeout 5 dash -c id",
        "./run.sh", "bin/tool", "../../usr/bin/id", "/usr/../bin/id",
        "definitely-not-a-command-xyz",
    ])
    def test_refused_for_agent(self, tmp_path, command):
        h, spy = self._handler(tmp_path)
        out = h({"command": command})
        assert out["status"] == "denied", out
        assert spy.calls == []

    def test_plain_command_runs_in_jail_with_minimal_env(self, tmp_path):
        h, spy = self._handler(tmp_path)
        out = h({"command": "whoami"})
        assert out["status"] == ToolStatus.SUCCESS.value
        spec = spy.calls[0]
        assert spec.argv == ["whoami"]
        assert spec.env_mode == "minimal"
        assert spec.cwd == str(Path(tmp_path).resolve())

    def test_absolute_executable_allowed(self, tmp_path):
        exe = shutil.which("whoami")
        h, _spy = self._handler(tmp_path)
        assert h({"command": exe})["status"] == ToolStatus.SUCCESS.value

    def test_researcher_tier_unchanged(self, tmp_path):
        h, spy = self._handler(tmp_path, actor=ActorKind.RESEARCHER)
        assert h({"command": "bash -c id"})["status"] == ToolStatus.SUCCESS.value
        assert spy.calls[0].env_mode == "scrubbed_inherit" and spy.calls[0].cwd is None


# ── #15 install.sh desktop Exec escaping ─────────────────────────────────────────

def _desktop_exec_argv(value: str):
    """Desktop Entry spec: string unescape, then double-quote rules, then %% -> %."""
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            n = value[i + 1]
            out.append({"s": " ", "n": "\n", "t": "\t", "r": "\r", "\\": "\\"}.get(n, "\\" + n))
            i += 2
        else:
            out.append(c)
            i += 1
    v = "".join(out)
    args, cur, i, inq, have = [], [], 0, False, False
    while i < len(v):
        c = v[i]
        if inq:
            if c == "\\" and i + 1 < len(v) and v[i + 1] in '"`$\\':
                cur.append(v[i + 1])
                i += 2
                continue
            if c == '"':
                inq = False
            else:
                cur.append(c)
            i += 1
            continue
        if c == '"':
            inq, have = True, True
        elif c == " ":
            if cur or have:
                args.append("".join(cur))
            cur, have = [], False
        else:
            cur.append(c)
        i += 1
    if cur or have:
        args.append("".join(cur))
    return [a.replace("%%", "%") for a in args]


@pytest.mark.skipif(os.name != "posix" or shutil.which("bash") is None,
                    reason="install.sh is a POSIX/bash installer")
class TestFinding15DesktopExec:
    @pytest.mark.parametrize("name", [
        'R&D proj "q" $HOME `x` \\back 100% |p',
        "it's a & b",
        "plain",
    ])
    def test_exec_line_round_trips(self, name):
        base = Path(tempfile.mkdtemp(prefix="raven-install-"))
        try:
            proj = base / name
            (proj / "packaging/linux").mkdir(parents=True)
            for f in ("install.sh", "raven-recon.desktop.in", "raven-recon.png"):
                shutil.copy(REPO / "packaging/linux" / f, proj / "packaging/linux" / f)
            (proj / "raven-app").write_text("#!/bin/sh\nexit 0\n")
            os.chmod(proj / "raven-app", 0o755)
            env = dict(os.environ, HOME=str(base / "home"), XDG_DATA_HOME=str(base / "xdg"),
                       RAVEN_DATA_DIR=str(base / "data"))
            r = subprocess.run(["bash", str(proj / "packaging/linux/install.sh")], env=env,
                               check=False, capture_output=True, text=True, timeout=60)
            assert r.returncode == 0, r.stderr
            desktop = base / "xdg/applications/raven-recon.desktop"
            lines = desktop.read_text().splitlines()
            exec_line = next(line for line in lines if line.startswith("Exec="))
            assert _desktop_exec_argv(exec_line[len("Exec="):]) == [str(proj / "raven-app")]
            assert "StartupWMClass=raven-recon" in lines
            assert not any("@EXEC@" in line or "@WMCLASS@" in line for line in lines)
            if shutil.which("desktop-file-validate"):
                v = subprocess.run(["desktop-file-validate", str(desktop)],
                                   check=False, capture_output=True, text=True, timeout=30)
                assert v.returncode == 0, v.stdout + v.stderr
        finally:
            shutil.rmtree(base, ignore_errors=True)
