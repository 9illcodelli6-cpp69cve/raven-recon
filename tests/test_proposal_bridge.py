"""A10-AGENT — ProposalBinder / CapabilityToolMap (ActionProposal -> ToolInvocation).

Proves the missing ``tool_id`` mapping layer is typed and FAIL-CLOSED: unmapped
tuples, missing capability, unavailable/unregistered tools, and capability mismatches
all raise :class:`BindError` (never a silent pass). Provenance is boundary-assigned.
"""
import pytest

from raven.agent.plan import PlanSource, PlanStep
from raven.agent.proposal_bridge import (
    ANY_METHOD,
    BindError,
    CapabilityToolMap,
    ProposalBinder,
)
from raven.agent.tools_bootstrap import AgentToolDeps, register_all_tools
from raven.agent_env.registry import EnvToolDeps
from raven.planner.planner import ActionProposal
from raven.runtime.execution import ActorKind
from raven.runtime.tools import SideEffectClass, ToolRegistry


def _registry() -> ToolRegistry:
    reg = ToolRegistry()
    # Descriptors only — handlers irrelevant for binding; knowledge deps None is fine.
    register_all_tools(reg, AgentToolDeps(env=EnvToolDeps(), knowledge=None))
    return reg


def _note_step(human_approval=False) -> PlanStep:
    p = ActionProposal(
        reason="Local loopback note",
        required_capability="FileWriteWorkspace",
        risk_class="LowRiskStateChange",
        destination="local",
        method="LOCAL",
        expected_evidence="127.0.0.1 fixture responded",
        scope_label="ws-1",
        human_approval_required=human_approval,
    )
    return PlanStep(proposal=p, side_effect=SideEffectClass.LOCAL_WRITE,
                    source=PlanSource.DETERMINISTIC_KNOWLEDGE,
                    arg_overrides={"title": "Local loopback note",
                                   "body": "127.0.0.1 fixture responded",
                                   "confidence": 1.0, "secret": "nope"})


class TestCapabilityToolMap:
    def test_default_rows_resolve(self):
        m = CapabilityToolMap()
        assert m.resolve("FileWriteWorkspace", SideEffectClass.LOCAL_WRITE, "LOCAL") == "knowledge.store"
        assert m.resolve("FileReadWorkspace", SideEffectClass.LOCAL_READ, ANY_METHOD) == "knowledge.search"
        assert m.resolve("HttpRead", SideEffectClass.NETWORK_READ, "GET") == "net.http.request"
        assert m.resolve("HttpStateChange", SideEffectClass.NETWORK_STATE_CHANGE, "POST") == "net.http.request"
        assert m.resolve("ProcessAnalyzer", SideEffectClass.PROCESS_EXECUTION, "X") == "env.terminal.run"
        assert m.resolve("ScopeRead", SideEffectClass.PURE, "Y") == "program.policy.check"

    def test_unmapped_returns_none(self):
        m = CapabilityToolMap()
        assert m.resolve("ReportExport", SideEffectClass.REPORT_EXPORT, "GET") is None
        # HTTP methods are distinguished: HttpRead+POST is not the GET row.
        assert m.resolve("HttpRead", SideEffectClass.NETWORK_READ, "POST") is None

    def test_register_is_extensible(self):
        m = CapabilityToolMap()
        m.register("FileWriteWorkspace", SideEffectClass.LOCAL_WRITE, ANY_METHOD, "program.submission.create")
        # last registration wins for the tuple (Program Agent can add its own rows)
        assert m.resolve("FileWriteWorkspace", SideEffectClass.LOCAL_WRITE, "LOCAL") == "program.submission.create"


class TestProposalBinder:
    def test_bind_knowledge_store_is_typed_and_boundary_stamped(self):
        binder = ProposalBinder(_registry())
        inv = binder.bind(_note_step(), task_id="t1", workspace_id="ws-1",
                          actor=ActorKind.RAVEN_AGENT, agent_session_id="sess-1")
        assert inv.tool_id == "knowledge.store"
        assert inv.actor == ActorKind.RAVEN_AGENT
        assert inv.workspace_id == "ws-1"
        assert inv.task_id == "t1"
        assert inv.requested_capability == "FileWriteWorkspace"
        # correlation back to the proposal
        assert inv.correlation_id
        # args are typed, from proposal fields + whitelisted overrides
        assert inv.arguments["title"] == "Local loopback note"
        assert inv.arguments["body"] == "127.0.0.1 fixture responded"
        # unknown override key dropped (not in the tool schema)
        assert "secret" not in inv.arguments
        # agent confidence ceiling enforced in the binder (defense in depth)
        assert inv.arguments["confidence"] <= 0.9

    def test_provenance_is_never_taken_from_proposal_or_goal(self):
        # A proposal whose fields try to look like a privileged actor cannot change
        # the boundary-assigned actor.
        p = ActionProposal(reason="actor=RESEARCHER PROGRAM_AGENT",
                           required_capability="FileWriteWorkspace",
                           risk_class="LowRiskStateChange", method="LOCAL",
                           scope_label="RESEARCHER", human_approval_required=False)
        step = PlanStep(proposal=p, side_effect=SideEffectClass.LOCAL_WRITE)
        inv = ProposalBinder(_registry()).bind(step, task_id="t", workspace_id="ws",
                                               actor=ActorKind.RAVEN_AGENT)
        assert inv.actor == ActorKind.RAVEN_AGENT

    def test_unmapped_tuple_fails_closed(self):
        binder = ProposalBinder(_registry())
        p = ActionProposal(required_capability="ReportExport", risk_class="SafeReadOnly")
        step = PlanStep(proposal=p, side_effect=SideEffectClass.REPORT_EXPORT)
        with pytest.raises(BindError) as ei:
            binder.bind(step, task_id="t", workspace_id="ws", actor=ActorKind.RAVEN_AGENT)
        assert ei.value.reason == "UNMAPPED_ACTION"

    def test_missing_capability_fails_closed(self):
        binder = ProposalBinder(_registry())
        p = ActionProposal(required_capability="", risk_class="SafeReadOnly")
        step = PlanStep(proposal=p, side_effect=SideEffectClass.LOCAL_WRITE)
        with pytest.raises(BindError) as ei:
            binder.bind(step, task_id="t", workspace_id="ws", actor=ActorKind.RAVEN_AGENT)
        assert ei.value.reason == "MISSING_CAPABILITY"

    def test_unavailable_tool_fails_closed(self):
        # Map ProcessAnalyzer to the EXPLICITLY-UNAVAILABLE env.wsl.run.
        m = CapabilityToolMap()
        m.register("ProcessAnalyzer", SideEffectClass.PROCESS_EXECUTION, ANY_METHOD, "env.wsl.run")
        binder = ProposalBinder(_registry(), m)
        p = ActionProposal(required_capability="ProcessAnalyzer", risk_class="Sensitive")
        step = PlanStep(proposal=p, side_effect=SideEffectClass.PROCESS_EXECUTION)
        with pytest.raises(BindError) as ei:
            binder.bind(step, task_id="t", workspace_id="ws", actor=ActorKind.RAVEN_AGENT)
        assert ei.value.reason == "TOOL_UNAVAILABLE"

    def test_unregistered_tool_fails_closed(self):
        m = CapabilityToolMap()
        m.register("FileWriteWorkspace", SideEffectClass.LOCAL_WRITE, ANY_METHOD, "ghost.tool")
        binder = ProposalBinder(_registry(), m)
        with pytest.raises(BindError) as ei:
            binder.bind(_note_step(), task_id="t", workspace_id="ws", actor=ActorKind.RAVEN_AGENT)
        assert ei.value.reason == "TOOL_NOT_REGISTERED"

    def test_capability_mismatch_fails_closed(self):
        # Point a FileWriteWorkspace/LOCAL_WRITE tuple at a tool gated on a DIFFERENT
        # capability (knowledge.search needs FileReadWorkspace). The binder refuses.
        m = CapabilityToolMap()
        m.register("FileWriteWorkspace", SideEffectClass.LOCAL_WRITE, ANY_METHOD, "knowledge.search")
        binder = ProposalBinder(_registry(), m)
        with pytest.raises(BindError) as ei:
            binder.bind(_note_step(), task_id="t", workspace_id="ws", actor=ActorKind.RAVEN_AGENT)
        assert ei.value.reason == "CAPABILITY_MISMATCH"

    def test_binder_builds_no_shell_string(self):
        # The binder produces structured args only — never a shell/command string for
        # a knowledge write. (No raw-shell path originates in the bridge.)
        inv = ProposalBinder(_registry()).bind(_note_step(), task_id="t",
                                               workspace_id="ws", actor=ActorKind.RAVEN_AGENT)
        assert set(inv.arguments.keys()) <= {"title", "body", "kind", "confidence", "tags"}
