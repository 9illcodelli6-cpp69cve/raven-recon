"""RAVEN deterministic agent execution loop (Wave 10, A10-AGENT).

The genuinely-missing pieces, built on the EXISTING substrate (one dispatcher, one
CapabilityGate, durable TaskRegistry/ExecutionStore, EventBus). No parallel loop, no
private path around the dispatcher/gate, no generative model on by default.

Public surface:
  - AgentExecutor / AgentService   — the loop + the single server façade
  - ApprovalSink / InMemoryApprovalSink / ApprovalRequest
  - ProposalBinder / CapabilityToolMap / BindError  — ActionProposal -> ToolInvocation
  - PlannerBackend / DeterministicPlanner / ManualPlanner / ModelPlannerAdapter
  - PlanRequest / PlanIntent / PlannerUnavailable
  - Plan / PlanStep / PlanSource
  - tools_bootstrap.register_all_tools / agent_gate_factory / AgentToolDeps
"""
from __future__ import annotations

from .executor import (
    AgentError,
    AgentExecutor,
    AgentService,
    ApprovalRequest,
    ApprovalSink,
    InMemoryApprovalSink,
)
from .plan import Plan, PlanSource, PlanStep
from .planner_backend import (
    DeterministicPlanner,
    ManualPlanner,
    ModelPlannerAdapter,
    PlanIntent,
    PlanRequest,
    PlannerBackend,
    PlannerUnavailable,
)
from .proposal_bridge import BindError, CapabilityToolMap, ProposalBinder

__all__ = [
    "AgentError",
    "AgentExecutor",
    "AgentService",
    "ApprovalRequest",
    "ApprovalSink",
    "InMemoryApprovalSink",
    "Plan",
    "PlanSource",
    "PlanStep",
    "DeterministicPlanner",
    "ManualPlanner",
    "ModelPlannerAdapter",
    "PlanIntent",
    "PlanRequest",
    "PlannerBackend",
    "PlannerUnavailable",
    "BindError",
    "CapabilityToolMap",
    "ProposalBinder",
]
