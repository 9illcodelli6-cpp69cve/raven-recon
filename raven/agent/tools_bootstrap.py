"""RAVEN Agent — real tool-handler bootstrap (Wave 10, A10-AGENT).

``register_all_tools`` builds the live ``ToolRegistry`` the agent dispatches
through, binding each descriptor to a REAL handler on a live subsystem (or marking
it EXPLICITLY ``UNAVAILABLE``) — so the agent dispatches real tools, never the dead
``_noop`` returning ``{"status":"not_dispatched"}`` (CANONICAL §1 row 19, §6).

What it wires:

* **env tools** via ``agent_env.registry.register_env_tools`` with real deps
  (workspace-jailed filesystem; ``env.terminal.run`` routed through the canonical
  ``ProcessExecutor``; ``env.wsl.run`` / ``env.script.run`` EXPLICITLY UNAVAILABLE).
* **knowledge tools** via ``knowledge_os.registry.register_knowledge_tools`` bound to
  the shared ``evidence_knowledge_handlers`` — the same handlers the HTTP routes use.
* It annotates the dispatcher-visible ``risk_class`` on the local evidence/knowledge
  descriptors (the subsystem registrar omitted it). This correctly classifies these
  LOCAL read/write tools as ``SafeReadOnly`` / ``LowRiskStateChange`` so the
  fail-closed gate maps them properly instead of defaulting them to ``SENSITIVE``.
  It is additive metadata on a freshly-built registry — it weakens no gate.
* **recon.collect** (optional) via ``recon.tools.register_recon_tools`` when a
  ``ReconService`` is supplied.

``net.http.request`` is registered EXPLICITLY ``UNAVAILABLE`` here: the live,
scheduler-admitted sender is wired by INT-SERVER once ``RavenRuntime`` is the
composition root (see INTEGRATION REQUIREMENTS). The agent never opens its own
sockets and never gets a fake HTTP success.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from raven.runtime.capabilities import CapabilityGate
from raven.runtime.execution import ActorKind
from raven.runtime.tools import SideEffectClass, ToolDescriptor, ToolRegistry
from raven.security.policy_gate import Capability

# Dispatcher-visible risk_class for the local evidence/knowledge plane (the subsystem
# registrar does not set it; without it the fail-closed gate maps None -> SENSITIVE).
_LOCAL_RISK = {
    "knowledge.search":            "SafeReadOnly",
    "knowledge.store":             "LowRiskStateChange",
    "knowledge.technique.search":  "SafeReadOnly",
    "knowledge.lesson.synthesize": "LowRiskStateChange",
    "evidence.node.list":          "SafeReadOnly",
    "evidence.edge.list":          "SafeReadOnly",
    "evidence.note.add":           "LowRiskStateChange",
}

# Capabilities the local evidence/knowledge agent plane needs (local file R/W only;
# no network). The HTTP/process grants are a separate, researcher-authorised action.
LOCAL_PLANE_GRANTS = frozenset({
    Capability.FILE_READ_WORKSPACE,
    Capability.FILE_WRITE_WORKSPACE,
    Capability.SCOPE_READ,
})


@dataclass
class AgentToolDeps:
    """Live dependencies the real handlers close over."""
    env: object = None               # agent_env.registry.EnvToolDeps (or None -> unavailable)
    knowledge: object = None         # evidence_knowledge_handlers.HandlerDeps (or None)
    recon_service: object = None     # recon.service.ReconService (or None -> not registered)


def annotate_local_risk(registry: ToolRegistry) -> None:
    """Stamp the dispatcher-visible risk_class on local-plane descriptors that the
    subsystem registrar left unset. Additive; mutates only this registry's freshly
    constructed descriptors."""
    for tool_id, risk in _LOCAL_RISK.items():
        desc = registry.get(tool_id)
        if desc is not None:
            desc.metadata.setdefault("risk_class", risk)


def register_all_tools(registry: ToolRegistry, deps: Optional[AgentToolDeps] = None) -> int:
    """Register every real agent-usable tool into ``registry``. Returns the count."""
    deps = deps or AgentToolDeps()
    count = 0

    # env tools (terminal via ProcessExecutor; fs jailed; wsl/script UNAVAILABLE)
    from raven.agent_env.registry import register_env_tools
    count += register_env_tools(registry, deps=deps.env)

    # knowledge tools bound to the shared handlers (one impl, two entry points)
    from raven.knowledge_os.registry import register_knowledge_tools
    count += register_knowledge_tools(registry, deps=deps.knowledge)

    # evidence tools (optional; present only if the canonical registry module exists)
    try:
        from raven.evidence_os.canonical_registry import register_evidence_tools
        count += register_evidence_tools(registry, deps=deps.knowledge)
    except Exception:
        pass

    annotate_local_risk(registry)

    # net.http.request — EXPLICITLY UNAVAILABLE until INT-SERVER wires the live sender.
    registry.register(
        ToolDescriptor(
            tool_id="net.http.request",
            name="HTTP Request",
            description=("Scheduler-admitted, scope-checked, IP-pinned HTTP request. "
                         "Live sender wiring is an INT-SERVER integration requirement."),
            required_capability="HttpRead",
            side_effect_class=SideEffectClass.NETWORK_READ,
            input_schema={"type": "object", "required": ["destination"],
                          "properties": {"destination": {"type": "string"},
                                         "method": {"type": "string"}}},
            execution_profile="NETWORK",
            availability="UNAVAILABLE",
            metadata={"risk_class": "LowRiskStateChange",
                      "unavailable_reason": "live sender not wired (INT-SERVER)"},
        ),
        _unavailable_handler("net.http.request not wired to the live sender yet"),
    )
    count += 1

    # recon.collect (optional, real) — only when a service is provided.
    if deps.recon_service is not None:
        from raven.recon.tools import register_recon_tools
        count += register_recon_tools(registry, service=deps.recon_service)

    return count


def _unavailable_handler(reason: str):
    def _h(args: dict) -> dict:
        return {"status": "unavailable", "reason": reason}
    return _h


# ── gate factory for the agent ────────────────────────────────────────────────

def agent_gate_factory(granted_capabilities=None, allowed_scope_hosts=None):
    """Return a ``(workspace_id) -> CapabilityGate`` factory for the agent.

    Grants default to the local evidence/knowledge plane (file R/W + scope read). The
    caller supplies HTTP/process grants explicitly (an auditable researcher action) —
    over-granting is never the default."""
    # None => default local-plane grants; an explicit (possibly empty) set is honoured
    # verbatim so a caller can deliberately build a zero-grant (deny-all) gate.
    grants = set(LOCAL_PLANE_GRANTS) if granted_capabilities is None else set(granted_capabilities)
    hosts = set(allowed_scope_hosts or set())

    def _factory(workspace_id: str) -> CapabilityGate:
        return CapabilityGate(
            workspace_id=workspace_id or "",
            granted_capabilities=grants,
            allowed_scope_hosts=hosts,
        )

    return _factory
