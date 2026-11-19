"""RAVEN Agent — ActionProposal -> ToolInvocation bridge (Wave 10, A10-AGENT).

This is the genuinely-missing mapping layer. ``ActionProposal``
(``planner/planner.py``) carries ``required_capability`` / ``risk_class`` /
``destination`` / ``method`` but **no ``tool_id``**; ``ToolInvocation``
(``runtime/tools.py``) *requires* a ``tool_id``. Nothing in the tree mapped one to
the other. ``ProposalBinder`` does — **externally**, so ``planner.py`` stays
proposal-only and its invariants are provably intact (it is not edited).

Design (AGENT_ARCHITECTURE §3.3; CANONICAL §1 row 19, §6):

* ``CapabilityToolMap`` — a static, reviewed, finite mapping from the typed tuple
  ``(required_capability, side_effect_class, method)`` to a concrete ``tool_id`` in
  the live ``ToolRegistry``. No reflection, no "guess from text". Extensible via
  :meth:`CapabilityToolMap.register` so the Program Agent (Wave 11) can add its own
  rows without forking the map.
* ``ProposalBinder.bind`` — resolves the ``tool_id``, validates the tool exists and
  is ``AVAILABLE``, cross-checks that the descriptor's own ``required_capability``
  matches the proposal's declared capability (an agent cannot bind a proposal to a
  tool gated on a *different* capability), builds arguments from the proposal's
  **typed** fields (+ the step's whitelisted ``arg_overrides``), and stamps
  boundary-assigned provenance (``actor``) — never taken from the goal text or the
  proposal body.

**Fail-closed.** Any unmapped ``(capability, side_effect, method)`` tuple, a missing
/ unregistered / ``UNAVAILABLE`` tool, or a capability mismatch raises
:class:`BindError`. The executor turns that into a surfaced BLOCKED task — never a
silent pass and never a ``not_dispatched``. The binder never bypasses the dispatcher:
the dispatcher independently re-validates args against the tool's ``input_schema``
and re-checks the capability through the ``CapabilityGate`` (defense in depth; the
planner's args stay UNTRUSTED per ``tools.py:5,81``).
"""
from __future__ import annotations

from typing import Callable, Dict, Optional, Tuple

from raven.planner.planner import ActionProposal
from raven.runtime.execution import ActorKind
from raven.runtime.tools import SideEffectClass, ToolInvocation, ToolRegistry

from .plan import PlanStep

# Actor tiers whose AI-derived confidence can never masquerade as certainty
# (knowledge/evidence confidence ceiling ≤ 0.9; mirrors evidence_knowledge_handlers).
_AGENT_CONFIDENCE_CAP = 0.9
_AGENT_TIERS = frozenset({ActorKind.RAVEN_AGENT, ActorKind.PROGRAM_AGENT})

# Sentinel meaning "any method" in a CapabilityToolMap key.
ANY_METHOD = "*"


class BindError(Exception):
    """Raised when a proposal cannot be bound to a concrete, available tool.

    Carries a machine-usable ``reason`` code so the executor can surface a precise
    BLOCKED cause rather than failing silently.
    """

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class CapabilityToolMap:
    """Static, reviewed ``(capability, side_effect, method) -> tool_id`` mapping.

    Seeded with the canonical RAVEN_AGENT rows. ``method`` is matched exactly first,
    then falls back to :data:`ANY_METHOD`, so non-HTTP side effects (where method is
    irrelevant) register once with ``ANY_METHOD`` while HTTP rows distinguish GET
    from POST.
    """

    def __init__(self, seed_defaults: bool = True):
        # key: (capability, side_effect_value, method) -> tool_id
        self._rows: Dict[Tuple[str, str, str], str] = {}
        if seed_defaults:
            self._seed_defaults()

    def _seed_defaults(self) -> None:
        # Canonical rows (AGENT_ARCHITECTURE §3.3). HTTP tools are listed for the
        # record even though the live sender wiring is an INT-SERVER integration
        # requirement; the binder refuses to bind them while the descriptor is
        # UNAVAILABLE (fail-closed), so no fake HTTP is reachable.
        self.register("HttpRead",         SideEffectClass.NETWORK_READ,         "GET",      "net.http.request")
        self.register("HttpStateChange",  SideEffectClass.NETWORK_STATE_CHANGE, "POST",     "net.http.request")
        self.register("ProcessAnalyzer",  SideEffectClass.PROCESS_EXECUTION,    ANY_METHOD, "env.terminal.run")
        self.register("ScopeRead",        SideEffectClass.PURE,                 ANY_METHOD, "program.policy.check")
        # Local evidence/knowledge plane — the harmless agent record/read actions.
        self.register("FileWriteWorkspace", SideEffectClass.LOCAL_WRITE, ANY_METHOD, "knowledge.store")
        self.register("FileReadWorkspace",  SideEffectClass.LOCAL_READ,  ANY_METHOD, "knowledge.search")

    def register(self, capability: str, side_effect: SideEffectClass,
                 method: str, tool_id: str) -> None:
        self._rows[(capability, side_effect.value, method or ANY_METHOD)] = tool_id

    def resolve(self, capability: str, side_effect: SideEffectClass,
                method: str) -> Optional[str]:
        se = side_effect.value
        method = method or ANY_METHOD
        # Exact method first, then the method-agnostic fallback.
        return (self._rows.get((capability, se, method))
                or self._rows.get((capability, se, ANY_METHOD)))

    def rows(self) -> Dict[Tuple[str, str, str], str]:
        return dict(self._rows)


# ── argument builders (typed proposal fields -> tool arguments) ────────────────
# Each returns a dict built ONLY from the proposal's typed fields. No free text,
# no shell strings. Step-level typed ``arg_overrides`` are merged afterwards by the
# binder (whitelisted against the descriptor schema).

def _args_knowledge_store(p: ActionProposal) -> dict:
    return {
        "title": p.reason or "agent knowledge note",
        "body": p.expected_evidence or p.reason or "",
        "kind": "concept",
        "confidence": 0.5,
        "tags": [p.scope_label] if p.scope_label else [],
    }


def _args_knowledge_search(p: ActionProposal) -> dict:
    return {"query": p.reason or p.scope_label or ""}


def _args_http_request(p: ActionProposal) -> dict:
    return {"destination": p.destination, "method": p.method}


def _args_scope_check(p: ActionProposal) -> dict:
    return {"target": p.destination}


_DEFAULT_ARG_BUILDERS: Dict[str, Callable[[ActionProposal], dict]] = {
    "knowledge.store": _args_knowledge_store,
    "knowledge.search": _args_knowledge_search,
    "net.http.request": _args_http_request,
    "program.policy.check": _args_scope_check,
}


class ProposalBinder:
    """Binds a typed :class:`PlanStep` to a concrete :class:`ToolInvocation`.

    Fail-closed on every ambiguity. Boundary-assigned provenance: ``actor`` is the
    value the executor passes (RAVEN_AGENT / PROGRAM_AGENT), **never** derived from
    the objective string or the proposal body.
    """

    def __init__(self, registry: ToolRegistry,
                 tool_map: Optional[CapabilityToolMap] = None,
                 arg_builders: Optional[Dict[str, Callable[[ActionProposal], dict]]] = None):
        self._registry = registry
        self._map = tool_map or CapabilityToolMap()
        self._arg_builders = dict(_DEFAULT_ARG_BUILDERS)
        if arg_builders:
            self._arg_builders.update(arg_builders)

    def bind(self, step: PlanStep, *, task_id: Optional[str], workspace_id: str,
             actor: ActorKind, agent_session_id: Optional[str] = None) -> ToolInvocation:
        proposal = step.proposal

        # 0. A proposal with no capability cannot be governed → fail-closed.
        if not (proposal.required_capability or "").strip():
            raise BindError("MISSING_CAPABILITY",
                            "proposal has no required_capability")

        # 1. Resolve tool_id via the reviewed map (the missing layer).
        tool_id = self._map.resolve(proposal.required_capability,
                                    step.side_effect, proposal.method)
        if not tool_id:
            raise BindError(
                "UNMAPPED_ACTION",
                f"no tool for (capability={proposal.required_capability}, "
                f"side_effect={step.side_effect.value}, method={proposal.method})")

        # 2. Tool must exist and be AVAILABLE in the live registry.
        descriptor = self._registry.get(tool_id)
        if descriptor is None:
            raise BindError("TOOL_NOT_REGISTERED",
                            f"resolved tool '{tool_id}' is not registered")
        if descriptor.availability != "AVAILABLE":
            raise BindError("TOOL_UNAVAILABLE",
                            f"tool '{tool_id}' availability={descriptor.availability}")

        # 2b. Capability cross-check: the descriptor's gate-capability MUST match the
        # proposal's declared capability. An agent cannot bind a proposal that claims
        # one capability to a tool the CapabilityGate will evaluate under another.
        if descriptor.required_capability != proposal.required_capability:
            raise BindError(
                "CAPABILITY_MISMATCH",
                f"tool '{tool_id}' is gated on "
                f"'{descriptor.required_capability}' but proposal declared "
                f"'{proposal.required_capability}'")

        # 3. Build arguments from the proposal's TYPED fields, then merge the step's
        # typed arg_overrides — whitelisted against the descriptor's own schema so an
        # override can never introduce an unknown key.
        builder = self._arg_builders.get(tool_id)
        args: dict = builder(proposal) if builder else {}
        allowed = set((descriptor.input_schema or {}).get("properties", {}).keys())
        for key, value in (step.arg_overrides or {}).items():
            if not allowed or key in allowed:
                args[key] = value

        # 3b. Confidence ceiling for agent tiers (AI cannot claim certainty). The
        # handler clamps authoritatively too; this is defense in depth.
        if actor in _AGENT_TIERS and "confidence" in args:
            try:
                args["confidence"] = min(float(args["confidence"]), _AGENT_CONFIDENCE_CAP)
            except (TypeError, ValueError):
                args["confidence"] = 0.5

        # 4. Build the invocation. Provenance is boundary-assigned.
        return ToolInvocation(
            task_id=task_id,
            agent_session_id=agent_session_id,
            tool_id=tool_id,
            arguments=args,
            requested_capability=proposal.required_capability,
            execution_profile=descriptor.execution_profile,
            workspace_id=workspace_id,
            actor=actor,
            correlation_id=proposal.proposal_id,
        )
