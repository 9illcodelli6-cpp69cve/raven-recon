"""RAVEN V7 Capability Gate — the single adapter in front of the PolicyGate kernel.

This is the one runtime entry point to the authority. It maps V7 capability /
risk strings onto the canonical PolicyGate (raven.security.policy_gate), which is
the SOLE source of ALLOW. There is no third policy class.

Rust is NOT the authority. PolicyGate (pure Python) decides. When explicitly
enabled (env RAVEN_RUST_VERIFY) the adapter consults raven.rust_bridge as an
OPTIONAL, off-by-default, fail-closed, *tighten-only* cross-check on
SENSITIVE / HTTP_STATE_CHANGE decisions Python already ALLOWed — a Rust DENY or
any bridge failure downgrades to DENY; a Rust ALLOW is a no-op. This is the only
place raven/ calls rust_bridge, and RAVEN runs identically with the binary absent.

INVARIANTS (§105-108, §158):
- DENY is not a signal to find an alternate bypass path.
- Unknown / unmapped risk is treated as SENSITIVE (fail-closed) — never silently
  treated as safe, and never a silent ALLOW.
- Rust cross-check unavailable while enabled → fail-closed (DENY), never permissive.
- No subsystem can self-grant authority; provenance is assigned at the boundary
  (raven.security.actor_context), never from request bodies or model output.
- Denied tool cannot be re-attempted through an equivalent adapter in tested paths.
"""
from __future__ import annotations

import enum
import os
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..security.policy_gate import Capability, PolicyGate, PolicyDecision, RiskClass


class CapabilityDecision(str, enum.Enum):
    ALLOW                   = "ALLOW"
    DENY                    = "DENY"
    REQUIRE_RESEARCHER_APPROVAL = "REQUIRE_RESEARCHER_APPROVAL"
    UNAVAILABLE             = "UNAVAILABLE"


@dataclass
class CapabilityResult:
    decision:    CapabilityDecision
    capability:  str
    reason:      str
    message:     str = ""
    action_id:   str = ""

    def is_allowed(self) -> bool:
        return self.decision == CapabilityDecision.ALLOW

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "capability": self.capability,
            "reason": self.reason,
            "message": self.message,
            "action_id": self.action_id,
        }


class CapabilityGate:
    """V7 capability evaluation for tool/task execution (§104-108).

    The one adapter in front of the canonical PolicyGate kernel. PolicyGate is
    the sole ALLOW authority; this class maps V7 strings onto it and, only when
    RAVEN_RUST_VERIFY is set, applies the optional tighten-only Rust cross-check.
    Per §158: unknown/unmapped risk → fail-closed (SENSITIVE → approval/deny).
    """

    def __init__(self, workspace_id: str, granted_capabilities: set = None,
                 allowed_scope_hosts: set = None):
        self._workspace_id = workspace_id
        self._granted = frozenset(granted_capabilities or set())
        self._allowed_hosts = frozenset(allowed_scope_hosts or set())
        self._lock = threading.RLock()
        self._policy_gate = PolicyGate(
            workspace_id=workspace_id,
            granted_capabilities=set(self._granted),
            allowed_scope_hosts=set(self._allowed_hosts),
        )

    def check(self, capability: str, context: dict = None) -> CapabilityResult:
        """Evaluate whether a capability is available in current context."""
        ctx = context or {}
        destination = ctx.get("destination", "local")
        method = ctx.get("method", "GET")
        reason = ctx.get("reason", "V7 tool execution")
        risk = ctx.get("risk_class")

        # Map V7 capability names to existing Capability enum
        cap_obj = self._map_capability(capability)
        if cap_obj is None:
            return CapabilityResult(
                decision=CapabilityDecision.UNAVAILABLE,
                capability=capability,
                reason="UNKNOWN_CAPABILITY",
                message=f"Capability '{capability}' is not recognized",
            )

        risk_obj = self._map_risk(risk)
        pd: PolicyDecision = self._policy_gate.evaluate(
            capability=cap_obj,
            destination=destination,
            method=method,
            reason=reason,
            risk_class=risk_obj,
        )

        if pd.allowed:
            allow_result = CapabilityResult(
                decision=CapabilityDecision.ALLOW,
                capability=capability,
                reason=pd.reason,
                message=pd.message,
                action_id=pd.action_id,
            )
            # Optional, OFF-by-default, tighten-only Rust cross-check.
            return self._maybe_rust_crosscheck(
                allow_result, cap_obj, risk_obj, destination, method, reason, ctx,
            )
        if pd.requires_approval:
            return CapabilityResult(
                decision=CapabilityDecision.REQUIRE_RESEARCHER_APPROVAL,
                capability=capability,
                reason=pd.reason,
                message=pd.message,
                action_id=pd.action_id,
            )
        return CapabilityResult(
            decision=CapabilityDecision.DENY,
            capability=capability,
            reason=pd.reason,
            message=pd.message,
            action_id=pd.action_id,
        )

    def require(self, capability: str, context: dict = None) -> CapabilityResult:
        """Check capability and raise CapabilityDeniedError if not allowed."""
        result = self.check(capability, context)
        if not result.is_allowed():
            from .errors import CapabilityDeniedError
            raise CapabilityDeniedError(
                capability=capability,
                reason=result.message or result.reason,
            )
        return result

    def _map_capability(self, name: str) -> Optional[Capability]:
        _MAP = {
            # V7 names → existing Capability enum
            "http_read":          Capability.HTTP_READ,
            "HttpRead":           Capability.HTTP_READ,
            "http_state_change":  Capability.HTTP_STATE_CHANGE,
            "HttpStateChange":    Capability.HTTP_STATE_CHANGE,
            "local_fixture":      Capability.LOCAL_FIXTURE_CONNECT,
            "LocalFixtureConnect": Capability.LOCAL_FIXTURE_CONNECT,
            "process_exec":       Capability.PROCESS_ANALYZER,
            "ProcessAnalyzer":    Capability.PROCESS_ANALYZER,
            "local_read":         Capability.FILE_READ_WORKSPACE,
            "FileReadWorkspace":  Capability.FILE_READ_WORKSPACE,
            "local_write":        Capability.FILE_WRITE_WORKSPACE,
            "FileWriteWorkspace": Capability.FILE_WRITE_WORKSPACE,
            "callback":           Capability.CALLBACK_COLLECTOR,
            "CallbackCollector":  Capability.CALLBACK_COLLECTOR,
            "report_export":      Capability.REPORT_EXPORT,
            "ReportExport":       Capability.REPORT_EXPORT,
            "scope_read":         Capability.SCOPE_READ,
            "ScopeRead":          Capability.SCOPE_READ,
            "scope_write":        Capability.SCOPE_WRITE,
            "ScopeWrite":         Capability.SCOPE_WRITE,
            # research_fetch maps to HTTP_READ (external docs, provenance-tracked)
            "research_fetch":     Capability.HTTP_READ,
            # target_readonly
            "target_readonly":    Capability.HTTP_READ,
            "target_statechange": Capability.HTTP_STATE_CHANGE,
        }
        return _MAP.get(name)

    def _map_risk(self, risk: Optional[str]) -> RiskClass:
        # FAIL-CLOSED: a missing or unrecognized risk class is treated as
        # SENSITIVE (requires researcher approval / blocks), NOT as safe. A tool
        # with no declared risk no longer gets a silent safe-read-only pass.
        if risk is None:
            return RiskClass.SENSITIVE
        _MAP = {
            "SAFE_READ_ONLY":       RiskClass.SAFE_READ_ONLY,
            "SafeReadOnly":         RiskClass.SAFE_READ_ONLY,
            "LOW_RISK_STATE_CHANGE": RiskClass.LOW_RISK_STATE_CHANGE,
            "LowRiskStateChange":   RiskClass.LOW_RISK_STATE_CHANGE,
            "SENSITIVE":            RiskClass.SENSITIVE,
            "Sensitive":            RiskClass.SENSITIVE,
            "DESTRUCTIVE":          RiskClass.DESTRUCTIVE,
            "Destructive":          RiskClass.DESTRUCTIVE,
            "EXFILTRATIVE":         RiskClass.EXFILTRATIVE,
            "Exfiltrative":         RiskClass.EXFILTRATIVE,
        }
        return _MAP.get(risk, RiskClass.SENSITIVE)

    # Map the canonical ActorKind provenance to the Rust bridge's provenance
    # vocabulary (informational to Rust; does not affect the tighten-only rule).
    _RUST_PROVENANCE = {
        "RESEARCHER":    "ResearcherDirect",
        "RAVEN_AGENT":   "MlPlanner",
        "PROGRAM_AGENT": "Scheduler",
        "SYSTEM":        "Scheduler",
    }

    def _maybe_rust_crosscheck(self, result: "CapabilityResult",
                               cap_obj: Capability, risk_obj: RiskClass,
                               destination: str, method: str, reason: str,
                               ctx: dict) -> "CapabilityResult":
        """OPTIONAL, OFF-by-default, fail-closed, tighten-only Rust cross-check.

        Consulted ONLY when RAVEN_RUST_VERIFY is truthy, the Python decision is
        ALLOW, and the action is SENSITIVE or HTTP_STATE_CHANGE. A Rust DENY or
        ANY bridge failure (missing/timeout/malformed) downgrades to DENY; a Rust
        ALLOW is a no-op. Rust can never widen a decision — it is only ever
        reached from an already-ALLOW result, so a Python DENY/approval is never
        affected. This is the sole raven/ → rust_bridge call site.
        """
        if not os.environ.get("RAVEN_RUST_VERIFY"):
            return result
        if result.decision != CapabilityDecision.ALLOW:
            return result  # defensive: never widen a non-ALLOW
        if not (risk_obj == RiskClass.SENSITIVE
                or cap_obj == Capability.HTTP_STATE_CHANGE):
            return result  # out of cross-check scope

        actor = ctx.get("actor") if isinstance(ctx, dict) else None
        actor_name = getattr(actor, "value", actor) if actor else None
        provenance = self._RUST_PROVENANCE.get(actor_name, "Scheduler")

        try:
            from .. import rust_bridge
            decision = rust_bridge.evaluate_action(
                workspace_id=self._workspace_id,
                capability=cap_obj.value,
                destination=destination,
                method=method,
                reason=reason,
                risk_class=risk_obj.value,
                provenance=provenance,
                granted_capabilities=[c.value for c in self._granted],
                allowed_hosts=list(self._allowed_hosts),
            )
        except Exception as exc:  # noqa: BLE001 — any bridge error → fail-closed
            return CapabilityResult(
                decision=CapabilityDecision.DENY,
                capability=result.capability,
                reason="RUST_CROSSCHECK_ERROR",
                message=f"Rust cross-check failed (fail-closed): {exc}",
                action_id=result.action_id,
            )

        if decision.is_allowed():
            return result  # Rust concurs — no-op

        # Rust DENY (or fail-closed DENY) tightens the ALLOW to DENY.
        return CapabilityResult(
            decision=CapabilityDecision.DENY,
            capability=result.capability,
            reason="RUST_CROSSCHECK_DENY",
            message=decision.message or decision.reason or "Rust cross-check denied",
            action_id=result.action_id,
        )

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

    def trigger_emergency_stop(self) -> None:
        PolicyGate.trigger_emergency_stop()

    def is_emergency_stop_active(self) -> bool:
        return PolicyGate.is_emergency_stop_active()

    def _reset_emergency_stop_for_test(self) -> None:
        PolicyGate._reset_emergency_stop_for_test()


# ── Live-workspace grant seeding ─────────────────────────────────────────────
# With the gate now fail-closed, the live researcher workspace must be seeded
# with the capabilities the shipped UI exercises, or gating (W6 terminal) turns
# the working terminal / send / recon paths into a 403. This is the canonical
# seed set and the function that builds a seeded gate.
#
# INTEGRATION REQUIREMENT (INT-SERVER / bootstrap): at startup, for the active
# workspace, construct the live CapabilityGate via
#     seed_live_workspace_gate(workspace_id, allowed_scope_hosts=<scope hosts>)
# and use THAT gate for the terminal/process/send endpoints.
LIVE_WORKSPACE_GRANTS = frozenset({
    Capability.PROCESS_ANALYZER,    # researcher terminal / process analysis (W6)
    Capability.HTTP_READ,           # recon probes / browser GET
    Capability.HTTP_STATE_CHANGE,   # browser POST / state-changing send
})


def seed_live_workspace_grants(extra: set = None) -> frozenset:
    """Return the capability set to grant the live researcher workspace."""
    grants = set(LIVE_WORKSPACE_GRANTS)
    if extra:
        grants |= set(extra)
    return frozenset(grants)


def seed_live_workspace_gate(workspace_id: str,
                             allowed_scope_hosts: set = None,
                             extra: set = None) -> "CapabilityGate":
    """Build a CapabilityGate for the live researcher workspace, pre-seeded with
    the grants the shipped UI needs so fail-closed gating does not regress it."""
    return CapabilityGate(
        workspace_id=workspace_id,
        granted_capabilities=seed_live_workspace_grants(extra),
        allowed_scope_hosts=allowed_scope_hosts or set(),
    )
