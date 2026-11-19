"""Canonical recon tool — the REAL dispatching ``recon.collect`` (Wave 7, A7-RECON).

Replaces the dead ``research_engine.register_research_tools`` noop (which registered four
descriptors whose handler was ``_noop -> {"status":"not_dispatched"}``,
research_engine/registry.py:66) with one descriptor whose handler ACTUALLY dispatches:
it validates the (untrusted) arguments through the ToolRegistry/ToolDispatcher contract,
is gated on a network-read capability by the CapabilityGate, and on success calls
``ReconService.submit`` — the exact same seam the loopback ``/api/collect`` route uses.
This is how Agent / Program mode reach recon under capability + actor provenance
(RECON_ARCHITECTURE §3.4).

No collection work runs inside the handler synchronously: ``submit`` is non-blocking and
hands the bounded job to the one scheduler, so the tool returns ``{job_id, state}``.
"""
from __future__ import annotations

from ..runtime.tools import ToolDescriptor, ToolRegistry, SideEffectClass


RECON_COLLECT = ToolDescriptor(
    tool_id="recon.collect",
    name="Recon Collect",
    description=("Start a bounded reconnaissance collection (passive crt.sh + active "
                 "HTTP probe) over the current workspace scope, through the one scheduler "
                 "and the one pinned sender. Non-blocking; returns a job_id."),
    required_capability="network_read",
    side_effect_class=SideEffectClass.NETWORK_READ,
    input_schema={
        "type": "object",
        "properties": {
            "passive":        {"type": "boolean"},
            "probe":          {"type": "boolean"},
            "external_tools": {"type": "boolean"},
        },
    },
    execution_profile="NETWORK",
    cancellation_support=True,
    metadata={"risk_class": "network_read"},
)


def register_recon_tools(registry: ToolRegistry, service=None) -> int:
    """Register the real ``recon.collect`` tool. ``service`` defaults to a shared
    :class:`ReconService` (resolves its live dependencies off the server at call time)."""
    if service is None:
        from .service import ReconService
        service = ReconService()

    def _handler(args: dict) -> dict:
        passive = args.get("passive", True)
        probe = args.get("probe", True)
        external_tools = bool(args.get("external_tools", False))
        # ReconService.submit re-validates the booleans (same guard as submit_collect).
        return service.submit(passive, probe, external_tools=external_tools)

    registry.register(RECON_COLLECT, _handler)
    return 1
