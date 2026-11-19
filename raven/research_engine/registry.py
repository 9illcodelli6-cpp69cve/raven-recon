"""Register research engine tools with the shared ToolRegistry.

**DEPRECATED (Wave 7, A7-RECON).** Every descriptor here binds a ``_noop`` handler that
returns ``{"status": "not_dispatched"}`` — it never dispatches. The canonical, actually
-dispatching recon tool is ``raven.recon.tools.register_recon_tools`` (``recon.collect``),
whose handler calls ``ReconService.submit``. This registrar is kept importable only for
the surviving Part-07 unit tests; it is unwired from the live runtime.
"""
import warnings

from raven.runtime.tools import ToolDescriptor, ToolRegistry, SideEffectClass


def register_research_tools(registry: ToolRegistry) -> int:
    warnings.warn(
        "register_research_tools is deprecated and registers noop (not_dispatched) "
        "handlers; use raven.recon.tools.register_recon_tools (recon.collect) instead.",
        DeprecationWarning, stacklevel=2,
    )
    return _register_research_tools(registry)


def _register_research_tools(registry: ToolRegistry) -> int:
    tools = [
        ToolDescriptor(
            tool_id="research.finding.add",
            name="Add Finding",
            description="Record a candidate finding (requires human verification).",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["title", "category", "endpoint"],
                "properties": {
                    "title":       {"type": "string"},
                    "description": {"type": "string"},
                    "category":    {"type": "string"},
                    "severity":    {"type": "string"},
                    "endpoint":    {"type": "string"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="research.finding.list",
            name="List Findings",
            description="List candidate findings for a workspace.",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.LOCAL_READ,
            input_schema={
                "type": "object",
                "properties": {"workspace_id": {"type": "string"}},
            },
        ),
        ToolDescriptor(
            tool_id="research.experiment.run",
            name="Run Experiment",
            description="Execute a controlled HTTP experiment.",
            required_capability="HttpRead",
            side_effect_class=SideEffectClass.RESEARCH,
            input_schema={
                "type": "object",
                "required": ["title", "hypothesis", "target_url"],
                "properties": {
                    "title":       {"type": "string"},
                    "hypothesis":  {"type": "string"},
                    "target_url":  {"type": "string"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="research.critique",
            name="Scientific Critique",
            description="Critique the quality of a candidate finding.",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.PURE,
            input_schema={
                "type": "object",
                "required": ["finding_id"],
                "properties": {"finding_id": {"type": "string"}},
            },
        ),
    ]

    def _noop(args: dict) -> dict:
        return {"status": "not_dispatched"}

    for t in tools:
        registry.register(t, _noop)
    return len(tools)
