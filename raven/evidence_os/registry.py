"""Register evidence OS tools with the shared ToolRegistry."""
from raven.runtime.tools import ToolDescriptor, ToolRegistry, SideEffectClass


def register_evidence_tools(registry: ToolRegistry) -> int:
    tools = [
        ToolDescriptor(
            tool_id="evidence.node.add",
            name="Add Evidence Node",
            description="Add a node (request/response/note/finding) to the evidence graph.",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["kind", "label"],
                "properties": {
                    "kind":  {"type": "string"},
                    "label": {"type": "string"},
                    "data":  {"type": "object"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="evidence.node.list",
            name="List Evidence Nodes",
            description="List evidence nodes for a workspace.",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.LOCAL_READ,
            input_schema={
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                    "kind":         {"type": "string"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="evidence.edge.add",
            name="Add Evidence Edge",
            description="Add a directed edge between two evidence nodes.",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["src_id", "dst_id"],
                "properties": {
                    "src_id":   {"type": "string"},
                    "dst_id":   {"type": "string"},
                    "relation": {"type": "string"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="evidence.poc.create",
            name="Create PoC Entry",
            description="Create an advisory PoC documentation entry for a candidate finding.",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["finding_id", "title"],
                "properties": {
                    "finding_id": {"type": "string"},
                    "title":      {"type": "string"},
                    "summary":    {"type": "string"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="evidence.report.generate",
            name="Generate Report",
            description="Generate an advisory security report from candidate findings.",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["finding_ids"],
                "properties": {
                    "finding_ids": {"type": "array", "items": {"type": "string"}},
                    "title":       {"type": "string"},
                    "format":      {"type": "string"},
                },
            },
        ),
    ]

    def _noop(args: dict) -> dict:
        return {"status": "not_dispatched"}

    for t in tools:
        registry.register(t, _noop)
    return len(tools)
