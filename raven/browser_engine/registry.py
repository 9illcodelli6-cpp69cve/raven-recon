"""Register browser/traffic tools with the shared ToolRegistry.

DEPRECATED / UNWIRED (see raven/browser_engine/__init__.py). register_browser_tools
binds the 4 ToolDescriptors to a _noop that returns {"status":"not_dispatched"};
the server never calls it, so these tools are never dispatched. The ToolDescriptor
SHAPES are retained as a spec for the eventual real ToolDispatcher wiring (a
separate assignment) — but the _noop runtime must NOT ship. No tool wiring here.
"""
from __future__ import annotations

from raven.runtime.tools import ToolDescriptor, ToolRegistry, SideEffectClass

__deprecated__ = True
__canonical_replacement__ = "real ToolDispatcher routing tools through POST /api/send"


def register_browser_tools(registry: ToolRegistry) -> int:
    tools = [
        ToolDescriptor(
            tool_id="browser.http.get",
            name="HTTP GET",
            description="Perform a scope-validated HTTP GET request.",
            required_capability="HttpRead",
            side_effect_class=SideEffectClass.NETWORK_READ,
            input_schema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url":     {"type": "string"},
                    "headers": {"type": "object"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="browser.http.post",
            name="HTTP POST",
            description="Perform a scope-validated HTTP POST request.",
            required_capability="HttpStateChange",
            side_effect_class=SideEffectClass.NETWORK_STATE_CHANGE,
            input_schema={
                "type": "object",
                "required": ["url", "body"],
                "properties": {
                    "url":     {"type": "string"},
                    "body":    {"type": "string"},
                    "headers": {"type": "object"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="browser.traffic.record",
            name="Traffic Record",
            description="Record an HTTP request/response to the traffic log.",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["session_id", "url"],
                "properties": {
                    "session_id": {"type": "string"},
                    "url":        {"type": "string"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="browser.repeater.send",
            name="Repeater Send",
            description="Resend a captured request with optional modifications.",
            required_capability="HttpRead",
            side_effect_class=SideEffectClass.NETWORK_READ,
            input_schema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url":            {"type": "string"},
                    "method":         {"type": "string"},
                    "headers":        {"type": "object"},
                    "body":           {"type": "string"},
                    "modify_headers": {"type": "object"},
                },
            },
        ),
    ]

    def _noop(args: dict) -> dict:
        return {"status": "not_dispatched"}

    for tool in tools:
        registry.register(tool, _noop)
    return len(tools)
