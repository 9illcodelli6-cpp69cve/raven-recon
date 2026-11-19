"""Register source intelligence tools with the shared ToolRegistry."""
from __future__ import annotations
from raven.runtime.tools import ToolDescriptor, ToolRegistry, SideEffectClass


def register_intel_tools(registry: ToolRegistry) -> int:
    tools = [
        ToolDescriptor(
            tool_id="intel.dns.resolve",
            name="DNS Resolve",
            description="Resolve DNS records for a domain.",
            required_capability="HttpRead",
            side_effect_class=SideEffectClass.NETWORK_READ,
            input_schema={
                "type": "object", "required": ["domain"],
                "properties": {"domain": {"type": "string"}},
            },
        ),
        ToolDescriptor(
            tool_id="intel.dns.enumerate",
            name="DNS Enumerate",
            description="Enumerate common subdomains via DNS brute-force.",
            required_capability="HttpRead",
            side_effect_class=SideEffectClass.NETWORK_READ,
            input_schema={
                "type": "object", "required": ["domain"],
                "properties": {
                    "domain":   {"type": "string"},
                    "wordlist": {"type": "array", "items": {"type": "string"}},
                },
            },
        ),
        ToolDescriptor(
            tool_id="intel.cert.search",
            name="Cert Transparency Search",
            description="Search crt.sh for certificates issued for a domain.",
            required_capability="HttpRead",
            side_effect_class=SideEffectClass.NETWORK_READ,
            input_schema={
                "type": "object", "required": ["domain"],
                "properties": {"domain": {"type": "string"}},
            },
        ),
        ToolDescriptor(
            tool_id="intel.subdomain.discover",
            name="Subdomain Discovery",
            description="Discover subdomains via DNS + cert transparency.",
            required_capability="HttpRead",
            side_effect_class=SideEffectClass.NETWORK_READ,
            input_schema={
                "type": "object", "required": ["domain"],
                "properties": {"domain": {"type": "string"}},
            },
        ),
        ToolDescriptor(
            tool_id="intel.ip.lookup",
            name="IP Lookup",
            description="Retrieve IP/ASN intelligence for an IP address.",
            required_capability="HttpRead",
            side_effect_class=SideEffectClass.NETWORK_READ,
            input_schema={
                "type": "object", "required": ["ip"],
                "properties": {"ip": {"type": "string"}},
            },
        ),
    ]

    def _noop(args: dict) -> dict:
        return {"status": "not_dispatched"}

    for t in tools:
        registry.register(t, _noop)
    return len(tools)
