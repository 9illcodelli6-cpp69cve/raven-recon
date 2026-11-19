"""Safe Payload Registry package.

INVARIANT: EXFILTRATION and DESTRUCTIVE payloads MUST NEVER execute automatically.
"""
from .registry import (
    PayloadRiskClass,
    Payload,
    PayloadDispatch,
    ProbeError,
    BUILTIN_PAYLOADS,
)

__all__ = [
    "PayloadRiskClass",
    "Payload",
    "PayloadDispatch",
    "ProbeError",
    "BUILTIN_PAYLOADS",
]
