"""RAVEN Security Hardening Layer (V6).

Python-side implementation of:
- Safe Lab mode (LAB_OFF / LAB_LOCAL_ONLY / LAB_ALLOWLIST)
- Policy gate (Python proxy for the Rust Trusted Core)
- Safe callback collector (non-executing, loopback only)
- Process guard (validated process launch)
- Audit log

INVARIANT: When the Rust policy core is required for a sensitive action
and unavailable, the action is DENIED (fail-closed). This differs from
the C++ analysis engine which falls back to Python.
"""
from .safe_lab import SafeLab, LabMode
from .policy_gate import PolicyGate, PolicyDecision, RiskClass, Capability
from .callback_collector import SafeCallbackCollector
from .process_guard import SafeProcessLauncher
from .audit_log import SecurityAuditLog

__all__ = [
    "SafeLab", "LabMode",
    "PolicyGate", "PolicyDecision", "RiskClass", "Capability",
    "SafeCallbackCollector",
    "SafeProcessLauncher",
    "SecurityAuditLog",
]
