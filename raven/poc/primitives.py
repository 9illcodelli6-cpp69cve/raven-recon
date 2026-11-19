"""RAVEN Safe Action Primitives (Gate 29).

Controlled, bounded primitives for safe security testing.
Each primitive declares: capability, risk_class, budget, scope, approval_policy.

NO generic execute_arbitrary_command().
NO generic open_arbitrary_socket().
NO generic run_exploit().
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class SafePrimitive:
    """Metadata for a safe testing primitive.

    Declares what capability it requires and under what policy it runs.
    All execution decisions go through PolicyGate, not through this class.
    """
    name:            str
    description:     str
    capability:      str     # from Capability enum
    risk_class:      str     # from RiskClass enum
    budget_notes:    str     # timeout, byte limits
    scope_notes:     str     # must be in-scope target
    approval_policy: str     # "automatic" | "researcher_approval" | "always_denied"
    reversible:      bool    # whether the action can be undone


def establish_baseline(
    endpoint: str, method: str, session_token: str, **kwargs
) -> Dict[str, Any]:
    """Establish a baseline request for comparison.

    Risk: SafeReadOnly. No state changes.
    Returns: {endpoint, method, status_code, response_size, headers_summary}
    """
    return {
        "primitive":      "establish_baseline",
        "endpoint":       endpoint,
        "method":         method,
        "capability":     "HttpRead",
        "risk_class":     "SafeReadOnly",
        "approval":       "automatic",
        "reversible":     True,
        "note":           "Read-only. No state change. Session redacted from record.",
    }


def repeat_request(
    endpoint: str, method: str, count: int, **kwargs
) -> Dict[str, Any]:
    """Repeat a request N times to check consistency.

    Risk: SafeReadOnly (GET) or LowRiskStateChange (POST with idempotent body).
    Budget: count <= 10 per call.
    """
    if count > 10:
        raise ValueError("repeat_request: count must be <= 10 (budget limit)")
    return {
        "primitive":  "repeat_request",
        "endpoint":   endpoint,
        "method":     method,
        "count":      count,
        "capability": "HttpRead",
        "risk_class": "SafeReadOnly",
        "approval":   "automatic",
        "reversible": True,
    }


def compare_response(
    baseline_ref: str, experiment_ref: str, fields: list
) -> Dict[str, Any]:
    """Compare two response observation records on specific fields.

    Risk: None (local computation on already-collected observations).
    """
    return {
        "primitive":      "compare_response",
        "baseline_ref":   baseline_ref,
        "experiment_ref": experiment_ref,
        "fields":         fields,
        "capability":     None,
        "risk_class":     "SafeReadOnly",
        "approval":       "automatic",
        "reversible":     True,
    }


def compare_identity(
    session_a_ref: str, session_b_ref: str, endpoint: str
) -> Dict[str, Any]:
    """Compare responses for two distinct authenticated sessions.

    Risk: SafeReadOnly (GET endpoints). Sessions must be researcher-controlled.
    """
    return {
        "primitive":    "compare_identity",
        "session_a":    session_a_ref,
        "session_b":    session_b_ref,
        "endpoint":     endpoint,
        "capability":   "HttpRead",
        "risk_class":   "SafeReadOnly",
        "approval":     "automatic",
        "reversible":   True,
        "note":         "Both sessions must be researcher-owned test accounts.",
    }


def replace_object_reference(
    endpoint: str, original_id: str, substitute_id: str, method: str = "GET"
) -> Dict[str, Any]:
    """Replace an object ID with a substitute to test IDOR.

    Risk: LowRiskStateChange for mutation methods; SafeReadOnly for GET.
    substitute_id must reference researcher-owned or test data.
    """
    risk = "SafeReadOnly" if method == "GET" else "LowRiskStateChange"
    return {
        "primitive":      "replace_object_reference",
        "endpoint":       endpoint,
        "original_id":    original_id,
        "substitute_id":  substitute_id,
        "method":         method,
        "capability":     "HttpRead",
        "risk_class":     risk,
        "approval":       "automatic" if method == "GET" else "researcher_approval",
        "reversible":     True,
        "note":           "substitute_id must be researcher-owned or test data only.",
    }


def change_safe_parameter(
    endpoint: str, parameter: str, safe_value: str
) -> Dict[str, Any]:
    """Substitute one safe parameter value to observe response changes.

    Risk: LowRiskStateChange.
    safe_value must be a non-destructive, non-sensitive value.
    """
    return {
        "primitive":   "change_safe_parameter",
        "endpoint":    endpoint,
        "parameter":   parameter,
        "safe_value":  safe_value,
        "capability":  "HttpRead",
        "risk_class":  "LowRiskStateChange",
        "approval":    "automatic",
        "reversible":  True,
    }


def observe_redirect(
    endpoint: str, follow: bool = False
) -> Dict[str, Any]:
    """Observe redirect behavior without following to uncontrolled destinations.

    Risk: SafeReadOnly.
    If follow=True, destination must be in policy scope.
    """
    return {
        "primitive":  "observe_redirect",
        "endpoint":   endpoint,
        "follow":     follow,
        "capability": "HttpRead",
        "risk_class": "SafeReadOnly",
        "approval":   "automatic",
        "reversible": True,
        "note":       "Redirect destinations validated against scope before following.",
    }


def record_evidence(
    observation_ref: str, evidence_type: str, notes: str
) -> Dict[str, Any]:
    """Record an evidence reference for a PoC candidate.

    Risk: None (local record keeping).
    Does not store raw response bodies — only references and metadata.
    """
    return {
        "primitive":       "record_evidence",
        "observation_ref": observation_ref,
        "evidence_type":   evidence_type,
        "notes":           notes[:500],  # bounded
        "capability":      None,
        "risk_class":      "SafeReadOnly",
        "approval":        "automatic",
        "reversible":      True,
    }


def run_negative_control(
    endpoint: str, control_type: str, **kwargs
) -> Dict[str, Any]:
    """Run a negative control (e.g. unauthenticated, non-existent ID).

    Risk: SafeReadOnly.
    control_type: one of "unauthenticated", "invalid_id", "expired_session", etc.
    """
    allowed_types = {
        "unauthenticated", "invalid_id", "expired_session",
        "other_user_baseline", "rate_limit_check",
    }
    if control_type not in allowed_types:
        raise ValueError(f"control_type must be one of {allowed_types}")
    return {
        "primitive":    "run_negative_control",
        "endpoint":     endpoint,
        "control_type": control_type,
        "capability":   "HttpRead",
        "risk_class":   "SafeReadOnly",
        "approval":     "automatic",
        "reversible":   True,
    }


SAFE_PRIMITIVES = [
    SafePrimitive("establish_baseline",      "Record baseline response",         "HttpRead",   "SafeReadOnly",       "1 request, 1MB max",          "In-scope target", "automatic",          True),
    SafePrimitive("repeat_request",          "Repeat request N<=10 times",       "HttpRead",   "SafeReadOnly",       "10 requests, 1MB each",       "In-scope target", "automatic",          True),
    SafePrimitive("compare_response",        "Compare two observations locally", None,         "SafeReadOnly",       "Local computation only",      "N/A",             "automatic",          True),
    SafePrimitive("compare_identity",        "Compare two researcher sessions",  "HttpRead",   "SafeReadOnly",       "2 requests, 1MB max",         "In-scope target", "automatic",          True),
    SafePrimitive("replace_object_reference","Substitute object ID (IDOR test)", "HttpRead",   "LowRiskStateChange", "1 request per substitution",  "In-scope target", "researcher_approval",True),
    SafePrimitive("change_safe_parameter",   "Substitute safe parameter value",  "HttpRead",   "LowRiskStateChange", "1 request",                   "In-scope target", "automatic",          True),
    SafePrimitive("observe_redirect",        "Observe redirect without follow",  "HttpRead",   "SafeReadOnly",       "1 request, no follow by default","In-scope target","automatic",        True),
    SafePrimitive("record_evidence",         "Record evidence reference",        None,         "SafeReadOnly",       "Local only",                  "N/A",             "automatic",          True),
    SafePrimitive("run_negative_control",    "Execute a negative control",       "HttpRead",   "SafeReadOnly",       "1 request, 1MB max",          "In-scope target", "automatic",          True),
]
