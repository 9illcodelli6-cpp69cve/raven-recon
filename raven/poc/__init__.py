"""RAVEN PoC Architecture (Gates 27-30).

Safe, evidence-driven PoC candidates and reasoning primitives.
Does NOT contain unrestricted arbitrary code execution.
"""
from .candidate   import PoCCandidate, PoCObservation, PoCStatus
from .primitives  import (
    SafePrimitive, establish_baseline, repeat_request, compare_response,
    compare_identity, replace_object_reference, change_safe_parameter,
    observe_redirect, record_evidence, run_negative_control,
    SAFE_PRIMITIVES,
)
from .autonomy    import AutonomyLevel, AutonomyConfig, DEFAULT_AUTONOMY

__all__ = [
    "PoCCandidate", "PoCObservation", "PoCStatus",
    "SafePrimitive", "establish_baseline", "repeat_request",
    "compare_response", "compare_identity", "replace_object_reference",
    "change_safe_parameter", "observe_redirect", "record_evidence",
    "run_negative_control", "SAFE_PRIMITIVES",
    "AutonomyLevel", "AutonomyConfig", "DEFAULT_AUTONOMY",
]
