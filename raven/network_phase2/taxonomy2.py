"""RAVEN Network Phase II — Phase II classification taxonomies.

Defines class labels for NET-E/F/G/H tasks and causal hypothesis taxonomy.

INVARIANT: No class here implies a confirmed vulnerability.
Classification is protocol/application state, not security verdict.
Security authority: NONE.
"""
from __future__ import annotations
from enum import Enum


# ── NET-E: State Transition Reasoning ─────────────────────────────────────────

class StateTransitionClass(str, Enum):
    """Output classes for NET-E task.

    Classifies the state transition that occurred between two consecutive
    observations. A transition is NOT a security finding.
    """
    NO_STATE_CHANGE        = "NO_STATE_CHANGE"        # Semantically identical state
    SESSION_CREATED        = "SESSION_CREATED"        # New session established
    SESSION_ROTATED        = "SESSION_ROTATED"        # Session ID changed (normal post-login)
    SESSION_EXPIRED        = "SESSION_EXPIRED"        # Session was valid, now expired
    AUTH_ESTABLISHED       = "AUTH_ESTABLISHED"       # Authentication newly present
    AUTH_LOST              = "AUTH_LOST"              # Authentication was present, now absent
    CACHE_VALIDATED        = "CACHE_VALIDATED"        # 304: representation unchanged
    CACHE_INVALIDATED      = "CACHE_INVALIDATED"      # Resource changed after cache hit
    RESOURCE_STATE_CHANGED = "RESOURCE_STATE_CHANGED" # Resource created/updated/deleted
    TRANSIENT_RECOVERY     = "TRANSIENT_RECOVERY"     # Recovered from 5xx/timeout
    REDIRECT_FOLLOWED      = "REDIRECT_FOLLOWED"      # 3xx → final response
    RATE_LIMIT_RECOVERY    = "RATE_LIMIT_RECOVERY"    # 429 → success after Retry-After
    UNKNOWN                = "UNKNOWN"                # Cannot classify from available signals

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]

    @classmethod
    def label_index(cls) -> dict[str, int]:
        return {c.value: i for i, c in enumerate(cls)}


# ── NET-F: Experiment Quality ──────────────────────────────────────────────────

class ExperimentQualityClass(str, Enum):
    """Output classes for NET-F task.

    Classifies whether a comparison between two observations constitutes
    a controlled experiment. This is epistemics, not security.
    """
    CONTROLLED_SINGLE_VARIABLE = "CONTROLLED_SINGLE_VARIABLE"  # Exactly one variable changed
    CONFOUNDED                 = "CONFOUNDED"                   # Multiple variables changed
    NO_MEANINGFUL_CHANGE       = "NO_MEANINGFUL_CHANGE"         # No observable difference
    INSUFFICIENT_CONTEXT       = "INSUFFICIENT_CONTEXT"         # Cannot determine changed vars
    UNKNOWN                    = "UNKNOWN"

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]

    @classmethod
    def label_index(cls) -> dict[str, int]:
        return {c.value: i for i, c in enumerate(cls)}


# ── NET-G: Causal Support ──────────────────────────────────────────────────────

class CausalSupportClass(str, Enum):
    """Output classes for NET-G task.

    Classifies whether the observed evidence supports a stated normal-behavior
    hypothesis. This is NOT security causality.
    """
    SUPPORTED            = "SUPPORTED"            # Evidence clearly supports hypothesis
    WEAKLY_SUPPORTED     = "WEAKLY_SUPPORTED"     # Consistent but incomplete evidence
    NOT_SUPPORTED        = "NOT_SUPPORTED"        # Evidence contradicts hypothesis
    CONFOUNDED           = "CONFOUNDED"           # Multiple variables prevent attribution
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # Too little data to evaluate
    UNKNOWN              = "UNKNOWN"

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]

    @classmethod
    def label_index(cls) -> dict[str, int]:
        return {c.value: i for i, c in enumerate(cls)}


# ── NET-H: Next Best Observation ──────────────────────────────────────────────

class NextObservationType(str, Enum):
    """Output classes for NET-H task.

    Classifies what type of safe follow-up observation would most reduce
    uncertainty. This is a conceptual recommendation — NOT an execution command.
    """
    REPEAT_SAME_OBSERVATION      = "REPEAT_SAME_OBSERVATION"
    COMPARE_WITHOUT_AUTH_HEADER  = "COMPARE_WITHOUT_AUTH_HEADER"
    COMPARE_WITH_AUTH_HEADER     = "COMPARE_WITH_AUTH_HEADER"
    KEEP_IDENTITY_CONSTANT       = "KEEP_IDENTITY_CONSTANT"
    KEEP_RESOURCE_CONSTANT       = "KEEP_RESOURCE_CONSTANT"
    CHECK_REDIRECT_CHAIN         = "CHECK_REDIRECT_CHAIN"
    CHECK_COOKIE_SCOPE           = "CHECK_COOKIE_SCOPE"
    CHECK_CACHE_VALIDATOR        = "CHECK_CACHE_VALIDATOR"
    ISOLATE_SESSION_VARIABLE     = "ISOLATE_SESSION_VARIABLE"
    ISOLATE_METHOD_VARIABLE      = "ISOLATE_METHOD_VARIABLE"
    VERIFY_TRANSIENT_RECOVERY    = "VERIFY_TRANSIENT_RECOVERY"
    NO_OBSERVATION_NEEDED        = "NO_OBSERVATION_NEEDED"
    UNKNOWN                      = "UNKNOWN"

    @classmethod
    def labels(cls) -> list[str]:
        return [c.value for c in cls]

    @classmethod
    def label_index(cls) -> dict[str, int]:
        return {c.value: i for i, c in enumerate(cls)}


# ── Causal Hypothesis Taxonomy (Part 10) ──────────────────────────────────────

class CausalHypothesis(str, Enum):
    """Named normal-behavior hypotheses RAVEN may evaluate.

    These are NOT vulnerability classifications.
    Example: AUTHENTICATION_DEPENDENCY_SUPPORTED != AUTH_BYPASS.
    """
    AUTHENTICATION_DEPENDENCY_SUPPORTED        = "AUTHENTICATION_DEPENDENCY_SUPPORTED"
    SESSION_DEPENDENCY_SUPPORTED               = "SESSION_DEPENDENCY_SUPPORTED"
    CACHE_DEPENDENCY_SUPPORTED                 = "CACHE_DEPENDENCY_SUPPORTED"
    CONTENT_NEGOTIATION_DEPENDENCY_SUPPORTED   = "CONTENT_NEGOTIATION_DEPENDENCY_SUPPORTED"
    LOCALE_DEPENDENCY_SUPPORTED                = "LOCALE_DEPENDENCY_SUPPORTED"
    METHOD_DEPENDENCY_SUPPORTED                = "METHOD_DEPENDENCY_SUPPORTED"
    RESOURCE_STATE_DEPENDENCY_SUPPORTED        = "RESOURCE_STATE_DEPENDENCY_SUPPORTED"
    RATE_LIMIT_STATE_DEPENDENCY_SUPPORTED      = "RATE_LIMIT_STATE_DEPENDENCY_SUPPORTED"
    MULTIPLE_VARIABLES_CHANGED                 = "MULTIPLE_VARIABLES_CHANGED"
    INSUFFICIENT_EVIDENCE                      = "INSUFFICIENT_EVIDENCE"
    NO_OBSERVED_DEPENDENCY                     = "NO_OBSERVED_DEPENDENCY"
    UNKNOWN                                    = "UNKNOWN"


# ── Request dimension taxonomy (Part 6) ───────────────────────────────────────

REQUEST_DIMENSIONS: tuple[str, ...] = (
    "method_changed",
    "path_changed",
    "query_changed",
    "body_changed",
    "authorization_changed",
    "cookie_changed",
    "origin_changed",
    "accept_changed",
    "language_changed",
    "content_type_changed",
    "identity_changed",
    "resource_changed",
)
