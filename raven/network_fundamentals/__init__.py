"""RAVEN Network Fundamentals — protocol/application behavior learning module.

This module teaches RAVEN to understand NORMAL network and HTTP behavior
before any vulnerability classification.

All models in this module are:
- ADVISORY ONLY
- DEVELOPMENT status
- Trained on EDUCATIONAL_SYNTHETIC data
- NOT authoritative for security decisions
- Cannot send requests, execute processes, or modify findings
"""
from raven.network_fundamentals.taxonomy import (
    ProtocolClass,
    DifferenceClass,
    SessionState,
    AuthContext,
    ResponseDifference,
    NON_VULNERABILITY_MAPPINGS,
)

__all__ = [
    "ProtocolClass",
    "DifferenceClass",
    "SessionState",
    "AuthContext",
    "ResponseDifference",
    "NON_VULNERABILITY_MAPPINGS",
]
