"""RAVEN Vulnerability Knowledge System (Gate 24-26).

Provides structured, versioned vulnerability knowledge for teaching
RAVEN security reasoning. Does NOT contain executable exploit code.
"""
from .schema    import VulnerabilityKnowledge, RiskClassKnowledge, KnowledgeVersion
from .taxonomy  import VULNERABILITY_FAMILIES, get_entry, list_families

__all__ = [
    "VulnerabilityKnowledge", "RiskClassKnowledge", "KnowledgeVersion",
    "VULNERABILITY_FAMILIES", "get_entry", "list_families",
]
