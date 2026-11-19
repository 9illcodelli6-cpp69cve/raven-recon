"""RAVEN Vulnerability Knowledge Schema (Gate 24).

Versioned structured knowledge entries. These teach reasoning and
evidence requirements — they do not provide autonomous exploit execution.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

KNOWLEDGE_SCHEMA_VERSION = "v1"

# Valid values sourced from raven/security/policy_gate.py
VALID_RISK_CLASSES = frozenset({
    "SafeReadOnly",
    "LowRiskStateChange",
    "Sensitive",
    "Destructive",
    "Exfiltrative",
})

VALID_CAPABILITIES = frozenset({
    "HttpRead",
    "HttpStateChange",
    "LocalFixtureConnect",
    "ProcessAnalyzer",
    "FileReadWorkspace",
    "FileWriteWorkspace",
    "CallbackCollector",
    "ReportExport",
    "ScopeRead",
    "ScopeWrite",
})


class KnowledgeVersion:
    SCHEMA = KNOWLEDGE_SCHEMA_VERSION


@dataclass(frozen=True)
class RiskClassKnowledge:
    name:        str
    description: str
    requires_human_approval: bool


@dataclass(frozen=True)
class VulnerabilityKnowledge:
    """Structured knowledge entry for one vulnerability pattern.

    NOT executable exploit code. Teaches preconditions, evidence
    requirements, and safe testing strategy for researcher reasoning.
    """
    knowledge_id:              str
    name:                      str
    family:                    str
    cwe:                       str           # e.g. "CWE-285"
    description:               str
    preconditions:             List[str]
    signals:                   List[str]
    false_positive_explanations: List[str]
    safe_test_strategy:        str
    negative_controls:         List[str]
    evidence_requirements:     List[str]
    remediation_concepts:      List[str]
    risk_class:                str           # from RiskClass enum
    required_capabilities:     List[str]     # from Capability enum
    version:                   str = KNOWLEDGE_SCHEMA_VERSION

    def validate(self) -> None:
        """Raise ValueError if entry is malformed. Called on load."""
        if not self.knowledge_id or not self.knowledge_id.strip():
            raise ValueError("knowledge_id must not be empty")
        if not self.name or not self.name.strip():
            raise ValueError(f"{self.knowledge_id}: name must not be empty")
        if not self.family or not self.family.strip():
            raise ValueError(f"{self.knowledge_id}: family must not be empty")
        if not self.description or not self.description.strip():
            raise ValueError(f"{self.knowledge_id}: description must not be empty")
        if self.risk_class not in VALID_RISK_CLASSES:
            raise ValueError(
                f"{self.knowledge_id}: unknown risk_class {self.risk_class!r}. "
                f"Valid: {sorted(VALID_RISK_CLASSES)}"
            )
        for cap in self.required_capabilities:
            if cap not in VALID_CAPABILITIES:
                raise ValueError(
                    f"{self.knowledge_id}: unknown capability {cap!r}. "
                    f"Valid: {sorted(VALID_CAPABILITIES)}"
                )
        if self.version != KNOWLEDGE_SCHEMA_VERSION:
            raise ValueError(
                f"{self.knowledge_id}: schema version {self.version!r} != "
                f"current {KNOWLEDGE_SCHEMA_VERSION!r}"
            )

    def to_dict(self) -> dict:
        return {
            "knowledge_id":              self.knowledge_id,
            "name":                      self.name,
            "family":                    self.family,
            "cwe":                       self.cwe,
            "description":               self.description,
            "preconditions":             list(self.preconditions),
            "signals":                   list(self.signals),
            "false_positive_explanations": list(self.false_positive_explanations),
            "safe_test_strategy":        self.safe_test_strategy,
            "negative_controls":         list(self.negative_controls),
            "evidence_requirements":     list(self.evidence_requirements),
            "remediation_concepts":      list(self.remediation_concepts),
            "risk_class":                self.risk_class,
            "required_capabilities":     list(self.required_capabilities),
            "version":                   self.version,
        }
