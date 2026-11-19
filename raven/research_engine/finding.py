"""RAVEN V7 Candidate Finding — Part 07.

A CandidateFinding is a POTENTIAL vulnerability observation.
It is NEVER a confirmed vulnerability until human-reviewed.

Security invariants:
- human_verification_required = ALWAYS True (AttributeError if set False)
- is_verified = ALWAYS False (set only by human review, outside this class)
- security_authority = "NONE" (AI cannot grant itself authority)
- BOLA/BFLA labels are CONCEPTUAL only
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class FindingSeverity(str, Enum):
    CRITICAL  = "CRITICAL"
    HIGH      = "HIGH"
    MEDIUM    = "MEDIUM"
    LOW       = "LOW"
    INFO      = "INFO"
    UNKNOWN   = "UNKNOWN"


class FindingCategory(str, Enum):
    # Conceptual/Educational labels — NOT confirmed vulnerability categories
    BOLA           = "BOLA"          # Broken Object Level Authorization (conceptual)
    BFLA           = "BFLA"          # Broken Function Level Authorization (conceptual)
    IDOR           = "IDOR"          # Insecure Direct Object Reference (conceptual)
    AUTH_BYPASS    = "AUTH_BYPASS"
    INJECTION      = "INJECTION"
    XSS            = "XSS"
    SSRF           = "SSRF"
    RATE_LIMIT     = "RATE_LIMIT"
    INFO_DISCLOSURE = "INFO_DISCLOSURE"
    MISCONFIG      = "MISCONFIG"
    OTHER          = "OTHER"


@dataclass
class CandidateFinding:
    """A potential security observation requiring human verification.

    INVARIANTS:
    - human_verification_required = True, always, immutable
    - security_authority = "NONE", always
    - is_verified = False (only a human reviewer can set this, not this class)
    """
    finding_id:   str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    title:        str = ""
    description:  str = ""
    category:     FindingCategory = FindingCategory.OTHER
    severity:     FindingSeverity = FindingSeverity.UNKNOWN
    endpoint:     str = ""
    evidence_ref: List[str] = field(default_factory=list)  # IDs, never raw data
    created_at:   int = field(default_factory=lambda: int(time.time() * 1000))
    workspace_id: str = "default"
    task_id:      Optional[str] = None
    metadata:     Dict = field(default_factory=dict)

    # Immutable security invariants
    human_verification_required: bool = True
    security_authority:          str  = "NONE"
    is_verified:                 bool = False

    def __post_init__(self):
        object.__setattr__(self, "human_verification_required", True)
        object.__setattr__(self, "security_authority", "NONE")
        object.__setattr__(self, "is_verified", False)

    def __setattr__(self, name: str, value):
        if name == "human_verification_required":
            if "human_verification_required" in self.__dict__:
                raise AttributeError("human_verification_required is immutable — always True")
        if name == "security_authority":
            if "security_authority" in self.__dict__:
                raise AttributeError("security_authority is immutable — always NONE")
        if name == "is_verified":
            if "is_verified" in self.__dict__:
                raise AttributeError(
                    "is_verified cannot be set on CandidateFinding — "
                    "human review is required (external process)"
                )
        object.__setattr__(self, name, value)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "endpoint": self.endpoint,
            "human_verification_required": True,
            "security_authority": "NONE",
            "is_verified": False,
            "created_at": self.created_at,
        }
