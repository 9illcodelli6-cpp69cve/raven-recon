"""RAVEN V7 Technique Library — Part 09.

Pre-seeded library of security testing techniques.
All techniques are educational content — not automated exploits.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


class TechniqueCategory(str, Enum):
    ACCESS_CONTROL = "access_control"
    INJECTION      = "injection"
    AUTH           = "auth"
    RECON          = "recon"
    BUSINESS_LOGIC = "business_logic"
    CRYPTO         = "crypto"
    CONFIG         = "config"
    NETWORK        = "network"


@dataclass
class Technique:
    tech_id:     str
    name:        str
    category:    TechniqueCategory
    description: str
    steps:       List[str] = field(default_factory=list)
    references:  List[str] = field(default_factory=list)
    is_advisory: bool = True   # ALWAYS True — techniques are educational

    def __post_init__(self):
        object.__setattr__(self, "is_advisory", True)

    def to_dict(self) -> dict:
        return {
            "tech_id": self.tech_id,
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "is_advisory": True,
        }


# Built-in technique library
_BUILTIN_TECHNIQUES: List[Technique] = [
    Technique(
        tech_id="AC-001",
        name="Horizontal Privilege Escalation Test",
        category=TechniqueCategory.ACCESS_CONTROL,
        description="Test if user A can access user B's resources by modifying object IDs.",
        steps=[
            "1. Authenticate as User A, note resource IDs",
            "2. Log in as User B, collect their resource IDs",
            "3. As User A, attempt to access User B's resource IDs",
            "4. Record any unauthorized access (advisory — human verification required)",
        ],
        references=["OWASP API3:2023"],
    ),
    Technique(
        tech_id="AC-002",
        name="Vertical Privilege Escalation Test",
        category=TechniqueCategory.ACCESS_CONTROL,
        description="Test if a low-privilege user can access admin functions.",
        steps=[
            "1. Map available admin endpoints from documentation",
            "2. As a regular user, attempt to call admin endpoints",
            "3. Record 200/403 responses",
        ],
        references=["OWASP API5:2023"],
    ),
    Technique(
        tech_id="AUTH-001",
        name="JWT Signature Validation Test",
        category=TechniqueCategory.AUTH,
        description="Test JWT token signature validation.",
        steps=[
            "1. Capture a valid JWT",
            "2. Modify the payload without updating signature",
            "3. Send modified token — verify server rejects it",
        ],
        references=["OWASP API2:2023"],
    ),
    Technique(
        tech_id="RECON-001",
        name="API Surface Mapping",
        category=TechniqueCategory.RECON,
        description="Map all API endpoints using documentation, JS files, and traffic analysis.",
        steps=[
            "1. Review OpenAPI/Swagger specifications",
            "2. Analyze JS bundles for API URLs",
            "3. Capture traffic via proxy",
            "4. Build endpoint inventory",
        ],
        references=["OWASP API9:2023"],
    ),
]


class TechniqueLibrary:
    """In-memory technique library with search."""

    def __init__(self):
        self._techniques: Dict[str, Technique] = {
            t.tech_id: t for t in _BUILTIN_TECHNIQUES
        }

    def add(self, technique: Technique) -> None:
        self._techniques[technique.tech_id] = technique

    def get(self, tech_id: str) -> Technique:
        return self._techniques.get(tech_id)

    def search(self, query: str = "", category: TechniqueCategory = None) -> List[Technique]:
        results = list(self._techniques.values())
        if category:
            results = [t for t in results if t.category == category]
        if query:
            q = query.lower()
            results = [t for t in results
                       if q in t.name.lower() or q in t.description.lower()]
        return results

    def count(self) -> int:
        return len(self._techniques)
