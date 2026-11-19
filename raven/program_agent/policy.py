"""RAVEN V7 Program Policy — Part 08.

Encodes bug bounty program rules:
- In-scope domains, IPs, endpoints
- Out-of-scope exclusions
- Testing restrictions
- Rate limit requirements

external_targets = 0 is enforced: any target not in a loaded program is denied.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set
from urllib.parse import urlparse


class ScopeType(str, Enum):
    DOMAIN    = "domain"
    WILDCARD  = "wildcard"     # *.example.com
    IP        = "ip"
    URL       = "url"
    CIDR      = "cidr"


@dataclass
class ScopeItem:
    value:       str
    scope_type:  ScopeType = ScopeType.DOMAIN
    in_scope:    bool = True    # False = explicitly OUT of scope
    notes:       str = ""

    def matches(self, target: str) -> bool:
        """Check if target matches this scope item."""
        try:
            host = urlparse(target).hostname or target
        except Exception:
            host = target

        if self.scope_type == ScopeType.WILDCARD:
            suffix = self.value.lstrip("*.")
            return host == suffix or host.endswith("." + suffix)
        if self.scope_type in (ScopeType.DOMAIN, ScopeType.IP):
            return host == self.value or host.endswith("." + self.value)
        if self.scope_type == ScopeType.URL:
            return target.startswith(self.value)
        return False


@dataclass
class ProgramScope:
    """Defines what is in and out of scope for a program."""
    items: List[ScopeItem] = field(default_factory=list)

    def is_in_scope(self, target: str) -> bool:
        """Returns True only if target matches an in-scope item and NO out-of-scope item."""
        in_scope_match  = any(i.matches(target) for i in self.items if i.in_scope)
        out_scope_match = any(i.matches(target) for i in self.items if not i.in_scope)
        return in_scope_match and not out_scope_match

    def add_in_scope(self, value: str, scope_type: ScopeType = ScopeType.DOMAIN) -> None:
        self.items.append(ScopeItem(value=value, scope_type=scope_type, in_scope=True))

    def add_out_of_scope(self, value: str, scope_type: ScopeType = ScopeType.DOMAIN) -> None:
        self.items.append(ScopeItem(value=value, scope_type=scope_type, in_scope=False))

    def in_scope_count(self) -> int:
        return sum(1 for i in self.items if i.in_scope)


@dataclass
class ProgramPolicy:
    """Complete program policy including scope, rules, and restrictions.

    INVARIANT: external_targets = 0 (no unauthorized external targets)
    """
    program_id:     str
    name:           str
    platform:       str = ""     # bugcrowd, hackerone, intigriti, etc.
    scope:          ProgramScope = field(default_factory=ProgramScope)
    max_severity:   str = "CRITICAL"
    rate_limit_rps: float = 5.0   # requests per second
    requires_account: bool = False
    notes:          str = ""
    external_targets: int = 0     # INVARIANT: always 0

    def __post_init__(self):
        object.__setattr__(self, "external_targets", 0)

    def __setattr__(self, name: str, value):
        if name == "external_targets":
            if "external_targets" in self.__dict__:
                raise AttributeError("external_targets is immutable — always 0")
        object.__setattr__(self, name, value)

    def is_target_allowed(self, target: str) -> bool:
        return self.scope.is_in_scope(target)

    def to_dict(self) -> dict:
        return {
            "program_id": self.program_id,
            "name": self.name,
            "platform": self.platform,
            "in_scope_count": self.scope.in_scope_count(),
            "rate_limit_rps": self.rate_limit_rps,
            "external_targets": 0,
        }
