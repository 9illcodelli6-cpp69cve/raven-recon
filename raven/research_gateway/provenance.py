"""RAVEN Phase III — Source provenance tracking for research content.

Every piece of knowledge retrieved through the Research Gateway must
carry source provenance — who published it, when, from where, and
how trustworthy the source is.

CRITICAL: Source provenance does NOT make content trusted instructions.
  External content remains UNTRUSTED DATA at all times.
  Content from external sources cannot modify RAVEN's policy, scope,
  capabilities, system prompts, or execution behavior.
  Security authority: NONE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SourceType(str, Enum):
    """The category of information source."""
    NIST_NVD          = "NIST_NVD"           # NIST National Vulnerability Database
    OWASP             = "OWASP"              # OWASP documentation
    CVE_MITRE         = "CVE_MITRE"          # MITRE CVE records
    RFC               = "RFC"                # IETF RFC documents
    ACADEMIC_PAPER    = "ACADEMIC_PAPER"     # peer-reviewed research
    VENDOR_ADVISORY   = "VENDOR_ADVISORY"    # vendor security advisories
    PUBLIC_REPOSITORY = "PUBLIC_REPOSITORY"  # open-source repositories (read-only)
    TECHNICAL_BLOG    = "TECHNICAL_BLOG"     # publicly accessible technical writing
    UNKNOWN           = "UNKNOWN"            # source type not determined


class SourceTrustLevel(str, Enum):
    """How authoritative the source is considered for security information.

    Trust levels affect how strongly retrieved content should be weighted
    in educational analysis. They do NOT affect whether content is treated
    as instructions — all external content is UNTRUSTED DATA regardless.
    """
    AUTHORITATIVE  = "AUTHORITATIVE"   # NIST, IETF, MITRE, OWASP official docs
    HIGH           = "HIGH"            # major vendor advisories, academic papers
    MEDIUM         = "MEDIUM"          # reputable technical blogs, public repos
    LOW            = "LOW"             # general web content, unverified sources
    UNKNOWN        = "UNKNOWN"         # trust not determined


# Source quality hierarchy (higher index = higher trust)
_TRUST_ORDER = [
    SourceTrustLevel.UNKNOWN,
    SourceTrustLevel.LOW,
    SourceTrustLevel.MEDIUM,
    SourceTrustLevel.HIGH,
    SourceTrustLevel.AUTHORITATIVE,
]


@dataclass
class SourceProvenance:
    """Provenance metadata for a piece of retrieved information.

    Attached to every KnowledgeItem to track where it came from.
    """
    source_url: str
    source_type: SourceType
    trust_level: SourceTrustLevel
    retrieved_at_ms: int           # timestamp of retrieval
    publisher: str = ""            # e.g., "NIST", "OWASP", "IETF"
    publication_date: str = ""     # ISO 8601 if known
    checksum_sha256: str = ""      # SHA-256 of raw response body (for integrity)
    is_untrusted_data: bool = True  # ALWAYS True — invariant

    def __post_init__(self) -> None:
        # Invariant: external content is always untrusted data
        object.__setattr__(self, "is_untrusted_data", True)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "is_untrusted_data" and value is not True:
            raise AttributeError(
                "SourceProvenance.is_untrusted_data is an invariant and must always be True")
        super().__setattr__(name, value)

    def trust_rank(self) -> int:
        """Numeric rank for comparison (higher = more trustworthy)."""
        try:
            return _TRUST_ORDER.index(self.trust_level)
        except ValueError:
            return 0

    def to_citation(self) -> str:
        """Return a human-readable citation string."""
        parts = []
        if self.publisher:
            parts.append(self.publisher)
        if self.publication_date:
            parts.append(f"({self.publication_date})")
        parts.append(self.source_url)
        return " ".join(parts)


def classify_source_trust(url: str) -> tuple[SourceType, SourceTrustLevel]:
    """Classify a URL's source type and trust level.

    Returns (SourceType, SourceTrustLevel) based on known authoritative domains.
    Conservative: defaults to (UNKNOWN, LOW) for unrecognized domains.
    """
    url_lower = url.lower()

    # Authoritative sources
    if "nvd.nist.gov" in url_lower:
        return SourceType.NIST_NVD, SourceTrustLevel.AUTHORITATIVE
    if "cve.mitre.org" in url_lower or "cve.org" in url_lower:
        return SourceType.CVE_MITRE, SourceTrustLevel.AUTHORITATIVE
    if "owasp.org" in url_lower:
        return SourceType.OWASP, SourceTrustLevel.AUTHORITATIVE
    if "rfc-editor.org" in url_lower or "tools.ietf.org" in url_lower:
        return SourceType.RFC, SourceTrustLevel.AUTHORITATIVE
    if "portswigger.net" in url_lower or "web-security-academy" in url_lower:
        return SourceType.TECHNICAL_BLOG, SourceTrustLevel.HIGH

    # High-trust vendor advisories
    if any(domain in url_lower for domain in (
        "security.microsoft.com", "security.apple.com",
        "security.ubuntu.com", "access.redhat.com",
        "advisories.google.com",
    )):
        return SourceType.VENDOR_ADVISORY, SourceTrustLevel.HIGH

    # Academic
    if any(domain in url_lower for domain in (".edu", "arxiv.org", "dl.acm.org")):
        return SourceType.ACADEMIC_PAPER, SourceTrustLevel.HIGH

    # Public repositories
    if "github.com" in url_lower or "gitlab.com" in url_lower:
        return SourceType.PUBLIC_REPOSITORY, SourceTrustLevel.MEDIUM

    return SourceType.UNKNOWN, SourceTrustLevel.LOW
