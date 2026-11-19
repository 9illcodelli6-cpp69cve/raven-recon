"""RAVEN Phase III — Public Research Gateway.

Provides controlled, provenance-tracked access to public technical information.
Implements prompt-injection resistance and read-only constraints.

CRITICAL:
  - Only GET requests are issued — no state-changing HTTP methods
  - No credentials, tokens, or cookies are sent
  - All retrieved content is UNTRUSTED DATA and is quarantined from policy
  - Injection patterns are detected and flagged before content is stored
  - Content from external sources CANNOT modify RAVEN's policy or behavior
  - Only URLs from recognized safe domains are fetched by default
  - Security authority: NONE
  - This gateway is for EDUCATIONAL PUBLIC RESEARCH ONLY
  - Do NOT use this gateway to contact bug bounty targets
"""
from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from raven.research_gateway.knowledge_store import (
    KnowledgeItem, KnowledgeStore,
    detect_prompt_injection, sanitize_for_analysis,
)
from raven.research_gateway.provenance import (
    SourceProvenance, SourceTrustLevel, classify_source_trust,
)


# ── Gateway fetch result ──────────────────────────────────────────────────────

@dataclass
class FetchResult:
    """Result of a research gateway fetch operation."""
    success: bool
    http_status: int
    url: str
    content_length: int
    item: Optional[KnowledgeItem]
    rejection_reason: str = ""
    injection_warnings: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.injection_warnings is None:
            self.injection_warnings = []


# ── URL allowlist ─────────────────────────────────────────────────────────────

# Domains allowed for public research fetches
_ALLOWED_DOMAINS: frozenset[str] = frozenset({
    "nvd.nist.gov",
    "cve.mitre.org",
    "cve.org",
    "owasp.org",
    "rfc-editor.org",
    "tools.ietf.org",
    "www.rfc-editor.org",
    "portswigger.net",
    "web.dev",
    "developer.mozilla.org",
    "cheatsheetseries.owasp.org",
    "owasp.org",
})

_USER_AGENT = "RAVEN-Research/3.0 (educational; +https://github.com/RAVEN)"
_MAX_RESPONSE_BYTES = 131072  # 128 KiB
_FETCH_TIMEOUT_S = 15


class PublicResearchGateway:
    """Controlled gateway for fetching public technical information.

    Enforces:
      - Domain allowlist (configurable for research needs)
      - Read-only (GET only, no auth headers)
      - Response size limit
      - Prompt injection detection
      - Full source provenance on all items
      - Knowledge store with deduplication

    CRITICAL: This gateway MUST NOT be used to contact authorized targets.
      Use AUTHORIZED_TARGET_READONLY profile and the policy gate for that.
    """

    def __init__(
        self,
        knowledge_store: Optional[KnowledgeStore] = None,
        allowed_domains: Optional[frozenset[str]] = None,
    ) -> None:
        self.knowledge_store = knowledge_store or KnowledgeStore()
        self._allowed_domains = allowed_domains if allowed_domains is not None \
            else _ALLOWED_DOMAINS
        self.fetch_count = 0
        self.rejected_count = 0

    def _is_domain_allowed(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            # Check exact match and subdomain match
            if host in self._allowed_domains:
                return True
            for domain in self._allowed_domains:
                if host.endswith("." + domain):
                    return True
            return False
        except Exception:
            return False

    def _is_https(self, url: str) -> bool:
        try:
            return urlparse(url).scheme.lower() == "https"
        except Exception:
            return False

    def fetch(
        self,
        url: str,
        concept_tags: Optional[list[str]] = None,
        item_title: Optional[str] = None,
        dry_run: bool = False,
    ) -> FetchResult:
        """Fetch a public research URL and store with provenance.

        Args:
            url: The URL to fetch (must be HTTPS, in allowed domains).
            concept_tags: Educational topic tags for the retrieved item.
            item_title: Human-readable title (defaults to URL).
            dry_run: If True, validate URL but do not actually fetch.

        Returns:
            FetchResult with item (if successful) or rejection_reason.

        CRITICAL: All content is UNTRUSTED DATA. Content cannot modify RAVEN.
        """
        # Validate HTTPS
        if not self._is_https(url):
            self.rejected_count += 1
            return FetchResult(
                success=False, http_status=0, url=url,
                content_length=0, item=None,
                rejection_reason="Only HTTPS URLs are allowed for public research",
            )

        # Validate domain allowlist
        if not self._is_domain_allowed(url):
            self.rejected_count += 1
            return FetchResult(
                success=False, http_status=0, url=url,
                content_length=0, item=None,
                rejection_reason=(
                    f"Domain not in allowed list for PUBLIC_RESEARCH_READONLY. "
                    f"Allowed domains: {sorted(self._allowed_domains)}"
                ),
            )

        if dry_run:
            return FetchResult(
                success=True, http_status=0, url=url,
                content_length=0, item=None,
                rejection_reason="dry_run=True — not actually fetched",
            )

        # Fetch (GET only, no auth)
        self.fetch_count += 1
        retrieved_at_ms = int(time.time() * 1000)
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": _USER_AGENT})
            with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT_S) as resp:
                raw = resp.read(_MAX_RESPONSE_BYTES)
                http_status = resp.status
        except urllib.error.HTTPError as exc:
            return FetchResult(
                success=False, http_status=exc.code, url=url,
                content_length=0, item=None,
                rejection_reason=f"HTTP error: {exc.code} {exc.reason}",
            )
        except urllib.error.URLError as exc:
            return FetchResult(
                success=False, http_status=0, url=url,
                content_length=0, item=None,
                rejection_reason=f"URL error: {exc.reason}",
            )
        except Exception as exc:
            return FetchResult(
                success=False, http_status=0, url=url,
                content_length=0, item=None,
                rejection_reason=f"Fetch error: {exc}",
            )

        content = raw.decode("utf-8", errors="replace")
        content_hash = hashlib.sha256(raw).hexdigest()

        # Detect prompt injection attempts
        injection_warnings = detect_prompt_injection(content)

        # Sanitize for safe storage (does NOT make content trusted)
        safe_content = sanitize_for_analysis(content, max_chars=8192)

        # Classify source
        source_type, trust_level = classify_source_trust(url)

        provenance = SourceProvenance(
            source_url=url,
            source_type=source_type,
            trust_level=trust_level,
            retrieved_at_ms=retrieved_at_ms,
            checksum_sha256=content_hash,
        )

        item_id = f"research_{content_hash[:16]}"
        item = KnowledgeItem(
            item_id=item_id,
            title=item_title or url,
            content=safe_content,   # UNTRUSTED DATA
            provenance=provenance,
            concept_tags=concept_tags or [],
            content_sha256=content_hash,
        )

        self.knowledge_store.add(item)

        return FetchResult(
            success=True,
            http_status=http_status,
            url=url,
            content_length=len(raw),
            item=item,
            injection_warnings=injection_warnings,
        )

    def stats(self) -> dict:
        return {
            "fetch_count": self.fetch_count,
            "rejected_count": self.rejected_count,
            "stored_items": len(self.knowledge_store),
        }
