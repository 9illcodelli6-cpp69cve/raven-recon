"""RAVEN V7 Subdomain Discovery — Part 06.

Combines DNS brute-force + cert transparency for comprehensive subdomain mapping.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set

from .dns_enum import DnsEnumerator, DnsResult


@dataclass
class SubdomainResult:
    base_domain:  str
    subdomains:   List[str] = field(default_factory=list)
    resolved:     List[DnsResult] = field(default_factory=list)
    sources:      List[str] = field(default_factory=list)
    human_verification_required: bool = True

    def __post_init__(self):
        object.__setattr__(self, "human_verification_required", True)

    def to_dict(self) -> dict:
        return {
            "base_domain": self.base_domain,
            "subdomains": self.subdomains,
            "subdomain_count": len(self.subdomains),
            "sources": self.sources,
            "human_verification_required": True,
        }


class SubdomainDiscovery:
    """Discovers subdomains via DNS brute-force and certificate transparency."""

    DEFAULT_WORDLIST = [
        "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
        "app", "cdn", "static", "beta", "portal", "vpn", "remote", "ns",
        "mx", "smtp", "imap", "pop", "webmail", "support", "help", "docs",
        "blog", "shop", "store", "checkout", "pay", "login", "auth", "sso",
    ]

    def __init__(self, dns: DnsEnumerator = None, cert: "CertTransparency" = None):
        self._dns  = dns or DnsEnumerator()
        self._cert = cert

    def discover(
        self,
        base_domain: str,
        use_wordlist: bool = True,
        use_cert: bool = True,
        wordlist: List[str] = None,
    ) -> SubdomainResult:
        found: Set[str] = set()
        sources: List[str] = []
        resolved: List[DnsResult] = []

        if use_wordlist:
            wl = wordlist or self.DEFAULT_WORDLIST
            dns_results = self._dns.enumerate_common(base_domain, wl)
            for r in dns_results:
                found.add(r.domain)
                resolved.append(r)
            if dns_results:
                sources.append("dns_brute")

        if use_cert and self._cert:
            try:
                cert_result = self._cert.search(base_domain)
                subs = self._cert.extract_subdomains(cert_result, base_domain)
                for s in subs:
                    found.add(s)
                if subs:
                    sources.append("cert_transparency")
            except Exception:
                pass

        return SubdomainResult(
            base_domain=base_domain,
            subdomains=sorted(found),
            resolved=resolved,
            sources=sources,
        )
