"""RAVEN V7 Certificate Transparency — Part 06.

Queries crt.sh for certificate records.
All results are UNTRUSTED DATA from external sources.
"""
from __future__ import annotations

import json
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CertRecord:
    domain:      str
    issuer:      str = ""
    not_before:  str = ""
    not_after:   str = ""
    serial:      str = ""
    human_verification_required: bool = True

    def __post_init__(self):
        object.__setattr__(self, "human_verification_required", True)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "human_verification_required": True,
        }


@dataclass
class CertSearchResult:
    query:    str
    records:  List[CertRecord] = field(default_factory=list)
    error:    Optional[str] = None
    source:   str = "crt.sh"
    duration_ms: int = 0
    human_verification_required: bool = True

    def __post_init__(self):
        object.__setattr__(self, "human_verification_required", True)


class CertTransparency:
    """Certificate Transparency log searcher via crt.sh API.

    External data source — all responses are UNTRUSTED DATA.
    Requires scope check before use.
    """

    CRTSH_URL = "https://crt.sh/?q={}&output=json"
    TIMEOUT_S = 15

    def __init__(self, scope_guard=None):
        self._scope = scope_guard

    def search(self, domain: str) -> CertSearchResult:
        """Search crt.sh for certificates matching a domain."""
        t0 = int(time.time() * 1000)

        try:
            url = self.CRTSH_URL.format(urllib.parse.quote(domain))
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=self.TIMEOUT_S) as resp:
                raw = resp.read(2 * 1024 * 1024)
            data = json.loads(raw)
        except Exception as exc:
            duration = int(time.time() * 1000) - t0
            return CertSearchResult(
                query=domain, error=f"crt.sh query failed: {exc}", duration_ms=duration,
            )

        records = []
        seen = set()
        for entry in (data if isinstance(data, list) else []):
            name = entry.get("common_name") or entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub and sub not in seen:
                    seen.add(sub)
                    records.append(CertRecord(
                        domain=sub,
                        issuer=entry.get("issuer_name", ""),
                        not_before=str(entry.get("not_before", "")),
                        not_after=str(entry.get("not_after", "")),
                        serial=str(entry.get("serial_number", "")),
                    ))

        duration = int(time.time() * 1000) - t0
        return CertSearchResult(query=domain, records=records, duration_ms=duration)

    def extract_subdomains(self, result: CertSearchResult, base_domain: str) -> List[str]:
        """Extract unique subdomains from cert results that match base_domain."""
        subs = set()
        for r in result.records:
            if r.domain.endswith("." + base_domain) or r.domain == base_domain:
                subs.add(r.domain)
        return sorted(subs)
