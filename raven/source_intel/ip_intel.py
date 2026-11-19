"""RAVEN V7 IP Intelligence — Part 06.

IP/ASN lookup via public APIs (ipinfo.io).
All data is UNTRUSTED from external sources.
"""
from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IpRecord:
    ip:       str
    hostname: str = ""
    city:     str = ""
    region:   str = ""
    country:  str = ""
    org:      str = ""     # ASN + org name
    asn:      str = ""
    source:   str = "ipinfo.io"
    human_verification_required: bool = True

    def __post_init__(self):
        object.__setattr__(self, "human_verification_required", True)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "country": self.country,
            "org": self.org,
            "asn": self.asn,
            "human_verification_required": True,
        }


class IpIntelligence:
    """IP/ASN intelligence via ipinfo.io (free tier, no key required)."""

    IPINFO_URL = "https://ipinfo.io/{}/json"
    TIMEOUT_S  = 10

    def lookup(self, ip: str) -> IpRecord:
        try:
            url = self.IPINFO_URL.format(ip)
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=self.TIMEOUT_S) as resp:
                data = json.loads(resp.read(64 * 1024))
        except Exception as exc:
            return IpRecord(ip=ip, source=f"error: {exc}")

        org = data.get("org", "")
        asn = org.split(" ")[0] if org.startswith("AS") else ""
        return IpRecord(
            ip=data.get("ip", ip),
            hostname=data.get("hostname", ""),
            city=data.get("city", ""),
            region=data.get("region", ""),
            country=data.get("country", ""),
            org=org,
            asn=asn,
        )

    def is_cloud_provider(self, record: IpRecord) -> bool:
        """Heuristic: is this IP likely a cloud provider?"""
        cloud_keywords = {"amazon", "google", "microsoft", "cloudflare",
                          "fastly", "akamai", "digitalocean", "linode"}
        org_lower = record.org.lower()
        return any(kw in org_lower for kw in cloud_keywords)
