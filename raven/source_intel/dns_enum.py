"""RAVEN V7 DNS Enumerator — Part 06.

DNS lookups using stdlib socket. No external libraries required.
All results are UNTRUSTED DATA.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


@dataclass
class DnsRecord:
    record_type: str
    value:       str
    ttl:         int = 0


@dataclass
class DnsResult:
    domain:   str
    records:  List[DnsRecord] = field(default_factory=list)
    error:    Optional[str] = None
    duration_ms: int = 0
    human_verification_required: bool = True   # INVARIANT

    def __post_init__(self):
        # Security invariant: always True
        object.__setattr__(self, "human_verification_required", True)

    @property
    def a_records(self) -> List[str]:
        return [r.value for r in self.records if r.record_type == "A"]

    @property
    def success(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "records": [{"type": r.record_type, "value": r.value} for r in self.records],
            "error": self.error,
            "human_verification_required": True,
        }


class DnsEnumerator:
    """DNS lookup using stdlib socket. Works without external DNS library."""

    def __init__(self, timeout_s: float = 5.0):
        self._timeout = timeout_s

    def resolve(self, domain: str) -> DnsResult:
        """Resolve A records for a domain."""
        t0 = int(time.time() * 1000)
        records: List[DnsRecord] = []
        error = None

        try:
            socket.setdefaulttimeout(self._timeout)
            addrs = socket.getaddrinfo(domain, None)
            seen = set()
            for addr in addrs:
                ip = addr[4][0]
                rec_type = "AAAA" if ":" in ip else "A"
                if ip not in seen:
                    seen.add(ip)
                    records.append(DnsRecord(record_type=rec_type, value=ip))
        except socket.gaierror as e:
            error = f"DNS resolution failed: {e}"
        except Exception as e:
            error = f"DNS error: {e}"
        finally:
            socket.setdefaulttimeout(None)

        duration = int(time.time() * 1000) - t0
        return DnsResult(domain=domain, records=records, error=error, duration_ms=duration)

    def reverse_lookup(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup. Returns hostname or None."""
        try:
            socket.setdefaulttimeout(self._timeout)
            result = socket.gethostbyaddr(ip)
            return result[0]
        except Exception:
            return None
        finally:
            socket.setdefaulttimeout(None)

    def enumerate_common(self, base_domain: str, wordlist: List[str] = None) -> List[DnsResult]:
        """Enumerate common subdomains. Results are data, not findings."""
        if wordlist is None:
            wordlist = ["www", "mail", "api", "dev", "staging", "test", "admin",
                        "app", "cdn", "static", "beta", "portal", "vpn", "remote"]
        results = []
        for prefix in wordlist:
            subdomain = f"{prefix}.{base_domain}"
            r = self.resolve(subdomain)
            if r.success and r.records:
                results.append(r)
        return results
