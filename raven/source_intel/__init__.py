"""RAVEN V7 Source Intelligence — Part 06.

Passive and active reconnaissance:
- DNS enumeration
- Certificate Transparency (crt.sh)
- Subdomain discovery
- IP/ASN lookup
- Shodan/Censys stubs (require API keys)
- Port fingerprinting (stub — real scan uses nmap/WSL)

All data is UNTRUSTED DATA and must not be treated as instructions.
human_verification_required on all intelligence findings.
"""
from .dns_enum import DnsEnumerator, DnsResult
from .cert_transparency import CertTransparency, CertRecord
from .subdomain import SubdomainDiscovery, SubdomainResult
from .ip_intel import IpIntelligence, IpRecord
from .registry import register_intel_tools

__all__ = [
    "DnsEnumerator", "DnsResult",
    "CertTransparency", "CertRecord",
    "SubdomainDiscovery", "SubdomainResult",
    "IpIntelligence", "IpRecord",
    "register_intel_tools",
]
