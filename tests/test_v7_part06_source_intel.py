"""RAVEN V7 Part 06 — Source Intelligence Tests."""
import pytest


# ── DNS Enumerator ────────────────────────────────────────────────────────────

class TestDnsEnumerator:
    def test_resolve_localhost(self):
        from raven.source_intel.dns_enum import DnsEnumerator
        e = DnsEnumerator(timeout_s=2)
        r = e.resolve("localhost")
        assert r.domain == "localhost"
        assert r.human_verification_required is True

    def test_resolve_invalid_domain(self):
        from raven.source_intel.dns_enum import DnsEnumerator
        e = DnsEnumerator(timeout_s=2)
        r = e.resolve("this-domain-absolutely-does-not-exist-xyz123.invalid")
        assert r.error is not None
        assert r.human_verification_required is True

    def test_result_to_dict(self):
        from raven.source_intel.dns_enum import DnsResult
        r = DnsResult(domain="example.com")
        d = r.to_dict()
        assert d["domain"] == "example.com"
        assert d["human_verification_required"] is True

    def test_human_verification_immutable(self):
        from raven.source_intel.dns_enum import DnsResult
        r = DnsResult(domain="x.com", human_verification_required=False)
        assert r.human_verification_required is True  # __post_init__ enforces

    def test_a_records_property(self):
        from raven.source_intel.dns_enum import DnsResult, DnsRecord
        r = DnsResult(
            domain="x.com",
            records=[DnsRecord("A", "1.2.3.4"), DnsRecord("AAAA", "::1")],
        )
        assert "1.2.3.4" in r.a_records
        assert "::1" not in r.a_records


# ── Certificate Transparency ──────────────────────────────────────────────────

class TestCertTransparency:
    def test_cert_record_invariant(self):
        from raven.source_intel.cert_transparency import CertRecord
        r = CertRecord(domain="example.com", human_verification_required=False)
        assert r.human_verification_required is True

    def test_cert_result_invariant(self):
        from raven.source_intel.cert_transparency import CertSearchResult
        r = CertSearchResult(query="x.com", human_verification_required=False)
        assert r.human_verification_required is True

    def test_extract_subdomains(self):
        from raven.source_intel.cert_transparency import CertTransparency, CertSearchResult, CertRecord
        ct = CertTransparency()
        result = CertSearchResult(query="example.com", records=[
            CertRecord(domain="www.example.com"),
            CertRecord(domain="api.example.com"),
            CertRecord(domain="evil.com"),
        ])
        subs = ct.extract_subdomains(result, "example.com")
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "evil.com" not in subs

    def test_to_dict(self):
        from raven.source_intel.cert_transparency import CertRecord
        r = CertRecord(domain="test.example.com", issuer="Let's Encrypt")
        d = r.to_dict()
        assert d["domain"] == "test.example.com"
        assert d["human_verification_required"] is True


# ── Subdomain Discovery ───────────────────────────────────────────────────────

class TestSubdomainDiscovery:
    def test_result_invariant(self):
        from raven.source_intel.subdomain import SubdomainResult
        r = SubdomainResult(base_domain="x.com", human_verification_required=False)
        assert r.human_verification_required is True

    def test_discover_no_cert(self):
        from raven.source_intel.subdomain import SubdomainDiscovery
        from raven.source_intel.dns_enum import DnsEnumerator
        disco = SubdomainDiscovery(dns=DnsEnumerator(timeout_s=1), cert=None)
        # Just verify it runs without crashing; results depend on network
        result = disco.discover("localhost", use_cert=False,
                                wordlist=["this-should-not-exist-abc123"])
        assert isinstance(result.subdomains, list)
        assert result.human_verification_required is True

    def test_to_dict(self):
        from raven.source_intel.subdomain import SubdomainResult
        r = SubdomainResult(base_domain="x.com", subdomains=["www.x.com"])
        d = r.to_dict()
        assert d["subdomain_count"] == 1
        assert d["human_verification_required"] is True


# ── IP Intelligence ───────────────────────────────────────────────────────────

class TestIpIntelligence:
    def test_ip_record_invariant(self):
        from raven.source_intel.ip_intel import IpRecord
        r = IpRecord(ip="1.2.3.4", human_verification_required=False)
        assert r.human_verification_required is True

    def test_is_cloud_provider(self):
        from raven.source_intel.ip_intel import IpIntelligence, IpRecord
        intel = IpIntelligence()
        r = IpRecord(ip="x.x.x.x", org="Amazon AWS EC2")
        assert intel.is_cloud_provider(r)
        r2 = IpRecord(ip="x.x.x.x", org="AS12345 Small ISP")
        assert not intel.is_cloud_provider(r2)

    def test_to_dict(self):
        from raven.source_intel.ip_intel import IpRecord
        r = IpRecord(ip="1.2.3.4", country="US", org="AS123 Test ISP")
        d = r.to_dict()
        assert d["ip"] == "1.2.3.4"
        assert d["human_verification_required"] is True


# ── Tool Registration ─────────────────────────────────────────────────────────

class TestIntelToolRegistration:
    def test_register_intel_tools(self):
        from raven.source_intel.registry import register_intel_tools
        from raven.runtime.tools import ToolRegistry
        registry = ToolRegistry()
        count = register_intel_tools(registry)
        assert count >= 5
        ids = [t.tool_id for t in registry.list_all()]
        assert "intel.dns.resolve" in ids
        assert "intel.cert.search" in ids
        assert "intel.subdomain.discover" in ids
        assert "intel.ip.lookup" in ids
