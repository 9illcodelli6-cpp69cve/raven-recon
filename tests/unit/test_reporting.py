"""Stage 9: Reporting foundation tests (Category 6).

Verifies Redactor strips credentials, ReportGenerator produces valid JSON/Markdown,
and reports are evidence-grounded with no fabricated content.
"""
import json
import pytest

from raven.reporting import (
    Redactor,
    ReportGenerator,
    FindingReport,
    EvidenceSummary,
    ReportingError,
)


@pytest.fixture
def redactor():
    return Redactor()


@pytest.fixture
def gen():
    return ReportGenerator()


def _finding(**kwargs):
    defaults = dict(
        id="f001abc",
        workspace_id="ws001",
        title="IDOR on /api/users",
        url="https://target.example/api/users/1",
        severity="high",
        verification_status="unverified",
        review_status="in_review",
        created_at="2026-10-01T12:00:00Z",
    )
    defaults.update(kwargs)
    return defaults


def _evidence(**kwargs):
    defaults = dict(
        id="ev001",
        kind="reflection",
        summary="Response body contained user email of a different user.",
        request_method="GET",
        request_url="https://target.example/api/users/2",
        request_headers={"Authorization": "Bearer eyJhbGc.rest", "Content-Type": "application/json"},
        response_status=200,
    )
    defaults.update(kwargs)
    return defaults


class TestRedactor:

    def test_authorization_header_redacted(self, redactor):
        h = {"Authorization": "Bearer secret-token"}
        result = redactor.redact_headers(h)
        assert result["Authorization"] == "[REDACTED]"

    def test_cookie_header_redacted(self, redactor):
        h = {"Cookie": "session=abc123"}
        result = redactor.redact_headers(h)
        assert result["Cookie"] == "[REDACTED]"

    def test_set_cookie_header_redacted(self, redactor):
        h = {"set-cookie": "session=xyz; HttpOnly"}
        result = redactor.redact_headers(h)
        assert result["set-cookie"] == "[REDACTED]"

    def test_x_api_key_redacted(self, redactor):
        h = {"x-api-key": "supersecret"}
        result = redactor.redact_headers(h)
        assert result["x-api-key"] == "[REDACTED]"

    def test_content_type_not_redacted(self, redactor):
        h = {"Content-Type": "application/json"}
        result = redactor.redact_headers(h)
        assert result["Content-Type"] == "application/json"

    def test_bearer_in_text_redacted(self, redactor):
        text = "Header: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
        result = redactor.redact_text(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "Bearer" in result
        assert "[REDACTED]" in result

    def test_basic_auth_in_text_redacted(self, redactor):
        text = "Basic dXNlcjpwYXNz"
        result = redactor.redact_text(text)
        assert "dXNlcjpwYXNz" not in result

    def test_non_sensitive_text_unchanged(self, redactor):
        text = "Status code 200 for /api/users"
        result = redactor.redact_text(text)
        assert result == text

    def test_redact_preserves_non_sensitive_headers(self, redactor):
        h = {"Accept": "application/json", "Authorization": "Bearer tok"}
        result = redactor.redact_headers(h)
        assert result["Accept"] == "application/json"
        assert result["Authorization"] == "[REDACTED]"


class TestReportGenerator:

    def test_build_finding_report_returns_instance(self, gen):
        r = gen.build_finding_report(_finding())
        assert isinstance(r, FindingReport)

    def test_missing_required_field_raises(self, gen):
        f = _finding()
        del f["severity"]
        with pytest.raises(ReportingError):
            gen.build_finding_report(f)

    def test_finding_fields_in_report(self, gen):
        r = gen.build_finding_report(_finding(title="Test Finding"))
        assert r.title == "Test Finding"
        assert r.verification_status == "unverified"

    def test_evidence_headers_redacted(self, gen):
        ev = _evidence()
        r = gen.build_finding_report(_finding(), evidence_rows=[ev])
        ev_summary = r.evidence[0]
        assert ev_summary.request_headers.get("Authorization") == "[REDACTED]"

    def test_content_type_header_not_redacted(self, gen):
        ev = _evidence()
        r = gen.build_finding_report(_finding(), evidence_rows=[ev])
        ev_summary = r.evidence[0]
        assert ev_summary.request_headers.get("Content-Type") == "application/json"

    def test_evidence_summary_redacted(self, gen):
        ev = _evidence(summary="Token: Bearer secret-token-123")
        r = gen.build_finding_report(_finding(), evidence_rows=[ev])
        assert "secret-token-123" not in r.evidence[0].summary

    def test_no_evidence_means_empty_list(self, gen):
        r = gen.build_finding_report(_finding())
        assert r.evidence == []

    def test_generated_at_set(self, gen):
        r = gen.build_finding_report(_finding())
        assert r.generated_at and "T" in r.generated_at


class TestJsonOutput:

    def test_to_json_is_valid_json(self, gen):
        r = gen.build_finding_report(_finding())
        output = gen.to_json(r)
        parsed = json.loads(output)
        assert parsed["id"] == "f001abc"

    def test_json_contains_verification_status(self, gen):
        r = gen.build_finding_report(_finding())
        output = gen.to_json(r)
        parsed = json.loads(output)
        assert parsed["verification_status"] == "unverified"

    def test_json_evidence_headers_redacted(self, gen):
        r = gen.build_finding_report(_finding(), evidence_rows=[_evidence()])
        output = gen.to_json(r)
        parsed = json.loads(output)
        headers = parsed["evidence"][0]["request_headers"]
        assert headers.get("Authorization") == "[REDACTED]"

    def test_json_contains_generated_at(self, gen):
        r = gen.build_finding_report(_finding())
        output = gen.to_json(r)
        parsed = json.loads(output)
        assert "generated_at" in parsed


class TestMarkdownOutput:

    def test_to_markdown_contains_title(self, gen):
        r = gen.build_finding_report(_finding(title="IDOR Finding"))
        md = gen.to_markdown(r)
        assert "IDOR Finding" in md

    def test_to_markdown_contains_severity(self, gen):
        r = gen.build_finding_report(_finding(severity="critical"))
        md = gen.to_markdown(r)
        assert "critical" in md

    def test_to_markdown_contains_verification_status(self, gen):
        r = gen.build_finding_report(_finding())
        md = gen.to_markdown(r)
        assert "unverified" in md

    def test_to_markdown_returns_string(self, gen):
        r = gen.build_finding_report(_finding())
        md = gen.to_markdown(r)
        assert isinstance(md, str)

    def test_to_markdown_evidence_section(self, gen):
        r = gen.build_finding_report(_finding(), evidence_rows=[_evidence()])
        md = gen.to_markdown(r)
        assert "Evidence" in md
        assert "ev001" in md

    def test_to_markdown_no_fabricated_content(self, gen):
        r = gen.build_finding_report(_finding(description="", remediation=""))
        md = gen.to_markdown(r)
        # No description/remediation sections added when empty
        assert "## Description" not in md
        assert "## Remediation" not in md
