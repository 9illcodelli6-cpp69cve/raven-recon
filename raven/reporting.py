"""Reporting Foundation — evidence-grounded report generation with redaction.

Reports are generated from actual finding/evidence data only.
No fabrication, no inference, no ML output in the report body.

INVARIANT: Redactor strips Authorization, Cookie, token headers before
           any report is serialized. Raw credentials must never appear
           in exported report output.

Design reference: blueprint Stage 9, Category 6.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# Headers that must always be redacted from reports
_REDACTED_HEADERS = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "proxy-authorization",
})

_REDACTED_VALUE = "[REDACTED]"

_TOKEN_PATTERN = re.compile(
    r"(Bearer\s+)[A-Za-z0-9._~+/]+=*|"
    r"(Basic\s+)[A-Za-z0-9+/]+=*",
    re.IGNORECASE,
)


class ReportingError(Exception):
    """Raised when report generation fails."""


class Redactor:
    """Strips sensitive headers and credential patterns from output."""

    def redact_headers(self, headers: dict) -> dict:
        """Return a copy of headers with sensitive keys replaced."""
        result = {}
        for k, v in headers.items():
            if k.lower() in _REDACTED_HEADERS:
                result[k] = _REDACTED_VALUE
            else:
                result[k] = self._redact_token_values(v)
        return result

    def _redact_token_values(self, value: str) -> str:
        return _TOKEN_PATTERN.sub(lambda m: (m.group(1) or m.group(2)) + _REDACTED_VALUE, value)

    def redact_text(self, text: str) -> str:
        """Redact token patterns from free-form text."""
        return _TOKEN_PATTERN.sub(lambda m: (m.group(1) or m.group(2)) + _REDACTED_VALUE, text)


_REDACTOR = Redactor()


@dataclass
class EvidenceSummary:
    """Redacted summary of an evidence row for inclusion in reports."""
    id: str
    kind: str
    summary: str
    request_method: Optional[str] = None
    request_url: Optional[str] = None
    request_headers: dict = field(default_factory=dict)
    response_status: Optional[int] = None


@dataclass
class FindingReport:
    """Structured report for a single finding."""
    id: str
    workspace_id: str
    title: str
    url: str
    severity: str
    verification_status: str
    review_status: str
    created_at: str
    description: str = ""
    remediation: str = ""
    evidence: list = field(default_factory=list)
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(tz=timezone.utc).isoformat()


class ReportGenerator:
    """Generates evidence-grounded finding reports in JSON or Markdown.

    Only reports what is present in the finding + evidence data.
    Never fabricates details or infers authorization conclusions.
    """

    def __init__(self, redactor: Optional[Redactor] = None):
        self._redactor = redactor or _REDACTOR

    def build_finding_report(
        self,
        finding: dict,
        evidence_rows: Optional[list] = None,
    ) -> FindingReport:
        """Build a FindingReport from a finding dict and optional evidence rows."""
        required = {"id", "workspace_id", "title", "url", "severity",
                    "verification_status", "review_status", "created_at"}
        missing = required - finding.keys()
        if missing:
            raise ReportingError(f"Finding missing required fields: {missing}")
        evidence_summaries = []
        for ev in (evidence_rows or []):
            raw_headers = ev.get("request_headers") or {}
            if isinstance(raw_headers, str):
                try:
                    raw_headers = json.loads(raw_headers)
                except (json.JSONDecodeError, ValueError):
                    raw_headers = {}
            redacted_headers = self._redactor.redact_headers(raw_headers)
            summary = self._redactor.redact_text(ev.get("summary", ""))
            evidence_summaries.append(EvidenceSummary(
                id=ev.get("id", ""),
                kind=ev.get("kind", "unknown"),
                summary=summary,
                request_method=ev.get("request_method"),
                request_url=ev.get("request_url"),
                request_headers=redacted_headers,
                response_status=ev.get("response_status"),
            ))
        return FindingReport(
            id=finding["id"],
            workspace_id=finding["workspace_id"],
            title=finding["title"],
            url=finding["url"],
            severity=finding["severity"],
            verification_status=finding["verification_status"],
            review_status=finding["review_status"],
            created_at=finding["created_at"],
            description=finding.get("description", ""),
            remediation=finding.get("remediation", ""),
            evidence=evidence_summaries,
        )

    def to_json(self, report: FindingReport) -> str:
        """Serialize a FindingReport to JSON."""
        def _serializable(obj):
            if isinstance(obj, EvidenceSummary):
                return asdict(obj)
            if isinstance(obj, FindingReport):
                d = asdict(obj)
                d["evidence"] = [_serializable(e) if isinstance(e, EvidenceSummary) else e
                                 for e in obj.evidence]
                return d
            return obj
        data = {
            "id": report.id,
            "workspace_id": report.workspace_id,
            "title": report.title,
            "url": report.url,
            "severity": report.severity,
            "verification_status": report.verification_status,
            "review_status": report.review_status,
            "created_at": report.created_at,
            "description": report.description,
            "remediation": report.remediation,
            "generated_at": report.generated_at,
            "evidence": [asdict(e) for e in report.evidence],
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def to_markdown(self, report: FindingReport) -> str:
        """Serialize a FindingReport to Markdown."""
        lines = [
            f"# {report.title}",
            "",
            f"**Severity:** {report.severity}  ",
            f"**Verification:** {report.verification_status}  ",
            f"**Review status:** {report.review_status}  ",
            f"**URL:** `{report.url}`  ",
            f"**Created:** {report.created_at}  ",
            f"**Generated:** {report.generated_at}  ",
            "",
        ]
        if report.description:
            lines += ["## Description", "", report.description, ""]
        if report.remediation:
            lines += ["## Remediation", "", report.remediation, ""]
        if report.evidence:
            lines += ["## Evidence", ""]
            for ev in report.evidence:
                lines.append(f"### Evidence `{ev.id}` ({ev.kind})")
                if ev.summary:
                    lines.append(f"> {ev.summary}")
                if ev.request_method and ev.request_url:
                    lines.append(f"- Request: `{ev.request_method} {ev.request_url}`")
                if ev.response_status:
                    lines.append(f"- Response status: `{ev.response_status}`")
                lines.append("")
        return "\n".join(lines)
