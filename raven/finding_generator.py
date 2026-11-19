"""Candidate Finding Generation.

CandidateFindingGenerator creates new Finding records with:
  - verification_status = 'unverified' (ALWAYS, immutable invariant)
  - review_status = 'new'
  - ml_probability = NULL (never populated here)
  - uuid4 primary key

INVARIANT: This module NEVER sets verification_status to anything other than
'unverified'. No heuristic, rule, model, or similarity score may change it here.

Design reference: blueprint Stage 6, invariants 3 and 4.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


class FindingGenerationError(Exception):
    """Raised when a candidate finding cannot be created."""


@dataclass
class CandidateFinding:
    """An unverified candidate finding.

    verification_status is ALWAYS 'unverified'; it is not a parameter.
    review_status is ALWAYS 'new' at creation.
    ml_probability is ALWAYS None at creation.
    """
    id: str
    workspace_id: str
    title: str
    url: str
    severity: str
    created_at: str
    updated_at: str
    observation_id: Optional[str] = None
    asset_id: Optional[str] = None
    evidence_ids: list = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    # Immutable invariant fields — set once, never changed by generator
    verification_status: str = "unverified"
    review_status: str = "new"
    ml_probability: None = None


class CandidateFindingGenerator:
    """Creates unverified candidate findings.

    All findings created here have verification_status='unverified' and
    review_status='new'. The ml_probability is always NULL.
    """

    def generate(
        self,
        workspace_id: str,
        title: str,
        url: str,
        severity: str,
        observation_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        evidence_ids: Optional[list] = None,
        description: str = "",
        remediation: str = "",
    ) -> CandidateFinding:
        """Create a new unverified candidate finding.

        Never accepts verification_status, review_status, or ml_probability
        as parameters — those are fixed by invariant.
        """
        if not workspace_id:
            raise FindingGenerationError("workspace_id is required")
        if not title or not title.strip():
            raise FindingGenerationError("title must not be empty")
        if not url or not url.strip():
            raise FindingGenerationError("url must not be empty")
        if severity not in VALID_SEVERITIES:
            raise FindingGenerationError(
                f"severity must be one of {sorted(VALID_SEVERITIES)}, got {severity!r}"
            )
        now = datetime.now(tz=timezone.utc).isoformat()
        return CandidateFinding(
            id=uuid.uuid4().hex,
            workspace_id=workspace_id,
            title=title.strip(),
            url=url.strip(),
            severity=severity,
            created_at=now,
            updated_at=now,
            observation_id=observation_id,
            asset_id=asset_id,
            evidence_ids=list(evidence_ids) if evidence_ids else [],
            description=description,
            remediation=remediation,
            verification_status="unverified",
            review_status="new",
            ml_probability=None,
        )

    def to_db_row(self, finding: CandidateFinding) -> dict:
        """Convert a CandidateFinding to a dict suitable for DB insertion."""
        return {
            "id": finding.id,
            "workspace_id": finding.workspace_id,
            "title": finding.title,
            "url": finding.url,
            "severity": finding.severity,
            "created_at": finding.created_at,
            "updated_at": finding.updated_at,
            "observation_id": finding.observation_id,
            "asset_id": finding.asset_id,
            "description": finding.description,
            "remediation": finding.remediation,
            "verification_status": finding.verification_status,
            "review_status": finding.review_status,
            "ml_probability": finding.ml_probability,
        }
