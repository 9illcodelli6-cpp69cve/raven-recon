"""RAVEN V7 Submission Management — Part 08."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class SubmissionStatus(str, Enum):
    DRAFT      = "DRAFT"
    READY      = "READY"       # human reviewed, ready to submit
    SUBMITTED  = "SUBMITTED"
    TRIAGED    = "TRIAGED"
    ACCEPTED   = "ACCEPTED"
    REJECTED   = "REJECTED"
    DUPLICATE  = "DUPLICATE"
    REWARDED   = "REWARDED"


@dataclass
class Submission:
    submission_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    program_id:    str = ""
    workspace_id:  str = "default"
    finding_id:    str = ""       # links to CandidateFinding
    title:         str = ""
    description:   str = ""
    severity:      str = "UNKNOWN"
    status:        SubmissionStatus = SubmissionStatus.DRAFT
    created_at:    int = field(default_factory=lambda: int(time.time() * 1000))
    submitted_at:  Optional[int] = None
    reward:        Optional[float] = None
    notes:         str = ""
    human_reviewed: bool = False   # MUST be True before submitting

    def to_dict(self) -> dict:
        return {
            "submission_id": self.submission_id,
            "program_id": self.program_id,
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status.value,
            "human_reviewed": self.human_reviewed,
        }


class SubmissionStore:
    """Persists submission records."""

    def __init__(self, db: sqlite3.Connection):
        self._db   = db
        self._lock = threading.RLock()
        self._migrate()

    def _migrate(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_submissions (
            submission_id TEXT PRIMARY KEY,
            program_id    TEXT,
            workspace_id  TEXT,
            finding_id    TEXT,
            title         TEXT,
            description   TEXT,
            severity      TEXT,
            status        TEXT,
            created_at    INTEGER,
            submitted_at  INTEGER,
            reward        REAL,
            notes         TEXT,
            human_reviewed INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS v7_sub_program ON v7_submissions(program_id);
        """)
        self._db.commit()

    def save(self, sub: Submission) -> str:
        with self._lock:
            self._db.execute(
                """INSERT OR REPLACE INTO v7_submissions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sub.submission_id, sub.program_id, sub.workspace_id,
                    sub.finding_id, sub.title, sub.description,
                    sub.severity, sub.status.value,
                    sub.created_at, sub.submitted_at, sub.reward,
                    sub.notes, 1 if sub.human_reviewed else 0,
                ),
            )
            self._db.commit()
        return sub.submission_id

    def list_for_program(self, program_id: str) -> List[Submission]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM v7_submissions WHERE program_id=? ORDER BY created_at DESC",
                (program_id,),
            ).fetchall()
        return [
            Submission(
                submission_id=r["submission_id"],
                program_id=r["program_id"] or "",
                finding_id=r["finding_id"] or "",
                title=r["title"] or "",
                severity=r["severity"] or "UNKNOWN",
                status=SubmissionStatus(r["status"]) if r["status"] else SubmissionStatus.DRAFT,
                human_reviewed=bool(r["human_reviewed"]),
            )
            for r in rows
        ]

    def count(self, workspace_id: str = None) -> int:
        with self._lock:
            if workspace_id:
                row = self._db.execute(
                    "SELECT COUNT(*) FROM v7_submissions WHERE workspace_id=?",
                    (workspace_id,),
                ).fetchone()
            else:
                row = self._db.execute("SELECT COUNT(*) FROM v7_submissions").fetchone()
        return row[0] if row else 0
