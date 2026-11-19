"""RAVEN V7 Research Engine — Part 07.

Coordinates experiments, findings, and the critic.
Persists findings and experiments to SQLite.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Dict, List, Optional

from .finding import CandidateFinding, FindingCategory, FindingSeverity
from .experiment import Experiment, ExperimentStatus, ExperimentResult
from .critic import ScientificCritic


class ResearchEngine:
    """Coordinates authorized security research experiments and findings."""

    def __init__(self, db: sqlite3.Connection):
        self._db     = db
        self._lock   = threading.RLock()
        self._critic = ScientificCritic()
        self._migrate()

    def _migrate(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_findings (
            finding_id   TEXT PRIMARY KEY,
            workspace_id TEXT,
            task_id      TEXT,
            title        TEXT,
            description  TEXT,
            category     TEXT,
            severity     TEXT,
            endpoint     TEXT,
            evidence_ref TEXT,
            created_at   INTEGER,
            metadata_json TEXT
        );
        CREATE INDEX IF NOT EXISTS v7_findings_ws ON v7_findings(workspace_id);

        CREATE TABLE IF NOT EXISTS v7_experiments (
            experiment_id TEXT PRIMARY KEY,
            workspace_id  TEXT,
            task_id       TEXT,
            title         TEXT,
            hypothesis    TEXT,
            target_url    TEXT,
            status        TEXT,
            result_json   TEXT,
            created_at    INTEGER
        );
        CREATE INDEX IF NOT EXISTS v7_experiments_ws ON v7_experiments(workspace_id);
        """)
        self._db.commit()

    # ── Findings ──────────────────────────────────────────────────────────────

    def add_finding(self, finding: CandidateFinding) -> str:
        with self._lock:
            self._db.execute(
                """INSERT OR REPLACE INTO v7_findings VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    finding.finding_id, finding.workspace_id, finding.task_id,
                    finding.title, finding.description,
                    finding.category.value, finding.severity.value,
                    finding.endpoint,
                    json.dumps(finding.evidence_ref),
                    finding.created_at,
                    json.dumps(finding.metadata),
                ),
            )
            self._db.commit()
        return finding.finding_id

    def list_findings(
        self, workspace_id: str = None, limit: int = 100,
    ) -> List[CandidateFinding]:
        with self._lock:
            if workspace_id:
                rows = self._db.execute(
                    "SELECT * FROM v7_findings WHERE workspace_id=? ORDER BY created_at DESC LIMIT ?",
                    (workspace_id, limit),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM v7_findings ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        result = []
        for r in rows:
            result.append(CandidateFinding(
                finding_id=r["finding_id"],
                workspace_id=r["workspace_id"] or "default",
                task_id=r["task_id"],
                title=r["title"] or "",
                description=r["description"] or "",
                category=FindingCategory(r["category"]) if r["category"] else FindingCategory.OTHER,
                severity=FindingSeverity(r["severity"]) if r["severity"] else FindingSeverity.UNKNOWN,
                endpoint=r["endpoint"] or "",
                evidence_ref=json.loads(r["evidence_ref"] or "[]"),
                created_at=r["created_at"] or 0,
            ))
        return result

    def get_finding(self, finding_id: str) -> Optional[CandidateFinding]:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM v7_findings WHERE finding_id=?", (finding_id,),
            ).fetchone()
        if not row:
            return None
        return CandidateFinding(
            finding_id=row["finding_id"],
            title=row["title"] or "",
            category=FindingCategory(row["category"]) if row["category"] else FindingCategory.OTHER,
            severity=FindingSeverity(row["severity"]) if row["severity"] else FindingSeverity.UNKNOWN,
            endpoint=row["endpoint"] or "",
        )

    # ── Experiments ───────────────────────────────────────────────────────────

    def add_experiment(self, experiment: Experiment) -> str:
        with self._lock:
            self._db.execute(
                """INSERT OR REPLACE INTO v7_experiments VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    experiment.experiment_id, experiment.workspace_id,
                    experiment.task_id, experiment.title, experiment.hypothesis,
                    experiment.target_url, experiment.status.value,
                    json.dumps(experiment.result.to_dict()) if experiment.result else None,
                    experiment.created_at,
                ),
            )
            self._db.commit()
        return experiment.experiment_id

    def count_findings(self, workspace_id: str = None) -> int:
        with self._lock:
            if workspace_id:
                row = self._db.execute(
                    "SELECT COUNT(*) FROM v7_findings WHERE workspace_id=?",
                    (workspace_id,),
                ).fetchone()
            else:
                row = self._db.execute("SELECT COUNT(*) FROM v7_findings").fetchone()
        return row[0] if row else 0

    def critique(self, finding: CandidateFinding):
        return self._critic.critique_finding(finding)
