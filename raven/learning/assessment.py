"""RAVEN Learning — live self-assessment + persisted mastery (Learning page backend).

Runs RAVEN's real educational exam categories (``curriculum.EXAMS``) once each,
projects the results onto the Security Mastery Matrix, and persists a snapshot
so the Learning page shows the last assessment across restarts.

HONESTY / SAFETY INVARIANTS
  * Exams run in-process over EDUCATIONAL_SYNTHETIC fixtures — no sockets, no
    targets, no model calls. They grade RAVEN's deterministic rules against the
    fixtures they were written for (self-consistency), NOT generalisation; the
    snapshot says so in ``note``.
  * Domains without an exam are reported ``NO_EXAM`` with ``accuracy: None`` —
    never a made-up score — and therefore block ``graduation_ready``.
  * Mastery grants NO security authority (``authority: "NONE"``).
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

from .curriculum import (
    DOMAIN_EXAMS, DOMAINS_WITHOUT_EXAM, EXAMS, STUDY_RESOURCES, run_exam,
)
from .mastery import KnowledgeDomain, SecurityMasteryMatrix

SCHEMA = "raven-learning/1"
DATA_SOURCE = "EDUCATIONAL_SYNTHETIC"
AUTHORITY = "NONE"
THRESHOLD = 0.85
HISTORY_LIMIT = 20
MAX_FAILURES_LISTED = 10

NOTE = ("Self-assessment over RAVEN's synthetic educational exams: it checks that "
        "RAVEN's rules agree with the fixtures they were written for "
        "(self-consistency), not that RAVEN generalises to real targets. "
        "Mastery grants no security authority.")

# Domain statuses (row-level; distinct from the page status vocabulary).
EVALUATED = "EVALUATED"
NOT_EVALUATED = "NOT_EVALUATED"
NO_EXAM = "NO_EXAM"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _domain_rows(matrix: Optional[SecurityMasteryMatrix]) -> List[dict]:
    rows = []
    for d in KnowledgeDomain:
        exam_id = DOMAIN_EXAMS.get(d)
        m = matrix.get_domain(d) if matrix is not None else None
        if exam_id is None:
            status = NO_EXAM
        elif m is None or m.n_evaluated == 0:
            status = NOT_EVALUATED
        else:
            status = EVALUATED
        evaluated = status == EVALUATED
        rows.append({
            "domain": d.value,
            "status": status,
            "exam_id": exam_id,
            "accuracy": round(m.accuracy, 4) if evaluated else None,
            "mastery_level": m.mastery_level.value if evaluated else None,
            "n_evaluated": m.n_evaluated if m is not None else 0,
            "n_correct": m.n_correct if m is not None else 0,
            "needs_study": (not evaluated) or m.accuracy < THRESHOLD,
        })
    return rows


def empty_snapshot() -> dict:
    """The honest never-assessed state (every examinable domain NOT_EVALUATED)."""
    return {
        "schema": SCHEMA,
        "assessed_at": None,
        "duration_ms": None,
        "exams": [],
        "domains": _domain_rows(None),
        "gaps": [],
        "graduation_ready": False,
        "no_exam_domains": sorted(d.value for d in DOMAINS_WITHOUT_EXAM),
    }


def run_assessment(*, should_stop: Callable[[], bool] = lambda: False,
                   clock: Callable[[], int] = _now_ms) -> dict:
    """Run every exam category once and return a mastery snapshot (not persisted).

    ``should_stop`` is polled between exams (Emergency Stop); a stopped run raises
    :class:`AssessmentStopped` and nothing is recorded.
    """
    started = clock()
    matrix = SecurityMasteryMatrix()
    exams: List[dict] = []
    for exam_id, (_mod, _fn, title) in EXAMS.items():
        if should_stop():
            raise AssessmentStopped("emergency stop engaged — assessment halted")
        domains = [d for d, e in DOMAIN_EXAMS.items() if e == exam_id]
        try:
            cat = run_exam(exam_id)
            results = list(cat.results)
            n_total, n_pass = len(results), int(cat.n_pass)
            failures = [str(getattr(r, "exam_id", "?")) for r in results
                        if not getattr(r, "passed", False)][:MAX_FAILURES_LISTED]
            error = None
        except Exception as exc:  # an exam that cannot run is a FAILED exam, not a pass
            n_total, n_pass, failures, error = 1, 0, [], f"{type(exc).__name__}: {exc}"
        for d in domains:
            matrix.update_domain(d, n_pass, n_total, evaluated_at_ms=started)
        exams.append({
            "exam_id": exam_id, "title": title,
            "n_pass": n_pass, "n_total": n_total,
            "domains": [d.value for d in domains],
            "failures": failures, "error": error,
        })
    gaps = [{
        "domain": g.domain.value,
        "accuracy": round(g.observed_accuracy, 4),
        "priority": g.priority,
        "description": g.description,
    } for g in matrix.identify_gaps(THRESHOLD)]
    return {
        "schema": SCHEMA,
        "assessed_at": started,
        "duration_ms": max(0, clock() - started),
        "exams": exams,
        "domains": _domain_rows(matrix),
        "gaps": gaps,
        # Every domain must be evaluated — the NO_EXAM ones keep this False.
        "graduation_ready": matrix.graduation_ready(threshold=THRESHOLD),
        "no_exam_domains": sorted(d.value for d in DOMAINS_WITHOUT_EXAM),
    }


class AssessmentStopped(RuntimeError):
    """Raised when Emergency Stop interrupts an assessment."""


class AssessmentBusy(RuntimeError):
    """Raised when an assessment is already running."""


class MasteryStore:
    """Atomic JSON persistence for the latest snapshot + a short history."""

    def __init__(self, path: os.PathLike | str):
        self.path = Path(path)
        self._lock = threading.Lock()

    def load(self) -> dict:
        """Return ``{"latest": snapshot|None, "history": [...]}``; never raises on a
        missing or corrupt file (a corrupt file reads as never-assessed)."""
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("schema") != SCHEMA:
                raise ValueError("unknown schema")
            latest = data.get("latest")
            history = data.get("history") or []
            if latest is not None and not isinstance(latest, dict):
                raise ValueError("bad latest")
            return {"latest": latest, "history": list(history)[-HISTORY_LIMIT:]}
        except (OSError, ValueError, TypeError):
            return {"latest": None, "history": []}

    def save(self, snapshot: dict) -> None:
        with self._lock:
            current = self.load()
            history = current["history"] + [{
                "assessed_at": snapshot.get("assessed_at"),
                "n_pass": sum(e["n_pass"] for e in snapshot.get("exams", [])),
                "n_total": sum(e["n_total"] for e in snapshot.get("exams", [])),
                "gaps": len(snapshot.get("gaps", [])),
            }]
            payload = {"schema": SCHEMA, "latest": snapshot,
                       "history": history[-HISTORY_LIMIT:]}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".learning-", dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2)
                os.replace(tmp, self.path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise


def study_resources() -> List[dict]:
    return [{
        "resource_id": r.resource_id, "domain": r.domain.value, "title": r.title,
        "description": r.description, "study_approach": r.study_approach,
        "data_source": r.data_source,
    } for r in STUDY_RESOURCES]


_RUN_LOCK = threading.Lock()


def assess_and_store(store: MasteryStore, *,
                     should_stop: Callable[[], bool] = lambda: False) -> dict:
    """Run one assessment (one at a time) and persist it; returns the snapshot."""
    if not _RUN_LOCK.acquire(blocking=False):
        raise AssessmentBusy("an assessment is already running")
    try:
        snapshot = run_assessment(should_stop=should_stop)
        store.save(snapshot)
        return snapshot
    finally:
        _RUN_LOCK.release()


__all__ = [
    "SCHEMA", "DATA_SOURCE", "AUTHORITY", "NOTE", "THRESHOLD",
    "EVALUATED", "NOT_EVALUATED", "NO_EXAM",
    "AssessmentBusy", "AssessmentStopped", "MasteryStore",
    "assess_and_store", "empty_snapshot", "run_assessment", "study_resources",
]
