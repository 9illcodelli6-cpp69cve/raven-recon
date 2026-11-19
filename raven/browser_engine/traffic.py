"""RAVEN V7 Traffic Recorder — Part 05.

DEPRECATED / UNWIRED (see raven/browser_engine/__init__.py). This recorder creates
its OWN v7_traffic_sessions / v7_traffic_entries tables — a SECOND, competing
traffic store. The canonical one traffic model is the `observations` table written
by CanonicalService.record_send_result and projected for the UI by
raven.api.traffic.TrafficEntry (GET /api/v7/traffic). DATA CHECK (Wave 8): no
production/dist DB holds any v7_traffic_* rows (this class is only instantiated by
the legacy test), so nothing to migrate. Kept importable; do NOT wire it in.

Records HTTP sessions for later replay and analysis.
Stored in SQLite via the runtime DB.
Sensitive headers (Authorization, Cookie, Set-Cookie) are redacted before storage.
"""
from __future__ import annotations

__deprecated__ = True
__canonical_replacement__ = (
    "observations table + raven.api.traffic (GET /api/v7/traffic)"
)

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .http_client import HttpRequest, HttpResponse

_REDACTED_HEADERS = frozenset({"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"})


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {
        k: ("[REDACTED]" if k.lower() in _REDACTED_HEADERS else v)
        for k, v in headers.items()
    }


@dataclass
class TrafficEntry:
    entry_id:    str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    session_id:  str = ""
    workspace_id: str = "default"
    url:         str = ""
    method:      str = "GET"
    request_headers:  Dict = field(default_factory=dict)
    request_body_len: int = 0
    status_code: int = 0
    response_headers: Dict = field(default_factory=dict)
    response_body:    str = ""    # truncated, safe for storage
    duration_ms: int = 0
    recorded_at: int = field(default_factory=lambda: int(time.time() * 1000))
    notes:       str = ""

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "session_id": self.session_id,
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "duration_ms": self.duration_ms,
            "recorded_at": self.recorded_at,
        }


@dataclass
class TrafficSession:
    session_id:   str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    workspace_id: str = "default"
    name:         str = ""
    created_at:   int = field(default_factory=lambda: int(time.time() * 1000))
    entry_count:  int = 0


class TrafficRecorder:
    """Records HTTP traffic to SQLite for replay and analysis."""

    def __init__(self, db: sqlite3.Connection):
        self._db   = db
        self._lock = threading.RLock()
        self._migrate()

    def _migrate(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_traffic_sessions (
            session_id   TEXT PRIMARY KEY,
            workspace_id TEXT,
            name         TEXT,
            created_at   INTEGER
        );
        CREATE TABLE IF NOT EXISTS v7_traffic_entries (
            entry_id          TEXT PRIMARY KEY,
            session_id        TEXT,
            workspace_id      TEXT,
            url               TEXT,
            method            TEXT,
            req_headers_json  TEXT,
            req_body_len      INTEGER,
            status_code       INTEGER,
            resp_headers_json TEXT,
            resp_body         TEXT,
            duration_ms       INTEGER,
            recorded_at       INTEGER,
            notes             TEXT
        );
        CREATE INDEX IF NOT EXISTS v7_traffic_session ON v7_traffic_entries(session_id);
        """)
        self._db.commit()

    def new_session(self, workspace_id: str = "default", name: str = "") -> TrafficSession:
        session = TrafficSession(workspace_id=workspace_id, name=name)
        with self._lock:
            self._db.execute(
                "INSERT INTO v7_traffic_sessions VALUES (?,?,?,?)",
                (session.session_id, workspace_id, name, session.created_at),
            )
            self._db.commit()
        return session

    def record(self, session_id: str, request: HttpRequest, response: HttpResponse) -> TrafficEntry:
        entry = TrafficEntry(
            session_id=session_id,
            url=request.url,
            method=request.method,
            request_headers=_redact_headers(request.headers),
            request_body_len=len(request.body) if request.body else 0,
            status_code=response.status_code,
            response_headers=_redact_headers(response.headers),
            response_body=response.body_text[:4096],   # truncate for storage
            duration_ms=response.duration_ms,
        )
        with self._lock:
            self._db.execute(
                """INSERT INTO v7_traffic_entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    entry.entry_id, session_id, entry.workspace_id,
                    entry.url, entry.method,
                    json.dumps(entry.request_headers), entry.request_body_len,
                    entry.status_code,
                    json.dumps(entry.response_headers), entry.response_body,
                    entry.duration_ms, entry.recorded_at, entry.notes,
                ),
            )
            self._db.commit()
        return entry

    def list_entries(self, session_id: str, limit: int = 100) -> List[TrafficEntry]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM v7_traffic_entries WHERE session_id=? ORDER BY recorded_at LIMIT ?",
                (session_id, limit),
            ).fetchall()
        result = []
        for r in rows:
            result.append(TrafficEntry(
                entry_id=r["entry_id"],
                session_id=r["session_id"] or "",
                url=r["url"] or "",
                method=r["method"] or "GET",
                status_code=r["status_code"] or 0,
                duration_ms=r["duration_ms"] or 0,
                recorded_at=r["recorded_at"] or 0,
                notes=r["notes"] or "",
            ))
        return result

    def count(self, session_id: str) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) FROM v7_traffic_entries WHERE session_id=?",
                (session_id,),
            ).fetchone()
        return row[0] if row else 0
