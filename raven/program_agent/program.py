"""RAVEN V7 Bug Bounty Program Store — Part 08."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

from .policy import ProgramPolicy, ProgramScope, ScopeItem, ScopeType


# ── policy (de)serialization ───────────────────────────────────────────────────
# ``ProgramPolicy.to_dict`` (policy.py — READ-ONLY, must not be edited) is lossy by
# design: it emits only ``in_scope_count`` and drops the actual scope items + the
# rule fields. Persisting that made a reloaded program lose its scope, so
# ``ProgramScope.is_in_scope`` returned False for everything (A11-PROGRAM audit;
# AGENT_ARCHITECTURE §1.2 program.py note). These helpers serialize the FULL,
# round-trippable policy WITHOUT editing policy.py, and restore it fail-closed.

def _scope_items_to_list(scope: ProgramScope) -> list:
    items = []
    for it in getattr(scope, "items", []) or []:
        st = it.scope_type
        items.append({
            "value": it.value,
            "scope_type": st.value if hasattr(st, "value") else str(st),
            "in_scope": bool(it.in_scope),
            "notes": it.notes or "",
        })
    return items


def _policy_to_full_dict(policy: ProgramPolicy) -> dict:
    """Round-trippable policy payload (additive superset of the lossy to_dict)."""
    return {
        "program_id": policy.program_id,
        "name": policy.name,
        "platform": policy.platform,
        "max_severity": policy.max_severity,
        "rate_limit_rps": policy.rate_limit_rps,
        "requires_account": policy.requires_account,
        "notes": policy.notes,
        "external_targets": 0,                       # INVARIANT, never persisted as != 0
        "scope_items": _scope_items_to_list(policy.scope),
        "in_scope_count": policy.scope.in_scope_count(),   # keep the legacy shallow key
    }


def _policy_from_dict(data: dict) -> Optional[ProgramPolicy]:
    """Reconstruct a ProgramPolicy, restoring full scope. FAIL-CLOSED: a missing or
    corrupt scope payload yields an EMPTY scope (deny-all) — never a silently widened
    or partially-trusted scope. Tolerates the legacy shallow rows (no ``scope_items``),
    which load with an empty scope (safe)."""
    if not data or not data.get("program_id"):
        return None
    scope = ProgramScope()
    try:
        for raw in (data.get("scope_items") or []):
            try:
                st_enum = ScopeType(raw.get("scope_type", "domain"))
            except ValueError:
                st_enum = ScopeType.DOMAIN
            scope.items.append(ScopeItem(
                value=raw.get("value", ""),
                scope_type=st_enum,
                in_scope=bool(raw.get("in_scope", True)),
                notes=raw.get("notes", "") or "",
            ))
    except Exception:
        scope = ProgramScope()   # fail-closed: deny-all rather than trust a bad payload
    policy = ProgramPolicy(
        program_id=data.get("program_id", ""),
        name=data.get("name", ""),
        platform=data.get("platform", ""),
        scope=scope,
    )
    # Restore rule fields when present (backward compatible). external_targets is
    # immutable (always 0) and is never assigned here.
    try:
        if data.get("rate_limit_rps") is not None:
            policy.rate_limit_rps = float(data["rate_limit_rps"])
    except (TypeError, ValueError):
        pass
    if data.get("max_severity"):
        policy.max_severity = data["max_severity"]
    if "requires_account" in data:
        policy.requires_account = bool(data["requires_account"])
    if data.get("notes"):
        policy.notes = data["notes"]
    return policy


@dataclass
class BugBountyProgram:
    program_id:   str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    workspace_id: str = "default"
    policy:       Optional[ProgramPolicy] = None
    created_at:   int = field(default_factory=lambda: int(time.time() * 1000))
    active:       bool = True

    def to_dict(self) -> dict:
        return {
            "program_id": self.program_id,
            "workspace_id": self.workspace_id,
            "policy": self.policy.to_dict() if self.policy else None,
            "active": self.active,
        }


class ProgramStore:
    """Persists bug bounty programs to SQLite."""

    def __init__(self, db: sqlite3.Connection):
        self._db   = db
        self._lock = threading.RLock()
        self._migrate()

    def _migrate(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_programs (
            program_id   TEXT PRIMARY KEY,
            workspace_id TEXT,
            policy_json  TEXT,
            created_at   INTEGER,
            active       INTEGER DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS v7_programs_ws ON v7_programs(workspace_id);
        """)
        self._db.commit()

    def save(self, program: BugBountyProgram) -> str:
        if program.policy is not None:
            try:
                policy_json = json.dumps(_policy_to_full_dict(program.policy))
            except Exception:
                # Fail-closed: if the scope cannot be serialized correctly, persist an
                # explicit empty-scope policy so a reload DENIES all targets rather than
                # trusting a lossy/partial scope.
                policy_json = json.dumps({
                    "program_id": getattr(program.policy, "program_id", ""),
                    "name": getattr(program.policy, "name", ""),
                    "platform": getattr(program.policy, "platform", ""),
                    "scope_items": [], "external_targets": 0,
                })
        else:
            policy_json = "{}"
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO v7_programs VALUES (?,?,?,?,?)",
                (program.program_id, program.workspace_id, policy_json,
                 program.created_at, 1 if program.active else 0),
            )
            self._db.commit()
        return program.program_id

    def list_active(self, workspace_id: str = None) -> List[BugBountyProgram]:
        with self._lock:
            if workspace_id:
                rows = self._db.execute(
                    "SELECT * FROM v7_programs WHERE workspace_id=? AND active=1",
                    (workspace_id,),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM v7_programs WHERE active=1",
                ).fetchall()
        result = []
        for r in rows:
            try:
                policy_data = json.loads(r["policy_json"] or "{}")
            except (ValueError, TypeError):
                policy_data = {}
            policy = _policy_from_dict(policy_data)   # full scope restored, fail-closed
            result.append(BugBountyProgram(
                program_id=r["program_id"],
                workspace_id=r["workspace_id"] or "default",
                policy=policy,
                created_at=r["created_at"] or 0,
                active=bool(r["active"]),
            ))
        return result

    def count(self, workspace_id: str = None) -> int:
        with self._lock:
            if workspace_id:
                row = self._db.execute(
                    "SELECT COUNT(*) FROM v7_programs WHERE workspace_id=?",
                    (workspace_id,),
                ).fetchone()
            else:
                row = self._db.execute("SELECT COUNT(*) FROM v7_programs").fetchone()
        return row[0] if row else 0
