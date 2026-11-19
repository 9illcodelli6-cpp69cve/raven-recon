"""RAVEN V7 Evidence Graph — Part 10.

Directed graph linking requests, responses, findings, and screenshots
as evidence nodes. All nodes carry is_advisory=True (never auto-confirmed).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class EvidenceNodeKind(str, Enum):
    REQUEST    = "request"
    RESPONSE   = "response"
    SCREENSHOT = "screenshot"
    NOTE       = "note"
    FINDING    = "finding"
    EXPERIMENT = "experiment"


@dataclass
class EvidenceNode:
    node_id:      str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    kind:         EvidenceNodeKind = EvidenceNodeKind.NOTE
    label:        str = ""
    data:         dict = field(default_factory=dict)
    workspace_id: str = "default"
    created_at:   int = field(default_factory=lambda: int(time.time() * 1000))
    is_advisory:  bool = True   # INVARIANT: always True

    def __post_init__(self):
        object.__setattr__(self, "is_advisory", True)

    def __setattr__(self, name: str, value):
        if name == "is_advisory" and "is_advisory" in self.__dict__:
            raise AttributeError("is_advisory is immutable — evidence is always advisory")
        object.__setattr__(self, name, value)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "label": self.label,
            "is_advisory": True,
        }


@dataclass
class EvidenceEdge:
    edge_id:   str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    src_id:    str = ""
    dst_id:    str = ""
    relation:  str = "supports"   # supports | contradicts | follows | contains
    weight:    float = 1.0


class EvidenceGraph:
    """SQLite-backed directed graph of evidence nodes and edges."""

    def __init__(self, db: sqlite3.Connection):
        self._db   = db
        self._lock = threading.RLock()
        self._migrate()

    def _migrate(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_evidence_nodes (
            node_id      TEXT PRIMARY KEY,
            kind         TEXT,
            label        TEXT,
            data_json    TEXT,
            workspace_id TEXT,
            created_at   INTEGER
        );
        CREATE TABLE IF NOT EXISTS v7_evidence_edges (
            edge_id   TEXT PRIMARY KEY,
            src_id    TEXT,
            dst_id    TEXT,
            relation  TEXT,
            weight    REAL
        );
        CREATE INDEX IF NOT EXISTS v7_ev_ws   ON v7_evidence_nodes(workspace_id);
        CREATE INDEX IF NOT EXISTS v7_ev_kind ON v7_evidence_nodes(kind);
        CREATE INDEX IF NOT EXISTS v7_ee_src  ON v7_evidence_edges(src_id);
        CREATE INDEX IF NOT EXISTS v7_ee_dst  ON v7_evidence_edges(dst_id);
        """)
        self._db.commit()

    def add_node(self, node: EvidenceNode) -> str:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO v7_evidence_nodes VALUES (?,?,?,?,?,?)",
                (node.node_id, node.kind.value, node.label,
                 json.dumps(node.data), node.workspace_id, node.created_at),
            )
            self._db.commit()
        return node.node_id

    def add_edge(self, edge: EvidenceEdge) -> str:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO v7_evidence_edges VALUES (?,?,?,?,?)",
                (edge.edge_id, edge.src_id, edge.dst_id, edge.relation, edge.weight),
            )
            self._db.commit()
        return edge.edge_id

    def get_node(self, node_id: str) -> Optional[EvidenceNode]:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM v7_evidence_nodes WHERE node_id=?", (node_id,)
            ).fetchone()
        return self._row_to_node(row) if row else None

    def get_neighbors(self, node_id: str, relation: str = None) -> List[EvidenceNode]:
        with self._lock:
            if relation:
                rows = self._db.execute(
                    """SELECT n.* FROM v7_evidence_nodes n
                       JOIN v7_evidence_edges e ON n.node_id = e.dst_id
                       WHERE e.src_id=? AND e.relation=?""",
                    (node_id, relation),
                ).fetchall()
            else:
                rows = self._db.execute(
                    """SELECT n.* FROM v7_evidence_nodes n
                       JOIN v7_evidence_edges e ON n.node_id = e.dst_id
                       WHERE e.src_id=?""",
                    (node_id,),
                ).fetchall()
        return [self._row_to_node(r) for r in rows]

    def list_nodes(
        self, workspace_id: str = None, kind: EvidenceNodeKind = None,
        limit: int = None,
    ) -> List[EvidenceNode]:
        # ``limit`` is accepted (optional) so callers that bound the result set
        # — e.g. api_evidence_list(server.py) which passes ``limit=50`` — do not
        # raise TypeError. Omitting it keeps the full-list behaviour (kind= path
        # used by the Part-10/12 tests) unchanged.
        clauses, params = [], []
        if workspace_id:
            clauses.append("workspace_id=?"); params.append(workspace_id)
        if kind:
            clauses.append("kind=?"); params.append(kind.value)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM v7_evidence_nodes {where} ORDER BY created_at DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params = params + [int(limit)]
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return [self._row_to_node(r) for r in rows]

    def count_nodes(self, workspace_id: str = None) -> int:
        with self._lock:
            if workspace_id:
                row = self._db.execute(
                    "SELECT COUNT(*) FROM v7_evidence_nodes WHERE workspace_id=?",
                    (workspace_id,),
                ).fetchone()
            else:
                row = self._db.execute(
                    "SELECT COUNT(*) FROM v7_evidence_nodes"
                ).fetchone()
        return row[0] if row else 0

    def count_edges(self) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) FROM v7_evidence_edges"
            ).fetchone()
        return row[0] if row else 0

    def _row_to_node(self, r) -> EvidenceNode:
        return EvidenceNode(
            node_id=r["node_id"],
            kind=EvidenceNodeKind(r["kind"]) if r["kind"] else EvidenceNodeKind.NOTE,
            label=r["label"] or "",
            data=json.loads(r["data_json"] or "{}"),
            workspace_id=r["workspace_id"] or "default",
            created_at=r["created_at"] or 0,
        )
