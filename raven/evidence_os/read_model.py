"""Canonical Evidence read model — read-only projection over V5 ``recon.db``.

The canonical evidence store is the workspace ``recon.db`` (``evidence`` +
``relationships`` tables, written INSERT-only by ``CanonicalService`` via the
validated V5 ``EvidenceGraph``). The V7 ``evidence_os/graph.py`` SQLite graph
(``evidence_v7.db``) is DEPRECATED: it holds 0 nodes and has no production
writer. This module is the canonical *read* surface: it projects the real
``observations`` + ``findings`` + ``evidence`` rows into the typed-node shape the
V7 UI already expects (``{node_id, kind, label, is_advisory}``) and the
``relationships`` rows into edges.

Invariants:
- READ-ONLY. This module never writes ``recon.db`` (no INSERT/UPDATE/DELETE/DDL).
- ``is_advisory`` is always True on every projected node (EvidenceNode enforces
  it). A finding carries its own verified/review status in the findings table —
  this projection never fabricates or asserts a verdict.
- Defensive: a missing store, missing table or read error projects to empty,
  never raises, so the evidence endpoint degrades to ``{nodes:[], total:0}``
  instead of erroring.
"""
from __future__ import annotations

from typing import List, Optional

from .graph import EvidenceNode, EvidenceNodeKind

# Projection: canonical row type -> V7 typed node kind.
_OBS_KIND = EvidenceNodeKind.REQUEST    # an observation = one controlled HTTP exchange
_FIND_KIND = EvidenceNodeKind.FINDING   # a candidate finding (advisory; human verify)
_EV_KIND = EvidenceNodeKind.NOTE        # an evidence row (incl. researcher NOTE)


def _node(node_id, kind: EvidenceNodeKind, label) -> EvidenceNode:
    # EvidenceNode forces is_advisory=True and exposes to_dict() ->
    # {node_id, kind, label, is_advisory}; reuse it so the UI contract is honored.
    return EvidenceNode(node_id=str(node_id or ""), kind=kind, label=str(label or ""))


class EvidenceReadModel:
    """Read-only projection of the canonical ``recon.db`` evidence store.

    Construct per request with the active workspace store + its canonical
    workspace_id. ``list_nodes`` / ``count_nodes`` mirror the V7 reader contract
    (``workspace_id=``, ``kind=``, ``limit=``) so the evidence endpoint can call
    it exactly as it called the old graph — without the empty ``evidence_v7.db``.
    """

    def __init__(self, store, workspace_id: Optional[str] = None):
        self._store = store
        self._ws = workspace_id

    def _ws_for(self, workspace_id: Optional[str]) -> Optional[str]:
        return workspace_id or self._ws

    # ── nodes ────────────────────────────────────────────────────────────────
    def list_nodes(self, workspace_id: str = None, kind=None,
                   limit: int = 50) -> List[EvidenceNode]:
        ws = self._ws_for(workspace_id)
        if not self._store or not ws:
            return []
        try:
            cap = int(limit) if limit else 50
        except (TypeError, ValueError):
            cap = 50
        nodes: List[EvidenceNode] = []
        # Evidence rows first (most recent annotations, incl. researcher NOTEs).
        for r in self._evidence_rows(ws, cap):
            nodes.append(_node(r.get("id"), _EV_KIND,
                               r.get("summary") or r.get("kind") or "evidence"))
        for f in self._safe(lambda: self._store.get_findings(ws, limit=cap)):
            nodes.append(_node(f.get("id"), _FIND_KIND, f.get("title")))
        for o in self._safe(lambda: self._store.get_observations(ws, limit=cap)):
            label = (f"{o.get('method', '') or ''} {o.get('url', '') or ''}").strip()
            nodes.append(_node(o.get("id"), _OBS_KIND, label))
        if kind is not None:
            kv = getattr(kind, "value", kind)
            nodes = [n for n in nodes if n.kind.value == kv]
        return nodes[:cap]

    def count_nodes(self, workspace_id: str = None) -> int:
        ws = self._ws_for(workspace_id)
        if not self._store or not ws:
            return 0
        return (self._count("evidence", ws)
                + self._count("findings", ws)
                + self._count("observations", ws))

    # ── edges ────────────────────────────────────────────────────────────────
    def list_edges(self, workspace_id: str = None) -> list:
        ws = self._ws_for(workspace_id)
        if not self._store or not ws:
            return []
        return [dict(r) for r in self._safe(lambda: self._store.get_relationships(ws))]

    def count_edges(self, workspace_id: str = None) -> int:
        ws = self._ws_for(workspace_id)
        if not self._store or not ws:
            return 0
        return self._count("relationships", ws)

    # ── internal read helpers (defensive: store/table/error -> empty) ─────────
    @staticmethod
    def _safe(fn):
        try:
            return fn() or []
        except Exception:
            return []

    def _evidence_rows(self, ws: str, cap: int) -> list:
        db = getattr(self._store, "db", None)
        lock = getattr(self._store, "_lock", None)
        if db is None:
            return []
        sql = ("SELECT id, kind, summary FROM evidence WHERE workspace_id=? "
               "ORDER BY timestamp DESC LIMIT ?")
        try:
            if lock is not None:
                with lock:
                    rows = db.execute(sql, (ws, cap)).fetchall()
            else:
                rows = db.execute(sql, (ws, cap)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _count(self, table: str, ws: str) -> int:
        # ``table`` is only ever one of this module's fixed internal literals —
        # never request/user input — so the f-string is injection-safe.
        db = getattr(self._store, "db", None)
        lock = getattr(self._store, "_lock", None)
        if db is None:
            return 0
        sql = f"SELECT COUNT(*) FROM {table} WHERE workspace_id=?"
        try:
            if lock is not None:
                with lock:
                    row = db.execute(sql, (ws,)).fetchone()
            else:
                row = db.execute(sql, (ws,)).fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0
