"""Evidence Graph — provenance graph with closed relation vocabulary.

EvidenceGraph manages nodes (findings, observations, evidence rows) and
edges (relationships table) using uuid4 identity. Node identity is uuid4 hex,
never title or URL.

INVARIANT: Only relations from VALID_RELATIONS may be stored.
           All node references use uuid4 hex (never mutable attributes).

Design reference: blueprint Stage 8, Category 5 (evidence integrity).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


# Closed relation vocabulary — only these strings may appear in relationships.relation
VALID_RELATIONS = frozenset({
    "supports",
    "contradicts",
    "derived_from",
    "corroborates",
    "supersedes",
    "linked_to",
    "triggered_by",
    "evidence_for",
})

VALID_NODE_TYPES = frozenset({
    "finding",
    "observation",
    "evidence",
    "asset",
    "workspace",
    "payload",
})


class EvidenceGraphError(Exception):
    """Raised when an EvidenceGraph operation violates a constraint."""


@dataclass
class GraphEdge:
    """A directed relationship between two graph nodes."""
    id: str
    workspace_id: str
    from_type: str
    from_id: str
    to_type: str
    to_id: str
    relation: str
    confidence: float = 1.0
    source: Optional[str] = None
    timestamp: Optional[str] = None


class EvidenceGraph:
    """In-process evidence graph with uuid4 node identity.

    Edges are validated before addition:
    - relation must be in VALID_RELATIONS
    - from_type and to_type must be in VALID_NODE_TYPES
    - node ids must be non-empty strings (uuid4 hex expected)

    This class does not manage persistence — callers persist edges via Store.
    """

    def __init__(self, workspace_id: str):
        if not workspace_id:
            raise EvidenceGraphError("workspace_id required")
        self.workspace_id = workspace_id
        self._edges: list[GraphEdge] = []
        self._nodes: dict[str, str] = {}  # id → node_type

    def add_node(self, node_id: str, node_type: str) -> None:
        if not node_id:
            raise EvidenceGraphError("node_id must not be empty")
        if node_type not in VALID_NODE_TYPES:
            raise EvidenceGraphError(
                f"node_type {node_type!r} not in VALID_NODE_TYPES: {sorted(VALID_NODE_TYPES)}"
            )
        self._nodes[node_id] = node_type

    def add_edge(
        self,
        from_id: str,
        from_type: str,
        to_id: str,
        to_type: str,
        relation: str,
        confidence: float = 1.0,
        source: Optional[str] = None,
    ) -> GraphEdge:
        """Create and store a directed edge.

        Both from_id and to_id must be previously registered via add_node
        (or present as implicit nodes). relation must be in VALID_RELATIONS.
        """
        if not from_id or not to_id:
            raise EvidenceGraphError("Edge node ids must not be empty")
        if from_type not in VALID_NODE_TYPES:
            raise EvidenceGraphError(f"from_type {from_type!r} not valid")
        if to_type not in VALID_NODE_TYPES:
            raise EvidenceGraphError(f"to_type {to_type!r} not valid")
        if relation not in VALID_RELATIONS:
            raise EvidenceGraphError(
                f"relation {relation!r} not in VALID_RELATIONS: {sorted(VALID_RELATIONS)}"
            )
        if not 0.0 <= confidence <= 1.0:
            raise EvidenceGraphError(f"confidence must be in [0,1], got {confidence}")
        edge = GraphEdge(
            id=uuid.uuid4().hex,
            workspace_id=self.workspace_id,
            from_type=from_type,
            from_id=from_id,
            to_type=to_type,
            to_id=to_id,
            relation=relation,
            confidence=confidence,
            source=source,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
        )
        self._edges.append(edge)
        return edge

    def edges_from(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self._edges if e.from_id == node_id]

    def edges_to(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self._edges if e.to_id == node_id]

    def edges_by_relation(self, relation: str) -> list[GraphEdge]:
        return [e for e in self._edges if e.relation == relation]

    def all_edges(self) -> list[GraphEdge]:
        return list(self._edges)

    def edge_to_db_row(self, edge: GraphEdge) -> dict:
        return {
            "id": edge.id,
            "workspace_id": edge.workspace_id,
            "from_type": edge.from_type,
            "from_id": edge.from_id,
            "to_type": edge.to_type,
            "to_id": edge.to_id,
            "relation": edge.relation,
            "confidence": edge.confidence,
            "source": edge.source,
            "timestamp": edge.timestamp,
        }
