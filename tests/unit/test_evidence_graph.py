"""Stage 8: Evidence graph tests (Category 5 — evidence integrity).

Verifies uuid4 node identity, closed relation vocabulary, edge provenance,
and query operations.
"""
import pytest

from raven.evidence_graph import (
    EvidenceGraph,
    EvidenceGraphError,
    GraphEdge,
    VALID_RELATIONS,
    VALID_NODE_TYPES,
)


@pytest.fixture
def graph():
    return EvidenceGraph(workspace_id="ws_abc123")


def _add_finding(graph, fid="finding001"):
    graph.add_node(fid, "finding")
    return fid


def _add_obs(graph, oid="obs001"):
    graph.add_node(oid, "observation")
    return oid


class TestGraphConstruction:

    def test_empty_workspace_raises(self):
        with pytest.raises(EvidenceGraphError):
            EvidenceGraph(workspace_id="")

    def test_workspace_id_stored(self, graph):
        assert graph.workspace_id == "ws_abc123"

    def test_initial_no_edges(self, graph):
        assert len(graph.all_edges()) == 0

    def test_add_node_valid_types(self, graph):
        for nt in VALID_NODE_TYPES:
            graph.add_node(f"node_{nt}", nt)

    def test_add_node_invalid_type_raises(self, graph):
        with pytest.raises(EvidenceGraphError):
            graph.add_node("n1", "unknown_type")

    def test_add_node_empty_id_raises(self, graph):
        with pytest.raises(EvidenceGraphError):
            graph.add_node("", "finding")


class TestEdgeAddition:

    def test_add_valid_edge(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        edge = graph.add_edge(fid, "finding", oid, "observation", "supports")
        assert isinstance(edge, GraphEdge)
        assert edge.relation == "supports"

    def test_edge_id_is_uuid4_hex(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        edge = graph.add_edge(fid, "finding", oid, "observation", "supports")
        assert len(edge.id) == 32
        assert all(c in "0123456789abcdef" for c in edge.id)

    def test_two_edges_different_ids(self, graph):
        fid = _add_finding(graph)
        oid1 = _add_obs(graph, "obs001")
        oid2 = _add_obs(graph, "obs002")
        e1 = graph.add_edge(fid, "finding", oid1, "observation", "supports")
        e2 = graph.add_edge(fid, "finding", oid2, "observation", "corroborates")
        assert e1.id != e2.id

    def test_invalid_relation_raises(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        with pytest.raises(EvidenceGraphError, match="relation"):
            graph.add_edge(fid, "finding", oid, "observation", "CONFIRMS_VULN")

    def test_invalid_from_type_raises(self, graph):
        with pytest.raises(EvidenceGraphError):
            graph.add_edge("n1", "hacker", "n2", "finding", "supports")

    def test_invalid_to_type_raises(self, graph):
        with pytest.raises(EvidenceGraphError):
            graph.add_edge("n1", "finding", "n2", "hacker", "supports")

    def test_empty_from_id_raises(self, graph):
        with pytest.raises(EvidenceGraphError):
            graph.add_edge("", "finding", "n2", "observation", "supports")

    def test_confidence_out_of_range_raises(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        with pytest.raises(EvidenceGraphError, match="confidence"):
            graph.add_edge(fid, "finding", oid, "observation", "supports", confidence=1.5)

    def test_confidence_zero_allowed(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        edge = graph.add_edge(fid, "finding", oid, "observation", "supports", confidence=0.0)
        assert edge.confidence == 0.0

    def test_all_valid_relations_accepted(self, graph):
        fid = _add_finding(graph)
        for i, rel in enumerate(VALID_RELATIONS):
            oid = f"obs_{i}"
            graph.add_node(oid, "observation")
            edge = graph.add_edge(fid, "finding", oid, "observation", rel)
            assert edge.relation == rel

    def test_edge_timestamp_present(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        edge = graph.add_edge(fid, "finding", oid, "observation", "supports")
        assert edge.timestamp and "T" in edge.timestamp

    def test_edge_workspace_id_matches(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        edge = graph.add_edge(fid, "finding", oid, "observation", "supports")
        assert edge.workspace_id == "ws_abc123"


class TestEdgeQueries:

    def test_edges_from(self, graph):
        fid = _add_finding(graph)
        oid1 = _add_obs(graph, "o1")
        oid2 = _add_obs(graph, "o2")
        graph.add_edge(fid, "finding", oid1, "observation", "supports")
        graph.add_edge(fid, "finding", oid2, "observation", "corroborates")
        graph.add_edge(oid1, "observation", oid2, "observation", "linked_to")
        result = graph.edges_from(fid)
        assert len(result) == 2
        assert all(e.from_id == fid for e in result)

    def test_edges_to(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        ev_id = "ev001"
        graph.add_node(ev_id, "evidence")
        graph.add_edge(fid, "finding", oid, "observation", "supports")
        graph.add_edge(ev_id, "evidence", oid, "observation", "corroborates")
        result = graph.edges_to(oid)
        assert len(result) == 2

    def test_edges_by_relation(self, graph):
        fid = _add_finding(graph)
        oid1 = _add_obs(graph, "o1")
        oid2 = _add_obs(graph, "o2")
        graph.add_edge(fid, "finding", oid1, "observation", "supports")
        graph.add_edge(fid, "finding", oid2, "observation", "contradicts")
        supports = graph.edges_by_relation("supports")
        contradicts = graph.edges_by_relation("contradicts")
        assert len(supports) == 1
        assert len(contradicts) == 1

    def test_all_edges_returns_all(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        graph.add_edge(fid, "finding", oid, "observation", "supports")
        graph.add_edge(fid, "finding", oid, "observation", "corroborates")
        assert len(graph.all_edges()) == 2


class TestEdgeToDbRow:

    def test_db_row_keys(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        edge = graph.add_edge(fid, "finding", oid, "observation", "supports")
        row = graph.edge_to_db_row(edge)
        required = {"id", "workspace_id", "from_type", "from_id",
                    "to_type", "to_id", "relation", "confidence",
                    "source", "timestamp"}
        assert required.issubset(row.keys())

    def test_db_row_values_match_edge(self, graph):
        fid = _add_finding(graph)
        oid = _add_obs(graph)
        edge = graph.add_edge(fid, "finding", oid, "observation", "evidence_for", confidence=0.9)
        row = graph.edge_to_db_row(edge)
        assert row["relation"] == "evidence_for"
        assert row["confidence"] == 0.9
        assert row["from_id"] == fid
        assert row["to_id"] == oid


class TestClosedVocabulary:

    def test_valid_relations_is_frozenset(self):
        assert isinstance(VALID_RELATIONS, frozenset)

    def test_valid_node_types_is_frozenset(self):
        assert isinstance(VALID_NODE_TYPES, frozenset)

    def test_ad_hoc_relation_not_in_vocabulary(self):
        assert "PROVEN_IDOR" not in VALID_RELATIONS
        assert "CONFIRMED_BUG" not in VALID_RELATIONS
