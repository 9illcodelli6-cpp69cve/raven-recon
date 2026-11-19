"""RAVEN V7 Part 07 — Security Research Engine Tests."""
import sqlite3
import pytest


def fresh_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db


# ── Candidate Finding invariants ──────────────────────────────────────────────

class TestCandidateFinding:
    def test_human_verification_always_true(self):
        from raven.research_engine.finding import CandidateFinding
        f = CandidateFinding(human_verification_required=False)
        assert f.human_verification_required is True

    def test_human_verification_immutable(self):
        from raven.research_engine.finding import CandidateFinding
        f = CandidateFinding(title="test")
        with pytest.raises(AttributeError):
            f.human_verification_required = False

    def test_security_authority_always_none(self):
        from raven.research_engine.finding import CandidateFinding
        f = CandidateFinding(security_authority="ADMIN")
        assert f.security_authority == "NONE"

    def test_security_authority_immutable(self):
        from raven.research_engine.finding import CandidateFinding
        f = CandidateFinding()
        with pytest.raises(AttributeError):
            f.security_authority = "ADMIN"

    def test_is_verified_always_false(self):
        from raven.research_engine.finding import CandidateFinding
        f = CandidateFinding(is_verified=True)
        assert f.is_verified is False

    def test_is_verified_immutable(self):
        from raven.research_engine.finding import CandidateFinding
        f = CandidateFinding()
        with pytest.raises(AttributeError):
            f.is_verified = True

    def test_bola_is_conceptual_label(self):
        from raven.research_engine.finding import CandidateFinding, FindingCategory
        f = CandidateFinding(category=FindingCategory.BOLA, title="Potential BOLA")
        # BOLA is just a label — never a confirmed finding
        assert f.category == FindingCategory.BOLA
        assert f.is_verified is False
        assert f.human_verification_required is True

    def test_to_dict(self):
        from raven.research_engine.finding import CandidateFinding, FindingCategory
        f = CandidateFinding(title="Test", category=FindingCategory.XSS)
        d = f.to_dict()
        assert d["human_verification_required"] is True
        assert d["security_authority"] == "NONE"
        assert d["is_verified"] is False


# ── Experiment ────────────────────────────────────────────────────────────────

class TestExperiment:
    def test_experiment_result_invariant(self):
        from raven.research_engine.experiment import ExperimentResult, ExperimentStatus
        r = ExperimentResult(
            experiment_id="e1",
            status=ExperimentStatus.COMPLETED,
            human_verification_required=False,
        )
        assert r.human_verification_required is True

    def test_experiment_to_dict(self):
        from raven.research_engine.experiment import Experiment, ExperimentStatus
        e = Experiment(title="Test probe", target_url="https://api.example.com")
        d = e.to_dict()
        assert d["title"] == "Test probe"
        assert d["status"] == ExperimentStatus.PENDING.value

    def test_add_step(self):
        from raven.research_engine.experiment import Experiment, ExperimentStep
        e = Experiment(title="probe")
        e.add_step(ExperimentStep(url="https://x.com/api", method="GET"))
        assert len(e.steps) == 1


# ── Scientific Critic ─────────────────────────────────────────────────────────

class TestScientificCritic:
    def test_complete_finding_scores_high(self):
        from raven.research_engine.critic import ScientificCritic
        from raven.research_engine.finding import CandidateFinding, FindingCategory, FindingSeverity
        critic = ScientificCritic()
        f = CandidateFinding(
            title="Test BOLA",
            description="User A can access User B's resources via /api/v1/users/{id}",
            category=FindingCategory.BOLA,
            severity=FindingSeverity.HIGH,
            endpoint="/api/v1/users/456",
            evidence_ref=["traffic-entry-abc"],
        )
        result = critic.critique_finding(f)
        assert result.score >= 0.7
        assert result.is_advisory is True

    def test_empty_finding_scores_low(self):
        from raven.research_engine.critic import ScientificCritic
        from raven.research_engine.finding import CandidateFinding
        critic = ScientificCritic()
        f = CandidateFinding()
        result = critic.critique_finding(f)
        assert result.score < 0.5
        assert len(result.concerns) > 0

    def test_critique_result_is_advisory(self):
        from raven.research_engine.critic import CritiqueResult
        r = CritiqueResult(target_id="x", score=0.5, is_advisory=False)
        assert r.is_advisory is True

    def test_quality_labels(self):
        from raven.research_engine.critic import CritiqueResult
        assert CritiqueResult(target_id="x", score=0.9).quality == "HIGH"
        assert CritiqueResult(target_id="x", score=0.6).quality == "MEDIUM"
        assert CritiqueResult(target_id="x", score=0.3).quality == "LOW"


# ── Research Engine ───────────────────────────────────────────────────────────

class TestResearchEngine:
    def test_add_and_list_findings(self):
        from raven.research_engine.engine import ResearchEngine
        from raven.research_engine.finding import CandidateFinding, FindingCategory
        engine = ResearchEngine(db=fresh_db())
        f = CandidateFinding(
            title="Potential IDOR",
            category=FindingCategory.IDOR,
            endpoint="/api/v1/users/123",
            workspace_id="ws1",
        )
        engine.add_finding(f)
        findings = engine.list_findings(workspace_id="ws1")
        assert len(findings) == 1
        assert findings[0].title == "Potential IDOR"

    def test_count_findings(self):
        from raven.research_engine.engine import ResearchEngine
        from raven.research_engine.finding import CandidateFinding
        engine = ResearchEngine(db=fresh_db())
        for i in range(3):
            engine.add_finding(CandidateFinding(title=f"finding {i}", workspace_id="ws1"))
        assert engine.count_findings(workspace_id="ws1") == 3

    def test_get_finding(self):
        from raven.research_engine.engine import ResearchEngine
        from raven.research_engine.finding import CandidateFinding
        engine = ResearchEngine(db=fresh_db())
        f = CandidateFinding(title="Test")
        engine.add_finding(f)
        retrieved = engine.get_finding(f.finding_id)
        assert retrieved is not None
        assert retrieved.finding_id == f.finding_id

    def test_critique_via_engine(self):
        from raven.research_engine.engine import ResearchEngine
        from raven.research_engine.finding import CandidateFinding
        engine = ResearchEngine(db=fresh_db())
        f = CandidateFinding()
        result = engine.critique(f)
        assert result.is_advisory is True


# ── Tool Registration ─────────────────────────────────────────────────────────

class TestResearchToolRegistration:
    def test_register_tools(self):
        from raven.research_engine.registry import register_research_tools
        from raven.runtime.tools import ToolRegistry
        registry = ToolRegistry()
        count = register_research_tools(registry)
        assert count >= 4
        ids = [t.tool_id for t in registry.list_all()]
        assert "research.finding.add" in ids
        assert "research.experiment.run" in ids
