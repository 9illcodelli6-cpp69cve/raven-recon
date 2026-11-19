"""Stage 6: Candidate finding generation tests.

Verifies that CandidateFindingGenerator always produces unverified findings
with uuid4 ids, correct defaults, and proper validation.
"""
import pytest

from raven.finding_generator import (
    CandidateFinding,
    CandidateFindingGenerator,
    FindingGenerationError,
    VALID_SEVERITIES,
)


@pytest.fixture
def gen():
    return CandidateFindingGenerator()


def _gen(gen, **kwargs):
    defaults = dict(
        workspace_id="ws123",
        title="Potential IDOR on /api/users",
        url="https://target.example/api/users/1",
        severity="high",
    )
    defaults.update(kwargs)
    return gen.generate(**defaults)


class TestCandidateFindingInvariants:

    def test_verification_status_always_unverified(self, gen):
        f = _gen(gen)
        assert f.verification_status == "unverified"

    def test_review_status_always_new(self, gen):
        f = _gen(gen)
        assert f.review_status == "new"

    def test_ml_probability_always_none(self, gen):
        f = _gen(gen)
        assert f.ml_probability is None

    def test_id_is_uuid4_hex(self, gen):
        f = _gen(gen)
        assert len(f.id) == 32
        assert all(c in "0123456789abcdef" for c in f.id)

    def test_two_findings_have_different_ids(self, gen):
        f1 = _gen(gen)
        f2 = _gen(gen)
        assert f1.id != f2.id

    def test_finding_is_candidate_finding_instance(self, gen):
        f = _gen(gen)
        assert isinstance(f, CandidateFinding)

    def test_verification_status_not_a_parameter(self, gen):
        # generate() signature must NOT accept verification_status
        import inspect
        sig = inspect.signature(gen.generate)
        assert "verification_status" not in sig.parameters

    def test_ml_probability_not_a_parameter(self, gen):
        import inspect
        sig = inspect.signature(gen.generate)
        assert "ml_probability" not in sig.parameters


class TestCandidateFindingValidation:

    def test_empty_workspace_id_raises(self, gen):
        with pytest.raises(FindingGenerationError, match="workspace_id"):
            _gen(gen, workspace_id="")

    def test_empty_title_raises(self, gen):
        with pytest.raises(FindingGenerationError, match="title"):
            _gen(gen, title="")

    def test_whitespace_title_raises(self, gen):
        with pytest.raises(FindingGenerationError, match="title"):
            _gen(gen, title="   ")

    def test_empty_url_raises(self, gen):
        with pytest.raises(FindingGenerationError, match="url"):
            _gen(gen, url="")

    def test_invalid_severity_raises(self, gen):
        with pytest.raises(FindingGenerationError, match="severity"):
            _gen(gen, severity="super_critical")

    def test_all_valid_severities_accepted(self, gen):
        for s in VALID_SEVERITIES:
            f = _gen(gen, severity=s)
            assert f.severity == s

    def test_title_stripped_of_whitespace(self, gen):
        f = _gen(gen, title="  IDOR  ")
        assert f.title == "IDOR"


class TestCandidateFindingFields:

    def test_optional_observation_id(self, gen):
        obs_id = "obs_" + "a" * 28
        f = _gen(gen, observation_id=obs_id)
        assert f.observation_id == obs_id

    def test_optional_asset_id(self, gen):
        f = _gen(gen, asset_id="asset123")
        assert f.asset_id == "asset123"

    def test_evidence_ids_list(self, gen):
        ev_ids = ["ev1", "ev2", "ev3"]
        f = _gen(gen, evidence_ids=ev_ids)
        assert f.evidence_ids == ev_ids

    def test_default_evidence_ids_empty(self, gen):
        f = _gen(gen)
        assert f.evidence_ids == []

    def test_description_and_remediation(self, gen):
        f = _gen(gen, description="Details here", remediation="Fix it")
        assert f.description == "Details here"
        assert f.remediation == "Fix it"

    def test_timestamps_present(self, gen):
        f = _gen(gen)
        assert f.created_at
        assert f.updated_at
        assert "T" in f.created_at


class TestToDbRow:

    def test_db_row_has_required_keys(self, gen):
        f = _gen(gen)
        row = gen.to_db_row(f)
        required = {"id", "workspace_id", "title", "url", "severity",
                    "created_at", "updated_at", "verification_status",
                    "review_status", "ml_probability"}
        assert required.issubset(row.keys())

    def test_db_row_verification_status_unverified(self, gen):
        f = _gen(gen)
        row = gen.to_db_row(f)
        assert row["verification_status"] == "unverified"

    def test_db_row_ml_probability_none(self, gen):
        f = _gen(gen)
        row = gen.to_db_row(f)
        assert row["ml_probability"] is None
