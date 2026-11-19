"""Stage 4: Baseline eligibility tests (Category 7 — baseline poisoning prevention).

Verifies BaselineEligibilityPolicy strictly enforces all four preconditions
and never admits probe, anomalous, or unapproved observations.
"""
import pytest

from raven.baseline_engine import BaselineEligibilityPolicy, ObservationEligibility


@pytest.fixture
def policy():
    return BaselineEligibilityPolicy()


def _eligible(**kwargs):
    defaults = dict(
        acquisition_mode="baseline_acquisition",
        is_probe=False,
        is_anomalous=False,
        baseline_approved=True,
    )
    defaults.update(kwargs)
    return ObservationEligibility(**defaults)


class TestBaselineEligibilityPolicy:

    def test_valid_baseline_acquisition_eligible(self, policy):
        assert policy.is_eligible(_eligible()) is True

    def test_valid_reference_observation_eligible(self, policy):
        assert policy.is_eligible(_eligible(acquisition_mode="reference_observation")) is True

    def test_collect_mode_not_eligible(self, policy):
        assert policy.is_eligible(_eligible(acquisition_mode="collect")) is False

    def test_probe_mode_not_eligible(self, policy):
        assert policy.is_eligible(_eligible(acquisition_mode="probe")) is False

    def test_experimental_mode_not_eligible(self, policy):
        assert policy.is_eligible(_eligible(acquisition_mode="experimental")) is False

    def test_probe_flag_disqualifies_even_eligible_mode(self, policy):
        obs = _eligible(acquisition_mode="baseline_acquisition", is_probe=True)
        assert policy.is_eligible(obs) is False

    def test_anomalous_flag_disqualifies_even_eligible_mode(self, policy):
        obs = _eligible(acquisition_mode="reference_observation", is_anomalous=True)
        assert policy.is_eligible(obs) is False

    def test_unapproved_disqualifies_even_eligible_mode(self, policy):
        obs = _eligible(acquisition_mode="baseline_acquisition", baseline_approved=False)
        assert policy.is_eligible(obs) is False

    def test_all_flags_bad_still_ineligible(self, policy):
        obs = ObservationEligibility(
            acquisition_mode="baseline_acquisition",
            is_probe=True,
            is_anomalous=True,
            baseline_approved=False,
        )
        assert policy.is_eligible(obs) is False

    def test_default_observation_not_eligible(self, policy):
        # Default acquisition_mode="collect", baseline_approved=False → ineligible
        assert policy.is_eligible(ObservationEligibility()) is False

    def test_eligible_modes_set_is_frozenset(self, policy):
        assert isinstance(policy.ELIGIBLE_MODES, frozenset)

    def test_unknown_acquisition_mode_not_eligible(self, policy):
        obs = _eligible(acquisition_mode="acl_check")
        assert policy.is_eligible(obs) is False

    def test_xss_probe_mode_not_eligible(self, policy):
        obs = _eligible(acquisition_mode="xss_probe", is_probe=True, baseline_approved=True)
        assert policy.is_eligible(obs) is False
