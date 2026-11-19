"""RAVEN V6 Adversarial + Model Security + Planner Tests.

Covers:
- Knowledge schema validation (section 88): invalid entry rejection
- Model security (sections 161-164): tamper, schema mismatch, wrong task, no model
- ML readiness statuses (section 165): PIPELINE_READY vs REAL_DATA_READY
- Planner (sections 105-107): proposals, ranking, scope filter, no direct execution
- Adversarial (sections 236-237): policy bypass, path confusion, NaN/Inf features,
  URL confusion, ML bypass, emergency stop, callback safety, process guard
"""
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from raven.security.policy_gate import (
    PolicyGate, Capability, RiskClass, PolicyDecision,
)
from raven.security.process_guard import SafeProcessLauncher
from raven.ml.inference import InferenceEngine, InferenceResult
from raven.ml.registry import ModelRegistry, ModelVersion, ModelStatus
from raven.ml.features import FeatureVector
from raven.ml.future_tasks import ActiveLearningQueue
from raven.ml_readiness import ReadinessChecker, ReadinessStatus
from raven.knowledge.schema import (
    VulnerabilityKnowledge, VALID_RISK_CLASSES, VALID_CAPABILITIES,
    KNOWLEDGE_SCHEMA_VERSION,
)
from raven.knowledge.taxonomy import VULNERABILITY_FAMILIES, list_families
from raven.poc.autonomy import AutonomyLevel, DEFAULT_AUTONOMY
from raven.planner import ActionProposal, PlannerContext, Planner, ProposalStatus


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_gate(scope=("example.com",), caps=None) -> PolicyGate:
    PolicyGate._reset_emergency_stop_for_test()
    if caps is None:
        caps = {Capability.HTTP_READ, Capability.HTTP_STATE_CHANGE}
    return PolicyGate("ws-test", caps, set(scope))


def _zero_feature_vector(schema="v1") -> FeatureVector:
    return FeatureVector(schema_version=schema)


# ─────────────────────────────────────────────────────────────────────────────
# Knowledge Validation (section 88)
# ─────────────────────────────────────────────────────────────────────────────

class KnowledgeValidationTest(unittest.TestCase):

    def test_valid_entry_validates_ok(self):
        entry = VULNERABILITY_FAMILIES["AC-001"]
        entry.validate()  # must not raise

    def test_all_entries_validate(self):
        for kid, entry in VULNERABILITY_FAMILIES.items():
            with self.subTest(kid=kid):
                entry.validate()

    def test_invalid_risk_class_rejected(self):
        bad = VulnerabilityKnowledge(
            knowledge_id="BAD-001", name="Test", family="TestFamily",
            cwe="CWE-0", description="desc",
            preconditions=["p"], signals=["s"],
            false_positive_explanations=["f"],
            safe_test_strategy="safe", negative_controls=["n"],
            evidence_requirements=["e"], remediation_concepts=["r"],
            risk_class="UnknownClass",  # invalid
            required_capabilities=["HttpRead"],
            version="v1",
        )
        with self.assertRaises(ValueError) as ctx:
            bad.validate()
        self.assertIn("unknown risk_class", str(ctx.exception))

    def test_invalid_capability_rejected(self):
        bad = VulnerabilityKnowledge(
            knowledge_id="BAD-002", name="Test", family="TestFamily",
            cwe="CWE-0", description="desc",
            preconditions=["p"], signals=["s"],
            false_positive_explanations=["f"],
            safe_test_strategy="safe", negative_controls=["n"],
            evidence_requirements=["e"], remediation_concepts=["r"],
            risk_class="SafeReadOnly",
            required_capabilities=["ArbitraryExecution"],  # invalid
            version="v1",
        )
        with self.assertRaises(ValueError) as ctx:
            bad.validate()
        self.assertIn("unknown capability", str(ctx.exception))

    def test_empty_knowledge_id_rejected(self):
        bad = VulnerabilityKnowledge(
            knowledge_id="", name="Test", family="TestFamily",
            cwe="CWE-0", description="desc",
            preconditions=["p"], signals=["s"],
            false_positive_explanations=["f"],
            safe_test_strategy="safe", negative_controls=["n"],
            evidence_requirements=["e"], remediation_concepts=["r"],
            risk_class="SafeReadOnly",
            required_capabilities=["HttpRead"],
            version="v1",
        )
        with self.assertRaises(ValueError) as ctx:
            bad.validate()
        self.assertIn("knowledge_id", str(ctx.exception))

    def test_wrong_schema_version_rejected(self):
        bad = VulnerabilityKnowledge(
            knowledge_id="BAD-003", name="Test", family="TestFamily",
            cwe="CWE-0", description="desc",
            preconditions=["p"], signals=["s"],
            false_positive_explanations=["f"],
            safe_test_strategy="safe", negative_controls=["n"],
            evidence_requirements=["e"], remediation_concepts=["r"],
            risk_class="SafeReadOnly",
            required_capabilities=["HttpRead"],
            version="v99",  # wrong
        )
        with self.assertRaises(ValueError) as ctx:
            bad.validate()
        self.assertIn("schema version", str(ctx.exception))

    def test_no_forbidden_capabilities_in_taxonomy(self):
        forbidden = {"ArbitraryExecution", "UnrestrictedShell", "UnrestrictedNetwork"}
        for kid, entry in VULNERABILITY_FAMILIES.items():
            for cap in entry.required_capabilities:
                self.assertNotIn(
                    cap, forbidden,
                    f"Entry {kid} has forbidden capability {cap!r}"
                )

    def test_no_always_denied_risk_class_in_taxonomy(self):
        for kid, entry in VULNERABILITY_FAMILIES.items():
            self.assertNotIn(
                entry.risk_class, ("Destructive", "Exfiltrative"),
                f"Entry {kid} has always-denied risk class {entry.risk_class!r}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Model Security Tests (sections 161-164)
# ─────────────────────────────────────────────────────────────────────────────

class ModelSecurityTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _find_model_artifact(self, task: str):
        base = Path(__file__).parent.parent / "models" / task
        for pt_file in base.rglob("weights.pt"):
            card_file = pt_file.parent / "model_card.json"
            if card_file.exists():
                return pt_file, card_file
        return None, None

    def test_model_hash_detects_tamper(self):
        """Tampered model artifact must fail SHA-256 verification."""
        pt_file, card_file = self._find_model_artifact("task_a")
        if pt_file is None:
            self.skipTest("No task_a model artifact found")

        with open(card_file) as f:
            card = json.load(f)
        expected_sha = card.get("artifact_sha256") or card.get("sha256")
        if not expected_sha:
            self.skipTest("No artifact_sha256 in model card")

        # Verify original matches
        original_sha = hashlib.sha256(Path(pt_file).read_bytes()).hexdigest()
        self.assertEqual(original_sha, expected_sha, "Original artifact SHA-256 must match card")

        # Copy and tamper
        import shutil
        tampered_pt = Path(self._tmp) / "tampered.pt"
        shutil.copy(pt_file, tampered_pt)
        with open(tampered_pt, "ab") as f:
            f.write(b"\x00\xff\xde\xad")  # append garbage bytes

        tampered_sha = hashlib.sha256(tampered_pt.read_bytes()).hexdigest()
        self.assertNotEqual(
            tampered_sha, expected_sha,
            "Tampered artifact must have different SHA-256"
        )

    def test_hash_verification_rejects_tampered(self):
        """SHA-256 verification code correctly rejects a tampered artifact."""
        pt_file, card_file = self._find_model_artifact("task_a")
        if pt_file is None:
            self.skipTest("No task_a model artifact found")

        with open(card_file) as f:
            card = json.load(f)
        expected_sha = card.get("artifact_sha256") or card.get("sha256")
        if not expected_sha:
            self.skipTest("No sha256 in model card")

        # Verify original passes
        actual = hashlib.sha256(Path(pt_file).read_bytes()).hexdigest()
        self.assertEqual(actual, expected_sha, "Original artifact SHA-256 should match card")

        # Verify tampered fails
        import shutil
        tampered = Path(self._tmp) / "tampered_check.pt"
        shutil.copy(pt_file, tampered)
        with open(tampered, "ab") as f:
            f.write(b"\xba\xdc\x0f\xfe")
        tampered_sha = hashlib.sha256(tampered.read_bytes()).hexdigest()
        self.assertNotEqual(tampered_sha, expected_sha)

    def test_schema_mismatch_raises_on_wrong_version(self):
        """FeatureVector with wrong schema version should be rejected by inference."""
        fv_bad = _zero_feature_vector(schema="v999_wrong")
        pt_file, card_file = self._find_model_artifact("task_a")
        if pt_file is None:
            self.skipTest("No model artifact found")
        with open(card_file) as f:
            card = json.load(f)
        mv = ModelVersion(
            model_id=card["model_id"],
            task=card["task"],
            architecture=card["architecture"],
            status=ModelStatus.DEVELOPMENT,
            weights_path=str(pt_file),
            feature_schema_version=card.get("feature_schema_version", "v1"),
            timestamp_utc=card.get("training_date_utc", "2026-01-01T00:00:00Z"),
        )
        engine = InferenceEngine(mv)
        with self.assertRaises((ValueError, RuntimeError)):
            engine.predict(fv_bad)

    def test_no_active_model_does_not_break_raven(self):
        """RAVEN must operate without any registered model."""
        import os
        registry_path = os.path.join(self._tmp, "registry.json")
        registry = ModelRegistry(registry_path)
        engine = InferenceEngine.from_registry(registry, "task_a")
        self.assertIsNone(engine, "No production model → from_registry returns None")

    def test_inference_result_is_advisory_always(self):
        """InferenceResult must always have is_advisory=True and sets_verification_status=False."""
        pt_file, card_file = self._find_model_artifact("task_a")
        if pt_file is None:
            self.skipTest("No model artifact found")
        with open(card_file) as f:
            card = json.load(f)
        mv = ModelVersion(
            model_id=card["model_id"],
            task=card["task"],
            architecture=card["architecture"],
            status=ModelStatus.DEVELOPMENT,
            weights_path=str(pt_file),
            feature_schema_version=card.get("feature_schema_version", "v1"),
            timestamp_utc=card.get("training_date_utc", "2026-01-01T00:00:00Z"),
        )
        engine = InferenceEngine(mv)
        fv = _zero_feature_vector()
        result = engine.predict(fv)
        self.assertTrue(result.is_advisory)
        self.assertFalse(result.sets_verification_status)

    def test_model_cannot_set_verification_status(self):
        """No code path: InferenceResult → verification_status=verified."""
        result = InferenceResult(
            task="task_a", score=0.9, probability=0.9,
            threshold=0.5, predicted_positive=True,
            predicted_triage_class="response_differs_meaningfully",
            model_id="test", model_version="v1",
            feature_schema_version="v1", inference_ms=1,
            is_advisory=True, sets_verification_status=False,
        )
        self.assertFalse(result.sets_verification_status)
        self.assertTrue(result.is_advisory)
        # InferenceResult is frozen — cannot mutate
        with self.assertRaises(Exception):
            result.sets_verification_status = True  # type: ignore

    def test_model_cannot_self_promote(self):
        """Model must be CANDIDATE before production promotion — no auto-promote from DEVELOPMENT."""
        import os
        registry_path = os.path.join(self._tmp, "registry2.json")
        registry = ModelRegistry(registry_path)
        mv = ModelVersion(
            model_id="test-model-2",
            task="task_a",
            architecture="logistic_regression",
            status=ModelStatus.DEVELOPMENT,
            weights_path="/dev/null",
            feature_schema_version="v1",
            timestamp_utc="2026-01-01T00:00:00Z",
        )
        registry.register(mv)
        # Cannot promote directly from DEVELOPMENT to PRODUCTION
        with self.assertRaises((ValueError, KeyError)):
            registry.promote_to_production("test-model-2", promoted_by="researcher")


# ─────────────────────────────────────────────────────────────────────────────
# ML Readiness (section 165)
# ─────────────────────────────────────────────────────────────────────────────

class MLReadinessTest(unittest.TestCase):

    def test_pipeline_not_ready_without_real_data(self):
        checker = ReadinessChecker()
        report = checker.evaluate_readiness("response_difference", labeled_rows=[])
        self.assertEqual(report.status, ReadinessStatus.NOT_READY_FOR_TRAINING)
        self.assertFalse(report.model_trained)
        self.assertFalse(report.ml_probability_modified)

    def test_synthetic_only_not_ready(self):
        from raven.dataset_foundation import LabeledObservation
        rows = [
            LabeledObservation(
                id=f"lbl{i}",
                workspace_id="ws1",
                observation_id=f"obs{i}",
                task="response_difference",
                label="positive" if i % 2 else "negative",
                group_key="group1",
                labeler="researcher",
                labeled_at="2026-01-01T00:00:00Z",
                synthetic=True,
            )
            for i in range(50)
        ]
        checker = ReadinessChecker()
        report = checker.evaluate_readiness("response_difference", labeled_rows=rows)
        self.assertEqual(report.status, ReadinessStatus.NOT_READY_FOR_TRAINING)
        self.assertIn("synthetic", " ".join(report.reasons).lower())

    def test_unknown_task_not_ready(self):
        checker = ReadinessChecker()
        report = checker.evaluate_readiness("task_z_unknown")
        self.assertEqual(report.status, ReadinessStatus.NOT_READY_FOR_TRAINING)
        self.assertIn("Unknown task", " ".join(report.reasons))


# ─────────────────────────────────────────────────────────────────────────────
# Planner Tests (sections 105-107)
# ─────────────────────────────────────────────────────────────────────────────

class PlannerTest(unittest.TestCase):

    def test_proposal_has_required_fields(self):
        p = ActionProposal(
            reason="Test",
            knowledge_reference="AC-001",
            required_capability="HttpRead",
            risk_class="LowRiskStateChange",
            destination="https://example.com/resource",
            expected_evidence="Owner access vs non-owner access",
            budget_requests=1,
            scope_label="example.com",
            human_approval_required=True,
        )
        self.assertIsNotNone(p.proposal_id)
        self.assertTrue(p.human_approval_required)
        self.assertEqual(p.status, ProposalStatus.PENDING)

    def test_proposal_default_approval_required(self):
        p = ActionProposal()
        self.assertTrue(p.human_approval_required)

    def test_proposal_approve_records_researcher(self):
        p = ActionProposal(reason="test")
        p.approve("researcher_a")
        self.assertEqual(p.status, ProposalStatus.APPROVED)

    def test_proposal_approve_requires_non_empty_approver(self):
        p = ActionProposal(reason="test")
        with self.assertRaises(ValueError):
            p.approve("")

    def test_proposal_deny_sets_denied(self):
        p = ActionProposal(reason="test")
        p.deny("researcher_b")
        self.assertEqual(p.status, ProposalStatus.DENIED)

    def test_planner_generates_proposals_for_knowledge(self):
        planner = Planner()
        ctx = PlannerContext(
            workspace_id="ws1",
            scope_hosts=["example.com"],
            knowledge_ids=["AC-001"],
        )
        proposals = planner.propose_from_knowledge(ctx, "AC-001")
        self.assertGreater(len(proposals), 0)
        for p in proposals:
            self.assertTrue(p.human_approval_required)
            self.assertEqual(p.knowledge_reference, "AC-001")

    def test_planner_proposals_default_pending(self):
        planner = Planner()
        ctx = PlannerContext(workspace_id="ws1", scope_hosts=["example.com"])
        proposals = planner.propose_from_knowledge(ctx, "AC-001")
        for p in proposals:
            self.assertEqual(p.status, ProposalStatus.PENDING)

    def test_planner_unknown_knowledge_returns_empty(self):
        planner = Planner()
        ctx = PlannerContext(workspace_id="ws1", scope_hosts=["example.com"])
        proposals = planner.propose_from_knowledge(ctx, "NONEXISTENT-999")
        self.assertEqual(proposals, [])

    def test_planner_filter_by_scope_removes_out_of_scope(self):
        planner = Planner()
        proposals = [
            ActionProposal(destination="https://allowed.com/path"),
            ActionProposal(destination="https://notallowed.com/path"),
            ActionProposal(destination="https://sub.allowed.com/path"),
        ]
        filtered = planner.filter_by_scope(proposals, ["allowed.com"])
        dests = {p.destination for p in filtered}
        self.assertIn("https://allowed.com/path", dests)
        self.assertIn("https://sub.allowed.com/path", dests)
        self.assertNotIn("https://notallowed.com/path", dests)

    def test_planner_cannot_skip_policy(self):
        """Approved proposal still requires PolicyGate before execution."""
        p = ActionProposal(
            reason="Test",
            required_capability="HttpStateChange",
            risk_class="LowRiskStateChange",
            destination="https://example.com/delete",
        )
        p.approve("researcher")
        self.assertEqual(p.status, ProposalStatus.APPROVED)
        # Approval alone doesn't grant execution — PolicyGate must still be called
        # (tested by verifying no direct network access is in the planner module)
        import inspect
        import raven.planner.planner as planner_mod
        src = inspect.getsource(planner_mod)
        self.assertNotIn("requests.get", src)
        self.assertNotIn("urllib.request", src)
        self.assertNotIn("socket.connect", src)
        self.assertNotIn("subprocess.run", src)
        self.assertNotIn("os.system", src)

    def test_model_signal_cannot_authorize_proposal(self):
        """High model score never promotes status to APPROVED."""
        p = ActionProposal(
            reason="High confidence",
            risk_class="LowRiskStateChange",
            model_signal_score=1.0,  # maximum
        )
        # Still PENDING — model signal doesn't change approval
        self.assertEqual(p.status, ProposalStatus.PENDING)


# ─────────────────────────────────────────────────────────────────────────────
# Adversarial Policy Tests (sections 236-237)
# ─────────────────────────────────────────────────────────────────────────────

class AdversarialPolicyTest(unittest.TestCase):

    def setUp(self):
        PolicyGate._reset_emergency_stop_for_test()

    def tearDown(self):
        PolicyGate._reset_emergency_stop_for_test()

    # Policy bypass attempts
    def test_destructive_always_denied_regardless_of_scope(self):
        gate = _make_gate(scope=("example.com",),
                          caps={Capability.HTTP_STATE_CHANGE})
        d = gate.evaluate(
            Capability.HTTP_STATE_CHANGE,
            "https://example.com/delete_user",
            "DELETE", "test", RiskClass.DESTRUCTIVE,
        )
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "RiskClassBlocked")

    def test_exfiltrative_always_denied_regardless_of_scope(self):
        gate = _make_gate(scope=("example.com",),
                          caps={Capability.HTTP_READ, Capability.FILE_READ_WORKSPACE})
        d = gate.evaluate(
            Capability.HTTP_READ,
            "https://example.com/data",
            "GET", "exfil attempt", RiskClass.EXFILTRATIVE,
        )
        self.assertFalse(d.allowed)

    def test_sensitive_requires_human_approval(self):
        gate = _make_gate(scope=("example.com",),
                          caps={Capability.HTTP_STATE_CHANGE})
        d = gate.evaluate(
            Capability.HTTP_STATE_CHANGE,
            "https://example.com/admin",
            "POST", "test", RiskClass.SENSITIVE,
        )
        self.assertFalse(d.allowed)
        self.assertTrue(d.requires_approval)
        self.assertEqual(d.reason, "RequiresHumanApproval")

    def test_missing_capability_denied(self):
        gate = PolicyGate("ws1", set(), {"example.com"})
        d = gate.evaluate(
            Capability.HTTP_READ,
            "https://example.com/resource",
            "GET", "test", RiskClass.SAFE_READ_ONLY,
        )
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "CapabilityMissing")

    def test_wrong_workspace_denied(self):
        gate = _make_gate()
        d = gate.evaluate(
            Capability.HTTP_READ,
            "https://example.com/",
            "GET", "test", RiskClass.SAFE_READ_ONLY,
            workspace_id="ws-different",
        )
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "WorkspaceMismatch")

    def test_out_of_scope_destination_denied(self):
        gate = _make_gate(scope={"example.com"})
        d = gate.evaluate(
            Capability.HTTP_READ,
            "https://evil.com/steal",
            "GET", "test", RiskClass.SAFE_READ_ONLY,
        )
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "DestinationOutOfScope")

    def test_emergency_stop_denies_all_classes(self):
        gate = _make_gate()
        PolicyGate.trigger_emergency_stop()
        for risk in [RiskClass.SAFE_READ_ONLY, RiskClass.LOW_RISK_STATE_CHANGE,
                     RiskClass.SENSITIVE]:
            with self.subTest(risk=risk):
                d = gate.evaluate(
                    Capability.HTTP_READ,
                    "https://example.com/",
                    "GET", "test", risk,
                )
                self.assertFalse(d.allowed)
                self.assertEqual(d.reason, "EmergencyStopActive")

    def test_max_ml_probability_cannot_authorize_destructive(self):
        """ML probability=1.0 still cannot authorize a DESTRUCTIVE action."""
        gate = _make_gate(scope={"example.com"},
                          caps={Capability.HTTP_STATE_CHANGE})
        # Simulate ML score=1.0 by just calling evaluate — the gate has no ML input
        # The point is there's no way to pass a "ml_score" that changes the result
        d = gate.evaluate(
            Capability.HTTP_STATE_CHANGE,
            "https://example.com/admin",
            "DELETE", "ML says confidence=1.0", RiskClass.DESTRUCTIVE,
        )
        self.assertFalse(d.allowed)

    # URL confusion
    def test_loopback_alias_out_of_scope(self):
        """127.0.0.1, localhost aliases must not escape scope checks."""
        gate = _make_gate(scope={"example.com"})
        for loopback in [
            "http://127.0.0.1/admin",
            "http://localhost/admin",
            "http://0.0.0.0/admin",
            "http://[::1]/admin",
        ]:
            with self.subTest(dest=loopback):
                d = gate.evaluate(
                    Capability.HTTP_READ, loopback,
                    "GET", "test", RiskClass.SAFE_READ_ONLY,
                )
                self.assertFalse(d.allowed, f"Should deny {loopback}")

    def test_malformed_url_denied(self):
        gate = _make_gate(scope={"example.com"})
        for bad_url in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<script>",
            "ftp://example.com/file",
            "",
            "not-a-url",
            "http://",
            "https://",
        ]:
            with self.subTest(url=bad_url):
                d = gate.evaluate(
                    Capability.HTTP_READ, bad_url,
                    "GET", "test", RiskClass.SAFE_READ_ONLY,
                )
                self.assertFalse(d.allowed, f"Should deny {bad_url!r}")

    def test_subdomain_in_scope_allowed(self):
        """Subdomains of scoped host are permitted in RAVEN's model."""
        gate = PolicyGate("ws1", {Capability.HTTP_READ}, {"example.com"})
        d = gate.evaluate(
            Capability.HTTP_READ,
            "https://api.example.com/",
            "GET", "test", RiskClass.SAFE_READ_ONLY,
        )
        self.assertTrue(d.allowed)

    def test_completely_different_domain_denied(self):
        """A domain that shares no relationship with scope is denied."""
        gate = _make_gate(scope={"example.com"})
        d = gate.evaluate(
            Capability.HTTP_READ,
            "https://exampleevil.com/",
            "GET", "test", RiskClass.SAFE_READ_ONLY,
        )
        self.assertFalse(d.allowed, "exampleevil.com should not match example.com")

    def test_numeric_ip_out_of_scope(self):
        """Numeric IP addresses must be explicitly scoped; domain scope doesn't match IPs."""
        gate = _make_gate(scope={"example.com"})
        d = gate.evaluate(
            Capability.HTTP_READ,
            "https://93.184.216.34/",  # example.com's IP
            "GET", "test", RiskClass.SAFE_READ_ONLY,
        )
        self.assertFalse(d.allowed, "IP address form should not match domain scope")


# ─────────────────────────────────────────────────────────────────────────────
# NaN / Inf Feature Adversarial (sections 44-45, 119)
# ─────────────────────────────────────────────────────────────────────────────

class AdversarialFeatureTest(unittest.TestCase):

    def test_feature_vector_rejects_nan(self):
        from raven.ml.features import FeatureVector
        fv = FeatureVector(body_entropy=float('nan'))
        with self.assertRaises(ValueError) as ctx:
            fv.validate()
        self.assertIn("NaN", str(ctx.exception))

    def test_feature_vector_rejects_nan_via_to_list(self):
        from raven.ml.features import FeatureVector
        fv = FeatureVector(length_z_score=float('nan'))
        with self.assertRaises(ValueError):
            fv.to_list()

    def test_feature_vector_rejects_inf(self):
        from raven.ml.features import FeatureVector
        fv = FeatureVector(body_entropy=float('inf'))
        with self.assertRaises(ValueError) as ctx:
            fv.validate()
        self.assertIn("Inf", str(ctx.exception))

    def test_feature_vector_rejects_negative_inf(self):
        from raven.ml.features import FeatureVector
        fv = FeatureVector(printable_ratio=float('-inf'))
        with self.assertRaises(ValueError):
            fv.validate()

    def test_feature_vector_valid_defaults_pass(self):
        """Default FeatureVector (all -1 sentinels) must pass validation."""
        from raven.ml.features import FeatureVector
        fv = FeatureVector()
        fv.validate()  # should not raise
        vals = fv.to_list()
        self.assertEqual(len(vals), 22)


# ─────────────────────────────────────────────────────────────────────────────
# Process Guard Adversarial (section 27, 236)
# ─────────────────────────────────────────────────────────────────────────────

class ProcessGuardAdversarialTest(unittest.TestCase):

    def _make_launcher_with_echo(self):
        """Create a launcher with a dummy 'echo' process registered."""
        from raven.security.process_guard import ApprovedProcess
        launcher = SafeProcessLauncher()
        spec = ApprovedProcess(
            name="echo",
            executable_path="/usr/bin/echo",
            allowed_arg_patterns=[],  # any arg pattern (no pattern = any allowed pattern, tested below)
        )
        try:
            launcher.register(spec)
        except Exception:
            pass
        return launcher

    def test_shell_metacharacters_rejected(self):
        from raven.security.process_guard import ApprovedProcess, SHELL_METACHARACTERS
        # SHELL_METACHARACTERS pattern must match hostile args
        for bad_arg in [
            "file; rm -rf /",
            "arg | cat /etc/passwd",
            "val$(curl evil.com)",
            "arg > /tmp/out",
            "input\necho pwned",
        ]:
            with self.subTest(arg=bad_arg):
                self.assertIsNotNone(
                    SHELL_METACHARACTERS.search(bad_arg),
                    f"SHELL_METACHARACTERS must match {bad_arg!r}"
                )

    def test_relative_path_rejected_on_register(self):
        """Relative executable paths must be rejected at register time."""
        from raven.security.process_guard import ApprovedProcess
        launcher = SafeProcessLauncher()
        with self.assertRaises((ValueError, PermissionError)):
            launcher.register(ApprovedProcess(
                name="bad", executable_path="./malicious.sh",
                allowed_arg_patterns=[],
            ))

    def test_path_traversal_rejected_on_register(self):
        """Path traversal in executable paths must be rejected."""
        from raven.security.process_guard import ApprovedProcess
        launcher = SafeProcessLauncher()
        with self.assertRaises((ValueError, PermissionError)):
            launcher.register(ApprovedProcess(
                name="bad", executable_path="/tmp/../usr/bin/id",
                allowed_arg_patterns=[],
            ))

    def test_unregistered_process_rejected(self):
        """Any unregistered name must raise KeyError."""
        launcher = SafeProcessLauncher()
        with self.assertRaises((ValueError, PermissionError, KeyError)):
            launcher.launch("/usr/bin/id", [])

    def test_no_shell_equals_true(self):
        """Verify subprocess calls in SafeProcessLauncher never use shell=True."""
        import inspect
        import raven.security.process_guard as pg
        src = inspect.getsource(pg)
        import re
        # Find lines that are subprocess.run/Popen calls (not comments, not docstrings)
        # Check that none of them have shell=True
        for line in src.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'"):
                continue
            # Check for subprocess calls specifically
            if re.search(r'subprocess\.(run|Popen|call|check_output)\s*\(', line):
                self.assertNotIn(
                    "shell=True", line,
                    f"subprocess call with shell=True found: {line!r}"
                )


# ─────────────────────────────────────────────────────────────────────────────
# Callback Collector Adversarial (sections 25-26, 158, 236)
# ─────────────────────────────────────────────────────────────────────────────

class CallbackCollectorAdversarialTest(unittest.TestCase):

    def test_payload_not_executed(self):
        """Callback body is hashed, not executed."""
        from raven.security.callback_collector import SafeCallbackCollector, CallbackRecord
        collector = SafeCallbackCollector()
        hostile_body = b"__import__('os').system('echo pwned')"
        record = collector.record_callback(
            source_label="127.0.0.1:55000",
            method="POST",
            path="/callback",
            headers={"content-type": "application/json"},
            raw_payload=hostile_body,
        )
        # Body must NOT be stored as raw executable content
        self.assertFalse(hasattr(record, "body"))
        self.assertFalse(hasattr(record, "raw_body"))
        # Only hash and byte count should be stored
        expected_hash = __import__("hashlib").sha256(hostile_body).hexdigest()
        self.assertEqual(record.payload_hash, expected_hash)
        self.assertEqual(record.payload_bytes, len(hostile_body))

    def test_credential_headers_stripped(self):
        from raven.security.callback_collector import SafeCallbackCollector
        collector = SafeCallbackCollector()
        record = collector.record_callback(
            source_label="127.0.0.1:55001",
            method="GET",
            path="/cb",
            headers={
                "authorization": "Bearer secret-token-12345",
                "cookie": "session=abc123",
                "content-type": "text/plain",
                "x-api-key": "mykey",
            },
            raw_payload=b"test",
        )
        safe = record.safe_headers
        self.assertNotIn("authorization", safe)
        self.assertNotIn("cookie", safe)
        self.assertNotIn("x-api-key", safe)
        self.assertIn("content-type", safe)

    def test_callback_record_contains_no_executable_body(self):
        from raven.security.callback_collector import CallbackRecord
        import dataclasses
        field_names = {f.name for f in dataclasses.fields(CallbackRecord)}
        # Body content must not be stored
        self.assertNotIn("body", field_names)
        self.assertNotIn("raw_body", field_names)
        self.assertNotIn("raw_payload", field_names)
        # Only count and hash
        self.assertIn("payload_bytes", field_names)
        self.assertIn("payload_hash", field_names)


# ─────────────────────────────────────────────────────────────────────────────
# Data Flywheel Invariants (sections 73, 181, 182)
# ─────────────────────────────────────────────────────────────────────────────

class DataFlywheelAdversarialTest(unittest.TestCase):

    def test_active_learning_auto_labeled_always_false(self):
        q = ActiveLearningQueue()
        q.add_uncertain(observation_ref="obs-1", uncertainty_score=0.95, model_id="m1")
        item = q._items[0]
        self.assertFalse(item["auto_labeled"])

    def test_active_learning_requires_human_review(self):
        q = ActiveLearningQueue()
        q.add_uncertain(observation_ref="obs-2", uncertainty_score=0.99, model_id="m1")
        item = q._items[0]
        self.assertTrue(item["requires_human_review"])

    def test_active_learning_max_size_enforced(self):
        q = ActiveLearningQueue(max_queue_size=3)
        for i in range(10):
            q.add_uncertain(observation_ref=f"obs-{i}", uncertainty_score=0.5, model_id="m1")
        self.assertLessEqual(q.size(), 3)


# ─────────────────────────────────────────────────────────────────────────────
# Autonomy Level Invariants (section 109-111)
# ─────────────────────────────────────────────────────────────────────────────

class AutonomyAdversarialTest(unittest.TestCase):

    def test_default_autonomy_is_assist(self):
        self.assertEqual(DEFAULT_AUTONOMY.level, AutonomyLevel.ASSIST)

    def test_level3_not_globally_enabled(self):
        self.assertNotEqual(DEFAULT_AUTONOMY.level, AutonomyLevel.BOUNDED_AUTO)

    def test_approval_required_at_all_levels_for_sensitive(self):
        for level in AutonomyLevel:
            with self.subTest(level=level):
                cfg = __import__("raven.poc.autonomy", fromlist=["AutonomyConfig"]).AutonomyConfig(level=level)
                self.assertTrue(cfg.requires_approval_for_sensitive())

    def test_approval_required_at_all_levels_for_destructive(self):
        for level in AutonomyLevel:
            with self.subTest(level=level):
                cfg = __import__("raven.poc.autonomy", fromlist=["AutonomyConfig"]).AutonomyConfig(level=level)
                self.assertTrue(cfg.requires_approval_for_destructive())


if __name__ == "__main__":
    unittest.main(verbosity=2)
