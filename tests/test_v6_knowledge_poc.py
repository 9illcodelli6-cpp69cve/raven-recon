"""RAVEN V6 Knowledge, PoC, and Autonomy Tests (Gates 24-35).

Tests:
- Vulnerability knowledge schema
- Taxonomy (17+ families)
- Access control knowledge (Gates 25-26)
- PoC Candidate model and scientific reasoning chain
- Safe primitives (9 defined, none execute arbitrary code)
- Autonomy levels (default ASSIST, Level 3 not global)
- Data flywheel (no prediction->auto-label allowed)
- Active learning queue (no auto-labeling)
- Future task specs (schema only, not implemented)
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from raven.knowledge import (
    VulnerabilityKnowledge, VULNERABILITY_FAMILIES, list_families, get_entry,
)
from raven.knowledge.schema import KNOWLEDGE_SCHEMA_VERSION
from raven.poc import (
    PoCCandidate, PoCObservation, PoCStatus,
    SafePrimitive, SAFE_PRIMITIVES,
    establish_baseline, repeat_request, compare_response,
    compare_identity, replace_object_reference, change_safe_parameter,
    observe_redirect, record_evidence, run_negative_control,
    AutonomyLevel, AutonomyConfig, DEFAULT_AUTONOMY,
)
from raven.poc.candidate import PoCStatus
from raven.ml.future_tasks import (
    FutureTaskType, FUTURE_TASK_SPECS,
    FLYWHEEL_FORBIDDEN, FLYWHEEL_REQUIRED,
    ActiveLearningQueue, DataFlywheelStage,
)


# ===========================================================================
# Gate 24 — Knowledge Schema
# ===========================================================================
class KnowledgeSchemaTest(unittest.TestCase):
    def test_schema_version(self):
        self.assertEqual(KNOWLEDGE_SCHEMA_VERSION, "v1")

    def test_knowledge_entry_has_all_required_fields(self):
        entry = get_entry("AC-001")
        required = [
            "knowledge_id", "name", "family", "cwe", "description",
            "preconditions", "signals", "false_positive_explanations",
            "safe_test_strategy", "negative_controls", "evidence_requirements",
            "remediation_concepts", "risk_class", "required_capabilities", "version",
        ]
        d = entry.to_dict()
        for field in required:
            self.assertIn(field, d, f"Missing field: {field}")

    def test_knowledge_entry_is_frozen(self):
        entry = get_entry("AC-001")
        with self.assertRaises((AttributeError, TypeError)):
            entry.name = "modified"  # type: ignore

    def test_knowledge_schema_version_in_entry(self):
        entry = get_entry("AC-001")
        self.assertEqual(entry.version, KNOWLEDGE_SCHEMA_VERSION)


# ===========================================================================
# Gate 25 — Vulnerability Taxonomy
# ===========================================================================
class VulnerabilityTaxonomyTest(unittest.TestCase):
    def test_at_least_17_families(self):
        families = list_families()
        self.assertGreaterEqual(len(families), 17,
                                f"Expected >=17 families, got {len(families)}: {families}")

    def test_major_families_present(self):
        families = set(list_families())
        expected = {
            "Access Control", "Authentication", "Session Management",
            "XSS", "CSRF", "SSRF", "Injection", "File Handling",
            "Path Traversal", "Business Logic", "Race Conditions",
            "Caching", "CORS", "Information Disclosure", "API Security",
            "GraphQL", "WebSocket",
        }
        for f in expected:
            self.assertIn(f, families, f"Missing family: {f}")

    def test_all_entries_have_cwe(self):
        for kid, entry in VULNERABILITY_FAMILIES.items():
            self.assertTrue(entry.cwe.startswith("CWE-"), f"{kid}: invalid CWE {entry.cwe!r}")

    def test_no_executable_exploit_code_in_entries(self):
        forbidden = [
            "exec(", "eval(", "subprocess", "os.system", "shell=True",
            "reverse_shell", "bind_shell", "meterpreter",
            "__import__", "exploit_db", "metasploit",
        ]
        for kid, entry in VULNERABILITY_FAMILIES.items():
            text = str(entry.to_dict()).lower()
            for bad in forbidden:
                self.assertNotIn(bad.lower(), text,
                                 f"{kid}: contains forbidden string {bad!r}")

    def test_get_entry_returns_correct_type(self):
        e = get_entry("SSRF-001")
        self.assertIsInstance(e, VulnerabilityKnowledge)
        self.assertEqual(e.family, "SSRF")

    def test_get_entry_unknown_raises(self):
        with self.assertRaises(KeyError):
            get_entry("NONEXISTENT-999")


# ===========================================================================
# Gate 26 — Access Control Knowledge
# ===========================================================================
class AccessControlKnowledgeTest(unittest.TestCase):
    def test_idor_entry_exists(self):
        e = get_entry("AC-001")
        self.assertIn("IDOR", e.name)
        self.assertGreater(len(e.preconditions), 0)
        self.assertGreater(len(e.signals), 0)
        self.assertGreater(len(e.false_positive_explanations), 0)
        self.assertGreater(len(e.negative_controls), 0)
        self.assertGreater(len(e.evidence_requirements), 0)

    def test_bfla_entry_exists(self):
        e = get_entry("AC-002")
        self.assertIn("BFLA", e.name)

    def test_horizontal_authorization_entry(self):
        e = get_entry("AC-003")
        self.assertEqual(e.family, "Access Control")

    def test_vertical_authorization_entry(self):
        e = get_entry("AC-004")
        self.assertIn("Vertical", e.name)
        self.assertIn("Sensitive", e.risk_class)

    def test_safe_test_strategy_nonempty(self):
        for kid in ["AC-001", "AC-002", "AC-003", "AC-004"]:
            e = get_entry(kid)
            self.assertTrue(e.safe_test_strategy.strip(),
                            f"{kid}: empty safe_test_strategy")

    def test_researcher_test_accounts_mentioned(self):
        for kid in ["AC-001", "AC-002", "AC-003"]:
            e = get_entry(kid)
            strat = e.safe_test_strategy.lower()
            self.assertIn("researcher", strat,
                          f"{kid}: safe_test_strategy must mention researcher-controlled accounts")


# ===========================================================================
# Gate 27 — PoC Candidate Data Model
# ===========================================================================
class PoCCandidateTest(unittest.TestCase):
    def test_default_status_is_hypothesis(self):
        c = PoCCandidate()
        self.assertEqual(c.status, PoCStatus.HYPOTHESIS)

    def test_human_verification_always_required(self):
        c = PoCCandidate()
        self.assertTrue(c.human_verification_required)

    def test_cannot_set_human_verified_without_reviewer(self):
        c = PoCCandidate()
        with self.assertRaises(ValueError):
            c.advance_to(PoCStatus.HUMAN_VERIFIED)

    def test_can_set_human_verified_with_reviewer(self):
        c = PoCCandidate()
        c.human_verified_by = "researcher@example.com"
        c.advance_to(PoCStatus.HUMAN_VERIFIED)
        self.assertEqual(c.status, PoCStatus.HUMAN_VERIFIED)
        self.assertTrue(c.can_be_promoted())

    def test_cannot_be_promoted_without_human_verification(self):
        c = PoCCandidate()
        c.status = PoCStatus.EVIDENCE_COLLECTED
        self.assertFalse(c.can_be_promoted())

    def test_is_advisory_only_before_verification(self):
        c = PoCCandidate()
        self.assertTrue(c.is_advisory_only())

    def test_summary_includes_human_verification_status(self):
        c = PoCCandidate()
        s = c.summary()
        self.assertIn("human_verification_required", s)
        self.assertTrue(s["human_verification_required"])


# ===========================================================================
# Gate 28 — Scientific Reasoning Chain
# ===========================================================================
class ScientificReasoningTest(unittest.TestCase):
    def test_candidate_has_all_reasoning_fields(self):
        c = PoCCandidate(
            hypothesis    = "Endpoint /api/orders/{id} allows IDOR",
            preconditions = ["Two researcher-owned accounts"],
            experiment_plan = "Account B accesses Account A order with GET /api/orders/{id}",
            control_plan  = "Unauthenticated request should return 401",
        )
        self.assertTrue(c.hypothesis)
        self.assertTrue(c.preconditions)
        self.assertTrue(c.experiment_plan)
        self.assertTrue(c.control_plan)

    def test_reasoning_chain_status_transitions(self):
        c = PoCCandidate()
        for status in [
            PoCStatus.PRECONDITIONS_MET,
            PoCStatus.EXPERIMENT_PENDING,
            PoCStatus.CONTROLS_RUNNING,
            PoCStatus.EVIDENCE_COLLECTED,
            PoCStatus.CANDIDATE_CONCLUSION,
            PoCStatus.AWAITING_HUMAN_REVIEW,
        ]:
            c.advance_to(status)
            self.assertEqual(c.status, status)

        # Final step requires human
        c.human_verified_by = "researcher@example.com"
        c.advance_to(PoCStatus.HUMAN_VERIFIED)
        self.assertEqual(c.status, PoCStatus.HUMAN_VERIFIED)


# ===========================================================================
# Gate 29 — Safe Primitives
# ===========================================================================
class SafePrimitivesTest(unittest.TestCase):
    def test_nine_primitives_defined(self):
        self.assertGreaterEqual(len(SAFE_PRIMITIVES), 9)

    def test_no_arbitrary_execute_primitive(self):
        names = [p.name for p in SAFE_PRIMITIVES]
        forbidden = ["execute_arbitrary_command", "open_arbitrary_socket", "run_exploit"]
        for bad in forbidden:
            self.assertNotIn(bad, names)

    def test_all_primitives_have_risk_class(self):
        for p in SAFE_PRIMITIVES:
            self.assertIn(p.risk_class, [
                "SafeReadOnly", "LowRiskStateChange", "Sensitive", None
            ])

    def test_all_primitives_have_approval_policy(self):
        for p in SAFE_PRIMITIVES:
            self.assertIn(p.approval_policy, [
                "automatic", "researcher_approval", "always_denied"
            ])

    def test_establish_baseline_returns_safe_metadata(self):
        r = establish_baseline("https://example.com/api", "GET", "session-token")
        self.assertEqual(r["risk_class"], "SafeReadOnly")
        self.assertEqual(r["approval"], "automatic")
        self.assertTrue(r["reversible"])

    def test_repeat_request_budget_enforced(self):
        with self.assertRaises(ValueError):
            repeat_request("https://example.com/api", "GET", count=100)

    def test_replace_object_reference_mutation_needs_approval(self):
        r = replace_object_reference("/api/orders/123", "123", "456", method="POST")
        self.assertEqual(r["approval"], "researcher_approval")

    def test_negative_control_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            run_negative_control("/api/test", "arbitrary_malicious_type")

    def test_record_evidence_notes_bounded(self):
        r = record_evidence("obs-123", "differential_response", "x" * 1000)
        self.assertLessEqual(len(r["notes"]), 500)


# ===========================================================================
# Gate 30 — Autonomy Levels
# ===========================================================================
class AutonomyLevelTest(unittest.TestCase):
    def test_default_is_assist(self):
        self.assertEqual(DEFAULT_AUTONOMY.level, AutonomyLevel.ASSIST)

    def test_level_1_does_not_auto_execute_reads(self):
        cfg = AutonomyConfig(level=AutonomyLevel.ASSIST)
        self.assertFalse(cfg.may_execute_read_only_autonomously())

    def test_level_2_auto_executes_reads_only(self):
        cfg = AutonomyConfig(level=AutonomyLevel.SUPERVISED)
        self.assertTrue(cfg.may_execute_read_only_autonomously())
        self.assertFalse(cfg.may_execute_low_risk_autonomously())

    def test_sensitive_always_requires_approval(self):
        for level in AutonomyLevel:
            cfg = AutonomyConfig(level=level)
            self.assertTrue(cfg.requires_approval_for_sensitive(),
                            f"Level {level} must still require approval for sensitive")

    def test_destructive_always_requires_approval(self):
        for level in AutonomyLevel:
            cfg = AutonomyConfig(level=level)
            self.assertTrue(cfg.requires_approval_for_destructive())

    def test_level_3_not_globally_enabled(self):
        # DEFAULT_AUTONOMY must never be LEVEL 3
        self.assertNotEqual(DEFAULT_AUTONOMY.level, AutonomyLevel.BOUNDED_AUTO)


# ===========================================================================
# Gate 31 — Future Task Schemas
# ===========================================================================
class FutureTaskSpecTest(unittest.TestCase):
    def test_unimplemented_tasks_not_implemented(self):
        for task_type in [
            FutureTaskType.VULNERABILITY_ROUTING,
            FutureTaskType.ANOMALY_PRIORITIZATION,
            FutureTaskType.REFLECTION_CONTEXT,
            FutureTaskType.ENDPOINT_SIMILARITY,
        ]:
            spec = FUTURE_TASK_SPECS[task_type]
            self.assertFalse(spec.is_implemented,
                             f"{task_type} must not be marked implemented (no training data)")

    def test_specs_have_minimum_label_counts(self):
        for task_type, spec in FUTURE_TASK_SPECS.items():
            self.assertGreaterEqual(spec.minimum_real_labels, 0)


# ===========================================================================
# Gate 32 — Data Flywheel
# ===========================================================================
class DataFlywheelTest(unittest.TestCase):
    def test_forbidden_patterns_documented(self):
        self.assertGreater(len(FLYWHEEL_FORBIDDEN), 0)
        self.assertIn("prediction -> automatic_label -> retrain", FLYWHEEL_FORBIDDEN)

    def test_required_patterns_documented(self):
        self.assertGreater(len(FLYWHEEL_REQUIRED), 0)
        # Human review is always a required step
        human_step = any("human_label" in s for s in FLYWHEEL_REQUIRED)
        self.assertTrue(human_step)

    def test_explicit_promotion_required(self):
        promo_step = any("explicit_promotion" in s for s in FLYWHEEL_REQUIRED)
        self.assertTrue(promo_step)


# ===========================================================================
# Gate 33 — Active Learning Queue
# ===========================================================================
class ActiveLearningTest(unittest.TestCase):
    def test_add_uncertain_sample(self):
        q = ActiveLearningQueue()
        q.add_uncertain("obs-001", 0.45, "mlp_task_a_v1")
        self.assertEqual(q.size(), 1)

    def test_pop_returns_highest_uncertainty_first(self):
        q = ActiveLearningQueue()
        q.add_uncertain("obs-low",  0.1, "model")
        q.add_uncertain("obs-high", 0.9, "model")
        q.add_uncertain("obs-mid",  0.5, "model")
        first = q.pop_for_review()
        self.assertEqual(first["observation_ref"], "obs-high")

    def test_auto_labeled_never_true(self):
        q = ActiveLearningQueue()
        q.add_uncertain("obs-001", 0.45, "model")
        item = q.pop_for_review()
        self.assertFalse(item["auto_labeled"],
                         "Active learning must never auto-label samples")

    def test_requires_human_review_always_true(self):
        q = ActiveLearningQueue()
        q.add_uncertain("obs-001", 0.45, "model")
        item = q.pop_for_review()
        self.assertTrue(item["requires_human_review"])

    def test_queue_respects_max_size(self):
        q = ActiveLearningQueue(max_queue_size=3)
        for i in range(10):
            q.add_uncertain(f"obs-{i}", float(i) / 10, "model")
        self.assertLessEqual(q.size(), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
