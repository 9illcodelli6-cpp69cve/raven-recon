"""RAVEN Phase III — Access Control Academy graduation exam engine.

Evaluates SEC-A rule accuracy, conceptual understanding, false-positive
rejection, BOLA/BFLA classification, and invariant enforcement.

INVARIANTS (same as all Phase III code):
  - external_targets == 0
  - human_reviewed_labels == 0
  - security_authority == NONE
  - All results are EDUCATIONAL only
  - human_verification_required is ALWAYS True on all findings
  - do NOT begin vulnerability-family training
  - do NOT fabricate results
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from raven.access_control.access_tuple import (
    AccessContext, AccessTuple,
    classify_authorization_experiment, compute_authorization_dimensions,
)
from raven.access_control.candidate import CandidateAuthorizationFinding
from raven.access_control.lab3 import AccessControlLab3, AccessControlFixture
from raven.access_control.principals import Action, Principal, Resource
from raven.access_control.rules3 import (
    build_candidate_finding, infer_violation_type_conceptual, rule_sec_a,
)
from raven.access_control.taxonomy3 import (
    AccessDecision, ActionType, AuthorizationExperimentQuality,
    AuthorizationViolationType, PrincipalType, ResourceType,
)


# ── Exam result types ─────────────────────────────────────────────────────────

class FailureReason(str, Enum):
    KNOWLEDGE_GAP        = "KNOWLEDGE_GAP"
    FEATURE_GAP          = "FEATURE_GAP"
    LABEL_ERROR          = "LABEL_ERROR"
    AMBIGUOUS_TARGET     = "AMBIGUOUS_TARGET"
    RULE_TOO_BROAD       = "RULE_TOO_BROAD"
    RULE_TOO_NARROW      = "RULE_TOO_NARROW"
    DATA_LEAKAGE         = "DATA_LEAKAGE"
    SPLIT_FAILURE        = "SPLIT_FAILURE"
    TASK_UNDERDETERMINED = "TASK_UNDERDETERMINED"
    IMPLEMENTATION_BUG   = "IMPLEMENTATION_BUG"
    TEST_BUG             = "TEST_BUG"


@dataclass
class ExamResult:
    exam_id: str
    category: str
    passed: bool
    predicted: object
    expected: object
    note: str = ""
    failure_reason: Optional[FailureReason] = None


@dataclass
class ExamCategory:
    name: str
    results: list[ExamResult] = field(default_factory=list)

    @property
    def n_pass(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def n_fail(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def accuracy(self) -> float:
        n = len(self.results)
        return self.n_pass / n if n else 0.0

    def summary(self) -> str:
        return (f"{self.name}: {self.n_pass}/{len(self.results)} "
                f"({self.accuracy:.0%})")


# ── Helper builders ───────────────────────────────────────────────────────────

def _p(pid: str, ptype: PrincipalType, identity: str,
       roles: Optional[list[str]] = None,
       is_owner: bool = False) -> Principal:
    return Principal(principal_id=pid, principal_type=ptype,
                     identity=identity, roles=roles or [], is_resource_owner=is_owner)


def _r(rid: str, rtype: ResourceType, path: str,
       owner: Optional[str] = None, sensitivity: str = "MEDIUM") -> Resource:
    return Resource(resource_id=rid, resource_type=rtype,
                    path=path, owner_principal_id=owner, sensitivity=sensitivity)


def _a(aid: str, atype: ActionType, method: str,
       requires_ownership: bool = False, requires_admin: bool = False) -> Action:
    return Action(action_id=aid, action_type=atype, http_method=method,
                  requires_ownership=requires_ownership,
                  requires_admin_role=requires_admin)


def _t(principal: Principal, action: Action, resource: Resource,
       expected: AccessDecision = AccessDecision.UNKNOWN,
       observed: AccessDecision = AccessDecision.UNKNOWN,
       session: Optional[str] = None) -> AccessTuple:
    ctx = AccessContext(session_id=session)
    return AccessTuple(principal=principal, action=action, resource=resource,
                       context=ctx,
                       expected_decision=expected,
                       observed_decision=observed)


def _check_sec_a(
    exam_id: str, category: str,
    control: AccessTuple, test: AccessTuple,
    expected: AuthorizationExperimentQuality,
    ctrl_status: Optional[int] = None, tst_status: Optional[int] = None,
    ctrl_body: Optional[str] = None, tst_body: Optional[str] = None,
    note: str = "",
) -> ExamResult:
    pred = rule_sec_a(control, test, ctrl_status, tst_status, ctrl_body, tst_body)
    passed = pred == expected
    return ExamResult(exam_id=exam_id, category=category,
                      passed=passed, predicted=pred.value, expected=expected.value,
                      note=note)


def _check_violation(
    exam_id: str, category: str,
    control: AccessTuple, test: AccessTuple,
    quality: AuthorizationExperimentQuality,
    expected: AuthorizationViolationType,
    ctrl_status: Optional[int] = None, tst_status: Optional[int] = None,
    note: str = "",
) -> ExamResult:
    pred = infer_violation_type_conceptual(
        control, test, quality, ctrl_status, tst_status)
    passed = pred == expected
    return ExamResult(exam_id=exam_id, category=category,
                      passed=passed, predicted=pred.value, expected=expected.value,
                      note=note)


# ── Exam categories ───────────────────────────────────────────────────────────

def run_sec_a_basic() -> ExamCategory:
    """SEC-A1-SEC-A12: Basic experiment quality classification."""
    cat = ExamCategory("sec_a_basic")

    alice = _p("p_a", PrincipalType.USER, "user_alice", ["user"], is_owner=True)
    bob   = _p("p_b", PrincipalType.USER, "user_bob",   ["user"], is_owner=False)
    admin = _p("p_admin", PrincipalType.ADMIN, "admin", ["admin"])
    anon  = _p("p_anon",  PrincipalType.ANONYMOUS, "anonymous", [])

    r_alice = _r("r_a", ResourceType.USER_OWNED_DATA, "/api/u/alice", "p_a", "HIGH")
    r_bob   = _r("r_b", ResourceType.USER_OWNED_DATA, "/api/u/bob",   "p_b", "HIGH")
    r_admin = _r("r_adm", ResourceType.ADMIN_RESOURCE, "/api/admin",  None,  "HIGH")
    r_pub   = _r("r_pub", ResourceType.PUBLIC_DATA,    "/api/catalog", None, "LOW")

    a_read   = _a("a_rd",  ActionType.READ,   "GET")
    a_write  = _a("a_wr",  ActionType.WRITE,  "PUT", requires_ownership=True)
    a_delete = _a("a_del", ActionType.DELETE, "DELETE", requires_ownership=True)
    a_admin  = _a("a_adm", ActionType.ADMIN,  "GET", requires_admin=True)

    # SA1: Only principal changed → CONTROLLED_SINGLE_PRINCIPAL
    cat.results.append(_check_sec_a(
        "sa1_single_principal", cat.name,
        _t(alice, a_read, r_alice), _t(bob, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        ctrl_status=200, tst_status=403,
        note="Only principal_id changed — CONTROLLED_SINGLE_PRINCIPAL",
    ))

    # SA2: Only resource changed → CONTROLLED_SINGLE_RESOURCE
    cat.results.append(_check_sec_a(
        "sa2_single_resource", cat.name,
        _t(bob, a_read, r_bob), _t(bob, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE,
        ctrl_status=200, tst_status=200,
        note="Only resource_id changed — CONTROLLED_SINGLE_RESOURCE",
    ))

    # SA3: Only action changed → CONTROLLED_SINGLE_ACTION
    cat.results.append(_check_sec_a(
        "sa3_single_action", cat.name,
        _t(alice, a_read, r_alice), _t(alice, a_write, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_ACTION,
        ctrl_status=200, tst_status=200,
        note="Only action changed (read→write) — CONTROLLED_SINGLE_ACTION",
    ))

    # SA4: Principal + resource both changed → CONFOUNDED
    cat.results.append(_check_sec_a(
        "sa4_confounded_pr", cat.name,
        _t(alice, a_read, r_alice), _t(bob, a_read, r_bob),
        AuthorizationExperimentQuality.CONFOUNDED,
        ctrl_status=200, tst_status=200,
        note="Principal and resource both changed — CONFOUNDED",
    ))

    # SA5: All three dimensions changed → CONFOUNDED
    cat.results.append(_check_sec_a(
        "sa5_confounded_all", cat.name,
        _t(alice, a_read, r_alice), _t(admin, a_admin, r_admin),
        AuthorizationExperimentQuality.CONFOUNDED,
        ctrl_status=200, tst_status=200,
        note="Principal, action, resource all changed — CONFOUNDED",
    ))

    # SA6: No dims changed, same 200 → NO_MEANINGFUL_CHANGE
    cat.results.append(_check_sec_a(
        "sa6_no_meaningful_change", cat.name,
        _t(alice, a_read, r_alice), _t(alice, a_read, r_alice),
        AuthorizationExperimentQuality.NO_MEANINGFUL_CHANGE,
        ctrl_status=200, tst_status=200, ctrl_body='{"data":1}', tst_body='{"data":1}',
        note="Identical tuples + identical response → NO_MEANINGFUL_CHANGE",
    ))

    # SA7: No dims changed, different response → INSUFFICIENT_CONTEXT
    cat.results.append(_check_sec_a(
        "sa7_insufficient_context", cat.name,
        _t(alice, a_read, r_alice), _t(alice, a_read, r_alice),
        AuthorizationExperimentQuality.INSUFFICIENT_CONTEXT,
        ctrl_status=200, tst_status=403,
        note="No dims changed but responses differ → INSUFFICIENT_CONTEXT",
    ))

    # SA8: PrincipalType changed (USER→ADMIN) → CONTROLLED_SINGLE_PRINCIPAL
    alice_as_admin = _p("p_a", PrincipalType.ADMIN, "user_alice", ["admin"])
    cat.results.append(_check_sec_a(
        "sa8_principal_type_change", cat.name,
        _t(alice, a_read, r_alice), _t(alice_as_admin, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        ctrl_status=200, tst_status=200,
        note="PrincipalType changed USER→ADMIN — CONTROLLED_SINGLE_PRINCIPAL",
    ))

    # SA9: Role changed → CONTROLLED_SINGLE_PRINCIPAL
    alice_norole = _p("p_a", PrincipalType.USER, "user_alice", [])
    alice_role   = _p("p_a", PrincipalType.USER, "user_alice", ["user"])
    cat.results.append(_check_sec_a(
        "sa9_role_changed", cat.name,
        _t(alice_norole, a_read, r_alice), _t(alice_role, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        ctrl_status=200, tst_status=200,
        note="Only roles changed — CONTROLLED_SINGLE_PRINCIPAL",
    ))

    # SA10: HTTP method changed (GET→DELETE) → CONTROLLED_SINGLE_ACTION
    cat.results.append(_check_sec_a(
        "sa10_method_changed", cat.name,
        _t(alice, a_read, r_alice), _t(alice, a_delete, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_ACTION,
        ctrl_status=200, tst_status=204,
        note="HTTP method changed GET→DELETE — CONTROLLED_SINGLE_ACTION",
    ))

    # SA11: Resource type changed → CONTROLLED_SINGLE_RESOURCE
    r_admin_type = _r("r_a", ResourceType.ADMIN_RESOURCE, "/api/u/alice", "p_a", "HIGH")
    cat.results.append(_check_sec_a(
        "sa11_resource_type_changed", cat.name,
        _t(alice, a_read, r_alice), _t(alice, a_read, r_admin_type),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE,
        ctrl_status=200, tst_status=200,
        note="ResourceType changed — CONTROLLED_SINGLE_RESOURCE",
    ))

    # SA12: Both principal and action changed → CONFOUNDED
    cat.results.append(_check_sec_a(
        "sa12_confounded_pa", cat.name,
        _t(alice, a_read, r_alice), _t(admin, a_admin, r_alice),
        AuthorizationExperimentQuality.CONFOUNDED,
        ctrl_status=200, tst_status=200,
        note="Principal and action both changed — CONFOUNDED",
    ))

    return cat


def run_shortcut_detection() -> ExamCategory:
    """SD1-SD8: Verify SEC-A/violation rules are not fooled by superficial signals."""
    cat = ExamCategory("shortcut_detection")

    alice = _p("p_a", PrincipalType.USER, "user_alice", ["user"], is_owner=True)
    bob   = _p("p_b", PrincipalType.USER, "user_bob",   ["user"], is_owner=False)
    admin = _p("p_adm", PrincipalType.ADMIN, "admin", ["admin"])

    r_alice = _r("r_a", ResourceType.USER_OWNED_DATA, "/api/u/alice", "p_a", "HIGH")
    r_admin = _r("r_adm", ResourceType.ADMIN_RESOURCE, "/api/admin", None, "HIGH")

    a_read  = _a("a_rd",  ActionType.READ,   "GET")
    a_admin = _a("a_adm", ActionType.ADMIN,  "GET", requires_admin=True)

    # SD1: 403 ≠ BOLA (correct enforcement is NOT a violation)
    cat.results.append(_check_violation(
        "sd1_403_not_bola", cat.name,
        _t(alice, a_read, r_alice), _t(bob, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.NO_VIOLATION_EXPECTED,
        ctrl_status=200, tst_status=403,
        note="SHORTCUT: 403 on non-owner ≠ BOLA. Correct enforcement = NO_VIOLATION_EXPECTED",
    ))

    # SD2: 200 on admin endpoint by admin ≠ BFLA
    cat.results.append(_check_violation(
        "sd2_admin_200_not_bfla", cat.name,
        _t(alice, a_read, r_alice), _t(admin, a_admin, r_admin),
        AuthorizationExperimentQuality.CONFOUNDED,
        AuthorizationViolationType.INCONCLUSIVE,
        ctrl_status=200, tst_status=200,
        note="CONFOUNDED experiment → INCONCLUSIVE regardless of 200 response",
    ))

    # SD3: Same principal, different resource IDs → NOT automatically BOLA
    r_alice2 = _r("r_a2", ResourceType.USER_OWNED_DATA, "/api/u/alice/orders", "p_a", "HIGH")
    cat.results.append(_check_violation(
        "sd3_resource_enum_not_bola", cat.name,
        _t(alice, a_read, r_alice), _t(alice, a_read, r_alice2),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE,
        AuthorizationViolationType.NO_VIOLATION_EXPECTED,
        ctrl_status=200, tst_status=200,
        note="Same principal, own resources — NOT BOLA even with resource ID change",
    ))

    # SD4: CONFOUNDED → always INCONCLUSIVE, never BOLA/BFLA
    cat.results.append(_check_violation(
        "sd4_confounded_inconclusive", cat.name,
        _t(alice, a_read, r_alice), _t(bob, a_admin, r_admin),
        AuthorizationExperimentQuality.CONFOUNDED,
        AuthorizationViolationType.INCONCLUSIVE,
        ctrl_status=200, tst_status=200,
        note="CONFOUNDED → INCONCLUSIVE always, regardless of response content",
    ))

    # SD5: NO_MEANINGFUL_CHANGE → INCONCLUSIVE
    cat.results.append(_check_violation(
        "sd5_no_change_inconclusive", cat.name,
        _t(alice, a_read, r_alice), _t(alice, a_read, r_alice),
        AuthorizationExperimentQuality.NO_MEANINGFUL_CHANGE,
        AuthorizationViolationType.INCONCLUSIVE,
        ctrl_status=200, tst_status=200,
        note="NO_MEANINGFUL_CHANGE → INCONCLUSIVE",
    ))

    # SD6: INSUFFICIENT_CONTEXT → INCONCLUSIVE
    cat.results.append(_check_violation(
        "sd6_insufficient_context_inconclusive", cat.name,
        _t(alice, a_read, r_alice), _t(alice, a_read, r_alice),
        AuthorizationExperimentQuality.INSUFFICIENT_CONTEXT,
        AuthorizationViolationType.INCONCLUSIVE,
        ctrl_status=200, tst_status=403,
        note="INSUFFICIENT_CONTEXT → INCONCLUSIVE",
    ))

    # SD7: Non-owner gets 403 (correct) — owner gets 200 — sec-a is CONTROLLED_SINGLE_PRINCIPAL
    cat.results.append(_check_sec_a(
        "sd7_sec_a_correct_denial", cat.name,
        _t(alice, a_read, r_alice), _t(bob, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        ctrl_status=200, tst_status=403,
        note="SHORTCUT: denial doesn't change SEC-A quality — still CONTROLLED_SINGLE_PRINCIPAL",
    ))

    # SD8: Admin successfully uses admin endpoint — CONTROLLED_SINGLE_PRINCIPAL, no violation
    cat.results.append(_check_violation(
        "sd8_admin_correct_access", cat.name,
        _t(bob, a_admin, r_admin), _t(admin, a_admin, r_admin),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.NO_VIOLATION_EXPECTED,
        ctrl_status=403, tst_status=200,
        note="Control=regular(403), test=admin(200) — correct enforcement, not BFLA",
    ))

    return cat


def run_false_positive_rejection() -> ExamCategory:
    """FP1-FP6: Verify the rule does not generate false BOLA/BFLA classifications."""
    cat = ExamCategory("false_positive_rejection")

    alice = _p("p_a", PrincipalType.USER, "user_alice", ["user"], is_owner=True)
    admin = _p("p_adm", PrincipalType.ADMIN, "admin", ["admin"])
    svc   = _p("p_svc", PrincipalType.SERVICE_ACCOUNT, "svc", ["service"])

    r_alice = _r("r_a", ResourceType.USER_OWNED_DATA, "/api/u/alice", "p_a")
    r_alice2 = _r("r_a2", ResourceType.USER_OWNED_DATA, "/api/u/alice/orders", "p_a")
    r_pub   = _r("r_pub", ResourceType.PUBLIC_DATA, "/api/catalog", None)

    a_read = _a("a_rd", ActionType.READ, "GET")

    # FP1: Admin reads alice's data — ADMIN has cross-user access by design
    # Infer should be INCONCLUSIVE (need policy context to determine if admin access is valid)
    cat.results.append(_check_violation(
        "fp1_admin_cross_user", cat.name,
        _t(alice, a_read, r_alice), _t(admin, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.INCONCLUSIVE,
        ctrl_status=200, tst_status=200,
        note="ADMIN accessing user data — INCONCLUSIVE (admin cross-user access is by design)",
    ))

    # FP2: Alice reads her own resources (two different ones) — NO violation
    cat.results.append(_check_violation(
        "fp2_owner_own_resources", cat.name,
        _t(alice, a_read, r_alice), _t(alice, a_read, r_alice2),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE,
        AuthorizationViolationType.NO_VIOLATION_EXPECTED,
        ctrl_status=200, tst_status=200,
        note="Owner reading own different resources — NO_VIOLATION_EXPECTED",
    ))

    # FP3: Public catalog accessible to anyone — NO violation
    alice_pub = _p("p_a", PrincipalType.USER, "user_alice", ["user"], is_owner=False)
    bob_pub   = _p("p_b", PrincipalType.USER, "user_bob",   ["user"], is_owner=False)
    cat.results.append(_check_violation(
        "fp3_public_resource_any_user", cat.name,
        _t(alice_pub, a_read, r_pub), _t(bob_pub, a_read, r_pub),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.NO_VIOLATION_EXPECTED,
        ctrl_status=200, tst_status=200,
        note="PUBLIC_DATA resource — any principal allowed; NO_VIOLATION_EXPECTED",
    ))

    # FP4: Correct 401 on anon → protected resource — NO violation (correct enforcement)
    anon = _p("p_anon", PrincipalType.ANONYMOUS, "anon", [], is_owner=False)
    cat.results.append(_check_violation(
        "fp4_anon_denied_correct", cat.name,
        _t(alice, a_read, r_alice), _t(anon, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.NO_VIOLATION_EXPECTED,
        ctrl_status=200, tst_status=401,
        note="Anon correctly denied (401) — NO_VIOLATION_EXPECTED",
    ))

    # FP5: Confounded experiment — never conclude BOLA even if pattern looks right
    bob_wrong = _p("p_b", PrincipalType.USER, "user_bob", [], is_owner=False)
    a_write   = _a("a_wr", ActionType.WRITE, "PUT", requires_ownership=True)
    cat.results.append(_check_violation(
        "fp5_confounded_no_bola", cat.name,
        _t(alice, a_read, r_alice), _t(bob_wrong, a_write, r_alice),
        AuthorizationExperimentQuality.CONFOUNDED,
        AuthorizationViolationType.INCONCLUSIVE,
        ctrl_status=200, tst_status=200,
        note="CONFOUNDED (principal + action changed) → INCONCLUSIVE, never BOLA/BFLA",
    ))

    # FP6: Service account reading user data — INCONCLUSIVE without policy context
    cat.results.append(_check_violation(
        "fp6_service_account_inconclusive", cat.name,
        _t(alice, a_read, r_alice), _t(svc, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.INCONCLUSIVE,
        ctrl_status=200, tst_status=200,
        note="Service account access — INCONCLUSIVE without knowing authorization policy",
    ))

    return cat


def run_lab_fixture_accuracy() -> ExamCategory:
    """LF1-LF_N: Verify SEC-A rule matches expected quality on all lab fixtures."""
    cat = ExamCategory("lab_fixture_accuracy")
    lab = AccessControlLab3(n_variants=1)

    for fix in lab.fixtures():
        pred = rule_sec_a(
            fix.control_tuple, fix.test_tuple,
            fix.control_http_status, fix.test_http_status,
        )
        passed = pred == fix.expected_quality
        cat.results.append(ExamResult(
            exam_id=f"lf_{fix.fixture_id}",
            category=cat.name,
            passed=passed,
            predicted=pred.value,
            expected=fix.expected_quality.value,
            note=fix.notes[:120] if fix.notes else "",
        ))
    return cat


def run_candidate_invariants() -> ExamCategory:
    """CI1-CI6: Verify CandidateAuthorizationFinding invariants hold."""
    cat = ExamCategory("candidate_invariants")

    alice = _p("p_a", PrincipalType.USER, "user_alice", ["user"], is_owner=True)
    bob   = _p("p_b", PrincipalType.USER, "user_bob",   ["user"], is_owner=False)
    r_alice = _r("r_a", ResourceType.USER_OWNED_DATA, "/api/u/alice", "p_a")
    a_read  = _a("a_rd", ActionType.READ, "GET")

    ctrl = _t(alice, a_read, r_alice, expected=AccessDecision.ALLOWED)
    test = _t(bob,   a_read, r_alice, expected=AccessDecision.DENIED,
              observed=AccessDecision.ALLOWED)

    # CI1: human_verification_required is always True
    finding = build_candidate_finding(
        "cf1", ctrl, test,
        hypothesis="Non-owner access to owner resource",
        control_http_status=200, test_http_status=200,
    )
    cat.results.append(ExamResult(
        exam_id="ci1_hvr_always_true", category=cat.name,
        passed=finding.human_verification_required is True,
        predicted=finding.human_verification_required,
        expected=True,
        note="human_verification_required must always be True",
    ))

    # CI2: Cannot set human_verification_required to False
    try:
        finding.human_verification_required = False
        cat.results.append(ExamResult(
            exam_id="ci2_hvr_immutable", category=cat.name,
            passed=False, predicted="no_error", expected="AttributeError",
            note="Setting human_verification_required=False must raise AttributeError",
        ))
    except AttributeError:
        cat.results.append(ExamResult(
            exam_id="ci2_hvr_immutable", category=cat.name,
            passed=True, predicted="AttributeError", expected="AttributeError",
            note="Correctly raises AttributeError when setting human_verification_required=False",
        ))

    # CI3: data_source is EDUCATIONAL_SYNTHETIC
    cat.results.append(ExamResult(
        exam_id="ci3_educational_synthetic", category=cat.name,
        passed=finding.data_source == "EDUCATIONAL_SYNTHETIC",
        predicted=finding.data_source,
        expected="EDUCATIONAL_SYNTHETIC",
        note="data_source must be EDUCATIONAL_SYNTHETIC",
    ))

    # CI4: SEC-A quality is populated by build_candidate_finding
    cat.results.append(ExamResult(
        exam_id="ci4_sec_a_quality_populated", category=cat.name,
        passed=finding.sec_a_quality != AuthorizationExperimentQuality.UNKNOWN,
        predicted=finding.sec_a_quality.value,
        expected="!= UNKNOWN",
        note="build_candidate_finding must populate sec_a_quality",
    ))

    # CI5: finding_id required — empty string must raise
    try:
        bad = CandidateAuthorizationFinding(
            finding_id="", control_tuple=ctrl, test_tuple=test)
        cat.results.append(ExamResult(
            exam_id="ci5_empty_id_raises", category=cat.name,
            passed=False, predicted="no_error", expected="ValueError",
            note="Empty finding_id must raise ValueError",
        ))
    except ValueError:
        cat.results.append(ExamResult(
            exam_id="ci5_empty_id_raises", category=cat.name,
            passed=True, predicted="ValueError", expected="ValueError",
            note="Correctly raises ValueError on empty finding_id",
        ))

    # CI6: is_inconclusive reflects quality correctly
    inconclusive_finding = build_candidate_finding(
        "cf6", ctrl, _t(alice, a_read, r_alice),  # identical — INSUFFICIENT_CONTEXT
        hypothesis="test", control_http_status=200, test_http_status=403,
    )
    cat.results.append(ExamResult(
        exam_id="ci6_inconclusive_reflects_quality", category=cat.name,
        passed=inconclusive_finding.is_inconclusive,
        predicted=inconclusive_finding.sec_a_quality.value,
        expected="is_inconclusive=True for INSUFFICIENT_CONTEXT/CONFOUNDED/UNKNOWN",
        note="is_inconclusive property must reflect INSUFFICIENT_CONTEXT quality",
    ))

    return cat


def run_phase2_retention() -> ExamCategory:
    """PR1-PR4: Verify Phase II knowledge is retained (NET-E/F/G/H spot-checks)."""
    cat = ExamCategory("phase2_retention")

    try:
        from raven.network_phase2.rules2 import rule_net_e, rule_net_f
        from raven.network_phase2.taxonomy2 import (
            ExperimentQualityClass, StateTransitionClass,
        )
        from raven.network_fundamentals.observation import (
            NetworkObservation, NetworkResponse,
        )
        from raven.network_phase2.sequence import ObservationSequence

        def _obs(method: str, path: str, status: int,
                 has_auth: bool = False, has_cookie: bool = False,
                 set_cookie: bool = False, body: str = "") -> NetworkObservation:
            req_h: dict = {"Content-Type": "application/json"}
            if has_auth:
                req_h["Authorization"] = "Bearer token"
            resp_h: dict = {}
            if set_cookie:
                resp_h["Set-Cookie"] = "session=abc123; Path=/; HttpOnly"
            return NetworkObservation.from_exchange(
                method=method, path=path, query_string="",
                request_headers=req_h,
                response=NetworkResponse(
                    status=status, headers=resp_h, body=body,
                    has_set_cookie=set_cookie,
                    has_www_auth=False,
                ),
            )

        def _seq(*steps: NetworkObservation) -> ObservationSequence:
            s = ObservationSequence("pr_seq")
            for obs in steps:
                s.add(obs)
            return s

        # PR1: 401 → 200 with auth header → AUTH_ESTABLISHED
        seq1 = _seq(_obs("GET", "/api/me", 401), _obs("GET", "/api/me", 200, has_auth=True))
        pred1 = rule_net_e(seq1)
        cat.results.append(ExamResult(
            exam_id="pr1_auth_established", category=cat.name,
            passed=(pred1 == StateTransitionClass.AUTH_ESTABLISHED.value or
                    pred1 == StateTransitionClass.AUTH_ESTABLISHED),
            predicted=str(pred1), expected=StateTransitionClass.AUTH_ESTABLISHED.value,
            note="Phase II retention: 401→200+auth = AUTH_ESTABLISHED",
        ))

        # PR2: 200 → 200 + Set-Cookie (no prior cookie) → SESSION_CREATED
        seq2 = _seq(_obs("POST", "/api/login", 200),
                    _obs("GET", "/api/me", 200, set_cookie=True))
        pred2 = rule_net_e(seq2)
        cat.results.append(ExamResult(
            exam_id="pr2_session_created", category=cat.name,
            passed=(pred2 == StateTransitionClass.SESSION_CREATED.value or
                    pred2 == StateTransitionClass.SESSION_CREATED),
            predicted=str(pred2), expected=StateTransitionClass.SESSION_CREATED.value,
            note="Phase II retention: 200 then 200+Set-Cookie = SESSION_CREATED",
        ))

        # PR3: NET-F single variable → CONTROLLED_SINGLE_VARIABLE
        obs_c = _obs("GET", "/api/res", 200, has_auth=False)
        obs_t = _obs("GET", "/api/res", 200, has_auth=True)
        from raven.network_phase2.experiment import ControlledExperiment
        from raven.network_phase2.taxonomy2 import CausalHypothesis
        exp = ControlledExperiment(
            experiment_id="pr3_exp",
            control=obs_c, test=obs_t,
            hypothesis=CausalHypothesis.AUTHENTICATION_DEPENDENCY_SUPPORTED,
        ).classify()
        cat.results.append(ExamResult(
            exam_id="pr3_net_f_controlled", category=cat.name,
            passed=(exp.quality == ExperimentQualityClass.CONTROLLED_SINGLE_VARIABLE),
            predicted=exp.quality.value,
            expected=ExperimentQualityClass.CONTROLLED_SINGLE_VARIABLE.value,
            note="Phase II retention: auth-only change → CONTROLLED_SINGLE_VARIABLE",
        ))

        # PR4: 304 → CACHE_VALIDATED
        seq4 = _seq(_obs("GET", "/api/data", 200, body="data"),
                    _obs("GET", "/api/data", 304))
        pred4 = rule_net_e(seq4)
        cat.results.append(ExamResult(
            exam_id="pr4_cache_validated", category=cat.name,
            passed=(pred4 == StateTransitionClass.CACHE_VALIDATED.value or
                    pred4 == StateTransitionClass.CACHE_VALIDATED),
            predicted=str(pred4), expected=StateTransitionClass.CACHE_VALIDATED.value,
            note="Phase II retention: last=304 → CACHE_VALIDATED",
        ))

    except Exception as exc:
        cat.results.append(ExamResult(
            exam_id="pr_import_error", category=cat.name,
            passed=False, predicted=str(exc), expected="no_exception",
            note=f"Phase II retention test failed with exception: {exc}",
            failure_reason=FailureReason.IMPLEMENTATION_BUG,
        ))

    return cat


def run_bola_bfla_conceptual() -> ExamCategory:
    """BB1-BB10: BOLA/BFLA conceptual classification accuracy."""
    cat = ExamCategory("bola_bfla_conceptual")

    alice = _p("p_a", PrincipalType.USER, "user_alice", ["user"], is_owner=True)
    bob   = _p("p_b", PrincipalType.USER, "user_bob",   ["user"], is_owner=False)
    admin = _p("p_adm", PrincipalType.ADMIN, "admin", ["admin"])

    r_alice = _r("r_a", ResourceType.USER_OWNED_DATA, "/api/u/alice", "p_a")
    r_bob   = _r("r_b", ResourceType.USER_OWNED_DATA, "/api/u/bob",   "p_b")
    r_admin = _r("r_adm", ResourceType.ADMIN_RESOURCE, "/api/admin", None)

    a_read   = _a("a_rd",  ActionType.READ,   "GET")
    a_admin  = _a("a_adm", ActionType.ADMIN,  "GET", requires_admin=True)
    a_delete = _a("a_del", ActionType.DELETE, "DELETE", requires_admin=True)

    # BB1: Non-owner reads owner's resource, succeeds → BOLA candidate
    cat.results.append(_check_violation(
        "bb1_bola_read", cat.name,
        _t(alice, a_read, r_alice), _t(bob, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.BOLA,
        ctrl_status=200, tst_status=200,
        note="Non-owner reads owner resource + succeeds → BOLA candidate",
    ))

    # BB2: Non-owner accesses owner resource by resource ID → BOLA candidate
    cat.results.append(_check_violation(
        "bb2_bola_resource_id", cat.name,
        _t(bob, a_read, r_bob), _t(bob, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE,
        AuthorizationViolationType.BOLA,
        ctrl_status=200, tst_status=200,
        note="Same principal, different resource owned by other → BOLA candidate",
    ))

    # BB3: Non-admin invokes admin function, succeeds → BFLA candidate
    cat.results.append(_check_violation(
        "bb3_bfla_list", cat.name,
        _t(admin, a_admin, r_admin), _t(bob, a_admin, r_admin),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.BFLA,
        ctrl_status=200, tst_status=200,
        note="Non-admin invokes admin function + succeeds → BFLA candidate",
    ))

    # BB4: Non-admin invokes admin delete, succeeds → BFLA candidate
    cat.results.append(_check_violation(
        "bb4_bfla_delete", cat.name,
        _t(admin, a_delete, r_admin), _t(bob, a_delete, r_admin),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.BFLA,
        ctrl_status=200, tst_status=200,
        note="Non-admin invokes admin delete + succeeds → BFLA candidate",
    ))

    # BB5: Non-owner denied (403) → NO_VIOLATION_EXPECTED
    cat.results.append(_check_violation(
        "bb5_denied_not_bola", cat.name,
        _t(alice, a_read, r_alice), _t(bob, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.NO_VIOLATION_EXPECTED,
        ctrl_status=200, tst_status=403,
        note="Non-owner correctly denied (403) → NO_VIOLATION_EXPECTED",
    ))

    # BB6: Non-admin denied (403) → NO_VIOLATION_EXPECTED
    cat.results.append(_check_violation(
        "bb6_admin_denied_not_bfla", cat.name,
        _t(admin, a_admin, r_admin), _t(bob, a_admin, r_admin),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.NO_VIOLATION_EXPECTED,
        ctrl_status=200, tst_status=403,
        note="Non-admin correctly denied (403) → NO_VIOLATION_EXPECTED",
    ))

    # BB7: CONFOUNDED → INCONCLUSIVE (not BOLA or BFLA)
    cat.results.append(_check_violation(
        "bb7_confounded_inconclusive", cat.name,
        _t(alice, a_read, r_alice), _t(bob, a_admin, r_admin),
        AuthorizationExperimentQuality.CONFOUNDED,
        AuthorizationViolationType.INCONCLUSIVE,
        ctrl_status=200, tst_status=200,
        note="CONFOUNDED → INCONCLUSIVE regardless of 200 response",
    ))

    # BB8: INSUFFICIENT_CONTEXT → INCONCLUSIVE
    cat.results.append(_check_violation(
        "bb8_insufficient_inconclusive", cat.name,
        _t(alice, a_read, r_alice), _t(alice, a_read, r_alice),
        AuthorizationExperimentQuality.INSUFFICIENT_CONTEXT,
        AuthorizationViolationType.INCONCLUSIVE,
        ctrl_status=200, tst_status=403,
        note="INSUFFICIENT_CONTEXT → INCONCLUSIVE",
    ))

    # BB9: Same-tier non-owner accesses owner's object → BOLA
    # (BOLA is the specific API-level label for object-level authorization failures,
    # regardless of whether principals are same-tier or cross-tier.)
    charlie = _p("p_c", PrincipalType.USER, "user_charlie", ["user"], is_owner=False)
    cat.results.append(_check_violation(
        "bb9_bola_same_tier", cat.name,
        _t(alice, a_read, r_alice), _t(charlie, a_read, r_alice),
        AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
        AuthorizationViolationType.BOLA,
        ctrl_status=200, tst_status=200,
        note=(
            "Same-tier non-owner access succeeds → BOLA candidate. "
            "BOLA is the specific API label for object-level auth failures."
        ),
    ))

    # BB10: Lab fixture comprehensive accuracy spot check
    lab = AccessControlLab3(n_variants=1)
    bola_fixtures = lab.get_by_family("acl2_bola_candidate")[:1]
    bfla_fixtures = lab.get_by_family("acl3_bfla_candidate")[:1]

    for fix in bola_fixtures + bfla_fixtures:
        pred_q = rule_sec_a(fix.control_tuple, fix.test_tuple,
                            fix.control_http_status, fix.test_http_status)
        pred_v = infer_violation_type_conceptual(
            fix.control_tuple, fix.test_tuple, pred_q,
            fix.control_http_status, fix.test_http_status)
        passed = pred_v == fix.expected_violation_type
        cat.results.append(ExamResult(
            exam_id=f"bb10_lab_{fix.fixture_id}", category=cat.name,
            passed=passed,
            predicted=pred_v.value,
            expected=fix.expected_violation_type.value,
            note=fix.notes[:120] if fix.notes else "",
        ))

    return cat


def run_matrix_accuracy() -> ExamCategory:
    """MA1-MA6: AuthorizationMatrix lookup accuracy."""
    cat = ExamCategory("matrix_accuracy")
    lab = AccessControlLab3(n_variants=1)
    matrix = lab.build_authorization_matrix()

    checks = [
        ("ma1_alice_read_own", "p_alice", "a_read",    "r_profile_alice", AccessDecision.ALLOWED),
        ("ma2_bob_read_own",   "p_bob",   "a_read",    "r_profile_bob",   AccessDecision.ALLOWED),
        ("ma3_bob_alice_denied","p_bob",  "a_read",    "r_profile_alice", AccessDecision.DENIED),
        ("ma4_admin_broad",    "p_admin", "a_read",    "r_profile_alice", AccessDecision.ALLOWED),
        ("ma5_anon_denied",    "p_anon",  "a_read",    "r_profile_alice", AccessDecision.DENIED),
        ("ma6_unknown_key",    "p_nobody","a_read",    "r_profile_alice", AccessDecision.UNKNOWN),
    ]
    for exam_id, pid, aid, rid, expected in checks:
        pred = matrix.lookup(pid, aid, rid)
        cat.results.append(ExamResult(
            exam_id=exam_id, category=cat.name,
            passed=(pred == expected),
            predicted=pred.value, expected=expected.value,
        ))
    return cat


def run_cross_process_determinism() -> ExamCategory:
    """CPD1: Three fresh processes produce identical fixture hashes."""
    cat = ExamCategory("cross_process_determinism")

    script = """
import hashlib, json, sys
sys.path.insert(0, r'{wd}')
from raven.access_control.lab3 import AccessControlLab3
lab = AccessControlLab3(n_variants=2)
data = sorted([
    (f.fixture_id, f.expected_quality.value, f.expected_violation_type.value)
    for f in lab.fixtures()
])
digest = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
print(digest)
""".strip()

    import os
    wd = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    script_filled = script.replace(r'{wd}', wd.replace("\\", "\\\\"))

    hashes: list[str] = []
    for _ in range(3):
        try:
            result = subprocess.run(
                [sys.executable, "-c", script_filled],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                h = result.stdout.strip()
                if h:
                    hashes.append(h)
        except Exception:
            pass

    if len(hashes) == 3 and len(set(hashes)) == 1:
        cat.results.append(ExamResult(
            exam_id="cpd1_fixture_hash_deterministic", category=cat.name,
            passed=True, predicted=hashes[0], expected=hashes[0],
            note="All 3 processes produced identical SHA-256 fixture hash",
        ))
    else:
        cat.results.append(ExamResult(
            exam_id="cpd1_fixture_hash_deterministic", category=cat.name,
            passed=False, predicted=str(hashes), expected="3 identical hashes",
            note=f"Determinism check failed: {len(hashes)} valid hashes, {len(set(hashes))} distinct",
            failure_reason=FailureReason.IMPLEMENTATION_BUG,
        ))

    return cat


def run_leakage_audit() -> ExamCategory:
    """LA1-LA3: No label leaks in fixture IDs, data sources, or multi-family coverage."""
    cat = ExamCategory("leakage_audit")
    lab = AccessControlLab3(n_variants=2)
    fixtures = lab.fixtures()

    # LA1: data_source must be EDUCATIONAL_SYNTHETIC
    wrong_src = [f for f in fixtures if f.data_source != "EDUCATIONAL_SYNTHETIC"]
    cat.results.append(ExamResult(
        exam_id="la1_data_source_synthetic", category=cat.name,
        passed=len(wrong_src) == 0,
        predicted=f"{len(wrong_src)} fixtures with wrong data_source",
        expected="0 fixtures with wrong data_source",
        note="All fixtures must have data_source='EDUCATIONAL_SYNTHETIC'",
    ))

    # LA2: Label values must not appear verbatim in fixture_id
    label_values = {v.value.lower() for v in AuthorizationViolationType}
    label_values |= {v.value.lower() for v in AuthorizationExperimentQuality}
    leaky = [
        f for f in fixtures
        if any(label in f.fixture_id.lower() for label in label_values
               if label not in ("bola", "bfla", "unknown", "inconclusive"))
    ]
    cat.results.append(ExamResult(
        exam_id="la2_label_not_in_fixture_id", category=cat.name,
        passed=len(leaky) == 0,
        predicted=f"{len(leaky)} fixtures with label in ID",
        expected="0 leaky fixture IDs",
        note="Full quality/violation label values must not appear verbatim in fixture_ids",
    ))

    # LA3: Multi-family coverage (soft check — ≥2 distinct families per expected quality)
    from collections import defaultdict
    family_by_quality: dict[str, set[str]] = defaultdict(set)
    for f in fixtures:
        family_by_quality[f.expected_quality.value].add(f.scenario_family)
    multi_family = sum(1 for fams in family_by_quality.values() if len(fams) >= 2)
    total_qualities = len(family_by_quality)
    multi_family_pct = multi_family / total_qualities if total_qualities else 0.0
    cat.results.append(ExamResult(
        exam_id="la3_multi_family_coverage", category=cat.name,
        passed=(multi_family_pct >= 0.30),
        predicted=f"{multi_family}/{total_qualities} ({multi_family_pct:.0%})",
        expected=">= 30% qualities have >=2 families",
        note="DATA_QUALITY_KNOWN_LIMITATION: some quality classes appear in only one family",
    ))

    return cat


def run_all_exams() -> dict:
    """Run all Phase III graduation exam categories and return results."""
    categories = [
        run_sec_a_basic(),
        run_shortcut_detection(),
        run_false_positive_rejection(),
        run_lab_fixture_accuracy(),
        run_candidate_invariants(),
        run_bola_bfla_conceptual(),
        run_matrix_accuracy(),
        run_phase2_retention(),
        run_cross_process_determinism(),
        run_leakage_audit(),
    ]
    total_pass = sum(c.n_pass for c in categories)
    total_fail = sum(c.n_fail for c in categories)
    total = total_pass + total_fail
    return {
        "categories": categories,
        "total_pass": total_pass,
        "total_fail": total_fail,
        "total": total,
        "overall_accuracy": total_pass / total if total else 0.0,
        "external_targets": 0,
        "human_reviewed_labels": 0,
        "security_authority": "NONE",
    }
