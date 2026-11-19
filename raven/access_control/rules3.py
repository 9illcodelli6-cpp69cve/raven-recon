"""RAVEN Phase III — SEC-A authorization experiment quality rule.

Deterministic rule for classifying authorization experiment quality.
Analogous to NET-F (ExperimentQualityClass) for Phase II but applied
to the PRINCIPAL / ACTION / RESOURCE / CONTEXT dimensions.

CRITICAL:
  SEC-A classification ≠ vulnerability detection.
  BOLA/BFLA are conceptual educational labels — they require human
  verification before any conclusion can be drawn.
  Security authority: NONE.
  Rule does not generate, schedule, or recommend network requests.
"""
from __future__ import annotations

from typing import Optional

from raven.access_control.access_tuple import (
    AccessTuple, classify_authorization_experiment,
    compute_authorization_dimensions,
)
from raven.access_control.candidate import CandidateAuthorizationFinding
from raven.access_control.taxonomy3 import (
    AuthorizationExperimentQuality, AuthorizationViolationType,
    _ACTION_DIMS, _PRINCIPAL_DIMS, _RESOURCE_DIMS,
)


# ── SEC-A rule ─────────────────────────────────────────────────────────────────

def rule_sec_a(
    control: AccessTuple,
    test: AccessTuple,
    control_http_status: Optional[int] = None,
    test_http_status: Optional[int] = None,
    control_body: Optional[str] = None,
    test_body: Optional[str] = None,
) -> AuthorizationExperimentQuality:
    """Classify the quality of an access control comparison experiment (SEC-A).

    The rule examines how many authorization dimensions changed between the
    control and test access tuples and returns the appropriate quality class.

    Args:
        control: The baseline/reference access tuple.
        test: The experimental (modified) access tuple.
        control_http_status: HTTP status of the control server response (optional).
        test_http_status: HTTP status of the test server response (optional).
        control_body: Response body string of the control response (optional).
        test_body: Response body string of the test response (optional).

    Returns:
        AuthorizationExperimentQuality — experiment quality classification.

    CRITICAL: The returned value is experiment quality, NOT a security verdict.
    """
    return classify_authorization_experiment(
        control=control,
        test=test,
        control_http_status=control_http_status,
        test_http_status=test_http_status,
        control_body=control_body,
        test_body=test_body,
    )


# ── Violation type inference (conceptual, educational only) ───────────────────

def infer_violation_type_conceptual(
    control: AccessTuple,
    test: AccessTuple,
    quality: AuthorizationExperimentQuality,
    control_http_status: Optional[int] = None,
    test_http_status: Optional[int] = None,
) -> AuthorizationViolationType:
    """Infer the conceptual violation type for educational classification.

    CRITICAL:
      This function produces EDUCATIONAL LABELS only.
      The inferred type is NOT a confirmed vulnerability finding.
      Human verification is ALWAYS required.
      security_authority = NONE

    Logic:
      - CONFOUNDED / INSUFFICIENT_CONTEXT / NO_MEANINGFUL_CHANGE → INCONCLUSIVE
      - CONTROLLED_SINGLE_PRINCIPAL + principal is non-owner accessing owner's
        resource + access appears to succeed → BOLA (conceptual)
      - CONTROLLED_SINGLE_ACTION + test action requires admin + non-admin
        principal + access appears to succeed → BFLA (conceptual)
      - CONTROLLED_SINGLE_RESOURCE + resource ID changed (same principal) +
        access appears to succeed on other-owner resource → BOLA (conceptual)
      - Cannot determine → INCONCLUSIVE
    """
    # Non-controlled experiments cannot support violation classification
    if quality in (
        AuthorizationExperimentQuality.CONFOUNDED,
        AuthorizationExperimentQuality.INSUFFICIENT_CONTEXT,
        AuthorizationExperimentQuality.NO_MEANINGFUL_CHANGE,
        AuthorizationExperimentQuality.UNKNOWN,
    ):
        return AuthorizationViolationType.INCONCLUSIVE

    # Apparent success = 2xx response on test
    test_appears_to_succeed = (
        test_http_status is not None and 200 <= test_http_status < 300
    )
    # Control denied = 4xx on control
    control_denied = (
        control_http_status is not None and 400 <= control_http_status < 500
    )

    changed = compute_authorization_dimensions(control, test)

    if quality == AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL:
        tp = test.principal
        resource = control.resource  # same resource (resource dims unchanged)
        test_denied = test_http_status is not None and 400 <= test_http_status < 500
        tp_is_admin = (
            tp.principal_type.value == "ADMIN"
            or "ADMIN" in [r.upper() for r in tp.roles]
        )

        # BFLA: non-admin invokes admin-required function
        if test.action.requires_admin_role and not tp_is_admin:
            if test_appears_to_succeed:
                return AuthorizationViolationType.BFLA
            if test_denied:
                return AuthorizationViolationType.NO_VIOLATION_EXPECTED

        # BOLA: USER or ANONYMOUS accesses another user's owned resource.
        # ADMIN and SERVICE_ACCOUNT may have authorized cross-entity access by design,
        # so we cannot infer a violation for them without policy context.
        if (
            resource.owner_principal_id is not None
            and resource.owner_principal_id != tp.principal_id
            and tp.principal_type.value in ("USER", "ANONYMOUS")
        ):
            if test_appears_to_succeed:
                return AuthorizationViolationType.BOLA
            if test_denied:
                return AuthorizationViolationType.NO_VIOLATION_EXPECTED

        # Vertical: non-admin accessing admin-only resource
        if resource.resource_type.value == "ADMIN_RESOURCE" and not tp_is_admin:
            if test_appears_to_succeed:
                return AuthorizationViolationType.VERTICAL_PRIVILEGE_ESCALATION
            if test_denied:
                return AuthorizationViolationType.NO_VIOLATION_EXPECTED

        # Admin principal on admin resource with successful access — correct authorization
        if (
            resource.resource_type.value == "ADMIN_RESOURCE"
            and tp_is_admin
            and test_appears_to_succeed
        ):
            return AuthorizationViolationType.NO_VIOLATION_EXPECTED

        # Public resource — any principal is allowed by design
        if resource.resource_type.value == "PUBLIC_DATA" and test_appears_to_succeed:
            return AuthorizationViolationType.NO_VIOLATION_EXPECTED

        return AuthorizationViolationType.INCONCLUSIVE

    if quality == AuthorizationExperimentQuality.CONTROLLED_SINGLE_ACTION:
        ta = test.action
        tp = test.principal
        if (
            ta.requires_admin_role
            and "ADMIN" not in [r.upper() for r in tp.roles]
            and tp.principal_type.value != "ADMIN"
            and test_appears_to_succeed
        ):
            return AuthorizationViolationType.BFLA
        return AuthorizationViolationType.INCONCLUSIVE

    if quality == AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE:
        tr = test.resource
        tp = test.principal
        test_denied = test_http_status is not None and 400 <= test_http_status < 500

        # Owner accessing their own resource — correct authorization
        if tr.owner_principal_id is not None and tr.owner_principal_id == tp.principal_id:
            if test_appears_to_succeed:
                return AuthorizationViolationType.NO_VIOLATION_EXPECTED

        # Public resource — any principal is allowed by design
        if tr.resource_type.value == "PUBLIC_DATA" and test_appears_to_succeed:
            return AuthorizationViolationType.NO_VIOLATION_EXPECTED

        # BOLA: USER/ANONYMOUS accesses another user's owned resource
        if (
            tr.owner_principal_id is not None
            and tr.owner_principal_id != tp.principal_id
            and tp.principal_type.value in ("USER", "ANONYMOUS")
        ):
            if test_appears_to_succeed:
                return AuthorizationViolationType.BOLA
            if test_denied:
                return AuthorizationViolationType.NO_VIOLATION_EXPECTED

        # Correct denial on any resource
        if test_denied:
            return AuthorizationViolationType.NO_VIOLATION_EXPECTED

        return AuthorizationViolationType.INCONCLUSIVE

    return AuthorizationViolationType.UNKNOWN


# ── Candidate builder helper ──────────────────────────────────────────────────

def build_candidate_finding(
    finding_id: str,
    control: AccessTuple,
    test: AccessTuple,
    hypothesis: str,
    control_http_status: Optional[int] = None,
    test_http_status: Optional[int] = None,
    control_body: Optional[str] = None,
    test_body: Optional[str] = None,
    alternative_explanations: Optional[list[str]] = None,
    negative_controls: Optional[list[str]] = None,
    evidence_refs: Optional[list[str]] = None,
) -> CandidateAuthorizationFinding:
    """Build a CandidateAuthorizationFinding with SEC-A quality and inferred type.

    Helper that applies rule_sec_a and infer_violation_type_conceptual to produce
    a complete candidate finding for educational analysis.

    CRITICAL: The returned finding has human_verification_required=True always.
    """
    quality = rule_sec_a(
        control=control,
        test=test,
        control_http_status=control_http_status,
        test_http_status=test_http_status,
        control_body=control_body,
        test_body=test_body,
    )
    violation_type = infer_violation_type_conceptual(
        control=control,
        test=test,
        quality=quality,
        control_http_status=control_http_status,
        test_http_status=test_http_status,
    )

    # Candidate conclusion is an educational summary — NOT a security verdict
    if violation_type == AuthorizationViolationType.INCONCLUSIVE:
        conclusion = (
            "Experiment quality insufficient to support a specific violation "
            "type. Additional controlled experiments required."
        )
    elif violation_type == AuthorizationViolationType.BOLA:
        conclusion = (
            "CANDIDATE: The experiment is consistent with Broken Object Level "
            "Authorization (BOLA) — a non-owning principal appears to have "
            "accessed an owner-scoped resource. This is a CANDIDATE finding "
            "requiring human verification before any conclusion."
        )
    elif violation_type == AuthorizationViolationType.BFLA:
        conclusion = (
            "CANDIDATE: The experiment is consistent with Broken Function Level "
            "Authorization (BFLA) — a non-admin principal appears to have "
            "invoked an admin-level function. This is a CANDIDATE finding "
            "requiring human verification before any conclusion."
        )
    else:
        conclusion = (
            f"CANDIDATE: Observed pattern consistent with "
            f"{violation_type.value}. Human verification required."
        )

    return CandidateAuthorizationFinding(
        finding_id=finding_id,
        control_tuple=control,
        test_tuple=test,
        hypothesis=hypothesis,
        sec_a_quality=quality,
        violation_type=violation_type,
        candidate_conclusion=conclusion,
        control_http_status=control_http_status,
        test_http_status=test_http_status,
        control_response_summary=f"HTTP {control_http_status}" if control_http_status else "",
        test_response_summary=f"HTTP {test_http_status}" if test_http_status else "",
        alternative_explanations=alternative_explanations or [],
        negative_controls=negative_controls or [],
        evidence_refs=evidence_refs or [],
        human_verification_required=True,
    )
