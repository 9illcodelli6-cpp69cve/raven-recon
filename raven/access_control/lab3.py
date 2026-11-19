"""RAVEN Phase III — Access Control Academy fixture lab.

Generates synthetic educational access control scenarios for training
the SEC-A task and related authorization concept analysis.

INVARIANTS:
  - All data is EDUCATIONAL_SYNTHETIC — no real users, no real targets
  - External targets contacted: 0
  - human_verification_required: True on all candidate findings
  - Security authority: NONE
  - No actual HTTP requests are made

Scenario families:
  ACL-1: Owner-only resource access (baseline: correct authorization)
  ACL-2: Cross-user object access (BOLA candidate scenarios)
  ACL-3: Function-level authorization (BFLA candidate scenarios)
  ACL-4: Anonymous access patterns
  ACL-5: Admin privilege scenarios
  ACL-6: False positive patterns (correct authorization that looks suspicious)
  ACL-7: Confounded experiments (insufficient evidence)
  ADV:   Adversarial/edge-case scenarios
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from raven.access_control.access_tuple import (
    AccessContext, AccessTuple, AuthorizationMatrix,
    classify_authorization_experiment,
)
from raven.access_control.candidate import CandidateAuthorizationFinding
from raven.access_control.principals import Action, Principal, Resource
from raven.access_control.rules3 import build_candidate_finding
from raven.access_control.taxonomy3 import (
    AccessDecision, ActionType, AuthorizationExperimentQuality,
    AuthorizationViolationType, PrincipalType, ResourceType,
)


# ── Reusable synthetic actors ─────────────────────────────────────────────────

def _make_actors() -> dict[str, Principal]:
    """Build a small set of reusable synthetic principals."""
    return {
        "alice": Principal(
            principal_id="p_alice",
            principal_type=PrincipalType.USER,
            identity="user_alice",
            roles=["user"],
            is_resource_owner=True,
        ),
        "bob": Principal(
            principal_id="p_bob",
            principal_type=PrincipalType.USER,
            identity="user_bob",
            roles=["user"],
            is_resource_owner=False,
        ),
        "charlie": Principal(
            principal_id="p_charlie",
            principal_type=PrincipalType.USER,
            identity="user_charlie",
            roles=["user"],
            is_resource_owner=False,
        ),
        "admin": Principal(
            principal_id="p_admin",
            principal_type=PrincipalType.ADMIN,
            identity="svc_admin",
            roles=["admin", "user"],
            is_resource_owner=False,
        ),
        "anon": Principal(
            principal_id="p_anon",
            principal_type=PrincipalType.ANONYMOUS,
            identity="anonymous",
            roles=[],
            is_resource_owner=False,
        ),
        "svc": Principal(
            principal_id="p_svc",
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            identity="svc_payment",
            roles=["service"],
            is_resource_owner=False,
        ),
    }


def _make_resources() -> dict[str, Resource]:
    """Build a set of reusable synthetic resources."""
    return {
        "alice_profile": Resource(
            resource_id="r_profile_alice",
            resource_type=ResourceType.USER_OWNED_DATA,
            path="/api/users/alice/profile",
            owner_principal_id="p_alice",
            sensitivity="HIGH",
        ),
        "bob_profile": Resource(
            resource_id="r_profile_bob",
            resource_type=ResourceType.USER_OWNED_DATA,
            path="/api/users/bob/profile",
            owner_principal_id="p_bob",
            sensitivity="HIGH",
        ),
        "alice_orders": Resource(
            resource_id="r_orders_alice",
            resource_type=ResourceType.USER_OWNED_DATA,
            path="/api/users/alice/orders",
            owner_principal_id="p_alice",
            sensitivity="HIGH",
        ),
        "bob_orders": Resource(
            resource_id="r_orders_bob",
            resource_type=ResourceType.USER_OWNED_DATA,
            path="/api/users/bob/orders",
            owner_principal_id="p_bob",
            sensitivity="HIGH",
        ),
        "admin_users": Resource(
            resource_id="r_admin_users",
            resource_type=ResourceType.ADMIN_RESOURCE,
            path="/api/admin/users",
            owner_principal_id=None,
            sensitivity="HIGH",
        ),
        "admin_config": Resource(
            resource_id="r_admin_config",
            resource_type=ResourceType.ADMIN_RESOURCE,
            path="/api/admin/config",
            owner_principal_id=None,
            sensitivity="HIGH",
        ),
        "public_catalog": Resource(
            resource_id="r_catalog",
            resource_type=ResourceType.PUBLIC_DATA,
            path="/api/catalog",
            owner_principal_id=None,
            sensitivity="LOW",
        ),
        "shared_doc": Resource(
            resource_id="r_shared_doc_1",
            resource_type=ResourceType.SHARED_DATA,
            path="/api/docs/shared/1",
            owner_principal_id="p_alice",
            sensitivity="MEDIUM",
        ),
    }


def _make_actions() -> dict[str, Action]:
    """Build a set of reusable synthetic actions."""
    return {
        "read": Action(
            action_id="a_read",
            action_type=ActionType.READ,
            http_method="GET",
            requires_ownership=False,
            requires_admin_role=False,
        ),
        "update": Action(
            action_id="a_update",
            action_type=ActionType.WRITE,
            http_method="PUT",
            requires_ownership=True,
            requires_admin_role=False,
        ),
        "delete": Action(
            action_id="a_delete",
            action_type=ActionType.DELETE,
            http_method="DELETE",
            requires_ownership=True,
            requires_admin_role=False,
        ),
        "admin_list": Action(
            action_id="a_admin_list",
            action_type=ActionType.LIST,
            http_method="GET",
            requires_ownership=False,
            requires_admin_role=True,
        ),
        "admin_delete": Action(
            action_id="a_admin_delete",
            action_type=ActionType.DELETE,
            http_method="DELETE",
            requires_ownership=False,
            requires_admin_role=True,
        ),
        "public_read": Action(
            action_id="a_pub_read",
            action_type=ActionType.READ,
            http_method="GET",
            requires_ownership=False,
            requires_admin_role=False,
        ),
    }


# ── Fixture dataclass ─────────────────────────────────────────────────────────

@dataclass
class AccessControlFixture:
    """A single access control experiment scenario for educational training."""
    fixture_id: str
    scenario_family: str
    description: str
    control_tuple: AccessTuple
    test_tuple: AccessTuple
    expected_quality: AuthorizationExperimentQuality
    expected_violation_type: AuthorizationViolationType
    control_http_status: int
    test_http_status: int
    notes: str = ""
    data_source: str = "EDUCATIONAL_SYNTHETIC"


# ── Lab ───────────────────────────────────────────────────────────────────────

class AccessControlLab3:
    """Generates all Phase III access control educational fixtures.

    Produces deterministic synthetic scenarios across 7 families:
      ACL-1: Correct owner-only access (baseline)
      ACL-2: Cross-user object access (BOLA candidate scenarios)
      ACL-3: Function-level authorization (BFLA candidate scenarios)
      ACL-4: Anonymous access (public vs. protected)
      ACL-5: Admin privilege scenarios
      ACL-6: False positive patterns
      ACL-7: Confounded / insufficient-evidence scenarios
      ADV:   Adversarial edge cases

    All scenarios are purely educational and synthetic.
    """

    def __init__(self, n_variants: int = 3) -> None:
        self._n = n_variants
        self._actors = _make_actors()
        self._resources = _make_resources()
        self._actions = _make_actions()
        self._fixtures: list[AccessControlFixture] = self._build_all()

    def _build_all(self) -> list[AccessControlFixture]:
        out: list[AccessControlFixture] = []
        for i in range(self._n):
            out.extend(self._acl1_owner_access(i))
            out.extend(self._acl2_bola_candidates(i))
            out.extend(self._acl3_bfla_candidates(i))
            out.extend(self._acl4_anonymous_access(i))
            out.extend(self._acl5_admin_scenarios(i))
            out.extend(self._acl6_false_positives(i))
            out.extend(self._acl7_confounded(i))
        out.extend(self._adv_scenarios())
        return out

    # ── ACL-1: Owner-only access (correct authorization) ─────────────────────

    def _acl1_owner_access(self, i: int) -> list[AccessControlFixture]:
        """Correct authorization: owner can read own data, denied on other's."""
        A = self._actors
        R = self._resources
        AC = self._actions

        # Alice reads her own profile (ALLOWED, correct)
        ctrl = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        # Alice reads her own orders (same principal, different resource — still owned)
        tst = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_orders"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        out = [AccessControlFixture(
            fixture_id=f"acl1_owner_read_{i}",
            scenario_family="acl1_owner_access",
            description="Owner reads own owned resources",
            control_tuple=ctrl, test_tuple=tst,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE,
            expected_violation_type=AuthorizationViolationType.NO_VIOLATION_EXPECTED,
            control_http_status=200, test_http_status=200,
            notes="Same owner, different resource — CONTROLLED_SINGLE_RESOURCE; both 200",
        )]

        # Alice updates own profile (ALLOWED) vs Bob updates Alice's profile (DENIED)
        alice_update = AccessTuple(
            principal=A["alice"], action=AC["update"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        bob_update = AccessTuple(
            principal=A["bob"], action=AC["update"], resource=R["alice_profile"],
            expected_decision=AccessDecision.DENIED,
            observed_decision=AccessDecision.DENIED,
        )
        out.append(AccessControlFixture(
            fixture_id=f"acl1_owner_update_{i}",
            scenario_family="acl1_owner_access",
            description="Owner can update own data; non-owner denied",
            control_tuple=alice_update, test_tuple=bob_update,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
            expected_violation_type=AuthorizationViolationType.NO_VIOLATION_EXPECTED,
            control_http_status=200, test_http_status=403,
            notes="CONTROLLED_SINGLE_PRINCIPAL; test=403 means correct authorization",
        ))
        return out

    # ── ACL-2: BOLA candidate scenarios ──────────────────────────────────────

    def _acl2_bola_candidates(self, i: int) -> list[AccessControlFixture]:
        """BOLA candidate: a non-owner accesses another user's owned object."""
        A = self._actors
        R = self._resources
        AC = self._actions

        # Bob reading Alice's profile — EXPECTED: DENIED. If server returns 200 → BOLA candidate
        alice_read = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        bob_read_alice = AccessTuple(
            principal=A["bob"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.DENIED,
            observed_decision=AccessDecision.ALLOWED,  # server incorrectly allows
        )
        out = [AccessControlFixture(
            fixture_id=f"acl2_bola_read_{i}",
            scenario_family="acl2_bola_candidate",
            description="Non-owner reads owner's object — BOLA candidate",
            control_tuple=alice_read, test_tuple=bob_read_alice,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
            expected_violation_type=AuthorizationViolationType.BOLA,
            control_http_status=200, test_http_status=200,
            notes=(
                "CANDIDATE: control=owner(200), test=non-owner(200). "
                "BOLA candidate — human verification required."
            ),
        )]

        # Bob reading Alice's orders via resource ID change — BOLA via resource path
        bob_alice_orders = AccessTuple(
            principal=A["bob"], action=AC["read"], resource=R["alice_orders"],
            expected_decision=AccessDecision.DENIED,
            observed_decision=AccessDecision.ALLOWED,  # server incorrectly allows
        )
        bob_own_orders = AccessTuple(
            principal=A["bob"], action=AC["read"], resource=R["bob_orders"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        out.append(AccessControlFixture(
            fixture_id=f"acl2_bola_resource_{i}",
            scenario_family="acl2_bola_candidate",
            description="Same user reads another user's orders — BOLA candidate via resource change",
            control_tuple=bob_own_orders, test_tuple=bob_alice_orders,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE,
            expected_violation_type=AuthorizationViolationType.BOLA,
            control_http_status=200, test_http_status=200,
            notes=(
                "CANDIDATE: control=own-resource(200), test=other-owned-resource(200). "
                "BOLA via resource enumeration — human verification required."
            ),
        ))
        return out

    # ── ACL-3: BFLA candidate scenarios ──────────────────────────────────────

    def _acl3_bfla_candidates(self, i: int) -> list[AccessControlFixture]:
        """BFLA candidate: non-admin invokes admin-only function."""
        A = self._actors
        R = self._resources
        AC = self._actions

        # Admin listing all users (expected allowed)
        admin_list = AccessTuple(
            principal=A["admin"], action=AC["admin_list"], resource=R["admin_users"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        # Regular user attempting admin list (expected denied, but server returns 200)
        user_admin_list = AccessTuple(
            principal=A["bob"], action=AC["admin_list"], resource=R["admin_users"],
            expected_decision=AccessDecision.DENIED,
            observed_decision=AccessDecision.ALLOWED,  # server incorrectly allows
        )
        out = [AccessControlFixture(
            fixture_id=f"acl3_bfla_list_{i}",
            scenario_family="acl3_bfla_candidate",
            description="Non-admin invokes admin list function — BFLA candidate",
            control_tuple=admin_list, test_tuple=user_admin_list,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
            expected_violation_type=AuthorizationViolationType.BFLA,
            control_http_status=200, test_http_status=200,
            notes=(
                "CANDIDATE: control=admin(200), test=regular_user(200) on admin endpoint. "
                "BFLA candidate — human verification required."
            ),
        )]

        # Admin delete vs regular user delete of admin resource
        admin_del = AccessTuple(
            principal=A["admin"], action=AC["admin_delete"], resource=R["admin_config"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        user_del = AccessTuple(
            principal=A["bob"], action=AC["admin_delete"], resource=R["admin_config"],
            expected_decision=AccessDecision.DENIED,
            observed_decision=AccessDecision.ALLOWED,  # server incorrectly allows
        )
        out.append(AccessControlFixture(
            fixture_id=f"acl3_bfla_delete_{i}",
            scenario_family="acl3_bfla_candidate",
            description="Non-admin invokes admin delete function — BFLA candidate",
            control_tuple=admin_del, test_tuple=user_del,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
            expected_violation_type=AuthorizationViolationType.BFLA,
            control_http_status=200, test_http_status=200,
            notes=(
                "CANDIDATE: control=admin(200), test=user(200) on admin-delete endpoint. "
                "BFLA candidate — human verification required."
            ),
        ))
        return out

    # ── ACL-4: Anonymous access patterns ─────────────────────────────────────

    def _acl4_anonymous_access(self, i: int) -> list[AccessControlFixture]:
        """Public resources accessible to anonymous; protected resources denied."""
        A = self._actors
        R = self._resources
        AC = self._actions

        # Anon reads public catalog (ALLOWED, correct)
        anon_pub = AccessTuple(
            principal=A["anon"], action=AC["public_read"], resource=R["public_catalog"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        # Authenticated user also reads public catalog
        user_pub = AccessTuple(
            principal=A["bob"], action=AC["public_read"], resource=R["public_catalog"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        out = [AccessControlFixture(
            fixture_id=f"acl4_anon_public_{i}",
            scenario_family="acl4_anonymous_access",
            description="Anonymous reads public resource — correct authorization",
            control_tuple=anon_pub, test_tuple=user_pub,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
            expected_violation_type=AuthorizationViolationType.NO_VIOLATION_EXPECTED,
            control_http_status=200, test_http_status=200,
            notes="PUBLIC_DATA — both anon and authenticated get 200; no violation",
        )]

        # Anon reads protected profile (DENIED, correct)
        anon_profile = AccessTuple(
            principal=A["anon"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.DENIED,
            observed_decision=AccessDecision.DENIED,
        )
        alice_profile = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        out.append(AccessControlFixture(
            fixture_id=f"acl4_anon_protected_{i}",
            scenario_family="acl4_anonymous_access",
            description="Anonymous denied on protected resource — correct authorization",
            control_tuple=alice_profile, test_tuple=anon_profile,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
            expected_violation_type=AuthorizationViolationType.NO_VIOLATION_EXPECTED,
            control_http_status=200, test_http_status=401,
            notes="Control=owner(200), test=anon(401); correct authorization enforcement",
        ))
        return out

    # ── ACL-5: Admin privilege scenarios ─────────────────────────────────────

    def _acl5_admin_scenarios(self, i: int) -> list[AccessControlFixture]:
        """Admin can access all; vertical privilege — regular user cannot."""
        A = self._actors
        R = self._resources
        AC = self._actions

        # Admin reads user data (should be allowed — admins have broader scope)
        admin_read_alice = AccessTuple(
            principal=A["admin"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        admin_read_bob = AccessTuple(
            principal=A["admin"], action=AC["read"], resource=R["bob_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        out = [AccessControlFixture(
            fixture_id=f"acl5_admin_access_{i}",
            scenario_family="acl5_admin_scenarios",
            description="Admin reads user data — correct broad authorization",
            control_tuple=admin_read_alice, test_tuple=admin_read_bob,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE,
            expected_violation_type=AuthorizationViolationType.NO_VIOLATION_EXPECTED,
            control_http_status=200, test_http_status=200,
            notes="Admin is authorized for all user data — this is expected behavior",
        )]

        # Regular user attempts admin endpoint — correctly denied
        bob_admin = AccessTuple(
            principal=A["bob"], action=AC["admin_list"], resource=R["admin_users"],
            expected_decision=AccessDecision.DENIED,
            observed_decision=AccessDecision.DENIED,
        )
        admin_admin = AccessTuple(
            principal=A["admin"], action=AC["admin_list"], resource=R["admin_users"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        out.append(AccessControlFixture(
            fixture_id=f"acl5_vertical_denied_{i}",
            scenario_family="acl5_admin_scenarios",
            description="Regular user correctly denied admin function",
            control_tuple=admin_admin, test_tuple=bob_admin,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
            expected_violation_type=AuthorizationViolationType.NO_VIOLATION_EXPECTED,
            control_http_status=200, test_http_status=403,
            notes="Control=admin(200), test=user(403); correct authorization enforced",
        ))
        return out

    # ── ACL-6: False positive patterns ───────────────────────────────────────

    def _acl6_false_positives(self, i: int) -> list[AccessControlFixture]:
        """Patterns that look suspicious but have legitimate explanations."""
        A = self._actors
        R = self._resources
        AC = self._actions

        # Service account reads user profile — might look like unauthorized access,
        # but services legitimately need to read user data for business logic
        svc_read = AccessTuple(
            principal=A["svc"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        alice_read = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        out = [AccessControlFixture(
            fixture_id=f"acl6_false_positive_svc_{i}",
            scenario_family="acl6_false_positive",
            description="Service account reads user data — authorized by design",
            control_tuple=alice_read, test_tuple=svc_read,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
            expected_violation_type=AuthorizationViolationType.INCONCLUSIVE,
            control_http_status=200, test_http_status=200,
            notes=(
                "Service accounts legitimately access user data in many designs. "
                "INCONCLUSIVE — cannot determine violation without policy context. "
                "Human verification required to understand authorization model."
            ),
        )]

        # Admin reading all users — admin has broad access, NOT a BOLA finding
        admin_alice = AccessTuple(
            principal=A["admin"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        admin_bob = AccessTuple(
            principal=A["admin"], action=AC["read"], resource=R["bob_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        out.append(AccessControlFixture(
            fixture_id=f"acl6_false_positive_admin_{i}",
            scenario_family="acl6_false_positive",
            description="Admin reads multiple users — authorized by admin policy",
            control_tuple=admin_alice, test_tuple=admin_bob,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE,
            expected_violation_type=AuthorizationViolationType.INCONCLUSIVE,
            control_http_status=200, test_http_status=200,
            notes=(
                "Admin has authorized cross-user access by policy. "
                "Resource changed but admin principal unchanged — not BOLA. "
                "INCONCLUSIVE without explicit policy context."
            ),
        ))
        return out

    # ── ACL-7: Confounded experiments ─────────────────────────────────────────

    def _acl7_confounded(self, i: int) -> list[AccessControlFixture]:
        """Confounded: multiple dimensions changed — cannot isolate cause."""
        A = self._actors
        R = self._resources
        AC = self._actions

        # Both principal AND action AND resource changed — totally confounded
        alice_read_own = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        bob_admin_del = AccessTuple(
            principal=A["bob"], action=AC["admin_delete"], resource=R["admin_config"],
            expected_decision=AccessDecision.DENIED,
            observed_decision=AccessDecision.DENIED,
        )
        out = [AccessControlFixture(
            fixture_id=f"acl7_multi_dim_all_{i}",
            scenario_family="acl7_confounded",
            description="Principal + action + resource all changed — fully confounded",
            control_tuple=alice_read_own, test_tuple=bob_admin_del,
            expected_quality=AuthorizationExperimentQuality.CONFOUNDED,
            expected_violation_type=AuthorizationViolationType.INCONCLUSIVE,
            control_http_status=200, test_http_status=403,
            notes="All three dimensions changed — cannot attribute response to any single factor",
        )]

        # Principal + resource changed (still confounded)
        alice_own = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_orders"],
            expected_decision=AccessDecision.ALLOWED,
            observed_decision=AccessDecision.ALLOWED,
        )
        bob_alice_orders = AccessTuple(
            principal=A["bob"], action=AC["read"], resource=R["alice_orders"],
            expected_decision=AccessDecision.DENIED,
            observed_decision=AccessDecision.ALLOWED,
        )
        # Make bob's resource different too to create confusion
        out.append(AccessControlFixture(
            fixture_id=f"acl7_multi_dim_pr_{i}",
            scenario_family="acl7_confounded",
            description="Principal changed, resource also changed — confounded",
            control_tuple=alice_own, test_tuple=bob_alice_orders,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
            expected_violation_type=AuthorizationViolationType.BOLA,
            control_http_status=200, test_http_status=200,
            notes=(
                "Principal changed only (same resource). BOLA candidate — "
                "non-owner accessing owner data. CANDIDATE — human verification required."
            ),
        ))
        return out

    # ── Adversarial scenarios ─────────────────────────────────────────────────

    def _adv_scenarios(self) -> list[AccessControlFixture]:
        """Adversarial edge cases designed to test shortcut resistance."""
        A = self._actors
        R = self._resources
        AC = self._actions
        out: list[AccessControlFixture] = []

        # ADV-1: 401 ≠ BOLA (unauthorized response is NOT a BOLA candidate)
        alice_read = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED, observed_decision=AccessDecision.ALLOWED,
        )
        bob_read_denied = AccessTuple(
            principal=A["bob"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.DENIED, observed_decision=AccessDecision.DENIED,
        )
        out.append(AccessControlFixture(
            fixture_id="adv_401_not_bola",
            scenario_family="adversarial_shortcut",
            description="Non-owner receives 401/403 — NOT BOLA (correct enforcement)",
            control_tuple=alice_read, test_tuple=bob_read_denied,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_PRINCIPAL,
            expected_violation_type=AuthorizationViolationType.NO_VIOLATION_EXPECTED,
            control_http_status=200, test_http_status=403,
            notes=(
                "SHORTCUT: 403 on non-owner ≠ BOLA. BOLA requires access to SUCCEED "
                "when it should be denied. 403 = correct enforcement."
            ),
        ))

        # ADV-2: Same principal, different resource IDs → NOT automatically BOLA
        alice_r1 = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED, observed_decision=AccessDecision.ALLOWED,
        )
        alice_r2 = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_orders"],
            expected_decision=AccessDecision.ALLOWED, observed_decision=AccessDecision.ALLOWED,
        )
        out.append(AccessControlFixture(
            fixture_id="adv_resource_enumeration_not_bola",
            scenario_family="adversarial_shortcut",
            description="Same principal reads different resources — NOT BOLA",
            control_tuple=alice_r1, test_tuple=alice_r2,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_RESOURCE,
            expected_violation_type=AuthorizationViolationType.NO_VIOLATION_EXPECTED,
            control_http_status=200, test_http_status=200,
            notes=(
                "SHORTCUT: Different resource IDs ≠ BOLA. BOLA requires non-owner principal. "
                "Here principal is alice accessing her own resources."
            ),
        ))

        # ADV-3: 200 ≠ BFLA (admin getting 200 is expected behavior)
        admin_list = AccessTuple(
            principal=A["admin"], action=AC["admin_list"], resource=R["admin_users"],
            expected_decision=AccessDecision.ALLOWED, observed_decision=AccessDecision.ALLOWED,
        )
        admin_list2 = AccessTuple(
            principal=A["admin"], action=AC["admin_delete"], resource=R["admin_users"],
            expected_decision=AccessDecision.ALLOWED, observed_decision=AccessDecision.ALLOWED,
        )
        out.append(AccessControlFixture(
            fixture_id="adv_admin_200_not_bfla",
            scenario_family="adversarial_shortcut",
            description="Admin invokes admin function — NOT BFLA (correct authorization)",
            control_tuple=admin_list, test_tuple=admin_list2,
            expected_quality=AuthorizationExperimentQuality.CONTROLLED_SINGLE_ACTION,
            expected_violation_type=AuthorizationViolationType.NO_VIOLATION_EXPECTED,
            control_http_status=200, test_http_status=200,
            notes=(
                "SHORTCUT: 200 on admin endpoint ≠ BFLA. Admin is authorized "
                "for admin functions. BFLA requires non-admin accessing admin function."
            ),
        ))

        # ADV-4: No_meaningful_change — identical tuples, same response
        alice_same1 = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED, observed_decision=AccessDecision.ALLOWED,
        )
        alice_same2 = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED, observed_decision=AccessDecision.ALLOWED,
        )
        out.append(AccessControlFixture(
            fixture_id="adv_identical_tuples",
            scenario_family="adversarial_shortcut",
            description="Identical tuples → NO_MEANINGFUL_CHANGE",
            control_tuple=alice_same1, test_tuple=alice_same2,
            expected_quality=AuthorizationExperimentQuality.NO_MEANINGFUL_CHANGE,
            expected_violation_type=AuthorizationViolationType.INCONCLUSIVE,
            control_http_status=200, test_http_status=200,
            notes="No dimensions changed, same response — NO_MEANINGFUL_CHANGE; cannot analyze",
        ))

        # ADV-5: Confounded — multiple dims changed — INCONCLUSIVE not BOLA
        alice_full = AccessTuple(
            principal=A["alice"], action=AC["read"], resource=R["alice_profile"],
            expected_decision=AccessDecision.ALLOWED, observed_decision=AccessDecision.ALLOWED,
        )
        bob_admin_orders = AccessTuple(
            principal=A["bob"], action=AC["admin_list"], resource=R["alice_orders"],
            expected_decision=AccessDecision.DENIED, observed_decision=AccessDecision.DENIED,
        )
        out.append(AccessControlFixture(
            fixture_id="adv_multi_dim_not_bola",
            scenario_family="adversarial_shortcut",
            description="Confounded experiment — INCONCLUSIVE, not BOLA/BFLA",
            control_tuple=alice_full, test_tuple=bob_admin_orders,
            expected_quality=AuthorizationExperimentQuality.CONFOUNDED,
            expected_violation_type=AuthorizationViolationType.INCONCLUSIVE,
            control_http_status=200, test_http_status=403,
            notes=(
                "Multiple dims changed — CONFOUNDED → INCONCLUSIVE. "
                "Cannot attribute 403 to BOLA or BFLA without isolating variables."
            ),
        ))

        return out

    # ── Public interface ──────────────────────────────────────────────────────

    def fixtures(self) -> list[AccessControlFixture]:
        return list(self._fixtures)

    def get_by_family(self, family: str) -> list[AccessControlFixture]:
        return [f for f in self._fixtures if f.scenario_family == family]

    def get_by_id(self, fixture_id: str) -> Optional[AccessControlFixture]:
        for f in self._fixtures:
            if f.fixture_id == fixture_id:
                return f
        return None

    def build_authorization_matrix(self) -> AuthorizationMatrix:
        """Build a reference AuthorizationMatrix from the lab actors/resources/actions."""
        A = self._actors
        R = self._resources
        AC = self._actions

        matrix = AuthorizationMatrix(
            "lab3_matrix",
            description="Reference authorization matrix for Phase III educational lab",
        )

        # Alice owns her resources
        for resource in [R["alice_profile"], R["alice_orders"]]:
            matrix.add_entry(A["alice"], AC["read"], resource, AccessDecision.ALLOWED,
                             rationale="Owner read access")
            matrix.add_entry(A["alice"], AC["update"], resource, AccessDecision.ALLOWED,
                             rationale="Owner write access")
            matrix.add_entry(A["alice"], AC["delete"], resource, AccessDecision.ALLOWED,
                             rationale="Owner delete access")
        # Bob owns his resources
        for resource in [R["bob_profile"], R["bob_orders"]]:
            matrix.add_entry(A["bob"], AC["read"], resource, AccessDecision.ALLOWED,
                             rationale="Owner read access")
            matrix.add_entry(A["bob"], AC["update"], resource, AccessDecision.ALLOWED,
                             rationale="Owner write access")
            matrix.add_entry(A["bob"], AC["delete"], resource, AccessDecision.ALLOWED,
                             rationale="Owner delete access")
        # Bob cannot access Alice's resources
        for resource in [R["alice_profile"], R["alice_orders"]]:
            matrix.add_entry(A["bob"], AC["read"], resource, AccessDecision.DENIED,
                             rationale="Non-owner denied")
            matrix.add_entry(A["bob"], AC["update"], resource, AccessDecision.DENIED,
                             rationale="Non-owner denied")

        # Public catalog accessible to all
        for principal in A.values():
            matrix.add_entry(principal, AC["public_read"], R["public_catalog"],
                             AccessDecision.ALLOWED, rationale="Public data")

        # Admin has access to everything
        for resource in R.values():
            for action in AC.values():
                matrix.add_entry(A["admin"], action, resource, AccessDecision.ALLOWED,
                                 rationale="Admin has broad access by policy")

        # Admin endpoints require admin role
        for action in [AC["admin_list"], AC["admin_delete"]]:
            for resource in [R["admin_users"], R["admin_config"]]:
                for principal in [A["alice"], A["bob"], A["anon"], A["charlie"]]:
                    matrix.add_entry(principal, action, resource, AccessDecision.DENIED,
                                     rationale="Admin function requires admin role")

        # Anonymous cannot access protected resources
        for resource in [R["alice_profile"], R["alice_orders"], R["bob_profile"],
                         R["bob_orders"], R["admin_users"], R["admin_config"]]:
            matrix.add_entry(A["anon"], AC["read"], resource, AccessDecision.DENIED,
                             rationale="Anonymous cannot access protected resources")

        return matrix
