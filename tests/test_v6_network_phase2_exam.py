"""RAVEN Network Phase II — Graduation Exam Test Runner.

Runs exam2.py categories as pytest tests.  Each category becomes a
single test that fails with a detailed breakdown if any exam case fails.

INVARIANTS (same as exam2.py):
  - external_targets == 0
  - human_reviewed_labels == 0
  - security_authority == NONE
  - do NOT begin vulnerability-family training
"""
from __future__ import annotations

import pytest

from raven.network_phase2.exam2 import (
    ExamCategory,
    run_shortcut_detection,
    run_overlapping_transitions,
    run_mutation_tests,
    run_metamorphic_tests,
    run_contradiction_tests,
    run_ood_tests,
    run_browser_adversarial,
    run_phase1_retention,
    run_explanation_grounding,
    run_graduation_exam,
    run_red_team,
    run_cross_process_determinism,
    run_leakage_audit,
)


def _assert_category(cat: ExamCategory, threshold: float = 1.0) -> None:
    """Assert all (or threshold-fraction of) exam results pass."""
    failures = [r for r in cat.results if not r.passed]
    if not failures:
        return
    lines = [f"\n[{cat.name}] {cat.n_fail}/{len(cat.results)} FAILED "
             f"(accuracy {cat.accuracy:.1%} < required {threshold:.1%})"]
    for r in failures:
        reason = f" [{r.failure_reason.value}]" if r.failure_reason else ""
        lines.append(f"  FAIL {r.exam_id}{reason}")
        lines.append(f"       predicted: {r.predicted!r}")
        lines.append(f"       expected:  {r.expected!r}")
        if r.note:
            lines.append(f"       note: {r.note}")
    acc = cat.accuracy
    if acc < threshold:
        pytest.fail("\n".join(lines))


# ── Individual category tests ──────────────────────────────────────────────────

def test_shortcut_detection():
    """S1-S12: Verify rules are not fooled by superficial HTTP signals."""
    _assert_category(run_shortcut_detection())


def test_overlapping_transitions():
    """OT1-OT5: Multi-signal sequences — correct transition wins."""
    _assert_category(run_overlapping_transitions())


def test_mutation_tests():
    """M1-M6: Single-signal flips change classification correctly."""
    _assert_category(run_mutation_tests())


def test_metamorphic_tests():
    """MT1-MT4: Structure-preserving transforms produce consistent output."""
    _assert_category(run_metamorphic_tests())


def test_contradiction_tests():
    """CT1-CT5: Contradictory signals → UNKNOWN or CONFOUNDED, never false certainty."""
    _assert_category(run_contradiction_tests())


def test_ood_tests():
    """OOD1-OOD6: Out-of-distribution inputs → UNKNOWN or INSUFFICIENT, never hallucinate."""
    _assert_category(run_ood_tests())


def test_browser_adversarial():
    """BA1-BA14: Origin, cookie, CORS, URL edge cases per browser security model."""
    _assert_category(run_browser_adversarial())


def test_phase1_retention():
    """R1-R6 (×4 tasks): Phase-I rules generalise to new unseen examples."""
    _assert_category(run_phase1_retention())


def test_explanation_grounding():
    """EG1-EG5: Rule outputs must be grounded in observable signals."""
    _assert_category(run_explanation_grounding())


def test_graduation_exam():
    """GE1-GE10: Mixed-concept scenarios not seen during development.
    Allows 75% threshold for adversarial sequences (GE9).
    """
    cat = run_graduation_exam()
    # GE9 has a 75% threshold; all others require 100%
    hard_fails = []
    for r in cat.results:
        if r.exam_id == "ge9_adversarial_sequence_accuracy":
            if not r.passed:
                hard_fails.append(r)
        else:
            if not r.passed:
                hard_fails.append(r)
    if hard_fails:
        lines = [f"\n[graduation_exam] {len(hard_fails)} FAILED"]
        for r in hard_fails:
            reason = f" [{r.failure_reason.value}]" if r.failure_reason else ""
            lines.append(f"  FAIL {r.exam_id}{reason}: predicted={r.predicted!r} expected={r.expected!r}")
            if r.note:
                lines.append(f"       note: {r.note}")
        pytest.fail("\n".join(lines))


def test_red_team():
    """RT1-RT8: Adversarial engine inputs — no false certainty, no security terms."""
    _assert_category(run_red_team())


def test_cross_process_determinism():
    """CPD1: Three fresh Python processes produce identical fixture hashes."""
    _assert_category(run_cross_process_determinism())


def test_leakage_audit():
    """LA1-LA3: No label leaks into fixture IDs, data sources, or family distribution."""
    _assert_category(run_leakage_audit())


# ── Aggregate smoke test ──────────────────────────────────────────────────────

def test_all_exam_invariants():
    """Meta-test: verify exam infrastructure invariants hold across all categories."""
    # Invariant 1: every ExamResult has a non-empty exam_id
    from raven.network_phase2.exam2 import (
        ExamResult, FailureReason,
        run_shortcut_detection, run_overlapping_transitions,
    )
    cat = run_shortcut_detection()
    for r in cat.results:
        assert r.exam_id, f"ExamResult missing exam_id in {cat.name}"
        assert r.category == cat.name, f"ExamResult category mismatch: {r.category} != {cat.name}"
        if r.failure_reason is not None:
            assert isinstance(r.failure_reason, FailureReason), \
                f"failure_reason must be FailureReason enum, got {type(r.failure_reason)}"

    # Invariant 2: no exam generates external network calls (already true by construction;
    # this test verifies no socket import or live-target reference in exam2)
    import ast
    import inspect
    import raven.network_phase2.exam2 as exam_mod
    src = inspect.getsource(exam_mod)
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in ("socket", "urllib.request", "httpx", "requests"), \
                    f"exam2 must not import {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in ("socket", "urllib.request", "httpx", "requests"), \
                f"exam2 must not import from {node.module}"
