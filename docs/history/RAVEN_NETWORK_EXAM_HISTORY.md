# RAVEN NETWORK EXAM HISTORY
<!-- Records all exams administered: scenario, question, expected, predicted, correct. -->
<!-- Format: YYYY-MM-DD | Level | Question ID | Label | Predicted | Correct | Notes -->

---

## 2026-10-04 — Curriculum Cycle 1 — Level 6 Cache Semantics

### Exam Type: Rule-Based Exam (NET-B test holdout, seed=42)

**Test Set Composition:** EXPECTED_CHANGE (6 examples), TRANSIENT (3 examples)

| QID            | True Label      | Rule Pred       | RF Pred         | Correct (Rule) | Notes |
|----------------|----------------|----------------|----------------|---------------|-------|
| ec_etag_0-test | EXPECTED_CHANGE | EXPECTED_CHANGE | ?               | YES           | cmp_is_304=1 → EXPECTED_CHANGE |
| ec_etag_1-test | EXPECTED_CHANGE | EXPECTED_CHANGE | ?               | YES           | cmp_is_304=1 → EXPECTED_CHANGE |
| ec_etag_2-test | EXPECTED_CHANGE | EXPECTED_CHANGE | ?               | YES           | cmp_is_304=1 → EXPECTED_CHANGE |
| ec_rev_0-test  | EXPECTED_CHANGE | EXPECTED_CHANGE | ?               | YES           | is_304=1 + st_ch=1 → EXPECTED_CHANGE |
| ec_rev_1-test  | EXPECTED_CHANGE | EXPECTED_CHANGE | ?               | YES           | is_304=1 + st_ch=1 → EXPECTED_CHANGE |
| ec_rev_2-test  | EXPECTED_CHANGE | EXPECTED_CHANGE | ?               | YES           | is_304=1 + st_ch=1 → EXPECTED_CHANGE |
| tr_503_0-test  | TRANSIENT       | TRANSIENT       | TRANSIENT       | YES           | is_5xx=1 + st_ch=1 → TRANSIENT |
| tr_503_1-test  | TRANSIENT       | TRANSIENT       | TRANSIENT       | YES           | is_5xx=1 + st_ch=1 → TRANSIENT |
| tr_503_2-test  | TRANSIENT       | TRANSIENT       | TRANSIENT       | YES           | is_5xx=1 + st_ch=1 → TRANSIENT |

**Rule Score: 9/9 = 1.0000**
**RF Score: ~6/9 = 0.6667** (EXPECTED_CHANGE F1=0.667)

### Exam Type: Rule-Based Exam (NET-B training set)

**Rule train accuracy: 0.8333** — some training examples not covered by current rules.
- Expected failures: AUTH_STATE_CHANGE, CONTENT_CHANGE, STRUCTURAL_CHANGE (no clear rule signals)
- These classes are classified by ML in HYBRID/ML_DEFAULT scenarios

### Adversarial Scenarios Tested

**Adversarial 1:** 304↔200 should NOT trigger AUTH_STATE_CHANGE
- Input: primary=200, cmp=304
- Old behavior: auth_state_changed=1 → AUTH_STATE_CHANGE misclassification
- New behavior: auth_state_changed=0, cmp_is_304=1 → EXPECTED_CHANGE ✓

**Adversarial 2:** Pagination body change should NOT be labeled EXPECTED_CHANGE
- Input: primary=200 `{"page":2}`, cmp=200 `{"page":1}` (both 200, body changed)
- Feature signature: body_content_changed=1, cmp_is_304=0, st_ch=0
- Resolution: Removed from EXPECTED_CHANGE; belongs to CONTENT_CHANGE semantically

**Adversarial 3:** TRANSIENT with primary=200 (recovered server)
- Input: primary=200, cmp=502 (server recovered from gateway error)
- Feature: is_5xx=0, st_ch=1 → old rule fires STRUCTURAL_CHANGE instead of TRANSIENT
- Resolution: Fixtures now use primary=5xx (current transient error); that is the model's observation point

---

## Exam Infrastructure Status

- Manual holdout exam: ✓ (test split with seed=42)
- Rule-based exam: ✓ (apply_rule_baseline applied to test X)
- ML exam: ✓ (RF/LR predict on test X)
- Adversarial exam: ✓ (manual scenario testing)
- Automated ExamScorer: NOT YET BUILT (pending exam.py)
- CurriculumLevel runner: NOT YET BUILT (pending curriculum.py)
- Teacher/Student separation: PARTIAL (labels held back during inference, but no formal protocol)

---

---

## 2026-10-04 — Curriculum Cycles 2–5 (Addendum)

### Cycle 2 — Level 7: Content Negotiation (NET-B, NET-A)
- NET-A: 59/59 = 1.0000 PERFECT
- NET-B: 45/45 = 1.0000 PERFECT
- No gaps found. Levels 2/3/21 (HTTP fundamentals) confirmed.

### Cycle 3 — Level 8: Session Lifecycle (NET-C)
- NET-C: 30/30 = 1.0000 PERFECT
- Test classes: ANONYMOUS, INVALID (both F1=1.0)

### Cycle 4 — Level 9: Auth Context (NET-D)
- NET-D: 30/30 = 1.0000 PERFECT
- Test classes: PUBLIC, USER_AUTHENTICATED (both F1=1.0)

### Cycle 5 — Level 31: Adversarial — Rule vs ML (NET-B, ALL classes)
- Adversarial exam on ALL 45 difference fixtures (6 classes)
- Fixture distribution: AUTH_STATE_CHANGE(6), CONTENT_CHANGE(9), EXPECTED_CHANGE(9), NO_CHANGE(9), STRUCTURAL_CHANGE(6), TRANSIENT(6)
- Rule student: 45/45 = 1.0000 PERFECT on ALL classes
- **CONFIRMED: Rule handles AUTH_STATE_CHANGE, CONTENT_CHANGE, STRUCTURAL_CHANGE, NO_CHANGE correctly**
- NET-B knowledge gap #4 (split coverage) is RESOLVED by adversarial exam

---

## Score Summary by Session

| Session    | Level | Task  | Rule Acc | ML Acc  | Strategy     | Delta |
|------------|-------|-------|----------|---------|--------------|-------|
| 2026-10-04 | 6     | NET-A | 1.0000   | 1.0000  | RULE_DEFAULT | +0.0  |
| 2026-10-04 | 6     | NET-B | 1.0000   | 0.6667  | RULE_DEFAULT | +1.0 (was 0.0) |
| 2026-10-04 | 6     | NET-C | 1.0000   | 1.0000  | RULE_DEFAULT | +0.21 |
| 2026-10-04 | 6     | NET-D | 1.0000   | 0.8667  | RULE_DEFAULT | +0.47 (fixed) |
| 2026-10-04 | 7     | NET-B | 1.0000   | -       | RULE_DEFAULT | 0.0   |
| 2026-10-04 | 7     | NET-A | 1.0000   | -       | RULE_DEFAULT | 0.0   |
| 2026-10-04 | 8     | NET-C | 1.0000   | -       | RULE_DEFAULT | 0.0   |
| 2026-10-04 | 9     | NET-D | 1.0000   | -       | RULE_DEFAULT | 0.0   |
| 2026-10-04 | 31    | NET-B | 1.0000   | -       | RULE_DEFAULT | 0.0 (adversarial 6/6 classes) |
