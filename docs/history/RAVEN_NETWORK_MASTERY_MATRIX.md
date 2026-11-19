# RAVEN NETWORK MASTERY MATRIX
<!-- Maps curriculum levels to mastery status. Updated each cycle. -->
<!-- Scale: 0=Not started | 1=Taught | 2=Tested | 3=Passed | 4=Adversarial exam passed | 5=Retained across sessions -->

| Level | Topic                        | Status | Rule Acc | ML Acc | Notes |
|-------|------------------------------|--------|----------|--------|-------|
| 1     | TCP/IP Practical             | 0      | -        | -      |       |
| 2     | HTTP Request/Response        | 2      | 1.0      | 1.0    | NET-A perfect; NORMAL_SUCCESS/CLIENT_ERROR/etc |
| 3     | HTTP Redirects               | 2      | 1.0      | 1.0    | NET-A REDIRECT rule and RF both perfect |
| 4     | HTTP Cache                   | 3      | 1.0      | 0.667  | NET-B ETag/304; rule perfect, RF partial |
| 5     | Content Negotiation          | 0      | -        | -      |       |
| 6     | **Cache Semantics (ETag/304)**| **3**  | **1.0**  | **0.667** | **Cycle 1 — GRADUATED NET-B to RULE_DEFAULT** |
| 7     | HTTP Cookies                 | 0      | -        | -      |       |
| 8     | Session Lifecycle            | 3      | 1.000    | 1.0    | NET-C RULE_DEFAULT; all 30 fixtures PERFECT |
| 9     | Auth Context                 | 3      | 1.000    | 0.867  | NET-D RULE_DEFAULT; 30/30 PERFECT (Cycle 1 addendum) |
| 10    | Authorization Concepts       | 0      | -        | -      |       |
| 11    | API Fundamentals             | 0      | -        | -      |       |
| 12    | JSON Semantics               | 2      | 1.0      | 1.0    | is_json feature used in NET-B |
| 13    | HTML Fundamentals            | 1      | -        | -      | content_change_html fixture added |
| 14    | Origin Model                 | 0      | -        | -      |       |
| 15    | CORS                         | 0      | -        | -      |       |
| 16    | Browser Request Context      | 0      | -        | -      |       |
| 17    | CSP                          | 0      | -        | -      |       |
| 18    | TLS                          | 0      | -        | -      |       |
| 19    | HTTP Version Behavior        | 0      | -        | -      |       |
| 20    | Proxy/CDN                    | 0      | -        | -      |       |
| 21    | Rate Limiting                | 2      | 1.0      | 1.0    | NET-A RATE_LIMITED rule perfect; 429 + Retry-After |
| 22    | Retries                      | 0      | -        | -      |       |
| 23    | Baseline Evolution           | 0      | -        | -      |       |
| 24    | Temporal Reasoning           | 0      | -        | -      |       |
| 25    | Causal Reasoning             | 0      | -        | -      |       |
| 26    | Controlled Experiments       | 0      | -        | -      |       |
| 27    | Adversarial Teacher          | 0      | -        | -      |       |
| 28    | Mutation Exams               | 0      | -        | -      |       |
| 29    | Contradiction Exams          | 0      | -        | -      |       |
| 30    | OOD Exams                    | 0      | -        | -      |       |
| 31    | Rule vs ML Competition       | 4      | 1.000    | -      | Adversarial exam: 45/45 ALL 6 DifferenceClass labels |
| 32    | Shortcut Detection           | 3      | 1.000    | -      | is_json shortcut detected+fixed; pagination removed; all classes pass |
| 33    | Feature Ablations            | 0      | -        | -      |       |
| 34    | Curriculum Holdout Mgmt      | 2      | -        | -      | Stratified grouped split; anchor families |
| 35    | Knowledge Retention          | 0      | -        | -      |       |
| 36    | Knowledge Graph Extension    | 0      | -        | -      |       |
| 37    | Explanation Grounding        | 0      | -        | -      |       |
| 38    | Confidence Discipline        | 0      | -        | -      |       |
| 39    | No Self-Generated Truth      | 5      | -        | -      | EDUCATIONAL_SYNTHETIC invariant maintained |
| 40    | Model Registry Discipline    | 5      | -        | -      | PROTECTED_TASKS; no live targets |
| 41-50 | Safe Local Lab Only          | 5      | -        | -      | No external targets; in-process fixtures |

---

## Feature Schema History

| Version | FEATURE_DIM | Key Changes |
|---------|------------|-------------|
| net_v1  | 26         | Initial schema |
| net_v2  | 26         | Added body_content_changed |
| net_v3  | 29         | Fixed auth_state_changed; added is_304, cmp_is_304, has_etag |

---

## Task Strategy History

| Task  | Net_V1       | Net_V2           | Net_V3       |
|-------|-------------|-----------------|--------------|
| NET-A | DEVELOPMENT_ONLY | RULE_DEFAULT | RULE_DEFAULT |
| NET-B | DEVELOPMENT_ONLY | DEVELOPMENT_ONLY | RULE_DEFAULT ← |
| NET-C | DEVELOPMENT_ONLY | ML_DEFAULT   | RULE_DEFAULT ← |
| NET-D | DEVELOPMENT_ONLY | ML_DEFAULT   | RULE_DEFAULT ← (fixed Cycle 1 addendum) |

---

## Knowledge Gaps (Priority Order for Next Cycles)

1. **NET-B EXPECTED_CHANGE RF weakness** (F1=0.667): RF doesn't generalize across EXPECTED_CHANGE sub-types. Rule is sufficient so ML path doesn't matter, but worth understanding.
2. **NET-D APPLICATION_AUTHENTICATED** (no test support): 6 training examples, never lands in test.
3. **NET-D AUTH_REQUIRED** (no test support): 12 training examples, never lands in test.
4. **NET-B test coverage** (only EXPECTED_CHANGE+TRANSIENT in last test split): AUTH_STATE_CHANGE, CONTENT_CHANGE, NO_CHANGE, STRUCTURAL_CHANGE not validated on test holdout.
5. **NET-C AUTHENTICATED confusion** (earlier runs): Rule doesn't distinguish AUTHENTICATED from ANONYMOUS well (F1=0 for rule). RF fixed it.
