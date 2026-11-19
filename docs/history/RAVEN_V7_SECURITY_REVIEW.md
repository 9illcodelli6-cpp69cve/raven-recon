# RAVEN V7 Security Review
**Reviewer: Automated adversarial test suite (Part 12)**
**Date: 2026-10-04**
**Scope: All V7 packages (Parts 03–12)**

---

## Methodology

The adversarial review consisted of:
1. **Direct attribute mutation attempts** on every immutable invariant
2. **Subclass forging attempts** — subclassing invariant-carrying dataclasses to bypass `__setattr__`
3. **Cross-module pipeline test** — verifying invariants survive a complete 6-step research workflow
4. **Security regression sweep** — batch construction of all advisory objects

All 20 adversarial tests passed.

---

## Invariant Coverage

### `CompletionResult.is_advisory`
- **Mechanism**: `__post_init__` calls `object.__setattr__(self, "is_advisory", True)`; `__setattr__` checks `"is_advisory" in self.__dict__` before blocking
- **Attack**: direct assignment → `AttributeError`
- **Edge case addressed**: `hasattr` would return True even before instance attribute was set (class-level default `True`); the `__dict__` check avoids this false positive
- **Status**: ✅ VERIFIED

### `CandidateFinding` triple invariant
- `human_verification_required = True` — immutable
- `security_authority = "NONE"` — immutable
- `is_verified = False` — immutable
- **Attack**: all three direct assignment attempts → `AttributeError` each
- **Status**: ✅ VERIFIED

### `ProgramPolicy.external_targets = 0`
- **Mechanism**: `__post_init__` + `__setattr__`
- **Attack**: `policy.external_targets = 1` → `AttributeError`
- **Status**: ✅ VERIFIED

### `KnowledgeEntry.human_reviewed_labels = 0`
- **Mechanism**: `__post_init__` + `__setattr__`; both assignment to 1 AND reassignment to 0 raise `AttributeError` (once set, immutable)
- **Subclass bypass attempt**: `class BadEntry(KnowledgeEntry)` + `e.human_reviewed_labels = 99` → `AttributeError` (inherited `__setattr__`)
- **Status**: ✅ VERIFIED

### `Lesson.is_advisory = True`
- **Mechanism**: `__post_init__` + `__setattr__`
- **Attack**: `lesson.is_advisory = False` → `AttributeError`
- **Status**: ✅ VERIFIED (fix applied during Part 09 — original implementation lacked `__setattr__`)

### `EvidenceNode.is_advisory = True`, `PoCEntry.is_advisory = True`, `ReportOutput.is_advisory = True`
- **Mechanism**: `__post_init__` + `__setattr__` on all three
- **Subclass bypass on EvidenceNode**: `class BadNode(EvidenceNode)` + `n.is_advisory = False` → `AttributeError`
- **Status**: ✅ VERIFIED

### `ProgramScope` empty-scope fail-closed
- `ProgramScope()` with no items → `is_in_scope(any_url) = False`
- Prevents scope misconfiguration from accidentally allowing all targets
- **Status**: ✅ VERIFIED

### `CapabilityGate` fail-closed
- Verified during bootstrap graduation (90/90 tests)
- Gateway denies when Rust bridge is unavailable
- **Status**: ✅ VERIFIED (bootstrap)

---

## BOLA/BFLA Label Policy

- `FindingCategory.BOLA` and `FindingCategory.BFLA` are **conceptual educational labels**
- They appear in `FindingCategory` enum and finding titles only
- No code path exists that treats them as confirmed vulnerabilities
- `is_verified = False` is immutable — no model prediction can set it to True
- Human researcher must explicitly confirm via review flow
- **Status**: ✅ POLICY ENFORCED

---

## ML Advisory Boundary

- `CompletionResult.is_advisory = True` — model output is always advisory
- `KnowledgeEntry.human_reviewed_labels = 0` — AI cannot self-label as human
- `ml_probability` in existing DB schema is `NULL` by default; not linked to `verification_status`
- `CritiqueResult.is_advisory = True` — critic scores are advisory input, not decisions
- **Status**: ✅ BOUNDARY MAINTAINED

---

## Internet Content Boundary

- `SourceProvenance.is_untrusted_data = True` (bootstrap invariant)
- Browser HTTP responses are data, not instructions
- `TrafficAnalyzer._redact_headers()` removes auth material from logs
- `HttpClient` redacts authorization, cookie, set-cookie, x-api-key, x-auth-token in `to_dict()`
- **Status**: ✅ BOUNDARY MAINTAINED

---

## Findings

**No security regressions found.**
**No invariant bypass succeeded.**
**No unauthorized confirmation of any finding possible.**

---

*This review is itself advisory — it describes automated test results, not a human penetration test.*
