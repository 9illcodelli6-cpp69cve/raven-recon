# Source-fix handoff — 27 September 2026

Changes applied directly to the existing RAVEN project after review of checkpoint 2255518.

- ACL now uses explicit public/private/unknown policy; expected denial cannot be suppressed by anonymous access. Anonymous visibility receives its own comparison. Full captured equality/lossless JSON normalization replaces lossy timestamp/token masking; partial or lossy evidence stays inconclusive. Differing body/status and login keywords no longer establish expected denial.
- Scheduler admission, shared budgets, global host limits, bounded queue/history, pause/cancel/finalization and shutdown corrected.
- Collections preserve submission context and account for every actual send attempt. Scheduled external tools are disabled with an explicit log message. Live collection records survive workspace reopening.
- HTTP framing, body deadlines, rejected-request connection handling and object validation hardened.
- Windows CLI workspace locking and collector termination made portable so the full repository suite can run locally.
- UI includes resource-policy selection and accurate collection-stop scope. See TASK_SCHEDULER.md and XSS_ISOLATION.md.

Validation: see final test log delivered with this handoff. Python 3.13 Windows virtual environment with pinned project dependencies, full pytest suite; inline JavaScript syntax check; dependency audit of the test environment. No external targets scanned.

Not performed: rebuilding dist/RAVEN.exe, clean-machine release qualification, or implementation of the isolated XSS execution verifier. Any existing executable still contains its prior build. Run from the updated source for these changes. Do not treat this checkpoint as completion of Stage 5 release qualification.

Final result: 149 tests passed, 60 subtests passed (24.72 seconds). Inline JavaScript parses; git diff --check passes; refreshed test-environment dependency audit found no known vulnerabilities.

Packaging note: an interim build (`dist/RAVEN-updated.exe`) was produced during this
handoff and smoke-tested. It has since been **superseded and removed** — the single
canonical app is now `dist/RAVEN.exe`, rebuilt cleanly from the committed source and
re-smoke-tested during Stage 5 (see `RAVEN_RELEASE_CHECKLIST.md` for its SHA-256 and
results). Clean-machine qualification remains outstanding.
