# RAVEN Recon — Release Readiness Checklist

Updated: **2026-09-29 — defensive audit verified locally**.

The V4/V5 test counts, executable hashes and broad PASS statements previously in
this file describe older snapshots. **They are superseded for the current working
tree.** Source repairs do not change an older executable or a running process.
The current integrated suite, build manifest, executable path and SHA-256 must be
recorded after final validation; none is inferred from the historical results.

Status: **IMPLEMENTED** means a source change and relevant regression coverage
exist; **PENDING** means final verification is outstanding; **LIMITATION** means the
boundary remains and must be stated to users. This is not a security certificate.

| Requirement | Current status | Evidence / acceptance |
|---|---|---|
| Unsafe XSS execution disabled | IMPLEMENTED | Executor compatibility calls fail closed; confirmation is refused before analysis sends. `tests/test_xss_lab.py`, `tests/test_xss_executor.py`; see `docs/XSS_ISOLATION.md`. |
| Identity updates preserve unrelated fields and survive write failure | IMPLEMENTED | Partial updates, atomic publication and rollback; `tests/test_defensive_regressions.py`. |
| Required headers / selected UA reach the controlled sender consistently | IMPLEMENTED | Case-insensitive merge, selected UA precedence, framing-header removal; local or mocked transport coverage. |
| Workspace isolation and restoration fail closed | IMPLEMENTED | Conflict requires a distinct name; corrupt configuration or failed rollback cannot silently enable sending. Temporary-filesystem regressions cover failure cases. |
| API admission, budgets and cancellation | IMPLEMENTED | Waiting manual requests block reset; stop generations prevent old waits reviving after Resume. `tests/test_scheduler.py`, `tests/test_identity_and_admission.py`. |
| Public-address policy | IMPLEMENTED | Public unicast required for API and CLI transports, including mapped-address handling; pure classification and mocked DNS coverage. |
| HTTP authentication and framing | VERIFIED locally | Token/Host/Origin, bounded body reads and keep-alive framing retained; `tests/test_api_security.py`, `tests/test_http_framing.py`. |
| ACL comparison and whole-operation context | IMPLEMENTED | All identities prevalidated; captured scope/identity remains fixed; incomplete evidence stays inconclusive. |
| Target-controlled UI text | VERIFIED locally | Response/error/header rendering must remain text; local browser verification complements Python tests. |
| Full integrated test suite and static/dependency checks | VERIFIED with limits | 266 tests and 71 subtests pass (re-run this session; 263 + 3 new framing regressions); JS re-run in system Chrome (29+5 cases); `pip-audit 2.10.1` shows no advisories in the app dependency tree (only `PYSEC-2026-3721` in the `pip` tool, not bundled). Ruff unavailable. |
| Build provenance and executable smoke test | VERIFIED with limits | Binary **rebuilt this session** from the fixed source; starts, enforces token auth + bad-Host rejection, inlines the token, serves scope/summary, resolves its data path next to the exe. `dist/RAVEN.exe` SHA-256 `3dccf7d5…ed502f6` (supersedes `72b5c8b4…`), full value + deps + source state in `RAVEN-build-manifest.json` / `RAVEN-audit-results.json` (repo root). Native GUI-window graceful close still not exercised. |
| Clean Windows qualification | PENDING | Separate machine without developer tools; verify required runtime, startup, writable data path and restart. Development-machine smoke tests do not satisfy this row. |
| Export privacy | LIMITATION | ACL export performs best-effort snippet redaction and a shortened preview. URLs, labels, errors or uncaught secrets may remain sensitive. |
| CLI / multiple-process controls | LIMITATION | Desktop Emergency Stop does not govern independent CLI or server processes. Concurrent processes sharing a workspace are unsupported. |
| Intruder cancellation | LIMITATION | Stops the next UI iteration; the current API call may still wait or complete. Emergency Stop governs further server admission. |
| Secrets in repository and deliverables | PENDING explicit review | `.gitignore` is not proof of absence. Inspect the actual tracked/untracked files selected for delivery and export contents. |

## Release decision

**Public-release readiness is not established.** Complete the pending checks and
record remaining limitations before distribution. Do not reuse the former claim
that no critical issue remains, or treat a successful subset as the full suite.

Current repairs and scope of review: [Defensive audit](docs/DEFENSIVE_AUDIT_2026-09-29.md).
