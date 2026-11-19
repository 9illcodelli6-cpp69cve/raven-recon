# RAVEN Recon — Feature Inventory

Historical feature inventory, updated for defensive repairs on 2026-09-29.
Earlier individual counts and E2E claims describe older snapshots; the current
audit report records the checks actually performed. Demo/unwired controls remain
incomplete.

| Control | Status | Backend route | Test / evidence |
|---|---|---|---|
| Surface dashboard | REAL | `GET /api/assets`,`/summary` | driven in-browser; scope-filtered read |
| Attack-surface Graph | REAL | (from `/api/assets`,`/urls`) | live `GRAPHDATA`; rendered nodes verified |
| Scan Radar / mini-map | REAL | (from `/api/assets`) | live host scores |
| Endpoints | REAL | `GET /api/urls` | live; empty until JS/gau produce URLs |
| Changes | REAL | `GET /api/changes` | live timeline |
| Runs | REAL | `GET /api/runs` | live run history |
| Repeater | REAL | `POST /api/send` | scope-aware real send; out-of-scope→BLOCKED; workspace search headers + UA enforced server-side |
| Intruder | REAL with cancellation limits | `POST /api/send` (loop) | Cancel prevents the next UI iteration; the current API call may still wait or complete. Workspace switches clear inputs and stop further iterations. |
| Decoder | REAL (offline) | none (in-browser) | Base64/URL/Hex verified |
| HTTP History | **DEMO** | none | 6 sample rows; **labelled** "demo capture" |
| Deep Audit | REAL | (from live data) | heuristics on live `GRAPHDATA`; empty on bare surface |
| Terminal | PARTIAL | `curl`→`/api/send` real; `raven *` echoes | FS commands real; recon commands illustrative |
| Workspaces switch | **DEMO/PARTIAL** | sample entries hidden in live mode | Use New Target for an actual server scope change; menu placeholders are not a persisted workspace selector. |
| New Target | REAL | `PUT /api/scope` | sets server scope + workspace; **precise (apex) scope is now the default**, wildcard is an explicit opt-in; full domain used as identity (no more first-label truncation) |
| Identity config | **REAL** | `GET`/`PUT /api/identity` | **server-side, per-workspace**: validated search headers (CR/LF rejected, Cookie/Authorization refused, case-insensitive dedup) applied to every real request from the central send path — Collection, Repeater, Intruder, curl, every ACL identity + anonymous baseline, and the XSS Lab; persisted in `identity.json`, survives restart; 17 tests against a real local receiving server |
| User-Agent select | REAL | `GET`/`PUT /api/identity` | Nine historical browser header profiles plus validated Custom. Persistent, fixed selection; no claim about installed/current browser versions. Keyboard activation and failed-save behavior covered locally. |
| Run collection | REAL | `POST /api/collect` → scheduler job | non-blocking submit → `job_id`; crt.sh + probing; per-host rate limit + budget; progress polled from `/api/jobs/<id>` |
| **Task Center** | **REAL** | `GET /api/jobs`,`/api/jobs/<id>`,`/api/scheduler`; `POST /api/jobs/<id>/cancel\|pause\|resume`,`/api/emergency-stop`,`/api/clear-stop`,`/api/reset-budget` | central scheduler: worker pool, live states, cancel/pause/resume, budget usage display + gated reset, crash-recovery of interrupted runs. **Emergency Stop now blocks new target requests from EVERY tool** (Collection, Repeater, Intruder, curl, ACL, XSS Lab), not Collection alone — verified with zero bytes reaching a local receiving server; 24+ tests |
| Read linked JS (collection stage) | **DISABLED (honest)** | none | was a fully-clickable toggle with **no effect** on `do_collect` (never wired); now disabled with a "not wired yet" label instead of silently doing nothing |
| Import | PARTIAL | `POST /api/import` | backend real+tested; **no UI button** yet |
| Export | **BROKEN/NOT WIRED** | none (CLI only) | `raven export` in CLI; no `/api/export` |
| **Access Control Lab** | **REAL** | `POST /api/access-check` | dual/multi-session compare (lossless JSON equality, not lossy masking), identity separation, resource-policy-gated anon-baseline (never auto-suppresses a real gap), truncated/lossy evidence → INCONCLUSIVE, credential redaction, →Repeater; **export now shows a preview + best-effort secret-pattern redaction of response snippets before download**, with an explicit "not guaranteed, response content may still be sensitive" notice; ~40 tests; E2E verified |
| **XSS Lab** | **REAL reflection analysis; execution DISABLED** | `POST /api/xss-check`; isolation route reports disabled | Browser executor quarantined at API/module/UI boundaries. No cached result can enable it. See `docs/XSS_ISOLATION.md`. |

## Planned (V4, not yet started)
Execution remains quarantined pending separate containment review. SSE progress streaming (Task Center currently
polls), API/Auth intelligence importers, Evidence Vault, Reporting Studio, workflow
builder, plugin/AI. Tracked in `RAVEN_NEXT_STEPS.md`. **Task scheduler: DONE** (Stage 2).

## Legend
- **REAL** — backend implemented, UI wired, exercised.
- **PARTIAL** — backend or UI incomplete (noted).
- **DEMO** — illustrative sample data, clearly labelled in-app.
- **BROKEN/NOT WIRED** — advertised elsewhere but not reachable from the app.
- **UNTESTED** — present but not covered by an automated/manual check.
