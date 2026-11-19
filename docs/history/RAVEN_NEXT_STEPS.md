# RAVEN Recon — Prioritized Next Steps

Based on the **actual** final repository state (HEAD `e6a267a`), not the aspirational
roadmap. Security and reliability first; features only on a solid base.

## P0 — Close out release gating (small, do first)
1. **Validate `dist/RAVEN.exe` on a clean Windows host** (WebView2 present, no dev tools).
   Currently verified only on the build machine → checklist item 15.
2. **Add a headless-JS test** (Playwright or jsdom) that asserts the XSS-escaping
   invariant, so it is CI-guarded rather than manually verified.
3. **Run `pip-audit` + a linter** (`ruff`) and fix anything flagged.
4. **Investigate the non-fatal `Invalid regular expression flags`** console line with real
   DevTools (it does not affect function; likely outside the main script).

## P1 — Security defence-in-depth (from the review's residual risks)
5. Route the **crt.sh** passive fetch through the pinned-IP path (currently plain hardened
   `urllib`).
6. Consider **session-token rotation / lifetime** if the API surface ever grows.
7. Add a **global rate limit + emergency stop** shared across Repeater/Intruder/collection
   (partially implicit today via per-request scope checks; make it explicit and
   workspace-scoped).

## P2 — Reliability / engineering quality
8. **Centralized async task manager**: background jobs, cancellation, timeouts, progress,
   concurrency caps. Today `/api/collect` runs synchronously under a lock — a long crt.sh
   fetch blocks other API calls. This is the highest-value reliability upgrade.
9. **SSE / WebSocket event stream** for live recon progress instead of the post-hoc log
   list (the task manager is a prerequisite).
10. **DB**: add pagination to `/api/assets|urls` for large workspaces; add indices as data
    grows; add a lightweight migration mechanism before any schema change.

## P3 — Features (only after P0–P2)
11. **HTTP History → real capture store** (currently demo-labelled). Persist every
    `/api/send` request/response with search, tags, notes.
12. **Export in the app**: add `/api/export` + a UI button wrapping `raven/export.py`
    (JSON / Markdown / hosts / urls).
13. **Import UI button** wired to the existing `/api/import`.
14. **Smart Request Lab**: response diff, request collections, variable extraction,
    sequential workflows, HAR import/export.
15. **JavaScript Intelligence**: real endpoint/GraphQL/parameter extraction with source
    attribution and local secret redaction (backend engine `analysis.py` already has a
    static extractor to build on).
16. **Investigation Studio**: turn Deep Audit candidates into saved investigations with
    evidence, states, and exportable bug-bounty reports (H1/Bugcrowd/Intigriti templates).
17. **Attack-surface diff** across recon runs; graph filtering and historical snapshots.
18. **Optional AI layer** — strictly a summarizer/assistant over the deterministic engine,
    off by default, no autonomous request execution, explicit consent before any external
    call, local secret redaction.

## Cross-cutting
- Keep the **standard-library-only** core; do not add runtime dependencies to the server.
- Preserve the cyberpunk visual identity and the "review priority ≠ vulnerability" framing.
- Every new active-network feature must go through the single scoped `do_send` path.

---

## V4 status (as of HEAD e6a267a)
**Done:** Phase 0 (verified baseline, docs, threat model, feature inventory); durable core
security (shared hardened sender, token/Origin/Host auth, DB isolation) meets the P0 bar;
**first P1 vertical slice — Access Control Lab** (backend + UI + fixture + 7 tests).

**Next vertical slices, in order (finish one before starting the next):**
1. **XSS Lab** (V4 Phase 3) — reflection-context detection + **isolated** browser verification
   with a harmless unique canary; must never execute target JS in the privileged WebView; local
   safe-context fixtures. Highest-priority remaining P1.
2. **Task scheduler + budgets** (V4 Phase 1) — so `/api/collect` and future active tools run as
   cancellable background jobs with per-host rate limits and an emergency stop (today collect is
   synchronous under a lock).
3. **SSE progress events** (depends on the scheduler).
4. **API/Auth intelligence importers** (OpenAPI/HAR/Postman) — passive, no network during parse.
5. **Evidence Vault + Reporting Studio**, then workflow builder.

**Access Control Lab follow-ons:** scenario/template library, owned-test-case import/export,
semantic JSON-path diff, preflight matrix, send-to-Repeater, exportable report.

**Release-gating (unchanged):** clean-Windows EXE test, headless-JS XSS test, `pip-audit`/lint.

---

## V4 session update (HEAD e6a267a) — done & next
**Completed this session:** Access Control Lab (REAL, 12 tests) with FP filtering,
expected-access matrix, session-expiry, export, →Repeater; XSS Lab safe-analysis engine
(REAL, 8 tests). Suite 47/47. New RC built + smoke-tested.

**Stage 1 — DB concurrency: DONE.** `Store` is internally thread-safe (RLock,
`busy_timeout`, WAL, rollback-on-failure, `integrity_check`, idempotent `close`,
`mark_interrupted`). The blanket API `_LOCK` is gone — collection network I/O holds no DB
lock, so reads stay responsive. 4 concurrency tests incl. slow-collect-doesn't-block-reads.

**Stage 2 — Central Task Scheduler: DONE.** `raven/api/scheduler.py` — bounded worker pool;
jobs `QUEUED→RUNNING→DONE/FAILED/CANCELLED/PAUSED`; per-`(workspace,host)` token-bucket
rate limits; per-workspace request budget; cancel/pause/resume; global Emergency Stop
(cancel-all + refuse-new + clear); cooperative `Control` checkpoints; cancellation keeps
partial results and never auto-replays; interrupted-run crash recovery via
`Store.mark_interrupted()`. `/api/collect` is now non-blocking (returns `job_id`); added
`/api/jobs`, `/api/jobs/<id>`, `/api/scheduler`, `/api/jobs/<id>/{cancel,pause,resume}`,
`/api/emergency-stop`, `/api/clear-stop`. New **Task Center** UI (live states, per-job
controls, Emergency Stop banner, progress). Fixed a keep-alive body-drain bug found during
verification (undrained POST body corrupted the next request). 11 scheduler tests + 1
keep-alive regression. Design: `docs/TASK_SCHEDULER.md`.

**Remaining V4 stages (this directive):**
3. **Access Control accuracy review** — ensure normalization never erases security-meaningful
   differences (object IDs, ownership, authz decisions); store both sanitized-original AND
   normalized responses; add false-NEGATIVE regression tests; verify public-resource FP filter
   doesn't suppress genuine authz inconsistencies.
4. **XSS isolation design doc** (`docs/XSS_ISOLATION_DESIGN.md`) — separate browser process,
   isolated temp profile, no RAVEN token, block external collection endpoints during verify,
   documented limits. Design only until isolation tests pass.
5. **Release validation** — full regression + build/smoke-test the exe + report refresh + Git
   checkpoint per stage.

**Later:** **SSE** progress streaming on top of the scheduler (Task Center polls today); the
XSS Lab **isolated-browser execution verifier** implementation (Stage 4 is its design).
