# Defensive repair audit — 29 September 2026

Scope: the working tree based on `92c1bc0`, the local API, scheduler, desktop UI,
configuration persistence and existing analysis paths. No external target was
scanned. Tests use temporary storage, mock transports or owned loopback fixtures.
This report supersedes earlier claims about browser execution and current builds.

## Repairs and evidence

| Area | Change | Evidence |
|---|---|---|
| Cancellation | Manual calls capture a stop generation before DNS. Stop then Resume cannot revive that call or a waiting rate slot. ACL retains one generation for its whole comparison. | Scheduler regressions and `test_stop_resume_during_dns_does_not_revive_prepared_request` |
| Budget and address limits | Waiting manual requests block budget reset; invalid numeric budgets are rejected. Both transports require public unicast unless explicitly permitted in local configuration. | Scheduler/network tests and loopback admission tests |
| Identity | Partial UA edits preserve research headers; case-insensitive merge; selected UA takes precedence; framing and local-auth headers are excluded; failed atomic save restores memory. | `test_defensive_regressions.py` and local receiving-server identity tests |
| Workspaces | Saved active workspace restores on startup. Corrupt settings block sending while permitting recovery. Conflicting folder ownership is refused without moving or merging data. Failed rollback remains blocked. | Temporary filesystem failure injection tests |
| Import and ACL | Scope/store are captured together; active imports are excluded from recovery interruption. ACL validates every identity before its first send and keeps one context. | Import-switch and ACL context/validation regressions |
| HTTP | Ambiguous framing is refused; body reads have bounded size and total deadline; supported keep-alive requests consume their own bodies. Token/Host/Origin controls retained. | HTTP framing and API security modules |
| UI | Untrusted responses/errors/headers rendered as text. Failed saves cannot show success. Workspace switch clears credentials and loads that workspace's identity; loading failure pauses sends. | Intercepted local browser tests, inert text markers |
| XSS | Unsafe execution module replaced by disabled compatibility interface; API confirmation refused before sending; UI offers reflection analysis only. | Executor/quarantine regressions; no browser payload or target execution |
| Launcher | Launcher finally block requests scheduler and HTTP shutdown after the UI returns; real native-window closure still needs verification. | Source review; packaged smoke test recorded separately |

UA presets are historical compatibility strings, not a claim about current or
installed browser versions. Required research headers are entered explicitly;
the UI no longer infers a header name from a platform label.

## Verification

Final local verification: **263 tests and 71 subtests passed**, with no failed or
skipped tests. Browser checks passed 29 literal-rendering cases, five workspace
persistence scenarios, identity failure/recovery and workspace credential clearing.
No page errors; all browser requests intercepted. Dependency audit: 58 packages,
zero known advisories. Ruff was unavailable and was not claimed as run.

Packaged startup, auth/Host/scope rejection, XSS quarantine, local fixture comparison,
no-network collection finalization, and saved settings after restart passed. The
hidden-window smoke needed termination of its own processes; real native-window
graceful closure remains unverified.

The exact executable hash and build environment are recorded in
`RAVEN-audit-results.json` and `RAVEN-build-manifest.json` (both present at the repo
root). Rebuilt binary `dist/RAVEN.exe` SHA-256:
`3dccf7d5fc4a96935763093deb5beddafb37684bdf7608c887f6aac01ed502f6`
(supersedes the earlier `72b5c8b4…82763e60`, which predated the framing fix below).

Independent re-verification and audit pass (2026-09-29): the guarded Python suite was
re-run from a clean dependency install and reproduced **266 passed, 71 subtests, 0
failed, 0 skipped** (263 before + 3 new framing regressions). `pip-audit 2.10.1` over
the app dependency tree found no advisories (the only finding is `PYSEC-2026-3721` in
the `pip` installer tool itself, which is not bundled into the executable). The
Playwright frontend harness was re-run this session (driving system Chrome, all
requests intercepted) and reproduced **29 inert-rendering cases + 5 workspace
scenarios + identity/recovery checks with zero outbound requests and zero page
errors** — including that the XSS UI stays "Browser execution disabled" and that a
workspace switch clears credential fields.

Audit fix this session (error framing): a full source read found one robustness gap —
`GET` data routes, `POST /api/import` and `POST /api/clear-stop` could let a store/disk
error (`sqlite3.Error`/`OSError`) or a post-shutdown `SchedulerStopped` raise unhandled
and drop the socket mid-request instead of sending a framed response. The request body
is always consumed before dispatch, so this was never request-smuggling — but it was
inconsistent with the `PUT` persistence routes. Fixed: those routes now return a framed
500 (import also sends `Connection: close`) or 409, without leaking internal error
text; three regressions were added to `tests/test_api_security.py`.

The exe was then **rebuilt from this fixed source** (PyInstaller 6.22.3) and smoke-tested
this session (server surface: startup, token auth, bad-Host rejection, token inlined,
`/api/scope`+`/api/summary` served, data path resolved next to the exe), then its
process tree was terminated. The interactive GUI-window graceful close was still NOT
exercised and remains unverified.

Reproduce the guarded Python run with `python tools/run_local_tests.py`. It
uses a process-local loopback-only socket guard, not an OS firewall. Browser tests intercept every
request, abort external resources and use inert marker text. Test fixtures that
previously inherited a stale workspace path now own isolated temporary storage;
production persistence errors are not suppressed to make those tests pass.

## Remaining boundaries and Stage 3–5

**Stage 3: evidence quality.** Keep conservative ACL verdicts. Equality and HTTP
denial are review evidence, not a security guarantee; truncated/decoded-lossy
captures remain inconclusive. Expand local fixtures for application-specific
denials and non-UTF-8 responses. Audit exported URLs, labels, errors and snippets;
pattern redaction cannot promise removal of every secret.

**Stage 4: containment and usability.** Keep XSS execution disabled. Finish the
documentation inventory for demo/unwired controls and refresh the older illustrated
Arabic guide. Evaluate a process-wide cap on manual HTTP handlers and a bounded
DNS service. Independent CLI/server processes do not share Emergency Stop or
budgets; simultaneous writers to one workspace are unsupported. Cancellation
cannot retract a request already admitted to the network. Budget counters reset
on process restart. Workspace store lifetime/refcount cleanup remains future work.

**Stage 5: release qualification.** Test the exact executable on a clean Windows
machine, including missing WebView runtime, read-only installation folder,
non-ASCII paths, shutdown/restart and recovery. Record dependency versions, source
state and SHA-256. Signing and distribution readiness are not established by a
successful development-machine smoke test. No blanket claim that all bugs or all
secrets have been found is made.
