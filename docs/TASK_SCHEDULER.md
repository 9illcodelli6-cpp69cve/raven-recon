# Scheduler and HTTP contracts — 29 September 2026

This document supersedes earlier collection-only admission guarantees.

- Three cooperative collection workers; at most 256 pending collections and 1,000 retained terminal jobs. Paused queued jobs do not occupy workers. These are collection-pool limits, not a cap on every HTTP handler.
- Emergency Stop rejects new collection submissions and new target HTTP admissions through the local API sender, including Repeater, Intruder, curl, ACL and XSS reflection analysis. It cancels queued collections and signals running ones. It does not control independent CLI or server processes.
- Already admitted requests may finish. Cancellation is checked after token waits and between requests. A stopped manual waiter belongs to a permanently cancelled generation; clearing stop admits new work but never revives that waiter or replays cancelled work.
- Intruder's Cancel button stops its next UI loop iteration. The current API call can still be waiting for admission or completing; it is not a server-side per-request cancellation token.
- Every admitted API target attempt, including fallback and network failure, consumes the workspace budget. Scheduled passive lookup attempts are also accounted for. Host rate ceilings span workspaces, default to 3 requests/second with burst one, and retain the lowest requested rate for this scheduler's lifetime.
- Budget defaults to 5,000 attempts per canonical workspace path, shared by jobs and manual requests. An explicitly supplied lower allowance tightens the budget. `/api/reset-budget` permits an explicit reset only while the workspace has no active/queued/paused job or waiting/in-flight manual request. It does not clear Emergency Stop. Invalid budget values and busy workspaces have distinct errors.
- Budget counters, limiter state and job metadata are process-local. They are not persisted across restart. Durable runs retain partial results; interrupted runs are not automatically replayed.
- Scheduled collections skip subfinder/gau because this scheduler cannot account for their outbound traffic. CLI collection is a separate workflow.
- A submitted collection captures its store, scope, research identity, private-address setting, timeout and response limit. Workspace changes do not redirect it. ACL likewise captures one context for the complete comparison. Reopening excludes this process's active run IDs from interruption recovery; simultaneous independent writers to one workspace remain unsupported.
- Durable finalization is serialized against cancellation: a successfully committed run is not subsequently relabeled cancelled.

HTTP accepts a single numeric Content-Length up to 4 MiB, rejects unsupported
transfer encoding and ambiguous framing with connection close, and bounds body
reads to a total ten seconds. Supported bodies are consumed on reused connections.
Malformed/non-object JSON receives 400. Protected requests authenticate before body
reads; rejections use a brief bounded discard to avoid losing the response to a
Windows TCP reset. These are local API request-body limits, not a guarantee that a
target response or DNS resolution completes within the same deadline.

Regression modules: `test_scheduler.py`, `test_collection_context.py`,
`test_http_framing.py`, `test_identity_and_admission.py`,
`test_defensive_regressions.py` and API security/concurrency tests. Final integrated
results belong in the current audit/build report, not in historical Stage 2 counts.
