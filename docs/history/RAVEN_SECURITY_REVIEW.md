# RAVEN Recon — Security Review

_Overnight security review. Scope: the local desktop application (Python backend +
HTML/JS frontend + PyInstaller build). All testing used loopback servers and mocks;
no external targets were probed._

Repository HEAD at review: `e6a267a`.

---

## 1. Threat model

RAVEN runs a local HTTP server on `127.0.0.1:8765` that (a) serves the workbench UI
and (b) exposes a **scope-aware HTTP sender** the researcher uses to reach *external
authorized targets* (Repeater / Intruder / `curl`). The two trust boundaries that
matter:

1. **Tool → target.** The sender must only ever reach hosts inside the researcher's
   explicitly-configured scope, and must never be tricked into reaching internal /
   cloud-metadata / loopback addresses (SSRF). This is the core safety property of a
   bug-bounty tool.
2. **Untrusted local browser context → the loopback API.** Any web page open in the
   user's browser, or a page whose DNS is rebound to `127.0.0.1`, can attempt requests
   to `http://127.0.0.1:8765`. Binding to loopback is **not** authentication. The API
   must reject cross-origin / unauthenticated / rebound-Host requests, especially the
   state-changing ones (change scope, send arbitrary requests).
3. **Target response → the tool UI.** Probed pages return attacker-influenced content
   (titles, `Server` headers, discovered URLs). Rendering it must not execute script
   in the workbench (stored XSS).

---

## 2. Vulnerabilities found and fixed

### A. DNS rebinding / SSRF TOCTOU — **CRITICAL — FIXED**
**Root cause:** the previous sender validated the resolved IP with
`socket.getaddrinfo`, then handed the *hostname* to `urllib`, which resolved it **again**
at connect time. A hostile resolver could return a public IP for the check and a private
IP (`127.0.0.1`, `169.254.169.254`) for the connection.

**Fix (`raven/api/server.py`):**
- `_pick_public_ip()` resolves once, rejects the request if **any** returned address is
  non-public, and returns a single pinned IP.
- `_PinnedHTTPConnection` / `_PinnedHTTPSConnection` connect to **that exact IP**. For
  TLS, the socket is wrapped with `server_hostname=<original host>`, so SNI and
  certificate hostname verification still validate the real name — no re-resolution.
- `_is_public()` unwraps **IPv4-mapped IPv6** (`::ffff:127.0.0.1`) and rejects private /
  loopback / link-local / reserved / multicast / unspecified addresses.
- Environment HTTP proxies disabled (`ProxyHandler({})` on the crt.sh opener; the pinned
  path uses no proxy at all).
- Redirects are never auto-followed (`http.client` returns the raw 3xx).

**Regression tests:** `test_dns_rebinding_to_loopback_blocked`,
`test_dns_rebinding_to_metadata_ip_blocked`, `test_dns_rebinding_ipv4_mapped_blocked`,
`test_mixed_public_and_private_blocked`, `test_is_public_classification`,
`test_tls_default_context_verifies`, `test_legitimate_request_works_and_pins`,
`test_redirects_are_not_followed`, `test_out_of_scope_blocked_before_dns`.

### B. Missing API authentication / CSRF — **CRITICAL — FIXED**
**Root cause:** any local origin could `POST /api/scope` (widen scope) and `POST
/api/send` (proxy arbitrary in-scope requests). Loopback binding was the only control.

**Fix:**
- A cryptographically random `SESSION_TOKEN` (`secrets.token_urlsafe(32)`) is generated
  per run and **inlined into the served page** (`window.RAVEN_TOKEN`). Same-origin JS
  reads it; a cross-origin page cannot.
- Every `/api/*` endpoint except `/api/health` requires header `X-RAVEN-Token`
  (compared with `secrets.compare_digest`). The token is **never** placed in a URL.
- State-changing endpoints (`/api/send`, `/api/collect`, `/api/import`, `PUT
  /api/scope`) additionally require an **Origin** in the loopback allow-list. A
  cross-origin simple request that cannot set the custom header is rejected regardless.

**Regression tests:** `test_api_requires_token`, `test_api_accepts_valid_token`,
`test_scope_change_requires_auth`, `test_cross_origin_rejected_even_with_token`,
`test_same_origin_with_token_allowed`, `test_token_inlined_into_page`.

**Note on token delivery (threat-modelled):** the token is delivered only in the page
body, which is itself protected by Host validation (below). There is **no**
unauthenticated endpoint that returns the token to arbitrary callers.

### C. DNS rebinding against the loopback API itself — **HIGH — FIXED**
**Root cause:** even with a token, a page whose domain is rebound to `127.0.0.1` could
fetch `/` and receive the inlined token, then call the API.

**Fix:** `_host_allowed()` rejects any request whose `Host` header is not
`127.0.0.1` / `localhost` / `::1` (with the port stripped, IPv6 literal aware). Applied
to **all** requests including the static page — so a rebound origin cannot even fetch
the page that carries the token.

**Regression tests:** `test_bad_host_header_rejected`, `test_loopback_host_allowed`.

### D. Frontend stored XSS from probed content — **HIGH — FIXED**
**Root cause:** the live render functions injected target-controlled strings (page
`<title>`, `Server` header, discovered URLs, families, sources, change values) into
`innerHTML` without escaping. A malicious target returning
`<img src=x onerror=…>` in its title would run script in the workbench.

**Fix (`web/prototype.html`):** added `HX()` (HTML-entity escaper) and applied it to
**every** target-controlled interpolation across `renderAssets`, `renderUrls`,
`renderChanges`, `renderRuns`, `chipsHtml`, `openDrawer`, the mini-map, the BloodHound
graph labels, and `showInfo`. Verified in-browser: an `onerror` payload renders as inert
text (`window.__XSS` stays `0`, no `<img>` is created).

**Regression evidence:** manual browser assertion (documented in the overnight report).
_Note: this is a client-side invariant; it is verified via the browser pane rather than
the Python unit suite._

### E. Workspace-name path traversal — **MEDIUM — FIXED**
**Root cause:** `_slug()` kept dots, so a workspace named `..` resolved
`workspaces/..` = the parent directory.

**Fix:** `_slug()` now strips leading/trailing dots and dashes; `..` → `workspace`.
**Regression test:** `test_slug_blocks_traversal`.

---

## 3. Reviewed and judged acceptable (with reasoning)

- **Path traversal on static serving** — `_serve_static` resolves the target and
  refuses anything not under `web/`. Covered by `test_path_traversal_does_not_leak_source`.
- **Command / shell injection (`_run_tool`)** — external tools are invoked with an
  argument **list** (never `shell=True`); the only interpolated value (`root`) comes
  from the scope include list, which `raven.scope.rule()` has already validated as a
  hostname/wildcard. No shell metacharacter path.
- **SQL injection (`raven/store.py`)** — all values are parameterised; the only
  interpolated identifiers (`table`, `key`, column names) are hard-coded literals, never
  user input.
- **Unsafe deserialization** — no `pickle` / `eval`; request bodies are `json.loads`
  with a 4 MiB cap and `{}` fallback (`test_malformed_json_does_not_500`).
- **External-tool scope enforcement** — subfinder/gau/crt.sh output is filtered through
  `scope.allows_host` / `allows_url` before storage (`test_import_rejects_hostile_and_out_of_scope`
  covers the same code path for imports).
- **Workspace isolation** — each workspace is a separate SQLite file under
  `workspaces/<slug>/`; `test_workspace_isolation` proves one cannot read another's data.

---

## 4. Remaining risks / limitations (documented, not fixed)

1. **Frontend XSS coverage is verified manually, not by an automated JS test runner**
   (no headless-JS harness in this environment). A DOM-test harness (jsdom / Playwright)
   is recommended so escaping is regression-guarded in CI.
2. **crt.sh fetch is not IP-pinned.** It uses the hardened `urllib` opener (no proxy, no
   redirect, TLS verified) but re-resolves `crt.sh`. Risk is low (fixed trusted host,
   response only parsed for names) but for defence-in-depth it should move to the pinned
   path. **Owner decision: acceptable for now.**
2. **No session expiry / rotation.** The token lives for the process lifetime. For a
   single-user local desktop app this is acceptable; rotation would matter if the API is
   ever exposed beyond loopback (which it must not be).
3. **One non-fatal `SyntaxError: Invalid regular expression flags`** is logged by the
   browser pane at load. The RAVEN main script parses and runs fully (all views, auth,
   escaping, graph verified working), and a `git diff` proves it predates and is
   independent of tonight's changes; it appears to originate outside the main script
   (favicon/instrumentation). Flagged for DevTools inspection on a real browser.
4. **Dependency review:** the app core is standard-library only. Optional extras
   (`pywebview`, `pythonnet`, `pyinstaller`, `pillow`) are used only for the native
   window / build / icon and are not required to run the server. No known-vulnerable
   pins were introduced; a `pip-audit` pass is recommended before any wider release.

---

## 5. Test summary

`python -m unittest tests.test_api_security tests.test_reliability` → **27 passed, 0 failed.**
Breakdown: 9 SSRF/TLS/redirect + 11 auth/CSRF/Host/traversal + 7 reliability/port-fallback/isolation.
The pre-existing engine tests (`test_engine`, `test_network`, `test_tui`, `test_core`)
require `aiohttp`/`textual`, which are **not installed** in this environment, so they are
**NOT TESTED** here.
