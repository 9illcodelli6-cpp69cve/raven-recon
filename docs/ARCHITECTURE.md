# RAVEN Recon — Architecture

_As-built, verified against the source at HEAD `d72e362`._

## Process shape
A single Python process runs a **standard-library HTTP server** bound to
`127.0.0.1` (default port 8765, with connect-probe fallback to the next free port).
It serves the HTML/CSS/JS workbench and a small JSON API. The desktop shell
(`launch.py`) starts that server on a daemon thread and opens the UI either in a
native **pywebview / WebView2** window or the default browser (fallback). PyInstaller
freezes the whole thing into a one-file `RAVEN.exe`.

```
launch.py ── start_background() ─┐
                                 ▼
        raven/api/server.py  (ThreadingHTTPServer, loopback)
          ├─ serves web/prototype.html  (+ inlined session token)
          ├─ scope-aware sender  do_send()  ──► authorized target
          ├─ recon collect / import         ──► crt.sh / subfinder / gau (optional)
          └─ reads/writes  workspaces/<slug>/recon.db  (SQLite, WAL)
                                 ▲
        web/prototype.html  (single-file UI; fetch()+token to same origin)
```

## Modules (`raven/`)
| Module | Responsibility | Notes |
|---|---|---|
| `api/server.py` | Local HTTP API, auth, the hardened sender, recon orchestration | stdlib only; the security-critical file |
| `scope.py` | Canonical URL / hostname validation, `Scope.allows_url/allows_host` | pure; shared by every path |
| `network.py` | Original aiohttp `Requester` (SSRF-safe resolver) | **not used by the app** (aiohttp not installed); reference for the engine |
| `store.py` | SQLite persistence (assets/urls/changes/runs/probes) | `check_same_thread=False`; WAL; per-workspace file |
| `analysis.py` | `priority()`, `family()`, `inspect_body()` (title/server/hash/scripts) | pure |
| `engine.py` | Full recon engine (fcntl/killpg) | **Linux-only**, not used by the desktop app |
| `cli.py`, `tui.py`, `demo.py`, `config.py`, `export.py` | Original CLI/TUI | retained; TUI needs Textual |
| `api/__main__.py` | `python -m raven.api` entry | calls `serve()` |

## The one network egress: `do_send()`
Every active request (Repeater, Intruder, terminal `curl`, HTTP root probing) goes
through `do_send()`. It: canonicalizes the URL, checks it against the workspace
`Scope` **at request time**, resolves the host and rejects if **any** address is
non-public (`_is_public`, IPv4-mapped aware), **pins** one resolved IP for the actual
`http.client` connection while keeping the hostname for TLS SNI + cert verification,
never follows redirects, caps the response body, and returns a structured result.
This is the single chokepoint for scope/SSRF invariants.

## Local API surface
`GET /` (UI+token), `GET /api/health` (open), and token-gated:
`GET /api/scope|assets|urls|changes|runs|summary`, `PUT /api/scope`,
`POST /api/send|collect|import`. State-changing verbs also require an allow-listed
`Origin`; every request requires a loopback `Host`.

## Auth / trust boundary
A per-run `secrets.token_urlsafe(32)` is inlined into the served page
(`window.RAVEN_TOKEN`). The UI attaches it as `X-RAVEN-Token` on every `/api/*`
call. Cross-origin pages cannot read it; a rebound `Host` cannot even fetch the page.
See `docs/THREAT_MODEL.md`.

## Data
One SQLite DB per workspace at `workspaces/<slug>/recon.db` (WAL). Schema is
`CREATE TABLE IF NOT EXISTS` only (no destructive migrations yet). `scope.json` is
persisted alongside for reference. Build artifacts, DBs, and `workspaces/` are
git-ignored.

## Known architectural debt (tracked in `RAVEN_NEXT_STEPS.md`)
- The UI is one large `prototype.html`; maintainability will need incremental modularization.
- `/api/collect` is synchronous under a global lock (no task scheduler yet).
- No SSE/event stream; the UI polls/refreshes after actions.
- No versioned DB migrations; HTTP History is demo data (labelled).
