# RAVEN Recon — Feature Audit

Every frontend view and backend endpoint, with a verified status:
**FUNCTIONAL** (real, working) · **PARTIAL** · **SIMULATED/DEMO** · **BROKEN** · **UNTESTED**.

Verified by driving the live app (served by `raven.api`) in a browser and by the
automated test suite. "Live" = backed by the real SQLite workspace + scope-aware sender.

## Backend endpoints (`raven/api/server.py`)

| Endpoint | Status | Notes |
|---|---|---|
| `GET /` (UI) | FUNCTIONAL | Serves `web/prototype.html`, injects session token, Host-checked |
| `GET /api/health` | FUNCTIONAL | Open (no token) liveness probe |
| `GET /api/scope` | FUNCTIONAL | Token-required |
| `PUT /api/scope` | FUNCTIONAL | Token + Origin required; validates via `raven.scope` |
| `GET /api/assets\|urls\|changes\|runs\|summary` | FUNCTIONAL | Token-required; read from SQLite, scope-filtered |
| `POST /api/send` | FUNCTIONAL (real HTTP) | Token+Origin; scope-aware, IP-pinned, no redirect |
| `POST /api/collect` | FUNCTIONAL (real recon) | Token+Origin; crt.sh + probing (+ subfinder/gau if installed) |
| `POST /api/import` | FUNCTIONAL | Token+Origin; scope-filtered host/URL ingest |

## Frontend views / features

| Feature | Status | Evidence / notes |
|---|---|---|
| Surface Dashboard | FUNCTIONAL | Stat tiles + table render live assets (`example.com → 200 "Example Domain" cloudflare`); evidence drawer opens; target-controlled fields HTML-escaped |
| Attack Surface Graph | FUNCTIONAL | BloodHound-style force graph built from **live** `GRAPHDATA`; zoom/pan/drag/select; apex auto-detected |
| Scan Radar / Mini-map | FUNCTIONAL | Rendered from live host scores |
| Endpoints | FUNCTIONAL | Live URL table (empty until JS/gau collection produces URLs) |
| Changes | FUNCTIONAL | Live timeline from `changes` records |
| Runs | FUNCTIONAL | Live run history (mode/state/note) |
| Repeater | FUNCTIONAL (real) | Sends via `/api/send`; scope-aware; out-of-scope → BLOCKED; parses headers/body from the request pane |
| Intruder | FUNCTIONAL (real) | Iterates payloads through `§FUZZ§` via `/api/send`; anomalies flagged |
| Decoder | FUNCTIONAL (real, in-browser) | Base64 / URL / Hex encode+decode (`RAVEN`↔`UkFWRU4=` verified) |
| HTTP History | **SIMULATED/DEMO** | Shows 6 illustrative rows; **now labelled** "demo capture · live request logging on roadmap". Clicking a row → Repeater works. Real capture logging is not yet implemented. |
| Deep Audit | FUNCTIONAL | Heuristics now run on **live** workspace data (0 findings on a bare surface; fires non-prod / 401-403 / 5xx / enumerable-ID / data-flow rules on real data). Framed as "review candidates", never confirmed vulns. Ledger is generic guidance. |
| Embedded Terminal | FUNCTIONAL (mixed) | Virtual FS (`ls/cd/cat/nano/grep/sed/touch`) real; `curl` sends **real** requests via backend; `raven doctor/list/scan/export` are illustrative echoes |
| Workspaces switcher | FUNCTIONAL | Switch UI; the 4 sample entries are placeholders |
| New Target | FUNCTIONAL (real) | Domain + wildcard/apex → `PUT /api/scope` sets the server scope; creates the workspace |
| Identity config | FUNCTIONAL | Platform (H1/Intigriti/Bugcrowd) + handle → headers actually sent by Repeater/Intruder |
| User-Agent selection | FUNCTIONAL | Selected UA sent on real requests |
| Run collection | FUNCTIONAL (real) | Triggers `/api/collect`; streams logs; reloads data |
| Import | PARTIAL | Backend `/api/import` is real and tested; **no dedicated UI button** wires to it yet (terminal/PoC only) |
| Export | **NOT WIRED** | `raven export` exists in the CLI (`raven/export.py`) but there is **no** `/api/export` endpoint or UI button. Available only via the Python CLI. |
| Mouse spotlight / rain / theme | FUNCTIONAL (cosmetic) | Cyberpunk identity preserved |

## Demonstration vs real operation — summary
- **Real when the backend is connected (served over http://127.0.0.1):** Surface, Graph,
  Endpoints, Changes, Runs, Repeater, Intruder, Decoder, Deep Audit, New Target, Identity,
  UA, Run collection, `curl`.
- **Still demo/illustrative (clearly labelled):** HTTP History list.
- **Not wired into the app yet:** Export (CLI-only), a dedicated Import button.
- **Demo fallback:** opening `prototype.html` directly as a `file://` (no backend) shows
  the synthetic Atlas dataset and simulated responses — this is intended offline-preview
  behaviour and is visibly distinct from a connected session (which shows the real scope
  badge, live workspace name, and the "connected to backend · LIVE" terminal line).
