# RAVEN V5.0.0 Release Notes
## 2026-10-02 (compliance build)

RAVEN V5 integrates the Stage 1–11 canonical research pipeline into the live runtime.
Every controlled HTTP exchange is now persisted as a canonical Observation. The Access
Control Lab and XSS Lab automatically generate candidate findings. A new REST API
exposes findings, observations, baselines, payloads, and ML readiness. The desktop UI
now includes a full Findings section with 9 new views. All security invariants from
the V5 specification are intact and verified.

---

## New in V5

### Canonical Observation Persistence
Every request sent through `POST /api/send`, the Access Control Lab, the XSS Lab,
and host probes is now recorded as a canonical Observation in the workspace database.
Request headers with credentials (Authorization, Cookie, X-RAVEN-Token) are excluded
from the stored record.

### Candidate Finding Generation
- **Access Control Lab**: INCONSISTENT verdicts automatically create unverified
  candidate findings. A matching response is logged as a hypothesis — not confirmed.
- **XSS Lab**: Reflected canaries create unverified candidate findings. Reflection is
  not execution — researcher confirmation is required.

### New REST Endpoints
- `GET /api/findings` — list candidate findings
- `GET /api/findings/{id}` — finding detail
- `GET /api/findings/{id}/evidence` — evidence records
- `GET /api/findings/{id}/report` — Markdown report
- `POST /api/findings/{id}/review` — submit `open`/`accepted`/`confirmed`/`dismissed`
- `GET /api/observations` — list observations
- `GET /api/observations/{id}` — observation detail
- `GET /api/baselines` — statistical baselines
- `GET /api/payloads` — safe payload registry
- `GET /api/ml-readiness` — ML training readiness (always NOT_READY until researcher gates are met)

### New Desktop UI (V5-21 through V5-29)
A new **FINDINGS** section in the sidebar exposes:
- **Findings Center** — table of all candidate findings; click a row to open inline detail
- **Finding Detail** — title, severity, verification_status badge, Markdown report
- **Review Controls** — Open / Accept / Confirm (researcher) / Dismiss buttons + note
- **Evidence Viewer** — evidence rows per finding (kind, summary, timestamp)
- **Evidence Graph** — observation→finding edge list
- **Observations** — every canonical HTTP exchange with method, URL, status, mode
- **Baselines** — statistical baseline records per URL fingerprint + identity
- **Payload Registry** — registered safe payloads; EXFILTRATION/DESTRUCTIVE highlighted
- **ML Readiness** — current readiness status, blockers, and notes

All target-derived content in the UI is escaped through `HX()`. No raw backend data
is ever assigned to `innerHTML`.

### Security Model
- `verification_status` is always `"unverified"` on creation. Only a researcher
  submitting `action="confirmed"` via `POST /api/findings/{id}/review` can confirm.
- No automated system — not ML probability, not baseline score, not XSS reflection —
  can set `verification_status = "verified"`.
- Workspace IDOR prevention: every parametric route filters by the current workspace.
  A finding ID from another workspace returns 404.

---

## Security Invariants (unchanged from V4, all verified in V5)
- `Evidence` and `ReviewEvent` rows are INSERT-only
- `ModelInference` rows are immutable
- Probe traffic cannot contaminate baselines
- EXFILTRATION and DESTRUCTIVE payloads cannot be registered or dispatched
- No model has been trained; `ml_probability` is NULL
- EvidenceGraph used at runtime for relationship validation (V5-15)

---

## Download

| File | SHA256 |
|------|--------|
| `RAVEN-V5.exe` | `29a0cfe443ea97f6e85c22634b4c94ea996abe66d283a750c6f2d0f32127d338` |
| `RAVEN-V5-windows.zip` | `214ee12ce10916dbf29794610c36e4eece60b1bec6200e63e3a55f7da0c365f9` |
