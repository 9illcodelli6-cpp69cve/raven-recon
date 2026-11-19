# RAVEN — Access Control Lab

A first-class dual-session authorization-testing tool. Compare one request under several
**researcher-owned** identities and get a conservative, evidence-oriented verdict.

## Safety model (non-negotiable)
- Runs through the **single hardened sender** (`do_send`): scope-checked at request time,
  IP-pinned (no SSRF/rebinding), TLS verified, no auto-redirects.
- **Owned resources & authorized accounts only.** RAVEN never generates or guesses
  third-party identifiers/credentials.
- **Strict identity separation** — each request is built fresh from one identity; session A's
  cookies/headers never enter session B's request (regression-tested).
- **Consent gate** — state-changing methods (POST/PUT/PATCH/DELETE) are refused unless the
  researcher ticks the ownership/authorization checkbox. Default off.
- **Credential redaction** — cookies/authorization values are memory-only for the request and
  are **never stored or echoed**; the UI shows `Cookie: <redacted N chars>` (tested).
- **No confirmed verdicts** — outcomes are review candidates only.

## Backend — `POST /api/access-check` (token + Origin gated)
Request:
```json
{ "method":"GET", "url":"https://target.example/api/orders/123",
  "sessions":[{"label":"owner","cookies":"session=…","headers":{}},
              {"label":"other","cookies":"session=…"}],
  "body":"", "confirm_state_changing": false }
```
Response: per-session `{label,status,bytes,content_type,body_sha256,snippet,credential_preview}`
plus `comparisons[]` with a verdict for each non-owner identity vs the owner.

### Classification (owner = first session)
| Condition | Verdict |
|---|---|
| owner or other request did not complete | INCONCLUSIVE |
| owner did not get 2xx on its own resource | INCONCLUSIVE |
| other got 401/403 | EXPECTED (properly denied) |
| other got a different status | EXPECTED (different handling) |
| other got same status **and identical body hash** | **INCONSISTENT** (review candidate) |
| same status, different body | INCONCLUSIVE (manual review) |

INCONSISTENT means "another identity received the same resource as the owner" — a *candidate*
for IDOR/BOLA/BFLA, **not** a confirmation. The researcher reproduces and confirms ownership.

## UI
`Access Control` view: method + resource URL, Session A (owner) and Session B (other/anonymous)
panels with masked cookie fields, an ownership/authorization consent checkbox, a **Compare**
button, and an A/B result panel with color-coded verdicts.

## Local test fixtures (`tests/test_access_control.py`)
A synthetic app with `/vuln/1` (IDOR: returns owner's resource to any identity) and `/secure/1`
(owner-only). Tests: identity separation, IDOR→INCONSISTENT, secure→EXPECTED, anonymous
baseline→EXPECTED, state-change consent required, out-of-scope blocked, credentials not echoed.
**7/7 passing.**

## Not yet implemented (roadmap)
Scenario/template library (BOLA/BFLA/RBAC/tenant/GraphQL…), import/export of owned test cases,
structured JSON-path semantic diff, preflight expected-vs-actual matrix, send-to-Repeater /
Investigation Studio, exportable review report. See `RAVEN_NEXT_STEPS.md`.
