# RAVEN — XSS Lab

Context-aware reflection analysis for **authorized** targets. It is a *safe analysis*
tool: it injects a harmless unique canary, finds where it reflects, and classifies the
context and which structural characters survive un-encoded. **It never injects script and
never claims execution.**

## Hard security rules (V4 Phase 3)
- **No script is ever injected.** The probe is `<canary> + <>"'` `` ` `` — a marker plus the
  five structural characters, used only to observe whether the app encodes them. The canary
  is alphanumeric (`rvn` + random hex).
- **Execution is never verified here.** The highest verdict is
  `REFLECTED IN POTENTIALLY UNSAFE CONTEXT`. The previous browser executor is
  **quarantined**: its isolation assumptions were insufficient. API, direct module
  calls and the UI cannot enable it. Cached success cannot override this state.
  RAVEN must **never** render target content in its privileged WebView.
- Runs through the hardened, scope-enforced sender. No WAF/anti-bot evasion.

## Backend — `POST /api/xss-check` (token + Origin gated)
Input: `{ method, url, param, body, cookies?, canary?, confirm_state_changing? }`.
Injection point: a `{XSS}` placeholder in the URL/body, else the named query `param`.
Output: `status`, `content_type`, `evidence_sha256`, `reflections[]`
(`offset`, `context`, `raw_chars`, `unsafe`, `surrounding`), a `verdict`, and canary
`representations` (plain/url/double-url/html-entities/unicode/hex/js-string/json-string).

### Context classification (byte-scan heuristic)
`html-text`, `attribute-double-quoted`, `attribute-single-quoted`, `attribute-unquoted`,
`js` (inside `<script>`), `css`, `comment`, `json`, `unknown`.

### Verdicts
| Condition | Verdict |
|---|---|
| canary not found in the response | NOT REFLECTED |
| reflected, but the context's dangerous chars are all encoded | REFLECTED ENCODED |
| reflected and context-relevant chars survive raw | REFLECTED IN POTENTIALLY UNSAFE CONTEXT |
| (execution) | disabled; never claimed by this build |

## UI
`XSS Lab` view: method + URL (with `{XSS}` support) + param, an Analyze button, and a result
panel showing the verdict, each reflection's context/raw-chars/surrounding bytes, and the
evidence hash. The UI explicitly states that browser execution is disabled.

## Local fixtures & tests (`tests/test_xss_lab.py`, `tests/test_xss_executor.py`)
Synthetic app: `/reflect/html` (raw into element text → unsafe), `/reflect/attr` (raw into a
quoted attribute → unsafe), `/reflect/safe` (HTML-escaped → encoded), `/noreflect`. Tests:
unsafe html-text, unsafe attribute, encoded-when-escaped, not-reflected, **never claims
execution**, **no script injected**, evidence fingerprint present, out-of-scope blocked.

## Remaining work
Keep execution disabled. A future containment design requires separate review;
passing a local browser fixture alone is not proof of network isolation. Improve
analysis explanations and evidence handling without executing target content.
Historical test counts and execution claims in older reports are superseded by
`docs/DEFENSIVE_AUDIT_2026-09-29.md`.
