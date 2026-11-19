# RAVEN — Test Results

Exact commands and outcomes. Environment: Windows 11, Python **3.13.14**, repo HEAD `e6a267a`.
All tests use loopback servers/mocks; **no external targets**.

## Command
```
python -m unittest tests.test_api_security tests.test_reliability tests.test_access_control
```
## Outcome
```
Ran 47 tests in ~6.6s
OK   (0 failures, 0 errors)
```

## Breakdown
| Suite | Count | Covers |
|---|---|---|
| `tests/test_api_security.py` | 20 | SSRF/DNS-rebind (loopback, metadata, IPv4-mapped, mixed), IP pinning to a live local server, TLS-context verification, no-redirect, out-of-scope block, token auth (present/absent/valid), scope-change auth, cross-origin reject, Host allow-list, malformed JSON no-500, static path-traversal, token inlined + still required |
| `tests/test_reliability.py` | 7 | slug traversal invariant, legit-name preservation, workspace isolation, hostile/out-of-scope import, port-fallback on occupied port, **no foreign-process attachment / no token leak**, Origin bound to actual port, clean shutdown+restart |
| `tests/test_access_control.py` | 7 | identity separation, IDOR→INCONSISTENT (never "confirmed"), secure→EXPECTED, anonymous baseline, state-change consent required, out-of-scope blocked, credentials not echoed |

## RC smoke test (frozen `dist/RAVEN.exe`)
```
health=200  /api/summary(no token)=403  /api/access-check(no token)=403
Host: evil.example =403   page contains ACCESS CONTROL LAB, RAVEN_TOKEN
```
Security controls and the new endpoint survive PyInstaller freezing.

## NOT TESTED (explicit)
- Legacy engine tests (`test_engine`, `test_network`, `test_tui`, `test_core`) — require
  `aiohttp`/`textual` which are **not installed** here.
- Clean/second Windows host EXE run (WebView2 present, no dev tools) — verified only on the
  build machine.
- Headless-JS test of the XSS-escaping invariant — currently verified **manually** in-browser.
- `pip-audit` / linter / property-based fuzz — not available in this environment.

## Notes on integrity
No assertion was weakened to obtain a pass. Two earlier issues the owner flagged were fixed at
the **root cause**: the `_slug` behaviour (code now collapses `..`; test asserts the invariant)
and the port-fallback (connect-probe defeats Windows `SO_REUSEADDR` false-negatives).

---

## Update — V4 session (HEAD e6a267a)
```
python -m unittest tests.test_api_security tests.test_reliability tests.test_access_control tests.test_xss_lab
Ran 47 tests — OK (0 failures)
```
New suites: `tests/test_access_control.py` (12: identity separation, IDOR→INCONSISTENT,
secure→EXPECTED, public-resource FP filter with anon baseline, expected-access matrix,
session-expiry→INCONCLUSIVE, out-of-scope block, credential redaction, norm not leaked);
`tests/test_xss_lab.py` (8: unsafe html-text, unsafe attribute, encoded-when-escaped,
not-reflected, never-claims-execution, no-script-injected, evidence fingerprint, out-of-scope).

**Dependency audit (pip-audit):** RAVEN's own dependencies are clean. The only advisory is for
`pip` itself (26.1.2 → 26.2, PYSEC-2026-3721) — a build tool, **not** a RAVEN runtime
dependency. Recommend `python -m pip install --upgrade pip` on the build machine.

**RC smoke test (frozen `dist/RAVEN.exe`, SHA 60829597…):** health=200, `/api/access-check`
and `/api/xss-check` =403 without token, bad-Host=403, both labs present in the page.
