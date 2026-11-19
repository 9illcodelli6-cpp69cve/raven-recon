# RAVEN Recon — Threat Model

_Verified against HEAD `d72e362`. Companion to `RAVEN_SECURITY_REVIEW.md`._

## Trust boundaries
1. **WebView / browser UI ↔ local HTTP API** — the UI is trusted (we ship it) but the
   *loopback port is reachable by any local process and by web pages in the user's
   browser*. Loopback binding is **not** authentication.
2. **RAVEN sender ↔ external target** — targets are untrusted and attacker-influenced
   (DNS, redirects, response bodies, headers).
3. **Target response ↔ UI rendering** — probed content must never execute in the
   workbench.
4. **Imported files / external tools ↔ store** — untrusted input must be validated and
   scope-filtered.
5. **Workspace ↔ workspace** — data must not leak across workspaces.

## Assets to protect
Session token; workspace scope integrity; the researcher's machine/network (no SSRF to
internal/metadata); the integrity of stored evidence; the researcher's own credentials
(future Access Control Lab — memory-only).

## Threats and current mitigations
| Threat | Vector | Mitigation | Status |
|---|---|---|---|
| SSRF to internal/metadata/loopback | hostile DNS, alt IP notation, IPv4-mapped IPv6 | resolve+reject non-public, **pin** connect IP, `_is_public` unmaps `::ffff:` | **mitigated + tested** |
| DNS rebinding (target) | TOCTOU between check and connect | single resolve, pinned IP, no re-resolution | **mitigated + tested** |
| DNS rebinding (against the API) | `evil.com`→127.0.0.1, browser hits API | `Host` allow-list on every request incl. the page | **mitigated + tested** |
| CSRF / cross-origin API abuse | malicious page POSTs to API | random token (unreadable cross-origin) + Origin allow-list | **mitigated + tested** |
| Token disclosure to a foreign process | another server squats port 8765 | connect-probe fallback; token only served on RAVEN's bound port | **mitigated + tested** |
| Redirect-based scope bypass | 3xx to out-of-scope/internal | redirects never auto-followed; raw 3xx returned | **mitigated + tested** |
| Env proxy bypass of IP checks | `HTTP_PROXY` | `ProxyHandler({})`; pinned path uses no proxy | **mitigated** |
| Stored XSS from probed content | `<img onerror>` in title/`Server`/URL | `HX()` escaping on every target-controlled sink | **mitigated (manual verify)** |
| Path traversal (static) | `/../..` | resolve + `base in parents` check | **mitigated + tested** |
| Path traversal (workspace name) | name `..` | `_slug` collapses `..`, strips leading dots | **mitigated + tested** |
| SQL injection | stored values | parameterized; identifiers are literals | reviewed OK |
| Command injection | external tools | arg-list (no shell); `root` is a validated hostname | reviewed OK |
| Cross-workspace leak | shared DB | one DB file per workspace | **tested** |
| Malformed/oversized input | huge/garbage bodies | 4 MiB cap, `{}` fallback, method allow-list | **mitigated + tested** |

## Residual risks (not yet mitigated)
- **Untrusted content is not yet rendered in a sandboxed context.** Today the UI only
  displays *escaped text* of target content; the future XSS Lab / preview must use an
  isolated frame with **no** access to `RAVEN_TOKEN` (V4 Phase 3). **Do not** render live
  target HTML/JS in the privileged WebView.
- Frontend XSS invariant is verified manually, not by a headless-JS test (V4 Phase 9).
- crt.sh passive fetch is hardened but not IP-pinned.
- No session expiry/rotation (acceptable for single-user loopback).
- No credential vault yet; when added it must be memory-only by default with redaction.

## Non-goals / explicit prohibitions (per V4)
No anti-bot/WAF evasion; UA profiles are compatibility settings. No credential stuffing,
password guessing, or account/identifier enumeration of third-party resources. No active
state-changing tests without explicit consent. No disabling TLS verification. No
untrusted CA installation.
