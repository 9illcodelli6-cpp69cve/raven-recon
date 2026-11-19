# RAVEN V6 — Safe Lab

**Default mode: LAB_OFF — no outbound connections**

## Modes

| Mode | Permitted connections |
|---|---|
| LAB_OFF (default) | None |
| LAB_LOCAL_ONLY | http://127.0.0.1, http://localhost, http://[::1] only |
| LAB_ALLOWLIST | Explicit URL prefix allowlist only |

## Bind Address Policy

RAVEN services bind ONLY to `127.0.0.1` or `::1`.
`0.0.0.0` and `::` are FORBIDDEN — `check_bind_address()` raises `ValueError`.

## Budget Defaults

| Limit | Default | Hard cap |
|---|---|---|
| Timeout | 10s | 120s |
| Response bytes | 1 MB | 100 MB |
| Redirects | 3 | 20 |
| Requests | 10 | 1,000 |
| Decompressed | 50 MB | 200 MB |

## Callback Collector

- Binds only to 127.0.0.1
- Raw payload never executed — stored as byte count + SHA-256 only
- Credential headers (`Authorization`, `Cookie`, `X-API-Key`, etc.) stripped before storage
- Max 64 KB per callback, max 1,000 records

## Key Files

- `raven/security/safe_lab.py` — Python enforcement
- `raven/security/callback_collector.py` — non-executing collector
- `rust/raven-sandbox/src/lib.rs` — Rust LabMode types (source-complete)
