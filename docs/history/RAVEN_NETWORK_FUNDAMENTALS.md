# RAVEN Network Fundamentals — Learning Phase

**Status:** COMPLETE  
**Date completed:** 2026-10-04  
**Phase:** Network & Web Fundamentals — before vulnerability classification

---

## Purpose

This phase teaches RAVEN to understand **normal** network and HTTP behavior
before any vulnerability classification. A system that does not understand
what normal looks like cannot reliably identify what abnormal means.

All models in this phase are:
- **ADVISORY ONLY**
- **DEVELOPMENT** status
- Trained on **EDUCATIONAL_SYNTHETIC** data
- **NOT authoritative** for security decisions
- Cannot send requests, execute processes, or modify findings

---

## What Was Built

### Module: `raven/network_fundamentals/`

| File | Purpose |
|------|---------|
| `__init__.py` | Package API — re-exports all taxonomy types |
| `taxonomy.py` | Classification enums and NON_VULNERABILITY_MAPPINGS |
| `observation.py` | NetworkObservation / NetworkResponse — scrubbed data structures |
| `features.py` | NetworkFeatureVector (25 fields) + NetworkFeaturePipeline |
| `lab.py` | LocalNetworkLab — in-process fixture generator (no real HTTP) |
| `dataset.py` | NetworkDataset — builds train/test splits with grouped splitting |
| `train.py` | Training pipeline for NET-A/B/C/D classifiers |

### Module: `raven/knowledge/network_fundamentals.py`

Structured knowledge curriculum covering 18 parts (Parts 1–18): OSI model,
TCP/IP, DNS, TLS, HTTP protocol, HTTP methods, HTTP status codes, HTTP headers,
URL structure, cookies, sessions, auth schemes, API patterns, caching, CORS,
response difference taxonomy, state machines, and normal baselines.

---

## Classification Tasks

### NET-A: Protocol Behavior (9 classes)

Classifies the protocol/application behavior of an HTTP response.
No class implies a vulnerability.

| Class | Description |
|-------|-------------|
| NORMAL_SUCCESS | 2xx with expected content |
| REDIRECT | 3xx redirect |
| CLIENT_ERROR | 4xx excluding 401/403/429 |
| AUTH_REQUIRED | 401 — authentication demanded |
| FORBIDDEN | 403 — authenticated, insufficient authorization |
| RATE_LIMITED | 429 — quota exceeded |
| SERVER_ERROR | 5xx — application/infrastructure error |
| NETWORK_FAILURE | Timeout / DNS / TCP connection error |
| UNKNOWN | Ambiguous — abstain |

### NET-B: Response Difference (8 classes)

Classifies the nature of a difference between two HTTP observations.
Difference ≠ vulnerability.

| Class | Description |
|-------|-------------|
| NO_CHANGE | Identical responses |
| EXPECTED_CHANGE | Predicted by protocol/app semantics |
| STATE_DEPENDENT | Auth/session/locale state difference |
| STRUCTURAL_CHANGE | JSON shape or HTTP structure changed |
| CONTENT_CHANGE | Same structure, different values |
| AUTH_STATE_CHANGE | Authentication state affected response |
| TRANSIENT | Timing/cache/502/retry artifact |
| UNKNOWN | Cannot classify with available evidence |

### NET-C: Session State (6 classes)

Classifies the session/auth state visible in an HTTP exchange.
Session ID ≠ session hijack.

| Class | Description |
|-------|-------------|
| ANONYMOUS | No auth context — normal unauthenticated |
| AUTHENTICATED | User/service session active |
| EXPIRED | Session was valid, now expired |
| INVALID | Malformed or rejected session token |
| ROTATED | Session ID changed (post-login rotation — EXPECTED) |
| UNKNOWN | Cannot determine from available signals |

### NET-D: Authentication Context (5 classes)

Classifies what KIND of authentication is present.
Auth context ≠ authorization verdict.

| Class | Description |
|-------|-------------|
| PUBLIC | No auth required or present |
| APPLICATION_AUTHENTICATED | client_id/client_secret — app identity |
| USER_AUTHENTICATED | Bearer/session — user identity |
| AUTH_REQUIRED | Response demands authentication |
| UNKNOWN | Cannot determine |

---

## Non-Vulnerability Mappings

These explicit mappings prevent false positive escalation:

| Observation | Correct Interpretation |
|-------------|----------------------|
| OPEN_PORT | Metadata only — not a vulnerability |
| HTTP_200 | Normal success — not a vulnerability |
| HTTP_500 | Application error — requires demonstrated impact |
| HTTP_403 | Forbidden by app logic — not proof of bypass |
| RESPONSE_DIFFERENCE | Difference requires context — not a vulnerability |
| SESSION_ID_PRESENT | Anonymous session ID is not session hijack |
| CORS_HEADER_PRESENT | Requires browser semantics — not auto-vuln |
| STRING_REFLECTION | Requires context — not automatically XSS |
| URL_NORMALIZATION_DIFF | Observation — not path traversal |

---

## Feature Vector (NET-V1, 25 fields)

| Field | Description |
|-------|-------------|
| status_code | Raw HTTP status (0 = network failure) |
| status_class | 1–5 (first digit); -1 if unknown |
| is_2xx / is_3xx / is_4xx / is_5xx | Status class flags |
| has_auth_request | Request carried auth header (presence only, never value) |
| has_www_auth | Response has WWW-Authenticate |
| has_set_cookie | Response sets a cookie (presence only, never value) |
| has_location | Response has Location header |
| has_retry_after | Response has Retry-After |
| body_size | Body length in bytes |
| body_entropy | Shannon entropy of body |
| is_json | 1 if body looks like JSON |
| header_count | Response header count |
| has_content_type | Content-Type header present |
| elapsed_ms | Round-trip time |
| timed_out | 1 if request timed out |
| connection_error | 1 if connection-level failure |
| status_changed | 1 if status differs from comparison response |
| body_length_changed | 1 if body length differs from comparison |
| headers_changed | 1 if headers differ from comparison |
| auth_state_changed | 1 if auth state changed between observations |
| path_depth | Number of path segments |
| is_read_method | 1 for GET/HEAD/OPTIONS |

---

## Fixture Lab

`LocalNetworkLab` generates all exchanges in-process — no sockets, no real HTTP.

| Fixture family group | Task focus | Examples |
|---------------------|------------|---------|
| normal_success, authed_success | NET-A | 8 |
| redirect | NET-A | 5 |
| client_error | NET-A | 8 |
| auth_required | NET-A | 4 |
| forbidden | NET-A | 4 |
| rate_limited | NET-A | 4 |
| server_error | NET-A | 5 |
| network_failure | NET-A | 4 |
| no_change, content_change, auth_state_change, structural_change, transient | NET-B | 19 |
| anonymous, authenticated, expired, invalid, rotated | NET-C | 22 |
| public, app_auth, user_auth, auth_required | NET-D | 20 |
| **Total** | | **103** |

Grouped splitting ensures fixture families never span train/test boundaries
(prevents leakage of near-identical requests).

---

## Security Constraints

| Constraint | Enforcement |
|-----------|-------------|
| No real network calls | `lab.py` imports no socket; test verifies source |
| No credential values stored | `_scrub_headers()` replaces values with `<REDACTED>` |
| No is_security_relevant auto-set | `ResponseDifference.from_observations()` always sets False |
| No ML security authority | Models are ADVISORY only; Rust is authoritative |
| No task_a/task_b overwrite | `PROTECTED_TASKS = frozenset({"task_a", "task_b"})` |
| NaN/Inf rejected | `NetworkFeatureVector.validate()` raises on bad values |

---

## Knowledge Curriculum Summary

18 parts covering the full web fundamentals stack:

1. OSI and TCP/IP Layering
2. TCP/IP Fundamentals
3. DNS — Domain Name System
4. TLS — Transport Layer Security (includes: DO NOT DISABLE TLS VALIDATION)
5. HTTP/1.1, HTTP/2, HTTP/3 Protocol Basics
6. HTTP Methods and Semantics
7. HTTP Status Codes
8. HTTP Headers — Request and Response
9. URL Structure and Parsing
10. Cookies — Purpose and Attributes
11. Sessions — State Management Patterns
12. Authentication Schemes
13. REST API Design Patterns
14. HTTP Caching
15. CORS — Cross-Origin Resource Sharing
16. Response Difference Taxonomy
17. HTTP State Machines and Flows
18. Normal Baselines — What Good Looks Like

Each part contains key concepts and explicit non-vulnerability reminders.

---

## STOP Boundary

This phase is complete. The next phase — vulnerability-family classification — must NOT begin until explicitly authorized. Current state:

- Network fundamentals: **COMPLETE**
- Vulnerability-family training: **NOT STARTED**
- Human-reviewed labels: **0**
- Synthetic EDUCATIONAL labels: 103 fixtures
