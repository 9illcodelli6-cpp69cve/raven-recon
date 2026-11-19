# RAVEN V6 — Threat Model

## System Description

RAVEN is a local-only, researcher-controlled security research assistant.
It runs on a researcher's workstation. No cloud backend. No multi-user tenancy.

## Scope

Bug bounty / authorized security research only.
Program: an authorized bug-bounty engagement
No live target access during engineering runs.

---

## Threat Actors

| Actor | Description | Trust Level |
|-------|-------------|-------------|
| Researcher | Authorized user running RAVEN | TRUSTED — final authority |
| Target Server | Bug bounty target — potentially hostile | UNTRUSTED |
| Third-Party JS/Content | Content from target responses | UNTRUSTED |
| ML Models | RAVEN's own statistical models | ADVISORY — never authoritative |
| Planner/Scheduler | RAVEN's internal proposal engine | CONSTRAINED — policy-bound |

---

## Trust Hierarchy (Section 4 Absolute Authority Rule)

```
1. Researcher                        ← final authority
2. Deterministic Security Policy     ← never overridden
3. Scope / Capability / Budget       ← hard limits
4. Scheduler                         ← execution control
5. Planner                           ← proposes only
6. ML Models                         ← advisory signals
```

A model probability of 1.0 cannot override DENY.

---

## Attack Surface

### Inbound from Target

| Vector | Risk | Mitigation |
|--------|------|-----------|
| HTTP response body | Hostile bytes, large payloads, encoding attacks | Bounded reading; binary = data only |
| HTTP headers | Value injection, newline injection | Header map; no shell interpolation |
| Redirect Location | Open redirect to out-of-scope destination | PolicyGate re-validates every redirect |
| Callback payload | SSRF verification body | Non-executing; SHA-256 + byte count only |
| JSON structure | Deeply nested; recursive | MAX_JSON_DEPTH enforced |
| Compressed response | Compression bomb | Bounded decompression; bomb detection |
| Unicode abuse | Normalization confusion | Bounded; error-replacement encoding |

### Execution Boundary

| Attempt | Verdict | Enforcement |
|---------|---------|-------------|
| Target content → shell command | BLOCKED | No shell=True; no shell metachar |
| Target filename → executable path | BLOCKED | Executable allowlist in registry |
| Target URL → arbitrary socket | BLOCKED | PolicyGate scope check; no raw socket for ML |
| Target content → model weight | BLOCKED | Model paths are RAVEN-controlled only |
| Model score → action execution | BLOCKED | Planner→Policy→Approval chain enforced |
| Downloaded binary → execution | BLOCKED | Download = DATA; no auto-execute |

### Network Exposure

| Surface | Verdict |
|---------|---------|
| Internet-exposed listener | NONE — callback binds 127.0.0.1 only |
| Reverse shell | NOT IMPLEMENTED |
| Bind shell | NOT IMPLEMENTED |
| Arbitrary TCP client (ML/planner) | BLOCKED — ML/planner has no raw socket access |

---

## Security Controls (V6 State)

### Python Policy Gate (Active)

- Default-deny: unknown capability → DENY
- Destructive / Exfiltrative risk class → always DENY
- Sensitive risk class → DENY + require human approval
- Emergency Stop (class-level atomic, irreversible) → DENY all
- Workspace ID binding → cross-workspace requests denied
- Scope enforcement: out-of-scope destinations denied
- Subdomain matching: explicit and bounded

### Rust Trusted Core (RUNTIME_INTEGRATED)

- `#![forbid(unsafe_code)]` on all 5 crates
- Same invariants as Python gate (same semantics)
- When compiled: Python delegates to Rust; Python is not bypassed
- When absent: sensitive action DENIED (fail-closed)
- **RUNTIME_INTEGRATED**: rustc 1.99.0 installed; `raven-bridge.exe` compiled; Python delegates to Rust

### Safe Lab

- LAB_OFF: no controlled HTTP action (default)
- LAB_LOCAL_ONLY: loopback-only fixtures
- LAB_ALLOWLIST: explicit authorized destinations
- All redirects re-validated before follow
- No 0.0.0.0/:: bind

### Process Guard

- Pre-approved executable registry only
- shell=False enforced (no shell=True anywhere in execution path)
- Shell metacharacter pattern check on all args
- Path traversal rejected at register time
- Sensitive env vars stripped from child environment

### Callback Collector

- Binds 127.0.0.1 only
- Payload stored as: SHA-256 + byte_count only
- No body execution, eval, template rendering, or deserialization
- Credential headers stripped before storage

### Filesystem Guard

- `../`, `..\`, absolute escape, UNC, device paths — all rejected
- Target-controlled filenames cannot become trusted executable/model paths

### Model Security

- `torch.load(..., weights_only=True)` — no arbitrary pickle
- SHA-256 verification before inference (artifact_sha256 in model card)
- Feature schema version checked before inference
- InferenceResult: frozen dataclass; is_advisory=True always
- ML score cannot promote finding to VERIFIED
- NaN/Inf features rejected before model input

---

## Non-Threats (Explicitly Out of Scope)

- Multi-user access control (local app, single researcher)
- Network transport encryption between RAVEN components (in-process IPC)
- Remote code execution on researcher machine via RAVEN itself (local app)
- Supply chain attacks via Python stdlib or OS

---

## Known Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|-----------|
| Rust RUNTIME_INTEGRATED | Rust PolicyEngine is active enforcer | Python fail-closed bridge calls raven-bridge.exe |
| REAL_HUMAN_LABEL_COUNT = 0 | No production ML | Models are DEVELOPMENT_ONLY_SYNTHETIC |
| C++ RUNTIME_INTEGRATED | Native analysis engine active | `_raven_native.cp313-win_amd64.pyd` ABI=1; Python AUTO picks native; Python fallback always available |

---

## Security Guarantees (Current)

1. No autonomous destructive exploitation
2. No autonomous exfiltration
3. No reverse/bind shells
4. No target-controlled command execution
5. No model self-promotion or self-labeling
6. No synthetic labels entering real-data metrics
7. No internet-exposed listeners
8. No custom cryptography
9. Emergency Stop is irreversible in production

## Threat Model Version

v1 — 2026-10-03
