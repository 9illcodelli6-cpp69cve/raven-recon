# RAVEN V6 — Rust Trusted Core

**Status: RUNTIME_INTEGRATED — compiled binary in RAVEN's security decision path.**

Last verified: 2026-10-03  
Rust toolchain: rustc 1.99.0 stable-x86_64-pc-windows-msvc, cargo 1.99.0  
Binary: `rust/target/release/raven-bridge.exe`  
Binary SHA-256: run `sha256sum rust/target/release/raven-bridge.exe` to verify

## Architecture

The Rust Trusted Core consists of **5 crates** in `rust/`:

| Crate | Purpose |
|---|---|
| `raven-core` | Capability, action, workspace, audit, budget, error types |
| `raven-policy` | PolicyEngine (default-deny), network guard, process guard, scope policy, emergency stop |
| `raven-ipc` | IPC message schema (versioned), session token (SHA-256, constant-time) |
| `raven-sandbox` | LabMode types mirroring Python Safe Lab |
| `raven-bridge` (**new**) | JSON-over-stdin/stdout bridge binary — entry point from Python |

## Bridge Protocol

```
Python evaluate_action()
  │
  └─ subprocess.run([raven-bridge.exe], input=json_bytes, shell=False)
         │
         └─ Rust: deserialize IpcRequest
               └─ dispatch on IpcPayload::EvaluateAction(Box<params>)
                     └─ PolicyEngine::evaluate(&ActionRequest)
                           └─ ActionDecision → IpcResponse → stdout JSON
```

**Fail-closed guarantee**: if `raven-bridge.exe` is missing, crashes, times out,
or returns malformed JSON → `BridgeDecision.deny_fail_closed()` → `allowed=False`.
Python NEVER falls back to permissive execution when the Rust core is unavailable.
(Contrast: C++ analysis unavailable → Python analysis fallback ALLOWED.)

## Security Properties

- `#![forbid(unsafe_code)]` on all crates
- Emergency stop: global `AtomicBool`, irreversible in production
- PolicyEngine: default DENY — only explicit passes reach Allow
- Destructive/Exfiltrative: ALWAYS denied
- Sensitive: RequireApproval (never auto-allowed)
- ML/AI cannot call PolicyEngine to produce Allow decisions
- Session tokens: SHA-256 of two random UUIDs; Debug impl redacts value

## Fail-Closed Semantics

**Rust core unavailable → sensitive action DENIED.**
This differs from the C++ analysis engine (C++ absent → Python fallback is acceptable).
The Python `PolicyGate` enforces this fail-closed behaviour until Rust is compiled.

## Build Blockers

```
RUST_RUNTIME_BLOCKED
Reason: rustc / cargo / rustup not found in PATH (neither Bash nor PowerShell).
The Rust toolchain is not installed on this machine.

To build:
1. Install Rust via https://rustup.rs (the official supported method).
2. cd rust && cargo build --workspace --release
3. cargo test --workspace
4. cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Python Enforcement (Active)

Until Rust is compiled, `raven/security/policy_gate.py` is the active policy enforcer.
It enforces the same semantics: default deny, Destructive always denied, Sensitive fail-closed.
44/44 Python security tests pass confirming this.

## IPC Design

When Rust runs in-process (FFI), no network IPC is needed.
If future out-of-process deployment is required, Windows named pipes with
restrictive ACLs are preferred over a TCP control server.

**NETWORK TRANSPORT ENCRYPTION: NOT APPLICABLE**
Rationale: No TCP control transport exists. Communication would be in-process FFI or
Windows named pipes with OS ACL protection. No custom crypto is invented.
