# RAVEN V6 — Native Analysis Engine Architecture

**Status:** RUNTIME_VALIDATED  
**Date validated:** 2026-10-04  
**Artifact:** `raven/native/_raven_native.cp313-win_amd64.pyd`  
**ABI version:** 1

---

## Role in the Stack

C++ is **analysis acceleration only**. It has no authority over security decisions,
scope, policy, findings, or network access.

```
┌────────────────────────────────────────────────────────┐
│  Researcher  ←  final verification authority           │
├────────────────────────────────────────────────────────┤
│  Python Control Plane  ←  orchestration, API, storage  │
│    raven/api/  raven/store.py  raven/network.py        │
├────────────────────────────────────────────────────────┤
│  Rust Trusted Core  ←  security decision authority     │
│    raven-bridge.exe (IPC)  ←  fail-closed              │
│    raven/rust_bridge.py  ←  Python→Rust bridge         │
├────────────────────────────────────────────────────────┤
│  C++ Native Engine  ←  analysis acceleration (optional)│
│    _raven_native.cp313-win_amd64.pyd                   │
│    raven/native/backend.py  ←  dispatch / fallback     │
├────────────────────────────────────────────────────────┤
│  Python Analysis Fallback  ←  always available         │
│    PythonAnalysisBackend in raven/native/backend.py    │
├────────────────────────────────────────────────────────┤
│  ML Models  ←  advisory signals only (never authoritative)│
│    raven/ml/  (DEVELOPMENT status, synthetic data)     │
└────────────────────────────────────────────────────────┘
```

---

## Compiled .pyd Loading

`raven/native/backend.py` loads the extension at import time via:

```python
importlib.import_module("._raven_native", package="raven.native")
```

The `.pyd` must be adjacent to `raven/native/__init__.py`. It is never loaded
from a target workspace, download directory, or user-controlled path.

On load, ABI version is checked:

```python
SUPPORTED_ABI_VERSIONS = frozenset({1})
if abi not in SUPPORTED_ABI_VERSIONS:
    # reject — _native_load_error set; fallback to Python
```

Any load failure (ImportError, ABI mismatch, runtime error) silently sets
`_native_load_error` and makes `_try_load_native()` return `None`.

---

## Backend Mode Dispatch

```python
class BackendMode(enum.Enum):
    AUTO   = "auto"    # use native if available; else Python
    PYTHON = "python"  # always use Python reference implementation
    NATIVE = "native"  # require native; raise NativeUnavailable if absent
```

`BackendMode.AUTO` is the production default. Python fallback is always available.
C++ failure does NOT cause a security DENY — it causes analysis fallback to Python.
Rust security failure causes DENY (fail-closed, no fallback).

---

## ABI Versioning

- `NATIVE_ABI_VERSION = 1` (constant in compiled binary)
- `SUPPORTED_ABI_VERSIONS = frozenset({1})` (checked in Python on every load)
- A compiled binary with a different ABI version is rejected before any function is called
- ABI mismatch is logged as a warning; Python fallback is used automatically

---

## Fallback Semantics

| Scenario | Outcome |
|----------|---------|
| Native valid, ABI=1 | AUTO uses native |
| Native missing (no .pyd) | AUTO uses Python; NATIVE raises NativeUnavailable |
| Native ABI mismatch | AUTO uses Python (logged warning) |
| Native load error | AUTO uses Python (logged warning) |
| Native runtime exception | Function returns error status dict; no exception propagates to Python caller |
| Rust unavailable | DENY — fail-closed; no fallback |

---

## What Native Can and Cannot Do

### Can do (compute-only)
- SHA-256 hashing
- Body normalization (CRLF, regex replacement, truncation)
- Shannon entropy calculation, printable ratio, magic byte detection
- Header diff (added/removed/changed, no verdict fields)
- Body diff (Levenshtein distance, SimHash)
- JSON structural diff (MAX_JSON_DEPTH=256, MAX_JSON_KEYS enforced)
- Pattern scanning (Aho-Corasick, MAX_PATTERN_COUNT=16384)
- Response fingerprinting (FP_VERSION=1)
- Feature extraction for ML pipeline (19 analysis fields)
- Decompression stub (returns UNSUPPORTED without zlib)

### Cannot do (enforced by design, verified by source audit)
- Network I/O (no socket includes anywhere in native source)
- Process execution (no CreateProcess/system/exec in native source)
- Credential handling (no credential fields; doc comment confirms exclusion)
- Policy decisions (no PolicyDecision/allow/deny calls)
- Finding verification (no verification_status fields)
- Bypass Rust DENY (no rust_bridge reference in native source)

---

## Resource Limits (enforced at API boundary)

| Resource | Limit | Rejection |
|----------|-------|-----------|
| Input body (sha256, inspect_binary, scan) | 10 MB | `status=input_too_large` |
| Pattern count (PatternScanner.build) | 16,384 | returns `None` |
| JSON depth (diff_json) | 256 | `status=malformed` |
| Decompressed output | N/A (zlib absent) | `status=unsupported` |

---

## Component Classifications

| Component | Classification | Justification |
|-----------|---------------|--------------|
| `sha256` | PYTHON_DEFAULT | Native slower than hashlib at ≤1MB (pybind11 overhead) |
| `extract_features` | NATIVE_DEFAULT | 17–38x faster; used via AUTO backend |
| `inspect_binary` | NATIVE_DEFAULT | Called internally by extract_features |
| `diff_headers` | NATIVE_OPTIONAL | Parity confirmed; overhead relevant at high frequency |
| `diff_json` | NATIVE_OPTIONAL | Bounded depth enforced; faster for large JSON |
| `PatternScanner` | NATIVE_OPTIONAL | Aho-Corasick; 16384 pattern limit enforced |
| `simhash` | NATIVE_OPTIONAL | FNV-1a 64-bit, deterministic |
| `normalize_body` | NATIVE_OPTIONAL | Regex/CRLF normalization |
| `compute_fingerprint` | NATIVE_OPTIONAL | FP_VERSION=1 composite hash |
| `decompress_gzip/deflate` | EXPERIMENTAL | Stub only — zlib absent; returns `status=unsupported` |

---

## Compression Status

`compression` capability is `False`. Both `decompress_gzip` and `decompress_deflate`
return `{"status": "unsupported", "ok": False}` at runtime. No live decompression
path exists. Compression bomb protection code exists in `compression.cpp` but is
not exercisable until zlib is installed.

To enable: `vcpkg install zlib` and rebuild. `compression.cpp` uses
`#if __has_include(<zlib.h>)` for auto-detection — no CMakeLists change needed.

---

## Build Parameters (validated 2026-10-04)

| Parameter | Value |
|-----------|-------|
| Compiler | MSVC 19.44.35229 x64 |
| Generator | Visual Studio 17 2022, x64 |
| C++ standard | C++20 (`/std:c++20`) |
| Warning level | /W4 |
| Warnings as errors | /WX |
| Optimization | /O2 /GL (Release) |
| Warning count | 0 |
| Artifact SHA-256 | `79d5c6425aa28c366765e188024974e6deba6f37a9abd95f77b4526bae3d5a2e` |
