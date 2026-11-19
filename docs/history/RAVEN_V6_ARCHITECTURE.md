# RAVEN V6 Architecture

## Date: 2026-10-03

---

## Goals

1. **C++ native analysis engine** — optional high-performance compute/analysis acceleration
   for response normalization, diff, hashing, pattern scanning, entropy, feature extraction.
2. **Real ML / neural network platform** — locally trained, researcher-controlled models
   for triage assistance (Task A: ResponseDifference, Task B: AuthorizationSignificance).
3. **Full V5.0.1 backward compatibility** — existing workspaces, DB schema, security invariants.
4. **Preserve security model** — researcher adjudication remains authoritative.

## Non-Goals

- C++ is NOT responsible for networking, scope, authorization, credentials, or policy.
- ML is NOT responsible for vulnerability verification, ground truth, or automatic exploitation.
- V6 is NOT a rewrite — it extends the V5.0.1 architecture.

---

## Architecture Diagram

```
                    RAVEN V6
                      |
              PYTHON CONTROL PLANE
                      |
      +---------------+----------------+
      |               |                |
    Scope          Scheduler       Identity
      |               |                |
      +---------------+----------------+
                      |
                 HTTP Engine
                      |
              CanonicalService
                      |
                  Observation
                      |
        +-------------+-------------+
        |                           |
 PythonAnalysisBackend        NativeAnalysisBackend
  (reference, always)          (optional, C++ bridge)
        |                           |
        +-------------+-------------+
                      |
               ResponseAnalysis
               (semantic authority)
                      |
          +-----------+-----------+
          |                       |
       Baseline                 Evidence
          |                       |
          +-----------+-----------+
                      |
                Candidate Finding
                      |
                Researcher Review
                      |
                  ReviewEvent
                      |
              Human Ground Truth
                      |
              DatasetFoundation
                      |
               Feature Pipeline
                      |
       +--------------+--------------+
       |                             |
 Classical ML                Neural Network
  (scikit-learn)              (PyTorch MLP)
       |                             |
       +--------------+--------------+
                      |
                ModelInference
                (append-only, immutable)
                      |
              Researcher Triage UI
```

---

## Compatibility

- V5.0.1 DB schema is extended, not replaced.
- V5.0.1 EXE artifacts are not modified.
- V6 dev build: `dist/RAVEN-V6-dev.exe` (distinct from V5.0.1).
- V5.0.1 workspaces load in V6 without migration (additive schema changes only).

---

## Security Invariants (all V5 invariants preserved)

1. All target traffic through RAVEN controlled path only.
2. `verification_status` always starts `unverified`; only researcher transition may change it.
3. Evidence is INSERT-only.
4. ReviewEvent is append-only.
5. ModelInference is immutable.
6. `ml_probability` never becomes ground truth.
7. No automatic vulnerability verification.
8. No self-labeling from model predictions.
9. C++ has no target networking capability.
10. ML has no verification_status write path.
11. DLL loading from controlled bundled path only.
12. No shell=True in any subprocess.
13. No credential exposure in native/ML layers.

---

## V6 Components

### Phase A: C++ Native Analysis Engine

| Component | Status |
|-----------|--------|
| `native/` tree (CMake, C++20) | BUILDING |
| Python bridge (`raven/native/`) | BUILDING |
| AnalysisBackend dispatch | BUILDING |
| Response normalization | BUILDING |
| Header diff | BUILDING |
| Body diff (exact + normalized) | BUILDING |
| JSON structural diff | BUILDING |
| SimHash | BUILDING |
| SHA-256 streaming | BUILDING |
| Response fingerprints | BUILDING |
| Aho-Corasick multi-pattern | BUILDING |
| Entropy / binary inspector | BUILDING |
| Feature extraction | BUILDING |
| Decompression guard | BUILDING |

### Phase B: ML Platform

| Component | Status |
|-----------|--------|
| Dataset audit (RAVEN_V6_ML_DATA_AUDIT.md) | BUILDING |
| Feature pipeline | BUILDING |
| Classical baseline (LogisticRegression/RF) | BUILDING |
| PyTorch MLP (Task A + B) | BUILDING |
| Model registry | BUILDING |
| Training CLI (`python -m raven.ml.train`) | BUILDING |
| Evaluation CLI | BUILDING |
| ModelInference integration | BUILDING |
| Model cards | BUILDING |
| UI: ML readiness + signals | PLANNED |

---

## Migration Strategy

V5.0.1 → V6:
- No breaking changes to Python control plane API.
- DB schema: additive columns/tables only (V5 schema version remains readable).
- Native subsystem is optional; RAVEN starts without native binaries.
- ML subsystem is optional; RAVEN operates without trained models.

---

## Build Requirements (V6)

**Python:**
- Python 3.11+ (3.13.14 on dev machine)
- PyTorch (CPU, optional CUDA)
- scikit-learn
- numpy

**C++ (native subsystem, optional to build):**
- CMake 3.20+
- MSVC 2022 / Clang-cl (C++20)
- pybind11 2.12+
- No external networking libraries

**Packaging:**
- Training stack separate from researcher runtime
- Native .pyd packaged separately from PyInstaller EXE (optional dependency)

---

## Documents

| Document | Purpose |
|----------|---------|
| `RAVEN_V6_ARCHITECTURE.md` | This document |
| `RAVEN_V6_NATIVE_FEASIBILITY.md` | Per-component profiling and native opportunity |
| `RAVEN_V6_NATIVE_ARCHITECTURE.md` | C++ native design detail |
| `RAVEN_V6_NATIVE_BENCHMARKS.md` | Measured benchmark results |
| `RAVEN_V6_ML_DATA_AUDIT.md` | Actual labeled data audit |
| `RAVEN_V6_ML_ARCHITECTURE.md` | ML model design |
| `RAVEN_V6_ML_TRAINING_REPORT.md` | Training results |
| `RAVEN_V6_THREAT_MODEL.md` | Updated threat model including C++ hostile input |
| `RAVEN_V6_IMPLEMENTATION_REPORT.md` | Implementation summary |
| `RAVEN_V6_STAGE_LEDGER.md` | Phase-by-phase status |
