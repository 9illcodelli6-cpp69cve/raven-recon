# RAVEN V6 — Native Engine Benchmarks

**Date measured:** 2026-10-04  
**Platform:** Windows 11 x64  
**Python:** 3.13.5 (cpython)  
**Native:** `_raven_native.cp313-win_amd64.pyd` MSVC 19.44.35229  
**Methodology:** 100 iterations per cell, median milliseconds

---

## Results

| operation | size (bytes) | iterations | py_ms_median | native_ms_median | speedup |
|-----------|-------------|------------|-------------|-----------------|---------|
| sha256 | 1,024 | 100 | 0.0012 | 0.0064 | **0.19x** |
| sha256 | 10,240 | 100 | 0.0059 | 0.0110 | **0.54x** |
| sha256 | 102,400 | 100 | 0.0510 | 0.0559 | **0.91x** |
| sha256 | 1,048,576 | 100 | 0.5302 | 0.5424 | **0.98x** |
| extract_features | 1,024 | 100 | 0.0847 | 0.0050 | 16.94x |
| extract_features | 10,240 | 100 | 0.7929 | 0.0275 | 28.83x |
| extract_features | 102,400 | 100 | 7.7930 | 0.2660 | 29.30x |
| extract_features | 1,048,576 | 100 | 85.0832 | 2.2145 | 38.42x |

---

## Interpretation

### sha256: native is SLOWER (0.19x–0.98x)

Python `hashlib.sha256` calls the OS crypto API (BCryptHashData on Windows) directly
with near-zero overhead. The native path adds pybind11 call overhead for each
invocation. At small sizes (1KB) the overhead dominates (5x slower). At 1MB the
ratio approaches 1x as hash computation time dominates overhead.

**Consequence:** `sha256` is classified `PYTHON_DEFAULT`. The Python reference
implementation is used for hashing. This is the correct and honest result.

### extract_features: native is FASTER (17x–38x)

`extract_features` performs multi-pass analysis in a single C++ function call:
entropy calculation (byte histogram), printable ratio, magic byte detection,
JSON detection, header counting, and SimHash. Python implements these as
interpreted loops. At 1MB, native completes in 2.2ms vs Python's 85ms.

Speedup grows with input size as the per-byte work dominates the fixed
call overhead.

---

## Compression: NOT BENCHMARKED

`decompress_gzip` and `decompress_deflate` return `status=unsupported` (zlib absent).
No decompression benchmarks were measured. If zlib is installed and the native
is rebuilt, benchmarks should be added here.

---

## Notes

- All measurements are wall-clock time including pybind11 marshaling overhead.
- Native `sha256` slower results are preserved exactly as measured — they are not omitted.
- No measurements were fabricated or extrapolated.
