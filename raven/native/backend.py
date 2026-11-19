"""RAVEN AnalysisBackend dispatch (Phases 50-51).

Single abstraction point for Python vs native C++ analysis.
Native is OPTIONAL — every function falls back to Python gracefully.

BackendMode:
  AUTO   — use native if available and ABI matches; else Python
  PYTHON — force Python reference implementation
  NATIVE — require native; raise NativeUnavailable if absent

Security:
  - Native backend has no networking capability.
  - Security decisions (verification_status, scope, auth) remain in Python.
  - ABI version is checked before any native function is called.
"""
from __future__ import annotations

import enum
import hashlib
import importlib
import importlib.util
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger(__name__)

SUPPORTED_ABI_VERSIONS = frozenset({1})

_native_mod: Any = None
_native_load_error: Optional[str] = None


class NativeUnavailable(RuntimeError):
    """Raised when BackendMode.NATIVE is requested but native library is absent."""


class BackendMode(enum.Enum):
    AUTO   = "auto"
    PYTHON = "python"
    NATIVE = "native"


# ─── Native module loading ────────────────────────────────────────────────────

def _import_native_module() -> Any:
    """Import the compiled ``_raven_native`` extension.

    Tries the normal package-relative import first — this resolves both from the
    source tree and inside a PyInstaller bundle once the ``.pyd`` is collected
    into the frozen ``raven/native/`` directory. If that fails *and* we are
    frozen, fall back to locating the ABI-tagged extension file directly under
    ``sys._MEIPASS`` / next to the executable and loading it by path. We only
    ever search the interpreter's own ``raven.native`` package dir or the frozen
    bundle — never a target workspace / download directory.

    Raises ``ImportError`` if the extension cannot be loaded, so the AUTO path in
    :class:`AnalysisBackend` falls back to the pure-Python backend.
    """
    try:
        return importlib.import_module("._raven_native", package="raven.native")
    except ImportError:
        if not getattr(sys, "frozen", False):
            raise

    import glob

    search_dirs: list[str] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        search_dirs += [os.path.join(meipass, "raven", "native"), meipass]
    exe_dir = os.path.dirname(sys.executable)
    search_dirs += [os.path.join(exe_dir, "raven", "native")]

    for d in search_dirs:
        for pattern in ("_raven_native*.pyd", "_raven_native*.so"):
            for path in sorted(glob.glob(os.path.join(d, pattern))):
                spec = importlib.util.spec_from_file_location(
                    "raven.native._raven_native", path)
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod

    raise ImportError(
        "_raven_native extension not found in frozen bundle "
        f"(searched: {search_dirs})")


def _try_load_native() -> Optional[Any]:
    """Attempt to import _raven_native; return None on any failure."""
    global _native_mod, _native_load_error
    if _native_mod is not None:
        return _native_mod
    if _native_load_error is not None:
        return None

    try:
        # DLL loading: _raven_native.pyd is expected adjacent to this package
        # (source tree) or bundled into raven/native/ in the frozen app.
        # Never load from target workspace/download directories.
        mod = _import_native_module()
        abi = getattr(mod, "NATIVE_ABI_VERSION", None)
        if abi not in SUPPORTED_ABI_VERSIONS:
            _native_load_error = f"unsupported ABI version {abi}"
            log.warning("raven.native: rejected native ABI %s (supported: %s)",
                        abi, SUPPORTED_ABI_VERSIONS)
            return None
        _native_mod = mod
        log.info("raven.native: loaded native backend v%s ABI=%s",
                 mod.NATIVE_VERSION, abi)
        return mod
    except ImportError as exc:
        _native_load_error = str(exc)
        log.debug("raven.native: native backend unavailable (%s)", exc)
        return None
    except Exception as exc:
        _native_load_error = str(exc)
        log.warning("raven.native: native load failed (%s)", exc)
        return None


def get_capabilities() -> dict:
    """Return capability dict (works whether native is available or not)."""
    mod = _try_load_native()
    if mod is not None:
        try:
            caps = mod.get_capabilities()
            caps["backend"] = "native"
            return caps
        except Exception:
            pass
    return {
        "available": False,
        "backend": "python",
        "hashing": True,
        "diff": True,
        "json_diff": True,
        "patterns": True,
        "compression": False,
        "binary_inspection": True,
        "feature_extraction": True,
        "simhash": True,
    }


# ─── Python reference implementations ────────────────────────────────────────

class PythonAnalysisBackend:
    """Pure-Python reference implementation of every analysis function.

    Always available; used as fallback and correctness oracle.
    """

    @staticmethod
    def sha256(data: bytes) -> dict:
        h = hashlib.sha256(data).hexdigest()
        return {"status": "ok", "ok": True, "hex": h}

    @staticmethod
    def normalize_body(body: bytes, content_type: str = "") -> dict:
        from raven.response_analysis import ResponseRepr  # noqa: avoid circular at module-level
        try:
            rr = ResponseRepr.from_raw(200, {}, body)
            return {
                "status": "ok", "ok": True,
                "normalized": rr.normalized_text.encode("utf-8", errors="replace"),
                "digest": rr.normalized_digest,
                "was_truncated": len(body) > 8192,
            }
        except Exception as exc:
            return {"status": "internal_error", "ok": False,
                    "normalized": b"", "digest": "", "was_truncated": False}

    @staticmethod
    def diff_headers(a: dict, b: dict) -> dict:
        added   = sorted(set(b) - set(a))
        removed = sorted(set(a) - set(b))
        changed = []
        for k in sorted(set(a) & set(b)):
            if a[k] != b[k]:
                changed.append({"name": k, "old_value": a[k], "new_value": b[k]})
        return {"status": "ok", "ok": True,
                "added": added, "removed": removed, "changed": changed}

    @staticmethod
    def diff_bodies(a: bytes, b: bytes) -> dict:
        exact   = a == b
        sim     = 1.0 if exact else (
            1.0 - abs(len(a) - len(b)) / max(len(a), len(b), 1))
        return {
            "status": "ok", "ok": True,
            "exact_match": exact,
            "normalized_match": exact,
            "length_delta": len(b) - len(a),
            "similarity": sim,
            "changed_regions": 0 if exact else 1,
            "similarity_approximate": True,
        }

    @staticmethod
    def diff_json(a: bytes, b: bytes) -> dict:
        import json as _json
        try:
            ja = _json.loads(a)
            jb = _json.loads(b)
        except Exception:
            return {"status": "malformed", "ok": False, "are_equal": False,
                    "differences": [], "total_keys_a": 0, "total_keys_b": 0,
                    "truncated": False}

        def _flatten(obj, prefix="$"):
            items = {}
            if isinstance(obj, dict):
                for k, v in obj.items():
                    items.update(_flatten(v, f"{prefix}.{k}"))
                items[prefix + ".__type__"] = "object"
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    items.update(_flatten(v, f"{prefix}[{i}]"))
                items[prefix + ".__type__"] = "array"
            else:
                items[prefix] = obj
            return items

        fa = _flatten(ja)
        fb = _flatten(jb)
        diffs = []
        for k in set(fa) | set(fb):
            if k.endswith(".__type__"): continue
            if k not in fa:
                diffs.append({"path": k, "change": "added",
                              "old_type": "", "new_type": type(fb[k]).__name__})
            elif k not in fb:
                diffs.append({"path": k, "change": "removed",
                              "old_type": type(fa[k]).__name__, "new_type": ""})
            elif fa[k] != fb[k]:
                diffs.append({"path": k, "change": "changed",
                              "old_type": type(fa[k]).__name__,
                              "new_type": type(fb[k]).__name__})

        def _count_keys(obj):
            if isinstance(obj, dict):
                return sum(1 + _count_keys(v) for v in obj.values())
            if isinstance(obj, list):
                return sum(_count_keys(v) for v in obj)
            return 0

        return {
            "status": "ok", "ok": True,
            "are_equal": len(diffs) == 0,
            "differences": diffs,
            "total_keys_a": _count_keys(ja),
            "total_keys_b": _count_keys(jb),
            "truncated": False,
        }

    @staticmethod
    def simhash(data: bytes) -> dict:
        # Simplified 64-bit SimHash via FNV1a shingles
        def fnv1a(b: bytes) -> int:
            h = 14695981039346656037
            for byte in b:
                h ^= byte
                h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
            return h

        if not data:
            return {"status": "ok", "ok": True, "hash": 0}

        v = [0] * 64
        n = 4
        for i in range(0, max(len(data) - n + 1, 1), 2):
            gram = data[i:i + n]
            h = fnv1a(gram)
            for b in range(64):
                v[b] += 1 if (h >> b) & 1 else -1

        fp = sum((1 << b) for b in range(64) if v[b] > 0)
        return {"status": "ok", "ok": True, "hash": fp}

    @staticmethod
    def simhash_similarity(a: int, b: int) -> float:
        diff = a ^ b
        hd = bin(diff).count("1")
        return 1.0 - hd / 64.0

    @staticmethod
    def inspect_binary(data: bytes, content_type: str = "") -> dict:
        import math, string
        if not data:
            return {"status": "ok", "ok": True, "magic_family": "text",
                    "detected_mime": "text", "mime_mismatch": False,
                    "entropy": 0.0, "printable_ratio": 1.0,
                    "size_bytes": 0, "text_like": True, "binary_like": False}

        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        entropy = -sum((f / n) * math.log2(f / n) for f in freq if f > 0)
        printable = sum(1 for b in data
                        if chr(b) in string.printable or b in (9, 10, 13))
        pr = printable / n

        magic = "text"
        d = data[:8]
        if len(d) >= 2 and d[:2] == b'PK': magic = "ZIP"
        elif len(d) >= 4 and d[:4] == b'\x7fELF': magic = "ELF"
        elif len(d) >= 2 and d[:2] == b'MZ': magic = "PE"
        elif len(d) >= 2 and d[:2] == b'\x1f\x8b': magic = "GZIP"
        elif pr < 0.5: magic = "binary"

        return {
            "status": "ok", "ok": True,
            "magic_family": magic, "detected_mime": magic,
            "mime_mismatch": False,
            "entropy": entropy, "printable_ratio": pr,
            "size_bytes": n, "text_like": pr >= 0.85, "binary_like": pr < 0.50,
        }

    @staticmethod
    def extract_features(status: int, headers: dict,
                          body: bytes, elapsed_ms: int = -1) -> dict:
        insp = PythonAnalysisBackend.inspect_binary(body,
                                                     headers.get("content-type", ""))
        ct = headers.get("content-type", "")
        is_json = "application/json" in ct

        json_key_count = 0
        if is_json and body:
            import json as _json
            try:
                obj = _json.loads(body)
                def _ck(o):
                    if isinstance(o, dict):
                        return sum(1 + _ck(v) for v in o.values())
                    if isinstance(o, list):
                        return sum(_ck(v) for v in o)
                    return 0
                json_key_count = _ck(obj)
            except Exception:
                pass

        return {
            "status": "ok", "ok": True,
            "status_code": status,
            "status_class": status // 100,
            "body_size": len(body),
            "body_entropy": insp["entropy"],
            "printable_ratio": insp["printable_ratio"],
            "is_text_like": insp["text_like"],
            "is_json": is_json,
            "header_count": len(headers),
            "has_content_type": "content-type" in headers,
            "has_set_cookie": "set-cookie" in headers,
            "has_location": "location" in headers,
            "elapsed_ms": elapsed_ms,
            "body_similarity": -1.0,
            "simhash_similarity": -1.0,
            "exact_body_match": False,
            "normalized_body_match": False,
            "json_key_count": json_key_count,
            "json_max_depth": 0,
            "length_z_score": 0.0,
        }

    @staticmethod
    def compute_fingerprint(status: int, headers: dict, body: bytes) -> dict:
        body_digest = hashlib.sha256(body).hexdigest()
        ct = headers.get("content-type", "").split(";")[0].strip().lower()
        fp_input = f"v1|{status}|{ct}|{body_digest}"
        fp_id = hashlib.sha256(fp_input.encode()).hexdigest()
        return {
            "status": "ok", "ok": True,
            "fp_version": 1,
            "status_code": status,
            "body_digest": body_digest,
            "content_type": ct,
            "body_size": len(body),
            "fingerprint_id": fp_id,
        }


# ─── NativeAnalysisBackend ────────────────────────────────────────────────────

class NativeAnalysisBackend:
    """Delegates to _raven_native C++ module; raises NativeUnavailable if absent."""

    def __init__(self) -> None:
        mod = _try_load_native()
        if mod is None:
            raise NativeUnavailable(
                _native_load_error or "native library not found")
        self._mod = mod

    def sha256(self, data: bytes) -> dict:
        return self._mod.sha256(data)

    def normalize_body(self, body: bytes, content_type: str = "") -> dict:
        return self._mod.normalize_body(body, content_type)

    def diff_headers(self, a: dict, b: dict) -> dict:
        return self._mod.diff_headers(a, b)

    def diff_bodies(self, a: bytes, b: bytes) -> dict:
        return self._mod.diff_bodies(a, b)

    def diff_json(self, a: bytes, b: bytes) -> dict:
        return self._mod.diff_json(a, b)

    def simhash(self, data: bytes) -> dict:
        return self._mod.simhash(data)

    def simhash_similarity(self, a: int, b: int) -> float:
        return self._mod.simhash_similarity(a, b)

    def inspect_binary(self, data: bytes, content_type: str = "") -> dict:
        return self._mod.inspect_binary(data, content_type)

    def extract_features(self, status: int, headers: dict,
                          body: bytes, elapsed_ms: int = -1) -> dict:
        return self._mod.extract_features(status, headers, body, elapsed_ms)

    def compute_fingerprint(self, status: int, headers: dict, body: bytes) -> dict:
        return self._mod.compute_fingerprint(status, headers, body)


# ─── AnalysisBackend — unified dispatch ──────────────────────────────────────

class AnalysisBackend:
    """Single dispatch interface for analysis functions (Phase 50).

    Always usable. Never requires native.
    """

    def __init__(self, mode: BackendMode = BackendMode.AUTO) -> None:
        self._mode = mode
        self._native: Optional[NativeAnalysisBackend] = None
        self._python = PythonAnalysisBackend()

        if mode == BackendMode.NATIVE:
            self._native = NativeAnalysisBackend()  # raises if unavailable
        elif mode == BackendMode.AUTO:
            try:
                self._native = NativeAnalysisBackend()
            except NativeUnavailable:
                pass

    @property
    def backend_name(self) -> str:
        if self._mode == BackendMode.PYTHON or self._native is None:
            return "python"
        return "native"

    def _be(self):
        if self._native is not None and self._mode != BackendMode.PYTHON:
            return self._native
        return self._python

    def sha256(self, data: bytes) -> dict:              return self._be().sha256(data)
    def normalize_body(self, body, ct=""): return self._be().normalize_body(body, ct)
    def diff_headers(self, a, b):          return self._be().diff_headers(a, b)
    def diff_bodies(self, a, b):           return self._be().diff_bodies(a, b)
    def diff_json(self, a, b):             return self._be().diff_json(a, b)
    def simhash(self, data):               return self._be().simhash(data)
    def simhash_similarity(self, a, b):    return self._be().simhash_similarity(a, b)
    def inspect_binary(self, data, ct=""): return self._be().inspect_binary(data, ct)
    def extract_features(self, s, h, b, e=-1): return self._be().extract_features(s, h, b, e)
    def compute_fingerprint(self, s, h, b): return self._be().compute_fingerprint(s, h, b)


# ─── Module-level singleton ───────────────────────────────────────────────────

_default_backend: Optional[AnalysisBackend] = None


def get_backend(mode: BackendMode = BackendMode.AUTO) -> AnalysisBackend:
    """Return the module-level default backend (auto mode)."""
    global _default_backend
    if _default_backend is None:
        _default_backend = AnalysisBackend(mode)
    return _default_backend
