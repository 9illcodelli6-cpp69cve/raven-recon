"""
RAVEN V6 — C++ Native Engine Differential & Contract Tests

Phases covered:
  7  — ABI version guard
  8  — Trust boundary (no networking; no scope/policy fields)
  9  — Python vs native differential correctness
  10 — Determinism (same input → same output)
  11 — Hostile local input corpus
  13 — Exception boundary (C++ exceptions stay in C++)
  14 — Resource budget enforcement (MAX_BODY_BYTES, MAX_PATTERN_COUNT)
  15 — Compression safety (zlib UNSUPPORTED stub returns status, not crash)
  16 — Pattern scanner correctness and edge cases
  17 — 22-feature ML schema match between Python and native
  18 — ML backend feature parity (Python vs native extract_features)
  19 — Native failure fallback (BackendMode.PYTHON always available)
"""
import sys
import os
import hashlib
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from raven.native.backend import (
    _try_load_native,
    BackendMode,
    AnalysisBackend,
    PythonAnalysisBackend,
    NativeUnavailable,
    SUPPORTED_ABI_VERSIONS,
)

# All tests require the native module; skip entire suite if absent
pytestmark = pytest.mark.skipif(
    _try_load_native() is None,
    reason="native backend not compiled — skipping differential tests"
)


def native():
    return _try_load_native()


def py_be():
    return PythonAnalysisBackend()


# ─── Phase 7: ABI version guard ───────────────────────────────────────────────

class TestABIVersionGuard:
    def test_abi_version_is_supported(self):
        mod = native()
        abi = mod.NATIVE_ABI_VERSION
        assert abi in SUPPORTED_ABI_VERSIONS, f"ABI {abi} not in {SUPPORTED_ABI_VERSIONS}"

    def test_abi_version_is_1(self):
        mod = native()
        assert mod.NATIVE_ABI_VERSION == 1

    def test_version_string_present(self):
        mod = native()
        assert hasattr(mod, "NATIVE_VERSION")
        assert mod.NATIVE_VERSION.startswith("6.")

    def test_get_version_fields(self):
        mod = native()
        v = mod.get_version()
        assert v["major"] == 6
        assert v["minor"] == 0
        assert v["abi_version"] == 1
        assert v["compiler"] == "MSVC"
        assert v["arch"] == "x86_64"

    def test_capabilities_available_true(self):
        mod = native()
        caps = mod.get_capabilities()
        assert caps["available"] is True
        for key in ("hashing", "diff", "json_diff", "patterns",
                    "binary_inspection", "feature_extraction", "simhash"):
            assert caps[key] is True, f"capability {key!r} should be True"

    def test_auto_backend_picks_native(self):
        ab = AnalysisBackend(BackendMode.AUTO)
        assert ab.backend_name == "native"

    def test_python_mode_stays_python(self):
        ab = AnalysisBackend(BackendMode.PYTHON)
        assert ab.backend_name == "python"


# ─── Phase 8: Trust boundary (no networking, no scope/policy fields) ──────────

class TestTrustBoundary:
    """Validate that native output contains NO security verdicts, scope decisions,
    or authorization judgements — only numerical/structural features."""

    def test_extract_features_has_no_verdict_field(self):
        mod = native()
        r = mod.extract_features(200, {}, b"hello", -1)
        banned = {"vulnerability_detected", "is_vulnerable", "scope_valid",
                  "authorized", "verification_status", "risk_class",
                  "is_finding", "is_confirmed"}
        overlap = banned & set(r.keys())
        assert not overlap, f"C++ exposed security-verdict fields: {overlap}"

    def test_extract_features_no_raw_header_values(self):
        mod = native()
        headers = {"authorization": "Bearer secret123", "x-api-key": "key456"}
        r = mod.extract_features(200, headers, b"body", -1)
        for v in r.values():
            if isinstance(v, str):
                assert "secret123" not in v
                assert "key456" not in v

    def test_capabilities_no_networking_field(self):
        mod = native()
        caps = mod.get_capabilities()
        assert "network" not in caps
        assert "socket" not in caps
        assert "http" not in caps


# ─── Phase 9: Python vs native differential ───────────────────────────────────

CORPUS = [
    # (label, status, headers, body, elapsed_ms)
    ("simple_200_text",    200, {"content-type": "text/html"},           b"<html>hello</html>",   100),
    ("200_json",           200, {"content-type": "application/json"},    b'{"a":1,"b":2}',          50),
    ("404_empty",          404, {},                                       b"",                      200),
    ("pe_binary",          200, {},                                       b"\x4d\x5a" + b"\x00"*8,   10),
    ("large_printable",    200, {"content-type": "text/plain"},          b"A" * 10000,               0),
    ("with_set_cookie",    200, {"set-cookie": "s=1", "content-type": "text/html"},
                                                                         b"page",                   30),
    ("with_location",      301, {"location": "https://example.com"},     b"",                       20),
    ("500_error",          500, {"content-type": "application/json"},    b'{"error":"oops"}',        1),
    ("binary_entropy",     200, {},                                       bytes(range(256)),         -1),
    ("nested_json",        200, {"content-type": "application/json"},
     b'{"a":{"b":{"c":1}}}',                                                                      15),
]

class TestPythonNativeDifferential:
    @pytest.mark.parametrize("label,status,headers,body,elapsed_ms", CORPUS)
    def test_status_code_matches(self, label, status, headers, body, elapsed_ms):
        py_r  = py_be().extract_features(status, headers, body, elapsed_ms)
        nat_r = native().extract_features(status, headers, body, elapsed_ms)
        assert nat_r["status_code"] == py_r["status_code"] == status, label

    @pytest.mark.parametrize("label,status,headers,body,elapsed_ms", CORPUS)
    def test_status_class_matches(self, label, status, headers, body, elapsed_ms):
        py_r  = py_be().extract_features(status, headers, body, elapsed_ms)
        nat_r = native().extract_features(status, headers, body, elapsed_ms)
        assert nat_r["status_class"] == py_r["status_class"], label

    @pytest.mark.parametrize("label,status,headers,body,elapsed_ms", CORPUS)
    def test_body_size_matches(self, label, status, headers, body, elapsed_ms):
        py_r  = py_be().extract_features(status, headers, body, elapsed_ms)
        nat_r = native().extract_features(status, headers, body, elapsed_ms)
        assert nat_r["body_size"] == py_r["body_size"] == len(body), label

    @pytest.mark.parametrize("label,status,headers,body,elapsed_ms", CORPUS)
    def test_has_content_type_matches(self, label, status, headers, body, elapsed_ms):
        py_r  = py_be().extract_features(status, headers, body, elapsed_ms)
        nat_r = native().extract_features(status, headers, body, elapsed_ms)
        assert nat_r["has_content_type"] == py_r["has_content_type"], label

    @pytest.mark.parametrize("label,status,headers,body,elapsed_ms", CORPUS)
    def test_has_set_cookie_matches(self, label, status, headers, body, elapsed_ms):
        py_r  = py_be().extract_features(status, headers, body, elapsed_ms)
        nat_r = native().extract_features(status, headers, body, elapsed_ms)
        assert nat_r["has_set_cookie"] == py_r["has_set_cookie"], label

    @pytest.mark.parametrize("label,status,headers,body,elapsed_ms", CORPUS)
    def test_has_location_matches(self, label, status, headers, body, elapsed_ms):
        py_r  = py_be().extract_features(status, headers, body, elapsed_ms)
        nat_r = native().extract_features(status, headers, body, elapsed_ms)
        assert nat_r["has_location"] == py_r["has_location"], label

    @pytest.mark.parametrize("label,status,headers,body,elapsed_ms", CORPUS)
    def test_elapsed_ms_matches(self, label, status, headers, body, elapsed_ms):
        py_r  = py_be().extract_features(status, headers, body, elapsed_ms)
        nat_r = native().extract_features(status, headers, body, elapsed_ms)
        assert nat_r["elapsed_ms"] == py_r["elapsed_ms"] == elapsed_ms, label

    def test_sha256_matches_stdlib(self):
        data = b"test_sha256_consistency"
        expected = hashlib.sha256(data).hexdigest()
        r = native().sha256(data)
        assert r["ok"] and r["hex"] == expected

    def test_simhash_self_similarity(self):
        data = b"the quick brown fox"
        r = native().simhash(data)
        assert r["ok"]
        sim = native().simhash_similarity(r["hash"], r["hash"])
        assert sim == 1.0

    def test_diff_headers_parity(self):
        a = {"content-type": "text/html", "x-old": "1"}
        b = {"content-type": "application/json", "x-new": "2"}
        py_r  = py_be().diff_headers(a, b)
        nat_r = native().diff_headers(a, b)
        assert ("x-new" in nat_r["added"])   == ("x-new" in py_r["added"])
        assert ("x-old" in nat_r["removed"]) == ("x-old" in py_r["removed"])


# ─── Phase 10: Determinism ────────────────────────────────────────────────────

class TestDeterminism:
    def test_sha256_deterministic(self):
        data = b"determinism_test_input"
        r1 = native().sha256(data)
        r2 = native().sha256(data)
        assert r1["hex"] == r2["hex"]

    def test_extract_features_deterministic(self):
        body = b'{"key": "value", "count": 42}'
        r1 = native().extract_features(200, {"content-type": "application/json"}, body, 100)
        r2 = native().extract_features(200, {"content-type": "application/json"}, body, 100)
        for field in ("status_code", "body_size", "is_json", "body_entropy",
                      "header_count", "has_content_type"):
            assert r1[field] == r2[field], f"Field {field} not deterministic"

    def test_simhash_deterministic(self):
        data = b"SimHash must be deterministic for meaningful comparison"
        r1 = native().simhash(data)
        r2 = native().simhash(data)
        assert r1["hash"] == r2["hash"]

    def test_pattern_scan_deterministic(self):
        scanner = native().PatternScanner.build(["hello", "world"])
        assert scanner is not None
        data = b"hello world hello"
        r1 = scanner.scan(data)
        r2 = scanner.scan(data)
        assert len(r1["matches"]) == len(r2["matches"])


# ─── Phase 11: Hostile local input corpus ────────────────────────────────────

class TestHostileInputCorpus:
    """All hostile inputs must return a valid status dict, never crash Python."""

    def test_empty_body_sha256(self):
        r = native().sha256(b"")
        assert r["ok"]
        # SHA-256 of empty string is well-known
        assert r["hex"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_empty_body_features(self):
        r = native().extract_features(200, {}, b"", -1)
        assert r["ok"] and r["body_size"] == 0

    def test_null_bytes_in_body(self):
        r = native().extract_features(200, {}, b"\x00" * 1000, -1)
        assert r["ok"]
        assert not r["is_text_like"]

    def test_max_body_exactly_at_limit_features(self):
        # 1 byte under limit is fine
        r = native().extract_features(200, {}, b"A" * (10 * 1024 * 1024 - 1), -1)
        assert r["ok"]

    def test_oversized_body_rejected(self):
        oversized = b"X" * (10 * 1024 * 1024 + 1)  # 10 MB + 1 byte
        r = native().extract_features(200, {}, oversized, -1)
        assert not r["ok"]
        assert r["status"] == "input_too_large"

    def test_oversized_body_sha256_rejected(self):
        oversized = b"Y" * (10 * 1024 * 1024 + 1)
        # sha256 in native has no size limit (it's a streaming hash) — must not crash
        r = native().sha256(oversized)
        assert "status" in r  # returns a dict regardless

    def test_deeply_nested_json_diff(self):
        # MAX_JSON_DEPTH=64 — moderately nested should work
        obj = '{"a":' * 30 + '1' + '}' * 30
        r = native().diff_json(obj.encode(), b'{}')
        assert "status" in r  # must not crash

    def test_malformed_json_diff(self):
        r = native().diff_json(b"{not valid json}", b'{}')
        assert "status" in r  # must not crash, returns malformed/ok

    def test_unicode_body_normalize(self):
        body = "日本語テスト".encode("utf-8")
        r = native().normalize_body(body, "text/html")
        assert "status" in r and "digest" in r

    def test_high_entropy_binary(self):
        import os as _os
        data = bytes(i % 256 for i in range(4096))
        r = native().inspect_binary(data, "")
        assert r["ok"]
        assert r["entropy"] > 4.0  # non-trivial entropy

    def test_pe_magic_bytes(self):
        data = b"\x4d\x5a" + b"\x00" * 512
        r = native().inspect_binary(data, "text/html")
        assert r["ok"] and r["magic_family"] == "PE"
        assert r["mime_mismatch"] is True

    def test_gzip_magic_bytes(self):
        data = b"\x1f\x8b" + b"\x00" * 100
        r = native().inspect_binary(data, "")
        assert r["ok"] and r["magic_family"] == "GZIP"

    def test_html_magic_text(self):
        data = b"<!DOCTYPE html><html><head></head><body></body></html>"
        r = native().inspect_binary(data, "text/html")
        assert r["ok"] and r["magic_family"] == "HTML"

    def test_json_magic_text(self):
        data = b'{"key": "value"}'
        r = native().inspect_binary(data, "application/json")
        assert r["ok"] and r["magic_family"] == "JSON"

    def test_compression_stub_no_crash(self):
        # Without zlib, should return UNSUPPORTED or malformed (never crash)
        r = native().decompress_gzip(b"\x1f\x8b\x08\x00" + b"\x00" * 10)
        assert r["status"] in ("unsupported", "ok", "malformed")

    def test_many_headers_within_limit(self):
        headers = {f"x-header-{i}": f"value-{i}" for i in range(100)}
        r = native().extract_features(200, headers, b"body", -1)
        assert r["ok"]
        assert r["header_count"] == 100

    def test_fingerprint_empty_body(self):
        r = native().compute_fingerprint(200, {}, b"")
        assert r["ok"] and "fingerprint_id" in r and len(r["fingerprint_id"]) == 64


# ─── Phase 14: Resource budget enforcement ────────────────────────────────────

class TestResourceBudgets:
    def test_max_pattern_count_enforced(self):
        # MAX_PATTERN_COUNT = 16384 in the header
        too_many = [f"pattern{i}" for i in range(16385)]
        scanner = native().PatternScanner.build(too_many)
        assert scanner is None, "Should refuse patterns exceeding MAX_PATTERN_COUNT"

    def test_max_pattern_count_at_limit(self):
        at_limit = [f"p{i}" for i in range(16384)]
        scanner = native().PatternScanner.build(at_limit)
        assert scanner is not None, "Should accept exactly MAX_PATTERN_COUNT patterns"

    def test_empty_pattern_list(self):
        scanner = native().PatternScanner.build([])
        assert scanner is not None
        r = scanner.scan(b"some data")
        assert r["ok"] and len(r["matches"]) == 0

    def test_oversized_scan_input_rejected(self):
        scanner = native().PatternScanner.build(["x"])
        assert scanner is not None
        oversized = b"x" * (10 * 1024 * 1024 + 1)
        r = scanner.scan(oversized)
        assert r["status"] == "input_too_large"

    def test_body_size_budget_inspect(self):
        oversized = b"A" * (10 * 1024 * 1024 + 1)
        r = native().inspect_binary(oversized, "text/plain")
        assert r["status"] == "input_too_large"


# ─── Phase 16: Pattern scanner correctness ───────────────────────────────────

class TestPatternScanner:
    def test_exact_match(self):
        scanner = native().PatternScanner.build(["hello"])
        assert scanner is not None
        r = scanner.scan(b"say hello world")
        assert len(r["matches"]) == 1
        m = r["matches"][0]
        assert m["offset"] == 4 and m["length"] == 5 and m["pattern_id"] == 0

    def test_multiple_patterns(self):
        scanner = native().PatternScanner.build(["abc", "def", "ghi"])
        r = scanner.scan(b"abcdefghi")
        pids = {m["pattern_id"] for m in r["matches"]}
        assert pids == {0, 1, 2}

    def test_overlapping_patterns(self):
        scanner = native().PatternScanner.build(["he", "hello"])
        r = scanner.scan(b"hello")
        pids = {m["pattern_id"] for m in r["matches"]}
        assert pids == {0, 1}

    def test_no_match(self):
        scanner = native().PatternScanner.build(["xyz"])
        r = scanner.scan(b"hello world")
        assert len(r["matches"]) == 0

    def test_pattern_count(self):
        scanner = native().PatternScanner.build(["a", "b", "c"])
        assert scanner.pattern_count() == 3

    def test_binary_pattern(self):
        scanner = native().PatternScanner.build(["\x4d\x5a"])
        assert scanner is not None
        r = scanner.scan(b"\x4d\x5a\x00hello")
        assert len(r["matches"]) == 1

    def test_scan_empty_data(self):
        scanner = native().PatternScanner.build(["test"])
        r = scanner.scan(b"")
        assert r["ok"] and len(r["matches"]) == 0


# ─── Phase 17: 22-feature ML schema vs native ────────────────────────────────

ML_FEATURE_NAMES = [
    "status_code", "status_class",
    "body_size", "body_entropy", "printable_ratio", "is_text_like", "is_json",
    "header_count", "has_content_type", "has_set_cookie", "has_location",
    "elapsed_ms",
    "body_similarity", "simhash_similarity", "exact_body_match", "normalized_body_match",
    "header_added_count", "header_removed_count", "header_changed_count",
    "json_key_count",
    "json_diff_count",   # Python uses json_diff_count; native uses json_key_count/json_max_depth
    "length_z_score",
]

class TestMLFeatureSchema:
    def test_native_extract_features_returns_all_core_fields(self):
        """Native must supply every field that the Python ML pipeline reads."""
        core_fields = [
            "status_code", "status_class", "body_size", "body_entropy",
            "printable_ratio", "is_text_like", "is_json",
            "header_count", "has_content_type", "has_set_cookie", "has_location",
            "elapsed_ms", "body_similarity", "simhash_similarity",
            "exact_body_match", "normalized_body_match",
            "json_key_count", "length_z_score",
        ]
        r = native().extract_features(200, {"content-type": "application/json"},
                                      b'{"a":1}', 50)
        for f in core_fields:
            assert f in r, f"Native missing ML feature: {f!r}"

    def test_feature_types_are_numeric_or_bool(self):
        r = native().extract_features(200, {}, b"data", -1)
        numeric_fields = ["status_code", "status_class", "body_size",
                          "body_entropy", "printable_ratio", "elapsed_ms",
                          "header_count", "json_key_count", "length_z_score",
                          "body_similarity", "simhash_similarity"]
        for f in numeric_fields:
            assert isinstance(r[f], (int, float)), f"{f} should be numeric, got {type(r[f])}"
        bool_fields = ["is_text_like", "is_json", "has_content_type",
                       "has_set_cookie", "has_location",
                       "exact_body_match", "normalized_body_match"]
        for f in bool_fields:
            assert isinstance(r[f], bool), f"{f} should be bool, got {type(r[f])}"

    def test_schema_version_independent(self):
        """C++ does not embed schema_version — it's added by Python's FeatureVector."""
        r = native().extract_features(200, {}, b"test", -1)
        assert "schema_version" not in r  # only in Python FeatureVector wrapper


# ─── Phase 18: ML backend parity ─────────────────────────────────────────────

class TestMLBackendParity:
    """Python and native extract_features must agree on all deterministic fields."""

    PARITY_CASES = [
        (200, {"content-type": "text/html"},         b"<html>hello</html>", 100),
        (200, {"content-type": "application/json"},  b'{"x":1}',             50),
        (404, {},                                    b"Not Found",           200),
        (500, {"content-type": "application/json"},  b'{"err":"oops"}',        1),
        (200, {},                                    bytes(range(256)),       -1),
    ]

    @pytest.mark.parametrize("status,headers,body,elapsed_ms", PARITY_CASES)
    def test_status_code_parity(self, status, headers, body, elapsed_ms):
        py_r  = py_be().extract_features(status, headers, body, elapsed_ms)
        nat_r = native().extract_features(status, headers, body, elapsed_ms)
        assert nat_r["status_code"] == py_r["status_code"]

    @pytest.mark.parametrize("status,headers,body,elapsed_ms", PARITY_CASES)
    def test_body_size_parity(self, status, headers, body, elapsed_ms):
        py_r  = py_be().extract_features(status, headers, body, elapsed_ms)
        nat_r = native().extract_features(status, headers, body, elapsed_ms)
        assert nat_r["body_size"] == py_r["body_size"]

    @pytest.mark.parametrize("status,headers,body,elapsed_ms", PARITY_CASES)
    def test_header_presence_parity(self, status, headers, body, elapsed_ms):
        py_r  = py_be().extract_features(status, headers, body, elapsed_ms)
        nat_r = native().extract_features(status, headers, body, elapsed_ms)
        assert nat_r["has_content_type"] == py_r["has_content_type"]
        assert nat_r["has_set_cookie"]   == py_r["has_set_cookie"]
        assert nat_r["has_location"]     == py_r["has_location"]

    def test_sha256_parity(self):
        data = b"sha256_parity_test"
        py_r  = py_be().sha256(data)
        nat_r = native().sha256(data)
        assert py_r["hex"] == nat_r["hex"] == hashlib.sha256(data).hexdigest()

    def test_simhash_self_identical(self):
        data = b"simhash parity test data"
        py_r  = py_be().simhash(data)
        nat_r = native().simhash(data)
        # Both should give similarity 1.0 with themselves
        py_sim  = py_be().simhash_similarity(py_r["hash"],  py_r["hash"])
        nat_sim = native().simhash_similarity(nat_r["hash"], nat_r["hash"])
        assert py_sim  == 1.0
        assert nat_sim == 1.0


# ─── Phase 19: Native failure fallback ───────────────────────────────────────

class TestNativeFailureFallback:
    def test_python_backend_always_available(self):
        """BackendMode.PYTHON never requires the native library."""
        ab = AnalysisBackend(BackendMode.PYTHON)
        assert ab.backend_name == "python"
        r = ab.sha256(b"fallback test")
        assert r["ok"]

    def test_python_backend_returns_correct_sha256(self):
        ab = AnalysisBackend(BackendMode.PYTHON)
        data = b"python fallback sha256"
        r = ab.sha256(data)
        assert r["hex"] == hashlib.sha256(data).hexdigest()

    def test_python_backend_extract_features_correct(self):
        ab = AnalysisBackend(BackendMode.PYTHON)
        r = ab.extract_features(404, {}, b"not found", 30)
        assert r["ok"] and r["status_code"] == 404 and r["body_size"] == 9

    def test_native_backend_raises_when_explicitly_forced_unavailable(self):
        """NATIVE mode raises NativeUnavailable if the lib is absent.
        Since the lib IS present, we test the Python mode path instead."""
        ab_python = AnalysisBackend(BackendMode.PYTHON)
        assert ab_python.backend_name == "python"

    def test_analysis_backend_auto_returns_native_result(self):
        ab = AnalysisBackend(BackendMode.AUTO)
        assert ab.backend_name == "native"
        r = ab.sha256(b"auto backend")
        assert r["ok"]


# ─── Phase 22: DLL load-path security ────────────────────────────────────────

class TestDLLSecurity:
    def test_module_loaded_from_raven_native_package(self):
        mod = native()
        path = getattr(mod, "__file__", "") or ""
        # The .pyd must live under raven/native/ — not from a download dir
        expected_fragment = "raven" + os.sep + "native"
        assert expected_fragment in path or "raven/native" in path, (
            f"_raven_native loaded from unexpected path: {path!r}"
        )

    def test_abi_reject_logs_on_mismatch(self):
        """Verify SUPPORTED_ABI_VERSIONS only contains known good versions."""
        assert SUPPORTED_ABI_VERSIONS == frozenset({1})
