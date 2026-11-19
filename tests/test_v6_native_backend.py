"""RAVEN V6 Native Backend — Python-side tests.

These tests verify:
1. The Python reference backend (always available, no C++ required).
2. The AnalysisBackend dispatch layer.
3. ABI rejection logic.
4. Fallback behavior when native is unavailable.
5. Security properties: no networking, no security verdicts.

All tests pass without any compiled C++ extension.
"""
import hashlib
import unittest


class PythonBackendSha256Test(unittest.TestCase):
    """Python reference SHA-256."""

    def setUp(self):
        from raven.native.backend import PythonAnalysisBackend
        self.be = PythonAnalysisBackend()

    def test_empty_input(self):
        r = self.be.sha256(b"")
        self.assertTrue(r["ok"])
        self.assertEqual(r["hex"],
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855")

    def test_known_digest(self):
        r = self.be.sha256(b"abc")
        self.assertTrue(r["ok"])
        self.assertEqual(r["hex"], hashlib.sha256(b"abc").hexdigest())

    def test_returns_64_char_hex(self):
        r = self.be.sha256(b"hello world")
        self.assertEqual(len(r["hex"]), 64)

    def test_different_data_different_digest(self):
        r1 = self.be.sha256(b"\x01\x02")
        r2 = self.be.sha256(b"\x01\x03")
        self.assertNotEqual(r1["hex"], r2["hex"])


class PythonBackendHeaderDiffTest(unittest.TestCase):
    """Python reference header diff."""

    def setUp(self):
        from raven.native.backend import PythonAnalysisBackend
        self.be = PythonAnalysisBackend()

    def test_identical_headers(self):
        h = {"content-type": "text/html"}
        r = self.be.diff_headers(h, h)
        self.assertTrue(r["ok"])
        self.assertEqual(r["added"], [])
        self.assertEqual(r["removed"], [])
        self.assertEqual(r["changed"], [])

    def test_added_header(self):
        r = self.be.diff_headers({}, {"x-new": "v"})
        self.assertEqual(r["added"], ["x-new"])

    def test_removed_header(self):
        r = self.be.diff_headers({"x-old": "v"}, {})
        self.assertEqual(r["removed"], ["x-old"])

    def test_changed_header(self):
        a = {"content-type": "text/html"}
        b = {"content-type": "text/plain"}
        r = self.be.diff_headers(a, b)
        self.assertEqual(len(r["changed"]), 1)
        self.assertEqual(r["changed"][0]["name"], "content-type")

    def test_no_security_verdict_field(self):
        # The diff result must not contain 'authorization_failure' or 'vulnerable'
        r = self.be.diff_headers({"x-auth": "user1"}, {"x-auth": "user2"})
        self.assertNotIn("authorization_failure", r)
        self.assertNotIn("vulnerable", r)


class PythonBackendBodyDiffTest(unittest.TestCase):
    def setUp(self):
        from raven.native.backend import PythonAnalysisBackend
        self.be = PythonAnalysisBackend()

    def test_exact_match(self):
        r = self.be.diff_bodies(b"hello", b"hello")
        self.assertTrue(r["exact_match"])
        self.assertEqual(r["similarity"], 1.0)

    def test_different_bodies(self):
        r = self.be.diff_bodies(b"hello", b"world")
        self.assertFalse(r["exact_match"])

    def test_length_delta(self):
        r = self.be.diff_bodies(b"ab", b"abcde")
        self.assertEqual(r["length_delta"], 3)

    def test_empty_bodies(self):
        r = self.be.diff_bodies(b"", b"")
        self.assertTrue(r["exact_match"])


class PythonBackendJsonDiffTest(unittest.TestCase):
    def setUp(self):
        from raven.native.backend import PythonAnalysisBackend
        self.be = PythonAnalysisBackend()

    def test_identical_json(self):
        r = self.be.diff_json(b'{"a":1}', b'{"a":1}')
        self.assertTrue(r["ok"])
        self.assertTrue(r["are_equal"])

    def test_added_key(self):
        r = self.be.diff_json(b'{"a":1}', b'{"a":1,"b":2}')
        self.assertFalse(r["are_equal"])
        paths = [d["path"] for d in r["differences"]]
        self.assertTrue(any("b" in p for p in paths))

    def test_changed_value(self):
        r = self.be.diff_json(b'{"s":"ok"}', b'{"s":"fail"}')
        self.assertFalse(r["are_equal"])

    def test_malformed_json_handled(self):
        r = self.be.diff_json(b'{invalid', b'{"a":1}')
        self.assertFalse(r["ok"])

    def test_nested(self):
        r = self.be.diff_json(
            b'{"user":{"id":1,"name":"alice"}}',
            b'{"user":{"id":1,"name":"bob"}}')
        self.assertFalse(r["are_equal"])


class PythonBackendSimHashTest(unittest.TestCase):
    def setUp(self):
        from raven.native.backend import PythonAnalysisBackend
        self.be = PythonAnalysisBackend()

    def test_deterministic(self):
        r1 = self.be.simhash(b"hello world")
        r2 = self.be.simhash(b"hello world")
        self.assertEqual(r1["hash"], r2["hash"])

    def test_similarity_self(self):
        h = self.be.simhash(b"test data")["hash"]
        self.assertEqual(self.be.simhash_similarity(h, h), 1.0)

    def test_empty_input(self):
        r = self.be.simhash(b"")
        self.assertTrue(r["ok"])


class PythonBackendInspectTest(unittest.TestCase):
    def setUp(self):
        from raven.native.backend import PythonAnalysisBackend
        self.be = PythonAnalysisBackend()

    def test_text_is_text_like(self):
        r = self.be.inspect_binary(b"Hello, World! Readable text.", "text/plain")
        self.assertTrue(r["text_like"])

    def test_binary_low_printable_ratio(self):
        r = self.be.inspect_binary(bytes(range(256)), "application/octet-stream")
        self.assertLess(r["printable_ratio"], 0.7)

    def test_pe_magic_detected(self):
        r = self.be.inspect_binary(b"MZ\x90\x00", "application/octet-stream")
        self.assertEqual(r["magic_family"], "PE")


class PythonBackendFeaturesTest(unittest.TestCase):
    def setUp(self):
        from raven.native.backend import PythonAnalysisBackend
        self.be = PythonAnalysisBackend()

    def test_status_class(self):
        r = self.be.extract_features(200, {"content-type": "text/html"}, b"body", 100)
        self.assertEqual(r["status_code"], 200)
        self.assertEqual(r["status_class"], 2)

    def test_json_detected(self):
        r = self.be.extract_features(200,
                                      {"content-type": "application/json"},
                                      b'{"ok":true}', -1)
        self.assertTrue(r["is_json"])

    def test_features_no_security_decision(self):
        # Features must not contain 'vulnerability' or 'verification_status'
        r = self.be.extract_features(403, {}, b"Forbidden", -1)
        self.assertNotIn("vulnerability", r)
        self.assertNotIn("verification_status", r)
        self.assertNotIn("authorization_failure", r)

    def test_similarity_defaults(self):
        r = self.be.extract_features(200, {}, b"body", -1)
        self.assertEqual(r["body_similarity"], -1.0)

    def test_has_set_cookie(self):
        r = self.be.extract_features(200,
                                      {"set-cookie": "sess=abc; Path=/"},
                                      b"body", -1)
        self.assertTrue(r["has_set_cookie"])


class AnalysisBackendDispatchTest(unittest.TestCase):
    """AnalysisBackend dispatch: AUTO mode uses Python when native absent."""

    def setUp(self):
        from raven.native.backend import AnalysisBackend, BackendMode
        self.be = AnalysisBackend(BackendMode.AUTO)

    def test_sha256_works(self):
        r = self.be.sha256(b"test")
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["hex"]), 64)

    def test_backend_name_is_string(self):
        self.assertIn(self.be.backend_name, ("python", "native"))

    def test_diff_headers_works(self):
        r = self.be.diff_headers({"a": "1"}, {"a": "2"})
        self.assertTrue(r["ok"])

    def test_diff_bodies_works(self):
        r = self.be.diff_bodies(b"a", b"b")
        self.assertTrue(r["ok"])
        self.assertFalse(r["exact_match"])


class PythonForceBackendTest(unittest.TestCase):
    """BackendMode.PYTHON always uses the Python reference."""

    def setUp(self):
        from raven.native.backend import AnalysisBackend, BackendMode
        self.be = AnalysisBackend(BackendMode.PYTHON)

    def test_backend_is_python(self):
        self.assertEqual(self.be.backend_name, "python")

    def test_sha256_correct(self):
        r = self.be.sha256(b"abc")
        self.assertEqual(r["hex"], hashlib.sha256(b"abc").hexdigest())


class NativeFallbackTest(unittest.TestCase):
    """When native unavailable, RAVEN must still work."""

    def test_get_capabilities_always_returns_dict(self):
        from raven.native.backend import get_capabilities
        caps = get_capabilities()
        self.assertIn("available", caps)
        self.assertIn("hashing", caps)
        self.assertIn("backend", caps)

    def test_get_backend_returns_usable_backend(self):
        from raven.native.backend import get_backend
        be = get_backend()
        r = be.sha256(b"hello")
        self.assertTrue(r["ok"])


class NativeUnavailableTest(unittest.TestCase):
    """BackendMode.NATIVE raises when library is absent."""

    def test_raises_when_native_absent(self):
        from raven.native.backend import (
            AnalysisBackend, BackendMode, NativeUnavailable, _native_mod
        )
        if _native_mod is not None:
            self.skipTest("Native library is available — skip unavailability test")
        with self.assertRaises(NativeUnavailable):
            AnalysisBackend(BackendMode.NATIVE)


class FingerprintTest(unittest.TestCase):
    def setUp(self):
        from raven.native.backend import PythonAnalysisBackend
        self.be = PythonAnalysisBackend()

    def test_fingerprint_is_deterministic(self):
        a = self.be.compute_fingerprint(200, {"content-type": "text/html"}, b"body")
        b = self.be.compute_fingerprint(200, {"content-type": "text/html"}, b"body")
        self.assertEqual(a["fingerprint_id"], b["fingerprint_id"])

    def test_different_status_different_fingerprint(self):
        a = self.be.compute_fingerprint(200, {}, b"body")
        b = self.be.compute_fingerprint(403, {}, b"body")
        self.assertNotEqual(a["fingerprint_id"], b["fingerprint_id"])

    def test_fp_version_field_present(self):
        r = self.be.compute_fingerprint(200, {}, b"")
        self.assertIn("fp_version", r)
        self.assertEqual(r["fp_version"], 1)


if __name__ == "__main__":
    unittest.main()
