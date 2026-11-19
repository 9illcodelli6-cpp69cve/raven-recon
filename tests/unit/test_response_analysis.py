"""Stage 3: Response analysis tests.

Tests normalization, ResponseRepr construction, and Task A ResponseDiff.
Verifies determinism and that normalization does NOT strip security-relevant content.
"""
import pytest

from raven.response_analysis import (
    ResponseRepr,
    ResponseDiff,
    compare_responses,
    normalize_body,
    _token_jaccard,
)


def _repr(
    status=200,
    headers=None,
    body=b"hello world",
    content_type="text/html",
    elapsed_ms=None,
    identity_label="owner",
    acquisition_mode="collect",
):
    h = headers or {"content-type": content_type}
    return ResponseRepr.from_raw(
        status=status,
        raw_headers=h,
        raw_body=body,
        elapsed_ms=elapsed_ms,
        identity_label=identity_label,
        acquisition_mode=acquisition_mode,
    )


class TestResponseRepr:

    def test_body_raw_not_stored(self):
        r = _repr(body=b"secret body content")
        assert not hasattr(r, "raw_body") or not r.__dict__.get("raw_body")
        # Only digest and length are stored
        assert r.body_len == len(b"secret body content")
        assert r.body_digest

    def test_sensitive_headers_stripped(self):
        r = _repr(headers={
            "Authorization": "Bearer tok123",
            "Cookie": "session=abc",
            "Content-Type": "text/html",
        })
        assert "authorization" not in r.headers
        assert "cookie" not in r.headers
        assert "content-type" in r.headers

    def test_body_digest_is_sha256_hex(self):
        import hashlib
        body = b"test body"
        r = _repr(body=body)
        assert r.body_digest == hashlib.sha256(body).hexdigest()

    def test_decode_lossy_flag(self):
        r = _repr(body=b"\xff\xfe invalid utf-8 \x80")
        assert r.decode_lossy is True

    def test_decode_clean_flag(self):
        r = _repr(body=b"clean utf-8 text")
        assert r.decode_lossy is False

    def test_empty_body(self):
        r = _repr(body=b"")
        assert r.body_len == 0
        assert r.normalized_text == ""


class TestNormalization:

    def test_uuid_stripped(self):
        text = "User ID: 550e8400-e29b-41d4-a716-446655440000"
        result = normalize_body(text, "text/plain")
        assert "550e8400" not in result
        assert "<DYNAMIC>" in result

    def test_iso_timestamp_stripped(self):
        text = "Created at 2026-09-01T12:34:56Z for user"
        result = normalize_body(text, "text/plain")
        assert "2026-09-01T12:34:56Z" not in result
        assert "<DYNAMIC>" in result

    def test_security_values_not_stripped(self):
        # Role, permissions, resource IDs — NOT stripped
        text = '{"role": "admin", "resource": "invoice-123", "action": "read"}'
        result = normalize_body(text, "application/json")
        assert "admin" in result
        assert "read" in result

    def test_json_sorted_keys(self):
        a = '{"z": 1, "a": 2}'
        b = '{"a": 2, "z": 1}'
        assert normalize_body(a, "application/json") == normalize_body(b, "application/json")

    def test_malformed_json_falls_back_to_text(self):
        text = "not json at all"
        result = normalize_body(text, "application/json")
        assert isinstance(result, str)

    def test_binary_content_type_not_parsed_as_json(self):
        text = '{"a": 1}'
        result = normalize_body(text, "application/octet-stream")
        # Falls back to regex-based normalization, not JSON parse
        assert isinstance(result, str)

    def test_deterministic_on_identical_input(self):
        text = '{"id": "550e8400-e29b-41d4-a716-446655440000", "value": 42}'
        r1 = normalize_body(text, "application/json")
        r2 = normalize_body(text, "application/json")
        assert r1 == r2


class TestTokenJaccard:

    def test_identical(self):
        assert _token_jaccard("a b c", "a b c") == pytest.approx(1.0)

    def test_disjoint(self):
        assert _token_jaccard("a b c", "x y z") == pytest.approx(0.0)

    def test_partial_overlap(self):
        j = _token_jaccard("a b c", "b c d")
        assert 0 < j < 1

    def test_both_empty(self):
        assert _token_jaccard("", "") == pytest.approx(1.0)

    def test_one_empty(self):
        assert _token_jaccard("hello", "") == pytest.approx(0.0)


class TestResponseDiff:

    def test_identical_responses(self):
        body = b"the same body text"
        r = _repr(body=body)
        diff = compare_responses(r, r)
        assert diff.label == "IDENTICAL"
        assert diff.body_digest_match is True
        assert diff.composite_similarity == pytest.approx(1.0, abs=0.01)

    def test_completely_different_status(self):
        r200 = _repr(status=200, body=b"ok content here")
        r404 = _repr(status=404, body=b"not found page text different")
        diff = compare_responses(r200, r404)
        assert diff.status_match is False

    def test_dynamic_nonce_only_not_different(self):
        body_a = b'{"user": "alice", "nonce": "550e8400-e29b-41d4-a716-446655440001"}'
        body_b = b'{"user": "alice", "nonce": "550e8400-e29b-41d4-a716-446655440002"}'
        r_a = _repr(body=body_a, content_type="application/json")
        r_b = _repr(body=body_b, content_type="application/json")
        diff = compare_responses(r_a, r_b)
        # After normalization, nonce is stripped; similarity should be high
        assert diff.normalized_digest_match is True

    def test_different_json_value_detected(self):
        body_a = b'{"role": "admin"}'
        body_b = b'{"role": "viewer"}'
        r_a = _repr(body=body_a, content_type="application/json")
        r_b = _repr(body=body_b, content_type="application/json")
        diff = compare_responses(r_a, r_b)
        assert diff.normalized_digest_match is False

    def test_missing_field_detected(self):
        body_a = b'{"secret": "value", "name": "alice"}'
        body_b = b'{"name": "alice"}'
        r_a = _repr(body=body_a, content_type="application/json")
        r_b = _repr(body=body_b, content_type="application/json")
        diff = compare_responses(r_a, r_b)
        assert diff.normalized_digest_match is False

    def test_diff_label_not_authorization_verdict(self):
        # DIFFERENT is evidence, not an authorization conclusion
        r_a = _repr(body=b"admin dashboard content")
        r_b = _repr(body=b"access denied page")
        diff = compare_responses(r_a, r_b)
        assert diff.label in ("DIFFERENT", "SIMILAR", "IDENTICAL")
        # The label does NOT say "AUTHORIZATION_BUG" or "CONFIRMED"
        assert "auth" not in diff.label.lower()
        assert "confirm" not in diff.label.lower()

    def test_empty_vs_nonempty(self):
        r_a = _repr(body=b"")
        r_b = _repr(body=b"some content here")
        diff = compare_responses(r_a, r_b)
        assert diff.label == "DIFFERENT"

    def test_unicode_body(self):
        body_a = "مرحبا بالعالم".encode("utf-8")
        body_b = "مرحبا بالمستخدم".encode("utf-8")
        r_a = _repr(body=body_a)
        r_b = _repr(body=body_b)
        diff = compare_responses(r_a, r_b)
        assert isinstance(diff, ResponseDiff)

    def test_huge_but_bounded_body(self):
        body = b"word " * 100_000  # 500KB
        r_a = _repr(body=body)
        r_b = _repr(body=body + b" extra")
        diff = compare_responses(r_a, r_b)
        # normalized_text is capped at 8192 chars — must not OOM or take forever
        assert isinstance(diff, ResponseDiff)

    def test_deterministic(self):
        r_a = _repr(body=b"body content here", status=200)
        r_b = _repr(body=b"different content", status=200)
        d1 = compare_responses(r_a, r_b)
        d2 = compare_responses(r_a, r_b)
        assert d1.label == d2.label
        assert d1.composite_similarity == pytest.approx(d2.composite_similarity)

    def test_components_present(self):
        r_a = _repr(body=b"a")
        r_b = _repr(body=b"b")
        diff = compare_responses(r_a, r_b)
        assert "status_match" in diff.components
        assert "body_token_jaccard" in diff.components
        assert "composite_similarity" in diff.components
