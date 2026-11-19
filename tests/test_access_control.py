"""Access Control Lab tests against a LOCAL synthetic app (owned fixtures only).

The fixture exposes a deliberately broken (IDOR) resource and a correctly-secured
one. Tests prove: strict per-identity separation, that the broken resource is flagged
INCONSISTENT (a review candidate, never "confirmed"), that the secured resource reads
EXPECTED, that state-changing methods need explicit consent, that scope is enforced,
and that credentials are never echoed.

No external targets. Run:  python -m unittest tests.test_access_control -v
"""
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from raven.api import server
from raven.scope import Scope

# Owner is "alice"; "bob" is another authorized test account. Distinctive cookie
# values so we can assert they never cross identities and never get echoed.
ALICE = "session=alice-tok-AAA111"
BOB = "session=bob-tok-BBB222"


class Lab(BaseHTTPRequestHandler):
    seen = []  # (path, cookie) observed — used to prove identity separation

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        Lab.seen.append((self.path, cookie))
        if self.path == "/vuln/1":
            # BROKEN: returns resource 1 (owned by alice) to ANY identity.
            return self._json(200, {"id": 1, "owner": "alice", "note": "private"})
        if self.path == "/secure/1":
            # CORRECT: only the owner may read it.
            if cookie == ALICE:
                return self._json(200, {"id": 1, "owner": "alice", "note": "private"})
            return self._json(403, {"error": "forbidden"})
        if self.path == "/public/1":
            # PUBLIC: served identically to everyone, including anonymous.
            return self._json(200, {"id": 1, "public": True, "note": "brochure"})
        self._json(404, {"error": "not found"})

    def log_message(self, *a):
        pass


class AccessControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._cwd = os.getcwd()
        cls._tmp = tempfile.mkdtemp(prefix="raven-ac-")
        os.chdir(cls._tmp)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        os.chdir(cls._cwd)

    def setUp(self):
        Lab.seen.clear()
        self._saved = dict(server.STATE)
        # Allow the local fixture only (isolated localhost test fixture, per V4).
        server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[self.port])
        server.STATE["allow_private"] = True

    def tearDown(self):
        server.STATE.clear()
        server.STATE.update(self._saved)

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_identity_separation(self):
        server.do_access_check({"method": "GET", "url": self._url("/vuln/1"), "sessions": [
            {"label": "alice", "cookies": ALICE}, {"label": "bob", "cookies": BOB}]})
        cookies_seen = [c for (_p, c) in Lab.seen]
        self.assertIn(ALICE, cookies_seen)
        self.assertIn(BOB, cookies_seen)
        # No request carried BOTH identities' tokens.
        for c in cookies_seen:
            self.assertFalse("alice-tok" in c and "bob-tok" in c)

    def test_idor_resource_flagged_inconsistent(self):
        out = server.do_access_check({"method": "GET", "url": self._url("/vuln/1"), "sessions": [
            {"label": "alice(owner)", "cookies": ALICE}, {"label": "bob", "cookies": BOB}]})
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONSISTENT")
        # The classifier must never emit a "confirmed vulnerability" verdict.
        verdicts = {c["verdict"] for c in out["comparisons"]}
        self.assertTrue(verdicts <= {"EXPECTED", "INCONSISTENT", "INCONCLUSIVE", "ENVIRONMENT ERROR"})

    def test_secure_resource_expected(self):
        out = server.do_access_check({"method": "GET", "url": self._url("/secure/1"), "sessions": [
            {"label": "alice(owner)", "cookies": ALICE}, {"label": "bob", "cookies": BOB}]})
        self.assertEqual(out["comparisons"][0]["verdict"], "EXPECTED")

    def test_anonymous_baseline_denied_is_expected(self):
        out = server.do_access_check({"method": "GET", "url": self._url("/secure/1"), "sessions": [
            {"label": "alice(owner)", "cookies": ALICE}, {"label": "anonymous"}]})
        self.assertEqual(out["comparisons"][0]["verdict"], "EXPECTED")

    def test_state_changing_requires_confirmation(self):
        out = server.do_access_check({"method": "DELETE", "url": self._url("/vuln/1"),
                                      "sessions": [{"label": "alice", "cookies": ALICE}]})
        self.assertIn("refused", out)

    def test_out_of_scope_is_blocked(self):
        out = server.do_access_check({"method": "GET", "url": "https://not-in-scope.example/",
                                      "sessions": [{"label": "alice", "cookies": ALICE}]})
        self.assertFalse(out["results"][0]["ok"])
        self.assertTrue(out["results"][0].get("blocked"))

    def test_public_resource_not_flagged_with_anon_baseline(self):
        # Public intent must come from the researcher, never from visibility.
        out = server.do_access_check({"method": "GET", "url": self._url("/public/1"),
                                      "anonymous_baseline": True, "resource_policy": "public", "sessions": [
                                          {"label": "alice", "cookies": ALICE},
                                          {"label": "bob", "cookies": BOB}]})
        self.assertEqual(out["comparisons"][0]["verdict"], "EXPECTED")
        self.assertIn("public", out["comparisons"][0]["reason"].lower())

    def test_baseline_does_not_suppress_private_disclosure(self):
        for policy in ("unspecified", "private", "public"):
            with self.subTest(policy=policy):
                out = server.do_access_check({"url": self._url("/vuln/1"),
                    "anonymous_baseline": True, "resource_policy": policy, "sessions": [
                        {"label": "alice", "cookies": ALICE},
                        {"label": "bob", "cookies": BOB, "expected": "deny"}]})
                self.assertEqual(out["comparisons"][0]["verdict"], "INCONSISTENT")

    def test_anonymous_visibility_requires_explicit_public_policy(self):
        out = server.do_access_check({"url": self._url("/public/1"),
            "anonymous_baseline": True, "sessions": [
                {"label": "alice", "cookies": ALICE}, {"label": "bob", "cookies": BOB}]})
        self.assertTrue(all(c["verdict"] == "INCONSISTENT" for c in out["comparisons"]))

    def test_single_owner_private_baseline_is_compared(self):
        out = server.do_access_check({"url": self._url("/vuln/1"),
            "resource_policy": "private", "anonymous_baseline": True,
            "sessions": [{"label": "alice", "cookies": ALICE}]})
        self.assertEqual(len(out["comparisons"]), 1)
        self.assertTrue(out["comparisons"][0]["anonymous_baseline"])
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONSISTENT")

    def test_identity_label_cannot_hide_comparison(self):
        out = server.do_access_check({"url": self._url("/vuln/1"), "sessions": [
            {"label": "alice", "cookies": ALICE},
            {"label": "anonymous baseline", "cookies": BOB, "expected": "deny"}]})
        self.assertEqual(len(out["comparisons"]), 1)
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONSISTENT")

    def test_public_resource_without_baseline_is_inconsistent(self):
        # Without the anonymous baseline the tool cannot know it is public -> conservative.
        out = server.do_access_check({"method": "GET", "url": self._url("/public/1"), "sessions": [
            {"label": "alice", "cookies": ALICE}, {"label": "bob", "cookies": BOB}]})
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONSISTENT")

    def test_expected_deny_still_flags_real_gap(self):
        # Declaring bob 'deny' must NOT suppress a genuine IDOR where bob still gets it.
        out = server.do_access_check({"method": "GET", "url": self._url("/vuln/1"), "sessions": [
            {"label": "alice", "cookies": ALICE},
            {"label": "bob", "cookies": BOB, "expected": "deny"}]})
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONSISTENT")

    def test_owner_session_expired_is_inconclusive(self):
        # If the owner's own request is denied, there is nothing to compare.
        out = server.do_access_check({"method": "GET", "url": self._url("/secure/1"), "sessions": [
            {"label": "alice(owner)", "cookies": BOB},   # wrong cookie for the owner
            {"label": "bob", "cookies": BOB}]})
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONCLUSIVE")

    def test_norm_not_leaked_in_output(self):
        out = server.do_access_check({"method": "GET", "url": self._url("/vuln/1"),
                                      "sessions": [{"label": "alice", "cookies": ALICE}]})
        self.assertNotIn("_norm", out["results"][0])

    def test_credentials_are_not_echoed(self):
        out = server.do_access_check({"method": "GET", "url": self._url("/vuln/1"),
                                      "sessions": [{"label": "alice", "cookies": ALICE}]})
        blob = json.dumps(out)
        self.assertNotIn("alice-tok-AAA111", blob)          # raw cookie value never returned
        self.assertIn("redacted", out["results"][0]["credential_preview"])

    def _compare_responses(self, owner_body, other_body, owner_status=200,
                           other_status=200, truncated=False):
        responses = [{"ok": True, "status": status, "body": body,
                      "bytes": len(body.encode()), "headers": {"Content-Type": "application/json"},
                      "truncated": truncated}
                     for status, body in ((owner_status, owner_body), (other_status, other_body))]
        with patch.object(server, "do_send", side_effect=responses):
            return server.do_access_check({"url": self._url("/vuln/1"), "sessions": [
                {"label": "alice", "cookies": ALICE},
                {"label": "bob", "cookies": BOB, "expected": "deny"}]})

    def test_matching_resource_with_different_success_status_is_inconsistent(self):
        body = '{"id":1,"owner":"alice","note":"private"}'
        out = self._compare_responses(body, body, other_status=206)
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONSISTENT")

    def test_denial_status_cannot_hide_matching_private_data(self):
        body = '{"id":1,"owner":"alice","note":"private"}'
        out = self._compare_responses(body, body, other_status=403)
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONSISTENT")

    def test_auth_words_in_successful_data_are_not_denial(self):
        for word in ("password", "login", "forbidden", "session expired", "access denied"):
            with self.subTest(word=word):
                body = json.dumps({"id": 1, "owner": "alice", "note": word})
                out = self._compare_responses(body, body)
                self.assertFalse(out["results"][0]["auth_wall"])
                self.assertEqual(out["comparisons"][0]["verdict"], "INCONSISTENT")

    def test_successful_auth_words_cannot_hide_different_private_data(self):
        out = self._compare_responses('{"owner":"alice","note":"private"}',
                                      '{"owner":"alice","password":"secret"}')
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONCLUSIVE")

    def test_long_common_prefix_does_not_erase_tail(self):
        prefix = "A" * 25000
        out = self._compare_responses(prefix + "alice private", prefix + "bob private")
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONCLUSIVE")
        self.assertNotEqual(out["results"][0]["norm_sha256"], out["results"][1]["norm_sha256"])
        self.assertTrue(out["comparisons"][0]["similarity_limited"])
        self.assertTrue(out["results"][0]["evidence_complete"])

    def test_truncated_matching_body_is_inconclusive(self):
        out = self._compare_responses("shared prefix", "shared prefix", truncated=True)
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONCLUSIVE")
        self.assertFalse(out["results"][0]["evidence_complete"])
        self.assertTrue(out["results"][0]["truncated"])

    def test_lossy_response_decoding_is_inconclusive_and_keeps_raw_hash(self):
        import hashlib
        responses = [{"ok": True, "status": 200, "body": "private \ufffd",
                      "decode_lossy": True, "raw_sha256": hashlib.sha256(raw).hexdigest()}
                     for raw in (b"private \xff", b"private \xfe")]
        with patch.object(server, "do_send", side_effect=responses):
            out = server.do_access_check({"url": self._url("/vuln/1"), "sessions": [
                {"label": "alice", "cookies": ALICE}, {"label": "bob", "cookies": BOB}]})
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONCLUSIVE")
        self.assertFalse(out["results"][0]["evidence_complete"])
        self.assertTrue(out["results"][0]["decode_lossy"])
        self.assertNotEqual(out["results"][0]["raw_sha256"], out["results"][1]["raw_sha256"])

    def test_different_response_does_not_prove_denial(self):
        for status in (200, 206, 302, 404, 500):
            with self.subTest(status=status):
                out = self._compare_responses('{"owner":"alice"}', '{"message":"different"}',
                                              other_status=status)
                self.assertEqual(out["comparisons"][0]["verdict"], "INCONCLUSIVE")

    def test_json_layout_and_key_order_do_not_hide_matching_resource(self):
        out = self._compare_responses('{"id": 1, "owner": "alice"}',
                                      '{\n "owner":"alice",\n "id":1\n}')
        self.assertEqual(out["comparisons"][0]["verdict"], "INCONSISTENT")

    def test_normalization_retains_security_relevant_values(self):
        pairs = [("sessionid", "alice-token", "bob-token"),
                 ("csrf_token", "first", "second"),
                 ("timestamp", "2026-09-27T12:00:00Z", "2026-09-27T12:00:01Z"),
                 ("note", "space  matters", "space matters")]
        for key, first, second in pairs:
            with self.subTest(key=key):
                out = self._compare_responses(json.dumps({key: first}), json.dumps({key: second}))
                self.assertNotEqual(out["results"][0]["norm_sha256"], out["results"][1]["norm_sha256"])
                self.assertEqual(out["comparisons"][0]["verdict"], "INCONCLUSIVE")

    def test_json_numbers_types_and_duplicate_keys_are_not_collapsed(self):
        for first, second in [('{"n":0.12345678901234567891}', '{"n":0.12345678901234567892}'),
                              ('{"n":1}', '{"n":"1"}'),
                              ('{"id":1,"id":2}', '{"id":2}')]:
            with self.subTest(first=first):
                self.assertNotEqual(server._ac_normalize(first), server._ac_normalize(second))


if __name__ == "__main__":
    unittest.main(verbosity=2)
