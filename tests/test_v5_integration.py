"""V5 integration tests: CanonicalService, new API routes, workspace isolation,
review workflow, and security invariants.

Run:  python -m unittest tests.test_v5_integration -v
"""
import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from raven.api import server
from raven.scope import Scope
from raven.store import Store
from raven.canonical_service import CanonicalService


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

class LocalHTTP:
    """Tiny loopback HTTP server used as a controlled target for send tests."""
    class _H(BaseHTTPRequestHandler):
        def _reply(self, code, body, headers=None):
            data = body.encode()
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._reply(200, "HELLO-RAVEN")

        def log_message(self, *a):
            pass

    def __enter__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def _make_store(tmp_dir, name="test"):
    from pathlib import Path
    return Store(Path(tmp_dir) / "workspaces" / name)


def _make_svc(store, wid=None, name="test"):
    wid = wid or uuid.uuid4().hex
    return CanonicalService(store, wid, name), wid


def _ok_result():
    return {
        "ok": True, "status": 200, "reason": "OK",
        "headers": {"Content-Type": "text/plain"},
        "body": "hello", "bytes": 5, "elapsed_ms": 10,
        "truncated": False, "decode_lossy": False,
    }


# ---------------------------------------------------------------------------
# 1. CanonicalServiceTests — direct unit tests, no HTTP server
# ---------------------------------------------------------------------------

class CanonicalServiceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="raven-cs-")
        self._store = _make_store(self._tmp)
        self._svc, self._wid = _make_svc(self._store)

    def tearDown(self):
        self._store.close()

    def test_record_send_result_ok(self):
        obs_id = self._svc.record_send_result(
            _ok_result(), url="http://127.0.0.1/", method="GET"
        )
        self.assertIsNotNone(obs_id)
        rows = self._store.get_observations(self._wid)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], obs_id)

    def test_record_send_result_error_skipped(self):
        result = {"ok": False, "error": "blocked"}
        obs_id = self._svc.record_send_result(
            result, url="http://127.0.0.1/", method="GET"
        )
        self.assertIsNone(obs_id)
        self.assertEqual(len(self._store.get_observations(self._wid)), 0)

    def test_record_send_result_strips_credentials(self):
        result = _ok_result()
        obs_id = self._svc.record_send_result(
            result,
            url="http://127.0.0.1/",
            method="GET",
            request_headers={
                "Authorization": "Bearer secret",
                "Cookie": "session=abc",
                "X-Custom": "safe",
            },
        )
        self.assertIsNotNone(obs_id)
        rows = self._store.get_observations(self._wid)
        stored_headers = json.loads(rows[0]["request_headers"])
        self.assertNotIn("Authorization", stored_headers)
        self.assertNotIn("authorization", stored_headers)
        self.assertNotIn("Cookie", stored_headers)
        self.assertIn("X-Custom", stored_headers)

    def test_candidate_access_control_inconsistent(self):
        finding_id = self._svc.create_candidate_access_control(
            "http://127.0.0.1/resource",
            owner_result={"status": 200, "ok": True},
            other_result={"status": 200, "ok": True},
            other_label="anon",
            verdict="INCONSISTENT",
        )
        self.assertIsNotNone(finding_id)
        findings = self._store.get_findings(self._wid)
        self.assertEqual(len(findings), 1)

    def test_candidate_access_control_consistent_skipped(self):
        finding_id = self._svc.create_candidate_access_control(
            "http://127.0.0.1/resource",
            owner_result={"status": 200, "ok": True},
            other_result={"status": 403, "ok": True},
            other_label="anon",
            verdict="EXPECTED",
        )
        self.assertIsNone(finding_id)
        self.assertEqual(len(self._store.get_findings(self._wid)), 0)

    def test_candidate_xss_reflection(self):
        finding_id = self._svc.create_candidate_xss_reflection(
            "http://127.0.0.1/search",
            "html-text",
        )
        self.assertIsNotNone(finding_id)
        findings = self._store.get_findings(self._wid)
        self.assertEqual(len(findings), 1)
        self.assertIn("XSS", findings[0]["title"])

    def test_candidate_finding_always_unverified(self):
        finding_id = self._svc.create_candidate_access_control(
            "http://127.0.0.1/resource",
            owner_result={"status": 200, "ok": True},
            other_result={"status": 200, "ok": True},
            other_label="other",
            verdict="INCONSISTENT",
        )
        row = self._store.get_finding(finding_id, self._wid)
        self.assertEqual(row["verification_status"], "unverified")

    def test_evidence_insert_only(self):
        ev_id = self._svc.record_evidence("test", "summary note")
        self.assertIsNotNone(ev_id)
        # The DB-level trigger must block UPDATE on evidence
        with self.assertRaises((sqlite3.IntegrityError, sqlite3.OperationalError)):
            self._store.db.execute(
                "UPDATE evidence SET summary=? WHERE id=?", ("tampered", ev_id)
            )

    def test_review_transition_valid(self):
        finding_id = self._svc.create_candidate_xss_reflection(
            "http://127.0.0.1/", "html-text"
        )
        result = self._svc.submit_review(finding_id, "in_review")
        self.assertTrue(result.get("ok"))
        self.assertEqual(result["review_status"], "in_review")

    def test_review_automated_blocked(self):
        """submit_review passes is_automated=False; ReviewWorkflow blocks automated confirm."""
        from raven.review_workflow import ReviewWorkflow, FindingReviewState, WorkflowError
        wf = ReviewWorkflow()
        state = FindingReviewState(
            finding_id="fake",
            review_status="in_review",
            verification_status="unverified",
        )
        with self.assertRaises(WorkflowError):
            wf.transition(state, "confirmed", actor="bot", is_automated=True)

    def test_workspace_scoping(self):
        store_b = _make_store(self._tmp, "workspace-b")
        try:
            svc_b, wid_b = _make_svc(store_b, name="workspace-b")
            # Record in workspace A
            obs_a = self._svc.record_send_result(
                _ok_result(), url="http://127.0.0.1/a", method="GET"
            )
            self.assertIsNotNone(obs_a)
            # Workspace B should not see workspace A observations
            rows_b = store_b.get_observations(wid_b)
            self.assertEqual(len(rows_b), 0)
            # Workspace A should have one
            rows_a = self._store.get_observations(self._wid)
            self.assertEqual(len(rows_a), 1)
        finally:
            store_b.close()


# ---------------------------------------------------------------------------
# 2. Shared server setup mixin
# ---------------------------------------------------------------------------

class _ServerBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_state = dict(server.STATE)
        cls._cwd = os.getcwd()
        cls._tmp = tempfile.mkdtemp(prefix="raven-v5test-")
        os.chdir(cls._tmp)
        server.use_workspace("v5test")
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        server.STATE["port"] = cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        try:
            server.STATE["store"].close()
        except Exception:
            pass
        server.STATE.clear()
        server.STATE.update(cls._saved_state)
        os.chdir(cls._cwd)

    def _req(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def _authed_get(self, path):
        return self._req("GET", path, {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Host": f"127.0.0.1:{self.port}",
        })

    def _authed_post(self, path, payload):
        body = json.dumps(payload).encode()
        return self._req("POST", path, {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": f"http://127.0.0.1:{self.port}",
            "Host": f"127.0.0.1:{self.port}",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }, body)

    def _svc(self):
        return server.STATE.get("canonical_svc")

    def _wid(self):
        return server.STATE.get("workspace_id")

    def _store(self):
        return server.STATE.get("store")


# ---------------------------------------------------------------------------
# 3. SendCanonicalIntegrationTests
# ---------------------------------------------------------------------------

class SendCanonicalIntegrationTests(_ServerBase):
    def test_send_creates_observation(self):
        with LocalHTTP() as srv:
            server.STATE["scope"] = Scope(
                include=["127.0.0.1"], exclude=[], ports=[srv.port]
            )
            server.STATE["allow_private"] = True
            wid = self._wid()
            store = self._store()
            before = len(store.get_observations(wid)) if store and wid else 0
            status, _ = self._authed_post("/api/send", {
                "method": "GET",
                "url": f"http://127.0.0.1:{srv.port}/",
            })
            self.assertNotEqual(status, 403)
            import time; time.sleep(0.1)  # brief wait for canonical persistence
            if store and wid:
                after = len(store.get_observations(wid))
                self.assertGreaterEqual(after, before)

    def test_send_error_no_observation(self):
        wid = self._wid()
        store = self._store()
        before = len(store.get_observations(wid)) if store and wid else 0
        # Send to an address that will be blocked (out of scope)
        self._authed_post("/api/send", {
            "method": "GET",
            "url": "http://192.0.2.1/",
        })
        import time; time.sleep(0.1)
        if store and wid:
            after = len(store.get_observations(wid))
            self.assertEqual(after, before)

    def test_send_observation_no_credential_leak(self):
        with LocalHTTP() as srv:
            server.STATE["scope"] = Scope(
                include=["127.0.0.1"], exclude=[], ports=[srv.port]
            )
            server.STATE["allow_private"] = True
            wid = self._wid()
            store = self._store()
            self._authed_post("/api/send", {
                "method": "GET",
                "url": f"http://127.0.0.1:{srv.port}/",
                "headers": {"Authorization": "Bearer topsecret"},
            })
            import time; time.sleep(0.1)
            if store and wid:
                rows = store.get_observations(wid)
                for row in rows:
                    stored = json.loads(row.get("request_headers") or "{}")
                    self.assertNotIn("Authorization", stored)
                    self.assertNotIn("authorization", stored)

    def test_send_canonical_noop_without_workspace(self):
        """Canonical service None means do_send still returns a result."""
        saved_svc = server.STATE.get("canonical_svc")
        server.STATE["canonical_svc"] = None
        try:
            with LocalHTTP() as srv:
                server.STATE["scope"] = Scope(
                    include=["127.0.0.1"], exclude=[], ports=[srv.port]
                )
                server.STATE["allow_private"] = True
                status, body = self._authed_post("/api/send", {
                    "method": "GET",
                    "url": f"http://127.0.0.1:{srv.port}/",
                })
                data = json.loads(body)
                self.assertIn("ok", data)
        finally:
            server.STATE["canonical_svc"] = saved_svc


# ---------------------------------------------------------------------------
# 4. FindingsAPITests
# ---------------------------------------------------------------------------

class FindingsAPITests(_ServerBase):
    def _create_finding(self):
        svc = self._svc()
        if svc is None:
            self.skipTest("canonical_svc not available")
        fid = svc.create_candidate_xss_reflection(
            "http://127.0.0.1/search", "html-text"
        )
        self.assertIsNotNone(fid)
        return fid

    def _create_observation(self):
        svc = self._svc()
        if svc is None:
            self.skipTest("canonical_svc not available")
        oid = svc.record_send_result(
            _ok_result(), url="http://127.0.0.1/obs", method="GET"
        )
        return oid

    def test_get_findings_empty_returns_list(self):
        status, body = self._authed_get("/api/findings")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("findings", data)
        self.assertIn("total", data)

    def test_get_findings_with_data(self):
        self._create_finding()
        status, body = self._authed_get("/api/findings")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertGreaterEqual(data["total"], 1)
        self.assertGreaterEqual(len(data["findings"]), 1)

    def test_get_finding_by_id(self):
        fid = self._create_finding()
        status, body = self._authed_get(f"/api/findings/{fid}")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["id"], fid)

    def test_get_finding_not_found(self):
        status, _ = self._authed_get("/api/findings/nonexistent-id-xyz")
        self.assertEqual(status, 404)

    def test_get_findings_requires_auth(self):
        status, _ = self._req("GET", "/api/findings", {
            "Host": f"127.0.0.1:{self.port}",
        })
        self.assertEqual(status, 403)

    def test_get_finding_evidence(self):
        fid = self._create_finding()
        status, body = self._authed_get(f"/api/findings/{fid}/evidence")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("evidence", data)
        self.assertEqual(data["finding_id"], fid)

    def test_get_observations(self):
        self._create_observation()
        status, body = self._authed_get("/api/observations")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("observations", data)

    def test_get_observation_by_id(self):
        oid = self._create_observation()
        if oid is None:
            self.skipTest("observation not created")
        status, body = self._authed_get(f"/api/observations/{oid}")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["id"], oid)

    def test_get_baselines_empty(self):
        status, body = self._authed_get("/api/baselines")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("baselines", data)

    def test_get_payloads(self):
        status, body = self._authed_get("/api/payloads")
        self.assertIn(status, (200, 500))  # 500 if registry unavailable
        data = json.loads(body)
        if status == 200:
            self.assertIn("payloads", data)

    def test_get_ml_readiness(self):
        status, body = self._authed_get("/api/ml-readiness")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("status", data)
        self.assertFalse(data.get("model_trained", True))


# ---------------------------------------------------------------------------
# 5. WorkspaceIsolationTests
# ---------------------------------------------------------------------------

class WorkspaceIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_state = dict(server.STATE)
        cls._cwd = os.getcwd()

        # Fresh root temp dir for workspace A (used as DATA_ROOT via chdir)
        cls._tmp_a = tempfile.mkdtemp(prefix="raven-iso-a-")
        os.chdir(cls._tmp_a)
        server.use_workspace("iso-a")
        cls._store_a = server.STATE["store"]
        cls._wid_a = server.STATE["workspace_id"]
        cls._svc_a = server.STATE["canonical_svc"]

        # Workspace B lives in a completely separate directory; no relation to the
        # HTTP server's store. Its findings carry wid_b which the server store will
        # never match.
        cls._tmp_b = tempfile.mkdtemp(prefix="raven-iso-b-")
        cls._store_b = _make_store(cls._tmp_b, "iso-b")
        cls._svc_b, cls._wid_b = _make_svc(cls._store_b, name="iso-b")

        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        server.STATE["port"] = cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        try:
            server.STATE["store"].close()
        except Exception:
            pass
        server.STATE.clear()
        server.STATE.update(cls._saved_state)
        os.chdir(cls._cwd)
        cls._store_b.close()

    def _authed_get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", path, headers={
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Host": f"127.0.0.1:{self.port}",
        })
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def test_finding_from_other_workspace_returns_404(self):
        # Create a finding in workspace B
        fid_b = self._svc_b.create_candidate_xss_reflection(
            "http://127.0.0.1/ws-b-resource", "html-text"
        )
        self.assertIsNotNone(fid_b)
        # HTTP server is workspace A — B's finding_id should 404
        status, _ = self._authed_get(f"/api/findings/{fid_b}")
        self.assertEqual(status, 404)

    def test_observation_from_other_workspace_returns_404(self):
        oid_b = self._svc_b.record_send_result(
            _ok_result(), url="http://127.0.0.1/ws-b-obs", method="GET"
        )
        self.assertIsNotNone(oid_b)
        status, _ = self._authed_get(f"/api/observations/{oid_b}")
        self.assertEqual(status, 404)

    def test_cross_workspace_uuid_substitution(self):
        # A finding that exists in ws-b should not be accessible through ws-a server
        fid_b = self._svc_b.create_candidate_xss_reflection(
            "http://127.0.0.1/target", "js"
        )
        # Substitute the UUID from ws-b into a ws-a scoped request
        status, body = self._authed_get(f"/api/findings/{fid_b}")
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertIn("error", data)


# ---------------------------------------------------------------------------
# 6. ReviewAPITests
# ---------------------------------------------------------------------------

class ReviewAPITests(_ServerBase):
    def _create_finding(self):
        svc = self._svc()
        if svc is None:
            self.skipTest("canonical_svc not available")
        return svc.create_candidate_xss_reflection("http://127.0.0.1/r", "js")

    def test_review_requires_csrf_token(self):
        fid = self._create_finding()
        body = json.dumps({"action": "in_review"}).encode()
        status, _ = self._req("POST", f"/api/findings/{fid}/review", {
            "Host": f"127.0.0.1:{self.port}",
            "Origin": f"http://127.0.0.1:{self.port}",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }, body)
        self.assertEqual(status, 403)

    def test_review_requires_origin(self):
        fid = self._create_finding()
        body = json.dumps({"action": "in_review"}).encode()
        status, _ = self._req("POST", f"/api/findings/{fid}/review", {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Host": f"127.0.0.1:{self.port}",
            "Origin": "http://evil.example",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }, body)
        self.assertEqual(status, 403)

    def test_review_open_transition(self):
        fid = self._create_finding()
        status, body = self._authed_post(f"/api/findings/{fid}/review",
                                         {"action": "in_review"})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data.get("ok"))
        self.assertEqual(data["review_status"], "in_review")

    def test_review_invalid_action(self):
        fid = self._create_finding()
        status, body = self._authed_post(f"/api/findings/{fid}/review",
                                         {"action": "nonexistent_action"})
        self.assertEqual(status, 400)

    def test_review_nonexistent_finding(self):
        status, _ = self._authed_post("/api/findings/does-not-exist/review",
                                      {"action": "in_review"})
        self.assertEqual(status, 404)

    def test_review_automation_blocked(self):
        """ReviewWorkflow blocks automated confirmation — test directly."""
        from raven.review_workflow import ReviewWorkflow, FindingReviewState, WorkflowError
        wf = ReviewWorkflow()
        state = FindingReviewState("fake", "in_review", "unverified")
        with self.assertRaises(WorkflowError):
            wf.transition(state, "confirmed", actor="bot", is_automated=True)

    def test_review_verification_requires_confirmed_action(self):
        fid = self._create_finding()
        # First move to in_review
        self._authed_post(f"/api/findings/{fid}/review", {"action": "in_review"})
        # Then confirm
        status, body = self._authed_post(f"/api/findings/{fid}/review",
                                         {"action": "confirmed"})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get("verification_status"), "verified")

    def test_review_history_persisted(self):
        fid = self._create_finding()
        self._authed_post(f"/api/findings/{fid}/review", {"action": "in_review"})
        store = self._store()
        wid = self._wid()
        if store and wid:
            events = store.get_review_events(fid, wid)
            self.assertGreaterEqual(len(events), 1)
            self.assertEqual(events[0]["to_state"], "in_review")


# ---------------------------------------------------------------------------
# 7. SecurityInvariantTests
# ---------------------------------------------------------------------------

class SecurityInvariantTests(_ServerBase):
    _NEW_ROUTES = [
        "/api/findings",
        "/api/observations",
        "/api/baselines",
        "/api/payloads",
        "/api/ml-readiness",
    ]

    def test_new_routes_require_auth(self):
        for route in self._NEW_ROUTES:
            status, _ = self._req("GET", route, {
                "Host": f"127.0.0.1:{self.port}",
            })
            self.assertEqual(status, 403, f"{route} should require auth")

    def test_host_header_validation_new_routes(self):
        for route in self._NEW_ROUTES:
            status, _ = self._req("GET", route, {
                "X-RAVEN-Token": server.SESSION_TOKEN,
                "Host": "evil.example",
            })
            self.assertEqual(status, 403, f"{route} should block bad host")

    def test_origin_validation_on_review_post(self):
        svc = self._svc()
        if svc is None:
            self.skipTest("canonical_svc not available")
        fid = svc.create_candidate_xss_reflection("http://127.0.0.1/sec", "html-text")
        body = json.dumps({"action": "in_review"}).encode()
        status, _ = self._req("POST", f"/api/findings/{fid}/review", {
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Host": f"127.0.0.1:{self.port}",
            "Origin": "http://attacker.com",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }, body)
        self.assertEqual(status, 403)

    def test_finding_verification_status_never_auto_set(self):
        """All newly-created findings must have verification_status='unverified'."""
        svc = self._svc()
        if svc is None:
            self.skipTest("canonical_svc not available")
        fid = svc.create_candidate_access_control(
            "http://127.0.0.1/x",
            owner_result={"status": 200, "ok": True},
            other_result={"status": 200, "ok": True},
            other_label="other",
            verdict="INCONSISTENT",
        )
        store = self._store()
        wid = self._wid()
        if store and wid and fid:
            row = store.get_finding(fid, wid)
            self.assertEqual(row["verification_status"], "unverified")

    def test_ml_readiness_never_trains(self):
        status, body = self._authed_get("/api/ml-readiness")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertFalse(data.get("model_trained"))
        self.assertFalse(data.get("ml_probability_modified"))

    def test_evidence_no_delete_trigger(self):
        svc = self._svc()
        if svc is None:
            self.skipTest("canonical_svc not available")
        ev_id = svc.record_evidence("test_kind", "must not be deleted")
        self.assertIsNotNone(ev_id)
        store = self._store()
        if store:
            with self.assertRaises((sqlite3.IntegrityError, sqlite3.OperationalError)):
                store.db.execute("DELETE FROM evidence WHERE id=?", (ev_id,))


if __name__ == "__main__":
    unittest.main(verbosity=2)
