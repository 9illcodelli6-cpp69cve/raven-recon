"""Wave 8 (A8-BROWSER) — canonical Traffic projection tests.

Proves the ONE traffic model: `observations` rows (written by the single
canonical writer on BOTH manual/Browser sends AND recon probes) project through
raven.api.traffic.TrafficEntry and surface at GET /api/v7/traffic under key
`entries`. No second store, no second HTTP client, no bodies.

Authority: reconstruction/BROWSER_TRAFFIC_ARCHITECTURE.md §3.3, §9.

Run:  python -m pytest tests/test_traffic_projection.py -q
"""
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from raven.api import server
from raven.api.traffic import (
    TrafficEntry,
    build_traffic_response,
    project_observations,
)
from raven.scope import Scope


# ---------------------------------------------------------------------------
# 1. Pure projection unit tests (no network, no DB)
# ---------------------------------------------------------------------------

def _obs_row(**over):
    row = {
        "id": "obs-1", "workspace_id": "ws-1", "asset_id": "a1",
        "run_id": None, "job_id": None,
        "url": "http://127.0.0.1/x", "method": "GET",
        "request_headers": json.dumps({"User-Agent": "RAVEN"}),
        "request_body_hash": None, "request_body_len": 0,
        "status": 200,
        "response_headers": json.dumps({"Content-Type": "text/plain"}),
        "response_body_len": 11, "response_body_hash": "deadbeef",
        "elapsed_ms": 12, "identity_label": "browser",
        "source_engine": "RAVEN", "source_version": "5.0.1",
        "timestamp": "2026-10-06T12:00:00+00:00",
        "truncated": 0, "decode_lossy": 0,
        "acquisition_mode": "collect", "is_probe": 0, "is_anomalous": 0,
        "baseline_approved": 0,
    }
    row.update(over)
    return row


class TrafficEntryProjectionTests(unittest.TestCase):
    def test_projects_every_dto_field(self):
        e = TrafficEntry.from_observation(_obs_row()).to_dict()
        self.assertEqual(e["entry_id"], "obs-1")
        self.assertEqual(e["workspace_id"], "ws-1")
        self.assertEqual(e["url"], "http://127.0.0.1/x")
        self.assertEqual(e["method"], "GET")
        self.assertEqual(e["status"], 200)
        self.assertEqual(e["identity_label"], "browser")
        self.assertEqual(e["acquisition_mode"], "collect")
        self.assertEqual(e["source_engine"], "RAVEN")
        self.assertEqual(e["elapsed_ms"], 12)
        self.assertEqual(e["request_body_len"], 0)
        self.assertEqual(e["response_body_len"], 11)
        self.assertEqual(e["response_body_hash"], "deadbeef")
        self.assertIs(e["is_probe"], False)
        self.assertIs(e["is_anomalous"], False)
        self.assertEqual(e["timestamp"], "2026-10-06T12:00:00+00:00")

    def test_metadata_only_no_bodies_or_headers(self):
        # Hard guarantee: the DTO never carries request/response BODIES or HEADERS.
        e = TrafficEntry.from_observation(_obs_row()).to_dict()
        for leaked in ("request_headers", "response_headers", "body",
                       "request_body", "response_body"):
            self.assertNotIn(leaked, e)

    def test_null_status_preserved(self):
        e = TrafficEntry.from_observation(_obs_row(status=None)).to_dict()
        self.assertIsNone(e["status"])

    def test_probe_and_anomalous_flags_coerced_to_bool(self):
        e = TrafficEntry.from_observation(
            _obs_row(is_probe=1, is_anomalous=1, identity_label="probe")
        ).to_dict()
        self.assertIs(e["is_probe"], True)
        self.assertIs(e["is_anomalous"], True)
        self.assertEqual(e["identity_label"], "probe")

    def test_partial_row_never_raises(self):
        e = TrafficEntry.from_observation({"id": "x"}).to_dict()
        self.assertEqual(e["entry_id"], "x")
        self.assertIsNone(e["status"])
        self.assertIsNone(e["url"])

    def test_build_traffic_response_envelope(self):
        rows = [_obs_row(id="a"), _obs_row(id="b")]
        resp = build_traffic_response(rows, "ws-1")
        self.assertEqual(set(resp), {"entries", "total", "workspace_id"})
        self.assertEqual(resp["total"], 2)
        self.assertEqual(resp["workspace_id"], "ws-1")
        self.assertEqual([x["entry_id"] for x in resp["entries"]], ["a", "b"])

    def test_project_empty(self):
        self.assertEqual(project_observations([]), [])
        self.assertEqual(project_observations(None), [])


# ---------------------------------------------------------------------------
# 2. Loopback integration — a real Browser send must appear on Traffic
# ---------------------------------------------------------------------------

class _LocalHTTP:
    """Controlled loopback target (authorized, no external egress)."""
    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            data = b"HELLO-RAVEN-TRAFFIC"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

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


class _ServerBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_state = dict(server.STATE)
        cls._cwd = os.getcwd()
        cls._tmp = tempfile.mkdtemp(prefix="raven-traffic-proj-")
        os.chdir(cls._tmp)
        server.use_workspace("trafficproj")
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

    def _authed_post(self, path, payload):
        body = json.dumps(payload).encode()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("POST", path, body=body, headers={
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Origin": f"http://127.0.0.1:{self.port}",
            "Host": f"127.0.0.1:{self.port}",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        })
        r = c.getresponse()
        data = json.loads(r.read())
        c.close()
        return r.status, data

    def _authed_get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", path, headers={
            "X-RAVEN-Token": server.SESSION_TOKEN,
            "Host": f"127.0.0.1:{self.port}",
        })
        r = c.getresponse()
        data = json.loads(r.read())
        c.close()
        return r.status, data


class TrafficRouteIntegrationTests(_ServerBase):
    def test_traffic_route_returns_entries_envelope(self):
        # Contract: GET /api/v7/traffic -> {entries, total, workspace_id}; the dead
        # `requests` key (recon asset inventory) is gone.
        status, data = self._authed_get("/api/v7/traffic")
        self.assertEqual(status, 200)
        self.assertTrue({"entries", "total", "workspace_id"} <= set(data))
        self.assertNotIn("requests", data)
        self.assertIsInstance(data["entries"], list)

    def test_traffic_shows_real_loopback_browser_send(self):
        # PROOF (deliverable 1): a real loopback /api/send with identity_label
        # 'browser' persists a canonical observation that the Traffic tab reads
        # back under `entries`.
        with _LocalHTTP() as srv:
            server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[srv.port])
            server.STATE["allow_private"] = True
            target = f"http://127.0.0.1:{srv.port}/"
            status, result = self._authed_post("/api/send", {
                "method": "GET", "url": target, "identity_label": "browser",
            })
            self.assertNotEqual(status, 403)
            self.assertTrue(result.get("ok"), result)
            time.sleep(0.1)  # persistence is synchronous, this is belt-and-braces
            _, traffic = self._authed_get("/api/v7/traffic")
            self.assertIn("entries", traffic)
            matches = [e for e in traffic["entries"]
                       if e.get("url") == target and e.get("identity_label") == "browser"]
            self.assertTrue(matches, f"browser send missing from traffic: {traffic}")
            entry = matches[0]
            self.assertEqual(entry["method"], "GET")
            self.assertEqual(entry["status"], 200)
            self.assertEqual(entry["source_engine"], "RAVEN")
            self.assertIsNotNone(entry["response_body_hash"])
            # metadata only: body itself never travels through the Traffic read
            self.assertNotIn("body", entry)
            self.assertNotIn("response_body", entry)

    def test_out_of_scope_send_adds_no_traffic_entry(self):
        # Blocked (out-of-scope) send -> no observation -> no new traffic entry.
        server.STATE["scope"] = Scope(include=["127.0.0.1"], exclude=[], ports=[80])
        server.STATE["allow_private"] = True
        _, before = self._authed_get("/api/v7/traffic")
        status, result = self._authed_post("/api/send", {
            "method": "GET", "url": "http://192.0.2.1/", "identity_label": "browser",
        })
        self.assertNotEqual(status, 403)
        self.assertFalse(result.get("ok"))
        self.assertTrue(result.get("blocked") or result.get("error"), result)
        time.sleep(0.1)
        _, after = self._authed_get("/api/v7/traffic")
        self.assertEqual(after["total"], before["total"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
