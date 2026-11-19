"""Collection integration regressions: local stores and stubbed transports only."""
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from raven.api import server
from raven.api.scheduler import Scheduler


def wait_until(predicate, timeout=4):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class FakeResponse:
    status = 200
    reason = "OK"

    def read(self, limit):
        return b"<html><title>Captured workspace A</title></html>"[:limit]

    def getheaders(self):
        return [("Content-Type", "text/html")]


class CollectionContextTests(unittest.TestCase):
    def setUp(self):
        self.previous_state = dict(server.STATE)
        self.previous_scheduler = server.SCHEDULER
        self.previous_cwd = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory(prefix="raven-context-")
        os.chdir(self.tmp.name)
        self.scheduler = Scheduler(workers=1, default_rate=1000)
        server.SCHEDULER = self.scheduler
        self.stores = []
        self.release_events = []
        self.select_workspace("A", "a.test", ports=[80], allow_private=True)
        self.dns = patch.object(server.socket, "getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0))])
        self.dns.start()
        self.network_guard = patch.object(server.socket, "create_connection",
                                          side_effect=AssertionError("real network is forbidden in this test"))
        self.network_guard.start()

    def tearDown(self):
        for event in self.release_events:
            event.set()
        self.scheduler.emergency_stop()
        self.scheduler.shutdown()
        self.dns.stop()
        self.network_guard.stop()
        for store in self.stores:
            store.close()
        server.SCHEDULER = self.previous_scheduler
        server.STATE.clear()
        server.STATE.update(self.previous_state)
        os.chdir(self.previous_cwd)
        self.tmp.cleanup()

    def select_workspace(self, name, host, ports=None, allow_private=True):
        server.set_scope({"name": name, "include": [host], "exclude": [],
                          "ports": ports or [80, 443], "allow_private": allow_private})
        store = server.STATE["store"]
        self.stores.append(store)
        return store

    def event(self):
        event = threading.Event()
        self.release_events.append(event)
        return event

    def terminal(self, job_id):
        self.assertTrue(wait_until(lambda: self.scheduler.get(job_id)["state"] in
                                   ("DONE", "CANCELLED", "FAILED")))
        return self.scheduler.get(job_id)

    @staticmethod
    def probe_data(host):
        return {"status": 200, "title": "partial result", "server": "fixture",
                "final_url": f"http://{host}/", "body_hash": "fixture-hash", "scripts": [],
                "error": "", "elapsed_ms": 1}

    def test_queued_collection_retains_submission_workspace_and_transport_policy(self):
        entered, release = threading.Event(), self.event()

        def hold(_):
            entered.set()
            self.assertTrue(release.wait(4))

        self.scheduler.submit("hold", "unrelated", hold)
        self.assertTrue(entered.wait(2))
        store_a = server.STATE["store"]
        original_scope = server.STATE["scope"]
        server.STATE["max_body"], server.STATE["timeout"] = 128, 0.75
        requests = []

        def send(connection, method, target, body=None, headers=None):
            requests.append((connection.host, connection.port, connection.timeout))

        with patch.object(server._PinnedHTTPConnection, "request", new=send), \
             patch.object(server._PinnedHTTPConnection, "getresponse", return_value=FakeResponse()):
            job = server.submit_collect(passive=False, probe=True, rate=1000)
            self.assertEqual(self.scheduler.get(job["job_id"])["state"], "QUEUED")
            original_scope.include.append("added-after-queue.test")
            store_b = self.select_workspace("B", "b.test", ports=[443], allow_private=False)
            server.STATE["max_body"], server.STATE["timeout"] = 2, 9
            release.set()
            finished = self.terminal(job["job_id"])
        self.assertEqual(finished["state"], "DONE", finished)
        self.assertEqual(finished["workspace"], "A")
        self.assertEqual(requests, [("a.test", 80, 0.75)])
        self.assertEqual([a["host"] for a in store_a.assets()], ["a.test"])
        self.assertEqual(store_a.assets()[0]["probe"]["title"], "Captured workspace A")
        self.assertFalse(any(r["mode"] == "collect" for r in store_b.runs()))
        self.assertFalse(store_b.assets()[0]["probe"])

    def test_reopening_workspace_keeps_active_run_but_recovers_stale_run(self):
        entered, release = threading.Event(), self.event()
        original_store = server.STATE["store"]
        stale_id = original_store.start("collect", {})

        def blocked_probe(host):
            entered.set()
            self.assertTrue(release.wait(8))
            return self.probe_data(host)

        with patch.object(server, "_probe_host", side_effect=blocked_probe):
            job = server.submit_collect(passive=False, probe=True)
            self.assertTrue(entered.wait(2))
            active_id = next(r["id"] for r in original_store.runs()
                             if r["mode"] == "collect" and r["id"] != stale_id)
            reopened = self.select_workspace("A", "a.test", ports=[80])
            states = {r["id"]: r["state"] for r in reopened.runs()}
            self.assertEqual(states[active_id], "running")
            self.assertEqual(states[stale_id], "interrupted")
            release.set()
            self.assertEqual(self.terminal(job["job_id"])["state"], "DONE")
        self.assertEqual({r["id"]: r["state"] for r in reopened.runs()}[active_id], "complete")

    def test_https_fallback_counts_each_transport_attempt(self):
        self.select_workspace("A", "a.test", ports=[80, 443])
        attempts = []

        def fail_https(connection, *args, **kwargs):
            attempts.append((connection.host, "https"))
            raise OSError("fixture TLS connection failure")

        def send_http(connection, *args, **kwargs):
            attempts.append((connection.host, "http"))

        with patch.object(server._PinnedHTTPSConnection, "request", new=fail_https), \
             patch.object(server._PinnedHTTPConnection, "request", new=send_http), \
             patch.object(server._PinnedHTTPConnection, "getresponse", return_value=FakeResponse()):
            job = server.submit_collect(passive=False, probe=True, rate=1000, budget=2)
            finished = self.terminal(job["job_id"])
        self.assertEqual(finished["state"], "DONE", finished)
        self.assertEqual(finished["requests"], 2)
        self.assertEqual(attempts, [("a.test", "https"), ("a.test", "http")])
        self.assertEqual(server.STATE["store"].assets()[0]["probe"]["status"], 200)

    def test_final_inflight_probe_is_preserved_and_run_is_cancelled(self):
        entered, release = threading.Event(), self.event()
        observed = []

        def final_probe(host):
            observed.append(host)
            entered.set()
            self.assertTrue(release.wait(4))
            return self.probe_data(host)

        with patch.object(server, "_probe_host", side_effect=final_probe):
            job = server.submit_collect(passive=False, probe=True)
            self.assertTrue(entered.wait(2))
            self.assertTrue(self.scheduler.cancel(job["job_id"]))
            release.set()
            finished = self.terminal(job["job_id"])
        self.assertEqual(finished["state"], "CANCELLED")
        store = server.STATE["store"]
        run = next(r for r in store.runs() if r["mode"] == "collect")
        self.assertEqual(run["state"], "cancelled")
        self.assertEqual(observed, ["a.test"])
        self.assertEqual(store.assets()[0]["probe"]["title"], "partial result")

    def test_scheduled_collection_does_not_launch_unaccounted_external_tools(self):
        with patch.object(server, "_passive_crtsh", return_value=[]), \
             patch.object(server, "_run_tool", side_effect=AssertionError("external tool must not run")) as external:
            job = server.submit_collect(passive=True, probe=False)
            finished = self.terminal(job["job_id"])
        self.assertEqual(finished["state"], "DONE", finished)
        external.assert_not_called()
        self.assertTrue(any("external traffic cannot be budgeted" in p for p in finished["progress"]))


if __name__ == "__main__":
    unittest.main()
