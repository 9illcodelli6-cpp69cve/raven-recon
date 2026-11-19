"""Database-concurrency tests (V4 Stage 1).

Prove that the Store is thread-safe, that a running collection (network I/O) does NOT
block API reads, that integrity checks pass, and that shutdown/crash paths are safe.
No external targets — collection network I/O is stubbed.

Run:  python -m unittest tests.test_concurrency -v
"""
import os
import tempfile
import threading
import time
import unittest

from raven.api import server
from raven.scope import Scope
from raven.store import Store


class StoreConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="raven-db-")
        self.store = Store(__import__("pathlib").Path(self._tmp) / "ws")

    def tearDown(self):
        self.store.close()

    def test_store_is_thread_safe(self):
        rid = self.store.start("t", {})
        errors = []

        def worker(n):
            try:
                for i in range(25):
                    self.store.host(f"h{n}-{i}.a.test", "w", rid)
                    self.store.assets()  # concurrent read
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.store.commit()
        self.assertEqual(errors, [])
        self.assertEqual(len(self.store.assets()), 8 * 25)

    def test_integrity_check_ok(self):
        rid = self.store.start("t", {})
        self.store.host("x.a.test", "w", rid)
        self.store.commit()
        self.assertEqual(self.store.integrity_check(), "ok")

    def test_operations_after_close_do_not_corrupt(self):
        self.store.close()
        with self.assertRaises(Exception):
            self.store.start("t", {})  # closed connection raises, does not hang/corrupt


class CollectDoesNotBlockReadsTests(unittest.TestCase):
    """The key regression: a slow collection must not block DB reads."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-cc-")
        os.chdir(self._tmp)
        self._saved = dict(server.STATE)
        self._probe = server._probe_host
        server.STATE["scope"] = Scope(include=["a.test", "*.a.test"], exclude=[], ports=[80, 443])
        server.use_workspace("cc")
        rid = server.STATE["store"].start("seed", {})
        for h in ("a.test", "b.a.test", "c.a.test"):
            server.STATE["store"].host(h, "seed", rid)
        server.STATE["store"].commit()

    def tearDown(self):
        server._probe_host = self._probe
        os.chdir(self._cwd)
        server.STATE.clear()
        server.STATE.update(self._saved)

    def test_reads_not_blocked_by_slow_collect(self):
        # Simulate slow network probing (no DB lock held during it).
        def slow(host):
            time.sleep(0.5)
            return {"status": 200, "title": "", "server": "", "final_url": f"https://{host}/",
                    "body_hash": "", "error": "", "elapsed_ms": 500, "scripts": []}
        server._probe_host = slow

        done = []
        collector = threading.Thread(target=lambda: (server.do_collect(passive=False, probe=True), done.append(1)))
        collector.start()
        time.sleep(0.2)  # collection is mid-flight, sleeping in probe (no lock held)
        t0 = time.monotonic()
        summary = server.data_summary()   # must return promptly
        read_ms = (time.monotonic() - t0) * 1000
        collector.join(timeout=15)
        self.assertTrue(done, "collection did not finish")
        self.assertIsInstance(summary, dict)
        self.assertLess(read_ms, 300, f"read blocked for {read_ms:.0f}ms during collect")


if __name__ == "__main__":
    unittest.main(verbosity=2)
