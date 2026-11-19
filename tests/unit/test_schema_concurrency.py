"""Stage 2: Concurrency tests.

Verifies that the Store's RLock correctly serializes concurrent DB access:
- Parallel observation inserts produce no lost rows
- Parallel finding inserts produce no duplicate UUIDs
- RLock is reentrant (nested with store._lock works)
- No partial rows or shared-cursor corruption
"""
import pathlib
import tempfile
import threading
import uuid

import pytest

from raven.store import Store


def uid():
    return uuid.uuid4().hex


@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as d:
        s = Store(pathlib.Path(d))
        try:
            yield s
        finally:
            s.close()


def _insert_observation(store, results, errors, index):
    oid = uid()
    try:
        with store._lock:
            store.db.execute(
                "INSERT INTO observations(id,workspace_id,url,method) VALUES(?,?,?,?)",
                (oid, uid(), f"https://t.example/path/{index}", "GET"),
            )
            store.db.commit()
        results.append(oid)
    except Exception as e:
        errors.append(e)


def _insert_finding(store, wid, results, errors, index):
    fid = uid()
    try:
        with store._lock:
            store.db.execute(
                "INSERT INTO findings(id,workspace_id,title,url,severity,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (fid, wid, f"finding-{index}", f"https://t.example/f{index}",
                 "info", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
            store.db.commit()
        results.append(fid)
    except Exception as e:
        errors.append(e)


class TestConcurrency:

    def test_parallel_observation_inserts_no_lost_rows(self, store):
        n = 20
        results, errors = [], []
        threads = [
            threading.Thread(target=_insert_observation, args=(store, results, errors, i))
            for i in range(n)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"Errors during parallel inserts: {errors}"
        assert len(results) == n, f"Expected {n} rows, got {len(results)}"
        count = store.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        assert count == n

    def test_parallel_finding_inserts_no_duplicate_ids(self, store):
        n = 20
        wid = uid()
        results, errors = [], []
        threads = [
            threading.Thread(target=_insert_finding, args=(store, wid, results, errors, i))
            for i in range(n)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"Errors during parallel inserts: {errors}"
        assert len(results) == n
        assert len(set(results)) == n, "Duplicate UUIDs detected"
        count = store.db.execute(
            "SELECT COUNT(*) FROM findings WHERE workspace_id=?", (wid,)
        ).fetchone()[0]
        assert count == n

    def test_rlock_is_reentrant(self, store):
        # Nested with store._lock should not deadlock
        result = []
        def work():
            with store._lock:
                with store._lock:  # reentrant
                    result.append("ok")
        t = threading.Thread(target=work)
        t.start()
        t.join(timeout=5)
        assert result == ["ok"], "RLock must support reentrant acquisition"

    def test_parallel_evidence_inserts_no_lost_rows(self, store):
        fid = uid()
        wid = uid()
        with store._lock:
            store.db.execute(
                "INSERT INTO findings(id,workspace_id,title,url,severity,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (fid, wid, "t", "https://t.example/", "info",
                 "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
            store.db.commit()

        n = 15
        errors = []

        def insert_ev(i):
            try:
                with store._lock:
                    store.db.execute(
                        "INSERT INTO evidence(id,workspace_id,finding_id,kind,summary)"
                        " VALUES(?,?,?,?,?)",
                        (uid(), wid, fid, "reflection", f"ev-{i}"),
                    )
                    store.db.commit()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=insert_ev, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        count = store.db.execute(
            "SELECT COUNT(*) FROM evidence WHERE finding_id=?", (fid,)
        ).fetchone()[0]
        assert count == n

    def test_reads_during_writes_ok(self, store):
        wid = uid()
        write_errors, read_errors = [], []
        gate = threading.Event()

        def writer(i):
            gate.wait()
            try:
                with store._lock:
                    store.db.execute(
                        "INSERT INTO findings(id,workspace_id,title,url,severity,"
                        "created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                        (uid(), wid, f"f{i}", "https://t.example/", "info",
                         "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
                    )
                    store.db.commit()
            except Exception as e:
                write_errors.append(e)

        def reader():
            gate.wait()
            try:
                with store._lock:
                    store.db.execute("SELECT COUNT(*) FROM findings").fetchone()
            except Exception as e:
                read_errors.append(e)

        threads = ([threading.Thread(target=writer, args=(i,)) for i in range(10)]
                   + [threading.Thread(target=reader) for _ in range(5)])
        for t in threads:
            t.start()
        gate.set()
        for t in threads:
            t.join()
        assert not write_errors
        assert not read_errors
