"""Learning page — live route over raven/learning (post-Linux-port development).

Locks in:
  * the self-assessment runs RAVEN's REAL exam categories, in-process, with no
    network access;
  * domains without an exam are NO_EXAM with accuracy None — the old fabricated
    8/10 ("80% DEVELOPING") placeholder is gone, from the page AND the
    SelfStudyLoop — and they keep graduation_ready False;
  * results persist (DATA_ROOT/learning_mastery.json) and survive a "restart";
  * Emergency Stop refuses / halts an assessment and nothing is recorded;
  * lessons are the ACTIVE workspace's KB entries of kind=lesson only;
  * the shared table renderer HTML-escapes cell values (target-derived strings).
"""
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from raven.api import contracts, server
from raven.learning import assessment as la
from raven.learning.curriculum import (
    DOMAIN_EXAMS, DOMAINS_WITHOUT_EXAM, SelfStudyLoop, StudyCycleState,
)
from raven.learning.mastery import KnowledgeDomain, SecurityMasteryMatrix

REPO = Path(__file__).resolve().parent.parent


class _NoNetwork:
    """Any socket use inside the block fails the test."""

    def __enter__(self):
        self._saved = (socket.socket.connect, socket.create_connection, socket.getaddrinfo)

        def deny(*a, **k):
            raise AssertionError("network access during learning assessment")
        socket.socket.connect = deny
        socket.create_connection = deny
        socket.getaddrinfo = deny
        return self

    def __exit__(self, *exc):
        socket.socket.connect, socket.create_connection, socket.getaddrinfo = self._saved
        return False


class AssessmentEngineTests(unittest.TestCase):
    def test_runs_real_exams_without_network(self):
        with _NoNetwork():
            snap = la.run_assessment()
        self.assertEqual({e["exam_id"] for e in snap["exams"]}, set(DOMAIN_EXAMS.values()))
        for e in snap["exams"]:
            self.assertGreater(e["n_total"], 0, e["exam_id"])
            self.assertIsNone(e["error"], e["exam_id"])

    def test_no_exam_domains_are_never_scored(self):
        snap = la.run_assessment()
        rows = {r["domain"]: r for r in snap["domains"]}
        self.assertEqual(len(rows), len(KnowledgeDomain))
        for d in DOMAINS_WITHOUT_EXAM:
            self.assertEqual(rows[d.value]["status"], la.NO_EXAM)
            self.assertIsNone(rows[d.value]["accuracy"])
            self.assertIsNone(rows[d.value]["mastery_level"])
        for d in DOMAIN_EXAMS:
            self.assertEqual(rows[d.value]["status"], la.EVALUATED)
            self.assertIsNotNone(rows[d.value]["accuracy"])
        # Graduation needs every domain evaluated; NO_EXAM domains block it.
        if DOMAINS_WITHOUT_EXAM:
            self.assertFalse(snap["graduation_ready"])

    def test_failed_exam_counts_as_failure_not_pass(self):
        from unittest import mock
        with mock.patch.object(la, "run_exam", side_effect=RuntimeError("boom")):
            snap = la.run_assessment()
        for e in snap["exams"]:
            self.assertEqual((e["n_pass"], e["n_total"]), (0, 1))
            self.assertIn("boom", e["error"])
        self.assertTrue(snap["gaps"])  # every examined domain is now a gap

    def test_emergency_stop_halts_and_records_nothing(self):
        calls = {"n": 0}

        def stop_after_first():
            calls["n"] += 1
            return calls["n"] > 1
        tmp = Path(tempfile.mkdtemp())
        try:
            store = la.MasteryStore(tmp / "m.json")
            with self.assertRaises(la.AssessmentStopped):
                la.assess_and_store(store, should_stop=stop_after_first)
            self.assertFalse((tmp / "m.json").exists())
        finally:
            shutil.rmtree(tmp)


class SelfStudyLoopHonestyTests(unittest.TestCase):
    def test_no_fabricated_score_for_domains_without_exam(self):
        loop = SelfStudyLoop(SecurityMasteryMatrix())
        for d in DOMAINS_WITHOUT_EXAM:
            self.assertEqual(loop.run_domain_exam(d), (0, 0))

    def test_loop_pauses_instead_of_graduating_with_untestable_domains(self):
        matrix = SecurityMasteryMatrix()
        loop = SelfStudyLoop(matrix, threshold=0.85, max_cycles=50)
        results = loop.run_until_graduation()
        self.assertTrue(results)
        if DOMAINS_WITHOUT_EXAM:
            self.assertEqual(loop.state, StudyCycleState.PAUSED)
            for d in DOMAINS_WITHOUT_EXAM:
                self.assertEqual(matrix.get_domain(d).n_evaluated, 0)


class MasteryStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = la.MasteryStore(self.tmp / "learning_mastery.json")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_missing_and_corrupt_read_as_never_assessed(self):
        self.assertEqual(self.store.load(), {"latest": None, "history": []})
        self.store.path.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.store.load(), {"latest": None, "history": []})

    def test_roundtrip_and_history_cap(self):
        snap = la.run_assessment()
        for _ in range(la.HISTORY_LIMIT + 3):
            self.store.save(snap)
        state = la.MasteryStore(self.store.path).load()  # fresh instance = restart
        self.assertEqual(state["latest"]["assessed_at"], snap["assessed_at"])
        self.assertEqual(len(state["history"]), la.HISTORY_LIMIT)
        self.assertFalse(list(self.tmp.glob(".learning-*")))  # no temp leftovers


class LearningRouteTests(unittest.TestCase):
    _SINGLETONS = ("_KB", "_LEARNING_STORE")

    def setUp(self):
        self._saved_state = dict(server.STATE)
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-learning-")
        os.chdir(self._tmp)
        self._saved = {n: getattr(server, n) for n in self._SINGLETONS}
        for n in self._SINGLETONS:
            setattr(server, n, None)
        server.use_workspace("learningtest")

    def tearDown(self):
        if server.SCHEDULER.stopped.is_set():
            server.SCHEDULER.clear_stop()
        store = server.STATE.get("store")
        if store is not None:
            try:
                store.close()
            except Exception:
                pass
        for n, v in self._saved.items():
            setattr(server, n, v)
        server.STATE.clear()
        server.STATE.update(self._saved_state)
        os.chdir(self._cwd)
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _conforms(self, endpoint, data):
        c = contracts.CONTRACTS[endpoint]
        self.assertFalse(set(c["required"]) - set(data), "missing required keys")
        self.assertFalse(set(data) - set(c["required"]) - set(c["optional"]),
                         "undeclared keys")

    def test_get_before_any_assessment_is_honest_empty(self):
        data, code = server.api_learning_get()
        self.assertEqual(code, 200)
        self._conforms("GET /api/v7/learning", data)
        self.assertEqual(data["status"], contracts.STATUS_EMPTY)
        self.assertIsNone(data["assessed_at"])
        self.assertEqual(data["authority"], "NONE")
        self.assertTrue(data["resources"])
        self.assertTrue(all(d["accuracy"] is None for d in data["domains"]))

    def test_assess_persists_and_survives_restart(self):
        data, code = server.api_learning_assess({})
        self.assertEqual(code, 200)
        self._conforms("POST /api/v7/learning/assess", data)
        self.assertEqual(data["status"], contracts.STATUS_READY)
        self.assertTrue(Path(self._tmp, "learning_mastery.json").is_file())
        server._LEARNING_STORE = None  # simulate an app restart
        again, _ = server.api_learning_get()
        self.assertEqual(again["status"], contracts.STATUS_READY)
        self.assertEqual(again["assessed_at"], data["assessed_at"])
        self.assertEqual(len(again["history"]), 1)

    def test_assess_refused_during_emergency_stop(self):
        server.SCHEDULER.emergency_stop()
        data, code = server.api_learning_assess({})
        self.assertEqual(code, 409)
        self.assertEqual(data["error"], "emergency_stop")
        self._conforms("POST /api/v7/learning/assess", data)
        self.assertFalse(Path(self._tmp, "learning_mastery.json").exists())

    def test_assess_refused_while_running(self):
        self.assertTrue(la._RUN_LOCK.acquire(blocking=False))
        try:
            data, code = server.api_learning_assess({})
        finally:
            la._RUN_LOCK.release()
        self.assertEqual((code, data["error"]), (409, "busy"))

    def test_lessons_are_active_workspace_lessons_only(self):
        from raven.knowledge_os.knowledge_base import KnowledgeEntry, KnowledgeKind
        kb = server._ensure_kb()
        ws = server._ev_know_ws_id()
        kb.store(KnowledgeEntry(kind=KnowledgeKind.LESSON, title="mine",
                                body="lesson body", workspace_id=ws))
        kb.store(KnowledgeEntry(kind=KnowledgeKind.LESSON, title="other-ws",
                                body="x", workspace_id="some-other-workspace"))
        kb.store(KnowledgeEntry(kind=KnowledgeKind.CONCEPT, title="not-a-lesson",
                                body="x", workspace_id=ws))
        data, _ = server.api_learning_get()
        self.assertEqual([l["title"] for l in data["lessons"]], ["mine"])
        self.assertEqual(data["lessons"][0]["summary"], "lesson body")


class LearningUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (REPO / "web" / "index.html").read_text(encoding="utf-8")

    def test_page_is_wired(self):
        self.assertIn("learning:loadLearning", self.html)
        self.assertIn("_RAV.get('/api/v7/learning')", self.html)
        self.assertIn("_RAV.post('/api/v7/learning/assess'", self.html)
        self.assertNotIn("not wired to this page", self.html)

    def test_table_renderer_escapes_cells(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        start = self.html.index("function _cellText(")
        end = self.html.index("function _setPage(")
        js = self.html[start:end] + (
            "\nprocess.stdout.write(_tableFrom(['a'],"
            "[{a:'<img src=x onerror=alert(1)>\"&\\''}],'<b>empty</b>'));"
            "\nprocess.stdout.write('\\n'+_tableFrom(['a'],[],'<i>e</i>'));")
        out = subprocess.run([node, "-e", js], capture_output=True, text=True,
                             timeout=30, check=True).stdout
        self.assertNotIn("<img", out)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;&quot;&amp;&#39;", out)
        self.assertNotIn("<i>", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
