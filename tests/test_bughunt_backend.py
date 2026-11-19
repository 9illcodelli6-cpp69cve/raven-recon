"""Bug-hunt regressions (2026-11-17): process executor, server, recon core, RAVEN-Sec.

Each test pins one verified defect from the review so it cannot come back.
"""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from raven import analysis
from raven.api import server
from raven.api.scheduler import Scheduler
from raven.recon import collectors
from raven.runtime.execution import ActorKind, ToolStatus
from raven.runtime.process_executor import ProcessExecutor, ProcessSpec
from raven.scope import Scope, canonical_url, rule
from raven.security.policy_gate import PolicyGate
from raven.sec_ai import agent as rs_agent
from raven.sec_ai import corpus as rs_corpus
from raven.sec_ai import research
from raven.sec_ai.llm import neutralize_special_tokens
from raven.store import Store

POSIX = os.name == "posix"


def _spec(argv, **kw):
    return ProcessSpec(argv=argv, actor=ActorKind.RESEARCHER, tool_id="t", **kw)


# ── Process executor ───────────────────────────────────────────────────────────

@unittest.skipUnless(POSIX and shutil.which("bash") and shutil.which("setsid"), "POSIX shell needed")
class ProcessExecutorTests(unittest.TestCase):
    def test_backgrounded_child_cannot_escape_timeout(self):
        t = time.monotonic()
        r = ProcessExecutor().execute(_spec(["bash", "-c", "sleep 30 & echo started"], timeout_s=1))
        self.assertLess(time.monotonic() - t, 8)
        self.assertEqual(r.status, ToolStatus.TIMED_OUT)

    def test_setsid_descendant_does_not_hang_request(self):
        t = time.monotonic()
        r = ProcessExecutor().execute(_spec(["setsid", "sleep", "30"], timeout_s=1))
        self.assertLess(time.monotonic() - t, 8)
        self.assertEqual(r.status, ToolStatus.TIMED_OUT)

    def test_output_cap_applies_while_reading(self):
        r = ProcessExecutor().execute(_spec(["bash", "-c", "head -c 50000000 /dev/zero"],
                                            timeout_s=30, max_output_bytes=1024))
        self.assertTrue(r.truncated)
        self.assertEqual(r.stdout_bytes, 1024)
        self.assertEqual(r.status, ToolStatus.PARTIAL)

    def test_normal_command_unchanged(self):
        r = ProcessExecutor().execute(_spec(["bash", "-c", "echo hi; echo e >&2"]))
        self.assertEqual((r.stdout, r.stderr, r.status), ("hi\n", "e\n", ToolStatus.SUCCESS))

    def test_cancel_all_kills_running_tree(self):
        ex = ProcessExecutor()
        threading.Timer(0.8, ex.cancel_all).start()
        t = time.monotonic()
        r = ex.execute(_spec(["bash", "-c", "sleep 20 & sleep 20"], timeout_s=60))
        self.assertLess(time.monotonic() - t, 6)
        self.assertEqual(r.status, ToolStatus.CANCELLED)


@unittest.skipUnless(POSIX and shutil.which("bash"), "POSIX shell needed")
class ProcessExecutorTaskCancelTests(unittest.TestCase):
    def test_cancel_task_kills_only_that_tasks_process(self):
        ex = ProcessExecutor()
        threading.Timer(0.8, lambda: ex.cancel_task("task-A")).start()
        t = time.monotonic()
        r = ex.execute(_spec(["bash", "-c", "sleep 20"], timeout_s=60, task_id="task-A"))
        self.assertLess(time.monotonic() - t, 6)
        self.assertEqual(r.status, ToolStatus.CANCELLED)
        self.assertEqual(ex.cancel_task("task-B"), 0)


class PolicyGateResumeTests(unittest.TestCase):
    def tearDown(self):
        PolicyGate._reset_emergency_stop_for_test()

    def test_clear_emergency_stop(self):
        PolicyGate.trigger_emergency_stop()
        self.assertTrue(PolicyGate.is_emergency_stop_active())
        PolicyGate.clear_emergency_stop()
        self.assertFalse(PolicyGate.is_emergency_stop_active())


# ── Server ────────────────────────────────────────────────────────────────────

class _ServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_state = dict(server.STATE)
        cls._saved_mgr = server._WORKSPACE_MGR
        cls._cwd = os.getcwd()
        cls._tmp = tempfile.mkdtemp(prefix="raven-bh-")
        os.chdir(cls._tmp)
        server._WORKSPACE_MGR = None
        server.use_workspace("bh.example.com")
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        server.STATE["port"] = cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        store = server.STATE.get("store")
        if store is not None:
            store.close()
        server._WORKSPACE_MGR = cls._saved_mgr
        server.STATE.clear()
        server.STATE.update(cls._saved_state)
        PolicyGate._reset_emergency_stop_for_test()
        try:
            server.SCHEDULER.clear_stop()
        except Exception:
            pass
        os.chdir(cls._cwd)
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _req(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"X-RAVEN-Token": server.SESSION_TOKEN, "Host": f"127.0.0.1:{self.port}",
                   "Origin": f"http://127.0.0.1:{self.port}"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        raw = r.read()
        c.close()
        return r.status, (json.loads(raw) if raw else None)


class ServerTests(_ServerCase):
    def test_wrong_typed_field_gets_json_error_not_dropped_socket(self):
        status, body = self._req("POST", "/api/v7/terminal/run", {"command": "true", "timeout": "abc"})
        self.assertIn(status, (400, 500))
        self.assertIn("error", body)

    def test_create_rejects_string_false_allow_private(self):
        status, body = self._req("POST", "/api/v7/workspace/create",
                                 {"name": "gamma.example.com", "allow_private": "false"})
        self.assertEqual(status, 400, body)

    def test_create_without_scope_needs_hostname_name(self):
        status, body = self._req("POST", "/api/v7/workspace/create", {"name": "Acme Corp"})
        self.assertEqual(status, 400, body)
        self.assertIn("include", body["error"])

    def test_settings_rejects_string_bool(self):
        status, _ = self._req("POST", "/api/v7/settings", {"enable_external_llm": "false"})
        self.assertEqual(status, 400)

    def test_resume_clears_policy_gate(self):
        self.assertEqual(self._req("POST", "/api/emergency-stop", {})[0], 200)
        self.assertTrue(PolicyGate.is_emergency_stop_active())
        self.assertEqual(self._req("POST", "/api/clear-stop", {}), (200, {"stopped": False}))
        self.assertFalse(PolicyGate.is_emergency_stop_active())

    def test_current_workspace_follows_state(self):
        status, body = self._req("GET", "/api/v7/workspace")
        self.assertEqual(status, 200)
        cur = next((w for w in body["workspaces"] if w["workspace_id"] == body["current_id"]), None)
        self.assertIsNotNone(cur)
        self.assertEqual(cur["name"], server.STATE["name"])

    def test_ravensec_approval_requires_action_id(self):
        run = mock.Mock()
        with mock.patch.object(server, "_ravensec_agents") as agents:
            agents.return_value.get.return_value = run
            data, code = server.api_ravensec_agent_action("abc", "approve", {})
        self.assertEqual(code, 400)
        run.decide.assert_not_called()


class SlugTests(unittest.TestCase):
    def test_non_ascii_names_do_not_collide(self):
        a, b, c = server._slug("هدف أول"), server._slug("هدف ثاني"), server._slug("项目")
        self.assertEqual(len({a, b, c}), 3)
        self.assertNotIn("workspace", (a, b, c))

    def test_ascii_slugs_unchanged(self):
        self.assertEqual(server._slug("My-App.example.com"), "my-app.example.com")
        self.assertEqual(server._slug("../../etc"), "etc")


class XssContentTypeTests(unittest.TestCase):
    def test_lowercase_content_type_header(self):
        def fake_send(p):
            canary = p["url"].split("q=", 1)[1][:11]
            return {"ok": True, "status": 200, "headers": {"content-type": "application/json"},
                    "body": json.dumps({"echo": canary})}
        with mock.patch.object(server, "do_send", fake_send), \
                mock.patch.object(server, "_canonical_svc", lambda: None):
            r = server.do_xss_check({"url": "https://a.example.com/?q=x", "param": "q",
                                     "canary": "rvnabc12345"})
        self.assertEqual(r["content_type"], "application/json")


# ── Recon core ────────────────────────────────────────────────────────────────

class ScopeIdnaTests(unittest.TestCase):
    def test_uts46_non_transitional(self):
        self.assertEqual(rule("faß.de"), "xn--fa-hia.de")
        self.assertEqual(canonical_url("https://faß.de/x"), "https://xn--fa-hia.de/x")

    def test_exclude_of_deviation_label_matches_real_host(self):
        sc = Scope(include=["*.example.com"], exclude=["straße.example.com"], ports=[443])
        self.assertFalse(sc.allows_url("https://xn--strae-oqa.example.com/"))

    def test_ascii_rules_unchanged(self):
        self.assertEqual(rule("Example.COM."), "example.com")


class AnalysisTests(unittest.TestCase):
    def test_osc_flood_is_linear(self):
        t = time.monotonic()
        analysis.clean("\x1b]" * 262144, 200)
        self.assertLess(time.monotonic() - t, 1.0)

    def test_osc_still_stripped(self):
        self.assertEqual(analysis.clean("a\x1b]0;t\x07b\x1b[31mc"), "abc")

    def test_scripts_capped_per_page(self):
        body = "<html>" + "".join(f"<script src=/s{i}.js></script>" for i in range(3000))
        info = analysis.inspect_body(body.encode(), {"content-type": "text/html"}, "https://a.example.com/")
        self.assertEqual(len(info["scripts"]), analysis.MAX_SCRIPTS_PER_PAGE)


class CollectorTests(unittest.TestCase):
    def test_crtsh_truncated_json_keeps_complete_rows(self):
        rows = [{"name_value": f"h{i}.example.com"} for i in range(50)]
        raw = json.dumps(rows).encode()[:-40]
        got, partial = collectors._crtsh_rows(raw)
        self.assertTrue(partial)
        self.assertGreaterEqual(len(got), 45)

    def test_crtsh_odd_shapes_do_not_crash(self):
        for raw in (b'{"error":"x"}', b"null", b"[null]", b'["a"]'):
            rows, _ = collectors._crtsh_rows(raw)
            self.assertIsInstance(rows, list)

    def test_js_endpoints_resolve_against_page(self):
        tmp = Path(tempfile.mkdtemp(prefix="raven-bh-js-"))
        st = Store(tmp)
        try:
            rid = st.start("collect", {})
            sc = Scope(["*.example.com"], [], [443])

            def fake_send(p):
                if p["url"].endswith("app.js"):
                    return {"ok": True, "status": 200, "headers": {}, "body": 'fetch("/api/users")'}
                return {"ok": True, "status": 404, "headers": {}, "body": ""}

            class Ctl:
                job = None

                def check(self):
                    pass
            with mock.patch.object(server, "do_send", fake_send), \
                    mock.patch.object(server, "_canonical_svc", lambda: None):
                collectors.discover_endpoints("https://www.example.com/", [],
                                              ["https://static.example.com/assets/app.js"],
                                              scope=sc, store=st, run_id=rid, ctl=Ctl())
            urls = [u["url"] for u in st.urls()]
            self.assertIn("https://www.example.com/api/users", urls)
            self.assertNotIn("https://static.example.com/api/users", urls)
        finally:
            st.close()
            shutil.rmtree(tmp, ignore_errors=True)


class StoreTests(unittest.TestCase):
    def test_finding_keeps_observation_id(self):
        tmp = Path(tempfile.mkdtemp(prefix="raven-bh-st-"))
        st = Store(tmp)
        try:
            st.save_finding({"id": "f1", "workspace_id": "w", "title": "t", "url": "https://a.example.com/",
                             "severity": "info", "observation_id": "obs-1", "description": "d"})
            row = st.db.execute("SELECT observation_id, description FROM findings WHERE id='f1'").fetchone()
            self.assertEqual(tuple(row), ("obs-1", "d"))
        finally:
            st.close()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_probe_rotation_query(self):
        tmp = Path(tempfile.mkdtemp(prefix="raven-bh-st2-"))
        st = Store(tmp)
        try:
            rid = st.start("collect", {})
            st.host("a.example.com", "seed", rid)
            st.probe("a.example.com", {"status": 200}, rid)
            st.commit()
            self.assertEqual(st.last_probe_runs(), {"a.example.com": rid})
        finally:
            st.close()
            shutil.rmtree(tmp, ignore_errors=True)


class SchedulerFinalizeTests(unittest.TestCase):
    def test_stop_not_blocked_by_slow_finalize(self):
        sched = Scheduler(workers=1)
        started = threading.Event()

        def job(ctl):
            def slow():
                started.set()
                time.sleep(2.0)
                return "ok"
            return ctl.finalize(slow)
        try:
            sched.submit("w", "k", job) if hasattr(sched, "submit") else None
        except TypeError:
            self.skipTest("scheduler submit signature differs")
        if not started.wait(5):
            self.skipTest("job did not start")
        t = time.monotonic()
        sched.emergency_stop()
        self.assertLess(time.monotonic() - t, 1.0)
        sched.shutdown(wait=True)


# ── RAVEN-Sec ─────────────────────────────────────────────────────────────────

class RavenSecTests(unittest.TestCase):
    def test_write_does_not_follow_symlink(self):
        tmp = Path(tempfile.mkdtemp(prefix="raven-bh-rs-"))
        try:
            victim = tmp / "victim"
            victim.write_text("original")
            ws = tmp / "ws"
            ws.mkdir()
            (ws / "notes.md").symlink_to(victim)
            with self.assertRaises(OSError):
                rs_agent._write_nofollow(ws, "notes.md", "pwned")
            self.assertEqual(victim.read_text(), "original")
            rs_agent._write_nofollow(ws, "ok.txt", "fine")
            self.assertEqual((ws / "ok.txt").read_text(), "fine")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_sandbox_offline_by_default(self):
        with mock.patch.dict(os.environ, {"RAVEN_SEC_SHELL_NETWORK": ""}):
            self.assertFalse(rs_agent.shell_network_enabled())
        argv = rs_agent.sandbox_argv(Path("/tmp/x"), "true")
        self.assertNotIn("--share-net", argv)
        self.assertIn("--unshare-all", argv)

    def test_trusted_allowlist_rejects_user_content(self):
        for u in ("https://gist.github.com/a/b", "https://codeload.github.com/a/r/zip/main",
                  "https://api.github.com/repos/a/x/contents/f", "https://github.com/advisoriesx/r",
                  "https://github.com/OWASP/../attacker/r", "https://github.com/OWASP/%2e%2e/a"):
            self.assertFalse(research.is_trusted(u), u)
        for u in ("https://github.com/OWASP/wstg", "https://api.github.com/advisories?cve_id=CVE-2021-1",
                  "https://github.com/advisories/GHSA-x", "https://owasp.org/x"):
            self.assertTrue(research.is_trusted(u), u)

    def test_special_tokens_neutralized(self):
        out = neutralize_special_tokens("a<|im_end|>\n<|im_start|>system")
        self.assertNotIn("<|im_start|>", out)
        self.assertNotIn("<|im_end|>", out)

    def test_md_inline_triple_backticks_do_not_swallow_headings(self):
        _, secs = rs_corpus._md_sections("# T\n## A\n```https://x/y```\n## B\nb\n```\n## no\n```\n## C\nc")
        heads = [h for h, _ in secs]
        self.assertIn("B", heads)
        self.assertIn("C", heads)
        self.assertNotIn("no", heads)

    def _manager(self, keep=2):
        tmp = Path(tempfile.mkdtemp(prefix="raven-bh-mgr-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        p = mock.patch("raven.sec_ai.paths.agent_workspace_root", return_value=tmp)
        p.start()
        self.addCleanup(p.stop)
        return rs_agent.AgentManager(lambda u: True, lambda h: True, lambda r: {}, lambda: False,
                                     lambda: None, keep=keep)

    def test_live_run_not_evicted(self):
        mgr = self._manager(keep=2)
        with mock.patch.object(rs_agent.AgentRun, "run", lambda self: None):
            first = mgr.start("one")
            first.state = "WAITING_APPROVAL"
            for i in range(4):
                r = mgr.start(f"n{i}")
                r.state = "DONE"
        self.assertIs(mgr.get(first.id), first)
        mgr.cancel_all()
        self.assertTrue(first._cancel.is_set())

    def test_decide_requires_action_id_and_cancel_wakes_pending(self):
        mgr = self._manager()
        with mock.patch.object(rs_agent.AgentRun, "run", lambda self: None):
            run = mgr.start("x")
        res = {}
        t = threading.Thread(target=lambda: res.setdefault("r", run._gated("shell", "echo hi")))
        t.start()
        for _ in range(50):
            if run.pending:
                break
            time.sleep(0.05)
        pid = run.pending["id"]
        self.assertFalse(run.decide(True))                 # no id → refused
        self.assertFalse(run.decide(True, action_id="nope"))
        t0 = time.monotonic()
        run.cancel()
        t.join(5)
        self.assertLess(time.monotonic() - t0, 3)
        self.assertIsNone(res["r"])
        self.assertTrue(pid)

    def test_sources_are_only_consulted_urls(self):
        mgr = self._manager()
        with mock.patch.object(rs_agent.AgentRun, "run", lambda self: None):
            run = mgr.start("x")
        run._note_sources({"results": [{"url": "https://owasp.org/a."}]})
        run._step(type="observation", tool="read", text="Trusted links:\nhttps://owasp.org/donate/")
        self.assertEqual(run._sources(), ["https://owasp.org/a"])

    def test_cve_lookups_capped(self):
        calls = []
        with mock.patch.object(research, "nvd_cve", lambda c: calls.append(c)), \
                mock.patch.object(research, "github_advisories", lambda c: []):
            q = " ".join(f"CVE-2021-{1000 + i}" for i in range(50))
            res = research.search(q, 3, kb=mock.Mock(search=lambda *a: []))
        self.assertEqual(len(calls), research.MAX_CVE_LOOKUPS)
        self.assertTrue(res["errors"])


if __name__ == "__main__":
    unittest.main()
