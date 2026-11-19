"""Claude (Anthropic API) integration — keystore, skills, tools, agent loop, chat adapter,
server routes. A fake Anthropic client is used: no network, no key, no cost."""
import copy  # noqa: F401
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest import mock

from raven.claude import MODEL, client as cl
from raven.claude import skills as sk
from raven.claude.agent import ClaudeAgentRun
from raven.claude.keystore import KeyStore, KeyStoreError, hint
from raven.claude.tools import TOOL_DEFS, ToolBox
from raven.runtime.process_executor import SENSITIVE_ENV_VARS

GOOD_KEY = "sk-ant-api03-" + "A" * 40 + "xyz9"


class KeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="raven-ks-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ks = KeyStore(self.tmp)

    def test_roundtrip_encrypted_and_private(self):
        self.assertEqual(self.ks.save(GOOD_KEY), hint(GOOD_KEY))
        self.assertEqual(self.ks.load(), GOOD_KEY)
        for f in (self.ks.secret, self.ks.blob):
            self.assertEqual(oct(f.stat().st_mode & 0o777), "0o600")
            self.assertNotIn(GOOD_KEY.encode(), f.read_bytes())
        self.assertEqual(oct(self.ks.dir.stat().st_mode & 0o777), "0o700")

    def test_rejects_bad_and_admin_keys(self):
        for bad in ("", "hello", "sk-ant-short", "sk-ant-admin01-" + "B" * 40):
            with self.assertRaises(KeyStoreError):
                self.ks.save(bad)

    def test_delete_and_corrupt_blob(self):
        self.ks.save(GOOD_KEY)
        self.assertTrue(self.ks.delete())
        self.assertIsNone(self.ks.load())
        self.ks.save(GOOD_KEY)
        self.ks.blob.write_bytes(b"garbage")
        self.assertIsNone(self.ks.load())          # never raises to callers

    def test_key_never_reaches_child_processes(self):
        self.assertIn("ANTHROPIC_API_KEY", SENSITIVE_ENV_VARS)
        self.assertIn("ANTHROPIC_AUTH_TOKEN", SENSITIVE_ENV_VARS)


class SkillsTests(unittest.TestCase):
    def test_parse_index_and_load(self):
        d = Path(tempfile.mkdtemp(prefix="raven-sk-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "api-recon").mkdir()
        (d / "api-recon" / "SKILL.md").write_text("---\nname: api-recon\ndescription: Map an API.\n---\n# Body\nsteps")
        (d / "bad").mkdir()
        (d / "bad" / "SKILL.md").write_text("---\nname: other-name\n---\nx")   # name/folder mismatch → ignored
        self.assertEqual(sk.index(d), [{"name": "api-recon", "description": "Map an API."}])
        self.assertIn("steps", sk.load("api-recon", d))
        self.assertIsNone(sk.load("../etc", d))
        self.assertIsNone(sk.load("bad", d))


class ShippedSkillsTests(unittest.TestCase):
    EXPECTED = {"api-recon", "api-security", "browser-testing", "code-audit", "patch-diff",
                "php-lfi-rce", "recon-breadth"}

    def test_shipped_skills_load_and_are_ravens_own(self):
        idx = {s["name"]: s["description"] for s in sk.index()}
        self.assertEqual(set(idx), self.EXPECTED)
        for name in idx:
            self.assertTrue(idx[name], name)
            body = sk.load(name)
            self.assertGreater(len(body), 1500, name)
            self.assertNotIn("ARTEX", body)              # clean-room rewrite, no copied text
        self.assertNotIn("edr", " ".join(idx).lower())   # no EDR/AV-evasion playbook by design


def _ctx(**over):
    ctx = {"scope_dict": lambda: {"include": ["app.example.com"], "exclude": [], "ports": [443]},
           "scope_url": lambda u: "app.example.com" in u, "scope_host": lambda h: h == "app.example.com",
           "send": lambda req: {"ok": True, "status": 200, "reason": "OK", "headers": {"Content-Type": "application/json"},
                                "body": '{"id": 2, "name": "bob"}', "bytes": 24, "elapsed_ms": 5},
           "collect": lambda p, pr, d: {"job_id": "j1", "state": "QUEUED"}, "job": lambda j: None,
           "assets": lambda: [{"host": "app.example.com", "score": 5, "probe": {"status": 200}}],
           "urls": lambda: [], "traffic": lambda n: [], "findings": lambda n: [],
           "record_finding": lambda *a: "f123"}
    ctx.update(over)
    return ctx


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="raven-tb-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.tb = ToolBox(_ctx(), self.tmp, lambda: None)

    def test_tool_schemas_are_closed_objects(self):
        names = {t["name"] for t in TOOL_DEFS}
        self.assertTrue({"http_request", "run_command", "start_collection", "load_skill", "record_finding"} <= names)
        for t in TOOL_DEFS:
            self.assertEqual(t["input_schema"]["type"], "object")
            self.assertFalse(t["input_schema"]["additionalProperties"])

    def test_out_of_scope_blocked_before_approval(self):
        blocked, _ = self.tb.precheck("http_request", {"method": "GET", "url": "https://evil.example.org/", "purpose": "x"})
        self.assertIn("outside the engagement scope", blocked)
        blocked, notes = self.tb.precheck("http_request", {"method": "POST", "url": "https://app.example.com/a", "purpose": "probe"})
        self.assertIsNone(blocked)
        self.assertTrue(any("may change data" in n for n in notes))

    def test_record_finding_requires_scope_and_severity(self):
        self.assertTrue(self.tb.run("record_finding", {"title": "t", "url": "https://evil.org/", "severity": "high",
                                                       "description": "d", "evidence": "e"})[1])
        txt, err = self.tb.run("record_finding", {"title": "t", "url": "https://app.example.com/x", "severity": "high",
                                                  "description": "d", "evidence": "e"})
        self.assertFalse(err)
        self.assertIn("f123", txt)

    def test_write_file_confined(self):
        txt, err = self.tb.run("write_file", {"name": "../../etc/passwd", "content": "x"})
        self.assertFalse(err)
        files = [p for p in self.tmp.iterdir()]
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].parent, self.tmp)       # confined to the run folder
        self.assertNotIn("/", files[0].name)


# ── fake Anthropic client ─────────────────────────────────────────────────────

def _text(t):
    return NS(type="text", text=t)


def _tool(i, name, inp):
    return NS(type="tool_use", id=i, name=name, input=inp)


def _resp(content, stop="end_turn", usage=(100, 50), details=None):
    return NS(content=content, stop_reason=stop, stop_details=details, model=MODEL,
              usage=NS(input_tokens=usage[0], output_tokens=usage[1], cache_read_input_tokens=0,
                       cache_creation_input_tokens=0))


class FakeClient:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []
        self.beta = NS(messages=NS(create=self._create))

    def _create(self, **kw):
        import copy
        self.calls.append(copy.deepcopy(kw))   # the loop keeps appending to the same list
        return self.responses.pop(0)


class AgentLoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="raven-ag-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _run(self, responses, **kw):
        fake = FakeClient(responses)
        run = ClaudeAgentRun("check IDOR on /api/users/2", self.tmp, _ctx(), lambda: False, lambda: fake, **kw)
        th = threading.Thread(target=run.run, daemon=True)
        th.start()
        return run, fake, th

    def _wait_pending(self, run):
        for _ in range(100):
            if run.pending:
                return run.pending
            time.sleep(0.02)
        self.fail("no pending action")

    def test_tool_loop_with_approval(self):
        run, fake, th = self._run([
            _resp([_text("Checking."), _tool("t1", "list_assets", {}),
                   _tool("t2", "http_request", {"method": "GET", "url": "https://app.example.com/api/users/2", "purpose": "IDOR"})],
                  stop="tool_use"),
            _resp([_text("bob's record came back with alice's session: IDOR.")]),
        ])
        p = self._wait_pending(run)
        self.assertEqual(p["tool"], "http_request")
        self.assertFalse(run.decide(True))                  # action_id required
        self.assertTrue(run.decide(True, action_id=p["id"]))
        th.join(5)
        snap = run.snapshot()
        self.assertEqual(snap["state"], "DONE")
        self.assertIn("IDOR", snap["answer"])
        # every request uses Opus 5.5 + refusal fallback + caching + tools
        kw = fake.calls[0]
        self.assertEqual(kw["model"], MODEL)
        self.assertEqual(kw["fallbacks"], "default")
        self.assertIn(cl.FALLBACK_BETA, kw["betas"])
        self.assertEqual(kw["cache_control"], {"type": "ephemeral"})
        self.assertEqual(kw["output_config"], {"effort": "high"})
        # both tool results returned in ONE user message, matching ids
        results = fake.calls[1]["messages"][-1]["content"]
        self.assertEqual([r["tool_use_id"] for r in results], ["t1", "t2"])
        self.assertIn('"name": "bob"', results[1]["content"])
        self.assertEqual(snap["usage"]["requests"], 2)
        self.assertGreater(snap["usage"]["cost_usd"], 0)

    def test_denied_action_is_reported_not_executed(self):
        sent = []
        fake = FakeClient([
            _resp([_tool("t1", "http_request", {"method": "GET", "url": "https://app.example.com/x", "purpose": "p"})], stop="tool_use"),
            _resp([_text("ok, stopping")]),
        ])
        run = ClaudeAgentRun("x", self.tmp, _ctx(send=lambda r: sent.append(r) or {}), lambda: False, lambda: fake)
        th = threading.Thread(target=run.run, daemon=True)
        th.start()
        p = self._wait_pending(run)
        run.decide(False, "not now", action_id=p["id"])
        th.join(5)
        self.assertEqual(sent, [])
        self.assertIn("DENIED", fake.calls[1]["messages"][-1]["content"][0]["content"])

    def test_out_of_scope_never_asks(self):
        run, fake, th = self._run([
            _resp([_tool("t1", "http_request", {"method": "GET", "url": "https://evil.org/", "purpose": "p"})], stop="tool_use"),
            _resp([_text("blocked, done")]),
        ])
        th.join(5)
        self.assertEqual(run.snapshot()["state"], "DONE")
        res = fake.calls[1]["messages"][-1]["content"][0]
        self.assertTrue(res["is_error"])
        self.assertIn("outside the engagement scope", res["content"])

    def test_refusal_and_budget_and_cancel(self):
        run, _, th = self._run([_resp([], stop="refusal", details=NS(category="cyber", explanation="x"))])
        th.join(5)
        self.assertEqual(run.snapshot()["state"], "REFUSED")
        run, _, th = self._run([_resp([_tool("t1", "get_scope", {})], stop="tool_use", usage=(10_000_000, 0))],
                               budget_usd=1.0)
        th.join(5)
        self.assertEqual(run.snapshot()["state"], "BUDGET")
        run, _, th = self._run([_resp([_tool("t1", "run_command", {"command": "id", "purpose": "p"})], stop="tool_use")])
        self._wait_pending(run)
        run.cancel()
        th.join(5)
        self.assertEqual(run.snapshot()["state"], "CANCELLED")


class ChatAdapterTests(unittest.TestCase):
    def test_complete_and_refusal_and_unavailable(self):
        from raven.claude.chat import build_provider
        fake = FakeClient([_resp([_text("Use ' OR 1=1 --")]),
                           _resp([], stop="refusal", details=NS(category="cyber", explanation=None))])
        _, adapter, _ = build_provider(lambda: fake)
        r = adapter.complete([{"role": "system", "content": "s"}, {"role": "user", "content": "sqli payloads?"}])
        self.assertIn("OR 1=1", r.content)
        self.assertEqual(r.usage["maturity"], "CLAUDE_API")
        self.assertEqual(fake.calls[0]["output_config"], {"effort": "medium"})
        r = adapter.complete([{"role": "user", "content": "x"}])
        self.assertIn("declined", r.content)

        def boom():
            raise cl.ClaudeUnavailable("No Anthropic API key configured")
        _, adapter, _ = build_provider(boom)
        r = adapter.complete([{"role": "user", "content": "x"}])
        self.assertIsNotNone(r.failure)
        self.assertIn("No Anthropic API key", r.usage["error"])


class ServerRouteTests(unittest.TestCase):
    def setUp(self):
        from raven.api import server
        self.server = server
        self.tmp = Path(tempfile.mkdtemp(prefix="raven-cl-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.object(server, "_CLAUDE_KEYSTORE", KeyStore(self.tmp))
        p.start()
        self.addCleanup(p.stop)
        env = mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": ""})
        env.start()
        self.addCleanup(env.stop)

    def test_status_never_returns_key(self):
        s = self.server
        data, code = s.api_claude_status()
        self.assertFalse(data["configured"])
        with mock.patch("raven.claude.client.test_connection", return_value={"ok": True}):
            data, code = s.api_claude_key_save({"api_key": GOOD_KEY})
        self.assertEqual(code, 200)
        self.assertNotIn(GOOD_KEY, json.dumps(data))
        data, _ = s.api_claude_status()
        self.assertTrue(data["configured"])
        self.assertNotIn(GOOD_KEY, json.dumps(data))
        self.assertEqual(data["key_hint"], hint(GOOD_KEY))

    def test_rejected_key_not_kept(self):
        with mock.patch("raven.claude.client.test_connection",
                        return_value={"ok": False, "error": "The Anthropic API key was rejected (401) — x"}):
            data, code = self.server.api_claude_key_save({"api_key": GOOD_KEY})
        self.assertEqual(code, 400)
        self.assertFalse(self.server._claude_keystore().configured())

    def test_input_validation(self):
        s = self.server
        self.assertEqual(s.api_claude_key_save({"api_key": "nope"})[1], 400)
        self.assertEqual(s.api_claude_key_save({})[1], 400)
        self.assertEqual(s.api_claude_settings({"budget_usd": "5"})[1], 400)
        self.assertEqual(s.api_claude_settings({"enabled": "false"})[1], 400)
        self.assertEqual(s.api_claude_agent_start({"objective": "x"})[1], 503)   # no key


if __name__ == "__main__":
    unittest.main()
