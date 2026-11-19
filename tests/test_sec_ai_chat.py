"""RAVEN-Sec chat/terminal/agent quality fixes found by testing the model for pentest use
(2026-11-18). No model is loaded here — these pin the deterministic parts."""
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from raven.sec_ai import agent as rs_agent
from raven.sec_ai import corpus, kb, tool_trajectories
from raven.sec_ai.cli import _scope_from, make_sender
from raven.sec_ai.llm import (_excerpt, answer_is_empty, compose_answer, retrieve_for_chat,
                              tidy_answer)
from raven.sec_ai.prompts import AGENT_SYSTEM


class TidyAnswerTests(unittest.TestCase):
    def test_links_inside_code_are_untouched(self):
        out = tidy_answer("```python\nurl = 'http://made-up.io/x'\n```\nsee `https://inline.io`")
        self.assertIn("url = 'http://made-up.io/x'", out)
        self.assertNotIn("unverified", out)

    def test_invented_prose_link_is_flagged_placeholders_are_not(self):
        out = tidy_answer("read https://made-up.io/a and http://example.com/x and http://127.0.0.1:38333/api")
        self.assertIn("https://made-up.io/a (⚠ unverified link)", out)
        self.assertNotIn("example.com/x (⚠", out)
        self.assertNotIn("38333/api (⚠", out)

    def test_repeated_lines_dropped(self):
        out = tidy_answer("* Determine if the endpoint allows X\n" * 5 + "done")
        self.assertEqual(out.count("Determine if the endpoint allows X"), 1)

    def test_empty_answer_detection(self):
        self.assertTrue(answer_is_empty("Source: https://x/y (⚠ unverified link)"))
        self.assertFalse(answer_is_empty("import requests\nprint(requests.get('http://a').headers)"))


class ComposeTests(unittest.TestCase):
    HIT = {"title": "SQL Injection", "heading": "Auth bypass",
           "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/x", "text": "' or '1'='1 --"}

    def test_trusted_sources_come_first_and_summary_is_labelled(self):
        out = compose_answer("Try the classic tautology payload in both fields.", [self.HIT])
        self.assertTrue(out.startswith("From the trusted sources (verbatim):"))
        self.assertIn("' or '1'='1 --", out)
        self.assertIn("model-written — verify", out)
        self.assertLess(out.index("' or '1'='1"), out.index("model-written"))

    def test_summary_that_only_echoes_a_link_is_dropped(self):
        out = compose_answer("Source: https://made-up.io/z", [self.HIT])
        self.assertNotIn("model-written", out)

    def test_excerpt_fences_always_balanced(self):
        for text in ("-- in a block\nSELECT 1\n```\nprose after", "intro\n```sql\nSELECT 1;" + "x" * 3000,
                     "a\n```py\nx=1\n```\nb"):
            self.assertEqual(_excerpt(text).count("```") % 2, 0, text[:30])


class RetrievalTests(unittest.TestCase):
    def test_acronyms_expand_to_full_names(self):
        q = kb.fts_query("How do I test an API for IDOR and jwt-protected endpoints?")
        self.assertIn('"insecure direct object"', q)
        self.assertIn('"json web token"', q)

    def test_identifier_match_is_decisive(self):
        hit = {"title": "CVE-2021-44228 Log4Shell", "heading": "", "url": "https://x", "text": "jndi lookup"}
        with mock.patch("raven.sec_ai.kb.KnowledgeBase") as K:
            K.return_value.search.return_value = [hit]
            got = retrieve_for_chat("Explain CVE-2021-44228 and how to detect it safely and quickly")
        self.assertEqual(got, [hit])


class CorpusCodeTests(unittest.TestCase):
    def test_code_indentation_preserved(self):
        out = corpus._clean("Intro   text\n```python\ndef f(x):\n    if x:\n        return  1\n```")
        self.assertIn("    if x:\n        return  1", out)
        self.assertIn("Intro text", out)


class ToolTrajectoryTests(unittest.TestCase):
    def test_protocol_shape_and_both_outcomes(self):
        ex = tool_trajectories.build(64)
        self.assertEqual(len(ex), 64)
        tools = set()
        for e in ex:
            m = e["messages"]
            self.assertEqual(m[0]["content"], AGENT_SYSTEM)
            self.assertTrue(m[2]["content"].startswith("ACTION: search\nINPUT: "))
            self.assertRegex(m[4]["content"], r"^ACTION: (http|shell)\nINPUT: ")
            self.assertTrue(m[5]["content"].startswith(("OBSERVATION (http):\nHTTP ", "OBSERVATION (shell):\n[exit")))
            self.assertTrue(m[6]["content"].startswith("ANSWER: "))
            tools.add(m[4]["content"].split("\n")[0])
        answers = [e["answer"] for e in ex]
        self.assertTrue(any(a.startswith(("Confirmed", "Likely")) for a in answers))
        self.assertTrue(any(a.startswith(("Not ", "No ", "Access correctly", "Reflected but")) for a in answers))
        self.assertEqual(tools, {"ACTION: http", "ACTION: shell"})


class CliSenderTests(unittest.TestCase):
    def test_scope_with_port(self):
        sc = _scope_from(["127.0.0.1:38333"])
        self.assertTrue(sc.allows_url("http://127.0.0.1:38333/x"))
        self.assertFalse(sc.allows_url("http://127.0.0.1:8790/x"))
        self.assertIsNone(_scope_from([]))

    def test_sender_blocks_out_of_scope_and_private(self):
        send = make_sender(_scope_from(["127.0.0.1:38333"]), allow_private=False)
        self.assertTrue(send({"url": "https://example.org/"})["blocked"])
        self.assertTrue(send({"url": "http://127.0.0.1:38333/"})["blocked"])  # private w/o flag


class AgentEvidenceTests(unittest.TestCase):
    def _run(self, objective, scope=lambda u: "127.0.0.1:38333" in u):
        tmp = tempfile.mkdtemp(prefix="raven-rs-")
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        with mock.patch("raven.sec_ai.paths.agent_workspace_root", return_value=Path(tmp)):
            return rs_agent.AgentRun(objective, scope, lambda h: True, lambda r: {}, lambda: False,
                                     lambda: None)

    def test_nudge_only_for_in_scope_target_to_test_once(self):
        run = self._run("Check for IDOR: request http://127.0.0.1:38333/api/users/2 with cookie session=alice")
        n = run._untested_target_nudge()
        self.assertIn("ACTION: http", n)
        self.assertIn("Cookie: session=alice", n)
        self.assertIsNone(run._untested_target_nudge())          # at most once
        self.assertIsNone(self._run("What is IDOR?")._untested_target_nudge())
        self.assertIsNone(self._run("test https://out-of-scope.example/x")._untested_target_nudge())

    def test_evidence_first_and_honest_when_model_has_nothing(self):
        run = self._run("x")
        run._step(type="action", tool="http", input="GET http://127.0.0.1:38333/api/users/2\nCookie: session=alice")
        run._step(type="observation", tool="http", text='HTTP 200 OK\n\n{"id": 2, "name": "bob"}')
        out = run._with_evidence("Source: https://made-up.io/z")
        self.assertTrue(out.startswith("Evidence — approved actions and their REAL results"))
        self.assertIn('{"id": 2, "name": "bob"}', out)
        self.assertIn("could not interpret", out)


if __name__ == "__main__":
    unittest.main()
