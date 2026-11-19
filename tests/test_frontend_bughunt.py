"""Regression checks for the 2026-11-17 frontend bug hunt (web/index.html "RAVEN OS"
and web/prototype.html "Recon Workbench").

Both pages hold the API token and POST /api/v7/terminal/run runs shell commands, so
an XSS in either page amounts to code execution on the researcher's machine. Most
checks are static (the markup / script text); a few small pure helpers are extracted
and executed with node when it is installed, to check behaviour rather than text.

Findings covered (numbering follows the review report):
  1  graph node data-id escaped                      (prototype)
  2  Settings AI audit / native model text escaped   (index)
  3  workspace switch clears Intruder headers/body   (prototype)
  4  Intruder stops on "not ready", never "finished" (prototype)
  5  stale finding-detail responses are dropped      (prototype)
  6  workspace switch: stale loadData + panel reload (prototype)
  7  ntCreate refuses during a workspace transition  (prototype)
  8  collection progress survives the 60-line window (prototype)
  9  RAVEN-Sec timeline not rebuilt when unchanged   (index)
 10  workspace cards: escaped, no inline onclick     (index)
 11  V7 tables show "—" for missing fields           (prototype)
 12  "+ New" workspace requires a scope for names    (index)
 13  Emergency Stop has a Resume (clear-stop)        (index)
"""
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "web"
INDEX = (WEB / "index.html").read_text(encoding="utf-8")
WB = (WEB / "prototype.html").read_text(encoding="utf-8")
NODE = shutil.which("node")


def _function_body(src, header):
    """Text of the function starting at `header` up to its matching closing brace."""
    start = src.index(header)
    i = src.index("{", start + len(header) - 1)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[start:j + 1]
    raise AssertionError(f"unbalanced braces after {header!r}")


def _absent(test, needle, src):
    """assertNotIn without dumping a 100 KB page into the failure message."""
    if needle in src:
        i = src.index(needle)
        test.fail(f"{needle!r} still present: ...{src[max(0, i - 80):i + 80]!r}...")


def _run_node(script):
    out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise AssertionError(out.stderr)
    return json.loads(out.stdout)


class WorkbenchEscapingTests(unittest.TestCase):
    def test_graph_node_data_id_is_escaped(self):  # 1
        self.assertIn('data-id="${HX(n.id)}"', WB)
        _absent(self, 'data-id="${n.id}"', WB)


class WorkbenchWorkspaceSwitchTests(unittest.TestCase):
    def test_clear_workspace_inputs_purges_intruder_credentials(self):  # 3
        body = _function_body(WB, "function clearWorkspaceInputs(){")
        for el in ("iHeaders", "iBody", "acCookieA", "acCookieB"):
            self.assertIn(f"'{el}'", body)

    def test_load_data_drops_responses_from_a_previous_workspace(self):  # 6
        body = _function_body(WB, "async function loadData(){")
        self.assertTrue(body.startswith("async function loadData(){const generation=workspaceGeneration;"))
        guard = body.index("if(generation!==workspaceGeneration)return;")
        self.assertLess(guard, body.index("renderSummary("))

    def test_workspace_change_reloads_panels_and_closes_finding_detail(self):  # 6
        handlers = re.findall(r"document\.addEventListener\('raven-workspace-changed',(.*?)\);\n", WB, re.S)
        joined = "\n".join(handlers)
        for loader in ("loadFindings()", "loadObservations()", "loadBaselines()", "loadKnowledge", "loadEvidence"):
            self.assertIn(loader, joined)
        self.assertIn("v5FSelected=null", joined)
        self.assertIn("getElementById('v5FDetail')", joined)

    def test_panel_loaders_check_the_workspace_generation(self):  # 6
        for header in ("async function loadFindings(){", "async function loadObservations(){",
                       "async function loadBaselines(){", "async function loadKnowledge(){",
                       "async function loadEvidence(){"):
            with self.subTest(loader=header):
                body = _function_body(WB, header)
                self.assertIn("const generation=workspaceGeneration;", body)
                self.assertIn("if(generation!==workspaceGeneration)return;", body)

    def test_new_target_create_has_the_transition_guard(self):  # 7
        body = _function_body(WB, "document.getElementById('ntCreate').onclick=async function(){")
        self.assertIn("if(scopeTransition)return;", body)
        self.assertLess(body.index("if(scopeTransition)return;"), body.index("scopeTransition=true"))


class WorkbenchIntruderTests(unittest.TestCase):  # 4
    def setUp(self):
        self.body = _function_body(WB, "intrStartBtn.onclick=async function(){")

    def test_refused_sends_are_tagged_before_any_io(self):
        self.assertIn("refused.ravenNotSent=true", WB)

    def test_loop_stops_when_requests_are_paused(self):
        loop = self.body[self.body.index("for(let i=0;i<payloads.length;i++){"):]
        ready = loop.index("liveReadinessMessage()")
        self.assertLess(ready, loop.index("apiSend("), "readiness must be checked before each send")
        self.assertIn("if(e&&e.ravenNotSent){interrupted=", loop)
        # a refused send breaks out BEFORE sent++ is reached
        self.assertLess(loop.index("ravenNotSent"), loop.index("sent++"))

    def test_interrupted_attack_is_never_reported_as_finished(self):
        self.assertIn("}else if(interrupted){", self.body)
        self.assertLess(self.body.index("}else if(interrupted){"), self.body.index("intruder finished"))
        self.assertIn("intruder interrupted", self.body)


class WorkbenchFindingDetailTests(unittest.TestCase):  # 5
    def test_every_await_is_followed_by_the_selection_check(self):
        body = _function_body(WB, "async function loadFindingDetail(f){")
        awaits = re.findall(r"await getJ\(", body)
        guarded = re.findall(r"await getJ\([^;]*\);\s*(?://[^\n]*\n\s*)*if\(v5FSelected!==f\.id\)return;", body)
        self.assertEqual(len(awaits), 2)
        self.assertEqual(len(guarded), len(awaits))

    def test_report_export_state_is_reset_when_a_finding_opens(self):
        body = _function_body(WB, "async function loadFindingDetail(f){")
        self.assertLess(body.index("v5FReportMd=''"), body.index("await getJ("))


class WorkbenchProgressTests(unittest.TestCase):  # 8
    def test_progress_is_not_diffed_by_array_length(self):
        _absent(self, "seen=(job.progress||[]).length", WB)
        self.assertIn("progressDelta(shown,cur)", WB)

    @unittest.skipUnless(NODE, "node not installed")
    def test_progress_keeps_printing_past_the_server_window(self):
        m = re.search(r"const progressDelta=\(prev,cur\)=>\{.*?return cur\.slice\(\);\};", WB, re.S)
        self.assertIsNotNone(m)
        script = m.group(0) + r"""
        function sim(total, step, burstAt){
          let log=[],shown=[],printed=[],n=0,poll=0;
          while(true){poll++;const add=(poll===burstAt)?100:step;
            for(let i=0;i<add&&n<total;i++){n++;log.push('200 host'+n);}
            const done=n>=total;if(done)log.push('Run #1 complete');
            const cur=log.slice(-60);progressDelta(shown,cur).forEach(l=>printed.push(l));shown=cur.slice();
            if(done)return {log,printed};}}
        const a=sim(101,3,0),b=sim(200,3,5);
        console.log(JSON.stringify({a_all:JSON.stringify(a.printed)===JSON.stringify(a.log),
          a_last:a.printed[a.printed.length-1],b_unique:new Set(b.printed).size===b.printed.length,
          b_last:b.printed[b.printed.length-1]}));"""
        r = _run_node(script)
        self.assertTrue(r["a_all"], "every line printed exactly once, in order")
        self.assertEqual(r["a_last"], "Run #1 complete")
        self.assertTrue(r["b_unique"])
        self.assertEqual(r["b_last"], "Run #1 complete")


class WorkbenchV7TableTests(unittest.TestCase):  # 11
    def test_missing_fields_are_not_invented(self):
        _absent(self, "Date.now()/1000", WB)
        _absent(self, "workspace_id||'default'", WB)
        self.assertIn("v7When(e.created_at)", WB)
        self.assertIn("v7When(nd.created_at)", WB)

    @unittest.skipUnless(NODE, "node not installed")
    def test_v7_when_formats_or_dashes(self):
        body = _function_body(WB, "function v7When(ts){")
        r = _run_node(body + """
        console.log(JSON.stringify([v7When(undefined),v7When(null),v7When(''),v7When('garbage'),
          v7When(1700000000),v7When(1700000000000),v7When('2026-01-02T03:04:05Z')]));""")
        self.assertEqual(r[:4], ["—"] * 4)
        self.assertEqual(r[4], "2023-11-14 22:13")
        self.assertEqual(r[5], "2023-11-14 22:13")
        self.assertEqual(r[6], "2026-01-02 03:04")


class OsSettingsEscapingTests(unittest.TestCase):  # 2
    def test_ai_audit_table_is_escaped(self):
        _absent(self, "'<td>'+r.value", INDEX)
        self.assertIn("_cellText(r.value)", INDEX)

    def test_native_model_option_and_maturity_are_escaped(self):
        _absent(self, "'<option value=\"'+m.model_id", INDEX)
        self.assertIn("'<option value=\"'+_cellText(mid)+'\"'", INDEX)
        _absent(self, "RAVEN Native — '+maturity+'", INDEX)
        body = _function_body(INDEX, "function renderNativeActive(sel, maturity){")
        self.assertIn("_cellText(maturity", body)


class OsRavenSecTests(unittest.TestCase):  # 9
    def setUp(self):
        self.body = _function_body(INDEX, "function _rsRenderRun(r){")

    def test_unchanged_run_is_not_rebuilt(self):
        self.assertIn("if(sig===_rsSig)return;", self.body)
        self.assertLess(self.body.index("if(sig===_rsSig)return;"), self.body.index("tl.innerHTML="))

    def test_deny_reason_survives_a_rebuild(self):
        self.assertIn('id="rsDenyReason" data-rs-id="', self.body)
        self.assertIn("newIn.value=keep.v", self.body)

    def test_note_steps_render_escaped(self):
        self.assertIn("s.type==='note'", self.body)
        # Every note branch (plain notes and Claude's messages) must render through an
        # escaping helper: _cellText directly, or _rsPre (which escapes via _cellText).
        self.assertIn("function _rsPre(t,max){return", INDEX)
        self.assertIn("_rsLinkify(t)", INDEX[INDEX.index("function _rsPre"):][:400])
        start = 0
        while True:
            i = self.body.find("s.type==='note'", start)
            if i < 0:
                break
            seg = self.body[i:i + 220]
            self.assertTrue("_cellText(" in seg or "_rsPre(" in seg, seg)
            start = i + 1


class OsWorkspaceTests(unittest.TestCase):
    def test_workspace_cards_escape_and_use_delegation(self):  # 10
        _absent(self, 'onclick="switchWorkspace(', INDEX)
        _absent(self, "switchWorkspace(\\''", INDEX)
        body = _function_body(INDEX, "function loadWorkspaces(){")
        self.assertIn("_cellText(w.name||'Workspace')", body)
        self.assertIn("data-ws-id=\"'+_cellText(wid)+'\"", body)
        self.assertIn("addEventListener('click',_wsCardsClick)", INDEX)

    def test_scope_is_not_labelled_optional(self):  # 12
        _absent(self, "Scope (optional)", INDEX)
        body = _function_body(INDEX, "function createWorkspace(){")
        self.assertLess(body.index("_wsNameIsHost(body.name)"), body.index("/api/v7/workspace/create"))

    @unittest.skipUnless(NODE, "node not installed")
    def test_client_host_check_matches_server_rule(self):  # 12
        from raven.scope import rule
        names = ["example.com", "Example.COM.", "*.example.com", "10.0.0.1", "::1", "[::1]",
                 "localhost", "acme", "Target Research", "Acme Corp", "a/b", "https://x.test",
                 "x..y", "-bad.test", "under_score.test", "a" * 64 + ".test", "user@host",
                 "*.10.0.0.1", "*.::1", "1.2.3", "", "   "]
        body = _function_body(INDEX, "function _wsNameIsHost(name){")
        client = _run_node(body + f"\nconsole.log(JSON.stringify({json.dumps(names)}.map(_wsNameIsHost)));")
        for name, ok in zip(names, client):
            try:
                rule(name.strip())
                server_ok = True
            except Exception:
                server_ok = False
            with self.subTest(name=name):
                self.assertEqual(ok, server_ok)


class OsEmergencyStopResumeTests(unittest.TestCase):  # 13
    def test_resume_control_sits_next_to_each_emergency_stop(self):
        stops = INDEX.count('onclick="doEmergencyStop()"')
        self.assertGreaterEqual(stops, 1)
        self.assertEqual(INDEX.count('onclick="doClearStop()"'), stops)
        for m in re.finditer(r'onclick="doEmergencyStop\(\)"', INDEX):
            near = INDEX[max(0, m.start() - 400):m.end() + 400]
            self.assertIn('onclick="doClearStop()"', near)

    def test_resume_posts_clear_stop_and_refreshes_the_indicator(self):
        body = _function_body(INDEX, "function doClearStop(){")
        self.assertIn("_RAV.post('/api/clear-stop'", body)
        self.assertIn("refreshStopIndicator()", body)
        self.assertIn("doClearStop:doClearStop", INDEX)
        self.assertIn("'/api/scheduler'", _function_body(INDEX, "function refreshStopIndicator(){"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
