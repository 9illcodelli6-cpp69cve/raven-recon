"""Recon Workbench revival — server + discovery + UI regressions (2026-11-17).

The V5 workbench (web/prototype.html) drives the real recon engine but was unreachable
(no token on /prototype.html) and had drifted from the server. These tests lock in:

  * /workbench is served with the session token and no-store caching;
  * JSON API responses are no-store;
  * /api/payloads, /api/ml-readiness, /api/v7/techniques, /api/report work;
  * on-disk workspace folders appear in the workspace registry list;
  * the probe honours every scoped port and crt.sh is skipped for IP targets;
  * bounded endpoint discovery (links / robots / sitemap / JS) stays in scope;
  * workbench UI regressions (identity crash, fake counters, demo history, hard-coded
    ports, intruder headers, report export).
"""
import http.client
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from raven.api import server
from raven import analysis
from raven.recon import collectors

REPO = Path(__file__).resolve().parent.parent
WB = (REPO / "web" / "prototype.html").read_text(encoding="utf-8")


class _Isolated(unittest.TestCase):
    """Fresh cwd-relative data root + a workspace, like the golden suites."""

    def setUp(self):
        self._saved_state = dict(server.STATE)
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-wb-")
        os.chdir(self._tmp)
        self._saved_mgr = server._WORKSPACE_MGR
        server._WORKSPACE_MGR = None
        server.use_workspace("wbtest")

    def tearDown(self):
        store = server.STATE.get("store")
        if store is not None:
            try:
                store.close()
            except Exception:
                pass
        server._WORKSPACE_MGR = self._saved_mgr
        server.STATE.clear()
        server.STATE.update(self._saved_state)
        os.chdir(self._cwd)
        shutil.rmtree(self._tmp, ignore_errors=True)


# ── HTTP-level: pages, caching ─────────────────────────────────────────────────

class PageServingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_state = dict(server.STATE)
        cls._cwd = os.getcwd()
        cls._tmp = tempfile.mkdtemp(prefix="raven-wbhttp-")
        os.chdir(cls._tmp)
        server.use_workspace("wbhttp")
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        server.STATE["port"] = cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        server.STATE["store"].close()
        server.STATE.clear()
        server.STATE.update(cls._saved_state)
        os.chdir(cls._cwd)
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _get(self, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r, body

    def test_workbench_is_served_with_token_and_no_store(self):
        for path in ("/workbench", "/prototype.html"):
            r, body = self._get(path)
            self.assertEqual(r.status, 200, path)
            self.assertIn(b"window.RAVEN_TOKEN=", body)
            self.assertEqual(r.getheader("Cache-Control"), "no-store")

    def test_main_page_no_store(self):
        r, body = self._get("/")
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        self.assertIn(b"window.RAVEN_TOKEN=", body)

    def test_api_json_is_no_store(self):
        r, _ = self._get("/api/summary", {"X-RAVEN-Token": server.SESSION_TOKEN})
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("Cache-Control"), "no-store")

    def test_report_requires_token(self):
        r, _ = self._get("/api/report")
        self.assertEqual(r.status, 403)


# ── Fixed / new API handlers ───────────────────────────────────────────────────

class ApiHandlerTests(_Isolated):
    def test_payloads_list_metadata_without_raw_values(self):
        data, code = server.api_payloads()
        self.assertEqual(code, 200, data)
        self.assertGreater(data["count"], 0)
        for p in data["payloads"]:
            self.assertNotIn("value", p)
            self.assertIn(p["payload_class"], {"SAFE_MARKER", "REFLECTION_PROBE", "HEADER_PROBE",
                                               "STATE_MUTATE", "EXFILTRATION", "DESTRUCTIVE"})

    def test_ml_readiness_reports_real_reasons(self):
        data, code = server.api_ml_readiness()
        self.assertEqual(code, 200)
        self.assertTrue(all("has no attribute" not in b for b in data["blockers"]), data)
        self.assertFalse(data["model_trained"])

    def test_techniques_route(self):
        data, code = server.api_techniques_list()
        self.assertEqual(code, 200)
        self.assertGreater(data["total"], 0)
        self.assertTrue(all(t["is_advisory"] for t in data["techniques"]))

    def test_workspace_report_markdown(self):
        server.set_scope({"name": "wbreport", "include": ["wbtest.test"], "ports": [443]})
        store = server.STATE["store"]
        run = 1
        store.host("wbtest.test", "seed", run)
        store.probe("wbtest.test", {"status": 200, "title": "Evil | `title` <b>", "server": "x",
                                    "final_url": "https://wbtest.test/", "body_hash": "", "error": "",
                                    "elapsed_ms": 1, "scripts": []}, run)
        data, code = server.api_workspace_report()
        self.assertEqual(code, 200, data)
        md = data["markdown"]
        self.assertIn("# RAVEN report — wbreport", md)
        self.assertIn("unverified candidate", md)
        self.assertIn("## Scope", md)
        self.assertIn("Evil \\| 'title' <b>", md)  # pipes/backticks neutralised in tables

    def test_workspace_list_includes_on_disk_folders(self):
        folder = Path(self._tmp) / "workspaces" / "fromdisk"
        folder.mkdir(parents=True)
        (folder / "scope.json").write_text(json.dumps(
            {"name": "fromdisk", "include": ["fromdisk.test"], "exclude": [], "ports": [443]}))
        bad = Path(self._tmp) / "workspaces" / "corrupt"
        bad.mkdir()
        (bad / "scope.json").write_text("{nope")
        data, code = server.api_workspace_list()
        names = [w["name"] for w in data["workspaces"]]
        self.assertIn("fromdisk", names)
        self.assertNotIn("corrupt", names)


# ── Probe ports / crt.sh / discovery ───────────────────────────────────────────

class ProbeAndDiscoveryTests(unittest.TestCase):
    def test_probe_candidates_keep_default_order_and_add_custom_ports(self):
        self.assertEqual(collectors.probe_candidates("a.test", [80, 443]),
                         [("https", "https://a.test/"), ("http", "http://a.test/")])
        self.assertEqual(collectors.probe_candidates("127.0.0.1", [8080]),
                         [("https", "https://127.0.0.1:8080/"), ("http", "http://127.0.0.1:8080/")])
        self.assertIn(("https", "https://[::1]:8443/"), collectors.probe_candidates("::1", [8443]))

    def test_crtsh_skipped_for_ip_targets(self):
        logs = []
        ctl = mock.Mock()
        with mock.patch.object(server, "_passive_crtsh") as crt:
            subs, added = collectors.PassiveCrtShCollector().collect_root(
                "10.0.0.5", scope=mock.Mock(), store=mock.Mock(), run_id=1, ctl=ctl, logs=logs)
        crt.assert_not_called()
        self.assertEqual((subs, added), ([], 0))
        self.assertIn("skipped (IP address target)", logs[0])

    def test_page_links_robots_sitemap(self):
        html_doc = (b"<html><a href='/a'>x</a><a href='mailto:x@y'>m</a><form action='/login'></form>"
                    b"<link rel='stylesheet' href='/s.css'><a href='https://other.test/z#frag'>o</a></html>")
        links = analysis.page_links(html_doc, {"content-type": "text/html"}, "https://t.test/dir/")
        self.assertEqual(links, ["https://t.test/a", "https://t.test/login", "https://other.test/z"])
        paths, maps = analysis.robots_entries(
            "User-agent: *\nDisallow: /admin/*.php\nDisallow: /\nAllow: /pub # c\nSitemap: https://t.test/sm.xml",
            "https://t.test/")
        self.assertEqual(paths, ["https://t.test/admin/", "https://t.test/pub"])
        self.assertEqual(maps, ["https://t.test/sm.xml"])
        self.assertEqual(analysis.sitemap_locs("<urlset><url><loc> https://t.test/x </loc></url></urlset>",
                                               "https://t.test/"), ["https://t.test/x"])
        self.assertEqual(analysis.page_links(b"{}", {"content-type": "application/json"}, "https://t.test/"), [])

    def test_discovery_stays_in_scope_and_records_sources(self):
        from raven.scope import Scope
        scope = Scope(include=["t.test"], exclude=["t.test"] and [], ports=[443])
        stored = {}

        class _Store:
            def url(self, url, source, run_id, evidence=None):
                stored[url] = source
                return True

            def commit(self):
                pass

        bodies = {
            "https://t.test/robots.txt": "Disallow: /secret\nSitemap: https://t.test/sm.xml",
            "https://t.test/sm.xml": "<loc>https://t.test/from-sitemap</loc><loc>https://evil.test/x</loc>",
            "https://t.test/app.js": "fetch('/api/v1/me'); fetch('https://evil.test/steal')",
        }

        def fake_send(req):
            body = bodies.get(req["url"])
            return {"ok": body is not None, "status": 200 if body else 404, "body": body or ""}

        ctl = mock.Mock()
        with mock.patch.object(server, "do_send", side_effect=fake_send), \
                mock.patch.object(server, "_canonical_svc", return_value=None):
            found, new = collectors.discover_endpoints(
                "https://t.test/", ["https://t.test/page", "https://evil.test/out"],
                ["https://t.test/app.js", "https://evil.test/x.js"],
                scope=scope, store=_Store(), run_id=1, ctl=ctl)
        self.assertEqual(stored, {
            "https://t.test/page": "html:link",
            "https://t.test/secret": "robots.txt",
            "https://t.test/from-sitemap": "sitemap",
            "https://t.test/api/v1/me": "js:fetch",
        })
        self.assertEqual((found, new), (4, 4))
        self.assertFalse(any("evil.test" in u for u in stored))

    def test_collector_strips_internal_keys_before_storage(self):
        saved = {}

        class _Store:
            def assets(self):
                return [{"host": "t.test"}]

            def host(self, *a):
                return True

            def probe(self, host, data, run_id):
                saved.update(data)

            def url(self, *a, **k):
                return True

            def commit(self):
                pass

        scope = mock.Mock()
        scope.allows_host.return_value = True
        scope.allows_url.return_value = False
        probe = {"status": 200, "title": "", "server": "", "final_url": "https://t.test/",
                 "body_hash": "", "error": "", "elapsed_ms": 1, "scripts": [],
                 "_base": "https://t.test/", "_links": []}
        ctl_on = mock.Mock()
        ctl_on.job.meta = {"discover": True}
        ctl_off = mock.Mock()
        ctl_off.job.meta = {"passive": True, "probe": True}
        with mock.patch.object(server, "_probe_host", side_effect=lambda h: dict(probe)), \
                mock.patch.object(collectors, "discover_endpoints", return_value=(0, 0)) as disc:
            collectors.ActiveProbeCollector().collect(scope=scope, store=_Store(), run_id=1,
                                                      ctl=ctl_on, logs=[])
            self.assertNotIn("_base", saved)
            self.assertNotIn("_links", saved)
            disc.assert_called_once()
            # Without the opt-in the request count stays exactly the historical one.
            collectors.ActiveProbeCollector().collect(scope=scope, store=_Store(), run_id=2,
                                                      ctl=ctl_off, logs=[])
            disc.assert_called_once()

    def test_submit_records_discover_only_when_requested(self):
        svc = collectors._server._RECON
        with mock.patch.object(server.SCHEDULER, "submit") as sub:
            sub.return_value = mock.Mock(id="j", state="QUEUED")
            svc.submit(True, True, discover=True)
            self.assertTrue(sub.call_args[0][3].get("discover"))
            svc.submit(True, True)
            self.assertNotIn("discover", sub.call_args[0][3])
            with self.assertRaises(ValueError):
                svc.submit(True, True, discover="yes")


# ── Workbench UI (static) ──────────────────────────────────────────────────────

class WorkbenchUiTests(unittest.TestCase):
    def test_identity_adoption_uses_existing_renderer(self):
        self.assertNotIn("renderUaMenu()", WB)  # renamed to renderUaModal; the stale call
        self.assertIn("function renderUaModal(", WB)  # blocked all live sending

    def test_no_demo_counters_in_markup(self):
        self.assertEqual(set(re.findall(r'class="tile-num" data-count="(\d+)"', WB)), {"0"})
        for view in ("surface", "endpoints", "changes", "runs", "history"):
            self.assertRegex(WB, rf'data-nav-count="{view}">0<')

    def test_scope_form_sends_full_scope(self):
        self.assertNotIn("exclude:[],ports:[80,443]", WB)
        for el in ("ntMore", "ntExclude", "ntPorts", "ntPrivate"):
            self.assertIn(f'id="{el}"', WB)
        self.assertIn("body:JSON.stringify(spec)", WB)

    def test_history_is_real(self):
        self.assertIn("getJSON('v7/traffic')", WB)
        self.assertNotIn("live request logging on roadmap", WB)

    def test_workspace_menu_is_real(self):
        self.assertIn("getJSON('v7/workspace')", WB)
        self.assertIn("/api/v7/workspace/switch", WB)

    def test_intruder_supports_headers_and_body(self):
        for el in ("iHeaders", "iBody"):
            self.assertIn(f'id="{el}"', WB)
        self.assertIn("{...identityHeaders(),...userHdrs},testBody", WB)

    def test_report_export_and_no_truncation(self):
        self.assertIn('id="v5FExport"', WB)
        self.assertIn("getJ('/api/report')", WB)
        self.assertNotIn("rpt.markdown.slice(0,800)", WB)

    def test_no_dead_routes(self):
        for dead in ("/api/v7/evidence/nodes", "/api/v7/evidence/pocs", "/api/v7/evidence/reports"):
            self.assertNotIn(f"getJ('{dead}')", WB)

    def test_terminal_live_shell_keeps_curl_scoped(self):
        self.assertIn("window.ravenRealShell=", WB)
        self.assertIn("['help','clear','curl'].includes(first)", WB)

    def test_os_links_to_workbench_and_back(self):
        index = (REPO / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="/workbench"', index)
        self.assertIn('id="backToOS"', WB)


if __name__ == "__main__":
    unittest.main(verbosity=2)
