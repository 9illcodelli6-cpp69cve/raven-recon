"""Part 11 — Final V7 GUI / UX tests.

Verifies that prototype.html contains the V7 Knowledge OS and Evidence OS
UI additions: nav items, view panels, JS handlers, and advisory disclaimers.
"""
import re
from pathlib import Path

HTML_PATH = Path(__file__).parent.parent / "web" / "prototype.html"


def _html() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


class TestHtmlExists:
    def test_file_exists(self):
        assert HTML_PATH.exists(), "web/prototype.html not found"

    def test_file_non_empty(self):
        assert HTML_PATH.stat().st_size > 0


class TestV7NavItems:
    def test_knowledge_os_nav_item_present(self):
        html = _html()
        assert 'data-view="knowledge"' in html

    def test_evidence_reports_nav_item_present(self):
        html = _html()
        assert 'data-view="evidence"' in html

    def test_knowledge_os_label(self):
        html = _html()
        assert "Knowledge OS" in html

    def test_evidence_reports_label(self):
        html = _html()
        assert "Evidence" in html and "Reports" in html

    def test_v7_badge_on_knowledge(self):
        html = _html()
        assert re.search(r'data-view="knowledge".*?V7', html, re.DOTALL), \
            "Knowledge OS nav item should carry V7 badge"

    def test_v7_badge_on_evidence(self):
        html = _html()
        assert re.search(r'data-view="evidence".*?V7', html, re.DOTALL), \
            "Evidence nav item should carry V7 badge"


class TestV7ViewPanels:
    def test_knowledge_view_panel_exists(self):
        html = _html()
        assert 'id="view-knowledge"' in html

    def test_evidence_view_panel_exists(self):
        html = _html()
        assert 'id="view-evidence"' in html

    def test_knowledge_has_entries_tab(self):
        html = _html()
        assert 'data-ktab="entries"' in html

    def test_knowledge_has_techniques_tab(self):
        html = _html()
        assert 'data-ktab="techniques"' in html

    def test_evidence_has_nodes_tab(self):
        html = _html()
        assert 'data-etab="nodes"' in html

    def test_evidence_has_poc_tab(self):
        html = _html()
        assert 'data-etab="poc"' in html

    def test_evidence_has_reports_tab(self):
        html = _html()
        assert 'data-etab="reports"' in html

    def test_knowledge_table_body_exists(self):
        html = _html()
        assert 'id="v7KBBody"' in html

    def test_technique_table_body_exists(self):
        html = _html()
        assert 'id="v7KBTechBody"' in html

    def test_evidence_nodes_table_body_exists(self):
        html = _html()
        assert 'id="v7EVNodesBody"' in html

    def test_poc_table_body_exists(self):
        html = _html()
        assert 'id="v7EVPocBody"' in html

    def test_reports_table_body_exists(self):
        html = _html()
        assert 'id="v7EVReportsBody"' in html


class TestV7JsHandlers:
    def test_knowledge_refresh_button_exists(self):
        html = _html()
        assert 'id="v7KBRefresh"' in html

    def test_evidence_refresh_button_exists(self):
        html = _html()
        assert 'id="v7EVRefresh"' in html

    def test_js_loads_knowledge_endpoint(self):
        html = _html()
        assert "/api/v7/knowledge" in html

    def test_js_loads_techniques_endpoint(self):
        html = _html()
        assert "/api/v7/techniques" in html

    # Updated 2026-11-17: /api/v7/evidence/{nodes,pocs,reports} never existed on the
    # server (every call 404'd). The workbench now reads the real routes instead.
    def test_js_loads_evidence_nodes_endpoint(self):
        html = _html()
        assert "getJ('/api/v7/evidence')" in html
        assert "/api/v7/evidence/nodes" not in html

    def test_js_loads_pocs_endpoint(self):
        html = _html()
        # No PoC store is wired: the panel says so instead of calling a 404 route.
        assert "No PoC store in this build" in html
        assert "/api/v7/evidence/pocs" not in html

    def test_js_loads_reports_endpoint(self):
        html = _html()
        # Reports are per-finding Markdown reports + the workspace report export.
        assert "/report'" in html and "getJ('/api/report')" in html
        assert "/api/v7/evidence/reports" not in html

    def test_knowledge_nav_click_handler_registered(self):
        html = _html()
        assert 'data-view="knowledge"' in html and "loadKnowledge" in html

    def test_evidence_nav_click_handler_registered(self):
        html = _html()
        assert 'data-view="evidence"' in html and "loadEvidence" in html


class TestV7AdvisoryDisclaimers:
    def test_knowledge_panel_advisory_disclaimer(self):
        html = _html()
        # Look for the advisory hint text inside view-knowledge
        idx = html.find('id="view-knowledge"')
        assert idx >= 0
        snippet = html[idx:idx+3000]
        assert "advisory" in snippet.lower() or "ADVISORY" in snippet

    def test_knowledge_human_reviewed_labels_disclaimer(self):
        html = _html()
        assert "human_reviewed_labels" in html

    def test_evidence_panel_advisory_disclaimer(self):
        html = _html()
        idx = html.find('id="view-evidence"')
        assert idx >= 0
        snippet = html[idx:idx+3000]
        assert "advisory" in snippet.lower() or "ADVISORY" in snippet

    def test_techniques_advisory_column(self):
        html = _html()
        assert "ADVISORY" in html

    def test_is_advisory_invariant_mentioned(self):
        html = _html()
        assert "is_advisory" in html

    def test_human_verification_disclaimer_in_evidence(self):
        html = _html()
        idx = html.find('id="view-evidence"')
        snippet = html[idx:idx+3000]
        assert "human verification" in snippet.lower()


class TestV7PreExistingFeaturesUnchanged:
    def test_surface_view_still_exists(self):
        assert 'data-view="surface"' in _html()

    def test_findings_view_still_exists(self):
        assert 'data-view="findings"' in _html()

    def test_ml_readiness_view_still_exists(self):
        assert 'data-view="mlreadiness"' in _html()

    def test_repeater_view_still_exists(self):
        assert 'data-view="repeater"' in _html()

    def test_title_unchanged(self):
        assert "RAVEN" in _html()
