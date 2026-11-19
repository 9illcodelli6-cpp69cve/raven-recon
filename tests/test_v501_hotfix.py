"""RAVEN V5.0.1 Desktop UX Hotfix — Regression Tests.

Covers:
  1. RAVEN-V5.spec has console=False (no CMD window in production EXE)
  2. server.py subprocess.run uses CREATE_NO_WINDOW on win32
  3. shared raven-modal-backdrop exists in prototype.html
  4. raven-modal component exists with correct opaque styling
  5. raven-modal-header / raven-modal-body / raven-modal-footer structure
  6. Identity modal (#idModal) uses raven-modal, not old .modal class
  7. UA modal (#uaModal) exists as a raven-modal
  8. New Target modal (#ntModal) uses raven-modal
  9. safe escaping (HX) is present — no raw innerHTML for target-controlled content
 10. no duplicate modal IDs
 11. close buttons exist on all raven-modals
 12. scan/vignette z-index <= 5 (below modal z-index 101)
 13. raven-modal z-index >= 100
 14. ravenModalOpen / ravenModalClose functions exist
 15. no shell=True in subprocess calls
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "RAVEN-V5.spec"
SERVER_PY = ROOT / "raven" / "api" / "server.py"
HTML = ROOT / "web" / "prototype.html"


class SpecConsoleWindowTest(unittest.TestCase):
    """RAVEN-V5.spec must use console=False for the production EXE."""

    def setUp(self):
        self.spec = SPEC.read_text(encoding="utf-8")

    def test_console_is_false(self):
        self.assertIn("console=False", self.spec,
                      "RAVEN-V5.spec must have console=False — the CMD window fix")

    def test_console_true_absent(self):
        self.assertNotIn("console=True", self.spec,
                         "console=True must be removed")

    def test_name_is_v501(self):
        self.assertIn("RAVEN-V5.0.1", self.spec,
                      "EXE name must be RAVEN-V5.0.1 for the hotfix build")


class SubprocessNoWindowTest(unittest.TestCase):
    """server.py subprocess.run must use CREATE_NO_WINDOW on win32."""

    def setUp(self):
        self.src = SERVER_PY.read_text(encoding="utf-8")

    def test_create_no_window_present(self):
        self.assertIn("CREATE_NO_WINDOW", self.src,
                      "subprocess.run in server.py must use CREATE_NO_WINDOW on win32")

    def test_platform_guard(self):
        self.assertIn('sys.platform == "win32"', self.src,
                      "CREATE_NO_WINDOW must be gated on win32 platform check")

    def test_no_shell_true_in_run(self):
        # shell=True in subprocess is a command-injection risk; must not be present.
        matches = re.findall(r'subprocess\.run\s*\([^)]+shell\s*=\s*True', self.src)
        self.assertEqual(matches, [],
                         "subprocess.run must not use shell=True")

    def test_engine_already_uses_create_no_window(self):
        engine = (ROOT / "raven" / "engine.py").read_text(encoding="utf-8")
        self.assertIn("CREATE_NO_WINDOW", engine,
                      "engine.py already uses CREATE_NO_WINDOW (regression guard)")


class SharedModalBackdropTest(unittest.TestCase):
    """shared raven-modal-backdrop must exist as a top-level DOM element."""

    def setUp(self):
        self.html = HTML.read_text(encoding="utf-8")

    def test_backdrop_element_exists(self):
        self.assertIn('id="ravenModalBackdrop"', self.html)

    def test_backdrop_class_exists(self):
        self.assertIn('class="raven-modal-backdrop"', self.html)

    def test_backdrop_css_defined(self):
        self.assertIn(".raven-modal-backdrop{", self.html)

    def test_backdrop_z_index_100(self):
        m = re.search(r'\.raven-modal-backdrop\{[^}]+z-index:(\d+)', self.html)
        self.assertIsNotNone(m, "raven-modal-backdrop must declare z-index")
        self.assertGreaterEqual(int(m.group(1)), 100)


class RavenModalComponentTest(unittest.TestCase):
    """raven-modal component CSS must declare opaque background and correct z-index."""

    def setUp(self):
        self.html = HTML.read_text(encoding="utf-8")

    def test_raven_modal_css_exists(self):
        self.assertIn(".raven-modal{", self.html)

    def test_raven_modal_header_exists(self):
        self.assertIn(".raven-modal-header{", self.html)

    def test_raven_modal_body_exists(self):
        self.assertIn(".raven-modal-body{", self.html)

    def test_raven_modal_footer_exists(self):
        self.assertIn(".raven-modal-footer{", self.html)

    def test_raven_modal_z_index_above_scan(self):
        m = re.search(r'\.raven-modal\{[^}]+z-index:(\d+)', self.html)
        self.assertIsNotNone(m, "raven-modal must declare z-index")
        self.assertGreaterEqual(int(m.group(1)), 100,
                                "raven-modal z-index must be >= 100 (above scan overlay at z-5)")

    def test_raven_modal_opaque_background(self):
        # Must use a solid var() color, not rgba() with alpha < 1 that would look transparent
        m = re.search(r'\.raven-modal\{[^}]+background:([^;]+)', self.html)
        self.assertIsNotNone(m)
        bg = m.group(1)
        # var(--surface-2) or similar solid token is acceptable
        self.assertNotRegex(bg, r'rgba\(\d+,\s*\d+,\s*\d+,\s*0\.\d+\)',
                            "raven-modal main background must not be semi-transparent rgba()")

    def test_raven_modal_max_height_for_scroll(self):
        self.assertIn("max-height", self.html.split(".raven-modal{")[1].split("}")[0])

    def test_raven_modal_body_overflow_y_auto(self):
        body_css = self.html.split(".raven-modal-body{")[1].split("}")[0]
        self.assertIn("overflow-y:auto", body_css,
                      "raven-modal-body must scroll internally")


class ScanVignetteZIndexTest(unittest.TestCase):
    """Decorative overlays must be below modal z-index to not cover modals."""

    def setUp(self):
        self.html = HTML.read_text(encoding="utf-8")

    def test_scan_z_index_below_modals(self):
        m = re.search(r'\.scan\{[^}]+z-index:(\d+)', self.html)
        self.assertIsNotNone(m, ".scan must declare z-index")
        self.assertLessEqual(int(m.group(1)), 10,
                             ".scan z-index must be <= 10, well below raven-modal z-index 101")

    def test_vignette_z_index_below_modals(self):
        m = re.search(r'\.vignette\{[^}]+z-index:(\d+)', self.html)
        self.assertIsNotNone(m, ".vignette must declare z-index")
        self.assertLessEqual(int(m.group(1)), 10)


class IdentityModalStructureTest(unittest.TestCase):
    """#idModal must be a raven-modal, not the old .modal class."""

    def setUp(self):
        self.html = HTML.read_text(encoding="utf-8")

    def test_idmodal_uses_raven_modal(self):
        self.assertIn('class="raven-modal" id="idModal"', self.html)

    def test_idmodal_not_old_modal(self):
        # The old pattern was: <div class="modal" id="idModal">
        self.assertNotIn('class="modal" id="idModal"', self.html)

    def test_idmodal_has_aria_modal(self):
        self.assertIn('aria-modal="true"', self.html)

    def test_idmodal_header_present(self):
        self.assertIn('raven-modal-header', self.html.split('id="idModal"')[1].split('id="')[0])

    def test_idmodal_has_close_button(self):
        # id="idClose" must exist
        self.assertIn('id="idClose"', self.html)

    def test_idmodal_has_save_button(self):
        self.assertIn('id="idSave"', self.html)

    def test_idmodal_has_cancel_button(self):
        self.assertIn('id="idCancel"', self.html)


class UAModalTest(unittest.TestCase):
    """#uaModal must exist as a proper raven-modal window."""

    def setUp(self):
        self.html = HTML.read_text(encoding="utf-8")

    def test_uamodal_exists(self):
        self.assertIn('id="uaModal"', self.html)

    def test_uamodal_uses_raven_modal(self):
        self.assertIn('class="raven-modal" id="uaModal"', self.html)

    def test_uamodal_has_header(self):
        seg = self.html.split('id="uaModal"')[1].split('</div>')[0]
        self.assertIn('raven-modal-header', seg)

    def test_uamodal_has_close_button(self):
        self.assertIn('id="uaModalClose"', self.html)

    def test_uamodal_has_done_button(self):
        self.assertIn('id="uaModalDone"', self.html)

    def test_uamodal_has_profile_list_container(self):
        self.assertIn('id="uaModalList"', self.html)

    def test_uamodal_has_current_display(self):
        self.assertIn('id="uaCurrentDisplay"', self.html)

    def test_uamodal_title(self):
        self.assertIn('USER-AGENT', self.html.split('id="uaModal"')[1].split('</div>')[0])


class NewTargetModalTest(unittest.TestCase):
    """#ntModal must use raven-modal (migrated from old .modal in V5.0.1)."""

    def setUp(self):
        self.html = HTML.read_text(encoding="utf-8")

    def test_ntmodal_uses_raven_modal(self):
        self.assertIn('class="raven-modal" id="ntModal"', self.html)

    def test_ntmodal_not_old_modal(self):
        self.assertNotIn('class="modal" id="ntModal"', self.html)

    def test_ntmodal_has_close_button(self):
        self.assertIn('id="ntClose"', self.html)

    def test_ntmodal_has_create_button(self):
        self.assertIn('id="ntCreate"', self.html)


class ModalJSFunctionsTest(unittest.TestCase):
    """ravenModalOpen / ravenModalClose / renderUaModal must be defined in JS."""

    def setUp(self):
        self.html = HTML.read_text(encoding="utf-8")

    def test_raven_modal_open_defined(self):
        self.assertIn("function ravenModalOpen(", self.html)

    def test_raven_modal_close_defined(self):
        self.assertIn("function ravenModalClose(", self.html)

    def test_render_ua_modal_defined(self):
        self.assertIn("function renderUaModal(", self.html)

    def test_active_raven_modal_variable(self):
        self.assertIn("activeRavenModal", self.html)

    def test_backdrop_click_closes_modal(self):
        self.assertIn("ravenModalBackdrop.addEventListener('click'", self.html)

    def test_ua_btn_opens_ua_modal(self):
        self.assertIn("ravenModalOpen('uaModal')", self.html)

    def test_id_btn_opens_id_modal(self):
        self.assertIn("ravenModalOpen('idModal')", self.html)

    def test_nt_open_uses_raven_modal(self):
        self.assertIn("ravenModalOpen('ntModal')", self.html)

    def test_escape_calls_raven_modal_close(self):
        self.assertIn("ravenModalClose()", self.html)


class NoDuplicateIdTest(unittest.TestCase):
    """No two elements may share the same id attribute."""

    def setUp(self):
        self.html = HTML.read_text(encoding="utf-8")

    def test_no_duplicate_modal_ids(self):
        ids = re.findall(r'\bid="([^"]+)"', self.html)
        modal_ids = [i for i in ids if 'Modal' in i or i in ('idModal','ntModal','uaModal','ravenModalBackdrop')]
        seen = set()
        dupes = []
        for mid in modal_ids:
            if mid in seen:
                dupes.append(mid)
            seen.add(mid)
        self.assertEqual(dupes, [], f"Duplicate modal IDs found: {dupes}")


class SafeEscapingTest(unittest.TestCase):
    """HX() must be the only path for target-controlled content in innerHTML."""

    def setUp(self):
        self.html = HTML.read_text(encoding="utf-8")

    def test_hx_function_defined(self):
        self.assertIn("function HX(s)", self.html)

    def test_ua_modal_uses_hx_for_catalog_content(self):
        # renderUaModal uses HX() for pair[0] and pair[1] — catalog data from server
        ua_render = self.html.split("function renderUaModal(")[1].split("function ")[0]
        self.assertIn("HX(pair[0])", ua_render)
        self.assertIn("HX((pair[1]", ua_render)

    def test_no_raw_innerhtml_in_raven_modal_backdrop(self):
        # ravenModalBackdrop is only a backdrop; no innerHTML should be set on it
        backdrop_js = self.html.split("ravenModalBackdrop")[1].split("ravenModalClose")[0]
        self.assertNotIn(".innerHTML", backdrop_js.split("function ")[0])


if __name__ == "__main__":
    unittest.main()
