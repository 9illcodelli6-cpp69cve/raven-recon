"""v7.1 horror theme + window controls: static checks on the shipped UI files."""
import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INDEX = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
WORKBENCH = (ROOT / "web" / "prototype.html").read_text(encoding="utf-8")


class ThemeTests(unittest.TestCase):
    def test_background_asset_exists_and_is_served_path(self):
        img = ROOT / "web" / "assets" / "raven-mask.jpg"
        self.assertTrue(img.is_file())
        self.assertGreater(img.stat().st_size, 10_000)
        self.assertEqual(img.read_bytes()[:3], b"\xff\xd8\xff")  # JPEG
        for page in (INDEX, WORKBENCH):
            self.assertIn("url('/assets/raven-mask.jpg')", page)

    def test_old_inline_hero_image_removed(self):
        self.assertNotIn('<img class="hero-artwork"', INDEX)
        self.assertLess(len(INDEX.encode("utf-8")), 180_000)

    def test_appearance_modes(self):
        for mode in ("full", "static", "off"):
            self.assertIn(f'data-fx-mode="{mode}"', INDEX)
            self.assertIn(f'[data-fx="{mode}"]' if mode != "full" else 'data-fx', INDEX)
        # the saved mode is applied before first paint on both pages, and storage
        # failures (private mode) fall back to "full"
        for page in (INDEX, WORKBENCH):
            self.assertIn('localStorage.getItem("raven.fx")', page)
            self.assertIn("catch(e){}", page)

    def test_reduced_motion_respected(self):
        self.assertIn("prefers-reduced-motion:reduce", INDEX)
        self.assertIn("prefers-reduced-motion:reduce", WORKBENCH)

    def test_placeholder_pages_not_in_sidebar(self):
        self.assertNotIn('data-nav="scripts"', INDEX)
        self.assertNotIn('data-nav="experiments"', INDEX)

    def test_agent_start_explains_missing_engine(self):
        self.assertIn("No AI engine is ready", INDEX)
        self.assertIn("Write an objective first", INDEX)


class WindowApiTests(unittest.TestCase):
    def _api(self):
        src = (ROOT / "launch.py").read_text(encoding="utf-8")
        mod = ast.parse(src)
        cls = next(n for n in mod.body if isinstance(n, ast.ClassDef) and n.name == "_WindowApi")
        ns = {}
        exec(compile(ast.Module(body=[cls], type_ignores=[]), "launch.py", "exec"), ns)
        return ns["_WindowApi"]

    def test_controls_call_the_window(self):
        calls = []

        class FakeWindow:
            def minimize(self): calls.append("min")
            def maximize(self): calls.append("max")
            def restore(self): calls.append("restore")
            def destroy(self): calls.append("close")

        api = self._api()()
        api.minimize()  # unbound: no error
        api._bind(FakeWindow())
        api.minimize(); api.toggle_maximize(); api.toggle_maximize(); api.close_window()
        self.assertEqual(calls, ["min", "max", "restore", "close"])

    def test_only_public_controls_exposed(self):
        api = self._api()()
        public = sorted(n for n in dir(api) if not n.startswith("_") and callable(getattr(api, n)))
        self.assertEqual(public, ["close_window", "minimize", "toggle_maximize"])


if __name__ == "__main__":
    unittest.main()
