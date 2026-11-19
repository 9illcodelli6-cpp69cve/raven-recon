"""Every inline on*="fn(...)" handler in web/index.html must resolve at runtime.

Regression: the main UI script is wrapped in a strict-mode IIFE, so functions it
declares are NOT globals. Inline handlers resolve names on `window`, so before
the `_INLINE_HANDLERS` export every inline button (Emergency Stop, Refresh, Run
Agent/Program, Save Settings, Add entry, Browser Send, Start Collection, the new
Learning buttons, ...) threw a silent ReferenceError. The older UI tests only
checked that the onclick TEXT existed, which is why this went unnoticed.
"""
import re
import unittest
from pathlib import Path

HTML = (Path(__file__).resolve().parent.parent / "web" / "index.html").read_text(encoding="utf-8")

# Attribute values of inline event handlers, e.g. onclick="navigateTo('x')".
_HANDLER_ATTR = re.compile(r'\son[a-z]+="([^"]*)"')
# A bare call `name(` that is not a method call (`.name(`).
_BARE_CALL = re.compile(r'(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(')
_JS_BUILTINS = {"if", "return", "function", "alert", "confirm"}


def _inline_called_names():
    names = set()
    for value in _HANDLER_ATTR.findall(HTML):
        names.update(n for n in _BARE_CALL.findall(value) if n not in _JS_BUILTINS)
    return names


def _exported_names():
    m = re.search(r"var _INLINE_HANDLERS=\{(.*?)\};", HTML, re.S)
    assert m, "_INLINE_HANDLERS export block missing from web/index.html"
    return set(re.findall(r"([A-Za-z_$][\w$]*)\s*:", m.group(1)))


class InlineHandlerExportTests(unittest.TestCase):
    def test_main_script_is_a_closure(self):
        # The premise of the export: if the IIFE is ever removed this test should be
        # revisited rather than silently passing.
        self.assertIn("(function(){\n'use strict';", HTML)

    def test_every_inline_handler_is_exported(self):
        called = _inline_called_names()
        self.assertGreater(len(called), 20, "sanity: expected many inline handlers")
        missing = called - _exported_names()
        self.assertFalse(missing, f"inline handlers not exported to window: {sorted(missing)}")

    def test_every_export_is_a_defined_function(self):
        for name in _exported_names():
            with self.subTest(name=name):
                self.assertEqual(
                    len(re.findall(rf"^\s*function {re.escape(name)}\(", HTML, re.M)), 1,
                    f"{name} must be defined exactly once")

    def test_export_runs_inside_the_closure(self):
        export_at = HTML.index("var _INLINE_HANDLERS=")
        self.assertIn("window[k]=_INLINE_HANDLERS[k]", HTML[export_at:])
        close_at = HTML.index("})();\n</script>", export_at)
        self.assertGreater(close_at, export_at)


if __name__ == "__main__":
    unittest.main(verbosity=2)
