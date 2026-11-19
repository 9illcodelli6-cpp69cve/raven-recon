"""Regression tests for the quarantined executor; no browser or target is used."""
from contextlib import ExitStack
import unittest
from unittest.mock import Mock, patch

from raven.api import xss_executor as xe


class DisabledExecutorTests(unittest.TestCase):
    def setUp(self):
        self.boundaries = ExitStack()
        self.addCleanup(self.boundaries.close)
        self.blocked_calls = []
        for target in (
            "subprocess.Popen", "subprocess.run", "socket.socket",
            "socket.create_connection", "socket.getaddrinfo",
            "urllib.request.urlopen", "tempfile.mkdtemp", "webbrowser.open",
        ):
            mocked = self.boundaries.enter_context(patch(
                target, side_effect=AssertionError(f"disabled executor called {target}")
            ))
            self.blocked_calls.append(mocked)

    def tearDown(self):
        for mocked in self.blocked_calls:
            mocked.assert_not_called()

    def test_direct_confirmation_is_refused_for_every_input(self):
        for url in ("https://example.invalid/", "http://127.0.0.1/", "", None):
            with self.subTest(url=url):
                result = xe.verify_confirmation(url, "unused-token", timeout=0)
                self.assertFalse(result["attempted"])
                self.assertFalse(result["executed"])
                self.assertTrue(result["disabled"])
                self.assertEqual(result["error"], xe.DISABLED_REASON)

    def test_self_test_cannot_start_supplied_fixtures_or_callbacks(self):
        fixture_factory = Mock(side_effect=AssertionError("fixture started"))
        logger = Mock(side_effect=AssertionError("callback called"))
        result = xe.self_test_with_local_fixtures(fixture_factory, logger)
        self.assertFalse(result["ok"])
        self.assertTrue(result["disabled"])
        self.assertEqual(result["cases"], [])
        self.assertIsNone(result["checked_at"])
        self.assertEqual(result["reason"], xe.DISABLED_REASON)
        fixture_factory.assert_not_called()
        logger.assert_not_called()

    def test_mutating_a_returned_status_cannot_enable_confirmation(self):
        stale_status = xe.isolation_status()
        stale_status.update({"ok": True, "disabled": False, "checked_at": "old success"})
        stale_status["cases"].append({"pass": True})
        current_status = xe.isolation_status()
        self.assertFalse(current_status["ok"])
        self.assertTrue(current_status["disabled"])
        self.assertEqual(current_status["cases"], [])
        self.assertIsNone(current_status["checked_at"])
        self.assertFalse(xe.verify_confirmation("https://example.invalid/", "unused")["attempted"])

    def test_self_test_never_enables_a_later_direct_call(self):
        for _ in range(3):
            self.assertFalse(xe.self_test_with_local_fixtures()["ok"])
            self.assertFalse(xe.verify_confirmation("http://127.0.0.1/", "unused")["executed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)