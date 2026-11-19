"""A6-TERM (Wave 6) — the console-flash is dead.

Proves deliverable #1: status polling no longer spawns a shell on every tick.
Today's defect: ``TerminalTool.is_available`` ran a fresh ``subprocess.run`` for
powershell AND bash on EVERY ``/api/v7/status`` poll (every 30s for the app's life),
each flashing a console on a window-less pywebview host.

After the rework ``api_terminal_status`` reads the cached, ``shutil.which``-first
``EnvironmentProbe``. These tests inject a spy probe (and monkeypatch the environment
module's ``subprocess``) to assert repeated polls spawn ZERO processes.

Run:  python -m pytest tests/test_terminal_no_flash.py -q
"""
import unittest

from raven.api import server
from raven.runtime import environment as env_mod
from raven.runtime.environment import EnvironmentProbe


class _SpyProber:
    """Counts fallback spawn-probe calls (a real spawn would be one of these)."""
    def __init__(self, result=True):
        self.calls = []
        self._result = result

    def __call__(self, shell):
        self.calls.append(shell)
        return self._result


class StatusNoFlash(unittest.TestCase):
    def setUp(self):
        self._saved_probe = server._ENV_PROBE

    def tearDown(self):
        server._ENV_PROBE = self._saved_probe

    def _install_probe(self, probe):
        server._ENV_PROBE = probe

    def test_which_resolved_shells_spawn_nothing(self):
        # which() resolves every shell -> the probe returns availability with ZERO
        # spawns, no matter how many times status is polled.
        spy = _SpyProber()
        self._install_probe(EnvironmentProbe(
            which=lambda s: r"C:\fake\%s.exe" % s, prober=spy))
        for _ in range(25):
            t = server.api_terminal_status()
        self.assertEqual(set(t), {"available", "shells", "default_shell", "history_count"})
        self.assertEqual(set(t["shells"]), {"powershell", "bash", "cmd"})
        self.assertEqual(spy.calls, [], "which-resolved shells must never spawn a probe")

    def test_repeated_polls_probe_at_most_once_per_shell(self):
        # Even when which() can't resolve (forcing the fallback spawn), repeated polls
        # hit the cache: the spawn count is bounded by the distinct shells, NOT by the
        # number of polls. This is what removes the per-tick flash.
        spy = _SpyProber()
        self._install_probe(EnvironmentProbe(
            ttl_s=10_000.0, which=lambda s: None, prober=spy))
        server.api_terminal_status()
        after_first = len(spy.calls)
        for _ in range(30):
            server.api_terminal_status()
        self.assertEqual(len(spy.calls), after_first,
                         "polls after the first must spawn zero new probes (cached)")
        # status queries exactly powershell/bash/cmd -> at most those three probes ever.
        self.assertLessEqual(len(set(spy.calls)), 3)

    def test_no_real_subprocess_on_status_poll(self):
        # Hard regression guard: if the status path ever tries a REAL spawn, fail.
        spy = _SpyProber()
        self._install_probe(EnvironmentProbe(
            which=lambda s: r"C:\fake\%s.exe" % s, prober=spy))
        called = {"n": 0}

        class _Boom:
            def __call__(self, *a, **k):
                called["n"] += 1
                raise AssertionError("status poll must not spawn a subprocess")

        saved_run = env_mod.subprocess.run
        env_mod.subprocess.run = _Boom()
        try:
            for _ in range(10):
                server.api_terminal_status()
        finally:
            env_mod.subprocess.run = saved_run
        self.assertEqual(called["n"], 0)

    def test_comprehensive_status_terminal_block_does_not_spawn(self):
        # api_comprehensive_status delegates the terminal block to api_terminal_status;
        # with a which-resolving probe it too spawns nothing. AI status is stubbed so
        # the test stays hermetic (AI boundary is A13's concern, not this wave).
        spy = _SpyProber()
        self._install_probe(EnvironmentProbe(
            which=lambda s: r"C:\fake\%s.exe" % s, prober=spy))
        saved_ai = server._ai_status_dict
        server._ai_status_dict = lambda: {"configured": False, "available": False,
                                          "display": "Not configured", "provider": None,
                                          "provider_display": None, "model": None}
        try:
            s = server.api_comprehensive_status()
        finally:
            server._ai_status_dict = saved_ai
        self.assertIn("terminal", s)
        self.assertEqual(set(s["terminal"]), {"available", "shells"})
        self.assertEqual(spy.calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
