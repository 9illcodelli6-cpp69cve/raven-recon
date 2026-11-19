"""Behavioral tests for the cached EnvironmentProbe (A2-PROC, Wave 2).

The core regression these guard is the "30s console flash": the probe must detect
once and then answer from cache, so the status poll spawns nothing. Also assert the
which()-first fast path (zero spawns), TTL re-probe, invalidate, and that the spawn
fallback is hidden.
"""
import subprocess
import sys

import pytest

import raven.runtime.environment as env_mod
from raven.runtime.environment import DEFAULT_SHELLS, EnvironmentProbe, _default_prober


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, d):
        self.t += d


def _counting_prober():
    box = {"n": 0}

    def prober(shell):
        box["n"] += 1
        return True

    return prober, box


def test_which_first_means_zero_spawns():
    prober, box = _counting_prober()
    p = EnvironmentProbe(which=lambda s: r"C:\fake\%s.exe" % s, prober=prober)
    assert p.detect("powershell") is True
    assert box["n"] == 0          # which() answered; nothing spawned
    assert p.probe_count == 0
    assert p.which_count == 1


def test_probe_fallback_is_cached():
    prober, box = _counting_prober()
    p = EnvironmentProbe(which=lambda s: None, prober=prober)
    assert p.detect("bash") is True
    for _ in range(5):
        assert p.detect("bash") is True
    assert box["n"] == 1          # probed exactly once, then cached
    assert p.probe_count == 1


def test_ttl_expiry_reprobes():
    clk = _Clock()
    prober, box = _counting_prober()
    p = EnvironmentProbe(ttl_s=10.0, which=lambda s: None, prober=prober, clock=clk)
    p.detect("bash")
    assert box["n"] == 1
    p.detect("bash")
    assert box["n"] == 1          # still cached within TTL
    clk.advance(11)
    p.detect("bash")
    assert box["n"] == 2          # TTL expired -> one re-probe


def test_invalidate_forces_reprobe():
    prober, box = _counting_prober()
    p = EnvironmentProbe(which=lambda s: None, prober=prober)
    p.detect("bash")
    assert box["n"] == 1
    p.invalidate("bash")
    p.detect("bash")
    assert box["n"] == 2
    p.invalidate()  # clear all
    p.detect("bash")
    assert box["n"] == 3


def test_snapshot_and_status_poll_spawn_once_then_never():
    """Explosion regression: snapshot once, then hammer it like the 30s poll."""
    prober, box = _counting_prober()
    p = EnvironmentProbe(which=lambda s: None, prober=prober)
    snap = p.snapshot()
    assert set(snap.keys()) == set(DEFAULT_SHELLS)
    first = box["n"]
    assert first == len(DEFAULT_SHELLS)   # one probe per shell, exactly once
    for _ in range(50):
        p.snapshot()
    assert box["n"] == first               # subsequent polls spawn nothing


def test_refresh_reprobes_all():
    prober, box = _counting_prober()
    p = EnvironmentProbe(which=lambda s: None, prober=prober)
    p.snapshot()
    base = box["n"]
    p.refresh()
    assert box["n"] == base + len(DEFAULT_SHELLS)


def test_default_prober_uses_hidden_window(monkeypatch):
    captured = {}

    class _R:
        returncode = 0

    def fake_run(argv, **kw):
        captured["argv"] = argv
        captured["kw"] = kw
        return _R()

    monkeypatch.setattr(env_mod.subprocess, "run", fake_run)
    ok = _default_prober("cmd")
    assert ok is True
    assert captured["kw"].get("shell") is False
    if sys.platform == "win32":
        assert captured["kw"]["creationflags"] & subprocess.CREATE_NO_WINDOW
        assert "startupinfo" in captured["kw"]
    else:
        assert captured["kw"].get("start_new_session") is True


def test_unknown_shell_probe_returns_false():
    assert _default_prober("no-such-shell-xyz") is False
