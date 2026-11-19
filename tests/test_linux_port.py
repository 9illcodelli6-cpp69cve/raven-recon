"""Linux-port regression tests.

Covers the pieces that changed so RAVEN runs natively on Linux:
  * raven.platform_paths — where persistent data lives (env override, frozen
    Windows next-to-exe, frozen Linux XDG dir, source = cwd);
  * raven.ml.inference.resolve_weights_path — the Windows-written model registry
    (C:\\Users\\... / models\\x.pkl) resolves on POSIX, only inside models/;
  * terminal default shell — PowerShell on Windows, bash elsewhere, with the
    frozen response shape unchanged;
  * launch.py — argument parsing works without importing the server.
"""
import importlib
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


# ── platform_paths ────────────────────────────────────────────────────────────

def test_data_root_env_override_wins(monkeypatch, tmp_path):
    from raven import platform_paths as pp
    monkeypatch.setenv("RAVEN_DATA_DIR", str(tmp_path / "data"))
    assert pp.resolve_data_root() == (tmp_path / "data").resolve()


def test_data_root_source_run_is_none(monkeypatch):
    from raven import platform_paths as pp
    monkeypatch.delenv("RAVEN_DATA_DIR", raising=False)
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert pp.resolve_data_root() is None


def test_data_root_frozen_linux_uses_xdg(monkeypatch, tmp_path):
    from raven import platform_paths as pp
    monkeypatch.delenv("RAVEN_DATA_DIR", raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert pp.resolve_data_root() == tmp_path / "xdg" / "raven-recon"


def test_data_root_frozen_linux_ignores_relative_xdg(monkeypatch):
    from raven import platform_paths as pp
    monkeypatch.delenv("RAVEN_DATA_DIR", raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", "relative/dir")
    assert pp.resolve_data_root() == Path.home() / ".local" / "share" / "raven-recon"


def test_data_root_frozen_windows_is_next_to_exe(monkeypatch, tmp_path):
    from raven import platform_paths as pp
    monkeypatch.delenv("RAVEN_DATA_DIR", raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    exe = tmp_path / "dist" / "RAVEN.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"")
    monkeypatch.setattr(sys, "executable", str(exe))
    assert pp.resolve_data_root() == exe.parent.resolve()


def test_ensure_dir_is_private_on_posix(tmp_path):
    from raven import platform_paths as pp
    d = pp.ensure_dir(tmp_path / "a" / "b")
    assert d.is_dir()
    if sys.platform != "win32":
        assert (d.stat().st_mode & 0o777) == 0o700


# ── resolve_weights_path (Windows-written model registry on POSIX) ────────────

def _a_model_file():
    files = sorted((REPO / "models").glob("*.pkl"))
    if not files:
        pytest.skip("no models/*.pkl artifacts in this checkout")
    return files[0]


def test_weights_windows_absolute_path_resolves_to_repo_models():
    from raven.ml.inference import resolve_weights_path
    f = _a_model_file()
    raw = "C:\\Users\\someone\\OneDrive\\Desktop\\RAVEN\\raven-recon\\models\\" + f.name
    assert Path(resolve_weights_path(raw)) == f


def test_weights_backslash_relative_path_resolves():
    from raven.ml.inference import resolve_weights_path
    f = _a_model_file()
    assert Path(resolve_weights_path("models\\" + f.name)).resolve() == f.resolve()


def test_weights_existing_path_is_unchanged():
    from raven.ml.inference import resolve_weights_path
    f = _a_model_file()
    assert resolve_weights_path(str(f)) == str(f)


def test_weights_unknown_file_returns_original():
    from raven.ml.inference import resolve_weights_path
    raw = "C:\\nowhere\\models\\does_not_exist_123.pkl"
    assert resolve_weights_path(raw) == raw


def test_weights_lookup_never_leaves_repo_models(tmp_path, monkeypatch):
    """A same-named pickle in cwd must NOT be picked up (pickle trust boundary)."""
    from raven.ml.inference import resolve_weights_path
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "planted_only_here.pkl").write_bytes(b"x")
    monkeypatch.chdir(tmp_path)
    raw = "C:\\x\\models\\planted_only_here.pkl"
    assert resolve_weights_path(raw) == raw


# ── terminal default shell ────────────────────────────────────────────────────

def test_terminal_default_shell_per_platform(monkeypatch):
    from raven.api import server
    monkeypatch.setattr(server.sys, "platform", "linux")
    assert server._default_terminal_shell(ps_available=True, bash_available=True) == "bash"
    assert server._default_terminal_shell(ps_available=True, bash_available=False) == "powershell"
    monkeypatch.setattr(server.sys, "platform", "win32")
    assert server._default_terminal_shell(ps_available=True, bash_available=True) == "powershell"
    assert server._default_terminal_shell(ps_available=False, bash_available=True) == "bash"


def test_terminal_status_shape_unchanged():
    from raven.api import server
    t = server.api_terminal_status()
    assert set(t) == {"available", "shells", "default_shell", "history_count"}
    assert set(t["shells"]) == {"powershell", "bash", "cmd"}
    if sys.platform.startswith("linux") and t["shells"]["bash"]:
        assert t["default_shell"] == "bash"


# ── launch.py ─────────────────────────────────────────────────────────────────

def test_launch_args_parse_without_server_import(monkeypatch):
    monkeypatch.syspath_prepend(str(REPO))
    sys.modules.pop("launch", None)
    launch = importlib.import_module("launch")
    a = launch._parse_args(["--browser", "--port", "9000", "--gui", "gtk"])
    assert a.browser and a.port == 9000 and a.gui == "gtk"
    assert launch._parse_args([]).port == launch.PORT


def test_linux_packaging_files_present():
    for rel in ("raven-app", "build-linux.sh", "packaging/linux/install.sh",
                "packaging/linux/raven-recon.desktop.in",
                "packaging/linux/raven-recon.png", "requirements-linux.txt"):
        assert (REPO / rel).is_file(), rel
    desktop = (REPO / "packaging/linux/raven-recon.desktop.in").read_text()
    assert "Exec=@EXEC@" in desktop and "Icon=raven-recon" in desktop
