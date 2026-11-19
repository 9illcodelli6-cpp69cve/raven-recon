"""Cross-platform locations for RAVEN's persistent data (Linux port).

One place decides where workspaces, the V7 control DBs and settings live, so the
desktop launcher, the packaged binary and the server agree on a single folder.

Resolution order (first match wins):

1. ``RAVEN_DATA_DIR`` environment variable — explicit override (the Linux
   launcher sets it so source runs and the packaged binary share one data folder).
2. Frozen Windows build (``RAVEN.exe``) — the exe's own directory, unchanged from
   the original behaviour (portable "data next to the exe").
3. Frozen Linux/macOS build — the per-user XDG data dir
   (``$XDG_DATA_HOME/raven-recon``, default ``~/.local/share/raven-recon``). A
   binary installed under ``~/.local/bin`` or ``/opt`` must not scatter data
   beside itself, and that location may not be writable.
4. Running from source — ``None``: the caller keeps its historical behaviour
   (cwd-relative ``Path(".")``), which the test-suite relies on.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

APP_DIR_NAME = "raven-recon"
ENV_DATA_DIR = "RAVEN_DATA_DIR"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def xdg_data_home() -> Path:
    raw = os.environ.get("XDG_DATA_HOME", "").strip()
    # The XDG spec says a relative value must be ignored.
    if raw and os.path.isabs(raw):
        return Path(raw)
    return Path.home() / ".local" / "share"


def user_data_dir() -> Path:
    """Per-user data folder for the packaged app on POSIX systems."""
    return xdg_data_home() / APP_DIR_NAME


def resolve_data_root() -> Optional[Path]:
    """Return the persistent data root, or ``None`` for the source/cwd default."""
    override = os.environ.get(ENV_DATA_DIR, "").strip()
    if override:
        return Path(override).expanduser().resolve()
    if is_frozen():
        if sys.platform == "win32":
            return Path(sys.executable).resolve().parent
        return user_data_dir()
    return None


def ensure_dir(path: Path) -> Path:
    """Create ``path`` (owner-only permissions on POSIX) and return it."""
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return path
