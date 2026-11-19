"""RAVEN V7 Agent Environment — Part 04.

Provides tool descriptors and handlers for:
- Terminal (PowerShell / cmd / bash)
- Filesystem (read / write / list / delete)
- WSL / Kali integration
- Script Workshop execution

All actions route through CapabilityGate. No environment tool can
self-grant authority. External output is UNTRUSTED DATA.
"""
from .terminal import TerminalTool, TerminalResult
from .filesystem import FilesystemTools, FileEntry
from .wsl import WslBridge, WslResult
from .scripts import ScriptRunner, ScriptResult
from .registry import register_env_tools

__all__ = [
    "TerminalTool", "TerminalResult",
    "FilesystemTools", "FileEntry",
    "WslBridge", "WslResult",
    "ScriptRunner", "ScriptResult",
    "register_env_tools",
]
