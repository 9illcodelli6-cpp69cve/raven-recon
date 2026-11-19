"""RAVEN V7 Agent Environment Tool Registration — Part 04.

Registers all agent-environment tools with the shared ToolRegistry.

Wave 10 (A10-AGENT): the handlers are no longer a silent ``_noop`` returning
``{"status":"not_dispatched"}``. Each descriptor binds to a REAL handler on a live
subsystem, or is marked EXPLICITLY ``UNAVAILABLE`` (never a silent pass):

* ``env.fs.read/write/list/delete`` -> the workspace-jailed ``FilesystemTools``
  (path-traversal blocked by that module). ``env.fs.delete`` never deletes the jail
  root, removes a directory only on an explicit ``recursive`` request (refused for
  agent tiers unless the composer opted in), and is classed ``Sensitive`` so the
  fail-closed gate requires researcher approval for it.
* ``env.terminal.run`` -> the canonical ``ProcessExecutor`` (``shell=False``,
  argv-only, hidden window, provenance-stamped). For agent tiers a command carrying
  shell metacharacters is rejected before any spawn, so model output can never reach
  a raw shell. The dispatcher additionally gates it on ``ProcessAnalyzer`` and — with
  no risk_class declared — the fail-closed gate treats process execution as SENSITIVE
  (requires researcher approval). This is intentional, not a gap. For agent tiers the
  executable (argv[0]) must be an absolute path or a name that resolves on PATH, may
  not contain ``..``, and no shell / code interpreter may be given an inline-code
  flag (``bash -c``, ``python3 -c``, ``perl -e``...); the command runs in the
  workspace jail with a minimal environment. ``timeout_s`` is honoured (clamped).
* ``env.wsl.run`` / ``env.script.run`` -> no safe canonical backend yet, so they are
  registered with ``availability="UNAVAILABLE"`` (EXPLICITLY unavailable).

``register_env_tools(registry)`` (one-argument) is preserved for existing callers and
tests; passing ``deps`` binds the real backends. Without ``deps`` every handler is an
explicit ``unavailable`` handler — still never ``not_dispatched``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from raven.runtime.execution import ActorKind
from raven.runtime.tools import ToolDescriptor, ToolRegistry, SideEffectClass

# Local filesystem tools are read/write of the workspace; classify them so the
# fail-closed dispatcher gate maps them correctly instead of defaulting SENSITIVE.
# Deleting can destroy irreplaceable workspace data (recon.db, scope.json), so it is
# never a low-risk agent action: Sensitive => the gate requires researcher approval.
_FS_RISK = {
    "env.fs.read":   "SafeReadOnly",
    "env.fs.list":   "SafeReadOnly",
    "env.fs.write":  "LowRiskStateChange",
    "env.fs.delete": "Sensitive",
}

_AGENT_TIERS = (ActorKind.RAVEN_AGENT, ActorKind.PROGRAM_AGENT)


@dataclass
class EnvToolDeps:
    """Live backends the real env handlers close over."""
    fs: object = None                 # agent_env.filesystem.FilesystemTools
    process_executor: object = None   # runtime.process_executor.ProcessExecutor
    actor: ActorKind = ActorKind.RAVEN_AGENT
    workspace_id: Optional[str] = None
    # Explicit, off-by-default composer opt-in (an auditable researcher decision made
    # in code, never from tool arguments) allowing agent tiers to delete directories.
    allow_agent_recursive_delete: bool = False


def _descriptors():
    return [
        ToolDescriptor(
            tool_id="env.terminal.run",
            name="Terminal Run",
            description="Execute a shell command (PowerShell/bash/cmd). Output is untrusted data.",
            required_capability="ProcessAnalyzer",
            side_effect_class=SideEffectClass.PROCESS_EXECUTION,
            input_schema={
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command":  {"type": "string"},
                    "shell":    {"type": "string"},
                    "timeout_s": {"type": "integer"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="env.fs.read",
            name="File Read",
            description="Read a file from the workspace. Path is workspace-relative.",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.LOCAL_READ,
            input_schema={
                "type": "object",
                "required": ["path"],
                "properties": {"path": {"type": "string"}},
            },
        ),
        ToolDescriptor(
            tool_id="env.fs.write",
            name="File Write",
            description="Write content to a workspace file.",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["path", "content"],
                "properties": {
                    "path":    {"type": "string"},
                    "content": {"type": "string"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="env.fs.list",
            name="File List",
            description="List files in a workspace directory.",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.LOCAL_READ,
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        ),
        ToolDescriptor(
            tool_id="env.fs.delete",
            name="File Delete",
            description="Delete a file from the workspace.",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["path"],
                "properties": {"path": {"type": "string"},
                               "recursive": {"type": "boolean"}},
            },
        ),
        ToolDescriptor(
            tool_id="env.wsl.run",
            name="WSL Run",
            description="Execute a command inside WSL/Kali. Output is untrusted data.",
            required_capability="ProcessAnalyzer",
            side_effect_class=SideEffectClass.PROCESS_EXECUTION,
            input_schema={
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {"type": "string"},
                    "distro":  {"type": "string"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="env.script.run",
            name="Script Run",
            description="Execute a script (Python/PowerShell/bash) from the Script Workshop.",
            required_capability="ProcessAnalyzer",
            side_effect_class=SideEffectClass.PROCESS_EXECUTION,
            input_schema={
                "type": "object",
                "required": ["code", "language"],
                "properties": {
                    "code":      {"type": "string"},
                    "language":  {"type": "string"},
                    "script_id": {"type": "string"},
                },
            },
        ),
    ]


def _unavailable(reason: str):
    def _h(args: dict) -> dict:
        return {"status": "unavailable", "reason": reason}
    return _h


def _fs_handlers(fs, actor: Optional[ActorKind] = None,
                 allow_agent_recursive_delete: bool = False):
    def _read(args: dict) -> dict:
        r = fs.read(str(args.get("path", "")))
        return {"status": "ok" if r.success else "error", "path": r.path,
                "content": r.content, "size": r.size, "error": r.error}

    def _write(args: dict) -> dict:
        r = fs.write(str(args.get("path", "")), str(args.get("content", "")))
        return {"status": "ok" if r.success else "error", "path": r.path,
                "bytes_written": r.bytes_written, "error": r.error}

    def _list(args: dict) -> dict:
        if getattr(fs, "root", "") is None:
            return {"status": "unavailable", "entries": [],
                    "error": "no active workspace"}
        entries = fs.list_dir(str(args.get("path", ".")))
        return {"status": "ok", "entries": [e.to_dict() for e in entries]}

    def _delete(args: dict) -> dict:
        path = str(args.get("path", "") or "")
        recursive = args.get("recursive", False) is True
        if (recursive and (actor in _AGENT_TIERS or actor is None)
                and not allow_agent_recursive_delete):
            return {"status": "denied", "deleted": False, "path": path,
                    "error": "recursive delete is not permitted for the agent tier"}
        remove = getattr(fs, "remove", None)
        if callable(remove):
            r = remove(path, recursive=recursive)
            if r.deleted:
                return {"status": "ok", "deleted": True, "path": path, "error": None}
            return {"status": "denied" if r.refused else "error", "deleted": False,
                    "path": path, "error": r.error}
        ok = fs.delete(path)
        return {"status": "ok" if ok else "error", "deleted": bool(ok), "path": path}

    return {"env.fs.read": _read, "env.fs.write": _write,
            "env.fs.list": _list, "env.fs.delete": _delete}


# Shells / code interpreters that execute an inline program given by a flag. For the
# agent tier these turn the argv-only contract back into "run arbitrary code", so an
# inline-code invocation is refused wherever it appears in argv (this also catches
# wrappers such as ``env``/``setsid``/``timeout``/``nohup`` ``bash -c ...``).
_SHELL_NAMES = frozenset({
    "sh", "bash", "rbash", "dash", "ash", "zsh", "ksh", "mksh", "pdksh", "yash",
    "fish", "csh", "tcsh", "busybox", "toybox", "xonsh", "elvish", "nu",
})
# interpreter -> short-option letters that take inline code (also matched inside a
# combined short-option cluster such as ``-lc`` / ``-ne``), plus long options.
_INLINE_CODE_FLAGS = {
    "python": ("c", ("--command",)),
    "pypy":   ("c", ()),
    "perl":   ("eE", ()),
    "ruby":   ("e", ()),
    "node":   ("ep", ("--eval", "--print")),
    "nodejs": ("ep", ("--eval", "--print")),
    "deno":   ("", ("eval",)),
    "bun":    ("e", ("--eval",)),
    "php":    ("rRBE", ("--run",)),
    "lua":    ("e", ()),
    "luajit": ("e", ()),
    "osascript": ("e", ()),
    "rscript": ("e", ()),
}
# Windows shells take inline commands through these (case-insensitive) options.
_WIN_SHELL_INLINE = {
    "pwsh":       ("-c", "-command", "/c", "/command", "-ec", "-e", "-enc",
                   "-encodedcommand", "-cwa", "-commandwithargs"),
    "powershell": ("-c", "-command", "/c", "/command", "-ec", "-e", "-enc",
                   "-encodedcommand"),
    "cmd":        ("/c", "/k", "/r"),
}


def _exe_base(arg: str) -> str:
    import ntpath
    import posixpath
    import re
    base = ntpath.basename(posixpath.basename(arg)).lower()
    for ext in (".exe", ".cmd", ".bat", ".com"):
        base = base.removesuffix(ext)
    # python3 / python3.12 / perl5.36 / lua5.4 -> python / perl / lua
    m = re.fullmatch(r"([a-z]+?)(?:\d+(?:\.\d+)*)?(?:-\w+)?", base)
    return m.group(1) if m else base


def _inline_code_reason(argv) -> Optional[str]:
    """Return a refusal reason if any shell/interpreter in argv gets inline code."""
    for i, arg in enumerate(argv):
        base = _exe_base(arg)
        rest = argv[i + 1:]
        if base in _WIN_SHELL_INLINE:
            for a in rest:
                low = a.lower()
                if low in _WIN_SHELL_INLINE[base] or low.startswith(("-command", "-encodedcommand")):
                    return (f"shell interpreter '{base}' with an inline command ({a}) "
                            f"is refused for the agent tier")
        elif base in _SHELL_NAMES:
            # POSIX shells: -c, alone or inside a short-option cluster (-lc, -xc...).
            for a in rest:
                if (a.startswith("-") and not a.startswith("--") and len(a) > 1
                        and a[1:].isalpha() and "c" in a[1:]):
                    return (f"shell interpreter '{base}' with an inline command ({a}) "
                            f"is refused for the agent tier")
        spec = _INLINE_CODE_FLAGS.get(base)
        if spec is not None:
            letters, longs = spec
            for a in rest:
                if a in longs or any(a.startswith(lo + "=") for lo in longs):
                    return (f"interpreter '{base}' with inline code ({a}) "
                            f"is refused for the agent tier")
                if (letters and a.startswith("-") and not a.startswith("--") and len(a) > 1
                        and any(ch in letters for ch in a[1:])):
                    return (f"interpreter '{base}' with inline code ({a}) "
                            f"is refused for the agent tier")
    return None


def _agent_executable_reason(argv) -> Optional[str]:
    """Conservative argv[0] check for agent tiers. None => acceptable."""
    import shutil
    exe = argv[0]
    if not exe or "\x00" in exe:
        return "empty executable"
    parts = exe.replace("\\", "/").split("/")
    if ".." in parts:
        return "path traversal in executable path is refused"
    has_sep = ("/" in exe) or ("\\" in exe)
    if has_sep:
        if not os.path.isabs(exe):
            return "a relative executable path is refused (use an absolute path or a bare command name)"
        if not (os.path.isfile(exe) and os.access(exe, os.X_OK)):
            return f"executable not found: {exe}"
    elif shutil.which(exe) is None:
        return f"executable not found on PATH: {exe}"
    return _inline_code_reason(argv)


def _terminal_handler(deps: EnvToolDeps):
    """Route env.terminal.run through the canonical ProcessExecutor (never raw shell)."""
    import shlex
    from raven.runtime import process_executor as _pe
    from raven.runtime.process_executor import ProcessSpec, SHELL_METACHARACTERS

    max_timeout = float(getattr(_pe, "MAX_DEFAULT_TIMEOUT_S", 60.0))
    pexec = deps.process_executor
    actor = deps.actor or ActorKind.RAVEN_AGENT
    agent_tier = actor in _AGENT_TIERS

    def _h(args: dict) -> dict:
        if pexec is None:
            return {"status": "unavailable",
                    "reason": "env.terminal.run not bound to a ProcessExecutor"}
        command = str(args.get("command", "") or "")
        # Agent tiers are argv-only: a command carrying shell metacharacters is
        # refused before any spawn. Model output can never reach a raw shell.
        if agent_tier and SHELL_METACHARACTERS.search(command):
            return {"status": "denied",
                    "error": "argv-only: shell metacharacters are rejected for the agent tier"}
        timeout_s = None
        raw_timeout = args.get("timeout_s")
        if raw_timeout is not None:
            if (isinstance(raw_timeout, bool) or not isinstance(raw_timeout, (int, float))
                    or raw_timeout <= 0):
                return {"status": "invalid", "error": "timeout_s must be a positive number"}
            timeout_s = float(min(float(raw_timeout), max_timeout))
        try:
            argv = shlex.split(command, posix=(os.name != "nt"))
        except ValueError as exc:
            return {"status": "invalid", "error": f"unparsable command: {exc}"}
        if not argv:
            return {"status": "invalid", "error": "empty command"}
        cwd = None
        env_mode = "scrubbed_inherit"
        if agent_tier:
            reason = _agent_executable_reason(argv)
            if reason:
                return {"status": "denied", "error": f"argv-only: {reason}"}
            # Run inside the workspace jail with a minimal, secret-free environment.
            env_mode = "minimal"
            fs = deps.fs
            if fs is not None:
                cwd = getattr(fs, "root", None)
        spec = ProcessSpec(
            argv=argv,
            cwd=cwd,
            env_mode=env_mode,
            timeout_s=timeout_s,
            actor=actor,
            tool_id="env.terminal.run",
            workspace_id=deps.workspace_id,
            execution_profile="PROCESS",
            task_id=_current_task_id(),
        )
        result = pexec.execute(spec)
        out = result.to_dict()
        out["status"] = result.status.value
        return out

    return _h


def register_env_tools(registry: ToolRegistry, deps: Optional[EnvToolDeps] = None) -> int:
    """Register all Part 04 environment tools. Returns count registered.

    ``deps`` (optional) binds real backends. Without it every handler is an explicit
    ``unavailable`` handler — never ``not_dispatched``.
    """
    tools = _descriptors()

    # Explicitly-unavailable tools (no safe canonical backend yet).
    unavailable_ids = {"env.wsl.run", "env.script.run"}

    handlers = {}
    if deps is not None and deps.fs is not None:
        handlers.update(_fs_handlers(
            deps.fs, actor=deps.actor,
            allow_agent_recursive_delete=bool(deps.allow_agent_recursive_delete)))
    if deps is not None:
        handlers["env.terminal.run"] = _terminal_handler(deps)

    registered = 0
    for tool in tools:
        if tool.tool_id in unavailable_ids:
            tool.availability = "UNAVAILABLE"
            tool.metadata.setdefault("unavailable_reason",
                                     "no safe canonical backend wired this phase")
            registry.register(tool, _unavailable(
                f"{tool.tool_id} is explicitly unavailable (no canonical backend)"))
            registered += 1
            continue
        if tool.tool_id in _FS_RISK:
            tool.metadata.setdefault("risk_class", _FS_RISK[tool.tool_id])
        handler = handlers.get(tool.tool_id)
        if handler is None:
            handler = _unavailable(
                f"{tool.tool_id} not bound to a live backend (no deps)")
        registry.register(tool, handler)
        registered += 1
    return registered


def _current_task_id():
    """The agent task this terminal call belongs to (see runtime.tools.CURRENT_TASK_ID)."""
    try:
        from ..runtime.tools import CURRENT_TASK_ID
        return CURRENT_TASK_ID.get()
    except Exception:
        return None
