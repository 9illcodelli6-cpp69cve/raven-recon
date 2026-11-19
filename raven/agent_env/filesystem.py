"""RAVEN V7 Filesystem Tool — Part 04.

Workspace-scoped file operations.
All paths are resolved relative to the workspace root.
Path traversal attempts are blocked.

The jail root is either a fixed directory or a resolver callable that returns the
ACTIVE workspace directory on every call (so the jail follows workspace switches).
A resolver that returns nothing (no workspace open) disables every operation — there
is deliberately no fallback to the data root or the server's working directory.

Deleting is the most dangerous operation, so it is the most restricted: the jail
root itself ("", ".", or anything resolving to it) is never deleted, a symlink is
removed as a link (never followed), and a directory is removed only when the caller
explicitly asks for a recursive delete.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Union


@dataclass
class FileEntry:
    name:        str
    path:        str
    is_dir:      bool = False
    size_bytes:  int = 0
    modified_at: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "is_dir": self.is_dir,
            "size_bytes": self.size_bytes,
            "modified_at": self.modified_at,
        }


@dataclass
class FileReadResult:
    path:    str
    content: str = ""
    error:   Optional[str] = None
    size:    int = 0

    @property
    def success(self) -> bool:
        return self.error is None


@dataclass
class FileWriteResult:
    path:  str
    bytes_written: int = 0
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


@dataclass
class FileDeleteResult:
    path:    str
    deleted: bool = False
    error:   Optional[str] = None
    refused: bool = False      # True when refused by policy (root, traversal, ...)

    @property
    def success(self) -> bool:
        return self.deleted and self.error is None


MAX_READ_BYTES = 1 * 1024 * 1024   # 1 MB read limit

NO_WORKSPACE_ERROR = "No active workspace — workspace filesystem tools are disabled"

RootSpec = Union[str, "os.PathLike[str]", Callable[[], Optional[str]]]


class FilesystemTools:
    """Workspace-scoped filesystem operations.

    All paths are validated against the workspace root.
    Path traversal (../) is rejected.

    ``workspace_root`` is a directory, or a zero-argument callable returning the
    active workspace directory (or None when no workspace is open). With a callable
    the root is re-resolved on every operation and is never created implicitly.
    """

    def __init__(self, workspace_root: RootSpec):
        if callable(workspace_root):
            self._resolver: Optional[Callable[[], Optional[str]]] = workspace_root
            self._static_root: Optional[pathlib.Path] = None
        else:
            self._resolver = None
            self._static_root = pathlib.Path(workspace_root).resolve()
            self._static_root.mkdir(parents=True, exist_ok=True)

    # -- jail root ---------------------------------------------------------------

    def _current_root(self) -> Optional[pathlib.Path]:
        """The jail root for this call, or None (=> every operation is refused)."""
        if self._resolver is None:
            root = self._static_root
        else:
            try:
                raw = self._resolver()
            except Exception:
                return None
            if raw is None or not str(raw).strip():
                return None
            try:
                root = pathlib.Path(raw).resolve()
            except Exception:
                return None
            if not root.is_dir():
                return None
        if root is None or root == pathlib.Path(root.anchor):
            return None            # never jail to a filesystem root
        return root

    @property
    def _root(self) -> Optional[pathlib.Path]:
        return self._current_root()

    def _safe_path(self, rel_path: str) -> Optional[pathlib.Path]:
        """Resolve a relative path inside the workspace. Returns None if unsafe."""
        root = self._current_root()
        if root is None:
            return None
        try:
            p = (root / rel_path).resolve()
            p.relative_to(root)   # raises ValueError if outside root
            return p
        except (ValueError, Exception):
            return None

    def _blocked_reason(self) -> str:
        return NO_WORKSPACE_ERROR if self._current_root() is None else "Path traversal blocked"

    def read(self, rel_path: str, encoding: str = "utf-8") -> FileReadResult:
        p = self._safe_path(rel_path)
        if p is None:
            return FileReadResult(path=rel_path, error=self._blocked_reason())
        if not p.exists():
            return FileReadResult(path=rel_path, error=f"File not found: {rel_path}")
        if p.is_dir():
            return FileReadResult(path=rel_path, error="Path is a directory")
        size = p.stat().st_size
        if size > MAX_READ_BYTES:
            return FileReadResult(
                path=rel_path, size=size,
                error=f"File too large ({size} bytes > {MAX_READ_BYTES})",
            )
        try:
            content = p.read_text(encoding=encoding, errors="replace")
            return FileReadResult(path=rel_path, content=content, size=size)
        except Exception as exc:
            return FileReadResult(path=rel_path, error=str(exc))

    def write(self, rel_path: str, content: str, encoding: str = "utf-8") -> FileWriteResult:
        p = self._safe_path(rel_path)
        if p is None:
            return FileWriteResult(path=rel_path, error=self._blocked_reason())
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding=encoding)
            return FileWriteResult(path=rel_path, bytes_written=len(content.encode(encoding)))
        except Exception as exc:
            return FileWriteResult(path=rel_path, error=str(exc))

    def remove(self, rel_path: str, *, recursive: bool = False) -> FileDeleteResult:
        """Delete one workspace path, refusing anything that could take out the jail.

        * the jail root ("", ".", or any path resolving to it) is never deleted;
        * a symlink is unlinked as a link — its target is never followed or removed;
        * a directory is removed only when ``recursive`` is True.
        """
        rel = "" if rel_path is None else str(rel_path)
        root = self._current_root()
        if root is None:
            return FileDeleteResult(path=rel, error=NO_WORKSPACE_ERROR, refused=True)
        if not rel.strip() or rel.strip() in (".", "./"):
            return FileDeleteResult(path=rel, refused=True,
                                    error="Refusing to delete the workspace root")
        lexical = root / rel
        # A symlink is removed as a link (its parent must itself be inside the jail).
        if lexical.name not in ("", ".", "..") and lexical.is_symlink():
            try:
                parent = lexical.parent.resolve()
                parent.relative_to(root)
            except Exception:
                return FileDeleteResult(path=rel, refused=True,
                                        error="Path traversal blocked")
            try:
                os.unlink(parent / lexical.name)
                return FileDeleteResult(path=rel, deleted=True)
            except Exception as exc:
                return FileDeleteResult(path=rel, error=str(exc))
        p = self._safe_path(rel)
        if p is None:
            return FileDeleteResult(path=rel, refused=True, error="Path traversal blocked")
        if p == root:
            return FileDeleteResult(path=rel, refused=True,
                                    error="Refusing to delete the workspace root")
        if not p.exists():
            return FileDeleteResult(path=rel, error=f"File not found: {rel}")
        try:
            if p.is_dir():
                if not recursive:
                    return FileDeleteResult(
                        path=rel, refused=True,
                        error="Path is a directory (an explicit recursive delete is required)")
                shutil.rmtree(p)
            else:
                p.unlink()
            return FileDeleteResult(path=rel, deleted=True)
        except Exception as exc:
            return FileDeleteResult(path=rel, error=str(exc))

    def delete(self, rel_path: str, recursive: bool = False) -> bool:
        """Boolean wrapper over :meth:`remove` (kept for existing callers)."""
        return self.remove(rel_path, recursive=recursive).deleted

    def list_dir(self, rel_path: str = ".") -> List[FileEntry]:
        root = self._current_root()
        p = self._safe_path(rel_path)
        if root is None or p is None or not p.is_dir():
            return []
        entries = []
        try:
            for item in sorted(p.iterdir()):
                stat = item.stat()
                entries.append(FileEntry(
                    name=item.name,
                    path=str(item.relative_to(root)),
                    is_dir=item.is_dir(),
                    size_bytes=stat.st_size if not item.is_dir() else 0,
                    modified_at=int(stat.st_mtime * 1000),
                ))
        except Exception:
            pass
        return entries

    def exists(self, rel_path: str) -> bool:
        p = self._safe_path(rel_path)
        return p is not None and p.exists()

    @property
    def root(self) -> Optional[str]:
        """The current jail root, or None when no workspace is active."""
        root = self._current_root()
        return str(root) if root is not None else None
