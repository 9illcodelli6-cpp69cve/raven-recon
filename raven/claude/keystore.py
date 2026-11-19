"""The Anthropic API key, encrypted at rest (Fernet / AES-128-CBC + HMAC).

Layout under the RAVEN data folder (owner-only permissions):
    claude/secret.key   random Fernet key            0600
    claude/api_key.enc  the encrypted API key        0600

Honest scope of the protection: the encryption key lives on the same disk, so this stops
the API key leaking in plain text (backups of the data folder without ``secret.key``,
config dumps, grep, screenshots of files) — it is not protection against someone who can
read both files as your user. The key is never returned by any API route (only a short
hint such as ``sk-ant-…3f9a``), never logged, and is scrubbed from child-process
environments.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Optional

_KEY_RE = re.compile(r"^sk-ant-[A-Za-z0-9_\-]{20,300}$")


class KeyStoreError(ValueError):
    pass


def validate_key(key: str) -> str:
    key = (key or "").strip()
    if not _KEY_RE.match(key):
        raise KeyStoreError("That does not look like an Anthropic API key (it starts with 'sk-ant-').")
    if key.startswith("sk-ant-admin"):
        raise KeyStoreError("That is an Admin API key — RAVEN needs a regular API key.")
    return key


def hint(key: Optional[str]) -> Optional[str]:
    if not key:
        return None
    return f"{key[:7]}…{key[-4:]}"


class KeyStore:
    def __init__(self, data_root: Path):
        self.dir = Path(data_root) / "claude"
        self.secret = self.dir / "secret.key"
        self.blob = self.dir / "api_key.enc"

    # ── internals ──────────────────────────────────────────────────────────────
    def _ensure_dir(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.dir, 0o700)

    @staticmethod
    def _write_private(path: Path, data: bytes) -> None:
        """Create/replace a 0600 file without following a symlink planted at ``path``."""
        tmp = path.with_name(path.name + ".tmp")
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    @staticmethod
    def _read_private(path: Path) -> bytes:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise KeyStoreError(f"{path.name} is not a regular file")
            with os.fdopen(fd, "rb") as fh:
                fd = None
                return fh.read(1 << 16)
        finally:
            if fd is not None:
                os.close(fd)

    def _fernet(self, create: bool):
        from cryptography.fernet import Fernet
        if not self.secret.exists():
            if not create:
                return None
            self._ensure_dir()
            self._write_private(self.secret, Fernet.generate_key())
        return Fernet(self._read_private(self.secret).strip())

    # ── public ─────────────────────────────────────────────────────────────────
    def save(self, key: str) -> str:
        key = validate_key(key)
        self._ensure_dir()
        token = self._fernet(create=True).encrypt(key.encode("utf-8"))
        self._write_private(self.blob, token)
        return hint(key)

    def load(self) -> Optional[str]:
        if not self.blob.exists():
            return None
        try:
            f = self._fernet(create=False)
            if f is None:
                return None
            return f.decrypt(self._read_private(self.blob).strip()).decode("utf-8")
        except Exception:
            return None   # corrupt / wrong secret: treated as "not configured", never raised to UI

    def delete(self) -> bool:
        existed = self.blob.exists()
        for p in (self.blob,):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        return existed

    def configured(self) -> bool:
        return self.load() is not None
