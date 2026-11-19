import json
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .scope import Scope, hostname


@dataclass
class Config:
    name: str
    roots: list[str]
    include: list[str]
    exclude: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=lambda: [80, 443])
    rate: float = 2.0
    concurrency: int = 4
    timeout: float = 8.0
    max_hosts: int = 300
    max_requests: int = 700
    max_js: int = 30
    max_body_bytes: int = 524288
    tool_timeout: float = 180.0
    max_records: int = 50000
    allow_private: bool = False
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def scope(self):
        return Scope(self.include, self.exclude, self.ports)

    def validate(self):
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name is required")
        for attr in ("roots", "include", "exclude"):
            values = getattr(self, attr)
            if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                raise ValueError(f"{attr} must be a list of strings")
        self.roots = [hostname(r) for r in self.roots]
        if not self.roots:
            raise ValueError("At least one root is required")
        scope = self.scope
        for root in self.roots:
            if not (scope.allows_host(root) or scope.allows_host("scope-check." + root)):
                raise ValueError(f"Root {root} has no usable include rule")
        for attr, lo, hi in (("rate", 0.1, 50), ("timeout", 1, 60), ("tool_timeout", 5, 3600)):
            n = getattr(self, attr)
            if type(n) not in (int, float) or not math.isfinite(n) or not lo <= n <= hi:
                raise ValueError(f"{attr} must be between {lo} and {hi}")
        for attr, lo, hi in (("concurrency", 1, 32), ("max_hosts", 1, 10000),
                             ("max_requests", 1, 100000), ("max_js", 0, 500),
                             ("max_body_bytes", 1024, 2097152), ("max_records", 1, 1000000)):
            n = getattr(self, attr)
            if type(n) is not int or not lo <= n <= hi:
                raise ValueError(f"{attr} must be an integer between {lo} and {hi}")
        if type(self.allow_private) is not bool or not isinstance(self.headers, dict):
            raise ValueError("Invalid allow_private or headers type")
        for key, value in self.headers.items():
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9-]+", key):
                raise ValueError("Invalid header name")
            if key.lower() in {"host", "content-length", "transfer-encoding", "connection", "accept-encoding"}:
                raise ValueError(f"Reserved header: {key}")
            if not isinstance(value, str) or any(ord(c) < 32 or ord(c) > 126 for c in value):
                raise ValueError("Headers must contain printable ASCII")
        return self

    def save(self, workspace: Path):
        self.validate()
        workspace.mkdir(parents=True, exist_ok=True)
        target = workspace / "scope.json"
        # Creating a workspace must never silently widen an existing scope.
        with target.open("x", encoding="utf-8") as out:
            json.dump(asdict(self), out, indent=2, ensure_ascii=False)
            out.write("\n")
        target.chmod(0o600)

    @classmethod
    def load(cls, workspace: Path):
        return cls(**json.loads((workspace / "scope.json").read_text(encoding="utf-8"))).validate()

