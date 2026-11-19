"""RAVEN skills: ``raven/skills/<name>/SKILL.md`` playbooks, loaded on demand.

Only the index (name + one-line "when to use") goes into the system prompt; the full text
is fetched with the ``load_skill`` tool when a task needs it (keeps every request small
and the cached prefix stable). The playbooks are RAVEN's own text, part of this repo.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")
MAX_SKILL_CHARS = 60_000


def _parse(path: Path) -> Optional[Dict[str, str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    meta: Dict[str, str] = {}
    body = text
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            for line in text[3:end].splitlines():
                k, sep, v = line.partition(":")
                if sep:
                    meta[k.strip()] = v.strip().strip('"').strip("'")
            body = text[end + 4:].lstrip("\n")
    name = meta.get("name") or path.parent.name
    if not _NAME.match(name) or name != path.parent.name:
        return None
    return {"name": name, "description": meta.get("description", "").strip(), "body": body}


def index(skills_dir: Path = SKILLS_DIR) -> List[Dict[str, str]]:
    out = []
    for p in sorted(skills_dir.glob("*/SKILL.md")):
        s = _parse(p)
        if s:
            out.append({"name": s["name"], "description": s["description"]})
    return out


def load(name: str, skills_dir: Path = SKILLS_DIR) -> Optional[str]:
    if not isinstance(name, str) or not _NAME.match(name.strip()):
        return None
    p = skills_dir / name.strip() / "SKILL.md"
    if not p.is_file() or p.is_symlink():
        return None
    s = _parse(p)
    return s["body"][:MAX_SKILL_CHARS] if s else None


def index_text(skills_dir: Path = SKILLS_DIR) -> str:
    rows = index(skills_dir)
    if not rows:
        return "(no skills installed)"
    return "\n".join(f"- {r['name']}: {r['description']}" for r in rows)
