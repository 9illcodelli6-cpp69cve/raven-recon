"""Parsers for the trusted cybersecurity sources → uniform ``Doc`` objects.

Sources (downloaded into ``paths.corpus_raw_dir()``; licences recorded per document):
  * MITRE CWE (cwec_*.xml)                 — weaknesses: description, consequences,
                                              detection, mitigations, observed CVEs
  * MITRE CAPEC (capec.xml)                — attack patterns: prerequisites, execution
                                              flow (explore/experiment/exploit), mitigations
  * MITRE ATT&CK enterprise (STIX JSON)    — techniques: description, detection
  * OWASP WSTG (markdown, CC BY-SA 4.0)    — how to test each weakness, with payloads
  * OWASP Cheat Sheet Series (CC BY-SA 4.0)— defensive + secure-coding guidance
  * PayloadsAllTheThings (MIT)             — payload collections per vulnerability class
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Tuple

LICENCES = {
    "cwe": "MITRE CWE Terms of Use (attribution)",
    "capec": "MITRE CAPEC Terms of Use (attribution)",
    "attack": "MITRE ATT&CK Terms of Use (attribution)",
    "wstg": "CC BY-SA 4.0 — OWASP Web Security Testing Guide",
    "cheatsheets": "CC BY-SA 4.0 — OWASP Cheat Sheet Series",
    "patt": "MIT — swisskyrepo/PayloadsAllTheThings",
}


@dataclass
class Doc:
    doc_id: str
    source: str
    title: str
    url: str
    sections: List[Tuple[str, str]] = field(default_factory=list)  # (heading, text)

    def text(self) -> str:
        return "\n\n".join(f"{h}\n{t}" if h else t for h, t in self.sections)


def _clean(text: str) -> str:
    """Normalise prose whitespace but keep code EXACTLY: collapsing spaces inside ```
    blocks flattened every indentation level to one space (the model then learned to
    write invalid Python)."""
    parts = re.split(r"(```.*?(?:```|$))", str(text or ""), flags=re.S)
    out = []
    for i, part in enumerate(parts):
        if i % 2:                                    # fenced code: verbatim
            out.append(part.replace("\t", "    "))
        else:
            part = re.sub(r"(?m)^([ \t]*)(.*)$",
                          lambda m: m.group(1).replace("\t", "    ") + re.sub(r"[ \t]+", " ", m.group(2)),
                          part)                        # keep leading indentation (lists, code)
            out.append(re.sub(r"\n[ \t]*\n[ \t]*\n+", "\n\n", part))
    return "".join(out).strip()


def _flat(el) -> str:
    """All text inside an XML element (CWE/CAPEC use XHTML inside fields)."""
    if el is None:
        return ""
    parts = []
    for t in el.itertext():
        t = t.strip()
        if t:
            parts.append(t)
    return _clean(" ".join(parts))


# ── MITRE CWE ──────────────────────────────────────────────────────────────────

def parse_cwe(path: Path) -> Iterator[Doc]:
    root = ET.parse(path).getroot()
    ns = {"c": root.tag.split("}")[0].strip("{")}
    for w in root.iterfind("c:Weaknesses/c:Weakness", ns):
        if w.get("Status") == "Deprecated":
            continue
        wid, name = w.get("ID"), w.get("Name")
        secs = []
        desc = _flat(w.find("c:Description", ns))
        ext = _flat(w.find("c:Extended_Description", ns))
        secs.append(("Description", _clean(desc + ("\n\n" + ext if ext else ""))))
        cons = []
        for c in w.iterfind("c:Common_Consequences/c:Consequence", ns):
            scope = ", ".join(_flat(s) for s in c.iterfind("c:Scope", ns))
            impact = ", ".join(_flat(s) for s in c.iterfind("c:Impact", ns))
            note = _flat(c.find("c:Note", ns))
            cons.append(f"- {scope}: {impact}" + (f" — {note}" if note else ""))
        if cons:
            secs.append(("Common consequences", "\n".join(cons)))
        det = [f"- {_flat(d.find('c:Method', ns))}: {_flat(d.find('c:Description', ns))}"
               for d in w.iterfind("c:Detection_Methods/c:Detection_Method", ns)]
        if det:
            secs.append(("Detection methods", "\n".join(det)))
        mit = []
        for m in w.iterfind("c:Potential_Mitigations/c:Mitigation", ns):
            phase = ", ".join(_flat(p) for p in m.iterfind("c:Phase", ns))
            mit.append(f"- [{phase}] {_flat(m.find('c:Description', ns))}")
        if mit:
            secs.append(("Potential mitigations", "\n".join(mit)))
        obs = [f"- {_flat(o.find('c:Reference', ns))}: {_flat(o.find('c:Description', ns))}"
               for o in list(w.iterfind("c:Observed_Examples/c:Observed_Example", ns))[:8]]
        if obs:
            secs.append(("Observed examples (CVEs)", "\n".join(obs)))
        yield Doc(f"CWE-{wid}", "cwe", f"CWE-{wid}: {name}",
                  f"https://cwe.mitre.org/data/definitions/{wid}.html", secs)


# ── MITRE CAPEC ────────────────────────────────────────────────────────────────

def parse_capec(path: Path) -> Iterator[Doc]:
    root = ET.parse(path).getroot()
    ns = {"c": root.tag.split("}")[0].strip("{")}
    for ap in root.iterfind("c:Attack_Patterns/c:Attack_Pattern", ns):
        if ap.get("Status") == "Deprecated":
            continue
        aid, name = ap.get("ID"), ap.get("Name")
        secs = [("Description", _flat(ap.find("c:Description", ns)))]
        pre = [f"- {_flat(p)}" for p in ap.iterfind("c:Prerequisites/c:Prerequisite", ns)]
        if pre:
            secs.append(("Prerequisites", "\n".join(pre)))
        steps = []
        for s in ap.iterfind("c:Execution_Flow/c:Attack_Step", ns):
            line = f"{_flat(s.find('c:Step', ns))}. [{_flat(s.find('c:Phase', ns))}] {_flat(s.find('c:Description', ns))}"
            techs = [f"   * {_flat(t)}" for t in s.iterfind("c:Technique", ns)]
            steps.append("\n".join([line] + techs))
        if steps:
            secs.append(("Execution flow", "\n".join(steps)))
        skills = [f"- [{sk.get('Level')}] {_flat(sk)}" for sk in ap.iterfind("c:Skills_Required/c:Skill", ns)]
        if skills:
            secs.append(("Skills required", "\n".join(skills)))
        mits = [f"- {_flat(m)}" for m in ap.iterfind("c:Mitigations/c:Mitigation", ns)]
        if mits:
            secs.append(("Mitigations", "\n".join(mits)))
        ex = [f"- {_flat(e)}" for e in list(ap.iterfind("c:Example_Instances/c:Example", ns))[:4]]
        if ex:
            secs.append(("Examples", "\n".join(ex)))
        cwes = [f"CWE-{r.get('CWE_ID')}" for r in ap.iterfind("c:Related_Weaknesses/c:Related_Weakness", ns)]
        if cwes:
            secs.append(("Related weaknesses", ", ".join(cwes)))
        yield Doc(f"CAPEC-{aid}", "capec", f"CAPEC-{aid}: {name}",
                  f"https://capec.mitre.org/data/definitions/{aid}.html", secs)


# ── MITRE ATT&CK (enterprise) ──────────────────────────────────────────────────

_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MDLINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def parse_attack(path: Path) -> Iterator[Doc]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for o in data.get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), {})
        tid, url = ref.get("external_id", ""), ref.get("url", "https://attack.mitre.org/")
        clean = lambda s: _clean(_MDLINK.sub(r"\1", _CITATION.sub("", s or "")))  # noqa: E731
        tactics = ", ".join(p.get("phase_name", "") for p in o.get("kill_chain_phases", []))
        secs = [("Description", clean(o.get("description")))]
        meta = [f"Tactics: {tactics}"] if tactics else []
        if o.get("x_mitre_platforms"):
            meta.append("Platforms: " + ", ".join(o["x_mitre_platforms"]))
        if meta:
            secs.append(("Context", "\n".join(meta)))
        if o.get("x_mitre_detection"):
            secs.append(("Detection", clean(o["x_mitre_detection"])))
        yield Doc(tid or o["id"], "attack", f"{tid}: {o.get('name')}", url, secs)


# ── Markdown sources (WSTG, Cheat Sheets, PayloadsAllTheThings) ────────────────

_HEADING = re.compile(r"^(#{1,4})\s+(.+?)\s*#*\s*$")
_IMG = re.compile(r"!\[[^\]]*\]\([^)]*\)")


_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


def _md_sections(text: str) -> Tuple[str, List[Tuple[str, str]]]:
    title, secs, head, buf = "", [], "", []
    fence = None  # the open fence marker ("```", "~~~~" …) while inside a code block
    for line in text.splitlines():
        f = _FENCE.match(line)
        if fence is None:
            # CommonMark: a backtick fence's info string cannot contain a backtick, so
            # "```https://x```" is inline code, NOT an opening fence (it used to flip the
            # state and swallow every later heading of the document).
            if f and not (f.group(1)[0] == "`" and "`" in f.group(2)):
                fence = f.group(1)
        elif f and f.group(1)[0] == fence[0] and len(f.group(1)) >= len(fence) and not f.group(2).strip():
            fence = None
            buf.append(line)
            continue
        in_code = fence is not None
        m = None if in_code else _HEADING.match(line)
        if m:
            if buf and "".join(buf).strip():
                secs.append((head, _clean("\n".join(buf))))
            level, head = len(m.group(1)), m.group(2).strip()
            if level == 1 and not title:
                title = head
            buf = []
        else:
            buf.append(_IMG.sub("", line))
    if buf and "".join(buf).strip():
        secs.append((head, _clean("\n".join(buf))))
    return title, secs


def _md_docs(root: Path, source: str, url_for, skip=("README.md", "CONTRIBUTING.md")) -> Iterator[Doc]:
    for path in sorted(root.rglob("*.md")):
        rel = path.relative_to(root).as_posix()
        # Skip only ROOT-level boilerplate: in PayloadsAllTheThings each category's
        # main content lives in "<Category>/README.md".
        if rel in skip or "/.github/" in f"/{rel}" or rel.startswith("."):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        title, secs = _md_sections(text)
        secs = [(h, t) for h, t in secs if len(t) >= 40]
        if not secs:
            continue
        title = title or path.stem.replace("_", " ")
        yield Doc(f"{source}:{rel}", source, title, url_for(rel), secs)


def parse_wstg(root: Path) -> Iterator[Doc]:
    base = root / "document" / "4-Web_Application_Security_Testing"
    yield from _md_docs(base, "wstg", lambda rel: (
        "https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/" + rel))


def parse_cheatsheets(root: Path) -> Iterator[Doc]:
    yield from _md_docs(root / "cheatsheets", "cheatsheets", lambda rel: (
        "https://cheatsheetseries.owasp.org/cheatsheets/" + rel[:-3] + ".html"))


def parse_patt(root: Path) -> Iterator[Doc]:
    yield from _md_docs(root, "patt", lambda rel: (
        "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/" + rel.replace(" ", "%20")))


def iter_all(raw: Path) -> Iterator[Doc]:
    """Every document from every source present under ``raw``."""
    cwe = sorted(raw.glob("cwec_*.xml"))
    if cwe:
        yield from parse_cwe(cwe[-1])
    if (raw / "capec.xml").is_file():
        yield from parse_capec(raw / "capec.xml")
    if (raw / "enterprise-attack.json").is_file():
        yield from parse_attack(raw / "enterprise-attack.json")
    if (raw / "wstg").is_dir():
        yield from parse_wstg(raw / "wstg")
    if (raw / "CheatSheetSeries").is_dir():
        yield from parse_cheatsheets(raw / "CheatSheetSeries")
    if (raw / "PayloadsAllTheThings").is_dir():
        yield from parse_patt(raw / "PayloadsAllTheThings")
