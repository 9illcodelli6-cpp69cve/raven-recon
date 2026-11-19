"""Trusted-source research for RAVEN-Sec: local knowledge base + official databases,
and a read-only "research browser" restricted to an allowlist of trusted domains.

* ``search(query)``  — local KB (CWE, CAPEC, ATT&CK, OWASP WSTG + Cheat Sheets,
  PayloadsAllTheThings) first; CVE ids are looked up live in NVD and the GitHub
  Advisory Database (official APIs). No general web search engine is used.
* ``read(url)``      — fetches ONE page from an allowlisted trusted domain (redirects are
  followed only while they stay on the allowlist), returns readable text + links.

Fetched content is UNTRUSTED data: the agent treats it as an observation, never as
instructions, and every side-effecting action still needs the researcher's approval.
"""
from __future__ import annotations

import html
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import List, Optional

from .kb import KnowledgeBase

USER_AGENT = "RAVEN-Sec-research/1.0 (+local security research assistant)"
MAX_BYTES = 2_000_000
TIMEOUT = 15

# Trusted research sources (host suffix match). Targets are NOT browsed through here —
# requests to engagement targets go through RAVEN's scoped sender with approval.
TRUSTED_DOMAINS = (
    "cwe.mitre.org", "capec.mitre.org", "attack.mitre.org", "cve.mitre.org", "cve.org",
    "nvd.nist.gov", "owasp.org", "cheatsheetseries.owasp.org", "portswigger.net",
    "developer.mozilla.org", "docs.python.org", "rfc-editor.org", "datatracker.ietf.org",
    "github.com", "raw.githubusercontent.com", "api.github.com", "cisa.gov", "first.org",
    "exploit-db.com", "learn.microsoft.com", "kubernetes.io", "docs.docker.com",
)
# On GitHub only these organisations/repos are trusted (not arbitrary user content).
GITHUB_ALLOWED_PREFIXES = (
    "/owasp/", "/swisskyrepo/payloadsallthethings", "/advisories", "/mitre/", "/mitre-attack/",
    "/github/advisory-database", "/projectdiscovery/", "/portswigger/", "/sqlmapproject/",
)
# The same rules as whole path SEGMENTS ("/advisories" must not admit
# "/advisoriesattacker/…", "/owasp/../attacker" must not pass).
_GITHUB_ALLOWED_SEGMENTS = tuple(tuple(x for x in p.split("/") if x) for p in GITHUB_ALLOWED_PREFIXES)
# GitHub hosts: exact names only (gist./codeload./… serve arbitrary user content).
_GITHUB_HOSTS = {"github.com": "repo", "raw.githubusercontent.com": "repo", "api.github.com": "api"}
MAX_CVE_LOOKUPS = 3
ONLINE_DEADLINE_S = 40
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def is_trusted(url: str) -> bool:
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if u.scheme != "https" or not u.hostname:
        return False
    host = u.hostname.lower()
    if not any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS):
        return False
    raw_path = u.path.lower()
    if "\\" in raw_path or any(enc in raw_path for enc in ("%2e", "%2f", "%5c")):
        return False
    segments = [seg for seg in raw_path.split("/") if seg]
    if any(seg in (".", "..") for seg in segments):
        return False
    if host.endswith(("github.com", "githubusercontent.com")):
        kind = _GITHUB_HOSTS.get(host)
        if kind is None:
            return False
        if kind == "api":  # the advisories API only (no repos/gists/contents)
            return segments[:1] == ["advisories"]
        return any(tuple(segments[:len(p)]) == p for p in _GITHUB_ALLOWED_SEGMENTS)
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


def _get(url: str, accept: str = "*/*", hops: int = 4):
    """GET with redirects followed only inside the trusted allowlist."""
    for _ in range(hops + 1):
        if not is_trusted(url):
            raise PermissionError(f"not a trusted research source: {url}")
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
        try:
            with _OPENER.open(req, timeout=TIMEOUT) as resp:
                return resp.geturl(), resp.headers.get("Content-Type", ""), resp.read(MAX_BYTES)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                url = urllib.parse.urljoin(url, e.headers["Location"])
                continue
            raise
    raise PermissionError("too many redirects")


class _Text(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "nav", "footer", "header", "form", "iframe"}
    BLOCK = {"p", "div", "li", "tr", "br", "h1", "h2", "h3", "h4", "h5", "pre", "section",
             "article", "table", "ul", "ol", "dd", "dt", "blockquote"}

    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.out, self.links, self.title = base, [], [], ""
        self._skip = 0
        self._in_title = False
        self._pre = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        if tag == "title":
            self._in_title = True
        if tag == "pre":
            self._pre += 1
            self.out.append("\n```\n")
        if tag in ("h1", "h2", "h3", "h4"):
            self.out.append("\n\n" + "#" * int(tag[1]) + " ")
        elif tag in self.BLOCK:
            self.out.append("\n")
        if tag == "a" and not self._skip:
            href = dict(attrs).get("href")
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(urllib.parse.urljoin(self.base, href))

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False
        if tag == "pre" and self._pre:
            self._pre -= 1
            self.out.append("\n```\n")

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._skip:
            return
        self.out.append(data if self._pre else re.sub(r"\s+", " ", data))


def read(url: str, max_chars: int = 6000, offset: int = 0) -> dict:
    """Read one trusted page → {url, title, text (paged), links (trusted only), more}."""
    final, ctype, body = _get(url, accept="text/html,application/json,text/plain;q=0.9")
    text = body.decode("utf-8", errors="replace")
    title = ""
    links: List[str] = []
    if "html" in ctype or text.lstrip().lower().startswith(("<!doctype html", "<html")):
        p = _Text(final)
        try:
            p.feed(text)
        except Exception:
            pass
        text = re.sub(r"\n\s*\n\s*\n+", "\n\n", "".join(p.out)).strip()
        title = html.unescape(p.title.strip())
        seen = set()
        for link in p.links:
            link = link.split("#")[0]
            if link not in seen and is_trusted(link):
                seen.add(link)
                links.append(link)
    elif "json" in ctype:
        try:
            text = json.dumps(json.loads(text), indent=1)[:200_000]
        except ValueError:
            pass
    page = text[offset:offset + max_chars]
    return {"url": final, "title": title, "text": page, "links": links[:40],
            "offset": offset, "more": len(text) > offset + max_chars, "length": len(text)}


# ── official databases ─────────────────────────────────────────────────────────

def nvd_cve(cve_id: str) -> Optional[dict]:
    _, _, body = _get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
                      + urllib.parse.quote(cve_id.upper()), accept="application/json")
    vulns = json.loads(body).get("vulnerabilities") or []
    if not vulns:
        return None
    c = vulns[0]["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    metrics = c.get("metrics", {})
    score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            d = metrics[key][0]["cvssData"]
            score = f"CVSS {d.get('version')} {d.get('baseScore')} ({d.get('vectorString')})"
            break
    cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    refs = [r["url"] for r in c.get("references", [])][:8]
    text = f"{desc}\n\n{score or 'no CVSS score yet'} · {', '.join(cwes) or 'no CWE'}\n" \
           f"Published {c.get('published', '')[:10]}\nReferences:\n" + "\n".join(f"- {r}" for r in refs)
    return {"title": f"{c['id']} (NVD)", "heading": "", "source": "nvd",
            "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}", "text": text}


def github_advisories(cve_id: str) -> List[dict]:
    _, _, body = _get("https://api.github.com/advisories?cve_id=" + urllib.parse.quote(cve_id.upper()),
                      accept="application/vnd.github+json")
    out = []
    for a in json.loads(body)[:3]:
        pkgs = ", ".join(f"{v['package']['ecosystem']}:{v['package']['name']} "
                         f"(vulnerable {v.get('vulnerable_version_range')}, patched {v.get('first_patched_version')})"
                         for v in a.get("vulnerabilities", []) if v.get("package"))
        out.append({"title": f"{a.get('ghsa_id')}: {a.get('summary')}", "heading": "", "source": "github-advisory",
                    "url": a.get("html_url", ""), "text": f"{a.get('description', '')[:1200]}\n\nAffected: {pkgs}"})
    return out


def search(query: str, k: int = 5, kb: Optional[KnowledgeBase] = None, online: bool = True) -> dict:
    """Search trusted sources. Returns {"results": [...], "errors": [...]}."""
    kb = kb or KnowledgeBase()
    results, errors = [], []
    if online:
        import time as _time
        deadline = _time.monotonic() + ONLINE_DEADLINE_S
        cves = list(dict.fromkeys(m.upper() for m in CVE_RE.findall(query)))
        if len(cves) > MAX_CVE_LOOKUPS:
            errors.append(f"{len(cves)} CVE ids in the query — looked up the first {MAX_CVE_LOOKUPS}")
        for cve in cves[:MAX_CVE_LOOKUPS]:
            if _time.monotonic() > deadline:
                errors.append("online lookups stopped: time budget used up")
                break
            try:
                r = nvd_cve(cve)
                if r:
                    results.append(r)
            except Exception as exc:
                errors.append(f"NVD {cve}: {type(exc).__name__}")
            try:
                results.extend(github_advisories(cve))
            except Exception as exc:
                errors.append(f"GitHub advisories {cve}: {type(exc).__name__}")
    results.extend(kb.search(query, k))
    return {"results": results[:k + 3], "errors": errors}


def format_results(res: dict, chars: int = 500) -> str:
    if not res["results"]:
        return "No results in the trusted sources." + (
            " Errors: " + "; ".join(res["errors"]) if res["errors"] else "")
    lines = []
    for i, r in enumerate(res["results"], 1):
        head = f" — {r['heading']}" if r.get("heading") else ""
        lines.append(f"[{i}] {r['title']}{head}\n{r['url']}\n{r['text'][:chars].strip()}")
    return "\n\n".join(lines)
