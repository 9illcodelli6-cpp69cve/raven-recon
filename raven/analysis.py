"""Explainable triage signals, never vulnerability verdicts."""
import hashlib
import html
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .scope import canonical_url


MAX_SCRIPTS_PER_PAGE = 100


def clean(value, limit=500):
    # Do not let target-controlled text inject ANSI/OSC terminal commands.
    # Bound the work BEFORE the regexes (a 512 KB hostile <title> used to be scanned in
    # full), and the OSC pattern cannot cross another ESC — `[^\x07]*` made every
    # "\x1b]" scan to the end of the text and backtrack: quadratic, and it held the GIL,
    # freezing the whole server (Emergency Stop included) for minutes.
    text = str(value)[: max(int(limit) * 8, 4096)]
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return "".join(c for c in text if c.isprintable())[:limit]


def family(url: str) -> str:
    u = urlsplit(url)
    path = re.sub(r"(?<=/)[0-9]+(?=/|$)", "{id}", u.path)
    path = re.sub(r"(?<=/)[a-fA-F0-9]{8}-[a-fA-F0-9-]{27,}(?=/|$)", "{uuid}", path)
    keys = sorted({k for k, _ in parse_qsl(u.query, keep_blank_values=True)})
    return urlunsplit((u.scheme, u.netloc, path, "&".join(keys), ""))


def priority(value: str, status=None) -> tuple[int, list[str]]:
    u = urlsplit(value if "://" in value else "https://" + value)
    # TLDs such as .test or .dev are not evidence of a staging subdomain.
    host = u.hostname or ""
    hay = host.rsplit(".", 1)[0] + u.path.lower()
    signals = []
    score = 0
    checks = [
        (r"(?:^|[./_-])(admin|console|manage|dashboard)(?:[./_-]|$)", 25, "management surface"),
        (r"(?:^|[./_-])(dev|stg|stage|staging|test|sandbox|beta)(?:[./_-]|$)", 20, "non-production naming"),
        (r"(?:^|[./_-])(api|graphql|v[0-9]+)(?:[./_-]|$)", 15, "API surface"),
        (r"(?:^|[./_-])(auth|oauth|sso|login|callback)(?:[./_-]|$)", 15, "identity flow"),
        (r"(?:^|[./_-])(upload|export|download|import|webhook)(?:[./_-]|$)", 15, "data-flow endpoint"),
    ]
    for pattern, points, reason in checks:
        if re.search(pattern, hay, re.I):
            score += points
            signals.append(reason)
    if u.query:
        score += 5
        signals.append("query parameters present")
    if status in (401, 403):
        score += 5
        signals.append("access boundary observed")
    if status is not None and 500 <= status < 600:
        score += 10
        signals.append("server error observed")
    return min(score, 99), signals


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts = []
        self.in_title = False
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True
        if tag == "script":
            src = dict(attrs).get("src")
            if src:
                self.scripts.append(src)

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def inspect_body(body: bytes, headers: dict, url: str):
    content_type = headers.get("content-type", "").lower()
    text = body.decode("utf-8", errors="replace")
    page = Page()
    if "html" in content_type or text.lstrip().lower().startswith(("<!doctype html", "<html")):
        page.feed(text)
    scripts = []
    for src in page.scripts:
        if len(scripts) >= MAX_SCRIPTS_PER_PAGE:  # one page could yield ~20k rows per run
            break
        try:
            u = canonical_url(urljoin(url, html.unescape(src)))
        except ValueError:
            continue
        if u not in scripts:
            scripts.append(u)
    return {
        "title": clean(" ".join(" ".join(page.title_parts)[:8192].split()), 200),
        "body_hash": hashlib.sha256(body).hexdigest(),
        "scripts": sorted(scripts),
    }


# Limited static extraction: URLs in fetch/axios/XHR calls and quoted API-like paths.
# Strings with computed/template expressions are deliberately left unresolved.
JS_RULES = [
    ("fetch", "high", re.compile(r"\bfetch\s*\(\s*(['\"`])([^'\"`\r\n]{1,2048})\1")),
    ("axios", "high", re.compile(r"\baxios\.(?:get|post|put|patch|delete|head|options)\s*\(\s*(['\"`])([^'\"`\r\n]{1,2048})\1")),
    ("XHR", "high", re.compile(r"\.open\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE|HEAD)['\"]\s*,\s*(['\"`])([^'\"`\r\n]{1,2048})\1", re.I)),
    ("quoted path", "medium", re.compile(r"(['\"`])((?:https?://|/(?:api/|graphql\b|v[0-9]+/|oauth/|auth/))[^'\"`\s]{1,2048})\1")),
]


def js_endpoints(text: str, base: str):
    seen = set()
    for kind, confidence, pattern in JS_RULES:
        line_number, last_position = 1, 0
        for match in pattern.finditer(text):
            value = match.group(2).replace("\\/", "/")
            if any(p in value for p in ("${", "{{", "\\", "<", ">")):
                continue
            try:
                url = canonical_url(urljoin(base, value))
            except (ValueError, UnicodeError):
                continue
            if url in seen:
                continue
            seen.add(url)
            line_number += text.count("\n", last_position, match.start())
            last_position = match.start()
            yield {
                "url": url, "kind": kind, "confidence": confidence,
                "line": line_number,
            }


# ── Same-page endpoint discovery (used by the scheduled collection) ──────────
# Pure parsing helpers: they never fetch anything. The caller decides what is in
# scope and sends every follow-up request through the pinned, budgeted sender.

_LINK_ATTRS = {"a": "href", "area": "href", "form": "action", "iframe": "src",
               "frame": "src", "link": "href"}
_SKIP_SCHEMES = ("mailto:", "javascript:", "data:", "tel:", "blob:", "about:")


class _LinkPage(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        attr = _LINK_ATTRS.get(tag)
        if not attr:
            return
        d = dict(attrs)
        if tag == "link" and str(d.get("rel", "")).lower() in ("stylesheet", "icon", "preconnect",
                                                                "dns-prefetch", "preload"):
            return
        value = d.get(attr)
        if value:
            self.links.append(value)


def _absolute(base: str, value: str):
    value = html.unescape(str(value)).strip()
    if not value or value.startswith("#") or value.lower().startswith(_SKIP_SCHEMES):
        return None
    try:
        return canonical_url(urljoin(base, value).split("#", 1)[0])
    except (ValueError, UnicodeError):
        return None


def page_links(body: bytes, headers: dict, url: str, limit: int = 300) -> list:
    """Absolute http(s) URLs linked from an HTML page (a/area/form/iframe/link)."""
    content_type = (headers or {}).get("content-type", "").lower()
    text = body.decode("utf-8", errors="replace")
    if "html" not in content_type and not text.lstrip().lower().startswith(("<!doctype html", "<html")):
        return []
    page = _LinkPage()
    try:
        page.feed(text)
    except Exception:  # malformed markup from a hostile target must not break collection
        pass
    out = []
    for raw in page.links:
        u = _absolute(url, raw)
        if u and u not in out:
            out.append(u)
            if len(out) >= limit:
                break
    return out


def robots_entries(text: str, base: str, limit: int = 200):
    """(paths, sitemaps) from robots.txt. Wildcard rules keep their literal prefix
    ("/admin/*.php" -> "/admin/"); a bare "/" carries no information and is dropped."""
    paths, sitemaps = [], []
    for line in str(text).splitlines()[:5000]:
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.split("#", 1)[0].strip()
        if not value:
            continue
        if key == "sitemap":
            u = _absolute(base, value)
            if u and u not in sitemaps:
                sitemaps.append(u)
        elif key in ("allow", "disallow"):
            prefix = re.split(r"[*$]", value, maxsplit=1)[0]
            if prefix in ("", "/"):
                continue
            u = _absolute(base, prefix)
            if u and u not in paths:
                paths.append(u)
        if len(paths) >= limit:
            break
    return paths, sitemaps[:5]


_LOC = re.compile(r"<loc>\s*([^<\s]{1,2048})\s*</loc>", re.I)


def sitemap_locs(text: str, base: str, limit: int = 300) -> list:
    """<loc> URLs from a sitemap or sitemap index (not followed recursively)."""
    out = []
    for match in _LOC.finditer(str(text)):
        u = _absolute(base, match.group(1))
        if u and u not in out:
            out.append(u)
            if len(out) >= limit:
                break
    return out
