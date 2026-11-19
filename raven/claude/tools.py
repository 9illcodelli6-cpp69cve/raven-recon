"""RAVEN capabilities exposed to Claude as tools.

Three tools touch the target or execute something and therefore PAUSE for the operator's
Approve: ``http_request`` (one request through RAVEN's scoped sender), ``start_collection``
(RAVEN's own recon job) and ``run_command`` (one command in the offline sandbox). Their cheap
pre-checks run BEFORE the operator is asked (an out-of-scope URL is blocked outright, never
offered for approval). Everything else is read-only local data or confined writes.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import skills

APPROVAL_TOOLS = frozenset({"http_request", "start_collection", "run_command"})
MAX_RESULT_CHARS = 24_000
HTTP_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
SEVERITIES = ("info", "low", "medium", "high", "critical")


def _obj(props: Dict[str, Any], required: List[str]) -> Dict[str, Any]:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


_S = {"type": "string"}
_I = {"type": "integer", "minimum": 1, "maximum": 500}
_PURPOSE = {"type": "string", "description": "One sentence for the operator: why this step, what you expect to learn."}

TOOL_DEFS: List[Dict[str, Any]] = [
    {"name": "get_scope", "description": "The engagement scope of the active RAVEN workspace: in-scope hosts/wildcards, exclusions and allowed ports.",
     "input_schema": _obj({}, [])},
    {"name": "search_trusted", "description": "Search RAVEN's offline trusted knowledge base (MITRE CWE/CAPEC/ATT&CK, OWASP WSTG and Cheat Sheets, PayloadsAllTheThings) plus NVD and GitHub security advisories for CVE ids.",
     "input_schema": _obj({"query": _S, "k": {"type": "integer", "minimum": 1, "maximum": 10}}, ["query"])},
    {"name": "read_trusted", "description": "Read one page from an allowlisted trusted source (OWASP, MITRE, NVD, PortSwigger, MDN, GitHub advisories, ...). Other domains are refused.",
     "input_schema": _obj({"url": _S}, ["url"])},
    {"name": "load_skill", "description": "Load one of RAVEN's testing playbooks by name (see the skills list in the system prompt).",
     "input_schema": _obj({"name": _S}, ["name"])},
    {"name": "list_assets", "description": "Hosts RAVEN has discovered in this workspace, with their latest HTTP probe (status, title, server, scripts).",
     "input_schema": _obj({"limit": _I}, [])},
    {"name": "list_endpoints", "description": "URLs RAVEN has discovered in this workspace. Optional filters: host (exact) and contains (substring).",
     "input_schema": _obj({"host": _S, "contains": _S, "limit": _I}, [])},
    {"name": "list_traffic", "description": "Recent HTTP history recorded by RAVEN (metadata: method, URL, status, length, time).",
     "input_schema": _obj({"limit": _I}, [])},
    {"name": "list_findings", "description": "Candidate findings recorded in this workspace and their review status.",
     "input_schema": _obj({"limit": _I}, [])},
    {"name": "start_collection", "description": "NEEDS OPERATOR APPROVAL. Run RAVEN's in-scope recon job: certificate-transparency subdomains (passive), HTTP probes of every scoped port (probe), and optional endpoint discovery from links/robots/sitemaps/JS (discover). Returns a job id; poll with collection_status.",
     "input_schema": _obj({"passive": {"type": "boolean"}, "probe": {"type": "boolean"}, "discover": {"type": "boolean"}, "purpose": _PURPOSE},
                          ["passive", "probe", "discover", "purpose"])},
    {"name": "collection_status", "description": "State and progress of a collection job started with start_collection.",
     "input_schema": _obj({"job_id": _S}, ["job_id"])},
    {"name": "http_request", "description": "NEEDS OPERATOR APPROVAL. Send exactly ONE HTTP request to an in-scope URL through RAVEN's scoped sender (out-of-scope URLs are blocked; redirects are not followed; rate/budget limits and Emergency Stop apply). Returns status, headers and up to ~20 KB of body.",
     "input_schema": _obj({"method": {"type": "string", "enum": list(HTTP_METHODS)}, "url": _S,
                           "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                           "body": _S, "purpose": _PURPOSE}, ["method", "url", "purpose"])},
    {"name": "run_command", "description": "NEEDS OPERATOR APPROVAL. Run ONE shell command in an OFFLINE bubblewrap sandbox (no network; working directory /work = this run's files). For local analysis: parsing saved data, decoding, diffing, grep/semgrep over source the operator provided, small scripts.",
     "input_schema": _obj({"command": _S, "purpose": _PURPOSE}, ["command", "purpose"])},
    {"name": "write_file", "description": "Save a text file in this run's workspace folder (visible to run_command as /work/<name>).",
     "input_schema": _obj({"name": _S, "content": _S}, ["name", "content"])},
    {"name": "record_finding", "description": "Save a CANDIDATE finding in the workspace (stays unverified until the operator confirms it). Only with reproducible evidence from this run.",
     "input_schema": _obj({"title": _S, "url": _S, "severity": {"type": "string", "enum": list(SEVERITIES)},
                           "description": _S, "evidence": _S}, ["title", "url", "severity", "description", "evidence"])},
]


def _clip(text: str, n: int = MAX_RESULT_CHARS) -> str:
    text = str(text)
    return text if len(text) <= n else text[:n] + f"\n…[truncated {len(text) - n} chars]"


def _safe_headers(h: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(h, dict):
        for k, v in list(h.items())[:40]:
            k, v = str(k), str(v)
            if not k or any(c in k + v for c in "\r\n\x00"):
                continue
            out[k] = v
    return out


def describe(name: str, inp: Dict[str, Any]) -> str:
    """Human-readable form of a call (timeline + approval card)."""
    if name == "http_request":
        lines = [f"{inp.get('method', 'GET')} {inp.get('url', '')}"]
        lines += [f"{k}: {v}" for k, v in _safe_headers(inp.get("headers")).items()]
        if inp.get("body"):
            lines += ["", str(inp["body"])[:4000]]
        return "\n".join(lines)
    if name == "run_command":
        return str(inp.get("command", ""))
    if name == "start_collection":
        return "collection: " + ", ".join(k for k in ("passive", "probe", "discover") if inp.get(k)) or "collection"
    if name == "write_file":
        return f"{inp.get('name')} ({len(str(inp.get('content', '')))} chars)"
    return json.dumps({k: v for k, v in inp.items() if k != "purpose"}, ensure_ascii=False)[:600]


class ToolBox:
    """Executes tools against the live RAVEN runtime (callables injected by the server)."""

    def __init__(self, ctx: Dict[str, Callable], workdir: Path, halt: Callable[[], Optional[str]]):
        self.ctx, self.workdir, self.halt = ctx, Path(workdir), halt

    # ── checks that run BEFORE the operator is asked ───────────────────────────
    def precheck(self, name: str, inp: Dict[str, Any]) -> Tuple[Optional[str], List[str]]:
        """(blocked_reason or None, notes for the approval card)."""
        notes: List[str] = []
        purpose = str(inp.get("purpose") or "").strip()
        if purpose:
            notes.append(f"Purpose: {purpose[:400]}")
        if name == "http_request":
            method = str(inp.get("method") or "").upper()
            url = str(inp.get("url") or "")
            if method not in HTTP_METHODS:
                return f"method {method!r} is not allowed", notes
            if not url.startswith(("http://", "https://")):
                return "url must be an absolute http(s) URL", notes
            if not self.ctx["scope_url"](url):
                return f"{url} is outside the engagement scope — not sent", notes
            if len(str(inp.get("body") or "")) > 1_000_000:
                return "request body larger than 1 MB", notes
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                notes.append(f"{method} may change data on the target — approve only if the program allows it.")
        elif name == "run_command":
            cmd = str(inp.get("command") or "")
            if not cmd.strip():
                return "empty command", notes
            if len(cmd) > 8000:
                return "command longer than 8000 characters", notes
            from ..sec_ai.agent import hosts_in, shell_network_enabled
            off = [h for h in hosts_in(cmd) if not self.ctx["scope_host"](h)]
            if off:
                notes.append("Command mentions hosts outside the scope: " + ", ".join(off[:6]))
            notes.append("Sandbox has network access (RAVEN_SEC_SHELL_NETWORK=1)." if shell_network_enabled()
                         else "Offline sandbox — the command cannot reach any host.")
        elif name == "start_collection":
            sc = self.ctx["scope_dict"]()
            notes.append("Scope: " + ", ".join(sc.get("include") or []) + (f" · ports {sc.get('ports')}" if sc.get("ports") else ""))
        return None, notes

    # ── execution ──────────────────────────────────────────────────────────────
    def run(self, name: str, inp: Dict[str, Any]) -> Tuple[str, bool]:
        """(result text, is_error). Approval has already happened for gated tools."""
        try:
            fn = getattr(self, "_t_" + name, None)
            if fn is None:
                return f"unknown tool {name!r}", True
            return fn(inp)
        except Exception as exc:  # a tool failure is reported to the model, never crashes the run
            return f"tool error: {type(exc).__name__}: {exc}", True

    def _t_get_scope(self, inp):
        return json.dumps(self.ctx["scope_dict"](), ensure_ascii=False, indent=1), False

    def _t_search_trusted(self, inp):
        from ..sec_ai import research
        res = research.search(str(inp.get("query", ""))[:500], int(inp.get("k") or 5))
        return _clip(research.format_results(res, 900)), False

    def _t_read_trusted(self, inp):
        from ..sec_ai import research
        try:
            p = research.read(str(inp.get("url", "")).strip(), max_chars=12000)
        except PermissionError as exc:
            return f"BLOCKED: {exc}", True
        links = "\n".join(p.get("links", [])[:10])
        return _clip(f"{p['title']}\n{p['url']}\n\n{p['text']}" + (f"\n\nTrusted links:\n{links}" if links else "")), False

    def _t_load_skill(self, inp):
        body = skills.load(str(inp.get("name", "")))
        if body is None:
            return "no such skill. Available:\n" + skills.index_text(), True
        return body, False

    def _t_list_assets(self, inp):
        rows = self.ctx["assets"]()[: int(inp.get("limit") or 100)]
        slim = [{"host": a.get("host"), "score": a.get("score"),
                 "probe": {k: (a.get("probe") or {}).get(k) for k in ("status", "title", "server", "url", "scripts")}}
                for a in rows]
        return _clip(json.dumps(slim, ensure_ascii=False)), False

    def _t_list_endpoints(self, inp):
        host, sub = str(inp.get("host") or ""), str(inp.get("contains") or "")
        rows = [u for u in self.ctx["urls"]() if (not host or u.get("host") == host) and (not sub or sub in (u.get("url") or ""))]
        rows = rows[: int(inp.get("limit") or 200)]
        return _clip(json.dumps([{"url": u.get("url"), "sources": u.get("sources")} for u in rows], ensure_ascii=False)), False

    def _t_list_traffic(self, inp):
        return _clip(json.dumps(self.ctx["traffic"](int(inp.get("limit") or 50)), ensure_ascii=False)), False

    def _t_list_findings(self, inp):
        return _clip(json.dumps(self.ctx["findings"](int(inp.get("limit") or 50)), ensure_ascii=False)), False

    def _t_start_collection(self, inp):
        job = self.ctx["collect"](bool(inp.get("passive")), bool(inp.get("probe")), bool(inp.get("discover")))
        return json.dumps({"job_id": job.get("id") or job.get("job_id"), "state": job.get("state")}, ensure_ascii=False), False

    def _t_collection_status(self, inp):
        job = self.ctx["job"](str(inp.get("job_id", "")))
        if not job:
            return "no such job", True
        slim = {k: job.get(k) for k in ("id", "state", "error", "result")}
        slim["progress"] = (job.get("progress") or [])[-15:]
        return _clip(json.dumps(slim, ensure_ascii=False, default=str)), False

    def _t_http_request(self, inp):
        req = {"method": str(inp.get("method", "GET")).upper(), "url": str(inp.get("url", "")),
               "headers": _safe_headers(inp.get("headers")), "body": str(inp.get("body") or "")}
        r = self.ctx["send"](req)
        if r.get("blocked") or (r.get("error") and not r.get("status")):
            return f"BLOCKED/FAILED: {r.get('error') or 'blocked by RAVEN'}", True
        hdrs = "\n".join(f"{k}: {v}" for k, v in list((r.get("headers") or {}).items())[:40])
        body = str(r.get("body", ""))
        return _clip(f"HTTP {r.get('status')} {r.get('reason', '')} · {r.get('bytes', len(body))} bytes · "
                     f"{r.get('elapsed_ms', '?')} ms\n{hdrs}\n\n{body[:20000]}"), False

    def _t_run_command(self, inp):
        from ..sec_ai.agent import run_sandboxed
        res = run_sandboxed(self.workdir, str(inp.get("command", "")), halt=self.halt)
        if res.get("halted"):
            return f"stopped: {res['halted']}", True
        if res.get("error"):
            return f"sandbox error: {res['error']}", True
        status = "timed out" if res.get("timed_out") else f"exit {res.get('exit_code')}"
        err = (res.get("stderr") or "").strip()
        return _clip(f"[{status}]\n{res.get('stdout') or ''}" + (f"\n[stderr]\n{err}" if err else "")), False

    def _t_write_file(self, inp):
        from ..sec_ai.agent import _write_nofollow
        name = re.sub(r"[^A-Za-z0-9._-]", "_", str(inp.get("name", "")).strip())[:80].lstrip(".") or "note.txt"
        data = str(inp.get("content", ""))
        if len(data) > 1_000_000:
            return "refused: file larger than 1 MB", True
        try:
            _write_nofollow(self.workdir, name, data)
        except OSError as exc:
            return f"refused: {name} is not a regular file in the workspace ({exc.strerror})", True
        return f"saved {name} ({len(data)} chars) — /work/{name} in the sandbox", False

    def _t_record_finding(self, inp):
        url = str(inp.get("url", ""))
        if not self.ctx["scope_url"](url):
            return f"refused: {url} is outside the scope", True
        sev = str(inp.get("severity", "info")).lower()
        if sev not in SEVERITIES:
            return f"severity must be one of {SEVERITIES}", True
        fid = self.ctx["record_finding"](str(inp.get("title", ""))[:300], url, sev,
                                         str(inp.get("description", ""))[:8000], str(inp.get("evidence", ""))[:20000])
        if not fid:
            return "could not record the finding (no workspace open?)", True
        return f"candidate finding {fid} recorded (unverified — needs the operator's review)", False
