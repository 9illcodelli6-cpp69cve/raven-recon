"""Recon collectors — the extracted V7 server-collection units (Wave 7, A7-RECON).

MIGRATED VERBATIM from ``raven/api/server.py`` (the ``_passive_crtsh`` / ``_probe_host``
/ ``_run_tool`` unit, server.py:1201-1234). Per RECON_ARCHITECTURE §2 (ADAPT/extract,
no rewrite, no third engine) and CANONICAL_ARCHITECTURE §1 row 13, the collection logic
moves out of ``server.py`` as whole units and lives here; ``server`` keeps thin,
re-imported delegations so ``server._passive_crtsh`` / ``server._probe_host`` /
``server._run_tool`` remain the exact same attributes — and monkeypatch surface — the
whole test-suite relies on.

Why collaborators are referenced through the ``raven.api.server`` module (``_server.``)
instead of as bare names (identical rationale to ``runtime/services/sender.py``): the
``server`` module is the single live-state and monkeypatch surface for the codebase and
tests. ``server._OPENER`` (patched by the crt.sh identity test), ``server._REQUEST_CONTROL``
/ ``server._request_context`` (the per-request context vars), ``server.do_send`` /
``server._PinnedHTTP(S)Connection`` (patched by the transport tests), ``server.inspect_body``,
``server._canonical_svc``, and the ``server._probe_host`` / ``_passive_crtsh`` / ``_run_tool``
indirection points (replaced wholesale by the scheduler/collection tests) are all mutated
at runtime. Resolving them on the server module at call time keeps behaviour byte-identical
to when this code lived in ``server.py`` — exactly what a behaviour-preserving extraction
requires.

The three collector CLASSES below (``PassiveCrtShCollector`` / ``ExternalToolCollector`` /
``ActiveProbeCollector``) are the per-phase units the ``ReconService`` orchestrates. Each
calls the patchable ``_server`` indirection points, so a test that patches
``server._probe_host`` (etc.) still intercepts, whether the call comes from the service
orchestration or a direct collector use.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.request

from ..scope import canonical_url


# ── Single-item logic (re-imported by server as _passive_crtsh/_probe_host/_run_tool) ──

def passive_crtsh(domain):
    """Certificate-transparency subdomain discovery (passive; queries crt.sh).

    Extracted verbatim from ``server._passive_crtsh``. Talks ONLY to the third-party
    OSINT source through the no-redirect/no-proxy ``server._OPENER`` and carries NO
    workspace search headers or target credentials (only a static UA).
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "RavenRecon/0.1 (+authorized-research)"})
        control = _server._REQUEST_CONTROL.get()
        if control is not None:
            control.rate("crt.sh")
        with _server._OPENER.open(request, timeout=25) as resp:
            raw = resp.read(CRTSH_MAX_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError):
        return []
    rows, partial = _crtsh_rows(raw[:CRTSH_MAX_BYTES])
    if partial or len(raw) > CRTSH_MAX_BYTES:
        # Large domains used to yield "0 names" silently (the cut JSON failed to parse).
        control = _server._REQUEST_CONTROL.get()
        note = (f"crt.sh {domain}: response truncated at {CRTSH_MAX_BYTES // (1024 * 1024)} MB — "
                f"kept {len(rows)} complete certificate rows")
        if control is not None and hasattr(control, "log"):
            try:
                control.log(note)
            except Exception:
                pass
    names = set()
    for row in rows:
        if not isinstance(row, dict):  # {"error":..}, null, ["a"] … never crash the run
            continue
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and "*" not in name and "@" not in name:
                names.add(name)
    return sorted(names)


CRTSH_MAX_BYTES = 24 * 1024 * 1024


def _crtsh_rows(raw):
    """Parse crt.sh JSON; a truncated body keeps every COMPLETE row instead of losing all.
    Returns (rows, partial)."""
    text = raw.decode("utf-8", errors="replace")
    try:
        data = json.loads(text or "[]")
        return (data if isinstance(data, list) else []), False
    except ValueError:
        pass
    dec = json.JSONDecoder()
    rows, i, n = [], text.find("["), len(text)
    if i < 0:
        return [], True
    i += 1
    while i < n:
        while i < n and text[i] in " \r\n\t,":
            i += 1
        if i >= n or text[i] != "{":
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError:
            break
        rows.append(obj)
    return rows, True


def _is_ip(value):
    import ipaddress
    try:
        ipaddress.ip_address(str(value).strip("[]"))
        return True
    except ValueError:
        return False


def probe_candidates(host, ports):
    """(scheme, url) pairs to try for ``host``, honouring EVERY scoped port.

    443 → https and 80 → http keep their historical priority and order. Any other
    scoped port (8080, 8443, 3000, …) used to be silently skipped, so a program with
    custom ports was never probed; it is now tried as https then http (a custom port
    may speak either). URLs are built canonically (IPv6 brackets, default-port
    elision) via ``scope.origin``.
    """
    from ..scope import origin
    out = []
    if 443 in ports:
        out.append(("https", origin(host, "https")))
    if 80 in ports:
        out.append(("http", origin(host, "http")))
    for port in ports:
        if port in (80, 443):
            continue
        out.append(("https", origin(host, "https", port)))
        out.append(("http", origin(host, "http", port)))
    return out


def probe_host(host):
    """Active HTTP probe of one in-scope host via the ONE pinned sender (``server.do_send``).

    Extracted verbatim from ``server._probe_host``. Every responding probe records a
    canonical Observation via ``canonical_service.record_send_result`` (fire-and-forget).
    Tries every scoped port (see :func:`probe_candidates`); the first response wins.
    """
    sc = _server._request_context().scope
    last = {"status": None, "title": "", "server": "", "final_url": f"https://{host}/",
            "body_hash": "", "error": "unreachable", "elapsed_ms": 0, "scripts": []}
    for scheme, url in probe_candidates(host, list(sc.ports)):
        result = _server.do_send({"method": "GET", "url": url})
        if result.get("blocked"):
            return {**last, "error": result.get("error", "blocked")}
        if not result.get("ok"):
            last = {**last, "error": result.get("error", "error"), "final_url": url}
            continue
        headers = {k.lower(): v for k, v in (result.get("headers") or {}).items()}
        info = _server.inspect_body(result.get("body", "").encode("utf-8", "replace"), headers, url)
        # V5-06: record canonical observation for every probe that gets a response
        try:
            _svc = _server._canonical_svc()
            if _svc is not None:
                _svc.record_send_result(
                    result, url=url, method="GET",
                    identity_label="probe", acquisition_mode="collect",
                )
        except Exception:
            pass
        body = result.get("body", "").encode("utf-8", "replace")
        return {"status": result.get("status"), "title": info.get("title", ""),
                "server": headers.get("server", ""), "final_url": url,
                "body_hash": info.get("body_hash", ""), "error": "",
                "elapsed_ms": result.get("elapsed_ms", 0), "scripts": info.get("scripts", []),
                # Internal hand-off to endpoint discovery (stripped before storage).
                "_base": url, "_links": _server_analysis().page_links(body, headers, url)}
    return last


def _server_analysis():
    from .. import analysis
    return analysis


# ── Endpoint discovery (bounded, scope-checked, through the pinned sender) ──────
# After a host answers, look one level deeper so the Endpoints view has real
# content without external tools: links on the landing page, robots.txt
# (+ its sitemaps / sitemap.xml) and endpoint strings in up to DISCOVERY_JS_FILES
# in-scope JavaScript files. Not a crawler: no recursion, no forms submitted,
# GET only, every request admitted/budgeted/rate-limited by the scheduler like
# any other target request, and every URL re-checked against the scope.
DISCOVERY_JS_FILES = 3
DISCOVERY_MAX_URLS_PER_HOST = 500


def _discovery_enabled(ctl):
    job = getattr(ctl, "job", None)
    meta = getattr(job, "meta", None)
    return bool(isinstance(meta, dict) and meta.get("discover"))


def _discovery_get(url):
    """GET ``url`` through the one pinned sender; returns (status, text) or (None, "")."""
    result = _server.do_send({"method": "GET", "url": url})
    if result.get("blocked") or not result.get("ok"):
        return None, ""
    try:
        _svc = _server._canonical_svc()
        if _svc is not None:
            _svc.record_send_result(result, url=url, method="GET",
                                    identity_label="probe", acquisition_mode="collect")
    except Exception:
        pass
    return result.get("status"), result.get("body", "") or ""


def discover_endpoints(base, links, scripts, *, scope, store, run_id, ctl):
    """Record in-scope endpoints for one responding host; returns count of new URLs."""
    an = _server_analysis()
    from urllib.parse import urljoin
    found = {}

    def add(url, source):
        if len(found) < DISCOVERY_MAX_URLS_PER_HOST and url not in found and scope.allows_url(url):
            found[url] = source

    for u in links or []:
        add(u, "html:link")
    ctl.check()
    status, text = _discovery_get(urljoin(base, "/robots.txt"))
    sitemaps = []
    if status == 200 and text:
        paths, sitemaps = an.robots_entries(text, base)
        for u in paths:
            add(u, "robots.txt")
    for sm in (sitemaps or [urljoin(base, "/sitemap.xml")])[:2]:
        if not scope.allows_url(sm):
            continue
        ctl.check()
        status, text = _discovery_get(sm)
        if status == 200 and text:
            for u in an.sitemap_locs(text, base):
                add(u, "sitemap")
    for script in [s for s in (scripts or []) if scope.allows_url(s)][:DISCOVERY_JS_FILES]:
        ctl.check()
        status, text = _discovery_get(script)
        if status == 200 and text:
            # fetch()/XHR URLs resolve against the DOCUMENT, not the script's own URL.
            for ep in an.js_endpoints(text[:2_000_000], base):
                add(ep["url"], "js:" + ep["kind"].replace(" ", "-"))
    new = 0
    for url, source in found.items():
        try:
            if store.url(url, source, run_id):
                new += 1
        except (ValueError, UnicodeError):
            continue
    store.commit()
    return len(found), new


def run_tool(args, timeout=90, actor=None):
    """Run an optional external collector if it is on PATH; None means missing.

    Extracted verbatim from ``server._run_tool``. Uses the ONE canonical hidden-window
    helper (``runtime.process_executor.hidden_process_kwargs``) so the CREATE_NO_WINDOW /
    STARTUPINFO flags have a single source. This is the raw-subprocess fallback used only
    by unscheduled callers that have NOT injected a ProcessExecutor; the scheduler-governed
    path never reaches it (external traffic cannot be budgeted — see ExternalToolCollector).

    HARD GUARD (Wave-P5): an agent/program-tier caller must NEVER reach this raw
    fallback — the trusted-tier recon path injects the canonical ``ProcessExecutor``
    (see ``ExternalToolCollector``/``ReconService``). If an agent/program actor is ever
    passed here, refuse (return ``None``) rather than spawn a raw subprocess.
    """
    try:
        from ..runtime.execution import ActorKind
        if actor in (ActorKind.RAVEN_AGENT, ActorKind.PROGRAM_AGENT):
            return None
    except Exception:
        pass
    binary = shutil.which(args[0])
    if not binary:
        return None
    try:
        from ..runtime.process_executor import hidden_process_kwargs
        proc = subprocess.run([binary, *args[1:]], capture_output=True, text=True,
                              timeout=timeout, encoding="utf-8", errors="replace",
                              **hidden_process_kwargs())
        return proc.stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return []


# ── Collector classes (the per-phase units orchestrated by ReconService) ────────

class PassiveCrtShCollector:
    """Passive crt.sh CT discovery for one root. Scope-filters names before storage."""

    source = "crt.sh"

    def collect_root(self, root, *, scope, store, run_id, ctl, logs):
        ctl.check()
        if _is_ip(root):
            # Certificate transparency indexes DNS names, not addresses: querying crt.sh
            # for an IP target returns nothing useful and needlessly discloses the
            # target to a third party.
            msg = f"crt.sh {root}: skipped (IP address target)"
            logs.append(msg); ctl.log(msg)
            return [], 0
        subs = _server._passive_crtsh(root)
        added = sum(1 for h in subs if scope.allows_host(h) and store.host(h, "crt.sh", run_id))
        store.commit()
        msg = f"crt.sh {root}: {len(subs)} names, {added} new in scope"
        logs.append(msg); ctl.log(msg)
        return subs, added


class ExternalToolCollector:
    """subfinder / gau — OPTIONAL, OFF by default (RECON_ARCHITECTURE §3.3).

    * Under the scheduler (``scheduled=True``) it is ALWAYS skipped — external-tool
      traffic cannot be budgeted by the one admission gate — and logs the exact skip
      message the collection tests assert. The tools are never spawned in this case.
    * Off the scheduler it runs ONLY when explicitly enabled. When a canonical
      ``ProcessExecutor`` is injected the tools spawn through it (hidden window, scrubbed
      env, output caps, audit) — NEVER a raw ``subprocess`` from the server path. With no
      executor it falls back to ``server._run_tool`` (the raw hidden-window runner).
    """

    def __init__(self, *, enabled=False, executor=None):
        self.enabled = bool(enabled)
        self.executor = executor

    def _run(self, argv, timeout=90):
        """Return stdout lines (list), or None when the tool is missing."""
        if self.executor is not None:
            return self._run_via_executor(argv, timeout)
        return _server._run_tool(argv, timeout)

    def _run_via_executor(self, argv, timeout):
        from ..runtime.process_executor import ProcessSpec
        from ..runtime.execution import ActorKind
        binary = shutil.which(argv[0])
        if not binary:
            return None
        spec = ProcessSpec(
            argv=[binary, *argv[1:]],
            timeout_s=float(timeout),
            actor=ActorKind.RESEARCHER,
            tool_id=f"recon.external.{argv[0]}",
        )
        result = self.executor.execute(spec)
        out = getattr(result, "stdout", "") or ""
        return out.splitlines()

    def collect_root(self, root, *, scope, store, run_id, ctl, logs, scheduled):
        if scheduled:
            # External tools cannot enforce this scheduler's request-level limits.
            msg = "subfinder/gau skipped: external traffic cannot be budgeted by the scheduler"
            logs.append(msg); ctl.log(msg)
            return
        if not self.enabled:
            return
        ctl.check()
        sf = self._run(["subfinder", "-d", root, "-silent"])
        if sf is None:
            logs.append("subfinder: not installed (optional)")
        else:
            got = sum(1 for h in sf if scope.allows_host(h.strip()) and store.host(h.strip(), "subfinder", run_id))
            store.commit()
            msg = f"subfinder {root}: {got} new in scope"; logs.append(msg); ctl.log(msg)
        ctl.check()
        gau = self._run(["gau", root])
        if gau is None:
            logs.append("gau: not installed (optional)")
        else:
            got = 0
            for line in gau:
                try:
                    if "://" not in line or not scope.allows_url(line.strip()):
                        continue
                    # Store the CANONICAL form that was scope-checked (raw archive lines
                    # can carry quotes/markup that later reach the UI).
                    if store.url(canonical_url(line.strip()), "gau", run_id):
                        got += 1
                except (ValueError, UnicodeError):
                    continue
            msg = f"gau {root}: {got} new URLs in scope"; logs.append(msg); ctl.log(msg)
            store.commit()


PROBE_MAX_HOSTS = 200


class ActiveProbeCollector:
    """Active HTTP probe phase. One ``server._probe_host`` call per in-scope host
    (pinned-IP ``do_send``), capped at 200, recording a probe + in-scope scripts."""

    def collect(self, *, scope, store, run_id, ctl, logs):
        candidates = [a["host"] for a in store.assets() if scope.allows_host(a["host"])]
        # Least-recently-probed first (never-probed hosts lead), so with more than
        # PROBE_MAX_HOSTS in scope every host gets its turn across runs instead of the
        # same top-scored 200 forever.
        try:
            last = store.last_probe_runs()
        except Exception:
            last = {}
        candidates.sort(key=lambda h: last.get(h, 0))
        hosts = candidates[:PROBE_MAX_HOSTS]
        skipped = len(candidates) - len(hosts)
        responded = 0
        endpoints = new_endpoints = 0
        for host in hosts:
            ctl.check()  # transport gates each individual outbound attempt
            data = dict(_server._probe_host(host))
            base = data.pop("_base", None)
            links = data.pop("_links", None)
            store.host(host, "http", run_id)
            store.probe(host, data, run_id)
            for script in data.get("scripts", []):
                if scope.allows_url(script):
                    store.url(script, "html:script", run_id)
            # Never hold the SQLite write transaction across the network I/O below
            # (discovery / the next host's probe): other connections would hit
            # "database is locked" and a rollback elsewhere would discard these rows.
            store.commit()
            if data.get("status") is not None:
                responded += 1
            ctl.check()  # observe cancellation during the last in-flight response
            # Only a real probe response carries the hand-off, and only collections
            # submitted with discover=True (job meta) run it.
            if base and _discovery_enabled(ctl):
                got, fresh = discover_endpoints(base, links, data.get("scripts", []),
                                                scope=scope, store=store, run_id=run_id, ctl=ctl)
                endpoints += got
                new_endpoints += fresh
        msg = f"probed {len(hosts)} hosts, {responded} responded"
        if skipped:
            msg += f" ({skipped} more in scope wait for the next run — least recently probed go first)"
        logs.append(msg); ctl.log(msg)
        if endpoints:
            msg = (f"discovered {endpoints} in-scope endpoints ({new_endpoints} new) "
                   f"from links, robots.txt, sitemaps and JavaScript")
            logs.append(msg); ctl.log(msg)
        return len(hosts), responded


# Circular import placed AFTER the definitions above so BOTH import orders work (identical
# to runtime/services/sender.py): whether server.py imports this module (server-first) or
# this module is imported first, every `_server.<name>` lookup happens at call time.
import raven.api.server as _server  # noqa: E402
