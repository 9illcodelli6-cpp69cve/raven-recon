"""SenderService — the ONE hardened outbound egress funnel (Wave 3, C-5).

MIGRATED VERBATIM from ``raven/api/server.py`` (the
``do_send``/``_send_in_context``/``_pick_public_ip``/``_is_public``/
``_PinnedHTTP(S)Connection`` unit). Per CANONICAL_ARCHITECTURE §1 row 12 and
RUNTIME_ARCHITECTURE §3.5 / §9 step 3, the egress stack moves as a whole,
behaviour-identical unit. The exact sequence it enforces is preserved:

    scope (``Scope.allows_url``)
      → ``_pick_public_ip`` (resolve-then-pin SSRF / DNS-rebind guard)
      → header build (strip framing/credential headers; force the workspace
        search headers + User-Agent to WIN over caller values; identity encoding;
        connection close)
      → ``SCHEDULER.admit_request`` (the ONE admission / rate / budget /
        emergency-stop gate)
      → send (``http.client`` never auto-follows redirects)

Nothing in the logic changed.

Why collaborators are referenced through the ``raven.api.server`` module
(``_server.``) instead of as bare names: the ``server`` module remains the single
live-state and monkeypatch surface for the whole codebase and test-suite.
``server.SCHEDULER`` (rebound per test / workspace), ``server._pick_public_ip``
and ``server._PinnedHTTP(S)Connection`` (monkeypatched by the transport
regression tests), ``server.do_send`` (monkeypatched by recon/import tests),
``server._REQUEST_CONTEXT`` / ``server._REQUEST_CONTROL`` (the per-request
context vars), and ``server.STATE`` (read via ``server._request_context``) are
all mutated at runtime. Resolving them on the server module at call time keeps
behaviour byte-identical to when this code lived in server.py — exactly what a
behaviour-preserving extraction requires. The server re-imports the five names
below, so ``server._pick_public_ip`` / ``server._PinnedHTTP(S)Connection`` /
``server._is_public`` / ``server.do_send`` / ``server._send_in_context`` stay
valid attributes (the patch targets the existing suite relies on).
"""
import http.client
import ipaddress
import socket
import ssl
import time
import hashlib as _hashlib
from urllib.parse import urlsplit

from raven.scope import canonical_url
from raven.api.scheduler import (
    Cancelled as _CancelledSignal, BudgetExhausted, SchedulerStopped,
)


def _is_public(addr):
    """True only for globally routable addresses. Unwraps IPv4-mapped IPv6
    (e.g. ::ffff:127.0.0.1) so loopback/metadata cannot hide behind v6, and
    rejects private / loopback / link-local / reserved / multicast / unspecified."""
    ip = ipaddress.ip_address(addr)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_loopback or ip.is_link_local or ip.is_reserved
                                 or ip.is_multicast or ip.is_unspecified
                                 or getattr(ip, "is_site_local", False))


def _pick_public_ip(host):
    """Resolve host, reject if ANY resolved address is non-public, and return one IP
    to pin the connection to. Connecting to that exact IP closes the DNS-rebinding
    TOCTOU: unlike urllib, we never re-resolve between the check and the connect."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    chosen = None
    for _family, _type, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0]
        if not _server._request_context().allow_private and not _server._is_public(addr):
            raise ValueError(f"Non-public address blocked: {addr}")
        if chosen is None:
            chosen = addr
    if chosen is None:
        raise ValueError("host did not resolve")
    return chosen


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        # TLS SNI + certificate validation still use the real hostname, not the IP.
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def do_send(payload):
    context = _server._request_context()
    context_token = _server._REQUEST_CONTEXT.set(context)
    try:
        return _send_in_context(payload, context)
    finally:
        _server._REQUEST_CONTEXT.reset(context_token)


def _send_in_context(payload, context):
    if context.configuration_error:
        return {"blocked": True, "error": context.configuration_error}
    method = str(payload.get("method") or "GET").upper()
    if method not in _server.METHODS:
        return {"error": f"unsupported method: {method}"}
    if not isinstance(payload.get("body", ""), str):
        return {"blocked": True, "error": "body must be a string"}
    try:
        url = canonical_url(str(payload.get("url", "")))
    except (ValueError, UnicodeError) as exc:
        return {"blocked": True, "error": f"invalid URL: {exc}"}
    if not context.scope.allows_url(url):
        return {"blocked": True, "error": "URL is outside configured scope / ports"}
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        ip = _server._pick_public_ip(host)
    except (ValueError, OSError) as exc:
        return {"blocked": True, "error": str(exc)}

    supplied = payload.get("headers", {})
    if not isinstance(supplied, dict):
        return {"blocked": True, "error": "headers must be an object"}
    headers = {}
    for key, value in supplied.items():
        if (not isinstance(key, str) or not _server._HEADER_NAME_RE.fullmatch(key)
                or not isinstance(value, str) or any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value)):
            return {"blocked": True, "error": "invalid request header"}
        try:
            value.encode("latin-1")
        except UnicodeEncodeError:
            return {"blocked": True, "error": "HTTP header values must be Latin-1 encodable"}
        if key.lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "x-raven-token"}:
            continue
        headers[key.lower()] = value
    # The workspace's research identity is applied to EVERY real target request from
    # here — Collection, Repeater, Intruder, curl, every Access Control identity plus
    # its anonymous baseline, and the XSS Lab all funnel through this one function.
    # Search headers (e.g. a bounty program's required X-Request-Purpose) WIN over
    # whatever the caller supplied for the same name, so a required header can never
    # be silently dropped by editing a raw request or changing the URL/method; they
    # never include Cookie/Authorization (rejected at _validate_header) so they can
    # never leak one identity's credentials into another request.
    for name, value in context.search_headers:
        headers[name.lower()] = value
    headers["user-agent"] = context.user_agent  # the visible workspace selection wins
    # changing it only changes this header; it does not run a browser engine, spoof a
    # TLS fingerprint, or guarantee anything about evading bot/anti-automation systems.
    headers["accept-encoding"] = "identity"
    headers["connection"] = "close"
    body = payload.get("body", "")
    data = body.encode("utf-8") if body and method not in ("GET", "HEAD") else None
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query

    timeout = context.timeout
    if scheme == "https":
        conn = _server._PinnedHTTPSConnection(host, ip, port, timeout, ssl.create_default_context())
    else:
        conn = _server._PinnedHTTPConnection(host, ip, port, timeout)
    started = time.monotonic()
    # The ONE admission gate for every real outbound attempt: Emergency Stop, the
    # shared per-host rate ceiling, and the shared per-workspace request budget — the
    # exact same check whether this call came from a scheduled Collection job or a
    # direct manual send (Repeater/Intruder/curl/ACL/XSS). A cancellable wait for a
    # rate-limit slot is interrupted immediately if Emergency Stop fires meanwhile.
    ctl = _server._REQUEST_CONTROL.get()
    job = ctl.job if ctl is not None else None
    try:
        _server.SCHEDULER.admit_request(context.workspace_key, host, job=job, generation=context.stop_generation)
    except _CancelledSignal:
        raise  # propagates to do_collect's job-cancellation handling
    except SchedulerStopped as exc:
        return {"blocked": True, "error": str(exc)}
    except BudgetExhausted as exc:
        return {"blocked": True, "error": str(exc)}
    try:
        conn.request(method, target, body=data, headers=headers)
        resp = conn.getresponse()  # http.client never auto-follows redirects
        raw = resp.read(context.max_body + 1)
        status, reason = resp.status, resp.reason
        rheaders = resp.getheaders()
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    finally:
        conn.close()
        if job is None:  # a scheduled job's in-flight accounting is its own job state
            _server.SCHEDULER.release_request(context.workspace_key)
    truncated = len(raw) > context.max_body
    raw = raw[:context.max_body]
    try:
        decoded = raw.decode("utf-8")
        decode_lossy = False
    except UnicodeDecodeError:
        decoded = raw.decode("utf-8", "replace")
        decode_lossy = True
    return {
        "ok": True, "status": status, "reason": str(reason),
        "headers": {k: v for k, v in rheaders},
        "body": decoded, "decode_lossy": decode_lossy,
        "raw_sha256": _hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw), "truncated": truncated,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }


class SenderService:
    """The one hardened outbound sender (C-5).

    Stateless facade: delegates to the live ``server.do_send`` so the
    scope → pin → admit → send funnel, its forced/stripped headers, and its
    monkeypatch surface are exactly as before. ``RUNTIME.sender.send(payload)``
    is the route-level entry point the thinned ``/api/send`` handler calls.
    """

    def send(self, payload):
        return _server.do_send(payload)


# Circular import placed AFTER the definitions above so BOTH import orders work:
# whether server.py imports this module (server-first) or this module is imported
# first (sender-first), the functions are already defined before the server module
# object is bound here, and every `_server.<name>` lookup happens at call time.
import raven.api.server as _server  # noqa: E402
