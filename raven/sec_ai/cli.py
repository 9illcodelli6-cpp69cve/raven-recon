"""RAVEN-Sec in the terminal.

    raven-sec                                  interactive chat (Claude; the local model only
                                               with RAVEN_LOCAL_AI=1 — docs/LOCAL_AI.md)
    raven-sec -q "question"                    one question, then exit
    raven-sec agent "objective" --scope HOST   research agent; asks before EVERY http/shell action
    raven-sec --claude [-q … | agent …]        the same, driven by Claude Opus 5.5 (Anthropic API)

Inside the chat:
    /agent <objective>   run the research agent on the current scope
    /scope <host,...>    set the engagement scope used by /agent (http is blocked outside it)
    /search <query>      search the trusted sources (KB + NVD + GitHub advisories)
    /read <url>          read one page from a trusted source
    /reset               forget the conversation        /quit   exit

Same model, prompts, knowledge base and safety rules as the app: target requests only to
in-scope hosts and only after you approve each one; shell commands run in the offline
bubblewrap sandbox; research reads only allowlisted trusted sources.
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import os
import re
import socket
import ssl
import sys
import threading
import time
from typing import List, Optional
from urllib.parse import urlsplit

from . import paths

_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


DIM, BOLD, RED, GREEN, YELLOW, CYAN = "2", "1", "31", "32", "33", "36"


# ── Scoped, pinned, no-redirect HTTP for the agent's `http` tool ───────────────

class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


_DROP_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization"}


def make_sender(scope, allow_private: bool = False, timeout: float = 15.0, max_body: int = 1_000_000):
    """One request, only to an in-scope URL, to a resolved address that is public (unless
    --allow-private for a local lab), with the connection pinned to that address (no
    DNS-rebinding), redirects NOT followed."""
    from ..scope import canonical_url

    def send(req: dict) -> dict:
        try:
            url = canonical_url(str(req.get("url", "")))
        except ValueError as exc:
            return {"blocked": True, "error": f"invalid URL: {exc}"}
        if not scope.allows_url(url):
            return {"blocked": True, "error": f"{url} is outside the scope"}
        u = urlsplit(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        try:
            infos = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            return {"error": f"DNS: {exc}"}
        ips = []
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if getattr(ip, "ipv4_mapped", None):
                ip = ip.ipv4_mapped
            ips.append(ip)
        if not allow_private and any(not ip.is_global for ip in ips):
            return {"blocked": True, "error": "resolves to a non-public address (use --allow-private for a local lab)"}
        method = str(req.get("method") or "GET").upper()
        headers = {}
        for k, v in (req.get("headers") or {}).items():
            if k.lower() in _DROP_HEADERS or any(c in f"{k}{v}" for c in "\r\n"):
                continue
            headers[k] = v
        headers.setdefault("User-Agent", "RAVEN-Sec-cli/1.0 (authorized testing)")
        body = req.get("body") or None
        conn_cls = _PinnedHTTPS if u.scheme == "https" else _PinnedHTTP
        conn = conn_cls(u.hostname, str(ips[0]), port, timeout)
        t = time.time()
        try:
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            conn.request(method, path, body=body.encode() if isinstance(body, str) else body, headers=headers)
            r = conn.getresponse()
            data = r.read(max_body)
            return {"ok": True, "status": r.status, "reason": r.reason, "headers": dict(r.getheaders()),
                    "body": data.decode("utf-8", "replace"), "bytes": len(data),
                    "elapsed_ms": int((time.time() - t) * 1000)}
        except (OSError, http.client.HTTPException) as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            conn.close()

    return send


DEFAULT_PORTS = [80, 443]


def _scope_from(hosts: List[str]):
    """``--scope app.example.com`` (ports 80/443) or ``--scope 127.0.0.1:38333`` (adds
    that port). Nothing given ⇒ no scope ⇒ every http action is blocked."""
    from ..scope import Scope
    rules, ports = [], list(DEFAULT_PORTS)
    for h in hosts:
        h = (h or "").strip()
        if not h:
            continue
        host, sep, port = h.rpartition(":")
        if sep and port.isdigit() and host and not host.endswith(":"):
            if int(port) not in ports:
                ports.append(int(port))
            h = host.strip("[]")
        rules.append(h)
    return Scope(include=rules, exclude=[], ports=ports) if rules else None


# ── Chat ───────────────────────────────────────────────────────────────────────

def _llm():
    from .llm import RavenSecLLM
    llm = RavenSecLLM.get("chat")
    if llm is None:
        print(_c(RED, f"RAVEN-Sec model not found under {paths.ai_dir()} (set RAVEN_AI_DIR)."))
        sys.exit(2)
    return llm


def ask(llm, history: list, question: str, out=sys.stdout) -> str:
    """Stream one answer to ``out``; returns the full text (with any sources footer)."""
    from .llm import _excerpt, chat_messages, sources_footer
    msgs, hits = chat_messages(history, question)
    if hits:
        # The verbatim trusted passages first (the most reliable part of the answer —
        # see pentest_bench), shown at once while the model writes its summary.
        out.write(_c(BOLD, "From the trusted sources (verbatim):\n"))
        for i, h in enumerate(hits, 1):
            head = h["title"] + (f" — {h['heading']}" if h.get("heading") else "")
            out.write(_c(CYAN, f"\n[{i}] {head}\n") + _c(DIM, h["url"] + "\n") + _excerpt(h["text"]) + "\n")
        out.write(_c(BOLD, "\n── RAVEN-Sec summary (model-written — verify before use) ──\n"))
        out.flush()
    t, parts = time.time(), []
    for piece in llm.stream(msgs):
        parts.append(piece)
        out.write(piece)
        out.flush()
    text = "".join(parts).strip()
    from .llm import answer_is_empty
    if answer_is_empty(text) and history:
        out.write(_c(YELLOW, "\n(no usable answer — retrying without the earlier conversation)\n"))
        alone, _ = chat_messages([], question)
        alone[-1] = msgs[-1]
        parts = []
        for piece in llm.stream(alone):
            parts.append(piece)
            out.write(piece)
            out.flush()
        text = "".join(parts).strip()
    if answer_is_empty(text) and not hits:
        out.write(_c(YELLOW, "\n(the local model produced no usable answer — try rephrasing)"))
    foot = sources_footer(text, hits)
    if foot:
        out.write(_c(DIM, foot))
    from .llm import tidy_answer
    bad = re.findall(r"(\S+) \(⚠ unverified link\)", tidy_answer(text, hits))
    if bad:
        out.write(_c(YELLOW, "\n⚠ not found in the trusted sources (the model may have invented them): "
                     + ", ".join(dict.fromkeys(bad))))
    out.write(_c(DIM, f"\n[{time.time() - t:.1f}s]\n"))
    out.flush()
    return text + foot


# ── Agent ──────────────────────────────────────────────────────────────────────

def _data_root():
    from ..platform_paths import resolve_data_root, user_data_dir
    return resolve_data_root() or user_data_dir()


def _claude_keystore():
    from ..claude.keystore import KeyStore
    return KeyStore(_data_root())


def _scope_fns(scope, allow_private):
    if scope is None:
        return (lambda url: False, lambda host: False,                      # no scope ⇒ http blocked
                lambda req: {"blocked": True, "error": "no scope set (use --scope)"})
    return scope.allows_url, scope.allows_host, make_sender(scope, allow_private)


def _claude_cli_ctx(scope, allow_private, workdir_holder):
    """Claude tools outside the app: scope-checked http + offline sandbox + skills + trusted
    research. Workspace data and collections live in the RAVEN app, not the terminal."""
    import json as _json
    scope_check, host_check, sender = _scope_fns(scope, allow_private)

    def unavailable(*_a, **_k):
        raise ValueError("only available inside the RAVEN app (workspace data / collections)")

    def record_finding(title, url, severity, description, evidence):
        wd = workdir_holder[0]
        with open(wd / "findings.jsonl", "a", encoding="utf-8") as fh:
            fh.write(_json.dumps({"title": title, "url": url, "severity": severity,
                                  "description": description, "evidence": evidence}) + "\n")
        return f"local:{wd.name}/findings.jsonl"

    return {"scope_dict": lambda: {"include": list(scope.include) if scope else [],
                                   "exclude": [], "ports": list(scope.ports) if scope else []},
            "scope_url": scope_check, "scope_host": host_check, "send": sender,
            "collect": unavailable, "job": lambda _j: None, "assets": lambda: [], "urls": lambda: [],
            "traffic": lambda _n: [], "findings": lambda _n: [], "record_finding": record_finding}


def run_agent(objective: str, scope, allow_private: bool = False, inp=input, engine: str = "local") -> Optional[str]:
    if engine == "claude":
        from ..claude.agent import ClaudeAgentRun
        from ..claude.client import make_client
        holder = [None]
        ks = _claude_keystore()
        run = ClaudeAgentRun(objective, _data_root() / "claude-agent", _claude_cli_ctx(scope, allow_private, holder),
                             lambda: False, lambda: make_client(ks))
        holder[0] = run.workdir
    else:
        from .agent import AgentRun
        from .llm import RavenSecLLM
        scope_check, host_check, sender = _scope_fns(scope, allow_private)
        run = AgentRun(objective, scope_check, host_check, sender, lambda: False, RavenSecLLM.get)
    th = threading.Thread(target=run.run, daemon=True)
    th.start()
    shown = 0
    print(_c(DIM, f"[agent {run.id} · files: {run.workdir}]"))
    try:
        while True:
            snap = run.snapshot()
            for st in snap["steps"][shown:]:
                _print_step(st)
            shown = len(snap["steps"])
            if snap["state"] == "WAITING_APPROVAL" and snap["pending"]:
                p = snap["pending"]
                print(_c(YELLOW, f"\n⚠ approval needed — {p['tool']}:"))
                print(_c(BOLD, "  " + p["input"].replace("\n", "\n  ")))
                for n in p.get("notes") or []:
                    print(_c(YELLOW, f"  • {n}"))
                try:
                    ans = inp("Approve this exact action? [y/N, or type a reason to deny] ").strip()
                except EOFError:
                    ans = ""
                ok = ans.lower() in ("y", "yes", "نعم", "اه", "اي")
                run.decide(ok, "" if ok else ans, action_id=p["id"])
                continue
            if snap["state"] in ("DONE", "FAILED", "CANCELLED", "REFUSED", "BUDGET"):
                for st in run.snapshot()["steps"][shown:]:
                    _print_step(st)
                if snap["state"] != "DONE":
                    print(_c(RED, f"\n[{snap['state']}] {snap.get('error') or ''}"))
                else:
                    print(_c(GREEN, "\n── ANSWER ──"))
                    print(snap["answer"])
                u = snap.get("usage")
                if u:
                    print(_c(DIM, f"[≈${u['cost_usd']} · {u['requests']} requests · "
                                  f"{u['input_tokens']} in / {u['output_tokens']} out tokens]"))
                return snap.get("answer")
            time.sleep(0.4)
    except KeyboardInterrupt:
        run.cancel()
        th.join(10)
        print(_c(RED, "\n[cancelled]"))
        return None


def _print_step(st: dict) -> None:
    kind = st.get("type")
    if kind == "action":
        tag = " (auto)" if st.get("auto") else ""
        print(_c(CYAN, f"→ {st.get('tool')}{tag}: ") + str(st.get("input", ""))[:300])
    elif kind == "observation":
        txt = str(st.get("text", ""))
        print(_c(DIM, "  " + txt[:700].replace("\n", "\n  ") + ("…" if len(txt) > 700 else "")))
    elif kind == "decision":
        verdict = _c(GREEN, "approved") if st.get("approved") else _c(RED, "denied")
        print(f"  {verdict} {st.get('reason') or ''}")
    elif kind == "note" and st.get("role") == "claude":
        print(_c(BOLD, "Claude: ") + str(st.get("text", "")))
    elif kind == "note":
        print(_c(YELLOW, f"  · {st.get('text')}"))


# ── Entry point ────────────────────────────────────────────────────────────────

HELP = __doc__.split("Inside the chat:", 1)[1].split("Same model", 1)[0]


class ClaudeChat:
    """Chat with Claude Opus 5.5 using the key saved in the RAVEN app (or ANTHROPIC_API_KEY)."""
    def __init__(self):
        from ..claude import MODEL_LABEL
        from ..claude.client import make_client
        self.client = make_client(_claude_keystore())
        self.label = f"{MODEL_LABEL} (Anthropic API) — usage billed to your Anthropic account"
        self.cost = 0.0


def ask_claude(chat: "ClaudeChat", history: list, question: str, out=sys.stdout) -> str:
    from ..claude import client as cl
    from ..claude.prompts import CHAT_SYSTEM
    t = time.time()
    resp = cl.create(chat.client, system=CHAT_SYSTEM,
                     messages=history[-40:] + [{"role": "user", "content": question}],
                     max_tokens=16000, effort="medium")
    u = cl.Usage()
    u.add(getattr(resp, "usage", None))
    chat.cost += u.cost_usd
    text = cl.text_of(resp)
    ref = cl.refusal_info(resp)
    if ref:
        text = (text + "\n" if text else "") + f"[declined — safety category: {ref['category']}]"
    out.write(text + _c(DIM, f"\n[{time.time() - t:.1f}s · ≈${u.cost_usd} · session ≈${chat.cost:.3f}]\n"))
    return text


def repl(llm, scope_hosts: List[str], allow_private: bool) -> int:
    engine = "claude" if isinstance(llm, ClaudeChat) else "local"
    print(_c(BOLD, llm.label))
    print(_c(DIM, "Advisory only — verify findings and code by hand. /help for commands, /quit to exit.\n"))
    history: list = []
    scope = _scope_from(scope_hosts)
    while True:
        try:
            line = input(_c(GREEN, "you› ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        if line in ("/quit", "/exit", "/q"):
            return 0
        if line == "/help":
            print(HELP)
            continue
        if line == "/reset":
            history = []
            print(_c(DIM, "conversation cleared"))
            continue
        if line.startswith("/scope"):
            hosts = line[6:].replace(",", " ").split()
            try:
                scope = _scope_from(hosts)
                print(_c(DIM, f"scope: {', '.join(scope.include) if scope else '(none — http blocked)'}"))
            except ValueError as exc:
                print(_c(RED, f"invalid scope: {exc}"))
            continue
        if line.startswith("/search "):
            from . import research
            print(research.format_results(research.search(line[8:], 5), 400))
            continue
        if line.startswith("/read "):
            from . import research
            try:
                p = research.read(line[6:].strip(), max_chars=3000)
                print(_c(BOLD, p["title"]) + "\n" + p["url"] + "\n\n" + p["text"])
            except Exception as exc:
                print(_c(RED, f"{type(exc).__name__}: {exc}"))
            continue
        if line.startswith("/agent "):
            run_agent(line[7:].strip(), scope, allow_private, engine=engine)
            continue
        print(_c(CYAN, "claude› " if engine == "claude" else "raven-sec› "), end="", flush=True)
        try:
            answer = ask_claude(llm, history, line) if engine == "claude" else ask(llm, history, line)
        except KeyboardInterrupt:
            print(_c(RED, "\n[interrupted]"))
            continue
        except Exception as exc:
            from ..claude.client import friendly_error
            print(_c(RED, f"\n[{friendly_error(exc)}]"))
            continue
        history += [{"role": "user", "content": line}, {"role": "assistant", "content": answer}]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="raven-sec", description="RAVEN-Sec in the terminal")
    ap.add_argument("-q", "--question", help="ask one question and exit")
    ap.add_argument("--scope", action="append", default=[],
                    help="in-scope host[:port] for the agent's http tool (repeatable, "
                         "e.g. --scope app.example.com --scope 127.0.0.1:38333)")
    ap.add_argument("--allow-private", action="store_true",
                    help="allow in-scope targets on private/loopback addresses (your own lab only)")
    ap.add_argument("--claude", action="store_true",
                    help="use Claude Opus 5.5 (Anthropic API key saved in RAVEN → Settings, or ANTHROPIC_API_KEY)")
    ap.add_argument("command", nargs="*", help='"agent <objective>" to run the research agent')
    args = ap.parse_args(argv)
    # Public builds: the local RAVEN-Sec model is opt-in (RAVEN_LOCAL_AI=1, docs/LOCAL_AI.md);
    # otherwise the terminal uses Claude with the key saved in RAVEN → Settings.
    local_ok = os.environ.get("RAVEN_LOCAL_AI", "").strip() == "1"
    engine = "claude" if (args.claude or not local_ok) else "local"
    if engine == "claude":
        from ..claude.client import ClaudeUnavailable
        try:
            chat = ClaudeChat()
        except ClaudeUnavailable as exc:
            print(_c(RED, str(exc)))
            return 2
    if args.command and args.command[0] == "agent":
        objective = " ".join(args.command[1:]).strip()
        if not objective:
            ap.error("agent needs an objective")
        if engine == "local":
            _llm()
        return 0 if run_agent(objective, _scope_from(args.scope), args.allow_private, engine=engine) else 1
    if args.command:
        ap.error(f"unknown command {args.command[0]!r} (did you mean -q?)")
    llm = chat if engine == "claude" else _llm()
    if args.question:
        if engine == "claude":
            ask_claude(llm, [], args.question)
        else:
            ask(llm, [], args.question)
        return 0
    return repl(llm, args.scope, args.allow_private)


if __name__ == "__main__":
    raise SystemExit(main())
