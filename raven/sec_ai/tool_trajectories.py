"""Synthetic agent trajectories that USE the approval-gated tools (http / shell).

The first fine-tune only ever saw "search → ANSWER", so the agent never proposed a request
and could not interpret one (measured on the local lab: it sent nothing, or answered with
a bare source line). These templates teach the exact runtime protocol:

    search (auto) → ACTION: http / shell → OBSERVATION (real-shaped response) → ANSWER

Every scenario has a VULNERABLE and a NOT-VULNERABLE outcome, so the model learns to read
the evidence instead of always claiming a finding. Hosts are placeholders/lab addresses;
cited sources are real pages of the local trusted corpus (looked up at build time).
Synthetic data — it teaches format and evidence-reading, not new security knowledge.
"""
from __future__ import annotations

import base64
import json
import random
from typing import Callable, List, Optional

from .prompts import AGENT_SYSTEM

HOSTS = ["https://app.example.com", "https://shop.target.test", "https://api.acme.test",
         "http://127.0.0.1:38333", "http://10.0.0.5:8080", "https://portal.example.org",
         "https://staging.target.test", "http://lab.local:8000"]
USERS = [("alice", 1), ("bob", 2), ("carol", 7), ("dave", 12), ("erin", 31), ("frank", 104)]
RESOURCES = ["users", "accounts", "orders", "invoices", "profiles", "documents"]


def _obs_http(status: int, reason: str, headers: dict, body: str) -> str:
    """Same shape as AgentRun._gated's http observation."""
    hdrs = "\n".join(f"{k}: {v}" for k, v in list(headers.items())[:15])
    return f"HTTP {status} {reason} · {len(body.encode())} bytes · {random.randint(3, 400)} ms\n{hdrs}\n\n{body[:1200]}"


def _hdrs(ctype="application/json", extra=None):
    h = {"Server": random.choice(["nginx", "Apache", "gunicorn", "LabServer/1.0"]),
         "Content-Type": ctype}
    h.update(extra or {})
    return h


# Each scenario returns (objective, action_input, observation, answer, source_query).

def _idor(rng, vuln):
    host = rng.choice(HOSTS)
    (u1, id1), (u2, id2) = rng.sample(USERS, 2)
    res = rng.choice(RESOURCES)
    tok = f"session={u1}" if rng.random() < 0.5 else f"sid={rng.getrandbits(40):x}"
    obj = (f"Check for IDOR: I am {u1} (cookie {tok}, my own id is {id1}). Request "
           f"{host}/api/{res}/{id2} and tell me if I can read another user's data.")
    act = f"GET {host}/api/{res}/{id2}\nCookie: {tok}"
    if vuln:
        body = json.dumps({"id": id2, "name": u2, "email": f"{u2}@corp.test"})
        obs = _obs_http(200, "OK", _hdrs(), body)
        ans = (f"Confirmed IDOR (broken object level authorization). Authenticated as {u1} (id {id1}), "
               f"GET /api/{res}/{id2} returned HTTP 200 with another user's record ({u2}, id {id2}). "
               "The server does not check that the object belongs to the caller.\n"
               "Next: repeat with a second account to rule out shared data, try write methods "
               "(PUT/PATCH/DELETE) on the same id, and include both requests and responses in the report.")
    else:
        code, reason, body = rng.choice([(403, "Forbidden", '{"error": "forbidden"}'),
                                         (404, "Not Found", '{"error": "not found"}'),
                                         (401, "Unauthorized", '{"error": "login required"}')])
        obs = _obs_http(code, reason, _hdrs(), body)
        ans = (f"Not vulnerable for this request: as {u1}, GET /api/{res}/{id2} returned HTTP {code} {reason} "
               "and no data of the other user — the server enforces object ownership here.\n"
               "Still check other identifiers (UUIDs, numeric neighbours), other methods (PUT/DELETE) "
               "and nested resources before concluding the endpoint is safe.")
    return obj, act, obs, ans, "insecure direct object references testing"


def _xss(rng, vuln):
    host = rng.choice(HOSTS)
    param = rng.choice(["q", "search", "name", "term", "redirect_msg"])
    path = rng.choice(["/search", "/results", "/profile", "/items"])
    canary = f"rvn{rng.getrandbits(24):x}"
    obj = f"Check whether the {param} parameter of {host}{path} reflects input unsafely (XSS)."
    act = f"GET {host}{path}?{param}={canary}%22%3E%3Cb%3E"
    if vuln:
        body = f'<html><body><h1>Results for {canary}"><b></h1><input value="{canary}"><b>"></body></html>'
        obs = _obs_http(200, "OK", _hdrs("text/html; charset=utf-8"), body)
        ans = (f"Likely reflected XSS: the canary {canary} came back with the probe characters "
               "`\"><b>` UNENCODED in the HTML (both in text and inside the value attribute), so input "
               "can break out of the attribute and add markup.\n"
               "Confirm in a browser with a harmless payload such as `\"><svg onload=alert(document.domain)>` "
               "and check whether a CSP blocks inline script.")
    else:
        body = (f"<html><body><h1>Results for {canary}&quot;&gt;&lt;b&gt;</h1>"
                f'<input value="{canary}&quot;&gt;&lt;b&gt;"></body></html>')
        obs = _obs_http(200, "OK", _hdrs("text/html; charset=utf-8"), body)
        ans = (f"Reflected but encoded: {canary} is echoed, yet `\"><b>` came back as "
               "`&quot;&gt;&lt;b&gt;` — HTML-encoded in both contexts, so this request does not show XSS.\n"
               "Check other contexts (JavaScript strings, URLs, attributes without quotes) and other parameters.")
    return obj, act, obs, ans, "reflected cross site scripting testing"


def _redirect(rng, vuln):
    host = rng.choice(HOSTS)
    param = rng.choice(["next", "url", "redirect", "returnTo", "continue"])
    path = rng.choice(["/login", "/logout", "/redirect", "/sso/callback"])
    obj = f"Test {host}{path} for an open redirect via the {param} parameter."
    act = f"GET {host}{path}?{param}=https://evil.example/landing"
    if vuln:
        obs = _obs_http(302, "Found", _hdrs("text/html", {"Location": "https://evil.example/landing"}), "")
        ans = (f"Confirmed open redirect: {path}?{param}=https://evil.example/landing answered 302 with "
               "`Location: https://evil.example/landing` — an external, attacker-chosen host.\n"
               "Impact depends on use (phishing, OAuth token theft via redirect_uri chains); report with the request.")
    else:
        loc = host + "/home"
        obs = _obs_http(302, "Found", _hdrs("text/html", {"Location": loc}), "")
        ans = (f"Not an open redirect for this input: the server ignored the external URL and redirected "
               f"to its own host ({loc}).\nTry bypasses: `//evil.example`, `/\\evil.example`, "
               "`https:evil.example`, `@evil.example`, and URL-encoded variants.")
    return obj, act, obs, ans, "open redirect testing"


def _cors(rng, vuln):
    host = rng.choice(HOSTS)
    path = rng.choice(["/api/me", "/api/account", "/api/v1/profile"])
    obj = f"Check {host}{path} for a CORS misconfiguration."
    act = f"GET {host}{path}\nOrigin: https://evil.example"
    body = json.dumps({"user": rng.choice(USERS)[0], "plan": "pro"})
    if vuln:
        obs = _obs_http(200, "OK", _hdrs(extra={"Access-Control-Allow-Origin": "https://evil.example",
                                                "Access-Control-Allow-Credentials": "true"}), body)
        ans = ("CORS misconfiguration: the response reflects the arbitrary Origin "
               "(`Access-Control-Allow-Origin: https://evil.example`) AND sends "
               "`Access-Control-Allow-Credentials: true`, so any website can read this authenticated "
               "response from a victim's browser.\nPoC: a page on another origin calling fetch(url, "
               "{credentials:'include'}) and reading the body.")
    else:
        obs = _obs_http(200, "OK", _hdrs(), body)
        ans = ("No CORS issue for this origin: the response has no Access-Control-Allow-Origin header, "
               "so browsers will not let https://evil.example read it.\nAlso try `Origin: null` and "
               "look-alike origins (e.g. https://app.example.com.evil.example).")
    return obj, act, obs, ans, "cors misconfiguration testing"


def _headers(rng, vuln):
    host = rng.choice(HOSTS)
    obj = f"Check which security headers {host}/ is missing."
    act = f"GET {host}/"
    present = {"Content-Security-Policy": "default-src 'self'", "Strict-Transport-Security": "max-age=31536000",
               "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"}
    if vuln:
        keep = dict(rng.sample(sorted(present.items()), rng.randint(0, 2)))
        missing = [h for h in present if h not in keep]
        obs = _obs_http(200, "OK", _hdrs("text/html", keep), "<html><title>Home</title></html>")
        ans = ("Missing security headers: " + ", ".join(missing) + ". "
               + ("Present: " + ", ".join(keep) + ". " if keep else "")
               + "These are hardening gaps (clickjacking, MIME sniffing, downgrade/XSS impact), usually "
                 "low severity on their own — report them together with an impact you can show.")
    else:
        obs = _obs_http(200, "OK", _hdrs("text/html", present), "<html><title>Home</title></html>")
        ans = ("All four checked headers are present: Content-Security-Policy, Strict-Transport-Security, "
               "X-Frame-Options and X-Content-Type-Options. Review the CSP value itself (e.g. 'unsafe-inline').")
    return obj, act, obs, ans, "http security response headers"


def _sqli(rng, vuln):
    host = rng.choice(HOSTS)
    param = rng.choice(["id", "item", "cat", "product"])
    path = rng.choice(["/item", "/product", "/news", "/api/items"])
    obj = f"Probe the {param} parameter of {host}{path} for SQL injection (error-based)."
    act = f"GET {host}{path}?{param}=1%27"
    if vuln:
        err = rng.choice(["You have an error in your SQL syntax; check the manual that corresponds to your "
                          "MySQL server version for the right syntax to use near ''1''' at line 1",
                          "PG::SyntaxError: ERROR:  unterminated quoted string at or near \"'1''\"",
                          "Unclosed quotation mark after the character string '1''."])
        obs = _obs_http(500, "Internal Server Error", _hdrs("text/html"), f"<pre>{err}</pre>")
        ans = (f"Likely SQL injection: a single quote in {param} produced a database syntax error in the "
               "response, so the input reaches the SQL query unescaped.\nConfirm safely with a boolean pair "
               f"({param}=1 AND 1=1 vs 1 AND 1=2) or a time delay, then stop — do not dump data beyond "
               "what the program allows.")
    else:
        obs = _obs_http(400, "Bad Request", _hdrs(), '{"error": "id must be an integer"}')
        ans = (f"No sign of SQL injection here: the quote was rejected by input validation (400, "
               f"\"{param} must be an integer\") before reaching the database.\nTry other parameters, "
               "JSON bodies and headers, and blind techniques if errors are suppressed.")
    return obj, act, obs, ans, "sql injection testing"


def _admin(rng, vuln):
    host = rng.choice(HOSTS)
    u, _ = rng.choice(USERS)
    path = rng.choice(["/admin", "/admin/users", "/internal/dashboard", "/manage"])
    obj = f"As the low-privilege user {u} (cookie session={u}), check whether {host}{path} is accessible."
    act = f"GET {host}{path}\nCookie: session={u}"
    if vuln:
        obs = _obs_http(200, "OK", _hdrs("text/html"), "<html><h1>Admin panel</h1><table>users…</table></html>")
        ans = (f"Broken access control: the low-privilege session of {u} got HTTP 200 and the admin panel "
               f"content at {path}. Vertical privilege escalation — check which admin actions also work.")
    else:
        obs = _obs_http(403, "Forbidden", _hdrs("text/html"), "<h1>403 Forbidden</h1>")
        ans = (f"Access correctly denied: {path} returned 403 Forbidden for {u}'s session.\n"
               "Also try method/path variations (HEAD, /admin/., /ADMIN, X-Original-URL) before concluding.")
    return obj, act, obs, ans, "testing for bypassing authorization schema"


def _shell_jwt(rng, vuln):
    u, uid = rng.choice(USERS)
    role = "admin" if vuln else "user"
    payload = {"sub": str(uid), "name": u, "role": role, "exp": 1893456000}
    p64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    h64 = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    jwt = f"{h64}.{p64}.{base64.urlsafe_b64encode(rng.randbytes(16)).decode().rstrip('=')}"
    obj = f"Decode this JWT and tell me its claims: {jwt}"
    act = f"echo '{p64}' | base64 -d 2>/dev/null; echo"
    obs = f"[exit 0]\n{json.dumps(payload)}"
    ans = (f"The payload decodes to: sub={uid}, name={u}, role={role}, exp=1893456000 (alg HS256). "
           "Decoding is not verification — the signature was not checked. Test whether the server accepts a "
           "modified token (role changed, alg none, weak HS256 secret) before claiming a finding.")
    return obj, act, obs, ans, "json web token"


SCENARIOS: List[Callable] = [_idor, _xss, _redirect, _cors, _headers, _sqli, _admin, _shell_jwt]


def build(n: int = 400, seed: int = 11, kb=None, fits: Optional[Callable] = None) -> List[dict]:
    rng = random.Random(seed)
    random.seed(seed)
    out: List[dict] = []
    tries = 0
    while len(out) < n and tries < n * 4:
        tries += 1
        scen = SCENARIOS[tries % len(SCENARIOS)]  # rotate on every try: a too-long scenario
                                                   # must not stall the whole loop
        vuln = rng.random() < 0.6
        obj, act, obs, ans, sq = scen(rng, vuln)
        tool = "shell" if scen is _shell_jwt else "http"
        hits = kb.search(sq, 2) if kb is not None and getattr(kb, "available", False) else []
        src = hits[0]["url"] if hits else ""
        for keep, chars in ((2, 160), (1, 120), (1, 60), (0, 0)):
            search_obs = "\n\n".join(
                f"[{i}] {h['title']}" + (f" — {h['heading']}" if h.get("heading") else "")
                + f"\n{h['url']}\n{h['text'][:chars].strip()}" for i, h in enumerate(hits[:keep], 1)) \
                or "No results in the trusted sources."
            msgs = _messages(obj, tool, act, obs, ans, src, search_obs)
            if fits is None or fits(msgs):
                break
        else:
            continue
        out.append({"doc_id": f"tools-{len(out)}", "source": "agent-tools", "question": obj,
                    "answer": ans, "url": src, "messages": msgs})
    return out


def _messages(obj, tool, act, obs, ans, src, search_obs):
    return [{"role": "system", "content": AGENT_SYSTEM},
                {"role": "user", "content": obj},
                {"role": "assistant", "content": f"ACTION: search\nINPUT: {obj[:300]}"},
                {"role": "user", "content": f"OBSERVATION (search):\n{search_obs}"},
                {"role": "assistant", "content": f"ACTION: {tool}\nINPUT: {act}"},
                {"role": "user", "content": f"OBSERVATION ({tool}):\n{obs}"},
                {"role": "assistant", "content": "ANSWER: " + ans + (f"\n\nSource: {src}" if src else "")}]
