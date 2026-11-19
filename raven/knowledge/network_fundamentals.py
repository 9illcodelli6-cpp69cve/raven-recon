"""RAVEN Network Knowledge — structured curriculum (Parts 1-18).

Provides structured, versioned knowledge about normal network and HTTP
behavior for educational purposes. NOT executable code. NOT security
verdicts. This is descriptive reference, not policy authority.

INVARIANTS:
- No executable exploit code.
- No network I/O.
- No security decisions derived from this module.
- is_security_relevant never set True by this module.
- Knowledge entries are reference material only.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class KnowledgePart(str, Enum):
    """Curriculum parts for network fundamentals knowledge."""
    PART_1_OSI             = "PART_1_OSI"
    PART_2_TCP_IP          = "PART_2_TCP_IP"
    PART_3_DNS             = "PART_3_DNS"
    PART_4_TLS             = "PART_4_TLS"
    PART_5_HTTP_PROTOCOL   = "PART_5_HTTP_PROTOCOL"
    PART_6_HTTP_METHODS    = "PART_6_HTTP_METHODS"
    PART_7_HTTP_STATUS     = "PART_7_HTTP_STATUS"
    PART_8_HTTP_HEADERS    = "PART_8_HTTP_HEADERS"
    PART_9_URL             = "PART_9_URL"
    PART_10_COOKIES        = "PART_10_COOKIES"
    PART_11_SESSIONS       = "PART_11_SESSIONS"
    PART_12_AUTH_SCHEMES   = "PART_12_AUTH_SCHEMES"
    PART_13_API_PATTERNS   = "PART_13_API_PATTERNS"
    PART_14_CACHING        = "PART_14_CACHING"
    PART_15_CORS           = "PART_15_CORS"
    PART_16_RESPONSE_DIFF  = "PART_16_RESPONSE_DIFF"
    PART_17_STATE_MACHINES = "PART_17_STATE_MACHINES"
    PART_18_NORMAL_BASELINES = "PART_18_NORMAL_BASELINES"


@dataclass
class KnowledgeEntry:
    part: KnowledgePart
    title: str
    summary: str
    key_concepts: list[str] = field(default_factory=list)
    non_vulnerability_reminders: list[str] = field(default_factory=list)
    related_parts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "part": self.part.value,
            "title": self.title,
            "summary": self.summary,
            "key_concepts": self.key_concepts,
            "non_vulnerability_reminders": self.non_vulnerability_reminders,
            "related_parts": self.related_parts,
        }


NETWORK_KNOWLEDGE: dict[str, KnowledgeEntry] = {
    KnowledgePart.PART_1_OSI.value: KnowledgeEntry(
        part=KnowledgePart.PART_1_OSI,
        title="OSI and TCP/IP Layering",
        summary=(
            "Network communication is modeled as layered abstractions. "
            "OSI has 7 layers (Physical to Application); TCP/IP has 4 (Link, "
            "Internet, Transport, Application). Each layer has defined responsibilities "
            "and passes data to the layer above or below."
        ),
        key_concepts=[
            "Encapsulation: each layer wraps lower-layer PDUs with its own header",
            "Application layer: HTTP, DNS, TLS operate here",
            "Transport layer: TCP (reliable, ordered) vs UDP (unreliable, unordered)",
            "Network layer: IP addressing, routing",
            "Layer boundaries define where security controls are applied",
        ],
        non_vulnerability_reminders=[
            "A packet at a given layer is normal — not a vulnerability by itself",
            "TCP SYN without prior SYN-ACK could be normal or scan — context required",
        ],
        related_parts=[KnowledgePart.PART_2_TCP_IP.value],
    ),

    KnowledgePart.PART_2_TCP_IP.value: KnowledgeEntry(
        part=KnowledgePart.PART_2_TCP_IP,
        title="TCP/IP Fundamentals",
        summary=(
            "TCP provides reliable, ordered, connection-oriented transport via "
            "three-way handshake (SYN, SYN-ACK, ACK). IP handles addressing "
            "and routing. Key concepts: ports, socket addresses, connection state, "
            "keep-alive, TIME_WAIT."
        ),
        key_concepts=[
            "Three-way handshake: SYN → SYN-ACK → ACK",
            "Port: logical multiplexing endpoint (0-65535); well-known < 1024",
            "Connection teardown: FIN-ACK exchange",
            "TCP keeps order via sequence numbers",
            "Keep-alive: heartbeat probes to detect dead connections",
        ],
        non_vulnerability_reminders=[
            "Open port != vulnerability; service must be evaluated in context",
            "Connection error is observation, not proof of attack",
        ],
        related_parts=[KnowledgePart.PART_3_DNS.value, KnowledgePart.PART_4_TLS.value],
    ),

    KnowledgePart.PART_3_DNS.value: KnowledgeEntry(
        part=KnowledgePart.PART_3_DNS,
        title="DNS — Domain Name System",
        summary=(
            "DNS translates domain names to IP addresses via recursive resolution. "
            "Resolvers query root → TLD → authoritative servers. Records: A, AAAA, "
            "CNAME, MX, TXT, NS, PTR. TTL controls caching."
        ),
        key_concepts=[
            "A record: domain → IPv4",
            "CNAME: canonical name alias",
            "TTL: time-to-live — how long resolvers may cache",
            "NXDOMAIN: non-existent domain response",
            "Resolution failure = NETWORK_FAILURE in protocol classification",
        ],
        non_vulnerability_reminders=[
            "DNS resolution failure is a network observation, not an attack indicator",
            "TXT record presence requires context — not automatically an issue",
        ],
        related_parts=[KnowledgePart.PART_2_TCP_IP.value, KnowledgePart.PART_4_TLS.value],
    ),

    KnowledgePart.PART_4_TLS.value: KnowledgeEntry(
        part=KnowledgePart.PART_4_TLS,
        title="TLS — Transport Layer Security",
        summary=(
            "TLS provides encryption, integrity, and authentication for TCP streams. "
            "Handshake: ClientHello → ServerHello → Certificate → Finished. "
            "TLS 1.3 is current; 1.2 still common. Certificate validation verifies "
            "hostname, chain of trust, and expiry."
        ),
        key_concepts=[
            "Certificate: binds public key to identity; signed by CA",
            "SNI: server name indication — client announces target hostname",
            "Certificate validation failure → connection rejected (fail-closed)",
            "HSTS: server instructs browser to always use TLS",
            "TLS does not mean the application is secure",
        ],
        non_vulnerability_reminders=[
            "TLS failure is a connection event — not a confirmed attack",
            "HTTPS does not mean content is safe or server is trustworthy",
            "DO NOT DISABLE TLS VALIDATION",
        ],
        related_parts=[KnowledgePart.PART_5_HTTP_PROTOCOL.value],
    ),

    KnowledgePart.PART_5_HTTP_PROTOCOL.value: KnowledgeEntry(
        part=KnowledgePart.PART_5_HTTP_PROTOCOL,
        title="HTTP/1.1, HTTP/2, HTTP/3 Protocol Basics",
        summary=(
            "HTTP is a stateless request/response protocol. HTTP/1.1 uses "
            "persistent connections. HTTP/2 multiplexes streams over one TCP "
            "connection (binary framing). HTTP/3 uses QUIC (UDP-based). "
            "Each request is method + URI + headers + optional body."
        ),
        key_concepts=[
            "Request: METHOD URI HTTP/version CRLF Headers CRLF [Body]",
            "Response: HTTP/version StatusCode ReasonPhrase CRLF Headers CRLF [Body]",
            "Stateless: each request independent; state carried in headers/cookies",
            "Content-Type and Content-Length describe the body",
            "Keep-Alive: reuse TCP connection across multiple requests",
        ],
        non_vulnerability_reminders=[
            "HTTP is inherently stateless — state management is by design",
            "HTTP/2 or HTTP/3 usage is not an anomaly",
        ],
        related_parts=[
            KnowledgePart.PART_6_HTTP_METHODS.value,
            KnowledgePart.PART_7_HTTP_STATUS.value,
        ],
    ),

    KnowledgePart.PART_6_HTTP_METHODS.value: KnowledgeEntry(
        part=KnowledgePart.PART_6_HTTP_METHODS,
        title="HTTP Methods and Semantics",
        summary=(
            "HTTP methods define the intended operation. Safe methods (GET/HEAD/OPTIONS) "
            "must not have side effects. Idempotent methods (GET/PUT/DELETE) produce "
            "the same result if repeated. POST is neither safe nor idempotent."
        ),
        key_concepts=[
            "GET: retrieve resource; safe, idempotent, no request body",
            "POST: create/submit; not safe, not idempotent",
            "PUT: replace resource; idempotent",
            "PATCH: partial update; not idempotent by default",
            "DELETE: remove resource; idempotent",
            "HEAD: like GET but no body in response",
            "OPTIONS: discover allowed methods / CORS preflight",
        ],
        non_vulnerability_reminders=[
            "POST to a known endpoint is normal application behavior",
            "405 Method Not Allowed is a server policy, not a vulnerability",
        ],
        related_parts=[KnowledgePart.PART_7_HTTP_STATUS.value],
    ),

    KnowledgePart.PART_7_HTTP_STATUS.value: KnowledgeEntry(
        part=KnowledgePart.PART_7_HTTP_STATUS,
        title="HTTP Status Codes",
        summary=(
            "Status codes communicate the result of an HTTP request. "
            "1xx: informational. 2xx: success. 3xx: redirection. "
            "4xx: client error. 5xx: server error."
        ),
        key_concepts=[
            "200 OK: request succeeded",
            "201 Created: new resource created",
            "301/302: permanent/temporary redirect",
            "400 Bad Request: malformed request syntax",
            "401 Unauthorized: authentication required",
            "403 Forbidden: authenticated but not authorized",
            "404 Not Found: resource does not exist",
            "429 Too Many Requests: rate limited",
            "500 Internal Server Error: unexpected server failure",
            "502/503/504: gateway/service/timeout errors",
        ],
        non_vulnerability_reminders=[
            "200 is NORMAL_SUCCESS — not a vulnerability",
            "500 is an application error — requires demonstrated impact",
            "403 means forbidden by app logic — not proof of auth bypass",
            "401 means auth required — not proof of weakness",
        ],
        related_parts=[KnowledgePart.PART_8_HTTP_HEADERS.value],
    ),

    KnowledgePart.PART_8_HTTP_HEADERS.value: KnowledgeEntry(
        part=KnowledgePart.PART_8_HTTP_HEADERS,
        title="HTTP Headers — Request and Response",
        summary=(
            "Headers carry metadata about the request, response, or the connection. "
            "Headers are case-insensitive name-value pairs separated by colons."
        ),
        key_concepts=[
            "Content-Type: describes body format (application/json, text/html, etc.)",
            "Authorization: carries credentials (Bearer, Basic, etc.)",
            "Cookie/Set-Cookie: session state management",
            "Location: redirect target (in 3xx responses)",
            "WWW-Authenticate: auth challenge (in 401 responses)",
            "Retry-After: delay before retry (in 429 responses)",
            "X-Request-ID/X-Trace-ID: tracing identifiers",
        ],
        non_vulnerability_reminders=[
            "Authorization header presence is normal for authenticated requests",
            "Set-Cookie presence is normal session management",
            "Stack trace in response body is information disclosure indicator — not confirmed vuln",
        ],
        related_parts=[KnowledgePart.PART_9_URL.value, KnowledgePart.PART_10_COOKIES.value],
    ),

    KnowledgePart.PART_9_URL.value: KnowledgeEntry(
        part=KnowledgePart.PART_9_URL,
        title="URL Structure and Parsing",
        summary=(
            "URL: scheme://[userinfo@]host[:port]/path[?query][#fragment]. "
            "Percent-encoding: characters → %HH hex. "
            "Query string: key=value pairs separated by &."
        ),
        key_concepts=[
            "scheme: protocol (https, http)",
            "host: domain or IP; port optional (default 443/80)",
            "path: hierarchical resource identifier",
            "query: ?key=value&key2=val2 — name-value pairs",
            "fragment: #section — client-side only, not sent to server",
            "URL normalization: multiple representations may point to same resource",
        ],
        non_vulnerability_reminders=[
            "URL normalization difference is an observation — not path traversal",
            "Query string presence is normal application behavior",
            "Fragment is client-side — server never receives it",
        ],
        related_parts=[KnowledgePart.PART_10_COOKIES.value],
    ),

    KnowledgePart.PART_10_COOKIES.value: KnowledgeEntry(
        part=KnowledgePart.PART_10_COOKIES,
        title="Cookies — Purpose and Attributes",
        summary=(
            "Cookies are name-value pairs set by Set-Cookie response headers. "
            "Attributes control scope (Domain, Path), lifetime (Expires/Max-Age), "
            "security (Secure, HttpOnly, SameSite)."
        ),
        key_concepts=[
            "Secure: cookie sent only over HTTPS",
            "HttpOnly: inaccessible to JavaScript (reduces XSS impact)",
            "SameSite=Strict/Lax/None: cross-site sending rules",
            "Domain/Path: scope of which requests include the cookie",
            "Max-Age/Expires: cookie lifetime; session cookie has neither",
        ],
        non_vulnerability_reminders=[
            "Session cookie presence is normal state management",
            "Missing Secure flag is an observation requiring context",
            "Cookie name/value presence is not session hijack evidence",
        ],
        related_parts=[KnowledgePart.PART_11_SESSIONS.value],
    ),

    KnowledgePart.PART_11_SESSIONS.value: KnowledgeEntry(
        part=KnowledgePart.PART_11_SESSIONS,
        title="Sessions — State Management Patterns",
        summary=(
            "HTTP is stateless; sessions track user state across requests. "
            "Session state: ANONYMOUS (no auth), AUTHENTICATED (active session), "
            "EXPIRED (session timed out), INVALID (rejected/malformed token), "
            "ROTATED (session ID changed post-login)."
        ),
        key_concepts=[
            "Session fixation defense: rotate session ID after successful login",
            "Session token storage: HttpOnly cookie preferred over localStorage",
            "Session expiry: server-side TTL + client-side Max-Age",
            "Token rotation on privilege elevation is normal security practice",
        ],
        non_vulnerability_reminders=[
            "Session ID in Set-Cookie is normal — not session hijacking",
            "Session rotation is good practice — not an anomaly",
            "Session expiry (401 on old token) is expected application behavior",
        ],
        related_parts=[KnowledgePart.PART_12_AUTH_SCHEMES.value],
    ),

    KnowledgePart.PART_12_AUTH_SCHEMES.value: KnowledgeEntry(
        part=KnowledgePart.PART_12_AUTH_SCHEMES,
        title="Authentication Schemes",
        summary=(
            "HTTP auth schemes: Basic (base64 credentials), Digest (challenge-response), "
            "Bearer (OAuth 2.0 tokens), API Key (custom header or query). "
            "OAuth 2.0 uses client_credentials (app) vs authorization_code (user). "
            "JWT: signed JSON Web Token; signature does not encrypt claims."
        ),
        key_concepts=[
            "Basic: Authorization: Basic <base64(user:pass)> — MUST use TLS",
            "Bearer: Authorization: Bearer <token>",
            "API Key: X-API-Key header or query param ?api_key=",
            "OAuth client_credentials: machine-to-machine — APPLICATION_AUTHENTICATED",
            "OAuth authorization_code: user-delegated — USER_AUTHENTICATED",
            "JWT: header.payload.signature — payload readable without key",
        ],
        non_vulnerability_reminders=[
            "Bearer token in Authorization header is normal authenticated request",
            "API key in X-API-Key header is APPLICATION_AUTHENTICATED — not exposure",
            "JWT payload is base64url encoded — not encrypted; reading claims is normal",
        ],
        related_parts=[KnowledgePart.PART_13_API_PATTERNS.value],
    ),

    KnowledgePart.PART_13_API_PATTERNS.value: KnowledgeEntry(
        part=KnowledgePart.PART_13_API_PATTERNS,
        title="REST API Design Patterns",
        summary=(
            "REST APIs use HTTP methods on resource URLs. "
            "Collections: GET /items (list), POST /items (create). "
            "Items: GET /items/1 (read), PUT /items/1 (replace), "
            "PATCH /items/1 (update), DELETE /items/1 (delete). "
            "Pagination: ?page=1&limit=20 or cursor-based."
        ),
        key_concepts=[
            "Collection vs item URLs: /resources vs /resources/:id",
            "Idempotency keys: X-Idempotency-Key for safe POST retry",
            "Pagination: Link header or JSON pagination metadata",
            "Versioning: /v1/resources or Accept: application/vnd.api+json;version=1",
            "HATEOAS: hypermedia links in response drive client navigation",
        ],
        non_vulnerability_reminders=[
            "CRUD operations on known API endpoints are normal behavior",
            "Pagination response with count/total is normal metadata",
        ],
        related_parts=[KnowledgePart.PART_14_CACHING.value],
    ),

    KnowledgePart.PART_14_CACHING.value: KnowledgeEntry(
        part=KnowledgePart.PART_14_CACHING,
        title="HTTP Caching",
        summary=(
            "Cache-Control directives control caching behavior. "
            "Validators: ETag (resource version token) and Last-Modified. "
            "Conditional requests: If-None-Match and If-Modified-Since. "
            "304 Not Modified means cached copy is valid."
        ),
        key_concepts=[
            "Cache-Control: max-age=N, no-cache, no-store, private, public",
            "ETag: opaque version identifier; server returns 304 if still valid",
            "304 Not Modified: cached response is fresh — use it",
            "Vary: header tells caches which request headers affect the response",
            "CDN/proxy caches may serve different responses than origin",
        ],
        non_vulnerability_reminders=[
            "Cache miss / cache hit difference is normal — not a vulnerability",
            "304 response is expected cache validation behavior",
            "Vary: header-driven response differences are expected",
        ],
        related_parts=[KnowledgePart.PART_15_CORS.value],
    ),

    KnowledgePart.PART_15_CORS.value: KnowledgeEntry(
        part=KnowledgePart.PART_15_CORS,
        title="CORS — Cross-Origin Resource Sharing",
        summary=(
            "CORS is a browser security mechanism restricting cross-origin requests. "
            "Preflight: OPTIONS request with Origin and Access-Control-Request-Method. "
            "Server responds with Access-Control-Allow-Origin etc. "
            "Server-side enforcement is what matters, not the header presence."
        ),
        key_concepts=[
            "Simple request: GET/POST with basic headers — no preflight",
            "Preflight: OPTIONS sent before non-simple request",
            "Access-Control-Allow-Origin: * or specific origin",
            "Access-Control-Allow-Credentials: true requires specific origin (not *)",
            "CORS only applies to browsers; non-browser clients bypass it entirely",
        ],
        non_vulnerability_reminders=[
            "CORS header presence requires browser semantics to be a concern",
            "Access-Control-Allow-Origin: * is only a vulnerability in specific contexts",
            "Preflight OPTIONS request is normal browser behavior — not an attack",
        ],
        related_parts=[KnowledgePart.PART_16_RESPONSE_DIFF.value],
    ),

    KnowledgePart.PART_16_RESPONSE_DIFF.value: KnowledgeEntry(
        part=KnowledgePart.PART_16_RESPONSE_DIFF,
        title="Response Difference Taxonomy",
        summary=(
            "Differences between two HTTP responses are observations, not findings. "
            "Classes: NO_CHANGE, EXPECTED_CHANGE, STATE_DEPENDENT, STRUCTURAL_CHANGE, "
            "CONTENT_CHANGE, AUTH_STATE_CHANGE, TRANSIENT, UNKNOWN. "
            "Difference classification is separate from vulnerability classification."
        ),
        key_concepts=[
            "NO_CHANGE: identical responses — baseline holds",
            "EXPECTED_CHANGE: cache expiry, pagination, time-based data",
            "STATE_DEPENDENT: different auth state → different response",
            "AUTH_STATE_CHANGE: 200→401/403 transition reveals auth boundary",
            "TRANSIENT: 502/503 transient error — not a consistent behavior",
            "CONTENT_CHANGE: same structure, different values — normal dynamic data",
        ],
        non_vulnerability_reminders=[
            "Response difference requires context before security classification",
            "STATE_DEPENDENT difference is normal multi-role application behavior",
            "AUTH_STATE_CHANGE shows auth boundary — requires further analysis",
        ],
        related_parts=[KnowledgePart.PART_17_STATE_MACHINES.value],
    ),

    KnowledgePart.PART_17_STATE_MACHINES.value: KnowledgeEntry(
        part=KnowledgePart.PART_17_STATE_MACHINES,
        title="HTTP State Machines and Flows",
        summary=(
            "HTTP applications have protocol state machines: login flow "
            "(anonymous → authenticated → session-active), "
            "checkout flow (cart → payment → confirmation), "
            "upload flow (initiate → upload-part → complete). "
            "Understanding normal flows prevents false positive findings."
        ),
        key_concepts=[
            "Login: POST /login → 200 (Set-Cookie: session) = ROTATED session",
            "Logout: POST /logout → 200 (clear session cookie) = ANONYMOUS",
            "Password reset: multi-step flow with token validation",
            "OAuth callback: GET /callback?code= → token exchange",
            "Pagination: GET /items?page=1 → next page link in response",
        ],
        non_vulnerability_reminders=[
            "Post-login session rotation is correct behavior — not an anomaly",
            "Redirect after login (302 to dashboard) is normal flow",
            "OAuth code exchange is a normal step — not a token leak",
        ],
        related_parts=[KnowledgePart.PART_18_NORMAL_BASELINES.value],
    ),

    KnowledgePart.PART_18_NORMAL_BASELINES.value: KnowledgeEntry(
        part=KnowledgePart.PART_18_NORMAL_BASELINES,
        title="Normal Baselines — What Good Looks Like",
        summary=(
            "Before classifying anomalies, RAVEN must understand normal behavior. "
            "Normal: 2xx for valid authenticated requests, 401 for missing auth, "
            "403 for insufficient auth, 3xx for moved resources, "
            "429 under load, consistent response structure for same endpoint."
        ),
        key_concepts=[
            "Authenticated endpoint: 200 with auth header, 401 without",
            "Admin endpoint: 403 for non-admin authenticated user",
            "Rate-limited endpoint: 429 with Retry-After after quota exceeded",
            "Redirect: 301 for permanently moved resources",
            "Consistent JSON schema for same endpoint across requests",
            "Session cookie rotation on each login is expected",
        ],
        non_vulnerability_reminders=[
            "All 2xx responses need endpoint context before security assessment",
            "Consistent behavior across many requests is evidence of normal baseline",
            "Baseline deviation is a signal — requires further analysis, not a finding",
        ],
        related_parts=[KnowledgePart.PART_16_RESPONSE_DIFF.value],
    ),
}


def get_knowledge(part: str) -> Optional[KnowledgeEntry]:
    return NETWORK_KNOWLEDGE.get(part)


def list_parts() -> list[str]:
    return list(NETWORK_KNOWLEDGE.keys())


def get_non_vulnerability_reminders() -> list[str]:
    """Aggregate all non-vulnerability reminders from all parts."""
    reminders: list[str] = []
    for entry in NETWORK_KNOWLEDGE.values():
        reminders.extend(entry.non_vulnerability_reminders)
    return reminders
