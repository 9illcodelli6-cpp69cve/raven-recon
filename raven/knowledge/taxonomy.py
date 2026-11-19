"""RAVEN Vulnerability Taxonomy — Foundation entries (Gates 25-26).

FOUNDATION knowledge only. 17 major families with structured entries.
Does NOT contain unrestricted autonomous exploit execution.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .schema import VulnerabilityKnowledge

# ─────────────────────────────────────────────────────────────────────────────
# Gate 25 — Major vulnerability families
# ─────────────────────────────────────────────────────────────────────────────

VULNERABILITY_FAMILIES: Dict[str, VulnerabilityKnowledge] = {}


def _add(entry: VulnerabilityKnowledge) -> None:
    """Register a knowledge entry. Validates schema and rejects duplicates."""
    entry.validate()
    if entry.knowledge_id in VULNERABILITY_FAMILIES:
        raise ValueError(f"Duplicate knowledge_id: {entry.knowledge_id!r}")
    VULNERABILITY_FAMILIES[entry.knowledge_id] = entry


# ── 1. IDOR / BOLA ───────────────────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "AC-001",
    name          = "Insecure Direct Object Reference (IDOR / BOLA)",
    family        = "Access Control",
    cwe           = "CWE-284",
    description   = (
        "A resource is accessible by substituting its identifier (ID, UUID, "
        "slug) in the request, without the server verifying that the requesting "
        "principal owns or is authorized to access that resource."
    ),
    preconditions = [
        "Endpoint accepts a user-controlled object reference (numeric ID, UUID, etc.)",
        "Server response differs between owned and unowned resources",
        "Attacker can enumerate or guess valid IDs of other users' resources",
    ],
    signals = [
        "Status 200 response to non-owner request where 403/404 expected",
        "PII or private data in response body for object owned by another user",
        "Same HTTP status code for own vs. other user's resource",
        "Lack of session/identity check in response headers",
    ],
    false_positive_explanations = [
        "Public resources intentionally accessible by any authenticated user",
        "Multi-tenant resources shared within the same organization/team",
        "Read-only public metadata endpoints (e.g., public profile, product info)",
        "Rate-limit or error page shown to all users regardless of identity",
        "Session expiry: 401 may look like access control but is authentication",
    ],
    safe_test_strategy = (
        "Create two controlled researcher-owned test accounts. "
        "From account A, create a resource and record its ID. "
        "From account B, attempt to access or modify the resource using its ID. "
        "Compare responses to baseline (A accessing own resource). "
        "Use only researcher-owned test data — never target real user objects."
    ),
    negative_controls = [
        "Access with unauthenticated session — should return 401/403",
        "Access a non-existent ID — should return 404, not another user's data",
        "Access own resource with correct session — should return 200 (baseline)",
        "Access expired/revoked session — should return 401",
    ],
    evidence_requirements = [
        "Baseline: authenticated owner access returns 200 with full resource",
        "Experiment: non-owner access returns 200 with the same resource data",
        "Differential: two sessions, two identities, same object ID",
        "Negative control: unauthenticated access denied",
    ],
    remediation_concepts = [
        "Server-side ownership check on every object access",
        "Use random UUIDs rather than sequential IDs to reduce enumeration",
        "Log and alert on access to resources not belonging to the requester",
        "Implement row-level security in the data layer",
    ],
    risk_class           = "LowRiskStateChange",
    required_capabilities= ["HttpRead", "ScopeRead"],
))

# ── 2. BFLA ──────────────────────────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "AC-002",
    name          = "Broken Function Level Authorization (BFLA)",
    family        = "Access Control",
    cwe           = "CWE-285",
    description   = (
        "A lower-privileged user can call administrative or privileged functions "
        "(endpoints) that should only be accessible to higher-privilege roles."
    ),
    preconditions = [
        "Application has multiple privilege levels (user, admin, superadmin)",
        "Administrative endpoints exist and are documented or discoverable",
        "Client-side role enforcement not mirrored server-side",
    ],
    signals = [
        "Admin endpoint responds 200 to non-admin credentials",
        "Successful admin action (creation, deletion, config change) from low-privilege session",
        "Presence of admin-only data in response from low-privilege session",
    ],
    false_positive_explanations = [
        "Endpoint is intentionally accessible to all authenticated users",
        "Action appears successful but side-effects are silently discarded server-side",
        "Debug/test endpoint enabled only in staging environment",
    ],
    safe_test_strategy = (
        "Use a researcher-controlled low-privilege test account. "
        "Identify admin-only endpoints from documentation or API discovery. "
        "Call them with the low-privilege session and observe responses. "
        "Only call read-only admin endpoints if possible to minimise side effects."
    ),
    negative_controls = [
        "Unauthenticated request to admin endpoint — should return 401/403",
        "Admin account accessing same endpoint — should succeed (establishes baseline)",
        "Low-privilege account accessing non-admin endpoint — should succeed",
    ],
    evidence_requirements = [
        "Confirmed admin-only endpoint via documentation or authoritative source",
        "Low-privilege session with known role",
        "200 response (or equivalent successful action) from low-privilege session",
        "Admin session baseline returning same 200",
    ],
    remediation_concepts = [
        "Server-side role/permission check on every function, not just at the UI layer",
        "Allowlist of capabilities per role",
        "Audit log for all privileged function invocations",
    ],
    risk_class           = "LowRiskStateChange",
    required_capabilities= ["HttpRead", "ScopeRead"],
))

# ── 3. Horizontal Authorization ───────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "AC-003",
    name          = "Horizontal Privilege Escalation",
    family        = "Access Control",
    cwe           = "CWE-639",
    description   = (
        "A user accesses another user's resources at the same privilege level "
        "by manipulating user-controlled identifiers without vertical escalation."
    ),
    preconditions = [
        "User-specific resources addressable by a user-controlled identifier",
        "No server-side binding of resource to requesting session identity",
    ],
    signals = [
        "Another user's private data returned in response",
        "Successful modification of another user's resource",
    ],
    false_positive_explanations = [
        "Shared team/organization resource",
        "Public profile or listing",
        "Admin feature that legitimately allows cross-user access",
    ],
    safe_test_strategy = (
        "Two researcher-controlled accounts. Account A creates resource. "
        "Account B accesses it. Compare with Account A baseline."
    ),
    negative_controls = [
        "Anonymous access denied",
        "Non-existent resource ID returns 404",
        "Access own resource succeeds (baseline)",
    ],
    evidence_requirements = [
        "Two distinct authenticated sessions",
        "Response from session B contains session A's private data",
        "Negative control (anonymous) denied",
    ],
    remediation_concepts = [
        "Bind resource to owner on creation; verify on every access",
        "Use opaque session-specific identifiers",
    ],
    risk_class           = "LowRiskStateChange",
    required_capabilities= ["HttpRead", "ScopeRead"],
))

# ── 4. Vertical Authorization ─────────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "AC-004",
    name          = "Vertical Privilege Escalation",
    family        = "Access Control",
    cwe           = "CWE-269",
    description   = (
        "A lower-privilege user gains the privileges of a higher-privilege role "
        "through manipulation of parameters, tokens, or API calls."
    ),
    preconditions = [
        "Role or privilege encoded in client-controlled parameter",
        "No server-side validation of privilege escalation path",
    ],
    signals = [
        "Role parameter accepted and reflected in server-side behavior",
        "Access to admin functionality after parameter manipulation",
    ],
    false_positive_explanations = [
        "Role change requires additional server-side validation step not tested",
        "Parameter accepted but silently ignored server-side",
    ],
    safe_test_strategy = (
        "Attempt to modify role/privilege parameters in requests. "
        "Observe whether server-side state changes. "
        "Do not perform destructive administrative actions."
    ),
    negative_controls = [
        "Without parameter manipulation: low-privilege behaviour confirmed",
        "Unauthenticated role escalation attempt: denied",
    ],
    evidence_requirements = [
        "Before: confirmed low-privilege session",
        "After: confirmed elevated privilege in server response",
        "Negative control shows low privilege without manipulation",
    ],
    remediation_concepts = [
        "Server-side role management only, never trust client-supplied role",
        "Separate session token from role claims; verify role from database",
    ],
    risk_class           = "Sensitive",
    required_capabilities= ["HttpRead", "ScopeRead"],
))

# ── 5. Authentication ─────────────────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "AUTH-001",
    name          = "Authentication Bypass",
    family        = "Authentication",
    cwe           = "CWE-287",
    description   = "Authentication mechanism can be bypassed to access protected resources.",
    preconditions = [
        "Protected resource exists",
        "Authentication bypass vector exists (token forgery, null byte, etc.)",
    ],
    signals = [
        "Protected resource accessible without valid credentials",
        "Authentication error skipped via request manipulation",
    ],
    false_positive_explanations = [
        "Resource is intentionally public",
        "IP allowlist or other control grants access",
    ],
    safe_test_strategy = (
        "Attempt access to a known protected endpoint without valid credentials "
        "using documented bypass patterns. Only use researcher-controlled accounts."
    ),
    negative_controls = [
        "Valid credentials return 200 (baseline)",
        "Clearly invalid credentials return 401",
    ],
    evidence_requirements = [
        "Confirmed protected endpoint",
        "Access without valid credentials returns 200 or equivalent",
    ],
    remediation_concepts = [
        "Server-side authentication on every protected endpoint",
        "Use battle-tested authentication libraries",
    ],
    risk_class="LowRiskStateChange", required_capabilities=["HttpRead", "ScopeRead"],
))

# ── 6. Session Management ─────────────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "SESS-001",
    name          = "Weak Session Management",
    family        = "Session Management",
    cwe           = "CWE-613",
    description   = "Session tokens are predictable, insufficiently invalidated, or improperly scoped.",
    preconditions = [
        "Application uses session tokens",
        "Token lifecycle management is defective",
    ],
    signals = [
        "Session token persists after explicit logout",
        "Session tokens are sequential or predictable",
        "Concurrent sessions not bounded",
    ],
    false_positive_explanations = [
        "Token revocation uses eventual consistency with short lag",
        "Persistent login feature is intentional",
    ],
    safe_test_strategy = (
        "After logout, attempt to reuse the previous session token. "
        "Observe whether the server honours the revoked token. "
        "Use researcher-owned sessions only."
    ),
    negative_controls = [
        "New session after login: confirmed valid",
        "Never-issued token: denied with 401",
    ],
    evidence_requirements = [
        "Token revoked via logout action",
        "Subsequent request with revoked token returns 200 (not 401)",
    ],
    remediation_concepts = [
        "Invalidate tokens server-side on logout",
        "Rotate tokens on privilege change",
        "Use cryptographically random token generation",
    ],
    risk_class="LowRiskStateChange", required_capabilities=["HttpRead", "ScopeRead"],
))

# ── 7. XSS ────────────────────────────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "XSS-001",
    name          = "Cross-Site Scripting (XSS)",
    family        = "XSS",
    cwe           = "CWE-79",
    description   = (
        "User-controlled input is reflected in an HTML/JS context without "
        "proper encoding, allowing script injection."
    ),
    preconditions = [
        "User input reflected in HTML response",
        "Input not escaped/encoded in the output context",
        "Browser interprets reflected content as code",
    ],
    signals = [
        "Input reflected verbatim in HTML response",
        "HTML special chars < > \" ' not encoded in output",
        "script or event handler attributes accepted",
    ],
    false_positive_explanations = [
        "Reflection is in a comment or non-executable context",
        "CSP blocks script execution even if reflected",
        "Input is in attribute but properly quoted",
    ],
    safe_test_strategy = (
        "Inject a unique non-executing probe string (e.g. <RAVEN-PROBE-ID>) "
        "and check if it appears unencoded in the response body. "
        "Do NOT inject actual alert() or script payloads in the primary test. "
        "Use researcher-owned sessions and data only."
    ),
    negative_controls = [
        "Inject inert probe: if encoded, reflected XSS is not present",
        "Inject in a different parameter: confirms parameter-specific behavior",
    ],
    evidence_requirements = [
        "Probe string reflected unencoded in HTML response",
        "HTML context allows script execution (not just data context)",
        "CSP absent or bypassable",
    ],
    remediation_concepts = [
        "Context-sensitive output encoding (HTML, JS, URL, CSS contexts)",
        "Content Security Policy",
        "Use templating engines with auto-escaping",
    ],
    risk_class="LowRiskStateChange", required_capabilities=["HttpRead", "ScopeRead"],
))

# ── 8. CSRF ────────────────────────────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "CSRF-001",
    name          = "Cross-Site Request Forgery (CSRF)",
    family        = "CSRF",
    cwe           = "CWE-352",
    description   = "State-changing requests can be triggered cross-origin without a CSRF token.",
    preconditions = [
        "State-changing endpoint exists",
        "Endpoint relies on cookies for authentication",
        "No CSRF token or SameSite cookie attribute",
    ],
    signals = [
        "Missing CSRF token in state-changing requests",
        "SameSite=None or missing SameSite attribute on session cookie",
        "CORS allows credentials from arbitrary origins",
    ],
    false_positive_explanations = [
        "Endpoint requires a body parameter not available cross-origin",
        "SameSite=Lax/Strict provides sufficient protection for GET vs POST",
        "Custom request header required (e.g. X-Requested-With)",
    ],
    safe_test_strategy = (
        "Replay the state-changing request with modified Origin/Referer headers "
        "using a researcher-owned session. "
        "Do not perform irreversible actions."
    ),
    negative_controls = [
        "Request with correct CSRF token succeeds",
        "Request with invalid CSRF token is rejected",
    ],
    evidence_requirements = [
        "State-changing request without CSRF token accepted",
        "Session cookie present and used for authentication",
    ],
    remediation_concepts = [
        "Per-session CSRF tokens",
        "SameSite=Strict or Lax cookie attribute",
        "Double-submit cookie pattern",
    ],
    risk_class="LowRiskStateChange", required_capabilities=["HttpRead", "ScopeRead"],
))

# ── 9. SSRF ────────────────────────────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "SSRF-001",
    name          = "Server-Side Request Forgery (SSRF)",
    family        = "SSRF",
    cwe           = "CWE-918",
    description   = "Server fetches a URL supplied by the client, allowing access to internal resources.",
    preconditions = [
        "Endpoint accepts a URL or hostname as input",
        "Server performs HTTP/DNS lookup using that input",
        "No URL allowlist or DNS pinning",
    ],
    signals = [
        "Out-of-band DNS/HTTP interaction with callback token embedded in URL",
        "Response contains internal service data (e.g. cloud metadata)",
        "Different response for internal vs. external URL",
    ],
    false_positive_explanations = [
        "Webhook endpoint that is legitimately user-configurable",
        "URL fetched but result is not returned to user",
        "Internal service returns no data (SSRF blind)",
    ],
    safe_test_strategy = (
        "Supply a researcher-controlled loopback or callback URL as input. "
        "Use the Safe Callback Collector to detect out-of-band interactions. "
        "Never target cloud metadata or production internal services."
    ),
    negative_controls = [
        "Allowlisted external URL accepted (establishes baseline)",
        "Non-URL input returns error",
    ],
    evidence_requirements = [
        "Callback token received at researcher-controlled collector",
        "DNS interaction confirms server performed lookup",
    ],
    remediation_concepts = [
        "URL allowlist (not blocklist)",
        "Bind outbound requests to egress proxy with access controls",
        "Disable redirects",
    ],
    risk_class="LowRiskStateChange", required_capabilities=["HttpRead", "CallbackCollector"],
))

# ── 10. Injection ──────────────────────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "INJ-001",
    name          = "SQL Injection",
    family        = "Injection",
    cwe           = "CWE-89",
    description   = "User-supplied input is interpolated into SQL queries without sanitization.",
    preconditions = [
        "Endpoint accepts input incorporated into a database query",
        "Input not parameterized or sanitized",
    ],
    signals = [
        "SQL error message in response",
        "Boolean-based response differences (true vs. false condition)",
        "Time-based delays with sleep/waitfor payloads",
        "Different row counts for true/false conditions",
    ],
    false_positive_explanations = [
        "Error message from application layer, not database",
        "Timing difference due to network/server load, not SQL evaluation",
        "Parameterized query on backend despite suspicious error message display",
    ],
    safe_test_strategy = (
        "Use minimal safe probes: a single quote to test error mode, "
        "or a tautology/contradiction pair (1=1 vs 1=2) to test boolean mode. "
        "Avoid time-based payloads initially. Never use UNION-based extraction "
        "or destructive statements."
    ),
    negative_controls = [
        "Safe string input returns normal response (no error, no delay)",
        "Numeric input without special chars returns expected result",
    ],
    evidence_requirements = [
        "Boolean differential: 1=1 returns different response than 1=2",
        "Or: SQL error in response with database fingerprint",
    ],
    remediation_concepts = [
        "Parameterized queries / prepared statements",
        "ORM with query abstraction",
        "Least-privilege database account",
    ],
    risk_class="LowRiskStateChange", required_capabilities=["HttpRead", "ScopeRead"],
))

# ── 11. Path Traversal ─────────────────────────────────────────────────────────
_add(VulnerabilityKnowledge(
    knowledge_id  = "PATH-001",
    name          = "Path Traversal",
    family        = "Path Traversal",
    cwe           = "CWE-22",
    description   = "User-controlled path component allows reading/writing files outside intended directory.",
    preconditions = [
        "Endpoint accepts a filename or path parameter",
        "Server reads/writes file using that parameter without sanitization",
    ],
    signals = [
        "Server reads a file at a path containing ../ sequences",
        "Different content returned for traversal path vs. safe path",
        "Internal files (e.g. /etc/passwd on Linux, win.ini on Windows) returned",
    ],
    false_positive_explanations = [
        "../ sequences sanitized by server before use",
        "Chroot or jail limits accessible files",
        "Response is the same for all path values (hardcoded response)",
    ],
    safe_test_strategy = (
        "Test with ../test-raven-probe as a filename. "
        "Check if error messages reveal path information. "
        "Target only researcher-controlled or known-safe paths."
    ),
    negative_controls = [
        "Safe filename returns expected file content (baseline)",
        "Non-existent filename returns 404",
    ],
    evidence_requirements = [
        "Server returns content of a file outside the intended directory",
        "Path traversal sequence present in successful request",
    ],
    remediation_concepts = [
        "Resolve canonical path and verify it starts with the intended base",
        "Allowlist of permitted file names or extensions",
    ],
    risk_class="LowRiskStateChange", required_capabilities=["HttpRead", "ScopeRead"],
))

# ── 12–17: Remaining families (condensed) ─────────────────────────────────────

for kid, name, family, cwe, desc in [
    ("BL-001",   "Business Logic Vulnerability",    "Business Logic",    "CWE-840",
     "Application logic can be manipulated to produce unintended outcomes (price manipulation, workflow bypass)."),
    ("RACE-001", "Race Condition",                  "Race Conditions",   "CWE-362",
     "Concurrent requests exploit TOCTOU windows to produce unintended state changes."),
    ("CACHE-001","Cache Poisoning",                 "Caching",           "CWE-444",
     "Attacker injects malicious content into a shared cache to serve to other users."),
    ("CORS-001", "CORS Misconfiguration",           "CORS",              "CWE-942",
     "Overly permissive CORS policy allows cross-origin access to authenticated endpoints."),
    ("INFO-001", "Sensitive Information Disclosure","Information Disclosure","CWE-200",
     "Application reveals sensitive internal information (stack traces, credentials, PII) in responses."),
    ("API-001",  "API Security Misconfiguration",   "API Security",      "CWE-16",
     "API endpoints lack proper authentication, rate limiting, or input validation."),
    ("GQL-001",  "GraphQL Security Issue",          "GraphQL",           "CWE-285",
     "GraphQL endpoint exposes excessive data, allows introspection in production, or lacks query depth limits."),
    ("WS-001",   "WebSocket Security Issue",        "WebSocket",         "CWE-285",
     "WebSocket endpoint lacks authentication, lacks CSRF protection, or processes hostile messages unsafely."),
    ("FILE-001", "Unrestricted File Upload",        "File Handling",     "CWE-434",
     "Server accepts and processes uploaded files of unrestricted type, enabling code execution or stored XSS."),
]:
    _add(VulnerabilityKnowledge(
        knowledge_id   = kid,
        name           = name,
        family         = family,
        cwe            = cwe,
        description    = desc,
        preconditions  = ["Target endpoint exists and accepts relevant input"],
        signals        = ["Response differs from baseline in a manner consistent with the vulnerability"],
        false_positive_explanations = ["Intentional application behaviour", "Mitigating control elsewhere in the stack"],
        safe_test_strategy = "Use researcher-controlled test data. Do not perform irreversible actions.",
        negative_controls  = ["Safe input returns expected response"],
        evidence_requirements = ["Differential response between probe and control", "Negative control confirmed"],
        remediation_concepts  = ["Implement appropriate server-side validation and access controls"],
        risk_class            = "LowRiskStateChange",
        required_capabilities = ["HttpRead", "ScopeRead"],
    ))


def get_entry(knowledge_id: str) -> VulnerabilityKnowledge:
    return VULNERABILITY_FAMILIES[knowledge_id]


def list_families() -> list:
    return sorted({e.family for e in VULNERABILITY_FAMILIES.values()})
