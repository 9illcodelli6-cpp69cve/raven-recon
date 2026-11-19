# RAVEN V6 — Network Security

## Outbound Request Policy

All outbound requests go through PolicyGate:
- HTTP_READ: requires capability + in-scope destination
- HTTP_STATE_CHANGE: requires capability + in-scope + researcher approval
- Destructive/Exfiltrative: ALWAYS DENIED
- Loopback destinations not in approved scope: DENIED (SSRF defense)

## Inbound Listener Policy

- Callback collector binds ONLY to 127.0.0.1 (never 0.0.0.0 or ::)
- No production internet-exposed listeners
- No reverse shell listeners
- No listeners on arbitrary port from target-controlled data

## Safe Lab Network Containment (verified)

Gate 17 runtime tests confirm:
- LAB_LOCAL_ONLY: loopback allowed, external denied
- LAB_OFF: all denied including loopback
- Malformed URLs denied before connection attempt
- Redirect to external destination denied
- validate_external_request() raises PermissionError for denied destinations

## IPC

**NETWORK TRANSPORT ENCRYPTION: NOT APPLICABLE**

Rationale: No TCP control transport exists between RAVEN components.
Future Rust-Python communication would use in-process FFI or Windows named pipes
with OS ACL protection — not a TCP socket. No custom crypto invented.

## Scope Enforcement

PolicyGate enforces scope:
- Exact host match: `example.com` permits `example.com`
- Subdomain match: `api.example.com` permitted if `example.com` in scope
- Out-of-scope destinations denied regardless of ML signal
