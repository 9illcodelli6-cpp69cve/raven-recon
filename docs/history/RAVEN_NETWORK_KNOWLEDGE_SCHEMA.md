# RAVEN Network Knowledge Schema

**Module:** `raven/knowledge/network_fundamentals.py`  
**Status:** Complete  
**Parts:** 18 (Parts 1–18)

---

## Overview

The network knowledge module provides structured, versioned knowledge entries
about normal network and HTTP behavior. These are reference descriptions,
not executable code and not security verdicts.

Each entry has:
- **Part key** (`KnowledgePart` enum value)
- **Title**
- **Summary** — 2-4 sentence description of the concept
- **Key concepts** — bulleted facts about this area
- **Non-vulnerability reminders** — explicit statements about what this class of observation does NOT imply
- **Related parts** — links to adjacent knowledge areas

---

## `KnowledgeEntry` Structure

```python
@dataclass
class KnowledgeEntry:
    part: KnowledgePart          # enum key
    title: str                   # human-readable title
    summary: str                 # 2-4 sentence description
    key_concepts: list[str]      # factual bullets
    non_vulnerability_reminders: list[str]  # explicit NOT-vulnerabilities
    related_parts: list[str]     # cross-references
```

---

## Knowledge Parts Index

| Part | Title | Key non-vulnerability reminder |
|------|-------|-------------------------------|
| PART_1_OSI | OSI and TCP/IP Layering | Packet at a given layer is normal — not a vulnerability |
| PART_2_TCP_IP | TCP/IP Fundamentals | Open port != vulnerability; context required |
| PART_3_DNS | DNS — Domain Name System | DNS resolution failure is a network observation, not an attack |
| PART_4_TLS | TLS — Transport Layer Security | DO NOT DISABLE TLS VALIDATION |
| PART_5_HTTP_PROTOCOL | HTTP/1.1, HTTP/2, HTTP/3 | HTTP/2 or HTTP/3 usage is not an anomaly |
| PART_6_HTTP_METHODS | HTTP Methods and Semantics | 405 Method Not Allowed is a server policy, not a vulnerability |
| PART_7_HTTP_STATUS | HTTP Status Codes | 200 is NORMAL_SUCCESS; 500 requires demonstrated impact |
| PART_8_HTTP_HEADERS | HTTP Headers | Authorization header presence is normal; Set-Cookie is normal |
| PART_9_URL | URL Structure and Parsing | URL normalization difference is observation — not path traversal |
| PART_10_COOKIES | Cookies — Attributes | Cookie name/value presence is not session hijack evidence |
| PART_11_SESSIONS | Sessions — State Management | Session rotation is expected behavior — not an anomaly |
| PART_12_AUTH_SCHEMES | Authentication Schemes | Bearer token is normal authenticated request |
| PART_13_API_PATTERNS | REST API Design Patterns | CRUD operations on known APIs are normal behavior |
| PART_14_CACHING | HTTP Caching | Cache miss/hit difference is normal — not a vulnerability |
| PART_15_CORS | CORS | CORS header presence requires browser semantics — not auto-vuln |
| PART_16_RESPONSE_DIFF | Response Difference Taxonomy | Difference requires context — not a finding |
| PART_17_STATE_MACHINES | HTTP State Machines and Flows | Post-login session rotation is correct behavior |
| PART_18_NORMAL_BASELINES | Normal Baselines | All 2xx responses need endpoint context |

---

## API

```python
from raven.knowledge.network_fundamentals import (
    NETWORK_KNOWLEDGE,    # dict: part_key → KnowledgeEntry
    get_knowledge,        # (part: str) → KnowledgeEntry | None
    list_parts,           # () → list[str]
    get_non_vulnerability_reminders,  # () → list[str] (all parts aggregated)
    KnowledgePart,        # enum of all 18 part keys
)
```

---

## Invariants

- No executable exploit code in any entry.
- No network I/O.
- `is_security_relevant` never set True by this module.
- Knowledge entries are reference material — they inform feature interpretation
  and non-vulnerability filtering, but do not make security decisions.
- TLS part explicitly includes: `DO NOT DISABLE TLS VALIDATION`
