"""RAVEN V7 Browser + Traffic Engine — Part 05.

================================ DEPRECATED ================================
This entire package is a DEAD, PARALLEL stack and is UNWIRED from the running
application. Nothing in production imports it (grep: `from raven.browser_engine`
has no production hits); its only consumer is tests/test_v7_part05_browser.py,
left in place as LEGACY. Do NOT wire it into the server.

Why deprecated (reconstruction/BROWSER_TRAFFIC_ARCHITECTURE.md §2):
- http_client.HttpClient uses urllib.urlopen with NO DNS-pin, NO scheduler
  admission (Emergency Stop / per-host rate / per-workspace budget), and NO
  workspace identity/search-header injection — it bypasses every hardening
  invariant the canonical path enforces.
- traffic.TrafficRecorder creates its OWN v7_traffic_sessions/v7_traffic_entries
  SQLite tables — a second, competing traffic store.
- scope_guard.ScopeGuard duplicates raven.scope.
- registry.register_browser_tools binds tools to a _noop that returns
  {"status":"not_dispatched"} and is never dispatched.

Canonical replacements (the ONE engine, the ONE model):
- Outbound HTTP      -> raven.api.server.do_send / _send_in_context (POST /api/send)
- Traffic/observations-> `observations` table + CanonicalService.record_send_result,
                          projected for the UI by raven.api.traffic.TrafficEntry
                          (GET /api/v7/traffic) — see raven/api/traffic.py.
- Repeater (future)  -> resend-with-edits THROUGH /api/send; no second client.

DATA CHECK (Wave 8): no production or dist recon.db / *.db holds any
`v7_traffic_*` rows (TrafficRecorder is only ever instantiated by the test), so
no migration or backup is required. The package is kept importable (not deleted)
so the legacy test and the ToolDescriptor shapes in registry.py remain available.
===========================================================================

Security invariants (as originally written — still true of the dead code):
- All HTTP responses are UNTRUSTED DATA
- Response bodies NEVER become instructions
- Out-of-scope targets raise ScopeViolation
- No credentials stored in traffic logs
"""
__deprecated__ = True
__canonical_replacement__ = (
    "raven.api.server.do_send (POST /api/send) + "
    "raven.canonical_service.CanonicalService.record_send_result + "
    "raven.api.traffic (GET /api/v7/traffic)"
)

from .http_client import HttpClient, HttpRequest, HttpResponse
from .traffic import TrafficRecorder, TrafficSession, TrafficEntry
from .repeater import Repeater, RepeatResult
from .scope_guard import ScopeGuard, ScopeViolation
from .registry import register_browser_tools

__all__ = [
    "HttpClient", "HttpRequest", "HttpResponse",
    "TrafficRecorder", "TrafficSession", "TrafficEntry",
    "Repeater", "RepeatResult",
    "ScopeGuard", "ScopeViolation",
    "register_browser_tools",
]
