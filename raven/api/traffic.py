"""Canonical Traffic projection — the ONE read model the Traffic UI consumes.

RAVEN has exactly one traffic/observation model: the ``observations`` table in
each per-workspace ``recon.db``, written by
``CanonicalService.record_send_result`` on BOTH manual/Browser sends AND recon
probes (see raven/canonical_service.py). This module does NOT introduce a second
store or a second HTTP client — it only *projects* an already-persisted
``observations`` row into a thin, UI-facing ``TrafficEntry`` DTO.

Metadata only. The canonical store deliberately keeps a response-body hash +
length, never the body (canonical_service.py:121-122). A ``TrafficEntry`` carries
method/url/status/timestamp and hash+length fields only — never request or
response bodies, and never request/response headers. Durable bodies do not exist;
full-body replay history lives client-side in the Browser page for the session.

Authority: reconstruction/BROWSER_TRAFFIC_ARCHITECTURE.md §3.3.
``GET /api/v7/traffic`` returns ``{entries: [TrafficEntry], total, workspace_id}``.
``GET /api/observations`` keeps returning the raw rows under ``observations``;
this is the thin projection over the SAME ``store.get_observations`` — one store,
two read shapes, not two stores.

Stdlib-only; pure (no network, no DB access of its own — the caller supplies
already-fetched rows).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass


def _as_int(value):
    """Coerce a stored SQLite value to int, or None when absent/unparseable.

    ``status`` may legitimately be NULL (exchange never completed); integer
    columns such as the body lengths default to 0 in the schema.
    """
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class TrafficEntry:
    """Projection of one ``observations`` row for UI/consumer reads.

    Metadata only — no request/response body, no headers. Fields mirror
    BROWSER_TRAFFIC_ARCHITECTURE.md §3.3. A ``TrafficEntry`` is produced from a
    row written by the single canonical writer, so a Browser send, a recon probe
    and a manual send all project through this identical shape; the
    ``identity_label`` field is what distinguishes the producer.
    """

    entry_id: str | None          # observations.id
    workspace_id: str | None
    url: str | None
    method: str | None
    status: int | None            # nullable when the exchange never completed
    identity_label: str | None    # "browser" | "manual" | "probe" | program label
    acquisition_mode: str | None  # "collect" | "baseline_acquisition" | ...
    source_engine: str | None     # "RAVEN"
    elapsed_ms: int | None
    request_body_len: int | None
    response_body_len: int | None
    response_body_hash: str | None  # integrity handle; the body itself is NOT stored
    is_probe: bool
    is_anomalous: bool
    timestamp: str | None         # ISO-8601 string, exactly as stored

    @classmethod
    def from_observation(cls, row: dict) -> "TrafficEntry":
        """Project a single ``observations`` row (dict) into a TrafficEntry.

        Tolerates partial rows: any missing column projects to None/0/False so a
        malformed or legacy row never raises here and stalls the Traffic tab.
        """
        row = row or {}
        return cls(
            entry_id=row.get("id"),
            workspace_id=row.get("workspace_id"),
            url=row.get("url"),
            method=row.get("method"),
            status=_as_int(row.get("status")),
            identity_label=row.get("identity_label"),
            acquisition_mode=row.get("acquisition_mode"),
            source_engine=row.get("source_engine"),
            elapsed_ms=_as_int(row.get("elapsed_ms")),
            request_body_len=_as_int(row.get("request_body_len")),
            response_body_len=_as_int(row.get("response_body_len")),
            response_body_hash=row.get("response_body_hash"),
            is_probe=bool(row.get("is_probe")),
            is_anomalous=bool(row.get("is_anomalous")),
            timestamp=row.get("timestamp"),
        )

    def to_dict(self) -> dict:
        return asdict(self)


def project_observations(rows) -> list:
    """Project a list of ``observations`` rows into TrafficEntry dicts."""
    return [TrafficEntry.from_observation(r).to_dict() for r in (rows or [])]


def build_traffic_response(rows, workspace_id) -> dict:
    """Build the ``GET /api/v7/traffic`` envelope.

    Returns ``{entries, total, workspace_id}`` — the key the UI reads (``entries``)
    — over the canonical observations rows the caller fetched. ``total`` is the
    count of projected entries in this page.
    """
    entries = project_observations(rows)
    return {"entries": entries, "total": len(entries), "workspace_id": workspace_id}
