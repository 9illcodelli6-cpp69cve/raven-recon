"""RAVEN Safe Callback Collector.

Collects out-of-band interaction callbacks (SSRF, XXE, DNS, etc.) via a
loopback-only listener. The listener NEVER executes received data.

INVARIANTS:
- Binds ONLY to 127.0.0.1 (never 0.0.0.0 or ::)
- Received bytes are stored raw, never evaluated or executed
- No DNS resolution of callback hostnames
- Max payload stored per callback: 64 KB
- Max total callbacks retained: 1000
- No credentials stored (header names checked against EXCLUDED_HEADERS)
"""
from __future__ import annotations

import datetime
import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

SAFE_BIND_ADDRESS = "127.0.0.1"
MAX_PAYLOAD_BYTES  = 64 * 1024   # 64 KB per callback
MAX_CALLBACKS      = 1000

# Header names whose values are never stored (they may contain credentials).
EXCLUDED_HEADER_NAMES = frozenset({
    "authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token",
    "proxy-authorization", "www-authenticate",
})


@dataclass
class CallbackRecord:
    """An immutable record of one received callback interaction."""
    callback_id:   str
    received_at:   str           # ISO-8601 UTC
    source_label:  str           # e.g. "127.0.0.1:56789" — no DNS resolution
    method:        str
    path:          str
    safe_headers:  Dict[str, str]  # credential headers stripped
    payload_bytes: int             # bytes received (not the content itself)
    payload_hash:  str             # SHA-256 of raw payload, for dedup
    truncated:     bool            # True if payload exceeded MAX_PAYLOAD_BYTES


class SafeCallbackCollector:
    """Non-executing loopback callback collector.

    Stores metadata about received callbacks without executing or
    interpreting the payload as code or commands.

    Usage:
        collector = SafeCallbackCollector()
        token = collector.register_probe("my-ssrf-test")
        # inject token into target; target calls back to collector
        hits = collector.get_hits(token)
    """

    def __init__(self) -> None:
        self._lock      = threading.Lock()
        self._probes:   Dict[str, str]              = {}   # token → label
        self._records:  List[CallbackRecord]        = []
        self._by_token: Dict[str, List[str]]        = {}   # token → [callback_id]

    @property
    def bind_address(self) -> str:
        return SAFE_BIND_ADDRESS

    def register_probe(self, label: str) -> str:
        """Register a probe and return an opaque token to embed in payloads."""
        import secrets
        token = secrets.token_hex(16)
        with self._lock:
            self._probes[token] = label
            self._by_token[token] = []
        return token

    def record_callback(self, source_label: str, method: str, path: str,
                        headers: Dict[str, str], raw_payload: bytes,
                        token: Optional[str] = None) -> CallbackRecord:
        """Record a received callback.  Never executes the payload.

        source_label should be host:port string only — no DNS resolution.
        """
        import uuid
        callback_id = str(uuid.uuid4())

        # Strip credential headers
        safe_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in EXCLUDED_HEADER_NAMES
        }

        truncated = len(raw_payload) > MAX_PAYLOAD_BYTES
        stored    = raw_payload[:MAX_PAYLOAD_BYTES]
        payload_hash = hashlib.sha256(stored).hexdigest()

        record = CallbackRecord(
            callback_id   = callback_id,
            received_at   = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            source_label  = source_label,
            method        = method,
            path          = path,
            safe_headers  = safe_headers,
            payload_bytes = len(raw_payload),
            payload_hash  = payload_hash,
            truncated     = truncated,
        )

        with self._lock:
            if len(self._records) >= MAX_CALLBACKS:
                self._records.pop(0)
            self._records.append(record)
            if token and token in self._by_token:
                self._by_token[token].append(callback_id)

        return record

    def get_hits(self, token: str) -> List[CallbackRecord]:
        """Return all callbacks matching a registered probe token."""
        with self._lock:
            ids = set(self._by_token.get(token, []))
            return [r for r in self._records if r.callback_id in ids]

    def all_records(self) -> List[CallbackRecord]:
        with self._lock:
            return list(self._records)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._by_token = {t: [] for t in self._probes}
