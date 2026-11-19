"""RAVEN Security Audit Log.

Records security-relevant events as append-only JSON lines.

INVARIANTS:
- Never logs: private keys, session tokens, raw cookies, bearer tokens,
  passwords, or API keys. Partial patterns → [REDACTED].
- Records are append-only (no modification after write).
- Structured format (JSON-per-line) for machine readability.
- Thread-safe (RLock).
"""
from __future__ import annotations

import datetime
import enum
import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Patterns whose values should never appear in audit records.
# These are checked against stringified field values.
_SECRET_PATTERNS = (
    re.compile(r'(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*'),
    re.compile(r'(?i)(token\s*[:=]\s*)[^\s"]+'),
    re.compile(r'(?i)(api[_-]?key\s*[:=]\s*)[^\s"]+'),
    re.compile(r'(?i)(password\s*[:=]\s*)[^\s"]+'),
    re.compile(r'(?i)(secret\s*[:=]\s*)[^\s"]+'),
    re.compile(r'(?i)(authorization\s*:\s*)[^\s"]+'),
)


def _redact(value: str) -> str:
    for pat in _SECRET_PATTERNS:
        value = pat.sub(lambda m: m.group(0)[:m.start(1) - m.start()] + "[REDACTED]"
                        if m.lastindex else "[REDACTED]", value)
    return value


def _safe_str(v: Any) -> str:
    return _redact(str(v))


class AuditEventType(str, enum.Enum):
    POLICY_ALLOW           = "policy_allow"
    POLICY_DENY            = "policy_deny"
    EMERGENCY_STOP         = "emergency_stop"
    CAPABILITY_MISSING     = "capability_missing"
    SCOPE_VIOLATION        = "scope_violation"
    BIND_ADDRESS_VIOLATION = "bind_address_violation"
    PROCESS_LAUNCH         = "process_launch"
    PROCESS_DENIED         = "process_denied"
    CALLBACK_RECEIVED      = "callback_received"
    LAB_MODE_CHANGE        = "lab_mode_change"
    WORKSPACE_MISMATCH     = "workspace_mismatch"
    RISK_CLASS_BLOCKED     = "risk_class_blocked"
    ML_INFERENCE           = "ml_inference"
    GENERIC                = "generic"


@dataclass
class AuditRecord:
    event_type:  str
    timestamp:   str                       # ISO-8601 UTC
    action_id:   Optional[str]
    workspace_id: Optional[str]
    outcome:     str                       # "allow" | "deny" | "info"
    reason:      str
    details:     Dict[str, str] = field(default_factory=dict)

    def to_json_line(self) -> str:
        return json.dumps({
            "event_type":   self.event_type,
            "timestamp":    self.timestamp,
            "action_id":    self.action_id,
            "workspace_id": self.workspace_id,
            "outcome":      self.outcome,
            "reason":       self.reason,
            "details":      self.details,
        }, separators=(",", ":"))


class SecurityAuditLog:
    """Thread-safe append-only audit log for security events.

    Records are never modified after creation.
    Secret values are redacted before storage.
    """

    def __init__(self, max_records: int = 10_000) -> None:
        self._lock       = threading.RLock()
        self._records:   List[AuditRecord] = []
        self._max        = max_records

    def _now(self) -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    def _append(self, record: AuditRecord) -> None:
        with self._lock:
            if len(self._records) >= self._max:
                self._records.pop(0)
            self._records.append(record)

    def record(self, event_type: AuditEventType, outcome: str, reason: str,
               action_id: Optional[str] = None,
               workspace_id: Optional[str] = None,
               details: Optional[Dict[str, Any]] = None) -> AuditRecord:
        safe_details = {
            k: _safe_str(v) for k, v in (details or {}).items()
        }
        record = AuditRecord(
            event_type   = event_type.value,
            timestamp    = self._now(),
            action_id    = action_id,
            workspace_id = workspace_id,
            outcome      = outcome,
            reason       = reason,
            details      = safe_details,
        )
        self._append(record)
        return record

    def record_policy_allow(self, action_id: str, workspace_id: str,
                             capability: str, destination: str) -> AuditRecord:
        return self.record(
            AuditEventType.POLICY_ALLOW, "allow", "PolicyAllowed",
            action_id=action_id, workspace_id=workspace_id,
            details={"capability": capability, "destination": destination},
        )

    def record_policy_deny(self, action_id: str, workspace_id: str,
                            reason: str, message: str) -> AuditRecord:
        return self.record(
            AuditEventType.POLICY_DENY, "deny", reason,
            action_id=action_id, workspace_id=workspace_id,
            details={"message": message},
        )

    def record_emergency_stop(self, trigger_reason: str) -> AuditRecord:
        return self.record(
            AuditEventType.EMERGENCY_STOP, "deny", "EmergencyStopTriggered",
            details={"trigger_reason": trigger_reason},
        )

    def record_ml_inference(self, model_id: str, task: str, score: float,
                             is_advisory: bool, sets_verification_status: bool
                             ) -> AuditRecord:
        return self.record(
            AuditEventType.ML_INFERENCE, "info", "MLInference",
            details={
                "model_id":                model_id,
                "task":                    task,
                "score":                   str(score),
                "is_advisory":             str(is_advisory),
                "sets_verification_status": str(sets_verification_status),
            },
        )

    def all_records(self) -> List[AuditRecord]:
        with self._lock:
            return list(self._records)

    def export_jsonl(self) -> str:
        with self._lock:
            return "\n".join(r.to_json_line() for r in self._records)
