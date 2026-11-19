"""Single source of truth for the RAVEN UI <-> server wire contracts.

Wave 14 (A14-FRONTEND). This module names, per endpoint, the exact response
key set that `raven/api/server.py` emits AND that `web/index.html` is allowed to
read. It exists so the two sides cannot drift silently: the contract tests
(`tests/test_api_contracts.py`) assert that

  1. server handlers produce the keys declared here, and
  2. every field the UI reads (`tests/contracts/ui_field_map.json`) resolves to a
     key declared here.

Historically there was no shared schema — every `fetch()` hand-matched field
names, so a renamed key (``entries`` vs ``requests``, ``shells`` vs
``available_shells``, ``proxy.active`` vs ``proxy_active``) left a pane silently
empty until someone noticed. The audit's D1-D8 defects were all this class of
bug. These declarations turn such a drift into a failing test.

This is a declarative schema only — importing it has no side effects and it does
not reach into the runtime. Handlers MAY import the status vocabulary; they are
not required to build their dicts from here (the golden tests already freeze the
exact shapes), so the contract test reads the handlers' output rather than
forcing a construction style.

Status vocabulary (honest; no fake green "Ready"):
  READY        subsystem live, contract satisfied
  DEGRADED     reachable but partial (e.g. provider up, no model)
  UNAVAILABLE  subsystem not present / offline
  DISABLED     intentionally off (e.g. optional external provider off)
  BROKEN       a contract/internal error was surfaced (never a silent empty)
  LOADING      a fetch is in flight / no value yet
  DENIED       scope / policy blocked the action
  EMPTY        a successful read with no rows (honest empty state)
"""

# ── Honest status vocabulary ─────────────────────────────────────────────────
STATUS_READY = "READY"
STATUS_DEGRADED = "DEGRADED"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_DISABLED = "DISABLED"
STATUS_BROKEN = "BROKEN"
STATUS_LOADING = "LOADING"
STATUS_DENIED = "DENIED"
STATUS_EMPTY = "EMPTY"

STATUS_VOCABULARY = frozenset({
    STATUS_READY, STATUS_DEGRADED, STATUS_UNAVAILABLE, STATUS_DISABLED,
    STATUS_BROKEN, STATUS_LOADING, STATUS_DENIED, STATUS_EMPTY,
})


def _c(required=(), optional=(), nested=None):
    """A single endpoint contract.

    required  keys ALWAYS present in a successful response.
    optional  keys that may be present (e.g. ``error``/``note`` envelopes, or the
              richer sub-shape of a two-branch handler).
    nested    {key: contract} for sub-objects whose shape the UI reaches into.
    """
    return {
        "required": frozenset(required),
        "optional": frozenset(optional),
        "nested": {k: v for k, v in (nested or {}).items()},
    }


# The honest AI-status sub-shape (_ai_status_dict). Served both at GET /api/ai/status
# AND nested under GET /api/v7/settings as `ai_status`, so it is declared once.
_AI_STATUS = _c(
    required=(
        "native_generative_model", "adapter_enabled", "third_party",
        "provider_kind", "configured", "available", "status", "display",
        "provider", "provider_display", "model",
    ),
)

# Learning page envelope (GET /api/v7/learning and a successful assess POST).
_LEARNING_KEYS = (
    "status", "assessed_at", "duration_ms", "domains", "gaps", "exams",
    "graduation_ready", "no_exam_domains", "history", "lessons", "resources",
    "threshold", "authority", "data_source", "note",
)

# ── Endpoint contracts (keyed "METHOD /path", matching the UI's fetch calls) ──
# Only the endpoints the LIVE V7 UI (web/index.html) actually calls are declared.
CONTRACTS = {
    # ---- read endpoints with a STABLE key set (golden-frozen) ---------------
    "GET /api/health": _c(
        required=("ok", "service"),
    ),
    "GET /api/ai/status": _AI_STATUS,
    "GET /api/v7/status": _c(
        required=("ai", "terminal", "proxy", "workspace", "scheduler", "runtime"),
        nested={
            "ai": _c(required=("system", "configured", "available",
                               "foundation_model", "provider", "provider_display",
                               "display")),
            "terminal": _c(required=("available", "shells")),
            "proxy": _c(required=("active", "port")),
            "workspace": _c(required=("name", "active")),
        },
    ),
    "GET /api/v7/terminal/status": _c(
        required=("available", "shells", "default_shell", "history_count"),
        nested={"shells": _c(required=("powershell", "bash", "cmd"))},
    ),
    "GET /api/v7/terminal/history": _c(
        required=("history",),
    ),
    "GET /api/v7/workspace": _c(
        required=("workspaces", "current_id"),
    ),
    "GET /api/v7/tasks": _c(
        required=("tasks", "recon_jobs"),
        optional=("error",),
    ),
    "GET /api/v7/plugins": _c(
        required=("plugins",),
        optional=("error",),
    ),
    "GET /api/v7/knowledge": _c(
        required=("entries", "total"),
        optional=("error",),
    ),
    "GET /api/v7/evidence": _c(
        required=("nodes", "total"),
        optional=("error",),
    ),
    "GET /api/v7/traffic": _c(
        required=("entries", "total", "workspace_id"),
        optional=("note", "error"),
    ),
    "GET /api/v7/settings": _c(
        required=("model_id", "provider_id", "ollama_url", "enable_external_llm",
                  "language", "theme", "ai_status"),
        # Claude (Anthropic API) options — additive; the API key itself is never here.
        optional=("claude_enabled", "claude_budget_usd", "claude_max_turns", "ravensec_enabled"),
        nested={"ai_status": _AI_STATUS},
    ),
    # api_system_resources has two branches: available:true carries the metrics;
    # available:false carries a note. Only `available` is guaranteed.
    "GET /api/v7/system/resources": _c(
        required=("available",),
        optional=("cpu_percent", "memory_percent", "memory_used_mb",
                  "memory_total_mb", "disk_percent", "disk_free_gb",
                  "net_bytes_sent", "net_bytes_recv", "net_bytes_sent_ps",
                  "net_bytes_recv_ps", "note"),
    ),
    # ---- side-effecting POSTs (success | envelope branches) -----------------
    "POST /api/chat": _c(
        required=(),
        optional=("response", "model", "provider", "session_id", "turn",
                  "error", "error_code"),
    ),
    "POST /api/send": _c(
        required=(),
        optional=("ok", "status", "reason", "headers", "body", "bytes",
                  "elapsed_ms", "truncated", "decode_lossy", "raw_sha256",
                  "blocked", "error"),
    ),
    "POST /api/collect": _c(
        required=(),
        optional=("job_id", "state", "kind", "workspace", "requests",
                  "progress", "error"),
    ),
    "POST /api/emergency-stop": _c(
        required=("stopped",),
    ),
    "POST /api/v7/terminal/run": _c(
        required=(),
        optional=("command", "stdout", "stderr", "exit_code", "duration_ms",
                  "timed_out", "blocked", "shell", "error"),
    ),
    "POST /api/v7/workspace/switch": _c(
        required=(),
        optional=("switched", "workspace", "error"),
    ),
    "POST /api/v7/workspace/create": _c(
        required=(),
        optional=("created", "workspace", "error"),
    ),
    "POST /api/v7/settings": _c(
        required=(),
        optional=("updated", "settings", "error"),
    ),
    "POST /api/v7/knowledge": _c(
        required=(),
        optional=("ok", "entry_id", "entry", "error", "status"),
    ),
    "POST /api/v7/evidence/note": _c(
        required=(),
        optional=("ok", "evidence_id", "error", "status"),
    ),
    # ---- Learning (live route over raven/learning; added after the Linux port) --
    # `status` is READY after an assessment has been persisted, EMPTY before the
    # first one (honest never-assessed state). `error` surfaces a lesson-read
    # failure instead of a silent empty list.
    "GET /api/v7/learning": _c(
        required=_LEARNING_KEYS,
        optional=("error",),
    ),
    # Success returns the GET shape; refusal (Emergency Stop / already running)
    # returns the {error, status?, message} envelope with HTTP 409.
    "POST /api/v7/learning/assess": _c(
        required=(),
        optional=_LEARNING_KEYS + ("error", "message"),
    ),
}

# Row-item field sets for the list endpoints. The UI renders table rows from
# these; a renamed row key is as breaking as a renamed envelope key, so they are
# named here too (used by the UI field-map resolver for ``entries[].method`` etc).
ITEM_CONTRACTS = {
    "GET /api/v7/traffic": _c(
        optional=("method", "url", "status", "identity_label", "timestamp"),
    ),
    "GET /api/v7/evidence": _c(
        optional=("node_id", "kind", "type", "label", "title", "data"),
    ),
    "GET /api/v7/knowledge": _c(
        optional=("entry_id", "title", "kind", "content_type", "source",
                  "confidence"),
    ),
    "GET /api/v7/tasks": _c(
        optional=("task_id", "id", "name", "type", "status", "created_at"),
    ),
    "GET /api/v7/plugins": _c(
        optional=("plugin_id", "id", "name", "status", "state", "version"),
    ),
    "GET /api/v7/workspace": _c(
        optional=("workspace_id", "id", "name"),
    ),
    # One row shape per endpoint (resolver limitation): the union of the
    # domains[] / lessons[] / exams[] / resources[] / gaps[] row keys.
    "GET /api/v7/learning": _c(
        optional=(
            # domains[]
            "domain", "status", "exam_id", "accuracy", "mastery_level",
            "n_evaluated", "n_correct", "needs_study",
            # gaps[]
            "priority", "description",
            # exams[]
            "title", "n_pass", "n_total", "domains", "failures", "error",
            # lessons[]
            "entry_id", "summary", "tags", "confidence", "source", "created_at",
            # resources[]
            "resource_id", "study_approach", "data_source",
        ),
    ),
}


def endpoints():
    """All declared endpoint ids."""
    return set(CONTRACTS)


def allowed_fields(endpoint):
    """The flat set of top-level keys allowed for ``endpoint`` (required|optional)."""
    c = CONTRACTS[endpoint]
    return set(c["required"]) | set(c["optional"])


def resolve(endpoint, dotted):
    """True if ``dotted`` (e.g. ``proxy.active`` or ``entries[].method``) resolves
    to a declared field of ``endpoint``. ``[]`` steps into that endpoint's
    ITEM_CONTRACTS row shape. Used by the UI field-map drift test."""
    if endpoint not in CONTRACTS:
        return False
    contract = CONTRACTS[endpoint]
    parts = dotted.split(".")
    for i, raw in enumerate(parts):
        last = i == len(parts) - 1
        if raw.endswith("[]"):
            key = raw[:-2]
            allowed = set(contract["required"]) | set(contract["optional"])
            if key not in allowed:
                return False
            # Subsequent step resolves against the row-item shape.
            item = ITEM_CONTRACTS.get(endpoint)
            if item is None:
                return last  # no declared row shape → accept the list itself
            contract = item
            continue
        allowed = set(contract["required"]) | set(contract["optional"])
        if raw not in allowed:
            return False
        if last:
            return True
        nested = contract["nested"].get(raw)
        if nested is None:
            # Not a declared sub-object; a deeper read is opaque — accept.
            return True
        contract = nested
    return True
