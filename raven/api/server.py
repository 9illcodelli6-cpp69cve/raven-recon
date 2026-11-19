"""Stdlib-only local server: serves the workbench UI and a scope-aware sender.

The sender reuses the project's own scope rules (`raven.scope`) so Repeater,
Intruder and `curl` obey exactly the same boundaries as the recon engine, and it
blocks non-public resolved addresses before every request. Redirects are never
followed automatically — the raw 3xx is returned, matching a request tool's
behaviour. Binds to loopback only.
"""
import http.client
import ipaddress
import json
import mimetypes
import os
import unicodedata
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid as _uuid
from contextvars import ContextVar
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


from ..analysis import inspect_body
from ..scope import Scope, canonical_url, hostname, rule
from ..store import Store
from . import xss_executor
from .traffic import build_traffic_response
from .scheduler import (
    Scheduler, Cancelled as _CancelledSignal, BudgetExhausted, SchedulerStopped, WorkspaceBusy,
)
import sqlite3 as _sqlite3
from ..runtime.model import (
    ModelService, ModelProvider, ProviderType, OllamaAdapter, ProviderStatus,
    NATIVE_PROVIDER_ID, build_native_provider,
)
from ..runtime.conversation import ConversationContext, MessageRole
from ..ai.chat import ChatSession, ChatConfig

import sys

from ..platform_paths import ensure_dir as _ensure_data_dir, resolve_data_root as _resolve_data_root

if getattr(sys, "frozen", False):  # bundled by PyInstaller
    WEB = Path(sys._MEIPASS) / "web"
else:
    WEB = Path(__file__).resolve().parent.parent.parent / "web"

# Persistent data location (see raven/platform_paths.py):
#   * RAVEN_DATA_DIR env override (set by the Linux launcher) wins;
#   * frozen Windows: NEXT TO THE EXE — never the process cwd, because a desktop
#     shortcut with no "Start in" folder can set cwd somewhere unrelated and scatter
#     workspace data across folders;
#   * frozen Linux: ~/.local/share/raven-recon (XDG) — the binary's folder may be
#     read-only (/opt, AppImage mount) or a shared bin dir;
#   * source (dev server, CLI, tests): cwd-relative, exactly as before — tests
#     deliberately os.chdir() into an isolated temp dir and rely on "workspaces/"
#     landing inside it.
_RESOLVED_DATA_ROOT = _resolve_data_root()
if _RESOLVED_DATA_ROOT is not None:
    DATA_ROOT = _ensure_data_dir(_RESOLVED_DATA_ROOT)
else:
    DATA_ROOT = Path(".")
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
# Serialises workspace/store swaps in set_scope only. Day-to-day DB access is made
# thread-safe by the Store itself, so no blanket lock wraps reads or collection.
_LOCK = threading.RLock()
# Per-run secret. The UI receives it inlined into the page (same-origin only); every
# /api call must present it, which defeats cross-site (CSRF) calls from other pages.
SESSION_TOKEN = secrets.token_urlsafe(32)

# Historical browser header profiles for compatibility. These strings do not
# identify the installed browser or claim current stable release versions.
UA_CATALOG_SOURCE = "Historical compatibility profiles: https://developer.chrome.com/release-notes/131 ; https://developer.mozilla.org/en-US/docs/Mozilla/Firefox/Releases/132"
UA_CATALOG_VERIFIED = "historical formats; not current installed browser versions"
UA_CATALOG = {
    "chrome-windows": ("Chrome — Windows",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"),
    "chrome-macos": ("Chrome — macOS",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"),
    "chrome-android": ("Chrome — Android",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Mobile Safari/537.36"),
    "edge-windows": ("Edge — Windows",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"),
    "firefox-windows": ("Firefox — Windows",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"),
    "firefox-linux": ("Firefox — Linux",
        "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"),
    "safari-macos": ("Safari — macOS",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/18.1 Safari/605.1.15"),
    "safari-iphone": ("Safari — iPhone",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"),
    "safari-ipad": ("Safari — iPad",
        "Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/18.1 Mobile/15E148 Safari/604.1"),
}
DEFAULT_UA_KEY = "chrome-windows"  # a documented real-browser profile — never the tool's own name

# Header names a "search header" (workspace-wide, non-secret identification header,
# e.g. a bounty program's required X-Request-Purpose) may NEVER be — these carry
# credentials or connection semantics and must stay per-request / per-identity only.
_FORBIDDEN_SEARCH_HEADERS = {
    "cookie", "authorization", "proxy-authorization", "host", "content-length",
    "transfer-encoding", "connection", "x-raven-token",
}
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")  # RFC 7230 token


def _validate_header(name, value):
    """Reject CR/LF (header/response-splitting injection) and malformed names; return
    the canonical (verbatim-cased, first-seen) name so case-insensitive duplicates
    collapse instead of silently sending two conflicting headers for the same field."""
    if not isinstance(name, str) or not isinstance(value, str):
        raise ValueError("header name and value must be strings")
    if not _HEADER_NAME_RE.fullmatch(name):
        raise ValueError(f"invalid header name: {name!r}")
    if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in value):
        raise ValueError(f"header value for {name!r} must not contain CR/LF or control characters")
    try:
        value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError("HTTP header values must be Latin-1 encodable") from exc
    if name.lower() in _FORBIDDEN_SEARCH_HEADERS:
        raise ValueError(f"{name} cannot be set as a workspace search header "
                          "(credentials and framing headers stay per-request only)")
    return name


def _normalize_search_headers(raw):
    """Validate + case-insensitively dedupe a {name: value} mapping. Later entries in
    iteration order win on a case-insensitive collision (dict insertion order), so a
    caller re-sending the same header with different casing gets one deterministic
    value rather than two conflicting headers on the wire."""
    if not isinstance(raw, dict):
        raise ValueError("headers must be an object of {name: value}")
    out = {}
    seen_lower = {}
    for name, value in raw.items():
        canon = _validate_header(name, value)
        key = canon.lower()
        if key in seen_lower:
            del out[seen_lower[key]]
        out[canon] = value
        seen_lower[key] = canon
    return out


def _resolve_user_agent(ua_key, custom):
    """The effective UA string for a workspace: a catalog key, or a validated custom
    string (still must look like a real header value — no CR/LF, non-empty)."""
    if ua_key == "custom":
        if not isinstance(custom, str) or not custom.strip():
            raise ValueError("custom User-Agent must be a non-empty string")
        _validate_header("User-Agent", custom)
        return custom.strip()
    if ua_key not in UA_CATALOG:
        raise ValueError(f"unknown user_agent_key: {ua_key!r}")
    return UA_CATALOG[ua_key][1]


# Mutable server state. Scope starts on IANA's reserved example.com so the tool is
# useful and verifiable out of the box; the UI narrows it to the real program.
STATE = {
    "scope": Scope(include=["example.com", "*.example.com"], exclude=[], ports=[80, 443]),
    "name": "example",
    "allow_private": False,
    "max_body": 512 * 1024,
    "timeout": 15.0,
    # Per-workspace research identity (V4 Stage 2/6): non-secret headers a bounty
    # program requires (e.g. X-Request-Purpose: Research) applied to EVERY real
    # outbound target request from the central send path, and the browser User-Agent
    # to present. Persisted per workspace in identity.json; never Cookie/Authorization.
    "search_headers": {},
    "user_agent_key": DEFAULT_UA_KEY,
    "user_agent": UA_CATALOG[DEFAULT_UA_KEY][1],
}


# ── AI Chat state ──────────────────────────────────────────────────────────────
_CHAT_LOCK = threading.Lock()
_AI_SVC: ModelService | None = None
_AI_CONV: ConversationContext | None = None
_CHAT_SESSIONS: dict = {}   # session_id → ChatSession

# Phase-4 (P4-NATIVE-CHAT): the model_id of the RAVEN-OWN native checkpoint the
# researcher has EXPLICITLY selected as the live first-party chat model, or None.
# OFF (None) by default — a default run loads no native checkpoint and imports no torch.
# This is a RUNTIME selection, NOT a shipped default: it deliberately lives OUTSIDE
# _RAVEN_SETTINGS (so the /api/v7/settings wire contract is unchanged) and NEVER flips
# the top-level honesty flag raven.native_ai.NATIVE_GENERATIVE_MODEL (stays None).
_NATIVE_SELECTED_MODEL_ID: str | None = None


def _native_models_dir() -> Path:
    """Directory holding RAVEN's native checkpoints + registry (models/native).

    Resolves against the bundle root when frozen, else the source repo root; falls
    back to the data root. Read-only lookup — opening it loads no checkpoint/torch.
    """
    candidates = []
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys._MEIPASS) / "models" / "native")
    candidates.append(WEB.parent / "models" / "native")   # source repo root
    candidates.append(DATA_ROOT / "models" / "native")
    for c in candidates:
        try:
            if c.exists():
                return c
        except Exception:
            continue
    return WEB.parent / "models" / "native"


def _native_registry():
    """The §16 native-model registry (JSON-backed). Importing registry_ext is pure
    stdlib (no torch); it merely lists checkpoints + their honest maturity."""
    from ..native_ai.generative.registry_ext import NativeModelRegistry
    return NativeModelRegistry(str(_native_models_dir() / "native_registry.json"))


def _resolve_native_checkpoint(entry) -> Path:
    """Resolve a registry entry's (possibly relative, Windows-slashed) checkpoint path
    to a concrete file. Tries absolute, repo-root-relative, then the native dir."""
    raw = str(entry.checkpoint_path).replace("\\", "/")
    p = Path(raw)
    if p.is_absolute() and p.exists():
        return p
    cand = WEB.parent / raw
    if cand.exists():
        return cand
    return _native_models_dir() / Path(raw).name


def _build_selected_native_provider(model_id: str):
    """Build the (ModelProvider, adapter, model_id) for the selected native checkpoint.

    Local-only load via NativeChatProvider.select_checkpoint (no network / no Ollama).
    Raises if the model is unknown or its checkpoint file is missing, so the caller
    leaves native UNREGISTERED and chat reports the honest unavailable (never fabricates).
    """
    reg = _native_registry()
    entry = reg.get(model_id)
    if entry is None:
        raise KeyError(f"native model not registered: {model_id}")
    ckpt = _resolve_native_checkpoint(entry)
    if not ckpt.exists():
        raise FileNotFoundError(f"native checkpoint file missing: {ckpt}")
    maturity = entry.maturity.value if hasattr(entry.maturity, "value") else str(entry.maturity)
    provider, adapter = build_native_provider(
        str(ckpt), maturity=maturity, max_threads=4,
        display_name=f"RAVEN Native (first-party · {maturity})")
    native_model_id = adapter.discover_models()[0].model_id   # "raven-native"
    return provider, adapter, native_model_id


def _external_llm_enabled() -> bool:
    """Is the OPTIONAL third-party external generative provider (Ollama) turned on?

    OFF by default. RAVEN ships NO native generative model and must not depend on any
    generative model at runtime (CANONICAL_ARCHITECTURE §6), so the adapter is reachable
    ONLY when the researcher explicitly opts in — via the ``enable_external_llm`` setting
    or the ``RAVEN_ENABLE_OLLAMA`` env var. Read lock-free (single-key dict reads are
    atomic under the GIL) to avoid a _SETTINGS_LOCK/_CHAT_LOCK ordering hazard, since
    this is called from inside _ensure_ai while _CHAT_LOCK is held.
    """
    env = (os.environ.get("RAVEN_ENABLE_OLLAMA") or "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    return bool(_RAVEN_SETTINGS.get("enable_external_llm", False))


def _ensure_ai():
    """Lazy-initialize ModelService + ConversationContext. Thread-safe.

    Wave 13 (A13-NATIVE): the Ollama adapter is NO LONGER auto-constructed or
    auto-probed. By default NO provider is registered and NO outbound connection to
    localhost:11434 is attempted — a default run makes zero network calls here. The
    optional third-party provider is constructed (and only then health-checked /
    model-discovered) solely when explicitly enabled; it honors the configured
    ``ollama_url``. When enabled-but-unreachable it is still registered (so the status/
    chat layer can report PROVIDER_UNAVAILABLE honestly, distinct from "no native
    model"), and never fabricates output.
    """
    global _AI_SVC, _AI_CONV
    with _CHAT_LOCK:
        if _AI_SVC is not None:
            return _AI_SVC, _AI_CONV
        svc = ModelService()
        if _external_llm_enabled():
            base_url = _RAVEN_SETTINGS.get("ollama_url") or "http://localhost:11434"
            adapter = OllamaAdapter(base_url=base_url)
            # Network is touched ONLY on this explicit opt-in path.
            status = adapter.health_check()
            models = adapter.discover_models() if status == ProviderStatus.AVAILABLE else []
            default_model = (_RAVEN_SETTINGS.get("model_id")
                             or (models[0].model_id if models else "qwen2.5-coder:latest"))
            provider = ModelProvider(
                provider_id="ollama",
                provider_type=ProviderType.OLLAMA,
                display_name="Ollama (optional external provider · third-party)",
                endpoint=base_url,
                status=status,
                models=models,
                configuration={"third_party": True, "optional": True},
            )
            svc.register_provider(provider, adapter)
            svc.set_default("ollama", default_model)
        # Phase-4 (P4-NATIVE-CHAT): FIRST-PARTY native RAVEN-LM provider — registered
        # ONLY when a checkpoint is EXPLICITLY selected (mirrors the Ollama gating, but
        # first-party + local-only). Nothing here loads torch or a checkpoint otherwise.
        # When a native model is selected it is the intended default chat path. A load
        # error is swallowed to an HONEST unregistered state (chat/status then report the
        # native model unavailable) — we never fabricate or degrade into a fake provider.
        if _NATIVE_SELECTED_MODEL_ID:
            try:
                nprov, nadapter, nmid = _build_selected_native_provider(_NATIVE_SELECTED_MODEL_ID)
                svc.register_provider(nprov, nadapter)
                svc.set_default(nprov.provider_id, nmid)
            except Exception:
                pass
        # RAVEN-Sec (cybersecurity + coding model, local CPU inference): registered when
        # its weights are installed under <data>/ai. It is the default chat path ONLY when
        # the user has not explicitly chosen another one (a selected native checkpoint or
        # the enabled external provider) — an explicit choice is never overridden.
        # Nothing is loaded here — weights load lazily on the first message.
        if _RAVEN_SETTINGS.get("ravensec_enabled", False):
            try:
                from ..sec_ai.llm import build_provider as _rs_build
                built = _rs_build()
                if built is not None:
                    rprov, radapter, rmid = built
                    prior_default = getattr(svc, "_default_provider", None)
                    svc.register_provider(rprov, radapter)
                    if not prior_default:  # nothing explicitly chosen (or it failed to load)
                        svc.set_default(rprov.provider_id, rmid)
            except Exception:
                pass
        # Claude (Anthropic API): registered once the operator saved a key (or set
        # ANTHROPIC_API_KEY). Saving a key is an explicit choice, so Claude becomes the chat
        # path — unless a native checkpoint was selected or the external LLM enabled.
        if _RAVEN_SETTINGS.get("claude_enabled", True):
            try:
                from ..claude.client import credential_source as _cl_src
                if _cl_src(_claude_keystore()):
                    from ..claude.chat import build_provider as _cl_build
                    cprov, cadapter, cmid = _cl_build(_claude_client)
                    svc.register_provider(cprov, cadapter)
                    if not (_NATIVE_SELECTED_MODEL_ID or _external_llm_enabled()):
                        svc.set_default(cprov.provider_id, cmid)
            except Exception:
                pass
        db_path = str(DATA_ROOT / "conversations.db")
        db_conn = _sqlite3.connect(db_path, check_same_thread=False)
        ctx = ConversationContext(db_conn)
        _AI_SVC = svc
        _AI_CONV = ctx
        return svc, ctx


def _ai_status_dict() -> dict:
    """Return honest, runtime-derived AI status. Never raises.

    Wave 13 (A13-NATIVE): RAVEN ships NO native generative model. Any chat capability
    comes only from an OPTIONAL third-party external provider (Ollama) that is OFF by
    default and never auto-probed. The status is labeled honestly:
      - ``native_generative_model``: always "none" (RAVEN owns no generative model).
      - ``adapter_enabled`` / ``third_party`` / ``provider_kind``: describe the optional
        external provider — never framed as "RAVEN's own AI".
      - ``status`` vocabulary: READY (enabled + reachable + a model), DEGRADED (enabled +
        reachable but no model), UNAVAILABLE (enabled but unreachable), DISABLED (off).
    Legacy keys (``configured``/``available``/``display``/``provider``/
    ``provider_display``/``model``) are preserved for the existing UI + status contract.
    """
    enabled = False
    try:
        enabled = _external_llm_enabled()
    except Exception:
        enabled = False
    base = {
        "native_generative_model": "none",
        "adapter_enabled": enabled,
        "third_party": enabled,
        "provider_kind": "third_party" if enabled else None,
    }
    try:
        svc, _ = _ensure_ai()
        providers = svc.list_providers()
        # Phase-4 (P4-NATIVE-CHAT): FIRST-PARTY native RAVEN-LM takes precedence when a
        # checkpoint has been selected AND actually loaded (registered). Reported through
        # the SAME declared status keys (no wire-contract change); the honest maturity
        # rides in `display` (e.g. "RAVEN Native — EXPERIMENTAL_BOOTSTRAP") and `model`
        # carries the concrete checkpoint id. `native_generative_model` stays "none" (that
        # key is the SHIPPED-default flag; a selected bootstrap is a runtime selection).
        cl_prov = next((p for p in providers if p.provider_id == "claude"), None)
        if cl_prov is not None and getattr(svc, "_default_provider", None) == "claude":
            base.update({
                "configured": True, "available": True, "status": "READY",
                "display": "Claude Opus 5.5 — Anthropic API",
                "provider": cl_prov.provider_id, "provider_display": cl_prov.display_name,
                "model": "claude-opus-5-5", "third_party": True, "provider_kind": "anthropic",
            })
            return base
        sec_prov = next((p for p in providers if p.provider_id == "raven_sec"), None)
        # Reported only when it is the ACTIVE chat path (an explicitly selected native
        # model / enabled external provider keeps the default and is reported below).
        if sec_prov is not None and getattr(svc, "_default_provider", None) == "raven_sec":
            tuned = bool(sec_prov.configuration.get("fine_tuned"))
            base.update({
                "configured": True,
                "available": True,
                "status": "READY",
                "display": ("RAVEN-Sec 0.5B — fine-tuned" if tuned
                            else "RAVEN-Sec — base model (fine-tune in progress)"),
                "provider": sec_prov.provider_id,
                "provider_display": sec_prov.display_name,
                "model": "raven-sec-0.5b" if tuned else "qwen2.5-coder-0.5b-instruct",
                "third_party": False,
                "provider_kind": "raven_sec",
            })
            return base
        native_prov = None
        if _NATIVE_SELECTED_MODEL_ID:
            for _p in providers:
                if _p.provider_id == NATIVE_PROVIDER_ID:
                    native_prov = _p
                    break
        if native_prov is not None:
            maturity = str(native_prov.configuration.get("maturity", "EXPERIMENTAL_BOOTSTRAP"))
            model_name = (native_prov.models[0].model_id if native_prov.models
                          else "raven-native")
            base.update({
                "configured": True,
                "available": True,
                "status": "READY",
                "display": f"RAVEN Native — {maturity}",
                "provider": native_prov.provider_id,
                "provider_display": native_prov.display_name,
                "model": _NATIVE_SELECTED_MODEL_ID or model_name,
                "third_party": False,
                "provider_kind": "raven_native",
            })
            return base
        if not providers:
            # No native model and no external provider enabled → honest DISABLED.
            base.update({
                "configured": False,
                "available": False,
                "status": "DISABLED",
                "display": "No native generative model (optional external provider disabled)",
                "provider": None,
                "provider_display": None,
                "model": None,
            })
            return base
        p = providers[0]
        probed = svc.probe_providers()
        available = probed.get(p.provider_id) == ProviderStatus.AVAILABLE
        models = p.models
        model_name = models[0].model_id if models else (_RAVEN_SETTINGS.get("model_id") or None)
        if not available:
            status = "UNAVAILABLE"
            display = "Optional external provider unavailable (Ollama · third-party)"
        elif not model_name:
            status = "DEGRADED"
            display = "Optional external provider reachable, no model (Ollama · third-party)"
        else:
            status = "READY"
            display = f"{model_name} (Ollama · third-party, optional)"
        base.update({
            "configured": True,
            "available": available,
            "status": status,
            "display": display,
            "provider": p.provider_id,
            "provider_display": p.display_name,
            "model": model_name,
            "third_party": True,
            "provider_kind": "third_party",
        })
        return base
    except Exception:
        base.update({
            "configured": False,
            "available": False,
            "status": "DISABLED",
            "display": "No native generative model",
            "provider": None,
            "provider_display": None,
            "model": None,
        })
        return base


def api_chat(payload: dict) -> tuple:
    """Handle POST /api/chat — send a message and return AI response."""
    msg = payload.get("message")
    sid = payload.get("session_id")
    if not isinstance(msg, str) or (sid is not None and not isinstance(sid, str)):
        return {"error": "message (and session_id, if given) must be strings"}, 400
    msg = msg.strip()
    if not msg:
        return {"error": "message is required"}, 400
    session_key = (sid or "default")[:64]
    try:
        svc, ctx = _ensure_ai()
        with _CHAT_LOCK:
            if session_key not in _CHAT_SESSIONS:
                conv = ctx.create_conversation(
                    workspace_id=STATE.get("name", "default"),
                    title="AI Chat",
                )
                _CHAT_SESSIONS[session_key] = ChatSession(
                    model_service=svc,
                    conversation_context=ctx,
                    config=ChatConfig(workspace_id=conv.conversation_id),
                )
            session = _CHAT_SESSIONS[session_key]
        resp = session.send(msg)
        # Wave 13 (A13-NATIVE): branch on the TYPED failure kind, not a string prefix.
        # The honest "NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE" (no native model + optional
        # provider off) and "PROVIDER_UNAVAILABLE" (enabled external provider down) both
        # return a typed 503 with error_code; neither fabricates a `response`, and the
        # user + assistant turns are already persisted by ChatSession.send above.
        if resp.failure:
            return {
                "error": resp.content,
                "error_code": resp.failure,
                "model": resp.model_id,
                "provider": resp.provider_id,
            }, 503
        out = {
            "response": resp.content,
            "model": resp.model_id,
            "provider": resp.provider_id,
            "session_id": session_key,
            "turn": resp.turn,
        }
        # Phase-4 (P4-NATIVE-CHAT): a native generation is TAGGED with its honest
        # maturity (e.g. EXPERIMENTAL_BOOTSTRAP) + advisory note — never hidden, never
        # restated as capable. Additive: only present for a native-model turn.
        if resp.maturity:
            out["maturity"] = resp.maturity
            out["advisory_note"] = resp.advisory_note or _NATIVE_CAUTION
        return out, 200
    except Exception as exc:
        return {"error": f"Chat service error: {type(exc).__name__}"}, 503


# ── Native (first-party) model selection (Phase-4, P4-NATIVE-CHAT) ───────────────
_NATIVE_CAUTION = ("experimental bootstrap — memorizes curriculum, not a capable "
                   "assistant yet")


def api_native_models_list() -> tuple:
    """GET /api/v7/native/models — list RAVEN's OWN native checkpoints from the §16
    registry (registry_ext), with honest maturity. Pure metadata: loads no checkpoint
    and imports no torch. First-party (NOT third-party Ollama)."""
    try:
        reg = _native_registry()
        entries = reg.list_entries()
        models = [{
            "model_id": e.model_id,
            "family": e.family,
            "maturity": (e.maturity.value if hasattr(e.maturity, "value") else str(e.maturity)),
            "parameter_count": int(e.parameter_count or 0),
            "context_window": int(e.context_window or 0),
            "architecture_version": e.architecture_version,
            "selected": (e.model_id == _NATIVE_SELECTED_MODEL_ID),
        } for e in entries]
        return {
            "models": models,
            "selected": _NATIVE_SELECTED_MODEL_ID,
            "first_party": True,
            "caution": _NATIVE_CAUTION,
        }, 200
    except Exception as exc:
        return {"models": [], "selected": _NATIVE_SELECTED_MODEL_ID,
                "first_party": True, "error": str(exc)}, 200


def api_native_select(payload: dict) -> tuple:
    """POST /api/v7/native/select — activate (or, with model_id null/"", clear) a native
    checkpoint as the live FIRST-PARTY chat model.

    On activation the checkpoint is loaded LOCALLY (NativeChatProvider.select_checkpoint
    on the next _ensure_ai) — no network, no Ollama. Honest: if the checkpoint is unknown
    or fails to load, selection is refused with a typed error (we never claim success or
    fabricate). Deselecting returns chat to the honest "native model not available".
    """
    global _AI_SVC, _NATIVE_SELECTED_MODEL_ID
    model_id = payload.get("model_id")
    if model_id is not None and not isinstance(model_id, str):
        return {"error": "model_id must be a string"}, 400
    model_id = (model_id or "").strip() or None

    if model_id is not None:
        try:
            reg = _native_registry()
            entry = reg.get(model_id)
        except Exception as exc:
            return {"error": f"native registry error: {type(exc).__name__}",
                    "selected": _NATIVE_SELECTED_MODEL_ID}, 503
        if entry is None:
            return {"error": f"unknown native model: {model_id}",
                    "selected": _NATIVE_SELECTED_MODEL_ID}, 404
        ckpt = _resolve_native_checkpoint(entry)
        if not ckpt.exists():
            return {"error": f"native checkpoint file missing for {model_id}",
                    "selected": _NATIVE_SELECTED_MODEL_ID}, 404

    # Apply the selection and force a rebuild of the AI service on next use.
    with _CHAT_LOCK:
        _NATIVE_SELECTED_MODEL_ID = model_id
        _AI_SVC = None
        _CHAT_SESSIONS.clear()
    # Durable: the native-model selection survives a restart (sweep B §7 / P6 §1).
    _persist_settings()

    if model_id is None:
        return {"selected": None, "maturity": None, "first_party": True}, 200

    # Eagerly build so we can report an HONEST load success/failure + maturity NOW.
    maturity = None
    try:
        svc, _ = _ensure_ai()
        prov = svc.get_provider(NATIVE_PROVIDER_ID)
    except Exception as exc:
        with _CHAT_LOCK:
            _NATIVE_SELECTED_MODEL_ID = None
            _AI_SVC = None
            _CHAT_SESSIONS.clear()
        _persist_settings()
        return {"error": f"native load error: {type(exc).__name__}", "selected": None}, 503
    if prov is None:
        with _CHAT_LOCK:
            _NATIVE_SELECTED_MODEL_ID = None
            _AI_SVC = None
            _CHAT_SESSIONS.clear()
        _persist_settings()
        return {"error": f"native model failed to load: {model_id}", "selected": None}, 503
    maturity = str(prov.configuration.get("maturity", "EXPERIMENTAL_BOOTSTRAP"))
    return {"selected": model_id, "maturity": maturity, "first_party": True,
            "caution": _NATIVE_CAUTION}, 200


# ── end AI Chat state ───────────────────────────────────────────────────────────


# ── V7 Subsystem APIs ────────────────────────────────────────────────────────

from ..agent_env.terminal import TerminalTool as _TerminalTool
from ..runtime.workspace import WorkspaceManager as _WorkspaceManager
from ..runtime.tasks import TaskRegistry as _TaskRegistry, TaskStatus as _TaskStatus
from ..runtime.plugins import PluginRegistry as _PluginRegistry
from ..knowledge_os.knowledge_base import KnowledgeBase as _KnowledgeBase
from ..evidence_os.graph import EvidenceGraph as _EvidenceGraph
# Wave 6 (A6-TERM): the terminal path is gated + routed through the ONE canonical
# ProcessExecutor. PolicyGate is the policy authority consulted by the seeded
# CapabilityGate and is the process-wide emergency-stop flag the executor honours.
from ..security.policy_gate import PolicyGate as _PolicyGate

_TERMINAL_TOOL: _TerminalTool | None = None
_TERMINAL_HISTORY: list = []
_TERM_LOCK = threading.Lock()

# Wave 6 (A6-TERM) shared, process-wide terminal/process singletons.
_ENV_PROBE = None          # cached EnvironmentProbe (kills the 30s status spawn)
_PROCESS_EXECUTOR = None    # the one ProcessExecutor the live terminal path uses
_CAP_GATE = None            # seeded CapabilityGate for the active workspace
_CAP_GATE_WS = None         # workspace id the cached gate was built for
_TERM_SINGLETON_LOCK = threading.Lock()

_WORKSPACE_MGR: _WorkspaceManager | None = None
_WS_LOCK = threading.Lock()
_ACTIVE_WORKSPACE_ID: str | None = None

_TASK_REGISTRY: _TaskRegistry | None = None
_TASK_LOCK = threading.Lock()

_PLUGIN_REGISTRY: _PluginRegistry | None = None
_KB: _KnowledgeBase | None = None
_EG: _EvidenceGraph | None = None

_RAVEN_SETTINGS: dict = {
    "model_id": None,
    "provider_id": "ollama",
    "ollama_url": "http://localhost:11434",
    # Wave 13 (A13-NATIVE): the single switch for the OPTIONAL third-party external
    # generative provider (Ollama). OFF by default — RAVEN ships no native generative
    # model and must not depend on one at runtime. Also honored via RAVEN_ENABLE_OLLAMA.
    "enable_external_llm": False,
    "language": None,
    "theme": "dark",
    # Local AI (RAVEN-Sec model) is OFF by default in public builds — opt in with
    # RAVEN_LOCAL_AI=1 after downloading a model (docs/LOCAL_AI.md).
    "ravensec_enabled": os.environ.get("RAVEN_LOCAL_AI", "").strip() == "1",
    # Claude (Anthropic API): used only once the operator saves an API key.
    "claude_enabled": True,
    "claude_budget_usd": 3.0,      # per agent run (estimated from token usage)
    "claude_max_turns": 40,
}
_SETTINGS_LOCK = threading.Lock()

_HAS_PSUTIL = False
try:
    import psutil as _psutil
    _HAS_PSUTIL = True
except ImportError:
    pass

# Wave 14 (A14-FRONTEND) — network throughput rate. psutil's net_io_counters are
# CUMULATIVE byte totals; a per-second RATE needs the delta between two polls.
# The right panel's Network row reads ``net_bytes_sent_ps`` (audit D5: previously
# absent, so the row was permanently "0 KB/s" behind a hardcoded "1.2 MB/s"
# placeholder). We retain the last sample and compute the delta here. The FIRST
# observation (or a counter reset) honestly yields 0.0 — there is no measurement
# window yet, so the UI shows a neutral rate rather than a fabricated one.
_NET_LOCK = threading.Lock()
_LAST_NET = None  # (bytes_sent, bytes_recv, monotonic_ts) or None before first poll


def _net_rate(sent: int, recv: int):
    """Per-second (bytes/s) send/recv throughput from the delta since the last
    call. Returns (0.0, 0.0) on the first sample or a counter reset/wrap."""
    global _LAST_NET
    now = time.monotonic()
    with _NET_LOCK:
        prev = _LAST_NET
        _LAST_NET = (sent, recv, now)
    if not prev:
        return 0.0, 0.0
    dt = now - prev[2]
    if dt <= 0:
        return 0.0, 0.0
    ds, dr = sent - prev[0], recv - prev[1]
    return (round(ds / dt, 1) if ds >= 0 else 0.0,
            round(dr / dt, 1) if dr >= 0 else 0.0)


def _ensure_env_probe():
    """The one cached EnvironmentProbe (shutil.which-first, hidden fallback, TTL).
    Status polling reads this and spawns nothing on the common path."""
    global _ENV_PROBE
    with _TERM_SINGLETON_LOCK:
        if _ENV_PROBE is None:
            from ..runtime.environment import EnvironmentProbe
            _ENV_PROBE = EnvironmentProbe()
        return _ENV_PROBE


def _ensure_process_executor():
    """The one canonical ProcessExecutor for the live terminal/process path.

    Its ``emergency_stop`` is wired to the process-wide PolicyGate flag, so a
    triggered emergency stop refuses every spawn (defence-in-depth alongside the
    gate's own emergency-stop check). shell=False, hidden window, env scrub,
    output/time caps and tree-kill are all enforced inside the executor.
    """
    global _PROCESS_EXECUTOR
    with _TERM_SINGLETON_LOCK:
        if _PROCESS_EXECUTOR is None:
            from ..runtime.process_executor import ProcessExecutor
            _PROCESS_EXECUTOR = ProcessExecutor(
                emergency_stop=_PolicyGate.is_emergency_stop_active,
            )
        return _PROCESS_EXECUTOR


def shutdown_background_work(wait: bool = True) -> None:
    """App exit: kill running terminal/process-plane commands and RAVEN-Sec agents
    (they would otherwise be orphaned and keep running after the window closes),
    then refuse new outbound work and stop the scheduler."""
    if _PROCESS_EXECUTOR is not None:
        try:
            _PROCESS_EXECUTOR.cancel_all()
        except Exception:
            pass
    for mgr in (_RAVENSEC_AGENTS, _CLAUDE_AGENTS):
        if mgr is not None:
            try:
                mgr.cancel_all()
            except Exception:
                pass
    try:
        SCHEDULER.shutdown(wait=wait)
    except Exception:
        pass


def _active_workspace_id_for_gate() -> str:
    """A non-empty workspace id for the policy gate (PolicyGate denies empty ids)."""
    wid = STATE.get("workspace_id") or _ACTIVE_WORKSPACE_ID or STATE.get("name") or "default"
    return wid if str(wid).strip() else "default"


def _active_workspace_cwd():
    """Run terminal commands in the active workspace dir, not the server CWD."""
    ws_dir = STATE.get("ws_dir")
    try:
        return str(ws_dir) if ws_dir else None
    except Exception:
        return None


def _ensure_capability_gate(ws_id: str):
    """Seeded CapabilityGate for the active workspace.

    Seeded with LIVE_WORKSPACE_GRANTS (PROCESS_ANALYZER / HTTP_READ /
    HTTP_STATE_CHANGE) via A4-SEC's ``seed_live_workspace_gate`` so the now
    fail-closed gate does NOT turn the working researcher terminal into a 403.
    """
    global _CAP_GATE, _CAP_GATE_WS
    with _TERM_SINGLETON_LOCK:
        if _CAP_GATE is None or _CAP_GATE_WS != ws_id:
            from ..runtime.capabilities import seed_live_workspace_gate
            hosts = set()
            try:
                sc = STATE.get("scope")
                if sc is not None:
                    hosts = {h for h in sc.include if h}
            except Exception:
                hosts = set()
            _CAP_GATE = seed_live_workspace_gate(ws_id, allowed_scope_hosts=hosts)
            _CAP_GATE_WS = ws_id
        return _CAP_GATE


def _ensure_terminal() -> _TerminalTool:
    global _TERMINAL_TOOL
    if _TERMINAL_TOOL is None:
        # Inject the shared, emergency-stop-wired executor + cached probe so the live
        # terminal honours the process-wide stop and never re-spawns a status probe.
        _TERMINAL_TOOL = _TerminalTool(
            timeout_s=30,
            executor=_ensure_process_executor(),
            env_probe=_ensure_env_probe(),
        )
    return _TERMINAL_TOOL


def _terminal_denied_envelope(command: str, shell: str, reason: str) -> dict:
    """A stable TerminalResult-shaped envelope for a gate refusal (keys frozen)."""
    return {
        "command": command,
        "stdout": "",
        "stderr": f"blocked: {reason}" if reason else "blocked by policy",
        "exit_code": -1,
        "duration_ms": 0,
        "timed_out": False,
        "blocked": True,
        "shell": shell,
    }


def _ensure_workspace_mgr() -> _WorkspaceManager:
    global _WORKSPACE_MGR
    with _WS_LOCK:
        if _WORKSPACE_MGR is not None:
            return _WORKSPACE_MGR
        db_path = str(DATA_ROOT / "workspaces_v7.db")
        db_conn = _sqlite3.connect(db_path, check_same_thread=False)
        db_conn.execute("""
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY, name TEXT, slug TEXT,
                created_at TEXT, scope_json TEXT, identity_json TEXT,
                note TEXT, settings_json TEXT, root_path TEXT, created_ms INTEGER
            )
        """)
        db_conn.commit()
        _WORKSPACE_MGR = _WorkspaceManager(db_conn)
        # Wave 5 (A5-WS): the V7 registry is a thin INDEX over System A. Rebuild it
        # from the real workspaces/<slug> dirs so the selector lists the actual
        # filesystem workspaces (e.g. example/<engagement>), not ghost rows.
        # READ-ONLY to every recon.db; additive to workspaces_v7.db only.
        try:
            _WORKSPACE_MGR.reconcile_from_filesystem(DATA_ROOT)
        except Exception:
            pass
        existing = _WORKSPACE_MGR.list_all()
        if not existing:
            _WORKSPACE_MGR.create("Default", root_path=str(DATA_ROOT))
        return _WORKSPACE_MGR


def _ensure_task_registry() -> _TaskRegistry:
    global _TASK_REGISTRY
    with _TASK_LOCK:
        if _TASK_REGISTRY is not None:
            return _TASK_REGISTRY
        db_path = str(DATA_ROOT / "tasks_v7.db")
        db_conn = _sqlite3.connect(db_path, check_same_thread=False)
        _TASK_REGISTRY = _TaskRegistry(db_conn)
        return _TASK_REGISTRY


def _ensure_plugin_registry() -> _PluginRegistry:
    global _PLUGIN_REGISTRY
    if _PLUGIN_REGISTRY is None:
        _PLUGIN_REGISTRY = _PluginRegistry()
    return _PLUGIN_REGISTRY


def _ensure_kb() -> _KnowledgeBase:
    global _KB
    if _KB is None:
        db_path = str(DATA_ROOT / "knowledge_v7.db")
        db_conn = _sqlite3.connect(db_path, check_same_thread=False)
        # KnowledgeBase._row_to_entry uses name-based row access (r["entry_id"],
        # r.keys()), so the connection MUST yield sqlite3.Row — otherwise a non-empty
        # /api/v7/knowledge list raises "tuple indices must be integers" (a latent bug
        # that surfaced once the live Agent began writing real entries to this shared
        # store). Row also supports index access, so count()/existing readers are
        # unaffected.
        db_conn.row_factory = _sqlite3.Row
        _KB = _KnowledgeBase(db_conn)
    return _KB


def _ensure_evidence_graph() -> _EvidenceGraph:
    global _EG
    if _EG is None:
        db_path = str(DATA_ROOT / "evidence_v7.db")
        db_conn = _sqlite3.connect(db_path, check_same_thread=False)
        _EG = _EvidenceGraph(db_conn)
    return _EG


def api_terminal_status() -> dict:
    # Wave 6 (A6-TERM): read the cached EnvironmentProbe instead of spawning a shell
    # on every poll. ``detect`` is shutil.which-first and TTL-cached, so repeated
    # /api/v7/status ticks spawn ZERO processes (kills the 30s console flash).
    probe = _ensure_env_probe()
    ps_available = probe.detect("powershell")
    bash_available = probe.detect("bash")
    cmd_available = probe.detect("cmd")
    # Response shape frozen (test_golden_payload_shapes): keys + shells{powershell,
    # bash, cmd}. The ``shells`` vs ``available_shells`` UI rename is A14's contract
    # wave — deliberately NOT changed here.
    return {
        "available": ps_available or bash_available or cmd_available,
        "shells": {
            "powershell": ps_available,
            "bash": bash_available,
            "cmd": cmd_available,
        },
        "default_shell": _default_terminal_shell(ps_available, bash_available),
        "history_count": len(_TERMINAL_HISTORY),
    }


def _default_terminal_shell(ps_available: bool, bash_available: bool) -> str:
    """Platform-native default: PowerShell on Windows, bash on Linux/macOS."""
    if sys.platform == "win32":
        return "powershell" if ps_available else ("bash" if bash_available else "cmd")
    return "bash" if bash_available else ("powershell" if ps_available else "cmd")


def api_terminal_run(payload: dict) -> tuple:
    command = (payload.get("command") or "").strip()
    if not command:
        return {"error": "command is required"}, 400
    shell = payload.get("shell") or ("powershell" if sys.platform == "win32" else "bash")
    timeout = int(payload.get("timeout", 30))

    # 1) Provenance is assigned at the TRUST BOUNDARY. The transport layer already
    #    authenticated the loopback researcher UI (do_POST -> _authed + _origin)
    #    before this handler runs, so the interactive-UI source resolves to
    #    RESEARCHER. Provenance is NEVER read from the request body / model output.
    from ..security.actor_context import ActorSource, ProvenanceError, resolve_actor
    try:
        actor = resolve_actor(ActorSource.INTERACTIVE_UI, authenticated=True)
    except ProvenanceError as exc:
        r = _terminal_denied_envelope(command, shell, str(exc))
        _record_terminal(r)
        return r, 200

    # 2) Capability/policy decision via the seeded, fail-closed CapabilityGate. The
    #    terminal declares PROCESS_ANALYZER (process_exec) with an explicit risk
    #    class (undeclared risk now fails closed to SENSITIVE). A RESEARCHER terminal
    #    is broad, so it declares LOW_RISK_STATE_CHANGE -> ALLOW with the grant.
    ws_id = _active_workspace_id_for_gate()
    gate = _ensure_capability_gate(ws_id)
    decision = gate.check("process_exec", {
        "risk_class": "LOW_RISK_STATE_CHANGE",
        "actor": actor,
        "reason": "researcher terminal command",
    })
    if not decision.is_allowed():
        # Fail closed: DENY / REQUIRE_APPROVAL / UNAVAILABLE -> refuse, do not spawn.
        r = _terminal_denied_envelope(command, shell,
                                      decision.message or decision.reason)
        _record_terminal(r)
        return r, 200

    # 3) On ALLOW -> run through the executor-backed tool: hidden window,
    #    provenance-stamped, emergency-stop checked, output-capped, tree-killable.
    tool = _ensure_terminal()
    result = tool.run(
        command, shell=shell, timeout_s=min(timeout, 120),
        actor=actor, capability_decision=decision.decision.value,
        workspace_id=ws_id, working_dir=_active_workspace_cwd(),
    )
    r = result.to_dict()
    _record_terminal(r)
    return r, 200


def api_terminal_cancel(payload: dict) -> tuple:
    """Cancel a running terminal command via ProcessExecutor.cancel (tree-kill).

    With ``execution_id`` cancels that run; without one, cancels every active
    terminal execution (the interactive UI drives a single terminal). Returns a
    new-route envelope (not part of any frozen golden shape)."""
    executor = _ensure_process_executor()
    execution_id = (payload or {}).get("execution_id")
    if execution_id:
        ok = executor.cancel(str(execution_id))
        return {"cancelled": bool(ok), "execution_id": str(execution_id)}, 200
    ids = executor.active_ids()
    cancelled = [eid for eid in ids if executor.cancel(eid)]
    return {"cancelled": bool(cancelled), "execution_ids": cancelled}, 200


def _record_terminal(r: dict) -> None:
    with _TERM_LOCK:
        _TERMINAL_HISTORY.append(r)
        if len(_TERMINAL_HISTORY) > 200:
            _TERMINAL_HISTORY.pop(0)


def api_terminal_history() -> tuple:
    with _TERM_LOCK:
        return {"history": list(_TERMINAL_HISTORY)}, 200


def _reconcile_workspace_folders(mgr) -> None:
    """Register every on-disk workspace folder (workspaces/<slug>/scope.json) that the
    V7 registry does not know yet.

    Workspaces created through PUT /api/scope (the recon Workbench's "New target"),
    or carried over from another install (e.g. the Windows build's data folder), have
    a real store + scope.json but no registry row — so the workspace pickers never
    listed them. Read-only on the folders; additive on the registry; a folder whose
    scope.json is unreadable is skipped (never guessed).
    """
    root = DATA_ROOT / "workspaces"
    try:
        folders = [p for p in root.iterdir() if p.is_dir()]
    except OSError:
        return
    for folder in folders:
        slug = folder.name
        try:
            if mgr.get_by_slug(slug) is not None:
                continue
            scope = json.loads((folder / "scope.json").read_text(encoding="utf-8"))
            if not isinstance(scope, dict) or not isinstance(scope.get("include"), list):
                continue
            name = scope.get("name") if isinstance(scope.get("name"), str) and scope.get("name") else slug
            mgr.ensure(slug, name, slug=slug, scope_json=scope,
                       root_path=str(folder.resolve()), recon_id=None, materialized=True)
        except Exception:
            continue


def _current_workspace_id(mgr, ws_list):
    """The registry row of the workspace that is ACTIVE in STATE (restored at start-up,
    switched, or set via PUT /api/scope) — not a mirror that only some paths update,
    and never simply the first row."""
    row = None
    wid = STATE.get("workspace_id")
    try:
        if wid:
            row = mgr.get(wid) or mgr.get_by_recon_id(wid)
        if row is None and STATE.get("name"):
            row = mgr.get_by_slug(_slug(STATE["name"]))
    except Exception:
        row = None
    if row is not None:
        return row.workspace_id
    return _ACTIVE_WORKSPACE_ID or (ws_list[0].workspace_id if ws_list else None)


def api_workspace_list() -> tuple:
    mgr = _ensure_workspace_mgr()
    _reconcile_workspace_folders(mgr)
    ws_list = mgr.list_all()
    current_id = _current_workspace_id(mgr, ws_list)
    return {
        "workspaces": [w.to_dict() for w in ws_list],
        "current_id": current_id,
    }, 200


def api_workspace_current() -> tuple:
    mgr = _ensure_workspace_mgr()
    _reconcile_workspace_folders(mgr)
    ws_list = mgr.list_all()
    current_id = _current_workspace_id(mgr, ws_list)
    if not current_id:
        return {"error": "no workspace"}, 404
    ws = mgr.get(current_id) or (ws_list[0] if ws_list else None)
    if not ws:
        return {"error": "workspace not found"}, 404
    return ws.to_dict(), 200


def api_workspace_switch(payload: dict) -> tuple:
    """Switch the ACTIVE workspace — Wave 5 (A5-WS) core fix.

    Previously this was label-only: it set `_ACTIVE_WORKSPACE_ID`/`STATE["name"]` and
    returned, so recon kept operating on the previously-opened store. It now drives the
    canonical System-A context engine: resolve the registry row -> read the saved
    workspaces/<slug>/scope.json -> `set_scope`, which atomically rebinds
    STATE["store"], STATE["scope"], STATE["ws_dir"], STATE["workspace_id"] and
    STATE["canonical_svc"], reloads identity, and writes active-workspace.json (rolling
    STATE back on failure). `_ACTIVE_WORKSPACE_ID` becomes a derived mirror of the recon
    workspace_id so knowledge/evidence key on the same canonical id. Response keys are
    unchanged: {"switched", "workspace"}.
    """
    global _ACTIVE_WORKSPACE_ID
    ws_id = payload.get("workspace_id")
    if not isinstance(ws_id, str) or not ws_id.strip():
        return {"error": "workspace_id is required (string)"}, 400
    ws_id = ws_id.strip()
    mgr = _ensure_workspace_mgr()
    ws = mgr.get(ws_id)
    if not ws:
        return {"error": f"workspace {ws_id!r} not found"}, 404
    name = ws.name
    ws_dir = DATA_ROOT / "workspaces" / _slug(name)
    scope_file = ws_dir / "scope.json"
    if not scope_file.is_file():
        # A registry-only row (e.g. the legacy Default) has no bindable scope. Fail
        # closed with guidance rather than a half-switch that changes the label while
        # STATE still points at the old store.
        return {"error": "workspace has no saved scope; open it from the Scope page or re-create it"}, 409
    try:
        saved = json.loads(scope_file.read_text(encoding="utf-8"))
        if not isinstance(saved, dict) or not isinstance(saved.get("include"), list):
            raise ValueError("invalid saved scope")
    except (OSError, ValueError) as exc:
        return {"error": f"workspace scope is unreadable: {type(exc).__name__}"}, 409
    try:
        set_scope({**saved, "name": name})  # atomic full rebind under _LOCK
    except Exception as exc:
        return {"error": f"switch failed; active workspace unchanged: {exc}"}, 409
    # Derived mirror of the canonical recon workspace_id + reconcile-on-switch.
    recon_wid = STATE.get("workspace_id")
    _ACTIVE_WORKSPACE_ID = recon_wid or ws_id
    try:
        mgr.ensure(recon_wid or ws_id, name, slug=_slug(name), scope_json=saved,
                   root_path=str(ws_dir.resolve()), recon_id=recon_wid, materialized=True)
    except Exception:
        pass
    updated = (mgr.get_by_recon_id(recon_wid) if recon_wid else None) or mgr.get_by_slug(_slug(name)) or ws
    return {"switched": True, "workspace": updated.to_dict()}, 200


def api_workspace_create(payload: dict) -> tuple:
    """Create a USABLE workspace — Wave 5 (A5-WS) fix.

    Previously this wrote one workspaces_v7.db row and nothing else (no dir, no
    recon.db, no scope.json) — an un-runnable ghost. It now materializes the real
    workspace via `set_scope` (creates workspaces/<slug>/ + recon.db + scope.json and
    opens it, becoming active), then upserts the registry row keyed on the recon
    workspace_id. Response keys are unchanged: {"created", "workspace"}.
    """
    global _ACTIVE_WORKSPACE_ID
    name = payload.get("name")
    if not isinstance(name, str) or not name.strip():
        return {"error": "name is required (string)"}, 400
    name = name.strip()
    # Optional scope inputs. The include root defaults to the name ONLY when the name
    # itself is a valid host/IP rule ("example.com"); a free-form name ("Acme Corp")
    # needs an explicit scope instead of failing deep inside set_scope.
    include = payload.get("include")
    if not isinstance(include, list) or not include:
        try:
            rule(name)
        except Exception:
            return {"error": "include (the in-scope hosts) is required when the workspace "
                             "name is not itself a hostname or IP"}, 400
        include = [name]
    exclude = payload.get("exclude") if isinstance(payload.get("exclude"), list) else []
    ports = payload.get("ports") if isinstance(payload.get("ports"), list) else [80, 443]
    allow_private = payload.get("allow_private", False)
    if type(allow_private) is not bool:  # "false" must never mean True
        return {"error": "allow_private must be a boolean"}, 400
    mgr = _ensure_workspace_mgr()
    try:
        saved = set_scope({"name": name, "include": include, "exclude": exclude,
                           "ports": ports, "allow_private": allow_private})
    except ValueError as exc:
        msg = str(exc)
        # A collision with an existing workspace bound to another scope is a conflict;
        # everything else (bad host rule, bad port …) is invalid input.
        code = 409 if ("workspace" in msg.lower() and "scope" in msg.lower()) else 400
        return {"error": f"could not create workspace: {msg}"}, code
    except Exception as exc:
        return {"error": f"could not create workspace: {exc}"}, 409
    recon_wid = STATE.get("workspace_id")
    _ACTIVE_WORKSPACE_ID = recon_wid
    ws_dir = STATE.get("ws_dir")
    ws = mgr.ensure(recon_wid or _slug(name), name, slug=_slug(name), scope_json=saved,
                    root_path=str(ws_dir.resolve()) if ws_dir else str(DATA_ROOT),
                    recon_id=recon_wid, materialized=True)
    return {"created": True, "workspace": ws.to_dict()}, 200


def api_tasks_list() -> tuple:
    try:
        registry = _ensure_task_registry()
        tasks = registry.list_all(limit=50)
        # Live SCHEDULER recon jobs (Wave 3 step 4 — the ONE sanctioned fix). The old
        # guard `SCHEDULER.list() if "SCHEDULER" in dir() else []` was always [] because
        # dir() with no args never contains a module global, so recon_jobs never
        # populated. Route through the runtime's adopted scheduler (== SCHEDULER).
        recon_jobs = RUNTIME.scheduler.list()
        return {
            "tasks": [t.to_dict() for t in tasks],
            "recon_jobs": recon_jobs,
        }, 200
    except Exception as exc:
        return {"tasks": [], "recon_jobs": [], "error": str(exc)}, 200


def api_tasks_cancel(task_id: str) -> tuple:
    try:
        registry = _ensure_task_registry()
        if registry.get(task_id) is None:
            return {"error": f"task {task_id!r} not found"}, 404
        registry.transition(task_id, _TaskStatus.CANCELLED, "Cancelled by researcher")
        return {"cancelled": True}, 200
    except Exception as exc:
        return {"error": str(exc)}, 400


def api_settings_get() -> tuple:
    with _SETTINGS_LOCK:
        settings = dict(_RAVEN_SETTINGS)
    ai = _ai_status_dict()
    settings["ai_status"] = ai
    return settings, 200


def api_settings_update(payload: dict) -> tuple:
    global _AI_SVC
    with _SETTINGS_LOCK:
        if "model_id" in payload:
            _RAVEN_SETTINGS["model_id"] = payload["model_id"] or None
        if "provider_id" in payload:
            _RAVEN_SETTINGS["provider_id"] = payload["provider_id"] or "ollama"
        if "ollama_url" in payload:
            _RAVEN_SETTINGS["ollama_url"] = payload["ollama_url"] or "http://localhost:11434"
        if "enable_external_llm" in payload:
            if type(payload["enable_external_llm"]) is not bool:  # "false" is truthy
                return {"error": "enable_external_llm must be a boolean"}, 400
            _RAVEN_SETTINGS["enable_external_llm"] = payload["enable_external_llm"]
        if "language" in payload:
            _RAVEN_SETTINGS["language"] = payload["language"] or None
    # Reset AI service so it re-initializes with new settings
    with _CHAT_LOCK:
        _AI_SVC = None
        _CHAT_SESSIONS.clear()
    # Durable: a Save now survives an app restart (sweep B §7). Best-effort.
    _persist_settings()
    return {"updated": True, "settings": dict(_RAVEN_SETTINGS)}, 200


def api_system_resources() -> dict:
    if _HAS_PSUTIL:
        try:
            cpu = _psutil.cpu_percent(interval=0.1)
            mem = _psutil.virtual_memory()
            disk = _psutil.disk_usage(str(DATA_ROOT))
            net = _psutil.net_io_counters()
            sent_ps, recv_ps = _net_rate(net.bytes_sent, net.bytes_recv)
            return {
                "available": True,
                "cpu_percent": round(cpu, 1),
                "memory_percent": round(mem.percent, 1),
                "memory_used_mb": round(mem.used / 1024 / 1024),
                "memory_total_mb": round(mem.total / 1024 / 1024),
                "disk_percent": round(disk.percent, 1),
                "disk_free_gb": round(disk.free / 1024 / 1024 / 1024, 1),
                "net_bytes_sent": net.bytes_sent,
                "net_bytes_recv": net.bytes_recv,
                # A14 (D5): derived per-second rate the UI's Network row reads.
                "net_bytes_sent_ps": sent_ps,
                "net_bytes_recv_ps": recv_ps,
            }
        except Exception:
            pass
    return {
        "available": False,
        "note": "Install psutil for real resource metrics: pip install psutil",
    }


def api_comprehensive_status() -> dict:
    ai = _ai_status_dict()
    term = api_terminal_status()
    proxy_active = STATE.get("canonical_svc") is not None
    ws_name = STATE.get("name", "Default")
    scheduler_stats = {}
    try:
        scheduler_stats = SCHEDULER.stats()
    except Exception:
        pass
    return {
        "ai": {
            "system": "RAVEN AI System",
            "configured": ai.get("configured", False),
            "available": ai.get("available", False),
            "foundation_model": ai.get("model"),
            "provider": ai.get("provider"),
            "provider_display": ai.get("provider_display"),
            "display": ai.get("display", "Not configured"),
        },
        "terminal": {
            "available": term.get("available", False),
            "shells": term.get("shells", {}),
        },
        "proxy": {
            # `active` = the canonical/controlled-sender plane is bound (a workspace
            # with a CanonicalService is open). RAVEN performs controlled sends through
            # SenderService (POST /api/send); it does NOT run an intercepting proxy, so
            # NO process listens on 8080. `port` is therefore always None (the old
            # hardcoded 8080 was a fabricated "Listening :8080" chip — sweep B §10).
            # Keys {active, port} are golden-frozen; only the fabricated value is removed.
            "active": proxy_active,
            "port": None,
        },
        "workspace": {
            "name": ws_name,
            "active": True,
        },
        "scheduler": scheduler_stats,
        "runtime": "RAVEN V7",
    }


def api_plugins_list() -> tuple:
    try:
        registry = _ensure_plugin_registry()
        plugins = registry.list_all()
        return {"plugins": [p.to_dict() for p in plugins]}, 200
    except Exception as exc:
        return {"plugins": [], "error": str(exc)}, 200


def _ev_know_ws_id() -> str:
    """The ONE canonical workspace id knowledge + evidence both key on.

    Prefers the recon ``STATE['workspace_id']`` (the uuid the CanonicalService /
    observations / findings / evidence all use) so that list, store AND count
    scope to the SAME id even at startup before any explicit switch — closing the
    §2.2 ``"global"``-vs-active mismatch. Falls back to the switch mirror, then
    ``"default"``.
    """
    wid = STATE.get("workspace_id") or _ACTIVE_WORKSPACE_ID or "default"
    return str(wid) if str(wid).strip() else "default"


def api_knowledge_list() -> tuple:
    try:
        kb = _ensure_kb()
        ws_id = _ev_know_ws_id()
        entries = kb.search("", workspace_id=ws_id, limit=50)
        # Count filtered by the SAME ws_id so `total` agrees with the listed rows
        # (§2.2 fix). Fall back for a stub KB whose count() predates the kwarg.
        try:
            total = kb.count(workspace_id=ws_id)
        except TypeError:
            total = kb.count()
        return {"entries": [e.to_dict() for e in entries], "total": total}, 200
    except Exception as exc:
        return {"entries": [], "total": 0, "error": str(exc)}, 200


def api_techniques_list() -> tuple:
    """GET /api/v7/techniques — the built-in, educational technique library
    (knowledge_os.technique). Advisory reference material only; read-only."""
    try:
        from ..knowledge_os.technique import TechniqueLibrary
        rows = []
        for t in TechniqueLibrary().search():
            d = t.to_dict()
            d["steps"] = list(t.steps)
            d["references"] = list(t.references)
            rows.append(d)
        return {"techniques": rows, "total": len(rows)}, 200
    except Exception as exc:
        return {"techniques": [], "total": 0, "error": str(exc)}, 200


# ── RAVEN-Sec: model status, trusted research, research agent ─────────────────
_RAVENSEC_AGENTS = None
_RAVENSEC_LOCK = threading.Lock()


def _ravensec_agents():
    global _RAVENSEC_AGENTS
    with _RAVENSEC_LOCK:
        if _RAVENSEC_AGENTS is None:
            from ..sec_ai.agent import AgentManager
            from ..sec_ai.llm import RavenSecLLM

            def scope_url(url):
                try:
                    return bool(STATE["scope"].allows_url(url))
                except Exception:
                    return False

            def scope_host(host):
                try:
                    return bool(STATE["scope"].allows_host(host))
                except Exception:
                    return False

            def send(req):
                # The SAME path as Repeater: scope pin, scheduler admission (budget, rate,
                # Emergency Stop), workspace identity, no auto-redirect — and the exchange
                # is recorded so it appears in HTTP History.
                tok = _REQUEST_CONTEXT.set(_capture_context())
                try:
                    result = RUNTIME.sender.send(req)
                    try:
                        _post_send_canonical(result, req)
                    except Exception:
                        pass
                finally:
                    _REQUEST_CONTEXT.reset(tok)
                return result

            _RAVENSEC_AGENTS = AgentManager(scope_url, scope_host, send,
                                            lambda: SCHEDULER.stopped.is_set(), RavenSecLLM.get)
        return _RAVENSEC_AGENTS


def api_ravensec_status() -> tuple:
    from ..sec_ai import paths as _p
    from ..sec_ai.kb import KnowledgeBase
    active = _p.active_model_dir()
    out = {"enabled": bool(_RAVEN_SETTINGS.get("ravensec_enabled", False)),
           "model_installed": active is not None,
           "fine_tuned": bool(active and active.name == _p.TUNED_MODEL_DIRNAME),
           "model": active.name if active else None,
           "base_model": _p.BASE_MODEL_ID, "knowledge_base": KnowledgeBase().stats(),
           "training": None, "manifest": None}
    run_dir = _p.ai_dir() / "train-run"
    try:
        state = json.loads((run_dir / "state.json").read_text())
        out["training"] = {"step": state.get("step"), "examples": state.get("pos"),
                           "last_loss": (state.get("losses") or [None])[-1],
                           "minutes": round(state.get("seconds", 0) / 60, 1)}
    except (OSError, ValueError):
        pass
    try:
        lines = [l for l in (run_dir / "train.log").read_text(errors="replace").splitlines()
                 if l.startswith("step ")]
        if lines:
            out["training_log"] = lines[-1]
    except OSError:
        pass
    if out["fine_tuned"]:
        try:
            m = json.loads((active / "manifest.json").read_text())
            m.pop("loss_curve", None)
            out["manifest"] = m
        except (OSError, ValueError):
            pass
    return out, 200


def api_ravensec_search(payload: dict) -> tuple:
    q = str(payload.get("query") or "").strip()
    if not q:
        return {"error": "query is required"}, 400
    from ..sec_ai import research
    try:
        k = max(1, min(20, int(payload.get("k") or 6)))
    except (TypeError, ValueError):
        return {"error": "k must be an integer"}, 400
    online = payload.get("online", True)
    if type(online) is not bool:
        return {"error": "online must be a boolean"}, 400
    res = research.search(q[:500], k, online=online)
    return res, 200


def api_ravensec_read(payload: dict) -> tuple:
    url = str(payload.get("url") or "").strip()
    from ..sec_ai import research
    try:
        max_chars = max(1, min(200_000, int(payload.get("max_chars") or 8000)))
        offset = max(0, int(payload.get("offset") or 0))
    except (TypeError, ValueError):
        return {"error": "max_chars and offset must be integers"}, 400
    try:
        return research.read(url, max_chars=max_chars, offset=offset), 200
    except PermissionError as exc:
        return {"error": str(exc), "blocked": True}, 403
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}, 502


def api_ravensec_agent_start(payload: dict) -> tuple:
    if not _RAVEN_SETTINGS.get("ravensec_enabled", False):
        return {"error": "The local RAVEN-Sec model is off. Use Claude (Settings → Claude), or "
                         "enable a local model — see docs/LOCAL_AI.md (RAVEN_LOCAL_AI=1)."}, 409
    if SCHEDULER.stopped.is_set():
        return {"error": "Emergency Stop is engaged — clear it first"}, 409
    from ..sec_ai import paths as _p
    if _p.active_model_dir() is None:
        return {"error": "RAVEN-Sec model is not installed"}, 503
    try:
        run = _ravensec_agents().start(str(payload.get("objective") or ""))
    except ValueError as exc:
        return {"error": str(exc)}, 400
    return run.snapshot(), 200


def api_ravensec_agent_get(run_id: str) -> tuple:
    run = _ravensec_agents().get(run_id)
    return (run.snapshot(), 200) if run else ({"error": "not found"}, 404)


def api_ravensec_agent_action(run_id: str, action: str, payload: dict) -> tuple:
    run = _ravensec_agents().get(run_id)
    if run is None:
        return {"error": "not found"}, 404
    if action == "cancel":
        run.cancel()
        return {"ok": True}, 200
    action_id = payload.get("action_id")
    if not isinstance(action_id, str) or not action_id:
        return {"error": "action_id (the id of the pending action you reviewed) is required"}, 400
    ok = run.decide(action == "approve", str(payload.get("reason") or ""), action_id=action_id)
    if not ok:
        return {"error": "no matching pending action (already decided or changed)"}, 409
    return {"ok": True}, 200


def api_ravensec_agent_file(run_id: str, name: str) -> tuple:
    run = _ravensec_agents().get(run_id)
    if run is None:
        return {"error": "not found"}, 404
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name or "")
    path = run.workdir / safe
    # Never follow a symlink a sandboxed command left in the workspace (it could point
    # at any file of the user's), and never read a whole huge file into memory.
    if (not safe or safe in (".", "..") or path.is_symlink() or not path.is_file()
            or path.resolve().parent != run.workdir.resolve()):
        return {"error": "file not found"}, 404
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(500_001)
    except OSError:
        return {"error": "file not found"}, 404
    return {"name": safe, "content": data[:500_000].decode("utf-8", errors="replace"),
            "truncated": len(data) > 500_000}, 200


# ── Claude (Anthropic API) ────────────────────────────────────────────────────
# The operator's API key is stored encrypted (raven/claude/keystore.py) and never returned.
# Agent runs are hosted here: read-only tools run directly; http_request / start_collection /
# run_command wait for the operator's Approve (action-id bound), exactly like RAVEN-Sec.
_CLAUDE_KEYSTORE = None
_CLAUDE_AGENTS = None
_CLAUDE_LOCK = threading.Lock()


def _claude_keystore():
    global _CLAUDE_KEYSTORE
    with _CLAUDE_LOCK:
        if _CLAUDE_KEYSTORE is None:
            from ..claude.keystore import KeyStore
            _CLAUDE_KEYSTORE = KeyStore(DATA_ROOT)
        return _CLAUDE_KEYSTORE


def _claude_client():
    from ..claude.client import make_client
    return make_client(_claude_keystore())


def _reset_ai_service():
    global _AI_SVC
    with _CHAT_LOCK:
        _AI_SVC = None
        _CHAT_SESSIONS.clear()


def _claude_ctx() -> dict:
    def scope_info():
        d = scope_dict()
        return {k: d.get(k) for k in ("name", "include", "exclude", "ports", "allow_private")}

    def scope_url(url):
        try:
            return bool(STATE["scope"].allows_url(url))
        except Exception:
            return False

    def scope_host(host):
        try:
            return bool(STATE["scope"].allows_host(host))
        except Exception:
            return False

    def send(req):
        tok = _REQUEST_CONTEXT.set(_capture_context())
        try:
            result = RUNTIME.sender.send(req)
            try:
                _post_send_canonical(result, req)
            except Exception:
                pass
        finally:
            _REQUEST_CONTEXT.reset(tok)
        return result

    def collect(passive, probe, discover):
        if SCHEDULER.stopped.is_set():
            raise ValueError("Emergency Stop is engaged")
        return submit_collect(passive=passive, probe=probe, discover=discover)

    def store():
        with _LOCK:
            st = STATE.get("store")
        if st is None:
            raise ValueError("no workspace is open")
        return st

    def traffic(limit):
        data, _code = api_traffic_list()
        return (data.get("entries") or [])[:limit] if isinstance(data, dict) else []

    def findings(limit):
        st, wid = _v5_store_and_workspace()
        if st is None:
            return []
        keep = ("id", "title", "url", "severity", "review_status", "verification_status", "created_at")
        return [{k: f.get(k) for k in keep} for f in st.get_findings(wid, limit=limit, offset=0)]

    def record_finding(title, url, severity, description, evidence):
        svc = _canonical_svc()
        return svc.create_candidate_agent_finding(title, url, severity, description, evidence) if svc else None

    return {"scope_dict": scope_info, "scope_url": scope_url, "scope_host": scope_host, "send": send,
            "collect": collect, "job": SCHEDULER.get, "assets": lambda: store().assets(),
            "urls": lambda: store().urls(), "traffic": traffic, "findings": findings,
            "record_finding": record_finding}


def _claude_agents():
    global _CLAUDE_AGENTS
    with _CLAUDE_LOCK:
        if _CLAUDE_AGENTS is None:
            from ..claude.agent import ClaudeAgentManager

            def run_settings():
                with _SETTINGS_LOCK:
                    return {"budget_usd": _RAVEN_SETTINGS.get("claude_budget_usd"),
                            "max_turns": _RAVEN_SETTINGS.get("claude_max_turns")}
            _CLAUDE_AGENTS = ClaudeAgentManager(DATA_ROOT / "claude-agent", _claude_ctx(),
                                                lambda: SCHEDULER.stopped.is_set(), _claude_client,
                                                run_settings)
        return _CLAUDE_AGENTS


def api_claude_status() -> tuple:
    from ..claude.client import status
    out = status(_claude_keystore())
    with _SETTINGS_LOCK:
        out.update({"enabled": bool(_RAVEN_SETTINGS.get("claude_enabled", True)),
                    "budget_usd": _RAVEN_SETTINGS.get("claude_budget_usd"),
                    "max_turns": _RAVEN_SETTINGS.get("claude_max_turns")})
    out["chat_default"] = _ai_status_dict().get("provider") == "claude"
    return out, 200


def api_claude_key_save(payload: dict) -> tuple:
    from ..claude.client import test_connection
    from ..claude.keystore import KeyStoreError
    key = payload.get("api_key")
    if not isinstance(key, str):
        return {"error": "api_key (string) is required"}, 400
    ks = _claude_keystore()
    try:
        key_hint = ks.save(key)
    except KeyStoreError as exc:
        return {"error": str(exc)}, 400
    test = test_connection(ks)
    if not test.get("ok") and "(401)" in str(test.get("error", "")):
        ks.delete()                       # a key Anthropic rejects is not kept
        _reset_ai_service()
        return {"saved": False, "error": test["error"]}, 400
    _reset_ai_service()
    return {"saved": True, "key_hint": key_hint, "test": test}, 200


def api_claude_key_delete() -> tuple:
    removed = _claude_keystore().delete()
    _reset_ai_service()
    return {"removed": removed}, 200


def api_claude_test() -> tuple:
    from ..claude.client import test_connection
    return test_connection(_claude_keystore()), 200


def api_claude_settings(payload: dict) -> tuple:
    upd = {}
    if "enabled" in payload:
        if type(payload["enabled"]) is not bool:
            return {"error": "enabled must be a boolean"}, 400
        upd["claude_enabled"] = payload["enabled"]
    if "budget_usd" in payload:
        b = payload["budget_usd"]
        if not isinstance(b, (int, float)) or isinstance(b, bool) or not 0.1 <= b <= 50:
            return {"error": "budget_usd must be a number between 0.1 and 50"}, 400
        upd["claude_budget_usd"] = float(b)
    if "max_turns" in payload:
        t = payload["max_turns"]
        if not isinstance(t, int) or isinstance(t, bool) or not 1 <= t <= 200:
            return {"error": "max_turns must be an integer between 1 and 200"}, 400
        upd["claude_max_turns"] = t
    with _SETTINGS_LOCK:
        _RAVEN_SETTINGS.update(upd)
    _reset_ai_service()
    _persist_settings()
    return api_claude_status()


def api_claude_agent_start(payload: dict) -> tuple:
    from ..claude.client import credential_source
    if SCHEDULER.stopped.is_set():
        return {"error": "Emergency Stop is engaged — clear it first"}, 409
    if not credential_source(_claude_keystore()):
        return {"error": "No Anthropic API key configured — add one in Settings → Claude"}, 503
    if not _RAVEN_SETTINGS.get("claude_enabled", True):
        return {"error": "Claude is disabled in Settings"}, 409
    objective = payload.get("objective")
    if not isinstance(objective, str) or not objective.strip():
        return {"error": "objective (string) is required"}, 400
    try:
        run = _claude_agents().start(objective)
    except ValueError as exc:
        return {"error": str(exc)}, 409
    return run.snapshot(), 200


def api_claude_agent_get(run_id: str) -> tuple:
    run = _claude_agents().get(run_id)
    return (run.snapshot(), 200) if run else ({"error": "not found"}, 404)


def api_claude_agent_action(run_id: str, action: str, payload: dict) -> tuple:
    run = _claude_agents().get(run_id)
    if run is None:
        return {"error": "not found"}, 404
    if action == "cancel":
        run.cancel()
        return {"ok": True}, 200
    action_id = payload.get("action_id")
    if not isinstance(action_id, str) or not action_id:
        return {"error": "action_id (the id of the pending action you reviewed) is required"}, 400
    if not run.decide(action == "approve", str(payload.get("reason") or ""), action_id=action_id):
        return {"error": "no matching pending action (already decided or changed)"}, 409
    return {"ok": True}, 200


def api_claude_agent_file(run_id: str, name: str) -> tuple:
    run = _claude_agents().get(run_id)
    if run is None:
        return {"error": "not found"}, 404
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name or "")
    path = run.workdir / safe
    if (not safe or safe in (".", "..") or path.is_symlink() or not path.is_file()
            or path.resolve().parent != run.workdir.resolve()):
        return {"error": "file not found"}, 404
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(500_001)
    except OSError:
        return {"error": "file not found"}, 404
    return {"name": safe, "content": data[:500_000].decode("utf-8", errors="replace"),
            "truncated": len(data) > 500_000}, 200


# ── Learning (live route over the existing learning engine) ───────────────────
# GET  /api/v7/learning         read-only: last persisted self-assessment (mastery
#                               per domain, gaps, exams), the ACTIVE workspace's
#                               synthesized lessons (Knowledge Base, kind=lesson),
#                               and the study-resource catalogue.
# POST /api/v7/learning/assess  runs RAVEN's synthetic educational exams in-process
#                               (no network / targets / model), persists the
#                               snapshot to DATA_ROOT/learning_mastery.json, and
#                               returns the same shape as GET. Refused while
#                               Emergency Stop is engaged. Authority: NONE.
_LEARNING_STORE = None


def _learning_store():
    global _LEARNING_STORE
    from ..learning.assessment import MasteryStore
    path = DATA_ROOT / "learning_mastery.json"
    if _LEARNING_STORE is None or _LEARNING_STORE.path != path:
        _LEARNING_STORE = MasteryStore(path)
    return _LEARNING_STORE


def _learning_lessons(ws_id: str) -> list:
    from ..knowledge_os.knowledge_base import KnowledgeKind
    entries = _ensure_kb().search("", kind=KnowledgeKind.LESSON, workspace_id=ws_id, limit=50)
    return [{
        "entry_id": e.entry_id, "title": e.title, "summary": e.body,
        "tags": list(e.tags or []), "confidence": e.confidence,
        "source": e.source, "created_at": e.created_at,
    } for e in entries]


def api_learning_get() -> tuple:
    from ..learning import assessment as _la
    from .contracts import STATUS_EMPTY, STATUS_READY
    state = _learning_store().load()
    snap = state["latest"] or _la.empty_snapshot()
    data = {
        "status": STATUS_READY if state["latest"] else STATUS_EMPTY,
        "assessed_at": snap.get("assessed_at"),
        "duration_ms": snap.get("duration_ms"),
        "domains": snap.get("domains") or [],
        "gaps": snap.get("gaps") or [],
        "exams": snap.get("exams") or [],
        "graduation_ready": bool(snap.get("graduation_ready")),
        "no_exam_domains": snap.get("no_exam_domains") or [],
        "history": state["history"],
        "lessons": [],
        "resources": _la.study_resources(),
        "threshold": _la.THRESHOLD,
        "authority": _la.AUTHORITY,
        "data_source": _la.DATA_SOURCE,
        "note": _la.NOTE,
    }
    try:
        data["lessons"] = _learning_lessons(_ev_know_ws_id())
    except Exception as exc:  # surfaced, never a silent empty (contracts: BROKEN)
        data["error"] = f"lessons unavailable: {exc}"
    return data, 200


def api_learning_assess(payload: dict) -> tuple:
    from ..learning import assessment as _la
    from .contracts import STATUS_DENIED
    if SCHEDULER.stopped.is_set():
        return {"error": "emergency_stop", "status": STATUS_DENIED,
                "message": "Emergency Stop is engaged — clear it before running an assessment."}, 409
    try:
        _la.assess_and_store(_learning_store(), should_stop=SCHEDULER.stopped.is_set)
    except _la.AssessmentBusy as exc:
        return {"error": "busy", "message": str(exc)}, 409
    except _la.AssessmentStopped as exc:
        return {"error": "emergency_stop", "status": STATUS_DENIED, "message": str(exc)}, 409
    return api_learning_get()


def _evidence_read_source(ws_id: str):
    """Return the evidence read source for ``api_evidence_list``.

    Honors an injected ``_EG`` (tests / future integration) exactly as before;
    otherwise returns the canonical READ-ONLY ``EvidenceReadModel`` over the active
    workspace ``recon.db``. The empty, deprecated ``evidence_v7.db`` is never
    opened on this path (the V5 recon.db evidence/relationships tables are the
    canonical store).
    """
    if _EG is not None:
        return _EG
    from ..evidence_os.read_model import EvidenceReadModel
    return EvidenceReadModel(STATE.get("store"), ws_id)


def api_evidence_list() -> tuple:
    try:
        ws_id = _ev_know_ws_id()
        eg = _evidence_read_source(ws_id)
        nodes = eg.list_nodes(workspace_id=ws_id, limit=50)
        total = eg.count_nodes()
        return {"nodes": [n.to_dict() for n in nodes], "total": total}, 200
    except Exception as exc:
        return {"nodes": [], "total": 0, "error": str(exc)}, 200


def api_knowledge_store(payload: dict) -> tuple:
    """POST /api/v7/knowledge — store a knowledge entry (gated, provenance-stamped).

    The actor is derived from the authenticated LOCAL session (RESEARCHER) — NEVER
    from the request body — and the workspace is the active workspace. Source,
    confidence clamping and the immutable ``human_reviewed_labels=0`` invariant are
    enforced by the shared handler (same function the dispatcher uses).
    """
    from .evidence_knowledge_handlers import handle_knowledge_store, build_evknow_gate
    from ..runtime.execution import ActorKind
    ws_id = _ev_know_ws_id()
    try:
        kb = _ensure_kb()
    except Exception as exc:
        return {"error": f"knowledge store unavailable: {type(exc).__name__}"}, 503
    res = handle_knowledge_store(
        payload or {}, actor=ActorKind.RESEARCHER, workspace_id=ws_id,
        kb=kb, gate=build_evknow_gate(ws_id),
    )
    status = res.get("status")
    if status == "stored":
        return {"ok": True, "entry_id": res.get("entry_id"), "entry": res.get("entry")}, 200
    if status == "denied":
        return {"error": res.get("error"), "status": "denied"}, 403
    return {"error": res.get("error", "invalid request")}, 400


def api_evidence_note(payload: dict) -> tuple:
    """POST /api/v7/evidence/note — record a researcher NOTE evidence row.

    Advisory, INSERT-only; never a verdict (candidate ≠ verified). Actor is the
    authenticated local RESEARCHER; workspace is the active workspace. Routed
    through the one trusted writer (CanonicalService) via the shared handler.
    """
    from .evidence_knowledge_handlers import handle_evidence_note, build_evknow_gate
    from ..runtime.execution import ActorKind
    ws_id = _ev_know_ws_id()
    svc = _canonical_svc()
    res = handle_evidence_note(
        payload or {}, actor=ActorKind.RESEARCHER, workspace_id=ws_id,
        canonical_svc=svc, gate=build_evknow_gate(ws_id),
    )
    status = res.get("status")
    if status == "recorded":
        return {"ok": True, "evidence_id": res.get("evidence_id")}, 200
    if status == "denied":
        return {"error": res.get("error"), "status": "denied"}, 403
    if status == "unavailable":
        return {"error": res.get("error")}, 503
    return {"error": res.get("error", "invalid request")}, 400


# ── Live Agent / Program routes (Wave-P5, P5-LIVE-RUNTIME) ──────────────────────
# APPEND-ONLY: new builders + append-only route arms (do_GET/do_POST). They drive the
# live ``RUNTIME.agent`` / ``RUNTIME.program`` — the ONE AgentExecutor/ProgramAgent
# loop through the canonical ToolDispatcher + CapabilityGate authority. Provenance is
# boundary-assigned (RAVEN_AGENT / PROGRAM_AGENT); it is NEVER read from the request
# body. No arbitrary shell is exposed (the agent's tool map has no raw-shell row; the
# program map has no process row at all), ``net.http.request`` is UNAVAILABLE (the
# agent never opens its own sockets), and there is no ``_noop``/fake-completion path:
# a denial → BLOCKED, an unavailable tool → BLOCKED, a budget/turn/emergency-stop →
# terminal, each surfaced on the durable Task.

def _task_result_envelope(task) -> tuple:
    """Thin, stable envelope for an agent/program task (status + boundary origin)."""
    if task is None:
        return {"error": "run did not produce a task"}, 500
    status = getattr(task.status, "value", str(task.status))
    origin = getattr(getattr(task, "origin", None), "value", None)
    return {"task_id": task.task_id, "status": status, "origin": origin,
            "failure": getattr(task, "failure", None)}, 200


def _agent_budget(payload: dict):
    """Build an optional TaskBudget from the request's TYPED budget fields only."""
    from ..runtime.tasks import TaskBudget
    b = payload.get("budget")
    if not isinstance(b, dict):
        return None
    kw = {}
    for k in ("max_steps", "max_tool_calls", "max_runtime_ms", "max_duration_s",
              "max_network_requests"):
        v = b.get(k)
        if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
            kw[k] = v
    return TaskBudget(**kw) if kw else None


def api_agent_run(payload: dict) -> tuple:
    """POST /api/v7/agent/run — start a harmless deterministic agent task.

    Provenance is boundary-assigned ``RAVEN_AGENT`` (do_POST already authenticated the
    loopback researcher UI); the ``objective`` string is a human-readable label and can
    never set the actor. The default plan is a RECORD_KNOWLEDGE_NOTE — a local,
    confidence-capped knowledge note (same store as /api/v7/knowledge). No network, no
    process, no shell.
    """
    from ..agent.planner_backend import PlanIntent, PlanRequest
    from ..runtime.execution import ActorKind
    objective = payload.get("objective") or payload.get("goal") or ""
    if not isinstance(objective, str) or not isinstance(payload.get("note_title") or "", str):
        return {"error": "objective and note_title must be strings"}, 400
    objective = objective.strip()
    if not objective:
        return {"error": "objective is required"}, 400
    ws_id = _ev_know_ws_id()
    pr = PlanRequest(
        intent=PlanIntent.RECORD_KNOWLEDGE_NOTE,
        note_title=(payload.get("note_title") or objective)[:120],
        note_body=str(payload.get("note_body") or objective),
        note_tags=["agent", "live"])
    try:
        task = RUNTIME.agent.start_run(
            objective, workspace_id=ws_id, plan_request=pr,
            budget=_agent_budget(payload), actor=ActorKind.RAVEN_AGENT)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"agent run failed: {type(exc).__name__}: {exc}"}, 500
    return _task_result_envelope(task)


def api_agent_get(task_id: str) -> tuple:
    """GET /api/v7/agent/run/<id> — task state + ordered tool/observation history."""
    run = RUNTIME.agent.get_run(task_id)
    if run is None:
        return {"error": "agent run not found"}, 404
    return run, 200


def api_agent_decision(task_id: str, action: str, payload: dict | None = None) -> tuple:
    """POST /api/v7/agent/run/<id>/{approve,deny,cancel} — researcher decisions.

    ``step_id`` (the pending step the researcher reviewed) binds the decision to that
    step: a stale/double-clicked approve can then never approve the NEXT step."""
    svc = RUNTIME.agent
    step_id = (payload or {}).get("step_id")
    if step_id is not None and not isinstance(step_id, str):
        return {"error": "step_id must be a string"}, 400
    try:
        if action == "approve":
            task = svc.approve_step(task_id, step_id)
        elif action == "deny":
            task = svc.deny_step(task_id, step_id)
        else:  # cancel
            task = svc.cancel_run(task_id)
            if _PROCESS_EXECUTOR is not None:  # and kill a command it is running now
                try:
                    _PROCESS_EXECUTOR.cancel_task(task_id)
                except Exception:
                    pass
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{action} failed: {type(exc).__name__}: {exc}"}, 500
    if task is None:
        return {"error": "agent run not found"}, 404
    return _task_result_envelope(task)


def _program_probe_plan(target: str):
    """A one-step MANUAL plan with a single scope-checked NETWORK_READ probe. Typed and
    bounded; the ProgramPolicy binder scope-checks it BEFORE dispatch and
    ``net.http.request`` is UNAVAILABLE, so it can only ever surface scope enforcement
    (out-of-scope → BLOCKED) — never a real send."""
    from ..agent.plan import PlanSource, PlanStep
    from ..agent.planner_backend import PlanIntent, PlanRequest
    from ..planner.planner import ActionProposal
    from ..runtime.tools import SideEffectClass
    proposal = ActionProposal(
        reason="program probe", required_capability="HttpRead",
        risk_class="SafeReadOnly", destination=str(target), method="GET",
        human_approval_required=False)
    step = PlanStep(proposal=proposal, side_effect=SideEffectClass.NETWORK_READ,
                    source=PlanSource.MANUAL)
    return PlanRequest(intent=PlanIntent.MANUAL, manual_steps=[step])


def api_program_run(payload: dict) -> tuple:
    """POST /api/v7/program/run — drive a program-agent run (ProgramPolicy-required).

    PROGRAM_AGENT provenance (boundary-assigned). Refuses with **409** when no loaded
    ``ProgramPolicy`` resolves — the no-autonomous-execution invariant (no task is
    created; there is no default-open path). No host shell, no external targets — local
    fixtures only. An optional typed ``probe_target`` builds exactly one scope-checked
    NETWORK_READ step (which can only ever BLOCK, never send).
    """
    from ..program_agent.executor import NoProgramPolicyError
    objective = payload.get("objective") or payload.get("goal") or ""
    if not isinstance(objective, str) or not isinstance(payload.get("note_title") or "", str):
        return {"error": "objective and note_title must be strings"}, 400
    objective = objective.strip()
    if not objective:
        return {"error": "objective is required"}, 400
    ws_id = _ev_know_ws_id()
    program_id = payload.get("program_id")
    probe_target = payload.get("probe_target")
    if probe_target:
        pr = _program_probe_plan(str(probe_target))
    else:
        from ..agent.planner_backend import PlanIntent, PlanRequest
        pr = PlanRequest(
            intent=PlanIntent.RECORD_KNOWLEDGE_NOTE,
            note_title=(payload.get("note_title") or objective)[:120],
            note_body=str(payload.get("note_body") or objective),
            note_tags=["program", "live"])
    try:
        task = RUNTIME.program.start_program_run(
            objective, workspace_id=ws_id, program_id=program_id, plan_request=pr)
    except NoProgramPolicyError as exc:
        return {"error": str(exc), "status": "no_program_policy"}, 409
    except Exception as exc:  # noqa: BLE001
        return {"error": f"program run failed: {type(exc).__name__}: {exc}"}, 500
    return _task_result_envelope(task)


# Parametric matchers for the live agent run routes (matched AFTER the fixed sets so
# no existing path changes meaning).
_RE_AGENT_RUN = re.compile(r"^/api/v7/agent/run/([^/]+)$")
_RE_AGENT_ACTION = re.compile(r"^/api/v7/agent/run/([^/]+)/(approve|deny|cancel)$")
_RE_RS_AGENT = re.compile(r"^/api/v7/ravensec/agent/([a-f0-9]{6,32})$")
_RE_RS_AGENT_ACTION = re.compile(r"^/api/v7/ravensec/agent/([a-f0-9]{6,32})/(approve|deny|cancel)$")
_RE_RS_AGENT_FILE = re.compile(r"^/api/v7/ravensec/agent/([a-f0-9]{6,32})/file$")
_RE_CL_AGENT = re.compile(r"^/api/v7/claude/agent/([a-f0-9]{6,32})$")
_RE_CL_AGENT_ACTION = re.compile(r"^/api/v7/claude/agent/([a-f0-9]{6,32})/(approve|deny|cancel)$")
_RE_CL_AGENT_FILE = re.compile(r"^/api/v7/claude/agent/([a-f0-9]{6,32})/file$")


def api_traffic_list() -> tuple:
    """GET /api/v7/traffic — real controlled HTTP exchanges as TrafficEntry[].

    Projects the canonical ``observations`` rows (written by BOTH manual/Browser
    sends AND recon probes) into the ``TrafficEntry`` DTO under key ``entries`` —
    the key the UI's loadTraffic() reads. This is the thin UI projection over the
    SAME ``store.get_observations`` that ``GET /api/observations`` serves (one
    store, two read shapes). Metadata only: no request/response bodies are ever
    returned (the store keeps body hash+len, never the body).

    Contract note: this previously returned ``store.urls()`` — the recon asset-URL
    inventory, NOT HTTP exchanges — under key ``requests``, so the Traffic tab was
    always empty (the UI never read ``requests``). Returning observations under
    ``entries`` is the documented contract fix from
    reconstruction/BROWSER_TRAFFIC_ARCHITECTURE.md §1.4/§3.3 and the audit's
    "entries vs requests" finding. The asset inventory remains at ``/api/urls``.
    """
    store = STATE.get("store")
    if store is None:
        return {"entries": [], "total": 0, "workspace_id": None,
                "note": "No workspace loaded"}, 200
    wid = STATE.get("workspace_id") or (
        store.get_workspace_id() if hasattr(store, "get_workspace_id") else None
    )
    try:
        rows = store.get_observations(wid, limit=200) if wid else []
        return build_traffic_response(rows, wid), 200
    except Exception as exc:
        return {"entries": [], "total": 0, "workspace_id": wid, "error": str(exc)}, 200


# ── end V7 Subsystem APIs ──────────────────────────────────────────────────────


def _canonical_svc():
    """Return the CanonicalService for the current workspace, or None if unavailable.

    Never raises — callers treat None as "canonical layer offline".
    All canonical operations are fire-and-forget; they must never interrupt
    the HTTP response to the client. Inside a captured request/collection context the
    service bound to THAT context's workspace is used (not whatever is active now).
    """
    ctx = _REQUEST_CONTEXT.get()
    if ctx is not None and getattr(ctx, "canonical_svc", None) is not None:
        return ctx.canonical_svc
    return STATE.get("canonical_svc")


def _post_send_canonical(result, payload):
    """Persist a controlled HTTP send as a canonical Observation (V5-04/V5-07).

    This is intentionally non-blocking and absorbs all exceptions so
    canonical persistence failures never degrade the send API.
    acquisition_mode defaults to 'collect'; baseline updates require the
    researcher to explicitly choose 'baseline_acquisition' AND set
    baseline_approved=True — the eligibility policy enforces both.
    """
    svc = _canonical_svc()
    if svc is None or not result.get("ok"):
        return
    try:
        url = str(payload.get("url", ""))
        acq_mode = str(payload.get("acquisition_mode") or "collect")
        identity_label = str(payload.get("identity_label") or "manual")
        svc.record_send_result(
            result,
            url=url,
            method=str(payload.get("method") or "GET").upper(),
            request_headers=dict(payload.get("headers") or {}),
            request_body=str(payload.get("body") or ""),
            identity_label=identity_label,
            acquisition_mode=acq_mode,
        )
        # V5-07: offer baseline update — eligibility policy silently rejects
        # collect/acl_check/xss_probe modes and unapproved observations.
        svc.maybe_update_baseline(
            result,
            asset_id=str(payload.get("asset_id") or url),
            url_fingerprint=url,
            identity_label=identity_label,
            acquisition_mode=acq_mode,
            is_probe=bool(payload.get("is_probe", False)),
            is_anomalous=bool(payload.get("is_anomalous", False)),
            baseline_approved=bool(payload.get("baseline_approved", False)),
        )
    except Exception:
        pass


# Central task scheduler (V4 Stage 2). All active collection runs through it so they
# are bounded (worker pool), rate-limited per host, cancellable, pausable, and covered
# by a global Emergency Stop. Defaults are deliberately conservative and polite.
DEFAULT_RATE = 3.0        # outbound collection attempts/sec per host across workspaces
DEFAULT_BUDGET = 5000     # shared workspace budget for this scheduler process
SCHEDULER = Scheduler(workers=3, default_rate=DEFAULT_RATE)
_REQUEST_CONTEXT = ContextVar("raven_request_context", default=None)
_REQUEST_CONTROL = ContextVar("raven_request_control", default=None)
_ACTIVE_RUNS = {}  # workspace path -> run ids owned by live collectors in this process

# ── Runtime composition root (Wave 3 step 2) ────────────────────────────────────
# The ONE RavenRuntime composition root the server holds. Built here (right after
# SCHEDULER) so it exists for EVERY entry path — start_background AND the many tests
# that drive the Handler/route builders directly without calling start_background.
# It ADOPTS the module-global SCHEDULER and the lazy `_ensure_*` subsystem singletons
# BY REFERENCE (no subsystem is reconstructed, no new DB is opened, no behaviour
# changes); route bodies delegate to `RUNTIME.<service>.<method>`. The module-global
# SCHEDULER stays the single scheduler (launch.py imports it directly, unchanged).
from . import bootstrap as _bootstrap  # noqa: E402
RUNTIME = _bootstrap.build_runtime(sys.modules[__name__])


@dataclass(frozen=True)
class RequestContext:
    name: str
    workspace_key: str
    store: object
    scope: Scope
    allow_private: bool
    max_body: int
    timeout: float
    search_headers: tuple  # tuple of (name, value) pairs — frozen/hashable, dict() at use
    user_agent: str
    configuration_error: str | None = None
    stop_generation: object = None
    # The canonical (observation/evidence) service of the SAME workspace, captured with
    # the store — never re-read from STATE later, or a workspace switch during a
    # collection/send would file this workspace's observations into the new one.
    canonical_svc: object = None


def _capture_context():
    with _LOCK:
        sc = STATE["scope"]
        scope = Scope(list(sc.include), list(sc.exclude), list(sc.ports))
        # No references to mutable global lists cross the submission boundary.
        scope.include, scope.exclude, scope.ports = tuple(scope.include), tuple(scope.exclude), tuple(scope.ports)
        path = Path(STATE.get("ws_dir", DATA_ROOT / "workspaces" / _slug(STATE["name"]))).resolve()
        return RequestContext(STATE["name"], os.path.normcase(str(path)), STATE.get("store"),
                              scope, STATE["allow_private"], STATE["max_body"], STATE["timeout"],
                              tuple((STATE.get("search_headers") or {}).items()),
                              STATE.get("user_agent") or UA_CATALOG[DEFAULT_UA_KEY][1],
                              STATE.get("configuration_error"), SCHEDULER.request_generation(),
                              canonical_svc=STATE.get("canonical_svc"))


def _request_context():
    return _REQUEST_CONTEXT.get() or _capture_context()


class _NoControl:
    """No-op Control so do_collect can run outside the scheduler (tests, CLI) without
    rate-limiting or cancellation. Every scheduled run gets a real Control instead."""

    def log(self, *_):
        pass

    def check(self):
        pass

    def rate(self, *_):
        pass

    def finalize(self, callback):
        callback()


def scope_dict():
    sc = STATE["scope"]
    ws_dir = STATE.get("ws_dir")
    return {
        "name": STATE["name"], "include": sc.include, "exclude": sc.exclude,
        "ports": sc.ports, "allow_private": STATE["allow_private"],
        # The actual on-disk data path — stable regardless of the shortcut or working
        # directory the app was launched from, since it always resolves against WEB's
        # sibling (the frozen exe's own folder) rather than the process cwd.
        "data_path": str(ws_dir.resolve()) if ws_dir else None,
        "configuration_error": STATE.get("configuration_error"),
    }


def identity_dict():
    """The research identity actually in effect for this workspace: every header that
    will be added to real target requests, and the exact User-Agent string that will
    be sent — shown verbatim so the operator never has to guess what goes out."""
    return {
        "search_headers": dict(STATE.get("search_headers") or {}),
        "user_agent_key": STATE.get("user_agent_key", DEFAULT_UA_KEY),
        "user_agent": STATE.get("user_agent") or UA_CATALOG[DEFAULT_UA_KEY][1],
        # {key: [label, full UA string]} — the UI shows the exact string that will be
        # sent for each choice, not just a name, so the operator never has to guess.
        "ua_catalog": {key: [label, value] for key, (label, value) in UA_CATALOG.items()},
        "ua_catalog_source": UA_CATALOG_SOURCE, "ua_catalog_verified": UA_CATALOG_VERIFIED,
    }


def set_identity(payload):
    """Validate and apply this workspace's research identity. Never touches Cookie/
    Authorization (rejected by _normalize_search_headers) and never sends anything to
    a passive data source like crt.sh — only real target requests via do_send."""
    with _LOCK:
        headers = _normalize_search_headers(payload["search_headers"]) if "search_headers" in payload else dict(STATE.get("search_headers") or {})
        ua_key = str(payload.get("user_agent_key") or STATE.get("user_agent_key") or DEFAULT_UA_KEY)
        custom = payload.get("user_agent_custom", STATE.get("user_agent") if STATE.get("user_agent_key") == "custom" else None)
        user_agent = _resolve_user_agent(ua_key, custom)
        old = dict(STATE)
        STATE.update(search_headers=headers, user_agent_key=ua_key, user_agent=user_agent)
        try:
            _persist_identity()
        except OSError:
            STATE.clear()
            STATE.update(old)
            raise
        return identity_dict()


def _atomic_json(path, value):
    """Publish a complete configuration file or leave the previous file intact."""
    path = Path(path)
    temporary = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


# ── Settings durable persistence (sweep B §7) ────────────────────────────────
# _RAVEN_SETTINGS and the native-model selection were in-session only, so a "Save"
# silently reverted on the next launch. Persist them atomically to a small JSON next
# to active-workspace.json and reload at startup. Additive (new file only); the
# /api/v7/settings wire contract is unchanged, and RAVEN_ENABLE_OLLAMA still wins at
# read time (_external_llm_enabled).
_SETTINGS_FILENAME = "active-settings.json"
_PERSISTED_SETTING_KEYS = ("model_id", "provider_id", "ollama_url",
                           "enable_external_llm", "language", "theme",
                           "claude_enabled", "claude_budget_usd", "claude_max_turns")


def _persist_settings():
    """Durably publish the researcher's settings + native-model selection. Best-effort:
    the in-memory update has already succeeded, and a desktop write failure must never
    turn a successful Save into an error — mirrors _persist_scope/_persist_identity."""
    try:
        with _SETTINGS_LOCK:
            payload = {k: _RAVEN_SETTINGS.get(k) for k in _PERSISTED_SETTING_KEYS}
        _atomic_json(DATA_ROOT / _SETTINGS_FILENAME, {
            "version": 1,
            "settings": payload,
            "native_selected_model_id": _NATIVE_SELECTED_MODEL_ID,
        })
    except Exception:
        pass


def _load_settings():
    """Reload persisted settings at startup so a Save survives a restart. A missing,
    corrupt or partial file is ignored (defaults kept) — it never widens behavior. A
    persisted native selection is restored ONLY if its checkpoint still resolves
    (else left unselected, honest); it imports no torch (load stays lazy in _ensure_ai)."""
    global _NATIVE_SELECTED_MODEL_ID
    marker = DATA_ROOT / _SETTINGS_FILENAME
    try:
        if not marker.exists():
            return
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return
    if not isinstance(data, dict):
        return
    settings = data.get("settings")
    if isinstance(settings, dict):
        with _SETTINGS_LOCK:
            if "model_id" in settings:
                _RAVEN_SETTINGS["model_id"] = settings["model_id"] or None
            if "provider_id" in settings:
                _RAVEN_SETTINGS["provider_id"] = settings["provider_id"] or "ollama"
            if "ollama_url" in settings:
                _RAVEN_SETTINGS["ollama_url"] = settings["ollama_url"] or "http://localhost:11434"
            if "enable_external_llm" in settings:
                _RAVEN_SETTINGS["enable_external_llm"] = bool(settings["enable_external_llm"])
            if "language" in settings:
                _RAVEN_SETTINGS["language"] = settings["language"] or None
            if settings.get("theme"):
                _RAVEN_SETTINGS["theme"] = settings["theme"]
            if type(settings.get("claude_enabled")) is bool:
                _RAVEN_SETTINGS["claude_enabled"] = settings["claude_enabled"]
            b = settings.get("claude_budget_usd")
            if isinstance(b, (int, float)) and not isinstance(b, bool) and 0.1 <= b <= 50:
                _RAVEN_SETTINGS["claude_budget_usd"] = float(b)
            t = settings.get("claude_max_turns")
            if isinstance(t, int) and not isinstance(t, bool) and 1 <= t <= 200:
                _RAVEN_SETTINGS["claude_max_turns"] = t
    nid = data.get("native_selected_model_id")
    if isinstance(nid, str) and nid.strip():
        try:
            entry = _native_registry().get(nid)
            if entry is not None and _resolve_native_checkpoint(entry).exists():
                _NATIVE_SELECTED_MODEL_ID = nid
        except Exception:
            pass


def _persist_identity():
    ws_dir = STATE.get("ws_dir")
    if ws_dir is None:  # set_identity() can be called before any workspace is open
        return
    _atomic_json(ws_dir / "identity.json", {
        "search_headers": STATE.get("search_headers") or {},
        "user_agent_key": STATE.get("user_agent_key", DEFAULT_UA_KEY),
        "user_agent": STATE.get("user_agent") or UA_CATALOG[DEFAULT_UA_KEY][1],
    })


def _load_identity():
    """Reload the CURRENT workspace's saved identity when reopening it, so the
    required search headers and UA choice survive a restart — a selection stays
    fixed until the user changes it, never silently reset by switching workspace."""
    marker = STATE["ws_dir"] / "identity.json"
    if not marker.is_file():
        STATE["search_headers"], STATE["user_agent_key"] = {}, DEFAULT_UA_KEY
        STATE["user_agent"] = UA_CATALOG[DEFAULT_UA_KEY][1]
        return
    try:
        saved = json.loads(marker.read_text())
        STATE["search_headers"] = _normalize_search_headers(saved.get("search_headers", {}))
        ua_key = str(saved.get("user_agent_key") or DEFAULT_UA_KEY)
        STATE["user_agent"] = _resolve_user_agent(ua_key, saved.get("user_agent"))
        STATE["user_agent_key"] = ua_key
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Saved research identity is invalid or unreadable; sending remains blocked") from exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # surface the 3xx instead of following it


# Certificates are validated (never bypassed); redirects are never auto-followed;
# ProxyHandler({}) disables environment HTTP proxies. Used only for the passive
# crt.sh data source — target traffic goes through the pinned do_send() path.
_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ssl.create_default_context()),
)


# ── Egress funnel (C-5) — MIGRATED VERBATIM to raven/runtime/services/sender.py ──
# The hardened outbound sender (scope → resolve-then-pin SSRF/rebind guard → header
# strip/force → SCHEDULER.admit_request → send, no auto-redirect) moved out as a
# whole, behaviour-identical unit (RUNTIME_ARCHITECTURE §3.5 / §9 step 3,
# CANONICAL_ARCHITECTURE §1 row 12). It is re-imported here so `server.do_send`,
# `server._pick_public_ip`, `server._PinnedHTTP(S)Connection` and `server._is_public`
# remain the exact same attributes (and monkeypatch surface) they were before; the
# sender module resolves these names back off this module at call time. `RUNTIME.sender`
# (SenderService) is the route-level entry point.
from ..runtime.services.sender import (  # noqa: E402
    _is_public, _pick_public_ip, _PinnedHTTPConnection, _PinnedHTTPSConnection,
    do_send, _send_in_context,
)


def set_scope(payload):
    include = payload.get("include") or []
    exclude = payload.get("exclude") or []
    ports = payload.get("ports") or [80, 443]
    if not all(isinstance(values, list) for values in (include, exclude, ports)):
        raise ValueError("include, exclude and ports must be lists")
    if not all(isinstance(v, str) for v in include + exclude):
        raise ValueError("scope rules must be strings")
    if "allow_private" in payload and type(payload["allow_private"]) is not bool:
        raise ValueError("allow_private must be a boolean")
    scope = Scope(include=list(include), exclude=list(exclude), ports=list(ports))
    with _LOCK:
        old = dict(STATE)
        name = payload.get("name") or STATE["name"]
        if not isinstance(name, str) or not name.strip():
            raise ValueError("workspace name must be a non-empty string")
        if include and name == include[0]:
            name = scope.include[0]
        STATE["scope"] = scope
        STATE["allow_private"] = bool(payload.get("allow_private", False))
        try:
            use_workspace(name)
        except Exception:
            configuration_error = STATE.get("configuration_error")
            STATE.clear()
            STATE.update(old)
            if configuration_error:
                STATE["configuration_error"] = configuration_error
            raise
        return scope_dict()


# --------------------------------------------------------------------------- #
# Real recon: a durable SQLite workspace, scope-aware HTTP probing, and a
# passive certificate-transparency source. All cross-platform (no POSIX locks).
# --------------------------------------------------------------------------- #

def _slug(name):
    # Produce a filesystem-safe, traversal-free workspace name:
    #   1. keep only [a-z0-9._-]
    #   2. collapse any run of 2+ dots to a single dot (kills the ".." token entirely)
    #   3. strip leading/trailing dot/dash/underscore
    # A legitimate domain-like name ("my-app.example.com") is preserved; "..",
    # "../../etc", "....//x" all reduce to a safe single path segment.
    raw = unicodedata.normalize("NFC", str(name))
    slug = re.sub(r"[^a-z0-9._-]", "", raw.lower())
    slug = re.sub(r"\.{2,}", ".", slug).strip("._-")
    if raw.isascii():
        return slug or "workspace"
    # Non-ASCII names (Arabic, CJK, accented Latin) lose characters in the ASCII filter,
    # so distinct names collided ("هدف أول" and "项目" were both "workspace"). Add a
    # stable hash suffix — unless a folder made by the old rule already belongs to
    # exactly this name (keeps existing workspaces reachable).
    legacy = slug or "workspace"
    try:
        saved = json.loads((DATA_ROOT / "workspaces" / legacy / "scope.json").read_text(encoding="utf-8"))
        if isinstance(saved, dict) and saved.get("name") == str(name):
            return legacy
    except (OSError, ValueError):
        pass
    digest = _hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    return f"{slug}-{digest}" if slug else f"ws-{digest}"


def _guard_workspace_conflict(ws_dir, scope):
    """Keep existing data in place; ambiguous ownership requires a new workspace."""
    marker = ws_dir / "scope.json"
    if not marker.is_file():
        if (ws_dir / "recon.db").exists():
            raise ValueError("Existing workspace has no valid scope; preserve it and choose a new workspace name")
        return None
    try:
        previous = json.loads(marker.read_text())
        if not isinstance(previous, dict) or not isinstance(previous.get("include"), list):
            raise ValueError("invalid saved scope")
    except (OSError, ValueError) as exc:
        raise ValueError("Saved workspace scope is unreadable; no data was replaced") from exc
    if sorted(previous.get("include") or []) == sorted(scope.include):
        return None
    raise ValueError("Workspace already belongs to a different scope; existing data was preserved. Choose a new workspace name")


def use_workspace(name):
    with _LOCK:
        old = dict(STATE)
        ws_dir = DATA_ROOT / "workspaces" / _slug(name)
        ws_dir.resolve().relative_to((DATA_ROOT / "workspaces").resolve())
        _guard_workspace_conflict(ws_dir, STATE["scope"])
        store = None
        previous_scope = (ws_dir / "scope.json").read_bytes() if (ws_dir / "scope.json").is_file() else None
        scope_saved = False
        try:
            STATE.update(name=str(name), ws_dir=ws_dir)
            _load_identity()
            store = Store(ws_dir)
            STATE["store"] = store
            key = os.path.normcase(str(ws_dir.resolve()))
            store.mark_interrupted(exclude_run_ids=_ACTIVE_RUNS.get(key, ()))
            STATE.pop("configuration_error", None)
            # V5-03: wire canonical service for this workspace
            try:
                from ..canonical_service import CanonicalService as _CanSvc
                _wid = store.get_workspace_id() or _uuid.uuid4().hex
                STATE["workspace_id"] = _wid
                STATE["canonical_svc"] = _CanSvc(store, _wid, str(name))
            except Exception:
                STATE.pop("canonical_svc", None)
            _seed_roots()
            _persist_scope()
            scope_saved = True
            _atomic_json(DATA_ROOT / "active-workspace.json", {"name": str(name)})
        except Exception:
            if store is not None:
                store.close()
            STATE.clear()
            STATE.update(old)
            if scope_saved and previous_scope is not None:
                try:
                    _atomic_json(ws_dir / "scope.json", json.loads(previous_scope))
                except OSError:
                    STATE["configuration_error"] = "Workspace configuration could not be restored; sending is blocked"
            raise


def _persist_scope(self=None):
    ws_dir = STATE.get("ws_dir")
    if ws_dir is None:
        return
    _atomic_json(ws_dir / "scope.json", scope_dict())


def _restore_workspace():
    """Restore only validated saved settings; a corrupt file never widens scope."""
    marker = DATA_ROOT / "active-workspace.json"
    old = dict(STATE)
    try:
        if not marker.exists():
            use_workspace(STATE["name"])
            return
        saved = json.loads(marker.read_text(encoding="utf-8"))
        name = saved["name"]
        if not isinstance(name, str) or not name:
            raise ValueError("invalid saved workspace name")
        folder = DATA_ROOT / "workspaces" / _slug(name)
        folder.resolve().relative_to((DATA_ROOT / "workspaces").resolve())
        scope = json.loads((folder / "scope.json").read_text(encoding="utf-8"))
        set_scope({**scope, "name": name})
    except (OSError, ValueError, TypeError, KeyError) as exc:
        STATE.clear()
        STATE.update(old)
        STATE["configuration_error"] = f"Saved workspace could not be restored; sending is blocked: {type(exc).__name__}"


def _seed_roots():
    store = STATE["store"]
    if store.assets():
        return
    roots = [r for r in STATE["scope"].include if not r.startswith("*.")]
    if not roots:
        return
    run_id = store.start("seed", {"headers": {}})
    for root in roots:
        store.host(root, "seed", run_id)
    store.finish(run_id, "complete")


# ── Recon collection (ADAPT/extract → raven/recon) ──────────────────────────────
# Wave 7 (A7-RECON): the V7 server collection unit — passive crt.sh + active HTTP probe,
# scheduler-admitted, IP-pinned via do_send — MIGRATED as whole units to the ONE canonical
# recon home (raven/recon) per RECON_ARCHITECTURE §2 / CANONICAL_ARCHITECTURE §1 row 13.
# No rewrite, no third engine: the logic moved out and these names stay thin re-imports /
# delegations so server._probe_host / _passive_crtsh / _run_tool / do_collect /
# _collect_in_context / submit_collect remain the exact same attributes — and monkeypatch
# surface — the whole suite relies on. The recon modules resolve every collaborator
# (do_send, _OPENER, _request_context, _ACTIVE_RUNS, SCHEDULER, …) back off THIS module at
# call time, so behaviour is byte-identical (same pattern as runtime/services/sender.py).
# Re-imported so server._probe_host / _passive_crtsh / _run_tool stay the exact same
# attributes (and monkeypatch surface) they were before — now backed by the extracted
# single-item logic in raven/recon/collectors.py. A collector/service call to
# server._probe_host (etc.) resolves these attributes at call time, so a test that
# replaces one still intercepts, whether the call comes from the service orchestration
# or a direct collector use.
#
# Hidden-window hardening (preserved at the server boundary, V5.0.1 regression guard):
# the optional external-tool runner (_run_tool, subfinder/gau) still spawns with a hidden
# window — it applies CREATE_NO_WINDOW only when sys.platform == "win32" through the ONE
# canonical hidden_process_kwargs() helper (now in runtime/process_executor.py, also used
# by the ExternalToolCollector's ProcessExecutor path), and no spawn ever uses shell=True.
# The subprocess.run itself now lives in raven/recon/collectors.py::run_tool (extracted),
# so no duplicate launcher survives here.
from ..recon.collectors import (  # noqa: E402
    passive_crtsh as _passive_crtsh, probe_host as _probe_host, run_tool as _run_tool,
)
from ..recon.service import ReconService as _ReconService  # noqa: E402

# One shared, stateless ReconService (resolves its live deps off this module at call time).
# Wave-P5 (Phase 4): inject the ONE canonical ProcessExecutor so the OPTIONAL external-tool
# collector (subfinder/gau) can only ever spawn through it (hidden window, env scrub, caps,
# emergency-stop) — never the raw-subprocess fallback — BEFORE any live path could reach it.
# External tools remain OFF by default and are always skipped under the scheduler, so this
# is a safety precondition, not a behaviour change (the raw fallback stays reachable only to
# an unscheduled, non-agent direct caller, and run_tool now refuses agent/program tiers).
_RECON = _ReconService(process_executor=_ensure_process_executor())


def do_collect(passive=True, probe=True, control=None, context=None, external_tools=None):
    """Bind all storage and transport calls to the workspace captured at submission.
    Delegates to the canonical ReconService (RECON_ARCHITECTURE §3.2)."""
    return _RECON.run(passive, probe, control, context, external_tools=external_tools)


def _collect_in_context(passive, probe, control, context, external_tools=None):
    """Thin delegate to ``ReconService.run_in_context`` (the extracted collection body)."""
    return _RECON.run_in_context(passive, probe, control, context, external_tools=external_tools)


def submit_collect(passive=True, probe=True, rate=None, budget=None, discover=False):
    """Queue a collection on the central scheduler and return its job descriptor.
    Non-blocking: the HTTP request returns immediately with a job_id the UI polls.
    Delegates to ReconService.submit (the same seam the recon.collect tool uses).
    ``discover`` opts in to bounded endpoint discovery (the UIs send it)."""
    return _RECON.submit(passive, probe, rate=rate, budget=budget, discover=discover)


def do_import(items):
    if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
        raise ValueError("items must be a list of strings")
    # Snapshot scope and store together before imports can race a workspace swap.
    with _LOCK:
        context = _capture_context()
        if context.configuration_error or context.store is None:
            raise ValueError(context.configuration_error or "No workspace is open")
        store, sc = context.store, context.scope
        run_id = store.start("import", {"headers": {}})
        _ACTIVE_RUNS.setdefault(context.workspace_key, set()).add(run_id)
    added = 0
    try:
        for raw in items:
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            try:
                if "://" in value:
                    value = canonical_url(value)
                    if sc.allows_url(value) and store.url(value, "import", run_id):
                        added += 1
                else:
                    value = hostname(value)
                    if sc.allows_host(value) and store.host(value, "import", run_id):
                        added += 1
            except (ValueError, UnicodeError):
                continue
        store.finish(run_id, "complete")
        store.commit()
        return {"run_id": run_id, "added": added, "assets": len(store.assets())}
    except Exception:
        store.finish(run_id, "failed", "import failed; partial results kept")
        raise
    finally:
        with _LOCK:
            _ACTIVE_RUNS[context.workspace_key].discard(run_id)
            if not _ACTIVE_RUNS[context.workspace_key]:
                del _ACTIVE_RUNS[context.workspace_key]


# --------------------------------------------------------------------------- #
# Access Control Lab (V4 Phase 2): send ONE request under several researcher-
# supplied identities through the hardened sender, with strict identity
# separation and conservative, never-"confirmed" classification.
# --------------------------------------------------------------------------- #
import difflib as _difflib
import hashlib as _hashlib

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_AC_MAX_REQUESTS = 6  # request budget per access-check (≤4 identities + anon + margin)

# A response's IDs, tokens, timestamps and whitespace inside strings can be
# security-relevant. Never mask them or truncate the value used for equality.
# Only JSON layout/key ordering is normalised; all other formats stay verbatim.
_AC_DIFF_LIMIT = 20000  # bounds the advisory similarity calculation, not equality


class _AcJsonNumber(str):
    """Keep arbitrary-size JSON numbers losslessly, distinct from JSON strings."""


def _ac_json_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON keys are ambiguous")
    return value


def _ac_json_value(value):
    if isinstance(value, _AcJsonNumber):
        return ["number", str(value)]
    if isinstance(value, dict):
        return ["object", [[k, _ac_json_value(v)] for k, v in sorted(value.items())]]
    if isinstance(value, list):
        return ["array", [_ac_json_value(v) for v in value]]
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["boolean", value]
    if isinstance(value, str):
        return ["string", value]
    raise ValueError("non-standard JSON value")


def _ac_normalize(body):
    body = body or ""
    try:
        value = json.loads(body, parse_int=_AcJsonNumber, parse_float=_AcJsonNumber,
                           object_pairs_hook=_ac_json_object)
        return "json:" + json.dumps(_ac_json_value(value), ensure_ascii=True, separators=(",", ":"))
    except (ValueError, TypeError, RecursionError):
        return "raw:" + body


def _ac_similarity(a, b):
    if a is None or b is None:
        return 0.0
    if a == b:
        return 1.0
    # The score is only a review aid. Equality always uses the entire captured
    # response; a common prefix must never erase a different private-data tail.
    def sample(value):
        if len(value) <= _AC_DIFF_LIMIT:
            return value
        half = _AC_DIFF_LIMIT // 2
        return value[:half] + value[-half:]
    return round(_difflib.SequenceMatcher(None, sample(a), sample(b)).ratio(), 3)


def _ac_summarize(result):
    if result.get("blocked"):
        return {"ok": False, "blocked": True, "error": result.get("error", "blocked")}
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error", "error")}
    body = result.get("body", "")
    status = result.get("status")
    norm = _ac_normalize(body)
    # Words such as "password" and "forbidden" also occur in legitimate data.
    # They are not evidence that authorization was enforced.
    auth_wall = status in (401, 403)
    truncated = bool(result.get("truncated"))
    decode_lossy = bool(result.get("decode_lossy"))
    return {
        "ok": True, "status": status, "reason": result.get("reason", ""),
        "bytes": result.get("bytes", 0),
        "content_type": next((v for k, v in (result.get("headers") or {}).items()
                              if k.lower() == "content-type"), ""),
        "elapsed_ms": result.get("elapsed_ms", 0),
        "body_sha256": _hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
        "norm_sha256": _hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest(),
        "snippet": body[:600], "auth_wall": auth_wall, "_norm": norm,
        "truncated": truncated, "decode_lossy": decode_lossy,
        "raw_sha256": result.get("raw_sha256"),
        "evidence_complete": not truncated and not decode_lossy,
        "captured_chars": len(body), "normalization": "json-lossless" if norm.startswith("json:") else "verbatim",
        "similarity_limited": len(norm) > _AC_DIFF_LIMIT,
        "denial_evidence": f"HTTP {status}" if auth_wall else None,
        "_has_content": body.strip() not in ("", "{}", "[]", "null"),
    }


def _ac_classify(owner, other, resource_policy="unspecified"):
    """Compare a non-owner identity against the owner for the SAME owned resource.
    Anonymous visibility is evidence, never proof of intended public access.
    Never returns 'confirmed'; uncertain evidence must not imply safe denial."""
    if not owner.get("ok") or not other.get("ok"):
        return {"verdict": "INCONCLUSIVE", "reason": "a request did not complete (blocked/error)"}
    if owner.get("auth_wall") or not (200 <= (owner.get("status") or 0) < 300):
        return {"verdict": "INCONCLUSIVE",
                "reason": "owner did not get its own resource — its session may be expired or unauthorised"}
    expected = other.get("expected")  # 'allow' | 'deny' | None
    if not owner.get("evidence_complete", True) or not other.get("evidence_complete", True):
        return {"verdict": "INCONCLUSIVE", "reason": "response capture was truncated or decoded with replacement — full resource comparison is unavailable"}
    sim = _ac_similarity(owner.get("_norm"), other.get("_norm"))
    details = {"similarity": sim,
               "similarity_limited": owner.get("similarity_limited", False) or other.get("similarity_limited", False)}
    matching = owner.get("_norm") == other.get("_norm") and owner.get("_has_content", True)
    if matching:
        if expected == "deny":
            return {"verdict": "INCONSISTENT", **details,
                    "reason": "identity expected to be denied received the owner's content — review possible disclosure (NOT confirmed)"}
        if not (200 <= (other.get("status") or 0) < 300):
            return {"verdict": "INCONSISTENT", **details,
                    "reason": "non-success status still contained the owner's content — review possible disclosure (NOT confirmed)"}
        if expected == "allow":
            return {"verdict": "EXPECTED", **details, "reason": "identity explicitly expected to have access received the same content"}
        if resource_policy == "public":
            return {"verdict": "EXPECTED", **details, "reason": "researcher explicitly declared this resource public; matching access is expected"}
        return {"verdict": "INCONSISTENT", **details,
                "reason": "other identity received the owner's content; intended public access was not declared — review candidate (NOT confirmed)"}
    if other.get("status") in (401, 403):
        if expected == "allow":
            return {"verdict": "INCONCLUSIVE", "reason": "identity expected to have access was denied — check the test setup"}
        return {"verdict": "EXPECTED", **details,
                "reason": f"explicit HTTP denial ({other.get('status')}); different response content still requires manual disclosure review"}
    return {"verdict": "INCONCLUSIVE", **details,
            "reason": f"response differs (HTTP {other.get('status')} vs {owner.get('status')}); differences alone do not establish authorization enforcement"}


def _ac_run_identity(method, url, sess, body):
    """One request under one identity — built fresh so no identity leaks into another."""
    headers = {}
    for key, value in (sess.get("headers") or {}).items():
        if isinstance(key, str) and isinstance(value, str):
            headers[key] = value
    cookies = sess.get("cookies")
    if isinstance(cookies, str) and cookies.strip():
        headers["Cookie"] = cookies.strip()
    _raw = do_send({"method": method, "url": url, "headers": headers, "body": body})
    summary = _ac_summarize(_raw)
    summary["label"] = str(sess.get("label") or "session")
    # V5-08: record canonical observation for this identity
    _svc = _canonical_svc()
    if _svc is not None:
        try:
            _obs_id = _svc.record_send_result(
                _raw, url=url, method=method,
                request_headers=headers,
                identity_label=summary["label"],
                acquisition_mode="acl_check",
            )
            summary["_canonical_obs_id"] = _obs_id
        except Exception:
            pass
    summary["expected"] = sess.get("expected") if sess.get("expected") in ("allow", "deny") else None
    cred = []
    if cookies:
        cred.append(f"Cookie: <redacted {len(str(cookies))} chars>")
    if any(k.lower() == "authorization" for k in headers):
        cred.append("Authorization: <redacted>")
    summary["credential_preview"] = " · ".join(cred) or "no credentials (anonymous)"
    return summary


def do_access_check(payload):
    token = _REQUEST_CONTEXT.set(_request_context())
    try:
        return _access_check_in_context(payload)
    finally:
        _REQUEST_CONTEXT.reset(token)


def _access_check_in_context(payload):
    method = str(payload.get("method") or "GET").upper()
    if method not in METHODS:
        return {"error": f"unsupported method: {method}"}
    if method in _STATE_CHANGING and payload.get("confirm_state_changing") is not True:
        return {"refused": "state-changing method requires explicit confirmation (default off)"}
    url = str(payload.get("url", ""))
    sessions = payload.get("sessions") or []
    if not isinstance(sessions, list) or not (1 <= len(sessions) <= 4):
        return {"error": "provide 1 to 4 identities"}
    body = payload.get("body", "")
    if not isinstance(body, str):
        return {"error": "body must be a string"}
    for session in sessions:
        if not isinstance(session, dict):
            return {"error": "each identity must be an object"}
        if session.get("expected") not in (None, "allow", "deny"):
            return {"error": "expected must be allow or deny"}
        if session.get("cookies") is not None and not isinstance(session["cookies"], str):
            return {"error": "cookies must be a string"}
        headers = session.get("headers", {})
        if not isinstance(headers, dict):
            return {"error": "identity headers must be an object"}
        for key, value in list(headers.items()) + ([('Cookie', session['cookies'])] if session.get('cookies') else []):
            if (not isinstance(key, str) or not _HEADER_NAME_RE.fullmatch(key)
                    or not isinstance(value, str) or any((ord(c) < 32 and c != '\t') or ord(c) == 127 for c in value)):
                return {"error": "invalid identity header"}
            try:
                value.encode("latin-1")
            except UnicodeEncodeError:
                return {"error": "identity header values must be Latin-1 encodable"}
    if "anonymous_baseline" in payload and type(payload["anonymous_baseline"]) is not bool:
        return {"error": "anonymous_baseline must be a boolean"}
    want_anon = bool(payload.get("anonymous_baseline"))
    resource_policy = payload.get("resource_policy") or "unspecified"
    if resource_policy not in ("public", "private", "unspecified"):
        return {"error": "resource_policy must be public, private, or unspecified"}
    if len(sessions) + (1 if want_anon else 0) > _AC_MAX_REQUESTS:
        return {"error": "request budget exceeded"}

    results = [_ac_run_identity(method, url, s, body) for s in sessions]
    if want_anon:
        anon = _ac_run_identity(method, url, {"label": "anonymous baseline",
                                "expected": "allow" if resource_policy == "public" else
                                            "deny" if resource_policy == "private" else None}, body)
        anon["anonymous_baseline"] = True
        results.append(anon)

    owner = results[0]
    comparisons = [{"label": r["label"], "anonymous_baseline": r.get("anonymous_baseline", False),
                    **_ac_classify(owner, r, resource_policy)} for r in results[1:]]
    # V5-08: create candidate findings for INCONSISTENT verdicts
    _svc = _canonical_svc()
    if _svc is not None:
        _owner_obs_id = owner.get("_canonical_obs_id")
        _result_by_label = {r["label"]: r for r in results[1:]}
        for comp in comparisons:
            if comp.get("verdict") == "INCONSISTENT":
                try:
                    _other_r = _result_by_label.get(comp["label"], {})
                    _svc.create_candidate_access_control(
                        url,
                        owner_result={"status": owner.get("status"), "ok": owner.get("ok")},
                        other_result={"status": _other_r.get("status"), "ok": _other_r.get("ok")},
                        other_label=comp["label"],
                        verdict="INCONSISTENT",
                        owner_obs_id=_owner_obs_id,
                        other_obs_id=_other_r.get("_canonical_obs_id"),
                    )
                except Exception:
                    pass
    for r in results:
        r.pop("_norm", None)  # internal only — never leaves the process
        r.pop("_has_content", None)
        r.pop("_canonical_obs_id", None)  # V5-08: internal only
    return {"method": method, "url": url, "owner_label": owner["label"],
            "anonymous_baseline": want_anon, "resource_policy": resource_policy,
            "results": results, "comparisons": comparisons,
            "note": "Verdicts are review candidates. A matching response is not a confirmed "
                    "authorization flaw — reproduce and confirm ownership by hand."}


# --------------------------------------------------------------------------- #
# XSS Lab (V4 Phase 3) — SAFE analysis only. Injects a harmless unique canary,
# finds reflections, and classifies the surrounding context and which structural
# characters survive un-encoded. It NEVER injects script, and never claims
# execution: the previous executor is quarantined (see docs/XSS_ISOLATION.md).
# Highest verdict is "REFLECTED IN POTENTIALLY UNSAFE CONTEXT".
# --------------------------------------------------------------------------- #
from urllib.parse import parse_qsl as _parse_qsl, urlencode as _urlencode, urlsplit as _urlsplit, urlunsplit as _urlunsplit

_XSS_BOUNDARY = "<>\"'`"


def _xss_representations(s):
    """Show the canary in common encodings (as representations — not evasion)."""
    from urllib.parse import quote as _q
    reps = {
        "plain": s,
        "url": _q(s, safe=""),
        "double_url": _q(_q(s, safe=""), safe=""),
        "html_entities": "".join(f"&#{ord(c)};" for c in s),
        "unicode_escape": "".join(f"\\u{ord(c):04x}" for c in s),
        "hex": s.encode("utf-8").hex(),
        "js_string": json.dumps(s),
        "json_string": json.dumps(s),
    }
    return reps


def _xss_inject(url, body, param, value):
    """Inject `value` via a {XSS} placeholder (url or body) or a query param."""
    if "{XSS}" in url or (body and "{XSS}" in body):
        return url.replace("{XSS}", value), (body or "").replace("{XSS}", value)
    if param:
        parts = _urlsplit(url)
        q = _parse_qsl(parts.query, keep_blank_values=True)
        q = [(k, value if k == param else v) for k, v in q]
        if param not in [k for k, _ in q]:
            q.append((param, value))
        return _urlunsplit((parts.scheme, parts.netloc, parts.path, _urlencode(q), parts.fragment)), (body or "")
    # default: append the param
    parts = _urlsplit(url)
    q = _parse_qsl(parts.query, keep_blank_values=True) + [("q", value)]
    return _urlunsplit((parts.scheme, parts.netloc, parts.path, _urlencode(q), parts.fragment)), (body or "")


def _xss_context(body, idx, content_type):
    """Classify the context at a reflection index. Heuristic, byte-scan based."""
    if "json" in (content_type or "").lower():
        return "json"
    before = body[:idx]
    ls, gt = before.rfind("<"), before.rfind(">")
    # inside <script>…</script> ?
    st = before.rfind("<script")
    if st != -1 and before.rfind("</script>") < st:
        return "js"
    sty = before.rfind("<style")
    if sty != -1 and before.rfind("</style>") < sty:
        return "css"
    if before.rfind("<!--") > before.rfind("-->"):
        return "comment"
    if ls > gt:  # we are inside a tag (attribute area)
        seg = before[ls:]
        dq, sq = seg.rfind('"'), seg.rfind("'")
        if dq != -1 and dq > seg.rfind("=") - 2 and seg.count('"') % 2 == 1:
            return "attribute-double-quoted"
        if sq != -1 and seg.count("'") % 2 == 1:
            return "attribute-single-quoted"
        return "attribute-unquoted"
    return "html-text"


def _xss_unsafe_for(context, raw_chars):
    """Given the context and which of <>\"'` reflected raw, is it potentially unsafe?"""
    need = {
        "html-text": {"<", ">"}, "attribute-double-quoted": {'"'},
        "attribute-single-quoted": {"'"}, "attribute-unquoted": {">", " "},
        "js": {"'", '"', "`", "<"}, "css": {"<"}, "comment": {"<", ">"},
        "json": {'"', "<"}, "unknown": {"<", ">"},
    }.get(context, {"<", ">"})
    return bool(need & set(raw_chars))


# Browser execution is quarantined. Cached state can never enable this feature.
_XSS_ISOLATION_STATE = xss_executor.isolation_status()


def do_xss_verify_isolation():
    """Return a fail-closed status; the quarantined executor cannot be enabled."""
    return xss_executor.isolation_status()


def do_xss_check(payload):
    # One captured workspace for the probe AND its observation/finding records.
    token = _REQUEST_CONTEXT.set(_request_context())
    try:
        return _xss_check_in_context(payload)
    finally:
        _REQUEST_CONTEXT.reset(token)


def _xss_check_in_context(payload):
    if payload.get("confirm_execution"):
        return {"refused": xss_executor.DISABLED_REASON,
                "execution_confirmation": {"attempted": False, "executed": False,
                                            "disabled": True, "reason": xss_executor.DISABLED_REASON}}
    method = str(payload.get("method") or "GET").upper()
    if method not in METHODS:
        return {"error": f"unsupported method: {method}"}
    if method in _STATE_CHANGING and payload.get("confirm_state_changing") is not True:
        return {"refused": "state-changing method requires explicit confirmation (default off)"}
    url = str(payload.get("url", ""))
    param = payload.get("param", "")
    body = payload.get("body", "")
    if not isinstance(body, str) or not isinstance(param, str):
        return {"error": "body and param must be strings"}
    headers = {}
    cookies = payload.get("cookies")
    if isinstance(cookies, str) and cookies.strip():
        headers["Cookie"] = cookies.strip()

    canary = str(payload.get("canary") or ("rvn" + secrets.token_hex(4)))
    canary = re.sub(r"[^a-zA-Z0-9]", "", canary)[:24] or ("rvn" + secrets.token_hex(4))
    probe = canary + _XSS_BOUNDARY  # canary + structural chars (harmless — no script)

    inj_url, inj_body = _xss_inject(url, body, param, probe)
    sent = do_send({"method": method, "url": inj_url, "headers": headers, "body": inj_body})
    if sent.get("blocked"):
        return {"blocked": True, "error": sent.get("error")}
    if not sent.get("ok"):
        return {"error": sent.get("error", "request failed")}
    resp = sent.get("body", "")
    # Header names keep the target's casing (`content-type` behind Envoy/Istio …).
    ctype = next((v for k, v in (sent.get("headers") or {}).items()
                  if str(k).lower() == "content-type"), "")
    fingerprint = _hashlib.sha256(resp.encode("utf-8", "replace")).hexdigest()

    reflections = []
    start = 0
    while True:
        i = resp.find(canary, start)
        if i == -1 or len(reflections) >= 20:
            break
        after = resp[i + len(canary): i + len(canary) + len(_XSS_BOUNDARY)]
        raw_chars = [c for c in _XSS_BOUNDARY if c in after]
        context = _xss_context(resp, i, ctype)
        reflections.append({
            "offset": i, "context": context, "raw_chars": raw_chars,
            "unsafe": _xss_unsafe_for(context, raw_chars),
            "surrounding": resp[max(0, i - 30): i + len(canary) + 12],
        })
        start = i + 1

    if not reflections:
        verdict = "NOT REFLECTED"
    elif any(r["unsafe"] for r in reflections):
        verdict = "REFLECTED IN POTENTIALLY UNSAFE CONTEXT"
    else:
        verdict = "REFLECTED ENCODED"

    # V5-09: record observation and create candidate finding for unsafe reflections
    _svc = _canonical_svc()
    _xss_obs_id = None
    if _svc is not None:
        try:
            _xss_obs_id = _svc.record_send_result(
                sent, url=inj_url, method=method,
                request_headers=headers,
                acquisition_mode="xss_probe",
                is_probe=True,
            )
        except Exception:
            pass
        # Candidate findings only for UNSAFE reflections (an HTML-encoded reflection is
        # not a candidate), one per context, and never a duplicate of an open finding
        # for the same URL + context from an earlier run.
        unsafe_ctx = list(dict.fromkeys(r.get("context", "unknown") for r in reflections if r.get("unsafe")))
        existing = set()
        if unsafe_ctx:
            try:
                _st, _wid = getattr(_svc, "_store", None), getattr(_svc, "_wid", None)
                if _st is not None and _wid:
                    existing = {(f.get("url"), f.get("title")) for f in _st.get_findings(_wid, limit=1000, offset=0)
                                if f.get("review_status") != "rejected"}
            except Exception:
                existing = set()
        for _ctx in unsafe_ctx:
            if (url, f"XSS canary reflected ({_ctx} context) — unverified") in existing:
                continue
            try:
                _svc.create_candidate_xss_reflection(url, _ctx, observation_id=_xss_obs_id)
            except Exception:
                pass

    result = {
        "method": method, "url": url, "param": param, "canary": canary,
        "status": sent.get("status"), "content_type": ctype,
        "evidence_sha256": fingerprint, "reflections": reflections, "verdict": verdict,
        "representations": _xss_representations(canary),
        "note": "SAFE analysis: reflection/context only — no script was injected during "
                "this step and execution was not verified here. Reflection alone is not "
                "execution.",
    }

    return result


def data_assets(context=None):
    ctx = context or _capture_context()
    return [a for a in ctx.store.assets() if ctx.scope.allows_host(a["host"])] if ctx.store else []


def data_urls(context=None):
    ctx = context or _capture_context()
    return [u for u in ctx.store.urls() if ctx.scope.allows_url(u["url"])] if ctx.store else []


def data_changes():
    out = []
    ctx = _capture_context()
    for change in ctx.store.changes() if ctx.store else []:
        value = change["value"]
        ok = ctx.scope.allows_url(value) if "://" in value else ctx.scope.allows_host(value)
        if ok:
            out.append(change)
    return out


def data_summary():
    ctx = _capture_context()
    assets, urls = data_assets(ctx), data_urls(ctx)
    observed = sum(1 for a in assets if a["probe"].get("status") is not None)
    return {"assets": len(assets), "http": observed, "urls": len(urls),
            "families": len({u["family"] for u in urls})}


def _md_cell(value, limit=120):
    """One Markdown table cell: target-derived text is flattened and pipe-escaped."""
    text = " ".join(str("" if value is None else value).split())[:limit]
    return text.replace("|", "\\|").replace("`", "'")


def api_workspace_report() -> tuple:
    """GET /api/report — one Markdown report for the ACTIVE workspace.

    Built only from stored data (no network): scope, surface summary, live hosts,
    the highest-priority endpoints, and every candidate finding with its own
    evidence report (``CanonicalService.generate_finding_report``). Findings are
    presented as UNVERIFIED candidates — the researcher confirms and writes impact.
    """
    store, wid = _v5_store_and_workspace()
    if store is None:
        return {"error": "no workspace loaded"}, 503
    import datetime as _dt
    ctx = _capture_context()
    scope = scope_dict()
    summary = data_summary()
    assets = sorted(data_assets(ctx), key=lambda a: -(a.get("score") or 0))
    urls = sorted(data_urls(ctx), key=lambda u: -(u.get("score") or 0))
    findings = store.get_findings(wid, limit=500, offset=0)
    svc = _canonical_svc()
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [
        f"# RAVEN report — {scope['name']}",
        "",
        f"_Generated {now}. Every finding below is an **unverified candidate** produced by "
        "RAVEN's analysis; reproduce it by hand, confirm impact and stay within the "
        "program's rules before submitting._",
        "",
        "## Scope",
        "",
        f"- **In scope:** {', '.join(f'`{h}`' for h in scope['include'])}",
        f"- **Out of scope:** {', '.join(f'`{h}`' for h in scope['exclude']) or '—'}",
        f"- **Ports:** {', '.join(str(p) for p in scope['ports'])}",
        "",
        "## Surface summary",
        "",
        f"| Assets | Responding | URLs | URL families | Candidate findings |",
        f"|---|---|---|---|---|",
        f"| {summary['assets']} | {summary['http']} | {summary['urls']} | {summary['families']} | {len(findings)} |",
        "",
    ]
    live = [a for a in assets if (a.get("probe") or {}).get("status") is not None]
    if live:
        out += ["## Live hosts", "", "| Host | Status | Title | Server | Priority |", "|---|---|---|---|---|"]
        for a in live[:100]:
            p = a.get("probe") or {}
            out.append(f"| `{_md_cell(a['host'])}` | {p.get('status')} | {_md_cell(p.get('title'), 60)} | "
                       f"{_md_cell(p.get('server'), 30)} | {a.get('score') or 0} |")
        out.append("")
    if urls:
        out += ["## Endpoints (highest review priority first)", "",
                "| URL | Priority | Source |", "|---|---|---|"]
        for u in urls[:150]:
            src = u.get("sources") or u.get("source") or ""
            if isinstance(src, (list, tuple)):
                src = ", ".join(src)
            out.append(f"| `{_md_cell(u['url'], 160)}` | {u.get('score') or 0} | {_md_cell(src, 40)} |")
        if len(urls) > 150:
            out.append(f"\n_{len(urls) - 150} more endpoints in the workspace._")
        out.append("")
    out += ["## Candidate findings", ""]
    if not findings:
        out.append("_No candidate findings recorded in this workspace._")
    for i, f in enumerate(findings, 1):
        body = ""
        if svc is not None:
            try:
                body = (svc.generate_finding_report(f["id"]) or {}).get("markdown", "")
            except Exception:
                body = ""
        if body:
            # Nest each finding's own report under "### N. <title>" so the combined
            # document keeps a single H1 and a consistent outline.
            for line in body.strip().splitlines():
                if line.startswith("# "):
                    out.append(f"### {i}. {line[2:]}")
                elif line.startswith("#"):
                    out.append("##" + line)
                else:
                    out.append(line)
            out.append("")
        else:
            out += [f"### {i}. {_md_cell(f.get('title'), 200)}", "",
                    f"- **URL:** `{_md_cell(f.get('url'), 300)}`",
                    f"- **Severity (heuristic):** {f.get('severity')} · "
                    f"**Verification:** {f.get('verification_status')} · "
                    f"**Review:** {f.get('review_status')}", ""]
    return {"workspace": scope["name"], "findings": len(findings),
            "markdown": "\n".join(out) + "\n"}, 200


# ---------------------------------------------------------------------------
# V5-19: Canonical data routes
# All routes enforce workspace isolation: resources outside the current
# workspace return 404, preventing object-level authorization bypass.
# ---------------------------------------------------------------------------

def _parse_pagination(params):
    """Parse and validate limit/offset query params.

    Returns (limit, offset, None) on success or (None, None, error_response)
    where error_response is a (body_dict, status_int) pair for a 400 reply.
    """
    try:
        raw_limit = params.get("limit", [100])[0]
        limit = int(raw_limit)
        if limit < 0:
            raise ValueError
    except (ValueError, TypeError):
        return None, None, ({"error": "limit must be a non-negative integer"}, 400)
    try:
        raw_offset = params.get("offset", [0])[0]
        offset = int(raw_offset)
        if offset < 0:
            raise ValueError
    except (ValueError, TypeError):
        return None, None, ({"error": "offset must be a non-negative integer"}, 400)
    return min(limit, 500), offset, None


def _v5_store_and_workspace():
    """Return (store, workspace_id) or (None, None) if no workspace is loaded."""
    store = STATE.get("store")
    workspace_id = STATE.get("workspace_id")
    if store is None or not workspace_id:
        return None, None
    return store, workspace_id


def api_findings(params):
    """GET /api/findings — list candidate findings for the current workspace."""
    store, wid = _v5_store_and_workspace()
    if store is None:
        return {"error": "no workspace loaded"}, 503
    limit, offset, err = _parse_pagination(params)
    if err:
        return err
    review_status = params.get("review_status", [None])[0]
    verification_status = params.get("verification_status", [None])[0]
    rows = store.get_findings(wid, limit=limit, offset=offset,
                               review_status=review_status,
                               verification_status=verification_status)
    total = store.count_findings(wid)
    return {"findings": rows, "total": total, "limit": limit, "offset": offset}, 200


def api_finding_detail(finding_id):
    """GET /api/findings/{id} — workspace-isolated."""
    store, wid = _v5_store_and_workspace()
    if store is None:
        return {"error": "no workspace loaded"}, 503
    row = store.get_finding(finding_id, wid)
    if row is None:
        return {"error": "not found"}, 404
    return row, 200


def api_finding_evidence(finding_id):
    """GET /api/findings/{id}/evidence — workspace-isolated."""
    store, wid = _v5_store_and_workspace()
    if store is None:
        return {"error": "no workspace loaded"}, 503
    if store.get_finding(finding_id, wid) is None:
        return {"error": "not found"}, 404
    rows = store.get_evidence(finding_id, wid)
    return {"finding_id": finding_id, "evidence": rows}, 200


def api_finding_report(finding_id):
    """GET /api/findings/{id}/report — generate Markdown report."""
    store, wid = _v5_store_and_workspace()
    if store is None:
        return {"error": "no workspace loaded"}, 503
    if store.get_finding(finding_id, wid) is None:
        return {"error": "not found"}, 404
    svc = _canonical_svc()
    if svc is None:
        return {"error": "canonical service offline"}, 503
    result = svc.generate_finding_report(finding_id)
    if "error" in result:
        return result, 404
    return result, 200


def api_finding_review(finding_id, payload):
    """POST /api/findings/{id}/review — researcher submits a review action."""
    store, wid = _v5_store_and_workspace()
    if store is None:
        return {"error": "no workspace loaded"}, 503
    if store.get_finding(finding_id, wid) is None:
        return {"error": "not found"}, 404
    action = payload.get("action")
    if not action or not isinstance(action, str):
        return {"error": "action is required"}, 400
    note = payload.get("note")
    actor = str(payload.get("actor") or "researcher")
    svc = _canonical_svc()
    if svc is None:
        return {"error": "canonical service offline"}, 503
    result = svc.submit_review(finding_id, action, actor=actor, note=note)
    if "error" in result:
        return result, 400
    return result, 200


def api_observations(params):
    """GET /api/observations — list observations for the current workspace."""
    store, wid = _v5_store_and_workspace()
    if store is None:
        return {"error": "no workspace loaded"}, 503
    limit, offset, err = _parse_pagination(params)
    if err:
        return err
    rows = store.get_observations(wid, limit=limit, offset=offset)
    return {"observations": rows, "limit": limit, "offset": offset}, 200


def api_observation_detail(obs_id):
    """GET /api/observations/{id} — workspace-isolated."""
    store, wid = _v5_store_and_workspace()
    if store is None:
        return {"error": "no workspace loaded"}, 503
    row = store.get_observation(obs_id, wid)
    if row is None:
        return {"error": "not found"}, 404
    return row, 200


def api_baselines():
    """GET /api/baselines — list baseline records for the current workspace."""
    store, wid = _v5_store_and_workspace()
    if store is None:
        return {"error": "no workspace loaded"}, 503
    rows = store.list_baselines(wid)
    return {"baselines": rows}, 200


def api_payloads():
    """GET /api/payloads — list safe registered payload metadata."""
    # The registry class is PayloadDispatch (the old import named a PayloadRegistry
    # class that never existed, so this route always answered 500). Metadata only:
    # raw payload values are deliberately not exposed here.
    try:
        from ..payloads.registry import PayloadDispatch
        payloads = [
            {
                "id": p.id,
                "name": p.id,
                "payload_class": p.risk_class.name,
                "risk_class": p.risk_class.value,
                "auto_dispatch_allowed": p.risk_class.name not in (
                    "EXFILTRATION", "DESTRUCTIVE", "STATE_MUTATE"),
                "encoding": "none",
                "description": p.description,
                "tags": sorted(p.tags),
                "created_at": "",
            }
            for p in PayloadDispatch().all_payloads()
        ]
        return {"payloads": payloads, "count": len(payloads)}, 200
    except Exception as exc:
        return {"error": str(exc)}, 500


def api_ml_readiness():
    """GET /api/ml-readiness — ML readiness status (never trains a model)."""
    svc = _canonical_svc()
    if svc is None:
        return {
            "status": "not_ready_for_training",
            "model_trained": False,
            "ml_probability_modified": False,
            "blockers": ["no workspace loaded"],
            "notes": [],
        }, 200
    return svc.ml_readiness_status(), 200


# Regex matchers for parametric V5 routes
_RE_FINDING = re.compile(r"^/api/findings/([^/]+)$")
_RE_FINDING_EVIDENCE = re.compile(r"^/api/findings/([^/]+)/evidence$")
_RE_FINDING_REPORT = re.compile(r"^/api/findings/([^/]+)/report$")
_RE_FINDING_REVIEW = re.compile(r"^/api/findings/([^/]+)/review$")
_RE_OBSERVATION = re.compile(r"^/api/observations/([^/]+)$")


class Handler(BaseHTTPRequestHandler):
    server_version = "RavenLocal/0.1"
    protocol_version = "HTTP/1.1"  # keep-alive; every response sets Content-Length
    max_request_body = 4 * 1024 * 1024
    body_read_timeout = 10.0       # total deadline, not a timeout renewed per byte
    timeout = 10.0                 # bound idle/header reads on each connection

    def send_response(self, code, message=None):
        self._raven_responded = True
        return super().send_response(code, message)

    def _guarded(self, impl):
        """Last-resort guard: an unexpected exception in a route (e.g. a wrong-typed JSON
        field such as {"message": 5}) used to drop the socket with no response. Now the
        client always gets a JSON error and the connection is closed."""
        self._raven_responded = False
        try:
            return impl()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as exc:
            import traceback as _tb
            _tb.print_exc()
            self.close_connection = True
            if not self._raven_responded:
                bad_input = isinstance(exc, (TypeError, ValueError))
                try:
                    self._send_json({"error": ("invalid request: " if bad_input else "internal error: ")
                                     + f"{type(exc).__name__}"}, 400 if bad_input else 500)
                except Exception:
                    pass

    def handle_expect_100(self):
        # BaseHTTPRequestHandler otherwise sends Continue before token/Origin checks.
        # Defer it until the route has authorized the request and will read its body.
        return True

    def parse_request(self):
        self._body_length = 0
        self._body_consumed = False
        if not super().parse_request():
            return False
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding", []):
            # Chunked framing is deliberately unsupported; never leave chunks to be
            # interpreted as the next request (including TE + Content-Length).
            self._reject("transfer encoding is unsupported", 501)
            return False
        if len(lengths) > 1 or (lengths and not re.fullmatch(r"[0-9]+", lengths[0])):
            self._reject("invalid content length", 400)
            return False
        if lengths:
            # Check digit count before int(): absurd values must also get a response.
            digits = lengths[0].lstrip("0") or "0"
            if len(digits) > len(str(self.max_request_body)):
                self._reject("request body too large", 413)
                return False
            self._body_length = int(digits)
        if self._body_length > self.max_request_body:
            self._reject("request body too large", 413)
            return False
        self._body_consumed = self._body_length == 0
        expectations = self.headers.get_all("Expect", [])
        if expectations and (len(expectations) != 1 or expectations[0].lower() != "100-continue"):
            self._reject("unsupported expectation", 417)
            return False
        return True

    def _reject(self, message, code):
        # Refuse untrusted/incomplete framing without waiting for bytes from a client.
        self.close_connection = True
        self._send_json({"error": message}, code)
        # Send the response and FIN before closing a socket with unread input. This
        # avoids losing the rejection to a TCP reset when the client sends its body
        # just after the headers (notably on Windows).
        try:
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
            # Windows can still reset a half-closed socket when a client's body is
            # in flight. Briefly discard input AFTER sending the rejection. Bound
            # both time and bytes; never parse it as another request or await a full
            # untrusted Content-Length.
            deadline = time.monotonic() + 0.1
            remaining = min(getattr(self, "_body_length", 0) or 65536, 65536)
            while remaining and time.monotonic() < deadline:
                self.connection.settimeout(max(0.001, deadline - time.monotonic()))
                chunk = self.rfile.read1(remaining)
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass

    def _send_json(self, obj, code=200):
        if not getattr(self, "_body_consumed", True):
            self.close_connection = True
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Live workspace data: never served from a browser/WebView cache.
        self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        if self._body_consumed:
            return b""
        if self.headers.get("Expect", "").lower() == "100-continue":
            self.send_response_only(100)
            self.end_headers()
        deadline = time.monotonic() + self.body_read_timeout
        previous_timeout = self.connection.gettimeout()
        remaining = self._body_length
        chunks = []
        try:
            while remaining:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    raise TimeoutError
                self.connection.settimeout(wait)
                # read1 performs at most one socket read, so a trickling client cannot
                # extend the total deadline. Never read into the next request.
                chunk = self.rfile.read1(min(remaining, 64 * 1024))
                if not chunk:
                    self._reject("incomplete request body", 400)
                    return None
                chunks.append(chunk)
                remaining -= len(chunk)
        except TimeoutError:
            self._reject("request body timed out", 408)
            return None
        except OSError:
            self._reject("incomplete request body", 400)
            return None
        finally:
            self.connection.settimeout(previous_timeout)
        self._body_consumed = True
        return b"".join(chunks)

    def _read_json(self):
        raw = self._read_body()
        if raw is None:
            return None
        try:
            payload = json.loads(raw or b"{}")
        except (ValueError, UnicodeError, RecursionError):
            self._send_json({"error": "invalid JSON body"}, 400)
            return None
        if not isinstance(payload, dict):
            self._send_json({"error": "JSON body must be an object"}, 400)
            return None
        return payload

    def _authed(self):
        tokens = self.headers.get_all("X-RAVEN-Token", [])
        return len(tokens) == 1 and secrets.compare_digest(
            tokens[0].encode("utf-8"), SESSION_TOKEN.encode("ascii"))

    def _origin_allowed(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True  # non-browser client or same-origin navigation
        port = self.server.server_address[1]
        return origin in (f"http://127.0.0.1:{port}", f"http://localhost:{port}")

    def _host_allowed(self):
        """Reject requests whose Host is not loopback. Defends against a rebound
        attacker domain (evil.com -> 127.0.0.1) being used to reach this API."""
        hosts = self.headers.get_all("Host", [])
        if not hosts:
            return self.request_version == "HTTP/1.0"
        if len(hosts) != 1:
            return False
        try:
            host = urlsplit("//" + hosts[0])
            return (not host.username and not host.password and not host.path
                    and not host.query and not host.fragment
                    and host.hostname in ("127.0.0.1", "localhost", "::1")
                    and (host.port is None or 0 < host.port <= 65535))
        except ValueError:
            return False

    def do_GET(self):
        return self._guarded(self._do_GET_impl)

    def _do_GET_impl(self):
        if not self._host_allowed():
            return self._reject("bad host", 403)
        path = urlsplit(self.path).path
        if path.startswith("/api/") and path != "/api/health" and not self._authed():
            return self._reject("unauthorized", 403)
        if self._read_body() is None:
            return
        if path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/api/health":
            return self._send_json({"ok": True, "service": "raven-local"})
        if path == "/api/ai/status":
            return self._send_json(_ai_status_dict())
        # ── V7 Subsystem GET routes ──────────────────────────────────────
        if path == "/api/v7/status":
            return self._send_json(api_comprehensive_status())
        if path == "/api/v7/system/resources":
            return self._send_json(api_system_resources())
        if path == "/api/v7/terminal/status":
            return self._send_json(api_terminal_status())
        if path == "/api/v7/terminal/history":
            data, code = api_terminal_history()
            return self._send_json(data, code)
        if path == "/api/v7/workspace":
            data, code = api_workspace_list()
            return self._send_json(data, code)
        if path == "/api/v7/workspace/current":
            data, code = api_workspace_current()
            return self._send_json(data, code)
        if path == "/api/v7/tasks":
            data, code = api_tasks_list()
            return self._send_json(data, code)
        if path == "/api/v7/settings":
            data, code = api_settings_get()
            return self._send_json(data, code)
        if path == "/api/v7/native/models":
            data, code = api_native_models_list()
            return self._send_json(data, code)
        if path == "/api/v7/plugins":
            data, code = api_plugins_list()
            return self._send_json(data, code)
        if path == "/api/v7/knowledge":
            data, code = api_knowledge_list()
            return self._send_json(data, code)
        if path == "/api/v7/learning":
            data, code = api_learning_get()
            return self._send_json(data, code)
        if path == "/api/v7/ravensec/status":
            data, code = api_ravensec_status()
            return self._send_json(data, code)
        if path == "/api/v7/claude/status":
            data, code = api_claude_status()
            return self._send_json(data, code)
        if path == "/api/v7/claude/agent":
            return self._send_json({"runs": _claude_agents().list()}, 200)
        _m_cl = _RE_CL_AGENT.fullmatch(path)
        if _m_cl:
            data, code = api_claude_agent_get(_m_cl.group(1))
            return self._send_json(data, code)
        _m_cl = _RE_CL_AGENT_FILE.fullmatch(path)
        if _m_cl:
            from urllib.parse import parse_qs as _pqs
            data, code = api_claude_agent_file(_m_cl.group(1),
                                               (_pqs(urlsplit(self.path).query).get("name") or [""])[0])
            return self._send_json(data, code)
        if path == "/api/v7/ravensec/agent":
            return self._send_json({"runs": _ravensec_agents().list()}, 200)
        _m_rs = _RE_RS_AGENT.fullmatch(path)
        if _m_rs:
            data, code = api_ravensec_agent_get(_m_rs.group(1))
            return self._send_json(data, code)
        _m_rs = _RE_RS_AGENT_FILE.fullmatch(path)
        if _m_rs:
            from urllib.parse import parse_qs as _pqs
            _name = (_pqs(urlsplit(self.path).query).get("name") or [""])[0]
            data, code = api_ravensec_agent_file(_m_rs.group(1), _name)
            return self._send_json(data, code)
        if path == "/api/v7/techniques":
            data, code = api_techniques_list()
            return self._send_json(data, code)
        if path == "/api/v7/evidence":
            data, code = api_evidence_list()
            return self._send_json(data, code)
        if path == "/api/v7/traffic":
            data, code = api_traffic_list()
            return self._send_json(data, code)
        if path.startswith("/api/v7/tasks/") and path.endswith("/cancel"):
            task_id = path[len("/api/v7/tasks/"):-len("/cancel")]
            data, code = api_tasks_cancel(task_id)
            return self._send_json(data, code)
        _m_agent_run = _RE_AGENT_RUN.fullmatch(path)
        if _m_agent_run:
            data, code = api_agent_get(_m_agent_run.group(1))
            return self._send_json(data, code)
        # ── end V7 Subsystem GET routes ──────────────────────────────────
        if path.startswith("/api/"):
            if path == "/api/scope":
                with _LOCK:
                    result = scope_dict()
                return self._send_json(result)
            if path == "/api/identity":
                with _LOCK:
                    result = identity_dict()
                return self._send_json(result)
            if path == "/api/xss-verify-isolation":
                return self._send_json(do_xss_verify_isolation())
            if path in ("/api/assets", "/api/urls", "/api/changes", "/api/runs", "/api/summary"):
                # Store is internally synchronised — no blanket lock, so reads stay
                # responsive even while a collection is running (its I/O holds no lock).
                try:
                    data = {
                        "/api/assets": data_assets, "/api/urls": data_urls,
                        "/api/changes": data_changes, "/api/summary": data_summary,
                        "/api/runs": lambda: STATE["store"].runs() if STATE.get("store") else [],
                    }[path]()
                except Exception:
                    # A store read failure must still send a framed response, never drop
                    # the socket mid-request and let the next request misread the stream.
                    return self._send_json({"error": "workspace data could not be read"}, 500)
                return self._send_json(data)
            if path == "/api/jobs":  # Wave 3 step 5: delegate to runtime scheduler
                return self._send_json({"jobs": RUNTIME.scheduler.list(), "stats": RUNTIME.scheduler.stats()})
            if path == "/api/scheduler":
                return self._send_json(RUNTIME.scheduler.stats())
            if path.startswith("/api/jobs/"):
                job = RUNTIME.scheduler.get(path[len("/api/jobs/"):])
                return self._send_json(job) if job else self._send_json({"error": "not found"}, 404)
            # V5-19: canonical data routes
            from urllib.parse import parse_qs, urlsplit as _us
            _params = parse_qs(_us(self.path).query)
            if path == "/api/findings":
                data, code = api_findings(_params)
                return self._send_json(data, code)
            if path == "/api/report":
                data, code = api_workspace_report()
                return self._send_json(data, code)
            if path == "/api/observations":
                data, code = api_observations(_params)
                return self._send_json(data, code)
            if path == "/api/baselines":
                data, code = api_baselines()
                return self._send_json(data, code)
            if path == "/api/payloads":
                data, code = api_payloads()
                return self._send_json(data, code)
            if path == "/api/ml-readiness":
                data, code = api_ml_readiness()
                return self._send_json(data, code)
            m = _RE_FINDING.fullmatch(path)
            if m:
                data, code = api_finding_detail(m.group(1))
                return self._send_json(data, code)
            m = _RE_FINDING_EVIDENCE.fullmatch(path)
            if m:
                data, code = api_finding_evidence(m.group(1))
                return self._send_json(data, code)
            m = _RE_FINDING_REPORT.fullmatch(path)
            if m:
                data, code = api_finding_report(m.group(1))
                return self._send_json(data, code)
            m = _RE_OBSERVATION.fullmatch(path)
            if m:
                data, code = api_observation_detail(m.group(1))
                return self._send_json(data, code)
            return self._send_json({"error": "not found"}, 404)
        return self._serve_static(path)

    def do_PUT(self):
        return self._guarded(self._do_PUT_impl)

    def _do_PUT_impl(self):
        if not self._host_allowed():
            return self._reject("bad host", 403)
        if not (self._authed() and self._origin_allowed()):
            return self._reject("unauthorized", 403)
        payload = self._read_json()
        if payload is None:
            return
        put_path = urlsplit(self.path).path
        if put_path == "/api/scope":
            try:
                with _LOCK:
                    result = set_scope(payload)
                return self._send_json(result)
            except (ValueError, TypeError) as exc:
                return self._send_json({"error": str(exc)}, 400)
            except OSError:
                return self._send_json({"error": "Workspace settings could not be saved; previous workspace retained"}, 503)
        if put_path == "/api/identity":
            try:
                return self._send_json(set_identity(payload))
            except (ValueError, TypeError) as exc:
                return self._send_json({"error": str(exc)}, 400)
            except OSError:
                return self._send_json({"error": "Identity settings could not be saved; previous identity retained"}, 503)
        self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        return self._guarded(self._do_POST_impl)

    def _do_POST_impl(self):
        if not self._host_allowed():
            return self._reject("bad host", 403)
        if not (self._authed() and self._origin_allowed()):
            return self._reject("unauthorized", 403)
        payload = self._read_json()
        if payload is None:
            return
        path = urlsplit(self.path).path
        fixed = ("/api/send", "/api/collect", "/api/import", "/api/access-check",
                 "/api/xss-check", "/api/xss-verify-isolation", "/api/emergency-stop",
                 "/api/clear-stop", "/api/reset-budget", "/api/chat",
                 "/api/v7/terminal/run", "/api/v7/terminal/cancel",
                 "/api/v7/workspace/switch",
                 "/api/v7/workspace/create", "/api/v7/settings",
                 "/api/v7/native/select",
                 "/api/v7/knowledge", "/api/v7/evidence/note",
                 "/api/v7/agent/run", "/api/v7/program/run",
                 "/api/v7/learning/assess")
        is_job_action = re.fullmatch(r"/api/jobs/([^/]+)/(cancel|pause|resume)", path)
        is_agent_action = _RE_AGENT_ACTION.fullmatch(path)
        # V5-19: parametric POST routes
        _m_review = _RE_FINDING_REVIEW.fullmatch(path)
        if _m_review:
            data, code = api_finding_review(_m_review.group(1), payload)
            return self._send_json(data, code)
        # RAVEN-Sec (authenticated + Origin-checked like every POST above)
        if path == "/api/v7/ravensec/search":
            data, code = api_ravensec_search(payload)
            return self._send_json(data, code)
        if path == "/api/v7/ravensec/read":
            data, code = api_ravensec_read(payload)
            return self._send_json(data, code)
        if path == "/api/v7/ravensec/agent":
            data, code = api_ravensec_agent_start(payload)
            return self._send_json(data, code)
        # Claude (authenticated + Origin-checked like every POST above)
        if path == "/api/v7/claude/key":
            data, code = api_claude_key_save(payload)
            return self._send_json(data, code)
        if path == "/api/v7/claude/key/delete":
            data, code = api_claude_key_delete()
            return self._send_json(data, code)
        if path == "/api/v7/claude/test":
            data, code = api_claude_test()
            return self._send_json(data, code)
        if path == "/api/v7/claude/settings":
            data, code = api_claude_settings(payload)
            return self._send_json(data, code)
        if path == "/api/v7/claude/agent":
            data, code = api_claude_agent_start(payload)
            return self._send_json(data, code)
        _m_cl = _RE_CL_AGENT_ACTION.fullmatch(path)
        if _m_cl:
            data, code = api_claude_agent_action(_m_cl.group(1), _m_cl.group(2), payload)
            return self._send_json(data, code)
        _m_rs = _RE_RS_AGENT_ACTION.fullmatch(path)
        if _m_rs:
            data, code = api_ravensec_agent_action(_m_rs.group(1), _m_rs.group(2), payload)
            return self._send_json(data, code)
        if path not in fixed and not is_job_action and not is_agent_action:
            return self._send_json({"error": "not found"}, 404)
        if path == "/api/chat":
            data, code = api_chat(payload)
            return self._send_json(data, code)
        # ── V7 Subsystem POST routes ──────────────────────────────────────
        if path == "/api/v7/terminal/run":
            data, code = api_terminal_run(payload)
            return self._send_json(data, code)
        if path == "/api/v7/terminal/cancel":
            data, code = api_terminal_cancel(payload)
            return self._send_json(data, code)
        if path == "/api/v7/workspace/switch":
            data, code = api_workspace_switch(payload)
            return self._send_json(data, code)
        if path == "/api/v7/workspace/create":
            data, code = api_workspace_create(payload)
            return self._send_json(data, code)
        if path == "/api/v7/settings":
            data, code = api_settings_update(payload)
            return self._send_json(data, code)
        if path == "/api/v7/native/select":
            data, code = api_native_select(payload)
            return self._send_json(data, code)
        if path == "/api/v7/knowledge":
            data, code = api_knowledge_store(payload)
            return self._send_json(data, code)
        if path == "/api/v7/evidence/note":
            data, code = api_evidence_note(payload)
            return self._send_json(data, code)
        if path == "/api/v7/agent/run":
            data, code = api_agent_run(payload)
            return self._send_json(data, code)
        if is_agent_action:
            data, code = api_agent_decision(is_agent_action.group(1),
                                            is_agent_action.group(2), payload)
            return self._send_json(data, code)
        if path == "/api/v7/program/run":
            data, code = api_program_run(payload)
            return self._send_json(data, code)
        if path == "/api/v7/learning/assess":
            data, code = api_learning_assess(payload)
            return self._send_json(data, code)
        # ── end V7 Subsystem POST routes ──────────────────────────────────
        if path == "/api/send":  # network only, no shared DB — safe unlocked
            # Wave 3 step 5: route delegates to the runtime's sender service. Identical
            # to calling do_send directly (SenderService.send → server.do_send).
            _tok = _REQUEST_CONTEXT.set(_capture_context())  # one workspace for send + record
            try:
                _send_result = RUNTIME.sender.send(payload)
                _post_send_canonical(_send_result, payload)  # V5-04
            finally:
                _REQUEST_CONTEXT.reset(_tok)
            return self._send_json(_send_result)
        if path == "/api/access-check":  # network only, no shared DB
            return self._send_json(do_access_check(payload))
        if path == "/api/xss-check":  # network only, no shared DB
            return self._send_json(do_xss_check(payload))
        if path == "/api/xss-verify-isolation":
            # Compatibility route reports the quarantine; it launches nothing.
            return self._send_json(do_xss_verify_isolation())
        if path == "/api/collect":
            # Non-blocking: hand the collection to the central scheduler and return a
            # job_id. The scheduler bounds concurrency, rate-limits per host, and makes
            # the run cancellable/pausable. The UI polls /api/jobs/<id> for progress.
            from .scheduler import SchedulerStopped, QueueFull
            try:
                result = submit_collect(
                    payload.get("passive", True), payload.get("probe", True),
                    payload.get("rate"), payload.get("budget"),
                    discover=payload.get("discover", False))
            except (ValueError, TypeError):
                return self._send_json({"error": "invalid collection settings"}, 400)
            except SchedulerStopped:
                return self._send_json({"error": "collection scheduler is stopped"}, 409)
            except QueueFull:
                return self._send_json({"error": "collection queue is full"}, 503)
            return self._send_json(result)
        if path == "/api/emergency-stop":
            # Wave 6 (A6-TERM): unify the two stops. The live emergency stop now also
            # trips the process-wide PolicyGate flag, so every subsequent capability
            # decision AND every ProcessExecutor spawn (terminal/process plane) is
            # refused — not only the scheduler's outbound sends. Response shape frozen.
            _PolicyGate.trigger_emergency_stop()
            stopped = SCHEDULER.emergency_stop()
            if _RAVENSEC_AGENTS is not None:  # research agents stop too (pending actions void)
                _RAVENSEC_AGENTS.cancel_all()
            if _CLAUDE_AGENTS is not None:    # and Claude agent runs
                _CLAUDE_AGENTS.cancel_all()
            # Running terminal/process-plane commands are killed too (not only new
            # spawns refused) — a Stop must stop what is already running.
            if _PROCESS_EXECUTOR is not None:
                try:
                    _PROCESS_EXECUTOR.cancel_all()
                except Exception:
                    pass
            return self._send_json({"stopped": stopped})
        if path == "/api/clear-stop":  # re-enable scheduling after an Emergency Stop
            try:
                SCHEDULER.clear_stop()
            except SchedulerStopped as exc:  # only after a full shutdown; report, don't drop
                return self._send_json({"error": str(exc)}, 409)
            # Resume restores the terminal/knowledge/agent capabilities as well; the
            # PolicyGate flag used to stay set until the process restarted.
            _PolicyGate.clear_emergency_stop()
            return self._send_json({"stopped": False})
        if path == "/api/reset-budget":
            # Explicit, user-authorized replenishment of THIS workspace's shared
            # request budget. Refused while ANY of its work is active — a scheduled
            # job OR an in-flight manual request (Repeater/Intruder/curl/ACL/XSS) —
            # so it can never silently reset a limit mid-request. Never touches
            # Emergency Stop and never resurrects a cancelled job. An invalid budget
            # NUMBER (400) is reported distinctly from a BUSY workspace (409).
            key = _capture_context().workspace_key
            try:
                SCHEDULER.reset_workspace_budget(key, payload.get("budget"))
            except (ValueError, TypeError) as exc:
                return self._send_json({"error": f"invalid budget value: {exc}"}, 400)
            except WorkspaceBusy as exc:
                return self._send_json({"error": str(exc)}, 409)
            return self._send_json({"reset": True, "workspace_budgets": SCHEDULER.stats()["workspace_budgets"]})
        if is_job_action:
            jid, action = is_job_action.groups()
            ok = {"cancel": SCHEDULER.cancel, "pause": SCHEDULER.pause,
                  "resume": SCHEDULER.resume}[action](jid)
            return self._send_json({"ok": ok, "job": SCHEDULER.get(jid)}, 200 if ok else 404)
        if path == "/api/import":
            try:
                return self._send_json(do_import(payload.get("items", [])))
            except (ValueError, TypeError) as exc:
                return self._send_json({"error": str(exc)}, 400)
            except Exception:
                # A store/disk failure (sqlite3.Error, OSError, …) must still send a
                # framed response and close the connection, never drop it mid-request
                # and leave the body for the next request on the socket to misread.
                self.close_connection = True
                return self._send_json({"error": "import failed; the workspace store could not be written"}, 500)

    # Token-bearing pages: the RAVEN OS shell and the recon Workbench (the V5 UI that
    # drives the real engine: scope, surface, endpoints, changes, runs, Repeater,
    # Intruder, Decoder, Access Control, XSS lab). Both are same-origin, loopback
    # only, and get the per-run token inlined exactly like before.
    _PAGES = {"/": "index.html", "/index.html": "index.html",
              "/workbench": "prototype.html", "/prototype.html": "prototype.html"}

    def _serve_static(self, path):
        base = WEB.resolve()
        page = self._PAGES.get(path)
        is_page = page is not None
        if is_page:
            target = base / page
        else:
            target = (base / path.lstrip("/")).resolve()
            if base != target and base not in target.parents:
                return self._send_json({"error": "forbidden"}, 403)
        if not target.is_file():
            return self._send_json({"error": "not found"}, 404)
        data = target.read_bytes()
        if is_page:  # inline the session token so same-origin JS can authenticate
            token = f'<script>window.RAVEN_TOKEN={json.dumps(SESSION_TOKEN)};</script>'
            data = data.replace(b"</head>", token.encode("utf-8") + b"</head>", 1)
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if is_page:
            # The page embeds this run's session token and must reflect the installed
            # UI version — never let the WebView/browser cache serve a stale copy.
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"[raven] {self.address_string()} {fmt % args}")


def _reconfigure_stdout():
    try:  # keep prints working on Windows consoles that default to cp1252
        import sys
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _port_in_use(host, port):
    """True if something is already accepting connections on host:port. A connect
    probe is used because Windows SO_REUSEADDR would otherwise let a second bind
    succeed on an actively-listening port."""
    probe = socket.socket()
    probe.settimeout(0.3)
    try:
        probe.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _bind(host, port):
    """Bind to the first free port in [port, port+10); returns (httpd, port).
    Avoids a hard crash when the preferred port is already in use."""
    last = None
    for candidate in range(port, port + 10):
        if _port_in_use(host, candidate):
            last = OSError(f"port {candidate} already in use")
            continue
        try:
            return ThreadingHTTPServer((host, candidate), Handler), candidate
        except OSError as exc:
            last = exc
    raise OSError(f"no free port in {port}..{port + 9}: {last}")


def start_background(host="127.0.0.1", port=None):
    """Prepare state, bind (with fallback), and serve on a daemon thread.
    Returns (httpd, port). The socket is listening before this returns, so the
    desktop launcher needs no arbitrary sleep. Used by launch.py."""
    _reconfigure_stdout()
    port = int(port or os.environ.get("PORT", 8765))
    _load_settings()   # sweep B §7: a saved Settings/native selection survives restart
    _restore_workspace()
    httpd, port = _bind(host, port)
    STATE["port"] = port  # actual bound port, used by the Origin allow-list
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


def serve(host="127.0.0.1", port=None):
    _reconfigure_stdout()
    port = int(port or os.environ.get("PORT", 8765))
    _load_settings()   # sweep B §7: a saved Settings/native selection survives restart
    _restore_workspace()
    httpd, port = _bind(host, port)
    STATE["port"] = port
    print(f"RAVEN local server -> http://{host}:{port}  (scope: {STATE['scope'].include})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        shutdown_background_work(wait=False)
        httpd.server_close()
