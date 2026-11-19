"""The one place RAVEN calls the Anthropic Messages API.

* Model: Claude Opus 5.5 (``claude-opus-5-5``). Thinking is always on for this model; depth
  is set with ``output_config.effort`` (agent ``high``, chat ``medium``).
* Server-side refusal fallback (``fallbacks: "default"``): when the safety classifiers
  decline a turn, the API re-runs it on a fallback model inside the same call. A final
  ``stop_reason == "refusal"`` means the whole chain declined — RAVEN shows that honestly.
* Automatic prompt caching (top-level ``cache_control``) — the agent re-sends a long,
  stable prefix every turn.
* Cost is estimated from ``usage`` at Opus 5.5 list prices (≈; a fallback turn is billed
  at the fallback model's own rates).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import MODEL
from .keystore import KeyStore, hint

FALLBACK_BETA = "server-side-fallback-2026-07-01"
# USD per million tokens (Claude Opus 5.5 list prices)
PRICE_IN, PRICE_OUT, PRICE_CACHE_READ, PRICE_CACHE_WRITE = 4.00, 20.00, 0.20, 5.00


class ClaudeUnavailable(RuntimeError):
    """No usable credentials / SDK."""


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read: int = 0
    cache_write: int = 0
    requests: int = 0

    def add(self, u: Any) -> None:
        if u is None:
            return
        self.input_tokens += int(getattr(u, "input_tokens", 0) or 0)
        self.output_tokens += int(getattr(u, "output_tokens", 0) or 0)
        self.cache_read += int(getattr(u, "cache_read_input_tokens", 0) or 0)
        self.cache_write += int(getattr(u, "cache_creation_input_tokens", 0) or 0)
        self.requests += 1

    @property
    def cost_usd(self) -> float:
        return round((self.input_tokens * PRICE_IN + self.output_tokens * PRICE_OUT
                      + self.cache_read * PRICE_CACHE_READ + self.cache_write * PRICE_CACHE_WRITE) / 1e6, 4)

    def as_dict(self) -> Dict[str, Any]:
        return {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "cache_read_tokens": self.cache_read, "cache_write_tokens": self.cache_write,
                "requests": self.requests, "cost_usd": self.cost_usd}


def credential_source(store: KeyStore) -> Optional[str]:
    """'saved' (RAVEN's encrypted key), 'environment' (ANTHROPIC_API_KEY / AUTH_TOKEN), or None."""
    if store.configured():
        return "saved"
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return "environment"
    return None


def make_client(store: KeyStore):
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - dependency is in requirements
        raise ClaudeUnavailable("The 'anthropic' Python package is not installed.") from exc
    key = store.load()
    if key:
        return anthropic.Anthropic(api_key=key, max_retries=2, timeout=600.0)
    if credential_source(store) == "environment":
        return anthropic.Anthropic(max_retries=2, timeout=600.0)
    raise ClaudeUnavailable("No Anthropic API key configured — add one in Settings → Claude.")


def create(client, *, system: Any, messages: List[dict], tools: Optional[List[dict]] = None,
           max_tokens: int = 16000, effort: str = "high"):
    kw: Dict[str, Any] = dict(
        model=MODEL, max_tokens=max_tokens, system=system, messages=messages,
        output_config={"effort": effort},
        cache_control={"type": "ephemeral"},
        betas=[FALLBACK_BETA], fallbacks="default",
    )
    if tools:
        kw["tools"] = tools
    return client.beta.messages.create(**kw)


def refusal_info(resp) -> Optional[Dict[str, Optional[str]]]:
    if getattr(resp, "stop_reason", None) != "refusal":
        return None
    d = getattr(resp, "stop_details", None)
    return {"category": getattr(d, "category", None), "explanation": getattr(d, "explanation", None)}


def served_by(resp) -> Optional[str]:
    """The model that actually answered when a fallback took over (else None)."""
    for b in getattr(resp, "content", None) or []:
        if getattr(b, "type", None) == "fallback":
            to = getattr(b, "to", None)
            return getattr(to, "model", None)
    return None


def text_of(resp) -> str:
    return "\n".join(b.text for b in (getattr(resp, "content", None) or [])
                     if getattr(b, "type", None) == "text" and getattr(b, "text", None)).strip()


def friendly_error(exc: BaseException) -> str:
    """Typed error chain → a message the operator can act on (never includes the key)."""
    try:
        import anthropic
    except ImportError:
        return f"{type(exc).__name__}: {exc}"
    rid = getattr(getattr(exc, "response", None), "headers", {}) or {}
    rid = rid.get("request-id") if hasattr(rid, "get") else None
    suffix = f" (request id {rid})" if rid else ""
    if isinstance(exc, anthropic.AuthenticationError):
        return "The Anthropic API key was rejected (401) — check or replace it in Settings → Claude."
    if isinstance(exc, anthropic.PermissionDeniedError):
        return "This API key is not allowed to use this model or feature (403)." + suffix
    if isinstance(exc, anthropic.NotFoundError):
        return f"Model {MODEL} is not available to this account (404)." + suffix
    if isinstance(exc, anthropic.RateLimitError):
        ra = exc.response.headers.get("retry-after") if getattr(exc, "response", None) is not None else None
        return f"Rate limited by the Anthropic API (429){f', retry after {ra}s' if ra else ''}." + suffix
    if isinstance(exc, anthropic.BadRequestError):
        return f"The API rejected the request (400): {getattr(exc, 'message', exc)}" + suffix
    if isinstance(exc, anthropic.APITimeoutError):
        return "The Anthropic API timed out."
    if isinstance(exc, anthropic.APIStatusError):
        return f"Anthropic API error {exc.status_code}: {getattr(exc, 'message', '')}" + suffix
    if isinstance(exc, anthropic.APIConnectionError):
        return "Could not reach the Anthropic API — check the internet connection."
    return f"{type(exc).__name__}: {exc}"


def test_connection(store: KeyStore) -> Dict[str, Any]:
    """One tiny request to prove the key + model work. Never returns the key."""
    try:
        client = make_client(store)
        resp = create(client, system="Reply with the single word OK.",
                      messages=[{"role": "user", "content": "ping"}], max_tokens=64, effort="low")
        u = Usage()
        u.add(getattr(resp, "usage", None))
        return {"ok": True, "model": getattr(resp, "model", MODEL), "stop_reason": resp.stop_reason,
                "reply": text_of(resp)[:40], "request_id": getattr(resp, "_request_id", None),
                "cost_usd": u.cost_usd}
    except ClaudeUnavailable as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "error": friendly_error(exc)}


def status(store: KeyStore) -> Dict[str, Any]:
    src = credential_source(store)
    try:
        import anthropic  # noqa: F401
        sdk = True
    except ImportError:
        sdk = False
    return {"configured": src is not None, "source": src,
            "key_hint": hint(store.load()) if src == "saved" else None,
            "model": MODEL, "sdk_installed": sdk}
