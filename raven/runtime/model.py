"""RAVEN V7 Model Service — Provider Abstraction (Bootstrap Layer).

Establishes the shared model abstraction without binding to one provider (§118-121).
Part 03 (V7-A) will implement real providers (Ollama, llama.cpp, LM Studio).

INVARIANTS:
- CompletionResult.is_advisory = True always (§350 Constitution Article XIX)
- Provider failure must be explicit — never fabricate a response (§121)
- Model output is UNTRUSTED INPUT — callers must validate (§168-169)
- No model may set task status to COMPLETED or mark findings verified
"""
from __future__ import annotations

import enum
import json as _json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional


class ModelCapability(str, enum.Enum):
    CHAT              = "CHAT"
    CODING            = "CODING"
    TOOL_CALLING      = "TOOL_CALLING"
    STRUCTURED_OUTPUT = "STRUCTURED_OUTPUT"
    MULTILINGUAL      = "MULTILINGUAL"
    VISION            = "VISION"
    LONG_CONTEXT      = "LONG_CONTEXT"
    EMBEDDING         = "EMBEDDING"


class ProviderType(str, enum.Enum):
    OLLAMA              = "OLLAMA"
    LLAMA_CPP           = "LLAMA_CPP"
    LM_STUDIO           = "LM_STUDIO"
    OPENAI_COMPATIBLE   = "OPENAI_COMPATIBLE_LOCAL"
    MOCK                = "MOCK"
    # Phase-4 (P4-NATIVE-CHAT): RAVEN's OWN from-scratch generative model (RAVEN-LM).
    # FIRST-PARTY (not third-party like Ollama). Still ADDITIVE + OFF until a checkpoint
    # is EXPLICITLY selected; local-only inference (no network / no Ollama).
    NATIVE              = "RAVEN_NATIVE"
    # Claude via the Anthropic API — enabled only when the operator saves an API key.
    ANTHROPIC           = "ANTHROPIC"


class ProviderStatus(str, enum.Enum):
    AVAILABLE   = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED    = "DEGRADED"
    UNKNOWN     = "UNKNOWN"


class ModelStatus(str, enum.Enum):
    READY    = "READY"
    LOADING  = "LOADING"
    NOT_FOUND = "NOT_FOUND"
    FAILED   = "FAILED"
    UNKNOWN  = "UNKNOWN"


class ModelFailureKind(str, enum.Enum):
    PROVIDER_UNAVAILABLE     = "PROVIDER_UNAVAILABLE"
    MODEL_NOT_FOUND          = "MODEL_NOT_FOUND"
    TIMEOUT                  = "TIMEOUT"
    INVALID_RESPONSE         = "INVALID_RESPONSE"
    CONTEXT_LIMIT            = "CONTEXT_LIMIT"
    STRUCTURED_OUTPUT_FAILURE = "STRUCTURED_OUTPUT_FAILURE"
    CANCELLED                = "CANCELLED"
    # Wave 13 (A13-NATIVE): the honest signal that RAVEN ships NO native generative
    # model and no optional external provider is enabled — distinct from
    # PROVIDER_UNAVAILABLE ("an enabled external provider is unreachable"). RAVEN must
    # not depend on any generative model at runtime; this is the truthful "nothing is
    # turned on" state, never a fabricated response. (NATIVE_AI_FOUNDATION §3.1,
    # CANONICAL_ARCHITECTURE §1 row 22.) The low-level ModelService.complete keeps
    # returning PROVIDER_UNAVAILABLE for a bare provider-less service (characterized by
    # test_v7_bootstrap); this product-level distinction is drawn in the chat layer
    # (ChatSession.send) from whether any provider is registered.
    NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE = "NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE"


@dataclass
class ModelDefinition:
    model_id:             str
    provider_id:          str
    display_name:         str
    capabilities:         List[ModelCapability] = field(default_factory=list)
    context_window:       Optional[int] = None
    status:               ModelStatus = ModelStatus.UNKNOWN
    structured_output:    bool = False
    tool_calling:         bool = False
    vision:               bool = False
    embedding:            bool = False
    language_capabilities: List[str] = field(default_factory=list)
    metadata:             Dict = field(default_factory=dict)

    def supports(self, capability: ModelCapability) -> bool:
        return capability in self.capabilities

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "provider_id": self.provider_id,
            "display_name": self.display_name,
            "capabilities": [c.value for c in self.capabilities],
            "context_window": self.context_window,
            "status": self.status.value,
        }


@dataclass
class ModelProvider:
    provider_id:   str
    provider_type: ProviderType
    display_name:  str
    endpoint:      str = ""
    status:        ProviderStatus = ProviderStatus.UNKNOWN
    models:        List[ModelDefinition] = field(default_factory=list)
    configuration: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "provider_type": self.provider_type.value,
            "display_name": self.display_name,
            "endpoint": self.endpoint,
            "status": self.status.value,
            "model_count": len(self.models),
        }


@dataclass
class ModelMessage:
    role:    str   # "user" / "assistant" / "system" / "tool"
    content: str


@dataclass
class CompletionResult:
    """Typed model completion result.

    INVARIANT: is_advisory = True always — model output never authorizes actions.
    """
    content:        str
    model_id:       str
    provider_id:    str
    is_advisory:    bool = True     # IMMUTABLE — always True
    finish_reason:  str = "stop"
    usage:          Dict = field(default_factory=dict)
    duration_ms:    int = 0
    failure:        Optional[ModelFailureKind] = None

    def __post_init__(self):
        # Enforce invariant — model output is ALWAYS advisory
        object.__setattr__(self, "is_advisory", True)

    def __setattr__(self, name: str, value):
        if name == "is_advisory" and "is_advisory" in self.__dict__:
            raise AttributeError("is_advisory is immutable — model output is always advisory")
        object.__setattr__(self, name, value)

    def is_failure(self) -> bool:
        return self.failure is not None

    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "model_id": self.model_id,
            "provider_id": self.provider_id,
            "is_advisory": True,
            "finish_reason": self.finish_reason,
            "usage": self.usage,
            "duration_ms": self.duration_ms,
            "failure": self.failure.value if self.failure else None,
        }


class BaseModelAdapter:
    """Base class for provider-specific adapters (Part 03 will implement real ones)."""

    def complete(self, messages: List[ModelMessage], model_id: str,
                 **kwargs) -> CompletionResult:
        raise NotImplementedError

    def stream(self, messages: List[ModelMessage], model_id: str,
               **kwargs) -> Iterator[str]:
        raise NotImplementedError

    def discover_models(self) -> List[ModelDefinition]:
        raise NotImplementedError

    def health_check(self) -> ProviderStatus:
        raise NotImplementedError


class MockModelAdapter(BaseModelAdapter):
    """Deterministic mock adapter for Bootstrap testing (§221, B10).

    Real providers are implemented in Part 03 (raven/ai/providers/).
    """

    def __init__(self, provider_id: str = "mock", fixed_response: str = ""):
        self._provider_id = provider_id
        self._fixed = fixed_response or "[mock response — real provider not configured]"
        self._call_count = 0

    def complete(self, messages: List[ModelMessage], model_id: str, **kwargs) -> CompletionResult:
        self._call_count += 1
        return CompletionResult(
            content=self._fixed,
            model_id=model_id,
            provider_id=self._provider_id,
            finish_reason="stop",
            usage={"input_tokens": len(messages), "output_tokens": 10},
            duration_ms=1,
        )

    def stream(self, messages: List[ModelMessage], model_id: str, **kwargs) -> Iterator[str]:
        yield self._fixed

    def discover_models(self) -> List[ModelDefinition]:
        return [ModelDefinition(
            model_id="mock-model",
            provider_id=self._provider_id,
            display_name="Mock Model (Testing)",
            capabilities=[ModelCapability.CHAT],
            status=ModelStatus.READY,
        )]

    def health_check(self) -> ProviderStatus:
        return ProviderStatus.AVAILABLE

    @property
    def call_count(self) -> int:
        return self._call_count


class OllamaAdapter(BaseModelAdapter):
    """Ollama HTTP adapter — calls a local Ollama REST API (default localhost:11434).

    THIRD-PARTY, OPTIONAL provider. RAVEN ships NO native generative model: Ollama is
    an external engine the researcher may opt into. This adapter is OFF by default and
    is NEVER auto-probed — the server only constructs it (and only then touches the
    network) when the external-LLM provider is explicitly enabled. See
    reconstruction/NATIVE_AI_FOUNDATION.md §3.1 and CANONICAL_ARCHITECTURE §1 row 22.
    """

    # Honest provenance flags for AI-status labeling (never "RAVEN's own model").
    IS_THIRD_PARTY = True
    PROVIDER_KIND = "third_party"

    def __init__(self, base_url: str = "http://localhost:11434",
                 default_model: str = ""):
        self._base_url = base_url.rstrip("/")
        self._default_model = default_model

    def _model(self, model_id: str) -> str:
        return model_id or self._default_model or "qwen2.5-coder:latest"

    def complete(self, messages: List[ModelMessage], model_id: str,
                 **kwargs) -> CompletionResult:
        model = self._model(model_id)
        payload = _json.dumps({
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
        }).encode()
        req = urllib.request.Request(
            f"{self._base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = _json.loads(resp.read())
            content = data.get("message", {}).get("content", "")
            if not content:
                return CompletionResult(
                    content="",
                    model_id=model,
                    provider_id="ollama",
                    failure=ModelFailureKind.INVALID_RESPONSE,
                )
            return CompletionResult(
                content=content,
                model_id=model,
                provider_id="ollama",
                finish_reason=data.get("done_reason", "stop"),
                usage={
                    "input_tokens": data.get("prompt_eval_count", 0),
                    "output_tokens": data.get("eval_count", 0),
                },
            )
        except urllib.error.URLError:
            return CompletionResult(
                content="",
                model_id=model,
                provider_id="ollama",
                failure=ModelFailureKind.PROVIDER_UNAVAILABLE,
            )
        except Exception:
            return CompletionResult(
                content="",
                model_id=model,
                provider_id="ollama",
                failure=ModelFailureKind.INVALID_RESPONSE,
            )

    def stream(self, messages: List[ModelMessage], model_id: str,
               **kwargs) -> Iterator[str]:
        model = self._model(model_id)
        payload = _json.dumps({
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": True,
        }).encode()
        req = urllib.request.Request(
            f"{self._base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                for line in resp:
                    if not line.strip():
                        continue
                    try:
                        chunk = _json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break
                    except (_json.JSONDecodeError, KeyError):
                        continue
        except Exception:
            return

    def discover_models(self) -> List[ModelDefinition]:
        try:
            with urllib.request.urlopen(f"{self._base_url}/api/tags",
                                        timeout=5) as resp:
                data = _json.loads(resp.read())
            return [
                ModelDefinition(
                    model_id=m["name"],
                    provider_id="ollama",
                    display_name=m["name"],
                    capabilities=[ModelCapability.CHAT, ModelCapability.CODING],
                    status=ModelStatus.READY,
                )
                for m in data.get("models", [])
            ]
        except Exception:
            return []

    def health_check(self) -> ProviderStatus:
        try:
            urllib.request.urlopen(f"{self._base_url}/api/tags", timeout=3)
            return ProviderStatus.AVAILABLE
        except Exception:
            return ProviderStatus.UNAVAILABLE


class ModelService:
    """V7 model service — registry + invocation abstraction (§118-121).

    Providers are registered with adapters. Part 03 adds real Ollama/llama.cpp adapters.
    This service ensures:
    - All completions are marked is_advisory=True
    - Provider unavailability is explicit, not silent fabrication
    - Model output is returned raw; caller validates schemas
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._providers: Dict[str, ModelProvider] = {}
        self._adapters: Dict[str, BaseModelAdapter] = {}
        self._default_provider: Optional[str] = None
        self._default_model: Optional[str] = None

    def register_provider(self, provider: ModelProvider, adapter: BaseModelAdapter) -> None:
        with self._lock:
            self._providers[provider.provider_id] = provider
            self._adapters[provider.provider_id] = adapter
            if self._default_provider is None:
                self._default_provider = provider.provider_id

    def set_default(self, provider_id: str, model_id: str) -> None:
        with self._lock:
            if provider_id not in self._providers:
                raise ValueError(f"Provider '{provider_id}' not registered")
            self._default_provider = provider_id
            self._default_model = model_id

    def complete(self, messages: List[ModelMessage], model_id: str = None,
                 provider_id: str = None) -> CompletionResult:
        adapter, pid, mid = self._resolve(provider_id, model_id)
        if adapter is None:
            return CompletionResult(
                content="",
                model_id=mid or "unknown",
                provider_id=pid or "unknown",
                failure=ModelFailureKind.PROVIDER_UNAVAILABLE,
            )
        t0 = int(time.time() * 1000)
        try:
            result = adapter.complete(messages, mid)
            result.duration_ms = int(time.time() * 1000) - t0
            # Enforce invariant
            object.__setattr__(result, "is_advisory", True)
            return result
        except Exception as exc:  # noqa: BLE001
            return CompletionResult(
                content="",
                model_id=mid or "unknown",
                provider_id=pid or "unknown",
                failure=ModelFailureKind.PROVIDER_UNAVAILABLE,
                duration_ms=int(time.time() * 1000) - t0,
            )

    def stream(self, messages: List[ModelMessage], model_id: str = None,
               provider_id: str = None) -> Iterator[str]:
        adapter, pid, mid = self._resolve(provider_id, model_id)
        if adapter is None:
            return
        try:
            yield from adapter.stream(messages, mid)
        except Exception:  # noqa: BLE001
            return

    def probe_providers(self) -> Dict[str, ProviderStatus]:
        """Check availability of all registered providers. Does NOT mark READY from config alone."""
        results = {}
        with self._lock:
            items = list(self._adapters.items())
        for pid, adapter in items:
            try:
                status = adapter.health_check()
            except Exception:  # noqa: BLE001
                status = ProviderStatus.UNAVAILABLE
            with self._lock:
                if pid in self._providers:
                    self._providers[pid].status = status
            results[pid] = status
        return results

    def list_providers(self) -> List[ModelProvider]:
        with self._lock:
            return list(self._providers.values())

    def get_provider(self, provider_id: str) -> Optional[ModelProvider]:
        with self._lock:
            return self._providers.get(provider_id)

    def _resolve(self, provider_id: str, model_id: str):
        with self._lock:
            pid = provider_id or self._default_provider
            mid = model_id or self._default_model or "default"
            if pid is None:
                return None, pid, mid
            adapter = self._adapters.get(pid)
            return adapter, pid, mid


# ── Native first-party provider (RAVEN-LM) — Phase-4 (P4-NATIVE-CHAT) ─────────
# RAVEN's OWN from-scratch generative model, registered as a selectable provider in
# ModelService. Unlike the optional Ollama adapter (THIRD-PARTY), this is FIRST-PARTY;
# like Ollama it is ADDITIVE and does nothing until a checkpoint is EXPLICITLY selected.
# The torch-backed adapter lives in ``raven.native_ai.generative.chat_provider`` and is
# imported LAZILY inside the builder below so that importing THIS module stays torch-free
# and side-effect-free for the default (no-native) path — nothing is loaded, probed, or
# run, and the honesty constant ``raven.native_ai.NATIVE_GENERATIVE_MODEL`` is untouched.
NATIVE_PROVIDER_ID = "raven_native"   # matches chat_provider.PROVIDER_ID


def build_native_provider(checkpoint_path: str, *, tokenizer_path: Optional[str] = None,
                          maturity: Optional[str] = None, max_threads: int = 4,
                          display_name: Optional[str] = None):
    """Load a RAVEN-LM checkpoint and return a ``(ModelProvider, adapter)`` pair ready
    for :meth:`ModelService.register_provider`.

    Local-only: generation runs through the in-process native inference engine — ZERO
    network, ZERO Ollama, ZERO HTTP. Raises on a bad/missing checkpoint so the caller
    fails HONESTLY (surfaces unavailable) instead of registering a provider that would
    fabricate. Honest provenance: ``configuration.provider_kind == "raven_native"`` and
    the model's maturity (e.g. ``EXPERIMENTAL_BOOTSTRAP``) rides in the config + display.
    """
    # Lazy import: keeps torch off the default import path (golden/no-native stays green).
    from raven.native_ai.generative.chat_provider import NativeChatProvider, PROVIDER_ID
    adapter = NativeChatProvider().select_checkpoint(
        checkpoint_path, tokenizer_path=tokenizer_path, max_threads=max_threads)
    mat = maturity or adapter.maturity or "EXPERIMENTAL_BOOTSTRAP"
    models = adapter.discover_models()
    provider = ModelProvider(
        provider_id=PROVIDER_ID,
        provider_type=ProviderType.NATIVE,
        display_name=display_name or f"RAVEN Native (first-party · {mat})",
        endpoint="local://native",
        status=ProviderStatus.AVAILABLE,
        models=models,
        configuration={"first_party": True, "third_party": False,
                       "provider_kind": "raven_native", "maturity": mat,
                       "checkpoint_path": str(checkpoint_path)},
    )
    return provider, adapter
