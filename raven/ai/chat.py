"""RAVEN V7 Chat Session — Part 03.

Multi-turn AI chat using the shared runtime's ModelService + ConversationContext.
All completions are advisory only — no model output can authorize actions.

Security invariants maintained:
- CompletionResult.is_advisory always True (enforced by ModelService)
- User messages are NOT instructions to the tool layer
- External content is untrusted data
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from raven.runtime.model import ModelMessage, ModelService, ModelFailureKind
from raven.runtime.conversation import ConversationContext, Message


# Wave 13 (A13-NATIVE): honest marker shown when RAVEN has NO native generative model
# and no optional external provider is enabled. This is NOT fabricated assistant text —
# it is a typed, truthful "nothing is turned on" notice. It deliberately contains the
# word "unavailable" so the (unchanged) chat contract and the characterization test in
# tests/test_v7_part03_ai_chat.py keep passing, while being clearly distinct from the
# generic "[Model unavailable: <kind>]" (an enabled-but-unreachable external provider).
_NATIVE_MODEL_NOT_AVAILABLE_TEXT = (
    "[Native generative model unavailable — RAVEN ships no built-in generative model "
    "and no optional external provider is enabled]"
)


class ChatRole(str, Enum):
    USER      = "user"
    ASSISTANT = "assistant"
    SYSTEM    = "system"


@dataclass
class ChatMessage:
    role:       ChatRole
    content:    str
    timestamp:  int = field(default_factory=lambda: int(time.time() * 1000))
    metadata:   Dict = field(default_factory=dict)

    def to_model_message(self) -> ModelMessage:
        return ModelMessage(role=self.role.value, content=self.content)


@dataclass
class ChatConfig:
    system_prompt:    str = "You are RAVEN, an AI security research assistant. All your outputs are advisory only and require human verification."
    max_context_turns: int = 20
    workspace_id:     str = "chat-default"
    language_hint:    str = "auto"
    self_correct:     bool = True


@dataclass
class ChatResponse:
    content:      str
    is_advisory:  bool = True    # ALWAYS True — immutable contract
    session_id:   str = ""
    turn:         int = 0
    duration_ms:  int = 0
    language:     str = "en"
    corrections:  int = 0
    model_id:     str = ""
    provider_id:  str = ""
    # Typed failure kind (ModelFailureKind.value) when the turn could not be completed,
    # else None. Lets the API layer map to an honest error_code without string-sniffing.
    failure:      Optional[str] = None
    # Phase-4 (P4-NATIVE-CHAT): when the response came from RAVEN's OWN native model, the
    # checkpoint maturity (e.g. "EXPERIMENTAL_BOOTSTRAP") + its advisory note, surfaced
    # from the provider's CompletionResult.usage. None for third-party/no provider. The
    # UI/API state the maturity honestly; they NEVER hide it or restate it as capable.
    maturity:      Optional[str] = None
    advisory_note: Optional[str] = None

    def __post_init__(self):
        # Enforce: chat responses are always advisory
        object.__setattr__(self, "is_advisory", True)


class ChatSession:
    """Multi-turn AI chat session backed by the shared runtime.

    Wraps ModelService and ConversationContext.
    Does NOT create its own model service — uses the runtime's.
    """

    def __init__(
        self,
        model_service: ModelService,
        conversation_context: ConversationContext,
        config: ChatConfig = None,
        on_response: Callable[[ChatResponse], None] = None,
    ):
        self.session_id   = uuid.uuid4().hex[:16]
        self._model       = model_service
        self._context     = conversation_context
        self._config      = config or ChatConfig()
        self._on_response = on_response
        self._turn        = 0
        self._history: List[ChatMessage] = []

    @property
    def turn(self) -> int:
        return self._turn

    @property
    def history(self) -> List[ChatMessage]:
        return list(self._history)

    def send(self, user_message: str, language: str = "auto") -> ChatResponse:
        """Send a user message and get an advisory AI response."""
        t0 = int(time.time() * 1000)
        self._turn += 1

        user_msg = ChatMessage(role=ChatRole.USER, content=user_message)
        self._history.append(user_msg)

        # Build context for model: system + recent history
        messages = [ModelMessage(role="system", content=self._config.system_prompt)]
        recent = self._history[-self._config.max_context_turns:]
        for m in recent:
            messages.append(m.to_model_message())

        # Routing: ModelService resolves the active provider. When a native RAVEN-LM
        # checkpoint has been explicitly selected + loaded, it is the default provider,
        # so this completes through LOCAL native inference (no network / no Ollama). With
        # nothing selected the service has no provider and returns the honest failure
        # below — we NEVER fabricate assistant text in any branch.
        result = self._model.complete(messages)

        duration = int(time.time() * 1000) - t0

        maturity: Optional[str] = None
        advisory_note: Optional[str] = None
        failure_value: Optional[str] = None
        if result.is_failure():
            # Distinguish the HONEST default state — RAVEN has no native generative
            # model and no optional external provider is enabled (zero providers
            # registered) — from an enabled-but-unreachable external provider. We never
            # fabricate assistant text in either case (NATIVE_AI_FOUNDATION §3.1).
            has_provider = False
            try:
                has_provider = bool(self._model.list_providers())
            except Exception:
                has_provider = False
            if not has_provider:
                failure_value = ModelFailureKind.NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE.value
                content = _NATIVE_MODEL_NOT_AVAILABLE_TEXT
            else:
                failure_value = (result.failure.value if result.failure
                                 else ModelFailureKind.PROVIDER_UNAVAILABLE.value)
                content = f"[Model unavailable: {failure_value}]"
                detail = (result.usage or {}).get("error")
                if detail:
                    content += f" {detail}"
        else:
            content = result.content
            # Honest maturity tag for a native generation (rides in usage metadata).
            usage = result.usage or {}
            maturity = usage.get("maturity")
            advisory_note = usage.get("advisory_note")

        asst_msg = ChatMessage(role=ChatRole.ASSISTANT, content=content)
        self._history.append(asst_msg)

        # Persist to ConversationContext
        try:
            from ..runtime.conversation import MessageRole as _MR
            self._context.add_message(
                conversation_id=self._config.workspace_id,
                role=_MR.RESEARCHER,
                content=user_message,
            )
            self._context.add_message(
                conversation_id=self._config.workspace_id,
                role=_MR.RAVEN,
                content=content,
                model_id=result.model_id,
            )
        except Exception:
            pass  # persistence is best-effort; chat always continues

        response = ChatResponse(
            content=content,
            session_id=self.session_id,
            turn=self._turn,
            duration_ms=duration,
            language=language if language != "auto" else "en",
            model_id=result.model_id,
            provider_id=result.provider_id,
            failure=failure_value,
            maturity=maturity,
            advisory_note=advisory_note,
        )

        if self._on_response:
            try:
                self._on_response(response)
            except Exception:
                pass

        return response

    def clear(self) -> None:
        self._history.clear()
        self._turn = 0

    def get_context_messages(self) -> List[Dict]:
        return [
            {"role": m.role.value, "content": m.content, "timestamp": m.timestamp}
            for m in self._history
        ]
