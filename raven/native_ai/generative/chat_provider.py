"""Native chat provider — ModelService-compatible, OFF by default, honest when absent.

A :class:`raven.runtime.model.BaseModelAdapter`-shaped adapter that can expose native
RAVEN-LM inference to the Phase-4 chat stack. It is deliberately inert until a checkpoint
is EXPLICITLY selected:

  * **OFF by default.** Constructed with no checkpoint it is unavailable; it never
    auto-probes, auto-loads, or auto-activates.
  * **Never fabricates text.** With no selected/loadable checkpoint, ``complete`` returns
    a typed failure (``ModelFailureKind.NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE``) and empty
    content — the same honest "nothing is turned on" signal the chat layer already knows.
  * **Surfaces maturity.** When it does serve, the result metadata carries the model's
    maturity (e.g. ``EXPERIMENTAL_BOOTSTRAP``) and an advisory note; output is always
    ``is_advisory=True`` (enforced by :class:`~raven.runtime.model.CompletionResult`).
  * Does NOT flip ``raven.native_ai.NATIVE_GENERATIVE_MODEL`` (stays ``None``) and is NOT
    wired into any live path here — Phase-4 is the only place that may register it, and
    only after an explicit, eval-gated selection.

Local-only: generation runs through :class:`NativeInferenceEngine` (zero network / zero
Ollama / zero HTTP).
"""
from __future__ import annotations

from typing import Iterator, List, Optional

from raven.runtime.model import (
    BaseModelAdapter, CompletionResult, ModelCapability, ModelDefinition,
    ModelFailureKind, ModelStatus, ProviderStatus,
)

from .infer import GenerationConfig, NativeInferenceEngine

PROVIDER_ID = "raven_native"
_UNAVAILABLE_TEXT = ""   # never fabricate — honest failure carries empty content

# Structural tokens of the curriculum's chat template (bpe_tokenizer SPECIALS). The
# engine decodes them literally; they must never reach the chat bubble. RAVEN's turn
# ends at <|endturn|> / <eos>, and a role token means the model started a new turn.
_TURN_END_MARKERS = ("<|endturn|>", "<eos>", "<|user|>", "<|system|>", "<|raven|>")
_NOISE_TOKENS = ("<pad>", "<bos>")


def _clean_reply(text: str) -> str:
    """Cut the generated text at the end of RAVEN's turn and drop structural tokens."""
    cut = len(text)
    for marker in _TURN_END_MARKERS:
        i = text.find(marker)
        if i != -1:
            cut = min(cut, i)
    text = text[:cut]
    for tok in _NOISE_TOKENS:
        text = text.replace(tok, "")
    return text.strip()


class NativeChatProvider(BaseModelAdapter):
    """OFF-by-default native-generation adapter (honest-unavailable until selected)."""

    # Honest provenance flags (this is RAVEN's OWN model, not third-party) for any
    # AI-status surface. Still OFF by default and eval-gated before Phase-4 wiring.
    IS_THIRD_PARTY = False
    PROVIDER_KIND = "raven_native"

    def __init__(self, *, engine: Optional[NativeInferenceEngine] = None,
                 maturity: Optional[str] = None,
                 default_generation: Optional[GenerationConfig] = None) -> None:
        # No checkpoint selected → inert. An engine is only set via an EXPLICIT
        # constructor injection or select_checkpoint(); it is never auto-loaded.
        self._engine = engine
        self._maturity = maturity or (engine.maturity if engine else None)
        self._gen = default_generation or GenerationConfig(max_new_tokens=64,
                                                           temperature=0.8)

    # -- explicit selection (the ONLY way to make this usable) -----------------

    def select_checkpoint(self, checkpoint_path: str, *, tokenizer=None,
                          tokenizer_path: Optional[str] = None,
                          max_threads: int = 4) -> "NativeChatProvider":
        """Explicitly load + select a RAVEN checkpoint. Until this is called (or an
        engine is injected at construction) the provider stays unavailable."""
        self._engine = NativeInferenceEngine.from_checkpoint(
            checkpoint_path, tokenizer=tokenizer, tokenizer_path=tokenizer_path,
            max_threads=max_threads)
        self._maturity = self._engine.maturity
        return self

    @property
    def is_available(self) -> bool:
        return self._engine is not None

    @property
    def maturity(self) -> Optional[str]:
        return self._maturity

    # -- BaseModelAdapter surface ----------------------------------------------

    def complete(self, messages: List, model_id: str = "", **kwargs) -> CompletionResult:
        if self._engine is None:
            # Honest, typed, NON-fabricated unavailability.
            return CompletionResult(
                content=_UNAVAILABLE_TEXT,
                model_id=model_id or "raven-native",
                provider_id=PROVIDER_ID,
                failure=ModelFailureKind.NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE,
            )
        prompt = self._render_prompt(messages)
        cfg = kwargs.get("generation") or self._gen
        result = self._engine.generate(prompt, cfg)
        return CompletionResult(
            content=_clean_reply(result.text),
            model_id=model_id or "raven-native",
            provider_id=PROVIDER_ID,
            finish_reason="stop",
            usage={
                "output_tokens": len(result.tokens),
                "maturity": self._maturity,
                "advisory_note": ("native bootstrap model — advisory only, requires "
                                  "human verification; not a verification verdict"),
            },
        )

    def stream(self, messages: List, model_id: str = "", **kwargs) -> Iterator[str]:
        if self._engine is None:
            return
        prompt = self._render_prompt(messages)
        cfg = kwargs.get("generation") or self._gen
        # Special tokens decode atomically, so a marker arrives whole inside a piece:
        # emit what precedes it, then end the turn (same rule as _clean_reply).
        for piece in self._engine.stream(prompt, cfg):
            cut = min((i for i in (piece.find(m) for m in _TURN_END_MARKERS) if i != -1),
                      default=-1)
            if cut != -1:
                if piece[:cut]:
                    yield piece[:cut]
                return
            for tok in _NOISE_TOKENS:
                piece = piece.replace(tok, "")
            if piece:
                yield piece

    def discover_models(self) -> List[ModelDefinition]:
        if self._engine is None:
            return []
        return [ModelDefinition(
            model_id="raven-native",
            provider_id=PROVIDER_ID,
            display_name=f"RAVEN-LM (native, {self._maturity})",
            capabilities=[ModelCapability.CHAT, ModelCapability.MULTILINGUAL],
            context_window=self._engine.model.cfg.context_length,
            status=ModelStatus.READY,
            metadata={"maturity": self._maturity, "provenance": "raven_native",
                      "advisory_only": True},
        )]

    def health_check(self) -> ProviderStatus:
        return ProviderStatus.AVAILABLE if self._engine is not None \
            else ProviderStatus.UNAVAILABLE

    # -- prompt rendering ------------------------------------------------------

    @staticmethod
    def _render_prompt(messages: List) -> str:
        """Render chat messages into the curriculum's role-token template."""
        role_map = {"system": "<|system|>", "user": "<|user|>", "assistant": "<|raven|>"}
        parts: List[str] = []
        for m in messages:
            role = getattr(m, "role", None) or (m.get("role") if isinstance(m, dict) else "user")
            content = getattr(m, "content", None) or (m.get("content") if isinstance(m, dict) else "")
            parts.append(f"{role_map.get(role, '<|user|>')}{content}")
        parts.append("<|raven|>")
        return "".join(parts)
