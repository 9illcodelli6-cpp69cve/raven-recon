"""Claude as the AI Chat provider (ModelService adapter). No tools in chat — the agent page
is where Claude acts; chat is for questions, payloads, code and explanations."""
from __future__ import annotations

from typing import Callable, Iterator

from . import MODEL, MODEL_LABEL
from . import client as cl
from .prompts import CHAT_SYSTEM

PROVIDER_ID = "claude"
ADVISORY = "Claude (Anthropic API) — verify findings and code by hand before reporting."


def build_provider(client_factory: Callable):
    """(ModelProvider, adapter, model_id)."""
    from ..runtime.model import (BaseModelAdapter, CompletionResult, ModelCapability, ModelDefinition,
                                 ModelFailureKind, ModelProvider, ModelStatus, ProviderStatus, ProviderType)

    class ClaudeAdapter(BaseModelAdapter):
        def complete(self, messages, model_id: str = "", **kwargs):
            msgs = []
            for m in messages:
                role = getattr(m, "role", None) or (m.get("role") if isinstance(m, dict) else "user")
                role = getattr(role, "value", role)
                content = getattr(m, "content", None) or (m.get("content") if isinstance(m, dict) else "")
                if role == "system" or not str(content).strip():
                    continue
                msgs.append({"role": "assistant" if role == "assistant" else "user", "content": str(content)})
            while msgs and msgs[0]["role"] != "user":   # the first message must be a user turn
                msgs.pop(0)
            if not msgs:
                return CompletionResult(content="", model_id=MODEL, provider_id=PROVIDER_ID,
                                        failure=ModelFailureKind.INVALID_RESPONSE, usage={"error": "empty conversation"})
            try:
                resp = cl.create(client_factory(), system=CHAT_SYSTEM, messages=msgs[-40:],
                                 max_tokens=16000, effort="medium")
            except Exception as exc:
                err = str(exc) if isinstance(exc, cl.ClaudeUnavailable) else cl.friendly_error(exc)
                return CompletionResult(content="", model_id=MODEL, provider_id=PROVIDER_ID,
                                        failure=ModelFailureKind.PROVIDER_UNAVAILABLE, usage={"error": err})
            u = cl.Usage()
            u.add(getattr(resp, "usage", None))
            refusal = cl.refusal_info(resp)
            text = cl.text_of(resp)
            if refusal:
                text = (text + "\n\n" if text else "") + (
                    f"[Claude declined this request — safety category: {refusal['category']}. "
                    "Rephrase with the authorized context (target, scope, program rules) or ask for the "
                    "defensive/testing angle.]")
            fb = cl.served_by(resp)
            return CompletionResult(
                content=text, model_id=MODEL, provider_id=PROVIDER_ID,
                usage={"output_tokens": u.output_tokens, "input_tokens": u.input_tokens,
                       "cost_usd": u.cost_usd, "model": fb or MODEL_LABEL,
                       "maturity": "CLAUDE_API", "advisory_note": ADVISORY})

        def stream(self, messages, model_id: str = "", **kwargs) -> Iterator[str]:
            r = self.complete(messages, model_id, **kwargs)
            if r.content:
                yield r.content

        def discover_models(self):
            return [ModelDefinition(model_id=PROVIDER_ID, provider_id=PROVIDER_ID, display_name=MODEL_LABEL,
                                    capabilities=[ModelCapability.CHAT], context_window=1_000_000,
                                    status=ModelStatus.READY, metadata={"advisory_only": True})]

        def health_check(self):
            return ProviderStatus.AVAILABLE

    adapter = ClaudeAdapter()
    provider = ModelProvider(provider_id=PROVIDER_ID, provider_type=ProviderType.ANTHROPIC,
                             display_name=f"{MODEL_LABEL} (Anthropic API)", endpoint="https://api.anthropic.com",
                             status=ProviderStatus.AVAILABLE, models=adapter.discover_models(),
                             configuration={"third_party": True, "model": MODEL})
    return provider, adapter, PROVIDER_ID
