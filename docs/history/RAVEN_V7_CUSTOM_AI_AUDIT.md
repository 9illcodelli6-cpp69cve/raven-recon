# RAVEN V7 — Custom AI Audit

**Date:** 2026-10-05  
**Auditor:** Claude Sonnet 4.6 (automated)  
**human_verification_required:** True (immutable)

---

## Finding: No Custom Generative LLM Exists

RAVEN does not contain a proprietary language model. The AI system is an **Ollama wrapper**.

### Technical Path

| Component | File | Role |
|---|---|---|
| `ModelService` | `raven/runtime/model.py` | Registry + invocation abstraction |
| `OllamaAdapter` | `raven/runtime/model.py:224` | Calls local Ollama REST API |
| `CompletionResult` | `raven/runtime/model.py:125` | `is_advisory=True` — immutable |
| `/api/chat` handler | `raven/api/server.py` | Proxies chat to `OllamaAdapter.complete()` |

### Why qwen2.5-coder appears

`OllamaAdapter._model()` (line 233) falls back to `"qwen2.5-coder:latest"` when no model is
configured:

```python
def _model(self, model_id: str) -> str:
    return model_id or self._default_model or "qwen2.5-coder:latest"
```

This is a hardcoded fallback. The actual model used is the first model installed in the local
Ollama catalog, or whatever `RAVEN_SETTINGS["model_id"]` is set to.

### ML Classifiers (raven/ml/)

Small MLP and logistic regression models exist for security triage. These are:
- Status: **DEVELOPMENT** — trained on synthetic data only
- Never promoted to PRODUCTION
- Entirely disconnected from chat
- Governed by `CapabilityGate` (fail-closed)

### Invariants Confirmed

- `CompletionResult.is_advisory` raises `AttributeError` if set to False (line 145)
- `human_verification_required = True` on all `CandidateAuthorizationFinding`
- ML predictions never become human labels (`human_reviewed_labels = 0` always)
- Model output is UNTRUSTED INPUT — callers validate

### Configured in V7

Settings API (`/api/v7/settings`) allows runtime model selection without code changes.
The Settings page in the UI exposes Foundation Model input and Ollama URL.
