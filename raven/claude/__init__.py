"""Claude (Anthropic API) as RAVEN's reasoning engine.

* ``keystore`` — the user's Anthropic API key, encrypted at rest, never returned to the UI.
* ``client``   — one place that calls the Messages API (model, effort, refusal fallback,
                 cost accounting, typed error mapping).
* ``skills``   — RAVEN's own playbooks (``raven/skills/*/SKILL.md``), loaded on demand.
* ``tools``    — RAVEN capabilities exposed to Claude; anything that touches a target or
                 runs a command waits for the operator's Approve.
* ``agent``    — the agent loop, hosted inside RAVEN (Messages API + tool use).
* ``chat``     — the AI Chat provider.
"""
MODEL = "claude-opus-5-5"
MODEL_LABEL = "Claude Opus 5.5"
