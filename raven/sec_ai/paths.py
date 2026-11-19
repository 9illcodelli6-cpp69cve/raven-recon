"""Filesystem layout for RAVEN-Sec (models, corpus, knowledge index, agent workspace)."""
from __future__ import annotations

import os
from pathlib import Path

BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-0.5B-Instruct"
BASE_MODEL_DIRNAME = "qwen2.5-coder-0.5b-instruct"
TUNED_MODEL_DIRNAME = "raven-sec-0.5b"


def ai_dir() -> Path:
    """Root for all AI artifacts. ``RAVEN_AI_DIR`` overrides; otherwise ``<data>/ai``.

    Large files (model weights, corpus) belong on a roomy disk — on the reference
    machine ``<data>/ai`` can be a symlink to a bigger disk.
    """
    env = os.environ.get("RAVEN_AI_DIR", "").strip()
    if env:
        return Path(env).expanduser()
    from ..platform_paths import resolve_data_root
    root = resolve_data_root()
    return (root if root is not None else Path(".")) / "ai"


def base_model_dir() -> Path:
    return ai_dir() / BASE_MODEL_DIRNAME


def tuned_model_dir() -> Path:
    return ai_dir() / TUNED_MODEL_DIRNAME


def corpus_raw_dir() -> Path:
    return ai_dir() / "corpus" / "raw"


def kb_path() -> Path:
    return ai_dir() / "corpus" / "kb.sqlite"


def dataset_dir() -> Path:
    return ai_dir() / "dataset"


def agent_workspace_root() -> Path:
    return ai_dir() / "agent-workspaces"


def active_model_dir() -> Path | None:
    """The fine-tuned model when it exists (and finished), else the base model."""
    tuned = tuned_model_dir()
    if (tuned / "config.json").is_file() and (tuned / "model.safetensors").is_file():
        return tuned
    base = base_model_dir()
    if (base / "config.json").is_file():
        return base
    return None


# Which weights write the CHAT summary. The agent always uses active_model_dir() (the
# fine-tune follows the tool protocol 100 % vs 13 % for the base). For free-form chat
# answers the pentest benchmark (raven.sec_ai.pentest_bench) decides the default.
CHAT_MODEL_DEFAULT = "tuned"


def chat_model_dir() -> Path | None:
    """RAVEN_SEC_CHAT_MODEL=base|tuned overrides the default."""
    import os
    choice = (os.environ.get("RAVEN_SEC_CHAT_MODEL") or CHAT_MODEL_DEFAULT).strip().lower()
    tuned, base = tuned_model_dir(), base_model_dir()
    tuned_ok = (tuned / "config.json").is_file() and (tuned / "model.safetensors").is_file()
    if choice == "base" and (base / "config.json").is_file():
        return base
    if choice == "tuned" and tuned_ok:
        return tuned
    return active_model_dir()
