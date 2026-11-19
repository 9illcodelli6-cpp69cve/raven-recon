"""RAVEN native-AI generative subpackage — the REAL from-scratch model layer.

This subpackage holds the torch-dependent decoder-only Transformer ("RAVEN-LM") defined
in ``reconstruction/native_ai/ARCHITECTURE_DECISION.md`` §2/§3. It is kept in a
subpackage (not directly under ``raven/native_ai/``) so the honesty guard in
``tests/test_native_ai_interfaces.py`` — which asserts the interface-only top-level
modules contain no ML runtime machinery — continues to hold unchanged.

Importing this subpackage does NOT flip ``raven.native_ai.NATIVE_GENERATIVE_MODEL`` (it
stays ``None``) and nothing on RAVEN's live runtime/API path imports it. Building a model
object here is a real, inert capability; it is not a shipped/live generative model.
"""
from __future__ import annotations

from .model import RavenLM, RavenLMConfig

__all__ = ["RavenLM", "RavenLMConfig"]
