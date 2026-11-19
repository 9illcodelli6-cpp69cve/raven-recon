"""Tokenizer — INTERFACE ONLY (no vocabulary, no encoding).

Forward contract: encode/decode/vocab_size signatures for a future native model. There
is NO vocabulary, NO merges file, and NO encoding logic here — every operational method
raises ``NotImplementedError``. Nothing imports this at runtime.
"""
from __future__ import annotations

from typing import List


class Tokenizer:
    """Interface for a native-model tokenizer. NOT IMPLEMENTED."""

    def encode(self, text: str) -> List[int]:
        raise NotImplementedError("native_ai.Tokenizer is an interface only — no tokenizer exists")

    def decode(self, tokens: List[int]) -> str:
        raise NotImplementedError("native_ai.Tokenizer is an interface only — no tokenizer exists")

    @property
    def vocab_size(self) -> int:
        raise NotImplementedError("native_ai.Tokenizer is an interface only — no tokenizer exists")
