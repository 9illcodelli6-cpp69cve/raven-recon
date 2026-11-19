"""RAVEN V7 Multilingual Support — Part 03.

Language detection and locale-aware prompting.
Uses heuristics only — no external API calls.
Arabic (العربية) is the primary non-English language for this deployment.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import re


class SupportedLanguage(str, Enum):
    ENGLISH = "en"
    ARABIC  = "ar"
    FRENCH  = "fr"
    SPANISH = "es"
    AUTO    = "auto"


# Arabic Unicode block: U+0600–U+06FF
_ARABIC_RE  = re.compile(r'[؀-ۿ]')
_FRENCH_RE  = re.compile(r'\b(le|la|les|de|du|un|une|est|avec|pour|dans|que)\b', re.I)
_SPANISH_RE = re.compile(r'\b(el|la|los|las|de|del|es|en|con|para|que|por)\b', re.I)


@dataclass
class LanguageDetector:
    default_language: SupportedLanguage = SupportedLanguage.ENGLISH

    def detect(self, text: str) -> SupportedLanguage:
        if not text or not text.strip():
            return self.default_language

        arabic_chars = len(_ARABIC_RE.findall(text))
        total_chars  = max(len(text.strip()), 1)

        if arabic_chars / total_chars > 0.15:
            return SupportedLanguage.ARABIC

        words = text.lower().split()
        if len(words) >= 3:
            fr_hits = len(_FRENCH_RE.findall(text))
            es_hits = len(_SPANISH_RE.findall(text))
            if fr_hits > es_hits and fr_hits >= 2:
                return SupportedLanguage.FRENCH
            if es_hits > fr_hits and es_hits >= 2:
                return SupportedLanguage.SPANISH

        return SupportedLanguage.ENGLISH

    def get_system_prompt_suffix(self, lang: SupportedLanguage) -> str:
        suffixes = {
            SupportedLanguage.ARABIC:  " أجب باللغة العربية ما أمكن.",
            SupportedLanguage.FRENCH:  " Répondez en français si possible.",
            SupportedLanguage.SPANISH: " Responde en español si es posible.",
            SupportedLanguage.ENGLISH: "",
            SupportedLanguage.AUTO:    "",
        }
        return suffixes.get(lang, "")
