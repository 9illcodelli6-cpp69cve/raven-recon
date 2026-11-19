"""RAVEN V7 AI Chat — Part 03.

Local AI chat session backed by the shared runtime.
Uses ModelService + ConversationContext; no competing runtime.
"""
from .chat import ChatSession, ChatMessage, ChatRole, ChatConfig
from .memory import MemoryManager, MemoryEntry
from .corrector import SelfCorrector, CorrectionResult
from .multilingual import LanguageDetector, SupportedLanguage

__all__ = [
    "ChatSession", "ChatMessage", "ChatRole", "ChatConfig",
    "MemoryManager", "MemoryEntry",
    "SelfCorrector", "CorrectionResult",
    "LanguageDetector", "SupportedLanguage",
]
