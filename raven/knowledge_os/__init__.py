"""RAVEN V7 Knowledge OS — Part 09.

Structured knowledge management and self-learning:
- KnowledgeBase: stores facts, patterns, techniques
- LearningEngine: synthesizes lessons from completed research
- KnowledgeQuery: retrieves relevant knowledge for current task
- TechniqueLibrary: indexed security techniques

Invariants:
- human_reviewed_labels = 0 (AI-derived knowledge is advisory, not ground truth)
- synthetic_data != human_reviewed_ground_truth
- Knowledge entries are tagged with their source and confidence
"""
from .knowledge_base import KnowledgeBase, KnowledgeEntry, KnowledgeKind
from .learning import LearningEngine, Lesson
from .technique import TechniqueLibrary, Technique, TechniqueCategory
from .registry import register_knowledge_tools

__all__ = [
    "KnowledgeBase", "KnowledgeEntry", "KnowledgeKind",
    "LearningEngine", "Lesson",
    "TechniqueLibrary", "Technique", "TechniqueCategory",
    "register_knowledge_tools",
]
