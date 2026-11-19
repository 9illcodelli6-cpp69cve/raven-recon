"""RAVEN Native Analysis Bridge (Phase 6/7/9).

Provides safe, optional access to the native C++ analysis backend.
RAVEN operates fully without this module — Python fallback is always available.

ABI contract: Python rejects native modules with unknown ABI_VERSION.
"""
from __future__ import annotations

from .backend import (
    AnalysisBackend,
    PythonAnalysisBackend,
    NativeAnalysisBackend,
    BackendMode,
    get_backend,
    get_capabilities,
    NativeUnavailable,
)

__all__ = [
    "AnalysisBackend",
    "PythonAnalysisBackend",
    "NativeAnalysisBackend",
    "BackendMode",
    "get_backend",
    "get_capabilities",
    "NativeUnavailable",
]
