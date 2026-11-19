"""RAVEN canonical reconnaissance package (Wave 7, A7-RECON).

ONE recon engine, extracted from the V7 server collector (RECON_ARCHITECTURE,
CANONICAL_ARCHITECTURE §1 row 13). Public surface:

* :class:`ReconService` — the single submit/run service both entry points converge on.
* :func:`register_recon_tools` — registers the real ``recon.collect`` dispatching tool.
* The collectors (:class:`PassiveCrtShCollector`, :class:`ActiveProbeCollector`,
  :class:`ExternalToolCollector`) for direct/unit use.

The legacy CLI/TUI engine (``raven/engine.py`` + ``raven/network.py``) remains LEGACY and
is not imported here; ``raven/research_engine`` is DEPRECATED. subfinder/gau are an
OPTIONAL, OFF-by-default ``ExternalToolCollector``.
"""
from .service import ReconService
from .collectors import (
    PassiveCrtShCollector, ActiveProbeCollector, ExternalToolCollector,
)
from .tools import register_recon_tools, RECON_COLLECT

__all__ = [
    "ReconService",
    "PassiveCrtShCollector", "ActiveProbeCollector", "ExternalToolCollector",
    "register_recon_tools", "RECON_COLLECT",
]
