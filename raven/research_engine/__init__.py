"""RAVEN V7 Security Research Engine — Part 07.  **DEPRECATED (Wave 7, A7-RECON).**

DEPRECATED — dead, test-only, not a recon engine. This package performs **no network
collection**: ``ResearchEngine`` only persists ``v7_findings``/``v7_experiments`` to
SQLite and ``register_research_tools`` registers four descriptors whose handler is a
``_noop -> {"status":"not_dispatched"}``. It has **zero non-test importers** across the
repo (RECON_ARCHITECTURE §1C, CANONICAL_ARCHITECTURE §1 row 13).

Per the reconstruction it is DEPRECATED but kept importable (the Part-07 unit tests still
exercise its invariants). The live findings path is the canonical V5 ``findings`` table
written by ``raven.canonical_service`` → ``raven.store`` (that supersedes this data model);
the real, dispatching recon tool is ``raven.recon.tools.register_recon_tools`` (``recon.collect``),
which replaces the ``register_research_tools`` noop.

**Data check (implementation-time, Wave 7):** no production database holds ``v7_findings``
or ``v7_experiments`` rows — this engine wrote zero persistent data — so no migration or
backup is required before deprecation. It is NOT deleted (kept importable).

Key invariants (unchanged, still enforced by the surviving classes):
- human_verification_required = True on ALL findings
- BOLA/BFLA are CONCEPTUAL EDUCATIONAL LABELS only
- AI output is advisory — never authorizes actions
- external_targets = 0 enforced by engine
- Candidate != Verified (always distinct states)
"""
from .experiment import Experiment, ExperimentStatus, ExperimentResult
from .finding import CandidateFinding, FindingCategory, FindingSeverity
from .critic import ScientificCritic, CritiqueResult
from .engine import ResearchEngine
from .registry import register_research_tools

#: This package is deprecated (unwired from the live path). Kept importable for tests.
__deprecated__ = True
__replacement__ = "raven.recon.tools.register_recon_tools"

__all__ = [
    "Experiment", "ExperimentStatus", "ExperimentResult",
    "CandidateFinding", "FindingCategory", "FindingSeverity",
    "ScientificCritic", "CritiqueResult",
    "ResearchEngine",
    "register_research_tools",
    "__deprecated__", "__replacement__",
]
