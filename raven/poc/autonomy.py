"""RAVEN Autonomy Levels (Gate 30).

LEVEL 0 — MANUAL:     RAVEN presents findings. Researcher executes everything.
LEVEL 1 — ASSIST:     RAVEN may analyze, rank, explain, propose safe tests,
                       build PoC candidates. Researcher decides execution.
                       (DEFAULT)
LEVEL 2 — SUPERVISED: RAVEN may execute SafeReadOnly primitives autonomously.
                       Researcher approves LowRiskStateChange and above.
LEVEL 3 — BOUNDED_AUTO: RAVEN may execute up to LowRiskStateChange with
                       pre-approved scope. Sensitive+ always requires approval.
                       NOT globally enabled.

INVARIANTS:
- LEVEL 3 is NEVER globally enabled.
- LEVEL 3 can only be enabled per-workspace with explicit researcher config.
- ML/AI cannot set its own autonomy level.
- Sensitive, Destructive, Exfiltrative always require human approval.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass


class AutonomyLevel(int, enum.Enum):
    MANUAL       = 0
    ASSIST       = 1  # default
    SUPERVISED   = 2
    BOUNDED_AUTO = 3  # never globally enabled


@dataclass
class AutonomyConfig:
    level: AutonomyLevel = AutonomyLevel.ASSIST
    workspace_id: str = ""

    def may_execute_read_only_autonomously(self) -> bool:
        return self.level >= AutonomyLevel.SUPERVISED

    def may_execute_low_risk_autonomously(self) -> bool:
        return self.level >= AutonomyLevel.BOUNDED_AUTO

    def requires_approval_for_sensitive(self) -> bool:
        return True  # ALWAYS — regardless of level

    def requires_approval_for_destructive(self) -> bool:
        return True  # ALWAYS — regardless of level

    def description(self) -> str:
        return {
            AutonomyLevel.MANUAL:       "MANUAL: RAVEN presents findings only. Researcher executes everything.",
            AutonomyLevel.ASSIST:       "ASSIST (DEFAULT): RAVEN analyzes, proposes. Researcher decides execution.",
            AutonomyLevel.SUPERVISED:   "SUPERVISED: RAVEN may execute read-only probes. Researcher approves state changes.",
            AutonomyLevel.BOUNDED_AUTO: "BOUNDED_AUTO: RAVEN may execute low-risk probes in pre-approved scope. Sensitive+ always requires approval.",
        }[self.level]


# Default: LEVEL 1 — ASSIST
DEFAULT_AUTONOMY = AutonomyConfig(level=AutonomyLevel.ASSIST)
