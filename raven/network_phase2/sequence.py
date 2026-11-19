"""RAVEN Network Phase II — Observation sequence representation.

An ObservationSequence is an ordered list of NetworkObservations that
together form a meaningful web interaction (login flow, cache validation,
session expiry, etc.).

INVARIANTS:
- Credentials are never stored (inherited from NetworkObservation).
- data_source is always EDUCATIONAL_SYNTHETIC.
- Sequence ordering is by step index, not arrival time.
- is_security_relevant is NEVER set True by this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from raven.network_fundamentals.observation import NetworkObservation


DATA_SOURCE = "EDUCATIONAL_SYNTHETIC"


@dataclass
class OrderedObservation:
    """Single step inside an observation sequence."""
    step: int                          # 0-based position in sequence
    observation: NetworkObservation
    timestamp_offset_ms: int = 0      # milliseconds since sequence start
    notes: str = ""                   # human-readable description of this step

    @property
    def status(self) -> int:
        return self.observation.response.status if self.observation.response else 0

    @property
    def method(self) -> str:
        return self.observation.method

    @property
    def path(self) -> str:
        return self.observation.path


@dataclass
class ObservationSequence:
    """An ordered sequence of HTTP observations forming one scenario.

    Used as input to NET-E/F/G/H tasks.
    Never a security verdict.
    """
    sequence_id: str
    observations: list[OrderedObservation] = field(default_factory=list)
    scenario_family: str = ""     # grouped splitting key (like fixture_family)
    description: str = ""         # human-readable scenario label
    data_source: str = DATA_SOURCE

    # Phase II labels (set externally — never by this class)
    net_e_label: Optional[str] = None   # StateTransitionClass
    net_f_label: Optional[str] = None   # ExperimentQualityClass
    net_g_label: Optional[str] = None   # CausalSupportClass
    net_h_label: Optional[str] = None   # NextObservationType

    def __len__(self) -> int:
        return len(self.observations)

    def __getitem__(self, idx: int) -> OrderedObservation:
        return self.observations[idx]

    def add(self, obs: NetworkObservation, *, timestamp_offset_ms: int = 0,
            notes: str = "") -> "ObservationSequence":
        step = len(self.observations)
        self.observations.append(OrderedObservation(
            step=step,
            observation=obs,
            timestamp_offset_ms=timestamp_offset_ms,
            notes=notes,
        ))
        return self

    def consecutive_pairs(self) -> list[tuple[OrderedObservation, OrderedObservation]]:
        """All consecutive (step_i, step_i+1) pairs."""
        if len(self.observations) < 2:
            return []
        return [(self.observations[i], self.observations[i + 1])
                for i in range(len(self.observations) - 1)]

    def first(self) -> Optional[OrderedObservation]:
        return self.observations[0] if self.observations else None

    def last(self) -> Optional[OrderedObservation]:
        return self.observations[-1] if self.observations else None

    def pair(self, i: int, j: int) -> tuple[OrderedObservation, OrderedObservation]:
        """Return a specific (i, j) pair for controlled comparison."""
        return self.observations[i], self.observations[j]

    @property
    def length(self) -> int:
        return len(self.observations)

    @property
    def status_sequence(self) -> list[int]:
        return [o.status for o in self.observations]

    def summary(self) -> str:
        steps = " → ".join(
            f"{o.method} {o.path} [{o.status}]"
            for o in self.observations
        )
        return f"[{self.sequence_id}] {steps}"


# ── Sequence pair: a control + test observation for experiment tasks ───────────

@dataclass
class SequencePair:
    """A control/test observation pair for NET-F/G/H tasks.

    Represents a comparison between two observations, possibly from
    the same or different sequences.
    """
    pair_id: str
    control: NetworkObservation
    test: NetworkObservation
    changed_dimensions: list[str]  # subset of REQUEST_DIMENSIONS
    scenario_family: str = ""
    data_source: str = DATA_SOURCE

    # Phase II labels
    net_f_label: Optional[str] = None   # ExperimentQualityClass
    net_g_label: Optional[str] = None   # CausalSupportClass — given a hypothesis
    net_h_label: Optional[str] = None   # NextObservationType
    hypothesis: Optional[str] = None   # CausalHypothesis being evaluated

    @property
    def n_changed(self) -> int:
        return len(self.changed_dimensions)

    @property
    def is_single_variable(self) -> bool:
        return self.n_changed == 1

    @property
    def is_confounded(self) -> bool:
        return self.n_changed > 1
