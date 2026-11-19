"""RAVEN Network Fundamentals — educational synthetic dataset.

Generates feature-label pairs for NET-A/B/C/D from LocalNetworkLab fixtures.
Uses STRATIFIED grouped splitting: guarantees at least 1 family per class
in the training set, preventing SPLIT_COVERAGE_FAILURE.

INVARIANTS:
- ALL data is EDUCATIONAL_SYNTHETIC.
- Human-reviewed labels are 0 (never mixed here).
- Grouped split prevents families from spanning train/test boundary.
- Stratified grouped split guarantees all classes covered in train.
- Labels are protocol/application state — NOT security verdicts.
- is_security_relevant is NEVER set True by this module.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional

from raven.network_fundamentals.lab import LocalNetworkLab, Fixture
from raven.network_fundamentals.features import NetworkFeaturePipeline, NetworkFeatureVector

DATA_SOURCE = "EDUCATIONAL_SYNTHETIC"


@dataclass
class LabelledExample:
    features: list[float]
    net_a_label: str
    net_b_label: str
    net_c_label: str
    net_d_label: str
    fixture_family: str
    fixture_id: str
    data_source: str = DATA_SOURCE


@dataclass
class SplitReport:
    """Evidence that stratified grouped split succeeded."""
    task: str
    n_train: int
    n_test: int
    train_families: list[str]
    test_families: list[str]
    train_classes: list[str]
    test_classes: list[str]
    missing_train_classes: list[str]   # must be empty for a valid split
    family_intersection: list[str]     # must be empty (no leakage)


def _stratified_grouped_split(
    examples: list[LabelledExample],
    label_field: str,
    test_fraction: float = 0.2,
    seed: int = 42,
) -> tuple[list[LabelledExample], list[LabelledExample], SplitReport]:
    """Stratified grouped split that guarantees all classes in train.

    Algorithm:
    1. For each class, find all families that contain that class.
    2. Guarantee 1 family per class stays in train (anchor families).
    3. Remaining non-anchor families are split proportionally into test.
    4. If test_fraction cannot be honoured without violating coverage,
       fewer families go to test (no exception — coverage wins).

    Returns (train_examples, test_examples, SplitReport).
    """
    rng = random.Random(seed)

    # Map class → set of families
    class_to_families: dict[str, set[str]] = {}
    for e in examples:
        lbl = getattr(e, label_field)
        fam = e.fixture_family
        class_to_families.setdefault(lbl, set()).add(fam)

    all_families = sorted({e.fixture_family for e in examples})
    rng.shuffle(all_families)

    # Anchor: for each class, pick 1 family (prefer those not yet anchored).
    # Use sorted class index (not hash()) to guarantee determinism across processes.
    anchor_families: set[str] = set()
    for idx, (cls, fams) in enumerate(sorted(class_to_families.items())):
        unanchored = fams - anchor_families
        candidates = list(unanchored) if unanchored else list(fams)
        rng_pick = random.Random(seed + idx)
        anchor_families.add(rng_pick.choice(sorted(candidates)))

    # Non-anchor families are candidates for test
    non_anchor = [f for f in all_families if f not in anchor_families]
    n_test = max(0, int(len(all_families) * test_fraction))
    # Never take more than available non-anchor families
    n_test = min(n_test, len(non_anchor))
    test_families = set(non_anchor[:n_test])
    train_families = set(all_families) - test_families

    train = [e for e in examples if e.fixture_family in train_families]
    test  = [e for e in examples if e.fixture_family in test_families]

    train_cls = sorted({getattr(e, label_field) for e in train})
    test_cls  = sorted({getattr(e, label_field) for e in test})
    all_cls   = sorted(class_to_families.keys())
    missing   = [c for c in all_cls if c not in train_cls]
    overlap   = sorted(train_families & test_families)

    report = SplitReport(
        task=label_field,
        n_train=len(train),
        n_test=len(test),
        train_families=sorted(train_families),
        test_families=sorted(test_families),
        train_classes=train_cls,
        test_classes=test_cls,
        missing_train_classes=missing,
        family_intersection=overlap,
    )
    return train, test, report


class NetworkDataset:
    """Builds train/test splits for all four NET tasks from lab fixtures."""

    def __init__(self, seed: int = 42):
        self._seed = seed
        self._pipeline = NetworkFeaturePipeline()
        self._examples: list[LabelledExample] = []
        self._built = False

    def build(self) -> "NetworkDataset":
        lab = LocalNetworkLab()
        for f in lab.all_fixtures():
            fv = self._pipeline.extract(f.observation)
            self._examples.append(LabelledExample(
                features=fv.to_list(),
                net_a_label=f.protocol_label,
                net_b_label=f.difference_label,
                net_c_label=f.session_label,
                net_d_label=f.auth_label,
                fixture_family=f.family,
                fixture_id=f.fixture_id,
            ))
        self._built = True
        return self

    def _check_built(self) -> None:
        if not self._built:
            raise RuntimeError("Call build() before using dataset")

    def split(self, test_fraction: float = 0.2) -> tuple[list, list]:
        """Simple grouped split on all examples (ignores UNKNOWN filtering)."""
        self._check_built()
        families = sorted({e.fixture_family for e in self._examples})
        rng = __import__("random").Random(self._seed)
        rng.shuffle(families)
        n_test = max(1, int(len(families) * test_fraction))
        test_families = set(families[:n_test])
        train = [e for e in self._examples if e.fixture_family not in test_families]
        test  = [e for e in self._examples if e.fixture_family in test_families]
        return train, test

    def get_task_arrays(
        self, task: str, test_fraction: float = 0.2,
    ) -> tuple[list, list, list, list]:
        """Return (X_train, y_train, X_test, y_test) for one task.

        Filters UNKNOWN first, then uses stratified grouped split to
        guarantee all non-UNKNOWN classes appear in training.
        """
        self._check_built()
        label_field = _task_field(task)
        relevant = [e for e in self._examples if getattr(e, label_field) != "UNKNOWN"]
        train, test, _ = _stratified_grouped_split(
            relevant, label_field, test_fraction, self._seed)
        X_tr = [e.features for e in train]
        y_tr = [getattr(e, label_field) for e in train]
        X_te = [e.features for e in test]
        y_te = [getattr(e, label_field) for e in test]
        return X_tr, y_tr, X_te, y_te

    def get_split_report(self, task: str, test_fraction: float = 0.2) -> SplitReport:
        """Return the split coverage report without discarding examples."""
        self._check_built()
        label_field = _task_field(task)
        relevant = [e for e in self._examples if getattr(e, label_field) != "UNKNOWN"]
        _, _, report = _stratified_grouped_split(
            relevant, label_field, test_fraction, self._seed)
        return report

    @property
    def n_examples(self) -> int:
        return len(self._examples)

    def label_distribution(self, task: str) -> dict[str, int]:
        self._check_built()
        label_field = _task_field(task)
        dist: dict[str, int] = {}
        for e in self._examples:
            lbl = getattr(e, label_field)
            dist[lbl] = dist.get(lbl, 0) + 1
        return dist

    def all_examples(self) -> list[LabelledExample]:
        self._check_built()
        return list(self._examples)


def _task_field(task: str) -> str:
    return {
        "net_a": "net_a_label",
        "net_b": "net_b_label",
        "net_c": "net_c_label",
        "net_d": "net_d_label",
    }[task]
