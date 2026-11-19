"""RAVEN ML Dataset Builder (Phases 70-75, 84-85).

Produces train/val/test splits from labeled observations.

INVARIANTS:
- No label-derived features (labels stored separately from feature vectors).
- Synthetic data allowed only for pipeline validation; always marked DEVELOPMENT_ONLY.
- Group-aware split: observations from the same target host never span train/test.
- Duplicate detection by feature hash before splitting.
- Temporal split option: earlier observations → train, later → test.
"""
from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Tuple, Dict, Any

from .features import FeatureVector, FeaturePipeline, FEATURE_SCHEMA_VERSION


class DatasetPolicy(str, Enum):
    REAL_ONLY     = "real_only"
    DEV_SYNTHETIC = "dev_synthetic"   # synthetic allowed; DEVELOPMENT_ONLY flag set


@dataclass
class LabeledExample:
    feature_vector: FeatureVector
    label_task_a: int    # 1=response differs meaningfully, 0=does not, -1=unlabeled
    label_task_b: int    # 1=auth-relevant difference, 0=not, -1=unlabeled / N/A
    observation_id: Optional[str] = None
    group_key: Optional[str] = None   # hostname — used for group-aware split
    timestamp_ms: Optional[int] = None
    synthetic: bool = False           # True → DEVELOPMENT_ONLY synthetic sample

    def feature_hash(self) -> str:
        vals = self.feature_vector.to_list()
        raw = json.dumps(vals, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()[:16]


@dataclass
class DatasetSplit:
    train: List[LabeledExample]
    val:   List[LabeledExample]
    test:  List[LabeledExample]
    policy: DatasetPolicy = DatasetPolicy.REAL_ONLY
    schema_version: str = FEATURE_SCHEMA_VERSION

    @property
    def n_train(self): return len(self.train)
    @property
    def n_val(self):   return len(self.val)
    @property
    def n_test(self):  return len(self.test)
    @property
    def n_total(self): return self.n_train + self.n_val + self.n_test

    def contains_synthetic(self) -> bool:
        return any(e.synthetic for e in self.train + self.val + self.test)

    def task_a_label_counts(self) -> dict:
        all_labels = [e.label_task_a for e in self.train + self.val + self.test]
        return {
            "positive":  sum(1 for x in all_labels if x == 1),
            "negative":  sum(1 for x in all_labels if x == 0),
            "unlabeled": sum(1 for x in all_labels if x == -1),
        }

    def summary(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "policy":         self.policy,
            "n_train":        self.n_train,
            "n_val":          self.n_val,
            "n_test":         self.n_test,
            "n_total":        self.n_total,
            "contains_synthetic": self.contains_synthetic(),
            "task_a_label_counts": self.task_a_label_counts(),
        }


class DatasetBuilder:
    """Build a DatasetSplit from labeled observations.

    Supports:
    - Group-aware split (by hostname group_key)
    - Temporal split (by timestamp_ms)
    - Duplicate detection and deduplication
    - Synthetic data injection (DEVELOPMENT_ONLY policy only)
    """

    DEFAULT_RATIOS = (0.70, 0.15, 0.15)

    def __init__(self, policy: DatasetPolicy = DatasetPolicy.REAL_ONLY,
                 seed: int = 42):
        self.policy = policy
        self.seed   = seed
        self._rng   = random.Random(seed)

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def build_from_examples(
        self,
        examples: List[LabeledExample],
        ratios: Tuple[float, float, float] = DEFAULT_RATIOS,
        temporal: bool = False,
        deduplicate: bool = True,
    ) -> DatasetSplit:
        """Build a DatasetSplit from a list of LabeledExamples.

        ratios: (train, val, test) fractions — must sum to ~1.0
        temporal: if True, sort by timestamp and split chronologically
        deduplicate: remove identical feature hashes before splitting
        """
        if self.policy == DatasetPolicy.REAL_ONLY:
            synthetic_count = sum(1 for e in examples if e.synthetic)
            if synthetic_count > 0:
                raise ValueError(
                    f"DatasetPolicy.REAL_ONLY but {synthetic_count} synthetic examples supplied. "
                    "Switch to DatasetPolicy.DEV_SYNTHETIC for pipeline validation."
                )

        if deduplicate:
            examples = self._deduplicate(examples)

        if len(examples) == 0:
            return DatasetSplit(train=[], val=[], test=[], policy=self.policy)

        tr, va, te = ratios
        if abs(tr + va + te - 1.0) > 1e-6:
            raise ValueError(f"Ratios must sum to 1.0, got {tr+va+te}")

        if temporal:
            split = self._temporal_split(examples, tr, va)
        else:
            split = self._group_aware_split(examples, tr, va)

        return DatasetSplit(
            train=split[0],
            val=split[1],
            test=split[2],
            policy=self.policy,
            schema_version=FEATURE_SCHEMA_VERSION,
        )

    def build_synthetic_dev_set(
        self,
        n_positive: int = 200,
        n_negative: int = 200,
    ) -> List[LabeledExample]:
        """Generate synthetic labeled examples for DEVELOPMENT_ONLY pipeline validation.

        These examples are purely synthetic — randomly generated feature values with
        plausible label assignments. They are NOT suitable for production training,
        NOT representative of real findings, and MUST NOT be used to claim model
        performance. Policy must be DEV_SYNTHETIC.
        """
        if self.policy != DatasetPolicy.DEV_SYNTHETIC:
            raise ValueError(
                "Synthetic data requires DatasetPolicy.DEV_SYNTHETIC. "
                "This data is DEVELOPMENT_ONLY and not suitable for production use."
            )

        examples: List[LabeledExample] = []

        for i in range(n_positive):
            fv = self._make_synthetic_positive_fv(i)
            examples.append(LabeledExample(
                feature_vector=fv,
                label_task_a=1,
                label_task_b=1 if self._rng.random() < 0.6 else 0,
                observation_id=f"synth_pos_{i}",
                group_key=f"synth_host_{i % 10}",
                timestamp_ms=i * 1000,
                synthetic=True,
            ))

        for i in range(n_negative):
            fv = self._make_synthetic_negative_fv(i)
            examples.append(LabeledExample(
                feature_vector=fv,
                label_task_a=0,
                label_task_b=0,
                observation_id=f"synth_neg_{i}",
                group_key=f"synth_host_{(n_positive + i) % 10}",
                timestamp_ms=(n_positive + i) * 1000,
                synthetic=True,
            ))

        self._rng.shuffle(examples)
        return examples

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _deduplicate(self, examples: List[LabeledExample]) -> List[LabeledExample]:
        seen: set = set()
        result: List[LabeledExample] = []
        for e in examples:
            h = e.feature_hash()
            if h not in seen:
                seen.add(h)
                result.append(e)
        return result

    def _group_aware_split(
        self, examples: List[LabeledExample], train_r: float, val_r: float
    ) -> Tuple[List, List, List]:
        """Assign entire groups to one split to prevent leakage."""
        groups: Dict[str, List[LabeledExample]] = {}
        for e in examples:
            key = e.group_key or "__ungrouped__"
            groups.setdefault(key, []).append(e)

        group_keys = list(groups.keys())
        self._rng.shuffle(group_keys)

        n = len(group_keys)
        n_train = max(1, int(round(n * train_r)))
        n_val   = max(1, int(round(n * val_r)))
        if n_train + n_val >= n:
            n_val = max(0, n - n_train - 1)

        train_keys = set(group_keys[:n_train])
        val_keys   = set(group_keys[n_train:n_train + n_val])
        test_keys  = set(group_keys[n_train + n_val:])

        train, val, test = [], [], []
        for k, exs in groups.items():
            if k in train_keys:
                train.extend(exs)
            elif k in val_keys:
                val.extend(exs)
            else:
                test.extend(exs)

        return train, val, test

    def _temporal_split(
        self, examples: List[LabeledExample], train_r: float, val_r: float
    ) -> Tuple[List, List, List]:
        """Sort by timestamp; earlier observations → train."""
        sorted_ex = sorted(examples, key=lambda e: (e.timestamp_ms or 0))
        n = len(sorted_ex)
        i_train = int(n * train_r)
        i_val   = int(n * (train_r + val_r))
        return sorted_ex[:i_train], sorted_ex[i_train:i_val], sorted_ex[i_val:]

    def _make_synthetic_positive_fv(self, seed_offset: int) -> FeatureVector:
        r = random.Random(self.seed + seed_offset)
        fv = FeatureVector()
        # "Positive" = response meaningfully differs (e.g., 200 vs 403 scenario)
        fv.status_code            = r.choice([200, 200, 200, 403, 404, 301])
        fv.status_class           = fv.status_code // 100
        fv.body_size              = r.randint(50, 10000)
        fv.body_entropy           = r.uniform(3.5, 6.0)
        fv.printable_ratio        = r.uniform(0.85, 1.0)
        fv.is_text_like           = 1
        fv.is_json                = r.randint(0, 1)
        fv.header_count           = r.randint(3, 15)
        fv.has_content_type       = 1
        fv.has_set_cookie         = r.randint(0, 1)
        fv.has_location           = r.randint(0, 1)
        fv.elapsed_ms             = r.randint(50, 2000)
        # Differs meaningfully: low similarity
        fv.body_similarity        = r.uniform(0.0, 0.5)
        fv.simhash_similarity     = fv.body_similarity + r.uniform(-0.1, 0.1)
        fv.exact_body_match       = 0
        fv.normalized_body_match  = 0
        fv.header_added_count     = r.randint(0, 5)
        fv.header_removed_count   = r.randint(0, 5)
        fv.header_changed_count   = r.randint(1, 8)
        fv.json_key_count         = r.randint(0, 30)
        fv.json_diff_count        = r.randint(1, 20)
        fv.length_z_score         = r.uniform(-3.0, 3.0)
        return fv

    def _make_synthetic_negative_fv(self, seed_offset: int) -> FeatureVector:
        r = random.Random(self.seed + 10000 + seed_offset)
        fv = FeatureVector()
        # "Negative" = response does NOT differ meaningfully
        fv.status_code            = r.choice([200, 200, 200, 200, 304])
        fv.status_class           = fv.status_code // 100
        fv.body_size              = r.randint(500, 5000)
        fv.body_entropy           = r.uniform(3.0, 5.5)
        fv.printable_ratio        = r.uniform(0.85, 1.0)
        fv.is_text_like           = 1
        fv.is_json                = r.randint(0, 1)
        fv.header_count           = r.randint(4, 12)
        fv.has_content_type       = 1
        fv.has_set_cookie         = r.randint(0, 1)
        fv.has_location           = 0
        fv.elapsed_ms             = r.randint(50, 800)
        # Does not differ: high similarity
        fv.body_similarity        = r.uniform(0.85, 1.0)
        fv.simhash_similarity     = fv.body_similarity + r.uniform(-0.05, 0.05)
        fv.exact_body_match       = 1 if fv.body_similarity > 0.98 else 0
        fv.normalized_body_match  = fv.exact_body_match
        fv.header_added_count     = 0
        fv.header_removed_count   = 0
        fv.header_changed_count   = r.randint(0, 1)
        fv.json_key_count         = r.randint(0, 20)
        fv.json_diff_count        = 0
        fv.length_z_score         = r.uniform(-0.5, 0.5)
        return fv
