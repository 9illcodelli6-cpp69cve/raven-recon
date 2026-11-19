"""RAVEN native-AI dataset + data-lineage system (pure Python, stdlib only).

Implements the dataset decisions in ``reconstruction/native_ai/ARCHITECTURE_DECISION.md``
§5 and the lineage policy in ``reconstruction/native_ai/DATASET_LINEAGE.md``:

  * Every sample carries full **lineage**: source id / source type / origin / license /
    language / domain / created_at / transformations / dedup status / split family /
    quality / synthetic flag / human-reviewed flag.
  * **Split families**: PRETRAIN / INSTRUCTION / EVALUATION / SECURITY_CURRICULUM /
    NETWORK_CURRICULUM / CODE / CONVERSATION.
  * **Leak-free splits**: reuses the grouped-family splitter from ``raven/ml/dataset.py``
    so no family (``group_key``) ever crosses the train/val/holdout boundary; every
    EVALUATION family is globally reserved to holdout.
  * A **dataset manifest** with a deterministic content hash.
  * **Private-data DEFAULT-DENY**: a hard guard (and a test) ensuring that
    ``conversations.db`` / ``evidence_v7.db`` / ``knowledge_v7.db`` / ``tasks_v7.db`` /
    ``workspaces_v7.db`` / ``workspaces/*/recon.db`` / any live engagement data can NEVER
    enter the corpus, the tokenizer training, or the eval sets.

This module is torch-free and does not build tensors (packing to training tensors is the
later SAFE_DESKTOP trainer's job). Nothing on the live path imports it, and it does not
flip ``raven.native_ai.NATIVE_GENERATIVE_MODEL`` (stays ``None``).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

# Reuse (do not reimplement) the grouped-family splitter from the ML dataset builder.
from raven.ml.dataset import DatasetBuilder, DatasetPolicy

SCHEMA_VERSION = "native-ai-dataset/1"


# ── split families & provenance vocab ─────────────────────────────────────────

class SplitFamily(str, Enum):
    PRETRAIN            = "PRETRAIN"
    INSTRUCTION         = "INSTRUCTION"
    EVALUATION          = "EVALUATION"
    SECURITY_CURRICULUM = "SECURITY_CURRICULUM"
    NETWORK_CURRICULUM  = "NETWORK_CURRICULUM"
    CODE                = "CODE"
    CONVERSATION        = "CONVERSATION"


class DedupStatus(str, Enum):
    UNIQUE     = "UNIQUE"
    DUPLICATE  = "DUPLICATE"
    UNCHECKED  = "UNCHECKED"


# ── private-data DEFAULT-DENY policy ──────────────────────────────────────────

class PrivateDataError(RuntimeError):
    """Raised when a sample's provenance points at private / engagement data."""


# Exact private store filenames that may NEVER be a training source.
PRIVATE_DB_FILES: Tuple[str, ...] = (
    "conversations.db", "evidence_v7.db", "knowledge_v7.db",
    "tasks_v7.db", "workspaces_v7.db",
)

# Lower-cased substring / pattern signals of private or live-engagement provenance.
_PRIVATE_PATTERNS: Tuple[str, ...] = (
    "recon.db",          # workspaces/*/recon.db and any recon store
    "_v7.db",            # any versioned private store
    "workspaces/",       # per-workspace engagement data
    "workspaces\\",
    "/engagement",
    "engagement/",
    "bugcrowd",          # live program data (e.g. the Web.com engagement)
    "hackerone",
    "live_target",
    "recon_session",
)

_WORKSPACE_RECON_RE = re.compile(r"workspaces[\\/][^\\/]+[\\/]recon\.db", re.IGNORECASE)


def is_private_source(*provenance: Optional[str]) -> bool:
    """True if any provenance string names a private store or live engagement data."""
    for p in provenance:
        if not p:
            continue
        low = p.lower()
        if any(low.endswith(name) or ("/" + name) in low or ("\\" + name) in low or low == name
               for name in PRIVATE_DB_FILES):
            return True
        if any(pat in low for pat in _PRIVATE_PATTERNS):
            return True
        if _WORKSPACE_RECON_RE.search(p):
            return True
    return False


def assert_not_private(*provenance: Optional[str]) -> None:
    if is_private_source(*provenance):
        raise PrivateDataError(
            "DEFAULT-DENY: provenance names private / live-engagement data "
            f"({[p for p in provenance if p]!r}); it may never enter the native-AI corpus."
        )


# ── sample + lineage ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DataSample:
    """One corpus sample with full lineage. Immutable."""
    sample_id: str
    text: str
    source_id: str
    source_type: str                 # e.g. REFERENCE_PROSE / DETERMINISTIC_TEACHER / AXIOM
    origin: str                      # module path or generator the text came from
    split_family: SplitFamily
    language: str = "en"             # "en", "ar", "mixed", "code", "technical"
    domain: str = "network-security"
    license: str = "RAVEN-OWNED"
    created_at: str = ""             # ISO date string (caller-supplied; not wallclock)
    transformations: Tuple[str, ...] = ()
    dedup_status: DedupStatus = DedupStatus.UNCHECKED
    quality: str = "reference"       # reference / synthetic-high / synthetic-low
    synthetic: bool = True           # RAVEN-authored synthetic/reference by default
    human_reviewed: bool = False
    group_key: str = ""              # family grouping used for leak-free splits

    def content_hash(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()[:16]

    def lineage(self) -> dict:
        d = asdict(self)
        d["split_family"] = self.split_family.value
        d["dedup_status"] = self.dedup_status.value
        d["content_hash"] = self.content_hash()
        return d


LINEAGE_FIELDS: Tuple[str, ...] = (
    "sample_id", "source_id", "source_type", "origin", "license", "language",
    "domain", "created_at", "transformations", "dedup_status", "split_family",
    "quality", "synthetic", "human_reviewed", "group_key",
)


# ── splits ──────────────────────────────────────────────────────────────────

@dataclass
class DatasetSplits:
    train: List[DataSample]
    val: List[DataSample]
    holdout: List[DataSample]

    @property
    def n_train(self) -> int: return len(self.train)
    @property
    def n_val(self) -> int: return len(self.val)
    @property
    def n_holdout(self) -> int: return len(self.holdout)

    def families(self, split: str) -> set:
        return {s.group_key for s in getattr(self, split)}

    def is_leak_free(self) -> bool:
        """No group_key (family) may appear in more than one split."""
        tr, va, ho = self.families("train"), self.families("val"), self.families("holdout")
        return not (tr & va) and not (tr & ho) and not (va & ho)


# ── the dataset ─────────────────────────────────────────────────────────────

class NativeDataset:
    """An in-memory, lineage-tracked, DENY-guarded native-AI corpus."""

    def __init__(self) -> None:
        self._samples: List[DataSample] = []
        self._seen_hashes: set = set()

    # -- construction (DENY-guarded) -------------------------------------------

    def add(self, sample: DataSample) -> DataSample:
        # Hard DEFAULT-DENY guard on provenance.
        assert_not_private(sample.source_id, sample.origin)
        self._samples.append(sample)
        return sample

    def extend(self, samples: Iterable[DataSample]) -> None:
        for s in samples:
            self.add(s)

    def deduplicate(self) -> int:
        """Drop later samples whose text hash was already seen. Returns #removed."""
        kept: List[DataSample] = []
        seen: set = set()
        removed = 0
        for s in self._samples:
            h = s.content_hash()
            if h in seen:
                removed += 1
                continue
            seen.add(h)
            kept.append(s)
        self._samples = kept
        self._seen_hashes = seen
        return removed

    # -- access ----------------------------------------------------------------

    @property
    def samples(self) -> List[DataSample]:
        return list(self._samples)

    def __len__(self) -> int:
        return len(self._samples)

    def by_family(self, family: SplitFamily) -> List[DataSample]:
        return [s for s in self._samples if s.split_family == family]

    def iterate(self, family: Optional[SplitFamily] = None) -> Iterator[DataSample]:
        for s in self._samples:
            if family is None or s.split_family == family:
                yield s

    def texts(self) -> List[str]:
        return [s.text for s in self._samples]

    def token_lengths(self, tokenizer) -> List[int]:
        """Token counts per sample using any encode()-providing tokenizer (torch-free)."""
        return [len(tokenizer.encode(s.text)) for s in self._samples]

    # -- leak-free splits (reuses ml/dataset grouped-family splitter) ----------

    def split(self, seed: int = 42,
              ratios: Tuple[float, float] = (0.80, 0.10)) -> DatasetSplits:
        """Leak-free train/val/holdout split.

        EVERY EVALUATION-family group is reserved globally to holdout; the remaining
        samples are split with the reused grouped-family splitter so no family crosses
        the train/val boundary. Group = ``group_key`` (a curriculum family id).
        """
        train_r, val_r = ratios
        eval_groups = {s.group_key for s in self._samples
                       if s.split_family == SplitFamily.EVALUATION}
        reserved = [s for s in self._samples if s.group_key in eval_groups]
        rest = [s for s in self._samples if s.group_key not in eval_groups]

        builder = DatasetBuilder(policy=DatasetPolicy.DEV_SYNTHETIC, seed=seed)
        # Reuse the grouped-family splitter verbatim; it reads only `.group_key`.
        tr, va, te = builder._group_aware_split(rest, train_r, val_r)

        splits = DatasetSplits(train=list(tr), val=list(va), holdout=list(te) + reserved)
        if not splits.is_leak_free():
            raise RuntimeError("split integrity violated: a family crossed a boundary")
        return splits

    # -- manifest --------------------------------------------------------------

    def manifest(self) -> dict:
        per_family: Dict[str, int] = {}
        per_language: Dict[str, int] = {}
        for s in self._samples:
            per_family[s.split_family.value] = per_family.get(s.split_family.value, 0) + 1
            per_language[s.language] = per_language.get(s.language, 0) + 1
        hashes = sorted(s.content_hash() for s in self._samples)
        content_hash = hashlib.sha256(
            json.dumps(hashes, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return {
            "schema_version": SCHEMA_VERSION,
            "n_samples": len(self._samples),
            "families": per_family,
            "languages": per_language,
            "lineage_fields": list(LINEAGE_FIELDS),
            "deny_policy": "DEFAULT-DENY: private/engagement data excluded",
            "content_hash": content_hash,
        }
