"""Native-model registry — §16 entries over the ml/registry JSON-registry pattern.

A JSON-backed registry for from-scratch RAVEN generative checkpoints. It REUSES the
lifecycle discipline of ``raven/ml/registry.py`` (which is NOT edited or imported for
mutation): persistent JSON file, register-as-earliest-maturity-only, explicit stepwise
transitions, and — crucially — **no model ever self-promotes to PRODUCTION**. Promotion
is an explicit researcher action with a human identifier.

Each :class:`NativeModelEntry` carries the §16 fields:
    model_id, family, architecture_version, tokenizer_version, parameter_count,
    context_window, checkpoint_path, checkpoint_hash, training_run_id,
    dataset_manifest_hash, maturity, capabilities, resource_profile,
    evaluation_summary, loaded_state.

Maturity ladder: ``EXPERIMENTAL_BOOTSTRAP → DEVELOPMENT → CANDIDATE → PRODUCTION``.
A newly registered entry may only be ``EXPERIMENTAL_BOOTSTRAP`` or ``DEVELOPMENT``;
``PRODUCTION`` is reachable only via :meth:`promote_to_production` from ``CANDIDATE``,
and only with a non-model human identifier. Registering/using this does NOT flip
``raven.native_ai.NATIVE_GENERATIVE_MODEL`` (stays ``None``).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional


class NativeMaturity(str, Enum):
    EXPERIMENTAL_BOOTSTRAP = "EXPERIMENTAL_BOOTSTRAP"
    DEVELOPMENT            = "DEVELOPMENT"
    CANDIDATE             = "CANDIDATE"
    PRODUCTION            = "PRODUCTION"
    ARCHIVED              = "ARCHIVED"


# Allowed forward transitions (archival is reachable from any live state).
_LADDER = {
    NativeMaturity.EXPERIMENTAL_BOOTSTRAP: {NativeMaturity.DEVELOPMENT, NativeMaturity.ARCHIVED},
    NativeMaturity.DEVELOPMENT:            {NativeMaturity.CANDIDATE, NativeMaturity.ARCHIVED},
    NativeMaturity.CANDIDATE:              {NativeMaturity.PRODUCTION, NativeMaturity.ARCHIVED},
    NativeMaturity.PRODUCTION:             {NativeMaturity.ARCHIVED},
    NativeMaturity.ARCHIVED:               set(),
}

_REGISTERABLE = {NativeMaturity.EXPERIMENTAL_BOOTSTRAP, NativeMaturity.DEVELOPMENT}
# Identifiers that may NOT promote anything — a model can never promote itself.
_FORBIDDEN_PROMOTERS = {"", "model", "auto", "self", "native_ai", "raven", "system",
                        "trainer", "pipeline"}

SCHEMA_VERSION = "native-registry/1"


@dataclass
class NativeModelEntry:
    """§16 record for one native RAVEN generative checkpoint."""
    model_id: str
    family: str                                   # e.g. "RAVEN-LM"
    architecture_version: str                     # e.g. "raven-lm/1"
    tokenizer_version: str
    parameter_count: int
    context_window: int
    checkpoint_path: str
    checkpoint_hash: str
    training_run_id: str
    dataset_manifest_hash: str
    maturity: NativeMaturity = NativeMaturity.EXPERIMENTAL_BOOTSTRAP
    capabilities: List[str] = field(default_factory=list)
    resource_profile: Dict = field(default_factory=dict)
    evaluation_summary: Dict = field(default_factory=dict)
    loaded_state: str = "NOT_LOADED"              # NOT_LOADED | LOADED | FAILED
    tokenizer_hash: str = ""
    promoted_by: Optional[str] = None
    promotion_notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["maturity"] = self.maturity.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "NativeModelEntry":
        d = dict(d)
        d["maturity"] = NativeMaturity(d.get("maturity", "EXPERIMENTAL_BOOTSTRAP"))
        return cls(**d)


# The §16 field set, exported so tests/other agents can assert completeness.
SECTION16_FIELDS = (
    "model_id", "family", "architecture_version", "tokenizer_version",
    "parameter_count", "context_window", "checkpoint_path", "checkpoint_hash",
    "training_run_id", "dataset_manifest_hash", "maturity", "capabilities",
    "resource_profile", "evaluation_summary", "loaded_state",
)


class NativeModelRegistry:
    """Persistent JSON registry for native checkpoints (mirrors ml/registry pattern)."""

    def __init__(self, registry_path: str) -> None:
        self._path = Path(registry_path)
        self._entries: Dict[str, NativeModelEntry] = {}
        self._load()

    # -- registration ----------------------------------------------------------

    def register(self, entry: NativeModelEntry) -> None:
        if entry.maturity not in _REGISTERABLE:
            raise ValueError(
                f"new registrations must be EXPERIMENTAL_BOOTSTRAP or DEVELOPMENT; "
                f"got {entry.maturity.value} (no auto-PRODUCTION)")
        if entry.model_id in self._entries:
            raise ValueError(f"model_id already registered: {entry.model_id}")
        self._entries[entry.model_id] = entry
        self._save()

    # -- lifecycle (explicit, stepwise, no auto-promotion) ---------------------

    def _transition(self, model_id: str, target: NativeMaturity) -> None:
        e = self._get(model_id)
        if target not in _LADDER[e.maturity]:
            raise ValueError(
                f"illegal maturity transition {e.maturity.value} -> {target.value}")
        e.maturity = target
        self._save()

    def advance_to_development(self, model_id: str) -> None:
        self._transition(model_id, NativeMaturity.DEVELOPMENT)

    def advance_to_candidate(self, model_id: str) -> None:
        self._transition(model_id, NativeMaturity.CANDIDATE)

    def promote_to_production(self, model_id: str, promoted_by: str,
                              notes: str = "") -> None:
        """Promote a CANDIDATE to PRODUCTION — explicit researcher action ONLY.

        Refuses any model/automated identifier: a model can never promote itself, and
        nothing in the pipeline promotes automatically.
        """
        who = (promoted_by or "").strip().lower()
        if who in _FORBIDDEN_PROMOTERS:
            raise PermissionError(
                f"promotion requires an explicit human researcher identifier; "
                f"{promoted_by!r} is not permitted (no model self-promotion)")
        e = self._get(model_id)
        if e.maturity != NativeMaturity.CANDIDATE:
            raise ValueError(
                f"{model_id} must be CANDIDATE to promote; is {e.maturity.value}")
        e.maturity = NativeMaturity.PRODUCTION
        e.promoted_by = promoted_by
        e.promotion_notes = notes
        self._save()

    def archive(self, model_id: str) -> None:
        self._transition(model_id, NativeMaturity.ARCHIVED)

    def set_loaded_state(self, model_id: str, state: str) -> None:
        e = self._get(model_id)
        e.loaded_state = state
        self._save()

    # -- queries ---------------------------------------------------------------

    def get(self, model_id: str) -> Optional[NativeModelEntry]:
        return self._entries.get(model_id)

    def list_entries(self, maturity: Optional[NativeMaturity] = None) -> List[NativeModelEntry]:
        out = list(self._entries.values())
        if maturity is not None:
            out = [e for e in out if e.maturity == maturity]
        return sorted(out, key=lambda e: e.model_id)

    def production_models(self) -> List[NativeModelEntry]:
        return self.list_entries(NativeMaturity.PRODUCTION)

    # -- persistence -----------------------------------------------------------

    def _get(self, model_id: str) -> NativeModelEntry:
        e = self._entries.get(model_id)
        if e is None:
            raise KeyError(f"native model not found: {model_id}")
        return e

    def _load(self) -> None:
        if not self._path.exists():
            return
        with open(self._path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for row in data.get("entries", []):
            e = NativeModelEntry.from_dict(row)
            self._entries[e.model_id] = e

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {"schema_version": SCHEMA_VERSION,
                "entries": [e.to_dict() for e in self._entries.values()]}
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        tmp.replace(self._path)


# ── builder: checkpoint manifest (+ eval summary) → §16 entry ─────────────────

def entry_from_manifest(manifest: Dict, *, checkpoint_path: str, checkpoint_hash: str,
                        evaluation_summary: Optional[Dict] = None,
                        family: str = "RAVEN-LM",
                        capabilities: Optional[List[str]] = None,
                        loaded_state: str = "NOT_LOADED") -> NativeModelEntry:
    """Construct a §16 registry entry from a trainer checkpoint manifest.

    Maturity is taken from the manifest (``EXPERIMENTAL_BOOTSTRAP`` for a bootstrap run)
    — never upgraded here. Promotion is a separate, explicit registry action.
    """
    cfg = manifest.get("config", {})
    run_id = manifest.get("run_id", "")
    model_id = f"{family.lower()}-{run_id or manifest.get('seed', 'x')}"
    budget = manifest.get("budget", {})
    resource_profile = {
        "posture": budget.get("name", "SAFE_DESKTOP"),
        "max_threads": budget.get("max_threads"),
        "max_batch_size": budget.get("max_batch_size"),
        "max_seq_len": budget.get("max_seq_len"),
        "max_steps": budget.get("max_steps"),
        "max_wall_clock_s": budget.get("max_wall_clock_s"),
        "device": "cpu",
        "precision": "fp32",
    }
    return NativeModelEntry(
        model_id=model_id,
        family=family,
        architecture_version=manifest.get("architecture_version", "raven-lm/1"),
        tokenizer_version=manifest.get("tokenizer_version", ""),
        parameter_count=int(manifest.get("parameter_count", 0)),
        context_window=int(manifest.get("context_window",
                                        cfg.get("context_length", 0))),
        checkpoint_path=checkpoint_path,
        checkpoint_hash=checkpoint_hash,
        training_run_id=run_id,
        dataset_manifest_hash=manifest.get("dataset_manifest_hash", ""),
        maturity=NativeMaturity(manifest.get("maturity", "EXPERIMENTAL_BOOTSTRAP")),
        capabilities=list(capabilities or ["text-generation", "advisory-only"]),
        resource_profile=resource_profile,
        evaluation_summary=dict(evaluation_summary or {}),
        loaded_state=loaded_state,
        tokenizer_hash=manifest.get("tokenizer_hash", ""),
    )
