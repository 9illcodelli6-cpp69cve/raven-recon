"""Tests for the RAVEN native-AI dataset + lineage + DENY system.

Proves: every sample carries the full lineage schema; split families are leak-free;
EVALUATION families are globally reserved to holdout; the private-data DEFAULT-DENY
guard blocks every private store / live-engagement provenance (and allows clean RAVEN
sources); the manifest hash is deterministic; the curriculum teaches all five honesty
axioms and populates every split family; the assembled corpus references NO private data.

Run:  python -m pytest tests/test_native_ai_dataset.py -q
"""
import pytest

from raven.native_ai.dataset import (
    DataSample, DedupStatus, NativeDataset, SplitFamily, PrivateDataError,
    is_private_source, assert_not_private, LINEAGE_FIELDS, PRIVATE_DB_FILES,
)
from raven.native_ai.curriculum_impl import (
    build_curriculum_dataset, HONESTY_AXIOMS, NativeCurriculum,
)


def _sample(**kw) -> DataSample:
    base = dict(
        sample_id="s1", text="hello 200 OK", source_id="raven.knowledge",
        source_type="REFERENCE_PROSE", origin="raven.knowledge.network_fundamentals",
        split_family=SplitFamily.NETWORK_CURRICULUM, group_key="g1",
    )
    base.update(kw)
    return DataSample(**base)


# ── lineage ───────────────────────────────────────────────────────────────

def test_every_lineage_field_present():
    s = _sample()
    lineage = s.lineage()
    for fld in LINEAGE_FIELDS:
        assert fld in lineage, f"missing lineage field: {fld}"
    assert "content_hash" in lineage
    # defaults encode a RAVEN-owned, synthetic-by-default provenance
    assert lineage["license"] == "RAVEN-OWNED"


def test_curriculum_samples_all_carry_lineage():
    ds = build_curriculum_dataset()
    assert len(ds) > 0
    for s in ds.samples:
        lin = s.lineage()
        assert all(f in lin for f in LINEAGE_FIELDS)
        assert isinstance(s.synthetic, bool)
        assert isinstance(s.human_reviewed, bool)
        assert s.split_family in set(SplitFamily)


# ── splits ──────────────────────────────────────────────────────────────────

def test_split_is_leak_free():
    ds = build_curriculum_dataset()
    splits = ds.split(seed=42)
    assert splits.is_leak_free()
    # no group_key crosses any boundary
    tr, va, ho = splits.families("train"), splits.families("val"), splits.families("holdout")
    assert not (tr & va) and not (tr & ho) and not (va & ho)


def test_evaluation_families_reserved_to_holdout():
    ds = build_curriculum_dataset()
    eval_groups = {s.group_key for s in ds.by_family(SplitFamily.EVALUATION)}
    assert eval_groups, "expected held-out EVALUATION families"
    splits = ds.split(seed=42)
    assert eval_groups <= splits.families("holdout")
    assert not (eval_groups & splits.families("train"))


def test_split_deterministic():
    ds = build_curriculum_dataset()
    a = ds.split(seed=7)
    b = ds.split(seed=7)
    assert [s.sample_id for s in a.train] == [s.sample_id for s in b.train]


# ── private-data DEFAULT-DENY ─────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    "conversations.db", "evidence_v7.db", "knowledge_v7.db", "tasks_v7.db",
    "workspaces_v7.db", "workspaces/acme/recon.db", "data/workspaces/x/recon.db",
    "recon.db", "C:\\raven\\workspaces\\t\\recon.db", "bugcrowd_live_target",
    "engagement/web_com", "some_v7.db",
])
def test_private_sources_detected(bad):
    assert is_private_source(bad) is True
    with pytest.raises(PrivateDataError):
        assert_not_private(bad)


def test_private_data_denied_on_add():
    ds = NativeDataset()
    with pytest.raises(PrivateDataError):
        ds.add(_sample(source_id="conversations.db", origin="conversations.db"))
    with pytest.raises(PrivateDataError):
        ds.add(_sample(source_id="x", origin="workspaces/acme/recon.db"))
    assert len(ds) == 0


def test_clean_sources_allowed():
    ds = NativeDataset()
    for origin in ("raven.knowledge.network_fundamentals",
                   "raven.network_fundamentals.taxonomy",
                   "raven.native_ai.curriculum_impl"):
        assert is_private_source(origin) is False
        ds.add(_sample(origin=origin, source_id=origin, group_key=origin))
    assert len(ds) == 3


def test_all_private_db_files_listed_and_blocked():
    for name in PRIVATE_DB_FILES:
        assert is_private_source(name)


def test_assembled_corpus_has_no_private_provenance():
    ds = build_curriculum_dataset()
    for s in ds.samples:
        assert not is_private_source(s.source_id, s.origin), s.lineage()


# ── manifest ──────────────────────────────────────────────────────────────

def test_manifest_fields_and_determinism():
    m1 = build_curriculum_dataset().manifest()
    m2 = build_curriculum_dataset().manifest()
    assert m1["content_hash"] == m2["content_hash"]
    assert m1["n_samples"] == len(build_curriculum_dataset())
    assert set(m1["lineage_fields"]) == set(LINEAGE_FIELDS)
    assert "DEFAULT-DENY" in m1["deny_policy"]


def test_dedup_removes_identical_text():
    ds = NativeDataset()
    ds.add(_sample(sample_id="a", text="same", group_key="a"))
    ds.add(_sample(sample_id="b", text="same", group_key="b"))
    ds.add(_sample(sample_id="c", text="other", group_key="c"))
    removed = ds.deduplicate()
    assert removed == 1
    assert len(ds) == 2


# ── curriculum content ────────────────────────────────────────────────────

def test_all_honesty_axioms_taught():
    assert set(HONESTY_AXIOMS) == {
        "200_not_vuln", "reflection_not_execution", "candidate_not_verified",
        "ml_not_ground_truth", "model_output_not_evidence",
    }
    ds = build_curriculum_dataset()
    corpus = "\n".join(ds.texts()).lower()
    for statement in HONESTY_AXIOMS.values():
        assert statement.lower()[:30] in corpus


def test_all_split_families_present():
    ds = build_curriculum_dataset()
    present = {s.split_family for s in ds.samples}
    assert present == set(SplitFamily)


def test_knowledge_curriculum_covers_18_parts():
    ds = build_curriculum_dataset()
    know = ds.by_family(SplitFamily.NETWORK_CURRICULUM)
    assert len(know) == 18


def test_teacher_pairs_are_deterministic_labels():
    ds = build_curriculum_dataset()
    instr = ds.by_family(SplitFamily.INSTRUCTION)
    assert instr
    for s in instr:
        assert "<|user|>" in s.text and "<|raven|>" in s.text and "<|endturn|>" in s.text


def test_native_curriculum_stage_order():
    c = NativeCurriculum()
    orders = [s.order for s in c.stages()]
    assert orders == sorted(orders)
    assert c.next_stage("s1_syntax").stage_id == "s2_knowledge"
    assert c.evaluation_hook("s4_teacher") == "eval_label_exact_match"
