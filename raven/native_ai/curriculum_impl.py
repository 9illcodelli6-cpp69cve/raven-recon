"""RAVEN native-AI curriculum builder (pure Python, stdlib only).

Builds the curriculum TEXT corpus from the reclassified RAVEN assets described in
``reconstruction/native_ai/ARCHITECTURE_DECISION.md`` §5 — provenance-only reuse, with
ZERO edits to the source packages:

  * **Knowledge prose** — the 18 ``NETWORK_KNOWLEDGE`` parts rendered as English
    technical curriculum text (NETWORK_CURRICULUM family).
  * **Deterministic teachers** — ``ProtocolClass.from_status`` turns observations into
    ``observation -> CLASS`` generative instruction pairs (INSTRUCTION family), with a
    disjoint held-out set tagged EVALUATION so eval families never appear in training.
  * **Honesty axioms** — the binding axioms (200 != vuln, reflection != execution,
    candidate != verified, ML != ground-truth, model-output != evidence) as explicit
    SECURITY_CURRICULUM text.
  * **Syntax warmup** — raw HTTP/JSON/header fixture text (PRETRAIN family) matching the
    tokenizer's technical atoms.
  * small **CODE** and **CONVERSATION** families for coverage.

Split integrity: EVALUATION families carry distinct ``group_key`` values, so the
dataset's grouped-family splitter keeps them held-out, never trained on.

Torch-free. Not imported by any live path; does not flip
``raven.native_ai.NATIVE_GENERATIVE_MODEL`` (stays ``None``).
"""
from __future__ import annotations

from typing import List, Optional

from raven.knowledge.network_fundamentals import NETWORK_KNOWLEDGE
from raven.network_fundamentals.taxonomy import ProtocolClass

from .curriculum import Curriculum, CurriculumStage
from .dataset import DataSample, DedupStatus, NativeDataset, SplitFamily

_CREATED = "2026-10-06"

# The five binding honesty axioms this curriculum must teach (keyword -> statement).
HONESTY_AXIOMS = {
    "200_not_vuln": (
        "A 200 OK status code is not a vulnerability. A successful response is normal "
        "protocol behavior; it is not evidence of a security flaw by itself."
    ),
    "reflection_not_execution": (
        "Reflection is not execution. An input echoed back in a response is reflected, "
        "not executed; reflection alone does not confirm code execution or injection."
    ),
    "candidate_not_verified": (
        "A candidate finding is not a verified finding. A candidate is a hypothesis "
        "awaiting evidence; only verification against ground truth can confirm it."
    ),
    "ml_not_ground_truth": (
        "A machine-learning prediction is not ground truth. A model score is advisory; "
        "it does not set verification status and never becomes a label by itself."
    ),
    "model_output_not_evidence": (
        "Model output is not evidence. Generated text is advisory and must be verified; "
        "it never authorizes an action and never becomes a security verdict."
    ),
}


# ── knowledge prose (NETWORK_CURRICULUM) ──────────────────────────────────────

def knowledge_prose_samples() -> List[DataSample]:
    out: List[DataSample] = []
    for part_id, entry in NETWORK_KNOWLEDGE.items():
        lines = [f"# {entry.title}", "", entry.summary, ""]
        if entry.key_concepts:
            lines.append("Key concepts:")
            lines.extend(f"- {c}" for c in entry.key_concepts)
            lines.append("")
        if entry.non_vulnerability_reminders:
            lines.append("Non-vulnerability reminders:")
            lines.extend(f"- {r}" for r in entry.non_vulnerability_reminders)
        text = "\n".join(lines).strip()
        out.append(DataSample(
            sample_id=f"know::{part_id}",
            text=text,
            source_id=part_id,
            source_type="REFERENCE_PROSE",
            origin="raven.knowledge.network_fundamentals:NETWORK_KNOWLEDGE",
            split_family=SplitFamily.NETWORK_CURRICULUM,
            language="en",
            created_at=_CREATED,
            transformations=("render_entry_to_prose",),
            dedup_status=DedupStatus.UNIQUE,
            quality="reference",
            synthetic=False,
            human_reviewed=True,
            group_key=f"knowledge:{part_id}",
        ))
    return out


# ── deterministic teacher (INSTRUCTION + held-out EVALUATION) ─────────────────

# Observation grid: (status, has_www_auth, has_retry_after, timed_out, conn_err).
_TEACHER_GRID = [
    (200, False, False, False, False),
    (201, False, False, False, False),
    (204, False, False, False, False),
    (301, False, False, False, False),
    (302, False, False, False, False),
    (400, False, False, False, False),
    (403, False, False, False, False),
    (404, False, False, False, False),
    (409, False, False, False, False),
    (422, False, False, False, False),
    (429, False, True,  False, False),
    (500, False, False, False, False),
    (502, False, False, False, False),
    (0,   False, False, True,  False),
    (0,   False, False, False, True),
]

# Disjoint held-out observations — distinct families, reserved for EVALUATION only.
_TEACHER_EVAL_GRID = [
    (401, True,  False, False, False),
    (503, False, True,  False, False),
    (405, False, False, False, False),
    (304, False, False, False, False),
]


def _observation_text(status, www_auth, retry_after, timed_out, conn_err) -> str:
    return (
        "Classify the HTTP response behavior. "
        f"status_code={status}, "
        f"www_authenticate={'present' if www_auth else 'absent'}, "
        f"retry_after={'present' if retry_after else 'absent'}, "
        f"timed_out={'yes' if timed_out else 'no'}, "
        f"connection_error={'yes' if conn_err else 'no'}."
    )


def _teacher_sample(obs, family: SplitFamily, idx: int) -> DataSample:
    status, www_auth, retry_after, timed_out, conn_err = obs
    label = ProtocolClass.from_status(
        status, has_www_auth=www_auth, has_retry_after=retry_after,
        timed_out=timed_out, connection_error=conn_err,
    ).value
    obs_text = _observation_text(*obs)
    text = f"<|user|>{obs_text}<|raven|>{label}<|endturn|>"
    tag = "eval" if family == SplitFamily.EVALUATION else "train"
    return DataSample(
        sample_id=f"teach::{tag}::{idx}::{status}",
        text=text,
        source_id=f"ProtocolClass.from_status(status={status})",
        source_type="DETERMINISTIC_TEACHER",
        origin="raven.network_fundamentals.taxonomy:ProtocolClass.from_status",
        split_family=family,
        language="technical",
        created_at=_CREATED,
        transformations=("rule_label", "wrap_chat_roles"),
        dedup_status=DedupStatus.UNIQUE,
        quality="synthetic-high",
        synthetic=True,
        human_reviewed=False,
        group_key=f"teacher:{tag}:{label}",
    )


def teacher_samples() -> List[DataSample]:
    out = [_teacher_sample(obs, SplitFamily.INSTRUCTION, i)
           for i, obs in enumerate(_TEACHER_GRID)]
    out += [_teacher_sample(obs, SplitFamily.EVALUATION, i)
            for i, obs in enumerate(_TEACHER_EVAL_GRID)]
    return out


# ── honesty axioms (SECURITY_CURRICULUM) ──────────────────────────────────────

def honesty_axiom_samples() -> List[DataSample]:
    out: List[DataSample] = []
    for key, statement in HONESTY_AXIOMS.items():
        out.append(DataSample(
            sample_id=f"axiom::{key}",
            text=statement,
            source_id=key,
            source_type="AXIOM",
            origin="raven.native_ai.curriculum_impl:HONESTY_AXIOMS",
            split_family=SplitFamily.SECURITY_CURRICULUM,
            language="en",
            created_at=_CREATED,
            transformations=(),
            dedup_status=DedupStatus.UNIQUE,
            quality="reference",
            synthetic=False,
            human_reviewed=True,
            group_key=f"axiom:{key}",
        ))
    return out


# ── syntax warmup (PRETRAIN) ──────────────────────────────────────────────────

_HTTP_FIXTURES = [
    "GET /api/v1/users HTTP/1.1\r\nhost: example.test\r\nauthorization: Bearer <token>\r\n\r\n",
    "POST /login HTTP/1.1\r\nhost: example.test\r\ncontent-type: application/json\r\n\r\n"
    '{"username":"alice","password":"<redacted>"}',
    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\netag: \"abc123\"\r\n\r\n"
    '{"id":1,"status":"ok","items":[]}',
    "HTTP/1.1 403 Forbidden\r\ncontent-type: text/html\r\n\r\n<html><body>denied</body></html>",
    "HTTP/1.1 429 Too Many Requests\r\nretry-after: 30\r\n\r\n",
    "HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Bearer realm=\"api\"\r\nset-cookie: s=1; HttpOnly\r\n\r\n",
    "GET /search?q=test&page=2 HTTP/1.1\r\nhost: example.test\r\nuser-agent: raven/0.1\r\n\r\n",
]


def syntax_warmup_samples() -> List[DataSample]:
    out: List[DataSample] = []
    for i, fx in enumerate(_HTTP_FIXTURES):
        out.append(DataSample(
            sample_id=f"syntax::{i}",
            text=fx,
            source_id=f"http_fixture_{i}",
            source_type="SYNTHETIC_FIXTURE",
            origin="raven.native_ai.curriculum_impl:_HTTP_FIXTURES",
            split_family=SplitFamily.PRETRAIN,
            language="technical",
            created_at=_CREATED,
            transformations=("author_fixture",),
            dedup_status=DedupStatus.UNIQUE,
            quality="synthetic-high",
            synthetic=True,
            human_reviewed=True,
            group_key=f"syntax:fixture:{i % 3}",
        ))
    return out


# ── code + conversation families (coverage) ──────────────────────────────────

_CODE_SNIPPETS = [
    "def classify(status):\n    if 200 <= status < 300:\n        return \"NORMAL_SUCCESS\"\n    return \"OTHER\"",
    "for row in rows:\n    if row[\"status\"] == 403:\n        count += 1",
    "resp = session.get(url, headers={\"authorization\": token})\nassert resp.status_code != 500",
]

_CONVO_TURNS = [
    "<|system|>You are RAVEN. Be honest and never overclaim.<|user|>Is a 200 response a vulnerability?"
    "<|raven|>No. A 200 OK is normal protocol behavior, not a vulnerability by itself.<|endturn|>",
    "<|system|>You are RAVEN.<|user|>My scanner flagged a candidate. Is it confirmed?"
    "<|raven|>A candidate is not verified. It needs evidence against ground truth before it is confirmed.<|endturn|>",
]


def code_samples() -> List[DataSample]:
    out: List[DataSample] = []
    for i, snip in enumerate(_CODE_SNIPPETS):
        out.append(DataSample(
            sample_id=f"code::{i}", text=snip,
            source_id=f"code_snippet_{i}", source_type="SYNTHETIC_FIXTURE",
            origin="raven.native_ai.curriculum_impl:_CODE_SNIPPETS",
            split_family=SplitFamily.CODE, language="code", created_at=_CREATED,
            transformations=("author_fixture",), dedup_status=DedupStatus.UNIQUE,
            quality="synthetic-high", synthetic=True, human_reviewed=True,
            group_key=f"code:{i}",
        ))
    return out


def conversation_samples() -> List[DataSample]:
    out: List[DataSample] = []
    for i, turn in enumerate(_CONVO_TURNS):
        out.append(DataSample(
            sample_id=f"convo::{i}", text=turn,
            source_id=f"convo_{i}", source_type="SYNTHETIC_DIALOGUE",
            origin="raven.native_ai.curriculum_impl:_CONVO_TURNS",
            split_family=SplitFamily.CONVERSATION, language="en", created_at=_CREATED,
            transformations=("author_dialogue",), dedup_status=DedupStatus.UNIQUE,
            quality="synthetic-high", synthetic=True, human_reviewed=True,
            group_key=f"convo:{i}",
        ))
    return out


# ── assembly ──────────────────────────────────────────────────────────────

def build_curriculum_dataset() -> NativeDataset:
    """Assemble the full curriculum corpus into a DENY-guarded NativeDataset."""
    ds = NativeDataset()
    ds.extend(syntax_warmup_samples())
    ds.extend(knowledge_prose_samples())
    ds.extend(honesty_axiom_samples())
    ds.extend(teacher_samples())
    ds.extend(code_samples())
    ds.extend(conversation_samples())
    return ds


def curriculum_corpus_texts() -> List[str]:
    """Flat text corpus for tokenizer training (no private data by construction)."""
    return build_curriculum_dataset().texts()


# ── Curriculum contract (concrete, fulfils raven.native_ai.curriculum.Curriculum) ──

class NativeCurriculum(Curriculum):
    """Ordered curriculum stages mirroring ARCHITECTURE_DECISION.md §5."""

    _STAGES = (
        CurriculumStage(stage_id="s1_syntax", name="Syntax warmup", order=1,
                        objective="Learn HTTP/JSON/header byte structure.",
                        metadata={"family": SplitFamily.PRETRAIN.value}),
        CurriculumStage(stage_id="s2_knowledge", name="Knowledge prose", order=2,
                        objective="Learn EN technical fundamentals (18 parts).",
                        metadata={"family": SplitFamily.NETWORK_CURRICULUM.value}),
        CurriculumStage(stage_id="s3_axioms", name="Honesty axioms", order=3,
                        objective="Learn the binding honesty axioms.",
                        metadata={"family": SplitFamily.SECURITY_CURRICULUM.value}),
        CurriculumStage(stage_id="s4_teacher", name="Teacher instruction pairs", order=4,
                        objective="Produce observation -> CLASS labels.",
                        evaluation_suite_id="eval_label_exact_match",
                        metadata={"family": SplitFamily.INSTRUCTION.value}),
    )

    def __init__(self) -> None:
        self._stages = list(self._STAGES)

    def stages(self) -> List[CurriculumStage]:
        return sorted(self._stages, key=lambda s: s.order)

    def add_stage(self, stage: CurriculumStage) -> None:
        self._stages.append(stage)

    def next_stage(self, completed_stage_id: Optional[str] = None) -> CurriculumStage:
        ordered = self.stages()
        if completed_stage_id is None:
            return ordered[0]
        for i, s in enumerate(ordered):
            if s.stage_id == completed_stage_id:
                if i + 1 < len(ordered):
                    return ordered[i + 1]
                raise StopIteration("curriculum complete")
        raise KeyError(completed_stage_id)

    def evaluation_hook(self, stage_id: str) -> str:
        for s in self._stages:
            if s.stage_id == stage_id:
                return s.evaluation_suite_id or "eval_perplexity_holdout"
        raise KeyError(stage_id)
