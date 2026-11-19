"""Training set for RAVEN-Sec: cybersecurity knowledge, coding, and tool use.

Every example is built from the trusted corpus (no synthetic "facts"):
  * knowledge Q/A    — question templates per source → the matching section text + source URL
  * coding           — sections containing code blocks (secure-coding cheat sheets,
                       payload/exploit snippets) → "write/show code" requests
  * tool use         — agent trajectories in the RAVEN protocol (ACTION/INPUT → OBSERVATION
                       → ANSWER with sources) so a small model learns to look things up
  * identity         — who the model is and that it is a fine-tune (honest)

Hold-out: whole documents are held out (never trained on) for honest evaluation.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
from pathlib import Path
from typing import Iterable, List, Optional

from . import corpus, paths
from .prompts import AGENT_SYSTEM, CHAT_SYSTEM

MAX_ANSWER_CHARS = 1400
_CODE = re.compile(r"```")


def _trim(text: str, limit: int = MAX_ANSWER_CHARS) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    cut = text.rfind("\n\n", 0, limit)
    if cut < limit // 2:
        cut = text.rfind("\n", 0, limit)
    if cut < limit // 2:
        cut = limit
    out = text[:cut].rstrip()
    if out.count("```") % 2:      # never leave a code fence open
        out += "\n```"
    return out


def _held_out(doc_id: str, ratio: float) -> bool:
    h = int(hashlib.sha256(doc_id.encode()).hexdigest()[:8], 16)
    return (h % 1000) < ratio * 1000


def _sec(doc, *names):
    for want in names:
        for h, t in doc.sections:
            if h.lower().startswith(want.lower()) and t.strip():
                return t
    return ""


def _name(doc) -> str:
    return doc.title.split(":", 1)[1].strip() if ":" in doc.title else doc.title


def qa_pairs(doc) -> List[tuple]:
    """(question, answer_body) pairs for one document."""
    name, out = _name(doc), []
    if doc.source == "cwe":
        desc = _sec(doc, "Description")
        cons = _sec(doc, "Common consequences")
        if desc:
            out.append((f"What is {doc.title}?", desc + (f"\n\nImpact:\n{cons}" if cons else "")))
        det = _sec(doc, "Detection methods")
        if det:
            out.append((f"How can I detect {name} ({doc.doc_id}) during a security assessment?", det))
        mit = _sec(doc, "Potential mitigations")
        if mit:
            out.append((f"How do I prevent {name} ({doc.doc_id}) in my code?", mit))
        obs = _sec(doc, "Observed examples")
        if obs:
            out.append((f"Give real-world CVE examples of {doc.doc_id}.", obs))
    elif doc.source == "capec":
        desc, flow = _sec(doc, "Description"), _sec(doc, "Execution flow")
        if desc:
            out.append((f"Describe the attack pattern {doc.title}.", desc))
        if flow:
            out.append((f"How is a '{name}' attack carried out step by step during a pentest?", flow))
        pre = _sec(doc, "Prerequisites")
        if pre:
            out.append((f"What are the prerequisites for {name}?", pre))
        mit = _sec(doc, "Mitigations")
        if mit:
            out.append((f"How do I defend against {name} ({doc.doc_id})?", mit))
    elif doc.source == "attack":
        desc, det = _sec(doc, "Description"), _sec(doc, "Detection")
        if desc:
            out.append((f"What is MITRE ATT&CK technique {doc.title}?", desc))
        if det:
            out.append((f"How can defenders detect {name} ({doc.doc_id})?", det))
    else:  # markdown sources
        for heading, text in doc.sections:
            if len(text) < 80 or heading.lower() in ("references", "summary", "table of contents", "labs"):
                continue
            h = heading or doc.title
            has_code = bool(_CODE.search(text))
            if doc.source == "wstg":
                hl = h.lower()
                if hl.startswith("how to test"):
                    q = f"How do I test for {doc.title}?"
                elif hl.startswith("test objectives"):
                    q = f"What should I check when testing {doc.title}?"
                elif hl.startswith("remediation"):
                    q = f"How is {doc.title.replace('Testing for ', '')} remediated?"
                elif hl.startswith("tools"):
                    q = f"Which tools help with {doc.title}?"
                else:
                    q = f"{doc.title}: explain '{h}'."
            elif doc.source == "patt":
                cat = doc.doc_id.split(":", 1)[1].split("/")[0]
                q = (f"Give me {h} payloads for {cat}." if has_code
                     else f"In {cat} testing, explain {h}.")
            else:  # cheatsheets
                q = (f"Show a secure code example for {h} ({doc.title})." if has_code
                     else f"{doc.title}: what is the guidance on {h}?")
            out.append((q, text))
    return out


def _answer(body: str, url: str) -> str:
    return f"{_trim(body)}\n\nSource: {url}"


def _observation(results: List[dict], per_hit: int = 500) -> str:
    lines = []
    for i, r in enumerate(results, 1):
        lines.append(f"[{i}] {r['title']} — {r['heading']}\n{r['url']}\n{_trim(r['text'], per_hit)}")
    return "OBSERVATION (search):\n" + "\n\n".join(lines)


class _Fitter:
    """Makes every example fit the training window (``max_len`` tokens) WITHOUT losing
    its final assistant turn. train_lora truncates on the right, so an agent example
    whose observations were too long silently lost its cited ANSWER (23 % of them did)."""

    def __init__(self, max_len: int):
        from transformers import AutoTokenizer
        self.max_len = int(max_len)
        self.tok = AutoTokenizer.from_pretrained(paths.base_model_dir())
        self.stats = {"fit_max_len": self.max_len, "obs_shortened": 0, "answers_shortened": 0,
                      "agent_fell_back_to_chat": 0, "dropped": 0}

    def n(self, messages) -> int:
        # Exactly what train_lora._encode feeds the model (template text → token ids).
        # NB: apply_chat_template(tokenize=True) returns a dict, whose len() is 2.
        text = self.tok.apply_chat_template(messages, tokenize=False)
        return len(self.tok(text, add_special_tokens=False)["input_ids"])

    def fits(self, messages) -> bool:
        return self.n(messages) <= self.max_len

    def chat(self, q: str, body: str, url: str) -> Optional[List[dict]]:
        for limit in (MAX_ANSWER_CHARS, 1000, 700, 450):
            msgs = [{"role": "system", "content": CHAT_SYSTEM}, {"role": "user", "content": q},
                    {"role": "assistant", "content": f"{_trim(body, limit)}\n\nSource: {url}"}]
            if self.fits(msgs):
                if limit != MAX_ANSWER_CHARS:
                    self.stats["answers_shortened"] += 1
                return msgs
        self.stats["dropped"] += 1
        return None

    def agent(self, q: str, hits: List[dict], body: str, url: str) -> Optional[List[dict]]:
        for per_hit, limit in ((500, MAX_ANSWER_CHARS), (300, MAX_ANSWER_CHARS), (200, 900),
                               (140, 700), (100, 500)):
            msgs = [{"role": "system", "content": AGENT_SYSTEM},
                    {"role": "user", "content": q},
                    {"role": "assistant", "content": f"ACTION: search\nINPUT: {q}"},
                    {"role": "user", "content": _observation(hits, per_hit)},
                    {"role": "assistant", "content": f"ANSWER: {_trim(body, limit)}\n\nSource: {url}"}]
            if self.fits(msgs):
                if per_hit != 500:
                    self.stats["obs_shortened"] += 1
                return msgs
        self.stats["agent_fell_back_to_chat"] += 1
        return None


IDENTITY = [
    ("Who are you?",),
    ("What model are you?",),
    ("Are you trained from scratch?",),
    ("What can you help me with?",),
]
IDENTITY_ANSWER = (
    "I'm RAVEN-Sec, the cybersecurity and coding assistant built into RAVEN. I'm a fine-tune "
    "of the open Qwen2.5-Coder-0.5B-Instruct model (about 494 million parameters), trained on "
    "MITRE CWE/CAPEC/ATT&CK, the OWASP testing guide and cheat sheets, and PayloadsAllTheThings. "
    "I help with web/API penetration testing, payloads, exploitation steps for authorized "
    "testing, secure code review and writing tools. In agent mode I can search trusted sources, "
    "read documentation, and — with your approval — send in-scope requests or run commands in a "
    "sandbox. My answers are advisory: verify findings by hand.")


def build(raw: Optional[Path] = None, out_dir: Optional[Path] = None, *, holdout_ratio: float = 0.05,
          agent_ratio: float = 0.25, max_examples: Optional[int] = None, seed: int = 7,
          fit_len: Optional[int] = 512, tool_examples: int = 400) -> dict:
    """``fit_len``: token window the examples must fit (train_lora --max-len); None
    disables fitting (no tokenizer needed)."""
    from .kb import KnowledgeBase
    fitter = _Fitter(fit_len) if fit_len else None
    raw = Path(raw or paths.corpus_raw_dir())
    out_dir = Path(out_dir or paths.dataset_dir())
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    kb = KnowledgeBase()
    train, hold = [], []
    for doc in corpus.iter_all(raw):
        bucket = hold if _held_out(doc.doc_id, holdout_ratio) else train
        for q, body in qa_pairs(doc):
            if len(body.strip()) < 60:
                continue
            ex = {"doc_id": doc.doc_id, "source": doc.source, "question": q,
                  "answer": _answer(body, doc.url), "url": doc.url}
            msgs = None
            if bucket is train and kb.available and rng.random() < agent_ratio:
                hits = [r for r in kb.search(q, 3) if not _held_out(r["doc_id"], holdout_ratio)]
                own = {"title": doc.title, "heading": "", "url": doc.url, "text": body}
                hits = [own] + [h for h in hits if h["doc_id"] != doc.doc_id][:2]
                rng.shuffle(hits)
                if fitter is not None:
                    msgs = fitter.agent(q, hits, body, doc.url)
                else:
                    msgs = [
                        {"role": "system", "content": AGENT_SYSTEM},
                        {"role": "user", "content": q},
                        {"role": "assistant", "content": f"ACTION: search\nINPUT: {q}"},
                        {"role": "user", "content": _observation(hits)},
                        {"role": "assistant", "content": "ANSWER: " + ex["answer"]},
                    ]
            if msgs is None:
                if fitter is not None:
                    msgs = fitter.chat(q, body, doc.url)
                    if msgs is None:
                        continue
                else:
                    msgs = [
                        {"role": "system", "content": CHAT_SYSTEM},
                        {"role": "user", "content": q},
                        {"role": "assistant", "content": ex["answer"]},
                    ]
            ex["answer"] = msgs[-1]["content"].removeprefix("ANSWER: ")
            ex["messages"] = msgs
            bucket.append(ex)
    if tool_examples:
        # http/shell trajectories (search → approved tool → real-shaped result → reading of
        # the evidence) — the first fine-tune had none, so its agent never tested anything.
        from . import tool_trajectories
        train.extend(tool_trajectories.build(tool_examples, kb=kb,
                                             fits=fitter.fits if fitter is not None else None))
    for (q,) in IDENTITY:
        for _ in range(6):
            train.append({"doc_id": "identity", "source": "identity", "question": q, "url": "",
                          "answer": IDENTITY_ANSWER,
                          "messages": [{"role": "system", "content": CHAT_SYSTEM},
                                       {"role": "user", "content": q},
                                       {"role": "assistant", "content": IDENTITY_ANSWER}]})
    rng.shuffle(train)
    if max_examples:
        train = balanced_subset(train, max_examples, seed)
    _write(out_dir / "train.jsonl", train)
    _write(out_dir / "holdout.jsonl", hold)
    stats = dataset_stats(train)
    stats["holdout"] = len(hold)
    if fitter is not None:
        stats.update(fitter.stats)
    (out_dir / "stats.json").write_text(json.dumps(stats, indent=2))
    return stats


def balanced_subset(rows: List[dict], n: int, seed: int = 7) -> List[dict]:
    """Cap to ``n`` examples keeping the source mix balanced (each source a fair share)."""
    rng = random.Random(seed)
    by_src: dict = {}
    for ex in rows:
        by_src.setdefault(ex["source"], []).append(ex)
    capped: List[dict] = []
    while len(capped) < n and any(by_src.values()):
        for src in list(by_src):
            if by_src[src] and len(capped) < n:
                capped.append(by_src[src].pop())
    rng.shuffle(capped)
    return capped


def dataset_stats(rows: List[dict]) -> dict:
    stats = {"train": len(rows),
             "agent_examples": sum(1 for e in rows if e["messages"][0]["content"] == AGENT_SYSTEM),
             "by_source": {}}
    for e in rows:
        stats["by_source"][e["source"]] = stats["by_source"].get(e["source"], 0) + 1
    return stats


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Build the RAVEN-Sec training set")
    ap.add_argument("--fit-len", type=int, default=512, help="token window (= train_lora --max-len)")
    ap.add_argument("--subset", type=int, default=0,
                    help="also write a balanced N-example subset as train_<N>.jsonl")
    args = ap.parse_args(argv)
    stats = build(fit_len=args.fit_len or None)
    print(json.dumps(stats, indent=1))
    if args.subset:
        rows = [json.loads(l) for l in open(paths.dataset_dir() / "train.jsonl", encoding="utf-8")]
        sub = balanced_subset(rows, args.subset)
        name = f"train_{args.subset // 1000}k.jsonl" if args.subset % 1000 == 0 else f"train_{args.subset}.jsonl"
        _write(paths.dataset_dir() / name, sub)
        print(name, json.dumps(dataset_stats(sub)))
    return 0



def _write(path: Path, rows: Iterable[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
