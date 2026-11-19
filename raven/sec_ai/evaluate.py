"""Honest evaluation: base model vs fine-tuned RAVEN-Sec.

    python -m raven.sec_ai.evaluate [--n 60]

1. Held-out loss — answer-token cross-entropy on examples from documents that were
   NEVER trained on (dataset/holdout.jsonl). Lower is better; reported for both models.
2. Tool-protocol compliance — share of agent prompts where the model replies with a
   well-formed "ACTION: <tool>\\nINPUT: …" (what the agent needs).
3. Sample answers to fixed pentest / coding questions, side by side.
Writes <ai>/raven-sec-0.5b/EVALUATION.json and EVALUATION.md.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import time

from . import paths
from .agent import degenerate_action, parse_reply
from .prompts import AGENT_SYSTEM, CHAT_SYSTEM
from .train_lora import _encode

PROBES = [
    "During an authorized test, how do I check a login form for SQL injection? Give payloads.",
    "Give me payloads to confirm server-side template injection in Jinja2.",
    "How do I test an API endpoint for IDOR / broken object level authorization?",
    "Write a Python function that checks a URL for missing security headers (CSP, HSTS, X-Frame-Options).",
    "What is CWE-918 and how do I test for it?",
    "Explain CVE-2021-44228 and how to detect it safely.",
]


def _load(model_dir):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model_dir)
    m = AutoModelForCausalLM.from_pretrained(model_dir, dtype=torch.float32)
    m.eval()
    return tok, m


def holdout_loss(tok, model, rows, max_len=512):
    import torch
    total, count = 0.0, 0
    with torch.no_grad():
        for r in rows:
            ids, labels = _encode(tok, r["messages"], max_len)
            if not any(l != -100 for l in labels):
                continue
            out = model(input_ids=torch.tensor([ids]), labels=torch.tensor([labels]))
            n = sum(1 for l in labels[1:] if l != -100)
            total += float(out.loss) * n
            count += n
    return total / max(1, count)


def _gen(tok, model, msgs, max_new=220):
    import torch
    enc = tok.apply_chat_template(msgs, add_generation_prompt=True, return_tensors="pt", return_dict=True)
    with torch.no_grad():
        out = model.generate(enc["input_ids"], attention_mask=enc["attention_mask"], max_new_tokens=max_new,
                             do_sample=False, repetition_penalty=1.08, pad_token_id=tok.eos_token_id)
    return tok.decode(out[0, enc["input_ids"].shape[1]:], skip_special_tokens=True).strip()


def protocol_rate(tok, model, questions):
    ok = 0
    for q in questions:
        reply = _gen(tok, model, [{"role": "system", "content": AGENT_SYSTEM},
                                  {"role": "user", "content": q}], 60)
        p = parse_reply(reply)
        if p["kind"] == "action" and not degenerate_action(p["tool"], p["input"]):
            ok += 1
    return ok / max(1, len(questions))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--protocol", type=int, default=15)
    args = ap.parse_args(argv)
    import torch
    torch.set_num_threads(max(1, (__import__("os").cpu_count() or 4) - 2))
    hold = [json.loads(l) for l in open(paths.dataset_dir() / "holdout.jsonl", encoding="utf-8")]
    random.Random(3).shuffle(hold)
    rows = hold[:args.n]
    questions = [r["question"] for r in hold[args.n:args.n + args.protocol]]
    report = {"holdout_examples": len(rows), "protocol_prompts": len(questions), "models": {}}
    for label, d in (("base", paths.base_model_dir()), ("raven_sec", paths.tuned_model_dir())):
        if not (d / "config.json").is_file():
            continue
        t = time.time()
        tok, model = _load(d)
        loss = holdout_loss(tok, model, rows)
        rate = protocol_rate(tok, model, questions)
        answers = {q: _gen(tok, model, [{"role": "system", "content": CHAT_SYSTEM},
                                        {"role": "user", "content": q}]) for q in PROBES}
        report["models"][label] = {"model_dir": str(d), "holdout_loss": round(loss, 4),
                                   "holdout_perplexity": round(math.exp(loss), 2),
                                   "protocol_compliance": round(rate, 3), "samples": answers,
                                   "eval_minutes": round((time.time() - t) / 60, 1)}
        print(label, "loss", round(loss, 4), "ppl", round(math.exp(loss), 2), "protocol", rate, flush=True)
        del model
    out = paths.tuned_model_dir()
    if out.is_dir():
        (out / "EVALUATION.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
        lines = ["# RAVEN-Sec evaluation", "",
                 f"Held-out examples (documents never trained on): {len(rows)} · "
                 f"protocol prompts: {len(questions)}", "",
                 "| model | held-out loss | perplexity | tool-protocol compliance |", "|---|---|---|---|"]
        for k, v in report["models"].items():
            lines.append(f"| {k} | {v['holdout_loss']} | {v['holdout_perplexity']} | {v['protocol_compliance']:.0%} |")
        for q in PROBES:
            lines += ["", f"## {q}"]
            for k, v in report["models"].items():
                lines += ["", f"**{k}:**", "", v["samples"][q]]
        (out / "EVALUATION.md").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
