"""The Claude agent loop, hosted inside RAVEN (Messages API + tool use).

Per turn: Claude answers (thinking always on, effort ``high``); every ``tool_use`` block is
executed by RAVEN — read-only tools directly, ``http_request`` / ``start_collection`` /
``run_command`` only after the operator approves that exact call (action-id bound, one
decision per action). All tool results of a turn go back in ONE user message. The full
assistant content (thinking + fallback blocks) is appended unchanged every turn
(append-only history — required by preserved thinking).

Stops on: final answer, operator cancel / Emergency Stop (checked between turns and while
waiting), per-run cost cap, max turns, a refusal of the whole fallback chain, or an API error.
The snapshot shape matches the RAVEN-Sec agent so the same UI timeline renders it.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import MODEL, MODEL_LABEL
from . import client as cl
from .prompts import agent_system
from .tools import APPROVAL_TOOLS, TOOL_DEFS, ToolBox, describe

APPROVAL_TIMEOUT = 1800
OBS_PREVIEW = 3000
DEFAULT_BUDGET_USD = 3.0
DEFAULT_MAX_TURNS = 40
TERMINAL = ("DONE", "FAILED", "CANCELLED", "REFUSED", "BUDGET")


class ClaudeAgentRun:
    def __init__(self, objective: str, root: Path, ctx: Dict[str, Callable], stopped: Callable[[], bool],
                 client_factory: Callable[[], Any], budget_usd: float = DEFAULT_BUDGET_USD,
                 max_turns: int = DEFAULT_MAX_TURNS):
        self.id = uuid.uuid4().hex[:12]
        self.objective = objective.strip()
        self.created = time.time()
        self.state = "RUNNING"
        self.steps: List[dict] = []
        self.pending: Optional[dict] = None
        self.answer: Optional[str] = None
        self.error: Optional[str] = None
        self.rundir = Path(root) / self.id
        self.workdir = self.rundir / "files"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.usage = cl.Usage()
        self.budget_usd = float(budget_usd)
        self.max_turns = int(max_turns)
        self._ctx, self._stopped, self._client_factory = ctx, stopped, client_factory
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._decision = threading.Event()
        self._approved, self._deny_reason = False, ""
        self.tools = ToolBox(ctx, self.workdir, self._halt)

    # ── public control (same contract as the RAVEN-Sec agent) ─────────────────
    def snapshot(self) -> dict:
        with self._lock:
            files = sorted(p.name for p in self.workdir.iterdir() if p.is_file() and not p.is_symlink())
            return {"id": self.id, "engine": "claude", "model": MODEL_LABEL, "objective": self.objective,
                    "state": self.state, "created": int(self.created * 1000), "steps": list(self.steps),
                    "pending": dict(self.pending) if self.pending else None, "answer": self.answer,
                    "error": self.error, "files": files,
                    "usage": {**self.usage.as_dict(), "budget_usd": self.budget_usd}}

    def decide(self, approve: bool, reason: str = "", action_id: Optional[str] = None) -> bool:
        with self._lock:
            if self.state != "WAITING_APPROVAL" or not self.pending:
                return False
            if not action_id or action_id != self.pending.get("id"):
                return False
            self._approved, self._deny_reason = bool(approve), str(reason or "")[:300]
            self.state = "RUNNING"
            self._decision.set()
            return True

    def cancel(self) -> None:
        self._cancel.set()
        with self._lock:
            self._decision.set()

    # ── internals ──────────────────────────────────────────────────────────────
    def _halt(self) -> Optional[str]:
        if self._cancel.is_set():
            return "cancelled by the operator"
        if self._stopped():
            return "Emergency Stop is engaged"
        return None

    def _step(self, **kw) -> None:
        kw.setdefault("t", int(time.time() * 1000))
        with self._lock:
            self.steps.append(kw)
        self._persist()

    def _persist(self) -> None:
        try:
            from ..sec_ai.agent import _write_nofollow
            _write_nofollow(self.rundir, "run.json", json.dumps(self.snapshot(), indent=1))
        except OSError:
            pass

    def _finish(self, state: str, answer: Optional[str] = None, error: Optional[str] = None) -> None:
        with self._lock:
            self.state, self.answer, self.error, self.pending = state, answer, error, None
        self._persist()

    def _await_approval(self, name: str, inp: dict, notes: List[str]) -> Optional[bool]:
        """True approved / False denied-or-timeout / None halted."""
        with self._lock:
            if self._halt():
                return None
            self._decision = decision = threading.Event()
            self.state = "WAITING_APPROVAL"
            self.pending = {"id": uuid.uuid4().hex[:10], "tool": name, "input": describe(name, inp),
                            "notes": notes, "since": int(time.time() * 1000)}
        self._persist()
        deadline = time.time() + APPROVAL_TIMEOUT
        decided = False
        while not decided and time.time() < deadline:
            decided = decision.wait(min(1.0, max(0.0, deadline - time.time())))
            if self._halt():
                break
        with self._lock:
            self.pending, self.state = None, "RUNNING"
        if self._halt():
            return None
        if not decided:
            self._step(type="decision", tool=name, approved=False, reason="approval timed out")
            self._deny_reason = "no decision within the time limit"
            return False
        self._step(type="decision", tool=name, approved=self._approved, reason=self._deny_reason)
        return self._approved

    def _execute(self, block) -> Optional[dict]:
        """One tool_use block → its tool_result block (None = halted while waiting)."""
        name, inp = block.name, dict(block.input or {})
        self._step(type="action", tool=name, input=describe(name, inp), auto=name not in APPROVAL_TOOLS)
        if name in APPROVAL_TOOLS:
            blocked, notes = self.tools.precheck(name, inp)
            if blocked:
                text, err = f"BLOCKED: {blocked}", True
            else:
                ok = self._await_approval(name, inp, notes)
                if ok is None:
                    return None
                if not ok:
                    text, err = ("DENIED by the operator" + (f": {self._deny_reason}" if self._deny_reason else ".")
                                 + " Do not retry this exact action."), False
                else:
                    text, err = self.tools.run(name, inp)
        else:
            text, err = self.tools.run(name, inp)
        self._step(type="observation", tool=name, text=text[:OBS_PREVIEW], is_error=err)
        return {"type": "tool_result", "tool_use_id": block.id, "content": text, "is_error": err}

    # ── loop ───────────────────────────────────────────────────────────────────
    def run(self) -> None:
        try:
            client = self._client_factory()
        except Exception as exc:
            return self._finish("FAILED", error=cl.friendly_error(exc) if not isinstance(exc, cl.ClaudeUnavailable) else str(exc))
        scope = json.dumps(self._ctx["scope_dict"](), ensure_ascii=False)
        messages: List[dict] = [{"role": "user", "content":
                                 f"Objective: {self.objective}\n\nCurrent RAVEN workspace scope: {scope}\n"
                                 f"Run budget: about ${self.budget_usd:.2f} of API usage and {self.max_turns} turns."}]
        system = [{"type": "text", "text": agent_system()}]
        last_text = ""
        warned = False
        for _turn in range(self.max_turns):
            why = self._halt()
            if why:
                return self._finish("CANCELLED", answer=last_text or None, error=why)
            if self.usage.cost_usd >= self.budget_usd:
                self._step(type="note", text=f"run budget of ${self.budget_usd:.2f} reached — stopped")
                return self._finish("BUDGET", answer=last_text or None,
                                    error=f"Run budget reached (${self.usage.cost_usd:.2f}).")
            try:
                resp = cl.create(client, system=system, messages=messages, tools=TOOL_DEFS,
                                 max_tokens=16000, effort="high")
            except Exception as exc:
                return self._finish("FAILED", answer=last_text or None, error=cl.friendly_error(exc))
            self.usage.add(getattr(resp, "usage", None))
            fb = cl.served_by(resp)
            if fb:
                self._step(type="note", text=f"safety fallback: this turn was answered by {fb}")
            refusal = cl.refusal_info(resp)
            if refusal:
                self._step(type="note", text=f"Claude declined this turn (category: {refusal['category']}). "
                                             f"{refusal['explanation'] or ''}".strip())
                return self._finish("REFUSED", answer=last_text or None,
                                    error=f"Declined by the model's safety system (category: {refusal['category']}).")
            messages.append({"role": "assistant", "content": resp.content})   # unchanged, append-only
            text = cl.text_of(resp)
            tool_uses = [b for b in resp.content if getattr(b, "type", None) == "tool_use"]
            if resp.stop_reason == "pause_turn":
                continue
            if not tool_uses:
                if resp.stop_reason == "max_tokens":
                    messages.append({"role": "user", "content": "Your reply was cut off by the length limit — continue, more concisely."})
                    last_text = text or last_text
                    continue
                self._step(type="answer", text=text, usage=self.usage.as_dict())
                return self._finish("DONE", answer=text)
            if text:
                last_text = text
                self._step(type="note", text=text[:4000], role="claude")
            results = []
            for block in tool_uses:
                res = self._execute(block)
                if res is None:
                    return self._finish("CANCELLED", answer=last_text or None, error=self._halt() or "cancelled")
                results.append(res)
            if not warned and self.usage.cost_usd >= 0.8 * self.budget_usd:
                warned = True
                results.append({"type": "text", "text": "Note from RAVEN: the run budget is almost used up — "
                                                        "wrap up now and give your final report."})
            messages.append({"role": "user", "content": results})
        self._step(type="note", text=f"stopped after {self.max_turns} turns")
        return self._finish("BUDGET", answer=last_text or None, error=f"Turn limit ({self.max_turns}) reached.")


class ClaudeAgentManager:
    MAX_ACTIVE = 3

    def __init__(self, root: Path, ctx: Dict[str, Callable], stopped: Callable[[], bool],
                 client_factory: Callable[[], Any], settings: Callable[[], Dict[str, Any]], keep: int = 30):
        self.root = Path(root)
        self._args = (ctx, stopped, client_factory)
        self._settings = settings
        self._runs: Dict[str, ClaudeAgentRun] = {}
        self._order: List[str] = []
        self._keep = keep
        self._lock = threading.Lock()

    def start(self, objective: str) -> ClaudeAgentRun:
        if not objective or not objective.strip():
            raise ValueError("objective is required")
        with self._lock:
            active = sum(1 for r in self._runs.values() if r.state not in TERMINAL)
            if active >= self.MAX_ACTIVE:
                raise ValueError(f"{active} Claude runs are already active — finish or cancel one first")
        s = self._settings() or {}
        run = ClaudeAgentRun(objective[:8000], self.root, *self._args,
                             budget_usd=float(s.get("budget_usd") or DEFAULT_BUDGET_USD),
                             max_turns=int(s.get("max_turns") or DEFAULT_MAX_TURNS))
        with self._lock:
            self._runs[run.id] = run
            self._order.append(run.id)
            for rid in list(self._order):
                if len(self._order) <= self._keep:
                    break
                old = self._runs.get(rid)
                if old is None or old.state in TERMINAL:
                    self._order.remove(rid)
                    self._runs.pop(rid, None)
        threading.Thread(target=run.run, name=f"claude-agent-{run.id}", daemon=True).start()
        return run

    def get(self, run_id: str) -> Optional[ClaudeAgentRun]:
        return self._runs.get(run_id)

    def list(self) -> List[dict]:
        return [{"id": r.id, "objective": r.objective[:120], "state": r.state, "engine": "claude",
                 "created": int(r.created * 1000), "cost_usd": r.usage.cost_usd}
                for r in (self._runs[i] for i in reversed(self._order) if i in self._runs)]

    def cancel_all(self) -> None:
        for r in list(self._runs.values()):
            r.cancel()
