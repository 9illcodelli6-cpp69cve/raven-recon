"""Register program agent tools with the shared ToolRegistry.

Wave 11 (A11-PROGRAM): the handlers are no longer a silent ``_noop`` returning
``{"status":"not_dispatched"}``. Each descriptor binds to a REAL handler on a live
program-agent backend (``ProgramPolicy`` / ``ProgramStore`` / ``SubmissionStore``),
or is registered with an EXPLICIT ``unavailable`` handler (never a silent pass):

* ``program.policy.check``     -> ``ProgramPolicy.is_target_allowed`` for the active
  program. With no loaded policy it returns an explicit, FAIL-CLOSED
  ``in_scope=False`` (never a default-permissive allow).
* ``program.program.list``     -> ``ProgramStore.list_active(workspace_id)``.
* ``program.submission.create`` -> ``SubmissionStore.save`` with
  ``human_reviewed=False`` + ``status=DRAFT`` (the program agent may only create
  DRAFT submissions; a researcher gates READY/SUBMITTED — never an automated submit).
* ``program.submission.list``  -> ``SubmissionStore.list_for_program(program_id)``.

``register_program_tools(registry)`` (one-argument) is preserved for existing callers
and tests; passing ``deps`` binds the real backends. Without ``deps`` — or for a tool
whose backend is absent — the handler is an explicit ``unavailable`` handler, still
never ``not_dispatched``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from raven.runtime.tools import ToolDescriptor, ToolRegistry, SideEffectClass


@dataclass
class ProgramToolDeps:
    """Live backends the real program-agent handlers close over."""
    policy: object = None            # a ProgramPolicy (the active program's policy) or None
    program_store: object = None     # program.ProgramStore or None
    submission_store: object = None  # submission.SubmissionStore or None
    # The workspace id, or a zero-argument callable returning the ACTIVE workspace id
    # (preferred: a fixed id goes stale after a workspace switch).
    workspace_id: Optional[object] = None
    actor: object = None             # ActorKind (provenance; informational here)

    def current_workspace_id(self) -> Optional[str]:
        ws = self.workspace_id
        if callable(ws):
            try:
                ws = ws()
            except Exception:
                return None
        return str(ws) if ws else None


def _descriptors():
    return [
        ToolDescriptor(
            tool_id="program.policy.check",
            name="Scope Check",
            description="Check if a target URL is in scope for the active program.",
            required_capability="ScopeRead",
            side_effect_class=SideEffectClass.PURE,
            input_schema={
                "type": "object", "required": ["target"],
                "properties": {"target": {"type": "string"}},
            },
            metadata={"risk_class": "SafeReadOnly"},
        ),
        ToolDescriptor(
            tool_id="program.program.list",
            name="List Programs",
            description="List active bug bounty programs.",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.LOCAL_READ,
            input_schema={"type": "object"},
            metadata={"risk_class": "SafeReadOnly"},
        ),
        ToolDescriptor(
            tool_id="program.submission.create",
            name="Create Submission",
            description="Create a draft submission from a finding (requires human review).",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["finding_id", "program_id"],
                "properties": {
                    "finding_id":  {"type": "string"},
                    "program_id":  {"type": "string"},
                    "title":       {"type": "string"},
                    "severity":    {"type": "string"},
                },
            },
            metadata={"risk_class": "LowRiskStateChange"},
        ),
        ToolDescriptor(
            tool_id="program.submission.list",
            name="List Submissions",
            description="List submissions for a program.",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.LOCAL_READ,
            input_schema={
                "type": "object",
                "properties": {"program_id": {"type": "string"}},
            },
            metadata={"risk_class": "SafeReadOnly"},
        ),
    ]


def _unavailable(reason: str):
    def _h(args: dict) -> dict:
        return {"status": "unavailable", "reason": reason}
    return _h


def _resolve_policy(deps: ProgramToolDeps):
    """Resolve the active ProgramPolicy from deps (direct policy preferred, else the
    first active program with a loaded policy in this workspace). None if absent."""
    if deps.policy is not None:
        return deps.policy
    store = deps.program_store
    if store is None:
        return None
    ws = deps.current_workspace_id()
    if not ws:
        # list_active(None) spans EVERY workspace; never borrow another
        # workspace's policy as scope authority — fail closed instead.
        return None
    try:
        for prog in store.list_active(ws):
            if getattr(prog, "workspace_id", ws) != ws:
                continue
            if getattr(prog, "policy", None) is not None:
                return prog.policy
    except Exception:
        return None
    return None


def _policy_check_handler(deps: ProgramToolDeps):
    def _h(args: dict) -> dict:
        target = str(args.get("target", "") or "")
        policy = _resolve_policy(deps)
        if policy is None:
            # FAIL-CLOSED: no loaded program policy ⇒ nothing is in scope.
            return {"status": "no_program_policy", "target": target,
                    "in_scope": False, "allowed": False, "external_targets": 0}
        allowed = bool(policy.is_target_allowed(target))
        return {"status": "ok", "target": target, "in_scope": allowed,
                "allowed": allowed, "program_id": getattr(policy, "program_id", ""),
                "external_targets": 0}
    return _h


def _program_list_handler(deps: ProgramToolDeps):
    store = deps.program_store
    if store is None:
        return _unavailable("program.program.list not bound to a ProgramStore")

    def _h(args: dict) -> dict:
        try:
            progs = store.list_active(deps.current_workspace_id())
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc), "programs": []}
        return {"status": "ok",
                "programs": [p.to_dict() for p in progs],
                "count": len(progs)}
    return _h


def _submission_create_handler(deps: ProgramToolDeps):
    store = deps.submission_store
    if store is None:
        return _unavailable("program.submission.create not bound to a SubmissionStore")

    def _h(args: dict) -> dict:
        from .submission import Submission, SubmissionStatus
        sub = Submission(
            program_id=str(args.get("program_id", "") or ""),
            workspace_id=deps.current_workspace_id() or "default",
            finding_id=str(args.get("finding_id", "") or ""),
            title=str(args.get("title", "") or ""),
            severity=str(args.get("severity", "") or "UNKNOWN"),
            status=SubmissionStatus.DRAFT,   # agent may only DRAFT
            human_reviewed=False,            # a researcher must review before submit
        )
        sub_id = store.save(sub)
        return {"status": "created", "submission_id": sub_id,
                "human_reviewed": False, "submission_status": SubmissionStatus.DRAFT.value}
    return _h


def _submission_list_handler(deps: ProgramToolDeps):
    store = deps.submission_store
    if store is None:
        return _unavailable("program.submission.list not bound to a SubmissionStore")

    def _h(args: dict) -> dict:
        program_id = str(args.get("program_id", "") or "")
        try:
            subs = store.list_for_program(program_id)
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc), "submissions": []}
        return {"status": "ok",
                "submissions": [s.to_dict() for s in subs],
                "count": len(subs)}
    return _h


def register_program_tools(registry: ToolRegistry,
                           deps: Optional[ProgramToolDeps] = None) -> int:
    """Register program-agent tools into ``registry``. Returns the count.

    ``deps`` (optional) binds the real backends. Without it every handler is an
    explicit ``unavailable`` handler — never the dead ``not_dispatched``.
    """
    tools = _descriptors()

    if deps is None:
        handlers = {t.tool_id: _unavailable(
            f"{t.tool_id} not bound to a program backend (no deps)") for t in tools}
    else:
        handlers = {
            "program.policy.check":     _policy_check_handler(deps),
            "program.program.list":     _program_list_handler(deps),
            "program.submission.create": _submission_create_handler(deps),
            "program.submission.list":  _submission_list_handler(deps),
        }

    for t in tools:
        registry.register(t, handlers[t.tool_id])
    return len(tools)
