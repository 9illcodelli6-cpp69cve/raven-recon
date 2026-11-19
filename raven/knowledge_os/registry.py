"""Register knowledge OS tools with the shared ToolRegistry.

Wave 9 (A9-EVKNOW): the handlers are no longer a silent ``_noop``
(``{"status":"not_dispatched"}``). Each descriptor is bound to a REAL handler in
``raven.api.evidence_knowledge_handlers`` — the same functions the interim HTTP
routes call (one implementation, two entry points). ``deps`` carries the live
subsystems (KnowledgeBase / LearningEngine / TechniqueLibrary) + actor/workspace;
when it is absent the tool reports ``unavailable`` (EXPLICITLY unavailable —
never a silent ``not_dispatched``). The ``register_knowledge_tools(registry)``
one-argument signature is preserved for existing callers/tests.
"""
from raven.runtime.tools import ToolDescriptor, ToolRegistry, SideEffectClass


def register_knowledge_tools(registry: ToolRegistry, deps=None) -> int:
    tools = [
        ToolDescriptor(
            tool_id="knowledge.search",
            name="Knowledge Search",
            description="Search the RAVEN knowledge base.",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.LOCAL_READ,
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "kind":  {"type": "string"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="knowledge.store",
            name="Store Knowledge",
            description="Add a knowledge entry to the knowledge base.",
            required_capability="FileWriteWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["title", "body"],
                "properties": {
                    "title":      {"type": "string"},
                    "body":       {"type": "string"},
                    "kind":       {"type": "string"},
                    "confidence": {"type": "number"},
                    "tags":       {"type": "array", "items": {"type": "string"}},
                },
            },
        ),
        ToolDescriptor(
            tool_id="knowledge.technique.search",
            name="Technique Search",
            description="Search the built-in security technique library.",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.PURE,
            input_schema={
                "type": "object",
                "properties": {
                    "query":    {"type": "string"},
                    "category": {"type": "string"},
                },
            },
        ),
        ToolDescriptor(
            tool_id="knowledge.lesson.synthesize",
            name="Synthesize Lesson",
            description="Derive a lesson from a set of research findings (advisory).",
            required_capability="FileReadWorkspace",
            side_effect_class=SideEffectClass.LOCAL_WRITE,
            input_schema={
                "type": "object",
                "required": ["finding_ids"],
                "properties": {
                    "finding_ids": {"type": "array", "items": {"type": "string"}},
                },
            },
        ),
    ]

    from raven.api.evidence_knowledge_handlers import (
        handle_knowledge_store,
        handle_knowledge_search,
        handle_technique_search,
        handle_lesson_synthesize,
    )

    def _unavailable(reason: str):
        def _h(args: dict) -> dict:
            return {"status": "unavailable", "reason": reason}
        return _h

    def _bound(fn):
        def _h(args: dict) -> dict:
            return fn(args)
        return _h

    if deps is None:
        handlers = {t.tool_id: _unavailable(
            "knowledge tools not bound to a live KnowledgeBase (no deps)")
            for t in tools}
    else:
        handlers = {
            "knowledge.search": _bound(lambda a: handle_knowledge_search(
                a, workspace_id=deps.workspace_id, kb=deps.kb, gate=deps.gate)),
            "knowledge.store": _bound(lambda a: handle_knowledge_store(
                a, actor=deps.actor, workspace_id=deps.workspace_id,
                kb=deps.kb, gate=deps.gate)),
            "knowledge.technique.search": _bound(lambda a: handle_technique_search(
                a, techniques=deps.techniques, gate=deps.gate)),
            "knowledge.lesson.synthesize": _bound(lambda a: handle_lesson_synthesize(
                a, actor=deps.actor, workspace_id=deps.workspace_id,
                learning=deps.learning, store=deps.store, gate=deps.gate)),
        }

    for t in tools:
        registry.register(t, handlers[t.tool_id])
    return len(tools)
