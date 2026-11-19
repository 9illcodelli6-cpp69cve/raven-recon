# RAVEN V7 Runtime Architecture
**Authority: RAVEN_CONSTITUTION.md**
**Status: Approved for V7-BOOTSTRAP implementation**
**Date: 2026-10-04**

---

## 1. Purpose

This document defines the shared runtime that all V7 subsystems (Chat, Browser, Terminal, Agents, Scripts, Research, Learning) must build on. It replaces the implicit assumption that every subsystem will independently manage tasks, memory, tool calls, cancellation, and model access.

The spec principle (§16) is: **ONE SHARED RUNTIME**.

---

## 2. Existing Reusable Components

The following existing modules provide strong foundations and must NOT be rewritten as part of V7-BOOTSTRAP:

| Module | Role | Reuse in V7 |
|--------|------|-------------|
| `raven/scope.py` | Target scope enforcement | Policy layer — unchanged |
| `raven/store.py` | SQLite persistence (assets, URLs, evidence) | Extend with V7 tables |
| `raven/security/process_guard.py` | Subprocess sandboxing | ExecutionRuntime → reuses this |
| `raven/security/audit_log.py` | Structured audit trail | EventBus → writes to audit log |
| `raven/rust_bridge.py` | Fail-closed Rust policy gate | CapabilityGate → calls this |
| `raven/api/scheduler.py` | Async rate-limited job queue | TaskQueue → wraps this |
| `raven/evidence_graph.py` | Typed evidence node/edge graph | EvidenceService → wraps this |
| `raven/poc/candidate.py` | PoCCandidate with human_verification_required | CandidateService → wraps this |
| `raven/poc/autonomy.py` | AutonomyLevel + approval gates | AgentRuntime → uses this |
| `raven/planner/planner.py` | ActionProposal — propose-only | AgentPlanner → wraps this |
| `raven/ml/inference.py` | Advisory-only InferenceResult | ModelService → wraps this |
| `raven/research_gateway/gateway.py` | Provenance-tracked research fetcher | ResearchService → wraps this |
| `raven/learning/curriculum.py` | SelfStudyLoop | LearningService → wraps this |
| `raven/review_workflow.py` | Confirmed/automated transition gates | WorkflowService → wraps this |

---

## 3. New Runtime Abstractions

### 3.1 EventBus
Single in-process publish/subscribe bus.

```python
class EventBus:
    def publish(self, event_type: str, payload: dict) -> None: ...
    def subscribe(self, event_type: str, handler: Callable) -> str: ...  # returns sub_id
    def unsubscribe(self, sub_id: str) -> None: ...
```

- Synchronous in Phase 1; async in Phase 2
- Every runtime service publishes events here
- UI subscribes to observe state changes
- Audit log subscribes to record all events

### 3.2 TaskRegistry
Tracks all long-running tasks. Tasks are the unit of cancellation and checkpointing.

```python
@dataclass
class Task:
    task_id: str           # uuid4
    title: str
    status: TaskStatus     # QUEUED/RUNNING/PAUSED/COMPLETED/FAILED/CANCELLED
    goal: str              # researcher-visible description
    created_at: int        # epoch ms
    workspace_id: str
    budget: TaskBudget     # max_steps, max_time_ms, max_cost
    checkpoint: Optional[dict]  # resumable state blob
    logs: list[str]
    result: Optional[dict]

class TaskRegistry:
    def create(self, title: str, goal: str, workspace_id: str, budget: TaskBudget) -> Task: ...
    def get(self, task_id: str) -> Optional[Task]: ...
    def update_status(self, task_id: str, status: TaskStatus) -> None: ...
    def checkpoint(self, task_id: str, state: dict) -> None: ...
    def cancel(self, task_id: str) -> None: ...
    def list_active(self, workspace_id: str) -> list[Task]: ...
```

All tasks are persisted to `store.py` (new `tasks` table).

### 3.3 ToolRegistry
Registers available tools and routes invocation requests.

```python
@dataclass
class ToolDescriptor:
    tool_id: str
    name: str
    description: str
    required_capability: str   # maps to CapabilityGate
    input_schema: dict         # JSON Schema
    output_schema: dict
    execution_profile: str     # PURE_LOCAL / LOCAL_FIXTURE / PUBLIC_RESEARCH / etc.

class ToolRegistry:
    def register(self, descriptor: ToolDescriptor, handler: Callable) -> None: ...
    def list_for_profile(self, profile: str) -> list[ToolDescriptor]: ...
    def invoke(self, tool_id: str, inputs: dict, task_id: str) -> ToolResult: ...
```

Tool invocation always goes through CapabilityGate before execution.

### 3.4 CapabilityGate
Wraps the existing Rust bridge. Every capability request goes through here.

```python
class CapabilityGate:
    def check(self, capability: str, context: dict) -> Literal["ALLOW", "DENY"]: ...
    def require(self, capability: str, context: dict) -> None: ...  # raises on DENY
```

Fail-closed: if the Rust bridge is unavailable, defaults to DENY.

### 3.5 ModelService
Wraps the existing `ml/inference.py`. Adds model selection and context management.

```python
class ModelService:
    def complete(self, messages: list[Message], model_id: str = "default") -> CompletionResult: ...
    def stream(self, messages: list[Message], model_id: str = "default") -> Iterator[str]: ...
```

- `CompletionResult.is_advisory = True` always
- Supports Ollama, llama.cpp, and OpenAI-compatible local endpoints
- Model selection is workspace-configurable
- Falls back gracefully when model is unavailable

### 3.6 WorkspaceContext
Each workspace is an isolated research environment.

```python
@dataclass
class WorkspaceContext:
    workspace_id: str
    name: str
    scope: ScopeConfig         # from existing scope.py
    program_policy: Optional[ProgramPolicy]
    model_config: ModelConfig
    created_at: int
    memory: WorkspaceMemory    # persisted per-workspace state
```

### 3.7 ConversationContext
Tracks multi-turn conversation state within a workspace.

```python
@dataclass
class Message:
    role: Literal["user", "assistant", "tool"]
    content: str
    timestamp: int
    language_hint: Optional[str]   # "ar", "en", "mixed"

class ConversationContext:
    workspace_id: str
    messages: list[Message]
    max_turns: int = 100
    
    def add(self, role: str, content: str) -> None: ...
    def get_for_model(self, max_tokens: int) -> list[Message]: ...
    def clear(self) -> None: ...
```

Persisted per-workspace to SQLite.

---

## 4. Ownership Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                         UI LAYER                            │
│  (Tauri/Textual/HTML)  observes EventBus, sends commands   │
└───────────────────────────────┬─────────────────────────────┘
                                │ commands
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                      RUNTIME LAYER                          │
│  TaskRegistry  ToolRegistry  ModelService  WorkspaceContext │
│  ConversationContext  EventBus  CapabilityGate              │
└───────────────────────────────┬─────────────────────────────┘
                                │ service calls
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                     RESEARCH SERVICES                       │
│  ResearchService  LearningService  EvidenceService          │
│  CandidateService  WorkflowService  ScriptService           │
└───────────────────────────────┬─────────────────────────────┘
                                │ policy checks
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                    POLICY / CAPABILITY                      │
│  CapabilityGate → rust_bridge.py → raven-policy (Rust)     │
│  scope.py (scope enforcement)                               │
└─────────────────────────────────────────────────────────────┘
```

**UI cannot call Research Services directly** — it goes through Runtime.
**Research Services cannot bypass CapabilityGate** — all tool calls route through ToolRegistry.
**ML models produce advisory results only** — they never call CapabilityGate.

---

## 5. Lifecycle

### Application Startup
1. Load workspace registry from SQLite
2. Initialize EventBus
3. Initialize CapabilityGate (probe Rust bridge — fail-open for local-only ops, fail-closed for target ops)
4. Initialize TaskRegistry (restore in-progress tasks from DB)
5. Initialize ToolRegistry (register built-in tools)
6. Initialize ModelService (probe local model providers)
7. Initialize WorkspaceContext (restore last workspace)
8. Start UI

### Workspace Load
1. Load WorkspaceContext from DB
2. Load ConversationContext (last N turns)
3. Load active Tasks
4. Publish `workspace.loaded` event

### Task Lifecycle
```
QUEUED → RUNNING → (PAUSED → RUNNING) → COMPLETED
                                      → FAILED
                                      → CANCELLED
```

Task state machine is enforced by TaskRegistry. Tasks cannot self-promote to COMPLETED — they must call `task_registry.update_status(id, COMPLETED, result=...)`.

### Shutdown
1. Pause all RUNNING tasks (checkpoint state)
2. Persist ConversationContext
3. Persist WorkspaceContext
4. Flush EventBus
5. Close SQLite connections

---

## 6. Persistence

All V7 runtime state is persisted to the existing SQLite store. New tables:

```sql
CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    goal TEXT,
    workspace_id TEXT NOT NULL,
    budget_json TEXT,
    checkpoint_json TEXT,
    result_json TEXT,
    created_at INTEGER,
    updated_at INTEGER
);

CREATE TABLE conversations (
    message_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    language_hint TEXT
);

CREATE TABLE workspaces (
    workspace_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scope_json TEXT,
    model_config_json TEXT,
    created_at INTEGER
);
```

Migrations use the existing migration pattern in `store.py`. No destructive migrations.

---

## 7. Event Flow

Key event types published to EventBus:

| Event | Publisher | Subscribers |
|-------|-----------|-------------|
| `task.created` | TaskRegistry | UI, AuditLog |
| `task.status_changed` | TaskRegistry | UI, AuditLog |
| `task.checkpoint` | TaskRegistry | AuditLog |
| `tool.invoked` | ToolRegistry | AuditLog |
| `tool.result` | ToolRegistry | AgentRuntime, AuditLog |
| `capability.denied` | CapabilityGate | UI, AuditLog |
| `model.completion` | ModelService | AgentRuntime |
| `workspace.loaded` | WorkspaceContext | UI |
| `finding.created` | CandidateService | UI, AuditLog |
| `finding.promoted` | WorkflowService | UI, AuditLog |

---

## 8. Cancellation

Cancellation propagates top-down:

```
researcher cancels task
    │
    ▼
TaskRegistry.cancel(task_id)
    │
    ▼
Sets task.status = CANCELLED
    │
    ├─→ Sends cancellation signal to active tool invocations
    │
    └─→ Publishes task.cancelled event
```

All tool handlers must check cancellation signals. Long-running subprocesses use `process_guard` (existing) with timeout enforcement.

---

## 9. Recovery

On startup, TaskRegistry scans for tasks in RUNNING state (crash recovery):
- If checkpoint exists → transition to PAUSED, allow researcher to resume
- If no checkpoint → transition to FAILED with reason "unclean_shutdown"

ConversationContext is always persisted before each model call — no message is lost on crash.

---

## 10. Capability Boundaries

| Capability | Gate Required | Human Approval |
|------------|--------------|----------------|
| `local_read` | No | No |
| `local_write` | No | Configurable |
| `local_exec` | CapabilityGate | Yes (by default) |
| `research_fetch` | CapabilityGate | No (allowlist) |
| `target_readonly` | CapabilityGate | Yes (scope check) |
| `target_statechange` | CapabilityGate | Always Yes |

---

## 11. Model Boundary

Models sit behind ModelService only. No module other than ModelService calls an LLM.
Model output is always labeled `is_advisory=True`. Model output never:
- directly triggers tool execution
- modifies capability grants  
- sets task status to COMPLETED
- marks findings as verified
- writes to evidence_graph as `supports` relation directly

---

## 12. UI Boundary

The UI:
- Subscribes to EventBus for all state updates
- Issues commands to the Runtime layer via explicit API (not direct service calls)
- Renders TaskRegistry state
- Renders ConversationContext
- NEVER owns canonical truth about tasks or findings

---

## 13. Rust / C++ Boundary

| Boundary | Interface |
|----------|-----------|
| Python → Rust | `rust_bridge.py` JSON-over-subprocess (versioned schema) |
| Python → C++ | `native/` pybind2 extension (versioned via `NATIVE_VERSION` constant) |
| Rust owns | Policy enforcement, capability decisions, scope gate |
| C++ owns | High-perf parsing, diff, simhash, entropy, fingerprint |

V7-BOOTSTRAP must add schema version checking on both bridges before adding new message types.

---

## 14. Migration Requirements

1. Add tasks / conversations / workspaces tables to existing SQLite DB (non-destructive)
2. Existing `urls`, `assets`, `runs`, `evidence`, `findings` tables are unchanged
3. All migrations are idempotent (`CREATE TABLE IF NOT EXISTS`)
4. No existing data is touched by V7-BOOTSTRAP migration

---

## 15. Testing Strategy

For V7-BOOTSTRAP, tests must cover:

| Component | Test Types |
|-----------|-----------|
| EventBus | Unit: publish/subscribe, unsubscribe, no-listener safe |
| TaskRegistry | Unit: lifecycle state machine; Integration: SQLite persistence; Negative: invalid transitions |
| ToolRegistry | Unit: register/invoke/list; Adversarial: unknown tool, capability denied |
| CapabilityGate | Unit: ALLOW/DENY; Negative: bridge unavailable → DENY (fail-closed) |
| ModelService | Unit: completion structure; Negative: model unavailable → explicit failure |
| ConversationContext | Unit: add/truncate; Persistence: round-trip through SQLite |
| WorkspaceContext | Unit: isolation; Integration: load/save round-trip |
| DB migrations | Integration: idempotent on existing DB |

Existing 1483-test baseline must not decrease.
