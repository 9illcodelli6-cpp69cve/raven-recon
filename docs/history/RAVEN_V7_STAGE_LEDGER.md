# RAVEN V7 Stage Ledger
**Authority: RAVEN_CONSTITUTION.md + RAVEN_V7_MASTER_SPEC.md**
**Updated: 2026-10-04**
**Baseline: 1483 passing tests (Phase I + II + III)**
**V7 Campaign: COMPLETE — 1,818 passed / 1 skipped / 0 failed**

## V7 Campaign Summary (2026-10-04)

| Part | Package | Tests | Status |
|------|---------|-------|--------|
| Bootstrap | `raven/runtime/` | 90/90 | ✅ GRADUATED |
| 03 | `raven/ai/` | ✅ | ✅ COMPLETE |
| 04 | `raven/agent_env/` | ✅ | ✅ COMPLETE |
| 05 | `raven/browser_engine/` | ✅ | ✅ COMPLETE |
| 06 | `raven/source_intel/` | ✅ | ✅ COMPLETE |
| 07 | `raven/research_engine/` | ✅ | ✅ COMPLETE |
| 08 | `raven/program_agent/` | ✅ | ✅ COMPLETE |
| 09 | `raven/knowledge_os/` | 36/36 | ✅ COMPLETE |
| 10 | `raven/evidence_os/` | 39/39 | ✅ COMPLETE |
| 11 | `web/prototype.html` | 40/40 | ✅ COMPLETE |
| 12 | Integration / Adversarial | 20/20 | ✅ COMPLETE |

**Build**: `dist/RAVEN.exe` (14.87 MB) — SHA-256: `C1A668ECF207654EA98780358635F9CBC7C81ADD8069D0FE94C5B231C8231DE6`

---

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | COMPLETE — implemented, tested, graduated |
| 🔧 | IN PROGRESS |
| 📋 | PLANNED — design ready, not started |
| ⏸ | BLOCKED — depends on predecessor |
| ❌ | NOT STARTED |

---

## Completed Baselines

| Stage | Description | Tests | Status |
|-------|-------------|-------|--------|
| Phase I | Network Fundamentals (NET-A/B/C/D) | 390 | ✅ GRADUATED |
| Phase II | Stateful Web Reasoning (NET-E/F/G/H) | 995 | ✅ GRADUATED |
| Phase III | Access Control Academy + Script Workshop + Research Gateway + Self Learning | 98 | ✅ GRADUATED |
| V5.0.1 Core | Desktop recon engine, scope, store, TUI, CLI | ~80 | ✅ STABLE |

**Total baseline: 1483 passing. Regression requirement: 1483 ≥ N (never decrease without justification).**

---

## V7 Stages

### STAGE 0: V7-BOOTSTRAP (MANDATORY FIRST)
**Prerequisite: Part 01 Acceptance Checklist complete**
**Description**: Shared runtime foundation that all later V7 modules depend on.
**Target: All V7 subsystems share one runtime.**

Deliverables:
- [ ] `raven/runtime/event_bus.py` — EventBus: publish/subscribe
- [ ] `raven/runtime/task_registry.py` — Task lifecycle + SQLite persistence
- [ ] `raven/runtime/tool_registry.py` — Tool registration + invocation
- [ ] `raven/runtime/capability_gate.py` — CapabilityGate wrapping rust_bridge
- [ ] `raven/runtime/model_service.py` — Ollama/llama.cpp/compatible endpoint wrapper
- [ ] `raven/runtime/conversation_context.py` — Multi-turn memory + SQLite persistence
- [ ] `raven/runtime/workspace_context.py` — Isolated workspace + scope
- [ ] `raven/runtime/migrations.py` — Add tasks/conversations/workspaces tables
- [ ] `tests/test_v7_bootstrap.py` — Full test suite for above

**Definition of Done:**
- All components implemented
- Unit tests for each component
- Integration test: full task lifecycle from QUEUED → COMPLETED with EventBus events
- Integration test: crash recovery (RUNNING → PAUSED on restart)
- Negative test: CapabilityGate fail-closed when Rust bridge absent
- Full regression: 1483 + new tests passing
- No existing API broken

---

### STAGE 1: V7-A — Local AI Chat
**Prerequisite: STAGE 0 complete**
**Description**: Multi-turn AI conversation with workspace memory, Arabic/English support.

Deliverables:
- [ ] `raven/chat/chat_service.py` — ChatService using ModelService
- [ ] `raven/chat/language_detector.py` — Arabic/English/mixed detection
- [ ] `raven/chat/context_manager.py` — Manages token budget, conversation pruning
- [ ] Chat UI page (Tauri/web) matching the V7 design reference
- [ ] `tests/test_v7_chat.py`

**Definition of Done:**
- Multi-turn conversation works with local model (Ollama)
- Arabic text handled correctly; technical identifiers preserved
- Workspace isolation: separate conversation per workspace
- Graceful failure when model is unavailable
- UI matches design reference screenshot

---

### STAGE 2: V7-B — Agent Runtime
**Prerequisite: STAGE 0, STAGE 1**
**Description**: Understand → Plan → Execute → Observe → Critique → Repair loop.

Deliverables:
- [ ] `raven/agent/agent_runtime.py` — Agent loop with existing planner/ + autonomy.py
- [ ] `raven/agent/agent_step.py` — Step descriptor with full observability
- [ ] Integration with TaskRegistry (each agent run is a Task)
- [ ] Integration with ToolRegistry (agent calls only registered tools)
- [ ] Researcher pause/resume/cancel controls
- [ ] `tests/test_v7_agent.py`

**Definition of Done:**
- Agent can complete a bounded task (e.g., "summarize workspace knowledge")
- Every tool call produces an execution record
- Cancellation propagates to subprocess tools
- No tool call bypasses CapabilityGate
- BOUNDED_AUTO autonomy level max enforced

---

### STAGE 3: V7-C — Tool Orchestrator
**Prerequisite: STAGE 0**
**Description**: Generic tool runtime. Every capability is a registered tool.

Deliverables:
- [ ] Built-in tools: `web_search`, `fetch_page`, `read_workspace_file`, `run_script`, `query_knowledge`
- [ ] Tool manifest schema (JSON Schema per tool)
- [ ] Tool result format (typed, with execution record)
- [ ] `tests/test_v7_tools.py`

**Definition of Done:**
- All built-in tools registered in ToolRegistry
- Each tool enforces its capability via CapabilityGate
- No tool executes without a task_id context
- Adversarial test: unknown tool ID → typed error, not crash

---

### STAGE 4: V7-D — Local Browser
**Prerequisite: STAGE 0**
**Description**: Real browser integration via Playwright or CDP.

Deliverables:
- [ ] `raven/browser/browser_service.py` — Navigate, read page, screenshot, HAR
- [ ] `raven/browser/browser_tool.py` — Registered as a tool in ToolRegistry
- [ ] `tests/test_v7_browser.py`

**Note**: network_phase2/browser.py is an educational data model — do not modify it. This is a new module.

**Definition of Done:**
- Navigate to URL, extract DOM, take screenshot
- HAR captured for all requests
- Requires `target_readonly` capability (user-configured scope)
- Cannot execute JavaScript that modifies security settings

---

### STAGE 5: V7-E — Traffic Analyzer
**Prerequisite: STAGE 4**
**Description**: Passive proxy layer — every browser request enriches knowledge.

Deliverables:
- [ ] `raven/traffic/proxy_service.py` — mitmproxy or native proxy
- [ ] `raven/traffic/traffic_enricher.py` — Extracts auth transitions, differences
- [ ] Integration with evidence_graph (traffic → observation nodes)
- [ ] `tests/test_v7_traffic.py`

**Definition of Done:**
- All browser requests/responses captured
- Auth state transitions detected (reuses network_phase2 logic)
- Each request stored as observation node in evidence_graph
- No PHI/credentials logged (EXCLUDED_HEADERS from ml/features.py)

---

### STAGE 6: V7-G — Research Gateway (Extend)
**Prerequisite: STAGE 0** (Phase III foundation already exists)
**Description**: Extend existing research_gateway/ into live agent integration.

Deliverables:
- [ ] `fetch_knowledge` registered as a tool in ToolRegistry
- [ ] KnowledgeStore.search_by_semantic_tag() using simple keyword matching
- [ ] Integration: when model asks "what is X?", gateway is queried first
- [ ] `tests/test_v7_gateway_integration.py`

**Definition of Done:**
- Agent can query KnowledgeStore before making model calls
- External research requires `research_fetch` capability
- Injection detection runs on all fetched content (existing detect_prompt_injection)
- All fetched content marked `is_untrusted_data=True`

---

### STAGE 7: V7-H — Self Learning (Extend)
**Prerequisite: STAGE 6** (Phase III foundation exists)
**Description**: Extend SelfStudyLoop to run study cycles during idle time.

Deliverables:
- [ ] `raven/learning/study_scheduler.py` — Idle-time study trigger
- [ ] Mastery matrix visible in UI (Learning page)
- [ ] Study progress persisted to SQLite (new `mastery` table)
- [ ] `tests/test_v7_learning_integration.py`

**Definition of Done:**
- When agent is IDLE, study cycle can run if gaps exist
- UI shows domain mastery levels
- Mastery never claimed without passing exam
- Human_reviewed_labels = 0 still holds

---

### STAGE 8: V7-I — Script Workshop (Extend)
**Prerequisite: STAGE 0** (Phase III foundation exists)
**Description**: Add execution harness to existing script_workshop/.

Deliverables:
- [ ] `raven/script_workshop/executor.py` — Bounded execution using process_guard
- [ ] `raven/script_workshop/project_store.py` — Script project persistence
- [ ] Script tool registered in ToolRegistry
- [ ] `tests/test_v7_script_executor.py`

**Definition of Done:**
- Scripts run in subprocess with timeout (process_guard)
- Only PURE_LOCAL and LOCAL_FIXTURE profiles auto-approved
- Higher profiles require explicit CapabilityGate grant
- All stdout/stderr captured and stored as execution record

---

### STAGE 9: V7-J — Terminal
**Prerequisite: STAGE 0**
**Description**: Observable, interruptible terminal runtime.

Deliverables:
- [ ] `raven/terminal/terminal_service.py` — Subprocess manager with stdout/stderr capture
- [ ] `raven/terminal/terminal_tool.py` — Registered tool
- [ ] Researcher can watch, pause, cancel
- [ ] `tests/test_v7_terminal.py`

**Definition of Done:**
- Commands run in configurable shell (WSL2/Kali or Windows)
- stdout/stderr/exit_code/duration all captured
- Cancellation works (SIGTERM propagated)
- No execution without explicit researcher approval (local_exec capability)

---

### STAGE 10: V7-K — Program Mode
**Prerequisite: STAGE 0**
**Description**: Machine-readable bug bounty policy compilation.

Deliverables:
- [ ] `raven/program/policy_compiler.py` — Text → ProgramPolicy struct
- [ ] `raven/program/policy_validator.py` — Checks for ambiguities, surfaces them
- [ ] Integration with CapabilityGate (target ops check active policy)
- [ ] `tests/test_v7_program_mode.py`

**Definition of Done:**
- Researcher pastes policy text → structured ProgramPolicy JSON
- Ambiguities surfaced to researcher (not silently guessed)
- All target-facing tool calls check policy before execution
- scope.py scope enforcement is not duplicated — policy references it

---

### STAGE 11: V7-L — Security Research Engine
**Prerequisite: STAGE 2, STAGE 5**
**Description**: Full scientific-reasoning loop for candidate findings.

Deliverables:
- [ ] `raven/research/reasoning_engine.py` — Hypothesis → Experiment → Controls → Evidence
- [ ] Integration with poc/candidate.py (existing)
- [ ] Integration with evidence_graph (existing)
- [ ] `tests/test_v7_research_engine.py`

**Definition of Done:**
- Candidate requires: hypothesis, experiment, at least 1 negative control, alternative_explanations
- `human_verification_required=True` enforced (existing invariant)
- `candidate != verified` enforced (existing review_workflow.py)
- Adversarial test: automated caller cannot set status to `confirmed`

---

### STAGE 12: V7-M — Evidence Graph (Integrate)
**Prerequisite: STAGE 11** (foundation already in evidence_graph.py)
**Description**: Wire evidence_graph to traffic, experiments, scripts, findings.

Deliverables:
- [ ] `raven/evidence/evidence_service.py` — Service wrapping evidence_graph.py
- [ ] Auto-linking: observations → findings, scripts → experiments
- [ ] Search: "what evidence supports finding X?"
- [ ] `tests/test_v7_evidence_service.py`

---

### STAGE 13: V7-F — Source Code Intelligence
**Prerequisite: STAGE 4**
**Description**: Multi-language source analysis.

Deliverables:
- [ ] `raven/source/html_analyzer.py` — Extend existing analysis.py
- [ ] `raven/source/js_analyzer.py` — Extend existing JS endpoint extraction
- [ ] `raven/source/openapi_parser.py` — OpenAPI/Swagger schema extraction
- [ ] `tests/test_v7_source_intel.py`

---

### STAGE 14: V7-N — Local Knowledge Tiers
**Prerequisite: STAGE 6**
**Description**: Verified / Learned / Inferred / Unknown tiers.

Deliverables:
- [ ] Extend `KnowledgeItem` with `epistemic_status` field
- [ ] Knowledge cannot be promoted from Inferred to Verified by ML alone
- [ ] `tests/test_v7_knowledge_tiers.py`

---

### STAGE 15: V7-O — Multilingual Engine
**Prerequisite: STAGE 1**
**Description**: Arabic/English/mixed conversation with preserved identifiers.

Deliverables:
- [ ] `raven/chat/language_detector.py` — Detect Arabic/English/mixed
- [ ] Identifier preservation logic (URLs, function names, headers not translated)
- [ ] `tests/test_v7_multilingual.py`

---

### STAGE 16: V7-P — Self Correction
**Prerequisite: STAGE 11**
**Description**: Contradiction detection and hypothesis invalidation.

Deliverables:
- [ ] `raven/research/contradiction_detector.py`
- [ ] When new evidence contradicts existing hypothesis → downgrade hypothesis status
- [ ] Correction log: what changed, why, what's new conclusion
- [ ] `tests/test_v7_self_correction.py`

---

### STAGE 17: V7-Q — UI (Full V7 Design)
**Prerequisite: STAGE 1, STAGE 9**
**Description**: Full desktop UI matching the V7 design reference.

Pages: AI Chat, Tasks, Browser, Traffic, Terminal, Recon, Scripts, Experiments, Evidence, Knowledge, Learning, Workspace, Program Mode, Plugins, Settings.

Design reference: `/images/1.webp` (RAVEN V7.0.0 screenshot).

Key visual elements:
- Dark background with RAVEN hero artwork (Japanese demon mask, fire/smoke)
- Left sidebar with page navigation (all 15 pages)
- Right sidebar: Active Task panel, Quick Actions, System Status, Resource Usage
- Top bar: logo + nav tabs + workspace selector + window controls
- Center: current page content
- Bottom bar: RAVEN OS Ready | Agent status | Proxy port | Workspace | Time
- Chat input: "Ask me anything... (Arabic, English, or mixed)" with toolbar

---

### STAGE 18: V7-R — Autonomous Tasks
**Prerequisite: STAGE 2**
**Description**: Resumable task graph with checkpoints.

---

### STAGE 19: V7-S — Extensibility
**Prerequisite: STAGE 0**
**Description**: Plugin manifest, hook registry, dynamic module loading.

---

### STAGE 20: V7-T — Performance Optimization
**Prerequisite: All core stages complete**
**Description**: Profile hotspots; move to C++/Rust where measured improvement exists.

---

### STAGE 21: V7-U — Full Test Coverage
**Prerequisite: Running parallel with all stages**
**Description**: Adversarial + stress + integration tests for all V7 subsystems.

---

## Part 01 Acceptance Checklist

| Requirement | Status |
|-------------|--------|
| Read Constitution | ✅ |
| Read V7 Architectural Review | ✅ |
| Verified test baseline (1483) | ✅ |
| Verified repository state (audit complete) | ✅ |
| Identified reusable V7 infrastructure | ✅ |
| Identified architectural conflicts | ✅ (test hollow assessment corrected) |
| Identified critical test hollows | ✅ (poc/planner/evidence/ml all have tests) |
| Produced V7 Runtime Architecture | ✅ RAVEN_RUNTIME_ARCHITECTURE.md |
| Produced V7 Stage Ledger | ✅ This document |
| Constitution amendments needed | None — existing Constitution is sufficient |
| Preserved Phase I–III invariants | ✅ |
| Preserved candidate != verified | ✅ |
| Preserved ML advisory-only | ✅ |
| Preserved human authority | ✅ |
| Preserved provenance separation | ✅ |
| Established V7-BOOTSTRAP as next stage | ✅ STAGE 0 |
| NOT prematurely built isolated Chat runtime | ✅ |

**Part 01 is SATISFIED. Next step: V7-BOOTSTRAP (STAGE 0).**
