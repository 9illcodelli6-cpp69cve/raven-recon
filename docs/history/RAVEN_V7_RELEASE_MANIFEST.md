# RAVEN V7 Release Manifest
**Version: 7.0.0**
**Build date: 2026-10-04**
**Platform: Windows 64-bit**

---

## Binary

| File | Size | SHA-256 |
|------|------|---------|
| `dist/RAVEN.exe` | 14.87 MB | `C1A668ECF207654EA98780358635F9CBC7C81ADD8069D0FE94C5B231C8231DE6` |

---

## Build Inputs

| File | SHA-256 |
|------|---------|
| `RAVEN-V7.spec` | `28A1F3FE017456E23C56F14A00702DEEB3FA4E5FB91D4D46BE69E73C931A531B` |
| `raven.ico` | (verify before distribution) |

---

## New V7 Source Packages

| Package | Description |
|---------|-------------|
| `raven/runtime/` | Shared runtime: EventBus, TaskRegistry, ToolRegistry, CapabilityGate, ModelService, Bootstrap |
| `raven/ai/` | Chat, Memory, SelfCorrector, LanguageDetector |
| `raven/agent_env/` | Terminal, Filesystem, WSL, Scripts |
| `raven/browser_engine/` | ScopeGuard, HttpClient, TrafficAnalyzer |
| `raven/source_intel/` | DNS, CertTransparency, Subdomains, IP Intel |
| `raven/research_engine/` | CandidateFinding, ResearchEngine, ResearchCritic |
| `raven/program_agent/` | ProgramPolicy, ProgramScope, BugBountyProgram, Submission |
| `raven/knowledge_os/` | KnowledgeBase, LearningEngine, TechniqueLibrary |
| `raven/evidence_os/` | EvidenceGraph, PoCBuilder, ReportEngine |

---

## Web UI Changes

| File | Change |
|------|--------|
| `web/prototype.html` | Added Knowledge OS (V7) and Evidence & Reports (V7) nav tabs and view panels |

---

## Test Report

| Suite | Pass | Fail | Skip |
|-------|------|------|------|
| Pre-existing (all phases) | 1,798 | 0 | 1 |
| V7-BOOTSTRAP | 90 | 0 | 0 |
| Part 09 — Knowledge OS | 36 | 0 | 0 |
| Part 10 — Evidence OS | 39 | 0 | 0 |
| Part 11 — GUI / UX | 40 | 0 | 0 |
| Part 12 — Integration | 20 | 0 | 0 |
| **TOTAL** | **~2,023** | **0** | **1** |

---

## PyInstaller Build Details

```
Bootloader: Windows-64bit-intel/runw.exe
Archives: PYZ-00.pyz (Python bytecode), RAVEN.pkg (resources)
Output: dist/RAVEN.exe
Icon: raven.ico (embedded)
Mode: windowed (no console)
UPX: enabled
```

---

## Security Attestation

- `human_verification_required = True` — immutable in all CandidateFinding objects
- `security_authority = "NONE"` — no automated security decisions
- `external_targets = 0` — enforced by ProgramPolicy
- `human_reviewed_labels = 0` — AI cannot self-label as human-reviewed
- All ML output is advisory (`is_advisory = True` immutable)
- CapabilityGate is fail-closed
- All 15 security invariants verified by adversarial test suite

*RAVEN V7 is an authorized security research assistant. All outputs are advisory and require human verification before action.*
