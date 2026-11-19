# RAVEN V7 Release Notes

**Release:** V7.0.0 Release Candidate  
**Date:** 2026-10-05

---

## What's New in V7

### Full SPA Navigation

All 15 sidebar items, 6 top tabs, 4 quick action buttons, and 4 composer tool buttons
are now wired to real page views. There are no more dead navigation elements.

### 14 New Page Views

Tasks, Browser, Traffic, Terminal, Recon, Scripts, Experiments, Evidence, Knowledge,
Learning, Workspace, Program Mode, Plugins, Settings — all connected to real backend APIs.

### 16 New Backend API Routes

`/api/v7/status`, `/api/v7/system/resources`, `/api/v7/terminal/status`,
`/api/v7/terminal/history`, `/api/v7/terminal/run`, `/api/v7/workspace`,
`/api/v7/workspace/current`, `/api/v7/workspace/switch`, `/api/v7/workspace/create`,
`/api/v7/tasks`, `/api/v7/tasks/<id>/cancel`, `/api/v7/settings`,
`/api/v7/plugins`, `/api/v7/knowledge`, `/api/v7/evidence`, `/api/v7/traffic`

### Real Resource Monitoring

CPU, Memory, Disk usage now come from `psutil` via `/api/v7/system/resources`.
Honest "unavailable" shown if psutil is not installed.

### Real System Status

Workspace name, terminal shell availability, and proxy state are read from live APIs,
not hardcoded strings.

### AI Model Configuration

Settings page allows runtime model selection (Ollama model name) and Ollama URL change
without modifying code or restarting the application.

### Integrated Terminal

Terminal page connects to `TerminalTool` (sandboxed subprocess). PowerShell, CMD, and
Bash shells are selectable. History is tracked.

---

## Bug Fixes

- `WorkspaceManager.list_all()` — fixed crash when iterating sqlite3.Row without row_factory

---

## Security Invariants

All V7 hardening constraints maintained:
- `human_verification_required = True` on all `CandidateAuthorizationFinding`
- `CompletionResult.is_advisory = True` — immutable
- ML never promotes predictions to human labels
- CapabilityGate fail-closed by default
- No model → raw shell path

---

## Regression

pytest baseline: **1818 passed, 1 skipped** — no regressions introduced.
