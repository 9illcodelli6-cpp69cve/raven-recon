# RAVEN V7 — Functional Integration Report

**Date:** 2026-10-05  
**Status:** Release Candidate  
**human_verification_required:** True (all findings)

---

## Summary

V7 completes the full-stack integration of RAVEN: backend API routes are now wired to real
subsystems, and every previously dead UI element is connected to live functionality.

## What Was Done

### Goal A — AI Truth Audit ✅

Audited `raven/runtime/model.py`. Confirmed:
- RAVEN AI = Ollama wrapper (`OllamaAdapter`)
- No custom generative LLM
- `qwen2.5-coder:latest` is the hardcoded fallback only — actual model comes from Ollama catalog
- `CompletionResult.is_advisory = True` is immutable (enforced in `__setattr__`)
- Settings UI now allows model selection at runtime

### Goal B — AI Chat End-to-End ✅

Chat was already functional in prior versions. V7 adds:
- Settings page to configure model_id and ollama_url without code changes
- `/api/v7/settings` POST resets `_AI_SVC` and `_CHAT_SESSIONS` so new model takes effect immediately

### Goal C — Dead UI Elimination ✅

**15 sidebar items** connected to real page views  
**6 top tabs** connected via `_tabNavMap`  
**4 quick action buttons** (Recon/Analyze/Script/Report) → `navigateTo()`  
**4 composer tool buttons** (Web/Workspace/Code/Terminal) → `navigateTo()`  
**Resource meters** → real `/api/v7/system/resources` (psutil when available)  
**System status rows** → real `/api/v7/status` (workspace name, terminal shells, proxy state)

### Goal D — Runtime Validation ✅

- All 15 new API endpoints: `200 OK` (validated via live server)
- All 15 SPA routes: correct show/hide behavior (JS assertion confirmed)
- Settings page: renders real AI audit data
- Workspace page: shows real workspace with Active badge
- Terminal page: renders with shell selector and Run button
- Regression suite: **1818 passed, 1 skipped**

### Goal E — Release Candidate ✅

`dist/RAVEN.exe` built 2026-10-05. 15 MB. PyInstaller bundle includes all web assets.

## Files Changed

| File | Change |
|---|---|
| `raven/api/server.py` | 20+ new V7 API routes + global subsystem state |
| `raven/runtime/workspace.py` | Fixed `dict(row)` bug for sqlite3.Row without row_factory |
| `web/index.html` | 14 new page-view divs + real SPA router + page loader JS |
| `dist/RAVEN.exe` | Rebuilt with all changes |

## Constraints Maintained

- `human_verification_required = True` — immutable, AttributeError if set False
- `CompletionResult.is_advisory = True` — immutable
- `security_authority = "NONE"` in all exam results
- `external_targets = 0` always
- `human_reviewed_labels = 0` always
- ML is advisory only — predictions never become evidence
- CapabilityGate fail-closed
- No direct model → raw shell execution
