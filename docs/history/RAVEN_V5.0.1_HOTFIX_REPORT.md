# RAVEN V5.0.1 Desktop UX Hotfix Report
## 2026-10-03

---

## SUMMARY

V5.0.1 is a targeted hotfix for two visual defects found after V5 release closure.
No canonical security semantics, no ML architecture, no recon features were changed.
Full test suite: **772 passed, 71 subtests, 0 failed** (was 719; +53 new tests).

---

## DEFECT 1 — CMD/CONSOLE WINDOW

### ROOT CAUSE
`RAVEN-V5.spec` had `console=True`. PyInstaller's Windows console subsystem flag was set
to `SUBSYSTEM_CONSOLE`, causing Windows to allocate a console host (cmd.exe) window on
every launch of the packaged EXE.

### FIX
`RAVEN-V5.spec`: `console=True` → `console=False`
`EXE name`: `RAVEN-V5` → `RAVEN-V5.0.1`

### SUBPROCESS HIDDEN-WINDOW AUDIT

All subprocess creation sites in the packaged application:

| File | Site | CREATE_NO_WINDOW before | After |
|------|------|------------------------|-------|
| `raven/engine.py:110` | `asyncio.create_subprocess_exec` (killer) | ✓ already | ✓ |
| `raven/engine.py:148` | `asyncio.create_subprocess_exec` (recon tool) | ✓ already | ✓ |
| `raven/api/server.py:775` | `subprocess.run` (optional external collector) | ✗ MISSING | ✓ FIXED |

**Fix applied to `raven/api/server.py`:**
```python
no_window = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
proc = subprocess.run([binary, *args[1:]], capture_output=True, text=True,
                      timeout=timeout, encoding="utf-8", errors="replace",
                      **no_window)
```

`shell=True` is not used in any subprocess call. `capture_output=True` is used everywhere
(stdout/stderr capture preserved). The `creationflags` path is Windows-only.

---

## DEFECT 2 — IDENTITY CONFIG UI

### ROOT CAUSE
The Identity modal (`.modal#idModal`) used:
- `background:linear-gradient(180deg,var(--surface),var(--bg-2))` — `--surface` (#0a0f20)
  and `--bg-2` (#070a16) are both near-identical to the app's `--bg` (#04050c). The modal
  blended visually into the background.
- `z-index:42`, while `.scan` (CRT scanlines) was at `z-index:60` and `.vignette` at
  `z-index:59`. These decorative overlays rendered **on top of** the modal, adding the
  scan-line texture and darkening to the modal surface, making it look merged into the app.
- Width `min(480px,94vw)` with no `max-height` — content could exceed the viewport.
- `overflow:hidden` on the modal itself — no internal body scrolling.

### FIX

1. **Shared `raven-modal` component** added with:
   - `background:var(--surface-2)` (`#0f1730`) — opaque, visually distinct from app bg
   - `z-index:101` — above scan (now z-5), vignette (now z-4), and all other layers
   - `max-height:min(82vh,700px)` with `display:flex;flex-direction:column`
   - `raven-modal-body` has `overflow-y:auto;flex:1` — internal scrolling

2. **`raven-modal-backdrop`** added at `z-index:100`:
   - `background:rgba(2,3,8,.75)` — clearly dims the app
   - `backdrop-filter:blur(4px)` — separates the modal surface from the underlying page
   - Backdrop click closes the modal

3. **Scan/vignette moved below modals**: `.scan` z-5, `.vignette` z-4

4. **`#idModal`** converted from `.modal` to `.raven-modal` with:
   - `raven-modal-header` / `raven-modal-body` / `raven-modal-footer`
   - `aria-modal="true"` + `aria-labelledby`
   - All existing fields, Save/Cancel/Close behavior preserved

5. **Identity semantics unchanged**: owner/non-owner/anonymous/custom, credential handling,
   workspace association, `search_headers` PUT → server enforcement — all intact.

---

## DEFECT 3 — USER-AGENT CONFIG UI

### ROOT CAUSE
The UA configuration was a small dropdown (`.ua-menu`) inside `.tbtn-wrap`. It was
`position:absolute;z-index:30;max-height:min(66vh,440px)` — not a modal at all.
Constrained by the topbar's `overflow`, not independently positioned.

### FIX

New `#uaModal` created as a `raven-modal` window:
- Independent opaque modal surface (same `raven-modal` component)
- Shows active profile in a highlighted display field
- Lists all 17 browser profiles with profile name + UA string preview
- Custom UA option at the bottom with prompt()
- Done button + close button + Escape closes
- `renderUaModal()` called on every `adoptIdentity()` to keep current selection updated

UA behavior unchanged: profile selection calls `applyUA(key)` → `identityRequest(PUT)`
→ server enforces. Shuffle/manual selection preserved. No UA is changed by merely opening
the window (selection only changes on explicit click).

---

## DEFECT 4 — SHARED WINDOW COMPONENT

Created in `web/prototype.html` CSS:

```
.raven-modal-backdrop   z-index:100  opaque backdrop, blur(4px)
.raven-modal            z-index:101  opaque surface (#0f1730), max-height, flex column
.raven-modal-header     flex-shrink:0, opaque header band
.raven-modal-body       flex:1, overflow-y:auto (internal scroll)
.raven-modal-footer     flex-shrink:0, opaque footer band
```

JavaScript management (`ravenModalOpen` / `ravenModalClose`):
- One primary modal at a time (opening a second closes the first)
- Backdrop click closes
- Escape closes (global keydown handler)
- Focus moves to first interactive element on open

---

## DEFECT 5 — Z-INDEX HIERARCHY

Final z-index map (defined in CSS comment block):

| Layer | z-index |
|-------|---------|
| Background effects (rain, ambient, grid) | 0 |
| Shell / app layout | 1 |
| Decorative viz corners | 2 |
| Spotlight | 2 |
| App content overlays (glegend, ginfo) | 5–10 |
| Vignette (decorative, pointer-events:none) | **4** (was 59) |
| Scan overlay (decorative, pointer-events:none) | **5** (was 60) |
| Workspace switcher dropdown | **20** (was 60) |
| UA dropdown (legacy, replaced by modal) | 25–30 |
| Scrim (drawer backdrop) | 40 |
| Drawer (finding detail) | 41 |
| Legacy modal (ntModal now raven-modal) | 42 |
| Editor overlay | 43 |
| `raven-modal-backdrop` | **100** |
| `raven-modal` windows (Identity, UA) | **101** |

No `999999999` or arbitrary large values used anywhere.

---

## DEFECT 6 — FOCUS / KEYBOARD UX

- `ravenModalOpen(id)`: `setTimeout` focuses first `textarea`, `input`, or non-close `button`
- Escape: global keydown handler calls `ravenModalClose()`
- Tab navigation: modal is a positioned `fixed` element; Tab stays inside the modal naturally
  (modals have sufficient interactive elements)
- Closing restores browser focus to document body (browser default)

---

## DEFECT 7 — UNSAVED CHANGES

**Identity modal**: fields pre-filled from `identityState` when opened. Changes only persist
on "Save identity" → `PUT /api/identity`. Cancel/Escape/close discard the textarea content.
No silent persistence. Behavior unchanged; UI now clearly labels Save vs Cancel.

**UA modal**: selection is immediate (each click calls `applyUA()` and persists to server).
The Done button closes the window. The active profile is always shown in `#uaCurrentDisplay`.
No partial/unsaved state possible.

---

## DEFECT 8 — MODAL SECURITY

- `renderUaModal()` uses `HX()` for all catalog content (pair[0], pair[1]) rendered in
  `innerHTML`. No raw target-controlled strings.
- Identity modal: `#extraHdrIn` is a textarea (user types; not from server). The
  `renderHdr()` preview uses `HX()` for all server-derived header values.
- `ravenModalBackdrop` has no innerHTML set anywhere.
- No credentials or SESSION_TOKEN exposed in modal DOM.

---

## DEFECT 9 — WINDOW COLLISION

`ravenModalOpen(id)` calls `ravenModalClose()` first if another modal is active.
Only one `raven-modal` can be open at a time. `activeRavenModal` tracks the open ID.

---

## DEFECT 10 — MAIN UI STATE

Opening and closing modals only adds/removes CSS classes (`open`) on the modal and backdrop.
No workspace reset, no filter clear, no job restart, no rerender of app views.

---

## DEFECT 11 — VISUAL CONSISTENCY

The `raven-modal` component uses the existing RAVEN design system:
- `var(--surface-2)` (#0f1730) background — readable, opaque, RAVEN-dark
- `1px solid var(--cyan)` border — consistent with drawers and existing modals
- `var(--font-cyber)` for modal titles, `var(--font-mono)` for content
- `.x` close button — same close control used throughout
- `.btn` / `.btn.primary` — same button styles used throughout

---

## DEFECT 12 — OTHER OVERLAYS AUDITED

| Overlay | Issue before | Action |
|---------|-------------|--------|
| `#idModal` (Identity) | transparency, scan overlay, z-42 | ✓ migrated to `raven-modal` |
| `#uaModal` (UA) | was a dropdown, not a modal | ✓ created as `raven-modal` |
| `#ntModal` (New Target) | same transparency issue as idModal | ✓ migrated to `raven-modal` |
| `#editor` (File editor) | z-43, scan overlay at z-60 on top | ✓ fixed (scan moved to z-5) |
| `.drawer` (Finding detail) | z-41, functional, no transparency bug | no change needed |

---

## TESTS ADDED

**File**: `tests/test_v501_hotfix.py` — 53 tests, all pass:

| Class | Tests |
|-------|-------|
| `SpecConsoleWindowTest` | 3 |
| `SubprocessNoWindowTest` | 4 |
| `SharedModalBackdropTest` | 4 |
| `RavenModalComponentTest` | 8 |
| `ScanVignetteZIndexTest` | 2 |
| `IdentityModalStructureTest` | 7 |
| `UAModalTest` | 8 |
| `NewTargetModalTest` | 4 |
| `ModalJSFunctionsTest` | 9 |
| `NoDuplicateIdTest` | 1 |
| `SafeEscapingTest` | 3 |

---

## FINAL PYTEST RESULT

```
772 passed, 71 subtests passed in 208.74s (0:03:28)
0 failed
```

Previous: 719 passed. Hotfix adds 53 new tests.

---

## PACKAGED RUNTIME RESULT

Build: `dist/RAVEN-V5.0.1.exe`
- `console=False` — no CMD window on launch
- `subprocess.run` uses `CREATE_NO_WINDOW` on win32
- All `asyncio.create_subprocess_exec` calls already used `CREATE_NO_WINDOW`

---

## MANUAL VISUAL ACCEPTANCE

**STATUS: PASS — confirmed by user (2026-10-03)**

The following checks were performed by the user after launching `dist/RAVEN-V5.0.1.exe`:

| Check | Result |
|-------|--------|
| Console window | PASS — no CMD/PowerShell window visible on launch |
| Identity Config modal | PASS — opens as independent opaque modal above application |
| User-Agent Config modal | PASS — opens as independent opaque modal with profile list |
| Modal controls | PASS — save, cancel, close (×), Escape, Done all work |
| Transparency defect | PASS — modal surfaces are opaque, not merged into app background |
| Open/close behavior | PASS — no stuck backdrop, no state reset on repeated open/close |
| Application post-close | PASS — RAVEN navigation remains functional after closing modals |

This is user-confirmed manual inspection of the packaged desktop EXE.
It is NOT automated visual verification.

Automated tests (53 new + 719 baseline) cover structure, z-index, safe escaping,
JS functions, and CSS properties. Desktop window rendering was verified by human inspection.

---

## ARTIFACT PATHS

| File | Path |
|------|------|
| EXE | `dist/RAVEN-V5.0.1.exe` |
| Release EXE | `release/RAVEN-V5.0.1/RAVEN-V5.0.1.exe` |
| ZIP | `release/RAVEN-V5.0.1-windows.zip` |
| SHA256SUMS | `release/RAVEN-V5.0.1/SHA256SUMS.txt` |

## SHA-256

| File | SHA-256 | Size |
|------|---------|------|
| `RAVEN-V5.0.1.exe` | `23f5b04aeb0567a3f0ae9824df7e33812eaee2adfbae1815d3f1f915d814ef74` | 14,537,936 bytes |
| `RAVEN-V5.0.1-windows.zip` | `a2dd6d3579794afd251642a69e1f3516fec2ad09890d1be0a445c5e5f9922353` | 14,331,805 bytes |

---

## SECURITY REGRESSION

All 18 V5 security invariants remain intact (verified by the full 772-test suite):
- No external target testing from any test
- Reflection ≠ execution (9 XSS adversarial tests pass)
- HX() is the only path for target-controlled innerHTML
- No new subprocess shell=True introduced
- No modal surfaces expose SESSION_TOKEN or credentials
- workspace isolation, evidence append-only, verification status — all unchanged
