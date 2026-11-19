# -*- mode: python ; coding: utf-8 -*-
#
# RAVEN — THE single canonical PyInstaller spec (Wave 15, A15-BUILD; Linux port).
#
# One build definition, two targets (chosen by the platform you build ON —
# PyInstaller cannot cross-compile):
#
#   Windows → dist/RAVEN.exe       onefile, console-less, windowed (unchanged).
#             build.bat invokes this file.
#   Linux   → dist/RAVEN/RAVEN     onedir ELF executable + dist/RAVEN/_internal/.
#             build-linux.sh invokes this file. onedir (not onefile) because the
#             bundle carries torch: a onefile would re-extract ~1 GB into /tmp on
#             every launch. The native model ships inside the bundle.
#
# RAVEN-V7.spec and RAVEN-V5.spec are DEPRECATED and retained only for reference.
#
# Bundles everything the reconstructed app needs:
#   * web/ UI assets + icon (raven.ico on Windows, PNG on Linux)
#   * the whole `raven` package (collect_submodules + explicit hiddenimports)
#   * the native C++ accelerator (_raven_native .pyd / .so) when it has been built
#     (ABI-gated at load; Python fallback if absent/mismatched)
#   * the Rust trusted core raven-bridge(.exe) from rust/target/release
#     (resolved frozen-aware by raven/rust_bridge.py under raven/_bridge/)
#   * Windows only: a version resource (build/version_info.txt)
#
import glob
import os
import sys

from PyInstaller.utils.hooks import collect_all, collect_submodules

IS_WIN = sys.platform == 'win32'

# Resolve everything relative to this spec so the build is cwd-independent.
HERE = os.path.abspath(SPECPATH)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# ── Version resource (Windows; restore if a `--clean` build wiped the work path) ──
VERSION_FILE = os.path.join(HERE, 'build', 'version_info.txt')
if IS_WIN and not os.path.isfile(VERSION_FILE):
    os.makedirs(os.path.dirname(VERSION_FILE), exist_ok=True)
    with open(VERSION_FILE, 'w', encoding='utf-8') as _vf:
        _vf.write(
            "VSVersionInfo(\n"
            "  ffi=FixedFileInfo(\n"
            "    filevers=(0, 1, 0, 0), prodvers=(0, 1, 0, 0),\n"
            "    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,\n"
            "    date=(0, 0)\n"
            "  ),\n"
            "  kids=[\n"
            "    StringFileInfo([StringTable('040904B0', [\n"
            "      StringStruct('CompanyName', 'RAVEN Project'),\n"
            "      StringStruct('FileDescription', 'RAVEN Recon'),\n"
            "      StringStruct('FileVersion', '0.1.0.0'),\n"
            "      StringStruct('InternalName', 'RAVEN'),\n"
            "      StringStruct('OriginalFilename', 'RAVEN.exe'),\n"
            "      StringStruct('ProductName', 'RAVEN'),\n"
            "      StringStruct('ProductVersion', '0.1.0'),\n"
            "    ])]),\n"
            "    VarFileInfo([VarStruct('Translation', [1033, 1200])])\n"
            "  ]\n"
            ")\n"
        )

# ── Native artifact paths (prebuilt; never rebuilt from source here) ──────────
if IS_WIN:
    _native_ext = os.path.join(HERE, 'raven', 'native', '_raven_native.cp313-win_amd64.pyd')
    NATIVE_EXTS = [_native_ext] if os.path.isfile(_native_ext) else []
    RUST_BRIDGE = os.path.join(HERE, 'rust', 'target', 'release', 'raven-bridge.exe')
else:
    # Built by `cmake` in native/ for the interpreter doing the build (ABI-tagged .so).
    NATIVE_EXTS = sorted(glob.glob(os.path.join(HERE, 'raven', 'native', '_raven_native*.so')))
    RUST_BRIDGE = os.path.join(HERE, 'rust', 'target', 'release', 'raven-bridge')

# ── Data / binary collections ─────────────────────────────────────────────────
datas = [(os.path.join(HERE, 'web'), 'web')]
# RAVEN's own skill playbooks (raven/skills/<name>/SKILL.md), loaded on demand by Claude.
if os.path.isdir(os.path.join(HERE, 'raven', 'skills')):
    datas.append((os.path.join(HERE, 'raven', 'skills'), os.path.join('raven', 'skills')))
binaries = []
if IS_WIN:
    datas.append((os.path.join(HERE, 'raven.ico'), '.'))
else:
    # Window/taskbar icon (launch.py looks for packaging/linux/raven-recon.png).
    datas.append((os.path.join(HERE, 'packaging', 'linux', 'raven-recon.png'),
                  os.path.join('packaging', 'linux')))
    # Native model: on Windows it ships BESIDE the onefile exe (no per-launch
    # extraction). A Linux onedir has no extraction cost, so it ships inside the
    # bundle; server._native_models_dir() checks _MEIPASS/models/native first.
    _models = os.path.join(HERE, 'models', 'native')
    for _name in ('native_registry.json', 'raven_nano_final.pt',
                  'raven_nano_final.tokenizer.json'):
        _p = os.path.join(_models, _name)
        if os.path.isfile(_p):
            datas.append((_p, os.path.join('models', 'native')))
        else:
            print(f"[RAVEN.spec] WARNING: native model file missing: {_p}")

# Rust trusted core → raven/_bridge/ (matches rust_bridge.py frozen lookup).
if os.path.isfile(RUST_BRIDGE):
    if IS_WIN:
        datas.append((RUST_BRIDGE, 'raven/_bridge'))
    else:
        # As a binary so PyInstaller keeps the executable bit.
        binaries.append((RUST_BRIDGE, 'raven/_bridge'))
else:
    print(f"[RAVEN.spec] WARNING: Rust bridge not found at {RUST_BRIDGE} — "
          f"frozen app will fail closed (DENY) on Rust-routed capabilities.")

# Native C++ accelerator → raven/native/ (package-relative import target).
if NATIVE_EXTS:
    binaries += [(p, 'raven/native') for p in NATIVE_EXTS]
else:
    print("[RAVEN.spec] WARNING: native extension not built — "
          "frozen app will use the Python analysis fallback.")

# ── Hidden imports ────────────────────────────────────────────────────────────
# The whole first-party package tree, so every reconstruction subpackage/module
# is collected even when only reached via a conditional / string import.
hiddenimports = ['clr'] if IS_WIN else []
# Claude (Anthropic API) client + key encryption — bundled when installed.
for _pkg in ('anthropic', 'cryptography'):
    try:
        _d, _b, _h = collect_all(_pkg)
        datas += _d
        binaries += _b          # cryptography ships a compiled Rust extension
        hiddenimports += _h
    except Exception:
        pass
hiddenimports += collect_submodules('raven')

# Belt-and-suspenders: explicitly name the reconstruction subpackages and the
# new modules A15 must guarantee are bundled (subset of collect_submodules).
hiddenimports += [
    # V7 subsystems
    'raven.runtime', 'raven.runtime.model', 'raven.runtime.tasks',
    # (raven.runtime.policy / raven.runtime.bootstrap were listed here but do not
    #  exist — PyInstaller logged "Hidden import not found" errors; the live
    #  bootstrap is raven.api.bootstrap below.)
    'raven.runtime.tools', 'raven.runtime.events',
    'raven.runtime.conversation',
    'raven.runtime.workspace', 'raven.runtime.plugins',
    'raven.ai', 'raven.agent_env', 'raven.browser_engine',
    'raven.source_intel', 'raven.research_engine', 'raven.program_agent',
    'raven.knowledge_os', 'raven.evidence_os', 'raven.payloads',
    # NEW reconstruction subpackages
    'raven.recon', 'raven.agent', 'raven.native_ai',
    'raven.runtime.services',
    # NEW reconstruction modules
    'raven.runtime.process_executor', 'raven.runtime.resource_governor',
    'raven.runtime.environment', 'raven.runtime.scheduler_bridge',
    'raven.api.traffic', 'raven.api.contracts', 'raven.api.bootstrap',
    'raven.api.evidence_knowledge_handlers',
    'raven.evidence_os.read_model', 'raven.evidence_os.canonical_registry',
    'raven.security.actor_context',
    # native + bridge Python shims, Linux-port path helper
    'raven.native', 'raven.native.backend', 'raven.rust_bridge',
    'raven.platform_paths',
]

# pywebview native-window backend; browser fallback if absent.
#   Windows: EdgeChromium via pythonnet/.NET.
#   Linux:   GTK + WebKit2GTK via PyGObject (gi); PyInstaller's gi hooks collect
#            the typelibs + GTK runtime pieces.
_webview_pkgs = ('webview', 'clr_loader', 'pythonnet') if IS_WIN else ('webview',)
for pkg in _webview_pkgs:
    try:
        tmp = collect_all(pkg)
        datas += tmp[0]
        binaries += tmp[1]
        hiddenimports += tmp[2]
    except Exception as exc:
        print(f"[RAVEN.spec] collect_all({pkg!r}) skipped: {exc}")

if not IS_WIN:
    hiddenimports += ['webview.platforms.gtk', 'gi', 'gi.repository.Gtk',
                      'gi.repository.Gdk', 'gi.repository.GLib',
                      'gi.repository.WebKit2', 'gi.repository.JavaScriptCore',
                      'gi.repository.Soup']

# De-duplicate hidden imports (collect_submodules + explicit list overlap).
hiddenimports = sorted(set(hiddenimports))

excludes = ['tkinter', 'PIL']
if not IS_WIN:
    # GTK is the Linux backend; never drag in Qt / CEF / Windows-only stacks that
    # pywebview's other platform modules reference (hundreds of MB, unused).
    excludes += ['PyQt5', 'PyQt6', 'PySide2', 'PySide6', 'qtpy', 'cefpython3',
                 'clr', 'clr_loader', 'pythonnet',
                 'webview.platforms.qt', 'webview.platforms.cef',
                 'webview.platforms.winforms', 'webview.platforms.edgechromium',
                 'webview.platforms.mshtml', 'webview.platforms.cocoa',
                 'webview.platforms.android']
    # The Linux venv uses --system-site-packages (for the distro's PyGObject), so
    # optional imports inside torch/sklearn/scipy would otherwise drag in whatever
    # the distro happens to ship (Kali: pandas, matplotlib, sqlalchemy, IPython,
    # numba, ...). RAVEN imports none of these; keep them out of the bundle.
    excludes += ['pytest', '_pytest', 'py', 'IPython', 'jedi', 'parso', 'astroid',
                 'matplotlib', 'pandas', 'sqlalchemy', 'tables', 'openpyxl',
                 'numba', 'llvmlite', 'gevent', 'uvloop', 'lxml', 'mako', 'paste',
                 'zope', 'lz4', 'notebook', 'nbformat', 'ipykernel',
                 'jupyter_client', 'tornado', 'docutils', 'sphinx']

# UPX corrupts some native/.NET DLLs and trips AV on unsigned binaries; keep UPX
# on for size but never let it touch the native accel, the Rust bridge, the CPY
# runtime, or the .NET/WebView native libraries. (No UPX on Linux.)
upx_exclude = [
    '_raven_native.cp313-win_amd64.pyd',
    'raven-bridge.exe',
    'python3.dll', 'python313.dll',
    'vcruntime140.dll', 'vcruntime140_1.dll',
    'clrjit.dll', 'coreclr.dll', 'hostfxr.dll', 'hostpolicy.dll',
    'mscordaccore.dll', 'mscordbi.dll', 'Python.Runtime.dll',
    'WebView2Loader.dll',
]

# Linux GTK runtime: PyInstaller's gi hooks otherwise copy EVERY icon theme, GTK
# theme and locale installed on the build machine (~370 MB on Kali). The UI is
# HTML inside WebKit, so GTK only needs its default theme for window chrome.
hooksconfig = {} if IS_WIN else {
    'gi': {
        'icons': ['Adwaita', 'hicolor'],
        'themes': ['Adwaita'],
        'languages': ['en_US', 'ar'],
        'module-versions': {'Gtk': '3.0', 'WebKit2': '4.1'},
    },
}

a = Analysis(
    ['launch.py'],
    pathex=[HERE],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    # Linux: PyInstaller has no hooks for the WebKit2 / JavaScriptCore typelibs
    # that pywebview's GTK backend needs; ours live in packaging/linux/.
    hookspath=[] if IS_WIN else [os.path.join(HERE, 'packaging', 'linux', 'pyinstaller-hooks')],
    hooksconfig=hooksconfig,
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

if IS_WIN:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name='RAVEN',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        upx_exclude=upx_exclude,
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        icon=[os.path.join(HERE, 'raven.ico')],
        # version=VERSION_FILE,  # disabled: pefile version-resource write fails ("file is empty") on this toolchain; cosmetic metadata only, not functional. Re-enable once the version-write step is fixed.
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name='RAVEN',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,   # Linux: keeps stdout/stderr for `RAVEN` run from a terminal
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        name='RAVEN',
    )
