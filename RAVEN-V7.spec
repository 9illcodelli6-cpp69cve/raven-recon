# -*- mode: python ; coding: utf-8 -*-
# ============================================================================
# DEPRECATED (Wave 15, A15-BUILD) — DO NOT USE.
# The single canonical spec is RAVEN.spec (emits dist/RAVEN.exe). Its package
# list, name='RAVEN' and native-artifact bundling supersede this file. Kept on
# disk for reference only; build.bat no longer invokes it.
# ============================================================================
# RAVEN V7 PyInstaller spec — bundles all V7 packages
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = [
    ('web',      'web'),
    ('raven.ico', '.'),
]
binaries       = []
hiddenimports  = [
    'clr',
    # V7 packages — explicit so the bundler finds them
    'raven.runtime',
    'raven.runtime.model',
    'raven.runtime.tasks',
    'raven.runtime.tools',
    'raven.runtime.events',
    'raven.runtime.policy',
    'raven.runtime.bootstrap',
    'raven.ai',
    'raven.agent_env',
    'raven.browser_engine',
    'raven.source_intel',
    'raven.research_engine',
    'raven.program_agent',
    'raven.knowledge_os',
    'raven.evidence_os',
]

# Pull in V7 submodules
for pkg in [
    'raven.runtime', 'raven.ai', 'raven.agent_env',
    'raven.browser_engine', 'raven.source_intel',
    'raven.research_engine', 'raven.program_agent',
    'raven.knowledge_os', 'raven.evidence_os',
]:
    hiddenimports += collect_submodules(pkg)

for pkg in ('webview', 'clr_loader', 'pythonnet'):
    try:
        tmp = collect_all(pkg)
        datas    += tmp[0]
        binaries += tmp[1]
        hiddenimports += tmp[2]
    except Exception:
        pass

a = Analysis(
    ['launch.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'PIL'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

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
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['raven.ico'],
)
