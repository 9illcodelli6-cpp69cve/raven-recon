# -*- mode: python ; coding: utf-8 -*-
# ============================================================================
# DEPRECATED (Wave 15, A15-BUILD) — DO NOT USE.
# Legacy V5-era variant (name='RAVEN-V5.0.1'; bundles raven/payloads as data,
# which is code PyInstaller already collects). Superseded by the canonical
# RAVEN.spec (emits dist/RAVEN.exe). Kept on disk for reference only.
# ============================================================================


a = Analysis(
    ['launch.py'],
    pathex=[],
    binaries=[],
    datas=[('web', 'web'), ('raven/payloads', 'raven/payloads')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='RAVEN-V5.0.1',
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
)
