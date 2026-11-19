#!/usr/bin/env bash
# Build the Linux RAVEN app: dist/RAVEN/RAVEN (ELF executable + _internal/).
#
#   ./build-linux.sh            build (uses .venv, creates it if missing)
#   ./build-linux.sh --install  build, then add it to the applications menu
#
# Same single build definition as Windows (RAVEN.spec); the platform you build on
# decides the target. Steps:
#   1. Rust trusted core      rust/target/release/raven-bridge   (cargo, if present)
#   2. C++ native accelerator raven/native/_raven_native*.so     (cmake, optional;
#      needs python3-dev — skipped otherwise, the app uses the Python fallback)
#   3. PyInstaller            RAVEN.spec -> dist/RAVEN/
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$HERE"

if [[ ! -x .venv/bin/python ]]; then
    echo "==> creating .venv (system site-packages, for PyGObject/GTK)"
    python3 -m venv --system-site-packages .venv
    .venv/bin/pip install -q -r requirements-linux.txt
fi
PY="$HERE/.venv/bin/python"

echo "==> [1/3] Rust trusted core"
if command -v cargo >/dev/null 2>&1; then
    (cd rust && cargo build --release -p raven-bridge)
else
    echo "    cargo not found — skipping (Rust-routed capabilities will fail closed / DENY)"
fi

echo "==> [2/3] C++ native accelerator (optional)"
PYINC="$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["include"])')"
if [[ -f "$PYINC/Python.h" ]] && command -v cmake >/dev/null 2>&1; then
    PYBIND_DIR="$("$PY" -c 'import pybind11; print(pybind11.get_cmake_dir())' 2>/dev/null || true)"
    cmake -S native -B native/build-linux -DCMAKE_BUILD_TYPE=Release \
        -DRAVEN_NATIVE_BUILD_TESTS=OFF -DRAVEN_NATIVE_BUILD_BENCHMARKS=OFF \
        -DPython3_EXECUTABLE="$PY" ${PYBIND_DIR:+-Dpybind11_DIR="$PYBIND_DIR"} >/dev/null
    cmake --build native/build-linux --config Release -j"$(nproc)"
else
    echo "    Python.h not found (sudo apt install python3-dev) — skipping; Python fallback is used"
fi

echo "==> [3/3] PyInstaller"
if ! "$PY" -c "import gi; gi.require_version('WebKit2','4.1')" >/dev/null 2>&1; then
    echo "    WARNING: WebKit2 4.1 typelib not found — the binary will open in the browser"
    echo "             instead of its own window. Fix: sudo apt install gir1.2-webkit2-4.1"
fi
"$PY" -m PyInstaller RAVEN.spec --noconfirm --clean
# PyInstaller's work dir is large and only needed during the build.
rm -rf build/RAVEN

echo
echo "Built: $HERE/dist/RAVEN/RAVEN  ($(du -sh dist/RAVEN | cut -f1))"
echo "Run it:   ./dist/RAVEN/RAVEN"
if [[ "${1:-}" == "--install" ]]; then
    packaging/linux/install.sh --binary
fi
