#!/usr/bin/env bash
# RAVEN Recon — installer for Kali Linux / Debian / Ubuntu (per user; only the apt step
# needs sudo, and it asks first).
#
#   ./install.sh                  desktop app + local web UI + terminal tools
#                                 (AI: add your Claude key in Settings, or connect your own
#                                 local model through Ollama — see docs/LOCAL_AI.md)
#   ./install.sh --yes            run the `sudo apt install` step without asking
#   ./install.sh --uninstall      remove the menu entry and commands (your data is kept)
#
# After installing:
#   raven-recon             desktop app (its own window)
#   raven-recon --browser   local web UI in your browser (http://127.0.0.1:<port>)
#   raven-sec               AI assistant in the terminal (add --claude to use Claude)
set -euo pipefail
HERE="$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)"
cd -- "$HERE"
BIN="${HOME}/.local/bin"
YES=0

for arg in "$@"; do
    case "$arg" in
        --yes|-y) YES=1 ;;
        --uninstall)
            bash packaging/linux/install.sh --uninstall || true
            rm -f -- "$BIN/raven-sec"
            echo "Removed the menu entry and the raven-recon / raven-sec commands."
            echo "Your data is kept in ${RAVEN_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/raven-recon}."
            exit 0 ;;
        -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg (see --help)"; exit 2 ;;
    esac
done

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# 1) System packages (Python venv, native window, command sandbox).
APT_PKGS=(python3 python3-venv python3-pip python3-gi gir1.2-webkit2-4.1 bubblewrap)
missing=()
if command -v dpkg >/dev/null 2>&1; then
    for p in "${APT_PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
fi
if ((${#missing[@]})); then
    say "Missing system packages: ${missing[*]}"
    answer=y
    if ((YES == 0)); then read -r -p "Run 'sudo apt install ${missing[*]}' now? [Y/n] " answer || answer=n; fi
    if [[ "${answer:-y}" =~ ^[Yy]?$ ]]; then
        sudo apt-get update && sudo apt-get install -y "${missing[@]}"
    else
        echo "Continuing without them: the app opens in your browser instead of its own window,"
        echo "and the AI agent's command sandbox stays disabled until bubblewrap is installed."
    fi
fi

python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 or newer is required"'

# 2) Python environment.
say "Creating the Python environment (.venv)"
[[ -x .venv/bin/python ]] || python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install --upgrade pip >/dev/null
.venv/bin/python -m pip install -r requirements-linux.txt

# 3) Menu entry + commands.
say "Adding the applications-menu entry and commands"
bash packaging/linux/install.sh
mkdir -p "$BIN"
ln -sfn "$HERE/raven-sec" "$BIN/raven-sec"
chmod +x raven-app raven-sec

cat <<EOF

RAVEN Recon is installed.

  raven-recon             desktop app (applications menu → "RAVEN Recon")
  raven-recon --browser   local web UI in your browser
  raven-sec               AI assistant in the terminal   (raven-sec --claude → Claude)

Data folder: ${RAVEN_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/raven-recon}
Use it only on targets you are authorised to test — see RESPONSIBLE_USE.md.
EOF
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo; echo "Note: add $BIN to your PATH (e.g. echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.zshrc)";;
esac
