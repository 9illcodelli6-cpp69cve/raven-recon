#!/usr/bin/env bash
# RAVEN Recon — per-user Linux install (no root needed).
#
# Adds a "RAVEN Recon" entry to the applications menu, a `raven-recon` command in
# ~/.local/bin, and the app icon. Nothing is written outside your home directory.
#
#   packaging/linux/install.sh                      menu entry runs the source tree (./raven-app)
#   packaging/linux/install.sh --binary             menu entry runs the packaged dist/RAVEN/RAVEN
#   packaging/linux/install.sh --import-data DIR    also copy old Windows RAVEN data
#                                                   (the folder that held RAVEN.exe) into the
#                                                   Linux data dir — never overwrites files
#   packaging/linux/install.sh --uninstall          remove menu entry, command and icon
#                                                   (your data folder is kept)
set -euo pipefail

PROJECT="$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/../.." && pwd)"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
DATA_DIR="${RAVEN_DATA_DIR:-$DATA_HOME/raven-recon}"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$DATA_HOME/applications"
ICON_DIR="$DATA_HOME/icons/hicolor/256x256/apps"
DESKTOP="$APP_DIR/raven-recon.desktop"

MODE="source"
IMPORT_DIR=""
UNINSTALL=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) MODE="binary" ;;
        --import-data) IMPORT_DIR="${2:?--import-data needs a directory}"; shift ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

refresh_menus() {
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$APP_DIR" || true
    command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t "$DATA_HOME/icons/hicolor" 2>/dev/null || true
}

if [[ $UNINSTALL -eq 1 ]]; then
    rm -f -- "$DESKTOP" "$ICON_DIR/raven-recon.png"
    [[ -L "$BIN_DIR/raven-recon" ]] && rm -f -- "$BIN_DIR/raven-recon"
    refresh_menus
    echo "Removed menu entry, icon and command. Data kept in: $DATA_DIR"
    exit 0
fi

if [[ "$MODE" == "binary" ]]; then
    TARGET="$PROJECT/dist/RAVEN/RAVEN"
    [[ -x "$TARGET" ]] || { echo "Packaged binary not found: $TARGET  (run ./build-linux.sh first)" >&2; exit 1; }
    WMCLASS="raven-recon"
else
    TARGET="$PROJECT/raven-app"
    chmod +x "$TARGET"
    WMCLASS="raven-recon"
fi

mkdir -p -- "$BIN_DIR" "$APP_DIR" "$ICON_DIR" "$DATA_DIR"
chmod 700 "$DATA_DIR" 2>/dev/null || true

ln -sfn -- "$TARGET" "$BIN_DIR/raven-recon"
install -m 644 "$PROJECT/packaging/linux/raven-recon.png" "$ICON_DIR/raven-recon.png"

# Desktop Exec value for one program path, per the Desktop Entry spec:
#   1. quote it as a single argument; inside the double quotes escape " ` $ \ ;
#   2. write a literal % as %% (field codes);
#   3. apply the string-value escapes, which a reader undoes BEFORE unquoting:
#      \ -> \\ (so a literal $ ends up as \\$ and a literal \ as \\\\),
#      newline/tab/CR -> \n \t \r.
# Built with printf/case, never sed, so & | \ etc. in the path are not special.
desktop_exec_quote() {
    local s="$1" quoted="" out="" ch i
    for (( i = 0; i < ${#s}; i++ )); do
        ch="${s:i:1}"
        case "$ch" in
            '"'|'`'|'$'|'\') quoted+="\\$ch" ;;
            '%') quoted+="%%" ;;
            *) quoted+="$ch" ;;
        esac
    done
    quoted="\"$quoted\""
    for (( i = 0; i < ${#quoted}; i++ )); do
        ch="${quoted:i:1}"
        case "$ch" in
            '\') out+='\\' ;;
            $'\n') out+='\n' ;;
            $'\t') out+='\t' ;;
            $'\r') out+='\r' ;;
            *) out+="$ch" ;;
        esac
    done
    printf '%s' "$out"
}

# Fill the template line by line with printf (no sed: a project path containing
# & | \ " $ % or spaces is written verbatim-escaped, never reinterpreted).
EXEC_VALUE="$(desktop_exec_quote "$TARGET")"
{
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == *@EXEC@* ]]; then
            printf '%s%s%s\n' "${line%%@EXEC@*}" "$EXEC_VALUE" "${line#*@EXEC@}"
        elif [[ "$line" == *@WMCLASS@* ]]; then
            printf '%s%s%s\n' "${line%%@WMCLASS@*}" "$WMCLASS" "${line#*@WMCLASS@}"
        else
            printf '%s\n' "$line"
        fi
    done < "$PROJECT/packaging/linux/raven-recon.desktop.in"
} > "$DESKTOP"
chmod 644 "$DESKTOP"
refresh_menus

if [[ -n "$IMPORT_DIR" ]]; then
    [[ -d "$IMPORT_DIR" ]] || { echo "No such directory: $IMPORT_DIR" >&2; exit 1; }
    copied=0
    for item in workspaces workspaces_v7.db tasks_v7.db programs_v7.db submissions_v7.db \
                knowledge_v7.db evidence_v7.db conversations.db \
                active-settings.json active-workspace.json; do
        if [[ -e "$IMPORT_DIR/$item" ]]; then
            # -n: never overwrite anything already in the Linux data folder.
            cp -rn -- "$IMPORT_DIR/$item" "$DATA_DIR/" && copied=$((copied + 1))
        fi
    done
    echo "Imported $copied item(s) from $IMPORT_DIR into $DATA_DIR (existing files kept)."
fi

echo "Installed RAVEN Recon ($MODE):"
echo "  menu entry : $DESKTOP"
echo "  command    : $BIN_DIR/raven-recon -> $TARGET"
echo "  data       : $DATA_DIR"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "  note: add $BIN_DIR to PATH to use the raven-recon command" ;; esac
if [[ "$MODE" == "source" ]] && ! python3 -c "import gi; gi.require_version('WebKit2','4.1')" >/dev/null 2>&1; then
    echo "  note: for the native window run:  sudo apt install gir1.2-webkit2-4.1"
    echo "        (until then RAVEN opens in your default browser)"
fi
