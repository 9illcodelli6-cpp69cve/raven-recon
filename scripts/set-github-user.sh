#!/usr/bin/env bash
# Put your GitHub username into the README, installers, workflows and policy files
# (they ship with the placeholder YOUR_GITHUB_USER).
#   scripts/set-github-user.sh <github-username>
set -euo pipefail
u="${1:-}"
if ! [[ "$u" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]]; then
    echo "usage: $0 <github-username>"; exit 2
fi
cd -- "$(dirname -- "$0")/.."
mapfile -t files < <(grep -rlI --exclude-dir=.git --exclude-dir=.venv --exclude=set-github-user.sh "YOUR_GITHUB_USER" . || true)
if ((${#files[@]} == 0)); then echo "Nothing to replace."; exit 0; fi
sed -i "s/YOUR_GITHUB_USER/${u}/g" "${files[@]}"
printf 'Updated %d files:\n' "${#files[@]}"; printf '  %s\n' "${files[@]}"
