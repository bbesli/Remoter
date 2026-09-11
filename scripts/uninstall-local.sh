#!/usr/bin/env bash
# Remove the locally installed Remoter. Leaves your vaults untouched.
set -euo pipefail

pkill -TERM -x remoter-desktop 2>/dev/null || true
pkill -TERM -x remoter 2>/dev/null || true

rm -f "${HOME}/.local/bin/remoter"
rm -f "${HOME}/.local/share/applications/io.github.bbesli.remoter.desktop"
rm -f "${HOME}"/.local/share/icons/hicolor/*/apps/remoter.png
rm -f "${HOME}/.local/share/icons/hicolor/scalable/apps/remoter.svg"

echo "Removed. Your vault files and ${HOME}/.config/remoter were not touched."
