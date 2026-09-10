#!/usr/bin/env bash
#
# Build Remoter and install it for the current user, replacing any running
# instance. This is the fast iteration path: `tauri build --no-bundle` produces
# a real production binary with the frontend embedded, and skips AppImage/deb/rpm
# packaging, which adds a minute and buys nothing while developing.
#
# Note: plain `cargo build --release` does NOT work here. tauri-build decides
# between a development and a production build from DEP_TAURI_DEV, which the
# Tauri CLI sets — not from the cargo profile. Building with cargo directly
# produces a binary that still points at the dev server and fails at launch with
# "Could not connect to localhost".
#
#   scripts/install-local.sh              build, install, launch
#   scripts/install-local.sh --no-launch  build and install only
#   scripts/install-local.sh --bundle     also produce AppImage/deb/rpm
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_NAME="remoter-desktop"
INSTALL_BIN="${HOME}/.local/bin/remoter"
DESKTOP_FILE="${HOME}/.local/share/applications/io.github.bbesli.remoter.desktop"
ICON_DIR="${HOME}/.local/share/icons/hicolor"

LAUNCH=1
BUNDLE=0
for arg in "$@"; do
  case "$arg" in
    --no-launch) LAUNCH=0 ;;
    --bundle)    BUNDLE=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n\033[36m==>\033[0m %s\n' "$1"; }

# ---------------------------------------------------------------- build ----

TAURI="${REPO}/apps/desktop/ui/node_modules/.bin/tauri"
[[ -x "$TAURI" ]] || { echo "Tauri CLI missing. Run: npm install --prefix ${REPO}/apps/desktop/ui" >&2; exit 1; }

# `tauri build` runs beforeBuildCommand, which builds the frontend.
if [[ "$BUNDLE" == "1" ]]; then
  say "Building the application and its packages (release)"
  ( cd "${REPO}/apps/desktop" && "$TAURI" build )
else
  say "Building the application (release, no packaging)"
  ( cd "${REPO}/apps/desktop" && "$TAURI" build --no-bundle )
fi

BUILT="${REPO}/target/release/${BIN_NAME}"
[[ -x "$BUILT" ]] || { echo "build produced no binary at ${BUILT}" >&2; exit 1; }

# --------------------------------------------------------------- replace ----

if pgrep -x remoter >/dev/null 2>&1 || pgrep -x "$BIN_NAME" >/dev/null 2>&1; then
  say "Closing the running instance"
  pkill -TERM -x "$BIN_NAME" 2>/dev/null || true
  pkill -TERM -x remoter 2>/dev/null || true
  for _ in $(seq 1 20); do
    pgrep -x "$BIN_NAME" >/dev/null 2>&1 || pgrep -x remoter >/dev/null 2>&1 || break
    sleep 0.25
  done
  pkill -KILL -x "$BIN_NAME" 2>/dev/null || true
  pkill -KILL -x remoter 2>/dev/null || true
fi

# --------------------------------------------------------------- install ----

say "Installing to ${INSTALL_BIN}"
install -Dm755 "$BUILT" "$INSTALL_BIN"

for size in 32 64 128; do
  src="${REPO}/apps/desktop/src-tauri/icons/${size}x${size}.png"
  [[ -f "$src" ]] && install -Dm644 "$src" "${ICON_DIR}/${size}x${size}/apps/remoter.png"
done
install -Dm644 "${REPO}/brand/main-logo.svg" \
  "${ICON_DIR}/scalable/apps/remoter.svg"

install -Dm644 /dev/stdin "$DESKTOP_FILE" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Remoter
GenericName=Remote Connection Manager
Comment=RDP, SSH, VNC and SFTP sessions with an encrypted credential vault
Exec=${INSTALL_BIN}
Icon=remoter
Terminal=false
Categories=Utility;Network;RemoteAccess;
Keywords=ssh;rdp;vnc;sftp;remote;terminal;server;
StartupWMClass=Remoter
DESKTOP

command -v update-desktop-database >/dev/null 2>&1 \
  && update-desktop-database "${HOME}/.local/share/applications" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null 2>&1 \
  && gtk-update-icon-cache -f -t "$ICON_DIR" 2>/dev/null || true

say "Installed $(du -h "$INSTALL_BIN" | cut -f1) binary to ${INSTALL_BIN}"

# Guard against the failure this script used to cause: a binary built without
# the Tauri CLI embeds no frontend, points at the dev server, and shows
# "Could not connect to localhost" on screen. Catch it here instead.
#
# The asset *contents* are brotli-compressed and unsearchable, but the asset
# *keys* are stored as plain strings, so counting those is a reliable signal.
embedded=$(strings "$INSTALL_BIN" 2>/dev/null | grep -cE '^/(index\.html|assets/)' || true)
if [[ "${embedded:-0}" -lt 2 ]]; then
  echo "The frontend is not embedded in this binary — it would try the dev server." >&2
  echo "Build with the Tauri CLI, not 'cargo build --release'." >&2
  exit 1
fi

if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
  printf '\033[33mNote:\033[0m %s is not on your PATH. Add it, or launch from your application menu.\n' \
    "${HOME}/.local/bin"
fi

# ---------------------------------------------------------------- launch ----

if [[ "$LAUNCH" == "1" ]]; then
  say "Launching"
  ( setsid "$INSTALL_BIN" >/dev/null 2>&1 & ) || true
  sleep 2
  # The installed binary is named `remoter`; "$BIN_NAME" is the cargo target,
  # which is what the *uninstalled* build is called. Check both.
  if pgrep -x remoter >/dev/null 2>&1 || pgrep -x "$BIN_NAME" >/dev/null 2>&1; then
    echo "Remoter is running."
  else
    echo "Remoter did not stay running. Start it in a terminal to see why:"
    echo "  REMOTER_LOG=debug ${INSTALL_BIN}"
    exit 1
  fi
fi
