# Getting Started

Setting up a development environment. **No application code exists yet** — this
document is the contract for what the toolchain must be when it does.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| Rust | 1.85+ (2024 edition) | The core |
| Node.js | 22 LTS or newer | The frontend build |
| npm | 10+ | Package management |
| Git | 2.40+ | — |

Optional but recommended: `cargo-nextest` (faster test runs), `cargo-deny`,
`cargo-audit`, `cargo-fuzz`, and Docker for integration fixtures.

## Platform setup

### Linux

```bash
# Debian / Ubuntu
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev \
  libudev-dev pkg-config
```

```bash
# Arch / CachyOS
sudo pacman -S --needed webkit2gtk-4.1 base-devel curl wget file openssl \
  appmenu-gtk-module libappindicator-gtk3 librsvg xdotool
```

```bash
# Fedora
sudo dnf install webkit2gtk4.1-devel openssl-devel curl wget file \
  libappindicator-gtk3-devel librsvg2-devel systemd-devel
sudo dnf group install "c-development"
```

`libudev-dev` / `systemd-devel` is needed for FIDO2 hardware key support via
HID.

### Windows

- Visual Studio Build Tools with the C++ workload
- WebView2 runtime (present on Windows 11; installable on Windows 10)

### macOS

```bash
xcode-select --install
```

### Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup component add rustfmt clippy
```

## First build

```bash
git clone https://github.com/bbesli/Remoter.git
cd Remoter
npm install --prefix apps/desktop/ui
cargo build --workspace
npm run tauri dev
```

## The loop

```bash
cargo check --workspace --all-targets     # fastest feedback
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo test --workspace
```

Frontend, from `apps/desktop/ui`:

```bash
npm run dev          # Vite dev server alone
npm run typecheck
npm run lint
npm test
```

Full application:

```bash
npm run tauri dev    # hot reload for the frontend, rebuild for Rust changes
npm run tauri build  # release bundle for the current platform
```

## Integration fixtures

Protocol work needs real servers. `tests/fixtures/compose.yaml` provides them:

```bash
docker compose -f tests/fixtures/compose.yaml up -d
```

| Service | Port | Credentials |
|---|---|---|
| OpenSSH (`linuxserver/openssh-server`) | 2222 | `testuser` / `testpass` |
| SFTP (`atmoz/sftp`) | 2223 | `testuser` / `testpass` |
| xrdp | 3389 | `testuser` / `testpass` |
| TigerVNC | 5901 | password `testpass` |
| A second SSH host, for jump chain tests | 2224 | `testuser` / `testpass` |

```bash
cargo test --workspace --features integration-tests
```

These credentials are deliberately trivial and are for a throwaway container
network. **Never** point integration tests at a real host.

## Before opening a pull request

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
npm run typecheck --prefix apps/desktop/ui
npm run lint --prefix apps/desktop/ui
npm test --prefix apps/desktop/ui
```

If something fails and you cannot fix it, say so in the pull request rather than
leaving it to be discovered in review.

## Editor setup

**VS Code**: `rust-analyzer`, `Tauri`, `Even Better TOML`, `ESLint`, `Prettier`,
`Tailwind CSS IntelliSense`. A workspace configuration is committed in
`.vscode/`.

**JetBrains**: RustRover or IntelliJ with the Rust plugin.

Enable format-on-save for both languages. Formatting arguments waste review
time.

## Troubleshooting

**`webkit2gtk` not found (Linux).** Install the development package for your
distribution above. Note the `4.1` — Tauri v2 does not use 4.0.

**Blank window on Linux.** Usually a WebKitGTK compositing problem. Try
`WEBKIT_DISABLE_DMABUF_RENDERER=1 npm run tauri dev`. If that fixes it, hardware
acceleration is not working — worth reporting, because it directly affects
framebuffer rendering performance.

**FIDO2 device not detected (Linux).** The user needs udev rules for the
authenticator; most distributions ship `libfido2` udev rules in a package.

**Slow Rust builds.** Use `cargo check` during development, enable
`sccache`, and consider the `mold` linker on Linux.
