# Getting Started

Setting up a development environment. There is a full workspace here — ten
crates, a Tauri shell and a React frontend — and it builds and runs.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| Rust | 1.89+ (2024 edition) | The core |
| Node.js | 22 LTS or newer | The frontend build |
| npm | 10+ | Package management |
| Git | 2.40+ | — |

**1.89, not the 1.85 in `Cargo.toml`.** That line is knowingly stale and there is
a long comment above it explaining why correcting it belongs in its own change:
`ironrdp` 0.17 declares `rust-version = "1.89"` and `keyring` 4.2 declares
1.88, so nothing has built on 1.85 since the RDP adapter landed. Do not trust the
manifest over this table.

Optional but recommended: `cargo-nextest` (faster test runs), `cargo-deny`,
`cargo-audit` and `cargo-fuzz`. Docker is **not** needed — the live protocol
tests use a user-mode `sshd` instead (see below).

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

`libudev-dev` / `systemd-devel` is listed for FIDO2 hardware key support via HID.
That slot kind is not implemented and `ctap-hid-fido2` is not a dependency, so
the package is not needed for a build today — it is here so the list does not
have to change when it is.

### Windows

If you only want to *use* Remoter, none of this applies — take the installer
from a [release](https://github.com/bbesli/Remoter/releases) and skip to the
warning about SmartScreen in its notes. Everything below is for building from
source.

- **[Build Tools for Visual Studio 2022](https://aka.ms/vs/17/release/vs_BuildTools.exe)**,
  with the **Desktop development with C++** workload ticked. Rust links through
  the MSVC linker on Windows and cannot build anything without it.
- WebView2 runtime (present on Windows 11; installable on Windows 10)

Tick the workload, not just the individual compiler: a Visual Studio install
can carry `link.exe` without the C++ libraries beside it, and the failure comes
much later and says nothing useful —

```text
LINK : fatal error LNK1104: cannot open file 'msvcrt.lib'
```

The frontend will have built, several hundred crates will have downloaded, and
then every link step fails. Confirm the libraries exist before spending a build
on it:

```powershell
Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\lib\x64\msvcrt.lib" |
  Select-Object -First 3 FullName
```

A path means the toolchain is complete. Nothing printed means the workload is
missing, whatever the installer's summary said.

Prefer the released Build Tools over a Visual Studio preview or Insiders build:
Rust finds the toolchain through `vswhere` and expects the layout a released
install has. The two can sit side by side.

**WebView2.** Tauri v2 renders through the Edge WebView2 runtime rather than
bundling a browser, so it has to be on the machine. Windows 11 ships it.
Windows 10 may not have it, and the symptom is not an error — the window opens
and stays blank. Check, and install the Evergreen runtime if nothing comes back:

```powershell
Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application" -ErrorAction SilentlyContinue |
  Select-Object -First 1 Name
```

A version-numbered folder means the runtime is installed. Nothing printed means
it is not, and
[the Evergreen Standalone Installer](https://developer.microsoft.com/microsoft-edge/webview2/)
is the fix.

The installers a release publishes handle this themselves — `webviewInstallMode`
is `downloadBootstrapper`, so they fetch the runtime when it is missing. It is
only a development-machine concern.

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
cd apps/desktop && ./ui/node_modules/.bin/tauri dev
```

The Tauri CLI searches for `tauri.conf.json` in the directories **below** the
one it runs from, and this workspace keeps it in `apps/desktop/src-tauri`. So
the CLI runs from `apps/desktop`, while npm installed it under
`apps/desktop/ui/node_modules` — hence the two different paths on one line.
Running it from `apps/desktop/ui` fails with "Couldn't recognize the current
folder as a Tauri project", which is the same mistake with a confusing message.

On Windows, in PowerShell:

```powershell
cd apps\desktop; .\ui\node_modules\.bin\tauri.cmd dev
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

From `apps/desktop`, not from `apps/desktop/ui` — see **First build** above:

```bash
./ui/node_modules/.bin/tauri dev              # hot reload for the frontend
./ui/node_modules/.bin/tauri build            # installer for this platform
./ui/node_modules/.bin/tauri build --no-bundle  # the executable alone
```

The same three in PowerShell. Note the `.cmd` — npm installs two shims side by
side and PowerShell wants the Windows one — and, where two commands share a
line, the `;`, because `&&` is not a statement separator in Windows
PowerShell 5.1:

```powershell
cd apps\desktop
.\ui\node_modules\.bin\tauri.cmd dev
.\ui\node_modules\.bin\tauri.cmd build
.\ui\node_modules\.bin\tauri.cmd build --no-bundle
```

`tauri build` on Windows produces `Remoter_<version>_x64-setup.exe` and
`Remoter_<version>_x64_en-US.msi` under `target\release\bundle\`; on macOS,
`Remoter_<version>_<arch>.dmg`; on Linux, a `.deb`, an `.rpm` and an
`.AppImage`. Which of the seven configured bundle types a platform produces is
decided by the platform, not by the config — see
[Bundle configuration](build-release.md#bundle-configuration).

## Live protocol tests

Protocol work needs real servers. There is no `tests/fixtures/compose.yaml` and
no `tests/` directory — the Docker fixture set described in earlier drafts was
never built. What exists is a user-mode `sshd`:

```bash
scripts/dev-sshd.sh start      # 127.0.0.1:2222, throwaway keys in a temp dir
scripts/dev-sshd.sh info       # what a test needs to connect
scripts/dev-sshd.sh stop
```

`sshd` refuses to run as a non-root user only when it would have to change user,
and serving the invoking account is exactly what a test wants: real key exchange,
real authentication, a real SFTP subsystem. It starts faster than a container and
leaves nothing behind.

```bash
cargo test --workspace --features integration-tests
```

That covers the SSH and SFTP live tests. **RDP and VNC have no fixture.** RDP's
live test reads a server out of the environment and skips when it is absent —
`REMOTER_RDP_HOST`, `REMOTER_RDP_PORT`, `REMOTER_RDP_USER`,
`REMOTER_RDP_PASSWORD`, `REMOTER_RDP_NLA` — and VNC has no live test at all, only
a test that it never dials a socket of its own. **Never** point either at a host
you did not create for the purpose.

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

**VS Code**: `rust-analyzer`, `Tauri`, `Even Better TOML`, `ESLint`, `Prettier`.
No Tailwind extension — the frontend uses CSS modules. There is no committed
`.vscode/` workspace configuration.

**JetBrains**: RustRover or IntelliJ with the Rust plugin.

Enable format-on-save for both languages. Formatting arguments waste review
time.

## Troubleshooting

**`webkit2gtk` not found (Linux).** Install the development package for your
distribution above. Note the `4.1` — Tauri v2 does not use 4.0.

**Blank window on Linux.** Usually a WebKitGTK compositing problem. Try
`WEBKIT_DISABLE_DMABUF_RENDERER=1 ./ui/node_modules/.bin/tauri dev`. If that fixes it, hardware
acceleration is not working — worth reporting, because it directly affects
framebuffer rendering performance.

**`failed to run linuxdeploy` when building an AppImage (Arch, CachyOS, and
other distributions on current binutils).** `tauri build` reports only that one
line, because the bundler swallows linuxdeploy's stderr at the default log
level. Run it again with `--verbose` and the real error appears once per bundled
library:

```text
ERROR: Strip call failed: .../usr/bin/strip: .../libwebp.so.7:
  unknown type [0x13] section `.relr.dyn'
```

linuxdeploy carries its own `strip`, and it is old enough not to understand the
`DT_RELR` relative relocations that binutils 2.38 and glibc 2.36 onwards emit.
Nothing is wrong with the build — the packaging step cannot read the
distribution's own libraries. Skip the stripping:

```bash
NO_STRIP=1 ./ui/node_modules/.bin/tauri build
```

The AppImage comes out a little larger and otherwise identical; `.deb` and
`.rpm` are unaffected either way. CI does not hit this, because it builds on
Ubuntu 22.04, whose system libraries predate `DT_RELR`.

**FIDO2 device not detected (Linux).** Nothing detects one yet — the FIDO2 key
slot is unimplemented and every path that would use it returns
`Fido2Unsupported`. When it is built, the user will need udev rules for the
authenticator; most distributions ship `libfido2` udev rules in a package.

**Slow Rust builds.** Use `cargo check` during development, enable
`sccache`, and consider the `mold` linker on Linux.
