# Build and Release

## CI matrix

`.github/workflows/ci.yml`, on every pull request and every push to `main`:

| Job | Runner | Does |
|---|---|---|
| `check` | ubuntu-latest | Each crate on its own without test targets, every feature-gated target, `fmt --check`, `clippy -D warnings` |
| `test` | ubuntu-latest, windows-latest, macos-latest | `cargo test --locked --workspace --no-fail-fast` |
| `frontend` | ubuntu-latest, windows-latest, macos-latest | `npm ci`, `npm run build`, `vitest`; `typecheck` and `lint` on Linux only |
| `release-packaging` | ubuntu-latest | `.github/scripts/release-packaging-selftest.sh`: the release workflow's packaging path, against a fake bundle tree |
| `security` | ubuntu-latest | `cargo deny`, `cargo audit`, advisory-exception expiry, wildcard scan, `gitleaks` |
| `plugin-licence` | ubuntu-latest | No copyleft under `remoter-plugin-abi` or `-sdk` (ADR-0009) |

Everything runs on every pull request; nothing is deferred to `main`.

The split between what fans out and what does not is deliberate. `clippy`,
`rustfmt`, licence policy and the plugin ABI boundary are questions about the
source, and the source is the same on all three platforms — asking them three
times costs runner minutes and answers nothing. `cargo test` and the frontend
build are questions about the *machine*, and the answers differ: this workspace
carries a `cfg(windows)` dependency on `winreg` in `remoter-proto-rdp`, a
credential backend per platform in `remoter-vault`, and `cfg(unix)` arms in
`remoter-ipc` and `remoter-proto-ssh` whose Windows counterparts nothing had
ever compiled. `npm ci` resolves the per-platform native binaries that rollup
and esbuild ship as optional dependencies, which a Linux-only install never
fetches.

Until the matrix above, every job in this file ran on `ubuntu-latest`: nothing
in the repository had ever been compiled for Windows or macOS by anything but
the owner's own machine. Treat the first few runs on those two as a source of
findings rather than as a gate.

**Not built yet, despite being worth building:** a scheduled `fuzz` job over the
targets in `fuzz/`, an `e2e` job driving the built application through WebDriver,
and a Docker-fixture integration run (`tests/fixtures/compose.yaml` does not
exist; `scripts/dev-sshd.sh` is what there is). Do not read them into the table
above.

## Targets

What the release workflow actually produces, one job per row:

| Platform | Runner | Architecture | Artefacts |
|---|---|---|---|
| Linux | ubuntu-22.04 | `x86_64-unknown-linux-gnu` | `.AppImage`, `.deb`, `.rpm` |
| Windows | windows-latest | `x86_64-pc-windows-msvc` | `.msi`, NSIS `-setup.exe` |
| macOS | macos-latest | `universal-apple-darwin` | `.dmg` |

The Linux job is pinned to `ubuntu-22.04` rather than `ubuntu-latest`. The build
host sets the glibc floor for everyone who downloads the result, and
`ubuntu-latest` is 24.04 with glibc 2.39 — a binary from it refuses to start on
Ubuntu 22.04, which is the oldest release named below. Pinning is what makes the
floor a fact rather than a claim.

macOS builds `universal-apple-darwin`, not the runner's native architecture.
`macos-latest` is Apple silicon, so a plain build there would serve Apple
silicon and leave Intel Macs with nothing. The universal binary is two
compilations fused into one file, so the job installs both Rust targets first
and its output lands under `target/universal-apple-darwin/release/bundle` rather
than `target/release/bundle`.

That path is not a property of macOS; it is a consequence of the `--target`
flag, and the two have to be edited together. The matrix row carries
`target: universal-apple-darwin`, the build step expands that into
`--target universal-apple-darwin`, and the bundle then lands under the triple.
Drop the flag and the bundle is back at `target/release/bundle` while the
matrix still points at the triple, so the check finds nothing and the tag ships
no `.dmg`. `release-packaging` asserts the pair agrees on every push: a row with
a `target` must name `target/<triple>/release/bundle`, a row without one must
name `target/release/bundle`, and the build step must take the flag from
`matrix.target` rather than from a hard-coded triple.

The evidence for the triple being pushed verbatim, including for
`universal-apple-darwin`, is `@tauri-apps/cli`'s own binary: its strings place
the universal build in `crates/tauri-cli/src/interface/rust/desktop.rs`, next to
`aarch64-apple-darwin`, `x86_64-apple-darwin` and the `lipo` invocation that
fuses them, with no separate directory name of its own — the universal build is
two ordinary builds plus a `lipo -create -output` into that one directory, and
the bundler writes `bundle/<type>` beneath it.

**This path has never been run.** There is no macOS machine on this project and
the release workflow only fires on a tag, so the first tag is where the macOS
row is tested for real. If the path is wrong, `collect-installers.sh` fails
naming it and pointing at the `--target` flag, rather than the upload silently
attaching nothing.

A `.app` is produced on macOS and left in `bundle/macos` for local builds, but
only the `.dmg` is attached to a release: the `.dmg` already contains the `.app`,
and a bundle is a directory, which is not something a release asset can be
without being zipped first.

**Not built:** `aarch64-unknown-linux-gnu`, `aarch64-pc-windows-msvc`, and the
portable Windows `.zip`. Flatpak and a Windows Store package are still planned
once the release process has been through a few real runs.

Minimum supported platforms: glibc 2.35 with WebKitGTK 2.38 (Ubuntu 22.04 and
equivalents), Windows 10 1809, macOS 12.

## Bundle configuration

One `bundle.targets` list in `apps/desktop/src-tauri/tauri.conf.json` names all
seven bundle types, and each platform gets the subset that belongs to it. That
is not sloppiness: `tauri-bundler` intersects the configured list with the
types the host platform can produce and silently drops the rest, so `msi` in the
list is a no-op on Linux and `deb` is a no-op on Windows. One list therefore
serves three platforms, and the Linux artefacts keep working unchanged.

The cost of "silently" is that a platform can produce nothing without failing,
which is why the release workflow names what each platform owes — the
`expected` column of its matrix — and asserts the artefact *files* by glob
before uploading. Counting entries in the bundle directory was the earlier
version of that check and was not the same question: `bundle/deb/` holds
tauri's staging tree beside the `.deb`, so a directory with the staging tree
and no package in it scored one entry and passed. The check lives in
`.github/scripts/collect-installers.sh`, which also gathers what it found into
one flat staging directory, and the `release-packaging` job in the CI table
above runs it on every push against a fake bundle tree.

Three platform-specific settings are worth explaining, because each is a
decision rather than a default that happened:

**`bundle.windows.webviewInstallMode` is `downloadBootstrapper`, silent.**
Tauri v2 on Windows renders through the Edge WebView2 runtime. It is part of
Windows 11; on Windows 10 it may be absent, and without it the application
starts and shows nothing. Of the five modes, `skip` leaves those users with a
blank window and no explanation, `offlineInstaller` embeds the whole runtime and
adds about 127 MB to every download for every user including the Windows 11
majority who already have it, and `fixedRuntime` pins a private copy that never
gets security updates — an unreviewed browser engine inside a credential
manager. `embedBootstrapper` still needs the network to fetch the runtime, so
its extra 1.8 MB on every download buys nothing the default does not already
give. `downloadBootstrapper` installs the runtime only where
it is missing, at the cost of needing the machine online during installation,
which the release notes state plainly.

**`bundle.windows.nsis.installMode` is `currentUser`.** A per-user install needs
no administrator prompt. The user is already being asked to click past
SmartScreen on an unsigned binary; adding a UAC elevation to the same minute is
how people learn to approve things without reading them.

**`bundle.macOS.minimumSystemVersion` is `12.0`**, matching the minimum this
document promises. Tauri's own default is `10.13`, which would produce a bundle
claiming to support ten macOS releases nobody has tested it on.

`bundle.publisher` is set explicitly. Left unset, Tauri derives it from the
second element of the bundle identifier, which for `io.github.bbesli.remoter`
would list the publisher as "github" in Add/Remove Programs.

## Build profiles

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = true
panic = "unwind"        # deliberate — see ADR-0011

# For release builds we ship symbols separately rather than in the binary.
[profile.release-debug]
inherits = "release"
strip = false
debug = true
```

`panic = "unwind"` is deliberate and is settled by
[ADR-0011](../architecture/decisions/0011-panic-strategy.md). `abort` would buy
roughly 5–10 % smaller binaries and cost every open session whenever one
protocol decoder hit a bug on a malformed frame. Twenty sessions, two tunnels
and an in-flight transfer against a few megabytes of binary is not a close call.

Each session runs as its own `tokio::spawn`ed task, so a panic surfaces as
`JoinError::is_panic()` rather than propagating — no `catch_unwind` is needed or
used. A panicked session is **destroyed, never resumed**: its state is discarded
whole, which is what answers the legitimate objection that continuing past a
panic can mask corruption. A panic anywhere outside a session task is treated as
fatal, because those components have no isolation boundary.

## Signing

| Platform | Method |
|---|---|
| Windows | Authenticode, with a certificate held in the project's secrets |
| macOS | Developer ID, plus notarisation and stapling |
| Linux | GPG-signed release artefacts and checksums; AppImage signed |

Unsigned builds show OS warnings that train users to click through security
prompts. Signing is a security feature, not a polish item.

**None of this is in place yet.** There is no Authenticode certificate and no
Apple Developer ID, both of which cost money annually that this project does not
have. It is also why the in-app update check opens a release page instead of
installing anything — see [Updates](#updates) for the order the two land in.

What ships instead is `SHA256SUMS.txt`, generated in the release job over every
attached artefact. A checksum proves the download arrived intact; it proves
nothing about who produced it, and the release notes say so in those words
rather than implying otherwise. (An SBOM is not generated yet either. The table
above and this paragraph are the whole of the truth.)

Because the builds are unsigned, **both Windows and macOS will stop the user on
first run**, and an unexplained security warning on a credential manager reads
as malware. `.github/release-notes-template.md` is the body of every draft
release and carries the click-by-click instructions: More info → Run anyway for
SmartScreen; System Settings → Privacy & Security → Open Anyway on macOS 15 and
newer, Control-click → Open on macOS 12 to 14. That text is a release artefact
in its own right. Edit it when the dialogs change, and do not remove it before
the certificates exist.

## Versioning

Semantic versioning. Before 1.0, the minor version carries breaking changes.

Two version numbers matter and change independently:

| Version | Changes when |
|---|---|
| Application | Every release |
| **Vault format** | The on-disk format changes — rarely, deliberately |
| **Plugin ABI** | The plugin interface changes |

A vault written by a newer format version is refused by an older binary, with a
clear message rather than a parse attempt.

## Release process

1. Update `CHANGELOG.md` — user-facing changes, in the user's language, not
   commit subjects
2. Bump versions in `Cargo.toml` and `tauri.conf.json`. Both, and to the same
   number: the release workflow's first job compares them against the tag and
   refuses to spend three platform builds producing artefacts labelled with a
   version nobody asked for
3. Tag `vX.Y.Z` and push the tag. That is the trigger —
   `.github/workflows/release.yml` runs on `v[0-9]+.[0-9]+.[0-9]+*` and on
   nothing else
4. The workflow builds on all three platforms, checks that each produced every
   bundle it owes, gathers the artefacts, writes `SHA256SUMS.txt` over them, and
   opens a **draft** release whose body is
   `.github/release-notes-template.md` with the version substituted
5. Replace the notes' "What changed" section with this version's entries from
   `CHANGELOG.md`. Leave the rest: the SmartScreen and Gatekeeper instructions
   apply to every unsigned release and the person hitting them has no other
   source for the answer
6. Manually verify: install each artefact on a clean machine, create a vault,
   connect a session. The draft exists so that this step has somewhere to
   happen. A release that published itself would remove the only gate an
   unsigned build has
7. Publish. The GitHub release itself is what the in-app check reads and what
   its button opens, so the tag, the title and the notes are user-facing text —
   write them for somebody deciding whether to upgrade. There is no updater
   manifest yet; see below

The tag pattern ends in `*`, so a pre-release tag triggers the same workflow —
and a release candidate is the cheapest way to find out whether the Windows and
macOS halves of this process work, neither of which has been run for real yet.
Two constraints on the suffix, both worth knowing before spending a tag on it:

- The preflight job compares the tag to both manifests **exactly**, suffix
  included. `v0.2.0-1` needs `version = "0.2.0-1"` in `Cargo.toml` and
  `"version": "0.2.0-1"` in `tauri.conf.json`.
- The MSI bundler accepts only a **numeric** pre-release identifier, no greater
  than 65535 — because Windows Installer's `ProductVersion` has nowhere to put
  anything else. `v0.2.0-1` builds; `v0.2.0-rc1` fails the Windows job with
  "optional pre-release identifier in app version must be numeric-only".

## Updates

### What the check does today

It checks. It does not install. Those are two features, and only the first one
is built.

- **Opt-in, off by default.** `updateCheckEnabled` starts `false` and nothing
  is contacted until the user turns it on or presses **Check now**. The manual
  check works whether or not the automatic one is on: pressing a button is the
  user asking directly, which is not the same thing as standing permission.
- **It reads `GET /repos/bbesli/Remoter/releases`** on `api.github.com` — the
  public release list, no token, no authentication.
- **It sends one thing: `User-Agent: Remoter/<version>`.** No identifier, no
  locale, no machine name, no usage data, no cookies. The request is made from
  the Rust core (`update_check` in `remoter-ipc`) and not from the webview,
  precisely so that this list is the whole list — a `fetch` from the webview
  would carry the engine's own user-agent, `Accept-Language` and `Origin`, and
  the promise printed on the Updates screen would stop being true.
- **The comparison is real semver.** `apps/desktop/ui/src/features/settings/version.ts`
  implements SemVer 2.0.0 §11, including the pre-release ordering, and is
  tested against the specification's own example ladder. Pre-releases are
  ignored unless the running build is itself a pre-release.
- **The last check is recorded** in the settings file (`updateLastCheckedAt`),
  whether or not anything newer was found, and the automatic check runs at most
  once a day.
- **Every failure has its own sentence.** Unreachable, rate-limited, no release
  list, unreadable answer and "GitHub returned an error" are separate `IpcError`
  codes with separate messages and separate suggested actions. A check that
  fails vaguely teaches people to stop believing it, which is worse than not
  having one.
- **A newer release shows its version, its notes and a button** that opens the
  release page in the system browser through the opener plugin. The URL is
  built by the core from the tag, never taken from the response: the address is
  handed to the desktop's browser, and a `javascript:` or `file://` URL in a
  field the network controls would turn an update check into a way to open
  anything.
- **Release notes are untrusted remote text** and render as text, never as
  markup.

The client is `ureq` over `rustls`, added to `remoter-ipc` for this one request.
It is blocking and runs on the blocking pool: one request a day does not justify
an async TLS stack, and `reqwest`'s rustls feature would pull `aws-lc-rs` — a
second, C, cryptographic implementation into a process that already has one.
`ring`, which `rustls` uses here, was already in the tree.

TLS is verified against the bundled Mozilla root store (`webpki-roots`) rather
than the machine's. A TLS-inspecting proxy therefore fails the check rather than
silently answering it, which is the right way round for a process that holds
credentials: the honest outcome is "could not reach github.com", not a release
list from an intermediary.

### What it deliberately does not do

Remoter does not install updates. Tauri's updater downloads an artefact and
runs it, which is only safe if the artefact's signature can be verified — and
releases are not signed yet. Shipping self-update first would mean a credential
manager downloading and executing an unsigned binary, which is the exact
behaviour this application exists to argue against.

### The order

1. **Signing.** Authenticode on Windows, Developer ID with notarisation and
   stapling on macOS, GPG-signed artefacts and checksums on Linux — the table
   above, actually in place in CI.
2. **A signed updater manifest**, published as part of the release job, with
   the updater's public key baked into the binary.
3. **Self-update**, opt-in and separate from the check: it stays possible to
   have the check without the installer, because some people will always
   prefer to install by hand.

Nothing in step 3 starts before step 1 is done. That is the whole reason the
Updates screen says, in one line next to the button, that Remoter does not
install updates itself and why.

### It does not phone home

There is no telemetry, no usage reporting and no crash upload, at any setting.
Crash reports are written locally and the user chooses whether to attach one to
an issue — which means they can read it first, and that matters when the process
holds credentials.

The update check is the only outbound request the application makes that is not
a session the user opened, and it is the only one there will be. If a future
change would add a second, it needs an ADR, not a patch.

**Linux distribution.** v1.0 ships AppImage, `.deb` and `.rpm` as direct
downloads, plus Flathub. A hosted APT/RPM repository is better for users and a
standing maintenance commitment; it is deferred until there is someone willing
to own it, rather than started and left to rot. Downstream packaging by
distribution maintainers is welcomed and supported.
