# Build and Release

## CI matrix

| Job | Runner | Does |
|---|---|---|
| `check` | ubuntu-latest | `cargo check`, `clippy -D warnings`, `fmt --check` |
| `test-linux` | ubuntu-latest | Unit + integration, Docker fixtures |
| `test-windows` | windows-latest | Unit + integration |
| `test-macos` | macos-latest | Unit + integration |
| `frontend` | ubuntu-latest | `typecheck`, `lint`, `test`, `build` |
| `security` | ubuntu-latest | `cargo audit`, `cargo deny`, `gitleaks` |
| `fuzz` | ubuntu-latest | Nightly, 15 minutes per target |
| `build` | matrix | Release bundles for every target |
| `e2e` | matrix | WebDriver against the built app |

Pull requests run everything except `fuzz` and `build`. `main` runs everything.

## Targets

| Platform | Architecture | Artefacts |
|---|---|---|
| Linux | `x86_64-unknown-linux-gnu` | AppImage, `.deb`, `.rpm` |
| Linux | `aarch64-unknown-linux-gnu` | AppImage, `.deb`, `.rpm` |
| Windows | `x86_64-pc-windows-msvc` | `.msi`, NSIS `.exe`, portable `.zip` |
| Windows | `aarch64-pc-windows-msvc` | `.msi`, NSIS `.exe` |
| macOS | `universal-apple-darwin` | `.dmg`, `.app` |

Flatpak and a Windows Store package are planned once the release process is
settled.

Minimum supported platforms: glibc 2.35 with WebKitGTK 2.38 (Ubuntu 22.04 and
equivalents), Windows 10 1809, macOS 12.

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

Every release publishes an SBOM (CycloneDX) and SHA-256 checksums.

**None of this is in place yet**, which is why the in-app update check opens a
release page instead of installing anything. See [Updates](#updates) for the
order the two land in.

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
2. Bump versions in `Cargo.toml` and `tauri.conf.json`
3. Tag `vX.Y.Z`
4. CI builds, signs, generates the SBOM and publishes a draft release
5. Manually verify: install each artefact on a clean machine, create a vault,
   connect a session
6. Publish. The GitHub release itself is what the in-app check reads and what
   its button opens, so the tag, the title and the notes are user-facing text —
   write them for somebody deciding whether to upgrade. There is no updater
   manifest yet; see below.

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
