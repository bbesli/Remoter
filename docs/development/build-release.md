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
panic = "abort"

# For release builds we ship symbols separately rather than in the binary.
[profile.release-debug]
inherits = "release"
strip = false
debug = true
```

`panic = "abort"` deserves a note: session tasks are wrapped in `catch_unwind`
at the supervisor boundary, which `abort` disables. The decision is therefore
deliberate — with `abort`, a decoder panic terminates the process rather than
one tab. Before v1.0 we will measure whether `unwind` costs enough to matter; if
not, `unwind` is the better choice for a tool where losing every session to one
malformed frame is a worse outcome than a slightly larger binary.

`OPEN:` Resolve this before v1.0 and record the decision here.

## Signing

| Platform | Method |
|---|---|
| Windows | Authenticode, with a certificate held in the project's secrets |
| macOS | Developer ID, plus notarisation and stapling |
| Linux | GPG-signed release artefacts and checksums; AppImage signed |

Unsigned builds show OS warnings that train users to click through security
prompts. Signing is a security feature, not a polish item.

Every release publishes an SBOM (CycloneDX) and SHA-256 checksums.

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
6. Publish; the updater manifest is updated in the same step

## Updates

Tauri's updater with signed manifests. It is **opt-in**, checks a static
manifest, and never downloads anything without asking.

The application does not phone home. There is no telemetry, no usage reporting,
and no crash upload. Crash reports are written locally and the user chooses
whether to attach one to an issue — which means they can read it first, which
matters when the process holds credentials.

`OPEN:` Whether to ship a Linux distribution repository (APT/RPM) or rely on
AppImage and Flathub. A repository is better for users and more work to
maintain; decide before v1.0.
