# Remoter — Agent Working Guide

Operating instructions for AI coding agents working in this repository. Read this
before touching anything. Human contributors should read
[CONTRIBUTING.md](CONTRIBUTING.md) instead — it says the same things without the
machine-facing detail.

---

## 0. Non-negotiables

These rules override convenience, speed and personal preference.

1. **Never write an AI attribution anywhere.** No `Co-Authored-By` trailers
   naming an AI, no "generated with" footers in commits, pull requests, issues,
   code comments, changelogs or documentation. Commits are authored by the
   repository owner. This is a hard requirement, not a style preference.
2. **Never log, print, serialise or trace a secret.** Passwords, private keys,
   passphrases, key material, session tokens and vault keys must never reach
   stdout, a log file, an error message, a panic payload or a telemetry event.
   Wrap them in the `Secret<T>` newtype (see §5) which has a redacting `Debug`.
3. **Never weaken the cryptographic design to make a test pass.** If a KDF cost,
   a nonce policy or an authentication tag is inconvenient, change the test or
   raise the design question — not the parameter.
4. **Never invent a protocol implementation.** RDP, SSH, VNC and SFTP are
   specified formats. Cite the RFC/MS-* document section in a comment when
   implementing a wire-level detail.
5. **Do not add a dependency without checking its licence** against GPL-3.0
   compatibility and recording it in `deny.toml`. See §8.
6. **Never resume a panicked session.** Discard its state whole. See §5.
7. **`remoter-plugin-abi` and `remoter-plugin-sdk` must stay free of GPL
   dependencies.** They are Apache-2.0 OR MIT so that plugin authors compile
   against nothing copyleft; a GPL dependency there silently breaks the licence
   exception in `LICENSE-EXCEPTION`. CI enforces it, but do not rely on CI to
   catch what you already know.

---

## 1. What this project is

A cross-platform remote connection manager: an encrypted vault of servers and
credentials, plus embedded RDP / SSH / VNC / SFTP sessions in a tabbed desktop
application. Comparable to mRemoteNG and Royal TS. Licensed GPL-3.0.

**Current state: alpha, and it runs.** There is a Cargo workspace, a React
frontend and a Tauri shell. The vault, the connection tree, SSH, SFTP, RDP, VNC,
port forwarding, three importers, the audit log and ten localisations are
implemented and have been used against real servers.

What is **not** implemented, so that you do not go looking for it: session
recording of any kind, the FIDO2 key slot, FTP, the plugin host, the encrypted
`.rmtr` archive, the clipboard, and tab detach or split view. `docs/` is a specification
that describes the finished product, so it describes more than exists —
[README.md](README.md#what-works-today) carries the shipped-versus-planned
table, and §3 below is the tree as it actually is.

---

## 2. Where the truth lives

Design documents are normative **about design** — the shape of the vault format,
what a nonce is bound to, which layer owns which decision. Code that contradicts
them on any of that is a bug in the code, unless the document has been amended
first.

They are **not** a statement of what exists. Every document in `docs/` describes
the finished product, and much of the finished product is not written; every
file in `docs/features/` and `docs/architecture/` opens with a note saying which
part of it ships — thirteen files, the ADRs under `decisions/` excluded — and
individual claims carry ✅ / ◐ / ⏳ markers. So a document describing a
feature is never evidence that the feature is there — grep for it before you
build on it, and if you find it missing, say so rather than assuming you have
looked in the wrong place. `README.md`'s *What works today* table and
`docs/roadmap.md` are where shipped-versus-planned is recorded, and both must be
updated when that changes.

| Question | Authoritative document |
|---|---|
| Why is the stack what it is? | `docs/architecture/decisions/0001-technology-stack.md` |
| How is the vault encrypted? | `docs/security/vault-format.md` |
| What are we defending against? | `docs/security/threat-model.md` |
| How is a connection modelled? | `docs/architecture/data-model.md` |
| How does a session start? | `docs/architecture/session-pipeline.md` |
| What can a plugin do? | `docs/architecture/plugin-system.md` |
| What licence may a plugin use? | `docs/architecture/decisions/0009-plugin-licence-exception.md` |
| Why unwind and not abort? | `docs/architecture/decisions/0011-panic-strategy.md` |
| What ships when? | `docs/roadmap.md` |
| What does this word mean? | `docs/glossary.md` |

**If you change behaviour that a document describes, update the document in the
same commit.** If you make a decision that a future contributor would reasonably
ask "why?" about, write an ADR (`docs/architecture/decisions/NNNN-title.md`,
copying `0000-template.md`).

---

## 3. Repository layout

This is the tree as it exists. `Cargo.toml`'s `members` has eleven entries: the
ten crates below and `apps/desktop/src-tauri`, and nothing else. Four crates the
older drafts of this file listed — `remoter-proto-sftp`, `remoter-tunnel`,
`remoter-record`, `remoter-plugin` — have never been created. Where their work
lives instead is noted below.

```
crates/
  remoter-core/         Domain model: tree, nodes, inheritance resolution
  remoter-vault/        Envelope crypto, key slots, storage, migrations, audit log
  remoter-proto/        `Protocol` trait, session supervisor, event bus,
                        framebuffer contract, gateway chain builder
  remoter-proto-ssh/    SSH + PTY (russh), SFTP (russh-sftp), local/remote/
                        dynamic forwarding, the SOCKS5 server
  remoter-proto-rdp/    RDP (IronRDP), CredSSP/NTLMv2
  remoter-proto-vnc/    VNC / RFB (vnc-rs), with the handshake owned here
  remoter-import/       mRemoteNG confCons.xml, ssh_config, CSV; and the
                        CSV / ssh_config / JSON exporters
  remoter-plugin-abi/   Plugin ABI types and wire format   (Apache-2.0 OR MIT)
  remoter-plugin-sdk/   Guest-side helpers for plugin authors (Apache-2.0 OR MIT)
  remoter-ipc/          Tauri command surface — the ONLY crate Tauri touches
apps/
  desktop/
    src-tauri/          Tauri shell; thin. Business logic belongs in crates/
    ui/                 React + TypeScript frontend
docs/                   Specifications (see §2)
locales/                i18n message catalogs, one directory per language
fuzz/                   cargo-fuzz targets for the importers
scripts/                Local install, a throwaway sshd, the source-is-text check
```

**Where the four missing crates' work went.**

- **SFTP** is `remoter-proto-ssh/src/sftp.rs`. It is a subsystem on an SSH
  channel; a separate crate would have had to re-export `SshConnection` to say
  anything at all.
- **Tunnelling** is `remoter-proto-ssh/src/{forward,socks,bind}.rs` for the same
  reason, with the node-level surface in `remoter-ipc/src/tunnel.rs`. The
  gateway-chain builder that is genuinely protocol-agnostic lives one layer
  down, in `remoter-proto/src/gateway.rs`.
- **The audit log** is `remoter-vault/src/{audit,storage}.rs` — it is a table in
  the vault body, so it is written by whoever holds the vault.
- **Recording** does not exist anywhere. Not in a crate, not in the interface.
  `Capabilities::recordable` is reported by three adapters and read by nobody.
- **The plugin host** does not exist. `remoter-plugin-abi` and
  `remoter-plugin-sdk` define the boundary; nothing loads a module.

If you add a protocol, `crates/remoter-proto-<name>/` is still the right shape.
Do not recreate the crates above speculatively — §10 forbids scaffolding.

**Layering rule.** This is design intent, and the tree still satisfies it:

```
apps/ ──▶ remoter-ipc ──▶ remoter-proto-* ──▶ remoter-proto ──▶ remoter-core
                     └──▶ remoter-vault ────────────────────┘
```

`remoter-core` and `remoter-vault` depend on no other workspace crate. If you
find yourself wanting an upward dependency, the abstraction is in the wrong
place — introduce a trait in the lower crate instead.

---

## 4. Commands

```bash
# Rust
cargo check --workspace --all-targets      # fast feedback loop
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo test --workspace                     # unit + integration
cargo test -p remoter-vault -- --nocapture # crypto known-answer tests
cargo deny check                           # licences, advisories, bans
cargo audit                                # RUSTSEC advisories

# Frontend (from apps/desktop/ui)
npm run dev
npm run build
npm run lint
npm run typecheck
npm test

# Full app
# The Tauri CLI searches for tauri.conf.json BELOW its working directory, and
# this workspace keeps it in apps/desktop/src-tauri — so it runs from
# apps/desktop while the CLI itself lives under apps/desktop/ui/node_modules.
cd apps/desktop && ./ui/node_modules/.bin/tauri dev
cd apps/desktop && ./ui/node_modules/.bin/tauri build --no-bundle

# Documentation. Every relative link and #fragment resolves, every file under
# docs/features and docs/architecture opens with a note saying which part of it
# ships, the counts README.md and docs/README.md quote for that are the counts
# on disk, and the two index tables list every document that exists. Cheap,
# offline, no arguments.
scripts/check-docs.sh

# Live protocol tests. There is no `tests/fixtures/compose.yaml` — the only
# fixture that exists is a throwaway sshd, which covers the SSH and SFTP live
# tests. RDP and VNC have no fixture, so their `integration-tests` targets need
# a server you point them at yourself.
scripts/dev-sshd.sh
cargo test --workspace --features integration-tests
```

**Before you claim work is done**, run `cargo clippy -- -D warnings`,
`cargo fmt --all --check`, `cargo test --workspace` and `npm run typecheck` —
and `scripts/check-docs.sh` if you touched a Markdown file, which a change that
follows §2 usually has. Report failures honestly; do not describe a partially
working change as complete.

---

## 5. Rust conventions

**Errors.** `thiserror` for library crates, `anyhow` only in `apps/`. Every
public fallible function returns a typed error. `unwrap()` and `expect()` are
forbidden in `remoter-vault` and `remoter-proto-*` outside of tests; elsewhere
they require a comment proving the invariant.

**Secrets.** All secret-bearing values use the `Secret<T>` wrapper from
`remoter-vault`:

```rust
/// A value that must never be logged, and is zeroed on drop.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}
```

Never implement `Display`, `Serialize` or `Clone` on a secret type without an
explicit review note. Buffers holding plaintext key material are `Zeroizing<_>`.

**Async.** Tokio multi-thread runtime. Protocol sessions are supervised tasks
with cancellation tokens; a closed tab must terminate its task and free its
sockets deterministically. No `std::thread::sleep` in async code. No blocking
I/O on the runtime — use `spawn_blocking`.

**Panics.** `panic = "unwind"` in every profile. Each session is its own
`tokio::spawn`ed task, so a panic surfaces as `JoinError::is_panic()` rather
than propagating — no `catch_unwind` is needed or used. A panicking session
becomes one failed tab with a copyable diagnostic.

**A panicked session is destroyed, never resumed.** Discard its state whole:
sockets closed, recorder flushed, secrets zeroized. Recovering part of it
reintroduces the state-corruption risk. A panic outside a session task is fatal
by design. The panic hook logs the location, never the payload — payloads
contain formatted values, and formatted values contain secrets.

**Unsafe.** Forbidden, and the mechanism is a workspace lint, not an attribute
per file: `unsafe_code = "forbid"` in `[workspace.lints.rust]`, which all ten
crates inherit through `[lints] workspace = true`. Three of them —
`remoter-proto-ssh`, `remoter-proto-rdp`, `remoter-proto-vnc` — also write
`#![forbid(unsafe_code)]` at the top of `lib.rs`. That is belt and braces, and
says nothing about the other seven, which are covered exactly as strictly. So
grepping for the attribute finds three files and is not how you check whether a
crate is covered; the lint block in the root `Cargo.toml` is.

`remoter-desktop` is the one exception. It sets `unsafe_code = "deny"` in its
own `[lints.rust]` and allows a single block: the `std::env::set_var` call in
`main.rs` that applies the Wayland DMA-BUF workaround, which edition 2024 made
unsafe and which runs before any thread exists. It is written up in
`docs/development/coding-standards.md`; a further exception needs an ADR. Every
`unsafe` block carries a `// SAFETY:` comment stating the upheld invariant.

**Tests.** Cryptographic primitives get known-answer tests against published
vectors. Inheritance resolution and importers get `proptest` property tests.
Importers additionally get `cargo-fuzz` targets — they parse hostile input.

---

## 6. Frontend conventions

- React 19 function components, TypeScript `strict`, no `any` without a comment
- Server-ish state via TanStack Query over Tauri commands; UI state via Zustand
- **CSS modules**, one `.module.css` beside each component, over design tokens in
  `apps/desktop/ui/src/styles/tokens.css`. Tailwind was the original plan and is
  not installed; do not add a utility class expecting it to resolve
- Logical CSS properties only (`margin-inline-start`, not `margin-left`). Arabic
  is a shipped language and RTL is a layout, not a mirror
- Every user-visible string goes through `t()` — no hardcoded English in JSX.
  New strings are added to `locales/en/*.json` only; translators handle the rest
- Components that render remote content (hostnames, banners, MOTD, directory
  listings) must treat it as untrusted text. Never `dangerouslySetInnerHTML`
- The frontend never holds a decrypted secret. It requests an action; the Rust
  core performs it with the secret and returns a result

---

## 7. Security invariants to check on every change

Ask these before opening a pull request that touches the core:

- Could this value end up in a log, a panic message or a crash report?
- Is every plaintext buffer zeroized on every path, including error paths?
- Is the AEAD's associated data bound to everything that must not be swapped
  (record id, field name, slot index, header bytes)?
- Is a nonce reused anywhere? Nonces are random 24-byte (XChaCha20) or derived
  from a strictly increasing counter — never both schemes on one key.
- Does a failure leave the vault file truncated or half-written? All writes are
  write-to-temp + `fsync` + atomic rename.
- Does this widen what a plugin can reach?
- Does an error message distinguish "wrong password" from "corrupt file" in a
  way that helps an attacker? (It should distinguish them for the user, but only
  after authentication of the header succeeds.)

---

## 8. Dependencies

Adding a crate or npm package requires:

1. **Licence check.** GPL-3.0 permits linking MIT, Apache-2.0, BSD, ISC, MPL-2.0.
   It does **not** permit incorporating code under GPL-incompatible terms
   (e.g. SSPL, BUSL, CC-BY-NC, proprietary). Record the decision in `deny.toml`.
2. **Justification** in the pull request: what it does, why the standard library
   or an existing dependency will not do, and maintenance status.
3. **No new C dependency** without an ADR. Pure-Rust implementations are
   preferred specifically because this application parses hostile network input.

Pinned major choices (do not swap without an ADR): `tauri` 2.x, `russh` 0.63,
`russh-sftp` 3.x, `ironrdp` 0.17, `vnc-rs` 0.5, `argon2` 0.6,
`chacha20poly1305` 0.11, `zeroize` 1.x, `rusqlite` 0.40, `keyring` 4.x,
`quick-xml` 0.41 (the reason it is not 0.42 is a long comment in `Cargo.toml`;
read it before bumping).

Two more were chosen and are not in the graph, because the features that would
use them are not built: `ctap-hid-fido2` 3.x for the FIDO2 slot and `extism` 1.x
for the plugin host. They are decisions, not dependencies — do not add either
until the feature it serves is actually being written.

**The workspace `rust-version` is `1.85` and that is knowingly wrong**: `ironrdp`
0.17 declares 1.89 and `keyring` 4.2 declares 1.88, so nothing has built on 1.85
since the RDP adapter landed. The comment above it in `Cargo.toml` explains what
correcting it costs and why that belongs in its own change; read it before
"fixing" the line.

---

## 9. Git conventions

**Commits** follow Conventional Commits:

```
feat(vault): add FIDO2 hmac-secret key slot
fix(ssh): reset the PTY window size after a tab is detached
docs(security): document the recovery key rotation flow
refactor(core): extract inheritance resolution into a pure function
test(import): add fuzz target for confCons.xml parsing
chore(deps): bump russh to 0.63.3
```

Scopes match crate names without the `remoter-` prefix (`vault`, `core`, `ssh`,
`rdp`, `ui`, `deps`, `ci`).

**Commit bodies** explain *why*, not *what* — the diff already shows what.

**Branches**: `feat/<short-slug>`, `fix/<short-slug>`, `docs/<short-slug>`.

**Never commit** to `main` directly, never force-push a shared branch, and never
commit a real credential, key file or vault — even a test one. `.gitignore`
covers `*.rvault`, `*.pem`, `*.key`; do not override it with `git add -f`.

**Never add AI attribution to a commit, tag, or pull request.** See §0.1.

---

## 10. Working style in this repository

- **Read the relevant spec first.** Most "how should this work?" questions are
  already answered in `docs/`. Answering from imagination creates drift.
- **Prefer a small, complete change** over a large, partial one. A merged crate
  with tests beats three half-finished ones.
- **Surface disagreement early.** If a spec is wrong, say so and propose the
  amendment before writing code against it.
- **Do not scaffold speculatively.** No empty modules, no `todo!()` stubs for
  features that are not on the current milestone. The roadmap is the scope.
- **State what you did not do.** If a change is missing tests, missing a
  platform, or missing docs, say so explicitly rather than letting it be
  discovered in review.
