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

---

## 1. What this project is

A cross-platform remote connection manager: an encrypted vault of servers and
credentials, plus embedded RDP / SSH / VNC / SFTP sessions in a tabbed desktop
application. Comparable to mRemoteNG and Royal TS. Licensed GPL-3.0.

**Current state: design phase.** The repository holds specifications only. There
is no `Cargo.toml`, no `package.json` and no source tree yet. When implementation
starts, follow the layout in §3 exactly — the docs reference those paths.

---

## 2. Where the truth lives

Design documents are normative. Code that contradicts them is a bug in the code,
unless the document has been amended first.

| Question | Authoritative document |
|---|---|
| Why is the stack what it is? | `docs/architecture/decisions/0001-technology-stack.md` |
| How is the vault encrypted? | `docs/security/vault-format.md` |
| What are we defending against? | `docs/security/threat-model.md` |
| How is a connection modelled? | `docs/architecture/data-model.md` |
| How does a session start? | `docs/architecture/session-pipeline.md` |
| What can a plugin do? | `docs/architecture/plugin-system.md` |
| What ships when? | `docs/roadmap.md` |
| What does this word mean? | `docs/glossary.md` |

**If you change behaviour that a document describes, update the document in the
same commit.** If you make a decision that a future contributor would reasonably
ask "why?" about, write an ADR (`docs/architecture/decisions/NNNN-title.md`,
copying `0000-template.md`).

---

## 3. Repository layout

```
crates/
  remoter-core/         Domain model: tree, nodes, inheritance resolution
  remoter-vault/        Envelope crypto, key slots, storage, migrations
  remoter-proto/        `Protocol` trait, session supervisor, event bus
  remoter-proto-ssh/    SSH + PTY (russh)
  remoter-proto-sftp/   SFTP (russh-sftp)
  remoter-proto-rdp/    RDP (IronRDP)
  remoter-proto-vnc/    VNC / RFB (vnc-rs)
  remoter-tunnel/       Local/remote/dynamic forwarding, jump host chains
  remoter-import/       mRemoteNG, Royal TS, PuTTY, RDCMan, ssh_config, CSV
  remoter-record/       asciicast v2 writer, framebuffer recorder, audit log
  remoter-plugin/       WebAssembly host, manifest parsing, capability grants
  remoter-ipc/          Tauri command surface — the ONLY crate Tauri touches
apps/
  desktop/
    src-tauri/          Tauri shell; thin. Business logic belongs in crates/
    ui/                 React + TypeScript frontend
  cli/                  Headless companion (vault ops, scripted connects)
docs/                   Specifications (see §2)
locales/                i18n message catalogs, one directory per language
```

**Layering rule.** Dependencies point downward only:

```
apps/ ──▶ remoter-ipc ──▶ remoter-proto-* ──▶ remoter-proto ──▶ remoter-core
                     └──▶ remoter-vault ────────────────────┘
```

`remoter-core` and `remoter-vault` depend on no other workspace crate. If you
find yourself wanting an upward dependency, the abstraction is in the wrong
place — introduce a trait in the lower crate instead.

---

## 4. Commands

Once the workspace exists, these are the commands. Until then they are the
contract for what the workspace must support.

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
npm run tauri dev
npm run tauri build

# Integration fixtures (Docker: openssh-server, xrdp, tigervnc)
docker compose -f tests/fixtures/compose.yaml up -d
cargo test --workspace --features integration-tests
```

**Before you claim work is done**, run `cargo clippy -- -D warnings`,
`cargo fmt --all --check`, `cargo test --workspace` and `npm run typecheck`.
Report failures honestly; do not describe a partially working change as
complete.

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

**Panics.** A panic in a session task must not take down the process. Session
tasks run under `catch_unwind` at the supervisor boundary, and a panicking
session surfaces to the user as a failed tab with a copyable diagnostic.

**Unsafe.** `#![forbid(unsafe_code)]` at the top of every crate except where a
platform FFI genuinely requires it. Those exceptions are listed in
`docs/development/coding-standards.md` and each `unsafe` block carries a
`// SAFETY:` comment stating the upheld invariant.

**Tests.** Cryptographic primitives get known-answer tests against published
vectors. Inheritance resolution and importers get `proptest` property tests.
Importers additionally get `cargo-fuzz` targets — they parse hostile input.

---

## 6. Frontend conventions

- React 19 function components, TypeScript `strict`, no `any` without a comment
- Server-ish state via TanStack Query over Tauri commands; UI state via Zustand
- Tailwind for styling; design tokens live in `apps/desktop/ui/src/styles/tokens.css`
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
`ctap-hid-fido2` 3.x, `extism` 1.x.

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
