# Coding Standards

> **What ships.** These are enforced, not aspirational: the lints in the table
> are `deny` in the workspace `Cargo.toml`, `unsafe_code` is `forbid`, and the
> two ESLint rules that fail a build on a hardcoded string or a stray `invoke()`
> are in the frontend config. CI runs clippy with `-D warnings` on three
> platforms.

## Rust

### Errors

`thiserror` in library crates, `anyhow` only in `apps/`. Every public fallible
function returns a typed error whose variants a caller can match on and act
differently for.

```rust
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("no key slot accepted the supplied credentials")]
    UnlockFailed,
    #[error("the vault header failed integrity verification")]
    HeaderTampered,
    #[error("vault format version {found} is newer than this build supports ({supported})")]
    UnsupportedVersion { found: u16, supported: u16 },
    #[error("input/output error")]
    Io(#[from] std::io::Error),
}
```

Error messages are lowercase, without trailing punctuation, and describe what
went wrong rather than what the code was doing.

**`unwrap()` and `expect()` are forbidden** in `remoter-vault` and
`remoter-proto-*` outside of tests. Elsewhere they require a comment proving the
invariant:

```rust
// SAFETY-OF-UNWRAP: `hops` is validated non-empty by `GatewayChain::validate`
// at construction, and this struct is only built through that path.
let first = chain.hops.first().unwrap();
```

### Secrets

```rust
use zeroize::{Zeroize, Zeroizing};

/// A value that must never be logged, and is zeroed on drop.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}
```

Rules:

- Never implement `Display`, `Serialize` or `Clone` on a secret type without an
  explicit review note explaining why it is safe
- Key material is `Zeroizing<[u8; N]>`
- Never interpolate a secret into a format string, an error, a log line or a
  span field — including at `trace` level
- Never put a secret in `argv` or an environment variable

### Async

- Tokio multi-thread runtime
- Sessions are supervised tasks with `CancellationToken`. Every task must
  terminate when cancelled, releasing its resources
- No blocking I/O on the runtime. Argon2id, FIDO2 and keychain calls go through
  `spawn_blocking`
- No `std::thread::sleep` in async code
- Bounded channels everywhere. An unbounded channel is an unbounded memory leak
  waiting for a fast remote host

### Panics

`panic = "unwind"` in every profile
([ADR-0011](../architecture/decisions/0011-panic-strategy.md)). Two rules follow
and both are enforced in review:

- **A panicked session is destroyed, never resumed.** On
  `JoinError::is_panic()`, the supervisor discards the whole session state,
  closes its sockets, flushes its recorder and zeroizes its secrets. Any change
  that tries to recover or reuse part of a panicked session's state reintroduces
  precisely the state-corruption risk that made `abort` tempting
- **A session task never holds a lock on shared state across decoder code.** The
  vault is a single-writer task for this reason. `parking_lot` mutexes are used
  where locks are needed, so there is no poisoning to reason about

A panic anywhere outside a session task is fatal by design: those components
have no isolation boundary, and continuing past a bug in them would mask
corruption rather than contain it.

The panic hook logs the panic **location**, never the payload — a payload can
contain a formatted value, and a formatted value can contain a secret.

### Unsafe

`unsafe_code = "forbid"` at the workspace level, so every crate inherits it.

**One documented exception exists.** `remoter-desktop` downgrades the lint to
`deny` and allows a single `unsafe` block: the Wayland/DMA-BUF workaround in
`main.rs` calls `std::env::set_var`, which edition 2024 made unsafe. It runs as
the first statement of `main`, before the Tokio runtime, before GTK
initialisation and before any thread is spawned, so the data race the rule
exists to prevent cannot occur. Any further exception needs an ADR.

Each `unsafe` block carries a `// SAFETY:` comment naming the invariant it
upholds.

### Lints

Workspace-level, in the root `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"
unreachable_pub = "warn"

[workspace.lints.clippy]
all = "deny"
pedantic = "warn"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
dbg_macro = "deny"
print_stdout = "deny"
```

`print_stdout` is denied because a stray `println!` is how secrets escape.

### Documentation

Every public item has a doc comment. For anything non-obvious, say **why**, not
just what:

```rust
/// Derives the key-encryption key for a password slot.
///
/// The key file digest is concatenated *after* the password so that a
/// zero-length key file produces the same input as no key file at all —
/// which is what makes adding a key file to an existing vault a slot
/// rewrite rather than a re-derivation of every other slot.
pub fn derive_password_kek(…) -> Zeroizing<[u8; 32]> { … }
```

## TypeScript

### Configuration

`strict: true`, plus `noUncheckedIndexedAccess`, `noImplicitOverride` and
`exactOptionalPropertyTypes`. `any` requires a comment justifying it; `unknown`
with narrowing is almost always the right answer instead.

### Components

```tsx
interface ConnectionTreeProps {
  nodes: TreeNode[];
  selectedId: NodeId | null;
  onSelect: (id: NodeId) => void;
}

export function ConnectionTree({ nodes, selectedId, onSelect }: ConnectionTreeProps) {
  const { t } = useTranslation("connections");
  // …
}
```

- Function components with named exports. No default exports — they make
  refactoring and search worse
- Props interfaces are named and exported alongside the component
- One component per file; a file over ~200 lines usually wants splitting
- Custom hooks for anything stateful and reusable

### State

| Kind | Tool |
|---|---|
| Backend data | TanStack Query over typed IPC wrappers |
| UI state (open tabs, sidebar width) | Zustand |
| Form state | React Hook Form + Zod |
| Ephemeral component state | `useState` |

**The frontend never holds a decrypted secret.** It asks for an action; the
Rust core performs it.

### IPC

Every Tauri command has a typed wrapper in `lib/ipc.ts`, and that is the only
file where `invoke` appears:

```ts
export async function vaultUnlock(req: UnlockRequest): Promise<VaultInfo> {
  return invoke<VaultInfo>("vault_unlock", { req });
}
```

### Strings

Every user-visible string goes through `t()`. No literal English in JSX. Only
`locales/en/` is edited by contributors.

### Untrusted content

Content from remote hosts — hostnames, banners, MOTD, directory listings, window
titles — is rendered as text. `dangerouslySetInnerHTML` is banned by ESLint with
no override.

## Comments

Comment **why**, not what. The code shows what.

```rust
// Bad
// Increment the counter
counter += 1;

// Good
// RFB servers vary in whether they count the initial framebuffer as an update.
// We normalise by ignoring the first one, which keeps the frame-rate estimate
// stable across TigerVNC and RealVNC.
if updates_seen > 0 { rate.record(now); }
updates_seen += 1;
```

Wire-level protocol code cites its source:

```rust
// MS-RDPBCGR 2.2.1.3.2: the client core data block. `desktopWidth` and
// `desktopHeight` are little-endian u16 and must be even.
```

Do not comment out code. Delete it — Git remembers.

Do not leave `TODO` without an issue number: `// TODO(#142): …`.
