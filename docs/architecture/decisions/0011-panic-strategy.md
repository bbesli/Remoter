# ADR-0011: `panic = "unwind"` in release builds

- **Status**: Accepted
- **Date**: 2026-09-10
- **Resolves the open question in**: [build-release.md](../../development/build-release.md)

## Context

The draft release profile specified `panic = "abort"`, which contradicted the
architecture's stated invariant that "a panic in a session task fails one tab,
not the process". `abort` makes that invariant unimplementable: every panic,
anywhere, terminates the process immediately.

The question is which failure mode we want when a protocol decoder hits a bug on
a malformed frame from a remote host.

## The trade-off, with numbers

**What `abort` buys**: roughly 5–10 % smaller binaries from omitting landing
pads and unwinding tables, and marginally faster compilation. On the non-panic
path, execution speed is effectively identical — Rust's unwinding is zero-cost
until a panic actually occurs.

**What `abort` costs**: an administrator with twenty sessions open, a deployment
running in one of them, two persistent tunnels and an in-flight file transfer
loses all of it because one VNC server sent a rectangle with an implausible
dimension.

That is not a close call. A few megabytes of binary against every open session
in the application is not a trade any user would make if asked.

**The argument for `abort` that deserves a real answer**: continuing after a
panic can mask corrupted state, and a process limping on with inconsistent
invariants is arguably worse than one that stops. This is a legitimate concern
and it is why the decision comes with structural conditions rather than being a
single line in a profile.

## Decision

**`panic = "unwind"` in every profile**, with the following structure making it
safe:

### Session isolation is structural, not incidental

Each session runs as its own `tokio::spawn`ed task. A panic in a spawned task
does not propagate into the runtime — it surfaces as `JoinError::is_panic()` on
the handle. No explicit `catch_unwind` is needed, and none is used, because
`catch_unwind` around arbitrary async code has `UnwindSafe` problems that the
task boundary does not.

### A panicked session is destroyed, never resumed

On `JoinError::is_panic()`, the supervisor discards the entire session state,
closes its sockets, flushes and closes its recorder, zeroizes its cached
secrets, and marks the tab as failed with a copyable diagnostic. It does not
attempt to recover the session, reconnect automatically, or reuse any part of
its state. This is what answers the state-corruption objection: we do not
continue with possibly-corrupt state, we throw all of it away.

### Session tasks may not hold shared state across arbitrary code

Enforced in review, and the reason the vault is a single-writer task rather than
a shared lock: a session task never holds a vault lock while running decoder
code. `parking_lot` mutexes are used where locks are needed, so there is no
poisoning to reason about.

### A panic outside a session task is fatal, deliberately

The top-level panic hook treats a panic anywhere else — the vault task, the IPC
layer, the supervisor itself — as unrecoverable. It zeroizes key material,
attempts nothing clever, and exits. Those components have no isolation boundary
and continuing past a bug in them would be exactly the masking failure the
`abort` argument warns about.

### The panic hook never leaks a secret

A custom hook that:

- Logs the panic **location** and type, never the payload — a panic payload can
  contain a formatted value, and a formatted value can contain a secret
- Writes a crash report to a local file only, never uploaded, so the user can
  read it before deciding to attach it to an issue
- Zeroizes key material before the process exits, on the fatal path

## Consequences

**Positive.** One malformed frame costs one tab. Twenty concurrent sessions
survive a decoder bug in one of them. `#[should_panic]` tests work. The
behaviour matches what the architecture documents already claim.

**Negative.** Binaries are 5–10 % larger. There is a real obligation to keep the
"panicked session is destroyed" rule intact — a future change that tries to
resume a panicked session would reintroduce the state-corruption risk, so it is
called out in the coding standards rather than left as folklore.

**Neutral.** Unwinding tables make stack traces in crash reports more useful,
which is a small benefit for debugging.

## Revisit if

Profiling shows unwinding costs something measurable on the hot path — it should
not, but the claim is worth checking once rather than assuming — or if the
session-isolation structure is ever weakened, in which case the reasoning above
no longer holds.
