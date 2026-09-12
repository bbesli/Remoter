# ADR-0007: Single process for v1; protocol isolation deferred

- **Status**: Accepted
- **Date**: 2026-09-10

## Context

Protocol decoders parse hostile input inside a process that holds every
credential the user owns. Even with memory-safe Rust, a logic bug — an infinite
loop, an unbounded allocation, a decompression bomb — can degrade or crash the
process. Browsers solved the analogous problem by putting each site in its own
sandboxed process.

## Options considered

**A · Single process, task isolation.** Sessions are supervised Tokio tasks with
cancellation tokens and `catch_unwind` at the supervisor boundary. Simple, fast,
one binary. Memory is shared: an exploitable bug in a decoder reaches the vault.

**B · Process per protocol adapter.** Each adapter runs in a sandboxed child
(seccomp, AppContainer, App Sandbox) with only a socket and a pipe. A compromised
decoder cannot read the vault. Costs: IPC for every frame — precisely the
high-bandwidth path that is already the hardest problem — plus per-platform
sandbox code, and a much harder debugging story.

**C · Process per session.** Maximum isolation, and prohibitive overhead at the
twenty-plus concurrent sessions our users actually keep open.

## Decision

**Option A for v1.0. Option B designed for, and deferred to, v2.**

Three reasons, in order of weight:

1. **The bug class option B protects against is the one Rust already removes.**
   Its marginal value here is much lower than in a C codebase, where it would be
   mandatory.
2. **It collides with the hardest open problem.** Framebuffer transport across
   the WebView boundary is already the project's principal risk
   ([rendering.md](../rendering.md)). Adding a second process hop to that path
   before we have measured the first one is bad sequencing.
3. **Shipping matters.** A design that never ships protects nobody.

Deferring is not the same as ignoring. Compensating controls in v1.0:

- Every protocol crate is `#![forbid(unsafe_code)]`
- Per-session resource limits: maximum frame size, channel count, and
  decompressed size — decompression bombs are a real RDP 6.0 and RemoteFX
  concern
- Continuous fuzzing of every decoder and every importer
- A panic in a session task fails one tab, not the process
- Third-party protocol code is already sandboxed, because plugins run in WASM
  (ADR-0004)

The architecture keeps option B cheap to adopt: adapters already communicate
through the `Protocol` trait over an injected transport and an event stream.
Moving that boundary across a process is a mechanical change, not a redesign.

## Consequences

**Positive.** A simpler, faster v1.0. One binary to build, ship and debug. No
per-platform sandbox code yet. The lowest-latency rendering path is available to
us.

**Negative.** An exploitable decoder bug reaches the vault key. We accept this
risk explicitly, having reduced its likelihood as far as language choice allows.
It is stated in the threat model rather than buried.

**Neutral.** The v2 migration is real work but well-scoped, because the seam
already exists.

## Revisit if

A memory-safety or logic vulnerability is found in any protocol crate, if we
ever need to link a C protocol library (in which case isolation becomes
mandatory, not optional), or once v1.0 has shipped and the rendering path is
settled.

## Amendment, 2026-09-12: option A was built without `catch_unwind`

The decision above stands — one process, sessions isolated as tasks — but the
sketch of option A names a mechanism that was never written. There is no
`catch_unwind` anywhere in the workspace, and there is not meant to be.

Each session is its own `tokio::spawn`ed task, so a panic inside one unwinds
that task and stops there rather than propagating into the runtime: the
supervisor sees it as `JoinError::is_panic()` on the join handle
(`crates/remoter-proto/src/supervisor.rs`) and fails that one tab. Nothing is
*caught*, because there is nothing left to catch by the time the supervisor
hears about it. `catch_unwind` around arbitrary async code also brings
`UnwindSafe` problems the task boundary does not have, and it would hand back a
panic payload — which is formatted values, which is where secrets are — to code
that then has to be trusted not to log it. [ADR-0011](0011-panic-strategy.md)
is the full argument and is the document to read on panics; this note exists so
that the accepted option here is not read as a specification of code that does
not exist. Cancellation tokens, the other half of the sentence, are real.

The compensating controls listed above are in place unevenly, and this is where
that is recorded rather than in a status document that a reader of this ADR
will not open:

- **`unsafe` is forbidden**, and more widely than the line above claims: it is
  `unsafe_code = "forbid"` in `[workspace.lints.rust]`, inherited by all ten
  crates, so it covers `remoter-core` and `remoter-vault` too. Three protocol
  crates also carry `#![forbid(unsafe_code)]` in the file, which is belt and
  braces, not the mechanism.
- **Per-session limits** exist for the ones that bound memory on the frame
  path: a session cap (`SupervisorConfig::max_sessions`), a coalesced frame
  ceiling (`max_frame_bytes`), a framebuffer dimension gate
  (`remoter_proto_vnc::gate::MAX_FRAMEBUFFER_PIXELS`) and RDP reassembly
  accounting that is sound only because bulk compression is never negotiated
  (`remoter-proto-rdp/src/framed.rs`).
- **Continuous fuzzing is importers only.** `fuzz/` holds three targets, all of
  them parsers in `remoter-import`. No protocol decoder is fuzzed, and nothing
  runs any target on a schedule — see `docs/development/testing-strategy.md`.
  This is the weakest of the five and the honest reason the deferral is still
  a deferral rather than a settled position.
- A panic failing one tab, and WASM sandboxing for third-party protocol code,
  are as described — the second vacuously, since no plugin host exists.
