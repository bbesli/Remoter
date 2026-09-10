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
