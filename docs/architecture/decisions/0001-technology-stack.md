# ADR-0001: Tauri v2 with a Rust core and a React frontend

- **Status**: Accepted
- **Date**: 2026-09-10

## Context

Remoter must simultaneously: hold every credential its user owns, parse hostile
binary protocols from potentially compromised servers, render interactive
graphics at video frame rates, and present a modern interface in ten languages
on Linux, Windows and macOS.

Those requirements pull hard in different directions. Security and protocol
parsing want a memory-safe systems language. The interface wants the web
platform's productivity and its mature i18n and accessibility story. Whatever we
choose, we live with for years.

## Options considered

### A · Tauri v2 + Rust core + React/TypeScript frontend

Rust owns crypto, protocols, session management. The system WebView renders the
UI.

**Pros** — memory safety exactly where hostile input arrives; excellent
cryptography ecosystem (RustCrypto, rustls, argon2); pure-Rust protocol
implementations available for every protocol we need (`russh`, `IronRDP`,
`vnc-rs`); ~15 MB binaries against Electron's ~150 MB; roughly a fifth of the
memory; a genuinely capable UI layer; `#![forbid(unsafe_code)]` is achievable
across the network-facing crates.

**Cons** — the WebView differs per platform (WebKitGTK, WebView2, WKWebView), so
rendering must be tested three times; message-passing IPC with no shared memory
makes high-frame-rate framebuffer transport hard; a smaller contributor pool
than JavaScript; Linux WebKitGTK can silently fall back to software rendering.

### B · Electron + Node.js

**Pros** — the largest ecosystem; every library exists; the fastest path to a
prototype; the biggest contributor pool.

**Cons** — an application holding every credential a sysadmin owns should not
ship a full browser as its trusted computing base; ~150 MB binaries and high
memory use, which matters when users keep twenty sessions open; Node's native
protocol libraries are largely C bindings, which reintroduces exactly the
memory-safety risk we most want to eliminate; secrets in a garbage-collected
heap cannot be reliably zeroized.

### C · C# / .NET 9 + Avalonia UI

**Pros** — mRemoteNG's and Royal TS's native territory; the most mature Windows
RDP integration; strong enterprise tooling.

**Cons** — Linux and macOS remain second-class in practice; RDP integration
depends on Windows-specific components; a garbage-collected heap has the same
secret-zeroization problem as Node; and the platform's centre of gravity is
Windows, which conflicts with a genuinely cross-platform goal.

### D · C++ / Qt 6

**Pros** — the highest performance ceiling; the most natural fit with FreeRDP
and libssh2; complete control over rendering.

**Cons** — manual memory management in code that parses hostile network input is
precisely the risk this project should not take; slow development; a much
smaller pool of contributors willing to work on a C++ Qt codebase in 2026.

## Decision

**Option A.**

The decisive argument is the threat model. Remoter's most dangerous input is a
malformed RDP or RFB frame from a compromised server, arriving in a process that
holds every credential the user owns. A memory-safety bug there is a total
compromise. Rust removes that class of bug at the language level, and — crucially
— every protocol we need already has a maintained pure-Rust implementation, so
we are not choosing safety at the cost of capability.

Tauri gives us the web platform for the interface without shipping a browser as
part of our trusted computing base.

## Consequences

**Positive.** Memory safety where it matters most. Small, fast binaries. Real
cross-platform parity. First-class cryptography libraries. Secrets can be
deterministically zeroized, which is impossible on a garbage-collected heap.

**Negative.** Framebuffer rendering over message-passing IPC is the project's
principal technical risk — see [rendering.md](../rendering.md) and ADR-0003.
Three WebView engines to test. A steeper contribution curve than JavaScript,
which will slow community growth. Some Rust protocol crates are younger than
their C equivalents and we should expect to contribute fixes upstream.

**Neutral.** The frontend/backend split is enforced by the architecture rather
than by discipline, which is good for structure and occasionally verbose.

## Revisit if

The rendering spike (v0.3) shows the WebView path cannot sustain acceptable
framebuffer performance *and* the native-surface-overlay fallback also proves
unworkable. That would call the presentation layer into question — though not
the Rust core, which stands on its own merits.
