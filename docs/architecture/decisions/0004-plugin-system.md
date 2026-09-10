# ADR-0004: WebAssembly plugins with declared capabilities

- **Status**: Accepted
- **Date**: 2026-09-10

## Context

The project is explicitly meant to be extensible: new protocols, new importers,
new credential backends, without forking. But the host process holds every
credential its user owns, so "extensible" and "safe" are in direct tension.

## Options considered

**Native dynamic libraries.** A plugin shares the process address space, so it
can read the vault master key. For this application that is disqualifying,
regardless of how convenient it is.

**Embedded scripting (Lua, Rhai).** Sandboxable and pleasant for hooks, but
single-language and too slow for protocol decoding.

**Subprocess with IPC.** Genuinely good isolation. The cost is that every plugin
author must build and distribute native binaries for three platforms — a
distribution problem large enough to prevent an ecosystem forming.

**WebAssembly.** Memory-isolated by construction, capability-based, one artefact
for all platforms, written in any language that targets WASM, fast enough for
protocol work.

## Decision

**WebAssembly, via Extism on Wasmtime.**

Extism is Wasmtime plus the plumbing a plugin host needs anyway: host function
linking, cross-boundary memory management, fuel metering, timeouts. Writing that
layer ourselves would be reimplementing it less well.

The rule that shapes everything else: **plugins never receive key material.**
A plugin requests a credential *by purpose*, receives an opaque handle, and asks
the host to perform operations with it. Signatures are computed host-side. Where
a protocol genuinely requires plaintext on the wire, the host performs that
authentication step itself. Where that is impossible, we decline to offer the
capability rather than misrepresent the isolation.

The ABI ships **unstable** in v1.1 and stabilises no earlier than v1.2.
Publishing a frozen contract before the internal traits have settled would
preserve our early mistakes permanently.

## Consequences

**Positive.** Untrusted third-party code can extend a credential-holding
application without being trusted. One artefact per plugin, all platforms. Any
source language. Capability prompts users can actually read.

**Negative.** A WASM boundary costs performance — acceptable for importers and
credential providers, and something to measure carefully for protocol plugins.
Plugin authors face a less convenient toolchain than a native library. Some
integrations are simply not expressible under these constraints, and we will
have to say no to them.

**Neutral.** Built-in protocols are compiled in, not sandboxed. They are part of
the application and reviewed as such; the sandbox exists for code we have not
reviewed.

`OPEN:` The GPL-3.0 status of WASM plugins loaded over a published ABI needs a
decision from the project owner before the ABI is published. The intent is to
treat them as separate works, which likely requires an explicit licence
exception. See [plugin-system.md](../plugin-system.md#licensing-note).

## Revisit if

Protocol plugins prove too slow at the WASM boundary — in which case protocol
extension may need the subprocess model while other plugin kinds stay in WASM.
