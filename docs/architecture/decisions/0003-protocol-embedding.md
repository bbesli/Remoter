# ADR-0003: Embed protocols in-process using pure-Rust implementations

- **Status**: Accepted
- **Date**: 2026-09-10

## Context

Sessions can be delivered three ways: embedded in the application, launched as
external clients, or proxied through a gateway that translates protocols. The
choice determines the product's core value and the bulk of its engineering
effort.

## Options considered

### A · Launch external clients
Shell out to `xfreerdp`, `mstsc`, `ssh`, `vncviewer`.

**Pros** — trivially simple; battle-tested clients; no protocol code to
maintain.

**Cons** — no tabs, no unified interface, no session recording, no consistent
clipboard handling. Credentials must be passed to a child process, and doing so
safely (never via `argv`, which is world-readable) is awkward for every client.
Behaviour varies per platform and per installed version. This is a launcher, not
a connection manager — the thing that makes mRemoteNG and Royal TS worth using
is precisely the embedding.

### B · Embed with C libraries
FreeRDP, libssh2, libvncclient via FFI.

**Pros** — the most mature and complete implementations; every protocol feature
exists.

**Cons** — these libraries parse hostile, attacker-controlled binary data inside
the process that holds every credential the user owns. Their CVE histories are
what one would expect from decades of C parsing network input. Cross-compiling
and packaging them for three platforms is a persistent tax.

### C · Embed with pure-Rust implementations
`russh`, `russh-sftp`, `IronRDP`, `vnc-rs`.

**Pros** — memory safety in the parsers, which is where the danger is;
`#![forbid(unsafe_code)]` across the protocol crates; no C toolchain in the
build; IronRDP is maintained by Devolutions (a commercial remote-access vendor)
and used in production by Cloudflare Access and Teleport, so it is not a hobby
project.

**Cons** — feature gaps against FreeRDP, particularly in exotic device
redirection and older codecs; `vnc-rs` is younger and less proven; we will need
to contribute upstream rather than file a bug and wait.

### D · Guacamole-style gateway
A daemon translates protocols, the client renders a normalised stream.

**Pros** — one rendering path; enables browser access later.

**Cons** — a large architectural addition for a desktop product; a service that
holds credentials and terminates protocols is a far bigger attack surface than a
local application; introduces deployment where there was none.

## Decision

**Option C**, with **transport injection** as the organising principle.

The `Protocol` trait receives an already-connected `Box<dyn Transport>` rather
than dialling out itself. One consequence is worth more than it first appears:
jump host chains, SOCKS proxies and SSH tunnels work identically for every
protocol, including plugin-provided ones. RDP through two SSH bastions is the
same code path as RDP on the LAN, and no protocol adapter contains gateway
logic.

Pure Rust is chosen specifically because of the threat model
([threat-model.md](../../security/threat-model.md#t4--malicious-remote-host)):
the most dangerous input in the entire application is a malformed frame from a
compromised host, arriving in a process holding every credential. Trading some feature completeness for the
elimination of that bug class is the right trade for this product.

## Consequences

**Positive.** Tabs, unified clipboard, session recording, consistent
configuration — the actual product. Memory-safe parsers. No C toolchain.
Uniform tunnelling for every protocol.

**Negative.** Feature gaps versus FreeRDP that we will have to close or document
— exotic redirections and legacy codecs in particular. Dependence on the health
of upstream crates, `vnc-rs` most of all; if it stalls, we maintain a fork.
Framebuffer rendering across the WebView IPC boundary is a real risk
([rendering.md](../rendering.md)).

**Neutral.** "Open in external client" remains available as a per-connection
escape hatch for the cases we cannot cover. It is a fallback, not the product.

## Revisit if

A protocol has no viable pure-Rust implementation and users genuinely need it.
The escalation order is: contribute upstream → maintain a fork → isolate a C
library in a separate sandboxed process (never in-process) → external client.
