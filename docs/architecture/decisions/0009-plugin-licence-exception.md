# ADR-0009: A GPL-3.0 interface exception for WebAssembly plugins

- **Status**: Accepted
- **Date**: 2026-09-10
- **Supersedes the open question in**: [ADR-0004](0004-plugin-system.md), [ADR-0006](0006-licensing.md)

## Context

Remoter is GPL-3.0-or-later. It loads third-party plugins as WebAssembly
modules. Whether such a plugin becomes a derivative work of the host — and must
therefore itself be GPL — is not settled law, and the uncertainty alone is
enough to prevent an ecosystem forming: no vendor writes a plugin for their
appliance if the licence status is a question their counsel has to answer.

Two facts make this urgent rather than something to leave until v1.1:

1. **An exception can be added, but never removed.** Once granted, it is
   irrevocable for the versions it covers.
2. **Adding it later requires unanimous consent from every copyright holder.**
   Today that is one person. After the first external pull request is merged, it
   is everyone who has ever contributed. The window is open now and closes
   permanently the first time someone else's code lands.

Deferring this decision to v1.1, as ADR-0004 originally proposed, is therefore
not a neutral act. It is a decision to make the exception much harder to grant.

## The technical position

A WASM plugin is already, by construction, at arm's length from the host:

- It executes in its own linear memory. It cannot read or write host memory
- It cannot call host code except through a fixed, published set of imported
  functions
- All data crosses the boundary as serialised bytes in explicitly copied buffers
- It cannot obtain a pointer into the host, share a data structure with it, or
  link against its symbols

That is architecturally the same relationship as two processes communicating
over a pipe, which is the canonical example of separate works. The uncertainty
is not really about the technology; it is about a doctrine written for C
dynamic linking being applied to something that does not resemble it.

We could rest on that argument. We should not rest on it *alone*, because
"we believe a court would agree with us" is not something a plugin author's
legal department will accept.

## Decision

**Three measures, all taken now, in v0.1.**

### 1 · The ABI and guest SDK are permissively licensed

The crates a plugin author actually compiles against are separated out and
licensed **Apache-2.0 OR MIT**:

| Crate | Licence | Role |
|---|---|---|
| `remoter-plugin-abi` | Apache-2.0 OR MIT | Type definitions, function signatures, wire format |
| `remoter-plugin-sdk` | Apache-2.0 OR MIT | Guest-side helpers, macros, bindings |
| `remoter-plugin` (host) | GPL-3.0-or-later | The runtime that loads and sandboxes modules |

This removes most of the question before it is asked. A plugin author writes
code against permissively-licensed crates and never incorporates a line of GPL
source. There is no linking, static or dynamic, in any conventional sense.

### 2 · An explicit additional permission under GPL-3.0 §7

Published as `LICENSE-EXCEPTION` in the repository root and reproduced in the
header of every host source file that participates in plugin loading. It grants
permission to combine the Program with WASM modules that interact solely through
the published ABI, and to convey the result under the plugin's own terms.

Deliberate limits, all stated in the text:

- It covers **WebAssembly modules only**, executed in the host's sandbox
- It covers interaction **solely through the published ABI**. A plugin that
  incorporates Remoter source code beyond the permissive SDK crates is outside it
- It does **not** cover forks or modifications of Remoter itself. Change the
  host, and the GPL applies to that change in full
- It does **not** cover native code loaded into the process, which we do not
  support and do not intend to

### 3 · The exception travels with the ABI version

The permission is granted with respect to the published ABI. If a future ABI
version fundamentally changes the relationship — for example by giving plugins
access to host memory — the exception is not automatically extended to it, and
that change would require its own ADR.

## Consequences

**Positive.** A plugin author can pick their own licence, including a
proprietary one, with a written grant rather than an argument. Vendor
integrations become possible: an appliance manufacturer can ship a plugin for
their own console. The core application, and every fork of it, stays GPL — which
is the part that actually matters for a security tool, because it is what keeps
the code users run inspectable.

**Negative.** A company can build a proprietary plugin on top of our work and
give nothing back. That is the deliberate price of an ecosystem, and it is a
narrower concession than a permissive licence for the whole project would be.
The exception cannot be withdrawn.

**Neutral.** The workspace gains two small crates that must be kept genuinely
free of GPL code — enforced in CI by a licence check on their dependency trees.

## A caveat stated plainly

This ADR is an engineering and policy decision, not legal advice. The exception
text is modelled on well-established GPL §7 additional permissions in wide use,
but **it should be reviewed by a lawyer before the plugin ABI is published in
v1.1**. If review finds the wording inadequate, the wording changes; the
decision to grant an exception does not.

## Revisit if

Legal review finds the text insufficient, or a future ABI version changes the
isolation properties the exception depends on.
