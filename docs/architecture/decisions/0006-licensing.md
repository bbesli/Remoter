# ADR-0006: GPL-3.0-or-later

- **Status**: Accepted
- **Date**: 2026-09-10

## Context

Remoter is released as open source. The licence determines who can build on it,
under what obligations, and whether a commercial fork can take the work
proprietary.

## Options considered

**MIT / BSD.** Maximum adoption, maximum permissiveness. Anyone may fork and
close the source. No patent grant.

**Apache-2.0.** Permissive with an explicit patent grant and a trademark clause.
The Rust ecosystem's default; the friendliest to corporate adoption. Still
permits proprietary forks.

**GPL-3.0-or-later.** Derivative works must remain free software under the same
terms. Includes an implicit patent grant and anti-tivoisation provisions.
Deters proprietary forks; deters some corporate use.

**AGPL-3.0.** GPL plus a network-use clause. Since Remoter is a desktop
application with no server component, the network clause has almost nothing to
attach to — it would add friction without adding protection.

## Decision

**GPL-3.0-or-later.**

For a security tool that holds credentials, the ability for anyone to inspect
the source of the binary they are running is a security property, not just a
philosophical stance. Copyleft is what keeps that true of derivatives too. This
also aligns with mRemoteNG, the most direct point of comparison, which lowers
the barrier to code and ideas moving between the projects.

The trade-off is accepted knowingly: some corporate contributors will be
excluded by policy, and the project will grow more slowly than under Apache-2.0.

**"or later"** is included so the project can adopt a future GPL revision
without tracking down every contributor.

## Dependency compatibility

GPL-3.0 permits incorporating MIT, Apache-2.0, BSD, ISC and MPL-2.0 code. Every
planned dependency qualifies:

| Dependency | Licence | Compatible |
|---|---|---|
| Tauri | MIT / Apache-2.0 | ✅ |
| russh, russh-sftp | Apache-2.0 | ✅ |
| IronRDP | MIT / Apache-2.0 | ✅ |
| vnc-rs | MIT | ✅ |
| RustCrypto (argon2, chacha20poly1305) | MIT / Apache-2.0 | ✅ |
| rustls | MIT / Apache-2.0 / ISC | ✅ |
| SQLite | Public domain | ✅ |
| React, xterm.js | MIT | ✅ |
| Wasmtime, Extism | Apache-2.0 / BSD-3 | ✅ |

Note the direction: GPL-3.0 code may *use* Apache-2.0 code, not the reverse.
`cargo-deny` enforces the allowlist in CI, and any new dependency requires an
explicit entry in `deny.toml`.

## Consequences

**Positive.** Derivatives stay free software. Users can verify what their
credential manager does. Patent protection. Alignment with mRemoteNG.

**Negative.** Some organisations forbid GPL software outright. Fewer corporate
contributions than a permissive licence would attract. The licence cannot
practically be changed later without unanimous contributor agreement — the
Contributor Licence Agreement question should be settled before the first
external pull request is merged.

**Plugins.** WebAssembly plugins are covered by an explicit §7 additional
permission and may carry any licence — see
[ADR-0009](0009-plugin-licence-exception.md) and
[`LICENSE-EXCEPTION`](../../../LICENSE-EXCEPTION). The core, and every fork of
it, remains GPL.

## Revisit if

The plugin ecosystem or a specific institutional adoption blocker makes the
licence a demonstrable obstacle — and even then, relicensing requires every
contributor's agreement, so the practical answer is usually a narrow exception
rather than a change.
