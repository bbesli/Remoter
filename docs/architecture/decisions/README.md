# Architecture Decision Records

Each ADR records one significant decision: the context that forced it, the
options considered, what was chosen, and what it costs. They are immutable —
when a decision changes, a new ADR supersedes the old one rather than editing
history.

| # | Decision | Status |
|---|---|---|
| [0001](0001-technology-stack.md) | Tauri v2, Rust core, React frontend | Accepted |
| [0002](0002-vault-cryptography.md) | Envelope encryption with independent key slots | Accepted |
| [0003](0003-protocol-embedding.md) | Embed protocols in-process, pure Rust | Accepted |
| [0004](0004-plugin-system.md) | WebAssembly plugins with declared capabilities | Accepted |
| [0005](0005-local-first-storage.md) | Local-first, single encrypted file, sync-ready | Accepted |
| [0006](0006-licensing.md) | GPL-3.0-or-later | Accepted |
| [0007](0007-process-isolation.md) | Single process in v1, isolation deferred | Accepted |
| [0008](0008-internationalisation.md) | Ten languages from v1, ICU MessageFormat, RTL | Accepted |

Copy [0000-template.md](0000-template.md) to start a new one.
