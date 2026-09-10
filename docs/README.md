# Remoter Documentation

This directory is the specification for Remoter. It is written before the code
and kept in step with it: when behaviour changes, the document changes in the
same commit.

## Start here

New to the project? Read in this order:

1. [Architecture overview](architecture/overview.md) — the whole system on one page
2. [Data model](architecture/data-model.md) — how connections and credentials are shaped
3. [Threat model](security/threat-model.md) — what we are actually protecting
4. [Vault format](security/vault-format.md) — the cryptographic core
5. [Roadmap](roadmap.md) — what is being built now

## Map

### Architecture
| Document | Contents |
|---|---|
| [overview.md](architecture/overview.md) | Layers, crates, processes, data flow |
| [data-model.md](architecture/data-model.md) | Node tree, credentials, property inheritance |
| [session-pipeline.md](architecture/session-pipeline.md) | From click to live session, hop by hop |
| [rendering.md](architecture/rendering.md) | Terminal and framebuffer rendering, IPC transport |
| [plugin-system.md](architecture/plugin-system.md) | WebAssembly ABI, capabilities, sandbox |
| [storage.md](architecture/storage.md) | SQLite schema, migrations, sync-readiness |
| [decisions/](architecture/decisions/) | Architecture Decision Records (0001–0012) |

### Security
| Document | Contents |
|---|---|
| [threat-model.md](security/threat-model.md) | Assets, adversaries, scope, non-goals |
| [vault-format.md](security/vault-format.md) | On-disk container, key slots, KDF parameters |
| [key-management.md](security/key-management.md) | Unlock flows, recovery key, rotation, auto-lock |
| [transport-security.md](security/transport-security.md) | Host keys, TLS, pinning, NLA |

### Features
| Document | Contents |
|---|---|
| [connections.md](features/connections.md) | Tree, search, tags, bulk operations |
| [protocols.md](features/protocols.md) | Per-protocol capability matrix and settings |
| [tunneling.md](features/tunneling.md) | Port forwarding, SOCKS, jump host chains |
| [import-export.md](features/import-export.md) | Migration from other tools |
| [recording-audit.md](features/recording-audit.md) | Session recording and the audit log |
| [i18n.md](features/i18n.md) | Supported languages, RTL, translation workflow |

### Interface
| Document | Contents |
|---|---|
| [information-architecture.md](ui/information-architecture.md) | Screens, navigation, keyboard model |
| [design-system.md](ui/design-system.md) | Tokens, theming, accessibility targets |

### Development
| Document | Contents |
|---|---|
| [getting-started.md](development/getting-started.md) | Toolchain, first build, per-platform setup |
| [project-structure.md](development/project-structure.md) | Where code goes and why |
| [coding-standards.md](development/coding-standards.md) | Rust and TypeScript conventions |
| [testing-strategy.md](development/testing-strategy.md) | Unit, property, fuzz, integration, E2E |
| [build-release.md](development/build-release.md) | CI matrix, packaging, signing, updates |

### Reference
| Document | Contents |
|---|---|
| [roadmap.md](roadmap.md) | Milestones and their exit criteria |
| [glossary.md](glossary.md) | Vocabulary used across these documents |
| [prior-art.md](prior-art.md) | What we learned from mRemoteNG, Royal TS, and others |

## Conventions used in these documents

- **MUST / SHOULD / MAY** carry their [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
  meanings.
- Code blocks marked `rust` in design documents are *illustrative sketches*, not
  compiled source, unless stated otherwise.
- Open questions are marked **`OPEN:`** and are tracked as issues. A document
  with no open questions is not necessarily finished — it is merely unblocked.
