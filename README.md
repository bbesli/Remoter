<div align="center">

# Remoter

**A modern, cross-platform remote connection manager.**

RDP · SSH · VNC · SFTP · FTP — every session in a tab, every secret in a vault you control.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Status: Design](https://img.shields.io/badge/status-design%20phase-orange.svg)](docs/roadmap.md)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](#platform-support)

</div>

---

> **Project status: design phase.** This repository currently contains the
> specification, architecture and security design. No application code has been
> written yet. See the [roadmap](docs/roadmap.md) for what lands when, and
> [CONTRIBUTING.md](CONTRIBUTING.md) if you want to help build it.

## What is Remoter?

Remoter is a connection manager for people who administer more than one machine.
It keeps an organised, searchable tree of servers, network devices and cloud
instances, stores their credentials in an encrypted vault, and opens every
protocol — RDP, SSH, VNC, SFTP — inside a single tabbed window.

It is a spiritual successor to tools like mRemoteNG and Royal TS, rebuilt around
three commitments:

1. **Real cross-platform parity.** Linux, Windows and macOS are first-class
   targets, not ports. The same vault file opens everywhere.
2. **Cryptography you can audit.** Secrets are protected by an envelope scheme
   with independent key slots (password, key file, hardware key, recovery key).
   The design is written down in [docs/security/](docs/security/) before a line
   of it is implemented.
3. **Extensibility by design.** Protocols, importers and credential backends sit
   behind stable interfaces. Third-party plugins run in a WebAssembly sandbox
   with explicitly granted capabilities.

## Feature overview

### Connections
- Hierarchical folder tree with drag-and-drop organisation
- **Property inheritance** — set a credential, gateway or port on a folder and
  every connection beneath it inherits, with per-field override
- Reusable credential sets, decoupled from the connections that use them
- Fast fuzzy search, tags, favourites and recently-used
- Bulk edit and multi-select actions

### Protocols
| Protocol | Transport | Status |
|---|---|---|
| SSH (shell, exec, PTY) | `russh` — pure Rust | Planned v0.2 |
| SFTP | `russh-sftp` | Planned v0.2 |
| RDP | `IronRDP` — pure Rust | Planned v0.3 |
| VNC / RFB | `vnc-rs` | Planned v0.4 |
| FTP / FTPS | `suppaftp` | Planned v0.5 |
| Telnet, Serial, Local shell | native | Planned post-1.0 |
| HTTP/HTTPS panel, PowerShell, Kubernetes, Docker | plugin | Post-1.0 |

Every session opens as a tab. Tabs can be split, detached into their own window,
grouped and reordered.

### Networking
- SSH tunnels: local (`-L`), remote (`-R`) and dynamic SOCKS (`-D`) forwarding
- **Jump host chains** — connect through one or more bastions, with per-hop
  credentials, for any protocol (not just SSH)
- SSH agent integration (`ssh-agent`, `gpg-agent`, Pageant, Windows OpenSSH agent)
- Per-connection proxy configuration

### Security
- Vault encrypted with XChaCha20-Poly1305; key derived with Argon2id
- Multiple independent **key slots**: master password, optional key file,
  FIDO2/WebAuthn hardware key (YubiKey, Nitrokey, SoloKey), OS keychain,
  and a one-time **recovery key**
- Secrets are decrypted only at the moment of use, then zeroed from memory
- Auto-lock on idle, on screen lock and on suspend
- Host key and TLS certificate pinning with an explicit trust-on-first-use prompt

### Auditing
- SSH session recording in [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/)
  format — replayable, greppable, diffable
- Graphical session recording for RDP/VNC
- Local append-only audit log: what connected where, when, as whom, and for how long

### Migration
Import from mRemoteNG (`confCons.xml`), Royal TS, PuTTY, Remote Desktop Connection
Manager, `~/.ssh/config`, and CSV. Export to a documented, portable format so you
are never locked in.

### Interface
- Modern UI built with React and Tailwind; light, dark and high-contrast themes
- Full keyboard navigation and a command palette
- **10 languages**: English, 简体中文, Español, हिन्दी, العربية (RTL), Português (BR),
  Русский, Français, Deutsch, Türkçe

## Platform support

| | Linux | Windows | macOS |
|---|---|---|---|
| Minimum | glibc 2.35+ (WebKitGTK 2.38+) | Windows 10 1809+ | macOS 12+ |
| Packages | AppImage, `.deb`, `.rpm`, Flatpak | `.msi`, NSIS installer, portable `.zip` | `.dmg` (universal) |
| Architectures | x86_64, aarch64 | x86_64, aarch64 | x86_64, aarch64 |

## Architecture at a glance

```
┌──────────────────────────────────────────────────────────┐
│  Web frontend  (React · TypeScript · Tailwind · xterm.js)│
│  connection tree · tabs · terminal · framebuffer canvas   │
└───────────────────────────┬──────────────────────────────┘
                            │  Tauri IPC (typed commands, raw byte payloads)
┌───────────────────────────┴──────────────────────────────┐
│  Rust core                                                │
│                                                           │
│  remoter-vault    envelope crypto, key slots, storage     │
│  remoter-core     connection tree, inheritance resolution │
│  remoter-proto    Protocol trait + session supervisor     │
│    ├─ ssh (russh)   ├─ rdp (IronRDP)   ├─ vnc (vnc-rs)    │
│  remoter-tunnel   port forwarding, jump host chains       │
│  remoter-record   asciicast + framebuffer recording       │
│  remoter-plugin   WebAssembly host (Extism / Wasmtime)    │
└───────────────────────────────────────────────────────────┘
```

Read the full design in [docs/architecture/overview.md](docs/architecture/overview.md).

## Why Tauri and Rust?

Because a tool that holds every credential you own should be small, memory-safe
and inspectable. The Rust core gives us memory-safe protocol parsers and a
first-class cryptography ecosystem; Tauri gives us a native, ~15 MB binary
instead of a 150 MB bundled browser. The reasoning, including what we gave up,
is recorded in [ADR-0001](docs/architecture/decisions/0001-technology-stack.md).

## Documentation

| Document | What it covers |
|---|---|
| [Architecture overview](docs/architecture/overview.md) | System design, crate layout, data flow |
| [Architecture decisions](docs/architecture/decisions/) | ADRs — every significant choice and its trade-offs |
| [Threat model](docs/security/threat-model.md) | What we defend against, and what we do not |
| [Vault format](docs/security/vault-format.md) | On-disk format, key slots, recovery key |
| [Data model](docs/architecture/data-model.md) | Connections, folders, credentials, inheritance |
| [Session pipeline](docs/architecture/session-pipeline.md) | How a click becomes a live remote session |
| [Plugin system](docs/architecture/plugin-system.md) | WebAssembly ABI, capabilities, sandbox |
| [Roadmap](docs/roadmap.md) | Milestones from v0.1 to v1.0 and beyond |
| [Getting started](docs/development/getting-started.md) | Toolchain setup and first build |
| [Glossary](docs/glossary.md) | Terms used throughout the docs |

## Contributing

Contributions are welcome — especially protocol work, cryptography review,
translations and platform packaging. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[good first issue](https://github.com/bbesli/Remoter/labels/good%20first%20issue)
label.

If you believe you have found a security vulnerability, please **do not** open a
public issue. Follow [SECURITY.md](SECURITY.md) instead.

## Licence

Remoter is free software, licensed under the
[GNU General Public License v3.0](LICENSE). You may use, study, share and modify
it; if you distribute a modified version, it must remain free software under the
same licence.
