# Architecture Overview

## The shape of the problem

A remote connection manager does four things, and each pulls the design in a
different direction:

1. **It stores secrets.** That demands a small, auditable, memory-safe core with
   conservative cryptography and a minimal attack surface.
2. **It speaks hostile protocols.** RDP, SSH, VNC and SFTP parse untrusted bytes
   from machines that may already be compromised. That demands memory safety at
   the parser level and strong process-level isolation.
3. **It renders interactive graphics.** A 1080p RDP session at 30 fps is a video
   pipeline. That demands low-latency, low-copy paths from socket to screen.
4. **It must feel modern.** Tree, tabs, search, theming, ten languages. That
   demands a productive UI toolkit.

Requirements 1 and 2 point at Rust. Requirement 4 points at the web platform.
Requirement 3 is where those two meet, and it is the hardest part of the design
— it is treated explicitly in [rendering.md](rendering.md) and
[ADR-0003](decisions/0003-protocol-embedding.md).

## Layered view

```
╔═══════════════════════════════════════════════════════════════════════╗
║  PRESENTATION — WebView (WebKitGTK / WebView2 / WKWebView)            ║
║                                                                       ║
║   React 19 + TypeScript                                               ║
║   ┌─────────────┬──────────────────────────────┬──────────────────┐  ║
║   │ Connection  │  Tab host                    │  Inspector       │  ║
║   │ tree        │  ├ xterm.js (SSH, serial)    │  properties,     │  ║
║   │ search      │  ├ canvas/WebGL (RDP, VNC)   │  inheritance,    │  ║
║   │ favourites  │  ├ file grid (SFTP, FTP)     │  session stats   │  ║
║   └─────────────┴──────────────────────────────┴──────────────────┘  ║
╚═══════════════════════════════════════╤═══════════════════════════════╝
                                        │
             Tauri IPC ─ typed commands (JSON) for control,
                         raw byte responses + event channels for data
                                        │
╔═══════════════════════════════════════╧═══════════════════════════════╗
║  APPLICATION — remoter-ipc                                            ║
║  Command surface, permission checks, DTO mapping, event fan-out.      ║
║  Holds no business logic; it is the seam, nothing more.               ║
╠═══════════════════════════════════════════════════════════════════════╣
║  DOMAIN                                                               ║
║                                                                       ║
║  remoter-core        node tree · inheritance resolver · validation    ║
║  remoter-proto       Protocol trait · SessionSupervisor · event bus   ║
║  remoter-tunnel      local/remote/dynamic forwards · jump host chains ║
║  remoter-record      asciicast writer · frame recorder · audit log    ║
║  remoter-import      confCons.xml · Royal TS · PuTTY · ssh_config     ║
╠═══════════════════════════════════════════════════════════════════════╣
║  PROTOCOL ADAPTERS                                                    ║
║  proto-ssh (russh) · proto-sftp (russh-sftp)                          ║
║  proto-rdp (IronRDP) · proto-vnc (vnc-rs)                             ║
╠═══════════════════════════════════════════════════════════════════════╣
║  PLATFORM                                                             ║
║  remoter-vault   envelope crypto · key slots · SQLite · migrations    ║
║  remoter-plugin  Wasmtime/Extism host · capability grants             ║
║  OS integration  keychain · FIDO2/HID · agent sockets · idle detect   ║
╚═══════════════════════════════════════════════════════════════════════╝
```

**Dependency direction is strictly downward.** `remoter-core` and
`remoter-vault` are leaves: they depend on no other workspace crate. Anything
that appears to need an upward dependency gets a trait defined in the lower
crate and implemented above it.

## Crate responsibilities

| Crate | Owns | Explicitly does not own |
|---|---|---|
| `remoter-core` | Node tree, inheritance resolution, validation rules, IDs | Any I/O, any crypto, any UI concept |
| `remoter-vault` | Container format, key slots, KDF, AEAD, SQLite storage, migrations | Knowledge of what a "connection" means beyond opaque records |
| `remoter-proto` | `Protocol` trait, `SessionSupervisor`, session lifecycle, event bus | Any specific protocol's wire format |
| `remoter-proto-*` | One protocol each: handshake, framing, capability negotiation | Session policy, retry strategy, UI decisions |
| `remoter-tunnel` | Forward listeners, SOCKS5 server, hop chain construction | Which connection wants a tunnel |
| `remoter-record` | asciicast v2 writer, frame encoder, append-only audit log | Retention policy UI |
| `remoter-import` | Parsers for foreign formats → `remoter-core` types | Writing to the vault |
| `remoter-plugin` | WASM runtime, manifest parsing, capability enforcement | Plugin business logic |
| `remoter-ipc` | Tauri commands, DTOs, event channels, rate limits | Business rules |

## Process and thread model

Remoter is a **single process** with a strict internal task structure. A
multi-process model (one sandboxed process per protocol adapter) is desirable
for isolation and is planned for v2 — see
[ADR-0007](decisions/0007-process-isolation.md) for why it is deferred rather
than done now.

```
main thread
 └─ Tauri event loop, window management, WebView

tokio multi-thread runtime (worker threads = CPU count)
 ├─ SessionSupervisor          owns the session registry
 │   ├─ session task #1        cancellation-token scoped
 │   │   ├─ transport task     socket read/write
 │   │   └─ decode task        protocol state machine → frames/bytes
 │   └─ session task #2 …
 ├─ tunnel listener tasks      one per active forward
 ├─ recorder tasks             one per recorded session, buffered writes
 └─ vault task                 serialised access; the vault is single-writer

blocking pool (spawn_blocking)
 ├─ Argon2id derivation        deliberately CPU-heavy, never on the runtime
 ├─ FIDO2 / HID transactions   blocking USB I/O with user presence waits
 └─ OS keychain calls          platform APIs are synchronous
```

**Invariants.**

- Closing a tab cancels its session token; the session task must release all
  sockets, file handles and recorder buffers before the tab is removed from the
  UI. Leaked sessions are a correctness bug, not a cosmetic one.
- A panic inside a session task is caught at the supervisor boundary. It fails
  one tab, not the process — the vault must never be brought down by a
  malformed frame from a remote host.
- The vault is a single-writer resource. All mutations funnel through one task;
  readers get consistent snapshots.

## Data flow: opening an SSH session through a jump host

```
UI                remoter-ipc      remoter-core     remoter-vault    remoter-tunnel   remoter-proto-ssh
│  open(node_id)      │                 │                 │                │                │
├────────────────────▶│                 │                 │                │                │
│                     │ resolve(node)   │                 │                │                │
│                     ├────────────────▶│                 │                │                │
│                     │  EffectiveConn  │ walks ancestors,│                │                │
│                     │◀────────────────┤ merges inherited│                │                │
│                     │                 │ fields          │                │                │
│                     │ borrow_secret(cred_id, purpose)   │                │                │
│                     ├──────────────────────────────────▶│                │                │
│                     │            Secret<Credential> ────┤ decrypts one   │                │
│                     │                 │                 │ field, in-place│                │
│                     │ build_chain(hops)                 │                │                │
│                     ├───────────────────────────────────────────────────▶│                │
│                     │            authenticated hop 1 ───┤ opens direct-  │                │
│                     │            → hop 2 → target       │ tcpip channels │                │
│                     │ connect(stream, EffectiveConn)                     │                │
│                     ├────────────────────────────────────────────────────────────────────▶│
│                     │                                                    │  handshake,    │
│                     │                                                    │  host key check│
│                     │◀── HostKeyUnknown(fingerprint) ────────────────────────────────────┤
│◀── prompt ──────────┤                                                    │                │
├── trust ───────────▶│                                                    │                │
│                     ├── resume ─────────────────────────────────────────────────────────▶│
│                     │                                                    │  auth, PTY     │
│◀═ SessionEvent::Data (raw bytes, channel) ═════════════════════════════════════════════════
│  xterm.js write     │                                                    │                │
```

Note what happens to the secret: it is borrowed for the duration of
authentication, held in a `Zeroizing` buffer, and dropped as soon as the
handshake completes. **It never crosses the IPC boundary into the WebView.**

## The `Protocol` trait

Every protocol adapter, built-in or plugin, implements one interface. This is
the extension point that makes new protocols cheap.

```rust
/// Illustrative sketch — see remoter-proto for the normative definition.
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Stable identifier: "ssh", "rdp", "vnc", "sftp", or "vendor.myproto".
    fn id(&self) -> ProtocolId;

    /// What this adapter can do — drives which UI affordances appear.
    fn capabilities(&self) -> Capabilities;

    /// Schema for protocol-specific settings, used to render the settings
    /// form and to validate imported configurations.
    fn settings_schema(&self) -> &SettingsSchema;

    /// Establish a session over an already-connected, possibly tunnelled
    /// stream. The adapter never dials out itself — transport is supplied,
    /// so jump hosts, proxies and tunnels work uniformly for every protocol.
    async fn connect(
        &self,
        transport: Box<dyn Transport>,
        config: &EffectiveConnection,
        creds: &dyn CredentialProvider,
        events: EventSink,
        cancel: CancellationToken,
    ) -> Result<Box<dyn Session>, ProtocolError>;
}

pub struct Capabilities {
    pub kind: SessionKind,           // Terminal | Framebuffer | FileTransfer
    pub resizable: bool,
    pub clipboard: ClipboardSupport, // None | Text | TextAndFiles
    pub file_transfer: bool,
    pub audio: bool,
    pub printing: bool,
    pub multi_monitor: bool,
    pub recordable: RecordingSupport,
}

#[async_trait]
pub trait Session: Send {
    async fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ProtocolError>;
    async fn input(&mut self, input: InputEvent) -> Result<(), ProtocolError>;
    async fn clipboard(&mut self, op: ClipboardOp) -> Result<(), ProtocolError>;
    async fn disconnect(self: Box<Self>) -> Result<(), ProtocolError>;
}
```

Two consequences worth stating plainly:

- **Transport is injected, not dialled.** Because `connect` receives a
  `Box<dyn Transport>`, jump host chains, SOCKS proxies and SSH tunnels work
  identically for RDP as they do for SSH. This is the single most important
  design decision in the protocol layer.
- **Capabilities drive the UI.** The frontend does not hardcode "RDP has a
  clipboard". It asks the adapter. A plugin protocol therefore gets the same
  first-class treatment as a built-in one.

## Storage

The vault is a single portable file (`*.rvault`) containing an authenticated
header, a key slot table, and an encrypted SQLite database. The full format is
in [vault-format.md](../security/vault-format.md); the schema and migration
strategy are in [storage.md](storage.md).

Design intent worth flagging here: the schema carries `id` (UUIDv7),
`updated_at` and `revision` columns on every mutable row from v0.1, even though
v1.0 ships with no synchronisation. Retrofitting identity and causality onto an
existing dataset is painful; carrying four unused columns is not.

## Extensibility

Three tiers, deliberately separated by risk:

| Tier | Mechanism | Trust | Available |
|---|---|---|---|
| In-tree | Implement `Protocol` in a workspace crate | Full | v0.2 |
| Sandboxed plugin | WebAssembly module, declared capabilities | None — enforced by sandbox | v1.1 |
| Scripted hook | Pre/post-connect scripts with user-visible commands | User's own | v1.2 |

The plugin ABI is **not** stabilised in v1.0 on purpose. Shipping a stable ABI
before the internal traits have settled would freeze mistakes into a public
contract. See [plugin-system.md](plugin-system.md).

## What this architecture deliberately does not do

- **No cloud service, no telemetry, no account.** There is no server component
  in v1.0 and no phone-home of any kind. Update checks are opt-in and hit a
  static manifest.
- **No browser-based access.** Remoter is a desktop application. A
  Guacamole-style gateway is a fundamentally different product with a much
  larger attack surface; it is out of scope.
- **No credential escrow.** We cannot recover your vault. That is a feature —
  see [key-management.md](../security/key-management.md).
