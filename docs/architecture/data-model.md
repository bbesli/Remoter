# Data Model

How connections, folders and credentials are shaped, and how property
inheritance works — the feature that makes a connection manager useful at scale
rather than a bookmark list.

## The node tree

Everything the user organises is a **node**. Nodes form a tree.

```
Vault: "Acme Production"
│
├─ 📁 Datacentre EU-West              ← Folder: gateway, credentials, timezone
│  ├─ 📁 Web tier                     ← Folder: inherits, overrides port
│  │  ├─ 🖥  web-01.eu.acme.internal   ← Connection: SSH
│  │  ├─ 🖥  web-02.eu.acme.internal
│  │  └─ 🖥  web-lb.eu.acme.internal
│  ├─ 📁 Database tier
│  │  ├─ 🖥  db-primary                ← Connection: SSH + SFTP + RDP
│  │  └─ 🖥  db-replica
│  └─ 🔑 svc-deploy                    ← Credential: used by everything above
│
├─ 📁 Customer sites
│  └─ 📁 Contoso
│     ├─ 🖥  ctso-dc01                 ← Connection: RDP
│     └─ 🔑 CONTOSO\admin
│
└─ 🖥  jump.acme.io                    ← Connection: SSH, used as a gateway
```

```rust
pub struct Node {
    pub id: NodeId,               // UUIDv7 — time-ordered, sync-friendly
    pub parent_id: Option<NodeId>,
    pub sort_order: i64,
    pub kind: NodeKind,
    pub name: String,
    pub description: String,
    pub tags: Vec<Tag>,
    pub icon: Option<IconRef>,
    pub colour: Option<Colour>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub revision: u64,            // monotonic; bound into secret AAD
}

pub enum NodeKind {
    Folder(FolderProps),
    Connection(ConnectionProps),
    Credential(CredentialProps),
    Group(GroupProps),      // opens several connections at once
    Separator,              // visual only
}
```

Four notes on that struct:

- **UUIDv7, not an autoincrement.** Time-ordered so tree inserts stay
  index-friendly, globally unique so a future merge of two vaults cannot
  collide.
- **`revision` from day one.** It is bound into the AAD of every encrypted
  secret field, which is what makes rollback attacks detectable. It also gives
  future synchronisation a causality handle for free.
- **`parent_id` plus `sort_order`, not a materialised path.** Moving a subtree is
  one row update. Path reconstruction is a recursive CTE, which SQLite handles
  well at the scale a human curates.
- **Credentials are nodes.** They live in the tree, are organised in folders, and
  are inherited like any other property. That is what makes them shareable
  between hundreds of connections without duplication.

## Property inheritance

This is the core mechanism. Every inheritable field is a three-state value:

```rust
pub enum Inherited<T> {
    /// Take the nearest ancestor's effective value.
    Inherit,
    /// Use this value, and pass it down to descendants.
    Explicit(T),
    /// Use the type's default and stop inheriting here.
    Default,
}
```

Resolution walks from the node to the root and takes the first `Explicit` value:

```rust
/// Pure function. No I/O, no allocation of the tree — fully unit-testable
/// and property-tested with proptest.
pub fn resolve<T: Clone + Default>(
    node: &Node,
    ancestors: &[Node],           // ordered nearest → root
    field: impl Fn(&Node) -> &Inherited<T>,
) -> Resolved<T> {
    match field(node) {
        Inherited::Explicit(v) => Resolved::own(v.clone()),
        Inherited::Default     => Resolved::default_at(node.id),
        Inherited::Inherit => {
            for a in ancestors {
                match field(a) {
                    Inherited::Explicit(v) => return Resolved::from(a.id, v.clone()),
                    Inherited::Default     => return Resolved::default_at(a.id),
                    Inherited::Inherit     => continue,
                }
            }
            Resolved::default_at_root()
        }
    }
}
```

`Resolved<T>` carries **where the value came from**, which the UI uses to show
the user why a field has the value it does:

```
Username    ┌──────────────────────────────────────┐
            │ svc-deploy                           │  ⓘ Inherited from
            └──────────────────────────────────────┘     📁 Datacentre EU-West
                                                          [Override here]
```

That provenance display is not a nicety. Inheritance without visible provenance
is the single most common source of "why did it connect as the wrong user?"
support questions in tools that have this feature.

### What is inheritable

| Category | Fields |
|---|---|
| Identity | Credential reference, username, domain |
| Network | Port, gateway/jump host chain, proxy, connection timeout, keep-alive |
| Protocol | Per-protocol defaults — colour depth, resolution, encodings, terminal type |
| Security | Redirection policy, agent forwarding, TLS pinning mode, legacy-algorithm opt-in |
| Behaviour | Auto-reconnect, on-connect script, on-disconnect script |
| Presentation | Icon, colour, terminal theme, font size |
| Compliance | Recording policy, audit tags |

### What is never inheritable

Hostname and node name — inheriting a hostname would produce two nodes that
silently point at the same machine, which is confusing and dangerous. Each
connection names its own target.

### Precedence

```
Session-time override  (the "Connect as…" dialog, this session only)
        ↓
Node's own Explicit value
        ↓
Nearest ancestor with an Explicit value      ← walking up the tree
        ↓
Protocol adapter default
        ↓
Application default
```

## Connections

```rust
pub struct ConnectionProps {
    pub protocol: ProtocolId,           // "ssh" | "rdp" | "vnc" | "sftp" | "vendor.x"
    pub host: String,                   // never inherited
    pub port: Inherited<u16>,
    pub credential: Inherited<CredentialRef>,
    pub gateway: Inherited<GatewayChain>,
    pub settings: ProtocolSettings,     // validated against the adapter's schema
    pub on_connect: Inherited<Vec<Action>>,
    pub on_disconnect: Inherited<Vec<Action>>,
    pub recording: Inherited<RecordingPolicy>,
    pub auto_reconnect: Inherited<ReconnectPolicy>,
}

pub struct GatewayChain {
    /// Ordered list of hops. Empty = direct connection.
    pub hops: Vec<GatewayHop>,
}

pub struct GatewayHop {
    pub node: NodeRef,                  // another Connection node, reused
    pub credential: Option<CredentialRef>,  // else the hop node's own
}
```

`ProtocolSettings` is a validated map rather than a fixed struct. Each adapter
publishes a `SettingsSchema`; the UI renders the form from it, importers
validate against it, and plugin protocols get exactly the same treatment as
built-ins. Unknown keys are preserved on round-trip so that opening a vault in
an older build does not silently discard a newer protocol's settings.

## Credentials

```rust
pub struct CredentialProps {
    pub username: String,
    pub domain: Option<String>,
    pub secret: SecretKind,
    pub totp: Option<TotpConfig>,          // for keyboard-interactive 2FA
    pub expires_at: Option<Timestamp>,     // rotation reminder, not enforcement
}

pub enum SecretKind {
    Password(EncryptedField),
    PrivateKey {
        key:        EncryptedField,
        passphrase: Option<EncryptedField>,
        format:     KeyFormat,             // OpenSSH | PKCS#8 | PuTTY PPK
    },
    /// Delegated to the platform agent — no key material stored at all.
    Agent { comment_filter: Option<String> },
    /// Delegated to an external provider via plugin (Vault, Bitwarden, 1Password).
    External { provider: String, reference: String },
    /// Certificate-based (SSH certificates, smart cards)
    Certificate { cert: EncryptedField, key: EncryptedField },
}
```

`EncryptedField` is never plaintext in memory unless actively borrowed:

```rust
pub struct EncryptedField {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub alg: AeadAlg,
}
```

`Agent` is worth highlighting as the recommended option for SSH: the private key
stays in the platform agent and never enters Remoter's address space at all.

## Groups

A `Group` opens several connections at once, into a chosen layout.

```rust
pub struct GroupProps {
    pub members: Vec<NodeRef>,
    pub layout: GroupLayout,    // Tabs | SplitH | SplitV | Grid(rows, cols)
    pub broadcast: bool,        // send keystrokes to every terminal member
}
```

`broadcast` — typing once into several SSH sessions — is genuinely useful and
genuinely dangerous. It is off by default, shows a persistent, unmissable banner
while active, and is disabled entirely for sessions whose folder carries a
`production` tag unless explicitly permitted.

## Referential integrity

- Deleting a credential that connections reference: the UI lists every affected
  connection and requires confirmation. The reference becomes a tombstone, not a
  dangling id, so the connection reports "credential deleted" rather than
  silently falling back to inherited values.
- Deleting a connection used as a gateway hop: same treatment.
- Cycles in gateway chains are rejected at edit time and re-validated at connect
  time, with a depth limit of 8 hops.
- Moving a node re-resolves inheritance for its whole subtree, and the UI shows a
  diff of what will change before the move is applied. Silent behaviour changes
  from a drag-and-drop are exactly the sort of thing that erodes trust in a
  tool.

## Validation

Enforced in `remoter-core`, not in the UI, so importers and the CLI get the same
guarantees:

| Rule | Enforcement |
|---|---|
| Node names non-empty, ≤ 255 chars | Reject |
| Hostname is a valid DNS name, IPv4, or bracketed IPv6 | Reject |
| Port in 1–65535 | Reject |
| Folder cannot be its own ancestor | Reject |
| Tree depth ≤ 64 | Reject |
| Gateway chain length ≤ 8 | Reject |
| Protocol settings match the adapter schema | Reject with the offending key |
| Credential referenced from another vault | Reject |
| Duplicate hostname under one folder | Warn, allow |
| Connection with no credential at any level | Warn, allow (prompt at connect) |

## Extensibility

Three deliberate seams, so that adding capability does not require a schema
migration:

1. **`ProtocolSettings` is schema-driven.** A new protocol adds a schema, not a
   table.
2. **Every node carries a `custom_fields: Map<String, Value>`.** Users can record
   asset tags, ticket references, rack positions; plugins can attach their own
   namespaced data. Preserved verbatim on export and round-trip.
3. **`SecretKind::External`** means a credential can live in HashiCorp Vault,
   Bitwarden or 1Password without the core knowing those products exist.
