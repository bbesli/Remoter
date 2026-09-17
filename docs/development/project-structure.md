# Project Structure

Where code goes, and the rules that keep it there. This is the tree as it is,
not as it was planned — see **Crates that were planned and do not exist** below
for the four that earlier drafts listed.

```
Remoter/
├── crates/
│   ├── remoter-core/          Domain model, tree, inheritance
│   ├── remoter-vault/         Crypto, key slots, storage, migrations, audit log
│   ├── remoter-proto/         Protocol trait, session supervisor, framebuffer
│   │                          contract, gateway chains
│   ├── remoter-proto-ssh/     SSH, SFTP, port forwarding, the SOCKS5 server
│   ├── remoter-proto-rdp/     RDP, CredSSP/NTLMv2
│   ├── remoter-proto-vnc/     VNC / RFB, handshake owned here (ADR-0013)
│   ├── remoter-import/        Foreign format parsers, and the exporters
│   ├── remoter-plugin-abi/    Plugin ABI types and wire format  (Apache-2.0 OR MIT)
│   ├── remoter-plugin-sdk/    Guest-side helpers for plugin authors (Apache-2.0 OR MIT)
│   └── remoter-ipc/           Tauri command surface
├── apps/
│   └── desktop/
│       ├── src-tauri/         Tauri shell — thin
│       └── ui/                React frontend
├── locales/                   Translation catalogs, one directory per language
├── docs/                      Specifications
├── ui_parts/                  The interface designs the frontend was built from
├── fuzz/                      cargo-fuzz targets (the eight importers)
├── scripts/                   install-local, uninstall-local, dev-sshd,
│                              check-source-is-text
├── .github/workflows/         ci.yml and release.yml
├── deny.toml                  Licence and advisory policy
├── LICENSE-EXCEPTION          GPL-3.0 §7 permission for WASM plugins
├── Cargo.toml                 Workspace root
├── CHANGELOG.md
├── CLAUDE.md                  Agent working guide
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── README.md
```

There is no `tests/` directory: integration tests live in each crate's own
`tests/`, and there are no WebDriver end-to-end tests. There is no `apps/cli`.

## Crates that were planned and do not exist

Four crates appear in older drafts of this document and in
[architecture/overview.md](../architecture/overview.md). None was ever created,
and three of the four have their work somewhere else.

| Planned crate | Where the work actually is |
|---|---|
| `remoter-proto-sftp` | `remoter-proto-ssh/src/sftp.rs` — it is a subsystem on an SSH channel, and a separate crate would have to re-export `SshConnection` |
| `remoter-tunnel` | `remoter-proto-ssh/src/{forward,socks,bind}.rs`, with the node-level surface in `remoter-ipc/src/tunnel.rs`. The genuinely protocol-agnostic part, the hop-chain builder, is in `remoter-proto/src/gateway.rs` |
| `remoter-record` | Only its audit-log half exists, as `remoter-vault/src/{audit,storage}.rs` — the log is a table in the vault body. **Recording does not exist at all** |
| `remoter-plugin` | Nowhere. `remoter-plugin-abi` and `remoter-plugin-sdk` define the boundary; nothing loads a WebAssembly module |

A new protocol still gets `crates/remoter-proto-<name>/`. Do not create the
crates above until something needs to go in them.

## Layering

```
apps/ ──▶ remoter-ipc ──▶ remoter-proto-* ──▶ remoter-proto ──▶ remoter-core
                     └──▶ remoter-vault ────────────────────────┘
```

Dependencies point downward only, and the tree satisfies this today.
`remoter-core` is the only true leaf; `remoter-vault` depends on it, and
`remoter-proto` additionally depends on `remoter-plugin-abi` for the capability
and settings types a plugin protocol would have to speak.

Wanting an upward dependency means the abstraction is in the wrong place: define
a trait in the lower crate and implement it above. This is enforced by
`cargo-deny`'s dependency bans, not by good intentions — `deny.toml` bans
`remoter-core` with an explicit allow-list of dependents, which is what makes the
day `remoter-plugin-abi` or `remoter-plugin-sdk` grows a dependency on
GPL-3.0-or-later `remoter-core` a CI failure rather than a licensing accident.

## Crate anatomy

```
crates/remoter-vault/
├── src/
│   ├── lib.rs           Public API and re-exports only
│   ├── error.rs         thiserror types for this crate
│   ├── crypto.rs        Primitives; the most closely reviewed code
│   ├── slots.rs         Key slot implementations
│   ├── storage.rs       SQLite access
│   └── …
├── migrations/          Numbered SQL, embedded
├── tests/               Integration tests
└── Cargo.toml
```

Modules are files rather than directories while they fit in one; `crypto/`,
`slots/` and `storage/` become directories when they stop fitting. There are no
`benches/` anywhere — KDF calibration is a constant in `crypto.rs` with a test
that fails if the floor is lowered, not a Criterion benchmark.

`lib.rs` contains no logic. It declares the public surface, which makes the
crate's API reviewable in one file.

## Frontend anatomy

```
apps/desktop/ui/src/
├── main.tsx
├── app/
│   ├── App.tsx
│   └── queryClient.ts
├── features/            One directory per feature — the primary organisation
│   ├── vault/           Picker, unlock, create
│   ├── vaultsettings/   Key slots, rotation, per-vault settings
│   ├── connections/     Tree, editor, command palette
│   ├── sessions/        Tabs, terminal, framebuffer, tunnels, prompts
│   ├── files/           The SFTP file manager
│   ├── import/          The import wizard
│   ├── audit/           The audit log viewer
│   ├── settings/        Application settings
│   └── shell/           Main window, sidebar, footer
├── components/          Shared, presentational, feature-agnostic
├── i18n/                The localisation layer; `useT` is the only accessor
├── lib/
│   ├── ipc.ts           Typed Tauri command wrappers — the only place
│   │                    `invoke` is called
│   ├── queryKeys.ts
│   └── terminalPalette.ts
├── hooks/
├── stores/              Zustand
└── styles/
    ├── base.css
    └── tokens.css
```

Styling is **CSS modules**, one `.module.css` beside each component, over the
tokens in `styles/tokens.css`. Tailwind was the original plan and is not
installed.

**Feature-first, not type-first.** Everything about connections lives in
`features/connections/`, rather than being scattered across `components/`,
`hooks/` and `types/`. Features are how the product changes; file types are not.

`lib/ipc.ts` is the single place `invoke` is called. Every command has a typed
wrapper, generated from the Rust command signatures where possible. A component
calling `invoke` directly is a review rejection.

## Naming

| Thing | Convention | Example |
|---|---|---|
| Crate | `remoter-<area>` | `remoter-proto-ssh` |
| Rust module | `snake_case` | `key_slots` |
| Rust type | `PascalCase` | `EffectiveConnection` |
| Rust function | `snake_case` | `resolve_inheritance` |
| Tauri command | `snake_case`, verb first | `vault_unlock`, `session_open` |
| React component | `PascalCase.tsx` | `ConnectionTree.tsx` |
| Hook | `useCamelCase.ts` | `useSessionEvents.ts` |
| Translation key | `namespace.dotted.key` | `vault.recovery_warning` |
| Migration | `NNN_description.sql` | `002_add_session_history.sql` |

## Where things belong

| If you are adding… | It goes in… |
|---|---|
| A new protocol | `crates/remoter-proto-<name>/`, implementing `Protocol` |
| A new import format | `crates/remoter-import/src/<source>.rs` + a fuzz target |
| A new key slot type | `crates/remoter-vault/src/slots/<kind>.rs` |
| A plugin ABI type or signature | `crates/remoter-plugin-abi/` — **must stay free of GPL dependencies**, enforced in CI |
| A new screen | `apps/desktop/ui/src/features/<feature>/` |
| A shared button variant | `apps/desktop/ui/src/components/` |
| A new Tauri command | `crates/remoter-ipc/` + a wrapper in `lib/ipc.ts` |
| Business logic | A `crates/` crate — never `src-tauri/`, never the frontend |
| A user-visible string | `locales/en/<namespace>.json` |
