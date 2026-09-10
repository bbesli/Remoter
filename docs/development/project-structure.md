# Project Structure

Where code goes, and the rules that keep it there.

```
Remoter/
├── crates/
│   ├── remoter-core/          Domain model, tree, inheritance
│   ├── remoter-vault/         Crypto, key slots, storage, migrations
│   ├── remoter-proto/         Protocol trait, session supervisor
│   ├── remoter-proto-ssh/
│   ├── remoter-proto-sftp/
│   ├── remoter-proto-rdp/
│   ├── remoter-proto-vnc/
│   ├── remoter-tunnel/        Forwarding, jump host chains
│   ├── remoter-import/        Foreign format parsers
│   ├── remoter-record/        Recording, audit log
│   ├── remoter-plugin/        WASM host
│   └── remoter-ipc/           Tauri command surface
├── apps/
│   ├── desktop/
│   │   ├── src-tauri/         Tauri shell — thin
│   │   └── ui/                React frontend
│   └── cli/                   Headless companion
├── locales/                   Translation catalogs
├── docs/                      Specifications
├── tests/
│   ├── fixtures/              Docker compose, sample import files
│   └── e2e/                   WebDriver end-to-end tests
├── fuzz/                      cargo-fuzz targets
├── .github/workflows/         CI
├── deny.toml                  Licence and advisory policy
├── Cargo.toml                 Workspace root
├── CLAUDE.md                  Agent working guide
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── README.md
```

## Layering

```
apps/ ──▶ remoter-ipc ──▶ remoter-proto-* ──▶ remoter-proto ──▶ remoter-core
                     └──▶ remoter-vault ────────────────────────┘
```

Dependencies point downward only. `remoter-core` and `remoter-vault` are leaves
and depend on no other workspace crate.

Wanting an upward dependency means the abstraction is in the wrong place: define
a trait in the lower crate and implement it above. This is enforced by
`cargo-deny`'s dependency bans, not by good intentions.

## Crate anatomy

```
crates/remoter-vault/
├── src/
│   ├── lib.rs           Public API and re-exports only
│   ├── error.rs         thiserror types for this crate
│   ├── crypto/          Primitives; the most closely reviewed code
│   ├── slots/           Key slot implementations, one file per kind
│   ├── storage/         SQLite access
│   └── migrations/      Numbered SQL, embedded
├── tests/               Integration tests
├── benches/             Criterion benchmarks (KDF calibration lives here)
└── Cargo.toml
```

`lib.rs` contains no logic. It declares the public surface, which makes the
crate's API reviewable in one file.

## Frontend anatomy

```
apps/desktop/ui/src/
├── main.tsx
├── app/
│   ├── router.tsx
│   └── providers.tsx
├── features/            One directory per feature — the primary organisation
│   ├── vault/
│   ├── connections/
│   ├── sessions/
│   ├── terminal/
│   ├── framebuffer/
│   ├── transfer/
│   ├── import/
│   └── settings/
├── components/          Shared, presentational, feature-agnostic
├── lib/
│   ├── ipc.ts           Typed Tauri command wrappers — the only place
│   │                    `invoke` is called
│   ├── i18n.ts
│   └── utils.ts
├── hooks/
├── stores/              Zustand
└── styles/
    └── tokens.css
```

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
| A new screen | `apps/desktop/ui/src/features/<feature>/` |
| A shared button variant | `apps/desktop/ui/src/components/` |
| A new Tauri command | `crates/remoter-ipc/` + a wrapper in `lib/ipc.ts` |
| Business logic | A `crates/` crate — never `src-tauri/`, never the frontend |
| A user-visible string | `locales/en/<namespace>.json` |
