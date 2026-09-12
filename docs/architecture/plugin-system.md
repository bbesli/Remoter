# Plugin System

Third-party extensions run as WebAssembly modules in a sandbox with no ambient
authority. This document specifies what they can do, how they ask, and what the
host guarantees.

> **Status: designed, not built.** `remoter-plugin-abi` and `remoter-plugin-sdk`
> exist and define the boundary's types and the guest-side helpers. **There is no
> host.** No `remoter-plugin` crate, no Wasmtime or Extism dependency, no
> manifest parser, no capability enforcement, no plugin manager screen — nothing
> loads a WebAssembly module, and `session_open` refuses a plugin protocol by
> name because no adapter in this workspace speaks it. Everything below except
> the two ABI crates and the licence arrangement is specification.
>
> The plugin ABI is then to ship as *unstable* in v1.1 and be stabilised no
> earlier than v1.2. Freezing a public contract before the internal traits have
> settled would preserve our early mistakes forever.

## Why WebAssembly

The alternatives and why they lose:

| Approach | Verdict |
|---|---|
| Native dynamic libraries (`.so`/`.dll`) | A plugin gets full process memory — including the vault key. Unacceptable for this application |
| Embedded scripting (Lua, Rhai) | Sandboxable, but single-language and slow for protocol work |
| Subprocess with IPC | Good isolation, but a per-platform packaging and distribution problem for every plugin |
| **WebAssembly (Wasmtime)** | **Chosen.** Memory-isolated by construction, capability-based, cross-platform, language-agnostic, fast enough for protocol decoding |

We use **Extism**, which is Wasmtime plus the plumbing a plugin host actually
needs: host function linking, memory management across the boundary, fuel
metering and timeouts. Building that layer ourselves would be reinventing it
worse.

## Plugin kinds

| Kind | Provides | Milestone |
|---|---|---|
| **Protocol** | A new `Protocol` implementation — Telnet, serial, a vendor console | v1.1 |
| **Importer** | Parse a foreign format into node trees | v1.1 |
| **Credential provider** | Back `SecretKind::External` — HashiCorp Vault, Bitwarden, 1Password, cloud secret managers | v1.1 |
| **Action** | Commands in the palette and context menus; connect/disconnect hooks | v1.2 |
| **Panel** | A custom UI surface in a tab or the inspector | v1.3 |
| **Theme** | Colour tokens and terminal palettes — declarative, no code | v1.0 |

Themes need no sandbox because they are data. Everything else runs in WASM.

## Manifest

```toml
# plugin.toml
[plugin]
id          = "com.example.telnet"
name        = "Telnet"
version     = "1.2.0"
abi          = "1"                       # plugin ABI version, not app version
authors     = ["Example Corp"]
license     = "GPL-3.0-or-later"
homepage    = "https://example.com/telnet"
description = "Telnet and rlogin sessions"

[plugin.provides]
protocols = ["telnet", "rlogin"]

# Every capability must be declared. Undeclared calls fail — they do not
# silently no-op, because a plugin that appears to work while doing nothing
# is worse than one that fails loudly.
[capabilities]
network.outbound = ["tcp"]               # dial TCP; host-supplied transports only
storage.local    = "1MiB"                # private key-value store, per plugin
config.read      = true                  # read its own settings
ui.notify        = true                  # post notifications

# NOT granted, and not grantable:
#   filesystem access of any kind
#   process spawning
#   access to other plugins' storage
#   the vault master key, or any key material
#   arbitrary IPC to the frontend
```

At install time the user sees the capabilities in plain language, not TOML:

```
  Telnet  v1.2.0  ·  Example Corp  ·  GPL-3.0

  This plugin will be able to:
    • Open TCP connections to hosts you connect to
    • Store up to 1 MB of its own settings
    • Show notifications

  It will NOT be able to:
    • Read your files
    • Read your passwords or keys
    • Run programs on your computer
    • See connections you do not open with it

                              [Cancel]  [Install]
```

## Host interface

Host functions the plugin may call, subject to its grants:

```
host_log(level, message)                     always available
host_config_get(key) -> value                config.read
host_storage_get(key) -> bytes               storage.local
host_storage_set(key, bytes)                 storage.local
host_notify(level, title, body)              ui.notify
host_transport_read(handle, len) -> bytes    network.outbound
host_transport_write(handle, bytes) -> n     network.outbound
host_credential_request(purpose) -> handle   mediated — see below
host_credential_use(handle, operation)       mediated — see below
```

Exports the plugin provides depend on its kind. A protocol plugin exports:

```
plugin_manifest() -> json
protocol_capabilities(protocol_id) -> json
protocol_settings_schema(protocol_id) -> json
session_open(transport_handle, config_json) -> session_handle
session_input(session_handle, input_bytes)
session_resize(session_handle, cols, rows)
session_poll(session_handle) -> event_bytes
session_close(session_handle)
```

## Credentials are mediated, never handed over

This is the most important rule in the design. **A plugin never receives a
password, a private key, or the vault master key.** It receives an opaque handle
and asks the host to perform operations with it.

```
plugin                          host                          user
  │  host_credential_request(     │                             │
  │    purpose: SshPassword,      │                             │
  │    host: "10.0.0.5")          │                             │
  ├──────────────────────────────▶│                             │
  │                               │  policy check: does this    │
  │                               │  plugin have a grant for    │
  │                               │  this connection?           │
  │                               ├────── prompt if needed ────▶│
  │                               │◀───── allow / deny ─────────┤
  │◀───── handle: 0x7f ───────────┤                             │
  │                               │                             │
  │  host_credential_use(0x7f,    │                             │
  │    Sign { data })             │                             │
  ├──────────────────────────────▶│  host performs the          │
  │◀───── signature ──────────────┤  operation with the real    │
  │                               │  key; key never crosses     │
  │                               │  the WASM boundary          │
```

For password authentication where the protocol genuinely requires the plaintext
on the wire, the host performs the authentication step itself through a
protocol-specific hook, rather than releasing the password into the sandbox.
Where that is not possible, the capability is simply not offered — we would
rather not support a protocol than lie about the isolation.

Credential handles are scoped to a single session and revoked when it closes.

## Resource limits

| Limit | Default |
|---|---|
| Linear memory | 64 MiB |
| Fuel per host call | 100 M instructions |
| Wall clock per host call | 5 s |
| Concurrent sessions per plugin | 16 |
| Private storage | as declared, ≤ 16 MiB |
| Outbound connections | Host-supplied transports only; a plugin cannot dial arbitrary addresses |

Exceeding a limit terminates the plugin instance and surfaces a clear error. A
runaway plugin fails its own sessions; it does not degrade the application.

## Distribution and trust

- Plugins are `.wasm` files with a detached signature and a manifest
- v1.1: manual installation from a file, with the capability prompt above
- v1.2: an optional registry — a signed index in a Git repository, no server
  component, no accounts
- Plugins are **not** auto-updated. An update re-prompts if it requests any new
  capability
- Every plugin's id, version and hash appear in the audit log when it is loaded

## Licensing

**Plugins may carry any licence, including a proprietary one.** This is settled
by [ADR-0009](decisions/0009-plugin-licence-exception.md) and rests on two
things rather than on an argument about derivative works:

1. **The crates a plugin author compiles against are permissively licensed.**
   `remoter-plugin-abi` (types, signatures, wire format) and
   `remoter-plugin-sdk` (guest-side helpers and macros) are **Apache-2.0 OR
   MIT**. A plugin author never incorporates a line of GPL source. Only the
   host-side runtime, `remoter-plugin`, is GPL-3.0.

2. **An explicit additional permission under GPL-3.0 §7**, published as
   [`LICENSE-EXCEPTION`](../../LICENSE-EXCEPTION) in the repository root,
   granting permission to combine the Program with WebAssembly modules that
   interact solely through the published ABI.

The exception is deliberately narrow. It does **not** cover forks or
modifications of Remoter itself, which remain GPL in full; it does **not** cover
a plugin that incorporates Remoter source beyond the two permissive crates; and
it does **not** cover native code loaded into the process, which is not
supported.

Why this was decided in v0.1 rather than at v1.1 when the ABI ships: an
exception can be granted but never withdrawn, and granting one later requires
unanimous consent from every copyright holder by that point. With one
contributor it is a decision; after the first external pull request it is a
negotiation.

The exception text is modelled on additional permissions in wide use, but it is
not legal advice and should be reviewed by a lawyer before the ABI is
published.

## Internal protocols are not plugins

Built-in protocols (SSH, RDP, VNC, SFTP) implement the `Protocol` trait directly
in Rust and are compiled in. They are not sandboxed, because they are part of
the application and are reviewed as such. The plugin ABI exists for *third-party*
code, and its constraints exist because third-party code is untrusted — not
because sandboxing is intrinsically desirable for our own crates.
