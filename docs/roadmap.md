# Roadmap

Milestones and their exit criteria. Dates are deliberately absent — this is an
open-source project driven by available time. Order is meaningful; sizes are
relative.

**Development has not followed this order.** Work was done breadth-first
instead: all four protocol adapters, the importers and the ten localisations
landed together, while several items from the earliest milestone are still open.
No milestone has been declared complete, because no milestone has passed its exit
criteria. ✅ below means a user can do it in a running build, ⏳ means it is not
built, and ◐ means part of it is.

The shipped-versus-planned summary a reader wants first is the *What works
today* table in [README.md](../README.md#what-works-today).

## v0.1 — Foundation

*The vault works and can be trusted.*

- ✅ Cargo workspace, licence and dependency policy (`deny.toml`, `cargo-deny`
  in CI), and a CI matrix testing Linux, Windows and macOS
- ◐ `remoter-vault`: container format, atomic saves, rolling backups,
  migrations, and **three** of the four key slot kinds — password (with an
  optional key file), recovery key and OS keychain. ⏳ The FIDO2 slot is
  reserved in the format and refused on every code path
- ✅ `remoter-core`: node tree, inheritance resolution, validation
- ✅ Tauri shell with the main window layout
- ✅ Vault creation wizard including the recovery key flow
- ◐ Unlock, lock, auto-lock. Idle and lock-on-resume-from-suspend work (Linux);
  ⏳ screen lock and minimise cannot be observed from this build, and the
  settings screen disables those switches and says why
- ✅ Connection tree: create, edit, move, delete, search
- ✅ Light and dark themes — and the high-contrast pair from v0.5 arrived early, so there are four
- ✅ `remoter-plugin-abi` and `remoter-plugin-sdk` crates established under
  Apache-2.0 OR MIT, and `LICENSE-EXCEPTION` published
  ([ADR-0009](architecture/decisions/0009-plugin-licence-exception.md))
- ⏳ **`remoter-bench-framepath`** — the framebuffer transport harness. It was
  to be built before any protocol work
  ([ADR-0010](architecture/decisions/0010-framebuffer-transport.md)); RDP and VNC
  were built first and the harness does not exist, so the presenter choice
  below was never measured

**Exit criteria**

- ✅ Every cryptographic known-answer test passes
- ✅ Recovery unlock works after the password slot is deliberately destroyed
- ◐ Truncation fuzzing produces no panic at any byte offset — the fuzz targets
  that exist cover the four importers, the `.rmtr` archive among them, not the
  vault container
- ⏳ No secret appears in a `trace`-level log capture — **nothing runs this
  check.** `tracing-subscriber` is a dependency of `apps/desktop/src-tauri`
  alone, no test in any crate installs a subscriber, and so no test has ever
  captured a log line to search. What is tested instead is narrower and does
  run: `Debug` is redacted on every secret-bearing type — `Secret`,
  `ImportedSecret`, `RecoveryKey`, `InputEvent`, `ClipboardData` and the
  credential DTO in `remoter-ipc` — which is the form a secret would take in a
  log line, but is not the same as looking at one
- ⏳ A vault survives 1000 save/load cycles with no corruption
- ⏳ The frame path harness produces latency and throughput numbers on all three
  platforms, with hardware acceleration confirmed in use

## v0.2 — SSH and SFTP

*The first real sessions.*

- ✅ `remoter-proto` with the `Protocol` trait and `SessionSupervisor`
- ◐ SSH: shell with PTY and host key verification, with public key, password and
  keyboard-interactive. ⏳ GSSAPI/Kerberos and SSH certificates are not
  implemented, so "all authentication methods" is not met
- ✅ xterm.js terminal with the WebGL renderer
- ✅ SFTP: dual-pane file manager, transfer queue, resume
- ◐ Tabs: open, close and reorder work. ⏳ Detach does not
- ✅ Local, remote and dynamic forwarding — in `remoter-proto-ssh` rather than a
  `remoter-tunnel` crate, which was never created
- ✅ Jump host chains: built and honoured by every protocol and by tunnels,
  imported from `ssh_config`'s `ProxyJump`, and set in the connection editor on a
  connection or a folder. ⏳ A per-hop credential cannot yet be chosen there
- ✅ SSH agent integration, off by default
- ⏳ **Presenter decision gate** — see the harness above. It was not run

**Exit criteria**

- ◐ Connect and authenticate against OpenSSH 8.x and 9.x — live tests run
  against `scripts/dev-sshd.sh`, which is whichever OpenSSH the developer has
- ⏳ A three-hop jump chain works
- ⏳ A 1 GB file transfers, is interrupted, and resumes correctly
- ⏳ Twenty concurrent sessions with no leaked tasks or sockets
- ⏳ Closing a tab releases every resource, verified under a leak checker
- ⏳ A panicking session task fails exactly one tab and leaves the other
  sessions, tunnels and transfers running
  ([ADR-0011](architecture/decisions/0011-panic-strategy.md))
- ⏳ The presenter choice is recorded per platform, with the measurements behind it

## v0.3 — RDP

*The hard one — but no longer the risky one, because the transport was measured
in v0.1 and chosen in v0.2.* Neither of those happened, so it was the risky one
after all.

- ◐ IronRDP integration: TLS and NLA/CredSSP with NTLMv2. ⏳ Kerberos is not
  implemented
- ✅ Framebuffer rendering with dirty rectangles and coalescing
- ⏳ Native `wgpu` presenter — the gate that would have selected it never ran, so
  every platform uses the WebView presenter by default rather than by decision
- ◐ Scaling modes work. ⏳ Dynamic resolution depends on a channel the server
  opens and there is no way to revise a tab's capabilities mid-session; HiDPI at
  physical pixel size is not built
- ✅ Keyboard scancode translation, with the layout read from the local machine
- ⏳ Clipboard synchronisation (text) — not requested on the wire, not exposed
  as a command, not drawn as a control
- ✅ RDP through a jump chain

**Exit criteria**

- ⏳ The [ADR-0010](architecture/decisions/0010-framebuffer-transport.md)
  acceptance bar met on every platform, by whichever presenter that platform
  selected
- ◐ Connects to Windows Server 2019, 2022 and Windows 10/11 — a real Windows
  Server has been driven with keyboard and mouse; the matrix has not been walked
- ⏳ Turkish Q and F, German, French AZERTY, Spanish, Russian and Arabic keyboard
  layouts verified against a live server. The mapping tables have unit tests
- ⏳ Hardware acceleration confirmed in use on Linux, not merely available

## v0.4 — VNC and recording

- ◐ VNC. ⏳ **Not** with the full encoding set: Raw and CopyRect only, because
  [ADR-0013](architecture/decisions/0013-rfb-handshake-and-bounded-input.md)
  withdrew every encoding whose lengths this build cannot bound itself
- ⏳ VNC over SSH as a one-click configuration — the tunnel works, the one click
  does not exist
- ⏳ Terminal recording in asciicast v2, with echo-based password redaction
- ⏳ Framebuffer recording
- ⏳ Built-in playback with seek and search
- ◐ Audit log and its viewer: shipped for vault, node, import, export, secret,
  trust, session, file transfer and settings events, with JSON and CSV export.
  Each entry names the operating-system account and computer that wrote it
  (schema 3). ⏳ Remote file delete and rename, and plugin events, are not
  logged, and there is no retention policy
- ⏳ Session groups with layouts, and broadcast typing with its safeguards — the
  group node kind exists in the data model and nothing opens one

**Exit criteria**

- ⏳ Works against TigerVNC, TightVNC, RealVNC and x11vnc
- ⏳ A `sudo` password is not present in a recording
- ⏳ An eight-hour session records without unbounded memory growth

## v0.5 — Migration and languages

- ◐ Importers: ✅ Remoter's own `.rmtr` archive, with its secrets, ✅ mRemoteNG (GCM and legacy CBC, including the well-known
  default password), ✅ `~/.ssh/config` (including `Include`, `Match`, wildcards
  and `ProxyJump`), ✅ CSV. ⏳ Royal TS and PuTTY are not written
- ◐ Import preview and report ship. ⏳ Per-item conflict resolution does not
- ◐ Export: ✅ the encrypted `.rmtr` archive with secrets, for another Remoter,
  and ✅ CSV, `ssh_config` and JSON with none, for other tools — each for the
  whole vault or a folder. ⏳ The structure-only archive and plaintext secret
  export
- ✅ All ten languages, including RTL
- ⏳ FTP/FTPS
- ◐ High-contrast themes ship (`hc-light`, `hc-dark`). ⏳ The full accessibility pass has not been done

**Exit criteria**

- ⏳ A 500-connection mRemoteNG file imports with inheritance preserved
- ◐ Export/import round trip: ✅ an archive moves a folder and its passwords into
  another vault, and CSV and `ssh_config` exports read back as the same
  connections, under test, with a property test on CSV field contents. ⏳ A
  property test over arbitrary trees, and the JSON — which needs an importer
- ◐ Every fuzz target has run 24 hours with no crash — four targets exist, for
  the four importers; none has had a 24-hour run recorded
- ⏳ WCAG 2.2 AA verified across all four themes — the four themes exist; nothing has audited them
- ⏳ Screen readers verified on all three platforms

## v1.0 — Release

- RDCMan and `.rdp` import
- Code signing for every target — Authenticode on Windows, Developer ID with
  notarisation and stapling on macOS, GPG-signed artefacts on Linux. The
  packaging half of this has landed: a `vX.Y.Z` tag already produces installers
  for all three platforms. They are unsigned, which is what makes both Windows
  and macOS stop the first launch, and what keeps the updater below blocked
- Updater
- The complete documentation set
- **Independent cryptographic review of the vault format** — a release gate, not
  an aspiration
- Performance pass and a memory-leak soak test

**Exit criteria**

- No known security issue open
- External review complete, findings addressed
- Clean install verified on every supported platform
- 72-hour soak with 20 sessions and no leak

## Post-1.0

**v1.1** — plugin ABI published (unstable), with the interface exception legally
reviewed first; plugin manager; Telnet, serial, local shell; RDP audio and
multi-monitor; RD Gateway; credential provider plugins

**v1.2** — plugin ABI stabilised, scripted hooks, PowerShell Remoting,
Kubernetes and Docker `exec`, RDP printing, HTTP panel

**v1.3** — plugin UI panels, dashboards, batch command execution

**v2.0** — process isolation per protocol adapter
([ADR-0007](architecture/decisions/0007-process-isolation.md)); end-to-end
encrypted team synchronisation with a self-hostable server; shared vaults and
RBAC; forward-secure audit log sealing, which becomes meaningful once the log
has a reader who is not its owner
([ADR-0012](architecture/decisions/0012-audit-log-integrity.md))

## Deliberately not planned

| | Why |
|---|---|
| Browser-based access | A fundamentally different product with a far larger attack surface |
| A hosted cloud service | Contrary to the local-first, no-account trust model |
| Telemetry or analytics | Not in a tool that holds credentials |
| Mobile applications | A different interaction model; better served by a purpose-built client |
| Credential escrow or recovery service | A recovery channel we control is one an attacker can subvert |
