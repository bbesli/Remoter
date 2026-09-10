# Roadmap

Milestones and their exit criteria. Dates are deliberately absent — this is an
open-source project driven by available time. Order is meaningful; sizes are
relative.

## v0.1 — Foundation

*The vault works and can be trusted.*

- Cargo workspace, CI matrix, licence and dependency policy
- `remoter-vault`: full container format, all four key slot kinds, atomic saves,
  rolling backups, migrations
- `remoter-core`: node tree, inheritance resolution, validation
- Tauri shell with the main window layout
- Vault creation wizard including the recovery key flow
- Unlock, lock, auto-lock
- Connection tree: create, edit, move, delete, search
- Light and dark themes
- English only
- `remoter-plugin-abi` and `remoter-plugin-sdk` crates established under
  Apache-2.0 OR MIT, and `LICENSE-EXCEPTION` published
  ([ADR-0009](architecture/decisions/0009-plugin-licence-exception.md))
- **`remoter-bench-framepath`** — the framebuffer transport harness, built
  before any protocol work ([ADR-0010](architecture/decisions/0010-framebuffer-transport.md))

**Exit criteria**

- Every cryptographic known-answer test passes
- Recovery unlock works after the password slot is deliberately destroyed
- Truncation fuzzing produces no panic at any byte offset
- No secret appears in a `trace`-level log capture
- A vault survives 1000 save/load cycles with no corruption
- The frame path harness produces latency and throughput numbers on all three
  platforms, with hardware acceleration confirmed in use

## v0.2 — SSH and SFTP

*The first real sessions.*

- `remoter-proto` with the `Protocol` trait and `SessionSupervisor`
- SSH: shell with PTY, all authentication methods, host key verification
- xterm.js terminal with the WebGL renderer
- SFTP: dual-pane file manager, transfer queue, resume
- Tabs: open, close, reorder, detach
- `remoter-tunnel`: local, remote and dynamic forwarding
- Jump host chains
- SSH agent integration
- **Presenter decision gate**: per platform, WebView presenter or native
  `wgpu` surface, decided from the v0.1 harness numbers against the acceptance
  bar in [ADR-0010](architecture/decisions/0010-framebuffer-transport.md)

**Exit criteria**

- Connect and authenticate against OpenSSH 8.x and 9.x
- A three-hop jump chain works
- A 1 GB file transfers, is interrupted, and resumes correctly
- Twenty concurrent sessions with no leaked tasks or sockets
- Closing a tab releases every resource, verified under a leak checker
- A panicking session task fails exactly one tab and leaves the other sessions,
  tunnels and transfers running
  ([ADR-0011](architecture/decisions/0011-panic-strategy.md))
- The presenter choice is recorded per platform, with the measurements behind it

## v0.3 — RDP

*The hard one — but no longer the risky one, because the transport was measured
in v0.1 and chosen in v0.2.*

- IronRDP integration: TLS, NLA/CredSSP with NTLM and Kerberos
- Framebuffer rendering with dirty rectangles and budgeted adaptive encoding
- Native `wgpu` presenter, on any platform the v0.2 gate selected it for
- Dynamic resolution, scaling modes, HiDPI
- Keyboard scancode translation, tested across the layout matrix
- Clipboard synchronisation (text)
- RDP through a jump chain

**Exit criteria**

- The [ADR-0010](architecture/decisions/0010-framebuffer-transport.md)
  acceptance bar met on every platform, by whichever presenter that platform
  selected
- Connects to Windows Server 2019, 2022 and Windows 10/11
- Turkish Q and F, German, French AZERTY, Spanish, Russian and Arabic keyboard
  layouts verified
- Hardware acceleration confirmed in use on Linux, not merely available

## v0.4 — VNC and recording

- VNC with the full encoding set
- VNC over SSH as a one-click configuration
- Terminal recording in asciicast v2, with echo-based password redaction
- Framebuffer recording
- Built-in playback with seek and search
- Audit log and its viewer
- Session groups with layouts, and broadcast typing with its safeguards

**Exit criteria**

- Works against TigerVNC, TightVNC, RealVNC and x11vnc
- A `sudo` password is not present in a recording
- An eight-hour session records without unbounded memory growth

## v0.5 — Migration and languages

- Importers: mRemoteNG, Royal TS, PuTTY, `~/.ssh/config`, CSV
- Import preview, conflict resolution, report
- Export in every documented format
- All ten languages, including RTL
- FTP/FTPS
- High-contrast themes and the full accessibility pass

**Exit criteria**

- A 500-connection mRemoteNG file imports with inheritance preserved
- Export/import round trip is lossless, verified by property test
- Every fuzz target has run 24 hours with no crash
- WCAG 2.2 AA verified across all four themes
- Screen readers verified on all three platforms

## v1.0 — Release

- RDCMan and `.rdp` import
- Packaging and signing for every target
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
