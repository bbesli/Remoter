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

**Exit criteria**

- Every cryptographic known-answer test passes
- Recovery unlock works after the password slot is deliberately destroyed
- Truncation fuzzing produces no panic at any byte offset
- No secret appears in a `trace`-level log capture
- A vault survives 1000 save/load cycles with no corruption

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

**Exit criteria**

- Connect and authenticate against OpenSSH 8.x and 9.x
- A three-hop jump chain works
- A 1 GB file transfers, is interrupted, and resumes correctly
- Twenty concurrent sessions with no leaked tasks or sockets
- Closing a tab releases every resource, verified under a leak checker

## v0.3 — RDP

*The hard one.*

- **Rendering spike first** — measure the framebuffer path on all three
  platforms before building on it
- IronRDP integration: TLS, NLA/CredSSP with NTLM and Kerberos
- Framebuffer rendering with dirty rectangles and adaptive encoding
- Dynamic resolution, scaling modes, HiDPI
- Keyboard scancode translation, tested across the layout matrix
- Clipboard synchronisation (text)
- RDP through a jump chain

**Exit criteria**

- ≥ 30 fps at 1080p with < 80 ms input-to-photon latency on all three platforms,
  **or** the native-surface fallback implemented and meeting the same bar
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
- `panic` strategy decided and documented

**Exit criteria**

- No known security issue open
- External review complete, findings addressed
- Clean install verified on every supported platform
- 72-hour soak with 20 sessions and no leak

## Post-1.0

**v1.1** — plugin ABI (unstable), plugin manager, Telnet, serial, local shell,
RDP audio and multi-monitor, RD Gateway, credential provider plugins

**v1.2** — plugin ABI stabilised, scripted hooks, PowerShell Remoting,
Kubernetes and Docker `exec`, RDP printing, HTTP panel

**v1.3** — plugin UI panels, dashboards, batch command execution

**v2.0** — process isolation per protocol adapter
([ADR-0007](architecture/decisions/0007-process-isolation.md)); end-to-end
encrypted team synchronisation with a self-hostable server; shared vaults and
RBAC

## Deliberately not planned

| | Why |
|---|---|
| Browser-based access | A fundamentally different product with a far larger attack surface |
| A hosted cloud service | Contrary to the local-first, no-account trust model |
| Telemetry or analytics | Not in a tool that holds credentials |
| Mobile applications | A different interaction model; better served by a purpose-built client |
| Credential escrow or recovery service | A recovery channel we control is one an attacker can subvert |
