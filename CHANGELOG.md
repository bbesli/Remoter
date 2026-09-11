# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

#### Localisation
- `apps/desktop/ui/src/i18n/`: the localisation layer. `useT(namespace)` is the
  only accessor a component uses; catalogues are JSON at
  `locales/<code>/<namespace>.json`, namespaced per feature and loaded per
  screen, with English compiled in as the fallback
- ICU MessageFormat through `i18next-icu`, so plurals use real CLDR categories.
  Russian's four and Arabic's six are covered by tests; a one/other switch is
  wrong in half the shipping languages and now fails rather than shipping
- Interpolated values are substituted as data. A hostname, a MOTD line or a
  file name containing `{`, `#` or `<script>` cannot become message syntax or
  markup, and each case has a test
- A missing key falls back to the chosen language, then English, then the
  humanised key marked `⟦ ⟧` in development. Never a raw key, never a throw
- `Intl`-based formatting for dates, times, numbers, percentages, lists, file
  sizes and durations, each taking the locale explicitly
- Runtime language switching with no restart: the stored locale is read at
  startup, applied above every screen, and written to `<html lang dir>`
- `remoter-i18n/no-literal-jsx-text` and `remoter-i18n/no-text-constant`: two
  ESLint rules that fail the build on a user-visible string hardcoded in JSX or
  hidden in a per-file `TEXT` constant, with a shrinking baseline for the
  features not yet extracted
- English catalogues for the shell and settings screens, and those screens
  migrated to `t()` as the worked example

#### File transfer — SFTP
- `remoter-ipc::sftp`: the command surface
  `docs/architecture/sftp-command-surface.md` specifies. Browsing (`sftp_list`,
  `sftp_stat`, `sftp_canonicalize`, `sftp_read_link`, `sftp_mkdir`,
  `sftp_rename`, `sftp_delete`, `sftp_set_permissions`, `sftp_symlink`) and a
  transfer queue (`sftp_enqueue`, `sftp_transfers`, `sftp_transfer_cancel`,
  `sftp_transfer_cancel_all`, `sftp_transfer_retry`), each transfer cancellable
  on its own and each surviving a tab switch because the queue lives beside the
  session rather than in the interface
- A file pane attaches to a session rather than to a node: `sftp_open` opens one
  more channel on the connection a tab already holds (RFC 4254 §6.5), so a file
  manager on a host with a shell costs a channel and not a second handshake,
  host key check and authentication
- `session_open` now opens `sftp` connections as well as `ssh` ones. An `sftp`
  session runs the identical pipeline and registers as
  `SessionKind::FileTransfer`, so it is in the session list, counts against the
  session cap, and is closed by the same supervisor. `rdp` and `vnc` are still
  refused by name
- Progress is pushed over the session's own event channel rather than polled,
  every 512 KiB — a 2 GB transfer with no progress is indistinguishable from a
  hang. `sftp_transfers` is for the first paint and for reconciliation
- Resume, and the refusal: a resume is honoured only where the destination is
  strictly shorter than a source of known size, and where it is declined the
  transfer says which file was in the way rather than silently starting over
- Every server-supplied name crosses the boundary twice — raw, which is what
  goes back on the wire, and escaped, which is what a human reads — with the
  control bytes, bidirectional overrides, zero-width characters and path
  separators found in it reported per row. A recursive delete composes child
  paths from the entry's name and refuses one that is not a single component,
  and unlinks symbolic links rather than following them
- Live integration tests against `scripts/dev-sshd.sh`: browsing, both transfer
  directions with progress, resume and its refusal, per-transfer cancellation,
  a concurrent queue, recursive removal, and a listing of deliberately hostile
  file names

#### Graphical sessions — RDP
- `remoter-proto-rdp`: a working RDP client. The connection sequence of
  MS-RDPBCGR §1.3.1.1 end to end — X.224 negotiation, the TLS upgrade of
  §5.4.5.1, MCS Connect Initial/Response, Erect Domain, Attach User, the
  batched channel joins, the Client Info PDU, licensing (MS-RDPELE), the
  Demand Active/Confirm Active capability exchange and the Synchronize,
  Control and Font List finalization
- Network Level Authentication: CredSSP (MS-CSSP) over NTLMv2 with extended
  session security (MS-NLMP), including the `pubKeyAuth` check that proves the
  server holds the certificate's private key before the password is sent. Both
  are implemented in-crate because `sspi` cannot be added to this workspace —
  it pins a `curve25519-dalek` release candidate that contradicts `russh`'s
  requirement — and both carry known-answer tests against MS-NLMP §4.2.4's
  published vectors. Kerberos is not implemented
- The server certificate gets the host key treatment: a chain that validates
  against a trust anchor connects silently, anything else prompts with the
  fingerprint and the reason and pins on acceptance, and a **changed** pinned
  certificate is a hard failure that can only be replaced by typing the tail of
  the offered fingerprint. It reuses `remoter-proto`'s own `HostKeyOutcome`
  types rather than a parallel set, so "the same trust model" is a fact about
  the code
- Graphics: every codec a modern Windows Server negotiates — RemoteFX, the
  surface-bits path, the legacy bitmap updates and the pointer updates —
  decoded into the shared framebuffer format, with per-rectangle run-length
  encoding where it shrinks the payload and raw where it does not
- Input: PS/2 Set 1 scancodes with the extended-key prefix preserved, explicit
  lock-state synchronisation, the full button set including back and forward,
  and both wheel axes. Everything held is released before a clean disconnect
- Dynamic resize over MS-RDPEDISP, and the Deactivation-Reactivation Sequence
  the server answers it with
- Three different failures with three different remedies: an unreachable host,
  an untrusted certificate and a rejected password never collapse into one
  another, and a server that requires NLA says so by name
- The clipboard capability the skeleton claimed is withdrawn until the
  MS-RDPECLIP channel exists; a paste button that silently discards is worse
  than no paste button

#### Graphical sessions — groundwork
- `remoter-proto::framebuffer`: the vocabulary RDP and VNC share — rectangles,
  pixel formats, per-rectangle encodings, the binary frame format, the
  keyframe/delta distinction, cursor shapes and a frame coalescer. Framebuffer
  updates ride the session supervisor and event bus that terminals already use
- `InputEvent::Key` carries both a PS/2 scancode and an X11 keysym, because RDP
  and RFB want different things from one keypress and neither is derivable from
  the other outside the browser; lock states and the second wheel axis are
  carried explicitly
- `remoter-proto::SyncTransport`, so an injected transport can be handed to a
  library that demands `Sync` without a pump task
- `remoter-proto-vnc` crate skeleton, and the IronRDP/`ironrdp-async`
  dependency conflict recorded rather than worked around
- `docs/architecture/sftp-command-surface.md`: what the file manager needs from
  `remoter-ipc`

#### v0.1 foundation — implementation
- Cargo workspace: `remoter-core`, `remoter-vault`, `remoter-plugin-abi`,
  `remoter-plugin-sdk`, `remoter-ipc`, and the Tauri desktop application
- Design tokens extracted from the supplied screen designs, covering the dark,
  light and both high-contrast themes
- Local install script for Linux, and CI covering Rust, the frontend, security
  advisories and the plugin ABI licence boundary

#### Specification
- Project specification: architecture, threat model, vault format, data model,
  session pipeline, rendering, plugin system, storage
- Architecture Decision Records 0001–0012
- `LICENSE-EXCEPTION`: GPL-3.0 §7 additional permission allowing WebAssembly
  plugins to carry any licence
- Feature specifications: connections, protocols, tunnelling, import/export,
  recording and audit, internationalisation
- Interface specification: information architecture and design system
- Development documentation: setup, structure, standards, testing, release
- Roadmap through v1.0 and beyond

### Changed
- The Language screen's list of available languages is measured from the
  catalogue directory instead of a hardcoded flag, so a language stops being
  marked "Not yet available" when its catalogue lands rather than when someone
  remembers to edit the list
- `styles/tokens.css` gained `--dir-flip` and `--dir-arrow`; the last two
  physical directional CSS properties in the frontend became logical ones
