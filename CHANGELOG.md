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
- **Ten languages**: Arabic, English, French, German, Hindi, Portuguese
  (Brazil), Russian, Simplified Chinese, Spanish and Turkish, covering the
  shell, vault, connections, sessions, settings, audit, import and error
  catalogues. The file manager's catalogue is English only so far, which is a
  gap rather than a decision
- Right-to-left is a layout, not a mirror. Every physical directional CSS
  property in the frontend became a logical one, remote content keeps its own
  direction rather than the interface's, and the three things that are
  *geometry* rather than text — a framebuffer canvas, a terminal, a coordinate
  from a pointer event — are pinned left-to-right on purpose, because the remote
  host addresses pixels from its own left edge
- Case folding happens in the right language, which is not always the reader's.
  A name or a tag folds in the reader's language; a hostname, a username, a
  protocol name, a file name or a keyboard shortcut folds invariantly — under
  Turkish rules `VDI-GW` folds to `vdı-gw`, so a Turkish reader searching `vdi`
  used to find nothing a colleague on the English interface could find with the
  same three keystrokes

#### Security
- ADR-0013: the RFB handshake and every length the VNC library acts on are
  owned by Remoter rather than by `vnc-rs`. Two defects made that necessary —
  an authentication result decided through a `transmute`, and allocations sized
  straight from wire fields in a process that aborts rather than unwinds when
  one fails. See *Graphical sessions — VNC* below
- RDP's server certificate gets the SSH host key treatment, reusing
  `remoter-proto`'s own `HostKeyOutcome` types rather than a parallel set: an
  unknown certificate prompts with its fingerprint and the reason it is not
  trusted, acceptance pins it, and a **changed** pinned certificate is a hard
  failure that only a typed confirmation of the offered fingerprint can replace
- CredSSP/NTLMv2 with extended session security, including the `pubKeyAuth`
  check that proves the server holds the certificate's private key **before**
  the password is sent, with known-answer tests against MS-NLMP §4.2.4
- Remote text is quarantined in three layers, and
  `docs/architecture/rendering.md` now names all three: it renders as text
  (enforced by an ESLint rule with no override), it is escaped in Rust and the
  escaped twin is what is drawn, and it is bidi-isolated at the point of display
  so a directional character cannot reorder the sentence around it
- Two ESLint rules that fail the build rather than warn: `invoke()` outside
  `lib/ipc.ts`, and `dangerouslySetInnerHTML` anywhere. Both are selector-based
  and need no plugin, so neither can be turned off by a config change that looks
  like a dependency bump
- The frontend holds no decrypted secret, and the surfaces that would have
  needed one say so rather than offering a control that goes nowhere

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
- `session_open` now opens all four shipped protocols. An `sftp` session runs
  the identical pipeline and registers as `SessionKind::FileTransfer`, so it is
  in the session list, counts against the session cap, and is closed by the same
  supervisor; `rdp` and `vnc` register as `SessionKind::Framebuffer` on the same
  pipeline. What is still refused by name is a protocol no adapter in this
  workspace speaks — a plugin protocol, for which no plugin host is loaded
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

#### File transfer — the file manager
- Two panes and a transfer queue: browse both sides, transfer in either
  direction with live progress, rename, create, delete, change permissions, and
  cancel one transfer without touching the others
- Two mount points, because there are two ways a user reaches one. An `sftp`
  connection opened from the tree gets a file tab instead of a terminal; a tab
  that already has a shell gets a docked pane from the Files toggle, running on
  the connection that tab has already authenticated — one more channel, not a
  second sign-in
- Every server-supplied name, path, user and group is drawn as the escaped twin
  the DTO carries, never the raw field, and a name whose escaping changed it
  carries a badge saying which hazard was found — a control character, a
  bidirectional override, an invisible character, or a path separator in
  something that is supposed to be a single component. A name flagged as not
  being one component is not navigable and offers no actions at all

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

#### Graphical sessions — VNC
- `remoter-proto-vnc`: a working RFB client over `vnc-rs`, with the handshake
  and the server message stream owned in-crate rather than by the library
  (ADR-0013). The version is bracketed by a **floor** as well as a ceiling, and
  the security type is chosen here under a policy that refuses `None` whenever a
  credential is configured — the trust model `remoter_proto::hostkey` sets for
  SSH, applied to a graphical protocol
- The gate between the socket and the library, which is where that ownership
  becomes code: it replays a synthetic handshake carrying exactly the security
  type that was really selected, reads the real `SecurityResult` itself and
  refuses anything RFC 6143 §7.1.3 does not define, and checks every
  wire-supplied length before the library can size an allocation from it. Two of
  those were real defects — `vnc-rs` decides "did authentication fail?" through a
  `transmute` into a two-variant enum, so a server sending `2` was undefined
  behaviour in a decision that gates access; and its allocations come straight
  off wire fields, where an allocation failure aborts rather than unwinds and so
  cannot be contained by the session supervisor
- The security-type registry is open, not an enum: a macOS host offering only
  Apple Remote Desktop authentication is told apart from "the handshake failed"
- What VNC authentication actually is, said out loud and on screen: a password
  truncated to eight bytes, DES with a 56-bit effective key, and nothing
  protected after the handshake. Whether that matters *to this connection* is
  answered per connection — loopback, private network or routable address get
  three different warnings, and a session inside an SSH tunnel raises none,
  because a blanket warning trains users to ignore warnings
- **Raw and CopyRect only**, plus the Cursor and DesktopSize pseudo-encodings,
  and that narrowing is the point rather than an omission. Tight has no RFC and
  delimits its rectangles inside a compression stream, so a length cannot be
  checked before decoding; ZRLE and TRLE are framable but the bound that matters
  is written *inside* the compressed data. Neither can be bounded from outside,
  so neither is promised — a slower link that sends raw pixels is the price of a
  decoder that cannot be told to allocate whatever the server likes
- X11 keysyms, which are not scancodes; the button mask, and the wheel RFB has
  no field for; a Latin-1 clipboard with the two places it loses characters
  named on screen rather than silently substituted

#### Graphical sessions — the interface
- The framebuffer surface: an RDP or VNC session is on screen, from keyframes
  and deltas through copy-rects, both pixel formats, the server's cursor shape
  and dropped-frame detection. Canvas 2D rather than WebGL2, because a copy-rect
  reads the surface the presenter already holds and a 2D context can serve that
  from the canvas itself — `docs/architecture/rendering.md` has the full reason
- The canvas is owned outside React and borrowed by the component. It holds the
  only copy of the remote screen that exists anywhere, so a re-mount would clear
  it with no way to ask for a repaint, and it has to exist before the first
  frame arrives — which is before any component could have mounted
- Four scaling modes: smart resize, fit, 1:1 and an **integer** zoom. Integer
  because a remote desktop carries text already rasterised for its own pixel
  grid, and a fractional resample turns 8pt text into a grey smear
- Every warning a session raises is drawn, over the session. They had been
  collected since the session feature was written and thrown away when the tab
  closed. A `danger` one — an unauthenticated session — cannot be folded out of
  sight, and a warning the interface has no wording for is shown as its own key
  rather than swallowed

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

#### Packaging and release
- Installers for Windows and macOS beside the Linux ones that already existed:
  an NSIS `-setup.exe` and an `.msi` on Windows, and a universal `.dmg` on
  macOS covering both Apple silicon and Intel. Running Remoter no longer
  requires a Rust toolchain and an afternoon with linker errors
- A release workflow on a `vX.Y.Z` tag. It refuses to start if the tag and the
  two version fields disagree, builds on all three platforms, checks that each
  one produced every bundle it owes rather than trusting that it did, writes
  `SHA256SUMS.txt` over the result, and opens a **draft** GitHub release for a
  person to install and verify before anyone else can download it
- Release notes that explain the security warning instead of leaving the reader
  to guess. The builds are unsigned — there is no code-signing certificate —
  so Windows SmartScreen and macOS Gatekeeper both stop the first launch, and
  the notes carry the click-by-click way through each, on every macOS version
  where the steps differ. An unexplained warning on a credential manager reads
  as malware
- On Windows 10 the installer fetches the Edge WebView2 runtime when it is
  missing, so the blank window its absence causes cannot happen. Windows 11
  already ships it
- The Linux release build is pinned to Ubuntu 22.04, so the published `.deb`,
  `.rpm` and AppImage sit on the glibc 2.35 floor the documentation promises
  rather than on whatever the newest runner image happens to carry
- CI builds and tests on Windows and macOS as well as Linux. Until now nothing
  in this workspace had been compiled for either by anything but one developer's
  own machine, while three crates carried platform-specific code

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
- A session's capabilities are no longer read once and trusted for ever. The
  RDP adapter's `rdp.display_control_unavailable` warning is now a capability
  *revision*: a tab that was told it could resize and then finds the server
  never opened the Display Control channel withdraws the capability, takes the
  Smart control off the screen, stops sending resize requests, and moves itself
  to Fit — while still showing the warning that explains why

### Fixed
- **Reordering a connection by dragging it was refused half the time, by
  construction.** Every row divided its height into three bands — above,
  inside, below — including rows that cannot hold anything. Aiming at the
  connection you want to sit next to, which is where everyone aims, landed in
  the middle band, and the only answer that band has for a connection is "only
  a folder can hold other entries". A row that reads as a container still
  splits in three; everything else is halved into above and below. A *group*
  keeps its middle band and still refuses it by name, because it wears the
  folder glyph and a gesture aimed at its inside deserves an answer rather than
  a silent reinterpretation
- **The drop target was read from the event's target rather than from where the
  pointer was.** Each row answered `pointermove` for itself, which holds only
  as long as the platform delivers every move to the element under the pointer
  — and stops the moment anything captures the pointer, after which one element
  receives the whole gesture and the tree sees the source row for all of it.
  The tree now captures the pointer itself once the press becomes a drag, and
  finds the target by hit-testing the point. The capture is deliberately not
  taken on `pointerdown`: a captured pointer retargets the compatibility mouse
  events too, which would send the `click` ending an ordinary press somewhere
  other than the row and stop clicking a connection from selecting it
- **A drag carried nothing under the pointer.** The source row dimmed and a
  two-pixel rule appeared somewhere in a list of twenty-eight-pixel rows, which
  is enough to confirm a gesture you already trust and not enough to discover
  one. The pointer now carries a chip naming the entry, and the chip carries
  the reason when the row under it will not take the drop — before the release
  rather than after it. The insertion line is thicker and capped, and a refusal
  is explained *below* the tree, so the rows no longer move under the pointer
  between one attempt and the next
- **A passphrase-protected `.pem` was refused as though the format were
  unsupported.** `ssh-keygen -m PEM` and `openssl rsa -aes256` write PKCS#1 or
  SEC 1 with an RFC 1421 `DEK-Info` header, and the vault refused every one of
  them at the step that identifies a key file — which runs before the interface
  knows to ask for a passphrase, so the refusal arrived the moment the file was
  chosen with no passphrase field anywhere on screen. Such a file is now
  identified, reported as encrypted so that the field is drawn, deciphered with
  the passphrase (`crates/remoter-vault/src/legacy_pem.rs`, AES-128/192/256-CBC
  with OpenSSL's `EVP_BytesToKey`) and re-enveloped as PKCS#8 like any other
  legacy PEM. Its passphrase is not kept afterwards: it opened a container the
  vault does not store. A PEM enciphered with DES-EDE3-CBC is still refused, and
  now says so by name rather than as a generic failure
- **A wrong key passphrase was accepted, sealed, and reported later as a
  rejection by a server that never saw the key.** An encrypted OpenSSH or PKCS#8
  container is stored ciphertext and all, so nothing downstream of the import
  ever tried the passphrase against it; the failure surfaced at connect time as
  "the server rejected these credentials (private-key)", which is a sentence
  about a machine that was not involved, on a screen with nothing on it
  connecting the failure to the file. The container is now opened at the moment
  the passphrase is offered — `crates/remoter-vault/src/openssh.rs` derives with
  bcrypt-pbkdf and compares the two check integers `PROTOCOL.key` puts at the
  head of the private section, and `check_passphrase` in
  `crates/remoter-vault/src/pkcs8.rs` runs the document's own PBES2 derivation
  and requires the plaintext to be a `PrivateKeyInfo` — and a passphrase that
  does not open the key is refused there, with nothing written
- The four things that can be wrong with a key passphrase are four failures with
  four codes, where two of them used to share one and be told apart only by a
  diagnostic the interface does not branch on: `key.passphrase-required` for
  none given, `key.passphrase-rejected` for one that does not open the
  container, `key.passphrase-not-needed` for one offered for a container that is
  not enciphered, and `key.passphrase-uncheckable` for a container this build
  cannot open to find out — a PuTTY `.ppk`, or an OpenSSH container under an
  AEAD cipher. The last is a refusal rather than a shrug: a passphrase nothing
  can check is one whose failure arrives at connect time
- A passphrase stored beside a key that needs none made authentication fail with
  a key that was perfectly good: `ssh-key` refuses that pairing outright. It is
  now refused rather than dropped — under its own code, because a person who
  typed a passphrase for a key that needs none is not looking at a bug and
  should not be asked to report one — and the vault refuses to seal it even if a
  caller insists
- An unenciphered container is checked too, at the moment the file is chosen,
  because its plaintext is readable without any passphrase: an OpenSSH one must
  carry matching check integers and a PKCS#8 one must be a whole
  `PrivateKeyInfo`. A file that merely began with a DER `SEQUENCE` tag used to be
  sealed and to fail when a session was opened
- **The Smart resize control was drawn on every RDP session, and chosen as the
  default, whether or not the server could honour it.** `capabilities.resizable`
  as it reaches the interface is the adapter's static offer — fixed before the
  connection sequence runs — not what the server granted, so a host that never
  opened the Display Control channel still got a control that did nothing, on by
  default. See the entry above for what replaced it, and
  `docs/architecture/rendering.md` for the capability-revision event that will
  replace *that*
- An SSH login banner and a keyboard-interactive instruction — remote text
  shown before authentication completes — rendered in a block that took its
  direction from the interface and gave each line none of its own. They are now
  drawn left-to-right with one bidi isolate per line, so a directional character
  cannot reorder the lines around it or the translated sentence the block sits
  in, and a stray carriage return no longer reaches the document at all.
  `SessionWarning::Banner` is still the one remote-text DTO with no escaped
  twin; that is recorded in `docs/architecture/rendering.md` rather than papered
  over with a second escaping table in TypeScript
- The connection tree's filter claimed to match a protocol name and did not, so
  typing `rdp` into the sidebar found nothing while the same word typed into the
  import preview found every row. Both now fold host, username and protocol the
  same invariant way
- **An RDP session against a default Windows host dead-ended on its first
  dialog.** Almost every Windows host presents a self-signed certificate, so the
  first connection raises a first-use certificate question — and that arrives as
  a `prompt` message, for which the session surface drew a panel whose only
  control was Cancel. The protocol worked, the picture worked, and there was no
  way to say yes. `host_key_decide` had accepted a certificate prompt the whole
  time; what was missing was a dialog, and the evidence to put on it.
  `PromptDto` now carries the certificate's fingerprint and the reason it did
  not validate — they were being dropped in `classify_prompt` — and
  `PromptPanel` draws a first-use trust decision with the same weight as the
  unknown-host-key dialog: the fingerprint to compare, the reason in words, an
  explicit accept, and Escape as a rejection. There is no path through it that
  accepts a *changed* certificate the way a first use is accepted: that one is
  raised as a host key prompt and goes through the typed confirmation, and the
  four reasons this dialog will accept exclude `changed`, `revoked` and
  `malformed` — as does the absence of any `replace` control here at all
- **Full screen could never work.** `core:window:allow-set-fullscreen` was not
  granted in `capabilities/default.json`, so Tauri denied the call, and the
  handler's `catch` then told the user there was no window to resize — the wrong
  explanation for the real cause. A remote desktop that cannot go full screen is
  barely a remote desktop. The grant is in, `allow-is-fullscreen` beside it, and
  every entry in that file now names the caller that needs it
- **Decoded frames were never released.** `createImageBitmap` returns pixels the
  garbage collector cannot see — about eight megabytes for one 1080p rectangle,
  held outside the JavaScript heap — and the presenter dropped the reference and
  moved on. A JPEG-encoded stream therefore grew for the life of the tab, which
  is nothing on a short session and gigabytes on an all-day one. Every decoded
  image is now closed in a `finally`, so a decode that threw part-way through a
  message, a tab disposed while one was in flight, and a target that raised on
  the draw all release what they decoded
- Five of the warnings the VNC adapter raises had no translated sentence and
  rendered as the raw key string — `vnc.clipboard.policy_refused` on screen
  inside a box that otherwise contains prose. Every `WARNING_*` constant in the
  three protocol adapters now has one, the SSH block included, and a test lists
  them by name so a new adapter warning fails rather than appearing as its own
  identifier. The one family still uncovered is `ssh.exit_signal.*`, whose
  detail carries a signal name inside the token; it needs an interpolated value
  on `WarningView` and is named in `warnings.ts` as absent by decision
