# Protocols

What each protocol adapter supports, which library implements it, and where the
gaps are.

## Capability matrix

| | SSH | SFTP | RDP | VNC | FTP/FTPS |
|---|:---:|:---:|:---:|:---:|:---:|
| Session kind | Terminal | File transfer | Framebuffer | Framebuffer | File transfer |
| Library | `russh` | `russh-sftp` | `IronRDP` | `vnc-rs` | `suppaftp` |
| Milestone | v0.2 | v0.2 | v0.3 | v0.4 | v0.5 |
| Resize | ✅ | — | ✅ dynamic | ✅ where supported | — |
| Clipboard, text | ✅ | — | ✅ | ✅ | — |
| Clipboard, files | — | — | ⏳ v1.1 | — | — |
| File transfer | via SFTP/SCP | ✅ | ⏳ drive redirect | — | ✅ |
| Audio | — | — | ⏳ v1.1 | — | — |
| Printing | — | — | ⏳ v1.2 | — | — |
| Multi-monitor | — | — | ⏳ v1.1 | — | — |
| Recording | ✅ asciicast | ✅ operation log | ✅ frames | ✅ frames | ✅ operation log |
| Tunnelling | ✅ | ✅ | ✅ | ✅ | ✅ |
| Agent auth | ✅ | ✅ | — | — | — |

Tunnelling is ✅ everywhere because transport is injected rather than dialled
([session-pipeline.md](../architecture/session-pipeline.md#4--transport)).

---

## SSH

**Library**: [`russh`](https://github.com/Eugeny/russh) 0.63 — pure Rust, Tokio,
no `libssh2`.

**Authentication**: public key (vault or agent), password,
keyboard-interactive including 2FA prompts, GSSAPI/Kerberos where the platform
provides it, and SSH certificates.

**Key formats**: OpenSSH (`ed25519`, `ecdsa`, `rsa`), PKCS#8, and PuTTY `.ppk`
(v2 and v3) — the last is essential for migration from PuTTY and Royal TS.

**Channels**: interactive shell with PTY, `exec` for one-shot commands,
`direct-tcpip` for forwarding and gateway chains, `subsystem` for SFTP, and
optional agent forwarding (off by default, with a warning — a compromised remote
host with a forwarded agent can impersonate the user everywhere that key opens).

**Terminal**: xterm.js with the WebGL renderer. True colour, 256 colours,
mouse reporting, bracketed paste, OSC 8 hyperlinks, correct wide-character and
combining-mark handling, working IME.

**Settings**: terminal type (`xterm-256color` default), environment variables,
keep-alive interval, compression, per-connection algorithm preferences,
X11 forwarding (v1.1), and an initial command to run on connect.

**Algorithm policy** is in
[transport-security.md](../security/transport-security.md#ssh). Legacy
algorithms are not compiled into the default build; they live behind a
`legacy-crypto` feature flag for the network engineers who genuinely need to
reach a 2009 switch.

---

## SFTP

**Library**: [`russh-sftp`](https://crates.io/crates/russh-sftp) 3.0, running as
a subsystem over an existing SSH connection — so an SFTP tab on a host that
already has a shell open reuses that connection rather than authenticating
again.

**Interface**: dual-pane file manager, local on one side and remote on the
other. Drag and drop within and between panes.

**Operations**: browse, upload, download, rename, delete, `mkdir`, `chmod`,
`chown`, symlink handling, and an edit-in-place flow that downloads to a
temporary file, opens the user's editor, watches for changes and re-uploads.

**Transfers**: a queue with per-file and aggregate progress, pause and resume,
concurrency limits, resumption of interrupted transfers where the server
supports it, and recursive directory operations. Conflicts prompt with
size and timestamp comparison rather than silently overwriting.

**Not in v1.0**: server-to-server transfer, and synchronisation/mirroring modes.

---

## RDP

**Library**: [`IronRDP`](https://github.com/Devolutions/IronRDP) 0.17 — pure
Rust, maintained by Devolutions, used in production by Cloudflare Access and
Teleport. Sans-I/O state machines, which is exactly what the injected-transport
design needs.

**Security**: Enhanced RDP Security with TLS 1.2/1.3, and NLA via CredSSP with
both NTLM and Kerberos. Restricted Admin mode and Remote Credential Guard where
the server permits — both avoid sending reusable credentials to the target and
are recommended for administrative connections.

**Graphics**: raw bitmaps, Interleaved RLE, RDP 6.0 bitmap compression, and
RemoteFX. Colour depth is configurable, and a bandwidth profile (LAN / broadband
/ constrained) sets sensible defaults for compression and effects.

**Display**: dynamic resolution — the remote desktop resizes to the tab —
plus fit-to-window, 1:1, and manual zoom. HiDPI requests a framebuffer at
physical pixel size so text is sharp rather than upscaled.

**Input**: full scancode translation, which is where keyboard-layout bugs live.
The mapping tables are tested against Turkish Q and F, German, French AZERTY,
Spanish, Russian and Arabic layouts.

**Gateway**: RD Gateway support is planned for v1.1. Until then, RDP through an
SSH bastion works today via the gateway chain, which covers most of the same
need.

**Known gaps versus FreeRDP** — stated plainly because users will hit them:
audio and microphone redirection, printer redirection, smart card redirection,
USB redirection, and multi-monitor are post-1.0. Where a gap blocks a user, the
per-connection "open in external client" escape hatch remains.

---

## VNC

**Library**: [`vnc-rs`](https://crates.io/crates/vnc-rs) 0.5.

**Encodings**: Raw, CopyRect, RRE, Hextile, Tight, ZRLE, and cursor
pseudo-encodings.

**Compatibility**: TigerVNC, TightVNC, RealVNC, UltraVNC, x11vnc, and the
built-in servers in macOS Screen Sharing and various hypervisors.

**Security** is RFB's weak point and Remoter treats it as such. Classic VNC
authentication uses DES with an 8-byte key and no transport encryption.
VeNCrypt (TLS) is used where the server supports it; otherwise the connection
editor offers a one-click "secure this with SSH" that builds the tunnel and
rewrites the target to loopback. Plain VNC authentication to a non-loopback,
non-private address raises a blocking warning.

**Features**: view-only mode, clipboard synchronisation, `SetDesktopSize` where
supported, and configurable JPEG quality for Tight encoding.

`OPEN:` `vnc-rs` is younger than the other protocol crates. If it stalls, the
fallback is a maintained fork — the adapter interface means that decision does
not touch anything else.

---

## FTP and FTPS

**Library**: [`suppaftp`](https://crates.io/crates/suppaftp).

Included because network appliances and legacy systems still require it, not
because it is a good idea. FTPS (explicit TLS) is supported with certificate
validation; plain FTP carries a persistent warning badge in the UI and requires
per-connection opt-in, because it sends credentials in clear text.

Active and passive modes, resume, and directory listing parsing for both Unix
and DOS-style server responses.

---

## Planned

| Protocol | Approach | Milestone |
|---|---|---|
| Telnet | Built-in adapter | v1.1 |
| Serial / COM | `serialport` crate | v1.1 |
| Local shell | `portable-pty` | v1.1 |
| PowerShell Remoting / WinRM | Plugin | v1.2 |
| HTTP/HTTPS panel | Embedded WebView tab | v1.2 |
| Kubernetes `exec` | Plugin | v1.2 |
| Docker `exec` | Plugin | v1.2 |
| Proxmox / VMware consoles | Plugin | Community |
| AWS SSM / Azure Bastion | Plugin, custom `Transport` | Community |

The last group illustrates why `Transport` is a trait: a cloud session manager
is a transport, not a protocol. A plugin supplies the transport and the existing
SSH or RDP adapter runs over it unchanged.
