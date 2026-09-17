# Protocols

What each protocol adapter supports, which library implements it, and where the
gaps are.

> **What ships.** SSH, SFTP, RDP and VNC are implemented and have run against
> real servers. FTP/FTPS has no adapter and no crate. The matrix below is the
> ground truth for the four that exist; ✅ means a user can do it in a running
> build, ⏳ means specified and not built, and — means it does not apply. Where
> the adapter's own `capabilities()` disagrees with anything here, the adapter
> wins and this file is the bug.

## Capability matrix

| | SSH | SFTP | RDP | VNC | FTP/FTPS |
|---|:---:|:---:|:---:|:---:|:---:|
| Session kind | Terminal | File transfer | Framebuffer | Framebuffer | File transfer |
| Library | `russh` | `russh-sftp` | `IronRDP` | `vnc-rs` | `suppaftp` — *not a dependency* |
| Status | ✅ shipped | ✅ shipped | ✅ shipped | ✅ shipped | ⏳ not started |
| Resize | ✅ | — | ✅ where the server opens MS-RDPEDISP | ⏳ needs `SetDesktopSize` | — |
| Clipboard, text | — | — | ✅ both ways, each a setting | ⏳ half on the wire, unreachable | — |
| Clipboard, files | — | — | ⏳ v1.1 | — | — |
| File transfer | via SFTP on the same connection | ✅ | ⏳ drive redirect | — | ⏳ |
| Audio | — | — | ⏳ v1.1 | — | — |
| Printing | — | — | ⏳ v1.2 | — | — |
| Multi-monitor | — | — | ⏳ v1.1 | — | — |
| Recording | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| Tunnelling | ✅ | ✅ | ✅ | ✅ | ⏳ |
| Agent auth | ✅ off by default | ✅ off by default | — | — | — |

Tunnelling is ✅ everywhere because transport is injected rather than dialled
([session-pipeline.md](../architecture/session-pipeline.md#4--transport)).

### The rows that were wrong, and what is actually true

**Clipboard.** RDP reports `ClipboardSupport::Text` and carries text both ways;
VNC and SSH report `None`, and the interface does nothing clipboard-shaped for
them. The four protocols differ underneath:

- **RDP** requests the MS-RDPECLIP channel whenever the connection lets text
  cross in either direction — *Paste into the remote desktop* and *Copy from the
  remote desktop* are two settings, both on by default. Text copied on the
  server is fetched as soon as the server announces it and written to the local
  clipboard. Local text is offered with delayed rendering (§1.3.1.4): announced
  as `CF_UNICODETEXT` and sent only when something on the server pastes it. The
  interface asks the core to offer it — `session_clipboard_sync`, which reads the
  clipboard in the core so that the text never crosses into the WebView — when
  the tab takes the keyboard, when the window regains focus over it, and before
  Ctrl+V, Shift+Insert or Cmd+V is sent. An offer of text the server already
  holds, including text that came from it, does nothing: without that, clicking
  back into the tab after copying a range of cells on the server would replace
  the server's clipboard with plain text. Lines end in CRLF on the wire and on a
  Windows clipboard and in LF elsewhere. A clipboard PDU declaring more than
  16 MiB is dropped whole on its first chunk and the tab says so, rather than
  ending the session; an offer above 4 MiB is refused the same way, and a server
  that still has not opened the channel a minute into the session is reported
  once. ⏳ Files, images and rich formats do not cross — text only.
- **VNC** can write the remote clipboard — `ClipboardOp::Offer(Text)` becomes a
  `ClientCutText` (RFC 6143 §7.5.6), lossily, because `vnc-rs` writes UTF-8 where
  RFB wants Latin-1 and so the transcoder restricts to ASCII and reports what it
  substituted. Reading is refused: a `ServerCutText` is announced as an offer
  and its text deliberately dropped rather than held in memory.
  `SessionEvent::ClipboardContent`, which RDP delivers remote text through, now
  exists; ⏳ wiring VNC's reading to it, and the interface's offers to VNC, is
  not done, so of `None` and `Text` the true answer is still `None`.
- **SSH** has no clipboard of its own; copy and paste in a terminal tab is
  xterm.js and the host operating system, which is what a terminal user expects.
- **SFTP** has no text to offer, and putting a *file* on the local clipboard is
  the `ClipboardPolicy::files` capability that
  [transport-security.md](../security/transport-security.md) keeps off
  everywhere.

**Recording.** Nothing records anything, on any protocol. There is no
`remoter-record` crate, no writer, no player and no control in the interface —
see [recording-audit.md](recording-audit.md). Three adapters report
`recordable: true` in their capabilities, which is a promise about the session
being replayable in principle and is read by no consumer.

**Agent auth** was not wrong, only unqualified. It works, and it is **off by
default** on purpose: each identity an
agent offers spends one of the server's `MaxAuthTries`, so an agent holding keys
the server will not take can get the connection dropped before the vault's own
password is tried.

---

## SSH

**Library**: [`russh`](https://github.com/Eugeny/russh) 0.63 — pure Rust, Tokio,
no `libssh2`.

**Authentication**: public key (vault or agent), password, and
keyboard-interactive including 2FA prompts. ⏳ GSSAPI/Kerberos and SSH
certificates are specified and not implemented — neither appears in `auth.rs`,
and a server that offers only those will report that no method succeeded.

**Key formats**: OpenSSH (`ed25519`, `ecdsa`, `rsa`), PKCS#8 (encrypted and
not), the legacy PEM containers — PKCS#1 RSA under `BEGIN RSA PRIVATE KEY`,
which is what AWS EC2 hands out, and SEC 1 under `BEGIN EC PRIVATE KEY` — and
PuTTY `.ppk` (v2 and v3), the last being essential for migration from PuTTY and
Royal TS. A key is identified by its contents, not its extension, so a PuTTY key
saved as `id_rsa` is read correctly.

A legacy PEM is re-enveloped as PKCS#8 as it is stored, so the vault holds one
representation; where the PEM is itself enciphered — `Proc-Type: 4,ENCRYPTED`
with an RFC 1421 `DEK-Info` header — the passphrase is what opens that
container, and the key is stored deciphered under the vault's own encryption
with no passphrase beside it. AES-128, AES-192 and AES-256 in CBC are read.
A PEM enciphered with DES-EDE3-CBC, which OpenSSL wrote before 1.1, is **not**:
it is refused by name, with the `ssh-keygen -p` that converts a copy. A block
whose RFC 1421 header is damaged — a `Proc-Type` with no `DEK-Info` under it, a
`DEK-Info` whose initialisation vector is not sixteen bytes of hexadecimal — is
refused with a sentence naming the damaged line, not as a file that is not a
key.

An **encrypted PKCS#8** file is stored ciphertext and all, with its passphrase
beside it, so the scheme inside it has to be one this build can open. Those are
PBES2 (RFC 8018) with PBKDF2 under HMAC-SHA-1 or an HMAC-SHA-2 function, or
scrypt, over AES-128, AES-192 or AES-256 in CBC mode — what `ssh-keygen -m PKCS8`
and `openssl pkcs8 -topk8` write today. HMAC-SHA-1 is the DEFAULT RFC 8018 §A.2
gives, and the LibreSSL-linked `ssh-keygen` Windows ships writes it, so it is
read. Anything else is refused **when the file is chosen**, naming the scheme,
rather than accepted and left to fail at connect time: `openssl genrsa -des3` on
OpenSSL 3 writes PBES2 over `des-ede3-cbc`, which cannot be opened here.

An **encrypted SEC 1 elliptic-curve key** — `-----BEGIN EC PRIVATE KEY-----` with
a `DEK-Info` header — may spell its curve out as explicit domain parameters
rather than naming it; the `ssh-keygen` macOS ships writes it that way. Those are
recognised as P-256, P-384 or P-521 when every parameter matches, and a private
key an encoder shortened by dropping leading zero octets is padded back to the
curve's length (RFC 5915 §3).
`remoter-proto-ssh`'s `keyfmt` module carries the readable set and the test that
establishes it; `remoter-vault`'s `pkcs8` module mirrors it for the refusal.

**A passphrase is tried against the key before it is stored.** An encrypted
OpenSSH or PKCS#8 container is sealed verbatim, so nothing downstream of the
import checks the passphrase against it — and until this check existed nothing
did: a wrong one was accepted, written to the vault, and surfaced days later as
"the server rejected these credentials", said about a machine that had never seen
the key. The container is now opened at the moment the passphrase is offered: an
OpenSSH one by deriving with bcrypt-pbkdf and comparing the two check integers
`PROTOCOL.key` puts at the head of the private section, a PKCS#8 one by running
its PBES2 derivation and requiring the plaintext to be a `PrivateKeyInfo`.

Four things can be wrong and they are four failures, because they have four
remedies:

| What is wrong | Code | What the reader does |
|---|---|---|
| No passphrase, and the container is enciphered | `key.passphrase-required` | Type one |
| The passphrase does not open the container | `key.passphrase-rejected` | Type a different one |
| A passphrase for a container that is not enciphered | `key.passphrase-not-needed` | Store the key without one |
| A container this build cannot open to find out | `key.passphrase-uncheckable` | Convert a copy |

The last of those is a refusal and not a shrug. It covers a PuTTY `.ppk`, whose
derivation this build does not implement, and an OpenSSH container under an AEAD
cipher — `ssh-keygen -Z aes256-gcm@openssh.com` and its ChaCha20-Poly1305
sibling. The key parser reads all of them, so this is a gap in the *check* and
not in what the application can connect with; storing a passphrase nothing can
check would put the failure back where it was, at connect time and a long way
from its cause, so the import says so instead.

An unenciphered container is held to the same standard, because its plaintext is
readable without any passphrase at all: an OpenSSH one must carry matching check
integers, and a PKCS#8 one must be a whole `PrivateKeyInfo` rather than a file
that merely begins with a DER `SEQUENCE` tag.

**Channels**: interactive shell with PTY, `exec` for one-shot commands,
`direct-tcpip` for forwarding and gateway chains, `subsystem` for SFTP, and
optional agent forwarding (off by default, with a warning — a compromised remote
host with a forwarded agent can impersonate the user everywhere that key opens).
There is no SCP implementation and none is planned: SFTP does the same job over
the same connection.

**Terminal**: xterm.js with the WebGL renderer, plus the fit, search and
web-links addons. True colour, 256 colours, mouse reporting, bracketed paste,
OSC 8 hyperlinks, correct wide-character and combining-mark handling, working
IME. The palette is user-editable in Settings, with a live contrast check.

**Settings** (each one validated against the adapter's own schema, which is what
generates the editor's form): terminal type (`xterm-256color` default), initial
columns and rows, environment variables as `NAME=value` lines, compression, an
initial command, an `exec` command, agent authentication, which agent identity to
use, and agent forwarding. Keep-alive is a field on the connection rather than a
protocol setting.

⏳ **Not in the schema**: per-connection algorithm preferences and X11
forwarding. `x11_forwarding` is specifically tested as an *unknown* key, so
setting it is reported rather than silently ignored.

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
other. Drag and drop between the panes and from the desktop, including on
Windows, where the webview ate the drop until
[ADR-0014](../architecture/decisions/0014-drag-and-drop-on-windows.md).

A pane attaches to a *session*, not to a node: `sftp_open` opens one more channel
on the connection a tab already holds (RFC 4254 §6.5), so a file manager on a
host with a shell costs a channel and not a second handshake, host key check and
authentication.

**Operations**: browse, upload, download, rename, delete (recursively, unlinking
symbolic links rather than following them), `mkdir`, `chmod`, `stat`,
`canonicalize`, `readlink` and `symlink`. ⏳ `chown` is not implemented — the
owner and group are read and displayed, not set — and neither is edit-in-place.

Every server-supplied name crosses the boundary twice: raw, which is what goes
back on the wire, and escaped, which is what a human reads, with the control
bytes, bidirectional overrides, zero-width characters and path separators found
in it reported per row.

**Transfers**: a queue with per-file progress pushed over the session's event
channel every 512 KiB rather than polled, resume where the destination is
strictly shorter than a source of known size — and a refusal that names the file
in the way where it is not — per-transfer cancellation, cancel-all, and retry.
The queue lives beside the session rather than in the interface, so it survives a
tab switch. Conflicts prompt with size and timestamp rather than silently
overwriting. ⏳ There is no pause, and no aggregate progress across the queue.

**Not in v1.0**: server-to-server transfer, and synchronisation/mirroring modes.

---

## RDP

**Library**: [`IronRDP`](https://github.com/Devolutions/IronRDP) 0.17 — pure
Rust, maintained by Devolutions, used in production by Cloudflare Access and
Teleport. Sans-I/O state machines, which is exactly what the injected-transport
design needs.

**Security**: Enhanced RDP Security with TLS, and NLA via CredSSP with **NTLMv2
only**, using extended session security. The `pubKeyAuth` exchange proves the
server holds the certificate's private key *before* the password is sent, with
known-answer tests against MS-NLMP §4.2.4. The server certificate gets the same
treatment as an SSH host key: an unknown one prompts with its fingerprint,
acceptance pins it, and a changed pinned certificate is a hard failure that only
a typed confirmation of the offered fingerprint can override.

⏳ **Kerberos is not implemented** — it needs a KDC, a realm and an SPN resolved
through DNS, and a domain that has disabled NTLM cannot be reached by this
build. ⏳ Restricted Admin mode and Remote Credential Guard are likewise
specified and absent.

**Graphics**: whatever IronRDP decodes for the capabilities this client
advertises, which includes RemoteFX and the uncompressed 32bpp surface-bits
path. ⏳ Colour depth is **not** configurable — the Client Core Data asks for
`WANT_32_BPP_SESSION` and offers no choice — and there is no bandwidth profile.

**Display**: the tab scales the framebuffer it is given. Dynamic resolution
needs the Display Control channel (MS-RDPEDISP), which the **server** opens; an
older Windows host or an `xrdp` never does, so `capabilities()` reporting
`resizable: true` is this adapter's offer and not a promise about a particular
server. What a given session actually got is `RdpSession::granted_capabilities`,
and a refusal reaches the user as a warning rather than a swallowed log line.
⏳ What is still missing is the plumbing that would let `remoter-ipc` replace a
tab's stored capabilities with the granted ones mid-session, and ⏳ HiDPI
framebuffers at physical pixel size.

**Input**: full scancode translation, which is where keyboard-layout bugs live.
The mapping tables are tested against Turkish Q and F, German, French AZERTY,
Spanish, Russian and Arabic layouts.

**Keyboard layout**: RDP sends scancodes and the *server* decodes them, using
the identifier the client names once in the Client Core Data
(MS-RDPBCGR §2.2.1.3.2). Naming the wrong one types the wrong characters and
reports no fault, so the identifier is a setting on the connection —
inheritable from a folder like any other — and its default is **read from the
machine the user is sitting at** rather than fixed. Windows is asked for the
layout it has configured; elsewhere the active X keyboard layout, or failing
that the locale, is mapped onto a Microsoft identifier. Where none of that
answers, the session falls back to US English **and says so** on screen: a
guess that announces itself is recoverable and a silent one is not. The picker
offers the layouts worth listing by name — Turkish Q and Turkish F are two of
them, and they are two different identifiers — and accepts any other
identifier typed in, because Microsoft publishes several hundred.

**Gateway**: ⏳ RD Gateway support is planned for v1.1. RDP through an SSH
bastion works via the gateway chain, set in the connection editor's Jump hosts
section, which covers most of the same need.

**Known gaps versus FreeRDP** — stated plainly because users will hit them:
audio and microphone redirection, printer redirection, smart card redirection,
USB redirection, drive redirection, files and images over the clipboard, and
multi-monitor are all absent. ⏳ The per-connection "open in external client" escape hatch is
specified and not built either, so where a gap blocks a user today the answer is
`mstsc` or `xfreerdp` started by hand.

---

## VNC

**Library**: [`vnc-rs`](https://crates.io/crates/vnc-rs) 0.5.

**Encodings**: **Raw and CopyRect, plus the three pseudo-encodings, and nothing
else.** Tight, ZRLE, TRLE, Hextile and RRE were all withdrawn by
[ADR-0013](../architecture/decisions/0013-rfb-handshake-and-bounded-input.md),
which owns the RFB handshake and every length this build acts on rather than
letting `vnc-rs` size an allocation from a wire field. Tight has no RFC and its
rectangles are delimited by a compression stream rather than by a length; ZRLE
and TRLE are framable but the run length that matters is written *inside* the
compressed stream. The cost is real — a slow link now sends raw pixels, and
CopyRect is the only saving left — and it is the price of not trusting a remote
host to choose this process's allocation sizes. ⏳ Re-adding them means bounding
them here first.

**Compatibility**: any server that speaks RFB 3.3–3.8 with `None` or VNC
Authentication. ⏳ The milestone's exit criterion — verified against TigerVNC,
TightVNC, RealVNC and x11vnc — has not been run.

**Security** is RFB's weak point and Remoter treats it as such. Classic VNC
authentication uses DES with an 8-byte key and no transport encryption, and
those two types are all this build can negotiate: ⏳ **VeNCrypt, RA2, Tight
security and Apple's RD are refused**, because `vnc-rs` 0.5 cannot complete any
of them and offering a connection that cannot succeed is worse than saying which
type would have been needed.

So an unencrypted RFB session is the normal case, and it is classified rather
than blanket-warned: loopback (the recommended configuration, and where an SSH
forward arrives) is annotated, a private or carrier-grade-NAT address is
annotated more loudly, and anything routable — including every DNS name, because
nothing here resolves one — is **blocking**. The warning is suppressed entirely
when the injected transport already protects the session, which the adapter
establishes by asking the transport what carries it rather than by guessing: an
SSH channel or a TLS session counts, a SOCKS5 or HTTP `CONNECT` proxy does not.
⏳ The connection editor's one-click "secure this with SSH" is not built; the
tunnel has to be created by hand.

**Features**: view-only mode — which covers the clipboard as well as the
keyboard, since `ClientCutText` replaces the server's selection and so modifies
the remote machine as surely as a keystroke — a shared/exclusive switch, cursor
handling, and an RFB version floor and ceiling. ⏳ `SetDesktopSize` needs client
messages outside RFC 6143 that `vnc-rs` does not implement, so `resizable` is
`false` and the tab scales instead. ⏳ JPEG quality is a Tight-encoding setting
and Tight is not offered.

**On `vnc-rs` maturity.** It is younger than the other protocol crates, and
that is a real dependency risk. The response is contingency rather than
avoidance: the adapter interface confines VNC to one crate, so if upstream
stalls we maintain a fork and nothing else in the codebase changes. The
milestone exit criteria — working against TigerVNC, TightVNC, RealVNC and x11vnc
— are what would surface the problem early enough to act on.

---

## FTP and FTPS — ⏳ not started

**Planned library**: [`suppaftp`](https://crates.io/crates/suppaftp), which is
not a dependency of this workspace. There is no `remoter-proto-ftp` crate, and
`ftp` is not one of the protocols the connection editor offers, so a connection
cannot be created for it.

Included in the plan because network appliances and legacy systems still require
it, not because it is a good idea. FTPS (explicit TLS) would be supported with
certificate validation; plain FTP would carry a persistent warning badge in the
UI and require per-connection opt-in, because it sends credentials in clear text.

Active and passive modes, resume, and directory listing parsing for both Unix
and DOS-style server responses.

---

## Planned

None of these exists. Everything in this table needs an adapter that has not
been written, and the four plugin rows additionally need the plugin host, which
has not been written either.

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
