# Transport Security

How Remoter authenticates the far end of every connection, and where each
protocol's weaknesses lie.

The trust store — SSH host keys, pinned TLS certificates, per-connection
exceptions — lives **inside the encrypted vault**, not in a plaintext
`known_hosts`. Poisoning it therefore requires opening the vault.

## SSH

**Host key verification is mandatory.** There is no "ignore" checkbox, because
in practice a checkbox becomes the default.

| Situation | Behaviour |
|---|---|
| Unknown host, first connection | Prompt showing the full fingerprint (SHA-256, base64) and the key type, plus an ASCII randomart rendering. Requires explicit acceptance |
| Known host, key matches | Connect silently |
| Known host, **key changed** | Hard failure. A red, blocking dialog explaining that this may be a man-in-the-middle attack, showing both fingerprints. Accepting requires typing the word shown on screen |
| Host key found in `~/.ssh/known_hosts` | Imported on first use, with a note in the audit log |

Algorithms, in preference order, following current OpenSSH defaults:

- **Key exchange**: `curve25519-sha256`, `sntrup761x25519-sha512` (post-quantum
  hybrid, preferred where the server offers it), `diffie-hellman-group16-sha512`
- **Host keys**: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `rsa-sha2-512`
- **Ciphers**: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`,
  `aes128-gcm@openssh.com`
- **MACs**: encrypt-then-MAC variants only

Legacy algorithms (`ssh-rsa` with SHA-1, `3des-cbc`, `hmac-md5`, DH group 1) are
**not compiled in** for v1.0. Network engineers with old switches genuinely need
them; that is handled by a separate, clearly-labelled "legacy compatibility"
build feature rather than by weakening the default binary.

Authentication methods: public key (from the vault or an agent), password,
keyboard-interactive (including 2FA prompts), and GSSAPI/Kerberos where the
platform provides it.

## RDP

**Network Level Authentication is the default and should stay on.** With NLA,
CredSSP authenticates the server before the user's credentials are sent; without
it, credentials go to whatever answered the port.

| Security layer | Default | Notes |
|---|---|---|
| Enhanced RDP Security (TLS) + NLA/CredSSP | **On** | NTLM and Kerberos both supported by IronRDP |
| TLS certificate validation | **On** | System trust store via `rustls`, plus optional per-connection pinning |
| Standard RDP Security (legacy RC4) | Off | Requires per-connection opt-in with a warning; recorded in the audit log |

Self-signed certificates are the norm on internal RDP hosts. Remoter's answer is
**trust on first use with pinning**: the first connection shows the certificate
details and its fingerprint; accepting pins it to that connection. A subsequent
change is treated like a changed SSH host key.

Restricted Admin mode and Remote Credential Guard are supported where the server
allows them — both avoid sending reusable credentials to the target and are
recommended for administrative connections.

## VNC / RFB

RFB's native security is weak and cannot be fixed at the client:

- The classic VNC authentication type uses **DES with a 8-byte key** and no
  transport encryption. It is broken, and Remoter treats it as such
- Extensions vary by server (RealVNC, TightVNC, TigerVNC, UltraVNC each differ)
- No integrity protection on the pixel stream

Remoter's position:

1. **Tunnel it.** The connection editor offers "secure this with SSH" as a
   one-click action that creates the tunnel and rewrites the target to
   `localhost`. This is presented as the recommended configuration
2. VNC over TLS (`VeNCrypt`) is used where the server supports it
3. Connecting with plain VNC authentication to a non-loopback, non-RFC1918
   address shows a blocking warning that names the risk in plain language

## SFTP and FTP

- **SFTP** runs inside SSH and inherits all of the above. Preferred always
- **FTPS** (explicit TLS) is supported with certificate validation
- **Plain FTP** transmits credentials and data in clear text. It is available
  because network appliances still require it, but it is marked with a
  persistent warning badge in the UI and requires per-connection opt-in

## Tunnels and jump hosts

Every hop in a chain is independently authenticated with its own credentials and
its own host key check. There is no "trust the whole path because the first hop
was fine".

A jump host chain is built from `direct-tcpip` channels: hop 1 opens a channel
to hop 2, and the next protocol handshake runs *inside* that channel. Because
the `Protocol` trait receives an already-connected transport
([overview.md](../architecture/overview.md#the-protocol-trait)), an RDP session
through two SSH bastions uses exactly the same code path as a direct one.

Dynamic (SOCKS5) forwarding binds to loopback only by default. Binding a
forward to a non-loopback address exposes it to the local network and requires
an explicit setting with an inline warning.

## Clipboard and device redirection

Redirection is convenient and is also a data-exfiltration path in both
directions.

| Feature | Default | Rationale |
|---|---|---|
| Clipboard, text, local → remote | On | Expected behaviour; the user initiated the paste |
| Clipboard, text, remote → local | On | Needed constantly for copying output |
| Clipboard, **files** | **Off** | A compromised host should not be able to drop files into your clipboard |
| Drive redirection | **Off** | Per-connection opt-in, per-folder, read-only offered first |
| Printer redirection | Off | Opt-in |
| Smart card redirection | Off | Opt-in |
| Audio, remote → local | On | Low risk |
| Microphone, local → remote | **Off** | Opt-in |
| USB redirection | Off | Opt-in, v2 |

Settings are inheritable through the folder tree, so an organisation can set
"no drive redirection" once at the root and have it apply everywhere beneath.

## Cryptographic library choices

| Purpose | Library | Why |
|---|---|---|
| TLS | `rustls` | Memory-safe, modern defaults, no OpenSSL configuration surface |
| SSH | `russh` | Pure Rust, actively maintained, no `libssh2` C dependency |
| RDP | `IronRDP` | Pure Rust, security-focused, maintained by Devolutions, includes CredSSP |
| Symmetric AEAD | `chacha20poly1305` (RustCrypto) | Audited, constant-time, no hardware assumptions |
| Password KDF | `argon2` (RustCrypto) | RFC 9106 |
| Hashing / MAC | `blake3` | Fast, keyed-MAC mode built in |

The common thread is **no C dependency in the network-facing path**. Remoter
parses hostile input from potentially compromised servers while holding every
credential its user owns; a memory-safety bug in a decoder would be a total
compromise. That constraint is worth the occasional feature gap.
