# Threat Model

This document states what Remoter protects, from whom, and — just as
importantly — what it does not protect against. A security tool that is vague
about its limits is a liability.

## Assets

Ranked by the damage their disclosure causes.

| # | Asset | Why it matters |
|---|---|---|
| A1 | Stored credentials — passwords, private keys, passphrases, API tokens | Direct lateral movement into every system the user administers |
| A2 | The Vault Master Key and derived keys, in memory | Unlocks A1 wholesale |
| A3 | The recovery key | Unlocks the vault permanently, bypassing the password |
| A4 | Connection inventory — hostnames, IPs, ports, usernames | A map of the target estate; valuable even without passwords |
| A5 | Live session content — keystrokes, framebuffers, transferred files | Real-time compromise; may include credentials typed into the session |
| A6 | Session recordings and audit logs | Historical A5, at rest |
| A7 | Host key and certificate trust store | Poisoning it enables silent MITM on future connections |

## Adversaries

| # | Adversary | Capability | In scope? |
|---|---|---|---|
| T1 | Thief of the vault file | Reads `*.rvault` from a backup, cloud sync folder, stolen laptop or discarded disk. Offline, unlimited time, GPU/ASIC cluster | **Yes — primary** |
| T2 | Passive network observer | Sees all traffic between Remoter and remote hosts | **Yes** |
| T3 | Active network attacker | Can MITM, spoof DNS, present forged host keys and certificates | **Yes** |
| T4 | Malicious remote host | A server the user connects to, already compromised, sending hostile protocol data | **Yes** |
| T5 | Malicious plugin | A third-party WASM extension the user installed | **Yes** |
| T6 | Malicious import file | A crafted `confCons.xml`, `.rtsz` or `ssh_config` shared by a colleague | **Yes** |
| T7 | Shoulder surfer / unattended screen | Physical proximity, no code execution | **Partial** |
| T8 | Local unprivileged process | Another user account on a shared machine | **Partial** |
| T9 | Malware running as the user | Keylogger, memory scraper, or a trojaned Remoter binary | **No — see below** |
| T10 | Malicious maintainer / supply chain | Compromised dependency or release pipeline | **Partial — mitigated, not solved** |
| T11 | Adversary with root / kernel access | Full machine control | **No** |
| T12 | Physical attacker with a cold-boot or DMA setup | Reads RAM directly | **No** |

## Controls, by adversary

### T1 — Offline vault theft (primary)

This is the threat the whole cryptographic design exists to answer.

- Content encrypted with **XChaCha20-Poly1305**, 256-bit key, 192-bit random nonces
- Key derived with **Argon2id**, calibrated to ≈1 second on the user's own
  machine (floor: 256 MiB memory, t=3, p=4). Memory-hardness is what makes GPU
  and ASIC clusters uneconomic; iteration counts alone are not enough
- **Envelope encryption with independent key slots** — see
  [vault-format.md](vault-format.md). Compromising one slot does not reveal the
  others' key material
- **Two-tier protection**: individual secret fields are encrypted a second time
  with a key derived from the Vault Master Key, with associated data binding
  each ciphertext to its record and field. Even a fully decrypted database file
  does not yield plaintext passwords
- The header is authenticated. An attacker cannot downgrade the KDF parameters,
  delete a slot or swap ciphertexts between records without detection

**Residual risk:** a weak master password with no key file and no hardware key.
Argon2id raises the cost per guess by roughly six orders of magnitude versus a
bare hash, but it cannot rescue `Password123`. Remoter therefore enforces a
minimum entropy estimate at vault creation and offers a generated passphrase.

### T2/T3 — Network attackers

- SSH: strict host key verification. Trust-on-first-use shows the full
  fingerprint and requires an explicit decision; a **changed** key is a hard
  failure with a prominent warning, never a soft prompt
- RDP: TLS with certificate validation, plus NLA/CredSSP so credentials are not
  exposed to a server that has not authenticated first. Downgrade to legacy RDP
  Standard Security requires a per-connection opt-in that is recorded in the
  audit log
- VNC: RFB's native authentication is weak by design. Remoter therefore defaults
  to refusing plain VNC over untrusted networks and steers the user to tunnel it
  over SSH, which is one click from the connection editor
- All TLS via `rustls` — no OpenSSL, no system trust-store ambiguity. Optional
  per-connection certificate pinning
- The trust store (A7) lives inside the encrypted vault, not in a plaintext
  `known_hosts` file

### T4 — Malicious remote host

This is why the protocol stack is pure Rust. RDP, RFB and SFTP decoders parse
attacker-controlled, length-prefixed binary data; a buffer overflow in a C
decoder is a full compromise of the process that holds every credential.

- All protocol crates are `#![forbid(unsafe_code)]`
- Decoders are fuzzed continuously (`cargo-fuzz`) against corpora of real and
  mutated captures
- Resource limits per session: maximum frame size, maximum channel count,
  maximum decompressed size (protecting against decompression bombs in RDP 6.0
  and RemoteFX)
- Remote-controlled strings — MOTD, server banners, window titles, directory
  listings — are rendered as text, never as markup. No `dangerouslySetInnerHTML`
- Clipboard synchronisation from remote to local is **off by default** for
  file-type clipboard formats
- A panic in a decoder fails one tab, not the process

### T5 — Malicious plugin

- Plugins are WebAssembly, executed in a Wasmtime sandbox with no ambient
  authority: no filesystem, no network, no environment, no clock beyond what is
  granted
- Capabilities are declared in a manifest, shown to the user at install time in
  plain language, and enforced by the host — not by convention
- A plugin **never** receives the Vault Master Key. Credential access is
  mediated: the plugin asks for a named credential by purpose, the host decides,
  and the user sees the request
- Plugins run with fuel metering and wall-clock limits; a runaway plugin is
  terminated, not tolerated
- Details in [../architecture/plugin-system.md](../architecture/plugin-system.md)

### T6 — Malicious import file

Import parsers are the classic soft underbelly of connection managers: XML with
entity expansion, zip files with traversal paths, INI files with unbounded keys.

- XML parsing with external entities and DTDs **disabled** — no XXE, no billion
  laughs
- Archive extraction rejects absolute paths, `..` segments and symlinks
- Every parser has a `cargo-fuzz` target and a corpus of real-world files
- Imports run in a transaction and are previewed before commit; nothing touches
  the vault until the user confirms what was found

### T7 — Unattended screen

- Auto-lock on configurable idle timeout, on OS screen lock, and on suspend
- Locking clears the Vault Master Key and every derived key from memory and
  requires a full unlock; it does not merely blank the window
- Optional: disconnect or freeze all sessions on lock
- Passwords are never shown in clear by default; revealing one requires an
  explicit action and is written to the audit log

### T8 — Local unprivileged process

- Vault file permissions `0600` on Unix, owner-only ACL on Windows
- No secrets in command-line arguments (visible in `/proc` and Task Manager),
  no secrets in environment variables, no secrets in temporary files
- When Remoter must hand a credential to an external helper, it uses a pipe or
  an anonymous socket, never `argv`
- On Linux, `prctl(PR_SET_DUMPABLE, 0)` and a `ptrace` scope check at startup
  with a warning if the system permits arbitrary same-user ptrace
- Core dumps disabled for the process

### T9 — Malware running as the user: **out of scope**

If an attacker executes code as your user account, they can read your memory,
log your keystrokes and replace the Remoter binary. No user-space application
can defend against this, and any product claiming otherwise is selling
something. We reduce the *window*, we do not close it:

- Keys live in memory only while unlocked, and are zeroized on lock, on
  disconnect and on drop
- `mlock`/`VirtualLock` on key pages where the OS permits, to keep key material
  out of swap
- Compiler-fence-protected zeroization (`zeroize` crate) so the clearing is not
  optimised away

### T10 — Supply chain: mitigated, not solved

- `cargo-deny` and `cargo-audit` in CI, failing the build on known advisories
- `Cargo.lock` and `package-lock.json` committed; dependency updates reviewed,
  never auto-merged
- Reproducible release builds as a goal, with a published SBOM per release
- Release artefacts signed; checksums published
- Minimal dependency count is an explicit design value, not an afterthought

### T11/T12 — Root, kernel, cold boot: **out of scope**

Stated for honesty. Against an adversary with kernel access or physical memory
capture, the correct mitigations are full-disk encryption, secure boot and
hardware key storage — all outside this application's control.

## Explicit non-goals

Remoter does **not**:

- Recover your vault if you lose both the master password and the recovery key.
  There is no escrow, no backdoor, no support-desk override. This is deliberate:
  a recovery channel we control is a recovery channel an attacker can subvert
- Defend against an already-compromised operating system
- Protect against a user who chooses to store a password in a connection's
  "description" field, or who screenshots a revealed password
- Guarantee that a remote host is not recording the session at the far end
- Provide anonymity. Remoter connects directly to the hosts you configure

## Cryptographic agility

Every encrypted structure carries a version byte and an algorithm identifier.
When a primitive needs replacing, the vault can be re-encrypted in place with a
new algorithm without changing the file format. Readers refuse unknown versions
rather than guessing — fail closed, never open.

## Review status

| Area | Status |
|---|---|
| Design review, internal | Pending first implementation |
| Independent cryptographic review | **Required before v1.0.** Tracked in the roadmap |
| Penetration test | Planned post-1.0 |

Independent review of the vault format is a **release gate for v1.0**, not an
aspiration: the tag does not happen until a review has been done and its
findings addressed. The specification is public before implementation for
exactly this reason. Contributors with applied-cryptography experience are
specifically invited — see [SECURITY.md](../../SECURITY.md).
