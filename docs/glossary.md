# Glossary

Terms as used in these documents. Where a word has a general meaning and a
Remoter-specific one, the Remoter meaning is given.

**AAD** — Additional Authenticated Data. Data covered by an AEAD's
authentication tag but not encrypted. Remoter uses it to bind ciphertexts to
their context, so they cannot be moved between records or fields.

**AEAD** — Authenticated Encryption with Associated Data. Encryption that also
detects tampering. XChaCha20-Poly1305 throughout.

**Argon2id** — The password-hashing function used for the password key slot.
Memory-hard, which is what makes GPU and ASIC attacks uneconomic.

**asciicast** — The recording format used for terminal sessions; newline-
delimited JSON, from asciinema.

**Blind index** — A keyed, truncated hash allowing equality lookup on encrypted
data without decrypting it. Present in the key hierarchy, unused in v1.0.

**Broadcast typing** — Sending keystrokes to every terminal in a session group
at once.

**CEK** — Content Encryption Key. Derived from the VMK; encrypts the vault body.

**Connection** — A node representing one remote target: protocol, address,
settings, and a credential reference.

**Credential** — A node holding a username and a secret. Referenced by
connections rather than embedded in them, so one credential serves many.

**CredSSP** — The protocol behind RDP's Network Level Authentication.

**Dirty rectangle** — A changed region of a remote framebuffer. Only these are
transmitted and rendered, which is what makes framebuffer streaming feasible.

**Effective connection** — A connection with all inheritance resolved into
concrete values, plus provenance for each.

**Envelope encryption** — Encrypting data with one key, then encrypting that key
with others. What makes multiple independent unlock methods possible.

**FIDO2 / CTAP2** — The standards behind hardware security keys.

**Framebuffer session** — A session whose content is pixels: RDP, VNC.

**Gateway chain** — An ordered list of hops to reach a target. Also "jump host
chain".

**hmac-secret** — The CTAP2 extension that lets a FIDO2 authenticator derive a
stable secret from a salt, without that secret ever leaving the device.

**HKDF** — HMAC-based Key Derivation Function. Used to derive subkeys from
high-entropy material.

**Inheritance** — Settings and credentials flowing from a folder to everything
beneath it, with per-field override.

**IronRDP** — The pure-Rust RDP implementation Remoter uses.

**Jump host** — An intermediate machine used to reach one that is not directly
reachable. Also "bastion".

**KDF** — Key Derivation Function.

**KEK** — Key Encryption Key. The per-slot key that wraps the VMK.

**Key file** — A file used as a second factor alongside the master password.

**Key slot** — One stored, wrapped copy of the VMK, unlockable by one method.
Modelled on LUKS keyslots.

**NLA** — Network Level Authentication. RDP authenticating the server before
credentials are sent.

**Node** — Any item in the tree: folder, connection, credential, group or
separator.

**Nonce** — A number used once. Reusing one with the same key breaks the
encryption entirely, which is why Remoter uses 192-bit random nonces.

**Protocol adapter** — An implementation of the `Protocol` trait for one
protocol.

**Provenance** — Where an inherited value came from, shown in the UI next to
that value.

**Recovery key** — A 256-bit key shown once at vault creation. The last resort
when the password and key file are lost.

**RFB** — Remote Framebuffer, the protocol VNC speaks.

**russh** — The pure-Rust SSH implementation Remoter uses.

**Sans-I/O** — A design where protocol logic is a state machine with no I/O of
its own, driven by the caller. Makes protocols testable without sockets and lets
Remoter inject any transport.

**SEK** — Secret Encryption Key. Derived from the VMK; encrypts individual
secret fields inside the already-encrypted database.

**Session** — One live connection to one remote target.

**Terminal session** — A session whose content is a byte stream: SSH, serial,
local shell.

**Tombstone** — A soft-deleted row retained so a future synchronisation can
propagate the deletion.

**Transport** — A connected, bidirectional byte stream handed to a protocol
adapter. May be a plain socket, an SSH channel, a proxy connection or a TLS
wrapper.

**TOFU** — Trust On First Use. Accepting an identity the first time and pinning
it thereafter.

**Vault** — A `.rvault` file: the encrypted container holding everything.

**VMK** — Vault Master Key. The 256-bit key at the root of the hierarchy. Never
stored in plaintext.

**Zeroize** — To overwrite a memory buffer holding a secret, with compiler
fences so the overwrite is not optimised away.
