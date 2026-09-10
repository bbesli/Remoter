# ADR-0002: Envelope encryption with independent key slots

- **Status**: Accepted
- **Date**: 2026-09-10

## Context

The vault must be openable by several independent methods — a master password,
optionally combined with a key file; a FIDO2 hardware key; the OS keychain; and
a recovery key for when the others are lost. Losing one method must not lose the
vault. Adding or revoking a method must not require re-encrypting the data.

The original requirement was phrased as storing passwords "hashed and
irreversible, decryptable only by the application". Those cannot both hold:
Remoter must transmit the actual password to an SSH or RDP server, so the
plaintext must be recoverable. Hashing verifies a secret you already have;
encryption stores one you need back. The design must therefore deliver the
*intent* — that stored secrets are useless to anyone who takes the file — through
encryption rather than hashing.

## Options considered

### A · Derive the content key directly from the password

`key = Argon2id(password)`, used to encrypt everything.

**Pros** — trivially simple; nothing extra on disk.

**Cons** — one unlock method only. Changing the password re-encrypts the entire
vault. A recovery key is impossible without storing a second full copy of the
data. Adding a hardware key is impossible.

### B · Envelope encryption with key slots (LUKS model)

A random Vault Master Key encrypts the content. Each unlock method stores its
own wrapped copy of the VMK.

**Pros** — any number of independent unlock methods; adding, rotating or
revoking one rewrites 64 bytes rather than the whole file; changing the password
does not invalidate the recovery key; a well-understood design with two decades
of deployment in LUKS.

**Cons** — more moving parts; the slot table must be authenticated or an attacker
could substitute a weakly-protected slot; each slot is another place to get the
AAD binding right.

### C · Shamir secret sharing

Split the VMK into shares requiring k-of-n to reconstruct.

**Pros** — elegant for team break-glass scenarios.

**Cons** — solves a problem we do not have in v1. Considerably harder to explain
to users, and a mechanism users do not understand is a mechanism they misuse.

## Decision

**Option B**, with a second protection tier inside it.

The full specification is in
[vault-format.md](../../security/vault-format.md). The essentials:

- Vault Master Key: 256 random bits, never written to disk in plaintext
- Content Encryption Key and Secret Encryption Key derived from the VMK by HKDF
  with distinct info strings
- Each key slot wraps the VMK with XChaCha20-Poly1305 under a slot-specific KEK
- Argon2id for the password slot; HKDF for the high-entropy slots (recovery,
  FIDO2, keychain) — a memory-hard KDF over a 256-bit random value costs a
  second and buys nothing
- Header authenticated with a keyed BLAKE3 MAC and bound as AAD to the body, so
  parameters cannot be downgraded and bodies cannot be swapped between vaults
- Secret *fields* are encrypted a second time under the SEK, with AAD binding
  each ciphertext to its record id, field name and revision

That second tier is the part that goes beyond the LUKS analogy, and it is worth
the complexity: it means decrypting the container does not yield plaintext
passwords. At any moment, only the handful of secrets actively in use exist as
plaintext, and a ciphertext cannot be moved between records, between fields, or
rolled back to an earlier revision without detection.

**XChaCha20-Poly1305 over AES-256-GCM**: the 192-bit nonce allows random nonces
with no practical collision risk and no counter state to synchronise. GCM's
96-bit nonce would require careful counter management, which becomes a
correctness hazard the moment a vault is ever synchronised or restored from a
backup.

## Consequences

**Positive.** Multiple independent unlock methods. Cheap rotation. A recovery
key that genuinely works. Defence in depth from the second tier. Cryptographic
agility via version and algorithm identifiers.

**Negative.** More complex than a single derived key, and complexity in
cryptographic code is where bugs live — which is why the format is specified
before implementation and why external review is a v1.0 release gate. Users must
understand that losing every slot means losing the vault; no amount of UI copy
fully prevents that.

**Neutral.** The header is readable without a key. Deliberate: it exposes no
secret and lets tooling inspect which methods a vault supports.

## Revisit if

A primitive is broken or deprecated (the format's version bytes exist for this),
or team features arrive and Shamir sharing becomes genuinely warranted.
