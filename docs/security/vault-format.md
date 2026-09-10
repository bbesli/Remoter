# Vault Format

The `.rvault` container: how it is laid out on disk, how it is encrypted, and
how the key slots work.

> **A note on wording.** People often ask for passwords to be "hashed and
> irreversible". For a connection manager that is impossible by definition:
> Remoter must send the actual password to an SSH or RDP server, so it must be
> able to recover the plaintext. Hashing is for *verifying* a secret you already
> know; encryption is for *storing* a secret you need back.
>
> What Remoter guarantees instead is stronger in practice: the plaintext exists
> **only** in RAM, **only** while the vault is unlocked, and **only** for the
> moments it is actually being used. On disk there is nothing but authenticated
> ciphertext, and the key to it is never stored anywhere — it is re-derived from
> something you know, something you have, or your recovery key, every single
> time.

## Design goals

1. **Single portable file.** Copy it to a USB stick, a Git repository or a
   network share and open it on any platform. No sidecar files, no registry, no
   OS-specific storage required.
2. **Independent key slots.** Losing one unlock method must not lose the vault.
   Adding, rotating or revoking a method must not require re-encrypting the data.
3. **Tamper-evident.** Any modification to the header, the slot table or the
   body is detected before a single byte of plaintext is produced.
4. **Two tiers of protection.** Decrypting the container yields a database whose
   secret fields are *still* encrypted. A memory scrape of the open database
   does not hand over every password at once.
5. **Versioned everything.** Algorithms and parameters are declared, not assumed,
   so they can be upgraded without a format break.

## File layout

```
┌─────────────────────────────────────────────────────────────────────┐
│ MAGIC          8 B   "RMTRVLT\x01"                                  │
│ FORMAT_VER     2 B   u16 LE — currently 1                           │
│ HEADER_LEN     4 B   u32 LE — length of the CBOR header             │
├─────────────────────────────────────────────────────────────────────┤
│ HEADER         variable, CBOR, PLAINTEXT but AUTHENTICATED          │
│   ├ vault_id           UUIDv7                                       │
│   ├ created_at, modified_at                                         │
│   ├ label                    user-chosen display name               │
│   ├ content_cipher           "xchacha20poly1305"                    │
│   ├ kdf                      "argon2id"                             │
│   ├ kdf_params               { m_cost, t_cost, p_cost, version }    │
│   └ slots[]                  the key slot table — see below         │
├─────────────────────────────────────────────────────────────────────┤
│ HEADER_MAC    32 B   BLAKE3 keyed MAC over MAGIC‖VER‖LEN‖HEADER     │
│                      key = HKDF(VMK, "remoter:header-mac:v1")       │
├─────────────────────────────────────────────────────────────────────┤
│ BODY_NONCE    24 B   random, regenerated on every save              │
│ BODY          variable   XChaCha20-Poly1305(CEK, nonce, sqlite_db)  │
│                          AAD = MAGIC ‖ FORMAT_VER ‖ HEADER          │
│ BODY_TAG      16 B                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

The header is readable without any key. That is intentional and safe: it holds
no secret, and it lets a user or a tool inspect which unlock methods a vault
supports before attempting to open it. It is covered by `HEADER_MAC`, so it is
readable but not modifiable.

Binding `AAD = MAGIC ‖ FORMAT_VER ‖ HEADER` means the body cannot be lifted out
of one vault and dropped into another, and the KDF parameters cannot be
downgraded — any tampering makes body decryption fail.

## Key hierarchy

```
                    ┌──────────────────────────────────┐
                    │  Vault Master Key (VMK)          │
                    │  256 bits from the OS CSPRNG     │
                    │  Generated once, at vault        │
                    │  creation. Never stored anywhere │
                    │  in plaintext. Never leaves RAM. │
                    └───────────────┬──────────────────┘
                                    │  HKDF-SHA256, distinct info strings
        ┌───────────────┬───────────┴────────┬──────────────────┐
        ▼               ▼                    ▼                  ▼
  ┌───────────┐  ┌─────────────┐   ┌──────────────────┐  ┌─────────────┐
  │ CEK       │  │ SEK         │   │ header-mac key   │  │ index key   │
  │ content   │  │ per-secret  │   │ BLAKE3 keyed MAC │  │ blind index │
  │ encryption│  │ field       │   │                  │  │ for search  │
  │           │  │ encryption  │   │                  │  │             │
  │ encrypts  │  │ encrypts    │   │                  │  │             │
  │ the whole │  │ each secret │   │                  │  │             │
  │ SQLite DB │  │ individually│   │                  │  │             │
  └───────────┘  └─────────────┘   └──────────────────┘  └─────────────┘

  info = "remoter:cek:v1" / "remoter:sek:v1" / "remoter:header-mac:v1" / "remoter:index:v1"
```

The VMK itself is never written to disk. Instead, each key slot stores a copy of
the VMK **wrapped** by a Key Encryption Key that only that unlock method can
produce. This is the same structure LUKS uses for its keyslots, and for the same
reason: it decouples "who may open the vault" from "how the data is encrypted".

Consequences worth being explicit about:

- Adding or removing an unlock method rewrites **only** the slot table. The
  multi-megabyte body is untouched.
- Changing the master password does not change the VMK, so it does not
  invalidate the recovery key or the hardware key.
- Rotating the VMK (a full re-encryption) is a separate, deliberate operation,
  offered when the user believes a key may have been exposed.

## Key slots

Each entry in `slots[]` is a CBOR map:

```
{
  "index":       u8,           // stable slot number
  "kind":        "password" | "recovery" | "fido2" | "keychain",
  "label":       "Master password",     // shown in the UI
  "created_at":  timestamp,
  "last_used":   timestamp | null,
  "salt":        24 bytes,     // per-slot, random
  "nonce":       24 bytes,     // per-slot, random
  "wrapped_vmk": 32 bytes ciphertext + 16 bytes tag,
  "kdf_params":  { ... } | null,   // present for low-entropy inputs only
  "extra":       { ... } | null    // slot-kind-specific, see below
}
```

Wrapping is always `XChaCha20-Poly1305(KEK, slot.nonce, VMK)` with
`AAD = "remoter:slot:v1" ‖ slot.index ‖ slot.kind`. Binding the index and kind
prevents an attacker from moving a weakly-protected wrapped VMK into a slot the
UI presents as strong.

### How each slot derives its KEK

| Kind | Input entropy | Derivation |
|---|---|---|
| `password` | Low (human-chosen) | `Argon2id(password ‖ keyfile_digest, salt, params)` → 32 B KEK |
| `recovery` | High (256 bits, generated) | `HKDF-SHA256(recovery_key, salt, "remoter:slot:recovery:v1")` → 32 B KEK |
| `fido2` | High (device secret) | `HKDF-SHA256(hmac_secret_output, salt, "remoter:slot:fido2:v1")` → 32 B KEK |
| `keychain` | High (256 bits, generated) | `HKDF-SHA256(keychain_token, salt, "remoter:slot:keychain:v1")` → 32 B KEK |

**Why Argon2id for only one of them.** A memory-hard KDF exists to make guessing
expensive. Guessing is only a threat when the input has low entropy. A 256-bit
random recovery key cannot be brute-forced regardless of the KDF, so spending a
second of Argon2id on it buys nothing and only slows an emergency unlock. Using
the right tool per slot is not a shortcut; it is the correct analysis.

### `password` slot

The password slot optionally incorporates a **key file** — any file the user
chooses (a `.pem`, an image, a random blob). Its contribution is
`keyfile_digest = BLAKE3(file_bytes)`, concatenated with the password before
Argon2id. Both factors are then required together.

```
KEK = Argon2id(
    password_utf8_nfkc ‖ keyfile_digest_or_empty,
    salt   = slot.salt,
    m_cost, t_cost, p_cost from slot.kdf_params
)
```

Passwords are normalised to Unicode NFKC before use, so a password typed on a
different keyboard layout or input method still matches.

**Argon2id parameters.** Calibrated at vault creation to take approximately one
second on the creating machine, subject to a hard floor:

| | Floor | Typical desktop, 2026 |
|---|---|---|
| `m_cost` (memory) | 256 MiB | 512 MiB – 1 GiB |
| `t_cost` (iterations) | 3 | 3–4 |
| `p_cost` (parallelism) | 4 | min(4, cores) |

Parameters are stored per slot, so a vault created on a workstation still opens
on a low-memory laptop — just more slowly. If a vault's parameters are below the
current floor, Remoter offers to upgrade them on the next successful unlock.

### `recovery` slot

Created automatically with every new vault. This is the answer to "what if I
lose my password or my key file?".

- 256 bits from the OS CSPRNG
- Displayed as 8 groups of 6 characters in Crockford Base32 (excludes I, L, O, U
  to avoid transcription errors), with a checksum group:

  ```
  RMTR-4K7P2M-9XQW3T-BF6HYN-58JVDC-EA2RG7-MZ4KP9-3WTXQB-H6NF5J
  ```

- Shown **exactly once**, at vault creation, on a dedicated screen
- The user must confirm they have stored it by re-entering the last group before
  the vault is created — a checkbox is too easy to click past
- Offered as a printable sheet and as a plain text file
- Never stored in plaintext anywhere; the vault holds only the wrapped VMK that
  this key unlocks

The UI copy at that screen must say, without softening it:

> **This is your only way back in.** If you lose your master password *and* this
> recovery key, your vault cannot be opened — not by you, not by us, not by
> anyone. There is no reset, no backup and no support override. Store it
> somewhere you would store a passport.

Recovery keys can be rotated at any time from vault settings (which replaces the
slot and invalidates the old key), and a vault may hold more than one — useful
for a team that wants a sealed break-glass envelope in a safe.

### `fido2` slot

Uses the CTAP2 `hmac-secret` extension, supported by YubiKey 5, Nitrokey 3,
SoloKey and most modern FIDO2 authenticators.

```
extra: {
  "credential_id": bytes,
  "hmac_salt":     32 bytes,   // random, per slot
  "rp_id":         "remoter.vault",
  "requires_pin":  bool,
  "requires_uv":   bool        // user verification (PIN or biometric)
}
```

At unlock, Remoter sends `hmac_salt` to the authenticator, which returns a
32-byte HMAC computed from a secret that never leaves the device. That output is
run through HKDF to produce the KEK. The device must be physically present and
touched for every unlock.

**Loss of the authenticator is expected, not exceptional.** The UI encourages
enrolling two devices, and the recovery key always remains as a fallback. A slot
may be revoked without the device being present, because revocation only deletes
a slot entry.

### `keychain` slot

The "remember this vault on this device" convenience. A 256-bit random token is
generated, stored in the platform credential store, and used to derive a KEK.

| Platform | Store |
|---|---|
| Linux | Secret Service — GNOME Keyring, KWallet — via `keyring` crate |
| Windows | Credential Manager, protected with DPAPI at user scope |
| macOS | Keychain Services, with an ACL scoped to the Remoter binary |

This slot is **off by default**. It is a genuine trade-off: it makes unlocking
one click, and it makes the vault openable by anything running as your user
account. The UI states that trade-off in one sentence at the moment of enabling
it, and the slot is automatically dropped if the vault file is moved to another
machine (the token will not be present).

Biometric gating — Windows Hello, Touch ID, `fprintd` — is layered on top of
this slot where the platform supports it, as an additional presence check.

## Second tier: per-field secret encryption

Decrypting the body yields a SQLite database. Its secret columns are **still
ciphertext**.

```
ciphertext = XChaCha20-Poly1305(
    key   = SEK,
    nonce = random 24 B, stored alongside,
    data  = secret_plaintext,
    aad   = record_uuid ‖ 0x1F ‖ field_name ‖ 0x1F ‖ record_revision
)
```

Three properties follow from that AAD:

- A ciphertext cannot be moved from one record to another (the UUID is bound)
- It cannot be moved between fields — a `password` cannot be replayed as a
  `private_key` (the field name is bound)
- An old ciphertext cannot be rolled back over a new one (the revision is bound)

The practical effect: at any moment, at most the handful of secrets the user is
actively using exist as plaintext in memory. The rest remain encrypted even
though the vault is "open".

## Searching without leaking

Secret fields are never searched. Non-secret fields — name, hostname, tags,
description — are stored as plaintext *inside* the encrypted body, so full-text
search works normally once the vault is unlocked, with no cryptographic
gymnastics.

The `index key` in the hierarchy exists for a narrow future case: if
synchronisation ever needs server-side lookup without server-side decryption, a
blind index (keyed BLAKE3 of a normalised value, truncated) can be added without
a format change. It is unused in v1.0.

## Writing safely

Every save is atomic and crash-safe:

1. Serialise the in-memory SQLite database to bytes
2. Generate a fresh `BODY_NONCE` — **never** reuse a nonce with the same CEK
3. Encrypt, assemble the full file image in memory
4. Write to `<vault>.tmp` in the same directory, `fsync` the file
5. `rename()` over the original — atomic on POSIX and on NTFS via
   `ReplaceFileW`
6. `fsync` the containing directory

Before overwriting, the previous file is rotated into a rolling backup
(`<vault>.bak.1` … `.bak.N`, default N=3, configurable). A vault that fails to
decrypt therefore has a recent, known-good predecessor.

**Nonce policy.** Random 192-bit nonces are used everywhere. At that size, the
birthday bound is far beyond any realistic number of saves, which is precisely
why XChaCha20 was chosen over ChaCha20's 96-bit nonce. There is no counter and
no state to get wrong across machines — a property that matters if a vault is
ever synchronised.

## Unlock sequence

```
1. Read MAGIC, FORMAT_VER, HEADER_LEN, HEADER
2. Reject unknown FORMAT_VER — fail closed, never guess
3. Present the available slots to the user (labels and kinds only)
4. User picks a method and supplies its input
5. Derive the KEK for that slot
6. Attempt to unwrap the VMK
      ├─ tag mismatch → "That did not unlock the vault." Do not say which
      │                  part was wrong. Apply rate limiting (§ below).
      └─ success      → VMK in a Zeroizing buffer, mlock'd where possible
7. Derive CEK, SEK, header-mac key via HKDF
8. Verify HEADER_MAC — if it fails, the header was tampered with. Stop, and
   tell the user plainly, offering the rolling backup
9. Decrypt BODY with CEK, AAD as specified
      ├─ tag mismatch → corruption or tampering. Offer the backup.
      └─ success      → load SQLite into an in-memory database
10. Run schema migrations if needed
11. Vault is open. Secret fields remain individually encrypted until used.
```

**Failed-attempt handling.** Because the attacker model is offline (they have
the file and can ignore our code), rate limiting protects against a *shoulder
surfer at the keyboard*, not against T1. It is therefore a UX safeguard: a short
exponential backoff after three failures, capped, with no lockout that could
destroy data. Argon2id is what makes offline guessing expensive; nothing in the
application layer can add to that.

## Test vectors

`remoter-vault` ships known-answer tests for every primitive, sourced from:

- Argon2id — RFC 9106 test vectors
- XChaCha20-Poly1305 — the `draft-irtf-cfrg-xchacha` vectors
- HKDF-SHA256 — RFC 5869 appendix A
- BLAKE3 — the reference implementation's test suite

Plus round-trip and negative tests, all of which MUST be present before the
crate is considered complete:

- Wrap/unwrap across every slot kind
- Recovery unlock after the password slot is deliberately destroyed
- Tampered header byte → unlock fails, no plaintext emitted
- Swapped ciphertext between two records → decryption fails
- Rolled-back ciphertext from an earlier revision → decryption fails
- Truncated file at every byte offset → clean error, no panic, no partial read
- Nonce uniqueness across 10⁶ simulated saves

## Format version history

| Version | Status | Changes |
|---|---|---|
| 1 | Current design | Initial format |

Readers MUST refuse a `FORMAT_VER` they do not implement rather than attempting
a best-effort parse. Writers MUST NOT silently upgrade a vault's format version
without telling the user, because doing so may make it unopenable by an older
build they still rely on.
