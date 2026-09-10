# Verified dependency APIs

The 2026 RustCrypto generation (`digest` 0.11, `cipher` 0.5, `crypto-common`
0.2, `hybrid-array`) changed call signatures substantially from the widely
documented 0.9/0.10 generation. Everything below was **compiled and tested**
against the exact versions pinned in the workspace `Cargo.toml`, not recalled.

Write code against these signatures. If a dependency version changes, re-verify
and update this file in the same commit.

## Argon2id — `argon2` 0.6

```rust
use argon2::{Algorithm, Argon2, Params, Version};

let params = Params::new(
    256 * 1024, // m_cost, in KiB
    3,          // t_cost
    4,          // p_cost
    Some(32),   // output length
)?;
let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
let mut out = Zeroizing::new([0u8; 32]);
a.hash_password_into(password_bytes, salt, out.as_mut())?;
```

`Params::new` returns `Result`. `hash_password_into` takes `&mut [u8]`, so pass
`out.as_mut()` on a `Zeroizing<[u8; 32]>`.

## HKDF-SHA256 — `hkdf` 0.13 + `sha2` 0.11

```rust
use hkdf::Hkdf;
use sha2::Sha256;

let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
let mut out = Zeroizing::new([0u8; 32]);
hk.expand(info, out.as_mut())?;
```

## XChaCha20-Poly1305 — `chacha20poly1305` 0.11

```rust
use chacha20poly1305::{
    XChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};

let c = XChaCha20Poly1305::new(key32.into());          // &[u8; 32] -> &Key
let ct = c.encrypt(nonce24.into(), Payload { msg: pt, aad })?;
let pt = c.decrypt(nonce24.into(), Payload { msg: ct, aad })?;
```

`AeadInPlace` is **deprecated** in this version — use `AeadInOut` if an
in-place variant is needed. `.into()` on `&[u8; 32]` / `&[u8; 24]` produces the
generic array types; no `GenericArray::from_slice` is required.

## BLAKE3 keyed MAC — `blake3` 1.8

```rust
let tag: [u8; 32] = *blake3::keyed_hash(&key32, data).as_bytes();
```

The key is `&[u8; 32]` exactly. Compare tags in constant time (`subtle`).

## SQLite serialise / deserialise — `rusqlite` 0.40

Features required: `bundled`, `serialize`.

```rust
use rusqlite::{Connection, MAIN_DB};   // MAIN_DB is a &CStr constant

// in-memory database -> bytes
let bytes: Vec<u8> = conn.serialize(MAIN_DB)?.to_vec();

// bytes -> in-memory database
let mut conn = Connection::open_in_memory()?;
conn.deserialize_read_exact(MAIN_DB, &mut &bytes[..], bytes.len(), false)?;
```

There is no `DatabaseName` enum and no `SerializedDatabase` type in this
version. `deserialize_bytes` requires a `&'static [u8]`; use
`deserialize_read_exact` for owned buffers.

## Randomness — `getrandom` 0.4

```rust
let mut b = [0u8; 32];
getrandom::fill(&mut b).map_err(|_| Error::Csprng)?;
```

Use `getrandom` directly rather than `rand`. `rand` 0.10 moved `OsRng` behind a
feature and adds a dependency tree we do not otherwise need.

## UUIDv7 — `uuid` 1.26

```rust
let id = uuid::Uuid::now_v7();
```

Declare the dependency **manually** in `Cargo.toml` as
`uuid = { version = "1.26", features = ["v7", "serde"] }`. `cargo add uuid
--features v7` misreports the feature as unrecognised against the current
index; the feature is real and compiles.

## CBOR — `ciborium` 0.2

```rust
let mut out = Vec::new();
ciborium::into_writer(&value, &mut out)?;
let value: T = ciborium::from_reader(&bytes[..])?;
```
