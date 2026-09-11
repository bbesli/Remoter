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

## IronRDP — `ironrdp` 0.17

Meta crate; every feature is a re-export of a separate `ironrdp-*` crate, so
the feature list in `crates/remoter-proto-rdp/Cargo.toml` *is* the dependency
list. `default = ["core", "pdu"]`. MIT OR Apache-2.0 throughout, recorded in
`deny.toml`. `rust-version = "1.89"`, above the workspace's declared 1.85; the
toolchain in `rust-toolchain.toml` is newer than both, so it resolves, but a
`rust-version` bump is the honest fix if RDP ships.

**`connector` still cannot be enabled, and neither can `ironrdp-async`.**
Verified by resolution, not by reading:

```
error: failed to select a version for `aes-gcm`.
    ... required by package `remoter-import`
  previously selected package `aes-gcm v0.11.0-rc.4`
    ... of package `picky v7.0.0-rc.25`
    ... of package `ironrdp-connector v0.10.0`
```

`ironrdp-connector` 0.10 pins `picky =7.0.0-rc.25` with default features, which
activate `jose`, which pins `aes-gcm =0.11.0-rc.4`. `remoter-import` depends on
`aes-gcm ^0.11`, resolving to 0.11.1. Both sit inside the 0.11 compatibility
range, so cargo carries one or the other and not both. `ironrdp-async` 0.10
depends on `ironrdp-connector`, so it is blocked by the same edge. An optional
feature is no escape: cargo resolves optional dependencies whether or not they
are activated.

**`sspi` cannot be added either, for a different reason.** Also verified by
resolution:

```
error: failed to select a version for `curve25519-dalek`.
    ... required by package `sspi v0.21.0`
  previously selected package `curve25519-dalek v5.0.0`
    ... of package `russh v0.63.2`
```

`sspi` 0.21 pins `curve25519-dalek =5.0.0-rc.1` in its
`cfg(any(target_os = "macos", target_os = "ios"))` dependency table, and cargo
resolves target-specific dependencies for **every** target in the graph, not
only the host's. `russh` requires the released `^5`, which does not match a
pre-release. So CredSSP and NTLM are implemented in
`crates/remoter-proto-rdp/src/credssp/` rather than delegated.

`crates/remoter-proto-rdp` therefore builds its connection sequence directly on
`ironrdp-pdu`, which resolves cleanly. The call shapes below were compiled.

### Framing

```rust
use ironrdp::pdu::{find_size, Action, PduInfo};

// Returns Ok(None) while the prefix is too short. `info.action` distinguishes
// an X.224 PDU (TPKT length) from a fast-path update (7- or 15-bit length).
let info: Option<PduInfo> = find_size(&buffer)?;
let action = Action::from_fp_output_header(buffer[0])?;   // Result<_, u8>
```

### The connection sequence

```rust
use ironrdp::core::{decode, encode_vec, Encode, WriteBuf};
use ironrdp::pdu::x224::{X224, X224Data, X224Pdu};
use ironrdp::pdu::{gcc, mcs, nego, rdp};

// X.224 PDUs wrap in `X224`, which is `Encode` and `Decode`.
let bytes = encode_vec(&X224(nego::ConnectionRequest { .. }))?;
let confirm = decode::<X224<nego::ConnectionConfirm>>(&bytes)?.0;

// `mcs::ConnectResponse` is NOT an `X224Pdu`: it travels inside an X.224 Data
// PDU and is unwrapped in two steps.
let payload = decode::<X224<X224Data<'_>>>(&bytes)?;
let response = decode::<mcs::ConnectResponse>(payload.0.data.as_ref())?;

// Everything after the channel joins is an MCS Send Data Request.
let request = mcs::SendDataRequest { initiator_id, channel_id, user_data: Cow::Owned(inner) };

// Server PDUs arrive as Send Data Indications, unwrapped by layer.
let indication = mcs::decode_send_data_indication(&bytes)?;
let license: rdp::server_license::LicensePdu = indication.decode_user_data()?;
let control = rdp::headers::decode_share_control(indication)?;   // consumes it
let data = rdp::headers::decode_share_data(indication)?;

// Writing a Share Control / Share Data PDU goes through a `WriteBuf`.
let mut buf = WriteBuf::new();
rdp::headers::encode_share_control(user_channel_id, io_channel_id, share_id, pdu, &mut buf)?;
stream.write_all(buf.filled()).await?;
```

Two field types that are enums rather than integers, and are easy to get wrong:
`gcc::ClientCoreData::keyboard_type` is `gcc::KeyboardType` (`IbmEnhanced` is
the 101/102-key one), and `gcc::ChannelName` has no `starts_with` — compare
against `ChannelName::from_utf8("drdynvc").unwrap()`.

Licensing (MS-RDPELE) is entirely in `ironrdp-pdu` and needs no connector:
`ClientNewLicenseRequest::from_server_license_request`,
`ClientPlatformChallengeResponse::from_server_platform_challenge` and
`ServerUpgradeLicense::verify_server_license` are all available, and the client
supplies its own randomness.

### The active stage

```rust
use ironrdp::session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp::session::image::DecodedImage;
use ironrdp::graphics::image_processing::PixelFormat;

let stage = ActiveStageBuilder {
    static_channels, user_channel_id, io_channel_id, message_channel_id, share_id,
    compression_type: None,
    enable_server_pointer: true,
    pointer_software_rendering: false,
}.build();

let mut image = DecodedImage::new(PixelFormat::BgrX32, width, height);
let outputs: Vec<ActiveStageOutput> = stage.process(&mut image, action, &frame)?;
```

`PixelFormat::BgrX32`'s `channel_offsets()` is `[r, g, b, a] = [2, 1, 0, 3]`,
which is byte-for-byte `remoter_proto::PixelFormat::Bgrx8888`. With
`pointer_software_rendering: false` the pointer arrives as
`ActiveStageOutput::PointerBitmap(Arc<DecodedPointer>)` whose `bitmap_data` is
RGBA with **straight** alpha — `remoter_proto::PixelFormat::Rgba8888`.

`DecodedImage::data_for_rect` returns a slice spanning whole scanlines,
**padding included**. The shared frame format wants no padding between rows, so
a sub-rectangle has to be repacked row by row.

`ActiveStage::encode_resize` returns `Option<SessionResult<Vec<u8>>>` — `None`
when the Display Control channel is absent or not yet connected. Clamp with
`ironrdp::displaycontrol::pdu::MonitorLayoutEntry::adjust_display_size` first.

### Input

```rust
use ironrdp::input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};

let mut db = Database::new();
let events = db.apply([Operation::KeyPressed(Scancode::from_u8(extended, code))]);
let sync = ironrdp::input::synchronize_event(scroll, num, caps, kana);
let released = db.release_all();
```

`Scancode::from_u16` expects the `0xE0xx` form; `from_u8(extended, code)` takes
the prefix as a boolean, which is what `remoter_proto::InputEvent::Key`'s bit 8
maps onto.

## rustls 0.23 and `tokio-rustls` 0.26

`tokio-rustls` is the one crate the RDP adapter adds to the dependency graph
that was not already in it. MIT OR Apache-2.0.

```rust
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

let provider = Arc::new(rustls::crypto::ring::default_provider());
let config = rustls::ClientConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
    .connect(ServerName::try_from(host.to_owned())?, transport)
    .await?;
```

Three details that matter:

1. A custom verifier must also implement `verify_tls12_signature` and
   `verify_tls13_signature`; delegate to `rustls::crypto::verify_tls12_signature`
   and `verify_tls13_signature` with
   `provider.signature_verification_algorithms`. Returning
   `HandshakeSignatureValid::assertion()` unconditionally would accept a peer
   that does not hold the private key.
2. `rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)`
   is the stock verifier, usable *inside* a custom one to do the mechanical
   chain and name checks while the trust decision is made elsewhere.
3. `tokio_rustls` wraps a `rustls::Error` in an `io::Error`. Recovering it with
   `error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>())` is what
   keeps an untrusted certificate from being reported as a generic I/O failure.
   `rustls::Error` has no `NoApplicableCipherSuite` variant in 0.23.

`Box<dyn remoter_proto::Transport>` satisfies `tokio-rustls`'s
`AsyncRead + AsyncWrite + Unpin` through tokio's blanket `Box<T>` impls, so the
injected transport is wrapped directly — no pump task, no copy.

## HMAC — `hmac` 0.13

```rust
use hmac::{Hmac, KeyInit as _, Mac as _};
use md5::Md5;

let mut mac = Hmac::<Md5>::new_from_slice(key)?;   // KeyInit must be in scope
mac.update(data);
let tag = mac.finalize().into_bytes();
```

`new_from_slice` comes from `KeyInit`, not from `Mac`; importing only `Mac`
gives "no associated function named `new_from_slice`".


## VNC / RFB — `vnc-rs` 0.5

The library target is named **`vnc`**, not `vnc_rs`: `use vnc::{VncConnector,
VncEvent, X11Event, PixelFormat, Rect};`.

```rust
let client = VncConnector::new(stream)          // takes the stream: ADR-0003 fits
    .set_auth_method(async move { Ok(password) })
    .add_encoding(vnc::VncEncoding::Tight)
    .add_encoding(vnc::VncEncoding::Zrle)
    .add_encoding(vnc::VncEncoding::CopyRect)
    .add_encoding(vnc::VncEncoding::Raw)
    .allow_shared(true)
    .set_pixel_format(PixelFormat::bgra())
    .build()?
    .try_start()
    .await?
    .finish()?;

match client.poll_event().await { /* VncEvent */ }
client.input(X11Event::Refresh).await?;
client.close().await?;
```

Verified against 0.5.3 by compiling and by exercising the whole session over a
`tokio::io::duplex` pair with RFC 6143 bytes written by hand
(`crates/remoter-proto-vnc/src/wire_tests.rs`).

Things that shape the adapter and are not obvious from the README:

1. **The stream bound is `AsyncRead + AsyncWrite + Unpin + Send + Sync +
   'static`.** `remoter_proto::Transport` requires `Send` and not `Sync`, so
   `Box<dyn Transport>` does **not** satisfy it. Use
   `remoter_proto::SyncTransport`, which adds `Sync` structurally through an
   uncontended mutex — no pump task, no copy. A `tokio::io::duplex` bridge is
   the wrong answer twice: it copies every framebuffer byte, and it adds a task
   that has to be cancelled with the session.
2. **`set_auth_method` takes a future returning `Result<String, VncError>`,
   i.e. an owned `String` password.** That is the one place in the VNC crate
   where a secret is handed over rather than borrowed, so the `String` must come
   straight out of a `CredentialProvider` borrow and go nowhere else. It cannot
   be a `Secret<T>`; the bound is on `String` — and the library drops it
   **without zeroizing**, which nothing on this side can fix.
3. ~~`VncState::try_start` contains `assert!(!security_types.is_empty())`.~~
   **Corrected: that assertion is unreachable.** `SecurityType::read` already
   returns `VncError::General` for a zero count in the 3.7/3.8 shape and for
   security type 0 in the 3.3 shape, so the list is never empty by the time the
   assertion is reached. There is no need to pre-validate the list, and the
   earlier note asked for a defence against something that cannot happen.
4. **`VncEvent` is `#[non_exhaustive]` and includes `Error(String)`.** The
   error arrives as an event rather than a `Result`, so a `match` that only
   handles the drawing variants silently ignores a failed session. The string
   is peer-influenced: map it onto the taxonomy, never forward it.
5. **`poll_event` is non-blocking** — it is `try_recv` under the hood and
   returns `Ok(None)` immediately when nothing is queued, so the README's loop
   spins a core. Use `recv_event`, which awaits. `recv_event` holds the
   client's internal `tokio::sync::Mutex` across that await, so it must never
   be raced with `input` from a second task; one task and a `select!` is fine,
   because the losing futures are dropped before an arm's body runs.
6. **`VncEncoding` has no `Rre` and no `Hextile` variant** — both are
   commented out in the source — and `From<u32> for VncEncoding` folds every
   unrecognised encoding number onto `Raw`. Offering RRE or Hextile in
   `SetEncodings` (RFC 6143 §7.5.2) therefore does not lose a rectangle, it
   desynchronises the stream: the library would read `width * height * 4` bytes
   of a much shorter rectangle. Offer only what it decodes.
7. **`set_pixel_format` is not optional in practice.** Left unset, the library
   adopts the server's format, and the cursor and Tight decoders both reach
   `unreachable!()` when the colour masks are not one of four expected values —
   so the server would be choosing whether the process panics.
8. **`VncClient` spawns two detached tasks and `VncInner::drop` stops them.**
   Dropping the client signals both, and the byte-moving one drops the stream
   as it returns. That is what makes every early-return path release the
   socket without a guard type.
9. **A desktop resize does not move the update request.** `X11Event::Refresh`
   and `FullRefresh` build their `FramebufferUpdateRequest` rectangle from the
   size read at `ServerInit`, and nothing updates it when the DesktopSize
   pseudo-encoding (RFC 6143 §7.8.2) changes the desktop. A framebuffer that
   grows leaves the new region unrequested, and `X11Event` offers no way to ask
   for a different rectangle.

**Decoder defects found by feeding it malformed rectangles.** None is
reachable through a conforming server; all are reachable from a hostile one.
Under ADR-0011 the first three cost one tab, because they panic inside a task
the library spawned. The fourth does not: `Vec::with_capacity` aborts.

- `ServerMsg::read` reaches `unimplemented!()` on `SetColorMapEntries`
  (RFC 6143 §7.6.2, server message type 1) — one byte panics the decode task.
- The ZRLE decoder indexes its palette without a bounds check, so an
  indexed-RLE tile whose index is past the palette panics.
- ZRLE run lengths are unbounded and are not clamped to the tile size, so a
  small compressed input can ask for billions of pixels.
- A rectangle's declared size is allocated before it is read: a raw rectangle
  of 65535 by 65535 is a 17 GiB allocation.
- `AuthResult::from(u32)` transmutes; RFC 6143 §7.2.2's `SecurityResult` is a
  `U32` and a server sending 2 produces undefined behaviour.
- `ServerCutText` is decoded as UTF-8 and `ClientCutText` encoded as UTF-8,
  while RFC 6143 §7.5.6 and §7.6.4 are Latin-1. Only ASCII survives both ways.

`vnc-rs` depends on `thiserror ^1` while the workspace is on 2. `deny.toml` has
`multiple-versions = "warn"`, so this is a warning and not a failure.

## SFTP — `russh-sftp` 3.0

Compiled against `russh-sftp` 3.0.0, as pinned. `SftpSession::new` takes the
channel's stream, so the same transport injection ADR-0003 requires everywhere
else applies here for free: SFTP is a subsystem on a channel of a connection
that already exists (RFC 4254 §6.5), and never a second dial.

```rust
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags};

channel.request_subsystem(true, "sftp").await?;
let session = SftpSession::new(channel.into_stream()).await?;

let entries = session.read_dir("/srv").await?;      // ReadDir: Iterator<DirEntry>
let meta    = session.metadata("/srv/a").await?;    // follows links
let lmeta   = session.symlink_metadata("/srv/a").await?; // does not
session.set_metadata("/srv/a", FileAttributes { permissions: Some(0o640),
                                                ..Default::default() }).await?;
let mut file = session.open_with_flags("/srv/a",
    OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::APPEND).await?;
```

Five things that shape the adapter:

1. **`Metadata` is a type alias for `FileAttributes`**, whose fields are
   `size`, `uid`, `user`, `gid`, `group`, `permissions`, `atime`, `mtime` — all
   `Option`. `user` and `group` are the *names*, which is what a file manager's
   ownership column wants, and they are server-supplied strings like any other.
   The type is read with `attrs.file_type() -> FileType::{Dir, File, Symlink,
   Other}` rather than by masking the mode bits.
2. **`DirEntry::path()` is composed by the library as `parent + "/" + name`,
   where `name` is whatever the server sent.** A server that answers a
   `readdir` with an entry called `../../etc/shadow` therefore produces a
   `path()` pointing outside the directory that was listed. Never use `path()`
   to address anything a walk will act on: check the *name* is a single
   component and compose the path yourself. `ReadDir::next` filters `.` and
   `..` and nothing else.
3. **`ReadDir` accumulates every `SSH_FXP_NAME` record before it yields**, so
   the caller, not the library, is what bounds a hostile listing.
4. **`File` implements `AsyncRead`, `AsyncWrite` and `AsyncSeek`**, so a
   resumed transfer is `seek(SeekFrom::Start(offset))` on both ends. `OpenFlags`
   is a bitflag; `APPEND` alone does not position the handle, so seek anyway.
5. **`client::error::Error` has five variants** — `Timeout`, `IO`, `Status`,
   `UnexpectedPacket`, `UnexpectedBehavior`, `Limited`. Only `Status` carries a
   code (`draft-ietf-secsh-filexfer-02` §7); everything a server refuses for a
   reason it will not name arrives as `StatusCode::Failure`, which is why a
   cross-filesystem rename is indistinguishable from any other refusal and has
   to be worded as a possibility rather than a diagnosis.
