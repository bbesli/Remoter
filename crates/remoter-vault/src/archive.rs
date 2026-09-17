//! The `.rmtr` archive: part of a vault, secrets included, under a password.
//!
//! What moves connections from one Remoter to another without losing their
//! passwords. `docs/features/import-export.md` asks for "the same envelope
//! construction as the vault with a single password slot, so there is one
//! cryptographic design to review rather than two", and that is what this is:
//! the vault's framing, its password slot, its KDF and its AEAD, reused rather
//! than re-derived. `docs/security/vault-format.md` has the layout.
//!
//! ```text
//! MAGIC        8 B   "RMTRARC\x01"
//! FORMAT_VER   2 B   u16 little-endian
//! HEADER_LEN   4 B   u32 little-endian
//! HEADER       variable, CBOR, plaintext but authenticated
//! HEADER_MAC  32 B   keyed BLAKE3 over MAGIC ‖ VER ‖ LEN ‖ HEADER
//! BODY_NONCE  24 B
//! BODY        variable, XChaCha20-Poly1305(CEK, nonce, cbor_body)
//!                       with AAD = MAGIC ‖ FORMAT_VER ‖ HEADER
//! ```
//!
//! The differences from a vault are all subtractions. There is one key slot, a
//! password slot at index 0, and no recovery key: an archive is a thing sent,
//! not a thing kept. The body is not a database but a CBOR document holding the
//! exported nodes and, beside them, their secrets in plaintext — plaintext
//! *inside* the body's AEAD. A vault's second tier of encryption guards a
//! database that stays open for hours; an archive body is decrypted for the
//! length of one import, into buffers that wipe themselves. And there is no
//! audit log, no settings and no trust store in it: an archive carries the
//! connections it was asked for and nothing about the vault they came from.
//!
//! Its own magic, so that neither kind of file can be mistaken for the other —
//! an archive offered to the vault picker, or a vault offered to the importer,
//! is refused by name before any key is derived.
//!
//! The key hierarchy is the vault's, with archive-specific info strings: a
//! random archive master key wrapped by the password slot, and the content and
//! header-MAC keys derived from it by HKDF.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use remoter_core::{Node, NodeKind, SecretKind};

use crate::crypto::{self, KEY_LEN, KeyBytes, MAC_LEN, NONCE_LEN, TAG_LEN};
use crate::error::VaultError;
use crate::header::{CIPHER_XCHACHA20POLY1305, KDF_ARGON2ID, KdfParams, KeySlot, SlotKind};
use crate::secret::{ExposeSecret, Secret};
use crate::slots;
use crate::vault::Vault;

/// The first eight bytes of every archive.
pub const ARCHIVE_MAGIC: [u8; 8] = *b"RMTRARC\x01";

/// The archive format this build reads and writes.
pub const ARCHIVE_FORMAT_VERSION: u16 = 1;

/// The largest archive this build will read. A whole vault of several thousand
/// connections is a few megabytes; the ceiling is what stops a file somebody
/// sent from being read into memory before anything about it is known.
pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

/// Upper bound on the CBOR header, as for a vault.
const MAX_HEADER_LEN: u32 = 1 << 16;

/// The largest single secret an archive may carry. A private key is kilobytes;
/// this is the size of the scratch buffer the body is decoded through, and a
/// byte string larger than it is refused rather than grown into a buffer that
/// would leave copies of itself behind as it reallocated.
const MAX_SECRET_BYTES: usize = 1024 * 1024;

/// HKDF info strings. Part of the format, like the vault's.
const INFO_CEK: &[u8] = b"remoter:archive:cek:v1";
const INFO_HEADER_MAC: &[u8] = b"remoter:archive:header-mac:v1";

/// Offset of `HEADER_LEN` within the file.
const HEADER_LEN_OFFSET: usize = ARCHIVE_MAGIC.len() + 2;

/// The index and label of the one slot an archive has.
const SLOT_INDEX: u8 = 0;
const SLOT_LABEL: &str = "Archive password";

/// Why an archive would not open.
///
/// As on the vault's unlock path, nothing before the slot unwraps says which
/// part of an attempt was wrong: [`ArchiveError::WrongPassword`] covers a wrong
/// password and a corrupted slot alike. [`ArchiveError::Tampered`] and
/// [`ArchiveError::Corrupt`] can only be produced after the password has been
/// shown to be right.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// The file does not begin with the archive magic.
    #[error("this file is not a Remoter archive")]
    NotAnArchive,
    /// The file declares a format this build does not implement.
    #[error("this archive uses format version {0}, which this build does not read")]
    UnsupportedFormat(u16),
    /// The framing is truncated, or a declared length runs past the end.
    #[error("the archive is truncated or malformed")]
    Malformed,
    /// The file is larger than [`MAX_ARCHIVE_BYTES`].
    #[error("the archive is larger than the {limit} bytes this build reads")]
    TooLarge {
        /// The ceiling.
        limit: usize,
    },
    /// The password did not unwrap the archive's key.
    #[error("that password does not open this archive")]
    WrongPassword,
    /// The password was right and the header does not match its MAC.
    #[error("the archive header has been modified since it was written")]
    Tampered,
    /// The password was right and the body would not decrypt or decode.
    #[error("the archive contents are damaged")]
    Corrupt,
    /// Everything that is not about this file: the random number generator,
    /// the KDF, a cost parameter this build refuses to spend.
    #[error(transparent)]
    Vault(#[from] VaultError),
}

/// One secret field of one exported node.
pub struct ArchiveSecret {
    /// The node the secret belongs to, by its id in the archive.
    pub node: Uuid,
    /// The field, as [`Vault::set_secret`] names it: `password`,
    /// `private_key`, `passphrase` and so on.
    pub field: String,
    /// The plaintext.
    pub value: Secret<Vec<u8>>,
}

impl core::fmt::Debug for ArchiveSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArchiveSecret")
            .field("node", &self.node)
            .field("field", &self.field)
            .field("value", &self.value)
            .finish()
    }
}

/// What an archive holds.
#[derive(Debug, Default)]
pub struct ArchiveContents {
    /// The exported nodes, parents before children. Their sealed fields carry
    /// [`Vault::sealed_placeholder`] and nothing else; the material is in
    /// [`ArchiveContents::secrets`].
    pub nodes: Vec<Node>,
    /// The secrets, by node and field.
    pub secrets: Vec<ArchiveSecret>,
}

/// What an archive says about itself before it is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveInfo {
    /// Identifies this archive.
    pub archive_id: Uuid,
    /// Unix seconds.
    pub created_at: i64,
}

/// The CBOR header.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArchiveHeader {
    archive_id: Uuid,
    created_at: i64,
    content_cipher: String,
    kdf: String,
    slot: KeySlot,
}

/// The CBOR body, as it is written: secrets borrowed rather than copied.
#[derive(Serialize)]
struct BodyOut<'a> {
    nodes: &'a [Node],
    secrets: Vec<SecretOut<'a>>,
}

#[derive(Serialize)]
struct SecretOut<'a> {
    node: Uuid,
    field: &'a str,
    #[serde(serialize_with = "serialize_bytes")]
    value: &'a [u8],
}

/// The CBOR body, as it is read.
#[derive(Deserialize)]
struct BodyIn {
    nodes: Vec<Node>,
    secrets: Vec<SecretIn>,
}

#[derive(Deserialize)]
struct SecretIn {
    node: Uuid,
    field: String,
    #[serde(deserialize_with = "deserialize_secret")]
    value: Secret<Vec<u8>>,
}

fn serialize_bytes<S: serde::Serializer>(value: &&[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(value)
}

/// Reads a byte string straight into a [`Secret`].
///
/// Through `deserialize_bytes`, which hands the visitor a slice of the scratch
/// buffer, so the one allocation is the exact-size copy made here — never a
/// vector grown chunk by chunk, each growth leaving a fragment of the secret in
/// freed memory.
fn deserialize_secret<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Secret<Vec<u8>>, D::Error> {
    struct SecretVisitor;

    impl serde::de::Visitor<'_> for SecretVisitor {
        type Value = Secret<Vec<u8>>;

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a byte string")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            Ok(Secret::new(v.to_vec()))
        }
    }

    d.deserialize_bytes(SecretVisitor)
}

/// Counts what a serialiser writes, so the real buffer can be allocated once at
/// its final size.
struct Counter(usize);

impl std::io::Write for Counter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Seals nodes and their secrets into an archive image, ready to be written.
///
/// Every sealed field on the nodes is replaced by
/// [`Vault::sealed_placeholder`] first: the ciphertext a vault holds is bound
/// to that vault's key and is no use anywhere else, and carrying it would put
/// one more copy of every secret into a file that leaves the machine. The
/// material travels in `contents.secrets`, inside the body's AEAD.
///
/// `params` are the password slot's Argon2id costs and must meet the floor.
///
/// # Errors
///
/// [`VaultError::KdfParamsTooWeak`] for parameters below the floor,
/// [`VaultError::Csprng`] if no randomness is available, and
/// [`VaultError::HeaderEncode`] if the header or body cannot be encoded.
pub fn seal_archive(
    contents: &ArchiveContents,
    password: &Secret<String>,
    params: KdfParams,
) -> Result<Vec<u8>, VaultError> {
    let params = params.check_floor()?;
    seal_with(contents, password, params)
}

/// [`seal_archive`] without the floor, for this crate's tests.
fn seal_with(
    contents: &ArchiveContents,
    password: &Secret<String>,
    params: KdfParams,
) -> Result<Vec<u8>, VaultError> {
    let nodes: Vec<Node> = contents.nodes.iter().cloned().map(strip_sealed).collect();
    let body = BodyOut {
        nodes: &nodes,
        secrets: contents
            .secrets
            .iter()
            .map(|secret| SecretOut {
                node: secret.node,
                field: &secret.field,
                value: secret.value.expose_secret(),
            })
            .collect(),
    };

    // Two passes: one to measure, one to write into a buffer that is already
    // the right size and therefore never reallocates with plaintext in it.
    let mut counter = Counter(0);
    ciborium::into_writer(&body, &mut counter).map_err(|_| VaultError::HeaderEncode)?;
    let mut plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(counter.0));
    ciborium::into_writer(&body, &mut *plaintext).map_err(|_| VaultError::HeaderEncode)?;
    drop(body);

    let amk = crypto::random_key()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let slot = slots::new_password_slot(
        SLOT_INDEX,
        SLOT_LABEL.to_owned(),
        now,
        password,
        None,
        params,
        &amk,
    )?;
    let header = ArchiveHeader {
        archive_id: Uuid::now_v7(),
        created_at: now,
        content_cipher: CIPHER_XCHACHA20POLY1305.to_owned(),
        kdf: KDF_ARGON2ID.to_owned(),
        slot,
    };

    let mut header_bytes = Vec::new();
    ciborium::into_writer(&header, &mut header_bytes).map_err(|_| VaultError::HeaderEncode)?;
    let header_len = u32::try_from(header_bytes.len()).map_err(|_| VaultError::HeaderEncode)?;
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(VaultError::HeaderEncode);
    }
    let (mac_input, aad) = framing(&header_bytes, header_len);

    let keys = ArchiveKeys::derive(&amk)?;
    let mac = crypto::keyed_mac(&keys.header_mac, &mac_input);
    let nonce: [u8; NONCE_LEN] = crypto::random_array()?;
    let sealed = crypto::seal(&keys.cek, &nonce, &plaintext, &aad)?;

    let mut image = Vec::with_capacity(mac_input.len() + MAC_LEN + NONCE_LEN + sealed.len());
    image.extend_from_slice(&mac_input);
    image.extend_from_slice(&mac);
    image.extend_from_slice(&nonce);
    image.extend_from_slice(&sealed);
    Ok(image)
}

/// Whether a file image begins like an archive. A sniff for choosing an
/// importer, not a check that it will open.
#[must_use]
pub fn is_archive(bytes: &[u8]) -> bool {
    bytes.starts_with(&ARCHIVE_MAGIC)
}

/// Reads what an archive says about itself, without a password.
///
/// # Errors
///
/// As the framing half of [`open_archive`].
pub fn probe_archive(bytes: &[u8]) -> Result<ArchiveInfo, ArchiveError> {
    let parsed = parse(bytes)?;
    Ok(ArchiveInfo {
        archive_id: parsed.header.archive_id,
        created_at: parsed.header.created_at,
    })
}

/// Opens an archive image with its password.
///
/// # Errors
///
/// [`ArchiveError::NotAnArchive`], [`ArchiveError::UnsupportedFormat`],
/// [`ArchiveError::Malformed`] and [`ArchiveError::TooLarge`] for a file that
/// cannot be framed; [`ArchiveError::Vault`] carrying
/// [`VaultError::KdfParamsRefused`] for a slot that declares costs this build
/// will not run; [`ArchiveError::WrongPassword`] when the slot does not unwrap;
/// and, only after it has, [`ArchiveError::Tampered`] or
/// [`ArchiveError::Corrupt`].
pub fn open_archive(
    bytes: &[u8],
    password: &Secret<String>,
) -> Result<ArchiveContents, ArchiveError> {
    let parsed = parse(bytes)?;
    let slot = &parsed.header.slot;
    if slot.kind != SlotKind::Password || slot.index != SLOT_INDEX {
        return Err(ArchiveError::Malformed);
    }
    let params = slot
        .kdf_params
        .ok_or(ArchiveError::Malformed)?
        .check_ceiling()?;
    slot.validate().map_err(|_| ArchiveError::Malformed)?;

    let kek = slots::password_kek(
        password.expose_secret(),
        slots::normalisation_of(slot),
        None,
        &slot.salt,
        &params,
    )
    .map_err(|error| match error {
        // A normalisation this build does not know: the file is from a newer
        // build, not a wrong password.
        VaultError::UnsupportedFormat(_) => ArchiveError::UnsupportedFormat(ARCHIVE_FORMAT_VERSION),
        other => ArchiveError::Vault(other),
    })?;
    let amk = slots::unwrap_vmk(&kek, slot).map_err(|_| ArchiveError::WrongPassword)?;
    let keys = ArchiveKeys::derive(&amk)?;

    let expected = crypto::keyed_mac(&keys.header_mac, &parsed.mac_input);
    if !crypto::ct_eq(&expected, &parsed.mac) {
        return Err(ArchiveError::Tampered);
    }

    let plaintext = crypto::open(&keys.cek, &parsed.body_nonce, parsed.body, &parsed.aad)
        .map_err(|_| ArchiveError::Corrupt)?;

    decode_body(&plaintext)
}

/// Decodes an archive body that has already been decrypted.
///
/// Public for the fuzz target, which cannot reach it through
/// [`open_archive`] without a password it could not know: the body is only
/// read after authentication, but whoever holds the password — the person who
/// sent the file — writes every byte of it, so it is hostile input all the
/// same.
///
/// # Errors
///
/// [`ArchiveError::Corrupt`] for a body that is not the archive's CBOR
/// document, or that holds a secret larger than the decoder will hold.
#[doc(hidden)]
pub fn decode_body(plaintext: &[u8]) -> Result<ArchiveContents, ArchiveError> {
    // The scratch buffer is where every string and byte string of the body
    // passes through on its way to its own allocation, secrets included, so it
    // is a wiping buffer too.
    let mut scratch: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; MAX_SECRET_BYTES]);
    let decoded: Result<BodyIn, _> =
        ciborium::de::from_reader_with_buffer(plaintext, &mut scratch[..]);
    scratch.zeroize();
    let body = decoded.map_err(|_| ArchiveError::Corrupt)?;

    Ok(ArchiveContents {
        nodes: body.nodes,
        secrets: body
            .secrets
            .into_iter()
            .map(|secret| ArchiveSecret {
                node: secret.node,
                field: secret.field,
                value: secret.value,
            })
            .collect(),
    })
}

/// The content and header-MAC keys, derived from the archive master key.
struct ArchiveKeys {
    cek: KeyBytes,
    header_mac: KeyBytes,
}

impl ArchiveKeys {
    fn derive(amk: &[u8; KEY_LEN]) -> Result<Self, VaultError> {
        Ok(Self {
            cek: crypto::hkdf_sha256(amk, None, INFO_CEK)?,
            header_mac: crypto::hkdf_sha256(amk, None, INFO_HEADER_MAC)?,
        })
    }
}

/// A framed archive, before any key has touched it.
struct Parsed<'a> {
    header: ArchiveHeader,
    mac_input: Vec<u8>,
    aad: Vec<u8>,
    mac: [u8; MAC_LEN],
    body_nonce: [u8; NONCE_LEN],
    body: &'a [u8],
}

/// `MAGIC ‖ VER ‖ LEN ‖ HEADER` and `MAGIC ‖ VER ‖ HEADER`.
fn framing(header_bytes: &[u8], header_len: u32) -> (Vec<u8>, Vec<u8>) {
    let mut mac_input = Vec::with_capacity(HEADER_LEN_OFFSET + 4 + header_bytes.len());
    mac_input.extend_from_slice(&ARCHIVE_MAGIC);
    mac_input.extend_from_slice(&ARCHIVE_FORMAT_VERSION.to_le_bytes());
    mac_input.extend_from_slice(&header_len.to_le_bytes());
    mac_input.extend_from_slice(header_bytes);

    let mut aad = Vec::with_capacity(HEADER_LEN_OFFSET + header_bytes.len());
    aad.extend_from_slice(&ARCHIVE_MAGIC);
    aad.extend_from_slice(&ARCHIVE_FORMAT_VERSION.to_le_bytes());
    aad.extend_from_slice(header_bytes);
    (mac_input, aad)
}

/// Reads a slice, or fails cleanly if the file ends first.
fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], ArchiveError> {
    let end = offset.checked_add(len).ok_or(ArchiveError::Malformed)?;
    let slice = bytes.get(*offset..end).ok_or(ArchiveError::Malformed)?;
    *offset = end;
    Ok(slice)
}

/// Frames an archive image. Total: every read goes through [`take`], and
/// nothing is allocated from a length until the length has been bounded.
fn parse(bytes: &[u8]) -> Result<Parsed<'_>, ArchiveError> {
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(ArchiveError::TooLarge {
            limit: MAX_ARCHIVE_BYTES,
        });
    }
    let mut offset = 0usize;
    let magic =
        take(bytes, &mut offset, ARCHIVE_MAGIC.len()).map_err(|_| ArchiveError::NotAnArchive)?;
    if magic != ARCHIVE_MAGIC {
        return Err(ArchiveError::NotAnArchive);
    }
    let version = u16::from_le_bytes(
        take(bytes, &mut offset, 2)?
            .try_into()
            .map_err(|_| ArchiveError::Malformed)?,
    );
    if version != ARCHIVE_FORMAT_VERSION {
        return Err(ArchiveError::UnsupportedFormat(version));
    }
    let header_len = u32::from_le_bytes(
        take(bytes, &mut offset, 4)?
            .try_into()
            .map_err(|_| ArchiveError::Malformed)?,
    );
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(ArchiveError::Malformed);
    }
    let header_bytes = take(
        bytes,
        &mut offset,
        usize::try_from(header_len).map_err(|_| ArchiveError::Malformed)?,
    )?;
    let header: ArchiveHeader =
        ciborium::from_reader(header_bytes).map_err(|_| ArchiveError::Malformed)?;
    if header.content_cipher != CIPHER_XCHACHA20POLY1305 || header.kdf != KDF_ARGON2ID {
        return Err(ArchiveError::UnsupportedFormat(version));
    }

    let mac: [u8; MAC_LEN] = take(bytes, &mut offset, MAC_LEN)?
        .try_into()
        .map_err(|_| ArchiveError::Malformed)?;
    let body_nonce: [u8; NONCE_LEN] = take(bytes, &mut offset, NONCE_LEN)?
        .try_into()
        .map_err(|_| ArchiveError::Malformed)?;
    let body = bytes.get(offset..).ok_or(ArchiveError::Malformed)?;
    if body.len() < TAG_LEN {
        return Err(ArchiveError::Malformed);
    }

    let (mac_input, aad) = framing(header_bytes, header_len);
    Ok(Parsed {
        header,
        mac_input,
        aad,
        mac,
        body_nonce,
        body,
    })
}

/// A node with every sealed field replaced by the placeholder.
fn strip_sealed(mut node: Node) -> Node {
    if let NodeKind::Credential(credential) = &mut node.kind {
        let placeholder = Vault::sealed_placeholder;
        credential.secret = match &credential.secret {
            SecretKind::Password { .. } => SecretKind::Password {
                sealed: placeholder(),
            },
            SecretKind::PrivateKey {
                sealed_passphrase,
                format,
                ..
            } => SecretKind::PrivateKey {
                sealed_key: placeholder(),
                sealed_passphrase: sealed_passphrase.as_ref().map(|_| placeholder()),
                format: *format,
            },
            SecretKind::Certificate { .. } => SecretKind::Certificate {
                sealed_cert: placeholder(),
                sealed_key: placeholder(),
            },
            other => other.clone(),
        };
        if credential.totp.is_some() {
            credential.totp = Some(placeholder());
        }
    }
    node
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod tests {
    use remoter_core::{ConnectionProps, CredentialProps, CredentialRef, Inherited, KeyFormat};

    use super::*;

    const PASSWORD: &str = "correct horse battery staple";
    const SERVER_PASSWORD: &[u8] = b"s3rver-p4ssw0rd-that-must-not-leak";

    fn secret(text: &str) -> Secret<String> {
        Secret::new(text.to_owned())
    }

    fn contents() -> ArchiveContents {
        let mut credential = Node::new(
            NodeKind::Credential(CredentialProps::new(
                "root",
                SecretKind::PrivateKey {
                    sealed_key: vec![0xee; 64],
                    sealed_passphrase: Some(vec![0xee; 40]),
                    format: KeyFormat::OpenSsh,
                },
            )),
            "root key",
            1,
        );
        credential.revision = 7;
        let mut connection = ConnectionProps::new("ssh", "10.0.0.1").unwrap();
        connection.credential = Inherited::Explicit(CredentialRef::live(credential.id));
        let connection = Node::new(NodeKind::Connection(connection), "web-01", 1);
        ArchiveContents {
            secrets: vec![
                ArchiveSecret {
                    node: *credential.id.as_uuid(),
                    field: "private_key".into(),
                    value: Secret::new(SERVER_PASSWORD.to_vec()),
                },
                ArchiveSecret {
                    node: *credential.id.as_uuid(),
                    field: "passphrase".into(),
                    value: Secret::new(b"key passphrase".to_vec()),
                },
            ],
            nodes: vec![connection, credential],
        }
    }

    fn sealed() -> Vec<u8> {
        seal_with(
            &contents(),
            &secret(PASSWORD),
            KdfParams::low_cost_for_tests(),
        )
        .unwrap()
    }

    #[test]
    fn an_archive_opens_with_its_password_and_gives_back_nodes_and_secrets() {
        let original = contents();
        let image = seal_with(
            &original,
            &secret(PASSWORD),
            KdfParams::low_cost_for_tests(),
        )
        .unwrap();
        assert!(is_archive(&image));
        let opened = open_archive(&image, &secret(PASSWORD)).unwrap();

        assert_eq!(opened.nodes.len(), 2);
        assert_eq!(
            opened.nodes[0], original.nodes[0],
            "a connection carries nothing sealed"
        );
        assert_eq!(opened.secrets.len(), 2);
        assert_eq!(opened.secrets[0].field, "private_key");
        assert_eq!(opened.secrets[0].value.expose_secret(), SERVER_PASSWORD);
        assert_eq!(opened.secrets[1].value.expose_secret(), b"key passphrase");

        // The source vault's ciphertext did not travel: the credential's sealed
        // fields are the placeholder, and the rest of it is as it was.
        let NodeKind::Credential(credential) = &opened.nodes[1].kind else {
            panic!("not a credential");
        };
        assert_eq!(
            credential.secret,
            SecretKind::PrivateKey {
                sealed_key: Vault::sealed_placeholder(),
                sealed_passphrase: Some(Vault::sealed_placeholder()),
                format: KeyFormat::OpenSsh,
            }
        );
        assert_eq!(opened.nodes[1].revision, 7);
    }

    #[test]
    fn no_secret_is_in_the_file_in_the_clear() {
        let image = sealed();
        for needle in [SERVER_PASSWORD, b"key passphrase".as_slice(), &[0xee; 16]] {
            assert!(
                !image.windows(needle.len()).any(|window| window == needle),
                "found {needle:?} in the archive"
            );
        }
    }

    #[test]
    fn a_wrong_password_says_only_that() {
        let image = sealed();
        assert!(matches!(
            open_archive(&image, &secret("correct horse battery stable")),
            Err(ArchiveError::WrongPassword)
        ));
    }

    #[test]
    fn a_password_typed_in_another_normal_form_still_opens_it() {
        let image = seal_with(
            &contents(),
            &secret("caf\u{e9}"),
            KdfParams::low_cost_for_tests(),
        )
        .unwrap();
        assert!(open_archive(&image, &secret("cafe\u{301}")).is_ok());
    }

    #[test]
    fn a_changed_header_or_body_is_caught_after_the_password_is_proved() {
        let image = sealed();
        let header_len = u32::from_le_bytes(image[10..14].try_into().unwrap()) as usize;

        // A byte of the CBOR header's created_at or id: still decodes, fails
        // the MAC. Flip bytes until one decodes, so the test does not depend
        // on where CBOR put a field.
        let mut tampered_header = None;
        for position in 14..14 + header_len {
            let mut candidate = image.clone();
            candidate[position] ^= 0x01;
            match open_archive(&candidate, &secret(PASSWORD)) {
                Err(ArchiveError::Tampered) => {
                    tampered_header = Some(position);
                    break;
                }
                Err(_) => continue,
                Ok(_) => panic!("a changed header byte at {position} still opened"),
            }
        }
        assert!(
            tampered_header.is_some(),
            "no header change was reported as tampering"
        );

        let mut body = image.clone();
        let last = body.len() - 1;
        body[last] ^= 0x80;
        assert!(matches!(
            open_archive(&body, &secret(PASSWORD)),
            Err(ArchiveError::Corrupt)
        ));
    }

    #[test]
    fn every_truncation_is_refused_without_a_panic() {
        let image = sealed();
        let header_len = u32::from_le_bytes(image[10..14].try_into().unwrap()) as usize;
        // Every cut through the framing, which is refused before any key is
        // derived, and a spread of cuts through the body, each of which costs
        // a derivation to refuse.
        let framing_end = 14 + header_len + MAC_LEN + NONCE_LEN + TAG_LEN;
        let body_cuts =
            (framing_end..image.len()).step_by(((image.len() - framing_end) / 6).max(1));
        for len in (0..framing_end).chain(body_cuts) {
            let result = open_archive(&image[..len], &secret(PASSWORD));
            assert!(result.is_err(), "a file cut to {len} bytes opened");
        }
    }

    #[test]
    fn a_vault_is_not_an_archive_and_an_archive_is_not_a_vault() {
        let mut vault_like = sealed();
        vault_like[..8].copy_from_slice(&crate::header::MAGIC);
        assert!(matches!(
            open_archive(&vault_like, &secret(PASSWORD)),
            Err(ArchiveError::NotAnArchive)
        ));
        assert!(matches!(
            crate::header::parse(&sealed()),
            Err(VaultError::NotAVault)
        ));
        assert!(!is_archive(b"RMTRVLT\x01"));
    }

    #[test]
    fn costs_this_build_will_not_spend_are_refused_before_any_derivation() {
        let image = sealed();
        let mut parsed = parse(&image).unwrap();
        parsed.header.slot.kdf_params = Some(KdfParams {
            m_cost: KdfParams::READ_MAX_M_COST + 1,
            ..KdfParams::low_cost_for_tests()
        });
        let mut header_bytes = Vec::new();
        ciborium::into_writer(&parsed.header, &mut header_bytes).unwrap();
        let (mac_input, _) = framing(&header_bytes, u32::try_from(header_bytes.len()).unwrap());
        let mut rebuilt = mac_input;
        rebuilt.extend_from_slice(&parsed.mac);
        rebuilt.extend_from_slice(&parsed.body_nonce);
        rebuilt.extend_from_slice(parsed.body);
        assert!(matches!(
            open_archive(&rebuilt, &secret(PASSWORD)),
            Err(ArchiveError::Vault(VaultError::KdfParamsRefused { .. }))
        ));
    }

    #[test]
    fn a_secret_larger_than_the_decoder_will_hold_is_refused_not_grown() {
        let mut big = contents();
        big.secrets[0].value = Secret::new(vec![7u8; MAX_SECRET_BYTES + 1]);
        let image = seal_with(&big, &secret(PASSWORD), KdfParams::low_cost_for_tests()).unwrap();
        assert!(matches!(
            open_archive(&image, &secret(PASSWORD)),
            Err(ArchiveError::Corrupt)
        ));
    }

    #[test]
    fn sealing_refuses_costs_below_the_floor() {
        assert!(matches!(
            seal_archive(
                &contents(),
                &secret(PASSWORD),
                KdfParams::low_cost_for_tests()
            ),
            Err(VaultError::KdfParamsTooWeak)
        ));
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_is_framed() {
        let huge = vec![0u8; MAX_ARCHIVE_BYTES + 1];
        assert!(matches!(
            probe_archive(&huge),
            Err(ArchiveError::TooLarge { .. })
        ));
    }
}
