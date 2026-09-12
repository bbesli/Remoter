//! Private key formats: what a file is, and how to read it.
//!
//! **The format is decided by the content, never by the file name.** A key
//! exported from PuTTY and saved as `id_rsa`, or an OpenSSH key saved as
//! `key.ppk`, are both things administrators actually have; a parser that
//! trusts the extension refuses them for no reason. Every discriminator below
//! is a byte sequence from the file's own header.
//!
//! Formats read here:
//!
//! | Format | Header |
//! |---|---|
//! | OpenSSH | `-----BEGIN OPENSSH PRIVATE KEY-----` |
//! | PKCS#8 | `-----BEGIN PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----` |
//! | PKCS#8, encrypted | `-----BEGIN ENCRYPTED PRIVATE KEY-----` |
//! | PKCS#1 RSA | `-----BEGIN RSA PRIVATE KEY-----` |
//! | PKCS#5, encrypted | the above plus a `DEK-Info:` line (RFC 1421 §4.6.1.3) |
//! | PuTTY | `PuTTY-User-Key-File-2:` / `-3:` |
//!
//! PuTTY's `.ppk` matters more than its market share suggests: it is where a
//! great many administrators' keys live, and refusing it means refusing the
//! migration that brought them here.
//!
//! Nothing in this module copies key material. The bytes are borrowed from the
//! vault's closure, viewed as `&str`, and handed to the parser; the parsed
//! `PrivateKey` zeroizes itself on drop.

use std::fmt;

use remoter_proto::{CredentialKind, ProtocolError};
use russh::keys::PrivateKey;

use crate::error::map_key_error;

/// Which PuTTY key file version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PpkVersion {
    /// `PuTTY-User-Key-File-2`. Encryption, where present, is AES-256-CBC with
    /// an SHA-1 based key derivation.
    V2,
    /// `PuTTY-User-Key-File-3`. Encryption, where present, is AES-256-CBC with
    /// Argon2.
    V3,
}

impl PpkVersion {
    /// The version number as it appears in the header.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }
}

/// A recognised private key file format.
///
/// `Debug` is derived and safe: a format is a shape, not a secret, and no
/// variant carries key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFormat {
    /// OpenSSH's own container, `ed25519`, `ecdsa` or `rsa` inside.
    OpenSsh,
    /// A bare PKCS#1 RSA key.
    Pkcs1Rsa,
    /// A PEM key with an RFC 1421 `DEK-Info` header: encrypted under PKCS#5.
    Pkcs5Encrypted,
    /// An unencrypted PKCS#8 `PrivateKeyInfo`.
    Pkcs8,
    /// A PKCS#8 `EncryptedPrivateKeyInfo`.
    Pkcs8Encrypted,
    /// A PuTTY key file.
    Ppk(PpkVersion),
}

impl KeyFormat {
    /// A stable ASCII name, for the interface's message catalogue.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenSsh => "openssh",
            Self::Pkcs1Rsa => "pkcs1-rsa",
            Self::Pkcs5Encrypted => "pkcs5-encrypted",
            Self::Pkcs8 => "pkcs8",
            Self::Pkcs8Encrypted => "pkcs8-encrypted",
            Self::Ppk(PpkVersion::V2) => "ppk2",
            Self::Ppk(PpkVersion::V3) => "ppk3",
        }
    }

    /// Whether the format itself proves the key is encrypted.
    ///
    /// `false` here does not mean "not encrypted": an OpenSSH container and a
    /// `.ppk` both carry the answer inside, which is what
    /// [`needs_passphrase`] reads.
    #[must_use]
    pub const fn is_always_encrypted(self) -> bool {
        matches!(self, Self::Pkcs5Encrypted | Self::Pkcs8Encrypted)
    }
}

impl fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

const PPK_PREFIX: &str = "PuTTY-User-Key-File-";
const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const RSA_BEGIN: &str = "-----BEGIN RSA PRIVATE KEY-----";
const PKCS8_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const EC_BEGIN: &str = "-----BEGIN EC PRIVATE KEY-----";
const PKCS8_ENCRYPTED_BEGIN: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const DEK_INFO: &str = "DEK-Info:";

/// Identifies a key file from its contents.
///
/// Returns `None` when nothing recognisable is present — which is the honest
/// answer for a public key, a certificate, or a file the user picked by
/// mistake.
#[must_use]
pub fn detect_key_format(bytes: &[u8]) -> Option<KeyFormat> {
    let text = std::str::from_utf8(bytes).ok()?;

    // PuTTY first: its header is the file's first line and cannot collide with
    // a PEM banner.
    if let Some(rest) = text.trim_start().strip_prefix(PPK_PREFIX) {
        return match rest.as_bytes().first() {
            Some(b'2') => Some(KeyFormat::Ppk(PpkVersion::V2)),
            Some(b'3') => Some(KeyFormat::Ppk(PpkVersion::V3)),
            // A version this build does not read. Reported as unrecognised
            // rather than guessed at, so the message says so.
            _ => None,
        };
    }

    let mut format = None;
    let mut dek_info = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        match line {
            OPENSSH_BEGIN => return Some(KeyFormat::OpenSsh),
            PKCS8_ENCRYPTED_BEGIN => return Some(KeyFormat::Pkcs8Encrypted),
            RSA_BEGIN => format = Some(KeyFormat::Pkcs1Rsa),
            PKCS8_BEGIN | EC_BEGIN => format = Some(KeyFormat::Pkcs8),
            _ if line.starts_with(DEK_INFO) => dek_info = true,
            _ => {}
        }
    }

    // RFC 1421 §4.6.1.3: a `DEK-Info` header means the body below it is
    // enciphered, whatever the banner said.
    match (format, dek_info) {
        (Some(_), true) => Some(KeyFormat::Pkcs5Encrypted),
        (format, _) => format,
    }
}

/// Whether reading this key will need a passphrase.
///
/// Read from the file rather than attempted-and-caught, so that the interface
/// can ask for the passphrase before the attempt rather than after a failure
/// the user has to interpret.
#[must_use]
pub fn needs_passphrase(bytes: &[u8]) -> bool {
    let Some(format) = detect_key_format(bytes) else {
        return false;
    };
    if format.is_always_encrypted() {
        return true;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    match format {
        // PuTTY records the cipher in a header line of its own. `none` is the
        // only other value the format defines.
        KeyFormat::Ppk(_) => text.lines().any(|line| {
            let line = line.trim_end_matches('\r');
            line.strip_prefix("Encryption: ")
                .is_some_and(|value| !value.trim().eq_ignore_ascii_case("none"))
        }),
        // OpenSSH's container names its cipher inside the base64 body, so the
        // header has to be decoded. `from_openssh` succeeds on an encrypted
        // key — it keeps the ciphertext — which is what makes this readable
        // without the passphrase.
        KeyFormat::OpenSsh => PrivateKey::from_openssh(bytes).is_ok_and(|key| key.is_encrypted()),
        _ => false,
    }
}

/// Reads a private key.
///
/// `passphrase` is borrowed from the credential provider and is not copied:
/// it is viewed as `&str` and passed straight to the parser.
///
/// # Errors
///
/// [`ProtocolError::CredentialMissing`] when the key is encrypted and no
/// passphrase was supplied — the caller should prompt and retry;
/// [`ProtocolError::AuthRejected`] when the key cannot be read, which covers
/// both a corrupt file and a wrong passphrase (the two are indistinguishable
/// from the outside of an authenticated cipher, and saying so would be a
/// guess); [`ProtocolError::NoSharedAlgorithm`] for a key of a type this build
/// does not support.
pub fn parse_private_key(
    bytes: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<PrivateKey, ProtocolError> {
    let Some(format) = detect_key_format(bytes) else {
        return Err(ProtocolError::AuthRejected {
            attempted: CredentialKind::PrivateKey,
        });
    };

    let wants_passphrase = needs_passphrase(bytes);
    if wants_passphrase && passphrase.is_none_or(<[u8]>::is_empty) {
        return Err(ProtocolError::CredentialMissing {
            name: "key passphrase".to_owned(),
        });
    }

    // A passphrase offered for a container that is not enciphered is dropped
    // rather than passed on. `ssh-key` refuses such a pairing outright — a
    // plaintext PKCS#8 handed a passphrase comes back as a parse failure — and
    // the credential that produces it is not implausible: a key replaced with
    // an unencrypted one while its passphrase field still held the old
    // key's. The resulting failure would be a rejected authentication with a
    // working key, which is a long way from its cause.
    let passphrase = if wants_passphrase { passphrase } else { None };

    // Key files are text. `from_utf8` borrows rather than copies, so the key
    // material still exists only in the vault's buffer.
    let text = std::str::from_utf8(bytes).map_err(|_| ProtocolError::AuthRejected {
        attempted: CredentialKind::PrivateKey,
    })?;
    let passphrase = match passphrase {
        Some(bytes) if !bytes.is_empty() => {
            Some(
                std::str::from_utf8(bytes).map_err(|_| ProtocolError::AuthRejected {
                    attempted: CredentialKind::PrivateKey,
                })?,
            )
        }
        _ => None,
    };

    tracing::debug!(format = format.as_str(), "reading a private key");
    russh::keys::decode_secret_key(text, passphrase).map_err(|error| map_key_error(&error))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::{Algorithm, LineEnding, private::KeypairData};

    /// A throwaway key, generated in the test process and never written to
    /// disk. The repository holds no key material — CLAUDE.md §9 forbids
    /// committing one even for a test — so every fixture below is built here.
    ///
    /// The loop steers around an upstream defect rather than hiding it:
    /// `ssh-key` 0.7 decodes a PuTTY Ed25519 private exponent with
    /// `Mpint::as_bytes`, which keeps the leading zero byte that a positive
    /// `mpint` carries when the top bit is set (RFC 4251 §5), and then rejects
    /// the 33-byte result as too long for a 32-byte scalar. Roughly half of
    /// all real `.ppk` Ed25519 keys hit it. See the crate documentation.
    pub(super) fn generate() -> PrivateKey {
        for _ in 0..64 {
            let key =
                PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
            if seed(&key)[0] & 0x80 == 0 {
                return key;
            }
        }
        panic!("no Ed25519 key with a leading zero-bit scalar in 64 attempts");
    }

    fn openssh(key: &PrivateKey) -> String {
        key.to_openssh(LineEnding::LF).unwrap().to_string()
    }

    /// The 32-byte Ed25519 seed, which is what both PKCS#8 and PuTTY store.
    fn seed(key: &PrivateKey) -> [u8; 32] {
        let KeypairData::Ed25519(pair) = key.key_data() else {
            panic!("expected an Ed25519 key");
        };
        pair.private.to_bytes()
    }

    /// An SSH wire string: `uint32 length` then the bytes (RFC 4251 §5).
    fn ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// An SSH `mpint`: two's complement big-endian, minimal length, with a
    /// leading zero byte where the top bit would otherwise read as negative
    /// (RFC 4251 §5). PuTTY stores an Ed25519 private exponent this way.
    fn mpint(value: &[u8]) -> Vec<u8> {
        let start = value
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(value.len());
        let trimmed = &value[start..];
        let mut body = Vec::new();
        if trimmed.first().is_some_and(|byte| byte & 0x80 != 0) {
            body.push(0);
        }
        body.extend_from_slice(trimmed);
        let mut out = Vec::new();
        ssh_string(&mut out, &body);
        out
    }

    /// HMAC (RFC 2104) over a `sha2`/`sha1` digest, written out because the
    /// PuTTY fixture below is the only thing in this crate that needs one and
    /// a dependency for a test helper is not worth its licence review.
    fn hmac<D: sha2::Digest + sha2::digest::FixedOutputReset>(
        block_size: usize,
        key: &[u8],
        message: &[u8],
    ) -> Vec<u8> {
        let mut digest = D::new();
        let mut block = vec![0u8; block_size];
        if key.len() > block_size {
            let hashed = D::digest(key);
            block[..hashed.len()].copy_from_slice(&hashed);
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        let inner: Vec<u8> = block.iter().map(|byte| byte ^ 0x36).collect();
        let outer: Vec<u8> = block.iter().map(|byte| byte ^ 0x5c).collect();

        sha2::Digest::update(&mut digest, &inner);
        sha2::Digest::update(&mut digest, message);
        let inner_hash = digest.finalize_reset();

        sha2::Digest::update(&mut digest, &outer);
        sha2::Digest::update(&mut digest, &inner_hash);
        digest.finalize().to_vec()
    }

    /// Writes an unencrypted `.ppk` for `key`, exactly as PuTTY would.
    ///
    /// The MAC covers `algorithm || encryption || comment || public || private`,
    /// each as an SSH string; the key for it is SHA-1 of a fixed prefix in v2
    /// and empty in v3 (PuTTY's `AppendixC`, and `ssh-key`'s reader).
    pub(super) fn write_ppk(key: &PrivateKey, version: PpkVersion) -> String {
        let comment = "remoter-test";
        let algorithm = key.algorithm().to_string();
        let public = key.public_key().to_bytes().unwrap();
        let private = mpint(&seed(key));

        let mut mac_input = Vec::new();
        ssh_string(&mut mac_input, algorithm.as_bytes());
        ssh_string(&mut mac_input, b"none");
        ssh_string(&mut mac_input, comment.as_bytes());
        ssh_string(&mut mac_input, &public);
        ssh_string(&mut mac_input, &private);

        let mac = match version {
            PpkVersion::V2 => {
                let mac_key = sha1::Sha1::digest(b"putty-private-key-file-mac-key").to_vec();
                hmac::<sha1::Sha1>(64, &mac_key, &mac_input)
            }
            PpkVersion::V3 => hmac::<sha2::Sha256>(64, &[], &mac_input),
        };

        let base64 = |bytes: &[u8]| -> Vec<String> {
            data_encoding::BASE64
                .encode(bytes)
                .as_bytes()
                .chunks(64)
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect()
        };
        let public_lines = base64(&public);
        let private_lines = base64(&private);

        let mut out = format!("{PPK_PREFIX}{}: {algorithm}\n", version.number());
        out.push_str("Encryption: none\n");
        out.push_str(&format!("Comment: {comment}\n"));
        out.push_str(&format!("Public-Lines: {}\n", public_lines.len()));
        for line in &public_lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&format!("Private-Lines: {}\n", private_lines.len()));
        for line in &private_lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&format!(
            "Private-MAC: {}\n",
            data_encoding::HEXLOWER.encode(&mac)
        ));
        out
    }

    /// A PKCS#8 `PrivateKeyInfo` for an Ed25519 key (RFC 8410 §7): version 0,
    /// the `id-Ed25519` OID `1.3.101.112`, and the 32-byte seed wrapped in an
    /// inner OCTET STRING. Small enough to write out, which is what lets the
    /// test build its own fixture instead of committing one.
    fn write_pkcs8(key: &PrivateKey) -> String {
        let mut der = vec![
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER 0
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier: 1.3.101.112
            0x04, 0x22, 0x04, 0x20, // OCTET STRING(34) { OCTET STRING(32) }
        ];
        der.extend_from_slice(&seed(key));

        let body = data_encoding::BASE64.encode(&der);
        let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in body.as_bytes().chunks(64) {
            out.push_str(&String::from_utf8_lossy(chunk));
            out.push('\n');
        }
        out.push_str("-----END PRIVATE KEY-----\n");
        out
    }

    use sha1::Digest as _;

    #[test]
    fn the_format_comes_from_the_content_not_the_name() {
        let key = generate();
        // The same key, in three containers. Nothing here has a file name.
        assert_eq!(
            detect_key_format(openssh(&key).as_bytes()),
            Some(KeyFormat::OpenSsh)
        );
        assert_eq!(
            detect_key_format(write_pkcs8(&key).as_bytes()),
            Some(KeyFormat::Pkcs8)
        );
        assert_eq!(
            detect_key_format(write_ppk(&key, PpkVersion::V2).as_bytes()),
            Some(KeyFormat::Ppk(PpkVersion::V2))
        );
        assert_eq!(
            detect_key_format(write_ppk(&key, PpkVersion::V3).as_bytes()),
            Some(KeyFormat::Ppk(PpkVersion::V3))
        );
    }

    #[test]
    fn the_remaining_pem_banners_are_recognised() {
        assert_eq!(
            detect_key_format(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"),
            Some(KeyFormat::Pkcs8Encrypted)
        );
        assert_eq!(
            detect_key_format(
                b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"
            ),
            Some(KeyFormat::Pkcs1Rsa)
        );
        assert_eq!(
            detect_key_format(
                b"-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"
            ),
            Some(KeyFormat::Pkcs8)
        );
        // RFC 1421 §4.6.1.3: the `DEK-Info` line, not the banner, is what says
        // the body is enciphered.
        assert_eq!(
            detect_key_format(
                b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123\n\nAAAA\n"
            ),
            Some(KeyFormat::Pkcs5Encrypted)
        );
    }

    #[test]
    fn carriage_returns_do_not_hide_a_banner() {
        // A key that travelled through Windows, or through a browser.
        let key = generate();
        let dos = openssh(&key).replace('\n', "\r\n");
        assert_eq!(detect_key_format(dos.as_bytes()), Some(KeyFormat::OpenSsh));
    }

    #[test]
    fn nothing_recognisable_is_not_a_key() {
        assert_eq!(detect_key_format(b""), None);
        assert_eq!(detect_key_format(b"ssh-ed25519 AAAAC3Nz user@host\n"), None);
        assert_eq!(detect_key_format(&[0xff, 0xfe, 0x00]), None);
        // A PuTTY version this build does not read is unrecognised rather than
        // silently treated as one it does.
        assert_eq!(
            detect_key_format(b"PuTTY-User-Key-File-4: ssh-ed25519\n"),
            None
        );
    }

    #[test]
    fn an_openssh_key_round_trips() {
        let key = generate();
        let parsed = parse_private_key(openssh(&key).as_bytes(), None).unwrap();
        assert_eq!(
            parsed.public_key().to_bytes().unwrap(),
            key.public_key().to_bytes().unwrap()
        );
    }

    #[test]
    fn a_pkcs8_key_round_trips() {
        let key = generate();
        let parsed = parse_private_key(write_pkcs8(&key).as_bytes(), None).unwrap();
        assert_eq!(
            parsed.public_key().to_bytes().unwrap(),
            key.public_key().to_bytes().unwrap()
        );
    }

    #[test]
    fn a_ppk_v2_key_round_trips() {
        let key = generate();
        let parsed = parse_private_key(write_ppk(&key, PpkVersion::V2).as_bytes(), None).unwrap();
        assert_eq!(
            parsed.public_key().to_bytes().unwrap(),
            key.public_key().to_bytes().unwrap()
        );
    }

    #[test]
    fn a_ppk_v3_key_round_trips() {
        let key = generate();
        let parsed = parse_private_key(write_ppk(&key, PpkVersion::V3).as_bytes(), None).unwrap();
        assert_eq!(
            parsed.public_key().to_bytes().unwrap(),
            key.public_key().to_bytes().unwrap()
        );
    }

    #[test]
    fn a_passphrase_protected_openssh_key_needs_its_passphrase() {
        let key = generate();
        let encrypted = key
            .encrypt(
                &mut russh::keys::key::safe_rng(),
                "correct horse battery staple",
            )
            .unwrap();
        let pem = openssh(&encrypted);

        assert!(needs_passphrase(pem.as_bytes()));

        // Without one, the answer is "ask the user", not "this failed".
        let error = parse_private_key(pem.as_bytes(), None).unwrap_err();
        assert!(
            matches!(error, ProtocolError::CredentialMissing { .. }),
            "expected CredentialMissing, got {error:?}"
        );

        // With the wrong one, the key is rejected — and the message cannot say
        // whether the file or the passphrase was wrong, because an
        // authenticated cipher cannot tell.
        let wrong = parse_private_key(pem.as_bytes(), Some(b"hunter2")).unwrap_err();
        assert!(matches!(
            wrong,
            ProtocolError::AuthRejected {
                attempted: CredentialKind::PrivateKey
            }
        ));

        let parsed =
            parse_private_key(pem.as_bytes(), Some(b"correct horse battery staple")).unwrap();
        assert_eq!(
            parsed.public_key().to_bytes().unwrap(),
            key.public_key().to_bytes().unwrap()
        );
    }

    #[test]
    fn an_encrypted_ppk_is_reported_as_needing_a_passphrase() {
        let key = generate();
        let encrypted =
            write_ppk(&key, PpkVersion::V3).replace("Encryption: none", "Encryption: aes256-cbc");
        assert!(needs_passphrase(encrypted.as_bytes()));
        let error = parse_private_key(encrypted.as_bytes(), None).unwrap_err();
        assert!(matches!(error, ProtocolError::CredentialMissing { .. }));
    }

    #[test]
    fn an_unencrypted_key_does_not_ask_for_a_passphrase() {
        let key = generate();
        assert!(!needs_passphrase(openssh(&key).as_bytes()));
        assert!(!needs_passphrase(
            write_ppk(&key, PpkVersion::V2).as_bytes()
        ));
        assert!(!needs_passphrase(write_pkcs8(&key).as_bytes()));
    }

    #[test]
    fn a_passphrase_offered_to_a_key_that_needs_none_is_ignored() {
        // `ssh-key` refuses the pairing: a plaintext PKCS#8 handed a passphrase
        // comes back as a parse failure, which reaches the user as a rejected
        // authentication with a key that is perfectly good. The passphrase is
        // dropped here instead, so the same key opens either way.
        let key = generate();
        for pem in [openssh(&key), write_pkcs8(&key)] {
            let parsed = parse_private_key(pem.as_bytes(), Some(b"a passphrase it has no use for"));
            assert!(
                parsed.is_ok_and(|parsed| parsed.public_key().to_bytes().ok()
                    == key.public_key().to_bytes().ok()),
                "an unencrypted key was refused because a passphrase came with it"
            );
        }
    }

    #[test]
    fn no_failure_renders_any_key_material() {
        // The single most likely way to leak a key from this crate is an error
        // that quotes the file it could not read.
        let key = generate();
        let pem = openssh(&key);
        let truncated = &pem.as_bytes()[..pem.len() / 2];
        let error = parse_private_key(truncated, Some(b"hunter2")).unwrap_err();

        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("hunter2"), "rendered: {rendered}");
        for window in pem.as_bytes().windows(16) {
            let fragment = String::from_utf8_lossy(window);
            assert!(
                !rendered.contains(fragment.as_ref()),
                "a key fragment reached the error: {rendered}"
            );
        }
    }

    #[test]
    fn the_format_name_is_stable_and_carries_nothing() {
        for format in [
            KeyFormat::OpenSsh,
            KeyFormat::Pkcs1Rsa,
            KeyFormat::Pkcs5Encrypted,
            KeyFormat::Pkcs8,
            KeyFormat::Pkcs8Encrypted,
            KeyFormat::Ppk(PpkVersion::V2),
            KeyFormat::Ppk(PpkVersion::V3),
        ] {
            assert!(!format.as_str().is_empty());
            assert_eq!(format.to_string(), format.as_str());
        }
        assert!(KeyFormat::Pkcs8Encrypted.is_always_encrypted());
        assert!(KeyFormat::Pkcs5Encrypted.is_always_encrypted());
        assert!(!KeyFormat::OpenSsh.is_always_encrypted());
    }
}
