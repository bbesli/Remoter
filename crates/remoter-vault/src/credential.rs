//! Private keys and agent-backed credentials.
//!
//! The vault stores private key material itself, encrypted, rather than
//! pointing at a file on disk: a credential that depends on `~/.ssh/id_ed25519`
//! stops working the moment the vault is carried to another machine, which is
//! the opposite of what a portable vault is for. The key is sealed under the
//! SEK like any other secret field, and its passphrase — if it has one — is a
//! separate field, so revealing one does not reveal the other.
//!
//! The most secure option is to store nothing at all. `SecretKind::Agent`
//! delegates the signature to the platform agent, so the key never enters this
//! process's address space; [`agent_credential`] exists so that saying that
//! takes one line.
//!
//! # Detecting the format
//!
//! From the content, never from the extension. A `.pem` holding an OpenSSH
//! container is ordinary — `ssh-keygen -m PEM` writes one — and a `.txt`
//! holding a PPK is what a support ticket produces. Guessing from the name
//! would file the key under a format the protocol adapter then fails to parse,
//! at connect time, far from the mistake.
//!
//! Container references, per the rule about wire formats in `CLAUDE.md` §0.4:
//!
//! - OpenSSH: `PROTOCOL.key` in the OpenSSH distribution — `AUTH_MAGIC`
//!   `"openssh-key-v1\0"`, then the `ciphername` string, which is `"none"` for
//!   an unencrypted key.
//! - PKCS#8: RFC 5958 — `PrivateKeyInfo` under `BEGIN PRIVATE KEY`,
//!   `EncryptedPrivateKeyInfo` under `BEGIN ENCRYPTED PRIVATE KEY`. Both are a
//!   DER `SEQUENCE`, so the decoded body starts with `0x30`.
//! - PuTTY PPK: the format described in PuTTY's `sshpubk.c` — a
//!   `PuTTY-User-Key-File-<version>:` line, then an `Encryption:` line whose
//!   value is `none` for an unencrypted key.

use std::fmt;
use std::path::Path;

use remoter_core::{CredentialProps, KeyFormat, SecretKind};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::secret::{ExposeSecret, Secret};

/// Largest key file this build will read, in bytes.
///
/// A private key is a few kilobytes; a PPK carrying a certificate and a long
/// comment is still far below this. The bound exists so that pointing the file
/// picker at a disk image does not read it into memory before deciding it is
/// not a key.
const MAX_KEY_BYTES: u64 = 1024 * 1024;

/// OpenSSH's container magic, including its terminating NUL.
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// A private key read from a file, with its container identified from its
/// content.
///
/// `Debug` names the format and whether the key is encrypted — both are
/// operationally useful and neither is secret — and prints nothing else, not
/// even a length.
pub struct ImportedKey {
    format: KeyFormat,
    encrypted: bool,
    material: Secret<Vec<u8>>,
}

impl ImportedKey {
    /// Identifies a key from bytes already in memory, taking ownership of them.
    ///
    /// Takes the buffer by value rather than by reference so that the only copy
    /// of the key material ends up inside the returned [`Secret`], which zeroes
    /// it on drop.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, VaultError> {
        // Wrapped first: every early return below drops this, and dropping it
        // wipes the buffer even when the file turns out not to be a key.
        let material = Secret::new(bytes);
        let (format, encrypted) = detect(material.expose_secret())?;
        Ok(Self {
            format,
            encrypted,
            material,
        })
    }

    /// Reads a key file, refusing anything that is not a private key.
    ///
    /// The error says which of the two it is: a file that is not a key at all
    /// ([`VaultError::NotAPrivateKey`]) or a key in a container this build does
    /// not store ([`VaultError::UnsupportedKeyFormat`]). Neither message quotes
    /// the file's contents.
    pub fn read(path: &Path) -> Result<Self, VaultError> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| VaultError::io("reading the private key", path, e))?;
        if metadata.len() > MAX_KEY_BYTES {
            return Err(VaultError::NotAPrivateKey);
        }
        let bytes =
            std::fs::read(path).map_err(|e| VaultError::io("reading the private key", path, e))?;
        Self::from_bytes(bytes)
    }

    /// The container this key is in.
    #[must_use]
    pub const fn format(&self) -> KeyFormat {
        self.format
    }

    /// Whether the key material itself is encrypted, and therefore needs a
    /// passphrase to use.
    ///
    /// Read from the container rather than inferred from whether the caller
    /// supplied a passphrase, so the interface can tell a user who supplied
    /// none that the key will not work.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// The key material, for the vault to seal. Crate-private: nothing outside
    /// this crate has a reason to hold the plaintext.
    pub(crate) const fn material(&self) -> &Secret<Vec<u8>> {
        &self.material
    }
}

impl fmt::Debug for ImportedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportedKey")
            .field("format", &self.format)
            .field("encrypted", &self.encrypted)
            .field("material", &"<redacted>")
            .finish()
    }
}

/// A private key opened out of the vault, with its passphrase if it has one.
///
/// Both buffers are zeroed when this drops. `Debug` redacts them.
pub struct PrivateKeyMaterial {
    format: KeyFormat,
    key: Secret<Vec<u8>>,
    passphrase: Option<Secret<Vec<u8>>>,
}

impl PrivateKeyMaterial {
    pub(crate) const fn new(
        format: KeyFormat,
        key: Secret<Vec<u8>>,
        passphrase: Option<Secret<Vec<u8>>>,
    ) -> Self {
        Self {
            format,
            key,
            passphrase,
        }
    }

    /// The container the key material is in.
    #[must_use]
    pub const fn format(&self) -> KeyFormat {
        self.format
    }

    /// The key material.
    #[must_use]
    pub const fn key(&self) -> &Secret<Vec<u8>> {
        &self.key
    }

    /// The passphrase that decrypts it, if one is stored.
    #[must_use]
    pub const fn passphrase(&self) -> Option<&Secret<Vec<u8>>> {
        self.passphrase.as_ref()
    }
}

impl fmt::Debug for PrivateKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyMaterial")
            .field("format", &self.format)
            .field("key", &"<redacted>")
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

/// A credential whose signing is delegated to the platform SSH agent.
///
/// No key material is stored, which makes this the most secure option for SSH:
/// the private key never enters this process. `comment_filter` narrows which of
/// the agent's identities is used, by comment substring.
#[must_use]
pub fn agent_credential(
    username: impl Into<String>,
    comment_filter: Option<String>,
) -> CredentialProps {
    CredentialProps::new(username, SecretKind::Agent { comment_filter })
}

/// A credential shaped to hold a private key, before the key itself is stored.
///
/// The sealed fields carry [`crate::Vault::sealed_placeholder`]: a ciphertext
/// is bound to its node's id and revision, so it cannot exist until the node
/// does. Insert this node, then call [`crate::Vault::set_private_key`] or
/// [`crate::Vault::import_private_key`], which replaces the placeholder and
/// corrects the format if the file turns out to be a different container.
#[must_use]
pub fn private_key_credential(
    username: impl Into<String>,
    format: KeyFormat,
    with_passphrase: bool,
) -> CredentialProps {
    CredentialProps::new(
        username,
        SecretKind::PrivateKey {
            sealed_key: crate::Vault::sealed_placeholder(),
            sealed_passphrase: with_passphrase.then(crate::Vault::sealed_placeholder),
            format,
        },
    )
}

/// Identifies a private key container, and whether its material is encrypted.
fn detect(bytes: &[u8]) -> Result<(KeyFormat, bool), VaultError> {
    let text = std::str::from_utf8(bytes).map_err(|_| VaultError::NotAPrivateKey)?;
    let text = text.trim_start_matches('\u{feff}').trim_start();

    if text.starts_with("PuTTY-User-Key-File-") {
        return detect_ppk(text);
    }

    let (label, body) = pem_block(text).ok_or(VaultError::NotAPrivateKey)?;
    match label {
        "OPENSSH PRIVATE KEY" => detect_openssh(&body),
        "PRIVATE KEY" => {
            require_der_sequence(&body)?;
            Ok((KeyFormat::Pkcs8, false))
        }
        "ENCRYPTED PRIVATE KEY" => {
            require_der_sequence(&body)?;
            Ok((KeyFormat::Pkcs8, true))
        }
        // Real private keys, in containers `remoter_core::KeyFormat` cannot
        // name. Refused by name rather than filed under PKCS#8: the two are
        // different ASN.1 structures and an adapter told the wrong one fails at
        // connect time.
        "RSA PRIVATE KEY" => Err(VaultError::UnsupportedKeyFormat("PKCS#1 RSA PEM")),
        "DSA PRIVATE KEY" => Err(VaultError::UnsupportedKeyFormat("OpenSSL DSA PEM")),
        "EC PRIVATE KEY" => Err(VaultError::UnsupportedKeyFormat("SEC 1 elliptic curve PEM")),
        _ => Err(VaultError::NotAPrivateKey),
    }
}

/// The label and decoded body of the first PEM block in a document.
///
/// Returns `None` if there is no `-----BEGIN x-----` / `-----END x-----` pair,
/// or if what lies between them is not base64. That second case is what stops a
/// text file with a pasted header from being accepted as a key.
fn pem_block(text: &str) -> Option<(&str, Zeroizing<Vec<u8>>)> {
    let mut label: Option<&str> = None;
    let mut base64 = Zeroizing::new(String::new());

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            label = rest.strip_suffix("-----");
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if label.is_some() && !line.is_empty() {
            // A legacy encrypted PEM carries `Proc-Type:` and `DEK-Info:`
            // headers inside the block. A colon is not in the base64 alphabet,
            // so it identifies such a line unambiguously; skipping it lets the
            // block still decode, and lets the caller refuse the container by
            // name rather than as "not a key".
            if line.contains(':') {
                continue;
            }
            base64.push_str(line);
        }
    }

    let label = label?;
    let decoded = data_encoding::BASE64.decode(base64.as_bytes()).ok()?;
    Some((label, Zeroizing::new(decoded)))
}

/// Rejects a body that is not a DER `SEQUENCE`.
///
/// RFC 5958 §2: both `PrivateKeyInfo` and `EncryptedPrivateKeyInfo` are a
/// `SEQUENCE`, whose DER identifier octet is `0x30`. Cheap, and it catches a
/// file carrying a PKCS#8 header over something else entirely.
fn require_der_sequence(body: &[u8]) -> Result<(), VaultError> {
    match body.first() {
        Some(0x30) => Ok(()),
        _ => Err(VaultError::NotAPrivateKey),
    }
}

/// Reads the `ciphername` out of an OpenSSH container.
///
/// `PROTOCOL.key`: `AUTH_MAGIC` then `string ciphername`, where a string is a
/// big-endian `u32` length followed by that many bytes. `"none"` means the
/// private half is not encrypted.
fn detect_openssh(body: &[u8]) -> Result<(KeyFormat, bool), VaultError> {
    let rest = body
        .strip_prefix(OPENSSH_MAGIC)
        .ok_or(VaultError::NotAPrivateKey)?;

    let (length, rest) = rest.split_at_checked(4).ok_or(VaultError::NotAPrivateKey)?;
    let length: [u8; 4] = length.try_into().map_err(|_| VaultError::NotAPrivateKey)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| VaultError::NotAPrivateKey)?;

    let cipher = rest.get(..length).ok_or(VaultError::NotAPrivateKey)?;
    Ok((KeyFormat::OpenSsh, cipher != b"none"))
}

/// Reads the `Encryption:` header out of a PPK.
fn detect_ppk(text: &str) -> Result<(KeyFormat, bool), VaultError> {
    let encryption = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("Encryption:"))
        .map(str::trim)
        .ok_or(VaultError::NotAPrivateKey)?;
    Ok((KeyFormat::PuttyPpk, encryption != "none"))
}

/// Builders for the sample keys the tests and the vault's own test suite use.
///
/// Public to the crate rather than to the world: they produce well-formed
/// containers around meaningless key material, which is the right thing for a
/// test and the wrong thing for anything else.
#[cfg(test)]
pub(crate) mod samples {
    use super::OPENSSH_MAGIC;

    /// A PEM document with `body` base64-encoded inside `label`.
    pub(crate) fn pem(label: &str, body: &[u8]) -> Vec<u8> {
        let encoded = data_encoding::BASE64.encode(body);
        let mut out = format!("-----BEGIN {label}-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            out.push_str(&String::from_utf8_lossy(chunk));
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out.into_bytes()
    }

    /// An OpenSSH container declaring `cipher`. Everything after the cipher
    /// name is arbitrary: the format detector reads no further.
    pub(crate) fn openssh(cipher: &str) -> Vec<u8> {
        let mut body = Vec::from(OPENSSH_MAGIC);
        let length = u32::try_from(cipher.len()).unwrap_or(0);
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(cipher.as_bytes());
        body.extend_from_slice(b"\0\0\0\x04none\0\0\0\0\0\0\0\x01");
        pem("OPENSSH PRIVATE KEY", &body)
    }

    /// A PKCS#8 document. The body is a minimal DER `SEQUENCE`.
    pub(crate) fn pkcs8(encrypted: bool) -> Vec<u8> {
        let body = [0x30, 0x03, 0x02, 0x01, 0x00];
        let label = if encrypted {
            "ENCRYPTED PRIVATE KEY"
        } else {
            "PRIVATE KEY"
        };
        pem(label, &body)
    }

    /// A PPK document declaring `encryption`.
    pub(crate) fn ppk(encryption: &str) -> Vec<u8> {
        format!(
            "PuTTY-User-Key-File-3: ssh-ed25519\n\
             Encryption: {encryption}\n\
             Comment: sample\n\
             Public-Lines: 1\n\
             AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
             Private-Lines: 1\n\
             AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
             Private-MAC: 00\n"
        )
        .into_bytes()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod tests {
    use super::*;

    #[test]
    fn each_container_is_recognised_from_its_content() {
        let cases: [(Vec<u8>, KeyFormat, bool); 6] = [
            (samples::openssh("none"), KeyFormat::OpenSsh, false),
            (samples::openssh("aes256-ctr"), KeyFormat::OpenSsh, true),
            (samples::pkcs8(false), KeyFormat::Pkcs8, false),
            (samples::pkcs8(true), KeyFormat::Pkcs8, true),
            (samples::ppk("none"), KeyFormat::PuttyPpk, false),
            (samples::ppk("aes256-cbc"), KeyFormat::PuttyPpk, true),
        ];

        for (bytes, format, encrypted) in cases {
            let key = ImportedKey::from_bytes(bytes).unwrap();
            assert_eq!(key.format(), format);
            assert_eq!(key.is_encrypted(), encrypted, "for {format:?}");
        }
    }

    #[test]
    fn the_extension_is_never_consulted() {
        // A `.pem` holding an OpenSSH container is what `ssh-keygen` writes by
        // default; the detector must not be swayed by the name it is given.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519.pem");
        std::fs::write(&path, samples::openssh("none")).unwrap();

        let key = ImportedKey::read(&path).unwrap();
        assert_eq!(key.format(), KeyFormat::OpenSsh);
    }

    #[test]
    fn something_that_is_not_a_key_is_refused() {
        for bytes in [
            b"just some notes about the server".to_vec(),
            b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 alice@laptop\n".to_vec(),
            samples::pem("CERTIFICATE", &[0x30, 0x03, 0x02, 0x01, 0x00]),
            // A PKCS#8 header over something that is not DER.
            samples::pem("PRIVATE KEY", b"not der at all"),
            // An OpenSSH header over something without the magic.
            samples::pem("OPENSSH PRIVATE KEY", b"wrong magic entirely"),
            vec![0xFF, 0xFE, 0x00, 0x01],
        ] {
            assert!(
                matches!(
                    ImportedKey::from_bytes(bytes),
                    Err(VaultError::NotAPrivateKey)
                ),
                "a file that is not a key must be refused"
            );
        }
    }

    #[test]
    fn a_key_in_a_container_this_build_cannot_store_is_named_not_guessed() {
        for (label, expected) in [
            ("RSA PRIVATE KEY", "PKCS#1 RSA PEM"),
            ("DSA PRIVATE KEY", "OpenSSL DSA PEM"),
            ("EC PRIVATE KEY", "SEC 1 elliptic curve PEM"),
        ] {
            let bytes = samples::pem(label, &[0x30, 0x03, 0x02, 0x01, 0x00]);
            match ImportedKey::from_bytes(bytes) {
                Err(VaultError::UnsupportedKeyFormat(named)) => assert_eq!(named, expected),
                other => panic!("expected UnsupportedKeyFormat for {label}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_legacy_pem_header_does_not_make_the_block_undecodable() {
        // `Proc-Type:` and `DEK-Info:` sit inside the block. The container is
        // refused by name, which is only possible if the block parsed.
        let mut document = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
        document.push_str("Proc-Type: 4,ENCRYPTED\n");
        document.push_str("DEK-Info: AES-128-CBC,0123456789ABCDEF\n\n");
        document.push_str(&data_encoding::BASE64.encode(&[0x30, 0x03, 0x02, 0x01, 0x00]));
        document.push_str("\n-----END RSA PRIVATE KEY-----\n");

        assert!(matches!(
            ImportedKey::from_bytes(document.into_bytes()),
            Err(VaultError::UnsupportedKeyFormat("PKCS#1 RSA PEM"))
        ));
    }

    #[test]
    fn an_oversized_file_is_refused_by_its_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.img");
        std::fs::write(
            &path,
            vec![0u8; usize::try_from(MAX_KEY_BYTES).unwrap_or(0) + 1],
        )
        .unwrap();

        assert!(matches!(
            ImportedKey::read(&path),
            Err(VaultError::NotAPrivateKey)
        ));
    }

    #[test]
    fn debug_never_shows_the_key_or_the_passphrase() {
        let bytes = samples::openssh("none");
        let key = ImportedKey::from_bytes(bytes.clone()).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("OpenSsh"));
        assert!(rendered.contains("<redacted>"));
        // The base64 of the container is what a leak would look like.
        let armour = String::from_utf8_lossy(&bytes);
        for line in armour.lines().filter(|l| !l.starts_with("-----")) {
            assert!(!rendered.contains(line), "the key material reached Debug");
        }

        let material = PrivateKeyMaterial::new(
            KeyFormat::Pkcs8,
            Secret::new(b"the key itself".to_vec()),
            Some(Secret::new(b"the passphrase".to_vec())),
        );
        let rendered = format!("{material:?}");
        assert!(!rendered.contains("the key itself"));
        assert!(!rendered.contains("the passphrase"));
    }

    #[test]
    fn an_agent_credential_stores_no_material() {
        let credential = agent_credential("svc-deploy", Some("deploy".into()));
        assert!(matches!(credential.secret, SecretKind::Agent { .. }));
        assert_eq!(
            format!("{:?}", credential.secret),
            "SecretKind::Agent(<redacted>)"
        );
    }
}
