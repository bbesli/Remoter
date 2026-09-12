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
//! - PKCS#1 RSA: RFC 8017 §A.1.2 — `RSAPrivateKey` under
//!   `BEGIN RSA PRIVATE KEY`. AWS EC2 hands one out with every key pair it
//!   generates, and `ssh-keygen` wrote them by default until OpenSSH 7.8.
//! - SEC 1 elliptic curve: RFC 5915 §3 — `ECPrivateKey` under
//!   `BEGIN EC PRIVATE KEY`, which is what `ssh-keygen -m PEM -t ecdsa`
//!   writes.
//! - RFC 1421 §4.6.1.3 — a `DEK-Info:` header inside a PEM block means the
//!   body below it is enciphered, whatever the banner said.
//!
//! # Normalising on the way in
//!
//! The last two of those are containers `remoter_core::KeyFormat` cannot name,
//! and both hold exactly what a PKCS#8 `PrivateKeyInfo` holds. Rather than
//! refuse them — which made the private-key option unusable for most of the
//! `.pem` files an administrator actually has — they are re-enveloped as
//! PKCS#8 as the file is read, by [`crate::pkcs8`], and stored under that
//! label. The rewrite is structural: no cipher, no key derivation, no key byte
//! changed. Everything below the vault therefore sees one representation and
//! never has to know which file it came from.
//!
//! # The passphrase-protected `.pem`
//!
//! An enciphered legacy PEM — `Proc-Type: 4,ENCRYPTED` and a `DEK-Info` line —
//! cannot be re-enveloped at this step, because reaching its plaintext needs a
//! passphrase and this step runs *before* the interface knows to ask for one.
//! It used to be refused outright here, which is the refusal a user reads as
//! ".pem is not supported": it arrives the moment the file is chosen, with no
//! passphrase field anywhere on screen to suggest otherwise.
//!
//! So it is not refused. It is identified, reported as encrypted — which is
//! precisely what makes the interface ask for the passphrase — and carried in
//! [`ImportedKey`] as ciphertext until [`ImportedKey::unlock`] is handed that
//! passphrase, at which point [`crate::legacy_pem`] deciphers it and
//! [`crate::pkcs8`] re-envelopes the result like any other legacy PEM.
//!
//! What is stored afterwards is therefore an *unenciphered* PKCS#8 document and
//! no stored passphrase, where an encrypted OpenSSH or PKCS#8 container is
//! stored as it stands with its passphrase beside it. That asymmetry is a
//! consequence of the container, not a policy: this build can read a legacy PEM
//! but cannot write one, so keeping the file's own envelope would mean storing
//! a key nothing downstream could open. The material is sealed under the SEK
//! either way, and a passphrase held in the same vault as the key it opens adds
//! nothing an attacker who has the vault open does not already have.

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
    material: Material,
}

/// What an [`ImportedKey`] is holding: something the vault can seal as it
/// stands, or a legacy PEM still waiting for its passphrase.
enum Material {
    /// A document in the container [`ImportedKey::format`] names.
    Ready(Secret<Vec<u8>>),
    /// The enciphered body of a legacy PEM, with the `DEK-Info` header that
    /// says how to read it. [`ImportedKey::unlock`] is what turns this into a
    /// `Ready` PKCS#8 document.
    Locked {
        kind: LegacyKind,
        /// The `DEK-Info` value: a cipher name and an IV. Neither is secret —
        /// both are written in the clear in the file — so this is an ordinary
        /// `String`.
        dek_info: String,
        body: Secret<Vec<u8>>,
    },
}

/// Which legacy PEM container a locked body came out of, so that the right
/// re-envelope runs once it has been deciphered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyKind {
    /// RFC 8017 §A.1.2 `RSAPrivateKey`.
    Pkcs1Rsa,
    /// RFC 5915 §3 `ECPrivateKey`.
    Sec1Ec,
}

impl ImportedKey {
    /// Identifies a key from bytes already in memory, taking ownership of them.
    ///
    /// Takes the buffer by value rather than by reference so that the only copy
    /// of the key material ends up inside the returned [`Secret`], which zeroes
    /// it on drop.
    ///
    /// A legacy PEM container is re-enveloped as PKCS#8 here; see the module
    /// documentation. The buffer that came off disk is dropped — and therefore
    /// wiped — in that case, so only the normalised copy survives the call.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, VaultError> {
        // Wrapped first: every early return below drops this, and dropping it
        // wipes the buffer even when the file turns out not to be a key.
        let material = Secret::new(bytes);
        match detect(material.expose_secret())? {
            Identified::AsIs { format, encrypted } => Ok(Self {
                format,
                encrypted,
                material: Material::Ready(material),
            }),
            Identified::Locked {
                kind,
                dek_info,
                body,
            } => {
                drop(material);
                Ok(Self {
                    // What this *will* be stored as, which is what the
                    // interface shows and what the credential will record. The
                    // file's own container is not one the domain model names,
                    // and naming it here would mean naming it twice.
                    format: KeyFormat::Pkcs8,
                    encrypted: true,
                    material: Material::Locked {
                        kind,
                        dek_info,
                        body: Secret::new(body),
                    },
                })
            }
            Identified::Normalised { pkcs8 } => {
                // Explicit rather than left to the end of the function: the
                // file's own bytes have no further use once the PKCS#8 copy
                // exists, and the sooner they are gone the smaller the window
                // in which both copies are resident.
                drop(material);
                Ok(Self {
                    format: KeyFormat::Pkcs8,
                    // The rewrite produces an unenciphered document, whatever
                    // the file it came from was: an enciphered one arrives
                    // here only after `unlock` deciphered it.
                    encrypted: false,
                    material: Material::Ready(Secret::new(pkcs8)),
                })
            }
        }
    }

    /// Reads a key file, refusing anything that is not a private key.
    ///
    /// The error says which of the three it is: a file that is not a key at all
    /// ([`VaultError::NotAPrivateKey`]), a key of a kind no protocol here can
    /// authenticate with ([`VaultError::UnsupportedKeyFormat`]), or a legacy
    /// PEM enciphered with a cipher this build cannot read
    /// ([`VaultError::UnsupportedKeyCipher`]) — three different remedies, which
    /// is why they are three errors. None of the messages quotes the file's
    /// contents.
    ///
    /// A legacy PEM enciphered with one this build *can* read is not an error:
    /// it comes back locked, and [`ImportedKey::unlock`] opens it.
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

    /// Whether this key is still enciphered in a container the vault cannot
    /// store, and therefore has to be opened with its passphrase first.
    ///
    /// True only for a legacy PEM. An encrypted OpenSSH or PKCS#8 container is
    /// stored exactly as it stands, ciphertext and all, and never needs this.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        matches!(self.material, Material::Locked { .. })
    }

    /// The key material, for the vault to seal, or `None` while the key is
    /// still locked.
    ///
    /// Crate-private, and an `Option` rather than a slice so that sealing a
    /// locked key's ciphertext under a label claiming PKCS#8 is not something a
    /// caller can do by forgetting a step.
    pub(crate) const fn material(&self) -> Option<&Secret<Vec<u8>>> {
        match &self.material {
            Material::Ready(material) => Some(material),
            Material::Locked { .. } => None,
        }
    }

    /// Deciphers a locked legacy PEM and re-envelopes it as PKCS#8.
    ///
    /// Returns a new key holding the re-enveloped document, which is what the
    /// vault seals. A key that is not locked is returned to the caller's
    /// attention as an error rather than silently: calling this on an
    /// already-readable key means the caller's model of the import is wrong.
    ///
    /// # Errors
    ///
    /// [`VaultError::KeyPassphraseRejected`] when the passphrase does not open
    /// the container — which is also what a corrupt body looks like, there
    /// being no authentication tag to tell them apart;
    /// [`VaultError::UnsupportedKeyCipher`] when the `DEK-Info` header names a
    /// cipher this build cannot read; [`VaultError::NotAPrivateKey`] when the
    /// deciphered body is not the key structure its banner promised.
    pub fn unlock(&self, passphrase: &[u8]) -> Result<Self, VaultError> {
        let Material::Locked {
            kind,
            dek_info,
            body,
        } = &self.material
        else {
            return Err(VaultError::NotAPrivateKey);
        };

        let der = crate::legacy_pem::decipher(dek_info, passphrase, body.expose_secret())?;
        // A wrong passphrase usually fails the padding check above, but one
        // time in a few hundred the padding is accidentally well-formed and the
        // plaintext is noise. Re-enveloping is what catches that, and the
        // answer for the user is the same either way: this passphrase did not
        // open this file.
        let pkcs8 = match kind {
            LegacyKind::Pkcs1Rsa => crate::pkcs8::from_pkcs1_rsa(&der),
            LegacyKind::Sec1Ec => crate::pkcs8::from_sec1_ec(&der),
        }
        .map_err(|_| VaultError::KeyPassphraseRejected)?;

        Ok(Self {
            format: KeyFormat::Pkcs8,
            encrypted: false,
            material: Material::Ready(Secret::new(pkcs8)),
        })
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

/// What reading a key file decided to do with it.
enum Identified {
    /// The file is in a container the domain model names; it is stored exactly
    /// as it was read.
    AsIs { format: KeyFormat, encrypted: bool },
    /// The file was in a legacy PEM container and has been re-enveloped as a
    /// PKCS#8 document; see [`crate::pkcs8`]. Always unencrypted, because only
    /// an unencrypted body can be re-enveloped without the passphrase.
    Normalised { pkcs8: Vec<u8> },
    /// The file is a legacy PEM whose body is enciphered. It can become a
    /// PKCS#8 document like the one above, but not until someone supplies the
    /// passphrase — see [`ImportedKey::unlock`].
    Locked {
        kind: LegacyKind,
        dek_info: String,
        body: Vec<u8>,
    },
}

/// Identifies a private key container, and decides how it is stored.
fn detect(bytes: &[u8]) -> Result<Identified, VaultError> {
    let text = std::str::from_utf8(bytes).map_err(|_| VaultError::NotAPrivateKey)?;
    let text = text.trim_start_matches('\u{feff}').trim_start();

    if text.starts_with("PuTTY-User-Key-File-") {
        let (format, encrypted) = detect_ppk(text)?;
        return Ok(Identified::AsIs { format, encrypted });
    }

    let block = pem_block(text).ok_or(VaultError::NotAPrivateKey)?;
    match block.label {
        "OPENSSH PRIVATE KEY" => {
            let (format, encrypted) = detect_openssh(&block.body)?;
            Ok(Identified::AsIs { format, encrypted })
        }
        "PRIVATE KEY" => {
            require_der_sequence(&block.body)?;
            Ok(Identified::AsIs {
                format: KeyFormat::Pkcs8,
                encrypted: false,
            })
        }
        "ENCRYPTED PRIVATE KEY" => {
            require_der_sequence(&block.body)?;
            Ok(Identified::AsIs {
                format: KeyFormat::Pkcs8,
                encrypted: true,
            })
        }
        // Real private keys in containers `remoter_core::KeyFormat` cannot
        // name. They are not mis-filed under PKCS#8 — the ASN.1 structures
        // differ, and a label that lies is a label — they are *converted* into
        // PKCS#8, which is a structural rewrite of the same key material.
        //
        // A body carrying an RFC 1421 `DEK-Info` header is ciphertext, so
        // there is nothing to re-envelope yet. It is carried as it stands and
        // opened by `unlock` once the interface — which is told the key is
        // encrypted, and asks — has the passphrase.
        "RSA PRIVATE KEY" | "EC PRIVATE KEY" if block.dek_info.is_some() => {
            let kind = if block.label == "RSA PRIVATE KEY" {
                LegacyKind::Pkcs1Rsa
            } else {
                LegacyKind::Sec1Ec
            };
            // The guard above has already decided this; the `else` is how the
            // arm says so without an `unwrap`.
            let Some(dek_info) = block.dek_info else {
                return Err(VaultError::NotAPrivateKey);
            };
            // Whether the cipher can be read at all is knowable now, without a
            // passphrase. Answering it here is what stops the interface from
            // asking for one it is going to refuse anyway.
            crate::legacy_pem::check_readable(dek_info)?;
            Ok(Identified::Locked {
                kind,
                dek_info: dek_info.to_owned(),
                body: block.body.to_vec(),
            })
        }
        "RSA PRIVATE KEY" => Ok(Identified::Normalised {
            pkcs8: crate::pkcs8::from_pkcs1_rsa(&block.body)?,
        }),
        "EC PRIVATE KEY" => Ok(Identified::Normalised {
            pkcs8: crate::pkcs8::from_sec1_ec(&block.body)?,
        }),
        // Not a conversion gap. OpenSSH disabled `ssh-dss` by default in 7.0
        // and removed it outright in 10.0, so a DSA key cannot authenticate a
        // session this build could open even if the vault stored it.
        "DSA PRIVATE KEY" => Err(VaultError::UnsupportedKeyFormat("OpenSSL DSA PEM")),
        _ => Err(VaultError::NotAPrivateKey),
    }
}

/// The first PEM block in a document, decoded.
struct PemBlock<'a> {
    /// The text between `-----BEGIN ` and `-----`.
    label: &'a str,
    /// The base64 body, decoded.
    body: Zeroizing<Vec<u8>>,
    /// The value of the block's RFC 1421 §4.6.1.3 `DEK-Info:` header — a
    /// cipher name and an IV — when it has one, which means the body below it
    /// is enciphered whatever the banner said. Borrowed from the document, and
    /// not a secret: both halves are written in the clear beside the
    /// ciphertext they describe.
    dek_info: Option<&'a str>,
}

/// The label and decoded body of the first PEM block in a document.
///
/// Returns `None` if there is no `-----BEGIN x-----` / `-----END x-----` pair,
/// or if what lies between them is not base64. That second case is what stops a
/// text file with a pasted header from being accepted as a key.
fn pem_block(text: &str) -> Option<PemBlock<'_>> {
    let mut label: Option<&str> = None;
    let mut base64 = Zeroizing::new(String::new());
    let mut dek_info: Option<&str> = None;

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
            // block still decode, and noting the `DEK-Info` lets the caller
            // tell ciphertext from a key it can re-envelope.
            if line.contains(':') {
                if let Some(value) = line.strip_prefix("DEK-Info:") {
                    dek_info = Some(value.trim());
                }
                continue;
            }
            base64.push_str(line);
        }
    }

    let label = label?;
    let decoded = data_encoding::BASE64.decode(base64.as_bytes()).ok()?;
    Some(PemBlock {
        label,
        body: Zeroizing::new(decoded),
        dek_info,
    })
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
    fn a_key_this_build_cannot_authenticate_with_is_named_not_guessed() {
        // DSA is the one refusal here that is a real limitation rather than a
        // missing conversion: OpenSSH disabled `ssh-dss` in 7.0 and removed it
        // in 10.0, so storing the key would only move the failure to connect
        // time. PKCS#1 RSA and SEC 1 EC used to sit in this list and are now
        // re-enveloped instead — see the tests below.
        let bytes = samples::pem("DSA PRIVATE KEY", &[0x30, 0x03, 0x02, 0x01, 0x00]);
        match ImportedKey::from_bytes(bytes) {
            Err(VaultError::UnsupportedKeyFormat(named)) => {
                assert_eq!(named, "OpenSSL DSA PEM");
            }
            other => panic!("expected UnsupportedKeyFormat for DSA, got {other:?}"),
        }
    }

    #[test]
    fn a_legacy_pem_header_does_not_make_the_block_undecodable() {
        // `Proc-Type:` and `DEK-Info:` sit inside the block, where base64 is
        // expected. Reaching a locked key at all proves the block parsed around
        // them and that the `DEK-Info` value came back out.
        let mut document = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
        document.push_str("Proc-Type: 4,ENCRYPTED\n");
        document.push_str("DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n");
        document.push_str(&data_encoding::BASE64.encode(&[0u8; 16]));
        document.push_str("\n-----END RSA PRIVATE KEY-----\n");

        let key = ImportedKey::from_bytes(document.into_bytes()).unwrap();
        assert!(key.is_locked());
        assert!(key.is_encrypted(), "which is what makes the editor ask");
        assert_eq!(key.format(), KeyFormat::Pkcs8, "what it will be stored as");
        assert!(key.material().is_none(), "ciphertext is not storable");
    }

    #[test]
    fn a_cipher_this_build_cannot_read_is_named_rather_than_attempted() {
        // DES-EDE3-CBC is what OpenSSL wrote before 1.1. The refusal has to be
        // its own sentence: the remedy is one `ssh-keygen -p` over a copy,
        // where an unsupported key *type* would still be refused afterwards.
        //
        // And it has to arrive here, while the file is being identified, rather
        // than after a passphrase has been asked for and typed: the cipher name
        // is written in the clear beside the ciphertext, so nothing about this
        // answer needed the passphrase.
        let document = |dek_info: &str| {
            format!(
                "-----BEGIN RSA PRIVATE KEY-----\n\
                 Proc-Type: 4,ENCRYPTED\n\
                 DEK-Info: {dek_info}\n\n\
                 {}\n\
                 -----END RSA PRIVATE KEY-----\n",
                data_encoding::BASE64.encode(&[0u8; 16])
            )
            .into_bytes()
        };

        match ImportedKey::from_bytes(document("DES-EDE3-CBC,0123456789ABCDEF")) {
            Err(VaultError::UnsupportedKeyCipher(named)) => {
                assert_eq!(named, "DES-EDE3-CBC");
            }
            other => panic!("expected UnsupportedKeyCipher, got {other:?}"),
        }

        // Whatever the file said. A message assembled from the file's own bytes
        // is a message the file wrote.
        match ImportedKey::from_bytes(document("PANTHER-9000-CBC,0123456789ABCDEF")) {
            Err(VaultError::UnsupportedKeyCipher(named)) => {
                assert_eq!(named, "an unrecognised cipher");
            }
            other => panic!("expected UnsupportedKeyCipher, got {other:?}"),
        }
    }

    #[test]
    fn a_pem_body_that_is_not_the_structure_its_banner_claims_is_refused() {
        // The banner says PKCS#1, the body is a bare INTEGER. Re-enveloping it
        // unexamined would build a PKCS#8 document around nonsense, and the
        // failure would surface at connect time instead of here.
        let bytes = samples::pem("RSA PRIVATE KEY", &[0x02, 0x01, 0x00]);
        assert!(matches!(
            ImportedKey::from_bytes(bytes),
            Err(VaultError::NotAPrivateKey)
        ));

        let bytes = samples::pem("EC PRIVATE KEY", &[0x02, 0x01, 0x00]);
        assert!(matches!(
            ImportedKey::from_bytes(bytes),
            Err(VaultError::NotAPrivateKey)
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

/// The containers `ssh-keygen` actually writes, read as real files.
///
/// Every key here is generated by the system's own `ssh-keygen` inside the
/// test process and destroyed with the temporary directory it was written to.
/// No key file is committed — `CLAUDE.md` §9 forbids it, and `.gitignore`
/// refuses `*.pem` and `*.key` — and a hand-written fixture would only ever be
/// evidence about the fixture. What has to be true is that Remoter reads the
/// files administrators have, so the files under test are made by the tool
/// that made theirs.
///
/// The proof that a re-enveloped key is still the same key is `ssh-keygen -y`,
/// which derives the public half from a private key file. Running it on the
/// original and on what the vault stored must produce the same public key: that
/// is one assertion covering both "a real SSH implementation can read this"
/// and "no key byte changed on the way through".
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod real_keys {
    use std::path::Path;
    use std::process::Command;

    use super::*;

    /// Runs `ssh-keygen`, returning its stdout.
    ///
    /// Absence of the tool is a hard failure rather than a skip: a test that
    /// quietly does nothing on the machine where it matters is worse than no
    /// test, and `ssh-keygen` ships with every OpenSSH client.
    fn ssh_keygen(args: &[&str]) -> Vec<u8> {
        let output = Command::new("ssh-keygen")
            .args(args)
            .output()
            .expect("ssh-keygen must be on PATH: these tests read real key files, not fixtures");
        assert!(
            output.status.success(),
            "ssh-keygen {args:?} failed: {}",
            // A generation diagnostic, never key material.
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    /// Generates a key pair with `ssh-keygen` and returns the private key file.
    ///
    /// `passphrase` is the empty string for an unencrypted key, exactly as
    /// `-N ""` means on the command line.
    fn generate(dir: &Path, name: &str, passphrase: &str, extra: &[&str]) -> Vec<u8> {
        let path = dir.join(name);
        let path = path.to_str().expect("a temporary path is valid UTF-8");
        let mut args = vec!["-q", "-C", "remoter-test", "-N", passphrase, "-f", path];
        args.extend_from_slice(extra);
        ssh_keygen(&args);
        std::fs::read(path).unwrap()
    }

    /// The public half `ssh-keygen` derives from a private key file, which is
    /// the identity the server will check.
    fn public_half(dir: &Path, name: &str, key: &[u8]) -> Vec<u8> {
        let path = dir.join(name);
        std::fs::write(&path, key).unwrap();
        // `ssh-keygen -y` refuses a key file other users could read, exactly as
        // the SSH client does. The file written here is made private so the
        // tool will read it; `ssh-keygen` does this for the ones it writes.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let path = path.to_str().expect("a temporary path is valid UTF-8");
        // The comment is not part of the identity and `-y` does not print one,
        // so the whole line can be compared.
        ssh_keygen(&["-y", "-f", path])
    }

    /// The same, for a key file whose own container is enciphered.
    ///
    /// `-P` is how `ssh-keygen` takes the passphrase without a terminal. It is
    /// a test passphrase for a key generated seconds earlier and thrown away
    /// seconds later; no real one ever goes on a command line.
    fn public_half_of_locked(dir: &Path, name: &str, key: &[u8], passphrase: &str) -> Vec<u8> {
        let path = dir.join(name);
        std::fs::write(&path, key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let path = path.to_str().expect("a temporary path is valid UTF-8");
        ssh_keygen(&["-y", "-P", passphrase, "-f", path])
    }

    #[test]
    fn an_aws_style_pkcs1_rsa_pem_is_accepted_and_is_still_the_same_key() {
        // This is the file AWS EC2 hands out with every key pair it generates,
        // and what `ssh-keygen` wrote by default until OpenSSH 7.8. It used to
        // be refused outright.
        let dir = tempfile::tempdir().unwrap();
        let original = generate(
            dir.path(),
            "aws.pem",
            "",
            &["-t", "rsa", "-b", "2048", "-m", "PEM"],
        );
        assert!(
            original.starts_with(b"-----BEGIN RSA PRIVATE KEY-----"),
            "ssh-keygen -m PEM did not write a PKCS#1 container"
        );

        let key = ImportedKey::from_bytes(original.clone()).unwrap();
        assert_eq!(key.format(), KeyFormat::Pkcs8);
        assert!(!key.is_encrypted());

        let stored = key.material().unwrap().expose_secret();
        assert!(
            stored.starts_with(b"-----BEGIN PRIVATE KEY-----"),
            "the vault stored something that is not a PKCS#8 document"
        );

        assert_eq!(
            public_half(dir.path(), "stored", stored),
            public_half(dir.path(), "original", &original),
            "the re-enveloped key is not the key that went in"
        );
    }

    #[test]
    fn a_sec1_ec_pem_is_accepted_and_is_still_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let original = generate(
            dir.path(),
            "ec.pem",
            "",
            &["-t", "ecdsa", "-b", "256", "-m", "PEM"],
        );
        assert!(
            original.starts_with(b"-----BEGIN EC PRIVATE KEY-----"),
            "ssh-keygen -m PEM -t ecdsa did not write a SEC 1 container"
        );

        let key = ImportedKey::from_bytes(original.clone()).unwrap();
        assert_eq!(key.format(), KeyFormat::Pkcs8);
        assert!(!key.is_encrypted());

        let stored = key.material().unwrap().expose_secret();
        assert!(stored.starts_with(b"-----BEGIN PRIVATE KEY-----"));
        assert_eq!(
            public_half(dir.path(), "stored", stored),
            public_half(dir.path(), "original", &original),
            "the re-enveloped key is not the key that went in"
        );
    }

    #[test]
    fn every_container_ssh_keygen_writes_is_recognised() {
        let dir = tempfile::tempdir().unwrap();
        let cases: [(&str, &str, &[&str], KeyFormat, bool); 8] = [
            // (name, passphrase, ssh-keygen arguments, stored as, encrypted)
            ("openssh", "", &["-t", "ed25519"], KeyFormat::OpenSsh, false),
            (
                "openssh-locked",
                "correct horse battery staple",
                &["-t", "ed25519"],
                KeyFormat::OpenSsh,
                true,
            ),
            (
                "pkcs8",
                "",
                &["-t", "rsa", "-b", "2048", "-m", "PKCS8"],
                KeyFormat::Pkcs8,
                false,
            ),
            (
                "pkcs8-locked",
                "correct horse battery staple",
                &["-t", "rsa", "-b", "2048", "-m", "PKCS8"],
                KeyFormat::Pkcs8,
                true,
            ),
            (
                "pkcs1",
                "",
                &["-t", "rsa", "-b", "2048", "-m", "PEM"],
                KeyFormat::Pkcs8,
                false,
            ),
            (
                "sec1",
                "",
                &["-t", "ecdsa", "-b", "256", "-m", "PEM"],
                KeyFormat::Pkcs8,
                false,
            ),
            // The two that were refused outright. They are reported under the
            // container they will be stored in and as encrypted, which is what
            // the interface reads to decide whether to ask for a passphrase.
            (
                "pkcs1-locked",
                "correct horse battery staple",
                &["-t", "rsa", "-b", "2048", "-m", "PEM"],
                KeyFormat::Pkcs8,
                true,
            ),
            (
                "sec1-locked",
                "correct horse battery staple",
                &["-t", "ecdsa", "-b", "256", "-m", "PEM"],
                KeyFormat::Pkcs8,
                true,
            ),
        ];

        for (name, passphrase, extra, format, encrypted) in cases {
            let bytes = generate(dir.path(), name, passphrase, extra);
            let key = ImportedKey::from_bytes(bytes)
                .unwrap_or_else(|err| panic!("{name} was refused: {err}"));
            assert_eq!(key.format(), format, "for {name}");
            assert_eq!(key.is_encrypted(), encrypted, "for {name}");
        }
    }

    #[test]
    fn a_passphrase_protected_legacy_pem_opens_and_is_still_the_same_key() {
        // The file the report was about. `ssh-keygen -m PEM -N <passphrase>`
        // writes PKCS#1 with an RFC 1421 `DEK-Info` header, which is also what
        // an AWS EC2 `.pem` becomes the moment its owner protects it. The
        // identification step has no passphrase — it is the step that runs so
        // the interface knows to ask for one — so it reports the key as
        // encrypted and leaves it locked, and `unlock` is where the passphrase
        // arrives.
        //
        // Both containers are exercised: `ssh-keygen` reads an enciphered
        // PKCS#1 and `russh` does too, but neither reads an enciphered SEC 1,
        // so the EC arm is a case that works here and nowhere downstream.
        let dir = tempfile::tempdir().unwrap();
        let passphrase = "correct horse battery staple";

        for (name, extra) in [
            ("locked-rsa.pem", ["-t", "rsa", "-b", "2048", "-m", "PEM"]),
            ("locked-ec.pem", ["-t", "ecdsa", "-b", "256", "-m", "PEM"]),
        ] {
            let bytes = generate(dir.path(), name, passphrase, &extra);
            assert!(
                String::from_utf8_lossy(&bytes).contains("DEK-Info:"),
                "ssh-keygen did not write a legacy encrypted PEM for {name}"
            );

            let locked = ImportedKey::from_bytes(bytes.clone()).unwrap();
            assert!(locked.is_locked(), "{name}");
            assert!(locked.is_encrypted(), "{name}");

            // The wrong passphrase is not a corrupt file, and does not claim
            // to be one.
            assert!(
                matches!(
                    locked.unlock(b"hunter2"),
                    Err(VaultError::KeyPassphraseRejected)
                ),
                "{name}: a wrong passphrase must say so"
            );

            let opened = locked.unlock(passphrase.as_bytes()).unwrap();
            assert!(!opened.is_locked(), "{name}");
            assert!(
                !opened.is_encrypted(),
                "{name}: what is stored is no longer enciphered"
            );
            assert_eq!(opened.format(), KeyFormat::Pkcs8, "{name}");

            let stored = opened.material().unwrap().expose_secret();
            assert!(
                stored.starts_with(b"-----BEGIN PRIVATE KEY-----"),
                "{name}: the vault stored something that is not a PKCS#8 document"
            );

            // The assertion that matters: a real SSH implementation reads the
            // document that came out, and it is the same identity a server
            // would have checked for the file that went in.
            assert_eq!(
                public_half(dir.path(), "stored", stored),
                public_half_of_locked(dir.path(), "original", &bytes, passphrase),
                "{name}: the deciphered key is not the key that went in"
            );
        }
    }

    #[test]
    fn no_refusal_and_no_debug_line_quotes_the_file() {
        // The likeliest way to leak a key from this module is a message that
        // repeats what it could not read.
        let dir = tempfile::tempdir().unwrap();
        let bytes = generate(
            dir.path(),
            "leak.pem",
            "correct horse battery staple",
            &["-t", "rsa", "-b", "2048", "-m", "PEM"],
        );

        // The refusal a wrong passphrase earns, which is the one whose error is
        // built while the ciphertext and the passphrase are both in hand.
        let locked = ImportedKey::from_bytes(bytes.clone()).unwrap();
        let error = locked.unlock(b"hunter2").unwrap_err();
        let rendered = format!("{error:?} {error} {locked:?}");
        assert!(
            !rendered.contains("hunter2"),
            "the passphrase reached the error"
        );
        for line in String::from_utf8_lossy(&bytes)
            .lines()
            .filter(|line| !line.starts_with("-----") && !line.contains(':') && !line.is_empty())
        {
            assert!(!rendered.contains(line), "a key fragment reached the error");
        }

        // And the refusal for a file that is not a key at all, which is built
        // from the same code path with nothing decipherable in it.
        let error =
            ImportedKey::from_bytes(b"ssh-rsa AAAAB3 nobody@example\n".to_vec()).unwrap_err();
        assert!(matches!(error, VaultError::NotAPrivateKey));

        let accepted = generate(
            dir.path(),
            "shown.pem",
            "",
            &["-t", "rsa", "-b", "2048", "-m", "PEM"],
        );
        let key = ImportedKey::from_bytes(accepted).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"));
        for line in String::from_utf8_lossy(key.material().unwrap().expose_secret())
            .lines()
            .filter(|line| !line.starts_with("-----"))
        {
            assert!(
                !rendered.contains(line),
                "the normalised key material reached Debug"
            );
        }
    }
}
