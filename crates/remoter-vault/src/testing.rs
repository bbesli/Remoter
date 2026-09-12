//! Key containers for this crate's own tests to read.
//!
//! Behind the `test-fixtures` feature, which only this crate's dev-dependency
//! on itself turns on — the same mechanism `insecure-test-kdf` uses, and for
//! the same reason: an integration test lives outside the crate and cannot see
//! a `#[cfg(test)]` item, and a fixture builder compiled into a shipped binary
//! is a fixture builder someone can call.
//!
//! **Nothing here produces a usable key.** The containers are well-formed and
//! the enciphering is real, so a passphrase check has something true to answer;
//! what sits where the key material belongs is meaningless bytes. The
//! repository holds no key file and `CLAUDE.md` §9 forbids committing one even
//! for a test, so every fixture the suite reads is built at the moment it runs.

/// An encrypted OpenSSH container that `passphrase` opens.
///
/// `aes256-ctr` with bcrypt-pbkdf, which is what `ssh-keygen` writes today. The
/// round count is deliberately small: this is a fixture, not a key, and the
/// derivation runs once per assertion.
///
/// What proves this is shaped like a real one is not this function but
/// `tests/key_passphrase.rs`, which runs the same assertions over a container
/// `ssh-keygen` itself wrote.
#[must_use]
pub fn encrypted_openssh_key(passphrase: &[u8]) -> Vec<u8> {
    let check = 0x5EED_1234;
    let body =
        crate::openssh::fixtures::container("aes256-ctr", "bcrypt", passphrase, 4, (check, check));
    pem("OPENSSH PRIVATE KEY", &body)
}

/// An OpenSSH container declaring `cipher`, for the ciphers this build does not
/// decipher.
///
/// The body is not actually enciphered under that name — nothing here can run
/// AES-GCM or OpenSSH's ChaCha20-Poly1305, which is the whole point — so this
/// is a container the vault must refuse to answer for rather than one it must
/// open.
#[must_use]
pub fn openssh_key_under(cipher: &str) -> Vec<u8> {
    pem(
        "OPENSSH PRIVATE KEY",
        &crate::openssh::fixtures::container(cipher, "bcrypt", b"anything", 4, (1, 1)),
    )
}

/// An unencrypted OpenSSH container.
#[must_use]
pub fn plain_openssh_key() -> Vec<u8> {
    pem(
        "OPENSSH PRIVATE KEY",
        &crate::openssh::fixtures::container("none", "none", b"", 0, (1, 1)),
    )
}

/// A PKCS#8 `PrivateKeyInfo` for an Ed25519 key (RFC 8410 §7), armoured.
///
/// Version 0, the `id-Ed25519` OID 1.3.101.112, and a seed of zeros where the
/// private scalar belongs — a real structure around no secret at all, which is
/// what a fixture may be and a key file may not.
#[must_use]
pub fn plain_pkcs8_key() -> Vec<u8> {
    pem("PRIVATE KEY", &private_key_info())
}

/// The same document, enciphered so that `passphrase` opens it.
///
/// PBES2 with PBKDF2-HMAC-SHA-256 over AES-256-CBC, which is what
/// `ssh-keygen -m PKCS8` and `openssl pkcs8 -topk8` write by default.
#[must_use]
pub fn encrypted_pkcs8_key(passphrase: &[u8]) -> Vec<u8> {
    pem(
        "ENCRYPTED PRIVATE KEY",
        &crate::pkcs8::fixtures::encrypted(&private_key_info(), passphrase),
    )
}

/// The Ed25519 `PrivateKeyInfo` both of the above wrap.
fn private_key_info() -> Vec<u8> {
    let mut der = vec![
        0x02, 0x01, 0x00, // version 0
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, // AlgorithmIdentifier 1.3.101.112
        0x04, 0x22, 0x04, 0x20, // OCTET STRING(34) { OCTET STRING(32) }
    ];
    der.extend_from_slice(&[0u8; 32]);
    crate::pkcs8::fixtures::seq(&[&der])
}

/// A PEM document with `body` base64-encoded inside `label`.
fn pem(label: &str, body: &[u8]) -> Vec<u8> {
    let encoded = data_encoding::BASE64.encode(body);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out.into_bytes()
}
