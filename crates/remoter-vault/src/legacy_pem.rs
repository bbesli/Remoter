//! Deciphering a legacy PEM body, so that a passphrase-protected `.pem` can be
//! imported at all.
//!
//! A PEM block carrying the RFC 1421 §4.6.1.3 headers
//!
//! ```text
//! Proc-Type: 4,ENCRYPTED
//! DEK-Info: AES-128-CBC,715F1D4A84633FF2726A9642A2672277
//! ```
//!
//! holds ciphertext where the DER would be. This is what `ssh-keygen -m PEM`
//! writes when it is given a passphrase, and what `openssl rsa -aes256` wrote
//! until OpenSSL 3 — which between them is most of the passphrase-protected
//! `.pem` files that exist. (OpenSSL 3 writes a PKCS#8
//! `EncryptedPrivateKeyInfo` for that command instead, headers and all; those
//! arrive in [`crate::pkcs8`], not here.) Until this module existed the vault
//! refused every one of them, and
//! the refusal is what a user reads as ".pem is not supported": the message
//! arrives at the moment the file is chosen, before anything has asked for a
//! passphrase, so nothing on screen suggests the key is a passphrase away from
//! working.
//!
//! The scheme is not PKCS#5 and it is not in any RFC. RFC 1421 defines the
//! headers; the key derivation is OpenSSL's `EVP_BytesToKey`, which nothing
//! standardises and every implementation copies from OpenSSL:
//!
//! - the *salt* is the first eight bytes of the IV the `DEK-Info` line carries;
//! - the key is `MD5(passphrase ‖ salt)`, then `MD5(previous ‖ passphrase ‖
//!   salt)` for as many blocks as the cipher's key length needs;
//! - the body is CBC with that key and the whole IV, PKCS#7 padded.
//!
//! One iteration of MD5 is a weak derivation by any modern standard, and that
//! is a fact about the files, not a choice made here: reading one is the only
//! way to open a key someone already has. Nothing in this module *writes* the
//! format, and what comes out of it is re-enveloped as PKCS#8 and sealed under
//! the vault's own XChaCha20-Poly1305 — so the weak derivation protects the
//! key for exactly as long as it takes to import it, and never again.
//!
//! Ciphers read here are AES-128, AES-192 and AES-256 in CBC mode. DES-EDE3-CBC
//! — OpenSSL's default before 1.1 — is named and refused rather than guessed
//! at, because supporting it means adding a DES implementation to a crate that
//! otherwise has none, and the remedy (`ssh-keygen -p` over a copy) is one the
//! user can carry out. See [`VaultError::UnsupportedKeyCipher`].
//!
//! Everything that variant carries from this module is a whole clause, not a
//! cipher name, because a `DEK-Info` line has more than one way of being
//! unreadable: it can name a cipher nothing here implements, or it can be
//! damaged — no comma, an initialisation vector that is not sixteen bytes of
//! hexadecimal, a `Proc-Type` with no `DEK-Info` under it at all. Those used to
//! come back as [`VaultError::NotAPrivateKey`], which the interface renders as
//! "that file is not a private key" — said about a file that *is* one, with one
//! mangled line in it. The interface reads the clause into a single sentence
//! naming the file, so each defect says what it is.
//!
//! Every buffer here holds key material or something derived from it and is
//! `Zeroizing`, including the intermediate MD5 blocks: a derivation block is
//! half of the key it produced.

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use md5::{Digest, Md5};
use zeroize::Zeroizing;

use crate::error::VaultError;

/// AES's block size, which is also the length of the IV a `DEK-Info` line
/// carries for every cipher this module reads.
const IV_LEN: usize = 16;

/// `EVP_BytesToKey` salts with the first eight bytes of the IV.
const SALT_LEN: usize = 8;

/// One MD5 block: the unit the derivation below produces key bytes in.
const MD5_LEN: usize = 16;

/// A cipher a `DEK-Info` line can name and this build can read.
///
/// Every one is CBC, which is all the format ever used; the variants are named
/// for the key width because that is the only thing that differs between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cipher {
    Aes128,
    Aes192,
    Aes256,
}

/// Reads the cipher out of a `DEK-Info` name.
///
/// A name this build cannot read is reported as itself where the name is one of
/// the handful that actually occur, and as "a cipher this build does not
/// recognise" otherwise. The distinction is deliberate: the string comes out of
/// a file someone else may have written, and echoing arbitrary bytes from it
/// into an error message is how a file gets to choose what the interface says.
///
/// Every refusal is a whole clause rather than a bare name, because the
/// interface reads it into one sentence — "Remoter cannot read the encrypted
/// container in <file>: <clause>" — and the things that can be wrong with an
/// RFC 1421 header are not all ciphers. See [`check_readable`].
fn cipher_for(name: &str) -> Result<Cipher, VaultError> {
    match name.to_ascii_uppercase().as_str() {
        "AES-128-CBC" => Ok(Cipher::Aes128),
        "AES-192-CBC" => Ok(Cipher::Aes192),
        "AES-256-CBC" => Ok(Cipher::Aes256),
        "DES-EDE3-CBC" => Err(VaultError::UnsupportedKeyCipher(
            "its DEK-Info header names DES-EDE3-CBC, and this build deciphers only AES-128, \
             AES-192 and AES-256 in CBC mode",
        )),
        "DES-CBC" => Err(VaultError::UnsupportedKeyCipher(
            "its DEK-Info header names DES-CBC, and this build deciphers only AES-128, \
             AES-192 and AES-256 in CBC mode",
        )),
        "RC2-CBC" | "RC2-40-CBC" | "RC2-64-CBC" => Err(VaultError::UnsupportedKeyCipher(
            "its DEK-Info header names RC2-CBC, and this build deciphers only AES-128, \
             AES-192 and AES-256 in CBC mode",
        )),
        _ => Err(VaultError::UnsupportedKeyCipher(
            "its DEK-Info header names a cipher this build does not recognise",
        )),
    }
}

/// OpenSSL's `EVP_BytesToKey` with MD5 and one iteration.
///
/// `D_1 = MD5(passphrase ‖ salt)`, `D_i = MD5(D_(i-1) ‖ passphrase ‖ salt)`,
/// and the key is the concatenation truncated to `N`.
///
/// The size is a const parameter rather than a runtime length so that the array
/// each cipher's constructor wants comes straight out of here: a `Vec` would
/// have to be re-checked against that size, and a length check that cannot fail
/// is a panic path nobody ever reads.
fn derive_key<const N: usize>(passphrase: &[u8], salt: &[u8]) -> Zeroizing<[u8; N]> {
    let mut key = Zeroizing::new([0u8; N]);
    let mut filled = 0;
    let mut previous: Option<Zeroizing<[u8; MD5_LEN]>> = None;

    while filled < N {
        let mut digest = Md5::new();
        if let Some(block) = &previous {
            digest.update(block.as_slice());
        }
        digest.update(passphrase);
        digest.update(salt);
        let block = Zeroizing::new(<[u8; MD5_LEN]>::from(digest.finalize()));

        let wanted = N.saturating_sub(filled).min(MD5_LEN);
        if let (Some(target), Some(source)) = (
            key.get_mut(filled..filled.saturating_add(wanted)),
            block.get(..wanted),
        ) {
            target.copy_from_slice(source);
        }
        filled = filled.saturating_add(wanted);
        previous = Some(block);
    }
    key
}

/// The clause for a `DEK-Info` whose initialisation vector is not sixteen
/// bytes of hexadecimal.
///
/// A damaged header is not a file that fails to be a private key: the banner,
/// the `Proc-Type` line and the body are all still there, and calling it "not a
/// private key" sends someone looking for a different file when what they have
/// is the right one with a mangled line in it. Very often the mangling happened
/// in transit — a mail client rewrapping the lines, a paste that lost a
/// character — and knowing *which* line is damaged is what makes fetching a
/// clean copy the obvious next step.
const IV_MALFORMED: &str = "its DEK-Info header's initialisation vector is not sixteen bytes of \
                            hexadecimal, so the header has been damaged";

/// The clause for a `DEK-Info` that is not a name, a comma and an IV at all.
const DEK_INFO_MALFORMED: &str = "its DEK-Info header is not a cipher name, a comma and a \
                                  hexadecimal initialisation vector, so the header has been \
                                  damaged";

/// The clause for a body that cannot be a whole number of cipher blocks.
const BODY_NOT_BLOCKS: &str = "its enciphered body is not a whole number of cipher blocks, so \
                               the file has been truncated or damaged";

/// The clause for a block whose `Proc-Type` says enciphered with no `DEK-Info`
/// beneath it. Not produced here — the header never reaches this module — but
/// written here with its siblings, because the interface renders all of them
/// through the same sentence.
pub(crate) const NO_DEK_INFO: &str = "its Proc-Type header says the body is enciphered, but no \
                                      DEK-Info line follows it to say what it was enciphered \
                                      with, so the header has been damaged";

/// Parses the hexadecimal IV a `DEK-Info` line carries.
fn parse_iv(hex: &str) -> Result<[u8; IV_LEN], VaultError> {
    let decoded = data_encoding::HEXUPPER
        .decode(hex.to_ascii_uppercase().as_bytes())
        .map_err(|_| VaultError::UnsupportedKeyCipher(IV_MALFORMED))?;
    decoded
        .try_into()
        .map_err(|_| VaultError::UnsupportedKeyCipher(IV_MALFORMED))
}

/// Reads a `DEK-Info` value into the cipher and IV it names.
fn parse_dek_info(dek_info: &str) -> Result<(Cipher, [u8; IV_LEN]), VaultError> {
    let (name, iv) = dek_info
        .split_once(',')
        .ok_or(VaultError::UnsupportedKeyCipher(DEK_INFO_MALFORMED))?;
    Ok((cipher_for(name.trim())?, parse_iv(iv.trim())?))
}

/// Whether this build could decipher such a body, given the passphrase.
///
/// Called while the file is being identified, which is before any passphrase
/// exists. Everything it checks — the cipher's name, the shape of the header,
/// the length of the body — is written in the clear beside the ciphertext and
/// is knowable then, and saying so at that moment is the difference between
/// naming what is wrong with the file and asking for a passphrase only to
/// refuse the key once it has been typed.
///
/// The body's length is checked here and not only in [`decipher`] for exactly
/// that reason: a truncated file is a fact about the file, and discovering it
/// after the passphrase is typed puts the blame on the passphrase.
pub(crate) fn check_readable(dek_info: &str, body: &[u8]) -> Result<(), VaultError> {
    parse_dek_info(dek_info)?;
    check_block_aligned(body)
}

/// Refuses a body that cannot be the output of a CBC cipher.
fn check_block_aligned(body: &[u8]) -> Result<(), VaultError> {
    if body.is_empty() || body.len() % IV_LEN != 0 {
        return Err(VaultError::UnsupportedKeyCipher(BODY_NOT_BLOCKS));
    }
    Ok(())
}

/// Deciphers a legacy PEM body.
///
/// `dek_info` is the value of the `DEK-Info:` header — a cipher name, a comma
/// and a hexadecimal IV — and `body` is the base64 beneath it, decoded.
///
/// # Errors
///
/// [`VaultError::UnsupportedKeyCipher`] when the header names a cipher this
/// build cannot read, when the header itself is damaged, or when the body is
/// not a whole number of blocks — each carrying the clause that says which;
/// [`VaultError::KeyPassphraseRejected`] when the deciphered body does not
/// carry valid padding, which is what a wrong passphrase looks like — this
/// container has no authentication tag, so a wrong passphrase and a corrupt
/// body are the same observation and are reported as the likelier of the two.
pub(crate) fn decipher(
    dek_info: &str,
    passphrase: &[u8],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let (cipher, iv) = parse_dek_info(dek_info)?;
    let salt = iv.get(..SALT_LEN).ok_or(VaultError::NotAPrivateKey)?;
    check_block_aligned(body)?;

    let mut buffer = Zeroizing::new(body.to_vec());

    // The key is derived at the width the cipher takes, so each arm hands its
    // constructor an array of exactly the right size and no length check is
    // needed anywhere.
    let plaintext_len = match cipher {
        Cipher::Aes128 => {
            let key = derive_key::<16>(passphrase, salt);
            cbc::Decryptor::<Aes128>::new(&(*key).into(), &iv.into())
                .decrypt_padded::<Pkcs7>(buffer.as_mut_slice())
        }
        Cipher::Aes192 => {
            let key = derive_key::<24>(passphrase, salt);
            cbc::Decryptor::<Aes192>::new(&(*key).into(), &iv.into())
                .decrypt_padded::<Pkcs7>(buffer.as_mut_slice())
        }
        Cipher::Aes256 => {
            let key = derive_key::<32>(passphrase, salt);
            cbc::Decryptor::<Aes256>::new(&(*key).into(), &iv.into())
                .decrypt_padded::<Pkcs7>(buffer.as_mut_slice())
        }
    }
    .map_err(|_| VaultError::KeyPassphraseRejected)?
    .len();

    // `Zeroize for Vec` covers the whole capacity, so the padding bytes that
    // fall off here are still wiped when the buffer drops.
    buffer.truncate(plaintext_len);
    Ok(buffer)
}

/// Enciphers a body the way `openssl` and `ssh-keygen` do for a PEM with a
/// `DEK-Info: AES-128-CBC` header: the key from [`derive_key`] with the first
/// eight octets of the IV as salt, CBC, PKCS#7 padding.
///
/// Tests only. Remoter reads these containers and never writes one; this
/// exists so a test can build the exact file another platform's tools write.
#[cfg(test)]
pub(crate) fn encipher_for_tests(body: &[u8], passphrase: &[u8], iv: [u8; IV_LEN]) -> Vec<u8> {
    use cbc::cipher::BlockModeEncrypt as _;
    let salt = iv.get(..SALT_LEN).unwrap_or_default();
    let key = derive_key::<16>(passphrase, salt);
    // PKCS#7 always adds between one and a whole block of padding.
    let mut buffer = vec![0u8; (body.len() / IV_LEN + 1) * IV_LEN];
    if let Some(start) = buffer.get_mut(..body.len()) {
        start.copy_from_slice(body);
    }
    cbc::Encryptor::<Aes128>::new(&(*key).into(), &iv.into())
        .encrypt_padded::<Pkcs7>(&mut buffer, body.len())
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;

    /// The published `EVP_BytesToKey` answer for an empty salt is the plain
    /// MD5 of the passphrase, which is a value anyone can check by hand:
    /// `md5("password") = 5f4dcc3b5aa765d61d8327deb882cf99`.
    #[test]
    fn the_derivation_starts_at_md5_of_the_passphrase() {
        let key = derive_key::<16>(b"password", b"");
        assert_eq!(
            data_encoding::HEXLOWER.encode(&*key),
            "5f4dcc3b5aa765d61d8327deb882cf99"
        );
    }

    /// Longer keys chain, and the first block is unchanged by asking for more:
    /// `D_1` does not depend on how many blocks follow it.
    #[test]
    fn a_longer_key_extends_the_shorter_one() {
        let short = derive_key::<16>(b"password", b"12345678");
        let long = derive_key::<32>(b"password", b"12345678");
        assert_eq!(&long[..16], &short[..]);
        // A width that is not a whole number of MD5 blocks is truncated, not
        // rounded up: AES-192 takes twenty-four bytes of a thirty-two byte
        // chain.
        let middle = derive_key::<24>(b"password", b"12345678");
        assert_eq!(&middle[..], &long[..24]);
    }

    /// The clause a refusal carries, or a marker the assertion can print.
    fn clause(result: Result<impl Sized, VaultError>) -> String {
        match result {
            Err(VaultError::UnsupportedKeyCipher(clause)) => clause.to_owned(),
            Err(other) => format!("<{other}>"),
            Ok(_) => String::from("<accepted>"),
        }
    }

    #[test]
    fn an_unreadable_cipher_is_named_rather_than_guessed_at() {
        assert!(
            clause(cipher_for("DES-EDE3-CBC")).contains("DES-EDE3-CBC"),
            "{}",
            clause(cipher_for("DES-EDE3-CBC"))
        );
        // Whatever the file said, the error carries a fixed string: a message
        // built from the file's own bytes is a message the file wrote.
        let unknown = clause(cipher_for("PANTHER-9000-CBC"));
        assert!(!unknown.contains("PANTHER"), "{unknown}");
        assert!(unknown.contains("does not recognise"), "{unknown}");
        assert!(matches!(cipher_for("aes-256-cbc"), Ok(Cipher::Aes256)));
    }

    /// A damaged RFC 1421 header used to come back as `NotAPrivateKey`, which
    /// the interface renders as "that file is not a private key" — said about a
    /// file that is a private key, with one mangled line in it. Each defect now
    /// names itself, and none of them is a wrong passphrase either.
    #[test]
    fn a_damaged_header_says_what_is_damaged() {
        let missing_iv = clause(decipher("AES-128-CBC", b"x", &[0; 16]));
        assert!(missing_iv.contains("DEK-Info"), "{missing_iv}");
        assert!(missing_iv.contains("comma"), "{missing_iv}");

        let bad_iv = clause(decipher("AES-128-CBC,zzzz", b"x", &[0; 16]));
        assert!(bad_iv.contains("initialisation vector"), "{bad_iv}");
        assert!(bad_iv.contains("hexadecimal"), "{bad_iv}");

        // An IV of the right alphabet but the wrong length is the same defect.
        let short_iv = clause(decipher("AES-128-CBC,0123", b"x", &[0; 16]));
        assert!(short_iv.contains("sixteen bytes"), "{short_iv}");

        // A body that is not a whole number of blocks never reached a cipher.
        let truncated = clause(decipher(
            "AES-128-CBC,715F1D4A84633FF2726A9642A2672277",
            b"x",
            &[0; 17],
        ));
        assert!(truncated.contains("truncated"), "{truncated}");
    }

    /// And all of it is knowable before a passphrase exists, which is the whole
    /// point of checking it at the moment the file is chosen.
    #[test]
    fn every_header_defect_is_refused_without_a_passphrase() {
        let good_iv = "715F1D4A84633FF2726A9642A2672277";
        assert!(check_readable(&format!("AES-128-CBC,{good_iv}"), &[0; 16]).is_ok());

        for (dek_info, body, expected) in [
            ("AES-128-CBC", &[0u8; 16][..], "comma"),
            ("AES-128-CBC,zzzz", &[0; 16][..], "hexadecimal"),
            (
                "DES-EDE3-CBC,0123456789ABCDEF0123456789ABCDEF",
                &[0; 16][..],
                "DES-EDE3-CBC",
            ),
            (
                "AES-128-CBC,715F1D4A84633FF2726A9642A2672277",
                &[0; 17][..],
                "truncated",
            ),
        ] {
            let said = clause(check_readable(dek_info, body));
            assert!(said.contains(expected), "for {dek_info}: {said}");
        }
    }
}
