//! Deciding whether a passphrase opens an OpenSSH private key container.
//!
//! The vault stores an encrypted OpenSSH key exactly as it stands, ciphertext
//! and all, with the passphrase beside it. Nothing about that arrangement
//! checks the passphrase, and until this module existed nothing did: a wrong
//! one was accepted, sealed, and discovered at connect time as "the server
//! rejected these credentials" — said about a key no server had seen, after the
//! user had every reason to believe the import had worked.
//!
//! So the passphrase is tried here, at the moment it is offered. Only the first
//! cipher block of the private section is deciphered, because that is where the
//! answer is.
//!
//! # The container
//!
//! `PROTOCOL.key` in the OpenSSH distribution, which is the only specification
//! of this format there is:
//!
//! ```text
//! byte[15]  AUTH_MAGIC = "openssh-key-v1\0"
//! string    ciphername
//! string    kdfname
//! string    kdfoptions      -- for "bcrypt": string salt, uint32 rounds
//! uint32    number of keys N
//! string    publickey1  ..  publickeyN
//! string    encrypted, padded list of private keys
//! ```
//!
//! and that last string, once deciphered, begins:
//!
//! ```text
//! uint32    checkint
//! uint32    checkint        -- the same value again
//! string    privatekey1
//! string    comment1
//! ...
//! ```
//!
//! A `string` is a big-endian `u32` length and that many bytes (RFC 4251 §5).
//!
//! **The two check integers are the whole check.** OpenSSH writes one random
//! value into both, and `sshkey_parse_private2` compares them after deciphering
//! for exactly the reason this module reads them: none of the ciphers the
//! format uses here authenticates the plaintext, so the duplicated word is what
//! tells a correct passphrase from a wrong one. Two words that differ mean the
//! passphrase did not open the container; the chance of a wrong passphrase
//! producing two equal words anyway is one in 2^32.
//!
//! # What can be checked
//!
//! The key is derived with bcrypt-pbkdf, which is the only `kdfname` OpenSSH
//! has ever written for an encrypted key, and the ciphers read here are AES in
//! CTR and CBC mode at all three key widths. That is what `ssh-keygen` writes —
//! `aes256-ctr` today, `aes256-cbc` in older releases — and what PuTTY exports.
//!
//! Everything else is reported as uncheckable rather than guessed at: the
//! AEAD ciphers `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com` and
//! `chacha20-poly1305@openssh.com`, which `ssh-keygen -Z` can be asked for, and
//! `3des-cbc`, which would mean a DES implementation in a crate that has none.
//! An uncheckable container is refused, not accepted on trust — see
//! [`VaultError::KeyPassphraseUncheckable`].
//!
//! Every buffer here holds key material or something derived from it and is
//! `Zeroizing`.

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, StreamCipher};
use zeroize::Zeroizing;

use crate::error::VaultError;

/// The container magic, including its terminating NUL.
pub(crate) const MAGIC: &[u8] = b"openssh-key-v1\0";

/// AES's block size, and the length of the initialisation vector every cipher
/// read here takes.
const BLOCK: usize = 16;

/// The two check integers, which is all of the plaintext this module reads.
const CHECK_BYTES: usize = 8;

/// A cipher an OpenSSH container can name and this build can decipher.
///
/// The variants carry the key width and the mode, which is the only thing that
/// differs between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cipher {
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
}

impl Cipher {
    /// The derived key length in bytes; the initialisation vector is always one
    /// AES block.
    const fn key_len(self) -> usize {
        match self {
            Self::Aes128Ctr | Self::Aes128Cbc => 16,
            Self::Aes192Ctr | Self::Aes192Cbc => 24,
            Self::Aes256Ctr | Self::Aes256Cbc => 32,
        }
    }
}

/// The clause for a container whose cipher this build cannot run.
///
/// Named families rather than the file's own bytes: the string comes out of a
/// file someone else may have written, and echoing it into a message is how a
/// file gets to choose what the interface says.
fn cipher_for(name: &[u8]) -> Result<Cipher, VaultError> {
    match name {
        b"aes128-ctr" => Ok(Cipher::Aes128Ctr),
        b"aes192-ctr" => Ok(Cipher::Aes192Ctr),
        b"aes256-ctr" => Ok(Cipher::Aes256Ctr),
        b"aes128-cbc" => Ok(Cipher::Aes128Cbc),
        b"aes192-cbc" => Ok(Cipher::Aes192Cbc),
        b"aes256-cbc" => Ok(Cipher::Aes256Cbc),
        b"aes128-gcm@openssh.com" | b"aes256-gcm@openssh.com" => {
            Err(VaultError::KeyPassphraseUncheckable(
                "it is an OpenSSH container enciphered with AES-GCM, which this build does not \
                 decipher",
            ))
        }
        b"chacha20-poly1305@openssh.com" => Err(VaultError::KeyPassphraseUncheckable(
            "it is an OpenSSH container enciphered with chacha20-poly1305@openssh.com, which \
             this build does not decipher",
        )),
        b"3des-cbc" => Err(VaultError::KeyPassphraseUncheckable(
            "it is an OpenSSH container enciphered with 3des-cbc, and this build deciphers only \
             AES in CTR and CBC mode",
        )),
        _ => Err(VaultError::KeyPassphraseUncheckable(
            "it is an OpenSSH container enciphered with a cipher this build does not recognise",
        )),
    }
}

/// The largest bcrypt-pbkdf round count this build will attempt.
///
/// `ssh-keygen` writes 16 by default and `-a` raises it; the hardening advice
/// people actually follow lands between 64 and 1000. The bound is here so that
/// a file declaring a round count nobody would choose cannot make the import
/// hang while the derivation runs, and it is set from a measurement rather than
/// a guess: this crate's own release build costs roughly half a millisecond a
/// round, so the bound is about two seconds — four times the highest figure the
/// advice reaches, and far short of the minutes a declared 2^32 would take.
///
/// It is deliberately generous. Refusing a key that works is worse than taking
/// a moment to open one, and the file came out of the user's own file picker
/// rather than off a network.
const MAX_ROUNDS: u32 = 4096;

/// The clause for a container declaring a derivation cost this build refuses.
const ROUNDS_REFUSED: &str = "its bcrypt-pbkdf round count is higher than this build will \
                              attempt, so the passphrase cannot be checked";

/// A cursor over the SSH wire fields of a container (RFC 4251 §5).
struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Fields<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The next `string`: a big-endian `u32` length and that many bytes.
    fn string(&mut self) -> Result<&'a [u8], VaultError> {
        let length = self.u32()?;
        let length = usize::try_from(length).map_err(|_| VaultError::NotAPrivateKey)?;
        let (value, rest) = self
            .rest
            .split_at_checked(length)
            .ok_or(VaultError::NotAPrivateKey)?;
        self.rest = rest;
        Ok(value)
    }

    /// The next `uint32`.
    fn u32(&mut self) -> Result<u32, VaultError> {
        let (head, rest) = self
            .rest
            .split_at_checked(4)
            .ok_or(VaultError::NotAPrivateKey)?;
        let head: [u8; 4] = head.try_into().map_err(|_| VaultError::NotAPrivateKey)?;
        self.rest = rest;
        Ok(u32::from_be_bytes(head))
    }
}

/// Reads a container far enough to say whether its private half is enciphered.
///
/// `"none"` is the unencrypted case. Kept here beside the rest of the container
/// reading rather than in `crate::credential`, so that one module owns the
/// format.
///
/// **An unenciphered container is checked, not merely recognised.** Its private
/// section is in the clear, so the two check integers can be compared without a
/// passphrase — and a file whose key material does not survive that is a file
/// no SSH implementation will read either. Answering it here is the same
/// argument as the passphrase check above: the alternative is a credential that
/// looks stored and fails when a session is opened, where nothing on screen
/// connects the failure to the file.
pub(crate) fn detect(body: &[u8]) -> Result<bool, VaultError> {
    let rest = body.strip_prefix(MAGIC).ok_or(VaultError::NotAPrivateKey)?;
    let mut fields = Fields::new(rest);
    let cipher = fields.string()?;
    if cipher != b"none" {
        return Ok(true);
    }

    // `kdfname`, `kdfoptions`, then the public keys, then the private section —
    // the same walk `check_passphrase` makes, without the deciphering.
    fields.string()?;
    fields.string()?;
    let count = fields.u32()?;
    for _ in 0..count {
        fields.string()?;
    }
    let private = fields.string()?;
    let (first, second) = private
        .get(..CHECK_BYTES)
        .ok_or(VaultError::NotAPrivateKey)?
        .split_at(CHECK_BYTES / 2);
    if first != second {
        return Err(VaultError::NotAPrivateKey);
    }
    Ok(false)
}

/// Whether `passphrase` opens this container.
///
/// # Errors
///
/// [`VaultError::KeyPassphraseRejected`] when the container was deciphered and
/// the two check integers came out different, which is what a wrong passphrase
/// looks like; [`VaultError::KeyPassphraseUncheckable`] when the cipher or the
/// key derivation is one this build cannot run, so the question cannot be
/// answered here at all; [`VaultError::NotAPrivateKey`] when the container is
/// truncated or its fields do not parse.
pub(crate) fn check_passphrase(body: &[u8], passphrase: &[u8]) -> Result<(), VaultError> {
    let rest = body.strip_prefix(MAGIC).ok_or(VaultError::NotAPrivateKey)?;
    let mut fields = Fields::new(rest);

    let cipher = cipher_for(fields.string()?)?;
    let kdf = fields.string()?;
    let options = fields.string()?;
    if kdf != b"bcrypt" {
        // `none` here with a real cipher above is a malformed container rather
        // than a plaintext key; anything else is a derivation OpenSSH has never
        // written. Neither can be deciphered, and neither is the passphrase's
        // fault.
        return Err(VaultError::KeyPassphraseUncheckable(
            "its key derivation is not bcrypt-pbkdf, which is the only one this build \
             recognises in an OpenSSH container",
        ));
    }

    // `kdfoptions` for bcrypt: the salt, then the round count.
    let mut options = Fields::new(options);
    let salt = options.string()?;
    let rounds = options.u32()?;
    if rounds == 0 || rounds > MAX_ROUNDS {
        return Err(VaultError::KeyPassphraseUncheckable(ROUNDS_REFUSED));
    }
    // The derivation refuses an empty salt, and so does this — one line earlier,
    // so that a container with no salt in it reads as the damaged file it is
    // rather than as a passphrase someone typed wrong.
    if salt.is_empty() {
        return Err(VaultError::NotAPrivateKey);
    }

    // The public keys are skipped: nothing here needs them, and the count is
    // read only so the cursor lands on the private section.
    let count = fields.u32()?;
    for _ in 0..count {
        fields.string()?;
    }
    let private = fields.string()?;

    // One block is enough — the check integers are the first eight bytes — and
    // deciphering only that keeps the key material that is not being examined
    // enciphered.
    let block = private
        .get(..BLOCK)
        .ok_or(VaultError::NotAPrivateKey)?
        .to_vec();
    let mut block = Zeroizing::new(block);

    // bcrypt-pbkdf produces the cipher key and the initialisation vector in one
    // run, exactly as `ssh-keygen` derives them.
    let mut material = Zeroizing::new(vec![0u8; cipher.key_len().saturating_add(BLOCK)]);
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, material.as_mut_slice())
        // An empty passphrase or an empty salt is refused by the derivation
        // itself. Neither can open the container, and neither is a fact about
        // this build's capabilities, so it reads as a rejection.
        .map_err(|_| VaultError::KeyPassphraseRejected)?;
    let (key, iv) = material.split_at(cipher.key_len());
    let iv: [u8; BLOCK] = iv.try_into().map_err(|_| VaultError::NotAPrivateKey)?;

    decipher_block(cipher, key, &iv, block.as_mut_slice())?;

    let (first, second) = block
        .split_at_checked(CHECK_BYTES / 2)
        .ok_or(VaultError::NotAPrivateKey)?;
    let second = second
        .get(..CHECK_BYTES / 2)
        .ok_or(VaultError::NotAPrivateKey)?;
    if first != second {
        return Err(VaultError::KeyPassphraseRejected);
    }
    Ok(())
}

/// Deciphers one block in place.
///
/// CBC and CTR both decipher the first block from the initialisation vector
/// alone, which is why no more of the private section has to be touched. The
/// key arrives as a slice and is turned into the array each constructor wants
/// here, once, rather than at six call sites.
fn decipher_block(
    cipher: Cipher,
    key: &[u8],
    iv: &[u8; BLOCK],
    block: &mut [u8],
) -> Result<(), VaultError> {
    /// The key at the width its cipher takes, or a malformed container.
    fn sized<const N: usize>(key: &[u8]) -> Result<Zeroizing<[u8; N]>, VaultError> {
        let key: [u8; N] = key.try_into().map_err(|_| VaultError::NotAPrivateKey)?;
        Ok(Zeroizing::new(key))
    }

    match cipher {
        Cipher::Aes128Ctr => {
            let key = sized::<16>(key)?;
            ctr::Ctr128BE::<Aes128>::new(&(*key).into(), iv.into()).apply_keystream(block);
        }
        Cipher::Aes192Ctr => {
            let key = sized::<24>(key)?;
            ctr::Ctr128BE::<Aes192>::new(&(*key).into(), iv.into()).apply_keystream(block);
        }
        Cipher::Aes256Ctr => {
            let key = sized::<32>(key)?;
            ctr::Ctr128BE::<Aes256>::new(&(*key).into(), iv.into()).apply_keystream(block);
        }
        // `NoPadding` because this is the first block of a longer message, not
        // a whole one: the padding OpenSSH applies lives at the far end of the
        // private section and is never read here.
        Cipher::Aes128Cbc => {
            let key = sized::<16>(key)?;
            cbc::Decryptor::<Aes128>::new(&(*key).into(), iv.into())
                .decrypt_padded::<NoPadding>(block)
                .map_err(|_| VaultError::NotAPrivateKey)?;
        }
        Cipher::Aes192Cbc => {
            let key = sized::<24>(key)?;
            cbc::Decryptor::<Aes192>::new(&(*key).into(), iv.into())
                .decrypt_padded::<NoPadding>(block)
                .map_err(|_| VaultError::NotAPrivateKey)?;
        }
        Cipher::Aes256Cbc => {
            let key = sized::<32>(key)?;
            cbc::Decryptor::<Aes256>::new(&(*key).into(), iv.into())
                .decrypt_padded::<NoPadding>(block)
                .map_err(|_| VaultError::NotAPrivateKey)?;
        }
    }
    Ok(())
}

/// Building the containers the tests read.
///
/// Compiled for this crate's own tests and for anything that turns on
/// `test-fixtures`, which nothing but this crate's dev-dependency on itself
/// can. A fixture built here carries meaningless key material: the repository
/// holds no key, and `CLAUDE.md` §9 forbids committing one even for a test.
#[cfg(any(test, feature = "test-fixtures"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test fixtures, per the workspace convention"
)]
pub(crate) mod fixtures {
    use super::*;
    use cbc::cipher::BlockModeEncrypt;
    use cbc::cipher::block_padding::ZeroPadding;

    /// Appends an SSH `string` (RFC 4251 §5).
    pub(crate) fn string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// An encrypted OpenSSH container around a private section that begins with
    /// `check` twice, built the way `ssh-keygen` builds one.
    ///
    /// The key material after the check integers is arbitrary: nothing this
    /// module does reads it, and a fixture carrying a real key would be a key
    /// in the repository. `ssh-keygen`'s own output is what
    /// `tests/key_passphrase.rs` checks this against.
    pub(crate) fn container(
        cipher_name: &str,
        kdf: &str,
        passphrase: &[u8],
        rounds: u32,
        check: (u32, u32),
    ) -> Vec<u8> {
        let salt = [0x5Au8; 16];

        let mut plain = Vec::new();
        plain.extend_from_slice(&check.0.to_be_bytes());
        plain.extend_from_slice(&check.1.to_be_bytes());
        string(&mut plain, b"ssh-ed25519");
        plain.extend_from_slice(&[0u8; 48]);
        while plain.len() % BLOCK != 0 {
            plain.push(u8::try_from(plain.len() % BLOCK).unwrap());
        }

        // A cipher this build cannot run leaves the body in the clear: the
        // fixture exists to be refused before any cipher is reached, and
        // enciphering it would need the implementation whose absence is the
        // thing under test.
        let private = if cipher_for(cipher_name.as_bytes()).is_err() {
            plain
        } else {
            let cipher = cipher_for(cipher_name.as_bytes()).unwrap();
            let mut material = vec![0u8; cipher.key_len() + BLOCK];
            bcrypt_pbkdf::bcrypt_pbkdf(passphrase, &salt, rounds, &mut material).unwrap();
            let (key, iv) = material.split_at(cipher.key_len());
            let iv: [u8; BLOCK] = iv.try_into().unwrap();
            encipher(cipher, key, &iv, &mut plain);
            plain
        };

        let mut body = Vec::from(MAGIC);
        string(&mut body, cipher_name.as_bytes());
        string(&mut body, kdf.as_bytes());
        let mut options = Vec::new();
        if kdf == "bcrypt" {
            string(&mut options, &salt);
            options.extend_from_slice(&rounds.to_be_bytes());
        }
        string(&mut body, &options);
        body.extend_from_slice(&1u32.to_be_bytes());
        string(&mut body, b"\0\0\0\x0bssh-ed25519");
        string(&mut body, &private);
        body
    }

    /// The inverse of [`decipher_block`], over a whole block-aligned buffer.
    fn encipher(cipher: Cipher, key: &[u8], iv: &[u8; BLOCK], buffer: &mut [u8]) {
        fn sized<const N: usize>(key: &[u8]) -> [u8; N] {
            key.try_into().unwrap()
        }
        let len = buffer.len();
        match cipher {
            Cipher::Aes128Ctr => {
                ctr::Ctr128BE::<Aes128>::new(&sized::<16>(key).into(), iv.into())
                    .apply_keystream(buffer);
            }
            Cipher::Aes192Ctr => {
                ctr::Ctr128BE::<Aes192>::new(&sized::<24>(key).into(), iv.into())
                    .apply_keystream(buffer);
            }
            Cipher::Aes256Ctr => {
                ctr::Ctr128BE::<Aes256>::new(&sized::<32>(key).into(), iv.into())
                    .apply_keystream(buffer);
            }
            Cipher::Aes128Cbc => {
                cbc::Encryptor::<Aes128>::new(&sized::<16>(key).into(), iv.into())
                    .encrypt_padded::<ZeroPadding>(buffer, len)
                    .unwrap();
            }
            Cipher::Aes192Cbc => {
                cbc::Encryptor::<Aes192>::new(&sized::<24>(key).into(), iv.into())
                    .encrypt_padded::<ZeroPadding>(buffer, len)
                    .unwrap();
            }
            Cipher::Aes256Cbc => {
                cbc::Encryptor::<Aes256>::new(&sized::<32>(key).into(), iv.into())
                    .encrypt_padded::<ZeroPadding>(buffer, len)
                    .unwrap();
            }
        }
    }
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
    use super::fixtures::{container, string};
    use super::*;

    /// The clause a refusal carries, or a marker the assertion can print.
    fn said(result: Result<(), VaultError>) -> String {
        match result {
            Ok(()) => String::from("<accepted>"),
            Err(VaultError::KeyPassphraseRejected) => String::from("<rejected>"),
            Err(VaultError::KeyPassphraseUncheckable(clause)) => clause.to_owned(),
            Err(other) => format!("<{other}>"),
        }
    }

    #[test]
    fn the_right_passphrase_opens_every_cipher_this_build_reads() {
        for name in [
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
        ] {
            let body = container(
                name,
                "bcrypt",
                b"open sesame",
                4,
                (0x0102_0304, 0x0102_0304),
            );
            assert_eq!(said(check_passphrase(&body, b"open sesame")), "<accepted>");
            assert_eq!(
                said(check_passphrase(&body, b"not the passphrase")),
                "<rejected>",
                "for {name}"
            );
        }
    }

    /// The two check integers are the whole test: a container whose plaintext
    /// carries two different words did not come from a correct passphrase, and
    /// is refused even though the deciphering itself succeeded.
    #[test]
    fn two_different_check_integers_are_a_rejection() {
        let body = container("aes256-ctr", "bcrypt", b"open sesame", 4, (1, 2));
        assert_eq!(said(check_passphrase(&body, b"open sesame")), "<rejected>");
    }

    #[test]
    fn a_cipher_this_build_cannot_run_says_so_rather_than_guessing() {
        for (name, expected) in [
            ("chacha20-poly1305@openssh.com", "chacha20-poly1305"),
            ("aes256-gcm@openssh.com", "AES-GCM"),
            ("3des-cbc", "3des-cbc"),
            ("rijndael-cbc@lysator.liu.se", "does not recognise"),
        ] {
            // The body never reaches a cipher, so it need not be enciphered.
            let body = container("none", "bcrypt", b"", 4, (1, 1));
            let mut head = Vec::from(MAGIC);
            string(&mut head, name.as_bytes());
            head.extend_from_slice(&body[MAGIC.len() + 4 + "none".len()..]);
            let clause = said(check_passphrase(&head, b"open sesame"));
            assert!(clause.contains(expected), "for {name}: {clause}");
            // And never the file's own bytes.
            assert!(!clause.contains("lysator"), "for {name}: {clause}");
        }
    }

    #[test]
    fn a_derivation_this_build_cannot_run_says_so() {
        let body = container("aes256-ctr", "argon2id", b"open sesame", 4, (1, 1));
        let clause = said(check_passphrase(&body, b"open sesame"));
        assert!(clause.contains("bcrypt-pbkdf"), "{clause}");

        let costly = container("aes256-ctr", "bcrypt", b"open sesame", 4, (1, 1));
        // The round count sits in `kdfoptions`, immediately after the salt.
        let mut raised = costly.clone();
        let at = raised
            .windows(4)
            .position(|window| window == 4u32.to_be_bytes())
            .unwrap();
        raised[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let clause = said(check_passphrase(&raised, b"open sesame"));
        assert!(clause.contains("round count"), "{clause}");
    }

    #[test]
    fn a_truncated_container_is_not_a_rejected_passphrase() {
        let body = container("aes256-ctr", "bcrypt", b"open sesame", 4, (1, 1));
        for cut in [MAGIC.len(), MAGIC.len() + 8, body.len() - 8] {
            let said = said(check_passphrase(&body[..cut], b"open sesame"));
            assert!(
                said.contains("not a private key"),
                "cut at {cut}: {said}, which blames the passphrase for a damaged file"
            );
        }
    }

    #[test]
    fn the_cipher_name_says_whether_the_private_half_is_enciphered() {
        let plain = container("none", "none", b"", 0, (1, 1));
        assert!(!detect(&plain).unwrap());
        let sealed = container("aes256-ctr", "bcrypt", b"open sesame", 4, (1, 1));
        assert!(detect(&sealed).unwrap());
        assert!(matches!(
            detect(b"not a key"),
            Err(VaultError::NotAPrivateKey)
        ));
    }

    /// An unenciphered container carries its own proof, and a file that fails
    /// it is refused at the moment it is chosen rather than at the moment a
    /// session is opened.
    #[test]
    fn an_unenciphered_container_that_is_not_a_key_is_refused_when_it_is_read() {
        let damaged = container("none", "none", b"", 0, (1, 2));
        assert!(
            matches!(detect(&damaged), Err(VaultError::NotAPrivateKey)),
            "a plaintext container whose check integers differ was accepted"
        );

        let truncated = container("none", "none", b"", 0, (1, 1));
        let cut = truncated.len().saturating_sub(8);
        assert!(matches!(
            detect(truncated.get(..cut).unwrap()),
            Err(VaultError::NotAPrivateKey)
        ));
    }
}
