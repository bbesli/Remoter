//! mRemoteNG's own encryption, as read by Remoter.
//!
//! None of this is Remoter's cryptography and none of it should be copied into
//! `remoter-vault`. It is here because a `confCons.xml` is encrypted the way
//! mRemoteNG encrypts it, and reading someone else's file means reading
//! someone else's scheme. `docs/features/import-export.md` lists the three
//! forms; the two that carry ciphertext are implemented here.
//!
//! **GCM** (mRemoteNG ≥ 1.75, `BlockCipherMode="GCM"`). Base64 of
//! `salt‖nonce‖ciphertext‖tag` with a 16-byte salt, a 16-byte nonce and a
//! 128-bit tag. The key is PBKDF2-HMAC-SHA1 over the password and that salt,
//! for the `KdfIterations` the document declares, to 256 bits. The salt is also
//! the AEAD's associated data — mRemoteNG passes it to BouncyCastle as the
//! `AeadParameters` non-secret payload, so a decryption that ignored it would
//! fail its tag check.
//!
//! **CBC** (legacy, pre-1.75). Base64 of `iv‖ciphertext`, AES-128-CBC with
//! PKCS#7 padding, and a key that is a plain unsalted MD5 of the password. It
//! is unauthenticated and its key derivation costs one hash, which is why an
//! import that meets it says so on the report.
//!
//! A 16-byte GCM nonce is unusual — the common instantiation uses 12 — and is
//! why the mode is spelled out generically below rather than reached for as
//! `Aes256Gcm`. NIST SP 800-38D §7.1 defines GCM for any nonce length; the
//! 12-byte case is only the one that skips the GHASH step.

use aes::{Aes128, Aes256};
use aes_gcm::AesGcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use aes_gcm::aes::cipher::consts::U16;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use data_encoding::BASE64;
use md5::{Digest, Md5};
use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::secret::ImportedSecret;

/// mRemoteNG's built-in password, used whenever the user has not set one.
///
/// A published constant, not a secret: `RootNodeInfo.DefaultPassword` in
/// mRemoteNG's own source. A file encrypted under it is encrypted in the sense
/// that a base64 blob is unreadable, and in no other sense — which is exactly
/// what the import report has to tell the user.
pub const DEFAULT_PASSWORD: &str = "mR3m";

/// The plaintext mRemoteNG puts in the `Protected` attribute of a file the user
/// gave a password to.
const PROTECTED_MARKER: &str = "ThisIsProtected";

/// The plaintext it puts there when the file is on the default password.
const UNPROTECTED_MARKER: &str = "ThisIsNotProtected";

/// The iteration count used when the document does not declare one.
const DEFAULT_KDF_ITERATIONS: u32 = 1000;

/// The most iterations this importer will run.
///
/// `KdfIterations` is an attacker-controlled number in a file a colleague sent
/// you. Without a ceiling, `KdfIterations="2000000000"` is a file that hangs
/// the application for an afternoon.
const MAX_KDF_ITERATIONS: u32 = 1_000_000;

/// AES-256-GCM with mRemoteNG's 16-byte nonce and 16-byte tag.
type MremotengGcm = AesGcm<Aes256, U16, U16>;

/// AES-128-CBC, the legacy scheme's cipher.
type LegacyCbc = cbc::Decryptor<Aes128>;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 16;
const IV_LEN: usize = 16;
const BLOCK_LEN: usize = 16;

/// Which scheme a document declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    /// AES-GCM, with the document's own iteration count.
    Gcm {
        /// PBKDF2 iterations, as declared.
        iterations: u32,
    },
    /// The legacy AES-CBC scheme.
    Cbc,
}

impl CipherMode {
    /// Reads the mode a `<Connections>` element declares.
    ///
    /// A document with no `BlockCipherMode` is a pre-2.6 one, which is the
    /// legacy scheme.
    ///
    /// # Errors
    ///
    /// [`ImportError::UnsupportedCipher`] for an engine or mode this build does
    /// not read, or [`ImportError::TooManyItems`] for an iteration count past
    /// the ceiling.
    pub fn from_attributes(
        engine: Option<&str>,
        mode: Option<&str>,
        iterations: Option<&str>,
    ) -> Result<Self, ImportError> {
        // mRemoteNG can be built against other BouncyCastle engines. Only AES
        // is implemented here, and guessing at a Serpent file would be worse
        // than refusing it.
        if let Some(engine) = engine {
            if !engine.eq_ignore_ascii_case("AES") {
                return Err(ImportError::UnsupportedCipher {
                    mode: sanitise(engine),
                });
            }
        }

        match mode {
            None => Ok(Self::Cbc),
            Some(mode) if mode.eq_ignore_ascii_case("GCM") => {
                let iterations = iterations
                    .and_then(|value| value.trim().parse::<u32>().ok())
                    .filter(|value| *value > 0)
                    .unwrap_or(DEFAULT_KDF_ITERATIONS);
                if iterations > MAX_KDF_ITERATIONS {
                    return Err(ImportError::TooManyItems {
                        limit: MAX_KDF_ITERATIONS as usize,
                        unit: "KDF iterations",
                    });
                }
                Ok(Self::Gcm { iterations })
            }
            Some(mode) if mode.eq_ignore_ascii_case("CBC") => Ok(Self::Cbc),
            Some(mode) => Err(ImportError::UnsupportedCipher {
                mode: sanitise(mode),
            }),
        }
    }

    /// Whether this is the unauthenticated legacy scheme.
    pub const fn is_legacy(self) -> bool {
        matches!(self, Self::Cbc)
    }
}

/// Reduces an attacker-supplied token to something safe to put in an error
/// message: ASCII alphanumerics, at most sixteen of them.
fn sanitise(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(16)
        .collect();
    if cleaned.is_empty() {
        "unnamed".to_owned()
    } else {
        cleaned
    }
}

/// Decrypts the fields of one document.
pub(crate) struct Decryptor {
    mode: CipherMode,
    password: Zeroizing<String>,
}

impl Decryptor {
    /// A decryptor for `mode` under `password`.
    #[must_use]
    pub(crate) fn new(mode: CipherMode, password: &str) -> Self {
        Self {
            mode,
            password: Zeroizing::new(password.to_owned()),
        }
    }

    /// A decryptor on mRemoteNG's default password.
    #[must_use]
    pub(crate) fn with_default_password(mode: CipherMode) -> Self {
        Self::new(mode, DEFAULT_PASSWORD)
    }

    /// Whether the scheme is the unauthenticated legacy one.
    #[must_use]
    pub(crate) const fn is_legacy(&self) -> bool {
        self.mode.is_legacy()
    }

    /// Checks the document's `Protected` attribute against the password.
    ///
    /// This is the one place a wrong password is distinguished from a corrupt
    /// file, and it is deliberately the first thing an import does. The
    /// distinction is drawn for the user only after the document's own
    /// authenticator has been checked, never inferred from a field failing to
    /// decrypt halfway through the tree — an importer that told the difference
    /// by trying each field in turn would be an oracle over the file's
    /// contents.
    ///
    /// # Errors
    ///
    /// [`ImportError::WrongPassword`] if the marker does not come back.
    pub(crate) fn authenticate(&self, protected: &str) -> Result<(), ImportError> {
        if protected.is_empty() {
            // Pre-1.4 documents have no authenticator. Nothing to check.
            return Ok(());
        }
        let Ok(marker) = self.decrypt(protected) else {
            return Err(ImportError::WrongPassword);
        };
        if marker.expose() == PROTECTED_MARKER || marker.expose() == UNPROTECTED_MARKER {
            Ok(())
        } else {
            Err(ImportError::WrongPassword)
        }
    }

    /// Whether the `Protected` attribute says the file is on the default
    /// password.
    ///
    /// mRemoteNG writes a different marker for the two cases, so this is the
    /// file's own statement rather than an inference from the password having
    /// worked.
    #[must_use]
    pub(crate) fn declares_no_protection(&self, protected: &str) -> bool {
        self.decrypt(protected)
            .is_ok_and(|marker| marker.expose() == UNPROTECTED_MARKER)
    }

    /// Decrypts one base64 field.
    ///
    /// The result is an [`ImportedSecret`] rather than a `String` even when the
    /// field is not itself a password. `Zeroizing`'s own `Debug` prints its
    /// contents, so a plaintext handed back in one would be a formatted secret
    /// waiting for a `{:?}` somewhere upstream.
    ///
    /// # Errors
    ///
    /// [`ImportError::MalformedCiphertext`] for anything that is not a
    /// well-formed, authentic ciphertext under this password: bad base64, a
    /// blob too short to hold its own header, a failed tag, or a plaintext that
    /// is not UTF-8.
    pub(crate) fn decrypt(&self, field: &str) -> Result<ImportedSecret, ImportError> {
        let raw = decode_base64(field)?;
        let plaintext = match self.mode {
            CipherMode::Gcm { iterations } => self.decrypt_gcm(&raw, iterations)?,
            CipherMode::Cbc => self.decrypt_cbc(&raw)?,
        };
        let text = core::str::from_utf8(&plaintext)
            .map_err(|_| ImportError::MalformedCiphertext)?
            .to_owned();
        Ok(ImportedSecret::new(text))
    }

    fn decrypt_gcm(&self, raw: &[u8], iterations: u32) -> Result<Zeroizing<Vec<u8>>, ImportError> {
        if raw.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
            return Err(ImportError::MalformedCiphertext);
        }
        let (salt, rest) = raw.split_at(SALT_LEN);
        let (nonce, body) = rest.split_at(NONCE_LEN);
        let (ciphertext, tag) = body.split_at(body.len() - TAG_LEN);

        let mut key = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
            self.password.as_bytes(),
            salt,
            iterations,
            key.as_mut_slice(),
        );

        let cipher = MremotengGcm::new((&*key).into());
        let nonce: Nonce<MremotengGcm> = slice_to_array::<NONCE_LEN>(nonce)?.into();
        let tag: Tag<MremotengGcm> = slice_to_array::<TAG_LEN>(tag)?.into();

        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        cipher
            // The salt doubles as the associated data; see the module comment.
            .decrypt_inout_detached(&nonce, salt, buffer.as_mut_slice().into(), &tag)
            .map_err(|_| ImportError::MalformedCiphertext)?;
        Ok(buffer)
    }

    fn decrypt_cbc(&self, raw: &[u8]) -> Result<Zeroizing<Vec<u8>>, ImportError> {
        if raw.len() <= IV_LEN || (raw.len() - IV_LEN) % BLOCK_LEN != 0 {
            return Err(ImportError::MalformedCiphertext);
        }
        let (iv, ciphertext) = raw.split_at(IV_LEN);

        let key = Zeroizing::new(<[u8; 16]>::from(Md5::digest(self.password.as_bytes())));
        let iv = slice_to_array::<IV_LEN>(iv)?;

        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        let plaintext_len = LegacyCbc::new((&*key).into(), &iv.into())
            .decrypt_padded::<Pkcs7>(buffer.as_mut_slice())
            .map_err(|_| ImportError::MalformedCiphertext)?
            .len();
        // `Zeroize for Vec` covers the whole capacity, so the padding bytes
        // that fall off here are still wiped when the buffer drops.
        buffer.truncate(plaintext_len);
        Ok(buffer)
    }
}

/// Copies a slice of known length into an array without indexing past its end.
fn slice_to_array<const N: usize>(slice: &[u8]) -> Result<[u8; N], ImportError> {
    slice
        .try_into()
        .map_err(|_| ImportError::MalformedCiphertext)
}

/// Decodes base64, tolerating the whitespace an XML formatter inserts into a
/// long attribute or a full-file-encrypted body.
fn decode_base64(field: &str) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let compact: String = field.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    BASE64
        .decode(compact.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| ImportError::MalformedCiphertext)
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
pub(crate) mod test_encrypt {
    //! The encrypting half of both schemes.
    //!
    //! Only a test builds an mRemoteNG file — Remoter exports its own format —
    //! so this is compiled out of every ordinary build. It exists because a
    //! decryption path that is only ever fed a hand-typed constant is a
    //! decryption path nobody has exercised.

    use super::{BLOCK_LEN, CipherMode, IV_LEN, MremotengGcm, NONCE_LEN, SALT_LEN};
    use aes::Aes128;
    use aes_gcm::aead::{AeadInOut, KeyInit, Nonce};
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
    use data_encoding::BASE64;
    use md5::{Digest, Md5};

    /// Encrypts `plaintext` the way mRemoteNG would.
    ///
    /// The salt, nonce and IV are derived from `seed` rather than drawn at
    /// random so that a fixture is byte-for-byte reproducible; that is exactly
    /// what a real implementation must not do, and exactly what a test needs.
    pub(crate) fn encrypt(mode: CipherMode, password: &str, plaintext: &str, seed: u8) -> String {
        match mode {
            CipherMode::Gcm { iterations } => {
                let salt = [seed; SALT_LEN];
                let nonce_bytes = [seed ^ 0xff; NONCE_LEN];
                let mut key = [0u8; 32];
                pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), &salt, iterations, &mut key);
                let cipher = MremotengGcm::new(&key.into());
                let nonce: Nonce<MremotengGcm> = nonce_bytes.into();
                let mut buffer = plaintext.as_bytes().to_vec();
                let tag = cipher
                    .encrypt_inout_detached(&nonce, &salt, buffer.as_mut_slice().into())
                    .unwrap();
                let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + buffer.len() + 16);
                out.extend_from_slice(&salt);
                out.extend_from_slice(&nonce_bytes);
                out.extend_from_slice(&buffer);
                out.extend_from_slice(&tag);
                BASE64.encode(&out)
            }
            CipherMode::Cbc => {
                let key = <[u8; 16]>::from(Md5::digest(password.as_bytes()));
                let iv = [seed; IV_LEN];
                let plain = plaintext.as_bytes();
                let padded_len = plain.len() + BLOCK_LEN - plain.len() % BLOCK_LEN;
                let mut buffer = vec![0u8; padded_len];
                buffer[..plain.len()].copy_from_slice(plain);
                let encryptor: cbc::Encryptor<Aes128> =
                    cbc::Encryptor::new(&key.into(), &iv.into());
                let ciphertext = encryptor
                    .encrypt_padded::<Pkcs7>(&mut buffer, plain.len())
                    .unwrap()
                    .to_vec();
                let mut out = Vec::with_capacity(IV_LEN + ciphertext.len());
                out.extend_from_slice(&iv);
                out.extend_from_slice(&ciphertext);
                BASE64.encode(&out)
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
mod tests {
    use super::test_encrypt::encrypt;
    use super::*;

    const GCM: CipherMode = CipherMode::Gcm { iterations: 1000 };

    #[test]
    fn gcm_round_trips() {
        let ciphertext = encrypt(GCM, "correct horse", "hunter2", 7);
        let decryptor = Decryptor::new(GCM, "correct horse");
        assert_eq!(decryptor.decrypt(&ciphertext).unwrap().expose(), "hunter2");
    }

    #[test]
    fn cbc_round_trips() {
        let ciphertext = encrypt(CipherMode::Cbc, "correct horse", "hunter2", 7);
        let decryptor = Decryptor::new(CipherMode::Cbc, "correct horse");
        assert_eq!(decryptor.decrypt(&ciphertext).unwrap().expose(), "hunter2");
    }

    #[test]
    fn cbc_round_trips_a_block_aligned_plaintext() {
        // PKCS#7 adds a whole block when the plaintext already fits exactly,
        // which is the case an off-by-one in the padding check would break.
        let ciphertext = encrypt(CipherMode::Cbc, "pw", "0123456789abcdef", 1);
        let decryptor = Decryptor::new(CipherMode::Cbc, "pw");
        assert_eq!(
            decryptor.decrypt(&ciphertext).unwrap().expose(),
            "0123456789abcdef"
        );
    }

    #[test]
    fn gcm_rejects_a_wrong_password() {
        let ciphertext = encrypt(GCM, "right", "hunter2", 3);
        let decryptor = Decryptor::new(GCM, "wrong");
        assert_eq!(
            decryptor.decrypt(&ciphertext),
            Err(ImportError::MalformedCiphertext)
        );
    }

    #[test]
    fn gcm_rejects_a_flipped_bit() {
        let ciphertext = encrypt(GCM, "pw", "hunter2", 3);
        let mut raw = BASE64.decode(ciphertext.as_bytes()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        let decryptor = Decryptor::new(GCM, "pw");
        assert_eq!(
            decryptor.decrypt(&BASE64.encode(&raw)),
            Err(ImportError::MalformedCiphertext)
        );
    }

    #[test]
    fn short_and_ragged_blobs_are_refused_rather_than_indexed_into() {
        let gcm = Decryptor::new(GCM, "pw");
        let cbc = Decryptor::new(CipherMode::Cbc, "pw");
        for len in 0..80_usize {
            let blob = BASE64.encode(&vec![0u8; len]);
            assert!(gcm.decrypt(&blob).is_err() || len >= SALT_LEN + NONCE_LEN + TAG_LEN);
            assert!(cbc.decrypt(&blob).is_err() || (len > IV_LEN && (len - IV_LEN) % 16 == 0));
        }
    }

    #[test]
    fn bad_base64_is_a_malformed_ciphertext_not_a_panic() {
        let decryptor = Decryptor::new(GCM, "pw");
        assert_eq!(
            decryptor.decrypt("not base64 !!!"),
            Err(ImportError::MalformedCiphertext)
        );
    }

    #[test]
    fn base64_may_be_wrapped_across_lines() {
        let ciphertext = encrypt(GCM, "pw", "a longer secret than one line", 9);
        let wrapped: String = ciphertext
            .as_bytes()
            .chunks(8)
            .map(|chunk| format!("{}\n  ", String::from_utf8_lossy(chunk)))
            .collect();
        let decryptor = Decryptor::new(GCM, "pw");
        assert_eq!(
            decryptor.decrypt(&wrapped).unwrap().expose(),
            "a longer secret than one line"
        );
    }

    #[test]
    fn authentication_separates_a_wrong_password_from_a_corrupt_file() {
        let protected = encrypt(GCM, "right", "ThisIsProtected", 5);
        assert!(
            Decryptor::new(GCM, "right")
                .authenticate(&protected)
                .is_ok()
        );
        assert_eq!(
            Decryptor::new(GCM, "wrong").authenticate(&protected),
            Err(ImportError::WrongPassword)
        );
        // An authentic ciphertext that is not the marker is still the wrong
        // password as far as the file is concerned.
        let other = encrypt(GCM, "right", "something else", 5);
        assert_eq!(
            Decryptor::new(GCM, "right").authenticate(&other),
            Err(ImportError::WrongPassword)
        );
        // A document with no authenticator has nothing to check.
        assert!(Decryptor::new(GCM, "right").authenticate("").is_ok());
    }

    #[test]
    fn the_default_password_marker_is_recognised() {
        let protected = encrypt(GCM, DEFAULT_PASSWORD, "ThisIsNotProtected", 2);
        let decryptor = Decryptor::with_default_password(GCM);
        assert!(decryptor.authenticate(&protected).is_ok());
        assert!(decryptor.declares_no_protection(&protected));

        let protected = encrypt(GCM, "real", "ThisIsProtected", 2);
        let decryptor = Decryptor::new(GCM, "real");
        assert!(!decryptor.declares_no_protection(&protected));
    }

    #[test]
    fn the_declared_mode_is_read_from_the_root_element() {
        assert_eq!(
            CipherMode::from_attributes(Some("AES"), Some("GCM"), Some("2000")),
            Ok(CipherMode::Gcm { iterations: 2000 })
        );
        assert_eq!(
            CipherMode::from_attributes(Some("AES"), Some("gcm"), None),
            Ok(CipherMode::Gcm { iterations: 1000 })
        );
        assert_eq!(
            CipherMode::from_attributes(Some("AES"), Some("CBC"), None),
            Ok(CipherMode::Cbc)
        );
        assert_eq!(
            CipherMode::from_attributes(None, None, None),
            Ok(CipherMode::Cbc)
        );
        assert!(
            CipherMode::from_attributes(None, None, None)
                .unwrap()
                .is_legacy()
        );
    }

    #[test]
    fn an_unreadable_engine_or_mode_is_refused_with_a_sanitised_name() {
        assert_eq!(
            CipherMode::from_attributes(Some("Serpent"), Some("GCM"), None),
            Err(ImportError::UnsupportedCipher {
                mode: "Serpent".to_owned()
            })
        );
        assert_eq!(
            CipherMode::from_attributes(Some("AES"), Some("EAX"), None),
            Err(ImportError::UnsupportedCipher {
                mode: "EAX".to_owned()
            })
        );
        // An engine name crafted to carry markup into a message is stripped to
        // alphanumerics and truncated.
        assert_eq!(
            CipherMode::from_attributes(Some("<script>alert(1)</script>"), None, None),
            Err(ImportError::UnsupportedCipher {
                mode: "scriptalert1scri".to_owned()
            })
        );
        assert_eq!(
            CipherMode::from_attributes(Some("***"), None, None),
            Err(ImportError::UnsupportedCipher {
                mode: "unnamed".to_owned()
            })
        );
    }

    #[test]
    fn an_absurd_iteration_count_is_refused_rather_than_run() {
        assert_eq!(
            CipherMode::from_attributes(Some("AES"), Some("GCM"), Some("2000000000")),
            Err(ImportError::TooManyItems {
                limit: MAX_KDF_ITERATIONS as usize,
                unit: "KDF iterations"
            })
        );
        // A count that is not a number at all falls back to the default rather
        // than failing the whole file.
        assert_eq!(
            CipherMode::from_attributes(Some("AES"), Some("GCM"), Some("-1")),
            Ok(CipherMode::Gcm { iterations: 1000 })
        );
        assert_eq!(
            CipherMode::from_attributes(Some("AES"), Some("GCM"), Some("0")),
            Ok(CipherMode::Gcm { iterations: 1000 })
        );
    }

    /// Known-answer vectors, produced by mRemoteNG itself.
    ///
    /// Every other test in this module encrypts with [`test_encrypt`] and
    /// decrypts with the code beside it, which proves only that the two halves
    /// agree. These base64 blobs came out of mRemoteNG's own build: they are
    /// the `Protected` attributes and one connection password from the
    /// `confCons` documents in `mRemoteNGTests/Resources`, whose file names
    /// state the password each was written under. If a future refactor moves
    /// the salt, changes the digest under PBKDF2, drops the salt as associated
    /// data or reorders the tag, these stop decrypting while a round-trip test
    /// carries on passing.
    #[test]
    fn ciphertext_written_by_mremoteng_itself_decrypts() {
        // confCons_v2_6.xml — GCM, 1000 iterations, on the default password.
        assert_eq!(
            Decryptor::with_default_password(GCM)
                .decrypt(
                    "8LmIO3+MWBY0zTmfjfOEdCGxhTAwnlohb1veTGNZFt6lAYvY2UOzWyjVzkx6V93smpbP0ZOu\
                     exN15u7rvwJEjawC"
                )
                .unwrap()
                .expose(),
            "ThisIsNotProtected"
        );
        // A connection password out of the same document.
        assert_eq!(
            Decryptor::with_default_password(GCM)
                .decrypt(
                    "fdZPNiJlK9u/uRr22ViSGc8w69qHSDjWw4oeqJWCqFS+kT03rMOOdCczpCtvs6sX59iIcxet\
                     SA=="
                )
                .unwrap()
                .expose(),
            "folder1"
        );

        // confCons_v2_6_passwordis_Password.xml — the same scheme under a
        // password the owner chose, which is the other marker.
        assert_eq!(
            Decryptor::new(GCM, "Password")
                .decrypt(
                    "e/T6ajrPtNNlHreSeD4QBqToTuiqtNACKiPJv7vU+l6TWCu9JNsmL+Y8lJ4aTl5YVcstXpQj\
                     xsZ9i8+YV4Gs"
                )
                .unwrap()
                .expose(),
            "ThisIsProtected"
        );

        // confCons_v2_6_5k-iterations.xml — the iteration count in the document
        // is the one the key is derived with, and not a constant.
        let five_thousand = CipherMode::Gcm { iterations: 5000 };
        assert_eq!(
            Decryptor::with_default_password(five_thousand)
                .decrypt(
                    "Z1IOT8h7neJ5V7es5Iv63A2WsDG6QWl10F/Rb9ljKxvCseEITty1BfMNgiaVPfm7w61uabQK\
                     qu2waDCXUpLo1OZW"
                )
                .unwrap()
                .expose(),
            "ThisIsNotProtected"
        );
        assert!(
            Decryptor::with_default_password(GCM)
                .decrypt(
                    "Z1IOT8h7neJ5V7es5Iv63A2WsDG6QWl10F/Rb9ljKxvCseEITty1BfMNgiaVPfm7w61uabQK\
                     qu2waDCXUpLo1OZW"
                )
                .is_err(),
            "the declared iteration count is being ignored"
        );

        // confCons_v2_5.xml — the legacy scheme, from before 1.75.
        assert_eq!(
            Decryptor::with_default_password(CipherMode::Cbc)
                .decrypt("95syzRuZ4mRxpNkZQzoyX8SDpQXLyMq3GncO8o4SyTBoYvn3TAWgn05ZEU2DrjkM")
                .unwrap()
                .expose(),
            "ThisIsNotProtected"
        );
        assert_eq!(
            Decryptor::with_default_password(CipherMode::Cbc)
                .decrypt("u1cFYiN+39rnIjT9JOVgqzF0LwDD08ON/32tXV6aMw8=")
                .unwrap()
                .expose(),
            "folder1"
        );
    }

    #[test]
    fn a_recovered_plaintext_does_not_print_itself() {
        let ciphertext = encrypt(GCM, "swordfish", "hunter2", 1);
        let plaintext = Decryptor::new(GCM, "swordfish")
            .decrypt(&ciphertext)
            .unwrap();
        assert_eq!(format!("{plaintext:?}"), "ImportedSecret(<redacted>)");
    }
}
