//! Key slots: LUKS-style wrapping of the vault master key.
//!
//! Each slot holds its own copy of the VMK, sealed under a key-encryption key
//! that only one unlock method can produce. Adding, rotating or revoking a
//! method rewrites one slot and leaves the multi-megabyte body alone.
//!
//! The wrapping associated data is
//! `"remoter:slot:v1" ‖ slot.index ‖ slot.kind`. Binding the index and the kind
//! is what stops an attacker moving a wrapped VMK from a weakly-protected slot
//! into one the interface presents as strong: the ciphertext simply will not
//! open in its new position.
//!
//! # Why only the password slot uses Argon2id
//!
//! A memory-hard KDF makes guessing expensive, and guessing is only a threat
//! when the input has little entropy. A 256-bit recovery key, a keychain token
//! and a FIDO2 `hmac-secret` output all have full entropy already, so a second
//! of Argon2id on them buys nothing measurable and costs a second in an
//! emergency. HKDF is the right tool there. This is analysis, not a shortcut.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN, KeyBytes, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::{UnlockError, VaultError};
use crate::header::{KdfParams, KeySlot, SlotExtra, SlotKind};
use crate::recovery::RecoveryKey;
use crate::secret::{ExposeSecret, Secret};

/// Domain separator for slot wrapping.
const SLOT_AAD_PREFIX: &[u8] = b"remoter:slot:v1";

/// HKDF info strings, one per high-entropy slot kind.
const INFO_RECOVERY: &[u8] = b"remoter:slot:recovery:v1";
const INFO_KEYCHAIN: &[u8] = b"remoter:slot:keychain:v1";
#[allow(dead_code, reason = "used once the CTAP2 unlock path lands")]
const INFO_FIDO2: &[u8] = b"remoter:slot:fido2:v1";

/// Service name used in the platform credential store.
const KEYCHAIN_SERVICE: &str = "remoter-vault";

/// Recorded in a password slot when the password bytes were used as typed.
///
/// Only slots written before NFKC landed carry this. It stays readable
/// forever: re-deriving such a slot from normalised bytes would produce a
/// different key and lock its owner out.
pub(crate) const NORMALISATION_NONE: &str = "none";

/// Recorded in every password slot this build writes.
pub(crate) const NORMALISATION_NFKC: &str = "nfkc";

/// Largest key file this build will read, in bytes.
///
/// A key file's whole contribution is its BLAKE3 digest, so size buys nothing
/// past the first few bytes. The bound exists so that pointing the key file
/// picker at a disk image does not try to hash a hundred gigabytes.
const MAX_KEYFILE_BYTES: u64 = 64 * 1024 * 1024;

/// How the user is unlocking.
///
/// `Debug` is derived: every variant that carries anything sensitive carries it
/// inside a redacting wrapper, so the derived output is safe to log.
#[derive(Debug)]
pub enum UnlockMethod {
    /// A password, optionally combined with a key file.
    Password {
        /// The password as typed.
        password: Secret<String>,
        /// The key file the slot was created with, if it has one.
        keyfile: Option<PathBuf>,
    },
    /// The recovery key issued when the vault was created.
    Recovery {
        /// The parsed key.
        key: RecoveryKey,
    },
    /// The token this machine filed in its platform credential store.
    Keychain,
    /// A CTAP2 authenticator. Not implemented in this version.
    Fido2,
}

impl UnlockMethod {
    /// A password-only unlock.
    #[must_use]
    pub fn password(password: Secret<String>) -> Self {
        Self::Password {
            password,
            keyfile: None,
        }
    }

    /// A password-plus-key-file unlock.
    #[must_use]
    pub fn password_with_keyfile(password: Secret<String>, keyfile: impl Into<PathBuf>) -> Self {
        Self::Password {
            password,
            keyfile: Some(keyfile.into()),
        }
    }

    /// A recovery-key unlock.
    #[must_use]
    pub fn recovery(key: RecoveryKey) -> Self {
        Self::Recovery { key }
    }

    /// Which slot kind this method can open.
    #[must_use]
    pub const fn kind(&self) -> SlotKind {
        match self {
            Self::Password { .. } => SlotKind::Password,
            Self::Recovery { .. } => SlotKind::Recovery,
            Self::Keychain => SlotKind::Keychain,
            Self::Fido2 => SlotKind::Fido2,
        }
    }
}

/// A password, and the key file that goes with it if the slot has one.
///
/// The pair travels together because a password slot's key-encryption key is
/// derived from both: passing them separately through four call sites is how
/// one of them ends up forgotten.
#[derive(Debug)]
pub struct PasswordCredential {
    password: Secret<String>,
    keyfile: Option<PathBuf>,
}

impl PasswordCredential {
    /// A password with no key file.
    #[must_use]
    pub const fn new(password: Secret<String>) -> Self {
        Self {
            password,
            keyfile: None,
        }
    }

    /// The same, with a key file as the second factor.
    #[must_use]
    pub fn with_keyfile(mut self, path: impl Into<PathBuf>) -> Self {
        self.keyfile = Some(path.into());
        self
    }

    pub(crate) const fn password(&self) -> &Secret<String> {
        &self.password
    }

    pub(crate) fn keyfile(&self) -> Option<&Path> {
        self.keyfile.as_deref()
    }
}

/// What a vault master key rotation should do with each existing slot.
///
/// A rotation replaces the master key, so every slot has to be rebuilt around
/// the new one. A password slot cannot be rebuilt without its password — the
/// vault holds the wrapped key, never the credential that unwraps it — so the
/// plan is where the caller supplies them. A slot with neither a credential nor
/// an explicit `dropping` is a refusal, not a silent deletion: quietly
/// discarding a slot takes away someone's way in.
///
/// Recovery slots are re-issued and their new keys returned; keychain slots are
/// re-wrapped under the token already in the platform store.
#[derive(Debug, Default)]
pub struct RotationPlan {
    passwords: Vec<(u8, PasswordCredential)>,
    dropped: std::collections::BTreeSet<u8>,
}

impl RotationPlan {
    /// A plan that keeps nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Supplies the credential that re-wraps the password slot at `index`.
    #[must_use]
    pub fn with_password(mut self, index: u8, credential: PasswordCredential) -> Self {
        self.passwords.retain(|(existing, _)| *existing != index);
        self.passwords.push((index, credential));
        self
    }

    /// Discards the slot at `index` rather than re-wrapping it.
    ///
    /// The deliberate half of the refusal above: a hardware key that is not to
    /// hand, or a password nobody remembers, is dropped by saying so.
    #[must_use]
    pub fn dropping(mut self, index: u8) -> Self {
        self.dropped.insert(index);
        self
    }

    pub(crate) fn password_for(&self, index: u8) -> Option<&PasswordCredential> {
        self.passwords
            .iter()
            .find(|(existing, _)| *existing == index)
            .map(|(_, credential)| credential)
    }

    pub(crate) fn drops(&self, index: u8) -> bool {
        self.dropped.contains(&index)
    }
}

/// What a master key rotation did.
///
/// `Debug` is derived and safe: [`RecoveryKey`] redacts itself.
#[derive(Debug)]
pub struct RotationOutcome {
    /// Slots re-wrapped around the new master key, in index order.
    pub rewrapped: Vec<u8>,
    /// Slots the plan discarded.
    pub dropped: Vec<u8>,
    /// The new recovery keys, one per recovery slot, each shown exactly once.
    /// Nothing in the file can reproduce them.
    pub recovery_keys: Vec<(u8, RecoveryKey)>,
    /// How many stored secret fields were re-sealed under the new field key.
    pub secrets_resealed: usize,
}

/// The associated data a slot's wrapped key is bound to.
pub(crate) fn slot_aad(index: u8, kind: SlotKind) -> Vec<u8> {
    let kind = kind.as_str().as_bytes();
    let mut aad = Vec::with_capacity(SLOT_AAD_PREFIX.len() + 1 + kind.len());
    aad.extend_from_slice(SLOT_AAD_PREFIX);
    aad.push(index);
    aad.extend_from_slice(kind);
    aad
}

/// Seals the master key under a slot's key-encryption key.
pub(crate) fn wrap_vmk(
    kek: &[u8; KEY_LEN],
    index: u8,
    kind: SlotKind,
    vmk: &[u8; KEY_LEN],
) -> Result<([u8; NONCE_LEN], Vec<u8>), VaultError> {
    let nonce: [u8; NONCE_LEN] = crypto::random_array()?;
    let wrapped = crypto::seal(kek, &nonce, vmk, &slot_aad(index, kind))?;
    debug_assert_eq!(wrapped.len(), KEY_LEN + TAG_LEN);
    Ok((nonce, wrapped))
}

/// Opens a slot's wrapped master key.
///
/// A tag mismatch here is the ordinary "wrong password" case, so the caller
/// must translate it into [`UnlockError::NotUnlocked`] rather than passing the
/// underlying error along.
pub(crate) fn unwrap_vmk(kek: &[u8; KEY_LEN], slot: &KeySlot) -> Result<KeyBytes, VaultError> {
    slot.validate()?;
    let nonce = slot.nonce_array()?;
    let plaintext = crypto::open(
        kek,
        &nonce,
        &slot.wrapped_vmk,
        &slot_aad(slot.index, slot.kind),
    )?;
    let bytes: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Aead)?;
    Ok(Zeroizing::new(bytes))
}

/// Prepares the password bytes that go into Argon2id.
///
/// `docs/security/vault-format.md` calls for Unicode NFKC normalisation, so
/// that a password typed on a different keyboard layout or through a different
/// input method still matches. Without it, a user who enrols `é` as U+00E9 and
/// later types `e` followed by U+0301 is locked out of their own vault — the
/// two are different byte strings and Argon2id has no way to know they were
/// meant to be the same character.
///
/// Which normalisation a slot used is recorded per slot — see
/// [`SlotExtra::password_normalisation`] — rather than assumed from the build.
/// That is what lets `"none"` slots written before this landed keep opening
/// from the bytes as typed while new slots record `"nfkc"`.
fn normalise_password(
    password: &str,
    normalisation: &str,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    match normalisation {
        NORMALISATION_NONE => Ok(Zeroizing::new(password.as_bytes().to_vec())),
        NORMALISATION_NFKC => {
            // The intermediate `String` is a second copy of the password, so it
            // is wiped when this function returns rather than left in the
            // allocator for whoever gets the block next.
            let normalised: Zeroizing<String> = Zeroizing::new(
                unicode_normalization::UnicodeNormalization::nfkc(password).collect(),
            );
            Ok(Zeroizing::new(normalised.as_bytes().to_vec()))
        }
        // A slot written by a build that knows a normalisation this one does
        // not must fail closed: deriving from the raw bytes would silently
        // produce the wrong key and report it as a wrong password.
        _ => Err(VaultError::UnsupportedFormat(crate::header::FORMAT_VERSION)),
    }
}

/// Which normalisation a password slot recorded, defaulting to
/// [`NORMALISATION_NONE`] for a slot that predates the field.
pub(crate) fn normalisation_of(slot: &KeySlot) -> &str {
    slot.extra
        .as_ref()
        .and_then(|e| e.password_normalisation.as_deref())
        .unwrap_or(NORMALISATION_NONE)
}

/// `BLAKE3(file_bytes)` — the key file's whole contribution.
pub(crate) fn keyfile_digest(path: &Path) -> Result<[u8; 32], VaultError> {
    let metadata = std::fs::metadata(path).map_err(|_| VaultError::Keyfile)?;
    if metadata.len() > MAX_KEYFILE_BYTES {
        return Err(VaultError::Keyfile);
    }
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| VaultError::Keyfile)?);
    Ok(crypto::digest(&bytes))
}

/// Argon2id over `password ‖ keyfile_digest`, per the specification.
pub(crate) fn password_kek(
    password: &str,
    normalisation: &str,
    keyfile: Option<&Path>,
    salt: &[u8],
    params: &KdfParams,
) -> Result<KeyBytes, VaultError> {
    let normalised = normalise_password(password, normalisation)?;

    let mut input = Zeroizing::new(Vec::with_capacity(normalised.len() + 32));
    input.extend_from_slice(&normalised);
    if let Some(path) = keyfile {
        input.extend_from_slice(&keyfile_digest(path)?);
    }

    crypto::argon2id(&input, salt, params)
}

/// HKDF over the recovery key. Not Argon2id — see the module documentation.
pub(crate) fn recovery_kek(key: &RecoveryKey, salt: &[u8]) -> Result<KeyBytes, VaultError> {
    crypto::hkdf_sha256(key.as_bytes(), Some(salt), INFO_RECOVERY)
}

/// HKDF over the keychain token.
pub(crate) fn keychain_kek(token: &[u8], salt: &[u8]) -> Result<KeyBytes, VaultError> {
    crypto::hkdf_sha256(token, Some(salt), INFO_KEYCHAIN)
}

/// The account name a vault's keychain token is filed under.
pub(crate) fn keychain_account(vault_id: uuid::Uuid, index: u8) -> String {
    format!("{vault_id}#{index}")
}

/// Stores a keychain token in the platform credential store.
pub(crate) fn keychain_store(account: &str, token: &[u8]) -> Result<(), VaultError> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|_| VaultError::Keychain)?;
    entry.set_secret(token).map_err(|_| VaultError::Keychain)
}

/// Reads a keychain token back.
///
/// Absence is not an error worth distinguishing: a vault file carried to
/// another machine simply has no token there, and the slot is skipped.
pub(crate) fn keychain_load(account: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|_| VaultError::Keychain)?;
    let secret = entry.get_secret().map_err(|_| VaultError::Keychain)?;
    Ok(Zeroizing::new(secret))
}

/// Removes a keychain token. Missing is success: the goal is that it is gone.
pub(crate) fn keychain_forget(account: &str) -> Result<(), VaultError> {
    match keyring::Entry::new(KEYCHAIN_SERVICE, account) {
        Ok(entry) => {
            let _ = entry.delete_credential();
            Ok(())
        }
        Err(_) => Ok(()),
    }
}

/// Builds a password slot around a freshly wrapped master key.
///
/// The cost floor is checked one layer up, in `vault.rs`, because that is where
/// the caller's intent is known. This function will happily wrap a key under
/// whatever parameters it is handed, which is also what lets it re-derive a
/// slot written by an older build with weaker settings.
pub(crate) fn new_password_slot(
    index: u8,
    label: String,
    now: i64,
    password: &Secret<String>,
    keyfile: Option<&Path>,
    params: KdfParams,
    vmk: &[u8; KEY_LEN],
) -> Result<KeySlot, VaultError> {
    let salt: [u8; SALT_LEN] = crypto::random_array()?;
    let kek = password_kek(
        password.expose_secret(),
        NORMALISATION_NFKC,
        keyfile,
        &salt,
        &params,
    )?;
    let (nonce, wrapped) = wrap_vmk(&kek, index, SlotKind::Password, vmk)?;

    Ok(KeySlot {
        index,
        kind: SlotKind::Password,
        label,
        created_at: now,
        last_used: None,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        wrapped_vmk: wrapped,
        kdf_params: Some(params),
        extra: Some(SlotExtra {
            requires_keyfile: Some(keyfile.is_some()),
            password_normalisation: Some(NORMALISATION_NFKC.to_owned()),
            ..SlotExtra::default()
        }),
    })
}

/// Builds a recovery slot and returns the key that opens it.
pub(crate) fn new_recovery_slot(
    index: u8,
    label: String,
    now: i64,
    vmk: &[u8; KEY_LEN],
) -> Result<(KeySlot, RecoveryKey), VaultError> {
    let key = RecoveryKey::generate()?;
    let salt: [u8; SALT_LEN] = crypto::random_array()?;
    let kek = recovery_kek(&key, &salt)?;
    let (nonce, wrapped) = wrap_vmk(&kek, index, SlotKind::Recovery, vmk)?;

    let slot = KeySlot {
        index,
        kind: SlotKind::Recovery,
        label,
        created_at: now,
        last_used: None,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        wrapped_vmk: wrapped,
        kdf_params: None,
        extra: None,
    };
    Ok((slot, key))
}

/// Builds a keychain slot, generating a token and filing it with the platform.
pub(crate) fn new_keychain_slot(
    index: u8,
    label: String,
    now: i64,
    vault_id: uuid::Uuid,
    vmk: &[u8; KEY_LEN],
) -> Result<KeySlot, VaultError> {
    let token = crypto::random_key()?;
    let account = keychain_account(vault_id, index);
    keychain_store(&account, token.as_slice())?;

    let salt: [u8; SALT_LEN] = crypto::random_array()?;
    let kek = keychain_kek(token.as_slice(), &salt)?;
    let (nonce, wrapped) = wrap_vmk(&kek, index, SlotKind::Keychain, vmk)?;

    Ok(KeySlot {
        index,
        kind: SlotKind::Keychain,
        label,
        created_at: now,
        last_used: None,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        wrapped_vmk: wrapped,
        kdf_params: None,
        extra: Some(SlotExtra {
            keychain_account: Some(account),
            ..SlotExtra::default()
        }),
    })
}

/// The account name a keychain slot's token is filed under.
fn keychain_account_of(slot: &KeySlot, vault_id: uuid::Uuid) -> String {
    slot.extra
        .as_ref()
        .and_then(|e| e.keychain_account.clone())
        .unwrap_or_else(|| keychain_account(vault_id, slot.index))
}

/// Whether this machine holds the token a keychain slot was built around.
///
/// A vault file carried to another machine has keychain slots whose tokens are
/// not here; a master key rotation has to know that before it starts, because a
/// slot it cannot rebuild is a slot it must refuse rather than silently drop.
pub(crate) fn keychain_token_available(slot: &KeySlot, vault_id: uuid::Uuid) -> bool {
    keychain_load(&keychain_account_of(slot, vault_id)).is_ok()
}

/// Rebuilds a keychain slot around a new master key, reusing the token the
/// platform store already holds.
///
/// The token is not re-minted. It is not the material a leaked vault file
/// exposes — it never appears in the file — and replacing it would break every
/// other machine enrolled under the same account name while adding nothing to
/// what the rotation is for. The salt and the wrapping nonce are fresh, so the
/// slot's ciphertext is new even though its input is not.
pub(crate) fn rewrap_keychain_slot(
    slot: &KeySlot,
    vault_id: uuid::Uuid,
    vmk: &[u8; KEY_LEN],
) -> Result<KeySlot, VaultError> {
    let account = keychain_account_of(slot, vault_id);
    let token = keychain_load(&account)?;

    let salt: [u8; SALT_LEN] = crypto::random_array()?;
    let kek = keychain_kek(&token, &salt)?;
    let (nonce, wrapped) = wrap_vmk(&kek, slot.index, SlotKind::Keychain, vmk)?;

    Ok(KeySlot {
        index: slot.index,
        kind: SlotKind::Keychain,
        label: slot.label.clone(),
        created_at: slot.created_at,
        last_used: slot.last_used,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        wrapped_vmk: wrapped,
        kdf_params: None,
        extra: Some(SlotExtra {
            keychain_account: Some(account),
            ..SlotExtra::default()
        }),
    })
}

/// Derives the key-encryption key for one slot from one unlock method.
///
/// Returns `Ok(None)` when this slot cannot be attempted at all — a keychain
/// slot on a machine that has no token for it, a password slot that wants a key
/// file the caller did not supply. The caller treats that the same as a failed
/// unwrap, because saying "this vault expects a key file" would tell an
/// attacker which half of the pair they still need.
pub(crate) fn kek_for(
    slot: &KeySlot,
    method: &UnlockMethod,
    vault_id: uuid::Uuid,
) -> Result<Option<KeyBytes>, UnlockError> {
    match (slot.kind, method) {
        (SlotKind::Password, UnlockMethod::Password { password, keyfile }) => {
            let params = slot.kdf_params.ok_or(UnlockError::NotUnlocked)?;
            let normalisation = normalisation_of(slot);
            let salt = slot.salt_array().map_err(UnlockError::Vault)?;

            match password_kek(
                password.expose_secret(),
                normalisation,
                keyfile.as_deref(),
                &salt,
                &params,
            ) {
                Ok(kek) => Ok(Some(kek)),
                // A missing or unreadable key file is indistinguishable from a
                // wrong password by design.
                Err(VaultError::Keyfile) => Ok(None),
                Err(e) => Err(UnlockError::Vault(e)),
            }
        }

        (SlotKind::Recovery, UnlockMethod::Recovery { key }) => {
            let salt = slot.salt_array().map_err(UnlockError::Vault)?;
            recovery_kek(key, &salt)
                .map(Some)
                .map_err(UnlockError::Vault)
        }

        (SlotKind::Keychain, UnlockMethod::Keychain) => {
            let account = slot
                .extra
                .as_ref()
                .and_then(|e| e.keychain_account.clone())
                .unwrap_or_else(|| keychain_account(vault_id, slot.index));
            let salt = slot.salt_array().map_err(UnlockError::Vault)?;

            match keychain_load(&account) {
                Ok(token) => keychain_kek(&token, &salt)
                    .map(Some)
                    .map_err(UnlockError::Vault),
                // No token on this machine: the slot simply does not apply here.
                Err(_) => Ok(None),
            }
        }

        (_, UnlockMethod::Fido2) => Err(UnlockError::Fido2Unsupported),

        // Kind and method disagree; the caller filtered wrongly.
        _ => Ok(None),
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
    use crate::header::SlotKind;

    fn vmk() -> KeyBytes {
        crypto::random_key().unwrap()
    }

    #[test]
    fn the_wrapping_associated_data_matches_the_specification() {
        let aad = slot_aad(3, SlotKind::Password);
        let mut expected = b"remoter:slot:v1".to_vec();
        expected.push(3);
        expected.extend_from_slice(b"password");
        assert_eq!(aad, expected);
    }

    #[test]
    fn password_slots_round_trip() {
        let vmk = vmk();
        let password = Secret::new(String::from("a long enough master password"));
        let slot = new_password_slot(
            0,
            "Master password".into(),
            10,
            &password,
            None,
            KdfParams::low_cost_for_tests(),
            &vmk,
        )
        .unwrap();

        let method =
            UnlockMethod::password(Secret::new(String::from("a long enough master password")));
        let kek = kek_for(&slot, &method, uuid::Uuid::nil()).unwrap().unwrap();
        let opened = unwrap_vmk(&kek, &slot).unwrap();
        assert_eq!(opened.as_slice(), vmk.as_slice());
    }

    #[test]
    fn a_wrong_password_does_not_unwrap() {
        let vmk = vmk();
        let slot = new_password_slot(
            0,
            "Master password".into(),
            10,
            &Secret::new(String::from("right")),
            None,
            KdfParams::low_cost_for_tests(),
            &vmk,
        )
        .unwrap();

        let method = UnlockMethod::password(Secret::new(String::from("wrong")));
        let kek = kek_for(&slot, &method, uuid::Uuid::nil()).unwrap().unwrap();
        assert!(unwrap_vmk(&kek, &slot).is_err());
    }

    #[test]
    fn recovery_slots_round_trip() {
        let vmk = vmk();
        let (slot, key) = new_recovery_slot(1, "Recovery key".into(), 10, &vmk).unwrap();

        let printed = key.printable().unwrap();
        let retyped = RecoveryKey::parse(&printed).unwrap();
        let method = UnlockMethod::recovery(retyped);

        let kek = kek_for(&slot, &method, uuid::Uuid::nil()).unwrap().unwrap();
        let opened = unwrap_vmk(&kek, &slot).unwrap();
        assert_eq!(opened.as_slice(), vmk.as_slice());
    }

    #[test]
    fn keychain_slots_round_trip_without_touching_the_platform() {
        // The credential store is not available in a test runner, so the token
        // is supplied directly. What is under test is the derivation and the
        // wrapping, not the platform integration.
        let vmk = vmk();
        let token = crypto::random_key().unwrap();
        let salt: [u8; SALT_LEN] = crypto::random_array().unwrap();
        let kek = keychain_kek(token.as_slice(), &salt).unwrap();
        let (nonce, wrapped) = wrap_vmk(&kek, 2, SlotKind::Keychain, &vmk).unwrap();

        let slot = KeySlot {
            index: 2,
            kind: SlotKind::Keychain,
            label: "This device".into(),
            created_at: 10,
            last_used: None,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            wrapped_vmk: wrapped,
            kdf_params: None,
            extra: None,
        };

        let again = keychain_kek(token.as_slice(), &salt).unwrap();
        let opened = unwrap_vmk(&again, &slot).unwrap();
        assert_eq!(opened.as_slice(), vmk.as_slice());
    }

    #[test]
    fn a_wrapped_key_cannot_be_moved_to_another_slot_index() {
        let vmk = vmk();
        let kek = crypto::random_key().unwrap();
        let (nonce, wrapped) = wrap_vmk(&kek, 0, SlotKind::Password, &vmk).unwrap();

        let mut moved = KeySlot {
            index: 1,
            kind: SlotKind::Password,
            label: "Moved".into(),
            created_at: 0,
            last_used: None,
            salt: vec![0; SALT_LEN],
            nonce: nonce.to_vec(),
            wrapped_vmk: wrapped,
            kdf_params: Some(KdfParams::floor()),
            extra: None,
        };
        assert!(unwrap_vmk(&kek, &moved).is_err());

        moved.index = 0;
        assert!(unwrap_vmk(&kek, &moved).is_ok());
    }

    #[test]
    fn a_wrapped_key_cannot_be_relabelled_as_another_kind() {
        let vmk = vmk();
        let kek = crypto::random_key().unwrap();
        let (nonce, wrapped) = wrap_vmk(&kek, 0, SlotKind::Recovery, &vmk).unwrap();

        let mut slot = KeySlot {
            index: 0,
            kind: SlotKind::Password,
            label: "Relabelled".into(),
            created_at: 0,
            last_used: None,
            salt: vec![0; SALT_LEN],
            nonce: nonce.to_vec(),
            wrapped_vmk: wrapped,
            kdf_params: Some(KdfParams::floor()),
            extra: None,
        };
        assert!(unwrap_vmk(&kek, &slot).is_err());

        slot.kind = SlotKind::Recovery;
        assert!(unwrap_vmk(&kek, &slot).is_ok());
    }

    #[test]
    fn a_key_file_changes_the_derived_key() {
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("vault.key");
        std::fs::write(&keyfile, b"some key file bytes").unwrap();

        let salt = [4u8; SALT_LEN];
        let params = KdfParams::low_cost_for_tests();

        let without = password_kek("pw", NORMALISATION_NONE, None, &salt, &params).unwrap();
        let with = password_kek(
            "pw",
            NORMALISATION_NONE,
            Some(keyfile.as_path()),
            &salt,
            &params,
        )
        .unwrap();
        assert_ne!(without.as_slice(), with.as_slice());
    }

    #[test]
    fn a_changed_key_file_no_longer_derives_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("vault.key");
        std::fs::write(&keyfile, b"original").unwrap();

        let salt = [4u8; SALT_LEN];
        let params = KdfParams::low_cost_for_tests();
        let before = password_kek(
            "pw",
            NORMALISATION_NONE,
            Some(keyfile.as_path()),
            &salt,
            &params,
        )
        .unwrap();

        std::fs::write(&keyfile, b"tampered").unwrap();
        let after = password_kek(
            "pw",
            NORMALISATION_NONE,
            Some(keyfile.as_path()),
            &salt,
            &params,
        )
        .unwrap();

        assert_ne!(before.as_slice(), after.as_slice());
    }

    #[test]
    fn an_unknown_normalisation_fails_closed() {
        assert!(normalise_password("pw", "nfd").is_err());
        assert!(normalise_password("pw", NORMALISATION_NONE).is_ok());
        assert!(normalise_password("pw", NORMALISATION_NFKC).is_ok());
    }

    /// `é` as one code point, and as `e` plus a combining acute accent. Two
    /// different byte strings, the same character, and what a user gets
    /// depending on the keyboard layout or input method they typed it with.
    const PRECOMPOSED: &str = "caf\u{00E9} pass";
    const DECOMPOSED: &str = "cafe\u{0301} pass";

    #[test]
    fn nfkc_makes_the_two_spellings_of_the_same_password_agree() {
        assert_ne!(
            PRECOMPOSED.as_bytes(),
            DECOMPOSED.as_bytes(),
            "the fixtures must differ as bytes or the test proves nothing"
        );

        let salt = [11u8; SALT_LEN];
        let params = KdfParams::low_cost_for_tests();

        let a = password_kek(PRECOMPOSED, NORMALISATION_NFKC, None, &salt, &params).unwrap();
        let b = password_kek(DECOMPOSED, NORMALISATION_NFKC, None, &salt, &params).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn a_new_password_slot_opens_from_either_spelling() {
        let vmk = vmk();
        let slot = new_password_slot(
            0,
            "Master password".into(),
            10,
            &Secret::new(String::from(PRECOMPOSED)),
            None,
            KdfParams::low_cost_for_tests(),
            &vmk,
        )
        .unwrap();

        assert_eq!(
            slot.extra
                .as_ref()
                .and_then(|e| e.password_normalisation.as_deref()),
            Some(NORMALISATION_NFKC),
            "slots written now must record the normalisation they used"
        );

        for typed in [PRECOMPOSED, DECOMPOSED] {
            let method = UnlockMethod::password(Secret::new(String::from(typed)));
            let kek = kek_for(&slot, &method, uuid::Uuid::nil()).unwrap().unwrap();
            let opened = unwrap_vmk(&kek, &slot).unwrap();
            assert_eq!(opened.as_slice(), vmk.as_slice(), "failed for {typed:?}");
        }
    }

    #[test]
    fn a_slot_recorded_as_none_still_opens_from_the_raw_bytes() {
        // What a vault written before NFKC landed looks like: the slot says
        // "none", so the decomposed spelling must NOT open it and the exact
        // bytes must.
        let vmk = vmk();
        let salt: [u8; SALT_LEN] = crypto::random_array().unwrap();
        let params = KdfParams::low_cost_for_tests();
        let kek = password_kek(PRECOMPOSED, NORMALISATION_NONE, None, &salt, &params).unwrap();
        let (nonce, wrapped) = wrap_vmk(&kek, 0, SlotKind::Password, &vmk).unwrap();

        let slot = KeySlot {
            index: 0,
            kind: SlotKind::Password,
            label: "Older build".into(),
            created_at: 10,
            last_used: None,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            wrapped_vmk: wrapped,
            kdf_params: Some(params),
            extra: Some(SlotExtra {
                requires_keyfile: Some(false),
                password_normalisation: Some(NORMALISATION_NONE.to_owned()),
                ..SlotExtra::default()
            }),
        };

        let method = UnlockMethod::password(Secret::new(String::from(PRECOMPOSED)));
        let kek = kek_for(&slot, &method, uuid::Uuid::nil()).unwrap().unwrap();
        assert_eq!(unwrap_vmk(&kek, &slot).unwrap().as_slice(), vmk.as_slice());

        let method = UnlockMethod::password(Secret::new(String::from(DECOMPOSED)));
        let kek = kek_for(&slot, &method, uuid::Uuid::nil()).unwrap().unwrap();
        assert!(
            unwrap_vmk(&kek, &slot).is_err(),
            "a \"none\" slot must keep deriving from the bytes as typed"
        );
    }

    #[test]
    fn fido2_is_refused_rather_than_guessed() {
        let slot = KeySlot {
            index: 0,
            kind: SlotKind::Fido2,
            label: "YubiKey".into(),
            created_at: 0,
            last_used: None,
            salt: vec![0; SALT_LEN],
            nonce: vec![0; NONCE_LEN],
            wrapped_vmk: vec![0; KEY_LEN + TAG_LEN],
            kdf_params: None,
            extra: None,
        };
        assert!(matches!(
            kek_for(&slot, &UnlockMethod::Fido2, uuid::Uuid::nil()),
            Err(UnlockError::Fido2Unsupported)
        ));
    }

    #[test]
    fn an_oversized_key_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.bin");
        std::fs::write(&path, b"small enough").unwrap();
        assert!(keyfile_digest(&path).is_ok());
        assert!(keyfile_digest(&dir.path().join("absent.bin")).is_err());
    }
}
