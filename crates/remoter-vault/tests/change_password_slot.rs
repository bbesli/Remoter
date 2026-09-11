//! Changing the password on one key slot.
//!
//! `Vault::change_password_slot` is the operation behind Vault settings → Key
//! slots → Change. It had no direct coverage: what existed went through
//! [`Vault::change_master_password`], which is a fixed index 0 and therefore
//! could not say whether the indexed form addresses the slot it is given.
//!
//! Every test here proves the credential first — by opening the file with it,
//! or by creating the vault under it — so a refusal below can only be about
//! what the change does with a credential that is known good. The dialog makes
//! three promises in its own words, and each is asserted rather than trusted:
//! the master key does not change, every other slot keeps working, and the
//! recovery keys stay valid.
//!
//! The reported defect is in here too. A key file's contribution is
//! `BLAKE3(file_bytes)`, so reading the file is a step that can fail on its
//! own; folding that failure into "your credential is wrong" is what told an
//! owner their password was wrong when it never was. See
//! `a_key_file_that_cannot_be_read_is_not_reported_as_a_wrong_credential`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::fs;
use std::path::{Path, PathBuf};

use remoter_vault::{
    CreateOptions, KdfParams, PasswordCredential, RecoveryKey, Secret, UnlockError, UnlockMethod,
    Vault, VaultError,
};

const PASSWORD: &str = "a master password";
const NEW_PASSWORD: &str = "a different master password";
const SECOND_PASSWORD: &str = "the password on the second slot";
const KEYFILE_BYTES: &[u8] = b"the bytes this vault was created around";
const OTHER_KEYFILE_BYTES: &[u8] = b"an unrelated file of the same shape";

fn keyfile_at(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

/// A saved vault, created under `PASSWORD` and optionally a key file.
fn create(dir: &Path, keyfile: Option<&Path>) -> (Vault, RecoveryKey, PathBuf) {
    let path = dir.join("acme.rvault");
    let mut options = CreateOptions::new(
        &path,
        "Acme Production",
        Secret::new(String::from(PASSWORD)),
    )
    .with_kdf_params(KdfParams::low_cost_for_tests());
    if let Some(keyfile) = keyfile {
        options = options.with_keyfile(keyfile.to_path_buf());
    }
    let (vault, recovery) = Vault::create(options).unwrap();
    (vault, recovery, path)
}

fn password_only(password: &str) -> PasswordCredential {
    PasswordCredential::new(Secret::new(String::from(password)))
}

fn pair(password: &str, keyfile: &Path) -> PasswordCredential {
    password_only(password).with_keyfile(keyfile)
}

fn open_with_password(path: &Path, password: &str) -> Result<Vault, UnlockError> {
    Vault::open(
        path,
        UnlockMethod::password(Secret::new(String::from(password))),
    )
}

fn open_with_pair(path: &Path, password: &str, keyfile: &Path) -> Result<Vault, UnlockError> {
    Vault::open(
        path,
        UnlockMethod::password_with_keyfile(Secret::new(String::from(password)), keyfile),
    )
}

fn requires_keyfile(vault: &Vault, index: u8) -> bool {
    vault
        .slots()
        .iter()
        .find(|slot| slot.index == index)
        .map(|slot| slot.requires_keyfile)
        .unwrap()
}

// ------------------------------------------------------------ the happy path

/// The owner's case: a slot created with a password *and* a key file, changed
/// under exactly the credential that opens the file.
#[test]
fn the_credential_that_opens_a_key_file_slot_also_changes_its_password() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (vault, _recovery, path) = create(dir.path(), Some(&keyfile));
    vault.lock();

    // Known good: it opens the file.
    let mut vault = open_with_pair(&path, PASSWORD, &keyfile).unwrap();

    let changed = vault.change_password_slot(
        0,
        &pair(PASSWORD, &keyfile),
        &pair(NEW_PASSWORD, &keyfile),
        None,
    );
    assert!(
        changed.is_ok(),
        "the credential that just opened the vault was refused by the change: {changed:?}"
    );
    vault.lock();

    let reopened = open_with_pair(&path, NEW_PASSWORD, &keyfile);
    assert!(
        reopened.is_ok(),
        "the new password and the same key file must open what the change rewrapped: \
         {reopened:?}"
    );
    assert!(requires_keyfile(&reopened.unwrap(), 0));
    assert!(matches!(
        open_with_pair(&path, PASSWORD, &keyfile),
        Err(UnlockError::NotUnlocked)
    ));
}

/// The same through the fixed-index wrapper the settings screen used to reach.
#[test]
fn the_master_password_wrapper_takes_the_same_credential() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (vault, _recovery, path) = create(dir.path(), Some(&keyfile));
    vault.lock();
    let mut vault = open_with_pair(&path, PASSWORD, &keyfile).unwrap();

    let changed = vault.change_master_password(
        &pair(PASSWORD, &keyfile),
        &pair(NEW_PASSWORD, &keyfile),
        None,
    );
    assert!(
        changed.is_ok(),
        "the wrapper refused the credential: {changed:?}"
    );
}

#[test]
fn a_slot_with_no_key_file_changes_its_password() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _recovery, path) = create(dir.path(), None);

    vault
        .change_password_slot(
            0,
            &password_only(PASSWORD),
            &password_only(NEW_PASSWORD),
            None,
        )
        .unwrap();
    vault.lock();

    assert!(open_with_password(&path, NEW_PASSWORD).is_ok());
    assert!(matches!(
        open_with_password(&path, PASSWORD),
        Err(UnlockError::NotUnlocked)
    ));
}

// ------------------------------------------------- adding and removing a file

/// The second factor is chosen at change time, not inherited, so a slot that
/// had no key file can acquire one.
#[test]
fn a_key_file_can_be_added_and_is_required_from_then_on() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (mut vault, _recovery, path) = create(dir.path(), None);

    vault
        .change_password_slot(
            0,
            &password_only(PASSWORD),
            &pair(NEW_PASSWORD, &keyfile),
            None,
        )
        .unwrap();
    vault.lock();

    assert!(
        matches!(
            open_with_password(&path, NEW_PASSWORD),
            Err(UnlockError::NotUnlocked)
        ),
        "the password alone must stop being enough once a key file is enrolled"
    );
    let opened = open_with_pair(&path, NEW_PASSWORD, &keyfile).unwrap();
    assert!(requires_keyfile(&opened, 0), "the slot says it needs one");
}

/// And the other direction: leaving the new key file empty removes it, which is
/// what the dialog's copy promises in as many words.
#[test]
fn a_key_file_can_be_removed_and_is_not_required_from_then_on() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (mut vault, _recovery, path) = create(dir.path(), Some(&keyfile));

    vault
        .change_password_slot(
            0,
            &pair(PASSWORD, &keyfile),
            &password_only(NEW_PASSWORD),
            None,
        )
        .unwrap();
    vault.lock();

    let opened = open_with_password(&path, NEW_PASSWORD).unwrap();
    assert!(
        !requires_keyfile(&opened, 0),
        "a slot changed without a key file must not still advertise one"
    );
    // And the file that used to be the second factor no longer is.
    assert!(
        matches!(
            open_with_pair(&path, NEW_PASSWORD, &keyfile),
            Err(UnlockError::NotUnlocked)
        ),
        "the removed key file must not still be mixed in"
    );
}

// ---------------------------------------------------------------- refusals

/// A rewrap the caller cannot currently open would destroy the only copy of the
/// master key that slot holds. The slot is left byte for byte as it was, and
/// the test proves it by opening with the old credential afterwards.
#[test]
fn a_wrong_current_password_leaves_the_slot_exactly_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (mut vault, _recovery, path) = create(dir.path(), Some(&keyfile));

    let refused = vault.change_password_slot(
        0,
        &pair("not the password", &keyfile),
        &pair(NEW_PASSWORD, &keyfile),
        None,
    );
    assert!(matches!(
        refused,
        Err(VaultError::SlotCredentialRejected(0))
    ));
    vault.lock();

    assert!(
        open_with_pair(&path, PASSWORD, &keyfile).is_ok(),
        "the old credential must still open the slot the change did not touch"
    );
    assert!(matches!(
        open_with_pair(&path, NEW_PASSWORD, &keyfile),
        Err(UnlockError::NotUnlocked)
    ));
}

/// The same guarantee for the other half of the pair.
#[test]
fn the_wrong_key_file_leaves_the_slot_exactly_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let other = keyfile_at(dir.path(), "unrelated.keyfile", OTHER_KEYFILE_BYTES);
    let (mut vault, _recovery, path) = create(dir.path(), Some(&keyfile));

    let refused = vault.change_password_slot(
        0,
        &pair(PASSWORD, &other),
        &pair(NEW_PASSWORD, &keyfile),
        None,
    );
    assert!(matches!(
        refused,
        Err(VaultError::SlotCredentialRejected(0))
    ));
    vault.lock();

    assert!(
        open_with_pair(&path, PASSWORD, &keyfile).is_ok(),
        "the right password with the wrong file must change nothing"
    );
}

/// Half a credential is not a credential. This is the check the whole operation
/// rests on: it must keep refusing.
#[test]
fn a_password_without_the_key_file_its_slot_needs_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (mut vault, _recovery, path) = create(dir.path(), Some(&keyfile));

    let refused = vault.change_password_slot(
        0,
        &password_only(PASSWORD),
        &pair(NEW_PASSWORD, &keyfile),
        None,
    );
    assert!(matches!(
        refused,
        Err(VaultError::SlotCredentialRejected(0))
    ));
    vault.lock();
    assert!(open_with_pair(&path, PASSWORD, &keyfile).is_ok());
}

/// The reported symptom, reproduced from an open vault: the path is right, the
/// password is right, and the file's bytes are not the enrolled ones.
///
/// The refusal is correct — the credential genuinely changed — and the vault
/// staying open is not evidence to the contrary: its master key was unwrapped
/// earlier in the session and the file is not read again until this asks.
#[test]
fn a_key_file_rewritten_after_the_vault_opened_no_longer_changes_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (vault, _recovery, path) = create(dir.path(), Some(&keyfile));
    vault.lock();
    let mut vault = open_with_pair(&path, PASSWORD, &keyfile).unwrap();

    // A re-generated key file, a synchronisation conflict, a restored backup.
    fs::write(&keyfile, OTHER_KEYFILE_BYTES).unwrap();

    let refused = vault.change_password_slot(
        0,
        &pair(PASSWORD, &keyfile),
        &pair(NEW_PASSWORD, &keyfile),
        None,
    );
    assert!(
        matches!(refused, Err(VaultError::SlotCredentialRejected(0))),
        "the enrolled bytes are the credential, not the path: {refused:?}"
    );
}

/// **The defect.** A key file that cannot be *read* is not a wrong credential,
/// and must not be reported as one.
///
/// Reading the file is its own step and it fails on its own: a removable drive
/// that dropped between the unlock and the change, a synchronised file whose
/// local copy is no longer materialised, a path that has become a directory, a
/// file past the size cap. Every one of those used to arrive as "that does not
/// open key slot 0" — a statement about the owner's password, which was never
/// the problem, and the reason this ticket exists.
///
/// A directory stands in for all of them here because it is the one case that
/// behaves the same way on every platform: metadata succeeds, the read does not.
#[test]
fn a_key_file_that_cannot_be_read_is_not_reported_as_a_wrong_credential() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (vault, _recovery, path) = create(dir.path(), Some(&keyfile));
    vault.lock();
    let mut vault = open_with_pair(&path, PASSWORD, &keyfile).unwrap();

    fs::remove_file(&keyfile).unwrap();
    fs::create_dir(&keyfile).unwrap();

    let refused = vault.change_password_slot(
        0,
        &pair(PASSWORD, &keyfile),
        &pair(NEW_PASSWORD, &keyfile),
        None,
    );
    assert!(
        matches!(refused, Err(VaultError::Keyfile)),
        "an unreadable key file must say so rather than accusing the password: {refused:?}"
    );

    // And it is still a refusal: nothing was rewrapped.
    vault.lock();
    fs::remove_dir(&keyfile).unwrap();
    fs::write(&keyfile, KEYFILE_BYTES).unwrap();
    assert!(open_with_pair(&path, PASSWORD, &keyfile).is_ok());
    assert!(matches!(
        open_with_pair(&path, NEW_PASSWORD, &keyfile),
        Err(UnlockError::NotUnlocked)
    ));
}

// ------------------------------------------------------- more than one slot

/// A vault holding two passwords: changing slot 1 changes slot 1.
///
/// Indices are reused — the header hands out the lowest free one — so removing
/// the recovery slot at index 1 and enrolling a password puts a password slot
/// there. That is also what makes the fixed-index wrapper the wrong entry point
/// for a slot the user picked.
#[test]
fn changing_slot_one_changes_slot_one_and_not_slot_zero() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (mut vault, _recovery, path) = create(dir.path(), Some(&keyfile));

    vault.remove_slot(1).unwrap();
    let second = vault
        .add_password_slot(
            "Laptop",
            &Secret::new(String::from(SECOND_PASSWORD)),
            None,
            Some(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
    assert_eq!(second, 1, "the freed index is handed out again");
    let (recovery_index, recovery) = vault.add_recovery_slot("Envelope in the safe").unwrap();
    assert_eq!(recovery_index, 2);
    vault.save().unwrap();

    vault
        .change_password_slot(
            1,
            &password_only(SECOND_PASSWORD),
            &password_only(NEW_PASSWORD),
            None,
        )
        .unwrap();
    vault.lock();

    assert!(
        open_with_password(&path, NEW_PASSWORD).is_ok(),
        "slot 1 is the slot that changed"
    );
    assert!(
        matches!(
            open_with_password(&path, SECOND_PASSWORD),
            Err(UnlockError::NotUnlocked)
        ),
        "slot 1's old password stops working"
    );
    assert!(
        open_with_pair(&path, PASSWORD, &keyfile).is_ok(),
        "slot 0 was not touched"
    );
    assert!(
        requires_keyfile(&open_with_pair(&path, PASSWORD, &keyfile).unwrap(), 0),
        "and it still needs its key file"
    );
    assert!(Vault::open(&path, UnlockMethod::recovery(recovery)).is_ok());
}

/// The promise on the dialog, asserted: "the master key does not change, so
/// nothing is re-encrypted, every other slot keeps working and the recovery
/// keys stay valid".
#[test]
fn every_other_slot_and_the_recovery_key_still_open_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (mut vault, recovery, path) = create(dir.path(), Some(&keyfile));
    vault
        .add_password_slot(
            "Laptop",
            &Secret::new(String::from(SECOND_PASSWORD)),
            None,
            Some(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
    let (_index, second_recovery) = vault.add_recovery_slot("Envelope in the safe").unwrap();
    vault.save().unwrap();

    vault
        .change_password_slot(
            0,
            &pair(PASSWORD, &keyfile),
            &pair(NEW_PASSWORD, &keyfile),
            None,
        )
        .unwrap();
    vault.lock();

    assert!(open_with_pair(&path, NEW_PASSWORD, &keyfile).is_ok());
    assert!(
        open_with_password(&path, SECOND_PASSWORD).is_ok(),
        "the other password slot keeps working"
    );
    let recovered = Vault::open(&path, UnlockMethod::recovery(recovery)).unwrap();
    assert_eq!(
        recovered.label(),
        "Acme Production",
        "the body is readable, so the master key did not move"
    );
    recovered.lock();
    assert!(
        Vault::open(&path, UnlockMethod::recovery(second_recovery)).is_ok(),
        "every recovery key stays valid, not just the first"
    );
}

/// The fixed-index wrapper on a vault whose password is no longer at index 0.
///
/// It refuses by kind rather than rebuilding a recovery slot as a password
/// slot. That guard is the only thing between the wrapper and a destroyed
/// recovery slot, and the wrapper is public API.
#[test]
fn the_slot_zero_wrapper_refuses_a_vault_whose_password_moved() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "devoplus.keyfile", KEYFILE_BYTES);
    let (mut vault, _recovery, path) = create(dir.path(), Some(&keyfile));

    vault.remove_slot(0).unwrap();
    let (recovery_index, recovery) = vault.add_recovery_slot("Envelope in the safe").unwrap();
    assert_eq!(recovery_index, 0);
    let password_index = vault
        .add_password_slot(
            "Master password",
            &Secret::new(String::from(PASSWORD)),
            Some(keyfile.as_path()),
            Some(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
    assert_ne!(password_index, 0);
    vault.save().unwrap();

    let refused = vault.change_master_password(
        &pair(PASSWORD, &keyfile),
        &pair(NEW_PASSWORD, &keyfile),
        None,
    );
    assert!(
        matches!(refused, Err(VaultError::WrongSlotKind { index: 0, .. })),
        "the wrapper must not rebuild a recovery slot as a password slot: {refused:?}"
    );

    // Aimed at the index the password actually lives in, it works.
    vault
        .change_password_slot(
            password_index,
            &pair(PASSWORD, &keyfile),
            &pair(NEW_PASSWORD, &keyfile),
            None,
        )
        .unwrap();
    vault.lock();

    assert!(open_with_pair(&path, NEW_PASSWORD, &keyfile).is_ok());
    assert!(Vault::open(&path, UnlockMethod::recovery(recovery)).is_ok());
}
