//! Confirming the vault's password while it is open.
//!
//! `Vault::password_check` is what stands between "the vault is open" and "a
//! stored password is shown on screen". These tests hold it to the three
//! things that gate has to get right: the vault's own password passes, any
//! other password does not, and a key file is offered only to the slots that
//! were created with one — so a vault with a password-only slot beside a
//! key-file slot confirms with either.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::fs;
use std::path::{Path, PathBuf};

use remoter_vault::{CreateOptions, KdfParams, Secret, Vault};

const PASSWORD: &str = "a master password";
const SECOND_PASSWORD: &str = "the password on the second slot";
const KEYFILE_BYTES: &[u8] = b"the bytes this vault was created around";

fn secret(text: &str) -> Secret<String> {
    Secret::new(String::from(text))
}

fn keyfile_at(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn create(dir: &Path, keyfile: Option<&Path>) -> Vault {
    let mut options = CreateOptions::new(dir.join("acme.rvault"), "Acme", secret(PASSWORD))
        .with_kdf_params(KdfParams::low_cost_for_tests());
    if let Some(keyfile) = keyfile {
        options = options.with_keyfile(keyfile.to_path_buf());
    }
    Vault::create(options).unwrap().0
}

#[test]
fn the_vaults_own_password_is_confirmed_and_another_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create(dir.path(), None);
    let check = vault.password_check();

    assert!(check.has_password_slot());
    assert!(check.verify(&secret(PASSWORD), None).unwrap());
    assert!(!check.verify(&secret("not the password"), None).unwrap());
    assert!(!check.verify(&secret(""), None).unwrap());
}

#[test]
fn a_key_file_slot_needs_its_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "vault.key", KEYFILE_BYTES);
    let wrong = keyfile_at(dir.path(), "other.key", b"some other bytes entirely");
    let vault = create(dir.path(), Some(&keyfile));
    let check = vault.password_check();

    assert!(check.verify(&secret(PASSWORD), Some(&keyfile)).unwrap());
    assert!(
        !check.verify(&secret(PASSWORD), None).unwrap(),
        "the password alone does not open a slot that also needs a key file"
    );
    assert!(!check.verify(&secret(PASSWORD), Some(&wrong)).unwrap());
    assert!(
        !check
            .verify(&secret(PASSWORD), Some(&dir.path().join("missing.key")))
            .unwrap(),
        "a key file that cannot be read is a refusal, not an error"
    );
}

#[test]
fn a_key_file_is_offered_only_to_the_slots_that_use_one() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = keyfile_at(dir.path(), "vault.key", KEYFILE_BYTES);
    let mut vault = create(dir.path(), Some(&keyfile));
    vault
        .add_password_slot(
            "Second",
            &secret(SECOND_PASSWORD),
            None,
            Some(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
    let check = vault.password_check();

    // The remembered key file is passed along with every attempt, as the
    // interface does. The password-only slot must still match.
    assert!(
        check
            .verify(&secret(SECOND_PASSWORD), Some(&keyfile))
            .unwrap()
    );
    assert!(check.verify(&secret(SECOND_PASSWORD), None).unwrap());
    assert!(check.verify(&secret(PASSWORD), Some(&keyfile)).unwrap());
}

#[test]
fn the_check_outlives_the_vault_and_prints_nothing_secret() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create(dir.path(), None);
    let check = vault.password_check();
    vault.lock();

    // Made under the lock, verified after it is released: that is the point.
    assert!(check.verify(&secret(PASSWORD), None).unwrap());

    let printed = format!("{check:?}");
    assert!(printed.contains("<redacted>"), "{printed}");
    assert!(!printed.contains(PASSWORD));
}
