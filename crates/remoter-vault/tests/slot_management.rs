//! Managing the slot table from the Vault settings screen.
//!
//! The invariant these exist for: a vault must always retain at least one
//! usable slot, and every operation that touches the table has to leave the file
//! openable by something. Each test therefore ends by actually opening the file
//! again, rather than by inspecting the table in memory — the table in memory is
//! not what a user is locked out of.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::fs;
use std::path::{Path, PathBuf};

use remoter_core::{CredentialProps, Node, NodeKind, SecretKind};
use remoter_vault::{
    CreateOptions, ExposeSecret, KdfParams, PasswordCredential, Purpose, RecoveryKey, RotationPlan,
    Secret, SlotKind, UnlockError, UnlockMethod, Vault, VaultError,
};

const PASSWORD: &str = "a master password";
const NEW_PASSWORD: &str = "a different master password";
const STORED_SECRET: &[u8] = b"correct horse battery staple";

fn create(dir: &Path, name: &str) -> (Vault, RecoveryKey, PathBuf) {
    let path = dir.join(name);
    let (vault, key) = Vault::create(
        CreateOptions::new(
            &path,
            "Acme Production",
            Secret::new(String::from(PASSWORD)),
        )
        .with_kdf_params(KdfParams::low_cost_for_tests()),
    )
    .unwrap();
    (vault, key, path)
}

fn open_with(path: &Path, password: &str) -> Result<Vault, UnlockError> {
    Vault::open(
        path,
        UnlockMethod::password(Secret::new(String::from(password))),
    )
}

fn credential(password: &str) -> PasswordCredential {
    PasswordCredential::new(Secret::new(String::from(password)))
}

/// A credential node carrying one stored password, so that a rotation has
/// something to re-seal.
fn add_secret(vault: &mut Vault) -> uuid::Uuid {
    let mut tree = vault.tree().unwrap();
    let node = Node::new(
        NodeKind::Credential(CredentialProps::new(
            "svc-deploy",
            SecretKind::Password {
                sealed: Vault::sealed_placeholder(),
            },
        )),
        "svc-deploy",
        1_700_000_000_000,
    );
    let id = *node.id.as_uuid();
    let patch = tree.insert(node).unwrap();
    vault.apply(&tree, &patch).unwrap();
    vault
        .set_secret(id, "password", Secret::new(STORED_SECRET.to_vec()))
        .unwrap();
    id
}

fn assert_secret_readable(vault: &mut Vault, node: uuid::Uuid) {
    let secret = vault
        .borrow_secret(node, "password", Purpose::SshPassword)
        .unwrap();
    assert_eq!(secret.expose_secret().as_slice(), STORED_SECRET);
}

#[test]
fn the_slot_list_describes_every_slot_the_settings_screen_shows() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("prod.pem");
    fs::write(&keyfile, b"a key file").unwrap();

    let path = dir.path().join("acme.rvault");
    let (vault, _key) = Vault::create(
        CreateOptions::new(
            &path,
            "Acme Production",
            Secret::new(String::from(PASSWORD)),
        )
        .with_kdf_params(KdfParams::low_cost_for_tests())
        .with_keyfile(&keyfile),
    )
    .unwrap();

    let slots = vault.slots();
    assert_eq!(slots.len(), 2);

    let password = &slots[0];
    assert_eq!(password.index, 0);
    assert_eq!(password.kind, SlotKind::Password);
    assert_eq!(password.label, "Master password");
    assert!(password.created_at > 0);
    assert_eq!(password.last_used, None);
    assert!(password.requires_keyfile);
    assert!(
        password
            .kdf_summary()
            .is_some_and(|s| s.starts_with("Argon2id, ")),
        "a password slot must describe its cost"
    );

    let recovery = &slots[1];
    assert_eq!(recovery.kind, SlotKind::Recovery);
    assert!(!recovery.requires_keyfile);
    assert_eq!(
        recovery.kdf_summary(),
        None,
        "a recovery slot derives with HKDF and has no cost to show"
    );
}

#[test]
fn changing_the_master_password_leaves_the_recovery_key_valid() {
    // The point of re-wrapping one slot rather than re-keying the vault: the
    // master key does not move, so nothing else has to be reissued.
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, recovery, path) = create(dir.path(), "acme.rvault");
    let node = add_secret(&mut vault);
    vault.save().unwrap();

    vault
        .change_master_password(
            &credential(PASSWORD),
            &credential(NEW_PASSWORD),
            Some(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
    vault.lock();

    assert!(matches!(
        open_with(&path, PASSWORD),
        Err(UnlockError::NotUnlocked)
    ));

    let mut reopened = open_with(&path, NEW_PASSWORD).unwrap();
    assert_secret_readable(&mut reopened, node);
    reopened.lock();

    let recovered = Vault::open(&path, UnlockMethod::recovery(recovery)).unwrap();
    assert_eq!(recovered.label(), "Acme Production");
}

#[test]
fn a_wrong_current_password_does_not_re_key_the_slot() {
    // Re-wrapping a slot the caller cannot open would destroy the only copy of
    // the master key it holds, and the owner would find out at the next unlock.
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    vault.save().unwrap();

    let refused = vault.change_master_password(
        &credential("not the password"),
        &credential(NEW_PASSWORD),
        Some(KdfParams::low_cost_for_tests()),
    );
    assert!(matches!(
        refused,
        Err(VaultError::SlotCredentialRejected(0))
    ));
    vault.lock();

    let opened = open_with(&path, PASSWORD).unwrap();
    assert_eq!(opened.label(), "Acme Production");
}

#[test]
fn a_changed_password_can_carry_a_new_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    let keyfile = dir.path().join("prod.key");
    fs::write(&keyfile, b"the second factor").unwrap();

    vault
        .change_master_password(
            &credential(PASSWORD),
            &credential(NEW_PASSWORD).with_keyfile(&keyfile),
            Some(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
    vault.lock();

    assert!(matches!(
        open_with(&path, NEW_PASSWORD),
        Err(UnlockError::NotUnlocked)
    ));

    let opened = Vault::open(
        &path,
        UnlockMethod::password_with_keyfile(Secret::new(String::from(NEW_PASSWORD)), &keyfile),
    )
    .unwrap();
    assert!(opened.slots()[0].requires_keyfile);
}

#[test]
fn rotating_the_recovery_key_invalidates_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, old_key, path) = create(dir.path(), "acme.rvault");
    let created_before = vault.slots()[1].created_at;

    let new_key = vault.rotate_recovery_key(1).unwrap();
    let slots = vault.slots();
    let rotated = &slots[1];
    assert_eq!(rotated.kind, SlotKind::Recovery);
    assert_eq!(rotated.label, "Recovery key");
    assert!(rotated.created_at >= created_before);
    assert_eq!(rotated.last_used, None);
    vault.lock();

    assert!(matches!(
        Vault::open(&path, UnlockMethod::recovery(old_key)),
        Err(UnlockError::NotUnlocked)
    ));

    let opened = Vault::open(&path, UnlockMethod::recovery(new_key)).unwrap();
    assert_eq!(opened.label(), "Acme Production");
    // The password slot is untouched: the master key did not move.
    opened.lock();
    assert!(open_with(&path, PASSWORD).is_ok());
}

#[test]
fn a_rotation_addressed_at_the_wrong_slot_is_refused_by_kind() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path(), "acme.rvault");

    match vault.rotate_recovery_key(0) {
        Err(VaultError::WrongSlotKind {
            index,
            expected,
            found,
        }) => {
            assert_eq!(index, 0);
            assert_eq!(expected, SlotKind::Recovery);
            assert_eq!(found, SlotKind::Password);
        }
        other => panic!("expected WrongSlotKind, got {other:?}"),
    }
    assert!(matches!(
        vault.rotate_recovery_key(9),
        Err(VaultError::NoSuchSlot(9))
    ));
}

#[test]
fn the_last_slot_cannot_be_removed() {
    // `docs/security/key-management.md`: "A vault must always retain at least
    // one usable slot." A table with nothing in it is a file nobody can ever
    // open again, so the refusal is typed rather than advisory.
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");

    vault.remove_slot(1).unwrap();
    assert!(matches!(vault.remove_slot(0), Err(VaultError::LastSlot)));
    assert_eq!(vault.slots().len(), 1);

    vault.save().unwrap();
    vault.lock();
    assert!(open_with(&path, PASSWORD).is_ok());
}

#[test]
fn slots_can_be_added_and_each_one_opens_the_same_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");

    let second = vault
        .add_password_slot(
            "Shared password",
            &Secret::new(String::from(NEW_PASSWORD)),
            None,
            Some(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
    let (third, break_glass) = vault.add_recovery_slot("Break-glass envelope").unwrap();
    vault.save().unwrap();
    vault.lock();

    assert_eq!(second, 2);
    assert_eq!(third, 3);
    assert!(open_with(&path, PASSWORD).is_ok());
    assert!(open_with(&path, NEW_PASSWORD).is_ok());
    assert!(Vault::open(&path, UnlockMethod::recovery(break_glass)).is_ok());
}

#[test]
fn rotating_the_master_key_re_wraps_every_slot_and_keeps_the_data() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, old_recovery, path) = create(dir.path(), "acme.rvault");
    let node = add_secret(&mut vault);
    vault.save().unwrap();

    // What a leaked copy of the file is: the same bytes, elsewhere.
    let leaked = dir.path().join("leaked.rvault");
    fs::copy(&path, &leaked).unwrap();

    let outcome = vault
        .rotate_master_key(&RotationPlan::new().with_password(0, credential(PASSWORD)))
        .unwrap();
    assert_eq!(outcome.rewrapped, vec![0, 1]);
    assert!(outcome.dropped.is_empty());
    assert_eq!(outcome.recovery_keys.len(), 1);
    assert_eq!(
        outcome.secrets_resealed, 1,
        "every stored secret must be re-sealed under the new field key"
    );

    assert_secret_readable(&mut vault, node);
    vault.lock();

    // The password did not change, so it still opens the file — under a
    // completely different master key.
    let mut reopened = open_with(&path, PASSWORD).unwrap();
    assert_secret_readable(&mut reopened, node);
    reopened.lock();

    let (_, new_recovery) = outcome.recovery_keys.into_iter().next().unwrap();
    assert!(Vault::open(&path, UnlockMethod::recovery(new_recovery)).is_ok());

    // The old recovery key belongs to the old master key. It opens the leaked
    // copy — rotation cannot reach into a file it does not have — and nothing
    // else. Which is why the settings screen tells the user to delete it.
    assert!(matches!(
        Vault::open(&path, UnlockMethod::recovery(old_recovery)),
        Err(UnlockError::NotUnlocked)
    ));
}

#[test]
fn a_rotation_re_encrypts_the_body_rather_than_only_the_slots() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    add_secret(&mut vault);
    vault.save().unwrap();
    let before = fs::read(&path).unwrap();

    vault
        .rotate_master_key(&RotationPlan::new().with_password(0, credential(PASSWORD)))
        .unwrap();
    let after = fs::read(&path).unwrap();

    // A byte-for-byte comparison proves only that the file was rewritten — the
    // body nonce is fresh on every save. That the old keys no longer open it is
    // what the rotation test above asserts.
    assert_ne!(before, after);
}

#[test]
fn a_rotation_refuses_a_slot_it_was_given_nothing_to_re_wrap() {
    // Silently dropping the slot would take away someone's way in without
    // saying so.
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    vault
        .add_password_slot(
            "Shared password",
            &Secret::new(String::from(NEW_PASSWORD)),
            None,
            Some(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
    vault.save().unwrap();

    let refused =
        vault.rotate_master_key(&RotationPlan::new().with_password(0, credential(PASSWORD)));
    assert!(matches!(refused, Err(VaultError::SlotCredentialMissing(2))));

    // Nothing moved: the plan was rejected before any key was generated.
    vault.lock();
    assert!(open_with(&path, PASSWORD).is_ok());
    assert!(open_with(&path, NEW_PASSWORD).is_ok());
}

#[test]
fn a_rotation_with_the_wrong_password_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    vault.save().unwrap();

    let refused = vault
        .rotate_master_key(&RotationPlan::new().with_password(0, credential("not the password")));
    assert!(matches!(
        refused,
        Err(VaultError::SlotCredentialRejected(0))
    ));

    vault.lock();
    assert!(open_with(&path, PASSWORD).is_ok());
}

#[test]
fn a_rotation_may_drop_a_slot_but_not_the_last_one() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, old_recovery, path) = create(dir.path(), "acme.rvault");
    vault.save().unwrap();

    let refused = vault.rotate_master_key(&RotationPlan::new().dropping(0).dropping(1));
    assert!(matches!(refused, Err(VaultError::LastSlot)));

    let outcome = vault
        .rotate_master_key(
            &RotationPlan::new()
                .with_password(0, credential(PASSWORD))
                .dropping(1),
        )
        .unwrap();
    assert_eq!(outcome.rewrapped, vec![0]);
    assert_eq!(outcome.dropped, vec![1]);
    assert!(outcome.recovery_keys.is_empty());
    vault.lock();

    assert!(open_with(&path, PASSWORD).is_ok());
    assert!(matches!(
        Vault::open(&path, UnlockMethod::recovery(old_recovery)),
        Err(UnlockError::NoSuchMethod(SlotKind::Recovery))
    ));
}
