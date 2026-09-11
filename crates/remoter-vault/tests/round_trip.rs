//! The lifecycle: create, populate, save, reopen, and get the same tree back.
//!
//! Also the parts of that lifecycle that must *not* work — a recovery key after
//! the password slot is gone, a secret borrowed for the wrong protocol, a
//! backup that has to be openable when the vault beside it is not.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use remoter_core::{
    ConnectionProps, CredentialProps, Inherited, Node, NodeKind, SecretKind, Tag, Tree,
};
use remoter_vault::{
    CreateOptions, ExposeSecret, KdfParams, Purpose, RecoveryKey, Secret, SlotKind, UnlockError,
    UnlockMethod, Vault, VaultError,
};

const PASSWORD: &str = "a master password";

fn options(path: &Path) -> CreateOptions {
    CreateOptions::new(path, "Acme Production", Secret::new(String::from(PASSWORD)))
        .with_kdf_params(KdfParams::low_cost_for_tests())
}

fn create(dir: &Path, name: &str) -> (Vault, RecoveryKey, PathBuf) {
    let path = dir.join(name);
    let (vault, key) = Vault::create(options(&path)).unwrap();
    (vault, key, path)
}

fn unlock(path: &Path) -> Result<Vault, UnlockError> {
    Vault::open(
        path,
        UnlockMethod::password(Secret::new(String::from(PASSWORD))),
    )
}

/// A small but not trivial tree: a folder, two connections under it, and a
/// credential beside them.
fn populate(vault: &mut Vault) -> Tree {
    let now = 1_700_000_000_000;
    let mut tree = vault.tree().unwrap();

    let mut folder = Node::new(NodeKind::folder(), "Datacentre EU-West", now);
    folder.description = "Everything in Frankfurt".into();
    folder.tags = vec![Tag::new("production").unwrap()];
    let folder_id = folder.id;
    let patch = tree.insert(folder).unwrap();
    vault.apply(&tree, &patch).unwrap();

    for (index, host) in ["web-01.eu.acme.internal", "web-02.eu.acme.internal"]
        .into_iter()
        .enumerate()
    {
        let mut props = ConnectionProps::new("ssh", host).unwrap();
        props.port = Inherited::Explicit(2222);
        let node = Node::new(
            NodeKind::Connection(props),
            host.split('.').next().unwrap(),
            now,
        )
        .under(folder_id, i64::try_from(index).unwrap());
        let patch = tree.insert(node).unwrap();
        vault.apply(&tree, &patch).unwrap();
    }

    let credential = Node::new(
        NodeKind::Credential(CredentialProps::new(
            "svc-deploy",
            SecretKind::Password {
                sealed: Vault::sealed_placeholder(),
            },
        )),
        "svc-deploy",
        now,
    )
    .under(folder_id, 2);
    let credential_id = credential.id;
    let patch = tree.insert(credential).unwrap();
    vault.apply(&tree, &patch).unwrap();

    vault
        .set_secret(
            *credential_id.as_uuid(),
            "password",
            Secret::new(b"correct horse battery staple".to_vec()),
        )
        .unwrap();

    // Read the tree back rather than returning the one that was built: storing
    // a secret changes the node's sealed material, and the in-memory copy the
    // caller assembled does not know that. Comparing a stale tree against a
    // reloaded one would be comparing the test's bookkeeping, not the vault's.
    drop(tree);
    vault.tree().unwrap()
}

/// Compares two trees by the data that must survive a round trip.
fn assert_same_tree(before: &Tree, after: &Tree) {
    assert_eq!(before.len(), after.len(), "node count changed");
    for node in before.nodes() {
        let reloaded = after
            .get(node.id)
            .unwrap_or_else(|| panic!("node {} did not survive", node.id));
        assert_eq!(node, reloaded, "node {} came back different", node.id);
    }
    assert_eq!(before.roots(), after.roots(), "root order changed");
}

#[test]
fn a_populated_vault_reopens_with_an_identical_tree() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");

    let before = populate(&mut vault);
    vault.save().unwrap();
    vault.lock();

    let reopened = unlock(&path).unwrap();
    let after = reopened.tree().unwrap();

    assert_same_tree(&before, &after);
    assert_eq!(reopened.label(), "Acme Production");
    assert_eq!(reopened.connection_count().unwrap(), 2);
    assert_eq!(reopened.credential_count().unwrap(), 1);
}

#[test]
fn a_secret_field_survives_the_round_trip_and_stays_bound_to_its_record() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");

    let tree = populate(&mut vault);
    let credential = tree
        .nodes()
        .find(|n| n.kind.as_credential().is_some())
        .unwrap()
        .id;
    vault.save().unwrap();
    vault.lock();

    let mut reopened = unlock(&path).unwrap();
    let secret = reopened
        .borrow_secret(*credential.as_uuid(), "password", Purpose::SshPassword)
        .unwrap();
    assert_eq!(
        secret.expose_secret().as_slice(),
        b"correct horse battery staple"
    );

    assert_eq!(
        reopened.secret_fields(*credential.as_uuid()).unwrap(),
        vec!["password".to_string()]
    );
    assert!(
        !reopened
            .has_secret(*credential.as_uuid(), "private_key")
            .unwrap()
    );
}

#[test]
fn a_secret_that_is_not_there_is_reported_as_missing_not_as_empty() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path(), "acme.rvault");
    let tree = populate(&mut vault);
    let connection = tree
        .nodes()
        .find(|n| n.kind.as_connection().is_some())
        .unwrap()
        .id;

    match vault.borrow_secret(*connection.as_uuid(), "password", Purpose::SshPassword) {
        Err(VaultError::NoSuchSecret { field, .. }) => assert_eq!(field, "password"),
        other => panic!("expected NoSuchSecret, got {other:?}"),
    }
}

#[test]
fn the_recovery_key_opens_a_vault_whose_password_slot_has_been_destroyed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, key, path) = create(dir.path(), "acme.rvault");
    let before = populate(&mut vault);

    // Deliberately destroy the way in that the user would normally use.
    vault.remove_slot(0).unwrap();
    vault.save().unwrap();
    vault.lock();

    assert!(matches!(
        unlock(&path),
        Err(UnlockError::NoSuchMethod(SlotKind::Password))
    ));

    // Retyped exactly as a user would, from the printed sheet.
    let printed = key.printable().unwrap();
    let retyped = RecoveryKey::parse(&printed).unwrap();

    let recovered = Vault::open(&path, UnlockMethod::recovery(retyped)).unwrap();
    assert_same_tree(&before, &recovered.tree().unwrap());
    assert_eq!(recovered.slots().len(), 1);
    assert_eq!(recovered.slots()[0].kind, SlotKind::Recovery);
}

#[test]
fn a_new_password_slot_can_be_added_from_a_recovery_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, key, path) = create(dir.path(), "acme.rvault");
    vault.remove_slot(0).unwrap();
    vault.save().unwrap();
    vault.lock();

    let mut recovered = Vault::open(&path, UnlockMethod::recovery(key)).unwrap();
    recovered
        .add_password_slot(
            "New master password",
            &Secret::new(String::from("a replacement password")),
            None,
            Some(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
    recovered.save().unwrap();
    recovered.lock();

    let reopened = Vault::open(
        &path,
        UnlockMethod::password(Secret::new(String::from("a replacement password"))),
    )
    .unwrap();
    assert_eq!(reopened.slots().len(), 2);
}

#[test]
fn a_wrong_recovery_key_does_not_open_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _key, path) = create(dir.path(), "acme.rvault");
    vault.lock();

    let other = RecoveryKey::generate().unwrap();
    assert!(matches!(
        Vault::open(&path, UnlockMethod::recovery(other)),
        Err(UnlockError::NotUnlocked)
    ));
}

#[test]
fn every_save_writes_a_fresh_body_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");

    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    for _ in 0..64 {
        vault.save().unwrap();
        let bytes = fs::read(&path).unwrap();
        let header_len = u32::from_le_bytes(bytes[10..14].try_into().unwrap()) as usize;
        let nonce_at = 8 + 2 + 4 + header_len + 32;
        let nonce = bytes[nonce_at..nonce_at + 24].to_vec();
        assert!(seen.insert(nonce), "a body nonce was reused between saves");
    }
    assert_eq!(seen.len(), 64);
}

#[test]
fn the_rolling_backups_stay_openable() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    populate(&mut vault);

    // The backups rotate once per session, not once per save, so five saves in
    // one sitting produce one of them. Three sessions produce three.
    for _ in 0..5 {
        vault.save().unwrap();
    }
    vault.lock();

    for _ in 0..3 {
        let mut reopened = unlock(&path).unwrap();
        reopened.save().unwrap();
        reopened.save().unwrap();
        reopened.lock();
    }

    // Three by default, and no more however many sessions there are.
    let backups: Vec<PathBuf> = (1..=4)
        .map(|n| {
            let mut name = path.clone().into_os_string();
            name.push(format!(".bak.{n}"));
            PathBuf::from(name)
        })
        .collect();
    assert!(backups[0].is_file());
    assert!(backups[1].is_file());
    assert!(backups[2].is_file());
    assert!(
        !backups[3].exists(),
        "more backups were kept than configured"
    );

    for backup in &backups[..3] {
        let opened = unlock(backup).unwrap();
        assert_eq!(opened.label(), "Acme Production");
    }
}

#[test]
fn a_backup_still_opens_when_the_vault_beside_it_is_destroyed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    let before = populate(&mut vault);
    vault.save().unwrap();
    vault.lock();

    // `.bak.1` is the file as it stood when the session that took it began, so
    // the population has to be committed and the vault reopened before the
    // backup contains it. That is the whole point of rotating once a session:
    // the backup is a predecessor, not the state one save ago.
    let mut second = unlock(&path).unwrap();
    second.save().unwrap();
    second.lock();

    let mut backup = path.clone().into_os_string();
    backup.push(".bak.1");
    let backup = PathBuf::from(backup);

    let mut damaged = fs::read(&path).unwrap();
    let last = damaged.len() - 1;
    damaged[last] ^= 0xFF;
    fs::write(&path, &damaged).unwrap();

    assert!(matches!(unlock(&path), Err(UnlockError::BodyCorrupt)));

    let rescued = unlock(&backup).unwrap();
    assert_same_tree(&before, &rescued.tree().unwrap());
}

#[test]
fn probing_a_vault_reports_its_backups_and_slots_without_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    vault.save().unwrap();
    vault.lock();

    let info = Vault::probe(&path).unwrap();
    assert_eq!(info.label, "Acme Production");
    assert_eq!(info.format_version, 1);
    assert_eq!(info.backups.len(), 1);
    assert_eq!(info.slots.len(), 2);

    let kinds: Vec<SlotKind> = info.slots.iter().map(|s| s.kind).collect();
    assert_eq!(kinds, vec![SlotKind::Password, SlotKind::Recovery]);
    assert!(info.slots[0].kdf_params.is_some());
    assert!(info.slots[1].kdf_params.is_none());
    assert!(info.created_at > 0);
    assert!(info.modified_at >= info.created_at);
}

#[test]
fn tombstoned_nodes_leave_the_tree_and_the_search_index() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    let mut tree = populate(&mut vault);

    let connection = tree
        .nodes()
        .find(|n| n.kind.as_connection().is_some())
        .unwrap()
        .id;
    assert!(!vault.search("web", 10).unwrap().is_empty());

    let patch = tree.soft_delete(connection, 1_700_000_100_000).unwrap();
    vault.apply(&tree, &patch).unwrap();
    vault.save().unwrap();
    vault.lock();

    let reopened = unlock(&path).unwrap();
    assert!(reopened.tree().unwrap().get(connection).is_none());
    assert!(
        reopened.node(*connection.as_uuid()).unwrap().is_some(),
        "the tombstone itself must survive"
    );
    assert_eq!(
        reopened.connection_count().unwrap(),
        1,
        "a tombstoned connection must not be counted as live"
    );
}

#[test]
fn a_credential_restricted_to_one_protocol_refuses_the_others() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path(), "acme.rvault");
    let mut tree = vault.tree().unwrap();

    let mut props = CredentialProps::new(
        "svc-ssh",
        SecretKind::Password {
            sealed: Vault::sealed_placeholder(),
        },
    );
    props.allowed_protocols = vec![remoter_core::ProtocolId::new("ssh").unwrap()];
    let node = Node::new(NodeKind::Credential(props), "svc-ssh", 1_700_000_000_000);
    let id = *node.id.as_uuid();
    let patch = tree.insert(node).unwrap();
    vault.apply(&tree, &patch).unwrap();

    vault
        .set_secret(id, "password", Secret::new(b"only for ssh".to_vec()))
        .unwrap();

    assert!(
        vault
            .borrow_secret(id, "password", Purpose::SshPassword)
            .is_ok()
    );
    assert!(matches!(
        vault.borrow_secret(id, "password", Purpose::RdpCredentials),
        Err(VaultError::PurposeRefused(Purpose::RdpCredentials))
    ));

    // The refusal is audited, and the audit entry names no secret.
    let denied = vault
        .audit_recent(10)
        .unwrap()
        .into_iter()
        .find(|(_, _, outcome, _)| outcome == "denied")
        .expect("the refusal was not audited");
    assert_eq!(denied.1, "secret_used");
    assert_eq!(denied.3.as_deref(), Some("password"));
}

#[test]
fn settings_survive_the_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    vault.set_setting("theme", b"dark").unwrap();
    vault.set_setting("locale", "tr-TR".as_bytes()).unwrap();
    vault.save().unwrap();
    vault.lock();

    let reopened = unlock(&path).unwrap();
    assert_eq!(
        reopened.setting("theme").unwrap().as_deref(),
        Some(&b"dark"[..])
    );
    assert_eq!(
        reopened.setting("locale").unwrap().as_deref(),
        Some("tr-TR".as_bytes())
    );
    assert!(reopened.setting("absent").unwrap().is_none());
}

#[test]
fn the_trust_store_survives_the_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path(), "acme.rvault");
    vault
        .trust_pin(
            "web-01.eu.acme.internal",
            22,
            "ssh_hostkey",
            "ssh-ed25519",
            b"SHA256:abcdef",
            b"ssh-ed25519 AAAA...",
            "user",
        )
        .unwrap();
    vault.save().unwrap();
    vault.lock();

    let reopened = unlock(&path).unwrap();
    assert_eq!(
        reopened
            .trust_lookup("web-01.eu.acme.internal", 22, "ssh_hostkey", "ssh-ed25519")
            .unwrap()
            .as_deref(),
        Some(&b"SHA256:abcdef"[..])
    );
}

#[test]
fn a_search_never_matches_a_secret_field() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path(), "acme.rvault");
    populate(&mut vault);

    // The credential's password is "correct horse battery staple". None of it
    // may be reachable through the index.
    for word in ["correct", "horse", "battery", "staple"] {
        assert!(
            vault.search(word, 10).unwrap().is_empty(),
            "the search index matched {word:?}, which is secret material"
        );
    }
    assert!(!vault.search("svc-deploy", 10).unwrap().is_empty());
}
