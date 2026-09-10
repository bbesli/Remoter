//! Querying the audit log, and the rule the log exists under: no secret ever
//! reaches it.
//!
//! The last test here is the important one. It runs a whole lifecycle — create,
//! store credentials, use them, be refused one, rotate keys, change settings —
//! renders every row the audit screen would show, and searches the rendered
//! text for the credentials it used. A `detail` string that starts carrying a
//! password fails it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::Path;

use remoter_core::{ConnectionProps, CredentialProps, Node, NodeKind, ProtocolId, SecretKind};
use remoter_vault::{
    AuditCategory, AuditEvent, AuditOutcome, AuditQuery, AuditRecord, CreateOptions, KdfParams,
    PasswordCredential, Purpose, RotationPlan, Secret, SessionOnLock, Vault, VaultError,
    VaultSettings,
};

const PASSWORD: &str = "a master password";
const SSH_PASSWORD: &[u8] = b"correct horse battery staple";
const KEY_PASSPHRASE: &[u8] = b"the passphrase on the key";

fn create(dir: &Path) -> (Vault, remoter_vault::RecoveryKey) {
    Vault::create(
        CreateOptions::new(
            dir.join("acme.rvault"),
            "Acme Production",
            Secret::new(String::from(PASSWORD)),
        )
        .with_kdf_params(KdfParams::low_cost_for_tests()),
    )
    .unwrap()
}

/// A credential restricted to RDP, so that borrowing it for SSH is refused and
/// the refusal is audited.
fn rdp_only_credential(vault: &mut Vault) -> uuid::Uuid {
    let mut props = CredentialProps::new(
        "svc-deploy",
        SecretKind::Password {
            sealed: Vault::sealed_placeholder(),
        },
    );
    props.allowed_protocols = vec![ProtocolId::new("rdp").unwrap()];

    let mut tree = vault.tree().unwrap();
    let node = Node::new(NodeKind::Credential(props), "svc-deploy", 1_700_000_000_000);
    let id = *node.id.as_uuid();
    let patch = tree.insert(node).unwrap();
    vault.apply(&tree, &patch).unwrap();
    vault
        .set_secret(id, "password", Secret::new(SSH_PASSWORD.to_vec()))
        .unwrap();
    vault
        .set_secret(id, "passphrase", Secret::new(KEY_PASSPHRASE.to_vec()))
        .unwrap();
    id
}

/// Everything an audit screen would show for one row, as one line.
fn render(record: &AuditRecord) -> String {
    format!(
        "{} {} {} {} {} {}",
        record.id,
        record.at,
        record.event,
        record.outcome,
        record
            .node
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".into()),
        record.detail.clone().unwrap_or_else(|| "-".into()),
    )
}

#[test]
fn the_whole_log_comes_back_newest_first() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key) = create(dir.path());
    vault.save().unwrap();

    let all = vault.audit_query(&AuditQuery::new()).unwrap();
    assert!(all.len() >= 3, "the lifecycle writes several rows");
    assert_eq!(all.len(), vault.audit_count(&AuditQuery::new()).unwrap());

    for pair in all.windows(2) {
        assert!(
            (pair[0].at, pair[0].id) >= (pair[1].at, pair[1].id),
            "entries must arrive newest first"
        );
    }

    let events: Vec<&str> = all.iter().map(|r| r.event.as_str()).collect();
    assert!(events.contains(&AuditEvent::VaultCreated.as_str()));
    assert!(events.contains(&AuditEvent::VaultSaved.as_str()));
}

#[test]
fn a_category_filter_selects_one_subsystem() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key) = create(dir.path());
    let node = rdp_only_credential(&mut vault);
    vault
        .session_start(Some(node), "ssh", "web-01.example.internal", Some("root"))
        .unwrap();

    let secrets = vault
        .audit_query(&AuditQuery::new().category(AuditCategory::Secret))
        .unwrap();
    assert!(!secrets.is_empty());
    for record in &secrets {
        assert_eq!(record.category(), Some(AuditCategory::Secret), "{record:?}");
    }

    let connections = vault
        .audit_query(&AuditQuery::new().category(AuditCategory::Connection))
        .unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].event, AuditEvent::SessionStarted.as_str());

    // Two categories are combined with "or", as the screen's chips are.
    let both = vault
        .audit_count(
            &AuditQuery::new()
                .category(AuditCategory::Secret)
                .category(AuditCategory::Connection),
        )
        .unwrap();
    assert_eq!(both, secrets.len() + connections.len());
}

#[test]
fn a_refusal_is_recorded_and_shows_under_warnings() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key) = create(dir.path());
    let node = rdp_only_credential(&mut vault);

    // Restricted to RDP; asking for it as an SSH password is the mistake the
    // restriction exists to catch.
    assert!(matches!(
        vault.borrow_secret(node, "password", Purpose::SshPassword),
        Err(VaultError::PurposeRefused(Purpose::SshPassword))
    ));

    let denied = vault
        .audit_query(&AuditQuery::new().outcome(AuditOutcome::Denied))
        .unwrap();
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].event, AuditEvent::SecretUsed.as_str());
    assert_eq!(denied[0].node, Some(node));
    assert!(denied[0].is_warning());

    let warnings = vault
        .audit_query(&AuditQuery::new().category(AuditCategory::Warning))
        .unwrap();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].id, denied[0].id);
}

#[test]
fn a_time_range_is_half_open_so_paging_by_day_shows_nothing_twice() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key) = create(dir.path());
    vault.save().unwrap();

    let all = vault.audit_query(&AuditQuery::new()).unwrap();
    let newest = all.first().unwrap().at;
    let oldest = all.last().unwrap().at;

    let before = vault.audit_count(&AuditQuery::new().until(newest)).unwrap();
    let from = vault.audit_count(&AuditQuery::new().since(newest)).unwrap();
    assert_eq!(
        before + from,
        all.len(),
        "an entry must fall on exactly one side of a boundary"
    );

    assert_eq!(
        vault.audit_count(&AuditQuery::new().since(oldest)).unwrap(),
        all.len()
    );
    assert_eq!(
        vault.audit_count(&AuditQuery::new().until(oldest)).unwrap(),
        0
    );
}

#[test]
fn pages_are_disjoint_and_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key) = create(dir.path());
    for _ in 0..6 {
        vault.save().unwrap();
    }

    let total = vault.audit_count(&AuditQuery::new()).unwrap();
    assert!(total > 4);

    let first = vault.audit_query(&AuditQuery::new().page(0, 2)).unwrap();
    let second = vault.audit_query(&AuditQuery::new().page(1, 2)).unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(second.len(), 2);
    assert!(
        first.iter().all(|a| second.iter().all(|b| a.id != b.id)),
        "pages must not overlap"
    );

    let unpaged = vault.audit_query(&AuditQuery::new()).unwrap();
    assert_eq!(first, unpaged[..2]);
    assert_eq!(second, unpaged[2..4]);

    // Counting ignores paging: it is what the pager divides.
    assert_eq!(
        vault.audit_count(&AuditQuery::new().page(0, 2)).unwrap(),
        total
    );
}

#[test]
fn filtering_by_node_narrows_to_one_credential() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key) = create(dir.path());
    let node = rdp_only_credential(&mut vault);

    let entries = vault
        .audit_query(&AuditQuery::new().for_node(node))
        .unwrap();
    assert!(!entries.is_empty());
    for record in &entries {
        assert_eq!(record.node, Some(node));
    }
}

#[test]
fn the_log_never_contains_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, recovery) = create(dir.path());

    // A full lifecycle: nodes, secrets, a refusal, a session, a trust pin,
    // settings, a password change and a master key rotation.
    let credential = rdp_only_credential(&mut vault);
    let _ = vault.borrow_secret(credential, "password", Purpose::SshPassword);
    vault
        .borrow_secret(credential, "password", Purpose::RdpCredentials)
        .unwrap();
    vault
        .borrow_secret(credential, "password", Purpose::Reveal)
        .unwrap();
    vault
        .borrow_secret(credential, "passphrase", Purpose::Export)
        .unwrap();

    let mut tree = vault.tree().unwrap();
    let connection = Node::new(
        NodeKind::Connection(ConnectionProps::new("ssh", "web-01.example.internal").unwrap()),
        "web-01",
        1_700_000_000_000,
    );
    let patch = tree.insert(connection).unwrap();
    vault.apply(&tree, &patch).unwrap();

    let session = vault
        .session_start(
            Some(credential),
            "ssh",
            "web-01.example.internal",
            Some("root"),
        )
        .unwrap();
    vault
        .session_end(session, "closed by user", 1_024, 2_048)
        .unwrap();
    vault
        .trust_pin(
            "web-01.example.internal",
            22,
            "ssh_hostkey",
            "ssh-ed25519",
            b"\x01\x02\x03",
            b"\x04\x05\x06",
            "user",
        )
        .unwrap();

    vault
        .set_settings(&VaultSettings {
            session_on_lock: SessionOnLock::DisconnectAll,
            ..vault.settings().unwrap()
        })
        .unwrap();
    vault.save().unwrap();

    vault
        .change_master_password(
            &PasswordCredential::new(Secret::new(String::from(PASSWORD))),
            &PasswordCredential::new(Secret::new(String::from("a new master password"))),
            Some(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
    let outcome = vault
        .rotate_master_key(&RotationPlan::new().with_password(
            0,
            PasswordCredential::new(Secret::new(String::from("a new master password"))),
        ))
        .unwrap();

    let rendered: String = vault
        .audit_query(&AuditQuery::new())
        .unwrap()
        .iter()
        .map(|record| render(record) + "\n")
        .collect();

    let recovery_groups = recovery.groups().unwrap();
    let mut forbidden: Vec<String> = vec![
        PASSWORD.into(),
        "a new master password".into(),
        String::from_utf8_lossy(SSH_PASSWORD).into_owned(),
        String::from_utf8_lossy(KEY_PASSPHRASE).into_owned(),
    ];
    forbidden.extend(recovery_groups.iter().cloned());
    for (_, key) in &outcome.recovery_keys {
        forbidden.extend(key.groups().unwrap().iter().cloned());
    }

    for needle in forbidden {
        assert!(
            !rendered.contains(&needle),
            "the audit log rendered a secret: {rendered}"
        );
    }

    // And the rows that must be there, so the search above is searching
    // something.
    assert!(rendered.contains(AuditEvent::SecretRevealed.as_str()));
    assert!(rendered.contains(AuditEvent::SecretExported.as_str()));
    assert!(rendered.contains(AuditEvent::PasswordChanged.as_str()));
    assert!(rendered.contains(AuditEvent::MasterKeyRotated.as_str()));
    assert!(rendered.contains(AuditEvent::TrustPinned.as_str()));
}
