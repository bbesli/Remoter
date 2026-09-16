//! Audit rows carry the operating-system account and machine they were written
//! from, through the real create and open paths.
//!
//! A file of its own because it sets the process-wide identity, which every
//! other test in the same binary would inherit. Each file under `tests/` is its
//! own process.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use remoter_vault::{
    AuditActor, AuditEvent, AuditQuery, CreateOptions, KdfParams, Secret, UnlockMethod, Vault,
    audit_actor, set_audit_actor,
};

const PASSWORD: &str = "a master password";

#[test]
fn the_unlock_and_the_creation_are_attributed_to_whoever_ran_them() {
    let burak = AuditActor::new("workstation", "burak", Some("DEVOPLUS"), "linux").unwrap();
    assert!(set_audit_actor(burak.clone()));
    assert!(
        !set_audit_actor(AuditActor::new("elsewhere", "mallory", None, "linux").unwrap()),
        "the identity of a running process is set once"
    );
    assert_eq!(audit_actor(), Some(&burak));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.rvault");
    let (vault, _recovery) = Vault::create(
        CreateOptions::new(&path, "Shared", Secret::new(String::from(PASSWORD)))
            .with_kdf_params(KdfParams::low_cost_for_tests()),
    )
    .unwrap();
    drop(vault);

    // Reopened from disk, so what is read back is what the encrypted body
    // holds, not what the in-memory store happened to keep.
    let vault = Vault::open(
        &path,
        UnlockMethod::password(Secret::new(String::from(PASSWORD))),
    )
    .unwrap();

    let rows = vault.audit_query(&AuditQuery::new()).unwrap();
    for event in [AuditEvent::VaultCreated, AuditEvent::VaultUnlocked] {
        let row = rows
            .iter()
            .find(|row| row.event_kind() == Some(event))
            .unwrap_or_else(|| panic!("no {} row", event.as_str()));
        assert_eq!(
            row.actor.as_ref().map(|a| &a.actor),
            Some(&burak),
            "{} must name who did it",
            event.as_str()
        );
    }
    assert!(
        rows.iter().all(|row| row.actor.is_some()),
        "every row this process wrote carries its identity"
    );

    let actors = vault.audit_actors().unwrap();
    assert_eq!(actors.len(), 1);
    assert_eq!(actors[0].record.actor.account(), "DEVOPLUS\\burak");
    assert_eq!(actors[0].entries, rows.len());
}
