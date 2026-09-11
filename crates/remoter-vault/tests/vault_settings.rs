//! Per-vault settings: they persist inside the vault, and the rolling backup
//! count has exactly one home.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::{Path, PathBuf};

use remoter_core::RecordingPolicy;
use remoter_vault::{
    AuditCategory, AuditEvent, AuditQuery, CreateOptions, KdfParams, RecoveryKey, Secret,
    SessionOnLock, UnlockMethod, Vault, VaultSettings,
};

const PASSWORD: &str = "a master password";

fn create(dir: &Path) -> (Vault, RecoveryKey, PathBuf) {
    let path = dir.join("acme.rvault");
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

fn reopen(path: &Path) -> Vault {
    Vault::open(
        path,
        UnlockMethod::password(Secret::new(String::from(PASSWORD))),
    )
    .unwrap()
}

#[test]
fn a_new_vault_starts_at_the_documented_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _key, _path) = create(dir.path());

    let settings = vault.settings().unwrap();
    assert_eq!(settings.auto_lock_minutes, 15);
    assert!(settings.lock_on_screen_lock);
    assert!(settings.lock_on_suspend);
    assert!(!settings.lock_on_minimise);
    assert_eq!(settings.session_on_lock, SessionOnLock::KeepRunning);
    assert_eq!(settings.recording, RecordingPolicy::Never);
    assert_eq!(settings.backup_count, vault.backup_count());
}

#[test]
fn settings_survive_a_save_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path());

    vault
        .set_settings(&VaultSettings {
            auto_lock_minutes: 5,
            lock_on_screen_lock: false,
            lock_on_suspend: true,
            lock_on_minimise: true,
            session_on_lock: SessionOnLock::FreezeInput,
            recording: RecordingPolicy::Always,
            backup_count: 2,
        })
        .unwrap();
    vault.save().unwrap();
    vault.lock();

    let reopened = reopen(&path);
    let settings = reopened.settings().unwrap();
    assert_eq!(settings.auto_lock_minutes, 5);
    assert!(!settings.lock_on_screen_lock);
    assert!(settings.lock_on_suspend);
    assert!(settings.lock_on_minimise);
    assert_eq!(settings.session_on_lock, SessionOnLock::FreezeInput);
    assert_eq!(settings.recording, RecordingPolicy::Always);
    assert_eq!(settings.backup_count, 2);
}

#[test]
fn the_backup_count_is_stored_in_the_header_and_nowhere_else() {
    // One source of truth. The header is the one, because the count has to be
    // known before the body is decrypted — which is exactly the situation the
    // backups exist for.
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path());

    vault
        .set_settings(&VaultSettings {
            backup_count: 1,
            ..vault.settings().unwrap()
        })
        .unwrap();
    assert_eq!(vault.backup_count(), 1);
    vault.save().unwrap();
    vault.lock();

    // Probing reads the header without any key, and the count it reports there
    // is the count the settings screen shows.
    let reopened = reopen(&path);
    assert_eq!(reopened.backup_count(), 1);
    assert_eq!(reopened.settings().unwrap().backup_count, 1);
}

#[test]
fn changing_the_session_policy_is_written_to_the_audit_log() {
    // `docs/security/key-management.md` asks for this one specifically: what
    // happens to running sessions on lock is a policy change worth a record.
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path());

    vault
        .set_settings(&VaultSettings {
            session_on_lock: SessionOnLock::DisconnectAll,
            ..vault.settings().unwrap()
        })
        .unwrap();

    let entries = vault
        .audit_query(&AuditQuery::new().category(AuditCategory::Vault))
        .unwrap();
    let changed = entries
        .iter()
        .find(|r| r.event == AuditEvent::SettingChanged.as_str())
        .expect("a settings change is audited");
    assert_eq!(changed.detail.as_deref(), Some("session_on_lock"));

    // Writing the same values again is not a change, and does not add a row.
    let before = vault.audit_count(&AuditQuery::new()).unwrap();
    let unchanged = vault.settings().unwrap();
    vault.set_settings(&unchanged).unwrap();
    assert_eq!(vault.audit_count(&AuditQuery::new()).unwrap(), before);
}

#[test]
fn the_audit_detail_names_fields_and_never_their_values() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path());

    vault
        .set_settings(&VaultSettings {
            auto_lock_minutes: 45,
            recording: RecordingPolicy::Always,
            ..vault.settings().unwrap()
        })
        .unwrap();

    let entries = vault.audit_query(&AuditQuery::new()).unwrap();
    let changed = entries
        .iter()
        .find(|r| r.event == AuditEvent::SettingChanged.as_str())
        .unwrap();
    let detail = changed.detail.clone().unwrap();
    assert_eq!(detail, "auto_lock_minutes, recording");
    assert!(!detail.contains("45"));
}
