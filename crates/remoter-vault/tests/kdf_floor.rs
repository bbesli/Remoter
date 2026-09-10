//! One vault at the real Argon2id cost.
//!
//! The rest of the suite runs at [`KdfParams::low_cost_for_tests`], because a
//! few hundred vaults at 256 MiB and three passes would take the better part of
//! an hour. That makes it worth having exactly one test that does the real
//! thing end to end: the floor parameters are the ones every shipped vault
//! uses, and a suite that only ever exercised the cheap path would not notice
//! if they stopped working.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use remoter_vault::{CreateOptions, KdfParams, Secret, UnlockError, UnlockMethod, Vault};

#[test]
fn a_vault_at_the_floor_parameters_creates_and_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("floor.rvault");
    let floor = KdfParams::floor();

    assert_eq!(floor.m_cost, 256 * 1024, "the floor is 256 MiB");
    assert_eq!(floor.t_cost, 3);
    assert_eq!(floor.p_cost, 4);
    assert!(!floor.is_below_floor());

    let (vault, _key) = Vault::create(
        CreateOptions::new(&path, "At the floor", Secret::new(String::from("hunter2")))
            .with_kdf_params(floor),
    )
    .unwrap();
    vault.lock();

    let info = Vault::probe(&path).unwrap();
    assert_eq!(info.slots[0].kdf_params, Some(floor));
    assert_eq!(
        info.slots[0].kdf_params.unwrap().summary(),
        "Argon2id, 256 MiB, 3 passes, 4 lanes"
    );

    let opened = Vault::open(
        &path,
        UnlockMethod::password(Secret::new(String::from("hunter2"))),
    )
    .unwrap();
    assert_eq!(opened.label(), "At the floor");
    assert!(
        !opened.kdf_upgrade_available(),
        "a vault created at the floor should not be offered an upgrade"
    );
    opened.lock();

    assert!(matches!(
        Vault::open(
            &path,
            UnlockMethod::password(Secret::new(String::from("hunter3"))),
        ),
        Err(UnlockError::NotUnlocked)
    ));
}

#[test]
fn calibration_lands_at_or_above_the_floor() {
    let calibrated = Vault::calibrate_kdf().unwrap();

    assert!(!calibrated.is_below_floor());
    assert!(calibrated.m_cost >= KdfParams::FLOOR_M_COST);
    assert!(calibrated.m_cost <= KdfParams::CALIBRATION_MAX_M_COST);
    assert_eq!(calibrated.t_cost, KdfParams::FLOOR_T_COST);
    assert_eq!(calibrated.p_cost, KdfParams::FLOOR_P_COST);
    assert_eq!(calibrated.version, KdfParams::CURRENT_VERSION);
}

#[test]
fn accepting_the_upgrade_rewrites_the_slot_and_keeps_every_credential() {
    // The other half of `kdf_upgrade_available`: the specification says
    // Remoter "offers to upgrade them on the next successful unlock", and an
    // offer nobody can accept is not one.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("older.rvault");

    let (vault, recovery) = Vault::create(
        CreateOptions::new(&path, "Older build", Secret::new(String::from("hunter2")))
            .with_kdf_params(KdfParams::low_cost_for_tests()),
    )
    .unwrap();
    vault.lock();

    let mut opened = Vault::open(
        &path,
        UnlockMethod::password(Secret::new(String::from("hunter2"))),
    )
    .unwrap();
    assert!(opened.kdf_upgrade_available());

    let upgraded = opened
        .upgrade_kdf(&UnlockMethod::password(Secret::new(String::from(
            "hunter2",
        ))))
        .unwrap();
    assert!(upgraded, "a below-floor vault must upgrade");
    assert!(!opened.kdf_upgrade_available());

    // Nothing left to do the second time.
    assert!(
        !opened
            .upgrade_kdf(&UnlockMethod::password(Secret::new(String::from(
                "hunter2"
            ))))
            .unwrap()
    );
    // Only password slots carry cost parameters.
    assert!(!opened.upgrade_kdf(&UnlockMethod::Keychain).unwrap());
    opened.lock();

    // The upgrade must have been saved, and the slot must still be the same
    // slot: same index, same kind, opened by the same password.
    let probed = Vault::probe(&path).unwrap();
    assert_eq!(probed.slots[0].index, 0);
    assert!(!probed.slots[0].kdf_params.unwrap().is_below_floor());

    let reopened = Vault::open(
        &path,
        UnlockMethod::password(Secret::new(String::from("hunter2"))),
    )
    .unwrap();
    assert_eq!(reopened.label(), "Older build");
    assert_eq!(reopened.opened_with(), Some(0));
    reopened.lock();

    // The recovery slot wraps the same master key and was not touched, so the
    // key issued at creation still opens the file.
    let by_recovery = Vault::open(&path, UnlockMethod::recovery(recovery)).unwrap();
    assert_eq!(by_recovery.label(), "Older build");

    // And a wrong password still does not open it afterwards.
    by_recovery.lock();
    assert!(matches!(
        Vault::open(
            &path,
            UnlockMethod::password(Secret::new(String::from("hunter3"))),
        ),
        Err(UnlockError::NotUnlocked)
    ));
}

#[test]
fn the_upgrade_refuses_a_credential_that_does_not_open_the_slot() {
    // Rewrapping a slot the caller cannot currently open would re-key it to
    // the wrong password and destroy the only copy of the master key it holds.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("older.rvault");

    let (vault, _key) = Vault::create(
        CreateOptions::new(&path, "Older build", Secret::new(String::from("hunter2")))
            .with_kdf_params(KdfParams::low_cost_for_tests()),
    )
    .unwrap();
    vault.lock();

    let mut opened = Vault::open(
        &path,
        UnlockMethod::password(Secret::new(String::from("hunter2"))),
    )
    .unwrap();
    let changed = opened
        .upgrade_kdf(&UnlockMethod::password(Secret::new(String::from(
            "not the password",
        ))))
        .unwrap();
    assert!(
        !changed,
        "a slot the credential does not open is left alone"
    );
    opened.lock();

    let reopened = Vault::open(
        &path,
        UnlockMethod::password(Secret::new(String::from("hunter2"))),
    )
    .unwrap();
    assert_eq!(reopened.label(), "Older build");
}

#[test]
fn a_vault_created_below_the_floor_is_offered_an_upgrade() {
    // The test parameter set is deliberately below the floor, which is exactly
    // the situation a vault written by an older build would be in.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("weak.rvault");

    let (vault, _key) = Vault::create(
        CreateOptions::new(&path, "Older build", Secret::new(String::from("hunter2")))
            .with_kdf_params(KdfParams::low_cost_for_tests()),
    )
    .unwrap();
    vault.lock();

    let opened = Vault::open(
        &path,
        UnlockMethod::password(Secret::new(String::from("hunter2"))),
    )
    .unwrap();
    assert!(
        opened.kdf_upgrade_available(),
        "a below-floor vault must still open, and must be offered an upgrade"
    );
}
