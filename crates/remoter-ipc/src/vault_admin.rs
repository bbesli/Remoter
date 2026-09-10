//! Key slots and per-vault settings — the Vault settings screen.
//!
//! Everything here changes the vault file itself rather than what is in it.
//! Three rules shape the mapping:
//!
//! 1. **A recovery key crosses outward exactly once.** Issuing or rotating one
//!    returns it in the shape `vault_create` already uses, and nothing in the
//!    file can reproduce it afterwards. It is returned only after the write
//!    that made it real has succeeded, so a key the user writes down is never a
//!    key the vault does not hold.
//! 2. **A new password meets the same bar the first one did.** An unlock method
//!    is only as strong as its weakest slot, so `docs/security/threat-model.md`
//!    T1's entropy gate applies to every password slot, not just the one the
//!    creation wizard asked for.
//! 3. **Nothing is removed by implication.** The last slot cannot be revoked,
//!    and a master key rotation refuses a plan that would silently drop a slot.

use std::path::PathBuf;

use remoter_core::RecordingPolicy;
use remoter_vault::{
    ExposeSecret as _, PasswordCredential, RecoveryKey, RotationPlan, Secret, SessionOnLock, Vault,
    VaultSettings,
};
use tauri::State;

use crate::commands::{estimate_strength, save, slot_dto, uniform_below};
use crate::dto::{
    AddPasswordSlotDto, ChangePasswordDto, LockTriggerSupportDto, RecoveryKeyDto,
    RotateMasterKeyDto, RotationOutcomeDto, SlotDto, VaultSettingsDto, VaultSettingsPatchDto,
    VaultSlotsDto,
};
use crate::error::IpcError;
use crate::state::{AppState, LockTrigger, now_seconds};

/// The longest idle timeout the settings screen will store, in minutes. A day
/// is the point at which "automatic" stops meaning anything; zero means never,
/// which is a choice rather than an accident.
const MAX_AUTO_LOCK_MINUTES: u32 = 1440;

/// The most rolling backups worth keeping beside a vault. Past this the folder
/// beside the vault is noise, and every one of them is a full copy of the
/// encrypted file.
const MAX_BACKUP_COUNT: usize = 20;

// ===================================================================== slots

/// The key slots of the open vault.
#[tauri::command]
pub(crate) fn vault_slots(state: State<'_, AppState>) -> Result<VaultSlotsDto, IpcError> {
    vault_slots_impl(&state)
}

fn vault_slots_impl(state: &AppState) -> Result<VaultSlotsDto, IpcError> {
    let mut guard = state.lock();
    let vault = guard.vault_ref()?;
    Ok(VaultSlotsDto {
        slots: vault.slots().iter().map(slot_dto).collect(),
        opened_with: vault.opened_with(),
        backup_count: vault.backup_count(),
    })
}

/// Adds a password slot: a second password, or a password plus a key file.
///
/// Adding a slot re-wraps the master key under a new credential. It does not
/// re-encrypt the body, which is why it is instant on a vault of any size.
#[tauri::command]
pub(crate) fn vault_add_password_slot(
    state: State<'_, AppState>,
    req: AddPasswordSlotDto,
) -> Result<SlotDto, IpcError> {
    vault_add_password_slot_impl(&state, req)
}

fn vault_add_password_slot_impl(
    state: &AppState,
    req: AddPasswordSlotDto,
) -> Result<SlotDto, IpcError> {
    let AddPasswordSlotDto {
        label,
        password,
        keyfile_path,
    } = req;

    // Wrapped before the first fallible step, as everywhere else a password
    // arrives from the interface.
    let password = Secret::new(password);
    let label = label.trim().to_owned();
    if label.is_empty() {
        return Err(IpcError::new(
            "slot.label-empty",
            "A key slot needs a name, so the list can say which key this is.",
        )
        .with_actions(["Type a name for this slot"]));
    }
    check_password_strength(&password)?;

    let keyfile = match keyfile_path {
        Some(path) => Some(existing_keyfile(PathBuf::from(path))?),
        None => None,
    };

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let index = vault
        .add_password_slot(label, &password, keyfile.as_deref(), None)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    save(vault)?;

    slot_by_index(vault, index)
}

/// Issues another recovery key.
///
/// Returned once, after the write that made it real. A vault may hold more than
/// one: a sealed envelope in a safe is a legitimate reason to want two.
#[tauri::command]
pub(crate) fn vault_add_recovery_slot(
    state: State<'_, AppState>,
    label: String,
) -> Result<RecoveryKeyDto, IpcError> {
    vault_add_recovery_slot_impl(&state, label)
}

fn vault_add_recovery_slot_impl(
    state: &AppState,
    label: String,
) -> Result<RecoveryKeyDto, IpcError> {
    let label = label.trim().to_owned();
    if label.is_empty() {
        return Err(IpcError::new(
            "slot.label-empty",
            "A key slot needs a name, so the list can say which key this is.",
        )
        .with_actions(["Type a name for this slot"]));
    }

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let (index, key) = vault
        .add_recovery_slot(label)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;

    // Saved before the key is rendered: a key the user writes down out of a
    // vault that never reached the disk is a key that opens nothing.
    save(vault)?;
    recovery_dto(index, &key)
}

/// Enrols this machine's credential store, so the vault opens without a prompt
/// while the user is logged in.
#[tauri::command]
pub(crate) fn vault_add_keychain_slot(
    state: State<'_, AppState>,
    label: String,
) -> Result<SlotDto, IpcError> {
    vault_add_keychain_slot_impl(&state, label)
}

fn vault_add_keychain_slot_impl(state: &AppState, label: String) -> Result<SlotDto, IpcError> {
    let label = label.trim().to_owned();
    if label.is_empty() {
        return Err(IpcError::new(
            "slot.label-empty",
            "A key slot needs a name, so the list can say which machine this is.",
        )
        .with_actions(["Type a name for this slot"]));
    }

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let index = vault
        .add_keychain_slot(label)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    save(vault)?;

    slot_by_index(vault, index)
}

/// Revokes a slot.
///
/// Revocation deletes the slot entry, so a lost hardware key can be revoked
/// without having it to hand. The last slot is refused with `vault.last-slot`:
/// a vault with an empty slot table is a file nobody can ever open again, and
/// there is no escrow key and no support override.
#[tauri::command]
pub(crate) fn vault_remove_slot(state: State<'_, AppState>, index: u8) -> Result<(), IpcError> {
    vault_remove_slot_impl(&state, index)
}

fn vault_remove_slot_impl(state: &AppState, index: u8) -> Result<(), IpcError> {
    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    vault
        .remove_slot(index)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    save(vault)
}

/// Re-wraps one password slot under a new password or key file.
///
/// The master key does not change: nothing is re-encrypted, every other slot
/// keeps working, and the recovery key stays valid. The current credential is
/// verified before anything is replaced — a rewrap without that check would
/// destroy the only copy of the master key that slot held, and the user would
/// find out at the next unlock.
#[tauri::command]
pub(crate) fn vault_change_master_password(
    state: State<'_, AppState>,
    req: ChangePasswordDto,
) -> Result<(), IpcError> {
    vault_change_master_password_impl(&state, req)
}

fn vault_change_master_password_impl(
    state: &AppState,
    req: ChangePasswordDto,
) -> Result<(), IpcError> {
    let ChangePasswordDto {
        slot_index,
        current_password,
        current_keyfile_path,
        new_password,
        new_keyfile_path,
    } = req;

    // Both passwords into wiping buffers before the first fallible step.
    let current_password = Secret::new(current_password);
    let new_password = Secret::new(new_password);
    let index = slot_index.unwrap_or(0);
    check_password_strength(&new_password)?;

    let mut current = PasswordCredential::new(current_password);
    if let Some(path) = current_keyfile_path {
        current = current.with_keyfile(existing_keyfile(PathBuf::from(path))?);
    }
    let mut new = PasswordCredential::new(new_password);
    let new_keyfile = match new_keyfile_path {
        Some(path) => Some(existing_keyfile(PathBuf::from(path))?),
        None => None,
    };
    if let Some(path) = &new_keyfile {
        new = new.with_keyfile(path.clone());
    }

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    // Saves on success, and puts the slot table back if the write fails.
    vault
        .change_password_slot(index, &current, &new, None)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;

    // The unlock screen offers back the key file this vault was last opened
    // with. If the slot the session was opened through now needs a different
    // file — or none — remembering the old one sends the user to a file that
    // no longer opens anything.
    if vault.opened_with() == Some(index) {
        let path = vault.path().to_path_buf();
        let label = vault.label().to_owned();
        let slots = vault
            .slots()
            .iter()
            .map(|slot| slot.kind.as_str().to_owned())
            .collect();
        let keyfile = new_keyfile.map(|path| path.display().to_string());
        let now = now_seconds();
        if let Err(err) =
            guard.update_recents(|recents| recents.record(&path, &label, slots, keyfile, now))
        {
            tracing::warn!(
                "the recent-vault list could not be written: {}",
                err.message
            );
        }
    }
    Ok(())
}

/// Replaces a recovery slot's key.
///
/// The old key stops working; the new one is returned exactly once. The master
/// key does not change, so every other slot is untouched.
#[tauri::command]
pub(crate) fn vault_rotate_recovery_key(
    state: State<'_, AppState>,
    index: u8,
) -> Result<RecoveryKeyDto, IpcError> {
    vault_rotate_recovery_key_impl(&state, index)
}

fn vault_rotate_recovery_key_impl(state: &AppState, index: u8) -> Result<RecoveryKeyDto, IpcError> {
    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    // Saves before it returns, and restores the slot table if the write fails.
    let key = vault
        .rotate_recovery_key(index)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    recovery_dto(index, &key)
}

/// Replaces the vault master key: every slot re-wrapped, every stored secret
/// re-sealed, the body re-encrypted.
///
/// The answer to "a copy of this file may have leaked while one of my keys was
/// compromised". What it does **not** do is make the leaked copy unreadable —
/// that file still opens with the old keys, including the rolling backups
/// beside the vault, which this save rotates. The interface says so; this
/// mapping is where the sentence would otherwise be lost.
#[tauri::command]
pub(crate) fn vault_rotate_master_key(
    state: State<'_, AppState>,
    req: RotateMasterKeyDto,
) -> Result<RotationOutcomeDto, IpcError> {
    vault_rotate_master_key_impl(&state, req)
}

fn vault_rotate_master_key_impl(
    state: &AppState,
    req: RotateMasterKeyDto,
) -> Result<RotationOutcomeDto, IpcError> {
    let RotateMasterKeyDto {
        credentials,
        drop_slots,
    } = req;

    // Every password into a wiping buffer before anything can fail, including
    // the key file checks below.
    let mut plan = RotationPlan::new();
    for entry in credentials {
        let mut credential = PasswordCredential::new(Secret::new(entry.password));
        if let Some(path) = entry.keyfile_path {
            credential = credential.with_keyfile(existing_keyfile(PathBuf::from(path))?);
        }
        plan = plan.with_password(entry.index, credential);
    }
    for index in drop_slots {
        plan = plan.dropping(index);
    }

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    // Refuses before a single key is generated if the plan does not account
    // for every slot, and puts the vault back as it was on a failed write.
    let outcome = vault
        .rotate_master_key(&plan)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;

    let mut recovery_keys = Vec::with_capacity(outcome.recovery_keys.len());
    for (index, key) in &outcome.recovery_keys {
        recovery_keys.push(recovery_dto(*index, key)?);
    }

    Ok(RotationOutcomeDto {
        rewrapped: outcome.rewrapped,
        dropped: outcome.dropped,
        recovery_keys,
        secrets_resealed: outcome.secrets_resealed,
    })
}

// ================================================================== settings

/// The settings that travel with the vault file.
#[tauri::command]
pub(crate) fn vault_settings_get(state: State<'_, AppState>) -> Result<VaultSettingsDto, IpcError> {
    vault_settings_get_impl(&state)
}

fn vault_settings_get_impl(state: &AppState) -> Result<VaultSettingsDto, IpcError> {
    let mut guard = state.lock();
    let vault = guard.vault_ref()?;
    let settings = vault
        .settings()
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    Ok(settings_dto(&settings))
}

/// Merges a patch into the vault's settings and writes them out.
///
/// The changed field *names* reach the vault's audit log; the values do not
/// need to, and a setting that did not change writes no row at all.
#[tauri::command]
pub(crate) fn vault_settings_set(
    state: State<'_, AppState>,
    patch: VaultSettingsPatchDto,
) -> Result<VaultSettingsDto, IpcError> {
    vault_settings_set_impl(&state, patch)
}

fn vault_settings_set_impl(
    state: &AppState,
    patch: VaultSettingsPatchDto,
) -> Result<VaultSettingsDto, IpcError> {
    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let mut settings = vault
        .settings()
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;

    if let Some(minutes) = patch.auto_lock_minutes {
        settings.auto_lock_minutes = minutes.min(MAX_AUTO_LOCK_MINUTES);
    }
    if let Some(value) = patch.lock_on_screen_lock {
        settings.lock_on_screen_lock = value;
    }
    if let Some(value) = patch.lock_on_suspend {
        settings.lock_on_suspend = value;
    }
    if let Some(value) = patch.lock_on_minimise {
        settings.lock_on_minimise = value;
    }
    if let Some(value) = patch.session_on_lock {
        settings.session_on_lock = SessionOnLock::parse(&value).ok_or_else(|| {
            IpcError::invalid_request(
                "sessionOnLock",
                format!(
                    "`{value}` is not one of {}",
                    SessionOnLock::ALL
                        .iter()
                        .map(|policy| policy.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })?;
    }
    if let Some(value) = patch.recording {
        settings.recording = parse_recording(&value)?;
    }
    if let Some(count) = patch.backup_count {
        settings.backup_count = count.min(MAX_BACKUP_COUNT);
    }

    vault
        .set_settings(&settings)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    save(vault)?;

    // Read back rather than returned from the copy in hand: `set_settings`
    // applies the backup count to the header, and the header is the source of
    // truth for it.
    let stored = vault
        .settings()
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    Ok(settings_dto(&stored))
}

// =================================================================== helpers

/// Adds the machine-side half: which lock triggers this build can honour here.
///
/// Sent with every read and every write of the settings, so the screen can
/// never render a switch without knowing whether it does anything.
fn settings_dto(settings: &VaultSettings) -> VaultSettingsDto {
    VaultSettingsDto {
        auto_lock_minutes: settings.auto_lock_minutes,
        lock_on_screen_lock: settings.lock_on_screen_lock,
        lock_on_suspend: settings.lock_on_suspend,
        lock_on_minimise: settings.lock_on_minimise,
        lock_triggers: LockTriggerSupportDto {
            screen_lock: LockTrigger::ScreenLock.observation().to_owned(),
            suspend: LockTrigger::Suspend.observation().to_owned(),
            minimise: LockTrigger::Minimise.observation().to_owned(),
        },
        session_on_lock: settings.session_on_lock.as_str().to_owned(),
        recording: recording_wire(settings.recording).to_owned(),
        backup_count: settings.backup_count,
    }
}

/// The wire spelling of a recording policy. Stable ASCII, not a rendering:
/// the interface translates it.
pub(crate) const fn recording_wire(policy: RecordingPolicy) -> &'static str {
    match policy {
        RecordingPolicy::Never => "never",
        RecordingPolicy::OnRequest => "on_request",
        RecordingPolicy::Always => "always",
    }
}

fn parse_recording(text: &str) -> Result<RecordingPolicy, IpcError> {
    match text {
        "never" => Ok(RecordingPolicy::Never),
        "on_request" => Ok(RecordingPolicy::OnRequest),
        "always" => Ok(RecordingPolicy::Always),
        other => Err(IpcError::invalid_request(
            "recording",
            format!("`{other}` is not one of never, on_request, always"),
        )),
    }
}

/// The strength gate `vault_create` applies, applied to every password slot.
///
/// A vault is as strong as its weakest slot, so a second password that is
/// easily guessed undoes the first one rather than adding to it.
fn check_password_strength(password: &Secret<String>) -> Result<(), IpcError> {
    if password.expose_secret().is_empty() {
        return Err(IpcError::new(
            "vault.password-empty",
            "A key slot needs a password. Nothing can be derived without one.",
        )
        .with_actions(["Type a password", "Generate a passphrase"]));
    }

    let strength = estimate_strength(password.expose_secret());
    if strength.acceptable {
        return Ok(());
    }
    Err(IpcError::new(
        "vault.password-too-weak",
        format!(
            "That password is too easy to guess, and a vault is only as strong as its \
             weakest slot. {} Argon2id raises the cost of every guess, but it cannot \
             rescue a password an attacker tries early.",
            strength.explanation
        ),
    )
    .with_actions([
        "Generate a passphrase",
        "Use a longer, less predictable password",
    ]))
}

/// Checks a key file is where the user says it is, before it is enrolled.
///
/// A slot wrapped around a file that is not there is a slot that opens nothing,
/// and the failure would arrive at the next unlock rather than now.
fn existing_keyfile(path: PathBuf) -> Result<PathBuf, IpcError> {
    if path.is_file() {
        return Ok(path);
    }
    Err(IpcError::bad_path(
        &path,
        "there is no file there to use as a key file",
    ))
}

/// One slot, read back from the vault after it was added.
fn slot_by_index(vault: &Vault, index: u8) -> Result<SlotDto, IpcError> {
    vault
        .slots()
        .iter()
        .find(|slot| slot.index == index)
        .map(slot_dto)
        .ok_or_else(|| {
            IpcError::from_vault(&remoter_vault::VaultError::NoSuchSlot(index), "this vault")
        })
}

/// Renders a recovery key for its single showing, and picks the group the
/// transcription check will ask for.
fn recovery_dto(index: u8, key: &RecoveryKey) -> Result<RecoveryKeyDto, IpcError> {
    // `groups` stays in the zeroizing buffer `RecoveryKey::groups` returns; the
    // one copy that escapes is the DTO, which is what the screen shows.
    let groups = key
        .groups()
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    let confirm_group_index =
        usize::try_from(uniform_below(u32::try_from(groups.len()).unwrap_or(1))?).unwrap_or(0);

    Ok(RecoveryKeyDto {
        slot_index: index,
        recovery_key_groups: groups.to_vec(),
        confirm_group_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vault_lock_impl;
    use crate::dto::UnlockRequestDto;
    use crate::test_support::{PASSPHRASE, Scratch, open_vault, why};

    /// The strength gate runs before the state lock, so it answers even with no
    /// vault open — and that is the point: a weak slot is refused on its own
    /// terms rather than as "no vault".
    #[test]
    fn a_weak_slot_password_is_refused_before_the_vault_is_touched() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));

        let refused = vault_add_password_slot_impl(
            &state,
            AddPasswordSlotDto {
                label: String::from("Laptop"),
                password: String::from("password123"),
                keyfile_path: None,
            },
        );
        assert!(
            refused.is_err_and(|err| err.code == "vault.password-too-weak"),
            "a second password that is easily guessed undoes the first"
        );
    }

    #[test]
    fn a_slot_needs_a_name() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));
        let refused = vault_add_recovery_slot_impl(&state, String::from("   "));
        assert!(refused.is_err_and(|err| err.code == "slot.label-empty"));
    }

    #[test]
    fn a_key_file_that_is_not_there_is_refused_rather_than_enrolled() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));

        let refused = vault_add_password_slot_impl(
            &state,
            AddPasswordSlotDto {
                label: String::from("USB stick"),
                password: String::from(PASSPHRASE),
                keyfile_path: Some(scratch.join("absent.key").display().to_string()),
            },
        );
        assert!(
            refused.is_err_and(|err| err.code == "path.unusable"),
            "a slot wrapped around a missing file opens nothing"
        );
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "a slot test without a vault has nothing left to assert"
    )]
    fn slots_can_be_added_and_revoked_but_never_the_last_one() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        // A new vault carries the master password slot and its recovery slot.
        let listed = vault_slots_impl(&state);
        assert!(listed.is_ok(), "listing failed: {}", why(&listed));
        let Ok(listed) = listed else {
            panic!("listing failed");
        };
        assert_eq!(listed.slots.len(), 2);
        // A vault that was created rather than opened was not reached through
        // a slot, so there is none to mark.
        assert_eq!(listed.opened_with, None);
        assert!(
            listed
                .slots
                .iter()
                .any(|slot| slot.kind == "password" && slot.kdf_summary.is_some()),
            "the password slot reports its Argon2id parameters: {:?}",
            listed.slots
        );

        // The recovery slot goes, and then the master slot cannot.
        assert!(vault_remove_slot_impl(&state, 1).is_ok());
        let refused = vault_remove_slot_impl(&state, 0);
        assert!(
            refused.is_err_and(|err| err.code == "vault.last-slot"),
            "removing the only way in must have its own code"
        );

        // And a slot that was never there is named as such.
        let missing = vault_remove_slot_impl(&state, 9);
        assert!(missing.is_err_and(|err| err.code == "vault.no-such-slot"));
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "a rotation test without a vault has nothing left to assert"
    )]
    fn rotating_the_recovery_key_issues_a_different_key() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        let first = vault_rotate_recovery_key_impl(&state, 1);
        assert!(first.is_ok(), "rotating failed: {}", why(&first));
        let second = vault_rotate_recovery_key_impl(&state, 1);
        assert!(second.is_ok(), "rotating failed: {}", why(&second));

        let (Ok(first), Ok(second)) = (first, second) else {
            panic!("rotating failed");
        };
        assert_eq!(first.slot_index, 1);
        assert_ne!(
            first.recovery_key_groups, second.recovery_key_groups,
            "a rotated key is a new key; the old one stops working"
        );
        assert!(first.confirm_group_index < first.recovery_key_groups.len());

        // The password slot is not a recovery slot, and the refusal says so.
        let wrong = vault_rotate_recovery_key_impl(&state, 0);
        assert!(
            wrong
                .as_ref()
                .is_err_and(|err| err.code == "vault.wrong-slot-kind"),
            "rotating a password slot as a recovery slot: {}",
            why(&wrong)
        );
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "a password test without a vault has nothing left to assert"
    )]
    fn the_master_password_changes_only_for_the_password_that_opens_the_slot() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let path = scratch.join("test.rvault").display().to_string();
        const NEW: &str = "granite-harbour-jasmine-kettle-lantern-marble";

        let refused = vault_change_master_password_impl(
            &state,
            ChangePasswordDto {
                slot_index: None,
                current_password: String::from("not the password"),
                current_keyfile_path: None,
                new_password: String::from(NEW),
                new_keyfile_path: None,
            },
        );
        assert!(
            refused.is_err_and(|err| err.code == "vault.slot-credential-rejected"),
            "a rewrap that skipped the check would destroy the only copy of the master key"
        );

        let changed = vault_change_master_password_impl(
            &state,
            ChangePasswordDto {
                slot_index: None,
                current_password: String::from(PASSPHRASE),
                current_keyfile_path: None,
                new_password: String::from(NEW),
                new_keyfile_path: None,
            },
        );
        assert!(changed.is_ok(), "changing failed: {}", why(&changed));

        // The new password opens the file, and the old one does not.
        assert!(vault_lock_impl(&state).is_ok());
        let stale = crate::commands::vault_unlock_impl(
            &state,
            path.clone(),
            UnlockRequestDto::Password {
                password: String::from(PASSPHRASE),
                keyfile_path: None,
            },
        );
        assert!(stale.is_err_and(|err| err.code == "vault.unlock-failed"));

        let opened = crate::commands::vault_unlock_impl(
            &state,
            path,
            UnlockRequestDto::Password {
                password: String::from(NEW),
                keyfile_path: None,
            },
        );
        assert!(opened.is_ok(), "unlocking failed: {}", why(&opened));
    }

    #[test]
    fn a_new_master_password_meets_the_same_bar_as_the_first() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));

        let refused = vault_change_master_password_impl(
            &state,
            ChangePasswordDto {
                slot_index: None,
                current_password: String::from(PASSPHRASE),
                current_keyfile_path: None,
                new_password: String::from("hunter2"),
                new_keyfile_path: None,
            },
        );
        assert!(refused.is_err_and(|err| err.code == "vault.password-too-weak"));
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "a settings test without a vault has nothing left to assert"
    )]
    fn vault_settings_round_trip_and_refuse_a_policy_that_does_not_exist() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        let defaults = vault_settings_get_impl(&state);
        assert!(defaults.is_ok(), "reading failed: {}", why(&defaults));
        let Ok(defaults) = defaults else {
            panic!("reading failed");
        };
        assert_eq!(defaults.auto_lock_minutes, 15);
        assert_eq!(defaults.session_on_lock, "keep_running");
        assert_eq!(defaults.recording, "never");
        assert!(defaults.lock_on_screen_lock);
        assert!(!defaults.lock_on_minimise);

        let patched = vault_settings_set_impl(
            &state,
            VaultSettingsPatchDto {
                auto_lock_minutes: Some(5),
                lock_on_minimise: Some(true),
                session_on_lock: Some(String::from("disconnect_all")),
                recording: Some(String::from("always")),
                backup_count: Some(4),
                ..VaultSettingsPatchDto::default()
            },
        );
        assert!(patched.is_ok(), "writing failed: {}", why(&patched));
        let Ok(patched) = patched else {
            panic!("writing failed");
        };
        assert_eq!(patched.auto_lock_minutes, 5);
        assert!(patched.lock_on_minimise);
        assert_eq!(patched.session_on_lock, "disconnect_all");
        assert_eq!(patched.recording, "always");
        // The header is the source of truth for the backup count, and reading
        // it back is what proves the two do not disagree.
        assert_eq!(patched.backup_count, 4);

        let refused = vault_settings_set_impl(
            &state,
            VaultSettingsPatchDto {
                session_on_lock: Some(String::from("panic")),
                ..VaultSettingsPatchDto::default()
            },
        );
        assert!(
            refused
                .as_ref()
                .is_err_and(|err| err.code == "request.invalid")
        );
        if let Err(err) = refused {
            assert!(
                err.message.contains("keep_running"),
                "the refusal names the policies that exist: {}",
                err.message
            );
        }

        // An hour past a day is clamped rather than stored.
        let clamped = vault_settings_set_impl(
            &state,
            VaultSettingsPatchDto {
                auto_lock_minutes: Some(100_000),
                ..VaultSettingsPatchDto::default()
            },
        );
        assert_eq!(
            clamped.ok().map(|settings| settings.auto_lock_minutes),
            Some(MAX_AUTO_LOCK_MINUTES)
        );
    }

    #[test]
    fn every_slot_command_says_no_vault_is_open_rather_than_failing_obscurely() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));

        assert!(vault_slots_impl(&state).is_err_and(|err| err.code == "vault.locked"));
        assert!(vault_remove_slot_impl(&state, 0).is_err_and(|err| err.code == "vault.locked"));
        assert!(
            vault_rotate_recovery_key_impl(&state, 1).is_err_and(|err| err.code == "vault.locked")
        );
        assert!(vault_settings_get_impl(&state).is_err_and(|err| err.code == "vault.locked"));
        assert!(
            vault_add_keychain_slot_impl(&state, String::from("This machine"))
                .is_err_and(|err| err.code == "vault.locked")
        );
    }

    #[test]
    fn the_recording_spellings_round_trip() {
        for policy in [
            RecordingPolicy::Never,
            RecordingPolicy::OnRequest,
            RecordingPolicy::Always,
        ] {
            let wire = recording_wire(policy);
            assert_eq!(parse_recording(wire).ok(), Some(policy), "wire: {wire}");
        }
        assert!(parse_recording("sometimes").is_err());
    }

    // ------------------------------------------------------ auto-lock ------
    //
    // These are the tests for the defect the reviewer found: the Vault settings
    // screen wrote `vault.settings.auto_lock_minutes` and the countdown read
    // the application-level one, so picking "1 min" or "Never" here changed
    // nothing whatsoever. Each of them fails on the code as it was.

    /// The value this screen writes is the value the countdown reads.
    #[test]
    #[expect(
        clippy::panic,
        reason = "an auto-lock test without a vault has nothing left to assert"
    )]
    fn the_timeout_written_here_is_the_one_the_countdown_uses() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        // The default the vault was created with. A range rather than an
        // equality: the countdown is a real clock, and the assertion is that
        // it is counting down from fifteen minutes rather than that no time
        // has passed since the vault opened.
        let default_countdown = state.lock().locks_in_seconds();
        assert!(
            default_countdown.is_some_and(|seconds| (14 * 60..=15 * 60).contains(&seconds)),
            "a fresh vault counts down from its own fifteen minutes: {default_countdown:?}"
        );

        let saved = vault_settings_set_impl(
            &state,
            VaultSettingsPatchDto {
                auto_lock_minutes: Some(1),
                ..VaultSettingsPatchDto::default()
            },
        );
        assert!(saved.is_ok(), "writing failed: {}", why(&saved));

        let countdown = state.lock().locks_in_seconds();
        assert!(
            countdown.is_some_and(|seconds| (30..=60).contains(&seconds)),
            "the screen that edits the timeout has to be the screen that changes it: \
             {countdown:?}"
        );
    }

    /// "Never" means never, and not "fall back to the machine's default".
    #[test]
    #[expect(
        clippy::panic,
        reason = "an auto-lock test without a vault has nothing left to assert"
    )]
    fn never_genuinely_never_locks() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        let saved = vault_settings_set_impl(
            &state,
            VaultSettingsPatchDto {
                auto_lock_minutes: Some(0),
                ..VaultSettingsPatchDto::default()
            },
        );
        assert!(saved.is_ok(), "writing failed: {}", why(&saved));

        assert_eq!(
            state.lock().locks_in_seconds(),
            None,
            "no countdown, because there is no deadline"
        );

        // A day of idleness, against a machine default of fifteen minutes.
        {
            let mut guard = state.lock();
            guard.expire_activity();
            guard.enforce_auto_lock();
        }
        assert!(
            vault_settings_get_impl(&state).is_ok(),
            "the vault locked itself after the user chose never"
        );
    }

    /// Traffic in a session is activity, so the vault does not lock under a
    /// user who is working in it.
    #[test]
    #[expect(
        clippy::panic,
        reason = "an auto-lock test without a vault has nothing left to assert"
    )]
    fn a_session_carrying_traffic_holds_the_lock_off() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        // Idle past the timeout, and then a frame of session output arrives —
        // which is what `session_input` and the event forwarder do to this
        // clock, without touching the vault.
        {
            let mut guard = state.lock();
            guard.expire_activity();
        }
        state.activity().touch();
        {
            let mut guard = state.lock();
            guard.enforce_auto_lock();
        }

        assert!(
            vault_settings_get_impl(&state).is_ok(),
            "a session carrying traffic is not an idle vault"
        );

        // And with nothing arriving, it locks as it should.
        {
            let mut guard = state.lock();
            guard.expire_activity();
            guard.enforce_auto_lock();
        }
        assert!(
            vault_settings_get_impl(&state).is_err_and(|err| err.code == "vault.auto-locked"),
            "idle past the timeout still has to lock"
        );
    }

    /// Each observed event locks when its switch is on, and does not when it is
    /// off.
    #[test]
    #[expect(
        clippy::panic,
        reason = "a trigger test without a vault has nothing left to assert"
    )]
    fn a_lock_trigger_is_honoured_only_when_its_switch_is_on() {
        for trigger in LockTrigger::ALL.iter().copied() {
            let scratch = Scratch::new();
            let Some(state) = open_vault(&scratch) else {
                panic!("the vault could not be created");
            };

            // Switched off: the event happens and the vault stays open.
            let off = vault_settings_set_impl(&state, all_triggers(false));
            assert!(off.is_ok(), "writing failed: {}", why(&off));
            assert!(
                !state.lock().lock_for_trigger(trigger),
                "{trigger:?} locked the vault with its switch off"
            );
            assert!(
                vault_settings_get_impl(&state).is_ok(),
                "{trigger:?} locked the vault with its switch off"
            );

            // Switched on: the same event locks it, and says why.
            let on = vault_settings_set_impl(&state, all_triggers(true));
            assert!(on.is_ok(), "writing failed: {}", why(&on));
            assert!(
                state.lock().lock_for_trigger(trigger),
                "{trigger:?} did nothing with its switch on"
            );

            let refused = vault_settings_get_impl(&state);
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|err| err.code == "vault.locked-by-trigger"),
                "{trigger:?} left the vault open"
            );
            if let Err(err) = refused {
                assert!(
                    err.message.contains(trigger.describe()),
                    "the message names the event: {}",
                    err.message
                );
            }
        }
    }

    /// A trigger with no vault open is a no-op rather than a failure.
    #[test]
    fn a_trigger_with_no_vault_open_does_nothing() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));
        for trigger in LockTrigger::ALL.iter().copied() {
            assert!(!state.lock().lock_for_trigger(trigger));
        }
    }

    /// The screen is told which switches this build can honour, so it can
    /// disable the ones it cannot instead of persisting a value nothing reads.
    #[test]
    #[expect(
        clippy::panic,
        reason = "a settings test without a vault has nothing left to assert"
    )]
    fn the_settings_say_which_lock_triggers_this_build_can_observe() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        let read = vault_settings_get_impl(&state);
        assert!(read.is_ok(), "reading failed: {}", why(&read));
        let Ok(read) = read else {
            panic!("reading failed");
        };

        for observation in [
            read.lock_triggers.screen_lock.as_str(),
            read.lock_triggers.suspend.as_str(),
            read.lock_triggers.minimise.as_str(),
        ] {
            assert!(
                ["observed", "on_resume", "unobserved"].contains(&observation),
                "the interface only knows three spellings, not `{observation}`"
            );
        }

        // What this build actually manages, stated rather than implied. If one
        // of these gains a watcher, this assertion is the reminder to change
        // the sentence on the screen with it.
        assert_eq!(read.lock_triggers.screen_lock, "unobserved");
        assert_eq!(read.lock_triggers.minimise, "unobserved");
        assert_eq!(
            read.lock_triggers.suspend,
            if cfg!(target_os = "linux") {
                "on_resume"
            } else {
                "unobserved"
            }
        );
    }

    /// Every trigger switch on or off in one patch.
    fn all_triggers(on: bool) -> VaultSettingsPatchDto {
        VaultSettingsPatchDto {
            lock_on_screen_lock: Some(on),
            lock_on_suspend: Some(on),
            lock_on_minimise: Some(on),
            ..VaultSettingsPatchDto::default()
        }
    }
}
