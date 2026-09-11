//! Per-vault settings.
//!
//! These travel with the vault file rather than with the machine: a user who
//! sets "disconnect everything on lock" on a production vault means it wherever
//! they open that vault. They live in the `settings` table inside the encrypted
//! body, under one key, as CBOR.
//!
//! The defaults are the table in `docs/security/key-management.md#auto-lock`.
//!
//! # Where the backup count lives
//!
//! [`VaultSettings::backup_count`] is a **view of the header field**, not a
//! second copy. The header is the single source of truth, because the count has
//! to be known before the body is decrypted — a vault that cannot be opened is
//! exactly when the rolling backups matter — and because
//! [`crate::VaultHeader::backup_count`] is already covered by the header MAC.
//! Reading settings fills the field in from the header; writing them applies it
//! back to the header. It is deliberately not serialised into the settings blob,
//! so the two can never disagree.

use remoter_core::RecordingPolicy;
use serde::{Deserialize, Serialize};

/// The settings key the blob is filed under.
pub(crate) const SETTINGS_KEY: &str = "vault.settings";

/// Default idle timeout, in minutes.
const DEFAULT_AUTO_LOCK_MINUTES: u32 = 15;

/// What happens to running sessions when the vault locks.
///
/// The default keeps them running: an administrator watching a long deployment
/// does not want their session killed because they went for coffee. The other
/// two exist because that trade-off is a policy decision, not a universal one.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SessionOnLock {
    /// Sessions stay connected and keep producing output.
    #[default]
    KeepRunning,
    /// Sessions stay connected but accept no input until the vault is unlocked.
    FreezeInput,
    /// Every session is closed. Strictest, and loses transfers in progress.
    DisconnectAll,
}

impl SessionOnLock {
    /// Every policy, in the order the settings screen lists them.
    pub const ALL: &'static [Self] = &[Self::KeepRunning, Self::FreezeInput, Self::DisconnectAll];

    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeepRunning => "keep_running",
            Self::FreezeInput => "freeze_input",
            Self::DisconnectAll => "disconnect_all",
        }
    }

    /// Reads back a stored spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_str() == text)
    }
}

impl core::fmt::Display for SessionOnLock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The settings the Vault settings screen writes.
///
/// Every field is defaulted on read, so a vault written before a field existed
/// loads with this build's default for it rather than being refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSettings {
    /// Lock after this many minutes of input idleness. Zero means never.
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: u32,

    /// Lock when the operating system's screen or session lock engages.
    #[serde(default = "enabled")]
    pub lock_on_screen_lock: bool,

    /// Lock when the machine suspends or hibernates.
    #[serde(default = "enabled")]
    pub lock_on_suspend: bool,

    /// Lock when the window is minimised. Off by default: people minimise far
    /// more often than they walk away.
    #[serde(default)]
    pub lock_on_minimise: bool,

    /// What happens to running sessions when the vault locks. Changing it is
    /// written to the audit log.
    #[serde(default)]
    pub session_on_lock: SessionOnLock,

    /// The recording policy inherited by everything in this vault that does not
    /// set its own.
    #[serde(default)]
    pub recording: RecordingPolicy,

    /// How many rolling backups are kept beside the vault file.
    ///
    /// A view of the header field; see the module documentation. Not
    /// serialised, so the header stays the only place it is stored.
    #[serde(skip)]
    pub backup_count: usize,
}

/// Serde default for [`VaultSettings::auto_lock_minutes`].
const fn default_auto_lock_minutes() -> u32 {
    DEFAULT_AUTO_LOCK_MINUTES
}

/// Serde default for the two lock triggers that are on by default.
const fn enabled() -> bool {
    true
}

impl Default for VaultSettings {
    /// The table in `docs/security/key-management.md`. `backup_count` is filled
    /// in from the header the moment these are read from a vault.
    fn default() -> Self {
        Self {
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            lock_on_screen_lock: true,
            lock_on_suspend: true,
            lock_on_minimise: false,
            session_on_lock: SessionOnLock::default(),
            recording: RecordingPolicy::default(),
            backup_count: 0,
        }
    }
}

impl VaultSettings {
    /// The names of the fields that differ between two sets, for the audit
    /// detail.
    ///
    /// Field *names*, never values: the detail column is exported wholesale by
    /// the compliance features, and a settings value is user data even when it
    /// is not a secret.
    #[must_use]
    pub(crate) fn changed_fields(&self, other: &Self) -> Vec<&'static str> {
        let mut changed = Vec::new();
        if self.auto_lock_minutes != other.auto_lock_minutes {
            changed.push("auto_lock_minutes");
        }
        if self.lock_on_screen_lock != other.lock_on_screen_lock {
            changed.push("lock_on_screen_lock");
        }
        if self.lock_on_suspend != other.lock_on_suspend {
            changed.push("lock_on_suspend");
        }
        if self.lock_on_minimise != other.lock_on_minimise {
            changed.push("lock_on_minimise");
        }
        if self.session_on_lock != other.session_on_lock {
            changed.push("session_on_lock");
        }
        if self.recording != other.recording {
            changed.push("recording");
        }
        if self.backup_count != other.backup_count {
            changed.push("backup_count");
        }
        changed
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

    #[test]
    fn the_defaults_match_the_specification() {
        let settings = VaultSettings::default();
        assert_eq!(settings.auto_lock_minutes, 15);
        assert!(settings.lock_on_screen_lock);
        assert!(settings.lock_on_suspend);
        assert!(!settings.lock_on_minimise);
        assert_eq!(settings.session_on_lock, SessionOnLock::KeepRunning);
        assert_eq!(settings.recording, RecordingPolicy::Never);
    }

    #[test]
    fn a_blob_written_before_a_field_existed_loads_with_this_builds_default() {
        // What an older build wrote: only the two fields it knew about.
        let mut encoded = Vec::new();
        ciborium::into_writer(
            &ciborium::value::Value::Map(vec![(
                ciborium::value::Value::Text("auto_lock_minutes".into()),
                ciborium::value::Value::Integer(5.into()),
            )]),
            &mut encoded,
        )
        .unwrap();

        let back: VaultSettings = ciborium::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(back.auto_lock_minutes, 5);
        assert!(
            back.lock_on_screen_lock,
            "a missing trigger must default on"
        );
        assert_eq!(back.session_on_lock, SessionOnLock::KeepRunning);
    }

    #[test]
    fn the_backup_count_is_not_part_of_the_blob() {
        // One source of truth: the header. If this field ever serialised, a
        // vault could disagree with itself about how many backups it keeps.
        let settings = VaultSettings {
            backup_count: 7,
            ..VaultSettings::default()
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&settings, &mut encoded).unwrap();
        let value: ciborium::value::Value = ciborium::from_reader(encoded.as_slice()).unwrap();

        let map = value.as_map().expect("settings encode as a CBOR map");
        assert!(
            !map.iter().any(|(k, _)| k.as_text() == Some("backup_count")),
            "backup_count must live in the header alone"
        );
    }

    #[test]
    fn policy_names_round_trip() {
        for policy in SessionOnLock::ALL {
            assert_eq!(SessionOnLock::parse(policy.as_str()), Some(*policy));
        }
        assert_eq!(SessionOnLock::parse("something else"), None);
    }

    #[test]
    fn the_changed_field_list_names_fields_and_not_values() {
        let before = VaultSettings::default();
        let after = VaultSettings {
            auto_lock_minutes: 30,
            session_on_lock: SessionOnLock::DisconnectAll,
            ..VaultSettings::default()
        };
        assert_eq!(
            before.changed_fields(&after),
            vec!["auto_lock_minutes", "session_on_lock"]
        );
        assert!(before.changed_fields(&before).is_empty());
    }
}
