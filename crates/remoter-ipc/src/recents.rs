//! The list of vaults this machine has opened.
//!
//! A small JSON file in the platform configuration directory holding paths,
//! labels and last-opened times. **It lives on this machine only** and is never
//! written into a vault: a list of recently opened production vaults is itself
//! an inventory, and it has no business travelling with the encrypted file.
//! Nothing in it is secret, but nothing in it is needed to open a vault either
//! — deleting the file loses the picker's history and nothing else.
//!
//! Every entry is probed when the list is read, so the picker can show a vault
//! that is currently unreachable — an unmounted drive, a network share that is
//! not connected — greyed out with the reason, rather than silently dropping
//! it. A vault vanishing from the list looks exactly like data loss.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use remoter_vault::Vault;
use serde::{Deserialize, Serialize};

use crate::dto::RecentVaultDto;
use crate::error::IpcError;

/// How many vaults the picker remembers. Beyond this the oldest is dropped.
const MAX_RECENTS: usize = 20;

/// Schema version of the file. Bumped when the shape changes; an unknown
/// version is discarded rather than guessed at.
const FILE_VERSION: u32 = 1;

/// One remembered vault, as stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecentEntry {
    /// Absolute path to the `.rvault` file.
    pub(crate) path: String,
    /// The label read from the header the last time it was reachable.
    pub(crate) label: String,
    /// Unix seconds.
    pub(crate) last_opened: Option<i64>,
    /// Slot kinds seen last time, so the picker can offer the right unlock
    /// methods before the file is reachable again.
    #[serde(default)]
    pub(crate) slots: Vec<String>,
    /// Where this vault's key file was last found, so the unlock screen can
    /// offer it instead of making the user find it again.
    ///
    /// The **path** is not the secret; the file's contents are. Recording it
    /// costs nothing an attacker with this machine does not already have — they
    /// would have the key file too — and it removes a mistake that is otherwise
    /// easy to make: the file browser opens in the vault's own folder, the
    /// vault is the obvious file in it, and picking it derives the wrong key.
    /// The failure then reads as "That did not unlock the vault", which is
    /// exactly the message that must not explain itself.
    #[serde(default)]
    pub(crate) keyfile_path: Option<String>,
}

/// The file itself.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Recents {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    entries: Vec<RecentEntry>,
}

impl Recents {
    /// Reads the file, or starts empty.
    ///
    /// A missing, unreadable or unparseable file is not an error the user can
    /// act on — the list is a convenience — so it is logged and replaced with
    /// an empty list. Nothing is written back until the next `record`.
    pub(crate) fn load(path: &Path) -> Self {
        // An earlier build wrote this file world-readable. Repair it on the way
        // past rather than leaving a map of every vault on the machine open to
        // any other local account.
        restrict_existing(path);

        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Self::empty(),
            Err(err) => {
                tracing::warn!("could not read the recent-vault list: {err}");
                return Self::empty();
            }
        };

        match serde_json::from_str::<Self>(&text) {
            Ok(recents) if recents.version == FILE_VERSION => recents,
            Ok(recents) => {
                tracing::warn!(
                    "the recent-vault list is version {}; this build writes {FILE_VERSION}, \
                     so it was discarded",
                    recents.version
                );
                Self::empty()
            }
            Err(err) => {
                tracing::warn!("the recent-vault list could not be parsed: {err}");
                Self::empty()
            }
        }
    }

    fn empty() -> Self {
        Self {
            version: FILE_VERSION,
            entries: Vec::new(),
        }
    }

    /// Writes the file atomically.
    pub(crate) fn save(&self, path: &Path) -> Result<(), IpcError> {
        let json = serde_json::to_vec_pretty(self).map_err(|err| {
            IpcError::new(
                "recents.encode",
                "The recent-vault list could not be encoded, so it was not written.",
            )
            .with_detail(err.to_string())
        })?;
        write_atomic(path, &json)
    }

    /// Moves a vault to the front of the list, or adds it.
    ///
    /// `keyfile` is the key file this unlock used, if any. `None` means the
    /// unlock used no key file — which is not the same as "we do not know", so
    /// a remembered path is only cleared when the vault genuinely opened
    /// without one.
    pub(crate) fn record(
        &mut self,
        path: &Path,
        label: &str,
        slots: Vec<String>,
        keyfile: Option<String>,
        now: i64,
    ) {
        let key = path.to_string_lossy().into_owned();
        self.entries.retain(|entry| entry.path != key);
        self.entries.insert(
            0,
            RecentEntry {
                path: key,
                label: label.to_owned(),
                last_opened: Some(now),
                slots,
                keyfile_path: keyfile,
            },
        );
        self.entries.truncate(MAX_RECENTS);
    }

    /// The key file this vault was last opened with, if one is remembered and
    /// still on disk.
    ///
    /// A path that no longer exists is not offered: a prefilled field naming a
    /// file that is gone — an unmounted USB key, say — is worse than an empty
    /// one, because the user tries it before they think to look.
    pub(crate) fn keyfile_for(&self, path: &str) -> Option<String> {
        let remembered = self
            .entries
            .iter()
            .find(|entry| entry.path == path)?
            .keyfile_path
            .clone()?;
        Path::new(&remembered).is_file().then_some(remembered)
    }

    /// Forgets one vault. Returns whether it was there.
    pub(crate) fn forget(&mut self, path: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|entry| entry.path != path);
        self.entries.len() != before
    }

    /// Forgets all of them.
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    /// The list as the picker wants it, with each entry probed.
    ///
    /// Probing reads the header only — no key is involved and nothing is
    /// decrypted — which is also what refreshes the label and the slot list
    /// for a vault whose password slot was renamed elsewhere.
    pub(crate) fn to_dtos(&self) -> Vec<RecentVaultDto> {
        self.entries.iter().map(probe_entry).collect()
    }
}

/// Fills in what the file system and the vault header say about one entry.
fn probe_entry(entry: &RecentEntry) -> RecentVaultDto {
    let path = PathBuf::from(&entry.path);
    let sync_warning = sync_warning(&path);

    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) => {
            let reason = if err.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "{} is not there. If it is on a removable drive or a network share, \
                     connect it and try again.",
                    path.display()
                )
            } else {
                format!("{} could not be read: {err}.", path.display())
            };
            return RecentVaultDto {
                path: entry.path.clone(),
                label: entry.label.clone(),
                last_opened: entry.last_opened,
                slots: entry.slots.clone(),
                reachable: false,
                unreachable_reason: Some(reason),
                sync_warning,
                size_bytes: None,
            };
        }
    };

    if !metadata.is_file() {
        return RecentVaultDto {
            path: entry.path.clone(),
            label: entry.label.clone(),
            last_opened: entry.last_opened,
            slots: entry.slots.clone(),
            reachable: false,
            unreachable_reason: Some(format!("{} is not a file any more.", path.display())),
            sync_warning,
            size_bytes: None,
        };
    }

    match Vault::probe(&path) {
        Ok(info) => RecentVaultDto {
            path: entry.path.clone(),
            label: info.label,
            last_opened: entry.last_opened,
            slots: info
                .slots
                .iter()
                .map(|slot| slot.kind.as_str().to_owned())
                .collect(),
            reachable: true,
            unreachable_reason: None,
            sync_warning,
            size_bytes: Some(info.size_bytes),
        },
        Err(err) => {
            // The file is there but does not read as a vault: a truncated
            // copy, a sync conflict file, or something else entirely. Kept
            // visible with the reason rather than hidden.
            let failure = IpcError::from_vault(&err, &path.display().to_string());
            RecentVaultDto {
                path: entry.path.clone(),
                label: entry.label.clone(),
                last_opened: entry.last_opened,
                slots: entry.slots.clone(),
                reachable: false,
                unreachable_reason: Some(failure.message),
                sync_warning,
                size_bytes: Some(metadata.len()),
            }
        }
    }
}

/// Cloud-sync folders this build recognises, by the folder name they use.
///
/// Detection is by path segment because that is all that is portable: there is
/// no cross-platform way to ask "is this directory synchronised?". A false
/// negative costs the user a warning they would have wanted; a false positive
/// costs them a warning they can dismiss, which is why the match is on a whole
/// segment or a segment prefix followed by punctuation ("OneDrive - Contoso"),
/// never a bare substring.
const SYNC_MARKERS: &[(&str, &str)] = &[
    ("dropbox", "Dropbox"),
    ("onedrive", "OneDrive"),
    ("google drive", "Google Drive"),
    ("googledrive", "Google Drive"),
    ("gdrive", "Google Drive"),
    ("drivefs", "Google Drive"),
    ("icloud", "iCloud Drive"),
    ("icloud drive", "iCloud Drive"),
    ("com~apple~clouddocs", "iCloud Drive"),
    ("mobile documents", "iCloud Drive"),
    ("nextcloud", "Nextcloud"),
    ("syncthing", "Syncthing"),
    ("mega", "MEGA"),
    ("megasync", "MEGA"),
    ("pcloud", "pCloud"),
    ("pclouddrive", "pCloud"),
];

/// The warning to show when a vault lives in a cloud-sync folder.
///
/// It works. It is worth saying once anyway, because the two consequences are
/// not obvious: two machines editing the same vault will produce a conflict
/// copy, and the provider keeps historical versions of the ciphertext, so a
/// password changed today does not retract the copies stored yesterday.
pub(crate) fn sync_warning(path: &Path) -> Option<String> {
    let provider = sync_provider(path)?;
    Some(format!(
        "This vault is inside a {provider} folder. It works, but editing it from two \
         machines at once will leave a conflict copy, and {provider} keeps earlier \
         versions of the encrypted file."
    ))
}

/// The provider whose folder this path sits in, if any.
fn sync_provider(path: &Path) -> Option<&'static str> {
    for component in path.components() {
        let segment = component.as_os_str().to_string_lossy().to_lowercase();
        for (marker, provider) in SYNC_MARKERS {
            if segment_matches(&segment, marker) {
                return Some(provider);
            }
        }
    }
    None
}

/// Whether a lower-cased path segment names a marker: the whole segment, or
/// the marker followed by punctuation, as in "OneDrive - Contoso".
fn segment_matches(segment: &str, marker: &str) -> bool {
    if segment == marker {
        return true;
    }
    match segment.strip_prefix(marker) {
        Some(rest) => rest
            .chars()
            .next()
            .is_some_and(|c| !c.is_alphanumeric() && c != '_'),
        None => false,
    }
}

/// Creates a file that only its owner can read.
///
/// This file is not a vault, but it is a map to every vault on this machine —
/// their paths, their labels, and where their key files live. Under a default
/// umask `File::create` would leave it at 0644, so on a shared machine any
/// other local account could read it and know exactly which files to take.
/// The mode is set at open time rather than chmod'd afterwards, so there is no
/// window in which the file exists and is world-readable.
fn create_private(path: &Path) -> Result<fs::File, IpcError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|err| IpcError::io("writing the configuration file", path, &err))
    }
    #[cfg(not(unix))]
    {
        fs::File::create(path)
            .map_err(|err| IpcError::io("writing the configuration file", path, &err))
    }
}

/// Best-effort repair of a configuration file left world-readable by an
/// earlier build. A failure here is not worth refusing to start over.
#[cfg(unix)]
fn restrict_existing(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Ok(meta) = fs::metadata(path) {
        if meta.permissions().mode() & 0o077 != 0 {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
}

#[cfg(not(unix))]
fn restrict_existing(_path: &Path) {}

/// Writes to a temporary file beside the target, flushes it, and renames over
/// the target. A crash halfway leaves either the old file or the new one, never
/// a half-written file.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), IpcError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| IpcError::io("creating the configuration directory", parent, &err))?;
    }

    let temporary = path.with_extension("tmp");
    let mut file = create_private(&temporary)?;
    file.write_all(bytes)
        .map_err(|err| IpcError::io("writing the configuration file", &temporary, &err))?;
    file.sync_all()
        .map_err(|err| IpcError::io("flushing the configuration file", &temporary, &err))?;
    drop(file);

    fs::rename(&temporary, path)
        .map_err(|err| IpcError::io("replacing the configuration file", path, &err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_sync_folder_by_segment() {
        assert!(sync_warning(Path::new("/home/a/Dropbox/vaults/x.rvault")).is_some());
        assert!(sync_warning(Path::new("/home/a/dropbox/x.rvault")).is_some());
        assert!(sync_warning(Path::new("/home/a/OneDrive - Contoso/x.rvault")).is_some());
        assert!(sync_warning(Path::new("/home/a/Google Drive/x.rvault")).is_some());
        assert!(sync_warning(Path::new("/home/a/Nextcloud/x.rvault")).is_some());
    }

    #[test]
    fn does_not_warn_on_a_word_that_merely_contains_a_marker() {
        assert!(sync_warning(Path::new("/home/a/omega/x.rvault")).is_none());
        assert!(sync_warning(Path::new("/home/a/megabytes/x.rvault")).is_none());
        assert!(sync_warning(Path::new("/srv/vaults/x.rvault")).is_none());
    }

    #[test]
    fn the_warning_names_the_provider() {
        let warning = sync_warning(Path::new("/home/a/Dropbox/x.rvault")).unwrap_or_default();
        assert!(warning.contains("Dropbox"), "warning was: {warning}");
    }

    #[test]
    fn recording_moves_an_existing_entry_to_the_front() {
        let mut recents = Recents::empty();
        recents.record(Path::new("/a.rvault"), "A", vec![], None, 1);
        recents.record(Path::new("/b.rvault"), "B", vec![], None, 2);
        recents.record(Path::new("/a.rvault"), "A", vec![], None, 3);

        assert_eq!(recents.entries.len(), 2);
        assert_eq!(recents.entries[0].path, "/a.rvault");
        assert_eq!(recents.entries[0].last_opened, Some(3));
    }

    #[test]
    fn the_list_is_capped() {
        let mut recents = Recents::empty();
        for i in 0..(MAX_RECENTS + 5) {
            recents.record(
                Path::new(&format!("/v{i}.rvault")),
                "V",
                vec![],
                None,
                i as i64,
            );
        }
        assert_eq!(recents.entries.len(), MAX_RECENTS);
    }

    #[test]
    fn forgetting_reports_whether_it_removed_anything() {
        let mut recents = Recents::empty();
        recents.record(Path::new("/a.rvault"), "A", vec![], None, 1);
        assert!(recents.forget("/a.rvault"));
        assert!(!recents.forget("/a.rvault"));
    }

    #[test]
    fn a_missing_file_probes_as_unreachable_with_a_reason() {
        let entry = RecentEntry {
            path: "/definitely/not/here/x.rvault".to_owned(),
            label: "Old".to_owned(),
            last_opened: Some(7),
            slots: vec!["password".to_owned()],
            keyfile_path: None,
        };
        let dto = probe_entry(&entry);

        assert!(!dto.reachable);
        assert!(dto.unreachable_reason.is_some());
        // The remembered label and slots survive, so the row stays useful.
        assert_eq!(dto.label, "Old");
        assert_eq!(dto.slots, vec!["password".to_owned()]);
    }
}

#[cfg(test)]
mod keyfile_memory_tests {
    use super::*;

    /// The mistake this prevents: the file browser opens in the vault's own
    /// folder, the `.rvault` is the obvious file in it, and picking it derives
    /// the wrong key. The failure then reads "That did not unlock the vault",
    /// which is deliberately unhelpful, so the user has no way to tell a wrong
    /// password from a wrong file.
    #[test]
    fn a_remembered_key_file_is_offered_back() {
        let dir = std::env::temp_dir().join("remoter-keyfile-memory");
        let _ = std::fs::create_dir_all(&dir);
        let keyfile = dir.join("test.keyfile");
        let _ = std::fs::write(&keyfile, b"not a real key");

        let mut recents = Recents::default();
        recents.record(
            Path::new("/vaults/test.rvault"),
            "test",
            vec!["password".to_owned()],
            Some(keyfile.display().to_string()),
            1,
        );

        assert_eq!(
            recents.keyfile_for("/vaults/test.rvault"),
            Some(keyfile.display().to_string())
        );

        // A path that has gone away is not offered: a field prefilled with a
        // file that is not there is worse than an empty one, because the user
        // tries it before they think to look.
        let _ = std::fs::remove_file(&keyfile);
        assert_eq!(recents.keyfile_for("/vaults/test.rvault"), None);
    }

    #[test]
    fn a_vault_with_no_key_file_remembers_none() {
        let mut recents = Recents::default();
        recents.record(Path::new("/vaults/plain.rvault"), "plain", vec![], None, 1);
        assert_eq!(recents.keyfile_for("/vaults/plain.rvault"), None);
    }
}

#[cfg(all(test, unix))]
mod permission_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0)
    }

    /// The file is not a vault, but it names every vault on this machine and
    /// where their key files live. Under a default umask `File::create` leaves
    /// it at 0644, which hands a local attacker the map.
    #[test]
    fn the_recent_list_is_readable_only_by_its_owner() {
        let dir = std::env::temp_dir().join("remoter-recents-mode");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("recents.json");
        let _ = fs::remove_file(&path);

        let mut recents = Recents::default();
        recents.record(Path::new("/vaults/a.rvault"), "A", vec![], None, 1);
        let _ = recents.save(&path);

        assert_eq!(
            mode_of(&path),
            0o600,
            "recents.json is {:o}",
            mode_of(&path)
        );

        // And a file left world-readable by an earlier build is repaired the
        // next time it is read, rather than staying open until it is rewritten.
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o644));
        let _ = Recents::load(&path);
        assert_eq!(mode_of(&path), 0o600, "not repaired on load");

        let _ = fs::remove_file(&path);
    }
}
