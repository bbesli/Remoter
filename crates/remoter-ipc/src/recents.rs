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

/// Why a remembered vault cannot be opened, as an identifier rather than a
/// sentence.
///
/// The picker used to print the core's English here, on the first screen of
/// the application, before anything has been unlocked — so a Turkish reader
/// met a Turkish window containing one English paragraph about their own
/// vault. Prose belongs to the frontend (CLAUDE.md §6,
/// `docs/features/i18n.md`), so what crosses the boundary is this kind plus
/// the values the sentence needs, and the interface composes it from
/// `vault:picker.unreachable.*`.
///
/// The strings are stable: the catalogue is keyed by them, and
/// `apps/desktop/ui/src/i18n/composed.catalogue.test.ts` reads the literals in
/// `as_str` out of this file and fails if any of them has no entry, in any
/// shipped language. Renaming one without renaming the catalogue key is a red
/// build rather than an English sentence in a Russian window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnreachableKind {
    /// No such file. An unmounted drive, a disconnected share, a deletion.
    Missing,
    /// The file system refused to describe it: permissions, a stale mount, an
    /// I/O error. The operating system's own text travels as the detail.
    NotReadable,
    /// The path is there but is a directory, a socket, something else.
    NotAFile,
}

impl UnreachableKind {
    /// The identifier the interface joins on. See the type's own note.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::NotReadable => "unreadable",
            Self::NotAFile => "not-a-file",
        }
    }
}

/// Everything the picker needs to say why one entry is unreachable: the kind,
/// the diagnostic the sentence may quote, and the English sentence itself as
/// the fallback for a kind the interface does not know — the arrangement
/// `IpcError` uses for its code and message, for the same reason.
struct Unreachable {
    kind: Option<UnreachableKind>,
    /// Set only when the file exists but is not a readable vault: the
    /// `IpcError` code of the probe failure, so the interface can render the
    /// sentence `errors.json` already has for it in every language.
    code: Option<String>,
    detail: Option<String>,
    reason: String,
}

/// Fills in what the file system and the vault header say about one entry.
fn probe_entry(entry: &RecentEntry) -> RecentVaultDto {
    let path = PathBuf::from(&entry.path);
    let provider = sync_provider(&path);

    // One place the DTO is built, so a field added to it cannot be filled in
    // on three paths and forgotten on the fourth.
    let dto = |label: String,
               slots: Vec<String>,
               unreachable: Option<Unreachable>,
               size_bytes: Option<u64>| {
        RecentVaultDto {
            path: entry.path.clone(),
            label,
            last_opened: entry.last_opened,
            slots,
            reachable: unreachable.is_none(),
            unreachable_reason: unreachable.as_ref().map(|u| u.reason.clone()),
            unreachable_kind: unreachable
                .as_ref()
                .and_then(|u| u.kind)
                .map(|kind| kind.as_str().to_owned()),
            unreachable_detail: unreachable.as_ref().and_then(|u| u.detail.clone()),
            unreachable_code: unreachable.as_ref().and_then(|u| u.code.clone()),
            sync_warning: provider.map(sync_warning_text),
            sync_provider: provider.map(str::to_owned),
            size_bytes,
        }
    };

    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) => {
            let unreachable = if err.kind() == std::io::ErrorKind::NotFound {
                Unreachable {
                    kind: Some(UnreachableKind::Missing),
                    code: None,
                    detail: None,
                    reason: format!(
                        "{} is not there. If it is on a removable drive or a network share, \
                         connect it and try again.",
                        path.display()
                    ),
                }
            } else {
                Unreachable {
                    kind: Some(UnreachableKind::NotReadable),
                    code: None,
                    // The operating system's own words, kept English: this is
                    // the line a reader copies into a bug report, and a
                    // translated one is no use to whoever reads that report.
                    detail: Some(err.to_string()),
                    reason: format!("{} could not be read: {err}.", path.display()),
                }
            };
            return dto(
                entry.label.clone(),
                entry.slots.clone(),
                Some(unreachable),
                None,
            );
        }
    };

    if !metadata.is_file() {
        return dto(
            entry.label.clone(),
            entry.slots.clone(),
            Some(Unreachable {
                kind: Some(UnreachableKind::NotAFile),
                code: None,
                detail: None,
                reason: format!("{} is not a file any more.", path.display()),
            }),
            None,
        );
    }

    match Vault::probe(&path) {
        Ok(info) => dto(
            info.label,
            info.slots
                .iter()
                .map(|slot| slot.kind.as_str().to_owned())
                .collect(),
            None,
            Some(info.size_bytes),
        ),
        Err(err) => {
            // The file is there but does not read as a vault: a truncated
            // copy, a sync conflict file, or something else entirely. Kept
            // visible with the reason rather than hidden.
            //
            // No `UnreachableKind` for this one: the vault error already has a
            // stable code and a sentence translated under it in `errors.json`,
            // so sending the code reaches a better sentence than any kind
            // invented here could.
            let failure = IpcError::from_vault(&err, &path.display().to_string());
            dto(
                entry.label.clone(),
                entry.slots.clone(),
                Some(Unreachable {
                    kind: None,
                    code: Some(failure.code),
                    detail: failure.detail,
                    reason: failure.message,
                }),
                Some(metadata.len()),
            )
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
///
/// **Not the text the user reads.** The interface writes that sentence itself,
/// from `vault:detail.syncWarning`, around the provider name; this English is
/// the fallback for an interface that has no entry for it. See
/// [`sync_provider`], which is the value that actually crosses the boundary.
pub(crate) fn sync_warning(path: &Path) -> Option<String> {
    sync_provider(path).map(sync_warning_text)
}

/// The English sentence for one provider. See [`sync_warning`] for why it is a
/// fallback rather than the copy.
fn sync_warning_text(provider: &str) -> String {
    format!(
        "This vault is inside a {provider} folder. It works, but editing it from two \
         machines at once will leave a conflict copy, and {provider} keeps earlier \
         versions of the encrypted file."
    )
}

/// The provider whose folder this path sits in, if any.
///
/// A brand name — "Dropbox", "iCloud Drive" — which is never translated
/// (`docs/features/i18n.md`, "What is never translated"). It is the one value
/// the warning is composed around, which is why it crosses the boundary on its
/// own rather than baked into a sentence.
pub(crate) fn sync_provider(path: &Path) -> Option<&'static str> {
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
    fn the_provider_crosses_the_boundary_as_a_value() {
        // The picker writes the sentence; it needs the brand name, not the
        // paragraph. Without this field the only thing on the DTO is English
        // prose, and the catalogue can never reach it.
        let dto = probe_entry(&RecentEntry {
            path: "/home/a/Dropbox/x.rvault".to_owned(),
            label: "Work".to_owned(),
            last_opened: None,
            slots: vec![],
            keyfile_path: None,
        });
        assert_eq!(dto.sync_provider.as_deref(), Some("Dropbox"));
        assert_eq!(
            dto.sync_warning,
            Some(sync_warning_text("Dropbox")),
            "the English stays as the fallback"
        );
    }

    #[test]
    fn no_provider_means_no_warning_and_no_value() {
        let dto = probe_entry(&RecentEntry {
            path: "/srv/vaults/x.rvault".to_owned(),
            label: "Work".to_owned(),
            last_opened: None,
            slots: vec![],
            keyfile_path: None,
        });
        assert_eq!(dto.sync_provider, None);
        assert_eq!(dto.sync_warning, None);
    }

    #[test]
    fn a_missing_vault_is_reported_by_kind_as_well_as_in_english() {
        let dto = probe_entry(&RecentEntry {
            // A path under a temporary directory that was never created.
            path: format!(
                "{}/remoter-does-not-exist/x.rvault",
                std::env::temp_dir().display()
            ),
            label: "Gone".to_owned(),
            last_opened: None,
            slots: vec![],
            keyfile_path: None,
        });
        assert!(!dto.reachable);
        assert_eq!(dto.unreachable_kind.as_deref(), Some("missing"));
        assert_eq!(dto.unreachable_code, None);
        // The English is still there, for an interface that has no entry for
        // this kind — the same fallback `IpcError::message` is.
        assert!(
            dto.unreachable_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("is not there")),
            "reason was: {:?}",
            dto.unreachable_reason
        );
    }

    #[test]
    fn a_directory_is_reported_as_not_a_file() {
        let dto = probe_entry(&RecentEntry {
            path: std::env::temp_dir().display().to_string(),
            label: "Not a vault".to_owned(),
            last_opened: None,
            slots: vec![],
            keyfile_path: None,
        });
        assert!(!dto.reachable);
        assert_eq!(dto.unreachable_kind.as_deref(), Some("not-a-file"));
    }

    #[test]
    fn a_file_that_is_not_a_vault_travels_as_a_failure_code() {
        let path = std::env::temp_dir().join("remoter-not-a-vault.bin");
        // A deliberate non-vault: the probe must refuse it, and the refusal
        // already has a translated sentence keyed by its code.
        let Ok(()) = fs::write(&path, b"not a vault") else {
            return;
        };
        let dto = probe_entry(&RecentEntry {
            path: path.display().to_string(),
            label: "Junk".to_owned(),
            last_opened: None,
            slots: vec![],
            keyfile_path: None,
        });
        let _ = fs::remove_file(&path);

        assert!(!dto.reachable);
        assert_eq!(
            dto.unreachable_kind, None,
            "this case is a coded failure, not a kind"
        );
        assert!(
            dto.unreachable_code
                .as_deref()
                .is_some_and(|code| code.starts_with("vault.")),
            "code was: {:?}",
            dto.unreachable_code
        );
    }

    #[test]
    fn every_kind_has_a_stable_identifier() {
        // The catalogue is keyed by these, and
        // `composed.catalogue.test.ts` reads them out of this file. The match
        // is exhaustive, so a variant added without an identifier does not
        // compile, and this pins the identifiers themselves.
        for (kind, expected) in [
            (UnreachableKind::Missing, "missing"),
            (UnreachableKind::NotReadable, "unreadable"),
            (UnreachableKind::NotAFile, "not-a-file"),
        ] {
            assert_eq!(kind.as_str(), expected);
        }
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
