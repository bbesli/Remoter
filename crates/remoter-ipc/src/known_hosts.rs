//! OpenSSH's `known_hosts`, into the vault's trust store.
//!
//! `docs/features/import-export.md` asks for it by name: a user who has been
//! connecting to their servers with `ssh` for years has already checked those
//! keys, and being asked again for every one of them teaches them to click
//! through the prompt. The file is read by `remoter_import::known_hosts`; this
//! module decides what each key means for the vault.
//!
//! **An import never replaces a trusted key.** A host whose trusted key is not
//! the one in the file keeps the key it has, and the preview says so: the file
//! may be old, and it may be somebody else's. What is written is marked
//! `accepted_by = "import"`, so a key nobody was shown in Remoter can be told
//! apart from one a person accepted.
//!
//! **Nothing here is secret.** Host keys are public, so the preview is read
//! twice — once to show and once to write — rather than held between the two.

use std::path::{Path, PathBuf};

use remoter_core::{Node, NodeKind, Tree};
use remoter_import::{Limits, known_hosts};
use remoter_proto::{Fingerprint, HostPort, KnownKey, TrustSource};
use remoter_proto_ssh::hostkey::KEY_ALGORITHMS;
use remoter_vault::{AuditEvent, AuditOutcome, Vault};
use tauri::State;

use crate::bridge::{pin_key, trusted_fingerprint};
use crate::commands::{read_tree, save};
use crate::dto::{KnownHostKeyDto, KnownHostsPreviewDto, KnownHostsResultDto};
use crate::error::IpcError;
use crate::import::read_source;
use crate::state::{AppState, now_millis};

/// How many keys the preview lists by name. The counts cover the rest.
const MAX_LISTED: usize = 500;

/// Where this account's own `known_hosts` is, when it has one.
#[tauri::command]
pub(crate) fn known_hosts_location() -> Option<String> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    let path = PathBuf::from(home).join(".ssh").join("known_hosts");
    path.is_file().then(|| path.display().to_string())
}

/// What importing the file at `path` would trust, keep and leave out.
#[tauri::command]
pub(crate) fn known_hosts_preview(
    state: State<'_, AppState>,
    path: String,
) -> Result<KnownHostsPreviewDto, IpcError> {
    known_hosts_preview_impl(&state, &path)
}

/// Trusts every key in the file at `path` that nothing is trusted for yet.
#[tauri::command]
pub(crate) fn known_hosts_import(
    state: State<'_, AppState>,
    path: String,
) -> Result<KnownHostsResultDto, IpcError> {
    known_hosts_import_impl(&state, &path)
}

/// A key from the file, and where it stands with the vault.
struct Classified {
    host: HostPort,
    key: known_hosts::HostKey,
    state: KeyState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum KeyState {
    Differs,
    New,
    Trusted,
    Unsupported,
}

impl KeyState {
    const fn wire(self) -> &'static str {
        match self {
            Self::Differs => "differs",
            Self::New => "new",
            Self::Trusted => "trusted",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Reads the file and compares each key with the vault.
///
/// The vault is locked twice and not in between: once for the hosts a hashed
/// or pattern name is compared with, and once to look each key up. The parse
/// in the middle can take most of a second on a large file, and every other
/// command would wait for it.
fn classify(
    state: &AppState,
    path: &Path,
) -> Result<(known_hosts::KnownHostsFile, Vec<Classified>, usize), IpcError> {
    let limits = Limits::new();
    let bytes = read_source(path, &limits)?;

    let hosts = {
        let mut guard = state.lock();
        let vault = guard.vault_ref()?;
        ssh_hosts(&read_tree(vault)?)
    };
    let mut file = known_hosts::parse(&bytes, &hosts, &limits)
        .map_err(|err| IpcError::from_import(&err, &path.display().to_string()))?;

    let mut guard = state.lock();
    let vault = guard.vault_ref()?;
    let mut classified = Vec::with_capacity(file.keys.len());
    let mut unusable = 0usize;
    for key in std::mem::take(&mut file.keys) {
        let Ok(host) = HostPort::new(key.host.clone(), key.port) else {
            unusable += 1;
            continue;
        };
        let state = if !KEY_ALGORITHMS.contains(&key.algorithm.as_str()) {
            KeyState::Unsupported
        } else {
            match trusted_fingerprint(vault, &host, &key.algorithm) {
                None => KeyState::New,
                Some(trusted) if trusted == Fingerprint::sha256(&key.blob).digest() => {
                    KeyState::Trusted
                }
                Some(_) => KeyState::Differs,
            }
        };
        classified.push(Classified { host, key, state });
    }
    Ok((file, classified, unusable))
}

/// Every SSH and SFTP connection's host and resolved port, once each.
fn ssh_hosts(tree: &Tree) -> Vec<(String, u16)> {
    let mut hosts: Vec<(String, u16)> = tree
        .nodes()
        .filter(|node| node.deleted_at.is_none())
        .filter_map(|node| match &node.kind {
            NodeKind::Connection(props) if matches!(props.protocol.as_str(), "ssh" | "sftp") => {
                let port = tree
                    .resolve_optional(node.id, Node::port_field)
                    .ok()
                    .and_then(|resolved| resolved.value)
                    .or_else(|| props.protocol.default_port())
                    .unwrap_or(22);
                Some((props.host.clone(), port))
            }
            _ => None,
        })
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

fn known_hosts_preview_impl(
    state: &AppState,
    path: &str,
) -> Result<KnownHostsPreviewDto, IpcError> {
    let path = PathBuf::from(path);
    let (file, mut classified, unusable) = classify(state, &path)?;
    classified.sort_by_key(|entry| entry.state);
    let count = |wanted: KeyState| {
        classified
            .iter()
            .filter(|entry| entry.state == wanted)
            .count()
    };

    Ok(KnownHostsPreviewDto {
        path: path.display().to_string(),
        entries: file.entries,
        total: classified.len(),
        new: count(KeyState::New),
        already_trusted: count(KeyState::Trusted),
        differs: count(KeyState::Differs),
        unsupported: count(KeyState::Unsupported),
        keys: classified
            .iter()
            .take(MAX_LISTED)
            .map(|entry| KnownHostKeyDto {
                host: entry.host.host().to_owned(),
                port: entry.host.port(),
                algorithm: entry.key.algorithm.clone(),
                fingerprint: Fingerprint::sha256(&entry.key.blob).to_string(),
                state: entry.state.wire().to_owned(),
            })
            .collect(),
        hashed_unmatched: file.hashed_unmatched,
        hashed_unchecked: file.hashed_unchecked,
        patterns_unmatched: file.patterns_unmatched,
        revoked: file.revoked,
        certificate_authorities: file.certificate_authorities,
        conflicting: file.conflicting,
        malformed: file.malformed + unusable,
    })
}

fn known_hosts_import_impl(state: &AppState, path: &str) -> Result<KnownHostsResultDto, IpcError> {
    let path = PathBuf::from(path);
    let (_, classified, _) = classify(state, &path)?;

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let now = now_millis();
    let mut result = KnownHostsResultDto {
        trusted: 0,
        already_trusted: 0,
        differs: 0,
    };
    for entry in classified {
        match entry.state {
            KeyState::Trusted => result.already_trusted += 1,
            KeyState::Differs => result.differs += 1,
            KeyState::Unsupported => {}
            KeyState::New => {
                // Asked again under the write lock: the preview's answer is
                // a second old, and a key accepted at a prompt in between is
                // the one that stays.
                if trusted_fingerprint(vault, &entry.host, &entry.key.algorithm).is_some() {
                    result.differs += 1;
                    continue;
                }
                let key = KnownKey::new(
                    entry.key.algorithm,
                    entry.key.blob,
                    now,
                    TrustSource::ImportedKnownHosts,
                );
                pin_key(vault, &entry.host, &key).map_err(|detail| write_failed(vault, detail))?;
                result.trusted += 1;
            }
        }
    }

    let detail = format!(
        "imported from known_hosts: {} host keys trusted, {} already trusted, {} kept where the \
         vault trusts another key",
        result.trusted, result.already_trusted, result.differs
    );
    vault
        .audit(
            AuditEvent::DataImported,
            AuditOutcome::Success,
            Some(&detail),
        )
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    save(vault)?;
    Ok(result)
}

/// A trust store write that failed part of the way through an import.
fn write_failed(vault: &mut Vault, detail: &'static str) -> IpcError {
    // Recorded, so the log does not show some keys trusted and no reason the
    // rest are not.
    let _ = vault.audit(
        AuditEvent::DataImported,
        AuditOutcome::Failure,
        Some("importing known_hosts stopped: a host key could not be written"),
    );
    IpcError::new(
        "import.trust-write-failed",
        "Remoter could not record a host key in this vault, so the import stopped.",
    )
    .with_detail(detail)
    .with_actions(["Try again"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Scratch, open_vault};

    const ED25519: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH";
    const ED25519_OTHER: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ";
    /// HMAC-SHA1 of `web-01.example.com` keyed with the salt `01 02 … 14`.
    const HASHED_WEB: &str = "|1|AQIDBAUGBwgJCgsMDQ4PEBESExQ=|8y5F4JDs7jm/Vivt/BsUoqMHxEM=";

    #[test]
    #[expect(
        clippy::panic,
        reason = "a trust store test without a vault has nothing left to assert"
    )]
    fn keys_nobody_trusts_yet_are_trusted_and_a_different_trusted_key_stays() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let mut web = crate::dto::CreateNodeDto {
            parent_id: None,
            kind: String::from("connection"),
            name: String::from("web-01"),
            protocol: Some(String::from("ssh")),
            host: Some(String::from("web-01.example.com")),
            port: None,
            username: None,
            password: None,
            credential: None,
            credential_id: None,
            gateway: None,
        };
        crate::commands::node_create_impl(&state, &mut web)
            .unwrap_or_else(|err| panic!("creating the connection failed: {}", err.message));

        // A key accepted at a prompt before the import.
        {
            let mut guard = state.lock();
            let Ok(vault) = guard.vault_mut() else {
                panic!("the vault closed");
            };
            let host = HostPort::new("db.example.com", 22).unwrap_or_else(|_| panic!("host"));
            let blob = data_encoding::BASE64
                .decode(ED25519_OTHER.as_bytes())
                .unwrap_or_default();
            let key = KnownKey::new("ssh-ed25519", blob, 1, TrustSource::Prompted);
            pin_key(vault, &host, &key).unwrap_or_else(|detail| panic!("pinning failed: {detail}"));
        }

        let file = scratch.join("known_hosts");
        std::fs::write(
            &file,
            format!(
                "{HASHED_WEB} ssh-ed25519 {ED25519}\n\
                 db.example.com ssh-ed25519 {ED25519}\n\
                 [git.example.com]:2200 ssh-ed25519 {ED25519}\n\
                 legacy.example.com ssh-foo AAAAB3NzaC1mb28=\n\
                 @cert-authority *.example.com ssh-ed25519 {ED25519}\n"
            ),
        )
        .unwrap_or_else(|err| panic!("writing failed: {err}"));
        let path = file.display().to_string();

        let preview = known_hosts_preview_impl(&state, &path)
            .unwrap_or_else(|err| panic!("the preview failed: {}", err.message));
        assert_eq!(preview.entries, 5);
        assert_eq!(
            (preview.new, preview.already_trusted, preview.differs),
            (2, 0, 1)
        );
        assert_eq!(preview.unsupported, 1);
        assert_eq!(preview.certificate_authorities, 1);
        assert_eq!(
            preview.keys.first().map(|key| key.state.as_str()),
            Some("differs")
        );
        assert!(
            preview
                .keys
                .iter()
                .all(|key| key.fingerprint.starts_with("SHA256:"))
        );

        let result = known_hosts_import_impl(&state, &path)
            .unwrap_or_else(|err| panic!("the import failed: {}", err.message));
        assert_eq!(
            (result.trusted, result.already_trusted, result.differs),
            (2, 0, 1)
        );

        let mut guard = state.lock();
        let Ok(vault) = guard.vault_ref() else {
            panic!("the vault closed");
        };
        let file_key = Fingerprint::sha256(
            &data_encoding::BASE64
                .decode(ED25519.as_bytes())
                .unwrap_or_default(),
        );
        let file_key: &[u8] = file_key.digest();
        let lookup = |host: &str, port: u16| {
            let host = HostPort::new(host, port).unwrap_or_else(|_| panic!("host"));
            trusted_fingerprint(vault, &host, "ssh-ed25519")
        };
        assert_eq!(lookup("web-01.example.com", 22).as_deref(), Some(file_key));
        assert_eq!(lookup("git.example.com", 2200).as_deref(), Some(file_key));
        // The prompt's decision stands.
        assert_ne!(lookup("db.example.com", 22).as_deref(), Some(file_key));
        drop(guard);

        // Twice is harmless.
        let again = known_hosts_import_impl(&state, &path)
            .unwrap_or_else(|err| panic!("the second import failed: {}", err.message));
        assert_eq!(
            (again.trusted, again.already_trusted, again.differs),
            (0, 2, 1)
        );
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "a trust store test without a vault has nothing left to assert"
    )]
    fn an_imported_key_is_what_a_connection_is_checked_against() {
        use remoter_proto::{HostKeyOutcome, OfferedKey, TrustStore, verify_host_key};

        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let file = scratch.join("known_hosts");
        std::fs::write(
            &file,
            format!("bastion.example.com ssh-ed25519 {ED25519}\n"),
        )
        .unwrap_or_else(|err| panic!("writing failed: {err}"));
        known_hosts_import_impl(&state, &file.display().to_string())
            .unwrap_or_else(|err| panic!("the import failed: {}", err.message));

        let store = crate::bridge::VaultTrustStore::new(state.inner_handle());
        let host = HostPort::new("Bastion.Example.com", 22).unwrap_or_else(|_| panic!("host"));
        let blob = data_encoding::BASE64
            .decode(ED25519.as_bytes())
            .unwrap_or_default();
        assert!(matches!(
            verify_host_key(&store, &host, &OfferedKey::new("ssh-ed25519", blob.clone())),
            HostKeyOutcome::Trusted
        ));
        let known = store
            .lookup(&host, "ssh-ed25519")
            .unwrap_or_else(|| panic!("the imported key was not found"));
        assert_eq!(known.source, TrustSource::ImportedKnownHosts);
        let other = data_encoding::BASE64
            .decode(ED25519_OTHER.as_bytes())
            .unwrap_or_default();
        assert!(matches!(
            verify_host_key(&store, &host, &OfferedKey::new("ssh-ed25519", other)),
            HostKeyOutcome::Changed(_)
        ));
    }
}
