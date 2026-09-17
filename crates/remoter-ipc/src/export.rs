//! Writing the connection tree to a file — the Export dialog.
//!
//! The formats are `remoter-import`'s to write; this module picks the part of
//! the tree, hands it over, puts the bytes on disk and records that it did. It
//! never touches a secret, and could not if it tried: the writers are given the
//! tree, which holds only sealed secrets, and none of them reads those.
//!
//! The file is written the way every other file this crate writes is — to a
//! temporary beside the target, flushed, renamed over it, readable by the
//! owner only — because a list of every server a person administers is worth
//! keeping away from the other accounts on the machine even without a password
//! in it.

use std::path::PathBuf;

use remoter_core::NodeKind;
use remoter_import::export::{self, ExportError, ExportFormat};
use remoter_vault::archive::{ArchiveContents, ArchiveSecret, seal_archive};
use remoter_vault::{AuditEvent, AuditOutcome, ExposeSecret, Purpose, Secret, Vault};
use tauri::State;

use crate::commands::{estimate_strength, parse_node_id, read_tree, save};
use crate::dto::{ArchiveExportDto, TreeExportDto, TreeExportResultDto};
use crate::error::IpcError;
use crate::recents::write_atomic;
use crate::state::{AppState, now_millis};

/// The wire name of the `.rmtr` archive. Not an [`ExportFormat`]: the flat
/// formats are `remoter-import`'s and never touch a secret, and the archive is
/// the one export that does.
const ARCHIVE: &str = "remoter-archive";

/// Writes the tree, or the part of it under one node, to a file.
#[tauri::command]
pub(crate) fn tree_export(
    state: State<'_, AppState>,
    req: TreeExportDto,
) -> Result<TreeExportResultDto, IpcError> {
    tree_export_impl(&state, req)
}

fn tree_export_impl(state: &AppState, req: TreeExportDto) -> Result<TreeExportResultDto, IpcError> {
    let TreeExportDto {
        path,
        format,
        root_id,
        password,
    } = req;
    // Into a wiping buffer before anything that can fail, as every other
    // secret arriving from the interface is.
    let password = password.map(Secret::new);

    if format == ARCHIVE {
        return archive_export(state, path, root_id, password);
    }
    // A flat format has no use for a password, and holding one it will not use
    // is holding it for nothing.
    drop(password);

    let Some(format) = ExportFormat::parse(&format) else {
        return Err(IpcError::invalid_request(
            "format",
            format!(
                "`{format}` is not an export format; expected remoter-archive, csv, ssh-config \
                 or json"
            ),
        ));
    };
    let root = root_id
        .as_deref()
        .map(|id| parse_node_id(id, "rootId"))
        .transpose()?;
    let path = PathBuf::from(path);
    if path.is_dir() {
        return Err(IpcError::bad_path(
            &path,
            "it is a folder, and an export is written as one file",
        ));
    }

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let tree = read_tree(vault)?;
    let exported = export::export(&tree, root, format, now_millis()).map_err(|err| match err {
        ExportError::Tree(err) => IpcError::from_core(&err),
        other => IpcError::new(
            "export.encode",
            "The connections could not be encoded, so nothing was written.",
        )
        .with_detail(other.to_string()),
    })?;
    let bytes = u64::try_from(exported.bytes.len()).unwrap_or(u64::MAX);
    write_atomic(&path, &exported.bytes)?;

    // The log says what left, in what shape and where to — counts and a path,
    // never a name from inside the tree, so the row reads the same to whoever
    // reviews it whatever the vault holds. Attributed to the exported folder,
    // so its history shows it.
    let report = &exported.report;
    let detail = format!(
        "connections exported: {} of {} connections, {}, to {}; no passwords or keys",
        report.connections.saturating_sub(report.skipped),
        report.connections,
        format.as_str(),
        path.display()
    );
    let recorded = match root {
        Some(root) => vault.audit_for_node(
            AuditEvent::DataExported,
            AuditOutcome::Success,
            *root.as_uuid(),
            Some(&detail),
        ),
        None => vault.audit(
            AuditEvent::DataExported,
            AuditOutcome::Success,
            Some(&detail),
        ),
    };
    recorded.map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    save(vault)?;

    Ok(TreeExportResultDto {
        path: path.display().to_string(),
        bytes,
        format: format.as_str().to_owned(),
        report: Some(exported.report),
        archive: None,
    })
}

/// [`tree_export_impl`], for the other modules' tests.
#[cfg(test)]
pub(crate) fn tree_export_for_tests(
    state: &AppState,
    req: TreeExportDto,
) -> Result<TreeExportResultDto, IpcError> {
    tree_export_impl(state, req)
}

/// Writes a `.rmtr` archive: the chosen nodes, what they depend on, and their
/// secrets, sealed under a password of the user's.
///
/// The vault lock is held to choose the nodes and read their secrets, and let
/// go for the second or two of key derivation, so that the rest of the
/// application is not waiting on Argon2id. What is read in that window is in
/// `Secret` buffers and is wiped when this returns, however it returns.
fn archive_export(
    state: &AppState,
    path: String,
    root_id: Option<String>,
    password: Option<Secret<String>>,
) -> Result<TreeExportResultDto, IpcError> {
    let Some(password) = password.filter(|password| !password.expose_secret().is_empty()) else {
        return Err(IpcError::new(
            "export.password-required",
            "An archive is sealed with a password of its own, and none was given.",
        )
        .with_actions(["Type a password", "Generate a passphrase"]));
    };
    // The same gate a vault's master password passes, for the same reason:
    // the archive is a file that leaves the machine carrying server passwords,
    // and an offline attacker with a copy guesses at leisure.
    let strength = estimate_strength(password.expose_secret());
    if !strength.acceptable {
        return Err(IpcError::new(
            "export.password-too-weak",
            format!(
                "That password is too easy to guess for a file that carries server passwords. \
                 {}",
                strength.explanation
            ),
        )
        .with_actions([
            "Generate a passphrase",
            "Use a longer, less predictable password",
        ]));
    }
    let root = root_id
        .as_deref()
        .map(|id| parse_node_id(id, "rootId"))
        .transpose()?;
    let path = PathBuf::from(path);
    if path.is_dir() {
        return Err(IpcError::bad_path(
            &path,
            "it is a folder, and an export is written as one file",
        ));
    }

    let (contents, dependencies) = {
        let mut guard = state.lock();
        let vault = guard.vault_mut()?;
        let tree = read_tree(vault)?;
        let selection = export::archive_selection(&tree, root).map_err(|err| match err {
            ExportError::Tree(err) => IpcError::from_core(&err),
            other => IpcError::new(
                "export.encode",
                "The connections could not be encoded, so nothing was written.",
            )
            .with_detail(other.to_string()),
        })?;
        let mut secrets = Vec::new();
        for node in &selection.nodes {
            let id = *node.id.as_uuid();
            let fields = vault
                .secret_fields(id)
                .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
            for field in fields {
                // Borrowed for export, which the vault records against the node:
                // each secret that leaves is on the log, not only the file.
                let value = vault
                    .borrow_secret(id, &field, Purpose::Export)
                    .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
                secrets.push(ArchiveSecret {
                    node: id,
                    field,
                    value,
                });
            }
        }
        (
            ArchiveContents {
                nodes: selection.nodes,
                secrets,
            },
            selection.dependencies,
        )
    };

    let params =
        Vault::calibrate_kdf().map_err(|err| IpcError::from_vault(&err, "this archive"))?;
    let image = seal_archive(&contents, &password, params)
        .map_err(|err| IpcError::from_vault(&err, "this archive"))?;
    drop(password);

    let mut summary = ArchiveExportDto {
        folders: 0,
        connections: 0,
        credentials: 0,
        secrets: contents.secrets.len(),
        dependencies,
    };
    for node in &contents.nodes {
        match node.kind {
            NodeKind::Folder(_) => summary.folders += 1,
            NodeKind::Connection(_) => summary.connections += 1,
            NodeKind::Credential(_) => summary.credentials += 1,
            _ => {}
        }
    }
    drop(contents);

    let bytes = u64::try_from(image.len()).unwrap_or(u64::MAX);
    write_atomic(&path, &image)?;

    let detail = format!(
        "connections exported: {} connections, {} secrets, remoter-archive, encrypted, to {}",
        summary.connections,
        summary.secrets,
        path.display()
    );
    {
        let mut guard = state.lock();
        // The file is written. A vault locked while the key was being derived
        // has nowhere to put the row, and the export has still happened; the
        // secret rows written above reached the log before it locked.
        match guard.vault_mut() {
            Ok(vault) => {
                let recorded = match root {
                    Some(root) => vault.audit_for_node(
                        AuditEvent::DataExported,
                        AuditOutcome::Success,
                        *root.as_uuid(),
                        Some(&detail),
                    ),
                    None => vault.audit(
                        AuditEvent::DataExported,
                        AuditOutcome::Success,
                        Some(&detail),
                    ),
                };
                recorded.map_err(|err| IpcError::from_vault(&err, "this vault"))?;
                save(vault)?;
            }
            Err(_) => {
                tracing::warn!("the vault locked during an export; its audit row was not written")
            }
        }
    }

    Ok(TreeExportResultDto {
        path: path.display().to_string(),
        bytes,
        format: ARCHIVE.to_owned(),
        report: None,
        archive: Some(summary),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::audit_query_impl;
    use crate::commands::node_create_impl;
    use crate::dto::{AuditQueryDto, CreateNodeDto, NodeDto};
    use crate::test_support::{Scratch, open_vault, why};

    #[expect(clippy::panic, reason = "a fixture that cannot be built ends the test")]
    fn create(
        state: &AppState,
        kind: &str,
        name: &str,
        protocol: Option<&str>,
        parent: Option<&str>,
        password: Option<&str>,
    ) -> NodeDto {
        let mut input = CreateNodeDto {
            parent_id: parent.map(ToOwned::to_owned),
            kind: kind.to_owned(),
            name: name.to_owned(),
            protocol: protocol.map(ToOwned::to_owned),
            host: protocol.map(|_| format!("{name}.example.internal")),
            port: None,
            username: password.map(|_| String::from("deploy")),
            password: password.map(ToOwned::to_owned),
            credential: None,
            credential_id: None,
            gateway: None,
        };
        match node_create_impl(state, &mut input) {
            Ok(node) => node,
            Err(err) => panic!("creating {name} failed: {}", err.message),
        }
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an export test without a vault has nothing left to assert"
    )]
    fn a_folder_is_written_without_its_passwords_and_the_export_is_on_record() {
        const PASSWORD: &str = "correct-horse-battery";

        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let production = create(&state, "folder", "Production", None, None, None);
        create(
            &state,
            "connection",
            "web-01",
            Some("ssh"),
            Some(&production.id),
            Some(PASSWORD),
        );
        create(
            &state,
            "connection",
            "dc-01",
            Some("rdp"),
            Some(&production.id),
            None,
        );
        create(&state, "connection", "elsewhere", Some("ssh"), None, None);

        let target = scratch.join("production.config");
        let exported = tree_export_impl(
            &state,
            TreeExportDto {
                path: target.display().to_string(),
                format: String::from("ssh-config"),
                root_id: Some(production.id.clone()),
                password: None,
            },
        );
        assert!(exported.is_ok(), "exporting failed: {}", why(&exported));
        let Ok(exported) = exported else {
            panic!("exporting failed");
        };
        let Some(report) = exported.report.as_ref() else {
            panic!("a flat export has a report");
        };
        assert_eq!(report.connections, 2);
        assert_eq!(report.skipped, 1, "RDP has no place in an ssh_config");

        let written = std::fs::read_to_string(&target).unwrap_or_default();
        assert_eq!(u64::try_from(written.len()).ok(), Some(exported.bytes));
        assert!(written.contains("Host web-01\n"), "{written}");
        assert!(written.contains("    User deploy\n"), "{written}");
        assert!(
            !written.contains("elsewhere"),
            "outside the folder: {written}"
        );
        assert!(!written.contains(PASSWORD), "a password was exported");

        let log = audit_query_impl(&state, AuditQueryDto::default());
        let Ok(log) = log else {
            panic!("reading the audit log failed");
        };
        let row = log
            .entries
            .iter()
            .find(|entry| entry.event == "data_exported");
        let Some(row) = row else {
            panic!("the export was not recorded: {:?}", log.entries);
        };
        assert_eq!(row.node_id.as_deref(), Some(production.id.as_str()));
        assert!(
            row.warning,
            "data leaving the vault is what a review looks for"
        );
        let detail = row.detail.as_deref().unwrap_or_default();
        assert!(
            detail.starts_with("connections exported: 1 of 2 connections, ssh-config, to "),
            "{detail}"
        );

        let rendered = serde_json::to_string(&exported).unwrap_or_default();
        assert!(!rendered.contains(PASSWORD));
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an export test without a vault has nothing left to assert"
    )]
    fn every_format_writes_the_whole_vault() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        create(&state, "connection", "web-01", Some("ssh"), None, None);
        for (format, marker) in [
            ("csv", "web-01,,ssh,web-01.example.internal"),
            ("ssh-config", "Host web-01"),
            ("json", "\"format\": \"remoter-tree\""),
        ] {
            let target = scratch.join(&format!("vault.{format}"));
            let exported = tree_export_impl(
                &state,
                TreeExportDto {
                    path: target.display().to_string(),
                    format: format.to_owned(),
                    root_id: None,
                    password: None,
                },
            );
            assert!(exported.is_ok(), "{format}: {}", why(&exported));
            let written = std::fs::read_to_string(&target).unwrap_or_default();
            assert!(written.contains(marker), "{format}: {written}");
        }
    }

    #[test]
    fn a_request_that_cannot_be_met_is_refused_before_anything_is_written() {
        let scratch = Scratch::new();
        let target = scratch.join("nothing.csv");

        let locked = AppState::with_config_dir(scratch.join("config"));
        let refused = tree_export_impl(
            &locked,
            TreeExportDto {
                path: target.display().to_string(),
                format: String::from("csv"),
                root_id: None,
                password: None,
            },
        );
        assert!(refused.is_err_and(|err| err.code == "vault.locked"));

        let Some(state) = open_vault(&scratch) else {
            return;
        };
        let refused = tree_export_impl(
            &state,
            TreeExportDto {
                path: target.display().to_string(),
                format: String::from("xlsx"),
                root_id: None,
                password: None,
            },
        );
        assert!(refused.is_err_and(|err| err.code == "request.invalid"));

        let refused = tree_export_impl(
            &state,
            TreeExportDto {
                path: target.display().to_string(),
                format: String::from("csv"),
                root_id: Some(uuid::Uuid::now_v7().to_string()),
                password: None,
            },
        );
        assert!(refused.is_err_and(|err| err.code.starts_with("node.")));
        assert!(!target.exists());
    }
}
