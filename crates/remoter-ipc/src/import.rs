//! The import wizard's three steps that reach the core: detect, parse, commit.
//!
//! **Nothing touches the vault before the commit call.** `remoter-import`
//! parses into an [`ImportPreview`](remoter_import::ImportPreview) and writes
//! nothing; this module holds that preview in memory and hands the interface a
//! secret-free summary of it. Step 7 of the flow is the first thing that opens
//! the vault for writing, and it writes the whole import or none of it.
//!
//! **A recovered password never reaches disk in plaintext and is never copied
//! to a temporary file.** It travels: cipher → `ImportedSecret` (zeroizing) →
//! `Secret<Vec<u8>>` → the vault's sealing call. Every one of those wipes
//! itself on drop, and the preview holding them is dropped when the import is
//! committed, cancelled, or the vault locks.
//!
//! The file's own bytes are read into a zeroizing buffer as well: a CSV export
//! from another manager carries its passwords in the clear, and the buffer they
//! were parsed out of is as sensitive as they are.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use remoter_core::{NodeId, TreePatch};
use remoter_import::{
    ImportPreview, ImportReport, ImportedSecret, Limits, NodeSummary, PreviewNode, Severity,
    SourceFormat, csv, mremoteng, ssh_config,
};
use remoter_vault::{Secret, Vault};
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::commands::{next_sort_order, read_tree, save};
use crate::dto::{
    ImportCommitDto, ImportCountsDto, ImportDetectionDto, ImportDocumentDto, ImportFindingDto,
    ImportNodeDto, ImportPreviewDto, ImportReportDto, ImportResultDto,
};
use crate::error::IpcError;
use crate::state::{AppState, PendingImport, now_millis};

/// The field an imported password is stored under, matching the domain model's
/// `SecretKind::Password`.
const PASSWORD_FIELD: &str = "password";

/// What a file appears to be, before anything is parsed.
///
/// Reads the file and, for an mRemoteNG document, its `<Connections>` header —
/// which is what tells the wizard whether to ask for the document password, and
/// whether the file was protected with the well-known default.
#[tauri::command]
pub(crate) fn import_detect(path: String) -> Result<ImportDetectionDto, IpcError> {
    import_detect_impl(path)
}

fn import_detect_impl(path: String) -> Result<ImportDetectionDto, IpcError> {
    let path = PathBuf::from(path);
    let limits = Limits::new();
    let bytes = read_source(&path, &limits)?;
    let size_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let format = remoter_import::detect(&bytes);

    let document = match format {
        Some(SourceFormat::MRemoteNg) => {
            let info = mremoteng::inspect(&bytes, &limits)
                .map_err(|err| IpcError::from_import(&err, &path.display().to_string()))?;
            let (cipher, kdf_iterations) = match info.cipher {
                mremoteng::CipherMode::Gcm { iterations } => ("gcm", Some(iterations)),
                mremoteng::CipherMode::Cbc => ("cbc", None),
            };
            Some(ImportDocumentDto {
                name: info.name,
                conf_version: info.conf_version,
                cipher: cipher.to_owned(),
                kdf_iterations,
                legacy_cipher: info.cipher.is_legacy(),
                full_file_encryption: info.full_file_encryption,
                password_required: info.password_required,
            })
        }
        _ => None,
    };

    Ok(ImportDetectionDto {
        path: path.display().to_string(),
        size_bytes,
        format: format.map(|format| source_wire(format).to_owned()),
        format_label: format.map(|format| format.label().to_owned()),
        password_required: document
            .as_ref()
            .is_some_and(|document| document.password_required),
        document,
    })
}

/// Parses a file into the tree it would create, and the report that goes with
/// it.
///
/// The preview stays here; what crosses the boundary is a summary of it with
/// every secret removed. One preview is held at a time — the wizard is one
/// flow, and a second parse wipes the first rather than accumulating plaintext.
#[tauri::command]
pub(crate) fn import_parse(
    state: State<'_, AppState>,
    path: String,
    password: Option<String>,
    source: Option<String>,
) -> Result<ImportPreviewDto, IpcError> {
    import_parse_impl(&state, path, password, source)
}

fn import_parse_impl(
    state: &AppState,
    path: String,
    password: Option<String>,
    source: Option<String>,
) -> Result<ImportPreviewDto, IpcError> {
    // The document password moves into a wiping buffer before anything that
    // can fail, as every other secret arriving from the interface does.
    let password = password.map(ImportedSecret::new);
    let path = PathBuf::from(path);
    let subject = path.display().to_string();
    let limits = Limits::new();

    let bytes = read_source(&path, &limits)?;
    let format = match source.as_deref() {
        Some(name) => parse_source(name)?,
        None => remoter_import::detect(&bytes).ok_or_else(unknown_format)?,
    };

    let preview = match format {
        SourceFormat::MRemoteNg => mremoteng::parse(&bytes, password.as_ref(), &limits),
        SourceFormat::Csv => csv::parse(&bytes, &limits),
        SourceFormat::OpenSshConfig => {
            // Includes are followed, confined to the directory the chosen file
            // lives in: an `Include /etc/shadow` in a file a colleague sent is
            // exactly the reason that confinement exists.
            let root = path.parent().unwrap_or(Path::new("."));
            let files = ssh_config::OsConfigFiles::rooted_at(root);
            ssh_config::parse_files(&path, &files, &limits)
        }
        // `SourceFormat` is `#[non_exhaustive]`: a format this build has no
        // parser for is refused by name rather than parsed as the wrong thing.
        _ => return Err(unknown_format()),
    }
    .map_err(|err| IpcError::from_import(&err, &subject))?;

    let dto = preview_dto(format, &preview);
    let (nodes, report) = preview.into_parts();

    let mut guard = state.lock();
    // A preview is only useful against an open vault, and holding one while
    // the vault is shut would keep the file's plaintext passwords in memory
    // with nothing to seal them into.
    guard.vault_ref()?;
    guard.set_pending_import(PendingImport {
        id: dto.import_id.clone(),
        source: format,
        nodes,
        report,
    });
    Ok(dto)
}

/// Drops a preview without importing it, wiping the secrets it holds.
///
/// Cancelling something that is already gone is not a failure: the wizard
/// closing twice must not raise an error at the user.
#[tauri::command]
pub(crate) fn import_cancel(state: State<'_, AppState>, import_id: String) -> Result<(), IpcError> {
    import_cancel_impl(&state, &import_id)
}

fn import_cancel_impl(state: &AppState, import_id: &str) -> Result<(), IpcError> {
    drop(state.lock().take_pending_import(import_id));
    Ok(())
}

/// Writes a previewed import into the vault, in one transaction.
///
/// Every node is validated into an in-memory tree first, so a preview that
/// cannot be created fails before the vault is touched at all. What follows is
/// one row-writing pass, the sealing of each recovered password, and one atomic
/// save — the whole import is one undo step and one file write.
#[tauri::command]
pub(crate) fn import_commit(
    state: State<'_, AppState>,
    req: ImportCommitDto,
) -> Result<ImportResultDto, IpcError> {
    import_commit_impl(&state, req)
}

#[allow(clippy::too_many_lines)] // one linear transaction; splitting it hides the order
fn import_commit_impl(state: &AppState, req: ImportCommitDto) -> Result<ImportResultDto, IpcError> {
    let ImportCommitDto {
        import_id,
        destination_id,
        excluded_ids,
    } = req;

    let destination = match destination_id.as_deref() {
        Some(id) => Some(crate::commands::parse_node_id(id, "destinationId")?),
        None => None,
    };
    let mut excluded: BTreeSet<NodeId> = BTreeSet::new();
    for id in excluded_ids.iter().flatten() {
        excluded.insert(crate::commands::parse_node_id(id, "excludedIds")?);
    }

    let mut guard = state.lock();
    // Checked before the preview is taken: taking it and then failing would
    // wipe the user's parse for a reason they can fix in a second.
    guard.vault_ref()?;
    let pending = guard.take_pending_import(&import_id)?;
    let pending_source = pending.source;
    // Counted from the report the parse produced, so the final step can say
    // how many items still want a human look at them.
    let needs_attention = pending.report.at_least(Severity::Warning).count();
    let vault = guard.vault_mut()?;
    let mut tree = read_tree(vault)?;

    if let Some(id) = destination {
        let Some(folder) = tree.get(id) else {
            return Err(IpcError::from_core(
                &remoter_core::CoreError::ParentNotFound(id),
            ));
        };
        if !folder.kind.is_container() {
            return Err(IpcError::from_core(
                &remoter_core::CoreError::NotAContainer(id),
            ));
        }
    }

    // Excluding a folder excludes what is under it: a connection whose folder
    // the user unticked has nowhere to land, and silently reparenting it to the
    // destination would import something nobody asked for.
    let excluded = closure_of(&pending.nodes, &excluded);
    let base_sort_order = next_sort_order(&tree, destination);
    let now = now_millis();

    let mut included: Vec<PreviewNode> = pending
        .nodes
        .into_iter()
        .filter(|node| !excluded.contains(&node.id))
        .collect();
    let skipped = excluded.len();

    // Parents before children, whatever order the parser produced. A preview
    // whose parents cannot all be reached is a bug in the importer rather than
    // a problem with the file, so it is reported as one.
    let ordered = order_by_parent(&mut included, destination)?;

    let mut patch = TreePatch::default();
    let mut secrets: Vec<(Uuid, Secret<Vec<u8>>)> = Vec::new();
    let mut counts = ImportCountsDto::default();
    let mut root_ids: Vec<String> = Vec::new();

    for mut node in ordered {
        let at_top = node.parent_id.is_none();
        if at_top {
            node.parent_id = destination;
            node.sort_order = base_sort_order.saturating_add(node.sort_order);
        }

        match node.kind {
            remoter_import::PreviewKind::Folder(_) => counts.folders += 1,
            remoter_import::PreviewKind::Connection(_) => counts.connections += 1,
            remoter_import::PreviewKind::Credential(_) => counts.credentials += 1,
        }

        // Copied out before `into_node` consumes the preview and drops the
        // plaintext. Both buffers wipe themselves; neither is written anywhere
        // but into the vault's sealing call below.
        let sealed = if node.needs_sealing() {
            if let Some(secret) = node.secret() {
                secrets.push((
                    *node.id.as_uuid(),
                    Secret::new(secret.expose().as_bytes().to_vec()),
                ));
            }
            // The real ciphertext is bound to the node's id and revision, so it
            // cannot exist until the row does.
            Some(Vault::sealed_placeholder())
        } else {
            None
        };

        let id = node.id;
        let node = node
            .into_node(now, sealed)
            .map_err(|err| IpcError::from_import(&err, "that file"))?;
        let inserted = tree.insert(node).map_err(|err| IpcError::from_core(&err))?;
        patch.inserted.extend(inserted.inserted);
        patch.updated.extend(inserted.updated);
        patch.tombstoned.extend(inserted.tombstoned);

        if at_top {
            root_ids.push(id.to_string());
        }
    }

    // Nothing above this line touched the vault. One row-writing pass, one
    // sealing pass, one atomic save.
    let imported = patch.inserted.len();
    vault
        .apply(&tree, &patch)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;

    let secrets_stored = secrets.len();
    for (node, secret) in secrets {
        vault
            .set_secret(node, PASSWORD_FIELD, secret)
            .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    }
    save(vault)?;

    Ok(ImportResultDto {
        source: source_wire(pending_source).to_owned(),
        imported,
        skipped,
        folders: counts.folders,
        connections: counts.connections,
        credentials: counts.credentials,
        secrets_stored,
        needs_attention,
        root_ids,
    })
}

// =================================================================== helpers

/// Reads a source file, refusing one larger than the importer will parse.
///
/// The size is checked against the metadata before the read, so a file chosen
/// by mistake — a disk image, a video — is refused rather than loaded into
/// memory and then refused.
fn read_source(path: &Path, limits: &Limits) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let metadata =
        fs::metadata(path).map_err(|err| IpcError::io("reading the file", path, &err))?;
    if !metadata.is_file() {
        return Err(IpcError::bad_path(
            path,
            "it is not a file, and an import reads one file",
        ));
    }
    let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if size > limits.max_input_bytes {
        return Err(IpcError::from_import(
            &remoter_import::ImportError::TooLarge {
                size,
                limit: limits.max_input_bytes,
            },
            &path.display().to_string(),
        ));
    }

    // Zeroizing: a CSV export from another manager carries its passwords in the
    // clear, and this buffer is where they arrive.
    let bytes = fs::read(path).map_err(|err| IpcError::io("reading the file", path, &err))?;
    Ok(Zeroizing::new(bytes))
}

/// The wire spelling of a source format.
const fn source_wire(format: SourceFormat) -> &'static str {
    match format {
        SourceFormat::MRemoteNg => "mremoteng",
        SourceFormat::OpenSshConfig => "ssh-config",
        SourceFormat::Csv => "csv",
        // `SourceFormat` is `#[non_exhaustive]`: a format added upstream is
        // named rather than mistaken for one of these three.
        _ => "unknown",
    }
}

fn parse_source(name: &str) -> Result<SourceFormat, IpcError> {
    match name {
        "mremoteng" => Ok(SourceFormat::MRemoteNg),
        "ssh-config" => Ok(SourceFormat::OpenSshConfig),
        "csv" => Ok(SourceFormat::Csv),
        other => Err(IpcError::invalid_request(
            "source",
            format!("`{other}` is not an importer; expected mremoteng, ssh-config or csv"),
        )),
    }
}

fn unknown_format() -> IpcError {
    IpcError::new(
        "import.unknown-format",
        "That file is not in a format Remoter imports: it is not an mRemoteNG document, an \
         OpenSSH config or a CSV export.",
    )
    .with_actions([
        "Choose the source format yourself",
        "Export the connections again as CSV",
    ])
}

/// The excluded set, closed over descendants.
fn closure_of(nodes: &[PreviewNode], seeds: &BTreeSet<NodeId>) -> BTreeSet<NodeId> {
    let parents: BTreeMap<NodeId, Option<NodeId>> =
        nodes.iter().map(|node| (node.id, node.parent_id)).collect();

    let mut excluded = BTreeSet::new();
    for node in nodes {
        // Walk up rather than down: the chain is at most the tree's depth, and
        // a preview cannot hold a cycle — the ids are allocated as it is built.
        let mut current = Some(node.id);
        let mut steps = 0usize;
        while let Some(id) = current {
            if seeds.contains(&id) {
                excluded.insert(node.id);
                break;
            }
            steps += 1;
            if steps > remoter_core::MAX_TREE_DEPTH {
                break;
            }
            current = parents.get(&id).copied().flatten();
        }
    }
    excluded
}

/// Orders the preview so that a node's parent is always inserted before it.
fn order_by_parent(
    nodes: &mut Vec<PreviewNode>,
    destination: Option<NodeId>,
) -> Result<Vec<PreviewNode>, IpcError> {
    let mut placed: BTreeSet<NodeId> = BTreeSet::new();
    let mut ordered = Vec::with_capacity(nodes.len());
    let mut remaining: Vec<PreviewNode> = std::mem::take(nodes);

    while !remaining.is_empty() {
        let mut progressed = false;
        let mut next_round = Vec::with_capacity(remaining.len());
        for node in remaining {
            let ready = match node.parent_id {
                None => true,
                Some(parent) => placed.contains(&parent) || Some(parent) == destination,
            };
            if ready {
                placed.insert(node.id);
                ordered.push(node);
                progressed = true;
            } else {
                next_round.push(node);
            }
        }
        remaining = next_round;

        if !progressed {
            return Err(IpcError::new(
                "import.orphaned-nodes",
                "That file produced items whose folder is not in the import, so the tree \
                 could not be built. Nothing was written.",
            )
            .with_detail(format!("{} items unplaced", remaining.len()))
            .with_actions(["Import the whole file", "Report this"]));
        }
    }
    Ok(ordered)
}

fn preview_dto(format: SourceFormat, preview: &ImportPreview) -> ImportPreviewDto {
    ImportPreviewDto {
        // Not the vault id and not derived from the file: a handle, valid for
        // as long as the preview is held.
        import_id: Uuid::now_v7().to_string(),
        source: source_wire(format).to_owned(),
        source_label: format.label().to_owned(),
        nodes: preview.summaries().iter().map(node_dto).collect(),
        report: report_dto(preview.report()),
    }
}

fn node_dto(summary: &NodeSummary) -> ImportNodeDto {
    ImportNodeDto {
        id: summary.id.to_string(),
        parent_id: summary.parent_id.map(|id| id.to_string()),
        sort_order: summary.sort_order,
        name: summary.name.clone(),
        kind: summary.kind.clone(),
        protocol: summary.protocol.clone(),
        host: summary.host.clone(),
        port: summary.port,
        port_inherited: summary.port_inherited,
        username: summary.username.clone(),
        domain: summary.domain.clone(),
        has_secret: summary.has_secret,
        credential_inherited: summary.credential_inherited,
        gateway_hops: summary.gateway_hops,
        custom_fields: summary.custom_fields,
    }
}

fn report_dto(report: &ImportReport) -> ImportReportDto {
    let counts = report.counts();
    ImportReportDto {
        source: source_wire(report.source()).to_owned(),
        counts: ImportCountsDto {
            folders: counts.folders,
            connections: counts.connections,
            credentials: counts.credentials,
            secrets: counts.secrets,
            skipped: counts.skipped,
        },
        findings: report
            .findings()
            .iter()
            .map(|finding| ImportFindingDto {
                severity: severity_wire(finding.severity()).to_owned(),
                finding: finding.clone(),
            })
            .collect(),
        truncated: report.is_truncated(),
        needs_attention: report.needs_attention(),
    }
}

const fn severity_wire(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Alert => "alert",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_source_name_says_which_ones_exist() {
        let failure = parse_source("royalts");
        assert!(
            failure
                .as_ref()
                .is_err_and(|err| err.code == "request.invalid")
        );
        if let Err(err) = failure {
            assert!(
                err.message.contains("mremoteng"),
                "message: {}",
                err.message
            );
        }
    }

    #[test]
    fn the_source_spellings_round_trip() {
        for format in [
            SourceFormat::MRemoteNg,
            SourceFormat::OpenSshConfig,
            SourceFormat::Csv,
        ] {
            let wire = source_wire(format);
            assert_eq!(parse_source(wire).ok(), Some(format), "wire: {wire}");
        }
    }
}

#[cfg(test)]
mod vault_tests {
    use super::*;
    use crate::commands::{tree_list_impl, vault_lock_impl};
    use crate::test_support::{Scratch, open_vault, why};

    /// A small export with one folder, one connection and one password.
    const CSV: &str = "name,folder,protocol,host,port,username,password\n\
                       web-01,Production,ssh,web-01.example.com,2222,svc-deploy,hunter2\n\
                       web-02,Production,ssh,web-02.example.com,,svc-deploy,hunter2\n";

    /// The password inside [`CSV`]. Asserted absent from everything that
    /// crosses the boundary.
    const CSV_PASSWORD: &str = "hunter2";

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn a_csv_is_detected_previewed_and_committed_in_one_step() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let file = scratch.write("export.csv", CSV);
        let path = file.display().to_string();

        let detected = import_detect_impl(path.clone());
        assert!(detected.is_ok(), "detecting failed: {}", why(&detected));
        let Ok(detected) = detected else {
            panic!("detecting failed");
        };
        assert_eq!(detected.format.as_deref(), Some("csv"));
        assert!(!detected.password_required);
        assert!(detected.document.is_none(), "only mRemoteNG carries one");

        let preview = import_parse_impl(&state, path, None, None);
        assert!(preview.is_ok(), "parsing failed: {}", why(&preview));
        let Ok(preview) = preview else {
            panic!("parsing failed");
        };
        assert_eq!(preview.source, "csv");
        assert!(preview.report.counts.connections >= 2);

        // Nothing has been written yet: the vault is exactly as it was.
        let before = tree_list_impl(&state).unwrap_or_default();
        assert!(before.is_empty(), "the preview must not touch the vault");

        // And nothing that crosses the boundary carries the password.
        let rendered = serde_json::to_string(&preview).unwrap_or_default();
        assert!(
            !rendered.contains(CSV_PASSWORD),
            "the preview leaked a password: {rendered}"
        );

        let committed = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id.clone(),
                destination_id: None,
                excluded_ids: None,
            },
        );
        assert!(committed.is_ok(), "committing failed: {}", why(&committed));
        let Ok(committed) = committed else {
            panic!("committing failed");
        };
        assert_eq!(committed.source, "csv");
        assert!(committed.imported >= 3, "outcome: {committed:?}");
        assert_eq!(committed.skipped, 0);
        assert!(committed.secrets_stored >= 1);
        assert!(!committed.root_ids.is_empty());

        let after = tree_list_impl(&state).unwrap_or_default();
        assert_eq!(after.len(), committed.imported);
        assert!(after.iter().any(|node| node.name == "web-01"));
        assert!(
            after
                .iter()
                .any(|node| node.kind == "credential"
                    && node.secret_kind.as_deref() == Some("password")),
            "the credential the passwords hang off should exist: {after:?}"
        );

        // The tree the interface reads carries no password either.
        let rendered = serde_json::to_string(&after).unwrap_or_default();
        assert!(
            !rendered.contains(CSV_PASSWORD),
            "the tree leaked a password"
        );

        // The preview is spent: committing it twice does not import twice.
        let again = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: None,
            },
        );
        assert!(again.is_err_and(|err| err.code == "import.no-such-preview"));
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn unticking_a_folder_leaves_out_everything_under_it() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let file = scratch.write("export.csv", CSV);

        let Ok(preview) = import_parse_impl(&state, file.display().to_string(), None, None) else {
            panic!("parsing failed");
        };
        let Some(folder) = preview.nodes.iter().find(|node| node.kind == "folder") else {
            panic!("the export should have produced a folder");
        };

        let committed = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: Some(vec![folder.id.clone()]),
            },
        );
        assert!(committed.is_ok(), "committing failed: {}", why(&committed));
        let Ok(committed) = committed else {
            panic!("committing failed");
        };
        assert_eq!(
            committed.connections, 0,
            "a connection whose folder was unticked has nowhere to land"
        );
        // The folder holding the credentials is a different folder, and was
        // not unticked: excluding one branch must not empty the import.
        assert_eq!(committed.folders, 1);
        assert_eq!(committed.credentials, 1);
        assert_eq!(
            committed.skipped, 3,
            "the folder and both connections under it: {committed:?}"
        );

        let after = tree_list_impl(&state).unwrap_or_default();
        assert!(
            after.iter().all(|node| node.name != "web-01"),
            "tree: {after:?}"
        );
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn locking_the_vault_drops_an_uncommitted_preview() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let file = scratch.write("export.csv", CSV);

        let Ok(preview) = import_parse_impl(&state, file.display().to_string(), None, None) else {
            panic!("parsing failed");
        };
        assert!(vault_lock_impl(&state).is_ok());

        // The preview held the file's passwords in plaintext; locking is
        // supposed to leave none in memory.
        let committed = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: None,
            },
        );
        assert!(committed.is_err(), "a preview must not survive the lock");
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn cancelling_forgets_the_preview_and_cancelling_twice_is_not_an_error() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let file = scratch.write("export.csv", CSV);

        let Ok(preview) = import_parse_impl(&state, file.display().to_string(), None, None) else {
            panic!("parsing failed");
        };
        assert!(import_cancel_impl(&state, &preview.import_id).is_ok());
        assert!(import_cancel_impl(&state, &preview.import_id).is_ok());

        let committed = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: None,
            },
        );
        assert!(committed.is_err_and(|err| err.code == "import.no-such-preview"));
    }

    #[test]
    fn a_file_that_is_no_importers_is_refused_by_name() {
        let scratch = Scratch::new();
        let file = scratch.write("notes.txt", "just some notes, nothing structured\n");

        let detected = import_detect_impl(file.display().to_string());
        assert!(detected.is_ok(), "detecting failed: {}", why(&detected));
        assert!(detected.is_ok_and(|detected| detected.format.is_none()));

        let state = AppState::with_config_dir(scratch.join("config"));
        let parsed = import_parse_impl(&state, file.display().to_string(), None, None);
        assert!(parsed.is_err_and(|err| err.code == "import.unknown-format"));
    }

    #[test]
    fn a_missing_file_says_which_file_and_what_to_do() {
        let scratch = Scratch::new();
        let missing = scratch.join("gone.csv");
        let detected = import_detect_impl(missing.display().to_string());
        assert!(detected.as_ref().is_err_and(|err| err.code == "io.failed"));
        if let Err(err) = detected {
            assert!(err.message.contains("gone.csv"), "message: {}", err.message);
            assert!(!err.actions.is_empty());
        }
    }
}
