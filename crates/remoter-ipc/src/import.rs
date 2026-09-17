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

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use remoter_core::{Node, NodeId, NodeKind, SecretKind, Tree, TreePatch};
use remoter_import::conflicts::{self, Candidate, ConflictPolicy};
use remoter_import::{
    ImportPreview, ImportReport, ImportedSecret, Limits, NodeSummary, PreviewNode, Severity,
    SourceFormat, csv, mremoteng, native, putty, rdcman, rdp_file, ssh_config,
};
use remoter_vault::archive::{self, ArchiveError};
use remoter_vault::{AuditEvent, AuditOutcome, Secret, Vault};
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::commands::{next_sort_order, read_tree, save};
use crate::dto::{
    ImportCommitDto, ImportConflictDto, ImportConflictsDto, ImportConflictsRequestDto,
    ImportCountsDto, ImportDetectionDto, ImportDocumentDto, ImportFindingDto, ImportNodeDto,
    ImportPreviewDto, ImportReportDto, ImportResultDto,
};
use crate::error::IpcError;
use crate::state::{AppState, PendingImport, PendingNative, now_millis};

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
    // PuTTY's sessions are a registry key or a directory, not a file, and are
    // answered for before anything tries to read one.
    if let Some(store) = SessionStore::at(&path) {
        let sessions = store.read(&limits)?;
        let size_bytes = sessions
            .iter()
            .flat_map(|session| session.values.iter())
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>();
        return Ok(ImportDetectionDto {
            path: path.display().to_string(),
            size_bytes: u64::try_from(size_bytes).unwrap_or(u64::MAX),
            format: Some(source_wire(SourceFormat::Putty).to_owned()),
            format_label: Some(SourceFormat::Putty.label().to_owned()),
            password_required: false,
            document: None,
        });
    }
    let bytes = read_source(&path, &limits)?;
    let size_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);

    // Remoter's own archive is recognised by its magic, before the text
    // formats are sniffed: it is binary, and a sniffer reading it as text
    // would be guessing.
    if archive::is_archive(&bytes) {
        return Ok(ImportDetectionDto {
            path: path.display().to_string(),
            size_bytes,
            format: Some(ARCHIVE_WIRE.to_owned()),
            format_label: Some(SourceFormat::RemoterArchive.label().to_owned()),
            password_required: true,
            document: None,
        });
    }
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

    if let Some(store) = SessionStore::at(&path) {
        drop(password);
        let sessions = store.read(&limits)?;
        let preview = putty::parse_sessions(sessions, &limits)
            .map_err(|err| IpcError::from_import(&err, &subject))?;
        return hold_preview(state, SourceFormat::Putty, preview);
    }

    let bytes = read_source(&path, &limits)?;
    let format = match source.as_deref() {
        Some(name) => parse_source(name)?,
        None if archive::is_archive(&bytes) => SourceFormat::RemoterArchive,
        None => remoter_import::detect(&bytes).ok_or_else(unknown_format)?,
    };
    if format == SourceFormat::RemoterArchive {
        return archive_parse(state, &bytes, password, &subject);
    }
    if format == SourceFormat::RemoterJson {
        drop(password);
        return json_parse(state, &bytes, &limits, &subject);
    }

    let preview = match format {
        SourceFormat::MRemoteNg => mremoteng::parse(&bytes, password.as_ref(), &limits),
        SourceFormat::Csv => csv::parse(&bytes, &limits),
        SourceFormat::RdcMan => rdcman::parse(&bytes, &limits),
        // Named after the file, the way Remote Desktop Connection lists one.
        SourceFormat::RdpFile => rdp_file::parse(
            &bytes,
            &path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default(),
            &limits,
        ),
        // A registry export, or one session file named as its session is.
        SourceFormat::Putty => putty::parse_file(
            &bytes,
            &path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            &limits,
        ),
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

    hold_preview(state, format, preview)
}

/// Holds a parsed preview until it is committed or cancelled, and hands the
/// interface its secret-free summary.
fn hold_preview(
    state: &AppState,
    format: SourceFormat,
    preview: ImportPreview,
) -> Result<ImportPreviewDto, IpcError> {
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
        native: None,
    });
    Ok(dto)
}

/// Where this computer keeps PuTTY's saved sessions, as a path the other
/// import commands accept — or nothing, when it keeps none.
///
/// On Windows that is the registry key, and nothing is read from it here but
/// whether it has sessions under it. Elsewhere it is `~/.putty/sessions`.
#[tauri::command]
pub(crate) fn import_putty_location() -> Option<String> {
    #[cfg(windows)]
    {
        putty::REGISTRY_KEYS
            .iter()
            .find(|key| putty::registry_has_sessions(key))
            .map(|key| format!("HKEY_CURRENT_USER\\{key}"))
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME")?;
        putty_directory_under(Path::new(&home))
    }
}

/// `~/.putty/sessions` under `home`, when it holds at least one session.
#[cfg(not(windows))]
fn putty_directory_under(home: &Path) -> Option<String> {
    let directory = home.join(".putty").join("sessions");
    let has_one = fs::read_dir(&directory)
        .ok()?
        .flatten()
        .any(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()));
    has_one.then(|| directory.display().to_string())
}

/// Saved sessions that are not one file.
enum SessionStore {
    /// One of [`putty::REGISTRY_KEYS`].
    #[cfg(windows)]
    Registry(&'static str),
    /// A directory of session files, as `~/.putty/sessions` is.
    Directory(PathBuf),
}

impl SessionStore {
    /// What `path` names, when it names sessions rather than a file.
    ///
    /// A registry path is recognised only on Windows and only for the two
    /// session keys; any other directory is read as a sessions directory,
    /// because a directory is nothing else an importer here reads.
    fn at(path: &Path) -> Option<Self> {
        #[cfg(windows)]
        if let Some(key) = path.to_str().and_then(putty::registry_key) {
            return Some(Self::Registry(key));
        }
        path.is_dir().then(|| Self::Directory(path.to_path_buf()))
    }

    fn read(&self, limits: &Limits) -> Result<Vec<putty::Session>, IpcError> {
        match self {
            #[cfg(windows)]
            Self::Registry(key) => putty::read_registry(key, limits)
                .map_err(|err| IpcError::from_import(&err, &format!("HKEY_CURRENT_USER\\{key}"))),
            Self::Directory(directory) => putty::read_directory(directory, limits)
                .map_err(|err| IpcError::from_import(&err, &directory.display().to_string())),
        }
    }
}

/// The wire spelling of Remoter's own archive.
const ARCHIVE_WIRE: &str = "remoter-archive";

/// The wire spelling of Remoter's own JSON export.
const JSON_WIRE: &str = "remoter-json";

/// Opens a `.rmtr` archive with its password and holds what it carries.
///
/// The key derivation runs before the state lock is taken: a second of
/// Argon2id is not a reason for every other command to wait.
fn archive_parse(
    state: &AppState,
    bytes: &[u8],
    password: Option<ImportedSecret>,
    subject: &str,
) -> Result<ImportPreviewDto, IpcError> {
    let Some(password) = password.filter(|password| !password.is_empty()) else {
        return Err(IpcError::new(
            "import.archive-password-required",
            format!(
                "{subject} is a Remoter archive, sealed with a password. Enter the password it \
                 was exported with."
            ),
        )
        .with_actions(["Enter the archive password"]));
    };
    let mut plaintext = password.into_zeroizing();
    let password = Secret::new(std::mem::take(&mut *plaintext));
    drop(plaintext);

    let contents = archive::open_archive(bytes, &password)
        .map_err(|err| archive_error(&err, subject, bytes.len()))?;
    drop(password);

    let with_secrets: HashSet<NodeId> = contents
        .secrets
        .iter()
        .map(|secret| NodeId::from_uuid(secret.node))
        .collect();
    let report = native::report(
        SourceFormat::RemoterArchive,
        &contents.nodes,
        contents.secrets.len(),
    );
    let dto = ImportPreviewDto {
        import_id: Uuid::now_v7().to_string(),
        source: ARCHIVE_WIRE.to_owned(),
        source_label: SourceFormat::RemoterArchive.label().to_owned(),
        nodes: native::summaries(&contents.nodes, &with_secrets)
            .iter()
            .map(node_dto)
            .collect(),
        report: report_dto(&report),
    };

    let mut guard = state.lock();
    guard.vault_ref()?;
    guard.set_pending_import(PendingImport {
        id: dto.import_id.clone(),
        source: SourceFormat::RemoterArchive,
        nodes: Vec::new(),
        report,
        native: Some(PendingNative {
            nodes: contents.nodes,
            secrets: contents.secrets,
        }),
    });
    Ok(dto)
}

/// Reads Remoter's own JSON export and holds its nodes.
fn json_parse(
    state: &AppState,
    bytes: &[u8],
    limits: &Limits,
    subject: &str,
) -> Result<ImportPreviewDto, IpcError> {
    let (nodes, report) = native::parse_json(bytes, limits, &Vault::sealed_placeholder())
        .map_err(|err| IpcError::from_import(&err, subject))?;
    let dto = ImportPreviewDto {
        import_id: Uuid::now_v7().to_string(),
        source: JSON_WIRE.to_owned(),
        source_label: SourceFormat::RemoterJson.label().to_owned(),
        nodes: native::summaries(&nodes, &HashSet::new())
            .iter()
            .map(node_dto)
            .collect(),
        report: report_dto(&report),
    };

    let mut guard = state.lock();
    guard.vault_ref()?;
    guard.set_pending_import(PendingImport {
        id: dto.import_id.clone(),
        source: SourceFormat::RemoterJson,
        nodes: Vec::new(),
        report,
        native: Some(PendingNative {
            nodes,
            secrets: Vec::new(),
        }),
    });
    Ok(dto)
}

/// What an archive that would not open means, in the user's terms.
fn archive_error(err: &ArchiveError, subject: &str, size: usize) -> IpcError {
    match err {
        ArchiveError::NotAnArchive => unknown_format(),
        ArchiveError::WrongPassword => IpcError::new(
            "import.archive-wrong-password",
            format!("That password does not open {subject}."),
        )
        .with_actions(["Try the password again"]),
        ArchiveError::UnsupportedFormat(version) => IpcError::new(
            "import.archive-unsupported",
            format!(
                "{subject} was written by a newer version of Remoter, in archive format \
                 {version}, which this build does not read."
            ),
        )
        .with_actions(["Update Remoter"]),
        ArchiveError::Malformed | ArchiveError::Tampered | ArchiveError::Corrupt => IpcError::new(
            "import.archive-damaged",
            format!(
                "{subject} is damaged: what it holds is not what was sealed into it, so nothing \
                 was read from it."
            ),
        )
        .with_detail(err.to_string())
        .with_actions([
            "Copy the file again from where it came from",
            "Export the archive again",
        ]),
        ArchiveError::TooLarge { limit } => IpcError::from_import(
            &remoter_import::ImportError::TooLarge {
                size,
                limit: *limit,
            },
            subject,
        ),
        ArchiveError::Vault(err) => IpcError::from_vault(err, subject),
    }
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
        conflict_policy,
    } = req;
    let policy = parse_policy(conflict_policy.as_deref())?;

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
    let tree = read_tree(vault)?;

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

    if let Some(native) = pending.native {
        let incoming = native_incoming(&tree, destination, &excluded, native)?;
        return commit_incoming(
            vault,
            tree,
            pending_source,
            destination,
            incoming,
            policy,
            needs_attention,
        );
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

    // Parents before children, whatever order the parser produced. A preview
    // whose parents cannot all be reached is a bug in the importer rather than
    // a problem with the file, so it is reported as one.
    let ordered = order_by_parent(&mut included, destination)?;

    let mut incoming = Incoming {
        nodes: Vec::with_capacity(ordered.len()),
        secrets: Vec::new(),
        excluded: excluded.len(),
    };
    for mut node in ordered {
        if node.parent_id.is_none() {
            node.parent_id = destination;
            node.sort_order = base_sort_order.saturating_add(node.sort_order);
        }

        // Copied out before `into_node` consumes the preview and drops the
        // plaintext. Both buffers wipe themselves; neither is written anywhere
        // but into the vault's sealing call. A password the file did not carry
        // gets the placeholder and nothing to seal, which is what makes it ask
        // for one the first time it is used.
        let sealed = if node.holds_password() {
            if let Some(secret) = node.secret() {
                incoming.secrets.push((
                    node.id,
                    PASSWORD_FIELD.to_owned(),
                    Secret::new(secret.expose().as_bytes().to_vec()),
                ));
            }
            // The real ciphertext is bound to the node's id and revision, so it
            // cannot exist until the row does.
            Some(Vault::sealed_placeholder())
        } else {
            None
        };
        incoming.nodes.push(
            node.into_node(now, sealed)
                .map_err(|err| IpcError::from_import(&err, "that file"))?,
        );
    }

    commit_incoming(
        vault,
        tree,
        pending_source,
        destination,
        incoming,
        policy,
        needs_attention,
    )
}

/// Nodes on their way into the vault, whatever they were read from.
struct Incoming {
    /// Parents before children, the import's top level parented at the
    /// destination, each with the id it has if it is inserted.
    nodes: Vec<Node>,
    /// Each secret, by the id of the node it belongs to and its field.
    secrets: Vec<(NodeId, String, Secret<Vec<u8>>)>,
    /// How many items the user left out.
    excluded: usize,
}

/// Remoter's own export, under new ids at the destination.
fn native_incoming(
    tree: &Tree,
    destination: Option<NodeId>,
    excluded: &BTreeSet<NodeId>,
    native: PendingNative,
) -> Result<Incoming, IpcError> {
    let PendingNative { nodes, secrets } = native;
    let grafted = native::graft(
        nodes,
        excluded,
        tree,
        destination,
        next_sort_order(tree, destination),
        now_millis(),
    )
    .map_err(|err| IpcError::from_import(&err, "that file"))?;
    // Each secret follows its node to the node's new id; a secret whose node
    // was left out goes nowhere.
    let secrets = secrets
        .into_iter()
        .filter_map(|secret| {
            let id = grafted.ids.get(&NodeId::from_uuid(secret.node))?;
            Some((*id, secret.field, secret.value))
        })
        .collect();
    Ok(Incoming {
        nodes: grafted.nodes,
        secrets,
        excluded: grafted.excluded,
    })
}

/// Writes nodes into the vault under a conflict policy: what is new inserted,
/// what the vault already has skipped or replaced, then the secrets sealed
/// under this vault's key, then one audit row and one save.
#[allow(clippy::too_many_lines)] // one linear transaction; splitting it hides the order
fn commit_incoming(
    vault: &mut Vault,
    mut tree: Tree,
    source: SourceFormat,
    destination: Option<NodeId>,
    incoming: Incoming,
    policy: ConflictPolicy,
    needs_attention: usize,
) -> Result<ImportResultDto, IpcError> {
    let Incoming {
        nodes,
        secrets,
        excluded,
    } = incoming;
    let resolution = conflicts::resolve(nodes, &tree, destination, policy);

    let mut patch = TreePatch::default();
    let mut counts = ImportCountsDto::default();
    let mut root_ids = Vec::new();
    let mut replaced_credentials = Vec::new();
    for node in resolution.updates {
        if node.kind.as_credential().is_some() {
            replaced_credentials.push(node.id);
        }
        let updated = tree.update(node).map_err(|err| IpcError::from_core(&err))?;
        patch.updated.extend(updated.updated);
    }
    let replaced = patch.updated.len();
    for node in resolution.inserts {
        match node.kind {
            NodeKind::Folder(_) => counts.folders += 1,
            NodeKind::Connection(_) => counts.connections += 1,
            NodeKind::Credential(_) => counts.credentials += 1,
            _ => {}
        }
        if node.parent_id == destination {
            root_ids.push(node.id.to_string());
        }
        let inserted = tree.insert(node).map_err(|err| IpcError::from_core(&err))?;
        patch.inserted.extend(inserted.inserted);
    }
    let imported = patch.inserted.len();

    // Nothing above this line touched the vault. One row-writing pass, one
    // sealing pass, one atomic save.
    vault
        .apply(&tree, &patch)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;

    // A replaced credential that now holds another kind of secret — a key where
    // there was a password — must not keep the old one.
    for id in replaced_credentials {
        let Some(node) = tree.get(id) else {
            continue;
        };
        let fields = vault
            .secret_fields(*id.as_uuid())
            .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
        for field in fields {
            if !holds_field(node, &field) {
                vault
                    .remove_secret(*id.as_uuid(), &field)
                    .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
            }
        }
    }

    // Each secret follows its node to where it ended up, and is stored only if
    // that node holds a secret in that field. A file that came from somewhere
    // does not get a field sealed into the vault on its say-so, and an item
    // the vault kept as it was keeps its own secrets.
    let mut secrets_stored = 0usize;
    for (id, field, value) in secrets {
        if resolution.skipped.contains(&id) {
            continue;
        }
        let target = resolution.ids.get(&id).copied().unwrap_or(id);
        if !tree
            .get(target)
            .is_some_and(|node| holds_field(node, &field))
        {
            continue;
        }
        vault
            .set_secret(*target.as_uuid(), &field, value)
            .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
        secrets_stored += 1;
    }

    // One row for the import as a whole, beside the row per node `apply` wrote:
    // four hundred "entry created" rows explain themselves only if something
    // says where they came from.
    let detail = format!(
        "imported from {}: folders {}, connections {}, credentials {}, passwords {secrets_stored}; \
         {} replaced, {} left as they were, {} folders merged",
        source.label(),
        counts.folders,
        counts.connections,
        counts.credentials,
        replaced,
        resolution.skipped.len(),
        resolution.merged,
    );
    vault
        .audit(
            AuditEvent::DataImported,
            AuditOutcome::Success,
            Some(&detail),
        )
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    save(vault)?;

    Ok(ImportResultDto {
        source: source_wire(source).to_owned(),
        imported,
        skipped: excluded,
        folders: counts.folders,
        connections: counts.connections,
        credentials: counts.credentials,
        secrets_stored,
        replaced,
        unchanged: resolution.skipped.len(),
        merged: resolution.merged,
        needs_attention,
        root_ids,
    })
}

/// Reads a conflict policy's wire spelling.
fn parse_policy(name: Option<&str>) -> Result<ConflictPolicy, IpcError> {
    match name {
        None | Some("keep-both") => Ok(ConflictPolicy::KeepBoth),
        Some("skip") => Ok(ConflictPolicy::Skip),
        Some("replace") => Ok(ConflictPolicy::Replace),
        Some(other) => Err(IpcError::invalid_request(
            "conflictPolicy",
            format!("`{other}` is not a conflict policy; expected keep-both, skip or replace"),
        )),
    }
}

/// What an import would collide with at a destination, before it is committed.
///
/// Read-only: the preview stays held, nothing is written, and the answer is
/// the same comparison the commit makes.
#[tauri::command]
pub(crate) fn import_conflicts(
    state: State<'_, AppState>,
    req: ImportConflictsRequestDto,
) -> Result<ImportConflictsDto, IpcError> {
    import_conflicts_impl(&state, req)
}

/// How many conflicts the interface lists by name. The total is always exact.
const MAX_LISTED_CONFLICTS: usize = 200;

fn import_conflicts_impl(
    state: &AppState,
    req: ImportConflictsRequestDto,
) -> Result<ImportConflictsDto, IpcError> {
    let ImportConflictsRequestDto {
        import_id,
        destination_id,
        excluded_ids,
    } = req;
    let destination = destination_id
        .as_deref()
        .map(|id| crate::commands::parse_node_id(id, "destinationId"))
        .transpose()?;
    let mut excluded: BTreeSet<NodeId> = BTreeSet::new();
    for id in excluded_ids.iter().flatten() {
        excluded.insert(crate::commands::parse_node_id(id, "excludedIds")?);
    }

    let mut guard = state.lock();
    let vault = guard.vault_ref()?;
    let tree = read_tree(vault)?;
    let pending = guard.pending_import(&import_id)?;

    let candidates: Vec<Candidate> = match &pending.native {
        Some(native) => {
            let grafted = native::graft(native.nodes.clone(), &excluded, &tree, destination, 0, 0)
                .map_err(|err| IpcError::from_import(&err, "that file"))?;
            grafted
                .nodes
                .iter()
                .map(|node| {
                    let mut candidate = Candidate::of(node);
                    if candidate.parent_id == destination {
                        candidate.parent_id = None;
                    }
                    candidate
                })
                .collect()
        }
        None => {
            let excluded = closure_of(&pending.nodes, &excluded);
            pending
                .nodes
                .iter()
                .filter(|node| !excluded.contains(&node.id))
                .map(|node| Candidate {
                    id: node.id,
                    parent_id: node.parent_id,
                    kind: node.kind.label(),
                    name: node.name.clone(),
                    attached_to: None,
                })
                .collect()
        }
    };

    let found = conflicts::find(&candidates, &tree, destination);
    Ok(ImportConflictsDto {
        total: found.len(),
        items: found
            .into_iter()
            .take(MAX_LISTED_CONFLICTS)
            .map(|conflict| ImportConflictDto {
                path: tree
                    .get(conflict.existing)
                    .and_then(|node| tree.ancestors(node.id).ok())
                    .map(|ancestors| {
                        let mut names: Vec<&str> =
                            ancestors.iter().map(|a| a.name.as_str()).collect();
                        names.reverse();
                        names.join(" / ")
                    })
                    .unwrap_or_default(),
                name: conflict.name,
                kind: conflict.kind,
            })
            .collect(),
    })
}

/// Whether a node keeps a secret in `field`, by what its kind says it holds.
fn holds_field(node: &Node, field: &str) -> bool {
    let NodeKind::Credential(credential) = &node.kind else {
        return false;
    };
    let by_kind = match (&credential.secret, field) {
        (SecretKind::Password { .. }, "password")
        | (SecretKind::PrivateKey { .. }, "private_key")
        | (SecretKind::Certificate { .. }, "certificate" | "certificate_key") => true,
        (
            SecretKind::PrivateKey {
                sealed_passphrase, ..
            },
            "passphrase",
        ) => sealed_passphrase.is_some(),
        _ => false,
    };
    by_kind || (field == "totp" && credential.totp.is_some())
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
    // The larger of the two ceilings, because which one applies is not known
    // until the bytes are: an archive may be bigger than a text file an
    // importer parses, and a text file this size is refused by its parser.
    let limit = limits.max_input_bytes.max(archive::MAX_ARCHIVE_BYTES);
    if size > limit {
        return Err(IpcError::from_import(
            &remoter_import::ImportError::TooLarge { size, limit },
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
        SourceFormat::RemoterArchive => ARCHIVE_WIRE,
        SourceFormat::RemoterJson => JSON_WIRE,
        SourceFormat::RdpFile => "rdp-file",
        SourceFormat::RdcMan => "rdcman",
        SourceFormat::Putty => "putty",
        // `SourceFormat` is `#[non_exhaustive]`: a format added upstream is
        // named rather than mistaken for one of these.
        _ => "unknown",
    }
}

fn parse_source(name: &str) -> Result<SourceFormat, IpcError> {
    match name {
        "mremoteng" => Ok(SourceFormat::MRemoteNg),
        "ssh-config" => Ok(SourceFormat::OpenSshConfig),
        "csv" => Ok(SourceFormat::Csv),
        ARCHIVE_WIRE => Ok(SourceFormat::RemoterArchive),
        JSON_WIRE => Ok(SourceFormat::RemoterJson),
        "rdp-file" => Ok(SourceFormat::RdpFile),
        "rdcman" => Ok(SourceFormat::RdcMan),
        "putty" => Ok(SourceFormat::Putty),
        other => Err(IpcError::invalid_request(
            "source",
            format!(
                "`{other}` is not an importer; expected mremoteng, rdcman, rdp-file, putty, \
                 ssh-config, csv, remoter-archive or remoter-json"
            ),
        )),
    }
}

fn unknown_format() -> IpcError {
    IpcError::new(
        "import.unknown-format",
        "That file is not in a format Remoter imports: it is not a Remoter archive or JSON \
         export, an mRemoteNG document, a Remote Desktop Connection Manager document, an .rdp \
         file, saved PuTTY sessions, an OpenSSH config or a CSV export.",
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
            SourceFormat::RemoterArchive,
            SourceFormat::RemoterJson,
            SourceFormat::RdpFile,
            SourceFormat::RdcMan,
            SourceFormat::Putty,
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
                conflict_policy: None,
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

        // The import is on the record as one row of its own that says where
        // the entries came from, and not what their passwords were.
        let log = crate::audit::audit_query_impl(&state, crate::dto::AuditQueryDto::default());
        let Ok(log) = log else {
            panic!("reading the audit log failed");
        };
        let imported: Vec<_> = log
            .entries
            .iter()
            .filter(|entry| entry.event == "data_imported")
            .collect();
        assert_eq!(imported.len(), 1, "one row per import: {:?}", log.entries);
        let detail = imported[0].detail.as_deref().unwrap_or_default();
        assert!(
            detail
                == "imported from csv: folders 2, connections 2, credentials 1, passwords 1; \
                    0 replaced, 0 left as they were, 0 folders merged",
            "{detail}"
        );
        assert!(!imported[0].warning, "bringing data in is not a warning");
        let rendered = serde_json::to_string(&log).unwrap_or_default();
        assert!(
            !rendered.contains(CSV_PASSWORD),
            "the audit log leaked a password"
        );

        // The preview is spent: committing it twice does not import twice.
        let again = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: None,
                conflict_policy: None,
            },
        );
        assert!(again.is_err_and(|err| err.code == "import.no-such-preview"));
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn an_archive_moves_a_folder_and_its_passwords_into_another_vault() {
        const SERVER_PASSWORD: &str = "root-password-on-the-server";
        const ARCHIVE_PASSWORD: &str = "orbit-lantern-quarry-velvet-78";

        // The vault it leaves.
        let from = Scratch::new();
        let Some(source) = open_vault(&from) else {
            panic!("the first vault could not be created");
        };
        let mut folder = crate::dto::CreateNodeDto {
            parent_id: None,
            kind: String::from("folder"),
            name: String::from("Production"),
            protocol: None,
            host: None,
            port: None,
            username: None,
            password: None,
            credential: None,
            credential_id: None,
            gateway: None,
        };
        let folder = crate::commands::node_create_impl(&source, &mut folder)
            .unwrap_or_else(|err| panic!("creating the folder failed: {}", err.message));
        let mut web = crate::dto::CreateNodeDto {
            parent_id: Some(folder.id.clone()),
            kind: String::from("connection"),
            name: String::from("web-01"),
            protocol: Some(String::from("ssh")),
            host: Some(String::from("203.0.113.10")),
            port: None,
            username: Some(String::from("root")),
            password: Some(String::from(SERVER_PASSWORD)),
            credential: None,
            credential_id: None,
            gateway: None,
        };
        crate::commands::node_create_impl(&source, &mut web)
            .unwrap_or_else(|err| panic!("creating the connection failed: {}", err.message));

        let archive = from.join("production.rmtr");
        let exported = crate::export::tree_export_for_tests(
            &source,
            crate::dto::TreeExportDto {
                path: archive.display().to_string(),
                format: String::from("remoter-archive"),
                root_id: Some(folder.id.clone()),
                password: Some(String::from(ARCHIVE_PASSWORD)),
            },
        );
        let Ok(exported) = exported else {
            panic!("exporting failed: {}", why(&exported));
        };
        assert_eq!(exported.format, "remoter-archive");
        let summary = exported
            .archive
            .unwrap_or_else(|| panic!("no archive summary"));
        assert_eq!(summary.connections, 1);
        assert_eq!(summary.secrets, 1);
        let written = std::fs::read(&archive).unwrap_or_default();
        assert!(
            !written
                .windows(SERVER_PASSWORD.len())
                .any(|w| w == SERVER_PASSWORD.as_bytes()),
            "the server password is in the archive in the clear"
        );

        // The vault it arrives in.
        let to = Scratch::new();
        let Some(target) = open_vault(&to) else {
            panic!("the second vault could not be created");
        };
        let path = archive.display().to_string();
        let detected = import_detect_impl(path.clone())
            .unwrap_or_else(|err| panic!("detecting failed: {}", err.message));
        assert_eq!(detected.format.as_deref(), Some("remoter-archive"));
        assert!(detected.password_required);

        let without = import_parse_impl(&target, path.clone(), None, None);
        assert!(without.is_err_and(|err| err.code == "import.archive-password-required"));
        let wrong = import_parse_impl(&target, path.clone(), Some(String::from("nope")), None);
        assert!(wrong.is_err_and(|err| err.code == "import.archive-wrong-password"));

        let preview = import_parse_impl(&target, path, Some(String::from(ARCHIVE_PASSWORD)), None)
            .unwrap_or_else(|err| panic!("parsing failed: {}", err.message));
        assert_eq!(preview.source, "remoter-archive");
        assert!(preview.nodes.iter().any(|node| node.has_secret));
        let rendered = serde_json::to_string(&preview).unwrap_or_default();
        assert!(
            !rendered.contains(SERVER_PASSWORD),
            "the preview leaked a password"
        );

        let committed = import_commit_impl(
            &target,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: None,
                conflict_policy: None,
            },
        )
        .unwrap_or_else(|err| panic!("committing failed: {}", err.message));
        assert_eq!(committed.connections, 1);
        assert_eq!(committed.folders, 1);
        assert_eq!(committed.secrets_stored, 1);

        // And the password is there, under this vault's key, for the
        // connection that came with it.
        let tree = tree_list_impl(&target).unwrap_or_default();
        let web = tree
            .iter()
            .find(|node| node.name == "web-01" && node.kind == "connection")
            .unwrap_or_else(|| panic!("web-01 did not arrive: {tree:?}"));
        let credential_id = web
            .attached_credential_id
            .clone()
            .unwrap_or_else(|| panic!("web-01 lost its credential: {web:?}"));
        let mut guard = target.lock();
        let Ok(vault) = guard.vault_mut() else {
            panic!("the vault closed");
        };
        let uuid = uuid::Uuid::parse_str(&credential_id).unwrap_or_default();
        let borrowed = vault
            .borrow_secret(uuid, "password", remoter_vault::Purpose::SshPassword)
            .unwrap_or_else(|err| panic!("the password did not arrive: {err}"));
        assert_eq!(
            remoter_vault::ExposeSecret::expose_secret(&borrowed).as_slice(),
            SERVER_PASSWORD.as_bytes()
        );
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn a_json_export_comes_back_with_its_credentials_asking_for_their_passwords() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let mut web = crate::dto::CreateNodeDto {
            parent_id: None,
            kind: String::from("connection"),
            name: String::from("web-01"),
            protocol: Some(String::from("ssh")),
            host: Some(String::from("203.0.113.10")),
            port: Some(2222),
            username: Some(String::from("root")),
            password: Some(String::from("server-password")),
            credential: None,
            credential_id: None,
            gateway: None,
        };
        let original = crate::commands::node_create_impl(&state, &mut web)
            .unwrap_or_else(|err| panic!("creating the connection failed: {}", err.message));

        let file = scratch.join("vault.json");
        crate::export::tree_export_for_tests(
            &state,
            crate::dto::TreeExportDto {
                path: file.display().to_string(),
                format: String::from("json"),
                root_id: None,
                password: None,
            },
        )
        .unwrap_or_else(|err| panic!("exporting failed: {}", err.message));

        // Back into the same vault: every id in the file is already taken.
        let path = file.display().to_string();
        let detected = import_detect_impl(path.clone())
            .unwrap_or_else(|err| panic!("detecting failed: {}", err.message));
        assert_eq!(detected.format.as_deref(), Some("remoter-json"));
        assert!(!detected.password_required);
        let preview = import_parse_impl(&state, path, None, None)
            .unwrap_or_else(|err| panic!("parsing failed: {}", err.message));
        let rendered = serde_json::to_string(&preview.report).unwrap_or_default();
        assert!(rendered.contains("secrets_not_carried"), "{rendered}");

        let committed = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: None,
                conflict_policy: None,
            },
        )
        .unwrap_or_else(|err| panic!("committing failed: {}", err.message));
        assert_eq!(committed.source, "remoter-json");
        assert_eq!(committed.connections, 1);
        assert_eq!(committed.secrets_stored, 0);

        let tree = tree_list_impl(&state).unwrap_or_default();
        let copies: Vec<_> = tree
            .iter()
            .filter(|node| node.name == "web-01" && node.kind == "connection")
            .collect();
        assert_eq!(copies.len(), 2, "the original and the import: {tree:?}");
        let imported = copies
            .iter()
            .find(|node| node.id != original.id)
            .copied()
            .unwrap_or_else(|| panic!("no imported copy: {copies:?}"));
        assert_eq!(imported.port, Some(2222));
        // The connection's own credential came with it, as the credential it
        // was: a password one, for root.
        assert_eq!(imported.username.as_deref(), Some("root"));
        assert_eq!(imported.secret_kind.as_deref(), Some("password"));
        let credential = imported
            .attached_credential_id
            .clone()
            .unwrap_or_else(|| panic!("the credential did not come with it: {imported:?}"));
        assert_ne!(Some(credential.clone()), original.attached_credential_id);

        // It is a password credential with no password: using it asks for one.
        let mut guard = state.lock();
        let Ok(vault) = guard.vault_mut() else {
            panic!("the vault closed");
        };
        let uuid = uuid::Uuid::parse_str(&credential).unwrap_or_default();
        assert!(matches!(
            vault.borrow_secret(uuid, "password", remoter_vault::Purpose::SshPassword),
            Err(remoter_vault::VaultError::NoSuchSecret { .. })
        ));
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn an_rdp_file_saved_by_mstsc_comes_in_asking_for_its_password() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let file = scratch.join("Domain controller.rdp");
        let mut bytes = vec![0xff, 0xfe];
        for unit in "screen mode id:i:2\r\nfull address:s:dc01.contoso.com:3390\r\n\
                     username:s:CONTOSO\\administrator\r\n\
                     password 51:b:01000000D08C9DDF0115D1118C7A00C04FC297EB\r\n"
            .encode_utf16()
        {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(&file, &bytes).unwrap_or_else(|err| panic!("writing failed: {err}"));

        let path = file.display().to_string();
        let detected = import_detect_impl(path.clone())
            .unwrap_or_else(|err| panic!("detecting failed: {}", err.message));
        assert_eq!(detected.format.as_deref(), Some("rdp-file"));
        let preview = import_parse_impl(&state, path, None, None)
            .unwrap_or_else(|err| panic!("parsing failed: {}", err.message));
        let rendered = serde_json::to_string(&preview.report).unwrap_or_default();
        assert!(
            rendered.contains("protected_passwords_not_carried"),
            "{rendered}"
        );
        assert!(!rendered.contains("D08C9DDF"), "{rendered}");

        let committed = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: None,
                conflict_policy: None,
            },
        )
        .unwrap_or_else(|err| panic!("committing failed: {}", err.message));
        assert_eq!(committed.connections, 1);
        assert_eq!(committed.credentials, 1);
        assert_eq!(committed.secrets_stored, 0);

        let tree = tree_list_impl(&state).unwrap_or_default();
        let connection = tree
            .iter()
            .find(|node| node.name == "Domain controller")
            .unwrap_or_else(|| panic!("the connection is not in the tree: {tree:?}"));
        assert_eq!(connection.protocol.as_deref(), Some("rdp"));
        assert_eq!(connection.host.as_deref(), Some("dc01.contoso.com"));
        assert_eq!(connection.port, Some(3390));
        let credential = connection
            .credential_id
            .clone()
            .unwrap_or_else(|| panic!("no credential: {connection:?}"));
        let account = tree
            .iter()
            .find(|node| node.id == credential)
            .unwrap_or_else(|| panic!("the credential is not in the tree: {tree:?}"));
        assert_eq!(account.username.as_deref(), Some("administrator"));
        assert_eq!(account.secret_kind.as_deref(), Some("password"));

        let mut guard = state.lock();
        let Ok(vault) = guard.vault_mut() else {
            panic!("the vault closed");
        };
        let uuid = uuid::Uuid::parse_str(&credential).unwrap_or_default();
        assert!(matches!(
            vault.borrow_secret(uuid, "password", remoter_vault::Purpose::RdpCredentials),
            Err(remoter_vault::VaultError::NoSuchSecret { .. })
        ));
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn a_putty_sessions_directory_imports_with_its_jump_host() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let home = scratch.join("home");
        let sessions = home.join(".putty").join("sessions");
        std::fs::create_dir_all(&sessions).unwrap_or_else(|err| panic!("mkdir failed: {err}"));
        for (name, body) in [
            (
                "bastion",
                "HostName=bastion.example.com\nProtocol=ssh\nUserName=jump\n",
            ),
            (
                "db%20primary",
                "HostName=db.internal\nProtocol=ssh\nPortNumber=2222\nProxyMethod=6\n\
                 ProxyHost=bastion\nUserName=postgres\n",
            ),
        ] {
            std::fs::write(sessions.join(name), body)
                .unwrap_or_else(|err| panic!("writing {name} failed: {err}"));
        }

        #[cfg(not(windows))]
        assert_eq!(
            putty_directory_under(&home),
            Some(sessions.display().to_string())
        );
        let path = sessions.display().to_string();
        let detected = import_detect_impl(path.clone())
            .unwrap_or_else(|err| panic!("detecting failed: {}", err.message));
        assert_eq!(detected.format.as_deref(), Some("putty"));
        let preview = import_parse_impl(&state, path, None, None)
            .unwrap_or_else(|err| panic!("parsing failed: {}", err.message));
        let committed = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: None,
                conflict_policy: None,
            },
        )
        .unwrap_or_else(|err| panic!("committing failed: {}", err.message));
        assert_eq!(committed.source, "putty");
        assert_eq!(committed.connections, 2);

        let tree = tree_list_impl(&state).unwrap_or_default();
        let bastion = tree
            .iter()
            .find(|node| node.name == "bastion")
            .unwrap_or_else(|| panic!("no bastion: {tree:?}"));
        let db = tree
            .iter()
            .find(|node| node.name == "db primary")
            .unwrap_or_else(|| panic!("no db primary: {tree:?}"));
        assert_eq!(db.port, Some(2222));
        let hops: Vec<&str> = db
            .gateway
            .iter()
            .flatten()
            .map(|hop| hop.node_id.as_str())
            .collect();
        assert_eq!(hops, [bastion.id.as_str()], "{db:?}");
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn an_rdcman_document_keeps_its_groups() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let file = scratch.join("lab.rdg");
        std::fs::write(
            &file,
            r#"<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.93" schemaVersion="3">
  <file>
    <properties><name>Lab</name></properties>
    <group>
      <properties><name>Web</name></properties>
      <connectionSettings inherit="None"><port>3390</port></connectionSettings>
      <server><properties><displayName>web01</displayName><name>192.0.2.10</name></properties></server>
      <server><properties><displayName>web02</displayName><name>192.0.2.11</name></properties></server>
    </group>
  </file>
</RDCMan>"#,
        )
        .unwrap_or_else(|err| panic!("writing failed: {err}"));

        let path = file.display().to_string();
        let detected = import_detect_impl(path.clone())
            .unwrap_or_else(|err| panic!("detecting failed: {}", err.message));
        assert_eq!(detected.format.as_deref(), Some("rdcman"));
        let preview = import_parse_impl(&state, path, None, None)
            .unwrap_or_else(|err| panic!("parsing failed: {}", err.message));
        let committed = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: None,
                conflict_policy: None,
            },
        )
        .unwrap_or_else(|err| panic!("committing failed: {}", err.message));
        assert_eq!((committed.folders, committed.connections), (2, 2));

        let tree = tree_list_impl(&state).unwrap_or_default();
        let web = tree
            .iter()
            .find(|node| node.name == "Web")
            .unwrap_or_else(|| panic!("no Web folder: {tree:?}"));
        for name in ["web01", "web02"] {
            let server = tree
                .iter()
                .find(|node| node.name == name)
                .unwrap_or_else(|| panic!("no {name}: {tree:?}"));
            assert_eq!(server.parent_id.as_deref(), Some(web.id.as_str()));
            // Set once on the group, and resolved from there.
            let effective = crate::commands::node_resolve_impl(&state, server.id.clone())
                .unwrap_or_else(|err| panic!("resolving {name} failed: {}", err.message));
            let port = effective
                .fields
                .iter()
                .find(|field| field.field == "port")
                .unwrap_or_else(|| panic!("no port for {name}: {effective:?}"));
            assert_eq!(port.value.as_deref(), Some("3390"), "{name}: {port:?}");
            assert_eq!(port.source_name.as_deref(), Some("Web"), "{name}: {port:?}");
        }
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn importing_the_same_file_again_skips_or_replaces_what_is_already_there() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let commit = |path: String, policy: Option<&str>| {
            let preview = import_parse_impl(&state, path, None, None)
                .unwrap_or_else(|err| panic!("parsing failed: {}", err.message));
            let conflicts = import_conflicts_impl(
                &state,
                ImportConflictsRequestDto {
                    import_id: preview.import_id.clone(),
                    destination_id: None,
                    excluded_ids: None,
                },
            )
            .unwrap_or_else(|err| panic!("reading conflicts failed: {}", err.message));
            let committed = import_commit_impl(
                &state,
                ImportCommitDto {
                    import_id: preview.import_id,
                    destination_id: None,
                    excluded_ids: None,
                    conflict_policy: policy.map(ToOwned::to_owned),
                },
            )
            .unwrap_or_else(|err| panic!("committing failed: {}", err.message));
            (conflicts, committed)
        };

        let first = scratch.write("export.csv", CSV);
        let (conflicts, committed) = commit(first.display().to_string(), None);
        assert_eq!(
            conflicts.total, 0,
            "an empty vault has nothing to collide with"
        );
        let size = tree_list_impl(&state).unwrap_or_default().len();
        assert_eq!(committed.imported, size);

        // The same file again, told to skip: nothing new, nothing changed.
        let (conflicts, committed) = commit(first.display().to_string(), Some("skip"));
        assert!(
            conflicts.items.iter().any(|item| item.name == "web-01"
                && item.kind == "connection"
                && item.path == "Production"),
            "{conflicts:?}"
        );
        assert_eq!(committed.imported, 0, "{committed:?}");
        assert!(
            committed.merged >= 1 && committed.unchanged >= 2,
            "{committed:?}"
        );
        assert_eq!(tree_list_impl(&state).unwrap_or_default().len(), size);

        // A changed file, told to replace: web-01 moves host, and stays one node.
        let changed = scratch.write(
            "changed.csv",
            &CSV.replace("web-01.example.com", "web-01.new.example.com"),
        );
        let (_, committed) = commit(changed.display().to_string(), Some("replace"));
        assert_eq!(committed.imported, 0, "{committed:?}");
        assert!(committed.replaced >= 2, "{committed:?}");
        let tree = tree_list_impl(&state).unwrap_or_default();
        assert_eq!(tree.len(), size);
        let web: Vec<_> = tree.iter().filter(|node| node.name == "web-01").collect();
        assert_eq!(web.len(), 1);
        assert_eq!(web[0].host.as_deref(), Some("web-01.new.example.com"));

        // And keeping both is still what it always was: a second copy.
        let (_, committed) = commit(first.display().to_string(), Some("keep-both"));
        assert_eq!(committed.imported, size);
        assert_eq!(tree_list_impl(&state).unwrap_or_default().len(), size * 2);

        let refused = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: String::from("nothing"),
                destination_id: None,
                excluded_ids: None,
                conflict_policy: Some(String::from("merge-everything")),
            },
        );
        assert!(refused.is_err_and(|err| err.code == "request.invalid"));
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
                conflict_policy: None,
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
                conflict_policy: None,
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
                conflict_policy: None,
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

#[cfg(test)]
mod mremoteng_tests {
    //! The wizard's own path over a `confCons.xml` shaped the way mRemoteNG
    //! shapes one.
    //!
    //! Not a parser test — `remoter-import` has those. This is `import_detect`
    //! → `import_parse` → `import_commit`, the three calls the wizard makes,
    //! against a document with the root element, the attribute set and the
    //! ciphertext a real export carries, asserting what ends up in the vault.
    //!
    //! **The ciphertext below was produced outside this workspace**, by an
    //! independent implementation of the scheme in
    //! `mRemoteNG/Security/SymmetricEncryption/AeadCryptographyProvider.cs`:
    //! PBKDF2-HMAC-SHA1 to 256 bits over a 16-byte salt, AES-GCM with a 16-byte
    //! nonce and the salt as associated data, base64 of
    //! `salt‖nonce‖ciphertext‖tag`. A fixture encrypted by the same code that
    //! decrypts it would prove only that the code agrees with itself.

    use super::*;
    use crate::commands::{node_resolve_impl, tree_list_impl};
    use crate::dto::NodeDto;
    use crate::test_support::{Scratch, open_vault, why};
    use remoter_vault::ExposeSecret;

    /// `Protected`, under mRemoteNG's published default password.
    const PROTECTED_DEFAULT: &str =
        "EREREREREREREREREREREe7u7u7u7u7u7u7u7u7u7u5eR8E9z/RfG1wmBH9Ka9P4DZkprbAa+gcL6bJHHfjyDFNG";
    /// The datacentre folder's account password: `hunter2`.
    const SVC_PASSWORD: &str =
        "ISEhISEhISEhISEhISEhId7e3t7e3t7e3t7e3t7e3t7MFk6snE233t6K4XjkvVfV0wCW1TmEGg==";
    /// The domain administrator's password: `Tr0ub4dor&3`.
    const ADMIN_PASSWORD: &str =
        "MTExMTExMTExMTExMTExMc7Ozs7Ozs7Ozs7Ozs7Ozs7tda2OyY8DI1/VSG6hH2DGKicVv+81guVajuo=";
    /// `Protected`, under the password `correct horse`.
    const PROTECTED_CUSTOM: &str =
        "QUFBQUFBQUFBQUFBQUFBQb6+vr6+vr6+vr6+vr6+vr4dJ7FEEZFjst08HafaeDOLKLKQVdnQwqrIcI1yCN8c";
    /// `hunter2` again, under `correct horse`.
    const CUSTOM_SVC_PASSWORD: &str =
        "UVFRUVFRUVFRUVFRUVFRUa6urq6urq6urq6urq6urq5awsLbsERQmJKmAg5opTeOku+aaKqgdw==";

    /// The plaintexts inside the document, asserted absent from everything that
    /// crosses the boundary.
    const PLAINTEXTS: &[&str] = &["hunter2", "Tr0ub4dor&3"];

    /// The attributes mRemoteNG writes on every node and this application has
    /// no field for.
    ///
    /// Abbreviated — a real node carries about eighty of these and another
    /// sixty `Inherit*` flags — but present, because a fixture with six
    /// attributes is not the file anybody has, and because what happens to
    /// them is part of what is asserted: they are preserved verbatim under
    /// `mremoteng.*` unless the node says it inherits them.
    const SETTINGS: &str = concat!(
        r#" Icon="mRemoteNG" Panel="General" RdpVersion="rdc" PuttySession="Default Settings""#,
        r#" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE""#,
        r#" RDPAuthenticationLevel="NoAuth" Colors="Colors16Bit" Resolution="FitToWindow""#,
        r#" RedirectDiskDrives="None" RedirectClipboard="true" RedirectSound="DoNotPlay""#,
        r#" VNCCompression="CompNone" VNCAuthMode="AuthVNC" RDGatewayUsageMethod="Never""#,
        r#" Connected="false" MacAddress="" UserField="""#,
    );

    /// A `confCons.xml` as mRemoteNG writes one.
    ///
    /// The root element is namespaced — `XmlRootNodeSerializer` has built it as
    /// `XNamespace "http://mremoteng.org" + "Connections"` with the prefix
    /// `mrng` beside it since 1.76, so this is the first line of every export a
    /// person has made this decade. It is also written with a byte-order mark
    /// and CRLF line endings, which is what a file off a Windows machine has.
    fn confcons(protected: &str, svc: &str, admin: &str) -> String {
        let body = format!(
            concat!(
                r#"<Node Name="Datacentre EU-West" Type="Container" Expanded="true" "#,
                r#"Descr="Frankfurt" Username="svc-deploy" Domain="" Password="{svc}" "#,
                r#"Hostname="" Protocol="RDP" Port="13389"{settings}>
    <Node Name="web-01" Type="Connection" Descr="" Username="" Domain="" Password="" "#,
                r#"Hostname="web-01.eu.acme.internal" Protocol="RDP" Port="3389"{settings} "#,
                r#"InheritPort="true" InheritUsername="true" InheritPassword="true" "#,
                r#"InheritDomain="true" InheritColors="true" InheritIcon="true" "#,
                r#"InheritResolution="true" />
    <Node Name="web-02" Type="Connection" Descr="" Username="root" Domain="" "#,
                r#"Password="{admin}" Hostname="web-02.eu.acme.internal" Protocol="SSH2" "#,
                r#"Port="2022"{settings} />
  </Node>
  <Node Name="SRV-DC01" Type="Connection" Descr="Domain controller" "#,
                r#"Username="administrator" Domain="CORP" Password="{admin}" "#,
                r#"Hostname="srv-dc01.corp.local" Protocol="RDP" Port="3390"{settings} />"#,
            ),
            svc = svc,
            admin = admin,
            settings = SETTINGS,
        );
        format!(
            concat!(
                "\u{feff}<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
                "<mrng:Connections xmlns:mrng=\"http://mremoteng.org\" Name=\"Acme Production\" ",
                "Export=\"false\" EncryptionEngine=\"AES\" BlockCipherMode=\"GCM\" ",
                "KdfIterations=\"1000\" FullFileEncryption=\"false\" Protected=\"{protected}\" ",
                "ConfVersion=\"2.7\">\n  {body}\n</mrng:Connections>\n",
            ),
            protected = protected,
            body = body,
        )
        .replace('\n', "\r\n")
    }

    fn named<'a>(tree: &'a [NodeDto], name: &str) -> &'a NodeDto {
        #[expect(
            clippy::panic,
            reason = "an assertion about a node that is not there has nothing to say"
        )]
        tree.iter()
            .find(|node| node.name == name)
            .unwrap_or_else(|| panic!("no node named {name} in {tree:#?}"))
    }

    /// What one node kept from the file, read out of the vault's own tree.
    fn node_custom_fields(
        state: &AppState,
        id: &str,
    ) -> Result<BTreeMap<String, String>, IpcError> {
        let id = crate::commands::parse_node_id(id, "id")?;
        let mut guard = state.lock();
        let vault = guard.vault_ref()?;
        let tree = read_tree(vault)?;
        Ok(tree
            .get(id)
            .map(|node| node.custom_fields.clone())
            .unwrap_or_default())
    }

    /// The effective value of one field, after inheritance.
    fn resolved(state: &AppState, id: &str, field: &str) -> Option<String> {
        node_resolve_impl(state, id.to_owned())
            .ok()?
            .fields
            .into_iter()
            .find(|resolved| resolved.field == field)
            .and_then(|resolved| resolved.value)
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn a_real_confcons_is_detected_parsed_and_committed_as_a_tree() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let file = scratch.write(
            "confCons.xml",
            &confcons(PROTECTED_DEFAULT, SVC_PASSWORD, ADMIN_PASSWORD),
        );
        let path = file.display().to_string();

        // Step 1. The wizard preselects the format from this, and a file it
        // cannot place is a file whose Continue button will not move.
        let detected = import_detect_impl(path.clone());
        assert!(detected.is_ok(), "detecting failed: {}", why(&detected));
        let Ok(detected) = detected else {
            panic!("detecting failed");
        };
        assert_eq!(
            detected.format.as_deref(),
            Some("mremoteng"),
            "a real confCons.xml was not recognised as one"
        );
        let Some(document) = detected.document else {
            panic!("an mRemoteNG file must carry its header");
        };
        assert_eq!(document.name, "Acme Production");
        assert_eq!(document.conf_version.as_deref(), Some("2.7"));
        assert_eq!(document.cipher, "gcm");
        assert_eq!(document.kdf_iterations, Some(1000));
        assert!(!document.legacy_cipher);
        assert!(
            !document.password_required,
            "a file on the published default needs nothing from the user"
        );

        // Step 3. No password: the file is on mRemoteNG's own default.
        let preview = import_parse_impl(&state, path, None, None);
        assert!(preview.is_ok(), "parsing failed: {}", why(&preview));
        let Ok(preview) = preview else {
            panic!("parsing failed");
        };
        assert_eq!(preview.source, "mremoteng");
        assert_eq!(preview.report.counts.connections, 3);
        assert_eq!(preview.report.counts.skipped, 0);
        // The file being on the published default is told to the user before
        // the import, not after it.
        assert!(preview.report.needs_attention);

        let rendered = serde_json::to_string(&preview).unwrap_or_default();
        for plaintext in PLAINTEXTS {
            assert!(
                !rendered.contains(plaintext),
                "the preview leaked a password"
            );
        }

        // Step 7.
        let committed = import_commit_impl(
            &state,
            ImportCommitDto {
                import_id: preview.import_id,
                destination_id: None,
                excluded_ids: None,
                conflict_policy: None,
            },
        );
        assert!(committed.is_ok(), "committing failed: {}", why(&committed));
        let Ok(committed) = committed else {
            panic!("committing failed");
        };
        assert_eq!(committed.connections, 3);
        assert_eq!(
            committed.folders, 2,
            "the estate's folder, and one for the credentials"
        );
        assert_eq!(committed.skipped, 0);
        assert!(committed.secrets_stored >= 2);

        // And now the only thing that matters: what is in the vault.
        let tree = tree_list_impl(&state).unwrap_or_default();

        let folder = named(&tree, "Datacentre EU-West");
        assert_eq!(folder.kind, "folder");
        assert_eq!(folder.parent_id, None);
        assert_eq!(folder.description, "Frankfurt");

        let web01 = named(&tree, "web-01");
        assert_eq!(web01.kind, "connection");
        assert_eq!(
            web01.parent_id.as_deref(),
            Some(folder.id.as_str()),
            "the folder tree was flattened"
        );
        assert_eq!(web01.host.as_deref(), Some("web-01.eu.acme.internal"));
        assert_eq!(web01.protocol.as_deref(), Some("rdp"));
        // The row shows the port that would be used, and web-01 stores none of
        // its own: what it shows is RDP's default, not the 13389 on the folder.
        // The resolved view below is where inheritance is asserted.
        assert_eq!(web01.port, Some(3389));

        let web02 = named(&tree, "web-02");
        assert_eq!(web02.parent_id.as_deref(), Some(folder.id.as_str()));
        assert_eq!(web02.host.as_deref(), Some("web-02.eu.acme.internal"));
        assert_eq!(web02.protocol.as_deref(), Some("ssh"));
        assert_eq!(web02.port, Some(2022));

        let dc01 = named(&tree, "SRV-DC01");
        assert_eq!(
            dc01.parent_id, None,
            "a top-level connection stays at the top"
        );
        assert_eq!(dc01.host.as_deref(), Some("srv-dc01.corp.local"));
        assert_eq!(dc01.protocol.as_deref(), Some("rdp"));
        assert_eq!(dc01.port, Some(3390));

        // An account out of mRemoteNG becomes a shared credential rather than
        // a field on the connection, which is why the row carries no username
        // of its own: `Username`, `Domain` and `Password` are one credential,
        // and two connections using the same account share one. It is named
        // the way the file named it — domain and account together.
        let admin = named(&tree, "CORP\\administrator");
        assert_eq!(admin.kind, "credential");
        assert_eq!(admin.secret_kind.as_deref(), Some("password"));
        assert_eq!(
            dc01.credential_id.as_deref(),
            Some(admin.id.as_str()),
            "SRV-DC01 did not get the account the file gave it"
        );
        assert_eq!(
            resolved(&state, &dc01.id, "username").as_deref(),
            Some("administrator")
        );
        // web-02's account has no domain, so it is a second, different
        // credential — and the same one both connections that use it point at.
        let root = named(&tree, "root");
        assert_eq!(root.kind, "credential");
        assert_eq!(web02.credential_id.as_deref(), Some(root.id.as_str()));
        assert_eq!(
            resolved(&state, &web02.id, "username").as_deref(),
            Some("root")
        );

        // Inheritance is not decoration: web-01 stores no port and no account,
        // and resolves to the folder's.
        assert_eq!(
            resolved(&state, &web01.id, "port").as_deref(),
            Some("13389"),
            "web-01 did not inherit the folder's port"
        );
        assert_eq!(
            resolved(&state, &web01.id, "username").as_deref(),
            Some("svc-deploy"),
            "web-01 did not inherit the folder's account"
        );

        // The settings the model has no field for came across rather than
        // being dropped, and the `Inherit*` flags did not become data. Read
        // from the vault's own tree: no command exposes `custom_fields` yet, so
        // this asserts what was written rather than what is drawn.
        let Ok(custom) = node_custom_fields(&state, &dc01.id) else {
            panic!("the vault closed");
        };
        assert_eq!(
            custom.get("mremoteng.Colors").map(String::as_str),
            Some("Colors16Bit"),
            "mRemoteNG's own settings were dropped: {custom:#?}"
        );
        assert!(
            custom.keys().all(|key| !key.contains("Inherit")),
            "an inheritance flag was stored as a setting: {custom:#?}"
        );
        let Ok(inheriting) = node_custom_fields(&state, &web01.id) else {
            panic!("the vault closed");
        };
        assert!(
            !inheriting.contains_key("mremoteng.Colors"),
            "a value web-01 inherits was flattened onto it: {inheriting:#?}"
        );
        // What it does not inherit, it keeps: the flags decide, not the
        // presence of the attribute — mRemoteNG writes every attribute on
        // every node whether or not the node owns its value.
        assert_eq!(
            inheriting.get("mremoteng.PuttySession").map(String::as_str),
            Some("Default Settings")
        );

        // The recovered password is in the vault, sealed, and readable. This is
        // the whole point of the import: not that a credential row exists, but
        // that the password out of the file is the password behind it.
        let Ok(uuid) = Uuid::parse_str(&admin.id) else {
            panic!("the credential id is not a uuid");
        };
        let mut guard = state.lock();
        let Ok(vault) = guard.vault_mut() else {
            panic!("the vault closed");
        };
        let Ok(secret) = vault.borrow_secret(uuid, PASSWORD_FIELD, remoter_vault::Purpose::Reveal)
        else {
            panic!("the administrator's password did not reach the vault");
        };
        assert_eq!(
            secret.expose_secret().as_slice(),
            b"Tr0ub4dor&3",
            "the password in the vault is not the one in the file"
        );
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "an import test without a vault has nothing left to assert"
    )]
    fn a_file_the_owner_put_a_password_on_says_so_before_it_fails() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let file = scratch.write(
            "confCons.xml",
            &confcons(PROTECTED_CUSTOM, CUSTOM_SVC_PASSWORD, CUSTOM_SVC_PASSWORD),
        );
        let path = file.display().to_string();

        // Detection says a password is wanted, which is what puts the field on
        // the screen — before the parse, not after it.
        let Ok(detected) = import_detect_impl(path.clone()) else {
            panic!("detecting failed");
        };
        assert_eq!(detected.format.as_deref(), Some("mremoteng"));
        assert!(
            detected.password_required,
            "a file with an owner's password must ask for one"
        );

        // Parsing without it is refused as "we need one", not "yours is wrong".
        let refused = import_parse_impl(&state, path.clone(), None, None);
        assert!(
            refused.is_err_and(|err| err.code == "import.password-required"),
            "a missing password must be told apart from a wrong one"
        );
        let wrong = import_parse_impl(&state, path.clone(), Some("nope".to_owned()), None);
        assert!(wrong.is_err_and(|err| err.code == "import.wrong-password"));

        // And with it, the same file imports.
        let preview = import_parse_impl(&state, path, Some("correct horse".to_owned()), None);
        assert!(preview.is_ok(), "parsing failed: {}", why(&preview));
        let Ok(preview) = preview else {
            panic!("parsing failed");
        };
        assert_eq!(preview.report.counts.connections, 3);
        // A file the owner protected is not on the published default, so the
        // report must not accuse it of being.
        assert!(
            !serde_json::to_string(&preview.report)
                .unwrap_or_default()
                .contains("DefaultFilePassword"),
            "a protected file was reported as unprotected"
        );
    }

    /// The three shapes a `confCons.xml` arrives in that are not the tool's own
    /// output, and one file that is not a `confCons.xml` at all.
    #[test]
    fn the_shapes_a_file_arrives_in_are_all_the_same_file() {
        let scratch = Scratch::new();
        let document = confcons(PROTECTED_DEFAULT, SVC_PASSWORD, ADMIN_PASSWORD);

        // Without the byte-order mark and with Unix line endings, as a file
        // that has been through a text editor on Linux.
        let stripped = document
            .trim_start_matches('\u{feff}')
            .replace("\r\n", "\n");
        let plain = scratch.write("plain.xml", &stripped);
        assert_eq!(
            import_detect_impl(plain.display().to_string())
                .ok()
                .and_then(|detected| detected.format),
            Some("mremoteng".to_owned())
        );

        // UTF-16, which is what a `>` redirect in Windows PowerShell 5 makes of
        // it. mRemoteNG writes UTF-8; the file does not always arrive the way
        // mRemoteNG wrote it.
        let mut utf16 = vec![0xff, 0xfe];
        for unit in stripped.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let wide = scratch.join("wide.xml");
        let _ = fs::write(&wide, &utf16);
        assert_eq!(
            import_detect_impl(wide.display().to_string())
                .ok()
                .and_then(|detected| detected.format),
            Some("mremoteng".to_owned()),
            "a UTF-16 confCons.xml was not recognised"
        );

        // An empty tree is a file, not a failure.
        let empty = scratch.write(
            "empty.xml",
            &format!(
                "<mrng:Connections xmlns:mrng=\"http://mremoteng.org\" Name=\"Connections\" \
                 EncryptionEngine=\"AES\" BlockCipherMode=\"GCM\" KdfIterations=\"1000\" \
                 Protected=\"{PROTECTED_DEFAULT}\" ConfVersion=\"2.7\" />"
            ),
        );
        let detected = import_detect_impl(empty.display().to_string());
        assert!(detected.is_ok(), "detecting failed: {}", why(&detected));
        assert_eq!(
            detected.ok().and_then(|detected| detected.format),
            Some("mremoteng".to_owned())
        );

        // And a file that is not one says so rather than being parsed as one.
        let other = scratch.write(
            "royal.rtsz",
            r#"<?xml version="1.0"?><RoyalDocument><Objects/></RoyalDocument>"#,
        );
        let detected = import_detect_impl(other.display().to_string());
        assert!(
            detected.is_ok_and(|detected| detected.format.is_none()),
            "a Royal TS document was taken for an mRemoteNG one"
        );
    }
}
