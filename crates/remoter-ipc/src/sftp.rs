//! The file manager's command surface.
//!
//! `docs/architecture/sftp-command-surface.md` specifies this; the engine it
//! sits on is `remoter_proto_ssh::sftp`, which was finished and tested long
//! before anything a user could click reached it. This module is the seam that
//! was missing, and it is only a seam: it maps DTOs, bounds what the interface
//! may ask for, and forwards. What a resume is safe on, what a listing cap is
//! and how a path is joined are all decided one layer down, and none of those
//! decisions is repeated here.
//!
//! Three rules shape everything below.
//!
//! **A pane belongs to a session, not to a node.** `SftpBrowser::open` takes
//! the `Arc<SshConnection>` a tab is already using and opens one more channel
//! on it (RFC 4254 §6.5), so a file pane on a host with a shell costs a channel
//! rather than a handshake, a host key check and an authentication. Opening a
//! file manager on a node with nothing open runs the ordinary pipeline first —
//! `session_open` on an `sftp` connection — so the session appears in the
//! session list, counts against the cap, and is closed by the same supervisor
//! as everything else. There is no second lifetime to get wrong.
//!
//! **Progress is pushed, never polled.** A transfer reports every
//! `PROGRESS_INTERVAL_BYTES` through the session's own `EventSink`, so it
//! arrives on the channel the tab already subscribes to as
//! `SessionMessageDto::Progress`. [`sftp_transfers`] exists for the first paint
//! and for reconciliation after a tab switch, not to drive a bar.
//!
//! **Everything the server said is untrusted text.** A name may hold a path
//! separator, a control byte or a right-to-left override; the first turns a
//! click into a write somewhere else, and the other two make a file look like
//! something it is not. Every DTO below therefore carries two forms — the raw
//! string, which is what goes back on the wire, and the escaped one, which is
//! what a human reads. They are never interchanged.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use remoter_proto::ProtocolError;
use remoter_proto_ssh::SftpBrowser;
use remoter_proto_ssh::sftp::{
    DeleteReport, DirectoryEntry, EntryKind, MAX_DIRECTORY_BYTES, MAX_DIRECTORY_ENTRIES, NameRisks,
    TransferDirection, TransferId, TransferQueue, TransferRequest, TransferStart, TransferState,
    TransferStatus, escape_untrusted, local_name_for, run_queue, safe_name, validate_remote_path,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::IpcError;
use crate::session::{SessionFailureDto, action_text, ipc_error};
use crate::state::AppState;

/// How many transfers one pane runs at once.
///
/// More than one because a transfer on a high-latency link spends most of its
/// time waiting for acknowledgements, and a queue of small files would
/// otherwise move at one round trip each. Not many more because every
/// concurrent transfer is another open file on the server, another buffer here,
/// and another writer competing for the same channel window.
const TRANSFER_CONCURRENCY: usize = 2;

/// How long a pane's transfer task has to stop before it is aborted.
///
/// The same policy the session supervisor applies, for the same reason: a task
/// that outlives the thing that owns it is holding a file handle and a channel
/// on a connection nobody is watching.
const PANE_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// The largest POSIX mode the interface may set: the permission bits, plus
/// set-user-id, set-group-id and sticky.
const MAX_MODE: u32 = 0o7777;

// ==================================================================== DTOs ==

/// A file pane, once it is attached to a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpPaneDto {
    pub pane_id: u64,
    /// The session it runs on. Closing that session closes this pane.
    pub session_id: u64,
    /// The server's idea of where the user starts, canonicalised. Raw.
    pub home: String,
    /// The same, escaped for display.
    pub home_display: String,
}

/// What is wrong with a name the far end chose.
///
/// None of these hides the row. A file called `report\u{202E}fdp.exe` exists
/// and the user may well want it; what they may not have is a listing that
/// renders it as `reportexe.pdf` without saying so.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NameRisksDto {
    /// Holds a control character. Truncates a log line; in a terminal, rewrites
    /// what was already printed.
    pub control: bool,
    /// Holds a bidirectional override — the Trojan Source trick
    /// (CVE-2021-42574) applied to a file listing.
    pub bidi: bool,
    /// Holds a zero-width character, so two rows can look identical and be
    /// different files.
    pub invisible: bool,
    /// Is not a single path component. The server is trying to make a click on
    /// this row touch something outside the directory being listed, and this
    /// layer refuses to build a path from it.
    pub separator: bool,
}

impl NameRisksDto {
    /// Whether the name is exactly what it appears to be.
    #[must_use]
    pub const fn clean(&self) -> bool {
        !self.control && !self.bidi && !self.invisible && !self.separator
    }
}

/// One row of the remote pane.
///
/// **Every string in this is server-supplied.** The interface renders `name`
/// and `path` never — it renders `displayName` and `displayPath`, as text, and
/// never through `dangerouslySetInnerHTML` (CLAUDE.md §6). A file called
/// `<img src=x onerror=…>` is a legal file name.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryEntryDto {
    /// The name as the server sent it. This is what goes back on the wire.
    pub name: String,
    /// The name with everything that could lie about it escaped.
    pub display_name: String,
    /// The full path, as the server would take it back.
    pub path: String,
    /// The same, escaped.
    pub display_path: String,
    /// `"file" | "directory" | "symlink" | "other"`.
    pub kind: String,
    /// Size in bytes, where the server reported one.
    pub size: Option<u64>,
    /// The POSIX mode bits, where the server reported them.
    pub permissions: Option<u32>,
    /// The same as `drwxr-xr-x`, so every pane renders them identically.
    pub mode: Option<String>,
    pub uid: Option<u32>,
    /// The owning user's name, escaped: it is server-supplied text too.
    pub user: Option<String>,
    pub gid: Option<u32>,
    /// The owning group's name, escaped.
    pub group: Option<String>,
    /// Last modification, in seconds since the Unix epoch.
    pub modified: Option<u32>,
    /// What was found wrong with the name.
    pub risks: NameRisksDto,
}

/// One thing a removal could not remove.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpDeleteFailureDto {
    /// Where it was, escaped for display.
    pub path: String,
    /// The stable code from the failure taxonomy.
    pub code: String,
    /// The sentence the user reads.
    pub message: String,
}

/// What a removal actually did.
///
/// A file manager that says "done" after removing nine of twelve files has
/// lied, so this reports rather than returning nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpDeleteReportDto {
    pub files_removed: u64,
    pub directories_removed: u64,
    pub failures: Vec<SftpDeleteFailureDto>,
    /// True if the user stopped it part way through.
    pub cancelled: bool,
    /// True if it stopped at the walk's own limit rather than at the end.
    pub limit_reached: bool,
    /// True only when everything asked for is gone.
    pub complete: bool,
}

/// A transfer the interface is asking for.
///
/// A download names its destination one of two ways, and exactly one:
/// `local` is a file path a save-as picker produced, and `localDirectory` is a
/// folder, in which case the file name is derived from the remote path by
/// `local_name_for` — the function that keeps a server-chosen name from
/// choosing a local path. An upload always names `local`, the file to send.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferRequestDto {
    /// `"upload" | "download"`.
    pub direction: String,
    /// The remote path, `/`-separated whatever the server runs on.
    pub remote: String,
    /// A local file path.
    #[serde(default)]
    pub local: Option<String>,
    /// A local folder to save into. Downloads only.
    #[serde(default)]
    pub local_directory: Option<String>,
    /// Whether to continue an interrupted transfer rather than start over.
    /// Honoured only where it is safe; see [`TransferStartDto`].
    #[serde(default)]
    pub resume: bool,
}

/// What a transfer decided before it moved a byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferStartDto {
    pub resume_requested: bool,
    /// Where it began. Zero unless a resume was honoured.
    pub resume_from: u64,
    /// The source's size, where the source reported one.
    pub total: Option<u64>,
    /// True when a resume was asked for and refused.
    pub resume_declined: bool,
    /// Why it was refused, in a sentence. Present only when it was.
    pub note: Option<String>,
}

/// Where a transfer has got to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TransferStateDto {
    /// Waiting for a slot.
    Queued,
    /// Moving bytes. `done` counts from the start of the file, not from the
    /// start of this attempt, so a resumed bar does not jump back to zero.
    Running { done: u64, total: Option<u64> },
    /// Finished.
    Completed { bytes: u64 },
    /// Failed, with everything the tab shows.
    Failed(SessionFailureDto),
    /// Stopped by the user. Whatever was written stays on disk, which is what
    /// makes a later resume possible.
    Cancelled,
}

/// One row of the transfer list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferStatusDto {
    pub transfer_id: u64,
    /// `"upload" | "download"`.
    pub direction: String,
    /// The remote path, raw.
    pub remote: String,
    /// The same, escaped for display.
    pub remote_display: String,
    /// The local path, as resolved when it was queued.
    pub local: String,
    pub resume: bool,
    pub state: TransferStateDto,
    /// What it settled before it began. `None` until it does.
    pub start: Option<TransferStartDto>,
}

// =============================================================== the pane ==

/// A file pane: a browser, its queue, and the task that drains it.
pub(crate) struct PaneEntry {
    session_id: u64,
    browser: Arc<SftpBrowser>,
    queue: Arc<TransferQueue>,
    /// Cancels the whole pane — the drain tasks, the listing in flight and any
    /// recursive delete. A **child** of the session's token, so closing the tab
    /// closes the pane without this layer walking a registry to find it.
    cancel: CancellationToken,
    /// One waker per drain task. `Notify::notify_one` leaves a permit when
    /// nobody is waiting, so work queued while a task is between transfers is
    /// never lost.
    wakers: Vec<Arc<Notify>>,
    drains: Mutex<Vec<JoinHandle<()>>>,
    /// The listing in flight. Replaced — and cancelled — when the next one
    /// starts, which is what "the pane cancels a listing when the user
    /// navigates away" means in practice: `readdir` runs until the server says
    /// it is done, and a server can decline to.
    listing: Mutex<Option<CancellationToken>>,
}

impl PaneEntry {
    /// The session this pane runs on.
    pub(crate) const fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Stops everything this pane started, and waits for it.
    ///
    /// Awaited rather than merely cancelled: "the pane is closed" and "nothing
    /// is still writing to disk" must be the same moment. A task that overruns
    /// its grace is aborted and logged as the defect it is — a lingering task
    /// holds a file handle and a channel on the user's connection.
    pub(crate) async fn stop(self) {
        self.cancel.cancel();
        let drains = {
            let mut guard = self.drains.lock();
            std::mem::take(&mut *guard)
        };
        for mut handle in drains {
            if tokio::time::timeout(PANE_SHUTDOWN_GRACE, &mut handle)
                .await
                .is_err()
            {
                handle.abort();
                tracing::error!(
                    session = self.session_id,
                    "a file pane's transfer task did not stop within its grace period and was \
                     aborted; this is a defect worth reporting"
                );
            }
        }
    }

    /// Cancels the listing in flight and hands out a token for the next one.
    fn begin_listing(&self) -> CancellationToken {
        let token = self.cancel.child_token();
        let previous = self.listing.lock().replace(token.clone());
        if let Some(previous) = previous {
            previous.cancel();
        }
        token
    }

    fn wake(&self) {
        for waker in &self.wakers {
            waker.notify_one();
        }
    }
}

impl std::fmt::Debug for PaneEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaneEntry")
            .field("session", &self.session_id)
            .field("queued", &self.queue.list().len())
            .finish()
    }
}

/// Drains one pane's queue for as long as the pane is open.
///
/// `run_queue` returns when there is nothing left to do, so the loop waits to
/// be woken rather than spinning. The session's token reaches the transfer that
/// is *already moving*, not merely the next one to start — which is the
/// requirement most easily got wrong, and the reason a closed tab does not
/// leave a 40 GB download writing to disk.
async fn drive_queue(
    browser: Arc<SftpBrowser>,
    queue: Arc<TransferQueue>,
    events: remoter_proto::EventSink,
    waker: Arc<Notify>,
    cancel: CancellationToken,
) {
    loop {
        run_queue(&browser, &queue, Some(&events), &cancel).await;
        if cancel.is_cancelled() {
            return;
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            () = waker.notified() => {}
        }
    }
}

// ============================================================== commands ===

/// Opens a file pane on a session that is already connected.
///
/// No handshake, no host key check and no authentication: this is one more
/// channel on the connection the tab is using. Which is why the command takes a
/// session and not a node — a file manager on a host with a shell should cost a
/// channel.
#[tauri::command]
pub(crate) async fn sftp_open(
    state: State<'_, AppState>,
    session_id: u64,
) -> Result<SftpPaneDto, IpcError> {
    sftp_open_impl(&state, session_id).await
}

pub(crate) async fn sftp_open_impl(
    state: &AppState,
    session_id: u64,
) -> Result<SftpPaneDto, IpcError> {
    let hub = state.sessions();
    let (connection, events, cancel) = hub.attach_parts(session_id).ok_or_else(|| {
        IpcError::new(
            "sftp.session-not-ready",
            "That session is not connected, so there is nothing to browse on it yet. A file pane \
             opens on a connection that has already authenticated.",
        )
        .with_actions(["Wait for it to connect", "Open the connection again"])
    })?;

    let browser = SftpBrowser::open(connection)
        .await
        .map_err(|err| subsystem_error(&err))?;
    let browser = Arc::new(browser);

    // Where the user starts. `.` is what every SFTP client asks for, and the
    // server answers with the absolute path it means by it.
    let home = browser
        .canonicalize(".")
        .await
        .map_err(|err| ipc_error(&err))?;

    let queue = Arc::new(TransferQueue::new(TRANSFER_CONCURRENCY));
    let mut wakers = Vec::with_capacity(TRANSFER_CONCURRENCY);
    let mut drains = Vec::with_capacity(TRANSFER_CONCURRENCY);
    for _ in 0..TRANSFER_CONCURRENCY {
        let waker = Arc::new(Notify::new());
        wakers.push(Arc::clone(&waker));
        drains.push(tokio::spawn(drive_queue(
            Arc::clone(&browser),
            Arc::clone(&queue),
            events.clone(),
            waker,
            cancel.clone(),
        )));
    }

    let pane_id = hub.next_pane_id();
    let entry = PaneEntry {
        session_id,
        browser,
        queue,
        cancel,
        wakers,
        drains: Mutex::new(drains),
        listing: Mutex::new(None),
    };
    hub.panes.lock().insert(pane_id, entry);

    Ok(SftpPaneDto {
        pane_id,
        session_id,
        home_display: escape_untrusted(&home),
        home,
    })
}

/// Closes a file pane, and waits for it to let go.
///
/// Returns only once the drain task has finished, so "the pane is closed" and
/// "nothing is still writing to disk" are the same moment.
#[tauri::command]
pub(crate) async fn sftp_close(state: State<'_, AppState>, pane_id: u64) -> Result<(), IpcError> {
    sftp_close_impl(&state, pane_id).await
}

pub(crate) async fn sftp_close_impl(state: &AppState, pane_id: u64) -> Result<(), IpcError> {
    let entry = state
        .sessions()
        .panes
        .lock()
        .remove(&pane_id)
        .ok_or_else(no_such_pane)?;
    entry.stop().await;
    Ok(())
}

/// Lists a directory.
///
/// Cancels whatever this pane was listing before: `readdir` runs until the
/// server says it is finished and a server can decline to, so six clicks
/// through six directories would otherwise leave six listings accumulating
/// against six caps.
#[tauri::command]
pub(crate) async fn sftp_list(
    state: State<'_, AppState>,
    pane_id: u64,
    path: String,
) -> Result<Vec<DirectoryEntryDto>, IpcError> {
    sftp_list_impl(&state, pane_id, path).await
}

pub(crate) async fn sftp_list_impl(
    state: &AppState,
    pane_id: u64,
    path: String,
) -> Result<Vec<DirectoryEntryDto>, IpcError> {
    validate_remote_path(&path).map_err(|err| ipc_error(&err))?;
    let (browser, cancel) = {
        let hub = state.sessions();
        let panes = hub.panes.lock();
        let pane = panes.get(&pane_id).ok_or_else(no_such_pane)?;
        (Arc::clone(&pane.browser), pane.begin_listing())
    };

    let entries = browser
        .list(&path, &cancel)
        .await
        .map_err(|err| listing_error(&err, &path))?;
    Ok(entries.iter().map(entry_dto).collect())
}

/// Reads one entry's metadata, following symbolic links.
#[tauri::command]
pub(crate) async fn sftp_stat(
    state: State<'_, AppState>,
    pane_id: u64,
    path: String,
) -> Result<DirectoryEntryDto, IpcError> {
    sftp_stat_impl(&state, pane_id, path).await
}

pub(crate) async fn sftp_stat_impl(
    state: &AppState,
    pane_id: u64,
    path: String,
) -> Result<DirectoryEntryDto, IpcError> {
    let browser = browser_for(state, pane_id, &path)?;
    let entry = browser
        .metadata(&path)
        .await
        .map_err(|err| ipc_error(&err))?;
    Ok(entry_dto(&entry))
}

/// Resolves a path to the absolute one the server means by it.
#[tauri::command]
pub(crate) async fn sftp_canonicalize(
    state: State<'_, AppState>,
    pane_id: u64,
    path: String,
) -> Result<String, IpcError> {
    sftp_canonicalize_impl(&state, pane_id, path).await
}

pub(crate) async fn sftp_canonicalize_impl(
    state: &AppState,
    pane_id: u64,
    path: String,
) -> Result<String, IpcError> {
    let browser = browser_for(state, pane_id, &path)?;
    browser
        .canonicalize(&path)
        .await
        .map_err(|err| ipc_error(&err))
}

/// Reads where a symbolic link points, without following it.
#[tauri::command]
pub(crate) async fn sftp_read_link(
    state: State<'_, AppState>,
    pane_id: u64,
    path: String,
) -> Result<String, IpcError> {
    sftp_read_link_impl(&state, pane_id, path).await
}

pub(crate) async fn sftp_read_link_impl(
    state: &AppState,
    pane_id: u64,
    path: String,
) -> Result<String, IpcError> {
    let browser = browser_for(state, pane_id, &path)?;
    browser
        .read_link(&path)
        .await
        .map_err(|err| ipc_error(&err))
}

/// Creates a directory.
#[tauri::command]
pub(crate) async fn sftp_mkdir(
    state: State<'_, AppState>,
    pane_id: u64,
    path: String,
) -> Result<(), IpcError> {
    sftp_mkdir_impl(&state, pane_id, path).await
}

pub(crate) async fn sftp_mkdir_impl(
    state: &AppState,
    pane_id: u64,
    path: String,
) -> Result<(), IpcError> {
    let browser = browser_for(state, pane_id, &path)?;
    browser
        .make_directory(&path)
        .await
        .map_err(|err| ipc_error(&err))
}

/// Renames or moves an entry.
#[tauri::command]
pub(crate) async fn sftp_rename(
    state: State<'_, AppState>,
    pane_id: u64,
    from: String,
    to: String,
) -> Result<(), IpcError> {
    sftp_rename_impl(&state, pane_id, from, to).await
}

pub(crate) async fn sftp_rename_impl(
    state: &AppState,
    pane_id: u64,
    from: String,
    to: String,
) -> Result<(), IpcError> {
    validate_remote_path(&to).map_err(|err| ipc_error(&err))?;
    let browser = browser_for(state, pane_id, &from)?;
    browser
        .rename(&from, &to)
        .await
        .map_err(|err| rename_error(&err, &from, &to))
}

/// Removes an entry, or a whole tree.
///
/// `SSH_FXP_RMDIR` fails on a non-empty directory, so a recursive removal is a
/// walk — and a walk that is interrupted leaves the tree half-removed. Hence a
/// report rather than nothing.
#[tauri::command]
pub(crate) async fn sftp_delete(
    state: State<'_, AppState>,
    pane_id: u64,
    path: String,
    recursive: bool,
) -> Result<SftpDeleteReportDto, IpcError> {
    sftp_delete_impl(&state, pane_id, path, recursive).await
}

pub(crate) async fn sftp_delete_impl(
    state: &AppState,
    pane_id: u64,
    path: String,
    recursive: bool,
) -> Result<SftpDeleteReportDto, IpcError> {
    validate_remote_path(&path).map_err(|err| ipc_error(&err))?;
    let (browser, cancel) = {
        let hub = state.sessions();
        let panes = hub.panes.lock();
        let pane = panes.get(&pane_id).ok_or_else(no_such_pane)?;
        (Arc::clone(&pane.browser), pane.cancel.child_token())
    };

    if recursive {
        let report = browser
            .remove_tree(&path, &cancel)
            .await
            .map_err(|err| ipc_error(&err))?;
        return Ok(delete_report_dto(&report));
    }

    // Not recursive: which of the two calls to make depends on what it is, and
    // `symlink_metadata` is what decides — a link *to* a directory is a link,
    // and `SSH_FXP_RMDIR` on it would fail with something the user cannot act
    // on.
    let entry = browser
        .symlink_metadata(&path)
        .await
        .map_err(|err| ipc_error(&err))?;
    let outcome = if entry.kind == EntryKind::Directory {
        browser.remove_directory(&path).await
    } else {
        browser.remove_file(&path).await
    };

    match outcome {
        Ok(()) => Ok(SftpDeleteReportDto {
            files_removed: u64::from(entry.kind != EntryKind::Directory),
            directories_removed: u64::from(entry.kind == EntryKind::Directory),
            failures: Vec::new(),
            cancelled: false,
            limit_reached: false,
            complete: true,
        }),
        Err(error) if entry.kind == EntryKind::Directory => {
            // The one failure worth its own sentence: §6.11 says a directory
            // must be empty, and "the SFTP server reported a failure" sends a
            // user looking for a permission problem they do not have.
            Err(IpcError::new(
                "sftp.directory-not-empty",
                format!(
                    "`{}` was not removed. A directory has to be empty before it can be removed, \
                     and this one may not be.",
                    escape_untrusted(&path)
                ),
            )
            .with_detail(format!("{error}"))
            .with_actions(["Delete its contents too", "Open it and look"]))
        }
        Err(error) => Err(ipc_error(&error)),
    }
}

/// Changes an entry's POSIX mode bits.
#[tauri::command]
pub(crate) async fn sftp_set_permissions(
    state: State<'_, AppState>,
    pane_id: u64,
    path: String,
    mode: u32,
) -> Result<(), IpcError> {
    sftp_set_permissions_impl(&state, pane_id, path, mode).await
}

pub(crate) async fn sftp_set_permissions_impl(
    state: &AppState,
    pane_id: u64,
    path: String,
    mode: u32,
) -> Result<(), IpcError> {
    if mode > MAX_MODE {
        return Err(IpcError::invalid_request(
            "mode",
            "a POSIX mode is at most 07777 — the permission bits plus set-user-id, set-group-id \
             and sticky",
        ));
    }
    let browser = browser_for(state, pane_id, &path)?;
    browser
        .set_permissions(&path, mode)
        .await
        .map_err(|err| ipc_error(&err))
}

/// Creates a symbolic link at `path` pointing at `target`.
#[tauri::command]
pub(crate) async fn sftp_symlink(
    state: State<'_, AppState>,
    pane_id: u64,
    path: String,
    target: String,
) -> Result<(), IpcError> {
    sftp_symlink_impl(&state, pane_id, path, target).await
}

pub(crate) async fn sftp_symlink_impl(
    state: &AppState,
    pane_id: u64,
    path: String,
    target: String,
) -> Result<(), IpcError> {
    validate_remote_path(&target).map_err(|err| ipc_error(&err))?;
    let browser = browser_for(state, pane_id, &path)?;
    browser
        .symlink(&path, &target)
        .await
        .map_err(|err| ipc_error(&err))
}

/// Queues transfers.
///
/// Returns the new ids in the order the requests were given. The queue drains
/// itself; nothing here waits for a byte to move.
#[tauri::command]
pub(crate) fn sftp_enqueue(
    state: State<'_, AppState>,
    pane_id: u64,
    requests: Vec<TransferRequestDto>,
) -> Result<Vec<u64>, IpcError> {
    sftp_enqueue_impl(&state, pane_id, requests)
}

pub(crate) fn sftp_enqueue_impl(
    state: &AppState,
    pane_id: u64,
    requests: Vec<TransferRequestDto>,
) -> Result<Vec<u64>, IpcError> {
    // Every request is resolved before any is queued: a batch of forty with a
    // bad one in the middle should refuse as a batch rather than start twenty
    // and then complain.
    let resolved = requests
        .iter()
        .map(resolve_request)
        .collect::<Result<Vec<_>, _>>()?;

    let hub = state.sessions();
    let panes = hub.panes.lock();
    let pane = panes.get(&pane_id).ok_or_else(no_such_pane)?;
    let ids = resolved
        .into_iter()
        .map(|request| pane.queue.enqueue(request).get())
        .collect();
    pane.wake();
    Ok(ids)
}

/// Every transfer this pane knows about, in the order they were queued.
///
/// For the first paint and for reconciliation after a tab switch. **Not** for
/// driving a progress bar: progress is pushed over the session's channel.
#[tauri::command]
pub(crate) fn sftp_transfers(
    state: State<'_, AppState>,
    pane_id: u64,
) -> Result<Vec<TransferStatusDto>, IpcError> {
    sftp_transfers_impl(&state, pane_id)
}

pub(crate) fn sftp_transfers_impl(
    state: &AppState,
    pane_id: u64,
) -> Result<Vec<TransferStatusDto>, IpcError> {
    let hub = state.sessions();
    let panes = hub.panes.lock();
    let pane = panes.get(&pane_id).ok_or_else(no_such_pane)?;
    Ok(pane.queue.list().iter().map(transfer_dto).collect())
}

/// Stops one transfer.
///
/// A queued one never starts; a running one stops where it is, and what has
/// been written stays on disk — which is what makes a later resume possible.
#[tauri::command]
pub(crate) fn sftp_transfer_cancel(
    state: State<'_, AppState>,
    pane_id: u64,
    transfer_id: u64,
) -> Result<(), IpcError> {
    sftp_transfer_cancel_impl(&state, pane_id, transfer_id)
}

pub(crate) fn sftp_transfer_cancel_impl(
    state: &AppState,
    pane_id: u64,
    transfer_id: u64,
) -> Result<(), IpcError> {
    let hub = state.sessions();
    let panes = hub.panes.lock();
    let pane = panes.get(&pane_id).ok_or_else(no_such_pane)?;
    let id = TransferId::from_raw(transfer_id);
    if pane.queue.status(id).is_none() {
        return Err(no_such_transfer());
    }
    pane.queue.cancel(id);
    // The slot it was holding is free now, so whatever is behind it may start.
    pane.wake();
    Ok(())
}

/// Stops every transfer on this pane.
#[tauri::command]
pub(crate) fn sftp_transfer_cancel_all(
    state: State<'_, AppState>,
    pane_id: u64,
) -> Result<(), IpcError> {
    sftp_transfer_cancel_all_impl(&state, pane_id)
}

pub(crate) fn sftp_transfer_cancel_all_impl(
    state: &AppState,
    pane_id: u64,
) -> Result<(), IpcError> {
    let hub = state.sessions();
    let panes = hub.panes.lock();
    let pane = panes.get(&pane_id).ok_or_else(no_such_pane)?;
    pane.queue.cancel_all();
    Ok(())
}

/// Queues a fresh transfer from a finished one's request.
///
/// It does not resurrect the old entry: a terminal state stays terminal, so the
/// history of what happened stays readable.
#[tauri::command]
pub(crate) fn sftp_transfer_retry(
    state: State<'_, AppState>,
    pane_id: u64,
    transfer_id: u64,
) -> Result<u64, IpcError> {
    sftp_transfer_retry_impl(&state, pane_id, transfer_id)
}

pub(crate) fn sftp_transfer_retry_impl(
    state: &AppState,
    pane_id: u64,
    transfer_id: u64,
) -> Result<u64, IpcError> {
    let hub = state.sessions();
    let panes = hub.panes.lock();
    let pane = panes.get(&pane_id).ok_or_else(no_such_pane)?;
    let id = TransferId::from_raw(transfer_id);
    if pane.queue.status(id).is_none() {
        return Err(no_such_transfer());
    }
    let retried = pane.queue.retry(id).ok_or_else(|| {
        IpcError::new(
            "sftp.transfer-running",
            "That transfer has not finished, so there is nothing to retry about it yet.",
        )
        .with_actions(["Stop it first", "Wait for it to finish"])
    })?;
    pane.wake();
    Ok(retried.get())
}

// ================================================================ mapping ===

/// The display form of anything the far end chose the text of.
///
/// Used by the session layer for a progress event's `detail`, which is a remote
/// path and therefore the one field in `ProgressUpdate` an attacker picks.
pub(crate) fn escape_remote_text(text: &str) -> String {
    escape_untrusted(text)
}

fn entry_dto(entry: &DirectoryEntry) -> DirectoryEntryDto {
    let safe = safe_name(&entry.name);
    DirectoryEntryDto {
        display_name: safe.display,
        name: entry.name.clone(),
        display_path: escape_untrusted(&entry.path),
        path: entry.path.clone(),
        kind: entry.kind.as_str().to_owned(),
        size: entry.size,
        permissions: entry.permissions,
        mode: entry.mode_string(),
        uid: entry.uid,
        // Escaped like a name: `user` and `group` are strings the server
        // composed, and a listing is where they are read.
        user: entry.user.as_deref().map(escape_untrusted),
        gid: entry.gid,
        group: entry.group.as_deref().map(escape_untrusted),
        modified: entry.modified,
        risks: risks_dto(safe.risks),
    }
}

const fn risks_dto(risks: NameRisks) -> NameRisksDto {
    NameRisksDto {
        control: risks.control,
        bidi: risks.bidi,
        invisible: risks.invisible,
        separator: risks.separator,
    }
}

fn delete_report_dto(report: &DeleteReport) -> SftpDeleteReportDto {
    SftpDeleteReportDto {
        files_removed: report.files_removed,
        directories_removed: report.directories_removed,
        failures: report
            .failures
            .iter()
            .map(|failure| {
                let mapped = ipc_error(&failure.reason);
                SftpDeleteFailureDto {
                    path: escape_untrusted(&failure.path),
                    code: mapped.code,
                    message: mapped.message,
                }
            })
            .collect(),
        cancelled: report.cancelled,
        limit_reached: report.limit_reached,
        complete: report.is_complete(),
    }
}

fn transfer_dto(status: &TransferStatus) -> TransferStatusDto {
    TransferStatusDto {
        transfer_id: status.id.get(),
        direction: direction_wire(status.request.direction).to_owned(),
        remote_display: escape_untrusted(&status.request.remote),
        remote: status.request.remote.clone(),
        local: status.request.local.display().to_string(),
        resume: status.request.resume,
        state: state_dto(&status.state),
        start: status
            .start
            .map(|start| start_dto(start, status.request.direction)),
    }
}

const fn direction_wire(direction: TransferDirection) -> &'static str {
    match direction {
        TransferDirection::Upload => "upload",
        TransferDirection::Download => "download",
    }
}

fn state_dto(state: &TransferState) -> TransferStateDto {
    match state {
        TransferState::Queued => TransferStateDto::Queued,
        TransferState::Running { done, total } => TransferStateDto::Running {
            done: *done,
            total: *total,
        },
        TransferState::Completed { bytes } => TransferStateDto::Completed { bytes: *bytes },
        TransferState::Cancelled => TransferStateDto::Cancelled,
        TransferState::Failed(report) => TransferStateDto::Failed(SessionFailureDto {
            code: String::from("sftp.transfer-failed"),
            message: report.message.clone(),
            detail: None,
            actions: report
                .next_actions
                .iter()
                .copied()
                .map(action_text)
                .collect(),
            stage: report.stage.as_str().to_owned(),
            retryable: report.retryable,
        }),
    }
}

fn start_dto(start: TransferStart, direction: TransferDirection) -> TransferStartDto {
    // Said outright, because `resume_offset` refuses more often than a user
    // expects and a bar that quietly restarted would be a bar that lied. There
    // is deliberately no setting that overrides the refusal: appending to the
    // wrong file corrupts it silently, and re-copying one costs time.
    let note = start.resume_declined().then(|| {
        let (source, destination) = match direction {
            TransferDirection::Download => ("remote", "local"),
            TransferDirection::Upload => ("local", "remote"),
        };
        start.total.map_or_else(
            || {
                format!(
                    "Starting from the beginning: the {source} file's size is unknown, so no \
                     offset could be justified."
                )
            },
            |_| {
                format!(
                    "Starting from the beginning: the {destination} file is not shorter than the \
                     {source} one, so continuing it could have corrupted it."
                )
            },
        )
    });
    TransferStartDto {
        resume_requested: start.resume_requested,
        resume_from: start.resume_from,
        total: start.total,
        resume_declined: start.resume_declined(),
        note,
    }
}

/// Turns one request into the engine's shape, deciding the local path.
///
/// The rule that matters: **a remote name never chooses a local path.** Where
/// the destination is a folder, only the last component of the remote path is
/// kept and anything that still looks like a traversal is refused, because a
/// file manager that writes where the server told it to is a file manager that
/// can be told to overwrite `~/.ssh/authorized_keys`.
fn resolve_request(request: &TransferRequestDto) -> Result<TransferRequest, IpcError> {
    let direction = match request.direction.as_str() {
        "upload" => TransferDirection::Upload,
        "download" => TransferDirection::Download,
        other => {
            return Err(IpcError::invalid_request(
                "direction",
                format!("`{other}` is neither `upload` nor `download`"),
            ));
        }
    };
    validate_remote_path(&request.remote).map_err(|err| ipc_error(&err))?;

    let local = match (
        direction,
        request.local.as_deref(),
        request.local_directory.as_deref(),
    ) {
        (_, Some(local), None) if !local.is_empty() => PathBuf::from(local),
        (TransferDirection::Download, None, Some(directory)) if !directory.is_empty() => {
            local_name_for(Path::new(directory), &request.remote).map_err(|_| {
                IpcError::new(
                    "sftp.unsafe-name",
                    format!(
                        "`{}` cannot be saved into that folder: the name the server gave it is \
                         not a plain file name.",
                        escape_untrusted(&request.remote)
                    ),
                )
                .with_actions(["Choose a name for it yourself", "Save it somewhere else"])
            })?
        }
        (TransferDirection::Upload, None, Some(_)) => {
            return Err(IpcError::invalid_request(
                "localDirectory",
                "an upload names the file to send in `local`; a folder is not a file",
            ));
        }
        (_, Some(_), Some(_)) => {
            return Err(IpcError::invalid_request(
                "local",
                "a transfer takes a local file or a local folder, not both",
            ));
        }
        _ => {
            return Err(IpcError::invalid_request(
                "local",
                "a transfer needs somewhere local to read from or write to",
            ));
        }
    };

    Ok(TransferRequest {
        direction,
        remote: request.remote.clone(),
        local,
        resume: request.resume,
    })
}

// ================================================================ helpers ===

/// The browser for a pane, with the path checked first.
///
/// Cloned out from under the lock so nothing awaits while holding it.
fn browser_for(state: &AppState, pane_id: u64, path: &str) -> Result<Arc<SftpBrowser>, IpcError> {
    validate_remote_path(path).map_err(|err| ipc_error(&err))?;
    let hub = state.sessions();
    let panes = hub.panes.lock();
    panes
        .get(&pane_id)
        .map(|pane| Arc::clone(&pane.browser))
        .ok_or_else(no_such_pane)
}

fn no_such_pane() -> IpcError {
    IpcError::new(
        "sftp.no-such-pane",
        "That file pane is not open any more. Its session may have ended.",
    )
    .with_actions(["Close the pane", "Open a file pane again"])
}

fn no_such_transfer() -> IpcError {
    IpcError::new(
        "sftp.no-such-transfer",
        "That transfer is not in this pane's queue.",
    )
    .with_actions(["Refresh the transfer list"])
}

/// A subsystem that could not be opened.
///
/// Worth its own sentence: a server with `Subsystem sftp` commented out refuses
/// the request, and reporting that as a protocol failure sends the user looking
/// at their network.
fn subsystem_error(error: &ProtocolError) -> IpcError {
    if matches!(
        error,
        ProtocolError::Disconnected { .. } | ProtocolError::HandshakeFailed { .. }
    ) {
        return IpcError::new(
            "sftp.subsystem-unavailable",
            "This server did not open an SFTP subsystem. Some servers have it switched off, and \
             some restrict it to particular accounts.",
        )
        .with_detail(format!("{error}"))
        .with_actions([
            "Ask the server's administrator to enable the SFTP subsystem",
            "Use the terminal instead",
        ]);
    }
    ipc_error(error)
}

/// A listing that failed, with the two caps named where they were the cause.
///
/// A user whose build directory holds 400 000 files needs to be told that, not
/// shown an empty pane.
fn listing_error(error: &ProtocolError, path: &str) -> IpcError {
    if let ProtocolError::ProtocolViolation { detail } = error
        && detail.contains("directory listing")
    {
        return IpcError::new(
            "sftp.listing-too-large",
            format!(
                "`{}` holds more than Remoter will read in one listing: the limits are \
                 {MAX_DIRECTORY_ENTRIES} entries and {} MiB of names.",
                escape_untrusted(path),
                MAX_DIRECTORY_BYTES / (1024 * 1024)
            ),
        )
        .with_actions([
            "Open a subdirectory instead",
            "Use the terminal for this directory",
        ]);
    }
    ipc_error(error)
}

/// A rename that failed, with the cause most servers cannot tell you about.
///
/// `SSH_FXP_RENAME` fails across filesystems on most servers and reports it as
/// a plain failure, which reads as a permission problem the user does not have.
fn rename_error(error: &ProtocolError, from: &str, to: &str) -> IpcError {
    if matches!(error, ProtocolError::ProtocolViolation { .. }) {
        return IpcError::new(
            "sftp.rename-failed",
            format!(
                "`{}` could not be renamed to `{}`. A rename cannot cross a filesystem on most \
                 servers, and one that tries is refused exactly like this.",
                escape_untrusted(from),
                escape_untrusted(to)
            ),
        )
        .with_detail(format!("{error}"))
        .with_actions([
            "Copy it across and delete the original",
            "Rename it within the same filesystem",
        ]);
    }
    ipc_error(error)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use remoter_proto_ssh::sftp::{DeleteFailure, MAX_DELETE_DEPTH, MAX_DELETE_ENTRIES};

    use super::*;

    fn download(local: Option<&str>, directory: Option<&str>) -> TransferRequestDto {
        TransferRequestDto {
            direction: String::from("download"),
            remote: String::from("/srv/data/backup.tar"),
            local: local.map(ToOwned::to_owned),
            local_directory: directory.map(ToOwned::to_owned),
            resume: false,
        }
    }

    /// The rule the whole resolution exists for: a name the server chose never
    /// chooses a local path.
    #[test]
    fn a_server_supplied_name_cannot_choose_where_a_download_lands() {
        let into_folder = resolve_request(&download(None, Some("/home/ada/Downloads"))).unwrap();
        assert_eq!(
            into_folder.local,
            PathBuf::from("/home/ada/Downloads/backup.tar")
        );

        // Only the last component survives, so the traversal cannot be smuggled
        // through the earlier ones.
        let traversal = TransferRequestDto {
            remote: String::from("../../../home/ada/.ssh/authorized_keys"),
            ..download(None, Some("/home/ada/Downloads"))
        };
        assert_eq!(
            resolve_request(&traversal).unwrap().local,
            PathBuf::from("/home/ada/Downloads/authorized_keys")
        );

        // And a remote path with no usable last component is refused outright
        // rather than guessed at.
        for hostile in ["/", "..", "///"] {
            let request = TransferRequestDto {
                remote: String::from(hostile),
                ..download(None, Some("/home/ada/Downloads"))
            };
            let refused = resolve_request(&request);
            assert!(
                matches!(refused, Err(ref error) if error.code == "sftp.unsafe-name"),
                "{hostile:?} produced {refused:?}"
            );
        }
    }

    #[test]
    fn a_path_with_a_nul_never_reaches_the_wire() {
        // Two readers disagree about where this path ends, which is the whole
        // trick. It is refused before a packet is built.
        let request = TransferRequestDto {
            remote: String::from("/srv/data/report.pdf\u{0000}/../../etc/shadow"),
            ..download(Some("/home/ada/report.pdf"), None)
        };
        let refused = resolve_request(&request).unwrap_err();
        assert_eq!(refused.code, "session.setting-invalid");
        assert!(refused.message.contains("path"), "{}", refused.message);
    }

    #[test]
    fn a_transfer_needs_exactly_one_local_destination() {
        assert!(resolve_request(&download(Some("/tmp/backup.tar"), None)).is_ok());
        assert!(resolve_request(&download(None, None)).is_err());
        assert!(resolve_request(&download(Some("/tmp/a"), Some("/tmp"))).is_err());

        // An upload sends a file, so a folder is not an answer.
        let upload = TransferRequestDto {
            direction: String::from("upload"),
            local: None,
            local_directory: Some(String::from("/home/ada")),
            ..download(None, None)
        };
        assert_eq!(
            resolve_request(&upload).err().map(|e| e.code),
            Some(String::from("request.invalid"))
        );

        let nonsense = TransferRequestDto {
            direction: String::from("sideways"),
            ..download(Some("/tmp/a"), None)
        };
        assert!(resolve_request(&nonsense).is_err());
    }

    /// The listing a file manager renders keeps the two forms apart: what is
    /// shown, and what goes back to the server.
    #[test]
    fn a_hostile_listing_row_is_shown_safely_and_addressed_exactly() {
        let entry = DirectoryEntry {
            name: String::from("annex\u{202E}txt.exe"),
            path: String::from("/srv/annex\u{202E}txt.exe"),
            kind: EntryKind::File,
            size: Some(4096),
            permissions: Some(0o644),
            modified: Some(1),
            uid: Some(1000),
            user: Some(String::from("ada\u{0007}")),
            gid: Some(1000),
            group: Some(String::from("staff")),
        };
        let dto = entry_dto(&entry);

        // What the user reads has nothing hostile left in it...
        assert!(!dto.display_name.contains('\u{202E}'));
        assert!(!dto.display_path.contains('\u{202E}'));
        assert!(!dto.user.as_deref().unwrap_or_default().contains('\u{0007}'));
        assert!(dto.risks.bidi);
        assert!(!dto.risks.clean());
        // ...and what addresses the file is untouched, or the pane could not
        // open the file it is showing.
        assert_eq!(dto.name, entry.name);
        assert_eq!(dto.path, entry.path);
        assert_eq!(dto.mode.as_deref(), Some("-rw-r--r--"));

        let ordinary = DirectoryEntry {
            name: String::from("report.pdf"),
            path: String::from("/srv/report.pdf"),
            ..entry
        };
        let dto = entry_dto(&ordinary);
        assert!(dto.risks.clean());
        assert_eq!(dto.display_name, "report.pdf");
    }

    #[test]
    fn a_declined_resume_says_which_file_was_in_the_way() {
        let declined = TransferStart {
            resume_requested: true,
            resume_from: 0,
            destination_len: 8_192,
            total: Some(4_096),
        };
        let dto = start_dto(declined, TransferDirection::Download);
        assert!(dto.resume_declined);
        let note = dto.note.expect("a declined resume must say so");
        assert!(note.contains("local file is not shorter"), "{note}");

        // The same refusal on an upload names the other end.
        let note = start_dto(declined, TransferDirection::Upload)
            .note
            .expect("a declined resume must say so");
        assert!(note.contains("remote file is not shorter"), "{note}");

        // A source of unknown size is a different reason, and says so.
        let unknown = TransferStart {
            total: None,
            ..declined
        };
        let note = start_dto(unknown, TransferDirection::Download)
            .note
            .expect("a declined resume must say so");
        assert!(note.contains("size is unknown"), "{note}");

        // Nothing was there to continue: the ordinary first attempt, and no
        // notice at all.
        let first = TransferStart {
            destination_len: 0,
            ..declined
        };
        let dto = start_dto(first, TransferDirection::Download);
        assert!(!dto.resume_declined);
        assert!(dto.note.is_none());
    }

    #[test]
    fn the_dtos_are_camel_case_and_the_state_is_tagged() {
        let queued = serde_json::to_string(&TransferStateDto::Queued).unwrap();
        assert_eq!(queued, r#"{"state":"queued"}"#);

        let running = serde_json::to_string(&TransferStateDto::Running {
            done: 512,
            total: Some(2048),
        })
        .unwrap();
        assert_eq!(running, r#"{"state":"running","done":512,"total":2048}"#);

        let request: TransferRequestDto = serde_json::from_str(
            r#"{"direction":"download","remote":"/srv/a.tar","localDirectory":"/tmp"}"#,
        )
        .unwrap();
        assert_eq!(request.local_directory.as_deref(), Some("/tmp"));
        // Absent means start over. A resume is never the default: it is an
        // optimisation the user opts into, because nothing verifies that the
        // bytes already on disk are the right ones.
        assert!(!request.resume);
    }

    #[test]
    fn a_listing_that_hit_a_cap_says_which_cap() {
        let error = listing_error(
            &ProtocolError::ProtocolViolation {
                detail: "the directory listing exceeded the limit of 250000 entries or 32 MiB",
            },
            "/srv/build",
        );
        assert_eq!(error.code, "sftp.listing-too-large");
        assert!(error.message.contains("250000"), "{}", error.message);
        assert!(error.message.contains("32 MiB"), "{}", error.message);
        assert!(error.message.contains("/srv/build"));

        // Anything else keeps its own identity in the taxonomy.
        let elsewhere = listing_error(
            &ProtocolError::ProtocolViolation {
                detail: "the server sent a malformed packet",
            },
            "/srv",
        );
        assert_eq!(elsewhere.code, "session.protocol-violation");
    }

    #[test]
    fn a_failed_rename_offers_the_thing_that_actually_works() {
        let error = rename_error(
            &ProtocolError::ProtocolViolation {
                detail: "the SFTP server reported a failure",
            },
            "/srv/data/a.tar",
            "/mnt/backup/a.tar",
        );
        assert_eq!(error.code, "sftp.rename-failed");
        assert!(error.message.contains("cross a filesystem"));
        assert!(
            error
                .actions
                .iter()
                .any(|action| action.contains("Copy it across")),
            "{:?}",
            error.actions
        );
    }

    #[test]
    fn the_delete_report_says_what_was_left_behind() {
        let report = DeleteReport {
            files_removed: 9,
            directories_removed: 1,
            failures: vec![DeleteFailure {
                path: String::from("/srv/data/locked\u{202E}txt.exe"),
                reason: ProtocolError::AuthRejected {
                    attempted: remoter_proto::CredentialKind::None,
                },
            }],
            cancelled: false,
            limit_reached: false,
        };
        let dto = delete_report_dto(&report);
        assert_eq!(dto.files_removed, 9);
        assert!(!dto.complete, "nine of twelve is not done");
        assert_eq!(dto.failures.len(), 1);
        assert!(!dto.failures[0].path.contains('\u{202E}'));
        assert!(!dto.failures[0].message.is_empty());

        let clean = DeleteReport {
            files_removed: 3,
            directories_removed: 1,
            ..DeleteReport::default()
        };
        assert!(delete_report_dto(&clean).complete);
    }

    #[test]
    fn the_walks_bounds_are_the_ones_the_specification_names() {
        // Repeated here so that changing one of them fails a test rather than
        // quietly changing what a file manager will do to a filesystem.
        assert_eq!(MAX_DELETE_ENTRIES, 250_000);
        assert_eq!(MAX_DELETE_DEPTH, 64);
        assert_eq!(MAX_DIRECTORY_ENTRIES, 250_000);
    }

    #[tokio::test]
    async fn a_pane_that_is_gone_says_so_rather_than_failing_obscurely() {
        let scratch = crate::test_support::Scratch::new();
        let Some(state) = crate::test_support::open_vault(&scratch) else {
            panic!("the fixture vault could not be created");
        };

        assert_eq!(
            sftp_list_impl(&state, 1, String::from("/srv"))
                .await
                .err()
                .map(|e| e.code),
            Some(String::from("sftp.no-such-pane"))
        );
        assert_eq!(
            sftp_transfers_impl(&state, 1).err().map(|e| e.code),
            Some(String::from("sftp.no-such-pane"))
        );
        assert_eq!(
            sftp_close_impl(&state, 1).await.err().map(|e| e.code),
            Some(String::from("sftp.no-such-pane"))
        );
        // And a session that has not connected has no connection to browse on.
        assert_eq!(
            sftp_open_impl(&state, 1).await.err().map(|e| e.code),
            Some(String::from("sftp.session-not-ready"))
        );
    }
}
