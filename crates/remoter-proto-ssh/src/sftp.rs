//! SFTP over an SSH connection that is already open.
//!
//! **An SFTP tab on a host with a shell does not authenticate again.** SFTP is
//! a subsystem (RFC 4254 §6.5), so it is one more channel on the connection
//! the shell is already using — [`SftpBrowser::open`] takes an
//! `Arc<SshConnection>` and opens a channel on it, and the credential is never
//! touched a second time.
//!
//! **Transfers apply real backpressure.** `docs/architecture/session-pipeline.md`
//! §8 draws the distinction: a terminal may coalesce and a framebuffer may drop
//! stale frames, but a file transfer may do neither, because dropping a byte
//! corrupts the file. Every transfer here is a bounded read-then-write loop
//! that awaits both halves; there is no queue between them to grow.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use remoter_proto::{EventSink, ProgressUpdate, ProtocolError, SessionEvent};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::connection::SshConnection;
use crate::error::{map_russh, map_sftp};

/// The SSH subsystem name (RFC 4254 §6.5, and `draft-ietf-secsh-filexfer`).
pub const SUBSYSTEM: &str = "sftp";

/// How much of a file is moved per round trip.
///
/// 32 KiB matches the largest SSH packet `russh` is configured for, so a chunk
/// becomes one channel packet rather than being split across two.
pub const CHUNK_BYTES: usize = 32 * 1024;

/// How often progress is reported, in bytes moved.
///
/// A progress event per 32 KiB chunk on a fast link is thousands of events per
/// second, all of which the interface would have to render. Every 512 KiB is
/// still a visibly smooth bar.
pub const PROGRESS_INTERVAL_BYTES: u64 = 512 * 1024;

/// The most entries one directory listing may contain.
///
/// The server chooses how many `SSH_FXP_NAME` records to send and
/// `russh-sftp` accumulates all of them, so without a cap a hostile host
/// (threat model T4) drives unbounded allocation from a single click on a
/// folder. The threat model requires resource limits per session; this is the
/// directory pane's. A quarter of a million entries is more than any real
/// directory and small enough that the cap is reached long before memory is.
pub const MAX_DIRECTORY_ENTRIES: usize = 250_000;

/// The most bytes of server-supplied text one directory listing may carry.
///
/// The count cap alone is not enough: entry names are server-chosen strings
/// and a listing of a thousand entries with 64 KiB names each is the same
/// attack by another route.
pub const MAX_DIRECTORY_BYTES: usize = 32 * 1024 * 1024;

/// The failure a listing that exceeds either cap reports.
///
/// A literal, because `ProtocolError::ProtocolViolation` carries one — and it
/// names the limits, which is what turns "something went wrong" into
/// something the user can act on. Kept in step with the constants above by
/// [`tests::the_listing_caps_are_named_in_the_failure`].
const LISTING_TOO_LARGE: &str =
    "the directory listing exceeded the limit of 250000 entries or 32 MiB";

/// What a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link. Not followed: the pane shows the link, and following
    /// it is the user's choice.
    Symlink,
    /// A device, socket, or anything else the server reported.
    Other,
}

impl EntryKind {
    /// A stable ASCII name for the message catalogue.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }

    fn from_attributes(attributes: &FileAttributes) -> Self {
        match attributes.file_type() {
            FileType::Dir => Self::Directory,
            FileType::File => Self::File,
            FileType::Symlink => Self::Symlink,
            FileType::Other => Self::Other,
        }
    }
}

/// One row of the remote pane.
///
/// Everything in it is server-supplied and therefore untrusted text; the
/// interface renders it as text and never as markup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// The file name, without a path.
    pub name: String,
    /// The full path, as the server would take it back.
    pub path: String,
    /// What it is.
    pub kind: EntryKind,
    /// Size in bytes, where the server reported one.
    pub size: Option<u64>,
    /// The POSIX mode bits, where the server reported them.
    pub permissions: Option<u32>,
    /// Last modification, in seconds since the Unix epoch.
    pub modified: Option<u32>,
}

/// Joins a directory and a name the way SFTP paths work.
///
/// SFTP is POSIX-shaped on the wire whatever the server runs on, so the
/// separator is `/` even when the far end is Windows.
#[must_use]
pub fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        return name.to_owned();
    }
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Which way a transfer moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferDirection {
    /// Local to remote.
    Upload,
    /// Remote to local.
    Download,
}

impl TransferDirection {
    /// A stable ASCII name, used as the [`ProgressUpdate::operation`] key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "sftp.upload",
            Self::Download => "sftp.download",
        }
    }
}

/// One queued transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
    /// Which way it moves.
    pub direction: TransferDirection,
    /// The remote path.
    pub remote: String,
    /// The local path.
    pub local: PathBuf,
    /// Whether to continue an interrupted transfer rather than start over.
    ///
    /// Honoured only when the destination is shorter than the source; see
    /// [`resume_offset`].
    pub resume: bool,
}

/// Identifies a transfer within one queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferId(u64);

impl TransferId {
    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for TransferId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Where a transfer is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferState {
    /// Waiting for a slot.
    Queued,
    /// Moving bytes.
    Running {
        /// Bytes moved so far.
        done: u64,
        /// The total, where the source reported one.
        total: Option<u64>,
    },
    /// Finished.
    Completed {
        /// Bytes moved.
        bytes: u64,
    },
    /// Failed, with what the tab shows.
    Failed(remoter_proto::FailureReport),
    /// Stopped by the user.
    Cancelled,
}

impl TransferState {
    /// Whether the transfer has finished, one way or another.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed { .. } | Self::Failed(_) | Self::Cancelled
        )
    }
}

/// A transfer and where it has got to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferStatus {
    /// Its identity.
    pub id: TransferId,
    /// What was asked for.
    pub request: TransferRequest,
    /// Where it is.
    pub state: TransferState,
}

/// The transfer queue.
///
/// Holds the requests and their states; [`run_queue`] drains it. Separated so
/// the interface can enqueue, inspect and cancel without touching the SFTP
/// session, which lives in one task.
#[derive(Debug)]
pub struct TransferQueue {
    entries: Mutex<Vec<Entry>>,
    next: AtomicU64,
    concurrency: usize,
}

#[derive(Debug)]
struct Entry {
    status: TransferStatus,
    cancel: CancellationToken,
}

impl TransferQueue {
    /// A queue running at most `concurrency` transfers at once.
    ///
    /// Concurrency helps on a high-latency link, where one transfer spends
    /// most of its time waiting for acknowledgements. It is bounded because
    /// every concurrent transfer is another SFTP handle and another buffer.
    #[must_use]
    pub fn new(concurrency: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            next: AtomicU64::new(1),
            concurrency: concurrency.max(1),
        }
    }

    /// How many transfers may run at once.
    #[must_use]
    pub const fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// Adds a transfer.
    pub fn enqueue(&self, request: TransferRequest) -> TransferId {
        let id = TransferId(self.next.fetch_add(1, Ordering::Relaxed));
        self.entries.lock().push(Entry {
            status: TransferStatus {
                id,
                request,
                state: TransferState::Queued,
            },
            cancel: CancellationToken::new(),
        });
        id
    }

    /// Every transfer, in the order they were added.
    #[must_use]
    pub fn list(&self) -> Vec<TransferStatus> {
        self.entries
            .lock()
            .iter()
            .map(|entry| entry.status.clone())
            .collect()
    }

    /// One transfer.
    #[must_use]
    pub fn status(&self, id: TransferId) -> Option<TransferStatus> {
        self.entries
            .lock()
            .iter()
            .find(|entry| entry.status.id == id)
            .map(|entry| entry.status.clone())
    }

    /// Stops a transfer.
    ///
    /// A queued one is marked cancelled immediately; a running one stops at
    /// its next chunk boundary, which is what keeps the partial file's length
    /// meaningful for a later resume.
    pub fn cancel(&self, id: TransferId) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|entry| entry.status.id == id) {
            entry.cancel.cancel();
            if !entry.status.state.is_terminal() {
                entry.status.state = TransferState::Cancelled;
            }
        }
    }

    /// Stops everything.
    pub fn cancel_all(&self) {
        let ids: Vec<TransferId> = self
            .entries
            .lock()
            .iter()
            .map(|entry| entry.status.id)
            .collect();
        for id in ids {
            self.cancel(id);
        }
    }

    /// The next transfer waiting for a slot.
    fn take_next(&self) -> Option<(TransferRequest, TransferId, CancellationToken)> {
        let mut entries = self.entries.lock();
        let running = entries
            .iter()
            .filter(|entry| matches!(entry.status.state, TransferState::Running { .. }))
            .count();
        if running >= self.concurrency {
            return None;
        }
        let entry = entries
            .iter_mut()
            .find(|entry| entry.status.state == TransferState::Queued)?;
        entry.status.state = TransferState::Running {
            done: 0,
            total: None,
        };
        Some((
            entry.status.request.clone(),
            entry.status.id,
            entry.cancel.clone(),
        ))
    }

    fn set_state(&self, id: TransferId, state: TransferState) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|entry| entry.status.id == id) {
            // A cancellation that landed while a chunk was in flight wins: the
            // transfer really did stop, and reporting it as completed would be
            // a lie about a partial file.
            if entry.status.state == TransferState::Cancelled && !state.is_terminal() {
                return;
            }
            entry.status.state = state;
        }
    }
}

/// Where a resumed transfer should start.
///
/// Resume is only safe when the destination is a strict prefix of the source,
/// which we can only approximate by length. Anything else — a destination
/// longer than the source, or a source whose size is unknown — starts over,
/// because appending to the wrong file silently corrupts it and re-copying a
/// file merely costs time.
#[must_use]
pub fn resume_offset(requested: bool, destination_len: u64, source_len: Option<u64>) -> u64 {
    if !requested || destination_len == 0 {
        return 0;
    }
    match source_len {
        Some(total) if destination_len < total => destination_len,
        _ => 0,
    }
}

/// SFTP on an existing SSH connection.
pub struct SftpBrowser {
    session: SftpSession,
    /// Kept so the SSH session outlives the subsystem channel.
    connection: Arc<SshConnection>,
}

impl SftpBrowser {
    /// Opens the SFTP subsystem on `connection`.
    ///
    /// # Errors
    ///
    /// Whatever the server said when it refused the channel or the subsystem —
    /// a server with `Subsystem sftp` disabled refuses the request, and that
    /// is worth saying rather than reporting as a protocol failure.
    pub async fn open(connection: Arc<SshConnection>) -> Result<Self, ProtocolError> {
        let channel = connection.open_session_channel().await?;
        channel
            .request_subsystem(true, SUBSYSTEM)
            .await
            .map_err(|error| map_russh(&error, "request the SFTP subsystem"))?;
        let session = SftpSession::new(channel.into_stream())
            .await
            .map_err(|error| map_sftp(&error))?;
        Ok(Self {
            session,
            connection,
        })
    }

    /// The connection this browser runs on.
    #[must_use]
    pub fn connection(&self) -> &Arc<SshConnection> {
        &self.connection
    }

    /// Lists a directory.
    ///
    /// Bounded on both sides of the click: `cancel` stops a listing the user
    /// navigated away from, and [`MAX_DIRECTORY_ENTRIES`] /
    /// [`MAX_DIRECTORY_BYTES`] stop a server that answers a `readdir` with
    /// more than a directory could hold.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Cancelled`] if the pane was closed while listing;
    /// [`ProtocolError::ProtocolViolation`] naming the limit if the server
    /// exceeded it; otherwise whatever the server reported — a missing path
    /// and a permission refusal are distinct in the taxonomy.
    pub async fn list(
        &self,
        path: &str,
        cancel: &CancellationToken,
    ) -> Result<Vec<DirectoryEntry>, ProtocolError> {
        bounded_listing(cancel, async {
            let entries = self
                .session
                .read_dir(path)
                .await
                .map_err(|error| map_sftp(&error))?;
            Ok(entries.map(|entry| {
                let metadata = entry.metadata();
                DirectoryEntry {
                    name: entry.file_name(),
                    path: entry.path(),
                    kind: EntryKind::from_attributes(&metadata),
                    size: metadata.size,
                    permissions: metadata.permissions,
                    modified: metadata.mtime,
                }
            }))
        })
        .await
    }

    /// Resolves a path to its absolute form.
    ///
    /// # Errors
    ///
    /// Whatever the server reported.
    pub async fn canonicalize(&self, path: &str) -> Result<String, ProtocolError> {
        self.session
            .canonicalize(path)
            .await
            .map_err(|error| map_sftp(&error))
    }

    /// Reads one entry's metadata, following symbolic links.
    ///
    /// # Errors
    ///
    /// Whatever the server reported.
    pub async fn metadata(&self, path: &str) -> Result<DirectoryEntry, ProtocolError> {
        let metadata = self
            .session
            .metadata(path)
            .await
            .map_err(|error| map_sftp(&error))?;
        Ok(DirectoryEntry {
            name: path.rsplit('/').next().unwrap_or(path).to_owned(),
            path: path.to_owned(),
            kind: EntryKind::from_attributes(&metadata),
            size: metadata.size,
            permissions: metadata.permissions,
            modified: metadata.mtime,
        })
    }

    /// Creates a directory.
    ///
    /// # Errors
    ///
    /// Whatever the server reported.
    pub async fn make_directory(&self, path: &str) -> Result<(), ProtocolError> {
        self.session
            .create_dir(path)
            .await
            .map_err(|error| map_sftp(&error))
    }

    /// Removes an empty directory.
    ///
    /// Recursive removal is the caller's business: walking a tree and deleting
    /// it is a decision with a confirmation attached, not a primitive.
    ///
    /// # Errors
    ///
    /// Whatever the server reported.
    pub async fn remove_directory(&self, path: &str) -> Result<(), ProtocolError> {
        self.session
            .remove_dir(path)
            .await
            .map_err(|error| map_sftp(&error))
    }

    /// Removes a file.
    ///
    /// # Errors
    ///
    /// Whatever the server reported.
    pub async fn remove_file(&self, path: &str) -> Result<(), ProtocolError> {
        self.session
            .remove_file(path)
            .await
            .map_err(|error| map_sftp(&error))
    }

    /// Renames or moves an entry.
    ///
    /// # Errors
    ///
    /// Whatever the server reported.
    pub async fn rename(&self, from: &str, to: &str) -> Result<(), ProtocolError> {
        self.session
            .rename(from, to)
            .await
            .map_err(|error| map_sftp(&error))
    }

    /// Changes an entry's POSIX mode bits.
    ///
    /// Only the permission bits are sent, so the request cannot accidentally
    /// truncate a file by carrying a stale size along with them.
    ///
    /// # Errors
    ///
    /// Whatever the server reported.
    pub async fn set_permissions(&self, path: &str, mode: u32) -> Result<(), ProtocolError> {
        let attributes = FileAttributes {
            permissions: Some(mode),
            ..FileAttributes::default()
        };
        self.session
            .set_metadata(path, attributes)
            .await
            .map_err(|error| map_sftp(&error))
    }

    /// Creates a symbolic link at `path` pointing at `target`.
    ///
    /// # Errors
    ///
    /// Whatever the server reported.
    pub async fn symlink(&self, path: &str, target: &str) -> Result<(), ProtocolError> {
        self.session
            .symlink(path, target)
            .await
            .map_err(|error| map_sftp(&error))
    }

    /// Reads where a symbolic link points, without following it.
    ///
    /// # Errors
    ///
    /// Whatever the server reported.
    pub async fn read_link(&self, path: &str) -> Result<String, ProtocolError> {
        self.session
            .read_link(path)
            .await
            .map_err(|error| map_sftp(&error))
    }

    /// Runs one transfer.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Cancelled`] if the transfer was stopped, or whatever
    /// the server or the local filesystem reported.
    pub async fn transfer(
        &self,
        request: &TransferRequest,
        events: Option<&EventSink>,
        cancel: &CancellationToken,
        mut on_progress: impl FnMut(u64, Option<u64>),
    ) -> Result<u64, ProtocolError> {
        match request.direction {
            TransferDirection::Download => {
                self.download(request, events, cancel, &mut on_progress)
                    .await
            }
            TransferDirection::Upload => {
                self.upload(request, events, cancel, &mut on_progress).await
            }
        }
    }

    async fn download(
        &self,
        request: &TransferRequest,
        events: Option<&EventSink>,
        cancel: &CancellationToken,
        on_progress: &mut impl FnMut(u64, Option<u64>),
    ) -> Result<u64, ProtocolError> {
        let total = self
            .session
            .metadata(request.remote.clone())
            .await
            .ok()
            .and_then(|metadata| metadata.size);

        let existing = tokio::fs::metadata(&request.local)
            .await
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let offset = resume_offset(request.resume, existing, total);

        let mut remote = self
            .session
            .open(request.remote.clone())
            .await
            .map_err(|error| map_sftp(&error))?;
        if offset > 0 {
            remote
                .seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|source| ProtocolError::Io {
                    operation: "seek a remote file to resume a transfer",
                    source,
                })?;
        }

        let mut local = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            // Truncate only when starting over. Appending to a file we are not
            // resuming would corrupt it, and truncating one we are resuming
            // would throw away the part already fetched.
            .truncate(offset == 0)
            .append(offset > 0)
            .open(&request.local)
            .await
            .map_err(|source| ProtocolError::Io {
                operation: "open the local file",
                source,
            })?;

        let moved = copy_chunks(
            &mut remote,
            &mut local,
            offset,
            total,
            request,
            events,
            cancel,
            on_progress,
        )
        .await?;

        // Flush before reporting success: a transfer reported complete while
        // bytes are still in a buffer is a transfer that can still fail.
        local.flush().await.map_err(|source| ProtocolError::Io {
            operation: "flush the local file",
            source,
        })?;
        Ok(moved)
    }

    async fn upload(
        &self,
        request: &TransferRequest,
        events: Option<&EventSink>,
        cancel: &CancellationToken,
        on_progress: &mut impl FnMut(u64, Option<u64>),
    ) -> Result<u64, ProtocolError> {
        let total = tokio::fs::metadata(&request.local)
            .await
            .map(|metadata| metadata.len())
            .ok();

        let existing = self
            .session
            .metadata(request.remote.clone())
            .await
            .ok()
            .and_then(|metadata| metadata.size)
            .unwrap_or(0);
        let offset = resume_offset(request.resume, existing, total);

        let mut local = tokio::fs::File::open(&request.local)
            .await
            .map_err(|source| ProtocolError::Io {
                operation: "open the local file",
                source,
            })?;
        if offset > 0 {
            local
                .seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|source| ProtocolError::Io {
                    operation: "seek the local file to resume a transfer",
                    source,
                })?;
        }

        let flags = if offset > 0 {
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::APPEND
        } else {
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE
        };
        let mut remote = self
            .session
            .open_with_flags(request.remote.clone(), flags)
            .await
            .map_err(|error| map_sftp(&error))?;
        if offset > 0 {
            remote
                .seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|source| ProtocolError::Io {
                    operation: "seek a remote file to resume a transfer",
                    source,
                })?;
        }

        let moved = copy_chunks(
            &mut local,
            &mut remote,
            offset,
            total,
            request,
            events,
            cancel,
            on_progress,
        )
        .await?;

        remote.flush().await.map_err(|source| ProtocolError::Io {
            operation: "flush the remote file",
            source,
        })?;
        Ok(moved)
    }
}

impl std::fmt::Debug for SftpBrowser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpBrowser")
            .field("target", self.connection.target())
            .finish()
    }
}

/// Collects a directory listing under the caps, honouring cancellation.
///
/// `source` is the whole server round trip, raced against `cancel` rather than
/// awaited: `russh-sftp` keeps issuing `SSH_FXP_READDIR` until the server says
/// EOF, so a server that never says it would otherwise hold the pane — and the
/// allocation — for as long as it liked.
async fn bounded_listing<F, I>(
    cancel: &CancellationToken,
    source: F,
) -> Result<Vec<DirectoryEntry>, ProtocolError>
where
    F: Future<Output = Result<I, ProtocolError>>,
    I: Iterator<Item = DirectoryEntry>,
{
    let entries = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(ProtocolError::Cancelled),
        entries = source => entries?,
    };

    let mut collected = Vec::new();
    let mut bytes = 0usize;
    for entry in entries {
        if collected.len() >= MAX_DIRECTORY_ENTRIES {
            return Err(ProtocolError::ProtocolViolation {
                detail: LISTING_TOO_LARGE,
            });
        }
        // Every string in an entry is server-chosen; the count cap alone would
        // let one long name stand in for a hundred thousand short ones.
        bytes = bytes
            .saturating_add(entry.name.len())
            .saturating_add(entry.path.len());
        if bytes > MAX_DIRECTORY_BYTES {
            return Err(ProtocolError::ProtocolViolation {
                detail: LISTING_TOO_LARGE,
            });
        }
        collected.push(entry);
    }
    Ok(collected)
}

/// Moves bytes one bounded chunk at a time.
///
/// The loop is deliberately not `tokio::io::copy`: it has to check
/// cancellation between chunks, and it has to report progress. Both halves are
/// awaited, so a slow destination stops the source — which is the backpressure
/// a file transfer must have.
#[expect(
    clippy::too_many_arguments,
    reason = "one call site each for upload and download; splitting the state into a struct would name every field twice"
)]
async fn copy_chunks<R, W>(
    source: &mut R,
    destination: &mut W,
    offset: u64,
    total: Option<u64>,
    request: &TransferRequest,
    events: Option<&EventSink>,
    cancel: &CancellationToken,
    on_progress: &mut impl FnMut(u64, Option<u64>),
) -> Result<u64, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; CHUNK_BYTES];
    let mut done = offset;
    let mut reported = offset;

    loop {
        if cancel.is_cancelled() {
            // Whatever has been written stays on disk: its length is what
            // makes a later resume possible.
            return Err(ProtocolError::Cancelled);
        }

        let read = source
            .read(&mut buffer)
            .await
            .map_err(|source| ProtocolError::Io {
                operation: "read a transfer chunk",
                source,
            })?;
        if read == 0 {
            break;
        }

        destination
            .write_all(buffer.get(..read).unwrap_or_default())
            .await
            .map_err(|source| ProtocolError::Io {
                operation: "write a transfer chunk",
                source,
            })?;

        done = done.saturating_add(read as u64);
        if done.saturating_sub(reported) >= PROGRESS_INTERVAL_BYTES {
            reported = done;
            on_progress(done, total);
            if let Some(events) = events {
                // A closed event stream means the tab is gone. The transfer is
                // not abandoned over it — a download the user started should
                // finish — but nothing more is reported.
                let _ = events
                    .send(SessionEvent::Progress(ProgressUpdate {
                        operation: request.direction.as_str().to_owned(),
                        done,
                        total,
                        detail: Some(request.remote.clone()),
                    }))
                    .await;
            }
        }
    }

    on_progress(done, total.or(Some(done)));
    if let Some(events) = events {
        let _ = events
            .send(SessionEvent::Progress(ProgressUpdate {
                operation: request.direction.as_str().to_owned(),
                done,
                total: total.or(Some(done)),
                detail: Some(request.remote.clone()),
            }))
            .await;
    }
    Ok(done)
}

/// What [`run_queue`] needs from the thing that moves the bytes.
///
/// Behind a trait so the cancellation path can be exercised against a transfer
/// that is genuinely in flight — the case the session token has to reach, and
/// the one an `SftpBrowser` cannot be made to reproduce without a server.
trait Transferrer {
    fn transfer(
        &self,
        request: &TransferRequest,
        events: Option<&EventSink>,
        cancel: &CancellationToken,
        on_progress: &mut dyn FnMut(u64, Option<u64>),
    ) -> impl Future<Output = Result<u64, ProtocolError>>;
}

impl Transferrer for SftpBrowser {
    async fn transfer(
        &self,
        request: &TransferRequest,
        events: Option<&EventSink>,
        cancel: &CancellationToken,
        on_progress: &mut dyn FnMut(u64, Option<u64>),
    ) -> Result<u64, ProtocolError> {
        Self::transfer(self, request, events, cancel, on_progress).await
    }
}

/// Drains a queue until it is empty or `cancel` fires.
///
/// Transfers run up to [`TransferQueue::concurrency`] at a time; here they are
/// taken one at a time because a single SFTP session is the shared resource,
/// and the queue's own accounting is what enforces the limit.
///
/// `cancel` is the *session's* token and it reaches the transfer that is
/// already moving bytes, not merely the next one to start.
pub async fn run_queue(
    browser: &SftpBrowser,
    queue: &TransferQueue,
    events: Option<&EventSink>,
    cancel: &CancellationToken,
) {
    drain(browser, queue, events, cancel).await;
}

async fn drain<T: Transferrer>(
    runner: &T,
    queue: &TransferQueue,
    events: Option<&EventSink>,
    cancel: &CancellationToken,
) {
    while let Some((request, id, transfer_cancel)) = queue.take_next() {
        if cancel.is_cancelled() {
            queue.set_state(id, TransferState::Cancelled);
            return;
        }

        // Raced rather than checked between files. A closed tab has to stop a
        // transfer in flight — CLAUDE.md §5 requires the task to terminate and
        // free its sockets deterministically, and a 40 GB file would otherwise
        // keep moving bytes over a session the user has ended. Whatever has
        // been written stays on disk, which is what makes a later resume
        // possible ([`resume_offset`]).
        let mut on_progress =
            |done, total| queue.set_state(id, TransferState::Running { done, total });
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(ProtocolError::Cancelled),
            outcome = runner.transfer(&request, events, &transfer_cancel, &mut on_progress)
                => outcome,
        };

        let state = match outcome {
            Ok(bytes) => TransferState::Completed { bytes },
            Err(ProtocolError::Cancelled) => TransferState::Cancelled,
            Err(error) => TransferState::Failed(remoter_proto::FailureReport::from(&error)),
        };
        queue.set_state(id, state);
        if cancel.is_cancelled() {
            return;
        }
    }
}

/// The local file name a remote path would be saved as.
///
/// The remote name is server-supplied and may contain a path separator, a
/// `..`, or a leading `/`; only the last component is kept and anything that
/// still looks like a traversal is refused. A file manager that writes where
/// the server told it to is a file manager that can be told to overwrite
/// `~/.ssh/authorized_keys`.
///
/// # Errors
///
/// [`ProtocolError::SettingInvalid`] if no safe name can be taken from
/// `remote`.
pub fn local_name_for(directory: &Path, remote: &str) -> Result<PathBuf, ProtocolError> {
    let invalid = || ProtocolError::SettingInvalid {
        key: "path".to_owned(),
        expected: "a file name that stays inside the chosen folder",
    };
    let name = remote
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .ok_or_else(invalid)?;
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(invalid());
    }
    Ok(directory.join(name))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;

    fn request(direction: TransferDirection) -> TransferRequest {
        TransferRequest {
            direction,
            remote: "/srv/data/backup.tar".to_owned(),
            local: PathBuf::from("/tmp/backup.tar"),
            resume: false,
        }
    }

    #[test]
    fn sftp_paths_are_posix_shaped_whatever_the_server_runs() {
        assert_eq!(join_path("/srv", "data"), "/srv/data");
        assert_eq!(join_path("/srv/", "data"), "/srv/data");
        assert_eq!(join_path("", "data"), "data");
        assert_eq!(join_path("/", "data"), "/data");
    }

    #[test]
    fn a_resume_only_continues_a_shorter_destination() {
        // The safe cases: a partial file, shorter than the source.
        assert_eq!(resume_offset(true, 1_000, Some(4_096)), 1_000);

        // Not asked for.
        assert_eq!(resume_offset(false, 1_000, Some(4_096)), 0);
        // Nothing there yet.
        assert_eq!(resume_offset(true, 0, Some(4_096)), 0);
        // Already the same length: starting over is the only way to be sure
        // the contents match.
        assert_eq!(resume_offset(true, 4_096, Some(4_096)), 0);
        // Longer than the source: this is not a prefix of anything.
        assert_eq!(resume_offset(true, 8_192, Some(4_096)), 0);
        // The source's size is unknown, so no offset can be justified.
        assert_eq!(resume_offset(true, 1_000, None), 0);
    }

    #[test]
    fn a_server_supplied_name_cannot_escape_the_chosen_folder() {
        // The remote side chooses these strings. A download that honoured a
        // traversal could overwrite `~/.ssh/authorized_keys`.
        let directory = Path::new("/home/ada/Downloads");
        assert_eq!(
            local_name_for(directory, "/srv/data/backup.tar").unwrap(),
            PathBuf::from("/home/ada/Downloads/backup.tar")
        );
        assert_eq!(
            local_name_for(directory, "backup.tar").unwrap(),
            PathBuf::from("/home/ada/Downloads/backup.tar")
        );
        // Only the last component survives, so a traversal cannot be smuggled
        // through the earlier ones.
        assert_eq!(
            local_name_for(directory, "../../../etc/passwd").unwrap(),
            PathBuf::from("/home/ada/Downloads/passwd")
        );
        assert_eq!(
            local_name_for(directory, "C:\\Windows\\System32\\config").unwrap(),
            PathBuf::from("/home/ada/Downloads/config")
        );

        for hostile in ["", "/", "..", "../", "./", "///"] {
            assert!(
                local_name_for(directory, hostile).is_err(),
                "{hostile:?} produced a path"
            );
        }
    }

    #[test]
    fn a_queue_hands_out_work_up_to_its_concurrency_limit() {
        let queue = TransferQueue::new(2);
        let first = queue.enqueue(request(TransferDirection::Download));
        let second = queue.enqueue(request(TransferDirection::Download));
        let third = queue.enqueue(request(TransferDirection::Upload));

        assert!(queue.take_next().is_some());
        assert!(queue.take_next().is_some());
        // The third waits: two are already running.
        assert!(queue.take_next().is_none());

        queue.set_state(first, TransferState::Completed { bytes: 10 });
        assert!(queue.take_next().is_some());

        assert_eq!(
            queue.status(second).unwrap().state,
            TransferState::Running {
                done: 0,
                total: None
            }
        );
        assert!(!queue.status(third).unwrap().state.is_terminal());
    }

    #[test]
    fn cancelling_a_queued_transfer_stops_it_being_started() {
        let queue = TransferQueue::new(4);
        let id = queue.enqueue(request(TransferDirection::Upload));
        queue.cancel(id);
        assert_eq!(queue.status(id).unwrap().state, TransferState::Cancelled);
        assert!(queue.take_next().is_none());
    }

    #[test]
    fn a_cancellation_that_races_a_finished_chunk_still_reads_as_cancelled() {
        // The user pressed stop; a progress update that was already in flight
        // must not resurrect the transfer as running.
        let queue = TransferQueue::new(1);
        let id = queue.enqueue(request(TransferDirection::Download));
        assert!(queue.take_next().is_some());
        queue.cancel(id);
        queue.set_state(
            id,
            TransferState::Running {
                done: 100,
                total: Some(200),
            },
        );
        assert_eq!(queue.status(id).unwrap().state, TransferState::Cancelled);

        // A terminal state still lands: a transfer that genuinely failed
        // afterwards should say so.
        queue.set_state(id, TransferState::Completed { bytes: 100 });
        assert_eq!(
            queue.status(id).unwrap().state,
            TransferState::Completed { bytes: 100 }
        );
    }

    #[test]
    fn cancelling_everything_leaves_nothing_runnable() {
        let queue = TransferQueue::new(4);
        for _ in 0..3 {
            queue.enqueue(request(TransferDirection::Download));
        }
        queue.cancel_all();
        assert!(queue.take_next().is_none());
        assert!(queue.list().iter().all(|status| status.state.is_terminal()));
    }

    #[test]
    fn a_queue_always_runs_at_least_one_transfer() {
        assert_eq!(TransferQueue::new(0).concurrency(), 1);
        assert_eq!(TransferQueue::new(4).concurrency(), 4);
    }

    #[tokio::test]
    async fn a_transfer_copies_every_byte_and_reports_progress() {
        let source = vec![7u8; (PROGRESS_INTERVAL_BYTES as usize) * 2 + 17];
        let mut read = std::io::Cursor::new(source.clone());
        let mut written: Vec<u8> = Vec::new();
        let mut updates = Vec::new();

        let moved = copy_chunks(
            &mut read,
            &mut written,
            0,
            Some(source.len() as u64),
            &request(TransferDirection::Download),
            None,
            &CancellationToken::new(),
            &mut |done, total| updates.push((done, total)),
        )
        .await
        .unwrap();

        assert_eq!(moved, source.len() as u64);
        assert_eq!(written, source, "a transfer may not drop or reorder a byte");
        assert!(updates.len() >= 2, "progress was not reported: {updates:?}");
        assert_eq!(updates.last().unwrap().0, source.len() as u64);
    }

    #[tokio::test]
    async fn a_cancelled_transfer_stops_and_leaves_what_it_wrote() {
        let source = vec![3u8; CHUNK_BYTES * 4];
        let mut read = std::io::Cursor::new(source);
        let mut written: Vec<u8> = Vec::new();
        let cancel = CancellationToken::new();
        cancel.cancel();

        let error = copy_chunks(
            &mut read,
            &mut written,
            0,
            None,
            &request(TransferDirection::Download),
            None,
            &cancel,
            &mut |_, _| {},
        )
        .await
        .unwrap_err();

        assert!(matches!(error, ProtocolError::Cancelled));
        // Nothing was written because the check happens before the first read;
        // what matters is that the partial file is not deleted, which is the
        // caller's contract and what makes a resume possible.
        assert!(written.is_empty());
    }

    #[tokio::test]
    async fn a_resumed_transfer_counts_from_the_offset() {
        let rest = vec![9u8; 100];
        let mut read = std::io::Cursor::new(rest.clone());
        let mut written: Vec<u8> = Vec::new();

        let moved = copy_chunks(
            &mut read,
            &mut written,
            400,
            Some(500),
            &request(TransferDirection::Download),
            None,
            &CancellationToken::new(),
            &mut |_, _| {},
        )
        .await
        .unwrap();

        // The progress figure is the file's position, not the bytes this run
        // moved: a bar that restarted at zero on a resume would be wrong.
        assert_eq!(moved, 500);
        assert_eq!(written, rest);
    }

    fn entry(index: usize, name_len: usize) -> DirectoryEntry {
        DirectoryEntry {
            name: "n".repeat(name_len),
            path: format!("/srv/{index}"),
            kind: EntryKind::File,
            size: Some(1),
            permissions: None,
            modified: None,
        }
    }

    #[test]
    fn the_listing_caps_are_named_in_the_failure() {
        // The message is a literal because `ProtocolViolation` carries one;
        // it must still say the same numbers the constants do, or it sends the
        // user looking for a limit that does not exist.
        assert!(LISTING_TOO_LARGE.contains(&MAX_DIRECTORY_ENTRIES.to_string()));
        assert_eq!(MAX_DIRECTORY_BYTES, 32 * 1024 * 1024);
        assert!(LISTING_TOO_LARGE.contains("32 MiB"));
    }

    #[tokio::test]
    async fn a_listing_within_the_caps_is_returned_whole() {
        let listed = bounded_listing(&CancellationToken::new(), async {
            Ok((0..64).map(|index| entry(index, 8)))
        })
        .await
        .unwrap();
        assert_eq!(listed.len(), 64);
        assert_eq!(listed[7].path, "/srv/7");
    }

    #[tokio::test]
    async fn a_server_cannot_make_the_pane_allocate_without_bound() {
        // A hostile host chooses how many `SSH_FXP_NAME` records to send and
        // `russh-sftp` accumulates every one of them (threat model T4). The
        // count cap is one half of the answer...
        let error = bounded_listing(&CancellationToken::new(), async {
            Ok((0..MAX_DIRECTORY_ENTRIES + 1).map(|index| entry(index, 1)))
        })
        .await
        .unwrap_err();
        let ProtocolError::ProtocolViolation { detail } = error else {
            panic!("expected ProtocolViolation, got {error:?}");
        };
        assert_eq!(detail, LISTING_TOO_LARGE);

        // ...and the byte cap is the other: names are server-chosen strings,
        // so a short listing of enormous ones is the same attack.
        let error = bounded_listing(&CancellationToken::new(), async {
            Ok((0..64).map(|index| entry(index, MAX_DIRECTORY_BYTES / 8)))
        })
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ProtocolError::ProtocolViolation {
                detail: LISTING_TOO_LARGE
            }
        ));
    }

    #[tokio::test]
    async fn a_listing_stops_when_the_pane_is_closed() {
        // `read_dir` keeps asking until the server says EOF. A server that
        // never says it would hold the pane open for as long as it liked.
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = bounded_listing::<_, std::iter::Empty<DirectoryEntry>>(&cancel, async {
            std::future::pending().await
        })
        .await
        .unwrap_err();
        assert!(matches!(error, ProtocolError::Cancelled));
    }

    /// A transfer that starts and never finishes — a large file, mid-flight.
    struct NeverFinishes {
        started: Arc<tokio::sync::Notify>,
    }

    impl Transferrer for NeverFinishes {
        async fn transfer(
            &self,
            _request: &TransferRequest,
            _events: Option<&EventSink>,
            _cancel: &CancellationToken,
            on_progress: &mut dyn FnMut(u64, Option<u64>),
        ) -> Result<u64, ProtocolError> {
            on_progress(1024, Some(u64::MAX));
            self.started.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancelling_a_session_stops_the_transfer_that_is_already_running() {
        // Checked only at the top of each loop iteration, a cancelled session
        // keeps moving bytes until the current file finishes — which for a
        // 40 GB download is not a bound at all. The doc comment claimed
        // otherwise; CLAUDE.md §5 requires a closed tab to stop its task.
        let queue = Arc::new(TransferQueue::new(1));
        let id = queue.enqueue(request(TransferDirection::Download));
        let cancel = CancellationToken::new();
        let started = Arc::new(tokio::sync::Notify::new());

        let runner = NeverFinishes {
            started: Arc::clone(&started),
        };
        let draining = drain(&runner, &queue, None, &cancel);
        let watching = async {
            started.notified().await;
            assert!(
                matches!(
                    queue.status(id).unwrap().state,
                    TransferState::Running { .. }
                ),
                "the transfer should be moving bytes"
            );
            cancel.cancel();
        };

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(draining, watching);
        })
        .await
        .expect("the queue kept transferring after the session was cancelled");

        assert_eq!(queue.status(id).unwrap().state, TransferState::Cancelled);
    }

    #[test]
    fn entry_kinds_have_stable_names() {
        assert_eq!(EntryKind::Directory.as_str(), "directory");
        assert_eq!(EntryKind::Symlink.as_str(), "symlink");
        assert_eq!(TransferDirection::Upload.as_str(), "sftp.upload");
        assert_eq!(TransferDirection::Download.as_str(), "sftp.download");
    }

    #[test]
    fn a_symlink_is_reported_as_a_symlink_rather_than_followed() {
        // The pane shows the link. Following it here would hide a link to
        // somewhere the user did not mean to go.
        let mut attributes = FileAttributes::default();
        attributes.set_symlink(true);
        assert_eq!(EntryKind::from_attributes(&attributes), EntryKind::Symlink);

        let mut directory = FileAttributes::default();
        directory.set_dir(true);
        assert_eq!(EntryKind::from_attributes(&directory), EntryKind::Directory);
    }
}
