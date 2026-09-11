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
//!
//! **Every name the server sends is hostile until proved otherwise.** A remote
//! file name is an arbitrary byte string with `/` and NUL removed — and on some
//! servers not even that. It may carry a path separator that turns a listing
//! entry into a write somewhere else entirely, a control byte that truncates a
//! log line, or a right-to-left override that renders `evil\u{202E}txt.exe` as
//! `evilexe.txt`. [`safe_name`] separates what is displayed from what is sent
//! back on the wire, and nothing in this module builds a path by trusting the
//! path the server volunteered — see [`SftpBrowser::remove_tree`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use remoter_core::ProtocolId;
use remoter_proto::{
    Capabilities, ClipboardSupport, CloseReason, EventSink, ProgressUpdate, ProtocolError,
    SessionCommand, SessionContext, SessionEvent, SessionKind,
};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::connection::SshConnection;
use crate::error::{map_russh, map_sftp};

/// The SSH subsystem name (RFC 4254 §6.5, and `draft-ietf-secsh-filexfer`).
pub const SUBSYSTEM: &str = "sftp";

/// The protocol identifier of a connection whose tab is a file pane.
///
/// An `sftp` connection is an SSH connection: the same key exchange, the same
/// host key check, the same credential, and — as `remoter_core` agrees by
/// giving it port 22 — the same service. What differs is what the tab shows.
pub const SFTP_ID: &str = "sftp";

/// The identifier as a validated [`ProtocolId`].
///
/// Fallible only in principle, and kept fallible because this crate forbids
/// `unwrap`: the failure degrades to a diagnostic rather than a panic.
///
/// # Errors
///
/// [`ProtocolError::Internal`] if `remoter-core` ever stops accepting
/// `"sftp"`.
pub fn sftp_protocol_id() -> Result<ProtocolId, ProtocolError> {
    ProtocolId::new(SFTP_ID).map_err(|_| ProtocolError::Internal {
        detail: "the sftp protocol identifier did not validate",
    })
}

/// How often a file session asks whether its connection is still there.
///
/// `russh` offers no future that completes when the session ends, and a file
/// pane — unlike a shell — has no read half whose end would tell it. Asking is
/// the only thing left, and asking cheaply turns a server that went away into a
/// tab that says so rather than a pane whose every click fails separately.
const CONNECTION_PROBE: Duration = Duration::from_secs(2);

/// What a file-transfer tab can do.
///
/// Read by the interface instead of hardcoding "SFTP has no clipboard button",
/// exactly as [`crate::session::capabilities`] is for a terminal.
#[must_use]
pub fn capabilities() -> Capabilities {
    Capabilities {
        kind: SessionKind::FileTransfer,
        // No cell grid, so no size to negotiate.
        resizable: false,
        // Putting a *file* on the local clipboard is `ClipboardPolicy::files`,
        // which `docs/security/transport-security.md` keeps off everywhere so
        // that a compromised host cannot drop one there; a file pane has no
        // text to offer either.
        clipboard: ClipboardSupport::None,
        file_transfer: true,
        audio: false,
        printing: false,
        multi_monitor: false,
        // There is nothing to replay. `remoter-record` writes asciicast and
        // framebuffer streams, and a transfer queue is neither; what a file
        // session leaves behind is an audit entry.
        recordable: false,
    }
}

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
/// interface renders it as text and never as markup, and shows
/// [`safe_name`]'s display form rather than [`name`](Self::name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// The file name, without a path. **Raw, as the server sent it**: this is
    /// what goes back on the wire, not what is put on screen.
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
    /// The owning user id, where the server reported one.
    pub uid: Option<u32>,
    /// The owning user's name, where the server reported one. Server-supplied
    /// text, and displayed under the same rule as a file name.
    pub user: Option<String>,
    /// The owning group id, where the server reported one.
    pub gid: Option<u32>,
    /// The owning group's name, where the server reported one. Server-supplied
    /// text.
    pub group: Option<String>,
}

impl DirectoryEntry {
    fn from_attributes(name: String, path: String, attributes: &FileAttributes) -> Self {
        Self {
            name,
            path,
            kind: EntryKind::from_attributes(attributes),
            size: attributes.size,
            permissions: attributes.permissions,
            modified: attributes.mtime,
            uid: attributes.uid,
            user: attributes.user.clone(),
            gid: attributes.gid,
            group: attributes.group.clone(),
        }
    }

    /// The `drwxr-xr-x` a file manager shows, where the server reported the
    /// mode bits.
    #[must_use]
    pub fn mode_string(&self) -> Option<String> {
        self.permissions.map(|mode| mode_string(self.kind, mode))
    }
}

/// Renders POSIX mode bits the way `ls -l` does.
///
/// Here rather than in the interface because it is the same nine bits in every
/// pane, and because the set-user-id, set-group-id and sticky bits are the ones
/// a person actually scans a listing for — an interface that formatted the low
/// nine bits alone would quietly hide a set-user-id binary.
#[must_use]
pub fn mode_string(kind: EntryKind, mode: u32) -> String {
    let mut out = String::with_capacity(10);
    out.push(match kind {
        EntryKind::Directory => 'd',
        EntryKind::Symlink => 'l',
        EntryKind::File => '-',
        EntryKind::Other => '?',
    });

    // The triples, then the three bits that overload the execute position:
    // set-user-id (04000), set-group-id (02000) and sticky (01000), each shown
    // as `s`/`t` when the matching execute bit is set and `S`/`T` when it is
    // not — the distinction that says whether the bit does anything.
    let special = [(0o4000, 's', 'S'), (0o2000, 's', 'S'), (0o1000, 't', 'T')];
    for (index, shift) in [6, 3, 0].into_iter().enumerate() {
        out.push(if mode & (0o4 << shift) == 0 { '-' } else { 'r' });
        out.push(if mode & (0o2 << shift) == 0 { '-' } else { 'w' });
        let executable = mode & (0o1 << shift) != 0;
        let (bit, set, unset) = special.get(index).copied().unwrap_or((0, 'x', '-'));
        out.push(match (mode & bit != 0, executable) {
            (true, true) => set,
            (true, false) => unset,
            (false, true) => 'x',
            (false, false) => '-',
        });
    }
    out
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

/// The most bytes a path crossing into this module may have.
///
/// `PATH_MAX` on every server this will meet. The cap is not about the server —
/// which will refuse an over-long path itself — but about not spending a round
/// trip, and a megabyte of channel window, on a request that cannot succeed.
pub const MAX_PATH_BYTES: usize = 4096;

/// Checks a remote path before it is put on the wire.
///
/// Deliberately permissive about what a *name* may contain: POSIX forbids only
/// `/` and NUL inside one, so a file legitimately called `weird\u{0007}name`
/// exists and a pane that refused to `stat` it would be a pane that cannot
/// manage the files that are there. What is refused is what cannot be a path at
/// all — and NUL in particular, which C-implemented servers and log writers
/// treat as the end of the string, so a path of `safe\u{0000}/../../etc` reads
/// as two different things to two different readers.
///
/// # Errors
///
/// [`ProtocolError::SettingInvalid`] naming `path`.
pub fn validate_remote_path(path: &str) -> Result<(), ProtocolError> {
    let invalid = |expected: &'static str| ProtocolError::SettingInvalid {
        key: "path".to_owned(),
        expected,
    };
    if path.is_empty() {
        return Err(invalid("a path, rather than nothing"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(invalid("a path of at most 4096 bytes"));
    }
    if path.contains('\0') {
        return Err(invalid("a path with no NUL byte in it"));
    }
    Ok(())
}

/// What is wrong with a name the far end chose.
///
/// None of these makes a name illegal — every one of them is a name that exists
/// on somebody's disk. They are the difference between rendering a listing and
/// rendering a listing the user can trust, and the interface shows a badge for
/// each rather than silently hiding the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NameRisks {
    /// Holds a C0/C1 control character or DEL. Truncates log lines, moves the
    /// cursor, and in a terminal can rewrite what was already printed.
    pub control: bool,
    /// Holds a bidirectional override or isolate. `report\u{202E}fdp.exe`
    /// renders as `reportexe.pdf` — the Trojan Source trick (CVE-2021-42574),
    /// applied to a file listing.
    pub bidi: bool,
    /// Holds a zero-width or otherwise invisible character, so two rows can
    /// look identical and be different files.
    pub invisible: bool,
    /// Is not a single path component: it holds a separator, or it is `.` or
    /// `..`. A server that sends one is trying to make a click on a listing
    /// row touch something outside the directory being listed.
    pub separator: bool,
}

impl NameRisks {
    /// Whether the name is exactly what it appears to be.
    #[must_use]
    pub const fn is_clean(self) -> bool {
        !self.control && !self.bidi && !self.invisible && !self.separator
    }

    /// Whether the name may be joined onto a directory path.
    ///
    /// The other three risks are cosmetic; this one is not.
    #[must_use]
    pub const fn is_component(self) -> bool {
        !self.separator
    }
}

/// A name as it may be shown, and what was wrong with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeName {
    /// The rendering. Every character that could lie about the rest has been
    /// replaced by an escape, so this string is safe to put in a table cell, a
    /// dialog or a log line — and is **never** put back on the wire.
    pub display: String,
    /// What was found.
    pub risks: NameRisks,
}

/// Separates what a server-supplied name looks like from what it is.
///
/// The escape is `\u{XXXX}`, which is unambiguous in one direction only: a file
/// genuinely named `\u{0041}` displays as itself and cannot be told apart from
/// one named `A`. That is acceptable precisely because the display form is
/// never used to address anything — [`DirectoryEntry::name`] is what goes back
/// to the server. Reversing this rule is how a file manager gets talked into
/// deleting the wrong file.
#[must_use]
pub fn safe_name(name: &str) -> SafeName {
    let mut risks = NameRisks {
        separator: name.contains('/') || name.contains('\\') || name == "." || name == "..",
        ..NameRisks::default()
    };
    let display = escape_into(name, &mut risks);
    SafeName { display, risks }
}

/// The display form of any server-supplied text: a name, a whole path, an
/// owner, a group, or the `detail` of a progress event.
///
/// Path separators are left alone — a path is meant to have them — so this is
/// [`safe_name`] without the component check, and it is the function to reach
/// for whenever remote text is going somewhere a human will read it.
#[must_use]
pub fn escape_untrusted(text: &str) -> String {
    escape_into(text, &mut NameRisks::default())
}

fn escape_into(text: &str, risks: &mut NameRisks) -> String {
    let mut display = String::with_capacity(text.len());
    for character in text.chars() {
        let hazard = match character {
            // C0, C1 and DEL.
            c if c.is_control() => {
                risks.control = true;
                true
            }
            // Bidirectional overrides, embeddings and isolates: U+061C,
            // U+200E/200F, U+202A..U+202E, U+2066..U+2069 (Unicode §2.10).
            '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}' => {
                risks.bidi = true;
                true
            }
            // Zero-width and other characters that occupy no space: two rows
            // that look identical and are not.
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}' => {
                risks.invisible = true;
                true
            }
            _ => false,
        };
        if hazard {
            display.push_str(&format!("\\u{{{:04X}}}", character as u32));
        } else {
            display.push(character);
        }
    }
    display
}

// ============================================================== removal ====

/// The most entries one recursive removal may touch.
///
/// A removal that has already dealt with a quarter of a million things and is
/// still going has met something nobody meant to point it at. Stopping with a
/// report is recoverable; carrying on is not.
pub const MAX_DELETE_ENTRIES: u64 = 250_000;

/// How deep a recursive removal descends before it refuses.
pub const MAX_DELETE_DEPTH: usize = 64;

/// The failure a walk that hit [`MAX_DELETE_DEPTH`] reports.
const TREE_TOO_DEEP: &str = "the directory tree is deeper than a recursive delete will descend";

/// The failure a listing entry that is not a single path component reports.
const NAME_NOT_A_COMPONENT: &str =
    "the server listed an entry whose name is not a single path component";

/// One thing a removal could not remove.
#[derive(Debug)]
pub struct DeleteFailure {
    /// What it was trying to remove. Server-supplied, so it is escaped with
    /// [`escape_untrusted`] before it is shown.
    pub path: String,
    /// Why it could not, in the failure taxonomy's terms.
    pub reason: ProtocolError,
}

/// What a removal actually did.
///
/// A file manager that says "done" after removing nine of twelve files has
/// lied, so a walk reports what it managed rather than returning a bare `Ok`.
#[derive(Debug, Default)]
pub struct DeleteReport {
    /// Files, links, sockets and devices unlinked.
    pub files_removed: u64,
    /// Directories removed.
    pub directories_removed: u64,
    /// Everything that could not be removed, and why.
    pub failures: Vec<DeleteFailure>,
    /// Whether the user stopped it part way.
    pub cancelled: bool,
    /// Whether it stopped at [`MAX_DELETE_ENTRIES`].
    pub limit_reached: bool,
}

impl DeleteReport {
    /// Whether everything asked for was removed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty() && !self.cancelled && !self.limit_reached
    }

    /// How much the walk has dealt with, one way or another.
    #[must_use]
    pub fn touched(&self) -> u64 {
        self.files_removed
            .saturating_add(self.directories_removed)
            .saturating_add(self.failures.len() as u64)
    }
}

/// One item of work in a recursive removal.
enum DeleteStep {
    /// List this directory and queue what is in it.
    List { path: String, depth: usize },
    /// Remove this directory, now that its children are gone.
    Remove { path: String },
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

    /// Wraps a raw value, for reading an id back from the interface.
    ///
    /// Naming a transfer that does not exist is not an error here: the queue
    /// answers `None` for it, which is the same answer as for one that has
    /// been forgotten.
    #[must_use]
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
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

/// What a transfer settled before it moved a byte.
///
/// The resume decision above all. [`resume_offset`] refuses more often than a
/// user expects, and a file manager that quietly started over would leave
/// someone watching a bar they believed was a resume. Reported so the interface
/// can say "starting over: the local file is not shorter than the remote one",
/// which is a sentence somebody can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferStart {
    /// Whether the request asked to continue rather than start over.
    pub resume_requested: bool,
    /// The offset it actually began at. Zero when no resume was asked for, and
    /// zero when one was asked for and declined.
    pub resume_from: u64,
    /// How much of the destination was already there.
    pub destination_len: u64,
    /// The source's size, where the source reported one.
    pub total: Option<u64>,
}

impl TransferStart {
    /// Whether a resume was asked for and refused.
    ///
    /// An empty destination is not a refusal: there was nothing to continue,
    /// which is the ordinary first attempt and not worth telling anyone about.
    /// Saying "starting over" there would train people to ignore the notice
    /// that matters.
    #[must_use]
    pub const fn resume_declined(&self) -> bool {
        self.resume_requested && self.resume_from == 0 && self.destination_len > 0
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
    /// What it decided when it began. `None` until it does.
    pub start: Option<TransferStart>,
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
                start: None,
            },
            cancel: CancellationToken::new(),
        });
        id
    }

    /// Queues a fresh transfer from a finished one's request.
    ///
    /// The finished entry is left exactly as it is: a terminal state stays
    /// terminal, so the history of what happened stays readable rather than
    /// being overwritten by the attempt that followed it.
    ///
    /// `None` when there is no such transfer, or when it has not finished —
    /// there is nothing to retry about a transfer that is still moving bytes.
    pub fn retry(&self, id: TransferId) -> Option<TransferId> {
        let request = {
            let entries = self.entries.lock();
            let entry = entries.iter().find(|entry| entry.status.id == id)?;
            if !entry.status.state.is_terminal() {
                return None;
            }
            entry.status.request.clone()
        };
        // The lock is released first: `enqueue` takes it again.
        Some(self.enqueue(request))
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

    fn set_start(&self, id: TransferId, start: TransferStart) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|entry| entry.status.id == id) {
            entry.status.start = Some(start);
        }
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
                DirectoryEntry::from_attributes(entry.file_name(), entry.path(), &entry.metadata())
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
        Ok(DirectoryEntry::from_attributes(
            path.rsplit('/').next().unwrap_or(path).to_owned(),
            path.to_owned(),
            &metadata,
        ))
    }

    /// Reads one entry's metadata **without** following symbolic links.
    ///
    /// What a file manager needs before it deletes something: `metadata` on a
    /// symbolic link describes what the link points at, and deciding whether to
    /// recurse from that is how a link to `/` becomes a recursive delete of the
    /// filesystem.
    ///
    /// # Errors
    ///
    /// Whatever the server reported.
    pub async fn symlink_metadata(&self, path: &str) -> Result<DirectoryEntry, ProtocolError> {
        let metadata = self
            .session
            .symlink_metadata(path)
            .await
            .map_err(|error| map_sftp(&error))?;
        Ok(DirectoryEntry::from_attributes(
            path.rsplit('/').next().unwrap_or(path).to_owned(),
            path.to_owned(),
            &metadata,
        ))
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

    /// Removes a directory and everything under it.
    ///
    /// `SSH_FXP_RMDIR` fails on a non-empty directory
    /// (`draft-ietf-secsh-filexfer-02` §6.11), so a recursive removal is a walk
    /// — and a walk that is interrupted leaves the tree half-removed. Hence a
    /// report rather than an `Ok`, and hence the two bounds: a walk that has
    /// touched [`MAX_DELETE_ENTRIES`] or descended [`MAX_DELETE_DEPTH`] stops
    /// and says so.
    ///
    /// **Child paths are composed here, from the entry's name.** The `path` a
    /// server puts in a listing is a string of its choosing; honouring it would
    /// let a listing of `/tmp/scratch` return an entry called `../../etc` and
    /// have this walk unlink it. Any name that is not a single component is
    /// refused and recorded instead.
    ///
    /// Symbolic links are unlinked, never followed. Descending into one is how
    /// a link to `/` becomes a recursive delete of the whole filesystem.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SettingInvalid`] if `path` is not usable, or whatever
    /// the server said when the root could not even be inspected. Everything
    /// that fails *during* the walk is in the report, not in the `Err`.
    pub async fn remove_tree(
        &self,
        path: &str,
        cancel: &CancellationToken,
    ) -> Result<DeleteReport, ProtocolError> {
        validate_remote_path(path)?;
        let mut report = DeleteReport::default();

        // `symlink_metadata`, not `metadata`: a link to a directory is a link,
        // and unlinking it is the whole of the work.
        let root = self.symlink_metadata(path).await?;
        if root.kind != EntryKind::Directory {
            self.remove_file(path).await?;
            report.files_removed = 1;
            return Ok(report);
        }

        // An explicit stack rather than recursion: an async function that calls
        // itself needs boxing at every level, and the stack is also where the
        // depth bound naturally lives. Each directory is pushed twice — listed
        // first, removed after its children, because of §6.11.
        let mut stack = vec![DeleteStep::List {
            path: path.to_owned(),
            depth: 0,
        }];

        while let Some(step) = stack.pop() {
            if cancel.is_cancelled() {
                report.cancelled = true;
                break;
            }
            if report.touched() >= MAX_DELETE_ENTRIES {
                report.limit_reached = true;
                break;
            }

            match step {
                DeleteStep::List { path, depth } => {
                    if depth >= MAX_DELETE_DEPTH {
                        report.failures.push(DeleteFailure {
                            path,
                            reason: ProtocolError::ProtocolViolation {
                                detail: TREE_TOO_DEEP,
                            },
                        });
                        continue;
                    }
                    let entries = match self.list(&path, cancel).await {
                        Ok(entries) => entries,
                        Err(ProtocolError::Cancelled) => {
                            report.cancelled = true;
                            break;
                        }
                        Err(reason) => {
                            report.failures.push(DeleteFailure { path, reason });
                            continue;
                        }
                    };

                    stack.push(DeleteStep::Remove { path: path.clone() });
                    for entry in entries {
                        if !safe_name(&entry.name).risks.is_component() {
                            // A report line, not an address: nothing is done
                            // with this path but show it.
                            report.failures.push(DeleteFailure {
                                path: join_path(&path, &escape_untrusted(&entry.name)),
                                reason: ProtocolError::ProtocolViolation {
                                    detail: NAME_NOT_A_COMPONENT,
                                },
                            });
                            continue;
                        }
                        let child = join_path(&path, &entry.name);
                        if entry.kind == EntryKind::Directory {
                            stack.push(DeleteStep::List {
                                path: child,
                                depth: depth.saturating_add(1),
                            });
                        } else {
                            match self.remove_file(&child).await {
                                Ok(()) => report.files_removed += 1,
                                Err(reason) => report.failures.push(DeleteFailure {
                                    path: child,
                                    reason,
                                }),
                            }
                        }
                    }
                }
                DeleteStep::Remove { path } => match self.remove_directory(&path).await {
                    Ok(()) => report.directories_removed += 1,
                    Err(reason) => report.failures.push(DeleteFailure { path, reason }),
                },
            }
        }

        Ok(report)
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
    /// `on_start` is called once, before a byte moves, with what the transfer
    /// decided — the resume offset in particular, which is refused far more
    /// often than a caller expects. `on_progress` is called every
    /// [`PROGRESS_INTERVAL_BYTES`] and once at the end.
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
        on_start: impl FnOnce(TransferStart),
        mut on_progress: impl FnMut(u64, Option<u64>),
    ) -> Result<u64, ProtocolError> {
        match request.direction {
            TransferDirection::Download => {
                self.download(request, events, cancel, on_start, &mut on_progress)
                    .await
            }
            TransferDirection::Upload => {
                self.upload(request, events, cancel, on_start, &mut on_progress)
                    .await
            }
        }
    }

    async fn download(
        &self,
        request: &TransferRequest,
        events: Option<&EventSink>,
        cancel: &CancellationToken,
        on_start: impl FnOnce(TransferStart),
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
        on_start(TransferStart {
            resume_requested: request.resume,
            resume_from: offset,
            destination_len: existing,
            total,
        });

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
        on_start: impl FnOnce(TransferStart),
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
        on_start(TransferStart {
            resume_requested: request.resume,
            resume_from: offset,
            destination_len: existing,
            total,
        });

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
        on_start: &mut (dyn FnMut(TransferStart) + Send),
        on_progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
    ) -> impl Future<Output = Result<u64, ProtocolError>>;
}

impl Transferrer for SftpBrowser {
    async fn transfer(
        &self,
        request: &TransferRequest,
        events: Option<&EventSink>,
        cancel: &CancellationToken,
        on_start: &mut (dyn FnMut(TransferStart) + Send),
        on_progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
    ) -> Result<u64, ProtocolError> {
        Self::transfer(self, request, events, cancel, on_start, on_progress).await
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

        // Both tokens are raced rather than checked between files. A closed tab
        // has to stop a transfer in flight — CLAUDE.md §5 requires the task to
        // terminate and free its sockets deterministically, and a 40 GB file
        // would otherwise keep moving bytes over a session the user has ended.
        // The per-transfer token is raced for the same reason at a smaller
        // scale: "stop this one" on a stalled connection must not wait for a
        // chunk that may never arrive. Whatever has been written stays on disk,
        // which is what makes a later resume possible ([`resume_offset`]).
        let mut on_start = |start| queue.set_start(id, start);
        let mut on_progress =
            |done, total| queue.set_state(id, TransferState::Running { done, total });
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(ProtocolError::Cancelled),
            () = transfer_cancel.cancelled() => Err(ProtocolError::Cancelled),
            outcome = runner.transfer(
                &request,
                events,
                &transfer_cancel,
                &mut on_start,
                &mut on_progress,
            ) => outcome,
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

/// Drives a file-transfer session until its tab closes.
///
/// The counterpart to [`crate::session::run_ssh_session`], and much smaller: a
/// file pane has no channel producing output on its own, so this loop exists to
/// hold the connection open, to notice the server going away, and to release
/// everything deterministically when the tab goes.
///
/// The panes browsing on this connection are the caller's, and their
/// cancellation tokens are children of `ctx.cancel` — so cancelling this
/// session stops the transfers running under it rather than leaving them
/// writing to disk after the tab has gone.
///
/// # Errors
///
/// Never returns `Err`: every outcome is a [`CloseReason`] the tab shows, which
/// is what the supervisor expects.
pub async fn run_sftp_session(
    connection: Arc<SshConnection>,
    mut ctx: SessionContext,
) -> Result<CloseReason, ProtocolError> {
    let mut probe = tokio::time::interval(CONNECTION_PROBE);
    // The first tick completes immediately, and the connection was alive a
    // moment ago; consuming it here keeps the loop from probing before it has
    // waited once.
    probe.tick().await;

    let reason = loop {
        tokio::select! {
            biased;
            () = ctx.cancel.cancelled() => break CloseReason::ClosedByUser,
            command = ctx.commands.recv() => match command {
                // Every handle is gone, so nothing can drive this session
                // again; holding its channel open would be a leak.
                None | Some(SessionCommand::Disconnect) => break CloseReason::ClosedByUser,
                // A file pane has no keyboard, no window and no clipboard. An
                // interface that sends one of these has a bug worth a line in
                // the log, and the transfers running underneath are not worth
                // ending over it.
                Some(other) => tracing::debug!(
                    ?other,
                    "a file-transfer session was sent a command it has no encoding for"
                ),
            },
            _ = probe.tick() => {
                if connection.is_closed() {
                    break CloseReason::Disconnected;
                }
            }
        }
    };

    if let Err(error) = connection.disconnect().await {
        tracing::debug!(
            stage = error.stage().as_str(),
            "the clean disconnect did not complete"
        );
    }
    Ok(reason)
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
            uid: None,
            user: None,
            gid: None,
            group: None,
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
            on_start: &mut (dyn FnMut(TransferStart) + Send),
            on_progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
        ) -> Result<u64, ProtocolError> {
            on_start(TransferStart {
                resume_requested: false,
                resume_from: 0,
                destination_len: 0,
                total: Some(u64::MAX),
            });
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

    // ------------------------------------------- names the server chose ----

    /// The three tricks a name plays, and the two things that must stay true
    /// of the answer: nothing hostile survives into the display, and the raw
    /// name — the one that goes back on the wire — is never touched.
    #[test]
    fn a_hostile_name_is_declawed_for_display_and_left_alone_on_the_wire() {
        // A right-to-left override: this renders as `annexe.txt` in every
        // toolkit that honours bidi, and it is a `.exe` (CVE-2021-42574
        // applied to a listing).
        let trojan = "annex\u{202E}txt.exe";
        let safe = safe_name(trojan);
        assert!(safe.risks.bidi, "the override was not noticed");
        assert!(!safe.risks.is_clean());
        assert!(
            !safe.display.contains('\u{202E}'),
            "the override reached the display: {:?}",
            safe.display
        );
        assert_eq!(safe.display, "annex\\u{202E}txt.exe");

        // A control byte: truncates a log line, and in a terminal can rewrite
        // what was already printed.
        let noisy = "notes\u{0007}\u{001B}[2Kmalicious";
        let safe = safe_name(noisy);
        assert!(safe.risks.control);
        assert!(!safe.display.contains('\u{001B}'));
        assert!(!safe.display.contains('\u{0007}'));

        // A NUL, which C-implemented readers treat as the end of the string.
        assert!(safe_name("safe\u{0000}/../../etc/passwd").risks.control);

        // A traversal. `russh-sftp` filters `.` and `..` out of a listing but
        // nothing filters this, and `DirEntry::path` would compose it into
        // `/tmp/scratch/../../etc/shadow`.
        for hostile in ["../../etc/shadow", "..", ".", "a/b", "a\\b"] {
            assert!(
                safe_name(hostile).risks.separator,
                "{hostile:?} passed as a single component"
            );
            assert!(!safe_name(hostile).risks.is_component());
        }

        // An ordinary name is left exactly as it is, including the non-ASCII
        // that most of the world's file names are made of.
        for ordinary in ["report.pdf", "Ünterlagen", "日報.txt", "a file.tar.gz"] {
            let safe = safe_name(ordinary);
            assert!(safe.risks.is_clean(), "{ordinary:?} was flagged");
            assert_eq!(safe.display, ordinary);
        }

        // A path keeps its separators: it is meant to have them.
        assert_eq!(
            escape_untrusted("/srv/data/annex\u{202E}txt.exe"),
            "/srv/data/annex\\u{202E}txt.exe"
        );
    }

    #[test]
    fn an_invisible_character_is_shown_because_two_rows_must_not_look_alike() {
        let sneaky = "invoice\u{200B}.pdf";
        let safe = safe_name(sneaky);
        assert!(safe.risks.invisible);
        assert_ne!(safe.display, "invoice.pdf");
        assert_eq!(safe.display, "invoice\\u{200B}.pdf");
    }

    #[test]
    fn a_path_is_refused_only_when_it_cannot_be_a_path() {
        // POSIX forbids `/` and NUL inside a name and nothing else, so a pane
        // that refused the rest could not manage the files that are there.
        assert!(validate_remote_path("/srv/weird\u{0007}name").is_ok());
        assert!(validate_remote_path("/srv/데이터").is_ok());

        for refused in ["", "/srv/data\u{0000}/../etc"] {
            let error = validate_remote_path(refused).unwrap_err();
            assert!(
                matches!(error, ProtocolError::SettingInvalid { ref key, .. } if key == "path"),
                "{refused:?} produced {error:?}"
            );
        }
        assert!(validate_remote_path(&"/".repeat(MAX_PATH_BYTES + 1)).is_err());
    }

    #[test]
    fn the_mode_column_reads_the_way_a_file_manager_shows_it() {
        assert_eq!(mode_string(EntryKind::Directory, 0o755), "drwxr-xr-x");
        assert_eq!(mode_string(EntryKind::File, 0o640), "-rw-r-----");
        assert_eq!(mode_string(EntryKind::Symlink, 0o777), "lrwxrwxrwx");
        // The bits a person actually scans a listing for: set-user-id on
        // `passwd`, and the sticky bit on `/tmp`.
        assert_eq!(mode_string(EntryKind::File, 0o4755), "-rwsr-xr-x");
        assert_eq!(mode_string(EntryKind::Directory, 0o1777), "drwxrwxrwt");
        // Set without the matching execute bit: capitalised, because that says
        // the bit is set and does nothing.
        assert_eq!(mode_string(EntryKind::File, 0o4644), "-rwSr--r--");
        assert_eq!(mode_string(EntryKind::File, 0o2644), "-rw-r-Sr--");

        let directory = DirectoryEntry {
            permissions: Some(0o755),
            kind: EntryKind::Directory,
            ..entry(0, 4)
        };
        assert_eq!(directory.mode_string().as_deref(), Some("drwxr-xr-x"));
        // A server that reported no mode bits leaves the column empty rather
        // than being guessed at.
        assert!(entry(0, 4).mode_string().is_none());
    }

    // ------------------------------------------------ resume and retry ----

    #[test]
    fn a_declined_resume_is_reported_rather_than_hidden() {
        // Something was already there, and it was not usable.
        let declined = TransferStart {
            resume_requested: true,
            resume_from: 0,
            destination_len: 8_192,
            total: Some(4_096),
        };
        assert!(declined.resume_declined());

        let honoured = TransferStart {
            resume_requested: true,
            resume_from: 1_000,
            destination_len: 1_000,
            total: Some(4_096),
        };
        assert!(!honoured.resume_declined());

        // Nothing was there to continue: the ordinary first attempt, and not
        // a notice anybody needs.
        let first_attempt = TransferStart {
            resume_requested: true,
            resume_from: 0,
            destination_len: 0,
            total: Some(4_096),
        };
        assert!(!first_attempt.resume_declined());

        // Never asked for is not the same as asked for and refused.
        let fresh = TransferStart {
            resume_requested: false,
            resume_from: 0,
            destination_len: 0,
            total: None,
        };
        assert!(!fresh.resume_declined());
    }

    #[test]
    fn a_retry_is_a_new_transfer_and_leaves_the_old_one_readable() {
        let queue = TransferQueue::new(1);
        let first = queue.enqueue(request(TransferDirection::Download));

        // Still running: there is nothing to retry yet.
        assert!(queue.take_next().is_some());
        assert!(queue.retry(first).is_none());

        queue.set_state(first, TransferState::Cancelled);
        let second = queue.retry(first).expect("a finished transfer may retry");
        assert_ne!(first, second);

        // The history stays readable: the old entry is exactly as it was.
        assert_eq!(queue.status(first).unwrap().state, TransferState::Cancelled);
        assert_eq!(queue.status(second).unwrap().state, TransferState::Queued);
        assert_eq!(
            queue.status(second).unwrap().request,
            queue.status(first).unwrap().request
        );
        assert!(queue.retry(TransferId(999)).is_none());
    }

    /// Stopping one transfer stops that one and starts the next.
    ///
    /// Checked only between chunks, "stop this one" on a link that has stalled
    /// would wait for a chunk that may never arrive — and a queue whose head is
    /// stuck is a queue, not a stalled transfer.
    #[tokio::test]
    async fn cancelling_one_transfer_releases_the_queue_for_the_next() {
        let queue = Arc::new(TransferQueue::new(1));
        let stuck = queue.enqueue(request(TransferDirection::Download));
        let waiting = queue.enqueue(request(TransferDirection::Upload));
        let cancel = CancellationToken::new();
        let started = Arc::new(tokio::sync::Notify::new());

        let runner = NeverFinishes {
            started: Arc::clone(&started),
        };
        let draining = drain(&runner, &queue, None, &cancel);
        let watching = async {
            // The first transfer is moving; stop it alone.
            started.notified().await;
            queue.cancel(stuck);
            // The second then starts, which is the proof the queue moved on.
            started.notified().await;
            cancel.cancel();
        };

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(draining, watching);
        })
        .await
        .expect("cancelling one transfer did not release the queue");

        assert_eq!(queue.status(stuck).unwrap().state, TransferState::Cancelled);
        assert_eq!(
            queue.status(waiting).unwrap().state,
            TransferState::Cancelled,
            "the session token stopped the second one"
        );
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
