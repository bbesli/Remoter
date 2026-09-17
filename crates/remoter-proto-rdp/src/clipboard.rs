//! The clipboard: MS-RDPECLIP text, in both directions.
//!
//! `ironrdp-cliprdr` implements the channel — its PDUs, its initialisation
//! sequence and the file-stream bookkeeping. What it leaves to its caller is the
//! *clipboard*: what this machine has to offer, when to ask the server for what
//! it copied, and what to do with the answer. That is this module.
//!
//! # Three pieces, and why there are three
//!
//! - [`ClipboardSignals`] is the `CliprdrBackend`, the object the channel calls
//!   back into. It only **records** what it was told. The backend is owned by
//!   the channel and the channel by the active stage, and every answer the
//!   channel expects — a format list, a data request, a data response — is a
//!   method on the channel itself, which a callback running inside it cannot
//!   borrow. So callbacks queue [`Signal`]s and the session drains the queue
//!   after every PDU.
//! - [`ClipboardState`] decides what to do about a signal or a command, as a
//!   list of [`Step`]s, and touches nothing on the wire. It is the part with
//!   decisions in it, and a list of steps is what lets it be tested without a
//!   server.
//! - `crate::session::RdpSession` carries the steps out. It owns the stream,
//!   and every write it makes happens where writing is allowed — never inside a
//!   branch of the read loop's `select!`.
//!
//! # Delayed rendering, in both directions
//!
//! MS-RDPECLIP §1.3.1.4: a copy announces a list of *formats*, and the data
//! moves only when the other side pastes and asks for it.
//!
//! - **Local to remote** keeps that shape. [`ClipboardState::offer`] holds the
//!   text and announces `CF_UNICODETEXT`; the text crosses when something on
//!   the server pastes and the server sends a Format Data Request (§2.2.5.1).
//! - **Remote to local** cannot. The system clipboard on this side is reached
//!   through `arboard`, which has no delayed rendering, so the text is fetched
//!   as soon as the server announces it and handed up as
//!   [`remoter_proto::SessionEvent::ClipboardContent`]. From the outside that is
//!   what `mstsc` looks like: copy on the server, paste on the laptop.
//!
//! # Nothing crosses back the way it came
//!
//! The interface offers the local clipboard whenever the tab takes the
//! keyboard, because that is the last moment before the user might paste into
//! the remote desktop. Without a check that is a defect with a precise shape:
//! the user copies a range of cells in Excel on the server, the text arrives
//! here, the user clicks back into the tab — and the offer of that same text
//! replaces the server's clipboard, so the paste into Excel loses every format
//! but plain text.
//!
//! So the state remembers a **digest** of the text both ends already hold —
//! set when text arrives from the server and when text is offered to it — and
//! an offer of that same text does nothing. The digest is salted per session
//! and the text itself is not kept: the most common thing on an administrator's
//! clipboard is a password.
//!
//! A remote copy with no text in it (an image, a file) leaves the digest where
//! it was. That is deliberate: the local clipboard did not change, and offering
//! it again would replace the image on the server with stale text.
//!
//! # Line endings
//!
//! `CF_UNICODETEXT` ends lines with CRLF. [`remoter_proto::ClipboardData::Text`]
//! is written with LF, which is what RFB carries too and what every platform
//! but Windows uses; `remoter-ipc` puts the CRs back when it writes the Windows
//! clipboard.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironrdp::cliprdr::backend::CliprdrBackend;
use ironrdp::cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardFormatName, ClipboardGeneralCapabilityFlags,
    FileContentsRequest, FileContentsResponse, FileDescriptor, FormatDataRequest,
    FormatDataResponse, LockDataId, OwnedFormatDataResponse,
};
use remoter_proto::{ClipboardFiles, ClipboardPolicy, ProtocolError};

use crate::clipboard_files::LocalFileSet;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// The largest clipboard PDU this build will reassemble.
///
/// A Format Data Response carrying text is the text in UTF-16 plus an eight-byte
/// header (MS-RDPECLIP §2.2.5.2), so sixteen megabytes is about eight of text:
/// twice the four the system clipboard will hand a remote session in the other
/// direction, and more than anyone copies out of a remote window on purpose.
///
/// **A PDU above it is dropped, not fatal.** Every other static channel's
/// ceiling ends the session, because nothing legitimate reaches it. This one is
/// reached by a user who selects a whole log file on the server and presses
/// Ctrl+C — and ending their desktop session for it would be absurd. See
/// `crate::framed::Reassembly::discard_oversized`, which refuses the PDU on its
/// first chunk by the total it declares, before `ironrdp-svc` has accumulated a
/// byte of it.
pub const MAX_CLIPBOARD_PDU_BYTES: u32 = 16 * 1024 * 1024;

/// The most text an offer will carry to the server, in UTF-8 bytes.
///
/// The same figure `remoter-ipc` applies when it reads the system clipboard,
/// held here as well so that the adapter does not depend on its caller to
/// bound what it announces.
pub const MAX_OFFER_BYTES: usize = 4 * 1024 * 1024;

/// How long the server gets to open the clipboard channel before an offer that
/// cannot be delivered is reported.
///
/// `rdpclip.exe`, which answers the channel on a Windows host, starts with the
/// user's logon rather than with the connection — so for the first seconds of
/// every session the channel is silent for an innocent reason. A minute is well
/// past any ordinary logon; a server still silent after it has almost always
/// been told by policy not to redirect the clipboard.
pub const CHANNEL_GRACE: Duration = Duration::from_secs(60);

/// The catalogue key surfaced when clipboard text was too large to carry.
pub const WARNING_CLIPBOARD_TOO_LARGE: &str = "rdp.clipboard_too_large";

/// The catalogue key surfaced when the server never opened its clipboard.
pub const WARNING_CLIPBOARD_UNAVAILABLE: &str = "rdp.clipboard_unavailable";

/// A policy that allows nothing, under which the channel is not requested at
/// all.
pub const NO_CLIPBOARD: ClipboardPolicy = ClipboardPolicy {
    text_to_remote: false,
    text_from_remote: false,
    files: false,
};

/// How many signals may wait for the session to drain them.
///
/// The session drains after every PDU and each PDU produces one callback, so
/// the queue holds one or two in practice. The bound exists so that a defect in
/// that assumption is a dropped signal and a log line rather than a buffer that
/// grows with the server's traffic.
const MAX_QUEUED_SIGNALS: usize = 64;

/// How many of this client's file lists the server may hold locked at once.
///
/// A Lock Clipboard Data PDU (§2.2.4.1) asks this side to keep serving a list
/// after the clipboard has moved on, and the server chooses how many to send.
/// `ironrdp-cliprdr` stops at the same number for its own snapshots.
const MAX_LOCKED_OFFERS: usize = 100;

/// What the channel told the backend, in the order it said it.
pub enum Signal {
    /// The server sent Monitor Ready (§2.2.2.2); the client's first Format List
    /// is owed, bundled with its capabilities.
    FormatListOwed,
    /// The server accepted that first list. The channel is usable.
    Ready,
    /// The server's clipboard changed (§2.2.3.1), and what is on it.
    RemoteCopied {
        /// `CF_UNICODETEXT` is on offer.
        unicode: bool,
        /// `CF_TEXT` is on offer.
        ansi: bool,
        /// The id the server gave `FileGroupDescriptorW`, when files are on
        /// offer (§1.3.1.2: the format is known by its name, not its id).
        file_list: Option<ClipboardFormatId>,
    },
    /// Something on the server pasted and wants this client's data (§2.2.5.1).
    DataRequested(ClipboardFormatId),
    /// The answer to this client's own request (§2.2.5.2). `None` when the
    /// server answered with `CB_RESPONSE_FAIL`.
    DataArrived(Option<Zeroizing<Vec<u8>>>),
    /// The server's file list, already stripped of absolute paths and `..` by
    /// `ironrdp-cliprdr`, and the lock it took on that list if it took one.
    RemoteFiles {
        /// The entries, in the order file requests index them.
        files: Vec<FileDescriptor>,
        /// The `clipDataId` of the lock (§2.2.4.1).
        clip_data_id: Option<u32>,
    },
    /// Something on the server is pasting a file this client offered and
    /// wants a piece of it (§2.2.5.3).
    FileContentsRequested(FileContentsRequest),
    /// A piece of a file this client asked for (§2.2.5.4). `None` on failure.
    FileContentsArrived {
        /// Which request it answers.
        stream_id: u32,
        /// The bytes.
        data: Option<Zeroizing<Vec<u8>>>,
    },
    /// The server locked this client's current file list (§2.2.4.1).
    Locked(u32),
    /// And released it (§2.2.4.2).
    Unlocked(u32),
}

impl core::fmt::Debug for Signal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FormatListOwed => f.write_str("FormatListOwed"),
            Self::Ready => f.write_str("Ready"),
            Self::RemoteCopied {
                unicode,
                ansi,
                file_list,
            } => f
                .debug_struct("RemoteCopied")
                .field("unicode", unicode)
                .field("ansi", ansi)
                .field("files", &file_list.is_some())
                .finish(),
            Self::DataRequested(format) => write!(f, "DataRequested({})", format.value()),
            // What the server copied is the user's clipboard. The length is
            // enough to debug a transfer with.
            Self::DataArrived(data) => match data {
                Some(bytes) => write!(f, "DataArrived(<redacted, {} bytes>)", bytes.len()),
                None => f.write_str("DataArrived(failed)"),
            },
            Self::RemoteFiles { files, .. } => write!(f, "RemoteFiles(<{} entries>)", files.len()),
            Self::FileContentsRequested(request) => write!(
                f,
                "FileContentsRequested(stream {}, index {})",
                request.stream_id, request.index
            ),
            Self::FileContentsArrived { stream_id, data } => match data {
                Some(bytes) => write!(
                    f,
                    "FileContentsArrived(stream {stream_id}, <redacted, {} bytes>)",
                    bytes.len()
                ),
                None => write!(f, "FileContentsArrived(stream {stream_id}, failed)"),
            },
            Self::Locked(id) => write!(f, "Locked({id})"),
            Self::Unlocked(id) => write!(f, "Unlocked({id})"),
        }
    }
}

/// The channel's backend: a recorder of what it was told.
pub struct ClipboardSignals {
    queue: VecDeque<Signal>,
    files: bool,
}

impl ClipboardSignals {
    /// A backend for a connection that does, or does not, let files cross.
    #[must_use]
    pub const fn new(files: bool) -> Self {
        Self {
            queue: VecDeque::new(),
            files,
        }
    }

    /// Everything recorded since the last call, oldest first.
    pub fn take(&mut self) -> VecDeque<Signal> {
        core::mem::take(&mut self.queue)
    }

    fn push(&mut self, signal: Signal) {
        if self.queue.len() >= MAX_QUEUED_SIGNALS {
            tracing::debug!(
                ?signal,
                "the clipboard signal queue is full; dropping a signal"
            );
            return;
        }
        self.queue.push_back(signal);
    }
}

impl core::fmt::Debug for ClipboardSignals {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClipboardSignals")
            .field("queued", &self.queue.len())
            .field("files", &self.files)
            .finish()
    }
}

ironrdp::core::impl_as_any!(ClipboardSignals);

impl CliprdrBackend for ClipboardSignals {
    /// §2.2.2.3's `wszTempDir`. The server builds paths from it only when
    /// `CB_FILECLIP_NO_FILE_PATHS` is not set, and this client sets it
    /// whenever files may cross — so the client's directory layout is not
    /// disclosed for nothing.
    fn temporary_directory(&self) -> &str {
        ""
    }

    /// Text needs no general capability flag (§2.2.2.1.1.1). Files need file
    /// streams, a promise that no source path travels with a name, locking so
    /// that a paste in progress survives the clipboard moving on, and 64-bit
    /// offsets for anything over 2 GiB. `ironrdp-cliprdr` adds
    /// `CB_USE_LONG_FORMAT_NAMES` itself.
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        if self.files {
            ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
                | ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS
                | ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA
                | ClipboardGeneralCapabilityFlags::HUGE_FILE_SUPPORT_ENABLED
        } else {
            ClipboardGeneralCapabilityFlags::empty()
        }
    }

    fn on_ready(&mut self) {
        self.push(Signal::Ready);
    }

    fn on_request_format_list(&mut self) {
        self.push(Signal::FormatListOwed);
    }

    fn on_process_negotiated_capabilities(
        &mut self,
        _capabilities: ClipboardGeneralCapabilityFlags,
    ) {
        // `ironrdp-cliprdr` keeps the negotiated set and refuses a file request
        // the server did not agree to; nothing here needs its own copy.
    }

    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        let offers = |id: ClipboardFormatId| formats.iter().any(|format| format.id() == id);
        let file_list = formats
            .iter()
            .find(|format| {
                format
                    .name()
                    .is_some_and(|name| name.value() == ClipboardFormatName::FILE_LIST.value())
            })
            .map(ClipboardFormat::id);
        self.push(Signal::RemoteCopied {
            unicode: offers(ClipboardFormatId::CF_UNICODETEXT),
            ansi: offers(ClipboardFormatId::CF_TEXT),
            file_list,
        });
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        self.push(Signal::DataRequested(request.format));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        let data = (!response.is_error()).then(|| Zeroizing::new(response.data().to_vec()));
        self.push(Signal::DataArrived(data));
    }

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        self.push(Signal::FileContentsRequested(request));
    }

    fn on_file_contents_response(&mut self, response: FileContentsResponse<'_>) {
        let data = (!response.is_error()).then(|| Zeroizing::new(response.data().to_vec()));
        self.push(Signal::FileContentsArrived {
            stream_id: response.stream_id(),
            data,
        });
    }

    fn on_lock(&mut self, data_id: LockDataId) {
        self.push(Signal::Locked(data_id.0));
    }

    fn on_unlock(&mut self, data_id: LockDataId) {
        self.push(Signal::Unlocked(data_id.0));
    }

    fn on_remote_file_list(&mut self, files: &[FileDescriptor], clip_data_id: Option<u32>) {
        self.push(Signal::RemoteFiles {
            files: files.to_vec(),
            clip_data_id,
        });
    }
}

/// One thing the session has to do for the clipboard.
pub enum Step {
    /// Send a Format List (§2.2.3.1) naming these formats. During
    /// initialisation `ironrdp-cliprdr` bundles the capabilities and the
    /// temporary directory with it, as §1.3.2.1 orders.
    Announce(Vec<ClipboardFormat>),
    /// Send a Format List offering these files (§2.2.5.2.3).
    AnnounceFiles(Vec<FileDescriptor>),
    /// Ask the server for its clipboard in this format (§2.2.5.1).
    Fetch(ClipboardFormatId),
    /// Answer the server's request (§2.2.5.2).
    Answer(OwnedFormatDataResponse),
    /// Answer a file request from one of this client's file lists.
    Serve {
        /// What the server asked for.
        request: FileContentsRequest,
        /// The list its index belongs to.
        files: Arc<LocalFileSet>,
    },
    /// Answer a file request without reading anything: a failure.
    AnswerFile(FileContentsResponse<'static>),
    /// Hand a piece of a file to the save in progress.
    SaveData {
        /// Which request it answers.
        stream_id: u32,
        /// The bytes, or `None` for a failure.
        data: Option<Zeroizing<Vec<u8>>>,
    },
    /// Hand text the server copied to the layer above, line endings already
    /// LF.
    Deliver(String),
    /// Tell the layer above about files.
    Files(ClipboardFiles),
    /// Tell the user something, by catalogue key.
    Warn(&'static str),
}

impl core::fmt::Debug for Step {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Announce(formats) => {
                let ids: Vec<u32> = formats.iter().map(|format| format.id().value()).collect();
                write!(f, "Announce({ids:?})")
            }
            Self::AnnounceFiles(files) => write!(f, "AnnounceFiles(<{} entries>)", files.len()),
            Self::Fetch(format) => write!(f, "Fetch({})", format.value()),
            Self::Answer(response) if response.is_error() => f.write_str("Answer(failed)"),
            Self::Answer(response) => {
                write!(f, "Answer(<redacted, {} bytes>)", response.data().len())
            }
            Self::Serve { request, .. } => write!(
                f,
                "Serve(stream {}, index {})",
                request.stream_id, request.index
            ),
            Self::AnswerFile(response) => {
                write!(f, "AnswerFile(stream {}, failed)", response.stream_id())
            }
            Self::SaveData { stream_id, data } => write!(
                f,
                "SaveData(stream {stream_id}, {})",
                data.as_ref().map_or_else(
                    || String::from("failed"),
                    |bytes| format!("{} bytes", bytes.len())
                )
            ),
            Self::Deliver(text) => {
                write!(f, "Deliver(<redacted, {} chars>)", text.chars().count())
            }
            Self::Files(files) => write!(f, "Files({files:?})"),
            Self::Warn(key) => write!(f, "Warn({key})"),
        }
    }
}

/// What this client asked the server for and is still waiting on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Awaited {
    /// Text, in this format.
    Text(ClipboardFormatId),
    /// The file list.
    FileList,
}

/// What the clipboard knows, and what it decides.
pub struct ClipboardState {
    policy: ClipboardPolicy,
    /// Whether the server joined the channel at all. One that did not will
    /// never send Monitor Ready.
    joined: bool,
    opened_at: Instant,
    /// Salt for [`ClipboardState::settled`], so the digest of a copied password
    /// is not the same number in every session and every process.
    salt: [u8; 32],
    /// The channel finished initialising.
    ready: bool,
    /// The text on offer, in its wire form: CRLF line endings.
    local: Option<Zeroizing<String>>,
    /// The files on offer instead, when those are what was copied.
    local_files: Option<Arc<LocalFileSet>>,
    /// Earlier file lists the server locked, by `clipDataId`.
    locked: BTreeMap<u32, Arc<LocalFileSet>>,
    /// Whether the current offer is in the Format List the server holds.
    announced: bool,
    /// The digest of what both ends already hold. See the module header.
    settled: Option<[u8; 32]>,
    /// Which text format the server's latest copy carries, if any.
    remote_text: Option<ClipboardFormatId>,
    /// The server's file list, once fetched, and the lock it took on it.
    remote_files: Option<(Vec<FileDescriptor>, Option<u32>)>,
    /// A file list still to fetch once the text request in flight answers:
    /// `ironrdp-cliprdr` matches a response to the one request it remembers.
    queued_file_list: Option<ClipboardFormatId>,
    /// This client's own request still in flight.
    awaiting: Option<Awaited>,
    /// Whether [`WARNING_CLIPBOARD_UNAVAILABLE`] has been said.
    unavailable_said: bool,
}

impl core::fmt::Debug for ClipboardState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClipboardState")
            .field("policy", &self.policy)
            .field("joined", &self.joined)
            .field("ready", &self.ready)
            .field("offering_text", &self.local.is_some())
            .field("offering_files", &self.local_files.is_some())
            .field("announced", &self.announced)
            .field("awaiting", &self.awaiting)
            .finish_non_exhaustive()
    }
}

impl ClipboardState {
    /// A clipboard for a session that has just attached.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Internal`] if the platform's random number generator
    /// fails, which leaves no salt to hash with.
    pub fn new(policy: ClipboardPolicy, joined: bool, now: Instant) -> Result<Self, ProtocolError> {
        let mut salt = [0_u8; 32];
        getrandom::fill(&mut salt).map_err(|_| ProtocolError::Internal {
            detail: "the platform random number generator failed",
        })?;
        Ok(Self {
            policy,
            joined,
            opened_at: now,
            salt,
            ready: false,
            local: None,
            local_files: None,
            locked: BTreeMap::new(),
            announced: false,
            settled: None,
            remote_text: None,
            remote_files: None,
            queued_file_list: None,
            awaiting: None,
            unavailable_said: false,
        })
    }

    /// Whether the channel has finished initialising.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.ready
    }

    /// What this connection lets cross.
    #[must_use]
    pub const fn policy(&self) -> ClipboardPolicy {
        self.policy
    }

    /// The server's file list and the lock on it, when there is one to save.
    #[must_use]
    pub fn remote_files(&self) -> Option<(&[FileDescriptor], Option<u32>)> {
        self.remote_files
            .as_ref()
            .map(|(files, clip_data_id)| (files.as_slice(), *clip_data_id))
    }

    /// Whether files are in play in either direction, which is what decides
    /// whether the channel's timers need driving.
    #[must_use]
    pub fn holds_files(&self) -> bool {
        self.remote_files.is_some() || self.local_files.is_some() || !self.locked.is_empty()
    }

    /// Acts on one thing the channel said.
    pub fn on_signal(&mut self, signal: Signal) -> Vec<Step> {
        match signal {
            Signal::FormatListOwed => {
                // §1.3.2.1: the client's capabilities, temporary directory and
                // first Format List, in that order, once Monitor Ready is in.
                // Text offered before the server was listening goes into that
                // first list rather than being lost. Files cannot: a file list
                // needs the channel ready, so they wait for `Ready`.
                self.announced = self.local.is_some();
                vec![Step::Announce(self.formats_on_offer())]
            }
            Signal::Ready => {
                self.ready = true;
                if self.announced {
                    return Vec::new();
                }
                if self.local.is_some() {
                    self.announced = true;
                    vec![Step::Announce(self.formats_on_offer())]
                } else if let Some(files) = &self.local_files {
                    self.announced = true;
                    vec![Step::AnnounceFiles(files.descriptors())]
                } else {
                    Vec::new()
                }
            }
            Signal::RemoteCopied {
                unicode,
                ansi,
                file_list,
            } => {
                // The server's clipboard owns the content now, so whatever this
                // client had on offer is no longer what a paste there gets.
                // Holding the text any longer would keep it in memory for
                // nothing. A file list the server locked stays in `locked`.
                self.local = None;
                self.local_files = None;
                self.announced = false;
                self.awaiting = None;
                self.remote_text = if unicode {
                    Some(ClipboardFormatId::CF_UNICODETEXT)
                } else if ansi {
                    Some(ClipboardFormatId::CF_TEXT)
                } else {
                    None
                };
                self.queued_file_list = file_list.filter(|_| self.policy.files);
                let mut steps = Vec::new();
                if self.remote_files.take().is_some() {
                    steps.push(Step::Files(ClipboardFiles::Withdrawn));
                }
                steps.extend(self.fetch());
                steps
            }
            Signal::DataRequested(format) => {
                let answer = match &self.local {
                    Some(text)
                        if format == ClipboardFormatId::CF_UNICODETEXT
                            && self.policy.text_to_remote =>
                    {
                        OwnedFormatDataResponse::new_unicode_string(text)
                    }
                    // A format this client never announced, or text it no
                    // longer holds. §3.1.5.2.3: the answer is a failure, not
                    // silence — a server left waiting holds the pasting
                    // application until its own timeout.
                    _ => OwnedFormatDataResponse::new_error(),
                };
                vec![Step::Answer(answer)]
            }
            Signal::DataArrived(data) => match self.awaiting.take() {
                // An answer to no request, or to one a newer copy superseded.
                // Delivering it would put stale text on the local clipboard.
                None => Vec::new(),
                // The server could not produce its file list after all.
                Some(Awaited::FileList) => Vec::new(),
                Some(Awaited::Text(format)) => {
                    let mut steps = self.deliver(format, data);
                    steps.extend(self.fetch_file_list());
                    steps
                }
            },
            Signal::RemoteFiles {
                files,
                clip_data_id,
            } => {
                if self.awaiting == Some(Awaited::FileList) {
                    self.awaiting = None;
                }
                if !self.policy.files || files.is_empty() {
                    return Vec::new();
                }
                let offer = crate::clipboard_files::offered(&files);
                self.remote_files = Some((files, clip_data_id));
                vec![Step::Files(offer)]
            }
            Signal::FileContentsRequested(request) => {
                let files = request
                    .data_id
                    .and_then(|id| self.locked.get(&id))
                    .or(self.local_files.as_ref())
                    .filter(|_| self.policy.files)
                    .map(Arc::clone);
                match files {
                    Some(files) => vec![Step::Serve { request, files }],
                    None => vec![Step::AnswerFile(FileContentsResponse::new_error(
                        request.stream_id,
                    ))],
                }
            }
            Signal::FileContentsArrived { stream_id, data } => {
                vec![Step::SaveData { stream_id, data }]
            }
            Signal::Locked(id) => {
                if let Some(files) = &self.local_files
                    && self.locked.len() < MAX_LOCKED_OFFERS
                {
                    self.locked.insert(id, Arc::clone(files));
                }
                Vec::new()
            }
            Signal::Unlocked(id) => {
                self.locked.remove(&id);
                Vec::new()
            }
        }
    }

    /// Offers local text to the server.
    ///
    /// Called every time the tab takes the keyboard, so most calls are about
    /// text the server already has and do nothing. See the module header.
    pub fn offer(&mut self, text: &str, now: Instant) -> Vec<Step> {
        if !self.policy.text_to_remote {
            // Not a warning. The offer is made automatically, on focus, and a
            // sentence each time the user clicked into the tab would be noise
            // about a setting they chose.
            return Vec::new();
        }
        let plain = from_wire(text);
        if plain.is_empty() {
            return Vec::new();
        }
        if plain.len() > MAX_OFFER_BYTES {
            return vec![Step::Warn(WARNING_CLIPBOARD_TOO_LARGE)];
        }
        let digest = self.digest(plain.as_bytes());
        if self.settled == Some(digest) {
            return Vec::new();
        }
        self.settled = Some(digest);
        self.local = Some(to_wire(&plain));
        self.local_files = None;
        self.announce(now, None)
    }

    /// Offers local files to the server.
    ///
    /// The same rules as [`ClipboardState::offer`]: offered on focus, so an
    /// offer of the same files — same names, sizes and times — does nothing.
    pub fn offer_files(&mut self, files: LocalFileSet, now: Instant) -> Vec<Step> {
        if !self.policy.files || files.is_empty() {
            return Vec::new();
        }
        let mut identity = b"files\0".to_vec();
        identity.extend_from_slice(&files.identity());
        let digest = self.digest(&identity);
        if self.settled == Some(digest) {
            return Vec::new();
        }
        self.settled = Some(digest);
        let skipped = files.skipped() > 0;
        self.local = None;
        self.local_files = Some(Arc::new(files));
        self.announce(
            now,
            skipped.then_some(crate::clipboard_files::WARNING_FILES_SKIPPED),
        )
    }

    /// Asks the server again for what it copied.
    pub fn request(&mut self) -> Vec<Step> {
        self.fetch()
    }

    /// Withdraws this client's offer.
    pub fn clear(&mut self) -> Vec<Step> {
        self.local = None;
        self.local_files = None;
        self.settled = None;
        if self.announced && self.ready {
            self.announced = false;
            // An empty Format List says the client's clipboard is empty
            // (§2.2.3.1). Sent only while this client's list is the one the
            // server holds, or it would empty a clipboard the server owns.
            return vec![Step::Announce(Vec::new())];
        }
        self.announced = false;
        Vec::new()
    }

    /// A clipboard PDU was dropped for its size before it was reassembled.
    pub fn discarded(&mut self) -> Vec<Step> {
        match self.awaiting.take() {
            Some(Awaited::Text(_)) => vec![Step::Warn(WARNING_CLIPBOARD_TOO_LARGE)],
            Some(Awaited::FileList) => {
                vec![Step::Warn(crate::clipboard_files::WARNING_FILES_TOO_MANY)]
            }
            None => Vec::new(),
        }
    }

    /// Puts the current offer in front of the server, or says why it cannot be.
    fn announce(&mut self, now: Instant, warning: Option<&'static str>) -> Vec<Step> {
        self.announced = false;
        // What this client asked for is no longer what it wants: the offer
        // replaces the server's clipboard, so content still on its way from
        // there would overwrite the local clipboard the user just changed.
        self.awaiting = None;
        self.queued_file_list = None;

        let mut steps: Vec<Step> = warning.into_iter().map(Step::Warn).collect();
        if self.ready {
            self.announced = true;
            match &self.local_files {
                Some(files) => steps.push(Step::AnnounceFiles(files.descriptors())),
                None => steps.push(Step::Announce(self.formats_on_offer())),
            }
            return steps;
        }
        let overdue =
            !self.joined || now.saturating_duration_since(self.opened_at) >= CHANNEL_GRACE;
        if overdue && !self.unavailable_said {
            self.unavailable_said = true;
            steps.push(Step::Warn(WARNING_CLIPBOARD_UNAVAILABLE));
        }
        steps
    }

    fn deliver(
        &mut self,
        format: ClipboardFormatId,
        data: Option<Zeroizing<Vec<u8>>>,
    ) -> Vec<Step> {
        let Some(bytes) = data else {
            return Vec::new();
        };
        if !self.policy.text_from_remote {
            return Vec::new();
        }
        let decoded = if format == ClipboardFormatId::CF_UNICODETEXT {
            decode_unicode(&bytes)
        } else {
            decode_ansi(&bytes)
        };
        let text = from_wire(&decoded);
        if text.is_empty() {
            return Vec::new();
        }
        self.settled = Some(self.digest(text.as_bytes()));
        vec![Step::Deliver(String::from(text.as_str()))]
    }

    /// Asks for the server's text, or for its file list when there is no text
    /// to ask for. One request at a time: see `queued_file_list`.
    fn fetch(&mut self) -> Vec<Step> {
        if !self.ready {
            return Vec::new();
        }
        match self.remote_text {
            Some(format) if self.policy.text_from_remote => {
                self.awaiting = Some(Awaited::Text(format));
                vec![Step::Fetch(format)]
            }
            _ => self.fetch_file_list(),
        }
    }

    fn fetch_file_list(&mut self) -> Vec<Step> {
        if !self.ready || self.awaiting.is_some() {
            return Vec::new();
        }
        match self.queued_file_list.take() {
            Some(format) => {
                self.awaiting = Some(Awaited::FileList);
                vec![Step::Fetch(format)]
            }
            None => Vec::new(),
        }
    }

    fn formats_on_offer(&self) -> Vec<ClipboardFormat> {
        if self.local.is_some() {
            vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]
        } else {
            Vec::new()
        }
    }

    fn digest(&self, bytes: &[u8]) -> [u8; 32] {
        Sha256::new()
            .chain_update(self.salt)
            .chain_update(bytes)
            .finalize()
            .into()
    }
}

/// `CF_UNICODETEXT`: UTF-16LE, ending at the first NUL (§2.2.5.2 carries the
/// terminator, and some servers pad past it).
///
/// An unpaired surrogate becomes U+FFFD rather than failing the paste: the
/// text came from a Windows clipboard, which does not validate it either.
fn decode_unicode(bytes: &[u8]) -> Zeroizing<String> {
    let units: Zeroizing<Vec<u16>> = Zeroizing::new(
        bytes
            .chunks_exact(2)
            .map(|pair| match *pair {
                [low, high] => u16::from_le_bytes([low, high]),
                _ => 0,
            })
            .take_while(|unit| *unit != 0)
            .collect(),
    );
    Zeroizing::new(String::from_utf16_lossy(&units))
}

/// `CF_TEXT`: bytes in the server's ANSI code page, ending at the first NUL.
///
/// A Windows server always offers `CF_UNICODETEXT` alongside it, so this is
/// reached only from a server that offers nothing else — in practice `xrdp`,
/// which sends UTF-8. Read as UTF-8, with anything that is not replaced.
fn decode_ansi(bytes: &[u8]) -> Zeroizing<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let text = bytes.get(..end).unwrap_or_default();
    Zeroizing::new(String::from_utf8_lossy(text).into_owned())
}

/// CRLF to LF.
fn from_wire(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.replace("\r\n", "\n"))
}

/// LF to CRLF, for text that has already been through [`from_wire`].
fn to_wire(plain: &str) -> Zeroizing<String> {
    Zeroizing::new(plain.replace('\n', "\r\n"))
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

    fn state() -> ClipboardState {
        ClipboardState::new(ClipboardPolicy::default(), true, Instant::now()).unwrap()
    }

    /// A state past initialisation, as it is for most of a session.
    fn ready() -> ClipboardState {
        let mut state = state();
        let _ = state.on_signal(Signal::FormatListOwed);
        let _ = state.on_signal(Signal::Ready);
        state
    }

    fn utf16(text: &str) -> Zeroizing<Vec<u8>> {
        let mut bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        bytes.extend_from_slice(&[0, 0]);
        Zeroizing::new(bytes)
    }

    fn announced_text(steps: &[Step]) -> bool {
        matches!(steps, [Step::Announce(formats)]
            if formats.len() == 1 && formats[0].id() == ClipboardFormatId::CF_UNICODETEXT)
    }

    #[test]
    fn the_first_format_list_is_empty_when_nothing_was_offered() {
        let mut state = state();
        let steps = state.on_signal(Signal::FormatListOwed);
        assert!(matches!(&steps[..], [Step::Announce(formats)] if formats.is_empty()));
        assert!(state.on_signal(Signal::Ready).is_empty());
        assert!(state.is_ready());
    }

    #[test]
    fn text_offered_before_the_channel_opened_goes_into_its_first_list() {
        let mut state = state();
        assert!(state.offer("early", Instant::now()).is_empty());
        assert!(announced_text(&state.on_signal(Signal::FormatListOwed)));
        // Already announced, so becoming ready announces nothing twice.
        assert!(state.on_signal(Signal::Ready).is_empty());
    }

    #[test]
    fn text_offered_between_monitor_ready_and_ready_is_announced_on_ready() {
        let mut state = state();
        let _ = state.on_signal(Signal::FormatListOwed);
        assert!(state.offer("between", Instant::now()).is_empty());
        assert!(announced_text(&state.on_signal(Signal::Ready)));
    }

    #[test]
    fn an_offer_is_announced_and_answered_in_crlf_when_the_server_pastes() {
        let mut state = ready();
        assert!(announced_text(&state.offer("one\ntwo", Instant::now())));

        let steps = state.on_signal(Signal::DataRequested(ClipboardFormatId::CF_UNICODETEXT));
        let [Step::Answer(answer)] = &steps[..] else {
            panic!("{steps:?}");
        };
        assert!(!answer.is_error());
        assert_eq!(answer.data(), &utf16("one\r\ntwo")[..]);
    }

    #[test]
    fn a_format_never_announced_is_answered_with_a_failure_not_silence() {
        let mut state = ready();
        let _ = state.offer("text", Instant::now());
        for format in [ClipboardFormatId::CF_TEXT, ClipboardFormatId::CF_DIB] {
            let steps = state.on_signal(Signal::DataRequested(format));
            assert!(matches!(&steps[..], [Step::Answer(answer)] if answer.is_error()));
        }
        // And with nothing on offer at all.
        let mut empty = ready();
        let steps = empty.on_signal(Signal::DataRequested(ClipboardFormatId::CF_UNICODETEXT));
        assert!(matches!(&steps[..], [Step::Answer(answer)] if answer.is_error()));
    }

    #[test]
    fn a_remote_copy_is_fetched_and_delivered_with_lf_line_endings() {
        let mut state = ready();
        let steps = state.on_signal(Signal::RemoteCopied {
            unicode: true,
            ansi: true,
            file_list: None,
        });
        assert!(
            matches!(&steps[..], [Step::Fetch(format)] if *format == ClipboardFormatId::CF_UNICODETEXT)
        );

        let steps = state.on_signal(Signal::DataArrived(Some(utf16("a\r\nb\r\n"))));
        assert!(matches!(&steps[..], [Step::Deliver(text)] if text == "a\nb\n"));
    }

    #[test]
    fn text_that_came_from_the_server_is_not_offered_back_to_it() {
        // The Excel defect in the module header: without this, clicking back
        // into the tab replaces a rich clipboard on the server with plain text.
        let mut state = ready();
        let _ = state.on_signal(Signal::RemoteCopied {
            unicode: true,
            ansi: false,
            file_list: None,
        });
        let _ = state.on_signal(Signal::DataArrived(Some(utf16("cells\r\n"))));

        // The system clipboard on Windows hands it back with CRLF, elsewhere
        // with LF. Both are the same text.
        assert!(state.offer("cells\r\n", Instant::now()).is_empty());
        assert!(state.offer("cells\n", Instant::now()).is_empty());
        assert!(announced_text(
            &state.offer("something new", Instant::now())
        ));
    }

    #[test]
    fn the_same_local_text_is_announced_once() {
        let mut state = ready();
        assert!(announced_text(&state.offer("password", Instant::now())));
        assert!(state.offer("password", Instant::now()).is_empty());
    }

    #[test]
    fn a_remote_copy_without_text_does_not_make_the_old_text_new_again() {
        // An image copied on the server must survive the user clicking back
        // into the tab with unchanged text on the local clipboard.
        let mut state = ready();
        assert!(announced_text(&state.offer("local", Instant::now())));
        let steps = state.on_signal(Signal::RemoteCopied {
            unicode: false,
            ansi: false,
            file_list: None,
        });
        assert!(steps.is_empty());
        assert!(state.offer("local", Instant::now()).is_empty());
        // And the text is no longer held: the server's clipboard owns it now.
        let steps = state.on_signal(Signal::DataRequested(ClipboardFormatId::CF_UNICODETEXT));
        assert!(matches!(&steps[..], [Step::Answer(answer)] if answer.is_error()));
    }

    #[test]
    fn an_answer_to_a_superseded_request_is_not_delivered() {
        let mut state = ready();
        let _ = state.on_signal(Signal::RemoteCopied {
            unicode: true,
            ansi: false,
            file_list: None,
        });
        // The user copied something locally and clicked into the tab before
        // the server answered.
        assert!(announced_text(&state.offer("newer", Instant::now())));
        assert!(
            state
                .on_signal(Signal::DataArrived(Some(utf16("older"))))
                .is_empty()
        );
        assert!(state.on_signal(Signal::DataArrived(None)).is_empty());
    }

    #[test]
    fn the_policy_stops_each_direction_on_its_own() {
        let inbound_only = ClipboardPolicy {
            text_to_remote: false,
            ..ClipboardPolicy::default()
        };
        let mut state = ClipboardState::new(inbound_only, true, Instant::now()).unwrap();
        let _ = state.on_signal(Signal::FormatListOwed);
        let _ = state.on_signal(Signal::Ready);
        assert!(state.offer("secret", Instant::now()).is_empty());
        assert!(
            !state
                .on_signal(Signal::RemoteCopied {
                    unicode: true,
                    ansi: false,
                    file_list: None,
                })
                .is_empty()
        );

        let outbound_only = ClipboardPolicy {
            text_from_remote: false,
            ..ClipboardPolicy::default()
        };
        let mut state = ClipboardState::new(outbound_only, true, Instant::now()).unwrap();
        let _ = state.on_signal(Signal::FormatListOwed);
        let _ = state.on_signal(Signal::Ready);
        assert!(
            state
                .on_signal(Signal::RemoteCopied {
                    unicode: true,
                    ansi: false,
                    file_list: None,
                })
                .is_empty()
        );
        assert!(state.request().is_empty());
        assert!(announced_text(&state.offer("paste me", Instant::now())));
    }

    #[test]
    fn nothing_is_fetched_before_the_channel_is_ready() {
        let mut state = state();
        let steps = state.on_signal(Signal::RemoteCopied {
            unicode: true,
            ansi: false,
            file_list: None,
        });
        assert!(steps.is_empty());
    }

    #[test]
    fn an_ansi_only_clipboard_is_fetched_as_ansi() {
        let mut state = ready();
        let steps = state.on_signal(Signal::RemoteCopied {
            unicode: false,
            ansi: true,
            file_list: None,
        });
        assert!(
            matches!(&steps[..], [Step::Fetch(format)] if *format == ClipboardFormatId::CF_TEXT)
        );
        let steps = state.on_signal(Signal::DataArrived(Some(Zeroizing::new(
            b"caf\xc3\xa9\r\n\0junk".to_vec(),
        ))));
        assert!(matches!(&steps[..], [Step::Deliver(text)] if text == "café\n"));
    }

    #[test]
    fn a_clipboard_too_large_to_carry_is_said_in_both_directions() {
        let mut state = ready();
        let huge = "x".repeat(MAX_OFFER_BYTES + 1);
        assert!(matches!(
            &state.offer(&huge, Instant::now())[..],
            [Step::Warn(WARNING_CLIPBOARD_TOO_LARGE)]
        ));

        let _ = state.on_signal(Signal::RemoteCopied {
            unicode: true,
            ansi: false,
            file_list: None,
        });
        assert!(matches!(
            &state.discarded()[..],
            [Step::Warn(WARNING_CLIPBOARD_TOO_LARGE)]
        ));
        // Once: a second dropped PDU that answers nothing says nothing.
        assert!(state.discarded().is_empty());
    }

    #[test]
    fn a_server_that_never_opens_the_channel_is_reported_once_and_not_at_logon() {
        let start = Instant::now();
        let mut state = ClipboardState::new(ClipboardPolicy::default(), true, start).unwrap();
        // During the logon, silence is innocent.
        assert!(
            state
                .offer("first", start + Duration::from_secs(5))
                .is_empty()
        );
        assert!(matches!(
            &state.offer("second", start + CHANNEL_GRACE)[..],
            [Step::Warn(WARNING_CLIPBOARD_UNAVAILABLE)]
        ));
        assert!(state.offer("third", start + CHANNEL_GRACE * 2).is_empty());

        // A channel the server never joined cannot open later.
        let mut unjoined = ClipboardState::new(ClipboardPolicy::default(), false, start).unwrap();
        assert!(matches!(
            &unjoined.offer("text", start)[..],
            [Step::Warn(WARNING_CLIPBOARD_UNAVAILABLE)]
        ));
    }

    #[test]
    fn clearing_empties_only_a_clipboard_this_client_owns() {
        let mut state = ready();
        let _ = state.offer("mine", Instant::now());
        assert!(matches!(&state.clear()[..], [Step::Announce(formats)] if formats.is_empty()));

        let mut state = ready();
        let _ = state.offer("mine", Instant::now());
        let _ = state.on_signal(Signal::RemoteCopied {
            unicode: true,
            ansi: false,
            file_list: None,
        });
        assert!(state.clear().is_empty());
    }

    #[test]
    fn utf16_decoding_stops_at_the_terminator_and_survives_a_lone_surrogate() {
        let mut bytes = utf16("ok").to_vec();
        bytes.extend_from_slice(&utf16("padding")[..]);
        assert_eq!(decode_unicode(&bytes).as_str(), "ok");

        let lone = [0x3d_u8, 0xd8, b'a', 0];
        assert_eq!(decode_unicode(&lone).as_str(), "\u{fffd}a");
        // An odd trailing byte is not half a character.
        assert_eq!(decode_unicode(&[b'a', 0, b'b']).as_str(), "a");
    }

    #[test]
    fn nothing_here_debug_prints_clipboard_text() {
        let secret = "hunter2-correct-horse";
        let rendered = [
            format!("{:?}", Signal::DataArrived(Some(utf16(secret)))),
            format!("{:?}", Step::Deliver(secret.to_owned())),
            format!(
                "{:?}",
                Step::Answer(OwnedFormatDataResponse::new_unicode_string(secret))
            ),
        ];
        for line in rendered {
            assert!(!line.contains("hunter2"), "{line}");
        }
        let mut state = ready();
        let _ = state.offer(secret, Instant::now());
        assert!(!format!("{state:?}").contains("hunter2"));
    }

    fn with_files() -> ClipboardState {
        let policy = ClipboardPolicy {
            files: true,
            ..ClipboardPolicy::default()
        };
        let mut state = ClipboardState::new(policy, true, Instant::now()).unwrap();
        let _ = state.on_signal(Signal::FormatListOwed);
        let _ = state.on_signal(Signal::Ready);
        state
    }

    fn file_list_id() -> ClipboardFormatId {
        ClipboardFormatId::new(0xC0FE)
    }

    fn descriptor(name: &str, size: u64) -> FileDescriptor {
        FileDescriptor::new(name).with_file_size(size)
    }

    async fn local_files(names: &[&str]) -> (tempfile::TempDir, LocalFileSet) {
        let scratch = tempfile::tempdir().unwrap();
        let paths: Vec<String> = names
            .iter()
            .map(|name| {
                let path = scratch.path().join(name);
                std::fs::write(&path, name.as_bytes()).unwrap();
                path.display().to_string()
            })
            .collect();
        let files = LocalFileSet::collect(&paths).await.unwrap();
        (scratch, files)
    }

    #[test]
    fn a_remote_copy_of_files_asks_for_the_text_first_and_the_list_after() {
        // `ironrdp-cliprdr` remembers one request at a time, so two in flight
        // would have one answer matched to the other.
        let mut state = with_files();
        let steps = state.on_signal(Signal::RemoteCopied {
            unicode: true,
            ansi: false,
            file_list: Some(file_list_id()),
        });
        assert!(
            matches!(&steps[..], [Step::Fetch(format)] if *format == ClipboardFormatId::CF_UNICODETEXT)
        );

        let steps = state.on_signal(Signal::DataArrived(Some(utf16("names"))));
        assert!(
            matches!(&steps[..], [Step::Deliver(_), Step::Fetch(format)] if *format == file_list_id())
        );

        let steps = state.on_signal(Signal::RemoteFiles {
            files: vec![descriptor("a.txt", 3), descriptor("b.txt", 4)],
            clip_data_id: Some(9),
        });
        assert!(matches!(
            &steps[..],
            [Step::Files(ClipboardFiles::Offered {
                total_entries: 2,
                total_bytes: 7,
                ..
            })]
        ));
        let (files, lock) = state.remote_files().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(lock, Some(9));
        assert!(state.holds_files());

        // The server copies something else: the offer is withdrawn.
        let steps = state.on_signal(Signal::RemoteCopied {
            unicode: true,
            ansi: false,
            file_list: None,
        });
        assert!(matches!(
            &steps[..],
            [Step::Files(ClipboardFiles::Withdrawn), Step::Fetch(_)]
        ));
        assert!(state.remote_files().is_none());
    }

    #[test]
    fn files_the_policy_does_not_allow_are_never_asked_for() {
        let mut state = ready();
        let steps = state.on_signal(Signal::RemoteCopied {
            unicode: false,
            ansi: false,
            file_list: Some(file_list_id()),
        });
        assert!(steps.is_empty());
        let steps = state.on_signal(Signal::RemoteFiles {
            files: vec![descriptor("a.txt", 3)],
            clip_data_id: None,
        });
        assert!(steps.is_empty());
        assert!(state.remote_files().is_none());
    }

    #[tokio::test]
    async fn local_files_are_announced_once_and_served_from_the_list_the_server_locked() {
        let mut state = with_files();
        let (_first_dir, first) = local_files(&["one.txt"]).await;
        let steps = state.offer_files(first, Instant::now());
        assert!(matches!(&steps[..], [Step::AnnounceFiles(list)] if list.len() == 1));

        // The server locks the list while it pastes.
        assert!(state.on_signal(Signal::Locked(4)).is_empty());

        // Then the user copies something else here.
        let (_second_dir, second) = local_files(&["two.txt", "three.txt"]).await;
        let steps = state.offer_files(second, Instant::now());
        assert!(matches!(&steps[..], [Step::AnnounceFiles(list)] if list.len() == 2));

        // A request under the lock reads the first list, not the current one.
        let locked = FileContentsRequest {
            stream_id: 1,
            index: 0,
            flags: ironrdp::cliprdr::pdu::FileContentsFlags::SIZE,
            position: 0,
            requested_size: 8,
            data_id: Some(4),
        };
        let [Step::Serve { files, .. }] =
            &state.on_signal(Signal::FileContentsRequested(locked))[..]
        else {
            panic!("a locked request was not served");
        };
        assert_eq!(files.descriptors()[0].name, "one.txt");

        let current = FileContentsRequest {
            stream_id: 2,
            index: 1,
            flags: ironrdp::cliprdr::pdu::FileContentsFlags::SIZE,
            position: 0,
            requested_size: 8,
            data_id: None,
        };
        let [Step::Serve { files, .. }] =
            &state.on_signal(Signal::FileContentsRequested(current))[..]
        else {
            panic!("a current request was not served");
        };
        // In the order the user's files were offered.
        assert_eq!(files.descriptors()[1].name, "three.txt");

        // Released, the old list answers nothing.
        assert!(state.on_signal(Signal::Unlocked(4)).is_empty());
        let stale = FileContentsRequest {
            stream_id: 3,
            index: 0,
            flags: ironrdp::cliprdr::pdu::FileContentsFlags::SIZE,
            position: 0,
            requested_size: 8,
            data_id: Some(4),
        };
        // Falls back to the current list, as `ironrdp-cliprdr` does.
        let steps = state.on_signal(Signal::FileContentsRequested(stale));
        assert!(matches!(&steps[..], [Step::Serve { .. }]));
    }

    #[tokio::test]
    async fn the_same_local_files_are_not_announced_twice() {
        let mut state = with_files();
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("same.txt");
        std::fs::write(&path, b"x").unwrap();
        let paths = [path.display().to_string()];
        let first = LocalFileSet::collect(&paths).await.unwrap();
        assert!(!state.offer_files(first, Instant::now()).is_empty());
        let again = LocalFileSet::collect(&paths).await.unwrap();
        assert!(state.offer_files(again, Instant::now()).is_empty());
    }

    #[tokio::test]
    async fn a_file_request_on_a_connection_without_files_is_refused() {
        let mut state = ready();
        let (_dir, files) = local_files(&["x.txt"]).await;
        assert!(state.offer_files(files, Instant::now()).is_empty());
        let request = FileContentsRequest {
            stream_id: 5,
            index: 0,
            flags: ironrdp::cliprdr::pdu::FileContentsFlags::SIZE,
            position: 0,
            requested_size: 8,
            data_id: None,
        };
        let steps = state.on_signal(Signal::FileContentsRequested(request));
        assert!(matches!(&steps[..], [Step::AnswerFile(response)] if response.is_error()));
    }
}
