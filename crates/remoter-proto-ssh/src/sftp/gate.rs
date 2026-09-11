//! The SFTP gate: the ceiling `russh-sftp` does not have.
//!
//! The same idea as [`remoter_proto_vnc::gate`] and
//! [`remoter_proto_rdp::framed::MAX_PDU_BYTES`], applied to the third adapter
//! that was missing it. A hostile or compromised server is in scope
//! (`docs/security/threat-model.md` T4), and two allocations inside
//! `russh-sftp` are sized by that server with nothing in the way.
//!
//! # 1 · One packet
//!
//! `russh-sftp`'s client read loop is
//! `read_packet(stream, u32::MAX)` (`client/mod.rs`), and `read_packet` is
//!
//! ```text
//! let length = stream.read_u32().await?;
//! if length > max_length { .. }          // max_length is u32::MAX here
//! let mut buf = vec![0; length as usize];
//! stream.read_exact(&mut buf).await?;
//! ```
//!
//! So four bytes off the wire reserve up to four gigabytes before a single
//! payload byte has arrived. The server crate passes its own
//! `max_client_packet_len` into the same function; the client passes
//! `u32::MAX`. Nothing this adapter can configure changes it —
//! `Config::max_packet_len` bounds what the client *asks* for, not what it
//! accepts.
//!
//! The fix has to sit **between the channel and the library**, because the
//! library is where the allocation happens. [`SftpGate`] parses the SFTP
//! framing (`draft-ietf-secsh-filexfer-02` §3: `uint32 length`, `byte type`,
//! payload) itself and withholds the four length bytes until the length they
//! declare has been checked against [`MAX_SFTP_PACKET_BYTES`]. A packet above
//! the ceiling never reaches `read_packet`, so the `vec![0; length]` is never
//! reached either.
//!
//! # 2 · One listing
//!
//! `SftpSession::read_dir` (`client/session.rs`) loops on `SSH_FXP_READDIR`
//! until the server answers `SSH_FX_EOF`, accumulating **every** record into
//! one `Vec` before the future resolves. A cap applied to the adapter's copy
//! of the result — which is what [`super::MAX_DIRECTORY_ENTRIES`] and
//! [`super::MAX_DIRECTORY_BYTES`] were, and still are — bounds the second copy
//! and never the first. A server that streams entries until memory runs out is
//! not stopped by a check that only runs once the future it is starving has
//! resolved.
//!
//! So the gate counts, on the wire, while a listing is in flight: the `count`
//! field of every `SSH_FXP_NAME` reply against [`super::MAX_DIRECTORY_ENTRIES`]
//! and the bytes of those replies against [`MAX_LISTING_WIRE_BYTES`]. The
//! budget is armed by [`SftpGateShared::begin_listing`], which
//! [`super::SftpBrowser::list`] holds across the `read_dir` call, and it is
//! reset for each listing so that browsing a thousand directories is not the
//! same as reading one enormous one. Exceeding it stops the stream, which
//! fails that `read_dir` — one failed pane with a diagnostic naming the limit,
//! never a truncated listing that looks like a shorter directory.
//!
//! # What it deliberately does not do
//!
//! It does not decode a payload. A `SSH_FXP_DATA` reply's bytes and an entry's
//! name pass through untouched and, in the common case, without a copy: what
//! the gate reads for itself is at most thirteen bytes per packet. Bounding an
//! entry's *own* size is the library's parser's job, and the packet ceiling
//! already bounds what that parser can be handed.
//!
//! It does not inspect the client's writes. The far end is the untrusted one.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::MAX_DIRECTORY_ENTRIES;

/// The largest single SFTP packet this build will let the library see.
///
/// The number that matters is what the client ever asks for: `russh-sftp`'s
/// `Config::max_packet_len` defaults to 256 KiB and every read it issues is
/// sized from that, so no honest reply is larger. A megabyte is four times the
/// largest legitimate packet and four thousand times smaller than the
/// `u32::MAX` the library would otherwise honour.
///
/// This is the ceiling that stops `utils.rs`'s `vec![0; length as usize]` —
/// the defect a `max_packet_len` setting looks like it would fix and does not.
pub const MAX_SFTP_PACKET_BYTES: u32 = 1024 * 1024;

/// The most `SSH_FXP_NAME` wire bytes one directory listing may carry.
///
/// Counted on the wire, which is where the library's own accumulation happens,
/// rather than on the adapter's copy of the result. It is deliberately larger
/// than [`super::MAX_DIRECTORY_BYTES`]: a listing record carries a `longname`
/// and an attribute block as well as the name, so the same directory is bigger
/// on the wire than in [`super::DirectoryEntry`]. 64 MiB is far more than any
/// real directory and far less than a server can send.
pub const MAX_LISTING_WIRE_BYTES: u64 = 64 * 1024 * 1024;

/// The failure an oversized packet reports. Names the ceiling, because a
/// diagnostic the user cannot act on is not a diagnostic.
pub const PACKET_TOO_LARGE: &str = "the SFTP server announced a packet larger than 1 MiB";

/// The failure a zero-length packet reports.
///
/// `draft-ietf-secsh-filexfer-02` §3 puts the type byte inside the length, so
/// a length of zero describes a packet with no type. Refused rather than
/// forwarded: it is a free way to make the library's loop spin.
pub const EMPTY_PACKET: &str = "the SFTP server announced a packet with nothing in it";

/// The failure a listing that declares too many entries reports.
pub const LISTING_ENTRIES_EXCEEDED: &str =
    "the server sent more than 250000 entries in one directory listing";

/// The failure a listing that sends too many bytes reports.
pub const LISTING_BYTES_EXCEEDED: &str =
    "the server sent more than 64 MiB in one directory listing";

/// `uint32 length` (`draft-ietf-secsh-filexfer-02` §3).
const LENGTH_BYTES: usize = 4;

/// `byte type`, `uint32 request-id`, `uint32 count` — the most of a payload
/// the gate ever reads for itself, and only a `SSH_FXP_NAME` has all three.
const PREFIX_BYTES: usize = 9;

/// The whole of what the gate buffers per packet.
const HEADER_BYTES: usize = LENGTH_BYTES + PREFIX_BYTES;

/// `SSH_FXP_NAME` (`draft-ietf-secsh-filexfer-02` §7): the reply a `READDIR`,
/// a `REALPATH` and a `READLINK` all come back as.
const SSH_FXP_NAME: u8 = 104;

/// How much of one listing the server has spent.
///
/// `depth` rather than a flag because one browser serves every pane on the
/// connection and [`super::SftpBrowser::list`] takes `&self`: two panes can be
/// listing at once. A second arming must join the budget already in flight
/// rather than zeroing it, or a server would only have to answer two listings
/// at a time to have neither of them bounded.
#[derive(Debug, Default, Clone, Copy)]
struct ListingBudget {
    depth: usize,
    entries: u64,
    bytes: u64,
}

/// State the gate shares with the [`super::SftpBrowser`] that owns it.
///
/// Two things travel this way because neither can travel through
/// `russh-sftp`: the library turns a refused stream into a read loop that
/// simply stops, so the failure a later request reports is "sender dropped"
/// rather than the reason; and the library has no way to be told that a
/// directory listing is in progress.
#[derive(Debug, Default)]
pub struct SftpGateShared {
    fault: Mutex<Option<&'static str>>,
    listing: Mutex<ListingBudget>,
}

impl SftpGateShared {
    /// The first rule the server broke, if it broke one.
    #[must_use]
    pub fn fault(&self) -> Option<&'static str> {
        *self.fault.lock()
    }

    /// Records a fault, keeping the first: later failures are consequences.
    fn record(&self, detail: &'static str) -> &'static str {
        let mut slot = self.fault.lock();
        let kept = slot.unwrap_or(detail);
        *slot = Some(kept);
        kept
    }

    /// Arms the listing budget for as long as the returned scope is held.
    ///
    /// Held across `read_dir` by [`super::SftpBrowser::list`]. Outside a scope
    /// nothing is counted, so a `REALPATH` or `READLINK` reply — an
    /// `SSH_FXP_NAME` with exactly one record — never spends a directory's
    /// budget.
    #[must_use]
    pub fn begin_listing(self: &Arc<Self>) -> ListingScope {
        let mut budget = self.listing.lock();
        if budget.depth == 0 {
            budget.entries = 0;
            budget.bytes = 0;
        }
        budget.depth = budget.depth.saturating_add(1);
        drop(budget);
        ListingScope {
            shared: Arc::clone(self),
        }
    }

    /// Charges one `SSH_FXP_NAME` reply against an armed budget.
    fn charge_listing(&self, entries: u64, wire_bytes: u64) -> Result<(), &'static str> {
        let mut budget = self.listing.lock();
        if budget.depth == 0 {
            return Ok(());
        }
        budget.entries = budget.entries.saturating_add(entries);
        budget.bytes = budget.bytes.saturating_add(wire_bytes);
        let entries = budget.entries;
        let bytes = budget.bytes;
        drop(budget);

        if entries > u64::try_from(MAX_DIRECTORY_ENTRIES).unwrap_or(u64::MAX) {
            return Err(LISTING_ENTRIES_EXCEEDED);
        }
        if bytes > MAX_LISTING_WIRE_BYTES {
            return Err(LISTING_BYTES_EXCEEDED);
        }
        Ok(())
    }

    fn end_listing(&self) {
        let mut budget = self.listing.lock();
        budget.depth = budget.depth.saturating_sub(1);
    }
}

/// A directory listing in flight. Dropping it disarms the budget.
#[derive(Debug)]
pub struct ListingScope {
    shared: Arc<SftpGateShared>,
}

impl Drop for ListingScope {
    fn drop(&mut self) {
        self.shared.end_listing();
    }
}

/// Where the reader is in the packet it is working on.
#[derive(Debug, Clone, Copy)]
enum Stage {
    /// Collecting `need` header bytes, `have` of which have arrived. Nothing
    /// collected here has been handed on yet — that is the whole point.
    Header { need: usize, have: usize },
    /// Handing out a header that has been checked, `at` bytes of `len` done.
    Deliver { len: usize, at: usize },
    /// Passing the rest of a checked packet straight through.
    Body { remaining: u64 },
}

/// A stream that will not let `russh-sftp` see a length it has not checked.
///
/// Wraps the SSH channel and is handed to `SftpSession::new` in its place.
/// Writes pass through untouched.
pub struct SftpGate<S> {
    inner: S,
    shared: Arc<SftpGateShared>,
    stage: Stage,
    header: [u8; HEADER_BYTES],
    /// The `uint32 length` of the packet being read, once it has been checked.
    packet_len: u32,
    /// Payload bytes still to pass through once the header has been delivered.
    pending_body: u64,
    /// Used only when a packet ends part way through the caller's buffer, so
    /// it is never larger than one caller's buffer nor than one packet.
    scratch: Vec<u8>,
    faulted: Option<&'static str>,
}

impl<S> SftpGate<S> {
    /// Wraps `inner`, returning the gate and the state its owner watches.
    #[must_use]
    pub fn new(inner: S) -> (Self, Arc<SftpGateShared>) {
        let shared = Arc::new(SftpGateShared::default());
        let gate = Self {
            inner,
            shared: Arc::clone(&shared),
            stage: Stage::Header {
                need: LENGTH_BYTES,
                have: 0,
            },
            header: [0; HEADER_BYTES],
            packet_len: 0,
            pending_body: 0,
            scratch: Vec::new(),
            faulted: None,
        };
        (gate, shared)
    }

    /// Records a fault once and latches it: every later read fails the same
    /// way, so the library stops rather than resynchronising onto a stream it
    /// has lost its place in.
    fn fail(&mut self, detail: &'static str) {
        self.faulted = Some(self.shared.record(detail));
    }

    /// The `uint32` at `offset` in the buffered header.
    fn word_at(&self, offset: usize) -> u32 {
        u32::from_be_bytes([
            self.header[offset],
            self.header[offset + 1],
            self.header[offset + 2],
            self.header[offset + 3],
        ])
    }

    /// Turns a complete length field into the rest of the header to collect.
    ///
    /// This is the check that must happen **before** the four length bytes are
    /// handed on, because handing them on is what makes `read_packet` do
    /// `vec![0; length as usize]`.
    fn length_complete(&mut self, have: usize) {
        let len = self.word_at(0);
        if len == 0 {
            self.fail(EMPTY_PACKET);
            return;
        }
        if len > MAX_SFTP_PACKET_BYTES {
            self.fail(PACKET_TOO_LARGE);
            return;
        }
        self.packet_len = len;
        let prefix = usize::try_from(len)
            .unwrap_or(PREFIX_BYTES)
            .min(PREFIX_BYTES);
        self.stage = Stage::Header {
            need: LENGTH_BYTES + prefix,
            have,
        };
    }

    /// Charges a complete header against the listing budget and readies it for
    /// delivery.
    fn header_complete(&mut self, need: usize) {
        // Only a `SSH_FXP_NAME` carries a record count, and only a header long
        // enough to hold one has it.
        if need == HEADER_BYTES && self.header[LENGTH_BYTES] == SSH_FXP_NAME {
            let count = u64::from(self.word_at(LENGTH_BYTES + 5));
            let wire =
                u64::from(self.packet_len).saturating_add(u64::try_from(LENGTH_BYTES).unwrap_or(0));
            if let Err(detail) = self.shared.charge_listing(count, wire) {
                self.fail(detail);
                return;
            }
        }
        self.pending_body = u64::from(self.packet_len)
            .saturating_sub(u64::try_from(need - LENGTH_BYTES).unwrap_or(0));
        self.stage = Stage::Deliver { len: need, at: 0 };
    }

    /// What comes after a run of bytes that has just finished.
    const fn after(remaining: u64) -> Stage {
        if remaining == 0 {
            Stage::Header {
                need: LENGTH_BYTES,
                have: 0,
            }
        } else {
            Stage::Body { remaining }
        }
    }
}

impl<S> std::fmt::Debug for SftpGate<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No payload and no length the peer chose: a `Debug` on a stream that
        // carries file contents must not be a way for one to reach a log.
        f.debug_struct("SftpGate")
            .field("faulted", &self.faulted)
            .finish()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SftpGate<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(detail) = this.faulted {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, detail)));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            match this.stage {
                // 1 · Hand over a header that has already been checked.
                Stage::Deliver { len, at } => {
                    let take = buf.remaining().min(len - at);
                    buf.put_slice(&this.header[at..at + take]);
                    let at = at + take;
                    this.stage = if at < len {
                        Stage::Deliver { len, at }
                    } else {
                        Self::after(this.pending_body)
                    };
                    return Poll::Ready(Ok(()));
                }

                // 2 · Collect a header, whole, before any of it is passed on.
                Stage::Header { need, have } => {
                    let mut window = ReadBuf::new(&mut this.header[have..need]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut window))?;
                    let read = window.filled().len();
                    if read == 0 {
                        // End of stream. Part way through a header it is a
                        // truncated packet, which the library reports as the
                        // disconnection it is rather than as a violation.
                        return Poll::Ready(Ok(()));
                    }
                    let have = have + read;
                    if have < need {
                        this.stage = Stage::Header { need, have };
                        continue;
                    }
                    if need == LENGTH_BYTES {
                        this.length_complete(have);
                    } else {
                        this.header_complete(need);
                    }
                    continue;
                }

                // 3 · A payload: nothing to inspect, only to count, so the
                // common case reads straight into the caller's buffer.
                Stage::Body { remaining } => {
                    let wanted = u64::try_from(buf.remaining()).unwrap_or(u64::MAX);
                    if remaining >= wanted {
                        let before = buf.filled().len();
                        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
                        let read = buf.filled().len() - before;
                        if read == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        let left = remaining.saturating_sub(u64::try_from(read).unwrap_or(0));
                        this.pending_body = left;
                        this.stage = Self::after(left);
                        return Poll::Ready(Ok(()));
                    }
                    // The payload ends inside this buffer, so only its tail
                    // may be taken: the bytes after it are a length that has
                    // to be checked before the library sees it. `remaining` is
                    // below `buf.remaining()` here, so the scratch is never
                    // larger than one caller's buffer.
                    let want = usize::try_from(remaining).unwrap_or(buf.remaining());
                    this.scratch.clear();
                    this.scratch.resize(want, 0);
                    let read = {
                        let mut window = ReadBuf::new(&mut this.scratch[..want]);
                        ready!(Pin::new(&mut this.inner).poll_read(cx, &mut window))?;
                        window.filled().len()
                    };
                    if read == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    buf.put_slice(&this.scratch[..read]);
                    let left = remaining.saturating_sub(u64::try_from(read).unwrap_or(0));
                    this.pending_body = left;
                    this.stage = Self::after(left);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SftpGate<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex};

    use super::*;

    /// A server that hands out its bytes `chunk` at a time, so that every
    /// header in these tests can arrive split across polls.
    struct Feed {
        data: Vec<u8>,
        at: usize,
        chunk: usize,
    }

    impl Feed {
        fn new(data: Vec<u8>, chunk: usize) -> Self {
            Self { data, at: 0, chunk }
        }
    }

    impl AsyncRead for Feed {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let take = buf
                .remaining()
                .min(this.chunk)
                .min(this.data.len() - this.at);
            buf.put_slice(&this.data[this.at..this.at + take]);
            this.at += take;
            Poll::Ready(Ok(()))
        }
    }

    /// `uint32 length`, `byte type`, payload.
    fn packet(kind: u8, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len() + 1).unwrap();
        let mut out = len.to_be_bytes().to_vec();
        out.push(kind);
        out.extend_from_slice(payload);
        out
    }

    /// An `SSH_FXP_NAME` declaring `count` records, padded to `filler` bytes
    /// of payload beyond the identifier and the count.
    fn name_packet(id: u32, count: u32, filler: usize) -> Vec<u8> {
        let mut payload = id.to_be_bytes().to_vec();
        payload.extend_from_slice(&count.to_be_bytes());
        payload.resize(payload.len() + filler, b'a');
        packet(SSH_FXP_NAME, &payload)
    }

    /// A plausible exchange: a version, a handle, a listing, a data reply.
    fn realistic_stream() -> Vec<u8> {
        let mut wire = packet(2, &3u32.to_be_bytes());
        wire.extend(packet(102, b"\x00\x00\x00\x01\x00\x00\x00\x01h"));
        wire.extend(name_packet(2, 3, 64));
        wire.extend(packet(103, &[0x00; 900]));
        wire.extend(packet(101, &[0x00; 16]));
        wire
    }

    async fn read_all(wire: Vec<u8>, chunk: usize) -> (io::Result<Vec<u8>>, Arc<SftpGateShared>) {
        let (mut gate, shared) = SftpGate::new(Feed::new(wire, chunk));
        let mut out = Vec::new();
        let outcome = gate.read_to_end(&mut out).await.map(|_| out);
        (outcome, shared)
    }

    #[test]
    fn the_gate_names_its_ceilings_in_the_failure() {
        // The messages are literals because `ProtocolViolation` carries one.
        // They must still say the numbers the constants do, or they send the
        // user looking for a limit that does not exist.
        assert_eq!(MAX_SFTP_PACKET_BYTES, 1024 * 1024);
        assert!(PACKET_TOO_LARGE.contains("1 MiB"));
        assert_eq!(MAX_LISTING_WIRE_BYTES, 64 * 1024 * 1024);
        assert!(LISTING_BYTES_EXCEEDED.contains("64 MiB"));
        assert!(LISTING_ENTRIES_EXCEEDED.contains(&MAX_DIRECTORY_ENTRIES.to_string()));
    }

    #[tokio::test]
    async fn an_ordinary_exchange_passes_through_byte_for_byte() {
        // The bound is worthless if it also breaks a legitimate session, and a
        // framing bug would show up as a stream the library cannot parse
        // rather than as an error anyone could read. Every chunk size puts the
        // split in a different place inside the headers.
        let wire = realistic_stream();
        for chunk in [1, 2, 3, 5, 13, 64, 4096] {
            let (outcome, shared) = read_all(wire.clone(), chunk).await;
            assert_eq!(outcome.unwrap(), wire, "chunk size {chunk}");
            assert_eq!(shared.fault(), None);
        }
    }

    #[tokio::test]
    async fn a_packet_above_the_ceiling_never_reaches_the_library() {
        // `read_packet(stream, u32::MAX)` does `vec![0; length as usize]` on
        // this number. The four length bytes must not be forwarded at all:
        // forwarding them and complaining afterwards is the defect, not the
        // fix. So the delivered prefix has to stop at the previous packet.
        let mut wire = packet(101, &[0x00; 16]);
        let prefix = wire.len();
        wire.extend_from_slice(&u32::MAX.to_be_bytes());
        wire.extend_from_slice(&[0x00; 64]);

        let (mut gate, shared) = SftpGate::new(Feed::new(wire, 7));
        let mut out = Vec::new();
        let error = gate.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), PACKET_TOO_LARGE);
        assert_eq!(out.len(), prefix);
        assert_eq!(shared.fault(), Some(PACKET_TOO_LARGE));
    }

    #[tokio::test]
    async fn a_packet_one_byte_over_the_ceiling_is_refused_and_one_byte_under_is_not() {
        // A ceiling that is off by one in the generous direction is a ceiling
        // that can be stepped over.
        let mut over = (MAX_SFTP_PACKET_BYTES + 1).to_be_bytes().to_vec();
        over.push(103);
        let (outcome, _) = read_all(over, 4096).await;
        assert_eq!(outcome.unwrap_err().to_string(), PACKET_TOO_LARGE);

        let body = vec![0x00; usize::try_from(MAX_SFTP_PACKET_BYTES).unwrap() - 1];
        let wire = packet(103, &body);
        let (outcome, shared) = read_all(wire.clone(), 65536).await;
        assert_eq!(outcome.unwrap(), wire);
        assert_eq!(shared.fault(), None);
    }

    #[tokio::test]
    async fn a_packet_with_nothing_in_it_is_refused() {
        // Length zero describes a packet with no type byte. Forwarding it
        // leaves the library reading a packet that can never complete.
        let wire = vec![0x00, 0x00, 0x00, 0x00, 0x01];
        let (outcome, shared) = read_all(wire, 4096).await;
        assert_eq!(outcome.unwrap_err().to_string(), EMPTY_PACKET);
        assert_eq!(shared.fault(), Some(EMPTY_PACKET));
    }

    #[tokio::test]
    async fn a_stream_that_stops_mid_packet_ends_rather_than_faults() {
        // A server that goes away is a disconnection, not a violation, and
        // calling it a violation would blame the wrong thing in the tab.
        let full = packet(103, &[0x00; 64]);
        let wire = full[..20].to_vec();
        let (outcome, shared) = read_all(wire.clone(), 7).await;
        assert_eq!(outcome.unwrap(), wire);
        assert_eq!(shared.fault(), None);
    }

    #[tokio::test]
    async fn a_listing_is_stopped_at_the_entry_cap_on_the_wire() {
        // The cap the adapter used to apply to its own copy of the listing,
        // applied where `russh-sftp` does its accumulating. Declared counts
        // are what the server chooses and what the library allocates from.
        let per_packet = 100_000u32;
        let mut wire = Vec::new();
        for id in 0..4u32 {
            wire.extend(name_packet(id, per_packet, 16));
        }
        let (mut gate, shared) = SftpGate::new(Feed::new(wire, 4096));
        let _scope = shared.begin_listing();

        let mut out = Vec::new();
        let error = gate.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(error.to_string(), LISTING_ENTRIES_EXCEEDED);
        assert_eq!(shared.fault(), Some(LISTING_ENTRIES_EXCEEDED));
    }

    #[tokio::test]
    async fn a_listing_is_stopped_at_the_byte_cap_even_when_it_declares_few_entries() {
        // The count cap alone is not enough: one record with an enormous name
        // is the same attack, and a server can send that record forever.
        let one = name_packet(0, 1, 900 * 1024);
        let packets = usize::try_from(MAX_LISTING_WIRE_BYTES).unwrap() / one.len() + 2;
        let mut wire = Vec::with_capacity(one.len() * packets);
        for _ in 0..packets {
            wire.extend_from_slice(&one);
        }
        let (mut gate, shared) = SftpGate::new(Feed::new(wire, 64 * 1024));
        let _scope = shared.begin_listing();

        let mut out = Vec::new();
        let error = gate.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(error.to_string(), LISTING_BYTES_EXCEEDED);
    }

    #[tokio::test]
    async fn a_name_reply_outside_a_listing_is_not_charged_to_one() {
        // `REALPATH` and `READLINK` answer with `SSH_FXP_NAME` too. Charging
        // them to a directory's budget would make a deep tree walk fail for a
        // reason that has nothing to do with any directory in it.
        let wire = name_packet(1, 1, 32);
        let (outcome, shared) = read_all(wire.clone(), 4096).await;
        assert_eq!(outcome.unwrap(), wire);
        assert_eq!(shared.fault(), None);
    }

    #[tokio::test]
    async fn each_listing_gets_its_own_budget() {
        // Browsing a thousand directories must not add up to one listing that
        // is too large. The scope is what resets it.
        let one = name_packet(0, 200_000, 16);
        let wire: Vec<u8> = std::iter::repeat_n(one.clone(), 8).flatten().collect();
        let (mut gate, shared) = SftpGate::new(Feed::new(wire, 4096));
        for _ in 0..8 {
            let scope = shared.begin_listing();
            let mut delivered = vec![0u8; one.len()];
            gate.read_exact(&mut delivered).await.unwrap();
            drop(scope);
        }
        assert_eq!(shared.fault(), None);
    }

    #[tokio::test]
    async fn a_second_listing_joins_the_budget_rather_than_resetting_it() {
        // One browser serves every pane on the connection, and `list` takes
        // `&self`, so two of them can be listing at once. A second arming that
        // zeroed the counters would mean a server had only to answer two
        // listings at a time to have neither of them bounded.
        let wire: Vec<u8> = (0..4u32)
            .flat_map(|id| name_packet(id, 100_000, 16))
            .collect();
        let (mut gate, shared) = SftpGate::new(Feed::new(wire, 4096));
        let outer = shared.begin_listing();
        let inner = shared.begin_listing();

        let mut out = Vec::new();
        let error = gate.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(error.to_string(), LISTING_ENTRIES_EXCEEDED);
        drop(inner);
        drop(outer);
    }

    // ============================================ against the real library ====

    /// Writes one SFTP packet onto `stream`.
    async fn send(stream: &mut DuplexStream, kind: u8, payload: &[u8]) -> io::Result<()> {
        stream.write_all(&packet(kind, payload)).await
    }

    /// `uint32` length prefix plus the bytes, as SFTP writes a string.
    fn sftp_string(text: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(text.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(text);
        out
    }

    /// One `SSH_FXP_NAME` record: filename, longname, empty attributes.
    fn record(name: &[u8], longname: &[u8]) -> Vec<u8> {
        let mut out = sftp_string(name);
        out.extend(sftp_string(longname));
        out.extend_from_slice(&0u32.to_be_bytes());
        out
    }

    /// Reads one whole packet, returning its type and payload.
    async fn recv(stream: &mut DuplexStream) -> io::Result<(u8, Vec<u8>)> {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).await?;
        let len = usize::try_from(u32::from_be_bytes(length)).unwrap();
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        Ok((body[0], body[1..].to_vec()))
    }

    /// A minimal SFTP server. `entries_per_reply` records per `READDIR`, each
    /// name `name_len` bytes; `replies` of them before it says EOF, or forever
    /// when `replies` is `None` — which is the hostile case.
    fn fake_server(
        mut stream: DuplexStream,
        entries_per_reply: usize,
        name_len: usize,
        replies: Option<usize>,
    ) {
        tokio::spawn(async move {
            let mut sent = 0usize;
            loop {
                let Ok((kind, payload)) = recv(&mut stream).await else {
                    return;
                };
                let id = || u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let result = match kind {
                    // SSH_FXP_INIT: answer with SSH_FXP_VERSION 3.
                    1 => send(&mut stream, 2, &3u32.to_be_bytes()).await,
                    // SSH_FXP_OPENDIR: answer with a handle.
                    11 => {
                        let mut out = id().to_be_bytes().to_vec();
                        out.extend(sftp_string(b"h"));
                        send(&mut stream, 102, &out).await
                    }
                    // SSH_FXP_READDIR.
                    12 => {
                        if replies.is_some_and(|limit| sent >= limit) {
                            // SSH_FXP_STATUS with SSH_FX_EOF.
                            let mut out = id().to_be_bytes().to_vec();
                            out.extend_from_slice(&1u32.to_be_bytes());
                            out.extend(sftp_string(b""));
                            out.extend(sftp_string(b""));
                            send(&mut stream, 101, &out).await
                        } else {
                            sent += 1;
                            let mut out = id().to_be_bytes().to_vec();
                            out.extend_from_slice(
                                &u32::try_from(entries_per_reply).unwrap().to_be_bytes(),
                            );
                            for index in 0..entries_per_reply {
                                // The bulk goes in the *filename*, because
                                // that is the half `read_dir` keeps: a
                                // demonstration that only grew the longname
                                // would show the library parsing a lot and
                                // retaining nothing.
                                let mut name = format!("{index:08}").into_bytes();
                                name.resize(name_len.max(name.len()), b'x');
                                out.extend(record(&name, &name));
                            }
                            send(&mut stream, 104, &out).await
                        }
                    }
                    // SSH_FXP_CLOSE: answer SSH_FX_OK.
                    4 => {
                        let mut out = id().to_be_bytes().to_vec();
                        out.extend_from_slice(&0u32.to_be_bytes());
                        out.extend(sftp_string(b""));
                        out.extend(sftp_string(b""));
                        send(&mut stream, 101, &out).await
                    }
                    _ => Ok(()),
                };
                if result.is_err() {
                    return;
                }
            }
        });
    }

    #[tokio::test]
    async fn an_ordinary_listing_through_the_gate_still_lists() {
        // The bound set too low would break a legitimate directory, which is
        // the worse bug. Four replies of sixteen entries is an ordinary
        // multi-round-trip listing.
        let (client, server) = duplex(64 * 1024);
        fake_server(server, 16, 64, Some(4));
        let (gate, shared) = SftpGate::new(client);

        let session = russh_sftp::client::SftpSession::new(gate)
            .await
            .expect("the fake server refused the handshake");
        let scope = shared.begin_listing();
        let listed = session
            .read_dir("/srv")
            .await
            .expect("a legitimate listing");
        drop(scope);

        assert_eq!(listed.count(), 64);
        assert_eq!(shared.fault(), None);
    }

    #[tokio::test]
    async fn a_listing_that_never_ends_is_stopped_inside_the_library() {
        // The defect this exists for: `read_dir` accumulates every record it
        // is sent into one `Vec` and only then resolves, so a cap applied to
        // the adapter's copy of the result bounds the second copy and never
        // the first. With the budget disarmed this call never returns and the
        // process grows until it is killed.
        let (client, server) = duplex(1024 * 1024);
        fake_server(server, 512, 512, None);
        let (gate, shared) = SftpGate::new(client);

        let session = russh_sftp::client::SftpSession::new(gate)
            .await
            .expect("the fake server refused the handshake");
        let scope = shared.begin_listing();
        let outcome = tokio::time::timeout(Duration::from_secs(60), session.read_dir("/srv")).await;
        drop(scope);

        assert!(outcome.expect("the listing did not stop").is_err());
        assert_eq!(shared.fault(), Some(LISTING_BYTES_EXCEEDED));
    }

    #[tokio::test]
    async fn a_hostile_length_is_refused_before_the_library_reserves_for_it() {
        // Four bytes off the wire, and `utils.rs` reserves four gigabytes.
        // The gate has to refuse them before `read_packet` ever sees them, so
        // what this asserts is that the session fails *and* that the reason
        // recorded is the ceiling rather than the library's ten-second request
        // timeout expiring on a read that will never complete.
        let (client, mut server) = duplex(64 * 1024);
        tokio::spawn(async move {
            let mut length = [0u8; 4];
            if server.read_exact(&mut length).await.is_err() {
                return;
            }
            let _ = server.write_all(&u32::MAX.to_be_bytes()).await;
            let _ = server.write_all(&[0x00; 64]).await;
            // Held open so that a session without the ceiling waits on
            // `read_exact` rather than seeing the stream close.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let (gate, shared) = SftpGate::new(client);
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            russh_sftp::client::SftpSession::new(gate),
        )
        .await;

        assert!(outcome.expect("the handshake did not stop").is_err());
        assert_eq!(shared.fault(), Some(PACKET_TOO_LARGE));
    }
}
