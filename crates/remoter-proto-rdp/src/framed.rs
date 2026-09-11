//! Reading whole PDUs off an injected transport, and upgrading it to TLS.
//!
//! RDP is a byte stream carrying self-delimiting PDUs, so something has to
//! accumulate bytes until a whole one is present. That is all this module is —
//! but three properties of it are load-bearing:
//!
//! - **It never dials.** The transport arrives connected (ADR-0003) and the
//!   TLS upgrade wraps *that* stream, so RDP through two SSH bastions is the
//!   same code path as RDP on the LAN. Nothing here constructs a socket.
//! - **It is dropped whole.** A cancelled connection attempt drops this value,
//!   which drops the `TlsStream`, which drops the injected transport, which
//!   closes the socket. There is no background task holding a copy — an
//!   earlier defect in this project leaked one task and one socket per
//!   cancelled attempt, and the shape that prevents it is "one owner, no
//!   spawn".
//! - **Nothing the far end sends sizes an allocation without a ceiling.**
//!   [`MAX_PDU_BYTES`] bounds one PDU, and [`Reassembly`] bounds the two
//!   buffers that span *many* PDUs and that this crate does not own. See its
//!   documentation: bounding only the allocations this crate writes is not the
//!   same as bounding the ones it causes.

use std::sync::Arc;

use bytes::BytesMut;
use ironrdp::core::{ReadCursor, decode_cursor};
use ironrdp::pdu as rdp_pdu;
use ironrdp::pdu::fast_path::{FastPathHeader, FastPathUpdatePdu, Fragmentation};
use ironrdp::pdu::rdp::vc::{ChannelControlFlags, ChannelPduHeader};
use remoter_proto::{HostPort, ProtocolError, Transport};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::cert::{DeferredVerifier, OfferedCertificate};
use crate::error::{handshake_failed, map_io, map_tls, violation};

/// How many bytes may accumulate while waiting for one PDU to complete.
///
/// A fast-path update's length field is 15 bits (MS-RDPBCGR §2.2.9.1.2), and
/// an X.224 PDU's TPKT length is 16 (RFC 905 / MS-RDPBCGR §2.2.1.1), so no
/// legitimate PDU exceeds 64 KiB. The cap is generous rather than exact
/// because a server that exceeds it is misbehaving and the point is to bound
/// the memory a misbehaving one can make this process allocate, not to police
/// the wire format twice.
pub const MAX_PDU_BYTES: usize = 256 * 1024;

/// The largest fast-path update this build will let `ironrdp-session`
/// reassemble out of fragments.
///
/// **This is not a number invented here.** MS-RDPBCGR §2.2.7.2.6's
/// Multifragment Update capability set carries `MaxRequestSize`, which for the
/// client is "the size of the buffer used to reassemble the fragments of a
/// Fast-Path Update" — the client tells the server how large a reassembly it
/// can hold, and the server is required not to exceed it.
/// `crate::connect`'s `client_confirm_active` puts exactly this number in the
/// Client Confirm Active PDU, clamping the server's own suggestion down to it,
/// so enforcing it here refuses nothing this client did not already forbid.
///
/// 8 MiB is far more than a full-screen RemoteFX frame needs, and `mstsc`
/// itself advertises a fraction of it.
pub const MAX_FASTPATH_REASSEMBLY_BYTES: u32 = 8 * 1024 * 1024;

/// The largest static virtual channel PDU this build will let `ironrdp-svc`
/// reassemble out of chunks.
///
/// One static channel is opened (`crate::connect::static_channels`): `drdynvc`,
/// MS-RDPEDYC's dynamic channel multiplexer, and inside it MS-RDPEDISP's
/// Display Control. Everything that travels there is small and fixed — a
/// capability exchange of tens of bytes, a create request, and a monitor layout
/// of at most sixteen forty-byte entries. A megabyte is three orders of
/// magnitude more than any of them and is reached by nothing legitimate.
///
/// **Raising this is a decision, not a default.** The clipboard channel
/// (MS-RDPECLIP) carries whatever the remote user copied, so adding it means
/// choosing a clipboard ceiling deliberately — the way
/// `remoter-proto-vnc`'s `MAX_CLIPBOARD_BYTES` is chosen — rather than
/// discovering that this number was already in the way.
pub const MAX_SVC_REASSEMBLY_BYTES: u32 = 1024 * 1024;

/// How much to ask the transport for at a time.
const READ_CHUNK: usize = 16 * 1024;

/// The stream the connection sequence runs over: plain until the X.224
/// negotiation selects TLS, wrapped afterwards.
enum Inner {
    /// Before MS-RDPBCGR §5.4.5.1's upgrade.
    Plain(Box<dyn Transport>),
    /// After it. Boxed because `TlsStream` is large and this enum is moved
    /// through the whole connection sequence.
    Tls(Box<TlsStream<Box<dyn Transport>>>),
    /// Momentarily, while the upgrade swaps one for the other. Reachable only
    /// inside [`Framed::upgrade_to_tls`], and an error there leaves the value
    /// in this state so that the stream cannot be used afterwards.
    Upgrading,
}

/// A transport plus the bytes read past the end of the last PDU.
pub struct Framed {
    inner: Inner,
    buffer: BytesMut,
    target: HostPort,
}

impl core::fmt::Debug for Framed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Framed")
            .field("target", &self.target)
            .field("encrypted", &matches!(self.inner, Inner::Tls(_)))
            .field("buffered", &self.buffer.len())
            .finish()
    }
}

impl Framed {
    /// Wraps an already-connected transport.
    #[must_use]
    pub fn new(transport: Box<dyn Transport>, target: HostPort) -> Self {
        Self {
            inner: Inner::Plain(transport),
            buffer: BytesMut::with_capacity(READ_CHUNK),
            target,
        }
    }

    /// Whether the stream is inside TLS yet.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        matches!(self.inner, Inner::Tls(_))
    }

    /// Writes `bytes`, in full.
    ///
    /// # Errors
    ///
    /// A mapped I/O failure. `flush` is called because a `TlsStream` buffers,
    /// and a connection sequence that half-writes a PDU and then waits for a
    /// reply deadlocks until the deadline fires.
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        let result = match &mut self.inner {
            Inner::Plain(stream) => stream.write_all(bytes).await.and(stream.flush().await),
            Inner::Tls(stream) => stream.write_all(bytes).await.and(stream.flush().await),
            Inner::Upgrading => {
                return Err(ProtocolError::Internal {
                    detail: "the RDP stream was used while its TLS upgrade was in flight",
                });
            }
        };
        result.map_err(|error| map_io(&error, &self.target, "write to the RDP connection"))
    }

    /// Reads one PDU whose size `size_of` can determine from a prefix.
    ///
    /// `size_of` returns `Ok(None)` while the prefix is too short, which is the
    /// signal to read more. It is a closure rather than an
    /// `ironrdp_pdu::PduHint` because CredSSP's `TSRequest` is not an RDP PDU
    /// and has to be framed by the same loop.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Disconnected`] if the peer closes mid-PDU,
    /// [`ProtocolError::ProtocolViolation`] if it announces a PDU larger than
    /// [`MAX_PDU_BYTES`], or a mapped I/O failure.
    pub async fn read_pdu<F>(&mut self, size_of: F) -> Result<BytesMut, ProtocolError>
    where
        F: Fn(&[u8]) -> Result<Option<usize>, ProtocolError>,
    {
        loop {
            if let Some(size) = size_of(&self.buffer)? {
                if size == 0 {
                    return Err(violation("the server announced a zero-length PDU"));
                }
                if size > MAX_PDU_BYTES {
                    // Refused before the allocation, not after: the length is
                    // the peer's claim, and honouring it is how a compromised
                    // host turns one connection into an out-of-memory abort.
                    return Err(violation("the server announced an implausibly large PDU"));
                }
                if self.buffer.len() >= size {
                    return Ok(self.buffer.split_to(size));
                }
                self.buffer.reserve(size - self.buffer.len());
            }
            self.fill().await?;
        }
    }

    /// Reads one X.224-framed PDU, discarding any fast-path update that
    /// arrives first.
    ///
    /// The whole connection sequence up to the Font Map PDU is X.224-framed,
    /// but the server may start sending graphics the moment it has the Client
    /// Font List PDU (MS-RDPBCGR §1.3.1.1), which is *before* the client has
    /// seen the Font Map that ends the sequence. Treating one of those as an
    /// error would fail a perfectly ordinary connection against Windows.
    ///
    /// The discarded frames are a redraw the client has not asked for yet; the
    /// Refresh Rect PDU sent at the end of the sequence asks for the desktop
    /// again, so nothing is permanently lost.
    ///
    /// # Errors
    ///
    /// As [`Framed::read_pdu`].
    pub async fn read_x224_pdu(&mut self) -> Result<BytesMut, ProtocolError> {
        loop {
            let frame = self.read_pdu(rdp_pdu_length).await?;
            let action = frame
                .first()
                .and_then(|header| rdp_pdu::Action::from_fp_output_header(*header).ok());
            match action {
                Some(rdp_pdu::Action::X224) => return Ok(frame),
                Some(rdp_pdu::Action::FastPath) => {
                    tracing::trace!(
                        bytes = frame.len(),
                        "discarding a fast-path update that arrived before the connection sequence ended"
                    );
                }
                None => {
                    return Err(violation(
                        "the server sent a PDU with no recognisable action",
                    ));
                }
            }
        }
    }

    /// Reads exactly `count` bytes.
    ///
    /// For the one message in the sequence that is not self-delimiting: the
    /// Early User Authorization Result PDU (MS-RDPBCGR §2.2.10.2) is four
    /// bytes with no header at all.
    ///
    /// # Errors
    ///
    /// As [`Framed::read_pdu`].
    pub async fn read_exact(&mut self, count: usize) -> Result<BytesMut, ProtocolError> {
        while self.buffer.len() < count {
            self.fill().await?;
        }
        Ok(self.buffer.split_to(count))
    }

    /// Pulls one chunk from the transport into the buffer.
    async fn fill(&mut self) -> Result<(), ProtocolError> {
        if self.buffer.len() >= MAX_PDU_BYTES {
            return Err(violation(
                "the server sent more than one PDU's worth of data",
            ));
        }
        let mut chunk = [0u8; READ_CHUNK];
        let read = match &mut self.inner {
            Inner::Plain(stream) => stream.read(&mut chunk).await,
            Inner::Tls(stream) => stream.read(&mut chunk).await,
            Inner::Upgrading => {
                return Err(ProtocolError::Internal {
                    detail: "the RDP stream was used while its TLS upgrade was in flight",
                });
            }
        };
        match read.map_err(|error| map_io(&error, &self.target, "read from the RDP connection"))? {
            0 => Err(ProtocolError::Disconnected {
                reason: "rdp.remote_closed".to_owned(),
            }),
            count => {
                self.buffer.extend_from_slice(&chunk[..count]);
                Ok(())
            }
        }
    }

    /// Upgrades the stream to TLS, as MS-RDPBCGR §5.4.5.1 requires once the
    /// X.224 Negotiation Response has selected an external security protocol.
    ///
    /// Returns what the server offered, for the trust decision. The decision
    /// itself is **not** made here — see [`crate::cert`] for why it cannot be,
    /// and for the guarantee that it happens before anything else is written.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::CertificateUntrusted`] if `rustls` rejected the
    /// certificate outright — a signature that does not verify, for instance,
    /// which is not deferred — or a mapped TLS or I/O failure.
    pub async fn upgrade_to_tls(&mut self) -> Result<OfferedCertificate, ProtocolError> {
        if !self.buffer.is_empty() {
            // The server sent application bytes before the TLS handshake it
            // just agreed to. Nothing legitimate does that, and carrying them
            // across the upgrade would inject unauthenticated bytes into the
            // encrypted stream.
            return Err(violation(
                "the server sent data before the TLS handshake it had selected",
            ));
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = DeferredVerifier::new(Arc::clone(&provider))?;
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| ProtocolError::Internal {
                detail: "the TLS client configuration could not be built",
            })?
            .dangerous()
            .with_custom_certificate_verifier(
                Arc::clone(&verifier) as Arc<dyn rustls::client::danger::ServerCertVerifier>
            )
            .with_no_client_auth();

        // The name is only used for the certificate's own name check, which
        // `DeferredVerifier` records rather than enforces. An address literal
        // is fine — a great many RDP hosts are reached by IP, and refusing to
        // build a `ServerName` for one would refuse the connection outright.
        let name = ServerName::try_from(self.target.host().to_owned())
            .map_err(|_| handshake_failed("the host name is not usable for TLS"))?;

        let transport = match core::mem::replace(&mut self.inner, Inner::Upgrading) {
            Inner::Plain(transport) => transport,
            // Upgrading twice would silently tunnel TLS inside TLS.
            other => {
                self.inner = other;
                return Err(ProtocolError::Internal {
                    detail: "the RDP stream was upgraded to TLS twice",
                });
            }
        };

        let stream = TlsConnector::from(Arc::new(config))
            .connect(name, transport)
            .await
            .map_err(|error| {
                // `tokio_rustls` wraps the `rustls` error in an `io::Error`;
                // recovering it is what keeps an untrusted certificate from
                // being reported as a generic I/O failure with a retry button.
                match error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                {
                    Some(tls) => map_tls(tls, &self.target),
                    None => map_io(&error, &self.target, "complete the TLS handshake"),
                }
            })?;

        let offered = verifier.offered().ok_or_else(|| {
            // Unreachable in practice: the handshake cannot succeed without
            // the verifier having been consulted. Reported rather than
            // assumed, because the alternative is proceeding with no
            // certificate to check.
            violation("the TLS handshake completed without a server certificate")
        })?;
        self.inner = Inner::Tls(Box::new(stream));
        Ok(offered)
    }
}

/// The ceiling on the two reassembly buffers `ironrdp` grows out of PDUs this
/// crate hands it.
///
/// # The defect this exists to prevent coming back
///
/// [`MAX_PDU_BYTES`] bounds **one** PDU. It says nothing about a buffer the
/// library accumulates across many, and there are two of those:
///
/// - `ironrdp-session`'s `CompleteData::append_data` extends `fragmented_data`
///   for every fast-path update whose fragmentation field is
///   [`Fragmentation::Next`] (MS-RDPBCGR §2.2.9.1.2.1). There is no declared
///   total and there was no ceiling: a server that sends `First` and then
///   `Next` for ever grows that `Vec` for ever, one legal 64 KiB PDU at a time.
/// - `ironrdp-svc`'s `ChunkProcessor::dechunkify` extends `chunked_pdu` for
///   every static virtual channel chunk that does not carry
///   `CHANNEL_FLAG_LAST` (§3.1.5.2.2). It reads the Channel PDU Header's
///   `length` — the *declared* total — not at all, and never stops.
///
/// Neither allocation is written by this crate, which is exactly why an earlier
/// sweep of "what does this adapter allocate from a server-chosen number?"
/// missed both. **Bounding your own allocations is not the same as bounding the
/// ones you cause.** An allocation failure aborts rather than unwinds, so
/// ADR-0011's "a panic is one failed tab" does not contain it; it takes every
/// other session and the unlocked vault with it.
///
/// # Why it sits here and not downstream
///
/// The ceiling has to be applied while this crate still holds the bytes —
/// before `ActiveStage::process` is called, not after it returns. A cap applied
/// to a copy the library has already materialised bounds the second copy and
/// never the first.
///
/// # How it stays correct
///
/// This is a **mirror** of the two state machines above, not a second
/// implementation of them: the fragmentation and chunk headers are decoded with
/// `ironrdp`'s own decoders, so there is no second parser to drift. The rules it
/// mirrors are:
///
/// - `CompleteData` discards whatever it held on `Single` and `First`, appends
///   on `Next` and `Last`, and takes the buffer on `Last`. A `Next` with no
///   `First` before it is dropped with a warning and grows nothing — so it is
///   not counted here either, or a session the library never grew a buffer for
///   would be refused.
/// - `ChunkProcessor` appends every chunk's payload and empties on
///   `CHANNEL_FLAG_LAST`.
///
/// Compression is not a hole in the first rule: the Client Info PDU does not set
/// `ClientInfoFlags::COMPRESSION` and the active stage is built with
/// `compression_type: None`, so `ironrdp-session` holds no decompressor and
/// appends the wire bytes unchanged. Negotiating bulk compression later would
/// mean a decompressed length this cannot see, and the ceiling would have to
/// move to where that length is known.
#[derive(Debug, Default)]
pub struct Reassembly {
    /// Bytes `CompleteData::fragmented_data` is holding. `None` when no `First`
    /// has been seen, which is the state in which the library appends nothing.
    fastpath: Option<u64>,
    /// One entry per joined static virtual channel, and how much of a chunked
    /// PDU each is holding. A `Vec` because there is one channel, occasionally
    /// two: a map would cost more than the linear scan it replaced.
    channels: Vec<SvcChannel>,
}

/// A static virtual channel's share of the chunk buffer.
#[derive(Debug)]
struct SvcChannel {
    id: u16,
    held: u64,
}

impl Reassembly {
    /// Starts a guard for the static virtual channels the server actually
    /// joined.
    ///
    /// Channels that were requested and never joined are not listed, and
    /// neither is the I/O or message channel: `ironrdp-session` routes those
    /// somewhere other than `ChunkProcessor`, so counting them would refuse a
    /// conforming server for bytes nothing accumulated.
    #[must_use]
    pub fn new(channel_ids: impl IntoIterator<Item = u16>) -> Self {
        Self {
            fastpath: None,
            channels: channel_ids
                .into_iter()
                .map(|id| SvcChannel { id, held: 0 })
                .collect(),
        }
    }

    /// Checks one whole PDU before it is handed to `ironrdp`.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ProtocolViolation`] if acting on this PDU would grow
    /// either reassembly buffer past its ceiling. That is a clean per-session
    /// failure — one tab with a diagnostic — which is what the allocation it
    /// replaces is not.
    pub fn inspect(&mut self, action: rdp_pdu::Action, frame: &[u8]) -> Result<(), ProtocolError> {
        match action {
            rdp_pdu::Action::FastPath => self.inspect_fast_path(frame),
            rdp_pdu::Action::X224 => self.inspect_x224(frame),
        }
    }

    /// MS-RDPBCGR §2.2.9.1.2: one fast-path PDU carries a header and then any
    /// number of updates, each with its own fragmentation field.
    fn inspect_fast_path(&mut self, frame: &[u8]) -> Result<(), ProtocolError> {
        let mut cursor = ReadCursor::new(frame);
        if decode_cursor::<FastPathHeader>(&mut cursor).is_err() {
            // Undecodable here is undecodable there: the library runs this same
            // decoder a moment later and fails the session itself. Reporting it
            // twice in two different words helps nobody.
            return Ok(());
        }
        while !cursor.is_empty() {
            let Ok(update) = decode_cursor::<FastPathUpdatePdu<'_>>(&mut cursor) else {
                return Ok(());
            };
            let carried = u64::try_from(update.data.len()).unwrap_or(u64::MAX);
            match update.fragmentation {
                // The buffer is discarded, not grown.
                Fragmentation::Single => self.fastpath = None,
                Fragmentation::First => {
                    self.fastpath = Some(check_fast_path(carried)?);
                }
                Fragmentation::Next => {
                    if let Some(held) = self.fastpath {
                        self.fastpath = Some(check_fast_path(held.saturating_add(carried))?);
                    }
                }
                Fragmentation::Last => {
                    if let Some(held) = self.fastpath {
                        // Checked *before* the buffer is released: the peak the
                        // library reaches is the append, and the release comes
                        // after it.
                        check_fast_path(held.saturating_add(carried))?;
                        self.fastpath = None;
                    }
                }
            }
        }
        Ok(())
    }

    /// MS-RDPBCGR §3.1.5.2.2: a static virtual channel PDU may be split into
    /// chunks, each repeating the Channel PDU Header, with the last one
    /// carrying `CHANNEL_FLAG_LAST`.
    fn inspect_x224(&mut self, frame: &[u8]) -> Result<(), ProtocolError> {
        if self.channels.is_empty() {
            return Ok(());
        }
        // Not every X.224 PDU is a Send Data Indication — a Disconnect Provider
        // Ultimatum is not — and one that is not carries no channel data.
        let Ok(indication) = rdp_pdu::mcs::decode_send_data_indication(frame) else {
            return Ok(());
        };
        let Some(channel) = self
            .channels
            .iter_mut()
            .find(|channel| channel.id == indication.channel_id)
        else {
            return Ok(());
        };
        let mut cursor = ReadCursor::new(indication.user_data);
        let Ok(header) = decode_cursor::<ChannelPduHeader>(&mut cursor) else {
            return Ok(());
        };

        // The declared total, which `dechunkify` never reads. Refusing an
        // absurd one on the first chunk turns a slow accumulation into an
        // immediate, accurate diagnostic; the running total below is what
        // actually holds when the declaration is a lie.
        if u64::from(header.length) > u64::from(MAX_SVC_REASSEMBLY_BYTES) {
            return Err(violation(
                "the server announced a virtual channel PDU larger than this build will reassemble",
            ));
        }
        let chunk = u64::try_from(cursor.len()).unwrap_or(u64::MAX);
        let held = channel.held.saturating_add(chunk);
        if held > u64::from(MAX_SVC_REASSEMBLY_BYTES) {
            return Err(violation(
                "the server sent more virtual channel chunks than this build will reassemble",
            ));
        }
        channel.held = if header.flags.contains(ChannelControlFlags::FLAG_LAST) {
            0
        } else {
            held
        };
        Ok(())
    }
}

/// Refuses a fast-path reassembly past the buffer size this client advertised.
fn check_fast_path(held: u64) -> Result<u64, ProtocolError> {
    if held > u64::from(MAX_FASTPATH_REASSEMBLY_BYTES) {
        return Err(violation(
            "the server sent a fast-path update larger than the reassembly buffer this client advertised",
        ));
    }
    Ok(held)
}

/// Reads the length of the next RDP PDU, X.224 or fast-path.
///
/// A thin adapter over `rdp_pdu::find_size`, which reads the TPKT length
/// (MS-RDPBCGR §2.2.1.1) or the fast-path header's 7- or 15-bit length
/// (§2.2.9.1.2) depending on the first byte.
///
/// # Errors
///
/// [`ProtocolError::ProtocolViolation`] if the first byte names no known
/// action, which is what a non-RDP service on port 3389 looks like.
pub fn rdp_pdu_length(bytes: &[u8]) -> Result<Option<usize>, ProtocolError> {
    match rdp_pdu::find_size(bytes) {
        Ok(Some(info)) => Ok(Some(info.length)),
        Ok(None) => Ok(None),
        Err(_) => Err(violation(
            "the server sent something that is not an RDP PDU",
        )),
    }
}

/// Reads the length of the next PDU and refuses one that is not X.224.
///
/// For a caller that wants a fast-path update to be an error rather than
/// something to skip — a test, or a phase where one genuinely cannot arrive.
/// The connection sequence uses [`Framed::read_x224_pdu`] instead, because a
/// server is allowed to start drawing before the sequence ends.
///
/// # Errors
///
/// As [`rdp_pdu_length`], plus a violation for a fast-path PDU.
pub fn x224_pdu_length(bytes: &[u8]) -> Result<Option<usize>, ProtocolError> {
    match rdp_pdu::find_size(bytes) {
        Ok(Some(info)) if info.action == rdp_pdu::Action::X224 => Ok(Some(info.length)),
        Ok(Some(_)) => Err(violation(
            "the server sent a fast-path update during the connection sequence",
        )),
        Ok(None) => Ok(None),
        Err(_) => Err(violation(
            "the server sent something that is not an RDP PDU",
        )),
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
    use super::*;
    use remoter_proto::{TransportKind, TransportPeer};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    fn target() -> HostPort {
        HostPort::new("ts-01.corp.example", 3389).unwrap()
    }

    /// A transport that replays a fixed script, one chunk per read, and
    /// reports when it is dropped — so a leaked stream is a failing test here
    /// rather than a slow leak in production.
    struct Script {
        chunks: std::collections::VecDeque<Vec<u8>>,
        peer: TransportPeer,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Script {
        fn new(chunks: Vec<Vec<u8>>, dropped: Arc<std::sync::atomic::AtomicBool>) -> Self {
            Self {
                chunks: chunks.into(),
                peer: TransportPeer::direct(TransportKind::Tcp, target()),
                dropped,
            }
        }
    }

    impl Drop for Script {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl AsyncRead for Script {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.chunks.pop_front() {
                Some(chunk) => {
                    let take = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..take]);
                    if take < chunk.len() {
                        self.chunks.push_front(chunk[take..].to_vec());
                    }
                    Poll::Ready(Ok(()))
                }
                // An empty read is end of stream, which is what a server that
                // hangs up looks like.
                None => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for Script {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Transport for Script {
        fn peer(&self) -> &TransportPeer {
            &self.peer
        }
    }

    /// A TPKT-framed X.224 PDU of `payload_len` bytes, as MS-RDPBCGR §2.2.1.1
    /// frames one: version 3, reserved 0, then a 16-bit big-endian total
    /// length.
    fn tpkt(payload: &[u8]) -> Vec<u8> {
        let total = u16::try_from(payload.len() + 4).unwrap();
        let mut out = vec![0x03, 0x00];
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn framed(chunks: Vec<Vec<u8>>) -> (Framed, Arc<std::sync::atomic::AtomicBool>) {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let transport = Script::new(chunks, Arc::clone(&dropped));
        (Framed::new(Box::new(transport), target()), dropped)
    }

    #[tokio::test]
    async fn a_pdu_split_across_reads_is_reassembled() {
        // The case a naive implementation gets wrong: TCP does not preserve
        // message boundaries, and a Windows server routinely splits a Demand
        // Active PDU across segments.
        let pdu = tpkt(&[0xaa; 40]);
        let (mut framed, _) = framed(vec![
            pdu[..3].to_vec(),
            pdu[3..10].to_vec(),
            pdu[10..].to_vec(),
        ]);
        let read = framed.read_pdu(x224_pdu_length).await.unwrap();
        assert_eq!(&read[..], &pdu[..]);
    }

    #[tokio::test]
    async fn two_pdus_in_one_read_are_delivered_one_at_a_time() {
        let first = tpkt(&[0x01; 8]);
        let second = tpkt(&[0x02; 12]);
        let mut both = first.clone();
        both.extend_from_slice(&second);
        let (mut framed, _) = framed(vec![both]);

        assert_eq!(
            &framed.read_pdu(x224_pdu_length).await.unwrap()[..],
            &first[..]
        );
        assert_eq!(
            &framed.read_pdu(x224_pdu_length).await.unwrap()[..],
            &second[..]
        );
    }

    #[tokio::test]
    async fn a_server_that_hangs_up_mid_pdu_is_a_disconnect() {
        let pdu = tpkt(&[0xaa; 40]);
        let (mut framed, _) = framed(vec![pdu[..8].to_vec()]);
        let error = framed.read_pdu(x224_pdu_length).await.unwrap_err();
        assert!(matches!(error, ProtocolError::Disconnected { .. }));
    }

    #[tokio::test]
    async fn a_fast_path_update_during_the_connection_sequence_is_refused() {
        // Both ends must agree about where in the sequence they are; decoding
        // a fast-path update as an MCS PDU fails several steps later, where
        // the message is useless.
        let (mut framed, _) = framed(vec![vec![0x00, 0x08, 0, 0, 0, 0, 0, 0]]);
        let error = framed.read_pdu(x224_pdu_length).await.unwrap_err();
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[tokio::test]
    async fn a_fast_path_update_before_the_sequence_ends_is_skipped_and_not_fatal() {
        // MS-RDPBCGR §1.3.1.1: the server may start sending graphics as soon
        // as it has the Client Font List PDU, which is before the client has
        // seen the Font Map that ends the sequence. Treating one of those as
        // an error fails an ordinary connection to Windows.
        let update = vec![0x00, 0x08, 0, 0, 0, 0, 0, 0];
        let font_map = tpkt(&[0x09; 12]);
        let mut script = update.clone();
        script.extend_from_slice(&font_map);
        let (mut framed, _) = framed(vec![script]);

        assert_eq!(&framed.read_x224_pdu().await.unwrap()[..], &font_map[..]);
    }

    #[tokio::test]
    async fn something_that_is_not_rdp_on_port_3389_fails_immediately() {
        // `SSH-2.0-OpenSSH_9.6` — a mistyped port, which should say so rather
        // than time out.
        let (mut framed, _) = framed(vec![b"SSH-2.0-OpenSSH_9.6\r\n".to_vec()]);
        let error = framed.read_pdu(rdp_pdu_length).await.unwrap_err();
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[tokio::test]
    async fn an_implausibly_large_pdu_is_refused_before_it_is_allocated() {
        // The length is the peer's claim. Honouring it is how a compromised
        // host turns one connection into an out-of-memory abort.
        let oversized = |bytes: &[u8]| -> Result<Option<usize>, ProtocolError> {
            Ok((!bytes.is_empty()).then_some(MAX_PDU_BYTES + 1))
        };
        let (mut framed, _) = framed(vec![vec![0x03, 0x00, 0xff, 0xff]]);
        let error = framed.read_pdu(oversized).await.unwrap_err();
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[tokio::test]
    async fn dropping_the_stream_drops_the_injected_transport() {
        // The property a leaked task destroys. A cancelled connection attempt
        // drops this value, and the socket must go with it — there is no
        // background task holding a copy.
        let (framed, dropped) = framed(vec![]);
        assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
        drop(framed);
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn reading_an_exact_count_leaves_the_rest_buffered() {
        // The Early User Authorization Result PDU is four bytes with no
        // header; the licensing PDU behind it must still be readable.
        let mut script = 0u32.to_le_bytes().to_vec();
        let following = tpkt(&[0x07; 6]);
        script.extend_from_slice(&following);
        let (mut framed, _) = framed(vec![script]);

        assert_eq!(&framed.read_exact(4).await.unwrap()[..], &[0, 0, 0, 0]);
        assert_eq!(
            &framed.read_pdu(x224_pdu_length).await.unwrap()[..],
            &following[..]
        );
    }

    #[tokio::test]
    async fn bytes_sent_before_the_tls_handshake_are_refused() {
        // Carrying them across the upgrade would inject unauthenticated bytes
        // into the encrypted stream.
        let (mut framed, _) = framed(vec![vec![0x16, 0x03, 0x03]]);
        // Put something in the buffer without consuming it.
        framed.fill().await.unwrap();
        let error = framed.upgrade_to_tls().await.unwrap_err();
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    /// One fast-path server update PDU (MS-RDPBCGR §2.2.9.1.2) carrying a
    /// single update structure with the given fragmentation field.
    fn fast_path(fragmentation: Fragmentation, payload: &[u8]) -> Vec<u8> {
        use ironrdp::core::encode_vec;
        use ironrdp::pdu::fast_path::{EncryptionFlags, UpdateCode};

        let update = FastPathUpdatePdu {
            fragmentation,
            update_code: UpdateCode::SurfaceCommands,
            compression_flags: None,
            compression_type: None,
            data: payload,
        };
        let body = encode_vec(&update).unwrap();
        let header = FastPathHeader::new(EncryptionFlags::empty(), body.len());
        let mut frame = encode_vec(&header).unwrap();
        frame.extend_from_slice(&body);
        frame
    }

    /// One static virtual channel chunk (§3.1.5.2.2) on `channel`, inside the
    /// MCS Send Data Indication every server-to-client PDU travels in.
    fn channel_chunk(
        channel: u16,
        declared: u32,
        flags: ChannelControlFlags,
        payload: &[u8],
    ) -> Vec<u8> {
        use ironrdp::core::encode_vec;
        use ironrdp::pdu::mcs::SendDataIndication;
        use ironrdp::pdu::x224::X224;

        let mut user_data = encode_vec(&ChannelPduHeader {
            length: declared,
            flags,
        })
        .unwrap();
        user_data.extend_from_slice(payload);
        encode_vec(&X224(SendDataIndication {
            initiator_id: 1002,
            channel_id: channel,
            user_data: std::borrow::Cow::Owned(user_data),
        }))
        .unwrap()
    }

    const SVC_CHANNEL: u16 = 1006;

    #[test]
    fn an_unfragmented_fast_path_update_never_accumulates_however_many_arrive() {
        // `CompleteData` discards its buffer on `Single`, so a session that
        // runs for hours must not be refused for the traffic it carried. A
        // guard that counted every update instead of the reassembled ones
        // would end a working session after eight megabytes of ordinary
        // graphics, which is a few seconds of a busy desktop.
        let mut guard = Reassembly::new([SVC_CHANNEL]);
        let payload = vec![0x5a_u8; 16 * 1024];
        for _ in 0..1024 {
            guard
                .inspect(
                    rdp_pdu::Action::FastPath,
                    &fast_path(Fragmentation::Single, &payload),
                )
                .unwrap();
        }
    }

    #[test]
    fn a_fast_path_reassembly_that_never_ends_is_refused() {
        // The defect: `CompleteData::append_data` extends `fragmented_data`
        // for every `Next` with no declared total and no ceiling, so `First`
        // followed by `Next` for ever is an allocation the server sizes.
        let mut guard = Reassembly::new([SVC_CHANNEL]);
        // 16 KiB a fragment: a size a real server sends, and well inside the
        // 15-bit length field a fast-path PDU carries (§2.2.9.1.2).
        let payload = vec![0xa5_u8; 16 * 1024];
        guard
            .inspect(
                rdp_pdu::Action::FastPath,
                &fast_path(Fragmentation::First, &payload),
            )
            .unwrap();

        let mut refused = None;
        for _ in 0..2048 {
            if let Err(error) = guard.inspect(
                rdp_pdu::Action::FastPath,
                &fast_path(Fragmentation::Next, &payload),
            ) {
                refused = Some(error);
                break;
            }
        }
        let Some(error) = refused else {
            panic!("the reassembly grew past 32 MiB without being refused");
        };
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
        assert!(error.to_string().contains("reassembly buffer"), "{error}");
    }

    #[test]
    fn a_completed_reassembly_gives_the_next_one_the_whole_budget_back() {
        // The counter must follow `CompleteData`, which *takes* the buffer on
        // `Last`. A guard that only ever added would refuse the second
        // large-but-legal update of a session.
        let mut guard = Reassembly::new([SVC_CHANNEL]);
        let payload = vec![0u8; 16 * 1024];
        for _ in 0..4 {
            guard
                .inspect(
                    rdp_pdu::Action::FastPath,
                    &fast_path(Fragmentation::First, &payload),
                )
                .unwrap();
            // 400 fragments of 16 KiB is 6.4 MiB: a reassembly that comes close
            // to the ceiling without reaching it must still complete.
            for _ in 0..400 {
                guard
                    .inspect(
                        rdp_pdu::Action::FastPath,
                        &fast_path(Fragmentation::Next, &payload),
                    )
                    .unwrap();
            }
            guard
                .inspect(
                    rdp_pdu::Action::FastPath,
                    &fast_path(Fragmentation::Last, &payload),
                )
                .unwrap();
        }
    }

    #[test]
    fn a_next_fragment_with_no_first_before_it_grows_nothing() {
        // `append_data` warns and returns when `fragmented_data` is `None`, so
        // counting these would refuse a session for bytes the library never
        // held.
        let mut guard = Reassembly::new([SVC_CHANNEL]);
        let payload = vec![0u8; 16 * 1024];
        for _ in 0..2048 {
            guard
                .inspect(
                    rdp_pdu::Action::FastPath,
                    &fast_path(Fragmentation::Next, &payload),
                )
                .unwrap();
        }
    }

    #[test]
    fn a_virtual_channel_pdu_declaring_an_absurd_total_is_refused_on_its_first_chunk() {
        // `ChunkProcessor::dechunkify` never reads the declared length at all.
        // Refusing it here turns a four-gigabyte accumulation into an
        // immediate, accurate diagnostic.
        let mut guard = Reassembly::new([SVC_CHANNEL]);
        let frame = channel_chunk(
            SVC_CHANNEL,
            u32::MAX,
            ChannelControlFlags::FLAG_FIRST,
            &[0u8; 16],
        );
        let error = guard.inspect(rdp_pdu::Action::X224, &frame).unwrap_err();
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
        assert!(
            error.to_string().contains("larger than this build"),
            "{error}"
        );
    }

    #[test]
    fn virtual_channel_chunks_that_never_set_the_last_flag_are_refused() {
        // The declared total may also be a lie: every chunk here announces a
        // modest length and none of them ends the PDU, which is what makes the
        // running total and not the declaration the thing that holds.
        let mut guard = Reassembly::new([SVC_CHANNEL]);
        // 16000 bytes a chunk. The MCS Send Data Indication's user data is
        // PER-length encoded (§2.2.1.11), so a chunk may not reach 32 KiB.
        let payload = vec![0u8; 16_000];
        let declared = u32::try_from(payload.len()).unwrap();

        let mut refused = None;
        for _ in 0..512 {
            let frame = channel_chunk(
                SVC_CHANNEL,
                declared,
                ChannelControlFlags::empty(),
                &payload,
            );
            if let Err(error) = guard.inspect(rdp_pdu::Action::X224, &frame) {
                refused = Some(error);
                break;
            }
        }
        let Some(error) = refused else {
            panic!("eight megabytes of chunks accumulated without being refused");
        };
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
        assert!(
            error.to_string().contains("more virtual channel chunks"),
            "{error}"
        );
    }

    #[test]
    fn a_channel_pdu_that_ends_releases_what_it_held() {
        let mut guard = Reassembly::new([SVC_CHANNEL]);
        let payload = vec![0u8; 16_000];
        let declared = u32::try_from(payload.len()).unwrap();
        for _ in 0..512 {
            let frame = channel_chunk(
                SVC_CHANNEL,
                declared,
                ChannelControlFlags::FLAG_FIRST | ChannelControlFlags::FLAG_LAST,
                &payload,
            );
            guard.inspect(rdp_pdu::Action::X224, &frame).unwrap();
        }
    }

    #[test]
    fn traffic_on_a_channel_that_is_not_a_static_virtual_channel_is_not_counted() {
        // The I/O and message channels are routed somewhere other than
        // `ChunkProcessor`, and their payloads are not Channel PDU Headers.
        // Counting them would refuse a conforming server for bytes nothing
        // accumulated.
        let mut guard = Reassembly::new([SVC_CHANNEL]);
        let payload = vec![0u8; 16_000];
        for _ in 0..512 {
            let frame = channel_chunk(1003, u32::MAX, ChannelControlFlags::empty(), &payload);
            guard.inspect(rdp_pdu::Action::X224, &frame).unwrap();
        }
    }

    #[test]
    fn the_advertised_reassembly_buffer_and_the_enforced_one_are_the_same_number() {
        // The bound is honest only because the server was told it: the Client
        // Confirm Active PDU's Multifragment Update capability carries exactly
        // this figure (MS-RDPBCGR §2.2.7.2.6). If one of the two moves without
        // the other, this client starts refusing updates it invited.
        assert_eq!(MAX_FASTPATH_REASSEMBLY_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn the_stream_never_debug_prints_its_contents() {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut framed = Framed::new(
            Box::new(Script::new(vec![], Arc::clone(&dropped))),
            target(),
        );
        framed
            .buffer
            .extend_from_slice(b"a screenful of somebody's desktop");
        let rendered = format!("{framed:?}");
        assert!(!rendered.contains("desktop"), "{rendered}");
        assert!(rendered.contains("buffered: 33"), "{rendered}");
    }
}
