//! Reading whole PDUs off an injected transport, and upgrading it to TLS.
//!
//! RDP is a byte stream carrying self-delimiting PDUs, so something has to
//! accumulate bytes until a whole one is present. That is all this module is —
//! but two properties of it are load-bearing:
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

use std::sync::Arc;

use bytes::BytesMut;
use ironrdp::pdu as rdp_pdu;
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
