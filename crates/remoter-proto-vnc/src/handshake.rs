//! Watching the RFB handshake go past, so a failure can be explained.
//!
//! # Why this exists
//!
//! `vnc-rs` owns the socket from the first byte, and when its security
//! handshake fails it produces one of two things: `VncError::WrongPassword`, or
//! `VncError::General` carrying either the *server's* reason string
//! (RFC 6143 §7.1.2) or an English sentence about a security type it has not
//! implemented. Neither may be shown to the user — the first is peer-authored
//! text and the second is a library internal — so on its own the adapter can
//! say no more than "the handshake failed".
//!
//! The information the user actually needs was on the wire a moment earlier.
//! RFC 6143 §7.1.1 and §7.1.2 put the protocol version and the list of security
//! types the server accepts in the first few bytes of the stream, in the clear,
//! before anything else happens. [`HandshakeObserver`] reads them as they pass
//! and stops looking, which turns "the handshake failed" into "this server
//! offers VeNCrypt and Tight, and this build implements neither".
//!
//! # It is a parser, and it is fed by the network
//!
//! Everything below runs on bytes chosen by the far end. It therefore has no
//! allocation that the peer controls the size of, no arithmetic that can wrap
//! into a large read, and no state in which it can fail to terminate: the
//! observer accepts at most [`MAX_SECURITY_TYPES`] type bytes — the count field
//! is a `U8`, so 255 is the wire maximum — and then stops. It never rejects
//! anything, because it is not in the connection's path: its job is to describe
//! what happened, and a parser that could fail would be one more way for a
//! session to break.
//!
//! # The version is not simply what the server said
//!
//! RFC 6143 §7.1.1: the server sends its highest supported version, the client
//! replies with the version it will actually use, and that must not be higher
//! than the server's. So the security handshake that follows is shaped by
//! `min(ours, theirs)` — and the two shapes differ, because RFB 3.3 has the
//! *server* choose the security type and send it as a `U32` while 3.7 and 3.8
//! have it send a list for the client to choose from. The observer is told our
//! maximum at construction for exactly this reason; guessing from the server's
//! announcement alone would misparse every connection to a 3.8 server from a
//! connection pinned to 3.3.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use remoter_proto::{Transport, TransportPeer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::security::SecurityType;

/// Bytes in the version string (RFC 6143 §7.1.1): `RFB 003.008\n`.
pub const VERSION_BYTES: usize = 12;

/// The most security types a server can offer, because the count is a `U8`.
pub const MAX_SECURITY_TYPES: usize = u8::MAX as usize;

/// An RFB protocol version (RFC 6143 §7.1.1).
///
/// Only the three versions the RFC describes. §7.1.1 is explicit that any other
/// version number "should be interpreted as 3.3", because a server reporting
/// one does not implement the different handshake 3.7 and 3.8 introduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RfbVersion {
    /// RFB 3.3: the server chooses the security type.
    Rfb33,
    /// RFB 3.7: the server offers a list; no `SecurityResult` after `None`.
    Rfb37,
    /// RFB 3.8: the server offers a list, and always sends a `SecurityResult`.
    Rfb38,
}

impl RfbVersion {
    /// The twelve bytes this version is written as.
    #[must_use]
    pub const fn as_wire(self) -> &'static [u8; VERSION_BYTES] {
        match self {
            Self::Rfb33 => b"RFB 003.003\n",
            Self::Rfb37 => b"RFB 003.007\n",
            Self::Rfb38 => b"RFB 003.008\n",
        }
    }

    /// Reads a version string, following RFC 6143 §7.1.1's instruction to
    /// treat anything unrecognised as 3.3.
    #[must_use]
    pub const fn from_wire(bytes: &[u8; VERSION_BYTES]) -> Self {
        match bytes {
            b"RFB 003.008\n" => Self::Rfb38,
            b"RFB 003.007\n" => Self::Rfb37,
            _ => Self::Rfb33,
        }
    }

    /// A stable name for a log line or a message-catalogue argument.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rfb33 => "3.3",
            Self::Rfb37 => "3.7",
            Self::Rfb38 => "3.8",
        }
    }

    /// The version both ends will use: the lower of the two (§7.1.1).
    #[must_use]
    pub fn negotiated_with(self, server: Self) -> Self {
        self.min(server)
    }
}

/// What phase of the handshake the observer is watching for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Collecting the twelve version bytes.
    Version,
    /// Collecting the security-type list, in whichever shape the negotiated
    /// version calls for.
    Security,
    /// Everything interesting has gone past. Later bytes are pixels.
    Done,
}

/// What the handshake said, as far as it got.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HandshakeFacts {
    /// The version the server announced, once twelve bytes have arrived.
    pub server_version: Option<RfbVersion>,
    /// The version both ends will therefore use.
    pub negotiated_version: Option<RfbVersion>,
    /// The security types the server offered, in the order it offered them.
    /// Empty until the list has been read, and empty for a server that refused
    /// the connection outright (RFC 6143 §7.1.2, count zero).
    pub offered_security: Vec<SecurityType>,
    /// Whether the server refused before offering anything — the `U8` count was
    /// zero, or RFB 3.3's `U32` was `0`. A reason string follows on the wire,
    /// and it is deliberately not read: it is peer-authored text.
    pub refused_outright: bool,
}

impl HandshakeFacts {
    /// The offered types this build could actually negotiate.
    #[must_use]
    pub fn usable_security(&self) -> Vec<SecurityType> {
        self.offered_security
            .iter()
            .copied()
            .filter(|kind| kind.is_implemented())
            .collect()
    }

    /// Whether the server offered nothing this build implements.
    ///
    /// `false` while the list has not been read yet: "we did not see a list" is
    /// not "the list had nothing in it", and reporting the second when the
    /// first happened would blame the server for a network failure.
    #[must_use]
    pub fn security_is_unusable(&self) -> bool {
        !self.offered_security.is_empty() && self.usable_security().is_empty()
    }

    /// The offered types as names, for
    /// [`remoter_proto::ProtocolError::AuthMethodUnavailable`].
    #[must_use]
    pub fn offered_names(&self) -> Vec<String> {
        self.offered_security
            .iter()
            .map(|kind| kind.name().to_owned())
            .collect()
    }
}

/// A state machine that reads the handshake out of a byte stream.
///
/// Fed by [`ObservingTransport`] one `poll_read` at a time, so it must cope
/// with the stream being split anywhere — including in the middle of the
/// version string, which is exactly what happens on a slow link and never
/// happens in a test that writes the handshake in one call.
#[derive(Debug)]
pub struct HandshakeObserver {
    our_max: RfbVersion,
    phase: Phase,
    /// At most `VERSION_BYTES` while reading the version, then at most
    /// `MAX_SECURITY_TYPES + 1` while reading the list. Bounded by the format,
    /// not by the peer.
    partial: Vec<u8>,
    /// How many type bytes the server said it would send. `None` until the
    /// count byte has arrived.
    expected_types: Option<usize>,
    facts: HandshakeFacts,
}

impl HandshakeObserver {
    /// An observer for a connection that will offer `our_max` as its version.
    #[must_use]
    pub fn new(our_max: RfbVersion) -> Self {
        Self {
            our_max,
            phase: Phase::Version,
            partial: Vec::with_capacity(VERSION_BYTES),
            expected_types: None,
            facts: HandshakeFacts::default(),
        }
    }

    /// What has been learned so far.
    #[must_use]
    pub const fn facts(&self) -> &HandshakeFacts {
        &self.facts
    }

    /// Whether there is nothing left to watch for.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.phase == Phase::Done
    }

    /// Feeds the next bytes read from the server.
    ///
    /// Bytes arriving after the handshake are ignored without being copied:
    /// this runs on the read path of a framebuffer stream, and buffering pixels
    /// to look for a header that has already gone past would be a copy of the
    /// entire session.
    pub fn observe(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            match self.phase {
                Phase::Done => return,
                Phase::Version => {
                    let wanted = VERSION_BYTES - self.partial.len();
                    let take = wanted.min(bytes.len());
                    self.partial.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if self.partial.len() < VERSION_BYTES {
                        return;
                    }
                    let mut version = [0_u8; VERSION_BYTES];
                    version.copy_from_slice(&self.partial);
                    let server = RfbVersion::from_wire(&version);
                    self.facts.server_version = Some(server);
                    self.facts.negotiated_version = Some(self.our_max.negotiated_with(server));
                    self.partial.clear();
                    self.phase = Phase::Security;
                }
                Phase::Security => {
                    let negotiated = self.facts.negotiated_version.unwrap_or(RfbVersion::Rfb33);
                    let consumed = if negotiated == RfbVersion::Rfb33 {
                        self.observe_single_type(bytes)
                    } else {
                        self.observe_type_list(bytes)
                    };
                    if consumed == 0 {
                        // More bytes are needed and none of these were usable.
                        return;
                    }
                    bytes = &bytes[consumed..];
                }
            }
        }
    }

    /// RFB 3.3 (RFC 6143 §7.1.2): the server sends one `U32` and the client
    /// has no say. A value of zero means the connection failed.
    fn observe_single_type(&mut self, bytes: &[u8]) -> usize {
        let wanted = 4 - self.partial.len();
        let take = wanted.min(bytes.len());
        self.partial.extend_from_slice(&bytes[..take]);
        if self.partial.len() < 4 {
            return take;
        }
        // The registry is a `U8` space; RFB 3.3 widens it to `U32` on the wire
        // and the low byte is the type. Reading only the low byte would make
        // `0x0000_0102` look like VNC authentication, so the whole word is
        // checked and anything above 255 is recorded as the invalid type it is.
        let word = u32::from_be_bytes([
            self.partial[0],
            self.partial[1],
            self.partial[2],
            self.partial[3],
        ]);
        match u8::try_from(word) {
            Ok(0) => self.facts.refused_outright = true,
            Ok(value) => self
                .facts
                .offered_security
                .push(SecurityType::from_wire(value)),
            Err(_) => self
                .facts
                .offered_security
                .push(SecurityType::from_wire(u8::MAX)),
        }
        self.partial.clear();
        self.phase = Phase::Done;
        take
    }

    /// RFB 3.7 and 3.8 (RFC 6143 §7.1.2): a `U8` count, then that many `U8`
    /// type numbers. A count of zero means the connection failed and a reason
    /// string follows.
    fn observe_type_list(&mut self, bytes: &[u8]) -> usize {
        let mut taken = 0;
        if self.expected_types.is_none() {
            let count = usize::from(bytes[0]);
            taken += 1;
            if count == 0 {
                self.facts.refused_outright = true;
                self.phase = Phase::Done;
                return taken;
            }
            self.expected_types = Some(count.min(MAX_SECURITY_TYPES));
        }
        let wanted = self.expected_types.unwrap_or(0);
        let remaining = wanted.saturating_sub(self.facts.offered_security.len());
        let available = bytes.len() - taken;
        let take = remaining.min(available);
        for byte in &bytes[taken..taken + take] {
            self.facts
                .offered_security
                .push(SecurityType::from_wire(*byte));
        }
        taken += take;
        if self.facts.offered_security.len() >= wanted {
            self.phase = Phase::Done;
        }
        taken
    }
}

/// A [`Transport`] that shows every byte it reads to a [`HandshakeObserver`].
///
/// It is a decorator, not a copy: `poll_read` fills the caller's buffer exactly
/// as the wrapped transport would, and the observer looks at the slice that was
/// just filled. Writes go straight through. Once the observer is finished it is
/// no longer consulted, so the cost on a running session is one comparison per
/// read.
///
/// This is what makes the whole arrangement possible without a pump task. The
/// alternative — reading the handshake ourselves before handing the stream to
/// `vnc-rs` — cannot work: `vnc-rs` starts at the version string, and a stream
/// with the first twelve bytes already consumed is a stream it cannot use.
pub struct ObservingTransport {
    inner: Box<dyn Transport>,
    observer: Arc<Mutex<HandshakeObserver>>,
    peer: TransportPeer,
}

impl ObservingTransport {
    /// Wraps `inner`, handing back the observer the caller will read later.
    #[must_use]
    pub fn new(
        inner: Box<dyn Transport>,
        our_max: RfbVersion,
    ) -> (Self, Arc<Mutex<HandshakeObserver>>) {
        let observer = Arc::new(Mutex::new(HandshakeObserver::new(our_max)));
        let peer = inner.peer().clone();
        (
            Self {
                inner,
                observer: Arc::clone(&observer),
                peer,
            },
            observer,
        )
    }
}

impl std::fmt::Debug for ObservingTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservingTransport")
            .field("peer", &self.peer)
            .finish()
    }
}

impl Transport for ObservingTransport {
    fn peer(&self) -> &TransportPeer {
        &self.peer
    }
}

impl AsyncRead for ObservingTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let outcome = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(outcome, Poll::Ready(Ok(()))) {
            let filled = buf.filled();
            if filled.len() > before {
                let mut observer = self.observer.lock();
                if !observer.is_finished() {
                    observer.observe(&filled[before..]);
                }
            }
        }
        outcome
    }
}

impl AsyncWrite for ObservingTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod tests {
    use super::*;

    /// Feeds `bytes` one chunk at a time, so a test proves the state machine
    /// survives a stream split wherever the network chose to split it.
    fn observe_in_chunks(our_max: RfbVersion, bytes: &[u8], chunk: usize) -> HandshakeObserver {
        let mut observer = HandshakeObserver::new(our_max);
        for slice in bytes.chunks(chunk.max(1)) {
            observer.observe(slice);
        }
        observer
    }

    #[test]
    fn a_38_handshake_yields_the_version_and_the_offered_types() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 003.008\n");
        wire.push(2); // number-of-security-types
        wire.push(1); // None
        wire.push(2); // VNC Authentication
        wire.extend_from_slice(b"pixels follow and must be ignored");

        let observer = observe_in_chunks(RfbVersion::Rfb38, &wire, 64);
        let facts = observer.facts();
        assert_eq!(facts.server_version, Some(RfbVersion::Rfb38));
        assert_eq!(facts.negotiated_version, Some(RfbVersion::Rfb38));
        assert_eq!(
            facts.offered_security,
            vec![SecurityType::NONE, SecurityType::VNC_AUTH]
        );
        assert!(!facts.refused_outright);
        assert!(!facts.security_is_unusable());
        assert!(observer.is_finished());
    }

    #[test]
    fn the_stream_may_be_split_at_any_byte() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 003.008\n");
        wire.push(3);
        wire.push(19); // VeNCrypt
        wire.push(16); // Tight
        wire.push(2); // VNC Authentication

        // One byte at a time is the worst case, and it is the one a slow link
        // actually produces.
        for chunk in [1, 2, 3, 5, 7, 12, 13, 16] {
            let observer = observe_in_chunks(RfbVersion::Rfb38, &wire, chunk);
            assert_eq!(
                observer.facts().offered_security,
                vec![
                    SecurityType::VENCRYPT,
                    SecurityType::TIGHT,
                    SecurityType::VNC_AUTH
                ],
                "split every {chunk} bytes"
            );
            assert!(observer.is_finished(), "split every {chunk} bytes");
        }
    }

    #[test]
    fn a_truncated_handshake_reports_what_it_saw_and_no_more() {
        // The server sent a version and then went away mid-list. Nothing here
        // may claim the list was empty: "we did not see it" and "there was
        // nothing in it" are different, and only one of them blames the server.
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 003.008\n");
        wire.push(4);
        wire.push(19);

        let observer = observe_in_chunks(RfbVersion::Rfb38, &wire, 3);
        assert_eq!(observer.facts().server_version, Some(RfbVersion::Rfb38));
        assert_eq!(
            observer.facts().offered_security,
            vec![SecurityType::VENCRYPT]
        );
        assert!(!observer.is_finished());
        assert!(!observer.facts().refused_outright);

        // And a version string that never completed says nothing at all.
        let observer = observe_in_chunks(RfbVersion::Rfb38, b"RFB 003.0", 4);
        assert_eq!(observer.facts().server_version, None);
        assert!(!observer.facts().security_is_unusable());
    }

    #[test]
    fn a_server_that_refuses_outright_is_recorded_as_such() {
        // RFC 6143 §7.1.2: a count of zero means the connection failed, and a
        // reason string follows. The reason string is peer-authored text and
        // is deliberately never read.
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 003.008\n");
        wire.push(0);
        wire.extend_from_slice(&[0, 0, 0, 5]);
        wire.extend_from_slice(b"go away");

        let observer = observe_in_chunks(RfbVersion::Rfb38, &wire, 5);
        assert!(observer.facts().refused_outright);
        assert!(observer.facts().offered_security.is_empty());
        assert!(observer.is_finished());
    }

    #[test]
    fn a_33_server_sends_one_type_as_a_word() {
        // RFB 3.3 has the server choose. The whole `U32` is read: taking the
        // low byte alone would make 0x0000_0102 look like VNC authentication.
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 003.003\n");
        wire.extend_from_slice(&2_u32.to_be_bytes());

        let observer = observe_in_chunks(RfbVersion::Rfb38, &wire, 7);
        assert_eq!(observer.facts().server_version, Some(RfbVersion::Rfb33));
        assert_eq!(
            observer.facts().negotiated_version,
            Some(RfbVersion::Rfb33),
            "the lower of the two versions wins"
        );
        assert_eq!(
            observer.facts().offered_security,
            vec![SecurityType::VNC_AUTH]
        );

        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 003.003\n");
        wire.extend_from_slice(&0x0000_0102_u32.to_be_bytes());
        let observer = observe_in_chunks(RfbVersion::Rfb38, &wire, 16);
        assert_ne!(
            observer.facts().offered_security,
            vec![SecurityType::VNC_AUTH],
            "a wide value is not its low byte"
        );
    }

    #[test]
    fn our_own_maximum_decides_which_shape_the_list_has() {
        // A client pinned to 3.3 talking to a 3.8 server negotiates 3.3, and
        // the server then sends a `U32` rather than a list. An observer that
        // trusted the server's announcement alone would misparse it.
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 003.008\n");
        wire.extend_from_slice(&1_u32.to_be_bytes());

        let observer = observe_in_chunks(RfbVersion::Rfb33, &wire, 16);
        assert_eq!(observer.facts().server_version, Some(RfbVersion::Rfb38));
        assert_eq!(observer.facts().negotiated_version, Some(RfbVersion::Rfb33));
        assert_eq!(observer.facts().offered_security, vec![SecurityType::NONE]);
    }

    #[test]
    fn an_unrecognised_version_is_treated_as_33_as_the_rfc_instructs() {
        // RFC 6143 §7.1.1: other version numbers are reported by some servers
        // but do not implement the 3.7 handshake, so they are 3.3.
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 004.001\n");
        wire.extend_from_slice(&2_u32.to_be_bytes());

        let observer = observe_in_chunks(RfbVersion::Rfb38, &wire, 16);
        assert_eq!(observer.facts().server_version, Some(RfbVersion::Rfb33));
        assert_eq!(
            observer.facts().offered_security,
            vec![SecurityType::VNC_AUTH]
        );
    }

    #[test]
    fn a_server_offering_nothing_we_implement_is_named_precisely() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 003.008\n");
        wire.push(2);
        wire.push(19); // VeNCrypt
        wire.push(30); // Apple Remote Desktop

        let observer = observe_in_chunks(RfbVersion::Rfb38, &wire, 16);
        assert!(observer.facts().security_is_unusable());
        assert!(observer.facts().usable_security().is_empty());
        assert_eq!(
            observer.facts().offered_names(),
            vec!["VeNCrypt".to_owned(), "Apple Remote Desktop".to_owned()]
        );
    }

    #[test]
    fn the_longest_possible_list_is_bounded_by_the_count_field() {
        // The count is a `U8`, so 255 is the wire maximum and there is no
        // input that makes the observer allocate more than that.
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 003.008\n");
        wire.push(255);
        wire.extend(std::iter::repeat_n(2_u8, 255));
        wire.extend_from_slice(b"and then pixels");

        let observer = observe_in_chunks(RfbVersion::Rfb38, &wire, 17);
        assert_eq!(observer.facts().offered_security.len(), MAX_SECURITY_TYPES);
        assert!(observer.is_finished());
    }

    #[test]
    fn bytes_after_the_handshake_are_not_retained() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"RFB 003.008\n");
        wire.push(1);
        wire.push(1);

        let mut observer = observe_in_chunks(RfbVersion::Rfb38, &wire, 64);
        assert!(observer.is_finished());
        // A megabyte of pixels through a finished observer must cost nothing.
        observer.observe(&vec![0xab; 1024 * 1024]);
        assert_eq!(observer.facts().offered_security, vec![SecurityType::NONE]);
        assert!(observer.partial.is_empty());
    }
}
