//! A scripted RFB server, and a [`Transport`] over an in-memory pipe.
//!
//! Compiled only for this crate's own tests and for the `integration-tests`
//! feature.
//!
//! # Why the adapter can be tested with no network at all
//!
//! ADR-0003: the transport is injected. So a test can hand the adapter one end
//! of a `tokio::io::duplex` pair, write RFB bytes into the other end by hand,
//! and exercise the entire handshake, every decoder and the whole session loop
//! without a socket, a port, a fixture container or a second machine.
//!
//! That is not only convenient. A test whose transport is a memory pipe cannot
//! pass if the crate opens a connection of its own, because there would be
//! nothing at the other end of it — so the tests below are, incidentally, the
//! behavioural half of the proof that this crate never dials. The structural
//! half is in `tests/no_dialling.rs`.
//!
//! # Everything here is written from RFC 6143
//!
//! The server side is the mirror of the client the adapter drives, so each
//! writer names the section it implements. Nothing is copied from `vnc-rs`;
//! a test harness derived from the implementation under test proves only that
//! the implementation agrees with itself.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use remoter_proto::{HostPort, Transport, TransportKind, TransportPeer};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};

/// How much the in-memory pipe buffers before a writer waits.
///
/// Large enough for a full 640x480 raw frame — 1.2 MiB — because a test that
/// deadlocks on its own fixture teaches nothing about the code under test.
pub const PIPE_CAPACITY: usize = 4 * 1024 * 1024;

/// One end of a `tokio::io::duplex` pair, presented as a transport.
///
/// The peer description is settable so a test can claim to be the far end of an
/// SSH chain, which is how "a tunnelled session needs no special code here" is
/// checked rather than asserted.
#[derive(Debug)]
pub struct PipeTransport {
    stream: DuplexStream,
    peer: TransportPeer,
}

impl PipeTransport {
    /// Wraps `stream`, claiming to be a direct TCP connection to `target`.
    #[must_use]
    pub fn new(stream: DuplexStream, target: HostPort) -> Self {
        Self {
            stream,
            peer: TransportPeer::direct(TransportKind::Tcp, target),
        }
    }

    /// Wraps `stream`, claiming to be an SSH channel through `via`.
    ///
    /// The adapter cannot tell the difference, which is the whole point of
    /// ADR-0003 — but it does read the *description*, to decide whether the
    /// clear-text warning applies.
    #[must_use]
    pub fn tunnelled(stream: DuplexStream, target: HostPort, via: Vec<String>) -> Self {
        Self {
            stream,
            peer: TransportPeer::through(TransportKind::SshChannel, target, via),
        }
    }
}

impl Transport for PipeTransport {
    fn peer(&self) -> &TransportPeer {
        &self.peer
    }
}

impl AsyncRead for PipeTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for PipeTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// A pipe with a transport on one end and this harness on the other.
#[must_use]
pub fn transport_pair(target: HostPort) -> (PipeTransport, RfbServer) {
    let (client, server) = duplex(PIPE_CAPACITY);
    (PipeTransport::new(client, target), RfbServer::new(server))
}

/// The same, describing the client end as the far side of an SSH chain.
#[must_use]
pub fn tunnelled_pair(target: HostPort, via: Vec<String>) -> (PipeTransport, RfbServer) {
    let (client, server) = duplex(PIPE_CAPACITY);
    (
        PipeTransport::tunnelled(client, target, via),
        RfbServer::new(server),
    )
}

/// Which security type a scripted server should offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// RFC 6143 §7.2.1: no authentication.
    None,
    /// RFC 6143 §7.2.2: the DES challenge.
    VncAuth,
    /// Something this build does not implement, so the failure path can be
    /// exercised. The number is VeNCrypt's.
    VeNCrypt,
}

/// A scripted RFB server, driven by a test one message at a time.
///
/// It is not a VNC server: it answers exactly what a test tells it to answer,
/// including things a real server never would. That is the point — the
/// interesting cases are the malformed ones.
#[derive(Debug)]
pub struct RfbServer {
    stream: DuplexStream,
}

impl RfbServer {
    /// Wraps the server end of a pipe.
    #[must_use]
    pub const fn new(stream: DuplexStream) -> Self {
        Self { stream }
    }

    /// Writes raw bytes.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported. A closed pipe means the adapter gave up,
    /// which several tests treat as the expected outcome.
    pub async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await
    }

    /// Reads exactly `count` bytes the client sent.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn read_exact(&mut self, count: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0_u8; count];
        self.stream.read_exact(&mut buffer).await?;
        Ok(buffer)
    }

    /// Closes the connection, as a server that has been shut down would.
    pub async fn hang_up(mut self) {
        let _ = self.stream.shutdown().await;
        drop(self);
    }

    /// RFC 6143 §7.1.1: announces `version` and reads the client's reply.
    ///
    /// Returns the twelve bytes the client chose, so a test can assert what the
    /// version floor did rather than assume it.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn announce(&mut self, version: &[u8; 12]) -> io::Result<Vec<u8>> {
        self.write(version).await?;
        self.read_exact(12).await
    }

    /// RFC 6143 §7.1.2 in the 3.7/3.8 shape: a `U8` count, that many `U8` type
    /// numbers, and the client's one-byte selection.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn offer_list(&mut self, types: &[u8]) -> io::Result<u8> {
        let mut message = vec![u8::try_from(types.len()).unwrap_or(0)];
        message.extend_from_slice(types);
        self.write(&message).await?;
        Ok(self.read_exact(1).await?[0])
    }

    /// RFC 6143 §7.1.2 in the 3.3 shape: the server chooses, and sends a `U32`.
    ///
    /// There is no selection to read back; RFB 3.3 gives the client no reply.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn offer_single(&mut self, security_type: u32) -> io::Result<()> {
        self.write(&security_type.to_be_bytes()).await
    }

    /// RFC 6143 §7.2.2: a 16-byte challenge out, a 16-byte DES response back.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn challenge(&mut self) -> io::Result<Vec<u8>> {
        self.write(&[0x11; 16]).await?;
        self.read_exact(16).await
    }

    /// RFC 6143 §7.1.3's `SecurityResult`.
    ///
    /// The word is a parameter because the interesting values are the ones the
    /// RFC does not define: `vnc-rs` transmutes this into a two-variant
    /// `#[repr(u32)]` enum, so a test needs to be able to send `2`.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn security_result(&mut self, word: u32) -> io::Result<()> {
        self.write(&word.to_be_bytes()).await
    }

    /// RFC 6143 §7.1.1, then §7.1.2, then §7.2 — the whole 3.8 handshake up to
    /// the point where the client sends `ClientInit`.
    ///
    /// Returns the sixteen bytes of the client's authentication response when
    /// the security type was VNC authentication, so a test can assert something
    /// about them without ever knowing the password.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn handshake(&mut self, security: Security) -> io::Result<Option<Vec<u8>>> {
        let chosen = self.announce(b"RFB 003.008\n").await?;
        assert_eq!(
            &chosen[..],
            b"RFB 003.008\n",
            "the client must not choose a version above the server's"
        );

        let offered = match security {
            Security::None => 1_u8,
            Security::VncAuth => 2,
            Security::VeNCrypt => 19,
        };
        if security == Security::VeNCrypt {
            // The client refuses before it selects anything, so waiting for a
            // selection here would hang the test rather than fail it.
            self.write(&[1, offered]).await?;
            return Ok(None);
        }
        let selected = self.offer_list(&[offered]).await?;
        assert_eq!(selected, offered, "the client picks from what was offered");

        match security {
            Security::None => {
                // §7.1.3: in 3.8 the SecurityResult is always sent, even for
                // `None`. Zero is OK.
                self.security_result(0).await?;
                Ok(None)
            }
            Security::VncAuth => {
                let response = self.challenge().await?;
                self.security_result(0).await?;
                Ok(Some(response))
            }
            Security::VeNCrypt => Ok(None),
        }
    }

    /// RFC 6143 §7.3.1 and §7.3.2: reads `ClientInit` and answers `ServerInit`.
    ///
    /// Then reads whatever the client sends next — `SetPixelFormat` (§7.5.1),
    /// `SetEncodings` (§7.5.2) and the first `FramebufferUpdateRequest`
    /// (§7.5.3) — and hands the encoding numbers back so a test can assert
    /// which encodings were actually promised.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn initialise(&mut self, width: u16, height: u16) -> io::Result<Vec<i32>> {
        let shared = self.read_exact(1).await?;
        assert!(shared[0] <= 1, "the shared flag is a boolean");

        let mut init = Vec::new();
        init.extend_from_slice(&width.to_be_bytes());
        init.extend_from_slice(&height.to_be_bytes());
        // The 16-byte PIXEL_FORMAT of §7.4. 32bpp true colour, BGRX, which is
        // what the adapter asks for anyway.
        init.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
        let name = b"scripted";
        init.extend_from_slice(&u32::try_from(name.len()).unwrap_or(0).to_be_bytes());
        init.extend_from_slice(name);
        self.write(&init).await?;

        // §7.5.1 `SetPixelFormat`: type, three padding bytes, sixteen bytes of
        // format. The adapter always sends one; see `set_pixel_format`.
        let header = self.read_exact(4).await?;
        assert_eq!(header[0], 0, "SetPixelFormat is client message type 0");
        let _format = self.read_exact(16).await?;

        // §7.5.2 `SetEncodings`: type, one padding byte, a U16 count, then that
        // many S32 encoding numbers.
        let header = self.read_exact(4).await?;
        assert_eq!(header[0], 2, "SetEncodings is client message type 2");
        let count = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let body = self.read_exact(count * 4).await?;
        let encodings = body
            .chunks_exact(4)
            .map(|chunk| i32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();

        // §7.5.3 the first `FramebufferUpdateRequest`, which `vnc-rs` sends
        // itself: type, incremental flag, and four U16 coordinates.
        let request = self.read_exact(10).await?;
        assert_eq!(
            request[0], 3,
            "FramebufferUpdateRequest is client message type 3"
        );
        assert_eq!(request[1], 0, "the first request is non-incremental");

        Ok(encodings)
    }

    /// RFC 6143 §7.6.1: a `FramebufferUpdate` header for `count` rectangles.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn framebuffer_update(&mut self, count: u16) -> io::Result<()> {
        let mut header = vec![0_u8, 0];
        header.extend_from_slice(&count.to_be_bytes());
        self.write(&header).await
    }

    /// The twelve-byte rectangle header of RFC 6143 §7.6.1: four U16
    /// coordinates and an S32 encoding number.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn rectangle_header(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        encoding: i32,
    ) -> io::Result<()> {
        let mut header = Vec::with_capacity(12);
        header.extend_from_slice(&x.to_be_bytes());
        header.extend_from_slice(&y.to_be_bytes());
        header.extend_from_slice(&width.to_be_bytes());
        header.extend_from_slice(&height.to_be_bytes());
        header.extend_from_slice(&encoding.to_be_bytes());
        self.write(&header).await
    }

    /// RFC 6143 §7.6.4 `ServerCutText`: type, three padding bytes, a U32
    /// length, then Latin-1 text.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn cut_text(&mut self, text: &[u8]) -> io::Result<()> {
        let mut message = vec![3_u8, 0, 0, 0];
        message.extend_from_slice(&u32::try_from(text.len()).unwrap_or(0).to_be_bytes());
        message.extend_from_slice(text);
        self.write(&message).await
    }

    /// RFC 6143 §7.6.3 `Bell`: one byte and nothing else.
    ///
    /// # Errors
    ///
    /// Whatever the pipe reported.
    pub async fn bell(&mut self) -> io::Result<()> {
        self.write(&[2_u8]).await
    }
}
