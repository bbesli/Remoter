//! Test scaffolding: a [`Transport`] over an in-memory pipe.
//!
//! Compiled only for this crate's own tests and for the `integration-tests`
//! feature. It exists so that the connection path can be exercised without a
//! socket — the injected-transport design (ADR-0003) makes that possible, and
//! a test that cannot reach the network is a test that runs everywhere.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use remoter_proto::{HostPort, Transport, TransportKind, TransportPeer};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// One end of a `tokio::io::duplex` pair, presented as a transport.
#[derive(Debug)]
pub struct PipeTransport {
    stream: DuplexStream,
    peer: TransportPeer,
}

impl PipeTransport {
    /// Wraps `stream`, claiming to be connected to `target`.
    #[must_use]
    pub fn new(stream: DuplexStream, target: HostPort) -> Self {
        Self {
            stream,
            peer: TransportPeer::direct(TransportKind::Tcp, target),
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
