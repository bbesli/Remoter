//! A scripted transport, so the connection sequence can be driven without a
//! Windows host.
//!
//! There is no substitute for a real server, and the report on this crate says
//! so plainly. What *can* be checked without one is the part where the defects
//! actually live: the state machine's ordering, the bytes it puts on the wire,
//! and what it does with a malformed or out-of-order reply. A scripted peer
//! that replays real IronRDP-encoded PDUs checks all three.
//!
//! The transport also records everything written to it, and reports when it is
//! dropped — so "a cancelled attempt frees its socket" is a failing test here
//! rather than a slow leak in production.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use parking_lot::Mutex;
use remoter_proto::{HostPort, Transport, TransportKind, TransportPeer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A transport that replays a fixed script and records what was written to it.
pub(crate) struct ScriptedTransport {
    reads: VecDeque<Vec<u8>>,
    written: Arc<Mutex<Vec<u8>>>,
    dropped: Arc<AtomicBool>,
    peer: TransportPeer,
}

impl ScriptedTransport {
    /// A transport that will hand back `reads`, one chunk per poll.
    #[must_use]
    pub(crate) fn new(target: HostPort, reads: Vec<Vec<u8>>) -> Self {
        Self {
            reads: reads.into(),
            written: Arc::new(Mutex::new(Vec::new())),
            dropped: Arc::new(AtomicBool::new(false)),
            peer: TransportPeer::direct(TransportKind::Tcp, target),
        }
    }

    /// A handle to everything written, readable after the transport has been
    /// moved into a [`crate::Framed`].
    #[must_use]
    pub(crate) fn written(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.written)
    }

    /// A flag set when this transport is dropped.
    #[must_use]
    pub(crate) fn dropped(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.dropped)
    }
}

impl Drop for ScriptedTransport {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for ScriptedTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.reads.pop_front() {
            Some(chunk) => {
                let take = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..take]);
                if take < chunk.len() {
                    self.reads.push_front(chunk[take..].to_vec());
                }
                Poll::Ready(Ok(()))
            }
            // An empty read is end of stream, which is what a server that
            // hangs up looks like.
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for ScriptedTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.written.lock().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Transport for ScriptedTransport {
    fn peer(&self) -> &TransportPeer {
        &self.peer
    }
}
