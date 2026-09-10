//! An SSH `direct-tcpip` channel, presented as a [`Transport`].
//!
//! RFC 4254 §7.2 defines `direct-tcpip`: the client asks the server to open a
//! TCP connection to a host *as the server sees it*, and the resulting channel
//! carries that connection's bytes. Wrapping it as a `Transport` is what makes
//! a jump host chain compose — hop 2's SSH handshake runs inside hop 1's
//! channel, and the adapter at the end cannot tell how many machines it
//! passed through (ADR-0003).
//!
//! **The owning connection travels with the channel.** Dropping an
//! `SshConnection` ends its session, which closes every channel on it,
//! including this one. A transport that did not hold its connection would work
//! in a test and close itself in production the moment the caller stopped
//! holding the handle.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use remoter_proto::{HostPort, Transport, TransportKind, TransportPeer};
use russh::client::Msg;
use russh::{Channel, ChannelStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::connection::SshConnection;

/// A `direct-tcpip` channel as a byte stream.
pub struct SshChannelTransport {
    stream: ChannelStream<Msg>,
    peer: TransportPeer,
    /// Kept alive for the channel's lifetime; never read. See the module
    /// documentation.
    _owner: Option<Arc<SshConnection>>,
}

impl SshChannelTransport {
    /// Wraps an opened channel.
    ///
    /// The caller must keep the SSH session alive for at least as long as the
    /// returned transport. Prefer [`with_session`](Self::with_session), which
    /// makes that structural rather than a rule to remember.
    #[must_use]
    pub fn new(channel: Channel<Msg>, target: HostPort, via: Vec<String>) -> Self {
        Self {
            stream: channel.into_stream(),
            peer: TransportPeer::through(TransportKind::SshChannel, target, via),
            _owner: None,
        }
    }

    /// Wraps an opened channel and takes a share of the session it belongs to.
    #[must_use]
    pub fn with_session(
        channel: Channel<Msg>,
        target: HostPort,
        via: Vec<String>,
        owner: Arc<SshConnection>,
    ) -> Self {
        Self {
            stream: channel.into_stream(),
            peer: TransportPeer::through(TransportKind::SshChannel, target, via),
            _owner: Some(owner),
        }
    }
}

impl std::fmt::Debug for SshChannelTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshChannelTransport")
            .field("peer", &self.peer)
            .finish()
    }
}

impl Transport for SshChannelTransport {
    fn peer(&self) -> &TransportPeer {
        &self.peer
    }
}

// `ChannelStream` is `Unpin`, so every projection below is a safe `Pin::new`.
// That is why `Transport` requires `Unpin`: without it these delegations would
// need `unsafe`, which this crate forbids.
impl AsyncRead for SshChannelTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshChannelTransport {
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_transport_is_a_transport() {
        // The bound the chain builder needs; asserted at compile time so a
        // change to `ChannelStream`'s auto traits shows up here rather than at
        // the first jump host.
        const fn assert_transport<T: Transport>() {}
        assert_transport::<SshChannelTransport>();
    }

    #[test]
    fn the_peer_describes_the_whole_path() {
        // Built without a channel, because the description is what is under
        // test and a channel needs a server.
        let target = HostPort::new("db-01.internal", 5432).unwrap();
        let peer = TransportPeer::through(
            TransportKind::SshChannel,
            target,
            vec!["bastion-1".to_owned(), "jump-eu".to_owned()],
        );
        assert_eq!(peer.hop_count(), 2);
        assert_eq!(
            peer.to_string(),
            "db-01.internal:5432 via bastion-1 → jump-eu"
        );
    }
}
