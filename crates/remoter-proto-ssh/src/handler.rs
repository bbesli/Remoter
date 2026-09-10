//! The `russh` client handler: everything the server initiates.
//!
//! Four of its callbacks matter here, and each one is a decision rather than a
//! formality:
//!
//! - **`check_server_key`** is the host key check. Its default implementation
//!   in `russh` rejects everything, which is the right default; this one
//!   delegates to [`crate::hostkey`].
//! - **`auth_banner`** carries text the *server* wrote. It is surfaced as a
//!   warning, bounded in length, and never interpreted.
//! - **`server_channel_open_forwarded_tcpip`** is a remote forward (`-R`)
//!   arriving. `russh`'s default accepts it; this one accepts only bindings
//!   the user actually asked for, because a server that opens a channel
//!   naming a port nobody forwarded is reaching into the local machine.
//! - **`server_channel_open_agent_forward`** is the remote asking to use the
//!   local agent. `russh`'s default accepts it. **This one refuses unless
//!   agent forwarding was explicitly enabled** — anyone with root on a host
//!   holding a forwarded agent can impersonate the user everywhere that key
//!   opens (`docs/features/tunneling.md`).

use std::sync::Arc;

use remoter_proto::{EventSink, ProtocolError, SessionEvent, SessionWarning};
use russh::client::{ChannelOpenHandle, Handler, Msg, Session};
use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelOpenFailure, Names};

use crate::algorithms::is_weak;
use crate::forward::RemoteForwards;
use crate::hostkey::HostKeyChecker;

/// The longest server banner surfaced to the interface.
///
/// A banner is attacker-controlled and arrives before authentication, so its
/// length is the server's choice. 8 KiB is more than any real
/// `/etc/issue.net`, and the cap means a hostile server cannot make the
/// application allocate on demand.
pub const MAX_BANNER_BYTES: usize = 8 * 1024;

/// What a handler callback can fail with.
///
/// `russh` requires `Debug` on this type and formats it into its own logs, so
/// nothing secret may reach it. `ProtocolError`'s `Debug` carries addresses,
/// fingerprints and fixed literals; that is the whole payload.
#[derive(Debug)]
pub enum SshHandlerError {
    /// A failure inside `russh` itself.
    Transport(russh::Error),
    /// A decision this crate made — a rejected host key, most often.
    Protocol(Box<ProtocolError>),
}

impl From<russh::Error> for SshHandlerError {
    fn from(error: russh::Error) -> Self {
        Self::Transport(error)
    }
}

impl From<ProtocolError> for SshHandlerError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(Box::new(error))
    }
}

impl From<SshHandlerError> for ProtocolError {
    fn from(error: SshHandlerError) -> Self {
        match error {
            SshHandlerError::Protocol(error) => *error,
            SshHandlerError::Transport(error) => crate::error::map_russh(&error, "run the session"),
        }
    }
}

impl std::fmt::Display for SshHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "{error}"),
            Self::Protocol(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SshHandlerError {}

/// The client handler for one SSH connection.
pub struct SshHandler {
    checker: Arc<HostKeyChecker>,
    events: EventSink,
    forwards: Arc<RemoteForwards>,
    agent_forwarding: bool,
}

impl SshHandler {
    /// A handler that verifies against `checker` and reports through `events`.
    ///
    /// `agent_forwarding` is off in every code path that does not set it
    /// deliberately; see the module documentation for why that matters.
    #[must_use]
    pub const fn new(
        checker: Arc<HostKeyChecker>,
        events: EventSink,
        forwards: Arc<RemoteForwards>,
        agent_forwarding: bool,
    ) -> Self {
        Self {
            checker,
            events,
            forwards,
            agent_forwarding,
        }
    }
}

impl Handler for SshHandler {
    type Error = SshHandlerError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Returning `Ok(false)` would make `russh` report a generic unknown-key
        // error and lose which of the three outcomes happened. The precise
        // failure is carried out through `Err` instead, so the interface can
        // tell a first use from a man-in-the-middle warning.
        self.checker.check(server_public_key).await?;
        Ok(true)
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Truncated on a character boundary so the string stays valid UTF-8:
        // the interface renders this as text, and a broken code point in a
        // banner is one more thing a hostile server should not get to cause.
        let text = if banner.len() > MAX_BANNER_BYTES {
            let mut end = MAX_BANNER_BYTES;
            while end > 0 && !banner.is_char_boundary(end) {
                end -= 1;
            }
            banner.get(..end).unwrap_or_default().to_owned()
        } else {
            banner.to_owned()
        };

        // A banner that cannot be delivered is not worth failing the
        // handshake over; the session is about to notice the closed stream.
        let _ = self
            .events
            .send(SessionEvent::Warning(SessionWarning::Banner { text }))
            .await;
        Ok(())
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &Names,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // `_shared_secret` is deliberately untouched and unnamed in any log
        // line: it is the key material every session key is derived from.
        let negotiated = [
            AsRef::<str>::as_ref(&names.kex).to_owned(),
            names.key.to_string(),
            AsRef::<str>::as_ref(&names.cipher).to_owned(),
            AsRef::<str>::as_ref(&names.client_mac).to_owned(),
            AsRef::<str>::as_ref(&names.server_mac).to_owned(),
        ];
        for algorithm in negotiated {
            if is_weak(&algorithm) {
                let _ = self
                    .events
                    .send(SessionEvent::Warning(SessionWarning::WeakAlgorithm {
                        algorithm,
                    }))
                    .await;
            }
        }
        Ok(())
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(destination) = self.forwards.destination(connected_address, connected_port) else {
            // RFC 4254 §7.2 lets a client refuse. A server opening a channel
            // for a binding this client never requested is either confused or
            // probing, and either way the answer is no.
            tracing::warn!(
                address = connected_address,
                port = connected_port,
                "refused a forwarded-tcpip channel for a binding that was not requested"
            );
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };

        reply.accept().await;
        crate::forward::spawn_forwarded_connection(channel, destination);
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.agent_forwarding {
            // The important line in this file. `russh`'s default accepts, and
            // accepting hands the remote host the ability to sign with every
            // key the local agent holds.
            tracing::warn!("refused an agent forwarding channel: forwarding is not enabled");
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        reply.accept().await;
        crate::forward::spawn_agent_forward(channel);
        Ok(())
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
    fn a_transport_failure_maps_through_the_taxonomy() {
        let error: ProtocolError = SshHandlerError::from(russh::Error::HUP).into();
        assert!(matches!(error, ProtocolError::Disconnected { .. }));
    }

    #[test]
    fn a_decision_survives_the_round_trip_unchanged() {
        // A rejected host key must reach the tab as a rejected host key, not
        // as "the handshake failed".
        let host = remoter_proto::HostPort::new("db-01.internal", 22).unwrap();
        let original = ProtocolError::HostKeyRejected {
            host: host.clone(),
            algorithm: "ssh-ed25519".to_owned(),
        };
        let round_tripped: ProtocolError = SshHandlerError::from(original).into();
        let ProtocolError::HostKeyRejected { host: reported, .. } = round_tripped else {
            panic!("the decision was rewritten");
        };
        assert_eq!(reported, host);
    }

    #[test]
    fn the_handler_error_renders_without_a_payload() {
        let error = SshHandlerError::from(russh::Error::PacketAuth);
        let rendered = format!("{error} {error:?}");
        assert!(rendered.contains("authentication code") || rendered.contains("PacketAuth"));
    }

    #[test]
    fn the_banner_cap_is_a_whole_number_of_kibibytes() {
        // Documented in the module header; asserted so a future edit that
        // makes it unbounded has to change a test that says why.
        assert_eq!(MAX_BANNER_BYTES, 8 * 1024);
    }
}
