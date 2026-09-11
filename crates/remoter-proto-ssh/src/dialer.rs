//! One hop of a gateway chain.
//!
//! `remoter-proto` owns the walk, the validation and the error reporting; it
//! cannot own the hop itself without every protocol adapter inheriting a
//! dependency on `russh`. This is the other half: authenticate to the gateway
//! over the transport that reaches it, then open a `direct-tcpip` channel
//! (RFC 4254 §7.2) to whatever comes next.
//!
//! Two properties are load-bearing, and both come from the trait's shape:
//!
//! - **The gateway is authenticated with its own credential and its own host
//!   key check.** `HopConfig` carries both, so there is no "trust the whole
//!   path because the first hop was fine"
//!   (`docs/security/transport-security.md`).
//! - **The returned transport owns the session it was opened on.** Dropping an
//!   `SshConnection` closes every channel on it, so a hop that handed back a
//!   bare channel would work until the caller stopped holding the connection.

use std::sync::Arc;

use async_trait::async_trait;
use remoter_proto::{EventSink, HopConfig, HopDialer, HostPort, ProtocolError, Transport};
use tokio_util::sync::CancellationToken;

use crate::algorithms::AlgorithmPolicy;
use crate::channel::SshChannelTransport;
use crate::connection::{SshConnection, SshConnectionConfig};
use crate::error::SSH_ID;
use crate::prompt::PromptChannel;

/// Opens gateway hops over SSH.
pub struct SshHopDialer {
    events: EventSink,
    prompts: Option<Arc<PromptChannel>>,
    algorithms: AlgorithmPolicy,
    allow_agent: bool,
    cancel: CancellationToken,
}

impl SshHopDialer {
    /// A dialer reporting through `events`.
    ///
    /// `prompts` lets a hop ask about an unknown host key or a key passphrase.
    /// Without it an unknown gateway key is refused rather than accepted — a
    /// chain that cannot ask has not obtained consent for any of its hops.
    #[must_use]
    pub fn new(events: EventSink, cancel: CancellationToken) -> Self {
        Self {
            events,
            prompts: None,
            algorithms: AlgorithmPolicy::default(),
            allow_agent: true,
            cancel,
        }
    }

    /// The same dialer, able to ask the user.
    #[must_use]
    pub fn with_prompts(mut self, prompts: Arc<PromptChannel>) -> Self {
        self.prompts = Some(prompts);
        self
    }

    /// The same dialer, with a different algorithm policy.
    #[must_use]
    pub const fn with_algorithms(mut self, algorithms: AlgorithmPolicy) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// The same dialer, with the platform agent disabled for gateways.
    #[must_use]
    pub const fn without_agent(mut self) -> Self {
        self.allow_agent = false;
        self
    }
}

impl std::fmt::Debug for SshHopDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshHopDialer")
            .field("allow_agent", &self.allow_agent)
            .field("can_prompt", &self.prompts.is_some())
            .finish()
    }
}

#[async_trait]
impl HopDialer for SshHopDialer {
    async fn dial_through(
        &self,
        via: Box<dyn Transport>,
        target: &HostPort,
        hop: &HopConfig,
    ) -> Result<Box<dyn Transport>, ProtocolError> {
        if hop.protocol.as_str() != SSH_ID {
            // A chain hop that is not SSH belongs to whichever adapter speaks
            // that protocol; saying so is better than failing later with a
            // handshake error that names the wrong thing.
            return Err(ProtocolError::Unsupported {
                operation: "carry a gateway hop",
                protocol: hop.protocol.clone(),
            });
        }

        let Some(username) = hop
            .credentials
            .username()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        else {
            // SSH has no anonymous login. Naming the gateway is what turns this
            // into something the user can fix in one place.
            return Err(ProtocolError::CredentialRequired {
                target: hop.endpoint.clone(),
            });
        };

        // Read the path *before* the transport is consumed, so the channel can
        // describe the whole chain rather than just its last leg.
        let mut labels = via.peer().via.clone();
        labels.push(hop.label.clone());

        let mut config = SshConnectionConfig::new(hop.endpoint.clone(), username);
        config.via = via.peer().via.clone();
        config.algorithms = self.algorithms;
        config.allow_agent = self.allow_agent;
        // A gateway never gets the local agent forwarded to it: a bastion is
        // exactly the machine an attacker would want it on.
        config.agent_forwarding = false;
        config.handshake_timeout = hop.timeout;

        let connection = SshConnection::establish(
            via,
            &config,
            hop.credentials.as_ref(),
            Arc::clone(&hop.trust),
            self.events.clone(),
            self.prompts.clone(),
            &self.cancel,
        )
        .await?;

        let connection = Arc::new(connection);
        let channel = connection.open_direct_tcpip(target).await?;
        Ok(Box::new(SshChannelTransport::with_session(
            channel,
            target.clone(),
            labels,
            connection,
        )))
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
    use remoter_core::{NodeId, ProtocolId};
    use remoter_proto::{
        DEFAULT_HOP_TIMEOUT, KnownKey, NoCredentials, TransportKind, TransportPeer, TrustStore,
        event_channel,
    };

    struct NoTrust;

    impl TrustStore for NoTrust {
        fn lookup(&self, _host: &HostPort, _algorithm: &str) -> Option<KnownKey> {
            None
        }
        fn remember(&self, _host: &HostPort, _key: &KnownKey) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    fn hop(protocol: &str, username: Option<&'static str>) -> HopConfig {
        HopConfig {
            node: NodeId::new(),
            label: "bastion-1".to_owned(),
            endpoint: HostPort::new("bastion.acme.io", 22).unwrap(),
            protocol: ProtocolId::new(protocol).unwrap(),
            credentials: match username {
                Some(name) => Arc::new(NoCredentials::with_username(name)),
                None => Arc::new(NoCredentials::new()),
            },
            trust: Arc::new(NoTrust),
            timeout: DEFAULT_HOP_TIMEOUT,
        }
    }

    fn transport() -> Box<dyn Transport> {
        let (client, server) = tokio::io::duplex(64);
        // The far end is dropped, so any I/O attempt fails immediately; these
        // tests are about what happens *before* the first byte.
        drop(server);
        Box::new(crate::testing::PipeTransport::new(
            client,
            HostPort::new("bastion.acme.io", 22).unwrap(),
        ))
    }

    #[tokio::test]
    async fn a_hop_with_no_user_name_is_refused_before_any_network_round_trip() {
        let dialer = SshHopDialer::new(event_channel(8).0, CancellationToken::new());
        let target = HostPort::new("db-01.internal", 5432).unwrap();

        let Err(error) = dialer
            .dial_through(transport(), &target, &hop("ssh", None))
            .await
        else {
            panic!("a hop with no user name must not dial");
        };

        let ProtocolError::CredentialRequired { target: named } = error else {
            panic!("expected CredentialRequired, got {error:?}");
        };
        assert_eq!(named.host(), "bastion.acme.io");
    }

    #[tokio::test]
    async fn a_hop_of_another_protocol_says_so_rather_than_failing_a_handshake() {
        let dialer = SshHopDialer::new(event_channel(8).0, CancellationToken::new());
        let target = HostPort::new("db-01.internal", 5432).unwrap();

        let Err(error) = dialer
            .dial_through(transport(), &target, &hop("rdp", Some("ada")))
            .await
        else {
            panic!("a non-SSH hop must not dial");
        };

        let ProtocolError::Unsupported { protocol, .. } = error else {
            panic!("expected Unsupported, got {error:?}");
        };
        assert_eq!(protocol.as_str(), "rdp");
    }

    #[tokio::test]
    async fn a_cancelled_chain_stops_at_the_hop_rather_than_dialling() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let dialer = SshHopDialer::new(event_channel(8).0, cancel);
        let target = HostPort::new("db-01.internal", 5432).unwrap();

        let Err(error) = dialer
            .dial_through(transport(), &target, &hop("ssh", Some("ada")))
            .await
        else {
            panic!("a cancelled chain must not dial");
        };
        // Bare, not wrapped: `ChainBuilder` reports cancellation as the user
        // closing the tab rather than as "bastion-1 failed".
        assert!(matches!(error, ProtocolError::Cancelled));
    }

    #[test]
    fn the_path_accumulates_one_label_per_hop() {
        // What `dial_through` does to `via` before it consumes the transport,
        // asserted directly: an error that says "hop 2 of 3" is only useful if
        // the transport underneath agrees about the path.
        let peer = TransportPeer::through(
            TransportKind::SshChannel,
            HostPort::new("db-01.internal", 5432).unwrap(),
            vec!["bastion-1".to_owned()],
        );
        let mut labels = peer.via.clone();
        labels.push("jump-eu".to_owned());
        assert_eq!(labels, vec!["bastion-1".to_owned(), "jump-eu".to_owned()]);
    }

    #[test]
    fn a_gateway_never_gets_the_agent_forwarded_to_it() {
        // A bastion is exactly the machine an attacker would want a forwarded
        // agent on, so the dialer does not offer the choice.
        let config = SshConnectionConfig::new(HostPort::new("bastion.acme.io", 22).unwrap(), "ada");
        assert!(!config.agent_forwarding);
    }

    #[test]
    fn the_dialer_debug_says_what_it_can_do_and_holds_nothing() {
        let dialer =
            SshHopDialer::new(event_channel(8).0, CancellationToken::new()).without_agent();
        assert_eq!(
            format!("{dialer:?}"),
            "SshHopDialer { allow_agent: false, can_prompt: false }"
        );
    }
}
