//! Gateway chains: building one transport by walking several machines.
//!
//! The chain is built outward from the local machine. Hop 1 is dialled
//! directly; every hop after it is opened *inside* the previous one, and each
//! is authenticated independently with its own credentials and its own host key
//! check (`docs/security/transport-security.md`). There is no "trust the whole
//! path because the first hop was fine".
//!
//! This crate cannot speak SSH — it must not, or every protocol adapter would
//! inherit a dependency on one. So the hop itself is a trait,
//! [`HopDialer`], which `remoter-proto-ssh` implements with a `direct-tcpip`
//! channel (RFC 4254 §7.2). The walk, the validation and the error reporting
//! live here, where they are the same for every protocol.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use remoter_core::{MAX_GATEWAY_HOPS, NodeId, ProtocolId};
use tokio_util::sync::CancellationToken;

use crate::credentials::CredentialProvider;
use crate::error::ProtocolError;
use crate::hostkey::TrustStore;
use crate::transport::{HostPort, TcpTransport, Transport};

/// The default per-hop connection timeout, when the connection does not set
/// one. Matches the 30 s the failure taxonomy quotes.
pub const DEFAULT_HOP_TIMEOUT: Duration = Duration::from_secs(30);

/// One hop of a chain: which machine, how to reach it, and what to
/// authenticate to it with.
///
/// The credential and the trust store travel with the hop rather than with the
/// chain because that is the invariant: hop 2 is authenticated with hop 2's
/// credential and checked against hop 2's stored key.
#[derive(Clone)]
pub struct HopConfig {
    /// The gateway node. Used for cycle detection, and to look the hop's own
    /// settings back up.
    pub node: NodeId,
    /// The gateway's name, for diagnostics — "bastion-2". Never a secret; it
    /// is what the user called the node.
    pub label: String,
    /// Where the gateway itself listens.
    pub endpoint: HostPort,
    /// The protocol that carries the hop. `ssh` today.
    pub protocol: ProtocolId,
    /// The credential for this hop alone.
    pub credentials: Arc<dyn CredentialProvider>,
    /// The trust store to check this hop's host key against.
    pub trust: Arc<dyn TrustStore>,
    /// How long to wait for this hop.
    pub timeout: Duration,
}

impl fmt::Debug for HopConfig {
    /// Hand-written rather than derived, and it stays hand-written.
    ///
    /// A derived `Debug` on a struct holding a credential provider is one
    /// `#[derive]` away from printing a password into a log line, which is the
    /// single easiest way to leak a secret in this crate. The provider is
    /// summarised by kind and never by content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HopConfig")
            .field("node", &self.node)
            .field("label", &self.label)
            .field("endpoint", &self.endpoint)
            .field("protocol", &self.protocol)
            .field("credentials", &self.credentials.kind())
            .field("trust", &"<trust store>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Opens the next hop of a chain.
///
/// Implemented by `remoter-proto-ssh`: authenticate to `hop` over `via`, then
/// open a `direct-tcpip` channel to `target` and hand it back as a transport.
/// `via` is a transport rather than an address precisely so that the second and
/// subsequent hops run inside the previous one.
#[async_trait]
pub trait HopDialer: Send + Sync {
    /// Authenticates to `hop` over `via` and opens a stream to `target`.
    ///
    /// The implementation owns `via` — dropping it must close the underlying
    /// stream, and the returned transport must keep whatever session it needs
    /// alive for its own lifetime.
    ///
    /// # Errors
    ///
    /// Any [`ProtocolError`]; the chain builder adds the hop's name and
    /// position, so an implementation should report the bare cause.
    async fn dial_through(
        &self,
        via: Box<dyn Transport>,
        target: &HostPort,
        hop: &HopConfig,
    ) -> Result<Box<dyn Transport>, ProtocolError>;
}

/// Dials the first leg — the one that leaves this machine.
///
/// Separated from [`HopDialer`] because the first leg is not a hop: it is a
/// socket. Making it a trait is what lets a SOCKS5 or HTTP CONNECT proxy sit in
/// front of an otherwise ordinary chain without the chain knowing, and lets a
/// test build a chain with no network at all.
#[async_trait]
pub trait EntryDialer: Send + Sync {
    /// Connects to `target`, giving up after `timeout`.
    ///
    /// # Errors
    ///
    /// Any [`ProtocolError`] from the transport stage.
    async fn dial(
        &self,
        target: &HostPort,
        timeout: Duration,
    ) -> Result<Box<dyn Transport>, ProtocolError>;
}

/// The ordinary entry: a direct TCP connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpDialer;

#[async_trait]
impl EntryDialer for TcpDialer {
    async fn dial(
        &self,
        target: &HostPort,
        timeout: Duration,
    ) -> Result<Box<dyn Transport>, ProtocolError> {
        Ok(Box::new(TcpTransport::connect(target, timeout).await?))
    }
}

/// A validated chain: the hops to walk, and where they end.
///
/// Validation happens at construction, before any I/O. That ordering is the
/// point — `docs/architecture/session-pipeline.md` §2 puts chain validation in
/// Authorise, *before* anything touches the network, so a chain that loops is
/// refused without first authenticating to a bastion.
#[derive(Debug, Clone)]
pub struct GatewayChainPlan {
    hops: Vec<HopConfig>,
    target: HostPort,
}

impl GatewayChainPlan {
    /// Validates `hops` and pairs them with `target`.
    ///
    /// `target_node` is the connection being opened, when it is known. It is
    /// checked for membership in its own chain: a connection routed through
    /// itself is the cycle users actually build, usually by setting a gateway
    /// on a folder that contains the gateway.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::GatewayTooLong`] beyond [`MAX_GATEWAY_HOPS`],
    /// [`ProtocolError::GatewayCycle`] if a node repeats, and
    /// [`ProtocolError::GatewayHopDeleted`] never — hop tombstones are resolved
    /// by the caller, which is the layer that can name the missing node.
    pub fn new(
        target: HostPort,
        target_node: Option<NodeId>,
        hops: Vec<HopConfig>,
    ) -> Result<Self, ProtocolError> {
        let total = hops.len();
        if total > MAX_GATEWAY_HOPS {
            return Err(ProtocolError::GatewayTooLong {
                hops: total,
                max: MAX_GATEWAY_HOPS,
            });
        }

        // Quadratic, deliberately: `MAX_GATEWAY_HOPS` is 8, and a `Vec` scan
        // over eight elements beats a hash set that has to be allocated and
        // then thrown away on every connect.
        for (index, hop) in hops.iter().enumerate() {
            let repeats_earlier = hops[..index].iter().any(|earlier| earlier.node == hop.node);
            let is_the_target = target_node == Some(hop.node);
            if repeats_earlier || is_the_target {
                return Err(ProtocolError::GatewayCycle {
                    label: hop.label.clone(),
                    position: index + 1,
                    total,
                });
            }
        }

        Ok(Self { hops, target })
    }

    /// A chain with no hops.
    #[must_use]
    pub const fn direct(target: HostPort) -> Self {
        Self {
            hops: Vec::new(),
            target,
        }
    }

    /// The hops, in the order they are traversed.
    #[must_use]
    pub fn hops(&self) -> &[HopConfig] {
        &self.hops
    }

    /// Where the chain ends — the machine the protocol will talk to.
    #[must_use]
    pub const fn target(&self) -> &HostPort {
        &self.target
    }

    /// Whether the target is reached without a gateway.
    #[must_use]
    pub fn is_direct(&self) -> bool {
        self.hops.is_empty()
    }

    /// The gateway names, outermost first, for a transport's peer description.
    #[must_use]
    pub fn labels(&self) -> Vec<String> {
        self.hops.iter().map(|hop| hop.label.clone()).collect()
    }
}

/// Walks a [`GatewayChainPlan`] and produces the transport at the end of it.
pub struct ChainBuilder<'a> {
    entry: &'a dyn EntryDialer,
    dialer: &'a dyn HopDialer,
}

impl<'a> ChainBuilder<'a> {
    /// A builder that dials the first leg with `entry` and every hop after it
    /// with `dialer`.
    #[must_use]
    pub const fn new(entry: &'a dyn EntryDialer, dialer: &'a dyn HopDialer) -> Self {
        Self { entry, dialer }
    }

    /// Builds the chain.
    ///
    /// On failure the error names which hop failed and where it sat in the
    /// chain — "hop 2 of 3" — because the failure taxonomy requires it and
    /// because "connection failed" tells an administrator with three bastions
    /// nothing they can act on.
    ///
    /// Cancellation is checked before each hop and races each dial, so closing
    /// the tab while a bastion is timing out does not leave the walk running.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Cancelled`] if the token fires, or
    /// [`ProtocolError::HopFailed`] wrapping the cause. A direct chain returns
    /// the transport error unwrapped, since there is no hop to name.
    pub async fn build(
        &self,
        plan: &GatewayChainPlan,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn Transport>, ProtocolError> {
        if cancel.is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }

        let total = plan.hops.len();
        let Some(first) = plan.hops.first() else {
            return with_cancel(cancel, self.entry.dial(&plan.target, DEFAULT_HOP_TIMEOUT)).await;
        };

        // The first leg leaves this machine, so it is a socket rather than a
        // hop — but a failure to reach bastion-1 is still "hop 1 of n failed".
        let mut transport = with_cancel(cancel, self.entry.dial(&first.endpoint, first.timeout))
            .await
            .map_err(|error| label_hop(error, &first.label, 1, total))?;

        for (index, hop) in plan.hops.iter().enumerate() {
            if cancel.is_cancelled() {
                // `transport` is dropped here, which closes every stream opened
                // so far. That is the whole cleanup: a chain owns nothing else.
                return Err(ProtocolError::Cancelled);
            }

            // Hop i authenticates over the stream reaching it, then opens a
            // channel to whatever comes next — the following gateway, or the
            // target itself for the last hop.
            let next = plan
                .hops
                .get(index + 1)
                .map_or(&plan.target, |following| &following.endpoint);

            transport = with_cancel(cancel, self.dialer.dial_through(transport, next, hop))
                .await
                .map_err(|error| label_hop(error, &hop.label, index + 1, total))?;
        }

        Ok(transport)
    }
}

impl fmt::Debug for ChainBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChainBuilder")
    }
}

/// Names the hop a failure happened at — except for cancellation, which is not
/// the hop's fault and would read as "bastion-2 failed" when the user simply
/// closed the tab.
///
/// An identity failure is wrapped like any other, deliberately: a changed host
/// key on hop 2 is a changed host key *on hop 2*, and the user has to be told
/// which machine was attacked. What must not happen is the wrapper changing the
/// verdict, so [`ProtocolError::is_retryable`] and its neighbours classify by
/// the wrapped cause rather than by the wrapper
/// (`docs/security/transport-security.md`: every hop is authenticated
/// independently, and there is no "trust the whole path because the first hop
/// was fine").
fn label_hop(error: ProtocolError, label: &str, position: usize, total: usize) -> ProtocolError {
    if matches!(error, ProtocolError::Cancelled) {
        error
    } else {
        error.at_hop(label, position, total)
    }
}

/// Races a dial against cancellation. The dial is dropped on cancellation,
/// which cancels the in-flight connect rather than leaving it to complete into
/// a socket nobody owns.
async fn with_cancel<F>(
    cancel: &CancellationToken,
    future: F,
) -> Result<Box<dyn Transport>, ProtocolError>
where
    F: Future<Output = Result<Box<dyn Transport>, ProtocolError>>,
{
    tokio::select! {
        () = cancel.cancelled() => Err(ProtocolError::Cancelled),
        result = future => result,
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
    use crate::credentials::NoCredentials;
    use crate::error::{FailureReport, NextAction, Stage};
    use crate::hostkey::{Fingerprint, KnownKey, TrustStore};
    use crate::transport::{TransportKind, TransportPeer};
    use std::io;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// A transport that carries nothing. The chain builder never reads or
    /// writes; it only threads ownership, which is exactly what this checks.
    struct NullTransport {
        peer: TransportPeer,
        /// Bumped when the transport is dropped, so a test can assert that a
        /// cancelled chain released what it had already built.
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for NullTransport {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Transport for NullTransport {
        fn peer(&self) -> &TransportPeer {
            &self.peer
        }
    }

    impl AsyncRead for NullTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for NullTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct NullTrust;

    impl TrustStore for NullTrust {
        fn lookup(&self, _host: &HostPort, _algorithm: &str) -> Option<KnownKey> {
            None
        }
        fn remember(&self, _host: &HostPort, _key: &KnownKey) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    struct RecordingEntry {
        dialled: Mutex<Vec<String>>,
        dropped: Arc<AtomicUsize>,
        fail: bool,
    }

    #[async_trait]
    impl EntryDialer for RecordingEntry {
        async fn dial(
            &self,
            target: &HostPort,
            _timeout: Duration,
        ) -> Result<Box<dyn Transport>, ProtocolError> {
            self.dialled.lock().unwrap().push(target.to_string());
            if self.fail {
                return Err(ProtocolError::ConnectionRefused {
                    target: target.clone(),
                });
            }
            Ok(Box::new(NullTransport {
                peer: TransportPeer::direct(TransportKind::Tcp, target.clone()),
                dropped: Arc::clone(&self.dropped),
            }))
        }
    }

    struct RecordingDialer {
        /// `(hop label, target)` for each hop opened, in order.
        opened: Mutex<Vec<(String, String)>>,
        dropped: Arc<AtomicUsize>,
        /// 1-based position of the hop that should fail, if any.
        fail_at: Option<usize>,
    }

    #[async_trait]
    impl HopDialer for RecordingDialer {
        async fn dial_through(
            &self,
            via: Box<dyn Transport>,
            target: &HostPort,
            hop: &HopConfig,
        ) -> Result<Box<dyn Transport>, ProtocolError> {
            let mut opened = self.opened.lock().unwrap();
            opened.push((hop.label.clone(), target.to_string()));
            let position = opened.len();
            drop(opened);

            if self.fail_at == Some(position) {
                // Dropping `via` is what closes the streams already built.
                drop(via);
                return Err(ProtocolError::ConnectTimeout {
                    target: target.clone(),
                    timeout_ms: 30_000,
                });
            }

            let via_peer = via.peer().clone();
            let mut labels = via_peer.via;
            labels.push(hop.label.clone());
            drop(via);
            Ok(Box::new(NullTransport {
                peer: TransportPeer::through(TransportKind::SshChannel, target.clone(), labels),
                dropped: Arc::clone(&self.dropped),
            }))
        }
    }

    fn hop(label: &str, host: &str) -> HopConfig {
        HopConfig {
            node: NodeId::new(),
            label: label.to_owned(),
            endpoint: HostPort::new(host, 22).unwrap(),
            protocol: ProtocolId::new("ssh").unwrap(),
            credentials: Arc::new(NoCredentials::new()),
            trust: Arc::new(NullTrust),
            timeout: DEFAULT_HOP_TIMEOUT,
        }
    }

    fn hop_on(node: NodeId, label: &str, host: &str) -> HopConfig {
        HopConfig {
            node,
            ..hop(label, host)
        }
    }

    fn target() -> HostPort {
        HostPort::new("db-01.internal", 5432).unwrap()
    }

    /// `Result::expect_err` needs the success type to be `Debug`, and
    /// `Box<dyn Transport>` deliberately is not — a transport has no business
    /// being formatted.
    fn expect_error(result: Result<Box<dyn Transport>, ProtocolError>, why: &str) -> ProtocolError {
        match result {
            Ok(_) => panic!("{why}"),
            Err(error) => error,
        }
    }

    fn builders(
        fail_at: Option<usize>,
        entry_fails: bool,
    ) -> (RecordingEntry, RecordingDialer, Arc<AtomicUsize>) {
        let dropped = Arc::new(AtomicUsize::new(0));
        (
            RecordingEntry {
                dialled: Mutex::new(Vec::new()),
                dropped: Arc::clone(&dropped),
                fail: entry_fails,
            },
            RecordingDialer {
                opened: Mutex::new(Vec::new()),
                dropped: Arc::clone(&dropped),
                fail_at,
            },
            dropped,
        )
    }

    // ── Validation ──────────────────────────────────────────────────────────

    #[test]
    fn a_chain_that_repeats_a_node_is_a_cycle() {
        let repeated = NodeId::new();
        let hops = vec![
            hop_on(repeated, "bastion-1", "b1.example.com"),
            hop("jump-eu", "j.example.com"),
            hop_on(repeated, "bastion-1", "b1.example.com"),
        ];
        let Err(ProtocolError::GatewayCycle {
            label,
            position,
            total,
        }) = GatewayChainPlan::new(target(), None, hops)
        else {
            panic!("a repeated node must be refused as a cycle");
        };
        assert_eq!(label, "bastion-1");
        assert_eq!((position, total), (3, 3));
    }

    #[test]
    fn a_connection_routed_through_itself_is_a_cycle() {
        // The one users actually build: a gateway set on a folder that
        // contains the gateway.
        let self_node = NodeId::new();
        let hops = vec![hop_on(self_node, "bastion-1", "b1.example.com")];
        assert!(matches!(
            GatewayChainPlan::new(target(), Some(self_node), hops),
            Err(ProtocolError::GatewayCycle { position: 1, .. })
        ));
    }

    #[test]
    fn a_chain_longer_than_the_limit_is_refused() {
        let hops: Vec<HopConfig> = (0..=MAX_GATEWAY_HOPS)
            .map(|i| hop(&format!("hop-{i}"), "h.example.com"))
            .collect();
        let Err(ProtocolError::GatewayTooLong { hops, max }) =
            GatewayChainPlan::new(target(), None, hops)
        else {
            panic!("a chain of {} hops must be refused", MAX_GATEWAY_HOPS + 1);
        };
        assert_eq!(hops, MAX_GATEWAY_HOPS + 1);
        assert_eq!(max, MAX_GATEWAY_HOPS);
    }

    #[test]
    fn a_chain_exactly_at_the_limit_is_accepted() {
        let hops: Vec<HopConfig> = (0..MAX_GATEWAY_HOPS)
            .map(|i| hop(&format!("hop-{i}"), "h.example.com"))
            .collect();
        let plan = GatewayChainPlan::new(target(), None, hops).unwrap();
        assert_eq!(plan.hops().len(), MAX_GATEWAY_HOPS);
        assert!(!plan.is_direct());
    }

    #[test]
    fn validation_happens_before_any_io() {
        // The plan is a pure value; building it dials nothing. This is what
        // stops a looping chain from authenticating to bastion-1 first.
        let repeated = NodeId::new();
        let hops = vec![
            hop_on(repeated, "a", "a.example.com"),
            hop_on(repeated, "a", "a.example.com"),
        ];
        assert!(GatewayChainPlan::new(target(), None, hops).is_err());
    }

    #[test]
    fn an_empty_chain_is_direct() {
        let plan = GatewayChainPlan::new(target(), None, Vec::new()).unwrap();
        assert!(plan.is_direct());
        assert!(plan.labels().is_empty());
        assert_eq!(plan.target(), &target());
    }

    #[test]
    fn a_hop_config_never_debug_prints_its_credential() {
        let rendered = format!("{:?}", hop("bastion-1", "b1.example.com"));
        assert!(rendered.contains("bastion-1"));
        assert!(
            rendered.contains("credentials: None"),
            "the credential kind is shown and nothing else: {rendered}"
        );
        assert!(rendered.contains("<trust store>"));
    }

    // ── Walking ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_direct_chain_dials_the_target_once() {
        let (entry, dialer, _) = builders(None, false);
        let plan = GatewayChainPlan::direct(target());
        let transport = ChainBuilder::new(&entry, &dialer)
            .build(&plan, &CancellationToken::new())
            .await
            .unwrap();

        assert_eq!(transport.peer().target, target());
        assert!(transport.peer().via.is_empty());
        assert_eq!(*entry.dialled.lock().unwrap(), vec!["db-01.internal:5432"]);
        assert!(dialer.opened.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn each_hop_opens_a_stream_to_the_next_machine() {
        let (entry, dialer, _) = builders(None, false);
        let hops = vec![
            hop("bastion-1", "b1.example.com"),
            hop("jump-eu", "j.example.com"),
        ];
        let plan = GatewayChainPlan::new(target(), None, hops).unwrap();

        let transport = ChainBuilder::new(&entry, &dialer)
            .build(&plan, &CancellationToken::new())
            .await
            .unwrap();

        // The socket goes to hop 1; hop 1 opens a channel to hop 2; hop 2
        // opens a channel to the target.
        assert_eq!(*entry.dialled.lock().unwrap(), vec!["b1.example.com:22"]);
        assert_eq!(
            *dialer.opened.lock().unwrap(),
            vec![
                ("bastion-1".to_owned(), "j.example.com:22".to_owned()),
                ("jump-eu".to_owned(), "db-01.internal:5432".to_owned()),
            ]
        );
        assert_eq!(transport.peer().target, target());
        assert_eq!(transport.peer().via, vec!["bastion-1", "jump-eu"]);
    }

    #[tokio::test]
    async fn a_failing_hop_is_named_with_its_position() {
        let (entry, dialer, _) = builders(Some(2), false);
        let hops = vec![
            hop("bastion-1", "b1.example.com"),
            hop("bastion-2", "b2.example.com"),
            hop("jump-eu", "j.example.com"),
        ];
        let plan = GatewayChainPlan::new(target(), None, hops).unwrap();

        let error = expect_error(
            ChainBuilder::new(&entry, &dialer)
                .build(&plan, &CancellationToken::new())
                .await,
            "hop 2 was told to fail",
        );

        let ProtocolError::HopFailed {
            label,
            position,
            total,
            source,
        } = error
        else {
            panic!("a hop failure must be reported as one");
        };
        assert_eq!(label, "bastion-2");
        assert_eq!((position, total), (2, 3));
        assert!(matches!(*source, ProtocolError::ConnectTimeout { .. }));
    }

    /// An active attacker (`docs/security/threat-model.md`, T3) forges the host
    /// key of one machine in the chain. Wherever that machine sits, the walk
    /// must produce a failure the reconnect loop refuses to retry, and one that
    /// names the machine.
    #[tokio::test]
    async fn a_changed_host_key_on_any_hop_is_never_retryable() {
        /// A dialler whose hop `attacked_at` presents a forged key.
        struct ForgedKeyAt {
            attacked_at: usize,
            opened: Mutex<usize>,
        }

        #[async_trait]
        impl HopDialer for ForgedKeyAt {
            async fn dial_through(
                &self,
                via: Box<dyn Transport>,
                target: &HostPort,
                hop: &HopConfig,
            ) -> Result<Box<dyn Transport>, ProtocolError> {
                let position = {
                    let mut opened = self.opened.lock().unwrap();
                    *opened += 1;
                    *opened
                };
                if position == self.attacked_at {
                    drop(via);
                    return Err(ProtocolError::HostKeyChanged {
                        host: hop.endpoint.clone(),
                        algorithm: "ssh-ed25519".to_owned(),
                        expected: Fingerprint::sha256(b"the key we trusted"),
                        offered: Fingerprint::sha256(b"the key the attacker offered"),
                    });
                }
                let via_peer = via.peer().clone();
                let mut labels = via_peer.via;
                labels.push(hop.label.clone());
                drop(via);
                Ok(Box::new(NullTransport {
                    peer: TransportPeer::through(TransportKind::SshChannel, target.clone(), labels),
                    dropped: Arc::new(AtomicUsize::new(0)),
                }))
            }
        }

        // The user connects to db-01 through bastion-1 and bastion-2. The key
        // is forged at hop 1, then at hop 2, then on the leg that reaches the
        // target itself — three positions, one verdict.
        for attacked_at in 1..=3 {
            let (entry, _, _) = builders(None, false);
            let dialer = ForgedKeyAt {
                attacked_at,
                opened: Mutex::new(0),
            };
            let hops = vec![
                hop("bastion-1", "b1.example.com"),
                hop("bastion-2", "b2.example.com"),
                hop("jump-eu", "j.example.com"),
            ];
            let plan = GatewayChainPlan::new(target(), None, hops).unwrap();

            let error = expect_error(
                ChainBuilder::new(&entry, &dialer)
                    .build(&plan, &CancellationToken::new())
                    .await,
                "a forged host key must not produce a transport",
            );

            assert!(
                !error.is_retryable(),
                "auto-reconnect would silently retry a man-in-the-middle at hop {attacked_at}: {error}"
            );
            assert!(error.needs_user_decision(), "hop {attacked_at}: {error}");
            assert_eq!(error.stage(), Stage::Handshake, "hop {attacked_at}");
            assert!(
                !FailureReport::from(&error).retryable,
                "hop {attacked_at}: {error}"
            );
            assert!(
                error
                    .next_actions()
                    .contains(&NextAction::VerifyFingerprintOutOfBand),
                "hop {attacked_at}: {error}"
            );

            // The position is still named, so the user learns which machine was
            // attacked rather than merely that something failed.
            let rendered = error.to_string();
            assert!(
                rendered.contains(&format!("hop {attacked_at} of 3")),
                "{rendered}"
            );
            assert!(
                rendered.contains(&Fingerprint::sha256(b"the key we trusted").to_string()),
                "the stored fingerprint never reached the user: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn a_failing_first_leg_is_reported_as_hop_one() {
        let (entry, dialer, _) = builders(None, true);
        let hops = vec![hop("bastion-1", "b1.example.com")];
        let plan = GatewayChainPlan::new(target(), None, hops).unwrap();

        let error = expect_error(
            ChainBuilder::new(&entry, &dialer)
                .build(&plan, &CancellationToken::new())
                .await,
            "the entry dialler was told to fail",
        );
        assert!(error.to_string().contains("hop 1 of 1"), "got: {error}");
    }

    #[tokio::test]
    async fn a_direct_chain_reports_the_transport_error_unwrapped() {
        // There is no hop to name, so wrapping would invent one.
        let (entry, dialer, _) = builders(None, true);
        let plan = GatewayChainPlan::direct(target());
        let error = expect_error(
            ChainBuilder::new(&entry, &dialer)
                .build(&plan, &CancellationToken::new())
                .await,
            "the entry dialler was told to fail",
        );
        assert!(matches!(error, ProtocolError::ConnectionRefused { .. }));
    }

    #[tokio::test]
    async fn a_failed_hop_releases_the_streams_already_opened() {
        let (entry, dialer, dropped) = builders(Some(2), false);
        let hops = vec![
            hop("bastion-1", "b1.example.com"),
            hop("bastion-2", "b2.example.com"),
        ];
        let plan = GatewayChainPlan::new(target(), None, hops).unwrap();

        let _ = ChainBuilder::new(&entry, &dialer)
            .build(&plan, &CancellationToken::new())
            .await;

        // The socket to bastion-1 and the channel through it are both gone.
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancelling_mid_walk_reports_cancellation_not_a_failed_hop() {
        // "bastion-2 failed" would be a lie when the user closed the tab.
        struct SlowEntry;

        #[async_trait]
        impl EntryDialer for SlowEntry {
            async fn dial(
                &self,
                _target: &HostPort,
                _timeout: Duration,
            ) -> Result<Box<dyn Transport>, ProtocolError> {
                std::future::pending().await
            }
        }

        let (_, dialer, _) = builders(None, false);
        let plan = GatewayChainPlan::new(target(), None, vec![hop("bastion-1", "b1.example.com")])
            .unwrap();

        let cancel = CancellationToken::new();
        let waker = cancel.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            waker.cancel();
        });

        let entry = SlowEntry;
        let error = expect_error(
            ChainBuilder::new(&entry, &dialer)
                .build(&plan, &cancel)
                .await,
            "a cancelled build must not connect",
        );
        assert!(matches!(error, ProtocolError::Cancelled), "got {error:?}");
    }

    #[tokio::test]
    async fn a_cancelled_chain_stops_and_releases_what_it_built() {
        let (entry, dialer, dropped) = builders(None, false);
        let hops = vec![
            hop("bastion-1", "b1.example.com"),
            hop("bastion-2", "b2.example.com"),
        ];
        let plan = GatewayChainPlan::new(target(), None, hops).unwrap();

        let cancel = CancellationToken::new();
        cancel.cancel();

        let error = expect_error(
            ChainBuilder::new(&entry, &dialer)
                .build(&plan, &cancel)
                .await,
            "a cancelled build must not connect",
        );
        assert!(matches!(error, ProtocolError::Cancelled));
        assert!(entry.dialled.lock().unwrap().is_empty());
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
    }
}
