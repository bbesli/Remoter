//! One authenticated SSH connection, and the channels opened on it.
//!
//! The connection is built **over an injected transport** (ADR-0003): `russh`
//! will happily open its own socket, and this crate never lets it. The stream
//! handed to [`SshConnection::establish`] may be a plain TCP socket or the far
//! end of a three-hop chain, and nothing below this line can tell — which is
//! what makes a jump host chain the same code path as a direct connection.
//!
//! One connection serves every channel: the shell, SFTP, and every port
//! forward. That is why an SFTP tab opened on a host that already has a shell
//! does not authenticate again (`docs/features/protocols.md`).

use std::borrow::Cow;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use remoter_proto::{
    CredentialProvider, EventSink, HostPort, ProtocolError, Transport, TransportKind,
    TransportPeer, TrustStore,
};
use russh::Channel;
use russh::client::{Config, Handle, Msg};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::algorithms::AlgorithmPolicy;
use crate::auth::{AuthContext, AuthReport, authenticate};
use crate::error::map_russh;
use crate::forward::RemoteForwards;
use crate::handler::SshHandler;
use crate::hostkey::HostKeyChecker;
use crate::prompt::PromptChannel;

/// How long the handshake and authentication may take before the attempt is
/// abandoned. Matches the 30 s the failure taxonomy quotes.
///
/// It bounds the **network**, not the user. A host key prompt, a passphrase
/// and a 2FA code all suspend it while they are on screen; see
/// [`with_deadline`].
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the deadline loop looks at the clock.
///
/// The budget is spent a tick at a time rather than by one `tokio::time::timeout`
/// so that the ticks spent waiting for a person can be given back. Small
/// enough that a 30 s budget is honoured to within a tick, large enough that a
/// connection attempt is not hundreds of wake-ups.
const DEADLINE_TICK: Duration = Duration::from_millis(100);

/// How the connection should be negotiated.
#[derive(Debug, Clone)]
pub struct SshConnectionConfig {
    /// The machine at the far end of the transport.
    pub target: HostPort,
    /// The account to log in as.
    pub username: String,
    /// The gateways already traversed, outermost first. Diagnostics only.
    pub via: Vec<String>,
    /// Which algorithms to offer.
    pub algorithms: AlgorithmPolicy,
    /// How often to send a keepalive when the server is quiet.
    pub keepalive: Option<Duration>,
    /// How long the handshake and authentication may take.
    pub handshake_timeout: Duration,
    /// Whether the platform agent may be used.
    pub allow_agent: bool,
    /// Which agent identity to use, by comment substring. `None` falls back to
    /// whatever the credential names.
    pub agent_filter: Option<String>,
    /// Whether the remote may use this machine's agent.
    ///
    /// **Off by default and it stays off unless asked for.** A compromised
    /// remote host with a forwarded agent can impersonate the user everywhere
    /// that key opens, for as long as the session lasts.
    pub agent_forwarding: bool,
}

impl SshConnectionConfig {
    /// The defaults for `target` as `username`.
    #[must_use]
    pub fn new(target: HostPort, username: impl Into<String>) -> Self {
        Self {
            target,
            username: username.into(),
            via: Vec::new(),
            algorithms: AlgorithmPolicy::default(),
            keepalive: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            allow_agent: true,
            agent_filter: None,
            agent_forwarding: false,
        }
    }
}

/// An authenticated SSH connection.
pub struct SshConnection {
    handle: Handle<SshHandler>,
    target: HostPort,
    username: String,
    via: Vec<String>,
    auth: AuthReport,
    forwards: Arc<RemoteForwards>,
}

// A connection is shared between the session task, the SFTP browser and every
// forward, so it must be usable from an `Arc`. Asserted here rather than
// discovered at the first `tokio::spawn` that captures one.
const _: fn() = || {
    const fn assert_shareable<T: Send + Sync + 'static>() {}
    assert_shareable::<SshConnection>();
};

impl SshConnection {
    /// Runs the handshake and the authentication ladder over `transport`.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Cancelled`] if the tab was closed while connecting;
    /// [`ProtocolError::ConnectTimeout`] if the far end never finished the
    /// handshake; any Handshake- or Authenticate-stage error otherwise —
    /// including a host key decision, which surfaces unchanged from
    /// [`crate::hostkey`].
    pub async fn establish(
        transport: Box<dyn Transport>,
        config: &SshConnectionConfig,
        credentials: &dyn CredentialProvider,
        trust: Arc<dyn TrustStore>,
        events: EventSink,
        prompts: Option<Arc<PromptChannel>>,
        cancel: &CancellationToken,
    ) -> Result<Self, ProtocolError> {
        if config.username.trim().is_empty() {
            // SSH has no notion of an anonymous login; a blank user name would
            // simply be rejected after the network round trip.
            return Err(ProtocolError::CredentialRequired {
                target: config.target.clone(),
            });
        }

        let forwards = Arc::new(RemoteForwards::new());
        let checker = Arc::new(HostKeyChecker::new(
            config.target.clone(),
            trust,
            events.clone(),
            prompts.clone(),
        ));
        let handler = SshHandler::new(
            checker,
            events.clone(),
            Arc::clone(&forwards),
            config.agent_forwarding,
        );

        // `russh::client::connect_stream` spawns `Session::run` internally and
        // only then awaits the kex-done signal; the `JoinHandle` for that task
        // is inside the `Handle` it has not returned yet. Abandoning the
        // future — a deadline, a closed tab — therefore *detaches* the task
        // with the socket, the handler and any credential already handed to
        // `russh` still inside it, and during the initial key exchange nothing
        // wakes it: the branch that notices the dropped sender is disabled
        // while `kex.active()`. So the stream handed to `russh` is wired to a
        // shutdown token instead. Firing it makes the spawned task's next read
        // fail, which unwinds it and drops everything it holds — which is what
        // ADR-0011 means by "closing a session releases everything
        // deterministically".
        //
        // A token of its own rather than a child of the session's: it exists to
        // end an *abandoned* attempt, and a connection that succeeds is torn
        // down the ordinary way, by `SSH_MSG_DISCONNECT` (RFC 4253 §11.1) and
        // then dropping the `Handle`. The guard covers every failure path out
        // of this function — a deadline, a cancellation, a refused host key, a
        // rejected credential — and is disarmed once the connection belongs to
        // the caller.
        let shutdown = CancellationToken::new();
        let stream = GuardedStream::new(transport, shutdown.clone());
        let abandoned = shutdown.drop_guard();

        let mut handle = with_deadline(
            cancel,
            config.handshake_timeout,
            &config.target,
            prompts.as_deref(),
            russh::client::connect_stream(Arc::new(russh_config(config)), stream, handler),
        )
        .await?
        .map_err(ProtocolError::from)?;

        let auth = with_deadline(
            cancel,
            config.handshake_timeout,
            &config.target,
            prompts.as_deref(),
            authenticate(
                &mut handle,
                &AuthContext {
                    username: &config.username,
                    credentials,
                    allow_agent: config.allow_agent,
                    agent_filter: config.agent_filter.as_deref(),
                    events: &events,
                    prompts: prompts.as_deref(),
                    target: &config.target,
                },
            ),
        )
        .await??;

        // Past here the connection belongs to the caller and its lifetime is
        // the session's; dropping the `Handle` closes it the ordinary way.
        drop(abandoned.disarm());

        tracing::info!(
            target = %config.target,
            method = auth.method.as_str(),
            "authenticated"
        );

        Ok(Self {
            handle,
            target: config.target.clone(),
            username: config.username.clone(),
            via: config.via.clone(),
            auth,
            forwards,
        })
    }

    /// The machine at the far end.
    #[must_use]
    pub const fn target(&self) -> &HostPort {
        &self.target
    }

    /// The account this connection is logged in as.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The gateways traversed to reach it, outermost first.
    #[must_use]
    pub fn via(&self) -> &[String] {
        &self.via
    }

    /// Which method authenticated, and what the server offered.
    #[must_use]
    pub const fn auth(&self) -> &AuthReport {
        &self.auth
    }

    /// The remote forwards registered on this connection.
    #[must_use]
    pub fn remote_forwards(&self) -> &Arc<RemoteForwards> {
        &self.forwards
    }

    /// Whether the session has ended.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Opens a `session` channel — a shell, an `exec`, or the SFTP subsystem.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Disconnected`] if the session is gone, or whatever the
    /// server said when it refused.
    pub async fn open_session_channel(&self) -> Result<Channel<Msg>, ProtocolError> {
        self.handle
            .channel_open_session()
            .await
            .map_err(|error| map_russh(&error, "open a session channel"))
    }

    /// Opens a `direct-tcpip` channel to `target` (RFC 4254 §7.2).
    ///
    /// This is the one primitive behind jump host chains, local forwards and
    /// dynamic forwards alike.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ConnectionRefused`] and friends, named against
    /// `target` rather than against this connection: what failed is the far
    /// side's connect, and that is what the user acts on.
    pub async fn open_direct_tcpip(
        &self,
        target: &HostPort,
    ) -> Result<Channel<Msg>, ProtocolError> {
        self.handle
            .channel_open_direct_tcpip(
                wire_host(target),
                u32::from(target.port()),
                // RFC 4254 §7.2 wants the *originating* address. There is no
                // meaningful one for a channel this client opened on its own
                // behalf, and OpenSSH sends loopback here too.
                "127.0.0.1",
                0,
            )
            .await
            .map_err(|error| crate::error::map_channel_open(&error, target))
    }

    /// Asks the server to listen on `address:port` (RFC 4254 §7.1).
    ///
    /// Returns the port the server actually bound, which differs from `port`
    /// only when `port` was zero and the server chose one.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Disconnected`] carrying a catalogue key: a refusal is
    /// almost always the port being in use over there, or `GatewayPorts` being
    /// off for a non-loopback bind, and the server does not say which.
    pub async fn request_remote_forward(
        &self,
        address: &str,
        port: u32,
    ) -> Result<u32, ProtocolError> {
        self.handle
            .tcpip_forward(address, port)
            .await
            .map_err(|error| match error {
                russh::Error::RequestDenied => ProtocolError::Disconnected {
                    reason: "ssh.remote_forward_refused".to_owned(),
                },
                other => map_russh(&other, "request a remote forward"),
            })
    }

    /// Withdraws a remote forward.
    ///
    /// # Errors
    ///
    /// As [`request_remote_forward`](Self::request_remote_forward).
    pub async fn cancel_remote_forward(
        &self,
        address: &str,
        port: u32,
    ) -> Result<(), ProtocolError> {
        self.forwards.remove(address, port);
        self.handle
            .cancel_tcpip_forward(address, port)
            .await
            .map_err(|error| map_russh(&error, "cancel a remote forward"))
    }

    /// Sends `SSH_MSG_DISCONNECT` (RFC 4253 §11.1) and lets the session end.
    ///
    /// # Errors
    ///
    /// A transport failure while saying goodbye. The connection is finished
    /// either way; the error is diagnostic.
    pub async fn disconnect(&self) -> Result<(), ProtocolError> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .map_err(|error| map_russh(&error, "disconnect"))
    }

    /// A description of a channel opened on this connection, for diagnostics.
    #[must_use]
    pub fn channel_peer(&self, target: HostPort) -> TransportPeer {
        let mut via = self.via.clone();
        via.push(self.target.to_string());
        TransportPeer::through(TransportKind::SshChannel, target, via)
    }
}

impl fmt::Debug for SshConnection {
    /// Hand-written: a derived one would reach into the handler, which holds
    /// the credential provider and the prompt channel.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshConnection")
            .field("target", &self.target)
            .field("username", &self.username)
            .field("method", &self.auth.method.as_str())
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// The host as it goes on the wire.
///
/// `HostPort` keeps an IPv6 literal bracketed, because that is the only
/// spelling that survives being concatenated with a port. RFC 4254 §7.2 sends
/// the host as a plain string with the port in a separate field, and OpenSSH
/// sends the literal unbracketed — a bracketed one is a name the far end will
/// fail to resolve.
fn wire_host(target: &HostPort) -> &str {
    target
        .host()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or_else(|| target.host())
}

/// The `russh` configuration a policy implies.
fn russh_config(config: &SshConnectionConfig) -> Config {
    Config {
        // The identification string is sent before encryption and is public by
        // design (RFC 4253 §4.2). Naming the client is what lets a server
        // administrator correlate a session with a bug report.
        client_id: russh::SshId::Standard(Cow::Owned(format!(
            "SSH-2.0-Remoter_{}",
            env!("CARGO_PKG_VERSION")
        ))),
        preferred: config.algorithms.preferred(),
        keepalive_interval: config.keepalive,
        // Three unanswered keepalives before the connection is declared lost:
        // long enough to ride out a roaming laptop, short enough that a dead
        // session does not sit in the tab bar pretending to work.
        keepalive_max: 3,
        // No inactivity timeout: a session left open on purpose is the normal
        // case for this application, and closing it would be a surprise.
        inactivity_timeout: None,
        // The socket is not ours to configure — `russh` never opens one here.
        nodelay: false,
        ..Config::default()
    }
}

/// A stream that stops carrying bytes once its token is cancelled.
///
/// The point is not politeness towards the peer: it is that `russh` owns the
/// stream inside a task this crate never sees a handle for, and a failed read
/// is the only lever that reaches into it. Cancelling the token makes the next
/// read — and any read already parked — fail, so the task unwinds and drops
/// the socket, the handler and whatever credential it was given.
struct GuardedStream<S> {
    inner: S,
    shutdown: CancellationToken,
    /// Kept so a read parked on a silent server is woken by the cancellation
    /// rather than waiting for bytes that will never come.
    notified: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl<S> GuardedStream<S> {
    fn new(inner: S, shutdown: CancellationToken) -> Self {
        Self {
            inner,
            notified: Box::pin(shutdown.clone().cancelled_owned()),
            shutdown,
        }
    }

    /// Whether the stream has been shut down, registering a wake-up if not.
    fn is_shut_down(&mut self, cx: &mut Context<'_>) -> bool {
        if self.shutdown.is_cancelled() {
            return true;
        }
        self.notified.as_mut().poll(cx).is_ready()
    }
}

/// The failure a shut-down stream reports.
///
/// `ConnectionAborted` rather than `BrokenPipe`: the connection was abandoned
/// at this end, and `russh` turns it into a disconnect either way.
fn aborted() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the connection attempt was abandoned",
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for GuardedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.is_shut_down(cx) {
            return Poll::Ready(Err(aborted()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GuardedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.is_shut_down(cx) {
            return Poll::Ready(Err(aborted()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.is_shut_down(cx) {
            return Poll::Ready(Err(aborted()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Shutting a shut-down stream down is what the abandoning path asks
        // for next, and reporting an error there would only be noise.
        if self.shutdown.is_cancelled() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Races a step against cancellation and a deadline, with the deadline
/// suspended while a question is on screen.
///
/// `russh` awaits `Handler::check_server_key` *before* signalling kex-done, so
/// the host key prompt runs inside the handshake. A deadline that enclosed it
/// would time a user out for doing the one thing
/// `docs/security/transport-security.md` asks of them — comparing a
/// fingerprint out of band — and report it as a network timeout. So the budget
/// is spent only while nobody is being asked anything: a slow *server* still
/// fails at 30 s, a slow *person* does not.
pub(crate) async fn with_deadline<F, T>(
    cancel: &CancellationToken,
    timeout: Duration,
    target: &HostPort,
    prompts: Option<&PromptChannel>,
    future: F,
) -> Result<T, ProtocolError>
where
    F: Future<Output = T>,
{
    // Checked before the race, and `biased` inside it: a tab the user closed
    // must report `Cancelled` rather than whatever the half-torn-down stream
    // said on its way out. A random `select!` would report either.
    if cancel.is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }

    let mut remaining = timeout;
    let mut future = std::pin::pin!(future);
    loop {
        let tick = DEADLINE_TICK.min(remaining);
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(ProtocolError::Cancelled),
            value = &mut future => return Ok(value),
            () = tokio::time::sleep(tick) => {
                if prompts.is_some_and(PromptChannel::awaiting_answer) {
                    // The clock is the network's. This tick was the user's.
                    continue;
                }
                remaining = remaining.saturating_sub(tick);
                if remaining.is_zero() {
                    return Err(ProtocolError::ConnectTimeout {
                        target: target.clone(),
                        timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                    });
                }
            }
        }
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
    use remoter_proto::{NoCredentials, event_channel};

    fn target() -> HostPort {
        HostPort::new("db-01.internal", 22).unwrap()
    }

    #[test]
    fn an_ipv6_literal_loses_its_brackets_on_the_wire() {
        // RFC 4254 §7.2 carries the host as a bare string with the port in its
        // own field. A bracketed literal would reach the gateway as a name it
        // cannot resolve, and the failure would look like a DNS problem on a
        // machine with no DNS involved.
        let bracketed = HostPort::new("[2001:db8::1]", 5432).unwrap();
        assert_eq!(wire_host(&bracketed), "2001:db8::1");

        let name = HostPort::new("db-01.internal", 5432).unwrap();
        assert_eq!(wire_host(&name), "db-01.internal");

        let v4 = HostPort::new("10.0.0.5", 5432).unwrap();
        assert_eq!(wire_host(&v4), "10.0.0.5");
    }

    #[test]
    fn the_defaults_follow_the_specification() {
        let config = SshConnectionConfig::new(target(), "ada");
        // Agent forwarding is the one that matters: `docs/features/tunneling.md`
        // requires it off unless asked for.
        assert!(!config.agent_forwarding);
        assert!(config.allow_agent);
        assert_eq!(config.handshake_timeout, DEFAULT_HANDSHAKE_TIMEOUT);
        assert!(config.keepalive.is_none());
        assert!(config.via.is_empty());
    }

    #[test]
    fn the_russh_configuration_carries_the_algorithm_policy() {
        let mut config = SshConnectionConfig::new(target(), "ada");
        config.keepalive = Some(Duration::from_secs(30));
        let built = russh_config(&config);

        assert_eq!(built.keepalive_interval, Some(Duration::from_secs(30)));
        assert!(built.inactivity_timeout.is_none());
        // `russh` must not touch the socket: it never opened one.
        assert!(!built.nodelay);
        assert!(
            built
                .preferred
                .kex
                .iter()
                .any(|name| name.as_ref() == "kex-strict-c-v00@openssh.com")
        );
    }

    #[test]
    fn the_client_identification_names_the_application() {
        let config = SshConnectionConfig::new(target(), "ada");
        let built = russh_config(&config);
        let russh::SshId::Standard(id) = built.client_id else {
            panic!("expected a standard identification string");
        };
        assert!(id.starts_with("SSH-2.0-Remoter_"), "id: {id}");
    }

    #[tokio::test]
    async fn a_blank_user_name_fails_before_any_network_round_trip() {
        // The far end would reject it anyway; failing here costs no packets
        // and names the actual problem.
        let (events, _rx) = event_channel(8);
        let config = SshConnectionConfig::new(target(), "   ");

        let (client, _server) = tokio::io::duplex(64);
        let transport = crate::testing::PipeTransport::new(client, target());

        let error = SshConnection::establish(
            Box::new(transport),
            &config,
            &NoCredentials::new(),
            Arc::new(NoTrust),
            events,
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();

        let ProtocolError::CredentialRequired { target: named } = error else {
            panic!("expected CredentialRequired, got {error:?}");
        };
        assert_eq!(named, target());
    }

    #[tokio::test]
    async fn a_cancelled_attempt_stops_rather_than_waiting_for_the_deadline() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = with_deadline(&cancel, Duration::from_secs(3600), &target(), None, async {
            std::future::pending::<()>().await;
        })
        .await
        .unwrap_err();
        assert!(matches!(error, ProtocolError::Cancelled));
    }

    #[tokio::test]
    async fn a_deadline_names_the_machine_that_did_not_answer() {
        let error = with_deadline(
            &CancellationToken::new(),
            Duration::from_millis(1),
            &target(),
            None,
            async {
                std::future::pending::<()>().await;
            },
        )
        .await
        .unwrap_err();

        let ProtocolError::ConnectTimeout {
            target: named,
            timeout_ms,
        } = error
        else {
            panic!("expected ConnectTimeout, got {error:?}");
        };
        assert_eq!(named, target());
        assert_eq!(timeout_ms, 1);
    }

    /// A handshake budget short enough to keep the deadline tests quick, and
    /// still several [`DEADLINE_TICK`]s long so the loop really spends it.
    const SHORT_BUDGET: Duration = Duration::from_millis(300);

    #[tokio::test]
    async fn a_slow_host_key_decision_does_not_time_the_connection_out() {
        // `russh` awaits `check_server_key` before signalling kex-done, so the
        // fingerprint dialog runs *inside* the handshake.
        // `docs/security/transport-security.md` exists to make people compare
        // that fingerprint out of band, and comparing one takes longer than
        // the thirty seconds the taxonomy gives a server. Timing the user out
        // — and calling it a network timeout — defeats the control.
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        let cancel = CancellationToken::new();

        let answering = tokio::spawn(async move {
            let Some(remoter_proto::SessionEvent::Prompt(prompt)) = rx.recv().await else {
                panic!("expected a prompt event");
            };
            // Several times the handshake budget: a person reading a
            // fingerprint back over a phone call.
            tokio::time::sleep(SHORT_BUDGET * 3).await;
            tx.send(remoter_proto::PromptAnswer::new(prompt.id, b"yes".to_vec()))
                .await
                .unwrap();
        });

        let asked = with_deadline(
            &cancel,
            SHORT_BUDGET,
            &target(),
            Some(prompts.as_ref()),
            async {
                prompts
                    .confirm(
                        &events,
                        remoter_proto::PromptKind::HostKey {
                            host: target().to_string(),
                            algorithm: "ssh-ed25519".to_owned(),
                            fingerprint: "SHA256:AAAA".to_owned(),
                            randomart: String::new(),
                            previously_trusted: None,
                        },
                        target().to_string(),
                    )
                    .await
            },
        )
        .await
        .expect("a thinking user is not a network timeout");

        assert!(asked.expect("the prompt round trip completed"));
        answering.await.unwrap();
    }

    #[tokio::test]
    async fn a_slow_server_still_times_out_while_the_gate_exists() {
        // The other half of the rule: suspending the clock for a person must
        // not suspend it for a silent server. Nothing is on screen here, so
        // every tick is spent.
        let (_tx, prompts) = PromptChannel::new();
        let error = with_deadline(
            &CancellationToken::new(),
            SHORT_BUDGET,
            &target(),
            Some(prompts.as_ref()),
            async {
                std::future::pending::<()>().await;
            },
        )
        .await
        .unwrap_err();

        let ProtocolError::ConnectTimeout {
            target: named,
            timeout_ms,
        } = error
        else {
            panic!("expected ConnectTimeout, got {error:?}");
        };
        assert_eq!(named, target());
        assert_eq!(timeout_ms, 300);
    }

    /// A transport that says when it was dropped.
    ///
    /// The whole question in the leak test is whether the task `russh` spawned
    /// let go of what it was given, and this is what answers it.
    struct WatchedTransport {
        inner: remoter_proto::TcpTransport,
        dropped: tokio::sync::mpsc::UnboundedSender<()>,
    }

    impl Drop for WatchedTransport {
        fn drop(&mut self) {
            let _ = self.dropped.send(());
        }
    }

    impl Transport for WatchedTransport {
        fn peer(&self) -> &TransportPeer {
            self.inner.peer()
        }
    }

    impl tokio::io::AsyncRead for WatchedTransport {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for WatchedTransport {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    struct NoTrust;

    impl TrustStore for NoTrust {
        fn lookup(&self, _host: &HostPort, _algorithm: &str) -> Option<remoter_proto::KnownKey> {
            None
        }
        fn remember(
            &self,
            _host: &HostPort,
            _key: &remoter_proto::KnownKey,
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    /// Runs one abandoned handshake against a listener that never speaks, and
    /// reports whether the socket and the task that held it went away.
    ///
    /// `abandon` decides *how* it is abandoned — a deadline or a closed tab —
    /// and `budget` how long the handshake is allowed before it gives up.
    async fn abandoned_handshake(budget: Duration, abandon: impl FnOnce(CancellationToken)) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = HostPort::new(address.ip().to_string(), address.port()).unwrap();

        // Answers with an identification string (RFC 4253 §4.2) and then goes
        // silent. That is the shape that matters: `connect_stream` spawns
        // `Session::run` only once it has read the peer's identification, and
        // then parks on the kex-done signal — so this is the point at which
        // abandoning the future detaches a task. The read ends only when the
        // client lets go of its end of the socket.
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"SSH-2.0-StalledServer\r\n")
                .await
                .unwrap();
            let mut sink = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut sink).await
        });

        let (dropped_tx, mut dropped_rx) = tokio::sync::mpsc::unbounded_channel();
        let transport = WatchedTransport {
            inner: remoter_proto::TcpTransport::connect(&target, Duration::from_secs(5))
                .await
                .unwrap(),
            dropped: dropped_tx,
        };

        let (events, _rx) = event_channel(8);
        let mut config = SshConnectionConfig::new(target.clone(), "ada");
        config.handshake_timeout = budget;
        config.allow_agent = false;

        let cancel = CancellationToken::new();
        abandon(cancel.clone());

        let error = SshConnection::establish(
            Box::new(transport),
            &config,
            &NoCredentials::new(),
            Arc::new(NoTrust),
            events,
            None,
            &cancel,
        )
        .await
        .expect_err("a server that never speaks cannot complete a handshake");
        assert!(
            matches!(
                error,
                ProtocolError::ConnectTimeout { .. } | ProtocolError::Cancelled
            ),
            "unexpected failure: {error:?}"
        );

        // The task `russh` spawned owns the only copy of the transport. If it
        // were still running, neither of these would ever arrive.
        tokio::time::timeout(Duration::from_secs(5), dropped_rx.recv())
            .await
            .expect("the spawned session task still holds the transport")
            .expect("the transport was never dropped");
        // Read-to-end returning means the peer saw EOF: the file descriptor is
        // closed, not merely unreferenced by this side.
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("the socket was never closed")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn an_abandoned_handshake_does_not_leak_the_session_task() {
        // `connect_stream` spawns `Session::run` and hands back no handle for
        // it. Racing that future and dropping it on a timeout detaches the
        // task — with the socket, the handler and any credential already given
        // to `russh` — for the life of the process, and any unresponsive or
        // hostile server can drive it once per attempt. ADR-0011 requires the
        // opposite: closing a session releases everything deterministically.
        abandoned_handshake(Duration::from_millis(300), |_cancel| {}).await;
    }

    #[tokio::test]
    async fn a_cancelled_handshake_does_not_leak_the_session_task() {
        // The same leak by the other route: the tab is closed while the key
        // exchange is in flight, so the deadline never comes into it.
        abandoned_handshake(Duration::from_secs(30), |cancel| {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                cancel.cancel();
            });
        })
        .await;
    }
}
