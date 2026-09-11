//! Port forwarding: local (`-L`), remote (`-R`) and dynamic SOCKS5 (`-D`).
//!
//! `docs/architecture/project-structure.md` gives forwarding a crate of its own
//! (`remoter-tunnel`). It lives here instead, and the reason is worth stating:
//! every forward is an SSH channel. A `-L` is a `direct-tcpip` opened on this
//! session, a `-R` is a `tcpip-forward` global request answered by
//! `forwarded-tcpip` channels arriving on *this* session's handler, and a `-D`
//! is a SOCKS5 front end that opens `direct-tcpip` for each request. A separate
//! crate could hold none of that without depending on `russh` and on this
//! crate's connection type — it would be a module in a different directory with
//! a circular dependency. The deviation is recorded in the crate documentation.
//!
//! **Every listener defaults to loopback.** See [`crate::bind`] for the rule
//! and for the RFC 4254 §7.1 trap that makes the empty string the wrong
//! default for a remote forward.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use remoter_proto::{HostPort, ProtocolError};
use russh::Channel;
use russh::client::Msg;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::bind::{Exposure, ForwardBind};
use crate::connection::SshConnection;
use crate::socks::{
    Socks5Command, Socks5Error, Socks5Reply, Socks5Request, encode_method_choice, encode_reply,
    parse_greeting, parse_request, select_method, unspecified_bound,
};

/// The most bytes read while waiting for a complete SOCKS5 message.
///
/// A greeting is at most 257 bytes and a request at most 262 (RFC 1928 §3–4),
/// so anything larger is a client that is not speaking SOCKS — or is trying to
/// make the listener buffer without bound.
const MAX_SOCKS_MESSAGE: usize = 512;

/// How many connections one forward listener serves at once.
///
/// A listener that spawns a task per accepted connection has no bound at all:
/// anything that can reach the port — the whole local network, for an exposed
/// bind — exhausts tasks and file descriptors by connecting in a loop. The
/// limit is applied *before* the accept, so surplus connections wait in the
/// kernel's backlog and are refused by the operating system rather than
/// queued in this process. 128 is well beyond what a database client or a
/// browser opens through a tunnel.
pub const MAX_FORWARD_CONNECTIONS: usize = 128;

/// How long a SOCKS5 client has to complete its handshake.
///
/// RFC 1928 §3–4 is two short messages; anything that has not finished them in
/// ten seconds is not going to. Without a deadline a peer holds a connection —
/// and a concurrency slot — open indefinitely by sending one byte and stopping.
pub const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Which way a forward points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwardDirection {
    /// `-L`: a port here reaches a host as the remote sees it.
    Local,
    /// `-R`: a port on the remote reaches a host as we see it.
    Remote,
    /// `-D`: a SOCKS5 proxy here, exiting through the remote.
    Dynamic,
}

impl ForwardDirection {
    /// A stable ASCII name for the message catalogue.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Dynamic => "dynamic",
        }
    }
}

/// One configured forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardSpec {
    /// A local listener tunnelling to `destination`, resolved by the remote.
    Local {
        /// Where to listen, on this machine.
        bind: ForwardBind,
        /// Where the *remote* should connect to.
        destination: HostPort,
    },
    /// A listener on the remote tunnelling back to `destination`, resolved
    /// here.
    Remote {
        /// Where the remote should listen.
        bind: ForwardBind,
        /// Where *this* machine should connect to.
        destination: HostPort,
    },
    /// A SOCKS5 proxy on this machine.
    Dynamic {
        /// Where to listen, on this machine.
        bind: ForwardBind,
    },
}

impl ForwardSpec {
    /// Which way it points.
    #[must_use]
    pub const fn direction(&self) -> ForwardDirection {
        match self {
            Self::Local { .. } => ForwardDirection::Local,
            Self::Remote { .. } => ForwardDirection::Remote,
            Self::Dynamic { .. } => ForwardDirection::Dynamic,
        }
    }

    /// Where it listens.
    #[must_use]
    pub const fn bind(&self) -> &ForwardBind {
        match self {
            Self::Local { bind, .. } | Self::Remote { bind, .. } | Self::Dynamic { bind } => bind,
        }
    }

    /// Where it sends traffic, where that is fixed.
    #[must_use]
    pub const fn destination(&self) -> Option<&HostPort> {
        match self {
            Self::Local { destination, .. } | Self::Remote { destination, .. } => Some(destination),
            Self::Dynamic { .. } => None,
        }
    }

    /// Whether the listener is reachable from beyond its own machine.
    #[must_use]
    pub const fn exposure(&self) -> Exposure {
        self.bind().exposure()
    }
}

/// Live counters for one forward. The session panel reads these.
#[derive(Debug, Default)]
pub struct ForwardStats {
    connections: AtomicU64,
    active: AtomicU64,
    bytes: AtomicU64,
}

impl ForwardStats {
    /// Counts one connection, and counts it out again when the guard drops.
    ///
    /// A guard rather than a matching `closed` call because the connection's
    /// task is routinely dropped mid-pump — the forward is stopped, the tab is
    /// closed — and a gauge that only came down on the tidy path would leave
    /// the session panel claiming connections that ended minutes ago.
    fn open(&self) -> ActiveConnection<'_> {
        self.connections.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        ActiveConnection {
            stats: self,
            bytes: 0,
        }
    }

    /// Connections accepted since the forward started.
    #[must_use]
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Connections open right now.
    #[must_use]
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    /// Bytes carried by connections that have finished.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

/// One counted connection. Releases the gauge on drop, whatever ended it.
struct ActiveConnection<'a> {
    stats: &'a ForwardStats,
    bytes: u64,
}

impl Drop for ActiveConnection<'_> {
    fn drop(&mut self) {
        self.stats.active.fetch_sub(1, Ordering::Relaxed);
        self.stats.bytes.fetch_add(self.bytes, Ordering::Relaxed);
    }
}

/// A snapshot for the session panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardStatus {
    /// Which way it points.
    pub direction: ForwardDirection,
    /// Where it listens, as configured.
    pub bind: String,
    /// Where it sends traffic, where that is fixed.
    pub destination: Option<String>,
    /// Whether the listener is reachable from the network. The interface's
    /// warning badge comes from here.
    pub exposure: Exposure,
    /// The socket actually bound, once known. A configured port of 0 is
    /// assigned by the operating system or by the server, and the user needs
    /// to be told which one they got.
    pub listening: Option<SocketAddr>,
    /// Connections open right now.
    pub active: u64,
    /// Connections accepted since the forward started.
    pub connections: u64,
    /// Bytes carried.
    pub bytes: u64,
    /// Whether the listener is still running.
    pub running: bool,
}

/// A running forward. Dropping it does **not** stop the forward; call
/// [`stop`](Self::stop), or cancel the token the session gave it.
pub struct ForwardHandle {
    spec: ForwardSpec,
    cancel: CancellationToken,
    stats: Arc<ForwardStats>,
    listening: Option<SocketAddr>,
    remote_port: Option<u16>,
}

impl ForwardHandle {
    /// What was configured.
    #[must_use]
    pub const fn spec(&self) -> &ForwardSpec {
        &self.spec
    }

    /// The port the far end actually bound, for a remote forward requested on
    /// port 0 (RFC 4254 §7.1: the server chooses and reports it).
    #[must_use]
    pub const fn remote_port(&self) -> Option<u16> {
        self.remote_port
    }

    /// Stops the listener and every connection it opened.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    /// A snapshot for the session panel.
    #[must_use]
    pub fn status(&self) -> ForwardStatus {
        ForwardStatus {
            direction: self.spec.direction(),
            bind: self.spec.bind().to_string(),
            destination: self.spec.destination().map(ToString::to_string),
            exposure: self.spec.exposure(),
            listening: self.listening,
            active: self.stats.active(),
            connections: self.stats.connections(),
            bytes: self.stats.bytes(),
            running: !self.cancel.is_cancelled(),
        }
    }
}

impl fmt::Debug for ForwardHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForwardHandle")
            .field("spec", &self.spec)
            .field("listening", &self.listening)
            .field("running", &!self.cancel.is_cancelled())
            .finish()
    }
}

/// Where a `forwarded-tcpip` channel should be delivered.
#[derive(Debug, Clone)]
pub struct RemoteDestination {
    /// The host to connect to, on this machine's side of the tunnel.
    pub host: String,
    /// The port to connect to.
    pub port: u16,
    stats: Arc<ForwardStats>,
    cancel: CancellationToken,
}

/// The remote forwards this session has requested.
///
/// The handler consults it before accepting a `forwarded-tcpip` channel: a
/// server opening one for a binding nobody asked for is reaching into the
/// local machine, and is refused (RFC 4254 §7.2 permits refusal).
#[derive(Debug, Default)]
pub struct RemoteForwards {
    entries: Mutex<HashMap<(String, u32), RemoteDestination>>,
}

impl RemoteForwards {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a binding the server accepted.
    pub fn insert(&self, address: &str, port: u32, destination: RemoteDestination) {
        self.entries
            .lock()
            .insert((address.to_owned(), port), destination);
    }

    /// Forgets a binding.
    pub fn remove(&self, address: &str, port: u32) {
        self.entries.lock().remove(&(address.to_owned(), port));
    }

    /// How many bindings are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Where a channel for `address:port` should be delivered.
    ///
    /// Exact match first. Failing that, a *unique* binding on the same port is
    /// accepted: servers routinely echo back a normalised address —
    /// `localhost` requested, `127.0.0.1` reported — and refusing the channel
    /// over a spelling difference would break the forward the user just made.
    /// The uniqueness requirement is what keeps that from being a way in: with
    /// two bindings on one port there is no unambiguous answer, so there is no
    /// answer.
    #[must_use]
    pub fn destination(&self, address: &str, port: u32) -> Option<RemoteDestination> {
        let entries = self.entries.lock();
        if let Some(found) = entries.get(&(address.to_owned(), port)) {
            return Some(found.clone());
        }
        let mut matches = entries
            .iter()
            .filter(|((_, bound), _)| *bound == port)
            .map(|(_, destination)| destination);
        let first = matches.next()?;
        matches.next().is_none().then(|| first.clone())
    }
}

/// Starts a local forward (`-L`).
///
/// # Errors
///
/// [`ProtocolError::SettingInvalid`] if the bind address is not usable, or
/// [`ProtocolError::Io`] if the port could not be bound — "already in use" is
/// the common case, and the operating system's message says so.
pub async fn start_local(
    connection: Arc<SshConnection>,
    spec: ForwardSpec,
    cancel: CancellationToken,
) -> Result<ForwardHandle, ProtocolError> {
    let (ForwardSpec::Local { destination, .. } | ForwardSpec::Remote { destination, .. }) = &spec
    else {
        return Err(ProtocolError::Internal {
            detail: "a dynamic forward was started as a local one",
        });
    };
    let destination = destination.clone();

    let listener = bind_listener(spec.bind()).await?;
    let listening = listener.local_addr().ok();
    let stats = Arc::new(ForwardStats::default());

    let cancel = cancel.child_token();
    tokio::spawn({
        let cancel = cancel.clone();
        let stats = Arc::clone(&stats);
        async move {
            accept_loop(
                listener,
                cancel,
                MAX_FORWARD_CONNECTIONS,
                move |stream, _peer| {
                    let connection = Arc::clone(&connection);
                    let destination = destination.clone();
                    let stats = Arc::clone(&stats);
                    async move {
                        let channel = connection.open_direct_tcpip(&destination).await?;
                        pump(stream, channel.into_stream(), &stats).await;
                        Ok(())
                    }
                },
            )
            .await;
        }
    });

    Ok(ForwardHandle {
        spec,
        cancel,
        stats,
        listening,
        remote_port: None,
    })
}

/// Starts a dynamic SOCKS5 forward (`-D`).
///
/// # Errors
///
/// As [`start_local`].
pub async fn start_dynamic(
    connection: Arc<SshConnection>,
    spec: ForwardSpec,
    cancel: CancellationToken,
) -> Result<ForwardHandle, ProtocolError> {
    if !matches!(spec, ForwardSpec::Dynamic { .. }) {
        return Err(ProtocolError::Internal {
            detail: "a fixed forward was started as a dynamic one",
        });
    }

    let listener = bind_listener(spec.bind()).await?;
    let listening = listener.local_addr().ok();
    let stats = Arc::new(ForwardStats::default());

    let cancel = cancel.child_token();
    tokio::spawn({
        let cancel = cancel.clone();
        let stats = Arc::clone(&stats);
        async move {
            accept_loop(
                listener,
                cancel,
                MAX_FORWARD_CONNECTIONS,
                move |stream, _peer| {
                    let connection = Arc::clone(&connection);
                    let stats = Arc::clone(&stats);
                    async move { serve_socks(stream, connection, &stats).await }
                },
            )
            .await;
        }
    });

    Ok(ForwardHandle {
        spec,
        cancel,
        stats,
        listening,
        remote_port: None,
    })
}

/// Starts a remote forward (`-R`).
///
/// The listener is on the *server*, so this sends a `tcpip-forward` global
/// request (RFC 4254 §7.1) and registers the binding; the channels arrive
/// through [`crate::handler::SshHandler`].
///
/// # Errors
///
/// [`ProtocolError::Disconnected`] if the server refused the request — the
/// usual reasons are the port being in use over there, or `GatewayPorts` being
/// off for a non-loopback bind.
pub async fn start_remote(
    connection: Arc<SshConnection>,
    spec: ForwardSpec,
    cancel: CancellationToken,
) -> Result<ForwardHandle, ProtocolError> {
    let ForwardSpec::Remote { bind, destination } = &spec else {
        return Err(ProtocolError::Internal {
            detail: "a local forward was started as a remote one",
        });
    };

    let assigned = connection
        .request_remote_forward(bind.wire_address(), u32::from(bind.port()))
        .await?;
    // RFC 4254 §7.1: a request for port 0 is answered with the port the server
    // chose, and the binding is keyed on that.
    let effective = if bind.port() == 0 {
        u16::try_from(assigned).unwrap_or(0)
    } else {
        bind.port()
    };

    let stats = Arc::new(ForwardStats::default());
    let cancel = cancel.child_token();
    connection.remote_forwards().insert(
        bind.wire_address(),
        u32::from(effective),
        RemoteDestination {
            host: destination
                .host()
                .trim_matches(|c| c == '[' || c == ']')
                .to_owned(),
            port: destination.port(),
            stats: Arc::clone(&stats),
            cancel: cancel.clone(),
        },
    );

    if bind.exposure() == Exposure::Network {
        tracing::warn!(
            bind = %bind,
            "a remote forward is bound beyond loopback: it opens a path from the remote network into this machine"
        );
    }

    Ok(ForwardHandle {
        spec,
        cancel,
        stats,
        listening: None,
        remote_port: Some(effective),
    })
}

/// Binds a local listener.
async fn bind_listener(bind: &ForwardBind) -> Result<TcpListener, ProtocolError> {
    let address = bind.local_socket()?;
    TcpListener::bind(address)
        .await
        .map_err(|source| ProtocolError::Io {
            operation: "bind a forward listener",
            source,
        })
}

/// Accepts until cancelled, handing each connection to `handle`.
///
/// At most `max_concurrent` connections are served at once, and the slot is
/// taken *before* `accept`: a peer that opens connections in a loop then waits
/// in the kernel's backlog instead of costing this process a task and a file
/// descriptor apiece.
async fn accept_loop<F, Fut>(
    listener: TcpListener,
    cancel: CancellationToken,
    max_concurrent: usize,
    handle: F,
) where
    F: Fn(TcpStream, SocketAddr) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), ProtocolError>> + Send + 'static,
{
    let handle = Arc::new(handle);
    let slots = Arc::new(Semaphore::new(max_concurrent.max(1)));
    loop {
        let slot = tokio::select! {
            () = cancel.cancelled() => return,
            slot = Arc::clone(&slots).acquire_owned() => match slot {
                Ok(slot) => slot,
                // Only if the semaphore were closed, which nothing here does.
                Err(_) => return,
            },
        };

        let accepted = tokio::select! {
            () = cancel.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, peer)) = accepted else {
            // A listener that cannot accept is finished; retrying in a tight
            // loop would spin a core for nothing.
            return;
        };
        // Interactive traffic goes through these too — a forwarded database
        // client, an HTTP request. Nagle's algorithm (RFC 896) would hold
        // small writes back waiting for company.
        let _ = stream.set_nodelay(true);

        let handle = Arc::clone(&handle);
        let cancel = cancel.clone();
        tokio::spawn(async move {
            // Held for the connection's whole life, released however it ends.
            let _slot = slot;
            tokio::select! {
                () = cancel.cancelled() => {}
                result = handle(stream, peer) => {
                    if let Err(error) = result {
                        tracing::debug!(stage = error.stage().as_str(), "a forwarded connection ended");
                    }
                }
            }
        });
    }
}

/// Speaks SOCKS5 to `stream`, then tunnels what it asked for.
async fn serve_socks(
    mut stream: TcpStream,
    connection: Arc<SshConnection>,
    stats: &ForwardStats,
) -> Result<(), ProtocolError> {
    let request = match socks5_handshake_within(&mut stream, SOCKS_HANDSHAKE_TIMEOUT).await {
        Ok(request) => request,
        Err(error) => {
            tracing::debug!(error = %error, "a SOCKS client was refused");
            return Ok(());
        }
    };

    if request.command != Socks5Command::Connect {
        // BIND is out of scope by design. UDP ASSOCIATE cannot be honoured
        // over SSH at all: RFC 4254 defines stream channels and nothing that
        // carries a datagram, so a SOCKS server whose only exit is this
        // session has nowhere to put the UDP. Saying so lets the client fall
        // back instead of waiting for a reply that will never come.
        let _ = stream
            .write_all(&encode_reply(
                Socks5Reply::CommandNotSupported,
                unspecified_bound(),
            ))
            .await;
        return Ok(());
    }

    let target = match HostPort::new(request.address.to_string(), request.port) {
        Ok(target) => target,
        Err(_) => {
            let _ = stream
                .write_all(&encode_reply(
                    Socks5Reply::AddressTypeNotSupported,
                    unspecified_bound(),
                ))
                .await;
            return Ok(());
        }
    };

    let channel = match connection.open_direct_tcpip(&target).await {
        Ok(channel) => channel,
        Err(error) => {
            let _ = stream
                .write_all(&encode_reply(socks_reply_for(&error), unspecified_bound()))
                .await;
            return Ok(());
        }
    };

    stream
        .write_all(&encode_reply(Socks5Reply::Succeeded, unspecified_bound()))
        .await
        .map_err(|source| ProtocolError::Io {
            operation: "write a SOCKS reply",
            source,
        })?;

    pump(stream, channel.into_stream(), stats).await;
    Ok(())
}

/// Maps a failed tunnel open onto a SOCKS reply code (RFC 1928 §6).
const fn socks_reply_for(error: &ProtocolError) -> Socks5Reply {
    match error {
        ProtocolError::ConnectionRefused { .. } => Socks5Reply::ConnectionRefused,
        ProtocolError::NetworkUnreachable { .. } => Socks5Reply::NetworkUnreachable,
        ProtocolError::DnsFailure { .. } | ProtocolError::ConnectTimeout { .. } => {
            Socks5Reply::HostUnreachable
        }
        _ => Socks5Reply::GeneralFailure,
    }
}

/// Performs the SOCKS5 greeting and reads the request.
///
/// Split out from the listener so that a hostile first packet can be exercised
/// over an in-memory pipe: this is the only attacker-facing parser loop in the
/// crate that is not driven by `russh`.
///
/// # Errors
///
/// [`Socks5Error`] for anything malformed, over-long or truncated, and for a
/// client offering no acceptable authentication method.
pub async fn socks5_handshake_within<S>(
    stream: &mut S,
    deadline: Duration,
) -> Result<Socks5Request, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The parser below reads until it has a whole message and has no clock of
    // its own, so a peer that sends one byte and stops holds the connection —
    // and one of the listener's slots — for as long as it likes.
    tokio::time::timeout(deadline, socks5_handshake(stream))
        .await
        .unwrap_or(Err(Socks5Error::Truncated))
}

/// Performs the SOCKS5 greeting and reads the request, with no deadline.
///
/// [`socks5_handshake_within`] is what the listener calls; this is the parser
/// loop on its own, so that a hostile first packet can be exercised without a
/// clock in the way.
///
/// # Errors
///
/// As [`socks5_handshake_within`].
pub async fn socks5_handshake<S>(stream: &mut S) -> Result<Socks5Request, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let methods = read_message(stream, parse_greeting).await?;
    let Some(method) = select_method(&methods) else {
        // RFC 1928 §3: tell the client rather than dropping the connection, so
        // it can report something better than a timeout.
        let _ = stream
            .write_all(&encode_method_choice(crate::socks::METHOD_NONE_ACCEPTABLE))
            .await;
        return Err(Socks5Error::NoMethods);
    };
    stream
        .write_all(&encode_method_choice(method))
        .await
        .map_err(|_| Socks5Error::Truncated)?;

    read_message(stream, parse_request).await
}

/// Reads until `parse` succeeds, or the message is too long to be one.
async fn read_message<S, T, F>(stream: &mut S, parse: F) -> Result<T, Socks5Error>
where
    S: AsyncRead + Unpin,
    F: Fn(&[u8]) -> Result<T, Socks5Error>,
{
    let mut buffer = Vec::with_capacity(64);
    let mut chunk = [0u8; 64];
    loop {
        match parse(&buffer) {
            Ok(value) => return Ok(value),
            // Only "truncated" is worth reading more for. A bad version or an
            // unknown command will not become valid with more bytes.
            Err(Socks5Error::Truncated) => {}
            Err(other) => return Err(other),
        }
        if buffer.len() >= MAX_SOCKS_MESSAGE {
            return Err(Socks5Error::Truncated);
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| Socks5Error::Truncated)?;
        if read == 0 {
            return Err(Socks5Error::Truncated);
        }
        buffer.extend_from_slice(chunk.get(..read).unwrap_or_default());
    }
}

/// Copies in both directions until either end closes, counting the bytes.
///
/// `copy_bidirectional` propagates backpressure in both directions: it never
/// buffers more than its own transfer buffer, so a slow consumer on either
/// side stops the producer on the other. That is what keeps a forward from
/// becoming an unbounded queue.
async fn pump<A, B>(mut local: A, mut remote: B, stats: &ForwardStats)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut counted = stats.open();
    counted.bytes = match tokio::io::copy_bidirectional(&mut local, &mut remote).await {
        Ok((to_remote, to_local)) => to_remote.saturating_add(to_local),
        Err(error) => {
            tracing::debug!(kind = ?error.kind(), "a forwarded connection ended with an error");
            0
        }
    };
    // Shut both halves down explicitly: dropping a channel stream closes it,
    // but a half-open TCP connection would otherwise sit in the accept
    // handler's task until the peer noticed.
    let _ = local.shutdown().await;
    let _ = remote.shutdown().await;
}

/// Delivers one `forwarded-tcpip` channel to its local destination.
pub(crate) fn spawn_forwarded_connection(channel: Channel<Msg>, destination: RemoteDestination) {
    tokio::spawn(async move {
        let address = format!("{}:{}", destination.host, destination.port);
        let stream = tokio::select! {
            () = destination.cancel.cancelled() => return,
            stream = TcpStream::connect(&address) => stream,
        };
        let Ok(stream) = stream else {
            // The channel is dropped, which closes it — the far end sees the
            // refusal, which is the honest answer.
            tracing::debug!(
                port = destination.port,
                "a remote forward could not reach its local destination"
            );
            return;
        };
        let _ = stream.set_nodelay(true);

        tokio::select! {
            () = destination.cancel.cancelled() => {}
            () = pump(stream, channel.into_stream(), &destination.stats) => {}
        }
    });
}

/// Pumps one agent-forwarding channel to the local agent.
///
/// Only ever reached when agent forwarding was explicitly enabled; see
/// [`crate::handler`].
pub(crate) fn spawn_agent_forward(channel: Channel<Msg>) {
    tokio::spawn(async move {
        if let Err(error) = pump_to_agent(channel).await {
            tracing::debug!(kind = ?error.kind(), "an agent forwarding channel ended");
        }
    });
}

#[cfg(unix)]
async fn pump_to_agent(channel: Channel<Msg>) -> std::io::Result<()> {
    use crate::agent::AgentEndpoint;

    let Some(path) = crate::agent::candidates()
        .into_iter()
        .find_map(|endpoint| match endpoint {
            AgentEndpoint::AuthSock(path) => Some(path),
            _ => None,
        })
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no local agent to forward to",
        ));
    };
    let mut agent = tokio::net::UnixStream::connect(path).await?;
    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut stream, &mut agent).await?;
    Ok(())
}

#[cfg(windows)]
async fn pump_to_agent(channel: Channel<Msg>) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let path = std::env::var("SSH_AUTH_SOCK")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".to_owned());
    let mut agent = ClientOptions::new().open(path)?;
    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut stream, &mut agent).await?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
async fn pump_to_agent(_channel: Channel<Msg>) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "agent forwarding is not implemented on this platform",
    ))
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
    use crate::socks::Socks5Address;
    use std::net::Ipv4Addr;

    fn destination(port: u16) -> RemoteDestination {
        RemoteDestination {
            host: "127.0.0.1".to_owned(),
            port,
            stats: Arc::new(ForwardStats::default()),
            cancel: CancellationToken::new(),
        }
    }

    #[test]
    fn a_channel_for_an_unrequested_binding_is_not_delivered() {
        // The whole point of the registry: a server opening a channel for a
        // port nobody forwarded is reaching into this machine.
        let forwards = RemoteForwards::new();
        assert!(forwards.is_empty());
        assert!(forwards.destination("localhost", 9000).is_none());

        forwards.insert("localhost", 9000, destination(9000));
        assert_eq!(forwards.len(), 1);
        assert!(forwards.destination("localhost", 9001).is_none());
        assert!(forwards.destination("localhost", 9000).is_some());
    }

    #[test]
    fn a_normalised_address_still_matches_when_it_is_unambiguous() {
        // Servers commonly report `127.0.0.1` for a `localhost` request.
        let forwards = RemoteForwards::new();
        forwards.insert("localhost", 9000, destination(5432));
        let found = forwards.destination("127.0.0.1", 9000).unwrap();
        assert_eq!(found.port, 5432);
    }

    #[test]
    fn an_ambiguous_port_matches_nothing() {
        // Two bindings on one port have no unambiguous answer, so there is no
        // answer: guessing here would deliver a connection to the wrong place.
        let forwards = RemoteForwards::new();
        forwards.insert("localhost", 9000, destination(1));
        forwards.insert("0.0.0.0", 9000, destination(2));
        assert!(forwards.destination("192.0.2.1", 9000).is_none());
        // The exact spellings still resolve.
        assert_eq!(forwards.destination("localhost", 9000).unwrap().port, 1);
        assert_eq!(forwards.destination("0.0.0.0", 9000).unwrap().port, 2);
    }

    #[test]
    fn removing_a_binding_stops_delivering_to_it() {
        let forwards = RemoteForwards::new();
        forwards.insert("localhost", 9000, destination(1));
        forwards.remove("localhost", 9000);
        assert!(forwards.is_empty());
        assert!(forwards.destination("localhost", 9000).is_none());
    }

    #[test]
    fn a_spec_reports_its_shape() {
        let local = ForwardSpec::Local {
            bind: ForwardBind::loopback(5432).unwrap(),
            destination: HostPort::new("db-01.internal", 5432).unwrap(),
        };
        assert_eq!(local.direction(), ForwardDirection::Local);
        assert_eq!(local.exposure(), Exposure::Loopback);
        assert_eq!(
            local.destination().unwrap().to_string(),
            "db-01.internal:5432"
        );

        let dynamic = ForwardSpec::Dynamic {
            bind: ForwardBind::new(Some("0.0.0.0"), 1080, true).unwrap(),
        };
        assert_eq!(dynamic.direction(), ForwardDirection::Dynamic);
        assert_eq!(dynamic.exposure(), Exposure::Network);
        assert!(dynamic.destination().is_none());
        assert_eq!(ForwardDirection::Remote.as_str(), "remote");
    }

    #[tokio::test]
    async fn a_socks_client_offering_no_auth_gets_its_request_read() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let serving = tokio::spawn(async move { socks5_handshake(&mut server).await });

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();
        assert_eq!(choice, [0x05, 0x00]);

        let mut request = vec![0x05, 0x01, 0x00, 0x03, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();

        let parsed = serving.await.unwrap().unwrap();
        assert_eq!(parsed.command, Socks5Command::Connect);
        assert_eq!(
            parsed.address,
            Socks5Address::Domain("example.com".to_owned())
        );
        assert_eq!(parsed.port, 443);
    }

    #[tokio::test]
    async fn a_message_split_across_reads_is_reassembled() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let serving = tokio::spawn(async move { socks5_handshake(&mut server).await });

        // One byte at a time, which is what a client behind a slow link or a
        // deliberately awkward one produces.
        for byte in [0x05, 0x01, 0x00] {
            client.write_all(&[byte]).await.unwrap();
        }
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();

        let mut request = vec![0x05, 0x01, 0x00, 0x01, 10, 0, 0, 5];
        request.extend_from_slice(&22u16.to_be_bytes());
        for byte in request {
            client.write_all(&[byte]).await.unwrap();
        }

        let parsed = serving.await.unwrap().unwrap();
        assert_eq!(
            parsed.address,
            Socks5Address::Ipv4(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[tokio::test]
    async fn a_client_with_no_acceptable_method_is_told_so() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let serving = tokio::spawn(async move { socks5_handshake(&mut server).await });

        // Username/password only.
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();
        assert_eq!(choice, [0x05, 0xff]);
        assert_eq!(serving.await.unwrap(), Err(Socks5Error::NoMethods));
    }

    #[tokio::test]
    async fn a_client_that_stops_mid_request_is_refused_rather_than_left_open() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let serving = tokio::spawn(async move { socks5_handshake(&mut server).await });

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();

        // A request header promising a 255-byte domain, then a hundred bytes
        // and a hang-up.
        client
            .write_all(&[0x05, 0x01, 0x00, 0x03, 0xff])
            .await
            .unwrap();
        client.write_all(&[b'a'; 100]).await.unwrap();
        drop(client);

        assert_eq!(serving.await.unwrap(), Err(Socks5Error::Truncated));
    }

    #[test]
    fn the_read_bound_still_admits_the_largest_legal_message() {
        // RFC 1928 §4: version, command, reserved, address type, a length byte,
        // 255 bytes of name and two of port. A bound below that would refuse
        // requests that are perfectly valid.
        const { assert!(MAX_SOCKS_MESSAGE >= 4 + 1 + 255 + 2) };
    }

    #[tokio::test]
    async fn a_client_that_is_not_speaking_socks_is_refused_immediately() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let serving = tokio::spawn(async move { socks5_handshake(&mut server).await });
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        assert_eq!(serving.await.unwrap(), Err(Socks5Error::UnsupportedVersion));
    }

    #[tokio::test]
    async fn a_pump_moves_bytes_both_ways_and_counts_them() {
        let (mut a_client, a_server) = tokio::io::duplex(1024);
        let (mut b_client, b_server) = tokio::io::duplex(1024);
        let stats = ForwardStats::default();

        let pumping = tokio::spawn(async move {
            let stats = ForwardStats::default();
            pump(a_server, b_server, &stats).await;
            (stats.connections(), stats.bytes())
        });

        a_client.write_all(b"towards the remote").await.unwrap();
        let mut seen = [0u8; 18];
        b_client.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"towards the remote");

        b_client.write_all(b"and back").await.unwrap();
        let mut back = [0u8; 8];
        a_client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"and back");

        drop(a_client);
        drop(b_client);
        let (connections, bytes) = pumping.await.unwrap();
        assert_eq!(connections, 1);
        assert_eq!(bytes, 26);
        assert_eq!(stats.active(), 0);
    }

    #[test]
    fn a_failed_tunnel_maps_to_a_socks_reply_the_client_can_act_on() {
        let target = HostPort::new("10.0.0.5", 5432).unwrap();
        assert_eq!(
            socks_reply_for(&ProtocolError::ConnectionRefused {
                target: target.clone()
            }),
            Socks5Reply::ConnectionRefused
        );
        assert_eq!(
            socks_reply_for(&ProtocolError::NetworkUnreachable {
                target: target.clone()
            }),
            Socks5Reply::NetworkUnreachable
        );
        assert_eq!(
            socks_reply_for(&ProtocolError::DnsFailure {
                host: "nope.invalid".to_owned()
            }),
            Socks5Reply::HostUnreachable
        );
        assert_eq!(
            socks_reply_for(&ProtocolError::Cancelled),
            Socks5Reply::GeneralFailure
        );
    }

    #[test]
    fn stats_track_open_and_closed_connections() {
        let stats = ForwardStats::default();
        let first = stats.open();
        let second = stats.open();
        assert_eq!(stats.active(), 2);
        assert_eq!(stats.connections(), 2);

        let mut first = first;
        first.bytes = 100;
        drop(first);
        assert_eq!(stats.active(), 1);
        assert_eq!(stats.bytes(), 100);

        drop(second);
        assert_eq!(stats.active(), 0);
        // A connection that ended without reporting its total still comes off
        // the gauge; the byte counter simply does not move.
        assert_eq!(stats.bytes(), 100);
    }

    #[tokio::test]
    async fn a_cancelled_connection_does_not_leave_the_active_gauge_raised() {
        // Every forwarded connection runs inside a `select!` against the
        // forward's token, so stopping a forward *drops* the pump rather than
        // letting it return. A gauge decremented only on the tidy path leaves
        // the session panel claiming connections that ended minutes ago.
        let stats = Arc::new(ForwardStats::default());
        let (a_client, a_server) = tokio::io::duplex(1024);
        let (b_client, b_server) = tokio::io::duplex(1024);
        let cancel = CancellationToken::new();

        let pumping = tokio::spawn({
            let stats = Arc::clone(&stats);
            let cancel = cancel.clone();
            async move {
                tokio::select! {
                    () = cancel.cancelled() => {}
                    () = pump(a_server, b_server, &stats) => {}
                }
            }
        });

        while stats.active() == 0 {
            tokio::task::yield_now().await;
        }
        cancel.cancel();
        pumping.await.unwrap();

        assert_eq!(stats.active(), 0, "the gauge leaked a live connection");
        assert_eq!(stats.connections(), 1);
        drop((a_client, b_client));
    }

    #[tokio::test]
    async fn a_listener_serves_no_more_than_its_concurrency_limit() {
        // Without a cap, anything that can reach the port exhausts tasks and
        // file descriptors simply by connecting in a loop — and an exposed
        // bind can be reached by the whole local network.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let serving = Arc::new(AtomicU64::new(0));
        let hold = CancellationToken::new();

        let accepting = tokio::spawn({
            let cancel = cancel.clone();
            let serving = Arc::clone(&serving);
            let hold = hold.clone();
            async move {
                accept_loop(listener, cancel, 2, move |_stream, _peer| {
                    let serving = Arc::clone(&serving);
                    let hold = hold.clone();
                    async move {
                        serving.fetch_add(1, Ordering::SeqCst);
                        hold.cancelled().await;
                        Ok(())
                    }
                })
                .await;
            }
        });

        let mut clients = Vec::new();
        for _ in 0..6 {
            clients.push(TcpStream::connect(address).await.unwrap());
        }
        // Long enough for the loop to have accepted everything it is willing
        // to accept.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            serving.load(Ordering::SeqCst),
            2,
            "the listener served past its limit"
        );

        // Releasing the two in flight lets the rest through, so the cap is a
        // queue and not a refusal.
        hold.cancel();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(serving.load(Ordering::SeqCst), 6);

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), accepting).await;
        drop(clients);
    }

    #[tokio::test]
    async fn a_socks_client_that_says_nothing_is_dropped_at_the_deadline() {
        // One byte and a wait would otherwise hold a connection — and one of
        // the listener's slots — open for as long as the peer liked.
        let (client, mut server) = tokio::io::duplex(1024);
        // Bounded well past the handshake deadline: without one, the read
        // never returns and a hanging test says nothing.
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            socks5_handshake_within(&mut server, Duration::from_millis(150)),
        )
        .await
        .expect("the handshake had no deadline");
        assert_eq!(outcome, Err(Socks5Error::Truncated));
        drop(client);
    }

    #[tokio::test]
    async fn a_deadline_does_not_cut_a_handshake_that_is_making_progress() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let serving = tokio::spawn(async move {
            socks5_handshake_within(&mut server, Duration::from_secs(30)).await
        });

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut choice = [0u8; 2];
        client.read_exact(&mut choice).await.unwrap();
        let mut request = vec![0x05, 0x01, 0x00, 0x01, 10, 0, 0, 5];
        request.extend_from_slice(&22u16.to_be_bytes());
        client.write_all(&request).await.unwrap();

        assert_eq!(serving.await.unwrap().unwrap().port, 22);
    }
}
