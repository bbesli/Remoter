//! Transports: a connected, bidirectional byte stream, and the description of
//! the far end that goes with it.
//!
//! A [`Transport`] is handed to a protocol adapter already connected
//! (ADR-0003). The adapter never dials out, which is why a jump host chain, a
//! SOCKS proxy or an SSH tunnel is the same code path for every protocol —
//! including plugin-provided ones — and why no adapter contains gateway logic.
//!
//! Only [`TcpTransport`] is implemented here. The others named in
//! `docs/architecture/session-pipeline.md` §4 belong to the crates that own the
//! machinery they need, and their expected shapes are documented on
//! [`TransportKind`] so the implementing crate has a contract to write against
//! rather than a guess.

use std::borrow::Cow;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::error::ProtocolError;

/// A host and port that something can be connected to.
///
/// The host is validated by `remoter-core`, so an IPv6 literal is bracketed
/// here exactly as it is in the vault. That matters more than it looks:
/// `Display` concatenates host and port, and an unbracketed `fe80::1` would
/// produce a string neither a resolver nor a user can parse.
///
/// **What the user typed is kept; what is compared is normalised.** DNS names
/// are case-insensitive (RFC 4343) and a single trailing dot is the root label
/// (RFC 1034 §3.1), so `DB-01.internal`, `db-01.internal` and `db-01.internal.`
/// name one machine. Comparing them as typed made them three trusted
/// identities: a key accepted for one spelling did not satisfy a lookup for
/// another, so an importer that emits a fully qualified name silently bypassed
/// a trust decision the user had already made and re-asked — or worse, treated a
/// changed key as a first use. Equality and hashing therefore use
/// [`canonical_host`](Self::canonical_host); [`host`](Self::host) and `Display`
/// still return the spelling the user chose.
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "HostPortRepr", into = "HostPortRepr")]
pub struct HostPort {
    host: String,
    port: u16,
}

impl HostPort {
    /// Validates `host` and `port` and pairs them.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::InvalidHost`] if the host is empty or is neither a DNS
    /// name, an IPv4 address nor a bracketed IPv6 address;
    /// [`ProtocolError::InvalidPort`] if the port is zero.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, ProtocolError> {
        let host = host.into();
        remoter_core::validate_host(&host)
            .map_err(|_| ProtocolError::InvalidHost { host: host.clone() })?;
        remoter_core::validate_port(port).map_err(|_| ProtocolError::InvalidPort)?;
        Ok(Self { host, port })
    }

    /// The host, as written: a DNS name, an IPv4 address, or a bracketed IPv6
    /// address.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The host folded to the form used for identity comparisons.
    ///
    /// A DNS name is lowercased (RFC 4343: labels are case-insensitive) and a
    /// single trailing dot is removed (RFC 1034 §3.1: the root label is a
    /// spelling of the same name). An address literal is returned as written
    /// apart from the case of IPv6 hexadecimal, because rewriting an address is
    /// how a normaliser turns one host into a different one — an IPv6 zone
    /// identifier (RFC 6874) is an interface name and is left exactly alone.
    ///
    /// This, with the port, is the key a trust store must use. Two spellings of
    /// one machine sharing one host key entry is the whole point: the user made
    /// one decision, not three.
    #[must_use]
    pub fn canonical_host(&self) -> Cow<'_, str> {
        canonical_host(&self.host)
    }

    /// The identity of this endpoint as a single string —
    /// `canonical-host:port` — for a trust store that keys on text.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!("{}:{}", self.canonical_host(), self.port)
    }
}

/// Folds a validated host into its comparison form. See
/// [`HostPort::canonical_host`].
fn canonical_host(host: &str) -> Cow<'_, str> {
    if let Some(inner) = host.strip_prefix('[') {
        // A bracketed IPv6 literal. Hexadecimal digits are case-insensitive, so
        // lowercasing the address is safe; the zone identifier after `%` names
        // a local interface and is case-sensitive, so it is copied verbatim.
        let Some(body) = inner.strip_suffix(']') else {
            return Cow::Borrowed(host);
        };
        let (address, zone) = body
            .split_once('%')
            .map_or((body, None), |(a, z)| (a, Some(z)));
        let address = address.to_ascii_lowercase();
        return Cow::Owned(zone.map_or_else(
            || format!("[{address}]"),
            |zone| format!("[{address}%{zone}]"),
        ));
    }

    // An IPv4 literal has no case and no trailing dot to fold; leaving it alone
    // is both correct and the cheap path.
    if host.parse::<Ipv4Addr>().is_ok() {
        return Cow::Borrowed(host);
    }

    let trimmed = host.strip_suffix('.').unwrap_or(host);
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else if trimmed.len() == host.len() {
        Cow::Borrowed(host)
    } else {
        Cow::Borrowed(trimmed)
    }
}

impl PartialEq for HostPort {
    /// Compares the canonical forms, so that one machine is one identity
    /// however the user or an importer spelled it.
    fn eq(&self, other: &Self) -> bool {
        self.port == other.port && self.canonical_host() == other.canonical_host()
    }
}

impl Eq for HostPort {}

impl std::hash::Hash for HostPort {
    /// Hashes what [`PartialEq`] compares — required for the two to agree, and
    /// what makes a `HashMap<HostPort, _>` trust store resolve every spelling
    /// of a host to one entry.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.canonical_host().hash(state);
        self.port.hash(state);
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // As typed: this is what the user recognises, and a diagnostic that
        // renames their host is a diagnostic they do not trust.
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl fmt::Debug for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The same rendering as `Display`: a target address is diagnostic
        // information, and two spellings of it in logs helps nobody.
        write!(f, "{self}")
    }
}

/// Serialisation shadow for [`HostPort`], so that a value arriving from disk or
/// from the interface goes through the same validation a typed-in one does.
#[derive(Serialize, Deserialize)]
struct HostPortRepr {
    host: String,
    port: u16,
}

impl TryFrom<HostPortRepr> for HostPort {
    type Error = ProtocolError;

    fn try_from(repr: HostPortRepr) -> Result<Self, Self::Error> {
        Self::new(repr.host, repr.port)
    }
}

impl From<HostPort> for HostPortRepr {
    fn from(value: HostPort) -> Self {
        Self {
            host: value.host,
            port: value.port,
        }
    }
}

/// Which mechanism carries a transport's bytes.
///
/// The variants this crate does not implement are listed because the session
/// pipeline names them and because each one's constructor shape is part of the
/// contract between this crate and the crate that supplies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// A direct TCP connection. See [`TcpTransport`].
    Tcp,

    /// An SSH `direct-tcpip` channel (RFC 4254 §7.2) — one hop of a gateway
    /// chain, or a port forward.
    ///
    /// Implemented by `remoter-proto-ssh`, which owns the `russh` session the
    /// channel belongs to. Expected shape:
    ///
    /// ```ignore
    /// impl SshChannelTransport {
    ///     /// `channel` is an opened `direct-tcpip` channel; `target` is what
    ///     /// the far end connected it to; `via` names the gateways already
    ///     /// traversed, outermost first.
    ///     pub fn new(
    ///         channel: russh::Channel<russh::client::Msg>,
    ///         target: HostPort,
    ///         via: Vec<String>,
    ///     ) -> Self;
    /// }
    /// ```
    ///
    /// The implementation must keep the owning SSH session alive for as long
    /// as the channel exists — dropping the session closes the channel out
    /// from under the protocol running inside it.
    SshChannel,

    /// A stream through a SOCKS5 proxy (RFC 1928), CONNECT command.
    ///
    /// Implemented by `remoter-tunnel`. Expected shape:
    ///
    /// ```ignore
    /// impl Socks5Transport {
    ///     /// Performs the greeting, optional username/password
    ///     /// authentication (RFC 1929) and the CONNECT request over
    ///     /// `via`, then hands back the tunnelled stream.
    ///     pub async fn connect(
    ///         via: Box<dyn Transport>,
    ///         target: &HostPort,
    ///         auth: Option<&dyn CredentialProvider>,
    ///     ) -> Result<Self, ProtocolError>;
    /// }
    /// ```
    ///
    /// `via` is itself a transport rather than an address so that a SOCKS
    /// proxy can be reached through a jump host, which is the whole point of
    /// the injected-transport design.
    Socks5,

    /// A stream through an HTTP proxy's `CONNECT` method (RFC 9110 §9.3.6).
    ///
    /// Implemented by `remoter-tunnel`. Expected shape:
    ///
    /// ```ignore
    /// impl HttpConnectTransport {
    ///     /// Sends `CONNECT host:port HTTP/1.1` over `via` and returns the
    ///     /// stream once a 2xx response has been read. Basic and Digest
    ///     /// authentication are driven from `auth`; the credential is
    ///     /// borrowed for the challenge and never retained.
    ///     pub async fn connect(
    ///         via: Box<dyn Transport>,
    ///         target: &HostPort,
    ///         auth: Option<&dyn CredentialProvider>,
    ///     ) -> Result<Self, ProtocolError>;
    /// }
    /// ```
    HttpConnect,

    /// A TLS session wrapping any other transport.
    Tls,

    /// A transport supplied by a WebAssembly plugin — a cloud provider's
    /// session manager, for instance. A session manager is a transport, not a
    /// protocol: the existing SSH or RDP adapter runs over it unchanged.
    Plugin,
}

/// What is at the far end of a transport, for diagnostics.
///
/// Carried so that an error can name the machine that failed rather than the
/// socket that noticed. Nothing in here is secret: a hostname, a port and the
/// names of the gateways traversed are all things the user typed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPeer {
    /// How the bytes are carried.
    pub kind: TransportKind,
    /// The address the far end represents.
    pub target: HostPort,
    /// The gateways traversed to reach it, outermost first. Empty for a direct
    /// connection.
    pub via: Vec<String>,
}

impl TransportPeer {
    /// A peer reached directly.
    #[must_use]
    pub const fn direct(kind: TransportKind, target: HostPort) -> Self {
        Self {
            kind,
            target,
            via: Vec::new(),
        }
    }

    /// A peer reached through the named gateways, outermost first.
    #[must_use]
    pub const fn through(kind: TransportKind, target: HostPort, via: Vec<String>) -> Self {
        Self { kind, target, via }
    }

    /// How many gateways the stream passes through.
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.via.len()
    }
}

impl fmt::Display for TransportPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.target)?;
        if !self.via.is_empty() {
            write!(f, " via {}", self.via.join(" → "))?;
        }
        Ok(())
    }
}

impl fmt::Debug for TransportPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self} ({:?})", self.kind)
    }
}

/// A connected, bidirectional byte stream.
///
/// The single most important decision in this layer (ADR-0003): a protocol
/// adapter *receives* one of these rather than dialling one. Jump host chains,
/// proxies and tunnels therefore work identically for every protocol, and RDP
/// through two SSH bastions is the same code path as RDP on the LAN.
///
/// `'static` and `Send` because a transport is moved into a session task;
/// `Unpin` so that `Box<dyn Transport>` can be read and written without pin
/// projection, which would need `unsafe` that this workspace forbids.
pub trait Transport: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    /// A description of the far end, for diagnostics and for the session
    /// panel. Never secret.
    fn peer(&self) -> &TransportPeer;
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn peer(&self) -> &TransportPeer {
        (**self).peer()
    }
}

/// A direct TCP connection.
#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
    peer: TransportPeer,
}

impl TcpTransport {
    /// Resolves `target` and connects, giving up after `timeout`.
    ///
    /// Resolution failure, refusal and timeout are three different errors
    /// because they have three different next actions: check the name, check
    /// the service, check the firewall. Collapsing them into "connection
    /// failed" is what forces a user to reach for `nc` to find out what their
    /// connection manager already knew.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::DnsFailure`], [`ProtocolError::ConnectionRefused`],
    /// [`ProtocolError::ConnectTimeout`], [`ProtocolError::NetworkUnreachable`]
    /// or [`ProtocolError::Io`].
    pub async fn connect(target: &HostPort, timeout: Duration) -> Result<Self, ProtocolError> {
        Self::connect_cancellable(target, timeout, &CancellationToken::new()).await
    }

    /// Resolves `target` and connects, giving up after `timeout` or when
    /// `cancel` fires.
    ///
    /// **Resolution is inside the deadline and inside the cancellation.** Name
    /// resolution is a network operation like any other: a DNS server that
    /// black-holes the query leaves `getaddrinfo` waiting, and awaiting it
    /// before the timeout starts means the 30 s the user was promised
    /// (`docs/architecture/session-pipeline.md`, "Transport | Timeout") is
    /// 30 s *plus* however long the resolver takes — with no cancel button that
    /// works, because closing the tab cannot reach a future nothing is racing.
    ///
    /// # Errors
    ///
    /// As [`connect`](Self::connect), plus [`ProtocolError::Cancelled`] when
    /// `cancel` fires first.
    pub async fn connect_cancellable(
        target: &HostPort,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<Self, ProtocolError> {
        let attempt = tokio::time::timeout(timeout, async {
            let addresses = tokio::net::lookup_host(target.to_string())
                .await
                .map_err(|_| ProtocolError::DnsFailure {
                    host: target.host().to_owned(),
                })?
                .collect::<Vec<_>>();

            if addresses.is_empty() {
                return Err(ProtocolError::DnsFailure {
                    host: target.host().to_owned(),
                });
            }

            // Addresses are tried in the order the resolver returned them.
            // RFC 8305 "Happy Eyeballs" would race the address families
            // instead; that is a latency optimisation, and doing it here would
            // make the error report which family lost rather than which host
            // was unreachable.
            let mut last: Option<io::Error> = None;
            for address in addresses {
                match TcpStream::connect(address).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last = Some(error),
                }
            }
            Err(Self::classify(
                target,
                &last.unwrap_or_else(|| io::Error::other("no address was tried")),
            ))
        });

        // Dropping `attempt` on cancellation drops the resolution and the
        // half-open socket with it, which is what makes a closed tab release
        // its file descriptors deterministically (CLAUDE.md §5, "Async").
        let stream = tokio::select! {
            () = cancel.cancelled() => return Err(ProtocolError::Cancelled),
            outcome = attempt => match outcome {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => return Err(error),
                Err(_elapsed) => {
                    return Err(ProtocolError::ConnectTimeout {
                        target: target.clone(),
                        timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                    });
                }
            },
        };

        // Interactive sessions send single keystrokes. Nagle's algorithm
        // (RFC 896, and RFC 1122 §4.2.3.4 on its interaction with delayed ACKs)
        // would hold each one back waiting for company, which is felt directly
        // as typing lag.
        stream
            .set_nodelay(true)
            .map_err(|source| ProtocolError::Io {
                operation: "set TCP_NODELAY",
                source,
            })?;

        Ok(Self {
            stream,
            peer: TransportPeer::direct(TransportKind::Tcp, target.clone()),
        })
    }

    /// Adopts an already-connected stream — the local end of a forward, or a
    /// socket a test supplied.
    #[must_use]
    pub fn from_stream(stream: TcpStream, peer: TransportPeer) -> Self {
        Self { stream, peer }
    }

    /// Maps an operating system error onto the failure taxonomy.
    fn classify(target: &HostPort, error: &io::Error) -> ProtocolError {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => ProtocolError::ConnectionRefused {
                target: target.clone(),
            },
            io::ErrorKind::TimedOut => ProtocolError::ConnectTimeout {
                target: target.clone(),
                timeout_ms: 0,
            },
            io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown => ProtocolError::NetworkUnreachable {
                target: target.clone(),
            },
            _ => ProtocolError::Io {
                operation: "connect",
                // `io::Error` is not `Clone`; rebuild it rather than take it by
                // value, which would make `classify` consume its argument at
                // every call site for the sake of one branch.
                source: io::Error::new(error.kind(), error.to_string()),
            },
        }
    }
}

impl Transport for TcpTransport {
    fn peer(&self) -> &TransportPeer {
        &self.peer
    }
}

// `TcpStream` is `Unpin`, so every projection below is a safe `Pin::new`. This
// is the reason `Transport` requires `Unpin`: without it these delegations
// would need `unsafe`, which the crate forbids.
impl AsyncRead for TcpTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpTransport {
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

/// A transport that is additionally `Sync`.
///
/// [`Transport`] requires `Send` and not `Sync`, because a stream lives in one
/// task and nothing in this workspace reads it from two. Some protocol
/// libraries ask for more than that anyway: `vnc-rs` 0.5 bounds its connector
/// on `AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static`, so
/// `Box<dyn Transport>` does not satisfy it and the adapter cannot hand its
/// injected transport straight over.
///
/// The obvious workaround — a task pumping bytes between the transport and a
/// `tokio::io::duplex` pair — is the wrong one twice over. It copies every
/// byte of a framebuffer stream, and it adds a task that has to be cancelled
/// with the session. A task that is *nearly* always cancelled is how one task
/// and one socket leaked per cancelled connection attempt once already.
///
/// This wrapper adds `Sync` structurally instead. The mutex is never contended
/// — `poll_read` and `poll_write` take `Pin<&mut Self>`, so the caller already
/// holds exclusive access — and it is never held across an await, because a
/// `poll_*` method cannot await. It costs an uncontended atomic per call and
/// no copy, and it needs no `unsafe`.
pub struct SyncTransport {
    inner: parking_lot::Mutex<Box<dyn Transport>>,
    /// Cloned at construction: `Transport::peer` returns a reference, and a
    /// reference cannot outlive the guard it would have to be read through.
    peer: TransportPeer,
}

impl SyncTransport {
    /// Wraps an injected transport so it can be handed to a library that
    /// demands `Sync`.
    #[must_use]
    pub fn new(inner: Box<dyn Transport>) -> Self {
        let peer = inner.peer().clone();
        Self {
            inner: parking_lot::Mutex::new(inner),
            peer,
        }
    }

    /// Gives the wrapped transport back.
    ///
    /// The point of returning it rather than dropping it is that a handshake
    /// which fails part way can hand the stream on — to a retry, or to an
    /// error path that wants to send a protocol-level goodbye — instead of
    /// silently abandoning a connected socket.
    #[must_use]
    pub fn into_inner(self) -> Box<dyn Transport> {
        self.inner.into_inner()
    }
}

impl Transport for SyncTransport {
    fn peer(&self) -> &TransportPeer {
        &self.peer
    }
}

impl fmt::Debug for SyncTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncTransport")
            .field("peer", &self.peer)
            .finish()
    }
}

// `Box<dyn Transport>` is `Unpin`, so every projection below is a safe
// `Pin::new` on the value behind the guard.
impl AsyncRead for SyncTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SyncTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_shutdown(cx)
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
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn a_host_port_renders_as_host_colon_port() {
        let hp = HostPort::new("db-01.internal", 5432).unwrap();
        assert_eq!(hp.to_string(), "db-01.internal:5432");
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets() {
        let hp = HostPort::new("[2001:db8::1]", 22).unwrap();
        assert_eq!(hp.to_string(), "[2001:db8::1]:22");
    }

    #[test]
    fn an_unbracketed_ipv6_literal_is_refused() {
        let Err(ProtocolError::InvalidHost { host }) = HostPort::new("2001:db8::1", 22) else {
            panic!("an unbracketed IPv6 literal must not be accepted");
        };
        assert_eq!(host, "2001:db8::1");
    }

    /// One machine is one identity, however it was spelled.
    ///
    /// Every trust store key derives from a `HostPort`. While the host was
    /// compared exactly as typed, an importer that emits `db-01.internal.` or a
    /// user who typed `DB-01.internal` got a *different* trusted identity from
    /// the one they had already approved — which bypasses the decision at best,
    /// and at worst reports a changed key as a first use.
    #[test]
    fn three_spellings_of_one_host_are_one_identity() {
        let typed = HostPort::new("db-01.internal", 22).unwrap();
        let shouted = HostPort::new("DB-01.internal", 22).unwrap();
        let qualified = HostPort::new("db-01.internal.", 22).unwrap();

        for other in [&shouted, &qualified] {
            assert_eq!(&typed, other, "{other} must be the same host as {typed}");
            assert_eq!(typed.canonical(), other.canonical());
        }
        assert_eq!(typed.canonical(), "db-01.internal:22");

        // Equal values must hash equally, or a `HashMap` store still splits
        // them across three entries.
        let mut store: HashMap<HostPort, &str> = HashMap::new();
        store.insert(typed.clone(), "the key the user approved");
        store.insert(shouted.clone(), "the key the user approved");
        store.insert(qualified.clone(), "the key the user approved");
        assert_eq!(store.len(), 1, "one machine became {} entries", store.len());
        assert!(store.contains_key(&qualified));

        // A different port is a different endpoint, and a different name is a
        // different machine — normalising must not merge those.
        assert_ne!(typed, HostPort::new("db-01.internal", 2222).unwrap());
        assert_ne!(typed, HostPort::new("db-02.internal", 22).unwrap());
    }

    #[test]
    fn the_spelling_the_user_chose_is_what_is_displayed_and_dialled() {
        // Normalisation is for comparison only. A diagnostic that renames the
        // user's host is a diagnostic they cannot match against their own notes.
        let shouted = HostPort::new("DB-01.internal", 22).unwrap();
        assert_eq!(shouted.host(), "DB-01.internal");
        assert_eq!(shouted.to_string(), "DB-01.internal:22");
        assert_eq!(format!("{shouted:?}"), "DB-01.internal:22");
    }

    #[test]
    fn an_address_literal_is_never_normalised_into_a_different_address() {
        // IPv4: nothing to fold, and nothing may be invented.
        let v4 = HostPort::new("10.0.0.5", 22).unwrap();
        assert_eq!(v4.canonical_host(), "10.0.0.5");
        assert_ne!(v4, HostPort::new("10.0.0.6", 22).unwrap());

        // IPv6: hexadecimal is case-insensitive, so the two spellings are one
        // address and the brackets survive.
        let upper = HostPort::new("[2001:DB8::1]", 22).unwrap();
        let lower = HostPort::new("[2001:db8::1]", 22).unwrap();
        assert_eq!(upper, lower);
        assert_eq!(upper.canonical_host(), "[2001:db8::1]");
        assert_ne!(upper, HostPort::new("[2001:db8::2]", 22).unwrap());

        // A zone identifier (RFC 6874) is a local interface name, not part of
        // the address, so it is carried through exactly as written.
        let zoned = HostPort::new("[fe80::1%Ethernet2]", 22).unwrap();
        assert_eq!(zoned.canonical_host(), "[fe80::1%Ethernet2]");
        assert_ne!(zoned, HostPort::new("[fe80::1%ethernet2]", 22).unwrap());
    }

    #[test]
    fn port_zero_is_refused() {
        assert!(matches!(
            HostPort::new("example.com", 0),
            Err(ProtocolError::InvalidPort)
        ));
    }

    #[test]
    fn a_host_port_arriving_from_disk_is_validated_like_a_typed_one() {
        // This is the path `#[serde(try_from = "HostPortRepr")]` routes
        // through, so a vault written by a buggy build cannot smuggle an
        // unvalidated address into a connection attempt.
        let repr = HostPortRepr {
            host: "not a host".to_owned(),
            port: 22,
        };
        assert!(HostPort::try_from(repr).is_err());

        let good = HostPortRepr {
            host: "example.com".to_owned(),
            port: 22,
        };
        assert_eq!(
            HostPort::try_from(good).unwrap(),
            HostPort::new("example.com", 22).unwrap()
        );
    }

    #[test]
    fn a_peer_names_the_gateways_it_passed_through() {
        let peer = TransportPeer::through(
            TransportKind::SshChannel,
            HostPort::new("db-01.internal", 5432).unwrap(),
            vec!["bastion-1".to_owned(), "jump-eu".to_owned()],
        );
        assert_eq!(peer.hop_count(), 2);
        assert_eq!(
            peer.to_string(),
            "db-01.internal:5432 via bastion-1 → jump-eu"
        );
    }

    #[tokio::test]
    async fn a_tcp_transport_carries_bytes_both_ways() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(b"pong!").await.unwrap();
            buf
        });

        let target = HostPort::new("127.0.0.1", port).unwrap();
        let mut transport = TcpTransport::connect(&target, Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(transport.peer().kind, TransportKind::Tcp);
        assert_eq!(transport.peer().target, target);
        assert!(transport.peer().via.is_empty());

        transport.write_all(b"ping!").await.unwrap();
        let mut reply = [0u8; 5];
        transport.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong!");
        assert_eq!(&server.await.unwrap(), b"ping!");
    }

    #[tokio::test]
    async fn a_boxed_transport_is_still_a_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _accepted = listener.accept().await;
        });

        let target = HostPort::new("127.0.0.1", port).unwrap();
        let boxed: Box<dyn Transport> = Box::new(
            TcpTransport::connect(&target, Duration::from_secs(5))
                .await
                .unwrap(),
        );
        assert_eq!(boxed.peer().target, target);
    }

    #[tokio::test]
    async fn a_refused_port_is_reported_as_refused_not_as_a_timeout() {
        // Bind and immediately drop, so the port is almost certainly closed and
        // is definitely not listening.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = HostPort::new("127.0.0.1", port).unwrap();
        let error = TcpTransport::connect(&target, Duration::from_secs(5))
            .await
            .expect_err("a closed port must not connect");
        assert!(
            matches!(error, ProtocolError::ConnectionRefused { .. }),
            "expected a refusal, got {error:?}"
        );
    }

    /// A connect that has not started resolving yet is already cancellable.
    ///
    /// Before the deadline and the token covered resolution, `connect` awaited
    /// `lookup_host` unconditionally: there was no token, so a closed tab could
    /// not reach the attempt at all, and a resolver that never answers held the
    /// session open past whatever deadline the user was promised.
    #[tokio::test]
    async fn a_cancelled_token_stops_a_connect_before_it_resolves() {
        let cancel = CancellationToken::new();
        cancel.cancel();

        // `.invalid` is reserved by RFC 2606 §2 and never resolves, so reaching
        // the resolver at all would be the bug.
        let target = HostPort::new("nothing.here.invalid", 22).unwrap();
        let error = TcpTransport::connect_cancellable(&target, Duration::from_secs(3600), &cancel)
            .await
            .expect_err("a cancelled connect must not produce a transport");
        assert!(matches!(error, ProtocolError::Cancelled), "got {error:?}");
    }

    /// Cancellation reaches the attempt *while it is resolving*, rather than
    /// only once the resolver has answered.
    ///
    /// The deadline here is an hour: if the token did not race the resolution,
    /// closing the tab would leave this waiting for one.
    #[tokio::test]
    async fn cancelling_mid_resolution_does_not_wait_for_the_deadline() {
        let cancel = CancellationToken::new();
        let waker = cancel.clone();
        tokio::spawn(async move {
            // The connect is inside its resolution by the time this runs: the
            // calling task can only reach here by having yielded, and the first
            // thing it yields on is the name lookup.
            tokio::task::yield_now().await;
            waker.cancel();
        });

        let target = HostPort::new("nothing.here.invalid", 22).unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            TcpTransport::connect_cancellable(&target, Duration::from_secs(3600), &cancel),
        )
        .await
        .expect("cancellation must not wait for the connect deadline")
        .expect_err("a cancelled connect must not produce a transport");
        assert!(matches!(error, ProtocolError::Cancelled), "got {error:?}");
    }

    #[tokio::test]
    async fn an_unresolvable_name_is_reported_as_a_dns_failure() {
        // `.invalid` is reserved by RFC 2606 §2 and guaranteed never to resolve.
        let target = HostPort::new("nothing.here.invalid", 22).unwrap();
        let error = TcpTransport::connect(&target, Duration::from_secs(5))
            .await
            .expect_err("a reserved-TLD name must not resolve");
        let ProtocolError::DnsFailure { host } = error else {
            panic!("expected a DNS failure, got {error:?}");
        };
        assert_eq!(host, "nothing.here.invalid");
    }

    /// A transport wrapped for a library that demands `Sync` must still be a
    /// transport: same peer, same bytes, no pump task in between.
    #[tokio::test]
    async fn a_sync_wrapped_transport_carries_bytes_and_keeps_its_peer() {
        // `Send + Sync + 'static` is the bound `vnc-rs` 0.5 applies to its
        // stream. Asserting it here means the VNC adapter finds out at this
        // test rather than at its own integration point.
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<SyncTransport>();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });

        let target = HostPort::new("127.0.0.1", port).unwrap();
        let direct = TcpTransport::connect(&target, Duration::from_secs(5))
            .await
            .unwrap();
        let peer = direct.peer().clone();
        let mut wrapped = SyncTransport::new(Box::new(direct));

        assert_eq!(wrapped.peer(), &peer);
        wrapped.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        wrapped.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");

        // The stream is handed back rather than abandoned, so a handshake that
        // fails part way still has a socket to say goodbye on.
        let recovered = wrapped.into_inner();
        assert_eq!(recovered.peer(), &peer);
        echo.await.unwrap();
    }
}
