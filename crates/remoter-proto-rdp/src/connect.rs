//! The connection sequence: MS-RDPBCGR §1.3.1.1, start to finish.
//!
//! ```text
//!   1  Connection Initiation      X.224 Connection Request / Confirm   §2.2.1.1–2.2.1.2
//!   2  Enhanced security upgrade  TLS handshake                        §5.4.5.1
//!   3  Network Level Auth         CredSSP inside the tunnel            §5.4.5.2, MS-CSSP
//!   4  Basic Settings Exchange    MCS Connect Initial / Response       §2.2.1.3–2.2.1.4
//!   5  Channel Connection         Erect Domain, Attach User, joins     §2.2.1.5–2.2.1.9
//!   6  Secure Settings Exchange   Client Info PDU                      §2.2.1.11
//!   7  Licensing                  MS-RDPELE                            §2.2.1.12
//!   8  Capabilities Exchange      Demand Active / Confirm Active       §2.2.1.13–2.2.1.13.2
//!   9  Connection Finalization    Synchronize, Control, Font List/Map  §2.2.1.14–2.2.1.19
//! ```
//!
//! # Why this is written out rather than delegated to `ironrdp-connector`
//!
//! `ironrdp-connector` is exactly this state machine, and it cannot be added to
//! this workspace: it pins `picky =7.0.0-rc.25` with default features, which
//! activate `aes-gcm =0.11.0-rc.4`, and `remoter-import` already depends on the
//! released `aes-gcm 0.11`. Cargo carries one or the other, so adding the
//! feature fails **every** command in the repository rather than only this
//! crate. `Cargo.toml` records the resolver's own error verbatim and the three
//! ways out, none of which is this commit's to take.
//!
//! What that crate is built on — `ironrdp-pdu`'s wire types — resolves and
//! compiles cleanly, and it is what this module uses. Every PDU below is
//! IronRDP's encoding of a structure MS-RDPBCGR defines; nothing here invents a
//! field, and the section number beside each step is where to check that claim.
//!
//! # Cancellation
//!
//! The whole sequence runs inside [`with_deadline`], which races it against the
//! session's cancellation token and a wall-clock budget. It is one future, not
//! a spawned task: cancelling it drops the [`Framed`], which drops the TLS
//! stream, which drops the injected transport, which closes the socket. A
//! previous defect in this project leaked one task and one socket per cancelled
//! connection attempt, and "no spawn" is the shape that cannot.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use ironrdp::core::{Encode, encode_vec};
use ironrdp::pdu::rdp::capability_sets::CapabilitySet;
use ironrdp::pdu::rdp::headers::{ShareControlPdu, ShareDataPdu};
use ironrdp::pdu::x224::{X224, X224Data};
use ironrdp::pdu::{gcc, mcs, nego, rdp};
use ironrdp::svc::{StaticChannelSet, SvcClientProcessor, make_channel_definition};
use remoter_proto::{ClipboardPolicy, CredentialProvider, EventSink, HostPort, ProtocolError};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize as _;

use crate::cert::CertificateChecker;
use crate::credssp::{self, CredsspClient, Step};
use crate::error::{handshake_failed, map_negotiation_failure, violation};
use crate::framed::{Framed, MAX_FASTPATH_REASSEMBLY_BYTES};
use crate::prompt::PromptChannel;

/// How long the whole sequence gets when the connection sets no timeout.
///
/// Thirty seconds is the figure `docs/architecture/session-pipeline.md`'s
/// failure taxonomy uses for "did not respond within". The clock is suspended
/// while a prompt is on screen — comparing a fingerprint out of band takes
/// longer than any server is allowed to take to answer.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the deadline is re-examined while the sequence runs.
const TICK: Duration = Duration::from_millis(100);

/// How many Deactivate All PDUs may precede the Demand Active before the
/// reactivation is given up on.
///
/// A server sends at most one (§1.3.1.3); Windows Server and
/// gnome-remote-desktop both do. A server that sends them without end is
/// either broken or wasting this client's time on purpose, and each one costs
/// a read — so the sequence is bounded by a count as well as by the clock
/// [`reactivate`] puts on it, because a count is what makes the bound testable
/// without waiting out a whole [`DEFAULT_TIMEOUT`].
pub const MAX_DEACTIVATIONS: usize = 8;

/// The MCS `result` value that means the request succeeded.
///
/// T.125 §7: `Result ::= ENUMERATED { rt-successful(0), ... }`. Every other
/// value is a refusal, and MS-RDPBCGR §2.2.1.7 and §2.2.1.9 carry the field
/// unchanged.
const MCS_RT_SUCCESSFUL: u8 = 0;

/// The name T.125 gives an MCS `result` code.
///
/// For the diagnostic log only — the taxonomy's `detail` fields are
/// `&'static str` so that no formatted value can reach one, and a bare number
/// in a log sends the reader to the specification for the one thing the
/// specification does supply. The codes a real RDP server sends are
/// `rt-no-such-channel` (the channel was never created),
/// `rt-too-many-channels` and `rt-user-rejected`.
const fn mcs_result_name(result: u8) -> &'static str {
    match result {
        0 => "rt-successful",
        1 => "rt-domain-merging",
        2 => "rt-domain-not-hierarchical",
        3 => "rt-no-such-channel",
        4 => "rt-no-such-domain",
        5 => "rt-no-such-user",
        6 => "rt-not-admitted",
        7 => "rt-other-user-id",
        8 => "rt-parameters-unacceptable",
        9 => "rt-token-not-available",
        10 => "rt-token-not-possessed",
        11 => "rt-too-many-channels",
        12 => "rt-too-many-tokens",
        13 => "rt-too-many-users",
        14 => "rt-unspecified-failure",
        15 => "rt-user-rejected",
        _ => "an MCS result T.125 does not define",
    }
}

/// The desktop the client asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopSize {
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
}

impl Default for DesktopSize {
    fn default() -> Self {
        // 1024x768 is the size every RDP server accepts without negotiation
        // and the one Windows falls back to; the interface overrides it with
        // the tab's real size on the first resize.
        Self {
            width: 1024,
            height: 768,
        }
    }
}

/// Everything the sequence needs that is not a credential or a socket.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Where the session is going. Used to name failures and to key the
    /// certificate trust store — never to open anything.
    pub target: HostPort,
    /// The account name, without a domain.
    pub username: String,
    /// The account's domain, empty for a local account.
    pub domain: String,
    /// This machine's name, as reported to the server.
    pub workstation: String,
    /// The desktop size to request.
    pub desktop: DesktopSize,
    /// The Windows keyboard layout identifier — `0x0409` for US English. The
    /// *server* applies the layout to the scancodes this client sends
    /// (MS-RDPBCGR §2.2.8.1.1.3.1.1.1), so this is what decides which glyph a
    /// physical key produces.
    pub keyboard_layout: u32,
    /// Whether to attempt Network Level Authentication. On by default;
    /// `docs/security/transport-security.md` says it should stay on, because
    /// without it credentials go to whatever answered the port.
    pub network_level_authentication: bool,
    /// A program to run instead of the shell (MS-RDPBCGR §2.2.1.11.1.1).
    pub alternate_shell: String,
    /// Its working directory.
    pub work_dir: String,
    /// How long the whole sequence gets.
    pub timeout: Duration,
    /// What may cross the clipboard. Decides whether the MS-RDPECLIP channel
    /// is requested at all — see [`static_channels`] — and travels on to the
    /// session in [`Connected::clipboard`].
    pub clipboard: ClipboardPolicy,
}

impl ConnectionConfig {
    /// A configuration for `target` with the documented defaults.
    #[must_use]
    pub fn new(target: HostPort, username: impl Into<String>) -> Self {
        Self {
            target,
            username: username.into(),
            domain: String::new(),
            workstation: "REMOTER".to_owned(),
            desktop: DesktopSize::default(),
            // US English. A layout the user actually has is set from the
            // connection's settings; this is only the fallback.
            keyboard_layout: 0x0000_0409,
            network_level_authentication: true,
            alternate_shell: String::new(),
            work_dir: String::new(),
            timeout: DEFAULT_TIMEOUT,
            // Text both ways, files never: `docs/security/transport-security.md`.
            clipboard: ClipboardPolicy::default(),
        }
    }

    /// The service principal name CredSSP asserts, `TERMSRV/<host>`.
    ///
    /// The host as the user typed it, because that is what the server compares
    /// against when SPN checking is on, and rewriting it here would produce a
    /// mismatch on exactly the hardened deployments that check.
    #[must_use]
    pub fn service_principal_name(&self) -> String {
        format!("TERMSRV/{}", self.target.host())
    }
}

/// What the sequence produced: a stream in the Active state, and the
/// identifiers everything afterwards is addressed with.
pub struct Connected {
    /// The stream, now inside TLS and past the Font Map PDU.
    pub stream: Framed,
    /// The MCS channel the graphics and input travel on.
    pub io_channel_id: u16,
    /// This client's MCS user channel.
    pub user_channel_id: u16,
    /// The message channel, where auto-detect and multitransport arrive.
    pub message_channel_id: Option<u16>,
    /// The share the server assigned.
    pub share_id: u32,
    /// The static virtual channels, with their negotiated ids attached.
    pub static_channels: StaticChannelSet,
    /// The desktop size the server actually gave, which may differ from the
    /// one requested.
    pub desktop: DesktopSize,
    /// The clipboard policy the connection was made with, for the session to
    /// enforce.
    pub clipboard: ClipboardPolicy,
}

impl core::fmt::Debug for Connected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Connected")
            .field("io_channel_id", &self.io_channel_id)
            .field("user_channel_id", &self.user_channel_id)
            .field("message_channel_id", &self.message_channel_id)
            .field("share_id", &self.share_id)
            .field("desktop", &self.desktop)
            .finish_non_exhaustive()
    }
}

/// Runs the whole connection sequence over an already-connected transport.
///
/// `channels` is the static virtual channel set to request — the caller builds
/// it so that the dynamic channel client, and therefore dynamic resize, is the
/// caller's decision rather than this module's.
///
/// # Errors
///
/// Any [`ProtocolError`] from the Handshake or Authenticate stages, plus
/// [`ProtocolError::Cancelled`] if the tab closed and
/// [`ProtocolError::ConnectTimeout`] if the budget ran out. Every failure
/// leaves nothing running: the stream is owned by the future and is dropped
/// with it.
#[allow(clippy::too_many_arguments, reason = "one argument per pipeline input")]
pub async fn connect(
    transport: Box<dyn remoter_proto::Transport>,
    config: &ConnectionConfig,
    creds: &dyn CredentialProvider,
    certificates: &CertificateChecker,
    channels: StaticChannelSet,
    events: &EventSink,
    prompts: Option<Arc<PromptChannel>>,
    cancel: &CancellationToken,
) -> Result<Connected, ProtocolError> {
    let stream = Framed::new(transport, config.target.clone());
    let sequence = run(
        stream,
        config,
        creds,
        certificates,
        channels,
        events,
        prompts.as_deref(),
    );
    with_deadline(
        cancel,
        config.timeout,
        &config.target,
        prompts.as_deref(),
        sequence,
    )
    .await
}

/// Races `future` against cancellation and a wall-clock budget.
///
/// The clock is suspended while a question is on screen. That is not a nicety:
/// `docs/security/transport-security.md` exists to make people compare a
/// certificate fingerprint out of band, and doing so takes longer than the
/// thirty seconds the taxonomy allows a *server* to answer in. A deadline that
/// counted the human would guarantee that the careful user times out and the
/// careless one does not.
///
/// # Errors
///
/// [`ProtocolError::Cancelled`] when the token fires,
/// [`ProtocolError::ConnectTimeout`] when the budget is spent, or whatever
/// `future` returned.
pub async fn with_deadline<F, T>(
    cancel: &CancellationToken,
    timeout: Duration,
    target: &HostPort,
    prompts: Option<&PromptChannel>,
    future: F,
) -> Result<T, ProtocolError>
where
    F: Future<Output = Result<T, ProtocolError>>,
{
    let mut future = core::pin::pin!(future);
    let mut remaining = timeout;
    loop {
        tokio::select! {
            // Biased so that a closed tab wins a race with a PDU that arrived
            // in the same wake-up: the tab is gone either way, and the socket
            // should close now rather than after one more round trip.
            biased;
            () = cancel.cancelled() => return Err(ProtocolError::Cancelled),
            outcome = &mut future => return outcome,
            () = tokio::time::sleep(TICK) => {
                if prompts.is_some_and(PromptChannel::awaiting_answer) {
                    continue;
                }
                remaining = remaining.saturating_sub(TICK);
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

/// The sequence itself, with no deadline of its own.
async fn run(
    mut stream: Framed,
    config: &ConnectionConfig,
    creds: &dyn CredentialProvider,
    certificates: &CertificateChecker,
    mut channels: StaticChannelSet,
    events: &EventSink,
    prompts: Option<&PromptChannel>,
) -> Result<Connected, ProtocolError> {
    // ── 1 · Connection Initiation, MS-RDPBCGR §2.2.1.1 ──────────────────────
    let requested = requested_protocols(config);
    let selected = initiate(&mut stream, config, requested).await?;

    // ── 2 · Enhanced RDP Security, MS-RDPBCGR §5.4.5.1 ──────────────────────
    // Standard RDP Security (RC4) is not implemented and will not be:
    // `docs/security/transport-security.md` rules it out. A server that
    // selected it has selected something this client cannot do.
    if selected.is_standard_rdp_security() {
        return Err(handshake_failed(
            "the server selected legacy RDP security, which Remoter does not implement",
        ));
    }
    let certificate = stream.upgrade_to_tls().await?;
    // Before a single byte of the connection sequence continues. A refusal
    // here drops the stream with the credentials still in the vault.
    certificates.check(&certificate).await?;

    // ── 3 · Network Level Authentication, MS-CSSP ───────────────────────────
    let hybrid =
        selected.intersects(nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX);
    if hybrid {
        let public_key = certificate.public_key(&config.target)?;
        network_level_authentication(
            &mut stream,
            config,
            creds,
            events,
            prompts,
            public_key,
            selected.contains(nego::SecurityProtocol::HYBRID_EX),
        )
        .await?;
    } else {
        tracing::debug!(
            target = %config.target,
            "connected with TLS only; the credentials will go in the Client Info PDU"
        );
    }

    // ── 4 · Basic Settings Exchange, MS-RDPBCGR §2.2.1.3–2.2.1.4 ────────────
    let blocks = client_gcc_blocks(config, selected, &channels);
    let connect_initial =
        mcs::ConnectInitial::with_gcc_blocks(blocks).map_err(|_| encode_failure())?;
    write_x224_data(&mut stream, &connect_initial).await?;

    // The Connect Response is an MCS PDU inside an X.224 Data PDU rather than
    // an X.224 PDU of its own, so it is unwrapped in two steps.
    let bytes = stream.read_x224_pdu().await?;
    let payload =
        ironrdp::core::decode::<X224<X224Data<'_>>>(&bytes).map_err(|_| decode_failure())?;
    let response = ironrdp::core::decode::<mcs::ConnectResponse>(payload.0.data.as_ref())
        .map_err(|_| decode_failure())?;
    let server = response.conference_create_response.into_gcc_blocks();
    let io_channel_id = server.network.io_channel;
    let message_channel_id = server
        .message_channel
        .as_ref()
        .map(|data| data.mcs_message_channel_id);

    // The server returns one channel id per requested channel, in the order
    // they were requested (MS-RDPBCGR §2.2.1.4.4). Pairing them by position is
    // the specification's own contract, not an assumption.
    let assigned: Vec<_> = channels
        .type_ids()
        .zip(server.network.channel_ids.iter().copied())
        .collect();
    for (type_id, channel_id) in assigned {
        channels.attach_channel_id(type_id, channel_id);
    }

    // ── 5 · Channel Connection, MS-RDPBCGR §2.2.1.5–2.2.1.9 ─────────────────
    let skip_joins = server
        .core
        .optional_data
        .early_capability_flags
        .is_some_and(|flags| {
            flags.contains(gcc::ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED)
        });
    let mut to_join = server.network.channel_ids.clone();
    to_join.push(io_channel_id);
    to_join.extend(message_channel_id);
    let user_channel_id =
        join_channels(&mut stream, if skip_joins { None } else { Some(to_join) }).await?;

    // ── 6 · Secure Settings Exchange, MS-RDPBCGR §2.2.1.11 ──────────────────
    send_client_info(
        &mut stream,
        config,
        creds,
        user_channel_id,
        io_channel_id,
        hybrid,
    )
    .await?;

    // ── 7 · Licensing, MS-RDPELE §3.1.5.3.1 ─────────────────────────────────
    let pending = licensing(
        &mut stream,
        config,
        user_channel_id,
        io_channel_id,
        message_channel_id,
    )
    .await?;

    // ── 8 · Capabilities Exchange, MS-RDPBCGR §2.2.1.13 ─────────────────────
    // No deadline of their own: `with_deadline` already bounds this whole
    // sequence from the outside, and a second clock inside it would silently
    // override the timeout the connection was configured with. The
    // *reactivation* path has no such outer bound and supplies one; see
    // `reactivate`.
    let (share_id, desktop) = capabilities_exchange(
        &mut stream,
        config,
        user_channel_id,
        io_channel_id,
        pending,
        None,
    )
    .await?;

    // ── 9 · Connection Finalization, MS-RDPBCGR §2.2.1.14–2.2.1.19 ──────────
    finalize(
        &mut stream,
        user_channel_id,
        io_channel_id,
        share_id,
        desktop,
        None,
    )
    .await?;

    tracing::info!(
        target = %config.target,
        width = desktop.width,
        height = desktop.height,
        nla = hybrid,
        "the RDP connection sequence completed"
    );

    Ok(Connected {
        stream,
        io_channel_id,
        user_channel_id,
        message_channel_id,
        share_id,
        static_channels: channels,
        desktop,
        clipboard: config.clipboard,
    })
}

/// What the client asks for in the X.224 Connection Request.
///
/// `PROTOCOL_SSL` is deliberately **not** set alongside the hybrid flags when
/// NLA is on. MS-RDPBCGR §2.2.1.1 says it "SHOULD" also be set, not "MUST",
/// and omitting it tells the server the client will not accept being
/// downgraded from Network Level Authentication to bare TLS — which is the
/// downgrade that puts the password on the far side of an unauthenticated
/// tunnel.
#[must_use]
pub fn requested_protocols(config: &ConnectionConfig) -> nego::SecurityProtocol {
    if config.network_level_authentication {
        nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX
    } else {
        nego::SecurityProtocol::SSL
    }
}

/// Steps 1 and 2 of MS-RDPBCGR §1.3.1.1.
async fn initiate(
    stream: &mut Framed,
    config: &ConnectionConfig,
    requested: nego::SecurityProtocol,
) -> Result<nego::SecurityProtocol, ProtocolError> {
    let request = nego::ConnectionRequest {
        // The routing cookie a load balancer reads to send a reconnecting user
        // back to the host holding their session. It is the `cookie` field of
        // the X.224 Connection Request PDU, MS-RDPBCGR §2.2.1.1 — the citation
        // here read §2.2.1.1.1, which is the RDP Negotiation Request that sits
        // *beside* the cookie and says nothing about it.
        // Carrying the user name is what every client does and what makes
        // session reconnection work behind a Connection Broker.
        nego_data: (!config.username.is_empty())
            .then(|| nego::NegoRequestData::cookie(config.username.clone())),
        flags: nego::RequestFlags::empty(),
        protocol: requested,
    };
    let encoded = encode_vec(&X224(request)).map_err(|_| encode_failure())?;
    stream.write_all(&encoded).await?;

    let confirm = read_x224::<nego::ConnectionConfirm>(stream).await?;
    match confirm {
        nego::ConnectionConfirm::Response { protocol, flags } => {
            tracing::debug!(?protocol, ?flags, "the server confirmed the connection");
            if !protocol.intersects(requested) && !protocol.is_standard_rdp_security() {
                // The server selected something that was never offered.
                // Continuing would mean speaking a protocol this client did
                // not agree to.
                return Err(handshake_failed(
                    "the server selected a security protocol the client did not offer",
                ));
            }
            Ok(protocol)
        }
        // MS-RDPBCGR §2.2.1.2.2. Each code is a different configuration
        // disagreement with a different answer; see `error::map_negotiation_failure`.
        nego::ConnectionConfirm::Failure { code } => Err(map_negotiation_failure(u32::from(code))),
    }
}

/// Step 3: CredSSP inside the tunnel.
async fn network_level_authentication(
    stream: &mut Framed,
    config: &ConnectionConfig,
    creds: &dyn CredentialProvider,
    events: &EventSink,
    prompts: Option<&PromptChannel>,
    public_key: Vec<u8>,
    hybrid_ex: bool,
) -> Result<(), ProtocolError> {
    let password = borrow_password(creds, config, events, prompts).await?;

    let mut nonce = [0u8; 32];
    let mut client_challenge = [0u8; 8];
    let mut session_key = [0u8; 16];
    fill_random(&mut nonce)?;
    fill_random(&mut client_challenge)?;
    fill_random(&mut session_key)?;

    let mut client = CredsspClient::new(
        &config.username,
        &config.domain,
        &config.workstation,
        &config.service_principal_name(),
        &password,
        public_key,
        nonce,
    );
    // Used and immediately dropped, as the pipeline requires: the client now
    // holds what it needs and this buffer zeroes itself here rather than at
    // the end of the function.
    drop(password);

    stream.write_all(&client.start()).await?;
    loop {
        let message = stream.read_pdu(credssp::ts_request_length).await?;
        match client.step(&message, client_challenge, session_key, now_filetime())? {
            Step::SendAndContinue(bytes) => stream.write_all(&bytes).await?,
            Step::SendAndFinish(bytes) => {
                stream.write_all(&bytes).await?;
                break;
            }
        }
    }
    client_challenge.zeroize();
    session_key.zeroize();
    drop(client);

    if hybrid_ex {
        // MS-RDPBCGR §5.4.5.2: with PROTOCOL_HYBRID_EX the server reports
        // whether the authenticated user may actually log on here, before the
        // connection sequence continues. It is four bytes with no header.
        let result = stream
            .read_exact(credssp::EARLY_USER_AUTH_RESULT_BYTES)
            .await?;
        credssp::check_early_user_auth_result(&result)?;
    }
    tracing::debug!(target = %config.target, "network level authentication succeeded");
    Ok(())
}

/// Borrows the password, prompting for one if the vault resolved none.
async fn borrow_password(
    creds: &dyn CredentialProvider,
    config: &ConnectionConfig,
    events: &EventSink,
    prompts: Option<&PromptChannel>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtocolError> {
    use remoter_proto::CredentialProviderExt as _;

    if let Some(password) =
        creds.with_password(&mut |bytes| zeroize::Zeroizing::new(bytes.to_vec()))
    {
        return Ok(password);
    }
    let Some(prompts) = prompts else {
        return Err(ProtocolError::CredentialRequired {
            target: config.target.clone(),
        });
    };
    prompts
        .ask(
            events,
            remoter_proto::PromptKind::Password,
            config.target.to_string(),
            // Never echoed. The interface honours this flag, and a password
            // echoed into a screen recording is a password in the recording.
            false,
        )
        .await
}

/// Steps 5: Erect Domain, Attach User, and the channel joins.
///
/// `to_join` is `None` when the server advertised
/// `SKIP_CHANNELJOIN_SUPPORTED` (MS-RDPBCGR §2.2.1.4.2), which lets a modern
/// Windows host skip a round trip per channel.
async fn join_channels(
    stream: &mut Framed,
    to_join: Option<Vec<u16>>,
) -> Result<u16, ProtocolError> {
    // §2.2.1.5. `sub_height` and `sub_interval` are zero for a client, which
    // is the only value MS-RDPBCGR permits.
    let erect = encode_vec(&X224(mcs::ErectDomainPdu {
        sub_height: 0,
        sub_interval: 0,
    }))
    .map_err(|_| encode_failure())?;
    // §2.2.1.6.
    let attach = encode_vec(&X224(mcs::AttachUserRequest)).map_err(|_| encode_failure())?;
    let mut batch = erect;
    batch.extend_from_slice(&attach);
    stream.write_all(&batch).await?;

    // §2.2.1.7. The `result` field is an MCS Result (T.125 §7), and only
    // rt-successful means a user was attached: on a refusal the `initiator_id`
    // beside it is not a channel this client owns. Reading the id without
    // reading the result is how a refusal becomes a session that continues on
    // a user channel the server declined — every later PDU addressed to
    // nobody, and the failure surfacing far from its cause.
    let confirm = read_x224::<mcs::AttachUserConfirm>(stream).await?;
    if confirm.result != MCS_RT_SUCCESSFUL {
        tracing::warn!(
            result = confirm.result,
            reason = mcs_result_name(confirm.result),
            "the server refused to attach an MCS user"
        );
        return Err(handshake_failed(
            "the server refused to attach this client to its MCS domain",
        ));
    }
    let user_channel_id = confirm.initiator_id;

    let Some(mut to_join) = to_join else {
        tracing::debug!(
            user_channel_id,
            "the server allows the channel joins to be skipped"
        );
        return Ok(user_channel_id);
    };

    // The user channel must be joined too (§2.2.1.8). Duplicates are removed
    // because a server that lists the I/O channel in `channel_ids` as well
    // would otherwise have a join sent twice and one confirm left unmatched.
    to_join.push(user_channel_id);
    to_join.sort_unstable();
    to_join.dedup();

    // Sent as one batch, which is what an RDP 8.1 and later client does to
    // save a round trip per channel (MS-RDPBCGR §3.2.5.3.8).
    let mut batch = Vec::new();
    for channel_id in &to_join {
        let request = mcs::ChannelJoinRequest {
            initiator_id: user_channel_id,
            channel_id: *channel_id,
        };
        batch.extend_from_slice(&encode_vec(&X224(request)).map_err(|_| encode_failure())?);
    }
    stream.write_all(&batch).await?;

    // §2.2.1.9, one confirm per request, in any order.
    let mut remaining = to_join;
    while !remaining.is_empty() {
        let confirm = read_x224::<mcs::ChannelJoinConfirm>(stream).await?;
        // Before anything else is read out of this PDU. `result` is an MCS
        // Result (T.125 §7): on anything but rt-successful the join did *not*
        // happen, and T.125 makes the joined `channelId` optional in that
        // case, so the comparison below would be comparing against a field the
        // server never filled in. Skipping this check let a T.125 refusal read
        // as success — the session then ran on a channel the server had
        // declined, which is a silent black screen rather than a message.
        if confirm.result != MCS_RT_SUCCESSFUL {
            tracing::warn!(
                channel_id = confirm.requested_channel_id,
                result = confirm.result,
                reason = mcs_result_name(confirm.result),
                "the server refused a channel join"
            );
            return Err(if confirm.requested_channel_id == user_channel_id {
                handshake_failed("the server refused to join this client's own MCS user channel")
            } else {
                handshake_failed("the server refused to join a channel this connection asked for")
            });
        }
        if confirm.requested_channel_id != confirm.channel_id {
            // The server joined a channel other than the one asked for. The
            // ids are how every later PDU is addressed, so proceeding would
            // send graphics to a channel nobody is listening on.
            return Err(violation(
                "the server joined a different channel than the one requested",
            ));
        }
        let before = remaining.len();
        remaining.retain(|id| *id != confirm.requested_channel_id);
        if remaining.len() == before {
            return Err(violation(
                "the server confirmed a channel that was not requested",
            ));
        }
    }
    Ok(user_channel_id)
}

/// Step 6: the Client Info PDU. MS-RDPBCGR §2.2.1.11.
async fn send_client_info(
    stream: &mut Framed,
    config: &ConnectionConfig,
    creds: &dyn CredentialProvider,
    user_channel_id: u16,
    io_channel_id: u16,
    nla_used: bool,
) -> Result<(), ProtocolError> {
    use rdp::client_info::{
        AddressFamily, ClientInfo, ClientInfoFlags, CompressionType, Credentials,
        ExtendedClientInfo, ExtendedClientOptionalInfo,
    };
    use rdp::headers::{BasicSecurityHeader, BasicSecurityHeaderFlags};

    let mut flags = ClientInfoFlags::MOUSE
        | ClientInfoFlags::MOUSE_HAS_WHEEL
        | ClientInfoFlags::UNICODE
        | ClientInfoFlags::DISABLE_CTRL_ALT_DEL
        | ClientInfoFlags::LOGON_NOTIFY
        | ClientInfoFlags::LOGON_ERRORS
        | ClientInfoFlags::ENABLE_WINDOWS_KEY
        | ClientInfoFlags::MAXIMIZE_SHELL
        // Audio redirection is not implemented (`capabilities()` says so), and
        // asking for it would make the server encode and send a stream nothing
        // decodes.
        | ClientInfoFlags::NO_AUDIO_PLAYBACK
        | ClientInfoFlags::VIDEO_DISABLE
        | ClientInfoFlags::AUTOLOGON;

    // With NLA the server already holds the credentials: CredSSP delegated
    // them, and repeating them here would put the password in a second place
    // on the wire for no benefit. Without NLA this field *is* the single
    // sign-on, so it carries the password and is zeroized immediately after
    // the PDU is encoded.
    let mut password = String::new();
    if !nla_used {
        use remoter_proto::CredentialProviderExt as _;
        if let Some(borrowed) =
            creds.with_password(&mut |bytes| String::from_utf8_lossy(bytes).into_owned())
        {
            password = borrowed;
        }
        if password.is_empty() {
            // Nothing to log in with; the user gets the remote login screen
            // rather than a failure, which is the useful outcome.
            flags.remove(ClientInfoFlags::AUTOLOGON);
        }
    }

    let pdu = rdp::ClientInfoPdu {
        security_header: BasicSecurityHeader {
            flags: BasicSecurityHeaderFlags::INFO_PKT,
        },
        client_info: ClientInfo {
            credentials: Credentials {
                username: config.username.clone(),
                password,
                domain: (!config.domain.is_empty()).then(|| config.domain.clone()),
            },
            // Ignored because the Client Core Data sets a keyboard layout.
            code_page: 0,
            flags,
            // Bulk compression is not negotiated: the flags above do not set
            // `ClientInfoFlags::COMPRESSION`, so this value is ignored.
            compression_type: CompressionType::K8,
            alternate_shell: config.alternate_shell.clone(),
            work_dir: config.work_dir.clone(),
            extra_info: ExtendedClientInfo {
                // The client's own address. Reported as a loopback literal
                // rather than the machine's real one: the server only logs it,
                // and a connection manager should not volunteer the operator's
                // internal address to every host they connect to.
                address_family: AddressFamily::INET,
                address: "127.0.0.1".to_owned(),
                dir: String::new(),
                optional_data: ExtendedClientOptionalInfo::builder()
                    .timezone(rdp::client_info::TimezoneInfo::default())
                    .session_id(0)
                    .performance_flags(performance_flags())
                    .build(),
            },
        },
    };

    // `ClientInfo` holds the password in a plain `String`, so it is wiped the
    // moment the encoded bytes exist — before the write, and on the encode
    // failure path too. The encoded buffer carries the same password in
    // UTF-16LE and is wiped after the write, again on both paths.
    let mut pdu = pdu;
    let encoded = send_data_request(user_channel_id, io_channel_id, &pdu);
    pdu.client_info.credentials.password.zeroize();
    drop(pdu);

    let mut encoded = encoded?;
    let outcome = stream.write_all(&encoded).await;
    encoded.zeroize();
    outcome
}

/// Performance flags: everything expensive off.
///
/// A connection manager is used over links that are not a LAN, and the visual
/// effects below cost bandwidth for nothing a system administrator wants. They
/// are advisory — the server may ignore them — and they are set here rather
/// than exposed as settings because the first RDP milestone has no place to
/// put them; `docs/roadmap.md` is the scope.
fn performance_flags() -> rdp::client_info::PerformanceFlags {
    use rdp::client_info::PerformanceFlags;
    PerformanceFlags::DISABLE_WALLPAPER
        | PerformanceFlags::DISABLE_FULLWINDOWDRAG
        | PerformanceFlags::DISABLE_MENUANIMATIONS
        | PerformanceFlags::DISABLE_THEMING
        | PerformanceFlags::DISABLE_CURSOR_SHADOW
        | PerformanceFlags::DISABLE_CURSORSETTINGS
}

/// Step 7: licensing. MS-RDPELE §3.1.5.3.1, the client state transition.
///
/// The common case by far is the first PDU being a licensing error message
/// with `STATUS_VALID_CLIENT`, which is how a host in Remote Desktop for
/// Administration mode says "no licence needed". A real Remote Desktop Session
/// Host runs the full exchange, and both are handled — but nothing is cached,
/// so a licensed host issues a new licence on every connection rather than
/// upgrading a stored one. That is correct and wasteful; a licence cache is a
/// vault change and belongs with one.
async fn licensing(
    stream: &mut Framed,
    config: &ConnectionConfig,
    user_channel_id: u16,
    io_channel_id: u16,
    message_channel_id: Option<u16>,
) -> Result<Option<bytes::BytesMut>, ProtocolError> {
    use rdp::server_license::{
        ClientNewLicenseRequest, ClientPlatformChallengeResponse, LicenseEncryptionData,
        LicenseErrorCode, LicensePdu, PREMASTER_SECRET_SIZE, RANDOM_NUMBER_SIZE,
    };

    // A hardware identifier the server records against the licence. Zero is
    // what a client with no platform identity sends, and volunteering a real
    // machine identifier to every host would be a fingerprint the user did not
    // agree to hand over.
    let hardware_id = [0u32; 4];
    let mut encryption: Option<LicenseEncryptionData> = None;

    loop {
        let pdu = stream.read_x224_pdu().await?;
        let indication = mcs::decode_send_data_indication(&pdu).map_err(|_| decode_failure())?;

        // The server may run connect-time auto-detection on the message
        // channel before licensing (MS-RDPBCGR §1.3.8). Those PDUs are not
        // licensing PDUs and must not be decoded as ones; they are answered
        // where an answer is defined and otherwise ignored.
        if Some(indication.channel_id) == message_channel_id {
            answer_autodetect(stream, &indication, user_channel_id).await?;
            continue;
        }

        // A server with nothing to license can go straight to the Demand
        // Active PDU. Decoding that as a licensing PDU would fail with a
        // message about licensing, several steps from the truth — so a PDU
        // that is not one is handed back for the capability exchange to read.
        let Ok(license) = indication.decode_user_data::<LicensePdu>() else {
            tracing::debug!(
                "the server sent no licensing PDU; continuing to the capability exchange"
            );
            return Ok(Some(pdu));
        };

        match license {
            LicensePdu::LicensingErrorMessage(message) => {
                if message.error_code == LicenseErrorCode::StatusValidClient {
                    tracing::debug!(target = %config.target, "licensing completed");
                    return Ok(None);
                }
                // A licensing failure is a server-side configuration problem —
                // no licences left, no licence server reachable — and the user
                // cannot fix it by retyping a password.
                tracing::warn!(code = ?message.error_code, "the server refused the licence request");
                return Err(handshake_failed(
                    "the server's Remote Desktop licensing refused this connection",
                ));
            }

            LicensePdu::ServerLicenseRequest(request) => {
                let mut client_random = [0u8; RANDOM_NUMBER_SIZE];
                let mut premaster = [0u8; PREMASTER_SECRET_SIZE];
                fill_random(&mut client_random)?;
                fill_random(&mut premaster)?;

                let (response, data) = ClientNewLicenseRequest::from_server_license_request(
                    &request,
                    &client_random,
                    &premaster,
                    &config.username,
                    &config.workstation,
                )
                .map_err(|_| {
                    handshake_failed("the server's licence request could not be answered")
                })?;
                premaster.zeroize();
                client_random.zeroize();

                encryption = Some(data);
                let pdu: LicensePdu = response.into();
                let encoded = send_data_request(user_channel_id, io_channel_id, &pdu)?;
                stream.write_all(&encoded).await?;
            }

            LicensePdu::ServerPlatformChallenge(challenge) => {
                let data = encryption.as_ref().ok_or_else(|| {
                    violation("the server sent a platform challenge before a licence request")
                })?;
                let response = ClientPlatformChallengeResponse::from_server_platform_challenge(
                    &challenge,
                    hardware_id,
                    data,
                )
                .map_err(|_| {
                    handshake_failed("the server's platform challenge could not be answered")
                })?;
                let pdu: LicensePdu = response.into();
                let encoded = send_data_request(user_channel_id, io_channel_id, &pdu)?;
                stream.write_all(&encoded).await?;
            }

            LicensePdu::ServerUpgradeLicense(upgrade) => {
                let data = encryption.as_ref().ok_or_else(|| {
                    violation("the server sent a licence before a licence request")
                })?;
                // The MAC over the licence is checked even though the licence
                // itself is discarded: a licence that does not verify means
                // the exchange was tampered with, and continuing anyway would
                // make the check decorative.
                upgrade
                    .verify_server_license(data)
                    .map_err(|_| violation("the server's licence failed its integrity check"))?;
                tracing::debug!("a new licence was issued and, with no cache, discarded");
                return Ok(None);
            }

            other => {
                tracing::debug!(?other, "an unexpected licensing PDU");
                return Err(violation("the server sent an unexpected licensing PDU"));
            }
        }
    }
}

/// Answers a connect-time Auto-Detect Request. MS-RDPBCGR §2.2.14.
///
/// Only the round-trip-time request is answered. The bandwidth measurement is
/// informational and the server proceeds to licensing whether or not it gets
/// one, so skipping it costs a latency estimate and stalls nothing.
///
/// This is only the *connect-time* phase. Once the session is active,
/// `ironrdp-session` answers round-trip-time requests itself and surfaces only
/// the network-characteristics result.
async fn answer_autodetect(
    stream: &mut Framed,
    indication: &mcs::SendDataIndicationCtx<'_>,
    user_channel_id: u16,
) -> Result<(), ProtocolError> {
    use rdp::autodetect::{
        AutoDetectReqPdu, AutoDetectRequest, AutoDetectResponse, AutoDetectRspPdu,
    };

    let Ok(request) = ironrdp::core::decode::<AutoDetectReqPdu>(indication.user_data) else {
        // Multitransport bootstrapping and heartbeat also arrive here and are
        // not this phase's business. Ignored rather than refused: the server
        // does not wait for an answer to either.
        return Ok(());
    };
    if let AutoDetectRequest::RttRequest {
        sequence_number, ..
    } = request.request
    {
        let response = AutoDetectRspPdu::new(AutoDetectResponse::RttResponse { sequence_number });
        let encoded = send_data_request(user_channel_id, indication.channel_id, &response)?;
        stream.write_all(&encoded).await?;
    }
    Ok(())
}

/// Re-runs the capability exchange and finalization on a live connection.
///
/// The Deactivation-Reactivation Sequence of MS-RDPBCGR §1.3.1.3: the server
/// sent a Deactivate All PDU, the share is gone, and steps 8 and 9 run again
/// over the same stream to establish a new one. This is what happens when the
/// server changes its own desktop size — including in response to the client's
/// own MS-RDPEDISP resize request — so it is not an error path.
///
/// Only `config.desktop` is read, as the fallback for a server that sends no
/// bitmap capability set; the rest of the connection is already established.
///
/// # This sequence is bounded, and the initial one is bounded elsewhere
///
/// [`connect()`] runs inside [`with_deadline`]; this does not, and for a while
/// nothing replaced it. A server that sent a Deactivate All and then simply
/// stopped — or sent Deactivate All for ever — held the session's read loop,
/// its task and its socket open indefinitely, with a tab that never painted
/// and never failed. Two bounds close that: every read below must complete
/// within `config.timeout` of entering this function ([`DEFAULT_TIMEOUT`]
/// unless the connection set its own), and at most [`MAX_DEACTIVATIONS`]
/// Deactivate All PDUs may arrive before the Demand Active.
///
/// The clock is applied to the reads one at a time rather than around the
/// whole call on purpose. Abandoning a read costs nothing — [`Framed`] keeps
/// what already arrived — while abandoning the call could drop a half-written
/// Confirm Active and leave a truncated PDU on the stream.
///
/// # Errors
///
/// As the connection sequence: a malformed PDU is a protocol violation, and a
/// server that sends something other than a Demand Active is refused. A server
/// that sends nothing, or nothing but Deactivate All PDUs, is a violation too:
/// §1.3.1.3 requires a Demand Active to follow.
pub async fn reactivate(
    stream: &mut Framed,
    config: &ConnectionConfig,
    user_channel_id: u16,
    io_channel_id: u16,
) -> Result<(u32, DesktopSize), ProtocolError> {
    // One deadline for the whole sequence, not one per read: a server that
    // answered each read a tick before its budget could otherwise stall the
    // session for as long as it liked. The budget is the connection's own
    // `timeout` — the same number that bounded the initial sequence, because
    // it answers the same question: how long this server may take to answer
    // before the user is told it is not answering.
    let deadline = Some(tokio::time::Instant::now() + config.timeout);
    let (share_id, desktop) = capabilities_exchange(
        stream,
        config,
        user_channel_id,
        io_channel_id,
        None,
        deadline,
    )
    .await?;
    finalize(
        stream,
        user_channel_id,
        io_channel_id,
        share_id,
        desktop,
        deadline,
    )
    .await?;
    Ok((share_id, desktop))
}

/// Reads one X.224-framed PDU, giving up at `deadline` when there is one.
///
/// Only the *read* is raced. A read abandoned mid-PDU loses nothing — the
/// bytes are in [`Framed`]'s buffer and the next read resumes from them — and
/// that is what makes bounding the read the right place to bound a phase that
/// also writes.
///
/// `None` is the initial connection sequence, which is bounded from the
/// outside by [`with_deadline`] and must not be bounded twice: two clocks on
/// one sequence means the shorter one silently wins and the configured timeout
/// stops meaning what it says.
async fn read_x224_pdu_by(
    stream: &mut Framed,
    deadline: Option<tokio::time::Instant>,
) -> Result<bytes::BytesMut, ProtocolError> {
    let Some(deadline) = deadline else {
        return stream.read_x224_pdu().await;
    };
    match tokio::time::timeout_at(deadline, stream.read_x224_pdu()).await {
        Ok(outcome) => outcome,
        // MS-RDPBCGR §1.3.1.3 makes the Demand Active the server's obligation
        // after a Deactivate All. Not sending one is a breach of the sequence,
        // not a network problem, and saying so puts the defect on the server
        // rather than on the user's link.
        Err(_) => Err(violation(
            "the server did not finish the deactivation-reactivation sequence in time",
        )),
    }
}

/// Step 8: Demand Active in, Confirm Active out. MS-RDPBCGR §2.2.1.13.
///
/// `deadline` bounds the reads when this runs as part of a reactivation; see
/// [`reactivate`]. The initial sequence passes `None` because [`with_deadline`]
/// already bounds it from the outside.
async fn capabilities_exchange(
    stream: &mut Framed,
    config: &ConnectionConfig,
    user_channel_id: u16,
    io_channel_id: u16,
    mut pending: Option<bytes::BytesMut>,
    deadline: Option<tokio::time::Instant>,
) -> Result<(u32, DesktopSize), ProtocolError> {
    let mut deactivations = 0usize;
    loop {
        // `pending` is the PDU the licensing phase read and found was not a
        // licensing PDU. It is consumed once; every later iteration reads.
        let pdu = match pending.take() {
            Some(pdu) => pdu,
            None => read_x224_pdu_by(stream, deadline).await?,
        };
        let indication = mcs::decode_send_data_indication(&pdu).map_err(|_| decode_failure())?;
        let control =
            rdp::headers::decode_share_control(indication).map_err(|_| decode_failure())?;

        match control.pdu {
            // Some servers — Windows Server and gnome-remote-desktop both do
            // it — send a Deactivate All before the first Demand Active, as
            // the Deactivation-Reactivation Sequence of §1.3.1.3. It carries
            // nothing this phase needs; the next PDU is the real one.
            //
            // Counted, because "the next PDU is the real one" is the server's
            // obligation and not something this loop can assume: an unbounded
            // `continue` here is a read loop a server can hold open by sending
            // Deactivate All and nothing else.
            ShareControlPdu::ServerDeactivateAll(_) => {
                deactivations += 1;
                if deactivations > MAX_DEACTIVATIONS {
                    tracing::warn!(
                        deactivations,
                        "the server sent Deactivate All PDUs without ever demanding active"
                    );
                    return Err(violation(
                        "the server deactivated the share repeatedly without demanding active",
                    ));
                }
                continue;
            }

            ShareControlPdu::ServerDemandActive(demand) => {
                let capabilities = demand.pdu.capability_sets;
                // The size the server actually chose. It answers the request
                // made in the Client Core Data and may differ from it, and the
                // rest of the session is in *these* coordinates — a client
                // that keeps its own number draws the desktop at the wrong
                // scale and puts every mouse click in the wrong place.
                let desktop = capabilities
                    .iter()
                    .find_map(|set| match set {
                        CapabilitySet::Bitmap(bitmap) => Some(DesktopSize {
                            width: bitmap.desktop_width,
                            height: bitmap.desktop_height,
                        }),
                        _ => None,
                    })
                    .unwrap_or(config.desktop);

                let confirm = ShareControlPdu::ClientConfirmActive(client_confirm_active(
                    capabilities,
                    desktop,
                ));
                let mut buffer = ironrdp::core::WriteBuf::new();
                rdp::headers::encode_share_control(
                    user_channel_id,
                    io_channel_id,
                    control.share_id,
                    confirm,
                    &mut buffer,
                )
                .map_err(|_| encode_failure())?;
                stream.write_all(buffer.filled()).await?;
                return Ok((control.share_id, desktop));
            }

            other => {
                tracing::debug!(
                    pdu = other.as_short_name(),
                    "an unexpected PDU during capabilities exchange"
                );
                return Err(violation(
                    "the server sent something other than a Demand Active PDU",
                ));
            }
        }
    }
}

/// Step 9: Synchronize, Control (Cooperate), Control (Request Control), Font
/// List; then wait for the server's Font Map. MS-RDPBCGR §2.2.1.14–2.2.1.19.
///
/// The four client PDUs go out in one write without waiting for a reply to
/// each, which is what §1.3.1.1 permits and what saves three round trips on a
/// high-latency link.
///
/// `deadline` bounds the reads when this runs as part of a reactivation; see
/// [`reactivate`]. The initial sequence passes `None` because [`with_deadline`]
/// already bounds it from the outside.
async fn finalize(
    stream: &mut Framed,
    user_channel_id: u16,
    io_channel_id: u16,
    share_id: u32,
    desktop: DesktopSize,
    deadline: Option<tokio::time::Instant>,
) -> Result<(), ProtocolError> {
    use rdp::finalization_messages::{ControlAction, ControlPdu, FontPdu, SynchronizePdu};

    let messages = [
        ShareDataPdu::Synchronize(SynchronizePdu {
            target_user_id: user_channel_id,
        }),
        ShareDataPdu::Control(ControlPdu {
            action: ControlAction::Cooperate,
            grant_id: 0,
            control_id: 0,
        }),
        ShareDataPdu::Control(ControlPdu {
            action: ControlAction::RequestControl,
            grant_id: 0,
            control_id: 0,
        }),
        ShareDataPdu::FontList(FontPdu::default()),
    ];

    let mut buffer = ironrdp::core::WriteBuf::new();
    for message in messages {
        rdp::headers::encode_share_data(
            user_channel_id,
            io_channel_id,
            share_id,
            message,
            &mut buffer,
        )
        .map_err(|_| encode_failure())?;
    }
    stream.write_all(buffer.filled()).await?;

    loop {
        let pdu = read_x224_pdu_by(stream, deadline).await?;
        let indication = mcs::decode_send_data_indication(&pdu).map_err(|_| decode_failure())?;
        let data = rdp::headers::decode_share_data(indication).map_err(|_| decode_failure())?;

        match data.pdu {
            // §2.2.1.19: once the Font Map arrives the connection is active
            // and the server may start sending graphics.
            ShareDataPdu::FontMap(_) => {
                // Ask for the whole desktop, once. The server may have started
                // drawing before the sequence ended — it is allowed to from the
                // moment it has the Font List PDU — and those fast-path frames
                // were discarded by `Framed::read_x224_pdu`. Without this the
                // first thing the user sees is whatever happens to change next,
                // which on an idle login screen is a blinking caret on black.
                // MS-RDPBCGR §2.2.11.2.
                refresh(stream, user_channel_id, io_channel_id, share_id, desktop).await?;
                return Ok(());
            }
            ShareDataPdu::Synchronize(_) | ShareDataPdu::Control(_) => {}
            ShareDataPdu::ServerSetErrorInfo(rdp::server_error_info::ServerSetErrorInfoPdu(
                info,
            )) => {
                use rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode};
                if matches!(
                    info,
                    ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::None)
                ) {
                    continue;
                }
                // The server explaining why it is about to close the
                // connection. `description` is Microsoft's own text for a
                // fixed code, not peer-supplied free text.
                tracing::warn!(
                    reason = info.description(),
                    "the server reported an error during finalization"
                );
                return Err(ProtocolError::Disconnected {
                    reason: info.description(),
                });
            }
            other => {
                tracing::debug!(pdu = ?other, "an unexpected PDU during finalization");
            }
        }
    }
}

/// Asks the server to redraw a region. MS-RDPBCGR §2.2.11.2.
///
/// Best-effort: a server that ignores it leaves the client with whatever it
/// already had, which is the same position as not sending one.
async fn refresh(
    stream: &mut Framed,
    user_channel_id: u16,
    io_channel_id: u16,
    share_id: u32,
    desktop: DesktopSize,
) -> Result<(), ProtocolError> {
    use ironrdp::pdu::geometry::InclusiveRectangle;
    use rdp::refresh_rectangle::RefreshRectanglePdu;

    // Inclusive on both edges, so the far corner is one less than the size.
    let area = InclusiveRectangle {
        left: 0,
        top: 0,
        right: desktop.width.saturating_sub(1),
        bottom: desktop.height.saturating_sub(1),
    };
    let mut buffer = ironrdp::core::WriteBuf::new();
    rdp::headers::encode_share_data(
        user_channel_id,
        io_channel_id,
        share_id,
        ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
            areas_to_refresh: vec![area],
        }),
        &mut buffer,
    )
    .map_err(|_| encode_failure())?;
    stream.write_all(buffer.filled()).await
}

/// The Client Confirm Active PDU's capability sets. MS-RDPBCGR §2.2.1.13.2.
///
/// The server's own Multifragment Update capability is echoed back, but never
/// above [`MAX_FASTPATH_REASSEMBLY_BYTES`]: §2.2.7.2.6's `MaxRequestSize` is,
/// on the client's side, the size of the buffer *this process* reassembles a
/// fragmented Fast-Path Update into, so echoing the server's figure unaltered
/// let the far end name it. Everything else here is the client's declaration of
/// what it can decode. Three of them decide what a modern Windows Server
/// actually sends:
///
/// - **Surface Commands** (§2.2.7.2.9) with `SET_SURFACE_BITS` is what enables
///   the surface-bits path, which is how RemoteFX and the uncompressed 32bpp
///   codec arrive. Without it the server falls back to the bitmap update path
///   of §2.2.9.1.1.3.1.2 and colour fidelity drops.
/// - **Bitmap Codecs** (MS-RDPRFX §2.2.1.1) advertises RemoteFX, which is what
///   a Windows Server negotiates by preference on anything but the slowest
///   link.
/// - **Bitmap** with `desktop_resize_flag` is required before the server will
///   accept a dynamic resize at all, which is what makes MS-RDPEDISP work.
fn client_confirm_active(
    server_capabilities: Vec<CapabilitySet>,
    desktop: DesktopSize,
) -> rdp::capability_sets::ClientConfirmActive {
    use rdp::capability_sets::{
        BITMAP_CACHE_ENTRIES_NUM, Bitmap, BitmapCache, BitmapDrawingFlags, Brush, CacheDefinition,
        CacheEntry, ClientConfirmActive, CmdFlags, DemandActive, FrameAcknowledge, GLYPH_CACHE_NUM,
        General, GeneralExtraFlags, GlyphCache, GlyphSupportLevel, Input, InputFlags, LargePointer,
        LargePointerSupportFlags, MultifragmentUpdate, OffscreenBitmapCache, Order, OrderFlags,
        OrderSupportExFlags, Pointer, SERVER_CHANNEL_ID, Sound, SoundFlags, SupportLevel,
        SurfaceCommands, VirtualChannel, VirtualChannelFlags, client_codecs_capabilities,
    };

    // Only the server's multifragment capability survives; the rest of what it
    // sent is its side of the negotiation, not ours.
    //
    // It survives *clamped*, and that is not tidying. §2.2.7.2.6's
    // `MaxRequestSize` is, for the client, the size of the buffer used to
    // reassemble a fragmented Fast-Path Update — this process's buffer, in
    // `ironrdp-session`'s `CompleteData`, not the server's. Echoing the
    // server's number back unaltered therefore let the server choose how much
    // memory this client would accumulate before it stopped, and `u32::MAX`
    // says four gigabytes. The number that goes on the wire and the number
    // `crate::framed::Reassembly` enforces are now the same one, which is what
    // makes enforcing it honest: the server was told.
    let mut capabilities: Vec<CapabilitySet> = server_capabilities
        .into_iter()
        .filter_map(|set| match set {
            CapabilitySet::MultiFragmentUpdate(update) => {
                Some(CapabilitySet::MultiFragmentUpdate(MultifragmentUpdate {
                    max_request_size: update.max_request_size.min(MAX_FASTPATH_REASSEMBLY_BYTES),
                }))
            }
            _ => None,
        })
        .collect();

    capabilities.extend([
        CapabilitySet::General(General {
            extra_flags: GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED
                | GeneralExtraFlags::NO_BITMAP_COMPRESSION_HDR,
            ..Default::default()
        }),
        CapabilitySet::Bitmap(Bitmap {
            pref_bits_per_pix: 32,
            desktop_width: desktop.width,
            desktop_height: desktop.height,
            // Required before the Display Control channel will work at all.
            desktop_resize_flag: true,
            drawing_flags: BitmapDrawingFlags::ALLOW_SKIP_ALPHA,
        }),
        CapabilitySet::Order(Order::new(
            OrderFlags::NEGOTIATE_ORDER_SUPPORT | OrderFlags::ZERO_BOUNDS_DELTAS_SUPPORT,
            OrderSupportExFlags::empty(),
            0,
            0,
        )),
        // No bitmap cache: a cache the client does not implement, advertised,
        // makes the server send cache references nothing can resolve.
        CapabilitySet::BitmapCache(BitmapCache {
            caches: [CacheEntry {
                entries: 0,
                max_cell_size: 0,
            }; BITMAP_CACHE_ENTRIES_NUM],
        }),
        CapabilitySet::Input(Input {
            input_flags: InputFlags::all(),
            keyboard_layout: 0,
            keyboard_type: None,
            keyboard_subtype: 0,
            keyboard_function_key: 12,
            keyboard_ime_filename: String::new(),
        }),
        CapabilitySet::Pointer(Pointer {
            // Non-zero, which is what enables client-side pointer rendering:
            // the pointer then arrives as its own update and the presenter can
            // follow the local mouse at the display's refresh rate instead of
            // the network's.
            color_pointer_cache_size: POINTER_CACHE_SIZE,
            pointer_cache_size: POINTER_CACHE_SIZE,
        }),
        CapabilitySet::Brush(Brush {
            support_level: SupportLevel::Default,
        }),
        CapabilitySet::GlyphCache(GlyphCache {
            glyph_cache: [CacheDefinition {
                entries: 0,
                max_cell_size: 0,
            }; GLYPH_CACHE_NUM],
            frag_cache: CacheDefinition {
                entries: 0,
                max_cell_size: 0,
            },
            glyph_support_level: GlyphSupportLevel::None,
        }),
        CapabilitySet::OffscreenBitmapCache(OffscreenBitmapCache {
            is_supported: false,
            cache_size: 0,
            cache_entries: 0,
        }),
        CapabilitySet::VirtualChannel(VirtualChannel {
            flags: VirtualChannelFlags::NO_COMPRESSION,
            chunk_size: Some(0),
        }),
        CapabilitySet::Sound(Sound {
            flags: SoundFlags::empty(),
        }),
        CapabilitySet::LargePointer(LargePointer {
            // 96x96 is what Windows Server 2019 and older need for a correct
            // cursor; 384x384 is what a high-DPI Windows 11 host sends.
            // Advertising both is what makes the pointer right on either.
            flags: LargePointerSupportFlags::UP_TO_96X96_PIXELS
                | LargePointerSupportFlags::UP_TO_384X384_PIXELS,
        }),
        CapabilitySet::SurfaceCommands(SurfaceCommands {
            flags: CmdFlags::SET_SURFACE_BITS
                | CmdFlags::STREAM_SURFACE_BITS
                | CmdFlags::FRAME_MARKER,
        }),
        CapabilitySet::BitmapCodecs(
            // RemoteFX (MS-RDPRFX), which is what a modern Windows Server
            // negotiates by preference. The empty configuration is IronRDP's
            // "everything this build can decode".
            client_codecs_capabilities(&[]).unwrap_or_default(),
        ),
        CapabilitySet::FrameAcknowledge(FrameAcknowledge {
            max_unacknowledged_frame_count: MAX_UNACKNOWLEDGED_FRAMES,
        }),
    ]);

    if !capabilities
        .iter()
        .any(|set| matches!(set, CapabilitySet::MultiFragmentUpdate(_)))
    {
        capabilities.push(CapabilitySet::MultiFragmentUpdate(MultifragmentUpdate {
            // Large enough that a full-screen RemoteFX frame is not
            // fragmented, and the buffer it describes is THIS process's — see
            // the clamp above and `MAX_FASTPATH_REASSEMBLY_BYTES`.
            max_request_size: MAX_FASTPATH_REASSEMBLY_BYTES,
        }));
    }

    ClientConfirmActive {
        originator_id: SERVER_CHANNEL_ID,
        pdu: DemandActive {
            source_descriptor: "MSTSC".to_owned(),
            capability_sets: capabilities,
        },
    }
}

/// Entries in the pointer caches. Non-zero enables client-side pointer
/// rendering; 32 is what every real client sends.
const POINTER_CACHE_SIZE: u16 = 32;

/// How many frames the server may have in flight unacknowledged
/// (MS-RDPBCGR §2.2.7.2.7).
const MAX_UNACKNOWLEDGED_FRAMES: u32 = 20;

/// The Client GCC blocks inside the MCS Connect Initial. MS-RDPBCGR §2.2.1.3.
fn client_gcc_blocks(
    config: &ConnectionConfig,
    selected: nego::SecurityProtocol,
    channels: &StaticChannelSet,
) -> gcc::ClientGccBlocks {
    use gcc::{
        ClientCoreData, ClientCoreOptionalData, ClientEarlyCapabilityFlags, ClientGccBlocks,
        ClientNetworkData, ClientSecurityData, ColorDepth, ConnectionType, EncryptionMethod,
        HighColorDepth, MonitorOrientation, RdpVersion, SecureAccessSequence, SupportedColorDepths,
    };

    let definitions: Vec<_> = channels.values().map(make_channel_definition).collect();

    ClientGccBlocks {
        // §2.2.1.3.2, Client Core Data.
        core: ClientCoreData {
            version: RdpVersion::V5_PLUS,
            desktop_width: config.desktop.width,
            desktop_height: config.desktop.height,
            // Superseded by `high_color_depth` in the optional data below;
            // the field is kept for RDP 4 servers that read no further.
            color_depth: ColorDepth::Bpp8,
            sec_access_sequence: SecureAccessSequence::Del,
            keyboard_layout: config.keyboard_layout,
            client_build: CLIENT_BUILD,
            client_name: config.workstation.clone(),
            // IBM enhanced (101/102 keys), the type every modern layout is
            // described in terms of.
            keyboard_type: gcc::KeyboardType::IbmEnhanced,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            ime_file_name: String::new(),
            optional_data: ClientCoreOptionalData {
                post_beta2_color_depth: Some(ColorDepth::Bpp8),
                client_product_id: Some(1),
                serial_number: Some(0),
                // 32bpp has no `highColorDepth` value of its own; it is asked
                // for with WANT_32_BPP_SESSION below.
                high_color_depth: Some(HighColorDepth::Bpp24),
                supported_color_depths: Some(
                    SupportedColorDepths::BPP32
                        | SupportedColorDepths::BPP24
                        | SupportedColorDepths::BPP16
                        | SupportedColorDepths::BPP15,
                ),
                early_capability_flags: Some(
                    ClientEarlyCapabilityFlags::VALID_CONNECTION_TYPE
                        // Without this the server closes the connection with
                        // no explanation instead of sending a Set Error Info
                        // PDU saying why.
                        | ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU
                        | ClientEarlyCapabilityFlags::STRONG_ASYMMETRIC_KEYS
                        | ClientEarlyCapabilityFlags::SUPPORT_NET_CHAR_AUTODETECT
                        | ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN
                        | ClientEarlyCapabilityFlags::WANT_32_BPP_SESSION,
                ),
                dig_product_id: Some(String::new()),
                connection_type: Some(ConnectionType::Lan),
                // §2.2.1.3.2: the client echoes what the server selected in
                // the Negotiation Response. A mismatch here is how a
                // downgrade attack on the X.224 exchange would be *hidden*
                // from the server, so it is not optional.
                server_selected_protocol: Some(selected),
                desktop_physical_width: Some(0),
                desktop_physical_height: Some(0),
                desktop_orientation: Some(if config.desktop.width > config.desktop.height {
                    MonitorOrientation::Landscape.as_u16()
                } else {
                    MonitorOrientation::Portrait.as_u16()
                }),
                desktop_scale_factor: Some(100),
                device_scale_factor: Some(100),
            },
        },
        // §2.2.1.3.3. Empty because Standard RDP Security is not implemented:
        // the encryption is TLS's, and asking for an RC4 method would be
        // asking for the thing this build refuses to do.
        security: ClientSecurityData {
            encryption_methods: EncryptionMethod::empty(),
            ext_encryption_methods: 0,
        },
        // §2.2.1.3.4.
        network: (!definitions.is_empty()).then_some(ClientNetworkData {
            channels: definitions,
        }),
        cluster: None,
        monitor: None,
        // §2.2.1.3.7. The message channel carries network auto-detection and
        // the multitransport and heartbeat PDUs; the server assigns its id in
        // the Server Message Channel Data.
        message_channel: Some(gcc::ClientMessageChannelData),
        // Multitransport is a UDP side channel this build does not open.
        multi_transport_channel: None,
        monitor_extended: None,
    }
}

/// The build number reported in the Client Core Data. Windows 10 21H2, which
/// is what a current `mstsc` reports.
const CLIENT_BUILD: u32 = 19041;

/// Encodes `pdu` inside an MCS Send Data Request on `channel_id`.
fn send_data_request<T: Encode>(
    initiator_id: u16,
    channel_id: u16,
    pdu: &T,
) -> Result<Vec<u8>, ProtocolError> {
    let user_data = encode_vec(pdu).map_err(|_| encode_failure())?;
    encode_vec(&X224(mcs::SendDataRequest {
        initiator_id,
        channel_id,
        user_data: Cow::Owned(user_data),
    }))
    .map_err(|_| encode_failure())
}

/// Writes an X.224 Data PDU whose payload is `pdu`'s own encoding.
///
/// The MCS Connect Initial is carried this way rather than as a Send Data
/// Request: no channel exists yet to send it on.
async fn write_x224_data<T: Encode>(stream: &mut Framed, pdu: &T) -> Result<(), ProtocolError> {
    let payload = encode_vec(pdu).map_err(|_| encode_failure())?;
    let framed = encode_vec(&X224(X224Data {
        data: Cow::Owned(payload),
    }))
    .map_err(|_| encode_failure())?;
    stream.write_all(&framed).await
}

/// Reads one X.224-framed PDU and decodes it as `T`.
async fn read_x224<T>(stream: &mut Framed) -> Result<T, ProtocolError>
where
    T: for<'de> ironrdp::pdu::x224::X224Pdu<'de>,
{
    let bytes = stream.read_x224_pdu().await?;
    ironrdp::core::decode::<X224<T>>(&bytes)
        .map(|pdu| pdu.0)
        .map_err(|_| decode_failure())
}

/// A PDU this client could not build. A defect here, not a server problem.
fn encode_failure() -> ProtocolError {
    ProtocolError::Internal {
        detail: "an RDP PDU could not be encoded",
    }
}

/// A PDU the server sent that this client could not read.
fn decode_failure() -> ProtocolError {
    violation("the server sent a PDU this client could not decode")
}

/// Fills `buffer` with cryptographically strong randomness.
///
/// # Errors
///
/// [`ProtocolError::Internal`] if the platform's generator failed. That is
/// fatal on purpose: continuing with a predictable client nonce or session key
/// would produce a CredSSP exchange an observer can replay.
fn fill_random(buffer: &mut [u8]) -> Result<(), ProtocolError> {
    getrandom::fill(buffer).map_err(|_| ProtocolError::Internal {
        detail: "the platform random number generator failed",
    })
}

/// The current time as a Windows `FILETIME`: 100-nanosecond intervals since
/// 1601-01-01 UTC.
///
/// Only used when the server's NTLM CHALLENGE carried no timestamp of its own,
/// which a modern Windows host always does.
fn now_filetime() -> u64 {
    // 11 644 473 600 seconds between the FILETIME epoch and the Unix one.
    const EPOCH_OFFSET_SECONDS: u64 = 11_644_473_600;
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            since
                .as_secs()
                .saturating_add(EPOCH_OFFSET_SECONDS)
                .saturating_mul(10_000_000)
                .saturating_add(u64::from(since.subsec_nanos()) / 100)
        })
}

/// The static channel set this adapter asks for.
///
/// - `drdynvc`, the dynamic virtual channel multiplexer (MS-RDPEDYC), and
///   inside it the Display Control channel (MS-RDPEDISP) that carries a
///   resize. Always.
/// - `cliprdr`, the clipboard (MS-RDPECLIP), when `clipboard` lets text cross
///   in either direction or lets files cross at all. A connection whose policy allows nothing does not
///   ask for the channel at all: requesting one nothing will use makes the
///   server start `rdpclip` and wait on it.
///
/// The channels go into the Client Network Data in this set's own order and
/// the server's ids come back in that order (MS-RDPBCGR §2.2.1.4.4), which
/// `crate::connect` relies on; the set is a `BTreeMap`, so the order is the
/// same on both passes.
#[must_use]
pub fn static_channels(clipboard: ClipboardPolicy) -> StaticChannelSet {
    use ironrdp::cliprdr::CliprdrClient;
    use ironrdp::displaycontrol::client::DisplayControlClient;
    use ironrdp::dvc::DrdynvcClient;

    let mut channels = StaticChannelSet::new();
    channels.insert(
        DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_capabilities| {
            // The capability exchange needs no reply; the channel is usable
            // from the moment it arrives, which is what `ready()` reports.
            Ok(Vec::new())
        })),
    );
    if clipboard.text_to_remote || clipboard.text_from_remote || clipboard.files {
        channels.insert(CliprdrClient::new(Box::new(
            crate::clipboard::ClipboardSignals::new(clipboard.files),
        )));
    }
    channels
}

/// Asserts at compile time that the channel set is a client one. A server
/// processor here would be accepted by `StaticChannelSet` and would then fail
/// at the first PDU.
const fn _assert_client_channels<T: SvcClientProcessor>() {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;

    fn target() -> HostPort {
        HostPort::new("ts-01.corp.example", 3389).unwrap()
    }

    fn config() -> ConnectionConfig {
        ConnectionConfig::new(target(), "ada")
    }

    use crate::testing::ScriptedTransport;
    use ironrdp::core::encode_vec;
    use ironrdp::pdu::rdp::headers::ShareControlHeader;
    use remoter_proto::{Transport, TransportKind, TransportPeer};

    /// A [`Framed`] over a scripted peer, plus what the client wrote to it.
    fn scripted(reads: Vec<Vec<u8>>) -> (Framed, std::sync::Arc<parking_lot::Mutex<Vec<u8>>>) {
        let transport = ScriptedTransport::new(target(), reads);
        let written = transport.written();
        (Framed::new(Box::new(transport), target()), written)
    }

    /// Wraps a server PDU in an MCS Send Data Indication, which is how every
    /// server-to-client PDU after the channel joins travels.
    fn indication<T: Encode>(channel_id: u16, pdu: &T) -> Vec<u8> {
        let user_data = encode_vec(pdu).unwrap();
        encode_vec(&X224(mcs::SendDataIndication {
            initiator_id: SERVER_INITIATOR,
            channel_id,
            user_data: Cow::Owned(user_data),
        }))
        .unwrap()
    }

    /// A Share Control PDU inside a Send Data Indication.
    fn share_control(channel_id: u16, share_id: u32, pdu: ShareControlPdu) -> Vec<u8> {
        indication(
            channel_id,
            &ShareControlHeader {
                share_control_pdu: pdu,
                pdu_source: SERVER_INITIATOR,
                share_id,
            },
        )
    }

    /// A Share Data PDU inside a Send Data Indication.
    fn share_data(channel_id: u16, share_id: u32, pdu: ShareDataPdu) -> Vec<u8> {
        use ironrdp::pdu::rdp::headers::{CompressionFlags, ShareDataHeader, StreamPriority};
        share_control(
            channel_id,
            share_id,
            ShareControlPdu::Data(ShareDataHeader {
                share_data_pdu: pdu,
                stream_priority: StreamPriority::Medium,
                compression_flags: CompressionFlags::empty(),
                compression_type: rdp::client_info::CompressionType::K8,
            }),
        )
    }

    /// MS-RDPBCGR §2.2.1.13.1: the server's own MCS channel is 1002.
    const SERVER_INITIATOR: u16 = 1002;
    const IO_CHANNEL: u16 = 1003;
    const USER_CHANNEL: u16 = 1004;
    const SHARE_ID: u32 = 0x0003_ea03;

    #[tokio::test]
    async fn the_connection_request_asks_for_what_was_configured_and_reads_the_confirm() {
        let confirm = encode_vec(&X224(nego::ConnectionConfirm::Response {
            flags: nego::ResponseFlags::EXTENDED_CLIENT_DATA_SUPPORTED,
            protocol: nego::SecurityProtocol::HYBRID,
        }))
        .unwrap();
        let (mut stream, written) = scripted(vec![confirm]);

        let config = config();
        let selected = initiate(&mut stream, &config, requested_protocols(&config))
            .await
            .unwrap();
        assert_eq!(selected, nego::SecurityProtocol::HYBRID);

        // The request is a real X.224 Connection Request carrying the routing
        // cookie a Connection Broker reads to send a reconnecting user back to
        // the host holding their session.
        let bytes = written.lock().clone();
        let request = ironrdp::core::decode::<X224<nego::ConnectionRequest>>(&bytes)
            .unwrap()
            .0;
        assert_eq!(
            request.nego_data,
            Some(nego::NegoRequestData::cookie("ada".to_owned()))
        );
        assert!(request.protocol.contains(nego::SecurityProtocol::HYBRID));
    }

    #[tokio::test]
    async fn a_negotiation_failure_becomes_its_own_error_rather_than_a_generic_one() {
        // HYBRID_REQUIRED_BY_SERVER, the code a default Windows Server sends to
        // a client that offered only TLS.
        let failure = encode_vec(&X224(nego::ConnectionConfirm::Failure {
            code: nego::FailureCode::HYBRID_REQUIRED_BY_SERVER,
        }))
        .unwrap();
        let (mut stream, _) = scripted(vec![failure]);

        let mut config = config();
        config.network_level_authentication = false;
        let error = initiate(&mut stream, &config, requested_protocols(&config))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("Network Level Authentication"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_server_that_selects_something_never_offered_is_refused() {
        // Continuing would mean speaking a protocol the client did not agree
        // to, which is the shape a downgrade takes.
        let confirm = encode_vec(&X224(nego::ConnectionConfirm::Response {
            flags: nego::ResponseFlags::empty(),
            protocol: nego::SecurityProtocol::RDSAAD,
        }))
        .unwrap();
        let (mut stream, _) = scripted(vec![confirm]);
        let config = config();
        assert!(
            initiate(&mut stream, &config, requested_protocols(&config))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn the_channel_joins_are_batched_and_every_confirm_is_matched() {
        // RDP 8.1 and later send every join in one batch to save a round trip
        // per channel (MS-RDPBCGR §3.2.5.3.8); the confirms may come back in
        // any order.
        let mut script = encode_vec(&X224(mcs::AttachUserConfirm {
            result: 0,
            initiator_id: USER_CHANNEL,
        }))
        .unwrap();
        for channel_id in [USER_CHANNEL, 1007, IO_CHANNEL] {
            script.extend_from_slice(
                &encode_vec(&X224(mcs::ChannelJoinConfirm {
                    result: 0,
                    initiator_id: USER_CHANNEL,
                    requested_channel_id: channel_id,
                    channel_id,
                }))
                .unwrap(),
            );
        }
        let (mut stream, written) = scripted(vec![script]);

        let user = join_channels(&mut stream, Some(vec![IO_CHANNEL, 1007]))
            .await
            .unwrap();
        assert_eq!(user, USER_CHANNEL);

        // Erect Domain and Attach User go out before the joins, and the user
        // channel is joined as well as the ones the server named.
        let bytes = written.lock().clone();
        assert!(bytes.len() > 3, "nothing was written");
    }

    #[tokio::test]
    async fn an_mcs_refusal_to_attach_a_user_is_not_read_as_success() {
        // T.125 §7: `result` is an MCS Result and only rt-successful means the
        // user was attached. The defect this covers read `initiator_id` and
        // ignored `result`, so a refusal became a session addressed to a user
        // channel the server had declined — every later PDU going nowhere, and
        // the failure surfacing several steps from its cause.
        let script = encode_vec(&X224(mcs::AttachUserConfirm {
            // rt-not-admitted: this client may not join the domain.
            result: 6,
            initiator_id: USER_CHANNEL,
        }))
        .unwrap();
        let (mut stream, _) = scripted(vec![script]);

        let error = join_channels(&mut stream, None).await.unwrap_err();
        assert_eq!(error.stage(), remoter_proto::Stage::Handshake);
        assert!(error.to_string().contains("refused to attach"), "{error}");
    }

    #[tokio::test]
    async fn an_mcs_refusal_to_join_a_channel_is_not_read_as_success() {
        // The same field on the other confirm. A refusal carries no joined
        // channel id — T.125 makes it optional — so the requested/joined
        // comparison below it cannot stand in for this check.
        let mut script = encode_vec(&X224(mcs::AttachUserConfirm {
            result: 0,
            initiator_id: USER_CHANNEL,
        }))
        .unwrap();
        script.extend_from_slice(
            &encode_vec(&X224(mcs::ChannelJoinConfirm {
                // rt-no-such-channel: the server never created it.
                result: 3,
                initiator_id: USER_CHANNEL,
                requested_channel_id: IO_CHANNEL,
                channel_id: IO_CHANNEL,
            }))
            .unwrap(),
        );
        let (mut stream, _) = scripted(vec![script]);

        let error = join_channels(&mut stream, Some(vec![IO_CHANNEL]))
            .await
            .unwrap_err();
        assert_eq!(error.stage(), remoter_proto::Stage::Handshake);
        assert!(
            error.to_string().contains("refused to join a channel"),
            "{error}"
        );
    }

    #[test]
    fn every_mcs_result_code_is_named_rather_than_logged_as_a_number() {
        // The names are T.125's own; a bare number in the log sends the reader
        // to the specification for the one thing it does supply.
        assert_eq!(mcs_result_name(MCS_RT_SUCCESSFUL), "rt-successful");
        assert_eq!(mcs_result_name(3), "rt-no-such-channel");
        assert_eq!(mcs_result_name(15), "rt-user-rejected");
        let mut named = std::collections::HashSet::new();
        for result in 0..=15u8 {
            assert!(
                named.insert(mcs_result_name(result)),
                "MCS result {result} repeats another name"
            );
        }
        assert!(!named.contains(mcs_result_name(16)));
    }

    #[tokio::test]
    async fn a_channel_confirmed_that_was_never_requested_is_refused() {
        // The ids are how every later PDU is addressed; accepting a stray one
        // would send graphics to a channel nobody is listening on.
        let mut script = encode_vec(&X224(mcs::AttachUserConfirm {
            result: 0,
            initiator_id: USER_CHANNEL,
        }))
        .unwrap();
        script.extend_from_slice(
            &encode_vec(&X224(mcs::ChannelJoinConfirm {
                result: 0,
                initiator_id: USER_CHANNEL,
                requested_channel_id: 4242,
                channel_id: 4242,
            }))
            .unwrap(),
        );
        let (mut stream, _) = scripted(vec![script]);
        assert!(
            join_channels(&mut stream, Some(vec![IO_CHANNEL]))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_channel_joined_under_a_different_id_than_requested_is_refused() {
        let mut script = encode_vec(&X224(mcs::AttachUserConfirm {
            result: 0,
            initiator_id: USER_CHANNEL,
        }))
        .unwrap();
        script.extend_from_slice(
            &encode_vec(&X224(mcs::ChannelJoinConfirm {
                result: 0,
                initiator_id: USER_CHANNEL,
                requested_channel_id: IO_CHANNEL,
                channel_id: 9999,
            }))
            .unwrap(),
        );
        let (mut stream, _) = scripted(vec![script]);
        assert!(
            join_channels(&mut stream, Some(vec![IO_CHANNEL]))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_server_that_skips_the_channel_joins_is_taken_at_its_word() {
        // MS-RDPBCGR §2.2.1.4.2: `SKIP_CHANNELJOIN_SUPPORTED` saves a round
        // trip per channel on a modern Windows host.
        let script = encode_vec(&X224(mcs::AttachUserConfirm {
            result: 0,
            initiator_id: USER_CHANNEL,
        }))
        .unwrap();
        let (mut stream, _) = scripted(vec![script]);
        assert_eq!(
            join_channels(&mut stream, None).await.unwrap(),
            USER_CHANNEL
        );
    }

    /// A Server Demand Active PDU announcing `width` by `height`.
    fn demand_active(width: u16, height: u16) -> Vec<u8> {
        use rdp::capability_sets::{Bitmap, BitmapDrawingFlags, DemandActive, ServerDemandActive};
        share_control(
            IO_CHANNEL,
            SHARE_ID,
            ShareControlPdu::ServerDemandActive(ServerDemandActive {
                pdu: DemandActive {
                    source_descriptor: "RDP".to_owned(),
                    capability_sets: vec![CapabilitySet::Bitmap(Bitmap {
                        pref_bits_per_pix: 32,
                        desktop_width: width,
                        desktop_height: height,
                        desktop_resize_flag: true,
                        drawing_flags: BitmapDrawingFlags::empty(),
                    })],
                },
            }),
        )
    }

    #[tokio::test]
    async fn the_size_the_server_chose_wins_over_the_one_that_was_asked_for() {
        // The rest of the session is in the server's coordinates; a client that
        // keeps its own number draws at the wrong scale and puts every mouse
        // click in the wrong place.
        let (mut stream, written) = scripted(vec![demand_active(1600, 900)]);
        let mut config = config();
        config.desktop = DesktopSize {
            width: 1920,
            height: 1080,
        };

        let (share_id, desktop) =
            capabilities_exchange(&mut stream, &config, USER_CHANNEL, IO_CHANNEL, None, None)
                .await
                .unwrap();
        assert_eq!(share_id, SHARE_ID);
        assert_eq!(
            desktop,
            DesktopSize {
                width: 1600,
                height: 900
            }
        );

        // And the Confirm Active echoes that size back, which is what the
        // server checks.
        assert!(!written.lock().is_empty());
    }

    #[tokio::test]
    async fn a_deactivate_all_before_the_demand_active_is_skipped_rather_than_refused() {
        // Windows Server and gnome-remote-desktop both send one; refusing it
        // would fail an ordinary connection at the last step.
        let mut script = share_control(
            IO_CHANNEL,
            SHARE_ID,
            ShareControlPdu::ServerDeactivateAll(rdp::headers::ServerDeactivateAll),
        );
        script.extend_from_slice(&demand_active(1024, 768));
        let (mut stream, _) = scripted(vec![script]);

        let (_, desktop) =
            capabilities_exchange(&mut stream, &config(), USER_CHANNEL, IO_CHANNEL, None, None)
                .await
                .unwrap();
        assert_eq!(desktop, DesktopSize::default());
    }

    /// A transport that never answers and never hangs up.
    ///
    /// The case a deadline exists for, and the one `ScriptedTransport` cannot
    /// express: an exhausted script reads as end of stream, which is a server
    /// that *did* say something. This one says nothing at all.
    struct SilentTransport {
        peer: TransportPeer,
    }

    impl SilentTransport {
        fn new() -> Self {
            Self {
                peer: TransportPeer::direct(TransportKind::Tcp, target()),
            }
        }
    }

    impl tokio::io::AsyncRead for SilentTransport {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl tokio::io::AsyncWrite for SilentTransport {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl Transport for SilentTransport {
        fn peer(&self) -> &TransportPeer {
            &self.peer
        }
    }

    #[tokio::test]
    async fn a_reactivation_the_server_never_finishes_is_given_up_on() {
        // The defect: the Deactivation-Reactivation Sequence ran with no
        // deadline, so a server that deactivated the share and then said
        // nothing held the session's read loop — and with it the tab, the task
        // and the socket — open for as long as the connection lasted. A tab
        // that never paints and never fails is the worst of both.
        //
        // The budget is the connection's own, so the test sets a short one
        // rather than waiting out `DEFAULT_TIMEOUT`. The outer timeout is
        // twenty times longer: *it* firing first is what "there is no deadline
        // in here" looks like.
        let mut config = config();
        config.timeout = Duration::from_millis(150);
        let mut stream = Framed::new(Box::new(SilentTransport::new()), target());
        let outcome = tokio::time::timeout(
            config.timeout * 20,
            reactivate(&mut stream, &config, USER_CHANNEL, IO_CHANNEL),
        )
        .await
        .expect("the reactivation sequence ran with no deadline of its own");

        let error = outcome.unwrap_err();
        assert!(
            matches!(error, ProtocolError::ProtocolViolation { .. }),
            "{error:?}"
        );
        // Named as the server's breach of §1.3.1.3, not as a network problem:
        // the link is fine and retrying the address fixes nothing.
        assert!(
            error.to_string().contains("deactivation-reactivation"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_server_that_only_deactivates_the_share_is_refused_rather_than_read_for_ever() {
        // The other half of the bound. A Demand Active does eventually follow
        // here, so nothing but the iteration cap can refuse this script —
        // which is what makes the test fail without one.
        let deactivate = share_control(
            IO_CHANNEL,
            SHARE_ID,
            ShareControlPdu::ServerDeactivateAll(rdp::headers::ServerDeactivateAll),
        );
        let mut script = Vec::new();
        for _ in 0..=MAX_DEACTIVATIONS {
            script.extend_from_slice(&deactivate);
        }
        script.extend_from_slice(&demand_active(1024, 768));
        let (mut stream, _) = scripted(vec![script]);

        let error =
            capabilities_exchange(&mut stream, &config(), USER_CHANNEL, IO_CHANNEL, None, None)
                .await
                .unwrap_err();
        assert!(
            matches!(error, ProtocolError::ProtocolViolation { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn the_capability_exchange_consumes_a_pdu_the_licensing_phase_handed_back() {
        // A server with nothing to license goes straight to the Demand Active.
        let pending = bytes::BytesMut::from(&demand_active(800, 600)[..]);
        let (mut stream, _) = scripted(Vec::new());
        let (_, desktop) = capabilities_exchange(
            &mut stream,
            &config(),
            USER_CHANNEL,
            IO_CHANNEL,
            Some(pending),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            desktop,
            DesktopSize {
                width: 800,
                height: 600
            }
        );
    }

    #[tokio::test]
    async fn finalization_ends_on_the_font_map_and_asks_for_a_redraw() {
        use rdp::finalization_messages::{ControlAction, ControlPdu, FontPdu};

        // The server's half: a Synchronize, two Controls, then the Font Map.
        let mut script = share_data(
            IO_CHANNEL,
            SHARE_ID,
            ShareDataPdu::Synchronize(rdp::finalization_messages::SynchronizePdu {
                target_user_id: SERVER_INITIATOR,
            }),
        );
        script.extend_from_slice(&share_data(
            IO_CHANNEL,
            SHARE_ID,
            ShareDataPdu::Control(ControlPdu {
                action: ControlAction::Cooperate,
                grant_id: 0,
                control_id: 0,
            }),
        ));
        script.extend_from_slice(&share_data(
            IO_CHANNEL,
            SHARE_ID,
            ShareDataPdu::Control(ControlPdu {
                action: ControlAction::GrantedControl,
                grant_id: USER_CHANNEL,
                control_id: u32::from(SERVER_INITIATOR),
            }),
        ));
        script.extend_from_slice(&share_data(
            IO_CHANNEL,
            SHARE_ID,
            ShareDataPdu::FontMap(FontPdu::default()),
        ));

        let (mut stream, written) = scripted(vec![script]);
        finalize(
            &mut stream,
            USER_CHANNEL,
            IO_CHANNEL,
            SHARE_ID,
            DesktopSize::default(),
            None,
        )
        .await
        .unwrap();

        // Four finalization PDUs and then a Refresh Rect: without the last one
        // the first thing the user sees is whatever happens to change next,
        // because the frames the server drew during the sequence were
        // discarded.
        let bytes = written.lock().clone();
        assert!(bytes.len() > 60, "only {} bytes were written", bytes.len());
    }

    #[tokio::test]
    async fn a_server_error_during_finalization_is_reported_rather_than_ignored() {
        use rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu};
        let script = share_data(
            IO_CHANNEL,
            SHARE_ID,
            ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
                ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::RpcInitiatedDisconnect),
            )),
        );
        let (mut stream, _) = scripted(vec![script]);
        let error = finalize(
            &mut stream,
            USER_CHANNEL,
            IO_CHANNEL,
            SHARE_ID,
            DesktopSize::default(),
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ProtocolError::Disconnected { .. }));
    }

    #[tokio::test]
    async fn licensing_completes_on_the_valid_client_alert_a_host_in_admin_mode_sends() {
        use rdp::server_license::{LicensePdu, LicensingErrorMessage};
        let message = LicensingErrorMessage::new_valid_client().unwrap();
        let script = indication(IO_CHANNEL, &LicensePdu::LicensingErrorMessage(message));
        let (mut stream, _) = scripted(vec![script]);

        let pending = licensing(&mut stream, &config(), USER_CHANNEL, IO_CHANNEL, None)
            .await
            .unwrap();
        assert!(pending.is_none());
    }

    #[tokio::test]
    async fn a_demand_active_where_a_licence_was_expected_is_handed_on_rather_than_refused() {
        // Reporting "the server's licensing refused this connection" here
        // would be a message several steps from the truth.
        let (mut stream, _) = scripted(vec![demand_active(1024, 768)]);
        let pending = licensing(&mut stream, &config(), USER_CHANNEL, IO_CHANNEL, None)
            .await
            .unwrap();
        assert!(
            pending.is_some(),
            "the PDU was consumed instead of handed on"
        );
    }

    #[tokio::test]
    async fn a_licensing_refusal_is_reported_as_a_server_side_problem() {
        // No licences left, or no licence server reachable. The user cannot
        // fix it by retyping a password, so it must not look like an
        // authentication failure.
        use rdp::server_license::{LicenseErrorCode, LicensePdu, LicensingErrorMessage};
        let mut message = LicensingErrorMessage::new_valid_client().unwrap();
        message.error_code = LicenseErrorCode::NoLicenseServer;
        let script = indication(IO_CHANNEL, &LicensePdu::LicensingErrorMessage(message));
        let (mut stream, _) = scripted(vec![script]);

        let error = licensing(&mut stream, &config(), USER_CHANNEL, IO_CHANNEL, None)
            .await
            .unwrap_err();
        assert_eq!(error.stage(), remoter_proto::Stage::Handshake);
        assert!(!matches!(error, ProtocolError::AuthRejected { .. }));
    }

    /// A credential provider with a distinctive password.
    struct Account;
    impl CredentialProvider for Account {
        fn username(&self) -> Option<&str> {
            Some("ada")
        }
        fn kind(&self) -> remoter_proto::CredentialKind {
            remoter_proto::CredentialKind::Password
        }
        fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
            f(b"hunter2");
            true
        }
        fn borrow_private_key(&self, _f: &mut remoter_proto::KeyBorrow<'_>) -> bool {
            false
        }
    }

    /// `hunter2` as the Client Info PDU would carry it.
    fn password_on_the_wire() -> Vec<u8> {
        crate::credssp::crypto::utf16le("hunter2")
    }

    #[tokio::test]
    async fn network_level_authentication_means_the_password_is_not_repeated_in_the_client_info() {
        // CredSSP already delegated the credentials; putting them in the
        // Client Info PDU as well would place the password in a second spot on
        // the wire for no benefit.
        let (mut stream, written) = scripted(Vec::new());
        send_client_info(
            &mut stream,
            &config(),
            &Account,
            USER_CHANNEL,
            IO_CHANNEL,
            true,
        )
        .await
        .unwrap();

        let bytes = written.lock().clone();
        let needle = password_on_the_wire();
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "the password was repeated in the Client Info PDU"
        );
        // The account name still is, which is how the server knows who is
        // connecting — and which proves the search above was looking in the
        // right buffer.
        let user = crate::credssp::crypto::utf16le("ada");
        assert!(bytes.windows(user.len()).any(|window| window == user));
    }

    #[tokio::test]
    async fn without_network_level_authentication_the_client_info_is_the_single_sign_on() {
        // The other half of the trade: with no CredSSP this field is the only
        // place the credentials travel, and without it the user meets the
        // remote login screen.
        let (mut stream, written) = scripted(Vec::new());
        send_client_info(
            &mut stream,
            &config(),
            &Account,
            USER_CHANNEL,
            IO_CHANNEL,
            false,
        )
        .await
        .unwrap();

        let bytes = written.lock().clone();
        let needle = password_on_the_wire();
        assert!(
            bytes.windows(needle.len()).any(|window| window == needle),
            "the password did not reach the Client Info PDU"
        );
    }

    #[tokio::test]
    async fn a_cancelled_connection_attempt_drops_the_injected_transport() {
        // The defect this shape exists to prevent, checked on the real type
        // rather than on a stand-in: an earlier version leaked one task and one
        // socket per cancelled attempt.
        let transport = ScriptedTransport::new(target(), Vec::new());
        let dropped = transport.dropped();
        let stream = Framed::new(Box::new(transport), target());

        let cancel = CancellationToken::new();
        cancel.cancel();
        let outcome = with_deadline(
            &cancel,
            Duration::from_secs(3600),
            &target(),
            None,
            async move {
                // Holds the stream, as the real sequence does.
                let _stream = stream;
                std::future::pending::<Result<(), ProtocolError>>().await
            },
        )
        .await;

        assert!(matches!(outcome, Err(ProtocolError::Cancelled)));
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "the socket outlived the cancelled attempt"
        );
    }

    #[test]
    fn network_level_authentication_does_not_offer_a_downgrade_to_bare_tls() {
        // MS-RDPBCGR §2.2.1.1 says PROTOCOL_SSL "SHOULD" accompany the hybrid
        // flags. Omitting it is deliberate: it tells the server this client
        // will not accept being downgraded out of NLA, and the downgrade is
        // what would put the password on the far side of an unauthenticated
        // tunnel.
        let requested = requested_protocols(&config());
        assert!(requested.contains(nego::SecurityProtocol::HYBRID));
        assert!(requested.contains(nego::SecurityProtocol::HYBRID_EX));
        assert!(!requested.contains(nego::SecurityProtocol::SSL));
    }

    #[test]
    fn turning_network_level_authentication_off_asks_for_tls_and_never_for_legacy_security() {
        let mut config = config();
        config.network_level_authentication = false;
        let requested = requested_protocols(&config);
        assert_eq!(requested, nego::SecurityProtocol::SSL);
        // Standard RDP Security is the empty set. Asking for it would be
        // asking for RC4, which `transport-security.md` rules out.
        assert!(!requested.is_standard_rdp_security());
    }

    #[test]
    fn the_service_principal_name_is_the_host_as_the_user_typed_it() {
        // A server with SPN checking on compares this literally; rewriting the
        // host would produce a mismatch on exactly the hardened deployments
        // that bother to check.
        assert_eq!(
            config().service_principal_name(),
            "TERMSRV/ts-01.corp.example"
        );
    }

    #[test]
    fn the_gcc_blocks_echo_the_protocol_the_server_selected() {
        // §2.2.1.3.2 requires it, and it is what lets the server notice that
        // the X.224 exchange was tampered with.
        let channels = static_channels(crate::clipboard::NO_CLIPBOARD);
        let blocks = client_gcc_blocks(&config(), nego::SecurityProtocol::HYBRID, &channels);
        assert_eq!(
            blocks.core.optional_data.server_selected_protocol,
            Some(nego::SecurityProtocol::HYBRID)
        );
        // And no RC4 method is offered anywhere.
        assert!(blocks.security.encryption_methods.is_empty());
        assert_eq!(blocks.security.ext_encryption_methods, 0);
    }

    #[test]
    fn the_gcc_blocks_ask_for_a_32_bit_session_and_the_message_channel() {
        let channels = static_channels(crate::clipboard::NO_CLIPBOARD);
        let blocks = client_gcc_blocks(&config(), nego::SecurityProtocol::HYBRID, &channels);
        let flags = blocks.core.optional_data.early_capability_flags.unwrap();
        assert!(flags.contains(gcc::ClientEarlyCapabilityFlags::WANT_32_BPP_SESSION));
        // Without this the server closes the connection with no explanation
        // instead of saying why.
        assert!(flags.contains(gcc::ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU));
        assert!(blocks.message_channel.is_some());
        // The dynamic channel multiplexer must be requested, or there is no
        // Display Control channel and therefore no resize.
        let network = blocks.network.unwrap();
        assert_eq!(network.channels.len(), 1);
        assert_eq!(
            network.channels[0].name,
            ironrdp::pdu::gcc::ChannelName::from_utf8("drdynvc").unwrap()
        );
    }

    #[test]
    fn the_confirmed_capabilities_enable_what_a_modern_windows_server_negotiates() {
        let desktop = DesktopSize {
            width: 1920,
            height: 1080,
        };
        let confirm = client_confirm_active(Vec::new(), desktop);
        let sets = &confirm.pdu.capability_sets;

        let surface = sets
            .iter()
            .find_map(|set| match set {
                CapabilitySet::SurfaceCommands(commands) => Some(commands),
                _ => None,
            })
            .expect("surface commands must be advertised");
        // Without SET_SURFACE_BITS the server falls back to the legacy bitmap
        // update path and colour fidelity drops.
        assert!(
            surface
                .flags
                .contains(rdp::capability_sets::CmdFlags::SET_SURFACE_BITS)
        );

        let bitmap = sets
            .iter()
            .find_map(|set| match set {
                CapabilitySet::Bitmap(bitmap) => Some(bitmap),
                _ => None,
            })
            .expect("a bitmap capability set is mandatory");
        assert_eq!(bitmap.pref_bits_per_pix, 32);
        assert_eq!(bitmap.desktop_width, 1920);
        assert_eq!(bitmap.desktop_height, 1080);
        // Required before the server accepts a dynamic resize at all.
        assert!(bitmap.desktop_resize_flag);

        assert!(
            sets.iter()
                .any(|set| matches!(set, CapabilitySet::BitmapCodecs(_))),
            "RemoteFX must be advertised"
        );
        // A cache this client does not implement, advertised, makes the server
        // send cache references nothing can resolve.
        let cache = sets
            .iter()
            .find_map(|set| match set {
                CapabilitySet::BitmapCache(cache) => Some(cache),
                _ => None,
            })
            .expect("a bitmap cache capability set is mandatory");
        assert!(cache.caches.iter().all(|entry| entry.entries == 0));
    }

    /// The maximum request size this client ends up advertising, given what
    /// the server suggested.
    fn advertised_max_request_size(server_suggested: Option<u32>) -> u32 {
        let server = server_suggested
            .map(|max_request_size| {
                CapabilitySet::MultiFragmentUpdate(rdp::capability_sets::MultifragmentUpdate {
                    max_request_size,
                })
            })
            .into_iter()
            .collect();
        client_confirm_active(server, DesktopSize::default())
            .pdu
            .capability_sets
            .iter()
            .find_map(|set| match set {
                CapabilitySet::MultiFragmentUpdate(update) => Some(update.max_request_size),
                _ => None,
            })
            .expect("a multifragment capability is always sent")
    }

    #[test]
    fn a_multifragment_buffer_the_server_names_is_clamped_to_the_one_this_build_holds() {
        // The defect this closes. §2.2.7.2.6's `MaxRequestSize` is, on the
        // client's side, the size of the buffer used to reassemble a
        // fragmented Fast-Path Update — `ironrdp-session`'s `CompleteData`,
        // inside THIS process. Echoing the server's figure back unaltered
        // handed the far end the number, and `u32::MAX` is four gigabytes of
        // it. `crate::framed::Reassembly` enforces the clamped figure, so the
        // two must be the same number or this client refuses what it invited.
        assert_eq!(
            advertised_max_request_size(Some(u32::MAX)),
            MAX_FASTPATH_REASSEMBLY_BYTES
        );
        assert_eq!(
            advertised_max_request_size(None),
            MAX_FASTPATH_REASSEMBLY_BYTES,
            "a server that sends no capability gets this build's own figure"
        );
        // And a modest suggestion is still the server's to make: clamping is a
        // ceiling, not an override.
        assert_eq!(advertised_max_request_size(Some(65_536)), 65_536);
    }

    #[test]
    fn the_servers_multifragment_capability_is_echoed_and_not_overridden() {
        // §2.2.7.2.6 leaves the maximum request size for the server to
        // suggest; anything at or below this build's own reassembly buffer is
        // taken as sent.
        let server = vec![CapabilitySet::MultiFragmentUpdate(
            rdp::capability_sets::MultifragmentUpdate {
                max_request_size: 65_536,
            },
        )];
        let confirm = client_confirm_active(server, DesktopSize::default());
        let echoed = confirm
            .pdu
            .capability_sets
            .iter()
            .find_map(|set| match set {
                CapabilitySet::MultiFragmentUpdate(update) => Some(update.max_request_size),
                _ => None,
            })
            .unwrap();
        assert_eq!(echoed, 65_536);
    }

    #[test]
    fn a_server_that_sends_no_multifragment_capability_gets_one() {
        let confirm = client_confirm_active(Vec::new(), DesktopSize::default());
        assert!(
            confirm
                .pdu
                .capability_sets
                .iter()
                .any(|set| matches!(set, CapabilitySet::MultiFragmentUpdate(_)))
        );
    }

    #[test]
    fn every_negotiation_failure_code_has_its_own_message() {
        // The one the user meets most often is HYBRID_REQUIRED_BY_SERVER, and
        // "the handshake failed" would send them to a packet capture.
        let mut rendered = std::collections::HashSet::new();
        for code in 1..=6u32 {
            assert!(
                rendered.insert(map_negotiation_failure(code).to_string()),
                "negotiation failure {code} repeats another message"
            );
        }
    }

    #[tokio::test]
    async fn a_cancelled_attempt_stops_immediately_and_frees_everything() {
        // The defect this shape exists to prevent: an earlier version leaked
        // one task and one socket per cancelled connection attempt. The
        // sequence is a future, not a task, so cancelling it drops the stream
        // and therefore the transport.
        let cancel = CancellationToken::new();
        cancel.cancel();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            with_deadline(
                &cancel,
                Duration::from_secs(3600),
                &target(),
                None,
                std::future::pending::<Result<(), ProtocolError>>(),
            ),
        )
        .await
        .expect("the sequence ignored its cancellation token");
        assert!(matches!(outcome, Err(ProtocolError::Cancelled)));
    }

    #[tokio::test]
    async fn a_server_that_stops_answering_times_out_with_the_budget_it_was_given() {
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            with_deadline(
                &CancellationToken::new(),
                Duration::from_millis(300),
                &target(),
                None,
                std::future::pending::<Result<(), ProtocolError>>(),
            ),
        )
        .await
        .expect("the sequence had no deadline");

        let Err(ProtocolError::ConnectTimeout {
            target: named,
            timeout_ms,
        }) = outcome
        else {
            panic!("expected a connect timeout, got {outcome:?}");
        };
        assert_eq!(named, target());
        // The budget the caller set, not a kernel timeout with no number.
        assert_eq!(timeout_ms, 300);
    }

    #[tokio::test]
    async fn the_deadline_is_suspended_while_a_question_is_on_screen() {
        // Comparing a certificate fingerprint out of band takes longer than
        // any server is allowed to take to answer. A deadline that counted the
        // human would time out the careful user and not the careless one.
        use remoter_proto::event_channel;

        let (_sender, prompts) = PromptChannel::new();
        let (events, mut rx) = event_channel(8);
        let asking = {
            let prompts = Arc::clone(&prompts);
            tokio::spawn(async move {
                prompts
                    .ask(
                        &events,
                        remoter_proto::PromptKind::Password,
                        String::new(),
                        false,
                    )
                    .await
            })
        };
        let _ = rx.recv().await;
        assert!(prompts.awaiting_answer());

        // A 200 ms budget against a 700 ms wait: without the suspension this
        // returns a timeout.
        let outcome = with_deadline(
            &CancellationToken::new(),
            Duration::from_millis(200),
            &target(),
            Some(prompts.as_ref()),
            async {
                tokio::time::sleep(Duration::from_millis(700)).await;
                Ok::<_, ProtocolError>(())
            },
        )
        .await;
        assert!(
            outcome.is_ok(),
            "the deadline counted the human: {outcome:?}"
        );

        asking.abort();
        let _ = asking.await;
    }

    #[test]
    fn a_windows_filetime_is_in_the_present_century() {
        // A FILETIME with the wrong epoch produces an NTLMv2 response the
        // server rejects, and nothing else looks wrong.
        let now = now_filetime();
        // 2020-01-01 and 2100-01-01 in FILETIME.
        assert!(now > 132_223_104_000_000_000, "{now}");
        assert!(now < 157_000_000_000_000_000, "{now}");
    }

    #[test]
    fn the_static_channel_set_carries_the_dynamic_channel_multiplexer() {
        let channels = static_channels(crate::clipboard::NO_CLIPBOARD);
        assert_eq!(channels.values().count(), 1);
        _assert_client_channels::<ironrdp::dvc::DrdynvcClient>();
    }

    #[test]
    fn the_clipboard_channel_is_asked_for_only_when_text_may_cross() {
        use ironrdp::cliprdr::CliprdrClient;

        _assert_client_channels::<CliprdrClient>();
        let default = static_channels(ClipboardPolicy::default());
        assert_eq!(default.values().count(), 2);
        assert!(default.get_by_type::<CliprdrClient>().is_some());

        let one_way = ClipboardPolicy {
            text_to_remote: false,
            ..ClipboardPolicy::default()
        };
        assert!(
            static_channels(one_way)
                .get_by_type::<CliprdrClient>()
                .is_some()
        );

        let none = static_channels(crate::clipboard::NO_CLIPBOARD);
        assert!(none.get_by_type::<CliprdrClient>().is_none());

        let files_only = ClipboardPolicy {
            files: true,
            ..crate::clipboard::NO_CLIPBOARD
        };
        assert!(
            static_channels(files_only)
                .get_by_type::<CliprdrClient>()
                .is_some()
        );

        // And the name the server matches it by (MS-RDPECLIP §2.1).
        let blocks = client_gcc_blocks(&config(), nego::SecurityProtocol::HYBRID, &default);
        let names: Vec<String> = blocks
            .network
            .unwrap()
            .channels
            .iter()
            .filter_map(|definition| definition.name.as_str().map(ToOwned::to_owned))
            .collect();
        assert!(names.iter().any(|name| name == "cliprdr"), "{names:?}");
    }
}
