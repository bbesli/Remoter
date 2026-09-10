//! The session seam: opening a session, driving it, and closing it.
//!
//! This is the nine-stage pipeline of `docs/architecture/session-pipeline.md`
//! expressed as a Tauri command. Each stage that can fail fails with its own
//! message — "connection failed" is not an acceptable outcome anywhere here,
//! and [`ipc_error`] is the table that keeps it from being one.
//!
//! # Why the events are a Channel and not a return value
//!
//! Terminal output is a byte stream, not a request and a response. The frontend
//! subscribes **once** per session by handing `session_open` a
//! [`Channel`](tauri::ipc::Channel); the core pushes into it for the life of
//! the session. Two properties of that channel matter:
//!
//! - **Terminal bytes are sent raw**, as `InvokeResponseBody::Raw`, never
//!   JSON-encoded. `docs/architecture/rendering.md` explains what the naive
//!   path costs; base64 inside JSON is roughly a 40 % size penalty plus a parse
//!   on the render thread, on the one path that has a 30 ms budget.
//! - **Output is not re-chunked.** `remoter-proto`'s `EventSink` already
//!   coalesces output at the frame interval, which is the difference between a
//!   responsive terminal and an unusable one. Each `SessionEvent::Data` is one
//!   frame, and this layer forwards it one-for-one. Splitting or re-batching
//!   here would undo the work.
//!
//! Control events — prompts, warnings, resizes, the close — travel over the
//! same channel as `InvokeResponseBody::Json`. The frontend tells them apart by
//! type: an `ArrayBuffer` is terminal output, anything else is a control event.
//!
//! # A deviation, stated outright
//!
//! This module drives `SshConnection` and `SshSession` directly rather than
//! through `remoter_proto_ssh::SshProtocol`. It is not a preference. An
//! `SshSession` is pumped by `remoter_proto_ssh::run_ssh_session`, which is the
//! only loop that polls the channel's read half; `remoter_proto::run_session`
//! waits on commands and cancellation alone, so a session driven by it would
//! produce no output at all and would not notice the server hanging up. The
//! `Protocol` trait's `connect` returns `Box<dyn Session>`, from which an
//! `SshSession` cannot be recovered — so using the trait here would mean using
//! the loop that cannot pump it. The cost is that the settings-to-connection
//! mapping below mirrors `SshProtocol::connect`; the fix belongs one layer
//! down, in an adapter that hands back a session its own runner can drive.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use remoter_core::{EffectiveConnection, GatewayHop, NodeId, NodeKind, RecordingPolicy};
use remoter_proto::{
    ChainBuilder, CloseReason, DEFAULT_HOP_TIMEOUT, EventSink, GatewayChainPlan, HopConfig,
    HostPort, InputEvent, NextAction, Prompt, PromptAnswer, PromptKind, ProtocolError,
    SessionEvent, SessionHandle, SessionId, SessionSpec, SessionSupervisor, SessionWarning,
    SettingsSchema, SupervisorConfig, TcpDialer, TrustStore, connection_target,
};
use remoter_proto_ssh::protocol::{
    SETTING_AGENT_AUTH, SETTING_AGENT_FORWARDING, SETTING_AGENT_IDENTITY, SETTING_COLUMNS,
    SETTING_COMPRESSION, SETTING_ENVIRONMENT, SETTING_EXEC_COMMAND, SETTING_INITIAL_COMMAND,
    SETTING_ROWS, SETTING_TERMINAL_TYPE,
};
use remoter_proto_ssh::{
    AlgorithmPolicy, DEFAULT_COLUMNS, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_ROWS, DEFAULT_TERM,
    PromptChannel, SSH_ID, SshConnection, SshConnectionConfig, SshHopDialer, SshSession,
    TerminalSettings, capabilities as ssh_capabilities, run_ssh_session, schema as ssh_schema,
};
use remoter_vault::SessionOnLock;
use serde::{Deserialize, Serialize};
use tauri::State;
use tauri::ipc::{Channel, InvokeResponseBody};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::bridge::{VaultCredentials, VaultTrustStore, acquire};
use crate::error::IpcError;
use crate::state::{ActivityClock, AppState, Inner};

/// How many characters of the offered fingerprint replace a changed host key.
///
/// Mirrors `remoter_proto_ssh::hostkey::REPLACEMENT_CHALLENGE_LEN`, which is not
/// re-exported. It is carried to the interface so the dialog can size its field
/// and validate before sending — never so the interface can *derive* the
/// answer, which is why the expected text itself is not sent.
const REPLACEMENT_CHALLENGE_LEN: usize = 8;

// ==================================================================== DTOs ==

/// What an adapter can do. The interface reads this rather than hardcoding
/// "SSH has no clipboard".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesDto {
    /// `"terminal" | "framebuffer" | "file_transfer"`
    pub kind: String,
    pub resizable: bool,
    /// `"none" | "text" | "text_and_files"`
    pub clipboard: String,
    pub file_transfer: bool,
    pub audio: bool,
    pub printing: bool,
    pub multi_monitor: bool,
    pub recordable: bool,
}

/// A session that authenticated and is now attached to a tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionOpenedDto {
    pub session_id: u64,
    pub node_id: String,
    /// The connection's name, as the user called it.
    pub name: String,
    /// `"ssh"` today.
    pub protocol: String,
    /// `host:port`, as connected.
    pub target: String,
    /// The account the session authenticated as. An identifier, not a secret.
    pub username: String,
    /// How authentication succeeded: `"agent"`, `"public-key"`, `"password"`,
    /// `"keyboard-interactive"`. Never what was sent.
    pub auth_method: String,
    /// The gateway names traversed, outermost first. Empty for a direct
    /// connection.
    pub via: Vec<String>,
    pub capabilities: CapabilitiesDto,
    pub started_at_ms: i64,
    /// The resolved recording policy: `"never" | "on_request" | "always"`.
    ///
    /// Reported so the tab can show the notice **before** anything is recorded.
    /// This build has no recorder; the policy is surfaced, not honoured.
    pub recording: String,
}

/// One row of the session list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummaryDto {
    pub session_id: u64,
    pub node_id: String,
    pub name: String,
    pub protocol: String,
    pub target: String,
    pub username: String,
    pub capabilities: CapabilitiesDto,
    pub started_at_ms: i64,
    /// `"connecting" | "running" | "closing"`.
    pub state: String,
    /// True while the vault is locked and the policy is `freeze_input`.
    pub frozen: bool,
}

/// The key a host was already trusted with, for the side-by-side comparison the
/// changed-key dialog is required to show.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedHostKeyDto {
    pub fingerprint: String,
    pub randomart: String,
    pub first_trusted_at_ms: i64,
}

/// A host key decision the pipeline is suspended on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyPromptDto {
    pub prompt_id: u64,
    /// Which machine, as `host:port`.
    pub host: String,
    /// The key algorithm, as named on the wire. Peer-supplied text.
    pub algorithm: String,
    /// `SHA256:…`, the value the user compares out of band.
    pub fingerprint: String,
    /// The ASCII-art rendering of the same digest.
    pub randomart: String,
    /// `"unknown"` for a first use, `"changed"` for a possible
    /// man-in-the-middle. **These are two different decisions, not one boolean**
    /// — `host_key_decide` refuses `accept` on a `"changed"` prompt.
    pub status: String,
    /// The key already trusted for this host. Present only when `status` is
    /// `"changed"`.
    pub previously_trusted: Option<TrustedHostKeyDto>,
    /// How many characters of the offered fingerprint the replacement path
    /// demands. `null` for an unknown key, which needs no typing.
    pub confirmation_len: Option<usize>,
}

/// Anything else the server asked for mid-handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptDto {
    pub prompt_id: u64,
    /// `"password" | "key_passphrase" | "keyboard_interactive" | "certificate"`
    pub kind: String,
    /// The server's text, for keyboard-interactive. Untrusted: render as text,
    /// never as markup.
    pub text: String,
    /// Whether the answer may be echoed. `false` for anything secret, and the
    /// interface must honour it.
    pub echo: bool,
}

/// Why a session ended, with everything the tab shows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionFailureDto {
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub actions: Vec<String>,
    /// Which of the nine stages failed.
    pub stage: String,
    /// Whether an automatic retry could plausibly work. **Always `false` for a
    /// changed host key**, so auto-reconnect cannot retry a possible
    /// man-in-the-middle.
    pub retryable: bool,
}

/// Progress on something long-running.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressDto {
    pub operation: String,
    pub done: u64,
    pub total: Option<u64>,
    pub detail: Option<String>,
}

/// A control event travelling to the tab over the session's channel.
///
/// Terminal output does **not** appear here: it is sent as a raw byte payload
/// on the same channel. See the module documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "event",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SessionMessageDto {
    /// The session has an id and is connecting. Sent before the handshake, so
    /// the interface can answer a host key prompt that arrives during it.
    Opening {
        session_id: u64,
    },
    /// Authentication succeeded and the shell is open.
    Ready(Box<SessionOpenedDto>),
    /// The remote display changed size.
    Resized {
        width: u16,
        height: u16,
    },
    /// The remote has something on its clipboard.
    ClipboardOffer {
        text: bool,
        files: bool,
    },
    /// A host key decision. Answer with `host_key_decide`.
    HostKey(HostKeyPromptDto),
    /// Anything else the server asked for.
    Prompt(PromptDto),
    Progress(ProgressDto),
    /// Something worth telling the user that did not end the session.
    Warning {
        /// A stable catalogue key: `unencrypted_transport`, `weak_algorithm`,
        /// `recording_started`, `output_throttled`, `banner`, `other`.
        kind: String,
        /// The detail, where the warning has one. For `banner` this is the
        /// server's text: untrusted, never markup.
        detail: Option<String>,
    },
    /// The session is over. Always the last message.
    Closed {
        /// `"disconnected" | "closed_by_user" | "application_exit" | "failed"
        /// | "panicked" | "aborted"`.
        reason: String,
        failure: Option<SessionFailureDto>,
    },
}

/// The answer to a suspended host key handshake.
///
/// The unknown and the changed paths are deliberately different variants. An
/// unknown key may be accepted with a click; a **changed** key is a possible
/// man-in-the-middle and needs the tail of the offered fingerprint copied off
/// the screen, which is the friction `docs/security/transport-security.md`
/// requires. Collapsing them into one boolean is how a blocking warning becomes
/// a dialog people dismiss with the shortcut they use for every other dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "decision",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum HostKeyDecisionDto {
    /// Trust a key nothing was stored for. Refused on a changed key.
    Accept { prompt_id: u64 },
    /// Decline. Always available, and the outcome of dismissing the dialog.
    Reject { prompt_id: u64 },
    /// Replace a key that changed. `confirmation` is the tail of the **offered**
    /// fingerprint as shown on screen — not a secret, and not something the
    /// interface may derive from the prompt.
    Replace {
        prompt_id: u64,
        confirmation: String,
    },
}

// =============================================================== the hub ===

/// Which question a suspended host key prompt is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKeyQuestion {
    /// Nothing is stored for this host and algorithm.
    Unknown,
    /// A different key is stored. A hard failure unless replaced deliberately.
    Changed,
}

/// The three things a session command needs, cloned out of the registry so the
/// lock is released before anything is awaited.
type SessionParts = (
    Arc<SessionHandle>,
    mpsc::Sender<PromptAnswer>,
    Arc<Mutex<BTreeMap<u64, HostKeyQuestion>>>,
);

/// One registered session, from this layer's side.
struct SessionEntry {
    /// Behind an `Arc` so a command can clone it out of the registry and await
    /// on it with the lock released. A session task wanting the same lock while
    /// the interface holds it across an await is the deadlock this avoids.
    handle: Arc<SessionHandle>,
    /// Where a prompt answer goes. Deliberately not the command channel: an
    /// answer must not queue behind the keystrokes of a session that has not
    /// finished connecting.
    answers: mpsc::Sender<PromptAnswer>,
    /// Host key prompts currently on screen, and which question each is asking.
    /// Written by the event forwarder, read by `host_key_decide`.
    host_keys: Arc<Mutex<BTreeMap<u64, HostKeyQuestion>>>,
    node: NodeId,
    name: String,
    target: String,
    username: String,
    started_at_ms: i64,
    connected: bool,
    /// The `sessions` row this session opened in the vault's audit log, closed
    /// when the session ends.
    audit_id: Option<Uuid>,
}

/// Everything the session and tunnel commands share.
///
/// Lives beside the vault rather than inside it: a session outlives a locked
/// vault when the policy says it should, and a lock on the vault must not be a
/// lock on the sessions.
pub(crate) struct SessionHub {
    supervisor: SessionSupervisor,
    sessions: Mutex<BTreeMap<u64, SessionEntry>>,
    pub(crate) tunnels: Mutex<BTreeMap<u64, crate::tunnel::TunnelEntry>>,
    next_tunnel: AtomicU64,
    /// Set while the vault is locked and its policy is `freeze_input`.
    frozen: AtomicBool,
}

impl std::fmt::Debug for SessionHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHub")
            .field("sessions", &self.sessions.lock().len())
            .field("tunnels", &self.tunnels.lock().len())
            .field("frozen", &self.frozen.load(Ordering::Relaxed))
            .finish()
    }
}

impl SessionHub {
    pub(crate) fn new() -> Self {
        Self {
            supervisor: SessionSupervisor::new(SupervisorConfig::default()),
            sessions: Mutex::new(BTreeMap::new()),
            tunnels: Mutex::new(BTreeMap::new()),
            next_tunnel: AtomicU64::new(1),
            frozen: AtomicBool::new(false),
        }
    }

    pub(crate) const fn supervisor(&self) -> &SessionSupervisor {
        &self.supervisor
    }

    pub(crate) fn next_tunnel_id(&self) -> u64 {
        self.next_tunnel.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::Acquire)
    }

    /// Applies the vault's `sessionOnLock` policy. Called from inside the state
    /// lock, on the way to closing the vault.
    ///
    /// `DisconnectAll` cancels rather than awaits: this runs on the thread that
    /// is locking the vault, and blocking it on a remote host's goodbye would
    /// hold the keys in memory for exactly as long as that took. The session
    /// tasks release their own resources — that is what the cancellation token
    /// is for — and the supervisor deregisters them.
    pub(crate) fn apply_lock_policy(&self, policy: SessionOnLock) {
        match policy {
            SessionOnLock::KeepRunning => {}
            SessionOnLock::FreezeInput => {
                self.frozen.store(true, Ordering::Release);
                tracing::info!("the vault locked; session input is frozen until it is unlocked");
            }
            SessionOnLock::DisconnectAll => {
                let sessions = self.sessions.lock();
                for entry in sessions.values() {
                    entry.handle.cancel();
                }
                let count = sessions.len();
                drop(sessions);

                let tunnels = self.tunnels.lock();
                for entry in tunnels.values() {
                    entry.stop();
                }
                drop(tunnels);

                if count > 0 {
                    tracing::info!("the vault locked; {count} sessions were disconnected");
                }
            }
        }
    }

    /// Lifts a freeze. Called when a vault is opened.
    pub(crate) fn thaw(&self) {
        self.frozen.store(false, Ordering::Release);
    }

    fn insert(&self, id: u64, entry: SessionEntry) {
        self.sessions.lock().insert(id, entry);
    }

    fn remove(&self, id: u64) {
        self.sessions.lock().remove(&id);
    }

    fn mark_connected(&self, id: u64) {
        if let Some(entry) = self.sessions.lock().get_mut(&id) {
            entry.connected = true;
        }
    }

    fn set_audit_id(&self, id: u64, audit_id: Uuid) {
        if let Some(entry) = self.sessions.lock().get_mut(&id) {
            entry.audit_id = Some(audit_id);
        }
    }

    /// Deregisters a finished session and hands back its audit row, so the
    /// caller can close it.
    ///
    /// The registry lock is released before this returns, and that is
    /// load-bearing: locking the vault holds `Inner` and then takes this lock,
    /// so anything that held this lock while taking `Inner` would close the
    /// cycle. Nothing in this module does.
    fn finish(&self, id: u64) -> Option<Uuid> {
        self.sessions
            .lock()
            .remove(&id)
            .and_then(|entry| entry.audit_id)
    }

    /// The pieces a command needs, cloned out so the lock is not held across an
    /// await. Holding it there is how a session task that wants the same lock
    /// deadlocks the interface.
    fn command_parts(&self, id: u64) -> Option<SessionParts> {
        let sessions = self.sessions.lock();
        let entry = sessions.get(&id)?;
        Some((
            Arc::clone(&entry.handle),
            entry.answers.clone(),
            Arc::clone(&entry.host_keys),
        ))
    }

    fn list(&self) -> Vec<SessionSummaryDto> {
        let frozen = self.is_frozen();
        let live: BTreeMap<u64, remoter_proto::SessionInfo> = self
            .supervisor
            .list()
            .into_iter()
            .map(|info| (info.id.get(), info))
            .collect();

        self.sessions
            .lock()
            .iter()
            .map(|(id, entry)| {
                let info = live.get(id);
                let state = match info.map(|i| &i.state) {
                    Some(remoter_proto::SessionState::Closing) => "closing",
                    _ if entry.connected => "running",
                    _ => "connecting",
                };
                SessionSummaryDto {
                    session_id: *id,
                    node_id: entry.node.as_uuid().to_string(),
                    name: entry.name.clone(),
                    protocol: String::from(SSH_ID),
                    target: entry.target.clone(),
                    username: entry.username.clone(),
                    capabilities: capabilities_dto(
                        &info.map_or_else(ssh_capabilities, |i| i.capabilities.clone()),
                    ),
                    started_at_ms: entry.started_at_ms,
                    state: state.to_owned(),
                    frozen: frozen && entry.connected,
                }
            })
            .collect()
    }
}

impl Default for SessionHub {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================== the plan ===

/// Everything stages 1 to 3 produced, ready for the network.
pub(crate) struct ConnectPlan {
    pub(crate) name: String,
    pub(crate) config: EffectiveConnection,
    pub(crate) target: HostPort,
    pub(crate) credentials: VaultCredentials,
    pub(crate) chain: GatewayChainPlan,
    pub(crate) labels: Vec<String>,
    pub(crate) username: String,
    pub(crate) recording: RecordingPolicy,
}

/// Stages 1 to 3 for a tunnel, which resolves the same way a session does.
///
/// A separate entry point only because a tunnel has no channel and no
/// supervisor entry; everything before the network is identical, and sharing it
/// is what keeps a tunnel's failures worded like a session's.
pub(crate) fn plan_for_tunnel(
    state: &AppState,
    trust: &Arc<dyn TrustStore>,
    node_id: &str,
) -> Result<ConnectPlan, IpcError> {
    let node = parse_node_id(node_id)?;
    let mut guard = state.lock();
    plan_connection(&mut guard, trust, node)
}

/// Stages 1 to 3, all of which touch the vault and none of which touch the
/// network.
///
/// Runs under the state lock in one pass so the tree cannot change underneath
/// the resolution, and returns before anything is dialled: the chain is
/// validated here, which is what `docs/architecture/session-pipeline.md` §2
/// means by "before anything touches the network".
fn plan_connection(
    inner: &mut Inner,
    trust: &Arc<dyn TrustStore>,
    node: NodeId,
) -> Result<ConnectPlan, IpcError> {
    // ── 1 · Resolve ────────────────────────────────────────────────────────
    let tree = {
        let vault = inner.vault_ref()?;
        vault
            .tree()
            .map_err(|err| IpcError::from_vault(&err, "this vault"))?
    };

    let name = tree
        .get(node)
        .map(|n| n.name.clone())
        .ok_or_else(|| IpcError::new(
            "session.no-such-node",
            "That connection is not in this vault any more. It may have been deleted in another window.",
        ).with_actions(["Refresh the list"]))?;

    let config = tree
        .effective_connection(node)
        .map_err(|err| IpcError::from_core(&err))?;

    if config.protocol.as_str() != SSH_ID {
        return Err(IpcError::new(
            "session.protocol-unsupported",
            format!(
                "`{name}` is a `{}` connection, and this build only opens SSH sessions.",
                config.protocol.as_str()
            ),
        )
        .with_actions(["Open its settings", "Use an SSH connection"]));
    }

    let target = connection_target(&config).map_err(|err| ipc_error(&err))?;

    // The schema is the adapter's own, so a mistyped setting is caught here
    // rather than three round trips later.
    let schema = ssh_schema();
    schema
        .validate(&config.settings)
        .map_err(|err| ipc_error(&err))?;

    // ── 3 · Acquire ────────────────────────────────────────────────────────
    // Before the hops, because a connection with no credential of its own is
    // not worth authenticating to three bastions to discover.
    let credentials = match config.credential.value.as_ref() {
        Some(reference) => acquire(inner, reference, &config.protocol, &name)?,
        None => {
            return Err(IpcError::new(
                "session.credential-required",
                format!(
                    "`{name}` has no credential, and SSH has no anonymous login. Choose one, or \
                     enter one for this attempt."
                ),
            )
            .with_actions(["Choose a credential", "Enter a credential for this attempt"]));
        }
    };

    let username = credentials
        .account()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .ok_or_else(|| {
            IpcError::new(
                "session.credential-no-username",
                format!(
                    "The credential `{name}` uses has no account name, and SSH has no anonymous \
                     login."
                ),
            )
            .with_actions(["Open the credential's settings"])
        })?
        .to_owned();

    // ── 2 · Authorise ──────────────────────────────────────────────────────
    // The hops, each with its own credential and its own trust store, then the
    // validation that rejects a chain that loops or runs too deep. No I/O yet.
    let mut hops = Vec::new();
    for (index, hop) in config.gateway.value.hops.iter().enumerate() {
        hops.push(plan_hop(inner, &tree, trust, hop, index, &name)?);
    }
    let labels: Vec<String> = hops.iter().map(|hop| hop.label.clone()).collect();
    let chain =
        GatewayChainPlan::new(target.clone(), Some(node), hops).map_err(|err| ipc_error(&err))?;

    Ok(ConnectPlan {
        name,
        recording: config.recording.value,
        config,
        target,
        credentials,
        chain,
        labels,
        username,
    })
}

/// One hop of the chain: where the gateway listens, and what authenticates to
/// it.
fn plan_hop(
    inner: &mut Inner,
    tree: &remoter_core::Tree,
    trust: &Arc<dyn TrustStore>,
    hop: &GatewayHop,
    index: usize,
    subject: &str,
) -> Result<HopConfig, IpcError> {
    let position = index + 1;
    if hop.node.is_deleted() {
        return Err(IpcError::new(
            "session.gateway-deleted",
            format!(
                "Gateway hop {position} of `{subject}` refers to a connection that has been \
                 deleted."
            ),
        )
        .with_actions(["Edit the gateway chain", "Open its settings"]));
    }

    let hop_id = hop.node.id();
    let hop_node = tree.get(hop_id).ok_or_else(|| {
        IpcError::new(
            "session.gateway-deleted",
            format!("Gateway hop {position} of `{subject}` is not in this vault any more."),
        )
        .with_actions(["Edit the gateway chain"])
    })?;
    let label = hop_node.name.clone();
    if !matches!(hop_node.kind, NodeKind::Connection(_)) {
        return Err(IpcError::new(
            "session.gateway-not-a-connection",
            format!(
                "Gateway hop {position} of `{subject}` is `{label}`, which is not a connection."
            ),
        )
        .with_actions(["Edit the gateway chain"]));
    }

    let hop_config = tree
        .effective_connection(hop_id)
        .map_err(|err| IpcError::from_core(&err))?;
    let endpoint = connection_target(&hop_config).map_err(|err| ipc_error(&err))?;

    // The hop's own credential unless the chain overrode it. Either way it is
    // this hop's, not the target's: there is no "trust the whole path because
    // the first hop was fine".
    let reference = hop
        .credential
        .clone()
        .or_else(|| hop_config.credential.value.clone())
        .ok_or_else(|| {
            IpcError::new(
                "session.gateway-credential-required",
                format!(
                    "Gateway `{label}`, hop {position}, has no credential to authenticate with."
                ),
            )
            .with_actions([
                "Choose a credential for the gateway",
                "Edit the gateway chain",
            ])
        })?;
    let credentials = acquire(inner, &reference, &hop_config.protocol, &label)?;

    Ok(HopConfig {
        node: hop_id,
        label,
        endpoint,
        protocol: hop_config.protocol.clone(),
        credentials: Arc::new(credentials),
        trust: Arc::clone(trust),
        timeout: hop_config
            .connect_timeout_ms
            .value
            .filter(|ms| *ms > 0)
            .map_or(DEFAULT_HOP_TIMEOUT, |ms| {
                Duration::from_millis(u64::from(ms))
            }),
    })
}

// ============================================================== commands ===

/// Opens a session: the nine-stage pipeline, end to end.
///
/// Returns once the far end has authenticated and a shell is open. The channel
/// is live from before the handshake, so a host key question or a 2FA prompt
/// reaches the interface while this call is still outstanding — which is what
/// "the pipeline suspends" means in practice.
#[tauri::command]
pub(crate) async fn session_open(
    state: State<'_, AppState>,
    node_id: String,
    channel: Channel<InvokeResponseBody>,
) -> Result<SessionOpenedDto, IpcError> {
    session_open_impl(&state, node_id, channel).await
}

pub(crate) async fn session_open_impl(
    state: &AppState,
    node_id: String,
    channel: Channel<InvokeResponseBody>,
) -> Result<SessionOpenedDto, IpcError> {
    let node = parse_node_id(&node_id)?;
    let hub = state.sessions();
    let trust: Arc<dyn TrustStore> = Arc::new(VaultTrustStore::new(state.inner_handle()));

    // Stages 1 to 3, under the lock, released before anything is dialled.
    let plan = {
        let mut guard = state.lock();
        plan_connection(&mut guard, &trust, node)?
    };

    // ── 2 · Authorise, continued ───────────────────────────────────────────
    let open = hub.supervisor().len();
    let limit = hub.supervisor().config().max_sessions;
    if open >= limit {
        return Err(IpcError::new(
            "session.limit",
            format!("You have {open} sessions open. Close one, or raise the limit in settings."),
        )
        .with_actions(["Close another session", "Open settings"]));
    }

    let (answers_tx, prompts) = PromptChannel::new();
    let host_keys = Arc::new(Mutex::new(BTreeMap::new()));
    let capabilities = ssh_capabilities();

    let spec = SessionSpec {
        node,
        protocol: plan.config.protocol.clone(),
        capabilities: capabilities.clone(),
        target: plan.target.clone(),
    };

    let (ready_tx, ready_rx) = oneshot::channel::<Result<Established, IpcError>>();

    let ConnectPlan {
        config,
        target,
        credentials,
        chain,
        labels,
        username,
        name,
        recording,
        ..
    } = plan;

    let body_prompts = Arc::clone(&prompts);
    let body_trust = Arc::clone(&trust);
    let body_target = target.clone();
    let body_username = username.clone();
    let body_labels = labels.clone();

    let mut handle = hub
        .supervisor()
        .spawn(spec, move |ctx| async move {
            let events = ctx.events.clone();
            let cancel = ctx.cancel.clone();

            let outcome = connect(
                &events,
                &cancel,
                &config,
                &body_target,
                &body_username,
                &body_labels,
                &credentials,
                &chain,
                Arc::clone(&body_prompts),
                body_trust,
            )
            .await;

            // Stage 6 ends here either way: the provider is dropped, and with
            // it every `Secret` buffer it held, which is what zeroizes them.
            drop(credentials);

            let session = match outcome {
                Ok(session) => session,
                Err(error) => {
                    let _ = ready_tx.send(Err(ipc_error(&error)));
                    return Err(error);
                }
            };

            let _ = ready_tx.send(Ok(Established {
                auth_method: session.connection().auth().method.as_str().to_owned(),
            }));

            // ── 8 · Run ───────────────────────────────────────────────────
            run_ssh_session(session, ctx).await
        })
        .map_err(|err| ipc_error(&err))?;

    let id = handle.id().get();
    let started_at_ms = handle.info().started_at_ms;

    // ── 7 · Attach ─────────────────────────────────────────────────────────
    // The event stream is taken and forwarded before the handshake gets going,
    // so a host key prompt has somewhere to land.
    let events = handle.take_events();
    hub.insert(
        id,
        SessionEntry {
            handle: Arc::new(handle),
            answers: answers_tx,
            host_keys: Arc::clone(&host_keys),
            node,
            name: name.clone(),
            target: target.to_string(),
            username: username.clone(),
            started_at_ms,
            connected: false,
            audit_id: None,
        },
    );

    // The interface needs the id before it can answer anything, and the
    // handshake may ask before this command returns.
    send_control(&channel, &SessionMessageDto::Opening { session_id: id });

    if let Some(events) = events {
        let forward_hub = Arc::clone(&hub);
        tokio::spawn(forward_events(
            events,
            channel.clone(),
            Arc::clone(&host_keys),
            forward_hub,
            state.inner_handle(),
            state.activity(),
            id,
        ));
    }

    let established = match ready_rx.await {
        Ok(Ok(established)) => established,
        Ok(Err(error)) => {
            hub.remove(id);
            return Err(error);
        }
        Err(_) => {
            // The body ended without answering — it panicked. ADR-0011: one
            // failed tab, and nothing about it is resumed.
            hub.remove(id);
            return Err(IpcError::new(
                "session.task-failed",
                format!(
                    "The session to `{name}` failed with an internal error and has been closed. \
                     Nothing else was affected."
                ),
            )
            .with_actions(["Try again", "Report this"]));
        }
    };

    hub.mark_connected(id);

    // ── 9 · Terminate, the first half ──────────────────────────────────────
    // The session row is opened now and closed by the event forwarder, so the
    // audit log records a session that started even if the process dies before
    // it ends. A failure to write it is logged and not raised: refusing a
    // session that is already authenticated because its bookkeeping row would
    // not write would be the wrong trade.
    let audit_id = {
        let mut guard = state.lock();
        match guard.vault_mut() {
            Ok(vault) => vault
                .session_start(
                    Some(*node.as_uuid()),
                    SSH_ID,
                    &target.to_string(),
                    Some(&username),
                )
                .ok(),
            Err(_) => None,
        }
    };
    if let Some(audit_id) = audit_id {
        hub.set_audit_id(id, audit_id);
    }

    let opened = SessionOpenedDto {
        session_id: id,
        node_id: node.as_uuid().to_string(),
        name,
        protocol: String::from(SSH_ID),
        target: target.to_string(),
        username,
        auth_method: established.auth_method,
        via: labels,
        capabilities: capabilities_dto(&capabilities),
        started_at_ms,
        recording: recording_wire(recording).to_owned(),
    };
    send_control(
        &channel,
        &SessionMessageDto::Ready(Box::new(opened.clone())),
    );
    Ok(opened)
}

/// What the body reports back once authentication has succeeded.
struct Established {
    auth_method: String,
}

/// Stages 4, 5 and 6: the chain, the handshake, the credentials.
#[allow(clippy::too_many_arguments, reason = "one argument per pipeline input")]
async fn connect(
    events: &EventSink,
    cancel: &tokio_util::sync::CancellationToken,
    config: &EffectiveConnection,
    target: &HostPort,
    username: &str,
    labels: &[String],
    credentials: &VaultCredentials,
    chain: &GatewayChainPlan,
    prompts: Arc<PromptChannel>,
    trust: Arc<dyn TrustStore>,
) -> Result<SshSession, ProtocolError> {
    // ── 4 · Transport ──────────────────────────────────────────────────────
    let entry = TcpDialer;
    let dialer =
        SshHopDialer::new(events.clone(), cancel.clone()).with_prompts(Arc::clone(&prompts));
    let transport = ChainBuilder::new(&entry, &dialer)
        .build(chain, cancel)
        .await?;

    // ── 5 · Handshake and 6 · Authenticate ─────────────────────────────────
    let schema = ssh_schema();
    let agent_forwarding = boolean(&schema, config, SETTING_AGENT_FORWARDING, false)?;

    let mut connection = SshConnectionConfig::new(target.clone(), username);
    connection.via = labels.to_vec();
    connection.algorithms = AlgorithmPolicy {
        compression: boolean(&schema, config, SETTING_COMPRESSION, false)?,
    };
    connection.allow_agent = boolean(&schema, config, SETTING_AGENT_AUTH, true)?;
    connection.agent_filter = schema
        .string(&config.settings, SETTING_AGENT_IDENTITY)
        .map(str::trim)
        .filter(|filter| !filter.is_empty())
        .map(ToOwned::to_owned);
    connection.agent_forwarding = agent_forwarding;
    connection.keepalive = config
        .keepalive_secs
        .value
        .filter(|seconds| *seconds > 0)
        .map(|seconds| Duration::from_secs(u64::from(seconds)));
    connection.handshake_timeout = config
        .connect_timeout_ms
        .value
        .filter(|ms| *ms > 0)
        .map_or(DEFAULT_HANDSHAKE_TIMEOUT, |ms| {
            Duration::from_millis(u64::from(ms))
        });

    let established = SshConnection::establish(
        transport,
        &connection,
        credentials,
        trust,
        events.clone(),
        Some(Arc::clone(&prompts)),
        cancel,
    )
    .await?;

    // ── 7 · Attach, the protocol's half ────────────────────────────────────
    let terminal = terminal_settings(&schema, config, agent_forwarding)?;
    let established = Arc::new(established);
    match schema.string(&config.settings, SETTING_EXEC_COMMAND) {
        Some(command) if !command.trim().is_empty() => {
            SshSession::open_exec(established, command, &terminal, events.clone()).await
        }
        _ => SshSession::open_shell(established, &terminal, events.clone()).await,
    }
}

/// The terminal the `pty-req` asks for.
fn terminal_settings(
    schema: &SettingsSchema,
    config: &EffectiveConnection,
    agent_forwarding: bool,
) -> Result<TerminalSettings, ProtocolError> {
    let columns = schema
        .integer(&config.settings, SETTING_COLUMNS)?
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(DEFAULT_COLUMNS);
    let rows = schema
        .integer(&config.settings, SETTING_ROWS)?
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(DEFAULT_ROWS);

    Ok(TerminalSettings {
        term: schema
            .string(&config.settings, SETTING_TERMINAL_TYPE)
            .map(str::trim)
            .filter(|term| !term.is_empty())
            .unwrap_or(DEFAULT_TERM)
            .to_owned(),
        columns,
        rows,
        environment: schema
            .string(&config.settings, SETTING_ENVIRONMENT)
            .map(parse_environment)
            .unwrap_or_default(),
        initial_command: schema
            .string(&config.settings, SETTING_INITIAL_COMMAND)
            .map(str::trim)
            .filter(|command| !command.is_empty())
            .map(ToOwned::to_owned),
        clipboard: remoter_proto::ClipboardPolicy::default(),
        agent_forwarding,
    })
}

/// `NAME=value` per line, as the settings form collects them.
fn parse_environment(raw: &str) -> Vec<(String, String)> {
    raw.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

fn boolean(
    schema: &SettingsSchema,
    config: &EffectiveConnection,
    key: &str,
    fallback: bool,
) -> Result<bool, ProtocolError> {
    Ok(schema.boolean(&config.settings, key)?.unwrap_or(fallback))
}

/// Sends keystrokes, a paste, or an IME commit to the remote host.
///
/// Refused while the vault is locked under a `freeze_input` policy. The freeze
/// is checked before the session is looked up, and deliberately: it is a
/// property of the vault rather than of one tab, so "the vault is locked" is
/// the true answer whichever session was named.
#[tauri::command]
pub(crate) async fn session_input(
    state: State<'_, AppState>,
    session_id: u64,
    bytes: Vec<u8>,
) -> Result<(), IpcError> {
    session_input_impl(&state, session_id, bytes).await
}

pub(crate) async fn session_input_impl(
    state: &AppState,
    session_id: u64,
    bytes: Vec<u8>,
) -> Result<(), IpcError> {
    let hub = state.sessions();
    if hub.is_frozen() {
        return Err(IpcError::new(
            "session.frozen",
            "The vault is locked, and this vault's policy is to freeze session input until it is \
             unlocked. The session is still connected.",
        )
        .with_actions(["Unlock the vault", "Change the policy in vault settings"]));
    }
    let (handle, ..) = hub.command_parts(session_id).ok_or_else(no_such_session)?;

    // Typing in a terminal is activity. It did not used to be: the idle clock
    // was only touched by commands that reached the vault, and a session
    // touches none, so the vault locked out from under a user who was working
    // in it. Recorded before the send rather than after, so a host that has
    // stopped reading cannot make the keystroke stop counting.
    state.activity().touch();

    handle
        .input(InputEvent::Bytes(bytes.into()))
        .await
        .map_err(|_| session_closed())
}

/// Tells the far end the tab changed size.
///
/// Not subject to the input freeze. A freeze exists so that nobody at an
/// unattended machine can type into a production shell; a window that was
/// resized while the vault was locked still has to redraw at the right width,
/// and a terminal told the wrong size draws wrongly rather than safely.
#[tauri::command]
pub(crate) async fn session_resize(
    state: State<'_, AppState>,
    session_id: u64,
    cols: u16,
    rows: u16,
) -> Result<(), IpcError> {
    session_resize_impl(&state, session_id, cols, rows).await
}

pub(crate) async fn session_resize_impl(
    state: &AppState,
    session_id: u64,
    cols: u16,
    rows: u16,
) -> Result<(), IpcError> {
    let (handle, ..) = state
        .sessions()
        .command_parts(session_id)
        .ok_or_else(no_such_session)?;
    handle
        .resize(cols, rows)
        .await
        .map_err(|_| session_closed())
}

/// Closes a session and waits for it to release everything.
///
/// Returns once the task has finished: sockets closed, buffers dropped, cached
/// secrets zeroized (ADR-0011). A session that overruns its grace period is
/// aborted, and that is reported rather than logged and forgotten — a lingering
/// task is a lingering exposure, because the process holds credentials.
#[tauri::command]
pub(crate) async fn session_close(
    state: State<'_, AppState>,
    session_id: u64,
) -> Result<(), IpcError> {
    session_close_impl(&state, session_id).await
}

pub(crate) async fn session_close_impl(state: &AppState, session_id: u64) -> Result<(), IpcError> {
    let hub = state.sessions();
    if hub.sessions.lock().get(&session_id).is_none() {
        return Err(no_such_session());
    }
    let outcome = hub
        .supervisor()
        .close(SessionId::from_raw(session_id))
        .await;
    hub.remove(session_id);
    match outcome {
        Ok(()) | Err(ProtocolError::SessionClosed) => Ok(()),
        Err(error) => Err(ipc_error(&error)),
    }
}

/// Every open session, oldest first.
#[tauri::command]
pub(crate) fn session_list(state: State<'_, AppState>) -> Result<Vec<SessionSummaryDto>, IpcError> {
    session_list_impl(&state)
}

pub(crate) fn session_list_impl(state: &AppState) -> Result<Vec<SessionSummaryDto>, IpcError> {
    Ok(state.sessions().list())
}

/// Answers a suspended host key handshake.
///
/// The two questions travel different paths on purpose. `accept` records a key
/// nothing was stored for. A **changed** key is refused by `accept` outright:
/// the only way past it is `replace`, carrying the tail of the offered
/// fingerprint copied off the screen, which the protocol layer then checks
/// itself. Nothing in this command can turn a changed key into an accepted one.
#[tauri::command]
pub(crate) async fn host_key_decide(
    state: State<'_, AppState>,
    session_id: u64,
    decision: HostKeyDecisionDto,
) -> Result<(), IpcError> {
    host_key_decide_impl(&state, session_id, decision).await
}

pub(crate) async fn host_key_decide_impl(
    state: &AppState,
    session_id: u64,
    decision: HostKeyDecisionDto,
) -> Result<(), IpcError> {
    let (_, answers, host_keys) = state
        .sessions()
        .command_parts(session_id)
        .ok_or_else(no_such_session)?;

    let prompt_id = match &decision {
        HostKeyDecisionDto::Accept { prompt_id }
        | HostKeyDecisionDto::Reject { prompt_id }
        | HostKeyDecisionDto::Replace { prompt_id, .. } => *prompt_id,
    };

    let question = host_keys.lock().get(&prompt_id).copied().ok_or_else(|| {
        IpcError::new(
            "session.no-such-prompt",
            "That host key question is no longer open. The session may have given up waiting.",
        )
        .with_actions(["Try connecting again"])
    })?;

    let answer = match (&decision, question) {
        (HostKeyDecisionDto::Accept { .. }, HostKeyQuestion::Unknown) => {
            PromptAnswer::new(remoter_proto::PromptId::new(prompt_id), b"yes".to_vec())
        }
        (HostKeyDecisionDto::Accept { .. }, HostKeyQuestion::Changed) => {
            // The rule this whole command exists for. A changed host key is a
            // possible man-in-the-middle; it must not be acceptable through the
            // path that accepts a first use.
            return Err(IpcError::new(
                "session.host-key-changed",
                "This host's key has changed since it was trusted, which can mean someone is \
                 intercepting the connection. It cannot be accepted the way a new key is: verify \
                 the fingerprint with the server's administrator first, then type the \
                 confirmation shown on screen.",
            )
            .with_actions([
                "Verify the fingerprint out of band",
                "Contact the administrator",
            ]));
        }
        (HostKeyDecisionDto::Replace { .. }, HostKeyQuestion::Unknown) => {
            return Err(IpcError::new(
                "session.host-key-nothing-to-replace",
                "Nothing is stored for this host yet, so there is no key to replace. Review the \
                 fingerprint and accept it, or decline.",
            )
            .with_actions(["Review the host key"]));
        }
        (HostKeyDecisionDto::Replace { confirmation, .. }, HostKeyQuestion::Changed) => {
            PromptAnswer::new(
                remoter_proto::PromptId::new(prompt_id),
                confirmation.trim().as_bytes().to_vec(),
            )
        }
        (HostKeyDecisionDto::Reject { .. }, _) => {
            PromptAnswer::cancelled(remoter_proto::PromptId::new(prompt_id))
        }
    };

    host_keys.lock().remove(&prompt_id);
    answers.send(answer).await.map_err(|_| session_closed())
}

// ======================================================== event forwarding ==

/// Pumps one session's events into its channel until it closes.
///
/// Terminal output goes out as a raw byte payload, one message per coalesced
/// frame. Everything else goes out as JSON on the same channel.
async fn forward_events(
    mut events: mpsc::Receiver<SessionEvent>,
    channel: Channel<InvokeResponseBody>,
    host_keys: Arc<Mutex<BTreeMap<u64, HostKeyQuestion>>>,
    hub: Arc<SessionHub>,
    inner: Arc<Mutex<Inner>>,
    activity: Arc<ActivityClock>,
    id: u64,
) {
    let mut closed_as = String::from("closed_by_user");
    while let Some(event) = events.recv().await {
        match event {
            SessionEvent::Data(bytes) => {
                // Output is activity too. `key-management.md` is explicit that
                // a session being watched but not typed into is not idle while
                // it is producing output, and this is the only place that can
                // be observed. It is an atomic store, not the vault lock: this
                // runs on the frame timer and must not queue behind a command.
                activity.touch();

                // Raw, and one message per frame. The sink upstream already
                // batched these at the frame interval; re-chunking them here is
                // the mistake `docs/architecture/rendering.md` describes.
                if channel
                    .send(InvokeResponseBody::Raw(bytes.to_vec()))
                    .is_err()
                {
                    break;
                }
            }
            SessionEvent::Resized { width, height } => {
                send_control(&channel, &SessionMessageDto::Resized { width, height });
            }
            SessionEvent::ClipboardOffer(formats) => {
                send_control(
                    &channel,
                    &SessionMessageDto::ClipboardOffer {
                        text: formats.text,
                        files: formats.files,
                    },
                );
            }
            SessionEvent::Prompt(prompt) => {
                let message = classify_prompt(&prompt, &host_keys);
                send_control(&channel, &message);
            }
            SessionEvent::Progress(update) => {
                send_control(
                    &channel,
                    &SessionMessageDto::Progress(ProgressDto {
                        operation: update.operation,
                        done: update.done,
                        total: update.total,
                        detail: update.detail,
                    }),
                );
            }
            SessionEvent::Warning(warning) => {
                let (kind, detail) = warning_wire(warning);
                send_control(&channel, &SessionMessageDto::Warning { kind, detail });
            }
            SessionEvent::Closed(reason) => {
                let (wire, failure) = close_wire(&reason);
                closed_as = wire.to_owned();
                send_control(
                    &channel,
                    &SessionMessageDto::Closed {
                        reason: wire.to_owned(),
                        failure,
                    },
                );
                break;
            }
        }
    }

    // ── 9 · Terminate ──────────────────────────────────────────────────────
    // The session is over, however it ended. Deregistering here rather than in
    // `session_close` alone is what keeps a tab the server hung up on out of
    // the session list.
    let audit_id = hub.finish(id);
    if let Some(audit_id) = audit_id {
        let mut guard = inner.lock();
        // Best effort: the vault may have been locked underneath a session the
        // policy left running, and an unwritten audit row is not a reason to
        // keep the task alive. Byte counters are not measured in this build, so
        // they are written as zero rather than guessed at.
        if let Ok(vault) = guard.vault_mut()
            && let Err(error) = vault.session_end(audit_id, &closed_as, 0, 0)
        {
            tracing::debug!(session = id, %error, "the session's audit row was not closed");
        }
    }
}

/// Turns a prompt into the message the interface renders, recording which
/// question a host key prompt is asking so the answer cannot take the other
/// path.
fn classify_prompt(
    prompt: &Prompt,
    host_keys: &Arc<Mutex<BTreeMap<u64, HostKeyQuestion>>>,
) -> SessionMessageDto {
    match &prompt.kind {
        PromptKind::HostKey {
            host,
            algorithm,
            fingerprint,
            randomart,
            previously_trusted,
        } => {
            let changed = previously_trusted.is_some();
            let question = if changed {
                HostKeyQuestion::Changed
            } else {
                HostKeyQuestion::Unknown
            };
            host_keys.lock().insert(prompt.id.get(), question);
            SessionMessageDto::HostKey(HostKeyPromptDto {
                prompt_id: prompt.id.get(),
                host: host.clone(),
                algorithm: algorithm.clone(),
                fingerprint: fingerprint.clone(),
                randomart: randomart.clone(),
                status: if changed { "changed" } else { "unknown" }.to_owned(),
                previously_trusted: previously_trusted
                    .as_ref()
                    .map(|trusted| TrustedHostKeyDto {
                        fingerprint: trusted.fingerprint.clone(),
                        randomart: trusted.randomart.clone(),
                        first_trusted_at_ms: trusted.first_trusted_at_ms,
                    }),
                confirmation_len: changed.then_some(REPLACEMENT_CHALLENGE_LEN),
            })
        }
        other => SessionMessageDto::Prompt(PromptDto {
            prompt_id: prompt.id.get(),
            kind: prompt_kind_wire(other).to_owned(),
            text: prompt.text.clone(),
            echo: prompt.echo,
        }),
    }
}

/// Serialises a control event onto the channel.
///
/// A failure means the webview is gone, which the session notices on its own
/// when the sink's consumer disappears; there is nothing useful to do here but
/// stop trying.
fn send_control(channel: &Channel<InvokeResponseBody>, message: &SessionMessageDto) {
    let Ok(json) = serde_json::to_string(message) else {
        tracing::error!("a session control event could not be encoded");
        return;
    };
    let _ = channel.send(InvokeResponseBody::Json(json));
}

// ================================================================ mapping ===

fn capabilities_dto(capabilities: &remoter_proto::Capabilities) -> CapabilitiesDto {
    CapabilitiesDto {
        kind: match capabilities.kind {
            remoter_proto::SessionKind::Terminal => "terminal",
            remoter_proto::SessionKind::Framebuffer => "framebuffer",
            remoter_proto::SessionKind::FileTransfer => "file_transfer",
        }
        .to_owned(),
        resizable: capabilities.resizable,
        clipboard: match capabilities.clipboard {
            remoter_proto::ClipboardSupport::None => "none",
            remoter_proto::ClipboardSupport::Text => "text",
            remoter_proto::ClipboardSupport::TextAndFiles => "text_and_files",
        }
        .to_owned(),
        file_transfer: capabilities.file_transfer,
        audio: capabilities.audio,
        printing: capabilities.printing,
        multi_monitor: capabilities.multi_monitor,
        recordable: capabilities.recordable,
    }
}

const fn recording_wire(policy: RecordingPolicy) -> &'static str {
    match policy {
        RecordingPolicy::Never => "never",
        RecordingPolicy::OnRequest => "on_request",
        RecordingPolicy::Always => "always",
    }
}

const fn prompt_kind_wire(kind: &PromptKind) -> &'static str {
    match kind {
        PromptKind::Password => "password",
        PromptKind::KeyPassphrase => "key_passphrase",
        PromptKind::KeyboardInteractive { .. } => "keyboard_interactive",
        PromptKind::HostKey { .. } => "host_key",
        PromptKind::Certificate { .. } => "certificate",
    }
}

fn warning_wire(warning: SessionWarning) -> (String, Option<String>) {
    match warning {
        SessionWarning::UnencryptedTransport { detail } => {
            (String::from("unencrypted_transport"), Some(detail))
        }
        SessionWarning::WeakAlgorithm { algorithm } => {
            (String::from("weak_algorithm"), Some(algorithm))
        }
        SessionWarning::RecordingStarted => (String::from("recording_started"), None),
        SessionWarning::OutputThrottled => (String::from("output_throttled"), None),
        SessionWarning::Banner { text } => (String::from("banner"), Some(text)),
        SessionWarning::Other { detail } => (String::from("other"), Some(detail)),
    }
}

fn close_wire(reason: &CloseReason) -> (&'static str, Option<SessionFailureDto>) {
    match reason {
        CloseReason::Disconnected => ("disconnected", None),
        CloseReason::ClosedByUser => ("closed_by_user", None),
        CloseReason::ApplicationExit => ("application_exit", None),
        CloseReason::Panicked => ("panicked", None),
        CloseReason::Aborted => ("aborted", None),
        CloseReason::Failed(report) => (
            "failed",
            Some(SessionFailureDto {
                code: String::from("session.failed"),
                message: report.message.clone(),
                detail: None,
                actions: report
                    .next_actions
                    .iter()
                    .copied()
                    .map(action_text)
                    .collect(),
                stage: report.stage.as_str().to_owned(),
                retryable: report.retryable,
            }),
        ),
    }
}

/// The failure taxonomy, as the interface receives it.
///
/// Every arm names what failed, names where, and offers a next action —
/// `docs/architecture/session-pipeline.md`, "Failure taxonomy". No arm falls
/// back on "connection failed": a message that only says something went wrong
/// makes the user reproduce the problem with a command-line tool, which is a
/// small admission that the application is not doing its job.
pub(crate) fn ipc_error(error: &ProtocolError) -> IpcError {
    let actions: Vec<String> = error
        .next_actions()
        .iter()
        .copied()
        .map(action_text)
        .collect();
    let (code, message) = message_for(error);
    let mut mapped = IpcError::new(&code, message).with_actions(actions);
    // The typed cause, for the "copy details" affordance. `ProtocolError`'s
    // `Display` is written under the same no-secret rule as this crate's.
    if !matches!(
        error,
        ProtocolError::Cancelled | ProtocolError::SessionClosed
    ) {
        mapped = mapped.with_detail(format!("{} ({})", error, error.stage().as_str()));
    }
    mapped
}

#[allow(
    clippy::too_many_lines,
    reason = "one arm per entry in the failure taxonomy"
)]
fn message_for(error: &ProtocolError) -> (String, String) {
    use ProtocolError as E;
    let code = |suffix: &str| format!("session.{suffix}");
    match error {
        // ── 1 · Resolve ────────────────────────────────────────────────────
        E::NoAddress => (
            code("no-address"),
            String::from("This connection has no address. Open its settings to add one."),
        ),
        E::InvalidHost { host } => (
            code("invalid-host"),
            format!(
                "`{host}` is not an address Remoter can use. Check it in the connection's settings."
            ),
        ),
        E::InvalidPort => (
            code("invalid-port"),
            String::from(
                "This connection has no usable port. Open its settings and set one between 1 and 65535.",
            ),
        ),
        E::GatewayCycle {
            label,
            position,
            total,
        } => (
            code("gateway-cycle"),
            format!(
                "The gateway chain loops back on itself: `{label}` appears at hop {position} of {total}, and again earlier in the chain."
            ),
        ),
        E::GatewayTooLong { hops, max } => (
            code("gateway-too-long"),
            format!("This gateway chain has {hops} hops; the most Remoter will walk is {max}."),
        ),
        E::GatewayHopDeleted {
            label,
            position,
            total,
        } => (
            code("gateway-deleted"),
            format!(
                "Gateway hop {position} of {total} refers to `{label}`, which has been deleted."
            ),
        ),

        // ── 2 · Authorise ──────────────────────────────────────────────────
        E::SessionLimit { open, limit } => (
            code("limit"),
            format!(
                "You have {open} sessions open; the limit is {limit}. Close one, or raise the limit in settings."
            ),
        ),

        // ── 3 · Acquire ────────────────────────────────────────────────────
        E::CredentialMissing { name } => (
            code("credential-deleted"),
            format!(
                "The credential `{name}` this connection used was deleted. Choose another, or enter one now."
            ),
        ),
        E::CredentialPurposeMismatch { allowed, attempted } => (
            code("credential-purpose"),
            format!(
                "This credential is restricted to {} and cannot be used for `{attempted}`.",
                allowed.join(", ")
            ),
        ),
        E::CredentialRequired { target } => (
            code("credential-required"),
            format!("No credential is available for `{target}`, and SSH has no anonymous login."),
        ),

        // ── 4 · Transport ──────────────────────────────────────────────────
        E::DnsFailure { host } => (
            code("dns"),
            format!("`{host}` could not be resolved. Check the name, or your DNS."),
        ),
        E::ConnectionRefused { target } => (
            code("refused"),
            format!("`{target}` refused the connection. Is the service running?"),
        ),
        E::ConnectTimeout { target, timeout_ms } => (
            code("timeout"),
            format!(
                "`{target}` did not respond within {} s. Check the firewall, or the gateway.",
                timeout_ms / 1000
            ),
        ),
        E::NetworkUnreachable { target } => (
            code("unreachable"),
            format!("`{target}` is unreachable from this machine. Check the network."),
        ),
        E::HopFailed {
            label,
            position,
            total,
            source,
        } => (
            code("hop-failed"),
            format!(
                "Could not reach the target through `{label}`. Hop {position} of {total} failed: {source}"
            ),
        ),
        E::Io { operation, source } => (code("io"), format!("{operation} failed: {source}")),

        // ── 5 · Handshake ──────────────────────────────────────────────────
        E::HostKeyUnknown {
            host,
            algorithm,
            fingerprint,
        } => (
            code("host-key-unknown"),
            format!(
                "`{host}` offered an {algorithm} key Remoter has never seen ({fingerprint}), and the session could not ask about it."
            ),
        ),
        E::HostKeyChanged {
            host,
            algorithm,
            expected,
            offered,
        } => (
            code("host-key-changed"),
            format!(
                "The {algorithm} key `{host}` offered is not the one Remoter trusts for it. This can mean someone is intercepting the connection. Trusted: {expected}. Offered: {offered}."
            ),
        ),
        E::HostKeyRejected { host, algorithm } => (
            code("host-key-rejected"),
            format!(
                "The {algorithm} key offered by `{host}` was not accepted, so the session did not continue."
            ),
        ),
        E::MalformedFingerprint => (
            code("fingerprint-malformed"),
            String::from(
                "That is not a SHA-256 fingerprint, so it could not be compared with the one the server offered.",
            ),
        ),
        E::ConfirmationMismatch => (
            code("confirmation-mismatch"),
            String::from(
                "That is not the confirmation shown on screen, so the stored host key was left alone.",
            ),
        ),
        E::NoSharedAlgorithm { kind, offered } => (
            code("no-shared-algorithm"),
            format!(
                "The server only offers {} algorithms Remoter no longer accepts: {}.",
                kind.as_str(),
                offered.join(", ")
            ),
        ),
        E::CertificateUntrusted { host, reason } => (
            code("certificate-untrusted"),
            format!(
                "The certificate for `{host}` is not trusted: {}.",
                reason.as_str()
            ),
        ),
        E::HandshakeFailed { protocol, detail } => (
            code("handshake-failed"),
            format!("The {protocol} handshake did not complete: {detail}"),
        ),
        E::TrustStore { operation, detail } => (
            code("trust-store"),
            format!(
                "The vault could not {operation}: {detail}. The host key decision was not recorded."
            ),
        ),

        // ── 6 · Authenticate ───────────────────────────────────────────────
        E::AuthRejected { attempted } => (
            code("auth-rejected"),
            format!("The server rejected these credentials ({attempted})."),
        ),
        E::AuthMethodUnavailable { attempted, offered } => (
            code("auth-method-unavailable"),
            format!(
                "The server does not accept {attempted} authentication. It offers: {}.",
                offered.join(", ")
            ),
        ),
        E::AuthCancelled => (
            code("auth-cancelled"),
            String::from("The sign-in was cancelled, so the session did not open."),
        ),
        E::AgentUnavailable => (
            code("agent-unavailable"),
            String::from("The SSH agent is not running, or this process cannot reach its socket."),
        ),

        // ── 7 · Attach ─────────────────────────────────────────────────────
        E::SettingInvalid { key, expected } => (
            code("setting-invalid"),
            format!("The setting `{key}` is not usable: it must be {expected}."),
        ),
        E::SettingRequired { key } => (
            code("setting-required"),
            format!(
                "The setting `{key}` has no value, and this connection cannot open without one."
            ),
        ),

        // ── 8 · Run ────────────────────────────────────────────────────────
        E::Unsupported {
            operation,
            protocol,
        } => (
            code("unsupported"),
            format!("`{protocol}` sessions do not support {operation}."),
        ),
        E::Disconnected { reason } => (
            code("disconnected"),
            if reason.trim().is_empty() {
                String::from("The server closed the connection.")
            } else {
                format!("The server closed the connection: {reason}")
            },
        ),
        E::NetworkLost => (
            code("network-lost"),
            String::from("The network connection was lost."),
        ),
        E::ProtocolViolation { detail } => (
            code("protocol-violation"),
            format!("The server sent something the protocol does not allow: {detail}"),
        ),
        E::Cancelled => (
            code("cancelled"),
            String::from("The session was cancelled before it opened."),
        ),
        E::SessionClosed => (
            code("closed"),
            String::from("That session is no longer running."),
        ),
        E::EventStreamClosed => (
            code("event-stream-closed"),
            String::from(
                "The session's output stream was closed before the session was, so it has been ended.",
            ),
        ),

        // ── 9 · Terminate ──────────────────────────────────────────────────
        E::Panicked { session } => (
            code("task-failed"),
            format!(
                "Session {session} failed with an internal error and has been closed. Nothing else was affected."
            ),
        ),
        E::ShutdownTimeout { session, grace_ms } => (
            code("shutdown-timeout"),
            format!(
                "Session {session} did not shut down within {grace_ms} ms and was stopped by force. This is a defect worth reporting."
            ),
        ),
        E::Internal { detail } => (
            code("internal"),
            format!("Remoter hit an internal error: {detail}. This is a defect worth reporting."),
        ),
    }
}

/// The sentence for one suggested action.
///
/// Plain sentences rather than catalogue keys because [`IpcError::actions`] is a
/// list of sentences everywhere else in this crate, and diverging on one
/// command would give the interface two things to render.
fn action_text(action: NextAction) -> String {
    match action {
        NextAction::OpenSettings => "Open this connection's settings",
        NextAction::EditGatewayChain => "Edit the gateway chain",
        NextAction::CheckAddress => "Check the address, or the DNS server that should know it",
        NextAction::CheckService => "Check that the service is listening on that port",
        NextAction::CheckFirewall => "Check the firewall, or the gateway in front of it",
        NextAction::CheckNetwork => "Check the network connection",
        NextAction::Retry => "Try again",
        NextAction::Reconnect => "Reconnect",
        NextAction::ChooseCredential => "Choose a different credential",
        NextAction::EnterCredential => "Enter a credential for this attempt",
        NextAction::ChooseAuthMethod => "Choose a different authentication method",
        NextAction::ReviewHostKey => "Review the host key",
        NextAction::VerifyFingerprintOutOfBand => {
            "Verify the fingerprint with the server's administrator before doing anything else"
        }
        NextAction::PinCertificate => "Pin the certificate to this connection",
        NextAction::CloseAnotherSession => "Close another session, or raise the limit",
        NextAction::ContactAdministrator => "Contact the server's administrator",
        NextAction::ReportDefect => "Report this — it is a defect in Remoter",
    }
    .to_owned()
}

// ================================================================= helpers ==

fn parse_node_id(text: &str) -> Result<NodeId, IpcError> {
    Uuid::parse_str(text)
        .map(NodeId::from_uuid)
        .map_err(|err| IpcError::invalid_request("nodeId", err.to_string()))
}

fn no_such_session() -> IpcError {
    IpcError::new(
        "session.no-such-session",
        "That session is not open any more. Its tab can be closed.",
    )
    .with_actions(["Close the tab"])
}

fn session_closed() -> IpcError {
    IpcError::new(
        "session.closed",
        "That session has ended, so it did not receive that.",
    )
    .with_actions(["Close the tab", "Reconnect"])
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
    use remoter_proto::{PromptId, TrustedHostKey};

    fn host_key_prompt(previously_trusted: Option<TrustedHostKey>) -> Prompt {
        Prompt {
            id: PromptId::new(7),
            kind: PromptKind::HostKey {
                host: String::from("127.0.0.1:2222"),
                algorithm: String::from("ssh-ed25519"),
                fingerprint: String::from("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                randomart: String::from("+--[ED25519 256]--+"),
                previously_trusted,
            },
            text: String::new(),
            echo: true,
        }
    }

    fn trusted() -> TrustedHostKey {
        TrustedHostKey {
            fingerprint: String::from("SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            randomart: String::from("+--[ED25519 256]--+"),
            first_trusted_at_ms: 1,
        }
    }

    #[test]
    fn an_unknown_key_and_a_changed_key_are_recorded_as_different_questions() {
        let registry = Arc::new(Mutex::new(BTreeMap::new()));

        let unknown = classify_prompt(&host_key_prompt(None), &registry);
        assert_eq!(
            registry.lock().get(&7).copied(),
            Some(HostKeyQuestion::Unknown)
        );
        let SessionMessageDto::HostKey(dto) = unknown else {
            panic!("a host key prompt should classify as one");
        };
        assert_eq!(dto.status, "unknown");
        assert!(dto.previously_trusted.is_none());
        assert!(dto.confirmation_len.is_none());

        let changed = classify_prompt(&host_key_prompt(Some(trusted())), &registry);
        assert_eq!(
            registry.lock().get(&7).copied(),
            Some(HostKeyQuestion::Changed)
        );
        let SessionMessageDto::HostKey(dto) = changed else {
            panic!("a host key prompt should classify as one");
        };
        assert_eq!(dto.status, "changed");
        // Both fingerprints, because the dialog is a comparison and a
        // comparison with one value in it is not one.
        assert!(dto.previously_trusted.is_some());
        assert_eq!(dto.confirmation_len, Some(REPLACEMENT_CHALLENGE_LEN));
    }

    #[test]
    fn a_keyboard_interactive_prompt_is_not_a_host_key_one() {
        let registry = Arc::new(Mutex::new(BTreeMap::new()));
        let prompt = Prompt {
            id: PromptId::new(3),
            kind: PromptKind::KeyboardInteractive {
                instruction: String::from("Enter your code"),
            },
            text: String::from("Verification code:"),
            echo: false,
        };
        let message = classify_prompt(&prompt, &registry);
        assert!(
            registry.lock().is_empty(),
            "only host key prompts are recorded"
        );
        let SessionMessageDto::Prompt(dto) = message else {
            panic!("expected a plain prompt");
        };
        assert_eq!(dto.kind, "keyboard_interactive");
        assert!(!dto.echo);
    }

    /// The rule the whole `host_key_decide` command exists for.
    #[tokio::test]
    async fn accepting_a_changed_host_key_is_refused_through_the_unknown_path() {
        let scratch = crate::test_support::Scratch::new();
        let Some(state) = crate::test_support::open_vault(&scratch) else {
            panic!("the fixture vault could not be created");
        };

        // A session that exists only far enough to carry a suspended prompt.
        let hub = state.sessions();
        let (answers, _prompts) = PromptChannel::new();
        let host_keys = Arc::new(Mutex::new(BTreeMap::new()));
        host_keys.lock().insert(9, HostKeyQuestion::Changed);
        let handle = hub
            .supervisor()
            .spawn(
                SessionSpec {
                    node: NodeId::new(),
                    protocol: remoter_core::ProtocolId::new(SSH_ID).unwrap(),
                    capabilities: ssh_capabilities(),
                    target: HostPort::new("127.0.0.1", 2222).unwrap(),
                },
                |ctx| async move {
                    ctx.cancel.cancelled().await;
                    Ok(CloseReason::ClosedByUser)
                },
            )
            .unwrap();
        let id = handle.id().get();
        hub.insert(
            id,
            SessionEntry {
                handle: Arc::new(handle),
                answers,
                host_keys: Arc::clone(&host_keys),
                node: NodeId::new(),
                name: String::from("db-01"),
                target: String::from("127.0.0.1:2222"),
                username: String::from("ada"),
                started_at_ms: 0,
                connected: false,
                audit_id: None,
            },
        );

        let refused =
            host_key_decide_impl(&state, id, HostKeyDecisionDto::Accept { prompt_id: 9 }).await;
        let Err(error) = refused else {
            panic!("a changed host key must not be acceptable as if it were new");
        };
        assert_eq!(error.code, "session.host-key-changed");
        // The prompt is still open: a refused decision must not consume it.
        assert!(host_keys.lock().contains_key(&9));

        // And the reverse: `replace` has nothing to replace on a first use.
        host_keys.lock().insert(10, HostKeyQuestion::Unknown);
        let refused = host_key_decide_impl(
            &state,
            id,
            HostKeyDecisionDto::Replace {
                prompt_id: 10,
                confirmation: String::from("abcdefgh"),
            },
        )
        .await;
        assert_eq!(
            refused.err().map(|e| e.code),
            Some(String::from("session.host-key-nothing-to-replace"))
        );

        let _ = session_close_impl(&state, id).await;
    }

    #[tokio::test]
    async fn a_frozen_vault_refuses_input_and_thawing_restores_it() {
        let scratch = crate::test_support::Scratch::new();
        let Some(state) = crate::test_support::open_vault(&scratch) else {
            panic!("the fixture vault could not be created");
        };
        let hub = state.sessions();

        hub.apply_lock_policy(SessionOnLock::FreezeInput);
        assert!(hub.is_frozen());
        let refused = session_input_impl(&state, 1, b"ls\n".to_vec()).await;
        assert_eq!(
            refused.err().map(|e| e.code),
            Some(String::from("session.frozen"))
        );

        hub.thaw();
        assert!(!hub.is_frozen());
        // Now it fails for the honest reason instead: there is no such session.
        let refused = session_input_impl(&state, 1, b"ls\n".to_vec()).await;
        assert_eq!(
            refused.err().map(|e| e.code),
            Some(String::from("session.no-such-session"))
        );
    }

    // --------------------------------------------- session traffic is activity

    /// Typing in a terminal is activity.
    ///
    /// It was not. The idle clock was only touched by commands that reached the
    /// vault, and a session touches none — so a user working in a shell watched
    /// the vault lock itself out from under them while they were using it.
    #[tokio::test]
    #[expect(
        clippy::panic,
        reason = "a session test without a vault has nothing left to assert"
    )]
    async fn typing_into_a_session_holds_the_idle_lock_off() {
        let scratch = crate::test_support::Scratch::new();
        let Some(state) = crate::test_support::open_vault(&scratch) else {
            panic!("the fixture vault could not be created");
        };
        let hub = state.sessions();

        // A session that exists far enough to accept a keystroke.
        let handle = hub
            .supervisor()
            .spawn(
                SessionSpec {
                    node: NodeId::new(),
                    protocol: remoter_core::ProtocolId::new(SSH_ID).unwrap(),
                    capabilities: ssh_capabilities(),
                    target: HostPort::new("127.0.0.1", 2222).unwrap(),
                },
                |ctx| async move {
                    ctx.cancel.cancelled().await;
                    Ok(CloseReason::ClosedByUser)
                },
            )
            .unwrap();
        let id = handle.id().get();
        hub.insert(
            id,
            SessionEntry {
                handle: Arc::new(handle),
                answers: PromptChannel::new().0,
                host_keys: Arc::new(Mutex::new(BTreeMap::new())),
                node: NodeId::new(),
                name: String::from("web-01"),
                target: String::from("127.0.0.1:2222"),
                username: String::from("ada"),
                started_at_ms: 0,
                connected: true,
                audit_id: None,
            },
        );

        // A day idle against the vault's fifteen minutes: the very next check
        // would lock it.
        state.lock().expire_activity();

        let typed = session_input_impl(&state, id, b"systemctl status nginx\r".to_vec()).await;
        assert!(typed.is_ok(), "the keystroke was not delivered");

        // Scoped, so the state lock is released before the await below: this
        // crate never holds it across one.
        {
            let mut guard = state.lock();
            guard.enforce_auto_lock();
            assert!(
                guard.locks_in_seconds().is_some(),
                "a keystroke sent to a session is activity, and the vault must still be open"
            );
        }

        let _ = session_close_impl(&state, id).await;
    }

    /// And output is activity too, which is the case the documentation calls
    /// out by name: a session being watched but not typed into is not idle
    /// while it is producing output.
    #[tokio::test]
    #[expect(
        clippy::panic,
        reason = "a session test without a vault has nothing left to assert"
    )]
    async fn output_arriving_from_a_host_holds_the_idle_lock_off() {
        let scratch = crate::test_support::Scratch::new();
        let Some(state) = crate::test_support::open_vault(&scratch) else {
            panic!("the fixture vault could not be created");
        };

        state.lock().expire_activity();

        let (tx, rx) = mpsc::channel(4);
        let channel = Channel::new(|_body| Ok(()));
        // One frame of output, then the far end hangs up so the forwarder ends.
        assert!(
            tx.send(SessionEvent::Data(b"deploy@web-01:~$ ".as_slice().into()))
                .await
                .is_ok()
        );
        assert!(
            tx.send(SessionEvent::Closed(CloseReason::ClosedByUser))
                .await
                .is_ok()
        );
        drop(tx);

        forward_events(
            rx,
            channel,
            Arc::new(Mutex::new(BTreeMap::new())),
            state.sessions(),
            state.inner_handle(),
            state.activity(),
            1,
        )
        .await;

        let mut guard = state.lock();
        guard.enforce_auto_lock();
        assert!(
            guard.locks_in_seconds().is_some(),
            "output kept arriving, so the session was being watched and the vault is not idle"
        );
    }

    #[test]
    fn keeping_sessions_running_is_the_default_and_freezes_nothing() {
        let hub = SessionHub::new();
        hub.apply_lock_policy(SessionOnLock::KeepRunning);
        assert!(!hub.is_frozen());
        hub.apply_lock_policy(SessionOnLock::DisconnectAll);
        assert!(!hub.is_frozen(), "disconnecting is not freezing");
    }

    /// Every failure in the taxonomy gets its own code and its own sentence.
    /// A message that only says something went wrong forces the user to
    /// reproduce the problem with a command-line tool.
    #[test]
    fn every_failure_names_what_failed_and_what_to_do() {
        let target = HostPort::new("10.0.0.5", 22).unwrap();
        let errors = vec![
            ProtocolError::NoAddress,
            ProtocolError::InvalidPort,
            ProtocolError::GatewayCycle {
                label: String::from("bastion-1"),
                position: 2,
                total: 3,
            },
            ProtocolError::SessionLimit {
                open: 32,
                limit: 32,
            },
            ProtocolError::CredentialRequired {
                target: target.clone(),
            },
            ProtocolError::DnsFailure {
                host: String::from("host.example.com"),
            },
            ProtocolError::ConnectionRefused {
                target: target.clone(),
            },
            ProtocolError::ConnectTimeout {
                target: target.clone(),
                timeout_ms: 30_000,
            },
            ProtocolError::HostKeyChanged {
                host: target.clone(),
                algorithm: String::from("ssh-ed25519"),
                expected: remoter_proto::Fingerprint::sha256(b"a"),
                offered: remoter_proto::Fingerprint::sha256(b"b"),
            },
            ProtocolError::AuthRejected {
                attempted: remoter_proto::CredentialKind::Password,
            },
            ProtocolError::Disconnected {
                reason: String::new(),
            },
            ProtocolError::Internal { detail: "a bug" },
        ];

        let mut codes = std::collections::BTreeSet::new();
        for error in &errors {
            let mapped = ipc_error(error);
            assert!(
                codes.insert(mapped.code.clone()),
                "duplicate code {}",
                mapped.code
            );
            assert!(
                mapped.message.len() > 20,
                "terse message: {}",
                mapped.message
            );
            assert!(
                mapped.message.ends_with('.') || mapped.message.ends_with('?'),
                "not a sentence: {}",
                mapped.message
            );
            assert!(!mapped.message.to_lowercase().contains("connection failed"));
        }

        // A changed host key names both fingerprints, offers no "accept", and
        // is never retryable — auto-reconnect must not walk into a possible
        // man-in-the-middle.
        let changed = ProtocolError::HostKeyChanged {
            host: target,
            algorithm: String::from("ssh-ed25519"),
            expected: remoter_proto::Fingerprint::sha256(b"a"),
            offered: remoter_proto::Fingerprint::sha256(b"b"),
        };
        assert!(!changed.is_retryable());
        let mapped = ipc_error(&changed);
        assert!(mapped.message.contains("SHA256:"));
        assert!(
            mapped
                .actions
                .iter()
                .any(|a| a.contains("Verify the fingerprint"))
        );
        assert!(
            !mapped
                .actions
                .iter()
                .any(|a| a.eq_ignore_ascii_case("Try again"))
        );
    }

    /// A hop failure keeps its cause's identity: a key that changed on
    /// `bastion-2` is not a transport problem, and must not be retried.
    #[test]
    fn a_changed_key_behind_a_gateway_is_still_a_changed_key() {
        let host = HostPort::new("bastion-2", 22).unwrap();
        let wrapped = ProtocolError::HopFailed {
            label: String::from("bastion-2"),
            position: 2,
            total: 3,
            source: Box::new(ProtocolError::HostKeyChanged {
                host,
                algorithm: String::from("ssh-ed25519"),
                expected: remoter_proto::Fingerprint::sha256(b"a"),
                offered: remoter_proto::Fingerprint::sha256(b"b"),
            }),
        };
        assert!(!wrapped.is_retryable());
        let mapped = ipc_error(&wrapped);
        assert!(mapped.message.contains("Hop 2 of 3"));
        assert!(
            mapped
                .actions
                .iter()
                .any(|a| a.contains("Verify the fingerprint")),
            "{:?}",
            mapped.actions
        );
    }

    #[test]
    fn the_channel_messages_are_camel_case_and_tagged() {
        let opening = serde_json::to_string(&SessionMessageDto::Opening { session_id: 4 }).unwrap();
        assert_eq!(opening, r#"{"event":"opening","sessionId":4}"#);

        let resized = serde_json::to_string(&SessionMessageDto::Resized {
            width: 120,
            height: 40,
        })
        .unwrap();
        assert_eq!(resized, r#"{"event":"resized","width":120,"height":40}"#);

        let closed = serde_json::to_string(&SessionMessageDto::Closed {
            reason: String::from("disconnected"),
            failure: None,
        })
        .unwrap();
        assert_eq!(
            closed,
            r#"{"event":"closed","reason":"disconnected","failure":null}"#
        );
    }

    #[test]
    fn a_host_key_decision_deserialises_from_the_shape_the_interface_sends() {
        let accept: HostKeyDecisionDto =
            serde_json::from_str(r#"{"decision":"accept","promptId":1}"#).unwrap();
        assert!(matches!(
            accept,
            HostKeyDecisionDto::Accept { prompt_id: 1 }
        ));
        let replace: HostKeyDecisionDto = serde_json::from_str(
            r#"{"decision":"replace","promptId":2,"confirmation":"abcdefgh"}"#,
        )
        .unwrap();
        let HostKeyDecisionDto::Replace {
            prompt_id,
            confirmation,
        } = replace
        else {
            panic!("expected a replacement");
        };
        assert_eq!(prompt_id, 2);
        assert_eq!(confirmation, "abcdefgh");
    }

    /// ADR-0011: a panicking session costs one tab and nothing else. The
    /// session is destroyed whole, the panic payload is never carried — a
    /// payload holds formatted values and a formatted value can hold a secret —
    /// and every other session keeps running.
    #[tokio::test]
    async fn a_panicking_session_fails_one_tab_and_no_more() {
        let hub = Arc::new(SessionHub::new());
        let spec = || SessionSpec {
            node: NodeId::new(),
            protocol: remoter_core::ProtocolId::new(SSH_ID).unwrap(),
            capabilities: ssh_capabilities(),
            target: HostPort::new("127.0.0.1", 2222).unwrap(),
        };

        // A session that survives, so the blast radius is measurable.
        let survivor = hub
            .supervisor()
            .spawn(spec(), |ctx| async move {
                // The whole context is held, not just the token: edition 2024's
                // disjoint capture would otherwise drop the command receiver
                // here and make the session look closed.
                let ctx = ctx;
                ctx.cancel.cancelled().await;
                Ok(CloseReason::ClosedByUser)
            })
            .unwrap();

        let mut doomed = hub
            .supervisor()
            .spawn(spec(), |_ctx| async move {
                panic!("a decoder fell over");
            })
            .unwrap();
        let doomed_id = doomed.id().get();
        let events = doomed.take_events().unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let channel = Channel::new(move |body| {
            if let InvokeResponseBody::Json(json) = body {
                let _ = tx.send(json);
            }
            Ok(())
        });
        hub.insert(
            doomed_id,
            SessionEntry {
                handle: Arc::new(doomed),
                answers: PromptChannel::new().0,
                host_keys: Arc::new(Mutex::new(BTreeMap::new())),
                node: NodeId::new(),
                name: String::from("doomed"),
                target: String::from("127.0.0.1:2222"),
                username: String::from("ada"),
                started_at_ms: 0,
                connected: true,
                audit_id: None,
            },
        );

        let scratch = crate::test_support::Scratch::new();
        let Some(state) = crate::test_support::open_vault(&scratch) else {
            panic!("the fixture vault could not be created");
        };
        forward_events(
            events,
            channel,
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::clone(&hub),
            state.inner_handle(),
            state.activity(),
            doomed_id,
        )
        .await;

        let mut saw_panic = false;
        while let Ok(json) = rx.try_recv() {
            if json.contains(r#""reason":"panicked""#) {
                saw_panic = true;
                // Nothing of the payload travels with it.
                assert!(!json.contains("a decoder fell over"), "{json}");
            }
        }
        assert!(saw_panic, "the tab was never told its session panicked");

        // One tab, and no more: the survivor is untouched and still registered.
        assert_eq!(
            hub.supervisor().get(survivor.id()).map(|info| info.state),
            Some(remoter_proto::SessionState::Running),
            "the panic took a session with it"
        );
        assert!(survivor.is_running());
        assert!(
            hub.sessions.lock().is_empty(),
            "the panicked session was deregistered"
        );
        assert_eq!(hub.supervisor().len(), 1, "only the survivor is left");
        survivor.cancel();
    }

    #[test]
    fn environment_lines_become_pairs_and_rubbish_is_dropped() {
        let parsed = parse_environment("LANG=en_GB.UTF-8\n  TZ = Europe/London \nnonsense\n=empty");
        assert_eq!(
            parsed,
            vec![
                (String::from("LANG"), String::from("en_GB.UTF-8")),
                (String::from("TZ"), String::from("Europe/London")),
            ]
        );
    }
}
