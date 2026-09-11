//! The session supervisor: one task per session, and the registry of them.
//!
//! Two invariants shape everything here.
//!
//! **A panicked session is destroyed, never resumed** (ADR-0011). Each session
//! is its own `tokio::spawn`ed task, so a panic in a protocol decoder does not
//! propagate into the runtime — it surfaces as `JoinError::is_panic()` on the
//! handle. No `catch_unwind` is used or needed: `catch_unwind` around arbitrary
//! async code has `UnwindSafe` problems that the task boundary does not have.
//! On a panic the supervisor discards the whole session — sockets closed,
//! buffers dropped, the tab reported failed — and does not try to recover any
//! part of it. Recovering part of it is exactly the state-corruption risk that
//! made `panic = "abort"` tempting in the first place. The panic *payload* is
//! never formatted, because a payload holds formatted values and a formatted
//! value can hold a secret.
//!
//! **A leaked session is a correctness bug, not a cosmetic one.** The process
//! holds every credential its user owns; a lingering task is a lingering
//! exposure. Closing a session cancels its token and waits for the task to
//! finish releasing its resources, and a session that overstays its grace
//! period is aborted and logged as a defect rather than left running.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use remoter_core::{NodeId, ProtocolId};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;
use tokio_util::sync::CancellationToken;

use crate::coalesce::{DEFAULT_FRAME_INTERVAL, DEFAULT_MAX_FRAME_BYTES};
use crate::error::{FailureReport, ProtocolError};
use crate::event::{CloseReason, DEFAULT_EVENT_CAPACITY, EventSink, PromptAnswer, SessionEvent};
use crate::protocol::{Capabilities, ClipboardOp, InputEvent, Session, SessionKind};
use crate::transport::HostPort;

/// A session's identity, unique within one run of the application.
///
/// A counter rather than a UUID: a session is not persisted, never leaves the
/// process, and appears in log lines a human reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(u64);

impl SessionId {
    /// Wraps a raw value. For tests and for reading an id back from the
    /// interface.
    #[must_use]
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How the supervisor is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorConfig {
    /// The most sessions that may run at once. The taxonomy's "you have 32
    /// sessions open" comes from here.
    pub max_sessions: usize,
    /// Events buffered per session before the producer waits.
    pub event_capacity: usize,
    /// Commands buffered per session before the sender waits.
    pub command_capacity: usize,
    /// How often terminal output is flushed.
    pub frame_interval: Duration,
    /// The most output held back between flushes.
    pub max_frame_bytes: usize,
    /// How long a cancelled session has to release its resources before it is
    /// aborted.
    pub shutdown_grace: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            max_sessions: 32,
            event_capacity: DEFAULT_EVENT_CAPACITY,
            command_capacity: 64,
            frame_interval: DEFAULT_FRAME_INTERVAL,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// What a session is, at the moment it is registered.
#[derive(Debug, Clone)]
pub struct SessionSpec {
    /// The connection node it was opened from.
    pub node: NodeId,
    /// Which adapter is driving it.
    pub protocol: ProtocolId,
    /// What the adapter reported it can do.
    pub capabilities: Capabilities,
    /// Where it is connected.
    pub target: HostPort,
}

/// Where a session is in its life.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Running normally.
    Running,
    /// Cancelled; releasing its resources.
    Closing,
    /// Finished, for the reason given.
    Closed(CloseReason),
}

impl SessionState {
    /// Whether the session has finished.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed(_))
    }
}

/// A snapshot of a registered session, for the session list.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Its identity.
    pub id: SessionId,
    /// The connection node it was opened from.
    pub node: NodeId,
    /// Which adapter is driving it.
    pub protocol: ProtocolId,
    /// Terminal, framebuffer or file transfer.
    pub kind: SessionKind,
    /// What the adapter can do.
    pub capabilities: Capabilities,
    /// Where it is connected.
    pub target: HostPort,
    /// When it started, in milliseconds since the Unix epoch.
    pub started_at_ms: i64,
    /// Where it is in its life.
    pub state: SessionState,
}

/// A command travelling towards a session.
///
/// `Debug` is hand-written: [`InputEvent`] and [`PromptAnswer`] both carry
/// material that must not reach a log, and a derived `Debug` here would undo
/// the redaction they each implement.
pub enum SessionCommand {
    /// The tab changed size.
    Resize {
        /// New width, in columns or pixels.
        cols: u16,
        /// New height.
        rows: u16,
    },
    /// User input.
    Input(InputEvent),
    /// A clipboard operation.
    Clipboard(ClipboardOp),
    /// The answer to a prompt the session raised.
    Prompt(PromptAnswer),
    /// Disconnect cleanly.
    Disconnect,
}

impl fmt::Debug for SessionCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resize { cols, rows } => write!(f, "Resize {{ cols: {cols}, rows: {rows} }}"),
            Self::Input(input) => write!(f, "Input({input:?})"),
            Self::Clipboard(op) => write!(f, "Clipboard({op:?})"),
            Self::Prompt(answer) => write!(f, "Prompt({answer:?})"),
            Self::Disconnect => f.write_str("Disconnect"),
        }
    }
}

/// What a session task is given when it starts.
#[derive(Debug)]
pub struct SessionContext {
    /// Its identity.
    pub id: SessionId,
    /// Fires when the tab is closed or the application shuts down. Every task
    /// must terminate when it does.
    pub cancel: CancellationToken,
    /// Where its output goes. Bounded and coalescing.
    pub events: EventSink,
    /// Where its commands arrive.
    pub commands: mpsc::Receiver<SessionCommand>,
}

/// The caller's end of a session.
pub struct SessionHandle {
    info: SessionInfo,
    cancel: CancellationToken,
    commands: mpsc::Sender<SessionCommand>,
    events: Option<mpsc::Receiver<SessionEvent>>,
}

impl SessionHandle {
    /// Its identity.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.info.id
    }

    /// The snapshot taken when it was registered.
    #[must_use]
    pub const fn info(&self) -> &SessionInfo {
        &self.info
    }

    /// What the adapter reported it can do. The interface reads this rather
    /// than hardcoding a protocol's features.
    #[must_use]
    pub const fn capabilities(&self) -> &Capabilities {
        &self.info.capabilities
    }

    /// Takes the event stream. Available once: the events are a stream, not a
    /// broadcast, because dropping terminal bytes for a slow subscriber
    /// corrupts the display. Fan-out, where it is wanted, belongs to the layer
    /// that knows which consumers may be dropped.
    pub fn take_events(&mut self) -> Option<mpsc::Receiver<SessionEvent>> {
        self.events.take()
    }

    /// A clone of the cancellation token, for a task that should stop when the
    /// session does — a recorder, or a tunnel opened for this session alone.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Cancels the session without waiting for it. Use
    /// [`SessionSupervisor::close`] when the resources must be released before
    /// the caller continues.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Whether the session is still accepting commands.
    #[must_use]
    pub fn is_running(&self) -> bool {
        !self.commands.is_closed()
    }

    /// Tells the session the tab resized.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SessionClosed`] if the session has ended.
    pub async fn resize(&self, cols: u16, rows: u16) -> Result<(), ProtocolError> {
        self.command(SessionCommand::Resize { cols, rows }).await
    }

    /// Sends user input.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SessionClosed`] if the session has ended.
    pub async fn input(&self, input: InputEvent) -> Result<(), ProtocolError> {
        self.command(SessionCommand::Input(input)).await
    }

    /// Performs a clipboard operation.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SessionClosed`] if the session has ended.
    pub async fn clipboard(&self, op: ClipboardOp) -> Result<(), ProtocolError> {
        self.command(SessionCommand::Clipboard(op)).await
    }

    /// Answers a prompt the session raised.
    ///
    /// The answer travels over this channel rather than through the event
    /// stream so that it is never held longer than the challenge requires and
    /// never reaches a subscriber that only wanted to render output.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SessionClosed`] if the session has ended.
    pub async fn answer(&self, answer: PromptAnswer) -> Result<(), ProtocolError> {
        self.command(SessionCommand::Prompt(answer)).await
    }

    /// Asks the session to disconnect cleanly.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SessionClosed`] if the session has already ended.
    pub async fn disconnect(&self) -> Result<(), ProtocolError> {
        self.command(SessionCommand::Disconnect).await
    }

    async fn command(&self, command: SessionCommand) -> Result<(), ProtocolError> {
        self.commands
            .send(command)
            .await
            .map_err(|_| ProtocolError::SessionClosed)
    }
}

impl fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.info.id)
            .field("target", &self.info.target)
            .field("running", &self.is_running())
            .finish()
    }
}

/// One registered session, from the supervisor's side.
struct Entry {
    info: SessionInfo,
    cancel: CancellationToken,
    abort: AbortHandle,
    state: watch::Sender<SessionState>,
}

struct Inner {
    config: SupervisorConfig,
    next_id: AtomicU64,
    // `parking_lot`, so there is no poisoning to reason about, and never held
    // across an await: a session task must not hold a lock on shared state
    // while running decoder code (ADR-0011).
    registry: Mutex<HashMap<SessionId, Entry>>,
    root: CancellationToken,
}

/// Spawns sessions, owns the registry, and enforces what happens when one ends.
#[derive(Clone)]
pub struct SessionSupervisor {
    inner: Arc<Inner>,
}

impl SessionSupervisor {
    /// A supervisor with the given configuration.
    #[must_use]
    pub fn new(config: SupervisorConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                next_id: AtomicU64::new(1),
                registry: Mutex::new(HashMap::new()),
                root: CancellationToken::new(),
            }),
        }
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &SupervisorConfig {
        &self.inner.config
    }

    /// Spawns `body` as a session.
    ///
    /// `body` receives a [`SessionContext`] and runs until it returns or its
    /// token fires. Its return value is the reason the tab shows; an error is
    /// flattened into [`CloseReason::Failed`], and a panic into
    /// [`CloseReason::Panicked`] — one failed tab, not a failed process.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SessionLimit`] when the cap is reached.
    pub fn spawn<F, Fut>(&self, spec: SessionSpec, body: F) -> Result<SessionHandle, ProtocolError>
    where
        F: FnOnce(SessionContext) -> Fut + Send + 'static,
        Fut: Future<Output = Result<CloseReason, ProtocolError>> + Send + 'static,
    {
        let config = self.inner.config;

        // Checked before the task is spawned so that the ordinary refusal costs
        // nothing. It is checked again under the lock at registration, which is
        // the authoritative one: two concurrent spawns can both pass here.
        let open = self.len();
        if open >= config.max_sessions {
            return Err(ProtocolError::SessionLimit {
                open,
                limit: config.max_sessions,
            });
        }

        let id = SessionId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));

        let (events_tx, events_rx) = mpsc::channel(config.event_capacity.max(1));
        let (commands_tx, commands_rx) = mpsc::channel(config.command_capacity.max(1));
        let (state_tx, _state_rx) = watch::channel(SessionState::Running);

        // A child token, so that shutting the supervisor down cancels every
        // session without the supervisor having to walk the registry and race
        // with sessions removing themselves from it.
        let cancel = self.inner.root.child_token();

        let info = SessionInfo {
            id,
            node: spec.node,
            protocol: spec.protocol,
            kind: spec.capabilities.kind,
            capabilities: spec.capabilities,
            target: spec.target,
            started_at_ms: now_ms(),
            state: SessionState::Running,
        };

        let sink = EventSink::new(events_tx, config.frame_interval, config.max_frame_bytes);
        let context = SessionContext {
            id,
            cancel: cancel.clone(),
            events: sink.clone(),
            commands: commands_rx,
        };

        // The body runs in its own task; the watcher below runs in another and
        // survives the body panicking, which is what turns a panic into one
        // failed tab.
        let task = tokio::spawn(async move { body(context).await });
        let abort = task.abort_handle();

        {
            let mut registry = self.inner.registry.lock();
            if registry.len() >= config.max_sessions {
                drop(registry);
                // Nothing has been handed out yet, so aborting is enough to
                // undo the spawn; the body may not even have been polled.
                abort.abort();
                return Err(ProtocolError::SessionLimit {
                    open: self.len(),
                    limit: config.max_sessions,
                });
            }
            registry.insert(
                id,
                Entry {
                    info: info.clone(),
                    cancel: cancel.clone(),
                    abort,
                    state: state_tx,
                },
            );
        }

        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let reason = match task.await {
                Ok(Ok(reason)) => reason,
                Ok(Err(error)) => {
                    tracing::warn!(session = %id, stage = error.stage().as_str(), "session failed");
                    CloseReason::Failed(FailureReport::from(&error))
                }
                Err(join) if join.is_panic() => {
                    // ADR-0011: the location is logged, never the payload. A
                    // payload holds formatted values, and a formatted value can
                    // hold a secret. The session is destroyed whole — its
                    // transport, its buffers and its cached secrets were owned
                    // by the task and have already been dropped by the unwind.
                    tracing::error!(
                        session = %id,
                        "session task panicked; the session has been destroyed and will not be resumed"
                    );
                    CloseReason::Panicked
                }
                Err(_) => CloseReason::Aborted,
            };

            // `send` flushes the coalescer first, so output written in the
            // last frame interval — often the server's parting error message —
            // still reaches the tab, and reaches it before the close. The sink
            // is a clone, so this works even when the body panicked without
            // flushing.
            //
            // The consumer may be gone, or slow. Neither may stop the session
            // being deregistered: a registry entry that outlives its task is
            // the leak this supervisor exists to prevent.
            let _ = tokio::time::timeout(
                inner.config.shutdown_grace,
                sink.send(SessionEvent::Closed(reason.clone())),
            )
            .await;
            drop(sink);

            inner.finish(id, reason);
        });

        Ok(SessionHandle {
            info,
            cancel,
            commands: commands_tx,
            events: Some(events_rx),
        })
    }

    /// A snapshot of one registered session.
    #[must_use]
    pub fn get(&self, id: SessionId) -> Option<SessionInfo> {
        self.inner
            .registry
            .lock()
            .get(&id)
            .map(|entry| entry.info.clone())
    }

    /// Snapshots of every registered session, oldest first.
    #[must_use]
    pub fn list(&self) -> Vec<SessionInfo> {
        let mut sessions: Vec<SessionInfo> = self
            .inner
            .registry
            .lock()
            .values()
            .map(|entry| entry.info.clone())
            .collect();
        sessions.sort_by_key(|info| info.id);
        sessions
    }

    /// How many sessions are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.registry.lock().len()
    }

    /// Whether no session is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Cancels a session and waits for it to release its resources.
    ///
    /// Returns once the task has finished. A session that overruns its grace
    /// period is aborted and reported: leaked sessions are a correctness bug,
    /// so the failure is surfaced rather than logged and forgotten.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SessionClosed`] if there is no such session, or
    /// [`ProtocolError::ShutdownTimeout`] if it had to be aborted.
    pub async fn close(&self, id: SessionId) -> Result<(), ProtocolError> {
        let Some((cancel, abort, mut state)) = self.parts(id) else {
            return Err(ProtocolError::SessionClosed);
        };

        self.mark(id, SessionState::Closing);
        cancel.cancel();

        let grace = self.inner.config.shutdown_grace;
        if tokio::time::timeout(grace, wait_terminal(&mut state))
            .await
            .is_ok()
        {
            return Ok(());
        }

        abort.abort();
        tracing::error!(
            session = %id,
            grace_ms = grace.as_millis(),
            "session did not shut down within its grace period and was aborted"
        );
        // Wait for the watcher to deregister the aborted task, so that the
        // caller can rely on the session being gone when this returns.
        let _ = tokio::time::timeout(grace, wait_terminal(&mut state)).await;
        Err(ProtocolError::ShutdownTimeout {
            session: id,
            grace_ms: u64::try_from(grace.as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// Cancels every session and waits for them all.
    ///
    /// # Errors
    ///
    /// The first [`ProtocolError::ShutdownTimeout`] encountered; every session
    /// is still cancelled and awaited regardless.
    pub async fn shutdown(&self) -> Result<(), ProtocolError> {
        // One cancellation for the whole tree, so a session spawned while this
        // is running is cancelled too rather than escaping the sweep.
        self.inner.root.cancel();

        let ids: Vec<SessionId> = self.inner.registry.lock().keys().copied().collect();
        let mut first_error = None;
        for id in ids {
            if let Err(error) = self.close(id).await
                && !matches!(error, ProtocolError::SessionClosed)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn parts(
        &self,
        id: SessionId,
    ) -> Option<(
        CancellationToken,
        AbortHandle,
        watch::Receiver<SessionState>,
    )> {
        let registry = self.inner.registry.lock();
        let entry = registry.get(&id)?;
        Some((
            entry.cancel.clone(),
            entry.abort.clone(),
            entry.state.subscribe(),
        ))
    }

    fn mark(&self, id: SessionId, state: SessionState) {
        let mut registry = self.inner.registry.lock();
        if let Some(entry) = registry.get_mut(&id) {
            entry.info.state = state.clone();
            // A failure here means nobody is watching, which is fine.
            let _ = entry.state.send(state);
        }
    }
}

impl Inner {
    /// Deregisters a finished session and publishes its final state.
    fn finish(&self, id: SessionId, reason: CloseReason) {
        let Some(entry) = self.registry.lock().remove(&id) else {
            return;
        };
        // Sent after the removal so that a waiter woken by this cannot observe
        // the session both finished and still registered.
        let _ = entry.state.send(SessionState::Closed(reason));
    }
}

impl Default for SessionSupervisor {
    fn default() -> Self {
        Self::new(SupervisorConfig::default())
    }
}

impl fmt::Debug for SessionSupervisor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSupervisor")
            .field("sessions", &self.len())
            .field("limit", &self.inner.config.max_sessions)
            .finish()
    }
}

/// Waits until the watched session reaches a terminal state. A dropped sender
/// also means terminal — the entry is gone, so the session is over.
async fn wait_terminal(state: &mut watch::Receiver<SessionState>) {
    loop {
        if state.borrow_and_update().is_terminal() {
            return;
        }
        if state.changed().await.is_err() {
            return;
        }
    }
}

/// Wall-clock milliseconds. Saturating rather than fallible: a clock before
/// 1970 is not a reason to refuse a session.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Drives a [`Session`] from a [`SessionContext`] until it is cancelled, the
/// command channel closes, or a command fails.
///
/// This is the body most adapters want: connect, then hand the session here.
/// Every exit path consumes the session through
/// [`Session::disconnect`], so the protocol's goodbye is sent and the
/// resources are released on cancellation exactly as they are on a clean close.
///
/// Cancellation is immediate: commands already queued are dropped rather than
/// drained. A closed tab should not sit there replaying the keystrokes that
/// were in flight when the user closed it.
///
/// # Errors
///
/// Anything [`Session`] returns other than the failure that ends the loop,
/// which is reported through the returned [`CloseReason`] instead.
pub async fn run_session(
    mut session: Box<dyn Session>,
    mut ctx: SessionContext,
) -> Result<CloseReason, ProtocolError> {
    let reason = loop {
        tokio::select! {
            () = ctx.cancel.cancelled() => break CloseReason::ClosedByUser,
            command = ctx.commands.recv() => {
                let Some(command) = command else {
                    // Every handle is gone; nobody can drive this session
                    // again, so holding its sockets open would be a leak.
                    break CloseReason::ClosedByUser;
                };
                let outcome = match command {
                    SessionCommand::Resize { cols, rows } => session.resize(cols, rows).await,
                    SessionCommand::Input(input) => session.input(input).await,
                    SessionCommand::Clipboard(op) => session.clipboard(op).await,
                    // A prompt answer is protocol-specific: the adapter that
                    // raised the prompt owns the channel it is waiting on, and
                    // an adapter that raises none never sees one.
                    SessionCommand::Prompt(_) => Ok(()),
                    SessionCommand::Disconnect => break CloseReason::ClosedByUser,
                };
                if let Err(error) = outcome {
                    break CloseReason::Failed(FailureReport::from(&error));
                }
            }
        }
    };

    // Flush anything the adapter buffered before saying goodbye: output written
    // a microsecond before the close is still output the user wants to read.
    let _ = ctx.events.flush().await;
    if let Err(error) = session.disconnect().await {
        tracing::debug!(
            session = %ctx.id,
            stage = error.stage().as_str(),
            "the clean disconnect did not complete"
        );
    }
    Ok(reason)
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
    use crate::event::PromptId;
    use crate::protocol::{ClipboardData, ClipboardSupport};
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::sync::atomic::AtomicBool;

    fn capabilities() -> Capabilities {
        Capabilities {
            kind: SessionKind::Terminal,
            resizable: true,
            clipboard: ClipboardSupport::Text,
            file_transfer: false,
            audio: false,
            printing: false,
            multi_monitor: false,
            recordable: true,
        }
    }

    fn spec(host: &str) -> SessionSpec {
        SessionSpec {
            node: NodeId::new(),
            protocol: ProtocolId::new("ssh").unwrap(),
            capabilities: capabilities(),
            target: HostPort::new(host, 22).unwrap(),
        }
    }

    fn supervisor() -> SessionSupervisor {
        SessionSupervisor::new(SupervisorConfig {
            shutdown_grace: Duration::from_millis(250),
            ..SupervisorConfig::default()
        })
    }

    /// A body that stays alive until it is cancelled.
    ///
    /// It runs through [`run_session`] rather than awaiting the token directly
    /// because that is what an adapter does — and because a body that captures
    /// only `ctx.cancel` drops the rest of the context, closing the command
    /// channel behind it.
    async fn idle(ctx: SessionContext) -> Result<CloseReason, ProtocolError> {
        let session: Box<dyn Session> = Box::new(Recorded {
            released: Arc::new(AtomicBool::new(false)),
            resizes: Arc::new(Mutex::new(Vec::new())),
        });
        run_session(session, ctx).await
    }

    /// A session that records what it was told and whether it was released.
    struct Recorded {
        released: Arc<AtomicBool>,
        resizes: Arc<Mutex<Vec<(u16, u16)>>>,
    }

    #[async_trait]
    impl Session for Recorded {
        async fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ProtocolError> {
            self.resizes.lock().push((cols, rows));
            Ok(())
        }
        async fn input(&mut self, _input: InputEvent) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn clipboard(&mut self, _op: ClipboardOp) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn disconnect(self: Box<Self>) -> Result<(), ProtocolError> {
            self.released.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    // ── Lifecycle ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_spawned_session_is_registered_and_deregisters_when_it_ends() {
        let supervisor = supervisor();
        let mut handle = supervisor
            .spawn(spec("host.example.com"), |ctx| async move {
                ctx.events.data(b"welcome").await?;
                Ok(CloseReason::Disconnected)
            })
            .unwrap();

        let mut events = handle.take_events().unwrap();
        assert!(handle.take_events().is_none(), "the stream is taken once");

        let Some(SessionEvent::Data(frame)) = events.recv().await else {
            panic!("the session wrote output");
        };
        assert_eq!(&frame[..], b"welcome");
        assert!(matches!(
            events.recv().await,
            Some(SessionEvent::Closed(CloseReason::Disconnected))
        ));

        // The Closed event is the last one, and the registry is empty behind it.
        assert!(events.recv().await.is_none());
        assert!(supervisor.is_empty());
        assert!(supervisor.get(handle.id()).is_none());
    }

    #[tokio::test]
    async fn the_registry_lists_running_sessions() {
        let supervisor = supervisor();

        let mut handles = Vec::new();
        for host in ["a.example.com", "b.example.com"] {
            handles.push(supervisor.spawn(spec(host), idle).unwrap());
        }

        let listed = supervisor.list();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].target.host(), "a.example.com");
        assert_eq!(listed[0].kind, SessionKind::Terminal);
        assert!(listed[0].started_at_ms > 0);
        assert_eq!(listed[0].state, SessionState::Running);

        for handle in &handles {
            supervisor.close(handle.id()).await.unwrap();
        }
        assert!(supervisor.is_empty());
    }

    #[tokio::test]
    async fn the_session_limit_is_enforced_and_named() {
        let supervisor = SessionSupervisor::new(SupervisorConfig {
            max_sessions: 1,
            shutdown_grace: Duration::from_millis(250),
            ..SupervisorConfig::default()
        });
        let held = supervisor.spawn(spec("a.example.com"), idle).unwrap();

        let Err(ProtocolError::SessionLimit { open, limit }) = supervisor
            .spawn(spec("b.example.com"), |_ctx| async {
                Ok(CloseReason::Disconnected)
            })
        else {
            panic!("the second session must be refused");
        };
        assert_eq!((open, limit), (1, 1));

        supervisor.close(held.id()).await.unwrap();
    }

    // ── Panics ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_panicking_session_fails_one_tab_and_leaves_the_others_running() {
        let supervisor = supervisor();
        let survivor = supervisor
            .spawn(spec("survivor.example.com"), idle)
            .unwrap();

        let mut doomed = supervisor
            .spawn(spec("doomed.example.com"), |_ctx| async {
                // Exactly what a decoder bug on a malformed frame looks like.
                #[expect(
                    clippy::panic,
                    reason = "the behaviour under test is what happens when a session panics"
                )]
                {
                    panic!("a malformed frame");
                }
            })
            .unwrap();

        let mut events = doomed.take_events().unwrap();
        assert!(matches!(
            events.recv().await,
            Some(SessionEvent::Closed(CloseReason::Panicked))
        ));
        assert!(events.recv().await.is_none());

        // Destroyed, not resumed, and not resurrected in the registry.
        assert!(supervisor.get(doomed.id()).is_none());
        assert!(!doomed.is_running());

        // The other session is untouched: one failed tab, not a failed process.
        assert!(supervisor.get(survivor.id()).is_some());
        assert!(survivor.is_running());

        supervisor.close(survivor.id()).await.unwrap();
    }

    #[tokio::test]
    async fn a_panicking_session_reports_no_payload() {
        // ADR-0011: a payload holds formatted values, and a formatted value can
        // hold a secret, so `CloseReason::Panicked` carries nothing at all.
        let supervisor = supervisor();
        let mut handle = supervisor
            .spawn(spec("doomed.example.com"), |_ctx| async {
                #[expect(
                    clippy::panic,
                    reason = "the behaviour under test is what happens when a session panics"
                )]
                {
                    panic!("password=hunter2");
                }
            })
            .unwrap();

        let mut events = handle.take_events().unwrap();
        let Some(SessionEvent::Closed(reason)) = events.recv().await else {
            panic!("the panicking session must report a close");
        };
        assert_eq!(reason, CloseReason::Panicked);
        assert!(!format!("{reason:?}").contains("hunter2"));
    }

    #[tokio::test]
    async fn a_failing_session_reports_what_the_tab_should_show() {
        let supervisor = supervisor();
        let mut handle = supervisor
            .spawn(spec("host.example.com"), |_ctx| async {
                Err(ProtocolError::AuthCancelled)
            })
            .unwrap();

        let mut events = handle.take_events().unwrap();
        let Some(SessionEvent::Closed(CloseReason::Failed(report))) = events.recv().await else {
            panic!("a failing session must report a failure");
        };
        assert_eq!(report.stage, crate::error::Stage::Authenticate);
        assert!(!report.retryable);
    }

    // ── Cancellation and cleanup ────────────────────────────────────────────

    #[tokio::test]
    async fn cancelling_a_session_releases_its_resources_before_close_returns() {
        let supervisor = supervisor();
        let released = Arc::new(AtomicBool::new(false));
        let resizes = Arc::new(Mutex::new(Vec::new()));

        let handle = {
            let released = Arc::clone(&released);
            let resizes = Arc::clone(&resizes);
            supervisor
                .spawn(spec("host.example.com"), move |ctx| async move {
                    let session: Box<dyn Session> = Box::new(Recorded { released, resizes });
                    run_session(session, ctx).await
                })
                .unwrap()
        };

        handle.resize(120, 40).await.unwrap();
        // Cancellation is immediate and does not drain queued commands — a
        // closed tab should not wait to replay keystrokes — so wait for this
        // one to land before closing rather than racing it.
        while resizes.lock().is_empty() {
            tokio::task::yield_now().await;
        }
        supervisor.close(handle.id()).await.unwrap();

        assert!(
            released.load(Ordering::SeqCst),
            "the session must be disconnected, not merely dropped"
        );
        assert_eq!(*resizes.lock(), vec![(120, 40)]);
        assert!(supervisor.is_empty());
        assert!(!handle.is_running());
    }

    #[tokio::test]
    async fn commands_to_a_finished_session_are_refused_rather_than_lost() {
        let supervisor = supervisor();
        let handle = supervisor
            .spawn(spec("host.example.com"), |_ctx| async {
                Ok(CloseReason::Disconnected)
            })
            .unwrap();

        // Wait for the task to finish and deregister.
        while supervisor.get(handle.id()).is_some() {
            tokio::task::yield_now().await;
        }

        assert!(matches!(
            handle.resize(80, 24).await,
            Err(ProtocolError::SessionClosed)
        ));
        assert!(matches!(
            handle
                .input(InputEvent::Bytes(Bytes::from_static(b"ls\n")))
                .await,
            Err(ProtocolError::SessionClosed)
        ));
        assert!(matches!(
            handle
                .answer(PromptAnswer::cancelled(PromptId::new(1)))
                .await,
            Err(ProtocolError::SessionClosed)
        ));
        assert!(matches!(
            supervisor.close(handle.id()).await,
            Err(ProtocolError::SessionClosed)
        ));
    }

    #[tokio::test]
    async fn a_session_that_ignores_cancellation_is_aborted_and_reported() {
        let supervisor = SessionSupervisor::new(SupervisorConfig {
            shutdown_grace: Duration::from_millis(50),
            ..SupervisorConfig::default()
        });
        let handle = supervisor
            .spawn(spec("stuck.example.com"), |_ctx| async {
                // A session that never observes its token. Left alone this is
                // the leak the grace period exists to bound.
                std::future::pending::<()>().await;
                Ok(CloseReason::Disconnected)
            })
            .unwrap();

        let error = supervisor
            .close(handle.id())
            .await
            .expect_err("a stuck session must be reported, not silently abandoned");
        assert!(matches!(error, ProtocolError::ShutdownTimeout { .. }));
        assert!(
            supervisor.is_empty(),
            "an aborted session must still be deregistered"
        );
    }

    #[tokio::test]
    async fn shutdown_cancels_every_session() {
        let supervisor = supervisor();
        for host in ["a.example.com", "b.example.com", "c.example.com"] {
            supervisor.spawn(spec(host), idle).unwrap();
        }
        assert_eq!(supervisor.len(), 3);

        supervisor.shutdown().await.unwrap();
        assert!(supervisor.is_empty());
    }

    #[tokio::test]
    async fn a_session_sees_its_own_cancellation_token() {
        let supervisor = supervisor();
        let handle = supervisor.spawn(spec("host.example.com"), idle).unwrap();

        let token = handle.cancellation_token();
        assert!(!token.is_cancelled());
        handle.cancel();
        assert!(token.is_cancelled());
    }

    // ── Redaction ───────────────────────────────────────────────────────────

    #[test]
    fn a_command_never_debug_prints_what_the_user_typed() {
        let typed = SessionCommand::Input(InputEvent::Bytes(Bytes::from_static(b"hunter2\n")));
        assert!(!format!("{typed:?}").contains("hunter2"));

        let answered =
            SessionCommand::Prompt(PromptAnswer::new(PromptId::new(1), b"hunter2".to_vec()));
        assert!(!format!("{answered:?}").contains("hunter2"));

        let pasted = SessionCommand::Clipboard(ClipboardOp::Offer(ClipboardData::Text(
            "hunter2".to_owned(),
        )));
        assert!(!format!("{pasted:?}").contains("hunter2"));

        // What is left is still useful.
        assert_eq!(
            format!("{:?}", SessionCommand::Resize { cols: 80, rows: 24 }),
            "Resize { cols: 80, rows: 24 }"
        );
    }

    #[tokio::test]
    async fn the_handle_never_debug_prints_more_than_it_should() {
        let supervisor = supervisor();
        let handle = supervisor.spawn(spec("host.example.com"), idle).unwrap();
        let rendered = format!("{handle:?}");
        assert!(rendered.contains("host.example.com:22"));
        supervisor.close(handle.id()).await.unwrap();
    }
}
