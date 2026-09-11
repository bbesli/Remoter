//! The interactive session: a PTY, a shell, and the loop that drives them.
//!
//! Two channel requests make a terminal (RFC 4254 §6.2 and §6.5):
//! `pty-req` with the window size and the terminal type, then `shell`. An
//! `exec` session ([`SshSession::open_exec`]) replaces the second with §6.5's
//! `exec` and usually asks for no PTY at all — a one-shot command whose output
//! is being read by a program does not want terminal escape sequences in it.
//!
//! **Backpressure is real here.** The read loop awaits [`EventSink::data`],
//! which blocks when the interface is behind. Blocking there stops draining
//! the channel, which stops `russh` adjusting the window, which stops the
//! server — the chain from a slow WebView back to a fast `yes(1)` is
//! unbroken, and nothing is dropped along the way.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use remoter_proto::{
    Capabilities, ClipboardData, ClipboardOp, ClipboardPolicy, ClipboardSupport, CloseReason,
    EventSink, FailureReport, InputEvent, ProtocolError, Session, SessionCommand, SessionContext,
    SessionEvent, SessionKind, SessionWarning,
};
use russh::client::Msg;
use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio_util::sync::CancellationToken;

use crate::connection::SshConnection;
use crate::error::{map_russh, unsupported};

/// The terminal type sent in `pty-req` when nothing else is configured.
///
/// `xterm-256color` because that is what xterm.js implements and what every
/// `terminfo` database this century has an entry for.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// The window size assumed before the interface reports its own.
pub const DEFAULT_COLUMNS: u16 = 80;
/// The window height assumed before the interface reports its own.
pub const DEFAULT_ROWS: u16 = 24;

/// The catalogue key for agent forwarding having been requested.
pub const WARNING_AGENT_FORWARDING: &str = "ssh.agent_forwarding_enabled";
/// The catalogue key for input a terminal has no encoding for.
pub const WARNING_INPUT_UNSUPPORTED: &str = "ssh.input_unsupported";
/// The catalogue key for a clipboard operation the session's policy forbids.
pub const WARNING_CLIPBOARD_POLICY: &str = "ssh.clipboard.policy_refused";
/// The catalogue key for a clipboard operation SSH has no encoding for.
pub const WARNING_CLIPBOARD_UNSUPPORTED: &str = "ssh.clipboard_unsupported";
/// The prefix every exit-signal catalogue key is built from.
///
/// See [`exit_signal_key`] for why the suffix comes from a fixed table rather
/// than from the name the server sent.
pub const WARNING_EXIT_SIGNAL_PREFIX: &str = "ssh.exit_signal.";

/// How the terminal should be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSettings {
    /// The `TERM` value sent in `pty-req`.
    pub term: String,
    /// Initial width, in columns.
    pub columns: u16,
    /// Initial height, in rows.
    pub rows: u16,
    /// Environment variables to request (RFC 4254 §6.4). Servers refuse most
    /// of these by default; a refusal is not an error.
    pub environment: Vec<(String, String)>,
    /// A command to write to the shell once it starts.
    pub initial_command: Option<String>,
    /// What clipboard traffic is allowed.
    pub clipboard: ClipboardPolicy,
    /// Whether to request agent forwarding on this channel.
    ///
    /// **Off unless asked for.** See [`crate::handler`].
    pub agent_forwarding: bool,
}

impl Default for TerminalSettings {
    fn default() -> Self {
        Self {
            term: DEFAULT_TERM.to_owned(),
            columns: DEFAULT_COLUMNS,
            rows: DEFAULT_ROWS,
            environment: Vec::new(),
            initial_command: None,
            clipboard: ClipboardPolicy::default(),
            agent_forwarding: false,
        }
    }
}

/// What this adapter can do. The interface reads it rather than hardcoding.
///
/// # `clipboard` is `None`, and that is a correction
///
/// It used to be `Text`, on the reasoning that a terminal's clipboard is text
/// by definition. What that missed is the *direction*: `clipboard_plan` below
/// refuses [`ClipboardOp::Request`] — "what does the remote have selected?" —
/// because SSH has no clipboard protocol at all. RFC 4254 defines no channel
/// request for one, and what the far end "has selected" is a property of the
/// terminal emulator on *this* side of the connection.
///
/// So the capability promised the interface a control the session then refused,
/// and the interface drew it: a clipboard button that fails in the user's hand.
/// [`ClipboardSupport`] has three values — `None`, `Text`, `TextAndFiles` — and
/// no way to say "one direction only", so of the two available answers `None`
/// is the true one. Pasting *into* the session still works for a caller that
/// sends [`ClipboardOp::Offer`]; what is withdrawn is the claim that the
/// interface may also read back. This is the same correction the VNC adapter
/// took for the same reason; the test at the foot of this file is what stops
/// the promise and the behaviour drifting apart again.
#[must_use]
pub fn capabilities() -> Capabilities {
    Capabilities {
        kind: SessionKind::Terminal,
        resizable: true,
        clipboard: ClipboardSupport::None,
        // Through SFTP on the same connection; see `crate::sftp`.
        file_transfer: true,
        audio: false,
        printing: false,
        multi_monitor: false,
        recordable: true,
    }
}

/// A live shell or `exec` on an SSH connection.
pub struct SshSession {
    write: ChannelWriteHalf<Msg>,
    read: ChannelReadHalf,
    events: EventSink,
    clipboard: ClipboardPolicy,
    exit_status: Option<u32>,
    /// Kept so the SSH session outlives the channel running on it.
    connection: Arc<SshConnection>,
    /// The catalogue keys of refusals already announced on the event stream.
    ///
    /// One entry per kind of refusal, not per refusal: a misrouted pointer
    /// event arrives as fast as a mouse moves, and the same warning at that
    /// rate is noise a user learns to dismiss. See [`SshSession::refuse`].
    refusals_announced: BTreeSet<&'static str>,
}

impl SshSession {
    /// Opens a PTY and a shell.
    ///
    /// # Errors
    ///
    /// Whatever the server said when it refused the channel or the request.
    pub async fn open_shell(
        connection: Arc<SshConnection>,
        settings: &TerminalSettings,
        events: EventSink,
    ) -> Result<Self, ProtocolError> {
        let channel = connection.open_session_channel().await?;
        request_environment(&channel, settings).await;

        if settings.agent_forwarding {
            // The channel request is only half of it: the handler must also be
            // willing to accept the channel the server opens back. Both are
            // driven from the same setting.
            channel
                .agent_forward(false)
                .await
                .map_err(|error| map_russh(&error, "request agent forwarding"))?;
            let _ = events
                .send(SessionEvent::Warning(SessionWarning::Other {
                    detail: WARNING_AGENT_FORWARDING.to_owned(),
                }))
                .await;
        }

        // RFC 4254 §6.2. The pixel dimensions are zero because a terminal
        // measured in characters has none, which is what the RFC says to send.
        channel
            .request_pty(
                true,
                &settings.term,
                u32::from(settings.columns.max(1)),
                u32::from(settings.rows.max(1)),
                0,
                0,
                &[],
            )
            .await
            .map_err(|error| map_russh(&error, "request a pseudo-terminal"))?;

        channel
            .request_shell(true)
            .await
            .map_err(|error| map_russh(&error, "request a shell"))?;

        if let Some(command) = &settings.initial_command {
            // Written as input rather than sent as `exec`: the user asked for
            // a command to run *in their shell*, and an `exec` would run it in
            // a different one with a different environment.
            let mut line = command.clone();
            line.push('\n');
            channel
                .data_bytes(bytes::Bytes::from(line.into_bytes()))
                .await
                .map_err(|error| map_russh(&error, "send the initial command"))?;
        }

        Ok(Self::from_channel(
            channel,
            connection,
            events,
            settings.clipboard,
        ))
    }

    /// Opens a one-shot `exec` (RFC 4254 §6.5).
    ///
    /// No PTY is requested: a command whose output another program will parse
    /// does not want a terminal's escape sequences in it.
    ///
    /// # Errors
    ///
    /// Whatever the server said when it refused the channel or the request.
    pub async fn open_exec(
        connection: Arc<SshConnection>,
        command: &str,
        settings: &TerminalSettings,
        events: EventSink,
    ) -> Result<Self, ProtocolError> {
        let channel = connection.open_session_channel().await?;
        request_environment(&channel, settings).await;
        channel
            .exec(true, command.as_bytes().to_vec())
            .await
            .map_err(|error| map_russh(&error, "run a command"))?;
        Ok(Self::from_channel(
            channel,
            connection,
            events,
            settings.clipboard,
        ))
    }

    fn from_channel(
        channel: russh::Channel<Msg>,
        connection: Arc<SshConnection>,
        events: EventSink,
        clipboard: ClipboardPolicy,
    ) -> Self {
        let (read, write) = channel.split();
        Self {
            write,
            read,
            events,
            clipboard,
            exit_status: None,
            connection,
            refusals_announced: BTreeSet::new(),
        }
    }

    /// The remote command's exit status, once it has reported one.
    #[must_use]
    pub const fn exit_status(&self) -> Option<u32> {
        self.exit_status
    }

    /// The connection this session runs on, for opening SFTP or a forward
    /// without authenticating again.
    #[must_use]
    pub fn connection(&self) -> &Arc<SshConnection> {
        &self.connection
    }

    /// Handles one message from the channel.
    ///
    /// `Some(reason)` means the session is over.
    async fn receive(&mut self, message: ChannelMsg) -> Option<CloseReason> {
        match message {
            // Awaiting here is the backpressure: a full event channel stops
            // this loop, which stops the window opening, which stops the far
            // end. Nothing is dropped and nothing is reordered.
            ChannelMsg::Data { data } => {
                if self.events.data(&data).await.is_err() {
                    return Some(CloseReason::ClosedByUser);
                }
            }
            // A PTY merges standard error into the same stream, so a session
            // with one never sees this. An `exec` without a PTY does, and the
            // user wants to read it: interleaved, in order, as it arrived.
            ChannelMsg::ExtendedData { data, .. } => {
                if self.events.data(&data).await.is_err() {
                    return Some(CloseReason::ClosedByUser);
                }
            }
            ChannelMsg::ExitStatus { exit_status } => self.exit_status = Some(exit_status),
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                ..
            } => {
                // The suffix comes from `exit_signal_key`, which is a fixed
                // table, and not from `{signal_name:?}`, which was what stood
                // here. See that function: the `Debug` of `russh::Sig` renders
                // the server's own bytes for any signal outside RFC 4254
                // §6.10's list, and this string is a catalogue key.
                let _ = self
                    .events
                    .send(SessionEvent::Warning(SessionWarning::Other {
                        detail: format!(
                            "{WARNING_EXIT_SIGNAL_PREFIX}{}{}",
                            exit_signal_key(&signal_name),
                            if core_dumped { ".core" } else { "" }
                        ),
                    }))
                    .await;
            }
            ChannelMsg::Eof | ChannelMsg::Close => return Some(CloseReason::Disconnected),
            ChannelMsg::OpenFailure(_) => {
                return Some(CloseReason::Failed(FailureReport::from(
                    &ProtocolError::Disconnected {
                        reason: "ssh.channel_refused".to_owned(),
                    },
                )));
            }
            // Window adjustments and request acknowledgements are `russh`'s
            // business; there is nothing for a terminal to do with them.
            _ => {}
        }
        None
    }

    /// Refuses an operation, and says so somewhere a user can see it.
    ///
    /// The defect this exists to stop coming back: a refusal that lived only
    /// in the returned `Err`. `SessionCommand` carries no reply channel, so
    /// nothing hands a command's result back to whoever issued it, and
    /// [`run_ssh_session`] matched `ProtocolError::Unsupported` into a
    /// `tracing::debug!` — which is not a place a user looks. The interface
    /// then drew a control, the control did nothing, and nothing on screen
    /// explained why. A failure the user is never told about is
    /// indistinguishable from a feature that does not work.
    ///
    /// The `Err` is still returned, so a caller holding this session directly
    /// gets the typed failure and the loop still declines to end a working
    /// shell over it. What changes is that the event stream carries the same
    /// fact, once per `key` per session.
    async fn refuse(&mut self, operation: &'static str, key: &'static str) -> ProtocolError {
        announce_refusal(&self.events, &mut self.refusals_announced, operation, key).await
    }
}

/// The body of [`SshSession::refuse`], with nothing of a session in it.
///
/// Split out for one reason: `russh::Channel::new` is `pub(crate)`, so an
/// [`SshSession`] cannot exist without a real SSH handshake against a real
/// server, and this crate's only such tests are the Docker-gated ones in
/// `tests/live_server.rs`. Keeping the rule — *a refusal is announced, once
/// per key* — in a function that takes only an [`EventSink`] and the set is
/// what puts it inside reach of an ordinary unit test. The companion guard is
/// `every_refusal_in_this_file_is_announced`, which checks that no refusal in
/// this file goes around it.
async fn announce_refusal(
    events: &EventSink,
    announced: &mut BTreeSet<&'static str>,
    operation: &'static str,
    key: &'static str,
) -> ProtocolError {
    if announced.insert(key) {
        // Deliberately ignored. A closed event stream means the terminal is
        // already gone and the loop is ending the session on its own account;
        // turning this into `EventStreamClosed` would replace a true statement
        // about the operation with a misleading one about the channel.
        let _ = events
            .send(SessionEvent::Warning(SessionWarning::Other {
                detail: key.to_owned(),
            }))
            .await;
    }
    unsupported(operation)
}

/// Names a signal from a fixed table, never from what the server sent.
///
/// RFC 4254 §6.10 lists twelve signal names and then says a server may send
/// any other name it likes, so `russh` models the field as
/// `Sig::Custom(String)` — a string whose contents and length the far end
/// chooses. `docs/security/threat-model.md` puts a hostile server in scope,
/// and two things follow that the code here used to get wrong.
///
/// **The key stopped being a key.** `format!("ssh.exit_signal.{signal_name:?}")`
/// renders `Custom("whatever the server wrote")` for that variant, quotation
/// marks, escapes and all. The comment above the call claimed the opposite —
/// that `Debug` renders the §6.10 constant "and nothing the server wrote" —
/// which is true for the twelve named variants and false for the thirteenth.
/// So a `SessionWarning::Other` detail, which a translator looks up and which
/// the tab renders, could be arbitrary remote prose.
///
/// **And the allocation was sized by the far end.** The `format!` copied that
/// string at whatever length it arrived. `russh` has already parsed and
/// allocated it by the time it reaches here, so the ceiling that bounds the
/// *first* copy is upstream and is not this crate's to place — what this
/// removes is the second copy, made in an adapter that had no bound of its
/// own. A cap on the second copy would never have bounded the first; a table
/// with no copy in it at all is the version that does not need one.
///
/// Every result is one of these literals, so the catalogue has a finite set of
/// keys and a server contributes no bytes to any of them. An unrecognised
/// signal becomes `other`: the fact that the shell was killed is what the user
/// needs, and the name the server invented for it is not worth the hole.
const fn exit_signal_key(signal: &russh::Sig) -> &'static str {
    use russh::Sig;
    match signal {
        Sig::ABRT => "ABRT",
        Sig::ALRM => "ALRM",
        Sig::FPE => "FPE",
        Sig::HUP => "HUP",
        Sig::ILL => "ILL",
        Sig::INT => "INT",
        Sig::KILL => "KILL",
        Sig::PIPE => "PIPE",
        Sig::QUIT => "QUIT",
        Sig::SEGV => "SEGV",
        Sig::TERM => "TERM",
        Sig::USR1 => "USR1",
        Sig::Custom(_) => "other",
    }
}

/// What [`SshSession::clipboard`] will do with an operation.
///
/// Split out of the method so that the decision can be checked against
/// [`capabilities`] without a channel, a server or a socket. A capability is a
/// promise, and the only way to stop a promise drifting from the behaviour that
/// keeps it is to put both within reach of one test.
///
/// There is deliberately no `Debug`: the `Paste` variant holds clipboard text,
/// which is a password often enough that CLAUDE.md §0.2 applies to it.
enum ClipboardPlan {
    /// Write these bytes to the channel.
    Paste(bytes::Bytes),
    /// Nothing to send, and nothing to report.
    Nothing,
    /// Refused: the operation for the taxonomy, and the catalogue key the user
    /// is told about it under.
    Refuse {
        /// What was asked for, as `ProtocolError::Unsupported` reports it.
        operation: &'static str,
        /// The message-catalogue key the tab renders.
        key: &'static str,
    },
}

/// Decides what one clipboard operation means to a terminal.
fn clipboard_plan(op: ClipboardOp) -> ClipboardPlan {
    match op {
        // Pasting into a terminal *is* writing bytes to it. Bracketed paste, if
        // the remote asked for it, is the emulator's business: it is the thing
        // that knows whether the application enabled it.
        ClipboardOp::Offer(ClipboardData::Text(text)) => {
            ClipboardPlan::Paste(bytes::Bytes::from(text.into_bytes()))
        }
        ClipboardOp::Offer(ClipboardData::Files(_)) => ClipboardPlan::Refuse {
            operation: "offering files to a terminal",
            key: WARNING_CLIPBOARD_UNSUPPORTED,
        },
        // There is no channel for this: SSH has no clipboard protocol, and what
        // the remote "has selected" is a property of the emulator on this side
        // of the connection. `capabilities` reports `ClipboardSupport::None`
        // **because** of this line.
        ClipboardOp::Request { .. } => ClipboardPlan::Refuse {
            operation: "reading the remote clipboard",
            key: WARNING_CLIPBOARD_UNSUPPORTED,
        },
        // Nothing crosses the wire, so there is nothing to fail at.
        ClipboardOp::Clear => ClipboardPlan::Nothing,
    }
}

/// Sends the configured environment. Refusals are expected and ignored.
///
/// RFC 4254 §6.4 lets a server accept or refuse each variable, and OpenSSH
/// refuses everything outside `AcceptEnv` by default. Treating that as a
/// failure would make a perfectly good session fail over a `LANG`.
async fn request_environment(channel: &russh::Channel<Msg>, settings: &TerminalSettings) {
    for (name, value) in &settings.environment {
        if channel
            .set_env(false, name.clone(), value.clone())
            .await
            .is_err()
        {
            tracing::debug!(
                variable = name,
                "the server refused an environment variable"
            );
        }
    }
}

#[async_trait]
impl Session for SshSession {
    async fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ProtocolError> {
        // RFC 4254 §6.7. Zero would tell the remote its terminal has no size,
        // and applications react to that by drawing nothing.
        self.write
            .window_change(u32::from(cols.max(1)), u32::from(rows.max(1)), 0, 0)
            .await
            .map_err(|error| map_russh(&error, "change the window size"))
    }

    async fn input(&mut self, input: InputEvent) -> Result<(), ProtocolError> {
        match input {
            InputEvent::Bytes(bytes) => self
                .write
                .data_bytes(bytes)
                .await
                .map_err(|error| map_russh(&error, "send input")),
            // A terminal's input is a byte stream. Scancodes and pointer
            // events belong to the framebuffer protocols, and translating one
            // into the other here would be a second, divergent implementation
            // of what the terminal emulator already does correctly.
            InputEvent::Key { .. } => Err(self
                .refuse("scancode input", WARNING_INPUT_UNSUPPORTED)
                .await),
            InputEvent::Pointer { .. } => Err(self
                .refuse("pointer input", WARNING_INPUT_UNSUPPORTED)
                .await),
        }
    }

    async fn clipboard(&mut self, op: ClipboardOp) -> Result<(), ProtocolError> {
        if !self.clipboard.permits(&op) {
            return Err(self
                .refuse("this clipboard operation", WARNING_CLIPBOARD_POLICY)
                .await);
        }
        match clipboard_plan(op) {
            ClipboardPlan::Paste(bytes) => self
                .write
                .data_bytes(bytes)
                .await
                .map_err(|error| map_russh(&error, "paste into the session")),
            ClipboardPlan::Nothing => Ok(()),
            ClipboardPlan::Refuse { operation, key } => Err(self.refuse(operation, key).await),
        }
    }

    async fn disconnect(self: Box<Self>) -> Result<(), ProtocolError> {
        // EOF then close, in that order (RFC 4254 §5.3): a shell reading its
        // input sees the stream end and exits, rather than being cut off
        // mid-write.
        let _ = self.write.eof().await;
        let _ = self.write.close().await;
        self.connection.disconnect().await
    }
}

impl std::fmt::Debug for SshSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshSession")
            .field("target", self.connection.target())
            .field("exit_status", &self.exit_status)
            .finish()
    }
}

/// How long until the buffered frame is due, or `None` if the tab was closed
/// while asking.
///
/// `EventSink::frame_deadline` takes the coalescer's lock, and another task
/// holds that lock across an await whenever the event channel is full — a
/// consumer that has stopped reading is exactly when a user closes the tab. A
/// bare `.await` outside the loop's `select!` would therefore wait on that
/// lock instead of on the cancellation token, and the session would sit there.
async fn frame_deadline_or_cancelled(
    events: &EventSink,
    cancel: &CancellationToken,
) -> Option<Option<Duration>> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => None,
        deadline = events.frame_deadline() => Some(deadline),
    }
}

/// Drives an [`SshSession`] until it ends.
///
/// This is the body an SSH tab is spawned with. It exists alongside
/// `remoter_proto::run_session` rather than instead of it because that loop
/// waits only on commands and cancellation: it has no way to notice the
/// *server* closing the channel, so a `logout` would leave the tab sitting
/// there until the user closed it. This loop selects on the channel as well,
/// and reports [`CloseReason::Disconnected`] when the far end goes.
///
/// # Errors
///
/// Never returns `Err`: every failure is folded into the [`CloseReason`] the
/// tab shows, which is what the supervisor expects.
pub async fn run_ssh_session(
    mut session: SshSession,
    mut ctx: SessionContext,
) -> Result<CloseReason, ProtocolError> {
    let reason = loop {
        // Only armed when something is buffered, so an idle session wakes for
        // nothing. `EventSink` coalesces terminal output at the frame
        // interval; without this timer the last chunk of a burst would sit in
        // the buffer until the next byte arrived.
        //
        // Read *inside* a race with cancellation rather than before it:
        // `frame_deadline` takes the coalescer's lock, which another task
        // holds across its own await, so a closed tab could otherwise wait on
        // a lock instead of stopping. CLAUDE.md §5 requires a closed tab to
        // terminate its task deterministically.
        let Some(deadline) = frame_deadline_or_cancelled(&session.events, &ctx.cancel).await else {
            break CloseReason::ClosedByUser;
        };

        tokio::select! {
            () = ctx.cancel.cancelled() => break CloseReason::ClosedByUser,

            () = async {
                match deadline {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => std::future::pending().await,
                }
            } => {
                if session.events.flush().await.is_err() {
                    break CloseReason::ClosedByUser;
                }
            }

            message = session.read.wait() => {
                let Some(message) = message else {
                    break CloseReason::Disconnected;
                };
                if let Some(reason) = session.receive(message).await {
                    break reason;
                }
            }

            command = ctx.commands.recv() => {
                let Some(command) = command else {
                    // Every handle is gone; nobody can drive this session
                    // again, so holding its channel open would be a leak.
                    break CloseReason::ClosedByUser;
                };
                let outcome = match command {
                    SessionCommand::Resize { cols, rows } => session.resize(cols, rows).await,
                    SessionCommand::Input(input) => session.input(input).await,
                    SessionCommand::Clipboard(op) => session.clipboard(op).await,
                    // Prompts raised during the handshake are answered through
                    // `crate::prompt`, which owns its own receiver. One
                    // arriving here answers nothing, and dropping it is right:
                    // there is no question left open.
                    SessionCommand::Prompt(_) => Ok(()),
                    SessionCommand::Disconnect => break CloseReason::ClosedByUser,
                };
                if let Err(error) = outcome {
                    // An unsupported operation is the interface asking for
                    // something this protocol has no encoding for. It is worth
                    // reporting and not worth ending a working session over.
                    //
                    // This branch is no longer the *only* record of it. Every
                    // refusal above goes through `SshSession::refuse`, which
                    // puts a catalogue key on the event stream where the tab
                    // can render it; a refusal that existed solely as this log
                    // line reached nobody at all.
                    if matches!(error, ProtocolError::Unsupported { .. }) {
                        tracing::debug!("the interface asked for something SSH does not carry");
                    } else {
                        break CloseReason::Failed(FailureReport::from(&error));
                    }
                }
            }
        }
    };

    // Output written a microsecond before the close is still output the user
    // wants to read — often the server's parting message.
    let _ = session.events.flush().await;
    if let Err(error) = Box::new(session).disconnect().await {
        tracing::debug!(
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
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_what_a_terminal_emulator_expects() {
        let settings = TerminalSettings::default();
        assert_eq!(settings.term, "xterm-256color");
        assert_eq!(settings.columns, 80);
        assert_eq!(settings.rows, 24);
        assert!(!settings.agent_forwarding, "agent forwarding is opt-in");
        assert!(settings.initial_command.is_none());
        assert!(settings.environment.is_empty());
    }

    #[test]
    fn the_capabilities_match_the_protocol_matrix() {
        // `docs/features/protocols.md`: a terminal that resizes, file transfer
        // through SFTP, recordable as asciicast. The clipboard entry is
        // `None` — see `capabilities` and the test below.
        let capabilities = capabilities();
        assert_eq!(capabilities.kind, SessionKind::Terminal);
        assert!(capabilities.resizable);
        assert_eq!(capabilities.clipboard, ClipboardSupport::None);
        assert!(capabilities.file_transfer);
        assert!(capabilities.recordable);
        assert!(!capabilities.audio);
        assert!(!capabilities.printing);
        assert!(!capabilities.multi_monitor);
    }

    #[test]
    fn the_clipboard_capability_promises_only_what_the_session_honours() {
        // The defect this pins, which stood in the adapter users open every
        // day: `capabilities()` said `ClipboardSupport::Text` while the
        // session answered `ClipboardOp::Request` with `Unsupported`. The
        // interface reads the capability to decide which controls to draw, so
        // the promise put a button on screen that could only fail.
        //
        // Written as the implication rather than as two constants, because two
        // constants are what drifted.
        let reads_the_remote_clipboard = !matches!(
            clipboard_plan(ClipboardOp::Request { files: false }),
            ClipboardPlan::Refuse { .. }
        );
        let promises_to_read = matches!(
            capabilities().clipboard,
            ClipboardSupport::Text | ClipboardSupport::TextAndFiles
        );
        assert_eq!(
            promises_to_read, reads_the_remote_clipboard,
            "a capability that claims a clipboard the session refuses is a control that fails in the user's hand"
        );

        // And the direction that does work still does: pasting into a terminal
        // is writing bytes to it, which is why the capability being `None` is
        // a narrowing of the promise rather than a loss of function.
        assert!(matches!(
            clipboard_plan(ClipboardOp::Offer(ClipboardData::Text("ok".to_owned()))),
            ClipboardPlan::Paste(_)
        ));
        assert!(matches!(
            clipboard_plan(ClipboardOp::Offer(ClipboardData::Files(vec![
                "/etc/passwd".to_owned()
            ]))),
            ClipboardPlan::Refuse { .. }
        ));
        assert!(matches!(
            clipboard_plan(ClipboardOp::Clear),
            ClipboardPlan::Nothing
        ));
    }

    #[test]
    fn nothing_in_this_session_logs_what_the_user_typed() {
        // CLAUDE.md §0.2, applied to input: a log line naming a key is
        // keystroke material at rest, and there is no exception for one key at
        // a time. A terminal's input is an opaque byte stream, so the rule here
        // is that no diagnostic in this file may carry any of it.
        //
        // The needles are assembled at run time so that this test's own source
        // is not what it finds, and only the code above the test module is
        // scanned.
        const SOURCE: &str = include_str!("session.rs");
        let body = SOURCE
            .split(concat!("#[cfg", "(test)]"))
            .next()
            .unwrap_or(SOURCE);
        for (at, _) in body.match_indices(concat!("tracing", "::")) {
            let rest = &body[at..];
            let statement = &rest[..rest.find(';').unwrap_or(rest.len())];
            for forbidden in ["scancode", "keysym", "keycode", "keystroke"] {
                assert!(
                    !statement.contains(forbidden),
                    "a diagnostic in this file mentions `{forbidden}`: {statement}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_refusal_reaches_the_user_and_does_so_once() {
        // The defect: every refusal in this file existed only as the returned
        // `Err`, and `run_ssh_session` folded `ProtocolError::Unsupported` into
        // a `tracing::debug!`. `SessionCommand` has no reply channel, so the
        // caller that issued the operation was never told anything at all — a
        // clipboard control that failed in the user's hand, silently.
        //
        // Reverted — `unsupported(operation)` with no send — this fails on the
        // first assertion below rather than on the returned error, because the
        // returned error was always right. That is precisely why the hole
        // survived review.
        let (events, mut rx) = remoter_proto::event_channel(8);
        let mut announced = BTreeSet::new();

        let error = announce_refusal(
            &events,
            &mut announced,
            "reading the remote clipboard",
            WARNING_CLIPBOARD_UNSUPPORTED,
        )
        .await;
        assert!(matches!(error, ProtocolError::Unsupported { .. }));
        assert_eq!(
            rx.try_recv(),
            Ok(SessionEvent::Warning(SessionWarning::Other {
                detail: WARNING_CLIPBOARD_UNSUPPORTED.to_owned(),
            })),
            "a refusal the user is never told about is a control that does nothing"
        );

        // Once per key. A misrouted pointer event arrives as fast as a mouse
        // moves, and the same warning at that rate is noise to be dismissed.
        let _ = announce_refusal(
            &events,
            &mut announced,
            "reading the remote clipboard",
            WARNING_CLIPBOARD_UNSUPPORTED,
        )
        .await;
        assert!(
            rx.try_recv().is_err(),
            "the warning repeated once per attempt"
        );

        // A different refusal is a different fact, and is said.
        let _ = announce_refusal(
            &events,
            &mut announced,
            "pointer input",
            WARNING_INPUT_UNSUPPORTED,
        )
        .await;
        assert_eq!(
            rx.try_recv(),
            Ok(SessionEvent::Warning(SessionWarning::Other {
                detail: WARNING_INPUT_UNSUPPORTED.to_owned(),
            }))
        );
    }

    #[test]
    fn every_refusal_in_this_file_is_announced() {
        // The companion to the test above, and the part that survives someone
        // adding a *new* refusal. `announce_refusal` is the only place in this
        // file permitted to build a `ProtocolError::Unsupported`; anywhere
        // else, `Err(unsupported(...))` would be a refusal that reaches the
        // debug log and nobody else — the defect this round removed.
        //
        // The needle is assembled at run time so that this test's own source is
        // not what it finds, and only the code above the test module is
        // scanned.
        const SOURCE: &str = include_str!("session.rs");
        let body = SOURCE
            .split(concat!("#[cfg", "(test)]"))
            .next()
            .unwrap_or(SOURCE);
        assert!(
            !body.contains(concat!("Err(unsup", "ported(")),
            "a refusal in this file is raised without announcing itself; route it through `refuse`"
        );
        // And the announcing path really is still there, so that deleting it
        // cannot make this test pass by vacuum.
        assert!(body.contains("async fn announce_refusal"));
    }

    #[test]
    fn an_exit_signal_key_never_carries_what_the_server_wrote() {
        // The defect: the key was built with `format!("...{signal_name:?}")`.
        // RFC 4254 §6.10 lets a server send a signal name outside its list, so
        // `russh` models the field as `Sig::Custom(String)` — and `Debug`
        // renders that variant as the server's own bytes. Two consequences:
        // free-form remote prose inside a message-catalogue key, and an
        // allocation whose length the far end picked, in an adapter that had
        // no bound of its own. `docs/security/threat-model.md` puts a hostile
        // server in scope.
        //
        // Reverted, this fails on the `Custom` case below: the key becomes
        // `Custom("...")` with the server's text in it.
        let hostile = russh::Sig::Custom("\u{1b}]0;pwned\u{7}".repeat(4096));
        let key = exit_signal_key(&hostile);
        assert_eq!(key, "other");

        // Stated as the property rather than as one example: every key is one
        // of a fixed set of literals, so a server contributes no byte to any
        // of them, whatever it sends.
        for signal in [
            russh::Sig::ABRT,
            russh::Sig::ALRM,
            russh::Sig::FPE,
            russh::Sig::HUP,
            russh::Sig::ILL,
            russh::Sig::INT,
            russh::Sig::KILL,
            russh::Sig::PIPE,
            russh::Sig::QUIT,
            russh::Sig::SEGV,
            russh::Sig::TERM,
            russh::Sig::USR1,
            russh::Sig::Custom("SIGSOMETHING".to_owned()),
        ] {
            let key = exit_signal_key(&signal);
            assert!(key.is_ascii(), "{key}");
            assert!(!key.is_empty());
            assert!(
                key.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    || key == "other",
                "{key}"
            );
            let detail = format!("{WARNING_EXIT_SIGNAL_PREFIX}{key}.core");
            assert!(
                detail.len() < 32,
                "a catalogue key is short by construction"
            );
        }
    }

    #[test]
    fn the_refusal_catalogue_keys_are_stable_ascii_and_namespaced() {
        // They are message-catalogue keys, not English: a translator looks them
        // up, and a key that drifts is a string that silently falls back.
        for key in [
            WARNING_AGENT_FORWARDING,
            WARNING_INPUT_UNSUPPORTED,
            WARNING_CLIPBOARD_POLICY,
            WARNING_CLIPBOARD_UNSUPPORTED,
            WARNING_EXIT_SIGNAL_PREFIX,
        ] {
            assert!(key.is_ascii(), "{key}");
            assert!(key.starts_with("ssh."), "{key}");
            assert!(!key.contains(' '), "{key}");
        }
    }

    #[test]
    fn the_clipboard_policy_refuses_files_by_default() {
        // A compromised host must not be able to drop files into the local
        // clipboard (`docs/security/transport-security.md`).
        let policy = ClipboardPolicy::default();
        assert!(policy.permits(&ClipboardOp::Offer(ClipboardData::Text("ok".to_owned()))));
        assert!(
            !policy.permits(&ClipboardOp::Offer(ClipboardData::Files(vec![
                "/etc/passwd".to_owned()
            ])))
        );
        assert!(!policy.permits(&ClipboardOp::Request { files: true }));
    }

    #[tokio::test]
    async fn a_closed_tab_is_not_kept_waiting_by_the_frame_timer() {
        // The consumer has stopped reading and the event channel is full, so
        // another task is parked inside `send` holding the coalescer's lock.
        // Asking for the frame deadline outside the loop's race would block on
        // that lock, and the closed tab would never see its own cancellation
        // — CLAUDE.md §5 requires the opposite.
        let (events, rx) = remoter_proto::event_channel(1);
        let cancel = CancellationToken::new();

        // Fill the channel, then park a sender inside it.
        events
            .send(SessionEvent::Warning(SessionWarning::Other {
                detail: "first".to_owned(),
            }))
            .await
            .unwrap();
        let blocked = tokio::spawn({
            let events = events.clone();
            async move {
                events
                    .send(SessionEvent::Warning(SessionWarning::Other {
                        detail: "second".to_owned(),
                    }))
                    .await
            }
        });
        // Give the parked sender time to take the lock.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }

        cancel.cancel();
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            frame_deadline_or_cancelled(&events, &cancel),
        )
        .await
        .expect("a closed tab waited on the coalescer's lock");
        assert!(outcome.is_none(), "cancellation must win the race");

        blocked.abort();
        drop(rx);
    }

    #[test]
    fn a_zero_window_is_never_sent() {
        // A remote told its terminal is 0×0 draws nothing, and the user sees a
        // blank tab with no explanation. `resize` and `open_shell` both clamp
        // through this helper.
        fn clamp(value: u16) -> u32 {
            u32::from(value.max(1))
        }
        assert_eq!(clamp(0), 1);
        assert_eq!(clamp(80), 80);
    }
}
