//! A live RDP session: the read loop, input, resize, and a clean disconnect.
//!
//! Stage 8 of `docs/architecture/session-pipeline.md`. Everything the server
//! sends after the Font Map PDU arrives here, is decoded into a framebuffer,
//! and leaves through the shared event bus; everything the user does arrives as
//! a [`remoter_proto::SessionCommand`] and leaves as fast-path input.
//!
//! # One task, one owner
//!
//! The session owns its stream and is driven by [`run_rdp_session`], which is
//! the *only* thing that polls it. Nothing here spawns. A closed tab cancels
//! the token, the loop breaks, the session is consumed by
//! [`remoter_proto::Session::disconnect`], and the socket closes with it —
//! deterministically, on every path including the failure ones. A previous
//! defect in this project leaked one task and one socket per cancelled
//! connection; the shape that cannot is the one where there is nothing else to
//! leak.
//!
//! # Backpressure
//!
//! `docs/architecture/session-pipeline.md` §8 says a framebuffer session drops
//! stale frames and keeps the newest, merging dirty rectangles — rendering a
//! frame the user will never see costs latency on the one they will. That is
//! what [`crate::display::FrameEncoder`]'s coalescer does, and it is why the
//! loop arms a timer only when something is pending.

use std::time::Instant;

use async_trait::async_trait;
use ironrdp::graphics::image_processing::PixelFormat as IronPixelFormat;
use ironrdp::pdu::Action;
use ironrdp::pdu::mcs;
use ironrdp::pdu::x224::X224;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use remoter_proto::{
    Capabilities, ClipboardOp, ClipboardSupport, CloseReason, EventSink, FailureReport, HostPort,
    InputEvent, ProtocolError, SessionContext, SessionEvent, SessionId, SessionKind,
};

use crate::connect::{Connected, ConnectionConfig, DesktopSize};
use crate::display::FrameEncoder;
use crate::error::{map_io, unsupported, violation};
use crate::framed::{Framed, rdp_pdu_length};
use crate::input::InputEncoder;

/// What an RDP session can do.
///
/// The interface reads this rather than hardcoding "RDP has a clipboard
/// button". Four of these are claims the implementation has not earned, and
/// claiming one early would put a control on the tab that does nothing:
///
/// - `clipboard` is `None` because the MS-RDPECLIP channel is not requested
///   yet. `docs/features/protocols.md` expects text both ways, and this is the
///   gap; a `ClipboardSupport::Text` here would render a paste button that
///   silently discards.
/// - `file_transfer` is drive redirection (MS-RDPEFS), not in scope for the
///   first RDP milestone.
/// - `audio` is MS-RDPEA, likewise — and the Client Info PDU actively asks the
///   server not to send any, so claiming it would be doubly wrong.
/// - `multi_monitor` needs a per-monitor framebuffer stream, which
///   `docs/architecture/rendering.md` defers until the presenter is chosen at
///   the end of v0.2 (ADR-0010).
#[must_use]
pub const fn capabilities() -> Capabilities {
    Capabilities {
        kind: SessionKind::Framebuffer,
        // MS-RDPEDISP: the client asks the server to change its desktop size
        // mid-session. This is "smart resize" in `rendering.md`.
        resizable: true,
        clipboard: ClipboardSupport::None,
        file_transfer: false,
        audio: false,
        printing: false,
        multi_monitor: false,
        recordable: true,
    }
}

/// A live RDP session.
pub struct RdpSession {
    stream: Framed,
    stage: ActiveStage,
    image: DecodedImage,
    frames: FrameEncoder,
    input: InputEncoder,
    events: EventSink,
    session: SessionId,
    target: HostPort,
    desktop: DesktopSize,
    io_channel_id: u16,
    user_channel_id: u16,
}

impl core::fmt::Debug for RdpSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpSession")
            .field("session", &self.session)
            .field("target", &self.target)
            .field("desktop", &self.desktop)
            .finish_non_exhaustive()
    }
}

impl RdpSession {
    /// Attaches to a connection that has reached the Active state.
    ///
    /// The session id is what the presenter demultiplexes frames by
    /// (`remoter_proto::FrameMessage`'s header carries it), so it is supplied
    /// here rather than defaulted: two tabs sharing an id quietly become one.
    #[must_use]
    pub fn attach(
        connected: Connected,
        events: EventSink,
        session: SessionId,
        target: HostPort,
    ) -> Self {
        let Connected {
            stream,
            io_channel_id,
            user_channel_id,
            message_channel_id,
            share_id,
            static_channels,
            desktop,
        } = connected;

        let stage = ActiveStageBuilder {
            static_channels,
            user_channel_id,
            io_channel_id,
            message_channel_id,
            share_id,
            // Bulk compression is not negotiated: the Client Info PDU does not
            // set `ClientInfoFlags::COMPRESSION`, so the server sends none.
            compression_type: None,
            // The pointer arrives as its own update rather than being drawn
            // into the framebuffer, so the presenter can follow the local
            // mouse at the display's refresh rate instead of the network's.
            enable_server_pointer: true,
            pointer_software_rendering: false,
        }
        .build();

        // `BgrX32` is byte-for-byte `PixelFormat::Bgrx8888`: blue, green, red,
        // then a padding byte that is not alpha. See `crate::display`.
        let image = DecodedImage::new(IronPixelFormat::BgrX32, desktop.width, desktop.height);

        Self {
            stream,
            stage,
            image,
            frames: FrameEncoder::new(desktop.width, desktop.height),
            input: InputEncoder::new(),
            events,
            session,
            target,
            desktop,
            io_channel_id,
            user_channel_id,
        }
    }

    /// The desktop size the server settled on.
    #[must_use]
    pub const fn desktop(&self) -> DesktopSize {
        self.desktop
    }

    /// Announces the session's size and sends a first, self-sufficient frame.
    ///
    /// Called once, immediately after attaching. Without it a presenter has a
    /// blank surface until the first thing on the remote desktop happens to
    /// change, which on an idle login screen can be a long time.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::EventStreamClosed`] if the consumer is already gone.
    pub async fn announce(&mut self) -> Result<(), ProtocolError> {
        self.events
            .send(SessionEvent::Resized {
                width: self.desktop.width,
                height: self.desktop.height,
            })
            .await?;
        if let Some(keyframe) = self.frames.keyframe(&self.image) {
            keyframe.emit(&self.events, self.session).await?;
        }
        Ok(())
    }

    /// Reads one frame from the server and acts on it.
    ///
    /// Returns `Some` when the session is over.
    ///
    /// # Errors
    ///
    /// Anything the read or the decode produced. A decode failure is a
    /// protocol violation and ends the session: the framebuffer is now a
    /// guess, and continuing would draw a guess.
    pub async fn pump(&mut self) -> Result<Option<CloseReason>, ProtocolError> {
        let frame = self.stream.read_pdu(rdp_pdu_length).await?;
        let action = frame
            .first()
            .and_then(|header| Action::from_fp_output_header(*header).ok())
            .ok_or_else(|| violation("the server sent a PDU with no recognisable action"))?;

        let outputs = self
            .stage
            .process(&mut self.image, action, &frame)
            .map_err(|error| {
                tracing::debug!(%error, "an RDP update could not be processed");
                violation("the server sent an update this client could not decode")
            })?;

        for output in outputs {
            if let Some(reason) = self.handle(output).await? {
                return Ok(Some(reason));
            }
        }
        Ok(None)
    }

    /// Flushes any frame whose coalescing window has closed.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::EventStreamClosed`] once the presenter is gone.
    pub async fn flush_frames(&mut self, now: Instant) -> Result<(), ProtocolError> {
        if let Some(message) = self.frames.take_if_due(now) {
            message.emit(&self.events, self.session).await?;
        }
        Ok(())
    }

    /// How long until a pending frame is due, for the loop's timer. `None`
    /// when nothing is pending, so an idle session arms no timer and wakes for
    /// nothing.
    #[must_use]
    pub fn frame_deadline(&self, now: Instant) -> Option<core::time::Duration> {
        self.frames.time_to_deadline(now)
    }

    async fn handle(
        &mut self,
        output: ActiveStageOutput,
    ) -> Result<Option<CloseReason>, ProtocolError> {
        match output {
            // The decoder's own replies: frame acknowledgements, virtual
            // channel responses, and the answers a pointer update needs.
            ActiveStageOutput::ResponseFrame(bytes) => self.stream.write_all(&bytes).await?,

            ActiveStageOutput::GraphicsUpdate(region) => {
                self.frames.push(&self.image, &region, Instant::now());
            }

            ActiveStageOutput::PointerBitmap(pointer) => {
                if let Some(message) = self.frames.cursor(&pointer) {
                    message.emit(&self.events, self.session).await?;
                }
            }
            ActiveStageOutput::PointerHidden => {
                self.frames
                    .hide_cursor()
                    .emit(&self.events, self.session)
                    .await?;
            }
            // "Use the system default pointer." `remoter_proto::CursorUpdate`
            // can say "here is a shape" and "no pointer at all" and has no
            // third thing to say, so nothing is sent and the presenter keeps
            // whatever it was showing. The visible consequence is that a
            // session which switches from a custom cursor back to the arrow
            // keeps the custom one until the next shape change. Adding a
            // `Default` to the shared format is the fix, and it is a change to
            // `remoter-proto` rather than something to fake here.
            ActiveStageOutput::PointerDefault => {
                tracing::trace!(
                    "the server asked for the default pointer, which the frame format cannot express"
                );
            }
            // The *server* moved the pointer — a program calling
            // `SetCursorPos`. The frame format has no way to say it, for the
            // same reason, so the local pointer stays where the user left it.
            ActiveStageOutput::PointerPosition { x, y } => {
                self.stage.update_mouse_pos(x, y);
            }

            ActiveStageOutput::Terminate(reason) => {
                tracing::info!(%reason, "the server ended the session");
                return Ok(Some(CloseReason::Disconnected));
            }

            // MS-RDPBCGR §1.3.1.3: the server is changing something
            // fundamental — most often its own desktop size — and the
            // capability exchange runs again on the same connection.
            ActiveStageOutput::DeactivateAll => {
                self.reactivate().await?;
            }

            // A UDP side channel this build does not open (§2.2.15.1). The
            // session continues over TCP, which is what a client that declines
            // multitransport gets.
            ActiveStageOutput::MultitransportRequest(_) => {
                tracing::debug!("declining the server's multitransport request");
            }

            // The server's own measurement of the link (MS-RDPBCGR §2.2.14.1.5).
            // Only the *result* reaches here — IronRDP answers round-trip-time
            // requests itself — and it is informational. There is nowhere in
            // `SessionEvent` shaped like a latency sample yet: `Progress`
            // counts work done, and putting a round-trip time in it would be
            // inventing a meaning for the field rather than reporting one.
            ActiveStageOutput::AutoDetect(request) => {
                tracing::debug!(?request, "the server reported its network measurement");
            }
        }
        Ok(None)
    }

    /// Runs the Deactivation-Reactivation Sequence. MS-RDPBCGR §1.3.1.3.
    ///
    /// The server sent a Deactivate All PDU, so the share is gone and a new
    /// capability exchange decides the new one — including, usually, a new
    /// desktop size. The framebuffer is rebuilt at that size and the presenter
    /// gets a keyframe, because every delta it holds describes a surface that
    /// no longer exists.
    async fn reactivate(&mut self) -> Result<(), ProtocolError> {
        tracing::debug!(target = %self.target, "the server deactivated the share; reactivating");
        let config = ConnectionConfig {
            desktop: self.desktop,
            ..ConnectionConfig::new(self.target.clone(), String::new())
        };
        let (share_id, desktop) = crate::connect::reactivate(
            &mut self.stream,
            &config,
            self.user_channel_id,
            self.io_channel_id,
        )
        .await?;

        self.stage.set_share_id(share_id);
        if desktop != self.desktop {
            self.desktop = desktop;
            self.image = DecodedImage::new(IronPixelFormat::BgrX32, desktop.width, desktop.height);
            self.frames.set_surface(desktop.width, desktop.height);
            self.events
                .send(SessionEvent::Resized {
                    width: desktop.width,
                    height: desktop.height,
                })
                .await?;
        }
        if let Some(keyframe) = self.frames.keyframe(&self.image) {
            keyframe.emit(&self.events, self.session).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl remoter_proto::Session for RdpSession {
    /// Asks the server to change its desktop size. MS-RDPEDISP §2.2.2.2.
    ///
    /// The arguments are **pixels**, not columns and rows: the trait's names
    /// come from the terminal case, and a framebuffer session has no cells.
    /// `docs/architecture/rendering.md` calls this "smart resize".
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Unsupported`] when the server did not open the Display
    /// Control channel, which is what an older host or a `xrdp` does. The
    /// session keeps working at its original size, which is the honest outcome
    /// — the alternative is scaling in the presenter, and that is the
    /// presenter's decision.
    async fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ProtocolError> {
        // §2.2.2.2.1: at least 200, at most 8192, and the width must be even.
        // A request outside that is rejected by the server rather than
        // clamped, so it is clamped here.
        let (width, height) = ironrdp::displaycontrol::pdu::MonitorLayoutEntry::adjust_display_size(
            u32::from(cols),
            u32::from(rows),
        );

        let Some(encoded) = self.stage.encode_resize(width, height, None, None) else {
            return Err(unsupported("resizing the remote desktop"));
        };
        let encoded = encoded.map_err(|error| {
            tracing::debug!(%error, "the resize request could not be encoded");
            ProtocolError::Internal {
                detail: "the resize request could not be encoded",
            }
        })?;
        self.stream.write_all(&encoded).await?;
        // The server answers with a Deactivate All and a fresh capability
        // exchange; the new size arrives from *there*, not from here. Setting
        // it now would draw at a size the server has not agreed to.
        tracing::debug!(width, height, "asked the server to resize its desktop");
        Ok(())
    }

    /// Sends user input. MS-RDPBCGR §2.2.8.1.2.
    ///
    /// # Errors
    ///
    /// A transport failure. An input event this protocol has no encoding for
    /// produces nothing rather than an error — see [`crate::input`].
    async fn input(&mut self, input: InputEvent) -> Result<(), ProtocolError> {
        let events = self.input.encode(&input);
        if events.is_empty() {
            return Ok(());
        }
        let outputs = self
            .stage
            .process_fastpath_input(&mut self.image, &events)
            .map_err(|error| {
                tracing::debug!(%error, "an input event could not be encoded");
                ProtocolError::Internal {
                    detail: "an input event could not be encoded",
                }
            })?;
        for output in outputs {
            if let ActiveStageOutput::ResponseFrame(bytes) = output {
                self.stream.write_all(&bytes).await?;
            }
        }
        Ok(())
    }

    /// Clipboard operations are not implemented.
    ///
    /// # Errors
    ///
    /// Always [`ProtocolError::Unsupported`]. The MS-RDPECLIP channel is not
    /// requested, and `capabilities()` reports `ClipboardSupport::None` so the
    /// interface does not offer the control in the first place.
    async fn clipboard(&mut self, _op: ClipboardOp) -> Result<(), ProtocolError> {
        Err(unsupported("clipboard transfer"))
    }

    /// Says goodbye and releases everything.
    ///
    /// Three things, in order, and the order matters:
    ///
    /// 1. Release every held key and button. A tab closed with Alt down leaves
    ///    the *server* believing Alt is down, and the next session inherits it.
    /// 2. Send the Shutdown Request PDU (MS-RDPBCGR §2.2.2.2), which is how a
    ///    client asks to log off cleanly rather than dropping the socket.
    /// 3. Send the MCS Disconnect Provider Ultimatum (§2.2.2.3), which tells
    ///    the server this was deliberate — without it the session lingers as
    ///    disconnected-but-alive and the user's next connection reattaches to
    ///    a session they thought they had closed.
    ///
    /// Every step is best-effort: the socket may already be gone, and the
    /// session is over either way. The stream is dropped when this returns,
    /// which is what actually frees the socket.
    ///
    /// # Errors
    ///
    /// A transport failure while saying goodbye. Diagnostic only.
    async fn disconnect(mut self: Box<Self>) -> Result<(), ProtocolError> {
        let released = self.input.release_all();
        if !released.is_empty()
            && let Ok(outputs) = self
                .stage
                .process_fastpath_input(&mut self.image, &released)
        {
            for output in outputs {
                if let ActiveStageOutput::ResponseFrame(bytes) = output {
                    let _ = self.stream.write_all(&bytes).await;
                }
            }
        }

        if let Ok(outputs) = self.stage.graceful_shutdown() {
            for output in outputs {
                if let ActiveStageOutput::ResponseFrame(bytes) = output {
                    let _ = self.stream.write_all(&bytes).await;
                }
            }
        }

        let ultimatum =
            mcs::DisconnectProviderUltimatum::from_reason(mcs::DisconnectReason::UserRequested);
        match ironrdp::core::encode_vec(&X224(ultimatum)) {
            Ok(bytes) => {
                let outcome = self.stream.write_all(&bytes).await;
                // The stream — and with it the TLS session and the injected
                // transport — is dropped here, on this path and on every
                // failure path above.
                drop(self);
                outcome
            }
            Err(_) => Err(ProtocolError::Internal {
                detail: "the disconnect PDU could not be encoded",
            }),
        }
    }
}

/// Drives a session until it ends.
///
/// The RDP counterpart of `remoter_proto::run_session`, which cannot be used
/// directly: a framebuffer session has a *read* loop of its own, and the
/// generic driver only pumps commands.
///
/// # Errors
///
/// Never returns an error for an ordinary end; a failure is reported as
/// [`CloseReason::Failed`] so that the tab can render it. The `Result` is kept
/// for the supervisor's signature.
pub async fn run_rdp_session(
    mut session: RdpSession,
    mut ctx: SessionContext,
) -> Result<CloseReason, ProtocolError> {
    if let Err(error) = session.announce().await {
        return Ok(CloseReason::Failed(FailureReport::from(&error)));
    }

    let reason = loop {
        let now = Instant::now();
        // Armed only when something is pending, so an idle session — a login
        // screen nobody is touching — wakes for nothing.
        let deadline = session.frame_deadline(now);

        tokio::select! {
            // Biased so a closed tab wins a race with an arriving frame: the
            // tab is gone either way, and decoding one more update costs the
            // user nothing and the process a socket.
            biased;
            () = ctx.cancel.cancelled() => break CloseReason::ClosedByUser,

            () = async {
                match deadline {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => std::future::pending().await,
                }
            } => {
                if session.flush_frames(Instant::now()).await.is_err() {
                    // The presenter is gone; there is nobody left to render.
                    break CloseReason::ClosedByUser;
                }
            }

            outcome = session.pump() => match outcome {
                Ok(Some(reason)) => break reason,
                Ok(None) => {}
                Err(error) => break close_reason_for(&error),
            },

            command = ctx.commands.recv() => {
                let Some(command) = command else {
                    // Every handle is gone; nobody can drive this session
                    // again, so holding its socket open would be a leak.
                    break CloseReason::ClosedByUser;
                };
                use remoter_proto::{Session as _, SessionCommand};
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
                    // something this protocol has no encoding for. Worth
                    // reporting, not worth ending a working session over.
                    if matches!(error, ProtocolError::Unsupported { .. }) {
                        tracing::debug!("the interface asked for something RDP does not carry");
                    } else {
                        break CloseReason::Failed(FailureReport::from(&error));
                    }
                }
            }
        }
    };

    // A frame produced a microsecond before the close is still a frame the
    // user is looking at.
    let _ = session.flush_frames(Instant::now()).await;
    let _ = session.events.flush().await;
    use remoter_proto::Session as _;
    if let Err(error) = Box::new(session).disconnect().await {
        tracing::debug!(
            stage = error.stage().as_str(),
            "the clean disconnect did not complete"
        );
    }
    Ok(reason)
}

/// How a read failure ends the session.
///
/// A server that closed cleanly is `Disconnected` and offers a reconnect
/// button; anything else is a failure the tab renders in full.
fn close_reason_for(error: &ProtocolError) -> CloseReason {
    match error {
        ProtocolError::Disconnected { .. } => CloseReason::Disconnected,
        other => CloseReason::Failed(FailureReport::from(other)),
    }
}

/// Maps a transport failure during the run phase. Kept beside the loop so the
/// `Run` stage's errors are named where they are produced.
#[must_use]
pub fn run_io_failure(error: &std::io::Error, target: &HostPort) -> ProtocolError {
    map_io(error, target, "run the RDP session")
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
    fn the_session_is_a_framebuffer_one_and_says_what_it_cannot_do() {
        let caps = capabilities();
        assert_eq!(caps.kind, SessionKind::Framebuffer);
        assert!(caps.resizable);
        // Claiming a redirection that is not implemented puts a dead control
        // on the tab, so these stay false until the channel exists.
        assert_eq!(caps.clipboard, ClipboardSupport::None);
        assert!(!caps.file_transfer);
        assert!(!caps.audio);
        assert!(!caps.multi_monitor);
        assert!(caps.recordable);
    }

    #[test]
    fn a_clean_close_and_a_failure_end_the_session_differently() {
        // "The server closed the connection" offers a reconnect button; a
        // protocol violation offers a defect report. Collapsing them would put
        // the wrong button on the tab.
        assert_eq!(
            close_reason_for(&ProtocolError::Disconnected {
                reason: "rdp.remote_closed".to_owned()
            }),
            CloseReason::Disconnected
        );
        let failed = close_reason_for(&violation("a malformed update"));
        let CloseReason::Failed(report) = failed else {
            panic!("a violation must be reported as a failure");
        };
        assert_eq!(report.stage, remoter_proto::Stage::Run);
        assert!(!report.retryable);
    }

    #[test]
    fn a_resize_is_clamped_to_what_the_specification_permits() {
        // MS-RDPEDISP §2.2.2.2.1: 200 to 8192, and the width must be even. A
        // request outside that is refused by the server rather than clamped,
        // so a tab dragged to 100 pixels wide would silently stop resizing.
        use ironrdp::displaycontrol::pdu::MonitorLayoutEntry;
        assert_eq!(
            MonitorLayoutEntry::adjust_display_size(1921, 1080),
            (1920, 1080)
        );
        assert_eq!(
            MonitorLayoutEntry::adjust_display_size(100, 100),
            (200, 200)
        );
        assert_eq!(
            MonitorLayoutEntry::adjust_display_size(9000, 9000),
            (8192, 8192)
        );
    }

    #[test]
    fn the_session_never_debug_prints_its_framebuffer() {
        // A framebuffer is a picture of someone's screen.
        let rendered = format!("{:?}", DesktopSize::default());
        assert!(rendered.contains("1024"));
    }
}
