//! A live VNC session: the loop that drives it, and the way it ends.
//!
//! # RFB is pull-based, and that shapes this loop
//!
//! RFC 6143 §7.5.3: the server sends a framebuffer update only in answer to a
//! `FramebufferUpdateRequest`, and an *incremental* request is one the server
//! is allowed to sit on until something actually changes. So a VNC session is
//! not a stream that is read, it is a conversation: ask, receive, ask again.
//!
//! `vnc-rs` sends the first, non-incremental request itself and then leaves the
//! asking to the caller — and it gives no signal for "this update is complete",
//! because the library's event stream has no update boundary in it. The loop
//! below therefore tracks one bit, [`VncSession::outstanding_request`]: a
//! request is sent when none is outstanding, and it stops being outstanding as
//! soon as any rectangle arrives. On an idle desktop that means exactly one
//! request is in flight and the loop wakes for nothing; on a busy one it means
//! at most one request per frame interval. It is a compromise the library's
//! shape forces, and it is written down rather than left to be inferred from a
//! timer.
//!
//! # How a session ends, and why nothing leaks
//!
//! `VncClient` spawns two tasks of its own — one moving bytes between the
//! socket and an internal bridge, one running the decoders — and neither takes
//! this session's `CancellationToken`. What makes them stop is `Drop`:
//! `VncInner`'s destructor signals both, the byte-moving task drops the
//! transport as it returns, and the decoding task ends when its input closes.
//!
//! That is worth stating precisely, because it is what makes every failure path
//! in this crate safe without a guard type: **dropping the client frees the
//! socket.** An early `?` on the connect path, a panic in this task, a
//! cancelled tab — all of them drop the client, and all of them therefore close
//! the socket. [`VncSession::disconnect`] additionally signals the stop before
//! dropping, so the tasks are already unwinding by the time the destructor
//! runs, but it is belt and braces rather than the mechanism.

use std::collections::VecDeque;
use std::time::Instant;

use async_trait::async_trait;
use remoter_proto::{
    ClipboardData, ClipboardFormats, ClipboardOp, ClipboardPolicy, CloseReason, EventSink,
    FailureReport, FrameCoalescer, FrameMessage, FrameUpdate, HostPort, InputEvent, ProtocolError,
    Rect, Session, SessionCommand, SessionContext, SessionEvent, SessionId, SessionWarning,
};
use vnc::{ClientKeyEvent, ClientMouseEvent, VncClient, X11Event};

use crate::clipboard;
use crate::error::{map_vnc, unsupported};
use crate::frame::{Decoded, FrameTranslator};
use crate::keymap::rfb_keysym;
use crate::pointer::{WheelAccumulator, button_mask, has_unencodable_button};

/// The catalogue key for the bell (RFC 6143 §7.6.3).
pub const WARNING_BELL: &str = "vnc.bell";
/// The catalogue key for a paste that lost characters RFB cannot carry.
pub const WARNING_CLIPBOARD_LOSSY: &str = "vnc.clipboard.substituted";
/// The catalogue key for remote clipboard text that arrived mangled.
pub const WARNING_CLIPBOARD_MANGLED: &str = "vnc.clipboard.inbound_mangled";
/// The catalogue key for a pointer button RFB has no encoding for.
pub const WARNING_BUTTON_DROPPED: &str = "vnc.pointer.button_unsupported";

/// The most events buffered while the connect path waits for `ServerInit`.
///
/// The connect path drains events until the server has said how big the
/// framebuffer is (RFC 6143 §7.3.2), and anything else it finds on the way is
/// kept for the session loop. A server that sent a thousand events before its
/// resolution is a server behaving strangely, and buffering them without a
/// ceiling would be an allocation the far end controls.
pub const MAX_PREFACE_EVENTS: usize = 64;

/// A connected VNC session.
pub struct VncSession {
    client: VncClient,
    events: EventSink,
    /// Which tab these pixels belong to. Set by [`run_vnc_session`], because
    /// the identity is minted by the supervisor and does not exist yet when
    /// [`crate::VncProtocol::connect`] builds this.
    id: SessionId,
    target: HostPort,
    translator: FrameTranslator,
    coalescer: FrameCoalescer,
    /// One counter for framebuffer batches and cursor updates together. The
    /// contract is explicit that they share a sequence — a presenter uses a gap
    /// in it to know its surface is stale — and `FrameCoalescer` keeps a
    /// counter of its own that this overrides, because a second, independent
    /// counter would produce two messages numbered the same.
    seq: u32,
    /// Events the connect path read while waiting for the resolution.
    preface: VecDeque<vnc::VncEvent>,
    wheel: WheelAccumulator,
    clipboard: ClipboardPolicy,
    view_only: bool,
    outstanding_request: bool,
    /// Whether the "this button has no RFB encoding" note has been logged. Once
    /// per session: a user holding the back button would otherwise fill a log.
    warned_about_button: bool,
}

impl VncSession {
    /// Wraps a started client.
    ///
    /// `width` and `height` come from `ServerInit` (RFC 6143 §7.3.2) and are
    /// what every rectangle is subsequently checked against.
    #[must_use]
    pub fn new(
        client: VncClient,
        events: EventSink,
        target: HostPort,
        width: u16,
        height: u16,
        clipboard: ClipboardPolicy,
        view_only: bool,
    ) -> Self {
        Self {
            client,
            events,
            // Overwritten by `run_vnc_session`; a session driven any other way
            // would put every tab's pixels under the same identity, which is
            // why the setter exists and why this is not left public.
            id: SessionId::from_raw(0),
            target,
            translator: FrameTranslator::with_surface(width, height),
            coalescer: FrameCoalescer::with_defaults(Rect::surface(width, height)),
            seq: 0,
            preface: VecDeque::new(),
            wheel: WheelAccumulator::new(),
            clipboard,
            view_only,
            // `VncClient::new` sends the first, non-incremental request before
            // handing the client back, so one is already in flight.
            outstanding_request: true,
            warned_about_button: false,
        }
    }

    /// Records the identity the supervisor minted for this session.
    pub const fn set_session_id(&mut self, id: SessionId) {
        self.id = id;
    }

    /// Where this session is connected.
    #[must_use]
    pub const fn target(&self) -> &HostPort {
        &self.target
    }

    /// The desktop size rectangles are being checked against.
    #[must_use]
    pub const fn surface(&self) -> Rect {
        self.translator.surface()
    }

    /// Queues an event the connect path read before the session loop started.
    ///
    /// Silently dropped past [`MAX_PREFACE_EVENTS`]: the alternative is an
    /// allocation whose size the far end chooses, and a server that emits more
    /// than this before saying how big its framebuffer is has already failed
    /// the check the session loop would apply anyway.
    pub fn queue_preface(&mut self, event: vnc::VncEvent) {
        if self.preface.len() < MAX_PREFACE_EVENTS {
            self.preface.push_back(event);
        }
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        seq
    }

    /// Handles one event from the engine.
    ///
    /// `Ok(Some(reason))` means the session is over.
    ///
    /// # Errors
    ///
    /// Whatever the translator rejected, or [`ProtocolError::EventStreamClosed`]
    /// once the interface has gone.
    pub async fn receive(
        &mut self,
        event: vnc::VncEvent,
    ) -> Result<Option<CloseReason>, ProtocolError> {
        match self.translator.translate(event)? {
            Decoded::Rect(rect) => {
                self.coalescer.push(rect, Instant::now());
                // Any rectangle means the server answered; the next tick may
                // ask again.
                self.outstanding_request = false;
            }

            Decoded::Cursor {
                hotspot_x,
                hotspot_y,
                width,
                height,
                image,
            } => {
                // Sent as its own message rather than drawn into the
                // framebuffer: the pointer moves far more often than it changes
                // shape, and a presenter that owns the shape can follow the
                // local pointer at the display's refresh rate.
                let seq = self.next_seq();
                let update = remoter_proto::CursorUpdate::new(
                    seq,
                    hotspot_x,
                    hotspot_y,
                    width,
                    height,
                    remoter_proto::PixelFormat::Rgba8888,
                    image,
                );
                FrameMessage::Cursor(update)
                    .emit(&self.events, self.id)
                    .await?;
            }

            Decoded::Resolution { width, height } => {
                // Whatever was pending described the old surface and cannot be
                // applied to the new one, so the coalescer discards it. Nothing
                // here can conjure a replacement, which is why the request that
                // follows is non-incremental: the server is asked for the whole
                // desktop rather than for the difference from a surface neither
                // end now holds.
                self.coalescer.set_surface(Rect::surface(width, height));
                self.events
                    .send(SessionEvent::Resized { width, height })
                    .await?;
                self.request(X11Event::FullRefresh).await?;
            }

            Decoded::ClipboardText(text) => {
                if self.clipboard.text_from_remote {
                    if clipboard::inbound_was_mangled(&text) {
                        // RFC 6143 §7.6.4 is Latin-1 and the library decodes it
                        // as UTF-8, so a byte above 0x7f is already lost. The
                        // user is told rather than handed text that is quietly
                        // not what was copied.
                        self.warn(SessionWarning::Other {
                            detail: WARNING_CLIPBOARD_MANGLED.to_owned(),
                        })
                        .await?;
                    }
                    // The text itself is **not** retained. There is no event in
                    // the session contract that carries clipboard *content* to
                    // the interface — only this offer — so holding the string
                    // would be a password sitting in memory for the life of the
                    // tab in exchange for nothing. See `clipboard` in the
                    // `Session` implementation below.
                    self.events
                        .send(SessionEvent::ClipboardOffer(ClipboardFormats {
                            text: true,
                            files: false,
                        }))
                        .await?;
                }
            }

            Decoded::Bell => {
                self.warn(SessionWarning::Other {
                    detail: WARNING_BELL.to_owned(),
                })
                .await?;
            }

            Decoded::Nothing => {}
        }
        Ok(None)
    }

    /// Sends whatever the coalescer has been holding.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::EventStreamClosed`] once the interface has gone.
    pub async fn flush_frame(&mut self) -> Result<(), ProtocolError> {
        let Some(update) = self.coalescer.take() else {
            return Ok(());
        };
        let seq = self.next_seq();
        let update = FrameUpdate { seq, ..update };
        FrameMessage::Framebuffer(update)
            .emit(&self.events, self.id)
            .await
    }

    /// Asks the server for an update, unless one is already outstanding.
    ///
    /// # Errors
    ///
    /// A transport failure, or [`ProtocolError::Disconnected`] once the engine
    /// has stopped.
    pub async fn poll_for_update(&mut self) -> Result<(), ProtocolError> {
        if self.outstanding_request {
            return Ok(());
        }
        self.request(X11Event::Refresh).await
    }

    async fn request(&mut self, what: X11Event) -> Result<(), ProtocolError> {
        self.client
            .input(what)
            .await
            .map_err(|error| map_vnc(&error, "ask the server for a framebuffer update"))?;
        self.outstanding_request = true;
        Ok(())
    }

    async fn warn(&self, warning: SessionWarning) -> Result<(), ProtocolError> {
        self.events.send(SessionEvent::Warning(warning)).await
    }

    /// Sends one key transition (RFC 6143 §7.5.4).
    async fn send_key(
        &mut self,
        scancode: u32,
        keysym: Option<u32>,
        pressed: bool,
    ) -> Result<(), ProtocolError> {
        let Some(keysym) = rfb_keysym(scancode, keysym) else {
            // A dead key mid-composition, or a key RFB cannot name. Dropping it
            // is the documented outcome; the composed character arrives as its
            // own event a keystroke later. The scancode is logged and the
            // keysym never is — a keysym *is* the character typed.
            tracing::debug!(scancode, "a key with no RFB keysym was dropped");
            return Ok(());
        };
        self.client
            .input(X11Event::KeyEvent(ClientKeyEvent {
                keycode: keysym,
                down: pressed,
            }))
            .await
            .map_err(|error| map_vnc(&error, "send a key event"))
    }

    /// Sends pointer state, and any wheel notches, at one position
    /// (RFC 6143 §7.5.5).
    async fn send_pointer(&mut self, input: &InputEvent) -> Result<(), ProtocolError> {
        let InputEvent::Pointer {
            x,
            y,
            buttons,
            wheel,
            wheel_x,
        } = *input
        else {
            return Ok(());
        };

        if has_unencodable_button(buttons) && !self.warned_about_button {
            self.warned_about_button = true;
            let _ = self
                .warn(SessionWarning::Other {
                    detail: WARNING_BUTTON_DROPPED.to_owned(),
                })
                .await;
        }

        // Clamped to the framebuffer. RFC 6143 §7.5.5 does not forbid a
        // position outside it, but a server is entitled to do anything with
        // one, and the frontend's zoom arithmetic can land a pixel past the
        // edge on the last column.
        let surface = self.translator.surface();
        let x = x.min(surface.width.saturating_sub(1));
        let y = y.min(surface.height.saturating_sub(1));

        let mask = button_mask(buttons);
        self.client
            .input(X11Event::PointerEvent(ClientMouseEvent {
                position_x: x,
                position_y: y,
                bottons: mask,
            }))
            .await
            .map_err(|error| map_vnc(&error, "send a pointer event"))?;

        for notch in self.wheel.notch_masks(mask, wheel, wheel_x) {
            self.client
                .input(X11Event::PointerEvent(ClientMouseEvent {
                    position_x: x,
                    position_y: y,
                    bottons: notch,
                }))
                .await
                .map_err(|error| map_vnc(&error, "send a wheel event"))?;
        }
        Ok(())
    }
}

#[async_trait]
impl Session for VncSession {
    /// RFB has no client-initiated resize that this build can send.
    ///
    /// RFC 6143 §7.8.2's DesktopSize pseudo-encoding is **server to client**:
    /// it tells the viewer the desktop changed size, and there is no reply. The
    /// client-initiated direction is the `SetDesktopSize` message (client
    /// message type 251) together with the ExtendedDesktopSize pseudo-encoding
    /// (`-308`), and neither is in RFC 6143 — both are community extensions,
    /// and `vnc-rs` 0.5 implements neither.
    ///
    /// So this reports what is true rather than accepting the call and doing
    /// nothing. [`crate::capabilities`] reports `resizable: false` for the same
    /// reason, so the interface scales the tab instead of offering a control
    /// that cannot work.
    async fn resize(&mut self, _cols: u16, _rows: u16) -> Result<(), ProtocolError> {
        Err(unsupported("asking the server to resize its desktop"))
    }

    async fn input(&mut self, input: InputEvent) -> Result<(), ProtocolError> {
        if self.view_only {
            // The user asked for a session that cannot type. Refusing each
            // event would fill the log with the consequence of their own
            // setting; dropping it is what "view only" means.
            return Ok(());
        }
        match input {
            InputEvent::Key {
                scancode,
                keysym,
                // RFB has no lock-state synchronisation: a lock is a key like
                // any other, and the frontend sends the physical key. See
                // `crate::keymap`.
                modifiers: _,
                pressed,
            } => self.send_key(scancode, keysym, pressed).await,
            InputEvent::Pointer { .. } => self.send_pointer(&input).await,
            // A framebuffer protocol's input is keys and a pointer. A byte
            // stream belongs to a terminal, and re-deriving key events from it
            // here would be a second, divergent implementation of what the
            // emulator already does.
            InputEvent::Bytes(_) => Err(unsupported("byte-stream input")),
        }
    }

    async fn clipboard(&mut self, op: ClipboardOp) -> Result<(), ProtocolError> {
        if !self.clipboard.permits(&op) {
            return Err(unsupported("this clipboard operation"));
        }
        match op {
            ClipboardOp::Offer(ClipboardData::Text(text)) => {
                let transcoded = clipboard::to_wire_text(&text);
                if transcoded.is_lossy() {
                    // Pasting a password that silently lost two characters is
                    // worse than being told the paste was incomplete.
                    let _ = self
                        .warn(SessionWarning::Other {
                            detail: WARNING_CLIPBOARD_LOSSY.to_owned(),
                        })
                        .await;
                }
                self.client
                    .input(X11Event::CopyText(transcoded.into_text()))
                    .await
                    .map_err(|error| map_vnc(&error, "offer the clipboard to the server"))
            }
            // RFB carries text and nothing else (RFC 6143 §7.5.6, §7.6.4).
            ClipboardOp::Offer(ClipboardData::Files(_)) => {
                Err(unsupported("offering files over RFB"))
            }
            // The remote pushes its clipboard unasked, as `ServerCutText`;
            // there is no request in the protocol. The push is reported as a
            // `ClipboardOffer`, but the session contract has no event that
            // carries the *content* to the interface — so the text cannot be
            // delivered, and it is deliberately not retained while it cannot
            // be. This becomes a one-line change the day `SessionEvent` grows
            // a clipboard-content variant.
            ClipboardOp::Request { .. } => Err(unsupported("reading the remote clipboard")),
            // RFB has no way to withdraw an offer. Reporting a failure would
            // make a tab close report an error it cannot act on.
            ClipboardOp::Clear => Ok(()),
        }
    }

    async fn disconnect(self: Box<Self>) -> Result<(), ProtocolError> {
        // RFB has no goodbye message: RFC 6143 §7.5 defines no client
        // disconnect, and a viewer leaves by closing the socket. So the clean
        // shutdown *is* stopping the engine and dropping the transport.
        let outcome = self
            .client
            .close()
            .await
            .map_err(|error| map_vnc(&error, "stop the VNC engine"));
        // Explicit, so that the release of the socket is a statement rather
        // than a consequence of the function ending. `VncInner`'s destructor
        // signals both engine tasks and the byte-moving one drops the transport
        // as it returns.
        drop(self);
        outcome
    }
}

impl std::fmt::Debug for VncSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VncSession")
            .field("target", &self.target)
            .field("surface", &self.translator.surface())
            .field("view_only", &self.view_only)
            .finish()
    }
}

/// Drives a [`VncSession`] until it ends.
///
/// This is the body a VNC tab is spawned with. It exists alongside
/// `remoter_proto::run_session` rather than instead of it because that loop
/// waits only on commands and cancellation: it has no way to notice the
/// *server* going away, and no way to send the framebuffer update requests
/// RFC 6143 §7.5.3 requires — so a desktop driven by it would draw once and
/// then freeze.
///
/// # Errors
///
/// Never returns `Err`: every failure is folded into the [`CloseReason`] the
/// tab shows, which is what the supervisor expects.
pub async fn run_vnc_session(
    mut session: VncSession,
    mut ctx: SessionContext,
) -> Result<CloseReason, ProtocolError> {
    session.set_session_id(ctx.id);

    // Events the connect path read while waiting for `ServerInit` are handled
    // before anything new is asked for, so nothing the server said is lost to
    // the fact that the loop started late.
    let reason = loop {
        let Some(event) = session.preface.pop_front() else {
            break None;
        };
        match session.receive(event).await {
            Ok(None) => {}
            Ok(Some(reason)) => break Some(reason),
            Err(error) => break Some(CloseReason::Failed(FailureReport::from(&error))),
        }
    };

    let reason = match reason {
        Some(reason) => reason,
        None => drive(&mut session, &mut ctx).await,
    };

    // Output written a microsecond before the close is still output the user
    // wants to see — often the last frame before a `logout` took the desktop
    // away.
    let _ = session.flush_frame().await;
    let _ = session.events.flush().await;
    if let Err(error) = Box::new(session).disconnect().await {
        tracing::debug!(
            stage = error.stage().as_str(),
            "the VNC engine did not stop cleanly"
        );
    }
    Ok(reason)
}

/// One thing the session loop woke for.
///
/// The `select!` produces this and nothing else, and every borrow it took ends
/// with it. Handling the outcome afterwards is what lets an arm that reads from
/// the engine sit beside one that writes to it: the reading future is gone
/// before the writing call is made.
enum Step {
    /// The frame timer fired, or an update request is due.
    Tick,
    /// The engine produced an event, or stopped.
    Event(Result<vnc::VncEvent, vnc::VncError>),
    /// A command arrived, or every handle was dropped.
    Command(Option<SessionCommand>),
}

async fn drive(session: &mut VncSession, ctx: &mut SessionContext) -> CloseReason {
    loop {
        // `None` means there is nothing to wake for: no rectangles are waiting
        // to be flushed, and the server already owes us an update. RFC 6143
        // §7.5.3 lets it sit on an incremental request until something changes,
        // so an idle desktop should cost no timer at all — a wake-up every
        // frame interval per idle tab is a laptop battery.
        let deadline = session
            .coalescer
            .time_to_deadline(Instant::now())
            .or_else(|| (!session.outstanding_request).then(|| session.events.frame_interval()));

        let step = tokio::select! {
            () = ctx.cancel.cancelled() => break CloseReason::ClosedByUser,

            () = async {
                match deadline {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => std::future::pending().await,
                }
            } => Step::Tick,

            // `recv_event` holds the engine's own lock across its await, so it
            // must never be raced with `input` from a second task. It is not:
            // this is one task, and the future is dropped — releasing the lock
            // — before any arm below is acted on.
            event = session.client.recv_event() => Step::Event(event),

            command = ctx.commands.recv() => Step::Command(command),
        };

        let outcome = match step {
            Step::Tick => match session.flush_frame().await {
                Ok(()) => session.poll_for_update().await,
                Err(error) => Err(error),
            },

            Step::Event(Ok(event)) => match session.receive(event).await {
                Ok(None) => Ok(()),
                Ok(Some(reason)) => break reason,
                Err(error) => Err(error),
            },

            Step::Event(Err(error)) => {
                // The engine stopped. That is the far end going away, and it is
                // the normal end of a session as often as it is a failure.
                let error = map_vnc(&error, "read from the VNC engine");
                break match error {
                    ProtocolError::Disconnected { .. } => CloseReason::Disconnected,
                    other => CloseReason::Failed(FailureReport::from(&other)),
                };
            }

            // Every handle is gone; nobody can drive this session again, so
            // holding its socket open would be a leak.
            Step::Command(None) => break CloseReason::ClosedByUser,

            Step::Command(Some(command)) => match command {
                SessionCommand::Resize { cols, rows } => session.resize(cols, rows).await,
                SessionCommand::Input(input) => session.input(input).await,
                SessionCommand::Clipboard(op) => session.clipboard(op).await,
                // This adapter raises no prompts: RFB's only credential is the
                // password, and it is borrowed during the handshake.
                SessionCommand::Prompt(_) => Ok(()),
                SessionCommand::Disconnect => break CloseReason::ClosedByUser,
            },
        };

        if let Err(error) = outcome {
            // An unsupported operation is the interface asking for something
            // RFB has no encoding for — a resize, a clipboard read. It is worth
            // reporting and not worth ending a working desktop over.
            if matches!(error, ProtocolError::Unsupported { .. }) {
                tracing::debug!("the interface asked for something RFB does not carry");
            } else {
                break CloseReason::Failed(FailureReport::from(&error));
            }
        }
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

    #[test]
    fn the_catalogue_keys_are_stable_ascii_and_namespaced() {
        // They are message-catalogue keys, not English: a translator looks them
        // up, and a key that drifts is a string that silently falls back.
        for key in [
            WARNING_BELL,
            WARNING_CLIPBOARD_LOSSY,
            WARNING_CLIPBOARD_MANGLED,
            WARNING_BUTTON_DROPPED,
        ] {
            assert!(key.is_ascii(), "{key}");
            assert!(key.starts_with("vnc."), "{key}");
            assert!(!key.contains(' '), "{key}");
        }
    }
}
