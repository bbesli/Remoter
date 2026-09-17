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
//! below tracks one bit, `outstanding_request`: a request is sent when none is
//! outstanding, and it stops being outstanding when the update that answers it
//! has arrived **in full**.
//!
//! "In full" is the part that used to be wrong. The flag was cleared on the
//! first rectangle of a `FramebufferUpdate`, so a multi-rectangle update
//! un-armed it while the server was still writing and the next tick sent a
//! second request — the very thing the comment claimed could not happen. The
//! boundary the rule needs is the *message* boundary (RFC 6143 §7.6.1), and the
//! only place in this crate that can see one is [`crate::gate`], which parses
//! the server stream on its way in. It counts completed updates; this loop
//! compares that count against the one it last saw. One outstanding request,
//! stated as something that is checked rather than as something that is hoped.
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

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
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
use crate::gate::{GateShared, refine_with_gate};
use crate::keymap::rfb_keysym;
use crate::pointer::{WheelAccumulator, button_mask, has_unencodable_button};
use crate::security::SecurityType;

/// The catalogue key for the bell (RFC 6143 §7.6.3).
pub const WARNING_BELL: &str = "vnc.bell";
/// The catalogue key for a paste that lost characters RFB cannot carry.
pub const WARNING_CLIPBOARD_LOSSY: &str = "vnc.clipboard.substituted";
/// The catalogue key for remote clipboard text that arrived mangled.
pub const WARNING_CLIPBOARD_MANGLED: &str = "vnc.clipboard.inbound_mangled";
/// The catalogue key for a pointer button RFB has no encoding for.
pub const WARNING_BUTTON_DROPPED: &str = "vnc.pointer.button_unsupported";
/// The catalogue key for a resize RFB gives this build no way to ask for.
pub const WARNING_RESIZE_UNSUPPORTED: &str = "vnc.resize_unsupported";
/// The catalogue key for input a framebuffer protocol cannot carry.
pub const WARNING_INPUT_UNSUPPORTED: &str = "vnc.input_unsupported";
/// The catalogue key for a paste refused because the session is view-only.
pub const WARNING_CLIPBOARD_VIEW_ONLY: &str = "vnc.clipboard.view_only";
/// The catalogue key for a clipboard operation the session's policy forbids.
pub const WARNING_CLIPBOARD_POLICY: &str = "vnc.clipboard.policy_refused";
/// The catalogue key for a clipboard operation RFB has no encoding for.
pub const WARNING_CLIPBOARD_UNSUPPORTED: &str = "vnc.clipboard_unsupported";

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
    /// The gate's half of the session: the completed-update counter, and
    /// whatever rule the peer breaks later.
    gate: Arc<GateShared>,
    /// How many complete framebuffer updates had arrived last time the loop
    /// looked. See the module documentation.
    updates_seen: u64,
    /// What RFC 6143 §7.1.2 settled on. Kept so that a session can be asked
    /// what it authenticated with rather than having it inferred.
    security: SecurityType,
    /// Whether the "this button has no RFB encoding" note has been logged. Once
    /// per session: a user holding the back button would otherwise fill a log.
    warned_about_button: bool,
    /// The catalogue keys of refusals already announced on the event stream.
    ///
    /// One entry per kind of refusal, not per refusal: a tab being dragged
    /// asks to resize once per frame, and the same warning once per frame is
    /// noise a user learns to dismiss. See [`VncSession::refuse`].
    refusals_announced: BTreeSet<&'static str>,
}

impl VncSession {
    /// Wraps a started client.
    ///
    /// `width` and `height` come from `ServerInit` (RFC 6143 §7.3.2) and are
    /// what every rectangle is subsequently checked against.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "every one of these is a distinct fact the connect path resolved;                   bundling them into a struct would move the argument list rather                   than shorten it"
    )]
    pub fn new(
        client: VncClient,
        events: EventSink,
        target: HostPort,
        width: u16,
        height: u16,
        clipboard: ClipboardPolicy,
        view_only: bool,
        gate: Arc<GateShared>,
        security: SecurityType,
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
            updates_seen: gate.updates_completed(),
            gate,
            security,
            warned_about_button: false,
            refusals_announced: BTreeSet::new(),
        }
    }

    /// What RFC 6143 §7.1.2 settled on for this session.
    ///
    /// Reported rather than inferred. Guessing it from the server's offer list
    /// and the library's preference is how a session that authenticated with
    /// nothing could be described as one that used the password.
    #[must_use]
    pub const fn security(&self) -> SecurityType {
        self.security
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
                // The flag is deliberately *not* cleared here. A rectangle is
                // not an answer; a complete `FramebufferUpdate` is, and this
                // event carries no boundary. Clearing it here is the defect
                // `poll_for_update` now prevents coming back.
                self.coalescer.push(rect, Instant::now());
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
        self.note_completed_updates();
        if self.outstanding_request {
            return Ok(());
        }
        self.request(X11Event::Refresh).await
    }

    /// Clears the outstanding-request flag once a whole update has landed.
    ///
    /// RFC 6143 §7.6.1: a `FramebufferUpdate` is one message carrying any
    /// number of rectangles, and the server answers one request with one
    /// message. [`crate::gate`] counts those messages as it parses them on the
    /// way in — it is the only thing here that sees the boundary — so "the
    /// request was answered" is a comparison rather than a guess.
    fn note_completed_updates(&mut self) {
        let completed = self.gate.updates_completed();
        if completed != self.updates_seen {
            self.updates_seen = completed;
            self.outstanding_request = false;
        }
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

    /// Refuses an operation, and says so somewhere a user can see it.
    ///
    /// The defect this exists to stop coming back: a refusal that lived only
    /// in the returned `Err`. `SessionCommand` carries no reply channel, so
    /// nothing sends a command's result back to whoever issued it, and
    /// [`run_vnc_session`] matched `ProtocolError::Unsupported` into a
    /// `tracing::debug!` two hundred lines below this method. The view-only
    /// clipboard refusal — added precisely so that a caller would *not*
    /// believe a paste had crossed to the remote machine — was therefore
    /// swallowed on exactly the path a paste takes. A refusal the user is
    /// never told about is indistinguishable from a control that does nothing.
    ///
    /// The `Err` is still returned: a caller holding this session directly
    /// gets the typed failure, and the loop still declines to end a working
    /// desktop over it. What changes is that the event stream now carries the
    /// same fact, once per `key` per session.
    async fn refuse(&mut self, operation: &'static str, key: &'static str) -> ProtocolError {
        if self.refusals_announced.insert(key) {
            // Deliberately ignored. A closed event stream means the presenter
            // is already gone and the loop is ending the session on its own
            // account; turning this into `EventStreamClosed` would replace a
            // true statement about the operation with a misleading one about
            // the channel.
            let _ = self
                .warn(SessionWarning::Other {
                    detail: key.to_owned(),
                })
                .await;
        }
        unsupported(operation)
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
            // own event a keystroke later.
            //
            // The scancode is **not** logged. It used to be, on the reasoning
            // that a keysym is the character typed and a scancode is not — but
            // a scancode names the physical key that was pressed, which is
            // keystroke material in a log file either way. CLAUDE.md §0.2 makes
            // no exception for one key at a time, and a user composing a
            // passphrase with dead keys would leave a trail of them.
            // The message names no field: see the test at the foot of this file.
            tracing::debug!("a key RFB has no name for was dropped");
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

/// Whether an operation puts bytes on the wire that change the far end.
///
/// The question a view-only session has to ask of everything it is handed, and
/// it is asked of the *operation* rather than of the message, because the two
/// arms that send nothing send nothing for reasons that could change.
const fn reaches_the_remote(op: &ClipboardOp) -> bool {
    match op {
        // RFC 6143 §7.5.6 `ClientCutText`: it replaces the server's selection,
        // which is a write to the remote machine by any reading.
        ClipboardOp::Offer(_) => true,
        // A request has no RFB encoding at all — the remote pushes its
        // clipboard unasked — and clearing has none either. Neither produces a
        // byte, so neither is a change a view-only session has to refuse.
        ClipboardOp::Request { .. }
        | ClipboardOp::Clear
        | ClipboardOp::SaveFiles { .. }
        | ClipboardOp::CancelSave => false,
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
    ///
    /// The refusal is also **said out loud**, once per session, as
    /// [`SessionWarning::Other`] carrying [`WARNING_RESIZE_UNSUPPORTED`] — see
    /// [`VncSession::refuse`]. It used to travel no further than
    /// [`run_vnc_session`]'s `tracing::debug!`, which is not a place a user
    /// looks.
    async fn resize(&mut self, _cols: u16, _rows: u16) -> Result<(), ProtocolError> {
        Err(self
            .refuse(
                "asking the server to resize its desktop",
                WARNING_RESIZE_UNSUPPORTED,
            )
            .await)
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
            InputEvent::Bytes(_) => Err(self
                .refuse("byte-stream input", WARNING_INPUT_UNSUPPORTED)
                .await),
        }
    }

    async fn clipboard(&mut self, op: ClipboardOp) -> Result<(), ProtocolError> {
        // View only has to mean the session changes nothing at the far end, not
        // merely that the keyboard is quiet. `ClientCutText` (RFC 6143 §7.5.6)
        // *replaces* the server's selection, so a paste modifies the remote
        // machine as surely as a keystroke does — and the flag used to gate
        // `input` and nothing else, so a session someone opened read-only on
        // purpose could still write to it.
        //
        // Refused rather than silently dropped, which is the opposite of what
        // `input` does with a held key, and deliberately: a paste is one
        // deliberate act, it happens at human speed so it cannot fill a log,
        // and a caller told `Ok` would believe the text had crossed.
        //
        // And the refusal now *travels*. It used to be raised here and dropped
        // two hundred lines below, where the session loop folded every
        // `Unsupported` into a `tracing::debug!` — so "refused, not silently
        // dropped" described the return value and nothing the user could ever
        // see. `refuse` puts it on the event stream as well.
        if self.view_only && reaches_the_remote(&op) {
            return Err(self
                .refuse(
                    "changing the remote clipboard of a view-only session",
                    WARNING_CLIPBOARD_VIEW_ONLY,
                )
                .await);
        }
        if !self.clipboard.permits(&op) {
            return Err(self
                .refuse("this clipboard operation", WARNING_CLIPBOARD_POLICY)
                .await);
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
            ClipboardOp::Offer(ClipboardData::Files(_)) => Err(self
                .refuse("offering files over RFB", WARNING_CLIPBOARD_UNSUPPORTED)
                .await),
            // The remote pushes its clipboard unasked, as `ServerCutText`;
            // there is no request in the protocol. The push is reported as a
            // `ClipboardOffer` and its text is not retained. The contract can
            // carry the content now — `SessionEvent::ClipboardContent` — and
            // this arm is not wired to it, for the reason
            // `crate::protocol::capabilities` gives: turning reading on turns
            // on an interface that offers the local clipboard on every focus,
            // and over RFB an offer is the text itself.
            //
            // `crate::capabilities` reports `ClipboardSupport::None` **because**
            // of this arm. It used to report `Text`, which promised the
            // interface a control this line then refused, and the interface
            // drew it. A capability is a promise; the two now agree.
            ClipboardOp::Request { .. } => Err(self
                .refuse(
                    "reading the remote clipboard",
                    WARNING_CLIPBOARD_UNSUPPORTED,
                )
                .await),
            // RFB carries no files, so there is nothing to save.
            ClipboardOp::SaveFiles { .. } => Err(self
                .refuse(
                    "saving files from the remote clipboard",
                    WARNING_CLIPBOARD_UNSUPPORTED,
                )
                .await),
            // RFB has no way to withdraw an offer, and no save to stop.
            // Reporting a failure would make a tab close report an error it
            // cannot act on.
            ClipboardOp::Clear | ClipboardOp::CancelSave => Ok(()),
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
                // the normal end of a session as often as it is a failure — but
                // it is also what a rule the gate refused looks like from here,
                // and the gate's reason is the better one. `vnc-rs` flattens a
                // rectangle that was refused before it could allocate and a
                // socket that simply closed into the same opaque error.
                let error =
                    refine_with_gate(&session.gate, map_vnc(&error, "read from the VNC engine"));
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
            //
            // This branch is no longer the *only* record of it. Every refusal
            // above goes through `VncSession::refuse`, which puts a catalogue
            // key on the event stream where the tab can render it; a refusal
            // that existed solely as this log line is what made the view-only
            // clipboard guard invisible to the person it was protecting.
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

    use std::collections::BTreeMap;
    use std::time::Duration;

    use remoter_core::{
        EffectiveConnection, GatewayChain, NodeId, ProtocolId, Provenance, ReconnectPolicy,
        RecordingPolicy, Resolved,
    };
    use remoter_proto::{CredentialKind, CredentialProvider, KeyBorrow, event_channel};
    use tokio_util::sync::CancellationToken;

    use crate::protocol::VncProtocol;
    use crate::testing::{RfbServer, Security, transport_pair};

    /// No test may hang: a deadlock would otherwise be a CI job that never
    /// finishes rather than a failure with a name.
    const PATIENCE: Duration = Duration::from_secs(5);
    /// How long a test waits to be sure nothing is coming.
    const SILENCE: Duration = Duration::from_millis(250);

    struct NoCredential;

    impl CredentialProvider for NoCredential {
        fn username(&self) -> Option<&str> {
            None
        }
        fn kind(&self) -> CredentialKind {
            CredentialKind::None
        }
        fn borrow_password(&self, _f: &mut dyn FnMut(&[u8])) -> bool {
            false
        }
        fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
            false
        }
    }

    fn root<T>(value: T) -> Resolved<T> {
        Resolved::new(value, Provenance::DefaultAtRoot)
    }

    /// A connection to loopback, so the clear-text warning is not raised and the
    /// only bytes on the wire are the ones under test.
    fn connection(settings: &[(&str, &str)]) -> EffectiveConnection {
        EffectiveConnection {
            node: NodeId::new(),
            name: "desktop".to_owned(),
            protocol: ProtocolId::new("vnc").unwrap(),
            host: "127.0.0.1".to_owned(),
            port: root(Some(5900)),
            credential: root(None),
            username: root(None),
            credential_attached: false,
            gateway: root(GatewayChain::direct()),
            connect_timeout_ms: root(Some(5_000)),
            keepalive_secs: root(None),
            settings: settings
                .iter()
                .map(|(key, value)| ((*key).to_owned(), root((*value).to_owned())))
                .collect::<BTreeMap<_, _>>(),
            on_connect: root(Vec::new()),
            on_disconnect: root(Vec::new()),
            recording: root(RecordingPolicy::Never),
            auto_reconnect: root(ReconnectPolicy::Never),
            icon: root(None),
            colour: root(None),
        }
    }

    /// A connected session over an in-memory pipe, with the server end left for
    /// the test to read. The receiver is returned because dropping it would
    /// close the event stream under the session.
    async fn connected(
        settings: &[(&str, &str)],
    ) -> (
        VncSession,
        RfbServer,
        tokio::sync::mpsc::Receiver<SessionEvent>,
    ) {
        let (transport, server) = transport_pair(HostPort::new("127.0.0.1", 5900).unwrap());
        let script = tokio::spawn(async move {
            let mut server = server;
            server
                .handshake(Security::None)
                .await
                .expect("the scripted handshake must complete");
            server
                .initialise(64, 32)
                .await
                .expect("the scripted ServerInit must complete");
            server
        });

        let (sink, events) = event_channel(256);
        let protocol = VncProtocol::new().unwrap();
        let session = tokio::time::timeout(
            PATIENCE,
            protocol.connect_session(
                Box::new(transport),
                &connection(settings),
                &NoCredential,
                sink,
                CancellationToken::new(),
            ),
        )
        .await
        .expect("the handshake must not hang")
        .expect("a server offering None authentication connects");

        let server = script.await.expect("the server script must finish");
        (session, server, events)
    }

    #[tokio::test]
    async fn a_view_only_session_puts_no_clipboard_on_the_wire() {
        // The defect: `view_only` gated `input` and nothing else, so
        // `ClientCutText` (RFC 6143 §7.5.6) still reached the server — and that
        // message *replaces* the remote selection. Someone who opened a session
        // read-only, deliberately, was modifying the remote machine.
        let (mut session, mut server, _events) = connected(&[("view_only", "true")]).await;

        let outcome = session
            .clipboard(ClipboardOp::Offer(ClipboardData::Text("paste".to_owned())))
            .await;

        // Nothing is written, so the read must time out rather than return.
        let read = tokio::time::timeout(SILENCE, server.read_exact(1)).await;
        assert!(
            read.is_err(),
            "not one byte may cross from a view-only session"
        );
        // And the caller is told, rather than being left believing the paste
        // arrived at a machine it never reached.
        assert!(
            matches!(outcome, Err(ProtocolError::Unsupported { .. })),
            "the refusal is reported, not swallowed"
        );
    }

    #[tokio::test]
    async fn an_ordinary_session_still_pastes_into_the_remote_clipboard() {
        // The control for the test above: it proves the harness can see a
        // `ClientCutText` when there is one, so the silence it asserts is the
        // fix working rather than the test looking in the wrong place.
        let (mut session, mut server, _events) = connected(&[("view_only", "false")]).await;

        session
            .clipboard(ClipboardOp::Offer(ClipboardData::Text("paste".to_owned())))
            .await
            .expect("an ordinary session pastes");

        let header = tokio::time::timeout(PATIENCE, server.read_exact(8))
            .await
            .expect("the cut text must reach the wire")
            .unwrap();
        assert_eq!(header[0], 6, "ClientCutText is client message type 6");
        assert_eq!(
            u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
            5,
            "five characters of Latin-1"
        );
    }

    #[test]
    fn a_request_and_a_clear_are_not_things_a_view_only_session_has_to_refuse() {
        // Neither produces a byte: RFB has no clipboard request — the server
        // pushes — and no way to withdraw an offer. Refusing them under
        // `view_only` would report a failure for something that never happened.
        assert!(reaches_the_remote(&ClipboardOp::Offer(
            ClipboardData::Text(String::new())
        )));
        assert!(reaches_the_remote(&ClipboardOp::Offer(
            ClipboardData::Files(Vec::new())
        )));
        assert!(!reaches_the_remote(&ClipboardOp::Request { files: false }));
        assert!(!reaches_the_remote(&ClipboardOp::Clear));
    }

    #[test]
    fn nothing_in_this_session_logs_what_the_user_typed() {
        // The defect: a dropped key was logged with its scancode. A scancode
        // names the physical key that was pressed — keystroke material in a log
        // file — and CLAUDE.md §0.2 makes no exception for one key at a time.
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

    /// Drains the sink for a `Warning` carrying `key`, until `PATIENCE` runs
    /// out or the stream goes quiet.
    async fn warning_arrived(
        events: &mut tokio::sync::mpsc::Receiver<SessionEvent>,
        key: &str,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.recv()).await else {
                return false;
            };
            if let SessionEvent::Warning(SessionWarning::Other { detail }) = event {
                if detail == key {
                    return true;
                }
            }
        }
    }

    #[tokio::test]
    async fn a_refused_paste_is_something_the_user_is_told_about() {
        // The defect: the view-only clipboard refusal was raised here and
        // swallowed two hundred lines below, where `drive` folds every
        // `ProtocolError::Unsupported` into a `tracing::debug!`. Nothing
        // carries a command's result back to its issuer — `SessionCommand` has
        // no reply channel — so the guard that was reported as "refused, not
        // silently dropped" was, on the path a paste actually takes, silently
        // dropped.
        //
        // Reverted, this fails on the assertion below rather than on the
        // `Err`: the return value was already right, and that is exactly why
        // the hole survived a round of review.
        let (mut session, _server, mut events) = connected(&[("view_only", "true")]).await;

        let outcome = session
            .clipboard(ClipboardOp::Offer(ClipboardData::Text("paste".to_owned())))
            .await;
        assert!(matches!(outcome, Err(ProtocolError::Unsupported { .. })));

        assert!(
            warning_arrived(&mut events, WARNING_CLIPBOARD_VIEW_ONLY).await,
            "a refused paste must reach the tab, not only the debug log"
        );
    }

    #[tokio::test]
    async fn a_refused_resize_is_announced_once_and_not_once_per_frame() {
        // RFB gives this build no client-initiated resize at all, so the
        // interface's every attempt is refused. The user has to be told; they
        // must not be told sixty times a second while a window is dragged.
        let (mut session, _server, mut events) = connected(&[]).await;

        let first = session.resize(1600, 900).await;
        assert!(matches!(first, Err(ProtocolError::Unsupported { .. })));
        assert!(
            warning_arrived(&mut events, WARNING_RESIZE_UNSUPPORTED).await,
            "the first refusal is announced"
        );

        let again = session.resize(1280, 720).await;
        assert!(matches!(again, Err(ProtocolError::Unsupported { .. })));
        let repeated = tokio::time::timeout(SILENCE, events.recv()).await;
        assert!(
            repeated.is_err(),
            "the warning repeated once per resize request"
        );
    }

    #[tokio::test]
    async fn a_clipboard_operation_rfb_cannot_carry_is_announced_too() {
        // `ClipboardOp::Request` has no RFB encoding — the server pushes, it is
        // never asked — and the policy refuses it besides. Either way the
        // interface is owed an answer it can render.
        let (mut session, _server, mut events) = connected(&[]).await;

        let outcome = session
            .clipboard(ClipboardOp::Request { files: false })
            .await;
        assert!(matches!(outcome, Err(ProtocolError::Unsupported { .. })));
        assert!(
            warning_arrived(&mut events, WARNING_CLIPBOARD_UNSUPPORTED).await,
            "a clipboard control that cannot work must say so"
        );

        // And a refusal that comes from the *policy* rather than from the
        // protocol is announced under its own key, so the tab can tell the
        // user which of the two it was. Files are off by default.
        let outcome = session
            .clipboard(ClipboardOp::Request { files: true })
            .await;
        assert!(matches!(outcome, Err(ProtocolError::Unsupported { .. })));
        assert!(
            warning_arrived(&mut events, WARNING_CLIPBOARD_POLICY).await,
            "a policy refusal is the user's own setting, and worth naming as one"
        );
    }

    #[test]
    fn every_refusal_in_this_file_is_announced() {
        // The part of this round's fix that survives someone adding a *new*
        // refusal. `VncSession::refuse` is the only place in this file
        // permitted to build a `ProtocolError::Unsupported`; anywhere else,
        // `Err(unsupported(...))` would be a refusal that reaches the debug log
        // in `drive` and nobody else — which is what made the view-only
        // clipboard guard invisible to the person it protects.
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
        assert!(body.contains("async fn refuse"));
    }

    #[test]
    fn the_catalogue_keys_are_stable_ascii_and_namespaced() {
        // They are message-catalogue keys, not English: a translator looks them
        // up, and a key that drifts is a string that silently falls back.
        for key in [
            WARNING_BELL,
            WARNING_CLIPBOARD_LOSSY,
            WARNING_CLIPBOARD_MANGLED,
            WARNING_BUTTON_DROPPED,
            WARNING_RESIZE_UNSUPPORTED,
            WARNING_INPUT_UNSUPPORTED,
            WARNING_CLIPBOARD_VIEW_ONLY,
            WARNING_CLIPBOARD_POLICY,
            WARNING_CLIPBOARD_UNSUPPORTED,
        ] {
            assert!(key.is_ascii(), "{key}");
            assert!(key.starts_with("vnc."), "{key}");
            assert!(!key.contains(' '), "{key}");
        }
    }
}
