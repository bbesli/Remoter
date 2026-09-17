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
//! # Nothing that writes is ever raced
//!
//! The loop's `tokio::select!` picks between four cancel-safe futures and then
//! acts *outside* it. Reading may be interrupted — the bytes are buffered
//! either way — but a write may not: a `write_all` dropped between two
//! `poll_write` calls leaves a truncated PDU on the stream, and from there the
//! peer is framing garbage. [`run_rdp_session`] names each branch and why it
//! is safe; [`RdpSession::process_frame`] is the half that must never become
//! one.
//!
//! # Backpressure
//!
//! `docs/architecture/session-pipeline.md` §8 says a framebuffer session drops
//! stale frames and keeps the newest, merging dirty rectangles — rendering a
//! frame the user will never see costs latency on the one they will. That is
//! what [`crate::display::FrameEncoder`]'s coalescer does, and it is why the
//! loop arms a timer only when something is pending.

use core::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use ironrdp::cliprdr::pdu::OwnedFormatDataResponse;
use ironrdp::cliprdr::{CliprdrClient, CliprdrSvcMessages};
use ironrdp::displaycontrol::client::DisplayControlClient;
use ironrdp::graphics::image_processing::PixelFormat as IronPixelFormat;
use ironrdp::pdu::Action;
use ironrdp::pdu::mcs;
use ironrdp::pdu::x224::X224;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use remoter_proto::{
    Capabilities, ClipboardData, ClipboardFiles, ClipboardOp, ClipboardSupport, CloseReason,
    EventSink, FailureReport, HostPort, InputEvent, ProtocolError, SessionContext, SessionEvent,
    SessionId, SessionKind, SessionWarning,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::clipboard::{ClipboardSignals, ClipboardState, MAX_CLIPBOARD_PDU_BYTES, Step};
use crate::clipboard_files::{
    LocalFileSet, OpenFile, SAVE_BUSY, SAVE_NOTHING, SaveJob, SaveStep, WARNING_FILES_UNSUPPORTED,
};
use crate::connect::{Connected, ConnectionConfig, DesktopSize};
use crate::display::FrameEncoder;
use crate::error::{map_io, unsupported, violation};
use crate::framed::{Framed, Reassembly, Verdict, rdp_pdu_length};
use crate::input::InputEncoder;

/// The largest desktop this build will allocate a framebuffer for.
///
/// **The size is the server's choice, not the client's.** MS-RDPBCGR
/// §2.2.7.1.1's Bitmap capability set inside the Demand Active PDU carries the
/// width and height the *server* settled on, and
/// [`crate::connect::capabilities_exchange`] reads them straight off the wire;
/// the requested size in the Client Core Data is only a suggestion. A hostile
/// or compromised host (`docs/security/threat-model.md`) therefore picks the
/// number that [`DecodedImage::new`] turns into `vec![0; width * height * 4]`,
/// and both fields are `u16`: unbounded, that is a 17 GiB allocation.
///
/// An allocation failure **aborts**. It does not unwind, so ADR-0011's "a panic
/// is one failed tab" does not contain it — the process goes, taking every
/// other session and the unlocked vault with it. This is the same class the VNC
/// adapter's gate was built to close (`remoter-proto-vnc/src/gate.rs`,
/// ADR-0013), and the bound is set the same way: at the largest desktop that is
/// *legitimate*, so that refusing anything above it refuses nothing real.
///
/// For RDP that number is fixed by the protocol rather than chosen. MS-RDPEDISP
/// §2.2.2.2.1 caps a monitor the client may **ask** for at 8192x8192, and
/// `crate::protocol`'s settings schema enforces exactly that on the width and
/// height a user can type — so a user may configure 8192x8192 and a conforming
/// server may grant it, and a tighter bound here would refuse a desktop this
/// build itself requested. 8192x8192 is 256 MiB of framebuffer — a great deal,
/// and one sixty-fourth of the 17 GiB `u16::MAX` squared asks for.
pub const MAX_DESKTOP_PIXELS: u64 = 8192 * 8192;

/// How long the deactivation-reactivation sequence gets.
///
/// [`crate::connect::DEFAULT_TIMEOUT`] — thirty seconds — is the budget for the
/// *connection* sequence: a TLS handshake, CredSSP, licensing and the first
/// capability exchange, over a link that has not yet proved it works. A
/// reactivation is none of that. It is one Demand Active and one finalisation
/// exchange on a connection that is already up and already authenticated.
///
/// It also sets a second, less obvious number. [`RdpSession::reactivate`] is
/// the only thing [`run_rdp_session`] awaits that is not bounded by a single
/// PDU, so this is the longest a *closing tab* can wait before its socket is
/// released. Half a minute of that reads as a hang and is what a user reports
/// as one; five seconds is several times longer than any server takes to answer
/// with a PDU it has already decided to send.
pub const REACTIVATION_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the clipboard channel's timers are driven while files are in play.
///
/// `ironrdp-cliprdr` releases a lock the server's clipboard has moved past, and
/// gives up on a file request the server never answered, only when it is
/// asked to look (`Cliprdr::drive_timeouts`). Its own timeouts are a minute, so
/// looking every five seconds is more than often enough — and it happens only
/// while files are on either clipboard or a save is running, so an idle session
/// still wakes for nothing.
pub const CLIPBOARD_TICK: Duration = Duration::from_secs(5);

/// The catalogue key surfaced when the server will not resize its desktop.
pub const WARNING_RESIZE_UNAVAILABLE: &str = "rdp.display_control_unavailable";

/// Refuses a desktop size this build will not allocate a framebuffer for.
///
/// Called on every path that sizes one from a server-chosen number: the first
/// attach, and every reactivation. Failing here is one failed tab with a
/// diagnostic; not failing here is an abort. See [`MAX_DESKTOP_PIXELS`].
fn check_desktop(desktop: DesktopSize) -> Result<(), ProtocolError> {
    if desktop.width == 0 || desktop.height == 0 {
        return Err(violation(
            "the server declared a desktop with no pixels in it",
        ));
    }
    if u64::from(desktop.width) * u64::from(desktop.height) > MAX_DESKTOP_PIXELS {
        return Err(violation(
            "the server declared a desktop larger than this build will accept",
        ));
    }
    Ok(())
}

/// What an RDP session can do, as the adapter offers it.
///
/// The interface reads this rather than hardcoding "RDP has a clipboard
/// button". Three of these are claims the implementation has not earned, and
/// claiming one early would put a control on the tab that does nothing:
///
/// - `file_transfer` is drive redirection (MS-RDPEFS), not in scope for the
///   first RDP milestone.
/// - `audio` is MS-RDPEA, likewise — and the Client Info PDU actively asks the
///   server not to send any, so claiming it would be doubly wrong.
/// - `multi_monitor` is the third; see below.
///
/// `clipboard` is `Text`: MS-RDPECLIP text in both directions, as
/// [`crate::clipboard`] describes, and not files yet. It is `Text` even for a
/// connection whose policy lets nothing cross, because this is asked before any
/// connection's settings are known. Such a connection does not request the
/// channel, and the offers the interface makes on focus are refused as
/// unsupported inside the session loop rather than drawn as anything.
///
/// - `multi_monitor` needs a per-monitor framebuffer stream, which
///   `docs/architecture/rendering.md` defers until the presenter is chosen at
///   the end of v0.2 (ADR-0010).
///
/// # `resizable` here is an offer, not a fact
///
/// `remoter_proto::Protocol::capabilities` is asked before any connection
/// exists, so this function cannot know whether *this* server will resize:
/// resizing needs the Display Control channel (MS-RDPEDISP), which is a dynamic
/// virtual channel the **server** opens, and an older Windows host or an `xrdp`
/// never opens it. `true` is the right answer to "can this adapter resize";
/// it is not an answer to "can this session resize", and it used to be read as
/// one — so the tab drew a resize control, the refusal came back as
/// `ProtocolError::Unsupported`, and the read loop swallowed it into a debug
/// log. The control did nothing and said nothing.
///
/// What the server actually granted is [`RdpSession::granted_capabilities`],
/// which can only be asked once the channel has had its chance to arrive; and a
/// refusal now reaches the user as [`WARNING_RESIZE_UNAVAILABLE`] rather than
/// as a log line. What is still missing is the plumbing that would let
/// `remoter-ipc` replace the tab's stored capabilities with the granted ones
/// mid-session — the session contract has no event shaped like a capability
/// revision, and adding one is a change in `remoter-proto`, not here.
#[must_use]
pub const fn capabilities() -> Capabilities {
    Capabilities {
        kind: SessionKind::Framebuffer,
        // MS-RDPEDISP: the client asks the server to change its desktop size
        // mid-session. This is "smart resize" in `rendering.md`. See the
        // section above for why this is the adapter's offer and not a promise
        // about any particular server.
        resizable: true,
        clipboard: ClipboardSupport::TextAndFiles,
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
    /// The tab's token, once [`run_rdp_session`] is driving. A session driven
    /// by something else holds a token nobody cancels, which is the behaviour
    /// it had before this field existed.
    cancel: CancellationToken,
    /// Whether [`WARNING_RESIZE_UNAVAILABLE`] has already been sent. A tab
    /// being dragged produces a resize request per frame, and a warning per
    /// frame is noise the user learns to ignore — which is the failure mode
    /// the warning exists to avoid.
    resize_refused: bool,
    /// The ceiling on the buffers `ironrdp` grows across many PDUs. See
    /// [`Reassembly`]: `crate::framed::MAX_PDU_BYTES` bounds one PDU and
    /// nothing bounded the reassembly of many.
    reassembly: Reassembly,
    /// The clipboard, when the connection asked for the channel. `None` for a
    /// connection whose policy lets nothing cross.
    clipboard: Option<ClipboardState>,
    /// The id the server gave the clipboard channel, if it joined it.
    clipboard_channel: Option<u16>,
    /// The save of the server's copied files, while one runs.
    save: Option<SaveJob>,
    /// The local file the server is reading, kept open between its requests.
    open_file: Option<OpenFile>,
    /// When the clipboard channel's timers were last driven.
    clipboard_ticked: Instant,
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
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ProtocolViolation`] if the server settled on a desktop
    /// outside [`MAX_DESKTOP_PIXELS`]. Fallible for exactly that reason: the
    /// framebuffer below is sized from a number the server chose, and the only
    /// way to refuse an impossible one without aborting the process is to
    /// refuse it *before* the allocation.
    pub fn attach(
        connected: Connected,
        events: EventSink,
        session: SessionId,
        target: HostPort,
    ) -> Result<Self, ProtocolError> {
        let Connected {
            stream,
            io_channel_id,
            user_channel_id,
            message_channel_id,
            share_id,
            static_channels,
            desktop,
            clipboard: policy,
        } = connected;

        // Before anything is sized from it. `DecodedImage::new` below is
        // `vec![0; width * height * 4]`, and `announce`'s keyframe copies the
        // same surface out again — two allocations from a pair of numbers that
        // came off the wire.
        check_desktop(desktop)?;

        // The channels the server actually joined, taken before the set is
        // moved into the stage. `Reassembly` needs them to tell a chunk of a
        // static virtual channel PDU — which `ironrdp-svc` accumulates without
        // a ceiling — from I/O and message channel traffic, which it does not.
        //
        // The clipboard's channel is the exception to the ceiling's rule: what
        // travels on it is what the remote user copied, so a PDU too large is
        // dropped and said rather than ending the session. See
        // `Reassembly::discard_oversized`.
        let clipboard_channel = static_channels.get_channel_id_by_type::<CliprdrClient>();
        let mut reassembly = Reassembly::new(static_channels.channel_ids().collect::<Vec<_>>());
        if let Some(channel) = clipboard_channel {
            reassembly = reassembly.discard_oversized(channel, MAX_CLIPBOARD_PDU_BYTES);
        }
        let clipboard = if static_channels.get_by_type::<CliprdrClient>().is_some() {
            Some(ClipboardState::new(
                policy,
                clipboard_channel.is_some(),
                Instant::now(),
            )?)
        } else {
            None
        };

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

        Ok(Self {
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
            cancel: CancellationToken::new(),
            resize_refused: false,
            reassembly,
            clipboard,
            clipboard_channel,
            save: None,
            open_file: None,
            clipboard_ticked: Instant::now(),
        })
    }

    /// Adopts the tab's cancellation token.
    ///
    /// [`run_rdp_session`]'s `tokio::select!` already races it, which covers
    /// everything the loop itself awaits. This copy is for the one thing the
    /// loop cannot race: a deactivation-reactivation sequence, which runs to
    /// completion inside [`RdpSession::process_frame`] because abandoning it
    /// could leave a half-written Confirm Active on the stream. Holding the
    /// token lets the sequence be declined at the one moment declining it is
    /// free — before it has written anything.
    pub fn watch_cancellation(&mut self, cancel: CancellationToken) {
        self.cancel = cancel;
    }

    /// What this session can do, as *this server* settled it.
    ///
    /// [`capabilities()`] is the adapter's offer, made before any connection
    /// exists. This is the same set with `resizable` replaced by whether the
    /// Display Control channel (MS-RDPEDISP) is actually open, which is the
    /// only thing that decides whether a resize request goes anywhere.
    ///
    /// The channel is opened by the server and arrives some time after the Font
    /// Map PDU, so this answers "as of now" and can go from `false` to `true`
    /// during the first seconds of a session. It never goes back.
    pub fn granted_capabilities(&mut self) -> Capabilities {
        Capabilities {
            resizable: self.display_control_open(),
            clipboard: if self.clipboard_channel.is_some() {
                ClipboardSupport::TextAndFiles
            } else {
                ClipboardSupport::None
            },
            ..capabilities()
        }
    }

    /// Whether the Display Control channel is open and carrying an id.
    ///
    /// Both halves matter: the channel may be present in the set this client
    /// asked for and not yet have been joined by the server, and
    /// `ActiveStage::encode_resize` returns `None` in either case.
    pub fn display_control_open(&mut self) -> bool {
        self.stage
            .get_dvc::<DisplayControlClient>()
            .and_then(|channel| channel.channel_id())
            .is_some()
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

    /// Reads one whole PDU from the server. Decodes nothing, writes nothing.
    ///
    /// This is the read half of what used to be one `pump` call, and it is
    /// split off so that [`run_rdp_session`]'s `tokio::select!` has something
    /// **cancel-safe** to race. Every byte this future takes from the
    /// transport is appended to the [`Framed`]'s own buffer before the future
    /// reaches its next await point, so dropping it mid-PDU loses nothing: the
    /// next call resumes from what was already buffered. Nothing here writes,
    /// which is the property that matters — see
    /// [`RdpSession::process_frame`].
    ///
    /// # Errors
    ///
    /// Anything the read produced: a peer that hung up, a PDU larger than
    /// [`crate::framed::MAX_PDU_BYTES`], or a transport failure.
    pub async fn read_frame(&mut self) -> Result<bytes::BytesMut, ProtocolError> {
        self.stream.read_pdu(rdp_pdu_length).await
    }

    /// Acts on one frame that [`RdpSession::read_frame`] produced.
    ///
    /// Returns `Some` when the session is over.
    ///
    /// **This must never appear as a branch of a `tokio::select!`, and must
    /// never be wrapped in a timeout.** It writes — the decoder's replies,
    /// frame acknowledgements, the reactivation's Confirm Active — and
    /// [`Framed::write_all`] is not cancel-safe: a future dropped between two
    /// `poll_write` calls leaves a *truncated PDU* on the TLS stream. After
    /// that the server is reading a byte stream that no longer frames and
    /// every later PDU is garbage, which reaches a bug report as "the session
    /// disconnects at random" and is close to undiagnosable from one. The
    /// defect this shape prevents was exactly that: `pump` — read, decode and
    /// reply in one future — raced against a timer tick and an arriving
    /// command inside the read loop's select.
    ///
    /// # Errors
    ///
    /// Anything the decode or the reply produced. A decode failure is a
    /// protocol violation and ends the session: the framebuffer is now a
    /// guess, and continuing would draw a guess.
    pub async fn process_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<Option<CloseReason>, ProtocolError> {
        let action = frame
            .first()
            .and_then(|header| Action::from_fp_output_header(*header).ok())
            .ok_or_else(|| violation("the server sent a PDU with no recognisable action"))?;

        // Before the frame is handed on, and that is the whole point. Both
        // buffers this bounds belong to `ironrdp`, not to this crate:
        // `CompleteData::fragmented_data` for fast-path fragments and
        // `ChunkProcessor::chunked_pdu` for static virtual channel chunks. Both
        // grew without a ceiling and without a declared total, so a server that
        // sent `First` and then `Next` for ever — or chunks that never set
        // `CHANNEL_FLAG_LAST` — grew them until the allocator gave up, which
        // aborts the process rather than failing the tab. A ceiling applied
        // after `process` returns would bound this crate's copy of a buffer the
        // library had already materialised, which is no bound at all. See
        // [`Reassembly`].
        if let Verdict::Discard { channel, first } = self.reassembly.inspect(action, frame)? {
            // Only the clipboard's channel drops rather than fails, and only a
            // PDU it has refused whole. Said once, on the chunk it was refused
            // on, and only if it answered something this client asked for.
            if first && Some(channel) == self.clipboard_channel {
                tracing::debug!("dropped a clipboard PDU larger than this build carries");
                let steps = self
                    .clipboard
                    .as_mut()
                    .map(ClipboardState::discarded)
                    .unwrap_or_default();
                self.carry_out(steps).await?;
            }
            return Ok(None);
        }

        let outputs = self
            .stage
            .process(&mut self.image, action, frame)
            .map_err(|error| {
                tracing::debug!(%error, "an RDP update could not be processed");
                violation("the server sent an update this client could not decode")
            })?;

        for output in outputs {
            if let Some(reason) = self.handle(output).await? {
                return Ok(Some(reason));
            }
        }
        // After the library's own replies, which include the Format List
        // Response a copy on the server is owed before anything else is said
        // about it (MS-RDPECLIP §3.1.5.2.2).
        self.service_clipboard().await?;
        Ok(None)
    }

    /// Acts on whatever the clipboard channel said while the last PDU was
    /// processed. See [`crate::clipboard`] for why it is said to a queue.
    async fn service_clipboard(&mut self) -> Result<(), ProtocolError> {
        if self.clipboard.is_none() {
            return Ok(());
        }
        let signals = self
            .stage
            .get_svc_processor_mut::<CliprdrClient>()
            .and_then(|channel| channel.downcast_backend_mut::<ClipboardSignals>())
            .map(ClipboardSignals::take)
            .unwrap_or_default();
        for signal in signals {
            let Some(state) = self.clipboard.as_mut() else {
                break;
            };
            let steps = state.on_signal(signal);
            self.carry_out(steps).await?;
        }
        Ok(())
    }

    /// Carries out what the clipboard state decided.
    ///
    /// # Errors
    ///
    /// A transport failure, or [`ProtocolError::EventStreamClosed`] once the
    /// presenter is gone. A clipboard PDU the library will not build is logged
    /// and skipped: a clipboard that fails is not a reason to end a desktop
    /// session.
    async fn carry_out(&mut self, steps: Vec<Step>) -> Result<(), ProtocolError> {
        for step in steps {
            match step {
                Step::Announce(formats) => {
                    self.send_on_clipboard(|channel| channel.initiate_copy(&formats))
                        .await?;
                }
                Step::AnnounceFiles(files) => {
                    // Refused by `ironrdp-cliprdr` when the server did not
                    // agree to file streams (§2.2.2.1.1.1), which is the one
                    // failure here the user can do something about.
                    if !self
                        .send_on_clipboard(move |channel| channel.initiate_file_copy(files))
                        .await?
                    {
                        self.warn(WARNING_FILES_UNSUPPORTED).await;
                    }
                }
                Step::Fetch(format) => {
                    self.send_on_clipboard(|channel| channel.initiate_paste(format))
                        .await?;
                }
                Step::Answer(response) => {
                    self.send_on_clipboard(move |channel| answer(channel, response))
                        .await?;
                }
                Step::Serve { request, files } => {
                    let (response, sent) = files.serve(&request, &mut self.open_file).await;
                    self.send_on_clipboard(move |channel| channel.submit_file_contents(response))
                        .await?;
                    if let Some(sent) = sent {
                        self.events.send(SessionEvent::ClipboardFiles(sent)).await?;
                    }
                }
                Step::AnswerFile(response) => {
                    self.send_on_clipboard(move |channel| channel.submit_file_contents(response))
                        .await?;
                }
                Step::SaveData { stream_id, data } => {
                    self.save_received(stream_id, data).await?;
                }
                Step::Deliver(text) => {
                    self.events
                        .send(SessionEvent::ClipboardContent(ClipboardData::Text(text)))
                        .await?;
                }
                Step::Files(files) => {
                    self.events
                        .send(SessionEvent::ClipboardFiles(files))
                        .await?;
                }
                Step::Warn(key) => self.warn(key).await,
            }
        }
        Ok(())
    }

    /// Says something on the event stream, by catalogue key.
    ///
    /// Ignored when it cannot be sent, as for the resize refusal: a closed
    /// event stream ends the session on the loop's own account.
    async fn warn(&mut self, key: &'static str) {
        let _ = self
            .events
            .send(SessionEvent::Warning(SessionWarning::Other {
                detail: key.to_owned(),
            }))
            .await;
    }

    /// Builds PDUs on the clipboard channel and writes them. Returns whether
    /// anything was sent.
    async fn send_on_clipboard(
        &mut self,
        build: impl FnOnce(
            &mut CliprdrClient,
        )
            -> ironrdp::pdu::PduResult<CliprdrSvcMessages<ironrdp::cliprdr::Client>>,
    ) -> Result<bool, ProtocolError> {
        let Some(channel) = self.stage.get_svc_processor_mut::<CliprdrClient>() else {
            return Ok(false);
        };
        let messages = match build(channel) {
            Ok(messages) => messages,
            Err(error) => {
                tracing::debug!(%error, "a clipboard PDU could not be built");
                return Ok(false);
            }
        };
        // Fails only when the server never joined the channel, in which case
        // there is nowhere to send it.
        let bytes = match self.stage.process_svc_processor_messages(messages) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::debug!(%error, "a clipboard PDU could not be encoded");
                return Ok(false);
            }
        };
        if !bytes.is_empty() {
            self.stream.write_all(&bytes).await?;
        }
        Ok(true)
    }

    /// Starts saving the server's copied files into `directory`.
    async fn start_save(&mut self, directory: String) -> Result<(), ProtocolError> {
        if self.save.is_some() {
            return self
                .files_event(ClipboardFiles::Failed {
                    reason: SAVE_BUSY.to_owned(),
                })
                .await;
        }
        let planned = match self
            .clipboard
            .as_ref()
            .and_then(ClipboardState::remote_files)
        {
            Some((files, clip_data_id)) => {
                SaveJob::plan(std::path::Path::new(&directory), files, clip_data_id).await
            }
            None => Err(SAVE_NOTHING),
        };
        match planned {
            Ok(mut job) => {
                let mut events = Vec::new();
                let outcome = job.advance(&mut events).await;
                self.save = Some(job);
                self.clipboard_ticked = Instant::now();
                self.step_save(outcome, events).await
            }
            Err(reason) => {
                self.files_event(ClipboardFiles::Failed {
                    reason: reason.to_owned(),
                })
                .await
            }
        }
    }

    /// Takes a piece of a file for the save in progress.
    async fn save_received(
        &mut self,
        stream_id: u32,
        data: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<(), ProtocolError> {
        let Some(job) = self.save.as_mut() else {
            return Ok(());
        };
        // A response to a request a cancelled or finished save made. Nothing is
        // waiting for it.
        if !job.expects(stream_id) {
            return Ok(());
        }
        let mut events = Vec::new();
        let outcome = job
            .receive(data.as_deref().map(Vec::as_slice), &mut events)
            .await;
        self.step_save(outcome, events).await
    }

    /// Reports what a save did and asks for what it needs next.
    async fn step_save(
        &mut self,
        outcome: Result<SaveStep, &'static str>,
        events: Vec<ClipboardFiles>,
    ) -> Result<(), ProtocolError> {
        for event in events {
            self.files_event(event).await?;
        }
        match outcome {
            Ok(SaveStep::Request(request)) => {
                let sent = self
                    .send_on_clipboard(move |channel| channel.request_file_contents(request))
                    .await?;
                if !sent {
                    self.fail_save(WARNING_FILES_UNSUPPORTED).await?;
                }
                Ok(())
            }
            Ok(SaveStep::Finished(done)) => {
                self.save = None;
                self.files_event(done).await
            }
            Err(reason) => self.fail_save(reason).await,
        }
    }

    async fn fail_save(&mut self, reason: &'static str) -> Result<(), ProtocolError> {
        if let Some(job) = self.save.take() {
            job.abandon().await;
        }
        self.files_event(ClipboardFiles::Failed {
            reason: reason.to_owned(),
        })
        .await
    }

    /// Stops the save in progress, if there is one.
    async fn cancel_save(&mut self) -> Result<(), ProtocolError> {
        let Some(job) = self.save.take() else {
            return Ok(());
        };
        job.abandon().await;
        self.files_event(ClipboardFiles::Cancelled).await
    }

    async fn files_event(&mut self, event: ClipboardFiles) -> Result<(), ProtocolError> {
        self.events.send(SessionEvent::ClipboardFiles(event)).await
    }

    /// How long until the clipboard channel's timers are due, when anything
    /// needs them. See [`CLIPBOARD_TICK`].
    #[must_use]
    pub fn clipboard_deadline(&self, now: Instant) -> Option<Duration> {
        let busy = self.save.is_some()
            || self
                .clipboard
                .as_ref()
                .is_some_and(ClipboardState::holds_files);
        busy.then(|| {
            CLIPBOARD_TICK.saturating_sub(now.saturating_duration_since(self.clipboard_ticked))
        })
    }

    /// Drives the clipboard channel's timers if they are due: locks the server
    /// no longer needs are released, and a file request it never answered is
    /// failed rather than waited on for ever.
    ///
    /// # Errors
    ///
    /// A transport failure.
    pub async fn drive_clipboard(&mut self, now: Instant) -> Result<(), ProtocolError> {
        match self.clipboard_deadline(now) {
            Some(remaining) if remaining.is_zero() => {}
            _ => return Ok(()),
        }
        self.clipboard_ticked = now;
        self.send_on_clipboard(ironrdp::cliprdr::Cliprdr::drive_timeouts)
            .await?;
        // A request given up on reaches the backend as a failed response.
        self.service_clipboard().await
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
                if self.cancel.is_cancelled() {
                    // The tab closed while this frame was being decoded.
                    // Nothing of the sequence has been written yet, so this is
                    // the one point at which declining it costs nothing: no
                    // half-written Confirm Active, no reply owed. Starting it
                    // anyway would hold the tab, its task and its socket for
                    // the whole of `REACTIVATION_TIMEOUT` to rebuild a share
                    // nobody will look at.
                    tracing::debug!(
                        target = %self.target,
                        "the tab closed before the reactivation began; declining it"
                    );
                    return Ok(Some(CloseReason::ClosedByUser));
                }
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
    ///
    /// The sequence is **bounded**, and has to be:
    /// [`crate::connect::reactivate`] gives the whole exchange the
    /// configuration's `timeout` and caps how many Deactivate All PDUs may
    /// precede the Demand Active ([`crate::connect::MAX_DEACTIVATIONS`]).
    /// Neither bound existed here once, and a server that sent a Deactivate All
    /// and then nothing held this read loop — and with it the tab, its socket
    /// and its task — open for as long as the connection stayed up. The bound
    /// lives in the reads rather than around the whole call so that reaching it
    /// cannot drop a half-written Confirm Active; see
    /// [`RdpSession::process_frame`].
    ///
    /// The budget is [`REACTIVATION_TIMEOUT`] and **not**
    /// [`crate::connect::DEFAULT_TIMEOUT`], which is what a fresh
    /// [`ConnectionConfig`] would carry. Thirty seconds is the connection
    /// sequence's number, and this is the one call the read loop cannot
    /// interrupt: a tab closed a moment after a Deactivate All arrived waited
    /// out the whole of it before its socket was released, which is half a
    /// minute of a window that will not go away.
    async fn reactivate(&mut self) -> Result<(), ProtocolError> {
        tracing::debug!(target = %self.target, "the server deactivated the share; reactivating");
        let config = ConnectionConfig {
            desktop: self.desktop,
            timeout: REACTIVATION_TIMEOUT,
            ..ConnectionConfig::new(self.target.clone(), String::new())
        };
        let (share_id, desktop) = crate::connect::reactivate(
            &mut self.stream,
            &config,
            self.user_channel_id,
            self.io_channel_id,
        )
        .await?;
        // The new size is the server's choice too, and it lands in the same
        // two allocations the first one did. See `MAX_DESKTOP_PIXELS`: a
        // reactivation is a second, equally unbounded route to the abort, and
        // one this adapter reaches *after* a session is already established.
        check_desktop(desktop)?;

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

/// `submit_format_data`, as a function so that the response can be moved into
/// the closure that builds it.
fn answer(
    channel: &mut CliprdrClient,
    response: OwnedFormatDataResponse,
) -> ironrdp::pdu::PduResult<CliprdrSvcMessages<ironrdp::cliprdr::Client>> {
    channel.submit_format_data(response)
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
    ///
    /// That refusal is also **said out loud**, once per session, as
    /// [`SessionWarning::Other`] carrying [`WARNING_RESIZE_UNAVAILABLE`]. It
    /// used to travel only as far as [`run_rdp_session`]'s
    /// `tracing::debug!`, which is not a place a user looks: the tab drew a
    /// resize control because [`capabilities()`] offers one, the control did
    /// nothing, and nothing on screen explained why.
    async fn resize(&mut self, cols: u16, rows: u16) -> Result<(), ProtocolError> {
        // §2.2.2.2.1: at least 200, at most 8192, and the width must be even.
        // A request outside that is rejected by the server rather than
        // clamped, so it is clamped here.
        let (width, height) = ironrdp::displaycontrol::pdu::MonitorLayoutEntry::adjust_display_size(
            u32::from(cols),
            u32::from(rows),
        );

        let Some(encoded) = self.stage.encode_resize(width, height, None, None) else {
            // MS-RDPEDISP is a dynamic virtual channel the *server* opens; an
            // older Windows host and `xrdp` never do. Told once, because a tab
            // being dragged asks per frame and a warning per frame is noise.
            if !self.resize_refused {
                self.resize_refused = true;
                tracing::info!(
                    target = %self.target,
                    "this server did not open the Display Control channel; it cannot be resized"
                );
                // Ignored deliberately: a closed event stream means the
                // presenter is already gone, and the loop ends the session on
                // its own account. Failing the resize with
                // `EventStreamClosed` would report the wrong thing about the
                // wrong subject.
                let _ = self
                    .events
                    .send(SessionEvent::Warning(SessionWarning::Other {
                        detail: WARNING_RESIZE_UNAVAILABLE.to_owned(),
                    }))
                    .await;
            }
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

    /// The clipboard: offers local text or files to the server, asks again
    /// for the server's text, saves the server's files, or withdraws an offer.
    /// MS-RDPECLIP; see [`crate::clipboard`] and [`crate::clipboard_files`].
    ///
    /// An offer the server already holds, or one the connection's policy does
    /// not allow, does nothing and succeeds: the interface offers on every
    /// focus, and neither is something the user did.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Unsupported`] for asking the server for its files by
    /// request (they are offered, then saved), and for any operation on a
    /// connection whose policy did not ask for the channel. A transport failure
    /// otherwise.
    async fn clipboard(&mut self, op: ClipboardOp) -> Result<(), ProtocolError> {
        let Some(state) = self.clipboard.as_mut() else {
            return Err(unsupported("clipboard transfer"));
        };
        let steps = match op {
            ClipboardOp::Offer(ClipboardData::Text(text)) => {
                let text = Zeroizing::new(text);
                state.offer(&text, Instant::now())
            }
            ClipboardOp::Offer(ClipboardData::Files(paths)) => {
                if !state.policy().files {
                    return Ok(());
                }
                match LocalFileSet::collect(&paths).await {
                    Ok(files) => match self.clipboard.as_mut() {
                        Some(state) => state.offer_files(files, Instant::now()),
                        None => Vec::new(),
                    },
                    Err(key) => vec![Step::Warn(key)],
                }
            }
            ClipboardOp::Request { files: true } => {
                return Err(unsupported("requesting files over the clipboard"));
            }
            ClipboardOp::Request { files: false } => state.request(),
            ClipboardOp::Clear => state.clear(),
            ClipboardOp::SaveFiles { directory } => {
                if !state.policy().files {
                    return Err(unsupported("saving files over the clipboard"));
                }
                return self.start_save(directory).await;
            }
            ClipboardOp::CancelSave => return self.cancel_save().await,
        };
        self.clipboard_ticked = Instant::now();
        self.carry_out(steps).await
    }

    /// Says goodbye and releases everything.
    ///
    /// Three things, in order, and the order matters:
    ///
    /// 1. Release every held key and button. A tab closed with Alt down leaves
    ///    the *server* believing Alt is down, and the next session inherits it.
    /// 2. Send the Client Shutdown Request PDU (MS-RDPBCGR §2.2.2.1), which is
    ///    how a client asks to log off cleanly rather than dropping the
    ///    socket. The section number was §2.2.2.2 here until someone checked
    ///    it: that is the *Server* Shutdown Request Denied PDU, the reply this
    ///    client may receive, not the request it sends. A wrong citation is
    ///    worse than none, because it stops the next reader verifying — they
    ///    read the wrong structure and find that the code matches nothing.
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

/// What woke the read loop. One variant per branch of its `tokio::select!`.
///
/// The select *chooses*; it does not *act*. Everything the choice leads to —
/// every await that writes to the socket — happens after the select has
/// returned one of these, where no other branch can drop it. See
/// [`run_rdp_session`].
enum Woken {
    /// The tab closed.
    Cancelled,
    /// A coalesced frame's window has closed and it is due.
    FrameDue,
    /// A whole PDU arrived, or the read failed.
    Frame(Result<bytes::BytesMut, ProtocolError>),
    /// The interface asked for something. `None` when every handle is gone.
    Command(Option<remoter_proto::SessionCommand>),
}

/// Drives a session until it ends.
///
/// The RDP counterpart of `remoter_proto::run_session`, which cannot be used
/// directly: a framebuffer session has a *read* loop of its own, and the
/// generic driver only pumps commands.
///
/// # Cancellation safety, and the defect that made it load-bearing
///
/// `tokio::select!` drops every branch it did not choose, at whatever await
/// point that branch had reached. So a future may only be a branch here if
/// dropping it mid-flight loses nothing. All four are:
///
/// - `CancellationToken::cancelled()` — documented cancel-safe; it registers
///   on a shared notification and holds no state of its own.
/// - `tokio::time::sleep` — dropping a timer forgets a wake-up, nothing more.
///   The deadline is recomputed from the coalescer at the top of every
///   iteration, so a forgotten one is re-armed, not lost.
/// - `mpsc::Receiver::recv` — documented cancel-safe: if it is dropped before
///   completing, no message has been taken off the channel.
/// - [`RdpSession::read_frame`] — bytes reach the `Framed`'s own buffer before
///   the future's next await point, so a dropped read resumes from what was
///   already buffered.
///
/// What is **not** here is anything that writes. It used to be:
/// `RdpSession::pump` read, decoded *and* replied in one future, and a timer
/// tick or an arriving `SessionCommand` could drop it in the middle of
/// `write_all` — leaving a truncated PDU on the TLS stream, after which the
/// server was reading a byte stream that no longer frames and every later PDU
/// was garbage. It surfaced as a random disconnect, which is nearly
/// undiagnosable from a bug report. The replies now happen in
/// [`RdpSession::process_frame`] *after* the select has returned, where they
/// run to completion; the same is true of every `Session` method called from
/// the command branch, and of `flush_frames`.
///
/// The cost is that a write already in flight is not interrupted by a closing
/// tab. That is a bounded wait on one PDU against a socket the peer is still
/// reading, and it is the trade this shape is making on purpose: half a PDU on
/// the wire is worse than one more PDU on the wire.
///
/// # What a closing tab actually waits for
///
/// "One PDU" is true of every arm but one. A Deactivate All sends
/// [`RdpSession::process_frame`] into the deactivation-reactivation sequence
/// (MS-RDPBCGR §1.3.1.3), which is several PDUs and writes in the middle of
/// them, so it cannot be abandoned part way without risking a truncated Confirm
/// Active. Two things keep that from reading as a hang, and both are needed:
/// the sequence is **declined outright** if the tab is already gone when the
/// Deactivate All arrives — nothing has been written at that point — and once
/// begun it is bounded by [`REACTIVATION_TIMEOUT`] rather than by the
/// connection sequence's thirty seconds. Five seconds is the honest worst case;
/// thirty was, and a tab that takes half a minute to close is reported as a
/// hang because that is what it is.
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
    // The loop's `select!` races this token too; the session needs its own
    // handle for the one stretch the select is not watching. See
    // [`RdpSession::watch_cancellation`].
    session.watch_cancellation(ctx.cancel.clone());

    if let Err(error) = session.announce().await {
        return Ok(CloseReason::Failed(FailureReport::from(&error)));
    }

    let reason = loop {
        let now = Instant::now();
        // Armed only when something is pending, so an idle session — a login
        // screen nobody is touching — wakes for nothing.
        let deadline = match (session.frame_deadline(now), session.clipboard_deadline(now)) {
            (Some(frame), Some(clipboard)) => Some(frame.min(clipboard)),
            (frame, clipboard) => frame.or(clipboard),
        };

        let woken = tokio::select! {
            // Biased so a closed tab wins a race with an arriving frame: the
            // tab is gone either way, and decoding one more update costs the
            // user nothing and the process a socket.
            biased;
            () = ctx.cancel.cancelled() => Woken::Cancelled,

            () = async {
                match deadline {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => std::future::pending().await,
                }
            } => Woken::FrameDue,

            outcome = session.read_frame() => Woken::Frame(outcome),

            command = ctx.commands.recv() => Woken::Command(command),
        };

        // From here down nothing is racing anything: whatever this arm awaits
        // runs to completion.
        match woken {
            Woken::Cancelled => break CloseReason::ClosedByUser,

            Woken::FrameDue => {
                if session.flush_frames(Instant::now()).await.is_err() {
                    // The presenter is gone; there is nobody left to render.
                    break CloseReason::ClosedByUser;
                }
                // The same timer serves the clipboard's, which fire only while
                // files are in play. Each checks whether it is actually due.
                if let Err(error) = session.drive_clipboard(Instant::now()).await {
                    break close_reason_for(&error);
                }
            }

            Woken::Frame(Err(error)) => break close_reason_for(&error),
            Woken::Frame(Ok(frame)) => match session.process_frame(&frame).await {
                Ok(Some(reason)) => break reason,
                Ok(None) => {}
                Err(error) => break close_reason_for(&error),
            },

            // Every handle is gone; nobody can drive this session again, so
            // holding its socket open would be a leak.
            Woken::Command(None) => break CloseReason::ClosedByUser,

            Woken::Command(Some(command)) => {
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
                    //
                    // This branch is no longer the *only* record of it: the
                    // method that raised it says so on the event stream, where
                    // the user can see it. A refusal that existed solely as
                    // this log line is what left a resize control on the tab
                    // doing nothing and explaining nothing.
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

    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    use bytes::BytesMut;
    use ironrdp::core::encode_vec;
    use ironrdp::pdu::rdp::autodetect::{
        AutoDetectReqPdu, AutoDetectRequest, AutoDetectResponse, AutoDetectRspPdu,
    };
    use ironrdp::svc::StaticChannelSet;
    use parking_lot::Mutex;
    use remoter_proto::{SessionCommand, Transport, TransportKind, TransportPeer, event_channel};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_util::sync::CancellationToken;

    /// MS-RDPBCGR §2.2.1.13.1: the server's own MCS channel is 1002.
    const SERVER_INITIATOR: u16 = 1002;
    const IO_CHANNEL: u16 = 1003;
    const USER_CHANNEL: u16 = 1004;
    const MESSAGE_CHANNEL: u16 = 1005;
    /// The id the server gives `drdynvc` in these tests.
    const SVC_CHANNEL: u16 = 1006;
    const SHARE_ID: u32 = 0x0003_ea03;

    /// How many bytes [`DripTransport`] accepts before stalling.
    const WRITE_CHUNK: usize = 4;

    fn target() -> HostPort {
        HostPort::new("ts-01.corp.example", 3389).unwrap()
    }

    /// A transport that takes a write a few bytes at a time, stalling in
    /// between, and that never hangs up when its script runs out.
    ///
    /// Both properties are needed to put the session where the defect lived:
    /// the stall leaves it suspended *inside* `write_all`, which is where a
    /// dropped future truncates a PDU, and a transport that read as end of
    /// stream would end the loop before anything could race. A real TLS stream
    /// over a real socket stalls for the same reason — a full send buffer —
    /// several times per frame on a busy link.
    struct DripTransport {
        reads: VecDeque<Vec<u8>>,
        /// Whether a pause follows each chunk, so that a PDU split across two
        /// chunks really is half-read for a while.
        pause_between_reads: bool,
        /// When the next chunk may be handed over. A *time*, not a "skip one
        /// poll" flag: `tokio::time::timeout` polls its inner future once more
        /// when the deadline expires, and a one-poll pause would hand the rest
        /// of the PDU over on exactly that poll.
        resume_at: Option<std::time::Instant>,
        written: Arc<Mutex<Vec<u8>>>,
        stall_next: Arc<AtomicBool>,
        peer: TransportPeer,
    }

    /// How long [`DripTransport`] pauses between two read chunks.
    const READ_PAUSE: core::time::Duration = core::time::Duration::from_millis(300);
    /// How long it stalls partway through a write.
    const WRITE_STALL: core::time::Duration = core::time::Duration::from_millis(20);

    impl DripTransport {
        fn new(reads: Vec<Vec<u8>>) -> Self {
            Self {
                reads: reads.into(),
                pause_between_reads: false,
                resume_at: None,
                written: Arc::new(Mutex::new(Vec::new())),
                stall_next: Arc::new(AtomicBool::new(false)),
                peer: TransportPeer::direct(TransportKind::Tcp, target()),
            }
        }

        fn pausing_between_reads(mut self) -> Self {
            self.pause_between_reads = true;
            self
        }

        fn written(&self) -> Arc<Mutex<Vec<u8>>> {
            Arc::clone(&self.written)
        }
    }

    /// Wakes `waker` after `delay`, from a task of its own.
    fn wake_after(waker: std::task::Waker, delay: core::time::Duration) {
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            waker.wake();
        });
    }

    impl AsyncRead for DripTransport {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if let Some(resume_at) = self.resume_at {
                let now = std::time::Instant::now();
                if now < resume_at {
                    wake_after(cx.waker().clone(), resume_at - now);
                    return Poll::Pending;
                }
                self.resume_at = None;
            }
            match self.reads.pop_front() {
                Some(chunk) => {
                    if self.pause_between_reads {
                        self.resume_at = Some(std::time::Instant::now() + READ_PAUSE);
                    }
                    let take = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..take]);
                    if take < chunk.len() {
                        self.reads.push_front(chunk[take..].to_vec());
                    }
                    Poll::Ready(Ok(()))
                }
                // Silent, not closed: a server with nothing to say yet.
                None => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for DripTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.stall_next.swap(false, Ordering::SeqCst) {
                // Woken again shortly. The delay is what gives anything else
                // that is ready — a queued command, an expired timer — the
                // chance to win a race against the half-finished write.
                wake_after(cx.waker().clone(), WRITE_STALL);
                return Poll::Pending;
            }
            self.stall_next.store(true, Ordering::SeqCst);
            let take = buf.len().min(WRITE_CHUNK);
            self.written.lock().extend_from_slice(&buf[..take]);
            Poll::Ready(Ok(take))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Transport for DripTransport {
        fn peer(&self) -> &TransportPeer {
            &self.peer
        }
    }

    /// A server Auto-Detect RTT Measure Request on the message channel
    /// (MS-RDPBCGR §2.2.14.1.1), wrapped in the MCS Send Data Indication every
    /// server-to-client PDU travels in.
    ///
    /// This one is used because `ironrdp-session` answers it *itself*: one
    /// inbound PDU, one outbound PDU, no framebuffer state involved. That is
    /// the smallest thing that makes the session write while it is reading.
    fn rtt_request(sequence_number: u16) -> Vec<u8> {
        let request = AutoDetectReqPdu::new(AutoDetectRequest::rtt_continuous(sequence_number));
        let user_data = encode_vec(&request).unwrap();
        encode_vec(&X224(mcs::SendDataIndication {
            initiator_id: SERVER_INITIATOR,
            channel_id: MESSAGE_CHANNEL,
            user_data: std::borrow::Cow::Owned(user_data),
        }))
        .unwrap()
    }

    /// The RTT Measure Response the session owes in reply (§2.2.14.2.1),
    /// encoded exactly as `ironrdp-session` encodes it.
    fn rtt_response(sequence_number: u16) -> Vec<u8> {
        let response = AutoDetectRspPdu::new(AutoDetectResponse::RttResponse { sequence_number });
        let mut buffer = ironrdp::core::WriteBuf::new();
        mcs::encode_send_data_request(USER_CHANNEL, MESSAGE_CHANNEL, &response, &mut buffer)
            .unwrap();
        buffer.filled().to_vec()
    }

    /// A session over `transport`, with a live event receiver so that
    /// `announce` does not fail for want of a consumer.
    fn attached(
        transport: DripTransport,
    ) -> (
        RdpSession,
        SessionContext,
        tokio::sync::mpsc::Sender<SessionCommand>,
        tokio::sync::mpsc::Receiver<SessionEvent>,
    ) {
        attached_at(
            transport,
            DesktopSize {
                width: 64,
                height: 64,
            },
            StaticChannelSet::new(),
        )
        .expect("64x64 is inside every bound this module has")
    }

    /// A session whose `drdynvc` channel the server has joined, which is what
    /// puts `ironrdp-svc`'s chunk reassembly on the path.
    fn attached_on_channel(
        transport: DripTransport,
    ) -> (
        RdpSession,
        SessionContext,
        tokio::sync::mpsc::Sender<SessionCommand>,
        tokio::sync::mpsc::Receiver<SessionEvent>,
    ) {
        let mut channels = crate::connect::static_channels(crate::clipboard::NO_CLIPBOARD);
        let type_id = channels
            .type_ids()
            .next()
            .expect("drdynvc is the one channel this build requests");
        channels.attach_channel_id(type_id, SVC_CHANNEL);
        attached_at(
            transport,
            DesktopSize {
                width: 64,
                height: 64,
            },
            channels,
        )
        .expect("64x64 is inside every bound this module has")
    }

    /// The same, for a desktop size the test chooses — including ones
    /// [`check_desktop`] must refuse.
    fn attached_at(
        transport: DripTransport,
        desktop: DesktopSize,
        static_channels: StaticChannelSet,
    ) -> Result<
        (
            RdpSession,
            SessionContext,
            tokio::sync::mpsc::Sender<SessionCommand>,
            tokio::sync::mpsc::Receiver<SessionEvent>,
        ),
        ProtocolError,
    > {
        attached_with_policy(
            transport,
            desktop,
            static_channels,
            remoter_proto::ClipboardPolicy::default(),
        )
    }

    fn attached_with_policy(
        transport: DripTransport,
        desktop: DesktopSize,
        static_channels: StaticChannelSet,
        clipboard: remoter_proto::ClipboardPolicy,
    ) -> Result<
        (
            RdpSession,
            SessionContext,
            tokio::sync::mpsc::Sender<SessionCommand>,
            tokio::sync::mpsc::Receiver<SessionEvent>,
        ),
        ProtocolError,
    > {
        let connected = Connected {
            stream: Framed::new(Box::new(transport), target()),
            io_channel_id: IO_CHANNEL,
            user_channel_id: USER_CHANNEL,
            message_channel_id: Some(MESSAGE_CHANNEL),
            share_id: SHARE_ID,
            static_channels,
            desktop,
            clipboard,
        };
        let (events, event_rx) = event_channel(32);
        let session =
            RdpSession::attach(connected, events.clone(), SessionId::from_raw(1), target())?;
        let (tx, commands) = tokio::sync::mpsc::channel(4);
        let ctx = SessionContext {
            id: SessionId::from_raw(1),
            cancel: CancellationToken::new(),
            events,
            commands,
        };
        Ok((session, ctx, tx, event_rx))
    }

    /// Any Share Control PDU on the io channel, wrapped in the MCS Send Data
    /// Indication every server-to-client PDU travels in.
    fn share_control(pdu: ironrdp::pdu::rdp::headers::ShareControlPdu) -> Vec<u8> {
        use ironrdp::pdu::rdp::headers::ShareControlHeader;
        let user_data = encode_vec(&ShareControlHeader {
            share_control_pdu: pdu,
            pdu_source: SERVER_INITIATOR,
            share_id: SHARE_ID,
        })
        .unwrap();
        encode_vec(&X224(mcs::SendDataIndication {
            initiator_id: SERVER_INITIATOR,
            channel_id: IO_CHANNEL,
            user_data: std::borrow::Cow::Owned(user_data),
        }))
        .unwrap()
    }

    /// A Share Data PDU inside one of those.
    fn share_data(pdu: ironrdp::pdu::rdp::headers::ShareDataPdu) -> Vec<u8> {
        use ironrdp::pdu::rdp::client_info::CompressionType;
        use ironrdp::pdu::rdp::headers::{
            CompressionFlags, ShareControlPdu, ShareDataHeader, StreamPriority,
        };
        share_control(ShareControlPdu::Data(ShareDataHeader {
            share_data_pdu: pdu,
            stream_priority: StreamPriority::Medium,
            compression_flags: CompressionFlags::empty(),
            compression_type: CompressionType::K8,
        }))
    }

    /// A Server Deactivate All PDU (MS-RDPBCGR §2.2.3.1).
    fn deactivate_all() -> Vec<u8> {
        use ironrdp::pdu::rdp::headers::{ServerDeactivateAll, ShareControlPdu};
        share_control(ShareControlPdu::ServerDeactivateAll(ServerDeactivateAll))
    }

    /// A Server Demand Active PDU (§2.2.1.13.1) declaring a desktop of
    /// `width` by `height` — the number the reactivation takes its new
    /// framebuffer size from.
    fn demand_active(width: u16, height: u16) -> Vec<u8> {
        use ironrdp::pdu::rdp::capability_sets::{
            Bitmap, BitmapDrawingFlags, CapabilitySet, DemandActive, ServerDemandActive,
        };
        use ironrdp::pdu::rdp::headers::ShareControlPdu;
        share_control(ShareControlPdu::ServerDemandActive(ServerDemandActive {
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
        }))
    }

    /// The server's half of the finalization sequence (§2.2.1.15–2.2.1.19):
    /// a Synchronize, two Controls, then the Font Map that ends it.
    fn finalization() -> Vec<u8> {
        use ironrdp::pdu::rdp::finalization_messages::{
            ControlAction, ControlPdu, FontPdu, SynchronizePdu,
        };
        use ironrdp::pdu::rdp::headers::ShareDataPdu;
        let mut script = share_data(ShareDataPdu::Synchronize(SynchronizePdu {
            target_user_id: SERVER_INITIATOR,
        }));
        script.extend_from_slice(&share_data(ShareDataPdu::Control(ControlPdu {
            action: ControlAction::Cooperate,
            grant_id: 0,
            control_id: 0,
        })));
        script.extend_from_slice(&share_data(ShareDataPdu::Control(ControlPdu {
            action: ControlAction::GrantedControl,
            grant_id: USER_CHANNEL,
            control_id: u32::from(SERVER_INITIATOR),
        })));
        script.extend_from_slice(&share_data(ShareDataPdu::FontMap(FontPdu::default())));
        script
    }

    #[tokio::test]
    async fn a_reply_in_flight_is_never_cut_in_half_by_something_else_waking_the_loop() {
        // The defect, exactly: `RdpSession::pump` read, decoded *and* replied
        // in one future, and that future was a branch of the read loop's
        // `tokio::select!`. A command arriving — or a frame timer expiring —
        // while the reply was suspended inside `write_all` dropped it mid-PDU,
        // leaving a truncated PDU on the TLS stream. From that byte onwards
        // the server is framing garbage, and the user sees "it disconnects at
        // random".
        //
        // The script is one Auto-Detect RTT request, which owes exactly one
        // reply; the transport stalls partway through writing it; and a
        // Disconnect command is already queued, so the select has a ready
        // branch to take the moment the reply suspends.
        let transport = DripTransport::new(vec![rtt_request(7)]);
        let written = transport.written();
        let (session, ctx, commands, _events) = attached(transport);

        commands.send(SessionCommand::Disconnect).await.unwrap();
        let reason = tokio::time::timeout(
            core::time::Duration::from_secs(10),
            run_rdp_session(session, ctx),
        )
        .await
        .expect("the session did not end")
        .unwrap();
        assert_eq!(reason, CloseReason::ClosedByUser);

        // The whole reply, not a prefix of it. `write_all` is the only thing
        // that can put these bytes on the wire, and it is the thing that used
        // to be interruptible.
        let bytes = written.lock().clone();
        let expected = rtt_response(7);
        assert!(
            bytes
                .windows(expected.len())
                .any(|window| window == expected.as_slice()),
            "the reply was truncated: {} bytes reached the wire, the reply is {} long",
            bytes.len(),
            expected.len()
        );
    }

    #[tokio::test]
    async fn the_read_half_can_be_dropped_mid_pdu_without_losing_a_byte() {
        // The other side of the split: what *is* allowed in the select. The
        // frame arrives in two chunks with nothing in between, so the first
        // `read_frame` is dropped while half a PDU is in hand; the next one
        // must resume from the buffered half rather than start over.
        let whole = rtt_request(11);
        let (head, tail) = whole.split_at(whole.len() / 2);
        let transport =
            DripTransport::new(vec![head.to_vec(), tail.to_vec()]).pausing_between_reads();
        let (mut session, _ctx, _commands, _events) = attached(transport);

        // A read that cannot complete, abandoned — exactly what `select!` does
        // to the branch it did not choose.
        let abandoned = tokio::time::timeout(READ_PAUSE / 4, session.read_frame()).await;
        assert!(abandoned.is_err(), "the half PDU should not have decoded");

        let frame: BytesMut =
            tokio::time::timeout(core::time::Duration::from_secs(5), session.read_frame())
                .await
                .expect("the resumed read hung")
                .expect("the resumed read failed");
        assert_eq!(&frame[..], &whole[..]);
    }

    #[test]
    fn the_session_is_a_framebuffer_one_and_says_what_it_cannot_do() {
        let caps = capabilities();
        assert_eq!(caps.kind, SessionKind::Framebuffer);
        assert!(caps.resizable);
        // Text and files both ways over MS-RDPECLIP; files only where the
        // connection turns them on.
        assert_eq!(caps.clipboard, ClipboardSupport::TextAndFiles);
        // Claiming a redirection that is not implemented puts a dead control
        // on the tab, so these stay false until the channel exists.
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
    fn a_desktop_larger_than_this_build_accepts_never_reaches_an_allocation() {
        // The CRITICAL defect as an executable fact. The width and height come
        // out of the server's Demand Active PDU, and `DecodedImage::new` turns
        // them into `vec![0; width * height * 4]` — 17 GiB at `u16::MAX`
        // squared. That allocation *aborts*; it does not unwind, so ADR-0011
        // does not contain it to one tab, and it takes the unlocked vault with
        // it. This is the same bound `remoter-proto-vnc`'s gate applies to
        // `ServerInit`.
        let outcome = attached_at(
            DripTransport::new(Vec::new()),
            DesktopSize {
                width: u16::MAX,
                height: u16::MAX,
            },
            StaticChannelSet::new(),
        );
        let Err(error) = outcome else {
            panic!("a 17 GiB framebuffer was allocated from a number the server chose");
        };
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
        assert!(
            error.to_string().contains("larger than this build"),
            "{error}"
        );
        // A clean per-session failure, not an abort: it has a stage, a card
        // and a remedy like any other.
        assert_eq!(error.stage(), remoter_proto::Stage::Run);
    }

    #[test]
    fn an_empty_desktop_is_refused_too() {
        // Zero is not an allocation problem, it is a framebuffer nothing can
        // be drawn into, and every rectangle against it is out of bounds.
        let outcome = attached_at(
            DripTransport::new(Vec::new()),
            DesktopSize {
                width: 1024,
                height: 0,
            },
            StaticChannelSet::new(),
        );
        assert!(matches!(
            outcome,
            Err(ProtocolError::ProtocolViolation { .. })
        ));
    }

    #[test]
    fn the_bound_admits_every_desktop_this_build_could_have_asked_for() {
        // The bound is not a number picked to make a test pass. It is
        // MS-RDPEDISP §2.2.2.2.1's ceiling on what the *client* may request,
        // which `crate::protocol`'s settings schema also enforces on the width
        // and height a user can type — so a desktop the user configured and
        // the server granted must pass, and an 8K one certainly must.
        for (width, height) in [(1024, 768), (7680, 4320), (8192, 8192)] {
            assert!(
                check_desktop(DesktopSize { width, height }).is_ok(),
                "{width}x{height} is a desktop this build can ask for"
            );
        }
        // And one pixel more is not.
        for (width, height) in [(8192, 8193), (16384, 8192), (u16::MAX, u16::MAX)] {
            assert!(
                check_desktop(DesktopSize { width, height }).is_err(),
                "{width}x{height} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn a_reactivation_to_an_impossible_desktop_is_refused_before_the_framebuffer_is_rebuilt()
    {
        // The second route to the same abort, and the one the verifier's line
        // number does not point at: a session that attached at a sane size can
        // be told to grow at any time (§1.3.1.3), and the rebuild is the same
        // `vec![0; width * height * 4]` in `DecodedImage::new`.
        let mut script = demand_active(u16::MAX, u16::MAX);
        script.extend_from_slice(&finalization());
        let (mut session, _ctx, _commands, _events) = attached(DripTransport::new(vec![script]));

        let error = tokio::time::timeout(
            core::time::Duration::from_secs(10),
            session.process_frame(&deactivate_all()),
        )
        .await
        .expect("the reactivation did not complete")
        .expect_err("a 17 GiB framebuffer was rebuilt from a number the server chose");
        assert!(
            matches!(error, ProtocolError::ProtocolViolation { .. }),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("larger than this build"),
            "{error}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_closing_tab_never_waits_the_connection_timeout_for_a_reactivation() {
        // The defect: `reactivate` built a fresh `ConnectionConfig`, which
        // carries `DEFAULT_TIMEOUT` — thirty seconds, the budget for a TLS
        // handshake and CredSSP over a link that has not proved it works. A
        // reactivation is neither, and it is the one thing the read loop
        // cannot interrupt, so it was also the longest a tab could take to
        // close. Time is paused, so this measures the bound rather than the
        // machine.
        let (session, ctx, _commands, _events) =
            attached(DripTransport::new(vec![deactivate_all()]));
        let started = tokio::time::Instant::now();
        let reason = run_rdp_session(session, ctx).await.unwrap();
        let waited = started.elapsed();

        assert!(matches!(reason, CloseReason::Failed(_)), "{reason:?}");
        assert!(
            waited < crate::connect::DEFAULT_TIMEOUT,
            "a closing tab waited {waited:?}, which is the connection sequence's budget"
        );
        assert!(
            waited <= REACTIVATION_TIMEOUT + core::time::Duration::from_secs(1),
            "the wait was {waited:?}, not the reactivation budget"
        );
    }

    #[tokio::test]
    async fn a_tab_closed_mid_decode_does_not_start_a_reactivation_at_all() {
        // The other half. Once the sequence has begun it must run to
        // completion — abandoning it could leave a truncated Confirm Active on
        // the stream — so the moment to decline it is before the first byte is
        // written, which is exactly here.
        let transport = DripTransport::new(Vec::new());
        let written = transport.written();
        let (mut session, ctx, _commands, _events) = attached(transport);
        session.watch_cancellation(ctx.cancel.clone());
        ctx.cancel.cancel();

        let frame = deactivate_all();
        let outcome = tokio::time::timeout(
            core::time::Duration::from_secs(2),
            session.process_frame(&frame),
        )
        .await
        .expect("the reactivation was started for a tab that had already closed")
        .unwrap();

        assert_eq!(outcome, Some(CloseReason::ClosedByUser));
        assert!(
            written.lock().is_empty(),
            "nothing of the sequence should have reached the wire"
        );
    }

    #[tokio::test]
    async fn a_server_that_cannot_resize_says_so_instead_of_leaving_a_dead_control() {
        // `capabilities()` offers `resizable: true` because the adapter can
        // resize; whether this *server* can depends on a channel it opens
        // itself. A session whose Display Control channel never arrived used
        // to refuse the resize into a debug log, so the tab drew a control
        // that did nothing and said nothing.
        use remoter_proto::Session as _;

        let (mut session, _ctx, _commands, mut events) = attached(DripTransport::new(Vec::new()));

        assert!(
            !session.display_control_open(),
            "no server has joined the channel in this test"
        );
        assert!(
            capabilities().resizable,
            "the adapter still offers what it can do"
        );
        assert!(
            !session.granted_capabilities().resizable,
            "the session must report what the server granted, not what the adapter offers"
        );

        let error = session
            .resize(1920, 1080)
            .await
            .expect_err("no Display Control channel, no resize");
        assert!(matches!(error, ProtocolError::Unsupported { .. }));

        // And the refusal reached the user, not only the log. `announce` was
        // never called here, so the stream carries nothing else.
        let event = tokio::time::timeout(core::time::Duration::from_secs(1), events.recv())
            .await
            .expect("the resize refusal was swallowed")
            .expect("the event stream closed");
        assert!(
            matches!(
                &event,
                SessionEvent::Warning(SessionWarning::Other { detail })
                    if detail == WARNING_RESIZE_UNAVAILABLE
            ),
            "{event:?}"
        );

        // Told once: a tab being dragged asks per frame, and a warning per
        // frame is the noise a user learns to dismiss.
        let _ = session.resize(1600, 900).await;
        let again =
            tokio::time::timeout(core::time::Duration::from_millis(200), events.recv()).await;
        assert!(
            again.is_err(),
            "the warning repeated once per resize request"
        );
    }

    #[test]
    fn nothing_in_this_session_logs_what_the_user_typed() {
        // The same guard the VNC and SSH sessions carry, and it was missing
        // from the adapter with the most input-handling code of the three.
        // CLAUDE.md §0.2, applied to input: a log line naming a key is
        // keystroke material at rest, and there is no exception for one key at
        // a time. RDP's input encoding lives in `crate::input`, but the
        // diagnostics *about* it live here — `input` below logs when an event
        // cannot be encoded, which is exactly the line someone adds the
        // offending scancode to while debugging.
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

    /// One fast-path server update PDU (MS-RDPBCGR §2.2.9.1.2) carrying a
    /// single update structure with the given fragmentation field.
    ///
    /// The payload is never decoded by `ironrdp-session` for `First` and
    /// `Next` — it is accumulated and nothing more — which is exactly the
    /// property that made the reassembly unbounded.
    fn fast_path_update(
        fragmentation: ironrdp::pdu::fast_path::Fragmentation,
        payload: &[u8],
    ) -> Vec<u8> {
        use ironrdp::pdu::fast_path::{
            EncryptionFlags, FastPathHeader, FastPathUpdatePdu, UpdateCode,
        };

        let update = FastPathUpdatePdu {
            fragmentation,
            update_code: UpdateCode::SurfaceCommands,
            compression_flags: None,
            compression_type: None,
            data: payload,
        };
        let body = encode_vec(&update).unwrap();
        let header = FastPathHeader::new(EncryptionFlags::empty(), body.len());
        let mut frame = encode_vec(&header).unwrap();
        frame.extend_from_slice(&body);
        frame
    }

    /// One chunk of a static virtual channel PDU (§3.1.5.2.2) on
    /// [`SVC_CHANNEL`], inside the MCS Send Data Indication it travels in.
    fn channel_chunk(
        declared: u32,
        flags: ironrdp::pdu::rdp::vc::ChannelControlFlags,
        payload: &[u8],
    ) -> Vec<u8> {
        use ironrdp::pdu::rdp::vc::ChannelPduHeader;

        let mut user_data = encode_vec(&ChannelPduHeader {
            length: declared,
            flags,
        })
        .unwrap();
        user_data.extend_from_slice(payload);
        encode_vec(&X224(mcs::SendDataIndication {
            initiator_id: SERVER_INITIATOR,
            channel_id: SVC_CHANNEL,
            user_data: std::borrow::Cow::Owned(user_data),
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn a_fast_path_reassembly_that_never_ends_is_refused_on_the_path_a_server_uses() {
        // The HIGH defect, on the real path. `process_frame` hands every
        // fast-path PDU to `ActiveStage`, and `CompleteData::append_data`
        // extends `fragmented_data` for every `Fragmentation::Next` with no
        // declared total and no ceiling. `framed.rs`'s MAX_PDU_BYTES bounds
        // one PDU; nothing bounded the reassembly of many, so a server that
        // sends First and then Next for ever grows that `Vec` until the
        // allocator gives up — and an allocation failure aborts rather than
        // unwinding, so ADR-0011 does not contain it to one tab.
        //
        // Without the ceiling every call below returns `Ok` and the loop runs
        // out rather than the session ending; what a real server does instead
        // of stopping at 32 MiB is keep going.
        use ironrdp::pdu::fast_path::Fragmentation;

        let (mut session, _ctx, _commands, _events) = attached(DripTransport::new(Vec::new()));
        let payload = vec![0xa5_u8; 16 * 1024];

        session
            .process_frame(&fast_path_update(Fragmentation::First, &payload))
            .await
            .unwrap();

        let mut refused = None;
        for _ in 0..2048 {
            if let Err(error) = session
                .process_frame(&fast_path_update(Fragmentation::Next, &payload))
                .await
            {
                refused = Some(error);
                break;
            }
        }
        let Some(error) = refused else {
            panic!("the server grew the reassembly buffer past 32 MiB unopposed");
        };
        assert!(
            matches!(error, ProtocolError::ProtocolViolation { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains("reassembly buffer"), "{error}");
        // A clean per-session failure with a stage and a card, not an abort.
        assert_eq!(error.stage(), remoter_proto::Stage::Run);
    }

    #[tokio::test]
    async fn an_ordinary_run_of_fast_path_updates_is_not_refused_for_its_length() {
        // The other half of the bound, and the one a careless guard breaks: a
        // session carries far more than eight megabytes of graphics over its
        // life. Only what is *reassembled* counts, and an unfragmented update
        // reassembles nothing.
        use ironrdp::pdu::fast_path::Fragmentation;

        let (mut session, _ctx, _commands, _events) = attached(DripTransport::new(Vec::new()));
        let payload = vec![0u8; 16 * 1024];
        for _ in 0..1024 {
            session
                .process_frame(&fast_path_update(Fragmentation::Single, &payload))
                .await
                .expect("16 MiB of ordinary updates is a few seconds of a busy desktop");
        }
    }

    #[tokio::test]
    async fn a_virtual_channel_pdu_that_never_ends_is_refused_on_the_path_a_server_uses() {
        // The same shape one layer over: `ironrdp-svc`'s
        // `ChunkProcessor::dechunkify` extends `chunked_pdu` for every chunk
        // lacking CHANNEL_FLAG_LAST and never reads the declared total at all.
        // `drdynvc` is registered on every session, so the path is open on
        // every session.
        use ironrdp::pdu::rdp::vc::ChannelControlFlags;

        let (mut session, _ctx, _commands, _events) =
            attached_on_channel(DripTransport::new(Vec::new()));
        let payload = vec![0u8; 16_000];
        let declared = u32::try_from(payload.len()).unwrap();

        let mut refused = None;
        for _ in 0..512 {
            let frame = channel_chunk(declared, ChannelControlFlags::empty(), &payload);
            if let Err(error) = session.process_frame(&frame).await {
                refused = Some(error);
                break;
            }
        }
        let Some(error) = refused else {
            panic!("the server grew the chunk buffer past eight megabytes unopposed");
        };
        assert!(
            matches!(error, ProtocolError::ProtocolViolation { .. }),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("more virtual channel chunks"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_virtual_channel_pdu_declaring_an_absurd_total_is_refused_at_once() {
        // The declared total is the thing `dechunkify` ignores; refusing it on
        // the first chunk is the difference between a four-gigabyte
        // accumulation and an immediate diagnostic.
        use ironrdp::pdu::rdp::vc::ChannelControlFlags;

        let (mut session, _ctx, _commands, _events) =
            attached_on_channel(DripTransport::new(Vec::new()));
        let frame = channel_chunk(u32::MAX, ChannelControlFlags::FLAG_FIRST, &[0u8; 16]);
        let error = session
            .process_frame(&frame)
            .await
            .expect_err("a four-gigabyte virtual channel PDU was accepted");
        assert!(
            matches!(error, ProtocolError::ProtocolViolation { .. }),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("larger than this build"),
            "{error}"
        );
    }

    /// The id the server gives `cliprdr` in these tests.
    const CLIPBOARD_CHANNEL: u16 = 1007;

    /// A session whose server joined both channels, clipboard included.
    fn attached_with_clipboard(
        transport: DripTransport,
    ) -> (
        RdpSession,
        SessionContext,
        tokio::sync::mpsc::Sender<SessionCommand>,
        tokio::sync::mpsc::Receiver<SessionEvent>,
    ) {
        attached_with_clipboard_policy(transport, remoter_proto::ClipboardPolicy::default())
    }

    /// The same, for a connection that lets files cross as well.
    fn attached_with_files(
        transport: DripTransport,
    ) -> (
        RdpSession,
        SessionContext,
        tokio::sync::mpsc::Sender<SessionCommand>,
        tokio::sync::mpsc::Receiver<SessionEvent>,
    ) {
        attached_with_clipboard_policy(
            transport,
            remoter_proto::ClipboardPolicy {
                files: true,
                ..remoter_proto::ClipboardPolicy::default()
            },
        )
    }

    fn attached_with_clipboard_policy(
        transport: DripTransport,
        policy: remoter_proto::ClipboardPolicy,
    ) -> (
        RdpSession,
        SessionContext,
        tokio::sync::mpsc::Sender<SessionCommand>,
        tokio::sync::mpsc::Receiver<SessionEvent>,
    ) {
        use core::any::TypeId;

        let mut channels = crate::connect::static_channels(policy);
        channels.attach_channel_id(TypeId::of::<ironrdp::dvc::DrdynvcClient>(), SVC_CHANNEL);
        channels.attach_channel_id(TypeId::of::<CliprdrClient>(), CLIPBOARD_CHANNEL);
        attached_with_policy(
            transport,
            DesktopSize {
                width: 64,
                height: 64,
            },
            channels,
            policy,
        )
        .expect("64x64 is inside every bound this module has")
    }

    /// One whole clipboard PDU from the server, as a single chunk.
    fn from_server(pdu: &ironrdp::cliprdr::pdu::ClipboardPdu<'_>) -> Vec<u8> {
        use ironrdp::pdu::rdp::vc::{ChannelControlFlags, ChannelPduHeader};

        let body = encode_vec(pdu).unwrap();
        let mut user_data = encode_vec(&ChannelPduHeader {
            length: u32::try_from(body.len()).unwrap(),
            flags: ChannelControlFlags::FLAG_FIRST | ChannelControlFlags::FLAG_LAST,
        })
        .unwrap();
        user_data.extend_from_slice(&body);
        encode_vec(&X224(mcs::SendDataIndication {
            initiator_id: SERVER_INITIATOR,
            channel_id: CLIPBOARD_CHANNEL,
            user_data: std::borrow::Cow::Owned(user_data),
        }))
        .unwrap()
    }

    /// Every clipboard PDU the client wrote, as `(name, decoded text)` —
    /// the text only for a Format Data Response, which is where it travels.
    fn clipboard_pdus_written(written: &Mutex<Vec<u8>>) -> Vec<(&'static str, Option<String>)> {
        use ironrdp::cliprdr::pdu::ClipboardPdu;
        use ironrdp::pdu::rdp::vc::ChannelPduHeader;

        let bytes = core::mem::take(&mut *written.lock());
        let mut rest = &bytes[..];
        let mut pdus = Vec::new();
        while rest.len() >= 4 {
            let length = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
            let (frame, tail) = rest.split_at(length);
            rest = tail;
            let request = ironrdp::core::decode::<X224<mcs::SendDataRequest<'_>>>(frame).unwrap();
            if request.0.channel_id != CLIPBOARD_CHANNEL {
                continue;
            }
            let mut cursor = ironrdp::core::ReadCursor::new(&request.0.user_data);
            let _header: ChannelPduHeader = ironrdp::core::decode_cursor(&mut cursor).unwrap();
            let pdu: ClipboardPdu<'_> = ironrdp::core::decode(cursor.remaining()).unwrap();
            let text = match &pdu {
                ClipboardPdu::FormatDataResponse(response) if !response.is_error() => {
                    response.to_unicode_string().ok()
                }
                ClipboardPdu::FileContentsResponse(response) if !response.is_error() => {
                    Some(String::from_utf8_lossy(response.data()).into_owned())
                }
                ClipboardPdu::FileContentsRequest(request) => Some(format!(
                    "stream={} index={} position={} size={}",
                    request.stream_id, request.index, request.position, request.requested_size
                )),
                _ => None,
            };
            pdus.push((pdu.message_name(), text));
        }
        pdus
    }

    /// Runs the channel's initialisation (MS-RDPECLIP §1.3.2.1) against a
    /// session, and returns what the client wrote during it.
    async fn initialise_clipboard(
        session: &mut RdpSession,
        written: &Mutex<Vec<u8>>,
    ) -> Vec<(&'static str, Option<String>)> {
        initialise_clipboard_with(
            session,
            written,
            ironrdp::cliprdr::pdu::ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES,
        )
        .await
    }

    /// The same, with the server offering the capabilities given.
    async fn initialise_clipboard_with(
        session: &mut RdpSession,
        written: &Mutex<Vec<u8>>,
        server: ironrdp::cliprdr::pdu::ClipboardGeneralCapabilityFlags,
    ) -> Vec<(&'static str, Option<String>)> {
        use ironrdp::cliprdr::pdu::{
            Capabilities, ClipboardPdu, ClipboardProtocolVersion, FormatListResponse,
        };

        let capabilities =
            ClipboardPdu::Capabilities(Capabilities::new(ClipboardProtocolVersion::V2, server));
        session
            .process_frame(&from_server(&capabilities))
            .await
            .unwrap();
        session
            .process_frame(&from_server(&ClipboardPdu::MonitorReady))
            .await
            .unwrap();
        let sent = clipboard_pdus_written(written);
        session
            .process_frame(&from_server(&ClipboardPdu::FormatListResponse(
                FormatListResponse::Ok,
            )))
            .await
            .unwrap();
        sent
    }

    #[tokio::test]
    async fn text_copied_on_the_server_reaches_the_event_stream_with_lf_endings() {
        use ironrdp::cliprdr::pdu::{ClipboardFormat, ClipboardFormatId, ClipboardPdu, FormatList};

        let transport = DripTransport::new(Vec::new());
        let written = transport.written();
        let (mut session, _ctx, _commands, mut events) = attached_with_clipboard(transport);

        let sent = initialise_clipboard(&mut session, &written).await;
        let names: Vec<&str> = sent.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "CLIPRDR_CAPABILITIES",
                "CLIPRDR_TEMP_DIRECTORY",
                "CLIPRDR_FORMAT_LIST"
            ],
            "§1.3.2.1's order"
        );

        let copied = ClipboardPdu::FormatList(
            FormatList::new_unicode(
                &[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)],
                true,
            )
            .unwrap(),
        );
        session.process_frame(&from_server(&copied)).await.unwrap();
        let names: Vec<&str> = clipboard_pdus_written(&written)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            names,
            [
                "CLIPRDR_FORMAT_LIST_RESPONSE",
                "CLIPRDR_FORMAT_DATA_REQUEST"
            ],
            "the copy is acknowledged before it is asked for"
        );

        let data = ClipboardPdu::FormatDataResponse(
            ironrdp::cliprdr::pdu::OwnedFormatDataResponse::new_unicode_string("dir\r\nls"),
        );
        session.process_frame(&from_server(&data)).await.unwrap();
        let delivered = loop {
            match events.try_recv() {
                Ok(SessionEvent::ClipboardContent(ClipboardData::Text(text))) => break text,
                Ok(_) => {}
                Err(error) => panic!("no clipboard content was delivered: {error:?}"),
            }
        };
        assert_eq!(delivered, "dir\nls");
    }

    #[tokio::test]
    async fn local_text_is_announced_and_sent_when_the_server_pastes_it() {
        use ironrdp::cliprdr::pdu::{ClipboardFormatId, ClipboardPdu, FormatDataRequest};
        use remoter_proto::Session as _;

        let transport = DripTransport::new(Vec::new());
        let written = transport.written();
        let (mut session, _ctx, _commands, _events) = attached_with_clipboard(transport);
        let _ = initialise_clipboard(&mut session, &written).await;

        session
            .clipboard(ClipboardOp::Offer(ClipboardData::Text(
                "Get-Service\n".to_owned(),
            )))
            .await
            .unwrap();
        let names: Vec<&str> = clipboard_pdus_written(&written)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, ["CLIPRDR_FORMAT_LIST"]);

        // The same text again, as the interface offers it on every focus.
        session
            .clipboard(ClipboardOp::Offer(ClipboardData::Text(
                "Get-Service\r\n".to_owned(),
            )))
            .await
            .unwrap();
        assert!(clipboard_pdus_written(&written).is_empty());

        let paste = ClipboardPdu::FormatDataRequest(FormatDataRequest {
            format: ClipboardFormatId::CF_UNICODETEXT,
        });
        session.process_frame(&from_server(&paste)).await.unwrap();
        let sent = clipboard_pdus_written(&written);
        assert_eq!(
            sent,
            [(
                "CLIPRDR_FORMAT_DATA_RESPONSE",
                Some("Get-Service\r\n".to_owned())
            )]
        );
    }

    #[tokio::test]
    async fn a_clipboard_too_large_to_carry_is_dropped_and_said_and_the_session_lives() {
        use ironrdp::cliprdr::pdu::{ClipboardFormat, ClipboardFormatId, ClipboardPdu, FormatList};
        use ironrdp::pdu::rdp::vc::{ChannelControlFlags, ChannelPduHeader};

        let transport = DripTransport::new(Vec::new());
        let written = transport.written();
        let (mut session, _ctx, _commands, mut events) = attached_with_clipboard(transport);
        let _ = initialise_clipboard(&mut session, &written).await;
        let copied = ClipboardPdu::FormatList(
            FormatList::new_unicode(
                &[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)],
                true,
            )
            .unwrap(),
        );
        session.process_frame(&from_server(&copied)).await.unwrap();
        let _ = clipboard_pdus_written(&written);

        // The first chunk of a response declaring more than the ceiling.
        let chunk = |flags: ChannelControlFlags| {
            let mut user_data = encode_vec(&ChannelPduHeader {
                length: MAX_CLIPBOARD_PDU_BYTES + 1,
                flags,
            })
            .unwrap();
            user_data.extend_from_slice(&[0u8; 1024]);
            encode_vec(&X224(mcs::SendDataIndication {
                initiator_id: SERVER_INITIATOR,
                channel_id: CLIPBOARD_CHANNEL,
                user_data: std::borrow::Cow::Owned(user_data),
            }))
            .unwrap()
        };
        session
            .process_frame(&chunk(ChannelControlFlags::FLAG_FIRST))
            .await
            .unwrap();
        session
            .process_frame(&chunk(ChannelControlFlags::empty()))
            .await
            .unwrap();
        session
            .process_frame(&chunk(ChannelControlFlags::FLAG_LAST))
            .await
            .unwrap();

        let mut warned = 0;
        while let Ok(event) = events.try_recv() {
            if let SessionEvent::Warning(SessionWarning::Other { detail }) = event {
                assert_eq!(detail, crate::clipboard::WARNING_CLIPBOARD_TOO_LARGE);
                warned += 1;
            }
        }
        assert_eq!(warned, 1, "said once, not once per chunk");

        // And the channel still works: the next copy is acknowledged.
        session.process_frame(&from_server(&copied)).await.unwrap();
        let names: Vec<&str> = clipboard_pdus_written(&written)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            names,
            [
                "CLIPRDR_FORMAT_LIST_RESPONSE",
                "CLIPRDR_FORMAT_DATA_REQUEST"
            ]
        );
    }

    /// Everything a file-capable server offers (MS-RDPECLIP §2.2.2.1.1.1).
    fn file_capable() -> ironrdp::cliprdr::pdu::ClipboardGeneralCapabilityFlags {
        use ironrdp::cliprdr::pdu::ClipboardGeneralCapabilityFlags as Flags;
        Flags::USE_LONG_FORMAT_NAMES
            | Flags::STREAM_FILECLIP_ENABLED
            | Flags::FILECLIP_NO_FILE_PATHS
            | Flags::CAN_LOCK_CLIPDATA
            | Flags::HUGE_FILE_SUPPORT_ENABLED
    }

    fn names(pdus: &[(&'static str, Option<String>)]) -> Vec<&'static str> {
        pdus.iter().map(|(name, _)| *name).collect()
    }

    #[tokio::test]
    async fn a_local_file_is_offered_and_read_by_the_server_piece_by_piece() {
        use ironrdp::cliprdr::pdu::{
            ClipboardFormatId, ClipboardPdu, FileContentsFlags, FileContentsRequest,
            FormatDataRequest,
        };
        use remoter_proto::Session as _;

        let scratch = tempfile::tempdir().unwrap();
        let file = scratch.path().join("deploy.ps1");
        std::fs::write(&file, b"Write-Host 'hello from the laptop'").unwrap();

        let transport = DripTransport::new(Vec::new());
        let written = transport.written();
        let (mut session, _ctx, _commands, mut events) = attached_with_files(transport);
        let _ = initialise_clipboard_with(&mut session, &written, file_capable()).await;

        session
            .clipboard(ClipboardOp::Offer(ClipboardData::Files(vec![
                file.display().to_string(),
            ])))
            .await
            .unwrap();
        assert_eq!(
            names(&clipboard_pdus_written(&written)),
            ["CLIPRDR_FORMAT_LIST"]
        );

        // Explorer pastes: first the list, which `ironrdp-cliprdr` answers
        // from what it was given, then the bytes.
        let list = ClipboardPdu::FormatDataRequest(FormatDataRequest {
            format: ClipboardFormatId::new(0xC0FE),
        });
        session.process_frame(&from_server(&list)).await.unwrap();
        assert_eq!(
            names(&clipboard_pdus_written(&written)),
            ["CLIPRDR_FORMAT_DATA_RESPONSE"]
        );

        let read = |stream_id, position, requested_size| {
            ClipboardPdu::FileContentsRequest(FileContentsRequest {
                stream_id,
                index: 0,
                flags: FileContentsFlags::RANGE,
                position,
                requested_size,
                data_id: None,
            })
        };
        session
            .process_frame(&from_server(&read(1, 0, 10)))
            .await
            .unwrap();
        session
            .process_frame(&from_server(&read(2, 10, 4096)))
            .await
            .unwrap();
        let answers = clipboard_pdus_written(&written);
        assert_eq!(
            answers,
            [
                (
                    "CLIPRDR_FILECONTENTS_RESPONSE",
                    Some("Write-Host".to_owned())
                ),
                (
                    "CLIPRDR_FILECONTENTS_RESPONSE",
                    Some(" 'hello from the laptop'".to_owned())
                ),
            ]
        );

        let mut sent = None;
        while let Ok(event) = events.try_recv() {
            if let SessionEvent::ClipboardFiles(ClipboardFiles::Sent { local, bytes }) = event {
                sent = Some((local, bytes));
            }
        }
        assert_eq!(sent, Some((file.display().to_string(), 34)));
    }

    #[tokio::test]
    async fn files_copied_on_the_server_are_offered_then_saved_into_the_chosen_folder() {
        use ironrdp::cliprdr::pdu::{
            ClipboardFileAttributes, ClipboardFormat, ClipboardFormatId, ClipboardFormatName,
            ClipboardPdu, FileContentsResponse, FileDescriptor, FormatList,
            OwnedFormatDataResponse, PackedFileList,
        };
        use remoter_proto::Session as _;

        let transport = DripTransport::new(Vec::new());
        let written = transport.written();
        let (mut session, _ctx, _commands, mut events) = attached_with_files(transport);
        let _ = initialise_clipboard_with(&mut session, &written, file_capable()).await;

        let file_list = ClipboardFormatId::new(0xC0DE);
        let copied = ClipboardPdu::FormatList(
            FormatList::new_unicode(
                &[ClipboardFormat::new(file_list).with_name(ClipboardFormatName::FILE_LIST)],
                true,
            )
            .unwrap(),
        );
        session.process_frame(&from_server(&copied)).await.unwrap();
        assert_eq!(
            names(&clipboard_pdus_written(&written)),
            [
                "CLIPRDR_FORMAT_LIST_RESPONSE",
                "CLIPRDR_LOCK_CLIPDATA",
                "CLIPRDR_FORMAT_DATA_REQUEST"
            ],
            "acknowledged, locked, and the list asked for; no bytes yet"
        );

        let body = b"quarterly numbers";
        let list = PackedFileList {
            files: vec![
                FileDescriptor::new("report.txt")
                    .with_attributes(ClipboardFileAttributes::ARCHIVE)
                    .with_file_size(body.len() as u64),
            ],
        };
        let response = ClipboardPdu::FormatDataResponse(
            OwnedFormatDataResponse::new_file_list(&list).unwrap(),
        );
        session
            .process_frame(&from_server(&response))
            .await
            .unwrap();
        let mut offered = false;
        while let Ok(event) = events.try_recv() {
            if let SessionEvent::ClipboardFiles(ClipboardFiles::Offered { total_entries, .. }) =
                event
            {
                offered = total_entries == 1;
            }
        }
        assert!(offered, "the file list was not offered to the interface");
        assert!(clipboard_pdus_written(&written).is_empty());

        let scratch = tempfile::tempdir().unwrap();
        session
            .clipboard(ClipboardOp::SaveFiles {
                directory: scratch.path().display().to_string(),
            })
            .await
            .unwrap();
        let requests = clipboard_pdus_written(&written);
        let [("CLIPRDR_FILECONTENTS_REQUEST", Some(detail))] = &requests[..] else {
            panic!("{requests:?}");
        };
        assert_eq!(
            detail,
            &format!("stream=1 index=0 position=0 size={}", body.len())
        );

        let bytes = ClipboardPdu::FileContentsResponse(FileContentsResponse::new_data_response(
            1,
            body.to_vec(),
        ));
        session.process_frame(&from_server(&bytes)).await.unwrap();
        assert_eq!(
            std::fs::read(scratch.path().join("report.txt")).unwrap(),
            body
        );
        let mut finished = false;
        while let Ok(event) = events.try_recv() {
            if let SessionEvent::ClipboardFiles(ClipboardFiles::Finished { files, .. }) = event {
                finished = files == 1;
            }
        }
        assert!(finished);
    }

    #[tokio::test]
    async fn a_save_the_user_stops_removes_what_was_half_written() {
        use ironrdp::cliprdr::pdu::{
            ClipboardFileAttributes, ClipboardFormat, ClipboardFormatId, ClipboardFormatName,
            ClipboardPdu, FileContentsResponse, FileDescriptor, FormatList,
            OwnedFormatDataResponse, PackedFileList,
        };
        use remoter_proto::Session as _;

        let transport = DripTransport::new(Vec::new());
        let written = transport.written();
        let (mut session, _ctx, _commands, mut events) = attached_with_files(transport);
        let _ = initialise_clipboard_with(&mut session, &written, file_capable()).await;
        let file_list = ClipboardFormatId::new(0xC0DE);
        let copied = ClipboardPdu::FormatList(
            FormatList::new_unicode(
                &[ClipboardFormat::new(file_list).with_name(ClipboardFormatName::FILE_LIST)],
                true,
            )
            .unwrap(),
        );
        session.process_frame(&from_server(&copied)).await.unwrap();
        let list = PackedFileList {
            files: vec![
                FileDescriptor::new("image.iso")
                    .with_attributes(ClipboardFileAttributes::ARCHIVE)
                    .with_file_size(8 * 1024 * 1024),
            ],
        };
        session
            .process_frame(&from_server(&ClipboardPdu::FormatDataResponse(
                OwnedFormatDataResponse::new_file_list(&list).unwrap(),
            )))
            .await
            .unwrap();

        let scratch = tempfile::tempdir().unwrap();
        session
            .clipboard(ClipboardOp::SaveFiles {
                directory: scratch.path().display().to_string(),
            })
            .await
            .unwrap();
        session
            .process_frame(&from_server(&ClipboardPdu::FileContentsResponse(
                // Less than was asked for — a server may answer short — and
                // small enough to travel as one channel chunk here.
                FileContentsResponse::new_data_response(1, vec![0u8; 16_000]),
            )))
            .await
            .unwrap();
        assert!(
            scratch
                .path()
                .join(format!("image.iso{}", crate::clipboard_files::PART_SUFFIX))
                .exists()
        );

        session.clipboard(ClipboardOp::CancelSave).await.unwrap();
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
        let mut cancelled = false;
        while let Ok(event) = events.try_recv() {
            cancelled |= matches!(
                event,
                SessionEvent::ClipboardFiles(ClipboardFiles::Cancelled)
            );
        }
        assert!(cancelled);

        // A late answer to the stopped save's request writes nothing.
        let _ = clipboard_pdus_written(&written);
        session
            .process_frame(&from_server(&ClipboardPdu::FileContentsResponse(
                FileContentsResponse::new_data_response(2, vec![1u8; 16]),
            )))
            .await
            .unwrap();
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn a_connection_that_allows_no_clipboard_asks_for_no_channel_and_refuses_offers() {
        use remoter_proto::Session as _;

        let (mut session, _ctx, _commands, _events) =
            attached_on_channel(DripTransport::new(Vec::new()));
        let error = session
            .clipboard(ClipboardOp::Offer(ClipboardData::Text("x".to_owned())))
            .await
            .unwrap_err();
        assert!(
            matches!(error, ProtocolError::Unsupported { .. }),
            "{error:?}"
        );
        assert_eq!(
            session.granted_capabilities().clipboard,
            ClipboardSupport::None
        );
    }

    #[test]
    fn the_session_never_debug_prints_its_framebuffer() {
        // A framebuffer is a picture of someone's screen.
        let rendered = format!("{:?}", DesktopSize::default());
        assert!(rendered.contains("1024"));
    }
}
