//! The gate: a [`Transport`] that stands between the socket and `vnc-rs`.
//!
//! ADR-0013. Two jobs, both of which exist because the far end is assumed
//! hostile (`docs/security/threat-model.md`) and the library is not written for
//! that assumption.
//!
//! # 1 · It replays a trusted handshake
//!
//! [`crate::negotiate`] has already performed RFC 6143 §7.1.1 and §7.1.2 on the
//! real wire, with a version floor and a security-type policy the server cannot
//! influence. `vnc-rs` cannot be handed a stream with those bytes already
//! consumed — it starts at the version string — so the gate *synthesises* the
//! handshake the library expects to see:
//!
//! - it serves `RFB 003.008\n` and a one-entry security list holding exactly
//!   the type that was really selected, so the library has no choice left to
//!   make and its own floorless `min` has nowhere to go;
//! - it swallows the thirteen bytes the library writes in reply — the version
//!   and the selection — because both have already been sent for real;
//! - it passes the sixteen-byte DES challenge and the sixteen-byte response
//!   straight through, which is the one part of the handshake the library must
//!   really do, because its DES implementation is not public;
//! - it reads the real `SecurityResult` word itself, checks it against the two
//!   values RFC 6143 §7.2.2 defines, and serves the library a synthetic zero.
//!
//! That last step is the whole of the second HIGH defect. `vnc-rs`'s
//! `AuthResult::from(u32)` is `std::mem::transmute` into a two-variant
//! `#[repr(u32)]` enum, and the branch it produces is the one that decides
//! whether authentication *failed*. A server sending `2` was undefined
//! behaviour in a decision that gates access. After this module the library
//! only ever sees `0`; every other value is refused here, with a `match`, on a
//! plain `u32`.
//!
//! # 2 · It bounds every length the library will act on
//!
//! `vnc-rs` sizes allocations directly from wire fields: `ServerInit`'s
//! name-length, `ServerCutText`'s length, and each rectangle's `width * height *
//! bytes-per-pixel`. Those are `Vec::with_capacity` and `vec![0; n]` calls made
//! *before* the bytes are read, so a one-line message can ask for gigabytes, and
//! an allocation failure **aborts** — it does not unwind, so it is not
//! containable to one tab the way ADR-0011 contains a panic. It takes every
//! other session and the unlocked vault with it.
//!
//! So the gate parses the server message stream (RFC 6143 §7.6) itself and
//! withholds every byte until the length that governs it has been checked. It
//! does not decode anything: a rectangle's pixels pass through untouched and,
//! in the common case, without a copy. What it does is refuse to hand the
//! library a header it would turn into an allocation nobody asked for.
//!
//! **This only works because every encoding this build negotiates is
//! self-delimiting to a parser that knows the rectangle's size.** See
//! [`crate::encoding`] for the encodings that were withdrawn to keep it true.
//!
//! # What it deliberately does not do
//!
//! It does not look inside a compressed stream, and it therefore cannot bound a
//! length that is written there. That is why Tight, ZRLE and TRLE are not
//! negotiated by this build; the reasoning is in ADR-0013 and the consequences
//! are in [`crate::encoding`].

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use parking_lot::Mutex;
use remoter_proto::{CredentialKind, ProtocolError, Transport, TransportPeer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::encoding::RfbEncoding;
use crate::error::violation;
use crate::handshake::VERSION_BYTES;
use crate::negotiate::Negotiated;
use crate::security::SecurityType;

/// Bytes per pixel on the wire.
///
/// Not read from `ServerInit`: [`crate::protocol`] always sends `SetPixelFormat`
/// (RFC 6143 §7.5.1) asking for 32-bit true colour, and `vnc-rs` decodes with
/// the format it was given rather than the one the server announced. The two
/// must agree or every rectangle length below is wrong, which is why this is a
/// constant with the reason attached rather than a field.
pub const BYTES_PER_PIXEL: u64 = 4;

/// The largest framebuffer this build will accept from a server.
///
/// 7680x4320 is an 8K desktop, and the number that matters is what a single
/// raw rectangle covering it costs: 132 MiB. That is a large allocation and a
/// legitimate one; `u16::MAX` squared is 17 GiB and is neither.
pub const MAX_FRAMEBUFFER_PIXELS: u64 = 7680 * 4320;

/// The largest cursor (RFC 6143 §7.8.1) this build will accept.
///
/// X11 cursors are at most 256x256 and are normally 32x32. A cursor rectangle
/// is not bounded by the framebuffer — its `x` and `y` are the hot spot, not a
/// position — so without a limit of its own it is a second route to the same
/// allocation.
pub const MAX_CURSOR_DIMENSION: u16 = 256;

/// The longest desktop name (RFC 6143 §7.3.2) this build will read.
///
/// `vnc-rs` does `vec![0; name_len as usize]` on a `U32` straight off the wire,
/// so `0xffff_ffff` is a 4 GiB allocation before a single byte of the name has
/// arrived. This vector is **not** in the defect list `lib.rs` used to carry.
pub const MAX_DESKTOP_NAME_BYTES: u32 = 1024;

/// The most `ServerCutText` (RFC 6143 §7.6.4) text this build will read.
///
/// Same shape as the desktop name, same `U32`, same missing bound, and also not
/// in the list `lib.rs` used to carry. A megabyte is far more clipboard than
/// any session needs and far less than a server can ask for.
pub const MAX_CLIPBOARD_BYTES: u32 = 1024 * 1024;

/// Why the gate stopped the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateFault {
    /// RFC 6143 §7.2.2's `SecurityResult` was 1: the server said no.
    AuthRejected(CredentialKind),
    /// The peer broke a rule. A literal, never peer-authored text.
    Violation(&'static str),
}

impl GateFault {
    /// The taxonomy entry this fault maps to.
    #[must_use]
    pub fn into_error(self) -> ProtocolError {
        match self {
            Self::AuthRejected(attempted) => ProtocolError::AuthRejected { attempted },
            Self::Violation(detail) => violation(detail),
        }
    }

    /// The message an `io::Error` crossing into `vnc-rs` carries.
    const fn detail(self) -> &'static str {
        match self {
            Self::AuthRejected(_) => "vnc.security_result.rejected",
            Self::Violation(detail) => detail,
        }
    }
}

/// State the gate shares with the session that owns it.
///
/// Two facts travel this way because neither can travel through `vnc-rs`: the
/// library turns every failure into one opaque `VncError`, and it has no event
/// for the end of a framebuffer update.
#[derive(Debug, Default)]
pub struct GateShared {
    /// Completed `FramebufferUpdate` messages (RFC 6143 §7.6.1).
    updates: AtomicU64,
    fault: Mutex<Option<GateFault>>,
}

impl GateShared {
    /// How many framebuffer updates have been delivered in full.
    ///
    /// The counter the session's "one outstanding request" rule needs. RFB is
    /// pull-based (RFC 6143 §7.5.3) and an update may carry many rectangles;
    /// counting *rectangles* and calling the first one an answer un-arms the
    /// rule while the server is still writing, and the next tick then sends a
    /// second request. Counting the message boundary is the fix, and the gate
    /// is the only place in this crate that can see one.
    ///
    /// The boundary is the last rectangle's last *byte*, not its header: a
    /// header still has a payload behind it, and a count taken there runs one
    /// payload ahead of the wire, which is what `opaque_run_finished` below
    /// exists to prevent.
    #[must_use]
    pub fn updates_completed(&self) -> u64 {
        self.updates.load(Ordering::Relaxed)
    }

    /// The first rule the peer broke, if it broke one.
    #[must_use]
    pub fn fault(&self) -> Option<GateFault> {
        *self.fault.lock()
    }

    /// Records a fault, keeping the first one: later failures are consequences.
    fn record(&self, fault: GateFault) -> GateFault {
        let mut slot = self.fault.lock();
        *slot.get_or_insert(fault)
    }
}

/// Which encodings the client promised in `SetEncodings` (RFC 6143 §7.5.2).
///
/// A rectangle in anything else is refused. That is not pedantry: `vnc-rs`
/// folds every encoding number it does not recognise onto `Raw` and then reads
/// `width * height * 4` bytes of a much shorter rectangle, taking the rest of
/// the stream with it — so an encoding that was never promised is both a
/// protocol violation and an allocation.
#[derive(Debug, Clone)]
pub struct NegotiatedEncodings(Vec<RfbEncoding>);

impl NegotiatedEncodings {
    /// The set actually sent to the server.
    #[must_use]
    pub fn new(list: &[RfbEncoding]) -> Self {
        Self(list.to_vec())
    }

    fn permits(&self, encoding: RfbEncoding) -> bool {
        self.0.contains(&encoding)
    }
}

/// What the gate is waiting to read from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// RFC 6143 §7.2.2's `SecurityResult`: a `U32`, 0 or 1 and nothing else.
    SecurityResult,
    /// RFC 6143 §7.3.2 `ServerInit` up to the name: two `U16` and a
    /// `PIXEL_FORMAT`.
    ServerInitFixed,
    /// `ServerInit`'s `U32` name-length.
    ServerInitName,
    /// A server message type byte (RFC 6143 §7.6).
    MessageType,
    /// `FramebufferUpdate`'s padding byte and rectangle count (§7.6.1).
    UpdateHeader,
    /// One rectangle header: four `U16` and an `S32` encoding number (§7.6.1).
    RectHeader,
    /// `ServerCutText`'s padding and `U32` length (§7.6.4).
    CutTextHeader,
}

impl Step {
    const fn needs(self) -> usize {
        match self {
            Self::SecurityResult | Self::ServerInitName => 4,
            Self::ServerInitFixed => 20,
            Self::MessageType => 1,
            Self::UpdateHeader => 3,
            Self::RectHeader => 12,
            Self::CutTextHeader => 7,
        }
    }
}

/// The read side: a stream parser that hands on only what it has checked.
#[derive(Debug)]
struct ReadGate {
    /// Bytes checked and waiting to go to the library.
    out: Vec<u8>,
    out_at: usize,
    /// The header being collected, at most [`Step::needs`] bytes.
    scratch: Vec<u8>,
    /// A landing place for the tail of an opaque run, when it ends inside the
    /// caller's buffer. Reused, and never larger than one caller's buffer.
    tail: Vec<u8>,
    /// How many opaque bytes still pass straight through before `step` applies.
    opaque: u64,
    step: Step,
    encodings: NegotiatedEncodings,
    attempted: CredentialKind,
    /// The framebuffer every rectangle is checked against. Set from
    /// `ServerInit`, revised by the DesktopSize pseudo-encoding (§7.8.2).
    surface: (u16, u16),
    rects_remaining: u16,
    /// Whether the opaque run now in flight is the last rectangle's payload, so
    /// that the `FramebufferUpdate` ends when the run does. See
    /// [`ReadGate::opaque_run_finished`].
    ends_update: bool,
    faulted: Option<GateFault>,
}

/// A [`Transport`] that gives `vnc-rs` a handshake it cannot be talked out of
/// and a message stream whose every length has been checked.
pub struct GatedTransport {
    inner: Box<dyn Transport>,
    peer: TransportPeer,
    shared: Arc<GateShared>,
    /// Bytes of the library's handshake reply still to be discarded: twelve for
    /// the version, one for the security-type selection. Both were already sent
    /// for real by [`crate::negotiate::negotiate`]; forwarding the library's
    /// copies would put thirteen stray bytes in front of the challenge.
    swallow: usize,
    read: ReadGate,
}

impl GatedTransport {
    /// Wraps `inner` for a connection that has already negotiated.
    ///
    /// The returned [`GateShared`] is the session's half: it carries the update
    /// counter and whatever rule the peer breaks later.
    #[must_use]
    pub fn new(
        inner: Box<dyn Transport>,
        negotiated: &Negotiated,
        encodings: &[RfbEncoding],
    ) -> (Self, Arc<GateShared>) {
        let peer = inner.peer().clone();
        let shared = Arc::new(GateShared::default());

        // The synthetic handshake. Always 3.8, because that is the one version
        // in which the library's own path is fully determined: it writes a
        // selection and then reads a `SecurityResult`, both of which this gate
        // answers. A synthetic 3.3 or 3.7 would leave the library taking a
        // different branch from the one the real wire is on.
        let mut out = Vec::with_capacity(VERSION_BYTES + 2 + 4);
        out.extend_from_slice(crate::handshake::RfbVersion::Rfb38.as_wire());
        out.push(1);
        out.push(negotiated.security.to_wire());

        let (opaque, step) = if negotiated.security == SecurityType::VNC_AUTH {
            // RFC 6143 §7.2.2: sixteen bytes of challenge in, sixteen of DES
            // response out. The response is the library's to compute — its DES
            // is not public — so these thirty-two bytes are the one part of the
            // handshake that is genuinely end to end.
            (16, Step::SecurityResult)
        } else if negotiated.expects_security_result() {
            (0, Step::SecurityResult)
        } else {
            // RFB 3.3 and 3.7 send no `SecurityResult` after `None`. The
            // library, told it is speaking 3.8, will read four bytes anyway, so
            // it gets four synthetic zeroes and the real stream is untouched.
            out.extend_from_slice(&[0, 0, 0, 0]);
            (0, Step::ServerInitFixed)
        };

        let attempted = if negotiated.security == SecurityType::VNC_AUTH {
            CredentialKind::Password
        } else {
            CredentialKind::None
        };

        let gate = Self {
            inner,
            peer,
            shared: Arc::clone(&shared),
            swallow: VERSION_BYTES + 1,
            read: ReadGate {
                out,
                out_at: 0,
                scratch: Vec::with_capacity(20),
                tail: Vec::new(),
                opaque,
                step,
                encodings: NegotiatedEncodings::new(encodings),
                attempted,
                surface: (0, 0),
                rects_remaining: 0,
                ends_update: false,
                faulted: None,
            },
        };
        (gate, shared)
    }

    /// Appends up to `want` bytes from the wire onto `dst`.
    ///
    /// Written as an associated function taking the pieces it needs so that the
    /// caller can keep borrowing the rest of `self`.
    fn poll_fill(
        inner: &mut Box<dyn Transport>,
        cx: &mut Context<'_>,
        dst: &mut Vec<u8>,
        want: usize,
    ) -> Poll<io::Result<usize>> {
        let base = dst.len();
        dst.resize(base + want, 0);
        let mut window = ReadBuf::new(&mut dst[base..]);
        let outcome = Pin::new(inner).poll_read(cx, &mut window);
        let filled = window.filled().len();
        dst.truncate(base + filled);
        match outcome {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(filled)),
        }
    }
}

impl ReadGate {
    /// Turns the collected header into checked output, and says what comes next.
    fn advance(&mut self, shared: &GateShared) -> Result<(), GateFault> {
        let step = self.step;
        match step {
            Step::SecurityResult => self.security_result()?,
            Step::ServerInitFixed => self.server_init_fixed()?,
            Step::ServerInitName => self.server_init_name()?,
            Step::MessageType => self.message_type()?,
            Step::UpdateHeader => self.update_header(shared),
            Step::RectHeader => self.rect_header(shared)?,
            Step::CutTextHeader => self.cut_text_header()?,
        }
        self.scratch.clear();
        Ok(())
    }

    fn word(&self) -> u32 {
        u32::from_be_bytes([
            self.scratch[0],
            self.scratch[1],
            self.scratch[2],
            self.scratch[3],
        ])
    }

    /// RFC 6143 §7.2.2. The `U32` is checked here, against the only two values
    /// the RFC defines, and the library is then handed a constant.
    ///
    /// This is the defect that must not come back: `vnc-rs` transmutes this
    /// word into a two-variant `#[repr(u32)]` enum, so a server sending `2`
    /// produced undefined behaviour in the branch that decides whether
    /// authentication failed.
    fn security_result(&mut self) -> Result<(), GateFault> {
        match self.word() {
            0 => {
                self.out.extend_from_slice(&[0, 0, 0, 0]);
                self.step = Step::ServerInitFixed;
                Ok(())
            }
            1 => Err(GateFault::AuthRejected(self.attempted)),
            _ => Err(GateFault::Violation(
                "the server sent a security result RFC 6143 does not define",
            )),
        }
    }

    /// RFC 6143 §7.3.2, up to the name.
    fn server_init_fixed(&mut self) -> Result<(), GateFault> {
        let width = u16::from_be_bytes([self.scratch[0], self.scratch[1]]);
        let height = u16::from_be_bytes([self.scratch[2], self.scratch[3]]);
        check_framebuffer(width, height)?;
        self.surface = (width, height);
        self.out.extend_from_slice(&self.scratch);
        self.step = Step::ServerInitName;
        Ok(())
    }

    /// `ServerInit`'s `U32` name-length, which the library allocates before it
    /// reads a byte of the name.
    fn server_init_name(&mut self) -> Result<(), GateFault> {
        let length = self.word();
        if length > MAX_DESKTOP_NAME_BYTES {
            return Err(GateFault::Violation(
                "the server sent a desktop name longer than this build will read",
            ));
        }
        self.out.extend_from_slice(&self.scratch);
        self.opaque = u64::from(length);
        self.step = Step::MessageType;
        Ok(())
    }

    /// RFC 6143 §7.6: which server message this is.
    fn message_type(&mut self) -> Result<(), GateFault> {
        match self.scratch[0] {
            0 => {
                self.out.push(0);
                self.step = Step::UpdateHeader;
                Ok(())
            }
            // §7.6.2 `SetColorMapEntries`. `vnc-rs` reaches `unimplemented!()`
            // on it, so one byte from a hostile server panicked its decoding
            // task. The adapter always asks for true colour (§7.5.1), so a
            // conforming server has no reason to send one and refusing it costs
            // nothing.
            1 => Err(GateFault::Violation(
                "the server sent a colour map to a client that asked for true colour",
            )),
            2 => {
                self.out.push(2);
                self.step = Step::MessageType;
                Ok(())
            }
            3 => {
                self.out.push(3);
                self.step = Step::CutTextHeader;
                Ok(())
            }
            _ => Err(GateFault::Violation(
                "the server sent an RFB message type this build does not accept",
            )),
        }
    }

    /// RFC 6143 §7.6.1's header. A count of zero is a complete update.
    fn update_header(&mut self, shared: &GateShared) {
        self.rects_remaining = u16::from_be_bytes([self.scratch[1], self.scratch[2]]);
        self.out.extend_from_slice(&self.scratch);
        if self.rects_remaining == 0 {
            self.finish_update(shared);
        } else {
            self.step = Step::RectHeader;
        }
    }

    /// One rectangle header, and the length of the payload behind it.
    fn rect_header(&mut self, shared: &GateShared) -> Result<(), GateFault> {
        let x = u16::from_be_bytes([self.scratch[0], self.scratch[1]]);
        let y = u16::from_be_bytes([self.scratch[2], self.scratch[3]]);
        let width = u16::from_be_bytes([self.scratch[4], self.scratch[5]]);
        let height = u16::from_be_bytes([self.scratch[6], self.scratch[7]]);
        let encoding = RfbEncoding::from_wire(i32::from_be_bytes([
            self.scratch[8],
            self.scratch[9],
            self.scratch[10],
            self.scratch[11],
        ]));

        if !self.encodings.permits(encoding) {
            return Err(GateFault::Violation(
                "the server sent a rectangle in an encoding this connection did not ask for",
            ));
        }

        self.rects_remaining = self.rects_remaining.saturating_sub(1);
        let payload = match encoding {
            RfbEncoding::LAST_RECT => {
                // Not a rectangle: "that was the last one". Whatever the header
                // claimed about size is meaningless and is not acted on.
                self.rects_remaining = 0;
                0
            }
            RfbEncoding::DESKTOP_SIZE => {
                check_framebuffer(width, height)?;
                self.surface = (width, height);
                0
            }
            RfbEncoding::CURSOR => {
                if width > MAX_CURSOR_DIMENSION || height > MAX_CURSOR_DIMENSION {
                    return Err(GateFault::Violation(
                        "the server sent a cursor larger than this build will read",
                    ));
                }
                // §7.8.1: the pixels, then a one-bit-per-pixel mask padded to a
                // whole byte per row.
                let pixels = u64::from(width) * u64::from(height) * BYTES_PER_PIXEL;
                let mask = u64::from(width).div_ceil(8) * u64::from(height);
                pixels + mask
            }
            RfbEncoding::COPY_RECT => {
                self.check_inside(x, y, width, height)?;
                // §7.7.2: two `U16` naming where to copy from. The *source* is
                // checked by `crate::frame`, which knows the surface the
                // presenter holds; there are no pixels here to bound.
                4
            }
            RfbEncoding::RAW => {
                self.check_inside(x, y, width, height)?;
                u64::from(width) * u64::from(height) * BYTES_PER_PIXEL
            }
            // Unreachable while `permits` only admits the five above, and
            // written as a refusal rather than as `unreachable!()` so that
            // adding an encoding to `crate::encoding` without adding its length
            // rule here fails the session instead of desynchronising it.
            _ => {
                return Err(GateFault::Violation(
                    "the server sent a rectangle this build has no length rule for",
                ));
            }
        };

        self.out.extend_from_slice(&self.scratch);
        self.opaque = payload;
        if self.rects_remaining == 0 {
            if self.opaque == 0 {
                // Nothing follows the header — `LastRect`, `DesktopSize` — so
                // the message really is over here.
                self.finish_update(shared);
            } else {
                // It is not over yet. The last rectangle's *payload* still has
                // to cross, and counting the update now would un-arm the
                // session's "one outstanding request" rule one payload early —
                // the same defect the counter was introduced to close, moved
                // from the first rectangle to the last one's header. The count
                // is what "the request was answered" is decided from, so it
                // must not run ahead of the wire.
                self.ends_update = true;
                self.step = Step::MessageType;
            }
        } else {
            self.step = Step::RectHeader;
        }
        Ok(())
    }

    /// RFC 6143 §7.6.4's padding and length.
    fn cut_text_header(&mut self) -> Result<(), GateFault> {
        let length = self.word_at(3);
        if length > MAX_CLIPBOARD_BYTES {
            return Err(GateFault::Violation(
                "the server sent more clipboard text than this build will read",
            ));
        }
        self.out.extend_from_slice(&self.scratch);
        self.opaque = u64::from(length);
        self.step = Step::MessageType;
        Ok(())
    }

    fn word_at(&self, at: usize) -> u32 {
        u32::from_be_bytes([
            self.scratch[at],
            self.scratch[at + 1],
            self.scratch[at + 2],
            self.scratch[at + 3],
        ])
    }

    /// A rectangle must lie inside the framebuffer the server declared.
    ///
    /// `crate::frame` checks this too, and must keep doing so — it is the last
    /// gate before a presenter writes pixels. The point of checking it *here*
    /// is that `crate::frame` sees the rectangle only after `vnc-rs` has
    /// allocated for it, and the allocation is the abort.
    fn check_inside(&self, x: u16, y: u16, width: u16, height: u16) -> Result<(), GateFault> {
        let (surface_width, surface_height) = self.surface;
        if u32::from(x) + u32::from(width) > u32::from(surface_width)
            || u32::from(y) + u32::from(height) > u32::from(surface_height)
        {
            return Err(GateFault::Violation(
                "the server sent a rectangle outside the framebuffer it declared",
            ));
        }
        Ok(())
    }

    fn finish_update(&mut self, shared: &GateShared) {
        shared.updates.fetch_add(1, Ordering::Relaxed);
        self.step = Step::MessageType;
    }

    /// An opaque run has been handed over in full.
    ///
    /// If that run was the last rectangle's payload, *this* is where the
    /// `FramebufferUpdate` (RFC 6143 §7.6.1) ends — the header that preceded it
    /// was not the end of anything. Called from the read path, which is the only
    /// place that knows when the last byte of a run has actually crossed.
    fn opaque_run_finished(&mut self, shared: &GateShared) {
        if std::mem::take(&mut self.ends_update) {
            shared.updates.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn check_framebuffer(width: u16, height: u16) -> Result<(), GateFault> {
    if width == 0 || height == 0 {
        return Err(GateFault::Violation(
            "the server declared a framebuffer with no pixels in it",
        ));
    }
    if u64::from(width) * u64::from(height) > MAX_FRAMEBUFFER_PIXELS {
        return Err(GateFault::Violation(
            "the server declared a framebuffer larger than this build will accept",
        ));
    }
    Ok(())
}

impl Transport for GatedTransport {
    fn peer(&self) -> &TransportPeer {
        &self.peer
    }
}

impl std::fmt::Debug for GatedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatedTransport")
            .field("peer", &self.peer)
            .field("step", &self.read.step)
            .finish()
    }
}

impl AsyncRead for GatedTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(fault) = this.read.faulted {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    fault.detail(),
                )));
            }

            // 1 · Hand over what has already been checked.
            if this.read.out_at < this.read.out.len() {
                let take = buf.remaining().min(this.read.out.len() - this.read.out_at);
                if take == 0 {
                    return Poll::Ready(Ok(()));
                }
                let at = this.read.out_at;
                buf.put_slice(&this.read.out[at..at + take]);
                this.read.out_at += take;
                return Poll::Ready(Ok(()));
            }
            this.read.out.clear();
            this.read.out_at = 0;
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            // 2 · An opaque run: pixels, a name, clipboard text. Nothing here
            // needs inspecting, only counting, so the common case reads
            // straight into the caller's buffer with no copy at all.
            if this.read.opaque > 0 {
                let wanted = u64::try_from(buf.remaining()).unwrap_or(u64::MAX);
                if this.read.opaque >= wanted {
                    let before = buf.filled().len();
                    ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
                    let read = buf.filled().len() - before;
                    this.read.opaque -= u64::try_from(read).unwrap_or(0);
                    if this.read.opaque == 0 {
                        this.read.opaque_run_finished(&this.shared);
                    }
                    return Poll::Ready(Ok(()));
                }
                // The run ends inside this buffer, so only its tail may be
                // taken: the bytes after it are a header that has to be checked
                // before the library sees it. `opaque < buf.remaining()` here,
                // so the scratch is never larger than one caller's buffer.
                let want = usize::try_from(this.read.opaque).unwrap_or(usize::MAX);
                this.read.tail.clear();
                let read = ready!(GatedTransport::poll_fill(
                    &mut this.inner,
                    cx,
                    &mut this.read.tail,
                    want
                ))?;
                if read == 0 {
                    return Poll::Ready(Ok(()));
                }
                buf.put_slice(&this.read.tail[..read]);
                this.read.opaque -= u64::try_from(read).unwrap_or(0);
                if this.read.opaque == 0 {
                    this.read.opaque_run_finished(&this.shared);
                }
                return Poll::Ready(Ok(()));
            }

            // 3 · A header, collected whole before any of it is passed on.
            let needs = this.read.step.needs();
            let have = this.read.scratch.len();
            if have < needs {
                let read = ready!(GatedTransport::poll_fill(
                    &mut this.inner,
                    cx,
                    &mut this.read.scratch,
                    needs - have
                ))?;
                if read == 0 {
                    // End of stream part way through a header. Reported as the
                    // disconnection it is, not as a violation.
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            if let Err(fault) = this.read.advance(&this.shared) {
                let fault = this.shared.record(fault);
                this.read.faulted = Some(fault);
                this.read.scratch.clear();
            }
        }
    }
}

impl AsyncWrite for GatedTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.swallow > 0 {
            // The library's version reply and security-type selection. Both
            // have already been sent for real, and the library was handed a
            // one-entry list so that the selection it makes is the one that was
            // really made; forwarding its copy would desynchronise the wire.
            let taken = this.swallow.min(buf.len());
            this.swallow -= taken;
            return Poll::Ready(Ok(taken));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// A gate fault, turned into the failure a tab shows.
///
/// `vnc-rs` flattens everything the gate refuses into one opaque `VncError`, so
/// the connect path and the session loop both ask here first.
#[must_use]
pub fn refine_with_gate(shared: &GateShared, fallback: ProtocolError) -> ProtocolError {
    match shared.fault() {
        Some(fault) => fault.into_error(),
        None => fallback,
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
    use crate::encoding::{CursorMode, EncodingPreference, encoding_list};
    use crate::handshake::{HandshakeFacts, RfbVersion};
    use crate::testing::PipeTransport;
    use remoter_proto::HostPort;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn negotiated(version: RfbVersion, security: SecurityType) -> Negotiated {
        Negotiated {
            version,
            security,
            facts: HandshakeFacts {
                selected_security: Some(security),
                ..HandshakeFacts::default()
            },
        }
    }

    /// A gate over a pipe, with the server end for a test to script.
    fn gated(
        version: RfbVersion,
        security: SecurityType,
    ) -> (GatedTransport, Arc<GateShared>, tokio::io::DuplexStream) {
        let (client, server) = duplex(1 << 20);
        let transport = PipeTransport::new(client, HostPort::new("127.0.0.1", 5900).unwrap());
        let list = encoding_list(EncodingPreference::Auto, CursorMode::Local);
        let (gate, shared) =
            GatedTransport::new(Box::new(transport), &negotiated(version, security), &list);
        (gate, shared, server)
    }

    /// `ServerInit` for a `width` by `height` desktop with an empty name.
    fn server_init(width: u16, height: u16) -> Vec<u8> {
        let mut init = Vec::new();
        init.extend_from_slice(&width.to_be_bytes());
        init.extend_from_slice(&height.to_be_bytes());
        init.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
        init.extend_from_slice(&0_u32.to_be_bytes());
        init
    }

    #[tokio::test]
    async fn the_library_is_told_38_whatever_the_wire_is_really_speaking() {
        // The synthetic handshake is what takes the version choice away from
        // the server: whatever it announced, the library reads 3.8 and a
        // one-entry security list, so its own floorless `min` has nowhere to go.
        let (mut gate, _shared, mut server) = gated(RfbVersion::Rfb33, SecurityType::NONE);
        server.write_all(&server_init(64, 32)).await.unwrap();

        let mut seen = vec![0_u8; 12 + 2 + 4];
        gate.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen[..12], b"RFB 003.008\n");
        assert_eq!(&seen[12..14], &[1, SecurityType::NONE.to_wire()]);
        assert_eq!(
            &seen[14..18],
            &[0, 0, 0, 0],
            "RFB 3.3 sends no SecurityResult, so the library is given one"
        );
    }

    #[tokio::test]
    async fn the_librarys_handshake_reply_never_reaches_the_wire() {
        let (mut gate, _shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        // Thirteen bytes of version reply and selection, then `ClientInit`.
        gate.write_all(b"RFB 003.008\n").await.unwrap();
        gate.write_all(&[1]).await.unwrap();
        gate.write_all(&[1]).await.unwrap();
        gate.flush().await.unwrap();
        drop(gate);

        let mut forwarded = Vec::new();
        server.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            forwarded,
            vec![1],
            "only ClientInit crosses; the rest was already sent for real"
        );
    }

    #[tokio::test]
    async fn an_out_of_range_security_result_is_refused_rather_than_transmuted() {
        // The HIGH defect as an executable fact. `vnc-rs` transmutes this word
        // into a two-variant `#[repr(u32)]` enum, so `2` was undefined
        // behaviour in the branch that decides whether authentication failed.
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        server.write_all(&2_u32.to_be_bytes()).await.unwrap();

        let mut prefix = vec![0_u8; 14];
        gate.read_exact(&mut prefix).await.unwrap();
        let mut next = [0_u8; 4];
        let error = gate
            .read_exact(&mut next)
            .await
            .expect_err("2 is not a security result");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(matches!(
            shared.fault(),
            Some(GateFault::Violation(detail)) if detail.contains("security result")
        ));
    }

    #[tokio::test]
    async fn a_security_result_of_one_is_a_rejected_credential() {
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::VNC_AUTH);
        server.write_all(&[0x11; 16]).await.unwrap();
        server.write_all(&1_u32.to_be_bytes()).await.unwrap();

        let mut prefix = vec![0_u8; 14 + 16];
        gate.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[14..], &[0x11; 16], "the challenge passes through");
        let mut next = [0_u8; 4];
        gate.read_exact(&mut next)
            .await
            .expect_err("the server said no");
        assert_eq!(
            shared.fault(),
            Some(GateFault::AuthRejected(CredentialKind::Password))
        );
    }

    #[tokio::test]
    async fn a_framebuffer_larger_than_this_build_accepts_is_refused_before_server_init_lands() {
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        server.write_all(&0_u32.to_be_bytes()).await.unwrap();
        server
            .write_all(&server_init(u16::MAX, u16::MAX))
            .await
            .unwrap();

        let mut prefix = vec![0_u8; 14 + 4];
        gate.read_exact(&mut prefix).await.unwrap();
        let mut next = [0_u8; 1];
        gate.read_exact(&mut next)
            .await
            .expect_err("65535 squared pixels is a 17 GiB raw rectangle");
        assert!(matches!(
            shared.fault(),
            Some(GateFault::Violation(detail)) if detail.contains("framebuffer larger")
        ));
    }

    /// Brings the gate past the handshake and `ServerInit` for a 64x32 desktop.
    async fn ready(
        gate: &mut GatedTransport,
        server: &mut tokio::io::DuplexStream,
    ) -> io::Result<()> {
        server.write_all(&0_u32.to_be_bytes()).await?;
        server.write_all(&server_init(64, 32)).await?;
        let mut prefix = vec![0_u8; 14 + 4 + 24];
        gate.read_exact(&mut prefix).await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_desktop_name_longer_than_this_build_reads_is_refused() {
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        server.write_all(&0_u32.to_be_bytes()).await.unwrap();
        let mut init = Vec::new();
        init.extend_from_slice(&64_u16.to_be_bytes());
        init.extend_from_slice(&32_u16.to_be_bytes());
        init.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
        init.extend_from_slice(&u32::MAX.to_be_bytes());
        server.write_all(&init).await.unwrap();

        let mut prefix = vec![0_u8; 14 + 4 + 20];
        gate.read_exact(&mut prefix).await.unwrap();
        let mut next = [0_u8; 1];
        gate.read_exact(&mut next)
            .await
            .expect_err("a 4 GiB name is allocated before a byte of it arrives");
        assert!(matches!(
            shared.fault(),
            Some(GateFault::Violation(detail)) if detail.contains("desktop name")
        ));
    }

    #[tokio::test]
    async fn a_raw_rectangle_outside_the_framebuffer_never_reaches_the_library() {
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        ready(&mut gate, &mut server).await.unwrap();

        // One rectangle, 65535 by 65535, raw: a 17 GiB `Vec::with_capacity`
        // inside the library, which aborts rather than unwinds.
        let mut message = vec![0_u8, 0];
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&u16::MAX.to_be_bytes());
        message.extend_from_slice(&u16::MAX.to_be_bytes());
        message.extend_from_slice(&RfbEncoding::RAW.to_wire().to_be_bytes());
        server.write_all(&message).await.unwrap();

        let mut seen = Vec::new();
        let _ = gate.read_to_end(&mut seen).await;
        assert_eq!(
            seen,
            vec![0, 0, 0, 1],
            "the update header crosses and the rectangle header does not"
        );
        assert!(matches!(
            shared.fault(),
            Some(GateFault::Violation(detail)) if detail.contains("outside the framebuffer")
        ));
    }

    #[tokio::test]
    async fn an_encoding_that_was_never_promised_is_refused() {
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        ready(&mut gate, &mut server).await.unwrap();

        let mut message = vec![0_u8, 0];
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&4_u16.to_be_bytes());
        message.extend_from_slice(&4_u16.to_be_bytes());
        message.extend_from_slice(&RfbEncoding::ZRLE.to_wire().to_be_bytes());
        server.write_all(&message).await.unwrap();

        let mut seen = Vec::new();
        let _ = gate.read_to_end(&mut seen).await;
        assert!(matches!(
            shared.fault(),
            Some(GateFault::Violation(detail)) if detail.contains("did not ask for")
        ));
    }

    #[tokio::test]
    async fn a_colour_map_is_refused_before_the_library_can_reach_its_unimplemented() {
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        ready(&mut gate, &mut server).await.unwrap();
        server.write_all(&[1_u8, 0, 0, 0, 0, 1]).await.unwrap();

        let mut seen = Vec::new();
        let _ = gate.read_to_end(&mut seen).await;
        assert!(seen.is_empty(), "not one byte of it crosses");
        assert!(matches!(
            shared.fault(),
            Some(GateFault::Violation(detail)) if detail.contains("colour map")
        ));
    }

    #[tokio::test]
    async fn clipboard_text_longer_than_this_build_reads_is_refused() {
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        ready(&mut gate, &mut server).await.unwrap();
        let mut message = vec![3_u8, 0, 0, 0];
        message.extend_from_slice(&u32::MAX.to_be_bytes());
        server.write_all(&message).await.unwrap();

        let mut seen = Vec::new();
        let _ = gate.read_to_end(&mut seen).await;
        assert_eq!(seen, vec![3], "the type byte crosses, the length does not");
        assert!(matches!(
            shared.fault(),
            Some(GateFault::Violation(detail)) if detail.contains("clipboard text")
        ));
    }

    #[tokio::test]
    async fn a_well_formed_update_crosses_unchanged_and_counts_as_one() {
        // The framer must be transparent: `vnc-rs` re-parses these bytes, so a
        // single byte added, dropped or reordered would desynchronise it.
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        ready(&mut gate, &mut server).await.unwrap();

        let mut message = vec![0_u8, 0];
        message.extend_from_slice(&2_u16.to_be_bytes());
        for index in 0..2_u16 {
            message.extend_from_slice(&(index * 4).to_be_bytes());
            message.extend_from_slice(&0_u16.to_be_bytes());
            message.extend_from_slice(&4_u16.to_be_bytes());
            message.extend_from_slice(&4_u16.to_be_bytes());
            message.extend_from_slice(&RfbEncoding::RAW.to_wire().to_be_bytes());
            let seed = u8::try_from(index).unwrap_or(0) + 1;
            message.extend(std::iter::repeat_n(seed, 4 * 4 * 4));
        }
        server.write_all(&message).await.unwrap();
        drop(server);

        let mut seen = Vec::new();
        let _ = gate.read_to_end(&mut seen).await;
        assert_eq!(seen, message, "byte for byte");
        assert_eq!(
            shared.updates_completed(),
            1,
            "two rectangles are one update, not two"
        );
    }

    #[tokio::test]
    async fn an_update_is_not_counted_until_its_last_payload_has_crossed() {
        // The defect: the counter advanced on the *last rectangle's header*,
        // one payload before the `FramebufferUpdate` actually ended. The
        // session decides "the request was answered" from this number
        // (RFC 6143 §7.5.3), so an early count un-arms the one-outstanding-
        // request rule while the server is still writing pixels — the same
        // defect the counter exists to close, moved from the first rectangle to
        // the last one's header.
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        ready(&mut gate, &mut server).await.unwrap();

        let mut message = vec![0_u8, 0];
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&4_u16.to_be_bytes());
        message.extend_from_slice(&4_u16.to_be_bytes());
        message.extend_from_slice(&RfbEncoding::RAW.to_wire().to_be_bytes());
        let pixels = [0x5a_u8; 4 * 4 * 4];

        // The whole header, and half the pixels behind it.
        server.write_all(&message).await.unwrap();
        server.write_all(&pixels[..32]).await.unwrap();
        let mut seen = vec![0_u8; 4 + 12 + 32];
        gate.read_exact(&mut seen).await.unwrap();
        assert_eq!(
            shared.updates_completed(),
            0,
            "a rectangle header is not the end of the message it introduces"
        );

        // The rest of the pixels, and only now is the update answered.
        server.write_all(&pixels[32..]).await.unwrap();
        let mut rest = vec![0_u8; 32];
        gate.read_exact(&mut rest).await.unwrap();
        assert_eq!(shared.updates_completed(), 1);
    }

    #[tokio::test]
    async fn last_rect_ends_an_update_whose_count_was_a_guess() {
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        ready(&mut gate, &mut server).await.unwrap();

        let mut message = vec![0_u8, 0];
        message.extend_from_slice(&u16::MAX.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&RfbEncoding::LAST_RECT.to_wire().to_be_bytes());
        // A Bell afterwards, which can only be read if the framer went back to
        // looking for a message type rather than for 65534 more rectangles.
        message.push(2);
        server.write_all(&message).await.unwrap();
        drop(server);

        let mut seen = Vec::new();
        let _ = gate.read_to_end(&mut seen).await;
        assert_eq!(seen, message);
        assert_eq!(shared.updates_completed(), 1);
    }

    #[tokio::test]
    async fn a_desktop_resize_moves_the_bound_every_later_rectangle_is_checked_against() {
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        ready(&mut gate, &mut server).await.unwrap();

        let mut message = vec![0_u8, 0];
        message.extend_from_slice(&2_u16.to_be_bytes());
        // §7.8.2: the desktop is now 128 by 96.
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&128_u16.to_be_bytes());
        message.extend_from_slice(&96_u16.to_be_bytes());
        message.extend_from_slice(&RfbEncoding::DESKTOP_SIZE.to_wire().to_be_bytes());
        // A rectangle at x = 100, which was outside the old 64-wide desktop.
        message.extend_from_slice(&100_u16.to_be_bytes());
        message.extend_from_slice(&80_u16.to_be_bytes());
        message.extend_from_slice(&8_u16.to_be_bytes());
        message.extend_from_slice(&8_u16.to_be_bytes());
        message.extend_from_slice(&RfbEncoding::RAW.to_wire().to_be_bytes());
        message.extend(std::iter::repeat_n(0x77_u8, 8 * 8 * 4));
        server.write_all(&message).await.unwrap();
        drop(server);

        let mut seen = Vec::new();
        let _ = gate.read_to_end(&mut seen).await;
        assert_eq!(seen, message);
        assert_eq!(shared.fault(), None);
    }

    #[tokio::test]
    async fn a_cursor_larger_than_this_build_reads_is_refused() {
        // A cursor rectangle is not bounded by the framebuffer — its x and y
        // are the hot spot — so without a limit of its own it is a second route
        // to the same allocation.
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        ready(&mut gate, &mut server).await.unwrap();

        let mut message = vec![0_u8, 0];
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&u16::MAX.to_be_bytes());
        message.extend_from_slice(&u16::MAX.to_be_bytes());
        message.extend_from_slice(&RfbEncoding::CURSOR.to_wire().to_be_bytes());
        server.write_all(&message).await.unwrap();

        let mut seen = Vec::new();
        let _ = gate.read_to_end(&mut seen).await;
        assert!(matches!(
            shared.fault(),
            Some(GateFault::Violation(detail)) if detail.contains("cursor larger")
        ));
    }

    #[tokio::test]
    async fn the_stream_may_be_split_at_any_byte() {
        // The framer is fed by `poll_read`, so every header can arrive in
        // pieces — which is what a slow link does and what a test that writes
        // the whole message at once never exercises.
        let (mut gate, shared, mut server) = gated(RfbVersion::Rfb38, SecurityType::NONE);
        server.write_all(&0_u32.to_be_bytes()).await.unwrap();

        let mut message = server_init(64, 32);
        message.extend_from_slice(&[0, 0]);
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&2_u16.to_be_bytes());
        message.extend_from_slice(&2_u16.to_be_bytes());
        message.extend_from_slice(&RfbEncoding::RAW.to_wire().to_be_bytes());
        message.extend(std::iter::repeat_n(0xab_u8, 2 * 2 * 4));

        let dribble = tokio::spawn(async move {
            for byte in message {
                server.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
            drop(server);
        });

        let mut seen = Vec::new();
        let _ = gate.read_to_end(&mut seen).await;
        dribble.await.unwrap();
        assert_eq!(
            shared.fault(),
            None,
            "one byte at a time is still valid RFB"
        );
        assert_eq!(shared.updates_completed(), 1);
        assert_eq!(seen.len(), 14 + 4 + 24 + 4 + 12 + 16);
    }
}
