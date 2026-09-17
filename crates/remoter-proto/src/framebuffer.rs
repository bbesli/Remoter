//! The shared vocabulary of a graphical session.
//!
//! SSH is a byte stream. RDP and VNC are a framebuffer plus input, and they are
//! *different* framebuffers plus *different* input: RDP speaks dirty rectangles
//! of RemoteFX or interleaved bitmaps and PS/2 scancodes (MS-RDPBCGR §2.2.9.1,
//! §2.2.8.1.1.3), RFB speaks rectangles of Raw, CopyRect, Tight or ZRLE and X11
//! keysyms (RFC 6143 §7.6.1, §7.5.4). Neither of those vocabularies belongs in
//! the interface.
//!
//! This module is the one that does. Both adapters decode into it, one
//! presenter renders it, and **the interface never learns which protocol it
//! has**. That is not tidiness: `docs/architecture/rendering.md` puts the
//! presenter behind an interface that may differ per platform, and a presenter
//! that had to branch on the protocol would have to be written twice per
//! platform instead of once.
//!
//! # It rides the session bus that already exists
//!
//! There is one [`crate::SessionSupervisor`], one [`crate::EventSink`] and one
//! [`crate::SessionEvent`]. A framebuffer session is not a second pipeline; it
//! is the same pipeline carrying different bytes:
//!
//! | What | How it travels |
//! |---|---|
//! | Pixels, cursor shape | [`FrameMessage::encode`] → [`SessionEvent::Data`] |
//! | The desktop changed size | [`SessionEvent::Resized`] |
//! | The remote has something copied | [`SessionEvent::ClipboardOffer`] |
//! | What it copied, for the local clipboard | [`SessionEvent::ClipboardContent`] |
//! | Credentials, certificate decisions | [`SessionEvent::Prompt`] |
//! | Clear-text warning, weak auth | [`SessionEvent::Warning`] |
//! | Input, clipboard, resize, disconnect | [`crate::SessionCommand`] |
//!
//! `SessionEvent::Data` is already documented as "terminal bytes, **or an
//! encoded framebuffer update**", and `remoter-ipc` already forwards it to the
//! interface as a raw byte payload rather than JSON. So the whole graphical
//! path is the terminal path with a different decoder on the far end, and
//! everything the supervisor guarantees — bounded channels, cancellation,
//! a panicked session destroyed rather than resumed — holds without a second
//! implementation.
//!
//! **Use [`FrameMessage::emit`], never [`crate::EventSink::data`].** `data` is
//! the *terminal* path: it coalesces and re-chunks, which is exactly right for
//! a byte stream and destructive for a framed one. Two framebuffer messages
//! written through it would arrive as one buffer split at an arbitrary
//! boundary, and the presenter would parse a header out of the middle of a
//! JPEG.
//!
//! # What is deliberately not here
//!
//! Named, so that the next person knows it is absent by decision rather than by
//! oversight:
//!
//! - **Audio (MS-RDPEA), printing and device redirection (MS-RDPEFS).**
//!   [`crate::Capabilities`] has a bit for each; none of them is pixels, and
//!   inventing a vocabulary before an adapter needs one is scaffolding.
//! - **Multi-monitor.** `rendering.md` says each monitor is a separate
//!   framebuffer stream with a layout negotiated at connect time. The header
//!   below has no monitor field, so adding it is a format revision — which is
//!   the honest position while the presenter itself is not chosen until the end
//!   of v0.2 (ADR-0010).
//! - **The adaptive encoder and its byte budget.** ADR-0010 §1 puts the
//!   encoding *choice* behind a measured budget. That is policy, and it lives
//!   with the encoder and `remoter-bench-framepath`. This module only fixes the
//!   vocabulary the choice is expressed in.
//! - **Touch and pen input (MS-RDPEI).**
//! - **A separate resize message.** [`SessionEvent::Resized`] already exists
//!   and already means "the remote display changed size". A second way to say
//!   the same thing is a second way to get it wrong.
//! - **Framebuffer *reading*.** Nothing here lets a caller ask for the current
//!   surface. The presenter owns the surface; the core streams deltas at it.
//!   Keeping a second copy in Rust would double the memory of every session for
//!   the benefit of nothing that exists.

use std::fmt;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};

use crate::coalesce::DEFAULT_FRAME_INTERVAL;
use crate::error::ProtocolError;
use crate::event::{EventSink, SessionEvent};
use crate::supervisor::SessionId;

/// Bytes in a message header.
pub const FRAME_HEADER_BYTES: usize = 16;

/// Bytes in one rectangle descriptor.
pub const FRAME_RECT_BYTES: usize = 14;

/// A message carrying dirty rectangles of the desktop.
pub const MESSAGE_FRAMEBUFFER: u8 = 0;

/// A message carrying the cursor shape the server set.
pub const MESSAGE_CURSOR: u8 = 1;

/// Header flag: this update is self-sufficient. See [`FrameUpdate::keyframe`].
pub const FLAG_KEYFRAME: u8 = 1 << 0;

/// How many bytes may accumulate between flushes before one is forced.
///
/// Four megabytes is roughly half an uncompressed 1080p frame: large enough
/// that a normal interactive update is never split, small enough that a full
/// redraw does not sit in a buffer waiting for a timer that is about to fire
/// anyway.
pub const DEFAULT_MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;

/// A rectangle of the remote display, in remote pixels.
///
/// Coordinates are `u16` because both protocols carry them that way: RFB's
/// `FramebufferUpdate` rectangle header is four `U16` fields (RFC 6143 §7.6.1)
/// and RDP's `TS_BITMAP_DATA` bounds are `destLeft`/`destTop`/`destRight`/
/// `destBottom`, all 16-bit (MS-RDPBCGR §2.2.9.1.1.3.1.2.2). A desktop wider
/// than 65 535 pixels is not representable by either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rect {
    /// Distance from the left edge of the desktop.
    pub x: u16,
    /// Distance from the top edge of the desktop.
    pub y: u16,
    /// Width, in pixels. Zero means an empty rectangle.
    pub width: u16,
    /// Height, in pixels. Zero means an empty rectangle.
    pub height: u16,
}

impl Rect {
    /// A rectangle at `x`, `y` of `width` by `height`.
    #[must_use]
    pub const fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// A rectangle covering a whole desktop of this size.
    #[must_use]
    pub const fn surface(width: u16, height: u16) -> Self {
        Self::new(0, 0, width, height)
    }

    /// Whether the rectangle encloses no pixels.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// The number of pixels enclosed. `u32` because 65 535 squared does not fit
    /// in a `u16` and a wrapping multiply here would under-allocate a buffer.
    #[must_use]
    pub const fn pixels(self) -> u32 {
        self.width as u32 * self.height as u32
    }

    /// One past the rightmost column, widened so the sum cannot wrap.
    #[must_use]
    pub const fn right(self) -> u32 {
        self.x as u32 + self.width as u32
    }

    /// One past the bottom row, widened so the sum cannot wrap.
    #[must_use]
    pub const fn bottom(self) -> u32 {
        self.y as u32 + self.height as u32
    }

    /// Whether `self` encloses every pixel of `other`.
    ///
    /// An empty `other` is contained by anything: it has no pixels to be
    /// outside.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        if other.is_empty() {
            return true;
        }
        if self.is_empty() {
            return false;
        }
        self.x <= other.x
            && self.y <= other.y
            && self.right() >= other.right()
            && self.bottom() >= other.bottom()
    }

    /// How many bytes of raw pixels this rectangle holds in `format`.
    ///
    /// `None` on overflow rather than a wrapped value, because the caller is
    /// about to size a buffer with it and a wrapped length is a short buffer.
    #[must_use]
    pub const fn raw_byte_len(self, format: PixelFormat) -> Option<usize> {
        let pixels = self.pixels() as usize;
        pixels.checked_mul(format.bytes_per_pixel() as usize)
    }
}

/// How the bytes of a rectangle's pixels are arranged.
///
/// Only 32-bit layouts, and deliberately. Both protocols can be asked for a
/// 32-bit true-colour format — RFB by sending `SetPixelFormat` (RFC 6143 §7.5.1)
/// and RDP by requesting a colour depth in the client core data (MS-RDPBCGR
/// §2.2.1.3.2) — and where a server insists on 8- or 16-bit or a palette, the
/// **adapter** converts. That conversion is a loop over pixels: in Rust it is
/// a few instructions per pixel on a worker thread, and in the WebView it is
/// the render thread, which has a 30 ms budget it is already spending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PixelFormat {
    /// Blue, green, red, then a byte that is **not** alpha and must be treated
    /// as fully opaque. This is what an RDP 32bpp surface and `vnc-rs`'s
    /// `PixelFormat::bgra()` actually deliver: the fourth byte is padding, and
    /// a presenter that believes it is alpha renders a transparent desktop.
    Bgrx8888,
    /// Red, green, blue, alpha, with straight (not premultiplied) alpha. Used
    /// for cursor images, which genuinely have a mask — RFB's cursor
    /// pseudo-encoding carries one (RFC 6143 §7.8.1) and so does RDP's colour
    /// pointer update (MS-RDPBCGR §2.2.9.1.1.4.4).
    Rgba8888,
}

impl PixelFormat {
    /// Bytes per pixel. Four for every format here, by design.
    #[must_use]
    pub const fn bytes_per_pixel(self) -> u8 {
        4
    }

    /// The value written into a rectangle descriptor.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Bgrx8888 => 0,
            Self::Rgba8888 => 1,
        }
    }

    /// The format a descriptor byte names, or `None` if it names nothing.
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Bgrx8888),
            1 => Some(Self::Rgba8888),
            _ => None,
        }
    }
}

/// How a rectangle's payload is compressed.
///
/// These are the four in `docs/architecture/rendering.md`'s encoding table, and
/// they are chosen per rectangle rather than per message — which is why the
/// encoding byte sits in the rectangle descriptor and not in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameEncoding {
    /// Uncompressed pixels in the rectangle's declared format, row-major, top
    /// row first, no padding between rows.
    Raw,
    /// Run-length encoded pixels: repeated `u32` little-endian run length, then
    /// one pixel of the declared format. Cheap, and very effective on the flat
    /// regions a desktop is mostly made of.
    Rle,
    /// A baseline JPEG image covering exactly the rectangle. Lossy, and the
    /// escape hatch ADR-0010 §1 escalates to when the byte budget tightens. The
    /// declared pixel format does not apply: the JPEG carries its own.
    Jpeg,
    /// The rectangle is a copy of another part of the surface the presenter
    /// already holds. The payload is exactly four bytes — `u16` source x, `u16`
    /// source y, little-endian — and no pixels at all. This is how scrolling
    /// and window drags cost nothing, and it is native to both protocols:
    /// RFB CopyRect (RFC 6143 §7.7.2) and the RDP scrblt primary drawing order
    /// (MS-RDPEGDI §2.2.2.2.1.1.2.7).
    CopyRect,
}

/// Bytes in a [`FrameEncoding::CopyRect`] payload: a source x and a source y.
pub const COPY_RECT_PAYLOAD_BYTES: usize = 4;

impl FrameEncoding {
    /// The value written into a rectangle descriptor.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Raw => 0,
            Self::Rle => 1,
            Self::Jpeg => 2,
            Self::CopyRect => 3,
        }
    }

    /// The encoding a descriptor byte names, or `None` if it names nothing.
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Raw),
            1 => Some(Self::Rle),
            2 => Some(Self::Jpeg),
            3 => Some(Self::CopyRect),
            _ => None,
        }
    }
}

/// One rectangle and the bytes that fill it.
///
/// `Debug` is hand-written and redacting, for the same reason
/// [`SessionEvent`]'s is. A framebuffer rectangle is a picture of someone's
/// screen; the screen may have a password manager open on it. The length is
/// enough for the diagnostics anyone actually needs.
#[derive(Clone, PartialEq, Eq)]
pub struct FrameRect {
    /// Where on the desktop the rectangle lands.
    pub rect: Rect,
    /// How its payload is compressed.
    pub encoding: FrameEncoding,
    /// How its pixels are arranged. Ignored for [`FrameEncoding::Jpeg`] and
    /// [`FrameEncoding::CopyRect`], which carry no pixels in this format.
    pub format: PixelFormat,
    payload: Bytes,
}

impl FrameRect {
    /// A rectangle of uncompressed pixels.
    #[must_use]
    pub const fn raw(rect: Rect, format: PixelFormat, payload: Bytes) -> Self {
        Self {
            rect,
            encoding: FrameEncoding::Raw,
            format,
            payload,
        }
    }

    /// A rectangle of run-length encoded pixels.
    #[must_use]
    pub const fn rle(rect: Rect, format: PixelFormat, payload: Bytes) -> Self {
        Self {
            rect,
            encoding: FrameEncoding::Rle,
            format,
            payload,
        }
    }

    /// A rectangle carrying a JPEG image.
    #[must_use]
    pub const fn jpeg(rect: Rect, payload: Bytes) -> Self {
        Self {
            rect,
            encoding: FrameEncoding::Jpeg,
            // Nominal: a JPEG declares its own colour space. Recorded rather
            // than left undefined so the descriptor never carries a byte whose
            // value nobody chose.
            format: PixelFormat::Bgrx8888,
            payload,
        }
    }

    /// A rectangle copied from elsewhere on the surface the presenter holds.
    #[must_use]
    pub fn copy_rect(destination: Rect, source_x: u16, source_y: u16) -> Self {
        let mut payload = BytesMut::with_capacity(COPY_RECT_PAYLOAD_BYTES);
        payload.put_u16_le(source_x);
        payload.put_u16_le(source_y);
        Self {
            rect: destination,
            encoding: FrameEncoding::CopyRect,
            format: PixelFormat::Bgrx8888,
            payload: payload.freeze(),
        }
    }

    /// The bytes filling the rectangle.
    #[must_use]
    pub const fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Where a [`FrameEncoding::CopyRect`] rectangle reads from, or `None` for
    /// any other encoding or a malformed payload.
    #[must_use]
    pub fn copy_source(&self) -> Option<(u16, u16)> {
        if self.encoding != FrameEncoding::CopyRect || self.payload.len() != COPY_RECT_PAYLOAD_BYTES
        {
            return None;
        }
        let x = u16::from_le_bytes([self.payload[0], self.payload[1]]);
        let y = u16::from_le_bytes([self.payload[2], self.payload[3]]);
        Some((x, y))
    }

    /// How many bytes this rectangle occupies once encoded, descriptor
    /// included.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        FRAME_RECT_BYTES + self.payload.len()
    }
}

impl fmt::Debug for FrameRect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameRect")
            .field("rect", &self.rect)
            .field("encoding", &self.encoding)
            .field("format", &self.format)
            .field(
                "payload",
                &format_args!("<redacted, {} bytes>", self.payload.len()),
            )
            .finish()
    }
}

/// A batch of dirty rectangles.
///
/// # Full frames and deltas
///
/// A **delta** describes what changed since the update before it. It is only
/// meaningful applied in order onto the surface the presenter already holds,
/// and [`FrameEncoding::CopyRect`] makes that literal: a copy-rect reads pixels
/// the presenter has and the core does not.
///
/// A **keyframe** covers the entire desktop and depends on nothing before it.
/// The presenter may discard everything it holds and start from one. Three
/// things need that:
///
/// - a presenter attaching to a session that is already running,
/// - a recorder, which needs a point a replay can seek to,
/// - a presenter that saw a gap in [`FrameUpdate::seq`] and therefore knows the
///   encoder dropped a stale frame under load, so its surface is now wrong.
///
/// The flag says which this is. It is not inferred from the rectangles,
/// because "these rectangles happen to tile the desktop" and "this update is
/// self-sufficient" are different claims — a full-screen batch of copy-rects
/// is the first and not the second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameUpdate {
    /// Increases by one per message within a session. A gap tells the
    /// presenter that the encoder dropped something and its surface is stale.
    pub seq: u32,
    /// Whether this update is self-sufficient. See the type documentation.
    pub keyframe: bool,
    /// The rectangles, **in the order they must be applied**. Reordering them
    /// is not a permitted optimisation: a copy-rect reads what the rectangles
    /// before it wrote.
    pub rects: Vec<FrameRect>,
}

/// The cursor shape the server set.
///
/// Sent as its own message rather than drawn into the framebuffer because the
/// pointer moves far more often than it changes shape, and a presenter that
/// owns the shape can follow the local pointer at the refresh rate of the
/// display instead of the rate of the network. Both protocols work this way:
/// RFB's cursor pseudo-encoding (RFC 6143 §7.8.1) and RDP's pointer updates
/// (MS-RDPBCGR §2.2.9.1.1.4).
///
/// `Debug` is redacting: a cursor image is small, but it is still pixels from
/// someone else's screen, and the rule is not worth an exception.
#[derive(Clone, PartialEq, Eq)]
pub struct CursorUpdate {
    /// Increases by one per message within a session, sharing the counter with
    /// [`FrameUpdate::seq`] — one stream, one sequence.
    pub seq: u32,
    /// The hot spot's offset from the top-left of the image, in pixels.
    pub hotspot_x: u16,
    /// The hot spot's vertical offset from the top-left of the image.
    pub hotspot_y: u16,
    /// The image's width. Zero, with a zero height, hides the cursor.
    pub width: u16,
    /// The image's height. Zero, with a zero width, hides the cursor.
    pub height: u16,
    /// Always [`PixelFormat::Rgba8888`] in practice: a cursor has a real mask,
    /// and dropping it draws a black box around every pointer.
    pub format: PixelFormat,
    image: Bytes,
}

impl CursorUpdate {
    /// A cursor image. `image` is `width * height` pixels in `format`,
    /// row-major.
    #[must_use]
    pub const fn new(
        seq: u32,
        hotspot_x: u16,
        hotspot_y: u16,
        width: u16,
        height: u16,
        format: PixelFormat,
        image: Bytes,
    ) -> Self {
        Self {
            seq,
            hotspot_x,
            hotspot_y,
            width,
            height,
            format,
            image,
        }
    }

    /// The server asked for no pointer at all — a full-screen video player, or
    /// a game that draws its own.
    #[must_use]
    pub const fn hidden(seq: u32) -> Self {
        Self {
            seq,
            hotspot_x: 0,
            hotspot_y: 0,
            width: 0,
            height: 0,
            format: PixelFormat::Rgba8888,
            image: Bytes::new(),
        }
    }

    /// Whether this update hides the pointer.
    #[must_use]
    pub const fn is_hidden(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// The cursor's pixels.
    #[must_use]
    pub const fn image(&self) -> &Bytes {
        &self.image
    }
}

impl fmt::Debug for CursorUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CursorUpdate")
            .field("seq", &self.seq)
            .field("hotspot", &(self.hotspot_x, self.hotspot_y))
            .field("size", &(self.width, self.height))
            .field("format", &self.format)
            .field(
                "image",
                &format_args!("<redacted, {} bytes>", self.image.len()),
            )
            .finish()
    }
}

/// Anything a graphical session sends as bytes.
///
/// # The wire format
///
/// Little-endian throughout, because every platform Remoter builds for is
/// little-endian, so encoding is a copy rather than a byte swap per field. The
/// frontend reads it with a `DataView`, which takes the endianness as an
/// argument and needs no alignment.
///
/// ```text
/// header, 16 bytes
///   0  u64  session        which tab these pixels belong to
///   8  u32  seq            message counter; a gap means frames were dropped
///  12  u8   message        0 = framebuffer, 1 = cursor
///  13  u8   flags          bit 0 = keyframe
///  14  u16  rect_count
///
/// then rect_count × 14 bytes
///   0  u16  x
///   2  u16  y
///   4  u16  width
///   6  u16  height
///   8  u8   encoding       0 raw, 1 RLE, 2 JPEG, 3 copy-rect
///   9  u8   pixel_format   0 BGRX8888, 1 RGBA8888
///  10  u32  byte_length
///
/// then the payloads, concatenated, in descriptor order
/// ```
///
/// A cursor message is one rectangle whose `x`/`y` are the hot spot rather than
/// a position on the desktop, and whose payload is the cursor image. A width
/// and height of zero hide the pointer.
///
/// This differs from the sketch in `docs/architecture/rendering.md` in two
/// ways, and that document has been amended to match. The session identifier is
/// 64 bits, because [`SessionId`] is a `u64` counter and truncating it into a
/// header is how two tabs quietly become one. The encoding byte moved from the
/// header into the rectangle descriptor, because the same document says the
/// encoder chooses per rectangle — which a single message-level byte cannot
/// express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameMessage {
    /// Dirty rectangles of the desktop.
    Framebuffer(FrameUpdate),
    /// The cursor shape the server set.
    Cursor(CursorUpdate),
}

impl FrameMessage {
    /// The sequence number this message carries.
    #[must_use]
    pub const fn seq(&self) -> u32 {
        match self {
            Self::Framebuffer(update) => update.seq,
            Self::Cursor(update) => update.seq,
        }
    }

    /// How many bytes [`encode`](Self::encode) will produce.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Framebuffer(update) => {
                FRAME_HEADER_BYTES
                    + update
                        .rects
                        .iter()
                        .map(FrameRect::encoded_len)
                        .sum::<usize>()
            }
            Self::Cursor(update) => FRAME_HEADER_BYTES + FRAME_RECT_BYTES + update.image.len(),
        }
    }

    /// Serialises this message for [`SessionEvent::Data`].
    ///
    /// Rectangles beyond [`u16::MAX`] are dropped rather than silently
    /// wrapping the count field, which would make the presenter read payload
    /// bytes as descriptors. An adapter producing 65 535 rectangles in one
    /// update has a defect of its own; truncating is the containable failure.
    #[must_use]
    pub fn encode(&self, session: SessionId) -> Bytes {
        let mut out = BytesMut::with_capacity(self.encoded_len());
        match self {
            Self::Framebuffer(update) => {
                let rects: &[FrameRect] = if update.rects.len() > usize::from(u16::MAX) {
                    &update.rects[..usize::from(u16::MAX)]
                } else {
                    &update.rects
                };
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "the slice above bounds the length to u16::MAX"
                )]
                let count = rects.len() as u16;
                put_header(
                    &mut out,
                    session,
                    update.seq,
                    MESSAGE_FRAMEBUFFER,
                    if update.keyframe { FLAG_KEYFRAME } else { 0 },
                    count,
                );
                for rect in rects {
                    put_descriptor(
                        &mut out,
                        rect.rect,
                        rect.encoding,
                        rect.format,
                        rect.payload.len(),
                    );
                }
                for rect in rects {
                    out.put_slice(&rect.payload);
                }
            }
            Self::Cursor(update) => {
                put_header(&mut out, session, update.seq, MESSAGE_CURSOR, 0, 1);
                put_descriptor(
                    &mut out,
                    Rect::new(
                        update.hotspot_x,
                        update.hotspot_y,
                        update.width,
                        update.height,
                    ),
                    FrameEncoding::Raw,
                    update.format,
                    update.image.len(),
                );
                out.put_slice(&update.image);
            }
        }
        out.freeze()
    }

    /// Parses a message produced by [`encode`](Self::encode).
    ///
    /// The recorder writes these to a file and a replay reads them back, so
    /// this parses input that has been on disk and may have been tampered with.
    /// Every length is therefore checked against what is actually present
    /// rather than trusted, and the payloads must account for the buffer
    /// exactly — trailing bytes are a malformed message, not something to
    /// ignore.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ProtocolViolation`] for a short buffer, an unknown
    /// message kind, an unknown encoding or pixel format, a payload length that
    /// does not fit, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<(SessionId, Self), ProtocolError> {
        let violation = |detail: &'static str| ProtocolError::ProtocolViolation { detail };

        if bytes.len() < FRAME_HEADER_BYTES {
            return Err(violation("a framebuffer message shorter than its header"));
        }
        let session = SessionId::from_raw(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]));
        let seq = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let message = bytes[12];
        let flags = bytes[13];
        let count = usize::from(u16::from_le_bytes([bytes[14], bytes[15]]));

        let descriptors_end = FRAME_HEADER_BYTES
            .checked_add(count.checked_mul(FRAME_RECT_BYTES).ok_or_else(|| {
                violation("a framebuffer message whose descriptor table overflows")
            })?)
            .ok_or_else(|| violation("a framebuffer message whose descriptor table overflows"))?;
        if bytes.len() < descriptors_end {
            return Err(violation(
                "a framebuffer message shorter than its descriptor table",
            ));
        }

        // Descriptors first, payloads second: the payload of rectangle n starts
        // where the payloads of every rectangle before it end, so the whole
        // table has to be read before any payload can be located.
        let mut descriptors = Vec::with_capacity(count.min(1024));
        let mut payload_total: usize = 0;
        for index in 0..count {
            let at = FRAME_HEADER_BYTES + index * FRAME_RECT_BYTES;
            let field =
                |offset: usize| u16::from_le_bytes([bytes[at + offset], bytes[at + offset + 1]]);
            let rect = Rect::new(field(0), field(2), field(4), field(6));
            let encoding = FrameEncoding::from_wire(bytes[at + 8])
                .ok_or_else(|| violation("a rectangle with an unknown encoding"))?;
            let format = PixelFormat::from_wire(bytes[at + 9])
                .ok_or_else(|| violation("a rectangle with an unknown pixel format"))?;
            let length = usize::try_from(u32::from_le_bytes([
                bytes[at + 10],
                bytes[at + 11],
                bytes[at + 12],
                bytes[at + 13],
            ]))
            .map_err(|_| violation("a rectangle longer than this machine can address"))?;
            payload_total = payload_total
                .checked_add(length)
                .ok_or_else(|| violation("a framebuffer message whose payloads overflow"))?;
            descriptors.push((rect, encoding, format, length));
        }

        let expected = descriptors_end
            .checked_add(payload_total)
            .ok_or_else(|| violation("a framebuffer message whose payloads overflow"))?;
        if bytes.len() != expected {
            return Err(violation(
                "a framebuffer message whose payloads do not account for its length",
            ));
        }

        let mut cursor = descriptors_end;
        let mut rects = Vec::with_capacity(descriptors.len());
        for (rect, encoding, format, length) in descriptors {
            let payload = Bytes::copy_from_slice(&bytes[cursor..cursor + length]);
            cursor += length;
            rects.push(FrameRect {
                rect,
                encoding,
                format,
                payload,
            });
        }

        match message {
            MESSAGE_FRAMEBUFFER => Ok((
                session,
                Self::Framebuffer(FrameUpdate {
                    seq,
                    keyframe: flags & FLAG_KEYFRAME != 0,
                    rects,
                }),
            )),
            MESSAGE_CURSOR => {
                let [only] = <[FrameRect; 1]>::try_from(rects)
                    .map_err(|_| violation("a cursor message with other than one rectangle"))?;
                Ok((
                    session,
                    Self::Cursor(CursorUpdate {
                        seq,
                        hotspot_x: only.rect.x,
                        hotspot_y: only.rect.y,
                        width: only.rect.width,
                        height: only.rect.height,
                        format: only.format,
                        image: only.payload,
                    }),
                ))
            }
            _ => Err(violation("a framebuffer message of an unknown kind")),
        }
    }

    /// Delivers this message on a session's event stream.
    ///
    /// This exists so that no adapter reaches for [`EventSink::data`], which is
    /// the terminal path: it coalesces and re-chunks, and a framed message that
    /// has been re-chunked is a message the presenter cannot parse. `send`
    /// delivers the buffer whole, and flushes anything buffered before it so
    /// ordering with the control events is preserved.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::EventStreamClosed`] once the consumer is gone. A
    /// session that sees this should tear down: there is nobody left to render
    /// it.
    pub async fn emit(&self, events: &EventSink, session: SessionId) -> Result<(), ProtocolError> {
        events.send(SessionEvent::Data(self.encode(session))).await
    }
}

fn put_header(
    out: &mut BytesMut,
    session: SessionId,
    seq: u32,
    message: u8,
    flags: u8,
    count: u16,
) {
    out.put_u64_le(session.get());
    out.put_u32_le(seq);
    out.put_u8(message);
    out.put_u8(flags);
    out.put_u16_le(count);
}

fn put_descriptor(
    out: &mut BytesMut,
    rect: Rect,
    encoding: FrameEncoding,
    format: PixelFormat,
    length: usize,
) {
    out.put_u16_le(rect.x);
    out.put_u16_le(rect.y);
    out.put_u16_le(rect.width);
    out.put_u16_le(rect.height);
    out.put_u8(encoding.to_wire());
    out.put_u8(format.to_wire());
    // Saturating rather than truncating: a payload above 4 GiB is a defect in
    // the adapter, and a wrapped length would make the presenter read the next
    // rectangle's pixels as this one's. Saturating produces a message that
    // fails `decode`'s accounting check loudly instead.
    out.put_u32_le(u32::try_from(length).unwrap_or(u32::MAX));
}

/// Accumulates dirty rectangles and hands them over one batch per frame.
///
/// The framebuffer counterpart of [`crate::OutputCoalescer`], and it exists for
/// the same reason: a remote host produces updates faster than a display can
/// show them, and rendering a frame the user will never see costs latency on
/// the one they will (`docs/architecture/session-pipeline.md` §8).
///
/// **What it does not do is merge overlapping rectangles.** That is the obvious
/// optimisation and it is unsound here, because [`FrameEncoding::CopyRect`]
/// reads the surface: dropping a rectangle that a later copy-rect copies *from*
/// corrupts the display, and knowing which those are means tracking the surface
/// this type deliberately does not keep. The one supersession that is always
/// safe is the one it does apply — a rectangle covering the whole desktop with
/// real pixels makes everything before it unobservable, so the batch is cleared
/// and marked a keyframe. Finer merging belongs to the encoder, which knows
/// what it emitted.
#[derive(Debug)]
pub struct FrameCoalescer {
    interval: Duration,
    max_pending_bytes: usize,
    surface: Rect,
    pending: Vec<FrameRect>,
    pending_bytes: usize,
    keyframe: bool,
    opened_at: Option<Instant>,
    seq: u32,
}

impl FrameCoalescer {
    /// A coalescer for a desktop of `surface`, flushing at `interval` or once
    /// `max_pending_bytes` have accumulated, whichever comes first.
    ///
    /// The interval is clamped to at least a millisecond: a zero interval would
    /// make every rectangle its own message, which is the behaviour this type
    /// exists to prevent.
    #[must_use]
    pub fn new(surface: Rect, interval: Duration, max_pending_bytes: usize) -> Self {
        Self {
            interval: interval.max(Duration::from_millis(1)),
            max_pending_bytes: max_pending_bytes.max(FRAME_RECT_BYTES),
            surface,
            pending: Vec::new(),
            pending_bytes: 0,
            keyframe: false,
            opened_at: None,
            seq: 0,
        }
    }

    /// A coalescer with the defaults from this module and the frame interval
    /// the terminal path already uses — one clock for both kinds of session,
    /// because a user with a shell and a desktop side by side should not see
    /// two different notions of "a frame".
    #[must_use]
    pub fn with_defaults(surface: Rect) -> Self {
        Self::new(surface, DEFAULT_FRAME_INTERVAL, DEFAULT_MAX_PENDING_BYTES)
    }

    /// The desktop size the coalescer is judging full-screen updates against.
    #[must_use]
    pub const fn surface(&self) -> Rect {
        self.surface
    }

    /// Records that the remote desktop changed size.
    ///
    /// Whatever was pending described the old surface and cannot be applied to
    /// the new one, so it is discarded. The adapter is expected to follow a
    /// resize with a full update from the server; nothing here can conjure one,
    /// and pretending otherwise by flagging the next batch a keyframe would be
    /// a claim this type cannot support.
    pub fn set_surface(&mut self, surface: Rect) {
        self.surface = surface;
        self.pending.clear();
        self.pending_bytes = 0;
        self.keyframe = false;
        self.opened_at = None;
    }

    /// Adds a rectangle to the batch being assembled.
    pub fn push(&mut self, rect: FrameRect, now: Instant) {
        // A full-surface rectangle of real pixels overwrites everything the
        // batch was going to draw, so the earlier rectangles are not merely
        // redundant — sending them costs bandwidth for pixels that are
        // immediately covered. Copy-rect is excluded because it *reads* the
        // surface those rectangles produce.
        if rect.encoding != FrameEncoding::CopyRect && rect.rect.contains(self.surface) {
            self.pending.clear();
            self.pending_bytes = 0;
            self.keyframe = true;
        }
        self.pending_bytes = self.pending_bytes.saturating_add(rect.encoded_len());
        self.pending.push(rect);
        if self.opened_at.is_none() {
            self.opened_at = Some(now);
        }
    }

    /// Whether anything is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Whether the batch should be sent now.
    #[must_use]
    pub fn is_due(&self, now: Instant) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        if self.pending_bytes >= self.max_pending_bytes {
            return true;
        }
        self.opened_at
            .is_some_and(|opened| now.duration_since(opened) >= self.interval)
    }

    /// How long until the batch is due, for the session loop's timer. `None`
    /// when nothing is pending, so an idle session arms no timer.
    #[must_use]
    pub fn time_to_deadline(&self, now: Instant) -> Option<Duration> {
        if self.pending.is_empty() {
            return None;
        }
        if self.pending_bytes >= self.max_pending_bytes {
            return Some(Duration::ZERO);
        }
        self.opened_at
            .map(|opened| self.interval.saturating_sub(now.duration_since(opened)))
    }

    /// Takes the batch, whether or not it is due. `None` if nothing is pending.
    ///
    /// The sequence number increases per batch taken, not per rectangle: it
    /// counts messages, which is what a presenter needs to spot a gap.
    pub fn take(&mut self) -> Option<FrameUpdate> {
        if self.pending.is_empty() {
            return None;
        }
        let update = FrameUpdate {
            seq: self.seq,
            keyframe: self.keyframe,
            rects: std::mem::take(&mut self.pending),
        };
        self.seq = self.seq.wrapping_add(1);
        self.pending_bytes = 0;
        self.keyframe = false;
        self.opened_at = None;
        Some(update)
    }

    /// Takes the batch if it is due.
    pub fn take_if_due(&mut self, now: Instant) -> Option<FrameUpdate> {
        if self.is_due(now) { self.take() } else { None }
    }

    /// The sequence number the next batch will carry.
    #[must_use]
    pub const fn next_seq(&self) -> u32 {
        self.seq
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

    fn pixels(rect: Rect) -> Bytes {
        Bytes::from(vec![
            0x7f;
            rect.raw_byte_len(PixelFormat::Bgrx8888).unwrap()
        ])
    }

    #[test]
    fn a_rectangle_reports_its_size_without_wrapping() {
        let full = Rect::surface(u16::MAX, u16::MAX);
        // 65535 squared does not fit in a u16, and a wrapped value here would
        // under-allocate the buffer the pixels are copied into.
        assert_eq!(full.pixels(), 4_294_836_225);
        assert_eq!(full.right(), 65_535);
        assert!(!full.is_empty());
        assert!(Rect::new(0, 0, 10, 0).is_empty());
    }

    #[test]
    fn containment_is_what_the_keyframe_rule_rests_on() {
        let surface = Rect::surface(1920, 1080);
        assert!(surface.contains(Rect::new(10, 10, 100, 100)));
        assert!(surface.contains(surface));
        assert!(!Rect::new(0, 0, 1919, 1080).contains(surface));
        // An empty rectangle encloses no pixels, so anything contains it.
        assert!(Rect::new(5, 5, 1, 1).contains(Rect::new(0, 0, 0, 0)));
    }

    #[test]
    fn a_framebuffer_update_survives_a_round_trip() {
        let session = SessionId::from_raw(7);
        let first = Rect::new(0, 0, 4, 4);
        let second = Rect::new(4, 0, 2, 2);
        let update = FrameUpdate {
            seq: 42,
            keyframe: true,
            rects: vec![
                FrameRect::raw(first, PixelFormat::Bgrx8888, pixels(first)),
                FrameRect::jpeg(second, Bytes::from_static(b"\xff\xd8\xff")),
                FrameRect::copy_rect(Rect::new(8, 8, 16, 16), 100, 200),
            ],
        };
        let message = FrameMessage::Framebuffer(update.clone());
        let encoded = message.encode(session);
        assert_eq!(encoded.len(), message.encoded_len());

        let (decoded_session, decoded) = FrameMessage::decode(&encoded).unwrap();
        assert_eq!(decoded_session, session);
        assert_eq!(decoded, FrameMessage::Framebuffer(update));

        let FrameMessage::Framebuffer(back) = decoded else {
            panic!("a framebuffer message must decode as one");
        };
        assert!(back.keyframe);
        assert_eq!(back.rects[2].copy_source(), Some((100, 200)));
        assert_eq!(back.rects[0].copy_source(), None);
    }

    #[test]
    fn a_cursor_survives_a_round_trip_and_can_hide_the_pointer() {
        let session = SessionId::from_raw(u64::MAX);
        let shape = CursorUpdate::new(
            3,
            2,
            1,
            2,
            2,
            PixelFormat::Rgba8888,
            Bytes::from(vec![0u8; 2 * 2 * 4]),
        );
        let (back_session, back) = {
            let encoded = FrameMessage::Cursor(shape.clone()).encode(session);
            FrameMessage::decode(&encoded).unwrap()
        };
        // A u32 session field would have folded u64::MAX onto every other tab
        // whose low 32 bits matched.
        assert_eq!(back_session, session);
        assert_eq!(back, FrameMessage::Cursor(shape));

        let hidden = CursorUpdate::hidden(4);
        assert!(hidden.is_hidden());
        let encoded = FrameMessage::Cursor(hidden.clone()).encode(session);
        let (_, back) = FrameMessage::decode(&encoded).unwrap();
        assert_eq!(back, FrameMessage::Cursor(hidden));
    }

    #[test]
    fn the_keyframe_flag_is_carried_not_inferred() {
        let session = SessionId::from_raw(1);
        let surface = Rect::surface(8, 8);
        // Rectangles that tile the desktop, but as a delta: a presenter that
        // inferred "covers the screen, therefore self-sufficient" would be
        // wrong the moment one of them is a copy-rect.
        let delta = FrameUpdate {
            seq: 0,
            keyframe: false,
            rects: vec![FrameRect::copy_rect(surface, 0, 0)],
        };
        let encoded = FrameMessage::Framebuffer(delta).encode(session);
        assert_eq!(encoded[13] & FLAG_KEYFRAME, 0);
        let (_, decoded) = FrameMessage::decode(&encoded).unwrap();
        let FrameMessage::Framebuffer(back) = decoded else {
            panic!("a framebuffer message must decode as one");
        };
        assert!(!back.keyframe);
    }

    #[test]
    fn a_truncated_message_is_refused_rather_than_read_past() {
        // The recorder writes these to a file, so decode parses input that has
        // been on disk and may have been tampered with.
        let session = SessionId::from_raw(1);
        let rect = Rect::new(0, 0, 2, 2);
        let encoded = FrameMessage::Framebuffer(FrameUpdate {
            seq: 0,
            keyframe: false,
            rects: vec![FrameRect::raw(rect, PixelFormat::Bgrx8888, pixels(rect))],
        })
        .encode(session);

        for cut in [
            0,
            8,
            FRAME_HEADER_BYTES,
            FRAME_HEADER_BYTES + 4,
            encoded.len() - 1,
        ] {
            assert!(
                matches!(
                    FrameMessage::decode(&encoded[..cut]),
                    Err(ProtocolError::ProtocolViolation { .. })
                ),
                "a message cut at {cut} bytes must be refused"
            );
        }

        // Trailing bytes are malformed too: silently ignoring them is how a
        // parser and an encoder drift apart without anyone noticing.
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(matches!(
            FrameMessage::decode(&trailing),
            Err(ProtocolError::ProtocolViolation { .. })
        ));
    }

    #[test]
    fn a_declared_length_that_is_not_there_is_refused() {
        let session = SessionId::from_raw(1);
        let rect = Rect::new(0, 0, 2, 2);
        let mut encoded = FrameMessage::Framebuffer(FrameUpdate {
            seq: 0,
            keyframe: false,
            rects: vec![FrameRect::raw(rect, PixelFormat::Bgrx8888, pixels(rect))],
        })
        .encode(session)
        .to_vec();

        // Claim a gigabyte of pixels in a sixteen-pixel message. The check must
        // be against what is present, not against what the header asserts.
        let length_at = FRAME_HEADER_BYTES + 10;
        encoded[length_at..length_at + 4].copy_from_slice(&1_000_000_000u32.to_le_bytes());
        assert!(matches!(
            FrameMessage::decode(&encoded),
            Err(ProtocolError::ProtocolViolation { .. })
        ));
    }

    #[test]
    fn an_unknown_encoding_or_format_is_refused() {
        let session = SessionId::from_raw(1);
        let rect = Rect::new(0, 0, 1, 1);
        let base = FrameMessage::Framebuffer(FrameUpdate {
            seq: 0,
            keyframe: false,
            rects: vec![FrameRect::raw(rect, PixelFormat::Bgrx8888, pixels(rect))],
        })
        .encode(session)
        .to_vec();

        for (offset, label) in [(8usize, "encoding"), (9, "pixel format")] {
            let mut broken = base.clone();
            broken[FRAME_HEADER_BYTES + offset] = 0xff;
            assert!(
                matches!(
                    FrameMessage::decode(&broken),
                    Err(ProtocolError::ProtocolViolation { .. })
                ),
                "an unknown {label} must be refused"
            );
        }

        let mut broken = base;
        broken[12] = 0xff;
        assert!(matches!(
            FrameMessage::decode(&broken),
            Err(ProtocolError::ProtocolViolation { .. })
        ));
    }

    #[test]
    fn a_full_surface_repaint_supersedes_the_batch_and_becomes_a_keyframe() {
        let surface = Rect::surface(16, 16);
        let mut coalescer = FrameCoalescer::with_defaults(surface);
        let now = Instant::now();

        let small = Rect::new(0, 0, 2, 2);
        coalescer.push(
            FrameRect::raw(small, PixelFormat::Bgrx8888, pixels(small)),
            now,
        );
        coalescer.push(
            FrameRect::raw(small, PixelFormat::Bgrx8888, pixels(small)),
            now,
        );
        coalescer.push(
            FrameRect::raw(surface, PixelFormat::Bgrx8888, pixels(surface)),
            now,
        );

        let update = coalescer.take().unwrap();
        assert_eq!(
            update.rects.len(),
            1,
            "the repaint covers the two before it"
        );
        assert!(update.keyframe);
        assert_eq!(update.seq, 0);
        assert!(coalescer.is_empty());
        assert_eq!(coalescer.next_seq(), 1);
    }

    #[test]
    fn a_full_surface_copy_rect_never_supersedes_anything() {
        // A copy-rect reads the surface the earlier rectangles wrote. Dropping
        // them would copy stale pixels over the whole desktop.
        let surface = Rect::surface(16, 16);
        let mut coalescer = FrameCoalescer::with_defaults(surface);
        let now = Instant::now();

        let small = Rect::new(0, 0, 2, 2);
        coalescer.push(
            FrameRect::raw(small, PixelFormat::Bgrx8888, pixels(small)),
            now,
        );
        coalescer.push(FrameRect::copy_rect(surface, 0, 0), now);

        let update = coalescer.take().unwrap();
        assert_eq!(update.rects.len(), 2);
        assert!(!update.keyframe);
    }

    #[test]
    fn a_batch_is_due_on_the_interval_or_on_the_byte_ceiling() {
        let surface = Rect::surface(64, 64);
        let mut coalescer = FrameCoalescer::new(surface, Duration::from_millis(16), 1024);
        let start = Instant::now();
        assert!(!coalescer.is_due(start));
        assert!(coalescer.time_to_deadline(start).is_none());

        let small = Rect::new(0, 0, 2, 2);
        coalescer.push(
            FrameRect::raw(small, PixelFormat::Bgrx8888, pixels(small)),
            start,
        );
        assert!(!coalescer.is_due(start));
        assert_eq!(
            coalescer.time_to_deadline(start),
            Some(Duration::from_millis(16))
        );
        assert!(coalescer.is_due(start + Duration::from_millis(16)));
        assert!(coalescer.take_if_due(start).is_none());

        // The ceiling short-circuits the timer: a big update should not wait.
        let big = Rect::new(0, 0, 32, 32);
        coalescer.push(
            FrameRect::raw(big, PixelFormat::Bgrx8888, pixels(big)),
            start,
        );
        assert!(coalescer.is_due(start));
        assert_eq!(coalescer.time_to_deadline(start), Some(Duration::ZERO));
        assert!(coalescer.take_if_due(start).is_some());
    }

    #[test]
    fn a_resize_discards_a_batch_that_described_the_old_desktop() {
        let mut coalescer = FrameCoalescer::with_defaults(Rect::surface(16, 16));
        let now = Instant::now();
        let small = Rect::new(0, 0, 2, 2);
        coalescer.push(
            FrameRect::raw(small, PixelFormat::Bgrx8888, pixels(small)),
            now,
        );
        coalescer.set_surface(Rect::surface(32, 32));
        assert!(coalescer.is_empty());
        assert_eq!(coalescer.surface(), Rect::surface(32, 32));
        assert!(coalescer.take().is_none());
    }

    #[tokio::test]
    async fn a_frame_leaves_through_the_session_bus_whole() {
        // The trap this guards: `EventSink::data` coalesces, so two frames
        // written through it would arrive as one buffer split at an arbitrary
        // byte. `emit` uses `send`, which delivers the message intact.
        let (sink, mut rx) = crate::event::event_channel(8);
        let session = SessionId::from_raw(9);
        let rect = Rect::new(0, 0, 2, 2);

        for seq in 0..2u32 {
            FrameMessage::Framebuffer(FrameUpdate {
                seq,
                keyframe: seq == 0,
                rects: vec![FrameRect::raw(rect, PixelFormat::Bgrx8888, pixels(rect))],
            })
            .emit(&sink, session)
            .await
            .unwrap();
        }

        for seq in 0..2u32 {
            let Some(SessionEvent::Data(frame)) = rx.recv().await else {
                panic!("each frame must arrive as its own data event");
            };
            let (back_session, decoded) = FrameMessage::decode(&frame).unwrap();
            assert_eq!(back_session, session);
            assert_eq!(decoded.seq(), seq);
        }
    }
}
