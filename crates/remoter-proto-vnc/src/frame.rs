//! The boundary where decoded rectangles become the shared frame vocabulary —
//! and where they are checked.
//!
//! # This is the crate's hostile-input surface
//!
//! Everything above this line is `vnc-rs`: it reads the socket, runs the ZRLE
//! and Tight decoders, and hands back a `VncEvent`. Everything below it is
//! [`remoter_proto::framebuffer`], which a presenter turns into pixels on
//! screen. The events crossing between the two carry rectangle coordinates and
//! buffer lengths that came from the far end, and the far end is the machine
//! `docs/security/threat-model.md` §T4 assumes is already compromised.
//!
//! So nothing here trusts a `VncEvent`. Every rectangle is checked against the
//! framebuffer size the server declared in `ServerInit` (RFC 6143 §7.3.2), and
//! every payload length is checked against the rectangle it claims to fill.
//! Both checks matter for the same reason: the presenter indexes a surface with
//! these numbers, and a rectangle that runs off the edge of it — or a buffer
//! shorter than the rectangle it describes — is how a malformed update becomes
//! a read out of bounds in whatever renders it.
//!
//! The checks are arithmetic on widened integers, never on `u16`, because
//! `x + width` for two `u16`s is exactly the sum that wraps to something small
//! and inside the surface. [`remoter_proto::Rect::right`] and `bottom` widen to
//! `u32` for this reason and are used rather than reimplemented.
//!
//! # Two pixel formats, and why the cursor has a different one
//!
//! The session asks the server for `PixelFormat::bgra()` (RFC 6143 §7.5.1
//! `SetPixelFormat`), which puts a pixel on the wire as `[blue, green, red,
//! padding]`. That is [`remoter_proto::PixelFormat::Bgrx8888`] exactly, whose
//! documentation is emphatic that the fourth byte is **not** alpha.
//!
//! A cursor is the exception. RFC 6143 §7.8.1 carries a bitmask beside the
//! pixels, and `vnc-rs` folds that mask into the fourth byte — so a cursor
//! image really does have alpha, and it has to be
//! [`remoter_proto::PixelFormat::Rgba8888`] to say so. That means swapping the
//! red and blue bytes of every cursor pixel. Skipping the swap gives every
//! pointer the wrong hue, which is subtle enough to ship.

use bytes::Bytes;
use remoter_proto::{FrameEncoding, FrameRect, PixelFormat, ProtocolError, Rect};
use vnc::{Rect as VncRect, VncEvent};

use crate::error::{classify_decoder_failure, violation};

/// Bytes per pixel in every format this adapter negotiates.
///
/// Four, and only four: `SetPixelFormat` asks for 32 bits per pixel, and both
/// contract formats are 32-bit. A server that ignored the request would be
/// caught by the length check rather than by a different arithmetic path.
pub const BYTES_PER_PIXEL: usize = 4;

/// The largest cursor image this adapter will accept, per side.
///
/// RFC 6143 §7.8.1 puts no ceiling on the cursor's dimensions, so a hostile
/// server may declare one the size of a desktop and make the client allocate
/// for it. 256 pixels is four times the largest cursor any platform actually
/// uses and the allocation it permits is a quarter of a megabyte.
pub const MAX_CURSOR_SIDE: u16 = 256;

/// The largest single compressed rectangle payload this adapter will forward.
///
/// A Tight JPEG rectangle carries its own length (up to three 7-bit
/// continuation bytes, so just under 4 MiB) and nothing checks it against the
/// rectangle's size, because a JPEG's compressed size has no fixed relationship
/// to its pixel count. This is the ceiling that stops one rectangle from
/// filling the event channel on its own.
pub const MAX_COMPRESSED_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// One `VncEvent`, checked and translated.
///
/// `Debug` is derived only on the variants that carry no pixels and no text;
/// the two that do carry their own redaction — [`FrameRect`] and
/// `remoter_proto::CursorUpdate` both have hand-written redacting `Debug` implementations in
/// `remoter-proto`, and the clipboard variant is redacted here.
#[derive(Clone, PartialEq, Eq)]
pub enum Decoded {
    /// A rectangle to draw.
    Rect(FrameRect),
    /// A cursor shape the server set.
    Cursor {
        /// Where the pointer's hot spot sits inside the image.
        hotspot_x: u16,
        /// The hot spot's vertical offset.
        hotspot_y: u16,
        /// The image's width; zero hides the pointer.
        width: u16,
        /// The image's height; zero hides the pointer.
        height: u16,
        /// `width * height` pixels, RGBA, straight alpha.
        image: Bytes,
    },
    /// The remote desktop is now this size.
    Resolution {
        /// New width, in remote pixels.
        width: u16,
        /// New height.
        height: u16,
    },
    /// The remote has text on its clipboard (RFC 6143 §7.6.4).
    ClipboardText(String),
    /// RFC 6143 §7.6.3. There is no bell in a WebView; it becomes a warning the
    /// interface may render however it likes.
    Bell,
    /// Nothing to do — an empty rectangle, or an event with no contract
    /// equivalent.
    Nothing,
}

impl std::fmt::Debug for Decoded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rect(rect) => write!(f, "Rect({rect:?})"),
            Self::Cursor {
                hotspot_x,
                hotspot_y,
                width,
                height,
                image,
            } => write!(
                f,
                "Cursor {{ hotspot: ({hotspot_x}, {hotspot_y}), size: ({width}, {height}), image: <redacted, {} bytes> }}",
                image.len()
            ),
            Self::Resolution { width, height } => {
                write!(f, "Resolution {{ width: {width}, height: {height} }}")
            }
            // The single most common thing on a system administrator's
            // clipboard is a password they just copied out of a password
            // manager, and it arrives here from the remote machine.
            Self::ClipboardText(text) => {
                write!(
                    f,
                    "ClipboardText(<redacted, {} chars>)",
                    text.chars().count()
                )
            }
            Self::Bell => f.write_str("Bell"),
            Self::Nothing => f.write_str("Nothing"),
        }
    }
}

/// Checks decoded rectangles against the framebuffer the server declared.
///
/// Holds one piece of state — the surface size — because every check needs it
/// and because RFC 6143 §7.8.2 lets the server change it mid-session.
#[derive(Debug, Clone, Copy)]
pub struct FrameTranslator {
    surface: Rect,
}

impl FrameTranslator {
    /// A translator for a desktop whose size is not yet known.
    ///
    /// Nothing can be validated until `ServerInit` (RFC 6143 §7.3.2) has said
    /// how big the framebuffer is, so a rectangle arriving before then is
    /// rejected rather than passed through on the assumption that it fits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            surface: Rect::new(0, 0, 0, 0),
        }
    }

    /// A translator for a desktop of a known size.
    #[must_use]
    pub const fn with_surface(width: u16, height: u16) -> Self {
        Self {
            surface: Rect::surface(width, height),
        }
    }

    /// The desktop size rectangles are being checked against.
    #[must_use]
    pub const fn surface(&self) -> Rect {
        self.surface
    }

    /// Records a new desktop size.
    pub fn set_surface(&mut self, width: u16, height: u16) {
        self.surface = Rect::surface(width, height);
    }

    /// Checks and translates one event.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ProtocolViolation`] for a rectangle outside the
    /// framebuffer, a payload that does not match the rectangle it fills, a
    /// cursor larger than [`MAX_CURSOR_SIDE`], or a rectangle arriving before
    /// the framebuffer size is known.
    pub fn translate(&mut self, event: VncEvent) -> Result<Decoded, ProtocolError> {
        match event {
            VncEvent::SetResolution(screen) => {
                // A zero-sized desktop is not a desktop. Accepting one would
                // leave every later rectangle failing its bounds check with a
                // message that blames the rectangle rather than the resize.
                if screen.width == 0 || screen.height == 0 {
                    return Err(violation(
                        "the server declared a framebuffer with no pixels",
                    ));
                }
                self.set_surface(screen.width, screen.height);
                Ok(Decoded::Resolution {
                    width: screen.width,
                    height: screen.height,
                })
            }

            VncEvent::RawImage(rect, data) => self.raw(rect, data),
            VncEvent::JpegImage(rect, data) => self.jpeg(rect, data),
            VncEvent::Copy(destination, source) => self.copy(destination, source),
            VncEvent::SetCursor(rect, image) => self.cursor(rect, image),

            VncEvent::Text(text) => Ok(Decoded::ClipboardText(text)),
            VncEvent::Bell => Ok(Decoded::Bell),

            // The connector always calls `set_pixel_format`, so the server was
            // told what to send and this event should never arrive. If it does,
            // the assumption every length check below rests on — 32 bits per
            // pixel — is no longer safe, and continuing would mean validating
            // against the wrong arithmetic.
            VncEvent::SetPixelFormat(_) => Err(violation(
                "the server changed the pixel format after being told which one to use",
            )),

            // The engine reports decoder failures as an event rather than as a
            // `Result`. A match that only handled the drawing variants would
            // treat a failed session as an idle one.
            VncEvent::Error(_) => Err(classify_decoder_failure()),

            // `VncEvent` is `#[non_exhaustive]`. A variant added upstream is
            // ignored rather than guessed at, and saying so out loud is the
            // difference between a deliberate omission and a silent one.
            _ => Ok(Decoded::Nothing),
        }
    }

    /// RFC 6143 §7.7.1: `width * height * bytesPerPixel` bytes, row-major.
    fn raw(&self, rect: VncRect, data: Vec<u8>) -> Result<Decoded, ProtocolError> {
        let rect = self.checked(rect)?;
        if rect.is_empty() {
            // A zero-sized rectangle is legal and carries nothing. Forwarding
            // it would put a descriptor with no payload in every frame a
            // chatty server sends.
            return Ok(Decoded::Nothing);
        }
        let expected = rect
            .raw_byte_len(PixelFormat::Bgrx8888)
            .ok_or_else(|| violation("a rectangle larger than this machine can address"))?;
        if data.len() != expected {
            // Both directions are a violation. Short is the dangerous one — the
            // presenter would read past the buffer — but long means the decoder
            // and the rectangle header disagree, and a stream where those two
            // disagree is a stream that has desynchronised.
            return Err(violation(
                "a raw rectangle whose pixels do not fill the rectangle it declares",
            ));
        }
        Ok(Decoded::Rect(FrameRect::raw(
            rect,
            PixelFormat::Bgrx8888,
            Bytes::from(data),
        )))
    }

    /// A Tight JPEG rectangle. The payload is a complete JPEG image and carries
    /// its own colour space, so the declared pixel format does not apply and
    /// its length has no fixed relationship to the rectangle's pixel count.
    fn jpeg(&self, rect: VncRect, data: Vec<u8>) -> Result<Decoded, ProtocolError> {
        let rect = self.checked(rect)?;
        if rect.is_empty() || data.is_empty() {
            return Ok(Decoded::Nothing);
        }
        if data.len() > MAX_COMPRESSED_PAYLOAD_BYTES {
            return Err(violation(
                "a compressed rectangle larger than this build accepts",
            ));
        }
        Ok(Decoded::Rect(FrameRect::jpeg(rect, Bytes::from(data))))
    }

    /// RFC 6143 §7.7.2: the rectangle is a copy of another part of the surface
    /// the presenter already holds.
    ///
    /// **Both** rectangles are checked. The destination is the obvious one; the
    /// source is the one that matters, because the presenter reads from it, and
    /// a source rectangle outside the surface is a read out of bounds in the
    /// renderer with no pixels on the wire to give it away.
    fn copy(&self, destination: VncRect, source: VncRect) -> Result<Decoded, ProtocolError> {
        let destination = self.checked(destination)?;
        // `vnc-rs` builds the source rectangle by copying the destination and
        // overwriting its origin, so the two always share a size. Checking the
        // source as its own rectangle rather than trusting that is what makes
        // this independent of the library's internals.
        let source = self.checked(source)?;
        if destination.width != source.width || destination.height != source.height {
            return Err(violation(
                "a copy rectangle whose source and destination are different sizes",
            ));
        }
        if destination.is_empty() {
            return Ok(Decoded::Nothing);
        }
        Ok(Decoded::Rect(FrameRect::copy_rect(
            destination,
            source.x,
            source.y,
        )))
    }

    /// RFC 6143 §7.8.1. The rectangle's `x` and `y` are the hot spot, not a
    /// position on the desktop, so they are **not** bounds-checked against the
    /// surface — a hot spot is an offset inside the cursor image.
    fn cursor(&self, rect: VncRect, image: Vec<u8>) -> Result<Decoded, ProtocolError> {
        if rect.width == 0 || rect.height == 0 {
            // §7.8.1 permits a zero-sized cursor, and it means "draw no
            // pointer" — a full-screen video player, or a game that draws its
            // own.
            return Ok(Decoded::Cursor {
                hotspot_x: 0,
                hotspot_y: 0,
                width: 0,
                height: 0,
                image: Bytes::new(),
            });
        }
        if rect.width > MAX_CURSOR_SIDE || rect.height > MAX_CURSOR_SIDE {
            return Err(violation("a cursor image larger than this build accepts"));
        }
        // A hot spot outside the image is meaningless and would place the
        // pointer's active point somewhere the image does not cover.
        if rect.x >= rect.width || rect.y >= rect.height {
            return Err(violation(
                "a cursor whose hot spot is outside its own image",
            ));
        }
        let expected = usize::from(rect.width) * usize::from(rect.height) * BYTES_PER_PIXEL;
        if image.len() != expected {
            return Err(violation(
                "a cursor image whose pixels do not fill the size it declares",
            ));
        }
        Ok(Decoded::Cursor {
            hotspot_x: rect.x,
            hotspot_y: rect.y,
            width: rect.width,
            height: rect.height,
            image: bgra_to_rgba(image),
        })
    }

    /// Converts a `vnc-rs` rectangle and checks it lies inside the framebuffer.
    fn checked(&self, rect: VncRect) -> Result<Rect, ProtocolError> {
        if self.surface.is_empty() {
            return Err(violation(
                "a framebuffer rectangle before the server said how big the framebuffer is",
            ));
        }
        let rect = Rect::new(rect.x, rect.y, rect.width, rect.height);
        // `right` and `bottom` widen to `u32` before adding. On `u16` the sum
        // wraps, and a rectangle at x = 65 000 of width 1 000 would appear to
        // end at 464 — comfortably inside any surface.
        if rect.right() > u32::from(self.surface.width)
            || rect.bottom() > u32::from(self.surface.height)
        {
            return Err(violation(
                "a framebuffer rectangle that runs outside the framebuffer",
            ));
        }
        Ok(rect)
    }
}

impl Default for FrameTranslator {
    fn default() -> Self {
        Self::new()
    }
}

/// Swaps the red and blue bytes of every pixel, in place.
///
/// `SetPixelFormat` asked for `[blue, green, red, x]`; a cursor image needs
/// `[red, green, blue, alpha]` because the fourth byte really is alpha there
/// (RFC 6143 §7.8.1's bitmask, folded in by the decoder). The green byte and
/// the alpha byte stay where they are, so the swap is two byte moves per pixel
/// and no allocation beyond the one the buffer already is.
fn bgra_to_rgba(mut image: Vec<u8>) -> Bytes {
    for pixel in image.chunks_exact_mut(BYTES_PER_PIXEL) {
        pixel.swap(0, 2);
    }
    Bytes::from(image)
}

/// Whether a decoded rectangle is one the coalescer may treat as a keyframe.
///
/// A rectangle covering the whole surface with real pixels makes everything
/// before it unobservable. A copy-rect does not, however large it is: it
/// *reads* the surface those earlier rectangles produced.
/// [`remoter_proto::FrameCoalescer::push`] applies the same rule; this exists
/// so the session can log the distinction without duplicating the reasoning.
#[must_use]
pub fn is_full_surface_repaint(rect: &FrameRect, surface: Rect) -> bool {
    rect.encoding != FrameEncoding::CopyRect && rect.rect.contains(surface)
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
    use vnc::Screen;

    fn vnc_rect(x: u16, y: u16, width: u16, height: u16) -> VncRect {
        VncRect {
            x,
            y,
            width,
            height,
        }
    }

    fn translator() -> FrameTranslator {
        FrameTranslator::with_surface(800, 600)
    }

    #[test]
    fn a_rectangle_before_the_framebuffer_size_is_known_is_refused() {
        // `ServerInit` (RFC 6143 §7.3.2) is what says how big the surface is.
        // Before it there is nothing to check a rectangle against, and passing
        // one through unchecked is the whole class of bug this module exists
        // to prevent.
        let mut translator = FrameTranslator::new();
        let error = translator
            .translate(VncEvent::RawImage(vnc_rect(0, 0, 1, 1), vec![0; 4]))
            .expect_err("no surface, no checks");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[test]
    fn a_well_formed_raw_rectangle_becomes_a_frame_rectangle() {
        let mut translator = translator();
        let decoded = translator
            .translate(VncEvent::RawImage(vnc_rect(10, 20, 2, 2), vec![7; 16]))
            .unwrap();
        let Decoded::Rect(rect) = decoded else {
            panic!("a raw rectangle is a frame rectangle");
        };
        assert_eq!(rect.rect, Rect::new(10, 20, 2, 2));
        assert_eq!(rect.encoding, FrameEncoding::Raw);
        assert_eq!(rect.format, PixelFormat::Bgrx8888);
        assert_eq!(rect.payload().len(), 16);
    }

    #[test]
    fn a_raw_rectangle_with_too_few_pixels_is_refused() {
        // This is the one that matters: the presenter indexes the buffer by the
        // rectangle's dimensions, so a short buffer is a read out of bounds in
        // whatever renders it.
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::RawImage(vnc_rect(0, 0, 4, 4), vec![0; 63]))
            .expect_err("64 bytes were promised");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));

        // And too many is refused too: a decoder and a rectangle header that
        // disagree mean the stream has desynchronised.
        let error = translator
            .translate(VncEvent::RawImage(vnc_rect(0, 0, 4, 4), vec![0; 65]))
            .expect_err("65 bytes is not 64 either");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[test]
    fn a_rectangle_outside_the_framebuffer_is_refused() {
        let mut translator = translator();
        for (x, y, width, height) in [(800, 0, 1, 1), (0, 600, 1, 1), (790, 0, 20, 1)] {
            let pixels = usize::from(width) * usize::from(height) * BYTES_PER_PIXEL;
            let error = translator
                .translate(VncEvent::RawImage(
                    vnc_rect(x, y, width, height),
                    vec![0; pixels],
                ))
                .expect_err("outside an 800x600 surface");
            assert!(
                matches!(error, ProtocolError::ProtocolViolation { .. }),
                "{x},{y} {width}x{height}"
            );
        }
        // The exact edge is inside.
        let decoded = translator
            .translate(VncEvent::RawImage(vnc_rect(799, 599, 1, 1), vec![0; 4]))
            .unwrap();
        assert!(matches!(decoded, Decoded::Rect(_)));
    }

    #[test]
    fn a_rectangle_whose_bounds_wrap_a_u16_is_refused() {
        // x + width for two u16 values is exactly the sum that wraps to
        // something small and apparently inside the surface. 65 000 + 1 000 is
        // 464 in 16 bits.
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::RawImage(
                vnc_rect(65_000, 0, 1_000, 1),
                vec![0; 4_000],
            ))
            .expect_err("the sum must be computed widened");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[test]
    fn a_copy_rectangles_source_is_checked_as_well_as_its_destination() {
        // The source is the dangerous one: the presenter *reads* from it, and
        // there are no pixels on the wire to give a bad one away.
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::Copy(
                vnc_rect(0, 0, 10, 10),
                vnc_rect(795, 0, 10, 10),
            ))
            .expect_err("the source runs off the right edge");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));

        let decoded = translator
            .translate(VncEvent::Copy(
                vnc_rect(0, 0, 10, 10),
                vnc_rect(100, 50, 10, 10),
            ))
            .unwrap();
        let Decoded::Rect(rect) = decoded else {
            panic!("a copy is a frame rectangle with no pixels");
        };
        assert_eq!(rect.encoding, FrameEncoding::CopyRect);
        assert_eq!(rect.copy_source(), Some((100, 50)));
        assert_eq!(rect.payload().len(), 4, "four bytes, and no pixels");
    }

    #[test]
    fn a_copy_whose_two_rectangles_are_different_sizes_is_refused() {
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::Copy(
                vnc_rect(0, 0, 10, 10),
                vnc_rect(100, 50, 20, 10),
            ))
            .expect_err("a copy cannot change a rectangle's size");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[test]
    fn an_empty_rectangle_carries_nothing_and_is_dropped() {
        let mut translator = translator();
        assert!(matches!(
            translator
                .translate(VncEvent::RawImage(vnc_rect(5, 5, 0, 10), Vec::new()))
                .unwrap(),
            Decoded::Nothing
        ));
        assert!(matches!(
            translator
                .translate(VncEvent::Copy(vnc_rect(0, 0, 0, 0), vnc_rect(0, 0, 0, 0)))
                .unwrap(),
            Decoded::Nothing
        ));
    }

    #[test]
    fn a_cursor_is_converted_to_straight_alpha_rgba() {
        // The session asked for BGRX; a cursor's fourth byte really is alpha
        // (RFC 6143 §7.8.1's bitmask), so red and blue have to change places
        // or every pointer is the wrong hue.
        let mut translator = translator();
        let bgra = vec![0x11, 0x22, 0x33, 0xff];
        let decoded = translator
            .translate(VncEvent::SetCursor(vnc_rect(0, 0, 1, 1), bgra))
            .unwrap();
        let Decoded::Cursor {
            width,
            height,
            image,
            ..
        } = decoded
        else {
            panic!("a cursor event is a cursor");
        };
        assert_eq!((width, height), (1, 1));
        assert_eq!(image.as_ref(), &[0x33, 0x22, 0x11, 0xff]);
    }

    #[test]
    fn a_zero_sized_cursor_hides_the_pointer_rather_than_failing() {
        let mut translator = translator();
        let decoded = translator
            .translate(VncEvent::SetCursor(vnc_rect(0, 0, 0, 0), Vec::new()))
            .unwrap();
        assert!(matches!(
            decoded,
            Decoded::Cursor {
                width: 0,
                height: 0,
                ..
            }
        ));
    }

    #[test]
    fn an_enormous_cursor_is_refused_before_it_is_allocated_for() {
        // §7.8.1 puts no ceiling on the dimensions, so a hostile server can
        // declare a cursor the size of a desktop.
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::SetCursor(
                vnc_rect(0, 0, MAX_CURSOR_SIDE + 1, 1),
                Vec::new(),
            ))
            .expect_err("larger than this build accepts");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[test]
    fn a_cursor_whose_pixels_do_not_fill_it_is_refused() {
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::SetCursor(vnc_rect(0, 0, 4, 4), vec![0; 60]))
            .expect_err("64 bytes were promised");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[test]
    fn a_hot_spot_outside_the_cursor_image_is_refused() {
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::SetCursor(vnc_rect(16, 0, 16, 16), vec![0; 1024]))
            .expect_err("a hot spot is an offset inside the image");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[test]
    fn a_resize_moves_the_bounds_every_later_rectangle_is_checked_against() {
        // RFC 6143 §7.8.2 lets this happen mid-session, and a translator that
        // kept the old size would reject every rectangle in the new one.
        let mut translator = FrameTranslator::with_surface(100, 100);
        assert!(
            translator
                .translate(VncEvent::RawImage(vnc_rect(0, 0, 200, 1), vec![0; 800]))
                .is_err()
        );
        let decoded = translator
            .translate(VncEvent::SetResolution(Screen::from((640_u16, 480_u16))))
            .unwrap();
        assert!(matches!(
            decoded,
            Decoded::Resolution {
                width: 640,
                height: 480
            }
        ));
        assert!(
            translator
                .translate(VncEvent::RawImage(vnc_rect(0, 0, 200, 1), vec![0; 800]))
                .is_ok()
        );
        assert_eq!(translator.surface(), Rect::surface(640, 480));
    }

    #[test]
    fn a_desktop_with_no_pixels_is_refused_at_the_resize_rather_than_later() {
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::SetResolution(Screen::from((0_u16, 600_u16))))
            .expect_err("a zero-sized desktop is not a desktop");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[test]
    fn a_pixel_format_change_after_the_request_is_refused() {
        // Every length check here assumes 32 bits per pixel because
        // `SetPixelFormat` asked for it. If the server changes it, continuing
        // means validating against the wrong arithmetic.
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::SetPixelFormat(vnc::PixelFormat::rgba()))
            .expect_err("the server was told which format to use");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[test]
    fn a_decoder_failure_arrives_as_an_event_and_is_not_ignored() {
        // The engine reports these as events rather than as a `Result`, so a
        // match on the drawing variants alone treats a failed session as idle.
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::Error("leftover zlib byte data".to_owned()))
            .expect_err("a decoder failure is a failure");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
        assert!(
            !error.to_string().contains("zlib"),
            "the library's text is not forwarded"
        );
    }

    #[test]
    fn an_oversized_compressed_rectangle_is_refused() {
        let mut translator = translator();
        let error = translator
            .translate(VncEvent::JpegImage(
                vnc_rect(0, 0, 10, 10),
                vec![0; MAX_COMPRESSED_PAYLOAD_BYTES + 1],
            ))
            .expect_err("larger than this build forwards");
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    #[test]
    fn a_jpeg_rectangle_keeps_its_own_colour_space() {
        let mut translator = translator();
        let decoded = translator
            .translate(VncEvent::JpegImage(vnc_rect(4, 4, 8, 8), vec![0xff; 32]))
            .unwrap();
        let Decoded::Rect(rect) = decoded else {
            panic!("a JPEG rectangle is a frame rectangle");
        };
        assert_eq!(rect.encoding, FrameEncoding::Jpeg);
        assert_eq!(
            rect.payload().len(),
            32,
            "compressed length has no relationship to the pixel count"
        );
    }

    #[test]
    fn clipboard_text_from_the_remote_is_never_debug_printed() {
        let mut translator = translator();
        let decoded = translator
            .translate(VncEvent::Text("s3cr3t".to_owned()))
            .unwrap();
        let rendered = format!("{decoded:?}");
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(rendered.contains("<redacted, 6 chars>"), "{rendered}");
    }

    #[test]
    fn a_full_surface_repaint_is_told_apart_from_a_full_surface_copy() {
        let surface = Rect::surface(64, 64);
        let repaint = FrameRect::raw(surface, PixelFormat::Bgrx8888, Bytes::from(vec![0; 16_384]));
        assert!(is_full_surface_repaint(&repaint, surface));

        // A copy-rect reads the surface those earlier rectangles produced, so
        // it supersedes nothing however large it is.
        let scroll = FrameRect::copy_rect(surface, 0, 0);
        assert!(!is_full_surface_repaint(&scroll, surface));
    }
}
