//! Turning decoded pixels into the shared framebuffer format.
//!
//! IronRDP decodes every codec a modern Windows Server negotiates — RemoteFX
//! (MS-RDPRFX), the surface-bits path of MS-RDPBCGR §2.2.9.2, the legacy
//! interleaved bitmap updates of §2.2.9.1.1.3.1.2, and the pointer updates of
//! §2.2.9.1.1.4 — into one `DecodedImage`. That is deliberate on IronRDP's
//! part and useful here: the adapter never learns which codec produced a
//! rectangle, so a codec added upstream needs no change in this crate.
//!
//! What this module does is the other half: take the rectangles that changed
//! and put them on the wire in `remoter_proto::framebuffer`'s vocabulary, so
//! that RDP and VNC reach the presenter through one format and one event bus.
//!
//! # Pixel format
//!
//! `DecodedImage` is created as `BgrX32`, whose channel offsets are
//! `[r, g, b, a] = [2, 1, 0, 3]` — blue, green, red, then a padding byte. That
//! is byte-for-byte [`PixelFormat::Bgrx8888`], so a rectangle is copied out
//! and not converted. The fourth byte is **not** alpha, and a presenter that
//! treats it as one renders a transparent desktop.
//!
//! Cursors are the exception: they have a real mask, so they arrive as
//! [`PixelFormat::Rgba8888`] with straight (not premultiplied) alpha, which is
//! what IronRDP's `PointerBitmapTarget::Accelerated` produces.
//!
//! # Why the rows are repacked
//!
//! `DecodedImage::data_for_rect` returns a slice spanning whole scanlines,
//! padding included. The frame format says "row-major, top row first, no
//! padding between rows", so a narrow rectangle out of a wide desktop has to
//! be copied row by row. Sending the padded span instead would draw the
//! rectangle sheared — the classic symptom of exactly this mistake.

use std::time::Instant;

use bytes::{BufMut as _, Bytes, BytesMut};
use ironrdp::graphics::pointer::DecodedPointer;
use ironrdp::pdu::geometry::InclusiveRectangle;
use ironrdp::session::image::DecodedImage;
use remoter_proto::{
    CursorUpdate, FrameCoalescer, FrameEncoding, FrameMessage, FrameRect, FrameUpdate, PixelFormat,
    Rect,
};

/// Bytes in one pixel, in every format this module produces.
const BYTES_PER_PIXEL: usize = 4;

/// Bytes in one run of the run-length encoding: a `u32` count and a pixel.
const RUN_BYTES: usize = 4 + BYTES_PER_PIXEL;

/// Assembles frame messages from decoded rectangles.
///
/// # The sequence number
///
/// `remoter_proto::framebuffer` says framebuffer and cursor messages share one
/// counter — "one stream, one sequence" — because a presenter spots a dropped
/// frame by looking for a gap in it. [`FrameCoalescer`] keeps a counter of its
/// own and has no way to advance it for a cursor, so the counter lives here
/// and the coalescer's is overwritten on the way out. Two counters would make
/// every cursor change look like a dropped frame.
pub struct FrameEncoder {
    coalescer: FrameCoalescer,
    seq: u32,
}

impl core::fmt::Debug for FrameEncoder {
    /// Hand-written and redacting: whatever is pending is a picture of
    /// someone's screen, and the screen may have a password manager open on
    /// it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameEncoder")
            .field("surface", &self.coalescer.surface())
            .field("seq", &self.seq)
            .field("pending", &!self.coalescer.is_empty())
            .finish()
    }
}

impl FrameEncoder {
    /// An encoder for a desktop of `width` by `height` pixels.
    #[must_use]
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            coalescer: FrameCoalescer::with_defaults(Rect::surface(width, height)),
            seq: 0,
        }
    }

    /// The desktop size being encoded.
    #[must_use]
    pub const fn surface(&self) -> Rect {
        self.coalescer.surface()
    }

    /// Records that the remote desktop changed size.
    ///
    /// Anything pending described the old surface and is discarded with it.
    /// The server follows a resize with a full redraw, which is where the new
    /// surface's pixels come from.
    pub fn set_surface(&mut self, width: u16, height: u16) {
        self.coalescer.set_surface(Rect::surface(width, height));
    }

    /// Adds one changed rectangle.
    ///
    /// A rectangle that falls outside the image is dropped rather than
    /// clamped: it means this encoder and the decoder disagree about the
    /// desktop size, and a clamped rectangle would draw the wrong pixels in
    /// the wrong place instead of drawing nothing.
    pub fn push(&mut self, image: &DecodedImage, region: &InclusiveRectangle, now: Instant) {
        let Some((rect, payload)) = extract(image, region) else {
            tracing::debug!(
                left = region.left,
                top = region.top,
                right = region.right,
                bottom = region.bottom,
                "a graphics update fell outside the decoded image and was dropped"
            );
            return;
        };
        self.coalescer.push(encode_rect(rect, &payload), now);
    }

    /// The batch, if it is due.
    #[must_use]
    pub fn take_if_due(&mut self, now: Instant) -> Option<FrameMessage> {
        self.coalescer
            .take_if_due(now)
            .map(|update| self.stamp(update))
    }

    /// The batch, whether or not it is due.
    #[must_use]
    pub fn take(&mut self) -> Option<FrameMessage> {
        self.coalescer.take().map(|update| self.stamp(update))
    }

    /// How long until the batch is due, for the session loop's timer.
    #[must_use]
    pub fn time_to_deadline(&self, now: Instant) -> Option<core::time::Duration> {
        self.coalescer.time_to_deadline(now)
    }

    /// A self-sufficient update covering the whole desktop.
    ///
    /// Sent when a presenter attaches to a session that is already running and
    /// after a resize, because both leave the presenter with a surface it
    /// cannot derive from any number of deltas. The batch in flight is
    /// discarded: everything in it is about to be overwritten.
    ///
    /// Returns `None` if the image is not the size this encoder was told about,
    /// which would mean sending a keyframe that does not cover the surface.
    #[must_use]
    pub fn keyframe(&mut self, image: &DecodedImage) -> Option<FrameMessage> {
        let surface = self.coalescer.surface();
        if image.width() != surface.width || image.height() != surface.height {
            return None;
        }
        let whole = InclusiveRectangle {
            left: 0,
            top: 0,
            right: surface.width.saturating_sub(1),
            bottom: surface.height.saturating_sub(1),
        };
        let (rect, payload) = extract(image, &whole)?;
        // Discards whatever was pending: `FrameCoalescer::push` recognises a
        // full-surface rectangle of real pixels and clears the batch, which is
        // exactly the right behaviour here and the reason this goes through
        // `push` rather than building a `FrameUpdate` directly.
        self.coalescer
            .push(encode_rect(rect, &payload), Instant::now());
        self.take()
    }

    /// The cursor shape the server set.
    ///
    /// `bitmap_data` is RGBA with straight alpha, which is what
    /// `PointerBitmapTarget::Accelerated` produces and what
    /// [`PixelFormat::Rgba8888`] means. Returns `None` if the image is not the
    /// size the pointer claims, which would leave the presenter reading past
    /// the end of it.
    #[must_use]
    pub fn cursor(&mut self, pointer: &DecodedPointer) -> Option<FrameMessage> {
        let expected = usize::from(pointer.width)
            .checked_mul(usize::from(pointer.height))?
            .checked_mul(BYTES_PER_PIXEL)?;
        if pointer.bitmap_data.len() != expected {
            return None;
        }
        let seq = self.next_seq();
        Some(FrameMessage::Cursor(CursorUpdate::new(
            seq,
            pointer.hotspot_x,
            pointer.hotspot_y,
            pointer.width,
            pointer.height,
            PixelFormat::Rgba8888,
            Bytes::copy_from_slice(&pointer.bitmap_data),
        )))
    }

    /// The server asked for no pointer at all — a full-screen video player, or
    /// a game that draws its own.
    #[must_use]
    pub fn hide_cursor(&mut self) -> FrameMessage {
        let seq = self.next_seq();
        FrameMessage::Cursor(CursorUpdate::hidden(seq))
    }

    /// Stamps a batch with this encoder's sequence number.
    fn stamp(&mut self, update: FrameUpdate) -> FrameMessage {
        let seq = self.next_seq();
        FrameMessage::Framebuffer(FrameUpdate { seq, ..update })
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        seq
    }
}

/// Copies one rectangle out of `image`, repacked with no row padding.
///
/// `None` when the rectangle is empty or does not fit inside the image.
fn extract(image: &DecodedImage, region: &InclusiveRectangle) -> Option<(Rect, Vec<u8>)> {
    // Inclusive on both edges (MS-RDPBCGR §2.2.9.1.1.3.1.2.2 bounds work this
    // way, and so does IronRDP's `InclusiveRectangle`), so a one-pixel
    // rectangle has `left == right`.
    if region.right < region.left || region.bottom < region.top {
        return None;
    }
    if region.right >= image.width() || region.bottom >= image.height() {
        return None;
    }
    let width = region.right - region.left + 1;
    let height = region.bottom - region.top + 1;

    let stride = image.stride();
    let row_bytes = usize::from(width) * BYTES_PER_PIXEL;
    let data = image.data();
    let mut payload = Vec::with_capacity(row_bytes * usize::from(height));
    for row in 0..usize::from(height) {
        let start =
            (usize::from(region.top) + row) * stride + usize::from(region.left) * BYTES_PER_PIXEL;
        // Checked rather than assumed: `stride` comes from the image's own
        // width, but the rectangle came off the network.
        let slice = data.get(start..start.checked_add(row_bytes)?)?;
        payload.extend_from_slice(slice);
    }

    Some((Rect::new(region.left, region.top, width, height), payload))
}

/// Chooses between raw and run-length encoding for one rectangle.
///
/// A desktop is mostly flat colour, and a run-length pass over it is a few
/// instructions per pixel on a worker thread against a WebView render thread
/// with a 30 ms budget it is already spending
/// (`docs/architecture/rendering.md`). The encoding is only used when it
/// actually shrinks the payload, so a photograph or a video frame still
/// travels raw rather than paying eight bytes per pixel to say "one of these".
fn encode_rect(rect: Rect, payload: &[u8]) -> FrameRect {
    match run_length_encode(payload) {
        Some(encoded) => FrameRect::rle(rect, PixelFormat::Bgrx8888, encoded),
        None => FrameRect::raw(rect, PixelFormat::Bgrx8888, Bytes::copy_from_slice(payload)),
    }
}

/// Run-length encodes 32-bit pixels, or `None` if it would not be smaller.
///
/// The format `remoter_proto::framebuffer` defines: a repeated `u32`
/// little-endian run length followed by one pixel in the declared format. Runs
/// are capped at [`u32::MAX`] by construction — a rectangle cannot hold that
/// many pixels — and the encoder gives up as soon as it has produced more
/// bytes than the raw form would take, so pathological input costs a bounded
/// amount of work and nothing else.
fn run_length_encode(payload: &[u8]) -> Option<Bytes> {
    if payload.is_empty() || payload.len() % BYTES_PER_PIXEL != 0 {
        return None;
    }
    let mut out = BytesMut::with_capacity(payload.len() / 2);
    let mut pixels = payload.chunks_exact(BYTES_PER_PIXEL);
    let mut current = pixels.next()?;
    let mut run: u32 = 1;

    for pixel in pixels {
        if pixel == current {
            run = run.saturating_add(1);
            continue;
        }
        out.put_u32_le(run);
        out.extend_from_slice(current);
        if out.len() + RUN_BYTES >= payload.len() {
            // Already no smaller than raw, and it can only grow from here.
            return None;
        }
        current = pixel;
        run = 1;
    }
    out.put_u32_le(run);
    out.extend_from_slice(current);

    (out.len() < payload.len()).then(|| out.freeze())
}

/// Whether a rectangle's payload is run-length encoded. For the session loop's
/// diagnostics, and for the tests below.
#[must_use]
pub const fn is_compressed(rect: &FrameRect) -> bool {
    matches!(rect.encoding, FrameEncoding::Rle)
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
    use ironrdp::graphics::image_processing::PixelFormat as IronPixelFormat;

    /// A blank decoded image of the given size.
    ///
    /// `DecodedImage` has no public pixel writer — pixels only arrive through
    /// a decoder — so these tests check the geometry, the repacking and the
    /// framing, and the pixel values are checked separately against the
    /// run-length codec, which is where a value can actually go wrong.
    fn image(width: u16, height: u16) -> DecodedImage {
        DecodedImage::new(IronPixelFormat::BgrX32, width, height)
    }

    fn rect(left: u16, top: u16, right: u16, bottom: u16) -> InclusiveRectangle {
        InclusiveRectangle {
            left,
            top,
            right,
            bottom,
        }
    }

    /// The run-length format from `remoter_proto::framebuffer`, decoded back.
    /// Written here so the encoder is checked against the *specification* and
    /// not against itself.
    fn run_length_decode(encoded: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        while cursor + RUN_BYTES <= encoded.len() {
            let count = u32::from_le_bytes(encoded[cursor..cursor + 4].try_into().unwrap());
            let pixel = &encoded[cursor + 4..cursor + RUN_BYTES];
            for _ in 0..count {
                out.extend_from_slice(pixel);
            }
            cursor += RUN_BYTES;
        }
        out
    }

    #[test]
    fn a_run_of_one_colour_round_trips_and_is_much_smaller() {
        // A desktop is mostly flat colour, which is the case this exists for.
        let flat = vec![0x20u8; 4 * 4096];
        let encoded = run_length_encode(&flat).expect("flat pixels must compress");
        assert_eq!(encoded.len(), RUN_BYTES);
        assert_eq!(run_length_decode(&encoded), flat);
    }

    #[test]
    fn alternating_pixels_are_left_raw_rather_than_doubled_in_size() {
        // Eight bytes to say "one of these" is worse than four bytes of the
        // pixel, so the encoder must decline.
        let mut noisy = Vec::new();
        for index in 0..1024u32 {
            noisy.extend_from_slice(&index.to_le_bytes());
        }
        assert!(run_length_encode(&noisy).is_none());
    }

    #[test]
    fn a_mixed_rectangle_round_trips_exactly() {
        let mut mixed = Vec::new();
        mixed.extend(std::iter::repeat_n(0xaau8, 4 * 100));
        mixed.extend_from_slice(&[1, 2, 3, 4]);
        mixed.extend(std::iter::repeat_n(0xbbu8, 4 * 50));
        mixed.extend_from_slice(&[5, 6, 7, 8]);
        let encoded = run_length_encode(&mixed).expect("mostly flat pixels must compress");
        assert_eq!(run_length_decode(&encoded), mixed);
    }

    #[test]
    fn a_payload_that_is_not_a_whole_number_of_pixels_is_never_compressed() {
        // It cannot be: the format is a run count and one pixel.
        assert!(run_length_encode(&[1, 2, 3]).is_none());
        assert!(run_length_encode(&[]).is_none());
    }

    #[test]
    fn the_chosen_encoding_declares_itself_correctly() {
        let flat = vec![0x11u8; 4 * 64];
        let compressed = encode_rect(Rect::new(0, 0, 8, 8), &flat);
        assert!(is_compressed(&compressed));
        assert_eq!(compressed.format, PixelFormat::Bgrx8888);
        assert_eq!(run_length_decode(compressed.payload()), flat);

        let mut noisy = Vec::new();
        for index in 0..64u32 {
            noisy.extend_from_slice(&index.to_le_bytes());
        }
        let raw = encode_rect(Rect::new(0, 0, 8, 8), &noisy);
        assert!(!is_compressed(&raw));
        assert_eq!(&raw.payload()[..], &noisy[..]);
    }

    #[test]
    fn a_rectangle_outside_the_image_is_refused_rather_than_clamped() {
        // A clamped rectangle draws the wrong pixels in the wrong place; a
        // refused one draws nothing and says so.
        let image = image(64, 48);
        assert!(extract(&image, &rect(0, 0, 64, 47)).is_none());
        assert!(extract(&image, &rect(0, 0, 63, 48)).is_none());
        // Inverted, which a malformed update can produce.
        assert!(extract(&image, &rect(10, 10, 5, 20)).is_none());
        assert!(extract(&image, &rect(10, 10, 20, 5)).is_none());
    }

    #[test]
    fn a_rectangle_is_repacked_with_no_row_padding() {
        // `data_for_rect` returns whole scanlines. Sending that span would
        // draw the rectangle sheared, which is the classic symptom of this
        // mistake.
        let image = image(64, 48);
        let (geometry, payload) = extract(&image, &rect(8, 4, 23, 11)).unwrap();
        assert_eq!(geometry, Rect::new(8, 4, 16, 8));
        assert_eq!(payload.len(), 16 * 8 * BYTES_PER_PIXEL);
        // The padded span would have been (7 rows * stride) + 16 pixels, which
        // is a different and larger number.
        assert_ne!(payload.len(), 7 * image.stride() + 16 * BYTES_PER_PIXEL);
    }

    #[test]
    fn a_single_pixel_rectangle_is_one_pixel_and_not_zero() {
        // The bounds are inclusive on both edges, so `left == right` is one
        // pixel wide. Treating it as exclusive drops every single-pixel
        // update — a text caret, for instance.
        let image = image(64, 48);
        let (geometry, payload) = extract(&image, &rect(5, 5, 5, 5)).unwrap();
        assert_eq!(geometry, Rect::new(5, 5, 1, 1));
        assert_eq!(payload.len(), BYTES_PER_PIXEL);
    }

    #[test]
    fn the_sequence_number_is_one_stream_shared_with_the_cursor() {
        // A presenter spots a dropped frame by looking for a gap. Two counters
        // would make every cursor change look like one.
        let mut encoder = FrameEncoder::new(64, 48);
        let image = image(64, 48);
        let now = Instant::now();

        encoder.push(&image, &rect(0, 0, 7, 7), now);
        let first = encoder.take().unwrap();
        assert_eq!(first.seq(), 0);

        let hidden = encoder.hide_cursor();
        assert_eq!(hidden.seq(), 1);

        encoder.push(&image, &rect(0, 0, 7, 7), now);
        let second = encoder.take().unwrap();
        assert_eq!(second.seq(), 2);
    }

    #[test]
    fn a_keyframe_covers_the_whole_surface_and_says_so() {
        // A presenter attaching mid-session, or one that saw a gap, needs an
        // update that depends on nothing before it.
        let mut encoder = FrameEncoder::new(64, 48);
        let image = image(64, 48);
        let FrameMessage::Framebuffer(update) = encoder.keyframe(&image).unwrap() else {
            panic!("a keyframe must be a framebuffer message");
        };
        assert!(update.keyframe);
        assert_eq!(update.rects.len(), 1);
        assert_eq!(update.rects[0].rect, Rect::surface(64, 48));
    }

    #[test]
    fn a_keyframe_for_the_wrong_size_image_is_refused() {
        // Sending one that does not cover the surface would claim
        // self-sufficiency the pixels cannot support.
        let mut encoder = FrameEncoder::new(64, 48);
        assert!(encoder.keyframe(&image(80, 60)).is_none());
    }

    #[test]
    fn a_resize_discards_what_was_pending_for_the_old_surface() {
        let mut encoder = FrameEncoder::new(64, 48);
        let image = image(64, 48);
        encoder.push(&image, &rect(0, 0, 7, 7), Instant::now());
        encoder.set_surface(80, 60);
        assert_eq!(encoder.surface(), Rect::surface(80, 60));
        // Whatever was pending described a surface that no longer exists.
        assert!(encoder.take().is_none());
    }

    #[test]
    fn a_cursor_whose_pixels_do_not_match_its_size_is_refused() {
        // Otherwise the presenter reads past the end of the image.
        let mut encoder = FrameEncoder::new(64, 48);
        let pointer = DecodedPointer {
            width: 16,
            height: 16,
            hotspot_x: 0,
            hotspot_y: 0,
            bitmap_data: vec![0u8; 16 * 16 * 4 - 1],
        };
        assert!(encoder.cursor(&pointer).is_none());

        let pointer = DecodedPointer {
            bitmap_data: vec![0u8; 16 * 16 * 4],
            ..pointer
        };
        let FrameMessage::Cursor(update) = encoder.cursor(&pointer).unwrap() else {
            panic!("expected a cursor message");
        };
        assert_eq!(update.width, 16);
        assert_eq!(update.format, PixelFormat::Rgba8888);
        assert!(!update.is_hidden());
    }

    #[test]
    fn a_frame_message_round_trips_through_the_shared_wire_format() {
        // The presenter parses what this produces; if the two disagree the
        // desktop is garbage, and the shared codec is the only place that can
        // be checked without a browser.
        use remoter_proto::SessionId;

        let mut encoder = FrameEncoder::new(64, 48);
        let image = image(64, 48);
        encoder.push(&image, &rect(0, 0, 15, 15), Instant::now());
        let message = encoder.take().unwrap();

        let session = SessionId::from_raw(7);
        let encoded = message.encode(session);
        let (decoded_session, decoded) = FrameMessage::decode(&encoded).unwrap();
        assert_eq!(decoded_session, session);
        assert_eq!(decoded, message);
    }

    #[test]
    fn the_encoder_never_debug_prints_the_pixels() {
        let mut encoder = FrameEncoder::new(64, 48);
        encoder.push(&image(64, 48), &rect(0, 0, 7, 7), Instant::now());
        let rendered = format!("{encoder:?}");
        assert!(rendered.contains("pending: true"), "{rendered}");
        assert!(!rendered.contains("payload"), "{rendered}");
    }
}
