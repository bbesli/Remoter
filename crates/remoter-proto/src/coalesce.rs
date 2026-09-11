//! Coalescing terminal output into frames.
//!
//! `yes` over SSH produces thousands of tiny writes a second. Forwarding each
//! one as its own event would push thousands of messages a second through a
//! bounded channel, across the IPC boundary and into a renderer that can draw
//! sixty times a second at best — **rendering the intermediate states of a
//! fast-scrolling terminal is wasted work**, because the user never sees them.
//! So bytes are batched and flushed at the frame interval, exactly as
//! `docs/architecture/session-pipeline.md` §8 requires.
//!
//! Coalescing is not the same as dropping. Every byte is delivered, in order;
//! only the *number of messages* is reduced. Terminal streams are stateful —
//! an escape sequence split across two writes is meaningless on its own — so
//! dropping is not available to us the way it is for framebuffer updates.
//!
//! The clock is a parameter rather than a call to `Instant::now` inside, which
//! is what makes the behaviour testable without sleeping.

use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

/// One frame's worth of time. 16 ms is a 60 Hz display's frame budget; drawing
/// more often than the screen refreshes cannot be seen.
pub const DEFAULT_FRAME_INTERVAL: Duration = Duration::from_millis(16);

/// The most that is held back before a flush happens regardless of the clock.
///
/// A ceiling is required, not merely prudent: a fast host on a fast link can
/// produce megabytes inside one frame interval, and an unbounded buffer waiting
/// for a timer is the same unbounded memory leak an unbounded channel would be.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 128 * 1024;

/// Batches terminal bytes into frames.
#[derive(Debug)]
pub struct OutputCoalescer {
    buffer: BytesMut,
    interval: Duration,
    max_bytes: usize,
    /// When the current batch started. `None` when the buffer is empty, so an
    /// idle session does not carry a stale deadline.
    opened_at: Option<Instant>,
}

impl OutputCoalescer {
    /// A coalescer that flushes after `interval`, or once `max_bytes` are
    /// buffered, whichever comes first.
    #[must_use]
    pub fn new(interval: Duration, max_bytes: usize) -> Self {
        Self {
            buffer: BytesMut::new(),
            interval,
            // A zero maximum would mean "flush nothing ever" or "flush every
            // byte" depending on how the comparison is written; one byte is the
            // only sane floor.
            max_bytes: max_bytes.max(1),
            opened_at: None,
        }
    }

    /// Adds as much of `bytes` as the ceiling allows, returning a frame if one
    /// is due and the bytes that did not fit.
    ///
    /// `now` is the caller's clock reading. A frame comes back when the
    /// interval has elapsed since the batch opened, or when the batch has
    /// reached its size ceiling.
    ///
    /// **The append is bounded.** Copying the whole write in and only then
    /// testing the ceiling makes the ceiling advisory: one `write(2)` of a
    /// hundred megabytes from a hostile or merely enthusiastic host
    /// (`docs/security/threat-model.md`, T4) allocates a hundred megabytes in a
    /// buffer whose entire purpose is to stay bounded. So a write larger than
    /// the remaining room is split, and the caller loops.
    ///
    /// Nothing is dropped: the remainder is returned rather than discarded, and
    /// each iteration of the caller's loop delivers a full frame through the
    /// bounded channel — which is where backpressure belongs. Progress is
    /// guaranteed because a non-empty remainder means the buffer reached the
    /// ceiling and was therefore flushed, and the ceiling is at least one byte.
    pub fn push<'a>(&mut self, bytes: &'a [u8], now: Instant) -> (Option<Bytes>, &'a [u8]) {
        if bytes.is_empty() {
            return (None, &[]);
        }
        let opened_at = *self.opened_at.get_or_insert(now);

        let room = self.max_bytes.saturating_sub(self.buffer.len());
        let taken = room.min(bytes.len());
        let (head, rest) = bytes.split_at(taken);
        self.buffer.extend_from_slice(head);

        let full = self.buffer.len() >= self.max_bytes;
        let due = now.duration_since(opened_at) >= self.interval;
        let frame = if full || due { self.flush() } else { None };
        (frame, rest)
    }

    /// Takes whatever is buffered, if anything.
    ///
    /// The session loop calls this on its frame timer and again before it
    /// disconnects — output that was written a microsecond before the server
    /// closed the channel is still output the user wants to read.
    pub fn flush(&mut self) -> Option<Bytes> {
        if self.buffer.is_empty() {
            return None;
        }
        self.opened_at = None;
        Some(self.buffer.split().freeze())
    }

    /// How many bytes are waiting.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    /// How long until the current batch is due, or `None` when nothing is
    /// buffered. Feeds a `tokio::select!` timer, so an idle session arms no
    /// timer at all.
    #[must_use]
    pub fn time_to_deadline(&self, now: Instant) -> Option<Duration> {
        self.opened_at
            .map(|opened| self.interval.saturating_sub(now.duration_since(opened)))
    }

    /// The configured frame interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }
}

impl Default for OutputCoalescer {
    fn default() -> Self {
        Self::new(DEFAULT_FRAME_INTERVAL, DEFAULT_MAX_FRAME_BYTES)
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

    fn coalescer() -> OutputCoalescer {
        OutputCoalescer::new(Duration::from_millis(16), 64)
    }

    #[test]
    fn writes_inside_one_frame_are_batched_into_a_single_event() {
        let mut c = coalescer();
        let t0 = Instant::now();

        // A thousand one-byte writes is what `yes` looks like from here.
        for _ in 0..10 {
            assert_eq!(c.push(b"y\n", t0), (None, &b""[..]));
        }
        assert_eq!(c.pending(), 20);

        let frame = c.flush().unwrap();
        assert_eq!(frame.len(), 20);
        assert_eq!(&frame[..2], b"y\n");
    }

    #[test]
    fn a_frame_is_emitted_once_the_interval_has_elapsed() {
        let mut c = coalescer();
        let t0 = Instant::now();
        assert_eq!(c.push(b"abc", t0), (None, &b""[..]));

        let (frame, rest) = c.push(b"def", t0 + Duration::from_millis(16));
        assert!(rest.is_empty());
        let frame = frame.expect("the frame interval has passed");
        assert_eq!(&frame[..], b"abcdef");
        assert_eq!(c.pending(), 0);
    }

    #[test]
    fn the_size_ceiling_flushes_before_the_timer_does() {
        // The ceiling is what keeps a fast host from turning the buffer into an
        // unbounded allocation while it waits for a 16 ms timer.
        let mut c = coalescer();
        let t0 = Instant::now();
        let (frame, rest) = c.push(&[b'x'; 64], t0);
        assert!(rest.is_empty());
        assert_eq!(frame.expect("the ceiling was reached").len(), 64);
    }

    /// The ceiling has to bound the *allocation*, not merely be consulted after
    /// it has already happened.
    ///
    /// One `write(2)` far larger than the ceiling is ordinary — `cat` of a large
    /// file, a `tar` to stdout, a hostile host (T4) choosing the size on
    /// purpose. Appending first and testing afterwards let that single write
    /// size the buffer, which is precisely the unbounded buffer the ceiling
    /// exists to prevent.
    #[test]
    fn one_oversized_write_never_allocates_past_the_ceiling() {
        const CEILING: usize = 64;
        let mut c = OutputCoalescer::new(Duration::from_millis(16), CEILING);
        let t0 = Instant::now();
        let huge = vec![b'x'; 1_000_000];

        let mut delivered = Vec::new();
        let mut rest = &huge[..];
        loop {
            let (frame, remainder) = c.push(rest, t0);
            assert!(
                c.pending() <= CEILING,
                "the buffer grew to {} bytes with a {CEILING}-byte ceiling",
                c.pending()
            );
            if let Some(frame) = frame {
                assert!(
                    frame.len() <= CEILING,
                    "a frame of {} bytes exceeds the ceiling",
                    frame.len()
                );
                delivered.extend_from_slice(&frame);
            }
            if remainder.is_empty() {
                break;
            }
            assert!(remainder.len() < rest.len(), "the loop made no progress");
            rest = remainder;
        }
        if let Some(frame) = c.flush() {
            delivered.extend_from_slice(&frame);
        }

        // Bounded, and still lossless: coalescing reduces the number of
        // messages, never the bytes.
        assert_eq!(delivered, huge);
    }

    #[test]
    fn no_byte_is_ever_dropped_or_reordered() {
        let mut c = OutputCoalescer::new(Duration::from_millis(16), 8);
        let t0 = Instant::now();
        let mut delivered = Vec::new();

        for i in 0..64u8 {
            let one = [i];
            let (frame, rest) = c.push(&one, t0 + Duration::from_micros(u64::from(i)));
            assert!(rest.is_empty());
            if let Some(frame) = frame {
                delivered.extend_from_slice(&frame);
            }
        }
        if let Some(frame) = c.flush() {
            delivered.extend_from_slice(&frame);
        }

        assert_eq!(delivered, (0..64u8).collect::<Vec<_>>());
    }

    #[test]
    fn flushing_an_empty_buffer_produces_nothing() {
        let mut c = coalescer();
        assert!(c.flush().is_none());
        assert_eq!(c.push(b"", Instant::now()), (None, &b""[..]));
    }

    #[test]
    fn an_idle_coalescer_arms_no_timer() {
        let mut c = coalescer();
        let t0 = Instant::now();
        assert!(c.time_to_deadline(t0).is_none());

        let _ = c.push(b"x", t0);
        assert_eq!(
            c.time_to_deadline(t0 + Duration::from_millis(6)),
            Some(Duration::from_millis(10))
        );
        // An overdue batch reports zero rather than underflowing.
        assert_eq!(
            c.time_to_deadline(t0 + Duration::from_millis(30)),
            Some(Duration::ZERO)
        );

        c.flush();
        assert!(c.time_to_deadline(t0).is_none());
    }

    #[test]
    fn the_deadline_is_measured_from_the_first_byte_of_the_batch() {
        // Not from the last: a stream that trickles a byte every 15 ms must
        // still reach the screen, rather than resetting its own deadline
        // forever.
        let mut c = coalescer();
        let t0 = Instant::now();
        assert_eq!(c.push(b"a", t0), (None, &b""[..]));
        assert_eq!(
            c.push(b"b", t0 + Duration::from_millis(10)),
            (None, &b""[..])
        );
        let (frame, rest) = c.push(b"c", t0 + Duration::from_millis(17));
        assert!(rest.is_empty());
        assert_eq!(&frame.expect("17 ms after the batch opened")[..], b"abc");
    }

    #[test]
    fn a_zero_ceiling_is_clamped_rather_than_dividing_by_itself() {
        let mut c = OutputCoalescer::new(Duration::from_millis(16), 0);
        let (frame, rest) = c.push(b"a", Instant::now());
        assert!(rest.is_empty());
        assert_eq!(&frame.expect("a one-byte ceiling")[..], b"a");
    }
}
