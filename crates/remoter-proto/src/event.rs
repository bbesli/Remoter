//! Session events, and the bounded, coalescing sink they leave through.
//!
//! **Bounded channels only.** An unbounded channel is an unbounded memory leak
//! waiting for a fast remote host: the producer is a socket on someone else's
//! machine and the consumer is a WebView, and there is no arrangement of those
//! two in which the producer can be trusted to slow down on its own. When the
//! channel fills, [`EventSink::data`] waits — which stops reading the socket,
//! which fills the TCP window, which is how backpressure is supposed to reach
//! the far end.
//!
//! Terminal output is coalesced on the way through; see [`crate::coalesce`] for
//! why.

use std::fmt;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc};
use zeroize::Zeroizing;

use crate::coalesce::{DEFAULT_FRAME_INTERVAL, DEFAULT_MAX_FRAME_BYTES, OutputCoalescer};
use crate::error::{FailureReport, ProtocolError};
use crate::protocol::{ClipboardData, ClipboardFormats};

/// How many events a session's channel holds before its producer waits.
///
/// Deep enough that a burst of control events does not stall a session,
/// shallow enough that a stalled consumer is felt in milliseconds rather than
/// megabytes.
pub const DEFAULT_EVENT_CAPACITY: usize = 256;

/// Identifies one prompt, so the answer can be matched to the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PromptId(u64);

impl PromptId {
    /// Wraps a counter value. Prompt ids are unique within a session only.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PromptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The key a host was already trusted with, for the side-by-side comparison a
/// changed-key dialog is required to show.
///
/// Nothing here is secret: a public host key, its fingerprint and its randomart
/// are exactly the values a user is meant to compare out of band, and they are
/// on screen for that purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedHostKey {
    /// The stored key's fingerprint, in `SHA256:` form.
    pub fingerprint: String,
    /// Its ASCII-art rendering, to be shown beside the offered one so the
    /// difference is visible rather than merely stated — a person compares two
    /// 43-character base64 strings badly and two pictures well.
    pub randomart: String,
    /// When it was first trusted, in milliseconds since the Unix epoch.
    ///
    /// "You accepted this key three years ago" and "you accepted it during
    /// yesterday's import" are different situations, and only the user can tell
    /// which one they are in.
    pub first_trusted_at_ms: i64,
}

/// What a prompt is asking for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PromptKind {
    /// The account password.
    Password,
    /// The passphrase for a private key.
    KeyPassphrase,
    /// An SSH keyboard-interactive challenge (RFC 4256 §3.2), which is where
    /// 2FA codes and expired-password changes arrive.
    KeyboardInteractive {
        /// The server's instruction text. Peer-supplied: render as text, never
        /// as markup.
        instruction: String,
    },
    /// A host key decision. Suspends the pipeline; never auto-answered.
    ///
    /// Everything the dialog has to show is carried here, because the interface
    /// cannot derive any of it. `docs/security/transport-security.md` requires
    /// the changed-key dialog to show **both** fingerprints — "a red, blocking
    /// dialog … showing both fingerprints" — and the first-use prompt to show
    /// the full fingerprint, the key type and the randomart. A prompt carrying
    /// only the offered fingerprint cannot do either: the whole point is that a
    /// person compares the stored value with the offered one, and with no host
    /// named they cannot even tell which machine is being talked about.
    HostKey {
        /// The host being verified, as `host:port` and as the user typed it.
        host: String,
        /// The key algorithm, as named on the wire: `ssh-ed25519`,
        /// `rsa-sha2-512`, `ecdsa-sha2-nistp256`. Peer-supplied text.
        algorithm: String,
        /// The offered key's fingerprint, in `SHA256:` form.
        fingerprint: String,
        /// Its ASCII-art rendering.
        randomart: String,
        /// The key already trusted for this host, when there is one and it is
        /// **not** the offered key. `Some` is the blocking, man-in-the-middle
        /// warning; `None` is a first-use question.
        previously_trusted: Option<TrustedHostKey>,
    },
    /// A certificate decision.
    Certificate {
        /// The certificate's fingerprint.
        fingerprint: String,
        /// Why it is not trusted.
        reason: String,
    },
}

impl PromptKind {
    /// Whether this is the blocking, changed-key warning rather than a
    /// first-use question.
    ///
    /// The two share a variant because they share a dialog, but they are not
    /// the same question: one asks the user to check a key they have never
    /// seen, the other tells them the key they already checked no longer
    /// matches (`docs/security/transport-security.md`).
    #[must_use]
    pub const fn is_changed_host_key(&self) -> bool {
        matches!(
            self,
            Self::HostKey {
                previously_trusted: Some(_),
                ..
            }
        )
    }
}

/// The server needs something before the session can continue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    /// Matches the answer to the question.
    pub id: PromptId,
    /// What is being asked.
    pub kind: PromptKind,
    /// The prompt text. Peer-supplied for keyboard-interactive: untrusted,
    /// and never rendered as markup.
    pub text: String,
    /// Whether the answer may be echoed. `false` for anything secret, and the
    /// interface must honour it — RFC 4256 §3.3 carries this flag per prompt
    /// precisely because the server knows which of its questions are secret.
    pub echo: bool,
}

/// The answer to a [`Prompt`].
///
/// Travels back over the session's command channel, never through an event, and
/// holds its bytes the same way the vault does: borrowed inside a closure,
/// zeroized on drop, and redacted in `Debug`. Nothing about a prompt answer is
/// less sensitive than a stored credential — it *is* a credential, typed a
/// moment ago.
pub struct PromptAnswer {
    id: PromptId,
    secret: Zeroizing<Vec<u8>>,
    cancelled: bool,
}

impl PromptAnswer {
    /// An answer to `id`. The buffer is zeroized when this value is dropped.
    #[must_use]
    pub fn new(id: PromptId, secret: Vec<u8>) -> Self {
        Self {
            id,
            secret: Zeroizing::new(secret),
            cancelled: false,
        }
    }

    /// The user dismissed the prompt.
    #[must_use]
    pub fn cancelled(id: PromptId) -> Self {
        Self {
            id,
            secret: Zeroizing::new(Vec::new()),
            cancelled: true,
        }
    }

    /// Which prompt this answers.
    #[must_use]
    pub const fn id(&self) -> PromptId {
        self.id
    }

    /// Whether the user declined to answer.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Borrows the answer for the duration of `f`, exactly as
    /// [`crate::CredentialProvider`] does — the bytes are never handed out as
    /// an owned value, so nothing downstream can retain them past the
    /// challenge they answer.
    pub fn with_secret<R>(&self, f: &mut dyn FnMut(&[u8]) -> R) -> Option<R> {
        if self.cancelled {
            return None;
        }
        Some(f(&self.secret))
    }
}

impl fmt::Debug for PromptAnswer {
    /// Redacting, and hand-written so that no future `#[derive]` can undo it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PromptAnswer")
            .field("id", &self.id)
            .field("cancelled", &self.cancelled)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Progress on something long-running: an SFTP transfer, an RDP connection
/// sequence, a latency sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressUpdate {
    /// What is progressing. A stable ASCII key for the message catalogue.
    pub operation: String,
    /// Work done so far, in whatever unit `total` uses.
    pub done: u64,
    /// The total, when it is known. Streaming transfers often do not know.
    pub total: Option<u64>,
    /// A detail line — the file being transferred, say. Never a secret.
    pub detail: Option<String>,
}

/// Something the user should know about but which did not end the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "warning", rename_all = "snake_case")]
pub enum SessionWarning {
    /// The connection is carrying credentials or data in clear text — plain
    /// FTP, or VNC's DES-based authentication to a routable address.
    UnencryptedTransport {
        /// What is unprotected, as a catalogue key.
        detail: String,
    },
    /// A weak or deprecated algorithm was negotiated.
    WeakAlgorithm {
        /// The algorithm, as named on the wire.
        algorithm: String,
    },
    /// The session is being recorded. Sent before recording starts, never
    /// after — the user is told first or not at all.
    RecordingStarted,
    /// Output is arriving faster than it can be consumed. Diagnostic; nothing
    /// is being lost, the producer is being made to wait.
    OutputThrottled,
    /// The server's message of the day or login banner. Untrusted text.
    Banner {
        /// The banner, as received.
        text: String,
    },
    /// Something protocol-specific worth surfacing.
    Other {
        /// A catalogue key.
        detail: String,
    },
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum CloseReason {
    /// The far end closed cleanly.
    Disconnected,
    /// The tab was closed, or the session was cancelled.
    ClosedByUser,
    /// The application is shutting down.
    ApplicationExit,
    /// The session failed. Carries what the tab shows.
    Failed(FailureReport),
    /// The session task panicked and was destroyed.
    ///
    /// Per ADR-0011 nothing about it is resumed and the panic payload is not
    /// carried — a payload holds formatted values, and a formatted value can
    /// hold a secret.
    Panicked,
    /// The session did not stop within its grace period and was aborted.
    Aborted,
}

/// Everything a session tells the layer above it.
///
/// `Debug` is hand-written and redacting for [`SessionEvent::Data`]. Terminal
/// output is not innocuous: `cat id_ed25519` puts a private key in it, and one
/// `tracing::debug!` on the event path would put that key in a log file. The
/// length is enough for the diagnostics anyone actually needs.
#[derive(Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Terminal bytes, or an encoded framebuffer update. A raw byte payload,
    /// never JSON-encoded — see `docs/architecture/rendering.md`.
    Data(Bytes),
    /// The remote display changed size.
    Resized {
        /// New width, in columns or pixels depending on the session kind.
        width: u16,
        /// New height.
        height: u16,
    },
    /// The remote has something on its clipboard.
    ClipboardOffer(ClipboardFormats),
    /// What the remote copied, for the local clipboard.
    ///
    /// Sent only when the session's [`crate::ClipboardPolicy`] lets remote
    /// content reach this machine, and only content the adapter has already
    /// bounded. The layer above puts it on the system clipboard; nothing keeps
    /// it longer than that. `Debug` is redacting, through [`ClipboardData`]'s.
    ClipboardContent(ClipboardData),
    /// The server needs something before it will continue.
    Prompt(Prompt),
    /// Progress on something long-running.
    Progress(ProgressUpdate),
    /// Something worth telling the user that did not end the session.
    Warning(SessionWarning),
    /// The session is over. Always the last event.
    Closed(CloseReason),
}

impl fmt::Debug for SessionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(bytes) => write!(f, "Data(<redacted, {} bytes>)", bytes.len()),
            Self::Resized { width, height } => {
                write!(f, "Resized {{ width: {width}, height: {height} }}")
            }
            Self::ClipboardOffer(formats) => write!(f, "ClipboardOffer({formats:?})"),
            Self::ClipboardContent(data) => write!(f, "ClipboardContent({data:?})"),
            Self::Prompt(prompt) => write!(f, "Prompt({prompt:?})"),
            Self::Progress(update) => write!(f, "Progress({update:?})"),
            Self::Warning(warning) => write!(f, "Warning({warning:?})"),
            Self::Closed(reason) => write!(f, "Closed({reason:?})"),
        }
    }
}

/// The write end of a session's event stream.
///
/// Cheap to clone: an adapter typically hands one clone to its read loop and
/// keeps another for control events.
#[derive(Clone)]
pub struct EventSink {
    tx: mpsc::Sender<SessionEvent>,
    // A `tokio` mutex rather than a `std` one because it is held across the
    // `send().await` below — and it must be, or two concurrent `data` calls
    // could interleave a flush between another's flush and its send, and
    // deliver terminal bytes out of order.
    coalescer: std::sync::Arc<Mutex<OutputCoalescer>>,
    interval: Duration,
}

impl EventSink {
    /// A sink writing into `tx`, coalescing terminal output at `interval`.
    #[must_use]
    pub fn new(tx: mpsc::Sender<SessionEvent>, interval: Duration, max_frame_bytes: usize) -> Self {
        Self {
            tx,
            coalescer: std::sync::Arc::new(Mutex::new(OutputCoalescer::new(
                interval,
                max_frame_bytes,
            ))),
            interval,
        }
    }

    /// Queues terminal output.
    ///
    /// Bytes are buffered and delivered as one [`SessionEvent::Data`] per frame
    /// interval. Nothing is dropped and nothing is reordered; the saving is in
    /// the number of messages, which is what the renderer is actually limited
    /// by.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::EventStreamClosed`] once the consumer is gone;
    /// [`ProtocolError::Internal`] if the coalescer stops making progress,
    /// which would otherwise be an infinite loop.
    pub async fn data(&self, bytes: &[u8]) -> Result<(), ProtocolError> {
        // The lock is held for the whole write, not per frame: releasing it
        // between frames would let a second writer interleave its bytes into
        // the middle of this one, and terminal output is order-sensitive — an
        // escape sequence split around someone else's bytes is meaningless.
        let mut coalescer = self.coalescer.lock().await;
        let mut rest = bytes;
        loop {
            // `push` bounds what it takes, so an oversized write comes back as
            // a remainder instead of being copied whole into a buffer that is
            // meant to be bounded. Each pass sends one full frame, so the
            // bounded channel applies backpressure inside the loop rather than
            // after a megabyte has already been allocated.
            let (frame, remainder) = coalescer.push(rest, Instant::now());
            if let Some(frame) = frame {
                self.emit(SessionEvent::Data(frame)).await?;
            }
            if remainder.is_empty() {
                return Ok(());
            }
            if remainder.len() >= rest.len() {
                // Unreachable while the ceiling is at least one byte, which
                // `OutputCoalescer::new` guarantees. Reported rather than
                // spun on: a hung session task holds credentials.
                return Err(ProtocolError::Internal {
                    detail: "the output coalescer accepted no bytes",
                });
            }
            rest = remainder;
        }
    }

    /// Delivers whatever output is buffered, if any.
    ///
    /// The session loop calls this on its frame timer and before it
    /// disconnects.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::EventStreamClosed`] once the consumer is gone.
    pub async fn flush(&self) -> Result<(), ProtocolError> {
        let mut coalescer = self.coalescer.lock().await;
        if let Some(frame) = coalescer.flush() {
            self.emit(SessionEvent::Data(frame)).await?;
        }
        Ok(())
    }

    /// Sends a control event.
    ///
    /// Buffered output is flushed first, so a `Resized` or a `Closed` never
    /// overtakes the bytes that were written before it. Ordering between the
    /// two is not cosmetic: a terminal that is told it resized before it
    /// receives the output written at the old size redraws wrongly.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::EventStreamClosed`] once the consumer is gone.
    pub async fn send(&self, event: SessionEvent) -> Result<(), ProtocolError> {
        let mut coalescer = self.coalescer.lock().await;
        if let Some(frame) = coalescer.flush() {
            self.emit(SessionEvent::Data(frame)).await?;
        }
        self.emit(event).await
    }

    /// How long until the buffered frame is due, for the session loop's timer.
    /// `None` when nothing is buffered, so an idle session arms no timer.
    pub async fn frame_deadline(&self) -> Option<Duration> {
        self.coalescer.lock().await.time_to_deadline(Instant::now())
    }

    /// The frame interval this sink coalesces at.
    #[must_use]
    pub const fn frame_interval(&self) -> Duration {
        self.interval
    }

    /// Whether the consumer has gone away. A session that sees this should
    /// tear down: there is nobody left to render it.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    async fn emit(&self, event: SessionEvent) -> Result<(), ProtocolError> {
        self.tx
            .send(event)
            .await
            .map_err(|_| ProtocolError::EventStreamClosed)
    }
}

impl fmt::Debug for EventSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventSink")
            .field("closed", &self.tx.is_closed())
            .field("interval", &self.interval)
            .finish()
    }
}

/// A bounded event channel with the defaults from this module.
#[must_use]
pub fn event_channel(capacity: usize) -> (EventSink, mpsc::Receiver<SessionEvent>) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    (
        EventSink::new(tx, DEFAULT_FRAME_INTERVAL, DEFAULT_MAX_FRAME_BYTES),
        rx,
    )
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

    fn sink(capacity: usize) -> (EventSink, mpsc::Receiver<SessionEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        (EventSink::new(tx, Duration::from_millis(16), 64), rx)
    }

    #[tokio::test]
    async fn small_writes_reach_the_consumer_as_one_frame() {
        let (sink, mut rx) = sink(8);
        for _ in 0..16 {
            sink.data(b"y\n").await.unwrap();
        }
        // Nothing has been sent yet: the frame is still open.
        assert!(rx.try_recv().is_err());

        sink.flush().await.unwrap();
        let Some(SessionEvent::Data(frame)) = rx.recv().await else {
            panic!("the flush must produce one data event");
        };
        assert_eq!(frame.len(), 32);
        assert!(rx.try_recv().is_err(), "exactly one event, not sixteen");
    }

    #[tokio::test]
    async fn a_control_event_never_overtakes_buffered_output() {
        let (sink, mut rx) = sink(8);
        sink.data(b"before the resize").await.unwrap();
        sink.send(SessionEvent::Resized {
            width: 120,
            height: 40,
        })
        .await
        .unwrap();

        let Some(SessionEvent::Data(frame)) = rx.recv().await else {
            panic!("the buffered output must be delivered first");
        };
        assert_eq!(&frame[..], b"before the resize");
        assert!(matches!(
            rx.recv().await,
            Some(SessionEvent::Resized {
                width: 120,
                height: 40
            })
        ));
    }

    #[tokio::test]
    async fn the_ceiling_flushes_without_waiting_for_the_timer() {
        let (sink, mut rx) = sink(8);
        sink.data(&[b'x'; 64]).await.unwrap();
        let Some(SessionEvent::Data(frame)) = rx.recv().await else {
            panic!("64 bytes reaches the ceiling this sink was built with");
        };
        assert_eq!(frame.len(), 64);
    }

    /// A single write far larger than the frame ceiling must leave through the
    /// sink in bounded frames, in order, with nothing lost.
    #[tokio::test]
    async fn one_oversized_write_leaves_as_bounded_frames_in_order() {
        // Capacity is generous so the test measures the ceiling rather than the
        // channel; the ceiling is 64 bytes, from `sink`.
        let (sink, mut rx) = sink(1024);
        let huge: Vec<u8> = (0..4_096u32)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();

        sink.data(&huge).await.unwrap();
        sink.flush().await.unwrap();

        let mut delivered = Vec::new();
        while let Ok(event) = rx.try_recv() {
            let SessionEvent::Data(frame) = event else {
                panic!("only data events were sent");
            };
            assert!(
                frame.len() <= 64,
                "a {} byte frame exceeds the 64 byte ceiling",
                frame.len()
            );
            delivered.extend_from_slice(&frame);
        }
        assert_eq!(delivered, huge, "bytes were dropped or reordered");
    }

    #[tokio::test]
    async fn a_full_channel_makes_the_producer_wait_rather_than_grow() {
        // This is the property the whole design rests on: the sink applies
        // backpressure instead of buffering without limit.
        let (sink, mut rx) = sink(1);
        sink.send(SessionEvent::Warning(SessionWarning::RecordingStarted))
            .await
            .unwrap();

        let blocked = sink.send(SessionEvent::Warning(SessionWarning::OutputThrottled));
        tokio::pin!(blocked);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut blocked)
                .await
                .is_err(),
            "the second send must wait for room"
        );

        // Draining one event unblocks it.
        rx.recv().await.unwrap();
        blocked.await.unwrap();
    }

    #[tokio::test]
    async fn a_closed_consumer_is_reported_not_ignored() {
        let (sink, rx) = sink(4);
        drop(rx);
        assert!(sink.is_closed());
        assert!(matches!(
            sink.send(SessionEvent::Closed(CloseReason::Disconnected))
                .await,
            Err(ProtocolError::EventStreamClosed)
        ));
    }

    #[tokio::test]
    async fn an_idle_sink_arms_no_frame_timer() {
        let (sink, _rx) = sink(4);
        assert!(sink.frame_deadline().await.is_none());
        sink.data(b"x").await.unwrap();
        assert!(sink.frame_deadline().await.is_some());
        sink.flush().await.unwrap();
        assert!(sink.frame_deadline().await.is_none());
    }

    #[test]
    fn a_prompt_answer_never_debug_prints_its_secret() {
        let answer = PromptAnswer::new(PromptId::new(1), b"hunter2".to_vec());
        let rendered = format!("{answer:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn a_prompt_answer_lends_its_secret_rather_than_giving_it_away() {
        let answer = PromptAnswer::new(PromptId::new(1), b"hunter2".to_vec());
        assert_eq!(answer.with_secret(&mut |bytes| bytes.len()), Some(7));
        assert!(!answer.is_cancelled());

        let declined = PromptAnswer::cancelled(PromptId::new(2));
        assert!(declined.is_cancelled());
        assert!(declined.with_secret(&mut |_| ()).is_none());
    }

    #[test]
    fn session_output_never_debug_prints_itself() {
        // `cat id_ed25519` is terminal output too.
        let event = SessionEvent::Data(Bytes::from_static(b"-----BEGIN OPENSSH PRIVATE KEY-----"));
        let rendered = format!("{event:?}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        assert!(rendered.contains("<redacted, 35 bytes>"), "{rendered}");
    }

    #[test]
    fn the_default_capacity_is_bounded() {
        let (_sink, rx) = event_channel(DEFAULT_EVENT_CAPACITY);
        assert_eq!(rx.capacity(), DEFAULT_EVENT_CAPACITY);
        // A zero capacity would panic inside tokio; it is clamped instead.
        let (_sink, rx) = event_channel(0);
        assert_eq!(rx.capacity(), 1);
    }
}
