//! Asking the user something, mid-handshake.
//!
//! RDP raises two questions that cannot be answered from stored state: an
//! unpinned server certificate, and a password when the vault resolved none.
//! `docs/architecture/session-pipeline.md` §5–6 says these **suspend** the
//! pipeline and surface as events, and that the answers come back over a
//! channel of their own rather than through the event stream.
//!
//! [`remoter_proto::Protocol::connect`] takes an [`EventSink`] but no
//! receiver, because a protocol that raises no prompts should not have to hold
//! one. This module supplies the other half: the caller builds a
//! [`PromptChannel`], forwards every
//! [`remoter_proto::SessionCommand::Prompt`] it sees into the sender, and
//! hands the channel to the adapter.
//!
//! An answer is a credential typed a moment ago, so it is treated as one: it
//! lives in a [`Zeroizing`] buffer, is never formatted, and is dropped as soon
//! as the challenge it answers is over.
//!
//! This is deliberately a near-copy of `remoter-proto-ssh`'s `prompt` module.
//! Sibling protocol crates do not depend on each other (CLAUDE.md §3), so the
//! choice was duplication here or an upward dependency there; the shared home
//! for it is `remoter-proto`, and moving it is the right change the moment a
//! third protocol needs it.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use remoter_proto::{
    EventSink, Prompt, PromptAnswer, PromptId, PromptKind, ProtocolError, SessionEvent,
};
use tokio::sync::{Mutex, mpsc};
use zeroize::Zeroizing;

/// How many unanswered prompts may queue before the interface waits.
///
/// Small on purpose: a session raising more than a couple of simultaneous
/// prompts is a session doing something wrong.
pub const PROMPT_CAPACITY: usize = 8;

/// The adapter's end of the prompt round trip.
///
/// Cheap to clone through an [`Arc`]; the receiver is behind a `tokio` mutex
/// because it is held across an `await` while the user is thinking.
pub struct PromptChannel {
    answers: Mutex<mpsc::Receiver<PromptAnswer>>,
    next: AtomicU64,
    /// How many questions are on screen right now, waiting for a person.
    ///
    /// The connection deadline must cover the network, not the human.
    /// `docs/security/transport-security.md` exists to make people compare a
    /// fingerprint out of band, and comparing one takes longer than the thirty
    /// seconds the failure taxonomy allows a *server* to answer in.
    outstanding: AtomicUsize,
}

impl PromptChannel {
    /// A channel and the sender the caller forwards answers into.
    #[must_use]
    pub fn new() -> (mpsc::Sender<PromptAnswer>, Arc<Self>) {
        let (tx, rx) = mpsc::channel(PROMPT_CAPACITY);
        (
            tx,
            Arc::new(Self {
                answers: Mutex::new(rx),
                next: AtomicU64::new(1),
                outstanding: AtomicUsize::new(0),
            }),
        )
    }

    /// Whether a question is on screen, waiting for a person to answer it.
    #[must_use]
    pub fn awaiting_answer(&self) -> bool {
        self.outstanding.load(Ordering::Acquire) > 0
    }

    /// Raises a prompt and waits for its answer.
    ///
    /// `text` carries the one datum the interface cannot derive from `kind` —
    /// for both of this crate's prompts, the address being connected to. It is
    /// never a secret and never markup.
    ///
    /// Answers to earlier prompts that arrive late are discarded rather than
    /// mistaken for this one: a password typed into the wrong dialog would
    /// otherwise be sent to the wrong challenge.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::AuthCancelled`] if the user dismissed the prompt or
    /// the interface went away; [`ProtocolError::EventStreamClosed`] if the
    /// question could not be delivered.
    pub async fn ask(
        &self,
        events: &EventSink,
        kind: PromptKind,
        text: String,
        echo: bool,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let id = PromptId::new(self.next.fetch_add(1, Ordering::Relaxed));
        // Raised before the question is delivered and released on every exit
        // from this function, cancellation included: the deadline consults it,
        // and a counter left raised would suspend that deadline for the rest
        // of the attempt.
        let _outstanding = Outstanding::raise(&self.outstanding);
        events
            .send(SessionEvent::Prompt(Prompt {
                id,
                kind,
                text,
                echo,
            }))
            .await?;

        let mut answers = self.answers.lock().await;
        loop {
            let Some(answer) = answers.recv().await else {
                return Err(ProtocolError::AuthCancelled);
            };
            if answer.id() != id {
                tracing::debug!(
                    expected = %id,
                    received = %answer.id(),
                    "discarding an answer to a prompt that is no longer open"
                );
                continue;
            }
            if answer.is_cancelled() {
                return Err(ProtocolError::AuthCancelled);
            }
            // The one copy this crate makes of a typed secret, into a buffer
            // that zeroes itself.
            let secret = answer.with_secret(&mut |bytes| Zeroizing::new(bytes.to_vec()));
            return secret.ok_or(ProtocolError::AuthCancelled);
        }
    }

    /// Asks a yes/no question and reads the answer as a decision.
    ///
    /// Anything that is not an explicit `yes` is a no. A prompt the user
    /// dismissed, closed or ignored must never be read as consent — which is
    /// the entire reason a certificate prompt has no default.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::EventStreamClosed`] if the question could not be
    /// delivered. A cancelled prompt is `Ok(false)`, not an error: declining
    /// is a valid answer.
    pub async fn confirm(
        &self,
        events: &EventSink,
        kind: PromptKind,
        text: String,
    ) -> Result<bool, ProtocolError> {
        match self.ask(events, kind, text, true).await {
            Ok(answer) => Ok(is_affirmative(&answer)),
            Err(ProtocolError::AuthCancelled) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

impl fmt::Debug for PromptChannel {
    /// Hand-written, and it stays hand-written: a derived `Debug` on a struct
    /// holding a receiver of answers is one refactor away from printing one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PromptChannel")
            .field(
                "raised",
                &self.next.load(Ordering::Relaxed).saturating_sub(1),
            )
            .finish()
    }
}

/// Exactly `yes`, case-insensitively, with surrounding whitespace forgiven.
///
/// Not "anything non-empty": a dialog dismissed with a stray keystroke must
/// not read as consent to a certificate the user never looked at.
fn is_affirmative(answer: &[u8]) -> bool {
    core::str::from_utf8(answer).is_ok_and(|text| text.trim().eq_ignore_ascii_case("yes"))
}

/// Counts one question that is on screen, and stops counting it on drop.
///
/// A guard rather than a pair of `fetch_add`/`fetch_sub` calls because
/// [`PromptChannel::ask`] can be dropped mid-await — a cancelled tab, a
/// deadline elsewhere — and a counter that only comes down on the happy path
/// would suspend the connection deadline forever.
struct Outstanding<'a>(&'a AtomicUsize);

impl<'a> Outstanding<'a> {
    fn raise(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self(counter)
    }
}

impl Drop for Outstanding<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
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
    use remoter_proto::event_channel;

    #[tokio::test]
    async fn an_answer_reaches_the_question_that_asked_it() {
        let (sender, prompts) = PromptChannel::new();
        let (events, mut rx) = event_channel(8);

        let asking = tokio::spawn(async move {
            prompts
                .ask(&events, PromptKind::Password, "ts-01".to_owned(), false)
                .await
        });

        let Some(SessionEvent::Prompt(prompt)) = rx.recv().await else {
            panic!("no prompt was raised");
        };
        sender
            .send(PromptAnswer::new(prompt.id, b"hunter2".to_vec()))
            .await
            .unwrap();

        let answer = asking.await.unwrap().unwrap();
        assert_eq!(answer.as_slice(), b"hunter2");
    }

    #[tokio::test]
    async fn an_answer_to_a_prompt_that_is_no_longer_open_is_discarded() {
        // A password typed into a dialog that has already closed must not be
        // delivered to the next question, whatever that question is.
        let (sender, prompts) = PromptChannel::new();
        let (events, mut rx) = event_channel(8);

        let stale = PromptId::new(999);
        sender
            .send(PromptAnswer::new(stale, b"the wrong secret".to_vec()))
            .await
            .unwrap();

        let asking = tokio::spawn(async move {
            prompts
                .ask(&events, PromptKind::Password, "ts-01".to_owned(), false)
                .await
        });

        let Some(SessionEvent::Prompt(prompt)) = rx.recv().await else {
            panic!("no prompt was raised");
        };
        sender
            .send(PromptAnswer::new(prompt.id, b"the right secret".to_vec()))
            .await
            .unwrap();

        assert_eq!(
            asking.await.unwrap().unwrap().as_slice(),
            b"the right secret"
        );
    }

    #[tokio::test]
    async fn a_dismissed_confirmation_is_a_no_and_not_an_error() {
        let (sender, prompts) = PromptChannel::new();
        let (events, mut rx) = event_channel(8);

        let asking = tokio::spawn(async move {
            prompts
                .confirm(
                    &events,
                    PromptKind::Certificate {
                        fingerprint: "SHA256:...".to_owned(),
                        reason: "self-signed".to_owned(),
                    },
                    "ts-01".to_owned(),
                )
                .await
        });

        let Some(SessionEvent::Prompt(prompt)) = rx.recv().await else {
            panic!("no prompt was raised");
        };
        sender
            .send(PromptAnswer::cancelled(prompt.id))
            .await
            .unwrap();

        assert!(!asking.await.unwrap().unwrap());
    }

    #[test]
    fn only_the_word_yes_is_consent() {
        assert!(is_affirmative(b"yes"));
        assert!(is_affirmative(b"  YES \n"));
        // A stray keystroke, an accidental Return, an empty answer: none of
        // these is a person having read a fingerprint.
        assert!(!is_affirmative(b""));
        assert!(!is_affirmative(b"y"));
        assert!(!is_affirmative(b"no"));
        assert!(!is_affirmative(b"ok"));
        assert!(!is_affirmative(&[0xff, 0xfe]));
    }

    #[tokio::test]
    async fn the_outstanding_counter_comes_back_down_when_a_question_is_abandoned() {
        // The connection deadline is suspended while a question is on screen.
        // A counter that only fell on the happy path would suspend it forever
        // and leave a tab open on a server that never answers.
        let (_sender, prompts) = PromptChannel::new();
        let (events, mut rx) = event_channel(8);
        assert!(!prompts.awaiting_answer());

        let asking = {
            let prompts = Arc::clone(&prompts);
            tokio::spawn(async move {
                prompts
                    .ask(&events, PromptKind::Password, String::new(), false)
                    .await
            })
        };
        let _ = rx.recv().await;
        assert!(prompts.awaiting_answer());

        asking.abort();
        let _ = asking.await;
        // The guard runs on drop, including the drop a cancelled task causes.
        assert!(!prompts.awaiting_answer());
    }

    #[test]
    fn the_channel_never_debug_prints_an_answer() {
        let (_sender, prompts) = PromptChannel::new();
        assert_eq!(format!("{prompts:?}"), "PromptChannel { raised: 0 }");
    }
}
