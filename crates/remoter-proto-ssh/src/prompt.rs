//! Asking the user something, mid-handshake.
//!
//! Three of SSH's questions cannot be answered from stored state: an unknown
//! host key, a key passphrase, and a keyboard-interactive challenge — which is
//! where a 2FA code arrives. `docs/architecture/session-pipeline.md` §5–6 says
//! these **suspend** the pipeline and surface as events, and that the answers
//! come back over a channel of their own rather than through the event stream.
//!
//! [`remoter_proto::Protocol::connect`] takes an [`EventSink`] but no receiver,
//! because a protocol that raises no prompts should not have to hold one. This
//! module supplies the other half: the caller builds a [`PromptChannel`],
//! forwards every [`remoter_proto::SessionCommand::Prompt`] it sees into the
//! sender, and hands the channel to the adapter.
//!
//! An answer is a credential typed a moment ago, so it is treated as one: it
//! lives in a [`Zeroizing`] buffer, is never formatted, and is dropped as soon
//! as the challenge it answers is over.

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
    /// Read by [`crate::connection`]: the handshake deadline must cover the
    /// network, not the human. `docs/security/transport-security.md` exists to
    /// make people compare a fingerprint out of band, and comparing one takes
    /// longer than the thirty seconds the failure taxonomy allows a *server*
    /// to answer in.
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
    ///
    /// The handshake deadline is suspended while this is true; see
    /// [`crate::connection::with_deadline`].
    #[must_use]
    pub fn awaiting_answer(&self) -> bool {
        self.outstanding.load(Ordering::Acquire) > 0
    }

    /// Raises a prompt and waits for its answer.
    ///
    /// `text` carries the one datum the interface cannot derive from `kind`;
    /// what that is per prompt is documented where the prompt is raised. It is
    /// never a secret and never markup — for keyboard-interactive it is text
    /// the *server* wrote, and must be rendered as text.
    ///
    /// Answers to earlier prompts that arrive late are discarded rather than
    /// mistaken for this one: a 2FA code typed into the wrong dialog would
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
        // from this function, cancellation included: the handshake deadline
        // consults it, and a counter left raised would suspend that deadline
        // for the rest of the attempt.
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
            // that zeroes itself. `PromptAnswer` lends rather than gives, and
            // `russh` needs an owned value to put on the wire.
            let secret = answer.with_secret(&mut |bytes| Zeroizing::new(bytes.to_vec()));
            return secret.ok_or(ProtocolError::AuthCancelled);
        }
    }

    /// Asks a yes/no question and reads the answer as a decision.
    ///
    /// Anything that is not an explicit `yes` is a no. A prompt the user
    /// dismissed, closed or ignored must never be read as consent — which is
    /// the entire reason a host key prompt has no default.
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

/// Counts one question that is on screen, and stops counting it on drop.
///
/// A guard rather than a pair of `fetch_add`/`fetch_sub` calls because
/// [`PromptChannel::ask`] can be dropped mid-await — a cancelled tab, a
/// deadline elsewhere — and a counter that only comes down on the happy path
/// would suspend the handshake deadline indefinitely.
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

/// The accepted spellings of "yes".
///
/// ASCII and fixed: this is a protocol token the interface sends, not
/// something a user types in their own language. The interface shows a button
/// and sends `yes`; the message on that button is the catalogue's business.
fn is_affirmative(answer: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(answer) else {
        return false;
    };
    matches!(text.trim().to_ascii_lowercase().as_str(), "yes" | "y")
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

    fn host_key_prompt() -> PromptKind {
        PromptKind::HostKey {
            host: "db-01.internal:22".to_owned(),
            algorithm: "ssh-ed25519".to_owned(),
            fingerprint: "SHA256:AAAA".to_owned(),
            randomart: String::new(),
            previously_trusted: None,
        }
    }

    #[tokio::test]
    async fn an_answer_reaches_the_asker() {
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();

        let asking = tokio::spawn({
            let prompts = Arc::clone(&prompts);
            async move {
                prompts
                    .ask(&events, PromptKind::Password, "ada@host".to_owned(), false)
                    .await
            }
        });

        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        assert!(!prompt.echo, "a password prompt must not be echoed");
        tx.send(PromptAnswer::new(prompt.id, b"hunter2".to_vec()))
            .await
            .unwrap();

        let answer = asking.await.unwrap().unwrap();
        assert_eq!(answer.as_slice(), b"hunter2");
    }

    #[tokio::test]
    async fn a_stale_answer_is_discarded_rather_than_used() {
        // A 2FA code typed into a dialog that has already been superseded must
        // not be sent to the challenge that replaced it.
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();

        let asking = tokio::spawn({
            let prompts = Arc::clone(&prompts);
            async move {
                prompts
                    .ask(&events, PromptKind::KeyPassphrase, String::new(), false)
                    .await
            }
        });

        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        tx.send(PromptAnswer::new(PromptId::new(9999), b"stale".to_vec()))
            .await
            .unwrap();
        tx.send(PromptAnswer::new(prompt.id, b"current".to_vec()))
            .await
            .unwrap();

        assert_eq!(asking.await.unwrap().unwrap().as_slice(), b"current");
    }

    #[tokio::test]
    async fn a_cancelled_prompt_is_a_cancelled_authentication() {
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();

        let asking = tokio::spawn({
            let prompts = Arc::clone(&prompts);
            async move {
                prompts
                    .ask(&events, PromptKind::Password, String::new(), false)
                    .await
            }
        });

        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        tx.send(PromptAnswer::cancelled(prompt.id)).await.unwrap();

        let error = asking.await.unwrap().unwrap_err();
        assert!(matches!(error, ProtocolError::AuthCancelled));
    }

    #[tokio::test]
    async fn an_interface_that_went_away_cancels_rather_than_hangs() {
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        drop(tx);

        let error = prompts
            .ask(&events, PromptKind::Password, String::new(), false)
            .await
            .unwrap_err();
        assert!(matches!(error, ProtocolError::AuthCancelled));
        assert!(rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn only_an_explicit_yes_is_consent() {
        for (answer, expected) in [
            (&b"yes"[..], true),
            (b"Y", true),
            (b" yes \n", true),
            (b"no", false),
            (b"", false),
            (b"yes please", false),
            (&[0xff][..], false),
        ] {
            let (events, mut rx) = event_channel(8);
            let (tx, prompts) = PromptChannel::new();
            let asking = tokio::spawn({
                let prompts = Arc::clone(&prompts);
                async move {
                    prompts
                        .confirm(&events, host_key_prompt(), String::new())
                        .await
                }
            });
            let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
                panic!("expected a prompt event");
            };
            tx.send(PromptAnswer::new(prompt.id, answer.to_vec()))
                .await
                .unwrap();
            assert_eq!(
                asking.await.unwrap().unwrap(),
                expected,
                "answer {answer:?} read wrongly"
            );
        }
    }

    #[tokio::test]
    async fn a_dismissed_confirmation_is_a_no_not_a_failure() {
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        let asking = tokio::spawn({
            let prompts = Arc::clone(&prompts);
            async move {
                prompts
                    .confirm(&events, host_key_prompt(), String::new())
                    .await
            }
        });
        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        tx.send(PromptAnswer::cancelled(prompt.id)).await.unwrap();
        assert!(!asking.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn prompt_ids_are_distinct_within_a_session() {
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        let mut seen = Vec::new();
        for _ in 0..3 {
            let asking = tokio::spawn({
                let prompts = Arc::clone(&prompts);
                let events = events.clone();
                async move {
                    prompts
                        .ask(&events, PromptKind::Password, String::new(), false)
                        .await
                }
            });
            let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
                panic!("expected a prompt event");
            };
            seen.push(prompt.id);
            tx.send(PromptAnswer::new(prompt.id, b"x".to_vec()))
                .await
                .unwrap();
            asking.await.unwrap().unwrap();
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 3);
    }

    #[tokio::test]
    async fn an_outstanding_question_is_visible_while_it_is_on_screen() {
        // The handshake deadline reads this to tell "the server has not
        // answered" from "the user is comparing a fingerprint".
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        assert!(!prompts.awaiting_answer());

        let asking = tokio::spawn({
            let prompts = Arc::clone(&prompts);
            async move {
                prompts
                    .ask(&events, host_key_prompt(), String::new(), true)
                    .await
            }
        });

        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        while !prompts.awaiting_answer() {
            tokio::task::yield_now().await;
        }

        tx.send(PromptAnswer::new(prompt.id, b"yes".to_vec()))
            .await
            .unwrap();
        asking.await.unwrap().unwrap();
        assert!(
            !prompts.awaiting_answer(),
            "an answered question must stop suspending the deadline"
        );
    }

    #[tokio::test]
    async fn an_abandoned_question_stops_being_outstanding() {
        // `ask` is dropped whenever the attempt around it is cancelled. A
        // counter that only came down on the happy path would suspend the
        // handshake deadline for the rest of the process's life.
        let (events, mut rx) = event_channel(8);
        let (_tx, prompts) = PromptChannel::new();

        let asking = tokio::spawn({
            let prompts = Arc::clone(&prompts);
            async move {
                prompts
                    .ask(&events, host_key_prompt(), String::new(), true)
                    .await
            }
        });
        rx.recv().await.unwrap();
        while !prompts.awaiting_answer() {
            tokio::task::yield_now().await;
        }

        asking.abort();
        assert!(asking.await.unwrap_err().is_cancelled());
        assert!(!prompts.awaiting_answer());
    }

    #[test]
    fn debug_shows_a_count_and_no_answers() {
        let (_tx, prompts) = PromptChannel::new();
        assert_eq!(format!("{prompts:?}"), "PromptChannel { raised: 0 }");
    }
}
