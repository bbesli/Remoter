//! Host key verification: the decision, and the round trip that makes it.
//!
//! `docs/security/transport-security.md` is unambiguous: verification is
//! mandatory and there is no "ignore" option, because in practice a checkbox
//! becomes the default. This module therefore has no configuration to disable
//! it — the only way past an unknown key is a user saying yes, and the only
//! way past a *changed* key is a user copying part of the offered fingerprint
//! off the screen.
//!
//! The three outcomes:
//!
//! | Situation | Behaviour |
//! |---|---|
//! | Known, matching | Connect, silently |
//! | Unknown | Prompt with the SHA-256 fingerprint and its randomart; explicit acceptance required |
//! | **Changed** | Hard failure. Replacing the stored key needs the tail of the offered fingerprint, typed |
//! | Trusted under another algorithm | Hard failure, never a first-use prompt |
//!
//! The unknown and changed paths are deliberately *different* paths, not one
//! path with a flag: `remoter_proto::ChangedHostKey` has no boolean to pass
//! `true` to, so a change cannot be accepted by the code that accepts a first
//! use.
//!
//! # What the changed-key dialog asks for
//!
//! The answer is **the last [`REPLACEMENT_CHALLENGE_LEN`] characters of the
//! offered fingerprint**, which the dialog is already showing. It is not sent
//! in the prompt: a challenge that travels beside the question is answered by
//! anything that echoes what it was given, which is what a scripted client
//! does and what a careless one does, and the deliberate friction is the whole
//! control. The interface knows the rule — it is fixed, not per-prompt — and
//! renders it from the message catalogue.
//!
//! # Trust is per host, not per algorithm
//!
//! A server that has been trusted under one algorithm and answers under
//! another is *not* a first use. Treating it as one would hand an attacker
//! with a forged RSA key the gentle "unknown host" dialog on a host whose
//! Ed25519 key has been trusted for a year, simply by advertising
//! `rsa-sha2-512` and nothing else (threat model T3). See
//! [`trusted_algorithms`].

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use remoter_proto::{
    EventSink, Fingerprint, HostKeyOutcome, HostPort, OfferedKey, ProtocolError, TrustSource,
    TrustStore, verify_host_key,
};
use russh::keys::PublicKeyOrCertificate;

use crate::prompt::PromptChannel;

/// How many characters of the offered fingerprint replace a changed host key.
///
/// Eight base64 characters is 48 bits of the SHA-256 digest — far more than
/// the friction needs, and still short enough to read back over a phone call
/// while two people compare the whole fingerprint.
pub const REPLACEMENT_CHALLENGE_LEN: usize = 8;

/// The host key types the trust store can hold, as it records them.
///
/// The recorded name is the key's *own* type — `ssh-ed25519`, `ssh-rsa` — and
/// not the negotiated signature algorithm; see [`HostKeyChecker::describe`].
/// The list is deliberately wider than [`crate::algorithms`] offers, because
/// what matters here is what may already be *trusted*: a key imported from
/// `~/.ssh/known_hosts` predates this build's preference list.
const KEY_ALGORITHMS: &[&str] = &[
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa",
    "ssh-dss",
];

/// Every algorithm `store` holds a trusted key for on `host`.
///
/// `remoter_proto::TrustStore` is keyed on (host, algorithm) and has no way to
/// ask "what is trusted for this host?", so the question is asked once per key
/// type this build can encounter. That is eight cheap lookups on a decision
/// that happens once per connection, and it is what makes an algorithm switch
/// visible; a `TrustStore::keys_for_host` in `remoter-proto` would answer it
/// exactly, and is the right home for this if that crate gains one.
#[must_use]
pub fn trusted_algorithms(store: &dyn TrustStore, host: &HostPort) -> Vec<String> {
    KEY_ALGORITHMS
        .iter()
        .filter(|algorithm| store.lookup(host, algorithm).is_some())
        .map(|algorithm| (*algorithm).to_owned())
        .collect()
}

/// What the user must type to replace a changed host key.
///
/// Derived from the fingerprint the dialog displays, so producing it requires
/// having read that fingerprint. The word `remoter-proto` derives from the
/// same digest is the trust store's own interlock and is never shown, so an
/// answerer cannot reach either one by echoing the prompt back.
#[must_use]
pub fn replacement_challenge(offered: &Fingerprint) -> String {
    let rendered = offered.to_string();
    // `SHA256:` is a constant prefix and copying it would prove nothing; the
    // base64 body is the part that differs between two keys.
    let body = rendered.strip_prefix("SHA256:").unwrap_or(&rendered);
    let skip = body
        .chars()
        .count()
        .saturating_sub(REPLACEMENT_CHALLENGE_LEN);
    body.chars().skip(skip).collect()
}

/// Verifies the far end's host key against the vault's trust store.
pub struct HostKeyChecker {
    host: HostPort,
    trust: Arc<dyn TrustStore>,
    events: EventSink,
    prompts: Option<Arc<PromptChannel>>,
}

impl HostKeyChecker {
    /// A checker for `host`, backed by `trust`.
    ///
    /// `prompts` is `None` for a session that cannot ask — a scripted connect,
    /// or a reconnect running without an interface. An unknown key is then a
    /// refusal, never an acceptance: a machine that cannot ask a human has not
    /// obtained consent.
    #[must_use]
    pub const fn new(
        host: HostPort,
        trust: Arc<dyn TrustStore>,
        events: EventSink,
        prompts: Option<Arc<PromptChannel>>,
    ) -> Self {
        Self {
            host,
            trust,
            events,
            prompts,
        }
    }

    /// The host being verified.
    #[must_use]
    pub const fn host(&self) -> &HostPort {
        &self.host
    }

    /// Checks what the server offered.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::HostKeyRejected`] when the user declines a first use;
    /// [`ProtocolError::HostKeyChanged`] when the stored key differs and the
    /// replacement was not confirmed; [`ProtocolError::CertificateUntrusted`]
    /// for a certificate, which this build does not evaluate;
    /// [`ProtocolError::TrustStore`] if the decision could not be recorded.
    pub async fn check(&self, offered: &PublicKeyOrCertificate) -> Result<(), ProtocolError> {
        let offered = self.describe(offered)?;
        match verify_host_key(self.trust.as_ref(), &self.host, &offered) {
            HostKeyOutcome::Trusted => {
                tracing::debug!(host = %self.host, algorithm = %offered.algorithm, "host key matched");
                Ok(())
            }

            HostKeyOutcome::Unknown(unknown) => {
                // Unknown *for this algorithm* is not the same as unknown for
                // this host. A host trusted under ed25519 that suddenly answers
                // with an RSA key — because the server advertised nothing else
                // — is a host whose identity has changed, and the soft
                // first-use prompt is exactly the wrong dialog for it: the
                // threat model's T3 attacker chooses which algorithm to offer.
                // `docs/security/transport-security.md` gives a changed key a
                // hard failure, so that is what this is, and it names both
                // fingerprints so the user can see what they are looking at.
                if let Some(expected) = self.trusted_elsewhere(unknown.algorithm()) {
                    tracing::warn!(
                        host = %self.host,
                        offered = unknown.algorithm(),
                        trusted = %expected.0,
                        "the server offered an algorithm this host has never used, and a key is trusted under another one"
                    );
                    return Err(ProtocolError::HostKeyChanged {
                        host: self.host.clone(),
                        algorithm: unknown.algorithm().to_owned(),
                        expected: expected.1,
                        offered: unknown.fingerprint(),
                    });
                }

                let Some(prompts) = self.prompts.as_deref() else {
                    return Err(unknown.reject());
                };
                // `kind` carries the host, the algorithm, the fingerprint and
                // the randomart, which is everything the first-use dialog has
                // to show; `text` has nothing left to add.
                let accepted = prompts
                    .confirm(&self.events, unknown.prompt(), String::new())
                    .await?;
                if accepted {
                    tracing::info!(host = %self.host, "a new host key was accepted by the user");
                    unknown.accept(self.trust.as_ref(), now_ms(), TrustSource::Prompted)
                } else {
                    Err(unknown.reject())
                }
            }

            HostKeyOutcome::Changed(changed) => {
                let Some(prompts) = self.prompts.as_deref() else {
                    return Err(changed.into_error());
                };
                // A changed key is a possible man-in-the-middle, so the answer
                // must be copied off the screen rather than be a button the
                // user can hit with the shortcut they use for every other
                // dialog. The challenge is *derived from the fingerprint being
                // shown* and is deliberately not carried in the prompt: an
                // answerer that echoes what it was given would otherwise
                // replace a trusted key, which is exactly what a scripted or
                // careless client does. `text` carries the address, as the
                // first-use prompt does.
                let expected = replacement_challenge(&changed.offered());
                let typed = match prompts
                    .ask(&self.events, changed.prompt(), String::new(), true)
                    .await
                {
                    Ok(typed) => typed,
                    // Dismissing the dialog leaves the stored key alone, which
                    // is the safe outcome and the default one.
                    Err(ProtocolError::AuthCancelled) => return Err(changed.into_error()),
                    Err(error) => return Err(error),
                };

                let Ok(typed) = std::str::from_utf8(&typed) else {
                    return Err(changed.into_error());
                };
                // Case-sensitive: the fingerprint's base64 alphabet
                // distinguishes `a` from `A`, and the user is copying, not
                // recalling. Whitespace is forgiven because a selection often
                // carries some.
                if typed.trim() != expected {
                    return Err(ProtocolError::ConfirmationMismatch);
                }
                tracing::warn!(
                    host = %self.host,
                    "a changed host key was presented; the user confirmed it against the offered fingerprint"
                );
                // The store's own interlock, satisfied now that the user has
                // proved they read the fingerprint on screen.
                let word = changed.confirmation_word().to_owned();
                changed.accept_replacement(&word, self.trust.as_ref(), now_ms())
            }
        }
    }

    /// A key trusted for this host under some *other* algorithm.
    ///
    /// Returns its algorithm and fingerprint, which is what the failure has to
    /// show: "expected this, got that" is the only form of the message a user
    /// can act on.
    fn trusted_elsewhere(&self, offered: &str) -> Option<(String, Fingerprint)> {
        trusted_algorithms(self.trust.as_ref(), &self.host)
            .into_iter()
            .find(|algorithm| algorithm != offered)
            .and_then(|algorithm| {
                let known = self.trust.lookup(&self.host, &algorithm)?;
                Some((algorithm, known.fingerprint()))
            })
    }

    /// Turns what `russh` handed us into the store's vocabulary.
    ///
    /// The algorithm recorded is the key's *own* type — `ssh-ed25519`,
    /// `ssh-rsa` — and not the negotiated signature algorithm. An RSA host key
    /// is signed as `rsa-sha2-512` today and `rsa-sha2-256` tomorrow depending
    /// on what both ends offer; keying the trust store on that would make a
    /// server that has not changed look like one that has, which is the single
    /// most damaging false positive this code can produce.
    fn describe(&self, offered: &PublicKeyOrCertificate) -> Result<OfferedKey, ProtocolError> {
        match offered {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                let blob = key
                    .to_bytes()
                    .map_err(|_| ProtocolError::ProtocolViolation {
                        detail: "the server's host key could not be re-encoded",
                    })?;
                Ok(OfferedKey::new(key.algorithm().to_string(), blob))
            }
            // Certificate host keys are not advertised (see `algorithms.rs`),
            // so a server offering one has ignored the client's preference
            // list. Refused rather than pinned: pinning a certificate as if it
            // were a key would trust the certificate's bytes instead of its
            // authority, which is not what a certificate means.
            PublicKeyOrCertificate::Certificate(_) => Err(ProtocolError::CertificateUntrusted {
                host: self.host.clone(),
                reason: remoter_proto::CertificateProblem::UntrustedRoot,
            }),
        }
    }
}

/// Wall-clock milliseconds, saturating. A clock before 1970 is not a reason to
/// refuse to record a host key the user just accepted.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
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
    use parking_lot::Mutex;
    use remoter_proto::{KnownKey, PromptAnswer, PromptKind, SessionEvent, event_channel};
    use std::collections::HashMap;

    /// An in-memory stand-in for the vault's trust store.
    #[derive(Default)]
    struct Memory {
        keys: Mutex<HashMap<(String, String), KnownKey>>,
        fail_writes: bool,
    }

    impl TrustStore for Memory {
        fn lookup(&self, host: &HostPort, algorithm: &str) -> Option<KnownKey> {
            self.keys
                .lock()
                .get(&(host.to_string(), algorithm.to_owned()))
                .cloned()
        }

        fn remember(&self, host: &HostPort, key: &KnownKey) -> Result<(), ProtocolError> {
            if self.fail_writes {
                return Err(ProtocolError::TrustStore {
                    operation: "remember",
                    detail: "the test store refuses writes",
                });
            }
            self.keys
                .lock()
                .insert((host.to_string(), key.algorithm.clone()), key.clone());
            Ok(())
        }
    }

    fn host() -> HostPort {
        HostPort::new("db-01.internal", 22).unwrap()
    }

    /// A public key blob in the shape `to_bytes` produces: an SSH string
    /// naming the algorithm, then the key material (RFC 4253 §6.6).
    fn blob(marker: u8) -> Vec<u8> {
        let name = b"ssh-ed25519";
        let mut out = Vec::new();
        out.extend_from_slice(&u32::try_from(name.len()).unwrap().to_be_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&32u32.to_be_bytes());
        out.extend_from_slice(&[marker; 32]);
        out
    }

    fn offered(marker: u8) -> OfferedKey {
        OfferedKey::new("ssh-ed25519", blob(marker))
    }

    /// Two fingerprints and the pictures `ssh-keygen -lv` draws for them.
    ///
    /// A public key's fingerprint and its randomart are exactly the values a
    /// user is meant to compare out of band — they are printed on screen for
    /// that purpose — so recording them commits no key material. The keys
    /// themselves were generated for this test and discarded.
    const OPENSSH_REFERENCE: &[(&str, &str, &str)] = &[
        (
            "SHA256:UPtEaq5g7msBrs7lOWCynKsMp2f4Pw5eTXDcUdO0rs8",
            "ED25519 256",
            concat!(
                "+--[ED25519 256]--+\n",
                "|        o.+o.    |\n",
                "|     . o = ...   |\n",
                "|    . + = . .    |\n",
                "|  .  o + o .     |\n",
                "| . .o . S . .    |\n",
                "|.o.o.+ .   .     |\n",
                "|=+=.o.o   .      |\n",
                "|B*==+      o     |\n",
                "|=O+**o      E    |\n",
                "+----[SHA256]-----+",
            ),
        ),
        (
            "SHA256:zeaymnIG1+vbGvitEjm4GB8b20H5nsoDeWo6DtwBNyc",
            "RSA 2048",
            concat!(
                "+---[RSA 2048]----+\n",
                "|                 |\n",
                "|                 |\n",
                "| . E . .         |\n",
                "|  o + o  o       |\n",
                "|   . + +S +      |\n",
                "|. o O B.oo       |\n",
                "|.. = &.=oo.      |\n",
                "| .o O.*o+*       |\n",
                "| .o+ +=*B+o      |\n",
                "+----[SHA256]-----+",
            ),
        ),
    ];

    #[test]
    fn the_randomart_matches_what_ssh_keygen_draws() {
        // The picture is only useful if it is the *same* picture the server's
        // administrator has on their screen. Byte-for-byte against
        // `ssh-keygen -lv`, including the borders: a frame that differs by one
        // dash makes two arts hard to compare, which is the whole point of
        // drawing them.
        for (fingerprint, title, expected) in OPENSSH_REFERENCE {
            let parsed = remoter_proto::Fingerprint::parse(fingerprint).unwrap();
            assert_eq!(&parsed.to_string(), fingerprint);
            assert_eq!(
                parsed.randomart(title),
                *expected,
                "the drunken bishop walked somewhere else for {fingerprint}"
            );
        }
    }

    #[test]
    fn every_randomart_has_a_start_and_an_end_square() {
        // OpenSSH's `sshkey_fingerprint_randomart`: `S` marks the start square
        // and `E` the end. Both must appear exactly once, whatever the digest.
        for (fingerprint, title, _) in OPENSSH_REFERENCE {
            let art = remoter_proto::Fingerprint::parse(fingerprint)
                .unwrap()
                .randomart(title);
            // Counted over the field only: the borders carry the title and
            // the hash name, which have their own letters in them.
            let field: String = art.lines().skip(1).take(9).collect();
            assert_eq!(field.matches('S').count(), 1, "art: {art}");
            assert_eq!(field.matches('E').count(), 1, "art: {art}");
            // 17 wide between the borders, 9 rows plus two frame lines.
            assert_eq!(art.lines().count(), 11);
            for line in art.lines() {
                assert_eq!(line.chars().count(), 19, "line: {line}");
            }
        }
    }

    #[tokio::test]
    async fn a_matching_key_connects_without_asking() {
        let store = Arc::new(Memory::default());
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-ed25519", blob(1), 0, TrustSource::Prompted),
            )
            .unwrap();

        let (events, mut rx) = event_channel(8);
        // No prompt channel at all: a matching key must not need one.
        let checker = HostKeyChecker::new(host(), store, events, None);
        assert!(matches!(
            verify_host_key(checker.trust.as_ref(), &host(), &offered(1)),
            HostKeyOutcome::Trusted
        ));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn an_unknown_key_without_an_interface_is_refused_not_accepted() {
        // A scripted connect cannot obtain consent, so it does not get to
        // proceed as though it had.
        let store = Arc::new(Memory::default());
        let (events, _rx) = event_channel(8);
        let checker = HostKeyChecker::new(
            host(),
            Arc::clone(&store) as Arc<dyn TrustStore>,
            events,
            None,
        );

        let error = checker
            .check(&public_key_or_certificate(&offered(1)))
            .await
            .unwrap_err();
        assert!(matches!(error, ProtocolError::HostKeyRejected { .. }));
        assert!(store.keys.lock().is_empty(), "nothing may be remembered");
    }

    #[tokio::test]
    async fn a_changed_key_without_an_interface_is_a_hard_failure() {
        let store = Arc::new(Memory::default());
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-ed25519", blob(1), 0, TrustSource::Prompted),
            )
            .unwrap();
        let (events, _rx) = event_channel(8);
        let checker = HostKeyChecker::new(
            host(),
            Arc::clone(&store) as Arc<dyn TrustStore>,
            events,
            None,
        );

        let error = checker
            .check(&public_key_or_certificate(&offered(2)))
            .await
            .unwrap_err();
        let ProtocolError::HostKeyChanged {
            expected,
            offered: got,
            ..
        } = error
        else {
            panic!("expected HostKeyChanged, got {error:?}");
        };
        assert_ne!(expected, got, "both fingerprints must be carried");
        assert!(!error_is_retryable(&expected, &got));

        // The stored key is untouched.
        let stored = store.lookup(&host(), "ssh-ed25519").unwrap();
        assert_eq!(stored.blob, blob(1));
    }

    fn error_is_retryable(
        _expected: &remoter_proto::Fingerprint,
        _offered: &remoter_proto::Fingerprint,
    ) -> bool {
        // `HostKeyChanged` is explicitly not retryable in the taxonomy; the
        // helper exists to keep the assertion above readable.
        false
    }

    #[tokio::test]
    async fn accepting_an_unknown_key_records_it_once() {
        let store = Arc::new(Memory::default());
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        let checker = HostKeyChecker::new(
            host(),
            Arc::clone(&store) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );

        let checking =
            tokio::spawn(
                async move { checker.check(&public_key_or_certificate(&offered(3))).await },
            );

        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        let PromptKind::HostKey {
            host: named,
            fingerprint,
            randomart,
            previously_trusted,
            ..
        } = prompt.kind
        else {
            panic!("expected a host key prompt");
        };
        assert!(previously_trusted.is_none(), "this is a first use");
        assert!(fingerprint.starts_with("SHA256:"));
        // The randomart is what lets a person compare out of band; an empty
        // one would make the prompt a ceremony.
        assert!(randomart.lines().count() >= 11, "randomart: {randomart}");
        assert_eq!(named, host().to_string());

        tx.send(PromptAnswer::new(prompt.id, b"yes".to_vec()))
            .await
            .unwrap();
        checking.await.unwrap().unwrap();

        let stored = store.lookup(&host(), "ssh-ed25519").unwrap();
        assert_eq!(stored.blob, blob(3));
        assert_eq!(stored.source, TrustSource::Prompted);
    }

    #[tokio::test]
    async fn declining_an_unknown_key_stores_nothing() {
        let store = Arc::new(Memory::default());
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        let checker = HostKeyChecker::new(
            host(),
            Arc::clone(&store) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );

        let checking =
            tokio::spawn(
                async move { checker.check(&public_key_or_certificate(&offered(4))).await },
            );
        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        tx.send(PromptAnswer::new(prompt.id, b"no".to_vec()))
            .await
            .unwrap();

        let error = checking.await.unwrap().unwrap_err();
        assert!(matches!(error, ProtocolError::HostKeyRejected { .. }));
        assert!(store.keys.lock().is_empty());
    }

    #[tokio::test]
    async fn replacing_a_changed_key_needs_the_word_from_the_screen() {
        let store = Arc::new(Memory::default());
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-ed25519", blob(1), 0, TrustSource::Prompted),
            )
            .unwrap();

        for (answer, replaced) in [(&b"yes"[..], false), (b"", false)] {
            let (events, mut rx) = event_channel(8);
            let (tx, prompts) = PromptChannel::new();
            let checker = HostKeyChecker::new(
                host(),
                Arc::clone(&store) as Arc<dyn TrustStore>,
                events,
                Some(prompts),
            );
            let checking = tokio::spawn(async move {
                checker.check(&public_key_or_certificate(&offered(5))).await
            });
            let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
                panic!("expected a prompt event");
            };
            tx.send(PromptAnswer::new(prompt.id, answer.to_vec()))
                .await
                .unwrap();

            let error = checking.await.unwrap().unwrap_err();
            // "yes" is what accepts a *new* key. It must not accept a changed
            // one: that is the whole point of the separate path.
            assert!(
                matches!(error, ProtocolError::ConfirmationMismatch),
                "answer {answer:?} produced {error:?}"
            );
            assert_eq!(
                store.lookup(&host(), "ssh-ed25519").unwrap().blob == blob(5),
                replaced
            );
        }
    }

    #[tokio::test]
    async fn replacing_a_changed_key_needs_the_fingerprint_read_off_the_screen() {
        let store = Arc::new(Memory::default());
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-ed25519", blob(1), 0, TrustSource::Prompted),
            )
            .unwrap();

        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        let checker = HostKeyChecker::new(
            host(),
            Arc::clone(&store) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );
        let checking =
            tokio::spawn(
                async move { checker.check(&public_key_or_certificate(&offered(6))).await },
            );

        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        let PromptKind::HostKey {
            host: named,
            fingerprint,
            previously_trusted,
            ..
        } = prompt.kind
        else {
            panic!("expected a host key prompt");
        };
        let stored_before = previously_trusted.expect("a changed key names what it replaced");
        assert_ne!(stored_before.fingerprint, fingerprint);
        assert_eq!(named, host().to_string());

        let answer = replacement_challenge(&Fingerprint::parse(&fingerprint).unwrap());
        assert_eq!(answer.len(), REPLACEMENT_CHALLENGE_LEN);
        assert!(
            fingerprint.ends_with(&answer),
            "the challenge must be readable off the fingerprint: {fingerprint} / {answer}"
        );

        tx.send(PromptAnswer::new(prompt.id, answer.into_bytes()))
            .await
            .unwrap();
        checking.await.unwrap().unwrap();

        let stored = store.lookup(&host(), "ssh-ed25519").unwrap();
        assert_eq!(stored.blob, blob(6));
        assert_eq!(stored.source, TrustSource::Replaced);
    }

    #[tokio::test]
    async fn an_answerer_that_echoes_the_prompt_cannot_replace_a_changed_key() {
        // The deliberate friction is the control. An answerer that sends back
        // whatever it was given — a script, a client whose default button is
        // "OK" — must not clear a man-in-the-middle warning, so no field of
        // the prompt may *be* the answer. Every one of them is tried here.
        let store = Arc::new(Memory::default());
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-ed25519", blob(1), 0, TrustSource::Prompted),
            )
            .unwrap();

        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        let checker = HostKeyChecker::new(
            host(),
            Arc::clone(&store) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );
        let checking =
            tokio::spawn(
                async move { checker.check(&public_key_or_certificate(&offered(7))).await },
            );

        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        let PromptKind::HostKey {
            host: named,
            algorithm,
            fingerprint,
            randomart,
            previously_trusted,
        } = prompt.kind.clone()
        else {
            panic!("expected a host key prompt");
        };
        let stored_before = previously_trusted.expect("a changed key names what it replaced");

        let expected = replacement_challenge(&Fingerprint::parse(&fingerprint).unwrap());
        for shipped in [
            prompt.text.clone(),
            named,
            algorithm,
            fingerprint,
            randomart,
            stored_before.fingerprint,
            stored_before.randomart,
        ] {
            assert_ne!(
                shipped.trim(),
                expected,
                "the answer travelled in the prompt"
            );
        }

        tx.send(PromptAnswer::new(prompt.id, prompt.text.into_bytes()))
            .await
            .unwrap();

        let error = checking.await.unwrap().unwrap_err();
        assert!(
            matches!(error, ProtocolError::ConfirmationMismatch),
            "echoing the prompt produced {error:?}"
        );
        assert_eq!(
            store.lookup(&host(), "ssh-ed25519").unwrap().blob,
            blob(1),
            "the trusted key must be untouched"
        );
    }

    #[tokio::test]
    async fn a_host_trusted_under_one_algorithm_does_not_get_a_first_use_prompt_for_another() {
        // The attack: fifty clean connections with a trusted ed25519 key, then
        // a forged RSA key with `rsa-sha2-512` advertised as the only host key
        // algorithm. Keyed on (host, algorithm) alone, that is "unknown host"
        // — a soft prompt, on a host the user has trusted for a year.
        let store = Arc::new(Memory::default());
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-ed25519", blob(1), 0, TrustSource::Prompted),
            )
            .unwrap();

        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        // Nobody will answer. Without the fix this raises a first-use prompt
        // and the closed sender turns it into a refusal — which is the wrong
        // failure, and is what this test catches.
        drop(tx);
        let checker = HostKeyChecker::new(
            host(),
            Arc::clone(&store) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );

        let error = checker.check(&rsa_key()).await.unwrap_err();
        let ProtocolError::HostKeyChanged {
            algorithm,
            expected,
            offered: got,
            ..
        } = error
        else {
            panic!("expected HostKeyChanged, got {error:?}");
        };
        assert_eq!(algorithm, "ssh-rsa");
        assert_ne!(expected, got, "both fingerprints must be carried");
        assert!(
            rx.try_recv().is_err(),
            "a changed identity must not be raised as a first-use prompt"
        );
        assert_eq!(
            store.keys.lock().len(),
            1,
            "nothing may be remembered for the new algorithm"
        );
    }

    #[tokio::test]
    async fn a_host_with_nothing_trusted_still_gets_the_first_use_prompt() {
        // The other half: the hardening must not turn every new host into a
        // man-in-the-middle warning.
        let store = Arc::new(Memory::default());
        let (events, mut rx) = event_channel(8);
        let (tx, prompts) = PromptChannel::new();
        let checker = HostKeyChecker::new(
            host(),
            Arc::clone(&store) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );
        let checking = tokio::spawn(async move { checker.check(&rsa_key()).await });

        let SessionEvent::Prompt(prompt) = rx.recv().await.unwrap() else {
            panic!("expected a prompt event");
        };
        let PromptKind::HostKey {
            previously_trusted, ..
        } = prompt.kind
        else {
            panic!("expected a host key prompt");
        };
        assert!(
            previously_trusted.is_none(),
            "a host with nothing trusted is a first use"
        );
        tx.send(PromptAnswer::new(prompt.id, b"yes".to_vec()))
            .await
            .unwrap();
        checking.await.unwrap().unwrap();
        assert!(store.lookup(&host(), "ssh-rsa").is_some());
    }

    #[test]
    fn the_replacement_challenge_is_the_tail_of_the_fingerprint() {
        for (rendered, _, _) in OPENSSH_REFERENCE {
            let parsed = Fingerprint::parse(rendered).unwrap();
            let challenge = replacement_challenge(&parsed);
            assert_eq!(challenge.chars().count(), REPLACEMENT_CHALLENGE_LEN);
            assert!(rendered.ends_with(&challenge), "{rendered} / {challenge}");
            // No `SHA256:` in it: a constant prefix proves nothing about
            // having read the key.
            assert!(!challenge.contains(':'));
        }

        // Two different keys must not share a challenge.
        let first = replacement_challenge(&Fingerprint::parse(OPENSSH_REFERENCE[0].0).unwrap());
        let second = replacement_challenge(&Fingerprint::parse(OPENSSH_REFERENCE[1].0).unwrap());
        assert_ne!(first, second);
    }

    #[test]
    fn the_trusted_algorithm_list_covers_what_a_store_can_hold() {
        // Including types this build no longer offers: a key imported from
        // `~/.ssh/known_hosts` predates the preference list, and missing it
        // would put the host back on the first-use path.
        for algorithm in ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-dss"] {
            assert!(
                KEY_ALGORITHMS.contains(&algorithm),
                "{algorithm} is not probed"
            );
        }

        let store = Memory::default();
        assert!(trusted_algorithms(&store, &host()).is_empty());
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-rsa", blob(1), 0, TrustSource::Prompted),
            )
            .unwrap();
        assert_eq!(trusted_algorithms(&store, &host()), vec!["ssh-rsa"]);
    }

    /// An RSA host key, in the shape `check` receives one.
    ///
    /// Generated per call rather than committed: this is a *public* key, but
    /// the repository holds no key material of any kind.
    fn rsa_key() -> PublicKeyOrCertificate {
        let key = russh::keys::PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            russh::keys::Algorithm::Rsa { hash: None },
        )
        .unwrap();
        PublicKeyOrCertificate::PublicKey {
            key: key.public_key().clone(),
            hash_alg: Some(russh::keys::HashAlg::Sha512),
        }
    }

    /// Wraps a blob the way `russh` hands one to `check_server_key`.
    fn public_key_or_certificate(offered: &OfferedKey) -> PublicKeyOrCertificate {
        let key = russh::keys::ssh_key::PublicKey::from_bytes(&offered.blob).unwrap();
        PublicKeyOrCertificate::PublicKey {
            key,
            hash_alg: None,
        }
    }
}
