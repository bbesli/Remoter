//! The server's certificate is the host key problem again.
//!
//! An RDP host almost always presents a certificate it signed itself — Windows
//! generates one on first boot and nobody replaces it — so the browser answer
//! ("not signed by a public CA, therefore refuse") would refuse every real
//! deployment, and the other browser answer ("show a warning the user clicks
//! through") is the mistake this project refuses to make. A checkbox that says
//! "ignore certificate errors" becomes, in practice, the default.
//!
//! `docs/security/transport-security.md` sets the policy, and it is the same
//! policy the SSH host key path already implements:
//!
//! | Situation | Behaviour |
//! |---|---|
//! | This exact certificate is pinned | Connect, silently |
//! | A **different** certificate is pinned | Hard failure, whether or not the new one chains to a trusted root. Replacing it needs the tail of the offered fingerprint, typed |
//! | Nothing pinned, chains to a trusted root **and** matches the name | Connect, silently. Nothing is pinned, so an ordinary renewal is not an alarm |
//! | Nothing pinned, and it did not validate | Prompt with the fingerprint and why it did not validate; accepting pins it to this host |
//!
//! # The pin is consulted before the trust anchors, always
//!
//! The order of those rows is the security property, not a presentational
//! choice. An earlier version of [`CertificateChecker::check`] returned `Ok` as
//! soon as the chain validated, *before* the trust store was consulted at all,
//! so a certificate that had been pinned and then changed was accepted in
//! silence as long as the replacement chained to a Mozilla root and matched the
//! name. Chaining to a public root says nothing about whether this is the same
//! machine the user trusted last week: anyone who can obtain a certificate for
//! the name — a hostile CA, a compromised registrar, an internal CA the machine
//! already trusts — walks through that short circuit
//! (`docs/security/threat-model.md`, T3). `remoter-proto-ssh/src/hostkey.rs`
//! has no such branch, and neither does this module any more: the trust store
//! answers first, and only a host with nothing stored for it can reach the
//! anchored fast path.
//!
//! The unknown and changed paths are deliberately different paths, not one path
//! with a flag: `remoter_proto::ChangedHostKey` has no boolean to pass `true`
//! to, so a change cannot be accepted by the code that accepts a first use.
//! This module reuses those exact types rather than parallel ones, which is
//! what makes "the same trust model" a fact about the code and not a claim in a
//! comment.
//!
//! # Trust is per host, not per key algorithm
//!
//! The trust store is keyed on (host, algorithm), and this module always passes
//! [`CERTIFICATE_ALGORITHM`]. That is not laziness. If the key were the
//! certificate's own signature algorithm, a server pinned under an RSA
//! certificate that suddenly offered an ECDSA one would get the gentle
//! first-use dialog instead of the blocking one — and which certificate to
//! offer is the attacker's choice (`docs/security/threat-model.md`, T3). The
//! SSH adapter documents the same trap in `hostkey.rs`; one label closes it
//! here by construction.
//!
//! # Where the decision is actually made
//!
//! `rustls` verifies certificates synchronously, inside the handshake, and the
//! answer here may require asking a person — which takes as long as it takes.
//! So [`DeferredVerifier`] does the *mechanical* half (chain, name, expiry,
//! and the signature that proves key possession) and records the verdict
//! instead of enforcing it, and [`CertificateChecker::check`] makes the trust
//! decision afterwards, before a single byte of the RDP connection sequence is
//! written. The signature checks are **not** deferred: a peer that cannot
//! prove it holds the private key never completes the handshake at all.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use remoter_proto::{
    CertificateProblem, EventSink, Fingerprint, HostKeyOutcome, HostPort, KnownKey, OfferedKey,
    ProtocolError, TrustSource, TrustStore, verify_host_key,
};
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use crate::error::certificate_untrusted;
use crate::prompt::PromptChannel;

/// The label every RDP certificate is stored under. See the module
/// documentation for why it is a constant and not the key's algorithm.
pub const CERTIFICATE_ALGORITHM: &str = "tls-certificate";

/// How many characters of the offered fingerprint replace a pinned
/// certificate.
///
/// The same rule and the same length the SSH adapter uses for a changed host
/// key: eight base64 characters is 48 bits of the SHA-256 digest, far more
/// friction than the control needs, and still short enough to read back over a
/// phone call while two people compare the whole fingerprint. It is duplicated
/// rather than shared because sibling protocol crates do not depend on each
/// other (CLAUDE.md §3); the shared home for it is `remoter-proto` if a third
/// protocol ever needs it.
pub const REPLACEMENT_CHALLENGE_LEN: usize = 8;

/// What the user must type to replace a pinned certificate.
///
/// Derived from the fingerprint the dialog is displaying, so producing it
/// requires having read that fingerprint. Deliberately **not** carried in the
/// prompt: a challenge that travels beside the question is answered by
/// anything that echoes what it was given.
#[must_use]
pub fn replacement_challenge(offered: &Fingerprint) -> String {
    let rendered = offered.to_string();
    // `SHA256:` is a constant prefix and copying it would prove nothing.
    let body = rendered.strip_prefix("SHA256:").unwrap_or(&rendered);
    let skip = body
        .chars()
        .count()
        .saturating_sub(REPLACEMENT_CHALLENGE_LEN);
    body.chars().skip(skip).collect()
}

/// What the TLS handshake saw, carried out of it for the trust decision.
#[derive(Debug, Clone)]
pub struct OfferedCertificate {
    /// The leaf certificate, DER, exactly as received. Public by definition —
    /// this is the value being pinned.
    pub der: Vec<u8>,
    /// Whether the chain validated against the trust anchors and the name
    /// matched. `true` means no prompt and no pin.
    pub anchored: bool,
    /// Why it did not validate, when it did not.
    pub problem: CertificateProblem,
}

impl OfferedCertificate {
    /// This certificate's fingerprint: SHA-256 over the DER, which is what
    /// `certutil -hashfile` and the Windows certificate dialog both show, so a
    /// user can compare it with what the server administrator has on screen.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::sha256(&self.der)
    }

    /// The server's public key, as the DER inside the certificate's
    /// `subjectPublicKeyInfo` BIT STRING.
    ///
    /// This is what CredSSP's `pubKeyAuth` binds to (MS-CSSP §3.1.5), and it
    /// is the *contents* of the BIT STRING rather than the whole
    /// `SubjectPublicKeyInfo` — an `RSAPublicKey` for an RSA certificate.
    /// Getting that boundary wrong produces a client that authenticates
    /// against nothing.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::CertificateUntrusted`] with
    /// [`CertificateProblem::Malformed`] if the certificate does not parse.
    pub fn public_key(&self, host: &HostPort) -> Result<Vec<u8>, ProtocolError> {
        use x509_cert::der::Decode as _;
        let parsed = x509_cert::Certificate::from_der(&self.der)
            .map_err(|_| certificate_untrusted(host, CertificateProblem::Malformed))?;
        parsed
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| certificate_untrusted(host, CertificateProblem::Malformed))
    }

    /// Whether the certificate signed itself, which is the ordinary case on an
    /// internal RDP host and is worth saying rather than reporting as the
    /// vaguer "untrusted root".
    #[must_use]
    fn is_self_signed(&self) -> bool {
        use x509_cert::der::Decode as _;
        x509_cert::Certificate::from_der(&self.der)
            .is_ok_and(|parsed| parsed.tbs_certificate.issuer == parsed.tbs_certificate.subject)
    }
}

/// A `rustls` verifier that records its verdict instead of enforcing it.
///
/// See the module documentation: the mechanical checks run here, the trust
/// decision runs afterwards where it can ask a person, and nothing is written
/// to the RDP connection before that decision is made.
#[derive(Debug)]
pub struct DeferredVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    seen: Mutex<Option<OfferedCertificate>>,
}

impl DeferredVerifier {
    /// A verifier over the Mozilla root store.
    ///
    /// **Not the platform store.** `docs/security/transport-security.md` says
    /// "system trust store via `rustls`", and this is a narrower set: a
    /// certificate issued by an enterprise CA that the machine trusts but
    /// Mozilla does not will fail the anchored check and reach the pin prompt.
    /// That is stricter than the document promises rather than looser — the
    /// user is asked instead of being trusted silently — and it costs no new
    /// dependency. Consulting the platform store needs `rustls-native-certs`,
    /// which is a dependency decision for the maintainer under CLAUDE.md §8.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Internal`] if the root store cannot be built, which
    /// would be a defect in this build rather than anything the user did.
    pub fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Result<Arc<Self>, ProtocolError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()
        .map_err(|_| ProtocolError::Internal {
            detail: "the certificate verifier could not be built",
        })?;
        Ok(Arc::new(Self {
            inner,
            provider,
            seen: Mutex::new(None),
        }))
    }

    /// What the handshake offered, once it has completed.
    #[must_use]
    pub fn offered(&self) -> Option<OfferedCertificate> {
        self.seen.lock().clone()
    }
}

impl ServerCertVerifier for DeferredVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verdict = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );

        let mut offered = OfferedCertificate {
            der: end_entity.as_ref().to_vec(),
            anchored: verdict.is_ok(),
            problem: match &verdict {
                Ok(_) => CertificateProblem::SelfSigned,
                Err(rustls::Error::InvalidCertificate(reason)) => {
                    crate::error::certificate_problem(reason)
                }
                Err(_) => CertificateProblem::Malformed,
            },
        };
        // "Untrusted root" is true of a self-signed certificate and tells the
        // user nothing they can act on; "self-signed" tells them this is the
        // machine's own certificate and that pinning it is the answer.
        if !offered.anchored
            && matches!(offered.problem, CertificateProblem::UntrustedRoot)
            && offered.is_self_signed()
        {
            offered.problem = CertificateProblem::SelfSigned;
        }
        *self.seen.lock() = Some(offered);

        // Deferred, not skipped: `CertificateChecker::check` runs before the
        // connection sequence writes anything, and a refusal there drops the
        // stream. The signature checks below are *not* deferred, so a peer
        // without the private key never gets this far.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Decides whether a certificate may be used for `host`.
pub struct CertificateChecker {
    host: HostPort,
    trust: Arc<dyn TrustStore>,
    events: EventSink,
    prompts: Option<Arc<PromptChannel>>,
}

impl CertificateChecker {
    /// A checker for `host`, backed by `trust`.
    ///
    /// `prompts` is `None` for a session that cannot ask — a scripted connect,
    /// or a reconnect running without an interface. An unpinned certificate is
    /// then a refusal, never an acceptance: a machine that cannot ask a human
    /// has not obtained consent.
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

    /// Checks what the server offered.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::CertificateUntrusted`] when the user declines a first
    /// use or when a pinned certificate was replaced and the replacement was
    /// not confirmed; [`ProtocolError::ConfirmationMismatch`] when the typed
    /// confirmation did not match; [`ProtocolError::TrustStore`] if the
    /// decision could not be recorded.
    pub async fn check(&self, offered: &OfferedCertificate) -> Result<(), ProtocolError> {
        // The trust store is asked FIRST, and `offered.anchored` is not
        // consulted until the answer is "nothing is stored for this host".
        // Reversing these two — returning early on `anchored` — is the defect
        // this ordering exists to prevent: it let a pinned certificate be
        // swapped for any other certificate that chained to a public root, in
        // silence. See the module documentation.
        let key = OfferedKey::new(CERTIFICATE_ALGORITHM, offered.der.clone());
        match verify_host_key(self.trust.as_ref(), &self.host, &key) {
            HostKeyOutcome::Trusted => {
                tracing::debug!(host = %self.host, "the server's certificate matched the pinned one");
                Ok(())
            }

            HostKeyOutcome::Unknown(unknown) => {
                if offered.anchored {
                    // Nothing is pinned *and* the chain validated against a
                    // trust anchor with a matching name: connect, and pin
                    // nothing. Pinning here would turn an ordinary renewal
                    // under the same authority into a man-in-the-middle
                    // warning, and a warning that fires on routine maintenance
                    // is a warning people learn to dismiss.
                    tracing::debug!(host = %self.host, "the server's certificate validated against a trust anchor");
                    return Ok(());
                }
                let Some(prompts) = self.prompts.as_deref() else {
                    return Err(certificate_untrusted(&self.host, offered.problem));
                };
                // `PromptKind::Certificate` carries the fingerprint and the
                // reason, which is what the taxonomy's first-use row asks for:
                // "the certificate for `host` is not trusted: self-signed",
                // plus a pin option.
                let accepted = prompts
                    .confirm(
                        &self.events,
                        remoter_proto::PromptKind::Certificate {
                            fingerprint: unknown.fingerprint().to_string(),
                            reason: offered.problem.as_str().to_owned(),
                        },
                        self.host.to_string(),
                    )
                    .await?;
                if accepted {
                    tracing::info!(host = %self.host, "a new RDP certificate was pinned by the user");
                    unknown.accept(self.trust.as_ref(), now_ms(), TrustSource::Pinned)
                } else {
                    Err(certificate_untrusted(&self.host, offered.problem))
                }
            }

            HostKeyOutcome::Changed(changed) => {
                // Reached whether or not `offered.anchored` is true. A pinned
                // certificate that has been replaced is a changed host
                // identity; that the replacement chains to a public root is
                // not evidence about *which* machine answered, and treating it
                // as evidence is the short circuit this arm is now reachable
                // past.
                let Some(prompts) = self.prompts.as_deref() else {
                    return Err(certificate_untrusted(
                        &self.host,
                        CertificateProblem::Changed,
                    ));
                };
                // A changed certificate is a possible man-in-the-middle, so
                // the answer must be copied off the screen rather than be a
                // button the user can hit with the shortcut they use for every
                // other dialog. `PromptKind::HostKey` is used here and
                // `PromptKind::Certificate` above because only the former can
                // carry *both* fingerprints, which
                // `docs/security/transport-security.md` requires this dialog
                // to show side by side — a comparison with one value in it is
                // not a comparison.
                let expected = replacement_challenge(&changed.offered());
                let typed = match prompts
                    .ask(&self.events, changed.prompt(), self.host.to_string(), true)
                    .await
                {
                    Ok(typed) => typed,
                    // Dismissing the dialog leaves the pinned certificate
                    // alone, which is the safe outcome and the default one.
                    Err(ProtocolError::AuthCancelled) => return Err(changed.into_error()),
                    Err(error) => return Err(error),
                };

                let Ok(typed) = core::str::from_utf8(&typed) else {
                    return Err(changed.into_error());
                };
                // Case-sensitive: base64 distinguishes `a` from `A`, and the
                // user is copying, not recalling. Whitespace is forgiven
                // because a selection often carries some.
                if typed.trim() != expected {
                    return Err(ProtocolError::ConfirmationMismatch);
                }
                tracing::warn!(
                    host = %self.host,
                    "a changed RDP certificate was presented; the user confirmed it against the offered fingerprint"
                );
                // The store's own interlock, satisfied now that the user has
                // proved they read the fingerprint on screen.
                let word = changed.confirmation_word().to_owned();
                changed.accept_replacement(&word, self.trust.as_ref(), now_ms())
            }
        }
    }
}

/// Wall-clock milliseconds, saturating. A clock before 1970 is not a reason to
/// refuse to record a certificate the user just pinned.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

/// A pinned certificate, for the vault to record. Exposed so that an importer
/// bringing pins across from another client builds the same shape.
#[must_use]
pub fn pinned(der: Vec<u8>, at_ms: i64) -> KnownKey {
    KnownKey::new(CERTIFICATE_ALGORITHM, der, at_ms, TrustSource::Pinned)
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
    use remoter_proto::{PromptAnswer, PromptKind, SessionEvent, event_channel};
    use std::collections::HashMap;

    /// An in-memory stand-in for the vault's trust store.
    #[derive(Default)]
    struct Memory {
        keys: Mutex<HashMap<(String, String), KnownKey>>,
    }

    impl TrustStore for Memory {
        fn lookup(&self, host: &HostPort, algorithm: &str) -> Option<KnownKey> {
            self.keys
                .lock()
                .get(&(host.canonical(), algorithm.to_owned()))
                .cloned()
        }

        fn remember(&self, host: &HostPort, key: &KnownKey) -> Result<(), ProtocolError> {
            self.keys
                .lock()
                .insert((host.canonical(), key.algorithm.clone()), key.clone());
            Ok(())
        }
    }

    fn host() -> HostPort {
        HostPort::new("ts-01.corp.example", 3389).unwrap()
    }

    fn offered(der: &[u8], anchored: bool) -> OfferedCertificate {
        OfferedCertificate {
            der: der.to_vec(),
            anchored,
            problem: CertificateProblem::SelfSigned,
        }
    }

    /// Drives one prompt round trip: reads the question off the event stream,
    /// answers it with `answer`, and hands back what the checker decided.
    async fn with_answer(
        checker: CertificateChecker,
        sender: tokio::sync::mpsc::Sender<PromptAnswer>,
        mut events: tokio::sync::mpsc::Receiver<SessionEvent>,
        certificate: OfferedCertificate,
        answer: impl Fn(&PromptKind) -> Option<Vec<u8>> + Send + 'static,
    ) -> (Result<(), ProtocolError>, Option<PromptKind>) {
        let asked = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if let SessionEvent::Prompt(prompt) = event {
                    let reply = match answer(&prompt.kind) {
                        Some(bytes) => PromptAnswer::new(prompt.id, bytes),
                        None => PromptAnswer::cancelled(prompt.id),
                    };
                    let _ = sender.send(reply).await;
                    return Some(prompt.kind);
                }
            }
            None
        });
        let outcome = checker.check(&certificate).await;
        // Dropped before the listener is joined so that a checker which
        // decided *without* asking closes the event channel instead of leaving
        // the listener blocked on a receive that will never complete. A test
        // asserting "this must prompt" then fails on its assertion rather than
        // hanging until CI's timeout, which is the difference between a
        // diagnosis and a mystery.
        drop(checker);
        let kind = asked.await.ok().flatten();
        (outcome, kind)
    }

    #[tokio::test]
    async fn a_certificate_that_chains_to_a_trust_anchor_is_not_pinned() {
        // Pinning one would turn a routine renewal under the same authority
        // into a man-in-the-middle warning.
        let trust = Arc::new(Memory::default());
        let (events, _rx) = event_channel(16);
        let checker = CertificateChecker::new(
            host(),
            Arc::clone(&trust) as Arc<dyn TrustStore>,
            events,
            None,
        );
        checker
            .check(&offered(b"a real certificate", true))
            .await
            .unwrap();
        assert!(trust.keys.lock().is_empty());
    }

    #[tokio::test]
    async fn a_first_use_certificate_is_prompted_for_and_pinned_on_acceptance() {
        let trust = Arc::new(Memory::default());
        let (sender, prompts) = PromptChannel::new();
        let (events, rx) = event_channel(16);
        let checker = CertificateChecker::new(
            host(),
            Arc::clone(&trust) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );

        let (outcome, kind) = with_answer(
            checker,
            sender,
            rx,
            offered(b"a self-signed certificate", false),
            |_| Some(b"yes".to_vec()),
        )
        .await;

        outcome.unwrap();
        // The first-use dialog has to show the fingerprint and *why* the
        // certificate did not validate; "not trusted" alone is the message
        // this project refuses to produce.
        let Some(PromptKind::Certificate {
            fingerprint,
            reason,
        }) = kind
        else {
            panic!("expected a certificate prompt, got {kind:?}");
        };
        assert!(fingerprint.starts_with("SHA256:"));
        assert_eq!(reason, "self-signed");
        assert_eq!(trust.keys.lock().len(), 1);
    }

    #[tokio::test]
    async fn declining_a_first_use_certificate_pins_nothing_and_fails() {
        let trust = Arc::new(Memory::default());
        let (sender, prompts) = PromptChannel::new();
        let (events, rx) = event_channel(16);
        let checker = CertificateChecker::new(
            host(),
            Arc::clone(&trust) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );

        let (outcome, _) = with_answer(
            checker,
            sender,
            rx,
            offered(b"a self-signed certificate", false),
            |_| None,
        )
        .await;

        assert!(matches!(
            outcome,
            Err(ProtocolError::CertificateUntrusted { .. })
        ));
        assert!(trust.keys.lock().is_empty());
    }

    #[tokio::test]
    async fn a_session_that_cannot_ask_refuses_rather_than_accepting() {
        // A machine that cannot ask a human has not obtained consent. This is
        // the scripted-connect path, and it is the one where an "accept
        // silently" default would be invisible.
        let trust = Arc::new(Memory::default());
        let (events, _rx) = event_channel(16);
        let checker = CertificateChecker::new(host(), trust, events, None);
        let outcome = checker
            .check(&offered(b"a self-signed certificate", false))
            .await;
        assert!(matches!(
            outcome,
            Err(ProtocolError::CertificateUntrusted { .. })
        ));
    }

    #[tokio::test]
    async fn a_changed_certificate_is_a_blocking_dialog_showing_both_fingerprints() {
        let trust = Arc::new(Memory::default());
        trust
            .remember(
                &host(),
                &pinned(b"the certificate from last week".to_vec(), 0),
            )
            .unwrap();

        let (sender, prompts) = PromptChannel::new();
        let (events, rx) = event_channel(16);
        let checker = CertificateChecker::new(
            host(),
            Arc::clone(&trust) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );

        let (outcome, kind) = with_answer(
            checker,
            sender,
            rx,
            offered(b"a different certificate entirely", false),
            // Dismissed: the safe outcome and the default one.
            |_| None,
        )
        .await;

        assert!(matches!(outcome, Err(ProtocolError::HostKeyChanged { .. })));
        let Some(PromptKind::HostKey {
            previously_trusted: Some(previous),
            fingerprint,
            randomart,
            ..
        }) = kind
        else {
            panic!("a changed certificate must produce the blocking dialog, got {kind:?}");
        };
        // Both halves of the comparison, as the security document requires.
        assert_ne!(previous.fingerprint, fingerprint);
        assert!(!previous.randomart.is_empty());
        assert!(!randomart.is_empty());
        // And the pinned certificate is untouched.
        assert_eq!(
            trust.lookup(&host(), CERTIFICATE_ALGORITHM).unwrap().blob,
            b"the certificate from last week"
        );
    }

    /// The regression this module's ordering exists for.
    ///
    /// A certificate was pinned; a *different* one arrives that chains to a
    /// trust anchor and matches the name. The anchored fast path used to
    /// return `Ok` before the trust store was consulted, so this was accepted
    /// in silence — which is exactly the position an attacker holding any
    /// certificate for the name wants to be in.
    #[tokio::test]
    async fn an_anchored_certificate_does_not_override_a_pin() {
        let trust = Arc::new(Memory::default());
        trust
            .remember(
                &host(),
                &pinned(b"the certificate from last week".to_vec(), 0),
            )
            .unwrap();

        let (sender, prompts) = PromptChannel::new();
        let (events, rx) = event_channel(16);
        let checker = CertificateChecker::new(
            host(),
            Arc::clone(&trust) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );

        let (outcome, kind) = with_answer(
            checker,
            sender,
            rx,
            // `anchored: true` — a hostile CA, a compromised registrar or an
            // internal CA the machine trusts can all produce one of these.
            offered(b"a certificate from a public authority", true),
            // Dismissed: the safe outcome and the default one.
            |_| None,
        )
        .await;

        assert!(
            matches!(outcome, Err(ProtocolError::HostKeyChanged { .. })),
            "an anchored certificate replaced a pinned one: {outcome:?}"
        );
        // And it must be the blocking dialog, not the gentle first-use one.
        assert!(
            matches!(kind, Some(PromptKind::HostKey { .. })),
            "expected the changed-key dialog, got {kind:?}"
        );
        // The pin is untouched.
        assert_eq!(
            trust.lookup(&host(), CERTIFICATE_ALGORITHM).unwrap().blob,
            b"the certificate from last week"
        );
    }

    /// The other half of the same ordering: a pinned certificate that also
    /// chains to an anchor still matches, and still does not prompt.
    #[tokio::test]
    async fn an_anchored_certificate_that_is_the_pinned_one_connects_silently() {
        let trust = Arc::new(Memory::default());
        trust
            .remember(&host(), &pinned(b"the pinned certificate".to_vec(), 0))
            .unwrap();

        let (events, _rx) = event_channel(16);
        let checker = CertificateChecker::new(
            host(),
            Arc::clone(&trust) as Arc<dyn TrustStore>,
            events,
            // No prompt channel: reaching a prompt at all would fail here.
            None,
        );
        checker
            .check(&offered(b"the pinned certificate", true))
            .await
            .unwrap();
        assert_eq!(
            trust.lookup(&host(), CERTIFICATE_ALGORITHM).unwrap().blob,
            b"the pinned certificate"
        );
    }

    /// A scripted connect — no interface to ask — must refuse a changed
    /// certificate rather than let the anchored path wave it through.
    #[tokio::test]
    async fn an_anchored_certificate_over_a_pin_is_refused_when_nobody_can_be_asked() {
        let trust = Arc::new(Memory::default());
        trust
            .remember(
                &host(),
                &pinned(b"the certificate from last week".to_vec(), 0),
            )
            .unwrap();

        let (events, _rx) = event_channel(16);
        let checker = CertificateChecker::new(
            host(),
            Arc::clone(&trust) as Arc<dyn TrustStore>,
            events,
            None,
        );
        let outcome = checker
            .check(&offered(b"a certificate from a public authority", true))
            .await;
        assert!(
            matches!(
                outcome,
                Err(ProtocolError::CertificateUntrusted {
                    reason: CertificateProblem::Changed,
                    ..
                })
            ),
            "{outcome:?}"
        );
        assert_eq!(
            trust.lookup(&host(), CERTIFICATE_ALGORITHM).unwrap().blob,
            b"the certificate from last week"
        );
    }

    #[tokio::test]
    async fn replacing_a_pinned_certificate_needs_the_offered_fingerprint_typed() {
        let trust = Arc::new(Memory::default());
        trust
            .remember(
                &host(),
                &pinned(b"the certificate from last week".to_vec(), 0),
            )
            .unwrap();

        let replacement = offered(b"the certificate from today", false);
        let expected = replacement_challenge(&replacement.fingerprint());

        // The wrong word leaves the pin alone.
        let (sender, prompts) = PromptChannel::new();
        let (events, rx) = event_channel(16);
        let checker = CertificateChecker::new(
            host(),
            Arc::clone(&trust) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );
        let (outcome, _) = with_answer(checker, sender, rx, replacement.clone(), |_| {
            Some(b"yes".to_vec())
        })
        .await;
        assert!(matches!(outcome, Err(ProtocolError::ConfirmationMismatch)));
        assert_eq!(
            trust.lookup(&host(), CERTIFICATE_ALGORITHM).unwrap().blob,
            b"the certificate from last week"
        );

        // The right one replaces it.
        let (sender, prompts) = PromptChannel::new();
        let (events, rx) = event_channel(16);
        let checker = CertificateChecker::new(
            host(),
            Arc::clone(&trust) as Arc<dyn TrustStore>,
            events,
            Some(prompts),
        );
        let word = expected.clone();
        let (outcome, _) = with_answer(checker, sender, rx, replacement, move |_| {
            Some(word.clone().into_bytes())
        })
        .await;
        outcome.unwrap();
        assert_eq!(
            trust.lookup(&host(), CERTIFICATE_ALGORITHM).unwrap().blob,
            b"the certificate from today"
        );
    }

    #[test]
    fn the_replacement_challenge_is_the_tail_of_the_offered_fingerprint() {
        let fingerprint = Fingerprint::sha256(b"a certificate");
        let challenge = replacement_challenge(&fingerprint);
        assert_eq!(challenge.chars().count(), REPLACEMENT_CHALLENGE_LEN);
        assert!(fingerprint.to_string().ends_with(&challenge));
        // Different certificate, different word: a challenge that did not
        // depend on the value being checked would be a formality.
        assert_ne!(
            challenge,
            replacement_challenge(&Fingerprint::sha256(b"another certificate"))
        );
    }

    #[test]
    fn every_certificate_is_stored_under_one_label_whatever_key_it_carries() {
        // A host pinned under an RSA certificate that suddenly offers an
        // ECDSA one must get the blocking dialog, not the gentle one; which
        // certificate to offer is the attacker's choice.
        assert_eq!(pinned(b"rsa".to_vec(), 0).algorithm, CERTIFICATE_ALGORITHM);
        assert_eq!(
            pinned(b"ecdsa".to_vec(), 0).algorithm,
            CERTIFICATE_ALGORITHM
        );
    }
}
