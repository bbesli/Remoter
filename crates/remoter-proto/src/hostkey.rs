//! Host identity: fingerprints, randomart, the trust store, and what happens
//! when a key changes.
//!
//! The trust store lives inside the encrypted vault rather than in a plaintext
//! `known_hosts` (`docs/security/transport-security.md`), so poisoning it
//! requires opening the vault. This crate therefore defines the trait and the
//! decision; `remoter-vault` implements the storage.
//!
//! Nothing in this module is secret. A public host key, its fingerprint and its
//! randomart are exactly the values a user is meant to compare out of band, and
//! they are printed on screen for that purpose.

use std::fmt;

use data_encoding::BASE64_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ProtocolError;
use crate::event::{PromptKind, TrustedHostKey};
use crate::transport::HostPort;

/// A SHA-256 host key fingerprint, in OpenSSH's presentation form.
///
/// SHA-256 and base64 because that is what `ssh-keygen -l` prints and what the
/// server administrator will have on their screen; a fingerprint the user
/// cannot compare against the one they were given is not a check, it is a
/// ceremony.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    digest: [u8; 32],
}

impl Fingerprint {
    /// Fingerprints a public key blob.
    ///
    /// `blob` is the SSH wire encoding of the public key (RFC 4253 §6.6) for
    /// SSH, or the DER of a certificate for TLS pinning. The hash is over the
    /// bytes as received, which is what makes two implementations agree.
    #[must_use]
    pub fn sha256(blob: &[u8]) -> Self {
        let digest: [u8; 32] = Sha256::digest(blob).into();
        Self { digest }
    }

    /// Wraps a digest that was computed elsewhere — by the vault, on the way
    /// back out of storage.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self { digest }
    }

    /// The raw digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Parses `SHA256:<base64>`, with or without the prefix and with or
    /// without padding.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::MalformedFingerprint`] if the text is not a base64
    /// SHA-256 digest.
    pub fn parse(text: &str) -> Result<Self, ProtocolError> {
        let body = text.strip_prefix("SHA256:").unwrap_or(text).trim();
        let body = body.trim_end_matches('=');
        let bytes = BASE64_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| ProtocolError::MalformedFingerprint)?;
        let digest: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ProtocolError::MalformedFingerprint)?;
        Ok(Self { digest })
    }

    /// The ASCII-art rendering of this fingerprint — OpenSSH's "drunken
    /// bishop".
    ///
    /// A human compares two 43-character base64 strings badly and two pictures
    /// well; the picture is there to make a *changed* key obvious at a glance,
    /// not to be authoritative. `title` is what appears in the top border, and
    /// is conventionally the key type and size (`ED25519 256`).
    ///
    /// The algorithm is OpenSSH's `sshkey_fingerprint_randomart`: a walk over
    /// the digest, two bits at a time, incrementing a counter in a 17×9 field;
    /// the counter selects a symbol from a fixed ramp. `S` marks the start
    /// square and `E` the end.
    #[must_use]
    pub fn randomart(&self, title: &str) -> String {
        randomart(&self.digest, title)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHA256:{}", BASE64_NOPAD.encode(&self.digest))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Width of the randomart field, in characters. OpenSSH's `FLDSIZE_X`.
const FIELD_WIDTH: usize = 17;
/// Height of the randomart field, in lines. OpenSSH's `FLDSIZE_Y`.
const FIELD_HEIGHT: usize = 9;
/// The symbol ramp, densest last. Indices past the end are the start and end
/// markers, which is why the walk caps the counter below `SYMBOLS.len() - 1`.
const SYMBOLS: &[u8; 15] = b" .o+=*BOX@%&#/^";

fn randomart(digest: &[u8], title: &str) -> String {
    let mut field = [[0u8; FIELD_WIDTH]; FIELD_HEIGHT];
    let mut x = FIELD_WIDTH / 2;
    let mut y = FIELD_HEIGHT / 2;

    for byte in digest {
        let mut bits = *byte;
        // Four moves per byte, two bits at a time, least significant first.
        for _ in 0..4 {
            if bits & 0x01 == 0 {
                x = x.saturating_sub(1);
            } else if x < FIELD_WIDTH - 1 {
                x += 1;
            }
            if bits & 0x02 == 0 {
                y = y.saturating_sub(1);
            } else if y < FIELD_HEIGHT - 1 {
                y += 1;
            }
            let cell = &mut field[y][x];
            if usize::from(*cell) < SYMBOLS.len() - 1 {
                *cell += 1;
            }
            bits >>= 2;
        }
    }

    // 15 and 16 are past the ramp: they render as the start and end markers.
    field[FIELD_HEIGHT / 2][FIELD_WIDTH / 2] = 15;
    field[y][x] = 16;

    let mut out = String::with_capacity((FIELD_WIDTH + 3) * (FIELD_HEIGHT + 2));
    out.push_str(&border(title));
    out.push('\n');
    for row in &field {
        out.push('|');
        for cell in row {
            out.push(match *cell {
                15 => 'S',
                16 => 'E',
                n => char::from(SYMBOLS[usize::from(n)]),
            });
        }
        out.push_str("|\n");
    }
    out.push_str(&border("SHA256"));
    out
}

/// A `+--[ TITLE ]--+` border, `FIELD_WIDTH` characters wide between the
/// corners. A title too long to fit is dropped rather than allowed to widen the
/// picture, because a ragged frame is what makes two randomarts hard to
/// compare.
fn border(title: &str) -> String {
    let label = format!("[{title}]");
    if label.chars().count() > FIELD_WIDTH {
        return format!("+{}+", "-".repeat(FIELD_WIDTH));
    }
    let padding = FIELD_WIDTH - label.chars().count();
    let left = padding / 2;
    let right = padding - left;
    format!("+{}{label}{}+", "-".repeat(left), "-".repeat(right))
}

/// Where a trusted key came from. Recorded so the audit log can distinguish a
/// key the user actually looked at from one that arrived with an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustSource {
    /// The user was shown the fingerprint and accepted it.
    Prompted,
    /// Read from the platform's `~/.ssh/known_hosts` on first use.
    ImportedKnownHosts,
    /// Pinned to this connection, for TLS and RDP certificates.
    Pinned,
    /// Replaced a previously trusted key after an explicit confirmation.
    Replaced,
}

/// A host key the trust store already holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownKey {
    /// The key algorithm, as named on the wire: `ssh-ed25519`,
    /// `rsa-sha2-512`, `ecdsa-sha2-nistp256`.
    pub algorithm: String,
    /// The public key blob, exactly as received. Public by definition — this
    /// is the value being pinned, not a secret.
    pub blob: Vec<u8>,
    /// When it was trusted, in milliseconds since the Unix epoch.
    pub added_at_ms: i64,
    /// How it came to be trusted.
    pub source: TrustSource,
}

impl KnownKey {
    /// Records `blob` as trusted for `algorithm`.
    #[must_use]
    pub fn new(
        algorithm: impl Into<String>,
        blob: Vec<u8>,
        added_at_ms: i64,
        source: TrustSource,
    ) -> Self {
        Self {
            algorithm: algorithm.into(),
            blob,
            added_at_ms,
            source,
        }
    }

    /// This key's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::sha256(&self.blob)
    }
}

/// A key a server has just offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedKey {
    /// The key algorithm, as named on the wire.
    pub algorithm: String,
    /// The public key blob, exactly as received.
    pub blob: Vec<u8>,
}

impl OfferedKey {
    /// Wraps what the server sent.
    #[must_use]
    pub fn new(algorithm: impl Into<String>, blob: Vec<u8>) -> Self {
        Self {
            algorithm: algorithm.into(),
            blob,
        }
    }

    /// This key's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::sha256(&self.blob)
    }
}

/// The trust store. Implemented by `remoter-vault`.
///
/// Lookup is by host *and* algorithm: a server legitimately offers an Ed25519
/// key and an RSA key, and finding no Ed25519 entry while an RSA one exists is
/// "unknown", not "changed".
///
/// **Implementations must key on [`HostPort::canonical`]**, never on the host as
/// typed. `DB-01.internal`, `db-01.internal` and `db-01.internal.` are one
/// machine (RFC 4343, RFC 1034 §3.1); storing them separately means an importer
/// that emits a fully qualified name walks past a trust decision the user
/// already made, and a changed key on the same machine looks like a first use.
/// A store built on a `HashMap<HostPort, _>` gets this from `HostPort`'s `Eq`
/// and `Hash`, which compare the canonical form.
pub trait TrustStore: Send + Sync {
    /// The key trusted for `host` under `algorithm`, if any.
    fn lookup(&self, host: &HostPort, algorithm: &str) -> Option<KnownKey>;

    /// Records `key` as trusted for `host`.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::TrustStore`] if the vault could not be written. A
    /// failure here must not be silently swallowed: a user who accepted a key
    /// and is asked again next time will start clicking through the prompt.
    fn remember(&self, host: &HostPort, key: &KnownKey) -> Result<(), ProtocolError>;
}

/// What the trust store had to say about an offered key. The serialisable,
/// inspectable form — this is what reaches the interface as an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum HostKeyDecision {
    /// The stored key matches. Connect without asking.
    Trusted,
    /// No key is stored for this host and algorithm. Ask, showing both
    /// renderings.
    Unknown {
        /// The offered key's fingerprint.
        fingerprint: Fingerprint,
        /// Its ASCII-art rendering.
        randomart: String,
    },
    /// A key is stored and it is **not** this one. Possible man-in-the-middle.
    ///
    /// Both keys are carried in full — fingerprint and picture — because the
    /// dialog this feeds is required to show them side by side
    /// (`docs/security/transport-security.md`), and a decision that carries
    /// only one of them cannot be compared with anything.
    Changed {
        /// What the vault says this host uses.
        expected: Fingerprint,
        /// The stored key's ASCII-art rendering.
        expected_randomart: String,
        /// When the stored key was first trusted, in milliseconds since the
        /// Unix epoch.
        expected_first_trusted_at_ms: i64,
        /// What answered.
        offered: Fingerprint,
        /// The offered key's ASCII-art rendering.
        offered_randomart: String,
    },
}

/// The result of a verification, carrying the *capability* to act on it.
///
/// Separate from [`HostKeyDecision`] on purpose. The decision is data: it is
/// cloned, serialised and sent to the interface. This is not — accepting a key
/// means consuming one of these, which cannot be conjured from a deserialised
/// event.
#[derive(Debug)]
#[must_use = "a host key decision that is neither accepted nor turned into an error silently trusts the server"]
pub enum HostKeyOutcome {
    /// The stored key matched.
    Trusted,
    /// Nothing is stored for this host and algorithm.
    Unknown(UnknownHostKey),
    /// The stored key and the offered key differ.
    Changed(ChangedHostKey),
}

impl HostKeyOutcome {
    /// The serialisable description, for the prompt event.
    #[must_use]
    pub fn decision(&self) -> HostKeyDecision {
        match self {
            Self::Trusted => HostKeyDecision::Trusted,
            Self::Unknown(unknown) => HostKeyDecision::Unknown {
                fingerprint: unknown.fingerprint,
                randomart: unknown.randomart.clone(),
            },
            Self::Changed(changed) => HostKeyDecision::Changed {
                expected: changed.expected,
                expected_randomart: changed.expected_randomart(),
                expected_first_trusted_at_ms: changed.expected_first_trusted_at_ms,
                offered: changed.offered,
                offered_randomart: changed.randomart(),
            },
        }
    }

    /// Whether the session may proceed with no further interaction.
    #[must_use]
    pub const fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// A host offering a key nothing is stored for.
///
/// First use is a prompt, never an auto-accept: an "ignore host keys" setting
/// becomes, in practice, the default.
#[derive(Debug)]
pub struct UnknownHostKey {
    host: HostPort,
    algorithm: String,
    blob: Vec<u8>,
    fingerprint: Fingerprint,
    randomart: String,
}

impl UnknownHostKey {
    /// The host that offered it.
    #[must_use]
    pub const fn host(&self) -> &HostPort {
        &self.host
    }

    /// The key algorithm, as named on the wire.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The offered key's fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Its ASCII-art rendering.
    #[must_use]
    pub fn randomart(&self) -> &str {
        &self.randomart
    }

    /// The prompt to put in front of the user.
    ///
    /// Built here rather than at the call site so that every adapter shows the
    /// same thing: the host, the key type, the full fingerprint and the
    /// randomart, which is what
    /// `docs/security/transport-security.md` requires of a first-use prompt.
    #[must_use]
    pub fn prompt(&self) -> PromptKind {
        PromptKind::HostKey {
            host: self.host.to_string(),
            algorithm: self.algorithm.clone(),
            fingerprint: self.fingerprint.to_string(),
            randomart: self.randomart.clone(),
            previously_trusted: None,
        }
    }

    /// Records the key as trusted, after the user said yes.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::TrustStore`] if the vault could not be written.
    pub fn accept(
        self,
        store: &dyn TrustStore,
        now_ms: i64,
        source: TrustSource,
    ) -> Result<(), ProtocolError> {
        let key = KnownKey::new(self.algorithm, self.blob, now_ms, source);
        store.remember(&self.host, &key)
    }

    /// The failure to return when the user says no.
    #[must_use]
    pub fn reject(self) -> ProtocolError {
        ProtocolError::HostKeyRejected {
            host: self.host,
            algorithm: self.algorithm,
        }
    }
}

/// A host offering a key that contradicts the one in the vault.
///
/// This is a hard failure, and the type is shaped so that it cannot be
/// accidentally accepted: there is no boolean to pass `true` to and no
/// `Ok`-returning default path. The only way through is
/// [`accept_replacement`](Self::accept_replacement), which consumes the value
/// and demands the exact word shown on screen. A dialog that a user can dismiss
/// with the keyboard shortcut they use for every other dialog is not a warning.
#[derive(Debug)]
#[must_use = "a changed host key must be turned into an error or explicitly replaced"]
pub struct ChangedHostKey {
    host: HostPort,
    algorithm: String,
    blob: Vec<u8>,
    expected: Fingerprint,
    offered: Fingerprint,
    /// When the key being contradicted was first trusted. Carried because
    /// "you accepted this three years ago" and "you accepted it during
    /// yesterday's import" are different situations, and only the user can
    /// tell which one they are in.
    expected_first_trusted_at_ms: i64,
    confirmation: String,
}

impl ChangedHostKey {
    /// The host that offered it.
    #[must_use]
    pub const fn host(&self) -> &HostPort {
        &self.host
    }

    /// The key algorithm, as named on the wire.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// What the vault says this host uses.
    #[must_use]
    pub const fn expected(&self) -> Fingerprint {
        self.expected
    }

    /// What answered.
    #[must_use]
    pub const fn offered(&self) -> Fingerprint {
        self.offered
    }

    /// The offered key's ASCII-art rendering, to be shown beside the stored
    /// one so the difference is visible rather than merely stated.
    #[must_use]
    pub fn randomart(&self) -> String {
        self.offered.randomart(&self.algorithm)
    }

    /// The stored key's ASCII-art rendering — the other half of that
    /// comparison, which is not a comparison with only one picture in it.
    #[must_use]
    pub fn expected_randomart(&self) -> String {
        self.expected.randomart(&self.algorithm)
    }

    /// When the key this one contradicts was first trusted, in milliseconds
    /// since the Unix epoch.
    #[must_use]
    pub const fn expected_first_trusted_at_ms(&self) -> i64 {
        self.expected_first_trusted_at_ms
    }

    /// The prompt to put in front of the user.
    ///
    /// Carries both fingerprints and both randomarts, because
    /// `docs/security/transport-security.md` requires the changed-key dialog to
    /// show both and because comparing them is the entire purpose of the
    /// dialog. It also names the host: with only the offered fingerprint the
    /// user could not tell which machine was being talked about.
    #[must_use]
    pub fn prompt(&self) -> PromptKind {
        PromptKind::HostKey {
            host: self.host.to_string(),
            algorithm: self.algorithm.clone(),
            fingerprint: self.offered.to_string(),
            randomart: self.randomart(),
            previously_trusted: Some(TrustedHostKey {
                fingerprint: self.expected.to_string(),
                randomart: self.expected_randomart(),
                first_trusted_at_ms: self.expected_first_trusted_at_ms,
            }),
        }
    }

    /// The word the user must type to replace the stored key.
    ///
    /// Derived from the offered fingerprint, so it is stable for one server and
    /// different for another, and it is plain ASCII in every locale: it is a
    /// token to be copied off the screen, not a translated string, and two
    /// colleagues can read it to each other over the phone while they compare
    /// fingerprints.
    #[must_use]
    pub fn confirmation_word(&self) -> &str {
        &self.confirmation
    }

    /// The hard failure. This is the default outcome and the one the pipeline
    /// takes unless a human intervenes.
    #[must_use]
    pub fn into_error(self) -> ProtocolError {
        ProtocolError::HostKeyChanged {
            host: self.host,
            algorithm: self.algorithm,
            expected: self.expected,
            offered: self.offered,
        }
    }

    /// Replaces the stored key, after the user typed the confirmation word.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ConfirmationMismatch`] if `typed` is not
    /// [`confirmation_word`](Self::confirmation_word) — the stored key is left
    /// alone. [`ProtocolError::TrustStore`] if the vault could not be written.
    pub fn accept_replacement(
        self,
        typed: &str,
        store: &dyn TrustStore,
        now_ms: i64,
    ) -> Result<(), ProtocolError> {
        // Case-insensitive and whitespace-trimmed, because the user is copying
        // from the screen; nothing else is forgiven.
        if !typed.trim().eq_ignore_ascii_case(&self.confirmation) {
            return Err(ProtocolError::ConfirmationMismatch);
        }
        let key = KnownKey::new(self.algorithm, self.blob, now_ms, TrustSource::Replaced);
        store.remember(&self.host, &key)
    }
}

/// Checks an offered key against the trust store.
///
/// Never auto-accepts and never mutates the store: recording a decision is a
/// separate, explicit call on the returned value.
pub fn verify_host_key(
    store: &dyn TrustStore,
    host: &HostPort,
    offered: &OfferedKey,
) -> HostKeyOutcome {
    let fingerprint = offered.fingerprint();
    match store.lookup(host, &offered.algorithm) {
        // Compared over the whole blob rather than the fingerprint: the digest
        // is what we show the user, the bytes are what we trust.
        Some(known) if known.blob == offered.blob => HostKeyOutcome::Trusted,
        Some(known) => HostKeyOutcome::Changed(ChangedHostKey {
            host: host.clone(),
            algorithm: offered.algorithm.clone(),
            blob: offered.blob.clone(),
            expected: known.fingerprint(),
            offered: fingerprint,
            expected_first_trusted_at_ms: known.added_at_ms,
            confirmation: confirmation_word(&fingerprint),
        }),
        None => HostKeyOutcome::Unknown(UnknownHostKey {
            host: host.clone(),
            algorithm: offered.algorithm.clone(),
            blob: offered.blob.clone(),
            fingerprint,
            randomart: fingerprint.randomart(&offered.algorithm),
        }),
    }
}

/// Short, unambiguous ASCII words. Thirty-two of them, so five bits of the
/// digest select one without modulo bias.
const WORDS: [&str; 32] = [
    "amber", "anchor", "beacon", "birch", "cobalt", "copper", "crimson", "delta", "ember",
    "falcon", "garnet", "harbor", "indigo", "ivory", "jasper", "kestrel", "lantern", "marble",
    "nickel", "onyx", "opal", "pewter", "quartz", "raven", "sable", "silver", "tundra", "umber",
    "violet", "walnut", "yarrow", "zephyr",
];

/// Two words from the fingerprint: `amber-quartz`.
fn confirmation_word(fingerprint: &Fingerprint) -> String {
    let digest = fingerprint.digest();
    let first = WORDS[usize::from(digest[0] & 0x1f)];
    let second = WORDS[usize::from(digest[1] & 0x1f)];
    format!("{first}-{second}")
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
    use std::sync::Mutex;

    /// An in-memory trust store, standing in for the vault.
    #[derive(Default)]
    struct MemoryStore {
        keys: Mutex<Vec<(String, String, KnownKey)>>,
        fail: bool,
    }

    impl MemoryStore {
        fn count(&self) -> usize {
            self.keys.lock().unwrap().len()
        }
    }

    impl TrustStore for MemoryStore {
        // Keyed on the canonical form, as the trait requires: the vault's store
        // has to behave this way, so the stand-in for it must too.
        fn lookup(&self, host: &HostPort, algorithm: &str) -> Option<KnownKey> {
            self.keys
                .lock()
                .unwrap()
                .iter()
                .find(|(h, a, _)| h == &host.canonical() && a == algorithm)
                .map(|(_, _, k)| k.clone())
        }

        fn remember(&self, host: &HostPort, key: &KnownKey) -> Result<(), ProtocolError> {
            if self.fail {
                return Err(ProtocolError::TrustStore {
                    operation: "remember a host key",
                    detail: "the store is read-only",
                });
            }
            let mut keys = self.keys.lock().unwrap();
            keys.retain(|(h, a, _)| !(h == &host.canonical() && a == &key.algorithm));
            keys.push((host.canonical(), key.algorithm.clone(), key.clone()));
            Ok(())
        }
    }

    fn host() -> HostPort {
        HostPort::new("bastion.acme.io", 22).unwrap()
    }

    #[test]
    fn a_fingerprint_renders_the_way_ssh_keygen_does() {
        // SHA-256 of the empty input, base64 without padding, which is the
        // form `ssh-keygen -l` prints.
        let fingerprint = Fingerprint::sha256(b"");
        assert_eq!(
            fingerprint.to_string(),
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        );
    }

    #[test]
    fn a_fingerprint_round_trips_through_its_text_form() {
        let fingerprint = Fingerprint::sha256(b"ssh-ed25519 key blob");
        let parsed = Fingerprint::parse(&fingerprint.to_string()).unwrap();
        assert_eq!(parsed, fingerprint);
        // The prefix is optional and padding is tolerated, because both turn up
        // in files people paste from.
        assert_eq!(
            Fingerprint::parse(&BASE64_NOPAD.encode(fingerprint.digest())).unwrap(),
            fingerprint
        );
    }

    #[test]
    fn a_malformed_fingerprint_is_refused() {
        assert!(matches!(
            Fingerprint::parse("SHA256:not base64!"),
            Err(ProtocolError::MalformedFingerprint)
        ));
        // Right alphabet, wrong length.
        assert!(matches!(
            Fingerprint::parse("SHA256:AAAA"),
            Err(ProtocolError::MalformedFingerprint)
        ));
    }

    #[test]
    fn randomart_is_a_fixed_size_deterministic_picture() {
        let fingerprint = Fingerprint::sha256(b"ssh-ed25519 AAAAC3Nz");
        let art = fingerprint.randomart("ED25519 256");
        let lines: Vec<&str> = art.lines().collect();

        // Two borders plus the field.
        assert_eq!(lines.len(), FIELD_HEIGHT + 2);
        for line in &lines {
            assert_eq!(line.chars().count(), FIELD_WIDTH + 2, "ragged line: {line}");
        }
        assert!(lines[0].contains("[ED25519 256]"));
        assert!(lines[FIELD_HEIGHT + 1].contains("[SHA256]"));
        assert!(art.contains('S'), "the start square must be marked");
        assert!(art.contains('E'), "the end square must be marked");
        assert_eq!(art, fingerprint.randomart("ED25519 256"));
    }

    /// A known-answer test against OpenSSH itself.
    ///
    /// The key below was generated with `ssh-keygen -t ed25519` and the
    /// picture is what `ssh-keygen -lvf` printed for it. Randomart is only
    /// useful if it matches what the rest of the world draws — a picture that
    /// is merely self-consistent cannot be compared with the one an
    /// administrator has on their screen.
    #[test]
    fn randomart_matches_what_ssh_keygen_draws() {
        let blob = data_encoding::BASE64
            .decode(b"AAAAC3NzaC1lZDI1NTE5AAAAIJRouY0PYR3LPh8XJKKfYRAhP3nKcDDhECrpwMZmMEmP")
            .unwrap();
        let fingerprint = Fingerprint::sha256(&blob);
        assert_eq!(
            fingerprint.to_string(),
            "SHA256:lT6JdE4ldV/P4i5ptUe7qHRhCNZHGkc67QxWOU8trg8"
        );
        assert_eq!(
            fingerprint.randomart("ED25519 256"),
            concat!(
                "+--[ED25519 256]--+\n",
                "|          .o+=o o|\n",
                "|          .+O+.++|\n",
                "|        .o=B +=.+|\n",
                "|       ..Bo.B..o |\n",
                "|        S =. *o .|\n",
                "|           .E+.o.|\n",
                "|           .++o..|\n",
                "|          ....o..|\n",
                "|           ... . |\n",
                "+----[SHA256]-----+",
            )
        );
    }

    #[test]
    fn randomart_differs_between_keys() {
        let one = Fingerprint::sha256(b"key one").randomart("ED25519 256");
        let two = Fingerprint::sha256(b"key two").randomart("ED25519 256");
        assert_ne!(one, two);
    }

    #[test]
    fn an_over_long_title_does_not_widen_the_frame() {
        let art = Fingerprint::sha256(b"k").randomart("a title far too long to fit");
        for line in art.lines() {
            assert_eq!(line.chars().count(), FIELD_WIDTH + 2);
        }
    }

    #[test]
    fn a_matching_key_is_trusted_silently() {
        let store = MemoryStore::default();
        let offered = OfferedKey::new("ssh-ed25519", b"blob".to_vec());
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-ed25519", b"blob".to_vec(), 0, TrustSource::Prompted),
            )
            .unwrap();

        let outcome = verify_host_key(&store, &host(), &offered);
        assert!(outcome.is_trusted());
        assert_eq!(outcome.decision(), HostKeyDecision::Trusted);
    }

    #[test]
    fn an_unknown_key_prompts_and_can_be_remembered() {
        let store = MemoryStore::default();
        let offered = OfferedKey::new("ssh-ed25519", b"blob".to_vec());

        let outcome = verify_host_key(&store, &host(), &offered);
        let HostKeyOutcome::Unknown(unknown) = outcome else {
            panic!("an empty store must report the key as unknown");
        };
        assert_eq!(unknown.fingerprint(), offered.fingerprint());
        assert!(!unknown.randomart().is_empty());
        unknown
            .accept(&store, 1_700_000_000_000, TrustSource::Prompted)
            .unwrap();

        assert!(verify_host_key(&store, &host(), &offered).is_trusted());
    }

    /// A trust decision the user already made must not be walked past because
    /// something respelled the host.
    ///
    /// An importer that writes a fully qualified name, or a user who typed the
    /// host in capitals, used to produce a second trusted identity for one
    /// machine: the stored key was not found, so the connection was reported as
    /// a first use and the person was asked again — training them to click
    /// through the one prompt that matters.
    #[test]
    fn a_key_trusted_under_one_spelling_is_trusted_under_the_others() {
        let store = MemoryStore::default();
        let approved = HostPort::new("db-01.internal", 22).unwrap();
        let offered = OfferedKey::new("ssh-ed25519", b"blob".to_vec());

        let HostKeyOutcome::Unknown(unknown) = verify_host_key(&store, &approved, &offered) else {
            panic!("an empty store must report the key as unknown");
        };
        unknown
            .accept(&store, 1_700_000_000_000, TrustSource::Prompted)
            .unwrap();

        for spelling in ["DB-01.internal", "db-01.internal.", "Db-01.Internal."] {
            let host = HostPort::new(spelling, 22).unwrap();
            assert!(
                verify_host_key(&store, &host, &offered).is_trusted(),
                "`{spelling}` was treated as a different machine"
            );
        }
        assert_eq!(
            store.count(),
            1,
            "one machine became {} entries",
            store.count()
        );

        // And a genuinely different machine is still a different machine.
        let other = HostPort::new("db-02.internal", 22).unwrap();
        assert!(matches!(
            verify_host_key(&store, &other, &offered),
            HostKeyOutcome::Unknown(_)
        ));
    }

    /// The dangerous half of the same bug: with the host respelled, a key that
    /// had actually changed looked like a host nothing was stored for, so the
    /// man-in-the-middle warning became an ordinary first-use prompt.
    #[test]
    fn a_changed_key_is_still_changed_when_the_host_is_respelled() {
        let store = MemoryStore::default();
        store
            .remember(
                &HostPort::new("db-01.internal", 22).unwrap(),
                &KnownKey::new("ssh-ed25519", b"old".to_vec(), 0, TrustSource::Prompted),
            )
            .unwrap();

        let forged = OfferedKey::new("ssh-ed25519", b"forged".to_vec());
        let qualified = HostPort::new("DB-01.internal.", 22).unwrap();
        let outcome = verify_host_key(&store, &qualified, &forged);
        let HostKeyOutcome::Changed(changed) = outcome else {
            panic!("a respelled host must not downgrade a changed key to a first use");
        };
        assert_eq!(changed.expected(), Fingerprint::sha256(b"old"));
    }

    #[test]
    fn a_key_stored_under_another_algorithm_is_unknown_not_changed() {
        let store = MemoryStore::default();
        store
            .remember(
                &host(),
                &KnownKey::new("rsa-sha2-512", b"rsa".to_vec(), 0, TrustSource::Prompted),
            )
            .unwrap();

        let offered = OfferedKey::new("ssh-ed25519", b"ed".to_vec());
        assert!(matches!(
            verify_host_key(&store, &host(), &offered),
            HostKeyOutcome::Unknown(_)
        ));
    }

    #[test]
    fn a_rejected_unknown_key_names_the_host() {
        let store = MemoryStore::default();
        let offered = OfferedKey::new("ssh-ed25519", b"blob".to_vec());
        let HostKeyOutcome::Unknown(unknown) = verify_host_key(&store, &host(), &offered) else {
            panic!("expected an unknown key");
        };
        let error = unknown.reject();
        assert!(error.to_string().contains("bastion.acme.io:22"));
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn a_changed_key_is_a_hard_failure_that_names_both_fingerprints() {
        let store = MemoryStore::default();
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-ed25519", b"old".to_vec(), 0, TrustSource::Prompted),
            )
            .unwrap();

        let offered = OfferedKey::new("ssh-ed25519", b"new".to_vec());
        let HostKeyOutcome::Changed(changed) = verify_host_key(&store, &host(), &offered) else {
            panic!("a differing key must be reported as changed");
        };
        assert_eq!(changed.expected(), Fingerprint::sha256(b"old"));
        assert_eq!(changed.offered(), Fingerprint::sha256(b"new"));

        let rendered = changed.into_error().to_string();
        assert!(rendered.contains(&Fingerprint::sha256(b"old").to_string()));
        assert!(rendered.contains(&Fingerprint::sha256(b"new").to_string()));
    }

    /// The changed-key dialog is a comparison, so the prompt has to carry both
    /// sides of it.
    ///
    /// Carrying only the offered fingerprint made the required dialog
    /// impossible to build: the user could not compare the stored value with
    /// the offered one, and with no host named they could not tell which
    /// machine was being talked about — while the transport-security document
    /// requires "a red, blocking dialog … showing both fingerprints".
    #[test]
    fn a_changed_key_prompt_carries_both_fingerprints_and_names_the_host() {
        let store = MemoryStore::default();
        store
            .remember(
                &host(),
                &KnownKey::new(
                    "ssh-ed25519",
                    b"old".to_vec(),
                    1_700_000_000_000,
                    TrustSource::Prompted,
                ),
            )
            .unwrap();

        let offered = OfferedKey::new("ssh-ed25519", b"new".to_vec());
        let HostKeyOutcome::Changed(changed) = verify_host_key(&store, &host(), &offered) else {
            panic!("a differing key must be reported as changed");
        };

        let prompt = changed.prompt();
        assert!(prompt.is_changed_host_key());
        let PromptKind::HostKey {
            host: named,
            algorithm,
            fingerprint,
            randomart,
            previously_trusted,
        } = prompt
        else {
            panic!("expected a host key prompt");
        };

        assert_eq!(named, "bastion.acme.io:22", "the dialog must name the host");
        assert_eq!(algorithm, "ssh-ed25519");
        assert_eq!(fingerprint, Fingerprint::sha256(b"new").to_string());
        assert!(randomart.lines().count() >= FIELD_HEIGHT + 2);

        let stored = previously_trusted.expect("a changed key has a previously trusted one");
        assert_eq!(stored.fingerprint, Fingerprint::sha256(b"old").to_string());
        assert_eq!(stored.first_trusted_at_ms, 1_700_000_000_000);
        assert!(stored.randomart.lines().count() >= FIELD_HEIGHT + 2);
        assert_ne!(
            stored.randomart, randomart,
            "two pictures that are the same are not a comparison"
        );

        // And the same values reach the serialisable decision the interface
        // subscribes to.
        let HostKeyDecision::Changed {
            expected,
            expected_randomart,
            expected_first_trusted_at_ms,
            offered: offered_print,
            offered_randomart,
        } = verify_host_key(&store, &host(), &offered).decision()
        else {
            panic!("expected a changed decision");
        };
        assert_eq!(expected, Fingerprint::sha256(b"old"));
        assert_eq!(offered_print, Fingerprint::sha256(b"new"));
        assert_eq!(expected_first_trusted_at_ms, 1_700_000_000_000);
        assert_ne!(expected_randomart, offered_randomart);
    }

    #[test]
    fn a_first_use_prompt_names_the_host_and_the_key_type_and_has_no_stored_key() {
        let store = MemoryStore::default();
        let offered = OfferedKey::new("ssh-ed25519", b"blob".to_vec());
        let HostKeyOutcome::Unknown(unknown) = verify_host_key(&store, &host(), &offered) else {
            panic!("an empty store must report the key as unknown");
        };

        let prompt = unknown.prompt();
        assert!(
            !prompt.is_changed_host_key(),
            "a first use is a question, not a man-in-the-middle warning"
        );
        let PromptKind::HostKey {
            host: named,
            algorithm,
            fingerprint,
            randomart,
            previously_trusted,
        } = prompt
        else {
            panic!("expected a host key prompt");
        };
        assert_eq!(named, "bastion.acme.io:22");
        assert_eq!(algorithm, "ssh-ed25519");
        assert_eq!(fingerprint, offered.fingerprint().to_string());
        assert!(randomart.lines().count() >= FIELD_HEIGHT + 2);
        assert!(previously_trusted.is_none());
    }

    #[test]
    fn replacing_a_changed_key_needs_the_exact_word() {
        let store = MemoryStore::default();
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-ed25519", b"old".to_vec(), 0, TrustSource::Prompted),
            )
            .unwrap();
        let offered = OfferedKey::new("ssh-ed25519", b"new".to_vec());

        let HostKeyOutcome::Changed(changed) = verify_host_key(&store, &host(), &offered) else {
            panic!("expected a changed key");
        };
        let word = changed.confirmation_word().to_owned();
        assert!(word.contains('-'));

        // A wrong word leaves the stored key alone.
        assert!(matches!(
            changed.accept_replacement("yes", &store, 1),
            Err(ProtocolError::ConfirmationMismatch)
        ));
        let still_old = store.lookup(&host(), "ssh-ed25519").unwrap();
        assert_eq!(still_old.blob, b"old".to_vec());

        // The right word, however it was capitalised on the way out of the
        // screen, replaces it.
        let HostKeyOutcome::Changed(changed) = verify_host_key(&store, &host(), &offered) else {
            panic!("expected a changed key");
        };
        changed
            .accept_replacement(&format!("  {} ", word.to_uppercase()), &store, 42)
            .unwrap();
        let replaced = store.lookup(&host(), "ssh-ed25519").unwrap();
        assert_eq!(replaced.blob, b"new".to_vec());
        assert_eq!(replaced.source, TrustSource::Replaced);
        assert_eq!(replaced.added_at_ms, 42);
    }

    #[test]
    fn the_confirmation_word_is_stable_for_a_key_and_differs_between_keys() {
        let store = MemoryStore::default();
        store
            .remember(
                &host(),
                &KnownKey::new("ssh-ed25519", b"old".to_vec(), 0, TrustSource::Prompted),
            )
            .unwrap();

        let word_for = |blob: &[u8]| {
            let offered = OfferedKey::new("ssh-ed25519", blob.to_vec());
            let HostKeyOutcome::Changed(changed) = verify_host_key(&store, &host(), &offered)
            else {
                panic!("expected a changed key");
            };
            changed.confirmation_word().to_owned()
        };

        assert_eq!(word_for(b"new"), word_for(b"new"));
        assert_ne!(word_for(b"new"), word_for(b"other"));
    }

    #[test]
    fn a_store_that_cannot_write_surfaces_the_failure() {
        let store = MemoryStore {
            fail: true,
            ..MemoryStore::default()
        };
        let offered = OfferedKey::new("ssh-ed25519", b"blob".to_vec());
        let HostKeyOutcome::Unknown(unknown) = verify_host_key(&store, &host(), &offered) else {
            panic!("expected an unknown key");
        };
        assert!(matches!(
            unknown.accept(&store, 0, TrustSource::Prompted),
            Err(ProtocolError::TrustStore { .. })
        ));
    }
}
