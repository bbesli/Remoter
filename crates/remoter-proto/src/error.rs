//! The failure taxonomy.
//!
//! Every variant here maps onto a row of the table in
//! `docs/architecture/session-pipeline.md`. The pattern that table sets is:
//! **name what failed, name where, and offer the next action**. "Connection
//! failed" is not an acceptable outcome anywhere in this pipeline, because it
//! forces the user to reproduce the problem with a command-line tool to learn
//! what the connection manager already knew.
//!
//! Two rules govern what a variant may carry.
//!
//! 1. **No secret, ever.** Errors are formatted into logs, crash reports and
//!    the copyable diagnostic on a failed tab; anything reachable from one is
//!    effectively public. Free-form detail fields are `&'static str` rather
//!    than `String` for exactly this reason: a secret is a runtime value, and a
//!    runtime value cannot be a string literal, so the leak is structurally
//!    impossible rather than merely discouraged. The fields that *are* `String`
//!    hold values the user typed (a hostname, a settings key) or the peer sent
//!    (an algorithm name, a disconnect message) — never a value this process
//!    decrypted.
//! 2. **English here is diagnostic, not user-facing.** The interface matches on
//!    the variant and renders a translated sentence; these `Display` strings are
//!    what goes in the log.

use std::io;

use remoter_core::ProtocolId;
use serde::{Deserialize, Serialize};

use crate::credentials::CredentialKind;
use crate::hostkey::Fingerprint;
use crate::supervisor::SessionId;
use crate::transport::HostPort;

/// Which stage of the session pipeline a failure belongs to.
///
/// The interface groups messages by this, and the audit log records it, so that
/// "we never get past Transport on this host" is a question the data can answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// 1 — flattening inheritance into an `EffectiveConnection`.
    Resolve,
    /// 2 — policy checks, confirmations, recording notice.
    Authorise,
    /// 3 — borrowing credentials from the vault.
    Acquire,
    /// 4 — building the gateway chain into a transport.
    Transport,
    /// 5 — negotiating, and verifying the far end's identity.
    Handshake,
    /// 6 — using the credentials.
    Authenticate,
    /// 7 — registering the session and binding the tab.
    Attach,
    /// 8 — input, output, resize, clipboard, recording.
    Run,
    /// 9 — cancellation, cleanup, audit entry.
    Terminate,
}

impl Stage {
    /// A stable ASCII name, for logs and message catalogue keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Authorise => "authorise",
            Self::Acquire => "acquire",
            Self::Transport => "transport",
            Self::Handshake => "handshake",
            Self::Authenticate => "authenticate",
            Self::Attach => "attach",
            Self::Run => "run",
            Self::Terminate => "terminate",
        }
    }
}

/// What the user can do about a failure.
///
/// Returned as a list rather than a sentence so the interface can render each
/// one as a button that actually does the thing, and so the wording stays in
/// the message catalogue where translators can reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    /// Open this connection's settings.
    OpenSettings,
    /// Open the gateway chain editor.
    EditGatewayChain,
    /// Check the address, or the DNS server that should know it.
    CheckAddress,
    /// Check that the service is listening on that port.
    CheckService,
    /// Check the firewall, or the gateway in front of it.
    CheckFirewall,
    /// Check the network connection.
    CheckNetwork,
    /// Try again now.
    Retry,
    /// Reconnect, with the backoff the connection is configured for.
    Reconnect,
    /// Pick a different credential.
    ChooseCredential,
    /// Enter a credential for this attempt.
    EnterCredential,
    /// Choose a different authentication method.
    ChooseAuthMethod,
    /// Show the host key prompt.
    ReviewHostKey,
    /// Verify the fingerprint out of band before doing anything else.
    VerifyFingerprintOutOfBand,
    /// Pin the certificate to this connection.
    PinCertificate,
    /// Close another session, or raise the limit.
    CloseAnotherSession,
    /// The server needs configuring, or the legacy build is required.
    ContactAdministrator,
    /// This is a defect in Remoter; the diagnostic is worth attaching to an
    /// issue.
    ReportDefect,
}

impl NextAction {
    /// A stable ASCII name, used as the message catalogue key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenSettings => "open-settings",
            Self::EditGatewayChain => "edit-gateway-chain",
            Self::CheckAddress => "check-address",
            Self::CheckService => "check-service",
            Self::CheckFirewall => "check-firewall",
            Self::CheckNetwork => "check-network",
            Self::Retry => "retry",
            Self::Reconnect => "reconnect",
            Self::ChooseCredential => "choose-credential",
            Self::EnterCredential => "enter-credential",
            Self::ChooseAuthMethod => "choose-auth-method",
            Self::ReviewHostKey => "review-host-key",
            Self::VerifyFingerprintOutOfBand => "verify-fingerprint-out-of-band",
            Self::PinCertificate => "pin-certificate",
            Self::CloseAnotherSession => "close-another-session",
            Self::ContactAdministrator => "contact-administrator",
            Self::ReportDefect => "report-defect",
        }
    }
}

/// Which family of algorithm failed to negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmKind {
    /// Key exchange.
    KeyExchange,
    /// Host key.
    HostKey,
    /// Symmetric cipher.
    Cipher,
    /// Message authentication code.
    Mac,
    /// Compression.
    Compression,
}

impl AlgorithmKind {
    /// A stable ASCII name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyExchange => "key exchange",
            Self::HostKey => "host key",
            Self::Cipher => "cipher",
            Self::Mac => "MAC",
            Self::Compression => "compression",
        }
    }
}

/// Why a TLS certificate was not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateProblem {
    /// Signed by itself — the norm on internal RDP hosts, and the reason
    /// pinning exists.
    SelfSigned,
    /// Signed by an authority not in the platform's trust store.
    UntrustedRoot,
    /// Outside its validity window.
    Expired,
    /// Valid, but not for this name.
    NameMismatch,
    /// Revoked by its issuer.
    Revoked,
    /// Could not be parsed.
    Malformed,
    /// Differs from the certificate pinned to this connection.
    Changed,
}

impl CertificateProblem {
    /// A stable ASCII name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SelfSigned => "self-signed",
            Self::UntrustedRoot => "untrusted root",
            Self::Expired => "expired",
            Self::NameMismatch => "name mismatch",
            Self::Revoked => "revoked",
            Self::Malformed => "malformed",
            Self::Changed => "changed",
        }
    }
}

/// Everything that can go wrong between a double-click and a shell prompt, and
/// everything that can go wrong afterwards.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    // ── 1 · Resolve ─────────────────────────────────────────────────────────
    /// The connection has no host to connect to.
    #[error("this connection has no address")]
    NoAddress,

    /// A host was not a DNS name, an IPv4 address or a bracketed IPv6 address.
    #[error("`{host}` is not a valid address")]
    InvalidHost {
        /// The rejected host, as the user typed it.
        host: String,
    },

    /// Port zero is not connectable.
    #[error("port must be in 1..=65535")]
    InvalidPort,

    /// The gateway chain visits a node twice, so it loops.
    #[error(
        "the gateway chain loops back on itself: `{label}` is hop {position} of {total} and appears earlier"
    )]
    GatewayCycle {
        /// The gateway that repeats, by name.
        label: String,
        /// Its 1-based position in the chain.
        position: usize,
        /// The chain length.
        total: usize,
    },

    /// The gateway chain is longer than the pipeline permits.
    #[error("the gateway chain has {hops} hops; the maximum is {max}")]
    GatewayTooLong {
        /// The number of hops supplied.
        hops: usize,
        /// The permitted maximum.
        max: usize,
    },

    /// A hop refers to a node that no longer exists.
    #[error("gateway hop {position} of {total} refers to `{label}`, which has been deleted")]
    GatewayHopDeleted {
        /// The deleted gateway's last known name.
        label: String,
        /// Its 1-based position in the chain.
        position: usize,
        /// The chain length.
        total: usize,
    },

    // ── 2 · Authorise ───────────────────────────────────────────────────────
    /// The session cap was reached.
    #[error("{open} sessions are open; the limit is {limit}")]
    SessionLimit {
        /// How many are open.
        open: usize,
        /// The configured cap.
        limit: usize,
    },

    // ── 3 · Acquire ─────────────────────────────────────────────────────────
    /// The credential this connection used has been deleted.
    #[error("the credential `{name}` this connection used has been deleted")]
    CredentialMissing {
        /// Its last known name.
        name: String,
    },

    /// The credential is restricted to other protocols.
    ///
    /// This is what stops an importer mistake or a mistyped protocol from
    /// spraying a password at the wrong service.
    #[error("this credential is restricted to {allowed:?} and cannot be used for `{attempted}`")]
    CredentialPurposeMismatch {
        /// The protocols the credential permits.
        allowed: Vec<String>,
        /// The protocol that tried to borrow it.
        attempted: ProtocolId,
    },

    /// Nothing resolved a credential and none was supplied.
    #[error("no credential is available for `{target}`")]
    CredentialRequired {
        /// Where the attempt was going.
        target: HostPort,
    },

    // ── 4 · Transport ───────────────────────────────────────────────────────
    /// The name did not resolve.
    #[error("`{host}` could not be resolved")]
    DnsFailure {
        /// The name that did not resolve.
        host: String,
    },

    /// Something answered the port and refused.
    #[error("`{target}` refused the connection")]
    ConnectionRefused {
        /// The address that refused.
        target: HostPort,
    },

    /// Nothing answered in time.
    #[error("`{target}` did not respond within {timeout_ms} ms")]
    ConnectTimeout {
        /// The address that did not answer.
        target: HostPort,
        /// How long was allowed.
        timeout_ms: u64,
    },

    /// There is no route.
    #[error("`{target}` is unreachable")]
    NetworkUnreachable {
        /// The address with no route to it.
        target: HostPort,
    },

    /// One hop of a gateway chain failed.
    ///
    /// The position is carried because the failure taxonomy requires it: "could
    /// not reach the target through `bastion-2`, hop 2 of 3" tells the user
    /// which machine to look at, and a generic connection error does not.
    ///
    /// The cause is rendered *inside* this message rather than left to
    /// `source()`. [`FailureReport`] — what a failed tab actually shows — keeps
    /// only `to_string()`, so a cause that is not in the sentence never reaches
    /// the user. That is how a changed host key on `bastion-2` became "hop 2 of
    /// 3 failed" with no mention of a possible man-in-the-middle
    /// (`docs/security/threat-model.md`, T3).
    #[error(
        "could not reach the target through `{label}`: hop {position} of {total} failed: {source}"
    )]
    HopFailed {
        /// The gateway that failed, by name.
        label: String,
        /// Its 1-based position in the chain.
        position: usize,
        /// The chain length.
        total: usize,
        /// What went wrong at that hop.
        #[source]
        source: Box<ProtocolError>,
    },

    /// An operating system error that is not one of the cases above.
    #[error("{operation} failed: {source}")]
    Io {
        /// What was being attempted, in the user's terms.
        operation: &'static str,
        /// The underlying error.
        #[source]
        source: io::Error,
    },

    // ── 5 · Handshake ───────────────────────────────────────────────────────
    /// Nothing is stored for this host and the user has not decided yet.
    ///
    /// The pipeline suspends here; it is never auto-accepted.
    #[error("`{host}` offered an unrecognised {algorithm} key ({fingerprint})")]
    HostKeyUnknown {
        /// The host that offered it.
        host: HostPort,
        /// The key algorithm, as named on the wire.
        algorithm: String,
        /// The offered key's fingerprint.
        fingerprint: Fingerprint,
    },

    /// The stored key and the offered key differ. Possible man-in-the-middle.
    #[error(
        "`{host}` offered a {algorithm} key that does not match the one Remoter has: expected {expected}, got {offered}"
    )]
    HostKeyChanged {
        /// The host that offered it.
        host: HostPort,
        /// The key algorithm, as named on the wire.
        algorithm: String,
        /// What the vault says this host uses.
        expected: Fingerprint,
        /// What answered.
        offered: Fingerprint,
    },

    /// The user declined the key.
    #[error("the {algorithm} key offered by `{host}` was not accepted")]
    HostKeyRejected {
        /// The host that offered it.
        host: HostPort,
        /// The key algorithm, as named on the wire.
        algorithm: String,
    },

    /// A stored or pasted fingerprint could not be read.
    #[error("that is not a SHA-256 fingerprint")]
    MalformedFingerprint,

    /// The word the user typed did not match the one on screen.
    #[error("the confirmation did not match")]
    ConfirmationMismatch,

    /// No algorithm in common.
    ///
    /// Legacy algorithms are not compiled into the default build
    /// (`docs/security/transport-security.md`), so this is the message a
    /// 2009 switch produces, and it names what the server offered so the user
    /// can decide whether the legacy build is warranted.
    #[error("no {kind} algorithm in common; the server offers {offered:?}", kind = kind.as_str())]
    NoSharedAlgorithm {
        /// Which family failed.
        kind: AlgorithmKind,
        /// What the server offered. Peer-supplied text.
        offered: Vec<String>,
    },

    /// A TLS certificate was not trusted.
    #[error("the certificate for `{host}` is not trusted: {reason}", reason = reason.as_str())]
    CertificateUntrusted {
        /// The host whose certificate it is.
        host: HostPort,
        /// What is wrong with it.
        reason: CertificateProblem,
    },

    /// The handshake failed for a protocol-specific reason.
    #[error("the {protocol} handshake failed: {detail}")]
    HandshakeFailed {
        /// The protocol that was negotiating.
        protocol: ProtocolId,
        /// What went wrong. A literal, so a formatted secret cannot land here.
        detail: &'static str,
    },

    // ── 6 · Authenticate ────────────────────────────────────────────────────
    /// The server rejected the credentials.
    #[error("the server rejected these credentials ({attempted})")]
    AuthRejected {
        /// Which kind was tried. Never the credential itself.
        attempted: CredentialKind,
    },

    /// The server does not offer the method the credential needs.
    #[error("the server does not accept {attempted} authentication; it offers {offered:?}")]
    AuthMethodUnavailable {
        /// Which kind was tried.
        attempted: CredentialKind,
        /// What the server offers. Peer-supplied text.
        offered: Vec<String>,
    },

    /// The user dismissed a prompt.
    #[error("authentication was cancelled")]
    AuthCancelled,

    /// The platform SSH agent could not be reached.
    #[error("the SSH agent is not available")]
    AgentUnavailable,

    // ── 7 · Attach and 8 · Run ──────────────────────────────────────────────
    /// A settings key the adapter's schema does not accept.
    ///
    /// The key is named because the user has to find it; the value never is,
    /// because a settings map is exactly where a mistyped password ends up.
    #[error("the setting `{key}` is not valid: expected {expected}")]
    SettingInvalid {
        /// The offending key.
        key: String,
        /// What the schema wanted. A literal.
        expected: &'static str,
    },

    /// A required setting was not supplied.
    #[error("the setting `{key}` is required")]
    SettingRequired {
        /// The missing key.
        key: String,
    },

    /// The operation is not something this protocol does.
    #[error("`{protocol}` sessions do not support {operation}")]
    Unsupported {
        /// What was asked for.
        operation: &'static str,
        /// The protocol that was asked.
        protocol: ProtocolId,
    },

    /// Nothing is at the path the operation named.
    ///
    /// A *file-manager* failure on a session that is connected and working, and
    /// deliberately its own variant rather than a
    /// [`SettingInvalid`](Self::SettingInvalid): reporting a missing file as a
    /// bad setting sent the reader to the connection editor to fix a setting
    /// that was never wrong. The path is not carried — an SFTP status message
    /// is server-supplied text about a path, and the operation that failed
    /// already has the path where the interface can see it.
    #[error("there is nothing at that path on the server")]
    PathNotFound,

    /// The server refused access to a path.
    ///
    /// Distinct from [`AuthRejected`](Self::AuthRejected), and the distinction
    /// is the whole point. This arrives on a connection that authenticated
    /// minutes ago; reporting it as a credential rejection sends the reader off
    /// to re-check an SSH key that is working perfectly. "Who you are" and
    /// "what this file allows" are different questions.
    #[error("the server refused access to that path")]
    PathPermissionDenied,

    /// The server refused a file operation and did not say why.
    ///
    /// SFTP version 3 has a single catch-all status
    /// (`draft-ietf-secsh-filexfer-02` §7, `SSH_FX_FAILURE`) for everything
    /// that is neither "no such file" nor "permission denied", so a full disk,
    /// a quota, a read-only mount, a lock and a rename across two filesystems
    /// are genuinely indistinguishable here. Naming one of them would be a
    /// guess presented as a diagnosis.
    #[error("the server could not complete that operation on this file")]
    FileOperationRefused,

    /// The server closed the connection.
    #[error("the server closed the connection: {reason}")]
    Disconnected {
        /// The reason, where the protocol carries one. Peer-supplied text, to
        /// be rendered as untrusted.
        reason: String,
    },

    /// The network went away mid-session.
    #[error("the network connection was lost")]
    NetworkLost,

    /// The peer sent something the protocol does not allow.
    #[error("the peer violated the protocol: {detail}")]
    ProtocolViolation {
        /// What was wrong. A literal.
        detail: &'static str,
    },

    /// The session was cancelled — a closed tab, or a shutdown.
    #[error("the session was cancelled")]
    Cancelled,

    /// The session is gone; the command had nowhere to go.
    #[error("the session is no longer running")]
    SessionClosed,

    /// The event stream's consumer went away.
    #[error("the session event stream was closed")]
    EventStreamClosed,

    /// The trust store could not be read or written.
    #[error("{operation} failed: {detail}")]
    TrustStore {
        /// What was being attempted.
        operation: &'static str,
        /// Why it failed. A literal supplied by the store implementation,
        /// which must not put vault contents in it.
        detail: &'static str,
    },

    // ── 9 · Terminate ───────────────────────────────────────────────────────
    /// A session task panicked.
    ///
    /// Per ADR-0011 the session is destroyed, never resumed, and the panic
    /// payload is deliberately not carried: a payload contains formatted
    /// values, and a formatted value can contain a secret.
    #[error("session {session} failed with an internal error and has been closed")]
    Panicked {
        /// Which session.
        session: SessionId,
    },

    /// A session did not stop within its grace period and was aborted.
    #[error("session {session} did not shut down within {grace_ms} ms and was aborted")]
    ShutdownTimeout {
        /// Which session.
        session: SessionId,
        /// The grace period it exceeded.
        grace_ms: u64,
    },

    /// An invariant of this crate was violated. A defect, not a user error.
    #[error("internal error: {detail}")]
    Internal {
        /// What went wrong. A literal.
        detail: &'static str,
    },
}

impl ProtocolError {
    /// The failure underneath any [`HopFailed`](Self::HopFailed) wrappers.
    ///
    /// Classification walks to this rather than matching the outermost variant.
    /// Every hop of a chain is authenticated independently
    /// (`docs/security/transport-security.md`, "Tunnels and jump hosts"), so a
    /// failure that matters at the target matters identically at hop 1 — and
    /// wrapping is exactly what a chain does to it.
    #[must_use]
    pub fn root_cause(&self) -> &Self {
        let mut current = self;
        while let Self::HopFailed { source, .. } = current {
            current = source;
        }
        current
    }

    /// Whether *this* variant is a question about who the far end is.
    ///
    /// These are the outcomes of stage 5 of the pipeline — the identity check
    /// that `docs/architecture/session-pipeline.md` says suspends the pipeline
    /// and is never auto-accepted. None of them is a connectivity problem, so
    /// none of them may be retried by a machine.
    #[must_use]
    pub const fn is_identity_failure(&self) -> bool {
        matches!(
            self,
            Self::HostKeyUnknown { .. }
                | Self::HostKeyChanged { .. }
                | Self::HostKeyRejected { .. }
                | Self::CertificateUntrusted { .. }
        )
    }

    /// Whether an identity failure sits anywhere in this error, however deeply
    /// a gateway chain has wrapped it.
    ///
    /// This is the predicate that keeps auto-reconnect from retrying a
    /// man-in-the-middle on a bastion: `ChainBuilder` wraps the hop's error in
    /// [`HopFailed`](Self::HopFailed), and a check on the outermost variant
    /// alone sees a retryable transport failure.
    #[must_use]
    pub fn involves_identity_failure(&self) -> bool {
        self.root_cause().is_identity_failure()
    }

    /// Which stage of the pipeline this belongs to.
    ///
    /// A hop failure reports the stage of what it wraps: a bastion that refused
    /// the socket failed at Transport, and one whose host key changed failed at
    /// Handshake. Reporting Transport for both would file a possible
    /// man-in-the-middle under "could not connect".
    #[must_use]
    pub fn stage(&self) -> Stage {
        match self.root_cause() {
            Self::NoAddress
            | Self::InvalidHost { .. }
            | Self::InvalidPort
            | Self::GatewayCycle { .. }
            | Self::GatewayTooLong { .. }
            | Self::GatewayHopDeleted { .. } => Stage::Resolve,

            Self::SessionLimit { .. } => Stage::Authorise,

            Self::CredentialMissing { .. }
            | Self::CredentialPurposeMismatch { .. }
            | Self::CredentialRequired { .. } => Stage::Acquire,

            Self::DnsFailure { .. }
            | Self::ConnectionRefused { .. }
            | Self::ConnectTimeout { .. }
            | Self::NetworkUnreachable { .. }
            // `root_cause` never yields a `HopFailed`; the arm is here to keep
            // the match exhaustive, so that a new variant is a compile error
            // rather than a silent fall-through.
            | Self::HopFailed { .. }
            | Self::Io { .. } => Stage::Transport,

            Self::HostKeyUnknown { .. }
            | Self::HostKeyChanged { .. }
            | Self::HostKeyRejected { .. }
            | Self::MalformedFingerprint
            | Self::ConfirmationMismatch
            | Self::NoSharedAlgorithm { .. }
            | Self::CertificateUntrusted { .. }
            | Self::HandshakeFailed { .. }
            | Self::TrustStore { .. } => Stage::Handshake,

            Self::AuthRejected { .. }
            | Self::AuthMethodUnavailable { .. }
            | Self::AuthCancelled
            | Self::AgentUnavailable => Stage::Authenticate,

            Self::SettingInvalid { .. } | Self::SettingRequired { .. } => Stage::Attach,

            Self::Unsupported { .. }
            // A file-manager failure on a session that is already running: the
            // connection is up, and only this one operation on this one path
            // failed.
            | Self::PathNotFound
            | Self::PathPermissionDenied
            | Self::FileOperationRefused
            | Self::Disconnected { .. }
            | Self::NetworkLost
            | Self::ProtocolViolation { .. }
            | Self::Cancelled
            | Self::SessionClosed
            | Self::EventStreamClosed
            | Self::Internal { .. } => Stage::Run,

            Self::Panicked { .. } | Self::ShutdownTimeout { .. } => Stage::Terminate,
        }
    }

    /// What the user can do about it, most useful first.
    ///
    /// A static slice rather than a sentence: the interface turns each entry
    /// into a button, and the wording lives in the message catalogue.
    ///
    /// A hop that failed on the far end's identity offers the identity actions,
    /// not the chain-editing ones: "edit the gateway chain" and "retry" are the
    /// wrong advice for a key that changed on `bastion-2`, and offering Retry
    /// beside a possible man-in-the-middle is the button the user will press.
    #[must_use]
    pub fn next_actions(&self) -> &'static [NextAction] {
        use NextAction as A;
        if let Self::HopFailed { source, .. } = self
            && source.involves_identity_failure()
        {
            return source.next_actions();
        }
        match self {
            Self::NoAddress | Self::InvalidHost { .. } | Self::InvalidPort => &[A::OpenSettings],

            Self::GatewayCycle { .. }
            | Self::GatewayTooLong { .. }
            | Self::GatewayHopDeleted { .. } => &[A::EditGatewayChain, A::OpenSettings],

            Self::SessionLimit { .. } => &[A::CloseAnotherSession, A::OpenSettings],

            Self::CredentialMissing { .. } => &[A::ChooseCredential, A::EnterCredential],
            Self::CredentialPurposeMismatch { .. } => &[A::ChooseCredential, A::OpenSettings],
            Self::CredentialRequired { .. } => &[A::EnterCredential, A::ChooseCredential],

            Self::DnsFailure { .. } => &[A::CheckAddress, A::OpenSettings],
            Self::ConnectionRefused { .. } => &[A::CheckService, A::OpenSettings, A::Retry],
            Self::ConnectTimeout { .. } => &[A::CheckFirewall, A::CheckAddress, A::Retry],
            Self::NetworkUnreachable { .. } | Self::NetworkLost => &[A::CheckNetwork, A::Retry],
            Self::HopFailed { .. } => &[A::EditGatewayChain, A::CheckNetwork, A::Retry],
            Self::Io { .. } => &[A::Retry, A::CheckNetwork],

            Self::HostKeyUnknown { .. } => &[A::ReviewHostKey],
            // Deliberately no "accept" action: a changed key is verified out of
            // band or not at all, and the replacement path is a separate,
            // typed confirmation rather than a button on an error card.
            Self::HostKeyChanged { .. } => {
                &[A::VerifyFingerprintOutOfBand, A::ContactAdministrator]
            }
            Self::HostKeyRejected { .. } => &[A::ReviewHostKey],
            Self::MalformedFingerprint | Self::ConfirmationMismatch => &[A::ReviewHostKey],
            Self::NoSharedAlgorithm { .. } => &[A::ContactAdministrator],
            Self::CertificateUntrusted { .. } => &[A::PinCertificate, A::ContactAdministrator],
            Self::HandshakeFailed { .. } => &[A::Retry, A::ContactAdministrator],
            Self::TrustStore { .. } => &[A::Retry, A::ReportDefect],

            Self::AuthRejected { .. } => &[A::EnterCredential, A::ChooseCredential],
            Self::AuthMethodUnavailable { .. } => &[A::ChooseAuthMethod, A::ChooseCredential],
            Self::AuthCancelled => &[A::Retry],
            Self::AgentUnavailable => &[A::ChooseCredential, A::ChooseAuthMethod],

            Self::SettingInvalid { .. } | Self::SettingRequired { .. } => &[A::OpenSettings],

            Self::Unsupported { .. } => &[],
            // "Try again" is the way out of a stale listing, which is the
            // commonest cause by a wide margin: the folder on screen is a few
            // seconds old and the file moved in between.
            Self::PathNotFound => &[A::Retry],
            // Deliberately *not* a credential action. Offering "enter a
            // credential" beside a file-permission refusal is what taught users
            // to re-check a working key.
            Self::PathPermissionDenied => &[A::ContactAdministrator],
            Self::FileOperationRefused => &[A::Retry, A::ContactAdministrator],
            Self::Disconnected { .. } => &[A::Reconnect],
            Self::ProtocolViolation { .. } => &[A::Reconnect, A::ReportDefect],
            Self::Cancelled | Self::SessionClosed => &[],
            Self::EventStreamClosed | Self::Internal { .. } => &[A::ReportDefect],

            Self::Panicked { .. } => &[A::Reconnect, A::ReportDefect],
            Self::ShutdownTimeout { .. } => &[A::ReportDefect],
        }
    }

    /// Whether trying the same thing again could plausibly work.
    ///
    /// Drives auto-reconnect: retrying a rejected password or a changed host
    /// key is not persistence, it is a lockout and a security hole
    /// respectively.
    ///
    /// A hop failure reports the retryability of **what it wraps**, never its
    /// own. `HopFailed` is a position label, not a diagnosis: classifying it as
    /// retryable made the reconnect loop retry whatever happened on the
    /// bastion, including an active attacker presenting a forged host key
    /// (`docs/security/threat-model.md`, T3) — and the loop is silent, so the
    /// user was never told the key had changed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        // Belt and braces: the delegation below already reaches the identity
        // failure, but a future wrapping variant must not be able to hide one.
        if self.involves_identity_failure() {
            return false;
        }
        match self {
            Self::HopFailed { source, .. } => source.is_retryable(),
            other => matches!(
                other,
                Self::ConnectionRefused { .. }
                    | Self::ConnectTimeout { .. }
                    | Self::NetworkUnreachable { .. }
                    | Self::NetworkLost
                    | Self::DnsFailure { .. }
                    | Self::Io { .. }
                    | Self::Disconnected { .. }
            ),
        }
    }

    /// Whether this failure needs a human before the session can continue.
    ///
    /// Walks the chain for the same reason [`is_retryable`](Self::is_retryable)
    /// does: a key that changed on hop 2 needs a person just as much as one
    /// that changed on the target.
    #[must_use]
    pub fn needs_user_decision(&self) -> bool {
        matches!(
            self.root_cause(),
            Self::HostKeyUnknown { .. }
                | Self::HostKeyChanged { .. }
                | Self::CertificateUntrusted { .. }
                | Self::CredentialRequired { .. }
                | Self::AuthRejected { .. }
        )
    }

    /// Wraps a hop failure with the position the taxonomy requires.
    #[must_use]
    pub fn at_hop(self, label: impl Into<String>, position: usize, total: usize) -> Self {
        Self::HopFailed {
            label: label.into(),
            position,
            total,
            source: Box::new(self),
        }
    }
}

/// A failure, flattened for the interface and for the audit log.
///
/// [`ProtocolError`] is not `Clone` — it carries an `io::Error` — and a session
/// event has to be. The conversion happens once, at the boundary, and keeps
/// only what a tab needs to render: the stage, the diagnostic sentence, and the
/// buttons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureReport {
    /// Which stage failed.
    pub stage: Stage,
    /// The diagnostic sentence. Never contains a secret, by the rules at the
    /// top of this module.
    pub message: String,
    /// What the user can do.
    pub next_actions: Vec<NextAction>,
    /// Whether an automatic retry is worth attempting.
    pub retryable: bool,
}

impl From<&ProtocolError> for FailureReport {
    fn from(error: &ProtocolError) -> Self {
        Self {
            stage: error.stage(),
            message: error.to_string(),
            next_actions: error.next_actions().to_vec(),
            retryable: error.is_retryable(),
        }
    }
}

impl From<ProtocolError> for FailureReport {
    fn from(error: ProtocolError) -> Self {
        Self::from(&error)
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
    use crate::credentials::CredentialProvider;
    use crate::hostkey::Fingerprint;

    fn target() -> HostPort {
        HostPort::new("10.0.0.5", 22).unwrap()
    }

    fn protocol() -> ProtocolId {
        ProtocolId::new("ssh").unwrap()
    }

    /// One of every variant, so that a new variant added without a stage, an
    /// action list or a secrecy review shows up as a compile or test failure
    /// rather than as a surprise in production.
    fn every_variant() -> Vec<ProtocolError> {
        vec![
            ProtocolError::NoAddress,
            ProtocolError::InvalidHost {
                host: "not a host".to_owned(),
            },
            ProtocolError::InvalidPort,
            ProtocolError::GatewayCycle {
                label: "bastion-1".to_owned(),
                position: 3,
                total: 3,
            },
            ProtocolError::GatewayTooLong { hops: 9, max: 8 },
            ProtocolError::GatewayHopDeleted {
                label: "jump-eu".to_owned(),
                position: 2,
                total: 3,
            },
            ProtocolError::SessionLimit {
                open: 32,
                limit: 32,
            },
            ProtocolError::CredentialMissing {
                name: "prod-root".to_owned(),
            },
            ProtocolError::CredentialPurposeMismatch {
                allowed: vec!["ssh".to_owned()],
                attempted: ProtocolId::new("rdp").unwrap(),
            },
            ProtocolError::CredentialRequired { target: target() },
            ProtocolError::DnsFailure {
                host: "host.example.com".to_owned(),
            },
            ProtocolError::ConnectionRefused { target: target() },
            ProtocolError::ConnectTimeout {
                target: target(),
                timeout_ms: 30_000,
            },
            ProtocolError::NetworkUnreachable { target: target() },
            ProtocolError::HopFailed {
                label: "bastion-2".to_owned(),
                position: 2,
                total: 3,
                source: Box::new(ProtocolError::ConnectionRefused { target: target() }),
            },
            ProtocolError::Io {
                operation: "connect",
                source: io::Error::other("boom"),
            },
            ProtocolError::HostKeyUnknown {
                host: target(),
                algorithm: "ssh-ed25519".to_owned(),
                fingerprint: Fingerprint::sha256(b"a"),
            },
            ProtocolError::HostKeyChanged {
                host: target(),
                algorithm: "ssh-ed25519".to_owned(),
                expected: Fingerprint::sha256(b"a"),
                offered: Fingerprint::sha256(b"b"),
            },
            ProtocolError::HostKeyRejected {
                host: target(),
                algorithm: "ssh-ed25519".to_owned(),
            },
            ProtocolError::MalformedFingerprint,
            ProtocolError::ConfirmationMismatch,
            ProtocolError::NoSharedAlgorithm {
                kind: AlgorithmKind::HostKey,
                offered: vec!["ssh-rsa".to_owned()],
            },
            ProtocolError::CertificateUntrusted {
                host: target(),
                reason: CertificateProblem::SelfSigned,
            },
            ProtocolError::HandshakeFailed {
                protocol: protocol(),
                detail: "the server closed the connection during key exchange",
            },
            ProtocolError::AuthRejected {
                attempted: CredentialKind::Password,
            },
            ProtocolError::AuthMethodUnavailable {
                attempted: CredentialKind::Password,
                offered: vec!["publickey".to_owned(), "keyboard-interactive".to_owned()],
            },
            ProtocolError::AuthCancelled,
            ProtocolError::AgentUnavailable,
            ProtocolError::SettingInvalid {
                key: "keepalive".to_owned(),
                expected: "an integer",
            },
            ProtocolError::SettingRequired {
                key: "terminal".to_owned(),
            },
            ProtocolError::Unsupported {
                operation: "resize",
                protocol: protocol(),
            },
            ProtocolError::Disconnected {
                reason: "administratively prohibited".to_owned(),
            },
            ProtocolError::NetworkLost,
            ProtocolError::ProtocolViolation {
                detail: "a channel window overflowed",
            },
            ProtocolError::Cancelled,
            ProtocolError::SessionClosed,
            ProtocolError::EventStreamClosed,
            ProtocolError::TrustStore {
                operation: "remember a host key",
                detail: "the vault is locked",
            },
            ProtocolError::Panicked {
                session: SessionId::from_raw(7),
            },
            ProtocolError::ShutdownTimeout {
                session: SessionId::from_raw(7),
                grace_ms: 5_000,
            },
            ProtocolError::Internal {
                detail: "the registry lost a session it created",
            },
        ]
    }

    #[test]
    fn every_variant_names_a_stage_and_renders_a_message() {
        for error in every_variant() {
            let rendered = error.to_string();
            assert!(!rendered.is_empty(), "{error:?} renders as nothing");
            assert!(
                !rendered.starts_with(char::is_uppercase),
                "diagnostics are lowercase: {rendered}"
            );
            assert!(
                !rendered.ends_with('.'),
                "diagnostics carry no trailing stop: {rendered}"
            );
            // `stage()` is exhaustive by construction; calling it proves the
            // variant was classified rather than falling through a wildcard.
            let _ = error.stage();
        }
    }

    #[test]
    fn a_failure_the_user_cannot_act_on_is_the_exception_not_the_rule() {
        let without: Vec<String> = every_variant()
            .into_iter()
            .filter(|e| e.next_actions().is_empty())
            .map(|e| e.to_string())
            .collect();
        // Cancellation and an unsupported operation are the only failures with
        // nothing to suggest; everything else must offer a next step, which is
        // the whole point of the taxonomy.
        assert_eq!(without.len(), 3, "no next action for: {without:?}");
    }

    /// The rule this crate exists to keep: nothing that formats an error can
    /// print a credential.
    #[test]
    fn no_error_renders_credential_material() {
        /// A provider holding a distinctive secret, live for the whole test.
        struct Loud;
        const SECRET: &str = "correct-horse-battery-staple";

        impl CredentialProvider for Loud {
            fn username(&self) -> Option<&str> {
                Some("ada")
            }
            fn kind(&self) -> CredentialKind {
                CredentialKind::Password
            }
            fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
                f(SECRET.as_bytes());
                true
            }
            fn borrow_private_key(&self, _f: &mut crate::credentials::KeyBorrow<'_>) -> bool {
                false
            }
        }

        // An authentication attempt that fails is the moment the secret is in
        // hand, so build the error the way the adapter would.
        let creds = Loud;
        let attempted = creds.kind();
        let errors = [
            ProtocolError::AuthRejected { attempted },
            ProtocolError::AuthMethodUnavailable {
                attempted,
                offered: vec!["publickey".to_owned()],
            },
        ];

        for error in errors.iter().chain(every_variant().iter()) {
            let display = error.to_string();
            let debug = format!("{error:?}");
            let report = FailureReport::from(error);
            for rendered in [&display, &debug, &report.message] {
                assert!(
                    !rendered.contains(SECRET),
                    "a credential reached a formatted error: {rendered}"
                );
                assert!(
                    !rendered.contains("horse"),
                    "a fragment of a credential reached a formatted error: {rendered}"
                );
            }
        }
    }

    #[test]
    fn a_hop_failure_names_the_hop_and_its_position() {
        let error = ProtocolError::ConnectionRefused { target: target() }
            .at_hop("bastion-2", 2, 3)
            .to_string();
        assert!(error.contains("bastion-2"), "{error}");
        assert!(error.contains("hop 2 of 3"), "{error}");
    }

    #[test]
    fn a_changed_host_key_is_never_offered_as_retryable_or_acceptable() {
        let error = ProtocolError::HostKeyChanged {
            host: target(),
            algorithm: "ssh-ed25519".to_owned(),
            expected: Fingerprint::sha256(b"a"),
            offered: Fingerprint::sha256(b"b"),
        };
        assert!(!error.is_retryable());
        assert!(error.needs_user_decision());
        assert!(
            error
                .next_actions()
                .contains(&NextAction::VerifyFingerprintOutOfBand),
            "the user must be told to verify out of band"
        );
        assert!(!error.next_actions().contains(&NextAction::Retry));
    }

    fn changed_key_on(host: &str) -> ProtocolError {
        ProtocolError::HostKeyChanged {
            host: HostPort::new(host, 22).unwrap(),
            algorithm: "ssh-ed25519".to_owned(),
            expected: Fingerprint::sha256(b"the key we trusted"),
            offered: Fingerprint::sha256(b"the key an attacker offered"),
        }
    }

    /// The regression this module exists to prevent.
    ///
    /// A changed host key on a gateway hop used to be wrapped in `HopFailed`,
    /// and `HopFailed` was classified retryable — so auto-reconnect retried a
    /// man-in-the-middle silently. An identity failure must survive wrapping at
    /// every position in the chain (`docs/security/threat-model.md`, T3).
    #[test]
    fn a_changed_host_key_is_not_retryable_at_any_position_in_a_chain() {
        // Hop 1 of 3 — the bastion this machine dials directly.
        let at_hop_one = changed_key_on("bastion-1.acme.io").at_hop("bastion-1", 1, 3);
        // Hop 2 of 3 — the reviewer's scenario: db-01 through bastion-2.
        let at_hop_two = changed_key_on("bastion-2.acme.io").at_hop("bastion-2", 2, 3);
        // The target, reached through two hops that were themselves fine.
        let at_target = changed_key_on("db-01.internal");
        // And nested twice, which is what a chain inside a chain produces.
        let nested = changed_key_on("bastion-2.acme.io")
            .at_hop("bastion-2", 2, 3)
            .at_hop("bastion-1", 1, 3);

        for error in [&at_hop_one, &at_hop_two, &at_target, &nested] {
            assert!(
                !error.is_retryable(),
                "auto-reconnect would retry a man-in-the-middle: {error}"
            );
            assert!(
                error.needs_user_decision(),
                "a changed key needs a person: {error}"
            );
            assert!(error.involves_identity_failure(), "{error}");
            assert!(
                matches!(error.root_cause(), ProtocolError::HostKeyChanged { .. }),
                "{error}"
            );
            assert_eq!(error.stage(), Stage::Handshake, "{error}");
            assert!(
                error
                    .next_actions()
                    .contains(&NextAction::VerifyFingerprintOutOfBand),
                "{error}"
            );
            assert!(
                !error.next_actions().contains(&NextAction::Retry),
                "{error}"
            );
            assert!(
                !FailureReport::from(error).retryable,
                "the tab would offer an automatic retry: {error}"
            );
        }

        // The position must still be named: the user has to learn which hop was
        // attacked, and both fingerprints have to reach the screen.
        let rendered = at_hop_two.to_string();
        assert!(rendered.contains("bastion-2"), "{rendered}");
        assert!(rendered.contains("hop 2 of 3"), "{rendered}");
        assert!(
            rendered.contains(&Fingerprint::sha256(b"the key we trusted").to_string()),
            "the stored fingerprint never reached the user: {rendered}"
        );
        assert!(
            rendered.contains(&Fingerprint::sha256(b"the key an attacker offered").to_string()),
            "the offered fingerprint never reached the user: {rendered}"
        );
    }

    #[test]
    fn an_unknown_host_key_on_a_hop_is_not_retryable_either() {
        // First use is a question for a person, not something to retry until it
        // stops asking.
        let error = ProtocolError::HostKeyUnknown {
            host: HostPort::new("bastion-2.acme.io", 22).unwrap(),
            algorithm: "ssh-ed25519".to_owned(),
            fingerprint: Fingerprint::sha256(b"new"),
        }
        .at_hop("bastion-2", 2, 3);

        assert!(!error.is_retryable());
        assert!(error.next_actions().contains(&NextAction::ReviewHostKey));
        assert!(error.to_string().contains("hop 2 of 3"));
    }

    #[test]
    fn a_hop_that_failed_on_connectivity_is_still_retryable_and_still_a_chain_problem() {
        // The other half of the rule: delegating retryability must not turn a
        // genuinely transient hop failure into a permanent one.
        let error = ProtocolError::ConnectionRefused { target: target() }.at_hop("bastion-2", 2, 3);
        assert!(error.is_retryable());
        assert_eq!(error.stage(), Stage::Transport);
        assert!(
            error.next_actions().contains(&NextAction::EditGatewayChain),
            "a connectivity failure on a hop is still a chain problem"
        );

        // A rejected credential on a hop is not retryable, for the same reason
        // it is not retryable at the target: replaying it locks the account.
        let rejected = ProtocolError::AuthRejected {
            attempted: CredentialKind::Password,
        }
        .at_hop("bastion-2", 2, 3);
        assert!(!rejected.is_retryable());
        assert_eq!(rejected.stage(), Stage::Authenticate);
    }

    #[test]
    fn a_rejected_password_is_not_retried_automatically() {
        // Auto-reconnect that replays a rejected password locks the account
        // out; that is why `is_retryable` is not simply "was it a failure".
        assert!(
            !ProtocolError::AuthRejected {
                attempted: CredentialKind::Password
            }
            .is_retryable()
        );
        assert!(ProtocolError::NetworkLost.is_retryable());
    }

    #[test]
    fn a_failure_report_carries_the_actions_the_tab_shows() {
        let report = FailureReport::from(ProtocolError::ConnectionRefused { target: target() });
        assert_eq!(report.stage, Stage::Transport);
        assert!(report.retryable);
        assert_eq!(report.next_actions.first(), Some(&NextAction::CheckService));
        assert!(report.message.contains("10.0.0.5:22"));
    }
}
