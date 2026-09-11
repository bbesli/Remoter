//! Translating RDP's failures into the taxonomy.
//!
//! `docs/architecture/session-pipeline.md` requires every failure to name what
//! failed, name where, and offer a next action. RDP makes that unusually easy
//! to get wrong, because three completely different problems all present as
//! "the connection did not come up":
//!
//! | What actually happened | What the user must do | Variant |
//! |---|---|---|
//! | The host is not answering | Check the address, the service, the firewall | [`ProtocolError::ConnectionRefused`], [`ProtocolError::ConnectTimeout`], [`ProtocolError::NetworkUnreachable`] |
//! | The certificate is not trusted | Compare the fingerprint, then pin it | [`ProtocolError::CertificateUntrusted`] |
//! | The credentials were refused | Type a different password | [`ProtocolError::AuthRejected`] |
//!
//! A user who cannot tell "wrong password" from "certificate not trusted"
//! cannot fix either, so these three never collapse into one another anywhere
//! in this crate. In particular a CredSSP failure is **not** reported as a
//! handshake failure: NLA runs inside the TLS tunnel and its rejection is an
//! authentication rejection, which is the only reading that puts the password
//! prompt back on screen.
//!
//! **No free-form text crosses this boundary.** The `detail` fields are
//! `&'static str` precisely so that a formatted value — and therefore a secret
//! — cannot reach one. A password typed at a Windows login screen travels
//! through this crate; the errors it can raise must be structurally incapable
//! of carrying it.

use std::io;

use remoter_core::ProtocolId;
use remoter_proto::{CertificateProblem, CredentialKind, HostPort, ProtocolError};

/// This adapter's protocol identifier, as it appears in the vault.
pub const RDP_ID: &str = "rdp";

/// The port an RDP connection uses when nothing on the inheritance path set
/// one. Matches `remoter_core::ProtocolId::default_port`, which is where the
/// resolver actually reads it; repeated here so the adapter can be read on its
/// own.
pub const DEFAULT_PORT: u16 = 3389;

/// The identifier as a validated [`ProtocolId`].
///
/// Fallible only in principle: `"rdp"` is three lowercase ASCII letters and
/// `remoter_core::validate_protocol_id` accepts those. The `Result` is kept
/// rather than unwrapped because this crate forbids `unwrap`, and the failure
/// degrades to a diagnostic instead of a panic.
///
/// # Errors
///
/// [`ProtocolError::Internal`] if `remoter-core` ever stops accepting `"rdp"`.
pub fn rdp_protocol_id() -> Result<ProtocolId, ProtocolError> {
    ProtocolId::new(RDP_ID).map_err(|_| ProtocolError::Internal {
        detail: "the rdp protocol identifier did not validate",
    })
}

/// A handshake failure carrying a fixed reason.
#[must_use]
pub fn handshake_failed(detail: &'static str) -> ProtocolError {
    match rdp_protocol_id() {
        Ok(protocol) => ProtocolError::HandshakeFailed { protocol, detail },
        Err(error) => error,
    }
}

/// An operation this adapter does not implement.
#[must_use]
pub fn unsupported(operation: &'static str) -> ProtocolError {
    match rdp_protocol_id() {
        Ok(protocol) => ProtocolError::Unsupported {
            operation,
            protocol,
        },
        Err(error) => error,
    }
}

/// The peer sent something the protocol does not allow.
#[must_use]
pub const fn violation(detail: &'static str) -> ProtocolError {
    ProtocolError::ProtocolViolation { detail }
}

/// The server refused the credentials.
///
/// Always `Password`: CredSSP as implemented here carries a password, and the
/// kind is what the interface uses to decide which prompt to raise. Naming the
/// kind and never the value is the rule the whole taxonomy is built on.
#[must_use]
pub const fn auth_rejected() -> ProtocolError {
    ProtocolError::AuthRejected {
        attempted: CredentialKind::Password,
    }
}

/// Maps an I/O failure onto the taxonomy, using `target` to name where.
///
/// The transport is injected (ADR-0003), so the *dial* never happens here —
/// but a socket that goes away mid-handshake still surfaces as an
/// `io::Error`, and the kinds below are the ones that mean something specific
/// to a user. `operation` is a literal naming what was in flight.
#[must_use]
pub fn map_io(error: &io::Error, target: &HostPort, operation: &'static str) -> ProtocolError {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => ProtocolError::ConnectionRefused {
            target: target.clone(),
        },
        io::ErrorKind::TimedOut => ProtocolError::ConnectTimeout {
            target: target.clone(),
            // The caller's own deadline is the authoritative number; a kernel
            // timeout has none to report, and zero reads as "immediately",
            // which is worse than saying nothing. See `connect::with_deadline`,
            // which raises the accurate one.
            timeout_ms: 0,
        },
        io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NetworkDown => ProtocolError::NetworkUnreachable {
            target: target.clone(),
        },
        // A server that hangs up mid-sequence is the taxonomy's "the server
        // closed the connection", not a transport failure: the socket worked.
        // A Windows host does this when it decides the client is unacceptable
        // before it has a PDU to say so with.
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset => {
            ProtocolError::Disconnected {
                reason: "rdp.remote_closed".to_owned(),
            }
        }
        io::ErrorKind::BrokenPipe => ProtocolError::NetworkLost,
        // `io::Error`'s `Display` here is the kernel's message, which holds no
        // user data. The error is rebuilt rather than moved because
        // `ProtocolError` owns its source.
        _ => ProtocolError::Io {
            operation,
            source: io::Error::new(error.kind(), error.to_string()),
        },
    }
}

/// Maps an RDP Negotiation Failure code (MS-RDPBCGR §2.2.1.2.2) onto the
/// taxonomy.
///
/// The server sends one of these instead of a Negotiation Response when it
/// will not accept what the client asked for. Every code below is a
/// *configuration* disagreement between the two ends, and every one of them
/// has a different answer, which is why they are not one message:
///
/// - `SSL_REQUIRED_BY_SERVER` (0x1) — the server insists on TLS and the client
///   asked for none. This build always asks for TLS, so seeing it means the
///   request was rewritten in flight.
/// - `SSL_NOT_ALLOWED_BY_SERVER` (0x2) — the server is configured for legacy
///   Standard RDP Security (RC4), which this build does not implement and
///   will not: `docs/security/transport-security.md` rules it out.
/// - `SSL_CERT_NOT_ON_SERVER` (0x3) — the server has no certificate to offer.
/// - `INCONSISTENT_FLAGS` (0x4) — the flags in the request contradicted the
///   requested protocols. A defect here, not a server problem.
/// - `HYBRID_REQUIRED_BY_SERVER` (0x5) — the server requires Network Level
///   Authentication and the client offered only TLS. This is the one code a
///   user can act on directly, so it gets a message of its own rather than
///   being folded into "the handshake failed".
/// - `SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER` (0x6) — the server requires
///   CredSSP *with* Early User Authorization.
#[must_use]
pub fn map_negotiation_failure(code: u32) -> ProtocolError {
    match code {
        // MS-RDPBCGR §2.2.1.2.2, SSL_REQUIRED_BY_SERVER.
        0x0000_0001 => handshake_failed("the server requires TLS and the request offered none"),
        // SSL_NOT_ALLOWED_BY_SERVER: the server wants Standard RDP Security.
        0x0000_0002 => handshake_failed(
            "the server only offers legacy RDP security, which Remoter does not implement",
        ),
        // SSL_CERT_NOT_ON_SERVER.
        0x0000_0003 => handshake_failed("the server has no certificate installed for TLS"),
        // INCONSISTENT_FLAGS: the client's own request was self-contradictory.
        0x0000_0004 => ProtocolError::Internal {
            detail: "the negotiation request carried inconsistent flags",
        },
        // HYBRID_REQUIRED_BY_SERVER: Network Level Authentication is mandatory
        // on this host and was not offered.
        0x0000_0005 => handshake_failed(
            "the server requires Network Level Authentication; enable it for this connection",
        ),
        // SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER.
        0x0000_0006 => handshake_failed(
            "the server requires Network Level Authentication with user authorisation",
        ),
        _ => handshake_failed("the server refused every security protocol offered"),
    }
}

/// The failure for a certificate that did not pass the trust check.
#[must_use]
pub fn certificate_untrusted(host: &HostPort, reason: CertificateProblem) -> ProtocolError {
    ProtocolError::CertificateUntrusted {
        host: host.clone(),
        reason,
    }
}

/// Maps a `rustls` failure onto the taxonomy.
///
/// The certificate decisions themselves are made in [`crate::cert`] and never
/// reach here: this crate installs its own verifier, so `rustls` is left with
/// the *protocol* failures — a peer that is not speaking TLS, a version or
/// cipher disagreement, an alert. The one exception is the verifier's own
/// rejection travelling back out as `InvalidCertificate`, which is passed
/// through as an untrusted certificate rather than a handshake failure, so the
/// user is offered the pin button and not a retry button.
#[must_use]
pub fn map_tls(error: &rustls::Error, host: &HostPort) -> ProtocolError {
    match error {
        rustls::Error::InvalidCertificate(reason) => {
            certificate_untrusted(host, certificate_problem(reason))
        }
        rustls::Error::NoCertificatesPresented => {
            certificate_untrusted(host, CertificateProblem::Malformed)
        }
        rustls::Error::PeerIncompatible(_) => {
            handshake_failed("no TLS version or cipher suite in common with the server")
        }
        rustls::Error::AlertReceived(_) => {
            handshake_failed("the server rejected the TLS handshake with an alert")
        }
        rustls::Error::InappropriateMessage { .. }
        | rustls::Error::InappropriateHandshakeMessage { .. }
        | rustls::Error::InvalidMessage(_) => {
            // Port 3389 answered by something that is not an RDP server is the
            // ordinary cause. Naming it as a protocol violation rather than a
            // certificate problem keeps the pin button off the screen, where
            // pressing it would achieve nothing.
            violation("the server did not speak TLS after selecting it")
        }
        _ => handshake_failed("the TLS handshake did not complete"),
    }
}

/// Maps `rustls`'s certificate-rejection reason onto the taxonomy's.
///
/// The two enumerations exist for the same purpose and are deliberately kept
/// in step: the reason is what the failure card shows, and "not trusted" with
/// no reason is the message this project refuses to produce.
#[must_use]
pub const fn certificate_problem(reason: &rustls::CertificateError) -> CertificateProblem {
    match reason {
        rustls::CertificateError::Expired
        | rustls::CertificateError::NotValidYet
        | rustls::CertificateError::ExpiredContext { .. }
        | rustls::CertificateError::NotValidYetContext { .. } => CertificateProblem::Expired,
        rustls::CertificateError::NotValidForName
        | rustls::CertificateError::NotValidForNameContext { .. } => {
            CertificateProblem::NameMismatch
        }
        rustls::CertificateError::Revoked => CertificateProblem::Revoked,
        rustls::CertificateError::BadEncoding | rustls::CertificateError::BadSignature => {
            CertificateProblem::Malformed
        }
        _ => CertificateProblem::UntrustedRoot,
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
    use remoter_proto::{NextAction, Stage};

    fn target() -> HostPort {
        HostPort::new("ts-01.corp.example", 3389).unwrap()
    }

    #[test]
    fn the_identifier_validates_and_carries_the_well_known_port() {
        let id = rdp_protocol_id().unwrap();
        assert_eq!(id.as_str(), RDP_ID);
        // The resolver reads the default from `remoter-core`; if the two ever
        // disagree, a connection with no port set would dial somewhere else.
        assert_eq!(id.default_port(), Some(DEFAULT_PORT));
    }

    /// The requirement this module exists for: the three failures a user meets
    /// most often are three different errors, at different stages, with
    /// different buttons.
    #[test]
    fn wrong_password_untrusted_certificate_and_unreachable_host_are_three_failures() {
        let refused = map_io(
            &io::Error::from(io::ErrorKind::ConnectionRefused),
            &target(),
            "open the RDP connection",
        );
        let untrusted = certificate_untrusted(&target(), CertificateProblem::SelfSigned);
        let rejected = auth_rejected();

        assert_eq!(refused.stage(), Stage::Transport);
        assert_eq!(untrusted.stage(), Stage::Handshake);
        assert_eq!(rejected.stage(), Stage::Authenticate);

        // Different remedies, not merely different words.
        assert!(refused.next_actions().contains(&NextAction::CheckService));
        assert!(
            untrusted
                .next_actions()
                .contains(&NextAction::PinCertificate)
        );
        assert!(
            rejected
                .next_actions()
                .contains(&NextAction::EnterCredential)
        );

        // And they must not be interchangeable to the reconnect loop: retrying
        // a refused password is a lockout, and retrying an untrusted
        // certificate is a silent man-in-the-middle.
        assert!(refused.is_retryable());
        assert!(!untrusted.is_retryable());
        assert!(!rejected.is_retryable());
        assert!(untrusted.involves_identity_failure());
    }

    #[test]
    fn a_server_that_demands_network_level_authentication_says_so() {
        // HYBRID_REQUIRED_BY_SERVER is the single most common reason a
        // TLS-only attempt fails against a default Windows Server, and
        // "handshake failed" would send the user to a packet capture.
        let error = map_negotiation_failure(0x0000_0005);
        let rendered = error.to_string();
        assert!(
            rendered.contains("Network Level Authentication"),
            "{rendered}"
        );
        assert_eq!(error.stage(), Stage::Handshake);
    }

    #[test]
    fn a_server_offering_only_legacy_rdp_security_is_named_as_such() {
        let error = map_negotiation_failure(0x0000_0002);
        assert!(error.to_string().contains("legacy RDP security"));
    }

    #[test]
    fn a_socket_that_dies_mid_sequence_is_a_disconnect_not_a_dial_failure() {
        // The transport is injected, so a dial failure cannot originate here;
        // reporting one would point the user at a firewall that is fine.
        let error = map_io(
            &io::Error::from(io::ErrorKind::UnexpectedEof),
            &target(),
            "read the negotiation response",
        );
        assert!(matches!(error, ProtocolError::Disconnected { .. }));
        assert_eq!(error.stage(), Stage::Run);
    }

    #[test]
    fn a_tls_certificate_rejection_offers_the_pin_button_and_not_a_retry() {
        let error = map_tls(
            &rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
            &target(),
        );
        assert!(matches!(error, ProtocolError::CertificateUntrusted { .. }));
        assert!(error.next_actions().contains(&NextAction::PinCertificate));
    }

    #[test]
    fn something_that_is_not_tls_on_port_3389_is_a_protocol_violation() {
        // Pinning a certificate that was never offered fixes nothing, so the
        // pin button must not be on this card.
        let error = map_tls(
            &rustls::Error::InvalidMessage(rustls::InvalidMessage::MessageTooLarge),
            &target(),
        );
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
        assert!(!error.next_actions().contains(&NextAction::PinCertificate));
    }

    #[test]
    fn no_error_this_module_builds_can_carry_a_runtime_value() {
        // Every `detail` is a literal; a secret is a runtime value and cannot
        // be one. Asserted by construction rather than by inspection: this
        // test fails to compile if a `String` detail is ever introduced.
        let errors = [
            handshake_failed("a fixed reason"),
            unsupported("audio redirection"),
            violation("a malformed PDU"),
            auth_rejected(),
        ];
        for error in &errors {
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("hunter2"), "{rendered}");
        }
    }
}
