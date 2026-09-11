//! Translating `vnc-rs`'s failures into the failure taxonomy.
//!
//! `docs/architecture/session-pipeline.md` requires that every failure name
//! what failed, name where, and offer a next action. `VncError` is a flat enum
//! covering the handshake, the authentication and the decoders at once, so the
//! mapping is written out rather than collapsed — collapsing it is how a
//! connection manager ends up saying "connection failed" and sending its user
//! to `vncviewer` to find out what happened.
//!
//! **No free-form text crosses this boundary.** `VncError::General(String)`
//! carries whatever the *server* wrote after a failed security handshake
//! (RFC 6143 §7.1.2: a failed connection is followed by a reason string chosen
//! by the far end), and `VncEvent::Error(String)` carries a formatted
//! `io::Error`. Neither is forwarded. The `detail` fields on
//! [`ProtocolError::HandshakeFailed`] and [`ProtocolError::ProtocolViolation`]
//! are `&'static str` precisely so that a formatted value — and therefore a
//! secret — cannot reach one.

use std::io;

use remoter_core::ProtocolId;
use remoter_proto::{CredentialKind, ProtocolError};
use vnc::VncError;

/// This adapter's protocol identifier, as it appears in the vault.
pub const VNC_ID: &str = "vnc";

/// The identifier as a validated [`ProtocolId`].
///
/// Fallible only in principle: `"vnc"` is three lowercase ASCII letters and
/// `remoter_core::validate_protocol_id` accepts those. The `Result` is kept
/// rather than unwrapped because this crate forbids `unwrap`, and the failure
/// degrades to a diagnostic instead of a panic.
///
/// # Errors
///
/// [`ProtocolError::Internal`] if `remoter-core` ever stops accepting `"vnc"`.
pub fn vnc_protocol_id() -> Result<ProtocolId, ProtocolError> {
    ProtocolId::new(VNC_ID).map_err(|_| ProtocolError::Internal {
        detail: "the vnc protocol identifier did not validate",
    })
}

/// A handshake failure carrying a fixed reason.
#[must_use]
pub fn handshake_failed(detail: &'static str) -> ProtocolError {
    match vnc_protocol_id() {
        Ok(protocol) => ProtocolError::HandshakeFailed { protocol, detail },
        Err(error) => error,
    }
}

/// An operation this adapter does not implement.
#[must_use]
pub fn unsupported(operation: &'static str) -> ProtocolError {
    match vnc_protocol_id() {
        Ok(protocol) => ProtocolError::Unsupported {
            operation,
            protocol,
        },
        Err(error) => error,
    }
}

/// The peer sent something RFB does not permit.
#[must_use]
pub const fn violation(detail: &'static str) -> ProtocolError {
    ProtocolError::ProtocolViolation { detail }
}

/// Maps a `vnc-rs` failure onto the taxonomy.
///
/// `stage_detail` is the fixed literal used when nothing more specific
/// applies; it names the operation that was in flight, never its contents.
///
/// [`VncError::General`] is the one that needs care. `vnc-rs` produces it in
/// three unrelated situations — the server refused the connection and sent a
/// reason string (RFC 6143 §7.1.2), the server offered only security types the
/// library does not implement, and an internal channel closed — and the string
/// that tells them apart is peer-influenced in the first case. It is therefore
/// mapped to one generic handshake failure here, and
/// [`crate::handshake::HandshakeObserver`] is what turns it into something
/// precise: the observer saw the security-type list on the wire, so the connect
/// path can say "the server offers VeNCrypt and Tight" without ever quoting the
/// server.
#[must_use]
pub fn map_vnc(error: &VncError, stage_detail: &'static str) -> ProtocolError {
    match error {
        // The server demanded VNC authentication (RFC 6143 §7.2.2) and this
        // connection has no password to answer it with. Rendered as "the
        // server does not accept none authentication; it offers
        // [\"VNC Authentication\"]", which is the true statement.
        VncError::NoPassword => ProtocolError::AuthMethodUnavailable {
            attempted: CredentialKind::None,
            offered: vec!["VNC Authentication".to_owned()],
        },

        // RFC 6143 §7.2.2: the security result is a U32, 0 for OK and 1 for
        // failed. This is the one authentication outcome RFB gives us, and it
        // says nothing about *why* — VNC authentication has no account name,
        // so "wrong password" is the whole diagnosis available.
        VncError::WrongPassword => ProtocolError::AuthRejected {
            attempted: CredentialKind::Password,
        },

        // A defect in this adapter, not in the far end: `crate::encoding`
        // always offers at least Raw, which RFC 6143 §7.7.1 requires every
        // client to support.
        VncError::NoEncoding => ProtocolError::Internal {
            detail: "no RFB encoding was offered to the server",
        },

        VncError::InvalidSecurityTyep(_) => {
            violation("the server offered a security type RFB does not define")
        }
        VncError::WrongPixelFormat => {
            violation("the server sent a pixel format RFB does not define")
        }
        VncError::WrongServerMessage => {
            violation("the server sent an RFB message type this build does not accept")
        }
        VncError::InvalidImageData => violation("a framebuffer rectangle could not be decoded"),

        // The engine's tasks have stopped. During a run that means the far end
        // went away; the session is over either way.
        VncError::ClientNotRunning => ProtocolError::Disconnected {
            reason: "vnc.engine_stopped".to_owned(),
        },

        VncError::ConnectError => handshake_failed("the RFB handshake did not complete"),

        VncError::IoError(source) => map_io(source, stage_detail),

        // See the doc comment: peer-influenced, never forwarded.
        VncError::General(_) => {
            handshake_failed("the server ended the connection during the RFB handshake")
        }

        // `VncError` is `#[non_exhaustive]`. A variant added upstream must not
        // silently become "something went wrong": it is reported as a
        // handshake failure with a literal that says the build is behind.
        _ => handshake_failed("the RFB library reported a failure this build does not recognise"),
    }
}

/// Maps an operating system error onto the taxonomy.
///
/// A clean end-of-stream is a disconnection rather than an I/O fault: a VNC
/// server that is shut down closes the socket, and telling the user their
/// network failed would send them to look at the wrong thing.
#[must_use]
pub fn map_io(source: &io::Error, stage_detail: &'static str) -> ProtocolError {
    match source.kind() {
        io::ErrorKind::UnexpectedEof => ProtocolError::Disconnected {
            reason: "vnc.remote_closed".to_owned(),
        },
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => ProtocolError::NetworkLost,
        kind => ProtocolError::Io {
            operation: stage_detail,
            // `io::Error` is not `Clone`; rebuild it rather than take it by
            // value, which would make every caller give up ownership for the
            // sake of one branch.
            source: io::Error::new(kind, source.to_string()),
        },
    }
}

/// Classifies a [`vnc::VncEvent::Error`] without forwarding its text.
///
/// The engine reports decoder failures as an *event* rather than as a `Result`
/// (`docs/development/verified-apis.md`), so a `match` that only handles the
/// drawing variants silently ignores a session that has already failed. The
/// string is a formatted `VncError`, which may embed a formatted `io::Error`,
/// so it is used for nothing but a debug log with no payload.
///
/// Every decoder failure lands on one literal on purpose. `vnc-rs` does not
/// distinguish "this rectangle was malformed" from "the zlib stream desynced",
/// and inventing a distinction the library cannot support would be a message
/// that reads precise and is not.
#[must_use]
pub fn classify_decoder_failure() -> ProtocolError {
    violation("the server sent a framebuffer update that could not be decoded")
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

    #[test]
    fn the_identifier_validates() {
        assert_eq!(vnc_protocol_id().unwrap().as_str(), VNC_ID);
    }

    #[test]
    fn a_missing_password_names_what_the_server_wanted() {
        let error = map_vnc(&VncError::NoPassword, "authenticate");
        let ProtocolError::AuthMethodUnavailable { attempted, offered } = error else {
            panic!("a server demanding VNC authentication with no password is an auth failure");
        };
        assert_eq!(attempted, CredentialKind::None);
        assert_eq!(offered, vec!["VNC Authentication".to_owned()]);
    }

    #[test]
    fn a_rejected_password_is_an_authentication_failure_not_a_handshake_one() {
        let error = map_vnc(&VncError::WrongPassword, "authenticate");
        assert!(matches!(
            error,
            ProtocolError::AuthRejected {
                attempted: CredentialKind::Password
            }
        ));
        assert_eq!(error.stage(), remoter_proto::Stage::Authenticate);
    }

    #[test]
    fn the_servers_own_words_never_reach_the_user() {
        // RFC 6143 §7.1.2 lets the far end choose this string. A compromised
        // host would choose it to say something useful to itself.
        let error = map_vnc(
            &VncError::General("Too many security failures. Try again in 10s".to_owned()),
            "handshake",
        );
        let rendered = error.to_string();
        assert!(!rendered.contains("Too many"), "{rendered}");
        assert!(!rendered.contains("10s"), "{rendered}");
        assert_eq!(error.stage(), remoter_proto::Stage::Handshake);
    }

    #[test]
    fn a_closed_stream_is_a_disconnection_and_not_an_io_fault() {
        let error = map_vnc(
            &VncError::IoError(io::Error::from(io::ErrorKind::UnexpectedEof)),
            "read a framebuffer update",
        );
        assert!(matches!(
            error,
            ProtocolError::Disconnected { ref reason } if reason == "vnc.remote_closed"
        ));

        let error = map_vnc(
            &VncError::IoError(io::Error::from(io::ErrorKind::ConnectionReset)),
            "read a framebuffer update",
        );
        assert!(matches!(error, ProtocolError::NetworkLost));
    }

    #[test]
    fn a_malformed_rectangle_is_reported_as_the_peers_fault() {
        let error = classify_decoder_failure();
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
        assert!(matches!(
            map_vnc(&VncError::InvalidImageData, "decode"),
            ProtocolError::ProtocolViolation { .. }
        ));
    }

    #[test]
    fn an_unrecognised_library_variant_is_not_silently_swallowed() {
        // `VncError` is `#[non_exhaustive]`; a variant added upstream must
        // surface as a failure rather than as a success or a panic.
        let error = map_vnc(&VncError::ConnectError, "handshake");
        assert!(matches!(error, ProtocolError::HandshakeFailed { .. }));
    }
}
