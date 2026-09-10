//! Translating `russh`'s errors into the failure taxonomy.
//!
//! `docs/architecture/session-pipeline.md` requires that every failure name
//! what failed, name where, and offer a next action. `russh::Error` is a flat
//! enum covering nine stages at once, so the mapping is written out rather than
//! collapsed into one `Other` variant — collapsing it is exactly how a
//! connection manager ends up saying "connection failed" and sending its user
//! to the command line.
//!
//! **No free-form text crosses this boundary.** The `detail` fields on
//! [`ProtocolError::HandshakeFailed`], [`ProtocolError::ProtocolViolation`],
//! [`ProtocolError::Internal`] and [`ProtocolError::TrustStore`] are
//! `&'static str` precisely so that a formatted value — and therefore a
//! secret — cannot reach one. `russh::Error`'s `Display` is never forwarded.

use remoter_core::ProtocolId;
use remoter_proto::{AlgorithmKind, CredentialKind, HostPort, ProtocolError};

/// This adapter's protocol identifier, as it appears in the vault.
pub const SSH_ID: &str = "ssh";

/// The identifier as a validated [`ProtocolId`].
///
/// Fallible only in principle: `"ssh"` is three lowercase ASCII letters and
/// `remoter_core::validate_protocol_id` accepts those. The `Result` is kept
/// rather than unwrapped because this crate forbids `unwrap`, and the failure
/// degrades to a diagnostic instead of a panic.
///
/// # Errors
///
/// [`ProtocolError::Internal`] if `remoter-core` ever stops accepting `"ssh"`.
pub fn ssh_protocol_id() -> Result<ProtocolId, ProtocolError> {
    ProtocolId::new(SSH_ID).map_err(|_| ProtocolError::Internal {
        detail: "the ssh protocol identifier did not validate",
    })
}

/// A handshake failure carrying a fixed reason.
#[must_use]
pub fn handshake_failed(detail: &'static str) -> ProtocolError {
    match ssh_protocol_id() {
        Ok(protocol) => ProtocolError::HandshakeFailed { protocol, detail },
        Err(error) => error,
    }
}

/// An operation this adapter does not implement.
#[must_use]
pub fn unsupported(operation: &'static str) -> ProtocolError {
    match ssh_protocol_id() {
        Ok(protocol) => ProtocolError::Unsupported {
            operation,
            protocol,
        },
        Err(error) => error,
    }
}

/// Maps a `russh` failure onto the taxonomy.
///
/// `stage_detail` is the fixed literal used when nothing more specific
/// applies; it names the operation that was in flight, never its contents.
#[must_use]
pub fn map_russh(error: &russh::Error, stage_detail: &'static str) -> ProtocolError {
    match error {
        // The taxonomy's "the server only offers algorithms Remoter no longer
        // accepts". `theirs` is the server's list — public, and the whole
        // point of the message.
        russh::Error::NoCommonAlgo { kind, theirs, .. } => ProtocolError::NoSharedAlgorithm {
            kind: algorithm_kind(kind),
            offered: theirs.clone(),
        },

        // A clean goodbye, or a socket that went away underneath one. Both are
        // "the server closed the connection" with a reconnect offered.
        russh::Error::Disconnect | russh::Error::HUP | russh::Error::RecvError => {
            ProtocolError::Disconnected {
                reason: "ssh.remote_closed".to_owned(),
            }
        }

        // Timeouts on an established connection are a lost network rather than
        // a refused connect: the taxonomy's "Network unreachable. Retrying."
        russh::Error::ConnectionTimeout
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout => ProtocolError::NetworkLost,

        // The far end sent something the protocol does not permit. Notable:
        // `StrictKeyExchangeViolation` is the Terrapin defence (CVE-2023-48795)
        // and must never be downgraded to a generic handshake failure.
        russh::Error::StrictKeyExchangeViolation { .. } => ProtocolError::ProtocolViolation {
            detail: "the server violated strict key exchange",
        },
        russh::Error::PacketAuth => ProtocolError::ProtocolViolation {
            detail: "a packet failed its authentication check",
        },
        russh::Error::DecryptionError => ProtocolError::ProtocolViolation {
            detail: "a packet could not be decrypted",
        },
        russh::Error::Inconsistent
        | russh::Error::WrongChannel
        | russh::Error::IndexOutOfBounds
        | russh::Error::PacketSize(_) => ProtocolError::ProtocolViolation {
            detail: "the server sent a malformed packet",
        },
        russh::Error::Version => ProtocolError::ProtocolViolation {
            detail: "the server sent an invalid SSH version string",
        },

        // Identity and key exchange.
        russh::Error::Kex | russh::Error::KexInit | russh::Error::UnknownAlgo => {
            handshake_failed("the key exchange did not complete")
        }
        russh::Error::WrongServerSig => {
            handshake_failed("the server's exchange signature did not verify")
        }
        russh::Error::UnknownKey | russh::Error::KeyChanged { .. } => {
            handshake_failed("the server's host key was not accepted")
        }

        // Authentication.
        russh::Error::NotAuthenticated | russh::Error::NoAuthMethod => {
            ProtocolError::AuthRejected {
                attempted: CredentialKind::None,
            }
        }
        russh::Error::UnsupportedAuthMethod => ProtocolError::AuthMethodUnavailable {
            attempted: CredentialKind::None,
            offered: Vec::new(),
        },

        // Anything carrying an operating system error keeps it: `io::Error`'s
        // `Display` is the kernel's message, which holds no user data.
        russh::Error::IO(source) => ProtocolError::Io {
            operation: stage_detail,
            source: std::io::Error::new(source.kind(), source.to_string()),
        },

        _ => handshake_failed(stage_detail),
    }
}

/// Maps `russh`'s algorithm categories onto the taxonomy's.
const fn algorithm_kind(kind: &russh::AlgorithmKind) -> AlgorithmKind {
    match kind {
        russh::AlgorithmKind::Kex => AlgorithmKind::KeyExchange,
        russh::AlgorithmKind::Key => AlgorithmKind::HostKey,
        russh::AlgorithmKind::Cipher => AlgorithmKind::Cipher,
        russh::AlgorithmKind::Mac => AlgorithmKind::Mac,
        russh::AlgorithmKind::Compression => AlgorithmKind::Compression,
    }
}

/// Maps a channel-open failure to what it means for the machine at the far end.
///
/// A `direct-tcpip` channel (RFC 4254 §7.2) that the gateway could not connect
/// is reported against the *target*, not against the gateway: the user's next
/// action is to check that the service is listening, exactly as it would be
/// for a direct connection.
#[must_use]
pub fn map_channel_open(error: &russh::Error, target: &HostPort) -> ProtocolError {
    match error {
        russh::Error::ChannelOpenFailure(reason) => match reason {
            // RFC 4254 §5.1: `SSH_OPEN_CONNECT_FAILED` is what a server sends
            // when its own connect() to the target failed.
            russh::ChannelOpenFailure::ConnectFailed => ProtocolError::ConnectionRefused {
                target: target.clone(),
            },
            russh::ChannelOpenFailure::AdministrativelyProhibited => {
                ProtocolError::NetworkUnreachable {
                    target: target.clone(),
                }
            }
            russh::ChannelOpenFailure::ResourceShortage => ProtocolError::NetworkUnreachable {
                target: target.clone(),
            },
            russh::ChannelOpenFailure::UnknownChannelType => ProtocolError::ProtocolViolation {
                detail: "the server refused a direct-tcpip channel as an unknown type",
            },
            _ => ProtocolError::ConnectionRefused {
                target: target.clone(),
            },
        },
        other => map_russh(other, "open a direct-tcpip channel"),
    }
}

/// Maps a private key parsing failure.
///
/// `russh::keys::Error` variants are matched by shape rather than forwarded,
/// because several of them format DER contents into their message and DER
/// contents here are key material.
#[must_use]
pub fn map_key_error(error: &russh::keys::Error) -> ProtocolError {
    match error {
        // "The key is encrypted" means a passphrase is needed, which is a
        // question for the user rather than a failure.
        russh::keys::Error::KeyIsEncrypted => ProtocolError::CredentialMissing {
            name: "key passphrase".to_owned(),
        },
        russh::keys::Error::UnsupportedKeyType {
            key_type_string, ..
        } => ProtocolError::NoSharedAlgorithm {
            kind: AlgorithmKind::HostKey,
            offered: vec![key_type_string.clone()],
        },
        // Everything else is "this file is not a key we can read". A wrong
        // passphrase surfaces here too, as a corrupt-looking decryption.
        _ => ProtocolError::AuthRejected {
            attempted: CredentialKind::PrivateKey,
        },
    }
}

/// Maps an SFTP failure.
///
/// SFTP status messages are server-supplied text about a *path*, so the
/// message is dropped and the status is reported as a stage failure. The path
/// itself is carried by the operation that failed, where the interface already
/// has it.
#[must_use]
pub fn map_sftp(error: &russh_sftp::client::error::Error) -> ProtocolError {
    match error {
        russh_sftp::client::error::Error::Timeout => ProtocolError::NetworkLost,
        russh_sftp::client::error::Error::IO(_) => ProtocolError::Disconnected {
            reason: "ssh.sftp_stream_lost".to_owned(),
        },
        russh_sftp::client::error::Error::Status(status) => sftp_status(status.status_code),
        russh_sftp::client::error::Error::UnexpectedPacket
        | russh_sftp::client::error::Error::UnexpectedBehavior(_) => {
            ProtocolError::ProtocolViolation {
                detail: "the SFTP server sent an unexpected packet",
            }
        }
        russh_sftp::client::error::Error::Limited(_) => ProtocolError::ProtocolViolation {
            detail: "the SFTP server exceeded its advertised limits",
        },
    }
}

/// Maps an SFTP status code (RFC draft-ietf-secsh-filexfer-02 §7).
fn sftp_status(code: russh_sftp::protocol::StatusCode) -> ProtocolError {
    use russh_sftp::protocol::StatusCode;
    match code {
        StatusCode::Ok | StatusCode::Eof => ProtocolError::Internal {
            detail: "an SFTP success status was reported as a failure",
        },
        StatusCode::NoSuchFile => ProtocolError::SettingInvalid {
            key: "path".to_owned(),
            expected: "a path that exists on the server",
        },
        StatusCode::PermissionDenied => ProtocolError::AuthRejected {
            attempted: CredentialKind::None,
        },
        StatusCode::OpUnsupported => unsupported("this SFTP operation"),
        StatusCode::ConnectionLost => ProtocolError::NetworkLost,
        StatusCode::NoConnection => ProtocolError::Disconnected {
            reason: "ssh.sftp_stream_lost".to_owned(),
        },
        _ => ProtocolError::ProtocolViolation {
            detail: "the SFTP server reported a failure",
        },
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

    #[test]
    fn the_protocol_id_validates() {
        let id = ssh_protocol_id().unwrap();
        assert_eq!(id.as_str(), "ssh");
        assert_eq!(id.default_port(), Some(22));
    }

    #[test]
    fn a_missing_algorithm_names_the_servers_offer() {
        let error = map_russh(
            &russh::Error::NoCommonAlgo {
                kind: russh::AlgorithmKind::Key,
                ours: vec!["ssh-ed25519".to_owned()],
                theirs: vec!["ssh-rsa".to_owned()],
            },
            "negotiate",
        );
        let ProtocolError::NoSharedAlgorithm { kind, offered } = error else {
            panic!("expected a NoSharedAlgorithm, got {error:?}");
        };
        assert_eq!(kind, AlgorithmKind::HostKey);
        assert_eq!(offered, vec!["ssh-rsa".to_owned()]);
    }

    #[test]
    fn strict_kex_violation_is_a_protocol_violation_not_a_handshake_failure() {
        // The Terrapin defence (CVE-2023-48795). Reporting it as an ordinary
        // handshake failure would invite a retry, and a retry is exactly what
        // the attack wants.
        let error = map_russh(
            &russh::Error::StrictKeyExchangeViolation {
                message_type: 2,
                sequence_number: 4,
            },
            "negotiate",
        );
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
        assert!(!error.is_retryable());
    }

    #[test]
    fn a_closed_connection_is_retryable_and_a_timeout_is_a_lost_network() {
        let closed = map_russh(&russh::Error::HUP, "read");
        assert!(matches!(closed, ProtocolError::Disconnected { .. }));
        assert!(closed.is_retryable());

        let lost = map_russh(&russh::Error::KeepaliveTimeout, "read");
        assert!(matches!(lost, ProtocolError::NetworkLost));
    }

    #[test]
    fn a_refused_target_behind_a_gateway_names_the_target() {
        let target = HostPort::new("db-01.internal", 5432).unwrap();
        let error = map_channel_open(
            &russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::ConnectFailed),
            &target,
        );
        let ProtocolError::ConnectionRefused { target: reported } = error else {
            panic!("expected ConnectionRefused, got {error:?}");
        };
        assert_eq!(reported, target);
    }

    #[test]
    fn an_encrypted_key_asks_for_a_passphrase_rather_than_failing() {
        let error = map_key_error(&russh::keys::Error::KeyIsEncrypted);
        assert!(
            error.needs_user_decision() || matches!(error, ProtocolError::CredentialMissing { .. })
        );
    }

    #[test]
    fn no_mapped_error_carries_the_underlying_message() {
        // `russh::keys::Error`'s `Display` can contain DER contents, and DER
        // contents here are key material. Nothing may forward it.
        let error = map_key_error(&russh::keys::Error::KeyIsCorrupt);
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("corrupt"), "rendered: {rendered}");
    }
}
