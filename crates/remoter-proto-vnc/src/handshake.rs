//! The vocabulary of RFC 6143 §7.1: protocol versions and what a server offered.
//!
//! # This module used to watch the handshake; now it only describes it
//!
//! Until ADR-0013 this file held a `HandshakeObserver` and an
//! `ObservingTransport`: `vnc-rs` owned the socket from the first byte, so the
//! only way to know what the server had offered was to watch the bytes go past
//! on their way into the library. That arrangement could describe a failure but
//! could not *prevent* one — and the failures it could not prevent were the
//! ones that mattered: a server that answered with RFB 3.3 and offered `None`
//! got an unauthenticated session while the configured password was never used,
//! and nothing in the client had a say in it.
//!
//! [`crate::negotiate`] now performs RFC 6143 §7.1.1 and §7.1.2 itself, before
//! `vnc-rs` sees a byte, and [`crate::gate`] replays a synthetic, trusted
//! handshake to the library. What survives here is the vocabulary both of them
//! speak: the version enum, and [`HandshakeFacts`] — the record of what the
//! server said, which is what turns "the handshake failed" into "this server
//! offers VeNCrypt and Apple Remote Desktop, and this build implements neither".
//!
//! # The version is not simply what the server said
//!
//! RFC 6143 §7.1.1: the server sends its highest supported version, the client
//! replies with the version it will actually use, and that must not be higher
//! than the server's. So the version in force is `min(ours, theirs)` — and the
//! two handshake shapes differ, because RFB 3.3 has the *server* choose the
//! security type and send it as a `U32` while 3.7 and 3.8 have it send a list
//! for the client to choose from.
//!
//! `min` alone is a **ceiling with no floor**, and a ceiling with no floor is a
//! downgrade the far end controls: any server can answer `RFB 003.003\n` and
//! move the conversation to the shape where it, not the client, picks the
//! security type. [`RfbVersion`] therefore carries [`RfbVersion::negotiated_with`]
//! *and* the floor check that goes with it — see
//! [`crate::negotiate::negotiate`].

use crate::security::SecurityType;

/// Bytes in the version string (RFC 6143 §7.1.1): `RFB 003.008\n`.
pub const VERSION_BYTES: usize = 12;

/// The most security types a server can offer, because the count is a `U8`.
pub const MAX_SECURITY_TYPES: usize = u8::MAX as usize;

/// An RFB protocol version (RFC 6143 §7.1.1).
///
/// Only the three versions the RFC describes. §7.1.1 is explicit that any other
/// version number "should be interpreted as 3.3", because a server reporting
/// one does not implement the different handshake 3.7 and 3.8 introduced.
///
/// `Ord` follows the protocol order, so `min` is the negotiation rule and `<`
/// is the floor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RfbVersion {
    /// RFB 3.3: the server chooses the security type, and the client cannot
    /// refuse it on the wire. This build refuses it *above* the wire instead —
    /// see [`crate::negotiate::select_security`].
    Rfb33,
    /// RFB 3.7: the server offers a list; no `SecurityResult` after `None`.
    Rfb37,
    /// RFB 3.8: the server offers a list, and always sends a `SecurityResult`.
    Rfb38,
}

impl RfbVersion {
    /// The twelve bytes this version is written as.
    #[must_use]
    pub const fn as_wire(self) -> &'static [u8; VERSION_BYTES] {
        match self {
            Self::Rfb33 => b"RFB 003.003\n",
            Self::Rfb37 => b"RFB 003.007\n",
            Self::Rfb38 => b"RFB 003.008\n",
        }
    }

    /// Reads a version string, following RFC 6143 §7.1.1's instruction to
    /// treat anything unrecognised as 3.3.
    #[must_use]
    pub const fn from_wire(bytes: &[u8; VERSION_BYTES]) -> Self {
        match bytes {
            b"RFB 003.008\n" => Self::Rfb38,
            b"RFB 003.007\n" => Self::Rfb37,
            _ => Self::Rfb33,
        }
    }

    /// Parses the stored setting value. `None` for anything else.
    #[must_use]
    pub fn from_setting(value: &str) -> Option<Self> {
        match value {
            "3.8" => Some(Self::Rfb38),
            "3.7" => Some(Self::Rfb37),
            "3.3" => Some(Self::Rfb33),
            _ => None,
        }
    }

    /// A stable name for a log line or a message-catalogue argument.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rfb33 => "3.3",
            Self::Rfb37 => "3.7",
            Self::Rfb38 => "3.8",
        }
    }

    /// The version both ends will use: the lower of the two (§7.1.1).
    ///
    /// This is a *ceiling*. On its own it lets the server choose how low the
    /// conversation goes, which is why every caller pairs it with a floor.
    #[must_use]
    pub fn negotiated_with(self, server: Self) -> Self {
        self.min(server)
    }
}

/// What the handshake said, as far as it got.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HandshakeFacts {
    /// The version the server announced.
    pub server_version: Option<RfbVersion>,
    /// The version both ends will therefore use.
    pub negotiated_version: Option<RfbVersion>,
    /// The security types the server offered, in the order it offered them.
    /// Empty until the list has been read, and empty for a server that refused
    /// the connection outright (RFC 6143 §7.1.2, count zero).
    pub offered_security: Vec<SecurityType>,
    /// The type this client actually selected. `None` until it has chosen.
    ///
    /// Carried rather than re-derived. The old code inferred the choice from
    /// the offer list and the library's preference, and inferring it is how a
    /// session that authenticated with nothing could still be described as one
    /// that used the password.
    pub selected_security: Option<SecurityType>,
    /// Whether the server refused before offering anything — the `U8` count was
    /// zero, or RFB 3.3's `U32` was `0`. A reason string follows on the wire,
    /// and it is deliberately not read: it is peer-authored text.
    pub refused_outright: bool,
}

impl HandshakeFacts {
    /// The offered types this build could actually negotiate.
    #[must_use]
    pub fn usable_security(&self) -> Vec<SecurityType> {
        self.offered_security
            .iter()
            .copied()
            .filter(|kind| kind.is_implemented())
            .collect()
    }

    /// Whether the server offered nothing this build implements.
    ///
    /// `false` while the list has not been read yet: "we did not see a list" is
    /// not "the list had nothing in it", and reporting the second when the
    /// first happened would blame the server for a network failure.
    #[must_use]
    pub fn security_is_unusable(&self) -> bool {
        !self.offered_security.is_empty() && self.usable_security().is_empty()
    }

    /// The offered types as names, for
    /// [`remoter_proto::ProtocolError::AuthMethodUnavailable`].
    #[must_use]
    pub fn offered_names(&self) -> Vec<String> {
        self.offered_security
            .iter()
            .map(|kind| kind.name().to_owned())
            .collect()
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

    #[test]
    fn a_version_string_round_trips() {
        for version in [RfbVersion::Rfb33, RfbVersion::Rfb37, RfbVersion::Rfb38] {
            assert_eq!(RfbVersion::from_wire(version.as_wire()), version);
            assert_eq!(RfbVersion::from_setting(version.as_str()), Some(version));
        }
        assert_eq!(RfbVersion::from_setting("3.9"), None);
    }

    #[test]
    fn an_unrecognised_version_is_treated_as_33_as_the_rfc_instructs() {
        // RFC 6143 §7.1.1: other version numbers are reported by some servers
        // but do not implement the 3.7 handshake, so they are 3.3.
        assert_eq!(RfbVersion::from_wire(b"RFB 004.001\n"), RfbVersion::Rfb33);
        assert_eq!(RfbVersion::from_wire(b"not a versi\n"), RfbVersion::Rfb33);
    }

    #[test]
    fn the_lower_version_wins_and_the_ordering_is_the_protocols() {
        assert_eq!(
            RfbVersion::Rfb38.negotiated_with(RfbVersion::Rfb33),
            RfbVersion::Rfb33
        );
        assert_eq!(
            RfbVersion::Rfb33.negotiated_with(RfbVersion::Rfb38),
            RfbVersion::Rfb33
        );
        assert!(RfbVersion::Rfb33 < RfbVersion::Rfb37);
        assert!(RfbVersion::Rfb37 < RfbVersion::Rfb38);
    }

    #[test]
    fn facts_do_not_claim_an_empty_list_before_one_has_been_read() {
        let mut facts = HandshakeFacts::default();
        assert!(!facts.security_is_unusable());
        facts.offered_security = vec![SecurityType::VENCRYPT, SecurityType::APPLE_RD];
        assert!(facts.security_is_unusable());
        assert!(facts.usable_security().is_empty());
        assert_eq!(
            facts.offered_names(),
            vec!["VeNCrypt".to_owned(), "Apple Remote Desktop".to_owned()]
        );
        facts.offered_security.push(SecurityType::VNC_AUTH);
        assert!(!facts.security_is_unusable());
    }
}
