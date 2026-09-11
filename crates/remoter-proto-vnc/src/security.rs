//! RFB security types, and how exposed a plain VNC connection actually is.
//!
//! # The security handshake
//!
//! RFC 6143 §7.1.2. After the version handshake the server announces which
//! security types it will accept. In RFB 3.7 and 3.8 that is a `U8` count
//! followed by that many `U8` type numbers; a count of zero means the
//! connection has failed and is followed by a reason string. In RFB 3.3 the
//! *server* chooses, and sends a single `U32`.
//!
//! RFC 6143 §7.2 defines exactly two of the types — `None` (1) and VNC
//! Authentication (2) — and hands the rest to an IANA registry that vendors
//! have been filling in ever since. The registered numbers below are named
//! because a user whose macOS host offers only Apple Remote Desktop
//! authentication deserves to be told that, not "the handshake failed".
//!
//! # VNC authentication is broken, and this module says so
//!
//! RFC 6143 §7.2.2 is a 16-byte challenge encrypted with **DES** under a key
//! made from the password. Three separate things are wrong with it, and none of
//! them is fixable at the client:
//!
//! - **The password is truncated to 8 bytes.** Everything past the eighth byte
//!   is discarded, so a 40-character passphrase has the strength of an
//!   8-character one. The user is told when their password is being truncated;
//!   silently accepting it would let them believe in security they do not have.
//! - **DES with a 56-bit effective key** was brute-forceable in public in 1998.
//! - **Nothing after the handshake is protected.** There is no session key, no
//!   integrity check and no encryption: every keystroke and every pixel travels
//!   in clear text, and an attacker on the path can *modify* the pixel stream,
//!   not merely read it.
//!
//! `docs/security/transport-security.md` states Remoter's position: tunnel it.
//! The transport is injected (ADR-0003), so a VNC session inside an SSH tunnel
//! needs no code here at all — which is why [`Exposure`] exists. It answers
//! "how bad is this particular connection?" so the warning the user sees is the
//! true one rather than a blanket scare that trains them to ignore it.

use std::net::{Ipv4Addr, Ipv6Addr};

use remoter_proto::{HostPort, TransportKind};

/// One entry from the RFB security-type registry (RFC 6143 §7.1.2, §7.2).
///
/// A newtype over `u8` rather than an enum: the registry is open, the wire
/// carries a number, and an enum with a `TryFrom` would turn "a type I have not
/// heard of" into an error at the point where the honest answer is "type 27,
/// whatever that is". The number survives; [`SecurityType::name`] says what is
/// known about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecurityType(u8);

impl SecurityType {
    /// The connection has failed; a reason string follows (RFC 6143 §7.1.2).
    pub const INVALID: Self = Self(0);
    /// No authentication (RFC 6143 §7.2.1).
    pub const NONE: Self = Self(1);
    /// VNC Authentication: DES challenge-response (RFC 6143 §7.2.2).
    pub const VNC_AUTH: Self = Self(2);
    /// RealVNC's RSA-AES, with the session encrypted.
    pub const RA2: Self = Self(5);
    /// RealVNC's RSA-AES with **no** session encryption — the `ne` is "not
    /// encrypted", and it authenticates without protecting anything after.
    pub const RA2NE: Self = Self(6);
    /// TightVNC's extension, which negotiates a sub-type of its own.
    pub const TIGHT: Self = Self(16);
    /// UltraVNC's extension.
    pub const ULTRA: Self = Self(17);
    /// Anthony Liguori's TLS wrapper, VeNCrypt's predecessor.
    pub const TLS: Self = Self(18);
    /// VeNCrypt: the RFB session inside TLS, with sub-types of its own.
    pub const VENCRYPT: Self = Self(19);
    /// GTK-VNC's SASL.
    pub const SASL: Self = Self(20);
    /// MD5 hash authentication.
    pub const MD5_HASH: Self = Self(21);
    /// Colin Dean's xvp.
    pub const XVP: Self = Self(22);
    /// Apple Remote Desktop — what macOS Screen Sharing offers.
    pub const APPLE_RD: Self = Self(30);

    /// Wraps a number from the wire.
    #[must_use]
    pub const fn from_wire(value: u8) -> Self {
        Self(value)
    }

    /// The number as it appears on the wire.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        self.0
    }

    /// A stable ASCII name, for a message the user reads and for logs.
    ///
    /// Not a translated string, and safe to show: the server broadcast this
    /// list to anyone who connected, so nothing here is confidential and
    /// nothing here is peer-authored text — the *number* came from the peer,
    /// the words did not.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0 => "invalid",
            1 => "None",
            2 => "VNC Authentication",
            5 => "RA2",
            6 => "RA2ne",
            16 => "Tight",
            17 => "UltraVNC",
            18 => "TLS",
            19 => "VeNCrypt",
            20 => "SASL",
            21 => "MD5 hash",
            22 => "xvp",
            30 => "Apple Remote Desktop",
            _ => "an unregistered security type",
        }
    }

    /// Whether `vnc-rs` 0.5 can complete this handshake.
    ///
    /// Only the two RFC 6143 §7.2 types. Everything else is refused by the
    /// library before it sends a byte, so offering the user a connection that
    /// cannot succeed is the thing to avoid — not by hiding it, but by saying
    /// which type would have been needed.
    #[must_use]
    pub const fn is_implemented(self) -> bool {
        matches!(self, Self::NONE | Self::VNC_AUTH)
    }

    /// Whether choosing this type would encrypt the session that follows.
    ///
    /// `false` for every type this build can actually negotiate, which is the
    /// point: VNC Authentication protects the password check and nothing after
    /// it, and `None` protects nothing at all.
    #[must_use]
    pub const fn encrypts_the_session(self) -> bool {
        // RA2ne is deliberately absent: the `ne` means the session is *not*
        // encrypted, and grouping it with RA2 because the names look alike is
        // exactly the mistake that produces a false "this is protected".
        matches!(self, Self::RA2 | Self::TLS | Self::VENCRYPT)
    }
}

/// How exposed the clear-text part of a VNC session is.
///
/// `docs/security/transport-security.md` asks for a *blocking* warning when
/// plain VNC authentication is used to "a non-loopback, non-RFC1918 address",
/// and for nothing so dramatic otherwise. One warning for every connection
/// would be worse than none: a user who sees the same red banner on their
/// tunnelled loopback session as on a session across the public internet stops
/// reading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Exposure {
    /// The far end is this machine. A local forward — the recommended
    /// configuration — arrives here, and so does a VNC server on the desktop.
    Loopback,
    /// A private or link-local address (RFC 1918, RFC 4193, RFC 3927,
    /// RFC 4291 §2.5.6). Clear text on a network the user plausibly controls.
    PrivateNetwork,
    /// Anything else, including every DNS name. Clear text where anyone on the
    /// path can read the keystrokes and rewrite the pixels.
    Routable,
}

impl Exposure {
    /// The message-catalogue key for the warning this exposure earns.
    #[must_use]
    pub const fn warning_key(self) -> &'static str {
        match self {
            Self::Loopback => "vnc.cleartext.loopback",
            Self::PrivateNetwork => "vnc.cleartext.private_network",
            Self::Routable => "vnc.cleartext.routable",
        }
    }

    /// Whether the interface should block on this rather than annotate it.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Routable)
    }
}

/// Classifies where an unencrypted RFB session is going.
///
/// **Nothing here resolves a name.** A DNS lookup is a network operation, this
/// crate does not perform network operations of its own (ADR-0003), and a
/// resolver answer would be attacker-influenced anyway. A name is therefore
/// classified [`Exposure::Routable`] — the conservative answer, and the honest
/// one: if we cannot tell, we must not claim it is safe.
#[must_use]
pub fn classify_exposure(target: &HostPort) -> Exposure {
    let host = target.host();
    // `HostPort` keeps an IPv6 literal bracketed, exactly as the vault stores
    // it, so the brackets come off before parsing. A zone identifier
    // (RFC 6874) names a local interface and is not part of the address.
    let literal = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .map_or(host, |inner| inner.split('%').next().unwrap_or(inner));

    if let Ok(v4) = literal.parse::<Ipv4Addr>() {
        return classify_v4(v4);
    }
    if let Ok(v6) = literal.parse::<Ipv6Addr>() {
        return classify_v6(v6);
    }
    Exposure::Routable
}

fn classify_v4(address: Ipv4Addr) -> Exposure {
    if address.is_loopback() {
        return Exposure::Loopback;
    }
    // RFC 1918 private ranges, RFC 3927 link-local, and RFC 6598 carrier-grade
    // NAT — which is not RFC 1918 but is just as much "not the open internet",
    // and treating a 100.64/10 address as routable would put a blocking
    // warning on every session behind a mobile network.
    let [a, b, ..] = address.octets();
    if address.is_private() || address.is_link_local() || (a == 100 && (64..128).contains(&b)) {
        return Exposure::PrivateNetwork;
    }
    Exposure::Routable
}

fn classify_v6(address: Ipv6Addr) -> Exposure {
    if address.is_loopback() {
        return Exposure::Loopback;
    }
    // An IPv4-mapped address (RFC 4291 §2.5.5.2) is an IPv4 destination
    // wearing a different notation; classifying it as "some IPv6 address"
    // would let `::ffff:203.0.113.7` skip the warning `203.0.113.7` earns.
    if let Some(v4) = address.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let first = address.segments()[0];
    // RFC 4193 unique local (fc00::/7) and RFC 4291 §2.5.6 link-local
    // (fe80::/10).
    if first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80 {
        return Exposure::PrivateNetwork;
    }
    Exposure::Routable
}

/// Whether the injected transport already protects what RFB does not.
///
/// This is the whole payoff of ADR-0003 expressed as one function. The adapter
/// cannot tell a plain socket from the far end of a three-hop chain, and it
/// does not try — it asks the transport what carries it. An SSH channel or a
/// TLS session means the clear-text pixel stream is inside something that
/// authenticates and encrypts it, and the warning would be false.
///
/// A SOCKS5 or HTTP `CONNECT` proxy is **not** protection: it relays bytes and
/// the bytes are still RFB in clear text on the far side. Grouping proxies with
/// tunnels because both are "not a direct connection" is how a user ends up
/// believing a corporate proxy encrypted their session.
#[must_use]
pub const fn transport_protects_the_session(kind: TransportKind) -> bool {
    match kind {
        TransportKind::SshChannel | TransportKind::Tls => true,
        TransportKind::Tcp
        | TransportKind::Socks5
        | TransportKind::HttpConnect
        // A plugin transport may or may not encrypt, and this crate has no way
        // to ask. Claiming protection it cannot verify is the failure mode
        // that matters, so it is refused.
        | TransportKind::Plugin => false,
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

    fn target(host: &str) -> HostPort {
        HostPort::new(host, 5900).unwrap()
    }

    #[test]
    fn the_two_types_the_rfc_defines_are_the_two_this_build_can_use() {
        assert!(SecurityType::NONE.is_implemented());
        assert!(SecurityType::VNC_AUTH.is_implemented());
        for other in [
            SecurityType::RA2,
            SecurityType::TIGHT,
            SecurityType::VENCRYPT,
            SecurityType::APPLE_RD,
        ] {
            assert!(!other.is_implemented(), "{}", other.name());
        }
    }

    #[test]
    fn every_type_this_build_can_negotiate_leaves_the_session_in_clear_text() {
        // This is the fact the whole warning path exists for: neither of the
        // two RFC 6143 §7.2 types protects a single byte after the handshake.
        assert!(!SecurityType::NONE.encrypts_the_session());
        assert!(!SecurityType::VNC_AUTH.encrypts_the_session());
    }

    #[test]
    fn ra2ne_is_not_grouped_with_ra2_however_similar_the_names_look() {
        assert!(SecurityType::RA2.encrypts_the_session());
        assert!(!SecurityType::RA2NE.encrypts_the_session());
    }

    #[test]
    fn an_unregistered_number_survives_rather_than_becoming_an_error() {
        let unknown = SecurityType::from_wire(200);
        assert_eq!(unknown.to_wire(), 200);
        assert_eq!(unknown.name(), "an unregistered security type");
        assert!(!unknown.is_implemented());
    }

    #[test]
    fn loopback_earns_no_blocking_warning_because_it_is_the_recommended_setup() {
        assert_eq!(classify_exposure(&target("127.0.0.1")), Exposure::Loopback);
        assert_eq!(classify_exposure(&target("[::1]")), Exposure::Loopback);
        assert!(!Exposure::Loopback.is_blocking());
    }

    #[test]
    fn private_ranges_are_told_apart_from_the_open_internet() {
        for private in ["10.0.0.5", "192.168.1.10", "172.16.4.4", "169.254.1.1"] {
            assert_eq!(
                classify_exposure(&target(private)),
                Exposure::PrivateNetwork,
                "{private}"
            );
        }
        // RFC 6598 carrier-grade NAT: not RFC 1918, and not the open internet
        // either. 100.64/10 is 100.64.0.0 through 100.127.255.255.
        assert_eq!(
            classify_exposure(&target("100.64.0.1")),
            Exposure::PrivateNetwork
        );
        assert_eq!(
            classify_exposure(&target("100.127.255.254")),
            Exposure::PrivateNetwork
        );
        // 100.128.0.1 is past the end of the block and is ordinary space.
        assert_eq!(
            classify_exposure(&target("100.128.0.1")),
            Exposure::Routable
        );
        assert_eq!(
            classify_exposure(&target("[fd00::1]")),
            Exposure::PrivateNetwork
        );
        assert_eq!(
            classify_exposure(&target("[fe80::1%eth0]")),
            Exposure::PrivateNetwork
        );
    }

    #[test]
    fn a_routable_address_is_the_blocking_case() {
        assert_eq!(
            classify_exposure(&target("203.0.113.7")),
            Exposure::Routable
        );
        assert_eq!(
            classify_exposure(&target("[2001:db8::1]")),
            Exposure::Routable
        );
        assert!(Exposure::Routable.is_blocking());
    }

    #[test]
    fn an_ipv4_mapped_address_cannot_smuggle_a_routable_host_past_the_warning() {
        assert_eq!(
            classify_exposure(&target("[::ffff:203.0.113.7]")),
            Exposure::Routable
        );
        assert_eq!(
            classify_exposure(&target("[::ffff:10.0.0.1]")),
            Exposure::PrivateNetwork
        );
    }

    #[test]
    fn a_name_is_assumed_routable_because_nothing_here_may_resolve_it() {
        // Resolving would be a network operation, and this crate performs
        // none. "We could not tell" must not read as "it is safe".
        assert_eq!(
            classify_exposure(&target("desktop.internal")),
            Exposure::Routable
        );
        assert_eq!(
            classify_exposure(&target("localhost")),
            Exposure::Routable,
            "even this one: the name is not the address"
        );
    }

    #[test]
    fn only_a_tunnel_or_tls_counts_as_protection() {
        assert!(transport_protects_the_session(TransportKind::SshChannel));
        assert!(transport_protects_the_session(TransportKind::Tls));
        // A proxy relays clear text; it does not encrypt it.
        assert!(!transport_protects_the_session(TransportKind::Socks5));
        assert!(!transport_protects_the_session(TransportKind::HttpConnect));
        assert!(!transport_protects_the_session(TransportKind::Tcp));
        assert!(!transport_protects_the_session(TransportKind::Plugin));
    }
}
