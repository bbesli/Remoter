//! SOCKS5 (RFC 1928), the wire half of dynamic forwarding.
//!
//! Dynamic forwarding (`-D`) runs a SOCKS5 server on this machine and carries
//! each accepted connection over the SSH session as a `direct-tcpip` channel.
//! Everything in this module is the parsing and encoding, kept free of I/O so
//! that a hostile first packet can be tested without a socket — a SOCKS
//! listener accepts from anything that can reach the port, so its parser is
//! attacker-facing even when bound to loopback.
//!
//! **Commands.** `CONNECT` is implemented. `BIND` is not, and
//! `docs/features/tunneling.md` says so. `UDP ASSOCIATE` is parsed and then
//! refused with `X'07'`: SSH has no datagram channel — RFC 4254 defines
//! `direct-tcpip` and `direct-streamlocal` and nothing that carries UDP — so a
//! SOCKS server whose only exit is an SSH session cannot honour it. Answering
//! `X'07'` is what lets a client fall back to TCP instead of hanging on a
//! reply that will never come.
//!
//! **Authentication.** Only `NO AUTHENTICATION REQUIRED` is offered. The
//! listener is loopback unless the user exposed it deliberately
//! ([`crate::bind`]), and a username and password checked in this process
//! would be one more secret in flight for no gain. A client that offers no
//! acceptable method is told `X'FF'` per RFC 1928 §3.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The only protocol version this speaks.
pub const VERSION: u8 = 0x05;
/// `NO AUTHENTICATION REQUIRED` (RFC 1928 §3).
pub const METHOD_NO_AUTH: u8 = 0x00;
/// `NO ACCEPTABLE METHODS` (RFC 1928 §3).
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

/// The longest domain name a request may carry. RFC 1928 encodes the length in
/// one byte, so this is the format's own maximum rather than a policy.
pub const MAX_DOMAIN_LEN: usize = 255;

/// Why a SOCKS exchange could not be parsed.
///
/// Carries no borrowed bytes: a malformed greeting is diagnostic, and quoting
/// it back would put attacker-chosen bytes into a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Error {
    /// Fewer bytes than the message needs.
    Truncated,
    /// A version byte that is not `0x05`.
    UnsupportedVersion,
    /// A command byte outside RFC 1928 §4.
    UnknownCommand,
    /// An address type outside RFC 1928 §5.
    UnknownAddressType,
    /// A domain name that is not UTF-8, or is empty.
    InvalidDomain,
    /// A greeting offering no methods at all.
    NoMethods,
}

impl fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "the SOCKS message was truncated",
            Self::UnsupportedVersion => "the client is not speaking SOCKS5",
            Self::UnknownCommand => "the SOCKS command is not one RFC 1928 defines",
            Self::UnknownAddressType => "the SOCKS address type is not one RFC 1928 defines",
            Self::InvalidDomain => "the SOCKS domain name is empty or not UTF-8",
            Self::NoMethods => "the client offered no authentication methods",
        })
    }
}

impl std::error::Error for Socks5Error {}

/// A request's command (RFC 1928 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Socks5Command {
    /// `X'01'`. The only one carried over SSH.
    Connect,
    /// `X'02'`. Not supported, by design.
    Bind,
    /// `X'03'`. Parsed, then refused: SSH carries no datagrams.
    UdpAssociate,
}

impl Socks5Command {
    /// The wire byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Connect => 0x01,
            Self::Bind => 0x02,
            Self::UdpAssociate => 0x03,
        }
    }

    /// A stable ASCII name for the message catalogue and the session panel.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Bind => "bind",
            Self::UdpAssociate => "udp-associate",
        }
    }

    const fn from_code(code: u8) -> Result<Self, Socks5Error> {
        match code {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            _ => Err(Socks5Error::UnknownCommand),
        }
    }
}

/// A request's destination address (RFC 1928 §5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Socks5Address {
    /// `X'01'`, four bytes.
    Ipv4(Ipv4Addr),
    /// `X'03'`, a length byte then that many bytes of name.
    Domain(String),
    /// `X'04'`, sixteen bytes.
    Ipv6(Ipv6Addr),
}

impl fmt::Display for Socks5Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(address) => write!(f, "{address}"),
            Self::Domain(name) => f.write_str(name),
            // Bracketed, because `remoter_core` validates IPv6 in that form
            // and a bare `fe80::1` concatenated with a port parses as neither
            // an address nor a name.
            Self::Ipv6(address) => write!(f, "[{address}]"),
        }
    }
}

/// A parsed SOCKS5 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Request {
    /// What the client asked for.
    pub command: Socks5Command,
    /// Where it asked to go.
    pub address: Socks5Address,
    /// The destination port.
    pub port: u16,
}

/// A reply code (RFC 1928 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Socks5Reply {
    /// `X'00'` succeeded.
    Succeeded,
    /// `X'01'` general SOCKS server failure.
    GeneralFailure,
    /// `X'02'` connection not allowed by ruleset.
    NotAllowed,
    /// `X'03'` network unreachable.
    NetworkUnreachable,
    /// `X'04'` host unreachable.
    HostUnreachable,
    /// `X'05'` connection refused.
    ConnectionRefused,
    /// `X'07'` command not supported.
    CommandNotSupported,
    /// `X'08'` address type not supported.
    AddressTypeNotSupported,
}

impl Socks5Reply {
    /// The wire byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::NotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        }
    }
}

/// Reads the client's greeting and returns the methods it offered.
///
/// RFC 1928 §3: `VER | NMETHODS | METHODS…`.
///
/// # Errors
///
/// [`Socks5Error::Truncated`], [`Socks5Error::UnsupportedVersion`] or
/// [`Socks5Error::NoMethods`].
pub fn parse_greeting(bytes: &[u8]) -> Result<Vec<u8>, Socks5Error> {
    let (&version, rest) = bytes.split_first().ok_or(Socks5Error::Truncated)?;
    if version != VERSION {
        return Err(Socks5Error::UnsupportedVersion);
    }
    let (&count, rest) = rest.split_first().ok_or(Socks5Error::Truncated)?;
    if count == 0 {
        return Err(Socks5Error::NoMethods);
    }
    let methods = rest
        .get(..usize::from(count))
        .ok_or(Socks5Error::Truncated)?;
    Ok(methods.to_vec())
}

/// Chooses a method from what the client offered.
///
/// `None` means the client must be told `X'FF'` and the connection closed.
#[must_use]
pub fn select_method(offered: &[u8]) -> Option<u8> {
    offered.contains(&METHOD_NO_AUTH).then_some(METHOD_NO_AUTH)
}

/// The two-byte method selection message (RFC 1928 §3).
#[must_use]
pub const fn encode_method_choice(method: u8) -> [u8; 2] {
    [VERSION, method]
}

/// Reads a request (RFC 1928 §4).
///
/// # Errors
///
/// Any [`Socks5Error`]; nothing here trusts a length byte it has not checked
/// against the buffer.
pub fn parse_request(bytes: &[u8]) -> Result<Socks5Request, Socks5Error> {
    let header = bytes.get(..4).ok_or(Socks5Error::Truncated)?;
    let (&version, rest) = header.split_first().ok_or(Socks5Error::Truncated)?;
    if version != VERSION {
        return Err(Socks5Error::UnsupportedVersion);
    }
    let (&command, rest) = rest.split_first().ok_or(Socks5Error::Truncated)?;
    let command = Socks5Command::from_code(command)?;
    // rest[0] is RSV, which RFC 1928 requires to be X'00' and which is ignored
    // here: refusing a connection over a reserved byte helps nobody.
    let &address_type = rest.get(1).ok_or(Socks5Error::Truncated)?;

    let body = bytes.get(4..).ok_or(Socks5Error::Truncated)?;
    let (address, consumed) = match address_type {
        0x01 => {
            let octets: [u8; 4] = body
                .get(..4)
                .ok_or(Socks5Error::Truncated)?
                .try_into()
                .map_err(|_| Socks5Error::Truncated)?;
            (Socks5Address::Ipv4(Ipv4Addr::from(octets)), 4)
        }
        0x03 => {
            let (&length, rest) = body.split_first().ok_or(Socks5Error::Truncated)?;
            if length == 0 {
                return Err(Socks5Error::InvalidDomain);
            }
            let name = rest
                .get(..usize::from(length))
                .ok_or(Socks5Error::Truncated)?;
            let name = std::str::from_utf8(name).map_err(|_| Socks5Error::InvalidDomain)?;
            (
                Socks5Address::Domain(name.to_owned()),
                1 + usize::from(length),
            )
        }
        0x04 => {
            let octets: [u8; 16] = body
                .get(..16)
                .ok_or(Socks5Error::Truncated)?
                .try_into()
                .map_err(|_| Socks5Error::Truncated)?;
            (Socks5Address::Ipv6(Ipv6Addr::from(octets)), 16)
        }
        _ => return Err(Socks5Error::UnknownAddressType),
    };

    let port = body
        .get(consumed..consumed + 2)
        .ok_or(Socks5Error::Truncated)?;
    let port = u16::from_be_bytes([
        *port.first().ok_or(Socks5Error::Truncated)?,
        *port.get(1).ok_or(Socks5Error::Truncated)?,
    ]);

    Ok(Socks5Request {
        command,
        address,
        port,
    })
}

/// Encodes a reply (RFC 1928 §6).
///
/// `bound` is what the server would report as `BND.ADDR`/`BND.PORT`. For a
/// tunnelled `CONNECT` there is no local socket that means anything to the
/// client, so `0.0.0.0:0` is sent — which is what OpenSSH's own dynamic
/// forwarder does, and what clients expect.
#[must_use]
pub fn encode_reply(reply: Socks5Reply, bound: SocketAddr) -> Vec<u8> {
    let mut out = vec![VERSION, reply.code(), 0x00];
    match bound.ip() {
        IpAddr::V4(address) => {
            out.push(0x01);
            out.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            out.push(0x04);
            out.extend_from_slice(&address.octets());
        }
    }
    out.extend_from_slice(&bound.port().to_be_bytes());
    out
}

/// The address a tunnelled reply reports: no local socket is meaningful.
#[must_use]
pub const fn unspecified_bound() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
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
    fn a_greeting_yields_its_methods() {
        assert_eq!(
            parse_greeting(&[0x05, 0x02, 0x00, 0x02]).unwrap(),
            vec![0, 2]
        );
        assert_eq!(parse_greeting(&[0x05, 0x01, 0x00]).unwrap(), vec![0]);
    }

    #[test]
    fn a_greeting_is_never_trusted_about_its_own_length() {
        // The count byte is attacker-controlled; reading past the buffer on it
        // is the classic parser bug this listener must not have.
        assert_eq!(
            parse_greeting(&[0x05, 0xff, 0x00]),
            Err(Socks5Error::Truncated)
        );
        assert_eq!(parse_greeting(&[]), Err(Socks5Error::Truncated));
        assert_eq!(parse_greeting(&[0x05]), Err(Socks5Error::Truncated));
        assert_eq!(parse_greeting(&[0x05, 0x00]), Err(Socks5Error::NoMethods));
        assert_eq!(
            parse_greeting(&[0x04, 0x01, 0x00]),
            Err(Socks5Error::UnsupportedVersion)
        );
    }

    #[test]
    fn only_no_authentication_is_offered() {
        assert_eq!(select_method(&[0x00]), Some(METHOD_NO_AUTH));
        assert_eq!(select_method(&[0x02, 0x00]), Some(METHOD_NO_AUTH));
        // Username/password only: refused, so the client is told rather than
        // left waiting.
        assert_eq!(select_method(&[0x02]), None);
        assert_eq!(select_method(&[]), None);
        assert_eq!(encode_method_choice(METHOD_NONE_ACCEPTABLE), [0x05, 0xff]);
    }

    #[test]
    fn a_connect_request_parses_for_every_address_type() {
        let ipv4 = parse_request(&[0x05, 0x01, 0x00, 0x01, 10, 0, 0, 5, 0x01, 0xbb]).unwrap();
        assert_eq!(
            ipv4,
            Socks5Request {
                command: Socks5Command::Connect,
                address: Socks5Address::Ipv4(Ipv4Addr::new(10, 0, 0, 5)),
                port: 443,
            }
        );

        let mut domain = vec![0x05, 0x01, 0x00, 0x03, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&80u16.to_be_bytes());
        let parsed = parse_request(&domain).unwrap();
        assert_eq!(
            parsed.address,
            Socks5Address::Domain("example.com".to_owned())
        );
        assert_eq!(parsed.port, 80);

        let mut ipv6 = vec![0x05, 0x01, 0x00, 0x04];
        ipv6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        ipv6.extend_from_slice(&22u16.to_be_bytes());
        let parsed = parse_request(&ipv6).unwrap();
        assert_eq!(parsed.address, Socks5Address::Ipv6(Ipv6Addr::LOCALHOST));
        // Bracketed on the way out, so the address and port concatenate into
        // something a resolver can read.
        assert_eq!(parsed.address.to_string(), "[::1]");
    }

    #[test]
    fn a_truncated_request_is_refused_at_every_cut() {
        let mut full = vec![0x05, 0x01, 0x00, 0x03, 11];
        full.extend_from_slice(b"example.com");
        full.extend_from_slice(&80u16.to_be_bytes());
        for cut in 0..full.len() {
            assert!(
                parse_request(&full[..cut]).is_err(),
                "a {cut}-byte prefix parsed"
            );
        }
        assert!(parse_request(&full).is_ok());
    }

    #[test]
    fn a_lying_domain_length_does_not_read_past_the_buffer() {
        let mut lying = vec![0x05, 0x01, 0x00, 0x03, 200];
        lying.extend_from_slice(b"short");
        lying.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(parse_request(&lying), Err(Socks5Error::Truncated));
    }

    #[test]
    fn a_domain_that_is_not_text_is_refused() {
        let mut invalid = vec![0x05, 0x01, 0x00, 0x03, 2, 0xff, 0xfe];
        invalid.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(parse_request(&invalid), Err(Socks5Error::InvalidDomain));

        let empty = [0x05, 0x01, 0x00, 0x03, 0, 0, 80];
        assert_eq!(parse_request(&empty), Err(Socks5Error::InvalidDomain));
    }

    #[test]
    fn unknown_commands_and_address_types_are_named() {
        assert_eq!(
            parse_request(&[0x05, 0x09, 0x00, 0x01, 1, 2, 3, 4, 0, 22]),
            Err(Socks5Error::UnknownCommand)
        );
        assert_eq!(
            parse_request(&[0x05, 0x01, 0x00, 0x09, 1, 2, 3, 4, 0, 22]),
            Err(Socks5Error::UnknownAddressType)
        );
        assert_eq!(
            parse_request(&[0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 22]),
            Err(Socks5Error::UnsupportedVersion)
        );
    }

    #[test]
    fn bind_and_udp_associate_parse_so_they_can_be_refused_properly() {
        // A client that asks for something unsupported gets `X'07'` and can
        // fall back; a parser that errored here would hang it instead.
        for (code, expected) in [
            (0x02, Socks5Command::Bind),
            (0x03, Socks5Command::UdpAssociate),
        ] {
            let request =
                parse_request(&[0x05, code, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]).unwrap();
            assert_eq!(request.command, expected);
            assert_eq!(request.command.code(), code);
        }
        assert_eq!(Socks5Reply::CommandNotSupported.code(), 0x07);
    }

    #[test]
    fn a_reply_is_the_shape_rfc_1928_section_6_describes() {
        let reply = encode_reply(Socks5Reply::Succeeded, unspecified_bound());
        assert_eq!(reply, vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

        let refused = encode_reply(
            Socks5Reply::ConnectionRefused,
            SocketAddr::from(([192, 0, 2, 1], 8080)),
        );
        assert_eq!(
            refused,
            vec![0x05, 0x05, 0x00, 0x01, 192, 0, 2, 1, 0x1f, 0x90]
        );

        let v6 = encode_reply(
            Socks5Reply::Succeeded,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1080),
        );
        assert_eq!(v6.len(), 4 + 16 + 2);
        assert_eq!(v6.get(3), Some(&0x04));
    }

    #[test]
    fn errors_quote_nothing_the_client_sent() {
        // A log line built from a hostile greeting is a log-injection bug.
        let error =
            parse_request(&[0x05, 0x01, 0x00, 0x03, 4, b'e', b'v', b'i', b'l']).unwrap_err();
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("evil"), "rendered: {rendered}");
    }

    #[test]
    fn the_command_names_are_stable() {
        assert_eq!(Socks5Command::Connect.as_str(), "connect");
        assert_eq!(Socks5Command::Bind.as_str(), "bind");
        assert_eq!(Socks5Command::UdpAssociate.as_str(), "udp-associate");
        assert_eq!(MAX_DOMAIN_LEN, 255);
    }
}
