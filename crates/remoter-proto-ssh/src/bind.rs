//! Where a port forward listens, and why the default is loopback.
//!
//! `docs/features/tunneling.md`: **the bind address defaults to loopback**, and
//! binding elsewhere is an explicit setting. For a local forward that keeps the
//! tunnel off the office network; for a remote forward it is stronger than
//! that — a `-R` bound to `0.0.0.0` opens a path *from the remote network back
//! into the user's machine*, which is a decision nobody makes by accident and
//! several people make by copying a command from a wiki.
//!
//! There is a second trap the RFC lays. RFC 4254 §7.1 defines the
//! `address_to_bind` of a `tcpip-forward` request:
//!
//! > "" means that connections are to be accepted on all protocol families […]
//! > "localhost" means to listen on all protocol families supported by the SSH
//! > implementation on loopback addresses only
//!
//! So the *empty* string — the natural spelling of "I did not configure this"
//! — asks the server for every interface. Defaulting to `""` would silently do
//! the exposing thing. This module defaults to `localhost`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use remoter_proto::ProtocolError;

/// The loopback spelling RFC 4254 §7.1 gives, and the default everywhere here.
pub const LOOPBACK: &str = "localhost";

/// How far a listener can be reached from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Exposure {
    /// Reachable only from the machine the listener runs on.
    Loopback,
    /// Reachable from the network. Carries the warning badge in the interface.
    Network,
}

impl Exposure {
    /// A stable ASCII name for the message catalogue.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Network => "network",
        }
    }
}

/// A validated listening address for a forward.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForwardBind {
    address: String,
    port: u16,
    exposure: Exposure,
}

impl ForwardBind {
    /// Validates a configured bind address.
    ///
    /// `address` of `None` or an empty string means the default, which is
    /// loopback — never RFC 4254's `""`. `allow_exposed` is the explicit
    /// setting the specification requires: without it a non-loopback address
    /// is refused rather than quietly accepted with a warning, because a
    /// warning on a listener that is already open has arrived too late.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SettingInvalid`] if the address is not an address, or
    /// is a non-loopback one without `allow_exposed`.
    pub fn new(
        address: Option<&str>,
        port: u16,
        allow_exposed: bool,
    ) -> Result<Self, ProtocolError> {
        let raw = address.map(str::trim).unwrap_or_default();
        let address = if raw.is_empty() { LOOPBACK } else { raw };
        let exposure = classify(address)?;

        if exposure == Exposure::Network && !allow_exposed {
            return Err(ProtocolError::SettingInvalid {
                key: "bind_address".to_owned(),
                expected: "a loopback address, unless the forward is explicitly exposed",
            });
        }

        Ok(Self {
            address: address.to_owned(),
            port,
            exposure,
        })
    }

    /// Validates a bind address for a listener on **this** machine.
    ///
    /// [`new`](Self::new) accepts every spelling RFC 4254 §7.1 defines,
    /// including `*`, because a `tcpip-forward` request is interpreted by the
    /// *server*. A listener here needs a real socket, so `*` — and anything
    /// else [`local_socket`](Self::local_socket) cannot turn into one — is
    /// refused at construction rather than at bind time. A configuration error
    /// that surfaces when the tunnel is started is a configuration error the
    /// user finds out about from a failed session.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SettingInvalid`] as [`new`](Self::new), and for an
    /// address that is only meaningful to a server.
    pub fn local(
        address: Option<&str>,
        port: u16,
        allow_exposed: bool,
    ) -> Result<Self, ProtocolError> {
        let bind = Self::new(address, port, allow_exposed)?;
        bind.local_socket()?;
        Ok(bind)
    }

    /// The loopback default on `port`.
    ///
    /// # Errors
    ///
    /// Never in practice; the signature matches [`new`](Self::new) so that
    /// call sites do not branch.
    pub fn loopback(port: u16) -> Result<Self, ProtocolError> {
        Self::local(None, port, false)
    }

    /// The address as configured.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// How far this listener can be reached from.
    #[must_use]
    pub const fn exposure(&self) -> Exposure {
        self.exposure
    }

    /// The string to put in a `tcpip-forward` request (RFC 4254 §7.1).
    ///
    /// `localhost` and `0.0.0.0` are both meaningful *to the server* and are
    /// passed through as written. What is never sent is `""`.
    #[must_use]
    pub fn wire_address(&self) -> &str {
        &self.address
    }

    /// The socket a local listener binds.
    ///
    /// `localhost` resolves to `127.0.0.1` rather than going through the
    /// resolver: a forward that lands on whatever `localhost` happens to mean
    /// in `/etc/hosts` is not a forward the user configured.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::SettingInvalid`] if the address is a name this cannot
    /// resolve without the network.
    pub fn local_socket(&self) -> Result<SocketAddr, ProtocolError> {
        let ip = match self.address.as_str() {
            LOOPBACK => IpAddr::V4(Ipv4Addr::LOCALHOST),
            other => other
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .map_err(|_| ProtocolError::SettingInvalid {
                    key: "bind_address".to_owned(),
                    expected: "an IP address, or `localhost`",
                })?,
        };
        Ok(SocketAddr::new(ip, self.port))
    }
}

impl fmt::Display for ForwardBind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

/// Whether an address reaches beyond the machine it is bound on.
///
/// `*` is accepted as a spelling of "everything" because that is what the
/// interface's own syntax uses and what OpenSSH's `-L *:port:...` means.
fn classify(address: &str) -> Result<Exposure, ProtocolError> {
    if address == LOOPBACK {
        return Ok(Exposure::Loopback);
    }
    if address == "*" {
        return Ok(Exposure::Network);
    }
    let ip = address
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .map_err(|_| ProtocolError::SettingInvalid {
            key: "bind_address".to_owned(),
            expected: "an IP address, `localhost`, or `*`",
        })?;
    Ok(if ip.is_loopback() {
        Exposure::Loopback
    } else {
        Exposure::Network
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

    #[test]
    fn nothing_configured_means_loopback_and_never_the_empty_string() {
        // RFC 4254 §7.1: `""` asks the server to listen on every interface.
        // Defaulting to it would expose a remote forward by omission.
        for unset in [None, Some(""), Some("   ")] {
            let bind = ForwardBind::new(unset, 8080, false).unwrap();
            assert_eq!(bind.wire_address(), "localhost");
            assert_eq!(bind.exposure(), Exposure::Loopback);
            assert_eq!(
                bind.local_socket().unwrap(),
                SocketAddr::from(([127, 0, 0, 1], 8080))
            );
        }
    }

    #[test]
    fn a_non_loopback_address_needs_the_explicit_setting() {
        for exposed in ["0.0.0.0", "*", "192.168.1.10", "::", "2001:db8::1"] {
            let refused = ForwardBind::new(Some(exposed), 9000, false).unwrap_err();
            let ProtocolError::SettingInvalid { key, .. } = refused else {
                panic!("expected SettingInvalid for {exposed}, got {refused:?}");
            };
            assert_eq!(key, "bind_address");

            let allowed = ForwardBind::new(Some(exposed), 9000, true).unwrap();
            assert_eq!(
                allowed.exposure(),
                Exposure::Network,
                "{exposed} should be flagged as exposed"
            );
        }
    }

    #[test]
    fn every_loopback_spelling_is_loopback() {
        for loopback in ["localhost", "127.0.0.1", "127.0.0.53", "::1", "[::1]"] {
            let bind = ForwardBind::new(Some(loopback), 1080, false).unwrap();
            assert_eq!(
                bind.exposure(),
                Exposure::Loopback,
                "{loopback} should be loopback"
            );
        }
    }

    #[test]
    fn a_name_that_is_not_an_address_is_refused() {
        // Resolving here would make the forward land wherever DNS said, which
        // is not the address the user configured.
        let error = ForwardBind::new(Some("bastion.example.com"), 22, true).unwrap_err();
        assert!(matches!(error, ProtocolError::SettingInvalid { .. }));
    }

    #[test]
    fn an_exposed_bind_keeps_its_wire_spelling() {
        // `0.0.0.0` and `*` mean different things to a server (RFC 4254 §7.1
        // distinguishes "all IPv4" from "all families"), so neither is
        // rewritten into the other.
        let any_v4 = ForwardBind::new(Some("0.0.0.0"), 9000, true).unwrap();
        assert_eq!(any_v4.wire_address(), "0.0.0.0");
        let all = ForwardBind::new(Some("*"), 9000, true).unwrap();
        assert_eq!(all.wire_address(), "*");
    }

    #[test]
    fn a_star_bind_cannot_be_turned_into_a_local_socket() {
        // `*` is a server-side spelling; a local listener needs a real address.
        let bind = ForwardBind::new(Some("*"), 9000, true).unwrap();
        assert!(bind.local_socket().is_err());
    }

    #[test]
    fn a_server_only_spelling_is_refused_when_the_listener_is_local() {
        // `*` passes `new` — it is a legal `tcpip-forward` address — and used
        // to be caught only when the socket was bound, so a `-L *:9000`
        // reached the user as a session that failed to start rather than as a
        // setting that would not save.
        let error = ForwardBind::local(Some("*"), 9000, true).unwrap_err();
        let ProtocolError::SettingInvalid { key, .. } = error else {
            panic!("expected SettingInvalid, got {error:?}");
        };
        assert_eq!(key, "bind_address");

        // A remote forward still gets the spelling the RFC defines.
        assert_eq!(
            ForwardBind::new(Some("*"), 9000, true)
                .unwrap()
                .wire_address(),
            "*"
        );

        // And every address a local listener really can use still passes.
        for usable in ["localhost", "127.0.0.1", "::1", "0.0.0.0"] {
            ForwardBind::local(Some(usable), 9000, true)
                .unwrap_or_else(|error| panic!("{usable} was refused: {error:?}"));
        }
        // The exposure rule is unchanged: it still needs the explicit setting.
        assert!(ForwardBind::local(Some("0.0.0.0"), 9000, false).is_err());
    }

    #[test]
    fn the_rendering_is_address_colon_port() {
        let bind = ForwardBind::new(None, 5432, false).unwrap();
        assert_eq!(bind.to_string(), "localhost:5432");
        assert_eq!(Exposure::Network.as_str(), "network");
        assert_eq!(Exposure::Loopback.as_str(), "loopback");
    }

    #[test]
    fn loopback_helper_matches_the_default() {
        assert_eq!(
            ForwardBind::loopback(1080).unwrap(),
            ForwardBind::new(None, 1080, false).unwrap()
        );
    }
}
