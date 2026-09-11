//! RFC 6143 §7.1: the version handshake and the security handshake, performed
//! here rather than in `vnc-rs`.
//!
//! # Why this is ours
//!
//! ADR-0013. `vnc-rs` 0.5.3 negotiates RFC 6143 §7.1 like this:
//!
//! - the version in force is `min(ours, theirs)` with **no floor**, so any
//!   server can answer `RFB 003.003\n` and move the conversation into the 3.3
//!   shape, where the *server* chooses the security type;
//! - the security type is chosen by `security_types.contains(&SecurityType::None)`
//!   — `None` is **preferred** over VNC authentication whenever it is offered.
//!
//! Put together, a hostile peer answers the version handshake with 3.3, offers
//! `None`, and gets an unauthenticated session in which the configured password
//! is never used and nothing tells the user. `docs/security/threat-model.md`
//! assumes exactly such a peer (T3, T4), and the graphical protocols were meant
//! to copy the trust model `remoter_proto::hostkey` sets for SSH: the client
//! decides what it will accept, and says what it accepted.
//!
//! So this module reads the version, applies a **floor as well as a ceiling**,
//! reads the offered security types, and **selects** one under a policy that
//! refuses `None` whenever a credential is configured. [`crate::gate`] then
//! replays a synthetic, trusted handshake to `vnc-rs`, which keeps the library
//! doing the large, dull part — DES and pixel decoding — over bytes it can no
//! longer be talked into misreading.
//!
//! # It is a parser, and it is fed by the network
//!
//! Nothing below allocates a buffer the peer sizes. The version is twelve
//! bytes; the security list is at most [`MAX_SECURITY_TYPES`], because the
//! count field is a `U8`. The reason string that follows a refusal
//! (RFC 6143 §7.1.2) is deliberately never read: it is peer-authored text, and
//! reading it would mean allocating a length the peer chose in order to show
//! the user words the peer wrote.

use remoter_proto::{CredentialKind, ProtocolError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{handshake_failed, map_io, violation};
use crate::handshake::{HandshakeFacts, MAX_SECURITY_TYPES, RfbVersion, VERSION_BYTES};
use crate::security::SecurityType;

/// What the handshake settled on, and what the server said on the way there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The version both ends are speaking.
    pub version: RfbVersion,
    /// The security type this client selected and told the server about.
    pub security: SecurityType,
    /// Everything the handshake revealed, for diagnostics and warnings.
    pub facts: HandshakeFacts,
}

impl Negotiated {
    /// Whether the session that follows authenticated with nothing at all.
    #[must_use]
    pub fn is_unauthenticated(&self) -> bool {
        self.security == SecurityType::NONE
    }

    /// Whether the server will send a `SecurityResult` word (RFC 6143 §7.1.3).
    ///
    /// Always after VNC authentication. After `None` only in 3.8 — 3.3 and 3.7
    /// proceed straight to the initialisation messages. Getting this wrong in
    /// either direction desynchronises the stream by four bytes, which is why
    /// it is one function with the rule written out rather than a condition
    /// repeated at each use.
    #[must_use]
    pub fn expects_security_result(&self) -> bool {
        self.security == SecurityType::VNC_AUTH || self.version == RfbVersion::Rfb38
    }
}

/// Runs RFC 6143 §7.1.1 and §7.1.2 against `stream`.
///
/// `floor` and `ceiling` bracket the versions this connection will speak;
/// `has_credential` says whether a password is available to answer a challenge
/// with. On return the wire is positioned immediately after the client's
/// security-type selection — that is, at the DES challenge for VNC
/// authentication, at the `SecurityResult` word where one is expected, and at
/// `ServerInit` otherwise.
///
/// # Errors
///
/// [`ProtocolError::Disconnected`] or [`ProtocolError::Io`] if the stream
/// failed; [`ProtocolError::HandshakeFailed`] if the server's version is below
/// the floor or it refused outright;
/// [`ProtocolError::AuthMethodUnavailable`] if nothing it offered is a type
/// this connection may use.
pub async fn negotiate<S>(
    stream: &mut S,
    floor: RfbVersion,
    ceiling: RfbVersion,
    has_credential: bool,
) -> Result<Negotiated, ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut facts = HandshakeFacts::default();

    // RFC 6143 §7.1.1. Exactly twelve bytes; nothing here is sized by the peer.
    let mut announced = [0_u8; VERSION_BYTES];
    stream
        .read_exact(&mut announced)
        .await
        .map_err(|error| map_io(&error, "read the RFB version"))?;
    let server = RfbVersion::from_wire(&announced);
    facts.server_version = Some(server);

    // The floor. Without it `min` is a downgrade the far end controls: a server
    // that answers 3.3 moves the security handshake into the shape where it,
    // not this client, picks the type. That is the defect this line prevents
    // coming back.
    if server < floor {
        return Err(handshake_failed(
            "the server offered an RFB version below the minimum this connection permits",
        ));
    }
    let version = ceiling.negotiated_with(server);
    facts.negotiated_version = Some(version);

    stream
        .write_all(version.as_wire())
        .await
        .map_err(|error| map_io(&error, "send the RFB version"))?;
    stream
        .flush()
        .await
        .map_err(|error| map_io(&error, "send the RFB version"))?;

    // RFC 6143 §7.1.2, in whichever of its two shapes applies.
    if version == RfbVersion::Rfb33 {
        read_single_type(stream, &mut facts).await?;
    } else {
        read_type_list(stream, &mut facts).await?;
    }

    if facts.refused_outright {
        // A reason string follows on the wire and is not read. See the module
        // documentation.
        return Err(handshake_failed(
            "the server refused the connection before offering a security type",
        ));
    }

    let security = select_security(&facts, has_credential)?;
    facts.selected_security = Some(security);

    // RFB 3.3 gives the client no reply to send: the server chose. Writing one
    // would put a stray byte in front of the challenge.
    if version != RfbVersion::Rfb33 {
        stream
            .write_all(&[security.to_wire()])
            .await
            .map_err(|error| map_io(&error, "select an RFB security type"))?;
        stream
            .flush()
            .await
            .map_err(|error| map_io(&error, "select an RFB security type"))?;
    }

    Ok(Negotiated {
        version,
        security,
        facts,
    })
}

/// RFB 3.3 (RFC 6143 §7.1.2): the server sends one `U32` and the client has no
/// say. A value of zero means the connection failed.
async fn read_single_type<S>(
    stream: &mut S,
    facts: &mut HandshakeFacts,
) -> Result<(), ProtocolError>
where
    S: AsyncRead + Unpin,
{
    let mut word = [0_u8; 4];
    stream
        .read_exact(&mut word)
        .await
        .map_err(|error| map_io(&error, "read the RFB security type"))?;
    let value = u32::from_be_bytes(word);
    if value == 0 {
        facts.refused_outright = true;
        return Ok(());
    }
    // The registry is a `U8` space; RFB 3.3 widens it to `U32` on the wire.
    // `vnc-rs` narrows with `as u8`, so `0x0000_0102` reads to it as VNC
    // authentication. Truncating a wide value into a *different* registered
    // type is how a server picks the branch the client takes, so anything above
    // 255 is refused rather than narrowed.
    let Ok(byte) = u8::try_from(value) else {
        return Err(violation(
            "the server sent an RFB 3.3 security type outside the one-byte registry",
        ));
    };
    facts.offered_security.push(SecurityType::from_wire(byte));
    Ok(())
}

/// RFB 3.7 and 3.8 (RFC 6143 §7.1.2): a `U8` count, then that many `U8` type
/// numbers. A count of zero means the connection failed.
async fn read_type_list<S>(stream: &mut S, facts: &mut HandshakeFacts) -> Result<(), ProtocolError>
where
    S: AsyncRead + Unpin,
{
    let mut count = [0_u8; 1];
    stream
        .read_exact(&mut count)
        .await
        .map_err(|error| map_io(&error, "read the RFB security types"))?;
    let count = usize::from(count[0]);
    if count == 0 {
        facts.refused_outright = true;
        return Ok(());
    }
    // `count` is a `U8`, so this buffer is at most `MAX_SECURITY_TYPES` bytes
    // whatever the peer sends. The assertion is written as a `min` rather than
    // as a comment so that widening the count field upstream cannot widen this.
    let mut types = vec![0_u8; count.min(MAX_SECURITY_TYPES)];
    stream
        .read_exact(&mut types)
        .await
        .map_err(|error| map_io(&error, "read the RFB security types"))?;
    facts
        .offered_security
        .extend(types.iter().map(|byte| SecurityType::from_wire(*byte)));
    Ok(())
}

/// Chooses the security type this connection will use, or refuses.
///
/// The whole policy, in one pure function, because it is the decision the
/// CRITICAL defect turned on:
///
/// - **A configured credential means authentication happens.** `None` is
///   refused outright when a password is available, whatever the server
///   prefers. `vnc-rs` does the opposite — it takes `None` whenever it is
///   offered, and the password is then never read — which hands any peer that
///   can answer the port an unauthenticated session and tells nobody.
/// - **No credential means `None` or nothing.** A VNC authentication challenge
///   cannot be answered without a password, so a server offering only that is
///   reported as the authentication failure it is rather than attempted.
/// - **Anything else is refused by name.** VeNCrypt, Apple Remote Desktop and
///   the rest are not implemented here; saying which one was needed is the
///   difference between a user who can act and a user who cannot.
///
/// # Errors
///
/// [`ProtocolError::AuthMethodUnavailable`], naming what the server offered.
pub fn select_security(
    facts: &HandshakeFacts,
    has_credential: bool,
) -> Result<SecurityType, ProtocolError> {
    let offered = &facts.offered_security;
    if has_credential {
        if offered.contains(&SecurityType::VNC_AUTH) {
            return Ok(SecurityType::VNC_AUTH);
        }
        // Including the case where `None` *was* offered. Accepting it would be
        // a silent downgrade to an unauthenticated session, which is the
        // defect; refusing it is the only answer that leaves the user's
        // password meaning something.
        return Err(ProtocolError::AuthMethodUnavailable {
            attempted: CredentialKind::Password,
            offered: facts.offered_names(),
        });
    }
    if offered.contains(&SecurityType::NONE) {
        return Ok(SecurityType::NONE);
    }
    Err(ProtocolError::AuthMethodUnavailable {
        // RFB has no account name and no key: a password is the only thing a
        // client can present, so "this connection has no credential" is the
        // true sentence when the server wants a challenge answered.
        attempted: CredentialKind::None,
        offered: facts.offered_names(),
    })
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
    use tokio::io::duplex;

    fn offering(types: &[SecurityType]) -> HandshakeFacts {
        HandshakeFacts {
            offered_security: types.to_vec(),
            ..HandshakeFacts::default()
        }
    }

    #[test]
    fn a_configured_password_refuses_a_server_that_offers_no_authentication() {
        // The CRITICAL defect as a unit. `vnc-rs` prefers `None` whenever it is
        // offered, so this exact list produced an unauthenticated session in
        // which the password was never read.
        let facts = offering(&[SecurityType::NONE]);
        let error = select_security(&facts, true).expect_err("a password must be used");
        let ProtocolError::AuthMethodUnavailable { attempted, offered } = error else {
            panic!("refusing a downgrade is an authentication failure");
        };
        assert_eq!(attempted, CredentialKind::Password);
        assert_eq!(offered, vec!["None".to_owned()]);
    }

    #[test]
    fn a_configured_password_takes_vnc_authentication_even_when_none_is_first() {
        // Order is the server's hint, not its decision: `None` leading the list
        // must not win over the type that actually uses the credential.
        let facts = offering(&[SecurityType::NONE, SecurityType::VNC_AUTH]);
        assert_eq!(
            select_security(&facts, true).unwrap(),
            SecurityType::VNC_AUTH
        );
    }

    #[test]
    fn a_session_with_no_credential_may_still_use_none() {
        let facts = offering(&[SecurityType::VNC_AUTH, SecurityType::NONE]);
        assert_eq!(select_security(&facts, false).unwrap(), SecurityType::NONE);
    }

    #[test]
    fn a_session_with_no_credential_cannot_answer_a_challenge() {
        let facts = offering(&[SecurityType::VNC_AUTH]);
        let error = select_security(&facts, false).expect_err("nothing to answer with");
        let ProtocolError::AuthMethodUnavailable { attempted, offered } = error else {
            panic!("a challenge with no password is an authentication failure");
        };
        assert_eq!(attempted, CredentialKind::None);
        assert_eq!(offered, vec!["VNC Authentication".to_owned()]);
    }

    #[test]
    fn a_server_offering_nothing_this_build_implements_names_what_it_offered() {
        let facts = offering(&[SecurityType::VENCRYPT, SecurityType::APPLE_RD]);
        for has_credential in [true, false] {
            let error =
                select_security(&facts, has_credential).expect_err("neither is implemented");
            let ProtocolError::AuthMethodUnavailable { offered, .. } = error else {
                panic!("this is an authentication failure, not a mystery");
            };
            assert_eq!(
                offered,
                vec!["VeNCrypt".to_owned(), "Apple Remote Desktop".to_owned()]
            );
        }
    }

    /// Drives [`negotiate`] against a script written by hand from RFC 6143.
    async fn against(
        script: &'static [u8],
        floor: RfbVersion,
        ceiling: RfbVersion,
        has_credential: bool,
    ) -> (Result<Negotiated, ProtocolError>, Vec<u8>) {
        let (mut client, mut server) = duplex(1024);
        let writer = tokio::spawn(async move {
            let _ = server.write_all(script).await;
            let mut sent = Vec::new();
            // The client's replies, so a test can assert what went on the wire.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(250),
                server.read_to_end(&mut sent),
            )
            .await;
            sent
        });
        let outcome = negotiate(&mut client, floor, ceiling, has_credential).await;
        drop(client);
        let sent = writer.await.unwrap();
        (outcome, sent)
    }

    #[tokio::test]
    async fn a_38_server_offering_vnc_authentication_is_selected_and_acknowledged() {
        let (outcome, sent) = against(
            b"RFB 003.008\n\x02\x01\x02",
            RfbVersion::Rfb38,
            RfbVersion::Rfb38,
            true,
        )
        .await;
        let negotiated = outcome.expect("3.8 with VNC authentication connects");
        assert_eq!(negotiated.version, RfbVersion::Rfb38);
        assert_eq!(negotiated.security, SecurityType::VNC_AUTH);
        assert!(negotiated.expects_security_result());
        assert!(!negotiated.is_unauthenticated());
        assert_eq!(&sent[..12], b"RFB 003.008\n");
        assert_eq!(sent[12], 2, "the selection is sent as one byte");
    }

    #[tokio::test]
    async fn a_server_that_answers_33_is_refused_by_the_floor() {
        // The downgrade the CRITICAL defect rode in on. The server announces
        // 3.3, which moves the security handshake into the shape where it
        // chooses — so the floor refuses before a security type is even read.
        let (outcome, sent) = against(
            b"RFB 003.003\n\x00\x00\x00\x01",
            RfbVersion::Rfb38,
            RfbVersion::Rfb38,
            true,
        )
        .await;
        let error = outcome.expect_err("3.3 is below the floor");
        assert!(
            matches!(error, ProtocolError::HandshakeFailed { .. }),
            "{error:?}"
        );
        assert!(
            sent.is_empty(),
            "nothing is sent to a server that failed the floor: {sent:?}"
        );
    }

    #[tokio::test]
    async fn a_33_server_is_reachable_when_the_floor_is_lowered_deliberately() {
        // Lowering the floor is a decision the user makes, and it still does
        // not hand the server the security choice: `None` with a credential
        // configured is refused in the 3.3 shape exactly as in the 3.8 one.
        let (outcome, sent) = against(
            b"RFB 003.003\n\x00\x00\x00\x01",
            RfbVersion::Rfb33,
            RfbVersion::Rfb38,
            true,
        )
        .await;
        let error = outcome.expect_err("a password must not be silently unused");
        assert!(
            matches!(
                error,
                ProtocolError::AuthMethodUnavailable {
                    attempted: CredentialKind::Password,
                    ..
                }
            ),
            "{error:?}"
        );
        assert_eq!(&sent[..12], b"RFB 003.003\n");
        assert_eq!(sent.len(), 12, "RFB 3.3 has no selection byte to send");
    }

    #[tokio::test]
    async fn a_33_server_offering_none_still_works_when_nothing_is_configured() {
        let (outcome, _sent) = against(
            b"RFB 003.003\n\x00\x00\x00\x01",
            RfbVersion::Rfb33,
            RfbVersion::Rfb38,
            false,
        )
        .await;
        let negotiated = outcome.expect("no credential, no authentication");
        assert_eq!(negotiated.version, RfbVersion::Rfb33);
        assert_eq!(negotiated.security, SecurityType::NONE);
        assert!(
            !negotiated.expects_security_result(),
            "RFB 3.3 sends no SecurityResult after None"
        );
    }

    #[tokio::test]
    async fn a_37_server_offering_none_sends_no_security_result() {
        let (outcome, _sent) = against(
            b"RFB 003.007\n\x01\x01",
            RfbVersion::Rfb33,
            RfbVersion::Rfb38,
            false,
        )
        .await;
        let negotiated = outcome.expect("3.7 with None connects");
        assert_eq!(negotiated.version, RfbVersion::Rfb37);
        assert!(!negotiated.expects_security_result());
    }

    #[tokio::test]
    async fn a_wide_33_security_type_is_not_narrowed_into_a_different_one() {
        // `vnc-rs` reads this as `2`, VNC authentication. Narrowing lets the
        // server pick which branch the client takes with bytes that are not the
        // type it named.
        let (outcome, _sent) = against(
            b"RFB 003.003\n\x00\x00\x01\x02",
            RfbVersion::Rfb33,
            RfbVersion::Rfb38,
            true,
        )
        .await;
        let error = outcome.expect_err("0x0102 is not a security type");
        assert!(
            matches!(error, ProtocolError::ProtocolViolation { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_refusal_is_reported_without_reading_the_servers_words() {
        let (outcome, _sent) = against(
            b"RFB 003.008\n\x00\x00\x00\x00\x07go away!",
            RfbVersion::Rfb38,
            RfbVersion::Rfb38,
            false,
        )
        .await;
        let error = outcome.expect_err("a count of zero is a refusal");
        assert!(
            matches!(error, ProtocolError::HandshakeFailed { .. }),
            "{error:?}"
        );
        assert!(!error.to_string().contains("go away"), "{error}");
    }

    #[tokio::test]
    async fn the_longest_possible_list_is_bounded_by_the_count_field() {
        // The count is a `U8`, so 255 is the wire maximum; there is no input
        // that makes this allocate more.
        let mut script = Vec::from(*b"RFB 003.008\n");
        script.push(255);
        script.extend(std::iter::repeat_n(2_u8, 255));
        let script: &'static [u8] = Box::leak(script.into_boxed_slice());

        let (outcome, _sent) = against(script, RfbVersion::Rfb38, RfbVersion::Rfb38, true).await;
        let negotiated = outcome.expect("255 offers of VNC authentication is still VNC auth");
        assert_eq!(negotiated.facts.offered_security.len(), MAX_SECURITY_TYPES);
    }

    #[tokio::test]
    async fn a_server_that_goes_away_mid_version_is_a_disconnection() {
        let (outcome, _sent) =
            against(b"RFB 003.0", RfbVersion::Rfb38, RfbVersion::Rfb38, false).await;
        let error = outcome.expect_err("nine bytes is not a version string");
        assert!(
            matches!(error, ProtocolError::Disconnected { .. }),
            "{error:?}"
        );
    }
}
