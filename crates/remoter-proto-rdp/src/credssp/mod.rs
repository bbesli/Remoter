//! Network Level Authentication: CredSSP over the RDP TLS tunnel. [MS-CSSP].
//!
//! A default Windows Server will not draw a login screen for a client that
//! cannot do this — "Allow connections only from computers running Remote
//! Desktop with Network Level Authentication" is on out of the box — so
//! without it the RDP adapter reaches a certificate it can pin and then stops.
//!
//! # The sequence
//!
//! Everything below happens **inside** the TLS tunnel established at
//! MS-RDPBCGR §5.4.5.1, which is why the transport is already encrypted when
//! the password crosses it. [MS-CSSP] §3.1.5:
//!
//! ```text
//!   client                                                    server
//!     │── TSRequest{ negoTokens: NTLM NEGOTIATE } ────────────────▶│
//!     │◀───────────── TSRequest{ negoTokens: NTLM CHALLENGE } ─────│
//!     │── TSRequest{ negoTokens: NTLM AUTHENTICATE,               │
//!     │              clientNonce, pubKeyAuth } ───────────────────▶│
//!     │◀───────────────────────── TSRequest{ pubKeyAuth } ─────────│   ← verified
//!     │── TSRequest{ authInfo: sealed TSCredentials } ────────────▶│
//! ```
//!
//! # Why `pubKeyAuth` is the part that matters
//!
//! The server proves it holds the private key of the certificate the TLS
//! tunnel was built with, by returning a hash the client can only recompute if
//! both ends saw the same certificate. Without that step CredSSP would hand a
//! password to whoever terminated the TLS connection, which on a self-signed
//! RDP host is exactly the position an attacker wants to be in. So the
//! verification in [`CredsspClient::step`] is not a formality: a mismatch is a
//! hard failure and the credentials are never sent.
//!
//! Two encodings exist, and the one to use depends on the version the peer
//! reports ([MS-CSSP] §3.1.5, "Processing Events and Sequencing Rules"):
//! version 5 and above hash a client-chosen nonce alongside the public key,
//! which is what stops a server from replaying an older client's value; below
//! that the raw public key is sealed, and the server returns it with its first
//! byte incremented.
//!
//! # Kerberos is not implemented
//!
//! Only NTLM. Kerberos would need a KDC, a realm, an SPN resolved through DNS,
//! and either `sspi` — which cannot be added to this workspace, see
//! [`ntlm`] — or a second protocol implementation of comparable size. A domain
//! deployment that has disabled NTLM entirely will therefore not authenticate,
//! and is told so rather than left to guess.

pub mod crypto;
pub mod der;
pub mod ntlm;

use remoter_proto::ProtocolError;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

use crate::error::{auth_rejected, violation};
use der::{Reader, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE, context};
use ntlm::{NtlmClient, NtlmSecurity};

/// The CredSSP version this client claims. [MS-CSSP] §2.2.1.
///
/// Six is what a current Windows client sends. The negotiated version is
/// `min(ours, theirs)`, and everything at five or above uses the nonce-bound
/// public key hash.
pub const CLIENT_VERSION: u32 = 6;

/// The first version that binds the public key hash to a client nonce.
const NONCE_BINDING_VERSION: u32 = 5;

/// Bytes in the client nonce. [MS-CSSP] §2.2.1, `clientNonce`.
const NONCE_BYTES: usize = 32;

/// [MS-CSSP] §3.1.5. The trailing NUL is part of the constant: it is a C
/// string in the specification and the hash is over its terminator too.
const CLIENT_BINDING_LABEL: &[u8] = b"CredSSP Client-To-Server Binding Hash\0";
/// The server's half of the same construction.
const SERVER_BINDING_LABEL: &[u8] = b"CredSSP Server-To-Client Binding Hash\0";

/// `credType` for `TSPasswordCreds`. [MS-CSSP] §2.2.1.2.
const CRED_TYPE_PASSWORD: u32 = 1;

/// Bytes in the Early User Authorization Result PDU. MS-RDPBCGR §2.2.10.2.
pub const EARLY_USER_AUTH_RESULT_BYTES: usize = 4;

/// `AUTHZ_SUCCESS`. MS-RDPBCGR §2.2.10.2.
const AUTHZ_SUCCESS: u32 = 0x0000_0000;

/// What the caller should do next.
#[derive(Debug)]
pub enum Step {
    /// Send these bytes and read another `TSRequest`.
    SendAndContinue(Vec<u8>),
    /// Send these bytes; CredSSP is complete.
    SendAndFinish(Vec<u8>),
}

/// Where the exchange is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for the NTLM CHALLENGE.
    Challenge,
    /// Waiting for the server's `pubKeyAuth`.
    PublicKeyVerification,
    /// Nothing left to do.
    Done,
}

/// The client half of a CredSSP exchange.
///
/// Holds the password, because [MS-CSSP] is a credential *delegation*
/// protocol and the last message is the credential itself. It lives in a
/// buffer that zeroes on drop, is never formatted, and is dropped as soon as
/// the final message is built — which is what makes the "used and immediately
/// dropped" of `docs/architecture/session-pipeline.md` §6 true here rather
/// than aspirational.
pub struct CredsspClient {
    ntlm: NtlmClient,
    security: Option<NtlmSecurity>,
    state: State,
    /// The server's public key, as the DER inside its certificate's
    /// `subjectPublicKeyInfo` BIT STRING. Public by definition.
    public_key: Vec<u8>,
    nonce: [u8; NONCE_BYTES],
    /// `min(CLIENT_VERSION, peer)`, known once the server has answered once.
    negotiated_version: u32,
    domain: String,
    username: String,
    password: Password,
}

/// The password, in a buffer that zeroes itself and refuses to print itself.
struct Password(Vec<u8>);

impl Drop for Password {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for Password {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl core::fmt::Debug for CredsspClient {
    /// Hand-written: a derived one would print the password field's contents
    /// the moment somebody removed `Password`'s own `Debug`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CredsspClient")
            .field("state", &self.state)
            .field("negotiated_version", &self.negotiated_version)
            .finish_non_exhaustive()
    }
}

impl CredsspClient {
    /// A client authenticating `username`@`domain` with `password`.
    ///
    /// `public_key` is the server's public key from the TLS certificate, and
    /// `nonce` is 32 random bytes the caller generated. `spn` is the service
    /// principal name, conventionally `TERMSRV/<hostname>`.
    #[must_use]
    pub fn new(
        username: &str,
        domain: &str,
        workstation: &str,
        spn: &str,
        password: &[u8],
        public_key: Vec<u8>,
        nonce: [u8; NONCE_BYTES],
    ) -> Self {
        Self {
            ntlm: NtlmClient::new(username, domain, workstation, spn, password),
            security: None,
            state: State::Challenge,
            public_key,
            nonce,
            negotiated_version: CLIENT_VERSION,
            domain: domain.to_owned(),
            username: username.to_owned(),
            password: Password(password.to_vec()),
        }
    }

    /// The first message: `TSRequest` carrying the NTLM NEGOTIATE_MESSAGE.
    pub fn start(&mut self) -> Vec<u8> {
        let token = self.ntlm.negotiate();
        TsRequest {
            version: CLIENT_VERSION,
            nego_token: Some(token),
            ..TsRequest::empty()
        }
        .encode()
    }

    /// Consumes one `TSRequest` from the server and produces the next one.
    ///
    /// `client_challenge` and `session_key` are the caller's randomness, taken
    /// as arguments so that the randomness is owned in one place and so the
    /// exchange is reproducible in a test.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::AuthRejected`] when the server reports an
    /// authentication error code, or when its `pubKeyAuth` does not match what
    /// the client computed — the second is a man-in-the-middle indication, and
    /// the credentials are never sent.
    /// [`ProtocolError::ProtocolViolation`] for a malformed or out-of-order
    /// message.
    pub fn step(
        &mut self,
        input: &[u8],
        client_challenge: [u8; 8],
        session_key: [u8; 16],
        now_filetime: u64,
    ) -> Result<Step, ProtocolError> {
        let request = TsRequest::decode(input)?;
        self.negotiated_version = self.negotiated_version.min(request.version);

        // [MS-CSSP] §2.2.1: `errorCode` carries an NTSTATUS. It is the
        // server's own report that the credentials will not do, and it arrives
        // *before* the pipeline would otherwise notice, so it is honoured
        // here rather than left to produce a confusing later failure.
        if let Some(code) = request.error_code
            && code != 0
        {
            tracing::debug!(
                code = format_args!("{code:#010x}"),
                "CredSSP reported an error"
            );
            return Err(auth_rejected());
        }

        match self.state {
            State::Challenge => {
                self.on_challenge(&request, client_challenge, session_key, now_filetime)
            }
            State::PublicKeyVerification => self.on_public_key(&request),
            State::Done => Err(violation(
                "the server sent a CredSSP message after the exchange ended",
            )),
        }
    }

    /// Whether the exchange is finished.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Whether the server will send an Early User Authorization Result PDU.
    ///
    /// It does when `PROTOCOL_HYBRID_EX` was selected (MS-RDPBCGR §5.4.5.2).
    /// Reading it when it will not come would stall the connection sequence
    /// for as long as the deadline allows, so the caller has to know.
    #[must_use]
    pub const fn expects_early_user_auth_result(hybrid_ex: bool) -> bool {
        hybrid_ex
    }

    fn on_challenge(
        &mut self,
        request: &TsRequest,
        client_challenge: [u8; 8],
        session_key: [u8; 16],
        now_filetime: u64,
    ) -> Result<Step, ProtocolError> {
        let challenge = request
            .nego_token
            .as_deref()
            .ok_or_else(|| violation("the server's CredSSP reply carried no NTLM challenge"))?;

        let (authenticate, mut security) =
            self.ntlm
                .authenticate(challenge, client_challenge, session_key, now_filetime)?;

        // [MS-CSSP] §3.1.5: the public key the client asserts. From version 5
        // the nonce is hashed in, which is what stops a server replaying a
        // value it captured from an older exchange.
        let asserted = if self.negotiated_version >= NONCE_BINDING_VERSION {
            binding_hash(CLIENT_BINDING_LABEL, &self.nonce, &self.public_key).to_vec()
        } else {
            self.public_key.clone()
        };
        let pub_key_auth = security.seal(&asserted);
        self.security = Some(security);
        self.state = State::PublicKeyVerification;

        Ok(Step::SendAndContinue(
            TsRequest {
                version: CLIENT_VERSION,
                nego_token: Some(authenticate),
                pub_key_auth: Some(pub_key_auth),
                client_nonce: (self.negotiated_version >= NONCE_BINDING_VERSION)
                    .then(|| self.nonce.to_vec()),
                ..TsRequest::empty()
            }
            .encode(),
        ))
    }

    fn on_public_key(&mut self, request: &TsRequest) -> Result<Step, ProtocolError> {
        let sealed = request.pub_key_auth.as_deref().ok_or_else(|| {
            // A server that skips this step is asking to be handed a password
            // without proving it holds the certificate's private key.
            violation("the server did not return the public key it was challenged with")
        })?;

        let security = self.security.as_mut().ok_or(ProtocolError::Internal {
            detail: "the CredSSP public key step ran before authentication",
        })?;
        let returned = security.unseal(sealed)?;

        let expected = if self.negotiated_version >= NONCE_BINDING_VERSION {
            binding_hash(SERVER_BINDING_LABEL, &self.nonce, &self.public_key).to_vec()
        } else {
            // [MS-CSSP] §3.1.5, legacy form: the server returns the public key
            // with its first byte incremented, so that a byte-for-byte replay
            // of the client's own value does not verify.
            let mut incremented = self.public_key.clone();
            if let Some(first) = incremented.first_mut() {
                *first = first.wrapping_add(1);
            }
            incremented
        };

        use subtle::ConstantTimeEq as _;
        if !bool::from(returned.ct_eq(&expected)) {
            // Not a "handshake failure": the TLS handshake succeeded and this
            // is the far end failing to prove it is the far end. The
            // credentials stop here.
            tracing::warn!(
                "the server's CredSSP public key check failed; the credentials were not sent"
            );
            return Err(ProtocolError::CertificateUntrusted {
                host: remoter_proto::HostPort::new("credssp-peer", 3389).unwrap_or_else(|_| {
                    // Unreachable: the literal is a valid host and 3389 a
                    // valid port. The fallback exists because this crate
                    // forbids `unwrap`, and losing the host name is better
                    // than losing the failure.
                    #[allow(clippy::expect_used, reason = "unreachable; see above")]
                    remoter_proto::HostPort::new("unknown", 3389).expect("a literal host")
                }),
                reason: remoter_proto::CertificateProblem::Changed,
            });
        }

        // The credentials, sealed, and then dropped. This is the only place in
        // the crate where the password is put on a wire.
        let credentials = self.credentials_blob();
        let security = self.security.as_mut().ok_or(ProtocolError::Internal {
            detail: "the CredSSP credential step ran before authentication",
        })?;
        let auth_info = security.seal(credentials.as_slice());
        drop(credentials);

        self.state = State::Done;
        Ok(Step::SendAndFinish(
            TsRequest {
                version: CLIENT_VERSION,
                auth_info: Some(auth_info),
                ..TsRequest::empty()
            }
            .encode(),
        ))
    }

    /// `TSCredentials` wrapping `TSPasswordCreds`. [MS-CSSP] §2.2.1.2.
    ///
    /// The strings are UTF-16LE inside OCTET STRINGs, which is what Windows
    /// expects and is not obvious from the ASN.1 alone.
    fn credentials_blob(&self) -> der::ZeroizingBytes {
        let mut password_utf16 = match core::str::from_utf8(&self.password.0) {
            Ok(text) => crypto::utf16le(text),
            Err(_) => self.password.0.clone(),
        };

        let mut inner = Vec::new();
        inner.extend_from_slice(&der::tagged(
            0,
            &der::octet_string(&crypto::utf16le(&self.domain)),
        ));
        inner.extend_from_slice(&der::tagged(
            1,
            &der::octet_string(&crypto::utf16le(&self.username)),
        ));
        inner.extend_from_slice(&der::tagged(2, &der::octet_string(&password_utf16)));
        password_utf16.zeroize();

        let mut password_creds = der::sequence(&inner);
        inner.zeroize();

        let mut body = Vec::new();
        body.extend_from_slice(&der::tagged(0, &der::integer(CRED_TYPE_PASSWORD)));
        body.extend_from_slice(&der::tagged(1, &der::octet_string(&password_creds)));
        password_creds.zeroize();

        let out = der::zeroizing(der::sequence(&body));
        body.zeroize();
        out
    }
}

/// Checks the Early User Authorization Result PDU. MS-RDPBCGR §2.2.10.2.
///
/// # Errors
///
/// [`ProtocolError::AuthRejected`] for anything that is not `AUTHZ_SUCCESS` —
/// which in practice is `AUTHZ_ACCESS_DENIED`, the server saying the account
/// authenticated but is not permitted to log on here. That distinction matters
/// to the user and is lost if it is reported as a handshake failure.
pub fn check_early_user_auth_result(bytes: &[u8]) -> Result<(), ProtocolError> {
    let value = bytes
        .get(..EARLY_USER_AUTH_RESULT_BYTES)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| violation("the server sent a truncated early user authorisation result"))?;
    if value == AUTHZ_SUCCESS {
        Ok(())
    } else {
        tracing::debug!(
            result = format_args!("{value:#010x}"),
            "the server refused the authenticated user"
        );
        Err(auth_rejected())
    }
}

/// `SHA256(label || nonce || publicKey)`. [MS-CSSP] §3.1.5.
fn binding_hash(label: &[u8], nonce: &[u8; NONCE_BYTES], public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(nonce);
    hasher.update(public_key);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// [MS-CSSP] §2.2.1.
///
/// `negoTokens` is a `SEQUENCE OF` in the ASN.1, but neither Windows nor any
/// client puts more than one token in it, so exactly one is carried here and
/// a list with more is refused rather than silently reduced to its first
/// element.
#[derive(Debug, Default)]
struct TsRequest {
    version: u32,
    nego_token: Option<Vec<u8>>,
    auth_info: Option<Vec<u8>>,
    pub_key_auth: Option<Vec<u8>>,
    error_code: Option<u32>,
    client_nonce: Option<Vec<u8>>,
}

impl TsRequest {
    const fn empty() -> Self {
        Self {
            version: CLIENT_VERSION,
            nego_token: None,
            auth_info: None,
            pub_key_auth: None,
            error_code: None,
            client_nonce: None,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&der::tagged(0, &der::integer(self.version)));
        if let Some(token) = &self.nego_token {
            // NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
            let entry = der::sequence(&der::tagged(0, &der::octet_string(token)));
            body.extend_from_slice(&der::tagged(1, &der::sequence(&entry)));
        }
        if let Some(info) = &self.auth_info {
            body.extend_from_slice(&der::tagged(2, &der::octet_string(info)));
        }
        if let Some(auth) = &self.pub_key_auth {
            body.extend_from_slice(&der::tagged(3, &der::octet_string(auth)));
        }
        if let Some(nonce) = &self.client_nonce {
            body.extend_from_slice(&der::tagged(5, &der::octet_string(nonce)));
        }
        der::sequence(&body)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut outer = Reader::new(bytes);
        let body = outer.expect(TAG_SEQUENCE)?;
        let mut fields = Reader::new(body);
        let mut request = Self::empty();
        let mut seen_version = false;

        while !fields.is_empty() {
            let (tag, content) = fields.read_any()?;
            match tag {
                t if t == context(0) => {
                    request.version = der::read_u32(Reader::new(content).expect(TAG_INTEGER)?)?;
                    seen_version = true;
                }
                t if t == context(1) => {
                    let list = Reader::new(content).expect(TAG_SEQUENCE)?;
                    let mut entries = Reader::new(list);
                    let entry = entries.expect(TAG_SEQUENCE)?;
                    let token = Reader::new(entry).expect(context(0))?;
                    request.nego_token =
                        Some(Reader::new(token).expect(TAG_OCTET_STRING)?.to_vec());
                    if !entries.is_empty() {
                        return Err(violation("the server sent more than one CredSSP token"));
                    }
                }
                t if t == context(2) => {
                    request.auth_info =
                        Some(Reader::new(content).expect(TAG_OCTET_STRING)?.to_vec());
                }
                t if t == context(3) => {
                    request.pub_key_auth =
                        Some(Reader::new(content).expect(TAG_OCTET_STRING)?.to_vec());
                }
                t if t == context(4) => {
                    request.error_code =
                        Some(der::read_u32(Reader::new(content).expect(TAG_INTEGER)?)?);
                }
                t if t == context(5) => {
                    request.client_nonce =
                        Some(Reader::new(content).expect(TAG_OCTET_STRING)?.to_vec());
                }
                // An unknown field from a newer CredSSP is skipped rather than
                // refused: the version negotiation is what governs behaviour,
                // and refusing an additive field would break against a future
                // Windows for no benefit.
                _ => {}
            }
        }

        if !seen_version {
            return Err(violation("the server's CredSSP message carried no version"));
        }
        Ok(request)
    }
}

/// Reads the length of a `TSRequest` from its first few bytes.
///
/// The transport is a byte stream, so the caller has to know how much to read
/// before it can parse anything. Returns `None` while the header is
/// incomplete, and an error only for a length that cannot be a `TSRequest` at
/// all — the same shape as `ironrdp_pdu::find_size`.
///
/// # Errors
///
/// [`ProtocolError::ProtocolViolation`] if the outer tag is not a SEQUENCE or
/// the length uses a form DER does not permit.
pub fn ts_request_length(bytes: &[u8]) -> Result<Option<usize>, ProtocolError> {
    let Some(&tag) = bytes.first() else {
        return Ok(None);
    };
    if tag != TAG_SEQUENCE {
        return Err(violation("the server did not send a CredSSP TSRequest"));
    }
    let Some(&first) = bytes.get(1) else {
        return Ok(None);
    };
    if first < 0x80 {
        return Ok(Some(2 + usize::from(first)));
    }
    if first == 0x80 {
        return Err(violation("the server used an indefinite DER length"));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 {
        return Err(violation("the server sent an implausible CredSSP length"));
    }
    let Some(slice) = bytes.get(2..2 + count) else {
        return Ok(None);
    };
    let mut len = 0usize;
    for byte in slice {
        len = (len << 8) | usize::from(*byte);
    }
    Ok(Some(2 + count + len))
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

    fn client() -> CredsspClient {
        CredsspClient::new(
            "ada",
            "CORP",
            "workstation",
            "TERMSRV/ts-01.corp.example",
            b"hunter2",
            b"a server public key".to_vec(),
            [0x5a; NONCE_BYTES],
        )
    }

    /// A stand-in for the far end: it speaks the same NTLM, so it can be
    /// driven through the whole exchange. It is *not* a conformance oracle —
    /// only MS-NLMP §4.2.4's published vectors are, and they are checked in
    /// [`ntlm`] — but it does prove the sequence, the framing and the public
    /// key check hold together.
    struct Server {
        challenge: Vec<u8>,
    }

    fn ntlm_challenge_message(target_info: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(b"NTLMSSP\0");
        message.extend_from_slice(&2u32.to_le_bytes());
        message.extend_from_slice(&[0u8; 8]);
        // Every flag the client offered, so nothing is negotiated away.
        message.extend_from_slice(&0xe288_8235u32.to_le_bytes());
        message.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        message.extend_from_slice(&[0u8; 8]);
        let len = u16::try_from(target_info.len()).unwrap();
        message.extend_from_slice(&len.to_le_bytes());
        message.extend_from_slice(&len.to_le_bytes());
        message.extend_from_slice(&56u32.to_le_bytes());
        message.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 0x0f]);
        message.extend_from_slice(target_info);
        message
    }

    fn target_info() -> Vec<u8> {
        // MsvAvNbDomainName, MsvAvNbComputerName, MsvAvTimestamp, EOL.
        let mut info = Vec::new();
        for (id, value) in [
            (0x0002u16, crypto::utf16le("CORP")),
            (0x0001, crypto::utf16le("TS-01")),
            (0x0007, 133_000_000_000_000_000u64.to_le_bytes().to_vec()),
        ] {
            info.extend_from_slice(&id.to_le_bytes());
            info.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
            info.extend_from_slice(&value);
        }
        info.extend_from_slice(&0u16.to_le_bytes());
        info.extend_from_slice(&0u16.to_le_bytes());
        info
    }

    impl Server {
        fn new() -> Self {
            Self {
                challenge: ntlm_challenge_message(&target_info()),
            }
        }

        fn challenge_request(&self) -> Vec<u8> {
            TsRequest {
                version: 6,
                nego_token: Some(self.challenge.clone()),
                ..TsRequest::empty()
            }
            .encode()
        }
    }

    #[test]
    fn the_first_message_is_a_well_formed_ts_request_carrying_ntlm() {
        let mut client = client();
        let first = client.start();
        let decoded = TsRequest::decode(&first).unwrap();
        assert_eq!(decoded.version, CLIENT_VERSION);
        let token = decoded.nego_token.unwrap();
        assert_eq!(&token[..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes(token[8..12].try_into().unwrap()), 1);
        // Nothing else may travel in the first message: the credentials do
        // not exist on the wire until the server has proved its certificate.
        assert!(decoded.auth_info.is_none());
        assert!(decoded.pub_key_auth.is_none());
    }

    #[test]
    fn the_second_message_carries_the_nonce_and_the_sealed_binding_hash() {
        let mut client = client();
        let _ = client.start();
        let server = Server::new();

        let Step::SendAndContinue(second) = client
            .step(&server.challenge_request(), [0xaa; 8], [0x55; 16], 0)
            .unwrap()
        else {
            panic!("the exchange finished a message early");
        };

        let decoded = TsRequest::decode(&second).unwrap();
        assert_eq!(decoded.client_nonce.as_deref(), Some(&[0x5a; 32][..]));
        let sealed = decoded.pub_key_auth.unwrap();
        // Signature plus the SHA-256 of the binding hash.
        assert_eq!(sealed.len(), ntlm::SIGNATURE_BYTES + 32);
        // Still no credentials.
        assert!(decoded.auth_info.is_none());
    }

    /// The property this module exists for. A server that returns the wrong
    /// public key hash is a server that did not hold the certificate's private
    /// key, and the password must never reach it.
    #[test]
    fn a_server_that_cannot_prove_its_certificate_never_receives_the_password() {
        let mut client = client();
        let _ = client.start();
        let server = Server::new();
        let _ = client
            .step(&server.challenge_request(), [0xaa; 8], [0x55; 16], 0)
            .unwrap();

        // Something plausible in the right shape, sealed by nobody.
        let forged = TsRequest {
            version: 6,
            pub_key_auth: Some(vec![0u8; ntlm::SIGNATURE_BYTES + 32]),
            ..TsRequest::empty()
        }
        .encode();

        let error = client.step(&forged, [0xaa; 8], [0x55; 16], 0).unwrap_err();
        // The signature check fires first, which is the earlier and stronger
        // of the two guards; either outcome must refuse.
        assert!(
            matches!(error, ProtocolError::ProtocolViolation { .. })
                || matches!(error, ProtocolError::CertificateUntrusted { .. }),
            "{error:?}"
        );
        assert!(!client.is_done());
    }

    #[test]
    fn a_server_that_omits_the_public_key_entirely_is_refused() {
        let mut client = client();
        let _ = client.start();
        let server = Server::new();
        let _ = client
            .step(&server.challenge_request(), [0xaa; 8], [0x55; 16], 0)
            .unwrap();

        let empty = TsRequest {
            version: 6,
            ..TsRequest::empty()
        }
        .encode();
        assert!(client.step(&empty, [0xaa; 8], [0x55; 16], 0).is_err());
    }

    #[test]
    fn an_error_code_from_the_server_is_an_authentication_rejection() {
        // STATUS_LOGON_FAILURE. Reporting it as a handshake failure would put
        // "contact your administrator" on screen where "the password is
        // wrong" belongs.
        let mut client = client();
        let _ = client.start();
        let mut body = Vec::new();
        body.extend_from_slice(&der::tagged(0, &der::integer(6)));
        body.extend_from_slice(&der::tagged(4, &der::integer(0xc000_006d)));
        let message = der::sequence(&body);

        let error = client.step(&message, [0xaa; 8], [0x55; 16], 0).unwrap_err();
        assert!(matches!(error, ProtocolError::AuthRejected { .. }));
        assert_eq!(error.stage(), remoter_proto::Stage::Authenticate);
    }

    #[test]
    fn a_malformed_ts_request_is_refused_at_every_prefix() {
        let mut client = client();
        let _ = client.start();
        let server = Server::new();
        let full = server.challenge_request();
        for cut in 0..full.len() {
            let mut fresh = self::client();
            let _ = fresh.start();
            assert!(
                fresh.step(&full[..cut], [0xaa; 8], [0x55; 16], 0).is_err(),
                "a {cut}-byte TSRequest parsed"
            );
        }
        // And the whole thing still works, so the loop above proved something.
        assert!(client.step(&full, [0xaa; 8], [0x55; 16], 0).is_ok());
    }

    #[test]
    fn the_length_probe_agrees_with_the_encoder() {
        let mut client = client();
        let first = client.start();
        assert_eq!(ts_request_length(&first).unwrap(), Some(first.len()));
        // An incomplete header is "not yet", not an error: the caller reads
        // more bytes and asks again.
        assert_eq!(ts_request_length(&[]).unwrap(), None);
        assert_eq!(ts_request_length(&first[..1]).unwrap(), None);
        // Something that is not a TSRequest at all is an error, so a server
        // answering with rubbish fails immediately rather than after a
        // timeout.
        assert!(ts_request_length(&[0x05, 0x00]).is_err());
    }

    #[test]
    fn a_long_ts_request_round_trips_through_the_length_probe() {
        // A real AUTHENTICATE_MESSAGE plus target info comfortably exceeds the
        // 127-byte short form, which is where a hand-written length encoder
        // usually breaks.
        let request = TsRequest {
            version: 6,
            nego_token: Some(vec![0x41; 4096]),
            ..TsRequest::empty()
        }
        .encode();
        assert_eq!(ts_request_length(&request).unwrap(), Some(request.len()));
        assert_eq!(
            TsRequest::decode(&request)
                .unwrap()
                .nego_token
                .unwrap()
                .len(),
            4096
        );
    }

    #[test]
    fn an_early_user_authorisation_denial_is_an_authentication_rejection() {
        assert!(check_early_user_auth_result(&0u32.to_le_bytes()).is_ok());
        // AUTHZ_ACCESS_DENIED: the account is real and may not log on here.
        let error = check_early_user_auth_result(&5u32.to_le_bytes()).unwrap_err();
        assert!(matches!(error, ProtocolError::AuthRejected { .. }));
        assert!(check_early_user_auth_result(&[0u8; 3]).is_err());
    }

    #[test]
    fn nothing_in_the_exchange_debug_prints_the_password() {
        let mut client = client();
        let _ = client.start();
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");

        // And the credentials blob, which literally contains the password,
        // prints only its length.
        let blob = client.credentials_blob();
        assert!(!format!("{blob:?}").contains("hunter2"));
        // The password really is in there, in UTF-16LE — otherwise the test
        // above would be checking nothing.
        let needle = crypto::utf16le("hunter2");
        assert!(
            blob.as_slice().windows(needle.len()).any(|w| w == needle),
            "the credentials blob does not carry the password"
        );
    }

    #[test]
    fn the_binding_hash_differs_by_direction_and_by_nonce() {
        // If the two labels were interchangeable, a server could replay the
        // client's own assertion back at it and pass the check.
        let key = b"a public key";
        let nonce = [0x11u8; NONCE_BYTES];
        assert_ne!(
            binding_hash(CLIENT_BINDING_LABEL, &nonce, key),
            binding_hash(SERVER_BINDING_LABEL, &nonce, key)
        );
        assert_ne!(
            binding_hash(CLIENT_BINDING_LABEL, &nonce, key),
            binding_hash(CLIENT_BINDING_LABEL, &[0x22; NONCE_BYTES], key)
        );
    }
}
