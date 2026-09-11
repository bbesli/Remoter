//! NTLM, as CredSSP uses it. [MS-NLMP].
//!
//! Only the client half, only NTLMv2, and only with extended session security
//! — which is what a Windows host offers and what MS-CSSP §3.1.5 needs a
//! `GSS_WrapEx` out of. LM authentication, NTLMv1, datagram mode, anonymous
//! authentication and the "negotiate local call" shortcut are all absent, and
//! their absence is deliberate: every one of them is either broken or is a
//! path a downgrade attack would like this code to have.
//!
//! # Why this is written out rather than delegated
//!
//! `sspi` is the crate IronRDP itself uses, and it cannot be added to this
//! workspace: `sspi` 0.21 pins `curve25519-dalek =5.0.0-rc.1` on Apple targets
//! while `russh` 0.63 requires the released `^5`, and cargo resolves
//! target-specific dependencies for every target in the graph, so adding it
//! fails every command in the repository rather than only this crate — the
//! same class of blocker `Cargo.toml` records for `ironrdp-connector`.
//!
//! # What is checked, given there is no server here
//!
//! The tests below reproduce [MS-NLMP] §4.2.4, "NTLMv2 Authentication", which
//! publishes the exact intermediate values for a fixed password, user, domain,
//! server challenge and client challenge: `NTOWFv2`, the session base key, the
//! NTLMv2 response and the sealed message with its signature. Matching those
//! byte for byte is the strongest evidence available without a Windows host,
//! and it is what CLAUDE.md §5 asks of a cryptographic primitive.
//!
//! [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/

use remoter_proto::ProtocolError;
use zeroize::{Zeroize, Zeroizing};

use super::crypto::{Rc4, hmac_md5, md4, md5, utf16le};
use crate::error::violation;

/// `NTLMSSP\0` — the signature every message starts with. [MS-NLMP] §2.2.1.1.
const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// [MS-NLMP] §2.2.1.1, NEGOTIATE_MESSAGE.
const MESSAGE_NEGOTIATE: u32 = 1;
/// [MS-NLMP] §2.2.1.2, CHALLENGE_MESSAGE.
const MESSAGE_CHALLENGE: u32 = 2;
/// [MS-NLMP] §2.2.1.3, AUTHENTICATE_MESSAGE.
const MESSAGE_AUTHENTICATE: u32 = 3;

// [MS-NLMP] §2.2.2.5, NEGOTIATE. Only the bits this client sets or reads.
/// Strings are UTF-16LE. Always set; OEM encoding is not implemented.
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
/// Ask the server to name itself in the CHALLENGE.
const REQUEST_TARGET: u32 = 0x0000_0004;
/// Message integrity is requested.
const NEGOTIATE_SIGN: u32 = 0x0000_0010;
/// Message confidentiality is requested. CredSSP requires it: `pubKeyAuth` and
/// `authInfo` are sealed, not merely signed.
const NEGOTIATE_SEAL: u32 = 0x0000_0020;
/// NTLM v1 session security is available. Set alongside the extended flag
/// because a server keyed only on this bit will not otherwise talk to us.
const NEGOTIATE_NTLM: u32 = 0x0000_0200;
/// Sign even when neither SIGN nor SEAL is negotiated.
const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
/// NTLM2 session security — the mode NTLMv2 signing and sealing is defined
/// in. Required: without it [MS-NLMP] §3.4.4.1's weaker CRC32 signature
/// applies, and CredSSP is not defined over it.
const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
/// The CHALLENGE carries an AV\_PAIR list.
const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
/// A Version field is present. [MS-NLMP] §2.2.2.10.
const NEGOTIATE_VERSION: u32 = 0x0200_0000;
/// 128-bit session security.
const NEGOTIATE_128: u32 = 0x2000_0000;
/// The session key is exchanged rather than used directly.
const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
/// 56-bit session security. Set beside [`NEGOTIATE_128`] as every real client
/// does; the server picks.
const NEGOTIATE_56: u32 = 0x8000_0000;

/// What this client offers in the NEGOTIATE_MESSAGE.
const CLIENT_FLAGS: u32 = NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_SIGN
    | NEGOTIATE_SEAL
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NEGOTIATE_TARGET_INFO
    | NEGOTIATE_VERSION
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

// [MS-NLMP] §2.2.2.1, AV_PAIR AvId values this client reads or writes.
/// End of the list.
const AV_EOL: u16 = 0x0000;
/// A `FILETIME` the server chose. Its presence obliges the client to send a
/// MIC ([MS-NLMP] §3.1.5.1.2).
const AV_TIMESTAMP: u16 = 0x0007;
/// A 32-bit flag field; bit 1 says a MIC is present.
const AV_FLAGS: u16 = 0x0006;
/// The service principal name the client believes it is talking to.
const AV_TARGET_NAME: u16 = 0x0009;
/// The channel binding hash. All zeroes means "no channel binding", which is
/// what a client sends when Extended Protection is not in use.
const AV_CHANNEL_BINDINGS: u16 = 0x000a;
/// `MsvAvFlags` bit 1: the AUTHENTICATE_MESSAGE carries a MIC.
const AV_FLAG_MIC_PRESENT: u32 = 0x0000_0002;

/// Bytes in a `NTLMSSP_MESSAGE_SIGNATURE`. [MS-NLMP] §2.2.2.9.
pub const SIGNATURE_BYTES: usize = 16;

/// Bytes in the AUTHENTICATE_MESSAGE header, before the payload.
///
/// Signature 8, MessageType 4, six 8-byte field descriptors, NegotiateFlags 4,
/// Version 8, MIC 16.
const AUTHENTICATE_HEADER_BYTES: usize = 88;

/// Byte offset of the MIC within an AUTHENTICATE_MESSAGE. [MS-NLMP] §2.2.1.3.
const MIC_OFFSET: usize = 72;

/// A client-side NTLM exchange.
///
/// Holds `NTOWFv2` and never the password: the password is consumed by
/// [`NtlmClient::new`] and the 16-byte response key is what survives, in a
/// buffer that zeroes itself. That is not merely tidy — a `Debug` on this
/// struct is one refactor away from a log line, and there has to be nothing
/// there to print.
pub struct NtlmClient {
    response_key: Zeroizing<[u8; 16]>,
    username: String,
    domain: String,
    workstation: String,
    /// The service principal name, `TERMSRV/<host>`, echoed back in the
    /// `MsvAvTargetName` pair so a server with SPN checking on accepts us.
    spn: String,
    /// The NEGOTIATE_MESSAGE exactly as sent. The MIC is computed over all
    /// three messages ([MS-NLMP] §3.1.5.1.2), so the first one has to survive
    /// until the third is built.
    negotiate: Vec<u8>,
}

impl core::fmt::Debug for NtlmClient {
    /// Hand-written, and it stays hand-written: `response_key` is the
    /// password's hash and is a password equivalent — anyone holding it can
    /// authenticate as this user.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NtlmClient")
            .field("username", &"<redacted>")
            .field("spn", &self.spn)
            .finish_non_exhaustive()
    }
}

impl NtlmClient {
    /// A client for `username`@`domain` with `password`.
    ///
    /// `password` is the UTF-8 password as typed; it is converted to UTF-16LE,
    /// hashed, and the intermediate buffers are zeroized before this returns.
    /// `spn` is the service principal name of the target, conventionally
    /// `TERMSRV/<hostname>`.
    #[must_use]
    pub fn new(
        username: &str,
        domain: &str,
        workstation: &str,
        spn: &str,
        password: &[u8],
    ) -> Self {
        Self {
            response_key: Zeroizing::new(ntowf_v2(username, domain, password)),
            username: username.to_owned(),
            domain: domain.to_owned(),
            workstation: workstation.to_owned(),
            spn: spn.to_owned(),
            negotiate: Vec::new(),
        }
    }

    /// Builds the NEGOTIATE_MESSAGE. [MS-NLMP] §2.2.1.1.
    ///
    /// The domain and workstation fields are left empty. They are only
    /// meaningful when `NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED` is set, which
    /// this client does not set, and a server that reads them anyway learns
    /// the local machine name for nothing.
    pub fn negotiate(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&MESSAGE_NEGOTIATE.to_le_bytes());
        out.extend_from_slice(&CLIENT_FLAGS.to_le_bytes());
        // DomainNameFields and WorkstationFields: empty, offset past the
        // header as the specification requires even for an empty field.
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&version_field());
        self.negotiate.clone_from(&out);
        out
    }

    /// Consumes the CHALLENGE_MESSAGE and produces the AUTHENTICATE_MESSAGE
    /// and the session security state that follows from it.
    ///
    /// `client_challenge` and `exported_session_key` are supplied rather than
    /// generated so the caller owns the randomness — and so [MS-NLMP] §4.2.4's
    /// fixed vectors can be reproduced exactly. `now_filetime` is used only
    /// when the server sent no timestamp of its own.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ProtocolViolation`] if the CHALLENGE_MESSAGE is
    /// malformed, truncated, or points a field outside itself. Every offset in
    /// it comes off the network from a host that may already be compromised,
    /// so every one is bounds-checked before it is followed.
    pub fn authenticate(
        &self,
        challenge: &[u8],
        client_challenge: [u8; 8],
        exported_session_key: [u8; 16],
        now_filetime: u64,
    ) -> Result<(Vec<u8>, NtlmSecurity), ProtocolError> {
        let parsed = ChallengeMessage::parse(challenge)?;

        // [MS-NLMP] §3.1.5.1.2: the client's flags are the ones it offered,
        // narrowed to what the server will actually do. Three are forced
        // rather than negotiated, because this client cannot operate without
        // them and a server that omits one is a server we must not silently
        // downgrade to.
        let negotiated = (CLIENT_FLAGS & parsed.flags)
            | NEGOTIATE_UNICODE
            | NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NEGOTIATE_NTLM;

        let timestamp = parsed.timestamp.unwrap_or(now_filetime);
        let target_info = self.build_target_info(&parsed, parsed.timestamp.is_some());

        // [MS-NLMP] §3.3.2, the `temp` blob the NTLMv2 response is computed
        // over: Responserversion(1) HiResponserversion(1) Z(6) Time(8)
        // ClientChallenge(8) Z(4) ServerName Z(4).
        let mut temp = Vec::with_capacity(32 + target_info.len());
        temp.push(0x01);
        temp.push(0x01);
        temp.extend_from_slice(&[0u8; 6]);
        temp.extend_from_slice(&timestamp.to_le_bytes());
        temp.extend_from_slice(&client_challenge);
        temp.extend_from_slice(&[0u8; 4]);
        temp.extend_from_slice(&target_info);
        temp.extend_from_slice(&[0u8; 4]);

        // NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || temp).
        let mut proof_input = Vec::with_capacity(8 + temp.len());
        proof_input.extend_from_slice(&parsed.server_challenge);
        proof_input.extend_from_slice(&temp);
        let nt_proof = hmac_md5(&*self.response_key, &proof_input);
        proof_input.zeroize();

        let mut nt_response = Vec::with_capacity(16 + temp.len());
        nt_response.extend_from_slice(&nt_proof);
        nt_response.extend_from_slice(&temp);

        // SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr); for NTLMv2 the
        // key exchange key is the session base key unchanged ([MS-NLMP] §3.4.5.1).
        let key_exchange_key = Zeroizing::new(hmac_md5(&*self.response_key, &nt_proof));

        // [MS-NLMP] §3.1.5.1.2: with NTLMSSP_NEGOTIATE_KEY_EXCH the client
        // chooses the session key and ships it sealed under the key exchange
        // key; without it the key exchange key *is* the session key.
        let (session_key, encrypted_session_key) = if negotiated & NEGOTIATE_KEY_EXCH != 0 {
            let mut rc4 = Rc4::new(&*key_exchange_key);
            let sealed = rc4.applied(&exported_session_key);
            (Zeroizing::new(exported_session_key), sealed)
        } else {
            (Zeroizing::new(*key_exchange_key), Vec::new())
        };

        // [MS-NLMP] §3.3.2: with a timestamp in the AV pairs the LM response
        // is Z(24). Sending a real one would add nothing and would expose the
        // LM hash of the password to an offline attack.
        let lm_response = [0u8; 24];

        let domain = utf16le(&self.domain);
        let username = utf16le(&self.username);
        let workstation = utf16le(&self.workstation);

        let mut message = Vec::with_capacity(AUTHENTICATE_HEADER_BYTES + nt_response.len() + 128);
        message.extend_from_slice(SIGNATURE);
        message.extend_from_slice(&MESSAGE_AUTHENTICATE.to_le_bytes());

        // The payload is laid out in the order the fields are declared, which
        // keeps the offsets trivially checkable against the header.
        let mut offset = AUTHENTICATE_HEADER_BYTES;
        let mut payload = Vec::new();
        let mut field = |bytes: &[u8], message: &mut Vec<u8>| {
            // A field longer than 64 KiB cannot be described by the 16-bit
            // length, and nothing here can legitimately be that long.
            let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
            message.extend_from_slice(&len.to_le_bytes());
            message.extend_from_slice(&len.to_le_bytes());
            let start = u32::try_from(offset).unwrap_or(u32::MAX);
            message.extend_from_slice(&start.to_le_bytes());
            payload.extend_from_slice(bytes);
            offset += bytes.len();
        };

        field(&lm_response, &mut message);
        field(&nt_response, &mut message);
        field(&domain, &mut message);
        field(&username, &mut message);
        field(&workstation, &mut message);
        field(&encrypted_session_key, &mut message);

        message.extend_from_slice(&negotiated.to_le_bytes());
        message.extend_from_slice(&version_field());
        // The MIC is written over these zeroes once the whole message exists;
        // it is computed with the field zeroed, which is why it is reserved
        // rather than appended.
        message.extend_from_slice(&[0u8; SIGNATURE_BYTES]);
        message.extend_from_slice(&payload);

        // MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE ||
        // AUTHENTICATE-with-MIC-zeroed). [MS-NLMP] §3.1.5.1.2.
        let mut mic_input =
            Vec::with_capacity(self.negotiate.len() + challenge.len() + message.len());
        mic_input.extend_from_slice(&self.negotiate);
        mic_input.extend_from_slice(challenge);
        mic_input.extend_from_slice(&message);
        let mic = hmac_md5(&*session_key, &mic_input);
        mic_input.zeroize();
        if let Some(slot) = message.get_mut(MIC_OFFSET..MIC_OFFSET + SIGNATURE_BYTES) {
            slot.copy_from_slice(&mic);
        }

        let security = NtlmSecurity::derive(session_key, negotiated);
        Ok((message, security))
    }

    /// The AV\_PAIR list the NTLMv2 response is computed over.
    ///
    /// [MS-NLMP] §3.1.5.1.2: the server's own list, with `MsvAvFlags` bit 1
    /// set to declare the MIC, and with the channel binding and target name
    /// the client is asserting. The channel binding is sixteen zero bytes,
    /// which is the encoding for "no binding" — Extended Protection for
    /// Authentication is off on an RDP host unless an administrator turns it
    /// on, and asserting a binding we did not compute would be worse than
    /// asserting none.
    fn build_target_info(&self, challenge: &ChallengeMessage, mic: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(challenge.target_info.len() + 64);
        let mut wrote_flags = false;
        for (id, value) in &challenge.av_pairs {
            if *id == AV_FLAGS && mic {
                let existing = value
                    .get(..4)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map_or(0, u32::from_le_bytes);
                push_av(
                    &mut out,
                    AV_FLAGS,
                    &(existing | AV_FLAG_MIC_PRESENT).to_le_bytes(),
                );
                wrote_flags = true;
            } else {
                push_av(&mut out, *id, value);
            }
        }
        if mic && !wrote_flags {
            push_av(&mut out, AV_FLAGS, &AV_FLAG_MIC_PRESENT.to_le_bytes());
        }
        push_av(&mut out, AV_CHANNEL_BINDINGS, &[0u8; 16]);
        push_av(&mut out, AV_TARGET_NAME, &utf16le(&self.spn));
        push_av(&mut out, AV_EOL, &[]);
        out
    }
}

/// Appends one AV\_PAIR. [MS-NLMP] §2.2.2.1.
fn push_av(out: &mut Vec<u8>, id: u16, value: &[u8]) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_le_bytes());
    out.extend_from_slice(value);
}

/// `NTOWFv2(Passwd, User, UserDom)` — [MS-NLMP] §3.3.2.
///
/// `HMAC_MD5(MD4(UNICODE(Passwd)), UNICODE(Uppercase(User) + UserDom))`. The
/// user name is upper-cased and the domain is **not**, which is easy to get
/// backwards and produces an implementation that works for lowercase-only
/// accounts and mysteriously fails for the rest.
fn ntowf_v2(username: &str, domain: &str, password: &[u8]) -> [u8; 16] {
    // The password reaches this function as UTF-8 bytes borrowed from the
    // vault. Both the UTF-16LE copy and the MD4 digest of it are password
    // equivalents and are zeroized before this returns.
    let mut wide = Zeroizing::new(Vec::with_capacity(password.len() * 2));
    match core::str::from_utf8(password) {
        Ok(text) => wide.extend_from_slice(&utf16le(text)),
        // A password that is not valid UTF-8 cannot have come from a text
        // field. Hashing the bytes as if they were UTF-16LE already is the
        // only reading left, and it at least fails deterministically rather
        // than authenticating as somebody else.
        Err(_) => wide.extend_from_slice(password),
    }
    let key = Zeroizing::new(md4(&wide));
    let identity = utf16le(&format!("{}{}", username.to_uppercase(), domain));
    hmac_md5(&*key, &identity)
}

/// The Version field. [MS-NLMP] §2.2.2.10.
///
/// Windows 10 build 19041 with NTLM revision 15, which is what a current
/// client reports. It is advisory: no server makes a decision on it, and a
/// value that is obviously synthetic invites one to start.
const fn version_field() -> [u8; 8] {
    let build = 19041u16.to_le_bytes();
    [10, 0, build[0], build[1], 0, 0, 0, 0x0f]
}

/// The parts of a CHALLENGE_MESSAGE this client uses. [MS-NLMP] §2.2.1.2.
struct ChallengeMessage {
    flags: u32,
    server_challenge: [u8; 8],
    target_info: Vec<u8>,
    av_pairs: Vec<(u16, Vec<u8>)>,
    timestamp: Option<u64>,
}

impl ChallengeMessage {
    /// Parses one, checking every length and offset against the buffer.
    ///
    /// This is attacker-controlled input by definition — the server may
    /// already be compromised, which is the whole premise of ADR-0003 — so
    /// nothing here indexes without checking, and a malformed message is a
    /// refusal rather than a panic.
    fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bad = || violation("the server sent a malformed NTLM challenge");

        if bytes.len() < 48 || bytes.get(..8) != Some(SIGNATURE.as_slice()) {
            return Err(bad());
        }
        if read_u32(bytes, 8).ok_or_else(bad)? != MESSAGE_CHALLENGE {
            return Err(bad());
        }

        let flags = read_u32(bytes, 20).ok_or_else(bad)?;
        let server_challenge: [u8; 8] = bytes
            .get(24..32)
            .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
            .ok_or_else(bad)?;

        // TargetInfoFields at offset 40: Len, MaxLen, BufferOffset.
        let info_len = usize::from(read_u16(bytes, 40).ok_or_else(bad)?);
        let info_offset =
            usize::try_from(read_u32(bytes, 44).ok_or_else(bad)?).map_err(|_| bad())?;
        let target_info = if info_len == 0 {
            Vec::new()
        } else {
            let end = info_offset.checked_add(info_len).ok_or_else(bad)?;
            bytes.get(info_offset..end).ok_or_else(bad)?.to_vec()
        };

        let av_pairs = parse_av_pairs(&target_info)?;
        let timestamp = av_pairs.iter().find_map(|(id, value)| {
            (*id == AV_TIMESTAMP)
                .then(|| value.get(..8).and_then(|b| <[u8; 8]>::try_from(b).ok()))
                .flatten()
                .map(u64::from_le_bytes)
        });

        Ok(Self {
            flags,
            server_challenge,
            target_info,
            av_pairs,
            timestamp,
        })
    }
}

/// Splits an AV\_PAIR list. [MS-NLMP] §2.2.2.1.
///
/// The terminating `MsvAvEOL` is dropped: the client rebuilds the list with
/// its own additions and appends a fresh terminator, and keeping the old one
/// would bury the additions behind it where no server would read them.
fn parse_av_pairs(bytes: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, ProtocolError> {
    let bad = || violation("the server sent a malformed NTLM target info list");
    let mut pairs = Vec::new();
    let mut cursor = 0usize;
    while cursor + 4 <= bytes.len() {
        let id = read_u16(bytes, cursor).ok_or_else(bad)?;
        let len = usize::from(read_u16(bytes, cursor + 2).ok_or_else(bad)?);
        cursor += 4;
        if id == AV_EOL {
            return Ok(pairs);
        }
        let end = cursor.checked_add(len).ok_or_else(bad)?;
        let value = bytes.get(cursor..end).ok_or_else(bad)?;
        pairs.push((id, value.to_vec()));
        cursor = end;
    }
    // A list that runs off the end without a terminator is malformed. It is
    // refused rather than salvaged: the AV pairs are what the NTLMv2 response
    // is computed over, so guessing at them produces a response the server
    // rejects for a reason nobody can see.
    if bytes.is_empty() {
        Ok(pairs)
    } else {
        Err(bad())
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.checked_add(2)?)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .map(u16::from_le_bytes)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_le_bytes)
}

/// The signing and sealing state an authenticated NTLM exchange leaves behind.
///
/// [MS-NLMP] §3.4: two RC4 handles and two signing keys, one pair per
/// direction, plus a sequence number per direction. The handles are stateful
/// and the state matters — see [`Rc4`].
pub struct NtlmSecurity {
    client_seal: Rc4,
    server_seal: Rc4,
    client_sign: Zeroizing<[u8; 16]>,
    server_sign: Zeroizing<[u8; 16]>,
    client_seq: u32,
    server_seq: u32,
    key_exchange: bool,
}

impl core::fmt::Debug for NtlmSecurity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NtlmSecurity")
            .field("client_seq", &self.client_seq)
            .field("server_seq", &self.server_seq)
            .finish_non_exhaustive()
    }
}

impl NtlmSecurity {
    /// Derives the four keys from the exported session key.
    ///
    /// [MS-NLMP] §3.4.5.2 `SIGNKEY` and §3.4.5.3 `SEALKEY`. The magic
    /// constants include their terminating NUL — a detail that is easy to drop
    /// and produces four wrong keys with no other symptom.
    ///
    /// **`SIGNKEY` and `SEALKEY` treat the key length differently**, and that
    /// asymmetry is the whole reason `flags` is read here. `SIGNKEY` always
    /// hashes the full sixteen bytes; `SEALKEY` hashes a *prefix* whose length
    /// is the strength the server agreed to:
    ///
    /// | Negotiated | `SealKey` input | Bytes |
    /// |---|---|---|
    /// | `NTLMSSP_NEGOTIATE_128` | `ExportedSessionKey` | 16 |
    /// | else `NTLMSSP_NEGOTIATE_56` | `ExportedSessionKey[0..6]` | 7 |
    /// | else | `ExportedSessionKey[0..4]` | 5 |
    ///
    /// [MS-NLMP]'s `X[0..n]` is inclusive of `n`, which is why the 56-bit row
    /// is seven bytes and not six — §3.4.5.3's own legacy branch concatenates
    /// `ExportedSessionKey[0..6]` with one more byte to make an eight-byte RC4
    /// key, which only adds up on the inclusive reading.
    ///
    /// This used to hash all sixteen bytes on every path and read `flags` only
    /// for `NTLMSSP_NEGOTIATE_KEY_EXCH`, so a server that agreed to 56-bit or
    /// 40-bit session security got four keys it could not use: every sealed
    /// message failed its integrity check, and the session died at the first
    /// `pubKeyAuth` with no way to tell that from an interception.
    ///
    /// The `NegFlg` without `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`
    /// branch of §3.4.5.3 is not implemented and is unreachable:
    /// [`NtlmClient::authenticate`] forces that flag into the negotiated set,
    /// because CredSSP is not defined over §3.4.4.1's weaker signature.
    #[must_use]
    fn derive(session_key: Zeroizing<[u8; 16]>, flags: u32) -> Self {
        let derive_key = |material: &[u8], constant: &[u8]| -> Zeroizing<[u8; 16]> {
            let mut input = Zeroizing::new(Vec::with_capacity(material.len() + constant.len()));
            input.extend_from_slice(material);
            input.extend_from_slice(constant);
            Zeroizing::new(md5(&input))
        };

        // [MS-NLMP] §3.4.5.3, `SEALKEY`. The prefix is whatever strength the
        // server actually agreed to; 128 is checked first because a client
        // offers 128 and 56 together and a server that accepts both means 128.
        let seal_bytes = if flags & NEGOTIATE_128 != 0 {
            16
        } else if flags & NEGOTIATE_56 != 0 {
            7
        } else {
            5
        };
        // `session_key` is 16 bytes and `seal_bytes` is at most 16, so the
        // slice is total; `get` rather than an index because this crate
        // forbids a panicking path outside tests. Borrowed, not copied: the
        // material stays inside the buffer that already zeroes itself.
        let seal_material: &[u8] = session_key.get(..seal_bytes).unwrap_or(&*session_key);

        // [MS-NLMP] §3.4.5.2, `SIGNKEY`: the whole key, at every strength.
        let client_sign = derive_key(
            &*session_key,
            b"session key to client-to-server signing key magic constant\0",
        );
        let server_sign = derive_key(
            &*session_key,
            b"session key to server-to-client signing key magic constant\0",
        );
        let client_seal = derive_key(
            seal_material,
            b"session key to client-to-server sealing key magic constant\0",
        );
        let server_seal = derive_key(
            seal_material,
            b"session key to server-to-client sealing key magic constant\0",
        );

        Self {
            client_seal: Rc4::new(&*client_seal),
            server_seal: Rc4::new(&*server_seal),
            client_sign,
            server_sign,
            client_seq: 0,
            server_seq: 0,
            key_exchange: flags & NEGOTIATE_KEY_EXCH != 0,
        }
    }

    /// The far end of an exchange that agreed to everything this client
    /// offers, for tests that have to play the server.
    ///
    /// `pub(crate)` and test-only so `credssp`'s own tests can drive a full
    /// round trip without `derive` or the flag constants leaving this module.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn matching_peer(session_key: [u8; 16]) -> Self {
        Self::derive(Zeroizing::new(session_key), CLIENT_FLAGS)
    }

    /// [`Self::seal`] in the server-to-client direction, for the same tests.
    ///
    /// The real client never seals as the server, which is why this is not
    /// part of the type's ordinary surface.
    #[cfg(test)]
    pub(crate) fn seal_as_server(&mut self, message: &[u8]) -> Vec<u8> {
        let sealed = self.server_seal.applied(message);
        let signature = Self::sign(
            &mut self.server_seal,
            &self.server_sign,
            self.server_seq,
            message,
            self.key_exchange,
        );
        self.server_seq = self.server_seq.wrapping_add(1);

        let mut out = Vec::with_capacity(SIGNATURE_BYTES + sealed.len());
        out.extend_from_slice(&signature);
        out.extend_from_slice(&sealed);
        out
    }

    /// Seals `message` for the server: the signature, then the ciphertext.
    ///
    /// [MS-NLMP] §3.4.3, `SEAL`. The order is load-bearing: the message is
    /// encrypted **first**, and the signature's checksum is then encrypted
    /// with the keystream that continues from where the message ended. A
    /// handle that restarts between the two produces a signature no server
    /// accepts.
    ///
    /// This is `GSS_WrapEx` as MS-CSSP §3.1.5 uses it, which is why the
    /// signature is prefixed rather than appended.
    pub fn seal(&mut self, message: &[u8]) -> Vec<u8> {
        let sealed = self.client_seal.applied(message);
        let signature = Self::sign(
            &mut self.client_seal,
            &self.client_sign,
            self.client_seq,
            message,
            self.key_exchange,
        );
        self.client_seq = self.client_seq.wrapping_add(1);

        let mut out = Vec::with_capacity(SIGNATURE_BYTES + sealed.len());
        out.extend_from_slice(&signature);
        out.extend_from_slice(&sealed);
        out
    }

    /// Unseals a message from the server and verifies its signature.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ProtocolViolation`] if the message is shorter than a
    /// signature, or if the signature does not verify. A failed signature is
    /// not "corrupt data": it means something between here and the server
    /// altered the bytes, and the session must not continue.
    pub fn unseal(&mut self, message: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let (signature, sealed) = message
            .split_at_checked(SIGNATURE_BYTES)
            .ok_or_else(|| violation("the server sent a CredSSP message with no signature"))?;

        let plaintext = self.server_seal.applied(sealed);
        let expected = Self::sign(
            &mut self.server_seal,
            &self.server_sign,
            self.server_seq,
            &plaintext,
            self.key_exchange,
        );
        self.server_seq = self.server_seq.wrapping_add(1);

        // Constant-time: the comparison is over a MAC, and a timing oracle on
        // one is a forgery oracle.
        use subtle::ConstantTimeEq as _;
        if bool::from(expected.ct_eq(signature)) {
            Ok(plaintext)
        } else {
            Err(violation(
                "a CredSSP message from the server failed its integrity check",
            ))
        }
    }

    /// `MAC` with extended session security. [MS-NLMP] §3.4.4.2.
    ///
    /// Version 1, then eight bytes of `HMAC_MD5(SigningKey, SeqNum || Message)`,
    /// then the sequence number. With `NTLMSSP_NEGOTIATE_KEY_EXCH` the
    /// checksum is additionally encrypted with the sealing handle.
    fn sign(
        seal: &mut Rc4,
        signing_key: &[u8; 16],
        seq: u32,
        message: &[u8],
        key_exchange: bool,
    ) -> [u8; SIGNATURE_BYTES] {
        let mut input = Vec::with_capacity(4 + message.len());
        input.extend_from_slice(&seq.to_le_bytes());
        input.extend_from_slice(message);
        let full = hmac_md5(signing_key, &input);

        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&full[..8]);
        if key_exchange {
            seal.apply(&mut checksum);
        }

        let mut signature = [0u8; SIGNATURE_BYTES];
        signature[..4].copy_from_slice(&1u32.to_le_bytes());
        signature[4..12].copy_from_slice(&checksum);
        signature[12..].copy_from_slice(&seq.to_le_bytes());
        signature
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// [MS-NLMP] §4.2.4.1.1. The single most load-bearing value in this
    /// module: every key below is derived from it, so if this matches the
    /// published vector then MD4, HMAC-MD5, the UTF-16LE encoding and the
    /// upper-casing rule are all correct at once.
    #[test]
    fn ntowf_v2_matches_the_published_vector() {
        // User "User", domain "Domain", password "Password".
        let key = ntowf_v2("User", "Domain", b"Password");
        assert_eq!(hex(&key), "0c868a403bfd7a93a3001ef22ef02e3f");
    }

    /// [MS-NLMP] §4.2.4.1.2, the session base key, computed from §4.2.4.1.3's
    /// target info and the fixed challenges.
    #[test]
    fn the_session_base_key_matches_the_published_vector() {
        let response_key = ntowf_v2("User", "Domain", b"Password");

        // §4.2.4.1.3: the AV_PAIR list, NetBIOS domain "Domain" and NetBIOS
        // computer "Server". The published temp blob carries a zero timestamp.
        let mut target_info = Vec::new();
        push_av(&mut target_info, 0x0002, &utf16le("Domain"));
        push_av(&mut target_info, 0x0001, &utf16le("Server"));
        push_av(&mut target_info, AV_EOL, &[]);

        let mut temp = Vec::new();
        temp.push(0x01);
        temp.push(0x01);
        temp.extend_from_slice(&[0u8; 6]);
        temp.extend_from_slice(&0u64.to_le_bytes());
        temp.extend_from_slice(&[0xaa; 8]);
        temp.extend_from_slice(&[0u8; 4]);
        temp.extend_from_slice(&target_info);
        temp.extend_from_slice(&[0u8; 4]);

        let server_challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut proof_input = Vec::new();
        proof_input.extend_from_slice(&server_challenge);
        proof_input.extend_from_slice(&temp);
        let nt_proof = hmac_md5(&response_key, &proof_input);
        assert_eq!(hex(&nt_proof), "68cd0ab851e51c96aabc927bebef6a1c");

        let session_base_key = hmac_md5(&response_key, &nt_proof);
        assert_eq!(hex(&session_base_key), "8de40ccadbc14a82f15cb0ad0de95ca3");
    }

    fn challenge_message(target_info: &[u8], flags: u32) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(SIGNATURE);
        message.extend_from_slice(&MESSAGE_CHALLENGE.to_le_bytes());
        // TargetNameFields: empty.
        message.extend_from_slice(&[0u8; 8]);
        message.extend_from_slice(&flags.to_le_bytes());
        message.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        message.extend_from_slice(&[0u8; 8]); // Reserved
        let len = u16::try_from(target_info.len()).unwrap();
        message.extend_from_slice(&len.to_le_bytes());
        message.extend_from_slice(&len.to_le_bytes());
        message.extend_from_slice(&56u32.to_le_bytes());
        message.extend_from_slice(&version_field());
        assert_eq!(message.len(), 56);
        message.extend_from_slice(target_info);
        message
    }

    fn server_target_info() -> Vec<u8> {
        let mut info = Vec::new();
        push_av(&mut info, 0x0002, &utf16le("CORP"));
        push_av(&mut info, 0x0001, &utf16le("TS-01"));
        push_av(
            &mut info,
            AV_TIMESTAMP,
            &133_000_000_000_000_000u64.to_le_bytes(),
        );
        push_av(&mut info, AV_EOL, &[]);
        info
    }

    fn client() -> NtlmClient {
        NtlmClient::new(
            "ada",
            "CORP",
            "workstation",
            "TERMSRV/ts-01.corp.example",
            b"hunter2",
        )
    }

    #[test]
    fn the_negotiate_message_is_well_formed_and_asks_for_what_credssp_needs() {
        let mut client = client();
        let message = client.negotiate();
        assert_eq!(message.len(), 40);
        assert_eq!(&message[..8], SIGNATURE);
        assert_eq!(u32::from_le_bytes(message[8..12].try_into().unwrap()), 1);
        let flags = u32::from_le_bytes(message[12..16].try_into().unwrap());
        // Without SEAL there is nothing to put `pubKeyAuth` inside, and
        // without extended session security the signature is the broken CRC32
        // form of §3.4.4.1.
        assert_ne!(flags & NEGOTIATE_SEAL, 0);
        assert_ne!(flags & NEGOTIATE_EXTENDED_SESSIONSECURITY, 0);
        assert_ne!(flags & NEGOTIATE_UNICODE, 0);
    }

    #[test]
    fn an_authenticate_message_carries_a_mic_when_the_server_sent_a_timestamp() {
        let mut client = client();
        let _ = client.negotiate();
        let challenge = challenge_message(&server_target_info(), CLIENT_FLAGS);
        let (message, _) = client
            .authenticate(&challenge, [0xaa; 8], [0x55; 16], 0)
            .unwrap();

        assert_eq!(&message[..8], SIGNATURE);
        assert_eq!(u32::from_le_bytes(message[8..12].try_into().unwrap()), 3);
        // A MIC of all zeroes means it was never written, which a server
        // treats as "no MIC" and, with a timestamp present, as a downgrade.
        let mic = &message[MIC_OFFSET..MIC_OFFSET + 16];
        assert_ne!(mic, [0u8; 16], "the MIC was not written");

        // Every declared field must land inside the message; a server reads
        // these offsets literally.
        for start in [12usize, 20, 28, 36, 44, 52] {
            let len = usize::from(u16::from_le_bytes(
                message[start..start + 2].try_into().unwrap(),
            ));
            let offset = u32::from_le_bytes(message[start + 4..start + 8].try_into().unwrap());
            let offset = usize::try_from(offset).unwrap();
            assert!(
                offset + len <= message.len(),
                "field at {start} runs off the end"
            );
        }
    }

    #[test]
    fn the_target_info_the_response_covers_keeps_the_servers_pairs() {
        let mut client = client();
        let _ = client.negotiate();
        let challenge = challenge_message(&server_target_info(), CLIENT_FLAGS);
        let (message, _) = client
            .authenticate(&challenge, [0xaa; 8], [0x55; 16], 0)
            .unwrap();

        // The NT response is NTProofStr(16) || temp, and temp ends with the
        // AV pair list. The server's NetBIOS name must survive into it: a
        // client that rebuilds the list from scratch produces a response the
        // server computes differently and rejects.
        let nt_len = usize::from(u16::from_le_bytes(message[20..22].try_into().unwrap()));
        let nt_offset =
            usize::try_from(u32::from_le_bytes(message[24..28].try_into().unwrap())).unwrap();
        let nt_response = &message[nt_offset..nt_offset + nt_len];
        let needle = utf16le("TS-01");
        assert!(
            nt_response.windows(needle.len()).any(|w| w == needle),
            "the server's computer name did not survive into the response"
        );
    }

    #[test]
    fn a_truncated_challenge_is_refused_rather_than_indexed() {
        let mut client = client();
        let _ = client.negotiate();
        let full = challenge_message(&server_target_info(), CLIENT_FLAGS);
        for length in 0..full.len() {
            let error = client.authenticate(&full[..length], [0xaa; 8], [0x55; 16], 0);
            assert!(error.is_err(), "a {length}-byte challenge was accepted");
        }
    }

    #[test]
    fn a_target_info_offset_pointing_outside_the_message_is_refused() {
        let mut client = client();
        let _ = client.negotiate();
        let mut challenge = challenge_message(&server_target_info(), CLIENT_FLAGS);
        // Point the target info a megabyte past the end of the buffer.
        challenge[44..48].copy_from_slice(&1_048_576u32.to_le_bytes());
        assert!(
            client
                .authenticate(&challenge, [0xaa; 8], [0x55; 16], 0)
                .is_err()
        );
    }

    #[test]
    fn an_av_pair_length_that_runs_past_the_list_is_refused() {
        let mut info = Vec::new();
        // A pair claiming 4 KiB of value inside a 4-byte list.
        info.extend_from_slice(&0x0002u16.to_le_bytes());
        info.extend_from_slice(&4096u16.to_le_bytes());
        assert!(parse_av_pairs(&info).is_err());
    }

    #[test]
    fn sealing_then_unsealing_round_trips_through_the_matching_direction() {
        // The client's sealing handle and the server's are different keys and
        // different keystreams; a session that used one for both would appear
        // to work in a loopback test and fail against every real server. The
        // two handles are exercised in opposite directions here on purpose.
        let session_key = Zeroizing::new([0x77u8; 16]);
        let mut client = NtlmSecurity::derive(session_key.clone(), CLIENT_FLAGS);
        let mut server = NtlmSecurity::derive(session_key, CLIENT_FLAGS);

        let wrapped = client.seal(b"a public key hash");
        // The server's "unseal" direction is the client's "seal" direction, so
        // the roles are swapped to model the far end.
        core::mem::swap(&mut server.client_seal, &mut server.server_seal);
        core::mem::swap(&mut server.client_sign, &mut server.server_sign);
        assert_eq!(server.unseal(&wrapped).unwrap(), b"a public key hash");
    }

    #[test]
    fn a_tampered_sealed_message_fails_its_integrity_check() {
        let session_key = Zeroizing::new([0x77u8; 16]);
        let mut client = NtlmSecurity::derive(session_key.clone(), CLIENT_FLAGS);
        let mut server = NtlmSecurity::derive(session_key, CLIENT_FLAGS);
        core::mem::swap(&mut server.client_seal, &mut server.server_seal);
        core::mem::swap(&mut server.client_sign, &mut server.server_sign);

        let mut wrapped = client.seal(b"a public key hash");
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xff;
        let error = server.unseal(&wrapped).unwrap_err();
        assert!(matches!(error, ProtocolError::ProtocolViolation { .. }));
    }

    /// [MS-NLMP] §3.4.5.3, `SEALKEY`, all three strengths.
    ///
    /// The sealing keys are MD5 over a *prefix* of the exported session key
    /// whose length is the strength the server agreed to — 16, 7 or 5 bytes —
    /// while the signing keys always hash all sixteen. `derive` used to hash
    /// sixteen everywhere and read `flags` only for
    /// `NTLMSSP_NEGOTIATE_KEY_EXCH`, so every sealed message to a server that
    /// agreed to 56-bit or 40-bit session security failed its integrity check
    /// with nothing on screen to say why.
    #[test]
    fn the_sealing_key_is_truncated_to_the_strength_the_server_agreed_to() {
        // Everything the client offers except the strength bits, so each case
        // below differs only in what it negotiated.
        let base = CLIENT_FLAGS & !(NEGOTIATE_128 | NEGOTIATE_56);
        let session_key = [0x77u8; 16];

        for (label, flags, prefix) in [
            ("128-bit", base | NEGOTIATE_128 | NEGOTIATE_56, 16usize),
            // A server that clears 128 and keeps 56.
            ("56-bit", base | NEGOTIATE_56, 7),
            // A server that clears both: the 40-bit fallback.
            ("40-bit", base, 5),
        ] {
            let mut derived = NtlmSecurity::derive(Zeroizing::new(session_key), flags);

            let keystream = |constant: &[u8]| -> Vec<u8> {
                let mut input = Vec::new();
                input.extend_from_slice(&session_key[..prefix]);
                input.extend_from_slice(constant);
                Rc4::new(&md5(&input)).applied(&[0u8; 32])
            };

            // The keystreams are compared rather than the keys, because the
            // keystream is what a server actually sees.
            assert_eq!(
                derived.client_seal.applied(&[0u8; 32]),
                keystream(b"session key to client-to-server sealing key magic constant\0"),
                "{label} client-to-server sealing key is not MD5 over the first {prefix} bytes"
            );
            assert_eq!(
                derived.server_seal.applied(&[0u8; 32]),
                keystream(b"session key to server-to-client sealing key magic constant\0"),
                "{label} server-to-client sealing key is not MD5 over the first {prefix} bytes"
            );
        }
    }

    /// The other half of §3.4.5.2/§3.4.5.3: `SIGNKEY` must *not* be truncated,
    /// so shortening the seal key must not quietly shorten the sign key too.
    #[test]
    fn the_signing_key_is_the_whole_session_key_at_every_strength() {
        let base = CLIENT_FLAGS & !(NEGOTIATE_128 | NEGOTIATE_56);
        let session_key = [0x77u8; 16];

        let mut input = Vec::new();
        input.extend_from_slice(&session_key);
        input.extend_from_slice(b"session key to client-to-server signing key magic constant\0");
        let expected = md5(&input);

        for flags in [base | NEGOTIATE_128, base | NEGOTIATE_56, base] {
            let derived = NtlmSecurity::derive(Zeroizing::new(session_key), flags);
            assert_eq!(*derived.client_sign, expected);
        }
    }

    #[test]
    fn a_message_shorter_than_a_signature_is_refused() {
        let mut security = NtlmSecurity::derive(Zeroizing::new([0x77u8; 16]), CLIENT_FLAGS);
        assert!(security.unseal(&[0u8; 8]).is_err());
    }

    #[test]
    fn neither_the_client_nor_its_keys_debug_print_anything_derived_from_the_password() {
        let client = client();
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("ada"), "{rendered}");

        let security = NtlmSecurity::derive(Zeroizing::new([0x77u8; 16]), CLIENT_FLAGS);
        let rendered = format!("{security:?}");
        assert!(!rendered.contains("77"), "{rendered}");
    }
}
