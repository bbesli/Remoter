//! Just enough DER for the four structures MS-CSSP defines, and no more.
//!
//! `TSRequest`, `NegoData`, `TSCredentials` and `TSPasswordCreds` are four
//! SEQUENCEs of context-tagged INTEGERs and OCTET STRINGs. A general-purpose
//! ASN.1 crate would parse them, and this workspace already carries two
//! (`der` and `picky-asn1`, both reached only through dependencies) — but
//! neither is a direct dependency, adding one is a licence review under
//! CLAUDE.md §8, and the subset needed here is small enough to read in one
//! sitting and to test exhaustively.
//!
//! The reader is the part that matters. Everything it parses arrives from a
//! server that may already be compromised (ADR-0003), before authentication
//! has completed, so it indexes nothing without checking, follows no length it
//! has not bounded against the buffer, and refuses rather than guesses.
//!
//! Definite-length form only: BER's indefinite length is not permitted in DER
//! (X.690 §10.1), and accepting it would mean accepting a re-encoding of a
//! structure whose signature was computed over the canonical form.

use remoter_proto::ProtocolError;
use zeroize::Zeroize;

use crate::error::violation;

/// X.690 §8.1.2: the universal, primitive INTEGER tag.
pub const TAG_INTEGER: u8 = 0x02;
/// The universal, primitive OCTET STRING tag.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// The universal, constructed SEQUENCE tag.
pub const TAG_SEQUENCE: u8 = 0x30;

/// The constructed, context-specific tag for `[n]`.
///
/// MS-CSSP §2.2.1 tags every field explicitly, so every one of them is
/// constructed and wraps a complete inner TLV.
#[must_use]
pub const fn context(number: u8) -> u8 {
    0xa0 | (number & 0x1f)
}

/// Encodes a length in the shortest permitted form. X.690 §8.1.3, §10.1.
///
/// Lengths above 2^32 cannot occur: the caller's buffers are PDUs bounded by
/// the transport, and the long form here tops out at four bytes for that
/// reason rather than because five would be hard.
#[must_use]
pub fn length(value: usize) -> Vec<u8> {
    if value < 0x80 {
        // The short form is mandatory below 128 in DER; using the long form
        // would be a re-encoding, and signatures are computed over bytes.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "guarded by the comparison above"
        )]
        return vec![value as u8];
    }
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    let mut out = Vec::with_capacity(significant.len() + 1);
    // The long form's first byte is 0x80 | count, and `significant` is at most
    // eight bytes, so the OR cannot collide with the indefinite-length 0x80.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "significant.len() is at most size_of::<usize>()"
    )]
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
    out
}

/// One tag-length-value.
#[must_use]
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    out.extend_from_slice(&length(content.len()));
    out.extend_from_slice(content);
    out
}

/// A non-negative INTEGER, minimally encoded with the leading zero X.690
/// §8.3.2 requires when the top bit would otherwise read as a sign.
#[must_use]
pub fn integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
    let mut content = Vec::with_capacity(5);
    if bytes[first] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(&bytes[first..]);
    tlv(TAG_INTEGER, &content)
}

/// An OCTET STRING.
#[must_use]
pub fn octet_string(value: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, value)
}

/// A SEQUENCE over already-encoded members.
#[must_use]
pub fn sequence(members: &[u8]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, members)
}

/// An explicitly tagged `[n] Inner`.
#[must_use]
pub fn tagged(number: u8, inner: &[u8]) -> Vec<u8> {
    tlv(context(number), inner)
}

/// A cursor over DER, which refuses everything it cannot verify.
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Whether anything is left.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.position >= self.bytes.len()
    }

    /// The tag of the next value, without consuming it.
    #[must_use]
    pub fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    /// Reads the next value, checking that it carries `tag`.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ProtocolViolation`] if the buffer is exhausted, the
    /// tag is not the expected one, the length uses the indefinite form, or
    /// the length runs past the end of the buffer.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], ProtocolError> {
        let found = self.peek_tag().ok_or_else(bad)?;
        if found != tag {
            return Err(bad());
        }
        self.read_any().map(|(_, content)| content)
    }

    /// Reads the next value whatever its tag.
    ///
    /// # Errors
    ///
    /// As [`Reader::expect`], minus the tag check.
    pub fn read_any(&mut self) -> Result<(u8, &'a [u8]), ProtocolError> {
        let tag = self.peek_tag().ok_or_else(bad)?;
        let mut cursor = self.position + 1;
        let first = *self.bytes.get(cursor).ok_or_else(bad)?;
        cursor += 1;

        let len = if first < 0x80 {
            usize::from(first)
        } else if first == 0x80 {
            // X.690 §10.1: DER forbids the indefinite form. Accepting it would
            // let a peer re-encode a structure whose hash we are about to
            // compare, so it is refused rather than tolerated.
            return Err(bad());
        } else {
            let count = usize::from(first & 0x7f);
            // Eight bytes is the widest length a `usize` can hold; more than
            // that is malformed rather than merely large.
            if count == 0 || count > 8 {
                return Err(bad());
            }
            let slice = self
                .bytes
                .get(cursor..cursor.checked_add(count).ok_or_else(bad)?)
                .ok_or_else(bad)?;
            cursor += count;
            let mut value = 0usize;
            for byte in slice {
                value = value.checked_shl(8).ok_or_else(bad)? | usize::from(*byte);
            }
            value
        };

        let end = cursor.checked_add(len).ok_or_else(bad)?;
        let content = self.bytes.get(cursor..end).ok_or_else(bad)?;
        self.position = end;
        Ok((tag, content))
    }

    /// Skips the next value.
    ///
    /// # Errors
    ///
    /// As [`Reader::read_any`].
    pub fn skip(&mut self) -> Result<(), ProtocolError> {
        self.read_any().map(|_| ())
    }
}

/// Reads a non-negative INTEGER's content as a `u32`.
///
/// # Errors
///
/// [`ProtocolError::ProtocolViolation`] if the value is empty or wider than
/// four significant bytes.
pub fn read_u32(content: &[u8]) -> Result<u32, ProtocolError> {
    // A leading zero is the sign padding X.690 §8.3.2 requires, not a digit.
    let trimmed = match content {
        [0, rest @ ..] => rest,
        other => other,
    };
    if trimmed.is_empty() {
        return Ok(0);
    }
    if trimmed.len() > 4 {
        return Err(bad());
    }
    let mut value = 0u32;
    for byte in trimmed {
        value = (value << 8) | u32::from(*byte);
    }
    Ok(value)
}

/// A UTF-16LE OCTET STRING built from a secret, in a buffer that zeroes
/// itself.
///
/// The password reaches the wire as `TSPasswordCreds.password`, and this is
/// the only place in the crate where it is copied. Every intermediate that
/// touches it — including the DER framing around it, which contains the
/// password verbatim — is zeroized by the caller.
#[must_use]
pub fn zeroizing(mut value: Vec<u8>) -> ZeroizingBytes {
    let out = ZeroizingBytes(core::mem::take(&mut value));
    value.zeroize();
    out
}

/// A byte buffer that zeroes itself and never prints itself.
pub struct ZeroizingBytes(Vec<u8>);

impl ZeroizingBytes {
    /// The bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for ZeroizingBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<redacted, {} bytes>", self.0.len())
    }
}

fn bad() -> ProtocolError {
    violation("the server sent a malformed CredSSP structure")
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
    fn lengths_use_the_shortest_permitted_form() {
        // DER is canonical: a signature computed over one encoding does not
        // verify against another, so "a length that parses" is not enough.
        assert_eq!(length(0), vec![0x00]);
        assert_eq!(length(127), vec![0x7f]);
        assert_eq!(length(128), vec![0x81, 0x80]);
        assert_eq!(length(255), vec![0x81, 0xff]);
        assert_eq!(length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(length(65_535), vec![0x82, 0xff, 0xff]);
        assert_eq!(length(65_536), vec![0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn integers_carry_the_sign_padding_x690_requires() {
        assert_eq!(integer(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer(6), vec![0x02, 0x01, 0x06]);
        assert_eq!(integer(127), vec![0x02, 0x01, 0x7f]);
        // 0x80 would read as -128 without the padding byte.
        assert_eq!(integer(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(0x8000_0000), vec![0x02, 0x05, 0x00, 0x80, 0, 0, 0]);
    }

    #[test]
    fn a_round_trip_through_the_reader_recovers_what_was_written() {
        let encoded = sequence(
            &[
                tagged(0, &integer(6)),
                tagged(2, &octet_string(b"auth info")),
            ]
            .concat(),
        );
        let mut outer = Reader::new(&encoded);
        let body = outer.expect(TAG_SEQUENCE).unwrap();

        let mut fields = Reader::new(body);
        let version = fields.expect(context(0)).unwrap();
        assert_eq!(
            read_u32(Reader::new(version).expect(TAG_INTEGER).unwrap()).unwrap(),
            6
        );
        let info = fields.expect(context(2)).unwrap();
        assert_eq!(
            Reader::new(info).expect(TAG_OCTET_STRING).unwrap(),
            b"auth info"
        );
        assert!(fields.is_empty());
    }

    #[test]
    fn a_length_running_past_the_buffer_is_refused() {
        // The whole point of this reader: a server that may be compromised
        // sends these bytes before it has authenticated.
        let malformed = [0x30, 0x7f, 0x01, 0x02];
        assert!(Reader::new(&malformed).expect(TAG_SEQUENCE).is_err());
    }

    #[test]
    fn the_indefinite_length_form_is_refused() {
        // BER allows it, DER does not, and tolerating it would accept a
        // re-encoding of a structure whose hash is about to be compared.
        let malformed = [0x30, 0x80, 0x00, 0x00];
        assert!(Reader::new(&malformed).expect(TAG_SEQUENCE).is_err());
    }

    #[test]
    fn a_truncated_value_is_refused_at_every_prefix() {
        let encoded = sequence(&tagged(0, &integer(6)));
        for cut in 0..encoded.len() {
            assert!(
                Reader::new(&encoded[..cut]).expect(TAG_SEQUENCE).is_err(),
                "a {cut}-byte prefix parsed"
            );
        }
    }

    #[test]
    fn an_unexpected_tag_is_refused_rather_than_reinterpreted() {
        let encoded = octet_string(b"not a sequence");
        assert!(Reader::new(&encoded).expect(TAG_SEQUENCE).is_err());
    }

    #[test]
    fn an_over_wide_integer_is_refused() {
        assert!(read_u32(&[1, 2, 3, 4, 5]).is_err());
        assert_eq!(read_u32(&[]).unwrap(), 0);
        assert_eq!(read_u32(&[0x00, 0xff]).unwrap(), 255);
    }

    #[test]
    fn a_secret_buffer_never_prints_itself() {
        let secret = zeroizing(b"hunter2".to_vec());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert_eq!(rendered, "<redacted, 7 bytes>");
    }
}
