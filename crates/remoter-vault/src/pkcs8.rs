//! Re-enveloping legacy PEM private keys into PKCS#8.
//!
//! The domain model names three containers — OpenSSH, PKCS#8 and PuTTY PPK —
//! and every stored key carries one of those labels. Two files that are
//! extremely common on an administrator's disk are in neither:
//!
//! - **PKCS#1 RSA**, under `-----BEGIN RSA PRIVATE KEY-----`. This is what AWS
//!   EC2 hands out with every key pair it generates, what `ssh-keygen` wrote by
//!   default until OpenSSH 7.8, and what `ssh-keygen -m PEM -t rsa` still
//!   writes today.
//! - **SEC 1 elliptic curve**, under `-----BEGIN EC PRIVATE KEY-----`, which is
//!   what `ssh-keygen -m PEM -t ecdsa` writes.
//!
//! Both hold exactly the key material a PKCS#8 `PrivateKeyInfo` holds, in a
//! different envelope. Re-enveloping them as the file is read is a structural
//! rewrite of ASN.1 — no cipher, no key derivation, not one key byte changed —
//! so the vault ends up with a single representation and nothing downstream has
//! to know which file it came from. Refusing them instead, which is what this
//! build did, made the private-key option unusable for the majority of `.pem`
//! files that actually exist.
//!
//! Only *unencrypted* bodies are re-enveloped. A legacy PEM whose body is
//! enciphered carries an RFC 1421 `DEK-Info` header, and its plaintext cannot
//! be reached without the passphrase; that case is refused by name in
//! [`crate::credential`] rather than guessed at here.
//!
//! Wire references, per `CLAUDE.md` §0.4:
//!
//! | Structure | Reference |
//! |---|---|
//! | `PrivateKeyInfo` | RFC 5958 §2 |
//! | `rsaEncryption` algorithm identifier, parameters `NULL` | RFC 8017 §A.1, RFC 4055 §1.2 |
//! | `RSAPrivateKey`, carried verbatim in `privateKey` | RFC 8017 §A.1.2 |
//! | `id-ecPublicKey` with a `namedCurve` parameter | RFC 5480 §2.1.1 |
//! | `ECPrivateKey`, and its use inside a `PrivateKeyInfo` | RFC 5915 §3 |
//! | DER tags, definite lengths | X.690 §8.1, §10.1 |
//! | PEM armour and the `PRIVATE KEY` label | RFC 7468 §10 |
//!
//! RFC 5915 §3 notes that the `parameters [0]` field inside an `ECPrivateKey`
//! is redundant once the structure sits in a `PrivateKeyInfo` — the curve is
//! already named by the `privateKeyAlgorithm` above it — so it is dropped on
//! the way in and `publicKey [1]` is carried across verbatim. That is the same
//! shape OpenSSL's own `pkcs8 -topk8` produces.
//!
//! What proves the rewrite correct is not this documentation but
//! `credential::real_keys`, which runs `ssh-keygen -y` over the file that went
//! in and the document that came out and requires the same public key from
//! both. That is one assertion covering "a real SSH implementation reads this"
//! and "no key byte changed".
//!
//! Every intermediate buffer here holds key material and is `Zeroizing`, and
//! every one is allocated at its exact final size: a `Vec` that grows leaves a
//! copy of what it held in freed memory, and nothing can zeroize that.

use zeroize::Zeroizing;

use crate::error::VaultError;

// DER identifier octets (X.690 §8.1.2).
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
/// `[0]`, constructed: `ECPrivateKey.parameters`.
const TAG_CONTEXT_0: u8 = 0xA0;
/// `[1]`, constructed: `ECPrivateKey.publicKey`.
const TAG_CONTEXT_1: u8 = 0xA1;

/// `INTEGER 0` — `PrivateKeyInfo.version`, `v1` (RFC 5958 §2).
const PKCS8_VERSION_V1: [u8; 3] = [TAG_INTEGER, 0x01, 0x00];

/// `INTEGER 1` — `ECPrivateKey.version`, `ecPrivkeyVer1`, the only version
/// RFC 5915 §3 defines.
const EC_VERSION_V1: [u8; 3] = [TAG_INTEGER, 0x01, 0x01];

/// `AlgorithmIdentifier { rsaEncryption, NULL }`, complete.
///
/// `SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }`. RFC 4055 §1.2 requires the
/// parameters to be present and `NULL` rather than absent, which is why the
/// trailing `05 00` is not an optional extra.
const RSA_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// The `id-ecPublicKey` OID as a complete TLV: `1.2.840.10045.2.1`
/// (RFC 5480 §2.1.1).
const EC_PUBLIC_KEY_OID: [u8; 9] = [TAG_OID, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// Re-envelopes a PKCS#1 `RSAPrivateKey` as a PKCS#8 PEM document.
///
/// `der` is the decoded body of a `-----BEGIN RSA PRIVATE KEY-----` block. It
/// becomes the `privateKey` OCTET STRING verbatim — RFC 8017 §A.1.2 is exactly
/// what RFC 5958 expects to find under `rsaEncryption` — so no RSA arithmetic
/// happens here and no component is re-encoded.
pub(crate) fn from_pkcs1_rsa(der: &[u8]) -> Result<Vec<u8>, VaultError> {
    // The body is wrapped unexamined, so its outer shape is checked first: a
    // PKCS#8 document built around something that is not an `RSAPrivateKey`
    // would fail at connect time, a long way from the file that caused it.
    let mut document = Tlvs::new(der);
    let (tag, _) = document.next()?;
    if tag != TAG_SEQUENCE || !document.is_empty() {
        return Err(VaultError::NotAPrivateKey);
    }

    let private_key = tlv(TAG_OCTET_STRING, der)?;
    let body = concat(&[&PKCS8_VERSION_V1, &RSA_ALGORITHM_ID, &private_key]);
    Ok(armour(&tlv(TAG_SEQUENCE, &body)?))
}

/// Re-envelopes a SEC 1 `ECPrivateKey` as a PKCS#8 PEM document.
///
/// `der` is the decoded body of a `-----BEGIN EC PRIVATE KEY-----` block. The
/// named curve moves up into the `AlgorithmIdentifier`, where RFC 5480 §2.1.1
/// puts it, and the inner structure is rebuilt without its now-redundant
/// `parameters [0]`.
///
/// A key whose `parameters` are explicit domain parameters rather than a named
/// curve OID is refused: RFC 5480 §2.1.1 does not allow them in this position,
/// and inventing a curve name for them would be a guess.
pub(crate) fn from_sec1_ec(der: &[u8]) -> Result<Vec<u8>, VaultError> {
    let mut document = Tlvs::new(der);
    let (tag, body) = document.next()?;
    if tag != TAG_SEQUENCE || !document.is_empty() {
        return Err(VaultError::NotAPrivateKey);
    }

    let mut fields = Tlvs::new(body);
    let (tag, version) = fields.next()?;
    if tag != TAG_INTEGER || version != [0x01] {
        return Err(VaultError::NotAPrivateKey);
    }
    let (tag, private_key) = fields.next()?;
    if tag != TAG_OCTET_STRING {
        return Err(VaultError::NotAPrivateKey);
    }

    // Both remaining fields are OPTIONAL and context-tagged, so they are read
    // by tag rather than by position.
    let mut curve: Option<&[u8]> = None;
    let mut public_key: Option<&[u8]> = None;
    while !fields.is_empty() {
        match fields.next()? {
            (TAG_CONTEXT_0, parameters) => {
                // `[0]` is EXPLICIT, so its content is the `ECParameters`
                // CHOICE — a bare OID for a named curve.
                let mut inner = Tlvs::new(parameters);
                let (tag, oid) = inner.next()?;
                if tag != TAG_OID || !inner.is_empty() {
                    return Err(VaultError::NotAPrivateKey);
                }
                curve = Some(oid);
            }
            (TAG_CONTEXT_1, encoded_point) => public_key = Some(encoded_point),
            _ => return Err(VaultError::NotAPrivateKey),
        }
    }
    let curve = curve.ok_or(VaultError::NotAPrivateKey)?;

    let curve = tlv(TAG_OID, curve)?;
    let algorithm = tlv(TAG_SEQUENCE, &concat(&[&EC_PUBLIC_KEY_OID, &curve]))?;

    let scalar = tlv(TAG_OCTET_STRING, private_key)?;
    let point = match public_key {
        Some(encoded_point) => tlv(TAG_CONTEXT_1, encoded_point)?,
        None => Zeroizing::new(Vec::new()),
    };
    let inner = tlv(TAG_SEQUENCE, &concat(&[&EC_VERSION_V1, &scalar, &point]))?;

    let body = concat(&[
        &PKCS8_VERSION_V1,
        &algorithm,
        &tlv(TAG_OCTET_STRING, &inner)?,
    ]);
    Ok(armour(&tlv(TAG_SEQUENCE, &body)?))
}

// ------------------------------------------------------------- reading ---

/// A cursor over a run of DER type-length-value triples.
///
/// Definite lengths only. X.690 §10.1 requires DER to use the definite form,
/// and accepting the indefinite form would mean accepting a BER document no
/// conforming writer produces — on a path that parses a file handed over by
/// someone else.
struct Tlvs<'a> {
    rest: &'a [u8],
}

impl<'a> Tlvs<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The next identifier octet and the value it introduces, advancing past
    /// both.
    fn next(&mut self) -> Result<(u8, &'a [u8]), VaultError> {
        let (tag, after_tag) = self.rest.split_first().ok_or(VaultError::NotAPrivateKey)?;
        let (first, after_first) = after_tag.split_first().ok_or(VaultError::NotAPrivateKey)?;

        let (length, after_length) = if *first < 0x80 {
            // Short form: the octet is the length (X.690 §8.1.3.4).
            (usize::from(*first), after_first)
        } else {
            // Long form: the low seven bits count the length octets that
            // follow. `0x80` alone is the indefinite form, and a count wider
            // than a `usize` cannot be represented; both are refused.
            let count = usize::from(*first & 0x7F);
            if count == 0 || count > size_of::<usize>() {
                return Err(VaultError::NotAPrivateKey);
            }
            let (octets, rest) = after_first
                .split_at_checked(count)
                .ok_or(VaultError::NotAPrivateKey)?;
            let mut length = 0usize;
            for octet in octets {
                length = length
                    .checked_mul(0x100)
                    .and_then(|shifted| shifted.checked_add(usize::from(*octet)))
                    .ok_or(VaultError::NotAPrivateKey)?;
            }
            (length, rest)
        };

        let (value, rest) = after_length
            .split_at_checked(length)
            .ok_or(VaultError::NotAPrivateKey)?;
        self.rest = rest;
        Ok((*tag, value))
    }
}

// ------------------------------------------------------------- writing ---

/// How many octets DER spends on a definite length of `len` (X.690 §8.1.3).
fn length_octets(len: usize) -> usize {
    if len < 0x80 {
        return 1;
    }
    let encoded = len.to_be_bytes();
    let significant = encoded
        .iter()
        .position(|octet| *octet != 0)
        .map_or(1, |first| size_of::<usize>().saturating_sub(first));
    // The count octet, then the significant octets themselves.
    1usize.saturating_add(significant)
}

/// Appends a DER definite length (X.690 §8.1.3).
///
/// Lengths here are bounded by the key file size limit, so the long form never
/// needs more than three octets; the general form is written anyway, because a
/// silently wrong length is the worst thing an encoder can emit.
fn push_length(out: &mut Vec<u8>, len: usize) -> Result<(), VaultError> {
    if len < 0x80 {
        out.push(u8::try_from(len).map_err(|_| VaultError::NotAPrivateKey)?);
        return Ok(());
    }
    let encoded = len.to_be_bytes();
    let first = encoded
        .iter()
        .position(|octet| *octet != 0)
        .ok_or(VaultError::NotAPrivateKey)?;
    let significant = encoded.get(first..).ok_or(VaultError::NotAPrivateKey)?;
    let count = u8::try_from(significant.len()).map_err(|_| VaultError::NotAPrivateKey)?;
    // `0x80` is the indefinite form and `0xFF` is reserved; neither can be
    // reached from a slice of at most eight octets, and both are refused
    // rather than emitted.
    if count == 0 || count > 0x7E {
        return Err(VaultError::NotAPrivateKey);
    }
    out.push(0x80 | count);
    out.extend_from_slice(significant);
    Ok(())
}

/// Wraps `value` in a TLV with `tag`.
///
/// The buffer is allocated at its exact final size. A `Vec` that grows copies
/// its contents to a new allocation and leaves the old one unzeroed, which for
/// a buffer holding key material is a leak nothing can clean up afterwards.
fn tlv(tag: u8, value: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let total = 1usize
        .saturating_add(length_octets(value.len()))
        .saturating_add(value.len());
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.push(tag);
    push_length(&mut out, value.len())?;
    out.extend_from_slice(value);
    Ok(out)
}

/// Joins `parts` into one exactly-sized, self-wiping buffer.
fn concat(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let total = parts
        .iter()
        .fold(0usize, |sum, part| sum.saturating_add(part.len()));
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// PEM armour around a PKCS#8 document (RFC 7468 §10), 64 characters to the
/// line and LF endings.
///
/// The returned buffer is the caller's to wrap in a [`crate::Secret`]; it is
/// allocated at its exact size for the same reason as [`tlv`].
fn armour(der: &[u8]) -> Vec<u8> {
    const BEGIN: &[u8] = b"-----BEGIN PRIVATE KEY-----\n";
    const END: &[u8] = b"-----END PRIVATE KEY-----\n";
    const LINE: usize = 64;

    let encoded = Zeroizing::new(data_encoding::BASE64.encode(der));
    let lines = encoded.len().div_ceil(LINE);
    let mut out = Vec::with_capacity(
        BEGIN
            .len()
            .saturating_add(encoded.len())
            .saturating_add(lines)
            .saturating_add(END.len()),
    );
    out.extend_from_slice(BEGIN);
    for chunk in encoded.as_bytes().chunks(LINE) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
    }
    out.extend_from_slice(END);
    out
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

    /// `SEQUENCE { INTEGER 0 }`, the smallest well-formed body the wrapper
    /// accepts. No key material, because none is needed to test the envelope.
    const TINY_SEQUENCE: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x00];

    fn body_of(pem: &[u8]) -> Vec<u8> {
        let text = String::from_utf8(pem.to_vec()).unwrap();
        let base64: String = text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        data_encoding::BASE64.decode(base64.as_bytes()).unwrap()
    }

    #[test]
    fn a_pkcs1_body_is_carried_across_untouched() {
        let pem = from_pkcs1_rsa(&TINY_SEQUENCE).unwrap();
        let der = body_of(&pem);

        let mut document = Tlvs::new(&der);
        let (tag, fields) = document.next().unwrap();
        assert_eq!(tag, TAG_SEQUENCE);
        assert!(document.is_empty(), "trailing bytes after the document");

        let mut fields = Tlvs::new(fields);
        assert_eq!(fields.next().unwrap(), (TAG_INTEGER, &[0x00][..]));
        assert_eq!(
            fields.next().unwrap(),
            (TAG_SEQUENCE, &RSA_ALGORITHM_ID[2..])
        );
        // The whole point: the PKCS#1 body is the OCTET STRING, unchanged.
        assert_eq!(
            fields.next().unwrap(),
            (TAG_OCTET_STRING, &TINY_SEQUENCE[..])
        );
        assert!(fields.is_empty());
    }

    #[test]
    fn a_body_that_is_not_a_sequence_is_refused_rather_than_wrapped() {
        // A PKCS#8 document built around this would parse here and fail at
        // connect time, which is the failure mode the check exists to prevent.
        assert!(matches!(
            from_pkcs1_rsa(b"not der at all"),
            Err(VaultError::NotAPrivateKey)
        ));
        // A SEQUENCE whose declared length runs past the buffer.
        assert!(matches!(
            from_pkcs1_rsa(&[0x30, 0x82, 0x01, 0x00]),
            Err(VaultError::NotAPrivateKey)
        ));
        // A well-formed SEQUENCE with a stray octet after it.
        assert!(matches!(
            from_pkcs1_rsa(&[0x30, 0x01, 0x00, 0x00]),
            Err(VaultError::NotAPrivateKey)
        ));
    }

    #[test]
    fn an_indefinite_length_is_refused() {
        // X.690 §10.1: DER is definite-length only. `0x80` is BER's indefinite
        // form, and a parser that accepted it would be reading a different
        // language from the one the document claims to be in.
        let mut tlvs = Tlvs::new(&[0x30, 0x80, 0x00, 0x00]);
        assert!(matches!(tlvs.next(), Err(VaultError::NotAPrivateKey)));
    }

    #[test]
    fn an_ec_key_without_a_named_curve_is_refused() {
        // `ECPrivateKey` with version and privateKey but no `parameters [0]`.
        let der = [0x30, 0x08, 0x02, 0x01, 0x01, 0x04, 0x03, 0x01, 0x02, 0x03];
        assert!(matches!(
            from_sec1_ec(&der),
            Err(VaultError::NotAPrivateKey)
        ));
    }

    #[test]
    fn an_ec_key_of_the_wrong_version_is_refused() {
        // RFC 5915 §3 defines `ecPrivkeyVer1` and nothing else.
        let der = [
            0x30, 0x14, 0x02, 0x01, 0x02, 0x04, 0x03, 0x01, 0x02, 0x03, 0xA0, 0x0A, 0x06, 0x08,
            0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        ];
        assert!(matches!(
            from_sec1_ec(&der),
            Err(VaultError::NotAPrivateKey)
        ));
    }

    #[test]
    fn the_armour_wraps_at_sixty_four_characters() {
        let der = tlv(TAG_OCTET_STRING, &[0x41; 200]).unwrap();
        let pem = armour(&der);
        let text = String::from_utf8(pem).unwrap();

        assert!(text.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(text.ends_with("-----END PRIVATE KEY-----\n"));
        for line in text.lines().filter(|line| !line.starts_with("-----")) {
            assert!(line.len() <= 64, "a PEM line ran long: {}", line.len());
        }
    }

    #[test]
    fn lengths_round_trip_through_both_forms() {
        for len in [0usize, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x1_0000] {
            let mut encoded = Vec::new();
            push_length(&mut encoded, len).unwrap();
            assert_eq!(
                encoded.len(),
                length_octets(len),
                "length_octets disagreed with push_length at {len}"
            );

            // Read it back through the parser that will actually see it.
            let mut document = vec![TAG_OCTET_STRING];
            document.extend_from_slice(&encoded);
            document.extend(std::iter::repeat_n(0x00, len));
            let (tag, value) = Tlvs::new(&document).next().unwrap();
            assert_eq!(tag, TAG_OCTET_STRING);
            assert_eq!(value.len(), len);
        }
    }
}
