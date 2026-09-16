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
//! What arrives here is always a plaintext body. A legacy PEM whose body is
//! enciphered carries an RFC 1421 `DEK-Info` header, and its plaintext is
//! reached first by [`crate::legacy_pem`], with the passphrase the interface
//! asked for; the deciphered DER then comes through these functions like any
//! other. Nothing in this module has a passphrase or wants one.
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
//! | `EncryptedPrivateKeyInfo` | RFC 5958 §3 |
//! | `PBES2-params`, `PBKDF2-params`, and the PBES1 algorithm identifiers | RFC 8018 §A.2, §A.4, §A.3 |
//! | AES-CBC algorithm identifiers | RFC 3565 §4.1 |
//! | `id-scrypt` | RFC 7914 §7 |
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
/// Two shapes real tools write are normalised on the way, both found because a
/// correct passphrase for a key macOS's own `ssh-keygen` had just written was
/// reported as wrong:
///
/// - **Explicit domain parameters.** `ssh-keygen` built against an older
///   LibreSSL — the one macOS ships — writes the curve as its full
///   `SpecifiedECDomain` (SEC 1 §C.2) instead of a named-curve OID. RFC 5480
///   §2.1.1 does not allow that in PKCS#8, so it is matched against P-256,
///   P-384 and P-521 and replaced by the curve's name — but only when *every*
///   parameter is the named curve's own: prime, both coefficients, generator,
///   order and cofactor. A curve that differs in any of them is a different
///   curve, whatever its order, and is refused as
///   [`VaultError::UnsupportedKeyFormat`].
/// - **A short private key.** RFC 5915 §3 fixes `privateKey` at the curve's
///   field length, and the same LibreSSL drops leading zero octets, so one key
///   in 256 arrives an octet short. It is padded back to length.
///
/// # Errors
///
/// [`VaultError::NotAPrivateKey`] when `der` is not an `ECPrivateKey` at all —
/// which is also what a wrongly deciphered body looks like;
/// [`VaultError::UnsupportedKeyFormat`] when it is one, but on a curve given by
/// explicit parameters this build does not recognise.
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
    let mut known: Option<&'static NamedCurve> = None;
    let mut public_key: Option<&[u8]> = None;
    while !fields.is_empty() {
        match fields.next()? {
            (TAG_CONTEXT_0, parameters) => {
                // `[0]` is EXPLICIT, so its content is the `ECParameters`
                // CHOICE: a bare OID for a named curve, or the whole
                // `SpecifiedECDomain` SEQUENCE.
                let mut inner = Tlvs::new(parameters);
                let (tag, value) = inner.next()?;
                if !inner.is_empty() {
                    return Err(VaultError::NotAPrivateKey);
                }
                match tag {
                    TAG_OID => {
                        curve = Some(value);
                        known = CURVES.iter().copied().find(|named| named.oid == value);
                    }
                    TAG_SEQUENCE => {
                        let named = named_curve_for(value)?;
                        curve = Some(named.oid);
                        known = Some(named);
                    }
                    _ => return Err(VaultError::NotAPrivateKey),
                }
            }
            (TAG_CONTEXT_1, encoded_point) => public_key = Some(encoded_point),
            _ => return Err(VaultError::NotAPrivateKey),
        }
    }
    let curve = curve.ok_or(VaultError::NotAPrivateKey)?;

    // RFC 5915 §3: exactly the field length. Longer is not a key on this
    // curve; shorter is the leading zeros a non-conforming encoder dropped.
    let padded;
    let private_key = match known {
        Some(named) if private_key.len() < named.field_bytes => {
            let mut full = Zeroizing::new(vec![0u8; named.field_bytes]);
            let offset = named.field_bytes - private_key.len();
            full.get_mut(offset..)
                .ok_or(VaultError::NotAPrivateKey)?
                .copy_from_slice(private_key);
            padded = full;
            padded.as_slice()
        }
        Some(named) if private_key.len() > named.field_bytes => {
            return Err(VaultError::NotAPrivateKey);
        }
        _ => private_key,
    };

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

// ------------------------------------------------- explicit curve domains ---

/// A curve explicit domain parameters can be recognised as.
struct NamedCurve {
    /// The content octets of the curve's OBJECT IDENTIFIER.
    oid: &'static [u8],
    /// The field length in octets: the length of `a`, `b`, a coordinate, and
    /// the private key (RFC 5915 §3).
    field_bytes: usize,
    /// Integers, big-endian, without leading zero octets.
    prime: &'static [u8],
    order: &'static [u8],
    /// Field elements, at `field_bytes` (SEC 1 §2.3.5).
    a: &'static [u8],
    b: &'static [u8],
    /// The base point, uncompressed: `04 || x || y` (SEC 1 §2.3.3).
    generator: &'static [u8],
}

/// `prime-field`, 1.2.840.10045.1.1 (SEC 1 §C.1, X9.62).
const OID_PRIME_FIELD: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01];

/// P-256: SEC 2 §2.4.2 domain parameters, taken from OpenSSL's own
/// `ecparam -name prime256v1 -param_enc explicit` encoding.
const P256: NamedCurve = NamedCurve {
    oid: &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    field_bytes: 32,
    prime: &[
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF,
    ],
    a: &[
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFC,
    ],
    b: &[
        0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86,
        0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2,
        0x60, 0x4B,
    ],
    generator: &[
        0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4,
        0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8,
        0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A,
        0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40,
        0x68, 0x37, 0xBF, 0x51, 0xF5,
    ],
    order: &[
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ],
};

/// P-384: SEC 2 §2.5.1 domain parameters, taken from OpenSSL's own
/// `ecparam -name secp384r1 -param_enc explicit` encoding.
const P384: NamedCurve = NamedCurve {
    oid: &[0x2B, 0x81, 0x04, 0x00, 0x22],
    field_bytes: 48,
    prime: &[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
        0xFF, 0xFF, 0xFF,
    ],
    a: &[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
        0xFF, 0xFF, 0xFC,
    ],
    b: &[
        0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4, 0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D,
        0x19, 0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8F, 0x50, 0x13,
        0x87, 0x5A, 0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D, 0x2A, 0x85, 0xC8, 0xED, 0xD3,
        0xEC, 0x2A, 0xEF,
    ],
    generator: &[
        0x04, 0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20,
        0xAD, 0x74, 0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, 0x59, 0xF7, 0x41, 0xE0, 0x82,
        0x54, 0x2A, 0x38, 0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38,
        0x72, 0x76, 0x0A, 0xB7, 0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98,
        0xBF, 0x92, 0x92, 0xDC, 0x29, 0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, 0xE9, 0xDA,
        0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0, 0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, 0x7A,
        0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F,
    ],
    order: &[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37,
        0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC,
        0xC5, 0x29, 0x73,
    ],
};

/// P-521: SEC 2 §2.6.1 domain parameters, taken from OpenSSL's own
/// `ecparam -name secp521r1 -param_enc explicit` encoding.
const P521: NamedCurve = NamedCurve {
    oid: &[0x2B, 0x81, 0x04, 0x00, 0x23],
    field_bytes: 66,
    prime: &[
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ],
    a: &[
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    ],
    b: &[
        0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C, 0x9A, 0x1F, 0x92, 0x9A, 0x21, 0xA0, 0xB6,
        0x85, 0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3, 0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91,
        0x8E, 0xF1, 0x09, 0xE1, 0x56, 0x19, 0x39, 0x51, 0xEC, 0x7E, 0x93, 0x7B, 0x16, 0x52, 0xC0,
        0xBD, 0x3B, 0xB1, 0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C, 0x34, 0xF1, 0xEF, 0x45,
        0x1F, 0xD4, 0x6B, 0x50, 0x3F, 0x00,
    ],
    generator: &[
        0x04, 0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66,
        0x23, 0x95, 0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F, 0xB5, 0x21, 0xF8, 0x28, 0xAF,
        0x60, 0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28, 0xFE, 0x1D,
        0xC1, 0x27, 0xA2, 0xFF, 0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A, 0x42, 0x9B, 0xF9,
        0x7E, 0x7E, 0x31, 0xC2, 0xE5, 0xBD, 0x66, 0x01, 0x18, 0x39, 0x29, 0x6A, 0x78, 0x9A, 0x3B,
        0xC0, 0x04, 0x5C, 0x8A, 0x5F, 0xB4, 0x2C, 0x7D, 0x1B, 0xD9, 0x98, 0xF5, 0x44, 0x49, 0x57,
        0x9B, 0x44, 0x68, 0x17, 0xAF, 0xBD, 0x17, 0x27, 0x3E, 0x66, 0x2C, 0x97, 0xEE, 0x72, 0x99,
        0x5E, 0xF4, 0x26, 0x40, 0xC5, 0x50, 0xB9, 0x01, 0x3F, 0xAD, 0x07, 0x61, 0x35, 0x3C, 0x70,
        0x86, 0xA2, 0x72, 0xC2, 0x40, 0x88, 0xBE, 0x94, 0x76, 0x9F, 0xD1, 0x66, 0x50,
    ],
    order: &[
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01,
        0x48, 0xF7, 0x09, 0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F,
        0xB7, 0x1E, 0x91, 0x38, 0x64, 0x09,
    ],
};

const CURVES: [&NamedCurve; 3] = [&P256, &P384, &P521];

/// Which named curve a `SpecifiedECDomain` (SEC 1 §C.2) is, if it is exactly
/// one of them.
///
/// ```text
/// SpecifiedECDomain ::= SEQUENCE {
///     version   INTEGER { ecdpVer1(1), ... },
///     fieldID   FieldID {{FieldTypes}},     -- prime-field, p
///     curve     Curve,                      -- a, b, seed OPTIONAL
///     base      ECPoint,
///     order     INTEGER,
///     cofactor  INTEGER OPTIONAL,
///     ... }
/// ```
///
/// The seed is ignored: it records how the coefficients were chosen and plays
/// no part in the arithmetic. Everything that does is compared.
fn named_curve_for(domain: &[u8]) -> Result<&'static NamedCurve, VaultError> {
    let unsupported = VaultError::UnsupportedKeyFormat(
        "SEC 1 elliptic-curve key on a curve other than P-256, P-384 or P-521",
    );

    let mut fields = Tlvs::new(domain);
    let (tag, version) = fields.next()?;
    if tag != TAG_INTEGER || version != [0x01] {
        return Err(VaultError::NotAPrivateKey);
    }

    let (tag, field_id) = fields.next()?;
    if tag != TAG_SEQUENCE {
        return Err(VaultError::NotAPrivateKey);
    }
    let mut field_id = Tlvs::new(field_id);
    let (tag, field_type) = field_id.next()?;
    if tag != TAG_OID {
        return Err(VaultError::NotAPrivateKey);
    }
    if field_type != OID_PRIME_FIELD.as_slice() {
        // A characteristic-two field. Nothing this build can use.
        return Err(unsupported);
    }
    let (tag, prime) = field_id.next()?;
    if tag != TAG_INTEGER || !field_id.is_empty() {
        return Err(VaultError::NotAPrivateKey);
    }

    let (tag, curve) = fields.next()?;
    if tag != TAG_SEQUENCE {
        return Err(VaultError::NotAPrivateKey);
    }
    let mut curve = Tlvs::new(curve);
    let (tag_a, a) = curve.next()?;
    let (tag_b, b) = curve.next()?;
    if tag_a != TAG_OCTET_STRING || tag_b != TAG_OCTET_STRING {
        return Err(VaultError::NotAPrivateKey);
    }

    let (tag, base) = fields.next()?;
    if tag != TAG_OCTET_STRING {
        return Err(VaultError::NotAPrivateKey);
    }
    let (tag, order) = fields.next()?;
    if tag != TAG_INTEGER {
        return Err(VaultError::NotAPrivateKey);
    }
    if !fields.is_empty() {
        let (tag, cofactor) = fields.next()?;
        if tag != TAG_INTEGER {
            return Err(VaultError::NotAPrivateKey);
        }
        // All three curves have cofactor 1.
        if unsigned(cofactor) != [0x01] {
            return Err(unsupported);
        }
    }

    CURVES
        .iter()
        .copied()
        .find(|named| {
            unsigned(prime) == named.prime
                && unsigned(order) == named.order
                && unsigned(a) == unsigned(named.a)
                && unsigned(b) == unsigned(named.b)
                && same_point(base, named.generator, named.field_bytes)
        })
        .ok_or(unsupported)
}

/// The `SpecifiedECDomain` for a named curve, as a complete SEQUENCE TLV, in
/// the shape OpenSSL and LibreSSL write it: version 1, a seed, a cofactor.
///
/// For tests here and in `credential.rs`, which rebuild real `ssh-keygen` keys
/// into the explicit form macOS's `ssh-keygen` writes.
#[cfg(test)]
pub(crate) fn specified_domain_for_tests(
    oid: &[u8],
    compressed_generator: bool,
) -> Option<Vec<u8>> {
    let named = CURVES.iter().copied().find(|named| named.oid == oid)?;
    let integer = |magnitude: &[u8]| {
        // A leading zero keeps a high-bit magnitude positive (X.690 §8.3.2).
        let needs_zero = magnitude.first().is_some_and(|first| first & 0x80 != 0);
        let content = if needs_zero {
            concat(&[&[0x00], magnitude]).to_vec()
        } else {
            magnitude.to_vec()
        };
        tlv(TAG_INTEGER, &content).ok()
    };
    let generator = if compressed_generator {
        let odd = named.generator.last().is_some_and(|last| last & 1 == 1);
        let x = named.generator.get(1..=named.field_bytes)?;
        concat(&[&[if odd { 0x03 } else { 0x02 }], x]).to_vec()
    } else {
        named.generator.to_vec()
    };
    let field_id = tlv(
        TAG_SEQUENCE,
        &concat(&[
            &tlv(TAG_OID, &OID_PRIME_FIELD).ok()?,
            &integer(named.prime)?,
        ]),
    )
    .ok()?;
    // BIT STRING, no unused bits, twenty octets of seed.
    let seed = concat(&[&[0x03, 0x15, 0x00], &[0xC4; 20]]);
    let curve = tlv(
        TAG_SEQUENCE,
        &concat(&[
            &tlv(TAG_OCTET_STRING, named.a).ok()?,
            &tlv(TAG_OCTET_STRING, named.b).ok()?,
            &seed,
        ]),
    )
    .ok()?;
    let domain = concat(&[
        &[TAG_INTEGER, 0x01, 0x01],
        &field_id,
        &curve,
        &tlv(TAG_OCTET_STRING, &generator).ok()?,
        &integer(named.order)?,
        &[TAG_INTEGER, 0x01, 0x01],
    ]);
    tlv(TAG_SEQUENCE, &domain).ok().map(|out| out.to_vec())
}

/// An integer's magnitude without its leading zero octets.
fn unsigned(value: &[u8]) -> &[u8] {
    let first = value
        .iter()
        .position(|octet| *octet != 0)
        .unwrap_or(value.len());
    value.get(first..).unwrap_or_default()
}

/// Whether `encoded` is `generator`, in either point form SEC 1 §2.3.3 allows.
///
/// The compressed form carries `x` and the parity of `y`; it names the
/// generator when both match. Deriving `y` would need field arithmetic, and
/// checking the parity against the known point is the same test.
fn same_point(encoded: &[u8], generator: &[u8], field_bytes: usize) -> bool {
    match encoded.split_first() {
        Some((0x04, _)) => encoded == generator,
        Some((prefix @ (0x02 | 0x03), x)) => {
            let known_x = generator.get(1..=field_bytes);
            let y_is_odd = generator.last().is_some_and(|last| last & 1 == 1);
            known_x == Some(x) && (*prefix == 0x03) == y_is_odd
        }
        _ => false,
    }
}

// ------------------------------------------- inspecting an encrypted one ---

// The algorithm identifiers an `EncryptedPrivateKeyInfo` can name, as the
// content octets of their OBJECT IDENTIFIER — the bytes after the `06 len`.
// Comparing the encoded form rather than a decoded arc list keeps this to one
// slice comparison and removes the only place an arithmetic slip could put the
// wrong name in a refusal.

/// `id-PBES2`, 1.2.840.113549.1.5.13 (RFC 8018 §A.4).
const OID_PBES2: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];
/// `id-PBKDF2`, 1.2.840.113549.1.5.12 (RFC 8018 §A.2).
const OID_PBKDF2: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C];
/// `id-scrypt`, 1.3.6.1.4.1.11591.4.11 (RFC 7914 §7).
const OID_SCRYPT: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x04, 0x0B];

/// `aes128-CBC-PAD`, 2.16.840.1.101.3.4.1.2 (RFC 3565 §4.1).
const OID_AES128_CBC: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02];
/// `aes192-CBC-PAD`, 2.16.840.1.101.3.4.1.22.
const OID_AES192_CBC: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16];
/// `aes256-CBC-PAD`, 2.16.840.1.101.3.4.1.42.
const OID_AES256_CBC: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A];

/// `des-EDE3-CBC`, 1.2.840.113549.3.7 (RFC 8018 §B.2.2).
const OID_DES_EDE3_CBC: [u8; 8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07];
/// `desCBC`, 1.3.14.3.2.7 (RFC 8018 §B.2.1).
const OID_DES_CBC: [u8; 5] = [0x2B, 0x0E, 0x03, 0x02, 0x07];
/// `rc2CBC`, 1.2.840.113549.3.2 (RFC 8018 §B.2.3).
const OID_RC2_CBC: [u8; 8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x02];

/// The first six octets of every `pkcs-5` and `pkcs-12` arc:
/// `1.2.840.113549.1`. What follows is `5` for the PBES1 schemes of
/// RFC 8018 §A.3 and `12` for the PKCS#12 ones.
const OID_PKCS_PREFIX: [u8; 6] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D];

/// `hmacWithSHA1`, 1.2.840.113549.2.7, `hmacWithSHA224` at `.8`, and its
/// SHA-256, SHA-384 and SHA-512 siblings at `.9`, `.10` and `.11`
/// (RFC 8018 §B.1.2).
///
/// HMAC-SHA-1 is RFC 8018 §A.2's DEFAULT, so it is usually written by leaving
/// the field out; that absence is read as `.7`. It used to be excluded because
/// the SSH parser downstream refused it, which made every passphrase-protected
/// PKCS#8 key `ssh-keygen` writes on Windows unusable. `remoter-proto-ssh` now
/// enables `pkcs5`'s `sha1-insecure` feature, and this list follows it.
const PBKDF2_PRFS_READ_HERE: [[u8; 8]; 5] = [
    [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07],
    [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08],
    [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09],
    [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A],
    [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B],
];

/// Whether the SSH parser downstream could open this `EncryptedPrivateKeyInfo`,
/// given the right passphrase.
///
/// An encrypted PKCS#8 document is stored ciphertext and all — the vault never
/// deciphers one — so nothing here proves the passphrase. What it decides is
/// the question that *is* answerable from the file alone, before anyone has
/// typed anything: whether the scheme the document names is one this build can
/// read at all.
///
/// It has to be answered here because the alternative is where this build was:
/// `openssl genrsa -des3` on OpenSSL 3.x writes an `ENCRYPTED PRIVATE KEY`
/// under PBES2 with `des-ede3-cbc`, the file inspected cleanly, the passphrase
/// was asked for and sealed, and the key then failed at connect time as
/// "the server rejected these credentials" — a long way from the file, and
/// after the user had every reason to believe the import worked.
///
/// The readable set is PBES2 — PBKDF2 with an HMAC-SHA-2 pseudorandom function,
/// or scrypt — over AES-128, AES-192 or AES-256 in CBC mode. That is what
/// `ssh-keygen -m PKCS8` and `openssl pkcs8 -topk8` write by default, and it is
/// established by experiment rather than by reading: `credential_tests` in
/// `remoter-ipc` writes one document per scheme with the system's own OpenSSL
/// and requires this function's verdict to match what the SSH parser then does
/// with it.
///
/// **It refuses only what it can prove unreadable.** Everything below walks the
/// document with the reader in this module, and a document that does not walk —
/// a length that runs long, a field where a `SEQUENCE` was expected — comes back
/// accepted rather than refused. The authority on whether a key parses is the
/// key parser, which reads the whole document; a second, partial parser that
/// refused what it could not follow would turn its own gaps into refusals of
/// files this build stores perfectly well today. Being unable to decide is not
/// evidence, and only evidence refuses a key.
///
/// # Errors
///
/// [`VaultError::UnsupportedKeyCipher`] naming the scheme, and nothing else.
pub(crate) fn check_encrypted_readable(der: &[u8]) -> Result<(), VaultError> {
    match unreadable_scheme(der) {
        Some(named) => Err(VaultError::UnsupportedKeyCipher(named)),
        None => Ok(()),
    }
}

/// The clause naming why this document cannot be opened here, or `None` when it
/// can be — or when the shape of it left the question undecided.
fn unreadable_scheme(der: &[u8]) -> Option<&'static str> {
    let mut document = Tlvs::new(der);
    let (tag, fields) = document.next().ok()?;
    if tag != TAG_SEQUENCE || !document.is_empty() {
        return None;
    }

    // RFC 5958 §3: the algorithm identifier, then the ciphertext. The
    // ciphertext is not looked at at all.
    let mut fields = Tlvs::new(fields);
    let (tag, algorithm) = fields.next().ok()?;
    if tag != TAG_SEQUENCE {
        return None;
    }

    let mut algorithm = Tlvs::new(algorithm);
    let (tag, oid) = algorithm.next().ok()?;
    if tag != TAG_OID {
        return None;
    }
    if oid != OID_PBES2.as_slice() {
        return Some(outer_scheme_name(oid));
    }

    // RFC 8018 §A.4: `PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }`.
    let (tag, parameters) = algorithm.next().ok()?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let mut parameters = Tlvs::new(parameters);
    let (tag, derivation) = parameters.next().ok()?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let (tag, encryption) = parameters.next().ok()?;
    if tag != TAG_SEQUENCE {
        return None;
    }

    unreadable_derivation(derivation).or_else(|| unreadable_encryption(encryption))
}

/// The `keyDerivationFunc` half of a `PBES2-params`.
fn unreadable_derivation(algorithm: &[u8]) -> Option<&'static str> {
    let mut algorithm = Tlvs::new(algorithm);
    let (tag, oid) = algorithm.next().ok()?;
    if tag != TAG_OID {
        return None;
    }
    // scrypt carries no choice this build could refuse: there is one function
    // and the parameters are numbers.
    if oid == OID_SCRYPT.as_slice() {
        return None;
    }
    if oid != OID_PBKDF2.as_slice() {
        return Some("it is a PKCS#8 container whose key derivation this build does not recognise");
    }

    let (tag, parameters) = algorithm.next().ok()?;
    if tag != TAG_SEQUENCE {
        return None;
    }

    // RFC 8018 §A.2: `salt`, `iterationCount`, an OPTIONAL `keyLength`, and an
    // OPTIONAL `prf` that DEFAULTs to `hmacWithSHA1`. The salt may itself be an
    // AlgorithmIdentifier, so the pseudorandom function is found as the last
    // SEQUENCE rather than the only one.
    let mut fields = Tlvs::new(parameters);
    // The salt, whichever of the two CHOICE alternatives it took. Skipped
    // rather than read: nothing here derives a key.
    fields.next().ok()?;
    let mut prf: Option<&[u8]> = None;
    while !fields.is_empty() {
        let (tag, value) = fields.next().ok()?;
        if tag == TAG_SEQUENCE {
            prf = Some(value);
        }
    }

    // Absent means `hmacWithSHA1` (RFC 8018 §A.2), which is how OpenSSL 1.x
    // wrote every `-v2` document and how Windows' `ssh-keygen` writes them
    // still. It is in the readable set, so there is nothing to refuse.
    let prf = prf?;
    let mut prf = Tlvs::new(prf);
    let (tag, oid) = prf.next().ok()?;
    if tag != TAG_OID {
        return None;
    }
    if PBKDF2_PRFS_READ_HERE
        .iter()
        .any(|known| known.as_slice() == oid)
    {
        return None;
    }
    Some(PBKDF2_PRF_UNKNOWN)
}

/// The `encryptionScheme` half of a `PBES2-params`.
fn unreadable_encryption(algorithm: &[u8]) -> Option<&'static str> {
    let mut algorithm = Tlvs::new(algorithm);
    let (tag, oid) = algorithm.next().ok()?;
    if tag != TAG_OID {
        return None;
    }
    if oid == OID_AES128_CBC.as_slice()
        || oid == OID_AES192_CBC.as_slice()
        || oid == OID_AES256_CBC.as_slice()
    {
        return None;
    }
    Some(cipher_name(oid))
}

/// The clause for a PBKDF2 whose pseudorandom function is none of the five
/// this build derives with.
const PBKDF2_PRF_UNKNOWN: &str = "it is a PKCS#8 container whose PBKDF2 derives its key with a \
                                  pseudorandom function this build does not recognise";

/// Names the scheme an `EncryptedPrivateKeyInfo` declares, when it is not
/// PBES2.
///
/// Only the families are named, never the OID's own digits: the document was
/// written by someone else, and an error message assembled out of its bytes is
/// a message that file got to write.
fn outer_scheme_name(oid: &[u8]) -> &'static str {
    // `1.2.840.113549.1.5.x` for the PBES1 schemes of RFC 8018 §A.3 and
    // `1.2.840.113549.1.12.1.x` for the PKCS#12 ones. Both derive with MD5 or
    // SHA-1 into DES or RC2, and neither is implemented here.
    let Some(arc) = oid.strip_prefix(OID_PKCS_PREFIX.as_slice()) else {
        return "it is a PKCS#8 container using an encryption scheme this build does not \
                recognise";
    };
    match arc {
        [0x01, 0x05, ..] => {
            "it is a PKCS#8 container using the superseded PKCS#5 v1.5 encryption schemes, \
             which the key parser in this build refuses"
        }
        [0x01, 0x0C, ..] => {
            "it is a PKCS#8 container using the PKCS#12 encryption schemes, which the key \
             parser in this build refuses"
        }
        _ => "it is a PKCS#8 container using an encryption scheme this build does not recognise",
    }
}

// --------------------------------------------- opening an encrypted one ---

/// The largest PBKDF2 iteration count this build will run.
///
/// OpenSSL writes 2048, `ssh-keygen -m PKCS8` writes rather more, and a file
/// may declare any number at all. The bound is what stops a document written by
/// someone else from making the import spin for minutes: it is far above any
/// cost a tool chooses and far below one that would be felt.
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;

/// The most memory this build will let an scrypt derivation ask for, in bytes.
///
/// RFC 7914 §2: the working buffer is 128·r·N, and the document chooses both.
/// `openssl pkcs8 -scrypt` writes N = 16384 and r = 8, which is sixteen
/// megabytes; the bound is sixteen times that, so every real file clears it and
/// a document declaring N = 2^30 is refused rather than allocating until the
/// application dies. Bounding the product rather than each factor is the point:
/// separate ceilings on N, r and p multiply into a number nobody chose.
const MAX_SCRYPT_BYTES: u64 = 256 * 1024 * 1024;

/// The largest parallelism this build will run. RFC 7914 §2 multiplies the work
/// by `p` without multiplying the memory, so it needs a bound of its own.
const MAX_SCRYPT_P: u32 = 16;

/// The clause for a derivation whose declared cost this build refuses to run.
const COST_REFUSED: &str = "it is a PKCS#8 container whose key derivation declares a cost higher \
                            than this build will attempt, so the passphrase cannot be checked";

/// The clause for a document whose ASN.1 does not walk far enough to decipher.
///
/// Distinct from every clause in [`unreadable_scheme`], which refuses only what
/// it can prove: a document that cannot be walked is not proof of anything, and
/// the honest thing to say is that the passphrase could not be tried rather
/// than that it was wrong.
const SHAPE_UNREADABLE: &str = "its PKCS#8 encryption parameters do not decode, so the passphrase \
                                cannot be tried against them";

/// Whether `passphrase` opens this `EncryptedPrivateKeyInfo`.
///
/// The vault stores an encrypted PKCS#8 document as it stands, ciphertext and
/// all, so nothing downstream of the import ever checks the passphrase against
/// it until a session is being opened — which is where a wrong one used to
/// surface, as a rejection by a server that had not seen the key. This is that
/// check, moved to the moment the passphrase is offered.
///
/// The scheme set is the one [`check_encrypted_readable`] already accepts:
/// PBES2 over PBKDF2 with an HMAC-SHA-2 pseudorandom function, or scrypt, into
/// AES-128, AES-192 or AES-256 in CBC mode. A document outside it has been
/// refused before reaching here.
///
/// # What counts as proof
///
/// The cipher carries no authentication tag, so the answer is assembled from
/// the plaintext: the PKCS#7 padding has to check out, and what is left has to
/// be a `PrivateKeyInfo` — a DER `SEQUENCE` filling the buffer exactly, whose
/// first field is the `version` INTEGER (RFC 5958 §2). A wrong passphrase gets
/// past the padding about once in 256 tries and past the rest about once in
/// 2^24, which is the difference between a check and a formality.
///
/// # Errors
///
/// [`VaultError::KeyPassphraseRejected`] when the document was deciphered with
/// this passphrase and the result is not a `PrivateKeyInfo`;
/// [`VaultError::KeyPassphraseUncheckable`] when the scheme, the cost or the
/// shape of the document means the question cannot be answered here.
pub(crate) fn check_passphrase(der: &[u8], passphrase: &[u8]) -> Result<(), VaultError> {
    // Anything this build *can* prove unreadable is refused with the clause
    // that names it, rather than being reported as a shape that would not walk.
    check_encrypted_readable(der)?;

    let (derivation, encryption, ciphertext) = parts(der)?;
    let cipher = cipher_for(encryption.oid)?;
    let key = derive(&derivation, cipher.key_len(), passphrase)?;

    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let plaintext_len = cipher
        .decipher(&key, encryption.iv, buffer.as_mut_slice())?
        .len();
    buffer.truncate(plaintext_len);

    if is_private_key_info(&buffer) {
        Ok(())
    } else {
        Err(VaultError::KeyPassphraseRejected)
    }
}

/// Whether a buffer is a `PrivateKeyInfo` (RFC 5958 §2).
///
/// Structure only: the key material itself is never examined, and a key type
/// this build does not implement is still a key someone may want stored.
pub(crate) fn is_private_key_info(plaintext: &[u8]) -> bool {
    let mut document = Tlvs::new(plaintext);
    let Ok((tag, body)) = document.next() else {
        return false;
    };
    // The SEQUENCE has to be the whole buffer: a declared length shorter than
    // what the cipher produced is a coincidence, not a document.
    if tag != TAG_SEQUENCE || !document.is_empty() {
        return false;
    }
    let mut fields = Tlvs::new(body);
    matches!(fields.next(), Ok((TAG_INTEGER, _)))
}

/// The `keyDerivationFunc`, the `encryptionScheme` and the ciphertext of an
/// `EncryptedPrivateKeyInfo` under PBES2.
fn parts(der: &[u8]) -> Result<(Derivation<'_>, Encryption<'_>, &[u8]), VaultError> {
    let uncheckable = || VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE);

    let mut document = Tlvs::new(der);
    let (tag, fields) = document.next().map_err(|_| uncheckable())?;
    if tag != TAG_SEQUENCE || !document.is_empty() {
        return Err(uncheckable());
    }

    let mut fields = Tlvs::new(fields);
    let (tag, algorithm) = fields.next().map_err(|_| uncheckable())?;
    if tag != TAG_SEQUENCE {
        return Err(uncheckable());
    }
    let (tag, ciphertext) = fields.next().map_err(|_| uncheckable())?;
    if tag != TAG_OCTET_STRING {
        return Err(uncheckable());
    }

    let mut algorithm = Tlvs::new(algorithm);
    let (tag, oid) = algorithm.next().map_err(|_| uncheckable())?;
    if tag != TAG_OID || oid != OID_PBES2.as_slice() {
        return Err(uncheckable());
    }
    let (tag, parameters) = algorithm.next().map_err(|_| uncheckable())?;
    if tag != TAG_SEQUENCE {
        return Err(uncheckable());
    }

    let mut parameters = Tlvs::new(parameters);
    let (tag, derivation) = parameters.next().map_err(|_| uncheckable())?;
    if tag != TAG_SEQUENCE {
        return Err(uncheckable());
    }
    let (tag, encryption) = parameters.next().map_err(|_| uncheckable())?;
    if tag != TAG_SEQUENCE {
        return Err(uncheckable());
    }

    Ok((
        read_derivation(derivation)?,
        read_encryption(encryption)?,
        ciphertext,
    ))
}

/// A `keyDerivationFunc`, read.
enum Derivation<'a> {
    /// PBKDF2 (RFC 8018 §A.2), with the pseudorandom function resolved.
    Pbkdf2 {
        salt: &'a [u8],
        iterations: u32,
        prf: Prf,
        key_length: Option<u32>,
    },
    /// scrypt (RFC 7914 §7).
    Scrypt {
        salt: &'a [u8],
        log_n: u8,
        r: u32,
        p: u32,
        key_length: Option<u32>,
    },
}

/// The PBKDF2 pseudorandom functions this build derives with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prf {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// An `encryptionScheme`, read.
struct Encryption<'a> {
    oid: &'a [u8],
    iv: &'a [u8],
}

fn read_derivation(algorithm: &[u8]) -> Result<Derivation<'_>, VaultError> {
    let uncheckable = || VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE);

    let mut algorithm = Tlvs::new(algorithm);
    let (tag, oid) = algorithm.next().map_err(|_| uncheckable())?;
    if tag != TAG_OID {
        return Err(uncheckable());
    }
    let (tag, parameters) = algorithm.next().map_err(|_| uncheckable())?;
    if tag != TAG_SEQUENCE {
        return Err(uncheckable());
    }
    let mut parameters = Tlvs::new(parameters);

    if oid == OID_SCRYPT.as_slice() {
        let (tag, salt) = parameters.next().map_err(|_| uncheckable())?;
        if tag != TAG_OCTET_STRING {
            return Err(uncheckable());
        }
        let n = integer(&mut parameters)?;
        let r = integer(&mut parameters)?;
        let p = integer(&mut parameters)?;
        // RFC 7914 §2 requires N to be a power of two, which is what makes
        // `log2` exact rather than a rounding.
        if !n.is_power_of_two() {
            return Err(VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE));
        }
        let log_n = u8::try_from(n.trailing_zeros()).map_err(|_| uncheckable())?;
        // 128·r·N, in `u64` so the multiplication cannot wrap on a 32-bit
        // target before it is compared.
        let bytes = u64::from(r)
            .checked_mul(u64::from(n))
            .and_then(|product| product.checked_mul(128));
        if p == 0 || p > MAX_SCRYPT_P || bytes.is_none_or(|bytes| bytes > MAX_SCRYPT_BYTES) {
            return Err(VaultError::KeyPassphraseUncheckable(COST_REFUSED));
        }
        let key_length = if parameters.is_empty() {
            None
        } else {
            integer(&mut parameters).ok()
        };
        return Ok(Derivation::Scrypt {
            salt,
            log_n,
            r,
            p,
            key_length,
        });
    }

    if oid != OID_PBKDF2.as_slice() {
        return Err(uncheckable());
    }

    let (tag, salt) = parameters.next().map_err(|_| uncheckable())?;
    if tag != TAG_OCTET_STRING {
        // The `otherSource` alternative of the salt CHOICE names a function
        // nothing implements. Undecided rather than rejected.
        return Err(uncheckable());
    }
    let iterations = integer(&mut parameters)?;
    if iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS {
        return Err(VaultError::KeyPassphraseUncheckable(COST_REFUSED));
    }

    // `keyLength` and `prf` are both OPTIONAL, and only the second is a
    // SEQUENCE, so they are told apart by tag rather than by position.
    let mut key_length = None;
    let mut prf = None;
    while !parameters.is_empty() {
        let (tag, value) = parameters.next().map_err(|_| uncheckable())?;
        match tag {
            TAG_INTEGER => key_length = be_u32(value).ok(),
            TAG_SEQUENCE => prf = Some(value),
            _ => return Err(uncheckable()),
        }
    }

    // Absent means `hmacWithSHA1` (RFC 8018 §A.2).
    let prf = match prf {
        None => Prf::Sha1,
        Some(prf) => {
            let mut prf = Tlvs::new(prf);
            let (tag, oid) = prf.next().map_err(|_| uncheckable())?;
            if tag != TAG_OID {
                return Err(uncheckable());
            }
            prf_for(oid).ok_or_else(uncheckable)?
        }
    };

    Ok(Derivation::Pbkdf2 {
        salt,
        iterations,
        prf,
        key_length,
    })
}

/// The pseudorandom function an OID names, of the four this build derives with.
///
/// Matched against the OID itself rather than against a position in
/// [`PBKDF2_PRFS_READ_HERE`]. The list is there to decide *whether* a document
/// is readable and says nothing about order; deriving with the wrong hash
/// because someone sorted it would refuse every correct passphrase under that
/// scheme, silently and in a way no reader of either place would suspect.
fn prf_for(oid: &[u8]) -> Option<Prf> {
    // RFC 8018 §B.1.2: `hmacWithSHA1` at 1.2.840.113549.2.7, `hmacWithSHA224`
    // at .8, and its SHA-256, SHA-384 and SHA-512 siblings at .9, .10 and .11.
    match oid {
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07] => Some(Prf::Sha1),
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08] => Some(Prf::Sha224),
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09] => Some(Prf::Sha256),
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A] => Some(Prf::Sha384),
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B] => Some(Prf::Sha512),
        _ => None,
    }
}

fn read_encryption(algorithm: &[u8]) -> Result<Encryption<'_>, VaultError> {
    let uncheckable = || VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE);

    let mut algorithm = Tlvs::new(algorithm);
    let (tag, oid) = algorithm.next().map_err(|_| uncheckable())?;
    if tag != TAG_OID {
        return Err(uncheckable());
    }
    let (tag, iv) = algorithm.next().map_err(|_| uncheckable())?;
    if tag != TAG_OCTET_STRING {
        return Err(uncheckable());
    }
    Ok(Encryption { oid, iv })
}

/// The next field as an INTEGER, refused if it is not one or does not fit.
fn integer(fields: &mut Tlvs<'_>) -> Result<u32, VaultError> {
    let (tag, value) = fields
        .next()
        .map_err(|_| VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE))?;
    if tag != TAG_INTEGER {
        return Err(VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE));
    }
    be_u32(value)
}

/// A DER INTEGER's content octets as a `u32`.
///
/// DER writes the minimum number of octets, with a leading zero where the top
/// bit would otherwise read as a sign. A value wider than a `u32` is past every
/// cost bound this module enforces, so it is refused as a cost rather than
/// truncated.
fn be_u32(value: &[u8]) -> Result<u32, VaultError> {
    let significant = value
        .iter()
        .position(|octet| *octet != 0)
        .map_or(&[][..], |first| value.get(first..).unwrap_or_default());
    if significant.len() > 4 {
        return Err(VaultError::KeyPassphraseUncheckable(COST_REFUSED));
    }
    let mut out = 0u32;
    for octet in significant {
        out = out
            .checked_mul(0x100)
            .and_then(|shifted| shifted.checked_add(u32::from(*octet)))
            .ok_or(VaultError::KeyPassphraseUncheckable(COST_REFUSED))?;
    }
    Ok(out)
}

/// Runs the derivation a document declares.
fn derive(
    derivation: &Derivation<'_>,
    key_len: usize,
    passphrase: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let declared = match derivation {
        Derivation::Pbkdf2 { key_length, .. } | Derivation::Scrypt { key_length, .. } => {
            *key_length
        }
    };
    // A `keyLength` that disagrees with the cipher's own width is a document
    // this build cannot follow: deriving the cipher's width anyway would be a
    // guess, and deriving the declared width would hand the cipher a key of the
    // wrong size.
    if declared.is_some_and(|declared| usize::try_from(declared) != Ok(key_len)) {
        return Err(VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE));
    }

    let mut key = Zeroizing::new(vec![0u8; key_len]);
    match *derivation {
        Derivation::Pbkdf2 {
            salt,
            iterations,
            prf,
            ..
        } => match prf {
            Prf::Sha1 => {
                pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, salt, iterations, &mut key);
            }
            Prf::Sha224 => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha224>(passphrase, salt, iterations, &mut key);
            }
            Prf::Sha256 => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase, salt, iterations, &mut key);
            }
            Prf::Sha384 => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha384>(passphrase, salt, iterations, &mut key);
            }
            Prf::Sha512 => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha512>(passphrase, salt, iterations, &mut key);
            }
        },
        Derivation::Scrypt {
            salt, log_n, r, p, ..
        } => {
            let params = scrypt::Params::new(log_n, r, p)
                .map_err(|_| VaultError::KeyPassphraseUncheckable(COST_REFUSED))?;
            scrypt::scrypt(passphrase, salt, &params, &mut key)
                .map_err(|_| VaultError::KeyPassphraseUncheckable(COST_REFUSED))?;
        }
    }
    Ok(key)
}

/// A block cipher a PBES2 document can name and this build can run.
///
/// Every one is CBC, which is the whole readable set, so the variants are named
/// for the key width — the only thing that differs between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pbes2Cipher {
    Aes128,
    Aes192,
    Aes256,
}

impl Pbes2Cipher {
    const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    /// Deciphers in place, returning the plaintext with its PKCS#7 padding
    /// removed.
    ///
    /// A padding that does not check out is the commonest way a wrong
    /// passphrase shows itself, so it is reported as one.
    fn decipher<'b>(
        self,
        key: &[u8],
        iv: &[u8],
        buffer: &'b mut [u8],
    ) -> Result<&'b [u8], VaultError> {
        use cbc::cipher::block_padding::Pkcs7;
        use cbc::cipher::{BlockModeDecrypt, KeyIvInit};

        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE))?;
        let rejected = |_| VaultError::KeyPassphraseRejected;
        match self {
            Self::Aes128 => {
                let key: [u8; 16] = key
                    .try_into()
                    .map_err(|_| VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE))?;
                cbc::Decryptor::<aes::Aes128>::new(&key.into(), &iv.into())
                    .decrypt_padded::<Pkcs7>(buffer)
                    .map_err(rejected)
            }
            Self::Aes192 => {
                let key: [u8; 24] = key
                    .try_into()
                    .map_err(|_| VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE))?;
                cbc::Decryptor::<aes::Aes192>::new(&key.into(), &iv.into())
                    .decrypt_padded::<Pkcs7>(buffer)
                    .map_err(rejected)
            }
            Self::Aes256 => {
                let key: [u8; 32] = key
                    .try_into()
                    .map_err(|_| VaultError::KeyPassphraseUncheckable(SHAPE_UNREADABLE))?;
                cbc::Decryptor::<aes::Aes256>::new(&key.into(), &iv.into())
                    .decrypt_padded::<Pkcs7>(buffer)
                    .map_err(rejected)
            }
        }
    }
}

/// The cipher an `encryptionScheme` OID names, of the three read here.
fn cipher_for(oid: &[u8]) -> Result<Pbes2Cipher, VaultError> {
    if oid == OID_AES128_CBC.as_slice() {
        return Ok(Pbes2Cipher::Aes128);
    }
    if oid == OID_AES192_CBC.as_slice() {
        return Ok(Pbes2Cipher::Aes192);
    }
    if oid == OID_AES256_CBC.as_slice() {
        return Ok(Pbes2Cipher::Aes256);
    }
    Err(VaultError::UnsupportedKeyCipher(cipher_name(oid)))
}

/// Names the block cipher a PBES2 document declares, when it is not AES-CBC.
fn cipher_name(oid: &[u8]) -> &'static str {
    if oid == OID_DES_EDE3_CBC.as_slice() {
        return "it is a PKCS#8 container enciphered with des-ede3-cbc, and this build reads \
                only AES-128, AES-192 and AES-256 in CBC mode";
    }
    if oid == OID_DES_CBC.as_slice() {
        return "it is a PKCS#8 container enciphered with des-cbc, and this build reads only \
                AES-128, AES-192 and AES-256 in CBC mode";
    }
    if oid == OID_RC2_CBC.as_slice() {
        return "it is a PKCS#8 container enciphered with rc2-cbc, and this build reads only \
                AES-128, AES-192 and AES-256 in CBC mode";
    }
    "it is a PKCS#8 container enciphered with a cipher this build does not recognise"
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

/// Building the encrypted documents the tests read.
///
/// A fixture here carries no key material: what sits inside the envelope is
/// whatever the caller passes, which for these tests is either the smallest
/// well-formed `PrivateKeyInfo` or something deliberately shaped not to be one.
#[cfg(any(test, feature = "test-fixtures"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test fixtures, per the workspace convention"
)]
pub(crate) mod fixtures {
    use super::*;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

    /// The eight-byte salt and the single iteration every fixture derives with.
    ///
    /// One iteration because a fixture is not a key: the derivation is run once
    /// per assertion and its cost buys nothing here. `openssl` writes a real
    /// count, and `tests/key_passphrase.rs` reads what `openssl` writes.
    const SALT: [u8; 8] = [0x11; 8];
    const ITERATIONS: u32 = 1;

    /// An `EncryptedPrivateKeyInfo` (RFC 5958 §3) under PBES2 with
    /// PBKDF2-HMAC-SHA-256 over AES-256-CBC, holding `plaintext`.
    pub(crate) fn encrypted(plaintext: &[u8], passphrase: &[u8]) -> Vec<u8> {
        encrypted_declaring(plaintext, passphrase, ITERATIONS)
    }

    /// The same under a named pseudorandom function.
    ///
    /// The OID written into the document and the hash the fixture derives with
    /// are chosen together *here*, from the name, without consulting
    /// [`prf_for`]. That independence is the test: a mapping that sent
    /// `hmacWithSHA512` to SHA-224 would derive a different key from the one
    /// this fixture enciphered with, and the right passphrase would be refused.
    #[cfg(test)]
    pub(crate) fn encrypted_under_prf(
        plaintext: &[u8],
        passphrase: &[u8],
        prf: &str,
    ) -> Option<Vec<u8>> {
        let mut key = [0u8; 32];
        let oid: [u8; 8] = match prf {
            "sha1" => {
                pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, &SALT, ITERATIONS, &mut key);
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07]
            }
            "sha224" => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha224>(passphrase, &SALT, ITERATIONS, &mut key);
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08]
            }
            "sha256" => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase, &SALT, ITERATIONS, &mut key);
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09]
            }
            "sha384" => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha384>(passphrase, &SALT, ITERATIONS, &mut key);
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A]
            }
            "sha512" => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha512>(passphrase, &SALT, ITERATIONS, &mut key);
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B]
            }
            _ => return None,
        };
        Some(assemble(plaintext, &key, &oid, ITERATIONS))
    }

    /// A document that leaves the pseudorandom function out, as Windows'
    /// `ssh-keygen -m PKCS8` and OpenSSL 1.x write it, enciphered under the
    /// HMAC-SHA-1 that absence means (RFC 8018 §A.2).
    #[cfg(test)]
    pub(crate) fn encrypted_with_default_prf(plaintext: &[u8], passphrase: &[u8]) -> Vec<u8> {
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, &SALT, ITERATIONS, &mut key);
        assemble(plaintext, &key, &[], ITERATIONS)
    }

    /// The same, with the iteration count the document *declares* separated
    /// from the one it was enciphered with.
    ///
    /// They agree everywhere but in the test for a refused cost, where a
    /// document declaring ten million iterations has to exist without a fixture
    /// spending ten million iterations building it. Nothing deciphers such a
    /// document — the cost is refused before the derivation runs — so the two
    /// never have to agree there.
    pub(crate) fn encrypted_declaring(
        plaintext: &[u8],
        passphrase: &[u8],
        declared: u32,
    ) -> Vec<u8> {
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase, &SALT, ITERATIONS, &mut key);
        assemble(plaintext, &key, &HMAC_SHA256, declared)
    }

    /// The `EncryptedPrivateKeyInfo` envelope around `plaintext`, enciphered
    /// with `key` and declaring `prf` and `declared`.
    fn assemble(plaintext: &[u8], key: &[u8; 32], prf_oid: &[u8], declared: u32) -> Vec<u8> {
        let iv = [0x22u8; 16];

        let mut buffer = vec![0u8; plaintext.len() + 16];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&(*key).into(), &iv.into())
            .encrypt_padded::<Pkcs7>(&mut buffer, plaintext.len())
            .unwrap()
            .to_vec();

        // PBKDF2-params: the salt, the iteration count, and the pseudorandom
        // function — named explicitly, or left out when `prf_oid` is empty,
        // which is how writers declare the DEFAULT.
        let prf = if prf_oid.is_empty() {
            Vec::new()
        } else {
            seq(&[&oid(prf_oid), &[0x05, 0x00]])
        };
        let pbkdf2 = seq(&[
            &oid(&OID_PBKDF2),
            &seq(&[&der(TAG_OCTET_STRING, &SALT), &integer(declared), &prf]),
        ]);
        let encryption = seq(&[&oid(&OID_AES256_CBC), &der(TAG_OCTET_STRING, &iv)]);
        let algorithm = seq(&[&oid(&OID_PBES2), &seq(&[&pbkdf2, &encryption])]);
        seq(&[&algorithm, &der(TAG_OCTET_STRING, &ciphertext)])
    }

    /// `hmacWithSHA256`, 1.2.840.113549.2.9 (RFC 8018 §B.1.2).
    const HMAC_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09];

    /// A DER type-length-value. Every fixture is well under 128 bytes except
    /// the ciphertext, so both length forms are written.
    pub(crate) fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 0x80 {
            out.push(u8::try_from(value.len()).unwrap());
        } else {
            out.push(0x82);
            out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        }
        out.extend_from_slice(value);
        out
    }

    pub(crate) fn seq(parts: &[&[u8]]) -> Vec<u8> {
        der(TAG_SEQUENCE, &parts.concat())
    }

    fn oid(arcs: &[u8]) -> Vec<u8> {
        der(TAG_OID, arcs)
    }

    /// A DER INTEGER: the minimum number of octets, with a leading zero where
    /// the top bit would otherwise read as a sign (X.690 §8.3).
    fn integer(value: u32) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let first = bytes.iter().position(|octet| *octet != 0).unwrap_or(3);
        let mut content = Vec::new();
        if bytes[first] & 0x80 != 0 {
            content.push(0);
        }
        content.extend_from_slice(&bytes[first..]);
        der(TAG_INTEGER, &content)
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
    use super::fixtures::{
        encrypted, encrypted_declaring, encrypted_under_prf, encrypted_with_default_prf, seq,
    };
    use super::*;

    /// `SEQUENCE { INTEGER 0 }`, the smallest well-formed body the wrapper
    /// accepts. No key material, because none is needed to test the envelope.
    const TINY_SEQUENCE: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x00];

    /// What `check_passphrase` said, in one word, so an assertion can print it.
    fn opened(result: Result<(), VaultError>) -> String {
        match result {
            Ok(()) => String::from("<accepted>"),
            Err(VaultError::KeyPassphraseRejected) => String::from("rejected"),
            Err(VaultError::KeyPassphraseUncheckable(clause)) => clause.to_owned(),
            Err(other) => format!("<{other}>"),
        }
    }

    #[test]
    fn the_right_passphrase_opens_an_encrypted_document_and_a_wrong_one_does_not() {
        let document = encrypted(&TINY_SEQUENCE, b"open sesame");
        assert_eq!(
            opened(check_passphrase(&document, b"open sesame")),
            "<accepted>"
        );
        assert_eq!(
            opened(check_passphrase(&document, b"not the passphrase")),
            "rejected"
        );
    }

    /// Valid padding is not proof, and this is the document that says so.
    ///
    /// A wrong passphrase gets past the PKCS#7 padding check about once in 256
    /// tries, because one byte of 0x01 at the end is all that form of padding
    /// requires. What catches the rest is the structure underneath: RFC 5958 §2
    /// says the plaintext is a `PrivateKeyInfo`, so a buffer that deciphers to
    /// anything else did not come from the right passphrase.
    ///
    /// The fixture is that case made certain rather than waited for: its
    /// plaintext is padded exactly as a cipher would pad it, and is not a
    /// `PrivateKeyInfo`. Without the structural check this document is accepted.
    #[test]
    fn well_formed_padding_over_something_that_is_not_a_key_is_still_a_rejection() {
        for plaintext in [
            // Not DER at all.
            &[0xAAu8; 15][..],
            // A SEQUENCE that does not fill the buffer: a length that stops
            // short is a coincidence, not a document.
            &seq(&[&TINY_SEQUENCE])[..1],
            // A SEQUENCE whose first field is not the `version` INTEGER.
            &seq(&[&[0x04, 0x01, 0x00]])[..],
        ] {
            let document = encrypted(plaintext, b"open sesame");
            assert_eq!(
                opened(check_passphrase(&document, b"open sesame")),
                "rejected",
                "a deciphered body that is not a PrivateKeyInfo was accepted"
            );
        }
    }

    /// Every pseudorandom function this build claims to read, read.
    ///
    /// The claim is made in two places — `PBKDF2_PRFS_READ_HERE`, which decides
    /// whether a document is accepted at all, and [`prf_for`], which decides
    /// which hash to derive with — and a document accepted by the first and
    /// misread by the second refuses a correct passphrase without anything
    /// saying so. The fixture picks its OID and its hash together from the
    /// name, so a mapping that disagrees with the OID shows up as a rejection.
    #[test]
    fn every_pseudorandom_function_this_build_accepts_is_one_it_derives_with() {
        let mut checked = 0usize;
        for name in ["sha1", "sha224", "sha256", "sha384", "sha512"] {
            let Some(document) = encrypted_under_prf(&TINY_SEQUENCE, b"open sesame", name) else {
                panic!("the fixture could not write {name}");
            };
            checked = checked.saturating_add(1);
            assert_eq!(
                opened(check_passphrase(&document, b"open sesame")),
                "<accepted>",
                "{name}: accepted by the readable-scheme list and misread by the derivation"
            );
            assert_eq!(
                opened(check_passphrase(&document, b"not the passphrase")),
                "rejected",
                "for {name}"
            );
        }
        assert_eq!(checked, 5, "every function in the list has to be exercised");
    }

    /// A pseudorandom function left out means HMAC-SHA-1, and is read as that.
    ///
    /// The shape every passphrase-protected PKCS#8 key made by `ssh-keygen` on
    /// Windows has. It used to be refused outright, so none of those keys could
    /// be imported.
    #[test]
    fn a_document_that_leaves_the_pseudorandom_function_out_derives_with_hmac_sha1() {
        let document = encrypted_with_default_prf(&TINY_SEQUENCE, b"open sesame");
        assert_eq!(check_encrypted_readable(&document).ok(), Some(()));
        assert_eq!(
            opened(check_passphrase(&document, b"open sesame")),
            "<accepted>"
        );
        assert_eq!(opened(check_passphrase(&document, b"not it")), "rejected");
    }

    /// scrypt is bounded by the memory it will actually ask for.
    ///
    /// RFC 7914 §2 lets the document choose both N and r, and the buffer is
    /// their product: three separate ceilings would multiply into a number
    /// nobody picked, which is how a file gets to decide how much memory this
    /// process allocates.
    #[test]
    fn an_scrypt_cost_is_bounded_by_the_memory_it_asks_for() {
        // N = 2^20 with r = 8 is a gigabyte, under any per-factor ceiling that
        // would let `openssl -scrypt`'s own N = 16384, r = 8 through.
        let refused = scrypt_derivation(1 << 20, 8, 1);
        assert!(
            matches!(
                read_derivation(&refused),
                Err(VaultError::KeyPassphraseUncheckable(COST_REFUSED))
            ),
            "a gigabyte of scrypt was accepted"
        );
        // What OpenSSL writes is not refused.
        assert!(read_derivation(&scrypt_derivation(16384, 8, 1)).is_ok());
        // Nor is a large N with a small r, which is the same memory.
        assert!(read_derivation(&scrypt_derivation(1 << 20, 1, 1)).is_ok());
        // Parallelism multiplies the work without multiplying the buffer, so it
        // is bounded on its own.
        assert!(read_derivation(&scrypt_derivation(16384, 8, 1_000)).is_err());
    }

    /// The content of a `keyDerivationFunc` naming scrypt with `n`, `r` and `p`
    /// (RFC 7914 §7) — the OID and its parameters, which is what
    /// [`read_derivation`] is handed.
    fn scrypt_derivation(n: u32, r: u32, p: u32) -> Vec<u8> {
        let integer = |value: u32| {
            let bytes = value.to_be_bytes();
            let first = bytes.iter().position(|octet| *octet != 0).unwrap_or(3);
            let mut content = Vec::new();
            if bytes[first] & 0x80 != 0 {
                content.push(0);
            }
            content.extend_from_slice(&bytes[first..]);
            super::fixtures::der(TAG_INTEGER, &content)
        };
        [
            super::fixtures::der(TAG_OID, &OID_SCRYPT),
            seq(&[
                &super::fixtures::der(TAG_OCTET_STRING, &[0u8; 8]),
                &integer(n),
                &integer(r),
                &integer(p),
            ]),
        ]
        .concat()
    }

    /// A cost nobody would choose is refused before it is run, and refusing it
    /// is not the same answer as refusing the passphrase.
    #[test]
    fn a_derivation_cost_this_build_will_not_run_says_so() {
        let over = encrypted_declaring(
            &TINY_SEQUENCE,
            b"open sesame",
            MAX_PBKDF2_ITERATIONS.saturating_add(1),
        );
        let clause = opened(check_passphrase(&over, b"open sesame"));
        assert!(clause.contains("cost"), "{clause}");

        // The bound is a bound and not a wall. Read through `parts`, which is
        // where the cost is decided, so that asserting it does not mean running
        // ten million iterations of a debug build.
        let at_the_bound =
            encrypted_declaring(&TINY_SEQUENCE, b"open sesame", MAX_PBKDF2_ITERATIONS);
        assert!(
            parts(&at_the_bound).is_ok(),
            "a cost at the bound was refused rather than run"
        );
        assert!(
            parts(&over).is_err(),
            "a cost past the bound was accepted for deriving"
        );
    }

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

    /// An `ECPrivateKey` with this scalar, these `parameters [0]` contents and
    /// a public key. The arithmetic is not checked by the code under test, so
    /// the point need not match the scalar.
    fn sec1(scalar: &[u8], parameters: &[u8]) -> Vec<u8> {
        let body = concat(&[
            &EC_VERSION_V1,
            &tlv(TAG_OCTET_STRING, scalar).unwrap(),
            &tlv(TAG_CONTEXT_0, parameters).unwrap(),
            &tlv(TAG_CONTEXT_1, &[0x03, 0x03, 0x00, 0x04, 0x01]).unwrap(),
        ]);
        tlv(TAG_SEQUENCE, &body).unwrap().to_vec()
    }

    fn named(oid: &[u8]) -> Vec<u8> {
        tlv(TAG_OID, oid).unwrap().to_vec()
    }

    #[test]
    fn explicit_parameters_for_a_known_curve_become_that_curve() {
        // What `ssh-keygen` linked against macOS's LibreSSL writes. The result
        // must be byte-for-byte what the named form produces: same key, same
        // container, nothing downstream able to tell the two apart.
        for curve in CURVES {
            let scalar = vec![0x5A; curve.field_bytes];
            let explicit = specified_domain_for_tests(curve.oid, false).unwrap();
            assert_eq!(
                from_sec1_ec(&sec1(&scalar, &explicit)).unwrap(),
                from_sec1_ec(&sec1(&scalar, &named(curve.oid))).unwrap(),
                "field of {} octets",
                curve.field_bytes
            );
        }
    }

    #[test]
    fn a_compressed_generator_names_the_curve_only_with_the_right_parity() {
        for curve in CURVES {
            let scalar = vec![0x5A; curve.field_bytes];
            let compressed = specified_domain_for_tests(curve.oid, true).unwrap();
            assert_eq!(
                from_sec1_ec(&sec1(&scalar, &compressed)).unwrap(),
                from_sec1_ec(&sec1(&scalar, &named(curve.oid))).unwrap()
            );

            // The other `y` for the same `x` is a different point.
            let mut flipped = compressed.clone();
            let prefix = flipped
                .windows(2)
                .position(|pair| matches!(pair, [0x02 | 0x03, _]) && pair[1] == curve.generator[1])
                .unwrap();
            flipped[prefix] ^= 0x01;
            assert!(matches!(
                from_sec1_ec(&sec1(&scalar, &flipped)),
                Err(VaultError::UnsupportedKeyFormat(_))
            ));
        }
    }

    #[test]
    fn a_curve_that_differs_in_any_parameter_is_not_the_named_one() {
        // Same order, same prime, one coefficient off: a different curve, and
        // naming it P-256 would hand the key to arithmetic it does not belong to.
        let explicit = specified_domain_for_tests(P256.oid, false).unwrap();
        let b_at = explicit
            .windows(P256.b.len())
            .position(|window| window == P256.b)
            .unwrap();
        let mut other_b = explicit.clone();
        other_b[b_at + P256.b.len() - 1] ^= 0x01;
        assert!(matches!(
            from_sec1_ec(&sec1(&[0x5A; 32], &other_b)),
            Err(VaultError::UnsupportedKeyFormat(_))
        ));

        let g_at = explicit
            .windows(P256.generator.len())
            .position(|window| window == P256.generator)
            .unwrap();
        let mut other_g = explicit;
        other_g[g_at + 10] ^= 0x01;
        assert!(matches!(
            from_sec1_ec(&sec1(&[0x5A; 32], &other_g)),
            Err(VaultError::UnsupportedKeyFormat(_))
        ));
    }

    #[test]
    fn a_short_private_key_is_padded_to_the_field_length() {
        // RFC 5915 §3 fixes the length; the older LibreSSL drops leading zero
        // octets, so one key in 256 arrives short.
        let mut full = vec![0x00];
        full.extend_from_slice(&[0x77; 31]);
        let short = vec![0x77; 31];
        let curve = named(P256.oid);
        assert_eq!(
            from_sec1_ec(&sec1(&short, &curve)).unwrap(),
            from_sec1_ec(&sec1(&full, &curve)).unwrap()
        );

        // Longer than the field is not a key on this curve at all.
        assert!(matches!(
            from_sec1_ec(&sec1(&[0x77; 33], &curve)),
            Err(VaultError::NotAPrivateKey)
        ));
    }

    #[test]
    fn a_binary_field_curve_is_named_as_unsupported_rather_than_as_a_bad_file() {
        // characteristic-two-field, 1.2.840.10045.1.2.
        let explicit = specified_domain_for_tests(P256.oid, false).unwrap();
        let mut binary = explicit;
        let at = binary
            .windows(OID_PRIME_FIELD.len())
            .position(|window| window == OID_PRIME_FIELD)
            .unwrap();
        binary[at + OID_PRIME_FIELD.len() - 1] = 0x02;
        assert!(matches!(
            from_sec1_ec(&sec1(&[0x5A; 32], &binary)),
            Err(VaultError::UnsupportedKeyFormat(_))
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
