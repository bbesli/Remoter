//! Primitives, and the key hierarchy they build.
//!
//! Every call signature here was taken from `docs/development/verified-apis.md`
//! rather than from memory: the 2026 RustCrypto generation changed most of
//! them. If a dependency version moves, re-verify that document first.
//!
//! Nothing in this module makes a policy decision. Which info string, which
//! salt and which associated data belong to which operation are decided in
//! `header.rs`, `slots.rs` and `storage.rs`; this module only performs the
//! arithmetic and hands back a `Zeroizing` buffer.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::header::KdfParams;

/// Length of every symmetric key in the hierarchy, in bytes.
pub(crate) const KEY_LEN: usize = 32;

/// XChaCha20's extended nonce, in bytes. The reason the format uses XChaCha20
/// at all: at 192 bits, random nonces do not need a counter to stay unique.
pub(crate) const NONCE_LEN: usize = 24;

/// Poly1305 tag length, in bytes.
pub(crate) const TAG_LEN: usize = 16;

/// Per-slot salt length, in bytes.
pub(crate) const SALT_LEN: usize = 24;

/// Keyed BLAKE3 output length, in bytes.
pub(crate) const MAC_LEN: usize = 32;

/// HKDF info strings. These are part of the on-disk format: changing one makes
/// every existing vault underivable, which is a format break, not a rename.
pub(crate) const INFO_CEK: &[u8] = b"remoter:cek:v1";
pub(crate) const INFO_SEK: &[u8] = b"remoter:sek:v1";
pub(crate) const INFO_HEADER_MAC: &[u8] = b"remoter:header-mac:v1";
pub(crate) const INFO_INDEX: &[u8] = b"remoter:index:v1";

/// A 256-bit key that is wiped when it goes out of scope.
pub(crate) type KeyBytes = Zeroizing<[u8; KEY_LEN]>;

/// Fills a buffer from the operating system CSPRNG.
///
/// There is deliberately no fallback. A vault created with predictable key
/// material is worse than no vault, because it looks encrypted.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), VaultError> {
    getrandom::fill(buf).map_err(|_| VaultError::Csprng)
}

/// Returns `N` fresh random bytes.
pub(crate) fn random_array<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

/// Returns a fresh random key.
pub(crate) fn random_key() -> Result<KeyBytes, VaultError> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    fill_random(out.as_mut_slice())?;
    Ok(out)
}

/// HKDF-SHA256 extract-and-expand to exactly one key's worth of output.
pub(crate) fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<KeyBytes, VaultError> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, out.as_mut_slice())
        .map_err(|_| VaultError::KeyDerivation)?;
    Ok(out)
}

/// Argon2id to exactly one key's worth of output.
///
/// The caller supplies the parameters; this function does not clamp them,
/// because it is also used to open vaults created on machines with more memory
/// than this one. Refusing parameters that are too *weak* is
/// [`KdfParams::check_floor`]'s job, at creation time.
pub(crate) fn argon2id(
    input: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<KeyBytes, VaultError> {
    let version = match params.version {
        0x13 => Version::V0x13,
        0x10 => Version::V0x10,
        _ => return Err(VaultError::KeyDerivation),
    };
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| VaultError::KeyDerivation)?;
    let ctx = Argon2::new(Algorithm::Argon2id, version, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    ctx.hash_password_into(input, salt, out.as_mut_slice())
        .map_err(|_| VaultError::KeyDerivation)?;
    Ok(out)
}

/// XChaCha20-Poly1305 seal. The returned vector is ciphertext followed by the
/// 16-byte tag.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::Aead)
}

/// XChaCha20-Poly1305 open. Fails on any tag mismatch, which is the only signal
/// the format needs: there is no "partially valid" ciphertext.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Aead)
}

/// Keyed BLAKE3, used for the header MAC.
pub(crate) fn keyed_mac(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; MAC_LEN] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Unkeyed BLAKE3, used for the key file digest and the recovery key's check
/// group.
pub(crate) fn digest(data: &[u8]) -> [u8; MAC_LEN] {
    *blake3::hash(data).as_bytes()
}

/// Constant-time equality. Slices of different lengths are unequal, and the
/// comparison of equal-length slices does not short-circuit.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// The four keys derived from the vault master key, plus the VMK itself.
///
/// Held together so that dropping the set wipes all of it at once — a partial
/// lock, where the CEK is gone but the SEK is still resident, is exactly the
/// state a memory scrape wants to find.
pub(crate) struct VaultKeys {
    /// The master key. Never written to disk except wrapped inside a key slot.
    pub(crate) vmk: KeyBytes,
    /// Encrypts the whole SQLite body.
    pub(crate) cek: KeyBytes,
    /// Encrypts each secret field individually.
    pub(crate) sek: KeyBytes,
    /// Keys the BLAKE3 MAC over the header.
    pub(crate) header_mac: KeyBytes,
    /// Reserved for the blind index. Derived so that adding a blind index later
    /// is not a format change; unused in v1.
    #[allow(
        dead_code,
        reason = "derived now so that adding a blind index later is not a format change"
    )]
    pub(crate) index: KeyBytes,
}

impl VaultKeys {
    /// Derives the hierarchy from a master key.
    pub(crate) fn derive(vmk: KeyBytes) -> Result<Self, VaultError> {
        let cek = hkdf_sha256(vmk.as_slice(), None, INFO_CEK)?;
        let sek = hkdf_sha256(vmk.as_slice(), None, INFO_SEK)?;
        let header_mac = hkdf_sha256(vmk.as_slice(), None, INFO_HEADER_MAC)?;
        let index = hkdf_sha256(vmk.as_slice(), None, INFO_INDEX)?;
        Ok(Self {
            vmk,
            cek,
            sek,
            header_mac,
            index,
        })
    }
}

impl core::fmt::Debug for VaultKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VaultKeys(<redacted>)")
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

    /// Turns a hex string into bytes, ignoring whitespace so vectors can be
    /// pasted in the layout the source document uses. Test-only, so a malformed
    /// literal is a test bug and panicking is the right response.
    fn hex(s: &str) -> Vec<u8> {
        let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert_eq!(cleaned.len() % 2, 0, "hex literal has an odd length");
        cleaned
            .chunks(2)
            .map(|pair| {
                let text = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    /// RFC 9106 section 5.3 — the Argon2id reference vector.
    ///
    /// This one uses the secret ("pepper") and associated-data inputs, which
    /// Remoter itself never uses, so it exercises the library rather than our
    /// wrapper. The wrapper is covered by `argon2id_matches_the_library`.
    #[test]
    fn argon2id_rfc9106() {
        use argon2::{AssociatedData, ParamsBuilder};

        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[0x04; 12]).unwrap())
            .build()
            .unwrap();
        let ctx = Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
            .unwrap();

        let mut out = [0u8; 32];
        ctx.hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
            .unwrap();

        assert_eq!(
            out.to_vec(),
            hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    /// The wrapper this crate actually calls, against the same reference
    /// implementation with the extra inputs left empty.
    #[test]
    fn argon2id_matches_the_library() {
        let params = KdfParams {
            m_cost: 32,
            t_cost: 3,
            p_cost: 4,
            version: 0x13,
        };
        let ours = argon2id(&[0x01; 32], &[0x02; 16], &params).unwrap();

        let reference = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(32, 3, 4, Some(32)).unwrap(),
        );
        let mut expected = [0u8; 32];
        reference
            .hash_password_into(&[0x01; 32], &[0x02; 16], &mut expected)
            .unwrap();

        assert_eq!(ours.as_slice(), expected.as_slice());
    }

    /// RFC 5869 appendix A.1 — HKDF-SHA256 with salt and info.
    ///
    /// The vector's output is 42 bytes; `hkdf_sha256` fixes its output at 32,
    /// so the vector is checked against the library directly and the wrapper is
    /// checked against the first 32 bytes of the same expansion.
    #[test]
    fn hkdf_sha256_rfc5869_a1() {
        let ikm = [0x0b; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        );

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(okm.to_vec(), expected);

        let ours = hkdf_sha256(&ikm, Some(&salt), &info).unwrap();
        assert_eq!(ours.as_slice(), &expected[..32]);
    }

    /// RFC 5869 appendix A.3 — zero-length salt and info.
    #[test]
    fn hkdf_sha256_rfc5869_a3() {
        let ikm = [0x0b; 22];
        let expected = hex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        );

        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&[], &mut okm).unwrap();
        assert_eq!(okm.to_vec(), expected);
    }

    /// draft-irtf-cfrg-xchacha appendix A.1.
    #[test]
    fn xchacha20poly1305_draft_vector() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 24] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        ];
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
            If I could offer you only one tip for the future, sunscreen would be it.";
        // Ciphertext followed by the tag, which is how `seal` returns it.
        let expected = hex(
            "bd6d179d 3e83d43b 95765794 93c0e939 572a1700 252bfacc bed2902c
             21396cbb 731c7f1b 0b4aa644 0bf3a82f 4eda7e39 ae64c670 8c54c216
             cb96b72e 1213b452 2f8c9ba4 0db5d945 b11b69b9 82c1bb9e 3f3fac2b
             c369488f 76b23835 65d3fff9 21f9664c 97637da9 768812f6 15c68b13
             b52e
             c0875924 c1c79879 47deafd8 780acf49",
        );

        let sealed = seal(&key, &nonce, plaintext, &aad).unwrap();
        assert_eq!(sealed, expected);

        let opened = open(&key, &nonce, &sealed, &aad).unwrap();
        assert_eq!(opened.as_slice(), plaintext);

        // One flipped associated-data byte must break it.
        let mut wrong_aad = aad.clone();
        wrong_aad[0] ^= 1;
        assert!(open(&key, &nonce, &sealed, &wrong_aad).is_err());
    }

    /// BLAKE3 reference test vectors: the unkeyed and keyed hash of the empty
    /// input, and of the single byte `0x00`.
    #[test]
    fn blake3_reference_vectors() {
        const REFERENCE_KEY: &[u8; 32] = b"whats the Elvish word for friend";

        assert_eq!(
            digest(b"").to_vec(),
            hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        );
        assert_eq!(
            digest(&[0x00]).to_vec(),
            hex("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213")
        );
        assert_eq!(
            keyed_mac(REFERENCE_KEY, b"").to_vec(),
            hex("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26")
        );
        assert_eq!(
            keyed_mac(REFERENCE_KEY, &[0x00]).to_vec(),
            hex("6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b")
        );
    }

    #[test]
    fn the_hierarchy_separates_its_keys() {
        let vmk = random_key().unwrap();
        let keys = VaultKeys::derive(vmk).unwrap();

        let all: [&[u8]; 5] = [
            keys.cek.as_slice(),
            keys.sek.as_slice(),
            keys.header_mac.as_slice(),
            keys.index.as_slice(),
            keys.vmk.as_slice(),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert!(!ct_eq(a, b));
            }
        }
    }

    #[test]
    fn the_hierarchy_is_deterministic() {
        let vmk = random_key().unwrap();
        let copy = Zeroizing::new(*vmk);
        let a = VaultKeys::derive(vmk).unwrap();
        let b = VaultKeys::derive(copy).unwrap();
        assert!(ct_eq(a.cek.as_slice(), b.cek.as_slice()));
        assert!(ct_eq(a.sek.as_slice(), b.sek.as_slice()));
    }

    #[test]
    fn keys_are_redacted_in_debug_output() {
        let keys = VaultKeys::derive(random_key().unwrap()).unwrap();
        assert_eq!(format!("{keys:?}"), "VaultKeys(<redacted>)");
    }

    /// The specification's nonce policy: random 192-bit nonces, no counter, no
    /// state to get wrong across machines. A million draws is well short of the
    /// birthday bound at that size — the expected number of collisions is about
    /// 10^-45 — so a single repeat here means the generator is broken, not
    /// unlucky.
    #[test]
    fn a_million_nonces_do_not_repeat() {
        use std::collections::HashSet;

        const DRAWS: usize = 1_000_000;
        let mut seen: HashSet<[u8; NONCE_LEN]> = HashSet::with_capacity(DRAWS);

        for _ in 0..DRAWS {
            let nonce: [u8; NONCE_LEN] = random_array().unwrap();
            assert!(seen.insert(nonce), "a 192-bit nonce repeated");
        }
        assert_eq!(seen.len(), DRAWS);
    }

    #[test]
    fn constant_time_comparison_rejects_length_mismatch() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
