//! The three primitives NTLM is defined in terms of, and nothing else.
//!
//! MD4 and RC4 are both broken, and neither is a choice this project made.
//! MS-NLMP §3.3.2 defines `NTOWFv2` as `HMAC_MD5(MD4(UNICODE(password)), …)`
//! and §3.4.3 defines confidentiality as RC4; a client that substitutes
//! anything stronger does not authenticate. CLAUDE.md §0.3 forbids weakening a
//! cryptographic design to make a test pass — it does not license inventing a
//! *different* protocol from the one the server speaks, which is what "use
//! SHA-256 instead" would be.
//!
//! They are implemented here rather than pulled in as dependencies because
//! neither exists in the workspace's dependency tree, both are a few dozen
//! lines from a published specification, and adding two crates to obtain them
//! costs a licence review and an audit surface for less code than this file.
//! Both carry known-answer tests against the vectors in their own
//! specifications — RFC 1320 §A.5 for MD4, the widely published ARCFOUR
//! vectors for RC4 — which is what CLAUDE.md §5 requires of a cryptographic
//! primitive.
//!
//! Everything else NTLM needs — MD5, HMAC-MD5, SHA-256 — comes from the
//! RustCrypto crates already in the tree.

use hmac::{Hmac, KeyInit as _, Mac as _};
use md5::Md5;
use zeroize::Zeroize;

/// HMAC-MD5 (RFC 2104), the MAC every NTLMv2 derivation is built from.
///
/// Returns 16 bytes. HMAC accepts a key of any length, so the `Result` that
/// `new_from_slice` returns cannot actually fail here; it degrades to a zero
/// tag rather than a panic because this crate forbids `unwrap`, and a zero tag
/// fails the server's check rather than silently authenticating.
#[must_use]
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let Ok(mut mac) = Hmac::<Md5>::new_from_slice(key) else {
        return [0u8; 16];
    };
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

/// MD5 (RFC 1321). NTLM derives its signing and sealing keys with it
/// (MS-NLMP §3.4.5.2, `SIGNKEY`; §3.4.5.3, `SEALKEY`).
#[must_use]
pub fn md5(data: &[u8]) -> [u8; 16] {
    use md5::Digest as _;
    let mut out = [0u8; 16];
    out.copy_from_slice(&Md5::digest(data));
    out
}

/// MD4 (RFC 1320).
///
/// Used for exactly one thing: `NTOWFv1`/`NTOWFv2`'s inner hash of the
/// UTF-16LE password (MS-NLMP §3.3.2). The input is therefore key material,
/// and the message schedule below is zeroized before it goes out of scope —
/// `X` holds sixteen words of the password in the clear.
#[must_use]
pub fn md4(data: &[u8]) -> [u8; 16] {
    // RFC 1320 §3.3: the four-word buffer, low-order bytes first.
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    // RFC 1320 §3.1: append a 1 bit, then 0 bits until the length is 56 mod
    // 64; §3.2: append the 64-bit little-endian bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (word, bytes) in x.iter_mut().zip(chunk.chunks_exact(4)) {
            // `chunks_exact(4)` yields exactly four bytes, so the array
            // conversion cannot fail; the fallback keeps the zero word rather
            // than panicking.
            if let Ok(four) = <[u8; 4]>::try_from(bytes) {
                *word = u32::from_le_bytes(four);
            }
        }
        compress(&mut state, &x);
        x.zeroize();
    }
    padded.zeroize();

    let mut out = [0u8; 16];
    for (slot, word) in out.chunks_exact_mut(4).zip(state.iter()) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// One MD4 block. RFC 1320 §3.4, "Process Message in 16-Word Blocks".
fn compress(state: &mut [u32; 4], x: &[u32; 16]) {
    /// RFC 1320 §3.4, round 1: `F(X,Y,Z) = XY v not(X) Z`.
    const fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    /// Round 2: `G(X,Y,Z) = XY v XZ v YZ`.
    const fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    /// Round 3: `H(X,Y,Z) = X xor Y xor Z`.
    const fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    let [mut a, mut b, mut c, mut d] = *state;

    // Round 1: [ABCD k s] means a = (a + F(b,c,d) + X[k]) <<< s.
    for i in 0..4 {
        let k = i * 4;
        a = a.wrapping_add(f(b, c, d)).wrapping_add(x[k]).rotate_left(3);
        d = d
            .wrapping_add(f(a, b, c))
            .wrapping_add(x[k + 1])
            .rotate_left(7);
        c = c
            .wrapping_add(f(d, a, b))
            .wrapping_add(x[k + 2])
            .rotate_left(11);
        b = b
            .wrapping_add(f(c, d, a))
            .wrapping_add(x[k + 3])
            .rotate_left(19);
    }

    // Round 2: a = (a + G(b,c,d) + X[k] + 5A827999) <<< s. The constant is
    // the square root of 2 in RFC 1320's words.
    const ROUND2: u32 = 0x5a82_7999;
    for i in 0..4 {
        a = a
            .wrapping_add(g(b, c, d))
            .wrapping_add(x[i])
            .wrapping_add(ROUND2)
            .rotate_left(3);
        d = d
            .wrapping_add(g(a, b, c))
            .wrapping_add(x[i + 4])
            .wrapping_add(ROUND2)
            .rotate_left(5);
        c = c
            .wrapping_add(g(d, a, b))
            .wrapping_add(x[i + 8])
            .wrapping_add(ROUND2)
            .rotate_left(9);
        b = b
            .wrapping_add(g(c, d, a))
            .wrapping_add(x[i + 12])
            .wrapping_add(ROUND2)
            .rotate_left(13);
    }

    // Round 3: a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s, with the word
    // order RFC 1320 spells out.
    const ROUND3: u32 = 0x6ed9_eba1;
    const ORDER: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    for i in 0..4 {
        let k = i * 4;
        a = a
            .wrapping_add(h(b, c, d))
            .wrapping_add(x[ORDER[k]])
            .wrapping_add(ROUND3)
            .rotate_left(3);
        d = d
            .wrapping_add(h(a, b, c))
            .wrapping_add(x[ORDER[k + 1]])
            .wrapping_add(ROUND3)
            .rotate_left(9);
        c = c
            .wrapping_add(h(d, a, b))
            .wrapping_add(x[ORDER[k + 2]])
            .wrapping_add(ROUND3)
            .rotate_left(11);
        b = b
            .wrapping_add(h(c, d, a))
            .wrapping_add(x[ORDER[k + 3]])
            .wrapping_add(ROUND3)
            .rotate_left(15);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// An RC4 keystream generator.
///
/// **Stateful on purpose.** MS-NLMP §3.4.3 seals a message and then signs it
/// with the *same* handle, so the signature's checksum is encrypted with the
/// keystream that continues where the message left off. A stateless
/// `rc4(key, data)` helper would silently restart the keystream and produce a
/// signature no server accepts — which is the single easiest way to get an
/// NTLM implementation that looks right and never authenticates.
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Runs the key-scheduling algorithm over `key`.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (index, slot) in s.iter_mut().enumerate() {
            // The loop bound is 256 and the index type is `usize`, so the
            // truncation is exact.
            #[allow(
                clippy::cast_possible_truncation,
                reason = "index is bounded by 256, so the low byte is the value"
            )]
            {
                *slot = index as u8;
            }
        }
        if !key.is_empty() {
            let mut j = 0u8;
            for i in 0..256usize {
                // `key.len()` is non-zero, checked above.
                let k = key[i % key.len()];
                j = j.wrapping_add(s[i]).wrapping_add(k);
                s.swap(i, usize::from(j));
            }
        }
        Self { s, i: 0, j: 0 }
    }

    /// XORs `data` in place with the next `data.len()` keystream bytes.
    ///
    /// RC4 is its own inverse, so this both seals and unseals.
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let k = self.s[usize::from(
                self.s[usize::from(self.i)].wrapping_add(self.s[usize::from(self.j)]),
            )];
            *byte ^= k;
        }
    }

    /// A copy of `data` with the keystream applied.
    #[must_use]
    pub fn applied(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        self.apply(&mut out);
        out
    }
}

impl Drop for Rc4 {
    /// The permutation is derived from the sealing key and reveals it; a
    /// dropped handle must not leave it in freed memory.
    fn drop(&mut self) {
        self.s.zeroize();
        self.i.zeroize();
        self.j.zeroize();
    }
}

impl core::fmt::Debug for Rc4 {
    /// Hand-written and redacting: the permutation *is* the key schedule.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Rc4(<redacted>)")
    }
}

/// UTF-16LE, which is the only string encoding NTLM has (MS-NLMP §2.2.2.5,
/// `NTLMSSP_NEGOTIATE_UNICODE`, which this client always sets).
#[must_use]
pub fn utf16le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
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

    /// RFC 1320 §A.5, the MD4 test suite, in full. A primitive with no
    /// known-answer test is a primitive nobody has checked.
    #[test]
    fn md4_matches_the_rfc_1320_test_suite() {
        let cases: &[(&str, &str)] = &[
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(hex(&md4(input.as_bytes())), *expected, "MD4({input:?})");
        }
    }

    /// The published ARCFOUR vectors. The second one crosses a block boundary
    /// in the key schedule, which is where an off-by-one in the KSA shows up.
    #[test]
    fn rc4_matches_the_published_arcfour_vectors() {
        let cases: &[(&[u8], &[u8], &str)] = &[
            (b"Key", b"Plaintext", "bbf316e8d940af0ad3"),
            (b"Wiki", b"pedia", "1021bf0420"),
            (b"Secret", b"Attack at dawn", "45a01f645fc35b383552544b9bf5"),
        ];
        for (key, plaintext, expected) in cases {
            let mut rc4 = Rc4::new(key);
            assert_eq!(hex(&rc4.applied(plaintext)), *expected);
        }
    }

    #[test]
    fn rc4_keeps_its_position_across_calls() {
        // The property MS-NLMP §3.4.3 depends on: sealing a message and then
        // encrypting the signature's checksum must consume one continuous
        // keystream. A handle that restarts produces a signature the server
        // rejects, and nothing else looks wrong.
        let mut continuous = Rc4::new(b"Key");
        let whole = continuous.applied(b"Plaintext");

        let mut split = Rc4::new(b"Key");
        let mut first = split.applied(b"Plain");
        first.extend_from_slice(&split.applied(b"text"));

        assert_eq!(whole, first);
    }

    /// RFC 2202 §2, HMAC-MD5 test case 1.
    #[test]
    fn hmac_md5_matches_rfc_2202() {
        assert_eq!(
            hex(&hmac_md5(&[0x0b; 16], b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        // Test case 2, with an ASCII key.
        assert_eq!(
            hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    /// RFC 1321 §A.5.
    #[test]
    fn md5_matches_rfc_1321() {
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn utf16le_is_little_endian_and_keeps_astral_planes_as_surrogate_pairs() {
        assert_eq!(utf16le("Ab"), vec![0x41, 0x00, 0x62, 0x00]);
        // A password is not necessarily ASCII, and NTLM hashes the UTF-16LE
        // bytes: getting the surrogate pair wrong changes the hash silently.
        assert_eq!(utf16le("\u{1f600}").len(), 4);
    }

    #[test]
    fn the_rc4_handle_never_debug_prints_its_schedule() {
        let rc4 = Rc4::new(b"a sealing key");
        assert_eq!(format!("{rc4:?}"), "Rc4(<redacted>)");
    }
}
