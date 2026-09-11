//! The algorithm policy, from `docs/security/transport-security.md`.
//!
//! Two rules shape this module.
//!
//! **Legacy algorithms are not compiled in.** `ssh-rsa` (SHA-1), CBC ciphers,
//! `hmac-sha1` and the small DH groups live behind the `legacy-crypto` cargo
//! feature, which is off by default. Network engineers reaching a 2009 switch
//! genuinely need them; everybody else should not have them in their binary,
//! and a runtime toggle would put them there anyway.
//!
//! **The key-exchange extensions are not optional.** `kex-strict-c-v00@openssh.com`
//! is the client half of OpenSSH's strict key exchange, which is the defence
//! against the Terrapin prefix-truncation attack (CVE-2023-48795). Dropping it
//! from the list silently disables that defence, so it is listed here with the
//! algorithms rather than left to a default.

use std::borrow::Cow;

use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
use russh::{Preferred, cipher, compression, kex, mac};

/// Key exchange, most preferred first.
///
/// `mlkem768x25519-sha256` leads because the specification asks for the
/// post-quantum hybrid "where the server offers it", and client preference is
/// how that is expressed on the wire: a server that does not offer it simply
/// falls through to `curve25519-sha256`.
///
/// The specification names `sntrup761x25519-sha512`, which was OpenSSH's
/// hybrid before 10.0 replaced it with the ML-KEM one standardised as
/// FIPS 203. `russh` 0.63 implements the ML-KEM hybrid and not the sntrup761
/// one, so that is what is offered; the intent — a post-quantum hybrid,
/// preferred where available — is unchanged.
#[cfg(not(feature = "legacy-crypto"))]
const KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::DH_G16_SHA512,
    // Not algorithms: the two extension advertisements. `ext-info-c` is what
    // makes a server send `server-sig-algs`, without which an RSA key can only
    // be offered under the SHA-1 name. `kex-strict-c-v00@openssh.com` is the
    // Terrapin defence.
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

/// Key exchange with the legacy additions.
#[cfg(feature = "legacy-crypto")]
const KEX_LEGACY: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::DH_G16_SHA512,
    kex::DH_G14_SHA256,
    kex::DH_GEX_SHA256,
    kex::DH_GEX_SHA1,
    kex::DH_G14_SHA1,
    kex::DH_G1_SHA1,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

/// Host key algorithms, most preferred first.
///
/// `rsa-sha2-512` and `rsa-sha2-256` are the RSA *signature* algorithms
/// (RFC 8332); the bare `ssh-rsa` name means SHA-1 and is absent from the
/// default build.
#[cfg(not(feature = "legacy-crypto"))]
const HOST_KEYS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
];

/// Host key algorithms with `ssh-rsa` (SHA-1) appended, last.
#[cfg(feature = "legacy-crypto")]
const HOST_KEYS_LEGACY: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
    Algorithm::Rsa { hash: None },
];

/// Ciphers, most preferred first. All three are AEAD.
#[cfg(not(feature = "legacy-crypto"))]
const CIPHERS: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_128_GCM,
];

/// Ciphers with the CTR and CBC modes appended.
#[cfg(feature = "legacy-crypto")]
const CIPHERS_LEGACY: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_128_GCM,
    cipher::AES_256_CTR,
    cipher::AES_192_CTR,
    cipher::AES_128_CTR,
    cipher::AES_256_CBC,
    cipher::AES_192_CBC,
    cipher::AES_128_CBC,
    cipher::TRIPLE_DES_CBC,
];

/// MACs: encrypt-then-MAC only.
///
/// The three ciphers above are AEAD and negotiate `mac` as `none`, so this
/// list only comes into play under `legacy-crypto`, where a CTR or CBC cipher
/// can be selected. Encrypt-and-MAC over CBC is what made the 2009 plaintext
/// recovery attack work, so the non-ETM names stay out even there.
#[cfg(not(feature = "legacy-crypto"))]
const MACS: &[mac::Name] = &[mac::HMAC_SHA512_ETM, mac::HMAC_SHA256_ETM];

/// MACs with the encrypt-and-MAC and SHA-1 variants appended.
#[cfg(feature = "legacy-crypto")]
const MACS_LEGACY: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
    mac::HMAC_SHA1_ETM,
    mac::HMAC_SHA1,
];

/// Algorithms that are accepted but should raise
/// [`remoter_proto::SessionWarning::WeakAlgorithm`] when negotiated.
///
/// Everything here is reachable only under `legacy-crypto`; the list is
/// compiled unconditionally so that the warning logic itself is testable in an
/// ordinary build.
const WEAK: &[&str] = &[
    "ssh-rsa",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "hmac-sha1",
    "hmac-sha1-etm@openssh.com",
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
];

/// Whether a negotiated algorithm name is one the user should be told about.
#[must_use]
pub fn is_weak(algorithm: &str) -> bool {
    WEAK.contains(&algorithm)
}

/// The negotiation policy for one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AlgorithmPolicy {
    /// Whether to offer `zlib@openssh.com`. Off by default: compression before
    /// encryption leaks length information, and on a modern link it buys
    /// little.
    pub compression: bool,
}

impl AlgorithmPolicy {
    /// The `russh` preference lists this policy implies.
    #[must_use]
    pub fn preferred(self) -> Preferred {
        Preferred {
            kex: Cow::Borrowed(kex_list()),
            key: Cow::Borrowed(host_key_list()),
            // Certificate host keys are advertised only when the caller has
            // said which authorities it trusts, which the vault does not yet
            // model. Advertising them without that would make a server prove
            // its identity with a certificate we cannot check.
            host_key_certificates: Cow::Borrowed(&[]),
            cipher: Cow::Borrowed(cipher_list()),
            mac: Cow::Borrowed(mac_list()),
            // `zlib@openssh.com` first: it is *delayed* compression, which
            // starts only after authentication succeeds, so the password
            // exchange is never fed to a compressor. RFC 4253's plain `zlib`
            // compresses from the first packet and is the fallback.
            compression: if self.compression {
                Cow::Borrowed(&[
                    compression::ZLIB_LEGACY,
                    compression::ZLIB,
                    compression::NONE,
                ])
            } else {
                Cow::Borrowed(&[compression::NONE])
            },
        }
    }
}

const fn kex_list() -> &'static [kex::Name] {
    #[cfg(feature = "legacy-crypto")]
    {
        KEX_LEGACY
    }
    #[cfg(not(feature = "legacy-crypto"))]
    {
        KEX
    }
}

const fn host_key_list() -> &'static [Algorithm] {
    #[cfg(feature = "legacy-crypto")]
    {
        HOST_KEYS_LEGACY
    }
    #[cfg(not(feature = "legacy-crypto"))]
    {
        HOST_KEYS
    }
}

const fn cipher_list() -> &'static [cipher::Name] {
    #[cfg(feature = "legacy-crypto")]
    {
        CIPHERS_LEGACY
    }
    #[cfg(not(feature = "legacy-crypto"))]
    {
        CIPHERS
    }
}

const fn mac_list() -> &'static [mac::Name] {
    #[cfg(feature = "legacy-crypto")]
    {
        MACS_LEGACY
    }
    #[cfg(not(feature = "legacy-crypto"))]
    {
        MACS
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

    fn names<T: AsRef<str>>(list: &[T]) -> Vec<&str> {
        list.iter().map(AsRef::as_ref).collect()
    }

    #[test]
    fn strict_key_exchange_is_always_advertised() {
        // Losing this line silently disables the Terrapin defence, which is
        // the kind of regression no integration test would catch.
        let preferred = AlgorithmPolicy::default().preferred();
        assert!(
            names(&preferred.kex).contains(&"kex-strict-c-v00@openssh.com"),
            "strict kex must be advertised: {:?}",
            names(&preferred.kex)
        );
        assert!(names(&preferred.kex).contains(&"ext-info-c"));
    }

    #[test]
    fn the_post_quantum_hybrid_is_offered_first() {
        let preferred = AlgorithmPolicy::default().preferred();
        assert_eq!(
            names(&preferred.kex).first(),
            Some(&"mlkem768x25519-sha256")
        );
        assert!(names(&preferred.kex).contains(&"curve25519-sha256"));
    }

    #[cfg(not(feature = "legacy-crypto"))]
    #[test]
    fn every_default_cipher_is_aead() {
        let preferred = AlgorithmPolicy::default().preferred();
        assert_eq!(
            names(&preferred.cipher),
            vec![
                "chacha20-poly1305@openssh.com",
                "aes256-gcm@openssh.com",
                "aes128-gcm@openssh.com",
            ]
        );
    }

    #[cfg(not(feature = "legacy-crypto"))]
    #[test]
    fn only_encrypt_then_mac_variants_are_offered() {
        let preferred = AlgorithmPolicy::default().preferred();
        for name in names(&preferred.mac) {
            assert!(
                name.ends_with("-etm@openssh.com"),
                "not encrypt-then-MAC: {name}"
            );
        }
    }

    #[cfg(not(feature = "legacy-crypto"))]
    #[test]
    fn legacy_algorithms_are_absent_from_the_default_build() {
        let preferred = AlgorithmPolicy::default().preferred();
        let kex = names(&preferred.kex);
        let cipher = names(&preferred.cipher);
        let mac = names(&preferred.mac);
        let key: Vec<String> = preferred.key.iter().map(ToString::to_string).collect();

        for weak in WEAK {
            assert!(!kex.contains(weak), "{weak} is compiled in");
            assert!(!cipher.contains(weak), "{weak} is compiled in");
            assert!(!mac.contains(weak), "{weak} is compiled in");
            assert!(!key.iter().any(|k| k == weak), "{weak} is compiled in");
        }
    }

    #[cfg(feature = "legacy-crypto")]
    #[test]
    fn the_legacy_feature_appends_rather_than_reorders() {
        // A legacy build must still prefer the modern algorithms: the point of
        // the feature is reaching an old switch, not downgrading every session.
        let preferred = AlgorithmPolicy::default().preferred();
        assert_eq!(
            names(&preferred.kex).first(),
            Some(&"mlkem768x25519-sha256")
        );
        assert_eq!(
            names(&preferred.cipher).first(),
            Some(&"chacha20-poly1305@openssh.com")
        );
        assert!(names(&preferred.cipher).contains(&"aes256-cbc"));
        assert!(names(&preferred.mac).contains(&"hmac-sha1"));
        // The encrypt-then-MAC variants still lead: a legacy build reaches an
        // old switch without downgrading every other session.
        assert_eq!(
            names(&preferred.mac).first(),
            Some(&"hmac-sha2-512-etm@openssh.com")
        );
    }

    #[test]
    fn compression_is_off_unless_asked_for() {
        assert_eq!(
            names(&AlgorithmPolicy::default().preferred().compression),
            vec!["none"]
        );
        let compressed = AlgorithmPolicy { compression: true }.preferred();
        assert_eq!(
            names(&compressed.compression).first(),
            Some(&"zlib@openssh.com")
        );
        // `none` stays in the list: a server that does not compress must still
        // be reachable.
        assert!(names(&compressed.compression).contains(&"none"));
    }

    #[test]
    fn weak_algorithms_are_recognised_for_the_warning() {
        assert!(is_weak("ssh-rsa"));
        assert!(is_weak("3des-cbc"));
        assert!(!is_weak("chacha20-poly1305@openssh.com"));
        assert!(!is_weak("ssh-ed25519"));
    }
}
