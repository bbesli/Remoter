//! The recovery key: 256 bits, written down once.
//!
//! This is the answer to "what if I lose my password?", so the encoding is
//! chosen for transcription by a human under stress rather than for density.
//! Crockford Base32 drops `I`, `L`, `O` and `U` from the alphabet — the first
//! three because they are read as `1`, `1` and `0`, the last because it turns
//! random strings into words nobody wants printed on their recovery sheet — and
//! parsing accepts the substitutions anyway, along with any mixture of case,
//! hyphens and spaces.
//!
//! A four-character check group is appended so that a slip is reported as a
//! typo rather than as a wrong key. Without it, every mistyped character
//! produces the same "that did not unlock the vault" as a genuinely wrong key,
//! and the user has no way to tell which of the two they are looking at.
//!
//! # Encoding
//!
//! ```text
//! RMTR-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-CCCC
//!      └──────────────── 13 groups, 52 symbols, 256 bits ───────────────┘ └┬┘
//!                                                                  check group
//! ```
//!
//! Thirteen groups rather than the eight the specification's illustration
//! shows: 256 bits do not fit in fewer, and shortening the key to make the
//! picture true would be exactly the kind of "weaken the design to fit" that
//! is forbidden.

use core::fmt;

use data_encoding::{Encoding, Specification};
use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN};
use crate::error::VaultError;

/// The Crockford Base32 alphabet, in value order.
const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters per group, as displayed.
const GROUP_LEN: usize = 4;

/// Symbols needed to carry 256 bits: `ceil(256 / 5)`.
const BODY_SYMBOLS: usize = 52;

/// Symbols in the check group.
const CHECK_SYMBOLS: usize = 4;

/// Total symbols, ignoring separators and the prefix.
const TOTAL_SYMBOLS: usize = BODY_SYMBOLS + CHECK_SYMBOLS;

/// Printed in front of the groups so a recovery key is recognisable on a sheet
/// of paper among other codes. Optional when parsing.
const PREFIX: &str = "RMTR";

/// Domain separator for the check group, so it cannot be confused with any
/// other digest of the same input.
const CHECK_DOMAIN: &[u8] = b"remoter:recovery-check:v1";

/// Builds the Crockford Base32 encoding.
///
/// Rebuilt per call rather than cached: recovery keys are generated and parsed
/// a handful of times in a vault's life, and a fallible one-time initialiser
/// would have to either panic or carry an error through every call site.
fn encoding() -> Result<Encoding, VaultError> {
    let mut spec = Specification::new();
    spec.symbols.push_str(ALPHABET);
    // A 52-symbol string carries 260 bits for a 256-bit key, so the last symbol
    // has four bits of padding. Accepting non-zero padding keeps a mistyped
    // final character reportable as a check-group failure — the message a user
    // can act on — rather than as an opaque decoding error.
    spec.check_trailing_bits = false;
    spec.encoding()
        .map_err(|_| VaultError::RecoveryKeyMalformed)
}

/// A 256-bit recovery key.
///
/// No `Display`, no `Clone`, no `Serialize`. Rendering it for the one screen
/// that is allowed to show it goes through [`RecoveryKey::groups`], which
/// returns a buffer that wipes itself.
pub struct RecoveryKey {
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

impl RecoveryKey {
    /// Generates a fresh key from the operating system CSPRNG.
    pub fn generate() -> Result<Self, VaultError> {
        Ok(Self {
            bytes: crypto::random_key()?,
        })
    }

    /// Parses a key as the user typed it.
    ///
    /// Tolerant of case, of hyphens, spaces and underscores anywhere, of the
    /// optional `RMTR` prefix, and of the classic Crockford substitutions
    /// (`O` → `0`, `I` and `L` → `1`).
    pub fn parse(input: &str) -> Result<Self, VaultError> {
        let cleaned = normalise(input);
        let cleaned = strip_prefix(&cleaned);

        if cleaned.len() != TOTAL_SYMBOLS {
            return Err(VaultError::RecoveryKeyMalformed);
        }
        let (body, check) = cleaned.split_at(BODY_SYMBOLS);

        // The check group covers the symbols, not the decoded bytes. Fifty-two
        // symbols carry 260 bits for a 256-bit key, so the last symbol has four
        // bits that decoding discards; a typo confined to those bits would
        // decode to the same key and slip past a check over the bytes.
        let expected = check_group(body)?;
        if !crypto::ct_eq(check.as_bytes(), expected.as_bytes()) {
            return Err(VaultError::RecoveryKeyChecksum);
        }

        let decoded = encoding()?
            .decode(body.as_bytes())
            .map_err(|_| VaultError::RecoveryKeyMalformed)?;
        let decoded = Zeroizing::new(decoded);
        let bytes: [u8; KEY_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::RecoveryKeyMalformed)?;

        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// The key as groups of four characters, check group last.
    ///
    /// The returned vector wipes its strings when it is dropped. It is still
    /// the caller's job not to copy them anywhere that outlives the one screen
    /// they are shown on.
    pub fn groups(&self) -> Result<Zeroizing<Vec<String>>, VaultError> {
        let mut text = Zeroizing::new(encoding()?.encode(self.bytes.as_slice()));
        let check = check_group(&text)?;
        text.push_str(&check);

        let groups: Vec<String> = text
            .as_bytes()
            .chunks(GROUP_LEN)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect();
        Ok(Zeroizing::new(groups))
    }

    /// The key as one hyphenated line, prefix included — the form printed on
    /// the recovery sheet and written to the plain text file.
    pub fn printable(&self) -> Result<Zeroizing<String>, VaultError> {
        let groups = self.groups()?;
        let mut out = String::with_capacity(PREFIX.len() + TOTAL_SYMBOLS + groups.len());
        out.push_str(PREFIX);
        for group in groups.iter() {
            out.push('-');
            out.push_str(group);
        }
        Ok(Zeroizing::new(out))
    }

    /// The raw key material, for slot derivation.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

/// Uppercases, drops separators, and applies the Crockford substitutions.
fn normalise(input: &str) -> Zeroizing<String> {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let upper = ch.to_ascii_uppercase();
        match upper {
            'O' => out.push('0'),
            'I' | 'L' => out.push('1'),
            c if c.is_ascii_alphanumeric() => out.push(c),
            // Hyphens, spaces, underscores, tabs and newlines are formatting.
            _ => {}
        }
    }
    Zeroizing::new(out)
}

/// Removes the optional `RMTR` prefix.
///
/// Only when what follows is exactly a full key, so a key whose first group
/// happens to start with those characters is not truncated.
fn strip_prefix(cleaned: &str) -> &str {
    if cleaned.len() == PREFIX.len() + TOTAL_SYMBOLS && cleaned.starts_with(PREFIX) {
        &cleaned[PREFIX.len()..]
    } else {
        cleaned
    }
}

/// The four-character check group for an encoded key body.
fn check_group(body: &str) -> Result<String, VaultError> {
    let mut input = Zeroizing::new(Vec::with_capacity(CHECK_DOMAIN.len() + body.len()));
    input.extend_from_slice(CHECK_DOMAIN);
    input.extend_from_slice(body.as_bytes());

    let digest = crypto::digest(&input);
    // Three bytes encode to five symbols; four of them carry the 20 bits the
    // check group needs.
    let encoded = encoding()?.encode(&digest[..3]);
    encoded
        .get(..CHECK_SYMBOLS)
        .map(str::to_owned)
        .ok_or(VaultError::RecoveryKeyMalformed)
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

    #[test]
    fn a_generated_key_round_trips() {
        let key = RecoveryKey::generate().unwrap();
        let printed = key.printable().unwrap();
        let back = RecoveryKey::parse(&printed).unwrap();
        assert_eq!(key.as_bytes(), back.as_bytes());
    }

    #[test]
    fn the_rendering_has_the_documented_shape() {
        let key = RecoveryKey::generate().unwrap();
        let groups = key.groups().unwrap();
        assert_eq!(groups.len(), 14);
        for group in groups.iter() {
            assert_eq!(group.len(), GROUP_LEN);
            assert!(group.chars().all(|c| ALPHABET.contains(c)));
        }

        let printed = key.printable().unwrap();
        assert!(printed.starts_with("RMTR-"));
        assert_eq!(printed.len(), PREFIX.len() + TOTAL_SYMBOLS + groups.len());
    }

    #[test]
    fn the_alphabet_excludes_the_ambiguous_letters() {
        for c in ['I', 'L', 'O', 'U'] {
            assert!(!ALPHABET.contains(c), "{c} must not be in the alphabet");
        }
        assert_eq!(ALPHABET.len(), 32);
    }

    #[test]
    fn parsing_tolerates_how_people_actually_type() {
        let key = RecoveryKey::generate().unwrap();
        let printed = key.printable().unwrap();
        let bare: String = printed.chars().filter(|c| *c != '-').collect();

        let variants = [
            printed.to_string(),
            printed.to_lowercase(),
            bare.clone(),
            bare.chars()
                .collect::<Vec<_>>()
                .chunks(8)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(" "),
            format!("  {}  \n", printed.as_str()),
        ];

        for variant in variants {
            let parsed = RecoveryKey::parse(&variant)
                .unwrap_or_else(|e| panic!("failed to parse {variant:?}: {e}"));
            assert_eq!(parsed.as_bytes(), key.as_bytes());
        }
    }

    #[test]
    fn parsing_applies_the_crockford_substitutions() {
        // Build a key whose encoding is all zeroes, so every symbol is '0', and
        // then type it with the letter O instead.
        let bytes = Zeroizing::new([0u8; KEY_LEN]);
        let key = RecoveryKey { bytes };
        let printed = key.printable().unwrap();
        let typed_with_letters = printed.replace('0', "O").replace('1', "l");

        let parsed = RecoveryKey::parse(&typed_with_letters).unwrap();
        assert_eq!(parsed.as_bytes(), key.as_bytes());
    }

    #[test]
    fn a_mistyped_character_is_reported_as_a_typo() {
        let key = RecoveryKey::generate().unwrap();
        let printed = key.printable().unwrap();

        // Change the first body symbol to something else in the alphabet.
        let mut chars: Vec<char> = printed.chars().collect();
        let position = PREFIX.len() + 1;
        chars[position] = if chars[position] == '7' { '8' } else { '7' };
        let mistyped: String = chars.into_iter().collect();

        match RecoveryKey::parse(&mistyped) {
            Err(VaultError::RecoveryKeyChecksum) => {}
            other => panic!("expected a checksum failure, got {other:?}"),
        }
    }

    #[test]
    fn the_wrong_length_is_refused() {
        for bad in ["", "RMTR", "RMTR-0000", &"A".repeat(200)] {
            assert!(matches!(
                RecoveryKey::parse(bad),
                Err(VaultError::RecoveryKeyMalformed)
            ));
        }
    }

    #[test]
    fn a_key_beginning_with_the_prefix_letters_is_not_truncated() {
        // A full key with no prefix must parse, even if its first characters
        // spell RMTR.
        let key = RecoveryKey::generate().unwrap();
        let printed = key.printable().unwrap();
        let without_prefix = printed.trim_start_matches("RMTR-");
        let parsed = RecoveryKey::parse(without_prefix).unwrap();
        assert_eq!(parsed.as_bytes(), key.as_bytes());
    }

    #[test]
    fn debug_is_redacted() {
        let key = RecoveryKey::generate().unwrap();
        assert_eq!(format!("{key:?}"), "RecoveryKey(<redacted>)");
    }

    #[test]
    fn distinct_keys_are_produced() {
        let a = RecoveryKey::generate().unwrap();
        let b = RecoveryKey::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
