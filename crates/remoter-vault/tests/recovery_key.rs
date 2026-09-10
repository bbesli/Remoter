//! The recovery key, from the outside: how it renders, and how forgiving it is
//! about how it is typed back in.
//!
//! This matters more than most encoding code. Someone reaching for their
//! recovery key has already lost their password, is probably reading it off a
//! printed sheet or a photograph of one, and gets no second chance if the
//! parser is fussy about a lowercase letter or a stray space.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::BTreeSet;

use remoter_vault::{RecoveryKey, VaultError};

/// The Crockford alphabet, in value order.
const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[test]
fn the_rendering_is_groups_of_four_from_a_restricted_alphabet() {
    let key = RecoveryKey::generate().unwrap();
    let groups = key.groups().unwrap();

    for group in groups.iter() {
        assert_eq!(
            group.chars().count(),
            4,
            "group {group:?} is not four characters"
        );
        for c in group.chars() {
            assert!(
                ALPHABET.contains(c),
                "character {c:?} is not in the Crockford alphabet"
            );
        }
    }

    // Thirteen groups carry the 256 bits; the fourteenth is the check group.
    assert_eq!(groups.len(), 14);
}

#[test]
fn the_alphabet_leaves_out_the_letters_people_misread() {
    let mut seen = BTreeSet::new();
    // A hundred keys is enough to see every symbol many times over.
    for _ in 0..100 {
        let key = RecoveryKey::generate().unwrap();
        for group in key.groups().unwrap().iter() {
            seen.extend(group.chars());
        }
    }

    for excluded in ['I', 'L', 'O', 'U'] {
        assert!(
            !seen.contains(&excluded),
            "{excluded} was rendered; it is excluded to avoid transcription errors"
        );
    }
}

#[test]
fn the_printable_form_is_prefixed_and_hyphenated() {
    let key = RecoveryKey::generate().unwrap();
    let printed = key.printable().unwrap();

    assert!(printed.starts_with("RMTR-"));
    assert_eq!(printed.matches('-').count(), 14);
    assert_eq!(printed.chars().count(), 4 + 14 + 14 * 4);
}

#[test]
fn a_key_round_trips_through_its_printed_form() {
    for _ in 0..32 {
        let key = RecoveryKey::generate().unwrap();
        let printed = key.printable().unwrap();
        let parsed = RecoveryKey::parse(&printed).unwrap();
        // The bytes are not exposed, so equality is established the way it
        // matters: the two render identically.
        assert_eq!(*parsed.printable().unwrap(), *printed);
    }
}

#[test]
fn parsing_forgives_case_separators_and_the_crockford_substitutions() {
    let key = RecoveryKey::generate().unwrap();
    let printed = key.printable().unwrap();
    let bare: String = printed.chars().filter(|c| *c != '-').collect();

    let variants = vec![
        printed.to_string(),
        printed.to_lowercase(),
        printed.to_uppercase(),
        bare.clone(),
        bare.to_lowercase(),
        printed.strip_prefix("RMTR-").unwrap().to_string(),
        format!("\n\t  {}  \n", printed.as_str()),
        printed.replace('-', " "),
        printed.replace('-', "_"),
        // Read off a sheet by someone who writes zero as the letter O and one
        // as a lowercase l.
        printed.replace('0', "O").replace('1', "l"),
        printed.replace('0', "o").replace('1', "I"),
    ];

    for variant in variants {
        let parsed = RecoveryKey::parse(&variant)
            .unwrap_or_else(|e| panic!("failed to parse {variant:?}: {e}"));
        assert_eq!(*parsed.printable().unwrap(), *printed);
    }
}

#[test]
fn a_single_mistyped_character_is_reported_as_a_typo() {
    let key = RecoveryKey::generate().unwrap();
    let printed = key.printable().unwrap();
    let chars: Vec<char> = printed.chars().collect();

    let mut checked = 0;
    for position in 5..chars.len() {
        if chars[position] == '-' {
            continue;
        }
        let mut mistyped = chars.clone();
        // Replace with a different symbol from the alphabet.
        mistyped[position] = if mistyped[position] == 'Z' { 'Y' } else { 'Z' };
        let typed: String = mistyped.into_iter().collect();

        match RecoveryKey::parse(&typed) {
            Err(VaultError::RecoveryKeyChecksum) => checked += 1,
            // A flip inside the check group itself is the same class of error.
            Err(other) => panic!("position {position} produced {other}"),
            Ok(_) => panic!("a key mistyped at position {position} was accepted"),
        }
    }
    assert_eq!(checked, 56, "every symbol should have been exercised");
}

#[test]
fn a_key_of_the_wrong_length_is_malformed_not_a_checksum_failure() {
    let key = RecoveryKey::generate().unwrap();
    let printed = key.printable().unwrap();

    let too_short = &printed[..printed.len() - 1];
    let too_long = format!("{}Z", printed.as_str());

    for bad in [
        "",
        "RMTR",
        "not a recovery key at all",
        too_short,
        too_long.as_str(),
    ] {
        assert!(
            matches!(
                RecoveryKey::parse(bad),
                Err(VaultError::RecoveryKeyMalformed)
            ),
            "{bad:?} was not reported as malformed"
        );
    }
}

#[test]
fn generated_keys_do_not_repeat() {
    let mut seen = BTreeSet::new();
    for _ in 0..512 {
        let key = RecoveryKey::generate().unwrap();
        let printed = key.printable().unwrap();
        assert!(seen.insert(printed.to_string()), "a recovery key repeated");
    }
}

#[test]
fn a_recovery_key_is_never_printed_by_debug() {
    let key = RecoveryKey::generate().unwrap();
    let printed = key.printable().unwrap();
    let rendered = format!("{key:?}");

    assert_eq!(rendered, "RecoveryKey(<redacted>)");
    for group in key.groups().unwrap().iter() {
        assert!(!rendered.contains(group.as_str()));
    }
    assert!(!rendered.contains(printed.as_str()));
}
