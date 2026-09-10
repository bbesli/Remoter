//! The file format under attack: truncation, tampering, substitution and
//! version confusion.
//!
//! Everything here goes through the public API, because the guarantee being
//! tested is a guarantee to callers: a damaged file produces a typed error and
//! no plaintext, whatever shape the damage takes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::fs;
use std::path::{Path, PathBuf};

use remoter_vault::{
    CreateOptions, KdfParams, MAGIC, Secret, SlotKind, UnlockError, UnlockMethod, Vault, VaultError,
};

const PASSWORD: &str = "a master password";

fn create(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let (mut vault, _key) = Vault::create(
        CreateOptions::new(
            &path,
            "Acme Production",
            Secret::new(String::from(PASSWORD)),
        )
        .with_kdf_params(KdfParams::low_cost_for_tests()),
    )
    .unwrap();
    vault.save().unwrap();
    vault.lock();
    path
}

fn unlock(path: &Path) -> Result<Vault, UnlockError> {
    Vault::open(
        path,
        UnlockMethod::password(Secret::new(String::from(PASSWORD))),
    )
}

/// Where the body begins, derived from the framing the same way a reader does.
fn body_offset(bytes: &[u8]) -> usize {
    let header_len = u32::from_le_bytes(bytes[10..14].try_into().unwrap()) as usize;
    // MAGIC + FORMAT_VER + HEADER_LEN + HEADER + HEADER_MAC + BODY_NONCE
    8 + 2 + 4 + header_len + 32 + 24
}

#[test]
fn the_file_starts_with_the_documented_magic() {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path(), "acme.rvault");
    let bytes = fs::read(&path).unwrap();

    assert_eq!(&bytes[..8], &MAGIC);
    assert_eq!(&MAGIC, b"RMTRVLT\x01");
    assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), 1);
}

/// Truncated at every byte offset: a clean typed error, no panic, and never a
/// vault that opens.
///
/// `probe` is run at every single offset — it reads only the framing, which is
/// where all the bounds arithmetic lives, so this is the exhaustive pass. It is
/// allowed to succeed once the header and the first sixteen body bytes are
/// present, because probing deliberately does not read the body; what it must
/// never do is succeed on a file whose header is incomplete.
///
/// `open` is run at every offset up to the first parseable length, and then on
/// a sample through the body. Opening runs Argon2id, so a hundred thousand of
/// them would take hours; the offsets it skips differ from the ones it takes
/// only in how much ciphertext is missing.
#[test]
fn truncation_at_every_offset_is_a_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path(), "acme.rvault");
    let bytes = fs::read(&path).unwrap();
    let truncated = dir.path().join("truncated.rvault");

    let first_parseable = body_offset(&bytes) + 16;
    assert!(first_parseable < bytes.len());

    for cut in 0..bytes.len() {
        fs::write(&truncated, &bytes[..cut]).unwrap();

        match Vault::probe(&truncated) {
            Ok(_) => assert!(
                cut >= first_parseable,
                "probe accepted a file truncated at {cut}, before the header ends"
            ),
            Err(VaultError::NotAVault | VaultError::Malformed | VaultError::HeaderDecode) => {}
            Err(other) => panic!("truncation at {cut} produced an unexpected error: {other}"),
        }
    }

    let sampled = (0..first_parseable)
        .chain((first_parseable..bytes.len()).step_by(bytes.len() / 32))
        .chain(bytes.len().saturating_sub(4)..bytes.len());

    for cut in sampled {
        fs::write(&truncated, &bytes[..cut]).unwrap();
        match unlock(&truncated) {
            Ok(_) => panic!("a file truncated at {cut} opened"),
            Err(UnlockError::BodyCorrupt | UnlockError::Vault(_)) => {}
            Err(other) => panic!("truncation at {cut} produced an unexpected error: {other}"),
        }
    }
}

#[test]
fn a_flipped_header_byte_is_detected_at_every_position() {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path(), "acme.rvault");
    let bytes = fs::read(&path).unwrap();
    let tampered = dir.path().join("tampered.rvault");

    // Every byte of the CBOR header, one at a time. Some flips break the CBOR
    // and are caught by the parser; the rest survive to the MAC check. Neither
    // may produce an open vault.
    for position in 14..body_offset(&bytes) - 56 {
        let mut damaged = bytes.clone();
        damaged[position] ^= 0x01;
        fs::write(&tampered, &damaged).unwrap();

        match unlock(&tampered) {
            Ok(_) => panic!("a header flipped at byte {position} still opened"),
            Err(
                UnlockError::HeaderTampered
                | UnlockError::NotUnlocked
                | UnlockError::NoSuchMethod(_)
                | UnlockError::Vault(_),
            ) => {}
            Err(other) => panic!("flip at {position} produced an unexpected error: {other}"),
        }
    }
}

#[test]
fn a_flipped_body_byte_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path(), "acme.rvault");
    let bytes = fs::read(&path).unwrap();
    let tampered = dir.path().join("tampered.rvault");

    let start = body_offset(&bytes);
    let step = (bytes.len() - start) / 16;
    for position in (start..bytes.len()).step_by(step.max(1)) {
        let mut damaged = bytes.clone();
        damaged[position] ^= 0x80;
        fs::write(&tampered, &damaged).unwrap();

        assert!(
            matches!(unlock(&tampered), Err(UnlockError::BodyCorrupt)),
            "a body flipped at byte {position} was not reported as corrupt"
        );
    }
}

#[test]
fn a_body_lifted_from_another_vault_does_not_decrypt() {
    let dir = tempfile::tempdir().unwrap();
    let first = create(dir.path(), "first.rvault");
    let second = create(dir.path(), "second.rvault");

    let a = fs::read(&first).unwrap();
    let b = fs::read(&second).unwrap();

    // Keep the first vault's framing — its header, its MAC, its slots — and
    // graft the second's nonce and ciphertext on. The associated data binds the
    // body to the header it was written with, so this must fail even though
    // both files are genuine vaults.
    let mut grafted = a[..body_offset(&a) - 24].to_vec();
    grafted.extend_from_slice(&b[body_offset(&b) - 24..]);

    let path = dir.path().join("grafted.rvault");
    fs::write(&path, &grafted).unwrap();

    assert!(matches!(unlock(&path), Err(UnlockError::BodyCorrupt)));
}

#[test]
fn an_unknown_format_version_is_refused_rather_than_guessed() {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path(), "acme.rvault");
    let mut bytes = fs::read(&path).unwrap();

    for version in [0u16, 2, 99, u16::MAX] {
        bytes[8..10].copy_from_slice(&version.to_le_bytes());
        let future = dir.path().join("future.rvault");
        fs::write(&future, &bytes).unwrap();

        match Vault::probe(&future) {
            Err(VaultError::UnsupportedFormat(found)) => assert_eq!(found, version),
            other => panic!("version {version} was not refused: {other:?}"),
        }
        assert!(matches!(
            unlock(&future),
            Err(UnlockError::Vault(VaultError::UnsupportedFormat(_)))
        ));
    }
}

#[test]
fn a_file_that_is_not_a_vault_is_named_as_such() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.txt");
    fs::write(&path, b"Dear diary, today I was not a vault.").unwrap();

    assert!(matches!(Vault::probe(&path), Err(VaultError::NotAVault)));
    assert!(matches!(
        unlock(&path),
        Err(UnlockError::Vault(VaultError::NotAVault))
    ));
}

#[test]
fn an_absent_file_is_an_io_error_not_a_format_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.rvault");

    assert!(matches!(Vault::probe(&path), Err(VaultError::Io { .. })));
    assert!(matches!(
        unlock(&path),
        Err(UnlockError::Vault(VaultError::Io { .. }))
    ));
}

#[test]
fn asking_for_an_unlock_method_the_vault_does_not_have_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path(), "acme.rvault");

    // The vault has no keychain slot. Saying so leaks nothing: the slot table
    // is plaintext and a probe would show the same thing.
    match Vault::open(&path, UnlockMethod::Keychain) {
        Err(UnlockError::NoSuchMethod(SlotKind::Keychain)) => {}
        other => panic!("expected NoSuchMethod, got {other:?}"),
    }
}

#[test]
fn hardware_keys_report_that_they_are_not_implemented() {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path(), "acme.rvault");

    match Vault::open(&path, UnlockMethod::Fido2) {
        Err(UnlockError::Fido2Unsupported) => {}
        other => panic!("expected Fido2Unsupported, got {other:?}"),
    }
}

#[test]
fn the_wrong_password_never_says_which_part_was_wrong() {
    let dir = tempfile::tempdir().unwrap();
    let path = create(dir.path(), "acme.rvault");

    let attempts = [
        UnlockMethod::password(Secret::new(String::new())),
        UnlockMethod::password(Secret::new(String::from("A MASTER PASSWORD"))),
        UnlockMethod::password(Secret::new(String::from("a master passwor"))),
        UnlockMethod::password_with_keyfile(
            Secret::new(String::from(PASSWORD)),
            dir.path().join("no-such-keyfile"),
        ),
    ];

    for attempt in attempts {
        let message = Vault::open(&path, attempt).unwrap_err().to_string();
        assert_eq!(message, "That did not unlock the vault.");
    }
}
