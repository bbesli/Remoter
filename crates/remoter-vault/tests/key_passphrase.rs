//! The passphrase is tried against the key before anything is sealed.
//!
//! This file exists because of one failure, which had the worst shape a failure
//! can have. A wrong passphrase for an encrypted OpenSSH or PKCS#8 container was
//! accepted at import, written to the vault, and surfaced days later as
//! "the server rejected these credentials (private-key)" — a sentence about a
//! machine that had never seen the key, on a screen with nothing on it
//! connecting the failure to the file that caused it.
//!
//! So the question is asked where it can be answered: at the moment the
//! passphrase is offered. Four things can be wrong and they are four errors,
//! because they have four remedies — no passphrase given, one that does not
//! open the container, one offered for a container that is not enciphered, and
//! a container this build cannot open to find out.
//!
//! **No key is committed.** `CLAUDE.md` §9 forbids it even for a test, so every
//! container here is generated while the test runs: by the system's own
//! `ssh-keygen` and `openssl` where they exist, which is what makes these
//! assertions about real files rather than about this crate agreeing with
//! itself, and by `remoter_vault::testing` where they do not.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use remoter_core::{KeyFormat, Node, NodeKind};
use remoter_vault::{
    CreateOptions, ExposeSecret, KdfParams, Purpose, RecoveryKey, Secret, Vault, VaultError,
    private_key_credential, testing,
};

const PASSWORD: &str = "a master password";
const RIGHT: &str = "correct horse battery staple";
const WRONG: &str = "definitely not the passphrase";

fn create(dir: &Path) -> (Vault, RecoveryKey) {
    let (vault, key) = Vault::create(
        CreateOptions::new(
            dir.join("acme.rvault"),
            "Acme Production",
            Secret::new(String::from(PASSWORD)),
        )
        .with_kdf_params(KdfParams::low_cost_for_tests()),
    )
    .unwrap();
    (vault, key)
}

/// A vault holding one credential node shaped for a private key.
fn vault_with_credential(dir: &Path) -> (Vault, uuid::Uuid) {
    let (mut vault, _recovery) = create(dir);
    let props = private_key_credential("svc-deploy", KeyFormat::OpenSsh, true);
    let mut tree = vault.tree().unwrap();
    let node = Node::new(NodeKind::Credential(props), "svc-deploy", 1_700_000_000_000);
    let id = *node.id.as_uuid();
    let patch = tree.insert(node).unwrap();
    vault.apply(&tree, &patch).unwrap();
    (vault, id)
}

/// What a refusal is, in one word, so an assertion can print it.
fn said(outcome: Result<KeyFormat, VaultError>) -> String {
    match outcome {
        Ok(format) => format!("<accepted as {format:?}>"),
        Err(VaultError::KeyPassphraseRejected) => String::from("rejected"),
        Err(VaultError::KeyPassphraseRequired) => String::from("required"),
        Err(VaultError::KeyPassphraseNotNeeded) => String::from("not-needed"),
        Err(VaultError::KeyPassphraseUncheckable(clause)) => format!("uncheckable: {clause}"),
        Err(other) => format!("<{other}>"),
    }
}

/// An encrypted OpenSSH container written by the system's own `ssh-keygen`, or
/// `None` where there is no `ssh-keygen` to write one.
fn ssh_keygen(dir: &Path, name: &str, passphrase: &str) -> Option<PathBuf> {
    let path = dir.join(name);
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", passphrase, "-C", "", "-f"])
        .arg(&path)
        .status()
        .ok()?;
    status.success().then_some(path)
}

/// An encrypted PKCS#8 document written by the system's own OpenSSL under the
/// scheme `args` names.
fn openssl_pkcs8(dir: &Path, name: &str, args: &[&str]) -> Option<PathBuf> {
    let plain = dir.join(format!("{name}.plain"));
    let generated = Command::new("openssl")
        .args(["genpkey", "-algorithm", "ed25519", "-out"])
        .arg(&plain)
        .status()
        .ok()?;
    if !generated.success() {
        return None;
    }
    let path = dir.join(name);
    let status = Command::new("openssl")
        .args(["pkcs8", "-topk8", "-in"])
        .arg(&plain)
        .arg("-out")
        .arg(&path)
        .args(args)
        .args(["-passout", &format!("pass:{RIGHT}")])
        .status()
        .ok()?;
    status.success().then_some(path)
}

// ------------------------------------------------- the containers as read ---

/// The defect, in the shape it was reported: `ssh-keygen` writes a key, a wrong
/// passphrase is offered for it, and the import must refuse rather than seal it.
///
/// Before this check existed both lines below returned `Ok`, the passphrase was
/// written to the vault, and the wrong one was discovered at connect time as a
/// rejection by a server.
#[test]
fn a_wrong_passphrase_for_an_openssh_key_is_refused_at_import() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, node) = vault_with_credential(dir.path());
    let Some(key) = ssh_keygen(dir.path(), "id_ed25519", RIGHT) else {
        // No `ssh-keygen` on this machine. The same assertions run over a
        // generated container in `a_wrong_passphrase_is_refused_without_any_tooling`.
        return;
    };

    let refused = vault.import_private_key(node, &key, Some(&Secret::new(String::from(WRONG))));
    assert_eq!(said(refused), "rejected");
    assert!(
        !vault.has_secret(node, "passphrase").unwrap(),
        "a passphrase that does not open the key reached the vault"
    );
    assert!(
        !vault.has_secret(node, "private_key").unwrap(),
        "a refused import wrote the key anyway"
    );

    // And the right one is not refused, which is the half that proves the check
    // is a check and not a wall.
    let accepted = vault.import_private_key(node, &key, Some(&Secret::new(String::from(RIGHT))));
    assert_eq!(said(accepted), "<accepted as OpenSsh>");
    let material = vault
        .borrow_private_key(node, Purpose::SshPrivateKey)
        .unwrap();
    assert_eq!(
        material.passphrase().map(|p| p.expose_secret().as_slice()),
        Some(RIGHT.as_bytes())
    );
}

/// The same, for every PKCS#8 scheme this build claims to read.
///
/// The schemes are the ones `crate::pkcs8` accepts at inspection time; a
/// document under one of them that this test could not then open with the right
/// passphrase would mean inspection and the passphrase check disagree, which is
/// the drift the whole arrangement exists to prevent.
#[test]
fn a_wrong_passphrase_for_a_pkcs8_key_is_refused_at_import() {
    let dir = tempfile::tempdir().unwrap();
    let schemes: [(&str, Vec<&str>); 4] = [
        ("aes256.pk8", vec!["-v2", "aes-256-cbc"]),
        ("aes128.pk8", vec!["-v2", "aes-128-cbc"]),
        (
            "sha384.pk8",
            vec!["-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA384"],
        ),
        ("scrypt.pk8", vec!["-scrypt"]),
    ];

    let mut checked = 0usize;
    for (name, args) in schemes {
        let Some(key) = openssl_pkcs8(dir.path(), name, &args) else {
            continue;
        };
        checked = checked.saturating_add(1);
        // One vault per scheme, in a directory of its own: `Vault::create`
        // refuses to write over a file that is already there.
        let home = dir.path().join(format!("{name}.vault"));
        std::fs::create_dir_all(&home).unwrap();
        let (mut vault, node) = vault_with_credential(&home);

        let refused = vault.import_private_key(node, &key, Some(&Secret::new(String::from(WRONG))));
        assert_eq!(said(refused), "rejected", "for {name}");
        assert!(
            !vault.has_secret(node, "passphrase").unwrap(),
            "for {name}: a passphrase that does not open the key reached the vault"
        );

        let accepted =
            vault.import_private_key(node, &key, Some(&Secret::new(String::from(RIGHT))));
        assert_eq!(said(accepted), "<accepted as Pkcs8>", "for {name}");
    }

    // Nothing to say where OpenSSL is absent; the generated container below
    // covers the same ground without it.
    assert!(checked == 0 || checked == 4, "checked {checked} of 4");
}

/// A passphrase with a character outside ASCII opens the container it opened
/// when it was typed, byte for byte.
///
/// The vault normalises the *master* password before deriving from it; a key
/// passphrase is handed to `ssh-keygen`, OpenSSL and every other tool as the
/// bytes it is, so normalising one here would refuse a passphrase that works
/// everywhere else.
#[test]
fn a_passphrase_outside_ascii_is_tried_as_the_bytes_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let phrase = "pêche Mélba 2026";
    let Some(key) = ssh_keygen(dir.path(), "id_ed25519", phrase) else {
        return;
    };
    let (mut vault, node) = vault_with_credential(dir.path());
    let accepted = vault.import_private_key(node, &key, Some(&Secret::new(String::from(phrase))));
    assert_eq!(said(accepted), "<accepted as OpenSsh>");
}

// --------------------------------------------- the four refusals, always ---

/// The reproduction without any tooling: the same assertions over a container
/// generated in this process, so a machine with no `ssh-keygen` still runs them.
#[test]
fn a_wrong_passphrase_is_refused_without_any_tooling() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, node) = vault_with_credential(dir.path());
    let path = dir.path().join("id_ed25519");
    std::fs::write(&path, testing::encrypted_openssh_key(RIGHT.as_bytes())).unwrap();

    let refused = vault.import_private_key(node, &path, Some(&Secret::new(String::from(WRONG))));
    assert_eq!(said(refused), "rejected");
    assert!(!vault.has_secret(node, "passphrase").unwrap());
    assert!(!vault.has_secret(node, "private_key").unwrap());

    let accepted = vault.import_private_key(node, &path, Some(&Secret::new(String::from(RIGHT))));
    assert_eq!(said(accepted), "<accepted as OpenSsh>");
}

/// Four things can be wrong with a passphrase, and they are four errors.
///
/// They used to be one — or none. "No passphrase given" and "that passphrase is
/// wrong" shared a code, "a passphrase for a key that needs none" was raised as
/// a malformed request, and "this build cannot check" did not exist because
/// nothing checked.
#[test]
fn the_four_things_that_can_be_wrong_are_four_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, node) = vault_with_credential(dir.path());

    let encrypted = dir.path().join("encrypted");
    std::fs::write(&encrypted, testing::encrypted_openssh_key(RIGHT.as_bytes())).unwrap();
    let plain = dir.path().join("plain");
    std::fs::write(&plain, testing::plain_openssh_key()).unwrap();
    let ppk = dir.path().join("key.ppk");
    std::fs::write(&ppk, ppk_document("aes256-cbc")).unwrap();

    let right = Secret::new(String::from(RIGHT));
    let wrong = Secret::new(String::from(WRONG));

    assert_eq!(
        said(vault.import_private_key(node, &encrypted, None)),
        "required"
    );
    assert_eq!(
        said(vault.import_private_key(node, &encrypted, Some(&wrong))),
        "rejected"
    );
    assert_eq!(
        said(vault.import_private_key(node, &plain, Some(&right))),
        "not-needed"
    );
    let uncheckable = said(vault.import_private_key(node, &ppk, Some(&right)));
    assert!(uncheckable.starts_with("uncheckable: "), "{uncheckable}");
    assert!(uncheckable.contains("PuTTY"), "{uncheckable}");

    // None of the four wrote anything.
    assert!(vault.secret_fields(node).unwrap().is_empty());
}

/// An empty passphrase is the same thing as no passphrase.
///
/// A field nobody typed into arrives as both, depending on which screen it came
/// from, and "that passphrase does not open the key" said about an empty box is
/// a sentence that helps nobody.
#[test]
fn an_empty_passphrase_reads_as_none_given() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, node) = vault_with_credential(dir.path());
    let path = dir.path().join("id_ed25519");
    std::fs::write(&path, testing::encrypted_openssh_key(RIGHT.as_bytes())).unwrap();

    let empty = Secret::new(String::new());
    assert_eq!(
        said(vault.import_private_key(node, &path, Some(&empty))),
        "required"
    );

    // And on a container that needs none, an empty passphrase is not the
    // spurious-passphrase refusal either: nobody offered anything.
    let plain = dir.path().join("plain");
    std::fs::write(&plain, testing::plain_openssh_key()).unwrap();
    assert_eq!(
        said(vault.import_private_key(node, &plain, Some(&empty))),
        "<accepted as OpenSsh>"
    );
}

/// A container this build cannot open is refused rather than sealed on trust.
///
/// `ssh-keygen -Z` writes these, the key parser downstream reads them, and this
/// build cannot try a passphrase against one. Storing the passphrase anyway is
/// the ordering the whole change exists to end, so the import says so instead —
/// and says which container, because the remedy is to convert that one.
#[test]
fn a_container_this_build_cannot_open_says_so_rather_than_sealing_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, node) = vault_with_credential(dir.path());
    let right = Secret::new(String::from(RIGHT));

    for (name, bytes, expected) in [
        ("key.ppk", ppk_document("aes256-cbc"), "PuTTY"),
        (
            "gcm",
            testing::openssh_key_under("aes256-gcm@openssh.com"),
            "AES-GCM",
        ),
        (
            "chacha",
            testing::openssh_key_under("chacha20-poly1305@openssh.com"),
            "chacha20-poly1305",
        ),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        let outcome = said(vault.import_private_key(node, &path, Some(&right)));
        assert!(outcome.contains(expected), "for {name}: {outcome}");
        assert!(
            vault.secret_fields(node).unwrap().is_empty(),
            "for {name}: something was written for a container nothing checked"
        );
    }
}

/// A PuTTY `.ppk` declaring `encryption`. Only the headers matter: the vault
/// reads the `Encryption:` line and refuses to try a passphrase against the
/// rest.
fn ppk_document(encryption: &str) -> Vec<u8> {
    format!(
        "PuTTY-User-Key-File-3: ssh-ed25519\n\
         Encryption: {encryption}\n\
         Comment: sample\n\
         Public-Lines: 1\n\
         AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
         Private-Lines: 1\n\
         AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
         Private-MAC: 00\n"
    )
    .into_bytes()
}

/// Nothing on this path formats a passphrase, including the refusals.
///
/// A refusal is the most likely thing to be copied into a bug report, and a
/// message naming the passphrase that was tried would put it there.
#[test]
fn no_refusal_carries_the_passphrase_that_was_tried() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, node) = vault_with_credential(dir.path());
    let path = dir.path().join("id_ed25519");
    std::fs::write(&path, testing::encrypted_openssh_key(RIGHT.as_bytes())).unwrap();

    let outcome = vault.import_private_key(node, &path, Some(&Secret::new(String::from(WRONG))));
    let Err(error) = outcome else {
        panic!("a wrong passphrase was accepted");
    };
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(WRONG), "{rendered}");
    assert!(!rendered.contains(RIGHT), "{rendered}");
}
