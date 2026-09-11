//! Private key credentials: import, round trip, and the refusals.
//!
//! The key material is stored in the vault rather than left on disk, so a
//! credential does not stop working when the vault is carried to another
//! machine. The format is read from the file's content, because a `.pem` holding
//! an OpenSSH container is ordinary and a name is not evidence.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::fs;
use std::path::{Path, PathBuf};

use remoter_core::{CredentialProps, KeyFormat, Node, NodeKind, SecretKind};
use remoter_vault::{
    CreateOptions, ExposeSecret, ImportedKey, KdfParams, Purpose, RecoveryKey, Secret,
    UnlockMethod, Vault, VaultError, agent_credential, private_key_credential,
};

const PASSWORD: &str = "a master password";
const PASSPHRASE: &str = "the passphrase on the key";

fn create(dir: &Path) -> (Vault, RecoveryKey, PathBuf) {
    let path = dir.join("acme.rvault");
    let (vault, key) = Vault::create(
        CreateOptions::new(
            &path,
            "Acme Production",
            Secret::new(String::from(PASSWORD)),
        )
        .with_kdf_params(KdfParams::low_cost_for_tests()),
    )
    .unwrap();
    (vault, key, path)
}

fn reopen(path: &Path) -> Vault {
    Vault::open(
        path,
        UnlockMethod::password(Secret::new(String::from(PASSWORD))),
    )
    .unwrap()
}

/// Inserts a credential node shaped to hold a private key, and returns its id.
fn key_credential(vault: &mut Vault, with_passphrase: bool) -> uuid::Uuid {
    insert(
        vault,
        private_key_credential("svc-deploy", KeyFormat::OpenSsh, with_passphrase),
    )
}

fn insert(vault: &mut Vault, props: CredentialProps) -> uuid::Uuid {
    let mut tree = vault.tree().unwrap();
    let node = Node::new(NodeKind::Credential(props), "svc-deploy", 1_700_000_000_000);
    let id = *node.id.as_uuid();
    let patch = tree.insert(node).unwrap();
    vault.apply(&tree, &patch).unwrap();
    id
}

// -------------------------------------------------------------- samples ---
//
// Well-formed containers around meaningless key material. Enough for the
// detector, which reads the armour and the cipher name and nothing else.

fn pem(label: &str, body: &[u8]) -> Vec<u8> {
    let encoded = data_encoding::BASE64.encode(body);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out.into_bytes()
}

fn openssh(cipher: &str) -> Vec<u8> {
    let mut body = Vec::from(&b"openssh-key-v1\0"[..]);
    body.extend_from_slice(&u32::try_from(cipher.len()).unwrap().to_be_bytes());
    body.extend_from_slice(cipher.as_bytes());
    body.extend_from_slice(b"\0\0\0\x04none\0\0\0\0\0\0\0\x01");
    pem("OPENSSH PRIVATE KEY", &body)
}

fn pkcs8(encrypted: bool) -> Vec<u8> {
    let label = if encrypted {
        "ENCRYPTED PRIVATE KEY"
    } else {
        "PRIVATE KEY"
    };
    pem(label, &[0x30, 0x03, 0x02, 0x01, 0x00])
}

fn ppk(encryption: &str) -> Vec<u8> {
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

// ---------------------------------------------------------------- tests ---

#[test]
fn every_format_survives_a_round_trip_through_the_file() {
    for (name, bytes, expected) in [
        ("id_ed25519", openssh("none"), KeyFormat::OpenSsh),
        ("id_rsa.pk8", pkcs8(false), KeyFormat::Pkcs8),
        ("id_ed25519.ppk", ppk("none"), KeyFormat::PuttyPpk),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _key, path) = create(dir.path());
        let node = key_credential(&mut vault, false);

        let key_path = dir.path().join(name);
        fs::write(&key_path, &bytes).unwrap();

        let format = vault.import_private_key(node, &key_path, None).unwrap();
        assert_eq!(format, expected, "for {name}");
        vault.save().unwrap();
        vault.lock();

        let mut reopened = reopen(&path);
        let material = reopened
            .borrow_private_key(node, Purpose::SshPrivateKey)
            .unwrap();
        assert_eq!(material.format(), expected);
        assert_eq!(material.key().expose_secret().as_slice(), bytes.as_slice());
        assert!(material.passphrase().is_none());

        // The node's own description agrees with what was stored.
        let stored = reopened.node(node).unwrap().unwrap();
        match stored.kind {
            NodeKind::Credential(credential) => match credential.secret {
                SecretKind::PrivateKey {
                    format,
                    sealed_passphrase,
                    sealed_key,
                } => {
                    assert_eq!(format, expected);
                    assert!(sealed_passphrase.is_none());
                    assert!(!sealed_key.is_empty());
                }
                other => panic!("expected a private key credential, got {other:?}"),
            },
            other => panic!("expected a credential node, got {other:?}"),
        }
    }
}

#[test]
fn a_format_is_detected_from_content_not_from_the_extension() {
    // `ssh-keygen -m PEM` writes an OpenSSH container into a file people name
    // `.pem`; a PPK arrives in a support ticket as `.txt`.
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path());

    for (name, bytes, expected) in [
        ("misleading.pem", openssh("none"), KeyFormat::OpenSsh),
        ("misleading.ppk", pkcs8(false), KeyFormat::Pkcs8),
        ("misleading.txt", ppk("none"), KeyFormat::PuttyPpk),
    ] {
        let node = key_credential(&mut vault, false);
        let key_path = dir.path().join(name);
        fs::write(&key_path, &bytes).unwrap();
        assert_eq!(
            vault.import_private_key(node, &key_path, None).unwrap(),
            expected,
            "for {name}"
        );
    }
}

#[test]
fn a_passphrase_protected_key_stores_its_passphrase_as_a_separate_field() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path());
    let node = key_credential(&mut vault, true);

    let bytes = openssh("aes256-ctr");
    let key_path = dir.path().join("id_ed25519");
    fs::write(&key_path, &bytes).unwrap();

    let key = ImportedKey::read(&key_path).unwrap();
    assert!(
        key.is_encrypted(),
        "the container says so; the interface must be able to ask before storing"
    );
    vault
        .set_private_key(node, &key, Some(&Secret::new(String::from(PASSPHRASE))))
        .unwrap();
    vault.save().unwrap();
    vault.lock();

    let mut reopened = reopen(&path);
    assert_eq!(
        reopened.secret_fields(node).unwrap(),
        vec![String::from("passphrase"), String::from("private_key")],
        "the passphrase is its own field, so revealing one does not reveal the other"
    );

    let material = reopened
        .borrow_private_key(node, Purpose::SshPrivateKey)
        .unwrap();
    assert_eq!(material.key().expose_secret().as_slice(), bytes.as_slice());
    assert_eq!(
        material.passphrase().map(|p| p.expose_secret().as_slice()),
        Some(PASSPHRASE.as_bytes())
    );
}

#[test]
fn replacing_an_encrypted_key_with_a_plain_one_removes_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path());
    let node = key_credential(&mut vault, true);

    let encrypted = dir.path().join("encrypted");
    fs::write(&encrypted, openssh("aes256-ctr")).unwrap();
    vault
        .import_private_key(
            node,
            &encrypted,
            Some(&Secret::new(String::from(PASSPHRASE))),
        )
        .unwrap();
    assert!(vault.has_secret(node, "passphrase").unwrap());

    let plain = dir.path().join("plain");
    fs::write(&plain, openssh("none")).unwrap();
    vault.import_private_key(node, &plain, None).unwrap();

    assert!(
        !vault.has_secret(node, "passphrase").unwrap(),
        "a stale passphrase is worse than none"
    );
    let material = vault
        .borrow_private_key(node, Purpose::SshPrivateKey)
        .unwrap();
    assert!(material.passphrase().is_none());
}

#[test]
fn a_file_that_is_not_a_key_is_refused_with_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path());
    let node = key_credential(&mut vault, false);

    let notes = dir.path().join("notes.txt");
    fs::write(&notes, b"remember to renew the certificate in March").unwrap();
    assert!(matches!(
        vault.import_private_key(node, &notes, None),
        Err(VaultError::NotAPrivateKey)
    ));

    let public = dir.path().join("id_ed25519.pub");
    fs::write(&public, b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 alice@laptop\n").unwrap();
    assert!(matches!(
        vault.import_private_key(node, &public, None),
        Err(VaultError::NotAPrivateKey)
    ));

    // A key this build cannot authenticate with is named rather than mis-filed.
    // PKCS#1 RSA and SEC 1 EC used to be refused here too; they are now
    // re-enveloped as PKCS#8 on import, which `crates/remoter-vault/src/
    // credential.rs` tests against real `ssh-keygen` output.
    let dsa = dir.path().join("id_dsa");
    fs::write(
        &dsa,
        pem("DSA PRIVATE KEY", &[0x30, 0x03, 0x02, 0x01, 0x00]),
    )
    .unwrap();
    assert!(matches!(
        vault.import_private_key(node, &dsa, None),
        Err(VaultError::UnsupportedKeyFormat("OpenSSL DSA PEM"))
    ));

    // Nothing was stored by any of the three.
    assert!(!vault.has_secret(node, "private_key").unwrap());
}

#[test]
fn a_missing_file_and_a_missing_node_are_both_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path());
    let node = key_credential(&mut vault, false);

    assert!(matches!(
        vault.import_private_key(node, &dir.path().join("nothing-here"), None),
        Err(VaultError::Io { .. })
    ));

    let key_path = dir.path().join("id_ed25519");
    fs::write(&key_path, openssh("none")).unwrap();
    assert!(matches!(
        vault.import_private_key(uuid::Uuid::now_v7(), &key_path, None),
        Err(VaultError::NoSuchNode(_))
    ));
}

#[test]
fn a_node_that_is_not_a_credential_cannot_hold_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path());

    let mut tree = vault.tree().unwrap();
    let folder = Node::new(NodeKind::folder(), "Datacentre EU-West", 1_700_000_000_000);
    let id = *folder.id.as_uuid();
    let patch = tree.insert(folder).unwrap();
    vault.apply(&tree, &patch).unwrap();

    let key_path = dir.path().join("id_ed25519");
    fs::write(&key_path, openssh("none")).unwrap();
    assert!(matches!(
        vault.import_private_key(id, &key_path, None),
        Err(VaultError::NotAPrivateKeyCredential(_))
    ));
}

#[test]
fn an_agent_credential_holds_no_key_material_at_all() {
    // The most secure option for SSH: the signing happens in the platform
    // agent, so the key never enters this process.
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, path) = create(dir.path());
    let node = insert(
        &mut vault,
        agent_credential("svc-deploy", Some("deploy".into())),
    );
    vault.save().unwrap();
    vault.lock();

    let mut reopened = reopen(&path);
    assert!(
        reopened.secret_fields(node).unwrap().is_empty(),
        "an agent credential must store nothing"
    );
    assert!(matches!(
        reopened.borrow_private_key(node, Purpose::SshPrivateKey),
        Err(VaultError::NotAPrivateKeyCredential(_))
    ));

    let stored = reopened.node(node).unwrap().unwrap();
    match stored.kind {
        NodeKind::Credential(credential) => match credential.secret {
            SecretKind::Agent { comment_filter } => {
                assert_eq!(comment_filter.as_deref(), Some("deploy"));
            }
            other => panic!("expected an agent credential, got {other:?}"),
        },
        other => panic!("expected a credential node, got {other:?}"),
    }
}

#[test]
fn no_debug_output_anywhere_on_the_path_shows_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _key, _path) = create(dir.path());
    let node = key_credential(&mut vault, true);

    let bytes = openssh("aes256-ctr");
    let key_path = dir.path().join("id_ed25519");
    fs::write(&key_path, &bytes).unwrap();

    let key = ImportedKey::read(&key_path).unwrap();
    vault
        .set_private_key(node, &key, Some(&Secret::new(String::from(PASSPHRASE))))
        .unwrap();
    let material = vault
        .borrow_private_key(node, Purpose::SshPrivateKey)
        .unwrap();

    let stored = vault.node(node).unwrap().unwrap();
    let rendered = format!(
        "{key:?} {material:?} {vault:?} {stored:?} {:?}",
        vault.slots()
    );

    // The armour lines are the key as a leak would show it.
    let armour = String::from_utf8_lossy(&bytes);
    for line in armour.lines().filter(|l| !l.starts_with("-----")) {
        assert!(
            !rendered.contains(line),
            "key material reached Debug output"
        );
    }
    assert!(!rendered.contains(PASSPHRASE), "a passphrase reached Debug");
    assert!(
        !rendered.contains(PASSWORD),
        "the master password reached Debug"
    );
    assert!(rendered.contains("<redacted>"));
}
