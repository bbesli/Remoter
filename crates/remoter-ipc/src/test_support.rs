//! Shared fixtures for the tests in this crate.
//!
//! Creating a vault runs Argon2id at the format's cost floor, which is
//! deliberately expensive: a test that needs one creates it once and asserts
//! several things against it rather than creating four.

use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::commands::vault_create_impl;
use crate::dto::CreateVaultRequestDto;
use crate::state::AppState;

/// A master password the entropy gate accepts. Six words from the generator's
/// list: 66 bits.
pub(crate) const PASSPHRASE: &str = "acorn-basil-cedar-drift-ember-fable";

/// A directory of our own under the system temporary directory, removed when
/// the guard drops.
pub(crate) struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().join(format!("remoter-ipc-{}", Uuid::now_v7().simple()));
        let _ = fs::create_dir_all(&path);
        Self { path }
    }

    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Writes a file inside the scratch directory and returns its path.
    pub(crate) fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.join(name);
        let _ = fs::write(&path, contents);
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A state with a freshly created, open vault.
///
/// Returns `None` if creation failed, so the caller can say so rather than
/// unwrapping — this crate denies `unwrap` in tests as well.
pub(crate) fn open_vault(scratch: &Scratch) -> Option<AppState> {
    let state = AppState::with_config_dir(scratch.join("config"));
    let path = scratch.join("test.rvault");
    let request = CreateVaultRequestDto {
        path: path.display().to_string(),
        label: String::from("Test vault"),
        password: String::from(PASSPHRASE),
        keyfile_path: None,
        generate_keyfile_at: None,
    };
    vault_create_impl(&state, request).ok().map(|_| state)
}

/// The message from a failed call, for an assertion that wants to say why.
pub(crate) fn why<T>(result: &Result<T, crate::error::IpcError>) -> String {
    result
        .as_ref()
        .err()
        .map_or_else(String::new, |err| err.message.clone())
}

/// The passphrase [`pkcs8_encrypted_key`] is enciphered under.
pub(crate) const KEY_PASSPHRASE: &str = "opensesame";

/// An unencrypted PKCS#8 container.
///
/// A whole `PrivateKeyInfo` rather than the header over arbitrary bytes this
/// used to be: the vault walks an unenciphered container all the way through
/// now, because a document it cannot read is a credential that would fail when
/// a session was opened. Still no key material — the structure is real and the
/// seed inside it is zeros, and `CLAUDE.md` §9 forbids committing the other
/// kind.
pub(crate) fn pkcs8_key() -> String {
    String::from_utf8_lossy(&remoter_vault::testing::plain_pkcs8_key()).into_owned()
}

/// The same document, enciphered so that [`KEY_PASSPHRASE`] opens it.
///
/// Really enciphered, because the vault now tries the passphrase against the
/// container before it seals one.
pub(crate) fn pkcs8_encrypted_key() -> String {
    String::from_utf8_lossy(&remoter_vault::testing::encrypted_pkcs8_key(
        KEY_PASSPHRASE.as_bytes(),
    ))
    .into_owned()
}

/// Generates a private key file with the system's own `ssh-keygen`.
///
/// `passphrase` is the empty string for an unencrypted key, exactly as `-N ""`
/// means on the command line; `args` carries the type and container flags.
///
/// Real `ssh-keygen` output rather than a fixture, because what is under test
/// is whether Remoter reads the files administrators actually have. No key
/// file is committed — `CLAUDE.md` §9 forbids it — and the one written here
/// goes into the scratch directory, which is removed when its guard drops.
///
/// Returns `None` when `ssh-keygen` is not on PATH or refused, so a caller can
/// say so rather than unwrapping: this crate denies `unwrap` in tests as well.
pub(crate) fn ssh_keygen(
    scratch: &Scratch,
    name: &str,
    passphrase: &str,
    args: &[&str],
) -> Option<PathBuf> {
    let path = scratch.join(name);
    let path_arg = path.to_str()?;
    let output = std::process::Command::new("ssh-keygen")
        .args(["-q", "-C", "remoter-test", "-N", passphrase, "-f", path_arg])
        .args(args)
        .output()
        .ok()?;
    output.status.success().then_some(path)
}

/// Whether a path exists, for a test that asserts a file was written.
pub(crate) fn exists(path: &Path) -> bool {
    path.exists()
}
