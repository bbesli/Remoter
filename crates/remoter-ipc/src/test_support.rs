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

/// An unencrypted PKCS#8 container.
///
/// The body is the shortest thing that satisfies the detector: valid base64
/// whose first byte is the DER `SEQUENCE` tag. No real key material is
/// committed to this repository, and none is needed — what is under test is the
/// container handling, not the cryptography.
pub(crate) const PKCS8_KEY: &str =
    "-----BEGIN PRIVATE KEY-----\nMIIBAA==\n-----END PRIVATE KEY-----\n";

/// The same, in the container that says its material is encrypted.
pub(crate) const PKCS8_ENCRYPTED_KEY: &str =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIBAA==\n-----END ENCRYPTED PRIVATE KEY-----\n";

/// Whether a path exists, for a test that asserts a file was written.
pub(crate) fn exists(path: &Path) -> bool {
    path.exists()
}
