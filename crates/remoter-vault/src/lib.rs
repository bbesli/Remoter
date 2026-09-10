//! The Remoter vault: an encrypted, portable container holding connections and
//! their credentials.
//!
//! The normative specification is `docs/security/vault-format.md`. Read it
//! before changing anything in this crate. The essentials:
//!
//! - A random 256-bit **Vault Master Key** (VMK) is generated once, at vault
//!   creation, and is never written to disk in plaintext.
//! - HKDF-SHA256 derives a content key (CEK), a per-field secret key (SEK), a
//!   header MAC key and an index key from the VMK, each with a distinct info
//!   string.
//! - Each unlock method stores its own copy of the VMK, wrapped under a
//!   slot-specific key-encryption key. Adding, rotating or revoking a method
//!   rewrites one slot; it never re-encrypts the body.
//! - Secret *fields* are encrypted a second time under the SEK, with the AEAD's
//!   associated data binding each ciphertext to its record id, field name and
//!   revision.
//!
//! Every dependency API used here is recorded in
//! `docs/development/verified-apis.md`. It was compiled and tested, not
//! recalled — the 2026 RustCrypto generation changed most of these signatures.

#![doc(html_no_source)]

mod audit;
mod credential;
mod crypto;
mod error;
mod header;
mod recovery;
mod secret;
mod settings;
mod slots;
mod storage;
mod vault;

pub use audit::{AuditCategory, AuditQuery, AuditRecord};
pub use credential::{ImportedKey, PrivateKeyMaterial, agent_credential, private_key_credential};
pub use error::{UnlockError, VaultError};
pub use header::{FORMAT_VERSION, KdfParams, MAGIC, SlotInfo, SlotKind, VaultHeader, VaultInfo};
pub use recovery::RecoveryKey;
pub use secret::{ExposeSecret, Secret};
pub use settings::{SessionOnLock, VaultSettings};
pub use slots::{PasswordCredential, RotationOutcome, RotationPlan, UnlockMethod};
pub use storage::{AuditEvent, AuditOutcome, SCHEMA_VERSION};
pub use vault::{CreateOptions, Vault};

/// Purpose a borrowed credential may be used for. Recorded in the audit log and
/// checked against the credential's own restriction, so an importer mistake or
/// a mistyped protocol cannot spray a password at the wrong service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    SshPassword,
    SshPrivateKey,
    RdpCredentials,
    VncPassword,
    SftpPassword,
    FtpPassword,
    /// Shown to the user on screen, on an explicit action. Always audited.
    Reveal,
    /// Written to an export. Always audited.
    Export,
}
