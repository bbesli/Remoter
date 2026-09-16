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

mod actor;
mod audit;
mod credential;
mod crypto;
mod error;
mod header;
mod legacy_pem;
mod openssh;
mod pkcs8;
mod recovery;
mod secret;
mod settings;
mod slots;
mod storage;
#[cfg(feature = "test-fixtures")]
pub mod testing;
mod vault;

pub use actor::{AuditActor, AuditActorRecord, AuditActorSummary, audit_actor, set_audit_actor};
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
///
/// A purpose names one protocol, because that is what the restriction is stated
/// in: the caller must pick the variant for the protocol it is actually
/// opening, never a convenient constant. Picking one variant for every protocol
/// turns the check into "is this credential allowed for SSH?" no matter what is
/// being opened, which refuses every correctly restricted RDP, VNC and SFTP
/// credential and, worse, would pass an SSH-only one if the constant ever
/// changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    SshPassword,
    SshPrivateKey,
    RdpCredentials,
    VncPassword,
    SftpPassword,
    /// A private key borrowed for an SFTP session.
    ///
    /// SFTP is a subsystem of an SSH connection (RFC 4254 §6.5), so the *key*
    /// is an SSH key — but the restriction the user wrote is per protocol, and
    /// `sftp` is a protocol of its own in the data model. A credential marked
    /// "SFTP only" must open an SFTP file pane, and an SSH-only one must not,
    /// so the two cannot share a purpose that resolves to `ssh`.
    SftpPrivateKey,
    FtpPassword,
    /// Shown to the user on screen, on an explicit action. Always audited.
    Reveal,
    /// Written to an export. Always audited.
    Export,
}
