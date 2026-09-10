//! Typed errors.
//!
//! Two separate enums, because the unlock path has a rule the rest of the crate
//! does not: until a key slot has been unwrapped, an error message must not
//! say *which* part of the attempt was wrong. [`UnlockError`] enforces that by
//! construction — the variants that describe the file in detail
//! ([`UnlockError::HeaderTampered`], [`UnlockError::BodyCorrupt`]) can only be
//! produced after a slot has already unwrapped the master key, so producing one
//! proves the caller held a valid unlock credential. Everything before that
//! point collapses into the single, uninformative
//! [`UnlockError::NotUnlocked`].
//!
//! No variant carries key material, a password, a recovery key or a decrypted
//! field. Errors are formatted into logs and crash reports; anything reachable
//! from one is effectively public.

use std::path::PathBuf;

use uuid::Uuid;

use crate::Purpose;
use crate::header::SlotKind;

/// Everything that can go wrong with a vault once it is open, plus the parts of
/// opening one that reveal nothing about the credential.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The vault file could not be read, written, renamed or synced.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// What was being attempted, in the user's terms.
        operation: &'static str,
        /// The file involved.
        path: PathBuf,
        /// The underlying operating system error.
        source: std::io::Error,
    },

    /// The operating system's random number generator refused. There is no
    /// fallback: a vault that cannot get real entropy must not be created.
    #[error("the operating system random number generator is unavailable")]
    Csprng,

    /// The file does not begin with the vault magic.
    #[error("this file is not a Remoter vault")]
    NotAVault,

    /// The file declares a format this build does not implement. Refused
    /// rather than parsed on a best-effort basis.
    #[error("this vault uses format version {0}, which this build does not support")]
    UnsupportedFormat(u16),

    /// The file is truncated, or a declared length runs past its end.
    #[error("the vault file is truncated or malformed")]
    Malformed,

    /// The CBOR header could not be decoded.
    #[error("the vault header could not be decoded")]
    HeaderDecode,

    /// The CBOR header could not be encoded.
    #[error("the vault header could not be encoded")]
    HeaderEncode,

    /// A key derivation step failed. Never says which one, and never carries
    /// its inputs.
    #[error("key derivation failed")]
    KeyDerivation,

    /// Authenticated encryption or decryption failed.
    #[error("authenticated encryption failed")]
    Aead,

    /// The requested Argon2id cost is below the floor in
    /// `docs/security/vault-format.md`.
    #[error("the Argon2id parameters are below the supported floor")]
    KdfParamsTooWeak,

    /// The file declares an Argon2id cost this build will not attempt.
    ///
    /// Distinct from [`VaultError::KdfParamsTooWeak`] and from
    /// [`UnlockError::HeaderTampered`]: the header is not authenticated at the
    /// point this is raised, so the honest thing to tell the user is what the
    /// file declares and what this build allows, not that someone tampered with
    /// it. Naming the declared value is safe — a cost parameter is public
    /// header data, not key material.
    #[error(
        "this vault declares an Argon2id {parameter} of {declared}, above the {limit} this build will attempt"
    )]
    KdfParamsRefused {
        /// Which parameter was out of range: `m_cost`, `t_cost` or `p_cost`.
        parameter: &'static str,
        /// The value the file declares.
        declared: u32,
        /// The largest value this build accepts.
        limit: u32,
    },

    /// No slot carries the given index.
    #[error("this vault has no key slot {0}")]
    NoSuchSlot(u8),

    /// No slot of the requested kind exists.
    #[error("this vault has no {0} slot")]
    NoSlotOfKind(SlotKind),

    /// The slot table is full.
    #[error("a vault may hold at most {0} key slots")]
    SlotTableFull(usize),

    /// Removing this slot would leave the vault with no way in.
    #[error("removing this slot would leave the vault unopenable")]
    LastSlot,

    /// The slot exists but is not the kind the operation works on — rotating a
    /// recovery key at the index of a password slot, for instance.
    #[error("key slot {index} is a {found} slot, not a {expected} slot")]
    WrongSlotKind {
        /// The slot that was addressed.
        index: u8,
        /// The kind the operation needs.
        expected: SlotKind,
        /// The kind the slot actually is.
        found: SlotKind,
    },

    /// A master key rotation was asked to keep a slot it was given nothing to
    /// re-wrap it with. Refused rather than dropped: silently discarding a slot
    /// takes away someone's way in.
    #[error("key slot {0} cannot be re-wrapped without its credential")]
    SlotCredentialMissing(u8),

    /// The credential offered for a slot does not open it. Safe to be specific:
    /// producing this needs an already-unlocked vault.
    #[error("the credential offered for key slot {0} does not open it")]
    SlotCredentialRejected(u8),

    /// The file is not a private key in any container this build recognises.
    #[error("that file is not a private key")]
    NotAPrivateKey,

    /// The file is a private key, in a container this build does not store.
    ///
    /// Named rather than silently filed under one of the three formats the
    /// domain model has: storing a PKCS#1 key labelled as PKCS#8 would produce
    /// a credential that fails at connect time, far from the mistake.
    #[error("that is a {0} private key; convert it to OpenSSH or PKCS#8 before importing it")]
    UnsupportedKeyFormat(&'static str),

    /// The node is not a credential holding a private key.
    #[error("node {0} is not a private-key credential")]
    NotAPrivateKeyCredential(Uuid),

    /// CTAP2 is not implemented in this version.
    #[error("hardware key slots are not implemented in this version")]
    Fido2Unsupported,

    /// The platform credential store could not be reached, or holds no token
    /// for this vault. Carries no detail from the store: those messages quote
    /// account names.
    #[error("the platform credential store is unavailable or holds no token for this vault")]
    Keychain,

    /// The recovery key does not have the right shape.
    #[error("that is not a valid recovery key")]
    RecoveryKeyMalformed,

    /// The recovery key's check group does not match its body, which almost
    /// always means a transcription slip rather than a wrong key.
    #[error("that recovery key looks mistyped — its check group does not match")]
    RecoveryKeyChecksum,

    /// The key file could not be read.
    #[error("the key file could not be read")]
    Keyfile,

    /// A database operation failed. `rusqlite` messages quote SQL text and
    /// constraint names, never bound parameter values, so they are safe to
    /// surface.
    #[error("the vault database reported an error: {0}")]
    Database(#[from] rusqlite::Error),

    /// The database inside the vault is not a database this build understands.
    #[error("the vault body is not a readable database")]
    NotADatabase,

    /// The vault was written by a newer build.
    #[error("this vault uses schema version {found}; this build supports {supported}")]
    SchemaTooNew {
        /// The version found in the file.
        found: u32,
        /// The newest version this build implements.
        supported: u32,
    },

    /// A migration failed and was rolled back.
    #[error("the vault could not be migrated to schema version {0}")]
    Migration(u32),

    /// A node id that is not in this vault.
    #[error("no node {0} in this vault")]
    NoSuchNode(Uuid),

    /// No such secret field on that node.
    #[error("node {node} has no {field} secret")]
    NoSuchSecret {
        /// The node that was asked.
        node: Uuid,
        /// The field name that was asked for.
        field: String,
    },

    /// The stored ciphertext is bound to a revision the record has moved past.
    /// Either a rollback, or a write that did not complete.
    #[error("the stored secret does not match the revision of its record")]
    StaleSecret,

    /// The credential is restricted and may not be used this way.
    #[error("this credential may not be used for {0:?}")]
    PurposeRefused(Purpose),

    /// A domain-model rule rejected the change.
    #[error("{0}")]
    Core(#[from] remoter_core::CoreError),

    /// A value stored in the database does not fit the schema this build
    /// expects — a 15-byte node id, an unknown node kind, a `props` blob that
    /// is not CBOR.
    #[error("the vault database holds a row this build cannot read: {0}")]
    CorruptRow(&'static str),
}

impl VaultError {
    /// Wraps an I/O error with what was being attempted and on which file.
    pub(crate) fn io(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }
}

/// What can go wrong while opening a vault.
///
/// The ordering of the variants mirrors the unlock sequence in
/// `docs/security/vault-format.md`. Read the module documentation before adding
/// a variant: which failures are allowed to be specific, and when, is a
/// security property of this enum rather than a matter of taste.
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// The supplied credential did not unwrap any slot of its kind.
    ///
    /// Deliberately says nothing further. A wrong password, a wrong key file, a
    /// missing key file and a corrupted slot table all land here, because
    /// distinguishing them tells an attacker at the keyboard which half of a
    /// two-factor unlock they have already guessed.
    #[error("That did not unlock the vault.")]
    NotUnlocked,

    /// A slot unwrapped, but the header does not match its MAC.
    ///
    /// Reaching this variant requires having already produced a valid
    /// key-encryption key, so the extra detail is given to someone who has
    /// authenticated. It points at the rolling backups because a tampered or
    /// bit-rotted header is exactly what they exist for.
    #[error(
        "The vault header has been modified since it was written. Open one of the backups beside it."
    )]
    HeaderTampered,

    /// A slot unwrapped and the header verified, but the body did not decrypt.
    #[error(
        "The vault contents could not be decrypted. The file is damaged; open one of the backups beside it."
    )]
    BodyCorrupt,

    /// The vault has no slot of the kind the caller tried to unlock with.
    #[error("This vault has no {0} unlock method.")]
    NoSuchMethod(SlotKind),

    /// CTAP2 is not implemented in this version.
    #[error("Hardware key unlock is not implemented in this version.")]
    Fido2Unsupported,

    /// Everything that is not about the credential: the file would not open,
    /// the format version is unknown, the database would not load.
    #[error(transparent)]
    Vault(#[from] VaultError),
}
