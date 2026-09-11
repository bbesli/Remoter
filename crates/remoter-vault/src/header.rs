//! The file header: framing, the CBOR header itself, and the key slot table.
//!
//! Layout, from `docs/security/vault-format.md`:
//!
//! ```text
//! MAGIC        8 B   "RMTRVLT\x01"
//! FORMAT_VER   2 B   u16 little-endian
//! HEADER_LEN   4 B   u32 little-endian
//! HEADER       variable, CBOR, plaintext but authenticated
//! HEADER_MAC  32 B   keyed BLAKE3 over MAGIC ‖ VER ‖ LEN ‖ HEADER
//! BODY_NONCE  24 B
//! BODY        variable, XChaCha20-Poly1305(CEK, nonce, sqlite_bytes)
//!                       with AAD = MAGIC ‖ FORMAT_VER ‖ HEADER
//! BODY_TAG    16 B   (the trailing 16 bytes of BODY as returned by the AEAD)
//! ```
//!
//! The header is readable without a key on purpose: a user should be able to
//! see which unlock methods a vault offers before committing to one. It holds
//! nothing secret — a salt, a nonce and a wrapped key are all safe in the
//! clear — and the MAC makes it readable but not modifiable.
//!
//! Two details that are easy to get wrong and are load-bearing:
//!
//! - The MAC covers `HEADER_LEN`; the body's associated data does not. They are
//!   different byte strings and the specification says so explicitly.
//! - Verification uses the header bytes exactly as they were read, never a
//!   re-serialisation. CBOR encoders are allowed latitude that would silently
//!   change the MAC input.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{MAC_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::VaultError;

/// The first eight bytes of every vault file.
pub const MAGIC: [u8; 8] = *b"RMTRVLT\x01";

/// The format version this build reads and writes. A reader that meets a
/// version it does not implement refuses the file rather than guessing.
pub const FORMAT_VERSION: u16 = 1;

/// Upper bound on the CBOR header, as a sanity check before allocating.
/// Sixteen slots with their labels come to a few kilobytes; a megabyte is
/// generous by three orders of magnitude and still bounded.
pub(crate) const MAX_HEADER_LEN: u32 = 1 << 20;

/// Maximum number of key slots. LUKS1 chose eight for the same reason: enough
/// for every unlock method a person actually enrols, small enough that the
/// table stays inspectable.
pub(crate) const MAX_SLOTS: usize = 16;

/// Offset of `HEADER_LEN` within the file.
pub(crate) const HEADER_LEN_OFFSET: usize = MAGIC.len() + 2;

/// Offset at which the CBOR header begins.
pub(crate) const HEADER_OFFSET: usize = HEADER_LEN_OFFSET + 4;

/// Name of the AEAD the body is sealed with, as recorded in the header.
pub(crate) const CIPHER_XCHACHA20POLY1305: &str = "xchacha20poly1305";

/// Name of the password-slot KDF, as recorded in the header.
pub(crate) const KDF_ARGON2ID: &str = "argon2id";

/// How a key slot turns its input into a key-encryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotKind {
    /// A human-chosen password, optionally combined with a key file.
    Password,
    /// A generated 256-bit recovery key.
    Recovery,
    /// A CTAP2 authenticator's `hmac-secret` output.
    Fido2,
    /// A generated token held in the platform credential store.
    Keychain,
}

impl SlotKind {
    /// The wire spelling, which is also what goes into the wrapping associated
    /// data. Changing one of these strings invalidates every existing slot of
    /// that kind, so they are fixed by the format.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Recovery => "recovery",
            Self::Fido2 => "fido2",
            Self::Keychain => "keychain",
        }
    }
}

impl fmt::Display for SlotKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Argon2id cost parameters, stored per slot so that a vault created on a
/// workstation still opens on a low-memory laptop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost, in kibibytes.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
    /// Argon2 version number; `0x13` is the current one.
    pub version: u32,
}

impl KdfParams {
    /// Minimum memory cost: 256 MiB, expressed in kibibytes.
    pub const FLOOR_M_COST: u32 = 256 * 1024;
    /// Minimum iterations.
    pub const FLOOR_T_COST: u32 = 3;
    /// Minimum lanes.
    pub const FLOOR_P_COST: u32 = 4;
    /// Upper bound used when calibrating: 1 GiB, in kibibytes. Past this the
    /// cost of unlocking on a modest machine outweighs the gain.
    pub const CALIBRATION_MAX_M_COST: u32 = 1024 * 1024;
    /// Argon2 version this build writes.
    pub const CURRENT_VERSION: u32 = 0x13;

    /// Largest memory cost this build will hand to Argon2id: 4 GiB, in
    /// kibibytes. Four times [`KdfParams::CALIBRATION_MAX_M_COST`], so a vault
    /// calibrated on a machine far larger than this one still opens.
    pub const READ_MAX_M_COST: u32 = 4 * 1024 * 1024;
    /// Largest iteration count this build will run.
    pub const READ_MAX_T_COST: u32 = 32;
    /// Largest lane count this build will run.
    pub const READ_MAX_P_COST: u32 = 16;

    /// The hard floor from `docs/security/vault-format.md`.
    #[must_use]
    pub const fn floor() -> Self {
        Self {
            m_cost: Self::FLOOR_M_COST,
            t_cost: Self::FLOOR_T_COST,
            p_cost: Self::FLOOR_P_COST,
            version: Self::CURRENT_VERSION,
        }
    }

    /// Deliberately weak parameters for this crate's own test suite.
    ///
    /// Never use these for a real vault: at 8 MiB and one pass they are worth
    /// roughly nothing against an offline attacker. They exist so that a test
    /// run that creates a few hundred vaults finishes in seconds rather than
    /// half an hour, and the suite still keeps one test at
    /// [`KdfParams::floor`] so the real path stays covered.
    #[doc(hidden)]
    #[must_use]
    pub const fn low_cost_for_tests() -> Self {
        Self {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            version: Self::CURRENT_VERSION,
        }
    }

    /// Rejects parameters below the floor.
    ///
    /// Applied when *creating* a slot, never when opening one: a vault written
    /// by an older build with weaker parameters must still open, and is offered
    /// an upgrade instead. See [`KdfParams::is_below_floor`].
    pub const fn check_floor(self) -> Result<Self, VaultError> {
        if self.m_cost < Self::FLOOR_M_COST
            || self.t_cost < Self::FLOOR_T_COST
            || self.p_cost < Self::FLOOR_P_COST
        {
            return Err(VaultError::KdfParamsTooWeak);
        }
        Ok(self)
    }

    /// Whether these parameters are weaker than the current floor. The unlock
    /// path uses this to offer an upgrade rather than to refuse.
    #[must_use]
    pub const fn is_below_floor(self) -> bool {
        self.m_cost < Self::FLOOR_M_COST
            || self.t_cost < Self::FLOOR_T_COST
            || self.p_cost < Self::FLOOR_P_COST
    }

    /// Rejects parameters this build will not spend the memory or the time on.
    ///
    /// This is the *read*-path bound and is the opposite direction to
    /// [`KdfParams::check_floor`], which is the *write*-path minimum. The two
    /// answer different questions and neither implies the other: the floor asks
    /// "is this strong enough to create a slot with?", the ceiling asks "will
    /// this build survive attempting a slot that declares this?".
    ///
    /// It has to be applied before a slot is attempted, because the cost
    /// parameters come out of the unauthenticated header: the MAC key is
    /// derived from the master key the KDF is about to produce, so there is no
    /// integrity check available yet. Without a ceiling, anyone who can write
    /// the file — a colleague with access to a shared folder, a synchronisation
    /// service — can set `m_cost` to 64 GiB or `t_cost` to 400 and make the
    /// owner's next unlock exhaust memory or hang, with no tamper report.
    pub const fn check_ceiling(self) -> Result<Self, VaultError> {
        if self.m_cost > Self::READ_MAX_M_COST {
            return Err(VaultError::KdfParamsRefused {
                parameter: "m_cost",
                declared: self.m_cost,
                limit: Self::READ_MAX_M_COST,
            });
        }
        if self.t_cost > Self::READ_MAX_T_COST {
            return Err(VaultError::KdfParamsRefused {
                parameter: "t_cost",
                declared: self.t_cost,
                limit: Self::READ_MAX_T_COST,
            });
        }
        if self.p_cost > Self::READ_MAX_P_COST {
            return Err(VaultError::KdfParamsRefused {
                parameter: "p_cost",
                declared: self.p_cost,
                limit: Self::READ_MAX_P_COST,
            });
        }
        Ok(self)
    }

    /// These parameters with every component raised to at least the floor.
    ///
    /// Used when a new slot inherits the header's parameters: a vault written
    /// by an older build may sit below the floor, and a credential minted today
    /// must not be created at yesterday's cost. See
    /// [`KdfParams::check_floor`], whose contract this keeps.
    #[must_use]
    pub const fn clamped_to_floor(self) -> Self {
        Self {
            m_cost: if self.m_cost < Self::FLOOR_M_COST {
                Self::FLOOR_M_COST
            } else {
                self.m_cost
            },
            t_cost: if self.t_cost < Self::FLOOR_T_COST {
                Self::FLOOR_T_COST
            } else {
                self.t_cost
            },
            p_cost: if self.p_cost < Self::FLOOR_P_COST {
                Self::FLOOR_P_COST
            } else {
                self.p_cost
            },
            version: self.version,
        }
    }

    /// A one-line description **for the audit log**, e.g. `"Argon2id, 512 MiB,
    /// 3 passes, 4 lanes"`.
    ///
    /// English on purpose, and named for its one caller so that it cannot
    /// quietly become the interface's text again. `docs/features/i18n.md` puts
    /// exported audit entries in the same class as a Rust `Display` and an
    /// `IpcError`'s `detail`: diagnostics, read by whoever is debugging and by
    /// tooling, and therefore not translated.
    ///
    /// It is *not* what a screen shows. This used to be `summary()`, it
    /// crossed the IPC boundary as a `String`, and six otherwise-translated
    /// screens printed it verbatim — "passes" and "lanes" are English words,
    /// not notation, and no catalogue could ever reach them. The interface now
    /// receives [`m_cost`](Self::m_cost), [`t_cost`](Self::t_cost) and
    /// [`p_cost`](Self::p_cost) as numbers and composes its own line.
    #[must_use]
    pub fn audit_note(self) -> String {
        format!(
            "Argon2id, {} MiB, {} passes, {} lanes",
            self.m_cost / 1024,
            self.t_cost,
            self.p_cost
        )
    }
}

/// Slot-kind-specific data. Everything here is optional so that a build which
/// does not know a newer slot kind can still read, display and preserve the
/// slot table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SlotExtra {
    /// Password slots: whether a key file is also required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) requires_keyfile: Option<bool>,

    /// Password slots: how the password was normalised before hashing.
    ///
    /// Recorded per slot rather than assumed, so that adding Unicode NFKC
    /// normalisation later does not lock anyone out of a vault created before
    /// it. See `slots::normalise_password`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) password_normalisation: Option<String>,

    /// Keychain slots: the account name the token is filed under in the
    /// platform credential store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) keychain_account: Option<String>,

    /// FIDO2 slots: the credential to assert against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "cbor_bytes_opt")]
    pub(crate) credential_id: Option<Vec<u8>>,

    /// FIDO2 slots: the salt sent to the authenticator's `hmac-secret`
    /// extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "cbor_bytes_opt")]
    pub(crate) hmac_salt: Option<Vec<u8>>,

    /// FIDO2 slots: the relying party id the credential was created under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rp_id: Option<String>,

    /// FIDO2 slots: whether the authenticator requires its PIN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) requires_pin: Option<bool>,

    /// FIDO2 slots: whether user verification is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) requires_uv: Option<bool>,
}

/// One entry in the key slot table.
///
/// Crate-private: `wrapped_vmk` is not secret, but handing callers a mutable
/// slot table invites exactly the substitution the wrapping associated data
/// exists to prevent. The read-only view callers get is [`SlotInfo`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KeySlot {
    pub(crate) index: u8,
    pub(crate) kind: SlotKind,
    pub(crate) label: String,
    pub(crate) created_at: i64,
    #[serde(default)]
    pub(crate) last_used: Option<i64>,
    #[serde(with = "cbor_bytes")]
    pub(crate) salt: Vec<u8>,
    #[serde(with = "cbor_bytes")]
    pub(crate) nonce: Vec<u8>,
    #[serde(with = "cbor_bytes")]
    pub(crate) wrapped_vmk: Vec<u8>,
    #[serde(default)]
    pub(crate) kdf_params: Option<KdfParams>,
    #[serde(default)]
    pub(crate) extra: Option<SlotExtra>,
}

impl KeySlot {
    /// Rejects a slot whose fixed-width fields are the wrong width, before any
    /// of them are used as a key, salt or nonce.
    pub(crate) fn validate(&self) -> Result<(), VaultError> {
        if self.salt.len() != SALT_LEN
            || self.nonce.len() != NONCE_LEN
            || self.wrapped_vmk.len() != crate::crypto::KEY_LEN + TAG_LEN
        {
            return Err(VaultError::Malformed);
        }
        Ok(())
    }

    /// The salt as a fixed-width array.
    pub(crate) fn salt_array(&self) -> Result<[u8; SALT_LEN], VaultError> {
        self.salt
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Malformed)
    }

    /// The wrapping nonce as a fixed-width array.
    pub(crate) fn nonce_array(&self) -> Result<[u8; NONCE_LEN], VaultError> {
        self.nonce
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Malformed)
    }

    /// The public, key-free description of this slot.
    pub(crate) fn info(&self) -> SlotInfo {
        SlotInfo {
            index: self.index,
            kind: self.kind,
            label: self.label.clone(),
            created_at: self.created_at,
            last_used: self.last_used,
            requires_keyfile: self
                .extra
                .as_ref()
                .and_then(|e| e.requires_keyfile)
                .unwrap_or(false),
            kdf_params: self.kdf_params,
        }
    }
}

/// What the interface may know about a key slot: enough to label a button,
/// nothing that helps attack it.
#[derive(Debug, Clone)]
pub struct SlotInfo {
    /// Stable slot number, used to address the slot when revoking it.
    pub index: u8,
    /// How this slot derives its key-encryption key.
    pub kind: SlotKind,
    /// User-chosen display name.
    pub label: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds of the last successful unlock through this slot.
    pub last_used: Option<i64>,
    /// Whether this password slot also requires a key file.
    pub requires_keyfile: bool,
    /// Argon2id parameters; `None` for every kind but `password`.
    pub kdf_params: Option<KdfParams>,
}

// There is deliberately no `SlotInfo::kdf_summary()`. A slot describes its cost
// with [`SlotInfo::kdf_params`] — three numbers and a version — and whoever
// displays them writes the sentence in the reader's language. The method that
// used to be here returned an English one, and every screen printed it.

/// The CBOR header.
///
/// `slots` is private: see [`KeySlot`]. Read it through
/// [`VaultHeader::slot_info`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Identifies this vault across copies and renames.
    pub vault_id: Uuid,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds, rewritten on every save.
    pub modified_at: i64,
    /// User-chosen display name.
    pub label: String,
    /// The AEAD the body is sealed with.
    pub content_cipher: String,
    /// The KDF used by low-entropy slots.
    pub kdf: String,
    /// The parameters the vault was created with. Slots carry their own; this
    /// is what a new slot inherits by default.
    pub kdf_params: KdfParams,
    /// How many rolling backups to keep beside the file.
    ///
    /// Stored in the header rather than in application settings because it has
    /// to be known before the body is decrypted, and because a user who turned
    /// backups off — a vault living in a synchronised folder is the usual
    /// reason — expects that to hold on every machine that opens the file. It
    /// is not secret, and the header MAC covers it.
    ///
    /// Defaulted on read so that a vault written before this field existed
    /// still loads; such a vault gets the build's default count.
    #[serde(default = "default_backup_count")]
    pub backup_count: usize,
    pub(crate) slots: Vec<KeySlot>,
}

/// Serde default for [`VaultHeader::backup_count`] on a header written before
/// the field existed.
fn default_backup_count() -> usize {
    crate::vault::DEFAULT_BACKUP_COUNT
}

impl VaultHeader {
    /// The public description of every slot, in index order.
    #[must_use]
    pub fn slot_info(&self) -> Vec<SlotInfo> {
        self.slots.iter().map(KeySlot::info).collect()
    }

    /// Whether the vault carries at least one slot of this kind.
    #[must_use]
    pub fn has_slot_kind(&self, kind: SlotKind) -> bool {
        self.slots.iter().any(|s| s.kind == kind)
    }

    pub(crate) fn slots(&self) -> &[KeySlot] {
        &self.slots
    }

    pub(crate) fn slots_mut(&mut self) -> &mut Vec<KeySlot> {
        &mut self.slots
    }

    /// The lowest slot index not already taken.
    pub(crate) fn next_slot_index(&self) -> Result<u8, VaultError> {
        for candidate in 0..MAX_SLOTS {
            let taken = self.slots.iter().any(|s| usize::from(s.index) == candidate);
            if !taken {
                return u8::try_from(candidate).map_err(|_| VaultError::SlotTableFull(MAX_SLOTS));
            }
        }
        Err(VaultError::SlotTableFull(MAX_SLOTS))
    }

    /// Rejects a header this build cannot honour before any key material is
    /// derived from it.
    pub(crate) fn validate(&self) -> Result<(), VaultError> {
        if self.content_cipher != CIPHER_XCHACHA20POLY1305 || self.kdf != KDF_ARGON2ID {
            return Err(VaultError::UnsupportedFormat(FORMAT_VERSION));
        }
        if self.slots.is_empty() || self.slots.len() > MAX_SLOTS {
            return Err(VaultError::Malformed);
        }
        // The cost parameters reach us unauthenticated, and the KDF is what
        // produces the key the MAC would be checked with. Bound them here,
        // before any slot is attempted, or a rewritten header turns the next
        // unlock into an out-of-memory kill.
        self.kdf_params.check_ceiling()?;
        for slot in &self.slots {
            slot.validate()?;
            if let Some(params) = slot.kdf_params {
                params.check_ceiling()?;
            }
        }
        Ok(())
    }
}

/// What a probe can learn from a vault without any key.
#[derive(Debug, Clone)]
pub struct VaultInfo {
    /// The file that was probed.
    pub path: PathBuf,
    /// Identifies this vault across copies and renames.
    pub vault_id: Uuid,
    /// User-chosen display name.
    pub label: String,
    /// The format version declared in the file.
    pub format_version: u16,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub modified_at: i64,
    /// Size of the vault file, in bytes.
    pub size_bytes: u64,
    /// The unlock methods this vault offers.
    pub slots: Vec<SlotInfo>,
    /// Rolling backups found beside the vault, newest first.
    pub backups: Vec<PathBuf>,
}

/// A parsed vault file, split into the pieces the unlock sequence needs.
///
/// `mac_input` and `aad` are kept as raw bytes rather than recomputed, because
/// re-encoding the header would not necessarily reproduce it byte for byte.
///
/// `Debug` is safe here: everything in a parsed file is either public framing
/// or ciphertext. Nothing in it is a key.
#[derive(Debug)]
pub(crate) struct ParsedFile {
    pub(crate) header: VaultHeader,
    /// `MAGIC ‖ FORMAT_VER ‖ HEADER_LEN ‖ HEADER` — the MAC input.
    pub(crate) mac_input: Vec<u8>,
    /// `MAGIC ‖ FORMAT_VER ‖ HEADER` — the body's associated data.
    pub(crate) aad: Vec<u8>,
    pub(crate) mac: [u8; MAC_LEN],
    pub(crate) body_nonce: [u8; NONCE_LEN],
    /// Ciphertext with its trailing tag, as the AEAD wants it.
    pub(crate) body: Vec<u8>,
}

/// Reads a slice, or fails cleanly if the file ends first.
///
/// Every read of the file image goes through here. That is the whole defence
/// against the truncation test: there is no direct indexing to get wrong.
fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], VaultError> {
    let end = offset.checked_add(len).ok_or(VaultError::Malformed)?;
    let slice = bytes.get(*offset..end).ok_or(VaultError::Malformed)?;
    *offset = end;
    Ok(slice)
}

/// Parses a whole vault file image.
///
/// Order matters: the magic is checked before the version, and the version
/// before anything is allocated from a length field, so a file that is not a
/// vault at all produces [`VaultError::NotAVault`] rather than a confusing
/// complaint about a header.
pub(crate) fn parse(bytes: &[u8]) -> Result<ParsedFile, VaultError> {
    let mut offset = 0usize;

    let magic = take(bytes, &mut offset, MAGIC.len()).map_err(|_| VaultError::NotAVault)?;
    if magic != MAGIC {
        return Err(VaultError::NotAVault);
    }

    let version_bytes = take(bytes, &mut offset, 2).map_err(|_| VaultError::NotAVault)?;
    let version = u16::from_le_bytes(
        version_bytes
            .try_into()
            .map_err(|_| VaultError::NotAVault)?,
    );
    if version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedFormat(version));
    }

    let len_bytes = take(bytes, &mut offset, 4)?;
    let header_len = u32::from_le_bytes(len_bytes.try_into().map_err(|_| VaultError::Malformed)?);
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(VaultError::Malformed);
    }
    let header_len = usize::try_from(header_len).map_err(|_| VaultError::Malformed)?;

    let header_bytes = take(bytes, &mut offset, header_len)?;
    let header: VaultHeader =
        ciborium::from_reader(header_bytes).map_err(|_| VaultError::HeaderDecode)?;
    header.validate()?;

    let mac: [u8; MAC_LEN] = take(bytes, &mut offset, MAC_LEN)?
        .try_into()
        .map_err(|_| VaultError::Malformed)?;
    let body_nonce: [u8; NONCE_LEN] = take(bytes, &mut offset, NONCE_LEN)?
        .try_into()
        .map_err(|_| VaultError::Malformed)?;

    let body = bytes.get(offset..).ok_or(VaultError::Malformed)?;
    if body.len() < TAG_LEN {
        return Err(VaultError::Malformed);
    }

    let mut mac_input = Vec::with_capacity(HEADER_OFFSET + header_len);
    mac_input.extend_from_slice(&MAGIC);
    mac_input.extend_from_slice(&version.to_le_bytes());
    mac_input.extend_from_slice(len_bytes);
    mac_input.extend_from_slice(header_bytes);

    let mut aad = Vec::with_capacity(MAGIC.len() + 2 + header_len);
    aad.extend_from_slice(&MAGIC);
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(header_bytes);

    Ok(ParsedFile {
        header,
        mac_input,
        aad,
        mac,
        body_nonce,
        body: body.to_vec(),
    })
}

/// The MAC input and the body's associated data for a header about to be
/// written. The mirror image of [`parse`]; keep the two in step.
pub(crate) fn framing_for(header_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    let header_len = u32::try_from(header_bytes.len()).map_err(|_| VaultError::HeaderEncode)?;
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(VaultError::HeaderEncode);
    }

    let mut mac_input = Vec::with_capacity(HEADER_OFFSET + header_bytes.len());
    mac_input.extend_from_slice(&MAGIC);
    mac_input.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    mac_input.extend_from_slice(&header_len.to_le_bytes());
    mac_input.extend_from_slice(header_bytes);

    let mut aad = Vec::with_capacity(MAGIC.len() + 2 + header_bytes.len());
    aad.extend_from_slice(&MAGIC);
    aad.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    aad.extend_from_slice(header_bytes);

    Ok((mac_input, aad))
}

/// Encodes the header to CBOR.
pub(crate) fn encode(header: &VaultHeader) -> Result<Vec<u8>, VaultError> {
    let mut out = Vec::new();
    ciborium::into_writer(header, &mut out).map_err(|_| VaultError::HeaderEncode)?;
    Ok(out)
}

/// Serde helpers that make `Vec<u8>` a CBOR byte string rather than an array of
/// integers.
///
/// Without this, a 48-byte wrapped key becomes 48 separate CBOR integers, which
/// roughly doubles the header and makes it unreadable in a CBOR diagnostic
/// dump. The deserialiser also accepts a sequence so that a header written by
/// something that did not do this still loads.
mod cbor_bytes {
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub(super) fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_bytes(BytesVisitor)
    }

    pub(super) struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a byte string")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            Ok(v)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(b) = seq.next_element::<u8>()? {
                out.push(b);
            }
            Ok(out)
        }
    }
}

/// The same, for optional fields.
mod cbor_bytes_opt {
    use serde::de::{Error as _, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub(super) fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => s.serialize_some(&Wrapped(v)),
            None => s.serialize_none(),
        }
    }

    struct Wrapped<'a>(&'a [u8]);

    impl serde::Serialize for Wrapped<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(self.0)
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        d.deserialize_option(OptVisitor)
    }

    struct OptVisitor;

    impl<'de> Visitor<'de> for OptVisitor {
        type Value = Option<Vec<u8>>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an optional byte string")
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_bytes(super::cbor_bytes::BytesVisitor)
                .map(Some)
                .map_err(D::Error::custom)
        }
    }
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

    fn sample_slot() -> KeySlot {
        KeySlot {
            index: 0,
            kind: SlotKind::Password,
            label: "Master password".into(),
            created_at: 1,
            last_used: None,
            salt: vec![7; SALT_LEN],
            nonce: vec![9; NONCE_LEN],
            wrapped_vmk: vec![3; crate::crypto::KEY_LEN + TAG_LEN],
            kdf_params: Some(KdfParams::floor()),
            extra: Some(SlotExtra {
                requires_keyfile: Some(true),
                ..SlotExtra::default()
            }),
        }
    }

    fn sample_header() -> VaultHeader {
        VaultHeader {
            vault_id: Uuid::now_v7(),
            created_at: 1,
            modified_at: 2,
            label: "Acme Production".into(),
            content_cipher: CIPHER_XCHACHA20POLY1305.into(),
            kdf: KDF_ARGON2ID.into(),
            kdf_params: KdfParams::floor(),
            backup_count: 3,
            slots: vec![sample_slot()],
        }
    }

    #[test]
    fn header_round_trips_through_cbor() {
        let header = sample_header();
        let bytes = encode(&header).unwrap();
        let back: VaultHeader = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.label, header.label);
        assert_eq!(back.vault_id, header.vault_id);
        assert_eq!(back.slots.len(), 1);
        assert_eq!(back.slots[0].salt, header.slots[0].salt);
        assert!(back.slots[0].extra.as_ref().unwrap().requires_keyfile == Some(true));
    }

    #[test]
    fn byte_fields_encode_as_cbor_byte_strings() {
        // Not a cosmetic point: an array of 24 CBOR integers is both far larger
        // than a 24-byte string and unreadable in a diagnostic dump, and serde's
        // default for `Vec<u8>` is the array. Prove the `cbor_bytes` helper is
        // actually in the path by looking at the encoded value's major type.
        let bytes = encode(&sample_header()).unwrap();
        let value: ciborium::value::Value = ciborium::from_reader(bytes.as_slice()).unwrap();

        let map = value.as_map().expect("the header is a CBOR map");
        let slots = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("slots"))
            .map(|(_, v)| v)
            .expect("the header has a slots field");
        let slot = slots.as_array().expect("slots is an array")[0]
            .as_map()
            .expect("a slot is a map");

        for field in ["salt", "nonce", "wrapped_vmk"] {
            let encoded = slot
                .iter()
                .find(|(k, _)| k.as_text() == Some(field))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("a slot has a {field} field"));
            assert!(
                encoded.is_bytes(),
                "slot.{field} encoded as {encoded:?}, not as a CBOR byte string"
            );
        }
    }

    #[test]
    fn framing_matches_between_writer_and_reader() {
        let header_bytes = encode(&sample_header()).unwrap();
        let (mac_input, aad) = framing_for(&header_bytes).unwrap();

        let mut image = mac_input.clone();
        image.extend_from_slice(&[0u8; MAC_LEN]);
        image.extend_from_slice(&[0u8; NONCE_LEN]);
        image.extend_from_slice(&[0u8; TAG_LEN]);

        let parsed = parse(&image).unwrap();
        assert_eq!(parsed.mac_input, mac_input);
        assert_eq!(parsed.aad, aad);
    }

    #[test]
    fn an_unknown_format_version_is_refused() {
        let header_bytes = encode(&sample_header()).unwrap();
        let (mac_input, _) = framing_for(&header_bytes).unwrap();
        let mut image = mac_input;
        image.extend_from_slice(&[0u8; MAC_LEN + NONCE_LEN + TAG_LEN]);
        image[MAGIC.len()] = 99;

        match parse(&image) {
            Err(VaultError::UnsupportedFormat(v)) => assert_eq!(v, 99),
            other => panic!("expected UnsupportedFormat, got {other:?}"),
        }
    }

    #[test]
    fn a_foreign_file_is_not_a_vault() {
        assert!(matches!(
            parse(b"not a vault at all, just some bytes"),
            Err(VaultError::NotAVault)
        ));
    }

    #[test]
    fn an_absurd_header_length_is_refused_before_allocating() {
        let mut image = Vec::new();
        image.extend_from_slice(&MAGIC);
        image.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        image.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(parse(&image), Err(VaultError::Malformed)));
    }

    #[test]
    fn slot_indices_are_handed_out_in_order() {
        let mut header = sample_header();
        assert_eq!(header.next_slot_index().unwrap(), 1);
        let mut second = sample_slot();
        second.index = 1;
        header.slots.push(second);
        assert_eq!(header.next_slot_index().unwrap(), 2);
    }

    #[test]
    fn an_absurd_cost_is_refused_before_any_memory_is_asked_for() {
        // 64 GiB, which is what a rewritten header can declare. The point of
        // the assertion is not only the error but the speed: reaching this
        // decision must not involve allocating anything.
        let mut header = sample_header();
        header.kdf_params.m_cost = 64 * 1024 * 1024;
        header.slots[0].kdf_params = Some(header.kdf_params);

        let bytes = encode(&header).unwrap();
        let (mac_input, _) = framing_for(&bytes).unwrap();
        let mut image = mac_input;
        image.extend_from_slice(&[0u8; MAC_LEN + NONCE_LEN + TAG_LEN]);

        let started = std::time::Instant::now();
        let result = parse(&image);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "the bound must be a comparison, not an allocation attempt"
        );

        match result {
            Err(VaultError::KdfParamsRefused {
                parameter,
                declared,
                limit,
            }) => {
                assert_eq!(parameter, "m_cost");
                assert_eq!(declared, 64 * 1024 * 1024);
                assert_eq!(limit, KdfParams::READ_MAX_M_COST);
            }
            other => panic!("expected KdfParamsRefused, got {other:?}"),
        }
    }

    #[test]
    fn an_absurd_iteration_or_lane_count_is_refused_too() {
        for (mutate, name) in [
            (
                (|p: &mut KdfParams| p.t_cost = 400) as fn(&mut KdfParams),
                "t_cost",
            ),
            (
                (|p: &mut KdfParams| p.p_cost = 4096) as fn(&mut KdfParams),
                "p_cost",
            ),
        ] {
            let mut header = sample_header();
            let mut params = header.kdf_params;
            mutate(&mut params);
            // Only the slot carries it, to prove slot parameters are bounded
            // and not merely the header's own copy.
            header.slots[0].kdf_params = Some(params);

            match header.validate() {
                Err(VaultError::KdfParamsRefused { parameter, .. }) => {
                    assert_eq!(parameter, name);
                }
                other => panic!("expected KdfParamsRefused for {name}, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_ceiling_leaves_realistic_parameters_alone() {
        assert!(KdfParams::floor().check_ceiling().is_ok());
        assert!(
            KdfParams {
                m_cost: KdfParams::CALIBRATION_MAX_M_COST,
                ..KdfParams::floor()
            }
            .check_ceiling()
            .is_ok()
        );
    }

    #[test]
    fn inherited_parameters_are_clamped_up_to_the_floor() {
        let clamped = KdfParams::low_cost_for_tests().clamped_to_floor();
        assert!(!clamped.is_below_floor());
        assert_eq!(clamped.m_cost, KdfParams::FLOOR_M_COST);
        assert_eq!(clamped.t_cost, KdfParams::FLOOR_T_COST);
        assert_eq!(clamped.p_cost, KdfParams::FLOOR_P_COST);

        // Anything already above the floor is left exactly as it is.
        let strong = KdfParams {
            m_cost: KdfParams::CALIBRATION_MAX_M_COST,
            t_cost: 5,
            p_cost: 8,
            version: KdfParams::CURRENT_VERSION,
        };
        assert_eq!(strong.clamped_to_floor(), strong);
    }

    #[test]
    fn a_header_written_before_backup_count_existed_still_loads() {
        // The field is defaulted on read, so an older header decodes rather
        // than being rejected as malformed.
        let header = sample_header();
        let bytes = encode(&header).unwrap();
        let mut value: ciborium::value::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        if let ciborium::value::Value::Map(entries) = &mut value {
            entries.retain(|(k, _)| k.as_text() != Some("backup_count"));
        }
        let mut without = Vec::new();
        ciborium::into_writer(&value, &mut without).unwrap();

        let back: VaultHeader = ciborium::from_reader(without.as_slice()).unwrap();
        assert_eq!(back.backup_count, crate::vault::DEFAULT_BACKUP_COUNT);
    }

    #[test]
    fn the_kdf_floor_is_enforced_on_creation_only() {
        assert!(KdfParams::floor().check_floor().is_ok());
        assert!(KdfParams::low_cost_for_tests().check_floor().is_err());
        assert!(KdfParams::low_cost_for_tests().is_below_floor());
        assert!(!KdfParams::floor().is_below_floor());
    }
}
