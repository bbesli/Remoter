//! The vault itself: create, probe, open, save, lock.
//!
//! The unlock sequence follows `docs/security/vault-format.md` step for step,
//! including the part that is easy to read as a mistake: the errors get *more*
//! specific once a slot has unwrapped. Before that point every failure is the
//! same "that did not unlock the vault", because saying more would tell an
//! attacker at the keyboard which half of a two-factor unlock they already
//! have. After it, the caller has proved they hold a valid credential, so
//! "your header has been tampered with, open the backup" is information they
//! are entitled to and need.
//!
//! Saves are atomic: serialise, seal with a fresh nonce, write a temporary
//! file, `fsync`, rotate the previous file into the rolling backups, rename
//! over the original, `fsync` the directory. A crash at any point leaves either
//! the old file or the new one, never half of either. The temporary file's name
//! carries this process's id and a random suffix, so two processes saving the
//! same vault cannot write into each other's half-finished image.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

use remoter_core::{
    KeyFormat, Node, NodeId, NodeKind, ProtocolId, SecretKind, Tag, Tree, TreePatch,
};
use uuid::Uuid;

use crate::Purpose;
use crate::audit::{AuditQuery, AuditRecord};
use crate::credential::{ImportedKey, PrivateKeyMaterial};
use crate::crypto::{self, MAC_LEN, NONCE_LEN, VaultKeys};
use crate::error::{UnlockError, VaultError};
use crate::header::{
    self, CIPHER_XCHACHA20POLY1305, FORMAT_VERSION, KDF_ARGON2ID, KdfParams, SlotInfo, SlotKind,
    VaultHeader, VaultInfo,
};
use crate::recovery::RecoveryKey;
use crate::secret::{ExposeSecret as _, Secret};
use crate::settings::{self, VaultSettings};
use crate::slots::{self, PasswordCredential, RotationOutcome, RotationPlan, UnlockMethod};
use crate::storage::{AuditEntry, AuditEvent, AuditOutcome, NodeRow, Store};

/// Default number of rolling backups kept beside a vault.
///
/// Not re-exported from the crate root, so it stays crate-private; callers set
/// the count through [`CreateOptions::with_backup_count`].
pub(crate) const DEFAULT_BACKUP_COUNT: usize = 3;

/// Most backups this build will keep or look for.
const MAX_BACKUP_COUNT: usize = 8;

/// Target for Argon2id calibration, in milliseconds.
const CALIBRATION_TARGET_MS: u128 = 1000;

/// Most slots of one kind [`Vault::open`] will run a key derivation against
/// before giving up.
///
/// The cost of an unlock attempt is the KDF cost times the number of candidate
/// slots, and the slot count comes from the same unauthenticated header as the
/// cost parameters. [`KdfParams::check_ceiling`] bounds one attempt; this
/// bounds how many. Four is more password slots than a vault has in practice —
/// a personal one, a shared one, a spare — and sixteen of them at the ceiling
/// is a wait nobody would sit through.
const MAX_KDF_SLOT_ATTEMPTS: usize = 4;

/// Permissions a vault file, its temporary image and its backups are created
/// with on Unix.
///
/// `docs/security/threat-model.md` T8 promises owner-only access. The default
/// umask gives 0644, which puts the primary artefact — the one an offline
/// attacker wants — in reach of every account on the machine, while the key
/// file that is only the *second* factor is already restricted.
#[cfg(unix)]
const OWNER_ONLY: u32 = 0o600;

/// Field names the vault files a credential's sealed material under.
///
/// `remoter-core` carries the sealed envelope inline, in `SecretKind`; the
/// vault stores it in the `secrets` table, where a listing query never touches
/// it and an auditor has one table to read. These names are the join between
/// the two, and they are part of the stored format: renaming one orphans every
/// secret filed under the old name.
const FIELD_PASSWORD: &str = "password";
const FIELD_PRIVATE_KEY: &str = "private_key";
const FIELD_PASSPHRASE: &str = "passphrase";
const FIELD_CERTIFICATE: &str = "certificate";
const FIELD_CERTIFICATE_KEY: &str = "certificate_key";
const FIELD_TOTP: &str = "totp";

/// How a vault is to be created.
///
/// Built rather than constructed with a literal because the password is a
/// [`Secret`], which is deliberately not `Clone` or `Default`.
#[derive(Debug)]
pub struct CreateOptions {
    path: PathBuf,
    label: String,
    password: Secret<String>,
    keyfile: Option<PathBuf>,
    kdf_params: Option<KdfParams>,
    backup_count: usize,
    keychain: bool,
}

impl CreateOptions {
    /// A vault at `path`, named `label`, opened by `password`.
    ///
    /// With no other calls, the vault gets a password slot with parameters
    /// calibrated on this machine, and a recovery slot.
    #[must_use]
    pub fn new(
        path: impl Into<PathBuf>,
        label: impl Into<String>,
        password: Secret<String>,
    ) -> Self {
        Self {
            path: path.into(),
            label: label.into(),
            password,
            keyfile: None,
            kdf_params: None,
            backup_count: DEFAULT_BACKUP_COUNT,
            keychain: false,
        }
    }

    /// Requires this key file in addition to the password.
    #[must_use]
    pub fn with_keyfile(mut self, path: impl Into<PathBuf>) -> Self {
        self.keyfile = Some(path.into());
        self
    }

    /// Uses these Argon2id parameters instead of calibrating.
    #[must_use]
    pub fn with_kdf_params(mut self, params: KdfParams) -> Self {
        self.kdf_params = Some(params);
        self
    }

    /// Keeps `count` rolling backups beside the vault.
    #[must_use]
    pub fn with_backup_count(mut self, count: usize) -> Self {
        self.backup_count = count.min(MAX_BACKUP_COUNT);
        self
    }

    /// Also enrols this machine's credential store.
    ///
    /// Off by default, and worth being blunt about in the interface at the
    /// moment it is switched on: it makes unlocking one click, and it makes the
    /// vault openable by anything running as this user account.
    #[must_use]
    pub fn with_keychain_slot(mut self, enabled: bool) -> Self {
        self.keychain = enabled;
        self
    }
}

/// An open vault.
///
/// Holds the master key and its derivatives in memory, along with the whole
/// decrypted database. Dropping it wipes the keys; the secret *fields* in the
/// database were never plaintext to begin with.
pub struct Vault {
    path: PathBuf,
    header: VaultHeader,
    keys: VaultKeys,
    store: Store,
    /// The slot that opened this vault, so its `last_used` can be written on
    /// the next save.
    opened_with: Option<u8>,
    /// Whether this session has already rotated the backups. See
    /// [`Vault::save`].
    rotated: bool,
}

impl core::fmt::Debug for Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("label", &self.header.label)
            .field("vault_id", &self.header.vault_id)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl Vault {
    // ------------------------------------------------------------ create ---

    /// Creates a vault file and returns it open, with its recovery key.
    ///
    /// The recovery key is returned exactly once and is not recoverable
    /// afterwards — nothing in the file can reproduce it. The caller must show
    /// it, confirm the user has stored it, and drop it.
    pub fn create(opts: CreateOptions) -> Result<(Self, RecoveryKey), VaultError> {
        if opts.path.exists() {
            return Err(VaultError::io(
                "creating the vault",
                opts.path,
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "a file already exists at that path",
                ),
            ));
        }

        let params = match opts.kdf_params {
            Some(params) => accept_kdf_params(params)?,
            None => Self::calibrate_kdf()?,
        };

        let now = now_seconds();
        let vmk = crypto::random_key()?;
        let vault_id = Uuid::now_v7();

        let password_slot = slots::new_password_slot(
            0,
            String::from("Master password"),
            now,
            &opts.password,
            opts.keyfile.as_deref(),
            params,
            &vmk,
        )?;
        let (recovery_slot, recovery_key) =
            slots::new_recovery_slot(1, String::from("Recovery key"), now, &vmk)?;

        let mut slot_table = vec![password_slot, recovery_slot];
        if opts.keychain {
            slot_table.push(slots::new_keychain_slot(
                2,
                String::from("This device"),
                now,
                vault_id,
                &vmk,
            )?);
        }

        let header = VaultHeader {
            vault_id,
            created_at: now,
            modified_at: now,
            label: opts.label,
            content_cipher: CIPHER_XCHACHA20POLY1305.to_owned(),
            kdf: KDF_ARGON2ID.to_owned(),
            kdf_params: params,
            backup_count: opts.backup_count.min(MAX_BACKUP_COUNT),
            slots: slot_table,
        };

        let store = Store::create_new(now_millis())?;
        let mut vault = Self {
            path: opts.path,
            header,
            keys: VaultKeys::derive(vmk)?,
            store,
            opened_with: None,
            rotated: false,
        };

        vault.audit(AuditEvent::VaultCreated, AuditOutcome::Success, None)?;
        vault.audit(AuditEvent::RecoveryKeyIssued, AuditOutcome::Success, None)?;
        vault.save()?;

        Ok((vault, recovery_key))
    }

    /// Times Argon2id at the floor and scales the memory cost towards one
    /// second on this machine, never going below the floor and never above
    /// [`KdfParams::CALIBRATION_MAX_M_COST`].
    ///
    /// Measured rather than guessed, because the point of the parameters is how
    /// long they take on real hardware. A machine slower than the floor keeps
    /// the floor: a weaker vault is not an acceptable answer to a slow laptop.
    pub fn calibrate_kdf() -> Result<KdfParams, VaultError> {
        let mut params = KdfParams::floor();
        let salt = [0u8; crate::crypto::SALT_LEN];

        // Two measurements: one to find the machine's rate, one to check the
        // scaled parameters did not overshoot. More would cost more time than
        // the accuracy is worth.
        for _ in 0..2 {
            let started = Instant::now();
            let derived = crypto::argon2id(b"calibration", &salt, &params)?;
            drop(derived);
            let elapsed = started.elapsed().as_millis().max(1);

            if elapsed >= CALIBRATION_TARGET_MS {
                break;
            }
            let scaled = u128::from(params.m_cost)
                .saturating_mul(CALIBRATION_TARGET_MS)
                .saturating_div(elapsed);
            let scaled = u32::try_from(scaled).unwrap_or(KdfParams::CALIBRATION_MAX_M_COST);
            let next = scaled.clamp(KdfParams::FLOOR_M_COST, KdfParams::CALIBRATION_MAX_M_COST);
            if next <= params.m_cost {
                break;
            }
            params.m_cost = next;
        }

        params.check_floor()
    }

    // ------------------------------------------------------------- probe ---

    /// Reads what a vault file says about itself, without any key.
    ///
    /// The header is plaintext by design: a user should be able to see which
    /// unlock methods a vault offers before committing to one. It is covered by
    /// the header MAC, so it is readable but not modifiable — though that MAC
    /// cannot be checked here, because checking it needs the master key.
    pub fn probe(path: &Path) -> Result<VaultInfo, VaultError> {
        let bytes = fs::read(path).map_err(|e| VaultError::io("reading the vault", path, e))?;
        let parsed = header::parse(&bytes)?;
        let size_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);

        Ok(VaultInfo {
            path: path.to_path_buf(),
            vault_id: parsed.header.vault_id,
            label: parsed.header.label.clone(),
            format_version: FORMAT_VERSION,
            created_at: parsed.header.created_at,
            modified_at: parsed.header.modified_at,
            size_bytes,
            slots: parsed.header.slot_info(),
            backups: existing_backups(path),
        })
    }

    // -------------------------------------------------------------- open ---

    /// Opens a vault.
    ///
    /// Follows the numbered sequence in `docs/security/vault-format.md`: read
    /// the framing, refuse an unknown format version, unwrap a slot, derive the
    /// hierarchy, verify the header MAC, decrypt the body, migrate.
    pub fn open(path: &Path, method: UnlockMethod) -> Result<Self, UnlockError> {
        let bytes = fs::read(path)
            .map_err(|e| UnlockError::Vault(VaultError::io("reading the vault", path, e)))?;

        // Steps 1 and 2: framing, and fail closed on an unknown version.
        let parsed = header::parse(&bytes).map_err(UnlockError::Vault)?;
        let wanted = method.kind();

        if wanted == SlotKind::Fido2 {
            return Err(UnlockError::Fido2Unsupported);
        }
        if !parsed.header.has_slot_kind(wanted) {
            return Err(UnlockError::NoSuchMethod(wanted));
        }

        // Steps 5 and 6: derive a key-encryption key per candidate slot and try
        // to unwrap. Every failure here is the same failure to the caller.
        let mut unwrapped: Option<(u8, crate::crypto::KeyBytes)> = None;
        let mut attempts = 0usize;
        for slot in parsed.header.slots() {
            if slot.kind != wanted {
                continue;
            }
            // A header the caller has not authenticated yet says how many slots
            // to try; without a cap, sixteen of them multiply the KDF cost.
            if attempts >= MAX_KDF_SLOT_ATTEMPTS {
                break;
            }
            attempts += 1;
            let Some(kek) = slots::kek_for(slot, &method, parsed.header.vault_id)? else {
                continue;
            };
            if let Ok(vmk) = slots::unwrap_vmk(&kek, slot) {
                unwrapped = Some((slot.index, vmk));
                break;
            }
        }
        let Some((slot_index, vmk)) = unwrapped else {
            return Err(UnlockError::NotUnlocked);
        };

        // Step 7: the rest of the hierarchy.
        let keys = VaultKeys::derive(vmk).map_err(UnlockError::Vault)?;

        // Step 8. From here the caller has proved they hold a credential, so
        // the errors may say what is actually wrong.
        let expected = crypto::keyed_mac(&keys.header_mac, &parsed.mac_input);
        if !crypto::ct_eq(&expected, &parsed.mac) {
            return Err(UnlockError::HeaderTampered);
        }

        // Step 9.
        let body = crypto::open(&keys.cek, &parsed.body_nonce, &parsed.body, &parsed.aad)
            .map_err(|_| UnlockError::BodyCorrupt)?;

        // Step 10.
        let store = Store::load(&body, now_millis()).map_err(|e| match e {
            VaultError::NotADatabase => UnlockError::BodyCorrupt,
            other => UnlockError::Vault(other),
        })?;
        drop(body);

        let mut header = parsed.header;
        if let Some(slot) = header
            .slots_mut()
            .iter_mut()
            .find(|s| s.index == slot_index)
        {
            slot.last_used = Some(now_seconds());
        }

        // A vault written by a build that did not set the mode is world-
        // readable, and it stays that way until something rewrites it. Repair
        // it here, where the caller has just proved the file is theirs. Best
        // effort: the file is open and readable, and a mode that cannot be
        // changed — read-only media, a file owned by someone else — is a reason
        // to warn, not to refuse an unlock that has already succeeded.
        if let Err(error) = restrict(path) {
            tracing::warn!(
                path = %path.display(),
                %error,
                "could not restrict the vault file to its owner"
            );
        }

        let mut vault = Self {
            path: path.to_path_buf(),
            header,
            keys,
            store,
            opened_with: Some(slot_index),
            rotated: false,
        };
        vault
            .audit(AuditEvent::VaultUnlocked, AuditOutcome::Success, None)
            .map_err(UnlockError::Vault)?;

        Ok(vault)
    }

    // -------------------------------------------------------------- save ---

    /// Serialises, encrypts and writes the vault, atomically.
    ///
    /// The backups are rotated on the first save of a session only. Rotating on
    /// every save makes the window a count of *user actions*: every node
    /// mutation is a save, so with the default of three backups the image from
    /// before an editing mistake is gone after four ordinary clicks. The
    /// specification justifies backups as "a recent, known-good predecessor",
    /// and a predecessor that a moment's clicking can erase is not one. Rotating
    /// once per session makes `.bak.1` the file as it stood when the vault was
    /// opened, and the window a count of sessions.
    pub fn save(&mut self) -> Result<(), VaultError> {
        // The row describing a save has to be inside the image the save
        // produces, so it is written before the outcome is known. If the write
        // then fails, it is corrected below: the log must not assert a save
        // that never reached the disk.
        let audit_id = self.store.audit_row(
            now_millis(),
            AuditEvent::VaultSaved,
            AuditOutcome::Success,
            None,
            None,
            None,
        )?;

        let previous_modified_at = self.header.modified_at;
        self.header.modified_at = now_seconds();

        match self.write_image() {
            Ok(rotated) => {
                // Only a rotation that actually happened closes the window. The
                // save that creates the file has no predecessor to keep, so the
                // first save after it is the one that takes the backup.
                self.rotated |= rotated;
                Ok(())
            }
            Err(error) => {
                // The file on disk is still the old one, so the header this
                // vault carries must go back to describing it.
                self.header.modified_at = previous_modified_at;
                // Best effort: if correcting the row fails too, the original
                // failure is the one worth reporting.
                let _ = self.store.set_audit_outcome(
                    audit_id,
                    AuditOutcome::Failure,
                    Some("the vault file could not be written"),
                );
                Err(error)
            }
        }
    }

    /// Everything in [`Vault::save`] that can fail after the audit row exists.
    /// Reports whether it rotated the backups.
    fn write_image(&mut self) -> Result<bool, VaultError> {
        let database = self.store.serialize()?;

        let header_bytes = header::encode(&self.header)?;
        let (mac_input, aad) = header::framing_for(&header_bytes)?;
        let mac = crypto::keyed_mac(&self.keys.header_mac, &mac_input);

        // A fresh nonce on every save, never a counter. At 192 bits the
        // birthday bound is far beyond any number of saves a vault will see,
        // and there is no state to get wrong if the file is ever synchronised
        // between machines.
        let nonce: [u8; NONCE_LEN] = crypto::random_array()?;
        let body = crypto::seal(&self.keys.cek, &nonce, &database, &aad)?;
        drop(database);

        let mut image = Vec::with_capacity(mac_input.len() + MAC_LEN + NONCE_LEN + body.len());
        image.extend_from_slice(&mac_input);
        image.extend_from_slice(&mac);
        image.extend_from_slice(&nonce);
        image.extend_from_slice(&body);

        write_atomically(&self.path, &image, self.header.backup_count, !self.rotated)
    }

    /// Closes the vault and wipes its keys.
    ///
    /// Takes `self` by value so there is no way to keep using it afterwards.
    /// The zeroing is `Drop`'s doing, which is what makes it happen on the
    /// error paths too.
    pub fn lock(self) {
        drop(self);
    }

    // -------------------------------------------------------- description ---

    /// Where this vault lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The user-chosen name.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.header.label
    }

    /// Renames the vault. Takes effect on the next save.
    pub fn set_label(&mut self, label: impl Into<String>) {
        self.header.label = label.into();
    }

    /// The identifier that follows this vault across copies and renames.
    #[must_use]
    pub fn vault_id(&self) -> Uuid {
        self.header.vault_id
    }

    /// The unlock methods this vault offers.
    #[must_use]
    pub fn slots(&self) -> Vec<SlotInfo> {
        self.header.slot_info()
    }

    /// The slot index this vault was opened with, if it was opened rather than
    /// created.
    #[must_use]
    pub fn opened_with(&self) -> Option<u8> {
        self.opened_with
    }

    /// How many rolling backups this vault keeps.
    #[must_use]
    pub fn backup_count(&self) -> usize {
        self.header.backup_count
    }

    /// Whether any password slot is weaker than the current cost floor, so the
    /// interface can offer to strengthen it.
    #[must_use]
    pub fn kdf_upgrade_available(&self) -> bool {
        self.header
            .slots()
            .iter()
            .filter(|s| s.kind == SlotKind::Password)
            .filter_map(|s| s.kdf_params)
            .any(KdfParams::is_below_floor)
    }

    /// Re-derives every below-floor password slot at freshly calibrated
    /// parameters, and saves.
    ///
    /// The upgrade `docs/security/vault-format.md` promises: "If a vault's
    /// parameters are below the current floor, Remoter offers to upgrade them
    /// on the next successful unlock." [`Vault::kdf_upgrade_available`] is the
    /// offer; this is the acceptance.
    ///
    /// The master key does not change — nothing is re-encrypted, the body is
    /// not touched. Each affected slot is rebuilt at the same index and the
    /// same kind, around the same VMK, with a new salt and stronger costs.
    /// `method` supplies the credential the slot is keyed to; a slot the
    /// credential does not open is left alone, which is what makes this correct
    /// on a vault holding more than one password slot.
    ///
    /// Returns `Ok(true)` if anything was upgraded, `Ok(false)` if nothing
    /// needed it. Only password slots have cost parameters, so any other
    /// unlock method has nothing to upgrade and reports `Ok(false)`.
    pub fn upgrade_kdf(&mut self, method: &UnlockMethod) -> Result<bool, VaultError> {
        let UnlockMethod::Password { password, keyfile } = method else {
            return Ok(false);
        };
        if !self.kdf_upgrade_available() {
            return Ok(false);
        }

        // Calibrated rather than pinned to the floor, so an upgrade lands where
        // a vault created today would: `calibrate_kdf` never returns anything
        // below the floor.
        let params = Self::calibrate_kdf()?;

        let stale: Vec<(u8, String, KdfParams)> = self
            .header
            .slots()
            .iter()
            .filter(|s| s.kind == SlotKind::Password)
            .filter_map(|s| {
                let old = s.kdf_params?;
                old.is_below_floor()
                    .then(|| (s.index, s.label.clone(), old))
            })
            .collect();

        let mut upgraded = 0usize;
        for (index, label, old_params) in stale {
            // Prove the credential opens this slot before replacing it.
            // Rewrapping a slot the caller cannot currently open would silently
            // re-key it to the wrong password and destroy the only copy of the
            // master key that slot held.
            if !self.password_opens_slot(index, password, keyfile.as_deref(), old_params)? {
                continue;
            }

            let created_at = self
                .header
                .slots()
                .iter()
                .find(|s| s.index == index)
                .map_or_else(now_seconds, |s| s.created_at);

            let mut replacement = slots::new_password_slot(
                index,
                label,
                created_at,
                password,
                keyfile.as_deref(),
                params,
                &self.keys.vmk,
            )?;
            replacement.last_used = self
                .header
                .slots()
                .iter()
                .find(|s| s.index == index)
                .and_then(|s| s.last_used);

            if let Some(slot) = self
                .header
                .slots_mut()
                .iter_mut()
                .find(|s| s.index == index)
            {
                *slot = replacement;
                upgraded += 1;
            }
        }

        if upgraded == 0 {
            return Ok(false);
        }

        // What a slot added from now on inherits.
        if self.header.kdf_params.is_below_floor() {
            self.header.kdf_params = params;
        }

        self.audit(
            AuditEvent::KdfUpgraded,
            AuditOutcome::Success,
            Some(params.audit_note().as_str()),
        )?;
        self.save()?;
        Ok(true)
    }

    /// Whether this credential, at the slot's stored parameters, unwraps the
    /// master key this vault is already holding.
    ///
    /// `Ok(false)` means the credential is wrong. A key file that was named but
    /// could not be read is **not** that, and is reported as
    /// [`VaultError::Keyfile`] rather than folded into the refusal.
    ///
    /// It used to be folded in, and that is how an owner whose credential was
    /// never wrong ends up being told it was. A key file contributes
    /// `BLAKE3(file_bytes)`, so reading it is a step that can fail on its own:
    /// a removable drive that dropped between the unlock and the change, a
    /// synchronised file whose local copy is no longer materialised, a path
    /// that now names a directory, a file that has grown past the size cap. The
    /// vault is still open on the master key it unwrapped earlier in the
    /// session, so none of that is visible until something re-reads the file —
    /// and when it did, "the key file could not be read" arrived on screen as
    /// "that does not open key slot 0", which sends the owner to retype a
    /// password that was never the problem.
    ///
    /// A key file the caller simply did not supply stays an ordinary refusal:
    /// nothing is read, the derivation runs over the password alone, and the
    /// wrong key comes out. That is the wrong credential, not an unreadable
    /// file.
    ///
    /// Saying which half failed is safe here and nowhere else. Every caller of
    /// this function holds an open vault, so the rule in
    /// `docs/security/threat-model.md` — say nothing before a slot has
    /// unwrapped — has already been satisfied. The silence that rule demands
    /// lives in [`slots::kek_for`], which runs before anything is
    /// authenticated and still answers every failure identically.
    fn password_opens_slot(
        &self,
        index: u8,
        password: &Secret<String>,
        keyfile: Option<&Path>,
        params: KdfParams,
    ) -> Result<bool, VaultError> {
        let Some(slot) = self.header.slots().iter().find(|s| s.index == index) else {
            return Ok(false);
        };
        let normalisation = slots::normalisation_of(slot);
        let salt = slot.salt_array()?;

        let kek = slots::password_kek(
            password.expose_secret(),
            normalisation,
            keyfile,
            &salt,
            &params,
        )?;

        match slots::unwrap_vmk(&kek, slot) {
            Ok(vmk) => Ok(crypto::ct_eq(vmk.as_slice(), self.keys.vmk.as_slice())),
            Err(_) => Ok(false),
        }
    }

    /// The same description [`Vault::probe`] returns, for an open vault.
    #[must_use]
    pub fn info(&self) -> VaultInfo {
        let size_bytes = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        VaultInfo {
            path: self.path.clone(),
            vault_id: self.header.vault_id,
            label: self.header.label.clone(),
            format_version: FORMAT_VERSION,
            created_at: self.header.created_at,
            modified_at: self.header.modified_at,
            size_bytes,
            slots: self.header.slot_info(),
            backups: existing_backups(&self.path),
        }
    }

    // -------------------------------------------------------------- tree ---

    /// The whole live tree, rebuilt from storage.
    ///
    /// Tombstoned nodes are left out: they exist so that references to a
    /// deleted node still have a name to show, and so that a future
    /// synchronisation can tell "deleted" from "never seen", not so that they
    /// appear in the interface.
    pub fn tree(&self) -> Result<Tree, VaultError> {
        let rows = self.store.live_nodes()?;
        let mut nodes = Vec::with_capacity(rows.len());
        for row in &rows {
            nodes.push(self.node_from_row(row)?);
        }
        Tree::from_nodes(nodes).map_err(VaultError::Core)
    }

    /// Persists the rows a tree mutation touched.
    ///
    /// Takes the tree as well as the patch because a [`TreePatch`] names ids,
    /// not contents — that is what lets a folder move write one row instead of
    /// ten thousand. The intended shape at the call site is:
    ///
    /// ```no_run
    /// # use remoter_vault::{Vault, VaultError};
    /// # use remoter_core::Node;
    /// # fn example(vault: &mut Vault, node: Node) -> Result<(), VaultError> {
    /// let mut tree = vault.tree()?;
    /// let patch = tree.insert(node)?;
    /// vault.apply(&tree, &patch)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// When a node's revision moved — `Tree::update` and `Tree::soft_delete`
    /// bump it — its secret fields are re-sealed under the new revision in the
    /// same step, because the revision is bound into their associated data.
    pub fn apply(&mut self, tree: &Tree, patch: &TreePatch) -> Result<(), VaultError> {
        for id in &patch.inserted {
            let node = tree.get(*id).ok_or(VaultError::NoSuchNode(*id.as_uuid()))?;
            self.store.insert_node(&row_from_node(node)?)?;
        }

        // A node can be named by both lists — a referrer that was also
        // tombstoned — and writing it twice would re-seal its secrets twice.
        let changed: BTreeSet<NodeId> = patch
            .updated
            .iter()
            .chain(patch.tombstoned.iter())
            .copied()
            .collect();

        for id in changed {
            let node = tree.get(id).ok_or(VaultError::NoSuchNode(*id.as_uuid()))?;
            let uuid = *id.as_uuid();
            let row = row_from_node(node)?;
            let stored = self.store.revision_of(uuid)?;
            self.store.update_node(&row)?;
            self.store
                .set_revision(&self.keys.sek, uuid, stored, row.revision, now_millis())?;
        }

        let event = if !patch.inserted.is_empty() {
            AuditEvent::NodeCreated
        } else if !patch.tombstoned.is_empty() {
            AuditEvent::NodeDeleted
        } else {
            AuditEvent::NodeUpdated
        };
        if !patch.is_empty() {
            self.audit(event, AuditOutcome::Success, None)?;
        }
        Ok(())
    }

    /// One node, tombstones included.
    pub fn node(&self, id: Uuid) -> Result<Option<Node>, VaultError> {
        match self.store.node(id)? {
            Some(row) => Ok(Some(self.node_from_row(&row)?)),
            None => Ok(None),
        }
    }

    /// Database row to domain node, with the sealed material filled in from the
    /// `secrets` table.
    fn node_from_row(&self, row: &NodeRow) -> Result<Node, VaultError> {
        let mut node = node_from_row(row)?;
        self.fill_sealed(row.id, &mut node.kind)?;
        Ok(node)
    }

    /// Puts the stored ciphertext back into a `SecretKind`.
    ///
    /// A credential with no stored secret gets [`Vault::sealed_placeholder`]
    /// rather than an empty vector, because `remoter-core` refuses a credential
    /// whose sealed material is empty — rightly, an empty envelope is not a
    /// credential — and a tree that cannot be rebuilt from its own storage
    /// would be worse than a marker.
    fn fill_sealed(&self, node: Uuid, kind: &mut NodeKind) -> Result<(), VaultError> {
        let NodeKind::Credential(credential) = kind else {
            return Ok(());
        };

        match &mut credential.secret {
            SecretKind::Password { sealed } => {
                *sealed = self.sealed_or_placeholder(node, FIELD_PASSWORD)?;
            }
            SecretKind::PrivateKey {
                sealed_key,
                sealed_passphrase,
                ..
            } => {
                *sealed_key = self.sealed_or_placeholder(node, FIELD_PRIVATE_KEY)?;
                if sealed_passphrase.is_some() {
                    *sealed_passphrase = Some(self.sealed_or_placeholder(node, FIELD_PASSPHRASE)?);
                }
            }
            SecretKind::Certificate {
                sealed_cert,
                sealed_key,
            } => {
                *sealed_cert = self.sealed_or_placeholder(node, FIELD_CERTIFICATE)?;
                *sealed_key = self.sealed_or_placeholder(node, FIELD_CERTIFICATE_KEY)?;
            }
            SecretKind::Agent { .. } | SecretKind::External { .. } => {}
        }

        if credential.totp.is_some() {
            credential.totp = Some(self.sealed_or_placeholder(node, FIELD_TOTP)?);
        }
        Ok(())
    }

    fn sealed_or_placeholder(&self, node: Uuid, field: &str) -> Result<Vec<u8>, VaultError> {
        Ok(self
            .store
            .raw_secret(node, field)?
            .unwrap_or_else(Self::sealed_placeholder))
    }

    /// The marker a credential carries in place of sealed material it does not
    /// have yet.
    ///
    /// A credential's ciphertext cannot exist before its node does — the
    /// associated data binds it to the node's id and revision — but
    /// `remoter-core` will not accept a credential node whose sealed material
    /// is empty. So a new credential is inserted carrying this marker and then
    /// given its real secret with [`Vault::set_secret`]. The marker is never
    /// stored: the vault strips every sealed field on the way into the database
    /// and fills them from the `secrets` table on the way out.
    #[must_use]
    pub fn sealed_placeholder() -> Vec<u8> {
        vec![0]
    }

    /// Live connection nodes.
    pub fn connection_count(&self) -> Result<usize, VaultError> {
        self.store.count_kind("connection")
    }

    /// Live credential nodes.
    pub fn credential_count(&self) -> Result<usize, VaultError> {
        self.store.count_kind("credential")
    }

    /// Full-text search over names, descriptions, hosts and tags — never over a
    /// secret field. Returns node ids, best match first.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<Uuid>, VaultError> {
        self.store.search(query, limit)
    }

    // ----------------------------------------------------------- secrets ---

    /// Seals a secret field under the SEK and stores it.
    ///
    /// The associated data binds the ciphertext to this node, this field name
    /// and this record's current revision, so it cannot be moved to another
    /// record, replayed as another field, or rolled back over a newer value.
    ///
    /// For a credential node, use the field names the domain model's
    /// `SecretKind` maps to — `password`, `private_key`, `passphrase`,
    /// `certificate`, `certificate_key`, `totp` — and the sealed envelope will
    /// appear in the node's `SecretKind` the next time the tree is read.
    pub fn set_secret(
        &mut self,
        node: Uuid,
        field: &str,
        value: Secret<Vec<u8>>,
    ) -> Result<(), VaultError> {
        self.store
            .put_secret(&self.keys.sek, node, field, &value, now_millis())?;
        self.audit_for_node(AuditEvent::SecretStored, AuditOutcome::Success, node, None)
    }

    /// Opens a secret field for a stated purpose, and records that it was used.
    ///
    /// The purpose is checked against the credential's own restriction, so an
    /// importer mistake or a mistyped protocol cannot spray a password at the
    /// wrong service, and it is written to the audit log either way. A refusal
    /// is audited as `denied`; nothing about the secret itself is recorded.
    pub fn borrow_secret(
        &mut self,
        node: Uuid,
        field: &str,
        purpose: Purpose,
    ) -> Result<Secret<Vec<u8>>, VaultError> {
        if let Some(protocol) = protocol_for(purpose) {
            let permitted = match self.store.node(node)? {
                Some(row) => match node_from_row(&row)?.kind.as_credential() {
                    Some(credential) => credential.permits(&protocol),
                    // Only credential nodes carry a restriction; a secret on a
                    // connection is the connection's own.
                    None => true,
                },
                None => return Err(VaultError::NoSuchNode(node)),
            };
            if !permitted {
                self.audit_for_node(
                    AuditEvent::SecretUsed,
                    AuditOutcome::Denied,
                    node,
                    Some(field),
                )?;
                return Err(VaultError::PurposeRefused(purpose));
            }
        }

        let secret = self.store.get_secret(&self.keys.sek, node, field)?;
        let event = match purpose {
            Purpose::Reveal => AuditEvent::SecretRevealed,
            Purpose::Export => AuditEvent::SecretExported,
            _ => AuditEvent::SecretUsed,
        };
        self.audit_for_node(event, AuditOutcome::Success, node, Some(field))?;
        Ok(secret)
    }

    /// Removes a secret field.
    pub fn remove_secret(&mut self, node: Uuid, field: &str) -> Result<(), VaultError> {
        self.store.delete_secret(node, field)?;
        self.audit_for_node(
            AuditEvent::SecretRemoved,
            AuditOutcome::Success,
            node,
            Some(field),
        )
    }

    /// Whether a node has a secret in that field, without decrypting it.
    pub fn has_secret(&self, node: Uuid, field: &str) -> Result<bool, VaultError> {
        self.store.has_secret(node, field)
    }

    /// The field names a node holds secrets for.
    pub fn secret_fields(&self, node: Uuid) -> Result<Vec<String>, VaultError> {
        self.store.secret_fields(node)
    }

    // ------------------------------------------------------ private keys ---

    /// Reads a private key file, identifies its container and stores it on a
    /// credential node.
    ///
    /// The format comes from the file's content, never from its name: a `.pem`
    /// holding an OpenSSH container is ordinary. A file that is not a private
    /// key is refused with [`VaultError::NotAPrivateKey`]; a key of a kind no
    /// protocol here can authenticate with, with
    /// [`VaultError::UnsupportedKeyFormat`]; a legacy PEM enciphered with a
    /// cipher this build cannot read, with
    /// [`VaultError::UnsupportedKeyCipher`]. No message, and no log line on
    /// this path, contains any part of the key.
    ///
    /// Returns the format the key was *stored* under, which is also written to
    /// the node. That is not always the container the file was in: a legacy
    /// PKCS#1 RSA or SEC 1 EC PEM is re-enveloped as PKCS#8 on the way in, so
    /// the vault holds one representation of the material. See
    /// `crate::credential` for why.
    pub fn import_private_key(
        &mut self,
        node: Uuid,
        path: &Path,
        passphrase: Option<&Secret<String>>,
    ) -> Result<KeyFormat, VaultError> {
        let key = ImportedKey::read(path)?;
        let format = key.format();
        self.set_private_key(node, &key, passphrase)?;
        Ok(format)
    }

    /// Stores private key material on a credential node.
    ///
    /// The node must already exist and be a credential: a secret's ciphertext
    /// is bound to its node's id and revision, so it cannot be written before
    /// the node is. Any `SecretKind` the credential had is replaced by
    /// `PrivateKey`, carrying the detected format, and the passphrase — if the
    /// key has one — is stored as its own field, so revealing one does not
    /// reveal the other.
    ///
    /// Passing `None` for the passphrase removes any passphrase already stored,
    /// which is what replacing an encrypted key with an unencrypted one means.
    ///
    /// A key still locked in a legacy PEM container is deciphered here, with
    /// the passphrase given, and stored as the PKCS#8 document it becomes. Its
    /// passphrase is then *not* stored: it belonged to an envelope that no
    /// longer exists, and a passphrase kept beside a key it does not open is
    /// one the protocol adapter would hand to a parser that has no use for it —
    /// which fails the connection rather than the import, a long way from the
    /// cause. See `crate::credential` for why the envelope is not preserved.
    pub fn set_private_key(
        &mut self,
        node: Uuid,
        key: &ImportedKey,
        passphrase: Option<&Secret<String>>,
    ) -> Result<(), VaultError> {
        // Before the row is touched: a locked key that cannot be opened must
        // leave the credential exactly as it was.
        let unlocked = match (key.material(), passphrase) {
            (Some(_), _) => None,
            (None, Some(passphrase)) => Some(key.unlock(passphrase.expose_secret().as_bytes())?),
            (None, None) => return Err(VaultError::KeyPassphraseRequired),
        };
        let stored = unlocked.as_ref().unwrap_or(key);
        let material = stored.material().ok_or(VaultError::KeyPassphraseRequired)?;
        // The passphrase opened the PEM container and has no second job.
        let passphrase = if unlocked.is_some() { None } else { passphrase };

        let row = self.store.node(node)?.ok_or(VaultError::NoSuchNode(node))?;
        let mut domain = node_from_row(&row)?;
        let NodeKind::Credential(credential) = &mut domain.kind else {
            return Err(VaultError::NotAPrivateKeyCredential(node));
        };

        credential.secret = SecretKind::PrivateKey {
            sealed_key: Self::sealed_placeholder(),
            sealed_passphrase: passphrase.map(|_| Self::sealed_placeholder()),
            format: stored.format(),
        };

        // The revision does not move: the row's own secrets stay bound to the
        // revision they were sealed under, and only the description of the
        // credential changed.
        self.store.update_node(&row_from_node(&domain)?)?;

        self.store.put_secret(
            &self.keys.sek,
            node,
            FIELD_PRIVATE_KEY,
            material,
            now_millis(),
        )?;

        match passphrase {
            Some(passphrase) => {
                // A second copy of the passphrase bytes, wrapped so it is wiped
                // when this scope ends. `Secret` is deliberately not `Clone`,
                // which is what makes the copy visible here.
                let bytes = Secret::new(passphrase.expose_secret().as_bytes().to_vec());
                self.store.put_secret(
                    &self.keys.sek,
                    node,
                    FIELD_PASSPHRASE,
                    &bytes,
                    now_millis(),
                )?;
            }
            None => self.store.delete_secret(node, FIELD_PASSPHRASE)?,
        }

        self.audit_for_node(
            AuditEvent::SecretStored,
            AuditOutcome::Success,
            node,
            Some(FIELD_PRIVATE_KEY),
        )
    }

    /// Opens a stored private key, with its passphrase if it has one, for a
    /// stated purpose.
    ///
    /// The purpose is checked against the credential's restriction and written
    /// to the audit log, exactly as [`Vault::borrow_secret`] does — this is
    /// that call, twice, plus the format the node records.
    pub fn borrow_private_key(
        &mut self,
        node: Uuid,
        purpose: Purpose,
    ) -> Result<PrivateKeyMaterial, VaultError> {
        let row = self.store.node(node)?.ok_or(VaultError::NoSuchNode(node))?;
        let format = match node_from_row(&row)?.kind {
            NodeKind::Credential(credential) => match credential.secret {
                SecretKind::PrivateKey { format, .. } => format,
                _ => return Err(VaultError::NotAPrivateKeyCredential(node)),
            },
            _ => return Err(VaultError::NotAPrivateKeyCredential(node)),
        };

        let key = self.borrow_secret(node, FIELD_PRIVATE_KEY, purpose)?;
        let passphrase = if self.store.has_secret(node, FIELD_PASSPHRASE)? {
            Some(self.borrow_secret(node, FIELD_PASSPHRASE, purpose)?)
        } else {
            None
        };

        Ok(PrivateKeyMaterial::new(format, key, passphrase))
    }

    // ------------------------------------------------------------- slots ---

    /// Adds a password slot, wrapping the same master key.
    ///
    /// Does not re-encrypt the body: that is the whole point of the slot table.
    pub fn add_password_slot(
        &mut self,
        label: impl Into<String>,
        password: &Secret<String>,
        keyfile: Option<&Path>,
        params: Option<KdfParams>,
    ) -> Result<u8, VaultError> {
        let params = match params {
            Some(params) => accept_kdf_params(params)?,
            // Inherited, but never below the floor. A vault written by an older
            // build carries weaker parameters in its header, and minting a
            // brand-new credential at yesterday's cost is exactly what
            // `KdfParams::check_floor`'s contract says must not happen.
            None => self.header.kdf_params.clamped_to_floor(),
        };
        let index = self.header.next_slot_index()?;
        let slot = slots::new_password_slot(
            index,
            label.into(),
            now_seconds(),
            password,
            keyfile,
            params,
            &self.keys.vmk,
        )?;
        self.header.slots_mut().push(slot);
        self.audit(
            AuditEvent::SlotAdded,
            AuditOutcome::Success,
            Some("password"),
        )?;
        Ok(index)
    }

    /// Adds a recovery slot and returns the key that opens it.
    ///
    /// A vault may hold more than one: a sealed break-glass envelope in a safe
    /// is a legitimate reason to want two.
    pub fn add_recovery_slot(
        &mut self,
        label: impl Into<String>,
    ) -> Result<(u8, RecoveryKey), VaultError> {
        let index = self.header.next_slot_index()?;
        let (slot, key) =
            slots::new_recovery_slot(index, label.into(), now_seconds(), &self.keys.vmk)?;
        self.header.slots_mut().push(slot);
        self.audit(AuditEvent::RecoveryKeyIssued, AuditOutcome::Success, None)?;
        Ok((index, key))
    }

    /// Enrols this machine's credential store.
    pub fn add_keychain_slot(&mut self, label: impl Into<String>) -> Result<u8, VaultError> {
        let index = self.header.next_slot_index()?;
        let slot = slots::new_keychain_slot(
            index,
            label.into(),
            now_seconds(),
            self.header.vault_id,
            &self.keys.vmk,
        )?;
        self.header.slots_mut().push(slot);
        self.audit(
            AuditEvent::SlotAdded,
            AuditOutcome::Success,
            Some("keychain"),
        )?;
        Ok(index)
    }

    /// Revokes a slot.
    ///
    /// Revocation deletes a slot entry, which is why a lost hardware key can be
    /// revoked without having it to hand. The last slot cannot be removed: a
    /// vault with an empty slot table is a file nobody can ever open again.
    pub fn remove_slot(&mut self, index: u8) -> Result<(), VaultError> {
        let position = self
            .header
            .slots()
            .iter()
            .position(|s| s.index == index)
            .ok_or(VaultError::NoSuchSlot(index))?;
        if self.header.slots().len() <= 1 {
            return Err(VaultError::LastSlot);
        }

        let removed = self.header.slots_mut().remove(position);
        if removed.kind == SlotKind::Keychain {
            if let Some(account) = removed
                .extra
                .as_ref()
                .and_then(|e| e.keychain_account.clone())
            {
                slots::keychain_forget(&account)?;
            }
        }
        self.audit(
            AuditEvent::SlotRemoved,
            AuditOutcome::Success,
            Some(removed.kind.as_str()),
        )
    }

    /// Re-wraps key slot 0 under a new password.
    ///
    /// Slot 0 is where [`Vault::create`] puts the master password, so on a
    /// vault whose slot table has never been edited this is the slot the
    /// settings screen calls "Master password".
    ///
    /// It is not a synonym for "the password slot". Indices are reused — the
    /// header hands out the lowest free one — so
    /// removing slot 0 and enrolling anything else puts a different kind of
    /// slot at index 0 and the next password slot elsewhere. This is a fixed
    /// index and nothing more: on such a vault it refuses by kind rather than
    /// rebuilding a recovery slot as a password slot, and the caller wants
    /// [`Vault::change_password_slot`] with the index the password actually
    /// lives in. Anything addressing a slot the user picked — the settings
    /// screen does — should call that instead of this.
    pub fn change_master_password(
        &mut self,
        current: &PasswordCredential,
        new: &PasswordCredential,
        params: Option<KdfParams>,
    ) -> Result<(), VaultError> {
        self.change_password_slot(0, current, new, params)
    }

    /// Re-wraps one password slot under a new password or key file.
    ///
    /// The master key does not change: nothing is re-encrypted, the body is not
    /// touched, and every other slot — the recovery key in particular — keeps
    /// working. Only this slot's key-encryption key changes, which is why
    /// changing a password is instant on a vault of any size.
    ///
    /// `current` is verified against **this** slot, by index, before anything
    /// is replaced. A rewrap without that check would re-key the slot to the
    /// new password while destroying the only copy of the master key it held,
    /// and the caller would find out at the next unlock.
    ///
    /// Two things follow from "this slot, by index", and both reach a user:
    ///
    /// - An unlock tries every slot of the method's kind; this tries one. "The
    ///   credential that has this vault open" and "the credential for slot
    ///   `index`" are therefore different claims on a vault holding more than
    ///   one password slot, and only the second one is asked here.
    /// - A key file's contribution is `BLAKE3(file_bytes)`, so the credential
    ///   is the file's *contents*. The same path is not the same key file once
    ///   the file has been re-generated, restored or re-synchronised, and an
    ///   open vault proves nothing about it: the master key was unwrapped
    ///   earlier in the session and the file is not read again until this asks
    ///   for it.
    ///
    /// [`VaultError::SlotCredentialRejected`] covers both, so a caller with a
    /// user in front of it should say what it knows — which slot the session
    /// was opened through, and what a key file actually is — rather than
    /// passing on "that does not open key slot 0" alone. A key file that could
    /// not be *read* is separate and arrives as [`VaultError::Keyfile`].
    ///
    /// `params` defaults to the slot's existing cost, raised to the floor if the
    /// vault was written by an older build. Saves on success.
    pub fn change_password_slot(
        &mut self,
        index: u8,
        current: &PasswordCredential,
        new: &PasswordCredential,
        params: Option<KdfParams>,
    ) -> Result<(), VaultError> {
        let slot = self.slot_of_kind(index, SlotKind::Password)?;
        let existing_params = slot.kdf_params.ok_or(VaultError::NoSuchSlot(index))?;
        let label = slot.label.clone();
        let created_at = slot.created_at;
        let last_used = slot.last_used;

        if !self.password_opens_slot(
            index,
            current.password(),
            current.keyfile(),
            existing_params,
        )? {
            return Err(VaultError::SlotCredentialRejected(index));
        }

        let params = match params {
            Some(params) => accept_kdf_params(params)?,
            None => rewrap_params(existing_params),
        };

        let mut replacement = slots::new_password_slot(
            index,
            label,
            created_at,
            new.password(),
            new.keyfile(),
            params,
            &self.keys.vmk,
        )?;
        replacement.last_used = last_used;

        let previous = self.header.slots().to_vec();
        self.replace_slot(index, replacement)?;
        self.audit(
            AuditEvent::PasswordChanged,
            AuditOutcome::Success,
            Some(SlotKind::Password.as_str()),
        )?;
        self.save_or_restore_slots(previous)
    }

    /// Replaces a recovery slot and returns the key that opens the new one.
    ///
    /// The old key stops working the moment this is saved. The new one is
    /// returned exactly once; nothing in the file can reproduce it. The master
    /// key does not change, so every other slot is untouched.
    pub fn rotate_recovery_key(&mut self, index: u8) -> Result<RecoveryKey, VaultError> {
        let slot = self.slot_of_kind(index, SlotKind::Recovery)?;
        let label = slot.label.clone();

        // A rotated key is a new key: it is dated today, and it has never been
        // used. Carrying the old dates forward would make the settings screen
        // claim a key was generated on a day it was not.
        let (replacement, key) =
            slots::new_recovery_slot(index, label, now_seconds(), &self.keys.vmk)?;

        let previous = self.header.slots().to_vec();
        self.replace_slot(index, replacement)?;
        self.audit(AuditEvent::RecoveryKeyIssued, AuditOutcome::Success, None)?;
        self.save_or_restore_slots(previous)?;
        Ok(key)
    }

    /// Replaces the vault master key: every slot re-wrapped, every stored
    /// secret re-sealed, the body re-encrypted on the next write.
    ///
    /// This is the answer to "a copy of this file may have leaked while one of
    /// my keys was compromised", and `docs/security/key-management.md` asks for
    /// it to be offered in those words rather than filed under "advanced". It
    /// is the only slot operation that is expensive, because it is the only one
    /// that changes the key everything else is derived from.
    ///
    /// What it does **not** do is make the leaked copy unreadable. That file
    /// still opens with the old keys; the outcome is that the *current* file no
    /// longer shares a key with it. Tell the user to delete the old copies —
    /// including the rolling backups beside the vault, which this save rotates
    /// and which hold the pre-rotation image.
    ///
    /// Every password slot needs its credential in the `plan`, or an explicit
    /// [`RotationPlan::dropping`]. Keychain slots are re-wrapped under the token
    /// already in the platform store, so the entry there is untouched and a
    /// vault carried to a machine that has no token must drop that slot.
    /// Hardware key slots cannot be re-wrapped without the authenticator, which
    /// this version cannot talk to, so they must be dropped.
    ///
    /// On a failed write the vault is put back as it was — keys, slot table and
    /// re-sealed secrets — so that a rotation is either complete or did not
    /// happen. The recovery keys of a failed rotation are dropped with it.
    pub fn rotate_master_key(
        &mut self,
        plan: &RotationPlan,
    ) -> Result<RotationOutcome, VaultError> {
        let (kept, dropped) = self.plan_rotation(plan)?;

        let new_keys = VaultKeys::derive(crypto::random_key()?)?;
        let mut rebuilt = Vec::with_capacity(kept.len());
        let mut recovery_keys = Vec::new();
        let now = now_seconds();

        for slot in &kept {
            match slot.kind {
                SlotKind::Password => {
                    // Checked in `plan_rotation`; this is the same lookup, not
                    // a second decision.
                    let credential = plan
                        .password_for(slot.index)
                        .ok_or(VaultError::SlotCredentialMissing(slot.index))?;
                    let params = rewrap_params(slot.kdf_params.unwrap_or(self.header.kdf_params));
                    let mut replacement = slots::new_password_slot(
                        slot.index,
                        slot.label.clone(),
                        slot.created_at,
                        credential.password(),
                        credential.keyfile(),
                        params,
                        &new_keys.vmk,
                    )?;
                    replacement.last_used = slot.last_used;
                    rebuilt.push(replacement);
                }
                SlotKind::Recovery => {
                    let (replacement, key) = slots::new_recovery_slot(
                        slot.index,
                        slot.label.clone(),
                        now,
                        &new_keys.vmk,
                    )?;
                    recovery_keys.push((slot.index, key));
                    rebuilt.push(replacement);
                }
                SlotKind::Keychain => {
                    let mut replacement =
                        slots::rewrap_keychain_slot(slot, self.header.vault_id, &new_keys.vmk)?;
                    replacement.last_used = slot.last_used;
                    rebuilt.push(replacement);
                }
                // Refused in `plan_rotation`, which runs before anything is
                // built.
                SlotKind::Fido2 => return Err(VaultError::Fido2Unsupported),
            }
        }

        let old_vmk = self.keys.vmk.clone();
        let previous_slots = self.header.slots().to_vec();
        let secrets_resealed =
            self.store
                .reseal_secrets(&self.keys.sek, &new_keys.sek, now_millis())?;

        let rewrapped: Vec<u8> = rebuilt.iter().map(|s| s.index).collect();
        *self.header.slots_mut() = rebuilt;
        self.keys = new_keys;
        // The vault was opened through a slot that no longer holds the same
        // wrapped key; the index is still that slot's, and its `last_used` was
        // carried over, so nothing about it is stale.
        self.audit(
            AuditEvent::MasterKeyRotated,
            AuditOutcome::Success,
            Some("every slot re-wrapped and every secret re-sealed"),
        )?;

        if let Err(error) = self.save() {
            self.undo_rotation(old_vmk, previous_slots);
            return Err(error);
        }

        Ok(RotationOutcome {
            rewrapped,
            dropped,
            recovery_keys,
            secrets_resealed,
        })
    }

    /// Checks a rotation plan against the slot table, and reports which slots
    /// are to be rebuilt and which discarded.
    ///
    /// Everything that can refuse the rotation refuses here, before a single
    /// key is generated: a plan that is wrong must not leave the vault half
    /// rotated.
    fn plan_rotation(
        &self,
        plan: &RotationPlan,
    ) -> Result<(Vec<crate::header::KeySlot>, Vec<u8>), VaultError> {
        let mut kept = Vec::new();
        let mut dropped = Vec::new();

        for slot in self.header.slots() {
            if plan.drops(slot.index) {
                dropped.push(slot.index);
                continue;
            }
            match slot.kind {
                SlotKind::Password => {
                    let params = slot.kdf_params.ok_or(VaultError::NoSuchSlot(slot.index))?;
                    let credential = plan
                        .password_for(slot.index)
                        .ok_or(VaultError::SlotCredentialMissing(slot.index))?;
                    if !self.password_opens_slot(
                        slot.index,
                        credential.password(),
                        credential.keyfile(),
                        params,
                    )? {
                        return Err(VaultError::SlotCredentialRejected(slot.index));
                    }
                }
                SlotKind::Keychain => {
                    // The token is the credential, and it lives in the platform
                    // store. A machine that does not have it cannot rebuild the
                    // slot, and inventing a new token here would silently
                    // enrol this machine while cutting off the one that had it.
                    if !slots::keychain_token_available(slot, self.header.vault_id) {
                        return Err(VaultError::SlotCredentialMissing(slot.index));
                    }
                }
                SlotKind::Fido2 => return Err(VaultError::Fido2Unsupported),
                SlotKind::Recovery => {}
            }
            kept.push(slot.clone());
        }

        if kept.is_empty() {
            return Err(VaultError::LastSlot);
        }
        Ok((kept, dropped))
    }

    /// Puts the vault back the way it was after a rotation that could not be
    /// written.
    ///
    /// Best effort by necessity: if re-sealing the secrets back fails, the
    /// in-memory database is left keyed to a master key that was never written,
    /// and the honest thing is to say so and let the caller lock the vault
    /// rather than to keep going.
    fn undo_rotation(
        &mut self,
        old_vmk: crate::crypto::KeyBytes,
        slots: Vec<crate::header::KeySlot>,
    ) {
        match VaultKeys::derive(old_vmk) {
            Ok(previous) => {
                if let Err(error) =
                    self.store
                        .reseal_secrets(&self.keys.sek, &previous.sek, now_millis())
                {
                    tracing::error!(
                        %error,
                        "the master key rotation could not be written and could not be undone; \
                         lock this vault and reopen it from the file on disk"
                    );
                    return;
                }
                self.keys = previous;
                *self.header.slots_mut() = slots;
            }
            Err(error) => tracing::error!(
                %error,
                "the master key rotation could not be written and could not be undone; \
                 lock this vault and reopen it from the file on disk"
            ),
        }
    }

    /// The slot at `index`, refusing one of the wrong kind.
    fn slot_of_kind(
        &self,
        index: u8,
        expected: SlotKind,
    ) -> Result<&crate::header::KeySlot, VaultError> {
        let slot = self
            .header
            .slots()
            .iter()
            .find(|s| s.index == index)
            .ok_or(VaultError::NoSuchSlot(index))?;
        if slot.kind != expected {
            return Err(VaultError::WrongSlotKind {
                index,
                expected,
                found: slot.kind,
            });
        }
        Ok(slot)
    }

    /// Swaps one slot for a rebuilt one at the same index.
    fn replace_slot(
        &mut self,
        index: u8,
        replacement: crate::header::KeySlot,
    ) -> Result<(), VaultError> {
        let slot = self
            .header
            .slots_mut()
            .iter_mut()
            .find(|s| s.index == index)
            .ok_or(VaultError::NoSuchSlot(index))?;
        *slot = replacement;
        Ok(())
    }

    /// Saves, and puts the slot table back if the write fails.
    ///
    /// A slot change that is not on disk has not happened: leaving the new
    /// credential live in memory while the file still answers to the old one is
    /// how a user ends up locked out by a full-disk error.
    fn save_or_restore_slots(
        &mut self,
        previous: Vec<crate::header::KeySlot>,
    ) -> Result<(), VaultError> {
        match self.save() {
            Ok(()) => Ok(()),
            Err(error) => {
                *self.header.slots_mut() = previous;
                Err(error)
            }
        }
    }

    // ---------------------------------------------------------- settings ---

    /// Reads one application setting from inside the vault.
    pub fn setting(&self, key: &str) -> Result<Option<Vec<u8>>, VaultError> {
        self.store.setting(key)
    }

    /// Writes one application setting.
    pub fn set_setting(&mut self, key: &str, value: &[u8]) -> Result<(), VaultError> {
        self.store.set_setting(key, value)?;
        self.audit(AuditEvent::SettingChanged, AuditOutcome::Success, Some(key))
    }

    /// The per-vault settings the Vault settings screen edits.
    ///
    /// A vault that has never had them written gets the defaults from
    /// `docs/security/key-management.md`. `backup_count` is filled in from the
    /// header, which is where it is stored — see [`VaultSettings`].
    pub fn settings(&self) -> Result<VaultSettings, VaultError> {
        let mut settings = match self.store.setting(settings::SETTINGS_KEY)? {
            Some(bytes) => ciborium::from_reader(bytes.as_slice())
                .map_err(|_| VaultError::CorruptRow("settings.vault"))?,
            None => VaultSettings::default(),
        };
        settings.backup_count = self.header.backup_count;
        Ok(settings)
    }

    /// Writes the per-vault settings.
    ///
    /// `backup_count` goes to the header rather than into the settings blob, so
    /// there is one place it is stored. Both the header and the settings table
    /// reach the disk on the next [`Vault::save`].
    ///
    /// The audit entry names the fields that changed and never their values:
    /// the detail column is exported wholesale by the compliance features.
    pub fn set_settings(&mut self, settings: &VaultSettings) -> Result<(), VaultError> {
        let previous = self.settings()?;
        let changed = previous.changed_fields(settings);

        let mut encoded = Vec::new();
        ciborium::into_writer(settings, &mut encoded).map_err(|_| VaultError::HeaderEncode)?;
        self.store.set_setting(settings::SETTINGS_KEY, &encoded)?;
        self.header.backup_count = settings.backup_count.min(MAX_BACKUP_COUNT);

        if changed.is_empty() {
            return Ok(());
        }
        self.audit(
            AuditEvent::SettingChanged,
            AuditOutcome::Success,
            Some(changed.join(", ").as_str()),
        )
    }

    // ------------------------------------------------------------- trust ---

    /// Pins a host key or certificate.
    #[allow(clippy::too_many_arguments, reason = "mirrors the trust_store columns")]
    pub fn trust_pin(
        &mut self,
        host: &str,
        port: u16,
        kind: &str,
        algorithm: &str,
        fingerprint: &[u8],
        raw: &[u8],
        accepted_by: &str,
    ) -> Result<Uuid, VaultError> {
        let id = self.store.trust_pin(
            host,
            port,
            kind,
            algorithm,
            fingerprint,
            raw,
            accepted_by,
            now_millis(),
        )?;
        self.audit(AuditEvent::TrustPinned, AuditOutcome::Success, Some(host))?;
        Ok(id)
    }

    /// The fingerprint pinned for a host, if any.
    pub fn trust_lookup(
        &self,
        host: &str,
        port: u16,
        kind: &str,
        algorithm: &str,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        self.store.trust_lookup(host, port, kind, algorithm)
    }

    // ----------------------------------------------------------- session ---

    /// Records the start of a session and returns its identifier.
    pub fn session_start(
        &mut self,
        node: Option<Uuid>,
        protocol: &str,
        host: &str,
        username: Option<&str>,
    ) -> Result<Uuid, VaultError> {
        let id = self
            .store
            .session_start(node, protocol, host, username, now_millis())?;
        self.audit(
            AuditEvent::SessionStarted,
            AuditOutcome::Success,
            Some(protocol),
        )?;
        Ok(id)
    }

    /// Records the end of a session.
    pub fn session_end(
        &mut self,
        session: Uuid,
        close_reason: &str,
        bytes_in: i64,
        bytes_out: i64,
    ) -> Result<(), VaultError> {
        self.store
            .session_end(session, close_reason, bytes_in, bytes_out, now_millis())?;
        self.audit(AuditEvent::SessionEnded, AuditOutcome::Success, None)
    }

    // ------------------------------------------------------------- audit ---

    /// Appends to the audit log.
    ///
    /// `detail` is a short plain-language note. It is exported wholesale by the
    /// compliance features, so it must never contain a secret — not a password,
    /// not a key, not a token.
    pub fn audit(
        &mut self,
        event: AuditEvent,
        outcome: AuditOutcome,
        detail: Option<&str>,
    ) -> Result<(), VaultError> {
        self.store
            .audit(now_millis(), event, outcome, None, None, detail)
    }

    /// The same, attributed to a node.
    pub fn audit_for_node(
        &mut self,
        event: AuditEvent,
        outcome: AuditOutcome,
        node: Uuid,
        detail: Option<&str>,
    ) -> Result<(), VaultError> {
        self.store
            .audit(now_millis(), event, outcome, Some(node), None, detail)
    }

    /// The most recent audit entries, newest first, as
    /// `(timestamp_millis, event, outcome, detail)`.
    pub fn audit_recent(&self, limit: usize) -> Result<Vec<AuditEntry>, VaultError> {
        self.store.audit_recent(limit)
    }

    /// The audit entries a filter selects, newest first.
    ///
    /// Filtering and paging happen in the database rather than in the caller: a
    /// vault that has been in use for a year holds tens of thousands of rows,
    /// and the screen shows fifty.
    pub fn audit_query(&self, query: &AuditQuery) -> Result<Vec<AuditRecord>, VaultError> {
        self.store.audit_query(query)
    }

    /// How many entries the same filter selects, ignoring its paging.
    ///
    /// The number beside the filter chips — "last 30 days · 4,182 entries" — and
    /// what the pager divides.
    pub fn audit_count(&self, query: &AuditQuery) -> Result<usize, VaultError> {
        self.store.audit_count(query)
    }
}

/// Accepts caller-supplied Argon2id parameters.
///
/// The floor from `docs/security/vault-format.md` is enforced unconditionally,
/// with exactly one exception, and the exception is a compile-time one: with the
/// `insecure-test-kdf` feature on, [`KdfParams::low_cost_for_tests`] is accepted
/// verbatim, so that a test suite creating hundreds of vaults does not spend a
/// second of Argon2id on each. The feature is reachable only through this
/// crate's own dev-dependency on itself, so no ordinary build can turn it on.
///
/// This used to be gated on `debug_assertions`, which is a different thing
/// entirely: `cargo tauri dev` is a debug build, and a real vault created under
/// it kept a slot at 8 MiB and one pass for the rest of its life. It also made
/// `cargo test --release` fail, because the parameters the suite uses were
/// refused by the very build that is meant to be tested hardest.
///
/// The ceiling is checked too. Writing a slot at a cost this build refuses to
/// read would produce a file nothing here can open.
fn accept_kdf_params(params: KdfParams) -> Result<KdfParams, VaultError> {
    params.check_ceiling()?;
    #[cfg(feature = "insecure-test-kdf")]
    if params == KdfParams::low_cost_for_tests() {
        return Ok(params);
    }
    params.check_floor()
}

/// The Argon2id cost a re-wrapped password slot keeps.
///
/// Its own, when this build would create a slot at that cost; the floor
/// otherwise. A slot written by an older build at yesterday's cost must not be
/// minted again at that cost — that is [`KdfParams::check_floor`]'s contract —
/// and a slot already at or above the floor has no business being re-tuned by
/// an operation that is about a different key.
fn rewrap_params(existing: KdfParams) -> KdfParams {
    accept_kdf_params(existing).unwrap_or_else(|_| existing.clamped_to_floor())
}

/// Which protocol a borrowed credential is about to be used with, for the
/// restriction check. `None` for purposes that are not a connection.
fn protocol_for(purpose: Purpose) -> Option<ProtocolId> {
    let name = match purpose {
        Purpose::SshPassword | Purpose::SshPrivateKey => "ssh",
        Purpose::RdpCredentials => "rdp",
        Purpose::VncPassword => "vnc",
        Purpose::SftpPassword | Purpose::SftpPrivateKey => "sftp",
        Purpose::FtpPassword => "ftp",
        Purpose::Reveal | Purpose::Export => return None,
    };
    ProtocolId::new(name).ok()
}

/// Domain node to database row.
///
/// `props` holds the CBOR of the whole [`NodeKind`], discriminant included,
/// rather than only the kind-specific half. The `kind` column already carries
/// the discriminant for the `CHECK` constraint and the indexes; keeping it in
/// the blob as well means the blob decodes on its own, without the reader
/// having to trust that the two agree.
fn row_from_node(node: &Node) -> Result<NodeRow, VaultError> {
    // Sealed material is stripped rather than serialised: the ciphertext lives
    // in the `secrets` table and nowhere else. A second copy inside `props`
    // would go stale the moment a revision bump re-sealed the first, and a
    // stale copy of a credential is worse than no copy.
    let mut kind = node.kind.clone();
    strip_sealed(&mut kind);

    let mut props = Vec::new();
    ciborium::into_writer(&kind, &mut props).map_err(|_| VaultError::HeaderEncode)?;

    let mut custom_fields = Vec::new();
    ciborium::into_writer(&node.custom_fields, &mut custom_fields)
        .map_err(|_| VaultError::HeaderEncode)?;

    Ok(NodeRow {
        id: *node.id.as_uuid(),
        parent_id: node.parent_id.map(|p| *p.as_uuid()),
        sort_order: node.sort_order,
        kind: kind.label().to_owned(),
        name: node.name.clone(),
        description: node.description.clone(),
        icon: node.icon.clone(),
        colour: node.colour.clone(),
        props,
        custom_fields,
        created_at: node.created_at,
        updated_at: node.updated_at,
        revision: i64::try_from(node.revision)
            .map_err(|_| VaultError::CorruptRow("nodes.revision"))?,
        deleted_at: node.deleted_at,
        tags: node.tags.iter().map(|t| t.as_str().to_owned()).collect(),
        search_host: node.kind.as_connection().map(|c| c.host.clone()),
    })
}

/// Empties every sealed field in a node kind, in place.
fn strip_sealed(kind: &mut NodeKind) {
    let NodeKind::Credential(credential) = kind else {
        return;
    };

    match &mut credential.secret {
        SecretKind::Password { sealed } => sealed.clear(),
        SecretKind::PrivateKey {
            sealed_key,
            sealed_passphrase,
            ..
        } => {
            sealed_key.clear();
            if let Some(passphrase) = sealed_passphrase {
                passphrase.clear();
            }
        }
        SecretKind::Certificate {
            sealed_cert,
            sealed_key,
        } => {
            sealed_cert.clear();
            sealed_key.clear();
        }
        SecretKind::Agent { .. } | SecretKind::External { .. } => {}
    }

    if let Some(totp) = &mut credential.totp {
        totp.clear();
    }
}

/// Database row to domain node. The sealed fields come back empty; filling them
/// needs the store, so it happens in [`Vault::node_from_row`].
fn node_from_row(row: &NodeRow) -> Result<Node, VaultError> {
    let kind: NodeKind = ciborium::from_reader(row.props.as_slice())
        .map_err(|_| VaultError::CorruptRow("nodes.props"))?;
    let custom_fields: BTreeMap<String, String> =
        ciborium::from_reader(row.custom_fields.as_slice())
            .map_err(|_| VaultError::CorruptRow("nodes.custom_fields"))?;

    let mut tags = Vec::with_capacity(row.tags.len());
    for tag in &row.tags {
        tags.push(Tag::new(tag.clone()).map_err(|e| VaultError::Core(e.into()))?);
    }

    Ok(Node {
        id: NodeId::from_uuid(row.id),
        parent_id: row.parent_id.map(NodeId::from_uuid),
        sort_order: row.sort_order,
        kind,
        name: row.name.clone(),
        description: row.description.clone(),
        tags,
        icon: row.icon.clone(),
        colour: row.colour.clone(),
        created_at: row.created_at,
        updated_at: row.updated_at,
        revision: u64::try_from(row.revision)
            .map_err(|_| VaultError::CorruptRow("nodes.revision"))?,
        custom_fields,
        deleted_at: row.deleted_at,
    })
}

/// Appends a suffix to a path without disturbing its extension.
///
/// `with_extension` would turn `acme.rvault` into `acme.tmp` and lose which
/// vault the temporary file belongs to.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// The rolling backups that exist beside a vault, newest first.
fn existing_backups(path: &Path) -> Vec<PathBuf> {
    (1..=MAX_BACKUP_COUNT)
        .map(|n| sibling(path, &format!(".bak.{n}")))
        .filter(|p| p.is_file())
        .collect()
}

/// A private temporary name beside `path`, unique to this process and this
/// call.
///
/// A fixed `<vault>.tmp` is a shared name: two processes saving the same vault
/// — a second window, the command-line companion, a synchronisation client's
/// helper — both truncate it and both write into it, and the rename publishes
/// whichever interleaving won. That is the one outcome the atomic-write comment
/// promises cannot happen.
fn temp_path(path: &Path) -> Result<PathBuf, VaultError> {
    let mut suffix = [0u8; 8];
    crypto::fill_random(&mut suffix)?;
    let suffix = data_encoding::HEXLOWER.encode(&suffix);
    Ok(sibling(
        path,
        &format!(".{}.{suffix}.tmp", std::process::id()),
    ))
}

/// Creates a file that only its owner can read, and fails if it already exists.
///
/// The mode is set at creation rather than afterwards so there is no instant in
/// which the file exists and is world-readable; on the temporary image it also
/// survives the rename, which is what gives the published vault its mode.
fn create_private(path: &Path) -> Result<File, VaultError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(OWNER_ONLY);
    options
        .open(path)
        .map_err(|e| VaultError::io("writing the vault", path, e))
}

/// Restricts an existing file to its owner.
///
/// Every file this build creates is already owner-only from the moment it
/// exists. This is for the ones it did not create: a vault written by an
/// earlier build sits at 0644 until something corrects it, and a vault that is
/// only ever read would never be corrected by a save.
fn restrict(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, std::fs::Permissions::from_mode(OWNER_ONLY))
            .map_err(|e| VaultError::io("restricting the vault permissions", path, e))?;
    }
    // An owner-only ACL on Windows needs the Win32 security APIs; this build
    // leaves the file at whatever the directory's inheritable ACL grants.
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Writes a complete vault image so that a crash leaves either the old file or
/// the new one.
///
/// The previous file is copied — not renamed — into `.bak.1` before the
/// rename, so that `path` names a complete vault at every instant. Renaming it
/// away first would open a window in which the vault simply does not exist.
fn write_atomically(
    path: &Path,
    image: &[u8],
    backup_count: usize,
    rotate: bool,
) -> Result<bool, VaultError> {
    let temp = temp_path(path)?;

    if let Err(error) = write_temp_image(&temp, image) {
        // Nothing has been published, so the half-written image is litter.
        let _ = fs::remove_file(&temp);
        return Err(error);
    }

    let rotated = rotate && path.exists() && backup_count > 0;
    if rotated {
        if let Err(error) = rotate_backups(path, backup_count) {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
    }

    if let Err(e) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(VaultError::io("replacing the vault", path, e));
    }
    // No `restrict` here on purpose. The rename replaces the directory entry,
    // not the inode, so the mode that lands on `path` is the temporary file's —
    // already owner-only. Re-asserting it after the image is published would
    // mean a `chmod` failure could fail a save that had in fact succeeded, and
    // roll `modified_at` back to disagree with the file on disk. A vault
    // written by an earlier build is repaired on open instead.
    sync_directory(path);
    Ok(rotated)
}

/// Fills the temporary image and flushes it to the platter.
fn write_temp_image(temp: &Path, image: &[u8]) -> Result<(), VaultError> {
    let mut file = create_private(temp)?;
    file.write_all(image)
        .map_err(|e| VaultError::io("writing the vault", temp, e))?;
    file.sync_all()
        .map_err(|e| VaultError::io("flushing the vault", temp, e))
}

/// Shifts `.bak.N-1` to `.bak.N` and copies the current file into `.bak.1`.
fn rotate_backups(path: &Path, count: usize) -> Result<(), VaultError> {
    if count == 0 {
        return Ok(());
    }
    let count = count.min(MAX_BACKUP_COUNT);

    let oldest = sibling(path, &format!(".bak.{count}"));
    if oldest.exists() {
        fs::remove_file(&oldest).map_err(|e| VaultError::io("rotating the backups", &oldest, e))?;
    }
    for n in (1..count).rev() {
        let from = sibling(path, &format!(".bak.{n}"));
        let to = sibling(path, &format!(".bak.{}", n + 1));
        if from.exists() {
            fs::rename(&from, &to).map_err(|e| VaultError::io("rotating the backups", &from, e))?;
        }
    }

    copy_backup(path, &sibling(path, ".bak.1"))
}

/// Copies the current vault into a backup and flushes it.
///
/// Written by hand rather than through `fs::copy` for two reasons. `fs::copy`
/// gives the copy the source's mode, which for a vault written by an earlier
/// build is 0644. And the flush needs a handle opened for writing:
/// `FlushFileBuffers` fails on a read-only handle on Windows, so flushing
/// through `File::open` and discarding the result — as this did — meant a power
/// loss could leave `.bak.1` partial with nothing having reported it.
fn copy_backup(from: &Path, to: &Path) -> Result<(), VaultError> {
    if to.exists() {
        fs::remove_file(to).map_err(|e| VaultError::io("writing the backup", to, e))?;
    }

    let mut source = File::open(from).map_err(|e| VaultError::io("writing the backup", from, e))?;
    let mut backup = create_private(to)?;

    if let Err(e) = std::io::copy(&mut source, &mut backup) {
        let _ = fs::remove_file(to);
        return Err(VaultError::io("writing the backup", to, e));
    }
    backup
        .sync_all()
        .map_err(|e| VaultError::io("flushing the backup", to, e))
}

/// Flushes the directory entry so the rename itself is durable.
///
/// POSIX only: on Windows the rename is durable through `ReplaceFileW`'s own
/// semantics and a directory cannot be opened as a file at all. A failure is
/// not fatal — the data is already on disk — so it is not propagated.
fn sync_directory(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Seconds since the Unix epoch, for the header and the key slots.
fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Milliseconds since the Unix epoch, for everything inside the database.
///
/// Two units in one crate is not an accident: the domain model timestamps nodes
/// in milliseconds and the header describes itself in seconds, and converting
/// at the boundary is less error-prone than converting at every call site.
fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
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
    use remoter_core::ConnectionProps;

    fn test_options(dir: &Path, name: &str) -> CreateOptions {
        CreateOptions::new(
            dir.join(name),
            "Test vault",
            Secret::new(String::from("a master password")),
        )
        .with_kdf_params(KdfParams::low_cost_for_tests())
    }

    fn open_test(path: &Path) -> Result<Vault, UnlockError> {
        Vault::open(
            path,
            UnlockMethod::password(Secret::new(String::from("a master password"))),
        )
    }

    fn connection(name: &str, host: &str, now: i64) -> Node {
        Node::new(
            NodeKind::Connection(ConnectionProps::new("ssh", host).unwrap()),
            name,
            now,
        )
    }

    #[test]
    fn a_new_vault_opens_with_its_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        assert_eq!(vault.slots().len(), 2);
        vault.lock();

        let reopened = open_test(&path).unwrap();
        assert_eq!(reopened.label(), "Test vault");
        assert_eq!(reopened.opened_with(), Some(0));
    }

    #[test]
    fn the_wrong_password_says_nothing_useful() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.lock();

        let err = Vault::open(
            &path,
            UnlockMethod::password(Secret::new(String::from("not the password"))),
        )
        .unwrap_err();
        assert!(matches!(err, UnlockError::NotUnlocked));
        assert_eq!(err.to_string(), "That did not unlock the vault.");
    }

    #[test]
    fn debug_output_never_carries_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        let rendered = format!("{vault:?}");
        assert!(rendered.contains("VaultKeys(<redacted>)"));
        assert_eq!(format!("{key:?}"), "RecoveryKey(<redacted>)");
    }

    #[test]
    fn nodes_survive_a_save_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();

        let mut tree = vault.tree().unwrap();
        let node = connection("web-01", "web-01.example.internal", 1_000);
        let id = node.id;
        let patch = tree.insert(node).unwrap();
        vault.apply(&tree, &patch).unwrap();
        vault.save().unwrap();
        vault.lock();

        let reopened = open_test(&path).unwrap();
        let tree = reopened.tree().unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.get(id).unwrap().name, "web-01");
        assert_eq!(reopened.connection_count().unwrap(), 1);
    }

    #[test]
    fn a_secret_survives_a_revision_bump_through_apply() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();

        let mut tree = vault.tree().unwrap();
        let node = connection("web-01", "web-01.example.internal", 1_000);
        let id = node.id;
        let patch = tree.insert(node).unwrap();
        vault.apply(&tree, &patch).unwrap();

        vault
            .set_secret(*id.as_uuid(), "password", Secret::new(b"hunter2".to_vec()))
            .unwrap();

        let mut updated = tree.get(id).unwrap().clone();
        updated.description = "the front end".into();
        let patch = tree.update(updated).unwrap();
        vault.apply(&tree, &patch).unwrap();

        let secret = vault
            .borrow_secret(*id.as_uuid(), "password", Purpose::SshPassword)
            .unwrap();
        use crate::ExposeSecret as _;
        assert_eq!(secret.expose_secret().as_slice(), b"hunter2");
    }

    #[test]
    fn the_backups_rotate_once_a_session_not_once_a_click() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();

        // Four saves is four ordinary clicks. Before this, the default of
        // three backups meant the pre-edit image was already gone by here.
        for _ in 0..4 {
            vault.save().unwrap();
        }
        assert!(sibling(&path, ".bak.1").is_file());
        assert!(
            !sibling(&path, ".bak.2").exists(),
            "one session must produce one backup, whatever it saves"
        );
        vault.lock();

        let mut reopened = open_test(&path).unwrap();
        reopened.save().unwrap();
        reopened.save().unwrap();
        assert!(sibling(&path, ".bak.2").is_file());
        assert!(!sibling(&path, ".bak.3").exists());
        assert_eq!(reopened.info().backups.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn the_vault_and_its_backups_are_readable_only_by_their_owner() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.save().unwrap();
        vault.lock();

        let backup = sibling(&path, ".bak.1");
        assert!(backup.is_file());

        for file in [&path, &backup] {
            let mode = fs::metadata(file).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o600,
                "{} is mode {mode:o}, not owner-only",
                file.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_vault_from_an_earlier_build_is_repaired_on_open() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.lock();

        // What a vault written under the default umask looks like.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let opened = open_test(&path).unwrap();
        assert_eq!(opened.label(), "Test vault");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "still mode {mode:o} after a successful unlock");
    }

    #[test]
    fn a_save_leaves_no_temporary_file_behind_and_never_reuses_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.save().unwrap();

        let leftovers: Vec<PathBuf> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind {leftovers:?}");

        // The old fixed `<vault>.tmp` was a name two processes shared; each
        // call must now pick its own.
        let first = temp_path(&path).unwrap();
        let second = temp_path(&path).unwrap();
        assert_ne!(first, second);
        assert_ne!(first, sibling(&path, ".tmp"));
        assert!(
            first
                .to_string_lossy()
                .contains(&std::process::id().to_string()),
            "the temporary name must identify the writing process"
        );
    }

    #[test]
    fn a_backup_copy_reports_a_failure_rather_than_discarding_it() {
        // The flush used to go through a read-only handle with its result
        // dropped, so a failing backup looked like a successful one.
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("acme.rvault");
        fs::write(&source, b"a vault image").unwrap();

        let ok = dir.path().join("acme.rvault.bak.1");
        copy_backup(&source, &ok).unwrap();
        assert_eq!(fs::read(&ok).unwrap(), b"a vault image");

        let unreachable = dir.path().join("no-such-directory").join("acme.bak.1");
        assert!(matches!(
            copy_backup(&source, &unreachable),
            Err(VaultError::Io { .. })
        ));
    }

    #[test]
    fn a_backup_opens_with_the_same_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.save().unwrap();
        vault.lock();

        let backup = sibling(&path, ".bak.1");
        let opened = open_test(&backup).unwrap();
        assert_eq!(opened.label(), "Test vault");
    }

    #[test]
    fn every_save_uses_a_fresh_body_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();

        let mut seen = BTreeSet::new();
        for _ in 0..8 {
            vault.save().unwrap();
            let bytes = fs::read(&path).unwrap();
            let parsed = header::parse(&bytes).unwrap();
            assert!(seen.insert(parsed.body_nonce), "a body nonce repeated");
        }
    }

    #[test]
    fn recovery_opens_a_vault_whose_password_slot_was_destroyed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (mut vault, key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();

        vault.remove_slot(0).unwrap();
        vault.save().unwrap();
        vault.lock();

        assert!(matches!(
            open_test(&path),
            Err(UnlockError::NoSuchMethod(SlotKind::Password))
        ));

        let reopened = Vault::open(&path, UnlockMethod::recovery(key)).unwrap();
        assert_eq!(reopened.label(), "Test vault");
    }

    #[test]
    fn the_last_slot_cannot_be_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.remove_slot(1).unwrap();
        assert!(matches!(vault.remove_slot(0), Err(VaultError::LastSlot)));
    }

    #[test]
    fn a_tampered_header_byte_is_detected_after_the_slot_unwraps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.lock();

        // Flip a byte inside the label, which is covered by the MAC but is not
        // part of any slot's key derivation.
        let mut bytes = fs::read(&path).unwrap();
        let needle = b"Test vault";
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("the label must be in the plaintext header");
        bytes[at] = b'B';
        fs::write(&path, &bytes).unwrap();

        assert!(matches!(open_test(&path), Err(UnlockError::HeaderTampered)));
    }

    #[test]
    fn a_tampered_body_byte_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.lock();

        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();

        assert!(matches!(open_test(&path), Err(UnlockError::BodyCorrupt)));
    }

    #[test]
    fn probing_needs_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.lock();

        let info = Vault::probe(&path).unwrap();
        assert_eq!(info.label, "Test vault");
        assert_eq!(info.format_version, FORMAT_VERSION);
        assert_eq!(info.slots.len(), 2);
        assert_eq!(info.slots[0].kind, SlotKind::Password);
        assert!(info.slots[0].kdf_params.is_some());
        assert!(!info.slots[0].requires_keyfile);
        assert!(info.size_bytes > 0);
    }

    #[test]
    fn a_key_file_is_required_when_the_slot_was_made_with_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let keyfile = dir.path().join("acme.key");
        fs::write(&keyfile, b"a key file").unwrap();

        let (vault, _key) =
            Vault::create(test_options(dir.path(), "acme.rvault").with_keyfile(keyfile.clone()))
                .unwrap();
        vault.lock();

        assert!(matches!(open_test(&path), Err(UnlockError::NotUnlocked)));

        let opened = Vault::open(
            &path,
            UnlockMethod::password_with_keyfile(
                Secret::new(String::from("a master password")),
                keyfile,
            ),
        )
        .unwrap();
        assert_eq!(opened.label(), "Test vault");
        assert!(opened.slots()[0].requires_keyfile);
    }

    #[test]
    fn a_second_password_slot_opens_the_same_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();

        vault
            .add_password_slot(
                "Second password",
                &Secret::new(String::from("another password")),
                None,
                Some(KdfParams::low_cost_for_tests()),
            )
            .unwrap();
        vault.save().unwrap();
        vault.lock();

        let opened = Vault::open(
            &path,
            UnlockMethod::password(Secret::new(String::from("another password"))),
        )
        .unwrap();
        assert_eq!(opened.slots().len(), 3);
    }

    #[test]
    fn a_weak_parameter_set_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let weak = KdfParams {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            version: KdfParams::CURRENT_VERSION,
        };
        let opts = CreateOptions::new(
            dir.path().join("weak.rvault"),
            "Weak",
            Secret::new(String::from("pw")),
        )
        .with_kdf_params(weak);

        assert!(matches!(
            Vault::create(opts),
            Err(VaultError::KdfParamsTooWeak)
        ));
    }

    #[test]
    fn creating_over_an_existing_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        fs::write(&path, b"already here").unwrap();
        assert!(matches!(
            Vault::create(test_options(dir.path(), "acme.rvault")),
            Err(VaultError::Io { .. })
        ));
    }

    #[test]
    fn settings_and_search_work_through_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();

        vault.set_setting("theme", b"dark").unwrap();
        assert_eq!(
            vault.setting("theme").unwrap().as_deref(),
            Some(&b"dark"[..])
        );

        let mut tree = vault.tree().unwrap();
        let node = connection("web-01", "web-01.example.internal", 1_000);
        let id = *node.id.as_uuid();
        let patch = tree.insert(node).unwrap();
        vault.apply(&tree, &patch).unwrap();

        assert_eq!(vault.search("web", 10).unwrap(), vec![id]);
    }

    #[test]
    fn the_audit_log_records_the_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.lock();

        let vault = open_test(&path).unwrap();
        let events: Vec<String> = vault
            .audit_recent(50)
            .unwrap()
            .into_iter()
            .map(|(_, event, _, _)| event)
            .collect();
        assert!(events.iter().any(|e| e == "vault_created"));
        assert!(events.iter().any(|e| e == "vault_saved"));
        assert!(events.iter().any(|e| e == "vault_unlocked"));
    }

    /// Rebuilds a vault file around a mutated header. The MAC will not match
    /// afterwards, which is fine for every test here: they all assert on a
    /// refusal that happens before the MAC is reached.
    fn rewrite_header(path: &Path, mutate: impl FnOnce(&mut VaultHeader)) {
        let bytes = fs::read(path).unwrap();
        let parsed = header::parse(&bytes).unwrap();
        let mut header = parsed.header;
        mutate(&mut header);

        let encoded = header::encode(&header).unwrap();
        let (mac_input, _) = header::framing_for(&encoded).unwrap();

        let mut image = mac_input;
        image.extend_from_slice(&parsed.mac);
        image.extend_from_slice(&parsed.body_nonce);
        image.extend_from_slice(&parsed.body);
        fs::write(path, &image).unwrap();
    }

    #[test]
    fn a_rewritten_cost_parameter_is_refused_instead_of_exhausting_the_machine() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.lock();

        // What someone with write access to a shared folder can do: the cost
        // parameters are in the plaintext header, and the key that would
        // detect the edit is derived from the KDF output itself.
        rewrite_header(&path, |header| {
            header.kdf_params.m_cost = 64 * 1024 * 1024;
            let params = header.kdf_params;
            if let Some(slot) = header.slots_mut().first_mut() {
                slot.kdf_params = Some(params);
            }
        });

        let started = Instant::now();
        let error = open_test(&path).unwrap_err();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the refusal must precede the derivation, not follow it"
        );
        match error {
            UnlockError::Vault(VaultError::KdfParamsRefused { declared, .. }) => {
                assert_eq!(declared, 64 * 1024 * 1024);
            }
            other => panic!("expected KdfParamsRefused, got {other:?}"),
        }

        // Probing reads the same header, so it must refuse it too rather than
        // showing the file as ordinary.
        assert!(matches!(
            Vault::probe(&path),
            Err(VaultError::KdfParamsRefused { .. })
        ));
    }

    #[test]
    fn only_a_bounded_number_of_slots_of_one_kind_are_attempted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();

        // Slot 0 is the original password slot, so this makes five in all: one
        // more than an unlock will try.
        for n in 0..4 {
            vault
                .add_password_slot(
                    format!("Extra {n}"),
                    &Secret::new(format!("password {n}")),
                    None,
                    Some(KdfParams::low_cost_for_tests()),
                )
                .unwrap();
        }
        vault.save().unwrap();
        vault.lock();

        // The fourth extra is the fifth password slot in the table.
        assert!(matches!(
            Vault::open(
                &path,
                UnlockMethod::password(Secret::new(String::from("password 3"))),
            ),
            Err(UnlockError::NotUnlocked)
        ));
        // The ones within the bound still open.
        let opened = Vault::open(
            &path,
            UnlockMethod::password(Secret::new(String::from("password 2"))),
        )
        .unwrap();
        assert_eq!(opened.label(), "Test vault");
    }

    #[test]
    fn an_inherited_parameter_set_is_raised_to_the_floor() {
        // The vault itself is below the floor, as one written by an older
        // build would be. A credential minted now must not be.
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        assert!(vault.slots()[0].kdf_params.unwrap().is_below_floor());

        let index = vault
            .add_password_slot(
                "Inherited",
                &Secret::new(String::from("another password")),
                None,
                None,
            )
            .unwrap();

        let added = vault
            .slots()
            .into_iter()
            .find(|s| s.index == index)
            .unwrap();
        let params = added.kdf_params.unwrap();
        assert!(
            !params.is_below_floor(),
            "an inherited set must be clamped, got {params:?}"
        );
        assert_eq!(params.m_cost, KdfParams::FLOOR_M_COST);
        assert_eq!(params.t_cost, KdfParams::FLOOR_T_COST);
        assert_eq!(params.p_cost, KdfParams::FLOOR_P_COST);
    }

    #[test]
    fn a_password_opens_however_its_accents_were_composed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let precomposed = "\u{00E9}t\u{00E9} 2026 passphrase";
        let decomposed = "e\u{0301}te\u{0301} 2026 passphrase";
        assert_ne!(precomposed.as_bytes(), decomposed.as_bytes());

        let (vault, _key) = Vault::create(
            CreateOptions::new(&path, "Accented", Secret::new(String::from(precomposed)))
                .with_kdf_params(KdfParams::low_cost_for_tests()),
        )
        .unwrap();
        vault.lock();

        let opened = Vault::open(
            &path,
            UnlockMethod::password(Secret::new(String::from(decomposed))),
        )
        .unwrap();
        assert_eq!(opened.label(), "Accented");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_save_is_logged_as_a_failure_and_leaves_modified_at_alone() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _key) = Vault::create(test_options(dir.path(), "acme.rvault")).unwrap();
        vault.save().unwrap();
        let before = vault.info().modified_at;

        // Take away the right to create the temporary image.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let writable_anyway = fs::write(dir.path().join("probe"), b"x").is_ok();
        if writable_anyway {
            // Running with a privilege that ignores the mode; nothing to test.
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        let failed = vault.save();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(failed, Err(VaultError::Io { .. })));

        assert_eq!(
            vault.info().modified_at,
            before,
            "the file on disk is still the old one, so modified_at must be too"
        );

        let last_save = vault
            .audit_recent(50)
            .unwrap()
            .into_iter()
            .find(|(_, event, _, _)| event == "vault_saved")
            .unwrap();
        assert_eq!(
            last_save.2, "failure",
            "the log must not assert a save that never reached the disk"
        );
    }

    #[test]
    fn the_backup_count_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synced.rvault");
        let (mut vault, _key) = Vault::create(
            CreateOptions::new(&path, "In a synced folder", Secret::new(String::from("pw")))
                .with_kdf_params(KdfParams::low_cost_for_tests())
                .with_backup_count(0),
        )
        .unwrap();
        assert_eq!(vault.backup_count(), 0);
        vault.save().unwrap();
        vault.lock();

        let mut reopened =
            Vault::open(&path, UnlockMethod::password(Secret::new("pw".into()))).unwrap();
        assert_eq!(
            reopened.backup_count(),
            0,
            "a user who turned backups off must not get three of them next session"
        );
        reopened.save().unwrap();
        assert!(!sibling(&path, ".bak.1").exists());
        assert!(reopened.info().backups.is_empty());
    }

    #[test]
    fn a_non_default_backup_count_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.rvault");
        let (vault, _key) = Vault::create(
            CreateOptions::new(&path, "Two backups", Secret::new(String::from("pw")))
                .with_kdf_params(KdfParams::low_cost_for_tests())
                .with_backup_count(2),
        )
        .unwrap();
        vault.lock();

        let reopened =
            Vault::open(&path, UnlockMethod::password(Secret::new("pw".into()))).unwrap();
        assert_eq!(reopened.backup_count(), 2);
    }

    /// The restriction check is only as good as this mapping: whatever
    /// `protocol_for` answers is the protocol the credential is asked to
    /// permit. A purpose that resolved to the wrong protocol would refuse a
    /// correctly restricted credential — and, in the other direction, ask the
    /// wrong question of the restriction the user wrote.
    #[test]
    fn every_connection_purpose_names_its_own_protocol() {
        for (purpose, protocol) in [
            (Purpose::SshPassword, "ssh"),
            (Purpose::SshPrivateKey, "ssh"),
            (Purpose::RdpCredentials, "rdp"),
            (Purpose::VncPassword, "vnc"),
            (Purpose::SftpPassword, "sftp"),
            // A key for a file pane is an SSH key, but the restriction it is
            // checked against says `sftp`.
            (Purpose::SftpPrivateKey, "sftp"),
            (Purpose::FtpPassword, "ftp"),
        ] {
            assert_eq!(
                protocol_for(purpose).map(|id| id.as_str().to_owned()),
                Some(String::from(protocol)),
                "{purpose:?} resolved to the wrong protocol"
            );
        }

        // Neither is a connection, so neither is checked against a protocol
        // restriction at all.
        assert_eq!(protocol_for(Purpose::Reveal), None);
        assert_eq!(protocol_for(Purpose::Export), None);
    }

    #[test]
    fn calibration_never_goes_below_the_floor() {
        // The real cost, run once, so the floor path is exercised for real
        // rather than only through the test parameter set.
        let params = Vault::calibrate_kdf().unwrap();
        assert!(!params.is_below_floor());
        assert!(params.m_cost >= KdfParams::FLOOR_M_COST);
        assert!(params.m_cost <= KdfParams::CALIBRATION_MAX_M_COST);
    }
}
