//! Confirming the vault's password while the vault is already open.
//!
//! Showing a stored password on screen is gated on the person at the keyboard
//! proving they know the vault's password, not merely on the vault being open:
//! an unlocked vault on an unattended screen is exactly the case
//! `docs/security/threat-model.md` T7 is about. That proof costs one Argon2id
//! derivation per password slot tried — a deliberate second or so of CPU — and
//! holding the vault for that long holds every command that needs it.
//!
//! So the check comes in two halves. [`crate::Vault::password_check`] copies out
//! what the check needs, cheaply, under whatever lock guards the vault.
//! [`PasswordCheck::verify`] spends the KDF time afterwards, with the vault
//! released.
//!
//! What is copied is the public half of each password slot — salt, parameters,
//! wrapped key, all of which are in the file in the clear — and a keyed BLAKE3
//! commitment to the vault master key. Never the master key itself: a check
//! that outlives the vault's lock, or is moved to another thread, must not be a
//! second copy of the key that opens everything.

use std::fmt;
use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN, MAC_LEN};
use crate::error::VaultError;
use crate::header::KeySlot;
use crate::secret::{ExposeSecret as _, Secret};
use crate::slots;

/// Domain separation for the commitment, so it can never be mistaken for —
/// or substituted by — any other keyed hash the vault computes under its
/// master key.
const COMMITMENT_CONTEXT: &[u8] = b"remoter/v1/password-check-commitment";

/// The most password slots one verification derives a key for.
///
/// The same cap an unlock uses (`MAX_KDF_SLOT_ATTEMPTS` in `vault.rs`), and for
/// the same reason seen from the other side: every slot tried is another full
/// Argon2id run, and a confirmation that takes sixteen of them is a frozen
/// dialog rather than a security property.
const MAX_SLOTS_TRIED: usize = 4;

/// What it takes to ask "is this the password of the vault that is open?",
/// without the vault.
///
/// Made by [`crate::Vault::password_check`]. Cheap to make; expensive to
/// [`verify`](Self::verify) against, by design.
pub struct PasswordCheck {
    /// The vault's password slots, in table order. Public data: these are the
    /// same bytes the file carries in its header.
    slots: Vec<KeySlot>,
    /// `BLAKE3-keyed(VMK, COMMITMENT_CONTEXT)`. Zeroed on drop.
    commitment: Zeroizing<[u8; MAC_LEN]>,
}

impl PasswordCheck {
    pub(crate) fn new(slots: Vec<KeySlot>, vmk: &[u8; KEY_LEN]) -> Self {
        Self {
            slots,
            commitment: Zeroizing::new(crypto::keyed_mac(vmk, COMMITMENT_CONTEXT)),
        }
    }

    /// Whether the vault has any password slot at all.
    ///
    /// A vault opened with its recovery key or this machine's keychain may have
    /// none, and then no password can ever confirm anything. That is a
    /// different sentence for the user from "that password is wrong".
    #[must_use]
    pub fn has_password_slot(&self) -> bool {
        !self.slots.is_empty()
    }

    /// Whether `password` opens one of the vault's password slots.
    ///
    /// A slot created with a key file needs one, and `keyfile` is offered to
    /// those slots only; a slot without one is tried with the password alone.
    /// Passing the key file to every slot would make a password-only slot
    /// refuse the right password, because the file's digest is part of the
    /// key-encryption key's input.
    ///
    /// A key file that cannot be read makes the slots that need it fail to
    /// match rather than failing the whole check. Every slot that does not need
    /// it is still tried.
    ///
    /// # Errors
    ///
    /// Only a slot the header cannot describe — a malformed salt — or a KDF
    /// failure that is not about the key file. A wrong password is `Ok(false)`.
    pub fn verify(
        &self,
        password: &Secret<String>,
        keyfile: Option<&Path>,
    ) -> Result<bool, VaultError> {
        for slot in self.slots.iter().take(MAX_SLOTS_TRIED) {
            let Some(params) = slot.kdf_params else {
                continue;
            };
            let needs_keyfile = slot
                .extra
                .as_ref()
                .and_then(|extra| extra.requires_keyfile)
                .unwrap_or(false);
            let keyfile = match (needs_keyfile, keyfile) {
                (true, Some(path)) => Some(path),
                (true, None) => continue,
                (false, _) => None,
            };
            let salt = slot.salt_array()?;
            let kek = match slots::password_kek(
                password.expose_secret(),
                slots::normalisation_of(slot),
                keyfile,
                &salt,
                &params,
            ) {
                Ok(kek) => kek,
                Err(VaultError::Keyfile) => continue,
                Err(other) => return Err(other),
            };
            let Ok(vmk) = slots::unwrap_vmk(&kek, slot) else {
                continue;
            };
            let candidate = Zeroizing::new(crypto::keyed_mac(&vmk, COMMITMENT_CONTEXT));
            if crypto::ct_eq(candidate.as_slice(), self.commitment.as_slice()) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl fmt::Debug for PasswordCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordCheck")
            .field("password_slots", &self.slots.len())
            .field("commitment", &"<redacted>")
            .finish()
    }
}
