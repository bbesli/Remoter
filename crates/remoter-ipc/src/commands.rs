//! The commands themselves.
//!
//! Each one is a thin mapping: parse the DTO, take the state lock, call
//! `remoter-vault` or `remoter-core`, map the result back. The decisions live
//! one layer down; what lives here is the translation and the failure text.
//!
//! **No command returns a secret.** A password, a private key, a passphrase or
//! a decrypted field never appears in a return value. The one thing that
//! crosses outward is the recovery key at vault creation, which exists only to
//! be shown once and is documented as such in `dto.rs`. Secrets travelling the
//! other way — a password being stored — are wrapped in `Secret<_>` on arrival
//! so they are zeroized when the command returns.
//!
//! Mutations write the vault immediately. `Vault::save` is atomic and rotates
//! the backups, so the alternative — batching writes and flushing later —
//! would trade a guarantee for a saving nobody asked for.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use remoter_core::{
    ConnectionProps, CredentialProps, CredentialRef, EffectiveConnection, GatewayChain, Inherited,
    KeyFormat, Node, NodeId, NodeKind, NodeRef, Provenance, ReconnectPolicy, RecordingPolicy,
    SecretKind, Tag, Tree, TreePatch, validate_port,
};
use remoter_vault::{
    AuditEvent, AuditOutcome, CreateOptions, ExposeSecret as _, ImportedKey, RecoveryKey, Secret,
    SlotInfo, UnlockError, UnlockMethod, Vault, VaultInfo, agent_credential,
    private_key_credential,
};
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::dto::{
    AppSettingsDto, BackupDto, CreateNodeDto, CreateVaultRequestDto, CreateVaultResultDto,
    CredentialInputDto, EffectiveConnectionDto, NodeDto, PasswordStrengthDto, PrivateKeyInfoDto,
    RecentVaultDto, ResolvedFieldDto, SearchHitDto, ShortcutDto, SlotDto, UnlockRequestDto,
    UpdateCheckDto, UpdateNodeDto, UpdateReleaseDto, VaultProbeDto, VaultStateDto,
};
use crate::error::IpcError;
use crate::recents::{Recents, sync_warning};
use crate::state::{AppSettingsPatch, AppState, now_millis, now_seconds};

/// How many search hits a single query returns. The palette shows far fewer;
/// the surplus is there so ranking has something to rank.
const SEARCH_LIMIT: usize = 50;

/// Bytes in a generated key file. 64 bytes of CSPRNG output is well past the
/// 256-bit key it feeds; the file is a second factor, not a passphrase, so
/// there is no reason to be frugal.
const KEYFILE_BYTES: usize = 64;

/// Bounds on a generated passphrase. Fewer than four words is not a passphrase;
/// past sixteen the user stops being able to transcribe it.
const MIN_PASSPHRASE_WORDS: usize = 4;
const MAX_PASSPHRASE_WORDS: usize = 16;

/// The longest word on the list, checked against it by a test. It sizes the
/// passphrase buffer, which must be allocated once and never grown.
const MAX_WORD_LEN: usize = 7;

/// Stands in if an index somehow lands outside the list — it cannot, but the
/// alternative is an `unwrap`. Sized to fit inside [`MAX_WORD_LEN`].
const FALLBACK_WORD: &str = "remoter";

/// Entropy at or above which a master password is accepted. Sixty bits is
/// roughly a five-word passphrase from the list below, and is the point at
/// which Argon2id at the format's cost floor puts an offline attack out of
/// reach of anything short of a state.
pub(crate) const ACCEPTABLE_ENTROPY_BITS: f64 = 60.0;

// =========================================================== vault lifecycle

/// The vaults this machine has opened, each probed for reachability.
#[tauri::command]
pub(crate) fn vault_list_recent(
    state: State<'_, AppState>,
) -> Result<Vec<RecentVaultDto>, IpcError> {
    vault_list_recent_impl(&state)
}

fn vault_list_recent_impl(state: &AppState) -> Result<Vec<RecentVaultDto>, IpcError> {
    Ok(state.lock().recents().to_dtos())
}

/// Forgets one remembered vault. Does not touch the file.
#[tauri::command]
pub(crate) fn vault_forget_recent(
    state: State<'_, AppState>,
    path: String,
) -> Result<(), IpcError> {
    vault_forget_recent_impl(&state, path)
}

fn vault_forget_recent_impl(state: &AppState, path: String) -> Result<(), IpcError> {
    state.lock().update_recents(|recents| {
        recents.forget(&path);
    })
}

/// Forgets all of them.
#[tauri::command]
pub(crate) fn vault_clear_recents(state: State<'_, AppState>) -> Result<(), IpcError> {
    vault_clear_recents_impl(&state)
}

fn vault_clear_recents_impl(state: &AppState) -> Result<(), IpcError> {
    state.lock().update_recents(Recents::clear)
}

/// What a vault file says about itself, without any key.
#[tauri::command]
pub(crate) fn vault_probe(
    state: State<'_, AppState>,
    path: String,
) -> Result<VaultProbeDto, IpcError> {
    vault_probe_impl(&state, path)
}

fn vault_probe_impl(state: &AppState, path: String) -> Result<VaultProbeDto, IpcError> {
    let path = PathBuf::from(path);
    let subject = path.display().to_string();
    let info = Vault::probe(&path).map_err(|err| IpcError::from_vault(&err, &subject))?;
    let remembered_keyfile = state.lock().recents_keyfile_for(&subject);
    Ok(probe_dto(&path, info, remembered_keyfile))
}

/// Creates a vault and opens it.
///
/// Returns the recovery key exactly once. Nothing in the file can reproduce it
/// afterwards, which is why the interface gates the next step behind a
/// transcription check on the group named here.
#[tauri::command]
pub(crate) fn vault_create(
    state: State<'_, AppState>,
    req: CreateVaultRequestDto,
) -> Result<CreateVaultResultDto, IpcError> {
    vault_create_impl(&state, req)
}

pub(crate) fn vault_create_impl(
    state: &AppState,
    req: CreateVaultRequestDto,
) -> Result<CreateVaultResultDto, IpcError> {
    let CreateVaultRequestDto {
        path,
        label,
        password,
        keyfile_path,
        generate_keyfile_at,
    } = req;

    // The password becomes a `Secret` before anything fallible runs, so every
    // early return below unwinds through its `Drop` rather than dropping the
    // plaintext `String` on the heap unwiped.
    let password = Secret::new(password);
    let path = PathBuf::from(path);
    let label = label.trim().to_owned();

    if label.is_empty() {
        return Err(IpcError::new("vault.label-empty", "A vault needs a name.")
            .with_actions(["Type a name for this vault"]));
    }
    if password.expose_secret().is_empty() {
        return Err(IpcError::new(
            "vault.password-empty",
            "A vault needs a master password. Nothing else can be derived without one.",
        )
        .with_actions(["Type a password", "Generate a passphrase"]));
    }

    // The entropy gate lives here rather than in the wizard because it is a
    // security decision: `docs/security/threat-model.md` T1 names it as the
    // answer to the residual risk of a weak master password, and a check that
    // only exists in the interface is a check a different caller skips.
    let strength = estimate_strength(password.expose_secret());
    if !strength.acceptable {
        return Err(IpcError::new(
            "vault.password-too-weak",
            format!(
                "That master password is too easy to guess. {} \
                 Argon2id raises the cost of every guess, but it cannot rescue a \
                 password an attacker tries early.",
                strength.explanation
            ),
        )
        .with_actions([
            "Generate a passphrase",
            "Use a longer, less predictable password",
        ]));
    }

    if path.exists() {
        return Err(IpcError::bad_path(
            &path,
            "a file already exists there, and creating a vault never overwrites one",
        ));
    }

    let keyfile = match generate_keyfile_at.as_deref() {
        Some(target) => {
            let target = PathBuf::from(target);
            write_keyfile(&target)?;
            Some(target)
        }
        None => keyfile_path.as_deref().map(PathBuf::from),
    };

    // Kept for the recents entry: the unlock screen offers this path back
    // rather than making the user find the file again in a folder where the
    // vault itself is the more obvious pick.
    let remembered_keyfile = keyfile.as_ref().map(|p: &PathBuf| p.display().to_string());

    let mut options = CreateOptions::new(&path, label.clone(), password);
    if let Some(keyfile) = keyfile {
        if !keyfile.is_file() {
            return Err(IpcError::bad_path(
                &keyfile,
                "there is no file there to use as a key file",
            ));
        }
        options = options.with_keyfile(keyfile);
    }

    let (vault, recovery) = Vault::create(options)
        .map_err(|err| IpcError::from_vault(&err, &path.display().to_string()))?;

    // `groups` stays in the zeroizing buffer `RecoveryKey::groups` returns for
    // the rest of this function. The recovery key permanently unlocks the
    // vault, and `docs/security/vault-format.md` says it is never stored in
    // plaintext anywhere; the one copy that escapes is made in the returned
    // DTO below, after every step that could fail has succeeded.
    let groups = recovery
        .groups()
        .map_err(|err| IpcError::from_vault(&err, "the new vault"))?;
    drop(recovery);

    let confirm_group_index =
        usize::try_from(uniform_below(u32::try_from(groups.len()).unwrap_or(1))?).unwrap_or(0);
    let kdf_summary = kdf_summary(&vault.info());
    let slots = slot_kinds(&vault);

    let mut guard = state.lock();
    guard.open_vault(vault);
    remember(&mut guard, &path, &label, slots, remembered_keyfile);

    Ok(CreateVaultResultDto {
        path: path.display().to_string(),
        recovery_key_groups: groups.to_vec(),
        confirm_group_index,
        kdf_summary,
    })
}

/// Opens a vault.
///
/// A failure that happens before a key slot unwraps is reported as exactly
/// "That did not unlock the vault." — see `error.rs`. The corrupt-file cases
/// carry their own codes so the interface can offer the backups.
#[tauri::command]
pub(crate) fn vault_unlock(
    state: State<'_, AppState>,
    path: String,
    method: UnlockRequestDto,
) -> Result<VaultStateDto, IpcError> {
    vault_unlock_impl(&state, path, method)
}

pub(crate) fn vault_unlock_impl(
    state: &AppState,
    path: String,
    method: UnlockRequestDto,
) -> Result<VaultStateDto, IpcError> {
    let path = PathBuf::from(path);
    let subject = path.display().to_string();

    // The backoff `docs/security/vault-format.md` requires. Its target is the
    // shoulder surfer at the keyboard, not the offline attacker — who has the
    // file and ignores this code entirely — so it delays and never locks the
    // user out of their own data.
    state.lock().check_unlock_allowed(&path)?;

    // Captured before the method is consumed. Only a password unlock carries a
    // key file; the other methods leave the remembered path alone rather than
    // clearing it, because "unlocked with the recovery key today" is not
    // evidence that the key file has stopped being the usual way in.
    let used_keyfile = match &method {
        UnlockRequestDto::Password { keyfile_path, .. } => Some(keyfile_path.clone()),
        UnlockRequestDto::Recovery { .. } | UnlockRequestDto::Keychain => None,
    };

    let method = unlock_method(method, &subject)?;

    let mut vault = match Vault::open(&path, method) {
        Ok(vault) => vault,
        Err(err) => {
            // Only a slot that refused to unwrap counts as an attempt. A
            // corrupt header or an unreadable file is not someone guessing.
            if matches!(err, UnlockError::NotUnlocked) {
                state.lock().record_unlock_failure(&path);
            }
            return Err(IpcError::from_unlock(&err, &subject));
        }
    };

    let failures = state.lock().clear_unlock_failures(&path);
    if failures > 0 {
        // The vault's own audit table is unreachable while the unlock is
        // failing — nothing is decrypted yet — so the attempts are counted in
        // memory and written here, on the first unlock that succeeds. The
        // detail is a count, never anything that was typed.
        let detail = format!("{failures} consecutive attempts failed before this unlock");
        if let Err(err) = vault.audit(
            AuditEvent::VaultUnlockFailed,
            AuditOutcome::Failure,
            Some(&detail),
        ) {
            tracing::warn!("the failed unlock attempts could not be recorded: {err}");
        } else if let Err(err) = vault.save() {
            tracing::warn!("the failed unlock attempts could not be written: {err}");
        }
    }

    let label = vault.label().to_owned();
    let slots = slot_kinds(&vault);
    let kdf_upgrade_available = vault.kdf_upgrade_available();
    let connection_count = vault
        .connection_count()
        .map_err(|err| IpcError::from_vault(&err, &subject))?;
    let credential_count = vault
        .credential_count()
        .map_err(|err| IpcError::from_vault(&err, &subject))?;

    let mut guard = state.lock();
    let keyfile_to_remember = match used_keyfile {
        Some(chosen) => chosen,
        None => guard.recents_keyfile_for(&subject),
    };
    guard.open_vault(vault);
    remember(&mut guard, &path, &label, slots, keyfile_to_remember);

    Ok(VaultStateDto {
        unlocked: true,
        path: Some(subject),
        label: Some(label),
        connection_count,
        credential_count,
        locks_in_seconds: guard.locks_in_seconds(),
        kdf_upgrade_available,
    })
}

/// Closes the vault and wipes its keys.
///
/// The keys go whatever happens: a lock that could be refused is not a lock.
/// A write that fails on the way out is still reported, because "locked" reads
/// as "saved" and losing the session's changes silently is worse than an error
/// the user can act on — a network share that dropped, most often.
#[tauri::command]
pub(crate) fn vault_lock(state: State<'_, AppState>) -> Result<(), IpcError> {
    vault_lock_impl(&state)
}

pub(crate) fn vault_lock_impl(state: &AppState) -> Result<(), IpcError> {
    let mut guard = state.lock();

    let failure = guard.save_before_locking();
    guard.close_vault();
    match failure {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Whether a vault is open, and how long until it locks itself.
#[tauri::command]
pub(crate) fn vault_state(state: State<'_, AppState>) -> Result<VaultStateDto, IpcError> {
    vault_state_impl(&state)
}

fn vault_state_impl(state: &AppState) -> Result<VaultStateDto, IpcError> {
    let mut guard = state.lock();
    guard.enforce_auto_lock();

    // An auto-lock that could not write the vault first has nobody to return
    // an error to, so it leaves one here for this poll to carry. Reported once
    // — the next poll returns the state as usual.
    if let Some(failure) = guard.take_lock_failure() {
        return Err(failure);
    }

    let Some(vault) = guard.vault_peek() else {
        return Ok(VaultStateDto {
            unlocked: false,
            path: None,
            label: None,
            connection_count: 0,
            credential_count: 0,
            locks_in_seconds: None,
            kdf_upgrade_available: false,
        });
    };

    let subject = vault.path().display().to_string();
    let label = vault.label().to_owned();
    let kdf_upgrade_available = vault.kdf_upgrade_available();
    let connection_count = vault
        .connection_count()
        .map_err(|err| IpcError::from_vault(&err, &subject))?;
    let credential_count = vault
        .credential_count()
        .map_err(|err| IpcError::from_vault(&err, &subject))?;

    Ok(VaultStateDto {
        unlocked: true,
        path: Some(subject),
        label: Some(label),
        connection_count,
        credential_count,
        locks_in_seconds: guard.locks_in_seconds(),
        kdf_upgrade_available,
    })
}

/// Re-derives the password slots that are below the current cost floor.
///
/// `docs/security/vault-format.md` promises this offer "on the next successful
/// unlock"; [`VaultStateDto::kdf_upgrade_available`] is the offer and this is
/// the acceptance. The password is needed again because a slot is re-wrapped
/// around the credential, not around the key already in memory.
///
/// Returns whether anything was upgraded.
#[tauri::command]
pub(crate) fn vault_upgrade_kdf(
    state: State<'_, AppState>,
    method: UnlockRequestDto,
) -> Result<bool, IpcError> {
    vault_upgrade_kdf_impl(&state, method)
}

fn vault_upgrade_kdf_impl(state: &AppState, method: UnlockRequestDto) -> Result<bool, IpcError> {
    // Wrapped before the lock is taken, as everywhere else a password arrives.
    let method = unlock_method(method, "this vault")?;

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let subject = vault.path().display().to_string();

    if !vault.kdf_upgrade_available() {
        return Ok(false);
    }
    let upgraded = vault
        .upgrade_kdf(&method)
        .map_err(|err| IpcError::from_vault(&err, &subject))?;
    if !upgraded {
        // The vault is already open, so naming the cause here tells an
        // attacker nothing they could not already do: the pre-unlock rule in
        // `error.rs` is about failures *before* a slot unwraps.
        return Err(IpcError::new(
            "vault.kdf-upgrade-refused",
            "That does not open the slot that needs strengthening, so the slot was left \
             exactly as it was.",
        )
        .with_actions([
            "Enter the password this vault was created with",
            "Leave it for now — the vault still opens",
        ]));
    }
    Ok(true)
}

// ==================================================== vault creation helpers

/// A Diceware-style passphrase from the embedded word list.
///
/// Each word is drawn independently from [`WORDS`] with rejection sampling, so
/// every word is equally likely — the modulo shortcut would quietly favour the
/// front of the list, and a generator that is subtly non-uniform is worse than
/// no generator at all.
#[tauri::command]
pub(crate) fn generate_passphrase(words: usize) -> Result<String, IpcError> {
    // One copy leaves this function, because the interface has to show the
    // suggestion. The buffer it was built in is wiped on the way out.
    Ok(build_passphrase(words)?.to_string())
}

/// The passphrase in a buffer that is wiped when it drops.
///
/// The capacity is reserved up front so the buffer never reallocates: a
/// `String` that grows leaves each partial passphrase behind in freed heap,
/// and those partials are most of the secret.
fn build_passphrase(words: usize) -> Result<Zeroizing<String>, IpcError> {
    if !(MIN_PASSPHRASE_WORDS..=MAX_PASSPHRASE_WORDS).contains(&words) {
        return Err(IpcError::invalid_request(
            "words",
            format!(
                "a passphrase is between {MIN_PASSPHRASE_WORDS} and {MAX_PASSPHRASE_WORDS} words"
            ),
        ));
    }

    let list_len = u32::try_from(WORDS.len()).unwrap_or(u32::MAX);

    // A generator that hands the user something `vault_create` then refuses is
    // worse than no generator: it makes the application look broken, and the
    // person reasonably concludes the strength gate is arbitrary. So the word
    // count is raised until the phrase clears the same bar the gate applies.
    //
    // Derived from the real list rather than a constant, so shortening or
    // extending WORDS cannot silently reintroduce the contradiction.
    let words = enough_words_for_the_gate(words, WORDS.len());

    let mut phrase = Zeroizing::new(String::with_capacity(passphrase_capacity(words)));
    for index in 0..words {
        if index > 0 {
            phrase.push('-');
        }
        let pick = usize::try_from(uniform_below(list_len)?).unwrap_or(0);
        phrase.push_str(WORDS.get(pick).copied().unwrap_or(FALLBACK_WORD));
    }
    Ok(phrase)
}

/// Bytes that `words` words and their separators can never exceed.
const fn passphrase_capacity(words: usize) -> usize {
    words * (MAX_WORD_LEN + 1)
}

/// The smallest word count at or above `requested` whose entropy clears
/// [`ACCEPTABLE_ENTROPY_BITS`], capped at [`MAX_PASSPHRASE_WORDS`].
///
/// With a 2,048-word list each word is worth 11 bits, so five words is 55 —
/// under the 60-bit gate. The generator asked for five and produced something
/// the vault then declined to be created with.
fn enough_words_for_the_gate(requested: usize, list_len: usize) -> usize {
    if list_len < 2 {
        return requested;
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "the word list is a few thousand entries; f64 is exact well past that"
    )]
    let bits_per_word = (list_len as f64).log2();
    let mut words = requested;
    while words < MAX_PASSPHRASE_WORDS {
        #[expect(
            clippy::cast_precision_loss,
            reason = "words is bounded by MAX_PASSPHRASE_WORDS"
        )]
        let bits = words as f64 * bits_per_word;
        if bits >= ACCEPTABLE_ENTROPY_BITS {
            break;
        }
        words += 1;
    }
    words
}

/// Estimates a password's strength and says what it means.
///
/// This is **not** zxcvbn: it scores length, character variety, a small list of
/// the passwords that turn up first in every breach corpus, and the shape of a
/// generated passphrase. That is enough to separate "this will be guessed" from
/// "this will not", which is the only decision the number drives. A bit count
/// on its own changes nobody's behaviour, so the sentence is the point.
#[tauri::command]
pub(crate) fn password_strength(password: String) -> Result<PasswordStrengthDto, IpcError> {
    // Wrapped even though it is only measured: it is a password, and the
    // wrapper is what zeroizes it when this command returns.
    let password = Secret::new(password);
    Ok(estimate_strength(password.expose_secret()))
}

/// Writes a random key file.
#[tauri::command]
pub(crate) fn generate_keyfile(path: String) -> Result<(), IpcError> {
    write_keyfile(Path::new(&path))
}

/// A path to offer for a new vault, based on its name.
#[tauri::command]
pub(crate) fn suggest_vault_path(
    state: State<'_, AppState>,
    label: String,
) -> Result<String, IpcError> {
    suggest_vault_path_impl(&state, label)
}

fn suggest_vault_path_impl(state: &AppState, label: String) -> Result<String, IpcError> {
    let stem = slugify(&label);
    let directory = directories::UserDirs::new()
        .and_then(|dirs| dirs.document_dir().map(Path::to_path_buf))
        .unwrap_or_else(|| state.lock().config_dir().to_path_buf());

    let mut candidate = directory.join(format!("{stem}.rvault"));
    // Never propose a path that would overwrite something. The create command
    // refuses an existing file anyway; suggesting one would just be rude.
    let mut suffix = 2u32;
    while candidate.exists() && suffix < 100 {
        candidate = directory.join(format!("{stem}-{suffix}.rvault"));
        suffix += 1;
    }

    Ok(candidate.display().to_string())
}

// ===================================================================== tree

/// Every live node, in tree order.
#[tauri::command]
pub(crate) fn tree_list(state: State<'_, AppState>) -> Result<Vec<NodeDto>, IpcError> {
    tree_list_impl(&state)
}

pub(crate) fn tree_list_impl(state: &AppState) -> Result<Vec<NodeDto>, IpcError> {
    let mut guard = state.lock();
    let vault = guard.vault_ref()?;
    let tree = read_tree(vault)?;
    let counts = inheritance_counts(&tree);

    let mut out = Vec::with_capacity(tree.len());
    push_subtree(&tree, None, &counts, &mut out);
    Ok(out)
}

/// Full-text search over names, descriptions, hosts and tags. Never over a
/// secret field: the index does not contain one.
#[tauri::command]
pub(crate) fn tree_search(
    state: State<'_, AppState>,
    query: String,
) -> Result<Vec<SearchHitDto>, IpcError> {
    tree_search_impl(&state, query)
}

fn tree_search_impl(state: &AppState, query: String) -> Result<Vec<SearchHitDto>, IpcError> {
    let mut guard = state.lock();
    let vault = guard.vault_ref()?;

    let hits = vault
        .search(&query, SEARCH_LIMIT)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    let tree = read_tree(vault)?;
    let counts = inheritance_counts(&tree);

    let total = i64::try_from(hits.len()).unwrap_or(i64::MAX);
    let mut out = Vec::with_capacity(hits.len());
    for (rank, id) in hits.into_iter().enumerate() {
        let id = NodeId::from_uuid(id);
        let Some(node) = tree.get(id) else {
            continue;
        };
        // A credential attached to a connection is part of that connection, not
        // a result of its own: it carries the connection's name, so every hit
        // would otherwise arrive twice.
        if is_attached_credential(node) {
            continue;
        }
        out.push(SearchHitDto {
            node: node_dto(&tree, node, &counts),
            path: breadcrumb(&tree, id),
            name_matches: match_ranges(&node.name, &query),
            subtitle: subtitle(&tree, node),
            score: total - i64::try_from(rank).unwrap_or(0),
        });
    }
    Ok(out)
}

/// Adds a node.
#[tauri::command]
pub(crate) fn node_create(
    state: State<'_, AppState>,
    input: CreateNodeDto,
) -> Result<NodeDto, IpcError> {
    let mut input = input;
    node_create_impl(&state, &mut input)
}

/// Takes the request by reference so the password can be moved out of it
/// before anything fallible runs; the test below asserts that it was.
pub(crate) fn node_create_impl(
    state: &AppState,
    input: &mut CreateNodeDto,
) -> Result<NodeDto, IpcError> {
    // First act, before any early return: every plaintext buffer moves into a
    // `Secret`, which zeroizes it however this function ends. The vault can
    // auto-lock between the user pressing Save and the lock being taken, and
    // that path used to drop the plaintext on the heap unwiped.
    let material = take_credential(input.password.take(), input.credential.take())?;

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let mut tree = read_tree(vault)?;

    let parent = match input.parent_id.as_deref() {
        Some(id) => Some(parse_node_id(id, "parentId")?),
        None => None,
    };
    if let Some(parent_id) = parent {
        let Some(parent_node) = tree.get(parent_id) else {
            return Err(IpcError::from_core(
                &remoter_core::CoreError::ParentNotFound(parent_id),
            ));
        };
        if !parent_node.kind.is_container() {
            return Err(IpcError::from_core(
                &remoter_core::CoreError::NotAContainer(parent_id),
            ));
        }
    }

    let identity_edit =
        input.kind == "connection" && is_identity_edit(input.username.as_ref(), &material);
    if identity_edit && input.credential_id.is_some() {
        return Err(identity_conflicts_with_reference());
    }

    let kind = build_kind(input, &material)?;
    let now = now_millis();
    let sort_order = next_sort_order(&tree, parent);

    let mut node = Node::new(kind, std::mem::take(&mut input.name), now);
    node.sort_order = sort_order;
    if let Some(parent_id) = parent {
        node = node.under(parent_id, sort_order);
    }
    let id = node.id;

    if let Some(credential_id) = input.credential_id.as_deref() {
        attach_credential(&mut node.kind, &tree, credential_id, id)?;
    }

    // A username or a secret on a new connection becomes a credential of its
    // own, created here so that the connection is saved already pointing at it.
    let mut patch = TreePatch::default();
    let identity = if identity_edit {
        route_identity(
            &mut tree,
            &mut node,
            input.username.as_deref(),
            &material,
            false,
            now,
            &mut patch,
        )?
    } else {
        IdentityOutcome {
            credential: None,
            change: None,
        }
    };

    merge_patch(
        &mut patch,
        tree.insert(node).map_err(|err| IpcError::from_core(&err))?,
    );
    vault
        .apply(&tree, &patch)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;

    // Onto the credential when the connection was given one of its own,
    // otherwise onto the node itself — which is the credential, when one is
    // what was created.
    let target = identity.credential.unwrap_or(id);
    store_credential(vault, *target.as_uuid(), material)?;
    save(vault)?;

    let counts = inheritance_counts(&tree);
    tree.get(id)
        .map(|node| node_dto(&tree, node, &counts).with_credential_change(identity.change))
        .ok_or_else(|| IpcError::from_core(&remoter_core::CoreError::NodeNotFound(id)))
}

/// Edits a node.
#[tauri::command]
pub(crate) fn node_update(
    state: State<'_, AppState>,
    id: String,
    patch: UpdateNodeDto,
) -> Result<NodeDto, IpcError> {
    let mut patch = patch;
    node_update_impl(&state, id, &mut patch)
}

/// Takes the patch by reference so the password can be moved out of it before
/// anything fallible runs; the test below asserts that it was.
fn node_update_impl(
    state: &AppState,
    id: String,
    patch: &mut UpdateNodeDto,
) -> Result<NodeDto, IpcError> {
    // First act, as in `node_create_impl`. Six fallible steps follow — the
    // plainest being the vault auto-locking as the user presses Save — and
    // each of them used to drop the new password unwiped.
    let material = take_credential(patch.password.take(), patch.credential.take())?;

    let id = parse_node_id(&id, "id")?;
    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let mut tree = read_tree(vault)?;

    let mut node = tree
        .get(id)
        .cloned()
        .ok_or_else(|| IpcError::from_core(&remoter_core::CoreError::NodeNotFound(id)))?;

    let now = now_millis();
    let identity_edit =
        node.kind.as_connection().is_some() && is_identity_edit(patch.username.as_ref(), &material);
    if identity_edit && patch.credential_id.is_some() {
        return Err(identity_conflicts_with_reference());
    }
    // Read before anything is rewritten: whether the credential this connection
    // owns has material in the vault decides whether clearing the username
    // removes it or leaves a credential the user still needs.
    let holds_secret = credential_holds_secret(vault, own_attached_credential(&tree, &node))?;

    apply_patch(&mut node, patch)?;
    if let Some(credential_id) = patch.credential_id.as_deref() {
        attach_credential(&mut node.kind, &tree, credential_id, id)?;
    }

    let mut tree_patch = TreePatch::default();
    let identity = if identity_edit {
        route_identity(
            &mut tree,
            &mut node,
            patch.username.as_deref(),
            &material,
            holds_secret,
            now,
            &mut tree_patch,
        )?
    } else {
        retarget_secret_kind(&mut node, &material)?;
        IdentityOutcome {
            credential: None,
            change: None,
        }
    };

    node.touch(now);
    merge_patch(
        &mut tree_patch,
        tree.update(node).map_err(|err| IpcError::from_core(&err))?,
    );
    // After the connection is written, so that "does it still point at the
    // credential it owns?" is asked of the edit's result rather than its input.
    prune_attached(&mut tree, id, now, &mut tree_patch)?;

    vault
        .apply(&tree, &tree_patch)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;

    // After `apply`, because the sealed material is bound to the record's
    // revision and `Tree::update` moved it.
    let target = identity.credential.unwrap_or(id);
    let uuid = *target.as_uuid();
    let switched_to = material.label();
    store_credential(vault, uuid, material)?;
    if let Some(kind) = switched_to {
        // A credential that authenticates one way must not keep the secrets of
        // another way behind it: a key credential with a stale password still
        // reachable is a credential the user believes they have replaced.
        forget_unused_secrets(vault, uuid, kind)?;
    }
    if identity_edit {
        forget_connection_secrets(vault, *id.as_uuid())?;
    }
    save(vault)?;

    let counts = inheritance_counts(&tree);
    tree.get(id)
        .map(|node| node_dto(&tree, node, &counts).with_credential_change(identity.change))
        .ok_or_else(|| IpcError::from_core(&remoter_core::CoreError::NodeNotFound(id)))
}

/// Deletes a node and everything under it.
///
/// A soft delete: the rows become tombstones so that references from elsewhere
/// still have a name to show, and so a future synchronisation can tell
/// "deleted" from "never seen".
#[tauri::command]
pub(crate) fn node_delete(state: State<'_, AppState>, id: String) -> Result<(), IpcError> {
    node_delete_impl(&state, id)
}

fn node_delete_impl(state: &AppState, id: String) -> Result<(), IpcError> {
    let id = parse_node_id(&id, "id")?;
    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let mut tree = read_tree(vault)?;

    let patch = tree
        .soft_delete(id, now_millis())
        .map_err(|err| IpcError::from_core(&err))?;
    vault
        .apply(&tree, &patch)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    save(vault)
}

/// Re-parents and re-orders a node.
#[tauri::command]
pub(crate) fn node_move(
    state: State<'_, AppState>,
    id: String,
    parent_id: Option<String>,
    sort_order: i64,
) -> Result<(), IpcError> {
    node_move_impl(&state, id, parent_id, sort_order)
}

fn node_move_impl(
    state: &AppState,
    id: String,
    parent_id: Option<String>,
    sort_order: i64,
) -> Result<(), IpcError> {
    let id = parse_node_id(&id, "id")?;
    let parent = match parent_id.as_deref() {
        Some(parent) => Some(parse_node_id(parent, "parentId")?),
        None => None,
    };

    let mut guard = state.lock();
    let vault = guard.vault_mut()?;
    let mut tree = read_tree(vault)?;

    let patch = tree
        .move_node(id, parent, sort_order)
        .map_err(|err| IpcError::from_core(&err))?;
    vault
        .apply(&tree, &patch)
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    save(vault)
}

/// A connection's settings with the inheritance flattened, and the provenance
/// of every field — what the inspector shows next to each value.
#[tauri::command]
pub(crate) fn node_resolve(
    state: State<'_, AppState>,
    id: String,
) -> Result<EffectiveConnectionDto, IpcError> {
    node_resolve_impl(&state, id)
}

fn node_resolve_impl(state: &AppState, id: String) -> Result<EffectiveConnectionDto, IpcError> {
    let id = parse_node_id(&id, "id")?;
    let mut guard = state.lock();
    let vault = guard.vault_ref()?;
    let tree = read_tree(vault)?;

    let effective = tree
        .effective_connection(id)
        .map_err(|err| IpcError::from_core(&err))?;
    Ok(effective_dto(&tree, id, &effective))
}

// ========================================================== private keys ==

/// What a candidate private key file is, without any of what is in it.
///
/// The editor calls this before it decides whether to ask for a passphrase.
/// The file is read — the container cannot be identified from a name — and the
/// bytes are wiped when this command returns. **Nothing about the key material
/// crosses the boundary**: the return value is a format, a flag and a size.
#[tauri::command]
pub(crate) fn key_inspect(path: String) -> Result<PrivateKeyInfoDto, IpcError> {
    key_inspect_impl(path)
}

fn key_inspect_impl(path: String) -> Result<PrivateKeyInfoDto, IpcError> {
    let path = PathBuf::from(path);
    let subject = path.display().to_string();
    let size_bytes = fs::metadata(&path).map_or(0, |meta| meta.len());

    // Dropped at the end of this function, which is what zeroizes the key.
    let key = ImportedKey::read(&path).map_err(|err| IpcError::from_vault(&err, &subject))?;

    Ok(PrivateKeyInfoDto {
        path: subject,
        format: key_format_wire(key.format()).to_owned(),
        format_label: key_format_label(key.format()).to_owned(),
        // Read out of the container, not inferred from anything.
        encrypted: key.is_encrypted(),
        size_bytes,
    })
}

// ================================================================= settings

/// The persisted interface settings.
#[tauri::command]
pub(crate) fn settings_get(state: State<'_, AppState>) -> Result<AppSettingsDto, IpcError> {
    settings_get_impl(&state)
}

fn settings_get_impl(state: &AppState) -> Result<AppSettingsDto, IpcError> {
    Ok(state.lock().settings().clone())
}

/// Merges a patch into the settings and writes them out.
#[tauri::command]
pub(crate) fn settings_set(
    state: State<'_, AppState>,
    patch: AppSettingsPatch,
) -> Result<AppSettingsDto, IpcError> {
    settings_set_impl(&state, patch)
}

fn settings_set_impl(
    state: &AppState,
    patch: AppSettingsPatch,
) -> Result<AppSettingsDto, IpcError> {
    let mut guard = state.lock();
    guard.apply_settings(patch).cloned()
}

/// Every keyboard binding, with its conflicts named.
///
/// The conflicts are computed here rather than left for the user to discover:
/// a shortcut that quietly does nothing because the desktop took it first
/// reads as a broken application.
#[tauri::command]
pub(crate) fn shortcuts_list(state: State<'_, AppState>) -> Result<Vec<ShortcutDto>, IpcError> {
    shortcuts_list_impl(&state)
}

fn shortcuts_list_impl(state: &AppState) -> Result<Vec<ShortcutDto>, IpcError> {
    Ok(state.lock().shortcuts())
}

// ============================================================= update check

/// The release list. Fixed in the binary rather than configurable: an update
/// source a user can be talked into changing is a way to point a credential
/// manager at somebody else's server, and there is no version of this feature
/// that needs it.
const RELEASES_API: &str = "https://api.github.com/repos/bbesli/Remoter/releases?per_page=20";

/// Where a release's own page lives. The interface opens this in the system
/// browser; it is never taken from the response. See [`release_page`].
const RELEASES_PAGE: &str = "https://github.com/bbesli/Remoter/releases";

/// Ten seconds, end to end. A check the user asked for has to either answer or
/// say it could not; hanging behind a captive portal is exactly the failure
/// that teaches people to stop trusting the button.
const UPDATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A ceiling on the response body. GitHub's own page size bounds this already;
/// the limit is here so that a substituted or compromised endpoint cannot make
/// this process allocate whatever it likes.
const UPDATE_BODY_LIMIT: u64 = 512 * 1024;

/// The only thing this request says about the machine making it: which build
/// is asking. No identifier, no locale, no telemetry — see
/// `docs/development/build-release.md`, which the Updates screen quotes.
fn update_user_agent() -> String {
    format!("Remoter/{}", env!("CARGO_PKG_VERSION"))
}

/// The fields of GitHub's release object this reads. Everything else in the
/// payload is ignored rather than mapped, so a change at the far end adds a
/// field here instead of breaking deserialisation.
#[derive(Debug, serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    published_at: Option<String>,
}

/// Asks GitHub what has been released.
///
/// It reports what it found; it does not decide whether an update is
/// available. Comparing versions — and deciding whether a pre-release counts —
/// happens in the interface, where the comparison has tests against it.
///
/// This is the only outbound request Remoter makes that the user did not
/// initiate by connecting somewhere, and it is made only when they ask.
#[tauri::command]
pub(crate) async fn update_check(state: State<'_, AppState>) -> Result<UpdateCheckDto, IpcError> {
    // `ureq` is a blocking client, and ten seconds of network wait on a
    // reactor thread is a frozen window. It goes to the blocking pool.
    let releases = tokio::task::spawn_blocking(fetch_releases)
        .await
        .map_err(|err| {
            // A panic in the fetch is reported, never swallowed: a check that
            // fails silently is the thing this screen exists not to do.
            IpcError::new(
                "update.failed",
                "The update check stopped before it finished.",
            )
            .with_detail(err.to_string())
            .with_actions(["Try again"])
        })??;

    let checked_at = now_seconds();
    // Recorded even when nothing newer was found. The user's question is "did
    // this reach the server", not "was there news".
    state.lock().record_update_check(checked_at)?;

    Ok(UpdateCheckDto {
        current_version: env!("CARGO_PKG_VERSION").to_owned(),
        releases,
        checked_at,
    })
}

/// One request, and every way it can end named separately.
fn fetch_releases() -> Result<Vec<UpdateReleaseDto>, IpcError> {
    let config = ureq::Agent::config_builder()
        .user_agent(update_user_agent())
        .timeout_global(Some(UPDATE_TIMEOUT))
        // Statuses are read rather than raised, because 403 and 404 mean
        // different things here and each gets its own sentence.
        .http_status_as_error(false)
        .max_redirects(3)
        .build();

    let mut response = ureq::Agent::new_with_config(config)
        .get(RELEASES_API)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .call()
        .map_err(|err| {
            IpcError::new(
                "update.unreachable",
                "Remoter could not reach github.com to look for a newer release.",
            )
            .with_detail(err.to_string())
            .with_actions([
                "Check this machine's network connection",
                "Try again",
                "Or open the releases page in a browser",
            ])
        })?;

    let status = response.status().as_u16();
    if status != 200 {
        return Err(status_failure(
            status,
            header(&response, "x-ratelimit-remaining"),
            header(&response, "x-ratelimit-reset"),
        ));
    }

    let body = response
        .body_mut()
        .with_config()
        .limit(UPDATE_BODY_LIMIT)
        .read_to_string()
        .map_err(|err| {
            IpcError::new(
                "update.unreadable",
                "GitHub answered, but the release list did not arrive whole.",
            )
            .with_detail(err.to_string())
            .with_actions(["Try again"])
        })?;

    let raw: Vec<GithubRelease> = serde_json::from_str(&body).map_err(|err| {
        IpcError::new(
            "update.unreadable",
            "GitHub answered with something that is not a release list.",
        )
        .with_detail(err.to_string())
        .with_actions(["Try again", "Or open the releases page in a browser"])
    })?;

    Ok(raw.into_iter().filter_map(into_release).collect())
}

/// Reads one header as text, dropping anything that is not.
fn header(response: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// A non-200 answer, told apart.
///
/// "Could not check" covers three genuinely different situations — the list is
/// not published, this network has asked too often, and something else went
/// wrong — and a user who cannot tell them apart cannot act on any of them.
fn status_failure(status: u16, remaining: Option<String>, reset: Option<String>) -> IpcError {
    let rate_limited = matches!(status, 403 | 429) && remaining.as_deref() == Some("0");

    if rate_limited {
        let mut failure = IpcError::new(
            "update.rate-limited",
            "GitHub is not answering any more update checks from this network for now.",
        )
        .with_actions(["Try again later", "Or open the releases page in a browser"]);
        if let Some(reset) = reset {
            // The reset stamp, not a countdown: the interface formats time, and
            // a number that was computed here would be stale by the time it is
            // read.
            failure = failure.with_detail(format!("The limit resets at {reset} (Unix seconds)."));
        }
        return failure;
    }

    match status {
        404 => IpcError::new(
            "update.no-releases",
            "GitHub has no published release list for bbesli/Remoter.",
        )
        .with_detail("The repository may be private, renamed, or without a release yet.")
        .with_actions(["Open the repository in a browser"]),
        403 => IpcError::new("update.refused", "GitHub refused the update check.")
            .with_detail("HTTP 403.")
            .with_actions(["Try again later", "Or open the releases page in a browser"]),
        other => IpcError::new(
            "update.failed",
            "GitHub answered the update check with an error.",
        )
        .with_detail(format!("HTTP {other}."))
        .with_actions(["Try again", "Or open the releases page in a browser"]),
    }
}

/// Maps one release, dropping the ones that cannot be offered.
///
/// A draft is not a release anyone can download, and a release whose tag will
/// not make a URL is one whose page cannot be opened — showing either would be
/// offering a button that goes nowhere.
fn into_release(raw: GithubRelease) -> Option<UpdateReleaseDto> {
    let url = release_page(&raw.tag_name)?;
    if raw.draft {
        return None;
    }

    Some(UpdateReleaseDto {
        tag: raw.tag_name,
        name: raw.name.unwrap_or_default(),
        notes: raw.body.unwrap_or_default(),
        url,
        prerelease: raw.prerelease,
        published_at: raw.published_at,
    })
}

/// Builds a release's page address from its tag.
///
/// Built here rather than read from the response on purpose. The address is
/// handed to the system browser, and a `javascript:`, `file://` or
/// somebody-else's-domain URL in a field the network controls would turn an
/// update check into a way to make the desktop open whatever the responder
/// chose. A tag that is not plain ASCII cannot make one of these, so its
/// release is dropped instead.
fn release_page(tag: &str) -> Option<String> {
    let usable = !tag.is_empty()
        && tag.len() <= 64
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'));

    usable.then(|| format!("{RELEASES_PAGE}/tag/{tag}"))
}

#[cfg(test)]
mod update_check_tests {
    use super::*;

    #[test]
    fn a_tag_that_cannot_make_a_url_takes_its_release_with_it() {
        // Each of these would either escape the repository's own path or put
        // something the browser interprets into an address we then open.
        for hostile in [
            "../../../etc/passwd",
            "v1.0.0 javascript:alert(1)",
            "v1.0.0?x=1",
            "v1.0.0#frag",
            "v1.0.0/../../other",
            "",
            "v1.0.0\nSet-Cookie: x",
        ] {
            assert_eq!(release_page(hostile), None, "accepted the tag {hostile:?}");
        }
    }

    #[test]
    fn an_ordinary_tag_makes_the_repositorys_own_page() {
        assert_eq!(
            release_page("v0.3.0").as_deref(),
            Some("https://github.com/bbesli/Remoter/releases/tag/v0.3.0"),
        );
        assert_eq!(
            release_page("v1.0.0-rc.1").as_deref(),
            Some("https://github.com/bbesli/Remoter/releases/tag/v1.0.0-rc.1"),
        );
    }

    #[test]
    fn a_draft_is_not_offered() {
        let draft = GithubRelease {
            tag_name: String::from("v9.9.9"),
            name: Some(String::from("Not out yet")),
            body: None,
            draft: true,
            prerelease: false,
            published_at: None,
        };
        assert_eq!(into_release(draft), None);
    }

    #[test]
    fn the_page_a_release_offers_is_never_the_one_the_response_asked_for() {
        // The response has no say in the address: `into_release` builds it.
        let release = into_release(GithubRelease {
            tag_name: String::from("v0.2.0"),
            name: None,
            body: None,
            draft: false,
            prerelease: false,
            published_at: Some(String::from("2026-01-02T03:04:05Z")),
        });

        let Some(release) = release else {
            unreachable!("an ordinary release was dropped");
        };
        assert!(
            release
                .url
                .starts_with("https://github.com/bbesli/Remoter/releases/"),
            "built {}",
            release.url,
        );
        assert_eq!(release.name, "");
        assert_eq!(release.notes, "");
    }

    #[test]
    fn the_request_says_which_build_is_asking_and_nothing_else() {
        let agent = update_user_agent();
        assert!(agent.starts_with("Remoter/"), "user agent was {agent}");
        assert!(
            !agent.contains(' '),
            "the user agent carries only a version: {agent}",
        );
    }

    #[test]
    fn a_rate_limit_is_told_apart_from_a_refusal() {
        let limited = status_failure(403, Some(String::from("0")), Some(String::from("1789")));
        assert_eq!(limited.code, "update.rate-limited");

        let refused = status_failure(403, Some(String::from("57")), None);
        assert_eq!(refused.code, "update.refused");

        assert_eq!(status_failure(404, None, None).code, "update.no-releases");
        assert_eq!(status_failure(500, None, None).code, "update.failed");
    }
}

// ================================================================== helpers

/// Reads the tree out of the vault.
pub(crate) fn read_tree(vault: &Vault) -> Result<Tree, IpcError> {
    vault
        .tree()
        .map_err(|err| IpcError::from_vault(&err, "this vault"))
}

/// Writes the vault to disk.
pub(crate) fn save(vault: &mut Vault) -> Result<(), IpcError> {
    vault
        .save()
        .map_err(|err| IpcError::from_vault(&err, "this vault"))
}

/// Records a vault in the picker's list. A failure to write the list is logged
/// rather than returned: the vault is open, and saying otherwise would be a
/// lie about the thing the user actually asked for.
fn remember(
    guard: &mut parking_lot::MutexGuard<'_, crate::state::Inner>,
    path: &Path,
    label: &str,
    slots: Vec<String>,
    keyfile: Option<String>,
) {
    let now = now_seconds();
    if let Err(err) =
        guard.update_recents(|recents| recents.record(path, label, slots, keyfile, now))
    {
        tracing::warn!(
            "the recent-vault list could not be written: {}",
            err.message
        );
    }
}

/// The slot kinds a vault offers, as the wire strings.
fn slot_kinds(vault: &Vault) -> Vec<String> {
    vault
        .slots()
        .iter()
        .map(|slot| slot.kind.as_str().to_owned())
        .collect()
}

/// The Argon2id summary of the password slot, for the creation summary screen.
fn kdf_summary(info: &VaultInfo) -> String {
    info.slots
        .iter()
        .find_map(|slot| slot.kdf_params.map(remoter_vault::KdfParams::summary))
        .unwrap_or_else(|| String::from("Argon2id"))
}

fn probe_dto(path: &Path, info: VaultInfo, remembered_keyfile: Option<String>) -> VaultProbeDto {
    let backups = info
        .backups
        .iter()
        .map(|backup| {
            let metadata = fs::metadata(backup).ok();
            BackupDto {
                path: backup.display().to_string(),
                modified_at: metadata
                    .as_ref()
                    .and_then(|meta| meta.modified().ok())
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .and_then(|since| i64::try_from(since.as_secs()).ok())
                    .unwrap_or_default(),
                size_bytes: metadata.map_or(0, |meta| meta.len()),
            }
        })
        .collect();

    VaultProbeDto {
        path: path.display().to_string(),
        label: info.label,
        format_version: info.format_version,
        created_at: info.created_at,
        modified_at: info.modified_at,
        size_bytes: info.size_bytes,
        slots: info.slots.iter().map(slot_dto).collect(),
        backups,
        sync_warning: sync_warning(path),
        remembered_keyfile,
    }
}

/// One key slot, as the picker and the settings screen read it.
pub(crate) fn slot_dto(slot: &SlotInfo) -> SlotDto {
    SlotDto {
        index: slot.index,
        kind: slot.kind.as_str().to_owned(),
        label: slot.label.clone(),
        created_at: slot.created_at,
        last_used: slot.last_used,
        requires_keyfile: slot.requires_keyfile,
        kdf_summary: slot.kdf_summary(),
    }
}

/// Builds the unlock method, wrapping the password on arrival.
fn unlock_method(request: UnlockRequestDto, subject: &str) -> Result<UnlockMethod, IpcError> {
    match request {
        UnlockRequestDto::Password {
            password,
            keyfile_path,
        } => {
            let password = Secret::new(password);
            Ok(match keyfile_path {
                Some(keyfile) => UnlockMethod::password_with_keyfile(password, keyfile),
                None => UnlockMethod::password(password),
            })
        }
        UnlockRequestDto::Recovery { key } => {
            // A malformed or mistyped recovery key is safe to name: it is a
            // statement about what was typed, not about what the vault holds.
            let parsed =
                RecoveryKey::parse(&key).map_err(|err| IpcError::from_vault(&err, subject))?;
            Ok(UnlockMethod::recovery(parsed))
        }
        UnlockRequestDto::Keychain => Ok(UnlockMethod::Keychain),
    }
}

/// Writes `KEYFILE_BYTES` of CSPRNG output, refusing to overwrite.
///
/// The file is created with its permissions already set, never widened
/// afterwards: a `chmod` after the write leaves a window in which the whole
/// second factor is on disk under the process umask — 0644 on a default
/// installation — and `create_new` closes the race between an `exists()` check
/// and the open at the same time.
///
/// A file system that cannot carry the permission — the exFAT or FAT removable
/// stick a key file often lives on — is a failure, not a warning. Enrolling a
/// second factor every account on the machine can read, and telling the user
/// they have two factors, is worse than refusing to write it.
fn write_keyfile(path: &Path) -> Result<(), IpcError> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|err| IpcError::io("creating the key file's directory", parent, &err))?;
        }
    }

    // `Secret` rather than a bare `Vec`: the buffer is key material until it
    // reaches the file, and it is zeroized when this function returns.
    let mut bytes = Secret::new(vec![0u8; KEYFILE_BYTES]);
    getrandom::fill(bytes.expose_secret_mut()).map_err(|_| IpcError::csprng())?;

    let mut file = create_owner_only(path)?;
    let written = file
        .write_all(bytes.expose_secret())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(err) = written {
        // Nothing else can use a half-written key file, and leaving it there
        // would make the retry look like "a file already exists".
        let _ = fs::remove_file(path);
        return Err(IpcError::io("writing the key file", path, &err));
    }

    if let Err(err) = verify_owner_only(path) {
        let _ = fs::remove_file(path);
        return Err(err);
    }

    Ok(())
}

/// Creates the key file with owner-only permissions applied at open time.
#[cfg(unix)]
fn create_owner_only(path: &Path) -> Result<fs::File, IpcError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| keyfile_create_error(path, &err))
}

#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> Result<fs::File, IpcError> {
    // Windows inherits the parent directory's ACL, and the per-user profile
    // directory is already owner-only. Narrowing the ACL explicitly needs an
    // API this crate does not reach for; `verify_owner_only` is the check.
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| keyfile_create_error(path, &err))
}

/// Maps a failure to create the key file, keeping the "never overwritten"
/// sentence for the case the user will actually hit.
fn keyfile_create_error(path: &Path, err: &std::io::Error) -> IpcError {
    if err.kind() == std::io::ErrorKind::AlreadyExists {
        return IpcError::bad_path(
            path,
            "a file already exists there, and a key file is never overwritten",
        );
    }
    IpcError::io("creating the key file", path, err)
}

/// Confirms nobody but the owner can read the key file.
///
/// Opening with mode 0600 is not enough on its own: a file system without Unix
/// permissions ignores the mode silently, so the mode is read back rather than
/// assumed.
#[cfg(unix)]
fn verify_owner_only(path: &Path) -> Result<(), IpcError> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata =
        fs::metadata(path).map_err(|err| IpcError::io("reading back the key file", path, &err))?;
    let mode = metadata.permissions().mode();
    if mode & 0o077 == 0 {
        return Ok(());
    }
    Err(keyfile_unprotected(path))
}

#[cfg(not(unix))]
fn verify_owner_only(_path: &Path) -> Result<(), IpcError> {
    Ok(())
}

/// The key file could not be restricted to this account.
fn keyfile_unprotected(path: &Path) -> IpcError {
    IpcError::new(
        "keyfile.unprotected",
        format!(
            "{} cannot be restricted to your account: the file system it is on does not \
             carry permissions, so every account on this machine could read it. A key file \
             anyone can read is not a second factor, so it was not written.",
            path.display()
        ),
    )
    .with_actions([
        "Choose a location on a disk that keeps file permissions",
        "Encrypt the removable drive, then write the key file to it",
    ])
}

/// A file-name stem from a vault label.
fn slugify(label: &str) -> String {
    let mut out = String::new();
    let mut last_dash = true;
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            out.extend(ch.to_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_owned();
    if trimmed.is_empty() {
        String::from("vault")
    } else {
        trimmed
    }
}

/// A uniform integer in `0..bound`, by rejection sampling.
///
/// `value % bound` would bias the low end whenever `bound` does not divide
/// 2^32. Rejecting the tail costs an occasional extra draw and removes the
/// bias entirely.
pub(crate) fn uniform_below(bound: u32) -> Result<u32, IpcError> {
    if bound <= 1 {
        return Ok(0);
    }
    let zone = (u32::MAX / bound) * bound;

    // A working CSPRNG lands inside the zone with probability at least 1/2 per
    // draw, so this cannot spin: it is a guard against a broken one.
    for _ in 0..64 {
        let mut buffer = [0u8; 4];
        getrandom::fill(&mut buffer).map_err(|_| IpcError::csprng())?;
        let value = u32::from_le_bytes(buffer);
        if value < zone {
            return Ok(value % bound);
        }
    }
    Err(IpcError::csprng())
}

pub(crate) fn parse_node_id(text: &str, field: &str) -> Result<NodeId, IpcError> {
    Uuid::parse_str(text)
        .map(NodeId::from_uuid)
        .map_err(|err| IpcError::invalid_request(field, err.to_string()))
}

/// The sort order to give a new child: after the last one already there.
pub(crate) fn next_sort_order(tree: &Tree, parent: Option<NodeId>) -> i64 {
    tree.children(parent)
        .iter()
        .filter_map(|id| tree.get(*id))
        .map(|node| node.sort_order)
        .max()
        .map_or(0, |last| last.saturating_add(1))
}

/// A credential's authentication material, out of the request and into
/// something that wipes itself.
///
/// The key bytes and the passphrase live here between the request arriving and
/// the vault sealing them; nothing in this enum is ever rendered, returned or
/// logged. `ImportedKey` and `Secret` both zeroize on drop, so dropping this —
/// on any path, including an early return — is what wipes them.
pub(crate) enum CredentialMaterial {
    /// The request named none, so nothing is stored and nothing is removed.
    Absent,
    Password(Secret<Vec<u8>>),
    PrivateKey {
        key: ImportedKey,
        passphrase: Option<Secret<String>>,
    },
    Agent {
        comment_filter: Option<String>,
    },
}

impl CredentialMaterial {
    /// The wire spelling of what this material makes the credential, or `None`
    /// when the request named nothing.
    const fn label(&self) -> Option<&'static str> {
        match self {
            Self::Absent => None,
            Self::Password(_) => Some("password"),
            Self::PrivateKey { .. } => Some("privateKey"),
            Self::Agent { .. } => Some("agent"),
        }
    }
}

/// Moves the request's secrets into wiping buffers, and reads the key file if
/// one was named.
///
/// Called as the first act of every command that takes a credential, before
/// the state lock and before anything that can fail: the plaintext `String`
/// serde built is moved out here, so an early return unwinds through `Drop`
/// rather than leaving it in freed heap.
fn take_credential(
    password: Option<String>,
    credential: Option<CredentialInputDto>,
) -> Result<CredentialMaterial, IpcError> {
    let password = password.map(|password| Secret::new(password.into_bytes()));

    match (password, credential) {
        (None, None) => Ok(CredentialMaterial::Absent),
        (Some(secret), None) => Ok(CredentialMaterial::Password(secret)),
        (Some(_), Some(_)) => Err(IpcError::invalid_request(
            "credential",
            "the request carries both a bare `password` and a `credential`, and guessing \
             which one the user meant is not something this layer may do",
        )),
        (None, Some(CredentialInputDto::Password { password })) => Ok(
            CredentialMaterial::Password(Secret::new(password.into_bytes())),
        ),
        (None, Some(CredentialInputDto::Agent { comment_filter })) => {
            Ok(CredentialMaterial::Agent { comment_filter })
        }
        (None, Some(CredentialInputDto::PrivateKey { path, passphrase })) => {
            // The passphrase is wrapped before the file is touched, because
            // reading the file is the next thing that can fail.
            let passphrase = passphrase.map(Secret::new);
            let path = PathBuf::from(path);
            let key = ImportedKey::read(&path)
                .map_err(|err| IpcError::from_vault(&err, &path.display().to_string()))?;
            if passphrase.is_none() && key.is_encrypted() {
                return Err(IpcError::new(
                    "key.passphrase-required",
                    format!(
                        "{} is passphrase-protected, and without the passphrase Remoter \
                         cannot use it to authenticate.",
                        path.display()
                    ),
                )
                .with_actions([
                    "Enter the key's passphrase",
                    "Choose a key that is not passphrase-protected",
                ]));
            }
            Ok(CredentialMaterial::PrivateKey { key, passphrase })
        }
    }
}

/// Seals the material onto a node that already exists.
///
/// After `Vault::apply`, always: a ciphertext is bound to its node's id and
/// revision, so it cannot be written before the row it belongs to.
fn store_credential(
    vault: &mut Vault,
    node: Uuid,
    material: CredentialMaterial,
) -> Result<(), IpcError> {
    match material {
        // The agent stores no key material at all, which is the whole reason
        // it is the recommended option.
        CredentialMaterial::Absent | CredentialMaterial::Agent { .. } => Ok(()),
        CredentialMaterial::Password(secret) => vault
            .set_secret(node, "password", secret)
            .map_err(|err| IpcError::from_vault(&err, "this vault")),
        CredentialMaterial::PrivateKey { key, passphrase } => vault
            .set_private_key(node, &key, passphrase.as_ref())
            .map_err(|err| IpcError::from_vault(&err, "this vault")),
    }
}

/// Deletes the stored secrets a credential no longer authenticates with.
fn forget_unused_secrets(vault: &mut Vault, node: Uuid, kind: &str) -> Result<(), IpcError> {
    // `set_private_key` already removes a passphrase that is no longer wanted,
    // so the key case only has the password to clear.
    let stale: &[&str] = match kind {
        "password" => &["private_key", "passphrase"],
        "privateKey" => &["password"],
        "agent" => &["password", "private_key", "passphrase"],
        _ => &[],
    };

    for field in stale {
        let present = vault
            .has_secret(node, field)
            .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
        if present {
            vault
                .remove_secret(node, field)
                .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
        }
    }
    Ok(())
}

/// Points a credential node's `SecretKind` at the material the edit supplies.
///
/// The sealed fields carry the vault's placeholder: the real ciphertext is
/// written after the row is, by [`store_credential`].
fn retarget_secret_kind(node: &mut Node, material: &CredentialMaterial) -> Result<(), IpcError> {
    if material.label().is_none() {
        // The request named no material, so there is nothing to point at.
        return Ok(());
    }

    let NodeKind::Credential(props) = &mut node.kind else {
        // A secret typed on a connection lands on the credential that
        // connection owns, which `route_identity` has already created or
        // found — so by the time this is reached with a connection there is
        // nothing left to retarget. Putting a secret on a folder is a request
        // that cannot mean anything: a folder authenticates nothing.
        if matches!(node.kind, NodeKind::Connection(_)) {
            return Ok(());
        }
        return Err(IpcError::new(
            "node.field-not-applicable",
            "Only a connection or a credential holds a secret.",
        )
        .with_actions(["Select a connection or a credential"]));
    };

    match material {
        CredentialMaterial::Absent => {}
        CredentialMaterial::Password(_) => {
            // An existing password credential keeps its record as it is: the
            // new ciphertext replaces the old one in the secrets table, and
            // rewriting the kind here would say nothing new.
            if !matches!(props.secret, SecretKind::Password { .. }) {
                props.secret = SecretKind::Password {
                    sealed: Vault::sealed_placeholder(),
                };
            }
        }
        CredentialMaterial::PrivateKey { key, passphrase } => {
            props.secret = SecretKind::PrivateKey {
                sealed_key: Vault::sealed_placeholder(),
                sealed_passphrase: passphrase.as_ref().map(|_| Vault::sealed_placeholder()),
                format: key.format(),
            };
        }
        CredentialMaterial::Agent { comment_filter } => {
            props.secret = SecretKind::Agent {
                comment_filter: comment_filter.clone(),
            };
        }
    }
    Ok(())
}

/// Builds the node kind a create request asks for.
fn build_kind(input: &CreateNodeDto, material: &CredentialMaterial) -> Result<NodeKind, IpcError> {
    // A connection may be given a key or the agent: it gets a credential of
    // its own to hold it. Nothing else may — a folder authenticates nothing.
    if !matches!(input.kind.as_str(), "credential" | "connection")
        && matches!(
            material,
            CredentialMaterial::PrivateKey { .. } | CredentialMaterial::Agent { .. }
        )
    {
        return Err(IpcError::new(
            "node.field-not-applicable",
            "Only a connection or a credential holds a secret.",
        )
        .with_actions(["Create a credential and point this connection at it"]));
    }

    match input.kind.as_str() {
        "folder" => Ok(NodeKind::folder()),
        "connection" => {
            let protocol = input.protocol.as_deref().ok_or_else(|| {
                IpcError::new(
                    "validation.protocol-missing",
                    "A connection needs a protocol: SSH, RDP, VNC or SFTP.",
                )
                .with_actions(["Choose a protocol"])
            })?;
            let host = input.host.as_deref().ok_or_else(|| {
                IpcError::from_validation(&remoter_core::ValidationError::HostEmpty)
            })?;
            let mut props = ConnectionProps::new(protocol, host)
                .map_err(|err| IpcError::from_validation(&err))?;
            if let Some(port) = input.port {
                validate_port(port).map_err(|err| IpcError::from_validation(&err))?;
                props.port = Inherited::Explicit(port);
            }
            Ok(NodeKind::Connection(props))
        }
        "credential" => {
            let username = input.username.clone().unwrap_or_default();
            // The real ciphertext cannot exist before the node does — the
            // associated data binds it to the node's id and revision — so the
            // credential is inserted carrying the vault's placeholder and given
            // its secret immediately afterwards.
            Ok(NodeKind::Credential(match material {
                CredentialMaterial::PrivateKey { key, passphrase } => {
                    private_key_credential(username, key.format(), passphrase.is_some())
                }
                CredentialMaterial::Agent { comment_filter } => {
                    agent_credential(username, comment_filter.clone())
                }
                CredentialMaterial::Absent | CredentialMaterial::Password(_) => {
                    CredentialProps::new(
                        username,
                        SecretKind::Password {
                            sealed: Vault::sealed_placeholder(),
                        },
                    )
                }
            }))
        }
        "group" => Ok(NodeKind::Group(remoter_core::GroupProps::default())),
        "separator" => Ok(NodeKind::Separator),
        other => Err(IpcError::invalid_request(
            "kind",
            format!(
                "`{other}` is not a node kind; expected folder, connection, credential, \
                 group or separator"
            ),
        )),
    }
}

/// Points a connection or a folder at a credential node.
///
/// The reference is checked against the tree here rather than left to the
/// storage layer: a connection pointing at something that is not a credential
/// fails at connect time, which is the worst moment to find out.
fn attach_credential(
    kind: &mut NodeKind,
    tree: &Tree,
    id: &str,
    referrer: NodeId,
) -> Result<(), IpcError> {
    let id = parse_node_id(id, "credentialId")?;
    let Some(node) = tree.get(id) else {
        return Err(IpcError::from_validation(
            &remoter_core::ValidationError::CredentialUnknown { credential: id },
        ));
    };
    let Some(props) = node.kind.as_credential() else {
        return Err(IpcError::from_validation(
            &remoter_core::ValidationError::CredentialNotACredential { credential: id },
        ));
    };
    // A credential attached to a connection is that connection's own. A second
    // node pointing at it would put two connections behind one password
    // without either saying so, and editing it from one would change the
    // other. Refused here rather than at connect time, which is the worst
    // moment to find out.
    if let Some(owner) = props.attached_to {
        if owner != referrer {
            return Err(IpcError::from_validation(
                &remoter_core::ValidationError::CredentialAttachedElsewhere {
                    credential: id,
                    connection: owner,
                },
            ));
        }
    }

    let reference = Inherited::Explicit(CredentialRef::live(id));
    match kind {
        NodeKind::Connection(props) => props.credential = reference,
        NodeKind::Folder(props) => props.credential = reference,
        _ => {
            return Err(IpcError::new(
                "node.field-not-applicable",
                "Only connections and folders authenticate with a credential.",
            )
            .with_actions(["Select a connection or a folder"]));
        }
    }
    Ok(())
}

// ======================================================== the identity seam ==
//
// A connection carries no username, no password and no key: the data model puts
// all three on a credential, which is what makes one service account shareable
// between two hundred connections without duplication. The connection editor
// nonetheless asks for a username and a password, because typing them on one
// server has to just work — nobody should have to learn that credential nodes
// exist to connect to a machine.
//
// This is the seam between the two. An identity typed on a connection lands on a
// credential *attached* to it: a real node with a real id, deleted and moved
// with its connection, that nothing else may point at. The case that shapes the
// code is the inherited one — a connection under a folder that supplies the
// credential. Editing that credential would change every other connection under
// the folder, so setting a username here creates a new attached credential that
// overrides the inherited one, exactly as overriding a port does.

/// What routing an identity edit onto a connection's own credential did.
struct IdentityOutcome {
    /// The credential the material must be sealed onto once the rows are
    /// written. `None` when the edit removed the connection's own credential.
    credential: Option<NodeId>,
    /// The wire spelling for [`NodeDto::credential_change`], or `None` when
    /// nothing happened worth telling the user about.
    change: Option<&'static str>,
}

/// Whether an edit carries an identity: a username, a password, a private key
/// or a choice of the agent.
fn is_identity_edit(username: Option<&String>, material: &CredentialMaterial) -> bool {
    username.is_some() || !matches!(material, CredentialMaterial::Absent)
}

/// The refusal for an edit that names a shared credential *and* an identity of
/// its own.
fn identity_conflicts_with_reference() -> IpcError {
    IpcError::invalid_request(
        "credentialId",
        "the request points this connection at a shared credential and also gives it a \
         username or a secret of its own, and choosing between the two is not something \
         this layer may do",
    )
}

/// The credential a node authenticates with as it currently stands: its own if
/// it has one, otherwise whatever it inherits.
///
/// Takes the node rather than an id because it is also asked about a connection
/// that is being created and is not in the tree yet.
fn effective_credential(tree: &Tree, node: &Node) -> Option<CredentialRef> {
    match node.credential_field() {
        Some(Inherited::Explicit(reference)) => Some(reference.clone()),
        // The node deliberately pins "no credential"; there is nothing to
        // inherit and nothing to carry over.
        Some(Inherited::Default) => None,
        _ => node
            .parent_id
            .and_then(|parent| tree.resolve_optional(parent, Node::credential_field).ok())
            .and_then(|resolved| resolved.value),
    }
}

/// The credential a node owns, if it owns one: its own explicit reference,
/// where that reference points at a credential attached to it.
fn own_attached_credential(tree: &Tree, node: &Node) -> Option<NodeId> {
    let reference = node.credential_field().and_then(Inherited::explicit)?;
    if reference.is_deleted() {
        return None;
    }
    let id = reference.id();
    tree.get(id)
        .and_then(|credential| credential.kind.as_credential())
        .is_some_and(|props| props.belongs_to(node.id))
        .then_some(id)
}

/// The account name held by the credential a reference points at.
fn referenced_username(tree: &Tree, reference: &CredentialRef) -> Option<String> {
    if reference.is_deleted() {
        return None;
    }
    tree.get(reference.id())
        .and_then(|node| node.kind.as_credential())
        .map(|props| props.username.clone())
        .filter(|username| !username.is_empty())
}

/// The properties of a credential belonging to `connection`.
///
/// The sealed fields carry the vault's placeholder: the real ciphertext is
/// written after the row is, by [`store_credential`].
fn attached_props(
    connection: NodeId,
    username: String,
    material: &CredentialMaterial,
) -> CredentialProps {
    let mut props = match material {
        CredentialMaterial::PrivateKey { key, passphrase } => {
            private_key_credential(username, key.format(), passphrase.is_some())
        }
        CredentialMaterial::Agent { comment_filter } => {
            agent_credential(username, comment_filter.clone())
        }
        // A username with no secret yet is a credential the user is halfway
        // through typing, not an error: the password field is the next one
        // along, and refusing to save the username until it is filled in would
        // lose what they typed.
        CredentialMaterial::Absent | CredentialMaterial::Password(_) => CredentialProps::new(
            username,
            SecretKind::Password {
                sealed: Vault::sealed_placeholder(),
            },
        ),
    };
    props.attached_to = Some(connection);
    props
}

/// Points a connection's credential field at `value`. A no-op on any other
/// kind, which cannot reach here.
fn set_credential_field(node: &mut Node, value: Inherited<CredentialRef>) {
    if let NodeKind::Connection(props) = &mut node.kind {
        props.credential = value;
    }
}

/// Merges the rows one mutation touched into the patch a command will apply.
///
/// Commands that mutate more than one node — a connection and the credential it
/// owns — apply one patch at the end rather than one per node, so a failure
/// halfway leaves the vault file untouched rather than half-written.
fn merge_patch(into: &mut TreePatch, from: TreePatch) {
    into.inserted.extend(from.inserted);
    into.updated.extend(from.updated);
    into.tombstoned.extend(from.tombstoned);
    into.resolution_changed.extend(from.resolution_changed);
}

/// Routes an identity edit onto the connection's own credential, creating one
/// where there is none.
///
/// `holds_secret` says whether the connection's existing own credential has
/// material stored in the vault; the caller reads it, because this function has
/// no vault. `connection` is mutated in place and written by the caller —
/// creating and updating a connection are different calls, and the difference
/// must not reach in here.
fn route_identity(
    tree: &mut Tree,
    connection: &mut Node,
    username: Option<&str>,
    material: &CredentialMaterial,
    holds_secret: bool,
    now: i64,
    patch: &mut TreePatch,
) -> Result<IdentityOutcome, IpcError> {
    let id = connection.id;
    let own = own_attached_credential(tree, connection);

    // Clearing both halves of the identity removes the credential rather than
    // leaving an empty one behind, so that the connection goes back to
    // whatever it inherits — the same "revert to inherited" the rest of the
    // editor does. The caller deletes the row; this decides.
    let cleared = username.is_some_and(|name| name.trim().is_empty())
        && matches!(material, CredentialMaterial::Absent)
        && !holds_secret;

    if let Some(credential_id) = own {
        if cleared {
            set_credential_field(connection, Inherited::Inherit);
            return Ok(IdentityOutcome {
                credential: None,
                change: Some("removed"),
            });
        }

        let mut credential = tree.get(credential_id).cloned().ok_or_else(|| {
            IpcError::from_core(&remoter_core::CoreError::NodeNotFound(credential_id))
        })?;
        if let (Some(name), NodeKind::Credential(props)) = (username, &mut credential.kind) {
            props.username = name.to_owned();
        }
        retarget_secret_kind(&mut credential, material)?;
        credential.touch(now);
        merge_patch(
            patch,
            tree.update(credential)
                .map_err(|err| IpcError::from_core(&err))?,
        );
        return Ok(IdentityOutcome {
            credential: Some(credential_id),
            change: Some("updated"),
        });
    }

    if cleared {
        // Nothing of its own to clear; the inherited credential was already
        // what this connection used.
        return Ok(IdentityOutcome {
            credential: None,
            change: None,
        });
    }

    // A tombstoned reference is not a credential this connection was using:
    // the user already deleted it, and what happens here is a fresh start.
    let previous =
        effective_credential(tree, connection).filter(|reference| !reference.is_deleted());
    let points_at_one = connection
        .credential_field()
        .and_then(Inherited::explicit)
        .is_some_and(|reference| !reference.is_deleted());
    let change = match (&previous, points_at_one) {
        // Its own reference to a credential somebody else may be using. It is
        // left exactly as it is, and the connection is given one of its own —
        // rewriting a shared credential from the editor of one connection is
        // the failure this whole mechanism exists to prevent.
        (Some(_), true) => "detachedFromShared",
        // Inherited from a folder. The folder's credential is untouched and
        // every other connection under it keeps resolving to it; this one now
        // overrides it.
        (Some(_), false) => "overridesInherited",
        (None, _) => "created",
    };

    // The username carries over from the credential this connection was using;
    // the secret deliberately does not. A username is an identifier, not secret
    // material, and dropping it would silently change the account a connection
    // logs in as. Copying the secret would put a second envelope of somebody
    // else's password in the vault, which a later rotation of the original
    // would silently miss.
    let name = username.map(str::to_owned).unwrap_or_else(|| {
        previous
            .as_ref()
            .and_then(|reference| referenced_username(tree, reference))
            .unwrap_or_default()
    });

    let props = attached_props(id, name, material);
    // Named after its connection: the node needs a name, nothing renders it as
    // an entry of its own, and a diagnostic that mentions it should say which
    // connection it belongs to.
    let mut credential = Node::new(NodeKind::Credential(props), connection.name.clone(), now);
    credential.parent_id = connection.parent_id;
    credential.sort_order = connection.sort_order;
    let credential_id = credential.id;

    merge_patch(
        patch,
        tree.insert(credential)
            .map_err(|err| IpcError::from_core(&err))?,
    );
    set_credential_field(
        connection,
        Inherited::Explicit(CredentialRef::live(credential_id)),
    );

    Ok(IdentityOutcome {
        credential: Some(credential_id),
        change: Some(change),
    })
}

/// Deletes the credentials that belonged to `connection` and that it no longer
/// points at.
///
/// An attached credential lives exactly as long as its connection references
/// it. One left behind after the connection reverted to an inherited credential
/// — or was pointed at a shared one — would be secret material owned by
/// nothing, reachable by nothing and visible nowhere.
fn prune_attached(
    tree: &mut Tree,
    connection: NodeId,
    now: i64,
    patch: &mut TreePatch,
) -> Result<(), IpcError> {
    let referenced = tree
        .get(connection)
        .and_then(Node::credential_field)
        .and_then(Inherited::explicit)
        .map(CredentialRef::id);

    for attached in tree.attached_credentials(connection) {
        if referenced == Some(attached) {
            continue;
        }
        merge_patch(
            patch,
            tree.soft_delete(attached, now)
                .map_err(|err| IpcError::from_core(&err))?,
        );
    }
    Ok(())
}

/// Removes secret fields filed under a connection node itself.
///
/// Before the identity seam existed, a password typed on a connection was
/// sealed under the connection's own id — where nothing reads it: the session
/// pipeline authenticates from the credential the connection resolves, and a
/// connection is not a credential. Such an envelope is unreachable material,
/// and unreachable material is exactly what should not sit in a vault.
fn forget_connection_secrets(vault: &mut Vault, node: Uuid) -> Result<(), IpcError> {
    for field in ["password", "private_key", "passphrase"] {
        let present = vault
            .has_secret(node, field)
            .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
        if present {
            vault
                .remove_secret(node, field)
                .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
        }
    }
    Ok(())
}

/// Whether the credential node `id` has any secret material stored for it.
fn credential_holds_secret(vault: &Vault, id: Option<NodeId>) -> Result<bool, IpcError> {
    let Some(id) = id else {
        return Ok(false);
    };
    let uuid = *id.as_uuid();
    for field in ["password", "private_key"] {
        if vault
            .has_secret(uuid, field)
            .map_err(|err| IpcError::from_vault(&err, "this vault"))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Applies an edit to a node in memory. Validation is left to `Tree::update`,
/// which runs the same rules the importer and the storage layer run.
fn apply_patch(node: &mut Node, patch: &UpdateNodeDto) -> Result<(), IpcError> {
    if let Some(name) = &patch.name {
        node.name = name.clone();
    }
    if let Some(description) = &patch.description {
        node.description = description.clone();
    }
    if let Some(tags) = &patch.tags {
        let mut parsed = Vec::with_capacity(tags.len());
        for tag in tags {
            parsed.push(Tag::new(tag.clone()).map_err(|err| IpcError::from_validation(&err))?);
        }
        node.tags = parsed;
    }
    if let Some(colour) = &patch.colour {
        node.colour = if colour.is_empty() {
            None
        } else {
            Some(colour.clone())
        };
    }

    if let Some(host) = &patch.host {
        match &mut node.kind {
            NodeKind::Connection(props) => props.host = host.clone(),
            _ => {
                return Err(IpcError::new(
                    "node.field-not-applicable",
                    "Only a connection has an address.",
                )
                .with_actions(["Edit the connection instead"]));
            }
        }
    }
    if let Some(port) = patch.port {
        match &mut node.kind {
            NodeKind::Connection(props) => {
                validate_port(port).map_err(|err| IpcError::from_validation(&err))?;
                props.port = Inherited::Explicit(port);
            }
            NodeKind::Folder(props) => {
                validate_port(port).map_err(|err| IpcError::from_validation(&err))?;
                props.port = Inherited::Explicit(port);
            }
            _ => {
                return Err(IpcError::new(
                    "node.field-not-applicable",
                    "Only connections and folders carry a port.",
                )
                .with_actions(["Edit a connection or a folder instead"]));
            }
        }
    }
    if let Some(username) = &patch.username {
        match &mut node.kind {
            NodeKind::Credential(props) => props.username = username.clone(),
            // A connection's username belongs to the credential it owns, and
            // is routed there by `route_identity` — which needs the tree, and
            // so cannot happen here.
            NodeKind::Connection(_) => {}
            _ => {
                return Err(IpcError::new(
                    "node.field-not-applicable",
                    "Only a connection or a credential has a username.",
                )
                .with_actions(["Edit the connection instead"]));
            }
        }
    }

    if let Some(fields) = &patch.clear_overrides {
        for field in fields {
            clear_override(node, field)?;
        }
    }
    Ok(())
}

/// Resets one field to `Inherited::Inherit`, so it takes the ancestors' value
/// again. Field names are the stable ASCII ones `EffectiveConnection`
/// reports; punctuation and case are ignored so the interface can send back
/// either the core's `connect_timeout_ms` or its own `connectTimeoutMs`.
fn clear_override(node: &mut Node, field: &str) -> Result<(), IpcError> {
    let key: String = field
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();

    macro_rules! clear {
        ($field:ident) => {
            match &mut node.kind {
                NodeKind::Connection(props) => {
                    props.$field = Inherited::Inherit;
                    return Ok(());
                }
                NodeKind::Folder(props) => {
                    props.$field = Inherited::Inherit;
                    return Ok(());
                }
                _ => {
                    return Err(IpcError::new(
                        "node.field-not-applicable",
                        "Only connections and folders inherit settings.",
                    )
                    .with_actions(["Select a connection or a folder"]));
                }
            }
        };
    }

    match key.as_str() {
        "port" => clear!(port),
        "credential" => clear!(credential),
        "gateway" => clear!(gateway),
        "connecttimeoutms" => clear!(connect_timeout_ms),
        "keepalivesecs" => clear!(keepalive_secs),
        "onconnect" => clear!(on_connect),
        "ondisconnect" => clear!(on_disconnect),
        "recording" => clear!(recording),
        "autoreconnect" => clear!(auto_reconnect),
        "icon" => {
            node.icon = None;
            Ok(())
        }
        "colour" => {
            node.colour = None;
            Ok(())
        }
        _ => Err(IpcError::invalid_request(
            "clearOverrides",
            format!("`{field}` is not an inheritable field"),
        )),
    }
}

// ------------------------------------------------------------------- DTOs --

/// Appends a subtree in the order the sidebar draws it.
///
/// Credentials attached to a connection are left out: they are part of that
/// connection — its username and its secret, which the connection's own row
/// carries — and listing them would put an entry in the sidebar for something
/// the user never created.
fn push_subtree(
    tree: &Tree,
    parent: Option<NodeId>,
    counts: &BTreeMap<NodeId, usize>,
    out: &mut Vec<NodeDto>,
) {
    for id in tree.children(parent) {
        if let Some(node) = tree.get(*id) {
            if is_attached_credential(node) {
                continue;
            }
            out.push(node_dto(tree, node, counts));
            push_subtree(tree, Some(*id), counts, out);
        }
    }
}

/// Whether a node is a credential belonging to one connection.
pub(crate) fn is_attached_credential(node: &Node) -> bool {
    node.kind
        .as_credential()
        .is_some_and(CredentialProps::is_attached)
}

pub(crate) fn node_dto(tree: &Tree, node: &Node, counts: &BTreeMap<NodeId, usize>) -> NodeDto {
    let (protocol, host, port) = match &node.kind {
        NodeKind::Connection(props) => (
            Some(props.protocol.as_str().to_owned()),
            Some(props.host.clone()),
            // The row shows the port that would be used: the explicit one, or
            // the protocol's default. The inspector is where the distinction
            // between the two is made visible.
            props
                .port
                .explicit()
                .copied()
                .or_else(|| props.protocol.default_port()),
        ),
        _ => (None, None, None),
    };

    // A connection has no identity of its own in the data model; what the
    // editor shows and edits is the credential attached to it. Reading it here
    // is what lets one form show a username and a secret without the user ever
    // learning that credential nodes exist.
    let identity = node.kind.as_credential().or_else(|| {
        own_attached_credential(tree, node)
            .and_then(|id| tree.get(id))
            .and_then(|credential| credential.kind.as_credential())
    });

    NodeDto {
        id: node.id.to_string(),
        parent_id: node.parent_id.map(|id| id.to_string()),
        sort_order: node.sort_order,
        kind: node.kind.label().to_owned(),
        name: node.name.clone(),
        description: node.description.clone(),
        tags: node
            .tags
            .iter()
            .map(|tag| tag.as_str().to_owned())
            .collect(),
        colour: node.colour.clone(),
        protocol,
        host,
        port,
        username: identity.map(|props| props.username.clone()),
        secret_kind: identity.map(|props| secret_kind_label(&props.secret).to_owned()),
        key_format: identity.and_then(|props| match props.secret {
            SecretKind::PrivateKey { format, .. } => Some(key_format_wire(format).to_owned()),
            _ => None,
        }),
        has_passphrase: identity.is_some_and(|props| {
            matches!(
                &props.secret,
                SecretKind::PrivateKey {
                    sealed_passphrase: Some(_),
                    ..
                }
            )
        }),
        agent_comment_filter: identity.and_then(|props| match &props.secret {
            SecretKind::Agent { comment_filter } => comment_filter.clone(),
            _ => None,
        }),
        credential_id: node
            .credential_field()
            .and_then(Inherited::explicit)
            .map(|credential| credential.id().to_string()),
        attached_credential_id: own_attached_credential(tree, node).map(|id| id.to_string()),
        attached_to: node
            .kind
            .as_credential()
            .and_then(|props| props.attached_to)
            .map(|owner| owner.to_string()),
        // Set by the two commands that can change it, on the node they return.
        credential_change: None,
        inherited_field_count: counts.get(&node.id).copied().unwrap_or_default(),
        updated_at: node.updated_at,
    }
}

impl NodeDto {
    /// Records what an edit did to the connection's own credential.
    #[must_use]
    fn with_credential_change(mut self, change: Option<&'static str>) -> Self {
        self.credential_change = change.map(ToOwned::to_owned);
        self
    }
}

/// The wire spelling of what a credential authenticates with.
pub(crate) const fn secret_kind_label(secret: &SecretKind) -> &'static str {
    match secret {
        SecretKind::Password { .. } => "password",
        SecretKind::PrivateKey { .. } => "privateKey",
        SecretKind::Agent { .. } => "agent",
        SecretKind::External { .. } => "external",
        SecretKind::Certificate { .. } => "certificate",
    }
}

/// The wire spelling of a private key's container.
pub(crate) const fn key_format_wire(format: KeyFormat) -> &'static str {
    match format {
        KeyFormat::OpenSsh => "openssh",
        KeyFormat::Pkcs8 => "pkcs8",
        KeyFormat::PuttyPpk => "putty-ppk",
    }
}

/// The container's name as a person would say it.
pub(crate) const fn key_format_label(format: KeyFormat) -> &'static str {
    match format {
        KeyFormat::OpenSsh => "OpenSSH",
        KeyFormat::Pkcs8 => "PKCS#8",
        KeyFormat::PuttyPpk => "PuTTY PPK",
    }
}

/// How many nodes take at least one field from each node — the "inherits 3"
/// badge in the sidebar.
pub(crate) fn inheritance_counts(tree: &Tree) -> BTreeMap<NodeId, usize> {
    let mut counts: BTreeMap<NodeId, usize> = BTreeMap::new();

    for node in tree.nodes() {
        // A credential attached to a connection is not an inheritor: it is
        // part of one, and counting it would tell a folder it is inherited
        // from once more than the user can see.
        if is_attached_credential(node) {
            continue;
        }
        let mut sources: BTreeSet<NodeId> = BTreeSet::new();
        let id = node.id;

        note_source(tree, id, Node::port_field, &mut sources);
        note_source(tree, id, Node::credential_field, &mut sources);
        note_source(tree, id, Node::gateway_field, &mut sources);
        note_source(tree, id, Node::connect_timeout_field, &mut sources);
        note_source(tree, id, Node::keepalive_field, &mut sources);
        note_source(tree, id, Node::on_connect_field, &mut sources);
        note_source(tree, id, Node::on_disconnect_field, &mut sources);
        note_source(tree, id, Node::recording_field, &mut sources);
        note_source(tree, id, Node::auto_reconnect_field, &mut sources);
        note_plain_source(tree, node, Node::icon_field, &mut sources);
        note_plain_source(tree, node, Node::colour_field, &mut sources);

        for source in sources {
            *counts.entry(source).or_default() += 1;
        }
    }
    counts
}

/// Records the ancestor an inheritable field resolved to, if it was inherited
/// rather than set on the node itself.
fn note_source<T, F>(tree: &Tree, id: NodeId, field: F, out: &mut BTreeSet<NodeId>)
where
    T: Clone,
    F: for<'a> Fn(&'a Node) -> Option<&'a Inherited<T>>,
{
    if let Ok(resolved) = tree.resolve_optional(id, field) {
        if resolved.provenance.is_inherited() {
            if let Some(source) = resolved.provenance.source() {
                out.insert(source);
            }
        }
    }
}

/// The same, for the two fields that are a plain `Option<String>` on the node
/// rather than an `Inherited<T>`: the nearest ancestor that sets one wins.
fn note_plain_source<F>(tree: &Tree, node: &Node, field: F, out: &mut BTreeSet<NodeId>)
where
    F: for<'a> Fn(&'a Node) -> Option<&'a String>,
{
    if field(node).is_some() {
        return;
    }
    if let Ok(ancestors) = tree.ancestors(node.id) {
        for ancestor in ancestors {
            if field(ancestor).is_some() {
                out.insert(ancestor.id);
                return;
            }
        }
    }
}

/// "Datacentre EU-West / Web tier" — the ancestors of a node, root first.
fn breadcrumb(tree: &Tree, id: NodeId) -> String {
    let Ok(ancestors) = tree.ancestors(id) else {
        return String::new();
    };
    ancestors
        .iter()
        .rev()
        .map(|node| node.name.as_str())
        .collect::<Vec<_>>()
        .join(" / ")
}

/// The second line of a search hit.
fn subtitle(tree: &Tree, node: &Node) -> String {
    match &node.kind {
        NodeKind::Connection(props) => {
            let port = props
                .port
                .explicit()
                .copied()
                .or_else(|| props.protocol.default_port());
            match port {
                Some(port) => format!("{}://{}:{port}", props.protocol.as_str(), props.host),
                None => format!("{}://{}", props.protocol.as_str(), props.host),
            }
        }
        NodeKind::Credential(props) => match &props.domain {
            Some(domain) if !domain.is_empty() => format!("{domain}\\{}", props.username),
            _ => props.username.clone(),
        },
        NodeKind::Folder(_) => {
            let count = tree.children(Some(node.id)).len();
            if count == 1 {
                String::from("1 item")
            } else {
                format!("{count} items")
            }
        }
        NodeKind::Group(props) => {
            let count = props.members.len();
            if count == 1 {
                String::from("1 member")
            } else {
                format!("{count} members")
            }
        }
        NodeKind::Separator => String::new(),
    }
}

/// Character ranges in `name` that the query matched, for highlighting.
///
/// Offsets are character indices, which agree with the interface's string
/// indices for every name that is not outside the basic multilingual plane;
/// highlighting is cosmetic, so a surrogate pair shifting a highlight by one is
/// not worth carrying UTF-16 arithmetic through the boundary for.
fn match_ranges(name: &str, query: &str) -> Vec<(usize, usize)> {
    let needle: Vec<char> = query
        .trim()
        .chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect();
    if needle.is_empty() {
        return Vec::new();
    }
    let hay: Vec<char> = name
        .chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect();
    if needle.len() > hay.len() {
        return Vec::new();
    }

    let mut ranges = Vec::new();
    let mut start = 0usize;
    while start + needle.len() <= hay.len() {
        if hay[start..start + needle.len()] == needle[..] {
            ranges.push((start, start + needle.len()));
            start += needle.len();
        } else {
            start += 1;
        }
    }
    ranges
}

/// The inspector's view of a connection: every field, its value, and where the
/// value came from.
fn effective_dto(
    tree: &Tree,
    id: NodeId,
    effective: &EffectiveConnection,
) -> EffectiveConnectionDto {
    let parent = tree.get(id).and_then(|node| node.parent_id);
    let inherited = parent.map(|parent| resolved_values(tree, parent));

    let mut fields = Vec::new();
    fields.push(ResolvedFieldDto {
        field: String::from("host"),
        value: Some(effective.host.clone()),
        origin: String::from("own"),
        source_name: None,
        source_id: None,
        overrides: None,
    });

    let mut push = |field: &str, value: Option<String>, provenance: Provenance| {
        let overrides = match (&inherited, provenance) {
            (Some(values), Provenance::Own(_)) => values.get(field).cloned(),
            _ => None,
        };
        fields.push(resolved_field(tree, field, value, provenance, overrides));
    };

    push(
        "port",
        effective.port.value.map(|port| port.to_string()),
        effective.port.provenance,
    );
    push(
        "credential",
        effective
            .credential
            .value
            .as_ref()
            .map(|credential| credential_label(tree, credential)),
        effective.credential.provenance,
    );
    // The username resolves with the credential that holds it, so it carries
    // the same provenance: "set on this connection" when the credential is the
    // connection's own, "from 📁 Datacentre EU-West" when it is the folder's.
    push(
        "username",
        effective.username.value.clone(),
        effective.username.provenance,
    );
    push(
        "gateway",
        Some(gateway_label(tree, &effective.gateway.value)),
        effective.gateway.provenance,
    );
    push(
        "connect_timeout_ms",
        effective
            .connect_timeout_ms
            .value
            .map(|value| value.to_string()),
        effective.connect_timeout_ms.provenance,
    );
    push(
        "keepalive_secs",
        effective
            .keepalive_secs
            .value
            .map(|value| value.to_string()),
        effective.keepalive_secs.provenance,
    );
    push(
        "on_connect",
        actions_label(&effective.on_connect.value),
        effective.on_connect.provenance,
    );
    push(
        "on_disconnect",
        actions_label(&effective.on_disconnect.value),
        effective.on_disconnect.provenance,
    );
    push(
        "recording",
        Some(recording_label(effective.recording.value)),
        effective.recording.provenance,
    );
    push(
        "auto_reconnect",
        Some(reconnect_label(&effective.auto_reconnect.value)),
        effective.auto_reconnect.provenance,
    );
    push(
        "icon",
        effective.icon.value.clone(),
        effective.icon.provenance,
    );
    push(
        "colour",
        effective.colour.value.clone(),
        effective.colour.provenance,
    );

    for (key, resolved) in &effective.settings {
        fields.push(resolved_field(
            tree,
            &format!("settings.{key}"),
            Some(resolved.value.clone()),
            resolved.provenance,
            None,
        ));
    }

    EffectiveConnectionDto {
        node_id: id.to_string(),
        protocol: effective.protocol.as_str().to_owned(),
        fields,
        gateway_chain: effective
            .gateway
            .value
            .hops
            .iter()
            .map(|hop| node_ref_label(tree, &hop.node))
            .collect(),
        tags: tree
            .get(id)
            .map(|node| {
                node.tags
                    .iter()
                    .map(|tag| tag.as_str().to_owned())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default(),
        credential_attached: effective.credential_attached,
    }
}

fn resolved_field(
    tree: &Tree,
    field: &str,
    value: Option<String>,
    provenance: Provenance,
    overrides: Option<String>,
) -> ResolvedFieldDto {
    let origin = if provenance.is_inherited() {
        "inherited"
    } else if provenance.is_default() {
        "default"
    } else {
        "own"
    };
    let source = provenance.source();

    ResolvedFieldDto {
        field: field.to_owned(),
        value,
        origin: origin.to_owned(),
        source_name: source
            .and_then(|id| tree.get(id))
            .map(|node| node.name.clone()),
        source_id: source.map(|id| id.to_string()),
        overrides,
    }
}

/// The values a node resolves for each inheritable field, formatted the same
/// way as the connection's own — this is what an override shadows.
fn resolved_values(tree: &Tree, id: NodeId) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    if let Ok(resolved) = tree.resolve_optional(id, Node::port_field) {
        if let Some(port) = resolved.value {
            out.insert(String::from("port"), port.to_string());
        }
    }
    if let Ok(resolved) = tree.resolve_optional(id, Node::credential_field) {
        if let Some(credential) = resolved.value {
            out.insert(
                String::from("credential"),
                credential_label(tree, &credential),
            );
            // The username the connection would log in as if it set none of
            // its own — which is what an override here shadows, and what the
            // editor shows beneath it.
            if let Some(username) = referenced_username(tree, &credential) {
                out.insert(String::from("username"), username);
            }
        }
    }
    if let Ok(resolved) = tree.resolve_optional(id, Node::gateway_field) {
        if let Some(chain) = resolved.value {
            out.insert(String::from("gateway"), gateway_label(tree, &chain));
        }
    }
    if let Ok(resolved) = tree.resolve_optional(id, Node::connect_timeout_field) {
        if let Some(value) = resolved.value {
            out.insert(String::from("connect_timeout_ms"), value.to_string());
        }
    }
    if let Ok(resolved) = tree.resolve_optional(id, Node::keepalive_field) {
        if let Some(value) = resolved.value {
            out.insert(String::from("keepalive_secs"), value.to_string());
        }
    }
    if let Ok(resolved) = tree.resolve_optional(id, Node::on_connect_field) {
        if let Some(label) = resolved.value.as_ref().and_then(|v| actions_label(v)) {
            out.insert(String::from("on_connect"), label);
        }
    }
    if let Ok(resolved) = tree.resolve_optional(id, Node::on_disconnect_field) {
        if let Some(label) = resolved.value.as_ref().and_then(|v| actions_label(v)) {
            out.insert(String::from("on_disconnect"), label);
        }
    }
    if let Ok(resolved) = tree.resolve_optional(id, Node::recording_field) {
        if let Some(policy) = resolved.value {
            out.insert(String::from("recording"), recording_label(policy));
        }
    }
    if let Ok(resolved) = tree.resolve_optional(id, Node::auto_reconnect_field) {
        if let Some(policy) = resolved.value {
            out.insert(String::from("auto_reconnect"), reconnect_label(&policy));
        }
    }

    if let Ok(ancestors) = tree.ancestors(id) {
        let chain = tree.get(id).into_iter().chain(ancestors);
        for node in chain {
            if let Some(icon) = &node.icon {
                out.entry(String::from("icon"))
                    .or_insert_with(|| icon.clone());
            }
            if let Some(colour) = &node.colour {
                out.entry(String::from("colour"))
                    .or_insert_with(|| colour.clone());
            }
        }
    }

    out
}

fn credential_label(tree: &Tree, credential: &CredentialRef) -> String {
    node_ref_label(tree, credential.as_node_ref())
}

fn node_ref_label(tree: &Tree, reference: &NodeRef) -> String {
    match reference {
        NodeRef::Live(id) => tree
            .get(*id)
            .map_or_else(|| format!("unknown item {id}"), |node| node.name.clone()),
        NodeRef::Deleted { name, .. } => format!("{name} (deleted)"),
    }
}

fn gateway_label(tree: &Tree, chain: &GatewayChain) -> String {
    if chain.is_direct() {
        return String::from("Direct");
    }
    chain
        .hops
        .iter()
        .map(|hop| node_ref_label(tree, &hop.node))
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn actions_label(actions: &[String]) -> Option<String> {
    if actions.is_empty() {
        None
    } else {
        Some(actions.join("; "))
    }
}

fn recording_label(policy: RecordingPolicy) -> String {
    match policy {
        RecordingPolicy::Never => String::from("never"),
        RecordingPolicy::OnRequest => String::from("on request"),
        RecordingPolicy::Always => String::from("always"),
    }
}

fn reconnect_label(policy: &ReconnectPolicy) -> String {
    match policy {
        ReconnectPolicy::Never => String::from("never"),
        ReconnectPolicy::Retry {
            max_attempts,
            initial_backoff_ms,
            max_backoff_ms,
        } => format!(
            "up to {max_attempts} attempts, backing off from {initial_backoff_ms} ms to \
             {max_backoff_ms} ms"
        ),
    }
}

// ------------------------------------------------------- password strength --

/// The estimate behind [`password_strength`].
pub(crate) fn estimate_strength(password: &str) -> PasswordStrengthDto {
    let entropy = entropy_bits(password);
    let score = score_for(entropy);
    let label = match score {
        0 | 1 => "Weak",
        2 => "Fair",
        3 => "Good",
        _ => "Strong",
    };

    PasswordStrengthDto {
        score,
        entropy_bits: entropy,
        label: label.to_owned(),
        explanation: consequence(entropy),
        acceptable: entropy >= ACCEPTABLE_ENTROPY_BITS,
    }
}

/// Bits of entropy, by the most generous of three readings: a passphrase drawn
/// from the word list, a password on a known-bad list, or a character-pool
/// estimate discounted for repetition.
fn entropy_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    if let Some(bits) = passphrase_bits(password) {
        return bits;
    }
    if let Some(bits) = common_password_bits(password) {
        return bits;
    }
    pool_bits(password)
}

/// A phrase whose every word is on the list is worth `log2(list)` per word and
/// nothing for the separators, which are not secret.
///
/// The words are compared in place. Lower-casing each one into an owned
/// `String` would scatter copies of the candidate password across the heap,
/// and the wizard calls this on every keystroke.
fn passphrase_bits(password: &str) -> Option<f64> {
    let mut count = 0usize;
    for word in password.split(PASSPHRASE_SEPARATORS) {
        if word.is_empty() {
            continue;
        }
        if !WORDS.iter().any(|listed| listed.eq_ignore_ascii_case(word)) {
            return None;
        }
        count += 1;
    }
    if count < 2 {
        return None;
    }

    #[allow(clippy::cast_precision_loss)] // list length is 2048; exact in f64
    let per_word = (WORDS.len() as f64).log2();
    #[allow(clippy::cast_precision_loss)]
    let words = count as f64;
    Some(per_word * words)
}

/// The separators the generator uses and the ones a user is likely to type.
const PASSPHRASE_SEPARATORS: [char; 4] = ['-', ' ', '.', '_'];

/// A password on the known-bad list is worth its position in that list and
/// nothing more: an attacker tries them first, in order.
///
/// Compared without allocating: the list is ASCII, so an ASCII-insensitive
/// comparison against the candidate itself says the same thing as lower-casing
/// a copy of it would.
fn common_password_bits(password: &str) -> Option<f64> {
    let stem = common_stem(password);
    let position = COMMON_PASSWORDS.iter().position(|candidate| {
        candidate.eq_ignore_ascii_case(password) || candidate.eq_ignore_ascii_case(stem)
    })?;

    #[allow(clippy::cast_precision_loss)] // the list is 200 long
    let rank = (position + 1) as f64;
    let suffix_bits = if stem.len() == password.len() {
        0.0
    } else {
        10.0
    };
    Some(rank.log2() + suffix_bits)
}

/// The candidate with its trailing digits and exclamation marks removed, as a
/// slice of the candidate rather than a copy of it.
///
/// Trailing digits are the first thing a cracking rule tries, so
/// "password2024" is worth barely more than "password".
fn common_stem(password: &str) -> &str {
    password.trim_end_matches(|c: char| c.is_ascii_digit() || c == '!')
}

/// `length * log2(pool)`, with the length discounted for runs and repeats: an
/// attacker's rules exhaust "aaaaaaaa" and "abcdefgh" long before they get to
/// eight independent characters.
fn pool_bits(password: &str) -> f64 {
    let mut pool = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password
        .chars()
        .any(|c| c.is_ascii_punctuation() || c == ' ')
    {
        pool += 33;
    }
    if !password.is_ascii() {
        // Anything outside ASCII widens the pool considerably, but guessing it
        // is rare enough in practice that crediting the full Unicode range
        // would flatter the password.
        pool += 100;
    }
    if pool == 0 {
        return 0.0;
    }

    // Effective length: a character that repeats one already seen, or continues
    // a run, counts for half.
    //
    // The characters seen so far are tracked in a stack bitmap for ASCII and,
    // only if the candidate needs it, a zeroized buffer for the rest — rather
    // than collecting the password into a `Vec<char>` and a `BTreeSet<char>`,
    // which left two more copies of it in freed heap on every keystroke.
    let mut effective = 0.0f64;
    let mut seen_ascii = Zeroizing::new(0u128);
    let mut seen_wide: Zeroizing<Vec<u32>> = Zeroizing::new(Vec::new());
    let mut previous: Option<char> = None;

    for ch in password.chars() {
        let repeated = if ch.is_ascii() {
            let bit = 1u128 << (u32::from(ch) & 0x7f);
            let already = *seen_ascii & bit != 0;
            *seen_ascii |= bit;
            already
        } else {
            let point = u32::from(ch);
            match seen_wide.binary_search(&point) {
                Ok(_) => true,
                Err(at) => {
                    seen_wide.insert(at, point);
                    false
                }
            }
        };
        let sequential = previous.is_some_and(|previous| is_sequential(previous, ch));
        effective += if repeated || sequential { 0.5 } else { 1.0 };
        previous = Some(ch);
    }

    f64::from(pool).log2() * effective
}

/// Whether `next` continues a run from `previous` — "abc", "789", "cba".
fn is_sequential(previous: char, next: char) -> bool {
    let (a, b) = (previous.to_ascii_lowercase(), next.to_ascii_lowercase());
    if !a.is_ascii_alphanumeric() || !b.is_ascii_alphanumeric() {
        return false;
    }
    u32::from(a).abs_diff(u32::from(b)) == 1
}

/// zxcvbn's five buckets, by entropy rather than by guess count.
///
/// The top bucket starts at 64 bits so that the six-word passphrase the
/// creation wizard offers reads as "Strong" — 6 x 11 bits = 66. A generator
/// whose own output the strength meter grades as merely "Good" teaches the user
/// to distrust one of the two.
fn score_for(entropy: f64) -> u8 {
    if entropy < 28.0 {
        0
    } else if entropy < 40.0 {
        1
    } else if entropy < 52.0 {
        2
    } else if entropy < 64.0 {
        3
    } else {
        4
    }
}

/// The sentence that actually changes behaviour.
///
/// The rate quoted is a billion guesses a second, which is a plausible offline
/// attack on a fast machine. The vault's own Argon2id parameters make the real
/// rate several orders of magnitude lower; quoting the pessimistic figure keeps
/// the advice honest if the password is ever reused somewhere with a weaker
/// hash, which is where reused passwords actually die.
fn consequence(entropy: f64) -> String {
    // Half the keyspace, at 1e9 guesses a second.
    let seconds = (2.0f64).powf(entropy - 1.0) / 1e9;

    const MINUTE: f64 = 60.0;
    const HOUR: f64 = 60.0 * MINUTE;
    const DAY: f64 = 24.0 * HOUR;
    const MONTH: f64 = 30.0 * DAY;
    const YEAR: f64 = 365.25 * DAY;

    if seconds < 1.0 {
        return String::from("Guessed instantly at a billion attempts a second.");
    }
    if seconds < MINUTE {
        return format!(
            "About {} seconds of guessing at a billion attempts a second.",
            seconds.round().max(1.0)
        );
    }
    if seconds < HOUR {
        return format!(
            "About {} minutes of guessing at a billion attempts a second.",
            (seconds / MINUTE).round().max(1.0)
        );
    }
    if seconds < DAY {
        return format!(
            "About {} hours of guessing at a billion attempts a second.",
            (seconds / HOUR).round().max(1.0)
        );
    }
    if seconds < MONTH {
        return format!(
            "About {} days of guessing at a billion attempts a second.",
            (seconds / DAY).round().max(1.0)
        );
    }
    if seconds < YEAR {
        return format!(
            "About {} months of guessing at a billion attempts a second.",
            (seconds / MONTH).round().max(1.0)
        );
    }
    if seconds < 100.0 * YEAR {
        return format!(
            "About {} years of guessing at a billion attempts a second.",
            (seconds / YEAR).round().max(1.0)
        );
    }
    if seconds < 1.0e6 * YEAR {
        return String::from("Centuries of guessing at a billion attempts a second.");
    }
    String::from("Longer than the age of the universe at a billion attempts a second.")
}

/// The two hundred passwords that appear at the top of every breach corpus.
/// Not a substitute for a dictionary attack model — it is the floor, so that
/// the estimate never calls one of these "Strong" because it happens to be
/// eleven characters long.
const COMMON_PASSWORDS: &[&str] = &[
    "123456",
    "password",
    "123456789",
    "12345678",
    "12345",
    "qwerty",
    "1234567",
    "111111",
    "123123",
    "abc123",
    "1234567890",
    "1234",
    "password1",
    "iloveyou",
    "000000",
    "letmein",
    "monkey",
    "dragon",
    "sunshine",
    "princess",
    "football",
    "welcome",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "michael",
    "superman",
    "696969",
    "batman",
    "trustno1",
    "jordan",
    "harley",
    "hunter",
    "buster",
    "soccer",
    "tigger",
    "charlie",
    "andrew",
    "michelle",
    "jessica",
    "pepper",
    "daniel",
    "access",
    "flower",
    "matrix",
    "computer",
    "jennifer",
    "hello",
    "freedom",
    "whatever",
    "qazwsx",
    "starwars",
    "passw0rd",
    "zaq1zaq1",
    "login",
    "admin",
    "administrator",
    "root",
    "toor",
    "guest",
    "test",
    "changeme",
    "secret",
    "manager",
    "server",
    "oracle",
    "postgres",
    "mysql",
    "database",
    "backup",
    "system",
    "internet",
    "service",
    "default",
    "public",
    "private",
    "temp",
    "demo",
    "sample",
    "user",
    "users",
    "operator",
    "support",
    "helpdesk",
    "security",
    "network",
    "firewall",
    "router",
    "switch",
    "cisco",
    "linux",
    "windows",
    "ubuntu",
    "debian",
    "redhat",
    "centos",
    "apache",
    "nginx",
    "tomcat",
    "jenkins",
    "docker",
    "kubernetes",
    "azure",
    "amazon",
    "google",
    "hunter2",
    "letmein1",
    "welcome1",
    "welcome123",
    "password123",
    "p@ssword",
    "p@ssw0rd",
    "abcd1234",
    "a1b2c3d4",
    "qwerty123",
    "1q2w3e4r",
    "1qaz2wsx",
    "zxcvbnm",
    "asdfgh",
    "asdfghjkl",
    "poiuyt",
    "lkjhgf",
    "mnbvcxz",
    "qweasdzxc",
    "112233",
    "121212",
    "131313",
    "141414",
    "151515",
    "222222",
    "333333",
    "444444",
    "555555",
    "777777",
    "888888",
    "999999",
    "101010",
    "abcdef",
    "abcdefg",
    "aaaaaa",
    "zzzzzz",
    "asdf1234",
    "qwer1234",
    "test123",
    "temp123",
    "admin123",
    "root123",
    "toor123",
    "pass",
    "passwd",
    "secret1",
    "secure",
    "letmein123",
    "openup",
    "opensesame",
    "sesame",
    "friend",
    "summer",
    "winter",
    "spring",
    "autumn",
    "january",
    "february",
    "december",
    "monday",
    "friday",
    "chocolate",
    "cookie",
    "banana",
    "orange",
    "purple",
    "yellow",
    "silver",
    "golden",
    "diamond",
    "phoenix",
    "falcon",
    "eagle",
    "raven",
    "wolf",
    "tiger",
    "lion",
    "bear",
    "shark",
    "cobra",
    "viper",
    "ranger",
    "hunter1",
    "sniper",
    "warrior",
    "knight",
    "wizard",
    "merlin",
    "gandalf",
    "frodo",
    "legolas",
    "aragorn",
    "skywalker",
    "vader",
    "yoda",
    "spock",
    "kirk",
    "picard",
    "neo",
    "morpheus",
    "trinity",
    "smith",
    "anderson",
];

/// The word list a generated passphrase is drawn from.
///
/// 2048 words, every one of them 4–7 lowercase ASCII letters, so a word is
/// worth exactly 11 bits and a six-word phrase 66. It is not the EFF's 7776
/// word list: that would be 12.9 bits a word, but it carries an attribution
/// requirement, and a list written here is one fewer thing to keep in step with
/// an upstream. The entropy figures reported by `password_strength` are
/// computed from `WORDS.len()` rather than from a remembered constant, so
/// growing this list improves them automatically.
///
/// Properties the tests enforce: no duplicates, no word outside `[a-z]{4,7}`,
/// and a length that is an exact power of two.
const WORDS: &[&str] = &[
    "abacus", "abbey", "able", "absent", "academy", "accept", "acorn", "active", "actor", "actual",
    "address", "adjust", "adopt", "advice", "advisor", "agent", "agile", "agree", "aide",
    "airport", "airy", "alarm", "album", "alcove", "alert", "algae", "algebra", "alike", "alive",
    "almond", "alpine", "alter", "amaze", "amber", "amend", "ample", "amuse", "ancient", "angry",
    "ankle", "annual", "anthem", "anthill", "anxious", "apple", "approve", "apricot", "april",
    "arena", "argue", "armor", "armory", "arrive", "artery", "article", "artist", "ascot",
    "ashtray", "aspen", "assist", "assume", "athlete", "attach", "attend", "attic", "attract",
    "august", "aurora", "author", "avenue", "aviator", "avocado", "aware", "awkward", "axis",
    "baby", "badge", "bagel", "balance", "balcony", "ball", "ballet", "balloon", "ballot",
    "bamboo", "bandage", "bandana", "bangle", "banjo", "banker", "bare", "bargain", "bark",
    "barley", "barn", "baron", "barrel", "basic", "basil", "basis", "basket", "bathe", "batter",
    "beach", "beaker", "beam", "bear", "beat", "bedrock", "beef", "beet", "beetle", "beggar",
    "begin", "behave", "beige", "belief", "believe", "bell", "bellows", "belong", "belt", "bend",
    "beret", "bicycle", "binder", "biology", "birch", "bird", "biscuit", "bishop", "bison",
    "black", "blade", "blank", "blanket", "blazer", "bleak", "blind", "block", "blond", "blood",
    "blouse", "bluff", "blunt", "blush", "boar", "board", "boast", "boat", "boil", "bolt",
    "bonnet", "bonus", "book", "boot", "borrow", "bossy", "botany", "bottle", "bough", "bounce",
    "bowl", "bowling", "boxer", "bracket", "brain", "bran", "branch", "brave", "bread", "breath",
    "brew", "bribe", "brick", "bridge", "brief", "bright", "brisk", "broad", "broker", "bronze",
    "brooch", "brook", "brow", "brown", "browse", "brunch", "bucket", "buckle", "budget", "buggy",
    "build", "builder", "bulb", "bull", "bump", "bumper", "bumpy", "bundle", "bunk", "buoy",
    "burly", "burn", "burst", "bury", "busy", "butcher", "butler", "butter", "button", "cabinet",
    "caboose", "cactus", "caddie", "cadence", "cadet", "cafe", "cake", "calm", "camel", "camera",
    "campus", "canal", "cancel", "cane", "canoe", "canteen", "canvas", "canyon", "cape", "capitol",
    "capture", "caramel", "caravan", "card", "care", "career", "careful", "carrot", "cart",
    "carton", "cashier", "cask", "casket", "cast", "castle", "casual", "catch", "cattle", "cause",
    "cease", "cedar", "cell", "census", "central", "century", "certain", "change", "chapel",
    "chapter", "chart", "charter", "chasm", "chassis", "chat", "chateau", "cheap", "cheek",
    "cheer", "chef", "chemist", "cherry", "chess", "chest", "chew", "chief", "chili", "chill",
    "chilly", "chimp", "chin", "chisel", "choice", "choir", "choose", "chop", "chord", "chorus",
    "church", "chutney", "cider", "cinema", "circle", "city", "civil", "claim", "clam", "clamp",
    "clasp", "class", "clause", "clean", "clear", "cleaver", "clerk", "clever", "cliff", "climate",
    "clinic", "cloak", "clock", "close", "closet", "cloth", "cloudy", "clove", "clumsy", "clutch",
    "coach", "coast", "coaster", "coat", "cobra", "coffee", "coffer", "coin", "cold", "collar",
    "collect", "college", "colonel", "comb", "combine", "comet", "comfort", "comment", "commit",
    "common", "compose", "compost", "concern", "condor", "conduct", "confess", "connect",
    "consult", "contain", "convert", "convoy", "cooper", "copper", "copse", "copy", "cord", "cork",
    "corn", "correct", "corset", "costly", "cottage", "cotton", "couch", "cough", "courage",
    "courier", "court", "cover", "coyote", "cozy", "crab", "cracker", "cradle", "crate", "crater",
    "cravat", "crawl", "crazy", "cream", "creamy", "create", "credit", "creep", "crepe", "crest",
    "crevice", "cricket", "crimson", "crisis", "crisp", "croquet", "cross", "crouton", "crow",
    "crowded", "crown", "cruiser", "crunchy", "crust", "crystal", "cube", "cuddly", "culture",
    "cupcake", "curator", "curb", "curd", "cure", "curl", "curling", "curly", "current", "curry",
    "curtain", "cushion", "cute", "cycling", "cymbal", "dagger", "dairy", "dancer", "dapper",
    "dare", "daring", "dart", "dash", "date", "dawn", "dean", "dear", "decade", "decide",
    "decimal", "deck", "declare", "deep", "defend", "defense", "define", "deliver", "delta",
    "dense", "dentist", "depart", "depend", "depot", "derby", "descend", "deserve", "design",
    "desire", "dessert", "destroy", "detail", "detour", "develop", "devote", "dewy", "dial",
    "dialect", "diaper", "diary", "dice", "dill", "dimple", "dine", "diner", "dinghy", "dingo",
    "dinner", "diploma", "dish", "dismiss", "display", "distant", "dive", "divide", "dizzy",
    "dock", "dogsled", "doll", "dome", "donate", "donkey", "door", "dotted", "dough", "dove",
    "dragon", "draw", "drawer", "dream", "dreamy", "dress", "dresser", "dribble", "drift", "drill",
    "drink", "drive", "driver", "drizzle", "drop", "drought", "drum", "drummer", "dryer", "dual",
    "duck", "duke", "dull", "dune", "dusty", "dwell", "eager", "early", "earn", "earth", "easy",
    "echo", "eclipse", "edit", "edition", "editor", "effort", "elbow", "elder", "elect", "elegant",
    "ellipse", "embassy", "ember", "emblem", "embrace", "employ", "energy", "enjoy", "enrich",
    "enter", "equal", "equator", "equinox", "erosion", "escape", "essay", "estate", "estuary",
    "evening", "exact", "exam", "examine", "example", "exceed", "excite", "exhale", "exhibit",
    "exit", "exotic", "expand", "expect", "expense", "expert", "explain", "explore", "express",
    "extend", "fable", "fact", "factory", "fail", "falcon", "false", "fancy", "fare", "farmer",
    "fasten", "fatal", "faucet", "fawn", "fear", "feature", "fedora", "feeble", "feel", "fence",
    "fennel", "ferret", "ferry", "fertile", "fever", "fiction", "fiddler", "fiery", "fight",
    "filet", "fill", "film", "filter", "final", "find", "fine", "finger", "finish", "firm", "fish",
    "fisher", "fist", "fixture", "flag", "flame", "flannel", "flask", "flat", "flea", "flee",
    "fleece", "fleet", "flight", "flint", "flood", "flora", "florist", "flour", "flower", "fluffy",
    "flute", "flutter", "foal", "foil", "fold", "folder", "follow", "fond", "fondue", "foot",
    "forbid", "forearm", "forest", "forgive", "formal", "former", "forum", "fossil", "founder",
    "foundry", "fragile", "freckle", "freeze", "freezer", "freight", "fresh", "friday", "frigid",
    "fritter", "frock", "frog", "frost", "frosty", "frozen", "fruit", "fudge", "fuel", "fumble",
    "funnel", "funny", "furnace", "furry", "future", "fuzzy", "gain", "galaxy", "galley", "gallop",
    "gangway", "garage", "garden", "garlic", "gate", "gather", "gaze", "gazebo", "gear", "gelatin",
    "geyser", "gift", "giggle", "girdle", "give", "glacier", "glad", "glance", "gland", "glen",
    "glide", "gloomy", "glossy", "glow", "gnaw", "goalie", "goat", "gong", "good", "gorilla",
    "gossip", "gouda", "govern", "gown", "grab", "gradual", "grain", "grammar", "granary",
    "granite", "granola", "grant", "grape", "grasp", "gravel", "gravity", "gray", "graze", "great",
    "greedy", "green", "grill", "grim", "grin", "grip", "grocer", "groom", "grotto", "grouse",
    "grove", "grow", "gruff", "gulf", "gully", "gulp", "gumbo", "gunner", "gust", "gutter",
    "gymnast", "hair", "hairpin", "hall", "hamlet", "hammer", "handbag", "handle", "handy", "hang",
    "hanger", "hankie", "happy", "hard", "hare", "harmony", "harp", "harper", "harsh", "hasty",
    "hatch", "haul", "hawk", "haze", "head", "health", "healthy", "hear", "heater", "heath",
    "heavy", "hedge", "helmet", "help", "herald", "herder", "heron", "hide", "high", "highway",
    "hike", "hiking", "hill", "hint", "hippo", "hire", "hockey", "hoist", "hold", "hollow",
    "homely", "honest", "honey", "honor", "hood", "hoodie", "hook", "hoop", "hope", "hopeful",
    "horn", "horse", "hotel", "hour", "house", "howl", "hull", "humid", "humor", "hungry",
    "hunter", "hurdle", "hurl", "hurry", "husky", "hydrant", "hyena", "hymn", "ibex", "idea",
    "iguana", "image", "imagine", "immense", "import", "improve", "inform", "inherit", "injury",
    "inkwell", "inquire", "insect", "insert", "inspect", "instant", "integer", "invent", "invest",
    "invite", "iron", "island", "isle", "issue", "jackal", "jacket", "jaguar", "janitor",
    "january", "jargon", "jazz", "jelly", "jester", "jetty", "jeweler", "jockey", "journey",
    "judge", "judo", "juggle", "juggler", "jump", "jumper", "jungle", "juror", "justice", "karate",
    "kayak", "keel", "keep", "keeper", "kick", "kilt", "kimono", "kind", "kindle", "kindly",
    "kingdom", "kiss", "kitchen", "kiwi", "knee", "kneel", "knife", "knit", "knob", "knock",
    "know", "known", "knuckle", "koala", "krill", "label", "laborer", "lace", "lagoon", "lake",
    "lamb", "lame", "lamp", "land", "lane", "lapel", "laptop", "lard", "large", "lark", "last",
    "late", "laugh", "launch", "lava", "lawful", "lawn", "lawyer", "lead", "leaf", "leafy",
    "league", "lean", "leap", "leather", "leave", "lecture", "ledge", "ledger", "leek", "legal",
    "legging", "leisure", "lemon", "lemur", "lens", "lentil", "leopard", "lessen", "lesson",
    "letter", "lettuce", "level", "lever", "liberty", "library", "license", "lichen", "lick",
    "lift", "lighter", "lily", "lime", "limit", "link", "lion", "listen", "live", "lively",
    "liver", "lizard", "llama", "loaf", "loafer", "loam", "loan", "lobby", "lobster", "local",
    "lock", "locker", "locket", "locust", "lodge", "loft", "logic", "lone", "long", "look", "loom",
    "loon", "loosen", "lorry", "lose", "lotion", "loud", "love", "lower", "loyal", "loyalty",
    "lucky", "luge", "luggage", "lumber", "lunar", "lunch", "lung", "lute", "lynx", "lyric",
    "macaw", "magenta", "magma", "magnet", "magnify", "mail", "mailbox", "main", "major", "mammal",
    "mammoth", "manage", "manager", "mango", "manor", "mansion", "many", "marble", "march", "mare",
    "mark", "marker", "market", "marlin", "marry", "marsh", "marshal", "marten", "mask", "mason",
    "mast", "match", "math", "mature", "mayor", "meadow", "meaning", "medal", "medic", "meek",
    "meet", "mellow", "melody", "memoir", "mend", "menu", "merry", "meteor", "method", "metro",
    "midday", "mighty", "mileage", "milk", "mill", "miller", "millet", "mimic", "mingle",
    "minivan", "minnow", "minor", "mirror", "mission", "mist", "mite", "mitt", "mitten", "mixer",
    "moan", "modern", "modify", "module", "moist", "moisten", "mold", "mole", "mollusk", "moment",
    "monday", "monitor", "monk", "monkey", "month", "moose", "moral", "morning", "moss", "motel",
    "motive", "motor", "motto", "mound", "mouse", "mouth", "muddy", "muffin", "mule", "murky",
    "muscle", "museum", "music", "mussel", "mustard", "mutton", "myth", "name", "napkin",
    "narrate", "nature", "neat", "necktie", "nectar", "needle", "needy", "nerve", "nest", "next",
    "nice", "night", "noble", "noisy", "noodle", "noon", "normal", "nose", "nostril", "nosy",
    "notepad", "notice", "notion", "nougat", "nourish", "novel", "nozzle", "nudge", "numb",
    "numeral", "nurse", "oatmeal", "object", "oboe", "observe", "obvious", "occupy", "occur",
    "ocean", "octopus", "offense", "offer", "officer", "oily", "olive", "omelet", "omit", "onion",
    "open", "operate", "opinion", "opossum", "option", "orca", "order", "orderly", "oregano",
    "organic", "osprey", "outcome", "outer", "outfit", "outline", "outpost", "oyster", "pace",
    "pack", "packet", "padlock", "pail", "paint", "palace", "pale", "pancake", "panda", "panther",
    "pantry", "papaya", "paper", "parcel", "pardon", "parfait", "park", "parka", "parlor",
    "parrot", "parsnip", "part", "partial", "partner", "pass", "passive", "past", "paste",
    "pastry", "pasture", "patch", "patient", "patron", "pattern", "pause", "payment", "peach",
    "peacock", "peak", "peanut", "pear", "pearly", "peat", "pebble", "pecan", "peddler", "peek",
    "pencil", "penguin", "pennant", "pepper", "perch", "perfect", "perform", "permit", "persist",
    "petite", "phone", "photo", "physics", "piccolo", "pick", "pickle", "picture", "pike", "pilaf",
    "pile", "pinch", "pine", "pinky", "pioneer", "pipe", "piston", "pitch", "pitcher", "place",
    "plain", "plan", "planet", "plaque", "plastic", "plateau", "platter", "play", "playoff",
    "plead", "please", "pledge", "plow", "plumber", "plunge", "pocket", "poet", "point", "policy",
    "polish", "polka", "polo", "poncho", "pond", "poor", "poplar", "poppy", "porch", "pork",
    "porter", "portion", "portray", "pose", "posh", "possess", "post", "potato", "potter", "pouch",
    "pounce", "prairie", "praise", "prawn", "preach", "precise", "predict", "preface", "prefer",
    "prelude", "premium", "prepare", "present", "pretty", "pretzel", "prevent", "price", "pride",
    "prime", "printer", "prism", "prison", "private", "prize", "process", "produce", "program",
    "project", "promise", "prompt", "proof", "propose", "protect", "protest", "proverb", "provide",
    "prune", "publish", "puck", "pudding", "puffin", "puffy", "pull", "pulse", "puma", "pump",
    "pumpkin", "punch", "pure", "purple", "purpose", "purse", "pursue", "push", "puzzle",
    "pyramid", "python", "quail", "quaint", "quarry", "quarter", "quartz", "quay", "query",
    "quest", "quiche", "quick", "quicken", "quiet", "quill", "quilt", "quinoa", "quiz", "quota",
    "quote", "rabbit", "race", "rack", "racket", "radio", "radius", "raft", "rail", "railing",
    "rain", "raise", "raisin", "rake", "rally", "ramble", "ranch", "rancher", "rank", "rapids",
    "rare", "rate", "raven", "ravioli", "razor", "reach", "read", "ready", "real", "realize",
    "reap", "rebuild", "recess", "recipe", "recite", "record", "reduce", "reflect", "reform",
    "refrain", "refuge", "refuse", "regal", "regard", "reggae", "region", "regular", "reject",
    "relax", "release", "relief", "remain", "remark", "remind", "remote", "rent", "repair",
    "replace", "reptile", "request", "require", "rescue", "reserve", "reside", "respond", "rest",
    "restore", "result", "retire", "reunion", "reverse", "review", "rhino", "rhythm", "rice",
    "rich", "ride", "rider", "ridge", "rift", "rigid", "rinse", "rise", "risk", "risotto",
    "ritual", "rival", "roadway", "roar", "roast", "robe", "robin", "rock", "rodent", "rodeo",
    "rooster", "root", "roster", "rosy", "rotate", "round", "route", "routine", "rugged", "ruin",
    "rule", "ruler", "rumor", "runner", "runway", "rural", "rush", "rusty", "sabbath", "sacred",
    "safe", "saffron", "saga", "sage", "sailing", "salad", "salami", "salary", "salmon", "salsa",
    "salt", "salute", "sand", "sandal", "sandbar", "sapling", "sardine", "sari", "sarong", "sash",
    "sauce", "savanna", "save", "savory", "scale", "scallop", "scalp", "scan", "scar", "scarce",
    "scarf", "scarlet", "scheme", "scholar", "school", "science", "scold", "scooter", "scope",
    "scratch", "screen", "screw", "seafood", "search", "season", "seat", "section", "sector",
    "seed", "select", "sell", "seminar", "senator", "send", "serene", "series", "serpent",
    "sesame", "session", "setting", "settle", "severe", "shabby", "shady", "shaggy", "shake",
    "shale", "shallot", "shallow", "shark", "sharp", "shave", "shawl", "shed", "sheer", "sheet",
    "sherbet", "sheriff", "shift", "shine", "shiny", "ship", "shirt", "shiver", "shooter", "shore",
    "short", "shorts", "shout", "shovel", "shower", "shrimp", "shrine", "shrub", "shrug", "shut",
    "shutter", "sick", "sieve", "sigh", "signal", "silent", "silly", "silo", "silt", "simile",
    "simple", "sincere", "sinew", "sing", "singer", "single", "sitar", "skater", "skiing", "skill",
    "skillet", "skin", "skip", "skipper", "skunk", "slack", "slacks", "slam", "slate", "slaw",
    "sleep", "sleepy", "sleeve", "slender", "slice", "slide", "slight", "slim", "slipper",
    "slogan", "slope", "sloth", "slow", "slush", "small", "smell", "smith", "smoke", "smoky",
    "smooth", "snack", "sneeze", "snore", "snow", "soak", "soar", "soccer", "socket", "soil",
    "solar", "soldier", "sole", "solemn", "solo", "solve", "sonata", "song", "soprano", "sorbet",
    "sorry", "sort", "sound", "soup", "sour", "source", "spade", "span", "spare", "sparrow",
    "spatula", "speak", "speaker", "speedy", "spell", "sphere", "spice", "spicy", "spiky", "spill",
    "spin", "spinach", "splash", "spleen", "splint", "spoke", "sponge", "spot", "spotted", "spout",
    "sprain", "spray", "spread", "sprint", "squad", "square", "stable", "stack", "stadium",
    "stage", "stain", "stale", "stalk", "stamp", "stand", "stanza", "stapler", "star", "stare",
    "start", "startle", "station", "status", "stay", "steady", "steak", "steam", "steep",
    "steeple", "steer", "stem", "steward", "stir", "stock", "stone", "stoop", "store", "stork",
    "stout", "stove", "strap", "straw", "stream", "street", "strict", "stride", "striped",
    "stroke", "strong", "strudel", "strum", "studio", "sturdy", "subject", "submit", "subtle",
    "succeed", "sudden", "suede", "sugar", "suite", "summit", "summon", "sundae", "sundial",
    "superb", "supper", "supply", "support", "suppose", "sure", "surf", "surgeon", "surgery",
    "survey", "survive", "suspect", "swamp", "swan", "sway", "swear", "sweat", "sweater", "sweep",
    "swift", "swim", "swimmer", "switch", "symbol", "syrup", "table", "tablet", "tack", "tactic",
    "taffy", "tailor", "tale", "tank", "tart", "task", "tassel", "taste", "tavern", "teach",
    "teacher", "teapot", "tear", "tell", "temple", "tenant", "tend", "tender", "tendon", "tennis",
    "tenor", "tense", "tent", "term", "terrace", "terrier", "test", "theater", "theme", "theorem",
    "therapy", "thick", "thigh", "thin", "thirsty", "thread", "thrifty", "thrive", "throat",
    "throne", "throw", "thumb", "thump", "thunder", "ticket", "tide", "tight", "tights", "tile",
    "tilt", "timbre", "timely", "tinker", "tiny", "tire", "tired", "toad", "toast", "toaster",
    "today", "toil", "token", "toll", "tomato", "tone", "tongue", "tonic", "tonight", "toolbox",
    "tooth", "topic", "torch", "torso", "total", "toucan", "tough", "tour", "tourist", "towel",
    "trace", "track", "traffic", "trail", "trailer", "tram", "transit", "trap", "trapper",
    "travel", "trawler", "tray", "tread", "treat", "tree", "trellis", "tremble", "tribute",
    "tricky", "trim", "trip", "triple", "tripod", "triumph", "trolley", "trophy", "trot", "trowel",
    "truce", "truffle", "trust", "trustee", "trusty", "truth", "tuba", "tube", "tuesday", "tumble",
    "tuna", "tundra", "tune", "tunic", "turban", "turn", "turnip", "turret", "tutor", "tuxedo",
    "twig", "twist", "ukulele", "umpire", "unfold", "uniform", "unique", "unit", "unite", "united",
    "unpack", "unroll", "unruly", "unwrap", "upbeat", "uphold", "upper", "upright", "urban",
    "urchin", "urgent", "useful", "usher", "usual", "utter", "vacant", "vacuum", "valid", "valley",
    "valve", "vanish", "vapor", "variety", "vary", "vase", "vast", "vault", "veal", "vector",
    "veggie", "veil", "vein", "velvet", "vent", "venture", "verb", "verdict", "verify", "vertex",
    "veteran", "viaduct", "vibrate", "vibrato", "view", "vine", "vinegar", "viola", "violet",
    "violin", "viper", "virtue", "visit", "visor", "vital", "vitamin", "vocal", "voice", "volcano",
    "vote", "vulture", "wade", "wage", "wagon", "waist", "wait", "wake", "walk", "wall", "wallet",
    "walnut", "wander", "warden", "warm", "warn", "warning", "warrior", "wary", "wash", "waste",
    "watch", "watery", "wave", "wavy", "wealth", "wealthy", "weary", "weasel", "weave", "week",
    "weekday", "weep", "weigh", "welcome", "welder", "welfare", "western", "whale", "wharf",
    "wheat", "whip", "whisper", "wick", "wicked", "widen", "wild", "willow", "wind", "window",
    "windy", "wing", "winter", "wipe", "wish", "witness", "witty", "wizard", "wobbly", "wolf",
    "wombat", "wonder", "wood", "wooden", "wool", "worm", "worry", "worth", "wrap", "wren",
    "wrench", "wrestle", "wrist", "write", "writer", "yacht", "yank", "yarn", "yawn", "year",
    "yearly", "yearn", "young", "zebra", "zipper", "zither", "zoology", "zoom",
];

#[cfg(test)]
mod tests {
    use super::*;

    // Only the tests build a settings DTO by hand, so it is imported here
    // rather than at the top of the module.
    use crate::dto::TerminalAppearanceDto;

    /// A directory of our own under the system temporary directory, removed
    /// when the guard drops. `tempfile` is not a dependency of this crate and
    /// adding one for four lines would be worse than the four lines.
    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("remoter-ipc-{}", Uuid::now_v7().simple()));
            let _ = fs::create_dir_all(&path);
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// A master password the entropy gate accepts, for the tests that need a
    /// vault rather than a password. Six words from the list: 66 bits.
    const PASSPHRASE: &str = "acorn-basil-cedar-drift-ember-fable";

    /// The command implementations take their request by reference so the
    /// password can be moved out of it before anything fallible runs; these
    /// two keep the tests below reading as calls.
    fn create_node(state: &AppState, mut input: CreateNodeDto) -> Result<NodeDto, IpcError> {
        node_create_impl(state, &mut input)
    }

    fn update_node(
        state: &AppState,
        id: String,
        mut patch: UpdateNodeDto,
    ) -> Result<NodeDto, IpcError> {
        node_update_impl(state, id, &mut patch)
    }

    /// The message from a failed call, for an assertion that wants to say why.
    fn why<T>(result: &Result<T, IpcError>) -> String {
        result
            .as_ref()
            .err()
            .map_or_else(String::new, |err| err.message.clone())
    }

    fn create_request(path: &Path, password: &str) -> CreateVaultRequestDto {
        CreateVaultRequestDto {
            path: path.display().to_string(),
            label: String::from("Test vault"),
            password: password.to_owned(),
            keyfile_path: None,
            generate_keyfile_at: None,
        }
    }

    fn connection(parent: Option<&str>, name: &str, host: &str) -> CreateNodeDto {
        CreateNodeDto {
            parent_id: parent.map(ToOwned::to_owned),
            kind: String::from("connection"),
            name: name.to_owned(),
            protocol: Some(String::from("ssh")),
            host: Some(host.to_owned()),
            port: None,
            username: None,
            password: None,
            credential: None,
            credential_id: None,
        }
    }

    fn folder(name: &str) -> CreateNodeDto {
        CreateNodeDto {
            parent_id: None,
            kind: String::from("folder"),
            name: name.to_owned(),
            protocol: None,
            host: None,
            port: None,
            username: None,
            password: None,
            credential: None,
            credential_id: None,
        }
    }

    /// One pass over the whole surface against a real vault file: create,
    /// build a tree, resolve, search, move, delete, lock, fail to unlock,
    /// unlock. Slow — it derives Argon2id at the calibrated cost several times
    /// — and worth it: everything it touches is the part that cannot be
    /// checked by reading the code.
    #[test]
    fn the_command_surface_round_trips_a_real_vault() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));
        let vault_path = scratch.join("test.rvault");
        let password = "correct-horse-battery-staple-42";

        // --- create -----------------------------------------------------
        let created = vault_create_impl(&state, create_request(&vault_path, password));
        assert!(
            created.is_ok(),
            "creating the vault failed: {}",
            why(&created)
        );
        let Ok(created) = created else { return };
        assert_eq!(created.recovery_key_groups.len(), 14);
        assert!(created.confirm_group_index < created.recovery_key_groups.len());
        assert!(created.kdf_summary.contains("Argon2id"));
        assert!(vault_path.is_file());

        let state_dto = vault_state_impl(&state).ok();
        assert!(state_dto.is_some_and(|state| state.unlocked));

        // The vault is remembered, and reachable.
        let recents = vault_list_recent_impl(&state).unwrap_or_default();
        assert_eq!(recents.len(), 1);
        assert!(recents.first().is_some_and(|entry| entry.reachable));

        // --- build a tree -----------------------------------------------
        let group = create_node(&state, folder("Datacentre"));
        assert!(group.is_ok(), "creating the folder failed: {}", why(&group));
        let Ok(group) = group else { return };
        assert_eq!(group.kind, "folder");

        let node = create_node(
            &state,
            connection(Some(&group.id), "web-1", "web1.example.com"),
        );
        assert!(
            node.is_ok(),
            "creating the connection failed: {}",
            why(&node)
        );
        let Ok(node) = node else { return };
        assert_eq!(node.parent_id.as_deref(), Some(group.id.as_str()));
        assert_eq!(node.port, Some(22), "the protocol default should show");

        let credential = create_node(
            &state,
            CreateNodeDto {
                parent_id: None,
                kind: String::from("credential"),
                name: String::from("root@web"),
                protocol: None,
                host: None,
                port: None,
                username: Some(String::from("root")),
                password: Some(String::from("hunter2")),
                credential: None,
                credential_id: None,
            },
        );
        assert!(
            credential.is_ok(),
            "a credential with a password should store"
        );

        let listed = tree_list_impl(&state).unwrap_or_default();
        assert_eq!(listed.len(), 3);

        // --- resolve ----------------------------------------------------
        let resolved = node_resolve_impl(&state, node.id.clone());
        assert!(resolved.is_ok(), "resolving failed: {}", why(&resolved));
        let Ok(resolved) = resolved else { return };
        assert_eq!(resolved.protocol, "ssh");
        assert!(resolved.fields.iter().any(|field| field.field == "host"));
        assert!(resolved.fields.iter().any(|field| field.field == "port"));
        assert!(
            resolved
                .fields
                .iter()
                .all(|field| ["own", "inherited", "default"].contains(&field.origin.as_str()))
        );

        // Only a connection resolves.
        assert!(node_resolve_impl(&state, group.id.clone()).is_err());

        // --- edit -------------------------------------------------------
        let renamed = update_node(
            &state,
            node.id.clone(),
            UpdateNodeDto {
                name: Some(String::from("web-primary")),
                description: Some(String::from("front end")),
                tags: Some(vec![String::from("production")]),
                colour: None,
                host: None,
                port: Some(2222),
                username: None,
                password: None,
                credential: None,
                credential_id: None,
                clear_overrides: None,
            },
        );
        assert!(
            renamed.is_ok(),
            "updating the connection failed: {}",
            why(&renamed)
        );
        let Ok(renamed) = renamed else { return };
        assert_eq!(renamed.name, "web-primary");
        assert_eq!(renamed.port, Some(2222));
        assert_eq!(renamed.tags, vec![String::from("production")]);

        // Clearing the override puts the protocol default back.
        let cleared = update_node(
            &state,
            node.id.clone(),
            UpdateNodeDto {
                name: None,
                description: None,
                tags: None,
                colour: None,
                host: None,
                port: None,
                username: None,
                password: None,
                credential: None,
                credential_id: None,
                clear_overrides: Some(vec![String::from("port")]),
            },
        );
        assert!(cleared.is_ok_and(|node| node.port == Some(22)));

        // A username typed on a connection gives that connection a credential
        // of its own, and the connection carries it.
        let named = update_node(
            &state,
            node.id.clone(),
            UpdateNodeDto {
                name: None,
                description: None,
                tags: None,
                colour: None,
                host: None,
                port: None,
                username: Some(String::from("nobody")),
                password: None,
                credential: None,
                credential_id: None,
                clear_overrides: None,
            },
        );
        assert!(named.is_ok(), "setting a username failed: {}", why(&named));
        let Ok(named) = named else { return };
        assert_eq!(named.username.as_deref(), Some("nobody"));
        assert_eq!(named.credential_change.as_deref(), Some("created"));
        assert!(named.attached_credential_id.is_some());

        // And it is not an entry of its own: the sidebar still shows the three
        // things the user made.
        let listed = tree_list_impl(&state).unwrap_or_default();
        assert_eq!(listed.len(), 3);

        // --- search -----------------------------------------------------
        let hits = tree_search_impl(&state, String::from("web-primary")).unwrap_or_default();
        assert!(hits.iter().any(|hit| hit.node.id == node.id));
        if let Some(hit) = hits.iter().find(|hit| hit.node.id == node.id) {
            assert_eq!(hit.path, "Datacentre");
            assert!(hit.subtitle.contains("web1.example.com"));
        }

        // --- move and delete --------------------------------------------
        assert!(node_move_impl(&state, node.id.clone(), None, 5).is_ok());
        let after_move = tree_list_impl(&state).unwrap_or_default();
        assert!(
            after_move
                .iter()
                .any(|listed| listed.id == node.id && listed.parent_id.is_none())
        );

        // A folder cannot be moved inside itself.
        assert!(node_move_impl(&state, group.id.clone(), Some(group.id.clone()), 0).is_err());

        assert!(node_delete_impl(&state, node.id.clone()).is_ok());
        let after_delete = tree_list_impl(&state).unwrap_or_default();
        assert!(after_delete.iter().all(|listed| listed.id != node.id));

        // --- lock and unlock --------------------------------------------
        assert!(vault_lock_impl(&state).is_ok());
        assert!(vault_state_impl(&state).is_ok_and(|state| !state.unlocked));
        // Nothing works while it is shut.
        assert!(tree_list_impl(&state).is_err());

        let wrong = vault_unlock_impl(
            &state,
            vault_path.display().to_string(),
            UnlockRequestDto::Password {
                password: String::from("not the password"),
                keyfile_path: None,
            },
        );
        assert!(
            wrong.is_err(),
            "the wrong password should not open the vault"
        );
        if let Err(err) = wrong {
            // Exactly this sentence, and nothing about which factor failed.
            assert_eq!(err.message, "That did not unlock the vault.");
            assert_eq!(err.code, "vault.unlock-failed");
            assert!(err.detail.is_none());
        }

        let opened = vault_unlock_impl(
            &state,
            vault_path.display().to_string(),
            UnlockRequestDto::Password {
                password: password.to_owned(),
                keyfile_path: None,
            },
        );
        assert!(
            opened.is_ok(),
            "the right password should open the vault: {}",
            why(&opened)
        );
        let Ok(opened) = opened else { return };
        assert!(opened.unlocked);
        assert_eq!(opened.label.as_deref(), Some("Test vault"));
        assert_eq!(opened.credential_count, 1);
        // The connection was deleted; the folder remains.
        assert_eq!(opened.connection_count, 0);
    }

    #[test]
    fn a_probe_of_something_that_is_not_a_vault_says_so() {
        let scratch = Scratch::new();
        let path = scratch.join("notes.txt");
        let _ = fs::write(&path, b"this is not a vault");

        let probed = vault_probe_impl(&AppState::new(), path.display().to_string());
        assert!(probed.is_err(), "a text file should not probe as a vault");
        if let Err(err) = probed {
            assert_eq!(err.code, "vault.not-a-vault");
            assert!(err.message.contains("notes.txt"));
            assert!(!err.actions.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_generated_key_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt as _;

        let scratch = Scratch::new();
        let path = scratch.join("second-factor.key");
        assert!(generate_keyfile(path.display().to_string()).is_ok());

        let mode = fs::metadata(&path)
            .map(|metadata| metadata.permissions().mode() & 0o777)
            .unwrap_or(0o777);
        assert_eq!(
            mode, 0o600,
            "the key file should never exist at any mode but 0600"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_that_cannot_be_restricted_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let scratch = Scratch::new();
        let path = scratch.join("world-readable.key");
        let _ = fs::write(&path, b"not really key material");
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o644));

        // What a FAT or exFAT stick looks like from here: the mode did not
        // take. Enrolling that as a second factor is refused, not warned about.
        let refused = verify_owner_only(&path);
        assert!(refused.is_err(), "a 0644 key file should be refused");
        if let Err(err) = refused {
            assert_eq!(err.code, "keyfile.unprotected");
            assert!(!err.actions.is_empty());
        }

        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        assert!(verify_owner_only(&path).is_ok());
    }

    #[test]
    fn a_weak_master_password_is_refused_by_the_command_not_only_the_wizard() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));
        let vault_path = scratch.join("weak.rvault");

        let refused = vault_create_impl(&state, create_request(&vault_path, "password123"));
        assert!(refused.is_err(), "a breached password should be refused");
        if let Err(err) = refused {
            assert_eq!(err.code, "vault.password-too-weak");
            assert!(
                err.actions
                    .iter()
                    .any(|action| action.contains("Generate a passphrase")),
                "actions were: {:?}",
                err.actions
            );
        }
        assert!(
            !vault_path.exists(),
            "nothing should have been written for a refused password"
        );
    }

    #[test]
    fn a_lock_that_cannot_write_the_vault_says_so_and_still_wipes_the_keys() {
        let scratch = Scratch::new();
        let directory = scratch.join("removable");
        let _ = fs::create_dir_all(&directory);
        let state = AppState::with_config_dir(scratch.join("config"));

        let created = vault_create_impl(
            &state,
            create_request(&directory.join("v.rvault"), PASSPHRASE),
        );
        assert!(
            created.is_ok(),
            "creating the vault failed: {}",
            why(&created)
        );

        // The share went away under the open vault — the case the warning used
        // to hide.
        let _ = fs::remove_dir_all(&directory);

        let locked = vault_lock_impl(&state);
        assert!(locked.is_err(), "a failed save must not report success");
        if let Err(err) = locked {
            assert_eq!(err.code, "vault.locked-unsaved");
            assert!(err.detail.is_some(), "the diagnostic should be copyable");
        }
        // The keys go whatever happens.
        assert!(vault_state_impl(&state).is_ok_and(|state| !state.unlocked));
    }

    #[test]
    fn an_auto_lock_that_cannot_write_the_vault_is_reported_by_the_next_poll() {
        let scratch = Scratch::new();
        let directory = scratch.join("removable");
        let _ = fs::create_dir_all(&directory);
        let state = AppState::with_config_dir(scratch.join("config"));

        let created = vault_create_impl(
            &state,
            create_request(&directory.join("v.rvault"), PASSPHRASE),
        );
        assert!(
            created.is_ok(),
            "creating the vault failed: {}",
            why(&created)
        );
        let _ = fs::remove_dir_all(&directory);

        {
            let mut guard = state.lock();
            guard.expire_activity();
        }

        let polled = vault_state_impl(&state);
        assert!(
            polled.is_err(),
            "the poll that auto-locks should carry the failed save"
        );
        if let Err(err) = polled {
            assert_eq!(err.code, "vault.locked-unsaved");
        }
        // Reported once; the poll after it is the ordinary locked state.
        assert!(vault_state_impl(&state).is_ok_and(|state| !state.unlocked));
    }

    #[test]
    fn repeated_failed_unlocks_are_made_to_wait_and_are_recorded_on_success() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));
        let vault_path = scratch.join("test.rvault");

        let created = vault_create_impl(&state, create_request(&vault_path, PASSPHRASE));
        assert!(
            created.is_ok(),
            "creating the vault failed: {}",
            why(&created)
        );
        assert!(vault_lock_impl(&state).is_ok());

        let wrong = || UnlockRequestDto::Password {
            password: String::from("not the password"),
            keyfile_path: None,
        };

        // One real attempt, to prove the command records what it refused, and
        // two more counted directly: each wrong password costs a full Argon2id
        // derivation, and three of them buy nothing this test needs.
        let failed = vault_unlock_impl(&state, vault_path.display().to_string(), wrong());
        assert!(
            failed.is_err_and(|err| err.code == "vault.unlock-failed"),
            "a wrong password should fail as a wrong password"
        );
        {
            let mut guard = state.lock();
            guard.record_unlock_failure(&vault_path);
            guard.record_unlock_failure(&vault_path);
        }

        // The fourth arrives inside the backoff, and says so distinctly enough
        // for the interface to render a countdown.
        let throttled = vault_unlock_impl(&state, vault_path.display().to_string(), wrong());
        assert!(throttled.is_err());
        if let Err(err) = throttled {
            assert_eq!(err.code, "vault.unlock-throttled");
            assert!(err.message.contains("seconds"), "message: {}", err.message);
        }

        // Nothing is locked out: once the wait is over the right password works.
        {
            let mut guard = state.lock();
            assert_eq!(guard.clear_unlock_failures(&vault_path), 3);
            guard.record_unlock_failure(&vault_path);
            guard.record_unlock_failure(&vault_path);
        }
        let opened = vault_unlock_impl(
            &state,
            vault_path.display().to_string(),
            UnlockRequestDto::Password {
                password: String::from(PASSPHRASE),
                keyfile_path: None,
            },
        );
        assert!(opened.is_ok(), "unlocking failed: {}", why(&opened));

        // The attempts could not be written while the vault was shut, so they
        // are in its audit log now.
        let guard = state.lock();
        let recorded = guard.vault_peek().and_then(|vault| {
            vault.audit_recent(16).ok().map(|entries| {
                entries
                    .iter()
                    .any(|(_, event, _, _)| event == AuditEvent::VaultUnlockFailed.as_str())
            })
        });
        assert_eq!(
            recorded,
            Some(true),
            "the failed attempts should reach the audit log on the next successful unlock"
        );
    }

    /// A vault created today is at the calibrated cost, so there is nothing to
    /// upgrade — which is the half of the promise this crate can construct.
    /// Building a below-floor vault needs `remoter-vault`'s `insecure-test-kdf`
    /// feature, which only that crate may switch on; the applied-upgrade path
    /// is covered by its own tests.
    #[test]
    fn a_vault_at_the_current_cost_is_offered_no_upgrade() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));
        let vault_path = scratch.join("current.rvault");

        let created = vault_create_impl(&state, create_request(&vault_path, PASSPHRASE));
        assert!(
            created.is_ok(),
            "creating the vault failed: {}",
            why(&created)
        );

        let polled = vault_state_impl(&state);
        assert!(polled.is_ok(), "polling failed: {}", why(&polled));
        assert!(
            polled.is_ok_and(|state| !state.kdf_upgrade_available),
            "a freshly created vault is already at the calibrated cost"
        );

        // Accepting an offer that was never made is not an error; it is a
        // no-op, so a stale window cannot fail on the user.
        let upgraded = vault_upgrade_kdf_impl(
            &state,
            UnlockRequestDto::Password {
                password: String::from(PASSPHRASE),
                keyfile_path: None,
            },
        );
        assert_eq!(upgraded.ok(), Some(false));
    }

    #[test]
    fn a_create_takes_the_password_out_of_the_request_before_it_can_fail() {
        let scratch = Scratch::new();
        // No vault is open, so `vault_mut` fails — the auto-lock case, which
        // is the one that used to drop the plaintext on the heap unwiped.
        let state = AppState::with_config_dir(scratch.join("config"));
        let mut input = CreateNodeDto {
            parent_id: None,
            kind: String::from("credential"),
            name: String::from("root@web"),
            protocol: None,
            host: None,
            port: None,
            username: Some(String::from("root")),
            password: Some(String::from("hunter2")),
            credential: None,
            credential_id: None,
        };

        let failed = node_create_impl(&state, &mut input);
        assert!(failed.is_err_and(|err| err.code == "vault.locked"));
        assert!(
            input.password.is_none(),
            "the password should have moved into a Secret before the first fallible step"
        );
    }

    #[test]
    fn an_update_takes_the_password_out_of_the_request_before_it_can_fail() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));
        let mut patch = UpdateNodeDto {
            name: None,
            description: None,
            tags: None,
            colour: None,
            host: None,
            port: None,
            username: None,
            password: Some(String::from("hunter2")),
            credential: None,
            credential_id: None,
            clear_overrides: None,
        };

        let failed = node_update_impl(&state, Uuid::now_v7().to_string(), &mut patch);
        assert!(failed.is_err_and(|err| err.code == "vault.locked"));
        assert!(
            patch.password.is_none(),
            "the password should have moved into a Secret before the first fallible step"
        );
    }

    #[test]
    fn a_generated_key_file_is_random_and_never_overwritten() {
        let scratch = Scratch::new();
        let first = scratch.join("one.key");
        let second = scratch.join("two.key");

        assert!(generate_keyfile(first.display().to_string()).is_ok());
        assert!(generate_keyfile(second.display().to_string()).is_ok());

        let one = fs::read(&first).unwrap_or_default();
        let two = fs::read(&second).unwrap_or_default();
        assert_eq!(one.len(), KEYFILE_BYTES);
        assert_ne!(one, two);

        // A second write to the same path is refused rather than destroying a
        // key file someone is depending on.
        assert!(generate_keyfile(first.display().to_string()).is_err());
    }

    #[test]
    fn commands_refuse_to_work_without_a_vault() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));

        let failure = tree_list_impl(&state).err();
        assert!(failure.is_some_and(|err| err.code == "vault.locked"));
        assert!(node_delete_impl(&state, Uuid::now_v7().to_string()).is_err());
        assert!(vault_state_impl(&state).is_ok_and(|state| !state.unlocked));
    }

    #[test]
    fn settings_round_trip_through_the_file() {
        let scratch = Scratch::new();
        let config = scratch.join("config");
        let state = AppState::with_config_dir(config.clone());

        let defaults = settings_get_impl(&state).unwrap_or_else(|_| AppSettingsDto {
            theme: String::new(),
            locale: String::new(),
            auto_lock_minutes: None,
            lock_on_screen_lock: false,
            lock_on_suspend: false,
            sidebar_width: 0,
            inspector_open: false,
            update_check_enabled: false,
            update_channel: String::new(),
            update_last_checked_at: None,
            terminal_prefix: String::new(),
            shortcuts: BTreeMap::new(),
            terminal: TerminalAppearanceDto::default(),
        });
        assert_eq!(defaults.theme, "system");
        // The shipped default is "follow the interface theme" with nothing
        // overridden, which resolves to the palette the application drew with
        // before any of it was configurable.
        assert_eq!(defaults.terminal.palette, "auto");
        assert!(defaults.terminal.overrides.is_empty());

        let patch: AppSettingsPatch =
            serde_json::from_str(r#"{"theme":"dark","autoLockMinutes":null}"#).unwrap_or_default();
        let patched = settings_set_impl(&state, patch);
        assert!(
            patched.is_ok_and(
                |settings| settings.theme == "dark" && settings.auto_lock_minutes.is_none()
            )
        );

        // A fresh state reads them back off disk.
        let reopened = AppState::with_config_dir(config);
        let settings = settings_get_impl(&reopened).ok();
        assert!(settings.is_some_and(|settings| settings.theme == "dark"));
    }

    #[test]
    fn a_terminal_palette_and_its_overrides_survive_a_restart() {
        let scratch = Scratch::new();
        let config = scratch.join("config");
        let state = AppState::with_config_dir(config.clone());

        // Short hex, upper case, and a translucent selection — all three are
        // shapes people actually paste, and all three have to come back in one
        // canonical form or "is this still the palette's colour?" stops being
        // a string comparison.
        let patch: AppSettingsPatch = serde_json::from_str(
            r##"{"terminal":{"palette":"nord","overrides":{"red":"#F00","selection":"#88C0D04D"},
                "fontFamily":"  Fira Code  ","fontSize":15}}"##,
        )
        .unwrap_or_default();
        let stored = settings_set_impl(&state, patch).ok();
        let stored = stored.map(|settings| settings.terminal);
        assert_eq!(
            stored.as_ref().map(|terminal| terminal.palette.as_str()),
            Some("nord")
        );
        assert_eq!(
            stored
                .as_ref()
                .and_then(|terminal| terminal.overrides.get("red"))
                .map(String::as_str),
            Some("#ff0000")
        );
        assert_eq!(
            stored
                .as_ref()
                .and_then(|terminal| terminal.overrides.get("selection"))
                .map(String::as_str),
            Some("#88c0d04d")
        );
        assert_eq!(
            stored
                .as_ref()
                .map(|terminal| terminal.font_family.as_str()),
            Some("Fira Code")
        );

        let reopened = AppState::with_config_dir(config);
        let read_back = settings_get_impl(&reopened).ok().map(|s| s.terminal);
        assert_eq!(read_back, stored);
    }

    #[test]
    fn a_terminal_appearance_that_is_not_one_is_refused() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));

        let unknown_palette: AppSettingsPatch = serde_json::from_str(
            r#"{"terminal":{"palette":"dracula","overrides":{},"fontFamily":"","fontSize":13}}"#,
        )
        .unwrap_or_default();
        assert!(settings_set_impl(&state, unknown_palette).is_err());

        let not_a_colour: AppSettingsPatch = serde_json::from_str(
            r#"{"terminal":{"palette":"auto","overrides":{"red":"crimson"},"fontFamily":"","fontSize":13}}"#,
        )
        .unwrap_or_default();
        assert!(settings_set_impl(&state, not_a_colour).is_err());

        let unknown_key: AppSettingsPatch = serde_json::from_str(
            r##"{"terminal":{"palette":"auto","overrides":{"puce":"#ff0000"},"fontFamily":"","fontSize":13}}"##,
        )
        .unwrap_or_default();
        assert!(settings_set_impl(&state, unknown_key).is_err());

        // A silly size is a slip of a spinner, not a lie about the world, so it
        // is clamped rather than refused.
        let huge: AppSettingsPatch = serde_json::from_str(
            r#"{"terminal":{"palette":"auto","overrides":{},"fontFamily":"","fontSize":400}}"#,
        )
        .unwrap_or_default();
        let clamped = settings_set_impl(&state, huge).ok();
        assert_eq!(
            clamped.map(|settings| settings.terminal.font_size),
            Some(32)
        );
    }

    #[test]
    fn a_suggested_path_is_a_vault_file_named_after_the_label() {
        let scratch = Scratch::new();
        let state = AppState::with_config_dir(scratch.join("config"));

        let suggested =
            suggest_vault_path_impl(&state, String::from("Production Vault")).unwrap_or_default();
        assert!(suggested.ends_with(".rvault"), "suggested: {suggested}");
        assert!(
            suggested.contains("production-vault"),
            "suggested: {suggested}"
        );
    }

    #[test]
    fn the_word_list_is_exactly_a_power_of_two() {
        assert_eq!(WORDS.len(), 2048);
    }

    #[test]
    fn every_word_is_short_lowercase_ascii() {
        for word in WORDS {
            assert!(
                (4..=7).contains(&word.len()),
                "`{word}` is {} characters",
                word.len()
            );
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase()),
                "`{word}` is not lowercase ASCII"
            );
        }
    }

    #[test]
    fn the_word_list_has_no_duplicates() {
        let unique: BTreeSet<&&str> = WORDS.iter().collect();
        assert_eq!(unique.len(), WORDS.len());
    }

    #[test]
    fn the_word_list_is_sorted() {
        // Sorted so that a duplicate added later is visible in the diff.
        assert!(WORDS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn a_passphrase_has_the_words_asked_for() {
        let phrase = generate_passphrase(6).ok().unwrap_or_default();
        assert_eq!(phrase.split('-').count(), 6);
        assert!(phrase.split('-').all(|word| WORDS.contains(&word)));
    }

    #[test]
    fn a_passphrase_length_outside_the_bounds_is_refused() {
        assert!(generate_passphrase(1).is_err());
        assert!(generate_passphrase(64).is_err());
    }

    #[test]
    fn two_passphrases_differ() {
        // Not a randomness test — a smoke test that the sampler is actually
        // drawing rather than returning the first word every time.
        let first = generate_passphrase(8).ok();
        let second = generate_passphrase(8).ok();
        assert!(first.is_some() && second.is_some());
        assert_ne!(first, second);
    }

    #[test]
    fn uniform_below_stays_in_range() {
        for bound in [1u32, 2, 3, 7, 2048, 100_000] {
            for _ in 0..64 {
                let value = uniform_below(bound).ok();
                assert!(
                    value.is_some_and(|value| value < bound.max(1)),
                    "a draw below {bound} was out of range or failed"
                );
            }
        }
    }

    #[test]
    fn uniform_below_covers_its_range() {
        // With 4096 draws over 4 values, every value appearing is overwhelmingly
        // likely; a sampler stuck on one value fails here.
        let mut seen = BTreeSet::new();
        for _ in 0..4096 {
            if let Ok(value) = uniform_below(4) {
                seen.insert(value);
            }
        }
        assert_eq!(seen.len(), 4);
    }

    /// Whether `part` points inside `whole` rather than at a copy of it.
    fn is_slice_of(whole: &str, part: &str) -> bool {
        let start = whole.as_ptr().addr();
        let at = part.as_ptr().addr();
        at >= start && at.saturating_add(part.len()) <= start.saturating_add(whole.len())
    }

    #[test]
    fn the_estimator_reads_the_candidate_in_place_rather_than_copying_it() {
        // The wizard calls this on a 180 ms debounce as the master password is
        // typed. Every owned copy it makes is another plaintext prefix left in
        // freed heap, so the stem is a slice of the candidate, not a `String`.
        let candidate = "password2024";
        let stem = common_stem(candidate);
        assert_eq!(stem, "password");
        assert!(
            is_slice_of(candidate, stem),
            "the stem should borrow the candidate rather than copy it"
        );
    }

    #[test]
    fn the_estimate_does_not_depend_on_case() {
        assert_eq!(
            estimate_strength("PASSWORD123").score,
            estimate_strength("password123").score
        );
        let upper = estimate_strength("ACORN-BASIL-CEDAR-DRIFT");
        let lower = estimate_strength("acorn-basil-cedar-drift");
        assert!((upper.entropy_bits - lower.entropy_bits).abs() < f64::EPSILON);
    }

    #[test]
    fn a_repeat_outside_ascii_is_still_discounted() {
        let repeated = estimate_strength("ééééééééé");
        let varied = estimate_strength("éàüñößçâê");
        assert!(
            repeated.entropy_bits < varied.entropy_bits,
            "repeated: {}, varied: {}",
            repeated.entropy_bits,
            varied.entropy_bits
        );
    }

    #[test]
    fn a_passphrase_is_built_in_a_buffer_that_is_never_grown() {
        // A `String` that grows leaves each partial passphrase in freed heap,
        // and the partials are most of the secret.
        let reserved = passphrase_capacity(MAX_PASSPHRASE_WORDS);
        let phrase = build_passphrase(MAX_PASSPHRASE_WORDS);
        assert!(phrase.is_ok());
        if let Ok(phrase) = phrase {
            assert!(
                phrase.capacity() >= reserved,
                "the buffer was grown rather than reserved: {} < {reserved}",
                phrase.capacity()
            );
            assert!(phrase.len() <= reserved);
        }
    }

    #[test]
    fn no_word_is_longer_than_the_reserved_capacity_assumes() {
        assert!(WORDS.iter().all(|word| word.len() <= MAX_WORD_LEN));
        assert!(FALLBACK_WORD.len() <= MAX_WORD_LEN);
    }

    #[test]
    fn a_breached_password_is_weak_however_long_it_looks() {
        let strength = estimate_strength("password123");
        assert_eq!(strength.score, 0);
        assert!(!strength.acceptable);
        assert_eq!(strength.label, "Weak");
    }

    #[test]
    fn an_empty_password_scores_nothing() {
        let strength = estimate_strength("");
        assert_eq!(strength.score, 0);
        assert!((strength.entropy_bits - 0.0).abs() < f64::EPSILON);
        assert!(!strength.acceptable);
    }

    #[test]
    fn a_six_word_passphrase_is_strong() {
        let phrase = "acorn-basil-cedar-drift-ember-fable";
        let strength = estimate_strength(phrase);
        assert!(
            strength.entropy_bits >= 60.0,
            "entropy was {}",
            strength.entropy_bits
        );
        assert!(strength.acceptable);
        assert_eq!(strength.label, "Strong");
    }

    #[test]
    fn repetition_does_not_buy_strength() {
        let repeated = estimate_strength("aaaaaaaaaaaaaaaa");
        let varied = estimate_strength("aqBz7#kLm2!vXpQ4");
        assert!(repeated.entropy_bits < varied.entropy_bits);
        assert!(!repeated.acceptable);
    }

    #[test]
    fn a_sequence_does_not_buy_strength() {
        let sequence = estimate_strength("abcdefghijklmnop");
        let varied = estimate_strength("aqBz7#kLm2!vXpQ4");
        assert!(sequence.entropy_bits < varied.entropy_bits);
    }

    #[test]
    fn the_explanation_is_a_sentence_about_consequences() {
        for password in ["a", "hunter2", "aqBz7#kLm2!vXpQ4"] {
            let strength = estimate_strength(password);
            assert!(strength.explanation.ends_with('.'));
            assert!(
                strength.explanation.contains("a billion attempts a second")
                    || strength.explanation.contains("age of the universe"),
                "explanation was: {}",
                strength.explanation
            );
        }
    }

    #[test]
    fn the_score_rises_with_entropy() {
        assert!(score_for(10.0) < score_for(45.0));
        assert!(score_for(45.0) < score_for(80.0));
        assert_eq!(score_for(200.0), 4);
    }

    #[test]
    fn a_slug_is_a_usable_file_name() {
        assert_eq!(slugify("Production vault"), "production-vault");
        assert_eq!(slugify("  ../etc/passwd  "), "etc-passwd");
        assert_eq!(slugify("!!!"), "vault");
    }

    #[test]
    fn match_ranges_are_case_insensitive_and_non_overlapping() {
        assert_eq!(match_ranges("Web Tier", "web"), vec![(0, 3)]);
        assert_eq!(match_ranges("aaaa", "aa"), vec![(0, 2), (2, 4)]);
        assert_eq!(match_ranges("Web Tier", ""), Vec::new());
        assert_eq!(match_ranges("Web", "web tier"), Vec::new());
    }
}

#[cfg(test)]
mod passphrase_gate_tests {
    use super::*;

    /// The failure this guards against: the generator handing the user a
    /// passphrase that `vault_create` then refuses.
    #[test]
    #[expect(
        clippy::panic,
        reason = "a test that cannot generate a passphrase has nothing left to assert"
    )]
    fn a_generated_passphrase_always_clears_the_strength_gate() {
        for requested in MIN_PASSPHRASE_WORDS..=8 {
            let Ok(phrase) = generate_passphrase(requested) else {
                panic!("generating {requested} words failed");
            };
            let strength = estimate_strength(&phrase);
            assert!(
                strength.acceptable,
                "asked for {requested} words, got {} bits, which the gate refuses",
                strength.entropy_bits
            );
        }
    }

    #[test]
    fn the_word_count_is_only_raised_when_it_has_to_be() {
        // 2,048 words is 11 bits each: five is short of 60, six clears it.
        assert_eq!(enough_words_for_the_gate(5, 2048), 6);
        assert_eq!(enough_words_for_the_gate(6, 2048), 6);
        assert_eq!(enough_words_for_the_gate(8, 2048), 8);
        // A larger list needs fewer words, and the count is not padded.
        assert_eq!(enough_words_for_the_gate(5, 7776), 5);
    }
}

/// The connection editor's credential input: password, private key, agent.
#[cfg(test)]
mod credential_tests {
    use super::*;
    use crate::test_support::{PKCS8_ENCRYPTED_KEY, PKCS8_KEY, Scratch, open_vault, why};

    fn credential(name: &str, credential: CredentialInputDto) -> CreateNodeDto {
        CreateNodeDto {
            parent_id: None,
            kind: String::from("credential"),
            name: name.to_owned(),
            protocol: None,
            host: None,
            port: None,
            username: Some(String::from("svc-deploy")),
            password: None,
            credential: Some(credential),
            credential_id: None,
        }
    }

    #[test]
    fn a_key_file_is_identified_by_its_content_and_never_read_back_out() {
        let scratch = Scratch::new();
        let plain = scratch.write("id_ed25519", PKCS8_KEY);
        let locked = scratch.write("id_locked", PKCS8_ENCRYPTED_KEY);

        let inspected = key_inspect_impl(plain.display().to_string());
        assert!(inspected.is_ok(), "inspecting failed: {}", why(&inspected));
        if let Ok(info) = inspected {
            assert_eq!(info.format, "pkcs8");
            assert_eq!(info.format_label, "PKCS#8");
            assert!(!info.encrypted, "this container says it is not encrypted");
            assert!(info.size_bytes > 0);

            // Metadata only: nothing that crosses the boundary is any part of
            // the file's contents.
            let rendered = serde_json::to_string(&info).unwrap_or_default();
            assert!(!rendered.contains("MIIBAA"), "rendered: {rendered}");
        }

        let inspected = key_inspect_impl(locked.display().to_string());
        assert!(
            inspected.is_ok_and(|info| info.encrypted),
            "an encrypted container is what makes the editor ask for a passphrase"
        );

        // A public key is the mistake people actually make, and it is named.
        let public = scratch.write("id_ed25519.pub", "ssh-ed25519 AAAAC3Nz nobody@example\n");
        let refused = key_inspect_impl(public.display().to_string());
        assert!(
            refused
                .as_ref()
                .is_err_and(|err| err.code == "key.not-a-private-key")
        );
        if let Err(err) = refused {
            assert!(err.actions.iter().any(|action| action.contains(".pub")));
        }

        // And a container this build does not store is refused by name.
        let pkcs1 = scratch.write(
            "id_rsa",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBAA==\n-----END RSA PRIVATE KEY-----\n",
        );
        let refused = key_inspect_impl(pkcs1.display().to_string());
        assert!(
            refused
                .as_ref()
                .is_err_and(|err| err.code == "key.unsupported-format")
        );
        if let Err(err) = refused {
            assert!(err.message.contains("PKCS#1"), "message: {}", err.message);
        }
    }

    #[test]
    fn a_request_carrying_both_a_password_and_a_credential_is_refused() {
        let refused = take_credential(
            Some(String::from("hunter2")),
            Some(CredentialInputDto::Password {
                password: String::from("hunter2"),
            }),
        );
        assert!(refused.is_err_and(|err| err.code == "request.invalid"));
    }

    #[test]
    fn a_passphrase_protected_key_without_its_passphrase_is_refused() {
        let scratch = Scratch::new();
        let locked = scratch.write("id_locked", PKCS8_ENCRYPTED_KEY);

        let refused = take_credential(
            None,
            Some(CredentialInputDto::PrivateKey {
                path: locked.display().to_string(),
                passphrase: None,
            }),
        );
        assert!(
            refused
                .as_ref()
                .is_err_and(|err| err.code == "key.passphrase-required")
        );
        if let Err(err) = refused {
            assert!(
                err.message.contains("id_locked"),
                "message: {}",
                err.message
            );
        }
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "a credential test without a vault has nothing left to assert"
    )]
    fn a_private_key_is_stored_in_the_vault_and_never_returned() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let key_file = scratch.write("id_ed25519", PKCS8_KEY);

        let created = node_create_impl(
            &state,
            &mut credential(
                "svc-deploy",
                CredentialInputDto::PrivateKey {
                    path: key_file.display().to_string(),
                    passphrase: Some(String::from("opensesame")),
                },
            ),
        );
        assert!(created.is_ok(), "creating failed: {}", why(&created));
        let Ok(created) = created else {
            panic!("creating failed");
        };
        assert_eq!(created.secret_kind.as_deref(), Some("privateKey"));
        assert_eq!(created.key_format.as_deref(), Some("pkcs8"));
        assert!(created.has_passphrase);

        let rendered = serde_json::to_string(&created).unwrap_or_default();
        assert!(!rendered.contains("opensesame"), "rendered: {rendered}");
        assert!(!rendered.contains("MIIBAA"), "rendered: {rendered}");

        // The key is in the vault rather than left as a reference to the file,
        // so deleting the file does not cost the user their credential.
        let _ = fs::remove_file(&key_file);
        let mut guard = state.lock();
        let Ok(vault) = guard.vault_ref() else {
            panic!("the vault should be open");
        };
        let Ok(id) = Uuid::parse_str(&created.id) else {
            panic!("the node id should be a uuid");
        };
        assert_eq!(vault.has_secret(id, "private_key").ok(), Some(true));
        assert_eq!(vault.has_secret(id, "passphrase").ok(), Some(true));
        assert_eq!(vault.has_secret(id, "password").ok(), Some(false));
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "a credential test without a vault has nothing left to assert"
    )]
    fn switching_a_credential_forgets_the_secrets_of_the_method_it_left() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        let created = node_create_impl(
            &state,
            &mut credential(
                "svc-deploy",
                CredentialInputDto::Password {
                    password: String::from("hunter2"),
                },
            ),
        );
        let Ok(created) = created else {
            panic!("creating failed");
        };
        assert_eq!(created.secret_kind.as_deref(), Some("password"));
        let Ok(id) = Uuid::parse_str(&created.id) else {
            panic!("the node id should be a uuid");
        };

        // Password to agent: no key material is stored at all, and the
        // password that used to open this credential is gone.
        let updated = node_update_impl(
            &state,
            created.id.clone(),
            &mut UpdateNodeDto {
                name: None,
                description: None,
                tags: None,
                colour: None,
                host: None,
                port: None,
                username: None,
                password: None,
                credential: Some(CredentialInputDto::Agent {
                    comment_filter: Some(String::from("deploy@")),
                }),
                credential_id: None,
                clear_overrides: None,
            },
        );
        assert!(updated.is_ok(), "updating failed: {}", why(&updated));
        let Ok(updated) = updated else {
            panic!("updating failed");
        };
        assert_eq!(updated.secret_kind.as_deref(), Some("agent"));
        assert_eq!(updated.agent_comment_filter.as_deref(), Some("deploy@"));
        assert!(updated.key_format.is_none());

        {
            let mut guard = state.lock();
            let Ok(vault) = guard.vault_ref() else {
                panic!("the vault should be open");
            };
            assert_eq!(
                vault.has_secret(id, "password").ok(),
                Some(false),
                "a credential the user replaced must not keep the old secret behind it"
            );
        }

        // Agent back to a key: the key and its passphrase are stored, and the
        // node says which container it is.
        let key_file = scratch.write("id_locked", PKCS8_ENCRYPTED_KEY);
        let updated = node_update_impl(
            &state,
            created.id,
            &mut UpdateNodeDto {
                name: None,
                description: None,
                tags: None,
                colour: None,
                host: None,
                port: None,
                username: None,
                password: None,
                credential: Some(CredentialInputDto::PrivateKey {
                    path: key_file.display().to_string(),
                    passphrase: Some(String::from("opensesame")),
                }),
                credential_id: None,
                clear_overrides: None,
            },
        );
        assert!(updated.is_ok(), "updating failed: {}", why(&updated));
        assert!(updated.is_ok_and(|node| node.secret_kind.as_deref() == Some("privateKey")));

        let mut guard = state.lock();
        let Ok(vault) = guard.vault_ref() else {
            panic!("the vault should be open");
        };
        assert_eq!(vault.has_secret(id, "private_key").ok(), Some(true));
        assert_eq!(vault.has_secret(id, "passphrase").ok(), Some(true));
    }

    #[test]
    fn a_key_cannot_be_hung_on_a_folder() {
        let scratch = Scratch::new();
        let key_file = scratch.write("id_ed25519", PKCS8_KEY);
        let material = take_credential(
            None,
            Some(CredentialInputDto::PrivateKey {
                path: key_file.display().to_string(),
                passphrase: None,
            }),
        );
        assert!(material.is_ok(), "reading the key failed");
        let Ok(material) = material else {
            return;
        };

        let input = CreateNodeDto {
            parent_id: None,
            kind: String::from("folder"),
            name: String::from("Production"),
            protocol: None,
            host: None,
            port: None,
            username: None,
            password: None,
            credential: None,
            credential_id: None,
        };
        let refused = build_kind(&input, &material);
        assert!(refused.is_err_and(|err| err.code == "node.field-not-applicable"));
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "a credential test without a vault has nothing left to assert"
    )]
    fn a_connection_reaches_a_key_by_pointing_at_the_credential_that_holds_it() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let key_file = scratch.write("id_ed25519", PKCS8_KEY);

        let Ok(key_credential) = node_create_impl(
            &state,
            &mut credential(
                "svc-deploy",
                CredentialInputDto::PrivateKey {
                    path: key_file.display().to_string(),
                    passphrase: None,
                },
            ),
        ) else {
            panic!("creating the credential failed");
        };

        let created = node_create_impl(
            &state,
            &mut CreateNodeDto {
                parent_id: None,
                kind: String::from("connection"),
                name: String::from("web-01"),
                protocol: Some(String::from("ssh")),
                host: Some(String::from("web-01.example.com")),
                port: None,
                username: None,
                password: None,
                credential: None,
                credential_id: Some(key_credential.id.clone()),
            },
        );
        assert!(created.is_ok(), "creating failed: {}", why(&created));
        let Ok(created) = created else {
            panic!("creating failed");
        };
        assert_eq!(
            created.credential_id.as_deref(),
            Some(key_credential.id.as_str())
        );

        // The inspector reads the same reference through the resolver, which
        // is where the inherited case comes from.
        let resolved = node_resolve_impl(&state, created.id.clone());
        assert!(resolved.is_ok(), "resolving failed: {}", why(&resolved));
        assert!(
            resolved.is_ok_and(|effective| effective
                .fields
                .iter()
                .any(|field| field.field == "credential"
                    && field.value.as_deref() == Some("svc-deploy")
                    && field.origin == "own")),
            "the connection should resolve to the credential it was pointed at"
        );

        // Reverting to the inherited credential is the same clear_overrides
        // the rest of the inspector uses.
        let reverted = node_update_impl(
            &state,
            created.id.clone(),
            &mut UpdateNodeDto {
                name: None,
                description: None,
                tags: None,
                colour: None,
                host: None,
                port: None,
                username: None,
                password: None,
                credential: None,
                credential_id: None,
                clear_overrides: Some(vec![String::from("credential")]),
            },
        );
        assert!(reverted.is_ok_and(|node| node.credential_id.is_none()));

        // A reference to something that is not a credential is refused here
        // rather than at connect time.
        let folder = node_create_impl(
            &state,
            &mut CreateNodeDto {
                parent_id: None,
                kind: String::from("folder"),
                name: String::from("Production"),
                protocol: None,
                host: None,
                port: None,
                username: None,
                password: None,
                credential: None,
                credential_id: None,
            },
        );
        let Ok(folder) = folder else {
            panic!("creating the folder failed");
        };
        let refused = node_update_impl(
            &state,
            created.id,
            &mut UpdateNodeDto {
                name: None,
                description: None,
                tags: None,
                colour: None,
                host: None,
                port: None,
                username: None,
                password: None,
                credential: None,
                credential_id: Some(folder.id),
                clear_overrides: None,
            },
        );
        assert!(refused.is_err_and(|err| err.code == "validation.credential-kind"));

        let missing = node_update_impl(
            &state,
            key_credential.id,
            &mut UpdateNodeDto {
                name: None,
                description: None,
                tags: None,
                colour: None,
                host: None,
                port: None,
                username: None,
                password: None,
                credential: None,
                credential_id: Some(Uuid::now_v7().to_string()),
                clear_overrides: None,
            },
        );
        assert!(missing.is_err_and(|err| err.code == "validation.credential-unknown"));
    }
}

/// The identity seam: a username and a secret typed on a connection.
///
/// The case these tests exist for is the inherited one. A connection under a
/// folder that supplies the credential must not have that credential edited
/// when the user types a username on the connection — every other connection
/// under the folder would change with it, silently, and that is exactly the
/// failure that makes people distrust a connection manager.
#[cfg(test)]
#[expect(
    clippy::panic,
    reason = "a seam test without a vault has nothing left to assert"
)]
mod identity_tests {
    use super::*;
    use crate::test_support::{Scratch, open_vault, why};

    fn blank_update() -> UpdateNodeDto {
        UpdateNodeDto {
            name: None,
            description: None,
            tags: None,
            colour: None,
            host: None,
            port: None,
            username: None,
            password: None,
            credential: None,
            credential_id: None,
            clear_overrides: None,
        }
    }

    fn blank_create(kind: &str, name: &str) -> CreateNodeDto {
        CreateNodeDto {
            parent_id: None,
            kind: kind.to_owned(),
            name: name.to_owned(),
            protocol: None,
            host: None,
            port: None,
            username: None,
            password: None,
            credential: None,
            credential_id: None,
        }
    }

    fn connection_under(parent: Option<&str>, name: &str, host: &str) -> CreateNodeDto {
        CreateNodeDto {
            parent_id: parent.map(ToOwned::to_owned),
            protocol: Some(String::from("ssh")),
            host: Some(host.to_owned()),
            ..blank_create("connection", name)
        }
    }

    fn create(state: &AppState, mut input: CreateNodeDto) -> NodeDto {
        match node_create_impl(state, &mut input) {
            Ok(node) => node,
            Err(err) => panic!("creating a node failed: {}", err.message),
        }
    }

    fn update(state: &AppState, id: &str, mut patch: UpdateNodeDto) -> Result<NodeDto, IpcError> {
        node_update_impl(state, id.to_owned(), &mut patch)
    }

    fn resolved(state: &AppState, id: &str, field: &str) -> Option<ResolvedFieldDto> {
        node_resolve_impl(state, id.to_owned())
            .ok()
            .and_then(|effective| {
                effective
                    .fields
                    .into_iter()
                    .find(|resolved| resolved.field == field)
            })
    }

    /// The vault's own tree, tombstones excluded — attached credentials
    /// included, which is what `tree_list` deliberately leaves out.
    fn stored(state: &AppState) -> Vec<Node> {
        let mut guard = state.lock();
        let Ok(vault) = guard.vault_ref() else {
            panic!("the vault should be open");
        };
        match read_tree(vault) {
            Ok(tree) => tree.into_nodes(),
            Err(err) => panic!("reading the tree failed: {}", err.message),
        }
    }

    fn username_of(state: &AppState, id: &str) -> Option<String> {
        let id = Uuid::parse_str(id).ok()?;
        stored(state)
            .into_iter()
            .find(|node| *node.id.as_uuid() == id)
            .and_then(|node| {
                node.kind
                    .as_credential()
                    .map(|props| props.username.clone())
            })
    }

    /// The bug the user reported: a username and a password typed on a
    /// connection, and Save.
    #[test]
    fn a_username_typed_on_a_connection_is_saved_and_resolves() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let connection = create(
            &state,
            connection_under(None, "web-01", "web-01.example.com"),
        );

        let saved = update(
            &state,
            &connection.id,
            UpdateNodeDto {
                username: Some(String::from("ada")),
                password: Some(String::from("hunter2")),
                ..blank_update()
            },
        );
        assert!(saved.is_ok(), "saving the username failed: {}", why(&saved));
        let Ok(saved) = saved else {
            panic!("saving failed");
        };
        assert_eq!(saved.username.as_deref(), Some("ada"));
        assert_eq!(saved.secret_kind.as_deref(), Some("password"));
        assert_eq!(saved.credential_change.as_deref(), Some("created"));
        let Some(attached) = saved.attached_credential_id.clone() else {
            panic!("the connection should now own a credential");
        };
        assert_eq!(saved.credential_id.as_deref(), Some(attached.as_str()));

        // It resolves as the connection's own, which is what the editor shows
        // beside the field.
        let username = resolved(&state, &connection.id, "username");
        assert!(
            username
                .as_ref()
                .is_some_and(|field| field.value.as_deref() == Some("ada")
                    && field.origin == "own"),
            "resolved: {username:?}"
        );
        let effective = node_resolve_impl(&state, connection.id.clone());
        assert!(effective.is_ok_and(|effective| effective.credential_attached));

        // The password is in the vault, filed under the credential — not
        // under the connection, where nothing could ever read it.
        let mut guard = state.lock();
        let Ok(vault) = guard.vault_ref() else {
            panic!("the vault should be open");
        };
        let Ok(credential_id) = Uuid::parse_str(&attached) else {
            panic!("the credential id should be a uuid");
        };
        let Ok(connection_id) = Uuid::parse_str(&connection.id) else {
            panic!("the connection id should be a uuid");
        };
        assert_eq!(vault.has_secret(credential_id, "password").ok(), Some(true));
        assert_eq!(
            vault.has_secret(connection_id, "password").ok(),
            Some(false)
        );
        drop(guard);

        // And it is not an entry of its own: the sidebar shows one connection.
        let listed = tree_list_impl(&state).unwrap_or_default();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed.first().map(|node| node.kind.clone()),
            Some(String::from("connection"))
        );
    }

    /// The test that matters. Editing an inherited credential would change
    /// every other connection under the folder; overriding it here changes
    /// nothing but this connection.
    #[test]
    fn a_username_on_an_inherited_credential_leaves_the_folder_and_its_other_connections_alone() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        let datacentre = create(&state, blank_create("folder", "Datacentre"));
        let shared = create(
            &state,
            CreateNodeDto {
                username: Some(String::from("svc-deploy")),
                password: Some(String::from("hunter2")),
                ..blank_create("credential", "svc-deploy")
            },
        );
        let pointed = update(
            &state,
            &datacentre.id,
            UpdateNodeDto {
                credential_id: Some(shared.id.clone()),
                ..blank_update()
            },
        );
        assert!(
            pointed.is_ok(),
            "pointing the folder failed: {}",
            why(&pointed)
        );

        let web01 = create(
            &state,
            connection_under(Some(&datacentre.id), "web-01", "web-01.example.com"),
        );
        let web02 = create(
            &state,
            connection_under(Some(&datacentre.id), "web-02", "web-02.example.com"),
        );

        // Both start out inheriting the folder's credential.
        for connection in [&web01, &web02] {
            let username = resolved(&state, &connection.id, "username");
            assert!(
                username
                    .as_ref()
                    .is_some_and(|field| field.value.as_deref() == Some("svc-deploy")
                        && field.origin == "inherited"
                        && field.source_name.as_deref() == Some("Datacentre")),
                "resolved: {username:?}"
            );
        }

        let saved = update(
            &state,
            &web01.id,
            UpdateNodeDto {
                username: Some(String::from("ada")),
                password: Some(String::from("opensesame")),
                ..blank_update()
            },
        );
        assert!(saved.is_ok(), "saving the username failed: {}", why(&saved));
        let Ok(saved) = saved else {
            panic!("saving failed");
        };
        assert_eq!(
            saved.credential_change.as_deref(),
            Some("overridesInherited")
        );
        assert_ne!(saved.credential_id.as_deref(), Some(shared.id.as_str()));

        // web-01 now overrides, and says what it overrides.
        let username = resolved(&state, &web01.id, "username");
        assert!(
            username
                .as_ref()
                .is_some_and(|field| field.value.as_deref() == Some("ada")
                    && field.origin == "own"
                    && field.overrides.as_deref() == Some("svc-deploy")),
            "resolved: {username:?}"
        );

        // This is the assertion the whole design exists for.
        let untouched = resolved(&state, &web02.id, "username");
        assert!(
            untouched
                .as_ref()
                .is_some_and(|field| field.value.as_deref() == Some("svc-deploy")
                    && field.origin == "inherited"
                    && field.source_name.as_deref() == Some("Datacentre")),
            "the other connections under the folder must not have moved: {untouched:?}"
        );
        assert_eq!(
            username_of(&state, &shared.id).as_deref(),
            Some("svc-deploy"),
            "the folder's credential must not have been rewritten"
        );

        // Reverting removes the credential it owns and puts the folder's back.
        let reverted = update(
            &state,
            &web01.id,
            UpdateNodeDto {
                clear_overrides: Some(vec![String::from("credential")]),
                ..blank_update()
            },
        );
        assert!(reverted.is_ok(), "reverting failed: {}", why(&reverted));
        let Ok(reverted) = reverted else {
            panic!("reverting failed");
        };
        assert!(reverted.attached_credential_id.is_none());
        let username = resolved(&state, &web01.id, "username");
        assert!(
            username
                .as_ref()
                .is_some_and(|field| field.value.as_deref() == Some("svc-deploy")
                    && field.origin == "inherited"),
            "resolved: {username:?}"
        );
        // The credential it owned is gone; the shared one is not.
        let names: Vec<String> = stored(&state)
            .iter()
            .filter(|node| node.kind.as_credential().is_some())
            .map(|node| node.name.clone())
            .collect();
        assert_eq!(names, vec![String::from("svc-deploy")]);
    }

    #[test]
    fn a_username_on_a_shared_credential_gives_the_connection_its_own_instead() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        let shared = create(
            &state,
            CreateNodeDto {
                username: Some(String::from("svc-deploy")),
                password: Some(String::from("hunter2")),
                ..blank_create("credential", "svc-deploy")
            },
        );
        let connection = create(
            &state,
            CreateNodeDto {
                credential_id: Some(shared.id.clone()),
                ..connection_under(None, "web-01", "web-01.example.com")
            },
        );
        assert_eq!(
            connection.credential_id.as_deref(),
            Some(shared.id.as_str())
        );

        let saved = update(
            &state,
            &connection.id,
            UpdateNodeDto {
                username: Some(String::from("ada")),
                ..blank_update()
            },
        );
        assert!(saved.is_ok(), "saving failed: {}", why(&saved));
        let Ok(saved) = saved else {
            panic!("saving failed");
        };
        assert_eq!(
            saved.credential_change.as_deref(),
            Some("detachedFromShared"),
            "the interface has to be able to say a new credential was made"
        );
        assert_ne!(saved.credential_id.as_deref(), Some(shared.id.as_str()));
        assert_eq!(saved.username.as_deref(), Some("ada"));
        assert_eq!(
            username_of(&state, &shared.id).as_deref(),
            Some("svc-deploy"),
            "a credential other connections may use must not be rewritten"
        );

        // Deleting the connection takes its own credential and nothing else.
        assert!(node_delete_impl(&state, connection.id.clone()).is_ok());
        let names: Vec<String> = stored(&state)
            .iter()
            .filter(|node| node.kind.as_credential().is_some())
            .map(|node| node.name.clone())
            .collect();
        assert_eq!(names, vec![String::from("svc-deploy")]);
    }

    #[test]
    fn clearing_a_username_with_no_secret_behind_it_removes_the_credential() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        let datacentre = create(&state, blank_create("folder", "Datacentre"));
        let shared = create(
            &state,
            CreateNodeDto {
                username: Some(String::from("svc-deploy")),
                password: Some(String::from("hunter2")),
                ..blank_create("credential", "svc-deploy")
            },
        );
        let pointed = update(
            &state,
            &datacentre.id,
            UpdateNodeDto {
                credential_id: Some(shared.id.clone()),
                ..blank_update()
            },
        );
        assert!(
            pointed.is_ok(),
            "pointing the folder failed: {}",
            why(&pointed)
        );

        // A username on its own — the user is halfway through the form.
        let connection = create(
            &state,
            CreateNodeDto {
                username: Some(String::from("ada")),
                ..connection_under(Some(&datacentre.id), "web-01", "web-01.example.com")
            },
        );
        assert_eq!(connection.username.as_deref(), Some("ada"));
        assert!(connection.attached_credential_id.is_some());

        // And typed away again: the connection goes back to the folder's.
        let cleared = update(
            &state,
            &connection.id,
            UpdateNodeDto {
                username: Some(String::new()),
                ..blank_update()
            },
        );
        assert!(cleared.is_ok(), "clearing failed: {}", why(&cleared));
        let Ok(cleared) = cleared else {
            panic!("clearing failed");
        };
        assert_eq!(cleared.credential_change.as_deref(), Some("removed"));
        assert!(cleared.attached_credential_id.is_none());

        let username = resolved(&state, &connection.id, "username");
        assert!(
            username
                .as_ref()
                .is_some_and(|field| field.value.as_deref() == Some("svc-deploy")
                    && field.origin == "inherited"),
            "the inherited credential should apply again: {username:?}"
        );
        let names: Vec<String> = stored(&state)
            .iter()
            .filter(|node| node.kind.as_credential().is_some())
            .map(|node| node.name.clone())
            .collect();
        assert_eq!(names, vec![String::from("svc-deploy")]);
    }

    /// A credential a connection owns is that connection's own; a second one
    /// pointing at it would mean editing either changed the other.
    #[test]
    fn a_second_connection_cannot_be_pointed_at_a_credential_another_one_owns() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        let first = create(
            &state,
            CreateNodeDto {
                username: Some(String::from("ada")),
                password: Some(String::from("hunter2")),
                ..connection_under(None, "web-01", "web-01.example.com")
            },
        );
        let Some(attached) = first.attached_credential_id.clone() else {
            panic!("the connection should own a credential");
        };

        let second = create(
            &state,
            connection_under(None, "web-02", "web-02.example.com"),
        );
        let refused = update(
            &state,
            &second.id,
            UpdateNodeDto {
                credential_id: Some(attached),
                ..blank_update()
            },
        );
        assert!(
            refused
                .as_ref()
                .is_err_and(|err| err.code == "validation.credential-attached"),
            "refused: {}",
            why(&refused)
        );

        // And an edit cannot say both "use that shared credential" and "have
        // one of your own".
        let conflicting = update(
            &state,
            &second.id,
            UpdateNodeDto {
                username: Some(String::from("ada")),
                credential_id: Some(first.id.clone()),
                ..blank_update()
            },
        );
        assert!(conflicting.is_err_and(|err| err.code == "request.invalid"));
    }
}
