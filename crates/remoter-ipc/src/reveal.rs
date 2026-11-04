//! Showing a stored password on screen.
//!
//! **Review note — this module is the exception to "a secret never crosses
//! this boundary" (`lib.rs`, CLAUDE.md §6).** It is the one command that
//! returns a password to the interface, and it exists because the user asked
//! for exactly that: to read the password of a server they manage. The rule
//! keeps the WebView from holding secrets it does not need; a person reading
//! their own password on purpose needs it, and nothing else in the design can
//! serve that. What keeps the exception narrow:
//!
//! - **It is gated on the vault's password, not on the vault being open.**
//!   `docs/security/threat-model.md` T7 is the unattended, unlocked screen;
//!   an open vault proves nothing about who is at the keyboard. The password
//!   is checked with the same Argon2id derivation an unlock uses, with the
//!   unlock's own backoff after repeated failures.
//! - **A confirmation lasts ten minutes and no longer.** Inside that window a
//!   second password is shown without asking again, which is what makes the
//!   feature usable for a run of servers. The window is fixed from the moment
//!   of confirmation — showing more passwords does not extend it — it lives
//!   here in the core where the interface cannot forge it, and locking the
//!   vault, by hand or by any trigger, ends it.
//! - **Every password shown is audited** as `secret_revealed`, through
//!   `Vault::borrow_secret` with `Purpose::Reveal`, and every refused
//!   confirmation as a failed unlock. Neither row carries the secret.
//! - **The password is the only secret it returns.** Never a private key, a
//!   passphrase or a TOTP seed: a connection authenticated by any of those has
//!   no password to show and is told so.
//! - **The interface keeps it in component state only** — not a query cache,
//!   not a store — and drops it when the dialog closes or the vault locks.
//!
//! The KDF runs on the blocking pool with the vault lock released: a second of
//! Argon2id held under the lock would stall every other command, and on the
//! main thread it would freeze the window.

use std::path::{Path, PathBuf};
use std::time::Duration;

use parking_lot::Mutex;
use remoter_core::{NodeId, NodeKind, SecretKind};
use remoter_vault::{AuditEvent, AuditOutcome, ExposeSecret as _, PasswordCheck, Purpose, Secret};
use serde::{Serialize, Serializer};
use tauri::State;
use uuid::Uuid;

use crate::commands::{parse_node_id, read_tree, save};
use crate::error::IpcError;
use crate::state::{AppState, Inner};

/// How long one confirmation of the vault's password lets passwords be shown
/// without asking again.
pub(crate) const REVEAL_WINDOW: Duration = Duration::from_secs(10 * 60);

/// A password, shown because the user asked to see it.
///
/// **Review note (CLAUDE.md §5).** Carries a plaintext password outward —
/// see the module documentation for why this one DTO may. `Serialize` writes
/// it through [`expose`]; `Debug` is the field's own, which redacts; there is
/// no `Clone`, and dropping the DTO wipes the buffer.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealedSecretDto {
    /// The node the user asked about.
    pub node_id: String,
    /// The credential the password is stored on. A connection's own credential
    /// carries the connection's name; a shared one its own.
    pub credential_name: String,
    /// Whether that credential is shared by several connections rather than
    /// belonging to this one, so the dialog can say whose password this is.
    pub shared: bool,
    /// The account the password is for, when the credential names one.
    pub username: Option<String>,
    /// The password itself.
    #[serde(serialize_with = "expose")]
    pub password: Secret<String>,
    /// How much longer passwords can be shown without asking for the vault's
    /// password, in milliseconds. Never zero: it was just confirmed or is
    /// still running.
    pub window_remaining_ms: u64,
}

/// Whether the window is open, for the corner countdown.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealWindowDto {
    /// Milliseconds left, or `None` when the next password shown asks for the
    /// vault's password first.
    pub remaining_ms: Option<u64>,
}

fn expose<S: Serializer>(secret: &Secret<String>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

// ================================================================ commands ==

/// Shows the password stored for a connection, or on a credential.
///
/// `password` is the vault's password. Without it the call succeeds only
/// while a previous confirmation's window is still open, and otherwise fails
/// with `secret.reveal-confirm` — which is the interface's cue to ask.
#[tauri::command]
pub(crate) async fn secret_reveal(
    state: State<'_, AppState>,
    node_id: String,
    password: Option<String>,
) -> Result<RevealedSecretDto, IpcError> {
    // Into a wiping buffer before anything can fail.
    let password = password.map(Secret::new);
    let inner = state.inner_handle();
    tokio::task::spawn_blocking(move || secret_reveal_impl(&inner, &node_id, password))
        .await
        .map_err(|err| {
            // A panic inside is reported, never swallowed — and nothing was
            // shown, which is the part the user needs to know.
            IpcError::new(
                "secret.reveal-interrupted",
                "Showing the password stopped before it finished, and nothing was shown.",
            )
            .with_detail(err.to_string())
            .with_actions(["Try again"])
        })?
}

/// Whether passwords can be shown without asking, and for how long.
#[tauri::command]
pub(crate) fn secret_reveal_window(state: State<'_, AppState>) -> RevealWindowDto {
    reveal_window_impl(&state.lock())
}

/// Ends the window now, so the next password shown asks for the vault's
/// password again.
#[tauri::command]
pub(crate) fn secret_reveal_end(state: State<'_, AppState>) {
    state.lock().end_reveal_window();
}

fn reveal_window_impl(inner: &Inner) -> RevealWindowDto {
    RevealWindowDto {
        remaining_ms: inner.reveal_window_remaining().map(millis),
    }
}

// ============================================================ the reveal ==

/// What a confirmation needs from the vault, taken under the lock.
struct Confirmation {
    vault_id: Uuid,
    path: PathBuf,
    keyfile: Option<PathBuf>,
    check: PasswordCheck,
}

pub(crate) fn secret_reveal_impl(
    inner: &Mutex<Inner>,
    node_id: &str,
    password: Option<Secret<String>>,
) -> Result<RevealedSecretDto, IpcError> {
    let id = parse_node_id(node_id, "nodeId")?;

    let Some(password) = password else {
        let mut guard = inner.lock();
        // `vault_mut` first: a vault that locked itself says so, rather than
        // asking for a password it can no longer check.
        guard.vault_mut()?;
        if guard.reveal_window_remaining().is_none() {
            return Err(confirm_required());
        }
        return reveal(&mut guard, id);
    };

    // 1 · Under the lock: what the check needs, and nothing that takes time.
    let confirmation = {
        let mut guard = inner.lock();
        let vault = guard.vault_ref()?;
        let vault_id = vault.vault_id();
        let path = vault.path().to_path_buf();
        let check = vault.password_check();
        // The same backoff as the unlock screen, against the same password.
        guard.check_unlock_allowed(&path)?;
        let keyfile = guard
            .recents_keyfile_for(&path.display().to_string())
            .map(PathBuf::from);
        Confirmation {
            vault_id,
            path,
            keyfile,
            check,
        }
    };
    if !confirmation.check.has_password_slot() {
        return Err(no_password_slot());
    }

    // 2 · With the lock released: the KDF.
    let confirmed = confirmation
        .check
        .verify(&password, confirmation.keyfile.as_deref())
        .map_err(|err| IpcError::from_vault(&err, "this vault"))?;
    drop(password);

    // 3 · Under the lock again, against the vault the check was made for.
    let mut guard = inner.lock();
    let vault = guard.vault_mut()?;
    if vault.vault_id() != confirmation.vault_id {
        // Another vault was opened while the password was being checked. The
        // confirmation was for the one that closed.
        return Err(IpcError::locked());
    }

    if !confirmed {
        record_refusal(&mut guard, &confirmation.path);
        return Err(refused());
    }

    guard.clear_unlock_failures(&confirmation.path);
    guard.open_reveal_window(REVEAL_WINDOW);
    reveal(&mut guard, id)
}

/// Shows the password, with the window known to be open.
fn reveal(inner: &mut Inner, id: NodeId) -> Result<RevealedSecretDto, IpcError> {
    let remaining = inner
        .reveal_window_remaining()
        .ok_or_else(confirm_required)?;
    let vault = inner.vault_mut()?;
    let tree = read_tree(vault)?;
    let node = tree.get(id).ok_or_else(|| {
        IpcError::new(
            "node.not-found",
            "That item is no longer in this vault; it was probably deleted elsewhere.",
        )
        .with_detail(format!("node {}", id.as_uuid()))
        .with_actions(["Reload the tree"])
    })?;

    // Which credential: the node itself, or the one the connection resolves to
    // through inheritance — the same credential a session would open with.
    let credential_id = match &node.kind {
        NodeKind::Credential(_) => id,
        NodeKind::Connection(_) => {
            let effective = tree
                .effective_connection(id)
                .map_err(|err| IpcError::from_core(&err))?;
            match effective.credential.value {
                Some(reference) if !reference.is_deleted() => reference.id(),
                Some(_) => {
                    return Err(nothing_to_show(format!(
                        "The credential `{}` used was deleted, so it has no password to show.",
                        node.name
                    )));
                }
                None => {
                    return Err(nothing_to_show(format!(
                        "`{}` has no credential, so there is no password to show.",
                        node.name
                    )));
                }
            }
        }
        _ => {
            return Err(nothing_to_show(format!(
                "`{}` is not a connection, so it has no password to show.",
                node.name
            )));
        }
    };

    let Some(credential) = tree.get(credential_id) else {
        return Err(nothing_to_show(format!(
            "The credential `{}` used is no longer in this vault, so it has no password to show.",
            node.name
        )));
    };
    let Some(props) = credential.kind.as_credential() else {
        return Err(nothing_to_show(format!(
            "`{}` is not a credential, so it has no password to show.",
            credential.name
        )));
    };
    if !matches!(props.secret, SecretKind::Password { .. }) {
        return Err(nothing_to_show(format!(
            "`{}` signs in with a key or an agent rather than a password, so there is no \
             password to show.",
            credential.name
        )));
    }

    let username = Some(props.username.clone()).filter(|name| !name.trim().is_empty());
    let shared = !props.is_attached();
    let credential_name = credential.name.clone();

    // Audited as `secret_revealed` inside the borrow, and saved so the row
    // survives a crash a moment from now.
    let bytes = vault
        .borrow_secret(*credential_id.as_uuid(), "password", Purpose::Reveal)
        .map_err(|err| IpcError::from_vault(&err, &credential_name))?;
    save(vault)?;

    // A password is typed text. Bytes that are not UTF-8 came from an import
    // that wrote them that way; showing them with replacement characters is
    // more useful than refusing, and says plainly that something is odd.
    let password = Secret::new(String::from_utf8_lossy(bytes.expose_secret()).into_owned());
    drop(bytes);

    Ok(RevealedSecretDto {
        node_id: id.as_uuid().to_string(),
        credential_name,
        shared,
        username,
        password,
        window_remaining_ms: millis(remaining),
    })
}

/// A refused confirmation counts toward the unlock backoff, and is written to
/// the audit log as the failed unlock it is.
fn record_refusal(inner: &mut Inner, path: &Path) {
    inner.record_unlock_failure(path);
    let Ok(vault) = inner.vault_mut() else {
        return;
    };
    let written = vault
        .audit(
            AuditEvent::VaultUnlockFailed,
            AuditOutcome::Failure,
            Some("the vault password was not confirmed before showing a stored password"),
        )
        .map_err(|err| IpcError::from_vault(&err, "this vault"))
        .and_then(|()| save(vault));
    if let Err(err) = written {
        tracing::warn!(
            "a refused password confirmation could not be recorded: {}",
            err.message
        );
    }
}

// ================================================================ failures ==

fn confirm_required() -> IpcError {
    IpcError::new(
        "secret.reveal-confirm",
        "Enter this vault's password to show a stored password. It is not asked for again for \
         ten minutes.",
    )
}

fn refused() -> IpcError {
    IpcError::new(
        "secret.reveal-refused",
        "That is not this vault's password, so nothing was shown.",
    )
    .with_actions(["Try again"])
}

fn no_password_slot() -> IpcError {
    IpcError::new(
        "secret.reveal-no-password-slot",
        "This vault has no password key slot, so there is no password to confirm before showing \
         one.",
    )
    .with_actions(["Add a password in Vault settings"])
}

fn nothing_to_show(message: String) -> IpcError {
    IpcError::new("secret.reveal-nothing", message)
        .with_actions(["Open this connection's settings"])
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;

    use remoter_vault::AuditQuery;

    use crate::commands::node_create_impl;
    use crate::dto::{CreateNodeDto, CredentialInputDto};
    use crate::test_support::{PASSPHRASE, Scratch, open_vault, why};

    const SERVER_PASSWORD: &str = "zq-server-pw-7731";
    const OTHER_PASSWORD: &str = "zq-other-pw-1209";

    fn connection(state: &AppState, name: &str, password: Option<&str>) -> String {
        let created = node_create_impl(
            state,
            &mut CreateNodeDto {
                parent_id: None,
                kind: String::from("connection"),
                name: name.to_owned(),
                protocol: Some(String::from("ssh")),
                host: Some(String::from("db-01.example.com")),
                port: None,
                username: password.map(|_| String::from("deploy")),
                password: password.map(ToOwned::to_owned),
                credential: None,
                credential_id: None,
                gateway: None,
            },
        );
        assert!(created.is_ok(), "creating failed: {}", why(&created));
        created.unwrap().id
    }

    fn reveal_with(
        state: &AppState,
        id: &str,
        password: Option<&str>,
    ) -> Result<RevealedSecretDto, IpcError> {
        secret_reveal_impl(
            &state.inner_handle(),
            id,
            password.map(|p| Secret::new(p.to_owned())),
        )
    }

    fn code<T>(result: &Result<T, IpcError>) -> String {
        result
            .as_ref()
            .err()
            .map_or_else(String::new, |err| err.code.clone())
    }

    fn audit_count(state: &AppState, event: AuditEvent) -> usize {
        let mut guard = state.lock();
        let vault = guard.vault_ref().unwrap();
        vault
            .audit_query(&AuditQuery::new())
            .unwrap()
            .iter()
            .filter(|record| record.event == event.as_str())
            .count()
    }

    #[test]
    fn nothing_is_shown_until_the_vault_password_is_confirmed() {
        let scratch = Scratch::new();
        let state = open_vault(&scratch).expect("the vault could not be created");
        let web = connection(&state, "web-01", Some(SERVER_PASSWORD));

        let asked = reveal_with(&state, &web, None);
        assert_eq!(code(&asked), "secret.reveal-confirm");

        let wrong = reveal_with(&state, &web, Some("not the vault password"));
        assert_eq!(code(&wrong), "secret.reveal-refused");
        assert!(reveal_window_impl(&state.lock()).remaining_ms.is_none());
        assert_eq!(audit_count(&state, AuditEvent::SecretRevealed), 0);
        assert_eq!(audit_count(&state, AuditEvent::VaultUnlockFailed), 1);

        let shown = reveal_with(&state, &web, Some(PASSPHRASE));
        assert!(shown.is_ok(), "showing failed: {}", why(&shown));
        let shown = shown.unwrap();
        assert_eq!(shown.password.expose_secret(), SERVER_PASSWORD);
        assert_eq!(shown.username.as_deref(), Some("deploy"));
        assert!(!shown.shared);
        assert!(shown.window_remaining_ms > 0);
        assert!(shown.window_remaining_ms <= millis(REVEAL_WINDOW));
        assert_eq!(audit_count(&state, AuditEvent::SecretRevealed), 1);
    }

    #[test]
    fn a_confirmation_covers_other_servers_for_the_window_and_not_after() {
        let scratch = Scratch::new();
        let state = open_vault(&scratch).expect("the vault could not be created");
        let web = connection(&state, "web-01", Some(SERVER_PASSWORD));
        let db = connection(&state, "db-01", Some(OTHER_PASSWORD));

        assert!(reveal_with(&state, &web, Some(PASSPHRASE)).is_ok());

        // No password this time: the window covers it.
        let second = reveal_with(&state, &db, None);
        assert!(second.is_ok(), "showing failed: {}", why(&second));
        assert_eq!(second.unwrap().password.expose_secret(), OTHER_PASSWORD);
        assert_eq!(audit_count(&state, AuditEvent::SecretRevealed), 2);

        state.lock().expire_reveal_window();
        assert!(reveal_window_impl(&state.lock()).remaining_ms.is_none());
        assert_eq!(
            code(&reveal_with(&state, &db, None)),
            "secret.reveal-confirm"
        );
    }

    #[test]
    fn ending_the_window_or_locking_the_vault_asks_again() {
        let scratch = Scratch::new();
        let state = open_vault(&scratch).expect("the vault could not be created");
        let web = connection(&state, "web-01", Some(SERVER_PASSWORD));

        assert!(reveal_with(&state, &web, Some(PASSPHRASE)).is_ok());
        assert!(reveal_window_impl(&state.lock()).remaining_ms.is_some());
        state.lock().end_reveal_window();
        assert_eq!(
            code(&reveal_with(&state, &web, None)),
            "secret.reveal-confirm"
        );

        assert!(reveal_with(&state, &web, Some(PASSPHRASE)).is_ok());
        assert!(state.lock().close_vault());
        assert!(reveal_window_impl(&state.lock()).remaining_ms.is_none());
        assert_eq!(code(&reveal_with(&state, &web, None)), "vault.locked");
    }

    #[test]
    fn only_a_password_is_ever_shown() {
        let scratch = Scratch::new();
        let state = open_vault(&scratch).expect("the vault could not be created");
        let bare = connection(&state, "no-credential", None);
        let agent = node_create_impl(
            &state,
            &mut CreateNodeDto {
                parent_id: None,
                kind: String::from("credential"),
                name: String::from("agent"),
                protocol: None,
                host: None,
                port: None,
                username: Some(String::from("deploy")),
                password: None,
                credential: Some(CredentialInputDto::Agent {
                    comment_filter: None,
                }),
                credential_id: None,
                gateway: None,
            },
        );
        assert!(agent.is_ok(), "creating failed: {}", why(&agent));
        let agent = agent.unwrap().id;

        assert!(reveal_with(&state, &bare, Some(PASSPHRASE)).is_err());
        assert_eq!(
            code(&reveal_with(&state, &bare, None)),
            "secret.reveal-nothing"
        );
        assert_eq!(
            code(&reveal_with(&state, &agent, None)),
            "secret.reveal-nothing"
        );
        assert_eq!(audit_count(&state, AuditEvent::SecretRevealed), 0);
    }

    #[test]
    fn the_password_is_serialised_and_never_printed() {
        let scratch = Scratch::new();
        let state = open_vault(&scratch).expect("the vault could not be created");
        let web = connection(&state, "web-01", Some(SERVER_PASSWORD));
        let shown = reveal_with(&state, &web, Some(PASSPHRASE)).unwrap();

        let debug = format!("{shown:?}");
        assert!(!debug.contains(SERVER_PASSWORD), "{debug}");
        let json = serde_json::to_string(&shown).unwrap();
        assert!(json.contains(SERVER_PASSWORD));
        assert!(json.contains("windowRemainingMs"));
    }
}
