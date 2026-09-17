//! The Tauri command surface.
//!
//! This crate is the seam and nothing more: it maps DTOs, checks permissions,
//! and forwards to `remoter-core` and `remoter-vault`. It holds no business
//! rules. If you find yourself writing a decision here, it belongs one layer
//! down.
//!
//! **A secret never crosses this boundary.** The frontend asks for an action;
//! the core performs it with the secret and returns a result. There is no
//! command that returns a password, and adding one requires an explicit
//! review note explaining why the rule does not apply.

#![doc(html_no_source)]

mod actor;
mod audit;
mod bridge;
mod clipboard;
mod commands;
mod dto;
mod error;
mod export;
mod import;
#[cfg(all(test, feature = "integration-tests"))]
mod live_tests;
mod lock_watch;
mod recents;
mod session;
mod sftp;
mod state;
#[cfg(test)]
mod test_support;
mod tunnel;
mod vault_admin;

pub use dto::*;
pub use error::IpcError;
pub use session::{
    CapabilitiesDto, HostKeyDecisionDto, HostKeyPromptDto, ProgressDto, PromptDto,
    SessionFailureDto, SessionMessageDto, SessionOpenedDto, SessionSummaryDto, TrustedHostKeyDto,
};
pub use sftp::{
    DirectoryEntryDto, EnqueueReportDto, EnqueueSkippedDto, NameRisksDto, PreflightProblemDto,
    ResolvedPathDto, SftpDeleteFailureDto, SftpDeleteReportDto, SftpPaneDto, TransferPreflightDto,
    TransferRequestDto, TransferStartDto, TransferStateDto, TransferStatusDto,
};
pub use state::AppState;
pub use tunnel::{TunnelDto, TunnelSpecDto};

/// Records which operating-system account and machine this process runs as, so
/// every audit row a vault writes from now on names them.
///
/// Call it once at startup, before the first vault is opened: the unlock row is
/// written inside the unlock itself. Returns whether an identity was found and
/// set. When the platform will not say, rows are written unattributed and the
/// audit screen shows them as not recorded, which is truer than a guess.
pub fn identify_process() -> bool {
    match actor::detect() {
        Some(actor) => remoter_vault::set_audit_actor(actor),
        None => {
            tracing::warn!(
                "could not determine the account this process runs as; audit rows will be unattributed"
            );
            false
        }
    }
}

/// Registers every command with the Tauri builder.
///
/// Keep this list and `apps/desktop/ui/src/lib/ipc.ts` in step — the TypeScript
/// wrappers are the only place the frontend may call `invoke`.
pub fn handler() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        // --- vault lifecycle ---
        commands::vault_list_recent,
        commands::vault_forget_recent,
        commands::vault_clear_recents,
        commands::vault_probe,
        commands::vault_create,
        commands::vault_unlock,
        commands::vault_lock,
        commands::vault_state,
        commands::vault_upgrade_kdf,
        // --- vault creation helpers ---
        commands::generate_passphrase,
        commands::password_strength,
        commands::generate_keyfile,
        commands::recovery_sheet_write,
        commands::suggest_vault_path,
        // --- tree ---
        commands::tree_list,
        commands::tree_search,
        commands::node_create,
        commands::node_update,
        commands::node_delete,
        commands::node_move,
        commands::node_resolve,
        // --- protocol schemas ---
        commands::protocol_schemas,
        // --- credentials ---
        commands::key_inspect,
        // --- key slots ---
        vault_admin::vault_slots,
        vault_admin::vault_add_password_slot,
        vault_admin::vault_add_recovery_slot,
        vault_admin::vault_add_keychain_slot,
        vault_admin::vault_remove_slot,
        vault_admin::vault_change_master_password,
        vault_admin::vault_rotate_recovery_key,
        vault_admin::vault_rotate_master_key,
        // --- per-vault settings ---
        vault_admin::vault_settings_get,
        vault_admin::vault_settings_set,
        // --- clipboard ---
        clipboard::clipboard_read_text,
        clipboard::clipboard_write_text,
        // --- audit ---
        audit::audit_query,
        audit::audit_filters,
        audit::audit_actors,
        audit::audit_export,
        // --- export ---
        export::tree_export,
        // --- import ---
        import::import_detect,
        import::import_parse,
        import::import_cancel,
        import::import_commit,
        import::import_conflicts,
        import::import_putty_location,
        // --- settings ---
        commands::settings_get,
        commands::settings_set,
        commands::shortcuts_list,
        // --- update check ---
        commands::update_check,
        // --- sessions ---
        session::session_open,
        session::session_input,
        session::session_key,
        session::session_pointer,
        session::session_resize,
        session::session_close,
        session::session_list,
        session::host_key_decide,
        // --- sftp ---
        sftp::sftp_open,
        sftp::sftp_close,
        sftp::sftp_list,
        sftp::sftp_stat,
        sftp::sftp_canonicalize,
        sftp::sftp_read_link,
        sftp::sftp_mkdir,
        sftp::sftp_rename,
        sftp::sftp_delete,
        sftp::sftp_set_permissions,
        sftp::sftp_symlink,
        sftp::sftp_preflight,
        sftp::sftp_enqueue,
        sftp::sftp_transfers,
        sftp::sftp_transfer_cancel,
        sftp::sftp_transfer_cancel_all,
        sftp::sftp_transfer_retry,
        // --- tunnels ---
        tunnel::tunnel_open,
        tunnel::tunnel_close,
        tunnel::tunnel_list,
    ]
}
