//! Process-wide state: the open vault, the settings, the recent-vault list.
//!
//! One `parking_lot::Mutex` guards all three. That is deliberate rather than
//! lazy: `docs/architecture/storage.md` specifies the vault as **single-writer**
//! — every mutation funnels through one owner and readers take consistent
//! snapshots — and one lock is the smallest thing that keeps that true. It is
//! `parking_lot`'s mutex because a poisoned `std` mutex would leave the vault
//! unreachable after any panic, and a panicking session is supposed to cost one
//! tab, not the whole application (ADR-0011).
//!
//! Commands hold the lock for the duration of one operation and never across an
//! await point; there are no async commands in this crate.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use parking_lot::{Mutex, MutexGuard};
use remoter_vault::{Vault, VaultSettings};
use serde::{Deserialize, Deserializer, Serialize};

use crate::dto::{AppSettingsDto, TerminalAppearanceDto};
use crate::error::IpcError;
use crate::recents::{Recents, write_atomic};
use crate::session::SessionHub;

/// Environment variable that relocates the configuration directory. Set by the
/// tests, and by anyone running Remoter from a portable drive.
const CONFIG_DIR_ENV: &str = "REMOTER_CONFIG_DIR";

const RECENTS_FILE: &str = "recents.json";
const SETTINGS_FILE: &str = "settings.json";

/// Schema version of `settings.json`.
const SETTINGS_VERSION: u32 = 1;

/// Narrowest and widest sidebar the interface will restore.
const MIN_SIDEBAR_WIDTH: u32 = 180;
const MAX_SIDEBAR_WIDTH: u32 = 640;

/// Auto-lock bounds. Below a minute the application is unusable; a day is the
/// point at which "automatic" stops meaning anything.
const MIN_AUTO_LOCK_MINUTES: u32 = 1;
const MAX_AUTO_LOCK_MINUTES: u32 = 1440;

/// The themes the interface implements. An unknown name would leave it with no
/// stylesheet, so it is rejected at the boundary rather than stored.
const THEMES: &[&str] = &["system", "light", "dark", "hc-light", "hc-dark"];

/// The update channels. Checking is opt-in and off by default; see
/// [`AppSettingsDto::update_check_enabled`](crate::AppSettingsDto).
const UPDATE_CHANNELS: &[&str] = &["stable", "beta"];

/// The terminal palettes this build ships, plus `"auto"`.
///
/// Mirrors `TERMINAL_PALETTES` in `apps/desktop/ui/src/lib/terminalPalette.ts`.
/// An unknown id would leave the terminal resolving to a fallback the user did
/// not choose, so it is refused at the boundary rather than stored.
const TERMINAL_PALETTES: &[&str] = &[
    "auto",
    "remoter-dark",
    "remoter-light",
    "solarized-dark",
    "solarized-light",
    "gruvbox-dark",
    "nord",
    "tomorrow-night",
    "high-contrast",
];

/// The colours a terminal appearance may override. Same order and same names
/// as `TERMINAL_COLOR_KEYS` on the TypeScript side.
const TERMINAL_COLOR_KEYS: &[&str] = &[
    "background",
    "foreground",
    "cursor",
    "cursorAccent",
    "selection",
    "black",
    "red",
    "green",
    "yellow",
    "blue",
    "magenta",
    "cyan",
    "white",
    "brightBlack",
    "brightRed",
    "brightGreen",
    "brightYellow",
    "brightBlue",
    "brightMagenta",
    "brightCyan",
    "brightWhite",
];

/// Terminal font bounds. Below 8px the cell stops being legible at all; above
/// 32 a standard 80-column shell no longer fits in a window.
const MIN_TERMINAL_FONT_SIZE: u32 = 8;
const MAX_TERMINAL_FONT_SIZE: u32 = 32;

/// Longest font family string accepted. A font stack is a few names; anything
/// longer is a paste accident, and it ends up in a CSS property.
const MAX_FONT_FAMILY_LEN: usize = 200;

/// One editable binding, as this build ships it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ShortcutSpec {
    pub(crate) id: &'static str,
    /// `"universal"` works even inside a focused terminal; `"application"` is
    /// reached through the terminal prefix while a session has focus.
    pub(crate) scope: &'static str,
    pub(crate) accelerator: &'static str,
    /// How many consecutive keys the binding covers. Nine for "jump to tab
    /// 1–9", which is one action and nine keys.
    pub(crate) series_len: u8,
    /// Whether the desktop environment takes this combination first. Stated
    /// rather than left to be discovered: a shortcut that mysteriously does
    /// nothing reads as a broken application.
    pub(crate) desktop_conflict: bool,
}

/// The shipped keyboard map — `ui_parts/project_ui_design/09 App Settings`.
///
/// Only overrides are stored, so changing a default here reaches everyone who
/// has not rebound that action.
pub(crate) const SHORTCUTS: &[ShortcutSpec] = &[
    ShortcutSpec {
        id: "palette.open",
        scope: "universal",
        accelerator: "ctrl+k",
        series_len: 1,
        desktop_conflict: false,
    },
    ShortcutSpec {
        id: "vault.lock",
        scope: "universal",
        accelerator: "ctrl+l",
        series_len: 1,
        desktop_conflict: false,
    },
    ShortcutSpec {
        id: "shortcuts.cheatsheet",
        scope: "universal",
        accelerator: "?",
        series_len: 1,
        desktop_conflict: false,
    },
    ShortcutSpec {
        id: "connection.new",
        scope: "application",
        accelerator: "ctrl+n",
        series_len: 1,
        desktop_conflict: false,
    },
    ShortcutSpec {
        id: "folder.new",
        scope: "application",
        accelerator: "ctrl+shift+n",
        series_len: 1,
        desktop_conflict: false,
    },
    ShortcutSpec {
        id: "tab.close",
        scope: "application",
        accelerator: "ctrl+w",
        series_len: 1,
        desktop_conflict: false,
    },
    ShortcutSpec {
        id: "tab.next",
        scope: "application",
        accelerator: "ctrl+tab",
        series_len: 1,
        // GNOME's window switcher takes this one, and Remoter yields to the
        // desktop rather than fighting it.
        desktop_conflict: true,
    },
    ShortcutSpec {
        id: "tab.jump",
        scope: "application",
        accelerator: "alt+1",
        series_len: 9,
        desktop_conflict: false,
    },
    ShortcutSpec {
        id: "sidebar.toggle",
        scope: "application",
        accelerator: "ctrl+b",
        series_len: 1,
        desktop_conflict: false,
    },
    ShortcutSpec {
        id: "session.fullscreen",
        scope: "application",
        accelerator: "f11",
        series_len: 1,
        desktop_conflict: false,
    },
];

/// Keystrokes a focused terminal has to receive.
///
/// `docs/architecture/session-pipeline.md` is unambiguous that the session owns
/// the keyboard: binding one of these would send an interrupt to the desktop
/// instead of to the remote shell, which is a data-loss bug wearing a
/// preferences dialogue.
const TERMINAL_RESERVED: &[&str] = &["ctrl+c", "ctrl+d", "alt+f"];

/// The modifier names an accelerator may carry, each mapped to its canonical
/// spelling. Platform aliases collapse here so that a binding made on a Mac
/// reads the same on a Linux machine.
const MODIFIERS: &[(&str, &str)] = &[
    ("ctrl", "ctrl"),
    ("control", "ctrl"),
    ("alt", "alt"),
    ("option", "alt"),
    ("shift", "shift"),
    ("meta", "meta"),
    ("cmd", "meta"),
    ("command", "meta"),
    ("super", "meta"),
    ("win", "meta"),
];

/// The named keys an accelerator may end on, beside a single character and the
/// function keys.
const NAMED_KEYS: &[&str] = &[
    "tab",
    "space",
    "enter",
    "return",
    "escape",
    "backspace",
    "delete",
    "insert",
    "home",
    "end",
    "pageup",
    "pagedown",
    "up",
    "down",
    "left",
    "right",
];

/// Failed unlocks tolerated before the backoff starts.
///
/// `docs/security/vault-format.md`: "a short exponential backoff after three
/// failures, capped, with no lockout that could destroy data". The attacker
/// this delays is the one at the keyboard; the one with the file offline is
/// held off by Argon2id, and nothing here adds to that.
const UNLOCK_FAILURES_BEFORE_BACKOFF: u32 = 3;

/// The delay after the first failure past the threshold, doubling thereafter.
const UNLOCK_BACKOFF_BASE: Duration = Duration::from_secs(1);

/// The cap. Long enough to make guessing at the keyboard tedious, short enough
/// that a user who has simply mistyped their passphrase four times is not shut
/// out of their own vault.
const UNLOCK_BACKOFF_CAP: Duration = Duration::from_secs(30);

/// How many consecutive failures this build will double for. Past this the
/// delay is the cap anyway, and the shift is what would overflow.
const UNLOCK_BACKOFF_MAX_DOUBLINGS: u32 = 16;

/// How long a resume has to have skipped for the machine to count as having
/// slept. See `lock_watch::slept_through`.
///
/// Declared here beside the other lock policy rather than in the watcher, so
/// that the number a reviewer has to argue with is next to the timeout it
/// belongs with.
///
/// # Why the lint is allowed off Linux
///
/// This constant, [`LockTrigger::enabled_in`], [`LockReason::Trigger`] and
/// [`Inner::lock_for_trigger`] are one chain: the link that enters it is the
/// resume watcher in [`crate::lock_watch`], and that watcher exists on Linux
/// only. Off Linux nothing calls any of the four, `dead_code` fires on all of
/// them, and CI runs with `RUSTFLAGS: -D warnings` — so the `test` job fails
/// to compile on windows-latest and macos-latest, which is how this was found.
///
/// The lint is allowed rather than the items being `cfg`-gated away. Gating
/// would not stop at these four: `LockReason::Trigger` is matched in
/// [`Inner::locked_error`], which is where `LockTrigger::describe` and
/// `IpcError::locked_by_trigger` are reached from, so removing the variant
/// would carry a live error message and its catalogue entry out with it on two
/// platforms. The settings these read, and the `observation()` the interface
/// renders from them, are present on all three platforms; what is missing off
/// Linux is a watcher to call them, not the feature. When one is written,
/// these four attributes come off with it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const RESUME_GAP: Duration = Duration::from_secs(60);

/// The moment anything last counted as activity, shared lock-free.
///
/// Deliberately *not* inside the state mutex. Two reasons, and the second is
/// the bug this type exists to fix:
///
/// 1. Session output arrives on the frame timer from a task that must never
///    queue behind the vault lock — `docs/architecture/rendering.md` measures
///    that queue in dropped frames.
/// 2. Idle used to be measured from the last vault-touching IPC call, so
///    working inside a session was not activity at all: the vault locked out
///    from under a user who was typing in a terminal. Session input and
///    session output touch this clock, and neither of them goes near the
///    vault.
///
/// What this measures is Remoter's own traffic — the vault, and the sessions.
/// It is **not** the desktop's input idle time, and the interface says so
/// rather than claiming otherwise.
#[derive(Debug)]
pub(crate) struct ActivityClock {
    /// Monotonic, so moving the system clock cannot postpone a lock.
    base: Instant,
    /// Milliseconds since `base`, signed so a test can push it into the past.
    /// Written with `fetch_max`, so two threads racing can only move it
    /// forward.
    millis: AtomicI64,
}

impl ActivityClock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            millis: AtomicI64::new(0),
        }
    }

    /// Records that something happened now.
    pub(crate) fn touch(&self) {
        self.millis
            .fetch_max(self.elapsed_millis(), Ordering::Relaxed);
    }

    /// How long since the last recorded activity.
    pub(crate) fn idle_for(&self) -> Duration {
        let idle = self
            .elapsed_millis()
            .saturating_sub(self.millis.load(Ordering::Relaxed));
        Duration::from_millis(u64::try_from(idle).unwrap_or_default())
    }

    fn elapsed_millis(&self) -> i64 {
        i64::try_from(self.base.elapsed().as_millis()).unwrap_or(i64::MAX)
    }

    /// Pushes the clock a day into the past, so a test can watch a timeout
    /// expire without waiting a minute for the shortest one.
    #[cfg(test)]
    pub(crate) fn expire(&self) {
        const A_DAY_MS: i64 = 1000 * 60 * 60 * 24;
        self.millis.store(
            self.elapsed_millis().saturating_sub(A_DAY_MS),
            Ordering::Relaxed,
        );
    }
}

/// An event outside Remoter that a vault can be configured to lock on.
///
/// `docs/security/key-management.md#auto-lock` lists these beside the idle
/// timeout. Each one is a switch in the vault's own settings, so the policy
/// travels with the file the way `sessionOnLock` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockTrigger {
    /// The operating system's screen or session lock engaged.
    ScreenLock,
    /// The machine suspended or hibernated.
    Suspend,
    /// The application window was minimised.
    Minimise,
}

impl LockTrigger {
    /// Every trigger, in the order the settings screen lists them.
    ///
    /// Test-only. The product code names each variant at the one place it maps
    /// them to their three separate settings fields, and a slice there would
    /// hide which field went with which trigger. What the tests need is the
    /// opposite: something to iterate, so that adding a fourth trigger cannot
    /// quietly go untested.
    #[cfg(test)]
    pub(crate) const ALL: &'static [Self] = &[Self::ScreenLock, Self::Suspend, Self::Minimise];

    /// The switch in the vault's settings that governs this trigger.
    ///
    /// Only [`Inner::lock_for_trigger`] asks, and only the Linux resume
    /// watcher calls that — see the note on [`RESUME_GAP`] for why the lint is
    /// allowed off Linux rather than the item gated away.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const fn enabled_in(self, settings: &VaultSettings) -> bool {
        match self {
            Self::ScreenLock => settings.lock_on_screen_lock,
            Self::Suspend => settings.lock_on_suspend,
            Self::Minimise => settings.lock_on_minimise,
        }
    }

    /// How a message names it. A clause, so it reads after "because".
    pub(crate) const fn describe(self) -> &'static str {
        match self {
            Self::ScreenLock => "the screen locked",
            Self::Suspend => "the machine had been suspended",
            Self::Minimise => "the window was minimised",
        }
    }

    /// How well **this build, on this platform** can actually see the event.
    ///
    /// This is the whole point of the type crossing the IPC boundary. A switch
    /// that persists a value nothing observes is a control that does not do
    /// what it says, so the interface is told which of these Remoter can see
    /// and disables the ones it cannot rather than pretending.
    ///
    /// - `"observed"` — seen as it happens.
    /// - `"on_resume"` — seen only afterwards, when the machine comes back.
    /// - `"unobserved"` — this build cannot see it here at all.
    pub(crate) const fn observation(self) -> &'static str {
        match self {
            // Watching this means the freedesktop screensaver and login1
            // session signals on Linux, and a different API on every other
            // platform. All of them need a D-Bus (or equivalent) client this
            // crate does not depend on, so the switch is declared unobservable
            // rather than left looking as though it works.
            Self::ScreenLock => "unobserved",
            // logind's `PrepareForSleep` would give advance notice. Without it,
            // what Remoter can still see for free is the *return*: on Linux
            // `Instant` is `CLOCK_MONOTONIC`, which does not advance across a
            // suspend, while the wall clock does. See `crate::lock_watch`.
            Self::Suspend => {
                if cfg!(target_os = "linux") {
                    "on_resume"
                } else {
                    "unobserved"
                }
            }
            // Tauri 2.11's `WindowEvent` has no minimise variant, and the
            // polled `Window::is_minimized()` under it is driven by GTK's
            // `ICONIFIED` window state, which a Wayland compositor never sends
            // to the client. An X11-only switch that silently does nothing on
            // Wayland is the defect, not the fix.
            Self::Minimise => "unobserved",
        }
    }
}

/// Why the vault is shut, when it shut itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockReason {
    /// The idle timeout expired. Carries the timeout that was in force, which
    /// may have come from the vault rather than from this machine.
    Idle(u32),
    /// An operating-system event the vault is configured to lock on.
    ///
    /// Constructed only by [`Inner::lock_for_trigger`], so off Linux it is
    /// never constructed at all — see the note on [`RESUME_GAP`]. It is still
    /// *matched* there, in [`Inner::locked_error`], which is what would break
    /// if this were gated out instead.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Trigger(LockTrigger),
}

/// Everything the command surface shares.
///
/// The vault and the sessions are deliberately separate. A session outlives a
/// locked vault whenever the vault's own policy says it should, so a lock on
/// the vault must not be a lock on the sessions — and a session task that needs
/// the trust store must not be able to deadlock the interface by wanting the
/// registry the interface is holding.
#[derive(Debug)]
pub struct AppState {
    inner: Arc<Mutex<Inner>>,
    sessions: Arc<SessionHub>,
    /// The idle clock, held here as well as in `Inner` so that the session
    /// commands can record traffic without taking the vault lock.
    activity: Arc<ActivityClock>,
}

impl AppState {
    /// Loads the settings and the recent-vault list, with no vault open.
    ///
    /// Never fails: an unreadable configuration file is a warning and a set of
    /// defaults, because refusing to start over a preferences file would be a
    /// poor trade.
    #[must_use]
    pub fn new() -> Self {
        let paths = ConfigPaths::resolve();
        let settings = load_settings(&paths.settings_file());
        let recents = Recents::load(&paths.recents_file());
        let sessions = Arc::new(SessionHub::new());
        let activity = Arc::new(ActivityClock::new());

        let inner = Arc::new(Mutex::new(Inner {
            paths,
            vault: None,
            settings,
            recents,
            activity: Arc::clone(&activity),
            lock_reason: None,
            unlock_failures: BTreeMap::new(),
            lock_failure: None,
            pending_import: None,
            sessions: Arc::clone(&sessions),
        }));

        // The only lock trigger this build can observe without reaching for a
        // platform service it does not depend on. Started here rather than
        // from the Tauri setup hook because it needs nothing from Tauri, and a
        // security control that only arms if the interface remembers to arm it
        // is a security control with a way to be forgotten.
        crate::lock_watch::watch_for_resume(&inner);

        Self {
            inner,
            sessions,
            activity,
        }
    }

    /// The same, with the configuration directory named outright.
    ///
    /// Exists because [`AppState::new`] resolves the directory from the
    /// platform and the environment, and a test may not set an environment
    /// variable: `std::env::set_var` is `unsafe` in this edition, and this
    /// crate forbids `unsafe`.
    #[cfg(test)]
    pub(crate) fn with_config_dir(config_dir: PathBuf) -> Self {
        let paths = ConfigPaths { config_dir };
        let settings = load_settings(&paths.settings_file());
        let recents = Recents::load(&paths.recents_file());
        let sessions = Arc::new(SessionHub::new());
        let activity = Arc::new(ActivityClock::new());

        // No resume watcher: a test that creates a hundred of these does not
        // want a hundred sleeping threads, and what the watcher decides is
        // tested directly in `lock_watch`.
        Self {
            inner: Arc::new(Mutex::new(Inner {
                paths,
                vault: None,
                settings,
                recents,
                activity: Arc::clone(&activity),
                lock_reason: None,
                unlock_failures: BTreeMap::new(),
                lock_failure: None,
                pending_import: None,
                sessions: Arc::clone(&sessions),
            })),
            sessions,
            activity,
        }
    }

    /// Takes the lock. Held for one operation, never across an await.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock()
    }

    /// A handle on the guarded interior, for something that outlives one
    /// command — the trust store a running handshake writes through.
    pub(crate) fn inner_handle(&self) -> Arc<Mutex<Inner>> {
        Arc::clone(&self.inner)
    }

    /// The session and tunnel registry. Reached without the vault lock: an
    /// async command must be able to await on a session without holding it.
    pub(crate) fn sessions(&self) -> Arc<SessionHub> {
        Arc::clone(&self.sessions)
    }

    /// The idle clock. Reached without the vault lock, which is what lets a
    /// keystroke and a frame of output count as activity from the session
    /// tasks.
    pub(crate) fn activity(&self) -> Arc<ActivityClock> {
        Arc::clone(&self.activity)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// The guarded interior.
#[derive(Debug)]
pub(crate) struct Inner {
    paths: ConfigPaths,
    vault: Option<Vault>,
    settings: AppSettingsDto,
    recents: Recents,
    /// The shared idle clock. Monotonic, so changing the system clock cannot
    /// postpone an auto-lock, and outside this mutex so that session traffic
    /// can reach it.
    activity: Arc<ActivityClock>,
    /// Set when the vault shut itself, so the next command can say why rather
    /// than just that it is shut.
    lock_reason: Option<LockReason>,
    /// Consecutive failed unlocks per vault path, and when the next attempt is
    /// allowed. In memory only: the vault's own audit table is unreachable
    /// while an unlock is failing, and a counter on disk would be a file an
    /// attacker with the vault could simply delete.
    unlock_failures: BTreeMap<PathBuf, UnlockFailures>,
    /// A save that failed on the way to locking, kept for the next
    /// `vault_state` poll to report. Auto-lock has no caller to return it to.
    lock_failure: Option<IpcError>,
    /// The import preview the wizard is working through, if any. Held here
    /// rather than sent to the interface because it carries the passwords
    /// recovered from the file in plaintext.
    pending_import: Option<PendingImport>,
    /// The same registry `AppState` holds. Here so that locking the vault —
    /// which happens on this side of the mutex, including from the idle
    /// timeout, which has no caller — can apply the vault's own
    /// `sessionOnLock` policy without a second entry point that could be
    /// forgotten.
    sessions: Arc<SessionHub>,
}

/// A parsed import, waiting for the user to confirm it.
///
/// `nodes` hold their recovered passwords in `remoter_import::ImportedSecret`,
/// which zeroizes on drop — so dropping this is what wipes them. It is dropped
/// when the import is committed, cancelled, or the vault locks.
#[derive(Debug)]
pub(crate) struct PendingImport {
    pub(crate) id: String,
    pub(crate) source: remoter_import::SourceFormat,
    pub(crate) nodes: Vec<remoter_import::PreviewNode>,
    pub(crate) report: remoter_import::ImportReport,
}

/// The failed-unlock record for one vault.
#[derive(Debug)]
struct UnlockFailures {
    consecutive: u32,
    /// `None` until the threshold is passed.
    next_allowed_at: Option<Instant>,
}

impl Inner {
    // ------------------------------------------------------------- vault ---

    /// The open vault, for a command that changes it.
    ///
    /// Enforces the idle timeout first, so a command arriving after the
    /// deadline finds the vault already locked rather than being served from
    /// keys that should have been wiped.
    pub(crate) fn vault_mut(&mut self) -> Result<&mut Vault, IpcError> {
        self.enforce_auto_lock();
        if self.vault.is_none() {
            return Err(self.locked_error());
        }
        self.activity.touch();
        self.vault.as_mut().ok_or_else(IpcError::locked)
    }

    /// The open vault, for a command that only reads it.
    pub(crate) fn vault_ref(&mut self) -> Result<&Vault, IpcError> {
        self.enforce_auto_lock();
        if self.vault.is_none() {
            return Err(self.locked_error());
        }
        self.activity.touch();
        self.vault.as_ref().ok_or_else(IpcError::locked)
    }

    /// Installs a freshly opened vault and clears the auto-lock reason.
    pub(crate) fn open_vault(&mut self, vault: Vault) {
        if let Some(previous) = self.vault.take() {
            previous.lock();
        }
        self.vault = Some(vault);
        self.activity.touch();
        self.lock_reason = None;
        // Whatever a previous lock froze is thawed: the keys are back, so the
        // reason to hold input is gone.
        self.sessions.thaw();
    }

    /// Writes the open vault, if there is one, before it is locked.
    ///
    /// Returns the failure instead of swallowing it: a lock that reports
    /// success has told the user their edits are on disk, and on a network
    /// share that dropped they are not. The keys are wiped either way — the
    /// caller closes the vault whatever this returns.
    pub(crate) fn save_before_locking(&mut self) -> Option<IpcError> {
        let vault = self.vault.as_mut()?;
        let path = vault.path().display().to_string();
        match vault.save() {
            Ok(()) => None,
            Err(err) => Some(
                IpcError::new(
                    "vault.locked-unsaved",
                    format!(
                        "The vault is locked and its keys are wiped, but {path} could not be \
                         written, so anything changed since the last successful save is gone."
                    ),
                )
                .with_detail(err.to_string())
                .with_actions([
                    "Check the drive or share the vault is stored on",
                    "Unlock it again and check what is missing",
                ]),
            ),
        }
    }

    /// Takes the pending lock failure, if any. Reported once.
    pub(crate) fn take_lock_failure(&mut self) -> Option<IpcError> {
        self.lock_failure.take()
    }

    // ------------------------------------------------- failed unlocks ------

    /// Refuses an unlock that arrives inside the backoff window.
    pub(crate) fn check_unlock_allowed(&self, path: &Path) -> Result<(), IpcError> {
        let Some(record) = self.unlock_failures.get(path) else {
            return Ok(());
        };
        let Some(deadline) = record.next_allowed_at else {
            return Ok(());
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }

        // The seconds are in the message so the interface can render a
        // countdown without a second round trip.
        let seconds = remaining.as_secs().saturating_add(1);
        Err(IpcError::new(
            "vault.unlock-throttled",
            format!(
                "That is {} unlock attempts in a row that did not work, so the next one \
                 waits {seconds} seconds. Nothing has been locked out: the vault opens as \
                 soon as the wait is over.",
                record.consecutive
            ),
        )
        .with_actions([
            "Wait for the countdown",
            "Use your recovery key",
            "Check the key file, if this vault uses one",
        ]))
    }

    /// Counts one failed unlock and extends the backoff.
    pub(crate) fn record_unlock_failure(&mut self, path: &Path) {
        let record = self
            .unlock_failures
            .entry(path.to_path_buf())
            .or_insert(UnlockFailures {
                consecutive: 0,
                next_allowed_at: None,
            });
        record.consecutive = record.consecutive.saturating_add(1);
        record.next_allowed_at = backoff_after(record.consecutive).map(|wait| {
            Instant::now()
                .checked_add(wait)
                .unwrap_or_else(Instant::now)
        });
    }

    /// Forgets a vault's failures and returns how many there were, so the
    /// caller can record them in the vault's own audit log now that it is
    /// open.
    pub(crate) fn clear_unlock_failures(&mut self, path: &Path) -> u32 {
        self.unlock_failures
            .remove(path)
            .map_or(0, |record| record.consecutive)
    }

    /// Closes the vault, wiping its keys. Returns whether one was open.
    ///
    /// Applies the vault's own `sessionOnLock` policy on the way through, which
    /// is the only place it can be applied without leaving a second path — the
    /// idle timeout locks from here too, and it has no caller to do it for it.
    pub(crate) fn close_vault(&mut self) -> bool {
        self.apply_session_lock_policy();
        self.lock_reason = None;
        // An uncommitted import holds plaintext passwords out of the source
        // file. Locking is supposed to leave none in memory, and a preview
        // that survived the lock would be exactly that.
        self.pending_import = None;
        match self.vault.take() {
            Some(vault) => {
                vault.lock();
                true
            }
            None => false,
        }
    }

    /// The open vault **without** counting as activity.
    ///
    /// `vault_state` polls on a timer, and a poll that reset the idle clock
    /// would postpone the auto-lock for as long as the window stayed open —
    /// which is exactly the case auto-lock exists for.
    pub(crate) fn vault_peek(&self) -> Option<&Vault> {
        self.vault.as_ref()
    }

    /// The idle timeout actually in force, in minutes. `None` means never.
    ///
    /// **The open vault's setting wins.** There are two `auto_lock_minutes` in
    /// this application — one in `settings.json` on this machine, one in the
    /// vault file — and until this function existed the countdown read the
    /// first while the Vault settings screen wrote the second, so choosing
    /// "1 min" or "Never" on that screen changed nothing at all.
    ///
    /// The vault is the authority because
    /// `docs/security/key-management.md#auto-lock` describes auto-lock as a
    /// property of the vault: a shared production vault reasonably deserves a
    /// tighter timeout than a personal one, and the timeout travels with the
    /// file the way `sessionOnLock` does. The application setting is what a
    /// vault gets when there is no vault open to ask.
    ///
    /// Read live rather than cached. It is one row of the already-decrypted
    /// in-memory database, and a cached copy would be a second value to keep in
    /// step — which is precisely how the two settings came to disagree.
    fn effective_auto_lock_minutes(&self) -> Option<u32> {
        let Some(vault) = self.vault.as_ref() else {
            return self.settings.auto_lock_minutes;
        };
        match vault.settings() {
            // Zero means never, which is what the interface's ladder offers
            // and what `VaultSettings::auto_lock_minutes` documents.
            Ok(settings) => (settings.auto_lock_minutes > 0).then_some(settings.auto_lock_minutes),
            // A settings row that will not read must not leave the vault open
            // for ever, so fall back to this machine's default rather than to
            // "never".
            Err(_) => self.settings.auto_lock_minutes,
        }
    }

    /// Seconds until the vault locks itself, or `None` when auto-lock is off
    /// or no vault is open.
    pub(crate) fn locks_in_seconds(&self) -> Option<u64> {
        self.vault.as_ref()?;
        let minutes = self.effective_auto_lock_minutes()?;
        let deadline = u64::from(minutes).saturating_mul(60);
        Some(deadline.saturating_sub(self.activity.idle_for().as_secs()))
    }

    /// Locks the vault if it has been idle past the configured timeout.
    ///
    /// v0.1 drives this from the commands themselves — every command that
    /// touches the vault checks first, and the interface polls `vault_state`
    /// on a timer — rather than from a background task. The consequence is
    /// that the keys can outlive the deadline in memory by as long as the poll
    /// interval; the timer task that closes that gap is on the roadmap.
    ///
    /// "Idle" is [`ActivityClock`]: no vault-touching command, and no session
    /// carrying traffic in either direction.
    pub(crate) fn enforce_auto_lock(&mut self) {
        if self.vault.is_none() {
            return;
        }
        let Some(minutes) = self.effective_auto_lock_minutes() else {
            return;
        };
        let deadline = Duration::from_secs(u64::from(minutes).saturating_mul(60));
        if self.activity.idle_for() < deadline {
            return;
        }

        self.lock_now(LockReason::Idle(minutes));
        tracing::info!("the vault locked itself after {minutes} minutes without activity");
    }

    /// Locks the vault because an operating-system event happened, if this
    /// vault's settings say that event should lock it. Returns whether it did.
    ///
    /// The switch is read from the vault rather than from this machine for the
    /// same reason `sessionOnLock` is: the policy travels with the file, so a
    /// vault carried to another computer locks on the same events there.
    ///
    /// The only caller outside the tests is the Linux resume watcher, so the
    /// lint is allowed elsewhere; see the note on [`RESUME_GAP`].
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn lock_for_trigger(&mut self, trigger: LockTrigger) -> bool {
        let Some(vault) = self.vault.as_ref() else {
            return false;
        };
        // A settings row that will not read falls back to the shipped
        // defaults, which is what a vault written before these switches
        // existed loads with anyway. Refusing to lock would be the wrong way
        // round for a security control; locking regardless of the switch would
        // ignore a decision the user made.
        let settings = vault.settings().unwrap_or_default();
        if !trigger.enabled_in(&settings) {
            return false;
        }

        self.lock_now(LockReason::Trigger(trigger));
        tracing::info!("the vault locked because {}", trigger.describe());
        true
    }

    /// Closes the vault and records why, for the locks that have no caller.
    ///
    /// The same save `vault_lock` does, and the same refusal to lose it
    /// quietly: there is nobody to return the failure to here, so it is kept
    /// for the next `vault_state` poll.
    fn lock_now(&mut self, reason: LockReason) {
        let failure = self.save_before_locking();
        if failure.is_some() {
            self.lock_failure = failure;
        }

        self.apply_session_lock_policy();
        if let Some(vault) = self.vault.take() {
            vault.lock();
        }
        self.pending_import = None;
        self.lock_reason = Some(reason);
    }

    /// Pushes the idle clock past any configured timeout, so a test can watch
    /// auto-lock happen without waiting a minute for it.
    #[cfg(test)]
    pub(crate) fn expire_activity(&mut self) {
        self.activity.expire();
    }

    /// Reads `sessionOnLock` out of the vault that is about to close, and
    /// applies it.
    ///
    /// Read from the vault rather than from the machine's settings because the
    /// policy travels with the vault file: a user who set "disconnect
    /// everything on lock" on a production vault means it wherever they open
    /// it. An unreadable setting keeps the sessions running, which is the
    /// documented default and the one that loses nothing.
    fn apply_session_lock_policy(&self) {
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        let policy = vault
            .settings()
            .map(|settings| settings.session_on_lock)
            .unwrap_or_default();
        self.sessions.apply_lock_policy(policy);
    }

    /// Why the vault is not available: idle timeout, or never opened.
    fn locked_error(&self) -> IpcError {
        match self.lock_reason {
            Some(LockReason::Idle(minutes)) => IpcError::auto_locked(minutes),
            Some(LockReason::Trigger(trigger)) => IpcError::locked_by_trigger(trigger.describe()),
            None => IpcError::locked(),
        }
    }

    // ----------------------------------------------------------- recents ---

    pub(crate) fn recents(&self) -> &Recents {
        &self.recents
    }

    /// Applies a change to the recent-vault list and writes it out.
    ///
    /// A failure to write is reported: the list is on this machine only, and a
    /// picker that silently forgets what the user just did is worse than an
    /// error they can act on.
    /// The key file this vault was last opened with, if one is remembered and
    /// still on disk. See `Recents::keyfile_for`.
    pub(crate) fn recents_keyfile_for(&self, path: &str) -> Option<String> {
        self.recents().keyfile_for(path)
    }

    pub(crate) fn update_recents(
        &mut self,
        change: impl FnOnce(&mut Recents),
    ) -> Result<(), IpcError> {
        change(&mut self.recents);
        self.recents.save(&self.paths.recents_file())
    }

    // ---------------------------------------------------------- settings ---

    pub(crate) fn settings(&self) -> &AppSettingsDto {
        &self.settings
    }

    /// Merges a patch into the settings and writes them out.
    pub(crate) fn apply_settings(
        &mut self,
        patch: AppSettingsPatch,
    ) -> Result<&AppSettingsDto, IpcError> {
        if let Some(theme) = patch.theme {
            if !THEMES.contains(&theme.as_str()) {
                return Err(IpcError::invalid_request(
                    "theme",
                    format!("`{theme}` is not one of {}", THEMES.join(", ")),
                ));
            }
            self.settings.theme = theme;
        }
        if let Some(locale) = patch.locale {
            if locale.trim().is_empty() {
                return Err(IpcError::invalid_request("locale", "it is empty"));
            }
            self.settings.locale = locale;
        }
        if let Some(minutes) = patch.auto_lock_minutes {
            self.settings.auto_lock_minutes =
                minutes.map(|minutes| minutes.clamp(MIN_AUTO_LOCK_MINUTES, MAX_AUTO_LOCK_MINUTES));
        }
        if let Some(value) = patch.lock_on_screen_lock {
            self.settings.lock_on_screen_lock = value;
        }
        if let Some(value) = patch.lock_on_suspend {
            self.settings.lock_on_suspend = value;
        }
        if let Some(width) = patch.sidebar_width {
            self.settings.sidebar_width = width.clamp(MIN_SIDEBAR_WIDTH, MAX_SIDEBAR_WIDTH);
        }
        if let Some(value) = patch.inspector_open {
            self.settings.inspector_open = value;
        }
        if let Some(value) = patch.update_check_enabled {
            self.settings.update_check_enabled = value;
        }
        if let Some(channel) = patch.update_channel {
            if !UPDATE_CHANNELS.contains(&channel.as_str()) {
                return Err(IpcError::invalid_request(
                    "updateChannel",
                    format!("`{channel}` is not one of {}", UPDATE_CHANNELS.join(", ")),
                ));
            }
            self.settings.update_channel = channel;
        }
        if let Some(at) = patch.update_last_checked_at {
            self.settings.update_last_checked_at = at;
        }
        if let Some(prefix) = patch.terminal_prefix {
            self.settings.terminal_prefix = normalise_prefix(&prefix)?;
        }
        if let Some(terminal) = patch.terminal {
            self.settings.terminal = normalise_terminal(terminal)?;
        }
        if let Some(folder) = patch.file_download_folder {
            // Nothing here checks that the folder exists. It is a path on the
            // user's own machine, it may be on a drive that is not plugged in
            // today, and refusing to *remember* it would be refusing to
            // remember the thing they will plug in tomorrow. The file manager
            // finds out when it writes, and says so then.
            self.settings.file_download_folder = folder.filter(|path| !path.trim().is_empty());
        }
        if let Some(shortcuts) = patch.shortcuts {
            self.apply_shortcuts(shortcuts)?;
        }

        save_settings(&self.paths.settings_file(), &self.settings)?;
        Ok(&self.settings)
    }

    /// Records that an update check reached the release list.
    ///
    /// Written whether or not anything newer was found, because "when did this
    /// last reach the server" is the question a user asking about updates
    /// actually has. A timestamp that only moved when there was news would
    /// answer a different one, and would look like a check that never runs.
    pub(crate) fn record_update_check(&mut self, at: i64) -> Result<(), IpcError> {
        self.apply_settings(AppSettingsPatch {
            update_last_checked_at: Some(Some(at)),
            ..AppSettingsPatch::default()
        })
        .map(|_| ())
    }

    /// Merges shortcut overrides, one action at a time.
    ///
    /// A `null` accelerator restores that action's shipped default rather than
    /// unbinding it: an action with no key at all is not something the screen
    /// offers, and storing an empty string would make the map say "bound to
    /// nothing" in a way nothing else reads.
    fn apply_shortcuts(
        &mut self,
        overrides: BTreeMap<String, Option<String>>,
    ) -> Result<(), IpcError> {
        for (id, accelerator) in overrides {
            let Some(spec) = SHORTCUTS.iter().find(|spec| spec.id == id) else {
                return Err(IpcError::invalid_request(
                    "shortcuts",
                    format!("`{id}` is not an action this build binds"),
                ));
            };
            let Some(accelerator) = accelerator else {
                self.settings.shortcuts.remove(&id);
                continue;
            };

            let accelerator = normalise_accelerator(&accelerator)?;
            if spec.scope == "universal" && TERMINAL_RESERVED.contains(&accelerator.as_str()) {
                return Err(IpcError::new(
                    "shortcut.terminal-reserved",
                    format!(
                        "`{accelerator}` belongs to the remote host: a focused terminal has \
                         to receive it, so binding it here would stop it reaching the shell."
                    ),
                )
                .with_actions([
                    "Choose another combination",
                    "Bind it as an application shortcut, reached through the terminal prefix",
                ]));
            }

            if accelerator == spec.accelerator {
                self.settings.shortcuts.remove(&id);
            } else {
                self.settings.shortcuts.insert(id, accelerator);
            }
        }
        Ok(())
    }

    /// Every binding, with its conflicts named.
    pub(crate) fn shortcuts(&self) -> Vec<crate::dto::ShortcutDto> {
        let mut resolved: Vec<(&ShortcutSpec, String)> = SHORTCUTS
            .iter()
            .map(|spec| {
                let accelerator = self
                    .settings
                    .shortcuts
                    .get(spec.id)
                    .cloned()
                    .unwrap_or_else(|| spec.accelerator.to_owned());
                (spec, accelerator)
            })
            .collect();
        resolved.sort_by(|(a, _), (b, _)| a.id.cmp(b.id));

        resolved
            .iter()
            .map(|(spec, accelerator)| {
                let conflicts_with: Vec<String> = resolved
                    .iter()
                    .filter(|(other, other_accelerator)| {
                        other.id != spec.id && other_accelerator == accelerator
                    })
                    .map(|(other, _)| other.id.to_owned())
                    .collect();

                // Order matters: a duplicate is the one the user can fix here,
                // so it is named first when a binding has more than one
                // problem.
                let conflict = if conflicts_with.is_empty() {
                    if TERMINAL_RESERVED.contains(&accelerator.as_str()) {
                        Some(String::from("terminal-reserved"))
                    } else if spec.desktop_conflict {
                        Some(String::from("desktop"))
                    } else {
                        None
                    }
                } else {
                    Some(String::from("duplicate"))
                };

                crate::dto::ShortcutDto {
                    id: spec.id.to_owned(),
                    scope: spec.scope.to_owned(),
                    accelerator: accelerator.clone(),
                    default_accelerator: spec.accelerator.to_owned(),
                    customised: accelerator != spec.accelerator,
                    series_len: spec.series_len,
                    conflict,
                    conflicts_with,
                }
            })
            .collect()
    }

    // ------------------------------------------------------------ import ---

    /// Holds the preview an import wizard is working through.
    ///
    /// One at a time: the wizard is a single flow, and a preview holds the
    /// passwords recovered from the file in plaintext, so a second parse
    /// replaces — and therefore zeroizes — the first rather than accumulating
    /// them.
    pub(crate) fn set_pending_import(&mut self, pending: PendingImport) {
        self.pending_import = Some(pending);
    }

    /// Takes the preview back out, checking it is the one the caller means.
    pub(crate) fn take_pending_import(&mut self, id: &str) -> Result<PendingImport, IpcError> {
        match self.pending_import.take() {
            Some(pending) if pending.id == id => Ok(pending),
            other => {
                // Put back a preview that belongs to a different wizard run
                // rather than dropping someone else's work on a stale click.
                self.pending_import = other;
                Err(IpcError::new(
                    "import.no-such-preview",
                    "That import preview is no longer held: it was committed, cancelled, or \
                     dropped when the vault locked. Nothing was written.",
                )
                .with_actions(["Choose the file again"]))
            }
        }
    }

    /// Where the configuration files live, for a command that needs to suggest
    /// a path.
    pub(crate) fn config_dir(&self) -> &Path {
        &self.paths.config_dir
    }
}

/// How long to wait before the next unlock attempt, after `consecutive`
/// failures in a row. `None` for the first three, which cost nothing.
///
/// Doubles from [`UNLOCK_BACKOFF_BASE`] and stops at [`UNLOCK_BACKOFF_CAP`].
/// There is no attempt count at which the vault stops opening: a lockout would
/// hand an attacker who can reach the keyboard a way to destroy access.
fn backoff_after(consecutive: u32) -> Option<Duration> {
    let over = consecutive.checked_sub(UNLOCK_FAILURES_BEFORE_BACKOFF)?;
    let doublings = over.min(UNLOCK_BACKOFF_MAX_DOUBLINGS);
    let wait = UNLOCK_BACKOFF_BASE.saturating_mul(1u32 << doublings);
    Some(wait.min(UNLOCK_BACKOFF_CAP))
}

/// A partial [`AppSettingsDto`], mirroring `Partial<AppSettings>` on the
/// TypeScript side.
///
/// `auto_lock_minutes` is doubly optional on purpose: absent means "leave it
/// alone" and `null` means "turn auto-lock off", and collapsing the two would
/// make it impossible to switch off.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct AppSettingsPatch {
    pub(crate) theme: Option<String>,
    pub(crate) locale: Option<String>,
    #[serde(deserialize_with = "explicit_option")]
    pub(crate) auto_lock_minutes: Option<Option<u32>>,
    pub(crate) lock_on_screen_lock: Option<bool>,
    pub(crate) lock_on_suspend: Option<bool>,
    pub(crate) sidebar_width: Option<u32>,
    pub(crate) inspector_open: Option<bool>,
    pub(crate) update_check_enabled: Option<bool>,
    pub(crate) update_channel: Option<String>,
    #[serde(deserialize_with = "explicit_option")]
    pub(crate) update_last_checked_at: Option<Option<i64>>,
    pub(crate) terminal_prefix: Option<String>,
    /// Replaced whole rather than merged field by field: the palette and its
    /// overrides are one decision, and a merge would let the core hold
    /// overrides belonging to a palette that is no longer selected.
    pub(crate) terminal: Option<TerminalAppearanceDto>,
    /// Absent leaves it alone; `null` forgets the folder. Collapsing the two
    /// would make it impossible to stop remembering one.
    #[serde(deserialize_with = "explicit_option")]
    pub(crate) file_download_folder: Option<Option<String>>,
    /// Action id to accelerator. A `null` accelerator restores that action's
    /// shipped default.
    pub(crate) shortcuts: Option<BTreeMap<String, Option<String>>>,
}

/// Checks and canonicalises a terminal appearance.
///
/// The interface computes contrast and warns, but it never blocks a colour —
/// it is the user's terminal. So nothing here judges *which* colour was
/// chosen. What it does refuse is a value that is not a colour at all, or a
/// palette this build cannot resolve: either one would leave a session drawn
/// in something nobody picked, and the failure would show up as an unreadable
/// terminal rather than as an error anyone could act on.
fn normalise_terminal(
    mut appearance: TerminalAppearanceDto,
) -> Result<TerminalAppearanceDto, IpcError> {
    if !TERMINAL_PALETTES.contains(&appearance.palette.as_str()) {
        return Err(IpcError::invalid_request(
            "terminal.palette",
            format!(
                "`{}` is not one of {}",
                appearance.palette,
                TERMINAL_PALETTES.join(", ")
            ),
        ));
    }

    let mut overrides = BTreeMap::new();
    for (key, value) in appearance.overrides {
        if !TERMINAL_COLOR_KEYS.contains(&key.as_str()) {
            return Err(IpcError::invalid_request(
                "terminal.overrides",
                format!("`{key}` is not a colour this terminal draws with"),
            ));
        }
        let Some(colour) = normalise_hex(&value) else {
            return Err(IpcError::invalid_request(
                "terminal.overrides",
                format!("`{key}` is `{value}`, which is not a colour; write it as #1a1c20"),
            ));
        };
        overrides.insert(key, colour);
    }
    appearance.overrides = overrides;

    appearance.font_family = appearance.font_family.trim().to_owned();
    if appearance.font_family.chars().count() > MAX_FONT_FAMILY_LEN {
        return Err(IpcError::invalid_request(
            "terminal.fontFamily",
            format!("it is longer than {MAX_FONT_FAMILY_LEN} characters"),
        ));
    }

    // Clamped rather than refused: a size outside the range is a slip of a
    // spinner, and the nearest usable size is what the user meant.
    appearance.font_size = appearance
        .font_size
        .clamp(MIN_TERMINAL_FONT_SIZE, MAX_TERMINAL_FONT_SIZE);

    Ok(appearance)
}

/// Canonicalises `#rgb`, `#rgba`, `#rrggbb` or `#rrggbbaa` to lower-case
/// `#rrggbb`/`#rrggbbaa`, or returns `None`.
///
/// The short forms are accepted because people paste hex from wherever they
/// found it. One canonical form is what makes "is this still the palette's own
/// colour?" a string comparison on both sides of the boundary.
fn normalise_hex(text: &str) -> Option<String> {
    let body = text.trim().strip_prefix('#')?;
    if !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let expanded = match body.len() {
        3 | 4 => body.chars().flat_map(|c| [c, c]).collect::<String>(),
        6 | 8 => body.to_owned(),
        _ => return None,
    };

    Some(format!("#{}", expanded.to_ascii_lowercase()))
}

/// Canonicalises an accelerator: lower case, modifiers in a fixed order, one
/// key at the end.
///
/// The canonical form is what is stored and what is compared, so "Shift+Ctrl+N"
/// and "ctrl+shift+n" are one binding rather than two that silently shadow each
/// other.
fn normalise_accelerator(text: &str) -> Result<String, IpcError> {
    let mut modifiers: Vec<&'static str> = Vec::new();
    let mut key: Option<String> = None;

    for part in text.split('+') {
        let part = part.trim().to_lowercase();
        if part.is_empty() {
            return Err(IpcError::invalid_request(
                "accelerator",
                format!("`{text}` has an empty part; write it as Ctrl+Shift+N"),
            ));
        }
        if let Some((_, canonical)) = MODIFIERS.iter().find(|(name, _)| *name == part) {
            if !modifiers.contains(canonical) {
                modifiers.push(canonical);
            }
            continue;
        }
        if key.is_some() {
            return Err(IpcError::invalid_request(
                "accelerator",
                format!("`{text}` names two keys; a shortcut ends on one"),
            ));
        }
        if !is_key(&part) {
            return Err(IpcError::invalid_request(
                "accelerator",
                format!("`{part}` is not a key Remoter can bind"),
            ));
        }
        key = Some(part);
    }

    let Some(key) = key else {
        return Err(IpcError::invalid_request(
            "accelerator",
            format!("`{text}` is modifiers only; a shortcut needs a key"),
        ));
    };

    // A fixed order rather than the order they were typed in.
    let mut out = String::new();
    for canonical in ["ctrl", "alt", "shift", "meta"] {
        if modifiers.contains(&canonical) {
            out.push_str(canonical);
            out.push('+');
        }
    }
    out.push_str(&key);
    Ok(out)
}

/// Whether a part is a key an accelerator can end on.
fn is_key(part: &str) -> bool {
    if part.chars().count() == 1 {
        return true;
    }
    if NAMED_KEYS.contains(&part) {
        return true;
    }
    // f1 to f24.
    part.strip_prefix('f')
        .and_then(|digits| digits.parse::<u8>().ok())
        .is_some_and(|number| (1..=24).contains(&number))
}

/// Canonicalises the terminal prefix, which is modifiers and nothing else.
fn normalise_prefix(text: &str) -> Result<String, IpcError> {
    let mut modifiers: Vec<&'static str> = Vec::new();
    for part in text.split('+') {
        let part = part.trim().to_lowercase();
        let Some((_, canonical)) = MODIFIERS.iter().find(|(name, _)| *name == part) else {
            return Err(IpcError::invalid_request(
                "terminalPrefix",
                format!("`{part}` is not a modifier; the prefix is modifiers only, e.g. Ctrl+Alt"),
            ));
        };
        if !modifiers.contains(canonical) {
            modifiers.push(canonical);
        }
    }
    if modifiers.is_empty() {
        return Err(IpcError::invalid_request(
            "terminalPrefix",
            "it is empty, and a prefix of nothing would take every key from the session",
        ));
    }

    let mut out = Vec::new();
    for canonical in ["ctrl", "alt", "shift", "meta"] {
        if modifiers.contains(&canonical) {
            out.push(canonical);
        }
    }
    Ok(out.join("+"))
}

/// Distinguishes a field that was sent as `null` from one that was not sent.
fn explicit_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer).map(Some)
}

/// The defaults a fresh installation starts with.
fn default_settings() -> AppSettingsDto {
    AppSettingsDto {
        theme: "system".to_owned(),
        locale: "en".to_owned(),
        // Fifteen minutes: long enough not to interrupt a working session,
        // short enough that a walked-away-from laptop is not an open vault.
        auto_lock_minutes: Some(15),
        lock_on_screen_lock: true,
        lock_on_suspend: true,
        sidebar_width: 280,
        inspector_open: true,
        // Off until asked for. `docs/security/threat-model.md` treats an
        // outbound request nobody asked for as a fingerprint, and there is no
        // telemetry in this application at any setting.
        update_check_enabled: false,
        update_channel: String::from("stable"),
        update_last_checked_at: None,
        terminal_prefix: String::from("ctrl+alt"),
        shortcuts: BTreeMap::new(),
        terminal: TerminalAppearanceDto::default(),
        file_download_folder: None,
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsFile {
    version: u32,
    settings: AppSettingsDto,
}

fn load_settings(path: &Path) -> AppSettingsDto {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return default_settings(),
        Err(err) => {
            tracing::warn!("could not read the settings file: {err}");
            return default_settings();
        }
    };

    match serde_json::from_str::<SettingsFile>(&text) {
        Ok(file) if file.version == SETTINGS_VERSION => file.settings,
        Ok(file) => {
            tracing::warn!(
                "the settings file is version {}; this build writes {SETTINGS_VERSION}, \
                 so the defaults were used",
                file.version
            );
            default_settings()
        }
        Err(err) => {
            tracing::warn!("the settings file could not be parsed: {err}");
            default_settings()
        }
    }
}

fn save_settings(path: &Path, settings: &AppSettingsDto) -> Result<(), IpcError> {
    let file = SettingsFile {
        version: SETTINGS_VERSION,
        settings: settings.clone(),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(|err| {
        IpcError::new(
            "settings.encode",
            "Your settings could not be encoded, so they were not saved.",
        )
        .with_detail(err.to_string())
    })?;
    write_atomic(path, &json)
}

/// Where the recent-vault list and the settings live.
#[derive(Debug, Clone)]
struct ConfigPaths {
    config_dir: PathBuf,
}

impl ConfigPaths {
    fn resolve() -> Self {
        if let Some(dir) = std::env::var_os(CONFIG_DIR_ENV) {
            return Self {
                config_dir: PathBuf::from(dir),
            };
        }

        if let Some(dirs) = directories::ProjectDirs::from("io.github", "bbesli", "Remoter") {
            return Self {
                config_dir: dirs.config_dir().to_path_buf(),
            };
        }

        // No home directory the platform will admit to. A relative directory
        // beside the working directory is a poor place for preferences, but it
        // is better than refusing to start.
        tracing::warn!("no platform configuration directory was found; using ./.remoter instead");
        Self {
            config_dir: PathBuf::from(".remoter"),
        }
    }

    fn recents_file(&self) -> PathBuf {
        self.config_dir.join(RECENTS_FILE)
    }

    fn settings_file(&self) -> PathBuf {
        self.config_dir.join(SETTINGS_FILE)
    }
}

/// Milliseconds since the Unix epoch — the unit every timestamp inside the
/// vault database uses.
pub(crate) fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or_default()
}

/// Seconds since the Unix epoch — the unit the vault header and the
/// recent-vault list use.
pub(crate) fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inner_with(settings: AppSettingsDto) -> Inner {
        Inner {
            paths: ConfigPaths {
                config_dir: PathBuf::from("/nonexistent"),
            },
            vault: None,
            settings,
            recents: Recents::load(Path::new("/nonexistent/recents.json")),
            activity: Arc::new(ActivityClock::new()),
            lock_reason: None,
            unlock_failures: BTreeMap::new(),
            lock_failure: None,
            pending_import: None,
            sessions: Arc::new(SessionHub::new()),
        }
    }

    #[test]
    fn a_locked_vault_reports_no_countdown() {
        let inner = inner_with(default_settings());
        assert!(inner.locks_in_seconds().is_none());
    }

    /// With no vault open there is nothing to ask, so the machine's own
    /// setting is what a vault would start from.
    #[test]
    fn the_application_setting_is_the_default_for_the_next_vault() {
        let inner = inner_with(default_settings());
        assert_eq!(inner.effective_auto_lock_minutes(), Some(15));

        let off = AppSettingsDto {
            auto_lock_minutes: None,
            ..default_settings()
        };
        assert_eq!(inner_with(off).effective_auto_lock_minutes(), None);
    }

    #[test]
    fn the_idle_clock_only_ever_moves_forward() {
        let clock = ActivityClock::new();
        clock.expire();
        let stale = clock.idle_for();
        assert!(
            stale >= Duration::from_secs(60 * 60 * 23),
            "expiring the clock should read as most of a day idle: {stale:?}"
        );

        clock.touch();
        assert!(
            clock.idle_for() < Duration::from_secs(1),
            "a touch is what resets it"
        );

        // A second, older writer must not undo it — `fetch_max`, not `store`.
        clock.expire();
        clock.touch();
        clock.expire();
        clock.touch();
        assert!(clock.idle_for() < Duration::from_secs(1));
    }

    /// Nothing may be offered to the interface but the three spellings it
    /// knows, and a trigger this build cannot see must say `"unobserved"`
    /// rather than looking like one it can.
    #[test]
    fn every_lock_trigger_declares_how_well_it_is_observed() {
        for trigger in LockTrigger::ALL.iter().copied() {
            let observation = trigger.observation();
            assert!(
                ["observed", "on_resume", "unobserved"].contains(&observation),
                "{trigger:?} reports `{observation}`, which the interface cannot render"
            );
            assert!(
                !trigger.describe().is_empty(),
                "{trigger:?} has no sentence to put in a lock message"
            );
        }
    }

    #[test]
    fn the_patch_can_switch_auto_lock_off() {
        let patch = serde_json::from_str::<AppSettingsPatch>(r#"{"autoLockMinutes": null}"#).ok();
        assert_eq!(
            patch.map(|patch| patch.auto_lock_minutes),
            Some(Some(None)),
            "an explicit null should read as \"turn it off\""
        );
    }

    #[test]
    fn an_absent_field_is_left_alone() {
        let patch = serde_json::from_str::<AppSettingsPatch>(r#"{"theme": "dark"}"#).ok();
        assert!(patch.is_some());
        if let Some(patch) = patch {
            assert_eq!(patch.auto_lock_minutes, None);
            assert_eq!(patch.theme.as_deref(), Some("dark"));
        }
    }

    #[test]
    fn an_unknown_theme_is_refused() {
        let mut inner = inner_with(default_settings());
        let patch = AppSettingsPatch {
            theme: Some("neon".to_owned()),
            ..AppSettingsPatch::default()
        };
        let failure = inner.apply_settings(patch);
        assert!(failure.is_err());
    }

    #[test]
    fn a_couple_of_mistyped_passwords_cost_nothing() {
        let mut inner = inner_with(default_settings());
        let path = Path::new("/vaults/one.rvault");

        for _ in 0..2 {
            inner.record_unlock_failure(path);
            assert!(
                inner.check_unlock_allowed(path).is_ok(),
                "a retry inside the allowance should not be delayed"
            );
        }
    }

    #[test]
    fn a_fourth_attempt_waits() {
        let mut inner = inner_with(default_settings());
        let path = Path::new("/vaults/one.rvault");

        for _ in 0..3 {
            inner.record_unlock_failure(path);
        }
        let refused = inner.check_unlock_allowed(path);
        assert!(refused.is_err(), "the fourth attempt should be delayed");
        if let Err(err) = refused {
            assert_eq!(err.code, "vault.unlock-throttled");
            // The wait is in the sentence so the interface can count down.
            assert!(err.message.contains("seconds"), "message: {}", err.message);
        }
    }

    #[test]
    fn a_successful_unlock_clears_the_backoff() {
        let mut inner = inner_with(default_settings());
        let path = Path::new("/vaults/one.rvault");

        for _ in 0..4 {
            inner.record_unlock_failure(path);
        }
        assert!(inner.check_unlock_allowed(path).is_err());

        assert_eq!(inner.clear_unlock_failures(path), 4);
        assert!(inner.check_unlock_allowed(path).is_ok());
        assert_eq!(inner.clear_unlock_failures(path), 0);
    }

    #[test]
    fn the_backoff_is_per_vault() {
        let mut inner = inner_with(default_settings());
        let one = Path::new("/vaults/one.rvault");
        let two = Path::new("/vaults/two.rvault");

        for _ in 0..4 {
            inner.record_unlock_failure(one);
        }
        assert!(inner.check_unlock_allowed(one).is_err());
        assert!(
            inner.check_unlock_allowed(two).is_ok(),
            "another vault's failures are not this vault's"
        );
    }

    #[test]
    fn the_backoff_doubles_and_then_stops_at_the_cap() {
        assert_eq!(backoff_after(0), None);
        assert_eq!(backoff_after(2), None);
        assert_eq!(backoff_after(3), Some(UNLOCK_BACKOFF_BASE));
        assert_eq!(backoff_after(4), Some(UNLOCK_BACKOFF_BASE * 2));
        assert_eq!(backoff_after(5), Some(UNLOCK_BACKOFF_BASE * 4));
        assert_eq!(backoff_after(40), Some(UNLOCK_BACKOFF_CAP));
        // No attempt count locks the vault out for good.
        assert_eq!(backoff_after(u32::MAX), Some(UNLOCK_BACKOFF_CAP));
    }

    #[test]
    fn the_sidebar_width_is_clamped() {
        let mut inner = inner_with(default_settings());
        let patch = AppSettingsPatch {
            sidebar_width: Some(9999),
            ..AppSettingsPatch::default()
        };
        // The write to /nonexistent fails; the merge that precedes it is what
        // is under test.
        let _ = inner.apply_settings(patch);
        assert_eq!(inner.settings.sidebar_width, MAX_SIDEBAR_WIDTH);
    }

    #[test]
    fn update_checking_is_off_until_it_is_asked_for() {
        let settings = default_settings();
        assert!(
            !settings.update_check_enabled,
            "an outbound request nobody asked for is a fingerprint"
        );
        assert_eq!(settings.update_channel, "stable");
        assert_eq!(settings.update_last_checked_at, None);
    }

    #[test]
    fn an_unknown_update_channel_is_refused() {
        let mut inner = inner_with(default_settings());
        let patch = AppSettingsPatch {
            update_channel: Some(String::from("nightly")),
            ..AppSettingsPatch::default()
        };
        let refused = inner.apply_settings(patch);
        assert!(refused.is_err());
        assert_eq!(inner.settings.update_channel, "stable");
    }

    #[test]
    fn an_accelerator_is_canonical_however_it_was_typed() {
        assert_eq!(
            normalise_accelerator("Ctrl+Shift+N").ok(),
            Some(String::from("ctrl+shift+n"))
        );
        assert_eq!(
            normalise_accelerator("shift+CONTROL+n").ok(),
            Some(String::from("ctrl+shift+n"))
        );
        // Platform aliases collapse, so a binding made on a Mac reads the same
        // on a Linux machine.
        assert_eq!(
            normalise_accelerator("Cmd+K").ok(),
            Some(String::from("meta+k"))
        );
        assert_eq!(normalise_accelerator("F11").ok(), Some(String::from("f11")));
        assert_eq!(normalise_accelerator("?").ok(), Some(String::from("?")));

        assert!(normalise_accelerator("ctrl+").is_err());
        assert!(
            normalise_accelerator("ctrl+alt").is_err(),
            "modifiers are not a shortcut"
        );
        assert!(normalise_accelerator("ctrl+a+b").is_err());
        assert!(normalise_accelerator("ctrl+f99").is_err());
    }

    #[test]
    fn the_terminal_prefix_is_modifiers_and_nothing_else() {
        assert_eq!(
            normalise_prefix("Alt+Ctrl").ok(),
            Some(String::from("ctrl+alt"))
        );
        assert!(normalise_prefix("ctrl+k").is_err());
        assert!(normalise_prefix("").is_err());
    }

    #[test]
    fn a_rebinding_is_stored_only_while_it_differs_from_the_default() {
        let mut inner = inner_with(default_settings());
        let mut overrides = BTreeMap::new();
        overrides.insert(
            String::from("palette.open"),
            Some(String::from("Ctrl+Shift+P")),
        );
        assert!(inner.apply_shortcuts(overrides).is_ok());
        assert_eq!(
            inner
                .settings
                .shortcuts
                .get("palette.open")
                .map(String::as_str),
            Some("ctrl+shift+p")
        );

        // Setting it back to the shipped binding forgets the override, so a
        // changed default reaches this user later.
        let mut overrides = BTreeMap::new();
        overrides.insert(String::from("palette.open"), Some(String::from("ctrl+k")));
        assert!(inner.apply_shortcuts(overrides).is_ok());
        assert!(inner.settings.shortcuts.is_empty());

        // And a null restores it outright.
        let mut overrides = BTreeMap::new();
        overrides.insert(
            String::from("vault.lock"),
            Some(String::from("ctrl+shift+l")),
        );
        assert!(inner.apply_shortcuts(overrides).is_ok());
        let mut overrides = BTreeMap::new();
        overrides.insert(String::from("vault.lock"), None);
        assert!(inner.apply_shortcuts(overrides).is_ok());
        assert!(inner.settings.shortcuts.is_empty());
    }

    #[test]
    fn an_action_this_build_does_not_bind_is_refused() {
        let mut inner = inner_with(default_settings());
        let mut overrides = BTreeMap::new();
        overrides.insert(
            String::from("launch.missiles"),
            Some(String::from("ctrl+m")),
        );
        let refused = inner.apply_shortcuts(overrides);
        assert!(refused.is_err_and(|err| err.code == "request.invalid"));
    }

    #[test]
    fn a_universal_shortcut_cannot_take_a_key_the_remote_shell_needs() {
        let mut inner = inner_with(default_settings());
        let mut overrides = BTreeMap::new();
        overrides.insert(String::from("vault.lock"), Some(String::from("Ctrl+C")));
        let refused = inner.apply_shortcuts(overrides);
        assert!(refused.is_err_and(|err| err.code == "shortcut.terminal-reserved"));
    }

    #[test]
    fn the_shipped_bindings_do_not_collide_with_each_other() {
        let inner = inner_with(default_settings());
        let listed = inner.shortcuts();
        assert_eq!(listed.len(), SHORTCUTS.len());
        assert!(
            listed
                .iter()
                .all(|shortcut| shortcut.conflict.as_deref() != Some("duplicate")),
            "shipped bindings collide: {listed:?}"
        );
        assert!(listed.iter().all(|shortcut| !shortcut.customised));

        // The one the desktop takes says so rather than mysteriously doing
        // nothing.
        let next_tab = listed.iter().find(|shortcut| shortcut.id == "tab.next");
        assert!(next_tab.is_some_and(|shortcut| shortcut.conflict.as_deref() == Some("desktop")));

        // "Jump to tab 1-9" is one action and nine keys.
        let jump = listed.iter().find(|shortcut| shortcut.id == "tab.jump");
        assert!(jump.is_some_and(|shortcut| shortcut.series_len == 9));
    }

    #[test]
    fn a_rebinding_that_collides_says_which_action_it_collides_with() {
        let mut inner = inner_with(default_settings());
        let mut overrides = BTreeMap::new();
        overrides.insert(String::from("sidebar.toggle"), Some(String::from("ctrl+w")));
        assert!(inner.apply_shortcuts(overrides).is_ok());

        let listed = inner.shortcuts();
        let clash = listed
            .iter()
            .find(|shortcut| shortcut.id == "sidebar.toggle");
        assert!(clash.is_some_and(|shortcut| shortcut.conflict.as_deref() == Some("duplicate")));
        assert!(
            clash.is_some_and(|shortcut| shortcut
                .conflicts_with
                .contains(&String::from("tab.close"))),
            "the row has to name the other action: {listed:?}"
        );
    }

    #[test]
    fn settings_written_before_these_fields_existed_still_load() {
        // The settings file is version 1 and stays version 1: a build that
        // added fields must not throw away the theme somebody chose.
        let text = r#"{"version":1,"settings":{"theme":"dark","locale":"en","autoLockMinutes":15,"lockOnScreenLock":true,"lockOnSuspend":true,"sidebarWidth":280,"inspectorOpen":true}}"#;
        let parsed = serde_json::from_str::<SettingsFile>(text);
        assert!(parsed.is_ok(), "an older settings file should still load");
        if let Ok(file) = parsed {
            assert_eq!(file.settings.theme, "dark");
            assert!(!file.settings.update_check_enabled);
            assert_eq!(file.settings.terminal_prefix, "ctrl+alt");
            assert!(file.settings.shortcuts.is_empty());
        }
    }
}
