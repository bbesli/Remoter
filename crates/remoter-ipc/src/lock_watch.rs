//! Watching for the operating-system events that lock the vault.
//!
//! `docs/security/key-management.md#auto-lock` lists three of them beside the
//! idle timeout: the screen lock, suspend or hibernate, and the window being
//! minimised. Each has a switch in the vault's own settings.
//!
//! # What this build can actually see, and what it cannot
//!
//! Only one of the three, and only afterwards.
//!
//! **Suspend or hibernate — seen on resume.** logind's `PrepareForSleep`
//! signal would give advance notice, and taking it needs a D-Bus client this
//! crate does not depend on. What is free is the *return*: on Linux
//! [`std::time::Instant`] is `CLOCK_MONOTONIC`, which does not advance while
//! the system is suspended, while [`SystemTime`] does. A thread that samples
//! both and finds the wall clock has run far ahead of the monotonic one has
//! just watched the machine come back. So Remoter locks when the machine wakes
//! rather than before it sleeps — which means the keys were in memory for the
//! duration of the sleep, and inside the hibernation image if it hibernated.
//! The interface says exactly that; it is not a caveat a user can be left to
//! discover.
//!
//! **The screen lock — not seen.** The freedesktop screensaver and login1
//! session signals are D-Bus, and every other platform has its own API. None of
//! them is reachable from here today.
//!
//! **Minimise — not seen.** Tauri 2.11's `WindowEvent` has no minimise variant,
//! and the polled `Window::is_minimized()` underneath it is fed by GTK's
//! `ICONIFIED` window state, which a Wayland compositor never sends to the
//! client. A switch that worked on X11 and silently did nothing on Wayland
//! would be the same defect in a smaller box.
//!
//! Both of those are reported to the interface as `"unobserved"` by
//! [`LockTrigger::observation`](crate::state::LockTrigger::observation), and
//! the Vault settings screen disables them and says why. A switch that persists
//! a value nothing reads is not shipped from here again.

use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::{
    sync::Weak,
    time::{Duration, Instant, SystemTime},
};

use parking_lot::Mutex;

use crate::state::Inner;
#[cfg(target_os = "linux")]
use crate::state::{LockTrigger, RESUME_GAP};

/// How often the watcher samples the two clocks.
///
/// Short enough that the vault is locked within a few seconds of the lid
/// opening, long enough that a sleeping thread is not a measurable cost.
#[cfg(target_os = "linux")]
const TICK: Duration = Duration::from_secs(5);

/// Whether the machine slept between two samples of the two clocks.
///
/// `monotonic` is how long [`Instant`] thinks passed and `wall` is how long
/// [`SystemTime`] thinks passed. On Linux the first excludes suspended time and
/// the second includes it, so their difference is how long the machine was
/// away.
///
/// Split out as a function with no clocks in it because that is the decision
/// worth testing: the loop around it is a sleep.
///
/// Gated to the one platform that calls it. The only caller is
/// [`resume_loop`], which is Linux-only, so anywhere else this is an item
/// nothing can reach — and `dead_code` is a warning, which CI turns into an
/// error, so an ungated helper under a gated caller is a compile failure on
/// Windows and macOS rather than a tidiness question.
#[cfg(target_os = "linux")]
pub(crate) fn slept_through(monotonic: Duration, wall: Duration) -> bool {
    // Saturating rather than signed: a wall clock that went *backwards* — an
    // NTP step, a user changing the time — is not a suspend, and must not be
    // read as one.
    wall.saturating_sub(monotonic) >= RESUME_GAP
}

/// Starts the resume watcher, on the platforms where the clock trick holds.
///
/// Holds a [`Weak`] reference so the thread does not keep a dropped `AppState`
/// alive; it stops the next time it wakes and finds nothing there.
///
/// A plain OS thread rather than a Tokio task on purpose. It has to be running
/// before the first command arrives — a security control that arms only when
/// the interface remembers to arm it is one with a way to be forgotten — and at
/// that point in start-up there is no runtime to spawn onto. It is not async
/// code, so the sleep in it is not the blocking sleep CLAUDE.md §5 forbids.
#[cfg(target_os = "linux")]
pub(crate) fn watch_for_resume(inner: &Arc<Mutex<Inner>>) {
    let weak = Arc::downgrade(inner);
    // Named, so it is identifiable in a debugger and in `ps -L`.
    let spawned = std::thread::Builder::new()
        .name(String::from("remoter-resume-watch"))
        .spawn(move || resume_loop(&weak));
    if let Err(error) = spawned {
        // Not fatal: the idle timeout still runs, and refusing to start over a
        // thread that would not spawn would be the wrong trade. It is a
        // warning because a lock trigger the user switched on is now not
        // firing.
        tracing::warn!(%error, "the suspend watcher did not start; the vault will not lock on resume");
    }
}

/// The same, on a platform where [`Instant`] is not documented to stop across a
/// suspend. Nothing is started, and `observation()` already says so.
#[cfg(not(target_os = "linux"))]
pub(crate) fn watch_for_resume(_inner: &Arc<Mutex<Inner>>) {}

/// Samples both clocks on a timer and locks the vault when they disagree.
#[cfg(target_os = "linux")]
fn resume_loop(inner: &Weak<Mutex<Inner>>) {
    let mut monotonic = Instant::now();
    let mut wall = SystemTime::now();

    loop {
        std::thread::sleep(TICK);

        let now_monotonic = Instant::now();
        let now_wall = SystemTime::now();
        let monotonic_delta = now_monotonic.saturating_duration_since(monotonic);
        // `duration_since` fails when the wall clock moved backwards, which is
        // not a suspend: treat it as no elapsed time rather than as a jump.
        let wall_delta = now_wall.duration_since(wall).unwrap_or_default();
        monotonic = now_monotonic;
        wall = now_wall;

        let Some(inner) = inner.upgrade() else {
            // The state is gone: the process is shutting down, or a test that
            // built one has finished with it.
            return;
        };

        if slept_through(monotonic_delta, wall_delta) {
            // Takes the lock only when something happened, so the ordinary
            // case never contends with a command.
            inner.lock().lock_for_trigger(LockTrigger::Suspend);
        }
    }
}

// Gated with the function they cover. `slept_through` does not exist off Linux,
// so neither can a test that calls it.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn a_tick_that_passed_normally_is_not_a_suspend() {
        // The two clocks agree to within scheduling noise, which is the whole
        // of the ordinary case.
        assert!(!slept_through(
            Duration::from_secs(5),
            Duration::from_millis(5_002)
        ));
    }

    #[test]
    fn a_wall_clock_that_ran_far_ahead_of_the_monotonic_one_is_a_suspend() {
        // Five seconds of ticking, two hours of wall clock: the lid was shut.
        assert!(slept_through(
            Duration::from_secs(5),
            Duration::from_secs(7205)
        ));
    }

    #[test]
    fn a_wall_clock_that_went_backwards_is_not_a_suspend() {
        // An NTP step or a user changing the time. `wall` arrives as zero
        // because `duration_since` refused it, and zero must not read as a
        // jump.
        assert!(!slept_through(Duration::from_secs(5), Duration::ZERO));
    }

    #[test]
    fn a_gap_shorter_than_the_threshold_is_left_alone() {
        // A stalled thread on a loaded machine, not a suspend. Locking here
        // would be a vault that shuts itself while the user is working.
        assert!(!slept_through(
            Duration::from_secs(5),
            Duration::from_secs(40)
        ));
    }
}
