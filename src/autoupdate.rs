//! Background update checking (on by default; `--no-auto-update` opts out).
//!
//! The daily check NOTIFIES by default and installs nothing. Installing means
//! compiling and running whatever the repo currently holds — including every
//! build script and proc macro in the dependency tree — so it is not something
//! that should happen on a timer, unattended, on a machine where monux may be
//! running as root for uinput access. The user pulls the trigger, via the tray
//! action, `mx daemon update`, or `monux update`.
//!
//! `--auto-install` restores unattended installing for people who want it.
//! Even then the target must carry a verified release signature (see
//! update::Trust): unattended and unverifiable together is precisely the
//! combination this exists to prevent.
//!
//! An install — however triggered — rebuilds at low CPU priority and then
//! restarts the process to apply it. The restart is the ordinary graceful
//! shutdown (SIGTERM to ourselves) followed by main re-exec'ing the new
//! binary, so the session drops for a few seconds and then heals itself:
//! clients reconnect automatically and the server re-activates whichever
//! machine was active (session resumption in rotation.rs).

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

use crate::update;

/// How often to check for updates.
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Delay before the first check after startup (let the session settle).
const INITIAL_DELAY: Duration = Duration::from_secs(60);
/// Grace period between a successful background update and the automatic
/// restart: lets the notification be seen and in-flight input settle.
const RESTART_DELAY: Duration = Duration::from_secs(20);

/// Set when an automatic restart is due after a background update; main
/// re-execs the new binary once the graceful shutdown completes.
static RESTART_AFTER_EXIT: AtomicBool = AtomicBool::new(false);

/// The last remote sha the check loop saw that's newer than this build,
/// shared for the control socket's status (update_available). None means up
/// to date — or never checked. A failed build attempt deliberately leaves it
/// set: the update is still out there.
static UPDATE_AVAILABLE: Mutex<Option<String>> = Mutex::new(None);

/// The newer remote sha last seen by the check loop, if any (control IPC).
pub fn update_available() -> Option<String> {
    UPDATE_AVAILABLE.lock().ok()?.clone()
}

/// Records what the check loop just learned about the remote HEAD.
fn set_update_available(sha: Option<String>) {
    if let Ok(mut slot) = UPDATE_AVAILABLE.lock() {
        *slot = sha;
    }
}

/// Process-global hint that an update is probably available (e.g. the client
/// saw a newer protocol version on the server). Wakes the check loop early
/// instead of waiting for the daily tick.
static UPDATE_HINT: Notify = Notify::const_new();

/// Set when someone explicitly asked to INSTALL, rather than just to check
/// (the control socket's update_now, which backs `mx daemon update` and the
/// tray's update action). The loop consumes it on its next pass, so a notify-
/// mode daemon installs exactly the updates a person asked for.
static INSTALL_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Hints that an update is probably available; the check loop (when running)
/// checks immediately rather than at the next interval. Cheap and coalescing:
/// repeated hints collapse into at most one extra check. Does NOT install.
pub fn hint_update_available() {
    UPDATE_HINT.notify_one();
}

/// Asks the check loop to install the update it finds, not merely report it.
/// Used by the control socket's update_now.
pub fn request_install() {
    INSTALL_REQUESTED.store(true, Ordering::SeqCst);
    UPDATE_HINT.notify_one();
}

/// How the loop treats an update it finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Report it and stop (the default).
    Notify,
    /// Build and restart into it, subject to signature verification.
    AutoInstall,
}

/// Test hook: override the startup delay (seconds).
fn initial_delay() -> Duration {
    std::env::var("MONUX_AUTO_UPDATE_INITIAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(INITIAL_DELAY)
}

/// Test hook: override the check interval (seconds).
fn check_interval() -> Duration {
    std::env::var("MONUX_AUTO_UPDATE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(CHECK_INTERVAL)
}

/// Test hook: override the restart grace period (seconds).
fn restart_delay() -> Duration {
    std::env::var("MONUX_AUTO_UPDATE_RESTART_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(RESTART_DELAY)
}

fn short(sha: &str) -> &str {
    &sha[..12.min(sha.len())]
}

/// Whether a post-update restart was scheduled; checked by main after the
/// server/client loop has shut down gracefully.
pub fn restart_scheduled() -> bool {
    RESTART_AFTER_EXIT.load(Ordering::SeqCst)
}

/// Triggers the restart: flag it for main, then send ourselves SIGTERM so the
/// process shuts down via the exact same graceful path as a manual stop
/// (releasing grabs, held keys and clipboard state) before main re-execs.
/// Also used by the control socket's restart command.
pub fn schedule_restart() {
    RESTART_AFTER_EXIT.store(true, Ordering::SeqCst);
    unsafe {
        libc::kill(std::process::id() as i32, libc::SIGTERM);
    }
}


/// What the check loop should do about a remote sha it just learned about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    /// Build and restart into it.
    Install,
    /// Tell the user it exists and stop.
    Notify,
    /// Nothing to do this pass.
    Nothing,
}

/// The install-or-notify decision, as a pure function over the four facts
/// that drive it.
///
/// It exists because the version that lived inline got this wrong: the notify
/// path shared `last_attempted` with the build path, so once the daemon had
/// reported an update, the same flag suppressed installing it — and the
/// explicit request had already been consumed by then. `mx daemon update` did
/// nothing, silently, in exactly the situation it is for.
///
/// The rule: an explicit request always installs, because a person just asked
/// and their intent outranks any bookkeeping. Unattended mode installs too,
/// but honours `attempted` so a failing build isn't retried every interval —
/// and then falls through to reporting it, because an auto-install machine
/// that has quietly stopped updating is exactly the thing worth surfacing.
/// Otherwise the update is reported once per sha.
fn decide(newer: bool, requested: bool, mode: Mode, attempted: bool, notified: bool) -> Action {
    if !newer {
        return Action::Nothing;
    }
    if requested || (mode == Mode::AutoInstall && !attempted) {
        return Action::Install;
    }
    if notified {
        return Action::Nothing;
    }
    Action::Notify
}

/// Runs the auto-update loop; spawn it on the tokio runtime.
/// `gate_config_dir`: for clients, the config dir holding the server's
/// protocol version record — refreshed via mDNS on every check, so updates
/// that would break compatibility with the server are skipped. Servers pass
/// None: they lead protocol upgrades.
pub async fn run(gate_config_dir: Option<std::path::PathBuf>, mode: Mode) {
    tokio::select! {
        _ = tokio::time::sleep(initial_delay()) => {}
        _ = UPDATE_HINT.notified() => {
            info!("Update hint received; checking for updates now");
        }
    }
    // Test hook: pretend an update was installed, exercising the automatic
    // restart without a rebuild. Fires once per boot lineage (the re-exec'd
    // image has MONUX_RESTARTED set) and skips the real update loop entirely.
    if std::env::var_os("MONUX_AUTO_UPDATE_FAKE").is_some() && mode == Mode::AutoInstall {
        if std::env::var_os("MONUX_RESTARTED").is_none() {
            info!("Pretending a background update succeeded (MONUX_AUTO_UPDATE_FAKE)");
            restart_after_grace("fake-update", false).await;
        }
        return;
    }
    // The sha of the last update attempt, so a persistent failure (or a
    // successful install whose restart is still pending) doesn't rebuild
    // every interval. Deliberately NOT set when the update gate skips a
    // build: the gate opens once the server is updated, which the next
    // check picks up.
    let mut last_attempted: Option<String> = None;
    // The sha we last NOTIFIED about, kept apart from last_attempted so that
    // telling the user about an update cannot also suppress installing it.
    let mut last_notified: Option<String> = None;
    // The pin lives in the config dir; servers pass no gate dir, so fall
    // back to the default location for the pin check.
    let pin_dir = gate_config_dir.clone().or_else(update::default_config_dir);
    loop {
        // A manual downgrade pins the version: auto-update never downgrades
        // (and never unpins — a plain 'monux update' does that), so a pinned
        // machine skips every check until then.
        if let Some((version, _commit)) = pin_dir.as_deref().and_then(update::update_pin) {
            info!(
                "update pinned at v{} (manual downgrade); skipping — return to latest with 'monux update'",
                version
            );
            wait_for_next_check().await;
            continue;
        }
        let repo = update::repo_url();
        // git ls-remote is blocking network IO: run it on the blocking pool
        // so a dead route can't park an async worker for minutes (the call
        // itself is bounded by git's low-speed limits in latest_remote_sha).
        let check = tokio::task::spawn_blocking(move || update::latest_remote_sha(&repo))
            .await
            .unwrap_or_else(|e| Err(e.into()));
        match check {
            Ok(remote_sha) => {
                let newer = update::is_newer_remote(&remote_sha, update::CURRENT_REVISION);
                // Publish for the control socket's status before any attempt:
                // the update is "available" whether or not we build it.
                set_update_available(newer.then(|| remote_sha.clone()));
                let attempted = last_attempted.as_deref() == Some(remote_sha.as_str());
                let notified = last_notified.as_deref() == Some(remote_sha.as_str());
                let requested = INSTALL_REQUESTED.swap(false, Ordering::SeqCst);
                let action = decide(newer, requested, mode, attempted, notified);
                if action == Action::Nothing && requested && !newer {
                    // The user asked and there was nothing to get: say so,
                    // rather than leaving 'mx daemon update' looking ignored.
                    info!("monux is already up to date ({})", short(&remote_sha));
                }
                if action == Action::Notify {
                    last_notified = Some(remote_sha.clone());
                    info!(
                        "monux update available ({}); install it with 'mx daemon update', the tray, or 'monux update'",
                        short(&remote_sha)
                    );
                    notify_update_available(&remote_sha);
                } else if action == Action::Install {
                    info!(
                        "monux update available ({}), rebuilding in the background...",
                        short(&remote_sha)
                    );
                    // Refresh the gate via mDNS on every check (healing a
                    // stale record) inside the blocking task: discovery is
                    // synchronous IO with a timeout.
                    let gate_dir = gate_config_dir.clone();
                    // An explicit request is Interactive: a person asked for
                    // it just now, so an unsigned build warns instead of
                    // refusing. The timer's own installs stay Unattended.
                    let trust = if mode == Mode::AutoInstall {
                        update::Trust::Unattended
                    } else {
                        update::Trust::Interactive
                    };
                    let result = tokio::task::spawn_blocking(move || {
                        let constraint = gate_dir
                            .as_deref()
                            .and_then(|dir| update::refresh_protocol_constraint(Some(dir)));
                        update::run(false, true, constraint, None, trust)
                    })
                    .await;
                    match result {
                        Ok(Ok(update::UpdateStatus::Installed)) => {
                            last_attempted = Some(remote_sha.clone());
                            restart_after_grace(&remote_sha, true).await;
                        }
                        Ok(Ok(update::UpdateStatus::AlreadyCurrent)) => {
                            // The remote moved between our check and the pull.
                            last_attempted = Some(remote_sha.clone());
                        }
                        Ok(Ok(update::UpdateStatus::SkippedIncompatible)) => {
                            // Logged by update::run; last_attempted stays unset
                            // so the next check retries (the gate may have opened).
                        }
                        Ok(Ok(update::UpdateStatus::SkippedUnverified)) => {
                            // Logged by update::run. Recorded, unlike the
                            // protocol gate: a commit's signature will not
                            // become valid later, so retrying it daily would
                            // only repeat the same refusal forever.
                            last_attempted = Some(remote_sha.clone());
                        }
                        Ok(Err(e)) => {
                            last_attempted = Some(remote_sha.clone());
                            warn!("Background monux update failed: {:?}", e);
                        }
                        Err(e) => {
                            last_attempted = Some(remote_sha.clone());
                            error!("Background monux update task failed: {:?}", e);
                        }
                    }
                } else if !newer {
                    debug!("monux is up to date ({})", short(&remote_sha));
                }
            }
            Err(e) => {
                debug!("monux update check failed (offline?): {:?}", e);
            }
        }
        wait_for_next_check().await;
    }
}

/// Waits for the next check tick, waking early on an update hint.
async fn wait_for_next_check() {
    tokio::select! {
        _ = tokio::time::sleep(check_interval()) => {}
        _ = UPDATE_HINT.notified() => {
            info!("Update hint received; checking for updates now");
        }
    }
}

/// Announces the update, then gives the session a short grace period before
/// scheduling the automatic restart.
async fn restart_after_grace(remote_sha: &str, notify: bool) {
    let delay = restart_delay();
    info!(
        "monux was updated to {}; restarting in {}s to apply (the session resumes automatically)",
        short(remote_sha),
        delay.as_secs()
    );
    if notify {
        notify_update(remote_sha, delay);
    }
    tokio::time::sleep(delay).await;
    info!("Restarting to apply monux {}...", short(remote_sha));
    schedule_restart();
}

/// Tells the user an update exists and that installing it is their call.
/// The tray shows the same fact continuously (update_available); this is the
/// one-shot nudge when it first appears.
fn notify_update_available(remote_sha: &str) {
    crate::notify::notify(
        "monux-update",
        crate::notify::Urgency::Low,
        10000,
        "monux update available",
        &format!(
            "monux {} is available. Install it from the tray, or run 'mx daemon update'.",
            short(remote_sha)
        ),
    );
}

/// Shows a best-effort desktop notification that an update was installed and
/// the process is about to restart.
fn notify_update(remote_sha: &str, delay: Duration) {
    crate::notify::notify(
        "monux-update",
        crate::notify::Urgency::Normal,
        10000,
        "monux update installed",
        &format!(
            "monux {} was installed in the background; restarting in {}s to apply it (your session will resume automatically)",
            short(remote_sha),
            delay.as_secs()
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this function was extracted for, stated as a test.
    ///
    /// A notify-mode daemon reports an update, then the user runs
    /// `mx daemon update`. The old inline version shared one flag between
    /// "already reported" and "already tried to build", so the report
    /// suppressed the install — and the request had been consumed reaching
    /// that decision, so it was lost rather than deferred. Nothing happened,
    /// nothing was logged, and the daemon stayed on the old build.
    #[test]
    fn an_explicit_request_installs_even_after_the_update_was_reported() {
        // Reported already (notified), never built (not attempted).
        assert_eq!(
            decide(true, true, Mode::Notify, false, true),
            Action::Install
        );
        // ...and even if a previous build attempt failed: the user asked
        // again, which is a deliberate retry.
        assert_eq!(
            decide(true, true, Mode::Notify, true, true),
            Action::Install
        );
    }

    #[test]
    fn notify_mode_reports_once_per_sha_and_then_stays_quiet() {
        // First sighting: report it.
        assert_eq!(
            decide(true, false, Mode::Notify, false, false),
            Action::Notify
        );
        // Same sha on the next daily tick: silence, not a second popup.
        assert_eq!(
            decide(true, false, Mode::Notify, false, true),
            Action::Nothing
        );
    }

    #[test]
    fn auto_install_builds_once_and_does_not_retry_a_failed_sha() {
        // Unattended: install without being asked.
        assert_eq!(
            decide(true, false, Mode::AutoInstall, false, false),
            Action::Install
        );
        // A build already attempted for this sha (it failed, or its restart
        // is pending): don't rebuild it every interval — but DO report it
        // once. An auto-install machine exists so nobody thinks about it, so
        // one that has quietly stopped updating is the failure worth
        // surfacing; silence there is how a machine rots.
        assert_eq!(
            decide(true, false, Mode::AutoInstall, true, false),
            Action::Notify
        );
        // ...and having reported it, it stays quiet.
        assert_eq!(
            decide(true, false, Mode::AutoInstall, true, true),
            Action::Nothing
        );
        // ...unless the user asks explicitly, which is a deliberate retry.
        assert_eq!(
            decide(true, true, Mode::AutoInstall, true, false),
            Action::Install
        );
    }

    #[test]
    fn nothing_newer_means_nothing_to_do_however_it_was_triggered() {
        for requested in [true, false] {
            for mode in [Mode::Notify, Mode::AutoInstall] {
                assert_eq!(
                    decide(false, requested, mode, false, false),
                    Action::Nothing,
                    "requested={} mode={:?}",
                    requested,
                    mode
                );
            }
        }
    }
}
