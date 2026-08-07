use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::watch;
use tracing::{debug, info, warn};
use wayland_client::globals::registry_queue_init;

use crate::clipboard::wayland::{common, connect, state};

/// Maximum backoff between reconnect attempts.
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(10);

/// How long start() waits for the watcher's first readiness signal. The
/// handshake must never deadlock a server start: a missed signal would
/// otherwise leave the process parked before the rotation loop exists, with
/// the keyboards already grabbed.
const READY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Task that listens for updates to the clipboard types (local cut or copy).
/// Sends out an event when an update occurs, indicating a new clipboard is available.
/// An unreachable compositor is not a failure — the watcher keeps retrying in
/// the background (see the reconnect loop). Ok(None), which disables clipboard
/// sharing, is now reserved for a watcher thread that never reports readiness.
pub fn start(
    regular_types_tx: Option<watch::Sender<Vec<String>>>,
) -> Result<Option<()>> {
    // The one case that still disables sharing up front: an explicitly empty
    // WAYLAND_DISPLAY, the documented opt-out. Retrying it would spin a
    // thread forever against a compositor we were told to ignore.
    if connect::opted_out() {
        warn!("Wayland clipboard support disabled: WAYLAND_DISPLAY is set to the empty string");
        return Ok(None);
    }

    // No initial availability probe: an unreachable compositor is a state to
    // wait out, not a reason to disable sharing for the process lifetime. A
    // daemon autostarted with the systemd user manager starts at login,
    // before the compositor exists — probing there and giving up left every
    // autostarted daemon without clipboard sharing until it was restarted by
    // hand. The reconnect loop below picks the compositor up whenever it
    // appears (first start, or a crash and restart later).
    let (thread_ready_tx, thread_ready_rx) = std::sync::mpsc::sync_channel(1);
    let _ = std::thread::spawn(move || {
        let mut backoff = Duration::from_secs(1);
        let mut signalled_ready = false;
        // Only the first error of a streak is a warning: while the compositor
        // stays away (a headless server, or a login screen that never gets
        // one) the loop retries every MAX_RECONNECT_BACKOFF forever, and
        // warning each time would bury the log in thousands of daily lines.
        let mut reported_failure = false;
        loop {
            let mut connected = false;
            match connect_and_watch(
                &regular_types_tx,
                &thread_ready_tx,
                &mut signalled_ready,
                &mut connected,
            ) {
                WatchOutcome::Unavailable => {
                    // Reachable compositor, but no clipboard protocol or no
                    // seat. Usually permanent (a compositor without
                    // data-control), but it also covers the moment before a
                    // starting compositor has advertised its seat — and
                    // giving up there would silently cost the session its
                    // clipboard sharing. Retry at the slow rate instead: one
                    // connect per MAX_RECONNECT_BACKOFF costs nothing, and
                    // logging it once keeps the log quiet.
                    if !reported_failure {
                        warn!("Wayland clipboard unavailable: no data-control protocol or no seat. Retrying every {:?}", MAX_RECONNECT_BACKOFF);
                        reported_failure = true;
                    }
                    if !signalled_ready {
                        signalled_ready = true;
                        let _ = thread_ready_tx.send(());
                    }
                    std::thread::sleep(MAX_RECONNECT_BACKOFF);
                    backoff = MAX_RECONNECT_BACKOFF;
                }
                WatchOutcome::Error(e) => {
                    // A cycle that did connect is a fresh failure, not a
                    // continuing one: start over from the short backoff and
                    // let it warn again.
                    if connected {
                        backoff = Duration::from_secs(1);
                        reported_failure = false;
                    }
                    if reported_failure {
                        debug!(
                            "Wayland clipboard type watcher still unavailable, retrying in {:?}: {}",
                            backoff, e
                        );
                    } else {
                        warn!(
                            "Wayland clipboard not reachable, retrying in {:?} — sharing starts as soon as a compositor is: {}. If monux runs under sudo, start it with 'sudo -E' to keep the session environment (WAYLAND_DISPLAY, XDG_RUNTIME_DIR)",
                            backoff, e
                        );
                        reported_failure = true;
                    }
                    if !signalled_ready {
                        signalled_ready = true;
                        let _ = thread_ready_tx.send(());
                    }
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);
                }
            }
        }
    });
    // Bounded handshake: the watcher signals on its first outcome — connected,
    // unavailable, or error — but a startup must never hinge on that signal
    // arriving. On timeout, start without clipboard sharing rather than
    // deadlocking the server with the keyboards already grabbed.
    match thread_ready_rx.recv_timeout(READY_HANDSHAKE_TIMEOUT) {
        Ok(()) => Ok(Some(())),
        Err(e) => {
            warn!(
                "Wayland clipboard type watcher did not report readiness ({}); clipboard sharing disabled",
                e
            );
            Ok(None)
        }
    }
}

/// Result of one connect + watch cycle.
enum WatchOutcome {
    /// Wayland or its clipboard protocols aren't available — don't reconnect.
    Unavailable,
    /// A dispatch error occurred (e.g. compositor crash) — reconnect.
    Error(anyhow::Error),
}

/// Connects to wayland, sets up the clipboard registry, and dispatches events
/// until the connection is lost. Returns Unavailable if wayland or the
/// clipboard protocols aren't present, Error on a dispatch failure. Signals
/// readiness on the FIRST successful connect too: previously only the
/// Unavailable/Error arms signalled, so a first-try success (a healthy,
/// fast compositor — e.g. right after a reboot) left start()'s readiness
/// recv blocked forever, deadlocking the server with the keyboards grabbed.
fn connect_and_watch(
    regular_types_tx: &Option<watch::Sender<Vec<String>>>,
    thread_ready_tx: &std::sync::mpsc::SyncSender<()>,
    signalled_ready: &mut bool,
    connected: &mut bool,
) -> WatchOutcome {
    let conn = match connect::connect() {
        Ok(conn) => conn,
        Err(e) => {
            return WatchOutcome::Error(
                anyhow::anyhow!("Failed to connect to wayland: {:#}", e),
            );
        }
    };
    let (globals, mut queue) = match registry_queue_init::<state::State>(&conn) {
        Ok(vals) => vals,
        Err(e) => {
            return WatchOutcome::Error(
                anyhow::anyhow!("Failed to init Wayland registry queue: {}", e),
            );
        }
    };
    let qh = queue.handle();

    let clipboard_manager = if let Some(clipboard_manager) = common::clipboard_manager(&globals, &qh) {
        clipboard_manager
    } else {
        return WatchOutcome::Unavailable;
    };

    let mut seats = HashMap::new();
    for seat in common::seats(&globals, &qh) {
        let data = state::SeatData::new(clipboard_manager.get_data_device(&seat, &qh, seat.clone()));
        seats.insert(seat, data);
    }
    if seats.is_empty() {
        return WatchOutcome::Unavailable;
    }
    // State handles advertising the regular clipboard types to upstream listeners
    let mut state = state::State::new(seats, regular_types_tx.clone());

    if let Err(e) = queue.roundtrip(&mut state).context("Failed to initialize Wayland state") {
        return WatchOutcome::Error(e);
    }
    info!("Wayland clipboard type watcher connected");
    *connected = true;
    // Report readiness on the first successful connect as well (see the fn
    // docs): start()'s recv unblocks here, on Unavailable, or on first Error.
    if !*signalled_ready {
        *signalled_ready = true;
        let _ = thread_ready_tx.send(());
    }
    loop {
        if let Err(e) = queue.blocking_dispatch(&mut state) {
            return WatchOutcome::Error(anyhow::anyhow!(
                "Wayland clipboard type watcher queue dispatch error: {}",
                e
            ));
        }
    }
}
