//! Talking to Hyprland.
//!
//! Everything that knows the compositor exists lives here: finding its IPC
//! socket, the request/response protocol, the two queries the edge switcher
//! makes (monitor layout, cursor position), and the poller that drives them.
//!
//! Kept apart from the state machine next door because they fail differently
//! and change for different reasons — the zone/dwell logic is pure and
//! exhaustively tested, this half is I/O against another process's socket.
//! It is also the piece a second compositor would need a sibling of.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::OutputRect;

/// The Hyprland IPC socket
/// ($XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket.sock), the
/// same channel hyprctl uses — falling back to the newest instance found in
/// the runtime dir when the signature is absent or stale (see
/// socket_path_in). Errors when no live instance is reachable.
pub(crate) fn hyprland_socket_path() -> Result<PathBuf> {
    let runtime_dir = PathBuf::from(
        std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|dir| !dir.is_empty())
            .context("XDG_RUNTIME_DIR is not set (no wayland session?)")?,
    );
    let signature =
        std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").filter(|signature| !signature.is_empty());
    socket_path_in(&runtime_dir.join("hypr"), signature.as_deref())
}

/// Resolves the instance socket under `hypr_dir` (the env-free half of
/// hyprland_socket_path, so the fallbacks are testable).
fn socket_path_in(hypr_dir: &Path, signature: Option<&std::ffi::OsStr>) -> Result<PathBuf> {
    if let Some(signature) = signature {
        let from_signature = hypr_dir.join(signature).join(".socket.sock");
        // The signature is only worth trusting while its socket is there: a
        // daemon outlives compositor restarts, and every restart mints a new
        // signature, so the inherited one goes stale — following it then
        // would poll a socket no compositor is behind.
        if from_signature.exists() {
            return Ok(from_signature);
        }
    }
    // No usable signature. A daemon autostarted with the systemd user
    // manager never gets one at all (the manager starts before the
    // compositor, and a later import-environment doesn't reach services
    // already running). The instance directory is right there in the runtime
    // dir, so find it instead of declaring this "not running under Hyprland".
    newest_hyprland_instance(hypr_dir).with_context(|| {
        format!(
            "no live Hyprland instance in {} (HYPRLAND_INSTANCE_SIGNATURE unset or stale)",
            hypr_dir.display()
        )
    })
}

/// A socket path to move to when `current` has stopped working: the newest
/// live instance, if it isn't the one already in use. Hyprland restarts
/// under a running daemon (a compositor crash, or a deliberate restart)
/// leave the old path dead forever, which used to strand screen-edge
/// switching silently until monux itself was restarted.
pub(crate) fn rebound_hyprland_socket(current: &Path) -> Option<PathBuf> {
    hyprland_socket_path()
        .ok()
        .filter(|resolved| resolved != current)
}

/// The IPC socket of the most recently started Hyprland instance under
/// `hypr_dir`. Newest wins: stale instance directories survive a crash, and
/// on the rare box running two instances the fresh one is the better guess.
fn newest_hyprland_instance(hypr_dir: &Path) -> Result<PathBuf> {
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(hypr_dir)
        .with_context(|| format!("Failed to read {}", hypr_dir.display()))?
        .flatten()
    {
        let socket = entry.path().join(".socket.sock");
        let mtime = match std::fs::metadata(&socket) {
            // Instance directories carry no useful timestamp of their own;
            // the socket's does, and a missing socket also rules out the
            // leftover directory of an instance that's gone.
            Ok(metadata) => metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
            Err(_) => continue,
        };
        if newest.as_ref().is_none_or(|(best, _)| mtime > *best) {
            newest = Some((mtime, socket));
        }
    }
    newest
        .map(|(_, socket)| socket)
        .context("no Hyprland instance socket found")
}

/// How long the edge manager waits between attempts while Hyprland isn't
/// reachable yet (see wait_for_hyprland).
pub(crate) const HYPRLAND_WAIT_INTERVAL: Duration = Duration::from_secs(10);

/// Resolves the Hyprland IPC socket and queries the initial monitor layout,
/// waiting for the compositor instead of giving up on it. An edge manager
/// only runs when the user configured an edge map, so "Hyprland isn't there
/// yet" is a state to wait out: a daemon autostarted with the systemd user
/// manager starts at login, before the compositor exists, and giving up
/// there left screen-edge switching dead for the whole session (the same
/// startup order that used to kill clipboard sharing, see
/// clipboard::wayland::connect). Only ever returns once Hyprland answers;
/// the caller's task is dropped with the daemon.
pub(crate) async fn wait_for_hyprland() -> (PathBuf, Vec<OutputRect>) {
    // Only the first failure of a streak warns: the retry is silent
    // afterwards so a machine that never gets Hyprland doesn't fill the log.
    let mut reported = false;
    loop {
        match hyprland_socket_path() {
            Ok(socket) => {
                let socket_for_layout = socket.clone();
                match tokio::task::spawn_blocking(move || hyprland_layout(&socket_for_layout)).await {
                    Ok(Ok(layout)) if !layout.is_empty() => return (socket, layout),
                    Ok(Ok(_)) => report_hyprland_wait(&mut reported, "Hyprland reports no outputs"),
                    Ok(Err(e)) => report_hyprland_wait(&mut reported, &format!("{:#}", e)),
                    Err(e) => {
                        report_hyprland_wait(&mut reported, &format!("layout query panicked: {:#}", e))
                    }
                }
            }
            Err(e) => report_hyprland_wait(&mut reported, &format!("{:#}", e)),
        }
        tokio::time::sleep(HYPRLAND_WAIT_INTERVAL).await;
    }
}

/// Logs one wait reason: a warning for the first of a streak, debug after.
pub(crate) fn report_hyprland_wait(reported: &mut bool, reason: &str) {
    if *reported {
        debug!("Screen-edge switching still waiting for Hyprland: {}", reason);
        return;
    }
    warn!(
        "Screen-edge switching waiting for Hyprland (retrying every {:?}): {}",
        HYPRLAND_WAIT_INTERVAL, reason
    );
    *reported = true;
}

/// Runs one command against Hyprland's IPC socket: connect, send the
/// command, half-close the write side, read the reply to EOF. One-shot per
/// query: the compositor closes the connection after each reply (verified
/// empirically — hyprctl --batch's single connection works only because all
/// its commands go out in ONE write), so each query reconnects.
pub(crate) fn hyprland_query(socket: &Path, cmd: &[u8]) -> Result<String> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("Failed to connect to Hyprland IPC at {}", socket.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("Failed to configure Hyprland IPC socket")?;
    let query = String::from_utf8_lossy(cmd);
    stream
        .write_all(cmd)
        .with_context(|| format!("Failed to query Hyprland '{}'", query))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .with_context(|| format!("Failed to finish the Hyprland '{}' query", query))?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .with_context(|| format!("Failed to read the Hyprland '{}' reply", query))?;
    Ok(reply)
}

/// Queries the monitor layout from Hyprland's IPC socket (see
/// hyprland_socket_path). Errors when not running under Hyprland.
pub(crate) fn hyprland_layout(socket: &Path) -> Result<Vec<OutputRect>> {
    // "j/monitors" is the JSON variant of the monitors request.
    parse_monitors_json(&hyprland_query(socket, b"j/monitors")?)
}

/// Parses Hyprland's JSON monitors reply into logical output rectangles
/// (mode size divided by scale). Disabled outputs are skipped.
fn parse_monitors_json(json: &str) -> Result<Vec<OutputRect>> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("Failed to parse Hyprland monitors reply")?;
    let monitors = value
        .as_array()
        .context("Hyprland monitors reply is not a JSON array")?;
    let mut outputs = Vec::new();
    for monitor in monitors {
        if monitor["disabled"].as_bool() == Some(true) {
            continue;
        }
        let name = monitor["name"]
            .as_str()
            .context("Hyprland monitor entry lacks a name")?
            .to_string();
        let get_i64 = |key: &str| -> Result<i64> {
            monitor[key]
                .as_i64()
                .with_context(|| format!("Hyprland monitor '{}' lacks '{}'", name, key))
        };
        let (x, y, mut width, mut height) = (
            get_i64("x")?,
            get_i64("y")?,
            get_i64("width")?,
            get_i64("height")?,
        );
        // Hyprland reports the native (pre-rotation) mode size. Odd transforms
        // (90°/270° and their flipped variants) rotate the output, so the
        // logical width and height are swapped relative to the mode.
        let transform = monitor["transform"].as_i64().unwrap_or(0);
        if transform % 2 == 1 {
            std::mem::swap(&mut width, &mut height);
        }
        let scale = monitor["scale"]
            .as_f64()
            .filter(|s| *s > 0.0)
            .unwrap_or(1.0);
        // The persistent identifiers (see OutputRect) are optional: a
        // compositor reporting none degrades silently to name-only
        // qualifier matching.
        let get_str = |key: &str| -> String { monitor[key].as_str().unwrap_or("").to_string() };
        outputs.push(OutputRect {
            name,
            make: get_str("make"),
            model: get_str("model"),
            serial: get_str("serial"),
            description: get_str("description"),
            x: x as i32,
            y: y as i32,
            width: (width as f64 / scale).round() as i32,
            height: (height as f64 / scale).round() as i32,
        });
    }
    Ok(outputs)
}


/// How often the cursor position is polled from Hyprland's IPC.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(40);

/// How long the poller waits after a failed query before retrying.
pub(crate) const POLL_FAILURE_BACKOFF: Duration = Duration::from_millis(500);

/// Queries the cursor position from Hyprland's IPC (see hyprland_query for
/// why each poll reconnects).
pub(crate) fn cursor_position(socket: &Path) -> Result<(i32, i32)> {
    parse_cursorpos(&hyprland_query(socket, b"cursorpos")?)
}

/// Parses Hyprland's cursorpos reply ("x, y"; coordinates can be negative
/// when outputs sit left of/above the layout origin).
fn parse_cursorpos(reply: &str) -> Result<(i32, i32)> {
    let reply = reply.trim();
    let (x, y) = reply
        .split_once(',')
        .with_context(|| format!("unexpected cursorpos reply '{}'", reply))?;
    let x = x
        .trim()
        .parse::<i32>()
        .with_context(|| format!("unexpected cursorpos reply '{}'", reply))?;
    let y = y
        .trim()
        .parse::<i32>()
        .with_context(|| format!("unexpected cursorpos reply '{}'", reply))?;
    Ok((x, y))
}

/// Polls the cursor position every POLL_INTERVAL and forwards it to the edge
/// manager; a failed query is logged at debug and retried after
/// POLL_FAILURE_BACKOFF. Runs on its own thread (blocking socket IO) and
/// ends when the edge manager is gone (server shutting down).
///
/// A failing poll also looks for a newer Hyprland instance and follows it
/// (see rebound_hyprland_socket), so a compositor restart resumes edge
/// switching instead of leaving the poller talking to a dead socket. The
/// path is shared with the manager's layout requery, which follows along.
pub(crate) fn run_cursor_poller(socket: Arc<Mutex<PathBuf>>, pos_tx: mpsc::UnboundedSender<(i32, i32)>) {
    loop {
        let path = socket.lock().unwrap_or_else(|e| e.into_inner()).clone();
        match cursor_position(&path) {
            Ok(pos) => {
                if pos_tx.send(pos).is_err() {
                    return;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                debug!(
                    "Screen-edge cursor poll failed ({:#}), retrying in {:?}",
                    e, POLL_FAILURE_BACKOFF
                );
                // A failed send is the usual way out, but a poller whose
                // queries never succeed again never gets to send: with the
                // compositor gone for good (the session ended under a
                // still-running daemon) this thread used to retry every
                // POLL_FAILURE_BACKOFF for the rest of the process's life,
                // long after the manager that reads it had returned.
                if pos_tx.is_closed() {
                    return;
                }
                if let Some(rebound) = rebound_hyprland_socket(&path) {
                    info!(
                        "Screen-edge switching following the new Hyprland instance at {}",
                        rebound.display()
                    );
                    *socket.lock().unwrap_or_else(|e| e.into_inner()) = rebound;
                }
                std::thread::sleep(POLL_FAILURE_BACKOFF);
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // The layout fixtures live with the geometry tests next door; sharing them
    // keeps one definition of what an OutputRect looks like.
    use crate::edge::tests::{rect, rect_id};
    use std::ffi::OsStr;

    fn hyprland_instance(hypr_dir: &Path, signature: &str, mtime_secs: u64) {
        let dir = hypr_dir.join(signature);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join(".socket.sock");
        std::fs::write(&socket, "").unwrap();
        let mtime = std::time::UNIX_EPOCH + Duration::from_secs(mtime_secs);
        std::fs::File::options()
            .write(true)
            .open(&socket)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(mtime))
            .unwrap();
    }

    #[test]
    fn a_stale_signature_falls_back_to_the_live_instance() {
        let tmp = tempfile::tempdir().unwrap();
        let hypr_dir = tmp.path().join("hypr");
        hyprland_instance(&hypr_dir, "live_instance", 2_000);

        assert_eq!(
            socket_path_in(&hypr_dir, Some(OsStr::new("live_instance"))).unwrap(),
            hypr_dir.join("live_instance").join(".socket.sock")
        );
        assert_eq!(
            socket_path_in(&hypr_dir, Some(OsStr::new("gone_with_the_old_session"))).unwrap(),
            hypr_dir.join("live_instance").join(".socket.sock")
        );
        // Nothing live at all: an error, so the caller keeps waiting.
        std::fs::remove_dir_all(hypr_dir.join("live_instance")).unwrap();
        assert!(socket_path_in(&hypr_dir, Some(OsStr::new("live_instance"))).is_err());
    }

    #[test]
    fn the_newest_hyprland_instance_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let hypr_dir = tmp.path().join("hypr");
        hyprland_instance(&hypr_dir, "old_crashed_instance", 1_000);
        hyprland_instance(&hypr_dir, "live_instance", 2_000);
        // A leftover directory whose socket is gone is not a candidate.
        std::fs::create_dir_all(hypr_dir.join("socketless_instance")).unwrap();

        assert_eq!(
            newest_hyprland_instance(&hypr_dir).unwrap(),
            hypr_dir.join("live_instance").join(".socket.sock")
        );
    }

    #[test]
    fn a_discovered_instance_socket_answers_queries() {
        let tmp = tempfile::tempdir().unwrap();
        let hypr_dir = tmp.path().join("hypr");
        // What a crashed compositor leaves behind: a socket file with
        // nothing listening on it. Older, so the live instance outranks it.
        hyprland_instance(&hypr_dir, "old_crashed_instance", 1_000);

        let live = hypr_dir.join("live_instance");
        std::fs::create_dir_all(&live).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(live.join(".socket.sock")).unwrap();
        let compositor = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("the daemon connects");
            let mut request = Vec::new();
            // Completes only because the daemon shuts down its write half.
            conn.read_to_end(&mut request)
                .expect("the daemon finishes its request");
            assert_eq!(request, b"j/monitors", "the JSON monitors request");
            conn.write_all(
                br#"[{"name": "DP-1", "x": 0, "y": 0, "width": 2560, "height": 1440, "scale": 1.0}]"#,
            )
            .expect("the reply goes out");
        });

        let socket = newest_hyprland_instance(&hypr_dir).expect("the live instance is discovered");
        assert_eq!(socket, live.join(".socket.sock"), "the leftover was preferred");
        let layout = hyprland_layout(&socket).expect("the discovered socket answers j/monitors");
        compositor.join().expect("the stub compositor served the query");
        assert_eq!(layout, vec![rect("DP-1", 0, 0, 2560, 1440)]);
    }

    #[test]
    fn no_hyprland_instance_is_an_error_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let hypr_dir = tmp.path().join("hypr");
        // Missing dir (no Hyprland ever), then an empty one (all gone).
        assert!(newest_hyprland_instance(&hypr_dir).is_err());
        std::fs::create_dir_all(&hypr_dir).unwrap();
        assert!(newest_hyprland_instance(&hypr_dir).is_err());
    }

    #[test]
    fn monitors_json_applies_scale_and_skips_disabled() {
        let json = r#"[
            {"name": "DP-1", "x": 0, "y": 0, "width": 3840, "height": 2160, "scale": 2.0, "disabled": false},
            {"name": "HDMI-A-1", "x": 1920, "y": 0, "width": 1920, "height": 1080, "scale": 1.0, "disabled": true}
        ]"#;
        let outputs = parse_monitors_json(json).unwrap();
        assert_eq!(outputs, vec![rect("DP-1", 0, 0, 1920, 1080)]);
    }

    #[test]
    fn monitors_json_reads_the_persistent_identifiers() {
        let json = r#"[
            {"name": "eDP-1", "x": 0, "y": 0, "width": 1920, "height": 1080, "scale": 1.0,
             "make": "Dell Inc.", "model": "DELL U2720Q", "serial": "83JLZ23",
             "description": "Dell Inc. DELL U2720Q 83JLZ23"},
            {"name": "DP-3", "x": 1920, "y": 0, "width": 1920, "height": 1080, "scale": 1.0}
        ]"#;
        let outputs = parse_monitors_json(json).unwrap();
        assert_eq!(
            outputs[0],
            rect_id(
                "eDP-1",
                ("Dell Inc.", "DELL U2720Q", "83JLZ23", "Dell Inc. DELL U2720Q 83JLZ23"),
                0,
                0,
                1920,
                1080
            )
        );
        // A compositor reporting no identifiers degrades to empty strings
        // (name-only qualifier matching; see qualifier_matches).
        assert_eq!(outputs[1], rect("DP-3", 1920, 0, 1920, 1080));
    }

    #[test]
    fn cursorpos_parses_replies() {
        assert_eq!(parse_cursorpos("3440, 160").unwrap(), (3440, 160));
        assert_eq!(parse_cursorpos("0, 0").unwrap(), (0, 0));
        // Outputs left of/above the layout origin report negatives.
        assert_eq!(parse_cursorpos("-100, -200").unwrap(), (-100, -200));
        assert_eq!(parse_cursorpos("3440,160\n").unwrap(), (3440, 160));
    }

    #[test]
    fn the_cursor_poller_gives_up_when_the_manager_is_gone() {
        // The manager has returned (its receiver is dropped) while every
        // query fails — the state a daemon outliving its graphical session
        // sits in. The Ok arm's failed send is unreachable there, so only
        // the failure path's own check ends the thread.
        let tmp = tempfile::tempdir().unwrap();
        let socket = Arc::new(Mutex::new(tmp.path().join("nothing-listens-here.sock")));
        let (pos_tx, pos_rx) = mpsc::unbounded_channel();
        drop(pos_rx);

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            run_cursor_poller(socket, pos_tx);
            let _ = done_tx.send(());
        });
        // The deadline is under one backoff on purpose: the poller must be
        // out before its first retry sleep. A generous one would pass on a
        // machine that does have Hyprland, where the rebound finds the live
        // instance and the second iteration's failed send ends the thread
        // anyway — the very escape a Hyprland-less machine never gets.
        done_rx
            .recv_timeout(POLL_FAILURE_BACKOFF / 2)
            .expect("the poller returns instead of retrying a dead socket forever");
    }

    #[test]
    fn cursorpos_rejects_garbage() {
        assert!(parse_cursorpos("").is_err());
        assert!(parse_cursorpos("3440").is_err());
        assert!(parse_cursorpos("a, b").is_err());
        assert!(parse_cursorpos("1, 2, 3").is_err());
    }
}
