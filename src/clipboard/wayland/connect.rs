use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use tracing::debug;
use wayland_client::Connection;

/// Connects to the compositor.
///
/// `WAYLAND_DISPLAY` first (the normal path), then any wayland socket found
/// in the runtime dir. The fallback exists because a daemon autostarted with
/// the systemd user manager never sees `WAYLAND_DISPLAY`: the user manager
/// starts at login, before the compositor exists, and the later
/// `import-environment` / `dbus-update-activation-environment` only updates
/// the manager's own environment — not that of services already running.
/// Such a daemon has `XDG_RUNTIME_DIR` but no `WAYLAND_DISPLAY`, so
/// connect_to_env falls back to the spec default `wayland-0` and fails
/// against a session whose socket is `wayland-1`, disabling clipboard
/// sharing for the whole session.
pub fn connect() -> Result<Connection> {
    if opted_out() {
        bail!("Wayland clipboard disabled: WAYLAND_DISPLAY is set to the empty string");
    }
    match Connection::connect_to_env() {
        Ok(conn) => return Ok(conn),
        Err(e) => debug!("WAYLAND_DISPLAY connect failed ({}), scanning the runtime dir", e),
    }

    let dir = match runtime_dir() {
        Some(dir) => dir,
        None => bail!("Couldn't reach Wayland: no WAYLAND_DISPLAY and no runtime dir to scan"),
    };
    let sockets = wayland_sockets_in(&dir);
    if sockets.is_empty() {
        bail!(
            "Couldn't reach Wayland: no WAYLAND_DISPLAY and no wayland socket in {}",
            dir.display()
        );
    }
    let mut last_err = None;
    for path in &sockets {
        match UnixStream::connect(path).map_err(anyhow::Error::from).and_then(|stream| {
            Connection::from_socket(stream).map_err(anyhow::Error::from)
        }) {
            Ok(conn) => {
                debug!("Connected to the wayland socket {} (WAYLAND_DISPLAY unusable)", path.display());
                return Ok(conn);
            }
            Err(e) => last_err = Some((path.clone(), e)),
        }
    }
    match last_err {
        Some((path, e)) => bail!("Couldn't reach any wayland socket (last tried {}): {}", path.display(), e),
        None => unreachable!("a non-empty socket list always sets last_err or returns"),
    }
}

/// Whether the user asked for no wayland clipboard at all. An explicitly
/// empty `WAYLAND_DISPLAY` is an opt-out, not a misconfigured session:
/// `WAYLAND_DISPLAY= monux server` is the documented way to run without
/// clipboard sharing (the isolation test for input freezes), so it must not
/// be second-guessed by the socket scan in connect().
pub fn opted_out() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some_and(|display| display.is_empty())
}

/// The session runtime dir: `XDG_RUNTIME_DIR`, else the systemd-standard
/// `/run/user/<uid>` (an autostarted daemon normally has the variable, but a
/// `sudo` invocation without `-E` may not).
fn runtime_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    let uid = unsafe { libc::geteuid() };
    let dir = PathBuf::from(format!("/run/user/{}", uid));
    dir.is_dir().then_some(dir)
}

/// The wayland display sockets in `dir`, in name order (so `wayland-0`
/// precedes `wayland-1` on the rare multi-session box). Only actual sockets
/// qualify: the `wayland-N.lock` files sitting next to them are regular
/// files, and connecting to one would fail.
fn wayland_sockets_in(dir: &Path) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!("Couldn't scan {} for wayland sockets: {}", dir.display(), e);
            return vec![];
        }
    };
    let mut sockets: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("wayland-"))
                && entry
                    .file_type()
                    .is_ok_and(|file_type| file_type.is_socket())
        })
        .map(|entry| entry.path())
        .collect();
    sockets.sort();
    sockets
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn only_wayland_sockets_are_candidates() {
        let dir = tempfile::tempdir().unwrap();
        // Two display sockets, plus the lock files and unrelated entries that
        // live next to them in a real runtime dir.
        let _first = UnixListener::bind(dir.path().join("wayland-1")).unwrap();
        let _second = UnixListener::bind(dir.path().join("wayland-0")).unwrap();
        let _other = UnixListener::bind(dir.path().join("bus")).unwrap();
        std::fs::write(dir.path().join("wayland-1.lock"), "").unwrap();
        std::fs::write(dir.path().join("wayland-0.lock"), "").unwrap();

        let sockets = wayland_sockets_in(dir.path());

        assert_eq!(
            sockets,
            vec![dir.path().join("wayland-0"), dir.path().join("wayland-1")]
        );
    }

    /// The fallback's real target: a socket discovered in the runtime dir
    /// must be connectable without WAYLAND_DISPLAY telling us about it. Runs
    /// only where a compositor is up — headless there is nothing to connect
    /// to. (No env mutation: discovery and connection are exercised directly,
    /// which is exactly what connect() does once connect_to_env has failed.)
    #[test]
    fn a_discovered_socket_connects_without_wayland_display() {
        let dir = match runtime_dir() {
            Some(dir) => dir,
            None => return,
        };
        let Some(socket) = wayland_sockets_in(&dir).into_iter().next() else {
            return;
        };
        let stream = UnixStream::connect(&socket).unwrap();
        assert!(
            Connection::from_socket(stream).is_ok(),
            "discovered socket {} did not accept a connection",
            socket.display()
        );
    }

    #[test]
    fn a_dir_without_wayland_sockets_yields_no_candidates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("wayland-1.lock"), "").unwrap();

        assert!(wayland_sockets_in(dir.path()).is_empty());
        // A missing dir is a miss, not a panic.
        assert!(wayland_sockets_in(&dir.path().join("nope")).is_empty());
    }
}
