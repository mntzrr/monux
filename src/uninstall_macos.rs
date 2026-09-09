//! `monux system uninstall` on macOS: stop the daemons and tray, boot the
//! LaunchAgents out, and remove the plists, logs, binary and (ask first) the
//! config. Everything monux installs on macOS is user-level, so the whole
//! uninstall is — no root, no sudo. The UX mirrors the Linux uninstall
//! (uninstall.rs): confirm up front, stop running instances, then remove
//! what exists, degrading per-item failures to notes.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::setup_macos::{self, Launchctl};

/// The labels of every LaunchAgent monux installs (order = removal order).
fn agent_labels() -> Vec<String> {
    vec![
        setup_macos::label_for_str("server"),
        setup_macos::label_for_str("client"),
        setup_macos::TRAY_LABEL.to_string(),
    ]
}

pub fn run(assume_yes: bool) -> Result<()> {
    // Nothing is touched before this confirmation lands.
    if !assume_yes && !confirm_uninstall() {
        println!("Aborted; nothing was removed.");
        return Ok(());
    }

    if unsafe { libc::geteuid() } == 0 {
        anyhow::bail!(
            "running as root: everything monux installs on macOS is per-user (LaunchAgents, \
             ~/.local/bin, ~/Library/Logs) — run the uninstall as the user who installed it"
        );
    }
    let home = home::home_dir().context("No home dir found: unable to locate binaries and config")?;

    // First: detach the AGENTS from launchd. Order matters — booting a
    // KeepAlive agent's process out is the only way to stop it for good:
    // SIGTERM alone (the single-instance takeover below) just makes launchd
    // respawn it within ThrottleInterval, and the lock is held again before
    // any wait-for-exit finishes. Booted-out jobs cannot come back until a
    // bootstrap, so a manually started straggler is all that's left for the
    // lock sweep after this.
    let uid = unsafe { libc::getuid() };
    let lc = Launchctl { uid };
    let agents_dir = setup_macos::agents_dir(&home);
    for label in agent_labels() {
        let job = lc.target(&label);
        // Probe before booting out: an unloaded job would only have
        // launchctl shout "No such process" at our stderr.
        let bootstrapped = lc
            .spec(&["print", &job])
            .probe()
            .map(|out| !out.trim().is_empty())
            .unwrap_or(false);
        if bootstrapped {
            if let Err(e) = lc.spec(&["bootout", &job]).run() {
                println!("note: couldn't boot out {job}: {:#}", e);
            }
        }
        let plist = agents_dir.join(format!("{label}.plist"));
        match std::fs::remove_file(&plist) {
            Ok(()) => println!("Removed {}", plist.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => println!("note: couldn't remove {}: {}", plist.display(), e),
        }
    }

    // Second: stop whatever still runs (manually started daemons or a
    // standalone tray — launchd-managed ones are already gone above). Taking
    // each single-instance lock SIGTERMs the holder (the same takeover the
    // daemons use against each other); the locks are held until this process
    // exits, which keeps a mid-uninstall respawn from taking the role again.
    for kind in ["server", "client", "indicator"] {
        match crate::single_instance::acquire(kind) {
            Ok(lock) if lock.took_over => println!("Stopped the running monux {kind}"),
            Ok(_) => {}
            Err(e) => println!("note: couldn't stop the running monux {kind}: {:#}", e),
        }
    }

    // The agents' captured output (client.log, tray.log, server.log).
    let logs = setup_macos::logs_dir(&home);
    match std::fs::remove_dir_all(&logs) {
        Ok(()) => println!("Removed {}", logs.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => println!("note: couldn't remove {}: {}", logs.display(), e),
    }

    // The binary — our own running executable included: unlink(2) keeps the
    // inode alive until the process exits, so removing it mid-uninstall is
    // safe.
    let binary = home.join(".local/bin/monux");
    match std::fs::remove_file(&binary) {
        Ok(()) => println!("Removed {}", binary.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => println!("note: couldn't remove {}: {}", binary.display(), e),
    }

    // The 'mx' alias — removed only when it's our symlink (alias::remove
    // leaves a foreign 'mx' alone).
    match crate::alias::remove(&home.join(".local/bin")) {
        Ok(true) => println!("Removed the 'mx' alias"),
        Ok(false) => {}
        Err(e) => println!("note: couldn't remove the 'mx' alias: {}", e),
    }

    let config_dir: PathBuf = home.join(".config/monux");
    if config_dir.exists() {
        let remove = if assume_yes {
            false
        } else {
            prompt_remove_config()
        };
        if remove {
            match std::fs::remove_dir_all(&config_dir) {
                Ok(()) => println!("Removed {}", config_dir.display()),
                Err(e) => println!("note: couldn't remove {}: {}", config_dir.display(), e),
            }
        } else {
            println!(
                "Kept ~/.config/monux (identity + approvals); a reinstall will pick up where it left off."
            );
        }
    }

    println!("monux uninstalled.");
    Ok(())
}

/// Pre-flight confirmation for the destructive uninstall, reading from
/// /dev/tty like the config prompt below. Without a usable terminal (cron,
/// CI, a pipe) there is no one to ask, so the run aborts: unattended removal
/// needs --yes.
fn confirm_uninstall() -> bool {
    let Ok(tty) = std::fs::File::open("/dev/tty") else {
        println!("No terminal to ask for confirmation (and --yes not given); aborting.");
        return false;
    };
    print!("This will stop any running monux daemon and tray, and remove the LaunchAgents, their logs, and ~/.local/bin/monux. Continue? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    match BufReader::new(tty).read_line(&mut answer) {
        Ok(_) => answered_yes(&answer),
        Err(_) => false,
    }
}

/// Asks whether to also remove the config dir. Defaults to no: the identity
/// keypair and peer approvals are the expensive-to-recreate part, and a
/// reinstall picks up where it left off with them.
fn prompt_remove_config() -> bool {
    let Ok(tty) = std::fs::File::open("/dev/tty") else {
        return false;
    };
    print!("Also remove ~/.config/monux (identity keypair and peer approvals)? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    match BufReader::new(tty).read_line(&mut answer) {
        Ok(_) => answered_yes(&answer),
        Err(_) => false,
    }
}

/// Interprets a [y/N] answer; anything but an explicit yes is a no.
fn answered_yes(answer: &str) -> bool {
    matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_parsing_defaults_to_no() {
        assert!(answered_yes("y\n"));
        assert!(answered_yes("  YES "));
        assert!(!answered_yes("\n"));
        assert!(!answered_yes("no\n"));
        assert!(!answered_yes("yeah sure\n"));
    }

    #[test]
    fn every_agent_label_is_a_monux_label() {
        // The removal list and the setup layer must not drift: each label
        // names its plist as <label>.plist, the same convention
        // setup --autostart writes.
        for label in agent_labels() {
            assert!(label.starts_with("sh.monux."), "{}", label);
        }
        assert_eq!(agent_labels().len(), 3);
    }
}
