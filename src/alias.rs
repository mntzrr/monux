//! The `mx` command alias: a symlink next to the installed binary, pointing
//! at it. A symlink (not a shell alias) works in every shell, in scripts, and
//! for `killall`-style flows, and needs no code in the binary itself — every
//! internal path (locks, config, sockets) hardcodes "monux".
//!
//! The link uses a RELATIVE target ("monux" in the same directory) so the
//! atomic binary replacement in update.rs (rename(2) over the binary) keeps
//! it valid, and moving the pair together never breaks it.
//!
//! Collision discipline, both directions: `ensure` never overwrites an `mx`
//! that isn't monux-ward (the user may have created one for something else),
//! and `remove` never deletes an `mx` that isn't a symlink pointing at monux.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::warn;

/// The alias' file name, placed in the same directory as the monux binary.
pub const ALIAS_NAME: &str = "mx";

/// What `ensure` did, for logging.
#[derive(Debug, Eq, PartialEq)]
pub enum EnsureOutcome {
    /// The alias was created.
    Created,
    /// The alias already pointed at monux; nothing to do.
    Already,
    /// A stale monux-ward symlink (e.g. an absolute old install path) was
    /// re-pointed at the relative target.
    Refreshed,
    /// An `mx` exists that isn't monux-ward: left untouched.
    SkippedForeign,
}

/// The symlink path for the alias inside `bin_dir`.
fn alias_path(bin_dir: &Path) -> PathBuf {
    bin_dir.join(ALIAS_NAME)
}

/// Whether a symlink target counts as monux-ward: the relative "monux" or
/// any path ending in "/monux" (an absolute link into an old install).
fn target_is_monux(target: &Path) -> bool {
    target == Path::new("monux") || target.file_name().is_some_and(|name| name == "monux")
}

/// Creates (or refreshes) `<bin_dir>/mx` as a symlink to "monux" (relative).
/// An existing `mx` that isn't monux-ward is left alone with a warning —
/// never overwrite something the user created for another purpose.
pub fn ensure(bin_dir: &Path) -> Result<EnsureOutcome> {
    let alias = alias_path(bin_dir);
    let mut refreshed = false;
    match fs::symlink_metadata(&alias) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let target = fs::read_link(&alias)
                .with_context(|| format!("Failed to read {}", alias.display()))?;
            if target == Path::new("monux") {
                return Ok(EnsureOutcome::Already);
            }
            if !target_is_monux(&target) {
                warn!(
                    "{} exists and points at {}; leaving it alone — the 'mx' alias is unavailable",
                    alias.display(),
                    target.display()
                );
                return Ok(EnsureOutcome::SkippedForeign);
            }
            fs::remove_file(&alias)
                .with_context(|| format!("Failed to refresh {}", alias.display()))?;
            refreshed = true;
        }
        Ok(_) => {
            warn!(
                "{} exists and is not our symlink; leaving it alone — the 'mx' alias is unavailable",
                alias.display()
            );
            return Ok(EnsureOutcome::SkippedForeign);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("Failed to stat {}", alias.display())),
    }
    std::os::unix::fs::symlink("monux", &alias)
        .with_context(|| format!("Failed to create {}", alias.display()))?;
    Ok(if refreshed {
        EnsureOutcome::Refreshed
    } else {
        EnsureOutcome::Created
    })
}

/// Removes `<bin_dir>/mx` — but only when it is a symlink pointing at monux.
/// Anything else (a regular file, a symlink elsewhere) stays: uninstalling
/// monux must not take an unrelated `mx` with it. Returns true when removed.
pub fn remove(bin_dir: &Path) -> Result<bool> {
    let alias = alias_path(bin_dir);
    let meta = match fs::symlink_metadata(&alias) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("Failed to stat {}", alias.display())),
    };
    if !meta.file_type().is_symlink() {
        return Ok(false);
    }
    let target = fs::read_link(&alias)
        .with_context(|| format!("Failed to read {}", alias.display()))?;
    if !target_is_monux(&target) {
        return Ok(false);
    }
    fs::remove_file(&alias).with_context(|| format!("Failed to remove {}", alias.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_creates_a_relative_monux_symlink() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(ensure(dir.path()).unwrap(), EnsureOutcome::Created);
        let target = fs::read_link(dir.path().join("mx")).unwrap();
        assert_eq!(target, Path::new("monux"));
        // Idempotent: a second run has nothing to do.
        assert_eq!(ensure(dir.path()).unwrap(), EnsureOutcome::Already);
    }

    #[test]
    fn ensure_refreshes_a_stale_monux_ward_symlink() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/home/user/.cargo/bin/monux", dir.path().join("mx")).unwrap();
        assert_eq!(ensure(dir.path()).unwrap(), EnsureOutcome::Refreshed);
        assert_eq!(fs::read_link(dir.path().join("mx")).unwrap(), Path::new("monux"));
    }

    #[test]
    fn ensure_skips_foreign_file_and_symlink() {
        let dir = tempfile::tempdir().unwrap();
        // A regular file named mx.
        fs::write(dir.path().join("mx"), "not ours").unwrap();
        assert_eq!(ensure(dir.path()).unwrap(), EnsureOutcome::SkippedForeign);
        assert_eq!(fs::read_to_string(dir.path().join("mx")).unwrap(), "not ours");
        // A symlink pointing elsewhere.
        fs::remove_file(dir.path().join("mx")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/python3", dir.path().join("mx")).unwrap();
        assert_eq!(ensure(dir.path()).unwrap(), EnsureOutcome::SkippedForeign);
        assert_eq!(
            fs::read_link(dir.path().join("mx")).unwrap(),
            Path::new("/usr/bin/python3")
        );
    }

    #[test]
    fn remove_deletes_only_our_symlink() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing there: nothing to do.
        assert!(!remove(dir.path()).unwrap());
        // Our symlink: removed.
        std::os::unix::fs::symlink("monux", dir.path().join("mx")).unwrap();
        assert!(remove(dir.path()).unwrap());
        assert!(dir.path().join("mx").symlink_metadata().is_err());
        // A foreign symlink and a regular file survive.
        std::os::unix::fs::symlink("/usr/bin/python3", dir.path().join("mx")).unwrap();
        assert!(!remove(dir.path()).unwrap());
        fs::remove_file(dir.path().join("mx")).unwrap();
        fs::write(dir.path().join("mx"), "not ours").unwrap();
        assert!(!remove(dir.path()).unwrap());
        assert_eq!(fs::read_to_string(dir.path().join("mx")).unwrap(), "not ours");
    }
}
