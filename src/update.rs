//! Self-update: pull the latest monux source, rebuild, and install.
//!
//! The source is cloned once into a cache dir (~/.cache/monux/src) and pulled
//! on each update. Building from source on this machine matters: the repo's
//! .cargo/config.toml sets target-cpu=native, so a binary built elsewhere can
//! crash with an illegal instruction on a CPU with fewer features.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::info;

const DEFAULT_REPO: &str = "https://github.com/mntzrr/monux.git";
/// Commit this binary was built from, set by build.rs ("<sha>" or "<sha>-dirty").
const CURRENT_REVISION: &str = env!("MONUX_GIT_SHA");

pub fn run(force: bool) -> Result<()> {
    let repo = std::env::var("MONUX_UPDATE_REPO").unwrap_or_else(|_| DEFAULT_REPO.to_string());
    let src_dir = match std::env::var_os("MONUX_UPDATE_CACHE") {
        Some(dir) => PathBuf::from(dir),
        None => home::home_dir()
            .context("No home dir found")?
            .join(".cache")
            .join("monux")
            .join("src"),
    };

    if src_dir.join(".git").exists() {
        info!("Pulling latest source in {}...", src_dir.display());
        git(&src_dir, &["pull", "--ff-only"]).with_context(|| {
            format!(
                "Failed to update the source checkout; delete it and retry: rm -rf {}",
                src_dir.display()
            )
        })?;
    } else {
        info!("Cloning {} into {}...", repo, src_dir.display());
        if let Some(parent) = src_dir.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        let status = Command::new("git")
            .args(["clone", "--depth", "1", &repo])
            .arg(&src_dir)
            .status()
            .context("Failed to run git: is it installed?")?;
        if !status.success() {
            bail!("git clone {} failed", repo);
        }
    }

    let latest = git_output(&src_dir, &["rev-parse", "--short=12", "HEAD"])?;
    let current_base = CURRENT_REVISION.trim_end_matches("-dirty");
    if !force && current_base != "unknown" && latest == current_base {
        info!(
            "monux is already up to date ({}). Use --force to rebuild anyway.",
            CURRENT_REVISION
        );
        return Ok(());
    }
    info!("Updating monux: {} -> {}", CURRENT_REVISION, latest);

    let root = install_root();
    let cargo = find_cargo()?;
    info!(
        "Building and installing to {} (this can take a few minutes)...",
        root.join("bin/monux").display()
    );
    let status = Command::new(cargo)
        .arg("install")
        .arg("--path")
        .arg(&src_dir)
        .arg("--root")
        .arg(&root)
        .arg("--force")
        .status()
        .context("Failed to run cargo install")?;
    if !status.success() {
        bail!("cargo install failed");
    }
    info!(
        "Updated monux to {} at {}. Restart any running monux server/client to pick it up.",
        latest,
        root.join("bin/monux").display()
    );
    Ok(())
}

/// Install next to the currently running binary (<root>/bin/monux -> <root>),
/// falling back to ~/.local.
fn install_root() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if exe.file_name().is_some_and(|name| name == "monux") {
            if let Some(bin_dir) = exe.parent() {
                if bin_dir.file_name().is_some_and(|name| name == "bin") {
                    if let Some(root) = bin_dir.parent() {
                        return root.to_path_buf();
                    }
                }
            }
        }
    }
    home::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
}

/// cargo from PATH if runnable, else the rustup default location (PATH can be
/// minimal depending on how monux was launched).
fn find_cargo() -> Result<PathBuf> {
    let in_path = Command::new("cargo")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if in_path {
        return Ok(PathBuf::from("cargo"));
    }
    let fallback = home::home_dir()
        .context("No home dir found")?
        .join(".cargo")
        .join("bin")
        .join("cargo");
    if fallback.exists() {
        return Ok(fallback);
    }
    bail!("cargo not found: install a Rust toolchain via https://rustup.rs/")
}

fn git(dir: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .context("Failed to run git: is it installed?")?;
    if !status.success() {
        bail!("git {:?} failed in {}", args, dir.display());
    }
    Ok(())
}

fn git_output(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .context("Failed to run git: is it installed?")?;
    if !out.status.success() {
        bail!("git {:?} failed in {}", args, dir.display());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}
