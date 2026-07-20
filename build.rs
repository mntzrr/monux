//! Embeds the git revision of the source tree as MONUX_GIT_SHA, shown by
//! `monux --version` and used by `monux update` to tell whether the latest
//! source differs from the running binary.

use std::process::Command;

fn main() {
    let mut revision =
        git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    if revision != "unknown" && !git(&["status", "--porcelain"]).unwrap_or_default().is_empty() {
        revision.push_str("-dirty");
    }
    println!("cargo:rustc-env=MONUX_GIT_SHA={revision}");
    // Rebuild when the checked-out commit changes: HEAD contains the symref
    // ("ref: refs/heads/..."), and the symref target contains the commit id.
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Some(symref) = git(&["symbolic-ref", "-q", "HEAD"]) {
        println!("cargo:rerun-if-changed=.git/{symref}");
    }
    println!("cargo:rerun-if-changed=.git/packed-refs");
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8(out.stdout).ok()?.trim().to_string();
    Some(stdout)
}
