//! Self-update: pull the latest monux source, rebuild, and install.
//!
//! The source is cloned once into a cache dir (~/.cache/monux/src) and pulled
//! on each update. Building from source on this machine matters: the repo's
//! .cargo/config.toml sets target-cpu=native, so a binary built elsewhere can
//! crash with an illegal instruction on a CPU with fewer features.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tracing::{debug, info, warn};

const DEFAULT_REPO: &str = "https://github.com/mntzrr/monux.git";
/// Commit this binary was built from, set by build.rs ("<sha>" or "<sha>-dirty").
pub const CURRENT_REVISION: &str = env!("MONUX_GIT_SHA");

/// The repo updates are pulled from.
///
/// MONUX_UPDATE_REPO overrides it in DEBUG BUILDS ONLY. In a release build it
/// would be a remote-code-execution channel for anything that can set the
/// daemon's environment: this path compiles and runs whatever it fetches, and
/// `monux setup` re-execs under `sudo -E`, which forwards the environment into
/// a root process.
pub fn repo_url() -> String {
    #[cfg(debug_assertions)]
    if let Ok(repo) = std::env::var("MONUX_UPDATE_REPO") {
        return repo;
    }
    DEFAULT_REPO.to_string()
}

/// The source checkout the updater fetches into and builds from.
///
/// MONUX_UPDATE_CACHE overrides it in DEBUG BUILDS ONLY, on the same reasoning
/// as MONUX_UPDATE_REPO above: it selects the directory this path compiles,
/// and `sudo -E` forwards the environment into a root process.
fn default_src_dir() -> Result<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("MONUX_UPDATE_CACHE") {
        return Ok(PathBuf::from(dir));
    }
    Ok(home::home_dir()
        .context("No home dir found")?
        .join(".cache")
        .join("monux")
        .join("src"))
}

/// The public half of the key that signs monux releases, in OpenSSH format
/// (`ssh-ed25519 AAAA...`). Empty here means release signing is NOT configured
/// for this build — see `verify_release_signature`.
///
/// SSH rather than GPG because the verification is self-contained: git checks
/// it against an allowed-signers file we write ourselves, with no keyring to
/// import into and no gnupg home to depend on.
///
/// To enable, generate a key kept OFF the build machines that run updates:
///     ssh-keygen -t ed25519 -C 'monux release signing' -f monux-release
/// paste the contents of `monux-release.pub` here, and sign every release tag:
///     git config gpg.format ssh
///     git config user.signingkey /path/to/monux-release
///     git tag -s v13.0.0 -m 'monux v13.0.0' && git push --tags
const RELEASE_SIGNING_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRgzzs8DrRL2XxJwYVuFXfZV2gVMA53v3ix7QdZlMtd monux release signing";

/// The identity the allowed-signers file binds the key to. Arbitrary, but it
/// must match the `-n` namespace-independent principal git records; git only
/// checks that SOME allowed principal signed, so any stable string works.
const RELEASE_SIGNING_PRINCIPAL: &str = "releases@monux";

/// What signature verification could conclude about a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// A tag whose signature verifies against RELEASE_SIGNING_KEY, and whose
    /// commit is the one we are about to build.
    Verified { tag: String },
    /// No signing key is compiled into this build, so nothing CAN be
    /// verified. Unattended installs refuse; an explicit `monux update` warns
    /// and proceeds, because the person who typed it is the review gate.
    Unconfigured,
    /// A key is configured and the check failed: no signed tag at this
    /// commit, a bad signature, or a signer we don't trust.
    Rejected { reason: String },
}

/// Whether release signing is compiled into this build at all.
pub fn signing_configured() -> bool {
    !RELEASE_SIGNING_KEY.trim().is_empty()
}

/// Verifies that `sha` is the commit of a tag signed by the release key.
///
/// Checking the TAG rather than the commit is deliberate: a tag is the
/// explicit "this is a release" act, so an attacker who lands a commit on
/// master — the exact scenario this exists for — still cannot produce
/// something this accepts.
fn verify_release_signature(src_dir: &Path, sha: &str) -> Signature {
    verify_against_key(src_dir, sha, RELEASE_SIGNING_KEY)
}

/// verify_release_signature against an explicit trusted key, so the whole
/// path — including the part that must REJECT a signature from the wrong
/// signer — can be exercised with a throwaway key in a test. The shipped key
/// is a const; the mechanism is not.
fn verify_against_key(src_dir: &Path, sha: &str, trusted_key: &str) -> Signature {
    if trusted_key.trim().is_empty() {
        return Signature::Unconfigured;
    }
    // git needs the trusted key on disk; a temp file next to the checkout is
    // enough, and it is rewritten every run so it can't go stale.
    let allowed = src_dir
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("monux-allowed-signers");
    let entry = format!("{} {}\n", RELEASE_SIGNING_PRINCIPAL, trusted_key.trim());
    if let Err(e) = std::fs::write(&allowed, entry) {
        return Signature::Rejected {
            reason: format!("could not stage the release signing key at {}: {}", allowed.display(), e),
        };
    }
    let tags = match git_output(src_dir, &["tag", "--points-at", sha]) {
        Ok(tags) => tags,
        Err(e) => {
            return Signature::Rejected {
                reason: format!("could not list tags at {}: {:#}", sha, e),
            }
        }
    };
    let tags: Vec<&str> = tags.lines().map(str::trim).filter(|t| !t.is_empty()).collect();
    if tags.is_empty() {
        return Signature::Rejected {
            reason: format!(
                "{} carries no tag — monux installs signed RELEASES, not whatever is on master",
                &sha[..12.min(sha.len())]
            ),
        };
    }
    for tag in &tags {
        let out = Command::new("git")
            .arg("-C")
            .arg(src_dir)
            .arg("-c")
            .arg("gpg.format=ssh")
            .arg("-c")
            .arg(format!(
                "gpg.ssh.allowedSignersFile={}",
                allowed.display()
            ))
            .args(["verify-tag", tag])
            .output();
        match out {
            Ok(out) if out.status.success() => {
                return Signature::Verified {
                    tag: (*tag).to_string(),
                }
            }
            Ok(_) => continue,
            Err(e) => {
                return Signature::Rejected {
                    reason: format!("could not run git verify-tag: {}", e),
                }
            }
        }
    }
    Signature::Rejected {
        reason: format!(
            "no tag at this commit ({}) carries a valid monux release signature",
            tags.join(", ")
        ),
    }
}

/// The commit of the newest release tag in a `git ls-remote --tags` or
/// `git show-ref --tags -d` listing. Both are whitespace-separated
/// `<sha> refs/tags/<name>` lines and peel annotated tags the same way, so one
/// parser serves the remote check and the local checkout.
///
/// An annotated tag appears TWICE: `refs/tags/v1` is the tag object and
/// `refs/tags/v1^{}` the commit it points at. The commit is what gets compared
/// against this build's revision and checked out, so the peeled entry wins
/// wherever it exists; a lightweight tag has only the plain entry.
///
/// Ordering is by parsed version rather than by git's --sort, so the choice is
/// deterministic and testable without a repo. Tags that aren't versions
/// (`nightly`, a personal marker) are ignored: monux releases are versions.
fn newest_release_tag(listing: &str) -> Option<(String, String)> {
    let mut best: Option<((u64, u64, u64), String, String)> = None;
    let mut peeled: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut plain: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        let (Some(sha), Some(refname)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Some(name) = refname.strip_prefix("refs/tags/") else {
            continue;
        };
        match name.strip_suffix("^{}") {
            Some(name) => peeled.insert(name.to_string(), sha.to_string()),
            None => plain.insert(name.to_string(), sha.to_string()),
        };
    }
    for (name, sha) in plain.iter().chain(peeled.iter()) {
        let Some(version) =
            crate::config::parse_version(name.strip_prefix('v').unwrap_or(name))
        else {
            continue;
        };
        // The peeled commit is authoritative when the tag has one.
        let sha = peeled.get(name).unwrap_or(sha);
        let candidate = (version, name.clone(), sha.clone());
        if best.as_ref().is_none_or(|(best, _, _)| version > *best) {
            best = Some(candidate);
        }
    }
    best.map(|(_, name, sha)| (name, sha))
}

/// The commit this build should move to, as published by the repo.
///
/// With release signing configured this is the newest RELEASE TAG, not the
/// branch head — because a signed tag is the only thing an install will
/// accept (see verify_release_signature). Reporting HEAD here instead would
/// announce "update available" for every push between releases and then
/// refuse to install it, which is a notification that lies.
///
/// Without a signing key nothing gates on tags, so the branch head is still
/// the right answer.
pub fn latest_remote_sha(repo: &str) -> Result<String> {
    if signing_configured() {
        return latest_remote_release(repo).map(|(_, sha)| sha);
    }
    let out = git_network_command()
        .args(["ls-remote", repo, "HEAD"])
        .output()
        .context("Failed to run git: is it installed?")?;
    if !out.status.success() {
        bail!("git ls-remote {} failed", repo);
    }
    let stdout = String::from_utf8(out.stdout)?;
    stdout
        .split_whitespace()
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .with_context(|| format!("git ls-remote {} returned no HEAD", repo))
}

/// The newest release tag published by the repo, as (tag, commit).
fn latest_remote_release(repo: &str) -> Result<(String, String)> {
    let out = git_network_command()
        .args(["ls-remote", "--tags", repo])
        .output()
        .context("Failed to run git: is it installed?")?;
    if !out.status.success() {
        bail!("git ls-remote --tags {} failed", repo);
    }
    let listing = String::from_utf8(out.stdout)?;
    newest_release_tag(&listing).with_context(|| {
        format!(
            "{} publishes no release tag yet — monux installs signed releases, so there is nothing to update to",
            repo
        )
    })
}

/// The newest release tag in the local checkout, as (tag, commit).
fn newest_local_release(src_dir: &Path) -> Result<(String, String)> {
    // show-ref exits 1 with no output when there are no tags at all, which is
    // "nothing to install", not a failure to report.
    let listing = git_output(src_dir, &["show-ref", "--tags", "-d"]).unwrap_or_default();
    newest_release_tag(&listing)
        .context("the source checkout carries no release tag to install")
}

/// Whether the remote HEAD sha means there's an update for a build with the
/// given revision ("<sha>" or "<sha>-dirty"; "unknown" never auto-updates).
/// Cheap and pure (no checkout needed); run() additionally refuses a remote
/// HEAD that isn't a descendant of the build's commit (see is_rewound_remote).
pub fn is_newer_remote(remote_sha: &str, current_revision: &str) -> bool {
    let current_base = current_revision.trim_end_matches("-dirty");
    current_base != "unknown" && !current_base.is_empty() && !remote_sha.starts_with(current_base)
}

/// Whether the just-pulled HEAD should be treated as not-newer despite
/// differing from our build's commit: yes when that commit is known to the
/// checkout but is NOT an ancestor of HEAD — master was rewound or
/// force-pushed, and pure inequality (is_newer_remote) would install a
/// downgrade. Undecidable ancestry (a commit beyond the shallow clone's
/// boundary, e.g. an unpushed local build) keeps the old behavior.
fn is_rewound_remote(src_dir: &Path, current_base: &str) -> bool {
    match is_ancestor_of_head(src_dir, current_base) {
        Some(is_ancestor) => !is_ancestor,
        None => {
            debug!(
                "Can't check whether the remote HEAD descends from {} (unknown to the checkout); assuming a normal update",
                current_base
            );
            false
        }
    }
}

/// Whether `base` is an ancestor of the checkout's HEAD: Some(true/false)
/// when git could decide, None when it can't (the commit isn't in the
/// checkout, e.g. beyond the shallow clone's boundary).
fn is_ancestor_of_head(src_dir: &Path, base: &str) -> Option<bool> {
    let out = Command::new("git")
        .arg("-C")
        .arg(src_dir)
        .args(["merge-base", "--is-ancestor", base, "HEAD"])
        .output()
        .ok()?;
    match out.status.code() {
        Some(0) => Some(true),
        Some(1) => Some(false),
        _ => None,
    }
}

/// How an update attempt ended.
pub enum UpdateStatus {
    /// A new build was installed.
    Installed,
    /// Already up to date; nothing was built.
    AlreadyCurrent,
    /// The new source speaks a protocol version our server couldn't pair
    /// with (see pair_works); nothing was built (see the
    /// protocol_constraint parameter of run).
    SkippedIncompatible,
    /// The target commit is not a signed release, so nothing was built (see
    /// verify_release_signature). Unlike SkippedIncompatible this will not
    /// resolve on its own — the signature of a given commit does not change —
    /// so the caller records the attempt and stops retrying it.
    SkippedUnverified,
}

/// Who asked for an install, which decides how strict signature checking is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// A person typed `monux update`. They are the review gate, so a build
    /// with no signing key compiled in warns loudly and proceeds; a build
    /// that HAS a key still demands a valid signature.
    Interactive,
    /// The background updater, with nobody watching. Fail closed: refuse
    /// anything not signed, including the unconfigured case, because
    /// "unverifiable" and "unattended" together is the situation this whole
    /// mechanism exists to prevent.
    Unattended,
}

/// Whether a build speaking `target` protocol can pair with a server
/// speaking `server`: both must be in the negotiation era (v16+), and the
/// pair then connects at the lower version (shared::negotiate).
///
/// The old exact-match escape hatch is gone with pre-v16 support (13.0.0):
/// there is no longer any build we could install that pairs with a v15
/// server, so a matching-but-ancient pair is not an outcome to preserve.
pub fn pair_works(target: u64, server: u64) -> bool {
    target.min(server) >= crate::msgs::shared::PROTOCOL_VERSION_NEGOTIATION
}

pub fn run(
    force: bool,
    low_priority: bool,
    protocol_constraint: Option<u64>,
    to: Option<&str>,
    trust: Trust,
) -> Result<UpdateStatus> {
    let repo = repo_url();
    // MONUX_UPDATE_CACHE is DEBUG-ONLY for the same reason MONUX_UPDATE_REPO
    // is (see repo_url): it names the directory this path compiles from, and
    // `sudo -E` forwards the environment into a root process, so honoring it
    // in a release build would let anything that can set the daemon's
    // environment choose what root builds.
    let src_dir = default_src_dir()?;
    // Serialize against other updaters before touching the checkout: the
    // other daemon on a dual-daemon machine, or a manual 'monux update'
    // mid-build. The second contender waits, then sees AlreadyCurrent
    // instead of colliding with the first on git locks.
    let _update_lock = acquire_update_lock(&src_dir)?;

    if src_dir.join(".git").exists() {
        if to.is_some() {
            // Resolving a version scans Cargo.toml history, so fetch first
            // (the newest commits must resolve too) and deepen the initial
            // --depth 1 clone once.
            if git_output(&src_dir, &["rev-parse", "--is-shallow-repository"])? == "true" {
                git(&src_dir, &["fetch", "--unshallow"])?;
            } else {
                git(&src_dir, &["fetch"])?;
            }
        } else {
            // A '--to' install leaves the checkout on a detached HEAD;
            // reattach to master before pulling. The pull then fast-forwards
            // across the pinned era like any other — no special casing.
            if head_is_detached(&src_dir) {
                // A '--to' downgrade, or the release-tag checkout below, both
                // leave a detached HEAD; reattach so the pull fast-forwards.
                info!("Reattaching the source checkout to master...");
                git(&src_dir, &["checkout", "master"])?;
            }
            info!("Pulling latest source in {}...", src_dir.display());
            // Tags reachable from the fetched history come along with a pull,
            // but the target is now a TAG, so ask for them explicitly rather
            // than relying on that.
            if signing_configured() {
                let _ = git(&src_dir, &["fetch", "--tags"]);
            }
            if git(&src_dir, &["pull", "--ff-only"]).is_err() {
                // The pull can only fail to fast-forward if the checkout and
                // the remote have diverged — in practice because master was
                // force-pushed (a rewritten commit message, an amended
                // commit), which strands every checkout that had fetched the
                // old commits. This is a disposable cache of upstream, never
                // a place work is done, so there is nothing to preserve:
                // fetch and hard-reset onto the remote instead of dead-ending
                // every future update until someone deletes the directory by
                // hand.
                info!(
                    "The source checkout diverged from the remote (master was likely force-pushed); resetting it to origin/master..."
                );
                resync_to_remote(&src_dir).with_context(|| {
                    format!(
                        "Failed to update the source checkout; delete it and retry: rm -rf {}",
                        src_dir.display()
                    )
                })?;
            }
        }
    } else {
        info!("Cloning {} into {}...", repo, src_dir.display());
        if let Some(parent) = src_dir.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        // A '--to' install resolves versions/commits from history, so it
        // needs a full clone; the latest-only path stays shallow.
        let mut args = vec!["clone"];
        if to.is_none() {
            args.extend(["--depth", "1"]);
        }
        let status = git_network_command()
            .args(args)
            .arg(&repo)
            .arg(&src_dir)
            .status()
            .context("Failed to run git: is it installed?")?;
        if !status.success() {
            bail!("git clone {} failed", repo);
        }
        // `--depth 1` implies --single-branch and brings only the tags that
        // point into the fetched history, so a fresh shallow clone can land
        // with no release tags at all whenever master's tip is untagged. The
        // repairing fetch on the existing-checkout path above never runs for a
        // clone, so ask here too — otherwise the FIRST update on a new machine
        // fails the signature gate for want of a tag, and an --auto-install
        // daemon records the attempt and skips that release entirely.
        if signing_configured() {
            let _ = git(&src_dir, &["fetch", "--tags"]);
        }
    }

    // Resolve what we would install and read everything the gates need
    // STRAIGHT FROM GIT OBJECTS. No checkout happens until every gate has
    // passed, so a refusal — for any reason — leaves the source checkout
    // exactly as it was, rather than parked on a commit we just declined.
    let current_base = CURRENT_REVISION.trim_end_matches("-dirty");
    // (sha, short sha, human label for logs, whether it needs a checkout)
    let (target_sha, latest, target_label, needs_checkout) = match to {
        Some(target) => {
            let sha = resolve_target(&src_dir, target)?;
            let short = git_output(&src_dir, &["rev-parse", "--short=12", &sha])?;
            (sha, short, target.to_string(), true)
        }
        None if signing_configured() => {
            // With signing configured the target is the newest RELEASE TAG,
            // not the branch head: a signed tag is the only thing the gate
            // below will accept, so aiming anywhere else guarantees a refusal
            // after a full checkout. This is also what the daily check
            // reported (latest_remote_sha), so the two agree on what "an
            // update is available" means.
            let (tag, sha) = newest_local_release(&src_dir)?;
            let short = git_output(&src_dir, &["rev-parse", "--short=12", &sha])?;
            (sha, short, tag, true)
        }
        None => {
            let sha = git_output(&src_dir, &["rev-parse", "HEAD"])?;
            let short = git_output(&src_dir, &["rev-parse", "--short=12", "HEAD"])?;
            (sha, short, "HEAD".to_string(), false)
        }
    };

    // The target's declared version and protocol, both read from git objects.
    let manifest = git_output(&src_dir, &["show", &format!("{}:Cargo.toml", target_sha)])?;
    let target_crate_version = cargo_toml_version(&manifest)
        .with_context(|| format!("No package version in Cargo.toml at {}", target_label))?;
    let shared = git_output(
        &src_dir,
        &["show", &format!("{}:src/msgs/shared.rs", target_sha)],
    )?;
    let target_protocol = protocol_version_in(&shared)
        .with_context(|| format!("Failed to read the protocol version of {}", target_label))?;

    if !force && current_base != "unknown" && latest == current_base {
        // Named for a '--to', which asked for a specific version and deserves
        // to be told it already has it; generic otherwise.
        match to {
            Some(_) => info!(
                "monux is already at v{} ({}). Use --force to rebuild anyway.",
                target_crate_version, CURRENT_REVISION
            ),
            None => info!(
                "monux is already up to date ({}). Use --force to rebuild anyway.",
                CURRENT_REVISION
            ),
        }
        return Ok(UpdateStatus::AlreadyCurrent);
    }

    // Downgrade guard. '--to' is exempt: naming a version IS the request to
    // install that version, downgrades included (that's --rollback).
    if !force && to.is_none() {
        if signing_configured() {
            // Compare VERSIONS, not git ancestry. Ancestry can't answer here:
            // is_ancestor_of_head returns None whenever the running build's
            // commit isn't in the checkout, which is the normal case for the
            // --depth 1 clone this path uses, and None was treated as "assume
            // a normal update". That left a fresh clone willing to install any
            // older signed release someone served as "newest" — the signature
            // still holds, but a known-vulnerable past release satisfies it.
            // A version comparison is a total order and needs no history.
            match (
                crate::config::parse_version(&target_crate_version),
                crate::config::parse_version(env!("CARGO_PKG_VERSION")),
            ) {
                (Some(target), Some(running)) if target < running => {
                    info!(
                        "Not updating to {} (v{}): this build is v{}, so that would be a downgrade. Use --force to override, or 'monux update --to {}' to install it deliberately.",
                        latest, target_crate_version, env!("CARGO_PKG_VERSION"), target_crate_version
                    );
                    return Ok(UpdateStatus::AlreadyCurrent);
                }
                (None, _) | (_, None) => {
                    // An unparseable version on either side: fall through
                    // rather than refuse, so a malformed manifest can't wedge
                    // updates entirely. The signature gate still applies.
                    debug!(
                        "Could not compare versions ({} vs {}); skipping the downgrade check",
                        target_crate_version,
                        env!("CARGO_PKG_VERSION")
                    );
                }
                _ => {}
            }
        } else if current_base != "unknown"
            && !current_base.is_empty()
            && is_rewound_remote(&src_dir, current_base)
        {
            // No signing key, so the target is the branch head and there are
            // no version tags to compare: fall back to ancestry, which does
            // answer the question this path actually faces (master rewound or
            // force-pushed under us).
            info!(
                "Not updating to {}: the remote HEAD is not a descendant of this build's commit ({}) — master was likely rewound or force-pushed, so the update would be a downgrade. Use --force to override.",
                latest, CURRENT_REVISION
            );
            return Ok(UpdateStatus::AlreadyCurrent);
        }
    }

    // The update gate: a client never installs a build its server couldn't
    // pair with. Since protocol v16 pairs negotiate (connecting at the lower
    // version), the gate accepts any negotiation-era pair; a pre-negotiation
    // server still demands an exact match (see pair_works).
    if !force {
        if let Some(server_version) = protocol_constraint {
            if let Err(e) = check_to_gate(
                &target_crate_version,
                &latest,
                target_protocol,
                server_version,
            ) {
                info!("{:#}", e);
                return Ok(UpdateStatus::SkippedIncompatible);
            }
        }
    }

    // Signature gate, before the checkout and the expensive build. `--force`
    // does NOT bypass it: force is about rebuilding and about the protocol
    // gate, never about running code we can't attribute. It reads tag objects
    // (git tag --points-at / verify-tag), so it needs no working tree — which
    // is what lets it run before the checkout rather than after it.
    match check_release_signature(&src_dir, &target_sha, trust) {
        SignatureGate::Proceed => {}
        SignatureGate::Refuse(reason) => {
            info!("{}", reason);
            return Ok(UpdateStatus::SkippedUnverified);
        }
    }

    // Every gate passed: now move the checkout onto the target.
    if needs_checkout {
        info!("Checking out v{} ({})...", target_crate_version, latest);
        git(&src_dir, &["checkout", &target_sha])?;
    }
    // A '--to' install pins auto-update at the version it just placed.
    let pinned: Option<(String, u64)> = to.map(|_| (target_crate_version.clone(), target_protocol));
    match &pinned {
        Some(_) => info!(
            "Installing monux v{} ({}): the current build is {}",
            target_crate_version, latest, CURRENT_REVISION
        ),
        // Names the target too: with signing configured that is the release
        // tag being installed, which the old flow logged separately.
        None => info!(
            "Updating monux: {} -> {} ({})",
            CURRENT_REVISION, latest, target_label
        ),
    }

    let root = install_root();
    let cargo = find_cargo()?;
    // Clean staging leftovers from previously killed installs. Skip dirs whose
    // pid suffix is a live process: a concurrent updater is building there.
    let our_pid = std::process::id() as i32;
    if let Ok(entries) = std::fs::read_dir(&root) {
        for entry in entries.flatten() {
            if let Some(pid_str) = entry
                .file_name()
                .to_string_lossy()
                .strip_prefix(".monux-install-staging-")
            {
                if let Ok(pid) = pid_str.parse::<i32>() {
                    if pid != our_pid && std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                        continue;
                    }
                }
                let _ = std::fs::remove_dir_all(entry.path());
            }
            if let Some(pid_str) = entry
                .file_name()
                .to_string_lossy()
                .strip_prefix(".monux-verified-src-")
            {
                if let Ok(pid) = pid_str.trim_end_matches(".tar").parse::<i32>() {
                    if pid != our_pid && std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                        continue;
                    }
                }
                let path = entry.path();
                let _ = std::fs::remove_dir_all(&path);
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    // Build from the verified objects rather than from the working tree the
    // checkout above left in the invoking user's home (see
    // export_verified_tree). build.rs reads the revision out of .git, which an
    // exported tree has none of, so it is passed in explicitly.
    let build_dir = root.join(format!(".monux-verified-src-{}", std::process::id()));
    export_verified_tree(&src_dir, &target_sha, &build_dir)?;
    let build_sha = target_sha
        .get(..12)
        .unwrap_or(target_sha.as_str())
        .to_string();
    // Install into a staging dir on the same filesystem, then rename the
    // binary into place atomically. 'cargo install' copies into bin/ in
    // place, so a kill mid-copy could leave a truncated monux binary;
    // rename(2) of a complete file replaces atomically instead.
    let staging = root.join(format!(".monux-install-staging-{}", std::process::id()));
    info!(
        "Building and installing to {} (this can take a few minutes)...",
        root.join("bin/monux").display()
    );
    let mut cmd = if low_priority {
        // Background auto-updates compile at the lowest CPU scheduling
        // priority, so a build can't stall interactive input on this machine.
        let mut c = Command::new("nice");
        c.args(["-n", "19"]).arg(cargo);
        c
    } else {
        Command::new(cargo)
    };
    cmd.arg("install")
        // Build exactly the locked dependencies (Cargo.lock is committed).
        .arg("--locked")
        .arg("--path")
        .arg(&build_dir)
        .arg("--root")
        .arg(&staging)
        .arg("--force")
        // cargo warns when the install root's bin/ isn't on PATH. The staging
        // root is transient (the binary is renamed out of it below), so put it
        // on PATH just for this subprocess to silence the misleading warning.
        .env("PATH", path_with(staging.join("bin")))
        .env("MONUX_BUILD_SHA", &build_sha);
    // A root build must not read the invoking user's ~/.cargo: its
    // config.toml sets rustc-wrapper and per-target linker, which is arbitrary
    // code execution as root with no race required. Costs a fresh registry
    // download per root update; correctness wins.
    if unsafe { libc::geteuid() } == 0 {
        cmd.env("CARGO_HOME", root.join(".monux-cargo-home"));
    }
    let status = cmd.status().context("Failed to run cargo install")?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&staging);
        let _ = std::fs::remove_dir_all(&build_dir);
        bail!("cargo install failed");
    }
    let _ = std::fs::remove_dir_all(&build_dir);
    place_binary_atomically(
        &staging.join("bin").join("monux"),
        &root.join("bin").join("monux"),
    )?;
    let _ = std::fs::remove_dir_all(&staging);
    // The 'mx' shorthand lives next to the binary (a relative symlink, so the
    // atomic rename above keeps it valid). Never fail the update over it.
    match crate::alias::ensure(&root.join("bin")) {
        Ok(crate::alias::EnsureOutcome::Created) => info!("Alias: mx -> monux (in {})", root.join("bin").display()),
        Ok(crate::alias::EnsureOutcome::Refreshed) => info!("Refreshed the mx -> monux alias"),
        Ok(_) => {}
        Err(e) => warn!("Couldn't create the 'mx' alias: {:#}", e),
    }
    // Per-user install artifacts install.sh owns but the updater path never
    // sees: ensure the tray desktop shortcut exists (create-if-missing only;
    // a user's edited copy is left alone).
    if let Some(home) = home::home_dir() {
        match crate::setup::ensure_desktop_shortcut(&home, std::env::var_os("XDG_DATA_HOME").as_deref()) {
            Ok(true) => info!("Wrote the 'monux tray' desktop shortcut"),
            Ok(false) => {}
            Err(e) => warn!("Couldn't write the desktop shortcut: {:#}", e),
        }
    }
    // Record the build this install replaced (the running one), so
    // '--rollback' can return to it. A build without a revision (built
    // outside git) can't be returned to, so nothing is recorded then.
    let config_dir = default_config_dir();
    if let Some(dir) = config_dir.as_deref() {
        let current_base = CURRENT_REVISION.trim_end_matches("-dirty");
        if current_base != "unknown" && !current_base.is_empty() {
            record_previous_version(dir, env!("CARGO_PKG_VERSION"), current_base);
        }
    }
    match pinned {
        Some((version, target_version)) => {
            // Pin auto-update so the daily check never undoes the manual
            // downgrade; a plain 'monux update' lifts the pin.
            if let Some(dir) = config_dir.as_deref() {
                write_update_pin(dir, &version, &latest);
            }
            info!(
                "Installed monux v{} ({}) at {}; it speaks protocol v{}.",
                version,
                latest,
                root.join("bin/monux").display(),
                target_version
            );
            info!("Restart daemons to apply: mx daemon restart");
            info!(
                "Auto-update is now pinned at v{} and will skip; return to latest with 'monux update'",
                version
            );
        }
        None => {
            info!(
                "Updated monux to {} at {}. Restart any running monux server/client to pick it up.",
                latest,
                root.join("bin/monux").display()
            );
        }
    }
    Ok(UpdateStatus::Installed)
}

/// Whether an install may proceed past the signature check.
enum SignatureGate {
    Proceed,
    Refuse(String),
}

/// Applies the release-signature policy for a given trust level (see Trust).
/// Split from verify_release_signature so the policy — as opposed to the git
/// plumbing — is unit-testable.
fn signature_gate(signature: Signature, trust: Trust) -> SignatureGate {
    match (signature, trust) {
        (Signature::Verified { tag }, _) => {
            info!("Release signature verified: {}", tag);
            SignatureGate::Proceed
        }
        (Signature::Unconfigured, Trust::Interactive) => {
            warn!(
                "This build has no release signing key compiled in, so the source being installed cannot be attributed to anyone. Proceeding because you asked for this update explicitly."
            );
            SignatureGate::Proceed
        }
        (Signature::Unconfigured, Trust::Unattended) => SignatureGate::Refuse(
            "Not installing in the background: this build has no release signing key compiled in, so nothing can be verified. Run 'monux update' yourself to install anyway."
                .to_string(),
        ),
        (Signature::Rejected { reason }, Trust::Unattended) => SignatureGate::Refuse(format!(
            "Not installing in the background: {}. Run 'monux update' if you mean to install it anyway.",
            reason
        )),
        (Signature::Rejected { reason }, Trust::Interactive) => SignatureGate::Refuse(format!(
            "Refusing to install: {}.",
            reason
        )),
    }
}

/// verify_release_signature plus the trust policy (see signature_gate).
fn check_release_signature(src_dir: &Path, sha: &str, trust: Trust) -> SignatureGate {
    signature_gate(verify_release_signature(src_dir, sha), trust)
}

/// Holds the cross-process update flock for the duration of an update run
/// (dropped when run() returns).
struct UpdateLock {
    _file: std::fs::File,
}

/// The update lock file: a sibling of the source checkout, derived from the
/// same MONUX_UPDATE_CACHE-aware path, so every updater on this machine —
/// either daemon, or a manual 'monux update' — serializes on the one file.
fn update_lock_path(src_dir: &Path) -> PathBuf {
    src_dir
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("monux-update.lock")
}

/// Takes the update flock (blocking LOCK_EX). flock is tied to the open file
/// description, so the kernel releases it when the process dies for any
/// reason — the lock can never go stale, and the file itself is never
/// deleted.
fn acquire_update_lock(src_dir: &Path) -> Result<UpdateLock> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let path = update_lock_path(src_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    // 0666 like the single-instance locks: a root-run daemon and the user's
    // own updater must share the file; flock itself is the authority. chmod
    // too since umask may restrict the create mode.
    let file = std::fs::OpenOptions::new()
        .create(true)
        // Explicitly NOT truncating: nothing ever reads this file's contents
        // (flock on the open file description is the whole mechanism), and
        // truncating a file another updater currently holds would be a write
        // to a file we do not own yet.
        .truncate(false)
        .write(true)
        .mode(0o666)
        .open(&path)
        .with_context(|| format!("Failed to open the update lock {}", path.display()))?;
    let _ = std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o666));
    let fd = file.as_raw_fd();
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        info!("Waiting for another monux update to finish...");
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("Failed to lock {}", path.display()));
        }
    }
    Ok(UpdateLock { _file: file })
}

/// Parses PROTOCOL_VERSION out of shared.rs content.
fn protocol_version_in(text: &str) -> Result<u64> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("pub const PROTOCOL_VERSION: u64 =") {
            if let Some(num) = rest.trim().strip_suffix(';') {
                return num
                    .trim()
                    .parse()
                    .context("Failed to parse PROTOCOL_VERSION");
            }
        }
    }
    bail!("PROTOCOL_VERSION not found")
}

/// Extracts the package version from Cargo.toml content: the first bare
/// `version = "X.Y.Z"` line (the [package] section heads monux's manifest;
/// dependency versions ride inline in their own entries).
fn cargo_toml_version(manifest: &str) -> Option<String> {
    for line in manifest.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("version") {
            if let Some(rest) = rest.trim_start().strip_prefix('=') {
                let rest = rest.trim();
                if let Some(version) = rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
                    return Some(version.to_string());
                }
            }
        }
    }
    None
}

/// Forces the source checkout onto the remote's master, discarding whatever
/// local history diverged from it. The recovery path for a force-pushed
/// upstream, where `pull --ff-only` refuses and would otherwise block every
/// future update (see the pull site). Safe to be this blunt: the checkout is
/// a cache of upstream that monux clones itself and only ever reads.
///
/// A shallow clone (the default for latest-only updates) can't be reset onto
/// commits it never fetched, so the fetch deepens it first.
fn resync_to_remote(src_dir: &Path) -> Result<()> {
    if git_output(src_dir, &["rev-parse", "--is-shallow-repository"])? == "true" {
        git(src_dir, &["fetch", "--unshallow"])?;
    } else {
        git(src_dir, &["fetch"])?;
    }
    git(src_dir, &["reset", "--hard", "origin/master"])?;
    Ok(())
}

/// Whether the source checkout is on a detached HEAD (a '--to' install
/// leaves it that way): symbolic-ref fails then.
fn head_is_detached(src_dir: &Path) -> bool {
    git(src_dir, &["symbolic-ref", "-q", "HEAD"]).is_err()
}

/// The version declared by Cargo.toml at each commit that touched it,
/// newest first: (version, sha) pairs.
fn version_history(src_dir: &Path) -> Result<Vec<(String, String)>> {
    let log = git_output(src_dir, &["log", "--format=%H", "--", "Cargo.toml"])?;
    let mut history = Vec::new();
    for sha in log.lines() {
        let manifest = git_output(src_dir, &["show", &format!("{}:Cargo.toml", sha)])?;
        if let Some(version) = cargo_toml_version(&manifest) {
            history.push((version, sha.to_string()));
        }
    }
    Ok(history)
}

/// Whether a '--to' argument is shaped like a release version (X.Y...),
/// for picking the right "not found" error.
fn looks_like_version(target: &str) -> bool {
    target.contains('.')
        && target
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

/// Resolves a '--to' argument to a full commit sha: first as a released
/// version (the newest commit whose Cargo.toml declares it wins), then as a
/// commit prefix.
fn resolve_target(src_dir: &Path, target: &str) -> Result<String> {
    let history = version_history(src_dir)?;
    let wanted = target.strip_prefix('v').unwrap_or(target);
    if let Some((_, sha)) = history.iter().find(|(version, _)| version == wanted) {
        return Ok(sha.clone());
    }
    // Not a known version: try the argument as a commit prefix.
    let rev = format!("{}^{{commit}}", target);
    if let Ok(sha) = git_output(src_dir, &["rev-parse", "--verify", &rev]) {
        return Ok(sha);
    }
    if looks_like_version(wanted) {
        let mut recent: Vec<&str> = Vec::new();
        for (version, _) in &history {
            if !recent.contains(&version.as_str()) {
                recent.push(version);
            }
            if recent.len() == 10 {
                break;
            }
        }
        bail!(
            "No version {} found in the update history; recent versions: {}",
            target,
            recent.join(", ")
        );
    }
    bail!("No such commit: {}", target)
}

/// The '--to' update gate: refuse installing a build the server couldn't
/// pair with (see pair_works). The refusal names the direction — downgrading
/// a client below the server's protocol only works once the server is
/// downgraded first, mirroring the server-first upgrade order.
fn check_to_gate(version: &str, short: &str, target: u64, server: u64) -> Result<()> {
    if pair_works(target, server) {
        return Ok(());
    }
    let (action, remedy) = if target < server {
        ("downgrading", "Downgrade the server first")
    } else {
        ("updating", "Update the server first")
    };
    bail!(
        "Not {} to v{} ({}): it speaks protocol v{}, but the server speaks v{} — the pair couldn't negotiate a common protocol. {}; this gate opens automatically once this client reconnects to it (or use --force to override).",
        action, version, short, target, server, remedy
    )
}

/// The monux config dir (~/.config/monux), when a home dir is known.
pub fn default_config_dir() -> Option<PathBuf> {
    home::home_dir().map(|home| home.join(".config").join("monux"))
}

/// Name of the file (inside the config dir) pinning updates after a manual
/// downgrade: auto-update skips while it exists and never removes it; a
/// plain 'monux update' does. One line: "<version> <commit>".
const UPDATE_PIN_FILE: &str = "update-pin";

/// Name of the file (inside the config dir) recording the build the last
/// install replaced, for '--rollback'. One line: "<version> <commit>".
const PREVIOUS_VERSION_FILE: &str = "previous-version";

/// Reads a "<version> <commit>" record file, tolerating a missing or
/// garbled file (reads as absent then).
fn read_version_record(config_dir: &Path, file: &str) -> Option<(String, String)> {
    let text = std::fs::read_to_string(config_dir.join(file)).ok()?;
    let mut fields = text.split_whitespace();
    let version = fields.next()?;
    let commit = fields.next()?;
    Some((version.to_string(), commit.to_string()))
}

/// Writes a "<version> <commit>" record file (best-effort, like the
/// protocol-constraint record above).
fn write_version_record(config_dir: &Path, file: &str, version: &str, commit: &str) {
    if let Err(e) = std::fs::write(config_dir.join(file), format!("{} {}\n", version, commit)) {
        tracing::warn!("Failed to record {}: {:?}", file, e);
    }
}

/// The update pin, if set: (version, commit) of the manual downgrade.
pub fn update_pin(config_dir: &Path) -> Option<(String, String)> {
    read_version_record(config_dir, UPDATE_PIN_FILE)
}

/// Pins updates at the given build; written after a successful
/// '--to'/'--rollback' install.
pub fn write_update_pin(config_dir: &Path, version: &str, commit: &str) {
    write_version_record(config_dir, UPDATE_PIN_FILE, version, commit)
}

/// Removes the update pin; returns whether one was set.
pub fn clear_update_pin(config_dir: &Path) -> bool {
    match std::fs::remove_file(config_dir.join(UPDATE_PIN_FILE)) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            tracing::warn!("Failed to remove the update pin: {:?}", e);
            false
        }
    }
}

/// Records the build an install replaced (for '--rollback').
pub fn record_previous_version(config_dir: &Path, version: &str, commit: &str) {
    write_version_record(config_dir, PREVIOUS_VERSION_FILE, version, commit)
}

/// The build the last install replaced, if recorded.
pub fn previous_version(config_dir: &Path) -> Option<(String, String)> {
    read_version_record(config_dir, PREVIOUS_VERSION_FILE)
}

/// Name of the file (inside the config dir) recording the protocol version of
/// the server this machine last talked to as a client.
const SERVER_PROTOCOL_VERSION_FILE: &str = "server_protocol_version";

/// How long a recorded server protocol version stays authoritative. Every
/// handshake rewrites the file, so an older record means this machine has not
/// acted as a client in days — typically a pure server, whose record can never
/// heal otherwise (its own mDNS advertisement is ignored for the gate and it
/// never handshakes as a client). Treating an expired record as absent lets
/// such a machine update again instead of being vetoed by history forever.
const SERVER_PROTOCOL_VERSION_MAX_AGE: Duration = Duration::from_secs(48 * 60 * 60);

/// Records the server's protocol version for the update gate (best-effort).
/// Called by the client on every handshake, including refused ones — that is
/// what re-opens the gate after the server upgrades ahead of us.
pub fn record_server_protocol_version(config_dir: &Path, version: u64) {
    if let Err(e) = std::fs::write(
        config_dir.join(SERVER_PROTOCOL_VERSION_FILE),
        version.to_string(),
    ) {
        tracing::warn!("Failed to record server protocol version: {:?}", e);
    }
}

/// The protocol version of the server this machine acts as a client to, if it
/// has connected to one recently. Used to gate updates so a client never
/// installs a build its server couldn't talk to. Records older than
/// SERVER_PROTOCOL_VERSION_MAX_AGE are ignored (see there).
pub fn server_protocol_constraint(config_dir: &Path) -> Option<u64> {
    server_protocol_constraint_fresh(config_dir, SERVER_PROTOCOL_VERSION_MAX_AGE)
}

/// The max age is a parameter so tests can force expiry without touching
/// file mtimes.
fn server_protocol_constraint_fresh(config_dir: &Path, max_age: Duration) -> Option<u64> {
    let path = config_dir.join(SERVER_PROTOCOL_VERSION_FILE);
    let version: u64 = std::fs::read_to_string(&path).ok()?.trim().parse().ok()?;
    let age = match std::fs::metadata(&path).and_then(|m| m.modified()) {
        // A future mtime (clock skew) counts as fresh.
        Ok(mtime) => mtime.elapsed().unwrap_or(Duration::ZERO),
        Err(_) => return None,
    };
    (age <= max_age).then_some(version)
}

/// Deletes the recorded server protocol version (the update gate file).
/// Called at server startup when no client runs on this machine: on a pure
/// server the record is stale history that cannot heal by itself — nothing
/// ever rewrites it — and it vetoes manual updates while the daemon happens
/// to be down (mDNS finds no live server to refresh it then).
pub fn clear_protocol_constraint(config_dir: &Path) {
    let path = config_dir.join(SERVER_PROTOCOL_VERSION_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => info!(
            "Cleared the recorded server protocol version: this machine runs only a server, so the client-side update gate does not apply"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("Failed to clear the server protocol version gate file: {:?}", e),
    }
}

/// The server protocol version to gate an update on: the minimum of the
/// versions Monux servers currently advertise via mDNS (also recorded, healing
/// a stale gate file), falling back to the version this client recorded at its
/// last handshake when no server answers (offline, another subnet, or a build
/// predating the advertisement). Since protocol v16 the gate accepts any
/// negotiation-era pair (see pair_works), so this value is the pair's floor,
/// not a demanded exact match. Never fails: discovery is best-effort. Blocks
/// for up to the mDNS discovery timeout: call it from a blocking context.
/// The update gate after a discovery: an mDNS observation may RAISE it, never
/// lower it below what a real, authenticated handshake recorded.
///
/// Discovery is attributed by fingerprint now, so a stranger's advertisement
/// is already ignored. This is the second line: the path both gates AND
/// persists, so any value that did get through would outlive the advertisement
/// that planted it and go on silently skipping every update — including the
/// one that would fix whatever let it through.
fn gate_floor(recorded: Option<u64>, discovered: u64) -> u64 {
    match recorded {
        Some(recorded) if discovered < recorded => recorded,
        _ => discovered,
    }
}

pub fn refresh_protocol_constraint(config_dir: Option<&Path>) -> Option<u64> {
    let recorded = config_dir.and_then(server_protocol_constraint);
    let discovered = match crate::discovery::discover_server_protocol_versions(
        &config_dir.map(crate::known_servers::load).unwrap_or_default(),
    ) {
        Ok(versions) => versions,
        Err(e) => {
            debug!(
                "Server protocol version discovery failed ({}); using the recorded gate value",
                e
            );
            return recorded;
        }
    };
    let constraint = match crate::discovery::protocol_version_constraint(&discovered) {
        Some(constraint) => constraint,
        // No server answered: fall back to the last recorded version.
        None => return recorded,
    };
    if gate_floor(recorded, constraint) != constraint {
        let recorded = recorded.expect("gate_floor only holds the line when something was recorded");
        info!(
            "Ignoring the mDNS-advertised protocol gate v{}: the last handshake recorded v{}, and a discovery may not lower it",
            constraint, recorded
        );
        return Some(recorded);
    }
    if discovered.len() > 1 {
        info!(
            "Monux servers advertise different protocol versions ({}); gating on the oldest, v{}",
            discovered
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            constraint
        );
    }
    if recorded != Some(constraint) {
        info!(
            "Refreshed the server protocol version gate via mDNS: v{} -> v{}",
            recorded
                .map(|v| v.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            constraint
        );
    }
    if let Some(dir) = config_dir {
        let _ = std::fs::create_dir_all(dir);
        record_server_protocol_version(dir, constraint);
    }
    Some(constraint)
}

/// Install next to the currently running binary (<root>/bin/monux -> <root>),
/// falling back to ~/.local.
fn install_root() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        // After an auto-update replaces the binary on disk while we run, Linux
        // reports our exe as "<path> (deleted)"; trim that suffix.
        let exe = PathBuf::from(exe.to_string_lossy().trim_end_matches(" (deleted)"));
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

/// Moves the staged binary onto its final path via rename(2), which replaces
/// atomically on the same filesystem: a kill at any point leaves either the
/// old or the new binary intact, never a partial one. The staging dir lives
/// inside the install root, so the two paths are always on the same
/// filesystem (renames across filesystems would fail rather than copy).
fn place_binary_atomically(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    std::fs::rename(from, to).with_context(|| {
        format!(
            "Failed to move {} into place at {}",
            from.display(),
            to.display()
        )
    })
}

/// PATH with `dir` prepended, for a subprocess (see the cargo install call).
fn path_with(dir: PathBuf) -> std::ffi::OsString {
    let mut paths = vec![dir];
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path));
    }
    std::env::join_paths(paths).expect("PATH entries can't contain NUL")
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
        if let Some(resolved) = resolve_on_path("cargo") {
            ensure_root_owned_when_root(&resolved, "the cargo binary")?;
        }
        return Ok(PathBuf::from("cargo"));
    }
    let fallback = home::home_dir()
        .context("No home dir found")?
        .join(".cargo")
        .join("bin")
        .join("cargo");
    if fallback.exists() {
        // The dangerous one: sudo's secure_path strips ~/.cargo/bin from PATH,
        // so a root daemon reaches this fallback and would exec a binary the
        // unprivileged user can rewrite. The signature gate attests the
        // SOURCE, never the toolchain that compiles it.
        ensure_root_owned_when_root(&fallback, "the cargo binary")?;
        return Ok(fallback);
    }
    bail!("cargo not found: install a Rust toolchain via https://rustup.rs/")
}

/// The first executable named `name` on PATH, so its ownership can be checked.
fn resolve_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Refuses a path that root would execute or read but an unprivileged user can
/// rewrite.
///
/// Only meaningful when running as root: `sudo -E monux server --auto-install`
/// is a documented way to run the daemon, and it keeps the invoking user's
/// HOME, so every default the updater derives from it points into a directory
/// that user still controls. A no-op for an ordinary user install, where the
/// user IS the trust boundary.
fn ensure_root_owned_when_root(path: &Path, what: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let owner = std::fs::metadata(path)
        .with_context(|| format!("could not stat {}", path.display()))?
        .uid();
    if owner != 0 {
        bail!(
            "refusing to run as root with {} at {}: it is owned by uid {}, which could replace it between this check and the build",
            what,
            path.display(),
            owner
        );
    }
    Ok(())
}

/// Extracts the verified commit's tree into `dest`, straight from git's object
/// database.
///
/// The signature gate attests a COMMIT, not a working tree. `git checkout`
/// leaves that commit's content in a directory the invoking user can still
/// rewrite — and under `sudo -E monux server --auto-install` the builder is
/// root while that user is not — so between the check and `cargo install`
/// anything could swap `build.rs` or a source file and have it compiled and
/// run as root. Git objects are content-addressed, so an archive of the
/// verified sha is exactly the bytes that were signed; extracting them into a
/// directory under the install root (which is root-owned wherever root
/// installs) closes the window.
fn export_verified_tree(src_dir: &Path, sha: &str, dest: &Path) -> Result<()> {
    let _ = std::fs::remove_dir_all(dest);
    std::fs::create_dir_all(dest)
        .with_context(|| format!("could not create {}", dest.display()))?;
    let tarball = dest.with_file_name(format!(
        "{}.tar",
        dest.file_name().and_then(|n| n.to_str()).unwrap_or("src")
    ));
    let status = Command::new("git")
        .arg("-C")
        .arg(src_dir)
        .args(["archive", "--format=tar", "--output"])
        .arg(&tarball)
        .arg(sha)
        .status()
        .context("Failed to run git archive")?;
    if !status.success() {
        let _ = std::fs::remove_file(&tarball);
        bail!("could not export the verified source of {}", sha);
    }
    let status = Command::new("tar")
        .arg("-xf")
        .arg(&tarball)
        .arg("-C")
        .arg(dest)
        .status()
        .context("Failed to run tar")?;
    let _ = std::fs::remove_file(&tarball);
    if !status.success() {
        bail!("could not unpack the verified source of {}", sha);
    }
    Ok(())
}

fn git(dir: &Path, args: &[&str]) -> Result<()> {
    let status = git_network_command()
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

/// A git command for network operations (ls-remote/clone/pull), bounded so a
/// dead route or hung connection fails in ~30s instead of blocking for
/// minutes: git aborts when the transfer rate stays below
/// GIT_HTTP_LOW_SPEED_LIMIT bytes/sec for GIT_HTTP_LOW_SPEED_TIME seconds.
fn git_network_command() -> Command {
    let mut cmd = Command::new("git");
    cmd.env("GIT_HTTP_LOW_SPEED_LIMIT", "1000")
        .env("GIT_HTTP_LOW_SPEED_TIME", "30");
    cmd
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_check_comparison() {
        // Different commit: update available.
        assert!(is_newer_remote(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbb"
        ));
        // Remote HEAD is our commit (possibly with more context): up to date.
        assert!(!is_newer_remote(
            "bbbbbbbbbbbbcccccccccccccccccccccccc",
            "bbbbbbbbbbbb"
        ));
        // Dirty build compares against its base sha.
        assert!(!is_newer_remote(
            "bbbbbbbbbbbbcccccccccccccccccccccccc",
            "bbbbbbbbbbbb-dirty"
        ));
        // Unknown build revision: never auto-update.
        assert!(!is_newer_remote(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "unknown"
        ));
    }

    #[test]
    fn pair_works_matrix() {
        // Negotiation era: any v16+ pair connects at the lower version,
        // whichever side is newer.
        assert!(pair_works(16, 16));
        assert!(pair_works(16, 17));
        assert!(pair_works(17, 16));
        assert!(pair_works(17, 18));
        // A pre-v16 peer on either side can no longer be paired with at all,
        // matching versions included: 13.0.0 dropped the exact-match escape
        // hatch along with the client's clamp retry, so there is no build we
        // could install that would talk to one.
        assert!(!pair_works(15, 15));
        assert!(!pair_works(14, 14));
        assert!(!pair_works(16, 15));
        assert!(!pair_works(15, 16));
        assert!(!pair_works(17, 15));
        assert!(!pair_works(15, 17));
        assert!(!pair_works(16, 14));
        assert!(!pair_works(14, 15));
    }

    fn proceeds(gate: SignatureGate) -> bool {
        matches!(gate, SignatureGate::Proceed)
    }

    fn refusal(gate: SignatureGate) -> String {
        match gate {
            SignatureGate::Refuse(reason) => reason,
            SignatureGate::Proceed => panic!("expected a refusal"),
        }
    }

    /// The whole point of the trust split: nothing installs unattended that
    /// cannot be attributed, while a person at a terminal is allowed to be
    /// their own review gate.
    #[test]
    fn unattended_installs_fail_closed_and_interactive_ones_do_not() {
        let verified = || Signature::Verified {
            tag: "v13.0.0".to_string(),
        };
        let rejected = || Signature::Rejected {
            reason: "no tag at this commit".to_string(),
        };

        // A verified release installs either way.
        assert!(proceeds(signature_gate(verified(), Trust::Unattended)));
        assert!(proceeds(signature_gate(verified(), Trust::Interactive)));

        // No signing key compiled in: the background updater refuses, a
        // person gets a warning and their update.
        let err = refusal(signature_gate(Signature::Unconfigured, Trust::Unattended));
        assert!(err.contains("no release signing key"), "{}", err);
        assert!(err.contains("monux update"), "{}", err);
        assert!(proceeds(signature_gate(
            Signature::Unconfigured,
            Trust::Interactive
        )));

        // A configured key with a failing check refuses BOTH ways: an
        // explicit ask is consent to install an unsigned build, never
        // consent to install one whose signature is wrong.
        let err = refusal(signature_gate(rejected(), Trust::Unattended));
        assert!(err.contains("no tag at this commit"), "{}", err);
        let err = refusal(signature_gate(rejected(), Trust::Interactive));
        assert!(err.contains("Refusing to install"), "{}", err);
    }

    /// With no key compiled in, verification cannot conclude anything — and
    /// must say so rather than reporting a pass.
    #[test]
    fn verification_reports_unconfigured_without_a_key() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            verify_against_key(tmp.path(), "deadbeefdeadbeef", ""),
            Signature::Unconfigured
        );
        assert_eq!(
            verify_against_key(tmp.path(), "deadbeefdeadbeef", "   \n"),
            Signature::Unconfigured
        );
    }

    /// The shipped key must be a well-formed OpenSSH public key. A truncated
    /// or mangled paste would compile fine, make signing_configured() report
    /// true, and then reject every real release — discovered at the worst
    /// possible moment.
    #[test]
    fn the_shipped_release_key_is_well_formed() {
        if !signing_configured() {
            // No key yet: nothing to check, and the unattended path fails
            // closed anyway (see unattended_installs_fail_closed).
            return;
        }
        let key = RELEASE_SIGNING_KEY.trim();
        let mut fields = key.split_whitespace();
        let algo = fields.next().expect("a key type");
        let blob = fields.next().expect("a key body");
        assert!(
            algo.starts_with("ssh-") || algo.starts_with("ecdsa-") || algo.starts_with("sk-"),
            "unexpected key type {:?}: git's ssh signing wants an OpenSSH public key",
            algo
        );
        // The base64 body of an ed25519 public key is 68 chars; anything much
        // shorter is a truncated paste.
        assert!(
            blob.len() >= 40 && blob.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)),
            "the key body doesn't look like base64: {:?}",
            blob
        );
        assert!(
            !key.contains("PRIVATE"),
            "that is a PRIVATE key — only the .pub half belongs in the binary"
        );
    }

    /// Runs git in a test repo with ssh signing configured.
    fn sign_git(dir: &Path, key: &Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "gpg.format=ssh"])
            .arg("-c")
            .arg(format!("user.signingkey={}", key.display()))
            .args(args)
            .env("GIT_AUTHOR_NAME", "monux-test")
            .env("GIT_AUTHOR_EMAIL", "monux-test@example.com")
            .env("GIT_COMMITTER_NAME", "monux-test")
            .env("GIT_COMMITTER_EMAIL", "monux-test@example.com")
            .output()
            .unwrap()
    }

    /// Generates a throwaway ssh signing key, returning (private path, public key).
    fn throwaway_key(dir: &Path, name: &str) -> (PathBuf, String) {
        let path = dir.join(name);
        let out = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-C", "monux-test", "-f"])
            .arg(&path)
            .output()
            .expect("ssh-keygen must be available");
        assert!(out.status.success(), "ssh-keygen failed: {:?}", out);
        let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
        (path, public.trim().to_string())
    }

    /// The property the whole mechanism exists for: a release signed by the
    /// trusted key verifies, and one signed by ANY other key does not.
    ///
    /// Exercises the real git plumbing — a real repo, a real `git tag -s`, a
    /// real `git verify-tag` against a real allowed-signers file — because
    /// the interesting failure modes live there, not in our branching.
    #[test]
    fn only_a_tag_signed_by_the_trusted_key_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let keys = tmp.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        let (ours, our_public) = throwaway_key(&keys, "release");
        let (theirs, _their_public) = throwaway_key(&keys, "impostor");

        // A checkout with one commit, tagged and signed by OUR key.
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        test_repo(&repo);
        let sha = test_commit_version(&repo, "13.0.0");
        let out = sign_git(&repo, &ours, &["tag", "-s", "v13.0.0", "-m", "monux v13.0.0"]);
        assert!(out.status.success(), "signed tag failed: {:?}", out);

        match verify_against_key(&repo, &sha, &our_public) {
            Signature::Verified { tag } => assert_eq!(tag, "v13.0.0"),
            other => panic!("a tag signed by the trusted key must verify: {:?}", other),
        }

        // The same tag is worthless against a different trusted key — this is
        // the assertion that makes the whole feature mean anything.
        let (_, stranger) = throwaway_key(&keys, "stranger");
        match verify_against_key(&repo, &sha, &stranger) {
            Signature::Rejected { reason } => {
                assert!(reason.contains("valid monux release signature"), "{}", reason)
            }
            other => panic!("a foreign signature must be rejected: {:?}", other),
        }

        // A tag signed by an impostor at the same commit is rejected too: it
        // is the SIGNER that is checked, not the presence of a signature.
        let out = sign_git(&repo, &theirs, &["tag", "-s", "v13.0.1", "-m", "impostor"]);
        assert!(out.status.success(), "impostor tag failed: {:?}", out);
        match verify_against_key(&repo, &sha, &our_public) {
            // Our own valid tag is still there, so this commit still verifies —
            // the impostor tag simply doesn't help it.
            Signature::Verified { tag } => assert_eq!(tag, "v13.0.0"),
            other => panic!("the genuine tag should still carry it: {:?}", other),
        }
    }

    /// monux installs signed RELEASES, not whatever happens to be on master:
    /// an untagged commit is refused however healthy the repo is.
    #[test]
    fn an_untagged_commit_is_refused_even_with_a_key() {
        let tmp = tempfile::tempdir().unwrap();
        let (_ours, our_public) = throwaway_key(tmp.path(), "release");
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        test_repo(&repo);
        let sha = test_commit_version(&repo, "13.0.0");

        match verify_against_key(&repo, &sha, &our_public) {
            Signature::Rejected { reason } => {
                assert!(reason.contains("carries no tag"), "{}", reason)
            }
            other => panic!("an untagged commit must be refused: {:?}", other),
        }

        // An UNSIGNED tag is no better: the tag is the release marker, the
        // signature is the authority.
        let out = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["tag", "v13.0.0"])
            .output()
            .unwrap();
        assert!(out.status.success());
        match verify_against_key(&repo, &sha, &our_public) {
            Signature::Rejected { reason } => {
                assert!(reason.contains("valid monux release signature"), "{}", reason)
            }
            other => panic!("an unsigned tag must be refused: {:?}", other),
        }
    }

    /// An untagged commit is refused by name: monux installs releases, not
    /// whatever happens to be on master.
    #[test]
    fn an_untagged_commit_is_not_a_release() {
        // Exercised through the policy layer, since the git-facing half is
        // inert until a key is compiled in.
        let gate = signature_gate(
            Signature::Rejected {
                reason: "5b4c00e carries no tag — monux installs signed RELEASES, not whatever is on master".to_string(),
            },
            Trust::Unattended,
        );
        assert!(refusal(gate).contains("carries no tag"));
    }


    /// The listing parser, against the exact shapes git produces. Annotated
    /// tags appear twice and the PEELED entry is the commit — picking the tag
    /// object instead would hand a sha that isn't a commit to checkout.
    #[test]
    fn newest_release_tag_picks_the_peeled_commit_of_the_highest_version() {
        // Exactly what `git ls-remote --tags` printed for this repo.
        let listing = "\
c1818045d7dd57faf82009f43d41add05a9f42aa\trefs/tags/v13.0.0
24cd1b5b87fe94aa3187d06b31b5ab02eaf2bcc2\trefs/tags/v13.0.0^{}
b0f4d3fcb7fd0fef721612e385aab9119cdc1c9c\trefs/tags/v13.0.1
a462dcb3d1d479d13dd27e78a16a7592e7b60b31\trefs/tags/v13.0.1^{}
";
        assert_eq!(
            newest_release_tag(listing),
            Some((
                "v13.0.1".to_string(),
                "a462dcb3d1d479d13dd27e78a16a7592e7b60b31".to_string()
            ))
        );
        // `git show-ref --tags -d` says the same thing space-separated.
        assert_eq!(
            newest_release_tag(&listing.replace('\t', " ")),
            newest_release_tag(listing)
        );
    }

    #[test]
    fn release_tags_order_by_version_not_by_string() {
        // "v9.0.0" sorts after "v13.0.0" lexically; by version it does not.
        let listing = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/v9.0.0
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/v13.0.0
cccccccccccccccccccccccccccccccccccccccc\trefs/tags/v13.2.0
";
        let (tag, _) = newest_release_tag(listing).unwrap();
        assert_eq!(tag, "v13.2.0");
    }

    #[test]
    fn non_version_tags_and_empty_listings_are_ignored() {
        // A personal marker is not a release; monux releases are versions.
        let listing = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/nightly
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/before-the-rewrite
";
        assert_eq!(newest_release_tag(listing), None);
        assert_eq!(newest_release_tag(""), None);
        // A lightweight tag has no peeled entry; its own sha is the commit.
        let light = "dddddddddddddddddddddddddddddddddddddddd\trefs/tags/v1.2.3\n";
        assert_eq!(
            newest_release_tag(light),
            Some(("v1.2.3".to_string(), "dddddddddddddddddddddddddddddddddddddddd".to_string()))
        );
    }

    /// The regression this fixes: the daily check reported the branch HEAD
    /// while the install demanded a signed tag, so every push between
    /// releases announced an update that could never be installed.
    ///
    /// The two now answer the same question — asserted against a real repo
    /// with a tagged commit and untagged commits on top of it.
    #[test]
    fn the_check_and_the_install_agree_on_the_target() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        test_repo(&repo);
        let released = test_commit_version(&repo, "13.0.1");
        test_git(&repo, &["tag", "v13.0.1"]);
        // Work lands on master after the release — the situation that used to
        // produce a phantom "update available".
        let head = test_commit_version(&repo, "13.0.2");
        assert_ne!(head, released);

        // The local resolution (what run() checks out) picks the TAG, not HEAD.
        let (tag, sha) = newest_local_release(&repo).unwrap();
        assert_eq!(tag, "v13.0.1");
        assert_eq!(sha, released, "the install must target the release, not master");

        // ...and it tracks the next release once one is tagged.
        test_git(&repo, &["tag", "v13.0.2"]);
        let (tag, sha) = newest_local_release(&repo).unwrap();
        assert_eq!(tag, "v13.0.2");
        assert_eq!(sha, head);
    }

    #[test]
    fn a_repo_with_no_release_tag_reports_nothing_to_install() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        test_repo(&repo);
        test_commit_version(&repo, "13.0.0");
        // Untagged: an install has no signed release to aim at, and says so
        // rather than aiming at master and failing the signature check after
        // a full checkout.
        let err = newest_local_release(&repo).unwrap_err().to_string();
        assert!(err.contains("no release tag"), "{}", err);
    }

    #[test]
    fn parses_own_source_protocol_version() {
        // Guards the gate against repo layout drift: the parser must find the
        // constant this very binary was built with. The gate now reads
        // shared.rs out of a git object rather than the working tree (so it
        // can run before the checkout), but it is the same parser, and this
        // file is the one whose format it has to keep matching.
        let shared_rs = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("msgs")
            .join("shared.rs");
        let text = std::fs::read_to_string(&shared_rs).unwrap();
        assert_eq!(
            protocol_version_in(&text).unwrap(),
            crate::msgs::shared::PROTOCOL_VERSION
        );
    }

    #[test]
    fn server_protocol_constraint_roundtrip() {
        let dir =
            std::env::temp_dir().join(format!("monux-test-constraint-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Never connected: no constraint.
        assert_eq!(server_protocol_constraint(&dir), None);
        record_server_protocol_version(&dir, 7);
        assert_eq!(server_protocol_constraint(&dir), Some(7));
        // A later handshake overwrites (e.g. the server upgraded).
        record_server_protocol_version(&dir, 8);
        assert_eq!(server_protocol_constraint(&dir), Some(8));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn server_protocol_constraint_expires() {
        let dir =
            std::env::temp_dir().join(format!("monux-test-constraint-exp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        record_server_protocol_version(&dir, 9);
        // Fresh record: honored.
        assert_eq!(
            server_protocol_constraint_fresh(&dir, Duration::from_secs(60)),
            Some(9)
        );
        // A record not refreshed within the max age is ignored: this is what
        // lets a pure server (nothing rewrites its file) update again.
        assert_eq!(server_protocol_constraint_fresh(&dir, Duration::ZERO), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_protocol_constraint_removes_the_file() {
        let dir = std::env::temp_dir().join(format!(
            "monux-test-constraint-clear-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        record_server_protocol_version(&dir, 9);
        assert_eq!(server_protocol_constraint(&dir), Some(9));
        clear_protocol_constraint(&dir);
        assert_eq!(server_protocol_constraint(&dir), None);
        // Idempotent: a missing file is not an error.
        clear_protocol_constraint(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_with_prepends_the_dir_and_preserves_path() {
        let path = path_with(PathBuf::from("/tmp/monux-staging-bin"));
        let paths: Vec<PathBuf> = std::env::split_paths(&path).collect();
        assert_eq!(paths[0], PathBuf::from("/tmp/monux-staging-bin"));
        let original: Vec<PathBuf> =
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
        assert_eq!(&paths[1..], original.as_slice());
    }

    #[test]
    fn place_binary_atomically_replaces_the_target() {
        let dir =
            std::env::temp_dir().join(format!("monux-test-atomic-place-{}", std::process::id()));
        let staging = dir.join("staging");
        let bin = dir.join("root").join("bin");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let from = staging.join("monux");
        let to = bin.join("monux");
        std::fs::write(&from, b"new-binary").unwrap();
        std::fs::write(&to, b"old-binary").unwrap();
        place_binary_atomically(&from, &to).unwrap();
        // The target is replaced wholesale and the staged file is consumed.
        assert_eq!(std::fs::read(&to).unwrap(), b"new-binary");
        assert!(!from.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_lock_is_shared_by_sequential_runs() {
        let tmp = tempfile::tempdir().unwrap();
        // The lock sits next to the (not yet existing) source checkout.
        let src_dir = tmp.path().join("cache").join("monux").join("src");
        let lock_path = update_lock_path(&src_dir);
        // Two sequential runs (the second having waited for the first)
        // acquire and release the one shared lock file.
        {
            let _first = acquire_update_lock(&src_dir).unwrap();
        }
        let _second = acquire_update_lock(&src_dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        // World-writable, like the single-instance locks: a root-run daemon
        // and the user's own updater must both be able to take it.
        assert_eq!(mode, 0o666);
    }

    /// An mDNS observation may raise the update gate but never lower it below
    /// what an authenticated handshake recorded — the gate is both consulted
    /// and persisted, so a lowered value outlives whatever planted it.
    #[test]
    fn a_discovery_may_raise_the_update_gate_but_never_lower_it() {
        // Nothing recorded yet: whatever was discovered stands.
        assert_eq!(gate_floor(None, 15), 15);
        // A newer server on the LAN raises it.
        assert_eq!(gate_floor(Some(16), 17), 17);
        // The attack: an advertisement below the recorded value is refused.
        assert_eq!(gate_floor(Some(16), 15), 16);
        assert_eq!(gate_floor(Some(16), 16), 16);
    }

    #[test]
    fn cargo_toml_version_extraction() {
        assert_eq!(
            cargo_toml_version("[package]\nname = \"monux\"\nversion = \"9.1.0\"\n"),
            Some("9.1.0".to_string())
        );
        // Leading whitespace is fine; inline dependency versions don't match.
        let manifest = "# comment\n  version = \"1.2.3\"\n\n[dependencies]\nanyhow = \"1.0\"\n";
        assert_eq!(cargo_toml_version(manifest), Some("1.2.3".to_string()));
        assert_eq!(cargo_toml_version("[package]\nname = \"monux\"\n"), None);
    }

    #[test]
    fn protocol_version_in_parses_the_constant() {
        // PROTOCOL_VERSION_NEGOTIATION sorts first in shared.rs; the parser
        // must skip it.
        let text = "pub const PROTOCOL_VERSION_NEGOTIATION: u64 = 16;\npub const PROTOCOL_VERSION: u64 = 16;\n";
        assert_eq!(protocol_version_in(text).unwrap(), 16);
        assert!(protocol_version_in("nothing here").is_err());
    }

    #[test]
    fn looks_like_version_shapes() {
        assert!(looks_like_version("9.1.0"));
        assert!(looks_like_version("9.1"));
        assert!(!looks_like_version("9"));
        assert!(!looks_like_version("5b4c00e"));
        assert!(!looks_like_version("9abcdef0"));
    }

    #[test]
    fn update_pin_roundtrip_and_clear() {
        let dir = std::env::temp_dir().join(format!("monux-test-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(update_pin(&dir), None);
        // Clearing with no pin set is not an error and reports so.
        assert!(!clear_update_pin(&dir));
        write_update_pin(&dir, "9.0.0", "abcdef123456");
        assert_eq!(
            update_pin(&dir),
            Some(("9.0.0".to_string(), "abcdef123456".to_string()))
        );
        assert!(clear_update_pin(&dir));
        assert_eq!(update_pin(&dir), None);
        assert!(!clear_update_pin(&dir));
        // Garbled content reads as absent.
        std::fs::write(dir.join(UPDATE_PIN_FILE), "garbage\n").unwrap();
        assert_eq!(update_pin(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn previous_version_roundtrip() {
        let dir = std::env::temp_dir().join(format!("monux-test-prev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(previous_version(&dir), None);
        record_previous_version(&dir, "9.0.0", "0123456789ab");
        assert_eq!(
            previous_version(&dir),
            Some(("9.0.0".to_string(), "0123456789ab".to_string()))
        );
        // A later install overwrites the record.
        record_previous_version(&dir, "9.1.0", "abcdef012345");
        assert_eq!(
            previous_version(&dir),
            Some(("9.1.0".to_string(), "abcdef012345".to_string()))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn to_gate_refusals_are_direction_aware() {
        // Accepted pairs pass silently (pair_works semantics).
        assert!(check_to_gate("9.1.0", "aaaaaaaaaaaa", 16, 16).is_ok());
        assert!(check_to_gate("9.1.0", "aaaaaaaaaaaa", 17, 16).is_ok());
        // Downgrading to a pre-negotiation build against a v16 server.
        let err = check_to_gate("8.0.0", "bbbbbbbbbbbb", 15, 16)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Not downgrading to v8.0.0 (bbbbbbbbbbbb)"), "{}", err);
        assert!(err.contains("Downgrade the server first"), "{}", err);
        // Installing a newer build against a pre-negotiation server.
        let err = check_to_gate("9.0.0", "cccccccccccc", 16, 15)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Not updating to v9.0.0 (cccccccccccc)"), "{}", err);
        assert!(err.contains("Update the server first"), "{}", err);
    }

    /// Runs git in a test repo, failing the test on a non-zero exit.
    fn test_git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "monux-test")
            .env("GIT_AUTHOR_EMAIL", "monux-test@example.com")
            .env("GIT_COMMITTER_NAME", "monux-test")
            .env("GIT_COMMITTER_EMAIL", "monux-test@example.com")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// Commits a Cargo.toml declaring `version` into the repo, returning the
    /// commit sha.
    fn test_commit_version(dir: &Path, version: &str) -> String {
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"monux\"\nversion = \"{}\"\n", version),
        )
        .unwrap();
        test_git(dir, &["add", "Cargo.toml"]);
        test_git(dir, &["commit", "-m", &format!("v{}", version)]);
        test_git(dir, &["rev-parse", "HEAD"])
    }

    fn test_repo(dir: &Path) {
        test_git(dir, &["-c", "init.defaultBranch=master", "init"]);
    }

    /// The signature gate attests a COMMIT, so the build must consume that
    /// commit's objects — not the working tree, which the invoking user can
    /// still rewrite after the check passes (the updater runs as root under
    /// the documented `sudo -E monux server --auto-install`).
    #[test]
    fn the_export_takes_its_content_from_objects_not_the_working_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        test_repo(&repo);
        let sha = test_commit_version(&repo, "13.0.0");

        // Exactly the attack: the verified commit is checked out, and then the
        // working tree is tampered before the build reads it.
        std::fs::write(repo.join("Cargo.toml"), "pwned").unwrap();
        std::fs::write(repo.join("build.rs"), "fn main() { /* pwned */ }").unwrap();

        let dest = tmp.path().join("verified-src");
        export_verified_tree(&repo, &sha, &dest).unwrap();

        // The signed content, not what was on disk a moment ago.
        assert_eq!(
            std::fs::read_to_string(dest.join("Cargo.toml")).unwrap(),
            "[package]\nname = \"monux\"\nversion = \"13.0.0\"\n"
        );
        assert!(
            !dest.join("build.rs").exists(),
            "a file absent from the commit must not appear in the export"
        );
        // The intermediate tarball is not left behind next to the export.
        assert!(!dest.with_file_name("verified-src.tar").exists());
    }

    /// A force-pushed upstream (a rewritten or amended commit) leaves every
    /// checkout that fetched the old commits unable to fast-forward, which
    /// used to fail the update and keep failing until someone deleted the
    /// directory by hand. The checkout must resync onto the remote instead.
    #[test]
    fn a_force_pushed_remote_resyncs_instead_of_stranding_the_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let remote = tmp.path().join("remote");
        let checkout = tmp.path().join("checkout");
        std::fs::create_dir_all(&remote).unwrap();
        test_repo(&remote);
        test_commit_version(&remote, "1.0.0");
        // A non-bare remote can't take a push to its checked-out branch.
        test_git(&remote, &["config", "receive.denyCurrentBranch", "ignore"]);
        test_git(
            tmp.path(),
            &["clone", &remote.to_string_lossy(), &checkout.to_string_lossy()],
        );
        let old = test_git(&checkout, &["rev-parse", "HEAD"]);

        // Upstream rewrites that commit: same content, new sha.
        test_git(&remote, &["commit", "--amend", "-m", "v1.0.0 (reworded)"]);
        let rewritten = test_git(&remote, &["rev-parse", "HEAD"]);
        assert_ne!(old, rewritten);

        // The checkout now has a history the remote no longer has, so a
        // fast-forward pull is impossible — the state users were left in.
        test_git(&checkout, &["fetch"]);
        assert!(git(&checkout, &["pull", "--ff-only"]).is_err());

        resync_to_remote(&checkout).unwrap();

        assert_eq!(test_git(&checkout, &["rev-parse", "HEAD"]), rewritten);
        // And an ordinary pull works again afterwards.
        assert!(git(&checkout, &["pull", "--ff-only"]).is_ok());
    }

    #[test]
    fn resolve_target_by_version_and_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        test_repo(dir);
        let v1 = test_commit_version(dir, "1.0.0");
        let v2 = test_commit_version(dir, "1.1.0");
        // A commit that doesn't touch Cargo.toml: version resolution must
        // skip it; commit-prefix resolution must still find it.
        std::fs::write(dir.join("note.txt"), "x\n").unwrap();
        test_git(dir, &["add", "note.txt"]);
        test_git(dir, &["commit", "-m", "note"]);
        let other = test_git(dir, &["rev-parse", "HEAD"]);
        let v3 = test_commit_version(dir, "1.2.0");

        // By version (a v-prefix is accepted); the newest match wins.
        assert_eq!(resolve_target(dir, "1.1.0").unwrap(), v2);
        assert_eq!(resolve_target(dir, "v1.0.0").unwrap(), v1);
        assert_eq!(resolve_target(dir, "1.2.0").unwrap(), v3);
        // By commit prefix, including the commit without a version bump.
        assert_eq!(resolve_target(dir, &other[..8]).unwrap(), other);
        assert_eq!(resolve_target(dir, &v1[..8]).unwrap(), v1);
        // An unknown version names the recent versions in its error.
        let err = resolve_target(dir, "9.9.9").unwrap_err().to_string();
        assert!(err.contains("No version 9.9.9"), "{}", err);
        assert!(err.contains("1.2.0"), "{}", err);
        // An unknown commit prefix gets its own error.
        let err = resolve_target(dir, "deadbeefdeadbeef")
            .unwrap_err()
            .to_string();
        assert!(err.contains("No such commit"), "{}", err);
    }

    #[test]
    fn head_detached_detection() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        test_repo(dir);
        let v1 = test_commit_version(dir, "1.0.0");
        assert!(!head_is_detached(dir));
        // A '--to' install checks out a bare sha: detached.
        test_git(dir, &["checkout", &v1]);
        assert!(head_is_detached(dir));
        // A plain update reattaches to master.
        test_git(dir, &["checkout", "master"]);
        assert!(!head_is_detached(dir));
    }

    #[test]
    fn rewound_remote_is_not_newer() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        test_repo(dir);
        let v1 = test_commit_version(dir, "1.0.0");
        let v2 = test_commit_version(dir, "1.1.0");
        // Normal history: older commits are ancestors of HEAD (HEAD included).
        assert_eq!(is_ancestor_of_head(dir, &v1), Some(true));
        assert_eq!(is_ancestor_of_head(dir, &v2), Some(true));
        assert!(!is_rewound_remote(dir, &v2[..12]));
        // Rewind master to the older commit (a force-push): the commit our
        // build came from is no longer an ancestor of HEAD, so the differing
        // HEAD must be treated as not-newer (installing it would downgrade).
        test_git(dir, &["reset", "--hard", &v1]);
        assert_eq!(is_ancestor_of_head(dir, &v2), Some(false));
        assert!(is_rewound_remote(dir, &v2[..12]));
        assert!(!is_rewound_remote(dir, &v1[..12]));
        // A commit unknown to the checkout (e.g. beyond a shallow clone's
        // boundary) is undecidable and keeps the old behavior.
        assert_eq!(
            is_ancestor_of_head(dir, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            None
        );
        assert!(!is_rewound_remote(dir, "deadbeefdead"));
    }
}
