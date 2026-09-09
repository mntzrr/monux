//! macOS autostart for `monux setup --autostart`: a per-user LaunchAgent
//! starting monux at login. The Linux half lives in setup.rs (systemd user
//! units); this module shares its user-context resolution, atomic writes and
//! symlink guards, and its role-status rendering, so `--autostart
//! server|client|off|status` behaves identically on both platforms.
//!
//! Everything here is user-level like the Linux flag: no elevation, no root.
//! The plist lands in the invoking user's ~/Library/LaunchAgents, the daemon
//! is managed through launchctl's per-user `gui/<uid>` domain, and stdout/
//! stderr are captured under ~/Library/Logs/monux/ (the closest thing to the
//! journald capture the Linux unit gets for free).
//!
//! Mapping from the Linux unit:
//! - `Restart=on-failure` → `KeepAlive = { SuccessfulExit = false }`: a clean
//!   exit stays down, a crash is restarted
//! - `RestartSec=3` → `ThrottleInterval = 3`
//! - `WantedBy=default.target` + `After=graphical-session.target` → the
//!   LaunchAgent lifecycle itself: launchd runs it when the user logs into
//!   the GUI session
//! - `%h` in ExecStart → the absolute home path baked into ProgramArguments
//!   (launchd expands nothing)
//!
//! The server role is refused on macOS: input capture needs the Linux evdev
//! API, so a server agent here could only restart-loop at every login.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::setup::{
    atomic_write_no_follow, autostart_binary_warning, chown_best_effort,
    create_dir_all_tracked, ensure_no_symlink_components, render_role_status,
    resolve_invoking_user, Autostart, CmdSpec, Role, RoleStatus,
};

/// The LaunchAgent label prefix: labels are `<prefix>.<role>` and the plist
/// file name mirrors them (`sh.monux.client.plist`), the same label-equals-
/// file-stem convention Apple's own agents follow.
pub(crate) const LABEL_PREFIX: &str = "sh.monux";

/// Where per-user LaunchAgents live, relative to the user's home.
pub(crate) const LAUNCH_AGENTS_DIR: &str = "Library/LaunchAgents";

/// Where the agents' stdout/stderr logs go, relative to the user's home.
/// launchd creates the log FILES but not intermediate directories, so enable
/// creates this one.
pub(crate) const LOGS_DIR: &str = "Library/Logs/monux";

/// The tray indicator's LaunchAgent label. Not a daemon role: the tray is a
/// separate process (`monux gui indicator`) with its own agent, so it gets
/// its own label/plist paths.
pub(crate) const TRAY_LABEL: &str = "sh.monux.tray";

/// The tray agent's plist file name ("sh.monux.tray.plist").
pub(crate) fn tray_plist_name() -> String {
    format!("{}.plist", TRAY_LABEL)
}

/// The launchd job label for a role ("sh.monux.client").
pub(crate) fn label_for(role: Role) -> String {
    label_for_str(role.as_str())
}

/// The launchd job label for a role given as text, for callers (diagnostics)
/// that carry the role as a string.
pub(crate) fn label_for_str(role: &str) -> String {
    format!("{}.{}", LABEL_PREFIX, role)
}

/// The LaunchAgent plist file name for a role ("sh.monux.client.plist").
pub(crate) fn plist_name_for(role: Role) -> String {
    format!("{}.plist", label_for(role))
}

/// The LaunchAgents directory under a home.
pub(crate) fn agents_dir(home: &Path) -> PathBuf {
    home.join(LAUNCH_AGENTS_DIR)
}

/// The log directory under a home.
pub(crate) fn logs_dir(home: &Path) -> PathBuf {
    home.join(LOGS_DIR)
}

/// Escapes the five XML predefined entities. Paths (homes can contain `&` or
/// quotes) and the label end up inside the plist, which launchd parses as
/// XML — an unescaped `&` would silently break the whole agent.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
}

/// Content of the per-user LaunchAgent plist for a role. The client runs
/// without an address argument, so nothing machine-specific beyond the home
/// path is baked in (mDNS auto-discovery, like the Linux unit).
fn plist_content(role: Role, home: &Path) -> String {
    plist_document(
        &label_for(role),
        &[&home.join(".local/bin/monux").display().to_string(), role.as_str()],
        &format!("{}.log", role.as_str()),
        home,
    )
}

/// Content of the tray indicator's LaunchAgent plist: runs `monux gui
/// indicator`, kept alive on failure like the daemons (and NOT restarted
/// after a clean exit, so "Hide tray" persists until login or 'show').
fn tray_plist_content(home: &Path) -> String {
    plist_document(
        TRAY_LABEL,
        &[
            &home.join(".local/bin/monux").display().to_string(),
            "gui",
            "indicator",
        ],
        "tray.log",
        home,
    )
}

/// The plist XML shared by every monux agent: absolute binary path (launchd
/// expands nothing), start at login, restart on failure with a 3s throttle
/// (the launchd mapping of Restart=on-failure/RestartSec=3), output captured
/// under the monux logs dir.
fn plist_document(label: &str, program_arguments: &[&str], log_name: &str, home: &Path) -> String {
    let stdout = xml_escape(&logs_dir(home).join(log_name).display().to_string());
    let label = xml_escape(label);
    let arguments = program_arguments
        .iter()
        .map(|arg| format!("    <string>{}</string>", xml_escape(arg)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{arguments}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>3</integer>
  <key>StandardOutPath</key>
  <string>{stdout}</string>
  <key>StandardErrorPath</key>
  <string>{stdout}</string>
</dict>
</plist>
"#
    )
}

/// Who the LaunchAgent belongs to: the invoking user's home, the uid naming
/// their launchd GUI domain (`gui/<uid>`), and the uid/gid files should be
/// chowned to when setup somehow runs as root via sudo (None when
/// unprivileged). None itself: no invoking user (a bare root shell).
pub(crate) struct Target {
    home: PathBuf,
    uid: u32,
    owner: Option<(u32, u32)>,
}

/// Resolves the LaunchAgent target user. Autostart never elevates on macOS,
/// but `sudo monux setup --autostart client` must still land the agent in the
/// INVOKING user's home and gui domain — the same rule runuser implements on
/// the Linux side.
fn resolve_target() -> Result<Option<Target>> {
    let Some((home, owner)) = resolve_invoking_user()? else {
        return Ok(None);
    };
    let uid = owner.map(|(uid, _)| uid).unwrap_or_else(|| unsafe { libc::getuid() });
    Ok(Some(Target { home, uid, owner }))
}

/// Builds `launchctl` invocations targeting the user's GUI domain. Kept as a
/// struct mirroring setup.rs's Systemctl: every command is a CmdSpec, so the
/// tests can record and inspect them instead of touching real launchd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Launchctl {
    pub(crate) uid: u32,
}

impl Launchctl {
    pub(crate) fn spec(&self, args: &[&str]) -> CmdSpec {
        CmdSpec {
            program: "launchctl".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: vec![],
        }
    }

    /// The per-user GUI domain ("gui/501") bootstrap installs into.
    pub(crate) fn domain(&self) -> String {
        format!("gui/{}", self.uid)
    }

    /// The fully qualified service target ("gui/501/sh.monux.client") that
    /// print/bootout/kickstart address, for any label (daemons and tray).
    pub(crate) fn target(&self, label: &str) -> String {
        format!("gui/{}/{}", self.uid, label)
    }

    /// The service target of a daemon role.
    pub(crate) fn service_target(&self, role: Role) -> String {
        self.target(&label_for(role))
    }
}

/// Writes the plist atomically (see atomic_write_no_follow: idempotent, and
/// symlink-safe should the path be pre-seeded) and chowns what it creates
/// when running as root via sudo, so the file stays user-manageable.
fn write_plist_file(path: &Path, content: &str, owner: Option<(u32, u32)>) -> Result<()> {
    if let Some(parent) = path.parent() {
        // The symlink guard protects a ROOT-run install: setup would create
        // and chown directories inside a tree the invoking user controls, so
        // a planted symlink could divert both operations. The normal macOS
        // autostart run is unprivileged — a symlinked component in the
        // user's own tree is the user's own choice (launchd would follow it
        // too, and the atomic rename below never follows a final-component
        // link) — and this platform's $TMPDIR itself sits behind a symlink
        // (/var -> /private/var). So the guard is scoped to root runs.
        if owner.is_some() {
            ensure_no_symlink_components(parent)?;
        }
        let created = create_dir_all_tracked(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
        // Same check/act race as in write_unit_file: re-check after creating.
        if owner.is_some() {
            ensure_no_symlink_components(parent)?;
        }
        if let Some((uid, gid)) = owner {
            for dir in &created {
                chown_best_effort(dir, uid, gid);
            }
        }
    }
    atomic_write_no_follow(path, content)
        .with_context(|| format!("could not write {}", path.display()))?;
    if let Some((uid, gid)) = owner {
        chown_best_effort(path, uid, gid);
    }
    Ok(())
}

/// One manageable login agent: a daemon role or the tray indicator. Carries
/// everything the enable/disable/status paths need, rendered against a
/// target so tests can build tempdir-shaped ones.
struct Agent {
    /// Display name in the report and the log file stem ("client" logs to
    /// client.log).
    name: &'static str,
    /// launchd job label (== the plist file stem).
    label: String,
    plist_path: PathBuf,
    /// Full plist XML (content differs per agent).
    content: String,
    /// The single-instance lock kind a live instance of this agent holds
    /// ("server"/"client" daemons, "indicator" for the tray) — the status
    /// report cross-references it to tell an autostarted process from a
    /// manually started one.
    lock_kind: &'static str,
}

/// The daemon-role agent for a target.
fn agent_for(target: &Target, role: Role) -> Agent {
    Agent {
        name: role.as_str(),
        label: label_for(role),
        plist_path: agents_dir(&target.home).join(plist_name_for(role)),
        content: plist_content(role, &target.home),
        lock_kind: role.as_str(),
    }
}

/// The tray indicator agent for a target.
fn tray_agent(target: &Target) -> Agent {
    Agent {
        name: "tray",
        label: TRAY_LABEL.to_string(),
        plist_path: agents_dir(&target.home).join(tray_plist_name()),
        content: tray_plist_content(&target.home),
        // The tray takes the "indicator" single-instance lock, like the
        // Linux indicator does.
        lock_kind: "indicator",
    }
}

/// Every agent `--autostart off` removes and `status` reports on, in report
/// order.
fn all_agents(target: &Target) -> Vec<Agent> {
    vec![
        agent_for(target, Role::Server),
        agent_for(target, Role::Client),
        tray_agent(target),
    ]
}

/// Applies the `--autostart` choice: writes/removes the plists under the
/// target's LaunchAgents dir and runs the launchctl steps via `run`, probing
/// the current state through `probe` (the seams that keep tests off the real
/// launchd). No flag: no autostart changes at all.
fn apply_autostart(
    choice: Option<Autostart>,
    target: &Target,
    failures: &mut u32,
    probe: &dyn Fn(&CmdSpec) -> Result<String>,
    run: &mut dyn FnMut(&CmdSpec) -> Result<()>,
) {
    let choice = match choice {
        Some(c) => c,
        None => return,
    };
    match choice {
        Autostart::Server => {
            *failures += 1;
            println!(
                "[fail] autostart: the monux server captures input through the Linux evdev API and cannot run on macOS; use '--autostart client' instead"
            );
        }
        Autostart::Client => enable_agent(&agent_for(target, Role::Client), target, failures, probe, run),
        Autostart::Tray => enable_agent(&tray_agent(target), target, failures, probe, run),
        Autostart::Off => disable_all_agents(target, failures, probe, run),
        // setup_autostart intercepts Status before apply (it needs the
        // report, not the mutation runner).
        Autostart::Status => {}
    }
}

fn enable_agent(
    agent: &Agent,
    target: &Target,
    failures: &mut u32,
    probe: &dyn Fn(&CmdSpec) -> Result<String>,
    run: &mut dyn FnMut(&CmdSpec) -> Result<()>,
) {
    if let Some(warning) = autostart_binary_warning(&target.home) {
        println!("[warn] autostart: {}", warning);
    }
    if let Err(e) = write_plist_file(&agent.plist_path, &agent.content, target.owner) {
        *failures += 1;
        println!("[fail] autostart: {}", e);
        return;
    }
    println!("[done] autostart: wrote {}", agent.plist_path.display());
    // launchd opens StandardOutPath/StandardErrorPath itself but does not
    // create intermediate directories; a missing dir must not stop the agent.
    if let Err(e) = create_dir_all_tracked(&logs_dir(&target.home)) {
        println!(
            "[warn] autostart: could not create {} (the agent still runs; logs may be dropped): {}",
            logs_dir(&target.home).display(),
            e
        );
    }
    if let Some((uid, gid)) = target.owner {
        chown_best_effort(&logs_dir(&target.home), uid, gid);
    }

    let lc = Launchctl { uid: target.uid };
    let job = lc.target(&agent.label);
    let bootstrapped = match probe(&lc.spec(&["print", &job])) {
        // `launchctl print` answers a missing job with an empty stdout and a
        // non-zero exit (the probe ignores both and hands back the stdout).
        Ok(out) => !out.trim().is_empty(),
        Err(e) => {
            *failures += 1;
            println!("[fail] autostart: {}", e);
            println!("       Run this yourself in your session:");
            println!("       $ launchctl print {job}");
            return;
        }
    };
    if bootstrapped {
        // Mirror `systemctl enable --now` on an already-active unit: no
        // restart. The freshly written plist applies at the next restart.
        println!("[ok]   autostart: {job} is already bootstrapped; leaving it running as-is");
        println!("       Restart it into the new plist with: launchctl kickstart -k {job}");
    } else {
        let bootstrap = lc.spec(&["bootstrap", &lc.domain(), &agent.plist_path.display().to_string()]);
        if let Err(e) = run(&bootstrap) {
            *failures += 1;
            println!("[fail] autostart: {}", e);
            println!("       Run this yourself in your session:");
            println!("       $ {}", bootstrap.manual_line());
            return;
        }
        println!(
            "[done] autostart: {job} bootstrapped and started (LaunchAgent; starts at every login)"
        );
    }
    println!(
        "[note] autostart: {} logs to {}/{}.log; remove the agent any time with 'monux setup --autostart off'",
        agent.name, LOGS_DIR, agent.name
    );
}

fn disable_all_agents(
    target: &Target,
    failures: &mut u32,
    probe: &dyn Fn(&CmdSpec) -> Result<String>,
    run: &mut dyn FnMut(&CmdSpec) -> Result<()>,
) {
    let lc = Launchctl { uid: target.uid };
    for agent in all_agents(target) {
        let job = lc.target(&agent.label);
        // Best-effort: the job may not be bootstrapped. Probe first — booting
        // out an unloaded job would only have launchctl shout "No such
        // process" at our stderr — then boot out, and remove the plist
        // regardless of both.
        let bootstrapped = probe(&lc.spec(&["print", &job]))
            .map(|out| !out.trim().is_empty())
            .unwrap_or(false);
        if bootstrapped {
            let bootout = lc.spec(&["bootout", &job]);
            if let Err(e) = run(&bootout) {
                println!(
                    "[skip] autostart: could not boot out {job} ({}); removing the plist anyway",
                    e
                );
            }
        }
        match std::fs::remove_file(&agent.plist_path) {
            Ok(()) => println!("[done] autostart: removed {}", agent.plist_path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                *failures += 1;
                println!(
                    "[fail] autostart: could not remove {}: {}",
                    agent.plist_path.display(),
                    e
                );
            }
        }
    }
    println!("[done] autostart: monux LaunchAgents boot-strapped out and plists removed");
}

/// Parses `launchctl print` output into (state, pid). Only TOP-LEVEL keys
/// count — exactly one leading tab: nested structures (per-event spans etc.)
/// also carry `state =` lines two tabs deep, which say nothing about the job.
/// A `(undefined)` pid and unknown states parse as absent; the state is
/// unquoted (`"running"` and `running` both seen in the wild).
pub(crate) fn parse_print(out: &str) -> (Option<String>, Option<i32>) {
    let mut state = None;
    let mut pid = None;
    for line in out.lines() {
        let Some(rest) = line.strip_prefix('\t') else {
            continue;
        };
        if rest.starts_with('\t') || rest.starts_with(' ') {
            continue;
        }
        let rest = rest.trim_end();
        if let Some(value) = rest.strip_prefix("state = ") {
            if state.is_none() {
                state = Some(value.trim_matches('"').to_string());
            }
        } else if let Some(value) = rest.strip_prefix("pid = ") {
            if pid.is_none() {
                pid = value.trim().parse::<i32>().ok().filter(|pid| *pid > 0);
            }
        }
    }
    (state, pid)
}

/// Probes one agent for the status report: the plist (filesystem) and the
/// bootstrap/running state (`launchctl print`, through `probe`), plus the
/// single-instance lock (passed in, so the probe stays testable). A
/// launchctl that can't even spawn degrades to a note plus the file/lock
/// state.
fn probe_agent_status(
    agent: &Agent,
    target: &Target,
    probe: &dyn Fn(&CmdSpec) -> Result<String>,
    holder_pid: Option<i32>,
    notes: &mut Vec<String>,
) -> RoleStatus {
    let mut status = RoleStatus {
        installed: agent.plist_path.exists(),
        holder_pid,
        ..Default::default()
    };
    if !status.installed {
        return status;
    }
    let lc = Launchctl { uid: target.uid };
    let job = lc.target(&agent.label);
    let out = match probe(&lc.spec(&["print", &job])) {
        Ok(out) => out,
        Err(e) => {
            let note = format!(
                "could not query launchctl ({:#}); reporting the plist and the lock state only",
                e
            );
            if !notes.contains(&note) {
                notes.push(note);
            }
            return status;
        }
    };
    if out.trim().is_empty() {
        // Installed but not bootstrapped: like a disabled unit, it never runs.
        status.enabled = Some(false);
        status.active = Some(false);
        return status;
    }
    status.enabled = Some(true);
    let (state, pid) = parse_print(&out);
    status.active = state.as_deref().map(|s| s == "running");
    status.main_pid = pid;
    status
}

/// Renders a plist path with the user's home as `~` (the report is for
/// humans: ~/Library/LaunchAgents/sh.monux.client.plist reads better than the
/// absolute path). Falls back to the absolute path when the plist isn't under
/// the home it was resolved against.
fn display_plist_path(home: &Path, path: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => path.display().to_string(),
    }
}

/// The full `setup --autostart status` report: one line per agent (both
/// daemon roles and the tray), then the plist path of every installed agent,
/// then any degradation notes. Read-only: the only outside contact is the
/// filesystem, the read-only launchctl probe (through `probe`) and the
/// single-instance lock probe (`holder`).
fn autostart_status_report(
    target: &Target,
    probe: &dyn Fn(&CmdSpec) -> Result<String>,
    holder: &dyn Fn(&str) -> Option<i32>,
) -> String {
    let mut notes = Vec::new();
    let mut lines = Vec::new();
    let agents = all_agents(target);
    for agent in &agents {
        let status = probe_agent_status(agent, target, probe, holder(agent.lock_kind), &mut notes);
        lines.push(render_role_status(agent.name, &status));
    }
    for agent in &agents {
        if agent.plist_path.exists() {
            lines.push(format!(
                "agent: {}",
                display_plist_path(&target.home, &agent.plist_path)
            ));
        }
    }
    for note in notes {
        lines.push(format!("[note] autostart: {}", note));
    }
    lines.join("\n")
}

/// The `setup --autostart status` report, for embedding in a diagnostics
/// bundle (diagnostics.rs). Read-only and non-interactive, like the CLI
/// path it shares; None when there is no autostart target to report on (a
/// bare root shell), so the bundle can say "could not probe" rather than
/// inventing a state.
pub fn autostart_status_text() -> Option<String> {
    let target = resolve_target().ok().flatten()?;
    Some(autostart_status_report(
        &target,
        &|spec| spec.probe(),
        &|kind| crate::single_instance::live_holder(kind),
    ))
}

fn setup_autostart(choice: Option<Autostart>, failures: &mut u32) {
    let Some(choice) = choice else {
        // No flag: leave autostart untouched.
        return;
    };
    let target = match resolve_target() {
        Ok(Some(t)) => t,
        Ok(None) => {
            *failures += 1;
            println!("[fail] autostart: no invoking user found (LaunchAgents are per-user; run setup as your regular user, not from a root shell)");
            return;
        }
        Err(e) => {
            *failures += 1;
            println!("[fail] autostart: {}", e);
            return;
        }
    };
    // Status is read-only: it never mutates launchd state, so it uses an
    // output-capturing probe seam instead of the mutation runner.
    if choice == Autostart::Status {
        println!(
            "{}",
            autostart_status_report(
                &target,
                &|spec| spec.probe(),
                &|kind| crate::single_instance::live_holder(kind),
            )
        );
        return;
    }
    apply_autostart(
        Some(choice),
        &target,
        failures,
        &|spec| spec.probe(),
        &mut |spec| spec.run(),
    );
}

/// `monux gui tray show` on macOS: bring the tray agent back. Bootstraps it
/// when installed-but-unloaded (the state Hide leaves), kickstarts it when
/// already bootstrapped (restart re-runs RunAtLoad, showing the icon), and
/// points at `setup --autostart tray` when nothing is installed. Returns the
/// human-facing message.
pub fn tray_show() -> Result<String> {
    let target = resolve_target()?.context(
        "no invoking user found (LaunchAgents are per-user; run as your regular user, not root)",
    )?;
    let agent = tray_agent(&target);
    let lc = Launchctl { uid: target.uid };
    let job = lc.target(&agent.label);
    if !agent.plist_path.exists() {
        return Ok(
            "no tray agent installed — run 'monux setup --autostart tray' to get one that starts at every login (or run 'monux gui indicator' for this session)"
                .to_string(),
        );
    }
    let bootstrapped = lc
        .spec(&["print", &job])
        .probe()
        .map(|out| !out.trim().is_empty())
        .unwrap_or(false);
    let spec = if bootstrapped {
        lc.spec(&["kickstart", "-k", &job])
    } else {
        lc.spec(&["bootstrap", &lc.domain(), &agent.plist_path.display().to_string()])
    };
    spec.run().with_context(|| format!("failed to show {job}"))?;
    Ok(format!("{job} is running (tray visible)"))
}

/// `monux gui tray hide` on macOS: take the tray off the menu bar. Boots the
/// agent out when it is launchd-managed (an unload persists until login or
/// 'show' — unlike a crash, which the KeepAlive policy restarts), and points
/// at the tray's own menu row when a MANUALLY started tray is running
/// (launchd has no handle on it). Returns the human-facing message.
pub fn tray_hide() -> Result<String> {
    let target = resolve_target()?.context(
        "no invoking user found (LaunchAgents are per-user; run as your regular user, not root)",
    )?;
    let agent = tray_agent(&target);
    let lc = Launchctl { uid: target.uid };
    let job = lc.target(&agent.label);
    let bootstrapped = lc
        .spec(&["print", &job])
        .probe()
        .map(|out| !out.trim().is_empty())
        .unwrap_or(false);
    if bootstrapped {
        lc.spec(&["bootout", &job])
            .run()
            .with_context(|| format!("failed to hide {job}"))?;
        return Ok(format!("{job} hidden (until login or 'monux gui tray show')"));
    }
    // Not launchd-managed: a manually started standalone tray may still be
    // on the menu bar — report honestly instead of claiming a hide.
    match crate::single_instance::live_holder(agent.lock_kind) {
        Some(pid) => Ok(format!(
            "a manually started tray is running (pid {pid}); hide it from its own 'Hide tray' menu row"
        )),
        None => Ok("the tray is not running".to_string()),
    }
}

pub fn run(autostart: Option<Autostart>, desktop_shortcut: bool) -> Result<()> {
    // macOS setup never elevates: the Linux base set (udev, sysctl, QoS
    // marking) does not exist here, and LaunchAgents are per-user files in
    // the invoking user's home.
    if autostart.is_none() && !desktop_shortcut {
        println!("[skip] base tuning: the optimization set (uinput permissions, WiFi power saving, UDP socket buffers, DSCP QoS marking) is Linux-specific; there is nothing to persist on macOS");
        println!("       Use 'monux setup --autostart client' to install the login service.");
        return Ok(());
    }
    let mut failures = 0;
    setup_autostart(autostart, &mut failures);
    if desktop_shortcut {
        println!("[skip] desktop shortcut: .desktop entries are a Linux desktop concept; on macOS, launch 'monux gui tray show' manually or add it to Login Items in System Settings");
    }

    // A status report changes nothing: no summary footer.
    if autostart == Some(Autostart::Status) && !desktop_shortcut {
        return Ok(());
    }

    println!();
    if failures > 0 {
        println!("Done with {} failed step(s); see messages above.", failures);
    } else {
        println!("All done. Undo any of this with 'monux setup --autostart off'.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;

    #[test]
    fn labels_and_plist_names_follow_the_role() {
        assert_eq!(label_for(Role::Client), "sh.monux.client");
        assert_eq!(label_for(Role::Server), "sh.monux.server");
        assert_eq!(plist_name_for(Role::Client), "sh.monux.client.plist");
        assert_eq!(plist_name_for(Role::Server), "sh.monux.server.plist");
        assert_eq!(
            agents_dir(Path::new("/Users/x")),
            PathBuf::from("/Users/x/Library/LaunchAgents")
        );
    }

    #[test]
    fn plist_content_points_at_home_bin_and_auto_discovers() {
        let content = plist_content(Role::Client, Path::new("/Users/x"));
        // Label and file conventions.
        assert!(content.contains("<string>sh.monux.client</string>"), "{}", content);
        // The binary path is absolute (launchd expands nothing).
        assert!(content.contains("<string>/Users/x/.local/bin/monux</string>"), "{}", content);
        // Client with no address argument = mDNS auto-discovery: nothing
        // machine-specific beyond the home path may be baked in.
        assert!(content.contains("<string>client</string>"), "{}", content);
        assert!(!content.contains("client "), "{}", content);
        // Start at login, keep alive on failure only, 3s throttle: the
        // launchd mapping of Restart=on-failure/RestartSec=3.
        assert!(content.contains("<key>RunAtLoad</key>\n  <true/>"), "{}", content);
        assert!(content.contains("<key>SuccessfulExit</key>\n    <false/>"), "{}", content);
        assert!(content.contains("<integer>3</integer>"), "{}", content);
        // Logs captured under the monux logs dir.
        assert!(content.contains("/Users/x/Library/Logs/monux/client.log"), "{}", content);
    }

    #[test]
    fn plist_content_escapes_xml_entities_in_paths() {
        let content = plist_content(Role::Client, Path::new("/Users/a&b'c\"d<e>"));
        assert!(content.contains("/Users/a&amp;b&apos;c&quot;d&lt;e&gt;/.local/bin/monux"), "{}", content);
        assert!(!content.contains("a&b'c\"d<e>"), "{}", content);
    }

    #[test]
    fn launchctl_specs_target_the_users_gui_domain() {
        let lc = Launchctl { uid: 501 };
        assert_eq!(lc.spec(&["print", "gui/501/sh.monux.client"]), CmdSpec {
            program: "launchctl".to_string(),
            args: vec!["print".to_string(), "gui/501/sh.monux.client".to_string()],
            env: vec![],
        });
        assert_eq!(lc.domain(), "gui/501");
        assert_eq!(lc.service_target(Role::Client), "gui/501/sh.monux.client");
    }

    /// A target rooted at a tempdir home, managing the current user directly.
    fn test_target(dir: &Path) -> Target {
        Target {
            home: dir.to_path_buf(),
            uid: 501,
            owner: None,
        }
    }

    /// The shared log a recording executor/probe appends to.
    type Recorded = std::rc::Rc<std::cell::RefCell<Vec<CmdSpec>>>;

    fn recording_executor() -> (Recorded, impl FnMut(&CmdSpec) -> Result<()>) {
        let recorded: Recorded = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let rec = recorded.clone();
        let run = move |spec: &CmdSpec| -> Result<()> {
            rec.borrow_mut().push(spec.clone());
            Ok(())
        };
        (recorded, run)
    }

    #[test]
    fn autostart_client_writes_plist_and_bootstraps() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let (recorded, mut run) = recording_executor();
        // Nothing bootstrapped yet: the probe sees an empty stdout.
        let mut failures = 0;
        apply_autostart(Some(Autostart::Client), &target, &mut failures, &|_| Ok(String::new()), &mut run);
        assert_eq!(failures, 0);
        // Plist written with the expected content...
        let content = std::fs::read_to_string(
            tmp.path().join("Library/LaunchAgents/sh.monux.client.plist"),
        )
        .unwrap();
        assert_eq!(content, plist_content(Role::Client, tmp.path()));
        // ...the logs dir exists (launchd needs it to capture output)...
        assert!(tmp.path().join("Library/Logs/monux").is_dir());
        // ...and print-probe precedes bootstrap, in order.
        let cmds = recorded.borrow();
        assert_eq!(cmds.len(), 1);
        assert_eq!(
            cmds[0],
            Launchctl { uid: 501 }.spec(&["bootstrap", "gui/501", &tmp.path().join("Library/LaunchAgents/sh.monux.client.plist").display().to_string()])
        );
    }

    #[test]
    fn autostart_when_already_bootstrapped_does_not_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let (recorded, mut run) = recording_executor();
        // The probe answers like a bootstrapped job (non-empty print dump).
        let mut failures = 0;
        apply_autostart(Some(Autostart::Client), &target, &mut failures, &|_| Ok("\tstate = running\n\tpid = 42\n".to_string()), &mut run);
        assert_eq!(failures, 0);
        // Only the probe ran (through the probe seam): no bootstrap, no
        // kickstart — `enable --now` on an active job doesn't restart either.
        assert!(recorded.borrow().is_empty());
    }

    #[test]
    fn autostart_server_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let mut failures = 0;
        let mut run = |_: &CmdSpec| -> Result<()> {
            panic!("no launchctl commands may run for a refused role")
        };
        apply_autostart(Some(Autostart::Server), &target, &mut failures, &|_| Ok(String::new()), &mut run);
        assert_eq!(failures, 1);
        // Nothing was installed.
        assert!(!tmp.path().join("Library/LaunchAgents").exists());
    }

    #[test]
    fn autostart_off_boots_out_and_removes() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let agents = all_agents(&target);
        std::fs::create_dir_all(tmp.path().join("Library/LaunchAgents")).unwrap();
        for agent in &agents {
            std::fs::write(&agent.plist_path, &agent.content).unwrap();
        }
        let (recorded, mut run) = recording_executor();
        let mut failures = 0;
        // All three jobs answer their print probe: bootstrapped, so each one
        // gets booted out before its plist is removed.
        apply_autostart(
            Some(Autostart::Off),
            &target,
            &mut failures,
            &|_| Ok("\tstate = running\n".to_string()),
            &mut run,
        );
        assert_eq!(failures, 0);
        // Every plist removed — both daemon roles AND the tray...
        for agent in &agents {
            assert!(!agent.plist_path.exists(), "{}", agent.plist_path.display());
        }
        // ...after booting every job out, in report order.
        let cmds = recorded.borrow();
        assert_eq!(
            *cmds,
            vec![
                Launchctl { uid: 501 }.spec(&["bootout", "gui/501/sh.monux.server"]),
                Launchctl { uid: 501 }.spec(&["bootout", "gui/501/sh.monux.client"]),
                Launchctl { uid: 501 }.spec(&["bootout", "gui/501/sh.monux.tray"]),
            ]
        );
    }

    #[test]
    fn autostart_tray_writes_the_tray_plist_and_bootstraps() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let (recorded, mut run) = recording_executor();
        let mut failures = 0;
        apply_autostart(Some(Autostart::Tray), &target, &mut failures, &|_| Ok(String::new()), &mut run);
        assert_eq!(failures, 0);
        // The tray plist runs the indicator, not a daemon role.
        let content = std::fs::read_to_string(
            tmp.path().join("Library/LaunchAgents/sh.monux.tray.plist"),
        )
        .unwrap();
        assert_eq!(content, tray_plist_content(tmp.path()));
        assert!(content.contains("<string>gui</string>"), "{}", content);
        assert!(content.contains("<string>indicator</string>"), "{}", content);
        assert!(content.contains("<string>sh.monux.tray</string>"), "{}", content);
        assert!(content.contains("tray.log"), "{}", content);
        // Bootstrap targeted the tray's job.
        let cmds = recorded.borrow();
        assert_eq!(
            cmds[0],
            Launchctl { uid: 501 }.spec(&["bootstrap", "gui/501", &tmp.path().join("Library/LaunchAgents/sh.monux.tray.plist").display().to_string()])
        );
    }

    #[test]
    fn autostart_none_changes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        std::fs::create_dir_all(tmp.path().join("Library/LaunchAgents")).unwrap();
        std::fs::write(tmp.path().join("Library/LaunchAgents/keep.plist"), "keep me").unwrap();
        let mut failures = 0;
        let probe = |_: &CmdSpec| -> Result<String> {
            panic!("no launchctl probes may run without --autostart")
        };
        let mut run = |_: &CmdSpec| -> Result<()> {
            panic!("no launchctl commands may run without --autostart")
        };
        apply_autostart(None, &target, &mut failures, &probe, &mut run);
        assert_eq!(failures, 0);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("Library/LaunchAgents/keep.plist")).unwrap(),
            "keep me"
        );
    }

    #[test]
    fn autostart_bootstrap_failure_counts_and_prints_the_manual_line() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let mut failures = 0;
        let mut run = |_: &CmdSpec| -> Result<()> { bail!("no launchd here") };
        apply_autostart(Some(Autostart::Client), &target, &mut failures, &|_| Ok(String::new()), &mut run);
        assert_eq!(failures, 1);
        // The plist was still written, so the printed manual command works.
        assert!(tmp.path().join("Library/LaunchAgents/sh.monux.client.plist").exists());
    }

    #[test]
    fn plist_write_replaces_a_symlink_without_following_it() {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        let plist_path = agents.join(plist_name_for(Role::Client));
        // A pre-placed symlink at the plist path: the write (possibly running
        // as root) must replace the link, never clobber its target.
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::write(&elsewhere, "precious").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &plist_path).unwrap();
        let content = plist_content(Role::Client, tmp.path());
        write_plist_file(&plist_path, &content, None).unwrap();
        let meta = std::fs::symlink_metadata(&plist_path).unwrap();
        assert!(!meta.file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&plist_path).unwrap(), content);
        // The symlink's old target is untouched.
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "precious");
    }

    #[test]
    fn print_parsing_reads_top_level_state_and_pid_only() {
        let sample = "gui/501/sh.monux.client = {\n\tactive count = 1\n\tpath = /Users/x/Library/LaunchAgents/sh.monux.client.plist\n\ttype = LaunchAgent\n\tstate = running\n\n\tprogram = /Users/x/.local/bin/monux\n\tpid = 817\n\tlast exit code = (never exited)\n\n\tevents = [{\n\t\tstate = active\n\t\tstate = active\n\t}]\n}";
        let (state, pid) = parse_print(sample);
        assert_eq!(state.as_deref(), Some("running"));
        assert_eq!(pid, Some(817));
        // A loaded but idle job: no top-level pid (or a (undefined) one).
        let (state, pid) = parse_print("\tstate = spawn scheduled\n\tpid = (undefined)\n");
        assert_eq!(state.as_deref(), Some("spawn scheduled"));
        assert_eq!(pid, None);
        // Quoted state values (seen on some versions) parse the same.
        let (state, _) = parse_print("\tstate = \"not running\"\n");
        assert_eq!(state.as_deref(), Some("not running"));
        // Nonsense: nothing parseable.
        assert_eq!(parse_print(""), (None, None));
        assert_eq!(parse_print("garbage"), (None, None));
    }

    #[test]
    fn role_status_probes_plist_then_launchctl() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let agents = tmp.path().join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        std::fs::write(agents.join(plist_name_for(Role::Client)), "plist").unwrap();

        let agent = agent_for(&target, Role::Client);
        let mut notes = Vec::new();
        // Not bootstrapped: empty stdout means the job isn't in the domain.
        let status = probe_agent_status(&agent, &target, &|_| Ok(String::new()), None, &mut notes);
        assert!(status.installed);
        assert_eq!(status.enabled, Some(false));
        assert_eq!(status.active, Some(false));
        assert!(notes.is_empty());

        // Bootstrapped and running.
        let status = probe_agent_status(
            &agent,
            &target,
            &|_| Ok("\tstate = running\n\tpid = 817\n".to_string()),
            None,
            &mut notes,
        );
        assert_eq!(status.enabled, Some(true));
        assert_eq!(status.active, Some(true));
        assert_eq!(status.main_pid, Some(817));

        // Bootstrapped but not running (crashed backoff, load-on-demand).
        let status = probe_agent_status(
            &agent,
            &target,
            &|_| Ok("\tstate = spawn scheduled\n".to_string()),
            None,
            &mut notes,
        );
        assert_eq!(status.enabled, Some(true));
        assert_eq!(status.active, Some(false));
        assert_eq!(status.main_pid, None);
    }

    #[test]
    fn role_status_degrades_when_launchctl_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let agents = tmp.path().join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        std::fs::write(agents.join(plist_name_for(Role::Client)), "plist").unwrap();

        let agent = agent_for(&target, Role::Client);
        let mut notes = Vec::new();
        let status = probe_agent_status(&agent, &target, &|_| bail!("launchctl not found"), None, &mut notes);
        // The plist and lock state still speak, with a note for the rest.
        assert!(status.installed);
        assert_eq!(status.enabled, None);
        assert_eq!(status.active, None);
        assert_eq!(
            notes,
            vec!["could not query launchctl (launchctl not found); reporting the plist and the lock state only".to_string()]
        );
    }

    #[test]
    fn status_report_installed_running_client_only() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let agents = tmp.path().join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        std::fs::write(agents.join(plist_name_for(Role::Client)), "plist").unwrap();
        // Fabricated launchctl: the client job is bootstrapped and running.
        let probe = |spec: &CmdSpec| -> Result<String> {
            assert_eq!(spec.manual_line(), "launchctl print gui/501/sh.monux.client");
            Ok("\tstate = running\n\tpid = 817\n".to_string())
        };
        // The lock probe: a live client daemon (the job's pid), nothing else.
        let holder = |kind: &str| match kind {
            "client" => Some(817),
            _ => None,
        };
        let report = autostart_status_report(&target, &probe, &holder);
        let expected = [
            "server: not installed",
            "client: installed, enabled, active (pid 817) — running (autostarted)",
            "tray: not installed",
            "agent: ~/Library/LaunchAgents/sh.monux.client.plist",
        ]
        .join("\n");
        assert_eq!(report, expected);
        // The golden report, for eyeballing with --nocapture.
        println!("{}", report);
    }

    #[test]
    fn status_report_no_agents_at_all() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let probe = |spec: &CmdSpec| -> Result<String> {
            panic!("unexpected probe: {}", spec.manual_line())
        };
        let holder = |_: &str| None;
        let report = autostart_status_report(&target, &probe, &holder);
        assert_eq!(
            report,
            "server: not installed\nclient: not installed\ntray: not installed"
        );
    }

    #[test]
    fn display_plist_path_uses_tilde_under_home() {
        let home = Path::new("/Users/x");
        assert_eq!(
            display_plist_path(home, &agents_dir(home).join(plist_name_for(Role::Client))),
            "~/Library/LaunchAgents/sh.monux.client.plist"
        );
        // A plist NOT under the home falls back to the absolute path.
        let plain = Path::new("/tmp/x/sh.monux.client.plist");
        assert_eq!(display_plist_path(home, plain), "/tmp/x/sh.monux.client.plist");
    }
}
