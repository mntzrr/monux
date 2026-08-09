//! `monux setup`: persists machine-local settings that optimize the host for
//! local KVM use. Everything here is idempotent and reported step by step.
//! No flags applies the full base set below; ANY flag scopes the run to that
//! flag's actions only.
//!
//! The base set:
//! - `input` group membership for the invoking user (input device access
//!   without running monux as root; takes effect on next login)
//! - a udev rule making /dev/uinput accessible to the `input` group (only if
//!   the current permissions are insufficient)
//! - the uinput kernel module loaded and persisted, if /dev/uinput is missing
//! - WiFi power saving disabled persistently via NetworkManager, and applied
//!   immediately to current wireless interfaces (power saving buffers packets
//!   and causes 60-300ms latency spikes, felt as stutter)
//! - raised net.core.rmem_max/wmem_max so the QUIC UDP socket buffers aren't
//!   silently clamped to the stock ~208 KiB (clamped buffers drop packets
//!   during clipboard bursts)
//! - DSCP CS6 netfilter marking of monux's UDP traffic (the AP/router hop
//!   picks its downlink queue from each packet's DSCP; quinn overwrites the
//!   TOS byte per packet, so only netfilter can set it)
//!
//! The flag-scoped actions:
//! - with `--autostart`, a per-user systemd service starting monux with the
//!   graphical session (the only action that does NOT need root; it manages
//!   the invoking user's own systemd units)
//! - with `--desktop-shortcut`, a per-user app-menu entry launching
//!   `monux gui tray show` (also user-level: it manages the invoking user's
//!   own data home)

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

pub(crate) const NM_POWERSAVE_CONF_PATH: &str =
    "/etc/NetworkManager/conf.d/99-monux-disable-wifi-powersave.conf";
pub(crate) const UDEV_RULE_PATH: &str = "/etc/udev/rules.d/99-monux-uinput.rules";
pub(crate) const MODULES_LOAD_PATH: &str = "/etc/modules-load.d/monux-uinput.conf";
pub(crate) const SYSCTL_BUF_CONF_PATH: &str = "/etc/sysctl.d/90-monux-udp-buffers.conf";

/// Where per-user systemd units live, relative to the target user's home.
pub(crate) const SYSTEMD_USER_UNIT_DIR: &str = ".config/systemd/user";

/// `--autostart` for `monux setup`: manage a per-user systemd service
/// that starts monux with the graphical session. When the flag is omitted, no
/// autostart changes are made.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Autostart {
    /// Write and enable+start monux-server.service.
    Server,
    /// Write and enable+start monux-client.service (mDNS auto-discovery).
    Client,
    /// Disable and remove both services.
    Off,
    /// Print a read-only status report for both services (installed? enabled?
    /// running — autostarted or manually?) and change nothing.
    Status,
}

/// The roles a service unit can run (`off` maps to no role).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Server,
    Client,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Server => "server",
            Role::Client => "client",
        }
    }

    fn unit_name(self) -> String {
        unit_name_for(self.as_str())
    }
}

/// The systemd user unit file name for a daemon role ("server"/"client").
pub(crate) fn unit_name_for(role: &str) -> String {
    format!("monux-{}.service", role)
}

/// Content of the per-user systemd unit for a role. `%h` expands to the
/// user's home at unit load time. `monux client` without an address argument
/// uses mDNS auto-discovery, so no server IP is baked into the unit.
fn unit_content(role: Role) -> String {
    let role = role.as_str();
    format!(
        "[Unit]\nDescription=monux KVM {role}\nAfter=graphical-session.target\n\n[Service]\nExecStart=%h/.local/bin/monux {role}\nRestart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n"
    )
}

/// A command to spawn, in test-inspectable form.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CmdSpec {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
}

impl CmdSpec {
    fn run(&self) -> Result<()> {
        let status = Command::new(&self.program)
            .args(&self.args)
            .envs(self.env.iter().cloned())
            .stdin(std::process::Stdio::null())
            .status()
            .with_context(|| format!("Failed to run {}: is it installed?", self.program))?;
        if !status.success() {
            bail!(
                "{} {} exited with {}",
                self.program,
                self.args.join(" "),
                status
            );
        }
        Ok(())
    }

    /// Runs the command and returns stdout REGARDLESS of exit status — for
    /// read-only status probes, whose answer may come with a non-zero exit
    /// (`systemctl is-enabled` answers "disabled" with exit 1). Only a spawn
    /// failure (the program is absent) is an error.
    fn probe(&self) -> Result<String> {
        let output = Command::new(&self.program)
            .args(&self.args)
            .envs(self.env.iter().cloned())
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .with_context(|| format!("Failed to run {}: is it installed?", self.program))?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// The equivalent command for the user to run in their own session: for a
    /// runuser-wrapped invocation that's the inner command (the session
    /// environment is already right there).
    fn manual_line(&self) -> String {
        match self.args.iter().position(|a| a == "--") {
            Some(pos) if self.program == "runuser" => self.args[pos + 1..].join(" "),
            _ => std::iter::once(self.program.as_str())
                .chain(self.args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" "),
        }
    }
}

/// A user to run `systemctl --user` as, when setup runs as root via sudo.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UserCtx {
    name: String,
    uid: u32,
}

/// Builds `systemctl --user` invocations for the autostart target user: plain
/// when running as that user, or wrapped in `runuser` with the session
/// environment pointed at the user's runtime dir when running as root.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Systemctl {
    user: Option<UserCtx>,
}

impl Systemctl {
    fn spec(&self, args: &[&str]) -> CmdSpec {
        let mut full: Vec<String> = std::iter::once("--user".to_string())
            .chain(args.iter().map(|s| s.to_string()))
            .collect();
        match &self.user {
            None => CmdSpec {
                program: "systemctl".to_string(),
                args: full,
                env: vec![],
            },
            Some(user) => {
                let mut wrapped = vec![
                    "-u".to_string(),
                    user.name.clone(),
                    "--".to_string(),
                    "systemctl".to_string(),
                ];
                wrapped.append(&mut full);
                let runtime_dir = format!("/run/user/{}", user.uid);
                CmdSpec {
                    program: "runuser".to_string(),
                    args: wrapped,
                    env: vec![
                        ("XDG_RUNTIME_DIR".to_string(), runtime_dir.clone()),
                        (
                            "DBUS_SESSION_BUS_ADDRESS".to_string(),
                            format!("unix:path={}/bus", runtime_dir),
                        ),
                    ],
                }
            }
        }
    }
}

/// Who the autostart service belongs to. Setup normally runs as root via
/// `sudo -E`: the unit must land in the INVOKING user's home and be managed
/// through their user manager, not root's.
struct AutostartTarget {
    unit_dir: PathBuf,
    systemctl: Systemctl,
    /// uid/gid the unit file (and directories we create) is chowned to, so a
    /// root-written file stays user-manageable.
    owner: Option<(u32, u32)>,
}

/// Looks up a user's home directory and uid/gid (getpwnam_r(3)).
///
/// The _r form, not plain getpwnam: the latter returns a pointer into a
/// static buffer that any concurrent lookup in the process may overwrite, so
/// its soundness would rest on a global "nothing else calls this right now"
/// property rather than on anything checkable here. With a caller-owned
/// buffer the result is ours alone.
pub(crate) fn passwd_entry(name: &str) -> Result<(PathBuf, u32, u32)> {
    use std::os::unix::ffi::OsStrExt;
    let cname = std::ffi::CString::new(name).context("Invalid user name")?;
    // sysconf's suggested size, with a floor for systems that don't answer
    // and a ceiling so a hostile value can't ask for an unbounded allocation.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut cap = if suggested > 0 { suggested as usize } else { 1024 };
    loop {
        // libc::c_char, not i8: it is u8 on aarch64, where a hardcoded i8
        // wouldn't compile.
        let mut buf = vec![0 as libc::c_char; cap];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: pwd and buf outlive the call and are exclusively ours;
        // getpwnam_r writes the entry into pwd, its strings into buf, and
        // sets result to &pwd on success or NULL when there is no such user.
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                cap,
                &mut result,
            )
        };
        if rc == libc::ERANGE && cap < 1024 * 1024 {
            // The entry didn't fit; retry with a bigger buffer.
            cap *= 2;
            continue;
        }
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc))
                .with_context(|| format!("Failed to look up user '{}'", name));
        }
        if result.is_null() {
            bail!("User '{}' not found", name);
        }
        // SAFETY: rc == 0 and result is non-null, so pwd is fully populated
        // and its string pointers point into buf, which is still alive.
        let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
        return Ok((
            PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())),
            pwd.pw_uid,
            pwd.pw_gid,
        ));
    }
}

/// Where a per-user install goes: the invoking user's home dir, plus the
/// uid/gid the files should be chowned to when setup runs as root via sudo
/// (None when unprivileged — the files are ours anyway).
type InvokingUser = (PathBuf, Option<(u32, u32)>);

/// Resolves the invoking user's home dir, plus the uid/gid user-visible
/// files should be chowned to when setup runs as root via sudo (None when
/// unprivileged: files are ours anyway). Returns Ok(None) when there is no
/// sensible target: running as root directly (root's home is not the one a
/// desktop session uses, and these installs are per-user). Shared by the
/// autostart and the desktop-shortcut targets.
fn resolve_invoking_user() -> Result<Option<InvokingUser>> {
    let sudo_user = std::env::var("SUDO_USER").unwrap_or_default();
    if unsafe { libc::geteuid() } == 0 {
        if sudo_user.is_empty() || sudo_user == "root" {
            return Ok(None);
        }
        let (home, uid, gid) = passwd_entry(&sudo_user)?;
        Ok(Some((home, Some((uid, gid)))))
    } else {
        // Unprivileged (e.g. experiments): manage the current user's own
        // files directly.
        let home = home::home_dir().context("No home dir found")?;
        Ok(Some((home, None)))
    }
}

/// Resolves the autostart target user (see resolve_invoking_user).
fn resolve_autostart_target() -> Result<Option<AutostartTarget>> {
    let sudo_user = std::env::var("SUDO_USER").unwrap_or_default();
    let Some((home, owner)) = resolve_invoking_user()? else {
        return Ok(None);
    };
    Ok(Some(AutostartTarget {
        unit_dir: home.join(SYSTEMD_USER_UNIT_DIR),
        systemctl: Systemctl {
            user: owner.map(|(uid, _)| UserCtx {
                    name: sudo_user,
                    uid,
                }),
        },
        owner,
    }))
}

/// Best-effort chown (used so root-written files stay user-manageable).
fn chown_best_effort(path: &Path, uid: u32, gid: u32) {
    use std::os::unix::ffi::OsStrExt;
    let cpath = match std::ffi::CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return,
    };
    unsafe {
        libc::chown(cpath.as_ptr(), uid, gid);
    }
}

fn write_unit_file(path: &Path, role: Role, owner: Option<(u32, u32)>) -> Result<()> {
    if let Some(parent) = path.parent() {
        // ~/.config may not exist yet; note it BEFORE create_dir_all creates
        // it, so we chown only a ~/.config we created ourselves — never a
        // pre-existing one (that directory isn't ours to touch).
        let config_dir = parent.parent().and_then(|p| p.parent());
        let config_dir_existed = config_dir.map(|dir| dir.exists());
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
        // Directories we may have just created must stay user-manageable when
        // running as root: chown the levels this feature owns
        // (.config/systemd and .config/systemd/user, plus ~/.config itself
        // when we just created it).
        if let Some((uid, gid)) = owner {
            chown_best_effort(parent, uid, gid);
            if let Some(grandparent) = parent.parent() {
                chown_best_effort(grandparent, uid, gid);
            }
            if let (Some(dir), Some(false)) = (config_dir, config_dir_existed) {
                chown_best_effort(dir, uid, gid);
            }
        }
    }
    atomic_write_no_follow(path, &unit_content(role))
        .with_context(|| format!("could not write {}", path.display()))?;
    if let Some((uid, gid)) = owner {
        chown_best_effort(path, uid, gid);
    }
    Ok(())
}

/// Writes `content` to `path` via a same-dir temp file + rename(2): atomic,
/// and symlink-safe in both directions. The temp is opened
/// O_NOFOLLOW|O_CREAT|O_EXCL so it can never be pre-seeded, and the rename
/// replaces a symlink at `path` instead of following it — this write can run
/// as root (setup re-executes with sudo) into the invoking user's home, where
/// a pre-placed unit-path symlink would otherwise be clobbered through.
fn atomic_write_no_follow(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unit");
    let tmp = path.with_file_name(format!(".{}.tmp-{}", name, std::process::id()));
    let open_tmp = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o644)
            .open(&tmp)
    };
    // A leftover temp from a killed earlier run is removed once and the
    // exclusive create retried; O_EXCL|O_NOFOLLOW still refuse anything
    // planted in between.
    let mut file = match open_tmp() {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&tmp)?;
            open_tmp()?
        }
        Err(e) => return Err(e),
    };
    let result = file
        .write_all(content.as_bytes())
        .and_then(|_| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Applies the `--autostart` choice: writes/removes the unit files under the
/// target's unit dir and runs the systemctl steps via `run` (the seam that
/// keeps tests off the real systemd). No flag: no autostart changes at all.
fn apply_autostart(
    choice: Option<Autostart>,
    target: &AutostartTarget,
    failures: &mut u32,
    run: &mut dyn FnMut(&CmdSpec) -> Result<()>,
) {
    let choice = match choice {
        Some(c) => c,
        None => return,
    };
    match choice {
        Autostart::Server => enable_role(Role::Server, target, failures, run),
        Autostart::Client => enable_role(Role::Client, target, failures, run),
        Autostart::Off => disable_all_roles(target, failures, run),
        // setup_autostart intercepts Status before apply (it needs an
        // output-capturing probe seam, not the mutation runner).
        Autostart::Status => {}
    }
}

fn enable_role(
    role: Role,
    target: &AutostartTarget,
    failures: &mut u32,
    run: &mut dyn FnMut(&CmdSpec) -> Result<()>,
) {
    let unit_path = target.unit_dir.join(role.unit_name());
    if let Err(e) = write_unit_file(&unit_path, role, target.owner) {
        *failures += 1;
        println!("[fail] autostart: {}", e);
        return;
    }
    println!("[done] autostart: wrote {}", unit_path.display());
    let daemon_reload = target.systemctl.spec(&["daemon-reload"]);
    let enable = target.systemctl.spec(&["enable", "--now", &role.unit_name()]);
    for spec in [&daemon_reload, &enable] {
        if let Err(e) = run(spec) {
            *failures += 1;
            println!("[fail] autostart: {}", e);
            println!("       Run these yourself in your session:");
            println!("       $ {}", daemon_reload.manual_line());
            println!("       $ {}", enable.manual_line());
            return;
        }
    }
    println!(
        "[done] autostart: {} enabled and started (systemd user service)",
        role.unit_name()
    );
    println!(
        "[note] autostart: clipboard sharing works without WAYLAND_DISPLAY in the service (the socket is found in XDG_RUNTIME_DIR, and a compositor that isn't up yet is retried), but the tray indicator needs DBUS_SESSION_BUS_ADDRESS imported into the systemd user manager — Hyprland handles that when launched via UWSM or with its systemd integration. See README.md for details."
    );
}

fn disable_all_roles(
    target: &AutostartTarget,
    failures: &mut u32,
    run: &mut dyn FnMut(&CmdSpec) -> Result<()>,
) {
    for role in [Role::Server, Role::Client] {
        // Best-effort: the service may not exist or be enabled; the unit file
        // is removed regardless.
        let disable = target.systemctl.spec(&["disable", "--now", &role.unit_name()]);
        if let Err(e) = run(&disable) {
            println!(
                "[skip] autostart: could not disable {} ({}); removing the unit file anyway",
                role.unit_name(),
                e
            );
        }
        let unit_path = target.unit_dir.join(role.unit_name());
        match std::fs::remove_file(&unit_path) {
            Ok(()) => println!("[done] autostart: removed {}", unit_path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                *failures += 1;
                println!(
                    "[fail] autostart: could not remove {}: {}",
                    unit_path.display(),
                    e
                );
            }
        }
    }
    // Forget the removed units; a failure here is harmless.
    let _ = run(&target.systemctl.spec(&["daemon-reload"]));
    println!("[done] autostart: monux services disabled and unit files removed");
}

/// Everything `setup --autostart status` learns about one role. The Option
/// fields are None when the probe couldn't answer (systemctl absent or
/// returning something unexpected); holder_pid is the single-instance lock
/// probe (Some = a live monux of this role).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RoleStatus {
    installed: bool,
    enabled: Option<bool>,
    active: Option<bool>,
    main_pid: Option<i32>,
    active_since: Option<String>,
    holder_pid: Option<i32>,
}

/// Parses `systemctl --user is-enabled` stdout: Some(bool) on a definitive
/// answer, None on anything unexpected (the report then shows "enabled?").
fn parse_is_enabled(out: &str) -> Option<bool> {
    match out.trim() {
        "enabled" => Some(true),
        "disabled" => Some(false),
        _ => None,
    }
}

/// Parses `systemctl --user is-active` stdout (see parse_is_enabled).
fn parse_is_active(out: &str) -> Option<bool> {
    match out.trim() {
        "active" => Some(true),
        "inactive" | "failed" => Some(false),
        _ => None,
    }
}

/// Parses `systemctl --user show -p MainPID,ActiveEnterTimestamp` output into
/// (main pid, start timestamp). A 0 pid (unit never ran) and an empty
/// timestamp count as absent. The timestamp is reformatted from systemd's
/// "Sat 2026-07-25 15:28:34 CEST" into "2026-07-25T15:28:34"; an unexpected
/// shape passes through unchanged.
fn parse_show(out: &str) -> (Option<i32>, Option<String>) {
    let mut pid = None;
    let mut since = None;
    for line in out.lines() {
        if let Some(value) = line.strip_prefix("MainPID=") {
            pid = value.trim().parse::<i32>().ok().filter(|pid| *pid > 0);
        } else if let Some(value) = line.strip_prefix("ActiveEnterTimestamp=") {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let parts: Vec<&str> = value.split_whitespace().collect();
            since = Some(match parts.as_slice() {
                [_weekday, date, time, _tz] => format!("{}T{}", date, time),
                _ => value.to_string(),
            });
        }
    }
    (pid, since)
}

/// Probes one role for the status report: the unit file (filesystem), the
/// enable/active state (systemctl, skipped for uninstalled units — they would
/// only error) and the single-instance lock (passed in, so the probe stays
/// testable). A systemctl that can't even spawn degrades to a note (once per
/// report) plus the file/lock state.
fn probe_role_status(
    role: Role,
    target: &AutostartTarget,
    query: &dyn Fn(&CmdSpec) -> Result<String>,
    holder_pid: Option<i32>,
    notes: &mut Vec<String>,
) -> RoleStatus {
    let unit_path = target.unit_dir.join(role.unit_name());
    let mut status = RoleStatus {
        installed: unit_path.exists(),
        holder_pid,
        ..Default::default()
    };
    if !status.installed {
        return status;
    }
    let mut query_once = |args: &[&str]| -> Option<String> {
        match query(&target.systemctl.spec(args)) {
            Ok(out) => Some(out),
            Err(e) => {
                let note = format!(
                    "could not query systemctl ({:#}); reporting the unit file and the lock state only",
                    e
                );
                if !notes.contains(&note) {
                    notes.push(note);
                }
                None
            }
        }
    };
    status.enabled = query_once(&["is-enabled", &role.unit_name()])
        .and_then(|out| parse_is_enabled(&out));
    status.active =
        query_once(&["is-active", &role.unit_name()]).and_then(|out| parse_is_active(&out));
    // The show query (pid + start timestamp) only has something to say when
    // the unit is actually up.
    if status.active == Some(true) {
        if let Some(out) =
            query_once(&["show", "-p", "MainPID,ActiveEnterTimestamp", &role.unit_name()])
        {
            let (pid, since) = parse_show(&out);
            status.main_pid = pid;
            status.active_since = since;
        }
    }
    status
}

/// One line of the report, e.g. "server: installed, enabled, active (pid
/// 417077 since 2026-07-25T15:28:34) — running (autostarted)".
fn render_role_status(role: Role, status: &RoleStatus) -> String {
    let mut line = format!("{}: ", role.as_str());
    if !status.installed {
        line.push_str("not installed");
        // No unit: any live daemon of this role was started by hand.
        if let Some(pid) = status.holder_pid {
            line.push_str(&format!(" — running (manual, pid {})", pid));
        }
        return line;
    }
    line.push_str("installed");
    line.push_str(match status.enabled {
        Some(true) => ", enabled",
        Some(false) => ", disabled",
        None => ", enabled?",
    });
    match status.active {
        Some(true) => {
            line.push_str(", active");
            match (status.main_pid, &status.active_since) {
                (Some(pid), Some(since)) => {
                    line.push_str(&format!(" (pid {} since {})", pid, since))
                }
                (Some(pid), None) => line.push_str(&format!(" (pid {})", pid)),
                (None, _) => {}
            }
        }
        Some(false) => line.push_str(", inactive"),
        None => line.push_str(", active?"),
    }
    // Cross-reference the single-instance lock to tell an autostarted daemon
    // from a manually started one.
    match (status.active, status.holder_pid) {
        // systemd says the unit is up: the daemon is autostarted (the lock
        // probe merely confirms; it can't override systemd's word).
        (Some(true), _) => line.push_str(" — running (autostarted)"),
        // systemd says the unit is down but a monux holds the role lock:
        // started by hand.
        (Some(false), Some(pid)) => {
            line.push_str(&format!(" — running (manual, pid {})", pid))
        }
        (Some(false), None) => line.push_str(" — not running"),
        // systemd couldn't answer: the lock probe alone says what's alive,
        // without an autostarted/manual claim it can't back up.
        (None, Some(pid)) => line.push_str(&format!(" — running (pid {})", pid)),
        (None, None) => line.push_str(" — not running"),
    }
    line
}

/// Renders a unit path with the user's home as `~` (the report is for
/// humans: ~/.config/systemd/user/monux-server.service reads better than the
/// absolute path). unit_dir is $HOME/.config/systemd/user by construction,
/// so its 4th ancestor (0-based 3) is the home.
fn display_unit_path(unit_dir: &Path, path: &Path) -> String {
    match unit_dir
        .ancestors()
        .nth(3)
        .and_then(|home| path.strip_prefix(home).ok())
    {
        Some(rel) => format!("~/{}", rel.display()),
        None => path.display().to_string(),
    }
}

/// The full `setup --autostart status` report: one line per role, then the
/// unit path of every installed unit, then any degradation notes. Read-only:
/// the only outside contact is the filesystem, read-only systemctl queries
/// (through `query`, the seam that keeps tests off the real systemd) and the
/// single-instance lock probe (`holder`).
fn autostart_status_report(
    target: &AutostartTarget,
    query: &dyn Fn(&CmdSpec) -> Result<String>,
    holder: &dyn Fn(Role) -> Option<i32>,
) -> String {
    let mut notes = Vec::new();
    let mut lines = Vec::new();
    for role in [Role::Server, Role::Client] {
        let status = probe_role_status(role, target, query, holder(role), &mut notes);
        lines.push(render_role_status(role, &status));
    }
    for role in [Role::Server, Role::Client] {
        let unit_path = target.unit_dir.join(role.unit_name());
        if unit_path.exists() {
            lines.push(format!(
                "unit: {}",
                display_unit_path(&target.unit_dir, &unit_path)
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
    let target = resolve_autostart_target().ok().flatten()?;
    Some(autostart_status_report(
        &target,
        &|spec| spec.probe(),
        &|role| crate::single_instance::live_holder(role.as_str()),
    ))
}

fn setup_autostart(choice: Option<Autostart>, failures: &mut u32) {
    if choice.is_none() {
        // No flag: leave autostart untouched.
        return;
    }
    let target = match resolve_autostart_target() {
        Ok(Some(t)) => t,
        Ok(None) => {
            *failures += 1;
            println!("[fail] autostart: no invoking user found (run setup via sudo from your user session, not from a root shell)");
            return;
        }
        Err(e) => {
            *failures += 1;
            println!("[fail] autostart: {}", e);
            return;
        }
    };
    // Status is read-only: it never mutates systemd state, so it uses an
    // output-capturing probe seam instead of the mutation runner.
    if choice == Some(Autostart::Status) {
        println!(
            "{}",
            autostart_status_report(
                &target,
                &|spec| spec.probe(),
                &|role| crate::single_instance::live_holder(role.as_str()),
            )
        );
        return;
    }
    apply_autostart(choice, &target, failures, &mut |spec| spec.run());
}

/// The desktop entry file name, under the per-user applications dir.
pub(crate) const DESKTOP_SHORTCUT_NAME: &str = "monux-tray.desktop";

/// The applications dir for per-user desktop entries: $XDG_DATA_HOME/
/// applications when set and absolute, else ~/.local/share/applications (the
/// XDG base-directory-spec default; a relative value is invalid and ignored,
/// an empty one counts as unset). `xdg_data_home` is the raw env value, a
/// parameter so the resolution is testable.
pub(crate) fn applications_dir_from(
    home: &Path,
    xdg_data_home: Option<&std::ffi::OsStr>,
) -> PathBuf {
    match xdg_data_home {
        Some(dir) if Path::new(dir).is_absolute() => PathBuf::from(dir).join("applications"),
        _ => home.join(".local").join("share").join("applications"),
    }
}

/// Content of the desktop entry. Exec is `monux gui tray show`: with a
/// daemon it un-hides the auto-spawned indicator, without one it starts a
/// standalone tray (see indicator.rs). Icon is a stock freedesktop name —
/// the repo ships no assets.
fn desktop_shortcut_content() -> &'static str {
    "[Desktop Entry]\nType=Application\nName=monux tray\nComment=Show the monux tray indicator (starts it when no daemon is running)\nExec=monux gui tray show\nTerminal=false\nCategories=Utility;\nIcon=input-keyboard\n"
}

/// Writes the desktop entry atomically (see atomic_write_no_follow:
/// idempotent, and symlink-safe should the path be pre-seeded) and chowns
/// what it creates when setup runs as root via sudo, so the file stays
/// user-manageable.
fn write_desktop_shortcut(path: &Path, owner: Option<(u32, u32)>) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
        if let Some((uid, gid)) = owner {
            chown_best_effort(parent, uid, gid);
        }
    }
    atomic_write_no_follow(path, desktop_shortcut_content())
        .with_context(|| format!("could not write {}", path.display()))?;
    if let Some((uid, gid)) = owner {
        chown_best_effort(path, uid, gid);
    }
    Ok(())
}

/// Ensures the desktop entry EXISTS, without touching one that's already
/// there: called by the updater so installs done via 'monux update' (which
/// never runs install.sh) get the shortcut too. Returns true when it wrote
/// the file. Never fails hard over it — the caller logs and moves on; an
/// existing file (stock or user-edited) is left alone.
pub fn ensure_desktop_shortcut(home: &Path, xdg_data_home: Option<&std::ffi::OsStr>) -> Result<bool> {
    let path = applications_dir_from(home, xdg_data_home).join(DESKTOP_SHORTCUT_NAME);
    if path.exists() {
        return Ok(false);
    }
    write_desktop_shortcut(&path, None)?;
    Ok(true)
}

/// `--desktop-shortcut`: installs a .desktop entry so the tray can be
/// launched from the desktop's app menu. User-level, like --autostart: it
/// never elevates; the file lands in the invoking user's data home.
fn setup_desktop_shortcut(failures: &mut u32) {
    let (home, owner) = match resolve_invoking_user() {
        Ok(Some(v)) => v,
        Ok(None) => {
            *failures += 1;
            println!("[fail] desktop shortcut: no invoking user found (run setup as your user, not from a root shell)");
            return;
        }
        Err(e) => {
            *failures += 1;
            println!("[fail] desktop shortcut: {}", e);
            return;
        }
    };
    let path = applications_dir_from(&home, std::env::var_os("XDG_DATA_HOME").as_deref())
        .join(DESKTOP_SHORTCUT_NAME);
    if let Err(e) = write_desktop_shortcut(&path, owner) {
        *failures += 1;
        println!("[fail] desktop shortcut: {}", e);
        return;
    }
    println!("[done] desktop shortcut: wrote {}", path.display());
}

/// Target for net.core.{r,w}mem_max: comfortably above the 2 MiB that monux
/// requests for its QUIC UDP socket buffers (the kernel clamps SO_SNDBUF/
/// SO_RCVBUF to these sysctls).
const SOCK_MEM_MAX: u64 = 2_621_440;

/// The nftables table monux's DSCP marks live in. A dedicated table makes the
/// feature atomic to install and to remove — `nft delete table` undoes
/// everything without touching anyone else's rules.
pub(crate) const NFT_QOS_TABLE: &str = "monux-qos";

/// The UDP port the QoS marks match: the default monux listen port. A server
/// on a custom --port needs matching custom rules.
const QOS_MARK_PORT: u16 = 1213;

/// The nftables commands installing monux's DSCP marks, in order (one `nft`
/// invocation per entry). nft takes a whole command as a single argument, so
/// no shell quoting is involved.
pub(crate) fn nft_qos_install_cmds() -> Vec<String> {
    vec![
        format!("add table inet {}", NFT_QOS_TABLE),
        format!(
            "add chain inet {} output {{ type filter hook output priority mangle; policy accept; }}",
            NFT_QOS_TABLE
        ),
        format!(
            "add rule inet {} output udp sport {} ip dscp set cs6",
            NFT_QOS_TABLE, QOS_MARK_PORT
        ),
        format!(
            "add rule inet {} output udp dport {} ip dscp set cs6",
            NFT_QOS_TABLE, QOS_MARK_PORT
        ),
    ]
}

/// Whether `nft list table inet <table>` output already carries both marks.
fn nft_ruleset_has_marks(ruleset: &str) -> bool {
    ruleset.contains("udp sport 1213")
        && ruleset.contains("udp dport 1213")
        && ruleset.contains("cs6")
}

/// The two iptables rules (everything after `iptables -t mangle <verb>
/// OUTPUT`) matching monux's DSCP marks.
pub(crate) fn iptables_qos_rule_specs() -> [Vec<String>; 2] {
    ["--sport", "--dport"].map(|side| {
        [
            "-p".to_string(),
            "udp".to_string(),
            side.to_string(),
            QOS_MARK_PORT.to_string(),
            "-j".to_string(),
            "DSCP".to_string(),
            "--set-dscp-class".to_string(),
            "CS6".to_string(),
        ]
        .to_vec()
    })
}

fn powersave_conf_content() -> &'static str {
    "[connection]\nwifi.powersave = 2\n"
}

fn udev_rule_content() -> &'static str {
    "SUBSYSTEM==\"misc\", KERNEL==\"uinput\", GROUP=\"input\", MODE=\"0660\"\n"
}

fn sysctl_buf_conf_content() -> String {
    format!(
        "net.core.rmem_max = {}\nnet.core.wmem_max = {}\n",
        SOCK_MEM_MAX, SOCK_MEM_MAX
    )
}

pub fn run(autostart: Option<Autostart>, desktop_shortcut: bool) -> Result<()> {
    // Flag scoping: no flags means the full base set below; ANY flag scopes
    // the run to that flag's actions only.
    let scoped = autostart.is_some() || desktop_shortcut;
    // The base set persists root-owned system settings. --autostart and
    // --desktop-shortcut manage per-user files and must NOT elevate: they
    // land in the invoking user's home (main.rs skips the sudo re-exec for
    // a run scoped to those flags).
    let needs_root = !scoped;
    if needs_root && unsafe { libc::geteuid() } != 0 {
        // Reaching here non-root means auto-elevation was opted out of
        // (MONUX_NO_ELEVATE). sudo resets PATH, so 'sudo monux setup' often
        // fails with "command not found": print the full invocation that works.
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "monux".to_string());
        let args = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
        bail!("monux setup persists system settings and needs root. Run it with: sudo {} {} (or re-run without MONUX_NO_ELEVATE to elevate automatically)", exe, args);
    }

    let mut failures = 0;
    if !scoped {
        setup_input_group(&mut failures);
        setup_uinput_access(&mut failures);
        setup_wifi_powersave(&mut failures);
        setup_socket_buffers(&mut failures);
        setup_qos_marking(&mut failures);
    }
    setup_autostart(autostart, &mut failures);
    if desktop_shortcut {
        setup_desktop_shortcut(&mut failures);
    }

    // A status report changes nothing: no summary footer.
    if autostart == Some(Autostart::Status) && !desktop_shortcut {
        return Ok(());
    }

    println!();
    if failures > 0 {
        println!("Done with {} failed step(s); see messages above.", failures);
    } else if !scoped {
        println!("All done. Undo any of these by removing the files listed above, removing the user from the 'input' group, and/or deleting the QoS rules ('sudo nft delete table inet {}' or the iptables -D equivalents).", NFT_QOS_TABLE);
    } else {
        println!("All done.");
    }
    Ok(())
}

/// The argv with secrets scrubbed for error messages (which land in the
/// system journal via the callers' warnings): the element following
/// `wifi-sec.psk` is a cleartext WiFi password.
fn redacted_args<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut redact_next = false;
    args.iter()
        .map(|arg| {
            if std::mem::replace(&mut redact_next, false) {
                return "<redacted>";
            }
            if *arg == "wifi-sec.psk" {
                redact_next = true;
            }
            *arg
        })
        .collect()
}

/// Runs a command, returning its stdout on success.
pub(crate) fn run_cmd(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run {}: is it installed?", program))?;
    if !output.status.success() {
        bail!(
            "{} {} failed: {}",
            program,
            redacted_args(args).join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Checks `id -nG` output for group membership.
pub(crate) fn groups_contain(id_ng_output: &str, group: &str) -> bool {
    id_ng_output
        .split_whitespace()
        .any(|g| g == group)
}

fn setup_input_group(failures: &mut u32) {
    // The user to grant device access: the one who invoked sudo.
    let user = std::env::var("SUDO_USER").unwrap_or_default();
    if user.is_empty() || user == "root" {
        println!("[skip] input group: no invoking user (running as root directly; root needs no group)");
        return;
    }
    match run_cmd("id", &["-nG", &user]) {
        Ok(groups) if groups_contain(&groups, "input") => {
            println!("[ok]   input group: user '{}' is already a member", user);
        }
        Ok(_) => match run_cmd("usermod", &["-aG", "input", &user]) {
            Ok(_) => println!(
                "[done] input group: added user '{}' (takes effect on next login)",
                user
            ),
            Err(e) => {
                *failures += 1;
                println!("[fail] input group: {}", e);
            }
        },
        Err(e) => {
            *failures += 1;
            println!("[fail] input group: could not query groups for '{}': {}", user, e);
        }
    }
}

/// Checks whether a path's permissions grant the group read+write.
fn group_has_rw(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o060 == 0o060
}

fn setup_uinput_access(failures: &mut u32) {
    let uinput = Path::new("/dev/uinput");
    if !uinput.exists() {
        // Try to load the kernel module right now, and persist it across boots.
        match run_cmd("modprobe", &["uinput"]) {
            Ok(_) if uinput.exists() => {
                println!("[done] uinput: loaded the kernel module");
            }
            Ok(_) => {
                *failures += 1;
                println!("[fail] uinput: modprobe succeeded but /dev/uinput still doesn't exist");
                return;
            }
            Err(e) => {
                *failures += 1;
                println!("[fail] uinput: could not load the kernel module: {}", e);
                return;
            }
        }
        match std::fs::write(MODULES_LOAD_PATH, "uinput\n") {
            Ok(_) => println!("[done] uinput: module persisted in {}", MODULES_LOAD_PATH),
            Err(e) => {
                *failures += 1;
                println!("[fail] uinput: could not write {}: {}", MODULES_LOAD_PATH, e);
            }
        }
    }

    let meta = match std::fs::metadata(uinput) {
        Ok(m) => m,
        Err(e) => {
            *failures += 1;
            println!("[fail] uinput: could not stat /dev/uinput: {}", e);
            return;
        }
    };
    if group_has_rw(&meta) {
        println!("[ok]   uinput: /dev/uinput is already group-accessible");
        return;
    }
    match std::fs::write(UDEV_RULE_PATH, udev_rule_content()) {
        Ok(_) => println!("[done] uinput: wrote group-access rule to {}", UDEV_RULE_PATH),
        Err(e) => {
            *failures += 1;
            println!("[fail] uinput: could not write {}: {}", UDEV_RULE_PATH, e);
            return;
        }
    }
    if let Err(e) = run_cmd("udevadm", &["control", "--reload"]) {
        *failures += 1;
        println!("[fail] uinput: udevadm reload failed: {}", e);
        return;
    }
    match run_cmd("udevadm", &["trigger"]) {
        Ok(_) => println!("[done] uinput: udev rules reloaded and triggered"),
        Err(e) => {
            *failures += 1;
            println!("[fail] uinput: udevadm trigger failed: {}", e);
        }
    }
}

/// Parses `iw dev` output into a list of interface names.
fn parse_iw_interfaces(iw_dev_output: &str) -> Vec<String> {
    iw_dev_output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("Interface ").map(|s| s.to_string())
        })
        .collect()
}

fn setup_wifi_powersave(failures: &mut u32) {
    // Persistent setting, via NetworkManager when it's in use.
    if Path::new("/etc/NetworkManager").exists() {
        let already = std::fs::read_to_string(NM_POWERSAVE_CONF_PATH)
            .map(|c| c.contains("wifi.powersave = 2"))
            .unwrap_or(false);
        if already {
            println!("[ok]   wifi powersave: already disabled in {}", NM_POWERSAVE_CONF_PATH);
        } else {
            match std::fs::write(NM_POWERSAVE_CONF_PATH, powersave_conf_content()) {
                Ok(_) => println!(
                    "[done] wifi powersave: wrote {} (applies to new connections; reconnect WiFi or reboot to activate)",
                    NM_POWERSAVE_CONF_PATH
                ),
                Err(e) => {
                    *failures += 1;
                    println!("[fail] wifi powersave: could not write {}: {}", NM_POWERSAVE_CONF_PATH, e);
                }
            }
        }
    } else {
        println!("[skip] wifi powersave: NetworkManager not found; disable power saving via your network stack if latency spikes appear");
    }

    // Immediate setting for currently-present wireless interfaces.
    let iw_dev = match run_cmd("iw", &["dev"]) {
        Ok(out) => out,
        Err(e) => {
            println!("[skip] wifi powersave: 'iw dev' unavailable ({}); skipping immediate apply", e);
            return;
        }
    };
    let ifaces = parse_iw_interfaces(&iw_dev);
    if ifaces.is_empty() {
        println!("[skip] wifi powersave: no wireless interfaces found");
        return;
    }
    for iface in ifaces {
        match run_cmd("iw", &["dev", &iface, "set", "power_save", "off"]) {
            Ok(_) => println!("[done] wifi powersave: disabled on {} (immediate)", iface),
            Err(e) => {
                *failures += 1;
                println!("[fail] wifi powersave: could not disable on {}: {}", iface, e);
            }
        }
    }
}

/// Installs DSCP CS6 netfilter marking for monux's UDP traffic. SO_PRIORITY
/// (set by monux itself in local mode) already covers this machine's own
/// wireless egress queue, but the AP/router hop picks its downlink queue from
/// each packet's DSCP — and quinn overwrites the TOS byte per packet with its
/// ECN codepoint, so only netfilter can set a wire-level mark. nftables is
/// preferred (a dedicated table is atomic to install and remove); iptables is
/// the fallback. Idempotent; the rules don't persist across reboots.
fn setup_qos_marking(failures: &mut u32) {
    if run_cmd("nft", &["--version"]).is_ok() {
        // A complete existing install is left alone; a partial one (older
        // version, manual edits) is replaced wholesale.
        match run_cmd("nft", &[&format!("list table inet {}", NFT_QOS_TABLE)]) {
            Ok(ruleset) if nft_ruleset_has_marks(&ruleset) => {
                println!(
                    "[ok]   qos marking: DSCP CS6 rules already installed (nftables table inet {})",
                    NFT_QOS_TABLE
                );
                return;
            }
            Ok(_) => {
                let _ = run_cmd("nft", &[&format!("delete table inet {}", NFT_QOS_TABLE)]);
            }
            Err(_) => {}
        }
        for cmd in nft_qos_install_cmds() {
            if let Err(e) = run_cmd("nft", &[&cmd]) {
                *failures += 1;
                println!("[fail] qos marking: nft {}: {}", cmd, e);
                // Don't leave a half-installed table behind.
                let _ = run_cmd("nft", &[&format!("delete table inet {}", NFT_QOS_TABLE)]);
                return;
            }
        }
        println!(
            "[done] qos marking: monux UDP marked CS6 via nftables (table inet {}; covers both server and client roles; does not persist across reboots)",
            NFT_QOS_TABLE
        );
        return;
    }
    if run_cmd("iptables", &["--version"]).is_ok() {
        let mut added = 0;
        for spec in iptables_qos_rule_specs() {
            let check: Vec<&str> = ["-t", "mangle", "-C", "OUTPUT"]
                .into_iter()
                .chain(spec.iter().map(String::as_str))
                .collect();
            if run_cmd("iptables", &check).is_ok() {
                continue;
            }
            let add: Vec<&str> = ["-t", "mangle", "-A", "OUTPUT"]
                .into_iter()
                .chain(spec.iter().map(String::as_str))
                .collect();
            match run_cmd("iptables", &add) {
                Ok(_) => added += 1,
                Err(e) => {
                    *failures += 1;
                    println!("[fail] qos marking: iptables {}: {}", add.join(" "), e);
                    return;
                }
            }
        }
        if added == 0 {
            println!("[ok]   qos marking: DSCP CS6 rules already installed (iptables mangle OUTPUT)");
        } else {
            println!(
                "[done] qos marking: monux UDP marked CS6 via iptables ({} rule(s) added to mangle OUTPUT; does not persist across reboots)",
                added
            );
        }
        return;
    }
    println!("[skip] qos marking: neither nft nor iptables found; monux's SO_PRIORITY WMM marking still covers this machine's own wireless egress");
}

/// Reads a numeric /proc sysctl value, e.g. /proc/sys/net/core/rmem_max.
fn read_proc_sysctl(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn setup_socket_buffers(failures: &mut u32) {
    const RMEM_PROC: &str = "/proc/sys/net/core/rmem_max";
    const WMEM_PROC: &str = "/proc/sys/net/core/wmem_max";
    let rmem = read_proc_sysctl(RMEM_PROC);
    let wmem = read_proc_sysctl(WMEM_PROC);
    if rmem.is_some_and(|v| v >= SOCK_MEM_MAX) && wmem.is_some_and(|v| v >= SOCK_MEM_MAX) {
        println!("[ok]   udp buffers: net.core.rmem_max/wmem_max already >= {}", SOCK_MEM_MAX);
        return;
    }

    // Persist for future boots, then apply immediately (don't require a reboot).
    if let Err(e) = std::fs::write(SYSCTL_BUF_CONF_PATH, sysctl_buf_conf_content()) {
        *failures += 1;
        println!("[fail] udp buffers: could not write {}: {}", SYSCTL_BUF_CONF_PATH, e);
        return;
    }
    println!("[done] udp buffers: wrote {}", SYSCTL_BUF_CONF_PATH);
    let rmem = format!("net.core.rmem_max={}", SOCK_MEM_MAX);
    let wmem = format!("net.core.wmem_max={}", SOCK_MEM_MAX);
    match run_cmd("sysctl", &["-w", &rmem, &wmem]) {
        Ok(_) => println!("[done] udp buffers: applied immediately (net.core.rmem_max=wmem_max={})", SOCK_MEM_MAX),
        Err(e) => {
            *failures += 1;
            println!("[fail] udp buffers: persisted but immediate apply failed (takes effect on reboot): {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_membership_parsing() {
        assert!(groups_contain("mntzr sys network docker input users", "input"));
        assert!(!groups_contain("mntzr sys network docker users", "input"));
        assert!(!groups_contain("", "input"));
        // Exact matching: 'input2' must not count as 'input'
        assert!(!groups_contain("mntzr input2", "input"));
    }

    #[test]
    fn iw_dev_interface_parsing() {
        let sample = "phy#0\n\tUnnamed/non-netdev interface\n\t\twdev 0x2\n\t\taddr aa:bb:cc:dd:ee:ff\n\t\ttype P2P-device\n\tInterface wlan0\n\t\tifindex 3\n\t\twdev 0x1\n\t\ttype managed\n\tchannel 7 (2442 MHz)\nphy#1\n\tInterface wlan1\n\t\tifindex 4\n\t\ttype managed\n";
        assert_eq!(parse_iw_interfaces(sample), vec!["wlan0", "wlan1"]);
        assert!(parse_iw_interfaces("phy#0\n").is_empty());
    }

    #[test]
    fn powersave_conf_disables() {
        assert!(powersave_conf_content().contains("wifi.powersave = 2"));
    }

    #[test]
    fn psk_is_redacted_from_error_messages() {
        let redacted = redacted_args(&[
            "connection", "modify", "monux-direct", "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk",
            "s3cret-p4ss",
        ]);
        assert_eq!(
            redacted.join(" "),
            "connection modify monux-direct wifi-sec.key-mgmt wpa-psk wifi-sec.psk <redacted>"
        );
        // No psk flag: every argument passes through.
        assert_eq!(
            redacted_args(&["connection", "up", "monux-direct"]).join(" "),
            "connection up monux-direct"
        );
        // The real error path: the failing command's message carries the
        // redaction marker and never the secret.
        let err = run_cmd("false", &["wifi-sec.psk", "s3cret-p4ss"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("<redacted>"), "{}", err);
        assert!(!err.contains("s3cret-p4ss"), "{}", err);
    }

    #[test]
    fn sysctl_conf_covers_both_buffers() {
        let content = sysctl_buf_conf_content();
        assert!(content.contains("net.core.rmem_max = 2621440"));
        assert!(content.contains("net.core.wmem_max = 2621440"));
    }

    #[test]
    fn nft_install_cmds_build_table_chain_and_both_marks() {
        let cmds = nft_qos_install_cmds();
        assert_eq!(cmds.len(), 4);
        assert!(cmds[0].contains(NFT_QOS_TABLE));
        assert!(cmds[1].contains("type filter hook output priority mangle"));
        assert!(cmds.iter().any(|c| c.contains("udp sport 1213")));
        assert!(cmds.iter().any(|c| c.contains("udp dport 1213")));
        assert!(cmds.iter().filter(|c| c.contains("cs6")).count() == 2);
    }

    #[test]
    fn nft_ruleset_mark_detection() {
        let installed = "table inet monux-qos {\n\tchain output {\n\t\ttype filter hook output priority mangle; policy accept;\n\t\tmeta l4proto udp udp sport 1213 ip dscp set cs6\n\t\tmeta l4proto udp udp dport 1213 ip dscp set cs6\n\t}\n}";
        assert!(nft_ruleset_has_marks(installed));
        // Only one direction marked: incomplete, gets replaced.
        let partial = "table inet monux-qos {\n\tchain output {\n\t\tmeta l4proto udp udp sport 1213 ip dscp set cs6\n\t}\n}";
        assert!(!nft_ruleset_has_marks(partial));
        assert!(!nft_ruleset_has_marks(""));
    }

    #[test]
    fn iptables_rule_specs_cover_both_directions() {
        let specs = iptables_qos_rule_specs();
        assert_eq!(specs.len(), 2);
        for spec in &specs {
            let joined = spec.join(" ");
            assert!(joined.contains("-p udp"));
            assert!(joined.contains("1213"));
            assert!(joined.contains("-j DSCP --set-dscp-class CS6"));
        }
        assert!(specs[0].join(" ").contains("--sport 1213"));
        assert!(specs[1].join(" ").contains("--dport 1213"));
    }

    #[test]
    fn group_rw_mode_check() {
        // rw for group means at least 0o060 in the group bits
        assert_eq!(0o660 & 0o060, 0o060);
        assert_ne!(0o600 & 0o060, 0o060);
    }

    /// A target rooted at a tempdir, managing the current user directly.
    fn test_target(dir: &Path) -> AutostartTarget {
        AutostartTarget {
            unit_dir: dir.to_path_buf(),
            systemctl: Systemctl { user: None },
            owner: None,
        }
    }

    /// The shared log a recording executor appends to.
    type Recorded = std::rc::Rc<std::cell::RefCell<Vec<CmdSpec>>>;

    /// An executor that records every command instead of running it.
    fn recording_executor() -> (Recorded, impl FnMut(&CmdSpec) -> Result<()>) {
        let recorded = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let rec = recorded.clone();
        let run = move |spec: &CmdSpec| -> Result<()> {
            rec.borrow_mut().push(spec.clone());
            Ok(())
        };
        (recorded, run)
    }

    #[test]
    fn unit_file_contents() {
        assert_eq!(
            unit_content(Role::Server),
            "[Unit]\nDescription=monux KVM server\nAfter=graphical-session.target\n\n[Service]\nExecStart=%h/.local/bin/monux server\nRestart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n"
        );
        let client = unit_content(Role::Client);
        assert!(client.contains("Description=monux KVM client\n"));
        assert!(client.contains("After=graphical-session.target\n"));
        assert!(client.contains("Restart=on-failure\n"));
        // Client with no address argument = mDNS auto-discovery: nothing
        // machine-specific (like a hardcoded server IP) may be baked in.
        assert!(client.contains("ExecStart=%h/.local/bin/monux client\n"));
        assert!(!client.contains("monux client "));
    }

    #[test]
    fn systemctl_specs_plain_and_runuser() {
        // Without a sudo target, systemctl runs directly.
        let plain = Systemctl { user: None }.spec(&["daemon-reload"]);
        assert_eq!(plain.program, "systemctl");
        assert_eq!(plain.args, vec!["--user", "daemon-reload"]);
        assert!(plain.env.is_empty());
        assert_eq!(plain.manual_line(), "systemctl --user daemon-reload");

        // As root via sudo: wrapped in runuser with the user's runtime dir.
        let sys = Systemctl {
            user: Some(UserCtx {
                name: "alice".to_string(),
                uid: 1001,
            }),
        };
        let spec = sys.spec(&["enable", "--now", "monux-server.service"]);
        assert_eq!(spec.program, "runuser");
        assert_eq!(
            spec.args,
            vec![
                "-u",
                "alice",
                "--",
                "systemctl",
                "--user",
                "enable",
                "--now",
                "monux-server.service"
            ]
        );
        assert_eq!(
            spec.env,
            vec![
                ("XDG_RUNTIME_DIR".to_string(), "/run/user/1001".to_string()),
                (
                    "DBUS_SESSION_BUS_ADDRESS".to_string(),
                    "unix:path=/run/user/1001/bus".to_string()
                ),
            ]
        );
        // The manual hint is the plain command the user runs in their session.
        assert_eq!(
            spec.manual_line(),
            "systemctl --user enable --now monux-server.service"
        );
    }

    #[test]
    fn autostart_server_writes_unit_and_enables() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let (recorded, mut run) = recording_executor();
        let mut failures = 0;
        apply_autostart(Some(Autostart::Server), &target, &mut failures, &mut run);
        assert_eq!(failures, 0);
        // Unit file written with the expected content.
        let content =
            std::fs::read_to_string(tmp.path().join("monux-server.service")).unwrap();
        assert_eq!(content, unit_content(Role::Server));
        // daemon-reload, then enable --now, in order.
        let cmds = recorded.borrow();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0], Systemctl { user: None }.spec(&["daemon-reload"]));
        assert_eq!(
            cmds[1],
            Systemctl { user: None }.spec(&["enable", "--now", "monux-server.service"])
        );
    }

    #[test]
    fn autostart_client_writes_unit_and_enables() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let (recorded, mut run) = recording_executor();
        let mut failures = 0;
        apply_autostart(Some(Autostart::Client), &target, &mut failures, &mut run);
        assert_eq!(failures, 0);
        let content =
            std::fs::read_to_string(tmp.path().join("monux-client.service")).unwrap();
        assert_eq!(content, unit_content(Role::Client));
        let cmds = recorded.borrow();
        assert_eq!(cmds.len(), 2);
        assert_eq!(
            cmds[1],
            Systemctl { user: None }.spec(&["enable", "--now", "monux-client.service"])
        );
    }

    #[test]
    fn autostart_off_disables_and_removes() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        std::fs::write(
            tmp.path().join("monux-server.service"),
            unit_content(Role::Server),
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("monux-client.service"),
            unit_content(Role::Client),
        )
        .unwrap();
        let (recorded, mut run) = recording_executor();
        let mut failures = 0;
        apply_autostart(Some(Autostart::Off), &target, &mut failures, &mut run);
        assert_eq!(failures, 0);
        // Both unit files removed...
        assert!(!tmp.path().join("monux-server.service").exists());
        assert!(!tmp.path().join("monux-client.service").exists());
        // ...after disabling both, then a daemon-reload.
        let cmds = recorded.borrow();
        assert_eq!(cmds.len(), 3);
        assert_eq!(
            cmds[0],
            Systemctl { user: None }.spec(&["disable", "--now", "monux-server.service"])
        );
        assert_eq!(
            cmds[1],
            Systemctl { user: None }.spec(&["disable", "--now", "monux-client.service"])
        );
        assert_eq!(cmds[2], Systemctl { user: None }.spec(&["daemon-reload"]));
    }

    #[test]
    fn autostart_none_changes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        std::fs::write(tmp.path().join("monux-server.service"), "keep me").unwrap();
        let mut failures = 0;
        let mut run = |_: &CmdSpec| -> Result<()> {
            panic!("no systemctl commands may run without --autostart")
        };
        apply_autostart(None, &target, &mut failures, &mut run);
        assert_eq!(failures, 0);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("monux-server.service")).unwrap(),
            "keep me"
        );
    }

    #[test]
    fn autostart_enable_failure_counts_and_stops() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        let mut failures = 0;
        let mut run = |_: &CmdSpec| -> Result<()> { bail!("no systemd here") };
        apply_autostart(Some(Autostart::Client), &target, &mut failures, &mut run);
        assert_eq!(failures, 1);
        // The unit file was still written, so the printed manual commands work.
        assert!(tmp.path().join("monux-client.service").exists());
    }

    #[test]
    fn unit_file_write_replaces_a_symlink_without_following_it() {
        let tmp = tempfile::tempdir().unwrap();
        let unit_path = tmp.path().join("monux-server.service");
        // A pre-placed symlink at the unit path: the write (possibly running
        // as root) must replace the link, never clobber its target.
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::write(&elsewhere, "precious").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &unit_path).unwrap();
        write_unit_file(&unit_path, Role::Server, None).unwrap();
        let meta = std::fs::symlink_metadata(&unit_path).unwrap();
        assert!(!meta.file_type().is_symlink());
        assert_eq!(
            std::fs::read_to_string(&unit_path).unwrap(),
            unit_content(Role::Server)
        );
        // The symlink's old target is untouched, and no temp file lingers.
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "precious");
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 2);
    }

    #[test]
    fn status_parsing() {
        assert_eq!(parse_is_enabled("enabled\n"), Some(true));
        assert_eq!(parse_is_enabled("disabled\n"), Some(false));
        assert_eq!(parse_is_enabled("static\n"), None);
        assert_eq!(parse_is_enabled(""), None);
        assert_eq!(parse_is_active("active\n"), Some(true));
        assert_eq!(parse_is_active("inactive\n"), Some(false));
        assert_eq!(parse_is_active("failed\n"), Some(false));
        assert_eq!(parse_is_active("activating\n"), None);
        let (pid, since) = parse_show(
            "MainPID=417077\nActiveEnterTimestamp=Sat 2026-07-25 15:28:34 CEST\n",
        );
        assert_eq!(pid, Some(417077));
        assert_eq!(since.as_deref(), Some("2026-07-25T15:28:34"));
        // A unit that never ran: pid 0 and an empty timestamp are absent.
        let (pid, since) = parse_show("MainPID=0\nActiveEnterTimestamp=\n");
        assert_eq!(pid, None);
        assert_eq!(since, None);
        // An unexpected timestamp shape passes through unchanged.
        let (_, since) = parse_show("MainPID=1\nActiveEnterTimestamp=weird\n");
        assert_eq!(since.as_deref(), Some("weird"));
    }

    #[test]
    fn status_rendering_matrix() {
        // Nothing installed, nothing running.
        assert_eq!(
            render_role_status(Role::Client, &RoleStatus::default()),
            "client: not installed"
        );
        // Not installed, but a manually started daemon holds the lock.
        let status = RoleStatus {
            holder_pid: Some(4242),
            ..Default::default()
        };
        assert_eq!(
            render_role_status(Role::Server, &status),
            "server: not installed — running (manual, pid 4242)"
        );
        // Installed and enabled, unit down, nothing running.
        let status = RoleStatus {
            installed: true,
            enabled: Some(true),
            active: Some(false),
            ..Default::default()
        };
        assert_eq!(
            render_role_status(Role::Server, &status),
            "server: installed, enabled, inactive — not running"
        );
        // Installed, unit down, but a manual daemon holds the lock.
        let status = RoleStatus {
            installed: true,
            enabled: Some(false),
            active: Some(false),
            holder_pid: Some(4242),
            ..Default::default()
        };
        assert_eq!(
            render_role_status(Role::Server, &status),
            "server: installed, disabled, inactive — running (manual, pid 4242)"
        );
        // systemctl unavailable: unknowns render as ?, the lock probe still
        // speaks — without an autostarted/manual claim it can't back up.
        let status = RoleStatus {
            installed: true,
            holder_pid: Some(4242),
            ..Default::default()
        };
        assert_eq!(
            render_role_status(Role::Server, &status),
            "server: installed, enabled?, active? — running (pid 4242)"
        );
        // Active per systemd: autostarted regardless of the lock probe.
        let status = RoleStatus {
            installed: true,
            enabled: Some(true),
            active: Some(true),
            main_pid: Some(417077),
            active_since: Some("2026-07-25T15:28:34".to_string()),
            holder_pid: None,
        };
        assert_eq!(
            render_role_status(Role::Server, &status),
            "server: installed, enabled, active (pid 417077 since 2026-07-25T15:28:34) — running (autostarted)"
        );
        // Active without the show details: no pid/since parenthetical.
        let status = RoleStatus {
            installed: true,
            active: Some(true),
            ..Default::default()
        };
        assert_eq!(
            render_role_status(Role::Server, &status),
            "server: installed, enabled?, active — running (autostarted)"
        );
    }

    #[test]
    fn status_report_installed_active_server_only() {
        // A home-shaped unit dir so the unit path renders with '~'.
        let tmp = tempfile::tempdir().unwrap();
        let unit_dir = tmp.path().join("home/user/.config/systemd/user");
        std::fs::create_dir_all(&unit_dir).unwrap();
        std::fs::write(
            unit_dir.join("monux-server.service"),
            unit_content(Role::Server),
        )
        .unwrap();
        let target = test_target(&unit_dir);
        // Fabricated systemctl: the server unit is enabled and active.
        let query = |spec: &CmdSpec| -> Result<String> {
            Ok(match spec.manual_line().as_str() {
                "systemctl --user is-enabled monux-server.service" => "enabled\n".to_string(),
                "systemctl --user is-active monux-server.service" => "active\n".to_string(),
                "systemctl --user show -p MainPID,ActiveEnterTimestamp monux-server.service" => {
                    "MainPID=417077\nActiveEnterTimestamp=Sat 2026-07-25 15:28:34 CEST\n"
                        .to_string()
                }
                other => panic!("unexpected query: {}", other),
            })
        };
        // The lock probe: a live server daemon (the unit's pid), no client.
        let holder = |role: Role| match role {
            Role::Server => Some(417077),
            Role::Client => None,
        };
        let report = autostart_status_report(&target, &query, &holder);
        let expected = [
            "server: installed, enabled, active (pid 417077 since 2026-07-25T15:28:34) — running (autostarted)",
            "client: not installed",
            "unit: ~/.config/systemd/user/monux-server.service",
        ]
        .join("\n");
        assert_eq!(report, expected);
        // The golden report, for eyeballing with --nocapture.
        println!("{}", report);
    }

    #[test]
    fn status_report_no_units_at_all() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        // systemctl is never queried for units that aren't installed.
        let query = |spec: &CmdSpec| -> Result<String> {
            panic!("unexpected query: {}", spec.manual_line())
        };
        let holder = |_: Role| None;
        let report = autostart_status_report(&target, &query, &holder);
        assert_eq!(report, "server: not installed\nclient: not installed");
    }

    #[test]
    fn status_report_degrades_when_systemctl_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        for role in [Role::Server, Role::Client] {
            std::fs::write(tmp.path().join(role.unit_name()), unit_content(role)).unwrap();
        }
        let query = |_: &CmdSpec| -> Result<String> { bail!("systemctl not found") };
        let holder = |role: Role| match role {
            Role::Server => Some(4242),
            Role::Client => None,
        };
        let report = autostart_status_report(&target, &query, &holder);
        let unit = |role: Role| tmp.path().join(role.unit_name()).display().to_string();
        let expected = [
            "server: installed, enabled?, active? — running (pid 4242)".to_string(),
            "client: installed, enabled?, active? — not running".to_string(),
            format!("unit: {}", unit(Role::Server)),
            format!("unit: {}", unit(Role::Client)),
            // Both roles hit the same spawn failure; the note prints once.
            "[note] autostart: could not query systemctl (systemctl not found); reporting the unit file and the lock state only".to_string(),
        ]
        .join("\n");
        assert_eq!(report, expected);
    }

    #[test]
    fn status_queries_are_read_only_and_skip_show_when_inactive() {
        let tmp = tempfile::tempdir().unwrap();
        let target = test_target(tmp.path());
        for role in [Role::Server, Role::Client] {
            std::fs::write(tmp.path().join(role.unit_name()), unit_content(role)).unwrap();
        }
        let asked = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let rec = asked.clone();
        let query = move |spec: &CmdSpec| -> Result<String> {
            rec.borrow_mut().push(spec.manual_line());
            Ok("disabled\n".to_string())
        };
        let holder = |_: Role| None;
        let report = autostart_status_report(&target, &query, &holder);
        // "disabled" parses as enabled:false and active:None; the show query
        // (pid/timestamp) only runs for an ACTIVE unit, so it never appears.
        assert_eq!(
            *asked.borrow(),
            vec![
                "systemctl --user is-enabled monux-server.service".to_string(),
                "systemctl --user is-active monux-server.service".to_string(),
                "systemctl --user is-enabled monux-client.service".to_string(),
                "systemctl --user is-active monux-client.service".to_string(),
            ]
        );
        assert!(report.contains("server: installed, disabled, active? — not running"));
        assert!(report.contains("client: installed, disabled, active? — not running"));
    }

    #[test]
    fn display_unit_path_uses_tilde_under_home() {
        let home = Path::new("/home/user");
        let unit_dir = home.join(SYSTEMD_USER_UNIT_DIR);
        let unit = unit_dir.join("monux-server.service");
        assert_eq!(
            display_unit_path(&unit_dir, &unit),
            "~/.config/systemd/user/monux-server.service"
        );
        // A unit dir NOT shaped like $HOME/.config/systemd/user (tests use
        // plain tempdirs) falls back to the absolute path.
        let plain = Path::new("/tmp/x");
        assert_eq!(
            display_unit_path(plain, &plain.join("monux-server.service")),
            "/tmp/x/monux-server.service"
        );
    }

    #[test]
    fn ensure_desktop_shortcut_creates_only_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        // Missing: written.
        assert!(ensure_desktop_shortcut(home, None).unwrap());
        let path = applications_dir_from(home, None).join(DESKTOP_SHORTCUT_NAME);
        assert!(path.exists());
        // Present: left alone (even user-edited), and reports so.
        std::fs::write(&path, "user edits").unwrap();
        assert!(!ensure_desktop_shortcut(home, None).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "user edits");
    }

    #[test]
    fn desktop_shortcut_content_is_a_valid_entry() {
        let content = desktop_shortcut_content();
        assert_eq!(
            content,
            "[Desktop Entry]\nType=Application\nName=monux tray\nComment=Show the monux tray indicator (starts it when no daemon is running)\nExec=monux gui tray show\nTerminal=false\nCategories=Utility;\nIcon=input-keyboard\n"
        );
        // Every line is a key=value under the one section header.
        let mut lines = content.lines();
        assert_eq!(lines.next(), Some("[Desktop Entry]"));
        for line in lines {
            assert!(line.contains('='), "bad desktop entry line: {}", line);
        }
    }

    #[test]
    fn applications_dir_resolution_honors_xdg_data_home() {
        let home = Path::new("/home/user");
        // Unset: the spec default under home.
        assert_eq!(
            applications_dir_from(home, None),
            PathBuf::from("/home/user/.local/share/applications")
        );
        // An absolute $XDG_DATA_HOME takes precedence.
        assert_eq!(
            applications_dir_from(home, Some(std::ffi::OsStr::new("/data"))),
            PathBuf::from("/data/applications")
        );
        // Empty and relative values are invalid per spec: ignored.
        assert_eq!(
            applications_dir_from(home, Some(std::ffi::OsStr::new(""))),
            PathBuf::from("/home/user/.local/share/applications")
        );
        assert_eq!(
            applications_dir_from(home, Some(std::ffi::OsStr::new("relative/data"))),
            PathBuf::from("/home/user/.local/share/applications")
        );
    }

    #[test]
    fn desktop_shortcut_write_is_atomic_and_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp
            .path()
            .join("applications")
            .join(DESKTOP_SHORTCUT_NAME);
        // The applications dir is created; the content lands as built.
        write_desktop_shortcut(&path, None).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            desktop_shortcut_content()
        );
        // A second write replaces without error (idempotent), leaving no
        // temp files behind.
        write_desktop_shortcut(&path, None).unwrap();
        assert_eq!(std::fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }
}
