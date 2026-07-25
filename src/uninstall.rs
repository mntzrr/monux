//! `monux system uninstall`: removes monux from this machine. The binary is always
//! at hand even when the repo clone (and its uninstall.sh) is gone, so the
//! uninstaller lives in the binary itself; uninstall.sh is a thin wrapper.
//!
//! Order matters:
//! 0. the user confirms the destructive run up front (skipped with --yes;
//!    without a terminal the run aborts instead of guessing);
//! 1. running server/client instances are asked to shut down first (a running
//!    server may hold input devices grabbed);
//! 2. the user is asked about ~/.config/monux (identity keypair + peer
//!    approvals) — only on a terminal, otherwise it is kept;
//! 3. root-owned system settings persisted by `monux setup` — the
//!    files, plus the netfilter DSCP marks — and the /usr/local/bin link are
//!    removed via sudo subprocesses (unlike setup, no sudo re-exec: uninstall
//!    must not swap its own process image mid-flight);
//! 4. the per-user autostart units `monux setup --autostart` installed are
//!    disabled and removed (otherwise systemd retries the deleted binary at
//!    every login);
//! 5. the running binary itself plus stale copies are removed (self-delete is
//!    fine on Linux: the file unlinks while the process keeps running);
//! 6. ~/.config/monux is removed, only if the user said yes.
//!
//! The `input` group membership is deliberately left alone (it may predate
//! monux or be used by other software); a hint with the undo command is printed.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::{setup, single_instance};

// --- Hotspot teardown ------------------------------------------------------
// The 'monux-direct' WiFi hotspot feature was removed in v10.0.0, but a
// machine that once ran 'monux setup --hotspot'/'--hotspot-join' can still
// have the unit, configs, NAT table, vif and NM profile installed — the
// uninstaller keeps tearing all of it down. These constants therefore moved
// here from setup.rs with the feature's removal.

/// Persistent net.ipv4.ip_forward enablement the removed hotspot's NAT
/// needed ('monux setup --hotspot' wrote it).
const IP_FORWARD_SYSCTL_PATH: &str = "/etc/sysctl.d/90-monux-ip-forward.conf";
/// systemd unit bringing up the AP interface, hostapd, dnsmasq and the NAT.
const HOTSPOT_UNIT_PATH: &str = "/etc/systemd/system/monux-hotspot.service";
/// hostapd config for the hotspot AP (ssid + WPA2 psk lived here).
const HOSTAPD_CONF_PATH: &str = "/etc/monux/hostapd.conf";
/// dnsmasq config (DHCP + DNS for hotspot clients).
const DNSMASQ_CONF_PATH: &str = "/etc/monux/dnsmasq.conf";
/// Directory holding the hotspot's hostapd/dnsmasq configuration.
const HOTSPOT_CONF_DIR: &str = "/etc/monux";
/// Name of the dedicated AP interface the hotspot ran on, driven by hostapd.
const AP_IFACE_NAME: &str = "monux-ap";
/// nftables table for the hotspot's NAT masquerade (removed on unit stop).
const HOTSPOT_NAT_TABLE: &str = "monux-hotspot-nat";
/// Name of the NetworkManager connection profile for the direct, routerless
/// KVM link: the client's join profile, or a migration leftover on the host.
const HOTSPOT_CON_NAME: &str = "monux-direct";
/// Priority of the policy rule that routed the hotspot subnet around a VPN
/// (one above Mullvad's 32764 suppress rule, so it won).
const VPN_WORKAROUND_RULE_PRIORITY: u32 = 32763;
/// The comment tag on the nftables rule setup inserted into Mullvad's table,
/// so teardown finds it even after Mullvad regenerates everything around it.
const VPN_WORKAROUND_COMMENT: &str = "monux-hotspot";

/// Handles of our comment-tagged rules in `nft -a list table inet mullvad`
/// output (the tag lets teardown find the rules after Mullvad rewrites the
/// rest of its table).
fn monux_rule_handles(nft_list_output: &str) -> Vec<u64> {
    nft_list_output
        .lines()
        .filter(|line| line.contains(VPN_WORKAROUND_COMMENT))
        .filter_map(|line| {
            line.rsplit_once("handle ")
                .and_then(|(_, handle)| handle.trim().parse().ok())
        })
        .collect()
}

/// Runs the uninstall. Best-effort throughout: individual failures downgrade
/// to notes with manual-removal hints instead of aborting the remaining steps.
pub fn run(assume_yes: bool) -> Result<()> {
    // Nothing is touched before this confirmation lands.
    if !assume_yes && !confirm_uninstall() {
        println!("Aborted; nothing was removed.");
        return Ok(());
    }

    // First: a running server may hold input devices grabbed.
    stop_running_instances();

    let home = target_home(
        unsafe { libc::geteuid() },
        std::env::var("SUDO_USER").ok().as_deref(),
    )?;
    let exe = current_exe_path()?;
    let mut plan = plan(&home, &exe);

    if plan.config_dir.is_some() {
        plan.remove_config = prompt_remove_config();
    }

    execute(&plan);
    Ok(())
}

/// The home the uninstall targets. Running as root is the `sudo monux system
/// uninstall` path; sudo configurations that reset $HOME (sudo -H, or HOME
/// missing from env_keep) would then aim every per-user removal — the stale
/// binaries, ~/.config/monux, the autostart units — at /root, silently
/// missing the real install. Resolve the INVOKING user's home via SUDO_USER
/// instead (mirroring setup.rs's autostart target), and refuse to guess when
/// there is no invoking user to aim at. The euid is a parameter so the
/// decision is unit-testable.
fn target_home(euid: u32, sudo_user: Option<&str>) -> Result<PathBuf> {
    if euid != 0 {
        return home::home_dir().context("No home dir found: unable to locate binaries and config");
    }
    match sudo_user {
        Some(name) if !name.is_empty() && name != "root" => {
            let (home, _uid, _gid) = setup::passwd_entry(name)?;
            Ok(home)
        }
        _ => anyhow::bail!(
            "Running as root with no invoking user (SUDO_USER unset): run the uninstall as the user, not root — as root it would target /root instead of the user's home"
        ),
    }
}

/// What exists and what will be removed, computed up front so the destructive
/// stage is a simple replay (and so this logic is unit-testable against
/// temporary directories).
struct Plan {
    /// Existing root-owned paths to remove via sudo: the system settings
    /// persisted by `monux setup`, plus /usr/local/bin/monux when it is
    /// clearly ours.
    root_owned: Vec<PathBuf>,
    /// User-owned binaries to remove directly: the running executable and
    /// stale copies from previous install locations/names.
    user_binaries: Vec<PathBuf>,
    /// ~/.config/monux, when it exists.
    config_dir: Option<PathBuf>,
    /// Where the per-user autostart units 'monux setup --autostart' writes
    /// live (home-relative), checked at execution time.
    autostart_unit_dir: PathBuf,
    /// Where the 'mx' alias symlink lives (home-relative), checked at
    /// execution time.
    alias_dir: PathBuf,
    /// Whether to remove the config dir; set by the interactive prompt.
    remove_config: bool,
}

fn plan(home: &Path, current_exe: &Path) -> Plan {
    let system_paths = [
        PathBuf::from(setup::UDEV_RULE_PATH),
        PathBuf::from(setup::MODULES_LOAD_PATH),
        PathBuf::from(setup::NM_POWERSAVE_CONF_PATH),
        PathBuf::from(setup::SYSCTL_BUF_CONF_PATH),
        PathBuf::from(IP_FORWARD_SYSCTL_PATH),
        PathBuf::from(HOTSPOT_UNIT_PATH),
        PathBuf::from(HOSTAPD_CONF_PATH),
        PathBuf::from(DNSMASQ_CONF_PATH),
    ];
    plan_impl(
        home,
        current_exe,
        &system_paths,
        Path::new("/usr/local/bin/monux"),
    )
}

fn plan_impl(home: &Path, current_exe: &Path, system_paths: &[PathBuf], usr_local: &Path) -> Plan {
    let mut root_owned: Vec<PathBuf> = system_paths
        .iter()
        .filter(|p| p.exists())
        .cloned()
        .collect();
    if let Some(path) = removable_usr_local(usr_local, current_exe, home) {
        root_owned.push(path);
    }

    let mut user_binaries = vec![current_exe.to_path_buf()];
    // Stale copies from previous install locations/names (see install.sh).
    for stale in [
        ".cargo/bin/monux",
        ".cargo/bin/nikau",
        ".local/bin/nikau",
        ".local/bin/monux",
    ] {
        let candidate = home.join(stale);
        if candidate.exists() && !same_file(&candidate, current_exe) {
            user_binaries.push(candidate);
        }
    }
    // Root-owned paths go via sudo; don't also try (and fail) them as the user.
    user_binaries.retain(|p| !root_owned.contains(p));

    let config_dir = home.join(".config").join("monux");
    Plan {
        root_owned,
        user_binaries,
        config_dir: config_dir.is_dir().then_some(config_dir),
        autostart_unit_dir: home.join(setup::SYSTEMD_USER_UNIT_DIR),
        alias_dir: home.join(".local").join("bin"),
        remove_config: false,
    }
}

/// /usr/local/bin/monux qualifies for removal only when it is clearly ours:
/// a symlink resolving to the running binary or into the user's own install
/// locations (install.sh links it to ~/.local/bin/monux), or a file identical
/// to the running binary. Anything else there — including another tool's
/// symlink — is left alone.
fn removable_usr_local(usr_local: &Path, current_exe: &Path, home: &Path) -> Option<PathBuf> {
    let meta = fs::symlink_metadata(usr_local).ok()?;
    if meta.file_type().is_symlink() {
        let ours =
            same_file(usr_local, current_exe) || symlink_target_is_user_install(usr_local, home);
        return ours.then(|| usr_local.to_path_buf());
    }
    files_identical(usr_local, current_exe).then(|| usr_local.to_path_buf())
}

/// Whether a symlink's target is one of the user's own monux install
/// locations (~/.local/bin/monux, ~/.cargo/bin/monux) — the links install.sh
/// creates. A dangling link (the binary already removed) still counts.
fn symlink_target_is_user_install(link: &Path, home: &Path) -> bool {
    let Ok(target) = fs::read_link(link) else {
        return false;
    };
    // A relative target resolves against the link's own directory (join
    // leaves an absolute target unchanged).
    let target = link
        .parent()
        .map(|parent| parent.join(&target))
        .unwrap_or(target);
    [".local/bin/monux", ".cargo/bin/monux"]
        .iter()
        .any(|install| same_file(&target, &home.join(install)))
}

fn files_identical(a: &Path, b: &Path) -> bool {
    match (fs::read(a), fs::read(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// True when both paths resolve to the same file (or are the same path).
fn same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn execute(plan: &Plan) {
    remove_root_owned(&plan.root_owned);
    remove_qos_marking();
    remove_hotspot_profile();
    remove_autostart_units(&plan.autostart_unit_dir, &mut systemctl_user);

    for path in &plan.user_binaries {
        match fs::remove_file(path) {
            Ok(()) => println!("Removed {}", path.display()),
            Err(e) => println!("note: couldn't remove {}: {}", path.display(), e),
        }
    }

    // The 'mx' alias — removed only when it's our symlink (alias::remove
    // leaves a foreign 'mx' alone).
    match crate::alias::remove(&plan.alias_dir) {
        Ok(true) => println!("Removed the 'mx' alias from {}", plan.alias_dir.display()),
        Ok(false) => {}
        Err(e) => println!("note: couldn't remove the 'mx' alias: {}", e),
    }

    match (&plan.config_dir, plan.remove_config) {
        (Some(dir), true) => match fs::remove_dir_all(dir) {
            Ok(()) => println!("Removed {}", dir.display()),
            Err(e) => println!("note: couldn't remove {}: {}", dir.display(), e),
        },
        (Some(_), false) => println!(
            "Kept ~/.config/monux (identity + approvals); a reinstall will pick up where it left off."
        ),
        (None, _) => {}
    }

    print_group_hint();
    println!("monux uninstalled.");
}

/// Removes root-owned paths via sudo subprocesses (sudo prompts inline).
/// A failure downgrades to a manual-removal hint; the rest of the uninstall
/// continues regardless.
fn remove_root_owned(paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    println!("Removing system settings persisted by 'monux setup'...");
    let removed = Command::new("sudo")
        .arg("rm")
        .arg("-f")
        .args(paths)
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !removed {
        println!("note: couldn't remove root-owned files (sudo failed); remove them manually:");
        for path in paths {
            println!("  sudo rm -f {}", path.display());
        }
        return;
    }
    // Reload udev so the removed rule stops applying, and restore the
    // kernel-default UDP buffer limits live: the persisted sysctl config is
    // gone, this also reverts the running values without waiting for reboot.
    let _ = Command::new("sudo")
        .args(["udevadm", "control", "--reload"])
        .status();
    let _ = Command::new("sudo")
        .args([
            "sysctl",
            "-w",
            "net.core.rmem_max=212992",
            "net.core.wmem_max=212992",
        ])
        .status();
    println!("Removed udev rules, uinput module load, WiFi powersave and UDP buffer configs.");
    if paths
        .iter()
        .any(|p| p == Path::new(setup::NM_POWERSAVE_CONF_PATH))
    {
        println!("note: WiFi powersave re-enables on next NetworkManager restart/reboot.");
    }
}

/// Removes the netfilter DSCP marks 'monux setup' installs. The rules
/// are self-describing (our own nftables table; two exact iptables rules), so
/// removal is idempotent and needs no state. Non-interactive: when sudo would
/// have to ask for a password (nothing earlier in the uninstall warmed the
/// credential cache), the rules are left alone with a manual hint instead —
/// an unexpected prompt mid-uninstall is worse than leftover QoS marks, which
/// are inert without monux traffic.
fn remove_qos_marking() {
    let sudo_ready = Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !sudo_ready {
        println!("note: DSCP QoS rules (if any were installed) were left in place; remove them with:");
        println!(
            "  sudo nft delete table inet {}  # or:",
            setup::NFT_QOS_TABLE
        );
        for spec in setup::iptables_qos_rule_specs() {
            println!("  sudo iptables -t mangle -D OUTPUT {}", spec.join(" "));
        }
        return;
    }
    // nftables variant: one delete undoes the whole feature. iptables variant:
    // delete both exact rules. Absence of either backend or rule is fine.
    let _ = Command::new("sudo")
        .args(["nft", "delete", "table", "inet", setup::NFT_QOS_TABLE])
        .status();
    for spec in setup::iptables_qos_rule_specs() {
        let _ = Command::new("sudo")
            .arg("iptables")
            .args(["-t", "mangle", "-D", "OUTPUT"])
            .args(&spec)
            .status();
    }
    println!("Removed DSCP QoS marking rules (if any were installed).");
}

/// Removes the hotspot pieces 'monux setup --hotspot/--hotspot-join'
/// installed before the feature was removed in v10.0.0: the monux-hotspot
/// systemd unit (stop+disable first, so the AP interface, NAT and dnsmasq
/// come down cleanly), /etc/monux, the NAT table and the vif if they linger,
/// and the 'monux-direct' NetworkManager profile (the client's join profile,
/// or a migration leftover on the host). All self-describing and idempotent.
/// Same non-interactive rule as the QoS cleanup: only attempted when sudo
/// won't prompt.
fn remove_hotspot_profile() {
    let sudo_ready = Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !sudo_ready {
        println!(
            "note: the hotspot (monux-hotspot unit / '{}' profile, if installed) was left in place; remove it with:",
            HOTSPOT_CON_NAME
        );
        println!("  sudo systemctl disable --now monux-hotspot");
        println!(
            "  sudo rm -rf {} {}",
            HOTSPOT_CONF_DIR, HOTSPOT_UNIT_PATH
        );
        println!("  sudo nmcli connection delete {}", HOTSPOT_CON_NAME);
        return;
    }
    // Stop+disable first: stopping runs the unit's ExecStopPost teardown
    // (dnsmasq, NAT table, vif). Works even when the unit file was already
    // removed above — systemd still has the unit in memory until the reload.
    let _ = Command::new("sudo")
        .args(["systemctl", "stop", "monux-hotspot"])
        .status();
    let _ = Command::new("sudo")
        .args(["systemctl", "disable", "monux-hotspot"])
        .status();
    let _ = Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status();
    let _ = Command::new("sudo")
        .args(["rm", "-rf", HOTSPOT_CONF_DIR])
        .status();
    // Belt-and-suspenders for a crashed or hand-built state.
    let _ = Command::new("sudo")
        .args(["nft", "delete", "table", "ip", HOTSPOT_NAT_TABLE])
        .status();
    let _ = Command::new("sudo")
        .args(["iw", "dev", AP_IFACE_NAME, "del"])
        .status();
    let _ = Command::new("sudo")
        .args(["nmcli", "connection", "delete", HOTSPOT_CON_NAME])
        .status();
    println!("Removed the monux hotspot (unit, configs, NAT, AP interface) and the '{}' profile (if installed).", HOTSPOT_CON_NAME);
    // The VPN workaround rules setup may have installed: the tagged rule in
    // Mullvad's table, and the policy rule by its priority. Best-effort —
    // anything already gone is skipped silently.
    let priority = VPN_WORKAROUND_RULE_PRIORITY.to_string();
    let _ = Command::new("sudo")
        .args(["ip", "rule", "del", "priority", &priority])
        .status();
    if let Some(list) = sudo_output(&["nft", "-a", "list", "table", "inet", "mullvad"]) {
        for handle in monux_rule_handles(&list) {
            let rule = format!("delete rule inet mullvad forward handle {}", handle);
            let _ = Command::new("sudo").args(["nft", &rule]).status();
        }
    }
}

/// Removes the per-user autostart units 'monux setup --autostart' installs:
/// left in place and enabled, systemd would retry the deleted binary at every
/// login. Best-effort and user-level (no sudo): disable+stop both services
/// via the user's manager (tolerating its absence — e.g. uninstall run from a
/// root shell — with a note), remove the unit files, then daemon-reload so
/// systemd forgets them. Nothing happens at all when no unit files exist.
/// The systemctl runner is a seam so tests stay off the real systemd.
fn remove_autostart_units(unit_dir: &Path, systemctl: &mut dyn FnMut(&[&str]) -> bool) {
    const UNITS: [&str; 2] = ["monux-server.service", "monux-client.service"];
    if !UNITS.iter().any(|unit| unit_dir.join(unit).exists()) {
        return;
    }
    let mut disable: Vec<&str> = vec!["disable", "--now"];
    disable.extend(UNITS);
    if !systemctl(&disable) {
        println!(
            "note: couldn't disable the monux user services (no reachable user manager); after the next login, run: systemctl --user disable --now {}",
            UNITS.join(" ")
        );
    }
    for unit in UNITS {
        let path = unit_dir.join(unit);
        match fs::remove_file(&path) {
            Ok(()) => println!("Removed {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => println!("note: couldn't remove {}: {}", path.display(), e),
        }
    }
    // Forget the removed units; a failure here is harmless.
    let _ = systemctl(&["daemon-reload"]);
}

/// `systemctl --user <args>` for the autostart cleanup; false when the
/// command can't run or fails (the cleanup tolerates either and moves on).
fn systemctl_user(args: &[&str]) -> bool {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Runs sudo non-interactively with output captured; None when sudo needs a
/// password or the command fails (best-effort cleanup treats it as "skip").
fn sudo_output(args: &[&str]) -> Option<String> {
    let out = Command::new("sudo").arg("-n").args(args).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        None
    }
}

/// Asks any running monux server and client to shut down gracefully, waiting
/// for them to exit. Reuses the single-instance machinery: acquiring the lock
/// SIGTERMs a live holder and waits for it to release; the lock is dropped
/// right away since uninstall itself needs no instance protection. Honors
/// MONUX_LOCK_DIR. Best-effort: a holder we can't signal (e.g. one running as
/// root) only warrants a note — the files are removed regardless.
fn stop_running_instances() {
    for kind in ["server", "client"] {
        match single_instance::acquire(kind) {
            Ok(lock) => {
                if lock.took_over {
                    println!("Stopped the running monux {}", kind);
                }
                drop(lock);
            }
            Err(e) => println!("note: couldn't stop the running monux {}: {}", kind, e),
        }
    }
}

/// Pre-flight confirmation for the destructive uninstall, reading from
/// /dev/tty like the config prompt below. Without a usable terminal (cron,
/// CI, a pipe) there is no one to ask, so the run aborts: unattended removal
/// needs --yes.
fn confirm_uninstall() -> bool {
    let tty = match fs::File::open("/dev/tty") {
        Ok(tty) => tty,
        Err(_) => {
            println!("No terminal to ask for confirmation (and --yes not given); aborting.");
            return false;
        }
    };
    print!("This will stop any running monux daemon and remove the binary, /usr/local/bin link, and persisted system settings. Continue? [y/N] ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    match io::BufReader::new(tty).read_line(&mut answer) {
        Ok(_) => answered_yes(&answer),
        Err(_) => false,
    }
}

/// Asks whether to also remove the config dir, reading from /dev/tty so the
/// prompt works even when stdin is a pipe. /dev/tty may exist but be
/// unopenable (cron, CI, no controlling terminal), so probe by opening it
/// first; without a usable terminal the config is kept.
fn prompt_remove_config() -> bool {
    let tty = match fs::File::open("/dev/tty") {
        Ok(tty) => tty,
        Err(_) => return false,
    };
    print!("Also remove ~/.config/monux (identity keypair and peer approvals)? [y/N] ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    match io::BufReader::new(tty).read_line(&mut answer) {
        Ok(_) => answered_yes(&answer),
        Err(_) => false,
    }
}

/// Interprets the config-removal answer; anything but an explicit yes keeps
/// the config (the prompt defaults to no).
fn answered_yes(answer: &str) -> bool {
    matches!(answer.trim_start().chars().next(), Some('y' | 'Y'))
}

/// The `input` group membership is left alone (it may predate monux); print
/// the undo command instead, mirroring uninstall.sh.
fn print_group_hint() {
    let in_input_group = Command::new("id")
        .arg("-nG")
        .output()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .any(|g| g == "input")
        })
        .unwrap_or(false);
    if in_input_group {
        let user = std::env::var("USER").unwrap_or_else(|_| "$USER".to_string());
        println!("note: your user is still in the 'input' group. If you added it only");
        println!("for monux, remove it with: sudo gpasswd -d {} input", user);
    }
}

/// Own executable path, with the " (deleted)" suffix Linux appends when the
/// file was replaced while running (auto-update) trimmed off — the plain
/// path is what to remove.
fn current_exe_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("Failed to find our own executable")?;
    Ok(PathBuf::from(
        exe.to_string_lossy().trim_end_matches(" (deleted)"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(path: &Path, contents: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn tagged_rule_handles_are_found() {
        let list = "table inet mullvad {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tip saddr 10.42.0.0/24 accept comment \"monux-hotspot\" # handle 7\n\t\tct state established,related accept # handle 2\n\t}\n}\n";
        assert_eq!(monux_rule_handles(list), vec![7]);
        let untagged = "table inet mullvad {\n\tchain forward {\n\t\tct state established,related accept # handle 2\n\t}\n}\n";
        assert!(monux_rule_handles(untagged).is_empty());
        assert!(monux_rule_handles("").is_empty());
    }

    #[test]
    fn plan_collects_only_existing_system_files() {
        let tmp = tempfile::tempdir().unwrap();
        let system_paths = [
            tmp.path().join("udev.rules"),
            tmp.path().join("modules-load.conf"),
            tmp.path().join("nm-powersave.conf"),
            tmp.path().join("sysctl.conf"),
        ];
        write_file(&system_paths[0], b"rule");
        write_file(&system_paths[2], b"conf");
        let home = tmp.path().join("home");
        let exe = tmp.path().join("monux");
        write_file(&exe, b"binary");
        let plan = plan_impl(
            &home,
            &exe,
            &system_paths,
            &tmp.path().join("usr-local-monux"),
        );
        assert_eq!(
            plan.root_owned,
            vec![system_paths[0].clone(), system_paths[2].clone()]
        );
        assert_eq!(plan.user_binaries, vec![exe]);
    }

    #[test]
    fn usr_local_symlink_is_removable() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("monux");
        write_file(&exe, b"binary");
        let link = tmp.path().join("usr-local-monux");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        let plan = plan_impl(&tmp.path().join("home"), &exe, &[], &link);
        assert_eq!(plan.root_owned, vec![link]);
    }

    #[test]
    fn usr_local_identical_file_is_removable() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("monux");
        write_file(&exe, b"binary");
        let copy = tmp.path().join("usr-local-monux");
        write_file(&copy, b"binary");
        let plan = plan_impl(&tmp.path().join("home"), &exe, &[], &copy);
        assert_eq!(plan.root_owned, vec![copy]);
    }

    #[test]
    fn usr_local_unrelated_file_is_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("monux");
        write_file(&exe, b"binary");
        let unrelated = tmp.path().join("usr-local-monux");
        write_file(&unrelated, b"some other tool");
        let plan = plan_impl(&tmp.path().join("home"), &exe, &[], &unrelated);
        assert!(plan.root_owned.is_empty());
    }

    #[test]
    fn usr_local_missing_is_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("monux");
        write_file(&exe, b"binary");
        let plan = plan_impl(
            &tmp.path().join("home"),
            &exe,
            &[],
            &tmp.path().join("usr-local-monux"),
        );
        assert!(plan.root_owned.is_empty());
    }

    #[test]
    fn usr_local_foreign_symlink_is_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("monux");
        write_file(&exe, b"binary");
        // Another tool's symlink — even to a byte-identical file — is not
        // ours and must survive the uninstall.
        let foreign = tmp.path().join("some-other-tool");
        write_file(&foreign, b"binary");
        let link = tmp.path().join("usr-local-monux");
        std::os::unix::fs::symlink(&foreign, &link).unwrap();
        let plan = plan_impl(&tmp.path().join("home"), &exe, &[], &link);
        assert!(plan.root_owned.is_empty());
    }

    #[test]
    fn usr_local_user_install_symlink_is_removable() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let exe = tmp.path().join("monux");
        write_file(&exe, b"binary");
        // install.sh links /usr/local/bin/monux into the user's own install
        // locations; the link is ours even when its target is already gone
        // (dangling), e.g. after the binary was removed by hand.
        let link = tmp.path().join("usr-local-monux");
        std::os::unix::fs::symlink(home.join(".local/bin/monux"), &link).unwrap();
        let plan = plan_impl(&home, &exe, &[], &link);
        assert_eq!(plan.root_owned, vec![link]);
    }

    #[test]
    fn autostart_units_are_disabled_and_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let unit_dir = tmp.path().join("systemd-user");
        write_file(&unit_dir.join("monux-server.service"), b"unit");
        write_file(&unit_dir.join("monux-client.service"), b"unit");
        let recorded: std::rc::Rc<std::cell::RefCell<Vec<Vec<String>>>> =
            std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let rec = recorded.clone();
        let mut systemctl = move |args: &[&str]| -> bool {
            rec.borrow_mut()
                .push(args.iter().map(|s| s.to_string()).collect());
            true
        };
        remove_autostart_units(&unit_dir, &mut systemctl);
        assert!(!unit_dir.join("monux-server.service").exists());
        assert!(!unit_dir.join("monux-client.service").exists());
        // Disabled first, then a daemon-reload after the files are gone.
        let calls = recorded.borrow();
        assert_eq!(
            calls.as_slice(),
            vec![
                vec!["disable", "--now", "monux-server.service", "monux-client.service"],
                vec!["daemon-reload"],
            ]
        );
    }

    #[test]
    fn autostart_removal_tolerates_systemctl_failure_and_absence() {
        let tmp = tempfile::tempdir().unwrap();
        let unit_dir = tmp.path().join("systemd-user");
        write_file(&unit_dir.join("monux-server.service"), b"unit");
        // A failing systemctl (no reachable user manager) must not stop the
        // unit files from being removed.
        let mut failing = |_: &[&str]| false;
        remove_autostart_units(&unit_dir, &mut failing);
        assert!(!unit_dir.join("monux-server.service").exists());
        // No unit files planted: systemctl is never invoked.
        let mut panicking = |_: &[&str]| -> bool { panic!("no systemctl calls without unit files") };
        remove_autostart_units(&unit_dir, &mut panicking);
    }

    #[test]
    fn stale_binaries_collected_and_deduped_against_current_exe() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        // The current exe is the canonical install location: listed once.
        let exe = home.join(".local/bin/monux");
        write_file(&exe, b"binary");
        let cargo_monux = home.join(".cargo/bin/monux");
        let local_nikau = home.join(".local/bin/nikau");
        write_file(&cargo_monux, b"old");
        write_file(&local_nikau, b"old");
        // ~/.cargo/bin/nikau deliberately absent.
        let plan = plan_impl(&home, &exe, &[], &tmp.path().join("usr-local-monux"));
        assert_eq!(plan.user_binaries, vec![exe, cargo_monux, local_nikau]);
    }

    #[test]
    fn root_owned_current_exe_is_removed_via_sudo_only() {
        // Running from /usr/local/bin/monux directly: the user can't unlink a
        // root-owned path, so it must only appear in the sudo list.
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("usr-local-monux");
        write_file(&exe, b"binary");
        let plan = plan_impl(&tmp.path().join("home"), &exe, &[], &exe);
        assert_eq!(plan.root_owned, vec![exe]);
        assert!(plan.user_binaries.is_empty());
    }

    #[test]
    fn config_dir_detected_only_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let exe = tmp.path().join("monux");
        write_file(&exe, b"binary");
        let missing_usr_local = tmp.path().join("usr-local-monux");
        let plan = plan_impl(&home, &exe, &[], &missing_usr_local);
        assert_eq!(plan.config_dir, None);
        assert!(!plan.remove_config);

        let config_dir = home.join(".config").join("monux");
        fs::create_dir_all(&config_dir).unwrap();
        let plan = plan_impl(&home, &exe, &[], &missing_usr_local);
        assert_eq!(plan.config_dir, Some(config_dir));
    }

    #[test]
    fn target_home_non_root_uses_own_home() {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            // The test suite running as root: the non-root branch can't be
            // exercised meaningfully (it would still return A home).
            return;
        }
        assert_eq!(
            target_home(euid, None).unwrap(),
            home::home_dir().unwrap()
        );
        // SUDO_USER is irrelevant for a non-root run.
        assert_eq!(
            target_home(euid, Some("someone")).unwrap(),
            home::home_dir().unwrap()
        );
    }

    #[test]
    fn target_home_root_without_invoking_user_bails() {
        for sudo_user in [None, Some(""), Some("root")] {
            let err = target_home(0, sudo_user).unwrap_err().to_string();
            assert!(
                err.contains("run the uninstall as the user, not root"),
                "unexpected error for {:?}: {}",
                sudo_user,
                err
            );
        }
    }

    #[test]
    fn target_home_root_resolves_the_invoking_users_home() {
        // The current user's name, resolved from our own uid: as root via
        // sudo, SUDO_USER holds exactly this kind of name.
        let name = unsafe {
            let pw = libc::getpwuid(libc::geteuid());
            assert!(!pw.is_null(), "current uid must have a passwd entry");
            std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned()
        };
        let home = target_home(0, Some(&name)).unwrap();
        // The resolved home is the named user's passwd home — never /root's
        // — and it exists.
        assert!(home.is_dir(), "{} should be a real home", home.display());
        if name != "root" {
            assert_ne!(home, Path::new("/root"));
        }
    }

    #[test]
    fn answered_yes_parsing() {
        assert!(answered_yes("y"));
        assert!(answered_yes("Y\n"));
        assert!(answered_yes("yes"));
        assert!(answered_yes(" y \n"));
        assert!(!answered_yes(""));
        assert!(!answered_yes("\n"));
        assert!(!answered_yes("n"));
        assert!(!answered_yes("no\n"));
    }
}
