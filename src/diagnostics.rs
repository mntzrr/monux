//! Bug-report bundles: what a user hands us when something goes wrong.
//!
//! One collector feeds both delivery paths — the tray's "Copy diagnostics"
//! and the `monux diagnostics` CLI — so a report filed from a terminal, an
//! SSH session or a headless box carries exactly what a tray user's report
//! carries. That matters more than it sounds: the bundle used to live behind
//! a GUI menu item, which is unreachable on precisely the machines whose
//! problems are hardest to reproduce.
//!
//! A bundle has four parts:
//!
//! - the daemon's **state dump** and **recent logs**, from the control
//!   socket's `diagnostics` command (control.rs);
//! - the **environment** the daemon runs in — kernel, session, device
//!   permissions, unit state. Collected inside the DAEMON, not the CLI: an
//!   autostarted daemon's environment differs from the invoking shell's in
//!   exactly the ways that cause the bugs being reported (a systemd unit
//!   that never saw `WAYLAND_DISPLAY`), so collecting it here would describe
//!   the wrong process. The CLI only falls back to its own environment when
//!   no daemon answers at all — the "it won't even start" report;
//! - **journal lines** for the role's systemd unit, which cover what the
//!   in-memory ring can't: evicted history, and the logs of a daemon that
//!   died (its ring died with it — the single most valuable report there is);
//! - optionally the **peer's** bundle, since a KVM problem is a two-machine
//!   problem (see `peer` below).
//!
//! Redaction is opt-in (`--redact`) and documented in [`PRIVACY_NOTE`]: a
//! user pasting into a public issue tracker should be able to tell what they
//! are about to publish without reading this source file.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::control::{self, Diagnostics, Role};

/// Where a user files what this module produces.
pub const ISSUE_URL: &str = "https://github.com/mntzrr/monux/issues";

/// The repository, for the `gh issue create` line `--issue` prints.
pub const ISSUE_REPO: &str = "mntzrr/monux";

/// The web form, for reporters without the `gh` CLI.
pub const NEW_ISSUE_URL: &str = "https://github.com/mntzrr/monux/issues/new";

/// What a bundle contains, in the user's terms. Printed by
/// `monux diagnostics --privacy` and embedded in the markdown bundle, so
/// nobody has to guess what they're pasting into a public issue.
pub const PRIVACY_NOTE: &str = "\
A diagnostics bundle contains:
  - the monux version, protocol version and build revision
  - the daemon's internal state: rotation/grab state, and for each connected
    peer its IP address, certificate fingerprint, RTT and connection age
  - the clipboard OWNER and the MIME TYPES currently advertised
  - recent log lines, and journal lines for the monux systemd unit
  - environment facts: kernel, OS, session type, desktop, whether /dev/uinput
    is writable, input-group membership, and systemd unit state
  - this machine's hostname and LAN IP addresses

It does NOT contain:
  - clipboard CONTENTS (only the owner and the MIME types are recorded)
  - keystrokes or key codes, unless you deliberately enabled key tracing with
    MONUX_TRACE_KEYS, which logs the traced key CODES (not typed text)
  - TLS private keys, or any file outside monux's own config directory

With --peer, the same facts are collected from each connected machine and
included alongside this one's.

Pass --redact to replace IP addresses, hostnames, usernames and home paths
with placeholders before the bundle leaves this machine — in the peer
sections too, using the names each peer reports about itself. Loopback
addresses and certificate fingerprints are kept: they identify nobody, and
the report is much harder to read without them. A hostname or username too
generic to substitute safely (three characters or fewer, or a word the report
is made of, like 'monux' or 'server') is left in place and called out on
stderr, as is a peer running a monux too old to report its names — that
section is then scrubbed for IP addresses only.

Separately from bug reports: COPYING FILES between machines sends each file's
full source path as its name inside the transferred archive, and the
receiving machine recreates that directory layout under its own unpack dir.
Copying ~/Documents/tax/2025.pdf therefore tells the other machine that path.
File CONTENTS only ever go to machines you have paired with.";

/// Recent daemon log lines a `monux diagnostics` bundle asks for by default.
/// Generous next to the socket's own default: a report is written once and
/// read by someone who wasn't there.
pub const DEFAULT_LOG_LINES: usize = 200;

/// Log lines the tray's "Copy diagnostics" asks for. Larger than the socket
/// default: the click means "I am filing a bug", and the tray is exactly
/// where a user with no terminal open reaches for one.
pub const TRAY_LOG_LINES: usize = 200;

/// Default journal window pulled into a bundle. Long enough to cover a
/// daemon that crashed and restarted a few minutes before the user got
/// around to filing the report, short enough that the bundle stays pasteable.
pub const DEFAULT_JOURNAL_SINCE: &str = "-30min";

/// Most journal lines pulled into a bundle, newest kept. A daemon in a crash
/// loop can produce thousands; a bundle nobody can paste helps nobody.
const JOURNAL_LINE_LIMIT: usize = 400;

/// Longest we wait for `journalctl` to answer. It reads a local journal, so
/// this only trips when the journal is enormous or the disk is stalled —
/// neither should hold a bug report hostage.
const JOURNAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest we wait for a short read-only probe (`systemctl`, `id`, `uname`)
/// while collecting the environment.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// The machine and session a daemon is running in — the half of a bug report
/// that otherwise costs a round-trip of "what's your setup?".
///
/// Every field is optional or carries its own "unknown" rendering: a probe
/// that can't answer (no systemd, no `id`, a container without
/// `/etc/os-release`) must degrade to a note, never to a failed bundle.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// Version plus embedded git revision, e.g. "11.0.1+7a1228583e80".
    pub build: String,
    pub arch: String,
    /// PRETTY_NAME from /etc/os-release.
    pub os: Option<String>,
    pub kernel: Option<String>,
    /// XDG_SESSION_TYPE ("wayland", "x11", "tty").
    pub session_type: Option<String>,
    /// XDG_CURRENT_DESKTOP.
    pub desktop: Option<String>,
    /// How the process sees WAYLAND_DISPLAY — the difference between "unset,
    /// so the runtime dir gets scanned", "empty, the clipboard opt-out" and a
    /// real value is the whole diagnosis for most clipboard reports.
    pub wayland_display: String,
    pub runtime_dir: Option<String>,
    /// Whether the process runs as root (the `sudo -E` fallback path).
    pub running_as_root: bool,
    /// /dev/uinput: presence and writability by this process.
    pub uinput: String,
    /// Whether the user is in the `input` group.
    pub input_group: String,
    /// Which clipboard tools are on PATH (the bundle-copy path needs one).
    pub clipboard_tools: String,
    /// `setup --autostart status` for both roles, or None when it couldn't
    /// be probed.
    pub autostart: Option<String>,
    /// This machine's hostname, and the user the daemon runs as.
    ///
    /// Carried so `--redact` can scrub a PEER's identity too. The CLI knows
    /// its OWN hostname, username and home dir, and used to scrub only those
    /// — but a `--peer` bundle is full of the other machine's (log targets,
    /// unit names, `/home/<them>/...` paths), and there is no other channel
    /// through which the CLI could learn them. Defaulted on the wire so a
    /// daemon from before this field existed still parses (its section is
    /// then scrubbed for IPs only, and the CLI says so).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Set when this environment describes the CLI process rather than a
    /// daemon — i.e. no daemon answered and the facts are the shell's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caveat: Option<String>,
}

impl Environment {
    /// Collects the current process's environment. Cached by
    /// [`daemon_environment`] for the daemon; the CLI calls this directly.
    pub fn collect() -> Self {
        Environment {
            build: build_string(),
            arch: std::env::consts::ARCH.to_string(),
            os: os_pretty_name(),
            kernel: read_trimmed("/proc/sys/kernel/osrelease"),
            session_type: env_opt("XDG_SESSION_TYPE"),
            desktop: env_opt("XDG_CURRENT_DESKTOP"),
            wayland_display: describe_wayland_display(),
            runtime_dir: env_opt("XDG_RUNTIME_DIR"),
            running_as_root: unsafe { libc::geteuid() } == 0,
            uinput: describe_uinput(),
            input_group: describe_input_group(),
            clipboard_tools: describe_clipboard_tools(),
            autostart: crate::setup::autostart_status_text(),
            hostname: hostname(),
            username: username(),
            caveat: None,
        }
    }

    /// Marks this environment as the CLI's own, not a daemon's.
    fn into_cli_fallback(mut self) -> Self {
        self.caveat = Some(
            "no daemon answered — these are the facts of the 'monux diagnostics' process, \
             which may differ from a daemon's (an autostarted daemon inherits the systemd \
             user manager's environment, not your shell's)"
                .to_string(),
        );
        self
    }

    /// Whether the daemon actually reported an environment. A daemon from
    /// before this section existed deserializes to the default, and rendering
    /// that as a wall of blank rows reads like "we checked and found
    /// nothing" — the opposite of the truth.
    fn is_reported(&self) -> bool {
        !self.build.is_empty()
    }

    fn render(&self) -> String {
        if !self.is_reported() {
            return "not reported — this daemon predates the environment section; \
                    restart it ('mx daemon restart') to include one"
                .to_string();
        }
        let mut out = String::new();
        if let Some(caveat) = &self.caveat {
            out.push_str(&format!("note: {}\n", caveat));
        }
        // Wide enough for the longest key ("WAYLAND_DISPLAY:") plus a space.
        let mut row = |k: &str, v: &str| out.push_str(&format!("{:<18}{}\n", format!("{}:", k), v));
        row("build", &self.build);
        row("arch", &self.arch);
        // Which machine this section describes: a two-machine report is
        // otherwise two anonymous blocks. `--redact` replaces it like every
        // other occurrence of the name.
        row("hostname", self.hostname.as_deref().unwrap_or("unknown"));
        row("os", self.os.as_deref().unwrap_or("unknown"));
        row("kernel", self.kernel.as_deref().unwrap_or("unknown"));
        row("session", self.session_type.as_deref().unwrap_or("unset"));
        row("desktop", self.desktop.as_deref().unwrap_or("unset"));
        row("WAYLAND_DISPLAY", &self.wayland_display);
        row(
            "XDG_RUNTIME_DIR",
            self.runtime_dir.as_deref().unwrap_or("unset"),
        );
        row("euid", if self.running_as_root { "root" } else { "user" });
        row("uinput", &self.uinput);
        row("input group", &self.input_group);
        row("clipboard tools", &self.clipboard_tools);
        match &self.autostart {
            Some(report) => {
                out.push_str("autostart:\n");
                for line in report.lines() {
                    out.push_str(&format!("  {}\n", line));
                }
            }
            None => row("autostart", "could not probe"),
        }
        out
    }
}

fn build_string() -> String {
    format!(
        "{}+{}",
        env!("CARGO_PKG_VERSION"),
        crate::update::CURRENT_REVISION
    )
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn os_pretty_name() -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    parse_os_release(&content)
}

/// Extracts PRETTY_NAME from an os-release file, unquoting the value.
fn parse_os_release(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

/// The three WAYLAND_DISPLAY states monux treats differently (see
/// clipboard::wayland::connect).
fn describe_wayland_display() -> String {
    match std::env::var("WAYLAND_DISPLAY") {
        Ok(v) if v.is_empty() => "empty (deliberate clipboard opt-out)".to_string(),
        Ok(v) => v,
        Err(_) => "unset (the session socket is looked up in XDG_RUNTIME_DIR)".to_string(),
    }
}

/// /dev/uinput's presence, mode and writability by this process — the first
/// thing to check on any "monux won't start" report.
fn describe_uinput() -> String {
    use std::os::unix::fs::PermissionsExt;
    let path = Path::new("/dev/uinput");
    let Ok(meta) = std::fs::metadata(path) else {
        return "missing (the uinput kernel module is not loaded)".to_string();
    };
    let mode = meta.permissions().mode() & 0o777;
    let writable = if path_is_writable(path) {
        "writable"
    } else {
        "NOT writable by this process — run 'monux setup'"
    };
    format!("present, mode {:04o}, {}", mode, writable)
}

/// access(2) for write permission: asks the kernel the same question the
/// daemon's open() will ask, without the side effect of actually opening the
/// device.
fn path_is_writable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: c_path is a valid NUL-terminated C string that outlives the
    // call; access(2) only reads it.
    unsafe { libc::access(c_path.as_ptr(), libc::W_OK) == 0 }
}

fn describe_input_group() -> String {
    match probe("id", &["-nG"]) {
        Ok(groups) if crate::setup::groups_contain(&groups, "input") => "member".to_string(),
        Ok(_) => "NOT a member — run 'monux setup', then log out and back in".to_string(),
        Err(e) => {
            debug!("Diagnostics: could not query groups: {:#}", e);
            "could not query".to_string()
        }
    }
}

/// Which clipboard tools the bundle-copy path can use. Absent tools are worth
/// reporting: "Copy diagnostics failed" is usually all three missing.
fn describe_clipboard_tools() -> String {
    let found: Vec<&str> = CLIPBOARD_TOOLS
        .iter()
        .map(|(tool, _)| *tool)
        .filter(|tool| which(tool).is_some())
        .collect();
    if found.is_empty() {
        "none (tried wl-copy, xclip, xsel)".to_string()
    } else {
        found.join(", ")
    }
}

/// First match for `program` on PATH.
fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// The daemon's environment, collected once. Every field is effectively
/// static for the life of a process (a daemon's env vars, its uid, its group
/// membership), so the first diagnostics request pays for the probes and the
/// rest are free — and a tray polling in a loop can't turn bug-report
/// plumbing into a process-spawning treadmill.
pub fn daemon_environment() -> Environment {
    static CACHE: std::sync::OnceLock<Environment> = std::sync::OnceLock::new();
    CACHE.get_or_init(Environment::collect).clone()
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

/// Journal lines for one role's systemd unit.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JournalCapture {
    pub unit: String,
    pub since: String,
    pub lines: Vec<String>,
    /// Why the capture is empty or partial, when it is.
    pub note: Option<String>,
}

/// Pulls the role's unit log out of the user journal.
///
/// This is the half of the log story the in-memory ring cannot tell: the ring
/// holds a bounded tail of the LIVE daemon, so it covers neither history that
/// scrolled past nor — the case that matters most — a daemon that crashed,
/// whose ring died with it. `--user` matches where `setup --autostart`
/// installs its units; a system-wide or non-systemd install degrades to a
/// note explaining where to look instead.
pub fn journal_capture(role: Role, since: &str) -> JournalCapture {
    let unit = crate::setup::unit_name_for(role.as_str());
    let mut capture = JournalCapture {
        unit: unit.clone(),
        since: since.to_string(),
        lines: Vec::new(),
        note: None,
    };
    if which("journalctl").is_none() {
        capture.note = Some(
            "journalctl is not installed; if monux runs under another init, attach its log by hand"
                .to_string(),
        );
        return capture;
    }
    // --utc so journal stamps and the ring buffer's stamps (logging.rs, also
    // UTC) can be read against each other, and against the peer machine's.
    let args = [
        "--user",
        "-u",
        &unit,
        "--since",
        since,
        "--utc",
        "--no-pager",
        "-o",
        "short-iso",
        "-n",
        "2000",
    ];
    match probe_with_timeout("journalctl", &args, JOURNAL_TIMEOUT) {
        Ok(out) => {
            let all: Vec<String> = out
                .lines()
                .map(str::trim_end)
                .filter(|l| !l.is_empty())
                // journalctl's "-- No entries --" is a message, not a log line.
                .filter(|l| !l.starts_with("-- ") || !l.ends_with(" --"))
                .map(str::to_string)
                .collect();
            if all.is_empty() {
                capture.note = Some(format!(
                    "no journal entries for {} since {} — monux is probably running outside systemd \
                     (started by hand), so its log went to that terminal instead",
                    unit, since
                ));
            } else if all.len() > JOURNAL_LINE_LIMIT {
                let dropped = all.len() - JOURNAL_LINE_LIMIT;
                capture.note = Some(format!(
                    "{} older lines dropped to keep the bundle pasteable; for the full log run: \
                     journalctl --user -u {} --since {}",
                    dropped, unit, since
                ));
                capture.lines = all[all.len() - JOURNAL_LINE_LIMIT..].to_vec();
            } else {
                capture.lines = all;
            }
        }
        Err(e) => {
            capture.note = Some(format!("journalctl failed: {:#}", e));
        }
    }
    capture
}

// ---------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------

/// A complete report: one machine's daemon state, its environment and its
/// journal — plus the peer's, when the daemon could reach one.
#[derive(Clone, Debug, Serialize)]
pub struct Bundle {
    pub diagnostics: Diagnostics,
    pub journal: JournalCapture,
    /// Bundles fetched from connected peers (`--peer`); empty otherwise.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<control::PeerDiagnostics>,
}

/// How a bundle is rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Section headers and bare text: for reading in a terminal.
    Plain,
    /// Fenced code blocks under a fill-in-the-blanks issue template: for
    /// pasting into the issue tracker. The default for anything that leaves
    /// the machine (`--copy`), since that is where it is going.
    Markdown,
    /// The raw JSON of the bundle.
    Json,
}

/// Rendering options for [`format_bundle`].
#[derive(Clone, Copy, Debug)]
pub struct FormatOptions {
    pub format: Format,
    /// Replace identifying values with placeholders (see [`redact`]).
    pub redact: bool,
}

/// Renders a bundle for a human to read or paste.
pub fn format_bundle(bundle: &Bundle, opts: FormatOptions) -> Result<String> {
    let out = match opts.format {
        Format::Json => serde_json::to_string_pretty(bundle)
            .context("Failed to serialize the diagnostics bundle")?,
        Format::Plain => render_plain(bundle),
        Format::Markdown => render_markdown(bundle),
    };
    // Redaction draws on the whole bundle, not just this machine: a --peer
    // report carries the other machine's hostname, username and home paths,
    // and the CLI can only learn them from the peer's own Environment.
    Ok(if opts.redact {
        redact_names(&out, &bundle_names(bundle))
    } else {
        out
    })
}

/// Every machine's identifying names in a bundle: this one's, plus each
/// peer's. The local names come from the environment as well as from our own
/// Environment section, so a daemon that reported none (or a CLI-fallback
/// bundle) still scrubs this machine.
fn bundle_names(bundle: &Bundle) -> Names {
    let mut names = Names::local();
    names.add(&bundle.diagnostics.environment);
    for peer in &bundle.peers {
        if let Ok(d) = &peer.diagnostics {
            names.add(&d.environment);
        }
    }
    names
}

/// The plain-text rendering, also what the tray's "Copy diagnostics" used to
/// produce on its own.
fn render_plain(bundle: &Bundle) -> String {
    let d = &bundle.diagnostics;
    let mut out = format!(
        "monux {} diagnostics ({} role, protocol {})\n",
        d.version, d.role, d.protocol_version
    );
    out.push_str(&section("environment", &d.environment.render()));
    out.push_str(&section("state", d.state_dump.trim_end()));
    out.push_str(&section(
        "recent logs (oldest first)",
        &render_lines(&d.recent_logs, "<no log lines captured>"),
    ));
    out.push_str(&section(
        &format!("journal: {} (since {})", bundle.journal.unit, bundle.journal.since),
        &render_journal(&bundle.journal),
    ));
    for peer in &bundle.peers {
        out.push_str(&render_peer_plain(peer));
    }
    out
}

fn section(title: &str, body: &str) -> String {
    format!("\n== {} ==\n{}\n", title, body.trim_end())
}

fn render_lines(lines: &[String], empty: &str) -> String {
    if lines.is_empty() {
        empty.to_string()
    } else {
        lines.join("\n")
    }
}

fn render_journal(journal: &JournalCapture) -> String {
    let mut body = render_lines(&journal.lines, "<no journal lines>");
    if let Some(note) = &journal.note {
        body.push_str(&format!("\n[note] {}", note));
    }
    body
}

fn render_peer_plain(peer: &control::PeerDiagnostics) -> String {
    match &peer.diagnostics {
        Ok(d) => {
            let mut out = section(
                &format!("peer {} ({})", peer.label, d.role),
                &format!("monux {}, protocol {}", d.version, d.protocol_version),
            );
            out.push_str(&section(
                &format!("peer {}: environment", peer.label),
                &d.environment.render(),
            ));
            out.push_str(&section(
                &format!("peer {}: state", peer.label),
                d.state_dump.trim_end(),
            ));
            out.push_str(&section(
                &format!("peer {}: recent logs (oldest first)", peer.label),
                &render_lines(&d.recent_logs, "<no log lines captured>"),
            ));
            out
        }
        Err(e) => section(
            &format!("peer {}", peer.label),
            &format!("could not be reached: {}", e),
        ),
    }
}

/// The issue-ready rendering: a template the reporter fills in, then the
/// evidence in fenced blocks so the tracker renders it as-is. The prompts sit
/// at the TOP because a report that is only evidence still costs a round-trip
/// to find out what the user expected to happen.
fn render_markdown(bundle: &Bundle) -> String {
    let d = &bundle.diagnostics;
    let mut out = String::from("### What happened\n\n<!-- what went wrong -->\n\n");
    out.push_str("### What you expected\n\n<!-- what you expected instead -->\n\n");
    out.push_str("### Steps to reproduce\n\n1. \n2. \n\n");
    out.push_str("### Diagnostics\n\n");
    out.push_str(&format!(
        "monux **{}** — {} role, protocol {}\n\n",
        d.version, d.role, d.protocol_version
    ));
    out.push_str(&fenced("Environment", "text", &d.environment.render()));
    out.push_str(&fenced("State", "text", d.state_dump.trim_end()));
    out.push_str(&fenced(
        "Recent logs",
        "log",
        &render_lines(&d.recent_logs, "<no log lines captured>"),
    ));
    out.push_str(&fenced(
        &format!("Journal — {} (since {})", bundle.journal.unit, bundle.journal.since),
        "log",
        &render_journal(&bundle.journal),
    ));
    for peer in &bundle.peers {
        match &peer.diagnostics {
            Ok(pd) => {
                out.push_str(&fenced(
                    &format!("Peer {} — environment ({} role)", peer.label, pd.role),
                    "text",
                    &pd.environment.render(),
                ));
                out.push_str(&fenced(
                    &format!("Peer {} — state", peer.label),
                    "text",
                    pd.state_dump.trim_end(),
                ));
                out.push_str(&fenced(
                    &format!("Peer {} — recent logs", peer.label),
                    "log",
                    &render_lines(&pd.recent_logs, "<no log lines captured>"),
                ));
            }
            Err(e) => out.push_str(&format!(
                "Peer {} could not be reached: {}\n\n",
                peer.label, e
            )),
        }
    }
    out
}

/// One collapsed `<details>` block holding a fenced code block. Collapsed
/// because a bundle is long and an issue thread should stay readable; the
/// evidence is one click away.
fn fenced(title: &str, lang: &str, body: &str) -> String {
    // A log line can contain a fence; pick a longer one than anything inside.
    let fence = "`".repeat(longest_backtick_run(body).max(2) + 1);
    format!(
        "<details><summary>{}</summary>\n\n{}{}\n{}\n{}\n\n</details>\n\n",
        title,
        fence,
        lang,
        body.trim_end(),
        fence
    )
}

fn longest_backtick_run(s: &str) -> usize {
    let (mut best, mut run) = (0, 0);
    for c in s.chars() {
        if c == '`' {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// The identifying names to scrub from one bundle: this machine's, plus
/// every peer's (each carried in its own `Environment`).
///
/// Collected as data rather than read from the environment at substitution
/// time, because only the LOCAL machine's names are discoverable that way —
/// and a `--peer` bundle's most identifying text belongs to the other
/// machine.
#[derive(Debug, Default, PartialEq, Eq)]
struct Names {
    /// Machine names, replaced with `<hostname>`.
    hostnames: Vec<String>,
    /// User names, replaced with `<user>`; each also implies a
    /// `/home/<name>` path to fold to `~`.
    usernames: Vec<String>,
}

impl Names {
    /// This machine's names, for a redaction that has no bundle to draw on.
    fn local() -> Self {
        Names {
            hostnames: hostname().into_iter().collect(),
            usernames: username().into_iter().collect(),
        }
    }

    fn add(&mut self, env: &Environment) {
        if let Some(host) = &env.hostname {
            self.hostnames.push(host.clone());
        }
        if let Some(user) = &env.username {
            self.usernames.push(user.clone());
        }
    }

    /// (name, placeholder) pairs to substitute, dropping the names that would
    /// damage the report more than they protect (see is_unsubstitutable) and
    /// de-duplicating. A name that is both a hostname and a username on some
    /// machine is scrubbed once, as a hostname.
    fn substitutions(&self) -> Vec<(&str, &'static str)> {
        let mut seen: Vec<&str> = Vec::new();
        let mut out = Vec::new();
        for (names, placeholder) in [
            (&self.hostnames, "<hostname>"),
            (&self.usernames, "<user>"),
        ] {
            for name in names {
                if is_unsubstitutable(name) || seen.contains(&name.as_str()) {
                    continue;
                }
                seen.push(name);
                out.push((name.as_str(), placeholder));
            }
        }
        out
    }

    /// Home directories to fold to `~`, longest first so a nested path can't
    /// be half-replaced. The local home dir is known exactly; a peer's is
    /// reconstructed from its username, which covers the ordinary
    /// `/home/<user>` layout (an unusual one simply keeps its path, and the
    /// username pass still scrubs the name inside it).
    fn home_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = home::home_dir()
            .and_then(|h| h.to_str().map(str::to_string))
            .filter(|h| h.len() > 1)
            .into_iter()
            .collect();
        for user in &self.usernames {
            if is_unsubstitutable(user) {
                continue;
            }
            let path = format!("/home/{}", user);
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        paths.sort_by_key(|p| std::cmp::Reverse(p.len()));
        paths
    }

    /// The names that had to be left in place (see is_unsubstitutable), so
    /// the CLI can say so rather than let the user believe everything was
    /// scrubbed.
    fn skipped(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for name in self.hostnames.iter().chain(self.usernames.iter()) {
            if is_unsubstitutable(name) && !out.contains(name) {
                out.push(name.clone());
            }
        }
        out
    }
}

/// Replaces the identifying values in text with placeholders, using only
/// THIS machine's names. Peer-aware redaction goes through
/// [`format_bundle`], which collects every machine's names first.
///
/// Deliberately kept: loopback and wildcard addresses (`127.0.0.1`,
/// `0.0.0.0`, `::1`) carry no identity and reading a state dump without them
/// is needlessly hard, and certificate fingerprints, which are public key
/// hashes and are what correlates the two machines' logs.
///
/// This is a best-effort scrub of the shapes monux itself emits, not a
/// guarantee about arbitrary text — which is why the bundle is shown to the
/// user rather than uploaded anywhere.
pub fn redact(text: &str) -> String {
    redact_names(text, &Names::local())
}

/// The substitution pass itself, over an explicit set of names (see [`Names`]).
fn redact_names(text: &str, names: &Names) -> String {
    use regex::Regex;
    use std::sync::OnceLock;
    static IPV4: OnceLock<Regex> = OnceLock::new();
    static IPV6: OnceLock<Regex> = OnceLock::new();

    let ipv4 = IPV4.get_or_init(|| {
        Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("valid ipv4 pattern")
    });
    // At least three colon-separated hex groups: enough structure that log
    // text and timestamps (two colons, non-hex neighbours) don't match.
    let ipv6 = IPV6.get_or_init(|| {
        Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b").expect("valid ipv6 pattern")
    });

    let mut out = ipv4
        .replace_all(text, |caps: &regex::Captures| {
            let found = &caps[0];
            if KEPT_ADDRS.contains(&found) {
                found.to_string()
            } else {
                "<ip>".to_string()
            }
        })
        .into_owned();
    out = ipv6
        .replace_all(&out, |caps: &regex::Captures| {
            let found = &caps[0];
            if KEPT_ADDRS.contains(&found) {
                found.to_string()
            } else {
                "<ipv6>".to_string()
            }
        })
        .into_owned();

    // Home paths before the usernames: /home/alice must become ~ rather than
    // /home/<user>, and the bare-username pass would otherwise get there first.
    for home in names.home_paths() {
        out = out.replace(&home, "~");
    }
    for (name, placeholder) in names.substitutions() {
        out = replace_whole_words(&out, name, placeholder);
        // mDNS presents the same name with a .local suffix.
        out = out.replace(&format!("{}.local", name), "<hostname>.local");
    }
    out
}

/// Names monux must NOT substitute, because doing so damages the report more
/// than leaving them in.
///
/// Learned the hard way from a machine whose hostname is literally `monux`:
/// substituting it rewrote every log target (`monux::device::input`), every
/// unit name and the product's own name, leaving a bundle nobody could read.
/// A hostname that collides with a word the bundle is structurally made of
/// carries almost no information anyway — the reader loses nothing.
///
/// Very short names are excluded for the same reason: scrubbing a two-letter
/// username out of every line mangles the evidence worse than leaking it.
fn is_unsubstitutable(name: &str) -> bool {
    const RESERVED: [&str; 10] = [
        "monux",
        "server",
        "client",
        "daemon",
        "localhost",
        "local",
        "root",
        "user",
        "home",
        "systemd",
    ];
    name.len() < 3 || RESERVED.contains(&name.to_ascii_lowercase().as_str())
}

/// The names `--redact` had to leave alone across a whole bundle — this
/// machine's and every peer's (see [`is_unsubstitutable`]) — so the CLI can
/// say so rather than let the user believe everything was scrubbed.
pub fn redaction_skips(bundle: &Bundle) -> Vec<String> {
    bundle_names(bundle).skipped()
}

/// Whether any peer in this bundle predates the hostname/username fields, so
/// its section could only be scrubbed for IP addresses. Reported by the CLI:
/// silently under-redacting is exactly the failure `--redact` exists to
/// prevent.
pub fn peers_missing_redaction_names(bundle: &Bundle) -> Vec<String> {
    bundle
        .peers
        .iter()
        .filter(|peer| {
            peer.diagnostics
                .as_ref()
                .is_ok_and(|d| d.environment.is_reported() && d.environment.hostname.is_none())
        })
        .map(|peer| peer.label.clone())
        .collect()
}

/// Addresses kept verbatim through redaction: they identify nobody, and a
/// state dump reads much better with them intact.
const KEPT_ADDRS: [&str; 4] = ["127.0.0.1", "0.0.0.0", "255.255.255.255", "::1"];

/// Replaces `needle` only where it stands as a whole word, so a username that
/// happens to be a substring of an unrelated identifier survives.
fn replace_whole_words(haystack: &str, needle: &str, replacement: &str) -> String {
    let is_word = |c: char| c.is_alphanumeric() || c == '_' || c == '-';
    let mut out = String::with_capacity(haystack.len());
    let mut rest = haystack;
    while let Some(pos) = rest.find(needle) {
        let before_ok = rest[..pos].chars().next_back().is_none_or(|c| !is_word(c));
        let after = &rest[pos + needle.len()..];
        let after_ok = after.chars().next().is_none_or(|c| !is_word(c));
        out.push_str(&rest[..pos]);
        if before_ok && after_ok {
            out.push_str(replacement);
        } else {
            out.push_str(needle);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

fn hostname() -> Option<String> {
    read_trimmed("/proc/sys/kernel/hostname")
}

fn username() -> Option<String> {
    env_opt("USER").or_else(|| env_opt("LOGNAME"))
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

const CLIPBOARD_TOOLS: [(&str, &[&str]); 3] = [
    ("wl-copy", &[]),
    ("xclip", &["-selection", "clipboard"]),
    ("xsel", &["--clipboard", "--input"]),
];

/// Longest we wait for a clipboard tool to exit before killing it. All three
/// tools daemonize after taking the selection and exit in milliseconds; a
/// wedged compositor must not freeze the tray's service thread in wait().
const CLIPBOARD_TOOL_TIMEOUT: Duration = Duration::from_secs(5);

/// Copies `text` to the desktop clipboard, trying wl-copy (Wayland), then
/// xclip and xsel (X11); returns the tool that worked. All three daemonize
/// after taking the selection, so spawn + write + wait returns promptly.
pub fn copy_to_clipboard(text: &str) -> Result<&'static str> {
    for (tool, args) in CLIPBOARD_TOOLS {
        match pipe_into(tool, args, text) {
            Ok(()) => return Ok(tool),
            Err(e) => debug!("Diagnostics: {} failed: {:?}", tool, e),
        }
    }
    bail!("no clipboard tool available (tried wl-copy, xclip, xsel)");
}

fn pipe_into(tool: &str, args: &[&str], text: &str) -> Result<()> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn {}", tool))?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    // Write on a worker thread so a wedged reader can't block the caller's
    // thread at the 64 KiB pipe-buffer boundary. The worker exits on write
    // success, pipe-break (child killed), or EOF.
    let (write_tx, write_rx) = std::sync::mpsc::channel();
    let text = text.to_string();
    let _worker = std::thread::spawn(move || {
        use std::io::Write;
        let _ = write_tx.send(stdin.write_all(text.as_bytes()));
    });
    match write_rx.recv_timeout(CLIPBOARD_TOOL_TIMEOUT) {
        // Write succeeded: the pipe is closed (stdin dropped when the
        // worker exits), so the tool sees EOF and exits in milliseconds.
        Ok(Ok(())) => match wait_with_timeout(&mut child, CLIPBOARD_TOOL_TIMEOUT)? {
            Some(status) if status.success() => Ok(()),
            Some(status) => bail!("{} exited with {}", tool, status),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{} did not exit within {:?}", tool, CLIPBOARD_TOOL_TIMEOUT)
            }
        },
        Ok(Err(e)) => {
            let _ = child.wait();
            Err(e).with_context(|| format!("failed to write to {}", tool))
        }
        Err(_) => {
            // Write timed out (wedged reader): kill the child to break the
            // pipe, which lets the leaked worker thread exit shortly after.
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "{} did not accept the clipboard data within {:?}",
                tool,
                CLIPBOARD_TOOL_TIMEOUT
            )
        }
    }
}

/// child.wait() with a deadline: Ok(None) when it expires (the caller then
/// kills and reaps). try_wait polling is plenty for a process that exits in
/// milliseconds in the common case.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<Option<std::process::ExitStatus>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().context("failed to poll child")? {
            return Ok(Some(status));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Runs a short read-only probe, returning stdout regardless of exit status
/// (`systemctl is-enabled` answers "disabled" with exit 1). Only a spawn
/// failure is an error.
fn probe(program: &str, args: &[&str]) -> Result<String> {
    probe_with_timeout(program, args, PROBE_TIMEOUT)
}

fn probe_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("Failed to run {}: is it installed?", program))?;
    // Read stdout on a worker: a probe that fills the pipe buffer and never
    // exits would otherwise deadlock a wait-then-read.
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let (tx, rx) = std::sync::mpsc::channel();
    let _worker = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = String::new();
        let _ = tx.send(stdout.read_to_string(&mut buf).map(|_| buf));
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(out)) => {
            let _ = wait_with_timeout(&mut child, timeout);
            Ok(out)
        }
        Ok(Err(e)) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e).with_context(|| format!("Failed to read {}'s output", program))
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{} did not answer within {:?}", program, timeout)
        }
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Everything `monux diagnostics` was asked for.
#[derive(Clone, Debug)]
pub struct CliOptions {
    pub server: bool,
    pub client: bool,
    pub socket: Option<PathBuf>,
    pub format: Format,
    pub redact: bool,
    pub copy: bool,
    /// Recent log lines to request from the daemon.
    pub lines: usize,
    /// journalctl `--since` expression, or None to skip the journal.
    pub journal_since: Option<String>,
    /// Also fetch connected peers' bundles (server only).
    pub peer: bool,
    /// Prepare a ready-to-file GitHub issue instead of printing the bundle.
    pub issue: bool,
    /// Issue title for `--issue`; a placeholder to edit when absent.
    pub title: Option<String>,
}

/// Implements `monux diagnostics`: collects a bundle and returns the text to
/// print.
///
/// A daemon that doesn't answer is NOT fatal. "monux won't start" and "monux
/// crashed" are among the reports we most want, and both arrive with no
/// daemon on the socket — so the bundle falls back to the environment and
/// the journal, which is exactly where the answer lives in those cases.
pub fn run_cli(opts: &CliOptions) -> Result<String> {
    let fetched = control::fetch_diagnostics(
        opts.server,
        opts.client,
        opts.socket.as_deref(),
        opts.lines,
        opts.peer,
    );
    let (role, diagnostics, peers) = match fetched {
        Ok(found) => found,
        Err(e) => {
            debug!("Diagnostics: no daemon answered: {:#}", e);
            let role = if opts.client { Role::Client } else { Role::Server };
            (role, offline_diagnostics(role, &e), Vec::new())
        }
    };
    if opts.peer && peers.is_empty() {
        // An empty peer list has three very different causes, and letting the
        // user assume the wrong one wastes exactly the round-trip this
        // feature exists to save.
        eprintln!("note: {}", empty_peers_reason(role, &diagnostics));
    }
    let journal = match &opts.journal_since {
        Some(since) => journal_capture(role, since),
        None => JournalCapture {
            unit: crate::setup::unit_name_for(role.as_str()),
            since: "skipped".to_string(),
            lines: Vec::new(),
            note: Some("journal collection was disabled with --no-journal".to_string()),
        },
    };
    let bundle = Bundle {
        diagnostics,
        journal,
        peers,
    };
    let text = format_bundle(
        &bundle,
        FormatOptions {
            format: opts.format,
            redact: opts.redact,
        },
    )?;
    if opts.redact {
        let skipped = redaction_skips(&bundle);
        if !skipped.is_empty() {
            eprintln!(
                "note: --redact left {} in place — {} too generic to substitute without \
                 mangling the report (see 'monux diagnostics --privacy')",
                skipped.join(" and "),
                if skipped.len() == 1 { "it is" } else { "they are" }
            );
        }
        // A peer too old to report its own names can only be scrubbed for IP
        // addresses. Say so: quietly under-redacting is the failure --redact
        // exists to prevent.
        let unnamed = peers_missing_redaction_names(&bundle);
        if !unnamed.is_empty() {
            eprintln!(
                "note: --redact scrubbed IP addresses only for {} — {} runs a monux from before \
                 peers reported their hostname, so its hostname, username and home paths remain. \
                 Update that machine, or run 'monux diagnostics --redact' on it directly.",
                unnamed.join(" and "),
                if unnamed.len() == 1 { "it" } else { "they" }
            );
        }
    }
    if opts.issue {
        return Ok(prepare_issue(
            &text,
            opts.title.as_deref(),
            &bundle.diagnostics,
            &default_report_path(),
        ));
    }
    if opts.copy {
        let tool = copy_to_clipboard(&text)?;
        return Ok(format!(
            "Diagnostics copied to the clipboard ({}), {} bytes.\nPaste it into a new issue: {}",
            tool,
            text.len(),
            ISSUE_URL
        ));
    }
    Ok(text)
}

/// Placeholder title, written so that leaving it unedited is obviously wrong.
const TITLE_PLACEHOLDER: &str = "<one-line summary of the problem>";

/// Where `--issue` leaves the report. The pid keeps repeated attempts from
/// overwriting each other, the same way capture files work.
fn default_report_path() -> PathBuf {
    std::env::temp_dir().join(format!("monux-report-{}.md", std::process::id()))
}

/// Gets a report to the point of filing — and stops there.
///
/// Deliberately does NOT create the issue, or open a browser. Filing is
/// publishing: the bundle carries the reporter's hostname, LAN addresses and
/// log lines, and a tool that posts that to a public tracker as a side effect
/// of a flag has made a disclosure decision that belongs to the person whose
/// machine it is. So this writes the file, fills the clipboard, and hands
/// over a command to run — every byte reviewable first.
///
/// The bundle goes to a FILE, not into the command line or a URL: a report
/// runs to tens of kilobytes, well past both a `?body=` query string and a
/// comfortable argv.
fn prepare_issue(text: &str, title: Option<&str>, d: &Diagnostics, path: &Path) -> String {
    let title = title.unwrap_or(TITLE_PLACEHOLDER);
    let mut out = String::new();

    let wrote = std::fs::write(path, text);
    match &wrote {
        Ok(()) => out.push_str(&format!(
            "Report written to {} ({} bytes).\n",
            path.display(),
            text.len()
        )),
        Err(e) => out.push_str(&format!(
            "Could not write the report file ({}); falling back to the clipboard.\n",
            e
        )),
    }

    match copy_to_clipboard(text) {
        Ok(tool) => out.push_str(&format!("Also copied to the clipboard ({}).\n", tool)),
        Err(e) => out.push_str(&format!("Could not reach a clipboard tool ({}).\n", e)),
    }

    out.push_str(&format!(
        "\nIt describes monux {} ({} role, protocol {}) on this machine.\n",
        d.version, d.role, d.protocol_version
    ));
    if title == TITLE_PLACEHOLDER {
        out.push_str("Replace the title placeholder, and fill in the What happened / What you \
                      expected sections at the top of the report.\n");
    }

    out.push_str("\nFile it with:\n");
    match (which("gh"), wrote.is_ok()) {
        (Some(_), true) => out.push_str(&format!(
            "    gh issue create --repo {} --title {:?} --body-file {}\n",
            ISSUE_REPO,
            title,
            path.display()
        )),
        // No file to point at: gh can still read the body from stdin.
        (Some(_), false) => out.push_str(&format!(
            "    monux diagnostics --markdown | gh issue create --repo {} --title {:?} --body-file -\n",
            ISSUE_REPO, title
        )),
        (None, _) => out.push_str(&format!(
            "    {} — then paste the report into the body\n\
             (install the 'gh' CLI and this becomes a single command)\n",
            NEW_ISSUE_URL
        )),
    }
    out.push_str(&format!(
        "\nReview it before sending — it contains this machine's hostname and LAN addresses. \
         Re-run with --redact to replace them, or --privacy for the full list of what a report \
         carries.\n"
    ));
    out
}

// ---------------------------------------------------------------------------
// Record: capturing a live reproduction
// ---------------------------------------------------------------------------

/// What `monux diagnostics record` was asked for.
#[derive(Clone, Debug, Default)]
pub struct RecordOptions {
    /// Record the client daemon instead of the server.
    pub client: bool,
    /// Comma-separated key codes to trace (MONUX_TRACE_KEYS).
    pub keys: Option<String>,
    /// Trace level instead of debug.
    pub trace: bool,
    /// Explicit capture path.
    pub out: Option<PathBuf>,
    /// Extra arguments for the recorded daemon.
    pub args: Vec<String>,
}

/// Runs a daemon with diagnostic logging turned up, tee-ing everything to a
/// capture file until the user stops it.
///
/// The troubleshooting recipes this replaces (set LOG_LEVEL, set
/// MONUX_TRACE_KEYS, redirect stderr, remember where you put it, find the
/// interesting window afterwards) are each individually easy and collectively
/// enough friction that reports arrive without them. Failures that a snapshot
/// bundle cannot explain — an input freeze, a dead key, a stall under load —
/// are exactly the ones that need this.
///
/// The daemon keeps its stderr on the terminal as well as in the file: a user
/// reproducing a freeze needs to see monux reacting, not stare at a silent
/// screen wondering whether it started.
pub fn record(opts: &RecordOptions) -> Result<String> {
    let role = if opts.client { Role::Client } else { Role::Server };
    // A recording daemon is a REAL daemon: it grabs the input devices and
    // accepts client connections. Started alongside a daemon that is already
    // running, the two fight over those devices and the session misbehaves
    // in ways that have nothing to do with the bug being recorded. Refuse,
    // and say exactly how to free the slot.
    if let Some(pid) = crate::single_instance::live_holder(role.as_str()) {
        bail!(
            "a monux {role} is already running (pid {pid}), and a second one would fight it for \
             the input devices.\nStop it first, then record:\n    \
             systemctl --user stop monux-{role}    # if it was autostarted\n    \
             mx daemon exit                        # otherwise\nThe capture needs to BE the \
             daemon, so that its own logs are what gets recorded.",
            role = role.as_str(),
            pid = pid
        );
    }
    let path = match &opts.out {
        Some(path) => path.clone(),
        None => default_capture_path(role),
    };
    let exe = std::env::current_exe().context("Could not find the running monux binary")?;
    let level = if opts.trace { "trace" } else { "debug" };

    let mut file = std::fs::File::create(&path)
        .with_context(|| format!("Could not create the capture file {}", path.display()))?;
    write_capture_header(&mut file, role, level, opts)?;

    println!("Recording a {} reproduction to {}", role.as_str(), path.display());
    println!("Reproduce the problem now, then press Ctrl-C to stop.");
    if opts.keys.is_none() && role == Role::Server {
        println!(
            "Tip: for a dead or repeating key, add --keys <code> (28 = Enter) to trace it \
             through every stage of the input pipeline."
        );
    }
    println!();

    let mut command = Command::new(&exe);
    command.arg(role.as_str());
    command.args(&opts.args);
    command.env("LOG_LEVEL", level);
    if let Some(keys) = &opts.keys {
        command.env("MONUX_TRACE_KEYS", keys);
    }
    command.stdin(Stdio::null());
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .with_context(|| format!("Failed to start {} {}", exe.display(), role.as_str()))?;
    let stderr = child.stderr.take().expect("stderr is piped");

    // Ctrl-C reaches the child too (same process group), so it shuts down
    // gracefully on its own and its stderr hits EOF — which ends this copy
    // loop. Copying rather than redirecting is what keeps the terminal live.
    let lines = tee_to_file(stderr, &mut file)?;
    let status = child.wait().context("Failed to wait for the recorded daemon")?;

    Ok(format!(
        "\nCapture written to {} ({} lines, {} exited with {}).\n\
         Attach that file to your report: {}\n\
         Review it first if you'd rather not share addresses or hostnames — \
         'monux diagnostics --redact' shows what a scrubbed bundle looks like.",
        path.display(),
        lines,
        role.as_str(),
        status,
        ISSUE_URL
    ))
}

/// Copies the daemon's stderr to both the capture file and our own stderr,
/// returning the line count. Line-buffered so a capture interrupted by a
/// crash or a kill still holds everything up to the last complete line.
fn tee_to_file(stderr: std::process::ChildStderr, file: &mut std::fs::File) -> Result<usize> {
    use std::io::{BufRead, BufReader, Write};
    let mut lines = 0;
    let reader = BufReader::new(stderr);
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            // A read error ends the capture; what we already wrote stands.
            Err(e) => {
                debug!("Recording: stderr read ended: {}", e);
                break;
            }
        };
        eprintln!("{}", line);
        writeln!(file, "{}", line).context("Failed to write to the capture file")?;
        file.flush().context("Failed to flush the capture file")?;
        lines += 1;
    }
    Ok(lines)
}

/// The header every capture opens with, so the file is self-describing when
/// it arrives in an issue without the command that produced it.
fn write_capture_header(
    file: &mut std::fs::File,
    role: Role,
    level: &str,
    opts: &RecordOptions,
) -> Result<()> {
    use std::io::Write;
    let env = Environment::collect();
    writeln!(file, "== monux reproduction capture ==")?;
    writeln!(file, "role: {}", role.as_str())?;
    writeln!(file, "log level: {}", level)?;
    writeln!(
        file,
        "traced keys: {}",
        opts.keys.as_deref().unwrap_or("<none>")
    )?;
    writeln!(
        file,
        "daemon args: {}",
        if opts.args.is_empty() {
            "<none>".to_string()
        } else {
            opts.args.join(" ")
        }
    )?;
    writeln!(file, "\n== environment ==")?;
    write!(file, "{}", env.render())?;
    writeln!(file, "\n== log ==")?;
    file.flush().context("Failed to write the capture header")?;
    Ok(())
}

/// A capture path nobody has to invent: role and pid, under the temp dir.
/// The pid keeps concurrent or repeated recordings from overwriting each
/// other — a user who records three attempts should end up with three files.
fn default_capture_path(role: Role) -> PathBuf {
    std::env::temp_dir().join(format!(
        "monux-{}-capture-{}.log",
        role.as_str(),
        std::process::id()
    ))
}

/// Why `--peer` came back with nothing. Three causes look identical in the
/// output and lead to completely different next steps, so the note names the
/// one that actually applies.
fn empty_peers_reason(role: Role, diagnostics: &Diagnostics) -> String {
    if role == Role::Client {
        return "--peer only applies to a server daemon — a client has no peers to poll. \
                Run it on the server to cover both machines."
            .to_string();
    }
    if diagnostics.protocol_version < crate::msgs::shared::PROTOCOL_VERSION_PEER_DIAGNOSTICS {
        return format!(
            "this daemon speaks protocol v{}, which predates peer diagnostics (v{}) — it ignored \
             --peer. Restart it ('mx daemon restart') to pick up the installed build.",
            diagnostics.protocol_version,
            crate::msgs::shared::PROTOCOL_VERSION_PEER_DIAGNOSTICS
        );
    }
    "--peer found no connected clients, so the bundle covers this machine only.".to_string()
}

/// The stand-in bundle for a machine where no daemon answered: real
/// environment facts, and the socket error in place of a state dump.
fn offline_diagnostics(role: Role, why: &anyhow::Error) -> Diagnostics {
    Diagnostics {
        version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: crate::msgs::shared::PROTOCOL_VERSION,
        role: role.as_str().to_string(),
        state_dump: format!(
            "no monux daemon answered on the control socket: {:#}\n\
             (the environment and journal below still describe this machine)",
            why
        ),
        recent_logs: Vec::new(),
        environment: Environment::collect().into_cli_fallback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostics_fixture() -> Diagnostics {
        Diagnostics {
            version: "1.5.0".to_string(),
            protocol_version: 8,
            role: "server".to_string(),
            state_dump: "switch=local grab=Ungrab".to_string(),
            recent_logs: vec!["INFO monux: started".to_string()],
            environment: Environment {
                build: "1.5.0+abc123".to_string(),
                arch: "x86_64".to_string(),
                ..Default::default()
            },
        }
    }

    fn bundle_fixture() -> Bundle {
        Bundle {
            diagnostics: diagnostics_fixture(),
            journal: JournalCapture {
                unit: "monux-server.service".to_string(),
                since: "-30min".to_string(),
                lines: vec!["2026-08-07T10:00:00+0000 host monux[1]: up".to_string()],
                note: None,
            },
            peers: Vec::new(),
        }
    }

    fn opts(format: Format) -> FormatOptions {
        FormatOptions {
            format,
            redact: false,
        }
    }

    #[test]
    fn the_plain_bundle_carries_every_section() {
        let out = format_bundle(&bundle_fixture(), opts(Format::Plain)).unwrap();
        assert!(out.contains("monux 1.5.0 diagnostics (server role, protocol 8)"));
        assert!(out.contains("== environment =="));
        assert!(out.contains("1.5.0+abc123"));
        assert!(out.contains("== state =="));
        assert!(out.contains("switch=local grab=Ungrab"));
        assert!(out.contains("== recent logs (oldest first) =="));
        assert!(out.contains("INFO monux: started"));
        assert!(out.contains("monux-server.service"));
    }

    #[test]
    fn empty_log_and_journal_captures_say_so() {
        let mut bundle = bundle_fixture();
        bundle.diagnostics.recent_logs.clear();
        bundle.journal.lines.clear();
        bundle.journal.note = Some("journalctl is not installed".to_string());
        let out = format_bundle(&bundle, opts(Format::Plain)).unwrap();
        assert!(out.contains("<no log lines captured>"));
        assert!(out.contains("<no journal lines>"));
        assert!(out.contains("[note] journalctl is not installed"));
    }

    #[test]
    fn the_markdown_bundle_is_an_issue_template_with_fenced_evidence() {
        let out = format_bundle(&bundle_fixture(), opts(Format::Markdown)).unwrap();
        assert!(out.contains("### What happened"));
        assert!(out.contains("### Steps to reproduce"));
        assert!(out.contains("<details><summary>Environment</summary>"));
        assert!(out.contains("```log"));
        assert!(out.contains("</details>"));
    }

    #[test]
    fn fences_outgrow_backticks_in_the_body() {
        // A log line quoting a fence must not end the block early.
        let body = "a ``` b ```` c";
        let out = fenced("T", "log", body);
        assert!(out.contains("`````log"), "{}", out);
        assert!(out.contains(body));
    }

    #[test]
    fn json_format_round_trips_the_bundle() {
        let out = format_bundle(&bundle_fixture(), opts(Format::Json)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["diagnostics"]["role"], "server");
        assert_eq!(v["journal"]["unit"], "monux-server.service");
        // Peers are omitted entirely when none were fetched.
        assert!(v.get("peers").is_none());
    }

    #[test]
    fn redaction_replaces_lan_addresses_and_keeps_loopback() {
        let text = "client 192.168.1.102:1213 fp d1d8 listen 0.0.0.0:1213 local 127.0.0.1";
        let out = redact(text);
        assert!(out.contains("<ip>:1213"));
        assert!(!out.contains("192.168.1.102"));
        // Non-identifying addresses stay: the dump is unreadable without them.
        assert!(out.contains("0.0.0.0:1213"));
        assert!(out.contains("127.0.0.1"));
        // Fingerprints are public key hashes, and they correlate the two
        // machines' logs.
        assert!(out.contains("fp d1d8"));
    }

    #[test]
    fn redaction_replaces_ipv6_but_spares_timestamps() {
        let text = "peer fe80::1c2d:3e4f:5a6b:7c8d at 2026-08-07T10:11:12Z";
        let out = redact(text);
        assert!(!out.contains("1c2d"), "{}", out);
        assert!(out.contains("<ipv6>"), "{}", out);
        // A clock time is not an address.
        assert!(out.contains("2026-08-07T10:11:12Z"), "{}", out);
    }

    #[test]
    fn redaction_refuses_names_the_report_is_made_of() {
        // A machine whose hostname is "monux" (this really happens):
        // substituting it would rewrite every log target and unit name.
        for name in ["monux", "server", "client", "Monux", "ab"] {
            assert!(is_unsubstitutable(name), "{} must be left alone", name);
        }
        for name in ["thinkpad", "alice", "desk-01"] {
            assert!(!is_unsubstitutable(name), "{} must be substitutable", name);
        }
    }

    #[test]
    fn whole_word_replacement_spares_substrings() {
        assert_eq!(replace_whole_words("alice ran", "alice", "<user>"), "<user> ran");
        // A name embedded in a longer identifier is not the name.
        assert_eq!(
            replace_whole_words("alicedomain ran", "alice", "<user>"),
            "alicedomain ran"
        );
        assert_eq!(
            replace_whole_words("/home/alice/x", "alice", "<user>"),
            "/home/<user>/x"
        );
        assert_eq!(replace_whole_words("none here", "alice", "<user>"), "none here");
    }

    /// A peer bundle whose Environment names the other machine, for the
    /// peer-redaction tests below.
    fn peer_fixture(label: &str, hostname: Option<&str>, username: Option<&str>) -> control::PeerDiagnostics {
        let mut d = diagnostics_fixture();
        d.role = "client".to_string();
        d.environment.hostname = hostname.map(str::to_string);
        d.environment.username = username.map(str::to_string);
        d.state_dump = "switch=active".to_string();
        d.recent_logs = vec![format!(
            "INFO monux: config at /home/{}/.config/monux on {}",
            username.unwrap_or("someone"),
            hostname.unwrap_or("somebox")
        )];
        control::PeerDiagnostics {
            label: label.to_string(),
            diagnostics: Ok(d),
        }
    }

    /// The gap this fixes: `--redact` used to scrub only the LOCAL machine's
    /// hostname, username and home paths, so a `--peer` bundle published the
    /// other machine's verbatim while PRIVACY_NOTE promised otherwise. The
    /// names now travel with each peer's Environment.
    #[test]
    fn redaction_scrubs_a_peers_identity_too() {
        let mut bundle = bundle_fixture();
        bundle.peers = vec![peer_fixture("aa11bb22 @ 10.0.0.5:1213", Some("thinkpad"), Some("bob"))];
        let out = format_bundle(
            &bundle,
            FormatOptions {
                format: Format::Plain,
                redact: true,
            },
        )
        .unwrap();

        assert!(!out.contains("thinkpad"), "the peer's hostname survived: {}", out);
        assert!(!out.contains("bob"), "the peer's username survived: {}", out);
        // The peer's home path folds to ~ like the local one, rather than
        // leaking the username through the path after the name pass.
        assert!(!out.contains("/home/bob"), "{}", out);
        assert!(out.contains("~/.config/monux"), "{}", out);
        assert!(out.contains("<hostname>"), "{}", out);
        // The peer's IP was already scrubbed before this change; still is.
        assert!(!out.contains("10.0.0.5"), "{}", out);
        // Nothing is owed for the PEER: both its names are substitutable, and
        // it reported them. (The skip list can still name the machine running
        // this test, whose hostname we don't control.)
        let skipped = redaction_skips(&bundle);
        assert!(!skipped.contains(&"thinkpad".to_string()), "{:?}", skipped);
        assert!(!skipped.contains(&"bob".to_string()), "{:?}", skipped);
        assert!(peers_missing_redaction_names(&bundle).is_empty());
    }

    /// A peer running a monux from before the names were on the wire can only
    /// be scrubbed for IPs. That must be REPORTED, not silently under-done.
    #[test]
    fn a_peer_without_reported_names_is_called_out() {
        let mut bundle = bundle_fixture();
        bundle.peers = vec![peer_fixture("aa11bb22 @ 10.0.0.5:1213", None, None)];
        assert_eq!(
            peers_missing_redaction_names(&bundle),
            vec!["aa11bb22 @ 10.0.0.5:1213".to_string()]
        );
        // A peer that DOES report them is not called out.
        let mut named = bundle_fixture();
        named.peers = vec![peer_fixture("cc33 @ 10.0.0.6:1213", Some("desk-01"), Some("carol"))];
        assert!(peers_missing_redaction_names(&named).is_empty());
    }

    /// A peer whose hostname is one of the words the report is structurally
    /// made of gets the same protection the local machine has always had:
    /// left in place, and named on the way out.
    #[test]
    fn a_peers_unsubstitutable_name_is_reported_not_mangled() {
        let mut bundle = bundle_fixture();
        bundle.peers = vec![peer_fixture("aa11 @ 10.0.0.5:1213", Some("monux"), Some("bo"))];
        let skipped = redaction_skips(&bundle);
        assert!(skipped.contains(&"monux".to_string()), "{:?}", skipped);
        assert!(skipped.contains(&"bo".to_string()), "{:?}", skipped);
        // ...and the report is still readable: log targets survive intact.
        let out = format_bundle(
            &bundle,
            FormatOptions {
                format: Format::Plain,
                redact: true,
            },
        )
        .unwrap();
        assert!(out.contains("INFO monux:"), "{}", out);
    }

    /// Two machines, two sets of names, one pass: each is replaced with the
    /// placeholder for the role it played, and a name that is both a hostname
    /// and a username is scrubbed once.
    #[test]
    fn names_dedupe_and_keep_their_placeholders() {
        let names = Names {
            hostnames: vec!["desk-01".to_string(), "laptop".to_string()],
            usernames: vec!["laptop".to_string(), "carol".to_string()],
        };
        assert_eq!(
            names.substitutions(),
            vec![
                ("desk-01", "<hostname>"),
                ("laptop", "<hostname>"),
                ("carol", "<user>"),
            ]
        );
        // Home paths are reconstructed per username, longest first so a
        // nested path can't be half-replaced.
        let homes = names.home_paths();
        assert!(homes.contains(&"/home/carol".to_string()), "{:?}", homes);
        assert!(homes.windows(2).all(|w| w[0].len() >= w[1].len()), "{:?}", homes);
    }

    #[test]
    fn redaction_applies_to_a_formatted_bundle() {
        let mut bundle = bundle_fixture();
        bundle.diagnostics.state_dump = "client 10.0.0.5:1213".to_string();
        let out = format_bundle(
            &bundle,
            FormatOptions {
                format: Format::Plain,
                redact: true,
            },
        )
        .unwrap();
        assert!(out.contains("<ip>:1213"));
        assert!(!out.contains("10.0.0.5"));
    }

    #[test]
    fn os_release_parsing_unquotes_the_pretty_name() {
        let content = "NAME=\"CachyOS Linux\"\nPRETTY_NAME=\"CachyOS Linux\"\nID=cachyos\n";
        assert_eq!(parse_os_release(content), Some("CachyOS Linux".to_string()));
        assert_eq!(parse_os_release("ID=none\n"), None);
        // An empty value is no answer at all.
        assert_eq!(parse_os_release("PRETTY_NAME=\"\"\n"), None);
    }

    #[test]
    fn the_environment_renders_every_row() {
        let env = Environment::collect();
        let out = env.render();
        for key in [
            "build:",
            "arch:",
            "os:",
            "kernel:",
            "WAYLAND_DISPLAY:",
            "uinput:",
            "input group:",
            "clipboard tools:",
        ] {
            assert!(out.contains(key), "missing {} in:\n{}", key, out);
        }
        // The build string always carries the embedded revision.
        assert!(out.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn the_cli_fallback_environment_is_labelled() {
        let env = Environment::collect().into_cli_fallback();
        assert!(env.render().starts_with("note: no daemon answered"));
    }

    #[test]
    fn an_unreported_environment_says_so_instead_of_showing_blank_rows() {
        // What a daemon from before this section existed deserializes to.
        let rendered = Environment::default().render();
        assert!(rendered.contains("predates the environment section"), "{}", rendered);
        // Not a wall of empty keys.
        assert!(!rendered.contains("kernel:"), "{}", rendered);
    }

    #[test]
    fn a_peer_that_could_not_be_reached_is_reported_not_dropped() {
        let mut bundle = bundle_fixture();
        bundle.peers.push(control::PeerDiagnostics {
            label: "d1d88653".to_string(),
            diagnostics: Err("timed out".to_string()),
        });
        let plain = format_bundle(&bundle, opts(Format::Plain)).unwrap();
        assert!(plain.contains("peer d1d88653"));
        assert!(plain.contains("could not be reached: timed out"));
        let md = format_bundle(&bundle, opts(Format::Markdown)).unwrap();
        assert!(md.contains("Peer d1d88653 could not be reached: timed out"));
    }

    #[test]
    fn a_reached_peer_contributes_its_own_sections() {
        let mut bundle = bundle_fixture();
        let mut peer = diagnostics_fixture();
        peer.role = "client".to_string();
        peer.state_dump = "connected=true".to_string();
        peer.recent_logs = vec!["INFO monux::client: linked".to_string()];
        bundle.peers.push(control::PeerDiagnostics {
            label: "d1d88653".to_string(),
            diagnostics: Ok(peer),
        });
        let out = format_bundle(&bundle, opts(Format::Plain)).unwrap();
        assert!(out.contains("== peer d1d88653 (client) =="));
        assert!(out.contains("connected=true"));
        assert!(out.contains("INFO monux::client: linked"));
    }

    #[test]
    fn an_empty_peer_list_names_the_cause_that_applies() {
        let mut d = diagnostics_fixture();
        d.protocol_version = crate::msgs::shared::PROTOCOL_VERSION;

        // A client simply has no peers to poll.
        assert!(empty_peers_reason(Role::Client, &d).contains("only applies to a server"));
        // A current server with nobody connected.
        assert!(empty_peers_reason(Role::Server, &d).contains("no connected clients"));
        // A server too old to have understood the flag must not be reported
        // as "no clients" — the user would go looking for a network problem.
        d.protocol_version = 17;
        let reason = empty_peers_reason(Role::Server, &d);
        assert!(reason.contains("predates peer diagnostics"), "{}", reason);
        assert!(reason.contains("mx daemon restart"), "{}", reason);
    }

    #[test]
    fn preparing_an_issue_hands_over_a_command_and_never_files_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.md");
        let out = prepare_issue(
            "# report body",
            Some("clipboard never crosses"),
            &diagnostics_fixture(),
            &path,
        );
        // The body goes to a FILE: a report is far too big for argv or a
        // ?body= query string.
        assert!(out.contains("Report written to"), "{}", out);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "# report body");
        // The title is quoted into the command, not interpolated raw.
        assert!(out.contains("\"clipboard never crosses\""), "{}", out);
        assert!(out.contains("File it with:"), "{}", out);
        // Filing is publishing: the reporter is told what is in it and sends
        // it themselves. Nothing here posts anything.
        assert!(out.contains("Review it before sending"), "{}", out);
        assert!(out.contains("--redact"), "{}", out);
    }

    #[test]
    fn an_untitled_issue_says_the_placeholder_needs_editing() {
        let dir = tempfile::tempdir().unwrap();
        let out = prepare_issue(
            "body",
            None,
            &diagnostics_fixture(),
            &dir.path().join("report.md"),
        );
        assert!(out.contains(TITLE_PLACEHOLDER), "{}", out);
        assert!(out.contains("Replace the title placeholder"), "{}", out);
    }

    #[test]
    fn an_unwritable_report_path_falls_back_instead_of_failing() {
        // A read-only or missing directory must not cost the user the report:
        // the clipboard copy and a stdin-fed command still get them there.
        let out = prepare_issue(
            "body",
            None,
            &diagnostics_fixture(),
            Path::new("/nonexistent-dir-xyz/report.md"),
        );
        assert!(out.contains("Could not write the report file"), "{}", out);
        assert!(out.contains("File it with:"), "{}", out);
    }

    #[test]
    fn the_privacy_note_states_both_halves() {
        assert!(PRIVACY_NOTE.contains("It does NOT contain"));
        assert!(PRIVACY_NOTE.contains("clipboard CONTENTS"));
        assert!(PRIVACY_NOTE.contains("--redact"));
    }

    #[test]
    fn probes_return_output_and_survive_a_nonzero_exit() {
        let out = probe("sh", &["-c", "echo hi; exit 1"]).unwrap();
        assert_eq!(out.trim(), "hi");
        // A missing program is an error, not a hang.
        assert!(probe("monux-no-such-program-xyz", &[]).is_err());
    }

    #[test]
    fn probes_time_out_instead_of_hanging() {
        let err = probe_with_timeout("sleep", &["30"], Duration::from_millis(150)).unwrap_err();
        assert!(err.to_string().contains("did not answer"), "{:#}", err);
    }

    #[test]
    fn wait_with_timeout_returns_status_or_none_on_expiry() {
        let mut fast = Command::new("true").spawn().unwrap();
        let status = wait_with_timeout(&mut fast, Duration::from_secs(5)).unwrap();
        assert!(status.expect("a fast child exits before the deadline").success());

        let mut slow = Command::new("sleep").arg("30").spawn().unwrap();
        let status = wait_with_timeout(&mut slow, Duration::from_millis(150)).unwrap();
        assert!(status.is_none(), "the deadline must expire first");
        let _ = slow.kill();
        let _ = slow.wait();
    }
}
