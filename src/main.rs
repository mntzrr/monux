use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use regex::Regex;
use signal_hook::{consts::signal, iterator::Signals};
use tokio::sync::{mpsc, watch as watchchan};
use tokio::{runtime, task, time};
use tracing::{debug, error, info, warn};

use monux::device::output::OutputHandler;
use monux::device::{handles, input, output, shortcut, watch, Event};
use monux::network::{approval, transport::NetworkMode};
use monux::{client, clipboard, discovery, logging, rotation, server, single_instance};

/// Version string including the git revision (see build.rs).
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("MONUX_GIT_SHA"));

/// Help section headings, shared so every subcommand groups its flags the same
/// way: a reader who learned the layout on 'server --help' knows it everywhere.
const H_SWITCHING: &str = "Switching";
const H_EDGES: &str = "Screen edges";
const H_NETWORK: &str = "Network";
const H_TUNING: &str = "Tuning";
const H_DAEMON: &str = "Daemon behavior";
const H_TARGET: &str = "Which daemon";
const H_OUTPUT: &str = "Output";
const H_CONTENT: &str = "Bundle contents";

/// Help colors: headings, flag names, and value placeholders each get their own
/// style, so a dense --help reads as a table rather than a paragraph. Colors are
/// dropped automatically when stdout is not a terminal (clap's own detection).
fn help_styles() -> clap::builder::Styles {
    use clap::builder::styling::{AnsiColor, Effects};
    clap::builder::Styles::styled()
        .header(AnsiColor::Green.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Cyan.on_default())
        .valid(AnsiColor::Green.on_default())
        .invalid(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
}

#[derive(Parser)]
#[command(
    author,
    version = format!("{} (protocol {})", VERSION, monux::msgs::shared::PROTOCOL_VERSION),
    about,
    long_about = format!(
        "{}\n\nWire protocol version: {}",
        env!("CARGO_PKG_DESCRIPTION"),
        monux::msgs::shared::PROTOCOL_VERSION
    ),
    styles = help_styles(),
    after_help = "\
Examples:
  monux server      # machine with the physical keyboard/mouse
  monux client      # each machine to control (mDNS auto-discovery)
  monux status      # live state of the running daemon

Run 'monux <command> --help' for the full reference on any command.",
    after_long_help = "\
Examples:
  monux server      # machine with the physical keyboard/mouse
  monux client      # each machine to control (mDNS auto-discovery)
  monux status      # live state of the running daemon
  monux update      # update to the latest version from GitHub"
)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Runs a Monux server
    ///
    /// The machine with the physical input devices; clients connect to it.
    #[command(after_long_help = "\
Examples:
  monux server
  monux server --edge-map bottom=auto    # switch input at the bottom screen edge
  monux server --www                     # conservative tuning for the public internet
  monux server --fingerprints aa11bbcc   # pre-approve a client (no approval prompt)")]
    Server(ServerArgs),

    /// Runs a Monux client
    ///
    /// A machine to be controlled; connects to the given server, or discovers
    /// it on the LAN via mDNS when no host is given.
    #[command(after_long_help = "\
Examples:
  monux client                     # discover the server via mDNS
  monux client 192.168.1.187       # connect directly
  monux client --www kvm.example.com
  monux client --mouse-scale 0.5   # compensate DPI/sensitivity differences")]
    Client(ClientArgs),

    /// Optimizes this machine for local KVM, persisting machine-local settings
    ///
    /// No flags: applies everything ('input' group membership, /dev/uinput
    /// permissions, WiFi power saving off, raised UDP socket buffers, DSCP
    /// QoS marking) and re-executes with sudo automatically. ANY flag scopes
    /// the run to that flag's actions only; '--autostart' manages a per-user
    /// systemd unit and '--desktop-shortcut' a per-user app-menu entry, both
    /// WITHOUT elevating.
    #[command(after_long_help = "\
Examples:
  monux setup                        # apply everything (elevates via sudo)
  monux setup --autostart server     # only install the login service (no sudo)
  monux setup --autostart status     # report the autostart state (no sudo, read-only)
  monux setup --desktop-shortcut     # install the app-menu tray shortcut (no sudo)")]
    Setup(SetupArgs),

    /// Updates monux to the latest version from GitHub, rebuilding from source
    ///
    /// The server protocol-compatibility gate is first refreshed from the
    /// mDNS advertisements of servers on the LAN, so a client never installs
    /// a build its server couldn't talk to ('--force' bypasses). '--to'
    /// installs a specific older (or newer) build instead — downgrade the
    /// server first — and pins auto-update so it never undoes the downgrade;
    /// a plain update lifts the pin.
    #[command(after_long_help = "\
Examples:
  monux update                # update to the latest version (also lifts a downgrade pin)
  monux update --force        # rebuild even if up to date, bypassing the protocol gate
  monux update --to 8.3.0     # downgrade to a released version (pins auto-update)
  monux update --to 5b4c00e   # downgrade to a commit
  monux update --rollback     # return to the previously installed build")]
    Update(UpdateArgs),

    /// Prints the live state of the running monux daemon (server or client)
    ///
    /// Queries the control socket in $XDG_RUNTIME_DIR/monux/ (server socket
    /// first, then the client's): rotation target, connected clients with
    /// fingerprint prefixes and resolved edge directions (the reference for
    /// configuring --edge-map), clipboard owner, update availability.
    #[command(after_long_help = "\
Examples:
  monux status              # server socket first, then the client's
  monux status --json       # machine-readable raw response
  monux status --server     # restrict to one role (or --client)")]
    Status(StatusArgs),

    /// Collects a bug-report bundle: daemon state, logs, journal, environment
    ///
    /// Everything a monux bug report needs, in one paste: the daemon's state
    /// dump and recent log lines, the systemd unit's journal, and the
    /// environment the daemon runs in (kernel, session, /dev/uinput
    /// permissions, autostart state). With no daemon running it still reports
    /// the environment and the journal — which is where the answer lives for
    /// "monux won't start" and "monux crashed".
    ///
    /// --privacy prints exactly what a bundle contains, and --redact strips
    /// IP addresses, hostnames, usernames and home paths before it leaves the
    /// machine.
    #[command(after_long_help = "\
Examples:
  monux diagnostics                  # read it here
  monux diagnostics --copy           # issue-ready markdown, on the clipboard
  monux diagnostics --issue          # ...plus the command that files it on GitHub
  monux diagnostics --redact --issue # ...with IPs and hostnames stripped first
  monux diagnostics --peer           # include the connected clients' side (server)
  monux diagnostics --privacy        # what a bundle contains, before you paste it
  monux diagnostics record           # capture a live reproduction to a file")]
    Diagnostics(DiagnosticsArgs),

    /// Lists the servers visible on the LAN and remembered from past connects
    ///
    /// The union of live mDNS advertisements and the remembered-servers
    /// store (~/.config/monux/known_servers, written on every successful
    /// connect). Display only: nothing is probed or connected to. One line
    /// per server address: name, ip:port, fingerprint prefix, protocol
    /// version, source ('mdns', or 'remembered' with the last connect); an
    /// address visible via both shows once, as mdns. Every printed field is
    /// a valid connect target for 'monux client'.
    #[command(after_long_help = "\
Examples:
  monux servers                  # what's out there, what do I remember
  monux client 192.168.1.187     # connect by address
  monux client myhost            # connect by remembered/mDNS name
  monux client aabbccdd          # connect by fingerprint prefix")]
    Servers,

    /// Desktop GUI integration: the tray indicator and its visibility
    #[command(after_long_help = "\
Examples:
  monux gui indicator    # run the tray icon (usually auto-spawned by the daemon)
  monux gui tray hide    # hide the icon without stopping the daemon
  monux gui tray show    # bring it back — or start a standalone tray when no daemon runs")]
    Gui(GuiArgs),

    /// Manages the persistent configuration (~/.config/monux/config.toml)
    ///
    /// The config file stores flag values for the server and client daemons,
    /// keyed by the flag long-names under [server] / [client] sections. An
    /// explicit CLI flag always beats the config file, which beats the
    /// built-in default. Daemons read the file once at startup.
    #[command(after_long_help = "\
Examples:
  monux config                             # effective values and their source
  monux config keys edge                   # the key reference, filtered
  monux config set server.port 4321        # persist a value (validated like --port)
  monux config set server.edge-map right=auto left=aa11bb
  monux config unset client.mouse-scale    # revert to the built-in default
  monux config edit                        # edit in $EDITOR, validated on save
  monux config history server.shortcut     # previous values, newest first
  monux config revert server.shortcut      # restore the previous value (undoable)")]
    Config(ConfigArgs),

    /// Manages a running monux daemon through its control socket
    ///
    /// Switching input between machines, pausing, restarting, and more.
    #[command(after_long_help = "\
Examples:
  monux daemon switch next    # or prev / local / a client fingerprint prefix
  monux daemon pause          # ungrab everything (raw local input)
  monux daemon resume
  monux daemon restart        # graceful restart into the installed binary
  monux daemon exit           # graceful stop")]
    Daemon(DaemonArgs),

    /// Destructive operations: removing monux from this machine
    #[command(after_long_help = "\
Examples:
  monux system uninstall           # interactive confirmation
  monux system uninstall --yes     # no prompt (for scripts)")]
    System(SystemArgs),
}

#[derive(Args)]
struct SystemArgs {
    #[command(subcommand)]
    command: SystemCommands,
}

#[derive(Args)]
struct GuiArgs {
    #[command(subcommand)]
    command: GuiCommands,
}

#[derive(Args)]
struct DaemonArgs {
    #[command(subcommand)]
    command: DaemonCommands,
}

#[derive(Args)]
struct ConfigArgs {
    /// show / keys / set / unset / edit / validate; bare 'monux config' shows
    /// the effective values
    #[command(subcommand)]
    command: Option<ConfigCommands>,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Shows the effective configuration [default action]
    ///
    /// Every key with its value and whether it came from the config file or
    /// the built-in default.
    Show,

    /// Lists every config key with its syntax and default
    ///
    /// One line of description per key, the expected value syntax, and the
    /// built-in default; keys introduced after the baseline are annotated
    /// (new in vX.Y).
    Keys {
        /// Only list keys whose name or description contains this substring
        filter: Option<String>,
    },

    /// Sets a config key (no value: print the key's reference card)
    ///
    /// Values are validated with the same parsers as the flags before
    /// anything is written; repeatable (array) keys take multiple values.
    Set {
        /// The full key name: server.<flag> or client.<flag>
        key: String,
        /// The value(s) to store
        values: Vec<String>,
    },

    /// Removes a config key, reverting it to the built-in default
    Unset {
        /// The full key name: server.<flag> or client.<flag>
        key: String,
    },

    /// Edits the config file in $EDITOR, installing it only if it validates
    ///
    /// Falls back to vi, and keeps the previous file on a failed validation —
    /// crontab-style.
    Edit,

    /// Checks the config file without changing it
    ///
    /// Reports unknown keys (with did-you-mean suggestions and the exact
    /// 'unset' cleanup lines) and invalid values, with line numbers.
    Validate,

    /// Shows a key's previous values, newest first
    ///
    /// The current value and the stack of previous values with timestamps —
    /// the preview of what 'revert' restores. Every set, unset, edit, and
    /// revert banks the replaced value as a '# was:' comment above the key
    /// (at most 5 per key). Omit the key to list every key that has history.
    History {
        /// The full key name: server.<flag> or client.<flag>
        ///
        /// Omit it to list every key that has history.
        key: Option<String>,
    },

    /// Restores a key's previous value from its history
    ///
    /// The newest entry (or the one matching --to) is re-validated and set,
    /// banking the current value — a revert is itself undoable. Recreates the
    /// key line when the key was unset.
    Revert {
        /// The full key name: server.<flag> or client.<flag>
        key: String,
        /// Restore the entry with this exact timestamp instead of the newest
        #[arg(long)]
        to: Option<String>,
    },
}

#[derive(Subcommand)]
enum DaemonCommands {
    /// Switches input to another machine
    ///
    /// The target is the next or previous client, the local machine, or a
    /// client fingerprint prefix.
    Switch(DaemonSwitchArgs),

    /// Pauses input handling, leaving the daemon listening
    ///
    /// All devices are ungrabbed, so the local machine gets raw input. Resume
    /// with 'monux daemon resume'.
    Pause,

    /// Resumes input handling after a pause
    Resume,

    /// Gracefully restarts the daemon into the installed binary
    ///
    /// The session resumes automatically.
    Restart,

    /// Gracefully stops the daemon
    ///
    /// Clients reconnect on its next start.
    Exit,

    /// Wakes the background update check immediately
    ///
    /// Instead of waiting for the daily tick.
    Update,
}

#[derive(Subcommand)]
enum GuiCommands {
    /// Runs a StatusNotifierItem tray indicator for the local monux daemon
    ///
    /// A colored dot (green = input local, blue = input on a client, grey =
    /// paused, red = degraded link / client not connected, hollow "?" = monux
    /// not running) whose menu drives switches, pause/resume, update checks,
    /// diagnostics copy, and restart/exit via the control socket. Needs a
    /// desktop session with an SNI host (waybar, KDE Plasma, ...). Started
    /// automatically with 'monux server'/'monux client' (opt out with
    /// --no-indicator); a manually started instance takes over from the
    /// auto-spawned one — only one indicator runs at a time.
    Indicator,

    /// Hides or restores the tray indicator
    ///
    /// 'hide' SIGTERMs the daemon's spawned indicator and suppresses respawns
    /// (the daemon itself keeps running), 'show' spawns it again. The hidden
    /// state is per-daemon-run only — a daemon restart always starts the
    /// indicator. Talks to the daemon's control socket (server socket first,
    /// then the client's), like 'monux status'. When NO daemon answers on the
    /// default discovery path, 'show' instead starts a standalone tray
    /// indicator (its menu offers to start the server or client); an explicit
    /// --socket that doesn't answer stays an error.
    Tray(TrayArgs),
}

#[derive(Subcommand)]
enum SystemCommands {
    /// Removes monux from this machine
    ///
    /// Stops any running server/client, then removes the binary (and stale
    /// copies), the /usr/local/bin link, and the system settings persisted by
    /// 'monux setup'. Asks for confirmation first (skip with '--yes'), and
    /// separately before also removing ~/.config/monux (identity keypair and
    /// peer approvals).
    Uninstall(UninstallArgs),
}

#[derive(Args)]
struct UninstallArgs {
    /// Skip the interactive confirmation prompt (for scripts)
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
struct DaemonSwitchArgs {
    /// next, prev, local, or a client fingerprint prefix
    #[arg(value_name = "target")]
    target: String,

    /// Query this explicit control socket path
    ///
    /// Instead of the default $XDG_RUNTIME_DIR/monux/{server,client}.sock
    /// locations.
    #[arg(long, value_name = "path")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct StatusArgs {
    /// Query the server daemon's socket only
    #[arg(long, conflicts_with = "client", help_heading = H_TARGET)]
    server: bool,

    /// Query the client daemon's socket only
    #[arg(long, help_heading = H_TARGET)]
    client: bool,

    /// Query this explicit control socket path
    ///
    /// Instead of the default $XDG_RUNTIME_DIR/monux/{server,client}.sock
    /// locations.
    #[arg(long, value_name = "path", help_heading = H_TARGET)]
    socket: Option<PathBuf>,

    /// Print the daemon's raw JSON response instead of a human-readable summary
    #[arg(long, help_heading = H_OUTPUT)]
    json: bool,
}

#[derive(Args)]
struct DiagnosticsArgs {
    /// Capture a live reproduction instead of a snapshot (see 'record --help')
    #[command(subcommand)]
    command: Option<DiagnosticsCommands>,

    /// Query the server daemon's socket only
    #[arg(long, conflicts_with = "client", help_heading = H_TARGET)]
    server: bool,

    /// Query the client daemon's socket only
    #[arg(long, help_heading = H_TARGET)]
    client: bool,

    /// Query this explicit control socket path
    ///
    /// Instead of the default $XDG_RUNTIME_DIR/monux/{server,client}.sock
    /// locations.
    #[arg(long, value_name = "path", help_heading = H_TARGET)]
    socket: Option<PathBuf>,

    /// Copy the bundle to the clipboard (as markdown) instead of printing it
    #[arg(long, help_heading = H_OUTPUT)]
    copy: bool,

    /// Render as issue-ready markdown [default with --copy]
    #[arg(long, conflicts_with_all = ["plain", "json"], help_heading = H_OUTPUT)]
    markdown: bool,

    /// Render as plain text [default when printing]
    #[arg(long, conflicts_with = "json", help_heading = H_OUTPUT)]
    plain: bool,

    /// Print the bundle as raw JSON
    #[arg(long, help_heading = H_OUTPUT)]
    json: bool,

    /// Strip IPs, hostnames, usernames and home paths
    ///
    /// Replaces them with placeholders before the bundle leaves this machine.
    #[arg(long, help_heading = H_OUTPUT)]
    redact: bool,

    /// Recent daemon log lines to include
    #[arg(long, value_name = "n", default_value_t = monux::diagnostics::DEFAULT_LOG_LINES, help_heading = H_CONTENT)]
    lines: usize,

    /// How far back to read the systemd journal (a journalctl --since value)
    #[arg(long, value_name = "when", default_value = monux::diagnostics::DEFAULT_JOURNAL_SINCE, help_heading = H_CONTENT)]
    since: String,

    /// Skip the journal entirely
    #[arg(long, conflicts_with = "since", help_heading = H_CONTENT)]
    no_journal: bool,

    /// Also fetch connected clients' bundles (server only)
    ///
    /// So one paste covers both sides of the link.
    #[arg(long, help_heading = H_CONTENT)]
    peer: bool,

    /// Prepare a ready-to-file GitHub issue
    ///
    /// Writes the report to a file, copies it to the clipboard, and prints
    /// the command that files it. Never posts anything by itself: filing is
    /// publishing, so you review and send.
    #[arg(long, conflicts_with = "copy", help_heading = H_OUTPUT)]
    issue: bool,

    /// Title for the issue prepared by --issue
    ///
    /// A placeholder to edit is used when this is omitted.
    #[arg(long, value_name = "text", requires = "issue", help_heading = H_OUTPUT)]
    title: Option<String>,

    /// Print what a bundle contains — and never contains — then exit
    #[arg(long, help_heading = H_CONTENT)]
    privacy: bool,
}

#[derive(Subcommand)]
enum DiagnosticsCommands {
    /// Records a live reproduction to a file, until Ctrl-C
    ///
    /// Runs monux with verbose logging and captures everything to a file.
    ///
    /// For bugs a snapshot can't show — an input freeze, a dead key, a stall
    /// under load. Start it, reproduce the problem, press Ctrl-C: the capture
    /// file it prints is what to attach to the report.
    #[command(after_long_help = "\
Examples:
  monux diagnostics record                  # capture a server reproduction
  monux diagnostics record --client         # ...of the client daemon
  monux diagnostics record --keys 28,42     # also trace these key codes (28 = Enter)
  monux diagnostics record --trace          # everything, including QUIC internals")]
    Record(RecordArgs),
}

#[derive(Args)]
struct RecordArgs {
    /// Record the client daemon instead of the server
    #[arg(long)]
    client: bool,

    /// Key codes to trace through the input pipeline, comma-separated
    ///
    /// For example 28 = Enter. Every stage that sees them logs a KEYTRACE line.
    #[arg(long, value_name = "codes")]
    keys: Option<String>,

    /// Log at trace level (very verbose, includes QUIC internals)
    #[arg(long)]
    trace: bool,

    /// Write the capture here instead of a generated path under $TMPDIR
    #[arg(long, value_name = "path")]
    out: Option<PathBuf>,

    /// Arguments to pass through to the daemon being recorded
    #[arg(trailing_var_arg = true, value_name = "daemon args")]
    args: Vec<String>,
}

#[derive(Args)]
struct TrayArgs {
    /// Whether to remove or restore the tray icon
    ///
    /// 'hide' removes the tray icon (the daemon keeps running), 'show'
    /// restores it — or starts a standalone tray when no daemon runs.
    #[arg(value_enum, value_name = "hide|show")]
    action: TrayAction,

    /// Send the command to this explicit control socket path
    ///
    /// Instead of the default $XDG_RUNTIME_DIR/monux/{server,client}.sock
    /// locations.
    #[arg(long, value_name = "path")]
    socket: Option<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum TrayAction {
    Hide,
    Show,
}

#[derive(Args)]
struct SetupArgs {
    /// Manage the login service (no sudo) [default: leave it alone]
    ///
    /// Also (de)activate autostart via a per-user systemd service: 'server' or
    /// 'client' writes ~/.config/systemd/user/monux-<role>.service and
    /// enables+starts it (client runs without an address, using mDNS
    /// auto-discovery); 'off' disables and removes both; 'status' prints a
    /// read-only report for both roles (unit installed? enabled? running —
    /// autostarted or manually?) and changes nothing. When omitted, no
    /// autostart changes are made.
    #[arg(long, value_enum, value_name = "server|client|status|off")]
    autostart: Option<monux::setup::Autostart>,

    /// Install the 'monux tray' app-menu shortcut (no sudo)
    ///
    /// The shortcut runs 'monux gui tray show': writes
    /// ~/.local/share/applications/monux-tray.desktop (XDG_DATA_HOME
    /// honored). User-level, like --autostart: no elevation.
    #[arg(long)]
    desktop_shortcut: bool,
}

// Every flag below opens with a one-line summary, then a blank line, then the
// detail. clap shows only the first paragraph for '-h' and the whole comment for
// '--help', so that split is what keeps '-h' a scannable table.
#[derive(Args)]
struct ServerArgs {
    /// Chord that switches to the next client [default: leftshift,leftalt,r]
    #[arg(long, alias = "shortcut-next", value_name = "key1,key2,key3", help_heading = H_SWITCHING)]
    shortcut: Option<String>,

    /// Chord that switches to the previous client [default: leftalt,p]
    #[arg(long, value_name = "key1,key2,key3", help_heading = H_SWITCHING)]
    shortcut_prev: Option<String>,

    /// Chord that switches straight to one client, by fingerprint prefix
    ///
    /// An empty fingerprint targets the server itself. Repeatable, one chord
    /// per target.
    #[arg(long, value_name = "key1,key2,key3=[fingerprint-prefix]", help_heading = H_SWITCHING)]
    shortcut_goto: Option<Vec<String>>,

    /// Chord that pauses/resumes input handling [default: disabled]
    ///
    /// While paused, ALL input devices (keyboards included) are ungrabbed so
    /// the local machine gets raw input with monux's re-emit out of the way
    /// (games, raw-input apps); press the chord again to resume. Disabled
    /// unless set (e.g. '--pause-shortcut leftshift,leftalt,p').
    #[arg(long, value_name = "key1,key2,key3", help_heading = H_SWITCHING)]
    pause_shortcut: Option<String>,

    /// Switch input at a screen edge: 'right=auto', 'left=aa11bb'
    ///
    /// Screen-edge switching (Hyprland only for now): switch input to a client
    /// when the cursor is pushed against this screen edge and dwells there.
    /// Repeatable and comma-separated: '--edge-map right=auto --edge-map left=aa11bb'
    /// or '--edge-map right=auto,left=laptop'. The target is a client fingerprint
    /// prefix (see the 'Added client ...' log line), a hostname, or 'auto' for
    /// exactly-one-connected-client. Multi-monitor setups expose only the outer
    /// edge segments; ~8% at each end of a segment is a corner dead zone.
    /// Pin a direction to one monitor with 'direction@monitor=target', e.g.
    /// 'bottom@eDP-1=auto': the qualified entry wins on its monitor, an
    /// unqualified entry for the same direction covers the others, and a
    /// qualified entry ALONE leaves the other monitors' edges in that
    /// direction inert. The qualifier is the output name (the default), or
    /// the monitor's serial, model, or description when the compositor
    /// reports them (Hyprland; see the layout log lines) — those survive
    /// output renames across restarts, so prefer the serial or model, e.g.
    /// '--edge-map bottom@83JLZ23=auto' (quote forms containing spaces; a
    /// literal ',' '=' or '@' can't appear in a qualifier). A qualifier
    /// matching several outputs (identical models) zones all of them.
    /// The server also advertises this layout to each mapped client
    /// (protocol v12+), so the client infers its return edge automatically —
    /// no client --edge-map needed unless you want to override the inference.
    #[arg(long, value_name = "direction[@monitor]=target", help_heading = H_EDGES)]
    edge_map: Option<Vec<String>>,

    /// Dwell time on the edge before the switch fires [default: 250]
    ///
    /// In milliseconds; see --edge-map.
    #[arg(long, value_name = "ms", help_heading = H_EDGES)]
    edge_dwell_ms: Option<u64>,

    /// Listen IP [default: 0.0.0.0]
    #[arg(short = 'l', long, value_name = "ip", help_heading = H_NETWORK)]
    listen: Option<IpAddr>,

    /// Listen port [default: 1213]
    #[arg(short = 'p', long, value_name = "port", help_heading = H_NETWORK)]
    port: Option<u16>,

    /// Pre-approve a client certificate fingerprint (repeatable)
    ///
    /// A client whose fingerprint is listed connects without the interactive
    /// approval prompt.
    #[arg(long, alias = "fingerprints", value_name = "fingerprint", help_heading = H_NETWORK)]
    fingerprint: Option<Vec<String>>,

    /// Tune for the public internet instead of a LAN
    ///
    /// Use conservative tuning suitable for traversing the public internet
    /// (WWW). The default is low-latency tuning for local networks.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_NETWORK)]
    www: Option<bool>,

    /// Pointer motion forwarding rate [default: adaptive 250-500]
    ///
    /// Target rate for forwarding pointer motion, in updates per second. Motion
    /// deltas are coalesced (summed losslessly) between updates and sent as
    /// unreliable datagrams with recent deltas repeated, so WiFi loss neither
    /// stalls nor misplaces the cursor. Unset (the default): adaptive — 250
    /// normally, raised to 500 while the link is measured close and clean.
    /// Set a number to pin the rate, or 0 to forward every event as it comes
    /// (e.g. for gaming with a high-polling-rate mouse).
    #[arg(long, value_name = "hz", help_heading = H_TUNING)]
    motion_hz: Option<u32>,

    /// Clipboard/bulk transfer pacing [default: adaptive 40-160]
    ///
    /// Pace clipboard/bulk transfers to this many megabits per second. QUIC
    /// stream priorities only order data inside the connection; the
    /// kernel/WiFi driver queue below is FIFO, so an unthrottled multi-MB
    /// clipboard transfer fills it and input packets behind it wait for the
    /// whole backlog to drain (bufferbloat: RTT spikes for the duration of
    /// the transfer). Unset (the default): adaptive — 40 normally, raised to
    /// 160 while the link is measured close and clean. Set a number to pin
    /// the rate (5MB takes ~1s at 40Mbps), or 0 to disable pacing.
    #[arg(long, value_name = "mbps", value_parser = monux::config::parse_bulk_throttle, help_heading = H_TUNING)]
    bulk_throttle_mbps: Option<f64>,

    /// Largest clipboard payload to transfer [default: 5MB]
    #[arg(long, value_name = "kb", help_heading = H_TUNING)]
    max_clipboard_size_kb: Option<u64>,

    /// Only monitor devices matching this pattern (repeatable)
    ///
    /// A substring or regular expression matched against the device name;
    /// repeat the flag for multiple filters.
    #[arg(long, value_name = "device-name-pattern", help_heading = H_TUNING)]
    device: Option<Vec<Regex>>,

    /// Turn off the automatic background update
    ///
    /// The background update is on by default: a daily check at low CPU
    /// priority, then an automatic restart into the new binary. The session
    /// resumes automatically on reconnect.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_DAEMON)]
    no_auto_update: Option<bool>,

    /// Do not auto-spawn the tray indicator
    ///
    /// By default 'monux gui indicator' starts once the daemon is up whenever
    /// a desktop session bus is available, and stops with the daemon. Can
    /// also be disabled with MONUX_NO_INDICATOR=1.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_DAEMON)]
    no_indicator: Option<bool>,

    /// Exit automatically after this many seconds, to test a configuration safely
    #[arg(long, value_name = "seconds", help_heading = H_DAEMON)]
    exit_secs: Option<u32>,
}

impl ServerArgs {
    /// Fills config-capable fields left unset on the command line from the
    /// config file's [server] section: explicit flag > config file > built-in
    /// default (the default is applied at the use sites).
    fn resolve(&mut self, cfg: &monux::config::File) {
        self.shortcut = self.shortcut.take().or_else(|| cfg.get_str("server.shortcut"));
        self.shortcut_prev = self
            .shortcut_prev
            .take()
            .or_else(|| cfg.get_str("server.shortcut-prev"));
        self.shortcut_goto = self
            .shortcut_goto
            .take()
            .or_else(|| cfg.get_str_vec("server.shortcut-goto"));
        self.pause_shortcut = self
            .pause_shortcut
            .take()
            .or_else(|| cfg.get_str("server.pause-shortcut"));
        self.device = self.device.take().or_else(|| cfg.get_regex_vec("server.device"));
        self.listen = self.listen.take().or_else(|| cfg.get_ip("server.listen"));
        self.port = self.port.take().or_else(|| cfg.get_int("server.port"));
        self.fingerprint = self
            .fingerprint
            .take()
            .or_else(|| cfg.get_str_vec("server.fingerprint"));
        self.exit_secs = self.exit_secs.take().or_else(|| cfg.get_int("server.exit-secs"));
        self.max_clipboard_size_kb = self
            .max_clipboard_size_kb
            .take()
            .or_else(|| cfg.get_int("server.max-clipboard-size-kb"));
        self.www = self.www.take().or_else(|| cfg.get_bool("server.www"));
        self.motion_hz = self.motion_hz.take().or_else(|| cfg.get_int("server.motion-hz"));
        self.bulk_throttle_mbps = self
            .bulk_throttle_mbps
            .take()
            .or_else(|| cfg.get_f64("server.bulk-throttle-mbps"));
        self.edge_map = self.edge_map.take().or_else(|| cfg.get_str_vec("server.edge-map"));
        self.edge_dwell_ms = self
            .edge_dwell_ms
            .take()
            .or_else(|| cfg.get_int("server.edge-dwell-ms"));
        self.no_auto_update = self
            .no_auto_update
            .take()
            .or_else(|| cfg.get_bool("server.no-auto-update"));
        self.no_indicator = self
            .no_indicator
            .take()
            .or_else(|| cfg.get_bool("server.no-indicator"));
    }
}

#[derive(Args)]
struct ClientArgs {
    /// Server hostname or IP [default: discover via mDNS]
    ///
    /// If omitted, the server is discovered on the local network via mDNS.
    host: Option<String>,

    /// Server port [default: 1213]
    #[arg(short = 'p', long, value_name = "port", help_heading = H_NETWORK)]
    port: Option<u16>,

    /// Pre-approve a server certificate fingerprint (repeatable)
    ///
    /// A server whose fingerprint is listed connects without the interactive
    /// approval prompt.
    #[arg(long, alias = "fingerprints", value_name = "fingerprint", help_heading = H_NETWORK)]
    fingerprint: Option<Vec<String>>,

    /// Tune for the public internet instead of a LAN
    ///
    /// Use conservative tuning suitable for traversing the public internet
    /// (WWW). The default is low-latency tuning for local networks.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_NETWORK)]
    www: Option<bool>,

    /// Return to the server at a screen edge: 'left=auto'
    ///
    /// Switching BACK to the server by screen edge (Hyprland only for now):
    /// while this client has input, pushing the cursor against this screen
    /// edge and dwelling there asks the server to take input back. Usually
    /// unnecessary: when the server maps this client to one of its edges, the
    /// client infers the opposite edge automatically — this flag overrides
    /// that inference. Same syntax as the server's --edge-map (including the
    /// 'direction@monitor=auto' form pinning a direction to one monitor by
    /// output name, serial, model, or description), but the only valid
    /// target is 'auto' (the server — a client has exactly one peer).
    /// Multi-monitor setups expose only the outer edge segments; ~8% at each
    /// end of a segment is a corner dead zone.
    #[arg(long, value_name = "direction[@monitor]=auto", help_heading = H_EDGES)]
    edge_map: Option<Vec<String>>,

    /// Dwell time on the edge before the return fires [default: 250]
    ///
    /// In milliseconds; see --edge-map.
    #[arg(long, value_name = "ms", help_heading = H_EDGES)]
    edge_dwell_ms: Option<u64>,

    /// Scale incoming pointer motion [default: 1.0]
    ///
    /// Multiplier applied to pointer motion deltas before injecting them on
    /// this machine, for compensating DPI/sensitivity differences with the
    /// server's mouse. Sub-tick fractions are carried between events, so small
    /// scales lose no motion over time.
    #[arg(long, value_name = "scale", value_parser = monux::config::parse_input_scale, help_heading = H_TUNING)]
    mouse_scale: Option<f64>,

    /// Scale incoming scroll wheel deltas [default: 1.0]
    ///
    /// Applies to the hi-res wheel axes as well.
    #[arg(long, value_name = "scale", value_parser = monux::config::parse_input_scale, help_heading = H_TUNING)]
    scroll_scale: Option<f64>,

    /// Clipboard/bulk transfer pacing [default: adaptive 40-160]
    ///
    /// Pace clipboard/bulk transfers to this many megabits per second. QUIC
    /// stream priorities only order data inside the connection; the
    /// kernel/WiFi driver queue below is FIFO, so an unthrottled multi-MB
    /// clipboard transfer fills it and input packets behind it wait for the
    /// whole backlog to drain (bufferbloat: RTT spikes for the duration of
    /// the transfer). Unset (the default): adaptive — 40 normally, raised to
    /// 160 while the link is measured close and clean. Set a number to pin
    /// the rate (5MB takes ~1s at 40Mbps), or 0 to disable pacing.
    #[arg(long, value_name = "mbps", value_parser = monux::config::parse_bulk_throttle, help_heading = H_TUNING)]
    bulk_throttle_mbps: Option<f64>,

    /// Largest clipboard payload to transfer [default: 5MB]
    #[arg(long, value_name = "kb", help_heading = H_TUNING)]
    max_clipboard_size_kb: Option<u64>,

    /// Turn off the automatic background update
    ///
    /// The background update is on by default: a daily check at low CPU
    /// priority, then an automatic restart into the new binary. The session
    /// resumes automatically on reconnect.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_DAEMON)]
    no_auto_update: Option<bool>,

    /// Do not auto-spawn the tray indicator
    ///
    /// By default 'monux gui indicator' starts once the daemon is up whenever
    /// a desktop session bus is available, and stops with the daemon. Can
    /// also be disabled with MONUX_NO_INDICATOR=1.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_DAEMON)]
    no_indicator: Option<bool>,
}

impl ClientArgs {
    /// Fills config-capable fields left unset on the command line from the
    /// config file's [client] section: explicit flag > config file > built-in
    /// default (the default is applied at the use sites). The positional host
    /// is deliberately not configurable.
    fn resolve(&mut self, cfg: &monux::config::File) {
        self.port = self.port.take().or_else(|| cfg.get_int("client.port"));
        self.fingerprint = self
            .fingerprint
            .take()
            .or_else(|| cfg.get_str_vec("client.fingerprint"));
        self.max_clipboard_size_kb = self
            .max_clipboard_size_kb
            .take()
            .or_else(|| cfg.get_int("client.max-clipboard-size-kb"));
        self.www = self.www.take().or_else(|| cfg.get_bool("client.www"));
        self.mouse_scale = self
            .mouse_scale
            .take()
            .or_else(|| cfg.get_f64("client.mouse-scale"));
        self.scroll_scale = self
            .scroll_scale
            .take()
            .or_else(|| cfg.get_f64("client.scroll-scale"));
        self.bulk_throttle_mbps = self
            .bulk_throttle_mbps
            .take()
            .or_else(|| cfg.get_f64("client.bulk-throttle-mbps"));
        self.edge_map = self.edge_map.take().or_else(|| cfg.get_str_vec("client.edge-map"));
        self.edge_dwell_ms = self
            .edge_dwell_ms
            .take()
            .or_else(|| cfg.get_int("client.edge-dwell-ms"));
        self.no_auto_update = self
            .no_auto_update
            .take()
            .or_else(|| cfg.get_bool("client.no-auto-update"));
        self.no_indicator = self
            .no_indicator
            .take()
            .or_else(|| cfg.get_bool("client.no-indicator"));
    }
}

#[derive(Args)]
struct UpdateArgs {
    /// Rebuild even if up to date, bypassing the protocol gate
    ///
    /// Reinstalls unconditionally and skips the server
    /// protocol-compatibility check.
    #[arg(long)]
    force: bool,

    /// Install a specific version or commit instead of the latest
    ///
    /// For example '--to 8.3.0' or '--to 5b4c00e'. Pins auto-update so it
    /// never undoes the downgrade; a plain 'monux update' lifts the pin again.
    #[arg(long, value_name = "version|commit", conflicts_with = "rollback")]
    to: Option<String>,

    /// Return to the previously installed build
    ///
    /// Every install records the build it replaced; this is shorthand for
    /// '--to <recorded commit>'.
    #[arg(long)]
    rollback: bool,
}

/// Listens for SIGUSR1 and SIGUSR2, treating them as "switch to next client" and "switch to prev client" respectively.
/// SIGHUP dumps the server's mirrored diagnostics state to the log for troubleshooting.
/// The dump reads the mirror directly instead of going through the server event
/// loop, so it still prints when the loop itself is stalled — the exact scenario
/// the dump exists to debug.
fn handle_signals(mut signals: Signals, out: mpsc::Sender<Event>, diagnostics: Arc<rotation::DiagnosticsMirror>) {
    let mut iter = signals.into_iter();
    loop {
        match iter.next() {
            Some(signal::SIGUSR1) => {
                if let Err(e) = out.blocking_send(Event::SwitchNext) {
                    error!("Failed to submit SwitchNext event for SIGUSR1: {:?}", e);
                }
            }
            Some(signal::SIGUSR2) => {
                if let Err(e) = out.blocking_send(Event::SwitchPrev) {
                    error!("Failed to submit SwitchPrev event for SIGUSR2: {:?}", e);
                }
            }
            Some(signal::SIGHUP) => {
                diagnostics.dump();
            }
            other => {
                // None means the signal stream closed; exit instead of spinning on it.
                warn!(
                    "Unexpected signal iterator state: {:?}, exiting signal handler",
                    other
                );
                return;
            }
        }
    }
}

/// Resolves when the process receives SIGINT (ctrl-c) or SIGTERM.
async fn shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
    monux::mark_shutting_down();
}

/// Client variant of shutdown_signal: additionally resolves on SIGUSR1, SIGUSR2
/// and SIGHUP. Those switch clients or dump diagnostics on the server (see
/// handle_signals), but have no such meaning on a client — where their default
/// action kills the process outright, skipping the cleanup that releases held
/// keys on the virtual devices (they'd stay pressed until kernel teardown).
/// Dying cleanly beats dying dirty.
async fn client_shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to install SIGTERM handler");
    let mut sigusr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        .expect("Failed to install SIGUSR1 handler");
    let mut sigusr2 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())
        .expect("Failed to install SIGUSR2 handler");
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("Failed to install SIGHUP handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
        _ = sigusr1.recv() => {}
        _ = sigusr2.recv() => {}
        _ = sighup.recv() => {}
    }
    monux::mark_shutting_down();
}

/// Print-and-exit CLI commands want to die silently on SIGPIPE ('monux
/// Which rendering `monux diagnostics` was asked for. The default depends on
/// where the bundle is going: printing to a terminal wants plain text,
/// copying wants markdown, since a copied bundle is on its way to the issue
/// tracker. An explicit flag always wins.
fn diagnostics_format(args: &DiagnosticsArgs) -> monux::diagnostics::Format {
    use monux::diagnostics::Format;
    match (args.json, args.markdown, args.plain) {
        (true, _, _) => Format::Json,
        (_, true, _) => Format::Markdown,
        (_, _, true) => Format::Plain,
        // Anything headed off this machine is headed for the issue tracker.
        _ if args.copy || args.issue => Format::Markdown,
        _ => Format::Plain,
    }
}

/// config show | head', '... | less' quit early) instead of panicking on a
/// failed println!: Rust ignores SIGPIPE by default, which turns a closed
/// pipe into a write error. Restoring the default disposition makes the
/// kernel kill us, matching every other CLI. DAEMONS (server/client/tray
/// indicator) must NOT get this: they write to pipes that legitimately
/// close — wayland clipboard pipes, an orphaned indicator's inherited
/// stderr — where SIGPIPE would kill them silently (the client-daemon
/// silent-death regression).
fn cli_sigpipe_kill() {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}

fn main() -> Result<()> {
    logging::init_logging();
    let cli = Cli::parse();
    // Record the exact build in the log: invaluable when diagnosing bug reports.
    info!("monux v{} starting", VERSION);

    // Setup/update/status/servers/config/gui/system/daemon/diagnostics commands
    // don't need the devices or the async runtime. They print to stdout and return, so they
    // get the die-quietly-on-SIGPIPE disposition; the daemon paths below
    // deliberately don't (see cli_sigpipe_kill).
    match &cli.command {
        Commands::Daemon(args) => match &args.command {
            DaemonCommands::Switch(args) => {
                cli_sigpipe_kill();
                let request = format!(r#"{{"cmd":"switch","target":"{}"}}"#, args.target);
                let out = monux::control::daemon_cli(&request, "Switch requested", args.socket.as_deref())?;
                println!("{}", out);
                return Ok(());
            }
            DaemonCommands::Pause => {
                cli_sigpipe_kill();
                let out = monux::control::daemon_cli(r#"{"cmd":"pause"}"#, "Input paused", None)?;
                println!("{}", out);
                return Ok(());
            }
            DaemonCommands::Resume => {
                cli_sigpipe_kill();
                let out = monux::control::daemon_cli(r#"{"cmd":"resume"}"#, "Input resumed", None)?;
                println!("{}", out);
                return Ok(());
            }
            DaemonCommands::Restart => {
                cli_sigpipe_kill();
                let out = monux::control::daemon_cli(
                    r#"{"cmd":"restart"}"#,
                    "Restarting the daemon (the session will resume automatically)",
                    None,
                )?;
                println!("{}", out);
                return Ok(());
            }
            DaemonCommands::Exit => {
                cli_sigpipe_kill();
                let out = monux::control::daemon_cli(r#"{"cmd":"exit"}"#, "Shutting down the daemon", None)?;
                println!("{}", out);
                return Ok(());
            }
            DaemonCommands::Update => {
                cli_sigpipe_kill();
                let out = monux::control::daemon_cli(r#"{"cmd":"update_now"}"#, "Update check started", None)?;
                println!("{}", out);
                return Ok(());
            }
        },
        Commands::Setup(args) => {
            cli_sigpipe_kill();
            // Elevate only when the selected steps need root: the base set
            // (a no-flags run) persists root-owned system settings;
            // --autostart/--desktop-shortcut manage per-user files and must
            // run as the invoking user instead.
            if setup_needs_root(&args.autostart, args.desktop_shortcut) {
                maybe_elevate("to persist system settings")?;
            }
            return monux::setup::run(args.autostart, args.desktop_shortcut);
        }
        Commands::Update(args) => {
            cli_sigpipe_kill();
            let config_dir = monux::update::default_config_dir();
            // Gate on the server's protocol version when this machine acts as
            // a client, so an update can't break the connection. The version
            // recorded at the last handshake can be stale (the server upgraded
            // while this client was away), so refresh it from the servers'
            // mDNS advertisements first; the config dir may not exist yet, the
            // constraint is simply absent then.
            let constraint = if args.force {
                // --force bypasses the gate; skip the discovery delay.
                None
            } else if single_instance::live_holder("server").is_some()
                && single_instance::live_holder("client").is_none()
            {
                // This machine runs a monux server and no client: it leads
                // protocol upgrades, and the gate must not block it (its own
                // mDNS advertisement or a stale client-role record would
                // otherwise refuse the update).
                info!("This machine runs a monux server and no client: the protocol-compatibility gate does not apply");
                None
            } else {
                monux::update::refresh_protocol_constraint(config_dir.as_deref())
            };
            // --rollback is shorthand for --to <the recorded previous build>.
            let to = if args.rollback {
                match config_dir.as_deref().and_then(monux::update::previous_version) {
                    Some((version, commit)) => {
                        info!("Rolling back to the previously installed build: v{} ({})", version, commit);
                        Some(commit)
                    }
                    None => bail!("no previous version recorded — use --to <version>"),
                }
            } else {
                args.to.clone()
            };
            let status = monux::update::run(args.force, false, constraint, to.as_deref())?;
            // A plain update returns to the latest and lifts a downgrade pin
            // (auto-update skips while pinned and never unpins itself) — but
            // only once the install actually succeeded: clearing it before
            // the attempt would let a failed update lose the pin, and the
            // nightly auto-update would then undo the downgrade. The
            // --to/--rollback paths (re)write their own pin inside
            // update::run and are unaffected.
            if !args.rollback && args.to.is_none() {
                if let monux::update::UpdateStatus::Installed = status {
                    if let Some(dir) = config_dir.as_deref() {
                        if monux::update::clear_update_pin(dir) {
                            info!("unpinned; updating to latest");
                        }
                    }
                }
            }
            return Ok(());
        }
        Commands::Status(args) => {
            cli_sigpipe_kill();
            let out = monux::control::status_cli(
                args.server,
                args.client,
                args.socket.as_deref(),
                args.json,
            )?;
            println!("{}", out);
            return Ok(());
        }
        Commands::Diagnostics(args) => {
            cli_sigpipe_kill();
            if args.privacy {
                println!("{}", monux::diagnostics::PRIVACY_NOTE);
                return Ok(());
            }
            if let Some(DiagnosticsCommands::Record(rec)) = &args.command {
                let out = monux::diagnostics::record(&monux::diagnostics::RecordOptions {
                    client: rec.client,
                    keys: rec.keys.clone(),
                    trace: rec.trace,
                    out: rec.out.clone(),
                    args: rec.args.clone(),
                })?;
                println!("{}", out);
                return Ok(());
            }
            let out = monux::diagnostics::run_cli(&monux::diagnostics::CliOptions {
                server: args.server,
                client: args.client,
                socket: args.socket.clone(),
                format: diagnostics_format(args),
                redact: args.redact,
                copy: args.copy,
                lines: args.lines,
                journal_since: if args.no_journal {
                    None
                } else {
                    Some(args.since.clone())
                },
                peer: args.peer,
                issue: args.issue,
                title: args.title.clone(),
            })?;
            println!("{}", out);
            return Ok(());
        }
        Commands::Servers => {
            cli_sigpipe_kill();
            // Display-only: reads mDNS advertisements and the remembered
            // store; never connects to anything (no probes, no handshake).
            println!("{}", monux::servers::listing(&init_config_dir()?));
            return Ok(());
        }
        Commands::Config(args) => {
            cli_sigpipe_kill();
            let action = match &args.command {
                None | Some(ConfigCommands::Show) => monux::config::Action::Show,
                Some(ConfigCommands::Keys { filter }) => {
                    monux::config::Action::Keys(filter.clone())
                }
                Some(ConfigCommands::Set { key, values }) => monux::config::Action::Set {
                    key: key.clone(),
                    values: values.clone(),
                },
                Some(ConfigCommands::Unset { key }) => monux::config::Action::Unset {
                    key: key.clone(),
                },
                Some(ConfigCommands::Edit) => monux::config::Action::Edit,
                Some(ConfigCommands::Validate) => monux::config::Action::Validate,
                Some(ConfigCommands::History { key }) => monux::config::Action::History {
                    key: key.clone(),
                },
                Some(ConfigCommands::Revert { key, to }) => monux::config::Action::Revert {
                    key: key.clone(),
                    to: to.clone(),
                },
            };
            // False only for a failed 'validate' or an aborted 'edit'.
            if !monux::config::cli(&init_config_dir()?, &action)? {
                std::process::exit(1);
            }
            return Ok(());
        }
        Commands::Gui(args) => match &args.command {
            GuiCommands::Tray(args) => {
                cli_sigpipe_kill();
                let hide = matches!(args.action, TrayAction::Hide);
                let out = monux::control::tray_cli(hide, args.socket.as_deref())?;
                println!("{}", out);
                return Ok(());
            }
            GuiCommands::Indicator => {
                // Headless sessions fail here, before touching the lock: no
                // point holding (or taking over) the single-instance lock for
                // an indicator that can't even reach a session bus.
                if !monux::indicator_spawn::has_desktop_session() {
                    bail!(
                        "no D-Bus session bus (DBUS_SESSION_BUS_ADDRESS unset and no /run/user/{}/bus): the indicator needs a desktop session running a StatusNotifierItem host (waybar, KDE Plasma, ...)",
                        unsafe { libc::geteuid() }
                    );
                }
                // One icon at all times: take over from any already-running
                // indicator (auto-spawned or manual).
                let _indicator_lock = single_instance::acquire("indicator")?;
                return monux::indicator::run();
            }
        },
        Commands::System(args) => match &args.command {
            SystemCommands::Uninstall(args) => {
                cli_sigpipe_kill();
                return monux::uninstall::run(args.yes);
            }
        },
        _ => {}
    }

    let config_dir = init_config_dir()?;

    let rt = Arc::new(
        runtime::Builder::new_multi_thread()
            // Two workers, not one-per-CPU: the interactive certificate
            // approval prompt blocks a worker on stdin, and with a single
            // worker that would freeze all IO/timers until it times out.
            // Heavier blocking work already runs off the executor (wayland
            // reads via spawn_blocking, clipboard writes on dedicated
            // threads), so two workers suffice.
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime"),
    );

    match cli.command {
        Commands::Setup(_)
        | Commands::Update(_)
        | Commands::Status(_)
        | Commands::Servers
        | Commands::Config(_)
        | Commands::Gui(_)
        | Commands::System(_)
        | Commands::Diagnostics(_)
        | Commands::Daemon(_) => {
            unreachable!("setup/update/status/servers/config/gui/system/daemon/diagnostics commands are handled before runtime initialization")
        }
        Commands::Server(mut args) => {
            // The config file fills whatever the command line left unset.
            args.resolve(&monux::config::load_for_daemon(&config_dir));
            let listen = args.listen.unwrap_or(monux::config::DEFAULT_LISTEN);
            let port = args.port.unwrap_or(monux::config::DEFAULT_PORT);
            if port == 0 {
                bail!("--port 0 (ephemeral port) is not supported: the mDNS advertisement must match the actual listen port");
            }
            let auto_update = !args.no_auto_update.unwrap_or(false);
            let auto_indicator = !args.no_indicator.unwrap_or(false);
            let www = args.www.unwrap_or(false);
            let server_lock = single_instance::acquire("server")?;
            settle_after_takeover(&server_lock);
            // A machine running only a server has no use for the client-side
            // update-gate file: its content can only be stale history (a
            // client machine's handshakes re-record it), and a stale entry
            // vetoes manual updates while the daemon is down (mDNS then finds
            // no live server to refresh it). Clear it unless a client also
            // runs here.
            if single_instance::live_holder("client").is_none() {
                monux::update::clear_protocol_constraint(&config_dir);
            }
            if auto_update {
                // The server leads protocol upgrades: no compatibility gate.
                rt.spawn(monux::autoupdate::run(None));
            }
            let verifier = approval::MonuxCertVerification::new(
                "server",
                args.fingerprint.take().unwrap_or(vec![]),
                &config_dir,
                // No interactive approval prompts when facing the public internet:
                // unknown peers must be pre-approved via --fingerprints instead.
                !www,
            )?;
            info!(
                "Our certificate fingerprint: {} (pre-approve this server on clients with '--fingerprints {}')",
                verifier.our_fingerprint(),
                verifier.our_fingerprint()
            );
            let mode = if www {
                NetworkMode::Www
            } else {
                NetworkMode::Local
            };
            let max_clipboard_size_bytes = args
                .max_clipboard_size_kb
                .unwrap_or(monux::config::DEFAULT_MAX_CLIPBOARD_SIZE_KB)
                .checked_mul(1024)
                .context("--max-clipboard-size-kb is too large")?;
            let motion_mode = match args.motion_hz {
                None => {
                    info!(
                        "Coalescing pointer motion adaptively: {} updates/s, raised to {} on a sustained close link (pin with --motion-hz; 0 disables)",
                        monux::rotation::ADAPTIVE_MOTION_NORMAL_HZ,
                        monux::rotation::ADAPTIVE_MOTION_PROXIMITY_HZ,
                    );
                    monux::rotation::MotionMode::Adaptive
                }
                Some(0) => monux::rotation::MotionMode::Pinned(None),
                Some(hz) => {
                    info!("Coalescing pointer motion to {} updates/s (pinned)", hz);
                    monux::rotation::MotionMode::Pinned(Some(Duration::from_secs_f64(
                        1.0 / hz as f64,
                    )))
                }
            };
            let throttle_mode = match args.bulk_throttle_mbps {
                None => {
                    info!(
                        "Pacing bulk transfers adaptively: {} Mbps, raised to {} on a sustained close link (pin with --bulk-throttle-mbps; 0 disables)",
                        monux::rotation::ADAPTIVE_THROTTLE_NORMAL_MBPS,
                        monux::rotation::ADAPTIVE_THROTTLE_PROXIMITY_MBPS,
                    );
                    monux::rotation::ThrottleMode::Adaptive
                }
                Some(mbps) if mbps <= 0.0 => monux::rotation::ThrottleMode::Pinned(None),
                Some(mbps) => {
                    info!("Pacing bulk transfers to {} Mbps (pinned)", mbps);
                    monux::rotation::ThrottleMode::Pinned(Some(mbps))
                }
            };
            // Screen-edge switching is opt-in: no --edge-map, no edge manager.
            let edge_map = match &args.edge_map {
                Some(specs) => Some(monux::edge::parse_edge_map(specs)?),
                None => None,
            };
            // An empty --pause-shortcut disables pause/resume.
            let pause_shortcut = args
                .pause_shortcut
                .as_deref()
                .unwrap_or(monux::config::DEFAULT_PAUSE_SHORTCUT);
            let pause_shortcut = if pause_shortcut.trim().is_empty() {
                None
            } else {
                Some(pause_shortcut)
            };
            rt.block_on(async {
                server(
                    config_dir,
                    SocketAddr::new(listen, port),
                    args.shortcut
                        .as_deref()
                        .unwrap_or(monux::config::DEFAULT_SHORTCUT),
                    Some(
                        args.shortcut_prev
                            .as_deref()
                            .unwrap_or(monux::config::DEFAULT_SHORTCUT_PREV),
                    ),
                    args.shortcut_goto.take().unwrap_or(vec![]),
                    pause_shortcut,
                    args.device.take().unwrap_or(vec![]),
                    args.exit_secs,
                    verifier,
                    max_clipboard_size_bytes,
                    mode,
                    motion_mode,
                    throttle_mode,
                    edge_map,
                    Duration::from_millis(
                        args.edge_dwell_ms
                            .unwrap_or(monux::config::DEFAULT_EDGE_DWELL_MS),
                    ),
                    auto_update,
                    auto_indicator,
                )
                .await
            })?;
        }
        Commands::Client(mut args) => {
            // The config file fills whatever the command line left unset.
            args.resolve(&monux::config::load_for_daemon(&config_dir));
            let auto_update = !args.no_auto_update.unwrap_or(false);
            let auto_indicator = !args.no_indicator.unwrap_or(false);
            let www = args.www.unwrap_or(false);
            let mouse_scale = args.mouse_scale.unwrap_or(monux::config::DEFAULT_INPUT_SCALE);
            let scroll_scale = args
                .scroll_scale
                .unwrap_or(monux::config::DEFAULT_INPUT_SCALE);
            let client_lock = single_instance::acquire("client")?;
            settle_after_takeover(&client_lock);
            if auto_update {
                rt.spawn(monux::autoupdate::run(Some(config_dir.clone())));
            }
            // When no host is given, the client cycles its server candidates:
            // the remembered servers (most recent first — a one-time
            // 'monux client <ip>' is remembered, see known_servers.rs) and
            // one mDNS discovery attempt, over and over.
            let port = args.port.unwrap_or(monux::config::DEFAULT_PORT);
            let initial_addr: Option<SocketAddr> = match &args.host {
                Some(host) => Some(monux::known_servers::resolve_host(
                    host,
                    port,
                    &monux::known_servers::load(&config_dir),
                    |host| {
                        format!("{}:{}", host, port)
                            .to_socket_addrs()
                            .map(|mut addrs| addrs.next())
                            .map_err(anyhow::Error::from)
                    },
                )?),
                None => {
                    if args.port.is_some() {
                        warn!("a configured port (--port or config file) is ignored when the server is auto-discovered via mDNS or tried from the remembered servers");
                    }
                    None
                }
            };
            let verifier = approval::MonuxCertVerification::new(
                "client",
                args.fingerprint.take().unwrap_or(vec![]),
                &config_dir,
                // The client connects outbound to a server it chose, so interactive
                // approval prompts stay enabled even in --www mode (unlike the server).
                true,
            )?;
            info!(
                "Our certificate fingerprint: {} (pre-approve this client on the server with '--fingerprints {}')",
                verifier.our_fingerprint(),
                verifier.our_fingerprint()
            );
            let mode = if www {
                NetworkMode::Www
            } else {
                NetworkMode::Local
            };
            let max_clipboard_size_bytes = args
                .max_clipboard_size_kb
                .unwrap_or(monux::config::DEFAULT_MAX_CLIPBOARD_SIZE_KB)
                .checked_mul(1024)
                .context("--max-clipboard-size-kb is too large")?;
            if mouse_scale != 1.0 || scroll_scale != 1.0 {
                info!(
                    "Scaling injected input: pointer motion x{}, scroll x{}",
                    mouse_scale, scroll_scale
                );
            }
            let throttle_mode = match args.bulk_throttle_mbps {
                None => {
                    info!(
                        "Pacing bulk transfers adaptively: {} Mbps, raised to {} on a sustained close link (pin with --bulk-throttle-mbps; 0 disables)",
                        monux::rotation::ADAPTIVE_THROTTLE_NORMAL_MBPS,
                        monux::rotation::ADAPTIVE_THROTTLE_PROXIMITY_MBPS,
                    );
                    monux::rotation::ThrottleMode::Adaptive
                }
                Some(mbps) if mbps <= 0.0 => monux::rotation::ThrottleMode::Pinned(None),
                Some(mbps) => {
                    info!("Pacing bulk transfers to {} Mbps (pinned)", mbps);
                    monux::rotation::ThrottleMode::Pinned(Some(mbps))
                }
            };
            // Screen-edge switching back to the server is opt-in: no
            // --edge-map, no edge detection. Client targets are validated at
            // startup ('auto' only), not at fire time.
            let edge_map = match &args.edge_map {
                Some(specs) => Some(monux::edge::parse_client_edge_map(specs)?),
                None => None,
            };
            rt.block_on(async {
                client(
                    config_dir,
                    initial_addr,
                    verifier,
                    max_clipboard_size_bytes,
                    mode,
                    mouse_scale,
                    scroll_scale,
                    throttle_mode,
                    edge_map,
                    Duration::from_millis(
                        args.edge_dwell_ms
                            .unwrap_or(monux::config::DEFAULT_EDGE_DWELL_MS),
                    ),
                    auto_update,
                    auto_indicator,
                )
                .await
            })?;
        }
    }
    // A background auto-update may have scheduled a restart (autoupdate.rs):
    // the graceful shutdown above has completed, so replace this process with
    // the freshly installed binary.
    if monux::autoupdate::restart_scheduled() {
        reexec_after_update()?;
    }
    Ok(())
}

/// Replaces this process image with the freshly installed monux binary after
/// a background auto-update. execve preserves our pid, args and environment
/// and closes our (CLOEXEC) fds, releasing the single-instance lock, keyboard
/// grabs and virtual devices for the new image in one atomic step.
/// MONUX_RESTARTED tells the new image to let udev settle before creating its
/// virtual devices (the same teardown/create race as a take-over restart).
fn reexec_after_update() -> Result<()> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe()
        .context("Failed to find our own executable for the post-update restart")?;
    // The update replaced the binary on disk while we were running, so Linux
    // reports our exe as "<path> (deleted)"; the plain path is the new binary.
    let exe = exe.to_string_lossy().trim_end_matches(" (deleted)").to_string();
    info!("Restarting into the updated monux ({})...", exe);
    let err = std::process::Command::new(&exe)
        .args(std::env::args_os().skip(1))
        .env("MONUX_RESTARTED", "1")
        .exec();
    Err(anyhow!(
        "Failed to restart into the updated monux ({}): {}",
        exe,
        err
    ))
}

/// After taking over from a previous instance (or re-exec'ing ourselves after
/// an auto-update), wait for udev to finish processing the previous instance's
/// virtual-device teardown before we create ours. Without this, rapid restarts
/// race: the old devices' evdev remove events can reach the compositor after
/// the new devices' add events for the same devpath, making the compositor
/// drop or never register our brand-new virtual keyboard (seen in the wild as
/// all keyboard input going dead after a few restarts; 'hyprctl reload' makes
/// it reappear).
fn settle_after_takeover(lock: &single_instance::InstanceLock) {
    // A re-exec after an auto-update (MONUX_RESTARTED) releases the lock
    // atomically, so took_over is false — but the old image's virtual devices
    // were torn down at the same instant, so the same udev race applies.
    if !lock.took_over && std::env::var_os("MONUX_RESTARTED").is_none() {
        return;
    }
    // udevadm settle waits for udev's event queue to drain, so the old remove
    // events are emitted before our new add events (monitor order is preserved
    // for libinput/the compositor). Fall back to a plain sleep if unavailable.
    // Note: --timeout is in SECONDS, not milliseconds.
    let settled = std::process::Command::new("udevadm")
        .args(["settle", "--timeout=2"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if settled {
        info!("Settled before creating virtual devices (udev queue drained)");
    } else {
        info!("Settling briefly before creating virtual devices");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Whether a 'monux setup' invocation must elevate: only the base set (a run
/// with no per-user flags) persists root-owned system settings. --autostart
/// and --desktop-shortcut manage files in the invoking user's home and must
/// run as that user.
fn setup_needs_root(autostart: &Option<monux::setup::Autostart>, desktop_shortcut: bool) -> bool {
    autostart.is_none() && !desktop_shortcut
}

/// 'monux setup' persists system settings and needs root. Rather than making
/// the user type 'sudo monux setup' (which also trips over sudo's restricted
/// PATH hiding ~/.local/bin), re-exec with sudo -E, prompting for the password.
/// Opt out with MONUX_NO_ELEVATE=1 to get the manual invocation instead.
fn maybe_elevate(reason: &str) -> Result<()> {
    if unsafe { libc::geteuid() } == 0 || std::env::var_os("MONUX_NO_ELEVATE").is_some() {
        return Ok(());
    }
    let exe = std::env::current_exe()
        .context("Failed to find our own executable for sudo re-exec")?;
    info!("Re-executing with sudo {} (MONUX_NO_ELEVATE=1 to opt out)...", reason);
    let status = std::process::Command::new("sudo")
        .arg("-E")
        .arg(&exe)
        .args(std::env::args().skip(1))
        .status()
        .context("Failed to re-exec with sudo")?;
    std::process::exit(status.code().unwrap_or(1));
}

fn init_config_dir() -> Result<PathBuf> {
    let mut homedir = home::home_dir().context("No home dir found: Unable to store certs")?;
    homedir.push(".config");
    let new_dir = homedir.join("monux");
    // One-time migration from the pre-rename config dir, preserving the
    // keypair (our identity) and known_certs (peer approvals).
    let old_dir = homedir.join("nikau");
    if !new_dir.exists() && old_dir.exists() {
        fs::rename(&old_dir, &new_dir).with_context(|| {
            format!(
                "Failed to migrate config directory from {} to {}",
                old_dir.display(),
                new_dir.display()
            )
        })?;
        info!(
            "Migrated config directory from {} to {}",
            old_dir.display(),
            new_dir.display()
        );
    }
    fs::create_dir_all(&new_dir)
        .with_context(|| format!("Failed to create config directory: {}", new_dir.display()))?;
    Ok(new_dir)
}

async fn server(
    config_dir: PathBuf,
    listen_addr: SocketAddr,
    keys_next: &str,
    keys_prev: Option<&str>,
    keys_goto: Vec<String>,
    keys_pause: Option<&str>,
    device_filters: Vec<Regex>,
    exit_secs: Option<u32>,
    verifier: Arc<approval::MonuxCertVerification<'static>>,
    max_clipboard_size_bytes: u64,
    mode: NetworkMode,
    motion_mode: monux::rotation::MotionMode,
    throttle_mode: monux::rotation::ThrottleMode,
    edge_map: Option<monux::edge::EdgeMap>,
    edge_dwell: Duration,
    auto_update: bool,
    auto_indicator: bool,
) -> Result<()> {
    // Try to set up virtual devices up-front - exit early if we can't access uinput
    let mut output_handler = output::uinput::VirtualUInputDevices::new()
        .context("Failed to create virtual devices for output, possible solutions:
- Add your user to the 'input' group and log back in: 'sudo usermod -aG input $USER'
- Enable uinput and/or evdev in the kernel, check for /dev/uinput and /dev/input/
- As a fallback, run as root with 'sudo -E monux server ...' (-E keeps clipboard support)")?;
    let virtual_nodes = output_handler.device_nodes();
    info!(
        "Virtual device nodes: {}",
        virtual_nodes
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let (event_tx, event_rx): (mpsc::Sender<Event>, mpsc::Receiver<Event>) = mpsc::channel(256);

    // Mirrored diagnostics state: the rotation loop refreshes it as it goes,
    // and the SIGHUP handler dumps it without involving the loop. The same
    // mirror carries the structured snapshot for the control socket.
    let diagnostics = Arc::new(rotation::DiagnosticsMirror::new(listen_addr));
    let event_tx2 = event_tx.clone();
    let diagnostics2 = diagnostics.clone();
    let signals = Signals::new([signal::SIGUSR1, signal::SIGUSR2, signal::SIGHUP])?;
    std::thread::spawn(move || handle_signals(signals, event_tx2, diagnostics2));

    // Local control IPC (status/switch/pause/update/restart/exit). Optional:
    // an unbindable path (e.g. another live daemon owns it) just drops the
    // feature, not the server. The tray-indicator supervisor is created here
    // so the socket can hide/show it, but only launched once the daemon is
    // up (see below); the guard SIGTERMs and reaps the child on every exit
    // path out of this function.
    let indicator = monux::indicator_spawn::Supervisor::new(!auto_indicator);
    // Created here rather than beside the rotation loop below: the control
    // socket needs a sender too (peer diagnostics reach the clients through
    // the rotation loop), and the socket is bound first.
    let (rotation_tx, rotation_rx) = mpsc::channel::<rotation::RotationEvent>(256);
    match monux::control::Listener::bind(monux::control::Role::Server) {
        Ok(listener) => {
            let handler = monux::control::Handler::Server(monux::control::ServerHandler {
                state: diagnostics.clone(),
                event_tx: event_tx.clone(),
                rotation_tx: rotation_tx.clone(),
                auto_update,
                indicator: indicator.handle(),
            });
            task::spawn(listener.run(handler));
        }
        Err(e) => warn!("Control socket unavailable: {:?}", e),
    }

    let (grab_tx, _grab_rx) = watchchan::channel(monux::device::GrabState {
        client_active: false,
        paused: false,
    });
    let grab_tx2 = grab_tx.clone();

    // Screen-edge switching (opt-in via --edge-map): the edge manager owns the
    // cursorpos poller and dwell timers, resolves targets against the live
    // client list that the rotation loop publishes through this watch channel,
    // and fires switches as Event::SwitchTo — the same entry point as goto
    // chords, so debounce/pause/no-op cleanup all apply. The rotation loop
    // also keeps a copy of the map itself, to tell each mapped client which
    // edge it sits beyond (ServerEvent::EdgeInfo; see rotation.rs add_client).
    let (edge_client_tx, edge_map) = match edge_map {
        Some(map) => {
            let (tx, rx) = watchchan::channel(Vec::new());
            task::spawn(monux::edge::run(map.clone(), edge_dwell, event_tx.clone(), rx));
            (Some(tx), Some(map))
        }
        None => (None, None),
    };

    let key_combos = shortcut::parse_key_combos(keys_next, keys_prev, keys_goto, keys_pause)?;
    if let Some(kp) = keys_pause {
        info!("Pause/resume shortcut: {} (ungrabs ALL devices; press again to resume)", kp);
    }
    let input_handler = input::InputHandler::new(&key_combos, event_tx)?;

    let mut watch_handle = task::spawn(async move {
        let device_handles =
            handles::DeviceHandles::new(input_handler, grab_tx, key_combos.all_keys);
        watch::watch_loop(device_handles, device_filters, virtual_nodes)
            .await
            .context(
                "Failed to listen to any input devices, possible solutions:
- Are any input devices (keyboard, mouse, etc) plugged into the machine?
- If any '--device' filters are specified, they might be filtering out all current devices",
            )
    });

    let rotation_tx2 = rotation_tx.clone();
    let mut server_events_handle = task::spawn(async move {
        server::run_server_events_loop(
            config_dir,
            event_rx,
            grab_tx2,
            output_handler,
            // Max compressed clipboard size over the wire
            max_clipboard_size_bytes,
            // Max uncompressed clipboard size, just in case
            10 * max_clipboard_size_bytes,
            rotation_tx,
            rotation_rx,
            motion_mode,
            throttle_mode,
            mode,
            diagnostics,
            edge_client_tx,
            edge_map,
        )
        .await
    });
    // Shared handle to the connections loop's QUIC endpoint, published once
    // the bind succeeds, so the shutdown path can close it gracefully (see
    // close_loops).
    let server_endpoint = server::SharedEndpoint::default();
    let server_endpoint2 = server_endpoint.clone();
    // Advertised in the mDNS TXT record ('monux servers' displays it);
    // read before the verifier moves into the connections loop.
    let our_fingerprint = verifier.our_fingerprint();
    let mut server_connections_handle = task::spawn(async move {
        server::run_server_connections_loop(
            &listen_addr,
            verifier,
            max_clipboard_size_bytes,
            rotation_tx2,
            mode,
            server_endpoint2,
        )
        .await
    });

    // Advertise the server on the local network so that clients can discover it.
    let _mdns_registration = match discovery::DiscoveryRegistration::register(listen_addr, &our_fingerprint) {
        Ok(r) => Some(r),
        Err(e) => {
            warn!("Failed to register mDNS service for LAN discovery: {}", e);
            None
        }
    };

    info!("Listening for clients: {}", listen_addr);
    if let Ok(ips) = discovery::advertise_ips(listen_addr.ip()) {
        if !ips.is_empty() {
            info!(
                "Local IP address(es) for clients: {}; connect with 'monux client {}' or omit the address for mDNS auto-discovery",
                ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", "),
                ips[0]
            );
        }
    }
    // The daemon is up (listening, rotation running): start the tray
    // indicator alongside it.
    indicator.launch();
    if let Some(exit_secs) = exit_secs {
        info!("Exiting in {} seconds...", exit_secs);
        tokio::select! {
            watch_exit = &mut watch_handle => {
                watch_exit?.context("Failed to watch input events, exiting early")?
            },
            server_events_exit = &mut server_events_handle => {
                server_events_exit?.context("Server events loop failed, exiting early")?
            },
            server_connections_exit = &mut server_connections_handle => {
                server_connections_exit?.context("Server connections loop failed, exiting early")?
            },
            _timeout = time::sleep(Duration::from_secs(exit_secs as u64)) => {
                info!("Exiting automatically as requested (--exit-secs={})", exit_secs);
            },
            _signal = shutdown_signal() => {
                close_loops(watch_handle, server_events_handle, server_connections_handle, server_endpoint).await;
                // Dropping _mdns_registration here sends the mDNS goodbye.
                // The active-client state file is deliberately left in place:
                // a restart (e.g. after 'monux update') resumes the session
                // automatically when the client reconnects (bounded by
                // ACTIVE_CLIENT_MAX_AGE).
                info!("Shutting down...");
                return Ok(());
            },
        };
    } else {
        tokio::select! {
            watch_exit = &mut watch_handle => {
                watch_exit?.context("Failed to watch input events, exiting")?
            },
            server_events_exit = &mut server_events_handle => {
                server_events_exit?.context("Server events loop failed, exiting early")?
            },
            server_connections_exit = &mut server_connections_handle => {
                server_connections_exit?.context("Server connections loop failed, exiting early")?
            },
            _signal = shutdown_signal() => {
                close_loops(watch_handle, server_events_handle, server_connections_handle, server_endpoint).await;
                // Dropping _mdns_registration here sends the mDNS goodbye.
                // The active-client state file is deliberately left in place:
                // a restart (e.g. after 'monux update') resumes the session
                // automatically when the client reconnects (bounded by
                // ACTIVE_CLIENT_MAX_AGE).
                info!("Shutting down...");
                return Ok(());
            },
        }
    }
    Ok(())
}

/// How long the shutdown path lets the QUIC endpoint drain its close frames
/// to clients before tearing down anyway (see close_loops).
const ENDPOINT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Closes the QUIC endpoint gracefully, then aborts the spawned loop tasks
/// and waits for them to drop their state. The graceful close comes FIRST,
/// while the tasks are still alive and the runtime is pumping I/O: quinn
/// sends no close frames when the endpoint is merely dropped, so without it
/// every client waited out its 25s idle timeout on each restart/takeover.
/// close() stops accepting and sends CONNECTION_CLOSE (code 0, normal) to
/// all current connections; wait_idle() lets those frames drain, bounded so
/// an unreachable client's drain can't hang shutdown.
///
/// All endpoint clones are gone once this returns (ours taken from the slot
/// and dropped here, the connections loop's with its task below): the
/// single-instance lock is released as soon as server() returns, and a
/// socket that outlives the lock makes the next instance's bind fail with
/// EADDRINUSE (seen in the wild when a manual start took over from an
/// auto-update restart).
async fn close_loops(
    watch_handle: task::JoinHandle<Result<()>>,
    server_events_handle: task::JoinHandle<Result<()>>,
    server_connections_handle: task::JoinHandle<Result<()>>,
    server_endpoint: server::SharedEndpoint,
) {
    // None when shutdown raced the bind retry loop: nothing to close then.
    let endpoint = server_endpoint
        .lock()
        .expect("server endpoint slot lock poisoned")
        .take();
    if let Some(endpoint) = endpoint {
        endpoint.close(quinn::VarInt::from_u32(0), b"server shutting down");
        if time::timeout(ENDPOINT_DRAIN_TIMEOUT, endpoint.wait_idle())
            .await
            .is_err()
        {
            debug!(
                "QUIC endpoint still draining after {:?}; finishing shutdown anyway",
                ENDPOINT_DRAIN_TIMEOUT
            );
        }
    }
    watch_handle.abort();
    server_events_handle.abort();
    server_connections_handle.abort();
    let _ = watch_handle.await;
    let _ = server_events_handle.await;
    let _ = server_connections_handle.await;
}

/// A failed connection that had survived beyond this was a healthy session: its
/// loss is a fresh network event, not a persistent failure — it neither counts
/// toward candidate cycling nor keeps the reconnect backoff elevated.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);

/// Cap for the reconnect backoff: the first retry after a failure is immediate,
/// then the delay doubles (1s, 2s, ...) up to this.
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

/// One candidate in the reconnect cycle of a discovery-mode client (no
/// --host).
enum Candidate {
    /// A remembered server address (known_servers.rs), most recent first.
    Remembered(SocketAddr),
    /// One mDNS discovery attempt.
    Discover,
}

/// Builds one pass of the reconnect candidate cycle: the remembered servers,
/// most recent first, then a single mDNS discovery attempt. The cycle is
/// rebuilt from a fresh store read every pass, so a server just recorded by
/// a successful connect leads the next one.
fn candidate_cycle(
    remembered: &[monux::known_servers::RememberedServer],
) -> std::collections::VecDeque<Candidate> {
    remembered
        .iter()
        .map(|server| Candidate::Remembered(server.addr))
        .chain(std::iter::once(Candidate::Discover))
        .collect()
}

/// Draws the next reconnect candidate for a discovery-mode client, rebuilding
/// the cycle from a fresh read of the remembered store when the current pass
/// is exhausted. Returns None when the pass's mDNS attempt found no server;
/// the caller then retries the current address.
async fn draw_candidate(
    cycle: &mut std::collections::VecDeque<Candidate>,
    config_dir: &std::path::Path,
    verifier: &approval::MonuxCertVerification<'static>,
) -> Option<SocketAddr> {
    if cycle.is_empty() {
        *cycle = candidate_cycle(&monux::known_servers::load(config_dir));
    }
    match cycle
        .pop_front()
        .expect("a candidate pass always holds at least the mDNS attempt")
    {
        Candidate::Remembered(addr) => Some(addr),
        Candidate::Discover => {
            info!("Discovering the server via mDNS...");
            match discovery::discover_server(None, &monux::known_servers::load(config_dir)).await {
                Ok((addr, name)) => {
                    verifier.set_discovered_server_name(name);
                    Some(addr)
                }
                Err(e) => {
                    warn!("mDNS discovery found no server: {:?}", e);
                    None
                }
            }
        }
    }
}

async fn client(
    config_dir: PathBuf,
    initial_addr: Option<SocketAddr>,
    verifier: Arc<approval::MonuxCertVerification<'static>>,
    max_clipboard_size_bytes: u64,
    mode: NetworkMode,
    mouse_scale: f64,
    scroll_scale: f64,
    throttle_mode: monux::rotation::ThrottleMode,
    edge_map: Option<monux::edge::EdgeMap>,
    edge_dwell: Duration,
    auto_update: bool,
    auto_indicator: bool,
) -> Result<()> {
    // Try to set up virtual devices up-front - exit early if we can't access uinput
    let mut output_handler = output::uinput::VirtualUInputDevices::new()
        .context("Failed to create virtual devices for output, possible solutions:
- Add your user to the 'input' group and log back in: 'sudo usermod -aG input $USER'
- Enable uinput and/or evdev in the kernel, check for /dev/uinput and /dev/input/
- As a fallback, run as root with 'sudo -E monux client ...' (-E keeps clipboard support)")?;
    let max_uncompressed_size_bytes = 10 * max_clipboard_size_bytes;
    let mut local_clipboard = clipboard::client::LocalClipboard::new(
        config_dir.clone(),
        max_uncompressed_size_bytes,
    ).await;

    // An explicit --host keeps retrying its own address; without one
    // (discovery mode) the reconnect loop cycles: the remembered servers
    // (most recent first), one mDNS attempt, then a fresh pass. The first
    // draw is the startup connection attempt; when nothing is remembered it
    // IS the mDNS discovery — fatal when it finds nothing, as before.
    let discovery_mode = initial_addr.is_none();
    let mut cycle: std::collections::VecDeque<Candidate> = std::collections::VecDeque::new();
    let mut connect_addr = match initial_addr {
        Some(addr) => addr,
        None => match draw_candidate(&mut cycle, &config_dir, &verifier).await {
            Some(addr) => addr,
            None => bail!(
                "No server found: nothing is remembered yet and mDNS discovery found no server on this network. Connect once with 'monux client <ip>' (remembered thereafter)"
            ),
        },
    };
    let mut consecutive_failures = 0u32;
    // Delay before the next reconnect attempt: the first retry after a failure
    // is immediate, then the delay doubles per failure (1s, 2s, ...) up to
    // MAX_RECONNECT_BACKOFF. A lost healthy session resets it to immediate.
    let mut reconnect_backoff = Duration::ZERO;
    // Live state for the control socket: the reconnect loop drives
    // (dis)connected, the Switch handler in client.rs drives `active`.
    let control_state = Arc::new(monux::control::ClientStateMirror::new(connect_addr));
    // Local control IPC (status/update/restart/exit only — rotation and pause
    // are server concepts). Optional, as on the server. The tray-indicator
    // supervisor is created here so the socket can hide/show it, but only
    // launched once the socket is bound; the guard SIGTERMs and reaps the
    // child on every exit path out of this function.
    let indicator = monux::indicator_spawn::Supervisor::new(!auto_indicator);
    match monux::control::Listener::bind(monux::control::Role::Client) {
        Ok(listener) => {
            let handler = monux::control::Handler::Client(monux::control::ClientHandler {
                state: control_state.clone(),
                auto_update,
                indicator: indicator.handle(),
            });
            task::spawn(listener.run(handler));
        }
        Err(e) => warn!("Control socket unavailable: {:?}", e),
    }
    // The daemon is up (control socket bound): start the tray indicator
    // alongside it; it polls until the socket serves.
    indicator.launch();
    // Keep one set of signal handlers registered across reconnect attempts.
    let shutdown = client_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        info!("Connecting to server: {}", connect_addr);
        control_state.set_server(connect_addr);
        let connected_at = Instant::now();
        tokio::select! {
            run_result = client::run(
                &connect_addr,
                verifier.clone(),
                max_clipboard_size_bytes,
                &mut local_clipboard,
                &mut output_handler,
                mode,
                &config_dir,
                mouse_scale,
                scroll_scale,
                control_state.clone(),
                throttle_mode,
                edge_map.clone(),
                edge_dwell,
            ) => {
                // client::run only returns on failure (its loop never exits otherwise).
                if let Err(e) = run_result {
                    error!("Client error: {:?}", e);
                }
                control_state.set_disconnected();
                // Clear any clipboard status that may have been accumulated while active
                if let Some(lc) = &mut local_clipboard {
                    if let Err(e) = lc.clear_remote_clipboard() {
                        warn!("Failed to clear remote clipboard: {}", e);
                    }
                }
                // Release any keys still held on the virtual devices so they don't
                // stay stuck while we're disconnected.
                if let Err(e) = output_handler.release_all().await {
                    warn!("Failed to release held keys after connection loss: {:?}", e);
                }
                if connected_at.elapsed() > HEALTHY_SESSION {
                    // The lost connection was a healthy session: start over with
                    // a clean failure count and an immediate retry of the same
                    // address.
                    consecutive_failures = 0;
                    reconnect_backoff = Duration::ZERO;
                } else {
                    consecutive_failures += 1;
                    if discovery_mode {
                        // A fast failure means this candidate is probably
                        // stale: advance to the next one (the remembered
                        // servers, most recent first, then one mDNS attempt,
                        // then a fresh pass — see draw_candidate). A failed
                        // mDNS attempt keeps the current address.
                        if let Some(next) = draw_candidate(&mut cycle, &config_dir, &verifier).await
                        {
                            if next != connect_addr {
                                info!(
                                    "Connection failure #{}: trying the next server candidate: {} (was {})",
                                    consecutive_failures, next, connect_addr
                                );
                            }
                            connect_addr = next;
                        }
                    }
                }
                // Back off before retrying (immediate on the first failure);
                // the next delay doubles, capped at MAX_RECONNECT_BACKOFF.
                tokio::select! {
                    _ = time::sleep(reconnect_backoff) => {}
                    _ = &mut shutdown => {
                        if let Some(lc) = &mut local_clipboard {
                            if let Err(e) = lc.clear_remote_clipboard() {
                                warn!("Failed to clear remote clipboard: {}", e);
                            }
                        }
                        if let Err(e) = output_handler.release_all().await {
                            warn!("Failed to release held keys after connection loss: {:?}", e);
                        }
                        info!("Shutting down...");
                        return Ok(());
                    }
                }
                reconnect_backoff = if reconnect_backoff.is_zero() {
                    Duration::from_secs(1)
                } else {
                    (reconnect_backoff * 2).min(MAX_RECONNECT_BACKOFF)
                };
            },
            _ = &mut shutdown => {
                // Same cleanup as the connection-loss path, then exit.
                if let Some(lc) = &mut local_clipboard {
                    if let Err(e) = lc.clear_remote_clipboard() {
                        warn!("Failed to clear remote clipboard: {}", e);
                    }
                }
                if let Err(e) = output_handler.release_all().await {
                    warn!("Failed to release held keys after connection loss: {:?}", e);
                }
                info!("Shutting down...");
                return Ok(());
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::path::Path;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn short_help_summaries_stay_one_line() {
        // The wall-of-text guard. clap prints only a doc comment's first
        // paragraph for '-h' and the whole thing for '--help', so a flag whose
        // comment opens straight into prose — no short first line, no blank
        // line after it — makes '-h' a page of paragraphs instead of a table.
        // A summary that fits here still fits beside the flag name on one row.
        const MAX: usize = 80;

        fn check(cmd: &clap::Command, path: &str) {
            for arg in cmd.get_arguments() {
                let Some(help) = arg.get_help() else { continue };
                let help = help.to_string();
                assert!(
                    help.len() <= MAX,
                    "'{path}' flag --{}: the short help is {} chars (max {MAX}). Open the doc \
                     comment with a one-line summary, then a blank line, then the detail.",
                    arg.get_long().unwrap_or_else(|| arg.get_id().as_str()),
                    help.len(),
                );
            }
            for sub in cmd.get_subcommands() {
                // 'help' is clap's own, and its wording is not ours to shorten.
                if sub.get_name() == "help" {
                    continue;
                }
                let path = format!("{path} {}", sub.get_name());
                if let Some(about) = sub.get_about() {
                    let about = about.to_string();
                    assert!(
                        about.len() <= MAX,
                        "'{path}': the short description is {} chars (max {MAX}). Open the doc \
                         comment with a one-line summary, then a blank line, then the detail.",
                        about.len(),
                    );
                }
                check(sub, &path);
            }
        }

        // The root's own 'about' is the crate description, so it starts at the
        // subcommands.
        check(&Cli::command(), "monux");
    }

    #[test]
    fn servers_command_parses() {
        let cli = Cli::try_parse_from(["monux", "servers"]).unwrap();
        assert!(matches!(cli.command, Commands::Servers));
    }

    #[test]
    fn candidate_cycle_is_remembered_first_then_one_mdns_attempt() {
        // Empty store: a pass is exactly one mDNS attempt.
        let cycle = candidate_cycle(&[]);
        assert_eq!(cycle.len(), 1);
        assert!(matches!(cycle[0], Candidate::Discover));

        // The remembered servers lead, most recent first, then the mDNS attempt.
        let remembered = vec![
            monux::known_servers::RememberedServer {
                addr: "10.0.0.1:1213".parse().unwrap(),
                fingerprint: "aa".to_string(),
                hostname: Some("one".to_string()),
                last_connected: 200,
            },
            monux::known_servers::RememberedServer {
                addr: "10.0.0.2:1213".parse().unwrap(),
                fingerprint: "bb".to_string(),
                hostname: None,
                last_connected: 100,
            },
        ];
        let cycle = candidate_cycle(&remembered);
        assert_eq!(cycle.len(), 3);
        assert!(matches!(&cycle[0], Candidate::Remembered(addr) if *addr == "10.0.0.1:1213".parse().unwrap()));
        assert!(matches!(&cycle[1], Candidate::Remembered(addr) if *addr == "10.0.0.2:1213".parse().unwrap()));
        assert!(matches!(cycle[2], Candidate::Discover));
    }

    #[test]
    fn setup_flags_parse_and_scope_elevation() {
        // No flags: the base set, which needs root.
        let cli = Cli::try_parse_from(["monux", "setup"]).unwrap();
        let Commands::Setup(args) = cli.command else {
            panic!("expected the setup command")
        };
        assert!(args.autostart.is_none() && !args.desktop_shortcut);
        assert!(setup_needs_root(&args.autostart, args.desktop_shortcut));

        // Either per-user flag scopes the run AND skips the sudo re-exec.
        let cli = Cli::try_parse_from(["monux", "setup", "--desktop-shortcut"]).unwrap();
        let Commands::Setup(args) = cli.command else {
            panic!("expected the setup command")
        };
        assert!(args.autostart.is_none() && args.desktop_shortcut);
        assert!(!setup_needs_root(&args.autostart, args.desktop_shortcut));

        let cli = Cli::try_parse_from(["monux", "setup", "--autostart", "status"]).unwrap();
        let Commands::Setup(args) = cli.command else {
            panic!("expected the setup command")
        };
        assert_eq!(args.autostart, Some(monux::setup::Autostart::Status));
        assert!(!setup_needs_root(&args.autostart, args.desktop_shortcut));

        // Both per-user flags combine; still user-level.
        let cli = Cli::try_parse_from([
            "monux",
            "setup",
            "--autostart",
            "server",
            "--desktop-shortcut",
        ])
        .unwrap();
        let Commands::Setup(args) = cli.command else {
            panic!("expected the setup command")
        };
        assert_eq!(args.autostart, Some(monux::setup::Autostart::Server));
        assert!(args.desktop_shortcut);
        assert!(!setup_needs_root(&args.autostart, args.desktop_shortcut));
    }

    #[test]
    fn tray_subcommand_parses_hide_show_and_socket() {
        let cli = Cli::try_parse_from(["monux", "gui", "tray", "hide"]).unwrap();
        let Commands::Gui(args) = cli.command else {
            panic!("expected a gui command")
        };
        let GuiCommands::Tray(tray) = args.command else {
            panic!("expected the tray subcommand")
        };
        assert!(matches!(tray.action, TrayAction::Hide));
        assert!(tray.socket.is_none());

        let cli = Cli::try_parse_from([
            "monux",
            "gui",
            "tray",
            "show",
            "--socket",
            "/tmp/x/monux/client.sock",
        ])
        .unwrap();
        let Commands::Gui(args) = cli.command else {
            panic!("expected a gui command")
        };
        let GuiCommands::Tray(tray) = args.command else {
            panic!("expected the tray subcommand")
        };
        assert!(matches!(tray.action, TrayAction::Show));
        assert_eq!(
            tray.socket.as_deref(),
            Some(Path::new("/tmp/x/monux/client.sock"))
        );
    }

    #[test]
    fn tray_subcommand_rejects_missing_and_unknown_actions() {
        assert!(Cli::try_parse_from(["monux", "gui", "tray"]).is_err());
        assert!(Cli::try_parse_from(["monux", "gui", "tray", "blink"]).is_err());
    }

    #[test]
    fn uninstall_accepts_yes_and_defaults_to_prompt() {
        let cli = Cli::try_parse_from(["monux", "system", "uninstall", "--yes"]).unwrap();
        let Commands::System(args) = cli.command else {
            panic!("expected a system command")
        };
        // 'system' has exactly one subcommand, so this pattern is irrefutable.
        let SystemCommands::Uninstall(uninstall) = args.command;
        assert!(uninstall.yes);

        let cli = Cli::try_parse_from(["monux", "system", "uninstall"]).unwrap();
        let Commands::System(args) = cli.command else {
            panic!("expected a system command")
        };
        let SystemCommands::Uninstall(uninstall) = args.command;
        assert!(!uninstall.yes);
    }

    #[test]
    fn removed_command_paths_are_rejected() {
        // Folded into first-level commands or 'gui'.
        assert!(Cli::try_parse_from(["monux", "system", "status"]).is_err());
        assert!(Cli::try_parse_from(["monux", "system", "clients"]).is_err());
        assert!(Cli::try_parse_from(["monux", "system", "update"]).is_err());
        assert!(Cli::try_parse_from(["monux", "system", "setup"]).is_err());
        assert!(Cli::try_parse_from(["monux", "system", "tray", "hide"]).is_err());
        assert!(Cli::try_parse_from(["monux", "system", "indicator"]).is_err());
        assert!(Cli::try_parse_from(["monux", "daemon", "status"]).is_err());
        // ...and the new paths parse.
        assert!(Cli::try_parse_from(["monux", "status"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "update"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "setup"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "gui", "indicator"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "daemon", "switch", "next"]).is_ok());
    }

    #[test]
    fn update_to_and_rollback_flags() {
        let cli = Cli::try_parse_from(["monux", "update", "--to", "8.3.0"]).unwrap();
        let Commands::Update(args) = cli.command else {
            panic!("expected the update subcommand")
        };
        assert_eq!(args.to.as_deref(), Some("8.3.0"));
        assert!(!args.rollback);
        assert!(!args.force);
        // --to and --rollback are mutually exclusive; --force combines with both.
        assert!(Cli::try_parse_from(["monux", "update", "--to", "8.3.0", "--rollback"]).is_err());
        let cli = Cli::try_parse_from(["monux", "update", "--rollback", "--force"]).unwrap();
        let Commands::Update(args) = cli.command else {
            panic!("expected the update subcommand")
        };
        assert!(args.rollback);
        assert!(args.force);
        assert!(Cli::try_parse_from(["monux", "update", "--to", "5b4c00e", "--force"]).is_ok());
    }

    #[test]
    fn server_and_client_accept_no_indicator() {
        assert!(Cli::try_parse_from(["monux", "server", "--no-indicator"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "client", "--no-indicator"]).is_ok());
    }

    #[test]
    fn server_accepts_edge_map_and_dwell() {
        let cli = Cli::try_parse_from([
            "monux",
            "server",
            "--edge-map",
            "right=auto",
            "--edge-map",
            "left=aa11bb,top=laptop",
            "--edge-dwell-ms",
            "400",
        ])
        .unwrap();
        let Commands::Server(args) = cli.command else {
            panic!("expected the server subcommand")
        };
        let specs = args.edge_map.expect("edge map should be set");
        assert_eq!(specs, vec!["right=auto", "left=aa11bb,top=laptop"]);
        assert_eq!(args.edge_dwell_ms, Some(400));
        assert!(monux::edge::parse_edge_map(&specs).is_ok());

        // Defaults: no edge map, no dwell override (250ms built-in).
        let cli = Cli::try_parse_from(["monux", "server"]).unwrap();
        let Commands::Server(args) = cli.command else {
            panic!("expected the server subcommand")
        };
        assert!(args.edge_map.is_none());
        assert_eq!(args.edge_dwell_ms, None);
    }

    #[test]
    fn client_accepts_edge_map_and_dwell() {
        let cli = Cli::try_parse_from([
            "monux",
            "client",
            "10.0.0.1",
            "--edge-map",
            "left=auto",
            "--edge-map",
            "top=auto",
            "--edge-dwell-ms",
            "400",
        ])
        .unwrap();
        let Commands::Client(args) = cli.command else {
            panic!("expected the client subcommand")
        };
        let specs = args.edge_map.expect("edge map should be set");
        assert_eq!(specs, vec!["left=auto", "top=auto"]);
        assert_eq!(args.edge_dwell_ms, Some(400));
        assert!(monux::edge::parse_client_edge_map(&specs).is_ok());

        // Defaults: no edge map, no dwell override (250ms built-in).
        let cli = Cli::try_parse_from(["monux", "client", "10.0.0.1"]).unwrap();
        let Commands::Client(args) = cli.command else {
            panic!("expected the client subcommand")
        };
        assert!(args.edge_map.is_none());
        assert_eq!(args.edge_dwell_ms, None);
    }

    #[test]
    fn bool_flags_are_optional_set_true() {
        // SetTrue on an Option<bool>: present = Some(true), absent = None
        // (so the config file can tell "not given" from "given").
        let cli = Cli::try_parse_from(["monux", "server", "--www", "--no-indicator"]).unwrap();
        let Commands::Server(args) = cli.command else {
            panic!("expected the server subcommand")
        };
        assert_eq!(args.www, Some(true));
        assert_eq!(args.no_indicator, Some(true));
        assert_eq!(args.no_auto_update, None);
        // ...and they take no value.
        assert!(Cli::try_parse_from(["monux", "server", "--www", "true"]).is_err());
    }

    #[test]
    fn config_subcommand_parses_actions() {
        let cli = Cli::try_parse_from(["monux", "config"]).unwrap();
        let Commands::Config(args) = cli.command else {
            panic!("expected the config subcommand")
        };
        assert!(args.command.is_none());

        let cli = Cli::try_parse_from(["monux", "config", "set", "server.port", "4321"]).unwrap();
        let Commands::Config(args) = cli.command else {
            panic!("expected the config subcommand")
        };
        let Some(ConfigCommands::Set { key, values }) = args.command else {
            panic!("expected config set")
        };
        assert_eq!(key, "server.port");
        assert_eq!(values, vec!["4321".to_string()]);

        // Repeatable keys take several values.
        let cli = Cli::try_parse_from([
            "monux",
            "config",
            "set",
            "server.edge-map",
            "right=auto",
            "left=aa11bb",
        ])
        .unwrap();
        let Commands::Config(args) = cli.command else {
            panic!("expected the config subcommand")
        };
        let Some(ConfigCommands::Set { values, .. }) = args.command else {
            panic!("expected config set")
        };
        assert_eq!(values, vec!["right=auto".to_string(), "left=aa11bb".to_string()]);

        // 'set <key>' with no value (the reference card) parses too.
        assert!(Cli::try_parse_from(["monux", "config", "set", "server.port"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "config", "unset", "client.www"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "config", "keys", "edge"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "config", "edit"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "config", "validate"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "config", "bogus"]).is_err());

        // history / revert: bare, with a key, and with --to.
        let cli = Cli::try_parse_from(["monux", "config", "history"]).unwrap();
        let Commands::Config(args) = cli.command else {
            panic!("expected the config subcommand")
        };
        assert!(matches!(
            args.command,
            Some(ConfigCommands::History { key: None })
        ));
        let cli = Cli::try_parse_from(["monux", "config", "history", "server.port"]).unwrap();
        let Commands::Config(args) = cli.command else {
            panic!("expected the config subcommand")
        };
        let Some(ConfigCommands::History { key }) = args.command else {
            panic!("expected config history")
        };
        assert_eq!(key, Some("server.port".to_string()));
        let cli = Cli::try_parse_from([
            "monux",
            "config",
            "revert",
            "server.port",
            "--to",
            "2026-07-25T01:12:03Z",
        ])
        .unwrap();
        let Commands::Config(args) = cli.command else {
            panic!("expected the config subcommand")
        };
        let Some(ConfigCommands::Revert { key, to }) = args.command else {
            panic!("expected config revert")
        };
        assert_eq!(key, "server.port");
        assert_eq!(to, Some("2026-07-25T01:12:03Z".to_string()));
        assert!(Cli::try_parse_from(["monux", "config", "revert", "server.port"]).is_ok());
        assert!(Cli::try_parse_from(["monux", "config", "revert"]).is_err());
    }

    #[test]
    fn config_registry_matches_server_and_client_flags() {
        // The registry (config.rs) must not drift from the clap definitions:
        // every registered key names a real flag of its subcommand.
        let cmd = Cli::command();
        for spec in monux::config::REGISTRY {
            let sub = cmd
                .get_subcommands()
                .find(|s| s.get_name() == spec.section.as_str())
                .unwrap_or_else(|| panic!("no '{}' subcommand", spec.section.as_str()));
            assert!(
                sub.get_arguments().any(|a| a.get_long() == Some(spec.flag)),
                "registry key '{}' has no matching --{} flag",
                spec.key,
                spec.flag
            );
        }
    }

    #[test]
    fn server_args_resolve_flag_beats_config_beats_default() {
        let cfg = monux::config::File::parse(
            "[server]\nport = 4321\nedge-dwell-ms = 400\nwww = true\nno-indicator = true\nedge-map = [\"right=auto\"]\n",
        )
        .unwrap();

        // Explicit flags win over the config file.
        let cli =
            Cli::try_parse_from(["monux", "server", "--port", "5555", "--edge-dwell-ms", "100"])
                .unwrap();
        let Commands::Server(mut args) = cli.command else {
            panic!("expected the server subcommand")
        };
        args.resolve(&cfg);
        assert_eq!(args.port, Some(5555));
        assert_eq!(args.edge_dwell_ms, Some(100));
        // ...while the config fills the flags that were not given.
        assert_eq!(args.www, Some(true));
        assert_eq!(args.no_indicator, Some(true));
        assert_eq!(args.edge_map, Some(vec!["right=auto".to_string()]));

        // The config file alone fills everything it sets.
        let cli = Cli::try_parse_from(["monux", "server"]).unwrap();
        let Commands::Server(mut args) = cli.command else {
            panic!("expected the server subcommand")
        };
        args.resolve(&cfg);
        assert_eq!(args.port, Some(4321));
        assert_eq!(args.edge_dwell_ms, Some(400));

        // Without a config file the use sites fall back to the built-ins.
        let cli = Cli::try_parse_from(["monux", "server"]).unwrap();
        let Commands::Server(mut args) = cli.command else {
            panic!("expected the server subcommand")
        };
        args.resolve(&monux::config::File::default());
        assert_eq!(args.port, None);
        assert_eq!(args.port.unwrap_or(monux::config::DEFAULT_PORT), 1213);
        assert_eq!(
            args.edge_dwell_ms.unwrap_or(monux::config::DEFAULT_EDGE_DWELL_MS),
            250
        );
        assert!(!args.www.unwrap_or(false));
        assert_eq!(
            args.shortcut.as_deref().unwrap_or(monux::config::DEFAULT_SHORTCUT),
            "leftshift,leftalt,r"
        );
        // Semantic-None flags stay None: the adaptive modes.
        assert!(args.motion_hz.is_none());
        assert!(args.bulk_throttle_mbps.is_none());
    }

    #[test]
    fn client_args_resolve_flag_beats_config_beats_default() {
        let cfg =
            monux::config::File::parse("[client]\nmouse-scale = 0.5\nedge-dwell-ms = 400\n")
                .unwrap();

        // Explicit flag wins; config fills the rest.
        let cli = Cli::try_parse_from(["monux", "client", "--mouse-scale", "2"]).unwrap();
        let Commands::Client(mut args) = cli.command else {
            panic!("expected the client subcommand")
        };
        args.resolve(&cfg);
        assert_eq!(args.mouse_scale, Some(2.0));
        assert_eq!(args.edge_dwell_ms, Some(400));

        // Without a config file the use sites fall back to the built-ins.
        let cli = Cli::try_parse_from(["monux", "client"]).unwrap();
        let Commands::Client(mut args) = cli.command else {
            panic!("expected the client subcommand")
        };
        args.resolve(&monux::config::File::default());
        assert_eq!(args.mouse_scale, None);
        assert_eq!(
            args.mouse_scale.unwrap_or(monux::config::DEFAULT_INPUT_SCALE),
            1.0
        );
        assert!(args.edge_dwell_ms.is_none());
        assert!(args.host.is_none(), "the positional host is not configurable");
    }
}
