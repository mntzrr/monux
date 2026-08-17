//! The command line: every flag, subcommand and help string.
//!
//! Split from main.rs, which is now the wiring — resolve the arguments, build
//! the daemons, run them. These two things change for different reasons and at
//! different times, and together they were most of a 2,800-line file.
//!
//! The `resolve` methods here are the one piece of behaviour that lives with
//! the definitions rather than the wiring, deliberately: precedence (explicit
//! flag > config file > built-in default) is a property of each flag, and
//! keeping it next to the flag is what stops the two drifting.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use regex::Regex;

/// Version string including the git revision (see build.rs).
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("MONUX_GIT_SHA"));

/// Help section headings, shared so every subcommand groups its flags the same
/// way: a reader who learned the layout on 'server --help' knows it everywhere.
pub const H_SWITCHING: &str = "Switching";
pub const H_EDGES: &str = "Screen edges";
pub const H_NETWORK: &str = "Network";
pub const H_TUNING: &str = "Tuning";
pub const H_DAEMON: &str = "Daemon behavior";
pub const H_TARGET: &str = "Which daemon";
pub const H_OUTPUT: &str = "Output";
pub const H_CONTENT: &str = "Bundle contents";

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
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Runs a Monux server
    ///
    /// The machine with the physical input devices; clients connect to it.
    #[command(after_long_help = "\
Examples:
  monux server
  monux server --edge-map bottom=auto    # switch input at the bottom screen edge
  monux server --www                     # conservative tuning for the public internet
  monux server --fingerprints aa11bbccaa11bbccaa11bbccaa11bbccaa11bbccaa11bbccaa11bbccaa11bbcc  # pre-approve a client (no approval prompt)")]
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
pub struct SystemArgs {
    #[command(subcommand)]
    pub command: SystemCommands,
}

#[derive(Args)]
pub struct GuiArgs {
    #[command(subcommand)]
    pub command: GuiCommands,
}

#[derive(Args)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub command: DaemonCommands,
}

#[derive(Args)]
pub struct ConfigArgs {
    /// show / keys / set / unset / edit / validate / history / revert; bare
    /// 'monux config' shows the effective values
    #[command(subcommand)]
    pub command: Option<ConfigCommands>,
}

#[derive(Subcommand)]
pub enum ConfigCommands {
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
pub enum DaemonCommands {
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
pub enum GuiCommands {
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
pub enum SystemCommands {
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
pub struct UninstallArgs {
    /// Skip the interactive confirmation prompt (for scripts)
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct DaemonSwitchArgs {
    /// next, prev, local, or a client fingerprint prefix
    #[arg(value_name = "target")]
    pub target: String,

    /// Query this explicit control socket path
    ///
    /// Instead of the default $XDG_RUNTIME_DIR/monux/{server,client}.sock
    /// locations.
    #[arg(long, value_name = "path")]
    pub socket: Option<PathBuf>,
}

#[derive(Args)]
pub struct StatusArgs {
    /// Query the server daemon's socket only
    #[arg(long, conflicts_with = "client", help_heading = H_TARGET)]
    pub server: bool,

    /// Query the client daemon's socket only
    #[arg(long, help_heading = H_TARGET)]
    pub client: bool,

    /// Query this explicit control socket path
    ///
    /// Instead of the default $XDG_RUNTIME_DIR/monux/{server,client}.sock
    /// locations.
    #[arg(long, value_name = "path", help_heading = H_TARGET)]
    pub socket: Option<PathBuf>,

    /// Print the daemon's raw JSON response instead of a human-readable summary
    #[arg(long, help_heading = H_OUTPUT)]
    pub json: bool,
}

#[derive(Args)]
pub struct DiagnosticsArgs {
    /// Capture a live reproduction instead of a snapshot (see 'record --help')
    #[command(subcommand)]
    pub command: Option<DiagnosticsCommands>,

    /// Query the server daemon's socket only
    #[arg(long, conflicts_with = "client", help_heading = H_TARGET)]
    pub server: bool,

    /// Query the client daemon's socket only
    #[arg(long, help_heading = H_TARGET)]
    pub client: bool,

    /// Query this explicit control socket path
    ///
    /// Instead of the default $XDG_RUNTIME_DIR/monux/{server,client}.sock
    /// locations.
    #[arg(long, value_name = "path", help_heading = H_TARGET)]
    pub socket: Option<PathBuf>,

    /// Copy the bundle to the clipboard (as markdown) instead of printing it
    #[arg(long, help_heading = H_OUTPUT)]
    pub copy: bool,

    /// Render as issue-ready markdown [default with --copy]
    #[arg(long, conflicts_with_all = ["plain", "json"], help_heading = H_OUTPUT)]
    pub markdown: bool,

    /// Render as plain text [default when printing]
    #[arg(long, conflicts_with = "json", help_heading = H_OUTPUT)]
    pub plain: bool,

    /// Print the bundle as raw JSON
    #[arg(long, help_heading = H_OUTPUT)]
    pub json: bool,

    /// Strip IPs, hostnames, usernames and home paths
    ///
    /// Replaces them with placeholders before the bundle leaves this machine.
    #[arg(long, help_heading = H_OUTPUT)]
    pub redact: bool,

    /// Recent daemon log lines to include
    #[arg(long, value_name = "n", default_value_t = monux::diagnostics::DEFAULT_LOG_LINES, help_heading = H_CONTENT)]
    pub lines: usize,

    /// How far back to read the systemd journal (a journalctl --since value)
    ///
    /// allow_hyphen_values is load-bearing: journalctl's relative windows all
    /// start with a minus ('-30min', '-2h'), which clap would otherwise treat
    /// as an unknown flag — so every explicit value failed while the
    /// identical default worked.
    #[arg(
        long,
        value_name = "when",
        allow_hyphen_values = true,
        default_value = monux::diagnostics::DEFAULT_JOURNAL_SINCE,
        help_heading = H_CONTENT
    )]
    pub since: String,

    /// Skip the journal entirely
    #[arg(long, conflicts_with = "since", help_heading = H_CONTENT)]
    pub no_journal: bool,

    /// Also fetch connected clients' bundles (server only)
    ///
    /// So one paste covers both sides of the link.
    #[arg(long, help_heading = H_CONTENT)]
    pub peer: bool,

    /// Prepare a ready-to-file GitHub issue
    ///
    /// Writes the report to a file, copies it to the clipboard, and prints
    /// the command that files it. Never posts anything by itself: filing is
    /// publishing, so you review and send.
    #[arg(long, conflicts_with = "copy", help_heading = H_OUTPUT)]
    pub issue: bool,

    /// Title for the issue prepared by --issue
    ///
    /// A placeholder to edit is used when this is omitted.
    #[arg(long, value_name = "text", requires = "issue", help_heading = H_OUTPUT)]
    pub title: Option<String>,

    /// Print what a bundle contains — and never contains — then exit
    #[arg(long, help_heading = H_CONTENT)]
    pub privacy: bool,
}

#[derive(Subcommand)]
pub enum DiagnosticsCommands {
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
pub struct RecordArgs {
    /// Record the client daemon instead of the server
    #[arg(long)]
    pub client: bool,

    /// Key codes to trace through the input pipeline, comma-separated
    ///
    /// For example 28 = Enter. Every stage that sees them logs a KEYTRACE line.
    #[arg(long, value_name = "codes")]
    pub keys: Option<String>,

    /// Log at trace level (very verbose, includes QUIC internals)
    #[arg(long)]
    pub trace: bool,

    /// Write the capture here instead of a generated path under $TMPDIR
    #[arg(long, value_name = "path")]
    pub out: Option<PathBuf>,

    /// Arguments to pass through to the daemon being recorded
    #[arg(trailing_var_arg = true, value_name = "daemon args")]
    pub args: Vec<String>,
}

#[derive(Args)]
pub struct TrayArgs {
    /// Whether to remove or restore the tray icon
    ///
    /// 'hide' removes the tray icon (the daemon keeps running), 'show'
    /// restores it — or starts a standalone tray when no daemon runs.
    #[arg(value_enum, value_name = "hide|show")]
    pub action: TrayAction,

    /// Send the command to this explicit control socket path
    ///
    /// Instead of the default $XDG_RUNTIME_DIR/monux/{server,client}.sock
    /// locations.
    #[arg(long, value_name = "path")]
    pub socket: Option<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum TrayAction {
    Hide,
    Show,
}

#[derive(Args)]
pub struct SetupArgs {
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
    pub autostart: Option<monux::setup::Autostart>,

    /// Install the 'monux tray' app-menu shortcut (no sudo)
    ///
    /// The shortcut runs 'monux gui tray show': writes
    /// ~/.local/share/applications/monux-tray.desktop (XDG_DATA_HOME
    /// honored). User-level, like --autostart: no elevation.
    #[arg(long)]
    pub desktop_shortcut: bool,
}

// Every flag below opens with a one-line summary, then a blank line, then the
// detail. clap shows only the first paragraph for '-h' and the whole comment for
// '--help', so that split is what keeps '-h' a scannable table.
#[derive(Args)]
pub struct ServerArgs {
    /// Chord that switches to the next client [default: leftshift,leftalt,r]
    #[arg(long, alias = "shortcut-next", value_name = "key1,key2,key3", help_heading = H_SWITCHING)]
    pub shortcut: Option<String>,

    /// Chord that switches to the previous client [default: leftalt,p]
    #[arg(long, value_name = "key1,key2,key3", help_heading = H_SWITCHING)]
    pub shortcut_prev: Option<String>,

    /// Chord that switches straight to one client, by fingerprint prefix
    ///
    /// An empty fingerprint targets the server itself. Repeatable, one chord
    /// per target.
    #[arg(long, value_name = "key1,key2,key3=[fingerprint-prefix]", help_heading = H_SWITCHING)]
    pub shortcut_goto: Option<Vec<String>>,

    /// Chord that pauses/resumes input handling [default: disabled]
    ///
    /// While paused, ALL input devices (keyboards included) are ungrabbed so
    /// the local machine gets raw input with monux's re-emit out of the way
    /// (games, raw-input apps); press the chord again to resume. Disabled
    /// unless set (e.g. '--pause-shortcut leftshift,leftalt,p').
    #[arg(long, value_name = "key1,key2,key3", help_heading = H_SWITCHING)]
    pub pause_shortcut: Option<String>,

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
    pub edge_map: Option<Vec<String>>,

    /// Dwell time on the edge before the switch fires [default: 250]
    ///
    /// In milliseconds; see --edge-map.
    #[arg(long, value_name = "ms", help_heading = H_EDGES)]
    pub edge_dwell_ms: Option<u64>,

    /// Listen IP [default: 0.0.0.0]
    #[arg(short = 'l', long, value_name = "ip", help_heading = H_NETWORK)]
    pub listen: Option<IpAddr>,

    /// Listen port [default: 1213]
    #[arg(short = 'p', long, value_name = "port", help_heading = H_NETWORK)]
    pub port: Option<u16>,

    /// Pre-approve a client certificate fingerprint (repeatable)
    ///
    /// A client whose fingerprint is listed connects without the interactive
    /// approval prompt.
    #[arg(long, alias = "fingerprints", value_name = "fingerprint", help_heading = H_NETWORK)]
    pub fingerprint: Option<Vec<String>>,

    /// Tune for the public internet instead of a LAN
    ///
    /// Use conservative tuning suitable for traversing the public internet
    /// (WWW). The default is low-latency tuning for local networks.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_NETWORK)]
    pub www: Option<bool>,

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
    pub motion_hz: Option<u32>,

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
    pub bulk_throttle_mbps: Option<f64>,

    /// Largest clipboard payload to transfer [default: 5MB]
    #[arg(long, value_name = "kb", help_heading = H_TUNING)]
    pub max_clipboard_size_kb: Option<u64>,

    /// Only monitor devices matching this pattern (repeatable)
    ///
    /// A substring or regular expression matched against the device name;
    /// repeat the flag for multiple filters.
    #[arg(long, value_name = "device-name-pattern", help_heading = H_TUNING)]
    pub device: Option<Vec<Regex>>,

    /// Turn off the automatic background update
    ///
    /// The background update is on by default: a daily check at low CPU
    /// priority, then an automatic restart into the new binary. The session
    /// resumes automatically on reconnect.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_DAEMON)]
    pub no_auto_update: Option<bool>,

    /// Install background updates automatically instead of only reporting them
    ///
    /// Off by default: the daily check reports an available update (tray,
    /// 'monux status') and installs nothing, because installing compiles and
    /// runs whatever the repo holds. With this flag the daemon installs and
    /// restarts on its own — and then REQUIRES a verified release signature,
    /// refusing anything it cannot attribute.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_DAEMON)]
    pub auto_install: Option<bool>,

    /// Do not auto-spawn the tray indicator
    ///
    /// By default 'monux gui indicator' starts once the daemon is up whenever
    /// a desktop session bus is available, and stops with the daemon. Can
    /// also be disabled with MONUX_NO_INDICATOR=1.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_DAEMON)]
    pub no_indicator: Option<bool>,

    /// Exit automatically after this many seconds, to test a configuration safely
    #[arg(long, value_name = "seconds", help_heading = H_DAEMON)]
    pub exit_secs: Option<u32>,
}

impl ServerArgs {
    /// Fills config-capable fields left unset on the command line from the
    /// config file's [server] section: explicit flag > config file > built-in
    /// default (the default is applied at the use sites).
    pub fn resolve(&mut self, cfg: &monux::config::File) {
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
        self.auto_install = self
            .auto_install
            .take()
            .or_else(|| cfg.get_bool("server.auto-install"));
    }
}

#[derive(Args)]
pub struct ClientArgs {
    /// Server hostname or IP [default: discover via mDNS]
    ///
    /// If omitted, the server is discovered on the local network via mDNS.
    pub host: Option<String>,

    /// Server port [default: 1213]
    #[arg(short = 'p', long, value_name = "port", help_heading = H_NETWORK)]
    pub port: Option<u16>,

    /// Pre-approve a server certificate fingerprint (repeatable)
    ///
    /// A server whose fingerprint is listed connects without the interactive
    /// approval prompt.
    #[arg(long, alias = "fingerprints", value_name = "fingerprint", help_heading = H_NETWORK)]
    pub fingerprint: Option<Vec<String>>,

    /// Tune for the public internet instead of a LAN
    ///
    /// Use conservative tuning suitable for traversing the public internet
    /// (WWW). The default is low-latency tuning for local networks.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_NETWORK)]
    pub www: Option<bool>,

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
    pub edge_map: Option<Vec<String>>,

    /// Dwell time on the edge before the return fires [default: 250]
    ///
    /// In milliseconds; see --edge-map.
    #[arg(long, value_name = "ms", help_heading = H_EDGES)]
    pub edge_dwell_ms: Option<u64>,

    /// Scale incoming pointer motion [default: 1.0]
    ///
    /// Multiplier applied to pointer motion deltas before injecting them on
    /// this machine, for compensating DPI/sensitivity differences with the
    /// server's mouse. Sub-tick fractions are carried between events, so small
    /// scales lose no motion over time.
    #[arg(long, value_name = "scale", value_parser = monux::config::parse_input_scale, help_heading = H_TUNING)]
    pub mouse_scale: Option<f64>,

    /// Scale incoming scroll wheel deltas [default: 1.0]
    ///
    /// Applies to the hi-res wheel axes as well.
    #[arg(long, value_name = "scale", value_parser = monux::config::parse_input_scale, help_heading = H_TUNING)]
    pub scroll_scale: Option<f64>,

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
    pub bulk_throttle_mbps: Option<f64>,

    /// Largest clipboard payload to transfer [default: 5MB]
    #[arg(long, value_name = "kb", help_heading = H_TUNING)]
    pub max_clipboard_size_kb: Option<u64>,

    /// Desktop notification when the link degrades or recovers
    ///
    /// Off by default: a degraded link (RTT over 50ms or packet loss over 2%)
    /// is only logged — the 'Link degraded:' line and the per-sample 'Link
    /// stats:' lines. Set to also get 'monux: link degraded' / 'monux: link
    /// recovered' desktop notifications (at most once per 5 minutes). Only
    /// meaningful in LAN mode: the link monitor does not run under --www.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_TUNING)]
    pub link_notify: Option<bool>,

    /// Turn off the automatic background update
    ///
    /// The background update is on by default: a daily check at low CPU
    /// priority, then an automatic restart into the new binary. The session
    /// resumes automatically on reconnect.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_DAEMON)]
    pub no_auto_update: Option<bool>,

    /// Install background updates automatically instead of only reporting them
    ///
    /// Off by default: the daily check reports an available update (tray,
    /// 'monux status') and installs nothing, because installing compiles and
    /// runs whatever the repo holds. With this flag the daemon installs and
    /// restarts on its own — and then REQUIRES a verified release signature,
    /// refusing anything it cannot attribute.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_DAEMON)]
    pub auto_install: Option<bool>,

    /// Do not auto-spawn the tray indicator
    ///
    /// By default 'monux gui indicator' starts once the daemon is up whenever
    /// a desktop session bus is available, and stops with the daemon. Can
    /// also be disabled with MONUX_NO_INDICATOR=1.
    #[arg(long, num_args = 0, default_missing_value = "true", help_heading = H_DAEMON)]
    pub no_indicator: Option<bool>,
}

impl ClientArgs {
    /// Fills config-capable fields left unset on the command line from the
    /// config file's [client] section: explicit flag > config file > built-in
    /// default (the default is applied at the use sites). The positional host
    /// is deliberately not configurable.
    pub fn resolve(&mut self, cfg: &monux::config::File) {
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
        self.link_notify = self
            .link_notify
            .take()
            .or_else(|| cfg.get_bool("client.link-notify"));
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
        self.auto_install = self
            .auto_install
            .take()
            .or_else(|| cfg.get_bool("client.auto-install"));
    }
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Rebuild even if up to date, bypassing the protocol gate
    ///
    /// Reinstalls unconditionally and skips the server
    /// protocol-compatibility check.
    #[arg(long)]
    pub force: bool,

    /// Install a specific version or commit instead of the latest
    ///
    /// For example '--to 8.3.0' or '--to 5b4c00e'. Pins auto-update so it
    /// never undoes the downgrade; a plain 'monux update' lifts the pin again.
    #[arg(long, value_name = "version|commit", conflicts_with = "rollback")]
    pub to: Option<String>,

    /// Return to the previously installed build
    ///
    /// Every install records the build it replaced; this is shorthand for
    /// '--to <recorded commit>'.
    #[arg(long)]
    pub rollback: bool,
}

