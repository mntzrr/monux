//! `monux gui indicator` — a StatusNotifierItem tray icon for the local
//! monux daemon, built on the ksni crate (pure-Rust SNI client over D-Bus).
//!
//! The indicator is a THIN CLIENT of the control socket (control.rs): every
//! POLL_INTERVAL it queries `{"cmd":"status"}` against server.sock, falling
//! back to client.sock, and renders the result; menu actions send the same
//! commands a CLI would. It never spawns or blocks on the daemon's event
//! loops — the daemon serves each control connection on its own task and
//! dispatch only reads mirrors, and the indicator's own socket reads carry a
//! short timeout (SOCKET_TIMEOUT), so a wedged daemon degrades the icon
//! instead of hanging the tray for good. Bounded, though, not free: the
//! poll and every menu callback run on ksni's single service thread with
//! blocking I/O, so a wedged daemon can freeze the tray for up to
//! SOCKET_TIMEOUT per socket tried, and "Copy diagnostics" additionally
//! shells out to journalctl and a clipboard tool synchronously — a menu
//! action can stall the tray for seconds before the icon degrades. When no
//! daemon answers, the indicator keeps running and shows the "not running"
//! state, whose menu doubles as a launcher: "Start server"/"Start client"
//! (via the autostart systemd unit when installed, otherwise a detached
//! `monux <role>` spawn) and "Hide tray" (exits the standalone indicator).
//! A daemon that ANSWERS without a usable state (ok:false, e.g. "state not
//! available yet") is alive: it gets a starting view WITHOUT the launcher
//! rows — "Start server" there would spawn a second daemon whose
//! single-instance takeover SIGTERMs the one that just answered. When there
//! is no D-Bus session bus or SNI host (headless TTY), run() fails with a
//! clean error and exit code 1.
//!
//! # Icon colors (the dot is a programmatically generated ARGB pixmap — SNI
//! supports pixmaps, so no icon-theme lookup is involved)
//!
//! - GREEN: input is local — server with current_target "local" and no
//!   degradation; client connected but not owning input
//! - BLUE: input is on a client — server with current_target set to a client
//!   addr; client that currently owns the server's input (active)
//! - GREY: the server is paused
//! - RED: the link is degraded. Precisely, for v1:
//!   - server role: any connected client with rtt_ms > 50 (DEGRADED_RTT_MS)
//!   - client role: connected == false
//!
//!   RED outranks GREY — a degraded link is a problem worth seeing even while
//!   paused.
//! - Unknown (no daemon answers, or it answered without a usable state
//!   yet): a hollow grey "?" instead of the dot.
//!
//! The tooltip carries the details ("monux: input on 192.168.1.102", per-client
//! rtt/uptime, clipboard owner, update availability, the last action's error).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tracing::{debug, info, warn};

use ksni::blocking::TrayMethods;

use crate::control::{self, Diagnostics, Role, ServerState, State};
use crate::diagnostics;
use crate::notify::{self, Urgency};

/// How often the indicator re-queries the daemon's control socket.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// A client link above this RTT (ms) counts as degraded: RED icon (server
/// role only; see module docs for the precise color rules).
const DEGRADED_RTT_MS: u64 = 50;

/// Tray icon edge length in pixels (square ARGB pixmap).
const ICON_SIZE: i32 = 22;

/// Dot colors, as (R, G, B). The alpha channel is always fully opaque.
const GREEN: (u8, u8, u8) = (0x2e, 0xcc, 0x40);
const BLUE: (u8, u8, u8) = (0x33, 0x7e, 0xf6);
const GREY: (u8, u8, u8) = (0x96, 0x96, 0x96);
const RED: (u8, u8, u8) = (0xe6, 0x28, 0x28);

/// Notification id for indicator messages (replaces, never stacks — see
/// notify.rs).
const NOTIFY_ID: &str = "monux-indicator";

/// The icon's semantic color; mapping rules are in the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IconColor {
    Green,
    Blue,
    Grey,
    Red,
    /// No daemon answered: rendered as a hollow grey "?", not a dot.
    Unknown,
}

/// Maps daemon state to the icon color (see module docs).
fn color_of(state: &State) -> IconColor {
    match state {
        State::Server(s) => {
            if s.clients
                .iter()
                .any(|c| c.rtt_ms.map(|rtt| rtt > DEGRADED_RTT_MS).unwrap_or(false))
            {
                return IconColor::Red;
            }
            if s.paused {
                return IconColor::Grey;
            }
            if s.current_target != "local" {
                return IconColor::Blue;
            }
            IconColor::Green
        }
        State::Client(c) => {
            if !c.connected {
                return IconColor::Red;
            }
            if c.active {
                return IconColor::Blue;
            }
            IconColor::Green
        }
    }
}

/// How the last status poll went, as far as the view and the menu care.
enum DaemonStatus {
    /// A full snapshot to render.
    Up(State),
    /// The socket ANSWERED but had no usable state (ok:false, e.g. "state
    /// not available yet (rotation loop has not run)", or a body we cannot
    /// parse): the daemon is ALIVE, so the menu must NOT offer the launcher
    /// rows — "Start server" would spawn a second daemon whose
    /// single-instance takeover SIGTERMs the one that just answered.
    /// Carries the reason, for the tooltip and the menu.
    NoState(String),
    /// No socket answered: the standalone tray doubles as a launcher.
    Silent,
}

/// What the indicator renders right now.
struct View {
    color: IconColor,
    /// Tooltip title ("monux: input on 10.0.0.2:1213", ...).
    title: String,
    /// Tooltip body: role/version plus per-connection details.
    details: String,
    /// The last poll's outcome, for the menu.
    status: DaemonStatus,
}

impl View {
    fn from_state(state: State) -> View {
        View {
            color: color_of(&state),
            title: title_of(&state),
            details: details_of(&state),
            status: DaemonStatus::Up(state),
        }
    }

    fn not_running() -> View {
        View {
            color: IconColor::Unknown,
            title: "monux: not running".to_string(),
            details: "No monux daemon is answering its control socket.".to_string(),
            status: DaemonStatus::Silent,
        }
    }

    /// The daemon answered but reported no usable state (see DaemonStatus::
    /// NoState): rendered like the unknown icon, but it is NOT the
    /// not-running launcher view.
    fn no_state(reason: String) -> View {
        View {
            color: IconColor::Unknown,
            title: "monux: starting".to_string(),
            details: format!(
                "The daemon answers its control socket but has no status yet: {}",
                reason
            ),
            status: DaemonStatus::NoState(reason),
        }
    }
}

fn fmt_rtt(rtt_ms: Option<u64>) -> String {
    rtt_ms
        .map(|rtt| format!("{}ms", rtt))
        .unwrap_or_else(|| "?".to_string())
}

fn clipboard_summary(s: &ServerState) -> String {
    if s.clipboard.owner == "none" {
        "none".to_string()
    } else if s.clipboard.types.is_empty() {
        s.clipboard.owner.clone()
    } else {
        format!("{} ({})", s.clipboard.owner, s.clipboard.types.join(", "))
    }
}

fn title_of(state: &State) -> String {
    match state {
        State::Server(s) => match color_of(state) {
            IconColor::Red => {
                // Name the worst offender.
                match s
                    .clients
                    .iter()
                    .filter(|c| c.rtt_ms.map(|rtt| rtt > DEGRADED_RTT_MS).unwrap_or(false))
                    .max_by_key(|c| c.rtt_ms)
                {
                    Some(c) => format!("monux: degraded — {} rtt {}", c.addr, fmt_rtt(c.rtt_ms)),
                    None => "monux: degraded".to_string(),
                }
            }
            IconColor::Grey => "monux: paused".to_string(),
            IconColor::Blue => format!("monux: input on {}", s.current_target),
            IconColor::Green => "monux: input local".to_string(),
            IconColor::Unknown => unreachable!("a state always maps to a dot color"),
        },
        State::Client(c) => match color_of(state) {
            IconColor::Red => format!("monux: not connected to {}", c.server),
            IconColor::Blue => format!("monux: input here (server {})", c.server),
            IconColor::Green => format!("monux: connected to {}", c.server),
            IconColor::Grey | IconColor::Unknown => {
                unreachable!("client states never map to grey/unknown")
            }
        },
    }
}

fn details_of(state: &State) -> String {
    match state {
        State::Server(s) => {
            let mut lines = vec![format!(
                "server v{} (protocol {}), listening {}",
                s.version, s.protocol_version, s.listen
            )];
            for c in &s.clients {
                lines.push(format!(
                    "{} — rtt {}, up {}s",
                    c.addr,
                    fmt_rtt(c.rtt_ms),
                    c.connected_since_secs
                ));
            }
            lines.push(format!("clipboard: {}", clipboard_summary(s)));
            if let Some(sha) = &s.update_available {
                lines.push(format!("update available: {}", sha));
            }
            lines.join("\n")
        }
        State::Client(c) => {
            let mut lines = vec![format!(
                "client v{} (protocol {})",
                c.version, c.protocol_version
            )];
            if c.connected {
                lines.push(format!(
                    "server {} — rtt {}, up {}s, {} packets lost",
                    c.server,
                    fmt_rtt(c.rtt_ms),
                    c.connected_since_secs.unwrap_or(0),
                    c.lost_packets.unwrap_or(0)
                ));
            } else {
                lines.push(format!("server {} — not connected", c.server));
            }
            lines.join("\n")
        }
    }
}

/// One row of the tray menu, before conversion to ksni types. Unit tests
/// check this model; the ksni conversion (to_ksni_menu) is mechanical.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MenuRow {
    /// A disabled informative row.
    Label(String),
    /// A row triggering a control-socket action; `enabled: false` renders it
    /// greyed out (used for switch rows while the server is paused: rotation
    /// drops switches then, so a clickable row would silently do nothing).
    Action {
        label: String,
        action: MenuAction,
        enabled: bool,
    },
    Separator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MenuAction {
    SwitchLocal,
    /// Switch to the client with this (full) fingerprint.
    SwitchTo(String),
    Pause,
    Resume,
    /// Sets the client's degraded-link notifications on/off (the bool is the
    /// TARGET state, the opposite of what the status poll reported).
    SetLinkNotify(bool),
    UpdateNow,
    CopyDiagnostics,
    /// Starts the server/client daemon (not-running menu only). Local: no
    /// control socket exists to ask (see start_daemon).
    StartServer,
    StartClient,
    /// Hides the tray icon until 'monux gui tray show' or a daemon restart:
    /// with a daemon, the hide is asked for over the socket (so no respawn
    /// follows) and this process then leaves on its own; without one (the
    /// standalone tray), leaving is the whole of it. See exits_after_ack for
    /// why the ack alone is not enough.
    HideTray,
    Restart,
    Exit,
}

impl MenuAction {
    /// Short name for error messages and notifications.
    fn label(&self) -> &'static str {
        match self {
            MenuAction::SwitchLocal => "Switch to local",
            MenuAction::SwitchTo(_) => "Switch",
            MenuAction::Pause => "Pause",
            MenuAction::Resume => "Resume",
            MenuAction::SetLinkNotify(_) => "Link notifications",
            MenuAction::UpdateNow => "Update check",
            MenuAction::CopyDiagnostics => "Copy diagnostics",
            MenuAction::StartServer => "Start server",
            MenuAction::StartClient => "Start client",
            MenuAction::HideTray => "Hide tray icon",
            MenuAction::Restart => "Restart monux",
            MenuAction::Exit => "Exit monux",
        }
    }
}

/// Builds the menu model for the current poll outcome (see the module docs
/// and the phase spec: dynamic per state, switch/pause rows on the server
/// socket only).
fn menu_rows(status: &DaemonStatus) -> Vec<MenuRow> {
    let mut rows = Vec::new();
    match status {
        DaemonStatus::Silent => {
            rows.push(MenuRow::Label("monux is not running".to_string()));
            rows.push(MenuRow::Separator);
            // The standalone tray doubles as a launcher: start a daemon
            // (via the autostart unit when installed, else a detached
            // spawn — see start_daemon)...
            rows.push(MenuRow::Action {
                label: "Start server".to_string(),
                action: MenuAction::StartServer,
                enabled: true,
            });
            rows.push(MenuRow::Action {
                label: "Start client".to_string(),
                action: MenuAction::StartClient,
                enabled: true,
            });
            rows.push(MenuRow::Separator);
            // ...and hide, which with no daemon to ask simply exits this
            // standalone indicator.
            rows.push(MenuRow::Action {
                label: "Hide tray".to_string(),
                action: MenuAction::HideTray,
                enabled: true,
            });
        }
        DaemonStatus::NoState(reason) => {
            rows.push(MenuRow::Label("monux is starting".to_string()));
            rows.push(MenuRow::Label(reason.clone()));
            rows.push(MenuRow::Separator);
            // NO launcher rows here: the daemon answered, so a "Start
            // server" click would spawn a SECOND daemon that takes over the
            // single-instance lock and SIGTERMs the one that just answered.
            rows.push(MenuRow::Action {
                label: "Hide tray icon".to_string(),
                action: MenuAction::HideTray,
                enabled: true,
            });
        }
        DaemonStatus::Up(State::Server(s)) => {
            rows.push(MenuRow::Label(format!("Input: {}", s.current_target)));
            rows.push(MenuRow::Separator);
            // While paused, rotation drops switch events (the paused guard),
            // so the switch rows are greyed out: a clickable row would ack
            // the command yet visibly do nothing. Resume stays enabled.
            let switching_enabled = !s.paused;
            if s.current_target != "local" {
                rows.push(MenuRow::Action {
                    label: "Switch to local".to_string(),
                    action: MenuAction::SwitchLocal,
                    enabled: switching_enabled,
                });
            }
            for client in &s.clients {
                // No switch row for the client that already owns input.
                if client.addr == s.current_target {
                    continue;
                }
                rows.push(MenuRow::Action {
                    label: format!("Switch to {}", client.addr),
                    // The full fingerprint is always a unique prefix.
                    action: MenuAction::SwitchTo(client.fingerprint.clone()),
                    enabled: switching_enabled,
                });
            }
            rows.push(MenuRow::Action {
                label: if s.paused { "Resume" } else { "Pause" }.to_string(),
                action: if s.paused {
                    MenuAction::Resume
                } else {
                    MenuAction::Pause
                },
                enabled: true,
            });
            rows.push(MenuRow::Separator);
            for client in &s.clients {
                rows.push(MenuRow::Label(format!(
                    "Connection: {} — rtt {}, up {}s",
                    client.addr,
                    fmt_rtt(client.rtt_ms),
                    client.connected_since_secs
                )));
            }
            rows.push(MenuRow::Label(format!("Clipboard: {}", clipboard_summary(s))));
            rows.push(MenuRow::Separator);
            match &s.update_available {
                Some(sha) => rows.push(MenuRow::Action {
                    label: format!("Update available: {} — update now", sha),
                    action: MenuAction::UpdateNow,
                    enabled: true,
                }),
                None => rows.push(MenuRow::Action {
                    label: "Check for update now".to_string(),
                    action: MenuAction::UpdateNow,
                    enabled: true,
                }),
            }
            rows.push(MenuRow::Action {
                label: "Copy diagnostics".to_string(),
                action: MenuAction::CopyDiagnostics,
                enabled: true,
            });
            rows.push(MenuRow::Action {
                label: "Hide tray icon".to_string(),
                action: MenuAction::HideTray,
                enabled: true,
            });
            rows.push(MenuRow::Separator);
            rows.push(MenuRow::Action {
                label: "Restart monux".to_string(),
                action: MenuAction::Restart,
                enabled: true,
            });
            rows.push(MenuRow::Action {
                label: "Exit monux".to_string(),
                action: MenuAction::Exit,
                enabled: true,
            });
        }
        DaemonStatus::Up(State::Client(c)) => {
            rows.push(MenuRow::Label(format!("Server: {}", c.server)));
            rows.push(MenuRow::Label(format!(
                "Connection: {}",
                if c.connected {
                    format!(
                        "rtt {}, up {}s",
                        fmt_rtt(c.rtt_ms),
                        c.connected_since_secs.unwrap_or(0)
                    )
                } else {
                    "not connected".to_string()
                }
            )));
            rows.push(MenuRow::Label(format!(
                "Input: {}",
                if c.active { "here" } else { "server" }
            )));
            rows.push(MenuRow::Separator);
            // Live + persisted toggle (the daemon's "link-notify" command
            // flips the monitor's flag and writes client.link-notify).
            rows.push(MenuRow::Action {
                label: if c.link_notify {
                    "Link notifications: on — turn off"
                } else {
                    "Link notifications: off — turn on"
                }
                .to_string(),
                action: MenuAction::SetLinkNotify(!c.link_notify),
                enabled: true,
            });
            // The client state has no update_available field, so this is
            // always the plain manual check.
            rows.push(MenuRow::Action {
                label: "Check for update now".to_string(),
                action: MenuAction::UpdateNow,
                enabled: true,
            });
            rows.push(MenuRow::Action {
                label: "Copy diagnostics".to_string(),
                action: MenuAction::CopyDiagnostics,
                enabled: true,
            });
            rows.push(MenuRow::Action {
                label: "Hide tray icon".to_string(),
                action: MenuAction::HideTray,
                enabled: true,
            });
            rows.push(MenuRow::Separator);
            rows.push(MenuRow::Action {
                label: "Restart monux".to_string(),
                action: MenuAction::Restart,
                enabled: true,
            });
            rows.push(MenuRow::Action {
                label: "Exit monux".to_string(),
                action: MenuAction::Exit,
                enabled: true,
            });
        }
    }
    rows
}

/// Converts the menu model to ksni items; action closures dispatch through
/// run_action.
fn to_ksni_menu(rows: Vec<MenuRow>) -> Vec<ksni::menu::MenuItem<MonuxTray>> {
    use ksni::menu::{MenuItem, StandardItem};
    rows.into_iter()
        .map(|row| match row {
            MenuRow::Separator => MenuItem::Separator,
            MenuRow::Label(label) => StandardItem {
                label,
                enabled: false,
                ..Default::default()
            }
            .into(),
            MenuRow::Action {
                label,
                action,
                enabled,
            } => StandardItem {
                label,
                enabled,
                activate: Box::new(move |tray: &mut MonuxTray| run_action(tray, &action)),
                ..Default::default()
            }
            .into(),
        })
        .collect()
}

/// Draws a filled circle with a 2px transparent margin. ARGB32 in network
/// byte order (A, R, G, B per pixel), as the SNI pixmap format requires.
fn dot_pixmap(size: i32, rgb: (u8, u8, u8)) -> Vec<u8> {
    let mut data = vec![0u8; (size * size * 4) as usize];
    let center = (size as f32 - 1.0) / 2.0;
    let radius = size as f32 / 2.0 - 2.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            if (dx * dx + dy * dy).sqrt() <= radius {
                let i = ((y * size + x) * 4) as usize;
                data[i] = 0xff;
                data[i + 1] = rgb.0;
                data[i + 2] = rgb.1;
                data[i + 3] = rgb.2;
            }
        }
    }
    data
}

/// 5x7 bitmap of '?', one bit per pixel (MSB is the leftmost pixel), scaled
/// up by 2 when rendered — the "hollow" unknown state (no font rendering
/// involved).
const QUESTION_GLYPH: [u8; 7] = [
    0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b00000, 0b00100,
];

/// Draws the grey "?" glyph (scaled 2x, centered) on a transparent canvas.
fn question_pixmap(size: i32, rgb: (u8, u8, u8)) -> Vec<u8> {
    const SCALE: i32 = 2;
    let mut data = vec![0u8; (size * size * 4) as usize];
    let origin_x = (size - 5 * SCALE) / 2;
    let origin_y = (size - 7 * SCALE) / 2;
    for (row, bits) in QUESTION_GLYPH.iter().enumerate() {
        for col in 0..5 {
            if bits & (0b10000 >> col) == 0 {
                continue;
            }
            for dy in 0..SCALE {
                for dx in 0..SCALE {
                    let x = origin_x + col * SCALE + dx;
                    let y = origin_y + row as i32 * SCALE + dy;
                    let i = ((y * size + x) * 4) as usize;
                    data[i] = 0xff;
                    data[i + 1] = rgb.0;
                    data[i + 2] = rgb.1;
                    data[i + 3] = rgb.2;
                }
            }
        }
    }
    data
}

fn icon_for(color: IconColor) -> ksni::Icon {
    let data = match color {
        IconColor::Green => dot_pixmap(ICON_SIZE, GREEN),
        IconColor::Blue => dot_pixmap(ICON_SIZE, BLUE),
        IconColor::Grey => dot_pixmap(ICON_SIZE, GREY),
        IconColor::Red => dot_pixmap(ICON_SIZE, RED),
        IconColor::Unknown => question_pixmap(ICON_SIZE, GREY),
    };
    ksni::Icon {
        width: ICON_SIZE,
        height: ICON_SIZE,
        data,
    }
}

/// The ksni tray object. Mutated only on ksni's service thread (menu
/// callbacks and Handle::update closures both run there), so no locking is
/// needed.
struct MonuxTray {
    view: View,
    /// The control socket that last answered a status poll; menu actions go
    /// here. None when no daemon has answered yet.
    socket: Option<PathBuf>,
    /// Note from the last menu action (an error, or a success confirmation
    /// for Copy diagnostics), shown in the tooltip; cleared by the next
    /// successful command action.
    note: Option<String>,
}

impl MonuxTray {
    fn new() -> Self {
        MonuxTray {
            view: View::not_running(),
            socket: None,
            note: None,
        }
    }

    /// Re-polls the control sockets and swaps in the fresh view.
    fn refresh(&mut self) {
        let (socket, view) = poll();
        self.socket = socket;
        self.view = view;
    }
}

impl ksni::Tray for MonuxTray {
    // There is no window to activate: a left click opens the menu.
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "monux".to_string()
    }

    fn title(&self) -> String {
        "monux".to_string()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![icon_for(self.view.color)]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        let description = match &self.note {
            Some(note) => format!("{}\n{}", self.view.details, note),
            None => self.view.details.clone(),
        };
        ksni::ToolTip {
            icon_name: String::new(),
            icon_pixmap: Vec::new(),
            title: self.view.title.clone(),
            description,
        }
    }

    fn menu(&self) -> Vec<ksni::menu::MenuItem<Self>> {
        to_ksni_menu(menu_rows(&self.view.status))
    }

    fn menu_about_to_show(&mut self) {
        // Fresh state right before the menu renders, even between poll ticks.
        self.refresh();
    }
}

/// Queries server.sock first, then client.sock; the first socket answering
/// with a parseable status wins (a machine usually runs one role, and the
/// server view is the richer one). A socket that ANSWERS without a usable
/// state (ok:false, e.g. "state not available yet") yields the starting
/// view with the socket kept bound — the daemon is alive, just not ready.
/// (None, not-running view) only when no daemon answers at all.
fn poll() -> (Option<PathBuf>, View) {
    for role in [Role::Server, Role::Client] {
        let path = control::socket_path(role);
        if !path.exists() {
            continue;
        }
        let raw = match control::request_line(&path, r#"{"cmd":"status"}"#) {
            Ok(raw) => raw,
            Err(e) => {
                debug!(
                    "Indicator: status from {} failed: {:?}",
                    path.display(),
                    e
                );
                continue;
            }
        };
        // The socket ANSWERED: the daemon is alive, so whatever is wrong
        // with the body must NOT fall through to the launcher view (see
        // DaemonStatus::NoState).
        let state = parse_ok(&raw, &path).and_then(|v| {
            serde_json::from_value::<State>(v["state"].clone())
                .with_context(|| format!("Unrecognized state from {}", path.display()))
        });
        return match state {
            Ok(state) => (Some(path), View::from_state(state)),
            Err(e) => {
                debug!(
                    "Indicator: {} answered without a usable state: {:?}",
                    path.display(),
                    e
                );
                (Some(path.clone()), View::no_state(format!("{:#}", e)))
            }
        };
    }
    (None, View::not_running())
}

/// Validates a response line and returns the parsed body. An `ok:false`
/// response becomes an Err carrying the daemon's error string.
fn parse_ok(raw: &str, socket: &Path) -> Result<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(raw)
        .with_context(|| format!("Malformed response from {}", socket.display()))?;
    if v.get("ok").and_then(|ok| ok.as_bool()) == Some(true) {
        return Ok(v);
    }
    Err(anyhow!(
        "{}",
        v.get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("the daemon reported an error")
    ))
}

/// Sends a command and checks the ack; the daemon's error string propagates.
fn send_command(socket: &Path, request: &str) -> Result<()> {
    let raw = control::request_line(socket, request)?;
    parse_ok(&raw, socket).map(|_| ())
}

fn action_request(action: &MenuAction) -> String {
    match action {
        MenuAction::SwitchLocal => r#"{"cmd":"switch","target":"local"}"#.to_string(),
        MenuAction::SwitchTo(fingerprint) => {
            serde_json::json!({"cmd": "switch", "target": fingerprint}).to_string()
        }
        MenuAction::Pause => r#"{"cmd":"pause"}"#.to_string(),
        MenuAction::Resume => r#"{"cmd":"resume"}"#.to_string(),
        MenuAction::SetLinkNotify(on) => {
            serde_json::json!({"cmd": "link-notify", "action": if *on { "on" } else { "off" }})
                .to_string()
        }
        MenuAction::UpdateNow => r#"{"cmd":"update_now"}"#.to_string(),
        MenuAction::HideTray => r#"{"cmd":"indicator","action":"hide"}"#.to_string(),
        MenuAction::Restart => r#"{"cmd":"restart"}"#.to_string(),
        MenuAction::Exit => r#"{"cmd":"exit"}"#.to_string(),
        MenuAction::CopyDiagnostics => {
            unreachable!("copy diagnostics fetches instead of commanding")
        }
        MenuAction::StartServer | MenuAction::StartClient => {
            unreachable!("start actions are local, never socket commands")
        }
    }
}

/// Whether an acked action ends this process.
///
/// INVARIANT: "Hide tray icon" hides the icon the user clicked on. The
/// daemon's ack does not carry that: `PostAction::IndicatorHide` only parks
/// the supervisor in the hidden state and SIGTERMs the indicator it spawned
/// ITSELF (indicator_spawn.rs: "The supervisor only ever manages ITS spawned
/// child"), which is nobody at all under --no-indicator, after a manually
/// started `monux gui indicator` took the single-instance lock, or once the
/// respawn budget is spent. Waiting to be killed in those cases leaves the
/// icon on screen with the row having reported success, so the indicator
/// takes itself off the tray instead. The daemon's deferred hide() still
/// flips `hidden`, so the exit is not mistaken for a crash and respawned.
fn exits_after_ack(action: &MenuAction) -> bool {
    matches!(action, MenuAction::HideTray)
}

/// Runs one menu action against the bound socket, then re-polls immediately
/// so the icon and menu reflect the effect — including the daemon vanishing
/// after restart/exit, which simply lands on the not-running view until the
/// daemon (re)appears. The not-running menu's actions (start server/client,
/// hide) are LOCAL: there is no daemon to ask. Errors surface in the tooltip
/// AND a transient notification.
fn run_action(tray: &mut MonuxTray, action: &MenuAction) {
    let outcome = match (action, tray.socket.clone()) {
        (MenuAction::StartServer, _) => start_daemon(Role::Server).map(|_| String::new()),
        (MenuAction::StartClient, _) => start_daemon(Role::Client).map(|_| String::new()),
        // Standalone indicator: there is no daemon to ask, so the hide is
        // nothing but this process leaving (below); 'monux gui tray show' /
        // 'monux gui indicator' brings a tray back.
        (MenuAction::HideTray, None) => Ok(String::new()),
        (MenuAction::CopyDiagnostics, Some(socket)) => copy_diagnostics(&socket)
            .map(|tool| format!("Diagnostics copied to the clipboard ({})", tool)),
        (other, Some(socket)) => send_command(&socket, &action_request(other)).map(|_| String::new()),
        (_, None) => Err(anyhow!("monux is not running")),
    };
    match outcome {
        Ok(note) => {
            if exits_after_ack(action) {
                info!("Hiding the tray indicator on request");
                std::process::exit(0);
            }
            if let MenuAction::CopyDiagnostics = action {
                tray.note = Some(note.clone());
                notify::notify(NOTIFY_ID, Urgency::Low, 3000, "monux", &note);
            } else {
                tray.note = None;
            }
        }
        Err(e) => {
            let note = format!("{} failed: {:#}", action.label(), e);
            tray.note = Some(note.clone());
            notify::notify(NOTIFY_ID, Urgency::Normal, 5000, "monux", &note);
        }
    }
    tray.refresh();
}

/// How to start a daemon role from the not-running menu: through the
/// autostart unit when one is installed (systemd then owns restarts and the
/// login lifecycle), otherwise by spawning `monux <role>` detached.
#[derive(Clone, Debug, PartialEq, Eq)]
enum StartHow {
    /// `systemctl --user start <unit file name>` (the unit file exists).
    Systemctl(PathBuf),
    /// A detached `monux <role>` spawn (no unit installed).
    Spawn(Role),
}

/// The start decision, pure over the pre-probed unit path (testable without
/// touching the home dir or systemd).
fn start_decision(unit_path: Option<&Path>, role: Role) -> StartHow {
    match unit_path {
        Some(path) if path.exists() => StartHow::Systemctl(path.to_path_buf()),
        _ => StartHow::Spawn(role),
    }
}

/// The autostart unit path for a role (~/.config/systemd/user/monux-<role>.service,
/// the same path `monux setup --autostart <role>` writes).
fn unit_path(role: Role) -> Option<PathBuf> {
    Some(
        home::home_dir()?
            .join(crate::setup::SYSTEMD_USER_UNIT_DIR)
            .join(crate::setup::unit_name_for(role.as_str())),
    )
}

/// Starts a daemon role from the not-running menu (see start_decision). On
/// success nothing more is done: the daemon appears within seconds and the
/// poll loop transitions to the normal state by itself — and the daemon's
/// own auto-spawned indicator then takes over from this standalone one via
/// the single-instance indicator lock (single_instance.rs, kind "indicator").
fn start_daemon(role: Role) -> Result<()> {
    match start_decision(unit_path(role).as_deref(), role) {
        StartHow::Systemctl(path) => {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("autostart unit path has no usable file name")?;
            info!("Starting monux {} via systemd unit {}", role.as_str(), name);
            start_via_systemctl(name)
        }
        StartHow::Spawn(role) => {
            info!(
                "Starting monux {} detached (no autostart unit installed)",
                role.as_str()
            );
            spawn_daemon(role)
        }
    }
}

/// `systemctl --user start <unit>` — starts the autostart-installed daemon.
/// The stderr text propagates on failure (no user manager, unit failed to
/// start) so the tray notification says something useful.
fn start_via_systemctl(unit_name: &str) -> Result<()> {
    let output = Command::new("systemctl")
        .args(["--user", "start", unit_name])
        .stdin(Stdio::null())
        .output()
        .context("failed to run systemctl")?;
    if !output.status.success() {
        bail!(
            "systemctl --user start {}: {}",
            unit_name,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// A daemon that dies within this long of being spawned never got past
/// startup — no uinput/evdev permissions, the port already bound, a config
/// it refused. Anything later is the daemon's own lifecycle and none of the
/// launcher's business to report.
const DAEMON_STARTUP_GRACE: Duration = Duration::from_secs(3);

/// What to tell the user about a spawned daemon that exited, or None when
/// the exit is not a failed start. A clean exit never is: the started daemon
/// spawns its own indicator, which takes the single-instance lock and
/// SIGTERMs this standalone one, so this thread usually dies with us long
/// before the daemon does.
fn startup_failure_note(
    role: Role,
    status: &std::process::ExitStatus,
    uptime: Duration,
) -> Option<String> {
    if status.success() || uptime >= DAEMON_STARTUP_GRACE {
        return None;
    }
    Some(format!(
        "monux {} exited immediately ({}) — run 'monux {}' in a terminal to see why",
        role.as_str(),
        status,
        role.as_str()
    ))
}

/// Spawns `monux <role>` detached: our own binary re-run as the daemon,
/// stdin null and output dropped (the daemon outlives this indicator, so it
/// must not hold our stdio handles open). Unsupervised: the indicator is not
/// a service manager, the daemon keeps running after we exit.
fn spawn_daemon(role: Role) -> Result<()> {
    let mut child = Command::new(crate::indicator_spawn::own_exe()?)
        .arg(role.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn monux {}", role.as_str()))?;
    // Wait off-thread: the menu callback has to return at once, but a child
    // nobody waits on stays a zombie for the lifetime of this indicator, and
    // the indicator polls forever (notify.rs reaps notify-send for the same
    // reason). The wait is also the only account we can give of a start that
    // failed — spawn() succeeding says nothing about the daemon coming up,
    // and by the time the truth is known run_action has long since cleared
    // its note, so an immediate death is reported as a notification.
    let started = std::time::Instant::now();
    std::thread::spawn(move || {
        let Ok(status) = child.wait() else { return };
        if let Some(note) = startup_failure_note(role, &status, started.elapsed()) {
            warn!("{}", note);
            notify::notify(NOTIFY_ID, Urgency::Normal, 5000, "monux", &note);
        }
    });
    Ok(())
}

/// Fetches the diagnostics bundle from the daemon and copies it to the
/// desktop clipboard; returns the clipboard tool that worked.
///
/// Formats as markdown, matching `monux diagnostics --copy`: a bundle taken
/// via "Copy diagnostics" is on its way to an issue tracker, so it leaves
/// here issue-ready. Everything else — collection, journal, rendering — is
/// the shared path in diagnostics.rs, so a tray report and a CLI report are
/// the same report.
fn copy_diagnostics(socket: &Path) -> Result<&'static str> {
    let request = serde_json::json!({
        "cmd": "diagnostics",
        "lines": diagnostics::TRAY_LOG_LINES,
    })
    .to_string();
    let raw = control::request_line(socket, &request)?;
    let v = parse_ok(&raw, socket)?;
    let d: Diagnostics = serde_json::from_value(v["diagnostics"].clone())
        .context("The daemon returned no diagnostics")?;
    let role = control::Role::parse(&d.role)
        .with_context(|| format!("Unknown daemon role '{}'", d.role))?;
    let journal = diagnostics::journal_capture(role, diagnostics::DEFAULT_JOURNAL_SINCE);
    let bundle = diagnostics::Bundle {
        diagnostics: d,
        journal,
        peers: Vec::new(),
    };
    let text = diagnostics::format_bundle(
        &bundle,
        diagnostics::FormatOptions {
            format: diagnostics::Format::Markdown,
            redact: false,
        },
    )?;
    diagnostics::copy_to_clipboard(&text)
}

/// Runs the indicator until the tray service shuts down. With no D-Bus
/// session bus or no StatusNotifierItem host (headless TTY), fails with a
/// clean error — main turns that into exit code 1. A missing monux daemon is
/// NOT an error: the indicator shows the "?" state and keeps polling.
pub fn run() -> Result<()> {
    let handle = match MonuxTray::new().spawn() {
        Ok(handle) => handle,
        Err(e) => bail!(
            "no D-Bus session / no tray host: {} — the indicator needs a desktop session running a StatusNotifierItem host (waybar, KDE Plasma, ...)",
            e
        ),
    };
    info!("Tray indicator running (polling every {:?})", POLL_INTERVAL);
    loop {
        // update() returns None once the tray service has shut down.
        if handle.update(|tray| tray.refresh()).is_none() {
            info!("Tray service shut down, exiting the indicator");
            return Ok(());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{ClientState, ServerClientState, ServerClipboardState};

    fn server_state(paused: bool, target: &str, clients: Vec<(&str, Option<u64>)>) -> State {
        State::Server(ServerState {
            version: "1.5.0".to_string(),
            protocol_version: 8,
            listen: "10.0.0.1:1213".to_string(),
            paused,
            current_target: target.to_string(),
            clients: clients
                .into_iter()
                .map(|(addr, rtt_ms)| ServerClientState {
                    addr: addr.to_string(),
                    fingerprint: format!("fp-{}", addr),
                    connected_since_secs: 42,
                    rtt_ms,
                    edge: None,
                })
                .collect(),
            clipboard: ServerClipboardState {
                owner: "none".to_string(),
                types: vec![],
            },
            update_available: None,
        })
    }

    fn client_state(connected: bool, active: bool) -> State {
        State::Client(ClientState {
            version: "1.5.0".to_string(),
            protocol_version: 8,
            server: "10.0.0.1:1213".to_string(),
            connected,
            active,
            connected_since_secs: if connected { Some(42) } else { None },
            rtt_ms: if connected { Some(3) } else { None },
            lost_packets: if connected { Some(0) } else { None },
            link_notify: false,
        })
    }

    #[test]
    fn server_color_mapping() {
        // Healthy, input local: green.
        let state = server_state(false, "local", vec![("10.0.0.2:1213", Some(3))]);
        assert_eq!(color_of(&state), IconColor::Green);
        assert_eq!(title_of(&state), "monux: input local");
        // Input on a client: blue.
        let state = server_state(false, "10.0.0.2:1213", vec![("10.0.0.2:1213", Some(3))]);
        assert_eq!(color_of(&state), IconColor::Blue);
        assert_eq!(title_of(&state), "monux: input on 10.0.0.2:1213");
        // Paused: grey.
        let state = server_state(true, "local", vec![]);
        assert_eq!(color_of(&state), IconColor::Grey);
        assert_eq!(title_of(&state), "monux: paused");
        // A client over the degradation threshold: red — even while paused
        // (problems outrank the deliberate paused state).
        let state = server_state(false, "local", vec![("10.0.0.2:1213", Some(120))]);
        assert_eq!(color_of(&state), IconColor::Red);
        assert_eq!(title_of(&state), "monux: degraded — 10.0.0.2:1213 rtt 120ms");
        let state = server_state(true, "local", vec![("10.0.0.2:1213", Some(120))]);
        assert_eq!(color_of(&state), IconColor::Red);
        // Exactly at the threshold is NOT degraded; an unknown rtt is ignored.
        let state = server_state(false, "local", vec![("10.0.0.2:1213", Some(50))]);
        assert_eq!(color_of(&state), IconColor::Green);
        let state = server_state(false, "local", vec![("10.0.0.2:1213", None)]);
        assert_eq!(color_of(&state), IconColor::Green);
    }

    #[test]
    fn client_color_mapping() {
        // Connected but not owning input: green; owning: blue; disconnected
        // (with a known server address): red.
        let state = client_state(true, false);
        assert_eq!(color_of(&state), IconColor::Green);
        assert_eq!(title_of(&state), "monux: connected to 10.0.0.1:1213");
        let state = client_state(true, true);
        assert_eq!(color_of(&state), IconColor::Blue);
        assert_eq!(title_of(&state), "monux: input here (server 10.0.0.1:1213)");
        let state = client_state(false, false);
        assert_eq!(color_of(&state), IconColor::Red);
        assert_eq!(title_of(&state), "monux: not connected to 10.0.0.1:1213");
    }

    #[test]
    fn tooltip_details_carry_connection_facts() {
        let state = server_state(
            false,
            "10.0.0.2:1213",
            vec![("10.0.0.2:1213", Some(3)), ("10.0.0.3:1213", None)],
        );
        let details = details_of(&state);
        assert!(details.contains("server v1.5.0 (protocol 8), listening 10.0.0.1:1213"));
        assert!(details.contains("10.0.0.2:1213 — rtt 3ms, up 42s"));
        assert!(details.contains("10.0.0.3:1213 — rtt ?, up 42s"));
        assert!(details.contains("clipboard: none"));

        let details = details_of(&client_state(true, false));
        assert!(details.contains("client v1.5.0 (protocol 8)"));
        assert!(details.contains("rtt 3ms, up 42s, 0 packets lost"));
    }

    #[test]
    fn menu_for_a_server_with_local_input() {
        let state = server_state(
            false,
            "local",
            vec![("10.0.0.2:1213", Some(3)), ("10.0.0.3:1213", Some(7))],
        );
        let rows = menu_rows(&DaemonStatus::Up(state));
        // Header row names the current input owner.
        assert!(rows.contains(&MenuRow::Label("Input: local".to_string())));
        // Local input: no "Switch to local", one switch row per client
        // carrying the full fingerprint as the target.
        assert!(!rows
            .iter()
            .any(|r| matches!(r, MenuRow::Action { action: MenuAction::SwitchLocal, .. })));
        assert!(rows.contains(&action_row(
            "Switch to 10.0.0.2:1213",
            MenuAction::SwitchTo("fp-10.0.0.2:1213".to_string()),
            true
        )));
        assert!(rows.contains(&action_row(
            "Switch to 10.0.0.3:1213",
            MenuAction::SwitchTo("fp-10.0.0.3:1213".to_string()),
            true
        )));
        // Not paused: the Pause action is offered.
        assert!(rows.contains(&action_row("Pause", MenuAction::Pause, true)));
        // Per-client connection rows and the clipboard row are disabled labels.
        assert!(rows.contains(&MenuRow::Label(
            "Connection: 10.0.0.2:1213 — rtt 3ms, up 42s".to_string()
        )));
        assert!(rows.contains(&MenuRow::Label("Clipboard: none".to_string())));
        // No update pending: plain manual check.
        assert!(rows.contains(&action_row("Check for update now", MenuAction::UpdateNow, true)));
        assert!(rows.contains(&action_row("Copy diagnostics", MenuAction::CopyDiagnostics, true)));
        assert!(rows.contains(&action_row("Hide tray icon", MenuAction::HideTray, true)));
        assert!(rows.contains(&action_row("Restart monux", MenuAction::Restart, true)));
        assert!(rows.contains(&action_row("Exit monux", MenuAction::Exit, true)));
    }

    #[test]
    fn menu_for_a_server_with_remote_input_pause_and_update() {
        let mut state = server_state(
            true,
            "10.0.0.2:1213",
            vec![("10.0.0.2:1213", Some(3)), ("10.0.0.3:1213", Some(7))],
        );
        if let State::Server(s) = &mut state {
            s.clipboard.owner = "local".to_string();
            s.clipboard.types = vec!["text/plain".to_string()];
            s.update_available = Some("abc123".to_string());
        }
        let rows = menu_rows(&DaemonStatus::Up(state));
        assert!(rows.contains(&MenuRow::Label("Input: 10.0.0.2:1213".to_string())));
        // Remote input: switching back to local is listed...
        assert!(rows.contains(&action_row("Switch to local", MenuAction::SwitchLocal, false)));
        // ...but the client already owning input has no switch row...
        assert!(!rows
            .iter()
            .any(|r| matches!(r, MenuRow::Action { label, .. } if label == "Switch to 10.0.0.2:1213")));
        // ...and while paused every switch row is DISABLED (rotation drops
        // switches then; a clickable row would silently do nothing)...
        assert!(rows.contains(&action_row(
            "Switch to 10.0.0.3:1213",
            MenuAction::SwitchTo("fp-10.0.0.3:1213".to_string()),
            false
        )));
        // ...while the Resume row stays enabled.
        assert!(rows.contains(&action_row("Resume", MenuAction::Resume, true)));
        assert!(rows
            .iter()
            .all(|r| !matches!(r, MenuRow::Action { action: MenuAction::SwitchLocal | MenuAction::SwitchTo(_), enabled: true, .. })));
        // Update pending: the sha is in the label.
        assert!(rows.contains(&action_row(
            "Update available: abc123 — update now",
            MenuAction::UpdateNow,
            true
        )));
        assert!(rows.contains(&MenuRow::Label(
            "Clipboard: local (text/plain)".to_string()
        )));
        // Unpausing re-enables the switch rows.
        let state = server_state(
            false,
            "10.0.0.2:1213",
            vec![("10.0.0.2:1213", Some(3)), ("10.0.0.3:1213", Some(7))],
        );
        let rows = menu_rows(&DaemonStatus::Up(state));
        assert!(rows.contains(&action_row("Switch to local", MenuAction::SwitchLocal, true)));
        assert!(rows.contains(&action_row(
            "Switch to 10.0.0.3:1213",
            MenuAction::SwitchTo("fp-10.0.0.3:1213".to_string()),
            true
        )));
    }

    /// Builds an Action menu row concisely for the assertions.
    fn action_row(label: &str, action: MenuAction, enabled: bool) -> MenuRow {
        MenuRow::Action {
            label: label.to_string(),
            action,
            enabled,
        }
    }

    #[test]
    fn menu_for_a_client_has_no_server_only_actions() {
        let rows = menu_rows(&DaemonStatus::Up(client_state(true, true)));
        assert!(rows.contains(&MenuRow::Label("Server: 10.0.0.1:1213".to_string())));
        assert!(rows.contains(&MenuRow::Label("Connection: rtt 3ms, up 42s".to_string())));
        assert!(rows.contains(&MenuRow::Label("Input: here".to_string())));
        // Rotation and pause are server concepts: absent on the client menu.
        for row in &rows {
            if let MenuRow::Action { action, enabled, .. } = row {
                assert!(matches!(
                    action,
                    MenuAction::SetLinkNotify(_)
                        | MenuAction::UpdateNow
                        | MenuAction::CopyDiagnostics
                        | MenuAction::HideTray
                        | MenuAction::Restart
                        | MenuAction::Exit
                ));
                assert!(enabled);
            }
        }
        // A disconnected client still gets the lifecycle actions.
        let rows = menu_rows(&DaemonStatus::Up(client_state(false, false)));
        assert!(rows.contains(&MenuRow::Label("Connection: not connected".to_string())));
        assert!(rows.contains(&MenuRow::Label("Input: server".to_string())));
    }

    #[test]
    fn client_menu_toggle_tracks_the_link_notify_state() {
        // Off (the default, and what an older daemon's state parses as): the
        // row offers to turn notifications ON.
        let rows = menu_rows(&DaemonStatus::Up(client_state(true, true)));
        assert!(rows.contains(&action_row(
            "Link notifications: off — turn on",
            MenuAction::SetLinkNotify(true),
            true
        )));
        // On: the row offers to turn them back off.
        let State::Client(mut state) = client_state(true, true) else {
            panic!("client_state builds a client state")
        };
        state.link_notify = true;
        let rows = menu_rows(&DaemonStatus::Up(State::Client(state)));
        assert!(rows.contains(&action_row(
            "Link notifications: on — turn off",
            MenuAction::SetLinkNotify(false),
            true
        )));
        // The wire request names the target state.
        assert_eq!(
            action_request(&MenuAction::SetLinkNotify(true)),
            r#"{"action":"on","cmd":"link-notify"}"#
        );
        assert_eq!(
            action_request(&MenuAction::SetLinkNotify(false)),
            r#"{"action":"off","cmd":"link-notify"}"#
        );
    }

    #[test]
    fn menu_without_a_daemon_offers_start_actions_and_hide() {
        let rows = menu_rows(&DaemonStatus::Silent);
        assert_eq!(
            rows,
            vec![
                MenuRow::Label("monux is not running".to_string()),
                MenuRow::Separator,
                action_row("Start server", MenuAction::StartServer, true),
                action_row("Start client", MenuAction::StartClient, true),
                MenuRow::Separator,
                action_row("Hide tray", MenuAction::HideTray, true),
            ]
        );
    }

    #[test]
    fn a_daemon_that_answered_without_state_gets_no_launcher_rows() {
        // The socket ANSWERED (ok:false — e.g. "state not available yet
        // (rotation loop has not run)"): the daemon is alive, so offering
        // "Start server" would spawn a second daemon whose single-instance
        // takeover SIGTERMs the one that just answered.
        let rows = menu_rows(&DaemonStatus::NoState(
            "state not available yet (rotation loop has not run)".to_string(),
        ));
        assert_eq!(
            rows,
            vec![
                MenuRow::Label("monux is starting".to_string()),
                MenuRow::Label(
                    "state not available yet (rotation loop has not run)".to_string()
                ),
                MenuRow::Separator,
                action_row("Hide tray icon", MenuAction::HideTray, true),
            ]
        );
    }

    #[test]
    fn start_decision_prefers_the_unit_when_installed() {
        let tmp = tempfile::tempdir().unwrap();
        let unit = tmp.path().join("monux-server.service");
        std::fs::write(&unit, "[Unit]\n").unwrap();
        // Unit file present: systemd starts the daemon.
        assert_eq!(
            start_decision(Some(&unit), Role::Server),
            StartHow::Systemctl(unit.clone())
        );
        // Unit file absent (or the home dir unresolvable): detached spawn.
        let missing = tmp.path().join("monux-client.service");
        assert_eq!(
            start_decision(Some(&missing), Role::Client),
            StartHow::Spawn(Role::Client)
        );
        assert_eq!(start_decision(None, Role::Server), StartHow::Spawn(Role::Server));
    }

    #[test]
    fn hiding_the_tray_ends_this_process_daemon_or_not() {
        // The daemon acks a hide it may have nothing to enforce with: it only
        // SIGTERMs the indicator it spawned itself, which is nobody under
        // --no-indicator or after a manual 'monux gui indicator' took over.
        // The row is only honest if this process leaves either way.
        assert!(exits_after_ack(&MenuAction::HideTray));
        // Every other action leaves the indicator on the tray to show the
        // effect it just had.
        for action in [
            MenuAction::SwitchLocal,
            MenuAction::SwitchTo("fp".to_string()),
            MenuAction::Pause,
            MenuAction::Resume,
            MenuAction::UpdateNow,
            MenuAction::CopyDiagnostics,
            MenuAction::StartServer,
            MenuAction::StartClient,
            MenuAction::Restart,
            MenuAction::Exit,
        ] {
            assert!(!exits_after_ack(&action), "{:?} must not exit", action);
        }
    }

    #[test]
    fn a_daemon_that_dies_at_once_is_reported_a_later_exit_is_not() {
        use std::os::unix::process::ExitStatusExt;
        let failed = std::process::ExitStatus::from_raw(1 << 8);
        let note = startup_failure_note(Role::Server, &failed, Duration::from_millis(50)).unwrap();
        assert!(note.contains("monux server exited immediately"), "{}", note);
        // Past the grace the daemon had started; its exit is its own story.
        assert_eq!(
            startup_failure_note(Role::Server, &failed, DAEMON_STARTUP_GRACE),
            None
        );
        // A clean exit is never a failed start — it is what the takeover by
        // the daemon's own indicator looks like.
        let clean = std::process::ExitStatus::from_raw(0);
        assert_eq!(
            startup_failure_note(Role::Client, &clean, Duration::from_millis(50)),
            None
        );
    }

    #[test]
    fn dot_pixmap_draws_a_filled_circle() {
        let data = dot_pixmap(ICON_SIZE, GREEN);
        assert_eq!(data.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        // The center pixel is opaque green (A, R, G, B order).
        let center = ((ICON_SIZE / 2) * ICON_SIZE + ICON_SIZE / 2) as usize * 4;
        assert_eq!(&data[center..center + 4], &[0xff, 0x2e, 0xcc, 0x40]);
        // The corners are fully transparent (2px margin around the dot).
        for px in corner_pixels(&data) {
            assert_eq!(px, &[0, 0, 0, 0]);
        }
    }

    /// The four corner pixels of a square ARGB pixmap.
    fn corner_pixels(data: &[u8]) -> [&[u8]; 4] {
        let size = ICON_SIZE as usize;
        [
            &data[0..4],
            &data[(size - 1) * 4..size * 4],
            &data[(size * (size - 1)) * 4..(size * (size - 1) + 1) * 4],
            &data[(size * size - 1) * 4..size * size * 4],
        ]
    }

    #[test]
    fn question_pixmap_is_a_sparse_grey_glyph() {
        let data = question_pixmap(ICON_SIZE, GREY);
        assert_eq!(data.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        let mut opaque = 0usize;
        for px in data.chunks(4) {
            if px[3] != 0 {
                opaque += 1;
                // Every drawn pixel is opaque grey.
                assert_eq!(px, &[0xff, 0x96, 0x96, 0x96]);
            } else {
                assert_eq!(px, &[0, 0, 0, 0]);
            }
        }
        // The glyph is sparse (a "?", not a filled dot) but visible.
        assert!(opaque > 20, "glyph too small: {}", opaque);
        assert!(opaque < (ICON_SIZE * ICON_SIZE) as usize / 4, "glyph too dense");
        // Corners stay transparent.
        assert_eq!(data[0], 0);
    }

    // Bundle formatting and the clipboard plumbing moved to diagnostics.rs,
    // which the CLI shares; their tests moved with them.
}
