//! `monux gui indicator` on macOS — a native menu-bar (NSStatusItem) tray,
//! the AppKit counterpart of the Linux D-Bus indicator (indicator.rs).
//!
//! It is the same THIN CLIENT of the control socket: the entire model layer
//! is shared — `indicator::poll()` queries server.sock/client.sock, and
//! `indicator::menu_rows()` builds the menu for whatever the poll returned.
//! This module only swaps the renderer: a colored dot (or grey "?") as the
//! status item glyph, and the menu model mapped onto NSMenuItems.
//!
//! Threading: AppKit UI is main-thread-only. The poll runs on a background
//! thread and posts `(view, socket)` updates to the main dispatch queue;
//! menu clicks run on the main thread (AppKit's action dispatch) and hand
//! the actual control-socket work to a short-lived background thread, so a
//! slow or wedged daemon never freezes the UI — the outcome lands in the
//! shared `note` and the next poll surfaces it as the menu's first row (and
//! in the tooltip). All UI objects live in a main-thread-only `thread_local`
//! slot; nothing else touches them.
//!
//! The not-running view doubles as a launcher, like on Linux: "Start
//! client" bootstraps the `setup --autostart` LaunchAgent when one is
//! installed (launchd then owns restarts and the login lifecycle),
//! otherwise it spawns `monux <role>` detached. The server rows are
//! unreachable on a macOS build (no server exists here), but the model
//! renders them all the same if one ever answers.

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};

use anyhow::{Context, Result};
use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::runtime::NSObject;
use objc2::{define_class, msg_send, MainThreadOnly, MainThreadMarker, sel};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSColor, NSMenu, NSMenuItem, NSStatusBar,
    NSStatusItem,
};
use objc2_foundation::NSString;
use tracing::{debug, info, warn};

use crate::control;
use crate::indicator::{
    action_request, menu_rows, parse_ok, poll, send_command, MenuAction, MenuRow, View, BLUE,
    GREEN, GREY, POLL_INTERVAL, RED,
};
use crate::indicator::IconColor;
use crate::indicator::NOTIFY_ID;

/// How long a "Start client" launcher spawn is given before its death is
/// reported as a failed start rather than the daemon's own lifecycle (same
/// rationale as the Linux indicator).
const DAEMON_STARTUP_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// State shared between the poll thread, the action threads and the main
/// thread. Everything is plain data (Send), so it crosses threads freely;
/// the UI itself never leaves the main thread.
struct Shared {
    /// Outcome of the last menu action (error, or the "diagnostics copied"
    /// confirmation), shown as the menu's first row and in the tooltip;
    /// cleared by the next successful command action. Mirrors the Linux
    /// tray's `note`.
    note: Mutex<Option<String>>,
    /// Signals the poll thread to re-poll immediately (after a menu action)
    /// instead of waiting out POLL_INTERVAL.
    poke: (Mutex<bool>, Condvar),
}

impl Shared {
    fn new() -> Arc<Shared> {
        Arc::new(Shared {
            note: Mutex::new(None),
            poke: (Mutex::new(false), Condvar::new()),
        })
    }

    fn poke(&self) {
        let mut poked = self.poke.0.lock().unwrap();
        *poked = true;
        self.poke.1.notify_one();
    }

    /// Waits for a poke or POLL_INTERVAL; true when poked.
    fn wait(&self) -> bool {
        let poked = self.poke.0.lock().unwrap();
        let (mut poked, _) = self
            .poke
            .1
            .wait_timeout_while(poked, POLL_INTERVAL, |poked| !*poked)
            .unwrap();
        // wait_timeout_while hands back the guard still holding the mutex:
        // reset the flag THROUGH it. Locking the mutex again here (instead of
        // using the guard) self-deadlocks — a plain std Mutex is not
        // reentrant, and the poll thread then never polls at all.
        let was_poked = *poked;
        *poked = false;
        was_poked
    }
}

/// The main-thread-only UI bundle. AppKit objects are neither Send nor Sync,
/// so they live in a thread_local slot that only main-thread code (the setup
/// in run(), the dispatch-queue closures and the menu action handler) reads.
struct Ui {
    item: Retained<NSStatusItem>,
    menu: Retained<NSMenu>,
    target: Retained<TrayTarget>,
    /// The control socket that last answered a status poll; menu actions go
    /// here (None: the launcher view).
    socket: Option<PathBuf>,
    shared: Arc<Shared>,
}

thread_local! {
    static UI: std::cell::RefCell<Option<Ui>> = const { std::cell::RefCell::new(None) };
}

// The menu action target: every actionable NSMenuItem points at this object
// with `monuxMenuAction:` and carries its tag (the control request JSON, or
// a `local:...` marker for actions that never touch the socket) as its
// representedObject. Main-thread-only: AppKit invokes the action there, and
// that is also the only place the thread_local UI bundle is touched.
define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "MonuxTrayTarget"]
    struct TrayTarget;

    impl TrayTarget {
        #[unsafe(method(monuxMenuAction:))]
        fn monux_menu_action(&self, sender: &NSMenuItem) {
            info!("Tray: menu action fired");
            let object = sender.representedObject();
            let tag = object
                .as_ref()
                .and_then(|object| object.clone().downcast::<NSString>().ok())
                .and_then(|string| tag_from_nsstring(&string));
            let Some(tag) = tag else {
                return;
            };
            UI.with_borrow(|ui| {
                let Some(ui) = ui.as_ref() else {
                    return;
                };
                let socket = ui.socket.clone();
                let shared = ui.shared.clone();
                // Never block AppKit's dispatch on a possibly wedged daemon:
                // the control-socket work runs off-thread, and its outcome
                // lands back in the shared note (surfaced by the next poll).
                std::thread::spawn(move || run_action(&socket, &tag, &shared));
            });
        }
    }
);

impl TrayTarget {
    fn new(mtm: MainThreadMarker) -> Retained<TrayTarget> {
        unsafe { msg_send![TrayTarget::alloc(mtm), init] }
    }
}

/// The action tag carried in a menu item's representedObject.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tag {
    /// Send this JSON request over the control socket; the label names the
    /// action in error notes.
    Socket(String, &'static str),
    /// Start a daemon role (LaunchAgent bootstrap or detached spawn).
    Start(control::Role),
    /// Fetch diagnostics and copy them to the clipboard.
    CopyDiagnostics,
    /// Hide the tray (with a daemon: ask, then leave; standalone: leave).
    Hide,
}

fn tag_for(action: &MenuAction) -> Tag {
    match action {
        MenuAction::StartServer => Tag::Start(control::Role::Server),
        MenuAction::StartClient => Tag::Start(control::Role::Client),
        MenuAction::CopyDiagnostics => Tag::CopyDiagnostics,
        MenuAction::HideTray => Tag::Hide,
        // Everything else is a socket command; action_request renders it.
        // The unreachable arms (start/copy actions) are matched above, so
        // the render cannot panic.
        other => Tag::Socket(action_request(other), other.label()),
    }
}

fn tag_from_nsstring(string: &NSString) -> Option<Tag> {
    let raw = string.to_string();
    Some(match raw.as_str() {
        "local:copy-diagnostics" => Tag::CopyDiagnostics,
        "local:hide" => Tag::Hide,
        other if other.starts_with("local:start:") => match &other["local:start:".len()..] {
            "server" => Tag::Start(control::Role::Server),
            "client" => Tag::Start(control::Role::Client),
            _ => return None,
        },
        // A raw request carries no label (it is not decodable back to an
        // action); the note then names the failure by its payload alone.
        request => Tag::Socket(request.to_string(), "command"),
    })
}

/// Maps the model's icon color to the status item glyph: a colored dot, or
/// the grey "?" for the unknown state (the Linux tray's pixmap, rendered in
/// tinted text because a status item wants no image assets).
fn glyph_for(color: IconColor) -> (&'static str, (u8, u8, u8)) {
    match color {
        IconColor::Green => ("●", GREEN),
        IconColor::Blue => ("●", BLUE),
        IconColor::Grey => ("●", GREY),
        IconColor::Red => ("●", RED),
        IconColor::Unknown => ("?", GREY),
    }
}

/// Applies a fresh poll to the status item (main thread only).
fn apply_view(ui: &Ui, view: &View, note: &Option<String>, mtm: MainThreadMarker) {
    let Some(button) = ui.item.button(mtm) else {
        warn!("Tray: the status item lost its button");
        return;
    };
    let (glyph, (r, g, b)) = glyph_for(view.color);
    button.setTitle(&NSString::from_str(glyph));
    let color = NSColor::colorWithRed_green_blue_alpha(
        f64::from(r) / 255.0,
        f64::from(g) / 255.0,
        f64::from(b) / 255.0,
        1.0,
    );
    button.setContentTintColor(Some(&color));
    // Status items have no rich tooltip; the details go there anyway
    // (they also surface as the menu's label rows, which is the
    // discoverable place).
    let tooltip = match note {
        Some(note) => format!("{}\n{}\n—\n{}", view.title, view.details, note),
        None => format!("{}\n{}", view.title, view.details),
    };
    button.setToolTip(Some(&NSString::from_str(&tooltip)));
    rebuild_menu(ui, view, note, mtm);
}

/// Rebuilds the NSMenu from the shared menu model. The menu is replaced
/// wholesale on every poll; an open menu keeps its snapshot until reopened,
/// and the poll thread's poke-on-action keeps clicks refreshing promptly.
fn rebuild_menu(ui: &Ui, view: &View, note: &Option<String>, mtm: MainThreadMarker) {
    {
        ui.menu.removeAllItems();
        // The last action's outcome leads the menu: it is the only feedback
        // a tray click gets (no notification center call needed).
        if let Some(note) = note {
            let item = unsafe { new_menu_item(&format!("⚠ {note}"), None, mtm) };
            item.setEnabled(false);
            ui.menu.addItem(&item);
        }
        for row in menu_rows(&view.status) {
            match row {
                MenuRow::Separator => {
                    ui.menu.addItem(&NSMenuItem::separatorItem(mtm));
                }
                MenuRow::Label(label) => {
                    let item = unsafe { new_menu_item(&label, None, mtm) };
                    item.setEnabled(false);
                    ui.menu.addItem(&item);
                }
                MenuRow::Action {
                    label,
                    action,
                    enabled,
                } => {
                    let item = unsafe {
                        new_menu_item(
                            &label,
                            Some((sel!(monuxMenuAction:), &ui.target, tag_for(&action))),
                            mtm,
                        )
                    };
                    item.setEnabled(enabled);
                    ui.menu.addItem(&item);
                }
            }
        }
    }
}

/// A fresh NSMenuItem: title, and optionally the action/target/tag triple
/// (None: a passive row, to be disabled by the caller).
unsafe fn new_menu_item(
    title: &str,
    action: Option<(objc2::runtime::Sel, &TrayTarget, Tag)>,
    mtm: MainThreadMarker,
) -> Retained<NSMenuItem> {
    let title = NSString::from_str(title);
    match action {
        None => NSMenuItem::initWithTitle_action_keyEquivalent(
            NSMenuItem::alloc(mtm),
            &title,
            None,
            &NSString::from_str(""),
        ),
        Some((selector, target, tag)) => {
            let item = NSMenuItem::initWithTitle_action_keyEquivalent(
                NSMenuItem::alloc(mtm),
                &title,
                Some(selector),
                &NSString::from_str(""),
            );
            item.setTarget(Some(target.as_ref()));
            let tag_string = tag_to_nsstring(&tag);
            item.setRepresentedObject(Some(tag_string.as_ref()));
            item
        }
    }
}

fn tag_to_nsstring(tag: &Tag) -> Retained<NSString> {
    match tag {
        Tag::Socket(request, _label) => NSString::from_str(request),
        Tag::Start(role) => NSString::from_str(&format!("local:start:{}", role.as_str())),
        Tag::CopyDiagnostics => NSString::from_str("local:copy-diagnostics"),
        Tag::Hide => NSString::from_str("local:hide"),
    }
}

/// Runs one menu action to completion (background thread). The outcome lands
/// in `shared.note` and a poke triggers an immediate re-poll, so the menu
/// and glyph reflect the effect — including the daemon vanishing after
/// restart/exit, which simply lands on the not-running view.
fn run_action(socket: &Option<PathBuf>, tag: &Tag, shared: &Shared) {
    info!("Tray: running action {:?}", tag);
    let outcome = match tag {
        Tag::Start(role) => start_daemon(*role).map(|_| String::new()),
        Tag::CopyDiagnostics => match socket {
            Some(socket) => copy_diagnostics(socket),
            None => Err(anyhow::anyhow!("monux is not running")),
        },
        Tag::Hide => {
            // The daemon's ack does not carry the hide to THIS process (it
            // only parks the supervisor's own spawned child, which is nobody
            // here — see exits_after_ack), so the indicator always takes
            // itself off the tray; with a daemon it asks first so no
            // auto-respawn follows.
            if let Some(socket) = socket {
                if let Err(e) = send_command(socket, &action_request(&MenuAction::HideTray)) {
                    warn!("Tray: the daemon did not ack the hide: {:#}", e);
                }
            }
            info!("Tray: hiding the indicator on request");
            std::process::exit(0);
        }
        Tag::Socket(request, label) => match socket {
            Some(socket) => send_command(socket, request).map(|_| String::new()),
            None => Err(anyhow::anyhow!("monux is not running")),
        }
        .map_err(|e| anyhow::anyhow!("{label} failed: {:#}", e)),
    };
    let mut note = shared.note.lock().unwrap();
    *note = match outcome {
        Ok(text) if text.is_empty() => None,
        Ok(text) => Some(text),
        Err(e) => Some(format!("{e:#}")),
    };
    drop(note);
    shared.poke();
}

/// How to start a daemon role from the not-running menu: bootstrap the
/// `setup --autostart` LaunchAgent when its plist is installed (launchd then
/// owns restarts and the login lifecycle), otherwise spawn `monux <role>`
/// detached — the macOS mirror of the Linux systemctl-or-spawn decision.
fn start_daemon(role: control::Role) -> Result<()> {
    // The setup layer carries its own Role type.
    let setup_role = match role {
        control::Role::Server => crate::setup::Role::Server,
        control::Role::Client => crate::setup::Role::Client,
    };
    let home = home::home_dir().context("no home dir found")?;
    let plist = crate::setup_macos::agents_dir(&home).join(crate::setup_macos::plist_name_for(setup_role));
    if plist.exists() {
        let lc = crate::setup_macos::Launchctl {
            uid: unsafe { libc::getuid() },
        };
        let job = lc.service_target(setup_role);
        // Bootstrapped and running: nothing to do. Bootstrapped but idle
        // (crashed into launchd's throttle, kicked off): kickstart. Not
        // bootstrapped at all: bootstrap, which starts it (RunAtLoad).
        let state = lc
            .spec(&["print", &job])
            .probe()
            .ok()
            .filter(|out| !out.trim().is_empty())
            .map(|out| crate::setup_macos::parse_print(&out));
        match state {
            Some((Some(state), _)) if state == "running" => return Ok(()),
            Some(_) => {
                return lc
                    .spec(&["kickstart", "-k", &job])
                    .run()
                    .with_context(|| format!("failed to kickstart {job}"));
            }
            None => {
                return lc
                    .spec(&["bootstrap", &lc.domain(), &plist.display().to_string()])
                    .run()
                    .with_context(|| format!("failed to bootstrap {job}"))
            }
        }
    }
    spawn_detached(role)
}

/// Spawns `monux <role>` detached: our own binary re-run as the daemon,
/// output dropped so it never holds our stdio handles open. Reaped
/// off-thread (a child nobody waits on stays a zombie for this indicator's
/// lifetime); a death inside DAEMON_STARTUP_GRACE is reported as a failure
/// note, anything later is the daemon's own lifecycle.
fn spawn_detached(role: control::Role) -> Result<()> {
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().context("cannot resolve our own binary")?;
    let mut child = Command::new(exe)
        .arg(role.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn monux {}", role.as_str()))?;
    let reaper = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let status = child.wait();
        (status, started.elapsed())
    });
    std::thread::spawn(move || {
        let Ok((Ok(status), uptime)) = reaper.join() else {
            return;
        };
        if status.success() || uptime >= DAEMON_STARTUP_GRACE {
            return;
        }
        let note = format!(
            "monux {} exited immediately ({}) — run 'monux {}' in a terminal to see why",
            role.as_str(),
            status,
            role.as_str()
        );
        warn!("{}", note);
        crate::notify::notify(NOTIFY_ID, crate::notify::Urgency::Normal, 5000, "monux", &note);
    });
    Ok(())
}

/// Fetches the diagnostics bundle from the daemon and copies it to the
/// clipboard, formatted as markdown like `monux diagnostics --copy`. The
/// journal part of the bundle is the LaunchAgent's own log tail (the
/// launchd-captured stdout/stderr), which is what a macOS daemon's history
/// actually lives in.
fn copy_diagnostics(socket: &std::path::Path) -> Result<String> {
    use crate::control::Diagnostics;
    use crate::diagnostics;
    let request = serde_json::json!({
        "cmd": "diagnostics",
        "lines": diagnostics::TRAY_LOG_LINES,
    })
    .to_string();
    let raw = control::request_line(socket, &request)?;
    let v = parse_ok(&raw, socket)?;
    let d: Diagnostics = serde_json::from_value(v["diagnostics"].clone())
        .context("The daemon returned no diagnostics")?;
    let role =
        control::Role::parse(&d.role).with_context(|| format!("Unknown daemon role '{}'", d.role))?;
    let bundle = diagnostics::Bundle {
        diagnostics: d,
        // The same journal half a `monux diagnostics` bundle carries: the
        // LaunchAgent's launchd-captured log tail.
        journal: diagnostics::journal_capture(role, diagnostics::DEFAULT_JOURNAL_SINCE),
        peers: Vec::new(),
    };
    let text = diagnostics::format_bundle(
        &bundle,
        diagnostics::FormatOptions {
            format: diagnostics::Format::Markdown,
            redact: false,
        },
    )?;
    let tool = diagnostics::copy_to_clipboard(&text)?;
    Ok(format!("Diagnostics copied to the clipboard ({tool})"))
}

/// The poll loop (background thread): wait for a poke or the interval,
/// poll, post the view to the main queue, repeat.
fn poll_loop(shared: Arc<Shared>) {
    debug!("Tray: poll thread up");
    let queue = DispatchQueue::main();
    loop {
        let poked = shared.wait();
        debug!("Tray: woke (poked: {})", poked);
        let (socket, view) = poll();
        debug!("Tray poll: {} (socket: {})", view.title, socket.as_deref().map(|p| p.display().to_string()).unwrap_or_else(|| "none".into()));
        let note = shared.note.lock().unwrap().clone();
        queue.exec_async(move || {
            debug!("Tray: applying polled view on the main thread");
            UI.with_borrow_mut(|ui| {
                let Some(ui) = ui.as_mut() else {
                    return;
                };
                let mtm = MainThreadMarker::new().expect("dispatch closure off the main thread");
                ui.socket = socket.clone();
                apply_view(ui, &view, &note, mtm);
            });
        });
    }
}

/// Runs the indicator until the process is hidden (menu) or killed. A
/// missing monux daemon is NOT an error: the tray shows the "?" state and
/// keeps polling, doubling as a launcher.
pub fn run() -> Result<()> {
    let mtm = MainThreadMarker::new().context("the indicator must run on the main thread")?;
    let app = NSApplication::sharedApplication(mtm);
    // A tray is not a window app: no Dock icon, no menu bar takeover.
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

    let item = NSStatusBar::systemStatusBar().statusItemWithLength(22.0);
    let menu = NSMenu::initWithTitle(NSMenu::alloc(mtm), &NSString::from_str("monux"));
    item.setMenu(Some(&menu));

    let target = TrayTarget::new(mtm);
    let shared = Shared::new();

    // First paint before the poll thread's first answer: the launcher view.
    let view = View::not_running();
    let ui = Ui {
        item: item.clone(),
        menu: menu.clone(),
        target,
        socket: None,
        shared: shared.clone(),
    };
    apply_view(&ui, &view, &None, mtm);
    UI.with_borrow_mut(|slot| *slot = Some(ui));

    std::thread::spawn(move || poll_loop(shared));

    info!("Tray indicator running (polling every {POLL_INTERVAL:?})");
    app.run();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glyphs_follow_the_model_colors() {
        assert_eq!(glyph_for(IconColor::Green), ("●", GREEN));
        assert_eq!(glyph_for(IconColor::Blue), ("●", BLUE));
        assert_eq!(glyph_for(IconColor::Grey), ("●", GREY));
        assert_eq!(glyph_for(IconColor::Red), ("●", RED));
        // The unknown state is a GLYPH change, not just a color: the grey
        // "?" reads as "no daemon" at a glance.
        assert_eq!(glyph_for(IconColor::Unknown), ("?", GREY));
    }

    #[test]
    fn tags_round_trip_through_plain_strings() {
        // Socket actions carry the control request verbatim.
        let tag = tag_for(&MenuAction::Pause);
        assert_eq!(tag, Tag::Socket(r#"{"cmd":"pause"}"#.to_string(), "Pause"));
        // Switch actions carry the target fingerprint inside the request.
        let tag = tag_for(&MenuAction::SwitchTo("fp123".to_string()));
        assert_eq!(
            tag,
            Tag::Socket(r#"{"cmd":"switch","target":"fp123"}"#.to_string(), "Switch")
        );
        // Local actions get local: markers.
        assert_eq!(tag_for(&MenuAction::StartClient), Tag::Start(control::Role::Client));
        assert_eq!(tag_for(&MenuAction::StartServer), Tag::Start(control::Role::Server));
        assert_eq!(tag_for(&MenuAction::CopyDiagnostics), Tag::CopyDiagnostics);
        assert_eq!(tag_for(&MenuAction::HideTray), Tag::Hide);

        // ...and the string encoding round-trips for every variant. The
        // label is the one thing that does NOT survive: it only lives in the
        // Rust-side tag, and the representedObject carries the request (the
        // decoder then falls back to the generic "command" label).
        for (tag, decoded) in [
            (
                Tag::Socket(action_request(&MenuAction::Resume), "Restart"),
                Some(Tag::Socket(action_request(&MenuAction::Resume), "command")),
            ),
            (
                Tag::Start(control::Role::Server),
                Some(Tag::Start(control::Role::Server)),
            ),
            (
                Tag::Start(control::Role::Client),
                Some(Tag::Start(control::Role::Client)),
            ),
            (Tag::CopyDiagnostics, Some(Tag::CopyDiagnostics)),
            (Tag::Hide, Some(Tag::Hide)),
        ] {
            let encoded = tag_to_nsstring(&tag);
            assert_eq!(tag_from_nsstring(&encoded), decoded);
        }
    }

    #[test]
    fn unknown_tags_are_dropped_not_misexecuted() {
        // A corrupted or foreign representedObject must decode to None (the
        // click is then ignored), never to a guess.
        assert_eq!(tag_from_nsstring(&NSString::from_str("local:start:wheel")), None);
        // An EMPTY string decodes as an (empty) socket request, not a guess:
        // only malformed local: markers are dropped.
        assert_eq!(
            tag_from_nsstring(&NSString::from_str("")),
            Some(Tag::Socket(String::new(), "command"))
        );
    }
}
