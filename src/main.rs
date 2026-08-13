use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use regex::Regex;
use signal_hook::{consts::signal, iterator::Signals};
use tokio::sync::{mpsc, watch as watchchan};
use tokio::{runtime, task, time};
use tracing::{debug, error, info, warn};

mod cli;

use cli::{
    Cli, Commands, ConfigCommands, DaemonCommands, DiagnosticsArgs, DiagnosticsCommands,
    GuiCommands, SystemCommands, TrayAction, VERSION,
};
use monux::device::output::OutputHandler;
use monux::device::{handles, input, output, shortcut, watch, Event};
use monux::network::{approval, transport::NetworkMode};
use monux::{client, clipboard, discovery, logging, rotation, server, single_instance};

/// Listens for SIGUSR1 and SIGUSR2, treating them as "switch to next client" and "switch to prev client" respectively.
/// SIGHUP dumps the server's mirrored diagnostics state to the log for troubleshooting.
/// The dump reads the mirror directly instead of going through the server event
/// loop, so it still prints when the loop itself is stalled — the exact scenario
/// the dump exists to debug.
fn handle_signals(mut signals: Signals, out: mpsc::Sender<Event>, diagnostics: Arc<rotation::DiagnosticsMirror>) {
    let mut iter = signals.into_iter();
    loop {
        match iter.next() {
            // try_send, not blocking_send: `out` is the same bounded channel
            // every input batch travels on, so a stalled events loop would
            // park this thread inside the switch arm and the SIGHUP below —
            // whose whole purpose is to report on a stalled loop — would never
            // be dequeued. A switch that cannot be queued is better dropped
            // loudly than paid for with the dump.
            Some(signal::SIGUSR1) => {
                if let Err(e) = out.try_send(Event::SwitchNext) {
                    error!("Failed to submit SwitchNext event for SIGUSR1: {:?}", e);
                }
            }
            Some(signal::SIGUSR2) => {
                if let Err(e) = out.try_send(Event::SwitchPrev) {
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

/// Print-and-exit CLI commands want to die silently on SIGPIPE ('monux
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
                // Built through serde rather than format!: the target is
                // arbitrary user input, and a quote or backslash in it would
                // otherwise produce a malformed request line.
                let request =
                    serde_json::json!({"cmd": "switch", "target": args.target}).to_string();
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
            let status = monux::update::run(
                args.force,
                false,
                constraint,
                to.as_deref(),
                // Typed by a person at a terminal: they are the review gate.
                monux::update::Trust::Interactive,
            )?;
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
                let _indicator_lock = match single_instance::acquire("indicator") {
                    Ok(lock) => lock,
                    Err(e) => {
                        // Standing down for a live indicator is an orderly
                        // outcome, not a failure: exit with the code that
                        // says so, so a supervising daemon parks instead of
                        // diagnosing a crash loop (indicator_spawn.rs).
                        if let Some(yielded) = e.downcast_ref::<single_instance::Yielded>() {
                            info!("{}; leaving the tray to it", yielded);
                            std::process::exit(single_instance::EXIT_YIELDED);
                        }
                        return Err(e);
                    }
                };
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
            let update_mode = update_mode(args.auto_install.unwrap_or(false));
            let www = args.www.unwrap_or(false);
            // Validation before the takeover below: single_instance::acquire
            // SIGTERMs the running daemon, so anything that can reject the
            // command line has to have rejected it by then. A typo would
            // otherwise leave the machine with no daemon at all — and the
            // installed unit's Restart=on-failure will not bring it back,
            // because the old one exited cleanly on the signal.
            let max_clipboard_size_bytes = args
                .max_clipboard_size_kb
                .unwrap_or(monux::config::DEFAULT_MAX_CLIPBOARD_SIZE_KB)
                .checked_mul(1024)
                .context("--max-clipboard-size-kb is too large")?;
            // Screen-edge switching is opt-in: no --edge-map, no edge manager.
            let edge_map = match &args.edge_map {
                Some(specs) => Some(monux::edge::parse_edge_map(specs)?),
                None => None,
            };
            // The shortcut chords are plain strings on the command line, so
            // clap accepts anything; reject typos here (mirroring --edge-map
            // above), not in parse_key_combos after the takeover.
            shortcut::validate_chord(
                args.shortcut
                    .as_deref()
                    .unwrap_or(monux::config::DEFAULT_SHORTCUT),
            )?;
            shortcut::validate_chord(
                args.shortcut_prev
                    .as_deref()
                    .unwrap_or(monux::config::DEFAULT_SHORTCUT_PREV),
            )?;
            for spec in args.shortcut_goto.as_deref().unwrap_or_default() {
                shortcut::validate_goto(spec)?;
            }
            // An empty --pause-shortcut disables pause/resume.
            let pause_shortcut = args
                .pause_shortcut
                .as_deref()
                .unwrap_or(monux::config::DEFAULT_PAUSE_SHORTCUT);
            let pause_shortcut = if pause_shortcut.trim().is_empty() {
                None
            } else {
                shortcut::validate_chord(pause_shortcut)?;
                Some(pause_shortcut)
            };
            let server_lock = single_instance::acquire("server")?;
            settle_after_takeover(&server_lock);
            // Before the indicator supervisor spawns anything (see the note
            // on the pid snapshot there).
            reap_inherited_children();
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
                rt.spawn(monux::autoupdate::run(None, update_mode));
            }
            // Constructed after the takeover on purpose: new() writes a fresh
            // keypair when none exists (write_new_keypair is not atomic), and
            // the single-instance lock serializes that between contenders.
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
            rt.block_on(async {
                server(ServerDaemonArgs {
                    config_dir,
                    listen_addr: SocketAddr::new(listen, port),
                    keys_next: args
                        .shortcut
                        .as_deref()
                        .unwrap_or(monux::config::DEFAULT_SHORTCUT),
                    keys_prev: Some(
                        args.shortcut_prev
                            .as_deref()
                            .unwrap_or(monux::config::DEFAULT_SHORTCUT_PREV),
                    ),
                    keys_goto: args.shortcut_goto.take().unwrap_or_default(),
                    keys_pause: pause_shortcut,
                    device_filters: args.device.take().unwrap_or_default(),
                    exit_secs: args.exit_secs,
                    verifier,
                    max_clipboard_size_bytes,
                    mode,
                    motion_mode,
                    throttle_mode,
                    edge_map,
                    edge_dwell: Duration::from_millis(
                        args.edge_dwell_ms
                            .unwrap_or(monux::config::DEFAULT_EDGE_DWELL_MS),
                    ),
                    auto_update,
                    auto_indicator,
                })
                .await
            })?;
        }
        Commands::Client(mut args) => {
            // The config file fills whatever the command line left unset.
            args.resolve(&monux::config::load_for_daemon(&config_dir));
            let auto_update = !args.no_auto_update.unwrap_or(false);
            let auto_indicator = !args.no_indicator.unwrap_or(false);
            let update_mode = update_mode(args.auto_install.unwrap_or(false));
            let www = args.www.unwrap_or(false);
            let mouse_scale = args.mouse_scale.unwrap_or(monux::config::DEFAULT_INPUT_SCALE);
            let scroll_scale = args
                .scroll_scale
                .unwrap_or(monux::config::DEFAULT_INPUT_SCALE);
            // Validation before the takeover below: single_instance::acquire
            // SIGTERMs the running daemon, so anything that can reject the
            // command line has to have rejected it by then. A typo would
            // otherwise leave the machine with no daemon at all — and the
            // installed unit's Restart=on-failure will not bring it back,
            // because the old one exited cleanly on the signal.
            let max_clipboard_size_bytes = args
                .max_clipboard_size_kb
                .unwrap_or(monux::config::DEFAULT_MAX_CLIPBOARD_SIZE_KB)
                .checked_mul(1024)
                .context("--max-clipboard-size-kb is too large")?;
            // Screen-edge switching back to the server is opt-in: no
            // --edge-map, no edge detection. Client targets are validated at
            // startup ('auto' only), not at fire time.
            let edge_map = match &args.edge_map {
                Some(specs) => Some(monux::edge::parse_client_edge_map(specs)?),
                None => None,
            };
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
            let client_lock = single_instance::acquire("client")?;
            settle_after_takeover(&client_lock);
            reap_inherited_children();
            if auto_update {
                rt.spawn(monux::autoupdate::run(Some(config_dir.clone()), update_mode));
            }
            // Constructed after the takeover on purpose, as on the server
            // path: new() writes a fresh keypair when none exists
            // (write_new_keypair is not atomic), and the single-instance lock
            // serializes that between contenders.
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
            rt.block_on(async {
                client(ClientDaemonArgs {
                    config_dir,
                    initial_addr,
                    verifier,
                    max_clipboard_size_bytes,
                    mode,
                    mouse_scale,
                    scroll_scale,
                    throttle_mode,
                    edge_map,
                    edge_dwell: Duration::from_millis(
                        args.edge_dwell_ms
                            .unwrap_or(monux::config::DEFAULT_EDGE_DWELL_MS),
                    ),
                    auto_update,
                    auto_indicator,
                })
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
/// Reaps processes inherited from the pre-exec image.
///
/// An auto-update restart re-execs: the pid survives, and so do its children.
/// The tray indicator is deliberately ORPHANED rather than killed on shutdown
/// (see indicator_spawn::Supervisor's Drop) so the icon stays up across the
/// gap — but "orphaned" means "reparented to init once we exit", and a
/// re-exec never exits. The old indicator therefore remains our child, stands
/// down a moment later when the new image's indicator takes the
/// single-instance lock, and becomes a zombie nobody waits on: one leaked
/// process-table entry per restart, accumulating for as long as the daemon
/// lives.
///
/// The new image holds no Child handle for a process it did not spawn, so it
/// waits on the raw pids instead. MUST be called before the supervisor spawns
/// anything: waitpid on a specific pid can never steal the status of a child
/// we spawn later, but only if the pid list was taken before those exist.
fn reap_inherited_children() {
    let inherited = children_of(std::process::id());
    if inherited.is_empty() {
        return;
    }
    debug!(
        "Reaping {} process(es) inherited across the restart: {:?}",
        inherited.len(),
        inherited
    );
    // On a thread: these exit on their own schedule (the old indicator only
    // stands down once the new one has taken the lock), and startup must not
    // wait for them.
    std::thread::spawn(move || {
        for pid in inherited {
            let mut status = 0;
            // SAFETY: waitpid on a specific pid; a non-child simply returns
            // ECHILD, which is the "already gone" case and equally fine.
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }
    });
}

/// The pids of our direct children, read from /proc.
///
/// /proc/<pid>/status rather than /stat: the latter's comm field can contain
/// spaces and parentheses, which makes positional parsing of PPid a trap.
fn children_of(parent: u32) -> Vec<libc::pid_t> {
    let mut children = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return children;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<libc::pid_t>().ok()) else {
            continue;
        };
        let Ok(status) = fs::read_to_string(format!("/proc/{}/status", pid)) else {
            // Raced with the process exiting; nothing to reap.
            continue;
        };
        let ppid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|value| value.trim().parse::<u32>().ok());
        if ppid == Some(parent) {
            children.push(pid);
        }
    }
    children
}

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
    // args_os, not args: the latter panics on non-UTF-8 argv, and a --device
    // regex or an --edge-map monitor description can carry anything the shell
    // passed us (see reexec_after_update, which already does this).
    let status = std::process::Command::new("sudo")
        .arg("-E")
        .arg(&exe)
        .args(std::env::args_os().skip(1))
        .status()
        .context("Failed to re-exec with sudo")?;
    std::process::exit(status.code().unwrap_or(1));
}

/// The background check's mode, and the one line that tells the user which
/// one they are running — the difference (does this machine install code on
/// its own?) is worth stating at startup rather than leaving to the docs.
fn update_mode(auto_install: bool) -> monux::autoupdate::Mode {
    if auto_install {
        info!("Background updates: checking daily AND installing automatically (--auto-install); only signed releases are accepted");
        monux::autoupdate::Mode::AutoInstall
    } else {
        info!("Background updates: checking daily, reporting only — install with 'mx daemon update', the tray, or 'monux update'");
        monux::autoupdate::Mode::Notify
    }
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

/// The server daemon's startup inputs, resolved from flags and the config
/// file. A struct rather than seventeen positional parameters: four of them
/// are `Option<&str>`/`bool` in a row, which is exactly where a transposed
/// argument compiles and then misbehaves at runtime.
struct ServerDaemonArgs<'a> {
    config_dir: PathBuf,
    listen_addr: SocketAddr,
    /// Switch chords: next, previous, the per-target gotos, and pause.
    keys_next: &'a str,
    keys_prev: Option<&'a str>,
    keys_goto: Vec<String>,
    keys_pause: Option<&'a str>,
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
}

async fn server(args: ServerDaemonArgs<'_>) -> Result<()> {
    let ServerDaemonArgs {
        config_dir,
        listen_addr,
        keys_next,
        keys_prev,
        keys_goto,
        keys_pause,
        device_filters,
        exit_secs,
        verifier,
        max_clipboard_size_bytes,
        mode,
        motion_mode,
        throttle_mode,
        edge_map,
        edge_dwell,
        auto_update,
        auto_indicator,
    } = args;
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
            spawn_control_listener(listener, handler);
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
        server::run_server_events_loop(server::ServerEventsLoop {
            config_dir,
            event_rx,
            grab_tx: grab_tx2,
            output_handler,
            // Max compressed clipboard size over the wire
            max_clipboard_size_bytes,
            // Max uncompressed clipboard size, just in case
            // Saturating, not plain: max_clipboard_size_bytes is already a
            // checked KB*1024 whose validator caps KB at u64::MAX/1024, so it
            // can reach values where *10 overflows — a debug build panicked
            // the whole daemon on a value the validator accepts, and a release
            // build wrapped to an arbitrary ceiling. Saturating is also the
            // honest meaning here: this bounds decompression, and u64::MAX is
            // "no practical limit".
            max_uncompressed_size_bytes: max_clipboard_size_bytes.saturating_mul(10),
            rotation_tx,
            rotation_rx,
            motion_mode,
            throttle_mode,
            mode,
            diagnostics,
            edge_client_tx,
            edge_map,
        })
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
    // Every exit from the select funnels through close_loops below — signal,
    // --exit-secs timeout, and loop failure alike. A plain return would drop
    // the QUIC endpoint without close frames, leaving clients to wait out
    // their ~25s idle timeout instead of reconnecting at once.
    let shutdown: Result<()> = if let Some(exit_secs) = exit_secs {
        info!("Exiting in {} seconds...", exit_secs);
        tokio::select! {
            watch_exit = &mut watch_handle => {
                watch_exit
                    .map_err(anyhow::Error::from)
                    .and_then(|exit| exit.context("Failed to watch input events, exiting early"))
            },
            server_events_exit = &mut server_events_handle => {
                server_events_exit
                    .map_err(anyhow::Error::from)
                    .and_then(|exit| exit.context("Server events loop failed, exiting early"))
            },
            server_connections_exit = &mut server_connections_handle => {
                server_connections_exit
                    .map_err(anyhow::Error::from)
                    .and_then(|exit| exit.context("Server connections loop failed, exiting early"))
            },
            _timeout = time::sleep(Duration::from_secs(exit_secs as u64)) => {
                info!("Exiting automatically as requested (--exit-secs={})", exit_secs);
                Ok(())
            },
            _signal = shutdown_signal() => {
                info!("Shutting down...");
                Ok(())
            },
        }
    } else {
        tokio::select! {
            watch_exit = &mut watch_handle => {
                watch_exit
                    .map_err(anyhow::Error::from)
                    .and_then(|exit| exit.context("Failed to watch input events, exiting"))
            },
            server_events_exit = &mut server_events_handle => {
                server_events_exit
                    .map_err(anyhow::Error::from)
                    .and_then(|exit| exit.context("Server events loop failed, exiting early"))
            },
            server_connections_exit = &mut server_connections_handle => {
                server_connections_exit
                    .map_err(anyhow::Error::from)
                    .and_then(|exit| exit.context("Server connections loop failed, exiting early"))
            },
            _signal = shutdown_signal() => {
                info!("Shutting down...");
                Ok(())
            },
        }
    };
    close_loops(watch_handle, server_events_handle, server_connections_handle, server_endpoint).await;
    // Dropping _mdns_registration here sends the mDNS goodbye.
    // The active-client state file is deliberately left in place:
    // a restart (e.g. after 'monux update') resumes the session
    // automatically when the client reconnects (bounded by
    // ACTIVE_CLIENT_MAX_AGE).
    shutdown
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

/// Spawns the control-socket accept loop on the runtime. The JoinHandle is
/// deliberately dropped — the listener is an optional sidecar, not a daemon
/// loop — so without this wrapper a fatal exit (Listener::run returning Err)
/// would vanish unlogged.
fn spawn_control_listener(listener: monux::control::Listener, handler: monux::control::Handler) {
    task::spawn(async move {
        if let Err(e) = listener.run(handler).await {
            warn!("Control socket listener exited: {:?}", e);
        }
    });
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
/// The mDNS name, when there is one, is returned alongside the address rather
/// than written to the shared verifier: it describes THIS candidate, and the
/// verifier outlives every attempt (see MonuxCertVerification::begin_attempt).
async fn draw_candidate(
    cycle: &mut std::collections::VecDeque<Candidate>,
    config_dir: &std::path::Path,
) -> Option<(SocketAddr, Option<String>)> {
    if cycle.is_empty() {
        *cycle = candidate_cycle(&monux::known_servers::load(config_dir));
    }
    match cycle
        .pop_front()
        .expect("a candidate pass always holds at least the mDNS attempt")
    {
        // A remembered address carries no name of its own; the handshake
        // supplies one once the far end answers.
        Candidate::Remembered(addr) => Some((addr, None)),
        Candidate::Discover => {
            info!("Discovering the server via mDNS...");
            match discovery::discover_server(None, &monux::known_servers::load(config_dir)).await {
                Ok((addr, name)) => Some((addr, Some(name))),
                Err(e) => {
                    warn!("mDNS discovery found no server: {:?}", e);
                    None
                }
            }
        }
    }
}

/// The client daemon's startup inputs that aren't part of a connection's own
/// configuration (see client::ClientConfig, which this builds).
struct ClientDaemonArgs {
    config_dir: PathBuf,
    /// The address to try first; None puts the reconnect loop in discovery
    /// mode (remembered servers, then mDNS).
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
}

async fn client(args: ClientDaemonArgs) -> Result<()> {
    let ClientDaemonArgs {
        config_dir,
        initial_addr,
        verifier,
        max_clipboard_size_bytes,
        mode,
        mouse_scale,
        scroll_scale,
        throttle_mode,
        edge_map,
        edge_dwell,
        auto_update,
        auto_indicator,
    } = args;
    // Try to set up virtual devices up-front - exit early if we can't access uinput
    let mut output_handler = output::uinput::VirtualUInputDevices::new()
        .context("Failed to create virtual devices for output, possible solutions:
- Add your user to the 'input' group and log back in: 'sudo usermod -aG input $USER'
- Enable uinput and/or evdev in the kernel, check for /dev/uinput and /dev/input/
- As a fallback, run as root with 'sudo -E monux client ...' (-E keeps clipboard support)")?;
    // Saturating for the same reason as the server's ceiling above.
    let max_uncompressed_size_bytes = max_clipboard_size_bytes.saturating_mul(10);
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
    // The name mDNS gave for the current candidate, if any: it captions the
    // approval prompt for THIS attempt only (see begin_attempt below).
    let mut discovered_name: Option<String> = None;
    let mut connect_addr = match initial_addr {
        Some(addr) => addr,
        None => match draw_candidate(&mut cycle, &config_dir).await {
            Some((addr, name)) => {
                discovered_name = name;
                addr
            }
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
            spawn_control_listener(listener, handler);
        }
        Err(e) => warn!("Control socket unavailable: {:?}", e),
    }
    // The daemon is up (control socket bound): start the tray indicator
    // alongside it; it polls until the socket serves.
    indicator.launch();
    // Keep one set of signal handlers registered across reconnect attempts.
    let shutdown = client_shutdown_signal();
    tokio::pin!(shutdown);

    // Everything a connection is configured with, built once. Only
    // server_addr changes as the loop cycles candidates.
    let mut connection_config = client::ClientConfig {
        server_addr: connect_addr,
        cert_verifier: verifier.clone(),
        max_clipboard_size_bytes,
        mode,
        config_dir: config_dir.clone(),
        mouse_scale,
        scroll_scale,
        control_state: control_state.clone(),
        throttle_mode,
        edge_map,
        edge_dwell,
    };

    loop {
        info!("Connecting to server: {}", connect_addr);
        control_state.set_server(connect_addr);
        connection_config.server_addr = connect_addr;
        // Scope the prompt's identity hint to the machine about to be dialled,
        // so a name learned on an earlier pass can never caption the approval
        // of a different server.
        verifier.begin_attempt(connect_addr, discovered_name.take());
        let connected_at = Instant::now();
        tokio::select! {
            run_result = client::run(
                &connection_config,
                &mut local_clipboard,
                &mut output_handler,
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
                        if let Some((next, name)) = draw_candidate(&mut cycle, &config_dir).await
                        {
                            if next != connect_addr {
                                info!(
                                    "Connection failure #{}: trying the next server candidate: {} (was {})",
                                    consecutive_failures, next, connect_addr
                                );
                            }
                            connect_addr = next;
                            discovered_name = name;
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


    /// The reaper has to find our own children and nobody else's — it feeds
    /// waitpid, so a wrong pid is at best a no-op and at worst a wait on
    /// something we don't own.
    #[test]
    fn children_of_finds_our_own_and_only_our_own() {
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        let ours = children_of(std::process::id());
        assert!(ours.contains(&pid), "our child {} is missing from {:?}", pid, ours);
        // pid 1 is nobody's child but init's, and certainly not ours.
        assert!(!ours.contains(&1));
        let _ = child.kill();
        let _ = child.wait();
        // Once reaped it is no longer a child.
        assert!(!children_of(std::process::id()).contains(&pid));
    }

    /// The regression itself: a child that is SIGTERM'd but never waited on
    /// becomes a zombie, and reap_inherited_children must clear it.
    ///
    /// This reproduces the shape of the restart bug rather than the mechanism
    /// — re-exec'ing the test binary isn't practical — by leaking a child
    /// handle, which is exactly what the pre-exec image leaves behind: a live
    /// child with no Child struct anywhere to wait on it.
    #[test]
    fn an_unwaited_child_is_reaped_instead_of_left_a_zombie() {
        let child = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        // Leak the handle: nothing will ever wait on this process, which is
        // the state a re-exec leaves the orphaned indicator in.
        std::mem::forget(child);
        unsafe { libc::kill(pid, libc::SIGTERM) };

        // It is now a zombie: still listed as ours, and in state Z.
        let zombie_state = || {
            std::fs::read_to_string(format!("/proc/{}/stat", pid))
                .ok()
                .and_then(|stat| {
                    // State is the field after the parenthesised comm.
                    stat.rsplit_once(") ")
                        .and_then(|(_, rest)| rest.split(' ').next().map(|s| s.to_string()))
                })
        };
        for _ in 0..100 {
            if zombie_state().as_deref() == Some("Z") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(zombie_state().as_deref(), Some("Z"), "expected a zombie to clear");

        reap_inherited_children();

        // The reaper runs on its own thread; give it a moment to drain.
        for _ in 0..100 {
            if !children_of(std::process::id()).contains(&pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            !children_of(std::process::id()).contains(&pid),
            "the zombie survived the reaper"
        );
    }

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
    fn diagnostics_since_accepts_journalctl_relative_windows() {
        // Every relative journalctl window starts with a minus, which clap
        // reads as a flag unless the arg allows hyphen values. The default
        // never exercised this, so only explicit values broke.
        for window in ["-2min", "-30min", "-2h", "-1day"] {
            let cli = Cli::try_parse_from(["monux", "diagnostics", "--since", window])
                .unwrap_or_else(|e| panic!("--since {} must parse: {}", window, e));
            let Commands::Diagnostics(args) = cli.command else {
                panic!("expected the diagnostics command");
            };
            assert_eq!(args.since, window);
        }
        // Absolute timestamps keep working.
        let cli =
            Cli::try_parse_from(["monux", "diagnostics", "--since", "2026-08-07 14:00:00"]).unwrap();
        let Commands::Diagnostics(args) = cli.command else {
            panic!("expected the diagnostics command");
        };
        assert_eq!(args.since, "2026-08-07 14:00:00");
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
