//! Local control IPC: both daemons (server and client) publish their live
//! state and accept a small command set over a per-user unix socket. This is
//! the backend of `monux status` and of the tray indicator
//! (`monux gui indicator`), so the field names below are STABLE — the tray
//! consumes them.
//!
//! # Socket location
//!
//! `$XDG_RUNTIME_DIR/monux/server.sock` and `$XDG_RUNTIME_DIR/monux/client.sock`.
//! When XDG_RUNTIME_DIR is unset, `/tmp/monux-<uid>/` is used instead. The
//! directory is created 0700 and the socket file is removed on shutdown. A
//! socket file left by a crashed instance is reclaimed; a path that answers a
//! connect belongs to another live daemon and is left alone (the daemon logs a
//! warning and runs without control IPC).
//!
//! # Security
//!
//! Same-user only, established by the KERNEL rather than by the filesystem:
//! both halves check SO_PEERCRED and refuse a peer that is neither this euid
//! nor root — the daemon so no other user can drive it, the CLI so a squatted
//! socket cannot answer for a daemon it is not (a fake `monux status`, a fake
//! ack for `monux daemon exit`, an attacker-authored bundle pasted into a bug
//! report). Neither end therefore depends on the socket's directory being
//! trustworthy, which matters because the /tmp fallback lives in a
//! world-writable directory.
//!
//! The directory is hardened regardless: XDG_RUNTIME_DIR is 0700 per the XDG
//! spec, the /tmp fallback is created 0700, and bind() refuses a socket dir
//! owned by another user (a pre-existing /tmp/monux-<uid> must never be
//! trusted) or reached through a symlink, treating a failed 0700 chmod as
//! fatal. Under the documented `sudo -E` fallback the root daemon first hands
//! the dir to the invoking user, exactly so that check passes for the socket
//! the user's own tools then reach. There is no authentication beyond identity — any process running as
//! the same user can drive switches, pause, updates and shutdown, exactly as
//! it already could via signals (SIGUSR1/SIGUSR2/SIGTERM).
//!
//! # Wire protocol (newline-delimited JSON)
//!
//! One JSON object per line in each direction; every request line gets
//! exactly one response line. Requests:
//!
//! - `{"cmd":"status"}` — the daemon's live state (schema below).
//! - `{"cmd":"diagnostics"}` — a troubleshooting bundle for bug reports
//!   (schema below); the tray indicator's "Copy diagnostics" uses it.
//! - `{"cmd":"switch","target":"next"|"prev"|"local"|<fingerprint-prefix>}` —
//!   rotate input to another machine (server socket only).
//! - `{"cmd":"pause"}` / `{"cmd":"resume"}` — suspend/resume input handling
//!   (server socket only). These are IDEMPOTENT, unlike the pause hotkey's
//!   toggle: pausing an already-paused server is a no-op success, so a GUI
//!   can send the command matching the state it wants without reading first.
//! - `{"cmd":"update_now"}` — wake the background auto-update check
//!   immediately instead of waiting for the daily tick.
//! - `{"cmd":"indicator","action":"hide"|"show"}` — hide the auto-spawned
//!   tray indicator (SIGTERM the daemon's spawned indicator child, and keep
//!   it down: no spawns/respawns) or show it again (spawn immediately when
//!   none is running). The hidden state is in-memory only: a daemon restart
//!   always starts the indicator fresh. show is REFUSED when the daemon runs
//!   with --no-indicator — an explicit opt-out the socket may not override.
//!   Manually-started indicators are never managed by this. The tray menu's
//!   "Hide tray icon" and `monux gui tray hide|show` drive this command.
//! - `{"cmd":"restart"}` — graceful shutdown, then re-exec into the installed
//!   binary (the auto-updater's restart path).
//! - `{"cmd":"exit"}` — graceful shutdown.
//!
//! Responses: `{"ok":true,"state":{...}}` for status,
//! `{"ok":true,"diagnostics":{...}}` for diagnostics, `{"ok":true}` for
//! accepted commands, `{"ok":false,"error":"..."}` on failure (unknown
//! command, wrong role, missing target, event queue full, ...). A command's
//! `ok` means it was accepted by the daemon's event loop — the effect (e.g.
//! a rotation switch) lands asynchronously; poll status to observe it. The
//! server socket serves the full command set; the client socket serves only
//! status/diagnostics/update_now/indicator/restart/exit (rotation and pause
//! are server concepts).
//!
//! # Diagnostics schema (the `diagnostics` object of a diagnostics response)
//!
//! Served by both roles:
//! - `version`, `protocol_version`, `role`: as in the status state
//! - `state_dump`: the server's SIGHUP rotation-state dump string
//!   (rotation::DiagnosticsMirror::state_dump); for the client role, the
//!   human-readable rendering of the client mirror's state
//! - `recent_logs`: the daemon's last ~50 log lines (the logging.rs ring
//!   buffer), oldest first; empty when nothing was logged yet
//!
//! # State schema (the `state` object of a status response)
//!
//! Server:
//! - `role`: "server"
//! - `version`: crate version string, e.g. "1.4.0"
//! - `protocol_version`: wire protocol version (int)
//! - `listen`: QUIC listen address, "ip:port"
//! - `paused`: bool — input handling suspended (see pause/resume)
//! - `current_target`: "local" or the addr of the client owning input
//! - `clients`: array of `{addr, fingerprint, connected_since_secs, rtt_ms,
//!   edge}` (rtt_ms from QUIC path stats, null when unavailable; edge the
//!   resolved --edge-map direction, null when unmapped)
//! - `clipboard`: `{owner: "none"|"local"|client addr, types: [mime strings]}`
//! - `update_available`: sha of a newer commit the auto-updater has seen,
//!   or null
//!
//! Client:
//! - `role`: "client"
//! - `version`, `protocol_version`: as above
//! - `server`: server address the client connects to, "ip:port"
//! - `connected`: bool — a session is currently established
//! - `active`: bool — this client currently owns the server's input
//!   (the ServerEvent::Switch state)
//! - `connected_since_secs`, `rtt_ms`, `lost_packets`: connection age, QUIC
//!   path RTT in ms, and cumulative lost packets; all null while disconnected

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::device::Event;
use crate::msgs::shared::PROTOCOL_VERSION;
use crate::rotation::DiagnosticsMirror;

/// Longest accepted request line, ENFORCED by capping the read itself (see
/// serve_connection: take() presents EOF at the cap, so a same-user peer
/// sending a never-terminated line gets a protocol error instead of growing
/// our read buffer without bound). Requests are tiny; the cap is generous.
const MAX_REQUEST_LINE: usize = 8192;

/// Which daemon a control socket belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

impl Role {
    fn socket_name(&self) -> &'static str {
        match self {
            Role::Server => "server.sock",
            Role::Client => "client.sock",
        }
    }

    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Role::Server => "server",
            Role::Client => "client",
        }
    }

    /// Parses the role back out of a wire/state string.
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "server" => Some(Role::Server),
            "client" => Some(Role::Client),
            _ => None,
        }
    }
}

/// The directory holding the control sockets, honoring XDG_RUNTIME_DIR (also
/// the test override) with a per-user /tmp fallback. The fallback lives in
/// world-writable /tmp, so bind() verifies the dir's ownership before
/// trusting it (see prepare_socket_dir).
fn socket_dir_from(runtime_dir: Option<&std::ffi::OsStr>) -> PathBuf {
    match runtime_dir {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("monux"),
        _ => PathBuf::from(format!("/tmp/monux-{}", unsafe { libc::geteuid() })),
    }
}

/// The directory holding the control sockets for this process.
pub fn socket_dir() -> PathBuf {
    socket_dir_from(std::env::var_os("XDG_RUNTIME_DIR").as_deref())
}

/// The default socket path for `role`.
pub fn socket_path(role: Role) -> PathBuf {
    socket_dir().join(role.socket_name())
}

/// Creates the socket dir if needed, then makes sure it is safe to trust
/// (see the module docs' Security section): it must be owned by us — a
/// pre-existing dir owned by another user could have its socket replaced,
/// feeding fake acks/state to `monux status` — and locked down to 0700. A
/// failed chmod is a hard error for the same reason.
///
/// One exception to "owned by us": the documented `sudo -E` fallback puts a
/// ROOT daemon behind a socket the invoking user must be able to reach, so
/// when euid is 0 and SUDO_UID is set the dir is handed to that user (a
/// root-owned 0700 dir would lock them out of the socket entirely, and a
/// pre-existing user-owned one would fail the owner check, leaving the
/// daemon with no control IPC either way).
///
/// The ownership check and the chmod run against a DESCRIPTOR opened
/// O_NOFOLLOW, never against the path. The /tmp fallback dir sits in a
/// world-writable directory, so a path-based check can be aimed elsewhere by
/// planting a symlink at that name: the owner check would then be satisfied
/// by the link's target and the 0700 chmod would land on a directory we never
/// meant to touch. single_instance.rs hardens its own /tmp lock file the same
/// way, for the same reason.
fn prepare_socket_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    // Refuse a planted link by name first, so the error says what is actually
    // wrong; the O_NOFOLLOW open below closes the swap-after-check race.
    if std::fs::symlink_metadata(dir)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        bail!(
            "Refusing to use control socket dir {}: it is a symlink",
            dir.display()
        );
    }
    // 0700 from birth rather than a create-then-chmod: no window in which a
    // freshly created dir is reachable by anyone else.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("Failed to create control socket dir {}", dir.display()))?;
    let handle = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(dir)
        .with_context(|| format!("Failed to open control socket dir {}", dir.display()))?;
    let euid = unsafe { libc::geteuid() };
    // The `sudo -E` fallback (see above): hand the dir to the invoking user.
    // fchown on the O_NOFOLLOW descriptor, never the path — the same threat
    // setup.rs's lchown defends against for root-written files in user homes.
    let invoker = if euid == 0 { invoking_uid() } else { None };
    if let Some(uid) = invoker {
        use std::os::unix::io::AsRawFd;
        // gid -1: leave the group alone, only the owner matters here.
        if unsafe { libc::fchown(handle.as_raw_fd(), uid, libc::gid_t::MAX) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "Failed to hand control socket dir {} to the invoking user (uid {})",
                    dir.display(),
                    uid
                )
            });
        }
    }
    let owner = handle
        .metadata()
        .with_context(|| format!("Failed to stat control socket dir {}", dir.display()))?
        .uid();
    ensure_dir_owner(dir, owner, euid, invoker)?;
    // 0700 even if the dir pre-existed with looser perms: the socket is
    // same-user only (see module docs).
    handle
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("Failed to lock down control socket dir {}", dir.display()))?;
    Ok(())
}

/// Bails unless `owner` is `euid` — or, for a root daemon under the `sudo
/// -E` fallback, the invoking user the dir was just handed to (the dir's uid
/// from an fstat of the opened dir, and the euid/invoker at the call site;
/// all are parameters so the mismatch branch is testable without root).
/// `dir` is only used in the message.
fn ensure_dir_owner(
    dir: &Path,
    owner: libc::uid_t,
    euid: libc::uid_t,
    invoker: Option<libc::uid_t>,
) -> Result<()> {
    if owner != euid && Some(owner) != invoker {
        bail!(
            "Control socket dir {} is owned by uid {}, not by us (uid {}): refusing to trust it — remove it or fix its ownership",
            dir.display(),
            owner,
            euid
        );
    }
    Ok(())
}

/// The uid of the process on the other end of a connected unix socket, as the
/// KERNEL reports it (SO_PEERCRED, recorded at connect time). Unlike the
/// socket path's permissions this says nothing about who created the path, so
/// it holds even when the directory itself cannot be trusted — which is what
/// makes it the right check for both halves of this protocol.
fn peer_uid(fd: std::os::unix::io::RawFd) -> Result<libc::uid_t> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a live connected socket borrowed from its owner for the
    // duration of the call, and cred/len describe exactly the buffer
    // SO_PEERCRED writes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("Failed to read the control socket peer's credentials");
    }
    Ok(cred.uid)
}

/// Whether a control-socket peer running as `peer` may be trusted by a
/// process running as `euid`, given the uid that invoked us (`SUDO_UID`, when
/// this process was elevated).
///
/// Same user, or root — and root is a statement of fact rather than a
/// concession: it can already ptrace the daemon and replace its binary.
///
/// The invoking user is the third case, and it is what keeps the documented
/// `sudo -E monux server` fallback working: that puts a ROOT daemon on one end
/// of this socket and the user's own unprivileged `mx status` / tray on the
/// other. Refusing them would be a stricter rule than the socket ever had —
/// it lives in that user's runtime dir, 0700 — while buying nothing: they
/// started this daemon with sudo, so they can restart it saying anything.
/// Every OTHER local user is still refused, which is the actual threat.
fn peer_uid_trusted(peer: libc::uid_t, euid: libc::uid_t, invoker: Option<libc::uid_t>) -> bool {
    peer == euid || peer == 0 || (euid == 0 && invoker == Some(peer))
}

/// The uid that invoked this process through sudo, if any. Only consulted when
/// running as root (see peer_uid_trusted); sudo sets it, so an unelevated
/// process inheriting a stale value gains nothing from it.
fn invoking_uid() -> Option<libc::uid_t> {
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse::<libc::uid_t>().ok())
}

/// Live server state, published in status responses (see module docs).
/// The rotation loop refreshes a snapshot of this in the DiagnosticsMirror
/// after every loop iteration. The `role` key on the wire comes from the
/// State enum's tag when this is wrapped for sending.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerState {
    pub version: String,
    pub protocol_version: u64,
    /// QUIC listen address "ip:port". Filled by the mirror (the rotation loop
    /// doesn't know it), so snapshots built by the loop leave it empty.
    pub listen: String,
    pub paused: bool,
    /// "local" or the addr of the client currently owning input.
    pub current_target: String,
    pub clients: Vec<ServerClientState>,
    pub clipboard: ServerClipboardState,
    /// Sha of a newer commit seen by the auto-updater, if any.
    pub update_available: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerClientState {
    pub addr: String,
    pub fingerprint: String,
    pub connected_since_secs: u64,
    pub rtt_ms: Option<u64>,
    /// The edge-map direction this client resolves to on the server, if any
    /// (for verifying --edge-map without testing edges).
    #[serde(default)]
    pub edge: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerClipboardState {
    /// "none", "local", or the addr of the client owning the clipboard.
    pub owner: String,
    pub types: Vec<String>,
}

/// Live client state, published in status responses (see module docs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientState {
    pub version: String,
    pub protocol_version: u64,
    /// Server address this client connects to.
    pub server: String,
    pub connected: bool,
    /// Whether this client currently owns the server's input.
    pub active: bool,
    pub connected_since_secs: Option<u64>,
    pub rtt_ms: Option<u64>,
    pub lost_packets: Option<u64>,
}

/// Either daemon's state, parsed by the status CLI (`role` discriminates).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase")]
pub enum State {
    Server(ServerState),
    Client(ClientState),
}

impl std::fmt::Display for State {
    /// Human-readable rendering for `monux status`.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            State::Server(s) => {
                writeln!(f, "monux server v{} (protocol {})", s.version, s.protocol_version)?;
                writeln!(f, "  listening:      {}", s.listen)?;
                writeln!(f, "  paused:         {}", yes_no(s.paused))?;
                writeln!(f, "  current target: {}", s.current_target)?;
                match &s.update_available {
                    Some(sha) => writeln!(f, "  update:         available ({})", sha)?,
                    None => writeln!(f, "  update:         up to date")?,
                }
                writeln!(f, "clipboard:")?;
                writeln!(f, "  owner:          {}", s.clipboard.owner)?;
                if s.clipboard.types.is_empty() {
                    writeln!(f, "  types:          -")?;
                } else {
                    writeln!(f, "  types:          {}", s.clipboard.types.join(", "))?;
                }
                writeln!(f, "clients ({}):", s.clients.len())?;
                for c in &s.clients {
                    // Lead with the fingerprint prefix that --edge-map and
                    // --shortcut-goto accept, so it's copy-paste ready. The
                    // resolved edge direction verifies --edge-map without
                    // testing edges.
                    let prefix: String = c.fingerprint.chars().take(8).collect();
                    writeln!(
                        f,
                        "  {} fingerprint {} (prefix: {}) connected {}s ago, rtt {}, edge {}",
                        c.addr,
                        c.fingerprint,
                        prefix,
                        c.connected_since_secs,
                        c.rtt_ms
                            .map(|rtt| format!("{}ms", rtt))
                            .unwrap_or_else(|| "?".to_string()),
                        c.edge.as_deref().unwrap_or("-")
                    )?;
                }
                Ok(())
            }
            State::Client(s) => {
                writeln!(f, "monux client v{} (protocol {})", s.version, s.protocol_version)?;
                writeln!(f, "  server:         {}", s.server)?;
                match (s.connected, s.connected_since_secs) {
                    (true, age) => writeln!(
                        f,
                        "  connected:      yes ({}, rtt {}, {} packets lost)",
                        age.map(|secs| format!("for {}s", secs))
                            .unwrap_or_else(|| "just now".to_string()),
                        s.rtt_ms
                            .map(|rtt| format!("{}ms", rtt))
                            .unwrap_or_else(|| "?".to_string()),
                        s.lost_packets.unwrap_or(0)
                    )?,
                    (false, _) => writeln!(f, "  connected:      no")?,
                }
                writeln!(f, "  active:         {}", yes_no(s.active))?;
                Ok(())
            }
        }
    }
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

/// Mirror of the client daemon's live state for the control socket (the
/// client-side analog of the rotation's DiagnosticsMirror). Written by the
/// connection lifecycle in main.rs and the Switch handler in client.rs; read
/// by the socket task. Stats are sampled live from the QUIC handle at query
/// time, so a status request always sees the current RTT.
pub struct ClientStateMirror {
    inner: Mutex<ClientStateInner>,
}

struct ClientStateInner {
    server: SocketAddr,
    connected: bool,
    active: bool,
    connected_at: Option<Instant>,
    /// Live connection handle for path stats; cleared on disconnect.
    conn: Option<quinn::Connection>,
}

impl ClientStateMirror {
    pub fn new(server: SocketAddr) -> Self {
        Self {
            inner: Mutex::new(ClientStateInner {
                server,
                connected: false,
                active: false,
                connected_at: None,
                conn: None,
            }),
        }
    }

    /// The reconnect loop re-discovered the server elsewhere.
    pub fn set_server(&self, server: SocketAddr) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.server = server;
        }
    }

    /// A session was established (called once per successful connect).
    pub fn set_connected(&self, conn: quinn::Connection) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.connected = true;
            inner.active = false;
            inner.connected_at = Some(Instant::now());
            inner.conn = Some(conn);
        }
    }

    /// The session dropped (or is about to be retried after a failure).
    pub fn set_disconnected(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.connected = false;
            inner.active = false;
            inner.connected_at = None;
            inner.conn = None;
        }
    }

    /// The server switched input to or away from this client.
    pub fn set_active(&self, active: bool) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.active = active;
        }
    }

    /// Builds the status state, sampling QUIC path stats live when connected.
    pub fn snapshot(&self) -> ClientState {
        let (server, connected, active, connected_at, conn) = match self.inner.lock() {
            Ok(inner) => (
                inner.server,
                inner.connected,
                inner.active,
                inner.connected_at,
                inner.conn.clone(),
            ),
            Err(_) => (
                "0.0.0.0:0".parse().expect("valid fallback addr"),
                false,
                false,
                None,
                None,
            ),
        };
        let (connected_since_secs, rtt_ms, lost_packets) = if connected {
            let stats = conn.as_ref().map(|c| c.stats());
            (
                connected_at.map(|at| at.elapsed().as_secs()),
                stats.map(|s| s.path.rtt.as_millis() as u64),
                stats.map(|s| s.path.lost_packets),
            )
        } else {
            (None, None, None)
        };
        ClientState {
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
            server: server.to_string(),
            connected,
            active,
            connected_since_secs,
            rtt_ms,
            lost_packets,
        }
    }
}

/// A parsed request line (see module docs for the protocol).
#[derive(Debug, Deserialize)]
pub struct Request {
    pub cmd: String,
    pub target: Option<String>,
    /// Sub-action for commands that need one ("indicator": hide|show).
    pub action: Option<String>,
    /// How many recent log lines "diagnostics" should return. Absent means
    /// the default; an older daemon simply ignores the field, so a newer CLI
    /// gets the default tail from it instead of an error.
    pub lines: Option<usize>,
    /// Whether "diagnostics" should also collect connected peers' bundles
    /// (server only). Absent means no.
    pub peer: Option<bool>,
}

/// Clamps a requested log-line count to what the ring can actually hold. A
/// caller asking for more than exists gets everything, not an error: a bug
/// report should never fail over a tuning knob.
fn requested_lines(requested: Option<usize>) -> usize {
    match requested {
        Some(n) => n.min(crate::logging::RECENT_LOGS_MAX),
        None => crate::logging::RECENT_LOGS_DEFAULT,
    }
}

/// Troubleshooting bundle served by `{"cmd":"diagnostics"}` (see module docs
/// for the schema). The tray indicator and the `monux diagnostics` CLI both
/// format this for bug reports (diagnostics.rs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diagnostics {
    pub version: String,
    pub protocol_version: u64,
    pub role: String,
    /// SIGHUP dump string (server) or client state rendering (client).
    pub state_dump: String,
    /// The daemon's recent log lines, oldest first (the ring in logging.rs).
    pub recent_logs: Vec<String>,
    /// The environment THIS DAEMON runs in — deliberately collected daemon-
    /// side: an autostarted daemon's environment differs from the invoking
    /// shell's in exactly the ways that produce bug reports.
    ///
    /// Defaulted on the wire so a freshly installed CLI can still read a
    /// daemon from before this field existed (an update installs the binary;
    /// the running daemon restarts later).
    #[serde(default)]
    pub environment: crate::diagnostics::Environment,
}

impl Diagnostics {
    fn server(mirror: &DiagnosticsMirror, lines: usize) -> Self {
        Diagnostics {
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
            role: Role::Server.as_str().to_string(),
            state_dump: mirror.state_dump(),
            recent_logs: crate::logging::recent_logs(lines),
            environment: crate::diagnostics::daemon_environment(),
        }
    }

    /// This client's own bundle, for answering the server's peer-diagnostics
    /// request (see bulk::DiagnosticsRequest).
    pub fn for_client(mirror: &ClientStateMirror, lines: usize) -> Self {
        Self::client(mirror, lines)
    }

    fn client(mirror: &ClientStateMirror, lines: usize) -> Self {
        Diagnostics {
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
            role: Role::Client.as_str().to_string(),
            state_dump: State::Client(mirror.snapshot())
                .to_string()
                .trim_end()
                .to_string(),
            recent_logs: crate::logging::recent_logs(lines),
            environment: crate::diagnostics::daemon_environment(),
        }
    }
}

/// Longest the server waits for the clients to answer a diagnostics request —
/// for the whole roster together, not per client (collect_peer_diagnostics
/// shares one deadline across it). A client builds its bundle from in-memory
/// mirrors, so this only trips when the peer is wedged or the link is dead —
/// which is very often exactly what the report is about. The wait is
/// therefore bounded and its expiry recorded, never allowed to hold the
/// report open.
pub const PEER_DIAGNOSTICS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Correlates outgoing peer-diagnostics requests with the responses that
/// arrive later, on a different task.
///
/// The request leaves through the rotation loop (which owns the clients'
/// bulk queues) and the answer arrives on the per-client bulk READ task, so
/// neither end can simply await the other. Both meet here: the requester
/// parks on a oneshot, the reader completes it by id.
#[derive(Default)]
pub struct PeerDiagnosticsHub {
    inner: Mutex<PeerDiagnosticsInner>,
}

/// The process's hub. A global for the same reason the log ring in
/// logging.rs is one: there is exactly one server per process, and the
/// alternative is threading an Arc through four layers of connection-
/// handling signatures that have nothing to do with bug reports.
pub fn peer_diagnostics_hub() -> &'static PeerDiagnosticsHub {
    static HUB: std::sync::OnceLock<PeerDiagnosticsHub> = std::sync::OnceLock::new();
    HUB.get_or_init(PeerDiagnosticsHub::new)
}

#[derive(Default)]
struct PeerDiagnosticsInner {
    next_id: u64,
    /// Requests still awaiting an answer, keyed by request id, each holding
    /// the peer that was asked. The responder is checked against it: the id
    /// travels in a frame the peer writes, so on its own it lets any connected
    /// client answer any other client's request (see complete).
    pending: std::collections::HashMap<u64, (SocketAddr, tokio::sync::oneshot::Sender<PeerReply>)>,
}

/// What a client's bulk reader hands back for one request.
pub type PeerReply = std::result::Result<Diagnostics, String>;

impl PeerDiagnosticsHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a new request against the peer being asked, returning its id
    /// and the receiver to await.
    pub fn open(&self, peer: SocketAddr) -> (u64, tokio::sync::oneshot::Receiver<PeerReply>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut inner = self.inner.lock().expect("peer diagnostics hub poisoned");
        inner.next_id += 1;
        let id = inner.next_id;
        inner.pending.insert(id, (peer, tx));
        (id, rx)
    }

    /// Delivers a response from `peer`. Unknown ids are dropped with a debug
    /// line rather than an error: a request that already timed out is exactly
    /// the case, and a late answer to it is not a fault.
    ///
    /// An id answered by a peer it was not addressed to is dropped the same
    /// way. Ids are a sequential counter handed out one per connected client
    /// in a tight loop, so a client can trivially guess its neighbour's and
    /// answer first — putting a bundle of its choosing under the other
    /// machine's label in the operator's bug report.
    pub fn complete(&self, peer: SocketAddr, id: u64, reply: PeerReply) {
        let sender = {
            let mut inner = self.inner.lock().expect("peer diagnostics hub poisoned");
            match inner.pending.get(&id) {
                Some((asked, _)) if *asked != peer => {
                    debug!(
                        "Ignoring peer diagnostics response for request {} from {}: it was addressed to {}",
                        id, peer, asked
                    );
                    None
                }
                _ => inner.pending.remove(&id).map(|(_, tx)| tx),
            }
        };
        match sender {
            Some(tx) => {
                // The receiver is gone if the requester timed out first.
                let _ = tx.send(reply);
            }
            None => debug!("Peer diagnostics response for unknown request {} ignored", id),
        }
    }

    /// Forgets a request whose wait ended, so a peer that never answers
    /// can't leak an entry per bug report.
    pub fn cancel(&self, id: u64) {
        let mut inner = self.inner.lock().expect("peer diagnostics hub poisoned");
        inner.pending.remove(&id);
    }
}

/// Asks the rotation loop to poll every connected client, then waits out the
/// answers.
///
/// Every client yields exactly one entry, whatever happens to it. Silence is
/// the outcome most worth reporting — a client that stops answering is what
/// half these bug reports are ABOUT — so a timeout becomes a recorded
/// failure rather than a missing section.
async fn collect_peer_diagnostics(
    rotation_tx: &mpsc::Sender<crate::rotation::RotationEvent>,
    lines: usize,
) -> Vec<PeerDiagnostics> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let request = crate::rotation::RotationEvent::RequestPeerDiagnostics(
        crate::rotation::PeerDiagnosticsArgs {
            lines: lines.min(u32::MAX as usize) as u32,
            reply: reply_tx,
        },
    );
    if rotation_tx.send(request).await.is_err() {
        return vec![PeerDiagnostics {
            label: "peers".to_string(),
            diagnostics: Err("the rotation loop is not accepting requests".to_string()),
        }];
    }
    // The rotation loop answers as soon as it drains its queue; if it is
    // wedged, that is itself the bug and must not hang the report.
    let pending = match tokio::time::timeout(PEER_DIAGNOSTICS_TIMEOUT, reply_rx).await {
        Ok(Ok(pending)) => pending,
        Ok(Err(_)) => {
            return vec![PeerDiagnostics {
                label: "peers".to_string(),
                diagnostics: Err("the rotation loop dropped the request".to_string()),
            }]
        }
        Err(_) => {
            return vec![PeerDiagnostics {
                label: "peers".to_string(),
                diagnostics: Err(format!(
                    "the rotation loop did not answer within {:?} — it appears wedged, which is \
                     itself worth reporting",
                    PEER_DIAGNOSTICS_TIMEOUT
                )),
            }]
        }
    };

    let hub = peer_diagnostics_hub();
    // ONE deadline for the whole roster rather than one per peer. Every
    // request is already in flight by the time we get here, so the peers are
    // answering in parallel whatever we do; billing each silent one its own
    // full timeout would only make the report take N times as long and push
    // it past the caller's budget (see PEER_SOCKET_TIMEOUT). A oneshot holds
    // its value, so a peer that answered while we were waiting on an earlier
    // one is still read here, without a wait of its own.
    let deadline = tokio::time::Instant::now() + PEER_DIAGNOSTICS_TIMEOUT;
    let mut out = Vec::with_capacity(pending.len());
    for peer in pending {
        let diagnostics = match peer.waiting {
            Err(reason) => Err(reason),
            Ok(rx) => match tokio::time::timeout_at(deadline, rx).await {
                Ok(Ok(reply)) => reply,
                Ok(Err(_)) => Err("the connection dropped before it answered".to_string()),
                Err(_) => {
                    // Stop the hub from holding an entry for an answer nobody
                    // is waiting for any more.
                    if let Some(id) = peer.request_id {
                        hub.cancel(id);
                    }
                    Err(format!("did not answer within {:?}", PEER_DIAGNOSTICS_TIMEOUT))
                }
            },
        };
        out.push(PeerDiagnostics {
            label: peer.label,
            diagnostics,
        });
    }
    out
}

/// One peer's contribution to a bundle: its diagnostics, or why they could
/// not be fetched. A peer that didn't answer is REPORTED rather than dropped
/// — "the client never replied" is itself evidence, and silently omitting it
/// would read as "there was no client".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerDiagnostics {
    /// How the peer is identified in the report (fingerprint prefix + addr).
    pub label: String,
    /// Result rather than Option so the failure travels with its reason;
    /// serialized as `{"Ok":…}` / `{"Err":…}`.
    pub diagnostics: std::result::Result<Diagnostics, String>,
}

/// The single response line sent back for every request.
#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Diagnostics>,
    /// Peer bundles, present only for a `diagnostics` request that asked for
    /// them and a server that has peers to ask.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerDiagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    fn ok_empty() -> Self {
        Response {
            ok: true,
            state: None,
            diagnostics: None,
            peers: Vec::new(),
            error: None,
        }
    }

    fn ok_state(state: impl Serialize) -> Self {
        // A state that fails to serialize must surface as an error, not as
        // {"ok":true} with no state — the CLI reads that as a daemon that
        // answered with nothing.
        match serde_json::to_value(state) {
            Ok(value) => Response {
                ok: true,
                state: Some(value),
                diagnostics: None,
                peers: Vec::new(),
                error: None,
            },
            Err(e) => Response::err(format!("failed to serialize the state: {}", e)),
        }
    }

    fn ok_diagnostics(diagnostics: Diagnostics, peers: Vec<PeerDiagnostics>) -> Self {
        Response {
            ok: true,
            state: None,
            diagnostics: Some(diagnostics),
            peers,
            error: None,
        }
    }

    fn err(error: impl Into<String>) -> Self {
        Response {
            ok: false,
            state: None,
            diagnostics: None,
            peers: Vec::new(),
            error: Some(error.into()),
        }
    }
}

/// A deferred effect of a command, executed only AFTER the response has been
/// written and flushed, so the peer reliably sees the ack first.
#[derive(Debug, PartialEq, Eq)]
enum PostAction {
    /// Graceful shutdown, then re-exec into the installed binary.
    Restart,
    /// Graceful shutdown.
    Exit,
    /// SIGTERM the spawned tray indicator. Deferred because the requester is
    /// usually the indicator itself (its "Hide tray icon" menu action): the
    /// ack must be on the wire before the requester is killed, or it would
    /// report its own hide as a failure.
    IndicatorHide,
}

/// Command/context bundle for the server socket.
pub struct ServerHandler {
    /// Structured live state, refreshed by the rotation loop.
    pub state: Arc<DiagnosticsMirror>,
    /// Commands enter the server events loop through the same channel as the
    /// hotkey/signal paths — the socket task never touches rotation state.
    pub event_tx: mpsc::Sender<Event>,
    /// Direct line to the rotation loop, for the one command that needs to
    /// reach the CLIENTS rather than the local input state: peer diagnostics
    /// (only the rotation loop owns the clients' bulk queues).
    pub rotation_tx: mpsc::Sender<crate::rotation::RotationEvent>,
    /// Whether the background auto-updater is running (update_now otherwise
    /// errors clearly instead of silently doing nothing).
    pub auto_update: bool,
    /// Hide/show control for the auto-spawned tray indicator.
    pub indicator: crate::indicator_spawn::SupervisorHandle,
}

/// Command/context bundle for the client socket.
pub struct ClientHandler {
    pub state: Arc<ClientStateMirror>,
    pub auto_update: bool,
    /// Hide/show control for the auto-spawned tray indicator.
    pub indicator: crate::indicator_spawn::SupervisorHandle,
}

pub enum Handler {
    Server(ServerHandler),
    Client(ClientHandler),
}

impl Handler {
    /// Validates and dispatches one request. Shared commands behave the same
    /// on both roles; rotation/pause are server-only (see module docs).
    async fn dispatch(&self, req: &Request) -> (Response, Option<PostAction>) {
        match req.cmd.as_str() {
            "status" => match self {
                Handler::Server(h) => match h.state.server_state() {
                    Some(state) => (Response::ok_state(State::Server(state)), None),
                    None => (
                        Response::err("state not available yet (rotation loop has not run)"),
                        None,
                    ),
                },
                Handler::Client(h) => (Response::ok_state(State::Client(h.state.snapshot())), None),
            },
            "diagnostics" => {
                let lines = requested_lines(req.lines);
                match self {
                    Handler::Server(h) => {
                        // Only a server has peers to ask.
                        let peers = if req.peer.unwrap_or(false) {
                            collect_peer_diagnostics(&h.rotation_tx, lines).await
                        } else {
                            Vec::new()
                        };
                        (
                            Response::ok_diagnostics(Diagnostics::server(&h.state, lines), peers),
                            None,
                        )
                    }
                    Handler::Client(h) => (
                        Response::ok_diagnostics(
                            Diagnostics::client(&h.state, lines),
                            Vec::new(),
                        ),
                        None,
                    ),
                }
            }
            "update_now" => {
                let auto_update = match self {
                    Handler::Server(h) => h.auto_update,
                    Handler::Client(h) => h.auto_update,
                };
                if auto_update {
                    // An explicit ask INSTALLS, where the daily check only
                    // reports: this command is what the tray's update action
                    // and `mx daemon update` are for, and a user who runs it
                    // means "do it", not "look again".
                    crate::autoupdate::request_install();
                    info!("Control socket: update requested");
                    (Response::ok_empty(), None)
                } else {
                    (
                        Response::err("auto-update is disabled (--no-auto-update)"),
                        None,
                    )
                }
            }
            "restart" => {
                info!("Control socket: restart requested");
                crate::mark_shutting_down();
                (Response::ok_empty(), Some(PostAction::Restart))
            }
            "exit" => {
                info!("Control socket: exit requested");
                crate::mark_shutting_down();
                (Response::ok_empty(), Some(PostAction::Exit))
            }
            "indicator" => {
                let indicator = match self {
                    Handler::Server(h) => &h.indicator,
                    Handler::Client(h) => &h.indicator,
                };
                match req.action.as_deref() {
                    // Deferred (see PostAction::IndicatorHide): the requester
                    // is usually the indicator about to be killed.
                    Some("hide") => {
                        info!("Control socket: tray indicator hide requested");
                        (Response::ok_empty(), Some(PostAction::IndicatorHide))
                    }
                    // Synchronous: spawn errors belong in the response.
                    Some("show") => {
                        info!("Control socket: tray indicator show requested");
                        match indicator.show() {
                            Ok(()) => (Response::ok_empty(), None),
                            Err(e) => (Response::err(format!("{:#}", e)), None),
                        }
                    }
                    _ => (
                        Response::err("indicator needs an action: hide|show"),
                        None,
                    ),
                }
            }
            "switch" | "pause" | "resume" => match self {
                Handler::Client(_) => (
                    Response::err(format!(
                        "'{}' is a server-side command (this is the client socket)",
                        req.cmd
                    )),
                    None,
                ),
                Handler::Server(h) => {
                    let event = match req.cmd.as_str() {
                        "switch" => match req.target.as_deref() {
                            Some("next") => Event::SwitchNext,
                            Some("prev") => Event::SwitchPrev,
                            Some("local") => Event::SwitchTo(String::new()),
                            Some(prefix) if !prefix.is_empty() => {
                                Event::SwitchTo(prefix.to_string())
                            }
                            _ => {
                                return (
                                    Response::err(
                                        "switch needs a target: next|prev|local|<fingerprint-prefix>",
                                    ),
                                    None,
                                )
                            }
                        },
                        "pause" => Event::SetPaused(true),
                        // "resume"
                        _ => Event::SetPaused(false),
                    };
                    // Origin evidence: a socket-driven switch/pause/resume is
                    // distinguishable from a chord-driven one in the log.
                    info!(
                        "Control socket: {} requested{}",
                        req.cmd,
                        req.target
                            .as_deref()
                            .map(|t| format!(" (target: {})", t))
                            .unwrap_or_default()
                    );
                    // Non-blocking hand-off: a full queue means the events
                    // loop is stalled, which the caller should know about
                    // instead of waiting on it.
                    match h.event_tx.try_send(event) {
                        Ok(()) => (Response::ok_empty(), None),
                        Err(_) => (
                            Response::err("server event queue is full (events loop stalled?)"),
                            None,
                        ),
                    }
                }
            },
            other => (Response::err(format!("unknown command '{}'", other)), None),
        }
    }
}

/// A bound control socket. Owns the socket file: dropping removes it, so a
/// clean shutdown never leaves a stale path behind. (A crash still can —
/// bind() reclaims stale files.)
pub struct Listener {
    listener: tokio::net::UnixListener,
    path: PathBuf,
}

impl Listener {
    /// Binds the default socket path for `role` (see socket_path).
    pub fn bind(role: Role) -> Result<Listener> {
        let dir = socket_dir();
        prepare_socket_dir(&dir)?;
        Self::bind_at(&dir.join(role.socket_name()), role.as_str())
    }

    /// Binds an explicit socket path. `role` is only used in error messages.
    fn bind_at(path: &Path, role: &str) -> Result<Listener> {
        if path.exists() {
            // A connect succeeds only when a live daemon owns the path: refuse
            // to hijack it. Otherwise it's a stale file from a crash; reclaim.
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                bail!(
                    "Refusing to take over control socket {}: another monux {} is serving it",
                    path.display(),
                    role
                );
            }
            std::fs::remove_file(path).with_context(|| {
                format!("Failed to remove stale control socket {}", path.display())
            })?;
        }
        let listener = tokio::net::UnixListener::bind(path)
            .with_context(|| format!("Failed to bind control socket {}", path.display()))?;
        info!("Control socket listening: {}", path.display());
        Ok(Listener {
            listener,
            path: path.to_path_buf(),
        })
    }

    /// Accepts connections forever; each is served by its own task so a slow
    /// or stuck peer never blocks the daemon's event loops (or other peers).
    pub async fn run(self, handler: Handler) -> Result<()> {
        use std::os::unix::io::AsRawFd;
        let handler = Arc::new(handler);
        let euid = unsafe { libc::geteuid() };
        loop {
            let (stream, _) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) if accept_error_is_transient(&e) => {
                    // Log and retry: a returned error would propagate out of
                    // the task, and Listener's Drop would then unlink the
                    // socket — a healthy daemon looking dead. The brief pause
                    // keeps a persistent condition (fd exhaustion) from
                    // spinning the loop.
                    warn!("Control socket accept failed (retrying): {:#}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => return Err(e).context("Control socket accept failed"),
            };
            // Identity comes from the kernel, not from the directory the
            // socket sits in (see the module docs' Security section). A
            // stranger reaching us at all is worth a WARN: on a correctly
            // set-up machine the socket dir already excludes them, so this
            // means the dir's protection is not doing its job.
            match peer_uid(stream.as_raw_fd()) {
                Ok(peer) if peer_uid_trusted(peer, euid, invoking_uid()) => {}
                Ok(peer) => {
                    warn!(
                        "Refused a control socket connection from uid {}: this daemon (uid {}) serves its own user only",
                        peer,
                        euid
                    );
                    continue;
                }
                Err(e) => {
                    warn!(
                        "Refused a control socket connection with unreadable credentials: {:#}",
                        e
                    );
                    continue;
                }
            }
            let handler = handler.clone();
            tokio::task::spawn(async move {
                if let Err(e) = serve_connection(stream, handler).await {
                    debug!("Control socket connection ended: {:?}", e);
                }
            });
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// accept() failures the listener must survive rather than propagate: fd
/// exhaustion (EMFILE/ENFILE) clears when something closes, ENOBUFS/ENOMEM
/// are similarly transient, and ECONNABORTED is just a peer that hung up
/// between connect and accept. Anything else (EBADF, ...) is a real fault
/// and still unwinds the task.
fn accept_error_is_transient(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EMFILE)
            | Some(libc::ENFILE)
            | Some(libc::ENOBUFS)
            | Some(libc::ENOMEM)
            | Some(libc::ECONNABORTED)
    )
}

/// Serves one control connection: newline-delimited requests in, one response
/// line each out, until the peer closes or misbehaves.
async fn serve_connection(stream: tokio::net::UnixStream, handler: Arc<Handler>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut read = read;
    loop {
        let mut line = String::new();
        // Bound the read itself, not just the result: take() presents EOF at
        // the cap, so read_line stops there instead of buffering a
        // never-terminated line without bound. The capacity-1 buffer reads
        // byte-by-byte, so it never swallows bytes belonging to the NEXT
        // request line (a connection may carry several, pipelined).
        let n = {
            let limited = AsyncReadExt::take(&mut read, MAX_REQUEST_LINE as u64 + 1);
            tokio::io::BufReader::with_capacity(1, limited)
                .read_line(&mut line)
                .await?
        };
        if n == 0 {
            return Ok(()); // peer closed
        }
        // The take() above admits one byte past the cap so an over-long line
        // is detectable rather than silently truncated; the line itself must
        // still fit, terminator included.
        if line.len() > MAX_REQUEST_LINE || !line.ends_with('\n') {
            return Err(anyhow!("request line exceeds {} bytes", MAX_REQUEST_LINE));
        }
        let (response, post_action) = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => handler.dispatch(&req).await,
            Err(e) => (Response::err(format!("invalid request: {}", e)), None),
        };
        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        write.write_all(out.as_bytes()).await?;
        write.flush().await?;
        // Deferred effects run only after the ack is on the wire.
        match post_action {
            Some(PostAction::Restart) => crate::autoupdate::schedule_restart(),
            Some(PostAction::Exit) => {
                // The same graceful shutdown as SIGTERM (main.rs).
                unsafe {
                    libc::kill(std::process::id() as i32, libc::SIGTERM);
                }
            }
            Some(PostAction::IndicatorHide) => {
                // hide() reaps the indicator child with a blocking wait (up
                // to TERM_GRACE of thread::sleep in terminate_and_reap), so
                // it must not run on this connection's async task.
                let indicator = match &*handler {
                    Handler::Server(h) => h.indicator.clone(),
                    Handler::Client(h) => h.indicator.clone(),
                };
                tokio::task::spawn_blocking(move || indicator.hide());
            }
            None => {}
        }
    }
}

/// Longest a synchronous socket request may block. The daemon answers in
/// microseconds (dispatch only reads mirrors or hands off to a channel), so
/// hitting this means the daemon is wedged; the tray indicator's poll loop
/// must not hang on that.
const SOCKET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Budget for the one request the daemon does NOT answer from memory: a
/// `diagnostics` that asks for the connected peers' bundles. Before it writes
/// a single byte the daemon may spend PEER_DIAGNOSTICS_TIMEOUT waiting for
/// the rotation loop to hand back the roster and another one waiting for the
/// clients themselves — and a silent client is precisely what the report is
/// usually about. A caller on SOCKET_TIMEOUT would walk away from a bundle
/// the daemon is about to produce and report the healthy daemon as "is monux
/// running?", so the budget is derived from PEER_DIAGNOSTICS_TIMEOUT (plus
/// slack for building and writing the bundle) instead of being an independent
/// constant the two sides can drift apart on.
const PEER_SOCKET_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(2 * PEER_DIAGNOSTICS_TIMEOUT.as_secs() + 2);

/// Sends one request to a control socket and returns the raw response line.
/// Synchronous with a short timeout: used by the short-lived
/// `monux status` CLI and the tray indicator's poll loop.
pub fn request_line(socket: &Path, request: &str) -> Result<String> {
    request_line_with_timeout(socket, request, SOCKET_TIMEOUT)
}

/// [`request_line`] with a caller-chosen budget, for the requests the daemon
/// cannot answer out of its mirrors (see PEER_SOCKET_TIMEOUT). The budget is
/// OVERALL, not per syscall: a same-user peer dribbling one byte per syscall
/// window must not hold the exchange open forever.
pub fn request_line_with_timeout(
    socket: &Path,
    request: &str,
    timeout: std::time::Duration,
) -> Result<String> {
    use std::io::{BufReader, Read, Write};
    use std::os::unix::io::AsRawFd;
    let stream = std::os::unix::net::UnixStream::connect(socket)
        .with_context(|| format!("Failed to connect to {}", socket.display()))?;
    // Who answers matters as much as what they answer: everything downstream
    // (status output, the tray, `daemon exit`'s ack, a diagnostics bundle
    // pasted into a bug report) is taken at face value, and the path alone
    // does not establish that a monux daemon of ours is on the other end.
    let peer = peer_uid(stream.as_raw_fd())?;
    let euid = unsafe { libc::geteuid() };
    if !peer_uid_trusted(peer, euid, invoking_uid()) {
        bail!(
            "Refusing to trust {}: it is served by uid {}, not by us (uid {}) — another user created it first, so its answers are not the daemon's; remove the directory or fix its ownership",
            socket.display(),
            peer,
            euid
        );
    }
    stream
        .set_read_timeout(Some(timeout))
        .context("Failed to set control socket read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("Failed to set control socket write timeout")?;
    let started = Instant::now();
    let mut writer = stream
        .try_clone()
        .context("Failed to clone control socket stream")?;
    writer.write_all(request.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    // The read deadline is OVERALL: a socket timeout expires per SYSCALL, so
    // a peer feeding us a byte per window would never trip it. Each read
    // gets only the budget that remains and elapsed is re-checked after
    // every return, so the deadline bounds the whole exchange no matter how
    // slowly the bytes trickle in.
    let mut response: Vec<u8> = Vec::new();
    let mut reader = BufReader::new(stream);
    loop {
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            bail!(
                "{} sent no complete response within {:?}",
                socket.display(),
                timeout
            );
        }
        reader
            .get_ref()
            .set_read_timeout(Some(timeout - elapsed))
            .context("Failed to re-arm control socket read timeout")?;
        let mut chunk = [0u8; 4096];
        match reader.read(&mut chunk) {
            // EOF mid-line keeps the partial response, as read_line did.
            Ok(0) if !response.is_empty() => break,
            Ok(0) => bail!("{} closed without a response", socket.display()),
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                if let Some(end) = response.iter().position(|&b| b == b'\n') {
                    // Anything past the first line is not ours to consume.
                    response.truncate(end + 1);
                    break;
                }
            }
            // A window expired with nothing read: loop and re-check the
            // deadline rather than failing on the spot.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e).context("Failed to read the control socket response"),
        }
    }
    let response =
        String::from_utf8(response).context("The control socket response was not valid UTF-8")?;
    Ok(response.trim_end().to_string())
}

/// Wire view of a response for the CLI (state parsed separately when ok).
#[derive(Deserialize)]
struct RawResponse {
    ok: bool,
    state: Option<serde_json::Value>,
    error: Option<String>,
}

/// Implements `monux status`: queries a daemon's control socket and
/// returns the text to print — the raw response line with `json`, otherwise a
/// human-readable summary. `server`/`client` restrict the default discovery
/// to that role's socket; `socket` overrides discovery entirely.
pub fn status_cli(
    server: bool,
    client: bool,
    socket: Option<&Path>,
    json: bool,
) -> Result<String> {
    let candidates: Vec<PathBuf> = match (socket, server, client) {
        (Some(path), _, _) => vec![path.to_path_buf()],
        (None, true, false) => vec![socket_path(Role::Server)],
        (None, false, true) => vec![socket_path(Role::Client)],
        (None, false, false) => {
            // Default: a machine usually runs either role — try the server
            // socket first, then the client's.
            vec![socket_path(Role::Server), socket_path(Role::Client)]
        }
        (None, true, true) => bail!("--server and --client are mutually exclusive"),
    };
    let (path, raw) = query_first(&candidates, r#"{"cmd":"status"}"#, SOCKET_TIMEOUT)?;
    format_status(&path, &raw, json)
}

/// Fetches a daemon's diagnostics bundle over the control socket, using the
/// same role discovery as `status_cli` (server socket first, then the
/// client's, unless a role or an explicit socket narrows it). Returns the
/// role that answered alongside the bundle, so the caller knows which
/// systemd unit's journal belongs with it.
///
/// `peer` asks a SERVER to include its connected clients' bundles; a client
/// daemon and older daemons ignore the flag and answer for themselves alone.
pub fn fetch_diagnostics(
    server: bool,
    client: bool,
    socket: Option<&Path>,
    lines: usize,
    peer: bool,
) -> Result<(Role, Diagnostics, Vec<PeerDiagnostics>)> {
    let candidates: Vec<PathBuf> = match (socket, server, client) {
        (Some(path), _, _) => vec![path.to_path_buf()],
        (None, true, false) => vec![socket_path(Role::Server)],
        (None, false, true) => vec![socket_path(Role::Client)],
        (None, false, false) => vec![socket_path(Role::Server), socket_path(Role::Client)],
        (None, true, true) => bail!("--server and --client are mutually exclusive"),
    };
    let request = serde_json::json!({
        "cmd": "diagnostics",
        "lines": lines,
        "peer": peer,
    })
    .to_string();
    // Asking for the peers turns this into the one request that waits on the
    // network before answering; the budget has to cover that (see
    // PEER_SOCKET_TIMEOUT) or the CLI abandons a bundle it is about to get.
    let timeout = if peer {
        PEER_SOCKET_TIMEOUT
    } else {
        SOCKET_TIMEOUT
    };
    let (path, raw) = query_first(&candidates, &request, timeout)?;
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("Malformed response from {}: {}", path.display(), raw))?;
    if parsed["ok"] != serde_json::Value::Bool(true) {
        bail!(
            "The daemon reported an error: {}",
            parsed["error"].as_str().unwrap_or("unknown error")
        );
    }
    let diagnostics: Diagnostics = serde_json::from_value(parsed["diagnostics"].clone())
        .with_context(|| format!("{} returned no diagnostics bundle", path.display()))?;
    // Peers are absent from an older daemon's response, and from any client's:
    // no peers is a normal answer, not a malformed one.
    let peers: Vec<PeerDiagnostics> = parsed
        .get("peers")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let role = Role::parse(&diagnostics.role)
        .with_context(|| format!("Unknown daemon role '{}'", diagnostics.role))?;
    Ok((role, diagnostics, peers))
}

/// Implements the `monux daemon` management verbs: sends a daemon-management
/// command (switch/pause/resume/restart/exit/update_now) to the control
/// socket (server socket first, then the client's) and returns the text to
/// print. The daemon's error string propagates — e.g. switch/pause from a
/// client socket, an unknown switch target, or --no-auto-update on update.
pub fn daemon_cli(request: &str, ok_message: &str, socket: Option<&Path>) -> Result<String> {
    let candidates: Vec<PathBuf> = match socket {
        Some(path) => vec![path.to_path_buf()],
        None => vec![socket_path(Role::Server), socket_path(Role::Client)],
    };
    let (path, raw) = query_first(&candidates, request, SOCKET_TIMEOUT)?;
    let response: RawResponse = serde_json::from_str(&raw)
        .with_context(|| format!("Malformed response from {}: {}", path.display(), raw))?;
    if !response.ok {
        bail!(
            "The daemon reported an error: {}",
            response.error.unwrap_or_default()
        );
    }
    Ok(ok_message.to_string())
}

/// Implements `monux gui tray hide|show`: sends the indicator hide/show
/// command to the daemon's control socket (server socket first, then the
/// client's, exactly like status discovery; `socket` overrides) and returns
/// the text to print. The daemon's error string propagates — e.g. the
/// refusal to override a --no-indicator daemon on show.
///
/// A `show` that finds no daemon on the DEFAULT discovery path doesn't
/// error: it spawns a standalone indicator instead (its not-running menu
/// doubles as a launcher — see indicator.rs). hide, and any explicit
/// --socket that doesn't answer, keep erroring (see tray_decision).
pub fn tray_cli(hide: bool, socket: Option<&Path>) -> Result<String> {
    let candidates: Vec<PathBuf> = match socket {
        Some(path) => vec![path.to_path_buf()],
        None => vec![socket_path(Role::Server), socket_path(Role::Client)],
    };
    let action = if hide { "hide" } else { "show" };
    let request = format!(r#"{{"cmd":"indicator","action":"{}"}}"#, action);
    let result = query_first(&candidates, &request, SOCKET_TIMEOUT);
    match (tray_decision(hide, socket.is_some(), result.is_ok()), result) {
        (TrayDecision::Unhide, Ok((path, raw))) => {
            let response: RawResponse = serde_json::from_str(&raw)
                .with_context(|| format!("Malformed response from {}: {}", path.display(), raw))?;
            if !response.ok {
                bail!(
                    "The daemon reported an error: {}",
                    response.error.unwrap_or_default()
                );
            }
            Ok(if hide {
                "Tray indicator hidden (no respawns until 'monux gui tray show' or a daemon restart)".to_string()
            } else {
                "Tray indicator shown".to_string()
            })
        }
        (TrayDecision::Standalone, Err(_)) => {
            crate::indicator_spawn::spawn_standalone()?;
            Ok("Tray indicator shown (standalone; no monux daemon running)".to_string())
        }
        (TrayDecision::Error, Err(e)) => Err(e),
        // tray_decision agrees with the query outcome by construction.
        _ => unreachable!("tray_decision disagrees with the query outcome"),
    }
}

/// What `monux gui tray hide|show` does with the socket-discovery outcome
/// (pure, so the matrix is testable without sockets): an answering daemon
/// takes the hide/show command as today; with no daemon answering, a `show`
/// on the default discovery path spawns a standalone indicator, while hide,
/// and any explicit --socket, keep erroring — the daemon they name must
/// exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrayDecision {
    /// A daemon answered: the socket command went through (or its error did).
    Unhide,
    /// No daemon on the default path: spawn a standalone indicator.
    Standalone,
    /// Propagate the query error.
    Error,
}

fn tray_decision(hide: bool, explicit_socket: bool, daemon_answered: bool) -> TrayDecision {
    if daemon_answered {
        return TrayDecision::Unhide;
    }
    if !hide && !explicit_socket {
        TrayDecision::Standalone
    } else {
        TrayDecision::Error
    }
}

/// Sends `request` to the first candidate socket that answers, returning the
/// answering path and the raw response line. The first socket that answers
/// wins; missing files and stale sockets (crash remnants) fall through to
/// the next candidate. `timeout` is per candidate — it bounds how long the
/// daemon has to answer, so it belongs to the REQUEST rather than to this
/// helper. Shared by status_cli, daemon_cli, tray_cli and fetch_diagnostics.
fn query_first(
    candidates: &[PathBuf],
    request: &str,
    timeout: std::time::Duration,
) -> Result<(PathBuf, String)> {
    let mut last_err = None;
    for path in candidates {
        if !path.exists() {
            continue;
        }
        match request_line_with_timeout(path, request, timeout) {
            Ok(raw) => return Ok((path.clone(), raw)),
            Err(e) => {
                debug!("Control socket {} unusable: {:?}", path.display(), e);
                last_err = Some(e);
            }
        }
    }
    match last_err {
        // A socket existed but didn't answer.
        Some(e) => Err(e).with_context(|| {
            format!(
                "Failed to query the monux daemon at {} — is monux running?",
                candidates
                    .iter()
                    .filter(|p| p.exists())
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }),
        None => bail!(
            "No monux control socket found (tried {}) — is monux running?",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Renders one raw status response line for the CLI: verbatim with `json`,
/// parsed and pretty-printed otherwise.
fn format_status(path: &Path, raw: &str, json: bool) -> Result<String> {
    if json {
        return Ok(raw.to_string());
    }
    let response: RawResponse = serde_json::from_str(raw)
        .with_context(|| format!("Malformed response from {}: {}", path.display(), raw))?;
    if !response.ok {
        bail!(
            "The daemon reported an error: {}",
            response.error.unwrap_or_default()
        );
    }
    let state: State = serde_json::from_value(response.state.context("The daemon returned no state")?)
        .with_context(|| format!("Unrecognized state from {}", path.display()))?;
    Ok(state.to_string().trim_end().to_string())
}


#[cfg(test)]
mod tests {
    use super::*;

    fn req(cmd: &str, target: Option<&str>) -> Request {
        Request {
            cmd: cmd.to_string(),
            target: target.map(|t| t.to_string()),
            action: None,
            lines: None,
            peer: None,
        }
    }

    fn req_action(cmd: &str, action: Option<&str>) -> Request {
        Request {
            cmd: cmd.to_string(),
            target: None,
            action: action.map(|a| a.to_string()),
            lines: None,
            peer: None,
        }
    }

    /// A supervisor handle whose daemon opted out of the indicator: no
    /// child, no task, and show() refuses — all without touching the
    /// environment or spawning processes.
    fn opted_out_indicator() -> crate::indicator_spawn::SupervisorHandle {
        let supervisor = crate::indicator_spawn::Supervisor::new(true);
        let handle = supervisor.handle();
        // The guard must outlive the handle: its Drop flips the shutdown
        // flag the handle checks (by design, for the daemon-exit window).
        // Test handlers never drop their fields anyway.
        std::mem::forget(supervisor);
        handle
    }

    fn server_handler(event_tx: mpsc::Sender<Event>, auto_update: bool) -> Handler {
        server_handler_with_rotation(event_tx, auto_update).0
    }

    /// A server handler plus the rotation receiver its peer-diagnostics
    /// requests land on, so a test can stand in for the rotation loop.
    fn server_handler_with_rotation(
        event_tx: mpsc::Sender<Event>,
        auto_update: bool,
    ) -> (Handler, mpsc::Receiver<crate::rotation::RotationEvent>) {
        let (rotation_tx, rotation_rx) = mpsc::channel(8);
        (
            Handler::Server(ServerHandler {
                state: Arc::new(DiagnosticsMirror::new("127.0.0.1:1".parse().unwrap())),
                event_tx,
                rotation_tx,
                auto_update,
                indicator: opted_out_indicator(),
            }),
            rotation_rx,
        )
    }

    fn client_handler(auto_update: bool) -> (Handler, Arc<ClientStateMirror>) {
        let mirror = Arc::new(ClientStateMirror::new("127.0.0.1:9999".parse().unwrap()));
        (
            Handler::Client(ClientHandler {
                state: mirror.clone(),
                auto_update,
                indicator: opted_out_indicator(),
            }),
            mirror,
        )
    }

    #[test]
    fn socket_dir_resolution() {
        // XDG_RUNTIME_DIR is honored (also the test override)...
        assert_eq!(
            socket_dir_from(Some(std::ffi::OsStr::new("/run/user/1000"))),
            PathBuf::from("/run/user/1000/monux")
        );
        // ...and unset/empty falls back to a per-user /tmp dir.
        let fallback = PathBuf::from(format!("/tmp/monux-{}", unsafe { libc::geteuid() }));
        assert_eq!(socket_dir_from(None), fallback);
        assert_eq!(socket_dir_from(Some(std::ffi::OsStr::new(""))), fallback);
    }

    #[test]
    fn socket_dir_owned_by_another_user_is_rejected() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let socket_dir = dir.path().join("monux");
        std::fs::create_dir_all(&socket_dir).unwrap();

        // Our own dir: prepare passes and locks it down to 0700.
        prepare_socket_dir(&socket_dir).unwrap();
        assert_eq!(
            std::fs::metadata(&socket_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let owner = std::fs::metadata(&socket_dir).unwrap().uid();
        ensure_dir_owner(&socket_dir, owner, unsafe { libc::geteuid() }, None).unwrap();

        // A dir owned by another user must be refused. (A foreign-owned dir
        // can't be chowned into existence without root, so the mismatch
        // branch is exercised with a uid that isn't the dir's owner.)
        let err = ensure_dir_owner(&socket_dir, owner, owner.wrapping_add(1), None).unwrap_err();
        assert!(
            format!("{:#}", err).contains("refusing to trust"),
            "unexpected error: {:#}",
            err
        );

        // The `sudo -E` fallback: a root daemon accepts a dir owned by the
        // INVOKING user (prepare_socket_dir fchowns it to them, which needs
        // root, so only the acceptance rule is exercised here) — but still
        // refuses everyone else.
        let invoker = owner.wrapping_add(2);
        ensure_dir_owner(&socket_dir, invoker, 0, Some(invoker)).unwrap();
        let err = ensure_dir_owner(&socket_dir, owner.wrapping_add(3), 0, Some(invoker))
            .unwrap_err();
        assert!(
            format!("{:#}", err).contains("refusing to trust"),
            "unexpected error: {:#}",
            err
        );

        // A dir that does not exist yet is created 0700 outright, never
        // created loose and tightened afterwards.
        let fresh = dir.path().join("fresh");
        prepare_socket_dir(&fresh).unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    /// A symlink planted at the socket dir's name — anyone can do that in the
    /// world-writable /tmp the fallback path lives in — must be refused, and
    /// its target left completely alone: the ownership check must not be
    /// satisfiable by the TARGET's uid, and the 0700 lockdown must not land
    /// on a directory we never meant to touch.
    #[test]
    fn a_symlinked_socket_dir_is_refused_and_its_target_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let planted = dir.path().join("monux");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        let err = prepare_socket_dir(&planted).unwrap_err();
        assert!(
            format!("{:#}", err).contains("symlink"),
            "unexpected error: {:#}",
            err
        );
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn only_our_own_user_and_root_may_use_a_control_socket() {
        // Same user: the ordinary case, both directions.
        assert!(peer_uid_trusted(1000, 1000, None));
        // Root: it can ptrace the daemon and replace its binary anyway.
        assert!(peer_uid_trusted(0, 1000, None));
        assert!(peer_uid_trusted(0, 0, None));
        // The documented `sudo -E monux server` fallback: a root daemon must
        // still answer the user who started it, or `mx status` and the tray
        // stop working against it.
        assert!(peer_uid_trusted(1000, 0, Some(1000)));
        // ...but only that user, and only while actually elevated.
        assert!(!peer_uid_trusted(1001, 0, Some(1000)));
        assert!(!peer_uid_trusted(1000, 0, None));
        // Any other local user is refused — the whole protocol assumes the
        // peer is us.
        assert!(!peer_uid_trusted(1001, 1000, None));
        assert!(!peer_uid_trusted(1000, 1001, Some(1000)));
    }

    #[test]
    fn transient_accept_errors_are_distinguished_from_fatal_ones() {
        for errno in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOBUFS,
            libc::ENOMEM,
            libc::ECONNABORTED,
        ] {
            assert!(
                accept_error_is_transient(&std::io::Error::from_raw_os_error(errno)),
                "errno {} must be treated as transient",
                errno
            );
        }
        // A real fault (or no errno at all) must still unwind the task.
        assert!(!accept_error_is_transient(&std::io::Error::from_raw_os_error(
            libc::EBADF
        )));
        assert!(!accept_error_is_transient(&std::io::Error::other("no errno")));
    }

    #[test]
    fn a_state_that_fails_to_serialize_becomes_an_error_response() {
        struct Unserializable;
        impl Serialize for Unserializable {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("boom"))
            }
        }
        // Not {"ok":true} with no state: the CLI would read that as a daemon
        // that answered with nothing.
        let resp = Response::ok_state(Unserializable);
        assert!(!resp.ok);
        assert!(resp.state.is_none());
        assert!(resp.error.unwrap().contains("serialize"));
    }

    #[test]
    fn request_parsing() {
        let r: Request = serde_json::from_str(r#"{"cmd":"status"}"#).unwrap();
        assert_eq!(r.cmd, "status");
        assert!(r.target.is_none());
        let r: Request = serde_json::from_str(r#"{"cmd":"switch","target":"d1d88653"}"#).unwrap();
        assert_eq!(r.cmd, "switch");
        assert_eq!(r.target.as_deref(), Some("d1d88653"));
        // The indicator command carries an action.
        let r: Request = serde_json::from_str(r#"{"cmd":"indicator","action":"hide"}"#).unwrap();
        assert_eq!(r.cmd, "indicator");
        assert_eq!(r.action.as_deref(), Some("hide"));
        assert!(r.target.is_none());
        // Unknown fields are ignored, so newer peers keep working.
        let r: Request = serde_json::from_str(r#"{"cmd":"exit","extra":42}"#).unwrap();
        assert_eq!(r.cmd, "exit");
        // Garbage is rejected by the caller as an invalid request.
        assert!(serde_json::from_str::<Request>("not json").is_err());
        assert!(serde_json::from_str::<Request>(r#"{"nope":1}"#).is_err());
    }

    #[test]
    fn response_wire_shapes() {
        // A command ack is exactly {"ok":true} — no state/error keys.
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&Response::ok_empty()).unwrap()).unwrap();
        assert_eq!(v, serde_json::json!({"ok": true}));
        // Failures are exactly {"ok":false,"error":"..."}.
        let v: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&Response::err("boom")).unwrap(),
        )
        .unwrap();
        assert_eq!(v, serde_json::json!({"ok": false, "error": "boom"}));
        // Status carries the state under "state".
        let (handler, _mirror) = client_handler(true);
        let mirror_state = match &handler {
            Handler::Client(h) => h.state.snapshot(),
            _ => unreachable!(),
        };
        let v: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&Response::ok_state(State::Client(mirror_state))).unwrap(),
        )
        .unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["state"]["role"], "client");
        assert!(v.get("error").is_none());
    }

    #[tokio::test]
    async fn server_commands_become_events() {
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let handler = server_handler(event_tx, false);

        // switch targets map onto the same events the hotkeys send.
        let (resp, post) = handler.dispatch(&req("switch", Some("next"))).await;
        assert!(resp.ok && post.is_none());
        assert!(matches!(event_rx.recv().await, Some(Event::SwitchNext)));
        let (resp, _) = handler.dispatch(&req("switch", Some("prev"))).await;
        assert!(resp.ok);
        assert!(matches!(event_rx.recv().await, Some(Event::SwitchPrev)));
        // "local" is the empty-fingerprint goto; a prefix goes through as-is.
        let (resp, _) = handler.dispatch(&req("switch", Some("local"))).await;
        assert!(resp.ok);
        match event_rx.recv().await {
            Some(Event::SwitchTo(f)) => assert!(f.is_empty()),
            other => panic!("expected SwitchTo, got {:?}", other),
        }
        let (resp, _) = handler.dispatch(&req("switch", Some("d1d8"))).await;
        assert!(resp.ok);
        match event_rx.recv().await {
            Some(Event::SwitchTo(f)) => assert_eq!(f, "d1d8"),
            other => panic!("expected SwitchTo, got {:?}", other),
        }
        // pause/resume are explicit state sets (idempotent downstream).
        let (resp, _) = handler.dispatch(&req("pause", None)).await;
        assert!(resp.ok);
        assert!(matches!(event_rx.recv().await, Some(Event::SetPaused(true))));
        let (resp, _) = handler.dispatch(&req("resume", None)).await;
        assert!(resp.ok);
        assert!(matches!(event_rx.recv().await, Some(Event::SetPaused(false))));

        // A switch without a target is a validation error, not an event.
        let (resp, _) = handler.dispatch(&req("switch", None)).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("needs a target"));
        let (resp, _) = handler.dispatch(&req("switch", Some(""))).await;
        assert!(!resp.ok);

        // Unknown commands are rejected.
        let (resp, _) = handler.dispatch(&req("explode", None)).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("unknown command"));

        // update_now errors clearly when the auto-updater isn't running.
        let (resp, _) = handler.dispatch(&req("update_now", None)).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("auto-update is disabled"));

        // restart/exit ack first and act after the response is flushed.
        let (resp, post) = handler.dispatch(&req("restart", None)).await;
        assert!(resp.ok && post == Some(PostAction::Restart));
        let (resp, post) = handler.dispatch(&req("exit", None)).await;
        assert!(resp.ok && post == Some(PostAction::Exit));

        // Status before the rotation loop's first refresh is a clear error.
        let (resp, _) = handler.dispatch(&req("status", None)).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("not available yet"));
    }

    #[tokio::test]
    async fn server_dispatch_reports_a_full_event_queue() {
        let (event_tx, _event_rx) = mpsc::channel(1);
        event_tx.try_send(Event::SwitchNext).unwrap(); // now full
        let handler = server_handler(event_tx, true);
        let (resp, _) = handler.dispatch(&req("pause", None)).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("queue is full"));
    }

    #[tokio::test]
    async fn client_socket_serves_only_its_command_set() {
        let (handler, _mirror) = client_handler(true);

        // status works and reports a disconnected client.
        let (resp, _) = handler.dispatch(&req("status", None)).await;
        assert!(resp.ok);
        let state = resp.state.unwrap();
        assert_eq!(state["role"], "client");
        assert_eq!(state["server"], "127.0.0.1:9999");
        assert_eq!(state["connected"], false);
        assert_eq!(state["active"], false);
        assert!(state["connected_since_secs"].is_null());
        assert!(state["rtt_ms"].is_null());
        assert!(state["lost_packets"].is_null());

        // Rotation and pause are server concepts: clear role error.
        for cmd in ["switch", "pause", "resume"] {
            let (resp, _) = handler.dispatch(&req(cmd, Some("next"))).await;
            assert!(!resp.ok, "{} must fail on the client socket", cmd);
            assert!(resp.error.unwrap().contains("server-side"));
        }

        // The lifecycle commands are shared.
        let (resp, _) = handler.dispatch(&req("update_now", None)).await;
        assert!(resp.ok);
        let (resp, post) = handler.dispatch(&req("exit", None)).await;
        assert!(resp.ok && post == Some(PostAction::Exit));
    }

    #[tokio::test]
    async fn indicator_command_maps_to_the_supervisor_handle() {
        // Both roles serve it (the test handles sit on opted-out
        // supervisors: no child, no task, show refused).
        let (event_tx, _event_rx) = mpsc::channel(8);
        let handler = server_handler(event_tx, false);
        // hide acks and defers the SIGTERM until after the response is on
        // the wire (the requester is usually the indicator itself).
        let (resp, post) = handler.dispatch(&req_action("indicator", Some("hide"))).await;
        assert!(resp.ok && post == Some(PostAction::IndicatorHide));
        // show must not override an explicit --no-indicator opt-out.
        let (resp, post) = handler.dispatch(&req_action("indicator", Some("show"))).await;
        assert!(!resp.ok && post.is_none());
        let err = resp.error.unwrap();
        assert!(err.contains("--no-indicator"), "unexpected error: {}", err);
        // Missing or unknown actions are validation errors.
        let (resp, _) = handler.dispatch(&req_action("indicator", None)).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("hide|show"));
        let (resp, _) = handler.dispatch(&req_action("indicator", Some("blink"))).await;
        assert!(!resp.ok);

        let (handler, _mirror) = client_handler(true);
        let (resp, post) = handler.dispatch(&req_action("indicator", Some("hide"))).await;
        assert!(resp.ok && post == Some(PostAction::IndicatorHide));
        let (resp, _) = handler.dispatch(&req_action("indicator", Some("show"))).await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("--no-indicator"));
    }

    #[tokio::test]
    async fn indicator_command_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.sock");
        let listener = Listener::bind_at(&path, "client").unwrap();
        let (handler, _mirror) = client_handler(true);
        let task = tokio::spawn(listener.run(handler));

        // hide: plain ack (the deferred effect runs after the response and
        // is a no-op here — the opted-out supervisor has no child).
        let raw = request(path.clone(), r#"{"cmd":"indicator","action":"hide"}"#).await;
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v, serde_json::json!({"ok": true}));
        // show on an opted-out daemon: the refusal comes back as an error.
        let raw = request(path.clone(), r#"{"cmd":"indicator","action":"show"}"#).await;
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("--no-indicator"));
        // An unknown action is a validation error, not a hang.
        let raw = request(path.clone(), r#"{"cmd":"indicator","action":"blink"}"#).await;
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("hide|show"));

        task.abort();
        let _ = task.await;
    }

    #[test]
    fn client_mirror_tracks_lifecycle() {
        let mirror = ClientStateMirror::new("127.0.0.1:9999".parse().unwrap());
        let state = mirror.snapshot();
        assert!(!state.connected && !state.active);

        mirror.set_server("127.0.0.1:8888".parse().unwrap());
        assert_eq!(mirror.snapshot().server, "127.0.0.1:8888");
        mirror.set_active(true);
        assert!(mirror.snapshot().active);
        // A drop clears active along with the connection.
        mirror.set_disconnected();
        let state = mirror.snapshot();
        assert!(!state.connected && !state.active);
    }

    /// Runs the synchronous request helper off the runtime: the test's
    /// single-threaded runtime must stay free to drive the accept loop.
    async fn request(path: PathBuf, req: &'static str) -> String {
        tokio::task::spawn_blocking(move || request_line(&path, req).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn socket_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.sock");
        let listener = Listener::bind_at(&path, "client").unwrap();
        let (handler, mirror) = client_handler(true);
        let task = tokio::spawn(listener.run(handler));

        // A status request gets the live client state as JSON.
        let raw = request(path.clone(), r#"{"cmd":"status"}"#).await;
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["state"]["role"], "client");
        assert_eq!(v["state"]["connected"], false);
        // Mirror updates are visible to later requests.
        mirror.set_active(true);
        let raw = request(path.clone(), r#"{"cmd":"status"}"#).await;
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["state"]["active"], true);

        // A server-only command on the client socket: clear error.
        let raw = request(path.clone(), r#"{"cmd":"switch","target":"next"}"#).await;
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("server-side"));

        // Invalid JSON gets a protocol-level error response, not a hang.
        let raw = request(path.clone(), "not json").await;
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("invalid request"));

        // Dropping the listener removes the socket file (clean shutdown).
        task.abort();
        let _ = task.await;
        assert!(!path.exists());
    }

    #[test]
    fn tray_decision_matrix() {
        // A daemon answered: the hide/show command goes through, as today.
        assert_eq!(tray_decision(true, false, true), TrayDecision::Unhide);
        assert_eq!(tray_decision(false, false, true), TrayDecision::Unhide);
        assert_eq!(tray_decision(false, true, true), TrayDecision::Unhide);
        // No daemon: 'show' on the default discovery path spawns a
        // standalone indicator...
        assert_eq!(tray_decision(false, false, false), TrayDecision::Standalone);
        // ...but hide (there is nothing to hide from) and any explicit
        // --socket (the user named the daemon they meant) keep erroring.
        assert_eq!(tray_decision(true, false, false), TrayDecision::Error);
        assert_eq!(tray_decision(false, true, false), TrayDecision::Error);
        assert_eq!(tray_decision(true, true, false), TrayDecision::Error);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn daemon_cli_sends_commands_and_propagates_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.sock");
        let listener = Listener::bind_at(&path, "server").unwrap();
        let (event_tx, _event_rx) = mpsc::channel(8);
        let task = tokio::spawn(listener.run(server_handler(event_tx, false)));
        // Let the listener come up before querying (connect would EAGAIN).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // ok:true passes the ok message through.
        let out = daemon_cli(r#"{"cmd":"pause"}"#, "fine", Some(&path)).unwrap();
        assert_eq!(out, "fine");
        // A daemon-side error (update without auto-update) propagates.
        let err = daemon_cli(r#"{"cmd":"update_now"}"#, "started", Some(&path)).unwrap_err();
        assert!(err.to_string().contains("The daemon reported an error"));

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn bind_reclaims_stale_socket_and_refuses_a_live_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.sock");
        // A leftover file that answers no connect (crash remnant): reclaimed.
        std::fs::write(&path, b"stale").unwrap();
        let listener = Listener::bind_at(&path, "server").unwrap();
        assert!(path.exists());
        // A live daemon owning the path: refused politely, not hijacked.
        let err = match Listener::bind_at(&path, "server") {
            Ok(_) => panic!("a second bind on a live socket must fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("Refusing"));
        drop(listener);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn pipelined_requests_work_and_oversized_lines_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.sock");
        let listener = Listener::bind_at(&path, "client").unwrap();
        let (handler, _mirror) = client_handler(true);
        let task = tokio::spawn(listener.run(handler));

        // Two requests written in one go (pipelined) on a single connection
        // each get their response: the bounded per-line read must not swallow
        // bytes belonging to the next line.
        let path2 = path.clone();
        let lines = tokio::task::spawn_blocking(move || {
            use std::io::{BufRead, BufReader, Write};
            let stream = std::os::unix::net::UnixStream::connect(&path2).unwrap();
            let mut writer = stream.try_clone().unwrap();
            writer
                .write_all(b"{\"cmd\":\"status\"}\n{\"cmd\":\"status\"}\n")
                .unwrap();
            writer.flush().unwrap();
            let mut reader = BufReader::new(stream);
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            let mut second = String::new();
            reader.read_line(&mut second).unwrap();
            (first, second)
        })
        .await
        .unwrap();
        assert!(lines.0.contains("\"ok\":true"), "{}", lines.0);
        assert!(lines.1.contains("\"ok\":true"), "{}", lines.1);

        // A never-terminated line longer than MAX_REQUEST_LINE is a protocol
        // error: the daemon closes the connection instead of buffering the
        // line without bound.
        let path3 = path.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::{BufRead, BufReader, Write};
            let stream = std::os::unix::net::UnixStream::connect(&path3).unwrap();
            let mut writer = stream.try_clone().unwrap();
            writer
                .write_all(&vec![b'a'; MAX_REQUEST_LINE + 100])
                .unwrap();
            writer.flush().unwrap();
            let mut line = String::new();
            match BufReader::new(stream).read_line(&mut line) {
                // Orderly close, or a reset from closing with our unread
                // bytes still queued: both mean no response was served.
                Ok(0) | Err(_) => {}
                Ok(n) => panic!("oversized line got {} response bytes: {:?}", n, line),
            }
        })
        .await
        .unwrap();

        task.abort();
        let _ = task.await;
    }

    /// A peer feeding us one byte per syscall window never trips a
    /// PER-SYSCALL timeout, so the request budget has to be overall: the
    /// exchange must fail at the deadline no matter how slowly the bytes
    /// trickle in.
    #[test]
    fn a_dribbling_peer_cannot_hold_the_exchange_past_its_budget() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let dribbler = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Read the request off, then answer one byte at a time, forever
            // (well within a per-syscall window) and never terminate the line.
            let mut sink = [0u8; 64];
            let _ = std::io::Read::read(&mut stream, &mut sink);
            loop {
                if stream.write_all(b"x").is_err() {
                    return; // the client gave up, as it should
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        });

        let budget = std::time::Duration::from_millis(300);
        let started = Instant::now();
        let err = request_line_with_timeout(&path, r#"{"cmd":"status"}"#, budget).unwrap_err();
        assert!(
            format!("{:#}", err).contains("no complete response"),
            "unexpected error: {:#}",
            err
        );
        assert!(
            started.elapsed() < budget * 4,
            "the exchange outlived its budget: {:?}",
            started.elapsed()
        );
        dribbler.join().unwrap();
    }

    #[test]
    fn state_parses_and_pretty_prints() {
        // The wire JSON parses into the tagged State enum by "role"...
        let server: State = serde_json::from_str(
            r#"{"role":"server","version":"1.4.0","protocol_version":8,"listen":"127.0.0.1:9999","paused":true,"current_target":"10.0.0.2:1213","clients":[{"addr":"10.0.0.2:1213","fingerprint":"d1d88653","connected_since_secs":42,"rtt_ms":1,"edge":"right"}],"clipboard":{"owner":"local","types":["text/plain"]},"update_available":"abc123"}"#,
        )
        .unwrap();
        let text = server.to_string();
        assert!(text.contains("monux server v1.4.0 (protocol 8)"));
        assert!(text.contains("current target: 10.0.0.2:1213"));
        assert!(text.contains("paused:         yes"));
        assert!(text.contains("available (abc123)"));
        assert!(text.contains(
            "10.0.0.2:1213 fingerprint d1d88653 (prefix: d1d88653) connected 42s ago, rtt 1ms, edge right"
        ));
        assert!(text.contains("owner:          local"));

        let client: State = serde_json::from_str(
            r#"{"role":"client","version":"1.4.0","protocol_version":8,"server":"10.0.0.1:1213","connected":true,"active":false,"connected_since_secs":42,"rtt_ms":1,"lost_packets":0}"#,
        )
        .unwrap();
        let text = client.to_string();
        assert!(text.contains("monux client v1.4.0 (protocol 8)"));
        assert!(text.contains("server:         10.0.0.1:1213"));
        assert!(text.contains("connected:      yes (for 42s, rtt 1ms, 0 packets lost)"));
    }

    #[tokio::test]
    async fn diagnostics_from_the_client_socket() {
        let (handler, mirror) = client_handler(true);
        mirror.set_server("10.0.0.1:1213".parse().unwrap());
        let (resp, post) = handler.dispatch(&req("diagnostics", None)).await;
        assert!(resp.ok && post.is_none());
        assert!(resp.state.is_none());
        let diag = resp.diagnostics.unwrap();
        assert_eq!(diag.role, "client");
        assert_eq!(diag.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(diag.protocol_version, PROTOCOL_VERSION);
        // The client state dump is the client mirror's rendering.
        assert!(diag.state_dump.contains("monux client"), "{}", diag.state_dump);
        assert!(diag.state_dump.contains("10.0.0.1:1213"), "{}", diag.state_dump);
        // No logging layer in tests: the buffer is simply empty.
        assert!(diag.recent_logs.is_empty());

        // The wire shape is {"ok":true,"diagnostics":{...}}.
        let v: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&Response::ok_diagnostics(diag, Vec::new())).unwrap(),
        )
        .unwrap();
        assert_eq!(v["ok"], true);
        assert!(v.get("state").is_none());
        assert!(v.get("error").is_none());
        // No peers were fetched, so the field is absent rather than empty —
        // an older CLI parsing this response must not trip over it.
        assert!(v.get("peers").is_none());
        for key in [
            "version",
            "protocol_version",
            "role",
            "state_dump",
            "recent_logs",
            "environment",
        ] {
            assert!(v["diagnostics"].get(key).is_some(), "missing {}", key);
        }
    }

    #[test]
    fn a_diagnostics_request_may_ask_for_more_log_lines() {
        // Absent means the socket default; a request is free to ask for more.
        assert_eq!(requested_lines(None), crate::logging::RECENT_LOGS_DEFAULT);
        assert_eq!(requested_lines(Some(10)), 10);
        // Asking for more than the ring holds yields the whole ring, not an
        // error: a bug report must never fail over a tuning knob.
        assert_eq!(
            requested_lines(Some(usize::MAX)),
            crate::logging::RECENT_LOGS_MAX
        );
    }

    #[test]
    fn a_request_line_parses_without_the_newer_fields() {
        // An older client (or a hand-written socat line) sends neither
        // "lines" nor "peer"; both must default rather than fail the parse.
        let req: Request = serde_json::from_str(r#"{"cmd":"diagnostics"}"#).unwrap();
        assert_eq!(req.cmd, "diagnostics");
        assert!(req.lines.is_none());
        assert!(req.peer.is_none());

        let req: Request =
            serde_json::from_str(r#"{"cmd":"diagnostics","lines":200,"peer":true}"#).unwrap();
        assert_eq!(req.lines, Some(200));
        assert_eq!(req.peer, Some(true));
    }

    #[test]
    fn a_diagnostics_response_parses_without_the_environment() {
        // A freshly installed CLI talking to a daemon from before the
        // environment field existed: the bundle parses, minus that section.
        let raw = r#"{"version":"11.0.0","protocol_version":17,"role":"server",
                      "state_dump":"x","recent_logs":[]}"#;
        let d: Diagnostics = serde_json::from_str(raw).unwrap();
        assert_eq!(d.role, "server");
        assert_eq!(d.environment, crate::diagnostics::Environment::default());
    }

    #[tokio::test]
    async fn a_peer_request_reaches_the_rotation_loop_and_its_answers_come_back() {
        let (event_tx, _event_rx) = mpsc::channel(8);
        let (handler, mut rotation_rx) = server_handler_with_rotation(event_tx, false);

        // Stand in for the rotation loop: answer with one reachable client
        // and one that is too old to ask.
        let hub = peer_diagnostics_hub();
        let peer_a: SocketAddr = "10.0.0.5:1213".parse().unwrap();
        let fake_rotation = tokio::spawn(async move {
            let event = rotation_rx.recv().await.expect("a request must arrive");
            let crate::rotation::RotationEvent::RequestPeerDiagnostics(args) = event else {
                panic!("expected a peer diagnostics request");
            };
            assert_eq!(args.lines, crate::logging::RECENT_LOGS_DEFAULT as u32);
            let (id, rx) = hub.open(peer_a);
            args.reply
                .send(vec![
                    crate::rotation::PendingPeer {
                        label: "aabbccdd @ 10.0.0.5:1213".to_string(),
                        waiting: Ok(rx),
                        request_id: Some(id),
                    },
                    crate::rotation::PendingPeer {
                        label: "eeff0011 @ 10.0.0.6:1213".to_string(),
                        waiting: Err("runs protocol v17".to_string()),
                        request_id: None,
                    },
                ])
                .expect("the requester is still waiting");
            // The client answers a moment later, as it would over the wire.
            let mut answer = Diagnostics {
                version: "12.0.0".to_string(),
                protocol_version: PROTOCOL_VERSION,
                role: "client".to_string(),
                state_dump: "connected=true".to_string(),
                recent_logs: vec!["INFO monux::client: linked".to_string()],
                environment: Default::default(),
            };
            answer.state_dump = "connected=true".to_string();
            hub.complete(peer_a, id, Ok(answer));
        });

        let mut req = req("diagnostics", None);
        req.peer = Some(true);
        let (resp, _) = handler.dispatch(&req).await;
        fake_rotation.await.unwrap();

        assert!(resp.ok);
        assert_eq!(resp.peers.len(), 2);
        let reachable = &resp.peers[0];
        assert_eq!(reachable.label, "aabbccdd @ 10.0.0.5:1213");
        assert_eq!(
            reachable.diagnostics.as_ref().unwrap().state_dump,
            "connected=true"
        );
        // The peer that could not be asked is REPORTED, not dropped: a
        // missing section would read as "there was no second client".
        let skipped = &resp.peers[1];
        assert_eq!(skipped.label, "eeff0011 @ 10.0.0.6:1213");
        assert_eq!(skipped.diagnostics.as_ref().unwrap_err(), "runs protocol v17");
    }

    #[tokio::test]
    async fn a_diagnostics_request_without_peer_never_asks_the_rotation_loop() {
        let (event_tx, _event_rx) = mpsc::channel(8);
        let (handler, mut rotation_rx) = server_handler_with_rotation(event_tx, false);
        let (resp, _) = handler.dispatch(&req("diagnostics", None)).await;
        assert!(resp.ok);
        assert!(resp.peers.is_empty());
        // Nothing was sent: the plain bundle must not touch the clients.
        assert!(rotation_rx.try_recv().is_err());
    }

    /// Three silent peers must cost the SAME wait as one: the deadline is
    /// shared across the roster. Waiting on them one after another used to
    /// bill each its own timeout, which took the response past the CLI's
    /// budget and turned a healthy daemon into "is monux running?".
    #[tokio::test]
    async fn silent_peers_are_recorded_and_share_one_deadline() {
        let (event_tx, _event_rx) = mpsc::channel(8);
        let (handler, mut rotation_rx) = server_handler_with_rotation(event_tx, false);
        let hub = peer_diagnostics_hub();
        let fake_rotation = tokio::spawn(async move {
            let event = rotation_rx.recv().await.expect("a request must arrive");
            let crate::rotation::RotationEvent::RequestPeerDiagnostics(args) = event else {
                panic!("expected a peer diagnostics request");
            };
            // None of them is ever completed: wedged clients, or links that
            // black-hole.
            let pending: Vec<_> = (0..3)
                .map(|i| {
                    let (id, rx) = hub.open(format!("10.0.0.{}:1213", 5 + i).parse().unwrap());
                    (
                        id,
                        crate::rotation::PendingPeer {
                            label: format!("aabbccd{} @ 10.0.0.{}:1213", i, 5 + i),
                            waiting: Ok(rx),
                            request_id: Some(id),
                        },
                    )
                })
                .collect();
            let (ids, peers): (Vec<u64>, Vec<_>) = pending.into_iter().unzip();
            args.reply.send(peers).expect("the requester is still waiting");
            ids
        });

        let mut req = req("diagnostics", None);
        req.peer = Some(true);
        let started = std::time::Instant::now();
        let (resp, _) = handler.dispatch(&req).await;
        let ids = fake_rotation.await.unwrap();

        assert!(resp.ok);
        assert_eq!(resp.peers.len(), 3);
        for peer in &resp.peers {
            let err = peer.diagnostics.as_ref().unwrap_err();
            assert!(err.contains("did not answer"), "{}", err);
        }
        // One timeout for the roster, not one per peer.
        assert!(
            started.elapsed() < PEER_DIAGNOSTICS_TIMEOUT * 2,
            "three silent peers took {:?}",
            started.elapsed()
        );
        // And the hub kept no entry for answers nobody awaits any more.
        for id in ids {
            hub.complete("10.0.0.5:1213".parse().unwrap(), id, Err("late".to_string()));
        }
    }

    /// The CLI half must outwait the daemon half on a peer request. The
    /// daemon writes nothing until it has polled its clients, which takes
    /// longer than the budget every other command gets — a plain
    /// SOCKET_TIMEOUT here made `monux diagnostics --peer` report a healthy
    /// daemon as absent and fall back to an offline bundle.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_peer_diagnostics_fetch_outwaits_the_daemon_side_collection() {
        // The budget has to cover both of the daemon's waits (the rotation
        // loop's, then the roster's) before a byte is written.
        assert!(PEER_SOCKET_TIMEOUT > PEER_DIAGNOSTICS_TIMEOUT * 2);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.sock");
        let listener = Listener::bind_at(&path, "server").unwrap();
        let (event_tx, _event_rx) = mpsc::channel(8);
        let (handler, mut rotation_rx) = server_handler_with_rotation(event_tx, false);
        let task = tokio::spawn(listener.run(handler));
        // Stand in for a rotation loop that takes its time — longer than the
        // ordinary SOCKET_TIMEOUT, well inside the peer budget.
        let fake_rotation = tokio::spawn(async move {
            let event = rotation_rx.recv().await.expect("a request must arrive");
            let crate::rotation::RotationEvent::RequestPeerDiagnostics(args) = event else {
                panic!("expected a peer diagnostics request");
            };
            tokio::time::sleep(SOCKET_TIMEOUT + std::time::Duration::from_millis(500)).await;
            args.reply.send(Vec::new()).expect("the requester is still waiting");
        });
        // Let the listener come up before querying (connect would EAGAIN).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let queried = path.clone();
        let fetched = tokio::task::spawn_blocking(move || {
            fetch_diagnostics(true, false, Some(&queried), 10, true)
        })
        .await
        .unwrap();
        fake_rotation.await.unwrap();
        let (role, diagnostics, peers) = fetched.expect("the daemon answered, just not quickly");
        assert_eq!(role, Role::Server);
        assert_eq!(diagnostics.role, "server");
        assert!(peers.is_empty());

        task.abort();
        let _ = task.await;
    }

    #[test]
    fn the_hub_correlates_answers_and_forgets_cancelled_requests() {
        let hub = PeerDiagnosticsHub::new();
        let a: SocketAddr = "10.0.0.5:1213".parse().unwrap();
        let b: SocketAddr = "10.0.0.6:1213".parse().unwrap();
        let (id_a, mut rx_a) = hub.open(a);
        let (id_b, mut rx_b) = hub.open(b);
        assert_ne!(id_a, id_b, "ids must not collide");

        hub.complete(a, id_a, Err("nope".to_string()));
        assert_eq!(rx_a.try_recv().unwrap().unwrap_err(), "nope");

        // A cancelled request's answer is dropped, not misdelivered.
        hub.cancel(id_b);
        hub.complete(b, id_b, Err("late".to_string()));
        assert!(rx_b.try_recv().is_err());

        // An id that was never opened is ignored rather than panicking.
        hub.complete(a, 9999, Err("unknown".to_string()));
    }

    /// Ids are a sequential counter handed out one per connected client in a
    /// tight loop, so a client can guess its neighbour's and answer first —
    /// putting a bundle of its choosing under the other machine's label in the
    /// operator's bug report. Only the peer that was asked may answer.
    #[test]
    fn a_peer_cannot_answer_a_request_addressed_to_another_peer() {
        let hub = PeerDiagnosticsHub::new();
        let asked: SocketAddr = "10.0.0.5:1213".parse().unwrap();
        let impostor: SocketAddr = "10.0.0.6:1213".parse().unwrap();
        let (id, mut rx) = hub.open(asked);

        hub.complete(impostor, id, Err("forged".to_string()));
        assert!(
            rx.try_recv().is_err(),
            "a peer that was not asked must not be able to answer"
        );

        // The real answer still lands afterwards: the forgery must not have
        // consumed the entry either.
        hub.complete(asked, id, Err("genuine".to_string()));
        assert_eq!(rx.try_recv().unwrap().unwrap_err(), "genuine");
    }

    #[test]
    fn roles_round_trip_through_their_wire_string() {
        for role in [Role::Server, Role::Client] {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert_eq!(Role::parse("nonsense"), None);
    }

    #[tokio::test]
    async fn diagnostics_from_the_server_socket() {
        let (event_tx, _event_rx) = mpsc::channel(8);
        let handler = server_handler(event_tx, true);
        let (resp, post) = handler.dispatch(&req("diagnostics", None)).await;
        assert!(resp.ok && post.is_none());
        let diag = resp.diagnostics.unwrap();
        assert_eq!(diag.role, "server");
        // The server state dump is the SIGHUP rotation dump string; it works
        // even before the rotation loop's first iteration.
        assert!(
            diag.state_dump.contains("rotation loop last completed an iteration"),
            "{}",
            diag.state_dump
        );
    }
}
