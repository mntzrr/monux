use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use quinn::{SendDatagramError, SendStream};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task;
use tracing::{debug, error, info, trace, warn};

pub mod clipboard;
pub mod edges;
pub mod link;
pub mod liveness;
pub mod motion;
pub mod roster;

pub use link::{BulkQueueError, ClientLink, LinkStats, QuicClientLink};
pub use liveness::{
    PING_INTERVAL, PONG_MISS_LIMIT, REACTIVATE_COOLDOWN, REACTIVATE_PONGS, WWW_PONG_MISS_LIMIT,
};

use link::{fingerprint_prefix, ClientInfo};
use liveness::{Heard, LivenessTracker};
use clipboard::{types_equal, ClipboardRouter, ClipboardTarget, Update as ClipboardUpdate};
use edges::{edge_info_directions, EdgeDirectionsCache};
use motion::{is_pure_pointer_motion, MotionCoalescer};
use roster::{ClientRoster, GotoResolution};

use crate::clipboard::{CLIPBOARD_SERVE_TIMEOUT_SECS, data, server};
use crate::device;
use crate::edge;
use crate::msgs::{bulk, event, shared};
use crate::network::link_quality::{LinkQuality, Tier};
use crate::network::throttle::{self, SharedThrottle};
use crate::network::transport::NetworkMode;

/// If the selected client reconnects within this long after being removed, then reselect it
/// automatically. This is intended to help with fast recovery following networking flakes.
/// Sized against the LAN QUIC idle timeout (transport.rs): a client that only learns of the
/// drop via the 25s idle timeout needs ~25s to detect it plus an immediate first reconnect
/// attempt; 45s leaves margin for a couple of backoff steps on top of that worst case.
const REMOVED_CLIENT_RECOVERY_DEADLINE: Duration = Duration::from_secs(45);

/// How the pointer-motion flush rate is chosen (see --motion-hz).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MotionMode {
    /// 250 Hz normally, raised to 500 Hz while the current client's link
    /// measures in the proximity tier (adaptive fidelity, the default).
    Adaptive,
    /// Pinned by an explicit --motion-hz: Some(interval), or None for
    /// --motion-hz 0 (forward every event as it comes, e.g. gaming).
    Pinned(Option<Duration>),
}

/// How the per-connection bulk pacing rate is chosen (see --bulk-throttle-mbps).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ThrottleMode {
    /// 40 Mbps normally, raised to 160 Mbps while the connection's link
    /// measures in the proximity tier (adaptive fidelity, the default).
    Adaptive,
    /// Pinned by an explicit --bulk-throttle-mbps: Some(mbps), or None for 0
    /// (unthrottled).
    Pinned(Option<f64>),
}

/// Adaptive-fidelity rates (see MotionMode/ThrottleMode and
/// network::link_quality for the tier state machine).
pub const ADAPTIVE_MOTION_NORMAL_HZ: u32 = 250;
pub const ADAPTIVE_MOTION_PROXIMITY_HZ: u32 = 500;
pub const ADAPTIVE_THROTTLE_NORMAL_MBPS: f64 = 40.0;
pub const ADAPTIVE_THROTTLE_PROXIMITY_MBPS: f64 = 160.0;

/// The effective bulk pacing rate for a link tier under a throttle mode.
pub fn effective_throttle_mbps(mode: &ThrottleMode, tier: Tier) -> Option<f64> {
    match mode {
        ThrottleMode::Pinned(mbps) => *mbps,
        ThrottleMode::Adaptive => Some(match tier {
            Tier::Normal => ADAPTIVE_THROTTLE_NORMAL_MBPS,
            Tier::Proximity => ADAPTIVE_THROTTLE_PROXIMITY_MBPS,
        }),
    }
}

/// Name of the file (inside the config dir) recording the fingerprint of the
/// client currently switched active. Written on every switch to a client and
/// removed on switch back to the local machine. It deliberately survives
/// shutdown, graceful or not: the next server instance uses it to re-activate
/// that client when it reconnects, making restarts (e.g. after an update)
/// seamless. Staleness is bounded by ACTIVE_CLIENT_MAX_AGE.
pub const ACTIVE_CLIENT_STATE_FILE: &str = "active_client";

/// How old the active-client state may be before it is ignored on startup.
/// Resumption is expected soon after the previous stop (crash or update);
/// resuming a days-old session would be surprising.
const ACTIVE_CLIENT_MAX_AGE: Duration = Duration::from_secs(3600);

/// Minimum spacing between processed clipboard source updates, per source
/// (the local machine, or each client endpoint). Clipboard managers
/// (wl-clip-persist, wl-paste --watch) can turn one copy into dozens of
/// updates per second; each processed update costs a fresh wayland
/// connection and data source on the compositor, so bursts are collapsed.
/// Per-source, because one source's burst must not drop another source's
/// update (e.g. a client's deactivate-announcement landing right after a
/// local update). The LOCAL source debounces trailing-edge — an update
/// inside the window is remembered and the newest one is applied when the
/// window expires — because a dropped local state (fast double Ctrl+C) is
/// never re-sent and would be lost outright. Remote sources use a plain
/// leading-edge check: their announcements are switch-driven one-shots
/// spaced by SWITCH_DEBOUNCE, so there is no final state to lose.
const CLIPBOARD_UPDATE_DEBOUNCE: Duration = Duration::from_millis(300);

/// Minimum spacing between processed rotation switches TO A CLIENT (next/prev).
/// When the rotation loop is briefly blocked (e.g. a network hiccup delaying a
/// write), every frustrated shortcut press queues another switch; without a
/// debounce they then execute back-to-back and the rotation ends up on a random
/// side. Switches back to the LOCAL machine are exempt: they ungrab the input
/// devices, so they are the escape hatch and must always work — a debounced
/// switch-away presents as dead keys with the client keeping the grab (see
/// switch_allowed).
const SWITCH_DEBOUNCE: Duration = Duration::from_millis(500);

/// RTT above which a client's link is called degraded in the input-status
/// heartbeat (mirrors LINK_RTT_WARN in client.rs). Only crossings are logged
/// — the heartbeat fires every 10s, so healthy links must stay silent.
const HEARTBEAT_LINK_RTT_WARN: Duration = Duration::from_millis(50);

/// Minimum spacing between diagnostics mirror refreshes (see
/// update_diagnostics). The refresh builds the full control-socket snapshot
/// and is invoked after EVERY rotation loop iteration — thousands of times a
/// second at high input rates. 10Hz is plenty for a diagnostics mirror: the
/// SIGHUP dump and the control status simply run up to 100ms stale.
const DIAGNOSTICS_REFRESH_INTERVAL: Duration = Duration::from_millis(100);

/// Keeps track of the most recently disconnected client,
/// used for automatically reactivating clients if they reconnect quickly.
#[derive(Debug)]
struct DefunctClientInfo {
    /// Use the endpoint, not the fingerprint, to identify recently disconnected clients.
    /// This reduces the likelihood of weird behavior if e.g. clients are sharing certificates.
    /// In practice we only address clients by certificate with certain keyboard shortcuts.
    endpoint: SocketAddr,
    removed_at: Instant,
}

impl DefunctClientInfo {
    /// Returns whether the specified endpoint should be reenabled as the selected client.
    /// true is returned if the IPs match and if the defunct client was disconnected <= N seconds ago.
    fn recoverable(&self, endpoint: SocketAddr, now: &Instant) -> bool {
        // Only check IP, port is expected to change
        endpoint.ip() == self.endpoint.ip() && !self.expired(now)
    }

    /// Returns whether this defunct client info has expired, in which case it can be cleared.
    fn expired(&self, now: &Instant) -> bool {
        now.duration_since(self.removed_at) > REMOVED_CLIENT_RECOVERY_DEADLINE
    }
}

/// Per-client adaptive-fidelity state (see network::link_quality), keyed by
/// endpoint in lockstep with the roster (inserted on add, removed on removal).
/// Kept beside ClientInfo rather than inside it: the tier machine is about
/// the link's measured quality over time, not about the connection handle.
struct ClientLinkState {
    /// The tier tracker fed by connection-stat samples.
    quality: LinkQuality,
    /// Counters the windowed loss rate is diffed against (last sample).
    last_sent: u64,
    last_lost: u64,
    /// The live pacing-rate cell shared with this client's bulk writer task;
    /// rewritten on every tier transition.
    throttle: SharedThrottle,
    /// The degraded-link log's last-reported state (see log_input_status):
    /// only rtt-threshold CROSSINGS log, so a chronically bad link doesn't
    /// add an INFO line per heartbeat window.
    degraded: bool,
}

/// The degraded-link transition for this heartbeat window, if any: Some(true)
/// = healthy→degraded, Some(false) = degraded→healthy. Only crossings are
/// reported — the heartbeat fires every 10s, so a chronically bad link must
/// not spam an INFO line per window.
fn degraded_link_transition(was_degraded: &mut bool, rtt: Duration) -> Option<bool> {
    let is_degraded = rtt > HEARTBEAT_LINK_RTT_WARN;
    let crossed = is_degraded != *was_degraded;
    *was_degraded = is_degraded;
    crossed.then_some(is_degraded)
}

pub enum RotationEvent {
    /// Request to add a client to the rotation
    AddClient(AddClientArgs),
    /// Request to remove a disconnected client from the rotation.
    /// If the client currently owns the clipboard, that status is cleared.
    /// Internal channel message only (never on the wire). Ignored when
    /// conn_token doesn't match the stored entry: the endpoint was reused by
    /// a newer connection and the removal belongs to the dead old one.
    RemoveClient {
        endpoint: SocketAddr,
        conn_token: u64,
    },
    /// Request to update the current clipboard location and info
    ClipboardUpdateSource(ClipboardUpdateSourceArgs),
    /// Request to fetch a current clipboard's content
    ClipboardRequestContent(ClipboardRequestContentArgs),
    /// Request to send a current clipboard's content in response to a prior request
    ClipboardSendContent(ClipboardSendContentArgs),
    /// Anything was received from a client (proof of liveness; see
    /// ServerEvent::Ping). Internal channel message only (never on the wire).
    ClientHeardFrom { endpoint: SocketAddr },
    /// A client asked the server to take input back (client-initiated return
    /// via screen-edge detection on the client; see ClientEvent::SwitchRequest).
    /// Internal channel message only (never on the wire).
    SwitchRequest { endpoint: SocketAddr },
    /// A serialized bulk frame produced by a spawned task (the server's own
    /// clipboard serve), to be queued on a client's bulk writer.
    ///
    /// Routed through the loop rather than queued directly because only the
    /// loop owns the client links (see ClientLink) — which also means the
    /// full-queue policy lives in exactly one place (send_bulk drops the
    /// client) instead of being restated at every call site. The frame moves
    /// through the channel; nothing is copied.
    SendBulkFrame {
        endpoint: SocketAddr,
        frame: Vec<u8>,
        /// Guards a reconnect that replaced the entry meanwhile.
        conn_token: u64,
    },

    /// Ask every connected client for its diagnostics bundle, for a bug
    /// report that covers both machines (`monux diagnostics --peer`).
    /// Internal channel message only; the requests themselves go out as
    /// bulk::ServerBulk::DiagnosticsRequest. Handled by the rotation loop
    /// because only it owns the clients' bulk queues.
    RequestPeerDiagnostics(PeerDiagnosticsArgs),
}

pub struct PeerDiagnosticsArgs {
    /// Recent log lines to ask each client for.
    pub lines: u32,
    /// Carries back one entry per connected client, so the requester can
    /// await the answers without ever touching the client list itself.
    pub reply: tokio::sync::oneshot::Sender<Vec<PendingPeer>>,
}

/// One client the rotation loop tried to ask.
#[derive(Debug)]
pub struct PendingPeer {
    /// How the client appears in the report: fingerprint prefix and address.
    pub label: String,
    /// The channel its answer will arrive on, or why it was never asked.
    pub waiting: std::result::Result<tokio::sync::oneshot::Receiver<crate::control::PeerReply>, String>,
    /// The hub id to cancel if the wait expires.
    pub request_id: Option<u64>,
}

pub struct AddClientArgs {
    pub endpoint: SocketAddr,
    pub fingerprint: String,
    pub events_send: SendStream,
    pub bulk_send: SendStream,
    pub conn: quinn::Connection,
    /// Token of the accepted connection (see ClientInfo::conn_token).
    pub conn_token: u64,
    /// Protocol version negotiated with this client (see
    /// ClientInfo::negotiated_version).
    pub negotiated_version: u64,
}

/// Outcome of a pointer-motion datagram send attempt.
enum MotionSend {
    Sent,
    /// The peer can't do datagrams (permanently disabled); use the stream.
    Fallback,
    /// Not queued right now (see SendDatagramError::TooLarge); the caller
    /// keeps the deltas pending and retries on the next opportunity.
    Retry,
}

/// Logs any traced key events (MONUX_TRACE_KEYS) in this batch with the
/// routing decision taken, so a dying keypress can be followed through the
/// pipeline in the wild.
fn keytrace_route(events: &[event::InputEvent], decision: &str) {
    const EV_KEY: u16 = evdev::EventType::KEY.0;
    for e in events {
        if let Some(i) = &e.inputi32 {
            if i.type_ == EV_KEY && device::key_traced(i.code) {
                info!(
                    "KEYTRACE route: {} code={} value={}",
                    decision, i.code, i.value
                );
            }
        }
    }
}

pub struct ClipboardUpdateSourceArgs {
    pub source: Option<SocketAddr>,
    pub types: Vec<String>,
    // min of source_client_max (if any), and server_max:
    pub max_size_bytes: u64,
}

pub struct ClipboardRequestContentArgs {
    pub request_source: ClipboardRequestSource,
    pub requested_type: String,
    pub max_size_bytes: u64,
    /// The request id assigned by the originator.
    /// None when the request originates locally on the server (an id is assigned
    /// during routing); Some(id) when forwarded from a client's request.
    pub request_id: Option<u64>,
}

/// Pointer to where clipboard data should be sent once it's been fetched
pub enum ClipboardRequestSource {
    /// The clipboard is being requested from the local (server) machine.
    /// The oneshot can be used for sending back the clipboard result.
    Local(oneshot::Sender<data::ClipboardData>),

    /// The clipboard is being requested from a remote client.
    /// The data should be sent to the client's address.
    Remote(SocketAddr),
}

impl std::fmt::Display for ClipboardRequestSource {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ClipboardRequestSource::Local(_) => f.write_str("Local"),
            ClipboardRequestSource::Remote(addr) => {
                f.write_str(format!("Remote({})", addr).as_str())
            }
        }
    }
}

pub struct ClipboardSendContentArgs {
    /// The client sending the clipboard data. This is the connection the frame
    /// arrived on, not anything the frame claims, which is what makes it safe
    /// to route on (see Rotation::clipboard_send_content_from_client).
    pub data_source: SocketAddr,
    /// Copied from the ClientClipboardHeader, correlates the content with its
    /// request. Only meaningful paired with data_source.
    pub request_id: u64,
    pub data: data::ClipboardData,
}

/// Input-flow counters for the current status window (see log_input_status).
/// They exist to make "the user is typing but nothing arrives anywhere"
/// observable instead of silent.
#[derive(Default)]
struct InputCounts {
    /// Physical events read from local devices.
    physical: u64,
    /// Of `physical`: events from devices monux currently holds grabbed. Only
    /// these have anywhere to go (forwarded to a client, or re-emitted
    /// locally) — ungrabbed devices pass through to the local system by
    /// design, so counting them in the swallow detector would false-positive
    /// on pure mouse movement.
    physical_grabbed: u64,
    /// Events forwarded to the remote client.
    forwarded: u64,
    /// Events emitted to local virtual devices.
    emitted_local: u64,
}

/// Mirror of the rotation loop's diagnostic state, read directly by the
/// SIGHUP handler on the signal thread. The dump must work when the loop
/// itself is stalled — that scenario is exactly what it exists to debug — so
/// nothing here touches the loop's channels: an atomic liveness timestamp
/// plus a pre-formatted state string behind a std Mutex that is only held for
/// a swap/clone. The rotation loop refreshes it after its iterations,
/// rate-limited to ~10Hz (see Rotation::update_diagnostics), so the contents
/// may lag the loop by up to 100ms.
///
/// The same mirror also carries the STRUCTURED snapshot served by the control
/// socket (control.rs): updated in the same refresh, so a status request
/// never waits on the rotation loop either.
pub struct DiagnosticsMirror {
    /// Base for the liveness timestamp.
    started: Instant,
    /// Milliseconds since `started` when the mirror was last refreshed. The
    /// refresh is rate-limited (~10Hz under load), but the loop wakes at
    /// least every 10s (input-status heartbeat), so a value much older than
    /// that in a dump means the loop is stuck.
    last_iteration_ms: AtomicU64,
    /// The dumpable state, formatted by the loop after each iteration.
    state: Mutex<String>,
    /// The server's QUIC listen address, published in the control state. The
    /// rotation loop doesn't know it, so the mirror (built by main) holds it.
    listen: SocketAddr,
    /// Structured snapshot for the control socket; None until the rotation
    /// loop's first refresh.
    control_state: Mutex<Option<crate::control::ServerState>>,
}

impl DiagnosticsMirror {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            started: Instant::now(),
            last_iteration_ms: AtomicU64::new(0),
            state: Mutex::new("<rotation loop has not completed an iteration yet>".to_string()),
            listen,
            control_state: Mutex::new(None),
        }
    }

    /// Stamps loop liveness and swaps in the latest formatted state.
    /// Rotation-loop side only.
    fn update(&self, state: String) {
        self.last_iteration_ms.store(
            self.started.elapsed().as_millis() as u64,
            Ordering::Relaxed,
        );
        if let Ok(mut s) = self.state.lock() {
            *s = state;
        }
    }

    /// Swaps in the latest structured snapshot (control socket status).
    /// Rotation-loop side only; called from update_diagnostics together with
    /// the string refresh above.
    fn update_control(&self, state: crate::control::ServerState) {
        if let Ok(mut s) = self.control_state.lock() {
            *s = Some(state);
        }
    }

    /// The latest structured snapshot, with the listen address filled in (the
    /// loop leaves it empty; it doesn't know it). Runs on the control socket
    /// task, so it must never wait on the rotation loop: it only reads.
    pub fn server_state(&self) -> Option<crate::control::ServerState> {
        let mut state = self.control_state.lock().ok()?.clone()?;
        state.listen = self.listen.to_string();
        Some(state)
    }

    /// The dump string: loop liveness plus the latest formatted state. Served
    /// verbatim by the control socket's diagnostics command (control.rs) and
    /// logged by dump(). Only reads this mirror, so it never waits on the
    /// rotation loop.
    pub fn state_dump(&self) -> String {
        let age_ms = self
            .started
            .elapsed()
            .as_millis()
            .saturating_sub(self.last_iteration_ms.load(Ordering::Relaxed) as u128);
        let state = match self.state.lock() {
            Ok(s) => s.clone(),
            Err(_) => "<diagnostics state lock poisoned>".to_string(),
        };
        format!(
            "rotation loop last completed an iteration {}ms ago (a healthy loop iterates at least every 10s); {}",
            age_ms, state
        )
    }

    /// Logs the full state dump for SIGHUP. Runs on the signal thread, so it
    /// must never wait on the rotation loop: it only reads this mirror.
    pub fn dump(&self) {
        info!("Diagnostics dump (SIGHUP): {}", self.state_dump());
    }
}

pub struct Rotation<O: device::output::OutputHandler> {
    grab_tx: watch::Sender<device::GrabState>,
    output_handler: O,
    roster: ClientRoster,
    /// Use the endpoint, not the fingerprint, to uniquely identify clients.
    /// This allows situations like a client reconnecting before the old socket has closed.
    current_client: Option<SocketAddr>,
    /// Pause mode (see --pause-shortcut and toggle_pause): ALL input devices —
    /// keyboards included — are ungrabbed, so the local machine gets raw evdev
    /// input with monux's re-emit fully out of the way. monux keeps listening
    /// ungrabbed so the pause chord still works; forwarding and rotation
    /// switches are suspended while clipboard sharing continues untouched.
    paused: bool,
    removed_current_client: Option<DefunctClientInfo>,
    /// Path of the file recording the active client's fingerprint for
    /// crash recovery (see ACTIVE_CLIENT_STATE_FILE).
    active_client_path: PathBuf,
    /// Fingerprint of the client that was active when the previous server
    /// instance exited unexpectedly. That client is re-activated
    /// automatically when it reconnects.
    pending_resume_fingerprint: Option<String>,

    /// Where the clipboard lives, the per-source debounce, and the fetches
    /// in flight (see clipboard.rs).
    clipboard: ClipboardRouter,
    /// Self-handle for spawned tasks (e.g. per-client bulk writers) to report
    /// events back to the rotation loop, such as client removal on stream failure.
    rotation_tx: mpsc::Sender<RotationEvent>,


    /// Input-flow counters for the current status window (see log_input_status).
    status_counts: InputCounts,
    /// When the current status window started.
    status_window_start: Instant,
    /// Pointer-motion coalescing and the datagram frames it produces (see
    /// motion.rs).
    motion: MotionCoalescer,
    /// Reusable serialization scratch for forwarded event batches (send_event):
    /// at input rates a fresh Vec per message is pure allocator churn. Only
    /// ever grows, to the largest frame seen — a separate buffer from
    /// datagram_scratch so the datagram path's clear() doesn't shrink it back.
    serialize_scratch: Vec<u8>,

    /// How the per-client bulk pacing rates are chosen (see ThrottleMode).
    throttle_mode: ThrottleMode,
    /// Per-client adaptive-fidelity state, keyed by endpoint in lockstep with
    /// the roster (inserted on add, removed on removal).
    link_quality: HashMap<SocketAddr, ClientLinkState>,
    /// When the last next/prev switch was processed (see SWITCH_DEBOUNCE).
    last_switch_at: Option<Instant>,
    /// Per-client Ping/Pong liveness, plus which endpoint's silence (if any)
    /// put the input back on the local machine (see liveness.rs).
    liveness: LivenessTracker,
    /// Loop-independent mirror of this rotation's diagnostic state, dumped by
    /// the SIGHUP handler without involving the loop (see DiagnosticsMirror).
    diagnostics: Arc<DiagnosticsMirror>,
    /// Publishes the live client list (endpoint + fingerprint) to the
    /// screen-edge switcher (edge.rs), which resolves --edge-map targets
    /// against it on every change and at switch time. None when --edge-map
    /// isn't in use.
    edge_client_tx: Option<watch::Sender<Vec<(SocketAddr, String)>>>,
    /// The server's --edge-map, used by add_client to tell each mapped client
    /// which server edge it sits beyond (ServerEvent::EdgeInfo), so the
    /// client can infer the return-trip edge without its own --edge-map.
    /// None when --edge-map isn't in use.
    edge_map: Option<edge::EdgeMap>,
    /// Cached per-client edge directions for the control-socket status (see
    /// EdgeDirectionsCache): re-resolved only on client add/remove and from
    /// set_edge_map, so building server_state never hits DNS.
    edge_dirs: EdgeDirectionsCache,
    /// Hostname → IPs resolution cache for --edge-map hostname targets (see
    /// edge::ResolveCache): refresh_edge_dirs/advertise_edge_info resolve
    /// against it, so those rotation-loop paths never run a blocking
    /// getaddrinfo themselves.
    resolve_cache: Arc<edge::ResolveCache>,
    /// Last advertised EdgeInfo directions per client, so unchanged maps
    /// aren't re-sent on topology changes (each re-advertise respawns the
    /// client's edge detector, resetting any in-progress dwell).
    edge_info_sent: HashMap<SocketAddr, BTreeSet<event::Direction>>,
    /// When the diagnostics mirror was last refreshed (see
    /// DIAGNOSTICS_REFRESH_INTERVAL); None until the first refresh.
    last_diagnostics_refresh: Option<Instant>,
    /// Per-client clipboard fetch budget (see CLIPBOARD_FETCH_BURST), keyed by
    /// endpoint in lockstep with the roster.
    clipboard_fetch_budget: HashMap<SocketAddr, FetchBudget>,
}

/// How many clipboard fetches one client may make per
/// CLIPBOARD_FETCH_WINDOW before being throttled.
///
/// Approval is permanent and unscoped: a client approved once may fetch the
/// clipboard whenever it likes, including while it is NOT the switched-active
/// machine. That is deliberate and load-bearing — the client advertises the
/// server's clipboard to its own local apps (set_remote_clipboard) regardless
/// of who holds input, so "copy on the server, walk over, paste on the
/// laptop" works, and refusing inactive clients would break it.
///
/// What the openness costs is a bound: nothing stopped an approved-and-
/// forgotten machine from polling continuously and receiving every clipboard
/// the server ever owns, silently. A budget keeps every legitimate paste
/// (which costs one fetch per mime type, a handful at most) while turning
/// continuous exfiltration into something that is both slow and loud.
const CLIPBOARD_FETCH_BURST: u32 = 30;
const CLIPBOARD_FETCH_WINDOW: Duration = Duration::from_secs(60);

/// One client's clipboard fetch budget over a sliding window.
struct FetchBudget {
    window_start: Instant,
    fetches: u32,
    /// Whether the throttle has already been reported for this window, so a
    /// client that keeps hammering costs one log line, not thousands.
    reported: bool,
}

impl FetchBudget {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            fetches: 0,
            reported: false,
        }
    }

    /// Charges one fetch. Returns whether it is allowed, and whether this is
    /// the first refusal of the current window (i.e. worth logging).
    fn charge(&mut self, now: Instant) -> (bool, bool) {
        if now.duration_since(self.window_start) >= CLIPBOARD_FETCH_WINDOW {
            *self = Self::new(now);
        }
        if self.fetches < CLIPBOARD_FETCH_BURST {
            self.fetches += 1;
            return (true, false);
        }
        let first_refusal = !self.reported;
        self.reported = true;
        (false, first_refusal)
    }
}

/// What a Rotation is built from: the handles it owns and the tuning modes
/// it applies. A struct rather than nine positional parameters, since the
/// three mode fields are distinct types only by name.
pub struct RotationConfig<O: device::output::OutputHandler> {
    pub grab_tx: watch::Sender<device::GrabState>,
    pub output_handler: O,
    /// None when the server's clipboard support is disabled.
    pub local_clipboard: Option<server::LocalClipboard>,
    pub config_dir: PathBuf,
    /// Self-handle for spawned tasks to report back (see Rotation::rotation_tx).
    pub rotation_tx: mpsc::Sender<RotationEvent>,
    pub motion_mode: MotionMode,
    pub throttle_mode: ThrottleMode,
    pub mode: NetworkMode,
    pub diagnostics: Arc<DiagnosticsMirror>,
}

impl<O: device::output::OutputHandler> Rotation<O> {
    pub async fn new(config: RotationConfig<O>) -> Result<Self> {
        let RotationConfig {
            grab_tx,
            output_handler,
            local_clipboard,
            config_dir,
            rotation_tx,
            motion_mode,
            throttle_mode,
            mode,
            diagnostics,
        } = config;
        let active_client_path = active_client_state_path(&config_dir);
        let pending_resume_fingerprint = load_pending_resume(&active_client_path);
        if let Some(pending) = &pending_resume_fingerprint {
            info!(
                "A client ({}) was active when the server last stopped; it will be re-activated when it reconnects",
                pending
            );
        }
        Ok(Rotation {
            grab_tx,
            output_handler,
            roster: ClientRoster::new(),
            current_client: None,
            paused: false,
            removed_current_client: None,
            active_client_path,
            pending_resume_fingerprint,
            clipboard: ClipboardRouter::new(local_clipboard),
            rotation_tx,


            status_counts: InputCounts::default(),
            status_window_start: Instant::now(),
            serialize_scratch: Vec::new(),
            motion: MotionCoalescer::new(motion_mode),
            throttle_mode,
            link_quality: HashMap::new(),
            last_switch_at: None,
            liveness: LivenessTracker::new(match mode {
                NetworkMode::Local => PONG_MISS_LIMIT,
                NetworkMode::Www => WWW_PONG_MISS_LIMIT,
            }),
            diagnostics,
            edge_client_tx: None,
            edge_map: None,
            edge_dirs: EdgeDirectionsCache::default(),
            resolve_cache: Arc::new(edge::ResolveCache::default()),
            edge_info_sent: HashMap::new(),
            last_diagnostics_refresh: None,
            clipboard_fetch_budget: HashMap::new(),
        })
    }

    /// Hands the screen-edge switcher (edge.rs) the channel it reads the live
    /// client list from, seeding it with the current (startup: empty) list.
    /// Called once from the server events loop when --edge-map is in use.
    pub fn set_edge_client_publisher(&mut self, tx: watch::Sender<Vec<(SocketAddr, String)>>) {
        let entries = self.edge_client_entries();
        // An empty seed (always the case at startup) would only trigger a
        // spurious change notification; the channel already starts empty.
        if !entries.is_empty() {
            let _ = tx.send(entries);
        }
        self.edge_client_tx = Some(tx);
    }

    /// Hands the rotation the server's --edge-map so add_client can tell each
    /// mapped client which server edge it sits beyond (ServerEvent::EdgeInfo).
    /// Called once from the server events loop when --edge-map is in use.
    pub fn set_edge_map(&mut self, map: edge::EdgeMap) {
        self.edge_map = Some(map);
        // Seed the server_state cache (startup: the client list is empty).
        self.refresh_edge_dirs();
    }

    /// Re-resolves the cached per-client edge directions (see
    /// EdgeDirectionsCache). Called on client add/remove and from
    /// set_edge_map — the only moments the resolution can change. Hostname
    /// targets resolve against the ResolveCache (a miss is "unresolvable"
    /// for this pass); the queued background refresh serves the next pass.
    fn refresh_edge_dirs(&mut self) {
        if let Some(map) = &self.edge_map {
            self.resolve_cache.queue_map_refresh(map);
        }
        let resolver = self.resolve_cache.resolver();
        let entries = self.edge_client_entries();
        self.edge_dirs
            .refresh(self.edge_map.as_ref(), &entries, &resolver);
    }

    /// Sends EdgeInfo for every edge-map direction resolving to this client,
    /// so it can infer its return edge (see ServerEvent::EdgeInfo). Used at
    /// add time and to re-advertise when the topology changes (a peer's
    /// removal can make 'auto' resolve to a remaining client, or resolve it
    /// away from one). Hostname targets resolve against the ResolveCache,
    /// never blocking getaddrinfo on this async loop (see refresh_edge_dirs).
    async fn advertise_edge_info(&mut self, endpoint: &SocketAddr, fingerprint: &str) {
        let Some(map) = &self.edge_map else {
            return;
        };
        self.resolve_cache.queue_map_refresh(map);
        let resolver = self.resolve_cache.resolver();
        let directions: BTreeSet<event::Direction> = edge_info_directions(
            map,
            &self.edge_client_entries(),
            fingerprint,
            &resolver,
        )
        .into_iter()
        .collect();
        let old = self.edge_info_sent.get(endpoint).cloned().unwrap_or_default();
        // Dedup: skip if nothing changed. Each re-advertise respawns the
        // client's edge detector, resetting any in-progress dwell.
        if old == directions {
            return;
        }
        self.edge_info_sent.insert(*endpoint, directions.clone());
        // Revoke directions that dropped out, then advertise new ones.
        let to_revoke: BTreeSet<event::Direction> = old.difference(&directions).copied().collect();
        let to_advertise: BTreeSet<event::Direction> = directions.difference(&old).copied().collect();
        for direction in to_revoke.iter().copied().chain(to_advertise.iter().copied()) {
            let is_revoke = to_revoke.contains(&direction);
            let (msg_str, msg) = if is_revoke {
                ("revoking", event::ServerEvent::EdgeInfoRevoke { direction })
            } else {
                ("telling", event::ServerEvent::EdgeInfo { direction })
            };
            info!(
                "{} client {} about its {}-hand edge",
                msg_str,
                fingerprint,
                direction.as_str()
            );
            let serialized = match postcard::to_stdvec_cobs(&msg) {
                Ok(m) => m,
                Err(e) => {
                    error!("Failed to serialize edge info message: {:?}", e);
                    return;
                }
            };
            let result = match self.roster.get_mut(endpoint) {
                Some(client) => client.link.send_events(&serialized).await,
                None => return,
            };
            if let Err(e) = result {
                debug!("Failed to send edge info to {}: {:?}", endpoint, e);
                return;
            }
        }
    }

    /// The current client list as (endpoint, fingerprint) pairs, in the
    /// shape the edge switcher resolves --edge-map targets against.
    fn edge_client_entries(&self) -> Vec<(SocketAddr, String)> {
        self.roster
            .iter()
            .map(|c| (c.endpoint, c.fingerprint.clone()))
            .collect()
    }

    /// Republishes the client list to the edge switcher after a change. A
    /// dead receiver means the edge switcher is gone (server shutting down).
    fn publish_edge_clients(&self) {
        if let Some(tx) = &self.edge_client_tx {
            let _ = tx.send(self.edge_client_entries());
        }
    }

    pub async fn accept(&mut self, event: RotationEvent) {
        match event {
            RotationEvent::AddClient(args) => self.add_client(args).await,
            RotationEvent::RemoveClient {
                endpoint,
                conn_token,
            } => {
                self.remove_client_and_clear_clipboard(endpoint, conn_token)
                    .await
            }
            RotationEvent::ClipboardUpdateSource(args) => {
                if let Err(e) = self
                    .clipboard_update_source(args.source, args.types, args.max_size_bytes)
                    .await
                {
                    warn!("Failed to update clipboard source: {:?}", e);
                }
            }
            RotationEvent::ClipboardRequestContent(args) => {
                if let Err(e) = self
                    .clipboard_request_content(
                        args.request_source,
                        &args.requested_type,
                        args.max_size_bytes,
                        args.request_id,
                    )
                    .await
                {
                    warn!("Failed to retrieve clipboard content: {:?}", e);
                }
            }
            RotationEvent::ClipboardSendContent(args) => {
                if let Err(e) = self
                    .clipboard_send_content_from_client(
                        args.data_source,
                        args.request_id,
                        args.data,
                    )
                    .await
                {
                    warn!("Failed to send clipboard content to client: {:?}", e);
                }
            }
            RotationEvent::ClientHeardFrom { endpoint } => {
                self.note_client_heard(endpoint).await;
            }
            RotationEvent::SendBulkFrame {
                endpoint,
                frame,
                conn_token,
            } => {
                self.send_bulk_frame(&endpoint, frame, conn_token).await;
            }
            RotationEvent::RequestPeerDiagnostics(args) => {
                let pending = self.request_peer_diagnostics(args.lines);
                // The requester gone (it timed out, or the CLI hung up) is
                // not an error: the report simply proceeds without peers.
                if args.reply.send(pending).is_err() {
                    debug!("Peer diagnostics requester went away before the client list was ready");
                }
            }
            RotationEvent::SwitchRequest { endpoint } => {
                self.switch_request_from_client(endpoint).await;
            }
        }
    }

    /// Takes the AddClientArgs whole rather than destructured: the fields
    /// travel together from the connection handler (server.rs), and spreading
    /// them over seven positional parameters — three of them u64/SocketAddr —
    /// only creates places to transpose them.
    async fn add_client(&mut self, args: AddClientArgs) {
        let AddClientArgs {
            endpoint,
            fingerprint,
            events_send,
            bulk_send,
            conn,
            conn_token,
            negotiated_version,
        } = args;
        // Dedicated writer task for this client's bulk stream: clipboard payloads
        // can be megabytes, and writing them inline would stall input forwarding
        // for the whole rotation. The task also keeps each header glued to its
        // payload by writing queued byte blobs sequentially. The queue is
        // bounded (bulk::BULK_QUEUE_CAPACITY): senders fail fast when the
        // client can't drain, and the client is dropped like a write failure.
        // Fresh adaptive-fidelity state for the (re)connection, kept in
        // lockstep with the clients entry (see handle_client_removal): the
        // bulk pacing cell starts at the Normal-tier rate and is rewritten by
        // the link sampler on every measured tier transition.
        let throttle_cell =
            throttle::shared_throttle(effective_throttle_mbps(&self.throttle_mode, Tier::Normal));
        self.link_quality.insert(
            endpoint,
            ClientLinkState {
                quality: LinkQuality::new(),
                last_sent: 0,
                last_lost: 0,
                throttle: throttle_cell.clone(),
                degraded: false,
            },
        );
        let (bulk_tx, bulk_rx) = mpsc::channel::<Vec<u8>>(bulk::BULK_QUEUE_CAPACITY);
        {
            let rotation_tx = self.rotation_tx.clone();
            throttle::spawn_bulk_writer(
                bulk_send,
                bulk_rx,
                throttle_cell,
                endpoint,
                move |_len, e| async move {
                    warn!("Bulk stream to {} failed, removing client: {:?}", endpoint, e);
                    let _ = rotation_tx
                        .send(RotationEvent::RemoveClient {
                            endpoint,
                            conn_token,
                        })
                        .await;
                },
            );
        }
        self.register_client(
            endpoint,
            fingerprint,
            Box::new(QuicClientLink {
                events_send,
                bulk_tx,
                conn,
            }),
            conn_token,
            negotiated_version,
        )
        .await;
    }

    /// Everything adding a client does once its link exists: the sorted
    /// insert (or in-place replace on a reconnect), fresh liveness and edge
    /// bookkeeping, the clipboard announcement, and the several ways a new
    /// client can be adopted as the current one.
    ///
    /// Split from add_client so a test can drive it with a fake ClientLink —
    /// this is the whole reason the trait exists. add_client keeps only the
    /// parts that need a real QUIC connection.
    async fn register_client(
        &mut self,
        endpoint: SocketAddr,
        fingerprint: String,
        link: Box<dyn ClientLink>,
        conn_token: u64,
        negotiated_version: u64,
    ) {
        let info = ClientInfo {
            endpoint,
            fingerprint: fingerprint.clone(),
            link,
            datagrams_ok: true,
            conn_token,
            connected_at: Instant::now(),
            negotiated_version,
        };
        // Clients stay sorted by endpoint as an arbitrary consistent order across
        // sessions. An identical endpoint can already be present when a reconnect
        // lands before the old connection's removal: update that entry in place
        // instead of inserting a duplicate (a later removal would clear only the
        // first copy, leaving a dead one behind). The old connection's late
        // removal is then ignored via its stale conn_token (see RemoveClient),
        // and its advertised-EdgeInfo record is forgotten (see reconnect_slot).
        self.roster.insert_or_replace(info, &mut self.edge_info_sent);
        // Fresh liveness bookkeeping for the (re)connection, kept in lockstep
        // with the clients entry (see handle_client_removal). The new client
        // gets the full miss window before the silence detector can fire.
        self.liveness.track(endpoint);
        self.publish_edge_clients();
        // Client list changed: re-resolve the cached edge directions for the
        // control status (an in-place replace may carry a new fingerprint).
        self.refresh_edge_dirs();

        info!(
            "Added client {} @ {} to rotation: {}",
            fingerprint,
            endpoint,
            self.roster
                .iter()
                .map(|c| c.endpoint.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        );
        notify_client_joined(&endpoint);

        // Server-driven edge inference (ServerEvent::EdgeInfo): tell the new
        // client which of our edges it sits beyond, so it watches the
        // OPPOSITE edge for the return trip without its own --edge-map. Sent
        // BEFORE any Switch(true) below, on this ordered events stream (the
        // same ordering discipline as the clipboard types push further down):
        // the client's inferred detector is running before its first
        // activation. Unmapped clients get nothing.
        self.advertise_edge_info(&endpoint, &fingerprint).await;

        // Topology changed: re-advertise surviving clients too — a new
        // connection can make 'auto' ambiguous, revoking a direction that
        // previously resolved to a single peer.
        let survivors: Vec<(SocketAddr, String)> = self
            .roster
            .entries()
            .into_iter()
            .filter(|(ep, _)| *ep != endpoint)
            .collect();
        for (ep, fp) in survivors {
            self.advertise_edge_info(&ep, &fp).await;
        }

        // Announce clipboard to client, if its IP doesn't match the clipboard owner's IP.
        // Matching IP would indicate that the client is reconnecting but we haven't disconnected the old one yet.
        // This runs BEFORE any re-activation below: the types must reach the
        // client before Switch(true) on the ordered events stream, so the
        // client replaces any stale local types (set_remote_clipboard) before
        // its first-activation re-announce check runs (see update_current_client).
        if let Some(clipboard_target) = self.clipboard.target() {
            if match clipboard_target.source {
                // Client has clipboard. Make sure it's not the same client IP.
                Some(clipboard_source) => clipboard_source.ip() != endpoint.ip(),
                // Server has clipboard.
                None => true,
            } {
                // Tell the new client about the current clipboard status.
                let types_str = clipboard_target.types.join(" ");
                let types_msg = event::ServerEvent::ClipboardTypes(event::ClipboardTypes {
                    types: &types_str,
                    max_size_bytes: clipboard_target.max_size_bytes,
                });
                if let Err(e) = self.send_event(&endpoint, types_msg).await {
                    // This shouldn't happen in practice, given we just added the client...
                    warn!("Newly added client already failed and was removed: {:?}", e);
                }
            }
        }

        // If the new client has the same IP as the currently enabled client, it's probably a fast retry
        // where we haven't removed the prior session yet. Mark the new client as enabled/current.
        // If two clients were connected from the same IP then this will result in spurious switches,
        // but that shouldn't be the case in practice.
        if let Some(current_client) = &self.current_client {
            // Only check IP: port is expected to change between sessions
            if current_client.ip() == endpoint.ip() {
                self.update_current_client(Some(endpoint)).await;
            }
        }

        // If the new client has the same IP as a recently disconnected client that was enabled,
        // it's probably a slow reconnect. Mark the new client as enabled/current.
        if let Some(removed_current_client) = &self.removed_current_client {
            // Only check IP: port is expected to change between sessions
            let now = Instant::now();
            if removed_current_client.recoverable(endpoint, &now) {
                // Enable this client automatically since it was recently disconnected
                // This automatically unsets self.removed_current_client
                // ...but never while paused: the user parked input on this
                // machine, and a peer reconnecting is not consent to move it.
                // Notifications are suppressed while paused, so the switch
                // would be silent, and input would land on the client the
                // moment the pause is lifted.
                if !self.paused {
                    self.update_current_client(Some(endpoint)).await;
                }
            } else if removed_current_client.expired(&now) {
                // Clean up expired client info
                self.removed_current_client = None;
            }
        }

        // Session resumption: this client was active when the previous server
        // instance stopped (crash or intentional restart, e.g. after an update).
        // Re-activate it immediately.
        if let Some(pending) = &self.pending_resume_fingerprint {
            if *pending == fingerprint {
                self.pending_resume_fingerprint = None;
                // Same rule as the reconnect path above: a resume is not a
                // reason to override a pause the user asked for.
                if self.paused {
                    info!(
                        "Not resuming the session for {} while input is paused; it stays on this machine",
                        endpoint
                    );
                } else {
                    info!(
                        "Resuming session: re-activating client {} that was active when the previous server stopped",
                        endpoint
                    );
                    self.update_current_client(Some(endpoint)).await;
                }
            }
        }
    }

    async fn remove_client_and_clear_clipboard(&mut self, endpoint: SocketAddr, conn_token: u64) {
        // A reconnect can reuse the same addr:port before the old connection's
        // teardown lands: add_client then replaces the entry in place, and the
        // old connection's late removal must not kill the healthy new entry.
        // Tokens are unique per accepted connection (see server.rs).
        if matches!(self.roster.conn_token(&endpoint), Some(token) if token != conn_token) {
            debug!(
                "Ignoring stale removal of {}: token {} belongs to a replaced connection",
                endpoint, conn_token
            );
            return;
        }
        if self.handle_client_removal(&endpoint).await {
            self.clipboard_clear().await;
        }
    }

    /// Returns true if a next/prev switch request should be ignored because one
    /// was just processed (see SWITCH_DEBOUNCE); otherwise records it and
    /// returns false.
    fn switch_debounced(&mut self) -> bool {
        if let Some(last) = self.last_switch_at {
            if last.elapsed() < SWITCH_DEBOUNCE {
                debug!(
                    "Ignoring switch request: a switch happened {:?} ago",
                    last.elapsed()
                );
                return true;
            }
        }
        self.last_switch_at = Some(Instant::now());
        false
    }

    /// Runs the same held-key cleanup on the CURRENT target that a real switch
    /// runs on the old one, for a chord that fired without producing a switch:
    /// dropped by SWITCH_DEBOUNCE, already on the target, or an unmatched goto.
    /// The user pressed the full chord intending to switch: the chord's
    /// modifier presses were forwarded to the current target, but ComboState
    /// consumes their releases once the chord fires (see device::shortcut), so
    /// without this the target would keep the chord's modifiers logically
    /// pressed until each is tapped again — presenting as dead keys (e.g.
    /// Enter) since every keypress becomes a modifier combo.
    async fn release_current_target_keys(&mut self) {
        match self.current_client {
            Some(endpoint) => {
                // Mirror of the deactivation a real switch sends the old
                // client: the client releases its held keys on Switch(false)
                // (see client.rs). Re-activate right away, since the rotation
                // stays on this client.
                let _ = self
                    .send_event(
                        &endpoint,
                        event::ServerEvent::Switch(event::SwitchEvent { enabled: false }),
                    )
                    .await;
                let _ = self
                    .send_event(
                        &endpoint,
                        event::ServerEvent::Switch(event::SwitchEvent { enabled: true }),
                    )
                    .await;
            }
            None => {
                // Mirror of set_and_grab_current_client switching away from the
                // local machine.
                if let Err(e) = self.output_handler.release_all().await {
                    warn!(
                        "Failed to release held keys on local virtual devices after debounced switch: {:?}",
                        e
                    );
                }
            }
        }
    }

    /// Decides whether a next/prev switch to `target` may run now, recording
    /// the switch time when it may. A switch back to the LOCAL machine always
    /// runs: it ungrabs the input devices, so it's the escape hatch and must
    /// never be debounced away — a dropped switch-away presents as dead keys
    /// with the client keeping the grab, and keystrokes meant to kill the
    /// server then land on the client instead. Switches to a client are
    /// debounced (see SWITCH_DEBOUNCE).
    fn switch_allowed(&mut self, target: Option<SocketAddr>) -> bool {
        match target {
            None => {
                self.last_switch_at = Some(Instant::now());
                true
            }
            Some(_) => !self.switch_debounced(),
        }
    }

    /// Switches to the previous client (or to the server) in the arbitrary rotation.
    pub async fn prev_client(&mut self) {
        if self.paused {
            // Paused: switch chords are not acted on. Devices are ungrabbed,
            // so those keystrokes also pass through to the local system, and
            // since nothing was forwarded anywhere there's no held-key cleanup
            // to run either.
            info!(
                "Ignoring switch request: input is paused (resume via the pause chord, the tray, or 'monux daemon resume')"
            );
            return;
        }
        // A manual switch action: any silence-driven local state is
        // superseded — the user's choice wins over automatic re-activation
        // (see silenced_endpoint).
        self.liveness.clear_silenced();
        let target = self.roster.prev_target(self.current_client);
        if target == self.current_client {
            // Already on the target: no switch happens, but the chord fired
            // and ComboState consumes the chord keys' releases, so the
            // modifiers it forwarded must be cleaned up here instead.
            debug!("Ignoring switch request: already on the target");
            self.release_current_target_keys().await;
            return;
        }
        if !self.switch_allowed(target) {
            info!(
                "Ignoring switch request: a switch happened less than {:?} ago",
                SWITCH_DEBOUNCE
            );
            self.release_current_target_keys().await;
            return;
        }
        self.update_current_client(target).await;
    }

    /// Switches to the next client (or to the server) in the arbitrary rotation.
    pub async fn next_client(&mut self) {
        if self.paused {
            // Paused: switch chords are not acted on (see prev_client). This
            // also covers remote switches via SIGUSR1: while paused the
            // devices must stay ungrabbed regardless.
            info!(
                "Ignoring switch request: input is paused (resume via the pause chord, the tray, or 'monux daemon resume')"
            );
            return;
        }
        // A manual switch action supersedes silence-driven local state (see
        // prev_client and silenced_endpoint).
        self.liveness.clear_silenced();
        let target = self.roster.next_target(self.current_client);
        if target == self.current_client {
            // Already on the target: no switch happens, but the chord fired
            // and ComboState consumes the chord keys' releases, so the
            // modifiers it forwarded must be cleaned up here instead.
            debug!("Ignoring switch request: already on the target");
            self.release_current_target_keys().await;
            return;
        }
        if !self.switch_allowed(target) {
            info!(
                "Ignoring switch request: a switch happened less than {:?} ago",
                SWITCH_DEBOUNCE
            );
            self.release_current_target_keys().await;
            return;
        }
        self.update_current_client(target).await;
    }

    /// Switches to the specified client by fingerprint, or to the server if the fingerprint is empty.
    /// If a matching client isn't connected, does nothing — except run the held-key
    /// cleanup, since the chord fired and its modifier releases are being consumed.
    pub async fn set_client(&mut self, fingerprint: String) {
        if self.paused {
            // Paused: switch chords are not acted on (see prev_client).
            info!(
                "Ignoring goto request: input is paused (resume via the pause chord, the tray, or 'monux daemon resume')"
            );
            return;
        }
        // A manual switch action supersedes silence-driven local state (see
        // prev_client and silenced_endpoint) — goto "" counts too: it is
        // a deliberate choice of the LOCAL machine.
        self.liveness.clear_silenced();
        // Resolve the target: Ok(Some(target)) switches, Err(()) means no
        // unique match (already warn-logged).
        let target: Result<Option<SocketAddr>, ()> =
            match self.roster.resolve_goto(&fingerprint) {
                GotoResolution::Local => Ok(None),
                GotoResolution::Client(endpoint) => Ok(Some(endpoint)),
                GotoResolution::NoMatch => {
                    warn!(
                        "Missing client with fingerprint {}, doing nothing",
                        fingerprint
                    );
                    Err(())
                }
                GotoResolution::Ambiguous(endpoints) => {
                    warn!(
                        "Multiple clients match fingerprint {}, doing nothing: {:?}",
                        fingerprint, endpoints
                    );
                    Err(())
                }
            };
        match target {
            Ok(target) if target != self.current_client => {
                self.update_current_client(target).await;
            }
            Ok(_) => {
                // Already on the target (no-op switch).
                debug!("Ignoring goto request: already on the target");
                self.release_current_target_keys().await;
            }
            Err(()) => {
                self.release_current_target_keys().await;
            }
        }
    }

    /// Toggles pause mode (the --pause-shortcut chord). PAUSED means ALL input
    /// devices — keyboards included — are ungrabbed, so the local machine gets
    /// raw evdev input with monux's uinput re-emit fully out of the way
    /// (games, raw-input apps). monux keeps listening ungrabbed, so the pause
    /// chord itself is still seen and resumes. While paused nothing is
    /// forwarded to clients and rotation switches (including SIGUSR1/SIGUSR2)
    /// are ignored; clipboard sharing continues untouched. Resuming re-grabs
    /// per the current rotation state: keyboards always, mice iff a client is
    /// current. `source` names the trigger ("pause chord", "control socket")
    /// in the log line and the notification, so an unexpected pause is
    /// identifiable after the fact.
    pub async fn toggle_pause(&mut self, source: &'static str) {
        if self.paused {
            self.paused = false;
            self.broadcast_grab_state();
            info!(
                "Input resumed (via {}): devices re-grabbed per rotation state ({})",
                source,
                match self.current_client {
                    Some(endpoint) => format!("switched to {}", endpoint),
                    None => "local machine".to_string(),
                }
            );
            notify_switch(&format!("monux resumed ({})", source));
        } else {
            // Run the held-key cleanup on the current target FIRST so nothing
            // sticks: the chord's modifier presses were already forwarded to
            // it, and from here on the physical devices go raw to the local
            // system while the virtual devices idle.
            self.release_current_target_keys().await;
            // Motion accumulated for the current target is moot once paused:
            // nothing is forwarded while paused (send_input_events drops it),
            // so don't let a stale pending frame flush to the client.
            self.motion.clear();
            self.paused = true;
            self.broadcast_grab_state();
            info!("Input paused (via {}): all devices ungrabbed (clipboard sharing continues); resume via the pause chord (if configured), the tray, or 'monux daemon resume'", source);
            notify_switch(&format!("monux paused ({})", source));
        }
    }

    /// Sets pause mode explicitly (the control socket's pause/resume commands,
    /// via Event::SetPaused). Idempotent, unlike the pause chord's toggle:
    /// asking for the state already in effect is a no-op, so a GUI can send
    /// the command matching the state it wants without reading status first.
    pub async fn set_paused(&mut self, paused: bool, source: &'static str) {
        if self.paused != paused {
            self.toggle_pause(source).await;
        }
    }

    /// Sends the current grab state to every device task (keyboard-class and
    /// toggled). The state is single-sourced here from current_client and
    /// paused, so a client drop or remote switch while paused can't leave the
    /// devices half-grabbed: every broadcast carries both fields.
    fn broadcast_grab_state(&self) {
        let state = device::GrabState {
            client_active: self.current_client.is_some(),
            paused: self.paused,
        };
        if let Err(e) = self.grab_tx.send(state) {
            // Avoid leaving devices in a bad grabbed state
            panic!(
                "Failed to update device grab, exiting server to avoid bad grab state: {}",
                e
            );
        }
    }

    /// Updates the tracked location for the current clipboard,
    /// whether on the server host or on a remote client.
    async fn clipboard_update_source(
        &mut self,
        source: Option<SocketAddr>,
        types: Vec<String>,
        // min of source_client_max (if any), and server_max:
        max_size_bytes: u64,
    ) -> Result<()> {
        // Machine-internal types (e.g. Chromium's chromium/x-internal-*
        // markers) never enter the sharing layer: meaningless off-machine,
        // and fetching them stalls the serving side. A token-only clipboard
        // filters down to no types — a clear.
        let types = crate::clipboard::filter_shareable_mime_types(types);
        debug!("Announcing new clipboard source: source={:?} current={:?} with max_size_bytes={} has types={:?}", source, self.current_client, max_size_bytes, types);
        // An update with no types means the selection is gone — locally (the
        // compositor revoked it) or on a client. Clear right away, bypassing
        // the debounce, and reset the source's debounce state so a re-own
        // right after (e.g. a clipboard manager persisting the content) is
        // processed.
        //
        // Only the OWNER's revocation clears, though. Everyone announces their
        // selection going away, including machines that never held the shared
        // clipboard: an ordinary app quitting on this machine while a client
        // owns the clipboard, or a client deactivating with nothing shareable
        // to offer. Treating those as a clear would drop the real owner's
        // content on every machine until someone copies again.
        if types.is_empty() {
            self.clipboard.reset_debounce(source);
            if self.clipboard.target().map(|target| target.source) == Some(source) {
                self.clipboard_clear().await;
            }
            return Ok(());
        }
        // The clipboard changed hands: drop any cached served payload so
        // stale contents are never served. Lock-free (an epoch bump), so it
        // never waits on a serve in progress. This must happen even when the
        // update is debounced below: a held update still means the clipboard
        // changed, and the old cache would otherwise keep being served.
        if let Some(reader) = self.clipboard.local.as_ref().map(|lc| lc.reader_handle()) {
            reader.invalidate();
        }
        let now = Instant::now();
        match self.clipboard.classify(source, &types, now) {
            ClipboardUpdate::HoldLocal => {
                self.clipboard.hold_local(types, max_size_bytes, now);
                return Ok(());
            }
            ClipboardUpdate::Drop => {
                debug!("Debouncing rapid clipboard source update from {:?}", source);
                return Ok(());
            }
            ClipboardUpdate::Duplicate => {
                debug!("Ignoring duplicate clipboard source update (unchanged source and types)");
                return Ok(());
            }
            ClipboardUpdate::Process => {}
        }
        self.clipboard.note_processed(source, now);
        self.apply_clipboard_source(source, types, max_size_bytes)
            .await
    }

    /// When the held local clipboard update (if any) should be applied — the
    /// trailing edge of its debounce window. The server events loop sleeps on
    /// this and then calls flush_pending_local_clipboard.
    pub fn pending_local_clipboard_deadline(&self) -> Option<Instant> {
        self.clipboard.pending_local_deadline()
    }

    /// Applies the local clipboard update held by the debounce's trailing
    /// edge (see CLIPBOARD_UPDATE_DEBOUNCE). Called by the server events loop
    /// when the debounce window expires.
    pub async fn flush_pending_local_clipboard(&mut self) {
        let Some((types, max_size_bytes)) = self.clipboard.take_pending_local() else {
            return;
        };
        // Deliberate tradeoff: a held local update can be applied over a
        // strictly newer remote announcement that landed inside the window
        // (a cross-machine copy race within 300ms). We favor never losing the
        // newest LOCAL user action; the remote state wins the next copy or
        // switch, so any divergence self-heals.
        // The same ping-pong guard as a directly processed update: the target
        // may have converged on these types while the update was held.
        if let Some(current) = self.clipboard.target() {
            if current.source.is_none() && types_equal(&current.types, &types) {
                debug!("Ignoring held local clipboard update: matches the current target");
                return;
            }
        }
        self.clipboard.note_processed(None, Instant::now());
        if let Err(e) = self
            .apply_clipboard_source(None, types, max_size_bytes)
            .await
        {
            warn!("Failed to apply held local clipboard update: {:?}", e);
        }
    }

    /// Records a new clipboard target and announces it to the active side.
    async fn apply_clipboard_source(
        &mut self,
        source: Option<SocketAddr>,
        types: Vec<String>,
        max_size_bytes: u64,
    ) -> Result<()> {
        // Save the clipboard types/source for future retrievals and client switches
        self.clipboard.set_target(source, types, max_size_bytes);

        // Notify the active client (or server) about the clipboard info we just received.
        // In practice we should be getting this shortly after a client switch.
        self.update_current_client_clipboard().await?;

        Ok(())
    }

    /// Fails an unservable clipboard content request fast: a local
    /// requester's oneshot gets an empty answer (dropping it un-answered
    /// surfaces as a stalled paste and a 'channel closed' error on the
    /// fetching side), a remote requester gets the empty reply message its
    /// own fetch would produce on timeout.
    async fn fail_clipboard_fetch(
        &mut self,
        request_source: ClipboardRequestSource,
        requested_type: &str,
        request_id: Option<u64>,
    ) {
        match request_source {
            ClipboardRequestSource::Local(tx) => {
                let _ = tx.send(data::ClipboardData {
                    requested_type: requested_type.to_string(),
                    data_type: None,
                    bytes: vec![],
                    remaining_bytes: 0,
                });
            }
            ClipboardRequestSource::Remote(client) => {
                self.reply_empty_clipboard_fetch(&client, requested_type, request_id.unwrap_or(0))
                    .await;
            }
        }
    }

    /// Routes a request for clipboard content to a remote client or a local application.
    /// Fetches that can't be served get an immediate empty reply, so the
    /// requester's paste fails fast instead of waiting out its fetch timeout.
    async fn clipboard_request_content(
        &mut self,
        request_source: ClipboardRequestSource,
        requested_type: &str,
        max_size_bytes: u64,
        request_id: Option<u64>,
    ) -> Result<()> {
        debug!("Handling clipboard content request from source={} with max_size_bytes={} for requested type {}: have {:?}", request_source, max_size_bytes, requested_type, self.clipboard.target());

        // Budget remote fetches (see CLIPBOARD_FETCH_BURST). Only remote ones:
        // a local fetch is this machine's own user pasting, and rationing that
        // would be rationing the server against itself.
        if let ClipboardRequestSource::Remote(client) = &request_source {
            let client = *client;
            let (allowed, first_refusal) = self
                .clipboard_fetch_budget
                .entry(client)
                .or_insert_with(|| FetchBudget::new(Instant::now()))
                .charge(Instant::now());
            if !allowed {
                if first_refusal {
                    warn!(
                        "Client {} asked for more than {} clipboard fetches in {}s; throttling it. A paste costs a handful of fetches, so this is either a misbehaving clipboard manager or a machine reading this server's clipboard on a loop — if you don't recognize it, remove its certificate from known_certs/.",
                        client,
                        CLIPBOARD_FETCH_BURST,
                        CLIPBOARD_FETCH_WINDOW.as_secs()
                    );
                }
                // Empty reply, not a dropped request: the requester's paste
                // then completes with nothing instead of waiting out its
                // timeout, exactly as for any other unservable fetch.
                self.fail_clipboard_fetch(request_source, requested_type, request_id)
                    .await;
                return Ok(());
            }
        }

        let target = match self.clipboard.target() {
            Some(c) => c,
            None => {
                let err = anyhow!(
                    "No clipboard types available: request from {} for requested type {}",
                    request_source,
                    requested_type
                );
                self.fail_clipboard_fetch(request_source, requested_type, request_id)
                    .await;
                return Err(err);
            }
        };
        // Sanity check: Is the requested type among the list of supported types?
        if !target.types.contains(&requested_type.to_string()) {
            // Formatted up front: the empty reply takes &mut self, ending the
            // borrow of the target.
            let err = anyhow!(
                "Requested clipboard type {} from source {} isn't among available types: {:?}",
                requested_type,
                request_source,
                target.types
            );
            self.fail_clipboard_fetch(request_source, requested_type, request_id)
                .await;
            return Err(err);
        }

        // Figure out where the requested clipboard can be found
        if let Some(clipboard_source) = target.source {
            // A client has the clipboard: route request to them.
            // Every fetch is tracked against the peer it is sent to, under an
            // id THIS machine allocates. The owner's reply is then matched on
            // (peer, id), so the routing never depends on a field the
            // answering peer chose — see ClipboardRouter::pending_requests.
            let (msg, local_request_id, on_behalf_of) = match request_source {
                ClipboardRequestSource::Local(waiting_clipboard_tx) => {
                    // Clipboard request is from the server itself: keep the
                    // oneshot for replying later.
                    let request_id = self.clipboard.track_request(
                        clipboard_source,
                        clipboard::PendingFetch::Local(waiting_clipboard_tx),
                    );
                    let msg = bulk::ServerBulk::ClipboardRequest(bulk::ServerClipboardRequest {
                        requested_type,
                        max_size_bytes,
                        request_client: None,
                        request_id,
                    });
                    (msg, Some(request_id), None)
                }
                ClipboardRequestSource::Remote(client) => {
                    // Clipboard request is from a client. Its own id is
                    // remembered rather than forwarded: two clients can pick
                    // the same one, and it is restored when the reply is
                    // relayed back.
                    let client_request_id = match request_id {
                        Some(id) => id,
                        None => {
                            warn!("Clipboard request from {} is missing a request_id, using 0", client);
                            0
                        }
                    };
                    let request_id = self.clipboard.track_request(
                        clipboard_source,
                        clipboard::PendingFetch::Relay {
                            client,
                            client_request_id,
                        },
                    );
                    let msg = bulk::ServerBulk::ClipboardRequest(bulk::ServerClipboardRequest {
                        requested_type,
                        max_size_bytes,
                        request_client: Some(client),
                        request_id,
                    });
                    (msg, Some(request_id), Some(client))
                }
            };
            debug!(
                "Requesting clipboard data with type {} from {}{}",
                requested_type,
                clipboard_source,
                match on_behalf_of {
                    Some(client) => format!(" on behalf of {}", client),
                    None => "".to_string(),
                }
            );
            let sent = self.send_bulk(&clipboard_source, msg, None).await;
            if let Some(request_id) = local_request_id {
                if !matches!(sent, Ok(true)) {
                    // The request couldn't be sent: drop the pending fetch so that
                    // it fails fast instead of waiting out the 5s timeout.
                    self.clipboard
                        .untrack_request(clipboard_source, request_id);
                }
            }
            match sent {
                Ok(true) => {}
                Ok(false) => {
                    if let Some(client) = on_behalf_of {
                        // The owning peer is gone: fail the requester's fetch
                        // fast instead of letting it wait out its timeout.
                        self.reply_empty_clipboard_fetch(&client, requested_type, request_id.unwrap_or(0))
                            .await;
                        warn!(
                            "Unable to send request for clipboard to {} on behalf of {}: not connected (clients: {:?})",
                            clipboard_source,
                            client,
                            self.roster,
                        );
                    } else {
                        warn!(
                            "Unable to send request for clipboard to {}: not connected (clients: {:?})",
                            clipboard_source,
                            self.roster,
                        );
                    }
                }
                Err(e) => return Err(e),
            }
            Ok(())
        } else {
            // The server has the clipboard: serve from the local clipboard app
            let request_client = if let ClipboardRequestSource::Remote(c) = &request_source {
                c
            } else {
                // The monux server process is getting asked for a clipboard from itself.
                // The server should only locally serve clipboards from remote clients, but there isn't one.
                // This may mean that the serving client disconnected, but we should have cleared the status.
                let err = anyhow!(
                    "Server got local clipboard request against itself? current_clipboard={:?}",
                    target
                );
                self.fail_clipboard_fetch(request_source, requested_type, request_id)
                    .await;
                return Err(err);
            };
            // Echo the requesting client's id back in the response.
            let request_id = match request_id {
                Some(id) => id,
                None => {
                    warn!("Clipboard request from {} is missing a request_id, using 0", request_client);
                    0
                }
            };
            let local_clipboard = match &self.clipboard.local {
                Some(c) => c,
                None => {
                    self.reply_empty_clipboard_fetch(request_client, requested_type, request_id)
                        .await;
                    bail!("Fetch for local server clipboard but server clipboard is disabled");
                }
            };
            let reader = local_clipboard.reader_handle();
            // Look up the requesting client's bulk queue before spawning.
            let conn_token = match self.roster.conn_token(request_client) {
                Some(token) => token,
                None => {
                    warn!(
                        "Unable to send server clipboard data to {}: not connected (clients: {:?})",
                        request_client, self.roster
                    );
                    return Ok(());
                }
            };
            // Reading the clipboard can take seconds for large copies (files get
            // zipped from disk), so serve it from a spawned task: the rotation
            // loop must keep forwarding input meanwhile.
            let rotation_tx = self.rotation_tx.clone();
            let request_client = *request_client;
            let requested_type = requested_type.to_string();
            task::spawn(async move {
                // A failed or slow read (clipboard gone, hung source app,
                // long convert/zip under the serve mutex) still gets an
                // immediate reply — empty content — so the requester's paste
                // completes right away instead of waiting out its fetch
                // timeout. The overall timeout covers read AND convert, like
                // the client-side serve path (CLIPBOARD_SERVE_TIMEOUT_SECS).
                // The next paste simply re-requests.
                let started = Instant::now();
                let (content, data_type) = match tokio::time::timeout(
                    Duration::from_secs(CLIPBOARD_SERVE_TIMEOUT_SECS),
                    server::LocalClipboard::read(
                        &reader,
                        &requested_type,
                        max_size_bytes,
                        &request_client,
                    ),
                )
                .await
                {
                    Ok(Ok(ok)) => ok,
                    Ok(Err(e)) => {
                        warn!(
                            "Failed to read server clipboard for {}: {:?}",
                            request_client, e
                        );
                        (Default::default(), None)
                    }
                    Err(_) => {
                        warn!(
                            "Timed out after {}s reading server clipboard for {}",
                            CLIPBOARD_SERVE_TIMEOUT_SECS, request_client
                        );
                        (Default::default(), None)
                    }
                };
                // Symmetric with the writer's "Serving paste request ... took
                // Ns": makes stalls attributable to the serving side.
                let elapsed = started.elapsed();
                if content.is_empty() {
                    debug!(
                        "Served clipboard fetch for {} in {:.1}s (empty)",
                        requested_type,
                        elapsed.as_secs_f32()
                    );
                } else {
                    debug!(
                        "Served clipboard fetch for {} in {:.1}s ({} bytes)",
                        requested_type,
                        elapsed.as_secs_f32(),
                        content.len()
                    );
                }
                let msg = bulk::ServerBulk::ClipboardHeader(bulk::ServerClipboardHeader {
                    requested_type: &requested_type,
                    data_type: data_type.as_deref(),
                    content_len_bytes: content.len() as u64,
                    request_id,
                });
                match postcard::to_stdvec_cobs(&msg) {
                    Ok(mut bytes) => {
                        bytes.extend_from_slice(&content);
                        // Hand the whole frame back to the loop, which owns
                        // the client links and the full-queue policy (see
                        // RotationEvent::SendBulkFrame).
                        let _ = rotation_tx
                            .send(RotationEvent::SendBulkFrame {
                                endpoint: request_client,
                                frame: bytes,
                                conn_token,
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("Failed to serialize clipboard header: {:?}", e);
                    }
                }
            });
            Ok(())
        }
    }

    /// Replies to a remote client's clipboard fetch with empty content, so its
    /// paste completes (with nothing) immediately instead of waiting out its
    /// fetch timeout. Sent whenever a fetch can't be served: the clipboard is
    /// gone, the requested type isn't offered, or the owning peer is gone.
    /// No-op when the requester is unknown; a requester whose bulk queue is
    /// full or closed is dropped like a write failure (it isn't draining).
    async fn reply_empty_clipboard_fetch(
        &mut self,
        request_client: &SocketAddr,
        requested_type: &str,
        request_id: u64,
    ) {
        if self.roster.get(request_client).is_none() {
            return;
        }
        let msg = bulk::ServerBulk::ClipboardHeader(bulk::ServerClipboardHeader {
            requested_type,
            data_type: None,
            content_len_bytes: 0,
            request_id,
        });
        match postcard::to_stdvec_cobs(&msg) {
            Ok(bytes) => {
                // Same policy as send_bulk: a full or closed queue means the
                // client isn't draining — drop it like a write failure.
                let queued = self
                    .roster
                    .get(request_client)
                    .map(|client| client.link.queue_bulk(bytes));
                if matches!(queued, Some(Err(_))) {
                    warn!(
                        "Unable to send empty clipboard reply to {}: bulk queue full or closed, removing client",
                        request_client
                    );
                    if self.handle_client_removal(request_client).await {
                        self.clipboard_clear().await;
                    }
                }
            }
            Err(e) => {
                error!("Failed to serialize empty clipboard header: {:?}", e);
            }
        }
    }

    /// Sends clipboard content in response to a prior request via clipboard_request_content.
    /// Routes a clipboard payload a peer sent back, to whoever asked for it.
    ///
    /// The destination comes from what we recorded when the fetch went out —
    /// never from the frame. The frame's own `request_client` field is written
    /// by the answering peer, so honoring it would let any approved client
    /// address bytes at any other machine (or at a local paste) simply by
    /// naming it, with no fetch outstanding at all.
    async fn clipboard_send_content_from_client(
        &mut self,
        // The client sending the clipboard data
        data_source: SocketAddr,
        // Correlates the content with its request. Only meaningful paired with
        // data_source: the two together are the key we tracked the fetch under.
        request_id: u64,
        data: data::ClipboardData,
    ) -> Result<()> {
        let Some(pending) = self.clipboard.take_request(data_source, request_id) else {
            // No such fetch is outstanding against this peer: a duplicate, a
            // reply that lost the race with the timeout, or a peer answering
            // something it was never asked.
            warn!(
                "Discarding clipboard data from {} for unknown/timed-out request_id={}",
                data_source, request_id
            );
            return Ok(());
        };
        debug!(
            "Sending clipboard content of requested_type={} data_type={:?} with len={} from source={}",
            data.requested_type,
            data.data_type,
            data.bytes.len(),
            data_source
        );
        match pending {
            clipboard::PendingFetch::Relay {
                client,
                client_request_id,
            } => {
                // Relay to the client that asked, under the id IT used.
                let msg = bulk::ServerBulk::ClipboardHeader(bulk::ServerClipboardHeader {
                    requested_type: &data.requested_type,
                    data_type: data.data_type.as_deref(),
                    content_len_bytes: data.bytes.len() as u64,
                    request_id: client_request_id,
                });
                // If send_bulk returns Ok(false), the client wasn't found. In that case just ignore the request,
                // don't try to reset state since the client should already be removed.
                if !(self.send_bulk(&client, msg, Some(data.bytes)).await?) {
                    warn!("Unable to send clipboard data received from {} to {}: not connected (clients: {:?})",
                          data_source, client, self.roster);
                }
            }
            clipboard::PendingFetch::Local(waiting_clipboard_tx) => {
                // Complete this machine's own pending paste.
                if let Err(_d_again) = waiting_clipboard_tx.send(data) {
                    warn!(
                        "Discarding clipboard data for request_id={}: the requester already gave up (timed out?)",
                        request_id
                    );
                }
            }
        }
        Ok(())
    }

    /// Updates internal state to route future events to the new client (or to the server).
    /// Goes through the steps of notifying the new client that it's active (if new_client is Some),
    /// then notifying any old client that it's inactive (if old_client is Some).
    async fn update_current_client(&mut self, new_client: Option<SocketAddr>) {
        // A switch settles the clipboard state: apply any local update held
        // for the debounce's trailing edge BEFORE the clipboard reconcile
        // below. Otherwise switching away and back inside the debounce window
        // re-advertises the stale pre-copy target on the server, leaving
        // monux's writer owning the selection while the target says the
        // server itself owns the clipboard — every local paste then fails
        // 'against itself' until the next copy.
        self.flush_pending_local_clipboard().await;
        // Either we automatically reenabled a client, or the user manually did.
        // In either case, clear up any history of previously enabled disconnected clients.
        self.removed_current_client = None;

        // Check if the client is already assigned, treat as a no-op if so
        match (&new_client, &self.current_client) {
            (Some(new_client), Some(current_client)) => {
                if new_client == current_client {
                    debug!("Already switched to client: {}", current_client);
                    return;
                }
            }
            (None, None) => {
                debug!("Already switched to local machine");
                return;
            }
            (_, _) => {}
        }

        // Save the old client for sending enabled=false below
        let old_client = self.current_client;

        self.set_and_grab_current_client(new_client).await;

        // Notify the new client (or server) about any current clipboard info,
        // or a noop if it fails. INVARIANT: the types are pushed on the ordered
        // events stream BEFORE Switch(true) below, so a (re-)activated client
        // replaces any stale local types (set_remote_clipboard) before its
        // first-activation re-announce check runs — a stale clipboard must
        // never shadow a genuinely newer one (see client.rs).
        // This may be overridden if the old client sends a clipboard update
        // following the switch, or it won't, if the old client doesn't have a
        // clipboard update to send.
        if let Err(e) = self.update_current_client_clipboard().await {
            warn!(
                "Failed to send clipboard update to active client/server: {:?}",
                e
            );
        }

        if let Some(new_client) = new_client {
            // Try to send switch{true} to the newly assigned current_client.
            // If it fails then current_client is cleaned up.
            //
            // Ok(()) alone does not mean the switch happened: it is also
            // returned when there is no current client to send to, and by the
            // unknown-endpoint recovery — both of which leave input on this
            // machine. The clipboard push just above can trigger exactly that
            // by removing the client on a failed write. Confirming the roster
            // agrees keeps the log line and the notification, which exist so a
            // surprising switch is identifiable afterwards, from reporting the
            // opposite of what happened.
            if let Ok(()) = self
                .send_event_to_remote_client(event::ServerEvent::Switch(event::SwitchEvent {
                    enabled: true,
                }))
                .await
            {
                if self.current_client != Some(new_client) {
                    warn!(
                        "Switch to {} did not take effect; input stays on this machine",
                        new_client
                    );
                    return;
                }
                info!(
                    "Switched to client: {} (clients: {})",
                    new_client,
                    self.roster
                        .iter()
                        .map(|c| c.endpoint.to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
                );
                // No "Input on X" notification while paused: input isn't going
                // anywhere. The resume notification already announces the
                // return to the active target.
                if !self.paused {
                    notify_switch(&format!("Input on {}", new_client.ip()));
                }
            }
        } else {
            info!(
                "Switched to local machine (clients: {})",
                self.roster
                    .iter()
                    .map(|c| c.endpoint.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            );
            if !self.paused {
                notify_switch("Input on this machine");
            }
        }

        // AFTER setting up the new client, lets send enabled=false to the old client.
        // This avoids a potential race between the above clipboard update for current data
        // vs the old client sending a new clipboard update when it's marked inactive.
        if let Some(old_client) = old_client {
            // Try to send switch{false} to last current_client.
            // If it fails then the client is cleaned up.
            let _ = self
                .send_event(
                    &old_client,
                    event::ServerEvent::Switch(event::SwitchEvent { enabled: false }),
                )
                .await;
        }
    }

    /// Updates and announces the current clipboard source for handling any future paste requests.
    /// In practice this occurs when a client broadcasts its clipboard shortly after being told its no longer active.
    async fn update_current_client_clipboard(&mut self) -> Result<()> {
        // Copied out rather than borrowed: the local-clipboard branch below
        // needs &mut self.clipboard, and the target lives inside it.
        let Some((source, types, max_size_bytes)) = self.clipboard.target().map(|c| {
            (c.source, c.types.clone(), c.max_size_bytes)
        }) else {
            // No clipboard to announce
            return Ok(());
        };
        let c = ClipboardTarget {
            source,
            types,
            max_size_bytes,
        };

        if let Some(clipboard_source) = &c.source {
            // The clipboard is from a client.
            if let Some(current_client) = self.current_client {
                // A remote client is active. Tell it about the clipboard, if it isn't the source of the clipboard.
                if current_client != *clipboard_source {
                    let types_str = c.types.join(" ");
                    let types_msg = event::ServerEvent::ClipboardTypes(event::ClipboardTypes {
                        types: &types_str,
                        max_size_bytes: c.max_size_bytes,
                    });
                    debug!(
                        "Sending clipboard types for {} to {}: {}",
                        clipboard_source, current_client, types_str
                    );
                    self.send_event_to_remote_client(types_msg).await?;
                }
            } else if let Some(local_clipboard) = &mut self.clipboard.local {
                // The server is active and its clipboard support is enabled.
                // Tell it about the client clipbard.
                debug!(
                    "Storing clipboard types for {} on server: {}",
                    clipboard_source,
                    c.types.join(" ")
                );
                local_clipboard.store_types(c.types.clone())?;
            } else {
                debug!("Ignoring clipboard types sent by client: Server clipboard is disabled");
            }
        } else {
            // The clipboard is from the server.
            if let Some(current_client) = self.current_client {
                // A remote client is active. Tell it about the clipboard.
                let types_str = c.types.join(" ");
                let types_msg = event::ServerEvent::ClipboardTypes(event::ClipboardTypes {
                    types: &types_str,
                    max_size_bytes: c.max_size_bytes,
                });
                debug!(
                    "Sending clipboard types for server to {}: {}",
                    current_client, types_str
                );
                self.send_event_to_remote_client(types_msg).await?;
            }
        }
        Ok(())
    }

    /// Sends an event to all connected clients, removing any where sending fails.
    /// If this returns true, then clipboard_clear() should also be called.
    async fn send_event_all<F>(&mut self, msg: event::ServerEvent<'_>, test_fn: F) -> Result<bool>
    where
        F: Fn(&ClientInfo) -> bool,
    {
        let mut clients_to_remove = vec![];
        let mut last_err = None;
        for client in self.roster.iter_mut() {
            if test_fn(client) {
                if let Err(e) = send_message_to_client(client.link.as_mut(), &msg).await {
                    clients_to_remove.push(client.endpoint);
                    last_err = Some(e);
                }
            }
        }
        // Reverse: Avoid issues with idx moving as entries are removed
        clients_to_remove.reverse();
        let mut should_clear_clipboard = false;
        for endpoint in clients_to_remove {
            if self.handle_client_removal(&endpoint).await {
                should_clear_clipboard = true;
            }
        }
        if let Some(e) = last_err {
            Err(e)
        } else {
            Ok(should_clear_clipboard)
        }
    }

    /// Records proof of liveness from a client (see ServerEvent::Ping): ANY
    /// received ClientEvent or bulk bytes refresh it, not just Pongs. While
    /// the client is silenced, each received CHUNK (one read on either
    /// stream — a single chunk can carry several buffered pongs, and raw
    /// clipboard payload counts too) increments the consecutive counter.
    /// Automatic re-activation fires once REACTIVATE_PONGS consecutive
    /// chunks arrived AND REACTIVATE_COOLDOWN has passed since the silence —
    /// i.e. at max(cooldown, enough heard-events), so a long freeze followed
    /// by a burst of buffered pongs recovers immediately on thaw. It only
    /// fires when the local target itself came from the silence
    /// (silenced_endpoint): any manual switch action — chord, socket,
    /// goto, a deliberate LOCAL choice included — clears that flag, and a
    /// manual choice always wins (the client is then only marked healthy).
    /// While paused it never fires either: rotation switches are suspended
    /// (see prev_client), so the recovery only marks the client healthy.
    async fn note_client_heard(&mut self, endpoint: SocketAddr) {
        let now = Instant::now();
        let Heard::Recovered {
            pongs,
            silenced_for,
        } = self.liveness.heard(endpoint, now)
        else {
            return;
        };
        // A recovery while paused does NOT re-activate: rotation switches
        // are suspended while paused (see prev_client), so the client is
        // only marked healthy — the user resumes onto the target they paused
        // on, not onto one a link flap picked meanwhile.
        if !self.paused
            && self.current_client.is_none()
            && self.liveness.silenced_endpoint() == Some(endpoint)
        {
            info!(
                "Client {} is answering again ({} consecutive pongs after {:?} silenced): re-activating it",
                endpoint, pongs, silenced_for
            );
            self.update_current_client(Some(endpoint)).await;
        } else {
            info!(
                "Client {} is answering again ({} consecutive pongs after {:?} silenced): input stays on {} ({})",
                endpoint,
                pongs,
                silenced_for,
                match &self.current_client {
                    Some(current) => current.to_string(),
                    None => "local".to_string(),
                },
                if self.paused {
                    "input is paused"
                } else {
                    "the target was chosen manually"
                },
            );
        }
    }

    /// Honors a client's return-to-local request (client-initiated return via
    /// screen-edge detection on the client; see ClientEvent::SwitchRequest):
    /// only the CURRENT client may hand input back — a request from any other
    /// endpoint is stale (or misbehaving) and is ignored. The switch itself
    /// reuses the normal path (update_current_client(None) also sends
    /// Switch(false) to the client, so it releases its keys); the server's
    /// cursor is already parked at the edge the switch out left from, so
    /// cursor continuity needs nothing else.
    async fn switch_request_from_client(&mut self, endpoint: SocketAddr) {
        if self.current_client != Some(endpoint) {
            debug!(
                "Ignoring switch request from {}: not the current client (current: {:?})",
                endpoint, self.current_client
            );
            return;
        }
        let fingerprint = self
            .roster
            .get(&endpoint)
            .map(|c| c.fingerprint.clone())
            .unwrap_or_else(|| "<unknown>".to_string());
        info!("Client {} requested return to local (edge)", fingerprint);
        self.update_current_client(None).await;
    }

    /// App-level liveness check (see ServerEvent::Ping): called every
    /// PING_INTERVAL from the server events loop, like the status and motion
    /// ticks. Pings the current client (and every silenced client, so a
    /// returning one can be heard) and runs the miss detector: a current
    /// client silent for pong_miss_limit intervals is declared silenced —
    /// the server switches to the local machine and ungrabs
    /// (update_current_client(None) also sends Switch(false), so the client
    /// releases its keys), WITHOUT removing the client or touching the
    /// connection: the QUIC idle timeout and the existing removal/resume
    /// paths stay as they are. While paused the detector does not fire:
    /// rotation switches are suspended (see prev_client) and the ungrab is
    /// already in effect, so the first tick after resume re-evaluates.
    pub async fn ping_tick(&mut self) {
        let now = Instant::now();
        // Stall guard: the pings this detector relies on originate from THIS
        // loop, so a loop stall (a slow write, a wedged clipboard op) would
        // guarantee a spurious silence declaration at the first catch-up
        // tick. A late tick (gap over two intervals) therefore skips silence
        // evaluation entirely and grants every watched client a fresh miss
        // window: after a stall we cannot know whether the client was
        // actually silent, and the QUIC idle timeout remains the backstop
        // for a truly dead client.
        let plan = self.liveness.begin_tick(now);
        let tick_late = plan.late;
        if tick_late {
            debug!(
                "Ping tick {:?} late (the rotation loop was busy): skipping silence evaluation and refreshing liveness windows",
                plan.gap.unwrap_or_default()
            );
        }
        // Miss detection first, so a silent current client is ungrabbed
        // before the next ping goes out.
        if !tick_late {
            // While paused the silence detector does not fire: rotation
            // switches are suspended (see prev_client), and the ungrab the
            // switch would provide is already in effect (broadcast_grab_state
            // carries paused to every device task). The same staleness is
            // evaluated again by the first tick after resume and fires then
            // if the client is still silent.
            if !self.paused {
                if let Some(current) = self.current_client {
                    if let Some(silent_for) = self.liveness.silent_for(&current, now) {
                        info!(
                            "No sign of life from current client {} for {:?}: switching to the local machine and ungrabbing; the client stays connected and will be re-activated when it answers again",
                            current, silent_for
                        );
                        // Arms automatic re-activation for THIS endpoint
                        // (see LivenessTracker::silence).
                        self.liveness.silence(current, now);
                        self.update_current_client(None).await;
                    }
                }
            }
            // A fresh miss while a silenced client was recovering resets its
            // consecutive counter (hysteresis against a flapping link).
            for endpoint in self.liveness.reset_stalled_recoveries(now) {
                debug!(
                    "Silenced client {} went quiet again during recovery: resetting its consecutive-pong count",
                    endpoint
                );
            }
        }
        // Ping the current client and every silenced client. A write failure
        // removes the client (same policy as input forwarding); a black-holed
        // link accepts the write into the send buffer, so the miss detector
        // above — not the write — is what notices the silence.
        for endpoint in self.liveness.ping_targets(self.current_client) {
            let _ = self
                .send_event(&endpoint, event::ServerEvent::Ping)
                .await;
        }
    }

    /// Periodic INFO snapshot of input flow, plus warnings for the two ways
    /// input can silently die: grabbed locally but nothing emitted, or a client
    /// is active but nothing is forwarded. Called on a timer from the server
    /// events loop; counters reset each call.
    pub fn log_input_status(&mut self) {
        // Per-client link quality, surfaced on rtt-threshold crossings only:
        // a degraded link is evidence worth having (even in an otherwise idle
        // window, which returns early below), but the heartbeat fires every
        // 10s, so the line is logged on the healthy→degraded transition (and
        // its degraded→healthy recovery), not in every window — a chronically
        // bad link must not spam one INFO line per client per window forever.
        for c in self.roster.iter() {
            let path = c.link.stats();
            let Some(link) = self.link_quality.get_mut(&c.endpoint) else {
                continue;
            };
            match degraded_link_transition(&mut link.degraded, path.rtt) {
                Some(true) => info!(
                    "Link to {} is degraded: rtt={:.0}ms, {} of {} packets lost over the connection's lifetime, {} congestion events — a WiFi/link issue, not monux (check power save on both machines, 2.4GHz congestion, prefer 5GHz)",
                    c.endpoint,
                    path.rtt.as_secs_f64() * 1000.0,
                    path.lost_packets,
                    path.sent_packets,
                    path.congestion_events,
                ),
                Some(false) => info!(
                    "Link to {} recovered: rtt={:.0}ms is back under the {:.0}ms degraded threshold",
                    c.endpoint,
                    path.rtt.as_secs_f64() * 1000.0,
                    HEARTBEAT_LINK_RTT_WARN.as_secs_f64() * 1000.0,
                ),
                None => {}
            }
        }
        let counts = std::mem::take(&mut self.status_counts);
        let secs = self.status_window_start.elapsed().as_secs_f64().max(0.1);
        self.status_window_start = Instant::now();
        let grab = format!("{:?}", *self.grab_tx.borrow());
        // Stay silent when completely idle on the local machine: a freeze
        // window always has non-zero counts, so silence loses no evidence.
        // Use physical_grabbed (not physical) so an ungrabbed mouse moving
        // while local doesn't look like activity — only forwarded or emitted
        // input is meaningful.
        let idle_local = self.current_client.is_none()
            && counts.physical_grabbed == 0
            && counts.forwarded == 0
            && counts.emitted_local == 0;
        if idle_local {
            return;
        }
        if self.paused {
            // Paused: devices are ungrabbed and input goes raw to the local
            // system; we only listen (and count) here. Report separately so a
            // paused server doesn't look like a swallowing one.
            info!(
                "Input status: PAUSED (all devices ungrabbed, raw local input): {} events seen and dropped ({:.1}/s)",
                counts.physical,
                counts.physical as f64 / secs
            );
            return;
        }
        match self.current_client {
            Some(endpoint) => info!(
                "Input status: switched to {} ({}): {} events in, {} forwarded ({:.1}/s)",
                endpoint,
                grab,
                counts.physical,
                counts.forwarded,
                counts.forwarded as f64 / secs
            ),
            // Input staying on the local machine is the resting state, and
            // grabbed keyboards emit locally the whole time you type — so at
            // INFO this line alone accounts for the overwhelming majority of
            // a normal day's log, burying the lines worth finding when
            // something goes wrong. Forwarding (above) and pausing stay at
            // INFO: those say where your input actually went.
            None => debug!(
                "Input status: local ({}): {} events in, {} emitted locally ({:.1}/s)",
                grab,
                counts.physical,
                counts.emitted_local,
                counts.emitted_local as f64 / secs
            ),
        }
        // Swallow detection: input from GRABBED devices arrived but had
        // nowhere to go. Ungrabbed (passthrough) devices never emit/forward
        // by design, so they must not count here (mouse movement is not
        // swallowed input). The event threshold avoids false positives from
        // a consumed switch combo. (The paused case returned above: dropped
        // input is expected there.)
        if counts.physical_grabbed >= 8 {
            if self.current_client.is_some() && counts.forwarded == 0 {
                warn!(
                    "INPUT SWALLOWED: {} physical events seen while switched to a client, but none were forwarded!",
                    counts.physical_grabbed
                );
            } else if self.current_client.is_none() && counts.emitted_local == 0 {
                warn!(
                    "INPUT SWALLOWED: {} physical events seen while local with devices grabbed, but none were emitted to the virtual devices!",
                    counts.physical_grabbed
                );
            }
        }
    }

    /// Builds the structured snapshot served by the control socket's status
    /// (control.rs). The listen address is left empty here — the loop doesn't
    /// know it; the mirror fills it in on read (DiagnosticsMirror::server_state).
    fn server_state(&self) -> crate::control::ServerState {
        crate::control::ServerState {
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: crate::msgs::shared::PROTOCOL_VERSION,
            listen: String::new(),
            paused: self.paused,
            current_target: match &self.current_client {
                Some(endpoint) => endpoint.to_string(),
                None => "local".to_string(),
            },
            clients: self
                .roster
                .iter()
                .map(|c| {
                    // Resolved edge directions come from the cache, refreshed
                    // on topology changes only: resolving here would cost a
                    // blocking DNS lookup per hostname target per refresh
                    // (see EdgeDirectionsCache).
                    let edge = self.edge_dirs.edge_string(&c.endpoint);
                    crate::control::ServerClientState {
                        addr: c.endpoint.to_string(),
                        fingerprint: c.fingerprint.clone(),
                        connected_since_secs: c.connected_at.elapsed().as_secs(),
                        rtt_ms: Some(c.link.stats().rtt.as_millis() as u64),
                        edge,
                    }
                })
                .collect(),
            clipboard: match self.clipboard.target() {
                Some(target) => crate::control::ServerClipboardState {
                    owner: match &target.source {
                        Some(source) => source.to_string(),
                        None => "local".to_string(),
                    },
                    types: target.types.clone(),
                },
                None => crate::control::ServerClipboardState {
                    owner: "none".to_string(),
                    types: Vec::new(),
                },
            },
            update_available: crate::autoupdate::update_available(),
        }
    }

    /// Refreshes the shared diagnostics mirror with the current state, at
    /// most once per DIAGNOSTICS_REFRESH_INTERVAL. Called after EVERY
    /// rotation loop iteration — thousands of times a second at 8kHz input —
    /// and the refresh builds the full control-socket snapshot, so the cap
    /// keeps that cost bounded. The mirror is a best-effort diagnostics
    /// view: the SIGHUP dump (which reads the mirror directly from the
    /// signal thread) and the control status may lag the loop by up to
    /// 100ms, and a stalled loop still shows up via the liveness timestamp
    /// of the last completed refresh. The first call always refreshes, so
    /// the seeding call at server start (before the first event) still
    /// lands.
    pub fn update_diagnostics(&mut self) {
        let now = Instant::now();
        if self
            .last_diagnostics_refresh
            .is_some_and(|last| now.duration_since(last) < DIAGNOSTICS_REFRESH_INTERVAL)
        {
            return;
        }
        self.last_diagnostics_refresh = Some(now);
        let grab = format!("{:?}", *self.grab_tx.borrow());
        let mut state = format!(
            "current_client={:?} grab={} paused={} clients={:?} removed_current_client={:?} pending_resume_fingerprint={:?} clipboard_target={:?} pending_clipboard_requests={} motion_seq={} datagrams_ok={} counts={{physical={} forwarded={} emitted_local={}}}",
            self.current_client,
            grab,
            self.paused,
            self.roster,
            self.removed_current_client,
            self.pending_resume_fingerprint,
            self.clipboard.target(),
            self.clipboard.pending_request_count(),
            self.motion.seq(),
            self.roster
                .iter()
                .map(|c| format!("{}:{}", c.endpoint, c.datagrams_ok))
                .collect::<Vec<_>>()
                .join(", "),
            self.status_counts.physical,
            self.status_counts.forwarded,
            self.status_counts.emitted_local,
        );
        if self.motion.dirty() {
            let (dx, dy, events) = self.motion.pending();
            state.push_str(&format!(
                " coalesced_motion_pending={{dx={} dy={} events={}}}",
                dx, dy, events
            ));
        }
        self.diagnostics.update(state);
        self.diagnostics.update_control(self.server_state());
    }

    /// Whether coalesced motion is waiting for the flush timer (see --motion-hz).
    pub fn motion_dirty(&self) -> bool {
        self.motion.dirty()
    }

    /// The motion flush interval currently in effect: pinned by --motion-hz,
    /// or derived from the current client's measured link tier in Adaptive
    /// mode (None = forward every event as it comes). Read on demand: in
    /// Adaptive mode the server events loop rebuilds its flush tick whenever
    /// the current client's tier changes (see sample_link_quality).
    pub fn motion_flush_interval(&self) -> Option<Duration> {
        self.motion.flush_interval(self.current_client_tier())
    }

    /// The measured tier of the current client's link, Normal when local (or
    /// its state hasn't been sampled yet).
    fn current_client_tier(&self) -> Tier {
        self.current_client
            .and_then(|endpoint| self.link_quality.get(&endpoint))
            .map(|state| state.quality.tier())
            .unwrap_or(Tier::Normal)
    }

    /// Samples every client's connection stats for the adaptive-fidelity
    /// tiers (see network::link_quality): feeds the per-client tracker,
    /// rewrites the bulk pacing cell on tier transitions, and returns true
    /// when the CURRENT client's tier changed — the caller then rebuilds the
    /// motion flush tick at the new rate. Called on a timer from the server
    /// events loop.
    pub fn sample_link_quality(&mut self) -> bool {
        let mut current_tier_changed = false;
        for client in self.roster.iter() {
            let Some(state) = self.link_quality.get_mut(&client.endpoint) else {
                continue;
            };
            let path = client.link.stats();
            let sent = path.sent_packets;
            let lost = path.lost_packets;
            let delta_sent = sent.saturating_sub(state.last_sent);
            let delta_lost = lost.saturating_sub(state.last_lost);
            state.last_sent = sent;
            state.last_lost = lost;
            // An idle window carries too few packets for its loss rate to
            // mean anything (one lost keepalive would read as >10% loss):
            // judge those windows on RTT alone.
            let loss_rate = if delta_sent >= 20 {
                delta_lost as f64 / delta_sent as f64
            } else {
                0.0
            };
            let Some(tier) = state.quality.sample(path.rtt, loss_rate) else {
                continue;
            };
            throttle::set_throttle(
                &state.throttle,
                effective_throttle_mbps(&self.throttle_mode, tier),
            );
            if self.current_client == Some(client.endpoint) {
                current_tier_changed = true;
            }
            info!(
                "Adaptive fidelity for {}: {} (motion {} Hz, bulk {})",
                client.endpoint,
                match tier {
                    Tier::Proximity => "link measured close and clean, raising fidelity",
                    Tier::Normal => "link no longer close, back to defaults",
                },
                match tier {
                    Tier::Proximity => ADAPTIVE_MOTION_PROXIMITY_HZ,
                    Tier::Normal => ADAPTIVE_MOTION_NORMAL_HZ,
                },
                match effective_throttle_mbps(&self.throttle_mode, tier) {
                    Some(mbps) => format!("{} Mbps", mbps),
                    None => "unthrottled".to_string(),
                }
            );
        }
        current_tier_changed
    }

    /// Sends any coalesced pointer motion to the active client as a single
    /// batch (see --motion-hz). No-op when nothing is pending.
    pub async fn flush_pending_motion(&mut self) {
        if !self.motion.dirty() {
            return;
        }
        let (dx, dy, source_count) = self.motion.take_pending();
        let endpoint = match self.current_client {
            Some(c) => c,
            // Switched away meanwhile; the pending deltas are moot.
            None => return,
        };
        if dx == 0 && dy == 0 {
            return;
        }
        // Coalesced flushes go as datagrams, not over the ordered stream: a
        // reliable stream retransmits and replays stale motion in order after
        // a WiFi blip, which presents as the cursor sluggishly replaying a
        // backlog. Datagrams never retransmit, and quinn drops the oldest
        // queued datagram when its buffer is full, so no stale-motion backlog
        // can ever pile up. Lost frames are healed position-losslessly via the
        // repeated history (see MotionDatagram).
        match self.try_send_motion_datagram(&endpoint, dx, dy, true) {
            MotionSend::Sent => {
                self.status_counts.forwarded += source_count;
                return;
            }
            MotionSend::Retry => {
                // Keep the deltas pending; they retry (with any newer motion
                // accumulated on top) at the next flush opportunity.
                self.motion.restore_pending((dx, dy, source_count));
                return;
            }
            MotionSend::Fallback => {}
        }
        // Stream fallback (peer can't do datagrams): ordered and lossless.
        let mut events = Vec::with_capacity(2);
        if dx != 0 {
            events.push(event::motion_event(evdev::RelativeAxisCode::REL_X.0, dx));
        }
        if dy != 0 {
            events.push(event::motion_event(evdev::RelativeAxisCode::REL_Y.0, dy));
        }
        if let Err(e) = self
            .send_event_to_remote_client(event::ServerEvent::Input(events))
            .await
        {
            warn!("Failed to forward coalesced motion: {:?}", e);
        } else {
            self.status_counts.forwarded += source_count;
        }
    }

    /// Attempts to send one motion frame as a QUIC datagram. `with_history`
    /// repeats recent frames so the receiver can heal losses (coalesced mode);
    /// full-rate motion skips it, since a lost frame is superseded anyway.
    /// Fallback means the peer can't do datagrams at all (permanently); Retry
    /// means the send buffer is momentarily full and the caller should keep
    /// the deltas pending.
    fn try_send_motion_datagram(
        &mut self,
        endpoint: &SocketAddr,
        dx: i32,
        dy: i32,
        with_history: bool,
    ) -> MotionSend {
        if !self
            .roster
            .get(endpoint)
            .is_some_and(|client| client.datagrams_ok)
        {
            return MotionSend::Fallback;
        }
        let Some(serialized) = self.motion.stage(dx, dy, with_history) else {
            return MotionSend::Fallback;
        };
        let history_len = self.motion.staged_frames();
        let sent = match self.roster.get(endpoint) {
            Some(client) => client.link.send_datagram(serialized),
            None => return MotionSend::Fallback,
        };
        match sent {
            Ok(()) => {
                self.motion.record_sent(dx, dy, with_history);
                if self.motion.announce_once() {
                    info!(
                        "Sending pointer motion to {} as QUIC datagrams (lost frames are healed from repeated history, not retransmitted)",
                        endpoint
                    );
                }
                trace!(
                    "Sent motion datagram seq={} ({} frames) to {}",
                    self.motion.seq(),
                    history_len,
                    endpoint
                );
                MotionSend::Sent
            }
            Err(e @ (SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled)) => {
                debug!(
                    "QUIC datagrams unsupported by {} ({}), using the ordered stream for motion",
                    endpoint, e
                );
                if let Some(client) = self.roster.get_mut(endpoint) {
                    client.datagrams_ok = false;
                }
                MotionSend::Fallback
            }
            Err(e @ SendDatagramError::TooLarge) => {
                // Unreachable for our tiny frames; treated as "not queued" so
                // the caller keeps the deltas pending rather than losing them.
                trace!("Motion datagram to {} not queued ({}), retrying later", endpoint, e);
                MotionSend::Retry
            }
            Err(e) => {
                // ConnectionLost: stream-write instead; a dead connection
                // fails there properly and removes the client.
                trace!(
                    "Motion datagram to {} not sent ({}), using the stream",
                    endpoint, e
                );
                MotionSend::Fallback
            }
        }
    }

    /// Sends an event to the currently active client, removing it if sending fails.
    /// If no client is active, this does nothing.
    /// Whether this client negotiated a version that understands
    /// class-tagged input frames. Unknown clients (never added, or already
    /// removed) fall back to the untagged frame: the older form is
    /// understood by every peer.
    fn client_speaks_device_class(&self, endpoint: &SocketAddr) -> bool {
        self.roster
            .iter()
            .find(|client| client.endpoint == *endpoint)
            .is_some_and(|client| shared::sends_device_class(client.negotiated_version))
    }

    async fn send_event_to_remote_client(&mut self, msg: event::ServerEvent<'_>) -> Result<()> {
        let current_client = match self.current_client {
            Some(client) => client,
            None => {
                // On local machine, nothing to do
                return Ok(());
            }
        };
        if !(self.send_event(&current_client, msg).await?) {
            // Active client not found?
            // Shouldn't happen, but recover by switching to local machine and ungrabbing.
            // Otherwise we're leaving the server stuck in a grabbed state.
            self.set_and_grab_current_client(None).await;
        }
        Ok(())
    }

    /// Handles an input event collected from the server.
    pub async fn send_input_events(&mut self, batch: device::InputBatch) -> Result<()> {
        let event_count = batch.events.len() as u64;
        self.status_counts.physical += event_count;
        if batch.is_grabbed {
            self.status_counts.physical_grabbed += event_count;
        }
        if self.paused {
            // Paused: all devices are ungrabbed, so the local machine already
            // sees this input raw. monux only keeps listening (for the pause
            // chord) — nothing is forwarded or re-emitted.
            keytrace_route(&batch.events, "paused drop");
            return Ok(());
        }
        if let Some(endpoint) = self.current_client {
            // Remote client is active, send all input to client and not to local machine.
            if !batch.is_grabbed {
                // ...but only GRABBED input: an ungrabbed device already
                // delivered this batch to the local compositor, so forwarding
                // it too would double every event (seen as double pointer
                // input while a mouse grab keeps failing — e.g. a foreign
                // process holding the grab — or during the re-grab window on
                // resume). Keyboards reach this arm too, while a grab of
                // theirs is still being retried (see apply_grab_transition).
                // This input belongs to the local system exclusively; drop it.
                keytrace_route(&batch.events, "ungrabbed drop (client active)");
                trace!(
                    "Dropping {} ungrabbed input events while client {} is active (grab pending or failing; the local system already has them)",
                    event_count,
                    endpoint
                );
                return Ok(());
            }
            let events = batch.events;
            keytrace_route(&events, "forward to client");
            if is_pure_pointer_motion(&events) {
                if self.motion_flush_interval().is_some() {
                    // Office-mode coalescing (--motion-hz): sum the deltas into
                    // the accumulator; the flush timer forwards them at the
                    // configured rate as datagrams. Lossless for the
                    // cursor position, far less network/CPU load than one
                    // message per 8kHz poll.
                    self.motion.accumulate(&events);
                    return Ok(());
                }
                // Full-rate motion (--motion-hz 0) goes over unreliable/unordered
                // QUIC datagrams: a lost motion update is instantly superseded by
                // the next one, so skipping it beats stalling all later input
                // behind a stream retransmission (the cause of visible
                // micro-stutter). The batch is pure REL_X/REL_Y, so summing it
                // into one frame is lossless.
                let mut dx = 0i32;
                let mut dy = 0i32;
                for e in &events {
                    if let Some(i) = &e.inputi32 {
                        if i.code == evdev::RelativeAxisCode::REL_X.0 {
                            dx = dx.saturating_add(i.value);
                        } else {
                            dy = dy.saturating_add(i.value);
                        }
                    }
                }
                match self.try_send_motion_datagram(&endpoint, dx, dy, false) {
                    MotionSend::Sent => {
                        self.status_counts.forwarded += event_count;
                        return Ok(());
                    }
                    MotionSend::Retry => {
                        // Send buffer full: skip this update entirely; the next
                        // poll supersedes it (full-rate motion is lossy by design).
                        return Ok(());
                    }
                    MotionSend::Fallback => {}
                }
            }
            // Best-effort ordering: flush coalesced motion (as unreliable
            // datagrams) before sending this batch on the ordered stream.
            // The datagram can race the stream on the wire, so the ordering
            // is not guaranteed — but the common case (click after motion on
            // the same path) works well enough in practice.
            self.flush_pending_motion().await;
            // Tag the frame with its source device's class for clients that
            // understand it; a client negotiated below v17 has no variant for
            // it and gets the untagged frame (see shared::sends_device_class).
            let msg = if self.client_speaks_device_class(&endpoint) {
                event::ServerEvent::ClassedInput {
                    class: batch.class,
                    events,
                }
            } else {
                event::ServerEvent::Input(events)
            };
            self.send_event_to_remote_client(msg).await?;
            self.status_counts.forwarded += event_count;
            Ok(())
        } else if batch.is_grabbed {
            // Local machine is active and device is grabbed, write input to local virtual devices.
            // For example, we grab keyboards so that we can skip sending switch combos to the local system.
            keytrace_route(&batch.events, "emit local");
            self.output_handler.write(batch.events).await?;
            self.status_counts.emitted_local += event_count;
            Ok(())
        } else {
            // Local machine is active and device isn't grabbed (passthrough), drop input event.
            // For example, we don't grab mice/touchpads since they aren't relevant to switch combos.
            keytrace_route(&batch.events, "passthrough drop");
            // If we send their input to the handler, the input is duplicated between the passthrough
            // and the virtual device.
            Ok(())
        }
    }

    /// Sends an event to the specified client, removing it if sending fails.
    /// If the client isn't found, returns Ok(false)
    /// If sending the message fails, removes the client and returns Err
    async fn send_event(
        &mut self,
        endpoint: &SocketAddr,
        msg: event::ServerEvent<'_>,
    ) -> Result<bool> {
        // Serialize up front: a serialization failure is a problem with the message,
        // not with the client's connection, so it shouldn't kick the client out.
        // postcard's cobs flavor backpatches the overhead byte, so it needs a
        // sized slice rather than an Extend target: serialize into the reusable
        // scratch, growing it (once per size class, then it stays put) whenever
        // a frame doesn't fit.
        let serializedmsg: &[u8] = loop {
            let attempt = postcard::to_slice_cobs(&msg, &mut self.serialize_scratch).map(|s| s.len());
            match attempt {
                Ok(len) => break &self.serialize_scratch[..len],
                Err(postcard::Error::SerializeBufferFull) => {
                    let grown = (self.serialize_scratch.len() * 2).max(1024);
                    self.serialize_scratch.resize(grown, 0);
                }
                Err(e) => {
                    error!("Failed to serialize event message: {:?}", e);
                    return Err(anyhow!("Failed to serialize event message: {:?}", e));
                }
            }
        };
        match self.roster.get_mut(endpoint) {
            Some(client) => {
                trace!(
                    "Sending {} byte serialized message: {:X?}",
                    serializedmsg.len(),
                    &serializedmsg
                );
                let sent = client.link.send_events(serializedmsg).await;
                if let Err(e) = sent {
                    if self.handle_client_removal(endpoint).await {
                        self.clipboard_clear().await;
                    }
                    Err(e)
                } else {
                    Ok(true)
                }
            }
            None => {
                warn!(
                    "Event client {} not found in the roster: {:?}",
                    endpoint, self.roster
                );
                Ok(false)
            }
        }
    }

    /// Sends a diagnostics request to every connected client, returning one
    /// entry per client for the requester to await.
    ///
    /// Every client produces an entry, including the ones that can't answer:
    /// a peer skipped for being too old, or one whose queue wouldn't take the
    /// request, is EVIDENCE. Dropping it would make a two-machine report
    /// quietly look like a one-machine setup.
    ///
    /// Deliberately NOT routed through send_bulk: that path drops a client
    /// whose queue won't take a frame, which is right for clipboard routing
    /// (both sides would otherwise disagree about who owns the clipboard) and
    /// wrong here. The queue holds bulk::BULK_QUEUE_CAPACITY frames and the
    /// writer sleeps BETWEEN them while pacing a large transfer (see
    /// network::throttle), so a full queue is an ordinary state during a
    /// multi-megabyte clipboard copy — and filing a bug report must never be
    /// the thing that severs the connection it is about. The client side
    /// already says exactly this about the answering direction (client.rs).
    fn request_peer_diagnostics(&self, lines: u32) -> Vec<PendingPeer> {
        let hub = crate::control::peer_diagnostics_hub();
        let mut pending = Vec::with_capacity(self.roster.len());
        for client in self.roster.iter() {
            let label = format!(
                "{} @ {}",
                fingerprint_prefix(&client.fingerprint),
                client.endpoint
            );
            if !shared::supports_peer_diagnostics(client.negotiated_version) {
                pending.push(PendingPeer {
                    label,
                    waiting: Err(format!(
                        "runs protocol v{}, which predates peer diagnostics (v{}); \
                         update that machine, or run 'monux diagnostics' on it directly",
                        client.negotiated_version,
                        shared::PROTOCOL_VERSION_PEER_DIAGNOSTICS
                    )),
                    request_id: None,
                });
                continue;
            }
            let (request_id, rx) = hub.open(client.endpoint);
            let msg = bulk::ServerBulk::DiagnosticsRequest(bulk::DiagnosticsRequest {
                request_id,
                lines,
            });
            let queued = match postcard::to_stdvec_cobs(&msg) {
                Ok(bytes) => queue_diagnostics_frame(client.link.as_ref(), bytes),
                Err(e) => Err(format!("its request could not be serialized: {:?}", e)),
            };
            match queued {
                Ok(()) => pending.push(PendingPeer {
                    label,
                    waiting: Ok(rx),
                    request_id: Some(request_id),
                }),
                Err(reason) => {
                    debug!("Not asking {} for diagnostics: {}", client.endpoint, reason);
                    hub.cancel(request_id);
                    pending.push(PendingPeer {
                        label,
                        waiting: Err(reason),
                        request_id: None,
                    });
                }
            }
        }
        pending
    }

    /// Queues a frame a spawned task produced (see
    /// RotationEvent::SendBulkFrame). A stale token means the endpoint was
    /// reused by a newer connection and this frame belongs to the dead one.
    async fn send_bulk_frame(&mut self, endpoint: &SocketAddr, frame: Vec<u8>, conn_token: u64) {
        let queued = match self.roster.get(endpoint) {
            Some(client) if client.conn_token == conn_token => {
                Some(client.link.queue_bulk(frame))
            }
            Some(_) => {
                debug!("Dropping a bulk frame for {}: its connection was replaced", endpoint);
                return;
            }
            None => {
                debug!("Dropping a bulk frame for {}: no longer connected", endpoint);
                return;
            }
        };
        if let Some(Err(e)) = queued {
            warn!("Bulk queue to {} failed ({}), removing client", endpoint, e);
            if self.handle_client_removal(endpoint).await {
                self.clipboard_clear().await;
            }
        }
    }

    async fn send_bulk(
        &mut self,
        endpoint: &SocketAddr,
        msg: bulk::ServerBulk<'_>,
        payload: Option<Vec<u8>>,
    ) -> Result<bool> {
        // Serialize up front: a serialization failure is a problem with the message,
        // not with the client's connection, so it shouldn't kick the client out.
        let mut bytes = postcard::to_stdvec_cobs(&msg)
            .map_err(|e| anyhow!("Failed to serialize bulk message: {:?}", e))?;
        if let Some(payload) = payload {
            trace!("Queueing {} byte payload for {}", payload.len(), endpoint);
            bytes.extend_from_slice(&payload);
        }
        // The network write happens in the client's bulk writer task, so large
        // payloads never block the rotation loop. try_send keeps it that way
        // with a bounded queue, and each queued blob is a whole frame, so
        // nothing is dropped mid-message. A FULL queue means the client isn't
        // draining (a closed one means its writer task died): drop the client
        // like a write failure — it would die on the QUIC idle timeout anyway.
        let sent = self
            .roster
            .get(endpoint)
            .map(|client| client.link.queue_bulk(bytes));
        match sent {
            Some(Ok(())) => Ok(true),
            Some(Err(e)) => {
                warn!("Bulk queue to {} failed ({}), removing client", endpoint, e);
                if self.handle_client_removal(endpoint).await {
                    self.clipboard_clear().await;
                }
                Ok(false)
            }
            None => {
                warn!(
                    "Bulk client {} not found in the roster: {:?}",
                    endpoint, self.roster
                );
                Ok(false)
            }
        }
    }

    /// Removes the client and switches to the server if it was the active client.
    /// If this returns true, then clipboard_clear() should also be called.
    async fn handle_client_removal(&mut self, endpoint: &SocketAddr) -> bool {
        // Liveness bookkeeping goes away with the client, kept in lockstep
        // with the clients list (a removal for a never-added endpoint just
        // finds no entry).
        self.liveness.forget(endpoint);
        self.link_quality.remove(endpoint);
        self.edge_info_sent.remove(endpoint);
        self.clipboard_fetch_budget.remove(endpoint);
        // Always refetch the idx to avoid issues if there was an await in which the client was
        // removed behind our back.
        if self.roster.remove(endpoint) {
            // Drop the source's debounce entry too: reconnects arrive with a
            // fresh ephemeral port, so keeping it would leak one map key per
            // reconnect.
            self.clipboard.forget_source(endpoint);
            // Fetches this client owed a reply to will never be answered, and
            // fetches made on its behalf have nowhere to go. Dropping both now
            // keeps the pending map from growing across reconnects; a Relay
            // entry has no closed-channel signal to prune it later.
            self.clipboard.drop_requests_for(*endpoint);
            notify_client_dropped(endpoint);
        } else {
            // Can happen when cleaning up a client that was never added.
            debug!("Client to remove not found in rotation: {}", endpoint);
            return false;
        }
        self.publish_edge_clients();
        // Client list changed: re-resolve the cached edge directions for the
        // control status (a peer's removal can make 'auto' resolve again).
        self.refresh_edge_dirs();
        // Topology changed: re-advertise so remaining clients that have
        // become resolvable (e.g. 'auto' with one peer left) learn their
        // return edge too. Re-sends are idempotent on the client.
        let remaining: Vec<(SocketAddr, String)> = self.roster.entries();
        for (endpoint, fingerprint) in remaining {
            self.advertise_edge_info(&endpoint, &fingerprint).await;
        }
        let client_list = self.roster.endpoint_list();

        let mut should_clear_clipboard = false;
        if let Some(clipboard_info) = self.clipboard.target() {
            if let Some(clipboard_source) = &clipboard_info.source {
                if clipboard_source == endpoint {
                    // The removed client owned the clipboard. Remove the clipboard.
                    should_clear_clipboard = true;
                }
            }
        }

        if let Some(current_client) = self.current_client {
            if current_client == *endpoint {
                // This is the active client. Remove it AND switch to local machine.
                info!(
                    "Removing client {} from rotation and switching to local machine (clients: {})",
                    endpoint,
                    if client_list.is_empty() {
                        "none".to_string()
                    } else {
                        client_list
                    }
                );

                // Current client is being removed. If it comes back soon, we can mark it current again.
                self.removed_current_client = Some(DefunctClientInfo {
                    endpoint: current_client,
                    removed_at: Instant::now(),
                });

                self.set_and_grab_current_client(None).await;
                return should_clear_clipboard;
            }
        }

        // Non-current client. If its silence sent us local, seed a recovery
        // window so its reconnect re-activates the session — otherwise the
        // silence → drop → reconnect path loses auto-reactivation (a
        // silenced client that then drops is no longer current_client, so
        // the removal would skip the DefunctClientInfo above).
        if self.liveness.silenced_endpoint() == Some(*endpoint) {
            self.removed_current_client = Some(DefunctClientInfo {
                endpoint: *endpoint,
                removed_at: Instant::now(),
            });
            self.liveness.clear_silenced();
        }

        info!(
            "Removing client {} from client rotation: {}",
            endpoint,
            if client_list.is_empty() {
                "empty".to_string()
            } else {
                client_list
            }
        );
        should_clear_clipboard
    }

    async fn set_and_grab_current_client(&mut self, client: Option<SocketAddr>) {
        if self.current_client.is_none() && client.is_some() {
            // Switching away from the local machine: release any keys held on the
            // local virtual devices so they don't get stuck pressed.
            if let Err(e) = self.output_handler.release_all().await {
                warn!("Failed to release held keys on local virtual devices: {:?}", e);
            }
        }
        // Motion accumulated (or already flushed) for the previous target is
        // moot after a switch.
        self.motion.clear();
        self.current_client = client;
        if let Some(endpoint) = client {
            // A switched-to client gets a fresh liveness window (see
            // ServerEvent::Ping): stale bookkeeping — e.g. a previous
            // silence — must not re-fire instantly, and if the client is
            // still silent the miss detector simply ungrabs again. This is
            // what makes a manual switch to a silenced client safe.
            self.liveness.track(endpoint);
            // Input is on a client now, so any silence-driven local state is
            // over (see silenced_endpoint).
            self.liveness.clear_silenced();
        }
        // Record which client is active (or none) so that an unexpected exit
        // mid-session can be recovered on the next server start. This is the
        // single funnel for current_client changes, incl. client removal.
        match client {
            Some(endpoint) => {
                if let Some(fingerprint) =
                    self.roster.get(&endpoint).map(|c| c.fingerprint.clone())
                {
                    if let Err(e) = fs::write(&self.active_client_path, &fingerprint) {
                        warn!("Failed to record active client state: {:?}", e);
                    }
                }
            }
            None => clear_active_client(&self.active_client_path),
        }
        // Broadcast the grab state to ALL device tasks (keyboard-class and
        // toggled): keyboards grab whenever input isn't paused, mice only
        // while a client is active too.
        self.broadcast_grab_state();
    }

    /// Drops pending server-originated clipboard fetches whose requester
    /// already gave up (timed out). New requests prune on arrival; this runs
    /// from the server events loop's status tick so dead entries also get
    /// pruned when no new requests arrive.
    pub fn prune_pending_clipboard_requests(&mut self) {
        self.clipboard.prune_requests();
    }

    /// Ensures that all clients and the server have their clipboard state cleared.
    /// To be called when handle_client_removal() returns true, when a client holding the clipboard has disconnected.
    /// Broken into a separate function to avoid recursive async calls.
    async fn clipboard_clear(&mut self) {
        debug!("Clearing clipboard on server and all clients");
        self.clipboard.clear_target();

        // Fail any server-originated fetches still waiting on the departed
        // owner: dropping the senders errors the receivers immediately, so
        // they resolve empty instead of waiting out the 5s fetch timeout.
        self.clipboard.clear_requests();

        // Clear the server's host clipboard status
        if let Some(c) = &mut self.clipboard.local {
            if let Err(e) = c.store_types(vec![]) {
                // Keep going with the clients...
                warn!("Failed to clear server clipboard: {}", e);
            }
        }

        // Clear all clients' host clipboard statuses (the client was already removed)
        let types_msg = event::ServerEvent::ClipboardTypes(event::ClipboardTypes {
            types: "",
            // Size shouldn't matter for clearing clipboard...
            max_size_bytes: 0,
        });
        // Treat this as best-effort to tidy up the clients, they should reset locally when disconnected.
        if let Err(e) = self
            .send_event_all(types_msg, |_client: &ClientInfo| true)
            .await
        {
            warn!("Failed to clear clipboard on all clients: {}", e);
        }
    }
}

async fn send_message_to_client<T>(link: &mut dyn ClientLink, msg: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    // Serialize message data: postcard with cobs encoding for event framing
    let serializedmsg = postcard::to_stdvec_cobs(&msg)
        .map_err(|e| anyhow!("Failed to serialize message: {:?}", e))?;
    trace!(
        "Sending {} byte serialized message: {:X?}",
        serializedmsg.len(),
        &serializedmsg
    );
    link.send_events(&serializedmsg).await
}

/// Queues one serialized diagnostics frame on a client's bulk writer,
/// mapping a queue that won't take it to the reason the bug report records
/// for that peer. Never drops the client (see request_peer_diagnostics).
///
/// A free function over the link so the policy reads on its own, and so a
/// test can hand it a queue that refuses.
fn queue_diagnostics_frame(
    link: &dyn ClientLink,
    bytes: Vec<u8>,
) -> std::result::Result<(), String> {
    link.queue_bulk(bytes).map_err(|e| match e {
        // The common case, and the reason this path exists: the writer is
        // pacing a large clipboard transfer and hasn't drained the queue yet.
        BulkQueueError::Full => "its bulk queue is busy — a large clipboard \
             transfer is probably in flight; retry the report once it finishes"
            .to_string(),
        BulkQueueError::Closed => {
            "its bulk stream is gone (the connection is tearing down)".to_string()
        }
    })
}

/// Shows a best-effort desktop notification about an input switch, so that an
/// accidental switch (e.g. a switch shortcut colliding with a compositor bind)
/// is visible at a glance instead of looking like dead keys.
fn notify_switch(body: &str) {
    crate::notify::notify("monux-switch", crate::notify::Urgency::Low, 2000, "monux", body);
}

/// Notifies that a client (re-)entered the rotation. Called from add_client,
/// which also covers reconnects (incl. session resumes).
fn notify_client_joined(endpoint: &SocketAddr) {
    crate::notify::notify(
        "monux-client",
        crate::notify::Urgency::Low,
        3000,
        "monux client connected",
        &format!("{} joined the rotation", endpoint.ip()),
    );
}

/// Notifies that a client left the rotation because its connection errored.
/// monux has no client goodbye message, so every removal stems from a
/// connection failure; a clean server shutdown removes nothing and stays silent.
fn notify_client_dropped(endpoint: &SocketAddr) {
    crate::notify::notify(
        "monux-client",
        crate::notify::Urgency::Normal,
        5000,
        "monux client lost",
        &format!("Connection to {} was lost; it left the rotation", endpoint.ip()),
    );
}

/// Path of the file recording the active client's fingerprint (see
/// ACTIVE_CLIENT_STATE_FILE).
pub(crate) fn active_client_state_path(config_dir: &Path) -> PathBuf {
    config_dir.join(ACTIVE_CLIENT_STATE_FILE)
}

/// Reads the fingerprint of the client that was active when the previous
/// server instance exited unexpectedly. Returns None when there is nothing to
/// resume: no state file, a stale one, or an empty one (stale and empty files
/// are removed as junk). A fresh file is LEFT IN PLACE: the resume may span
/// several restarts before the client manages to reconnect (e.g. chained
/// auto-update restarts), and consuming it at load would lose the state after
/// the first one. It is rewritten on the next switch to a client and removed
/// on switch back to the local machine.
fn load_pending_resume(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    let stale = match metadata.modified().ok().and_then(|m| m.elapsed().ok()) {
        Some(age) => age > ACTIVE_CLIENT_MAX_AGE,
        // Unreadable mtime or an mtime in the future (clock skew): treat as
        // fresh, resuming is the safer direction for crash recovery.
        None => false,
    };
    if stale {
        debug!("Ignoring stale active-client state file: {}", path.display());
        let _ = fs::remove_file(path);
        return None;
    }
    let fingerprint = fs::read_to_string(path).ok()?.trim().to_string();
    if fingerprint.is_empty() {
        let _ = fs::remove_file(path);
        None
    } else {
        Some(fingerprint)
    }
}

/// Removes the active-client state file, if present. Called on switches back
/// to the local machine. The file deliberately survives shutdown (graceful or
/// not): the next server instance uses it to resume the session.
pub(crate) fn clear_active_client(path: &Path) {
    if let Err(e) = fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!("Failed to clear active client state: {:?}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::tests::no_ips;
    use bytes::Bytes;
    use std::net::IpAddr;
    use std::sync::atomic::AtomicBool;

    /// A ClientLink standing in for a real QUIC connection.
    ///
    /// This is the point of the ClientLink trait: with it, a ClientInfo can be
    /// built in a test, so the rotation's behaviour can be exercised through
    /// its real entry points instead of through free functions lifted out to
    /// dodge the quinn handles.
    #[derive(Default)]
    struct FakeLink {
        /// Frames written to the events stream, in order.
        events: Arc<Mutex<Vec<Vec<u8>>>>,
        /// Frames accepted onto the bulk queue, in order.
        bulk: Arc<Mutex<Vec<Vec<u8>>>>,
        /// Datagrams accepted, in order.
        datagrams: Arc<Mutex<Vec<Bytes>>>,
        /// How many more bulk frames the queue will take before reporting Full.
        bulk_capacity: Arc<AtomicU64>,
        /// When set, every events write fails (a dead connection).
        events_fail: Arc<AtomicBool>,
        /// Path stats this link reports.
        stats: Arc<Mutex<LinkStats>>,
    }

    impl FakeLink {
        fn new() -> Self {
            let link = FakeLink::default();
            link.bulk_capacity
                .store(bulk::BULK_QUEUE_CAPACITY as u64, Ordering::SeqCst);
            link
        }

        /// A handle sharing this link's recording buffers, so a test can read
        /// what was sent after the link has moved into the rotation.
        fn probe(&self) -> FakeLink {
            FakeLink {
                events: Arc::clone(&self.events),
                bulk: Arc::clone(&self.bulk),
                datagrams: Arc::clone(&self.datagrams),
                bulk_capacity: Arc::clone(&self.bulk_capacity),
                events_fail: Arc::clone(&self.events_fail),
                stats: Arc::clone(&self.stats),
            }
        }

        fn events_sent(&self) -> Vec<Vec<u8>> {
            crate::lock(&self.events).clone()
        }

        fn bulk_sent(&self) -> Vec<Vec<u8>> {
            crate::lock(&self.bulk).clone()
        }

        /// Decodes the events frames as ServerEvents, for asserting on what
        /// the client would actually see.
        fn events_as_strings(&self) -> Vec<String> {
            self.events_sent()
                .into_iter()
                .map(|mut bytes| {
                    match postcard::take_from_bytes_cobs::<event::ServerEvent>(&mut bytes) {
                        Ok((msg, _)) => msg.to_string(),
                        Err(e) => format!("<undecodable: {:?}>", e),
                    }
                })
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl ClientLink for FakeLink {
        async fn send_events(&mut self, bytes: &[u8]) -> Result<()> {
            if self.events_fail.load(Ordering::SeqCst) {
                bail!("fake link: events stream is closed");
            }
            crate::lock(&self.events).push(bytes.to_vec());
            Ok(())
        }

        fn queue_bulk(&self, frame: Vec<u8>) -> std::result::Result<(), BulkQueueError> {
            if self.bulk_capacity.load(Ordering::SeqCst) == 0 {
                return Err(BulkQueueError::Full);
            }
            self.bulk_capacity.fetch_sub(1, Ordering::SeqCst);
            crate::lock(&self.bulk).push(frame);
            Ok(())
        }

        fn bulk_queue_free(&self) -> usize {
            self.bulk_capacity.load(Ordering::SeqCst) as usize
        }

        fn send_datagram(&self, bytes: Bytes) -> std::result::Result<(), SendDatagramError> {
            crate::lock(&self.datagrams).push(bytes);
            Ok(())
        }

        fn stats(&self) -> LinkStats {
            *crate::lock(&self.stats)
        }
    }

    /// A link whose bulk queue is permanently closed (the writer task died).
    struct ClosedBulkLink;

    #[async_trait::async_trait]
    impl ClientLink for ClosedBulkLink {
        async fn send_events(&mut self, _bytes: &[u8]) -> Result<()> {
            Ok(())
        }
        fn queue_bulk(&self, _frame: Vec<u8>) -> std::result::Result<(), BulkQueueError> {
            Err(BulkQueueError::Closed)
        }
        fn bulk_queue_free(&self) -> usize {
            0
        }
        fn send_datagram(&self, _bytes: Bytes) -> std::result::Result<(), SendDatagramError> {
            Ok(())
        }
        fn stats(&self) -> LinkStats {
            LinkStats::default()
        }
    }

    fn edge_client_entries(specs: &[(&str, &str)]) -> Vec<(SocketAddr, String)> {
        specs
            .iter()
            .map(|(addr, fp)| (addr.parse().unwrap(), fp.to_string()))
            .collect()
    }

    fn edge_map_of(specs: &[&str]) -> edge::EdgeMap {
        edge::parse_edge_map(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("monux-test-{}-{}", std::process::id(), name));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn i32_event(type_: u16, code: u16, value: i32) -> event::InputEvent {
        event::InputEvent {
            inputi32: Some(event::InputI32 { type_, code, value }),
            inputf64: None,
        }
    }

    #[test]
    fn pure_pointer_motion_detection() {
        let ev_rel = evdev::EventType::RELATIVE.0;
        let rel_x = evdev::RelativeAxisCode::REL_X.0;
        let rel_y = evdev::RelativeAxisCode::REL_Y.0;

        // Pure X/Y motion in one or several events: datagram-worthy.
        assert!(is_pure_pointer_motion(&[i32_event(ev_rel, rel_x, 3)]));
        assert!(is_pure_pointer_motion(&[
            i32_event(ev_rel, rel_x, 3),
            i32_event(ev_rel, rel_y, -2)
        ]));

        // Empty batches are not sent as datagrams.
        assert!(!is_pure_pointer_motion(&[]));

        // Wheel, buttons, keys, and absolute axes must stay on the ordered stream.
        let rel_wheel = evdev::RelativeAxisCode::REL_WHEEL.0;
        assert!(!is_pure_pointer_motion(&[i32_event(ev_rel, rel_wheel, 1)]));
        assert!(!is_pure_pointer_motion(&[
            i32_event(ev_rel, rel_x, 3),
            i32_event(evdev::EventType::KEY.0, 0x110, 1) // BTN_LEFT press
        ]));
        assert!(!is_pure_pointer_motion(&[event::InputEvent {
            inputi32: None,
            inputf64: Some(event::InputF64 {
                type_: evdev::EventType::ABSOLUTE.0,
                code: evdev::AbsoluteAxisCode::ABS_X.0,
                value: 0.5,
            }),
        }]));
    }

    #[test]
    fn pending_resume_roundtrip() {
        let dir = temp_dir("roundtrip");
        let path = active_client_state_path(&dir);
        fs::write(&path, "deadbeef").unwrap();
        assert_eq!(load_pending_resume(&path), Some("deadbeef".to_string()));
        // A fresh file survives the load: the resume may span several
        // restarts before the client manages to reconnect.
        assert!(path.exists());
        assert_eq!(load_pending_resume(&path), Some("deadbeef".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_resume_missing_or_empty() {
        let dir = temp_dir("empty");
        let path = active_client_state_path(&dir);
        assert_eq!(load_pending_resume(&path), None);
        fs::write(&path, "  \n").unwrap();
        assert_eq!(load_pending_resume(&path), None);
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_resume_stale_is_ignored() {
        let dir = temp_dir("stale");
        let path = active_client_state_path(&dir);
        fs::write(&path, "deadbeef").unwrap();
        let stale_mtime =
            std::time::SystemTime::now() - ACTIVE_CLIENT_MAX_AGE - Duration::from_secs(60);
        let file = fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(stale_mtime).unwrap();
        drop(file);
        assert_eq!(load_pending_resume(&path), None);
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_active_client_is_idempotent() {
        let dir = temp_dir("clear");
        let path = active_client_state_path(&dir);
        // Missing file: no-op, no warning-worthy error.
        clear_active_client(&path);
        fs::write(&path, "deadbeef").unwrap();
        clear_active_client(&path);
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Stub output handler that just counts what it's asked to write.
    struct StubOutput {
        written: usize,
        released: usize,
    }

    #[async_trait::async_trait]
    impl device::output::OutputHandler for StubOutput {
        async fn release_all(&mut self) -> Result<()> {
            self.released += 1;
            Ok(())
        }
        async fn write(&mut self, events: Vec<event::InputEvent>) -> Result<()> {
            self.written += events.len();
            Ok(())
        }
        async fn write_classed(
            &mut self,
            _class: event::DeviceClass,
            events: Vec<event::InputEvent>,
        ) -> Result<()> {
            self.write(events).await
        }
    }

    #[tokio::test]
    async fn input_status_counts_flow_and_reset() {
        let dir = temp_dir("status");
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let mut rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();

        let batch = device::InputBatch {
            events: vec![
                i32_event(evdev::EventType::KEY.0, 28, 1),
                i32_event(evdev::EventType::KEY.0, 28, 0),
            ],
            is_grabbed: true,
            class: event::DeviceClass::Mouse,
        };
        rotation.send_input_events(batch).await.unwrap();
        assert_eq!(rotation.status_counts.physical, 2);
        assert_eq!(rotation.status_counts.physical_grabbed, 2);
        assert_eq!(rotation.status_counts.emitted_local, 2);
        assert_eq!(rotation.output_handler.written, 2);

        // Events from ungrabbed (passthrough) devices don't count toward the
        // swallow detector's grabbed tally (mouse movement is not a swallow).
        let batch = device::InputBatch {
            events: vec![i32_event(evdev::EventType::RELATIVE.0, 0, 5)],
            is_grabbed: false,
            class: event::DeviceClass::Mouse,
        };
        rotation.send_input_events(batch).await.unwrap();
        assert_eq!(rotation.status_counts.physical, 3);
        assert_eq!(rotation.status_counts.physical_grabbed, 2);

        // The status log resets the window for the next interval.
        rotation.log_input_status();
        assert_eq!(rotation.status_counts.physical, 0);
        assert_eq!(rotation.status_counts.physical_grabbed, 0);
        assert_eq!(rotation.status_counts.emitted_local, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn motion_coalescing_accumulates_and_clears() {
        let dir = temp_dir("coalesce");
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let mut rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(Some(Duration::from_millis(8))),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();

        // With a client "active" (no network attached), pure motion batches are
        // accumulated instead of forwarded. (Grabbed: ungrabbed batches are
        // dropped while a client is active — see
        // client_active_drops_ungrabbed_batches.)
        rotation.current_client = Some("127.0.0.1:1234".parse().unwrap());
        let rel = evdev::EventType::RELATIVE.0;
        let rel_x = evdev::RelativeAxisCode::REL_X.0;
        let rel_y = evdev::RelativeAxisCode::REL_Y.0;
        for (dx, dy) in [(3, -2), (1, 0), (-2, 5)] {
            rotation
                .send_input_events(device::InputBatch {
                    events: vec![i32_event(rel, rel_x, dx), i32_event(rel, rel_y, dy)],
                    is_grabbed: true,
                    class: event::DeviceClass::Mouse,
                })
                .await
                .unwrap();
        }
        assert_eq!(rotation.motion.pending(), (2, 3, 6));
        assert!(rotation.motion_dirty());
        // Nothing was forwarded yet; the physical side was counted.
        assert_eq!(rotation.status_counts.physical, 6);
        assert_eq!(rotation.status_counts.forwarded, 0);

        // Switching away clears the accumulator without sending.
        rotation.current_client = None;
        rotation.flush_pending_motion().await;
        assert!(!rotation.motion_dirty());
        assert_eq!(rotation.motion.pending(), (0, 0, 0));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn client_active_drops_ungrabbed_batches() {
        let dir = temp_dir("ungrabbed-drop");
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let mut rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();

        let endpoint: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        rotation.current_client = Some(endpoint);
        // An ungrabbed batch while a client is active (mouse grab failing,
        // e.g. a foreign process holding it, or the resume re-grab window)
        // already went to the local compositor: it must NOT also be
        // forwarded, or every event lands twice.
        rotation
            .send_input_events(device::InputBatch {
                events: vec![i32_event(evdev::EventType::RELATIVE.0, 0, 5)],
                is_grabbed: false,
                class: event::DeviceClass::Mouse,
            })
            .await
            .unwrap();
        assert_eq!(rotation.status_counts.physical, 1);
        assert_eq!(rotation.status_counts.physical_grabbed, 0);
        assert_eq!(rotation.status_counts.forwarded, 0);
        assert_eq!(rotation.output_handler.written, 0);
        // No forward attempt happened: a send to the fabricated endpoint
        // would fail and recover by switching back to local.
        assert_eq!(rotation.current_client, Some(endpoint));

        // A grabbed batch takes the forward path as before (with the
        // fabricated endpoint the send fails and falls back to local).
        rotation
            .send_input_events(device::InputBatch {
                events: vec![i32_event(evdev::EventType::RELATIVE.0, 0, 5)],
                is_grabbed: true,
                class: event::DeviceClass::Mouse,
            })
            .await
            .unwrap();
        assert_eq!(rotation.current_client, None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn switch_requests_are_debounced() {
        let dir = temp_dir("debounce");
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let mut rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();

        // The first switch request is processed; an immediate repeat (e.g. a
        // queued frustrated press after a stall) is dropped.
        assert!(!rotation.switch_debounced());
        assert!(rotation.switch_debounced());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_target_switches_bypass_the_debounce() {
        let dir = temp_dir("debounce-local-bypass");
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let mut rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();

        let endpoint: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        // Record a fresh switch: an immediate switch to a client is debounced...
        assert!(!rotation.switch_debounced());
        assert!(!rotation.switch_allowed(Some(endpoint)));
        // ...but a switch back to the local machine (the ungrab escape hatch)
        // always runs, and re-arms the debounce window for the next
        // client-target switch.
        assert!(rotation.switch_allowed(None));
        assert!(!rotation.switch_allowed(Some(endpoint)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn edge_info_auto_resolves_to_the_single_client() {
        // --edge-map right=auto with exactly one client: it gets Right.
        let clients = edge_client_entries(&[("10.0.0.1:9000", "aaaa1111")]);
        let map = edge_map_of(&["right=auto"]);
        assert_eq!(
            edge_info_directions(&map, &clients, "aaaa1111", &no_ips),
            vec![event::Direction::Right]
        );
        // A different fingerprint (not connected) gets nothing.
        assert!(edge_info_directions(&map, &clients, "bbbb2222", &no_ips).is_empty());
    }

    #[test]
    fn edge_info_only_mapped_clients() {
        // Two clients, a prefix target: only the mapped client is told.
        let clients = edge_client_entries(&[
            ("10.0.0.1:9000", "aaaa1111"),
            ("10.0.0.2:9000", "bbbb2222"),
        ]);
        let map = edge_map_of(&["right=bbbb"]);
        assert_eq!(
            edge_info_directions(&map, &clients, "bbbb2222", &no_ips),
            vec![event::Direction::Right]
        );
        assert!(edge_info_directions(&map, &clients, "aaaa1111", &no_ips).is_empty());
        // 'auto' with two clients connected is ambiguous: no EdgeInfo at all.
        let map = edge_map_of(&["right=auto"]);
        assert!(edge_info_directions(&map, &clients, "aaaa1111", &no_ips).is_empty());
        assert!(edge_info_directions(&map, &clients, "bbbb2222", &no_ips).is_empty());
    }

    #[test]
    fn edge_info_hostname_and_multiple_directions() {
        // A hostname target resolves by IP, and one client can sit beyond
        // several edges (BTreeMap order: Left < Right < Top < Bottom).
        let clients = edge_client_entries(&[
            ("10.0.0.1:9000", "aaaa1111"),
            ("10.0.0.2:9000", "bbbb2222"),
        ]);
        let resolver = |name: &str| -> Vec<IpAddr> {
            match name {
                "laptop" => vec!["10.0.0.2".parse().unwrap()],
                _ => vec![],
            }
        };
        let map = edge_map_of(&["top=laptop,bottom=bbbb,right=auto"]);
        assert_eq!(
            edge_info_directions(&map, &clients, "bbbb2222", &resolver),
            vec![event::Direction::Top, event::Direction::Bottom]
        );
        // The other client matches nothing ('auto' is ambiguous with two).
        assert!(edge_info_directions(&map, &clients, "aaaa1111", &resolver).is_empty());
    }

    #[test]
    fn edge_info_treats_qualifiers_as_their_direction() {
        // A monitor-qualified entry advertises its plain direction: the wire
        // carries no geometry, the qualifier only pins the local zone.
        let clients = edge_client_entries(&[("10.0.0.1:9000", "aaaa1111")]);
        let map = edge_map_of(&["right@eDP-1=auto"]);
        assert_eq!(
            edge_info_directions(&map, &clients, "aaaa1111", &no_ips),
            vec![event::Direction::Right]
        );
        // A qualified and an unqualified entry for one direction resolving
        // to the same client still advertise the direction once.
        let map = edge_map_of(&["right@eDP-1=auto,right=auto"]);
        assert_eq!(
            edge_info_directions(&map, &clients, "aaaa1111", &no_ips),
            vec![event::Direction::Right]
        );
    }

    #[test]
    fn edge_dirs_cache_reads_never_resolve() {
        // Reads serve the cached resolution verbatim: the resolver is not
        // consulted again (the point of the cache — a read per control
        // snapshot must not hit DNS).
        let clients = edge_client_entries(&[
            ("10.0.0.1:9000", "aaaa1111"),
            ("10.0.0.2:9000", "bbbb2222"),
        ]);
        let map = edge_map_of(&["top=laptop,bottom=bbbb"]);
        let resolves = std::cell::Cell::new(0u32);
        let resolver = |name: &str| -> Vec<IpAddr> {
            resolves.set(resolves.get() + 1);
            match name {
                "laptop" => vec!["10.0.0.2".parse().unwrap()],
                _ => vec![],
            }
        };
        let mut cache = EdgeDirectionsCache::default();
        cache.refresh(Some(&map), &clients, &resolver);
        let after_refresh = resolves.get();
        assert!(after_refresh > 0);
        assert_eq!(cache.edge_string(&clients[0].0), None);
        assert_eq!(
            cache.edge_string(&clients[1].0),
            Some("top+bottom".to_string())
        );
        // An endpoint unknown to the cache gets nothing either.
        assert_eq!(
            cache.edge_string(&"10.0.0.9:9000".parse().unwrap()),
            None
        );
        assert_eq!(resolves.get(), after_refresh);
    }

    #[test]
    fn edge_dirs_cache_tracks_list_and_map_changes() {
        let clients = edge_client_entries(&[("10.0.0.1:9000", "aaaa1111")]);
        let mut cache = EdgeDirectionsCache::default();
        // No edge map: the cache just empties.
        cache.refresh(None, &clients, &no_ips);
        assert_eq!(cache.edge_string(&clients[0].0), None);
        // Map set: 'auto' resolves to the single client.
        let map = edge_map_of(&["right=auto"]);
        cache.refresh(Some(&map), &clients, &no_ips);
        assert_eq!(cache.edge_string(&clients[0].0), Some("right".to_string()));
        // A second client connects: 'auto' is ambiguous for everyone.
        let clients = edge_client_entries(&[
            ("10.0.0.1:9000", "aaaa1111"),
            ("10.0.0.2:9000", "bbbb2222"),
        ]);
        cache.refresh(Some(&map), &clients, &no_ips);
        assert_eq!(cache.edge_string(&clients[0].0), None);
        assert_eq!(cache.edge_string(&clients[1].0), None);
        // The second client leaves again: 'auto' resolves once more.
        let clients = edge_client_entries(&[("10.0.0.1:9000", "aaaa1111")]);
        cache.refresh(Some(&map), &clients, &no_ips);
        assert_eq!(cache.edge_string(&clients[0].0), Some("right".to_string()));
    }

    /// The budget must be invisible to normal use — a paste costs one fetch
    /// per mime type — while bounding a client that reads the clipboard on a
    /// loop. See CLIPBOARD_FETCH_BURST for why refusing inactive clients
    /// outright is not the answer.
    #[test]
    fn clipboard_fetch_budget_allows_pastes_and_bounds_polling() {
        let now = Instant::now();
        let mut budget = FetchBudget::new(now);
        // A realistic paste: a handful of types, all served.
        for i in 0..CLIPBOARD_FETCH_BURST {
            let (allowed, reported) = budget.charge(now);
            assert!(allowed, "fetch {} of the burst must be served", i);
            assert!(!reported);
        }
        // Past the burst, refused — and reported exactly once, so a client
        // hammering the socket costs one log line rather than thousands.
        let (allowed, first_refusal) = budget.charge(now);
        assert!(!allowed);
        assert!(first_refusal);
        let (allowed, first_refusal) = budget.charge(now);
        assert!(!allowed);
        assert!(!first_refusal, "the refusal must only be reported once");

        // The window rolls over and the client is served again: this throttles
        // exfiltration, it does not permanently cut a machine off.
        let (allowed, _) = budget.charge(now + CLIPBOARD_FETCH_WINDOW);
        assert!(allowed);
    }

    #[tokio::test]
    async fn noop_switch_releases_current_target_keys() {
        let dir = temp_dir("noop-release");
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let mut rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();

        // With no clients connected, every next/prev lands on the current
        // target (local): a no-op switch. The chord still fired, so the held
        // modifiers it forwarded must be released on the current target.
        rotation.next_client().await;
        assert_eq!(rotation.output_handler.released, 1);
        rotation.prev_client().await;
        assert_eq!(rotation.output_handler.released, 2);
        // Same for goto switches that don't switch: unmatched fingerprint,
        // and goto-local while already local.
        rotation.set_client("deadbeef".to_string()).await;
        assert_eq!(rotation.output_handler.released, 3);
        rotation.set_client("".to_string()).await;
        assert_eq!(rotation.output_handler.released, 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn debounced_switch_still_releases_current_target_keys() {
        let dir = temp_dir("debounce-release");
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let mut rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();

        // A switch to a client within SWITCH_DEBOUNCE of the last switch is
        // dropped by the debounce (a ClientInfo can't be fabricated in a unit
        // test, so this drives the same two calls next_client makes for a
        // dropped client-target switch)...
        rotation.last_switch_at = Some(Instant::now());
        let endpoint: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert!(!rotation.switch_allowed(Some(endpoint)));
        rotation.release_current_target_keys().await;
        // ...but the current target (here the local machine) must still get
        // the same held-key cleanup a real switch runs on the old target: the
        // chord's modifier presses were forwarded to it, and ComboState
        // consumes their releases once the chord fires.
        assert_eq!(rotation.output_handler.released, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn empty_local_types_update_clears_clipboard_target() {
        let dir = temp_dir("clipclear");
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let mut rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();

        let types = vec!["text/plain".to_string()];
        rotation
            .clipboard_update_source(None, types.clone(), 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.target().is_some());

        // The compositor revoked the selection (owner exited, nothing
        // persisted it): the tracked target must be cleared immediately...
        rotation
            .clipboard_update_source(None, vec![], 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.target().is_none());

        // ...and the debounce timestamp is reset, so a clipboard manager
        // re-owning the content right after is processed, not debounced away.
        rotation
            .clipboard_update_source(None, types, 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.target().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Builds a rotation for clipboard tests (no local clipboard, no clients;
    /// a ClientInfo can't be fabricated without a QUIC connection).
    async fn clipboard_rotation(name: &str) -> (PathBuf, Rotation<StubOutput>) {
        let dir = temp_dir(name);
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();
        (dir, rotation)
    }

    /// Builds a rotation with adaptive motion/throttle for link-tier tests.
    async fn adaptive_rotation(name: &str) -> (PathBuf, Rotation<StubOutput>) {
        let dir = temp_dir(name);
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Adaptive,
            throttle_mode: ThrottleMode::Adaptive,
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();
        (dir, rotation)
    }

    #[test]
    fn adaptive_throttle_rates_by_tier() {
        assert_eq!(
            effective_throttle_mbps(&ThrottleMode::Adaptive, Tier::Normal),
            Some(ADAPTIVE_THROTTLE_NORMAL_MBPS)
        );
        assert_eq!(
            effective_throttle_mbps(&ThrottleMode::Adaptive, Tier::Proximity),
            Some(ADAPTIVE_THROTTLE_PROXIMITY_MBPS)
        );
        // Pinned modes ignore the tier entirely.
        assert_eq!(
            effective_throttle_mbps(&ThrottleMode::Pinned(Some(12.0)), Tier::Proximity),
            Some(12.0)
        );
        assert_eq!(
            effective_throttle_mbps(&ThrottleMode::Pinned(None), Tier::Proximity),
            None
        );
    }

    #[tokio::test]
    async fn adaptive_motion_interval_tracks_the_current_client_tier() {
        let (dir, mut rotation) = adaptive_rotation("adaptive-motion").await;
        // Local (no current client): the Normal rate.
        let normal = 1.0 / ADAPTIVE_MOTION_NORMAL_HZ as f64;
        assert_eq!(
            rotation.motion_flush_interval(),
            Some(Duration::from_secs_f64(normal))
        );
        // Register a client link-state and make it the current client: the
        // interval follows its measured tier.
        let endpoint: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let cell = throttle::shared_throttle(Some(ADAPTIVE_THROTTLE_NORMAL_MBPS));
        rotation.link_quality.insert(
            endpoint,
            ClientLinkState {
                quality: LinkQuality::new(),
                last_sent: 0,
                last_lost: 0,
                throttle: cell.clone(),
                degraded: false,
            },
        );
        rotation.current_client = Some(endpoint);
        assert_eq!(
            rotation.motion_flush_interval(),
            Some(Duration::from_secs_f64(normal))
        );
        // Three consecutive good samples promote the link; the interval drops
        // to the Proximity rate and the bulk cell is rewritten.
        let good_rtt = crate::network::link_quality::GOOD_RTT;
        for _ in 0..crate::network::link_quality::PROMOTE_SAMPLES {
            rotation
                .link_quality
                .get_mut(&endpoint)
                .unwrap()
                .quality
                .sample(good_rtt, 0.0);
        }
        assert_eq!(
            rotation.motion_flush_interval(),
            Some(Duration::from_secs_f64(
                1.0 / ADAPTIVE_MOTION_PROXIMITY_HZ as f64
            ))
        );
        // A bad sample demotes immediately.
        rotation
            .link_quality
            .get_mut(&endpoint)
            .unwrap()
            .quality
            .sample(crate::network::link_quality::BAD_RTT + Duration::from_millis(1), 0.0);
        assert_eq!(
            rotation.motion_flush_interval(),
            Some(Duration::from_secs_f64(normal))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pinned_motion_ignores_the_tier() {
        let (dir, rotation) = clipboard_rotation("pinned-motion").await;
        // Pinned(None) = --motion-hz 0: every event, never an interval.
        assert_eq!(rotation.motion_flush_interval(), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sample_link_quality_without_clients_is_quiet() {
        let (dir, mut rotation) = adaptive_rotation("adaptive-sample-empty").await;
        assert!(!rotation.sample_link_quality());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn clipboard_debounce_is_per_source() {
        let (dir, mut rotation) = clipboard_rotation("clip-per-source").await;
        let client_a: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let client_b: SocketAddr = "127.0.0.1:1235".parse().unwrap();

        // A local update starts the LOCAL debounce window...
        rotation
            .clipboard_update_source(None, vec!["text/plain".to_string()], 1024)
            .await
            .unwrap();
        // ...but a client update right after is a different source and must be
        // processed (a global debounce would drop this deactivate-announcement).
        rotation
            .clipboard_update_source(Some(client_a), vec!["image/png".to_string()], 1024)
            .await
            .unwrap();
        assert_eq!(
            rotation.clipboard.target().unwrap().source,
            Some(client_a)
        );
        // A second client's update isn't debounced by the first client's either.
        rotation
            .clipboard_update_source(Some(client_b), vec!["text/html".to_string()], 1024)
            .await
            .unwrap();
        assert_eq!(
            rotation.clipboard.target().unwrap().source,
            Some(client_b)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_clipboard_debounce_collapses_to_newest_on_trailing_edge() {
        let (dir, mut rotation) = clipboard_rotation("clip-trailing").await;

        rotation
            .clipboard_update_source(None, vec!["one".to_string()], 1024)
            .await
            .unwrap();
        // Two rapid local updates inside the window (e.g. a fast double
        // Ctrl+C): neither applies immediately, and only the newest is held.
        rotation
            .clipboard_update_source(None, vec!["two".to_string()], 1024)
            .await
            .unwrap();
        rotation
            .clipboard_update_source(None, vec!["three".to_string()], 1024)
            .await
            .unwrap();
        assert_eq!(
            rotation.clipboard.target().unwrap().types,
            vec!["one".to_string()]
        );
        assert!(rotation.clipboard.pending_local_deadline().is_some());

        // The window expires (the server events loop calls this from its
        // timer): the newest held state is applied, never lost.
        rotation.flush_pending_local_clipboard().await;
        assert_eq!(
            rotation.clipboard.target().unwrap().types,
            vec!["three".to_string()]
        );
        assert!(rotation.clipboard.pending_local_deadline().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn remote_clipboard_debounce_is_leading_edge_without_trailing_state() {
        let (dir, mut rotation) = clipboard_rotation("clip-remote-leading").await;
        let client: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        rotation
            .clipboard_update_source(Some(client), vec!["one".to_string()], 1024)
            .await
            .unwrap();
        // A same-client update inside the window is dropped outright: remote
        // announcements are switch-driven one-shots, no final state is lost.
        rotation
            .clipboard_update_source(Some(client), vec!["two".to_string()], 1024)
            .await
            .unwrap();
        assert_eq!(
            rotation.clipboard.target().unwrap().types,
            vec!["one".to_string()]
        );
        // Remote sources never arm the local trailing-edge timer.
        assert!(rotation.clipboard.pending_local_deadline().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_revocation_supersedes_held_update() {
        let (dir, mut rotation) = clipboard_rotation("clip-held-revoked").await;

        rotation
            .clipboard_update_source(None, vec!["one".to_string()], 1024)
            .await
            .unwrap();
        rotation
            .clipboard_update_source(None, vec!["two".to_string()], 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.pending_local_deadline().is_some());
        // The compositor revokes the selection before the window expires: the
        // held (older) state must not resurrect it on the trailing edge.
        rotation
            .clipboard_update_source(None, vec![], 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.target().is_none());
        rotation.flush_pending_local_clipboard().await;
        assert!(rotation.clipboard.target().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn empty_remote_types_clear_clipboard_target() {
        let (dir, mut rotation) = clipboard_rotation("clip-remote-clear").await;
        let client: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        rotation
            .clipboard_update_source(Some(client), vec!["text/plain".to_string()], 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.target().is_some());

        // The owning app exited on the client: its watcher delivered empty
        // types and the client announced the clear. The rotation target must
        // not stay stale, same as a local revocation.
        rotation
            .clipboard_update_source(Some(client), vec![], 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.target().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Everyone announces their own selection going away, owner or not. Only
    /// the owner's revocation may clear the shared clipboard — otherwise an
    /// unrelated app quitting on one machine destroys the content every other
    /// machine is still pasting from.
    #[tokio::test]
    async fn an_empty_update_from_a_non_owner_leaves_the_clipboard_alone() {
        let (dir, mut rotation) = clipboard_rotation("clip-nonowner-clear").await;
        let owner: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        rotation
            .clipboard_update_source(Some(owner), vec!["text/plain".to_string()], 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.target().is_some());

        // The server's own watcher revoking a third-party app's offer, while
        // the client still owns the shared clipboard.
        rotation
            .clipboard_update_source(None, vec![], 1024)
            .await
            .unwrap();
        assert_eq!(
            rotation.clipboard.target().map(|t| t.source),
            Some(Some(owner)),
            "a non-owner's revocation must not clear the owner's clipboard"
        );

        // A different client deactivating with nothing shareable: also not the
        // owner, also not a clear.
        let bystander: SocketAddr = "127.0.0.1:5678".parse().unwrap();
        rotation
            .clipboard_update_source(Some(bystander), vec![], 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.target().is_some());

        // The owner's own revocation still clears, as before.
        rotation
            .clipboard_update_source(Some(owner), vec![], 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.target().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn clipboard_clear_drops_pending_fetches() {
        let (dir, mut rotation) = clipboard_rotation("clip-clear-pending").await;

        // A server-originated fetch still waiting on its reply (e.g. the
        // owner disconnected mid-fetch) must error immediately on clear, not
        // wait out the 5s fetch timeout.
        let (tx, rx) = oneshot::channel::<data::ClipboardData>();
        rotation.clipboard.track_request(
            "10.0.0.1:1".parse().unwrap(),
            clipboard::PendingFetch::Local(tx),
        );
        rotation.clipboard_clear().await;
        assert!(rx.await.is_err());
        assert_eq!(rotation.clipboard.pending_request_count(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_paste_fetch_gets_empty_answer_not_dropped_channel() {
        let (dir, mut rotation) = clipboard_rotation("clip-local-fail-fast").await;

        // No clipboard at all: an unservable local paste must be answered
        // empty, not dropped — a dropped oneshot surfaces as 'channel closed'
        // on the fetching side and the paste stalls for the fetch timeout.
        let (tx, rx) = oneshot::channel::<data::ClipboardData>();
        let result = rotation
            .clipboard_request_content(ClipboardRequestSource::Local(tx), "text/plain", 1024, None)
            .await;
        assert!(result.is_err());
        let answered = rx.await.expect("the fetch must be answered, not dropped");
        assert!(answered.bytes.is_empty());

        // The server is tracked as owning the clipboard, yet a local paste
        // fetch arrived (a stale monux advertisement was still up): the same
        // fail-fast answer, instead of the 'against itself' drop.
        rotation
            .clipboard_update_source(None, vec!["text/plain".to_string()], 1024)
            .await
            .unwrap();
        let (tx, rx) = oneshot::channel::<data::ClipboardData>();
        let result = rotation
            .clipboard_request_content(ClipboardRequestSource::Local(tx), "text/plain", 1024, None)
            .await;
        assert!(result.is_err());
        let answered = rx.await.expect("the fetch must be answered, not dropped");
        assert!(answered.bytes.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn switch_flushes_held_local_clipboard_update() {
        let (dir, mut rotation) = clipboard_rotation("clip-switch-flush").await;

        rotation
            .clipboard_update_source(None, vec!["one".to_string()], 1024)
            .await
            .unwrap();
        // A second local copy inside the debounce window is held for the
        // trailing edge.
        rotation
            .clipboard_update_source(None, vec!["two".to_string()], 1024)
            .await
            .unwrap();
        assert!(rotation.clipboard.pending_local_deadline().is_some());
        // A switch settles the held state immediately: otherwise switching
        // away and back inside the window reconciles (and re-advertises) the
        // stale pre-copy target over the new local clipboard.
        rotation.update_current_client(None).await;
        assert!(rotation.clipboard.pending_local_deadline().is_none());
        assert_eq!(
            rotation.clipboard.target().unwrap().types,
            vec!["two".to_string()]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A bug report must never be the thing that severs the connection it is
    /// about. The clipboard paths drop a client whose bulk queue won't take a
    /// frame (both sides would otherwise disagree about the clipboard owner);
    /// the diagnostics path must instead record the refusal as that peer's
    /// entry and leave the client connected. The queue is small
    /// (BULK_QUEUE_CAPACITY) and the writer sleeps between frames while
    /// pacing a large transfer, so "full" is an ordinary state mid-copy.
    #[test]
    fn a_busy_bulk_queue_does_not_cost_the_client_its_connection() {
        let link = FakeLink::new();
        let probe = link.probe();
        // A queue with room takes the frame.
        assert!(queue_diagnostics_frame(&link, vec![1, 2, 3]).is_ok());
        // Fill it: the writer is pacing a transfer and hasn't drained.
        for _ in 1..bulk::BULK_QUEUE_CAPACITY {
            queue_diagnostics_frame(&link, vec![0; 16]).expect("queue still has room");
        }
        let err = queue_diagnostics_frame(&link, vec![0; 16])
            .expect_err("a full queue must refuse the frame");
        assert!(
            err.contains("busy") && err.contains("clipboard"),
            "the report should name the cause: {}",
            err
        );
        // ...and the queue is intact: nothing was torn down, and the frames
        // already queued are still there for the writer to drain.
        assert_eq!(probe.bulk_sent()[0], vec![1, 2, 3]);

        // A closed queue (the writer task is gone) reads differently, so a
        // report can tell a busy peer from a departing one.
        let err = queue_diagnostics_frame(&ClosedBulkLink, vec![0; 16])
            .expect_err("a closed queue must refuse the frame");
        assert!(err.contains("gone"), "unexpected reason: {}", err);
    }


    /// Builds a Rotation wired to stubs, with no network anywhere. The grab
    /// receiver comes back with it: dropping the last one makes every
    /// broadcast_grab_state panic by design (a rotation with no device tasks
    /// listening would leave the machine's devices in an unknown grab state).
    async fn test_rotation(
        name: &str,
    ) -> (Rotation<StubOutput>, watch::Receiver<device::GrabState>, PathBuf) {
        let dir = temp_dir(name);
        let (grab_tx, grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        // Leaked so the rotation's self-handle stays usable for the whole
        // test without the receiver being dropped.
        let (rotation_tx, rotation_rx) = mpsc::channel(64);
        Box::leak(Box::new(rotation_rx));
        let rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();
        (rotation, grab_rx, dir)
    }

    fn addr(spec: &str) -> SocketAddr {
        spec.parse().unwrap()
    }

    /// Adds a client with a fake link, returning a probe onto what it receives.
    async fn add_fake_client(
        rotation: &mut Rotation<StubOutput>,
        endpoint: SocketAddr,
        fingerprint: &str,
    ) -> FakeLink {
        let link = FakeLink::new();
        let probe = link.probe();
        rotation
            .register_client(
                endpoint,
                fingerprint.to_string(),
                Box::new(link),
                endpoint.port() as u64,
                shared::PROTOCOL_VERSION,
            )
            .await;
        probe
    }

    /// A switch must activate exactly one client and deactivate the other, in
    /// that order — the ordering the clipboard handoff depends on.
    ///
    /// Previously untestable: it needs two live ClientInfos, which meant two
    /// QUIC connections.
    #[tokio::test]
    async fn switching_activates_the_new_client_and_deactivates_the_old() {
        let (mut rotation, _grab_rx, dir) = test_rotation("switch-pair").await;
        let a = addr("10.0.0.1:1001");
        let b = addr("10.0.0.2:1002");
        let probe_a = add_fake_client(&mut rotation, a, "aaaa1111").await;
        let probe_b = add_fake_client(&mut rotation, b, "bbbb2222").await;

        rotation.update_current_client(Some(a)).await;
        assert_eq!(rotation.current_client, Some(a));
        assert_eq!(probe_a.events_as_strings(), vec!["SwitchEvent(enabled=true)"]);
        assert!(probe_b.events_as_strings().is_empty(), "B must hear nothing yet");

        rotation.update_current_client(Some(b)).await;
        assert_eq!(rotation.current_client, Some(b));
        // A is told it is inactive; B is told it is active.
        assert_eq!(
            probe_a.events_as_strings(),
            vec!["SwitchEvent(enabled=true)", "SwitchEvent(enabled=false)"]
        );
        assert_eq!(probe_b.events_as_strings(), vec!["SwitchEvent(enabled=true)"]);

        // ...and the grab state follows: a client owns the input.
        assert!(rotation.grab_tx.borrow().client_active);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The silence detector's whole job: a current client that stops
    /// answering must lose the input and get a Switch(false), so its virtual
    /// devices release the keys it is holding — without being removed from
    /// the rotation.
    #[tokio::test]
    async fn a_silent_client_loses_input_and_is_told_so() {
        let (mut rotation, _grab_rx, dir) = test_rotation("silence").await;
        let a = addr("10.0.0.1:1001");
        let probe = add_fake_client(&mut rotation, a, "aaaa1111").await;
        rotation.update_current_client(Some(a)).await;
        assert!(rotation.grab_tx.borrow().client_active);

        // Backdate the last-heard past the miss limit and run the detector.
        let silent_for = PING_INTERVAL * (PONG_MISS_LIMIT + 1);
        rotation.liveness.backdate_for_test(&a, silent_for);
        // A first tick establishes the baseline, so the stall guard doesn't
        // treat the next one as a late catch-up tick.
        rotation.liveness.begin_tick(Instant::now());
        rotation.ping_tick().await;

        assert_eq!(rotation.current_client, None, "input must return to local");
        assert_eq!(rotation.liveness.silenced_endpoint(), Some(a), "auto-reactivation armed");
        assert!(!rotation.grab_tx.borrow().client_active, "devices must ungrab");
        // The client stays connected and is still pinged.
        assert_eq!(rotation.roster.len(), 1);
        let seen = probe.events_as_strings();
        assert!(seen.contains(&"SwitchEvent(enabled=false)".to_string()), "{:?}", seen);
        assert!(seen.contains(&"Ping".to_string()), "{:?}", seen);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A recovered client is re-activated only when the local target came
    /// FROM its silence. If the user picked local deliberately in between,
    /// their choice wins — the case the silenced_endpoint flag exists for.
    #[tokio::test]
    async fn a_manual_choice_outranks_automatic_reactivation() {
        let (mut rotation, _grab_rx, dir) = test_rotation("recovery").await;
        let a = addr("10.0.0.1:1001");
        add_fake_client(&mut rotation, a, "aaaa1111").await;
        rotation.update_current_client(Some(a)).await;

        // Silence it.
        rotation
            .liveness
            .backdate_for_test(&a, PING_INTERVAL * (PONG_MISS_LIMIT + 1));
        rotation.liveness.begin_tick(Instant::now());
        rotation.ping_tick().await;
        assert_eq!(rotation.liveness.silenced_endpoint(), Some(a));

        // The user deliberately chooses the local machine meanwhile.
        rotation.set_client(String::new()).await;
        assert_eq!(rotation.liveness.silenced_endpoint(), None, "a manual choice disarms it");

        // Now the client recovers: enough messages, cooldown served.
        rotation
            .liveness
            .silence_for_test(a, Instant::now() - REACTIVATE_COOLDOWN * 2);
        for _ in 0..REACTIVATE_PONGS {
            rotation.note_client_heard(a).await;
        }
        assert_eq!(
            rotation.current_client, None,
            "input must stay where the user put it"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A client whose events stream is dead must be removed from the rotation
    /// on the failed write, and the input must fall back to local rather than
    /// staying grabbed for a client that is gone.
    #[tokio::test]
    async fn a_dead_events_stream_removes_the_client_and_ungrabs() {
        let (mut rotation, _grab_rx, dir) = test_rotation("dead-stream").await;
        let a = addr("10.0.0.1:1001");
        let probe = add_fake_client(&mut rotation, a, "aaaa1111").await;
        rotation.update_current_client(Some(a)).await;
        assert!(rotation.grab_tx.borrow().client_active);

        // The connection dies; the next send fails.
        probe.events_fail.store(true, Ordering::SeqCst);
        let _ = rotation
            .send_event(&a, event::ServerEvent::Ping)
            .await;

        assert!(rotation.roster.is_empty(), "the client must be removed");
        assert_eq!(rotation.current_client, None);
        assert!(!rotation.grab_tx.borrow().client_active, "devices must ungrab");
        // Its bookkeeping goes with it, rather than leaking an entry per drop.
        assert!(rotation.liveness.is_empty());
        assert!(rotation.link_quality.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A reconnect from the same address replaces the entry in place, and the
    /// stale connection's late removal must not kill the healthy new one.
    #[tokio::test]
    async fn a_reconnect_replaces_in_place_and_survives_the_stale_removal() {
        let (mut rotation, _grab_rx, dir) = test_rotation("reconnect").await;
        let a = addr("10.0.0.1:1001");
        add_fake_client(&mut rotation, a, "aaaa1111").await;
        let old_token = rotation.roster.conn_token(&a).unwrap();

        // The same endpoint comes back on a new connection.
        let fresh = FakeLink::new();
        let probe = fresh.probe();
        rotation
            .register_client(a, "aaaa1111".to_string(), Box::new(fresh), old_token + 1, shared::PROTOCOL_VERSION)
            .await;
        assert_eq!(rotation.roster.len(), 1, "replaced, not duplicated");
        assert_eq!(rotation.roster.conn_token(&a).unwrap(), old_token + 1);

        // The old connection's teardown lands late, carrying its stale token.
        rotation.remove_client_and_clear_clipboard(a, old_token).await;
        assert_eq!(rotation.roster.len(), 1, "the healthy entry must survive");

        // The real removal does take effect.
        rotation.remove_client_and_clear_clipboard(a, old_token + 1).await;
        assert!(rotation.roster.is_empty());
        assert!(probe.events_as_strings().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A bulk frame handed back by a spawned serve task must reach the client
    /// it was built for — and be dropped, not misdelivered, when that
    /// connection has since been replaced.
    #[tokio::test]
    async fn a_bulk_frame_follows_its_connection_token() {
        let (mut rotation, _grab_rx, dir) = test_rotation("bulk-token").await;
        let a = addr("10.0.0.1:1001");
        let probe = add_fake_client(&mut rotation, a, "aaaa1111").await;
        let token = rotation.roster.conn_token(&a).unwrap();

        rotation.send_bulk_frame(&a, vec![1, 2, 3], token).await;
        assert_eq!(probe.bulk_sent(), vec![vec![1, 2, 3]]);

        // A frame from the previous connection is dropped, not delivered.
        rotation.send_bulk_frame(&a, vec![9, 9, 9], token - 1).await;
        assert_eq!(probe.bulk_sent(), vec![vec![1, 2, 3]]);
        assert_eq!(rotation.roster.len(), 1, "and the client is untouched");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn types_equal_is_set_based() {
        let six = vec![
            "text/plain".to_string(),
            "text/plain".to_string(),
            "text/plain;charset=utf-8".to_string(),
            "TEXT".to_string(),
            "STRING".to_string(),
            "UTF8_STRING".to_string(),
        ];
        let five = vec![
            "text/plain".to_string(),
            "text/plain;charset=utf-8".to_string(),
            "TEXT".to_string(),
            "STRING".to_string(),
            "UTF8_STRING".to_string(),
        ];
        // Same set, despite the duplicate entry and different lengths
        assert!(types_equal(&six, &five));
        // Order-insensitive
        let mut reordered = five.clone();
        reordered.reverse();
        assert!(types_equal(&five, &reordered));
        // Genuinely different types
        let other = vec!["image/png".to_string()];
        assert!(!types_equal(&five, &other));
    }

    /// Builds a rotation for pause tests, returning the grab-state receiver so
    /// the broadcast reaching ALL device tasks can be asserted on.
    async fn pause_rotation(name: &str) -> (PathBuf, Rotation<StubOutput>, watch::Receiver<device::GrabState>) {
        let dir = temp_dir(name);
        let (grab_tx, grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();
        (dir, rotation, grab_rx)
    }

    #[test]
    fn class_grabbed_matrix() {
        use crate::device::input::class_grabbed;
        use crate::device::DeviceClass;
        // Unpaused: keyboards always grabbed, mice only while a client is active.
        assert!(class_grabbed(DeviceClass::Keyboard, &device::GrabState { client_active: false, paused: false }));
        assert!(!class_grabbed(DeviceClass::Toggled, &device::GrabState { client_active: false, paused: false }));
        assert!(class_grabbed(DeviceClass::Keyboard, &device::GrabState { client_active: true, paused: false }));
        assert!(class_grabbed(DeviceClass::Toggled, &device::GrabState { client_active: true, paused: false }));
        // Paused ungrabs EVERYTHING, keyboards included, regardless of the client.
        assert!(!class_grabbed(DeviceClass::Keyboard, &device::GrabState { client_active: false, paused: true }));
        assert!(!class_grabbed(DeviceClass::Toggled, &device::GrabState { client_active: false, paused: true }));
        assert!(!class_grabbed(DeviceClass::Keyboard, &device::GrabState { client_active: true, paused: true }));
        assert!(!class_grabbed(DeviceClass::Toggled, &device::GrabState { client_active: true, paused: true }));
    }

    #[tokio::test]
    async fn control_state_reflects_rotation() {
        let dir = temp_dir("control-state");
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let diagnostics = Arc::new(DiagnosticsMirror::new("127.0.0.1:9999".parse().unwrap()));
        let mut rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: diagnostics.clone(),
        })
        .await
        .unwrap();

        // The refresh feeds the structured snapshot the control socket serves.
        rotation.update_diagnostics();
        let state = diagnostics.server_state().expect("seeded by update_diagnostics");
        assert_eq!(state.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(state.protocol_version, crate::msgs::shared::PROTOCOL_VERSION);
        // The listen address comes from the mirror, not the loop.
        assert_eq!(state.listen, "127.0.0.1:9999");
        assert!(!state.paused);
        assert_eq!(state.current_target, "local");
        assert!(state.clients.is_empty());
        assert_eq!(state.clipboard.owner, "none");
        assert!(state.clipboard.types.is_empty());
        assert!(state.update_available.is_none());

        // Rotation changes flow through: local clipboard, pause.
        rotation
            .clipboard_update_source(None, vec!["text/plain".to_string()], 1024)
            .await
            .unwrap();
        rotation.toggle_pause("test").await;
        // Step outside the rate-limit window: this second refresh comes
        // microseconds after the first and would be skipped by design (see
        // diagnostics_refresh_is_rate_limited).
        rotation.last_diagnostics_refresh = None;
        rotation.update_diagnostics();
        let state = diagnostics.server_state().unwrap();
        assert!(state.paused);
        assert_eq!(state.clipboard.owner, "local");
        assert_eq!(state.clipboard.types, vec!["text/plain".to_string()]);

        // set_paused (control socket) is idempotent, unlike the chord's toggle.
        let released = rotation.output_handler.released;
        rotation.set_paused(true, "test").await;
        assert!(rotation.paused);
        assert_eq!(rotation.output_handler.released, released);
        rotation.set_paused(false, "test").await;
        assert!(!rotation.paused);

        // The wire JSON uses the documented, tray-stable field names (the
        // "role" key comes from the State enum's tag).
        let v = serde_json::to_value(crate::control::State::Server(
            diagnostics.server_state().unwrap(),
        ))
        .unwrap();
        assert_eq!(v["role"], "server");
        assert!(v.get("protocol_version").is_some());
        assert!(v.get("current_target").is_some());
        assert!(v.get("clients").is_some());
        assert_eq!(v["clipboard"]["owner"], "local");
        assert!(v.get("update_available").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn diagnostics_refresh_is_rate_limited() {
        let dir = temp_dir("diag-ratelimit");
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let diagnostics = Arc::new(DiagnosticsMirror::new("127.0.0.1:9999".parse().unwrap()));
        let mut rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode: NetworkMode::Local,
            diagnostics: diagnostics.clone(),
        })
        .await
        .unwrap();

        // The first call always refreshes (the server start seeds the mirror
        // this way, so a SIGHUP before the first event still dumps).
        rotation.update_diagnostics();
        assert!(!diagnostics.server_state().unwrap().paused);

        // A refresh inside the window is skipped, even though state changed.
        rotation.toggle_pause("test").await;
        rotation.update_diagnostics();
        assert!(!diagnostics.server_state().unwrap().paused);

        // Outside the window the refresh lands again.
        rotation.last_diagnostics_refresh =
            Some(Instant::now() - DIAGNOSTICS_REFRESH_INTERVAL - Duration::from_millis(1));
        rotation.update_diagnostics();
        assert!(diagnostics.server_state().unwrap().paused);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pause_toggle_drives_ungrab_and_regrab_on_both_device_classes() {
        use crate::device::input::class_grabbed;
        use crate::device::DeviceClass;
        let (dir, mut rotation, grab_rx) = pause_rotation("pause-toggle").await;

        // Initial state (local target): keyboard grabbed, mouse passing through.
        let state = *grab_rx.borrow();
        assert!(class_grabbed(DeviceClass::Keyboard, &state));
        assert!(!class_grabbed(DeviceClass::Toggled, &state));

        // Pause: the held-key cleanup runs on the current (local) target FIRST,
        // then the broadcast ungrabs both device classes.
        rotation.toggle_pause("test").await;
        assert!(rotation.paused);
        assert_eq!(rotation.output_handler.released, 1);
        let state = *grab_rx.borrow();
        assert!(state.paused);
        assert!(!class_grabbed(DeviceClass::Keyboard, &state));
        assert!(!class_grabbed(DeviceClass::Toggled, &state));

        // While paused, switch chords are not acted on (and nothing was
        // forwarded, so no further cleanup runs either).
        rotation.next_client().await;
        rotation.prev_client().await;
        rotation.set_client("".to_string()).await;
        assert!(rotation.current_client.is_none());
        assert_eq!(rotation.output_handler.released, 1);

        // Resume: re-grab per the rotation state — keyboard grabbed, mouse
        // still passing through (no client is current).
        rotation.toggle_pause("test").await;
        assert!(!rotation.paused);
        let state = *grab_rx.borrow();
        assert!(!state.paused);
        assert!(class_grabbed(DeviceClass::Keyboard, &state));
        assert!(!class_grabbed(DeviceClass::Toggled, &state));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pause_with_client_regrabs_mice_on_resume_and_stays_ungrabbed_on_drop() {
        use crate::device::input::class_grabbed;
        use crate::device::DeviceClass;
        let (dir, mut rotation, grab_rx) = pause_rotation("pause-client").await;
        let endpoint: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        rotation.current_client = Some(endpoint);

        // Pause while a client is current: the mouse class ungrabs too (pause
        // wins over client_active), and resume re-grabs it (client current).
        rotation.toggle_pause("test").await;
        let state = *grab_rx.borrow();
        assert!(state.paused && state.client_active);
        assert!(!class_grabbed(DeviceClass::Keyboard, &state));
        assert!(!class_grabbed(DeviceClass::Toggled, &state));
        rotation.toggle_pause("test").await;
        let state = *grab_rx.borrow();
        assert!(class_grabbed(DeviceClass::Keyboard, &state));
        assert!(class_grabbed(DeviceClass::Toggled, &state));

        // Pause again, then the client drops (client removals funnel through
        // set_and_grab_current_client): the devices must stay ungrabbed, not
        // "re-grab for the local machine".
        rotation.toggle_pause("test").await;
        rotation.set_and_grab_current_client(None).await;
        let state = *grab_rx.borrow();
        assert!(state.paused && !state.client_active);
        assert!(!class_grabbed(DeviceClass::Keyboard, &state));
        assert!(!class_grabbed(DeviceClass::Toggled, &state));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn paused_server_drops_input_without_forwarding_or_emitting() {
        let (dir, mut rotation, _grab_rx) = pause_rotation("pause-input").await;
        rotation.current_client = Some("127.0.0.1:1234".parse().unwrap());
        rotation.toggle_pause("test").await;

        // Input seen while paused (monux keeps listening for the resume chord)
        // is counted as physical but neither forwarded nor emitted locally.
        rotation
            .send_input_events(device::InputBatch {
                events: vec![
                    i32_event(evdev::EventType::KEY.0, 28, 1),
                    i32_event(evdev::EventType::KEY.0, 28, 0),
                ],
                is_grabbed: false,
                class: event::DeviceClass::Mouse,
            })
            .await
            .unwrap();
        assert_eq!(rotation.status_counts.physical, 2);
        assert_eq!(rotation.status_counts.forwarded, 0);
        assert_eq!(rotation.status_counts.emitted_local, 0);
        assert_eq!(rotation.output_handler.written, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Builds a rotation for liveness tests, returning the grab-state
    /// receiver so the ungrab on silence can be asserted on. The liveness
    /// map is plain state precisely so these tests need no ClientInfo (it
    /// embeds quinn handles); fabricated endpoints stand in for clients, so
    /// sends to them fail benignly (warn-logged "not found").
    async fn liveness_rotation(
        name: &str,
    ) -> (PathBuf, Rotation<StubOutput>, watch::Receiver<device::GrabState>) {
        liveness_rotation_mode(name, NetworkMode::Local).await
    }

    /// liveness_rotation with an explicit network mode (the silence miss
    /// limit is mode-dependent: LAN 3 pings, WWW 6).
    async fn liveness_rotation_mode(
        name: &str,
        mode: NetworkMode,
    ) -> (PathBuf, Rotation<StubOutput>, watch::Receiver<device::GrabState>) {
        let dir = temp_dir(name);
        let (grab_tx, grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        let (rotation_tx, _rotation_rx) = mpsc::channel(8);
        let rotation = Rotation::new(RotationConfig {
            grab_tx,
            output_handler: StubOutput { written: 0, released: 0 },
            local_clipboard: None,
            config_dir: dir.clone(),
            rotation_tx,
            motion_mode: MotionMode::Pinned(None),
            throttle_mode: ThrottleMode::Pinned(None),
            mode,
            diagnostics: Arc::new(DiagnosticsMirror::new("127.0.0.1:0".parse().unwrap())),
        })
        .await
        .unwrap();
        (dir, rotation, grab_rx)
    }

    /// A liveness entry silenced since `silenced_for` ago with `pongs`
    /// consecutive recovery messages so far, heard from just now.
    #[test]
    fn degraded_link_logs_only_on_transitions() {
        let healthy = HEARTBEAT_LINK_RTT_WARN - Duration::from_millis(1);
        let degraded = HEARTBEAT_LINK_RTT_WARN + Duration::from_millis(1);
        let mut state = false;
        // Healthy windows log nothing (exactly AT the threshold is healthy:
        // the bar is strictly-greater).
        assert_eq!(degraded_link_transition(&mut state, healthy), None);
        assert_eq!(degraded_link_transition(&mut state, HEARTBEAT_LINK_RTT_WARN), None);
        // The healthy→degraded crossing logs once...
        assert_eq!(degraded_link_transition(&mut state, degraded), Some(true));
        // ...then repeated degraded windows stay quiet (no per-window spam on
        // a chronically bad link)...
        assert_eq!(degraded_link_transition(&mut state, degraded), None);
        assert_eq!(degraded_link_transition(&mut state, degraded), None);
        // ...the degraded→healthy crossing reports the recovery once...
        assert_eq!(degraded_link_transition(&mut state, healthy), Some(false));
        // ...and healthy windows are quiet again.
        assert_eq!(degraded_link_transition(&mut state, healthy), None);
    }

    #[tokio::test]
    async fn switch_request_from_current_client_switches_local() {
        let (dir, mut rotation, grab_rx) = liveness_rotation("switch-request").await;
        let endpoint: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        rotation.current_client = Some(endpoint);

        // The current client asks for the return: input goes local and the
        // devices ungrab (the fabricated endpoint's Switch(false) send fails
        // benignly, like the liveness tests).
        rotation.switch_request_from_client(endpoint).await;
        assert_eq!(rotation.current_client, None);
        assert!(!grab_rx.borrow().client_active);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn switch_request_from_non_current_client_is_ignored() {
        let (dir, mut rotation, _grab_rx) = liveness_rotation("switch-request-stale").await;
        let current: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let other: SocketAddr = "127.0.0.1:1235".parse().unwrap();
        rotation.current_client = Some(current);

        // A request from a client that doesn't have input changes nothing.
        rotation.switch_request_from_client(other).await;
        assert_eq!(rotation.current_client, Some(current));

        // Nor does any request while input is already local.
        rotation.current_client = None;
        rotation.switch_request_from_client(other).await;
        assert_eq!(rotation.current_client, None);
        let _ = fs::remove_dir_all(&dir);
    }

}
