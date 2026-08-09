use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use quinn::{RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio::task;
use tracing::{debug, error, info, trace, warn};

use crate::clipboard::{CLIPBOARD_SERVE_TIMEOUT_SECS, client, data};
use crate::device::output;
use crate::msgs::{bulk, event, shared};
use crate::network::{approval, link_quality::LinkQuality, link_quality::Tier, throttle, transport};
use crate::rotation::ThrottleMode;
use crate::notify;

/// Client-side scaling for relative pointer/scroll deltas (--mouse-scale,
/// --scroll-scale), applied on injection into this machine's virtual devices.
///
/// Deltas arrive as integers but scales are fractional: rounding each event
/// independently would turn every sub-1.0 scaled delta into zero and motion
/// would die (0.5x would emit nothing, ever). Instead each axis carries its
/// fractional remainder across events, so N input ticks emit floor(N*scale)
/// output ticks over time with no drift. Remainders are per-axis: X, Y, and
/// each wheel axis accumulate independently. Applied ONLY here, on the client
/// injection path — the server's local re-emit (rotation.rs) stays 1:1.
/// Whether this frame must be written on its own rather than coalesced with
/// its neighbours.
///
/// The server sends one message per evdev frame, and the output handler
/// emits exactly one SYN_REPORT per write() — so every frame merged into one
/// write() is delivered to the local compositor as a SINGLE frame. Relative
/// input survives that: deltas sum, and key events are independent. Absolute
/// input does not. The multitouch protocol is frame-based, so merging makes
/// the last value of each axis win: a stroke whose touch-down and lift land
/// in the same network chunk collapses into one frame ending at
/// ABS_MT_TRACKING_ID=-1 with BTN_TOUCH=0 — a touch that never happened, and
/// no pointer motion at all (verified by replaying a captured stroke both
/// ways into an identical virtual touchpad: per-frame moved the cursor,
/// merged moved nothing). Touchpads report at a few hundred Hz, so writing
/// their frames individually costs nothing; the coalescing that matters for
/// an 8kHz mouse is untouched.
fn frame_needs_own_syn(events: &[event::InputEvent]) -> bool {
    events.iter().any(|event| {
        let type_ = event
            .inputi32
            .as_ref()
            .map(|e| e.type_)
            .or_else(|| event.inputf64.as_ref().map(|e| e.type_));
        type_ == Some(evdev::EventType::ABSOLUTE.0)
    })
}

struct DeltaScaler {
    mouse_scale: f64,
    scroll_scale: f64,
    /// Carried fractional delta per relative-axis code.
    remainders: HashMap<u16, f64>,
}

impl DeltaScaler {
    fn new(mouse_scale: f64, scroll_scale: f64) -> DeltaScaler {
        DeltaScaler {
            mouse_scale,
            scroll_scale,
            remainders: HashMap::new(),
        }
    }

    /// Whether any scaling is in effect; 1.0/1.0 bypasses the math entirely.
    fn active(&self) -> bool {
        self.mouse_scale != 1.0 || self.scroll_scale != 1.0
    }

    /// The scale applying to a relative-axis code, if any: pointer motion axes
    /// scale by mouse_scale, wheel and hi-res wheel axes by scroll_scale.
    fn scale_for(&self, code: u16) -> Option<f64> {
        use evdev::RelativeAxisCode as R;
        if code == R::REL_X.0 || code == R::REL_Y.0 {
            Some(self.mouse_scale)
        } else if code == R::REL_WHEEL.0
            || code == R::REL_HWHEEL.0
            || code == R::REL_WHEEL_HI_RES.0
            || code == R::REL_HWHEEL_HI_RES.0
        {
            Some(self.scroll_scale)
        } else {
            None
        }
    }

    /// Scales the relative-axis deltas of a batch in place. An event whose
    /// scaled delta hasn't reached a whole tick yet is dropped — its fraction
    /// is carried in the axis remainder and emitted by a later event. All
    /// other events (keys, buttons, syn, absolute axes, unscaled relative
    /// axes) pass through untouched.
    fn apply(&mut self, events: &mut Vec<event::InputEvent>) {
        if !self.active() {
            return;
        }
        events.retain_mut(|e| {
            let Some(i) = &mut e.inputi32 else {
                return true;
            };
            if i.type_ != evdev::EventType::RELATIVE.0 {
                return true;
            }
            let Some(scale) = self.scale_for(i.code) else {
                return true;
            };
            if scale == 1.0 {
                return true;
            }
            let remainder = self.remainders.entry(i.code).or_insert(0.0);
            *remainder += i.value as f64 * scale;
            // Truncate toward zero: symmetric for negative deltas, so sign
            // changes can't bias the carried fraction.
            let whole = remainder.trunc();
            *remainder -= whole;
            if whole == 0.0 {
                // Sub-tick delta: carried, nothing to emit yet.
                false
            } else {
                i.value = whole as i32;
                true
            }
        });
    }
}

/// Everything a client connection is configured with, as opposed to the live
/// state it builds. Bundled rather than passed positionally: these values
/// travel together from main through run() into Connection::new(), and a
/// dozen positional parameters — two adjacent f64 scales among them — is a
/// transposition the compiler cannot catch.
///
/// Only `server_addr` changes over a client's lifetime: the reconnect loop
/// rewrites it as it cycles remembered servers and mDNS discovery.
pub struct ClientConfig {
    pub server_addr: SocketAddr,
    pub cert_verifier: Arc<approval::MonuxCertVerification<'static>>,
    pub max_clipboard_size_bytes: u64,
    pub mode: transport::NetworkMode,
    pub config_dir: std::path::PathBuf,
    /// Pointer/scroll scaling applied on injection (see DeltaScaler).
    pub mouse_scale: f64,
    pub scroll_scale: f64,
    pub control_state: Arc<crate::control::ClientStateMirror>,
    pub throttle_mode: ThrottleMode,
    /// An explicit --edge-map. None leaves the return edge to the server's
    /// EdgeInfo inference (see EdgeInference).
    pub edge_map: Option<crate::edge::EdgeMap>,
    pub edge_dwell: Duration,
}

/// Initializes a new client connection and runs its event loop.
/// Returns an error on connection failure or other logic error, in which case a new connection can be tried.
pub async fn run<O: output::OutputHandler>(
    cfg: &ClientConfig,
    local_clipboard: &mut Option<client::LocalClipboard>,
    output_handler: &mut O,
) -> Result<()> {
    let server_addr = &cfg.server_addr;
    let (mut client, connect_time) = Connection::new(cfg).await?;
    client.control_state.set_connected(client.conn().clone());
    // Remember this server for next time: mDNS (link-local multicast) can't
    // cross routers, so a working address is worth trying before discovery
    // on later runs (see known_servers.rs).
    if let Some(fingerprint) = cfg.cert_verifier.peer_fingerprint() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Err(e) = crate::known_servers::record(
            &cfg.config_dir,
            *server_addr,
            &fingerprint,
            client.server_hostname.as_deref(),
            now,
        ) {
            warn!("Failed to record the server in the remembered store: {:?}", e);
        }
    } else {
        debug!("No server fingerprint learned during the handshake; not remembering the server");
    }
    notify::notify(
        "monux-connection",
        notify::Urgency::Low,
        3000,
        "monux connected",
        &format!("Connected to server {}", server_addr),
    );
    // The link monitor's thresholds assume a LAN; a --www connection
    // legitimately exceeds them, so it only runs in Local mode.
    if cfg.mode == transport::NetworkMode::Local {
        task::spawn(monitor_link(
            client.conn().clone(),
            client.throttle_cell.clone(),
            cfg.throttle_mode,
        ));
    }
    // Screen-edge switching back to the server: either an explicit --edge-map
    // (spawned here per connection), or inferred from the server's EdgeInfo
    // advertisement (see handle_event_messages) — explicit wins. The detector
    // runs per connection and queues the edge-crossing fraction here; the
    // step loop turns it into a SwitchRequest on the events stream. Dropping
    // the receiver (connection teardown) quiets it.
    if let Some(map) = cfg.edge_map.clone() {
        let (request_tx, request_rx) = mpsc::unbounded_channel::<f64>();
        task::spawn(crate::edge::run_client(map, cfg.edge_dwell, request_tx));
        client.switch_request_rx = Some(request_rx);
    }
    loop {
        if let Err(e) = client
            .step(local_clipboard, output_handler, &connect_time)
            .await
        {
            // Log QUIC path stats: tells a lossy link apart from a silent peer.
            transport::log_conn_stats(client.conn());
            if !is_new_connection(&connect_time) {
                // An established session dropped. A connect that fails fast is
                // a setup/reachability problem and stays in the logs.
                notify::notify(
                    "monux-connection",
                    notify::Urgency::Normal,
                    5000,
                    "monux connection lost",
                    &format!(
                        "Lost the connection to server {}; reconnecting in the background",
                        server_addr
                    ),
                );
            }
            return Err(e);
        }
    }
}

struct Connection {
    events_send: SendStream,
    events_recv: RecvStream,
    /// Queue for the dedicated bulk-writer task, which owns the actual bulk
    /// stream. Queuing whole serialized frames (instead of writing inline)
    /// keeps a multi-megabyte clipboard write from suspending this loop —
    /// including input application — and keeps each header glued to its
    /// payload when transfers overlap.
    bulk_tx: mpsc::Sender<Vec<u8>>,
    bulk_recv: RecvStream,
    /// Live pacing-rate cell shared with the bulk writer task (adaptive
    /// fidelity: monitor_link rewrites it as the measured link tier changes).
    throttle_cell: throttle::SharedThrottle,
    max_clipboard_size_bytes: u64,

    active: bool,

    /// Reusable buffer for receiving input events.
    event_bytes: Vec<u8>,
    /// Reusable buffer for receiving bulk data (clipboards).
    bulk_recv_bytes: Vec<u8>,

    /// Accumulator of raw clipboard data streamed from the server, plus the fetch
    /// it answers (None when the header's request_id was unknown: the payload is
    /// still swallowed to keep stream framing, but never delivered to a fetch).
    /// Cleared when the clipboard data has all been received.
    incoming_clipboard_data: Option<(data::ClipboardData, Option<data::ClipboardFetch>)>,

    /// Pending fetch requests for this connection, keyed by request id.
    pending_fetches: HashMap<u64, data::ClipboardFetch>,
    /// Next fetch request id. Wrapping is fine: ids only need to correlate a
    /// reply with its request, not resist adversaries.
    next_fetch_id: u64,

    /// Connection handle for receiving unreliable QUIC datagrams carrying
    /// high-rate pointer motion (see MotionDatagram).
    quinn_conn: quinn::Connection,
    /// Newest applied motion frame sequence number (see MotionDatagram::apply).
    last_motion_seq: u64,
    /// Bitmap of which of the last 64 motion frames have been applied.
    motion_applied_mask: u64,
    /// Whether writes to the virtual input devices are currently failing
    /// (see note_output_result).
    output_write_failing: bool,
    /// True until this connection has been switched active once. The clipboard
    /// re-announcement on activation (see the Switch handler) only fires on the
    /// FIRST activation of each connection — i.e. on a fresh (re)connect.
    fresh_activation: bool,
    /// True when a Switch(false) deferred its clipboard re-announce: the
    /// server's release_current_target_keys sends Switch(false)+Switch(true)
    /// in quick succession (a no-op key release, not a real deactivation).
    /// The re-announce is deferred so that an immediate Switch(true) can
    /// suppress it entirely (preventing clipboard-ownership flap). If a
    /// non-Switch event arrives instead, the deactivation was real and the
    /// re-announce is flushed.
    pending_deactivate: bool,
    /// Pointer/scroll delta scaling applied on injection (see DeltaScaler).
    scaler: DeltaScaler,
    /// Live-state mirror for the control socket (control.rs): Switch events
    /// update `active`; the lifecycle in main.rs drives (dis)connected.
    control_state: Arc<crate::control::ClientStateMirror>,
    /// Receives edge-crossing fractions from the screen-edge detector
    /// (edge.rs, --edge-map), which the step loop turns into SwitchRequest
    /// messages on the events stream. None when the feature is off (no
    /// --edge-map, or the detector exited on an unavailable Hyprland IPC).
    switch_request_rx: Option<mpsc::UnboundedReceiver<f64>>,
    /// Server-driven return-edge inference (see ServerEvent::EdgeInfo):
    /// rebuilt per connection, so a reconnect re-applies whatever the new
    /// connection's EdgeInfo says.
    edge_inference: EdgeInference,
    /// Dwell for the inferred edge detector (--edge-dwell-ms).
    edge_dwell: Duration,
    /// The server's hostname, learned from the v15+ handshake (None from an
    /// older server): feeds the approval prompt and the remembered-servers
    /// store (known_servers.rs).
    server_hostname: Option<String>,
}

/// Per-connection state of server-driven edge inference (see
/// ServerEvent::EdgeInfo): the server advertises which of ITS edges this
/// client sits beyond, and the client watches the OPPOSITE edge of its own
/// machine for the return trip — no --edge-map needed on the client. An
/// explicit --edge-map always wins: advertisements are then ignored.
struct EdgeInference {
    /// Whether the user gave an explicit --edge-map (explicit wins).
    explicit: bool,
    /// The directions inferred so far on this connection (the opposites of
    /// the server's advertised edges), each with target auto (the server is
    /// a client's only peer).
    map: crate::edge::EdgeMap,
}

impl EdgeInference {
    fn new(explicit: bool) -> Self {
        Self {
            explicit,
            map: crate::edge::EdgeMap::default(),
        }
    }

    /// Applies one ServerEvent::EdgeInfo, returning the updated inferred map
    /// when the detector should (re)start with it, or None when an explicit
    /// --edge-map wins and the advertisement is ignored. The watched
    /// direction is the OPPOSITE of the server's edge (the return trip).
    fn apply(&mut self, direction: event::Direction) -> Option<crate::edge::EdgeMap> {
        if self.explicit {
            return None;
        }
        self.map
            .targets
            .insert(direction.opposite(), crate::edge::EdgeTarget::Auto);
        Some(self.map.clone())
    }

    /// Applies one ServerEvent::EdgeInfoRevoke: removes the watched (opposite)
    /// direction established by a prior EdgeInfo. Returns Some(map) when the
    /// detector should respawn with the trimmed map, Some(empty) to stop the
    /// detector entirely (no inferred directions left), or None when an
    /// explicit --edge-map wins.
    fn revoke(&mut self, direction: event::Direction) -> Option<crate::edge::EdgeMap> {
        if self.explicit {
            return None;
        }
        self.map.targets.remove(&direction.opposite());
        Some(self.map.clone())
    }
}

impl Connection {
    /// Connects to the specified server, or returns an error if the connection fails.
    async fn new(cfg: &ClientConfig) -> Result<(Self, Instant)> {
        let ClientConfig {
            server_addr,
            cert_verifier,
            max_clipboard_size_bytes,
            mode,
            config_dir,
            mouse_scale,
            scroll_scale,
            control_state,
            throttle_mode,
            edge_dwell,
            ..
        } = cfg;
        let (max_clipboard_size_bytes, mode, edge_dwell) =
            (*max_clipboard_size_bytes, *mode, *edge_dwell);
        // An explicit --edge-map wins over the server's EdgeInfo inference.
        let edge_map_explicit = cfg.edge_map.is_some();
        let bind_addr: SocketAddr = match server_addr {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("Failed to parse 0.0.0.0:0"),
            SocketAddr::V6(_) => "[::]:0".parse().expect("Failed to parse [::]:0"),
        };
        let client_endpoint = transport::build_client(&bind_addr, cert_verifier.clone(), mode)?;
        // Bound the connect (QUIC+TLS handshake): the reconnect loop cycles
        // remembered server addresses (known_servers.rs), and a dead one must
        // fail fast — a silent address otherwise rides the full QUIC idle
        // timeout. Www gets longer so slow internet handshakes still pass.
        // The cert-approval prompt never blocks this future: an unknown cert
        // is rejected instantly while the prompt runs on its own thread
        // (approval.rs), and the reconnect loop's retry converges once the
        // user approves.
        let connect_timeout = match mode {
            transport::NetworkMode::Local => Duration::from_secs(3),
            transport::NetworkMode::Www => Duration::from_secs(10),
        };
        // Connect to server, our custom cert verifiers result in server_name being ignored
        let conn = tokio::time::timeout(
            connect_timeout,
            client_endpoint.connect(*server_addr, "__ignored__")?,
        )
        .await
        .with_context(|| {
            format!(
                "Connecting to {} timed out after {}s",
                server_addr,
                connect_timeout.as_secs()
            )
        })??;
        info!(
            "Connected to server: {} (from local endpoint {})",
            conn.remote_address(),
            // IP is typically 0.0.0.0 but the local port should be there at least
            client_endpoint
                .local_addr()
                .map_or("<unknown endpoint>".to_string(), |s| s.to_string())
        );
        let connect_time = Instant::now();
        let (mut events_send, mut events_recv) = conn
            .open_bi()
            .await
            .context("Failed to initialize events stream")?;

        // Exchange versions with the server; either side closes the
        // connection if it can't support the other's version.
        let mut event_bytes = Vec::with_capacity(1024);
        transport::send_version(&mut events_send, shared::PROTOCOL_VERSION).await?;
        let server_version = transport::recv_version(&mut events_recv, &mut event_bytes).await?;
        // Record the server's version (even on mismatch) for the update gate:
        // 'monux update' refuses builds our server couldn't talk to. Recording
        // a refused handshake too is what unblocks the gate after the server
        // upgrades ahead of us.
        crate::update::record_server_protocol_version(config_dir, server_version);
        if server_version > shared::PROTOCOL_VERSION {
            // The server upgraded ahead of us: the pair still connects (it
            // negotiates down to our version), but we run without its newer
            // features — so don't wait for the daily check, wake the
            // auto-updater now (once per process; the handshake retries
            // would otherwise re-hint every few seconds).
            static UPDATE_HINTED: AtomicBool = AtomicBool::new(false);
            if !UPDATE_HINTED.swap(true, Ordering::SeqCst) {
                info!(
                    "The server runs a newer monux (protocol v{} > v{}): connecting at v{} without its newer features",
                    server_version,
                    shared::PROTOCOL_VERSION,
                    shared::PROTOCOL_VERSION
                );
                crate::autoupdate::hint_update_available();
            }
        }
        // One way to pair: both sides at v16+, running at the lower version.
        // A server below that is refused outright — it predates negotiation
        // and would refuse us anyway; it auto-updates and comes back.
        let negotiated = shared::negotiate(server_version, shared::PROTOCOL_VERSION)
            .with_context(|| {
                format!(
                    "The server speaks protocol v{}, which is too old for this client (v{} or newer is required). Update monux on the server; it will reconnect automatically.",
                    server_version,
                    shared::PROTOCOL_VERSION_NEGOTIATION
                )
            })?;
        if negotiated < shared::PROTOCOL_VERSION {
            info!(
                "The server speaks protocol v{}, we speak v{}: running at v{} (disabled: {})",
                server_version,
                shared::PROTOCOL_VERSION,
                negotiated,
                shared::disabled_features(negotiated)
            );
        }

        // The server follows the events-stream version with its hostname
        // (length-prefixed). Learned for the approval prompt (a direct-IP
        // connect has no mDNS name) and for the remembered-servers store
        // (known_servers.rs). Unconditional since 13.0.0 — the frame used to
        // ride a v15 gate, and v16 is the floor now.
        let server_hostname = {
            let hostname = transport::recv_hostname(&mut events_recv, &mut event_bytes).await?;
            if hostname.is_empty() {
                None
            } else {
                cert_verifier.set_handshake_server_name(hostname.clone());
                Some(hostname)
            }
        };

        let (mut bulk_send, mut bulk_recv) = conn
            .open_bi()
            .await
            .context("Failed to initialize bulk stream")?;
        // Clipboard bulk yields to the events stream (priority 0) when the
        // connection is congested, so a big transfer can't starve input.
        let _ = bulk_send.set_priority(-1);

        // Exchange versions again via the bulk stream.
        // This is required in order to initialize the bulk stream,
        // otherwise the server times out waiting for the stream to open.
        // The exchange gets its own scratch buffer: reusing event_bytes
        // would parse any leftover events-stream bytes as the bulk version
        // if either side ever pipelines data behind the version frame.
        let mut bulk_handshake_bytes = Vec::with_capacity(1024);
        transport::send_version(&mut bulk_send, shared::PROTOCOL_VERSION).await?;
        let bulk_server_version = transport::recv_version(&mut bulk_recv, &mut bulk_handshake_bytes).await?;
        // Same server as the events stream, whose version was already
        // negotiated there: it must speak the same version here.
        if bulk_server_version != server_version {
            bail!(
                "The server spoke protocol v{} on the events stream but v{} on the bulk stream",
                server_version,
                bulk_server_version
            );
        }

        // Dedicated writer task for the bulk stream: clipboard payloads can
        // be megabytes, and writing them inline would suspend the step loop —
        // including input application — for the whole transfer. The task also
        // keeps each header glued to its payload by writing queued byte blobs
        // sequentially. It exits when the last sender is dropped (connection
        // teardown) or when the stream fails. The queue is bounded
        // (bulk::BULK_QUEUE_CAPACITY): senders fail fast instead of queueing
        // clipboard payloads without limit behind a server that can't drain.
        let (bulk_tx, bulk_rx) = mpsc::channel::<Vec<u8>>(bulk::BULK_QUEUE_CAPACITY);
        // The pacing cell starts at the Normal-tier rate; monitor_link
        // rewrites it as the measured link tier changes (adaptive fidelity).
        let throttle_cell = throttle::shared_throttle(crate::rotation::effective_throttle_mbps(
            throttle_mode,
            Tier::Normal,
        ));
        throttle::spawn_bulk_writer(
            bulk_send,
            bulk_rx,
            throttle_cell.clone(),
            conn.remote_address(),
            |len, e| async move {
                // A broken stream also fails the step loop's read side, which
                // resets the connection.
                error!("Failed to write {} bytes to the bulk stream: {:?}", len, e);
            },
        );

        Ok((
            Self {
                events_send,
                events_recv,
                bulk_tx,
                bulk_recv,
                throttle_cell,
                max_clipboard_size_bytes,
                active: false,
                event_bytes,
                bulk_recv_bytes: Vec::with_capacity(65536),
                incoming_clipboard_data: None,
                pending_fetches: HashMap::new(),
                next_fetch_id: 0,
                quinn_conn: conn,
                last_motion_seq: 0,
                motion_applied_mask: 0,
                output_write_failing: false,
                fresh_activation: true,
                pending_deactivate: false,
                scaler: DeltaScaler::new(*mouse_scale, *scroll_scale),
                control_state: control_state.clone(),
                switch_request_rx: None,
                edge_inference: EdgeInference::new(edge_map_explicit),
                edge_dwell,
                server_hostname,
            },
            connect_time,
        ))
    }

    /// Exposes the QUIC connection for stats logging on connection loss.
    fn conn(&self) -> &quinn::Connection {
        &self.quinn_conn
    }

    /// Records the result of a write to the virtual input devices without
    /// tearing down the connection: a transient uinput failure (e.g. ENODEV
    /// while udev settles, or a partial writev) is logged once, repeat
    /// failures are suppressed while they continue, and the first success
    /// after a failing streak is logged as a recovery.
    /// Associated function (not &mut self) so it can be called while
    /// deserialized messages still borrow other fields.
    fn note_output_result(output_write_failing: &mut bool, result: Result<()>) {
        match result {
            Ok(()) => {
                if *output_write_failing {
                    info!("Writes to virtual input devices succeeded again");
                    *output_write_failing = false;
                }
            }
            Err(e) => {
                if !*output_write_failing {
                    warn!(
                        "Failed to write to virtual input devices, dropping events until writes recover: {:?}",
                        e
                    );
                    *output_write_failing = true;
                }
            }
        }
    }

    /// Writes the queued input frames, if any, and clears the queue. Uses
    /// the queued frames' device class when they carried one, so the routing
    /// is as precise on the flush as it was when the frames arrived.
    /// Associated function for the same reason as note_output_result.
    async fn flush_pending_input<O: output::OutputHandler>(
        output_handler: &mut O,
        output_write_failing: &mut bool,
        pending: &mut Vec<event::InputEvent>,
        pending_class: &mut Option<event::DeviceClass>,
    ) {
        let class = pending_class.take();
        if pending.is_empty() {
            return;
        }
        let events = std::mem::take(pending);
        let result = match class {
            Some(class) => output_handler.write_classed(class, events).await,
            None => output_handler.write(events).await,
        };
        Self::note_output_result(output_write_failing, result);
    }

    /// Queues one input frame for injection, or writes it immediately when
    /// it must keep its own frame boundary.
    ///
    /// Coalescing several frames into one write is what keeps an 8kHz mouse
    /// cheap — relative deltas sum and key events are independent, so the
    /// merge is lossless. Absolute input is different: the multitouch
    /// protocol is frame-based, so a merge makes the last value of each axis
    /// win and can collapse an entire touch into one frame the compositor
    /// reads as no touch at all. Those frames are written on their own.
    /// Frames from different devices never merge either: their events would
    /// interleave into one frame, and the queue can only carry one class.
    async fn queue_input<O: output::OutputHandler>(
        &mut self,
        output_handler: &mut O,
        pending: &mut Vec<event::InputEvent>,
        pending_class: &mut Option<event::DeviceClass>,
        class: Option<event::DeviceClass>,
        mut events: Vec<event::InputEvent>,
    ) {
        let own_frame =
            class == Some(event::DeviceClass::Touchpad) || frame_needs_own_syn(&events);
        if own_frame {
            // Flush what's queued first so ordering holds.
            Self::flush_pending_input(
                output_handler,
                &mut self.output_write_failing,
                pending,
                pending_class,
            )
            .await;
            let result = match class {
                Some(class) => output_handler.write_classed(class, events).await,
                None => output_handler.write(events).await,
            };
            Self::note_output_result(&mut self.output_write_failing, result);
            return;
        }
        if !pending.is_empty() && *pending_class != class {
            Self::flush_pending_input(
                output_handler,
                &mut self.output_write_failing,
                pending,
                pending_class,
            )
            .await;
        }
        *pending_class = class;
        pending.append(&mut events);
    }

    /// Performs a step of the client event loop, returning an error if the connection should be retried.
    async fn step<O: output::OutputHandler>(
        &mut self,
        local_clipboard: &mut Option<client::LocalClipboard>,
        output_handler: &mut O,
        connect_time: &Instant,
    ) -> Result<()> {
        // The clipboard channels get the same Option treatment as
        // switch_request_rx below: with no local clipboard they pend forever,
        // so a single select covers both cases.
        let (fetch_rx, types_rx) = match local_clipboard.as_mut() {
            Some(lc) => (
                Some(&mut lc.clipboard_fetch_rx),
                Some(&mut lc.local_types_rx),
            ),
            None => (None, None),
        };
        tokio::select! {
            local_fetch_request = async {
                match fetch_rx {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                // Send fetch request to server, keep request and its nested oneshot for handling the response
                if let Some(local_fetch_request) = local_fetch_request {
                    let request_id = self.next_fetch_id;
                    self.next_fetch_id = self.next_fetch_id.wrapping_add(1);
                    let msg = bulk::ClientBulk::ClipboardRequest(bulk::ClientClipboardRequest{
                        requested_type: &local_fetch_request.requested_type,
                        max_size_bytes: self.max_clipboard_size_bytes,
                        request_id,
                    });
                    let serializedmsg = postcard::to_stdvec_cobs(&msg)
                        .map_err(|e| anyhow!("Failed to serialize clipboard request message: {:?}", e))?;
                    trace!(
                        "Sending {} byte clipboard content request: {:X?}",
                        serializedmsg.len(),
                        &serializedmsg
                    );
                    // Drop fetches whose requester already timed out, then track this one.
                    self.pending_fetches.retain(|_, f| !f.fetch_result_tx.is_closed());
                    self.pending_fetches.insert(request_id, local_fetch_request);
                    // Queue the whole frame for the bulk writer task: a
                    // direct write here would suspend the whole select —
                    // including input application — behind any in-flight
                    // clipboard payload. try_send keeps the loop from
                    // parking on a full queue: a server that isn't
                    // draining leaves the connection wedged (it would die
                    // on the idle timeout anyway), so fail and reconnect.
                    self.bulk_tx
                        .try_send(serializedmsg)
                        .context("Failed to queue clipboard request message (bulk queue full or closed)")?;
                } else {
                    // The local clipboard stack is gone (its fetch channel
                    // closed). Bailing would fail every step — and every
                    // reconnect — on a local condition no reconnect can fix,
                    // so degrade like the other optional features (see
                    // switch_request_rx below): turn local clipboard serving
                    // off for this connection and carry on. Fetches from the
                    // server get an empty reply (handle_bulk_messages).
                    warn!("Local clipboard fetch channel closed; disabling local clipboard serving for this connection");
                    *local_clipboard = None;
                }
            },
            types_notify = async {
                match types_rx {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                // Local machine has a new clipboard entry.
                // If we're currently active, then store it until we're deactivated by a switch.
                // Ignore clipboard changes when inactive: Avoid polluting the rotation with "external" clipboards.
                if types_notify.is_err() {
                    // The clipboard type watcher died; degrade exactly like
                    // the fetch channel closing above.
                    warn!("Local clipboard types channel closed; disabling local clipboard serving for this connection");
                    *local_clipboard = None;
                }
                if self.active {
                    if let Some(lc) = local_clipboard {
                        lc.set_local_clipboard();
                    }
                }
            },
            event_result = self.events_recv.read_chunk(16384, true) => {
                // Incoming data may contain one or more messages, but I've never seen fragments of messages.
                let resp = event_result
                    .with_context(|| if is_new_connection(connect_time) {
                        // Additional help for typical behavior when setting things up
                        "Lost events connection, does server need to approve our fingerprint?"
                    } else {
                        "Lost events connection"
                    })?
                    .context("Server closed events connection")?;
                trace!("Received {} bytes from events stream: {:X?}", resp.bytes.len(), &*resp.bytes);
                // Copy the immutable response data into a mutable buffer
                self.event_bytes.extend_from_slice(&resp.bytes);
                if self.event_bytes.len() > shared::MAX_FRAME_BUFFER_BYTES {
                    bail!("Server sent an oversized events frame ({} bytes without a COBS terminator)", self.event_bytes.len());
                }
                self.handle_event_messages(local_clipboard.as_mut(), output_handler).await?;
            },
            datagram_result = self.quinn_conn.read_datagram() => {
                // Unreliable/unordered pointer motion (see MotionDatagram).
                let bytes = datagram_result.context("Lost datagram connection")?;
                self.handle_motion_datagram(&bytes, output_handler).await?;
            },
            bulk_result = self.bulk_recv.read_chunk(65536, true) => {
                let resp = bulk_result
                    .with_context(|| if is_new_connection(connect_time) {
                        // Additional help for typical behavior when setting things up
                        "Lost bulk connection, does server need to approve our fingerprint?"
                    } else {
                        "Lost bulk connection"
                    })?
                    .context("Server closed bulk connection")?;
                // Don't log the bytes themselves, there can be a lot for larger file copies
                trace!("Received {} bytes from bulk stream", resp.bytes.len());
                self.handle_bulk_data_or_messages(local_clipboard.as_mut(), resp.bytes).await?;
            },
            switch_request = async {
                match &mut self.switch_request_rx {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match switch_request {
                    // The screen-edge detector fired: ask the server to
                    // take input back (see ClientEvent::SwitchRequest).
                    Some(y_fraction) => self.send_switch_request(y_fraction).await?,
                    // The detector is gone (Hyprland IPC unavailable):
                    // the feature turns off, the connection is unaffected.
                    None => self.switch_request_rx = None,
                }
            },
        }
        Ok(())
    }

    /// Asks the server to switch input back to the local machine (see
    /// ClientEvent::SwitchRequest), on the ordered, reliable events stream.
    async fn send_switch_request(&mut self, y_fraction: f64) -> Result<()> {
        debug!("Sending switch request to server (y fraction {:.2})", y_fraction);
        let serializedmsg = postcard::to_stdvec_cobs(&event::ClientEvent::SwitchRequest {
            y_fraction,
        })
        .map_err(|e| anyhow!("Failed to serialize switch request message: {:?}", e))?;
        self.events_send
            .write_all(&serializedmsg)
            .await
            .context("Failed to send switch request message")
    }

    async fn handle_event_messages<O: output::OutputHandler>(
        &mut self,
        mut local_clipboard: Option<&mut client::LocalClipboard>,
        output_handler: &mut O,
    ) -> Result<()> {
        let mut offset = 0;
        let bytes_len = self.event_bytes.len();
        // Input events from all complete messages in this chunk are coalesced
        // into a single write per wake, so a burst of queued messages costs one
        // uinput write batch instead of one per message.
        let mut pending_input: Vec<event::InputEvent> = Vec::new();
        // The device class the queued frames came from, carried so the flush
        // can route them as precisely as the frames arrived. Frames of
        // different classes never share a queue (see queue_input).
        let mut pending_class: Option<event::DeviceClass> = None;
        while offset < self.event_bytes.len() {
            // A partial frame (no COBS terminator yet) is kept for the next chunk.
            if !shared::has_complete_cobs_frame(&self.event_bytes[offset..]) {
                break;
            }
            let (msg, resp_remainder) = postcard::take_from_bytes_cobs::<event::ServerEvent>(
                &mut self.event_bytes[offset..],
            )
            .map_err(|e| anyhow!("Failed to deserialize server message: {:?}", e))?;
            let consumed = bytes_len - resp_remainder.len() - offset;
            trace!(
                "Consumed event at offset={}: {} ({} bytes)",
                offset,
                msg,
                consumed
            );
            // Flush a deferred clipboard re-announce (from a preceding
            // Switch(false)) if this message isn't Switch(true): the
            // deactivation was real, not a no-op key-release pair.
            if self.pending_deactivate && !matches!(msg, event::ServerEvent::Switch(_)) {
                self.pending_deactivate = false;
                if let Some(local_clipboard) = &mut local_clipboard {
                    if let Some(types) = local_clipboard.get_local_clipboard_types() {
                        let types = types.join(" ");
                        debug!("Sending clipboard types to server: {}", types);
                        let msg =
                            event::ClientEvent::ClipboardTypes(event::ClipboardTypes {
                                types: &types,
                                max_size_bytes: self.max_clipboard_size_bytes,
                            });
                        let serializedmsg = postcard::to_stdvec_cobs(&msg).map_err(|e| {
                            anyhow!("Failed to serialize clipboard types message: {:?}", e)
                        })?;
                        self.events_send
                            .write_all(&serializedmsg)
                            .await
                            .context("Failed to send clipboard types message")?;
                    }
                }
            }
            match msg {
                event::ServerEvent::Switch(e) => {
                    // Preserve ordering: apply queued input before handling this.
                    Self::flush_pending_input(
                        output_handler,
                        &mut self.output_write_failing,
                        &mut pending_input,
                        &mut pending_class,
                    )
                    .await;
                    info!(
                        "This client is {}",
                        if e.enabled { "active" } else { "inactive" }
                    );
                    self.active = e.enabled;
                    self.control_state.set_active(e.enabled);
                    let first_activation = e.enabled && self.fresh_activation;
                    if e.enabled {
                        self.fresh_activation = false;
                    }
                    if !e.enabled {
                        // Deactivation: release held keys so they don't stay
                        // stuck on the virtual devices.
                        Self::note_output_result(
                            &mut self.output_write_failing,
                            output_handler.release_all().await,
                        );
                        // Defer the clipboard re-announce: the server's
                        // release_current_target_keys sends Switch(false)
                        // immediately followed by Switch(true) (a no-op key
                        // release, not a real deactivation). If Switch(true)
                        // comes next, we suppress the re-announce entirely.
                        self.pending_deactivate = true;
                    } else if self.pending_deactivate {
                        // Switch(true) right after Switch(false): no-op key
                        // release pair. Clear the deferred flag and skip the
                        // clipboard re-announce (it would flap ownership).
                        self.pending_deactivate = false;
                    } else if first_activation {
                        // First activation of a connection: re-announce local
                        // clipboard types so a pre-drop copy survives. See the
                        // detailed comment below for why this is safe.
                        //
                        // The first activation of a connection RE-announces:
                        // when a drop makes the server clear the rotation's
                        // clipboard state, a clipboard copied before the drop
                        // would otherwise silently vanish. This cannot
                        // resurrect a stale clipboard over a genuinely newer
                        // one: the server pushes the types of any clipboard
                        // owned elsewhere BEFORE the Switch(true) that
                        // activates us, on this ordered events stream (both
                        // when adding the client and when switching to it),
                        // and that announcement replaces our local types
                        // (set_remote_clipboard). Still holding local types at
                        // the first activation therefore means the rotation
                        // has nothing newer. Later activations on the same
                        // connection don't re-announce: the
                        // deactivate/activate handoff keeps the rotation
                        // current there.
                        if let Some(local_clipboard) = &mut local_clipboard {
                            if let Some(types) = local_clipboard.get_local_clipboard_types() {
                                let types = types.join(" ");
                                debug!("Sending clipboard types to server: {}", types);
                                let msg = event::ClientEvent::ClipboardTypes(
                                    event::ClipboardTypes {
                                        types: &types,
                                        max_size_bytes: self.max_clipboard_size_bytes,
                                    },
                                );
                                let serializedmsg = postcard::to_stdvec_cobs(&msg).map_err(
                                    |e| {
                                        anyhow!(
                                            "Failed to serialize clipboard types message: {:?}",
                                            e
                                        )
                                    },
                                )?;
                                self.events_send
                                    .write_all(&serializedmsg)
                                    .await
                                    .context("Failed to send clipboard types message")?;
                            }
                        }
                    }
                }
                // Untagged input frame: a server negotiated below v17, so
                // the destination device is inferred from event codes.
                event::ServerEvent::Input(mut events) => {
                    // User input events: coalesced and written after the loop.
                    // Pointer/scroll scaling (--mouse-scale/--scroll-scale)
                    // applies here, just before injection.
                    self.scaler.apply(&mut events);
                    self.queue_input(
                        output_handler,
                        &mut pending_input,
                        &mut pending_class,
                        None,
                        events,
                    )
                    .await;
                }
                // Class-tagged input frame (protocol v17+).
                event::ServerEvent::ClassedInput { class, mut events } => {
                    self.scaler.apply(&mut events);
                    self.queue_input(
                        output_handler,
                        &mut pending_input,
                        &mut pending_class,
                        Some(class),
                        events,
                    )
                    .await;
                }
                event::ServerEvent::ClipboardTypes(types) => {
                    // Preserve ordering: apply queued input before handling this.
                    Self::flush_pending_input(
                        output_handler,
                        &mut self.output_write_failing,
                        &mut pending_input,
                        &mut pending_class,
                    )
                    .await;
                    // Receiving types announcement from server (following recent activation)
                    // Announce the types to the local clipboard for local apps to see, and clear any prior types from local apps.
                    if let Some(local_clipboard) = &mut local_clipboard {
                        debug!("Got clipboard types from server: {}", types.types);
                        // An empty types string (clipboard clear) splits to no
                        // types, so the writer takes its clear branch instead
                        // of advertising a phantom "" mime type.
                        local_clipboard.set_remote_clipboard(types.types_vec())?;
                    } else {
                        debug!("Ignoring clipboard types from server: {}", types.types);
                    }
                }
                event::ServerEvent::Ping => {
                    // Server liveness check: answer immediately on this same
                    // ordered, reliable events stream. The server counts ANY
                    // received message as liveness; the pong is what an
                    // otherwise idle client has to say. No pending_input
                    // flush: the pong carries no input state and must not
                    // wait behind a burst of queued input.
                    let serializedmsg = postcard::to_stdvec_cobs(&event::ClientEvent::Pong)
                        .map_err(|e| anyhow!("Failed to serialize pong message: {:?}", e))?;
                    self.events_send
                        .write_all(&serializedmsg)
                        .await
                        .context("Failed to send pong message")?;
                }
                event::ServerEvent::EdgeInfo { direction } => {
                    // Server-driven edge inference: the server told us which
                    // of ITS edges we sit beyond, so we watch the OPPOSITE
                    // edge of this machine for the return trip. Carries no
                    // input state, so no pending_input flush.
                    match self.edge_inference.apply(direction) {
                        Some(map) => {
                            info!(
                                "Server says we're its {}-hand client: watching the {} edge (inferred)",
                                direction.as_str(),
                                direction.opposite().as_str()
                            );
                            // (Re)start the detector with the updated inferred
                            // map: dropping the old receiver quiets the
                            // previous detector (edge.rs client mode).
                            let (request_tx, request_rx) = mpsc::unbounded_channel::<f64>();
                            task::spawn(crate::edge::run_client(map, self.edge_dwell, request_tx));
                            self.switch_request_rx = Some(request_rx);
                        }
                        None => debug!(
                            "Server says we're its {}-hand client, but --edge-map was given explicitly: keeping it",
                            direction.as_str()
                        ),
                    }
                }
                event::ServerEvent::EdgeInfoRevoke { direction } => {
                    // The target on the server's side for `direction`
                    // disconnected (or 'auto' became ambiguous). Stop
                    // watching the opposite edge.
                    match self.edge_inference.revoke(direction) {
                        Some(map) => {
                            if map.targets.is_empty() {
                                info!(
                                    "Server revoked our {}-hand edge: no inferred edges left, stopping detector",
                                    direction.opposite().as_str()
                                );
                                self.switch_request_rx = None;
                            } else {
                                info!(
                                    "Server revoked our {}-hand edge: respawning detector with {} remaining",
                                    direction.opposite().as_str(),
                                    map.targets.len()
                                );
                                let (request_tx, request_rx) = mpsc::unbounded_channel::<f64>();
                                task::spawn(crate::edge::run_client(map, self.edge_dwell, request_tx));
                                self.switch_request_rx = Some(request_rx);
                            }
                        }
                        None => debug!(
                            "Server revoked our {}-hand edge, but --edge-map was given explicitly: keeping it",
                            direction.opposite().as_str()
                        ),
                    }
                }
            }
            offset += consumed;
        }
        Self::flush_pending_input(
            output_handler,
            &mut self.output_write_failing,
            &mut pending_input,
            &mut pending_class,
        )
        .await;
        // Retain any unconsumed partial frame for the next chunk.
        self.event_bytes.drain(..offset);
        Ok(())
    }

    /// Applies a pointer-motion datagram, healing lost frames from the repeated
    /// history and skipping ones already applied (see MotionDatagram::apply).
    async fn handle_motion_datagram<O: output::OutputHandler>(
        &mut self,
        bytes: &[u8],
        output_handler: &mut O,
    ) -> Result<()> {
        let msg = postcard::from_bytes::<event::MotionDatagram>(bytes)
            .map_err(|e| anyhow!("Failed to deserialize motion datagram: {:?}", e))?;
        if !self.active {
            // We're not the switched-active client; the datagram raced a switch.
            return Ok(());
        }
        if msg.history.is_empty() {
            // Never sent by a monux server; applying it would needlessly age
            // out still-healable frames.
            return Ok(());
        }
        let applied = msg.apply(self.last_motion_seq, self.motion_applied_mask);
        self.last_motion_seq = applied.last_seq;
        self.motion_applied_mask = applied.applied_mask;
        let (dx, dy) = applied.delta;
        if dx == 0 && dy == 0 {
            // Stale datagram, or one carrying only already-applied frames.
            trace!("Motion datagram seq={} contributed nothing new", msg.seq);
            return Ok(());
        }
        trace!("Applying motion datagram seq={}: dx={} dy={}", msg.seq, dx, dy);
        let mut events = Vec::with_capacity(2);
        if dx != 0 {
            events.push(event::motion_event(evdev::RelativeAxisCode::REL_X.0, dx));
        }
        if dy != 0 {
            events.push(event::motion_event(evdev::RelativeAxisCode::REL_Y.0, dy));
        }
        // Pointer scaling applies to datagram motion too (see DeltaScaler).
        self.scaler.apply(&mut events);
        Self::note_output_result(
            &mut self.output_write_failing,
            output_handler.write(events).await,
        );
        Ok(())
    }

    async fn handle_bulk_data_or_messages(
        &mut self,
        local_clipboard: Option<&mut client::LocalClipboard>,
        resp_bytes: Bytes,
    ) -> Result<()> {
        if let Some((c, _fetch)) = &mut self.incoming_clipboard_data {
            // Clipboard data streaming is in progress. The message should be raw clipboard data.
            if c.remaining_bytes >= resp_bytes.len() {
                // This chunk should entirely be raw clipboard data.
                c.bytes.extend_from_slice(&resp_bytes);
                c.remaining_bytes -= resp_bytes.len();
            } else {
                // Chunk contains more data than expected for the clipboard entry.
                // Finish the clipboard entry, then save the remainder to bulk_recv_bytes for processing below.
                c.bytes
                    .extend_from_slice(&(*resp_bytes)[..c.remaining_bytes]);
                self.bulk_recv_bytes
                    .extend_from_slice(&(*resp_bytes)[c.remaining_bytes..]);
                c.remaining_bytes = 0;
            }

            if c.remaining_bytes == 0 {
                // Raw clipboard data has all been accumulated, send it to the pending fetch.
                // Pass ownership of the data to the writer and clear local state.
                let (d, fetch) = self
                    .incoming_clipboard_data
                    .take()
                    .expect("Just checked data was present");
                if let Some(waiting_clipboard_fetch) = fetch {
                    if let Err(_d_again) = waiting_clipboard_fetch.fetch_result_tx.send(d) {
                        warn!("Discarding clipboard data from server: the requesting paste already timed out");
                    }
                }
                // fetch=None: unknown request_id (debug-logged when the header arrived);
                // the payload was only swallowed to keep the stream framed.
            }

            if !self.bulk_recv_bytes.is_empty() {
                // Handle any data/messages following the raw clipboard dump.
                if let Some(updated_clipboard_data) =
                    self.handle_bulk_messages(local_clipboard).await?
                {
                    self.incoming_clipboard_data.replace(updated_clipboard_data);
                }
            }
        } else {
            // Not in the middle of a raw clipboard dump. Must be a postcard message.
            // Copy the immutable response data into a mutable buffer for parsing.
            self.bulk_recv_bytes.extend_from_slice(&resp_bytes);
            if self.bulk_recv_bytes.len() > shared::MAX_FRAME_BUFFER_BYTES {
                bail!("Server sent an oversized bulk frame ({} bytes without a COBS terminator)", self.bulk_recv_bytes.len());
            }
            if let Some(updated_clipboard_data) = self.handle_bulk_messages(local_clipboard).await?
            {
                self.incoming_clipboard_data.replace(updated_clipboard_data);
            }
        }
        Ok(())
    }

    async fn handle_bulk_messages(
        &mut self,
        mut local_clipboard: Option<&mut client::LocalClipboard>,
    ) -> Result<Option<(data::ClipboardData, Option<data::ClipboardFetch>)>> {
        let mut offset = 0;
        let bytes_len = self.bulk_recv_bytes.len();
        while offset < bytes_len {
            // A partial frame (no COBS terminator yet) is kept for the next chunk.
            if !shared::has_complete_cobs_frame(&self.bulk_recv_bytes[offset..]) {
                break;
            }
            let (msg, resp_remainder) = postcard::take_from_bytes_cobs::<bulk::ServerBulk>(
                &mut self.bulk_recv_bytes[offset..],
            )
            .map_err(|e| anyhow!("Failed to deserialize bulk message: {:?}", e))?;
            let consumed = bytes_len - resp_remainder.len() - offset;
            trace!(
                "Consumed event at offset={}: {} ({} bytes)",
                offset,
                msg,
                consumed
            );
            offset += consumed;

            match msg {
                bulk::ServerBulk::ClipboardRequest(c) => {
                    let local_clipboard = match &mut local_clipboard {
                        Some(lc) => lc,
                        None => {
                            // No local clipboard to serve (never had one, or
                            // its stack died and serving was disabled for this
                            // connection): answer with an empty header so the
                            // requester's paste completes with nothing, instead
                            // of resetting the connection into a reconnect loop
                            // that faces the same local condition.
                            warn!("Got a clipboard fetch from the server but have no local clipboard; serving empty");
                            let msg = bulk::ClientBulk::ClipboardHeader(bulk::ClientClipboardHeader {
                                requested_type: c.requested_type,
                                data_type: None,
                                content_len_bytes: 0,
                                request_client: c.request_client,
                                request_id: c.request_id,
                            });
                            let bytes = postcard::to_stdvec_cobs(&msg)
                                .map_err(|e| anyhow!("Failed to serialize clipboard header message: {:?}", e))?;
                            // try_send, same policy as the serving task below.
                            if self.bulk_tx.try_send(bytes).is_err() {
                                error!("Failed to queue empty clipboard content for sending: bulk queue full or closed");
                            }
                            continue;
                        }
                    };
                    // Serve the data from a spawned task: reading the local
                    // clipboard (zipping large copied files can take seconds)
                    // must not stall input event handling.
                    let reader = local_clipboard.reader_handle();
                    let bulk_tx = self.bulk_tx.clone();
                    let requested_type = c.requested_type.to_string();
                    let max_size_bytes = c.max_size_bytes;
                    let request_client = c.request_client;
                    let request_id = c.request_id;
                    task::spawn(async move {
                        // Read the clipboard data from the local application.
                        // On read failure or timeout, reply with an empty header so that the requester just sets nothing.
                        // The read must always answer within the 5s fetch timeout on the requester side.
                        let started = Instant::now();
                        let (local_clipboard_data, data_type) = match tokio::time::timeout(
                            Duration::from_secs(CLIPBOARD_SERVE_TIMEOUT_SECS),
                            client::LocalClipboard::read(&reader, &requested_type, max_size_bytes, request_client),
                        )
                        .await
                        {
                            Ok(Ok(result)) => result,
                            Ok(Err(e)) => {
                                warn!("Failed to read local clipboard of type {}: {:?}", requested_type, e);
                                (Default::default(), None)
                            }
                            Err(_) => {
                                warn!("Timed out after {}s reading local clipboard of type {}", CLIPBOARD_SERVE_TIMEOUT_SECS, requested_type);
                                (Default::default(), None)
                            }
                        };
                        // Symmetric with the writer's "Serving paste request
                        // ... took Ns": makes stalls attributable to the
                        // serving side.
                        let elapsed = started.elapsed();
                        if local_clipboard_data.is_empty() {
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
                                local_clipboard_data.len()
                            );
                        }
                        let msg = bulk::ClientBulk::ClipboardHeader(bulk::ClientClipboardHeader {
                            requested_type: &requested_type,
                            data_type: data_type.as_deref(),
                            content_len_bytes: local_clipboard_data.len() as u64,
                            request_client,
                            request_id,
                        });
                        let mut bytes = match postcard::to_stdvec_cobs(&msg) {
                            Ok(b) => b,
                            Err(e) => {
                                error!("Failed to serialize clipboard header message: {:?}", e);
                                return;
                            }
                        };
                        bytes.extend_from_slice(&local_clipboard_data);
                        // The whole frame — header glued to its payload — goes
                        // to the bulk writer task as one blob, so overlapping
                        // transfers can't interleave on the stream, and this
                        // task never parks on a multi-megabyte write. A full
                        // queue means the server isn't draining; the wedged
                        // connection dies on the step loop's read side or the
                        // idle timeout, and the reconnect re-serves.
                        let len = bytes.len();
                        if bulk_tx.try_send(bytes).is_err() {
                            error!("Failed to queue {} byte clipboard content for sending: bulk queue full or closed", len);
                        }
                    });
                }
                bulk::ServerBulk::DiagnosticsRequest(d) => {
                    // The server is assembling a bug report and wants this
                    // machine's side of it (protocol v18). Answering is cheap
                    // — the bundle is built from in-memory mirrors — so it
                    // happens inline; the reply rides the bulk queue like
                    // clipboard content, never the events stream.
                    let (json, error) = build_diagnostics_reply(&self.control_state, d.lines);
                    let reply = bulk::ClientBulk::DiagnosticsResponse(bulk::DiagnosticsResponse {
                        request_id: d.request_id,
                        json: json.as_deref(),
                        error: error.as_deref(),
                    });
                    let bytes = postcard::to_stdvec_cobs(&reply).map_err(|e| {
                        anyhow!("Failed to serialize diagnostics response: {:?}", e)
                    })?;
                    // A full queue is the server not draining; the bug report
                    // simply records this peer as unanswered, which is far
                    // better than dropping a working connection over it.
                    if self.bulk_tx.try_send(bytes).is_err() {
                        warn!("Failed to queue the diagnostics response: bulk queue full or closed");
                    }
                }
                bulk::ServerBulk::ClipboardHeader(c) => {
                    if c.content_len_bytes > self.max_clipboard_size_bytes {
                        // The content length from the server is bigger than what we advertised.
                        // Reset the connection since this shouldn't happen to begin with.
                        bail!(
                            "Received clipboard size {} exceeds max size {}, resetting connection",
                            c.content_len_bytes,
                            self.max_clipboard_size_bytes
                        );
                    }
                    // Correlate the response with its request. A response with an unknown
                    // id (e.g. its fetch already timed out) is still consumed to keep the
                    // stream framed, but is never delivered to a different fetch.
                    let fetch = self.pending_fetches.remove(&c.request_id);
                    if fetch.is_none() {
                        debug!("Discarding clipboard data for unknown request_id={}", c.request_id);
                    }
                    if c.content_len_bytes as usize <= resp_remainder.len() {
                        // The clipboard content fits fully within resp_remainder, send it to the pending fetch.
                        // Mark content as consumed and continue looping in case another message follows.
                        if let Some(waiting_clipboard_fetch) = fetch {
                            let mut bytes = Vec::with_capacity(c.content_len_bytes as usize);
                            bytes
                                .extend_from_slice(&resp_remainder[..c.content_len_bytes as usize]);
                            let d = data::ClipboardData {
                                requested_type: c.requested_type.to_string(),
                                data_type: c.data_type.map(|t| t.to_string()),
                                bytes,
                                remaining_bytes: 0,
                            };
                            if let Err(_d_again) = waiting_clipboard_fetch.fetch_result_tx.send(d) {
                                warn!("Discarding clipboard data from server: the requesting paste already timed out");
                            }
                        }
                        offset += c.content_len_bytes as usize;
                    } else {
                        // Need to collect more data.
                        // Save what we've got so far, and assign remaining_bytes to what's left.
                        // Capped capacity hint, for the same reason as the
                        // server's mirror of this branch: content_len_bytes is
                        // declared by the peer, so a tiny header must not be
                        // able to commit the whole max clipboard size before
                        // any payload arrives (see payload_capacity_hint).
                        let mut payload =
                            Vec::with_capacity(crate::server::payload_capacity_hint(
                                c.content_len_bytes,
                            ));
                        payload.extend_from_slice(resp_remainder);
                        let d = data::ClipboardData {
                            requested_type: c.requested_type.to_string(),
                            data_type: c.data_type.map(|t| t.to_string()),
                            bytes: payload,
                            remaining_bytes: c.content_len_bytes as usize - resp_remainder.len(),
                        };
                        // All bytes were consumed (into the pending clipboard data).
                        self.bulk_recv_bytes.clear();
                        return Ok(Some((d, fetch)));
                    }
                }
            }
        }
        // Retain any unconsumed partial frame for the next chunk.
        self.bulk_recv_bytes.drain(..offset);
        Ok(None)
    }
}

fn is_new_connection(connect_time: &Instant) -> bool {
    Instant::now().duration_since(*connect_time) < Duration::from_secs(5)
}

/// Largest diagnostics bundle a client will send back. The requested line
/// count already bounds it, but the cap is what guarantees the frame stays
/// well under shared::MAX_FRAME_BUFFER_BYTES — a peer report must not be
/// able to trip the server's oversized-frame guard and drop the connection.
const MAX_DIAGNOSTICS_REPLY_BYTES: usize = 256 * 1024;

/// Builds this client's answer to a peer-diagnostics request: `(json, error)`,
/// exactly one of which is Some.
///
/// Every failure becomes an `error` string rather than a lost response. The
/// server is waiting on a timeout, and "the client said it couldn't build a
/// bundle" is a far better line in a bug report than five seconds of silence
/// that looks identical to a dead link.
fn build_diagnostics_reply(
    control_state: &crate::control::ClientStateMirror,
    lines: u32,
) -> (Option<String>, Option<String>) {
    let diagnostics = crate::control::Diagnostics::for_client(control_state, lines as usize);
    match serde_json::to_string(&diagnostics) {
        Ok(json) if json.len() <= MAX_DIAGNOSTICS_REPLY_BYTES => (Some(json), None),
        Ok(json) => (
            None,
            Some(format!(
                "built a {} byte bundle, over the {} byte reply cap; ask for fewer lines, \
                 or run 'monux diagnostics' on that machine",
                json.len(),
                MAX_DIAGNOSTICS_REPLY_BYTES
            )),
        ),
        Err(e) => (None, Some(format!("could not serialize its bundle: {}", e))),
    }
}

/// How often the link monitor samples the connection's QUIC path stats.
const LINK_SAMPLE_INTERVAL: Duration = Duration::from_secs(15);

/// RTT above which the link is called degraded. monux targets LANs, where RTT
/// is single-digit milliseconds; beyond this, the network (usually WiFi) is
/// adding user-visible lag to every input event.
const LINK_RTT_WARN: Duration = Duration::from_millis(50);

/// Packet-loss rate (lost/sent within one sample window) above which the link
/// is called degraded. A healthy LAN loses ~nothing; beyond this, pointer
/// motion stutters and keystrokes wait on retransmits.
const LINK_LOSS_WARN: f64 = 0.02;

/// Minimum packets in a sample window before its loss rate means anything. An
/// idle connection sends only keepalives (~8 per window), where a single lost
/// packet would already read as >10% loss.
const LINK_LOSS_MIN_WINDOW_PACKETS: u64 = 20;

/// Minimum spacing between link notifications (degraded and recovered alike),
/// so a flapping link can't turn into notification spam.
const LINK_NOTIFY_COOLDOWN: Duration = Duration::from_secs(5 * 60);

/// What a link sample means for the user.
#[derive(Debug, PartialEq, Eq)]
enum LinkVerdict {
    /// Nothing changed (or a change was suppressed by the cooldown).
    Steady,
    /// The link crossed a degradation threshold; warn.
    Degraded,
    /// The link returned under the thresholds after a warned degradation.
    Recovered,
}

/// Tracks link-degradation notification state across samples: warns once when
/// the link goes bad and once when it recovers, rate-limited to one
/// notification per LINK_NOTIFY_COOLDOWN. A transition suppressed by the
/// cooldown leaves the state untouched, so it is retried on the next sample —
/// a persistent degradation still surfaces once the cooldown expires.
struct LinkMonitor {
    /// Whether the user has been told the link is bad and not yet told it recovered.
    degraded: bool,
    /// When the last link notification (either kind) was shown.
    last_notification: Option<Instant>,
}

impl LinkMonitor {
    fn new() -> Self {
        LinkMonitor {
            degraded: false,
            last_notification: None,
        }
    }

    /// Classifies one stats sample; `loss_rate` is lost/sent over the window.
    fn check(&mut self, rtt: Duration, loss_rate: f64, now: Instant) -> LinkVerdict {
        let bad = rtt > LINK_RTT_WARN || loss_rate > LINK_LOSS_WARN;
        if bad == self.degraded {
            return LinkVerdict::Steady;
        }
        if self
            .last_notification
            .is_some_and(|last| last + LINK_NOTIFY_COOLDOWN > now)
        {
            return LinkVerdict::Steady;
        }
        self.degraded = bad;
        self.last_notification = Some(now);
        if bad {
            LinkVerdict::Degraded
        } else {
            LinkVerdict::Recovered
        }
    }
}

/// Details of an in-progress link degradation, for the recovery summary.
struct DegradationEpisode {
    start: Instant,
    peak_rtt: Duration,
    sent_at_start: u64,
    lost_at_start: u64,
}

impl DegradationEpisode {
    fn start_now(now: Instant, rtt: Duration, sent: u64, lost: u64) -> Self {
        Self {
            start: now,
            peak_rtt: rtt,
            sent_at_start: sent,
            lost_at_start: lost,
        }
    }

    fn record(&mut self, rtt: Duration) {
        self.peak_rtt = self.peak_rtt.max(rtt);
    }

    /// "degraded for 47s, peak rtt 213ms, 12 of 900 packets lost in that window"
    fn summary(&self, now: Instant, sent: u64, lost: u64) -> String {
        format!(
            "degraded for {:.0}s, peak rtt {:?}, {} of {} packets lost in that window",
            now.duration_since(self.start).as_secs_f64(),
            self.peak_rtt,
            lost.saturating_sub(self.lost_at_start),
            sent.saturating_sub(self.sent_at_start),
        )
    }
}

/// Samples the connection's QUIC path stats on a timer and warns — at most
/// once per LINK_NOTIFY_COOLDOWN — when the link degrades past LAN
/// expectations, plus once when it recovers. The message points at the
/// WiFi/link, not monux. Exits when the connection closes.
async fn monitor_link(
    conn: quinn::Connection,
    throttle: throttle::SharedThrottle,
    throttle_mode: ThrottleMode,
) {
    let mut monitor = LinkMonitor::new();
    let mut quality = LinkQuality::new();
    let mut episode: Option<DegradationEpisode> = None;
    let mut interval = tokio::time::interval(LINK_SAMPLE_INTERVAL);
    // The first interval tick is immediate: consume it and take the loss
    // baseline, so every judged window is a genuine post-connect interval.
    // A handshake that spanned a server outage retransmits Initials into the
    // void; those cumulative counters would otherwise poison the first window.
    interval.tick().await;
    let mut last_sent = conn.stats().path.sent_packets;
    let mut last_lost = conn.stats().path.lost_packets;
    loop {
        tokio::select! {
            _ = conn.closed() => return,
            _ = interval.tick() => {}
        }
        let path = conn.stats().path;
        // The counters are cumulative; the rate is over the last window. A
        // window too small for a meaningful rate (idle, keepalives only)
        // reports no loss; the RTT is still judged.
        let sent = path.sent_packets.saturating_sub(last_sent);
        let lost = path.lost_packets.saturating_sub(last_lost);
        last_sent = path.sent_packets;
        last_lost = path.lost_packets;
        let loss_rate = if sent < LINK_LOSS_MIN_WINDOW_PACKETS {
            0.0
        } else {
            lost as f64 / sent as f64
        };
        // Every sample leaves evidence in the log, independent of the
        // notification cooldown below: debug for routine samples, info once
        // past the warn thresholds (RTT spikes like WiFi bufferbloat show up
        // here even when no notification fires).
        let rtt_ms = path.rtt.as_secs_f64() * 1000.0;
        if path.rtt > LINK_RTT_WARN || loss_rate > LINK_LOSS_WARN {
            info!(
                "Link stats: rtt={:.0}ms loss={:.1}% over the last {:?} (above warn thresholds)",
                rtt_ms,
                loss_rate * 100.0,
                LINK_SAMPLE_INTERVAL
            );
        } else {
            debug!(
                "Link stats: rtt={:.0}ms loss={:.1}% over the last {:?}",
                rtt_ms,
                loss_rate * 100.0,
                LINK_SAMPLE_INTERVAL
            );
        }
        // Adaptive fidelity: the same sample feeds the tier tracker, which
        // rewrites the bulk pacing cell on transitions (see
        // network::link_quality).
        if let Some(tier) = quality.sample(path.rtt, loss_rate) {
            let rate = crate::rotation::effective_throttle_mbps(&throttle_mode, tier);
            throttle::set_throttle(&throttle, rate);
            info!(
                "Adaptive fidelity: {} (bulk {})",
                match tier {
                    Tier::Proximity => "link measured close and clean, raising bulk throughput",
                    Tier::Normal => "link no longer close, back to the default bulk pacing",
                },
                match rate {
                    Some(mbps) => format!("{} Mbps", mbps),
                    None => "unthrottled".to_string(),
                }
            );
        }
        match monitor.check(path.rtt, loss_rate, Instant::now()) {
            LinkVerdict::Steady => {}
            LinkVerdict::Degraded => {
                episode = Some(DegradationEpisode::start_now(
                    Instant::now(),
                    path.rtt,
                    path.sent_packets,
                    path.lost_packets,
                ));
                warn!(
                    "Link degraded: rtt={:.0}ms (threshold {:?}) loss={:.1}% windowed (lifetime {}/{} lost, {} congestion events, {} black holes, cwnd {}) — a WiFi/link issue, not monux. Checklist: power save off on both machines ('iw dev <iface> get power_save'), 2.4GHz congestion (wireless peripherals, neighbors), prefer 5GHz; large clipboard transfers are already paced (--bulk-throttle-mbps).",
                    rtt_ms,
                    LINK_RTT_WARN,
                    loss_rate * 100.0,
                    path.lost_packets,
                    path.sent_packets,
                    path.congestion_events,
                    path.black_holes_detected,
                    path.cwnd
                );
                notify::notify(
                    "monux-link",
                    notify::Urgency::Normal,
                    10000,
                    "monux: link degraded",
                    &format!(
                        "Connection to the server is degraded: RTT {:.0}ms, {:.1}% packet loss. This is a WiFi/link problem, not monux — check signal strength or cabling.",
                        path.rtt.as_secs_f64() * 1000.0,
                        loss_rate * 100.0
                    ),
                );
            }
            LinkVerdict::Recovered => {
                match episode
                    .take()
                    .map(|e| e.summary(Instant::now(), path.sent_packets, path.lost_packets))
                {
                    Some(summary) => info!("Link recovered: rtt={:?} ({})", path.rtt, summary),
                    None => info!("Link recovered: rtt={:?}", path.rtt),
                }
                notify::notify(
                    "monux-link",
                    notify::Urgency::Low,
                    4000,
                    "monux: link recovered",
                    &format!(
                        "Connection to the server is healthy again (RTT {:.0}ms).",
                        path.rtt.as_secs_f64() * 1000.0
                    ),
                );
            }
        }
        // While degraded, keep the episode's peak RTT up to date for the
        // recovery summary.
        if monitor.degraded {
            if let Some(e) = &mut episode {
                e.record(path.rtt);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degradation_episode_tracks_peak_and_window_loss() {
        let t0 = Instant::now();
        let mut e = DegradationEpisode::start_now(t0, Duration::from_millis(60), 1000, 5);
        e.record(Duration::from_millis(200));
        e.record(Duration::from_millis(80));
        let s = e.summary(t0 + Duration::from_secs(47), 1900, 17);
        assert!(
            s.contains("47s") && s.contains("200ms") && s.contains("12 of 900"),
            "summary should carry duration, peak rtt and window loss: {}",
            s
        );
    }

    const REL: u16 = evdev::EventType::RELATIVE.0;
    const KEY: u16 = evdev::EventType::KEY.0;
    const REL_X: u16 = evdev::RelativeAxisCode::REL_X.0;
    const REL_Y: u16 = evdev::RelativeAxisCode::REL_Y.0;
    const REL_WHEEL: u16 = evdev::RelativeAxisCode::REL_WHEEL.0;
    const REL_HWHEEL_HI_RES: u16 = evdev::RelativeAxisCode::REL_HWHEEL_HI_RES.0;

    fn rel(code: u16, value: i32) -> event::InputEvent {
        event::InputEvent {
            inputi32: Some(event::InputI32 {
                type_: REL,
                code,
                value,
            }),
            inputf64: None,
        }
    }

    fn abs(code: u16, value: i32) -> event::InputEvent {
        event::InputEvent {
            inputi32: Some(event::InputI32 {
                type_: evdev::EventType::ABSOLUTE.0,
                code,
                value,
            }),
            inputf64: None,
        }
    }

    fn abs_scaled(code: u16, value: f64) -> event::InputEvent {
        event::InputEvent {
            inputi32: None,
            inputf64: Some(event::InputF64 {
                type_: evdev::EventType::ABSOLUTE.0,
                code,
                value,
            }),
        }
    }

    /// A touchpad frame keeps its own SYN_REPORT; mouse and keyboard frames
    /// stay coalescable. Merging absolute frames collapses a whole touch into
    /// one frame, which the compositor reads as no touch at all.
    #[test]
    fn absolute_frames_are_not_coalesced() {
        let mt_position_x = evdev::AbsoluteAxisCode::ABS_MT_POSITION_X.0;
        assert!(frame_needs_own_syn(&[abs(mt_position_x, 4338)]));
        // Scaled continuous axes travel as inputf64 and must count too.
        assert!(frame_needs_own_syn(&[abs_scaled(mt_position_x, 0.5)]));
        // A real touchpad frame: buttons alongside the absolute axes.
        assert!(frame_needs_own_syn(&[
            abs(evdev::AbsoluteAxisCode::ABS_MT_TRACKING_ID.0, -1),
            rel(REL_X, 0),
        ]));
        // Relative and key frames keep the batching that matters at 8kHz.
        assert!(!frame_needs_own_syn(&[rel(REL_X, 3), rel(REL_Y, -2)]));
        assert!(!frame_needs_own_syn(&[event::InputEvent {
            inputi32: Some(event::InputI32 {
                type_: KEY,
                code: 30,
                value: 1
            }),
            inputf64: None,
        }]));
        assert!(!frame_needs_own_syn(&[]));
    }

    /// Feeds `events` through the scaler one event at a time (per-event batches
    /// exercise the carried remainder the hardest) and returns the values that
    /// survived, in order.
    fn scaled(scaler: &mut DeltaScaler, code: u16, values: &[i32]) -> Vec<i32> {
        let mut out = Vec::new();
        for &v in values {
            let mut batch = vec![rel(code, v)];
            scaler.apply(&mut batch);
            out.extend(batch.into_iter().map(|e| e.inputi32.unwrap().value));
        }
        out
    }

    #[test]
    fn half_scale_emits_one_tick_per_two_input_ticks() {
        let mut s = DeltaScaler::new(0.5, 1.0);
        // Per-event rounding would emit ten zeros; the remainder must carry.
        assert_eq!(
            scaled(&mut s, REL_X, &[1; 10]),
            vec![1, 1, 1, 1, 1],
            "0.5x must emit exactly one tick per two input ticks"
        );
        // An odd tick leaves its half carried, not lost.
        assert_eq!(scaled(&mut s, REL_X, &[1]), Vec::<i32>::new());
        assert_eq!(scaled(&mut s, REL_X, &[1]), vec![1]);
    }

    #[test]
    fn fractional_scale_above_one() {
        let mut s = DeltaScaler::new(2.5, 1.0);
        // 2.5x alternates 2 and 3 so the average is exactly 2.5.
        assert_eq!(scaled(&mut s, REL_X, &[1, 1, 1, 1]), vec![2, 3, 2, 3]);
    }

    #[test]
    fn negative_deltas_scale_symmetrically() {
        let mut s = DeltaScaler::new(0.5, 1.0);
        // Truncation toward zero: -0.5 carries, the next -1 completes a -1 tick.
        assert_eq!(scaled(&mut s, REL_X, &[-1, -1]), vec![-1]);
        // Sign changes cancel in the remainder instead of drifting.
        assert_eq!(scaled(&mut s, REL_X, &[1, -1, 1, -1]), Vec::<i32>::new());
        assert_eq!(s.remainders[&REL_X].abs(), 0.0);
    }

    #[test]
    fn axes_accumulate_independently() {
        let mut s = DeltaScaler::new(0.5, 1.0);
        // One X tick and one Y tick: each axis carries its own half, so neither
        // emits; a second tick on either completes only that axis.
        assert_eq!(scaled(&mut s, REL_X, &[1]), Vec::<i32>::new());
        assert_eq!(scaled(&mut s, REL_Y, &[1]), Vec::<i32>::new());
        assert_eq!(scaled(&mut s, REL_Y, &[1]), vec![1]);
        assert_eq!(scaled(&mut s, REL_X, &[1]), vec![1]);
    }

    #[test]
    fn mouse_and_scroll_scales_are_independent() {
        let mut s = DeltaScaler::new(1.0, 2.0);
        // Pointer untouched at 1.0, wheel (and hi-res wheel variants) doubled.
        assert_eq!(scaled(&mut s, REL_X, &[3]), vec![3]);
        assert_eq!(scaled(&mut s, REL_WHEEL, &[1, -1]), vec![2, -2]);
        assert_eq!(scaled(&mut s, REL_HWHEEL_HI_RES, &[60]), vec![120]);
    }

    #[test]
    fn no_drift_over_thousands_of_events() {
        // 0.5x and 2.5x are exact in binary: the totals must be exact too.
        let mut s = DeltaScaler::new(0.5, 1.0);
        let emitted: i32 = scaled(&mut s, REL_X, &[1; 10_000]).iter().sum();
        assert_eq!(emitted, 5_000);
        let mut s = DeltaScaler::new(2.5, 1.0);
        let emitted: i32 = scaled(&mut s, REL_X, &[1; 10_000]).iter().sum();
        assert_eq!(emitted, 25_000);
        // An inexact scale (0.1) must neither lose motion nor drift: emitted
        // plus the still-carried remainder always equals the scaled total.
        let mut s = DeltaScaler::new(0.1, 1.0);
        let emitted: i32 = scaled(&mut s, REL_X, &[1; 10_000]).iter().sum();
        let total = emitted as f64 + s.remainders[&REL_X];
        assert!(
            (total - 1_000.0).abs() < 1e-6,
            "emitted {} + carried {} drifted from 1000",
            emitted,
            s.remainders[&REL_X]
        );
        assert!((999..=1000).contains(&emitted));
    }

    #[test]
    fn scale_one_is_a_passthrough() {
        let mut s = DeltaScaler::new(1.0, 1.0);
        assert!(!s.active());
        let mut batch = vec![rel(REL_X, 7), rel(REL_WHEEL, -1)];
        s.apply(&mut batch);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].inputi32.as_ref().unwrap().value, 7);
        assert_eq!(batch[1].inputi32.as_ref().unwrap().value, -1);
    }

    #[test]
    fn unscaled_event_kinds_pass_through_untouched() {
        let mut s = DeltaScaler::new(0.5, 0.5);
        let key = event::InputEvent {
            inputi32: Some(event::InputI32 {
                type_: KEY,
                code: 30,
                value: 1,
            }),
            inputf64: None,
        };
        let abs = event::InputEvent {
            inputi32: None,
            inputf64: Some(event::InputF64 {
                type_: evdev::EventType::ABSOLUTE.0,
                code: evdev::AbsoluteAxisCode::ABS_X.0,
                value: 0.5,
            }),
        };
        // REL_Z is a relative axis but neither pointer motion nor wheel.
        let rel_z = rel(evdev::RelativeAxisCode::REL_Z.0, 4);
        let mut batch = vec![key, abs, rel_z];
        s.apply(&mut batch);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[2].inputi32.as_ref().unwrap().value, 4);
    }

    #[test]
    fn link_monitor_thresholds() {
        let mut m = LinkMonitor::new();
        let t0 = Instant::now();
        // Good samples never notify.
        assert_eq!(m.check(Duration::from_millis(2), 0.0, t0), LinkVerdict::Steady);
        // Exactly at a threshold is not yet a warning (> not >=).
        assert_eq!(
            m.check(LINK_RTT_WARN, LINK_LOSS_WARN, t0),
            LinkVerdict::Steady
        );
        // Loss alone can degrade the link.
        assert_eq!(
            m.check(Duration::from_millis(1), LINK_LOSS_WARN + 0.01, t0),
            LinkVerdict::Degraded
        );
    }

    #[test]
    fn link_monitor_warns_once_per_degradation() {
        let mut m = LinkMonitor::new();
        let t0 = Instant::now();
        // Bad RTT: warn once.
        assert_eq!(m.check(Duration::from_millis(80), 0.0, t0), LinkVerdict::Degraded);
        // Still bad: no repeat, however long it lasts.
        assert_eq!(
            m.check(Duration::from_millis(90), 0.0, t0 + Duration::from_secs(15)),
            LinkVerdict::Steady
        );
        assert_eq!(
            m.check(Duration::from_millis(2), 0.05, t0 + Duration::from_secs(30)),
            LinkVerdict::Steady
        );
        // A recovery inside the cooldown is suppressed (retried next sample)...
        assert_eq!(
            m.check(Duration::from_millis(2), 0.0, t0 + Duration::from_secs(45)),
            LinkVerdict::Steady
        );
        // ...and reported once the cooldown has expired.
        let t1 = t0 + LINK_NOTIFY_COOLDOWN + Duration::from_secs(15);
        assert_eq!(m.check(Duration::from_millis(2), 0.0, t1), LinkVerdict::Recovered);
        // Good samples stay quiet.
        assert_eq!(
            m.check(Duration::from_millis(2), 0.0, t1 + Duration::from_secs(15)),
            LinkVerdict::Steady
        );
    }

    #[test]
    fn link_monitor_rate_limits_flapping() {
        let mut m = LinkMonitor::new();
        let t0 = Instant::now();
        assert_eq!(m.check(Duration::from_millis(80), 0.0, t0), LinkVerdict::Degraded);
        // Recovering 30s later is inside the cooldown: suppressed, and the
        // state stays "degraded" (the user still believes the link is bad).
        assert_eq!(
            m.check(Duration::from_millis(2), 0.0, t0 + Duration::from_secs(30)),
            LinkVerdict::Steady
        );
        // Bad again right after: matches the state, nothing owed.
        assert_eq!(
            m.check(Duration::from_millis(80), 0.0, t0 + Duration::from_secs(45)),
            LinkVerdict::Steady
        );
        // Once the cooldown has expired, a recovery is reported.
        let t1 = t0 + LINK_NOTIFY_COOLDOWN + Duration::from_secs(15);
        assert_eq!(m.check(Duration::from_millis(2), 0.0, t1), LinkVerdict::Recovered);
        // And a new degradation right after is again suppressed by the
        // cooldown, then reported once it expires.
        assert_eq!(
            m.check(Duration::from_millis(80), 0.0, t1 + Duration::from_secs(15)),
            LinkVerdict::Steady
        );
        let t2 = t1 + LINK_NOTIFY_COOLDOWN + Duration::from_secs(1);
        assert_eq!(m.check(Duration::from_millis(80), 0.0, t2), LinkVerdict::Degraded);
    }

    #[test]
    fn edge_inference_applies_the_opposite_edge_when_absent() {
        // No explicit --edge-map: the server's advertisement is honored.
        let mut inference = EdgeInference::new(false);
        let map = inference
            .apply(event::Direction::Right)
            .expect("inference should apply");
        assert_eq!(
            map.targets[&event::Direction::Left],
            crate::edge::EdgeTarget::Auto
        );
        assert_eq!(map.targets.len(), 1);
        // Vertical edges invert too.
        let map = inference
            .apply(event::Direction::Top)
            .expect("inference should apply");
        assert_eq!(map.targets.len(), 2);
        assert_eq!(
            map.targets[&event::Direction::Bottom],
            crate::edge::EdgeTarget::Auto
        );
    }

    #[test]
    fn edge_inference_explicit_edge_map_wins() {
        // An explicit --edge-map makes the server's advertisement moot.
        let mut inference = EdgeInference::new(true);
        assert!(inference.apply(event::Direction::Right).is_none());
        assert!(inference.map.targets.is_empty());
    }

    #[test]
    fn edge_inference_resets_per_connection() {
        // A fresh connection starts with a clean slate (Connection::new builds
        // a fresh EdgeInference), so a reconnect re-applies whatever the new
        // connection's EdgeInfo says instead of inheriting stale directions.
        let mut inference = EdgeInference::new(false);
        inference.apply(event::Direction::Right);
        let mut reconnected = EdgeInference::new(false);
        assert!(reconnected.map.targets.is_empty());
        let map = reconnected
            .apply(event::Direction::Bottom)
            .expect("inference should apply");
        assert_eq!(map.targets.len(), 1);
        assert_eq!(
            map.targets[&event::Direction::Top],
            crate::edge::EdgeTarget::Auto
        );
    }
}
