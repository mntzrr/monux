use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tokio::sync::{mpsc, watch};
use tokio::task;
use tokio::time;
use tracing::{debug, error, info, trace, warn};

use crate::clipboard::data::ClipboardData;
use crate::clipboard::server::LocalClipboard;
use crate::control;
use crate::device::{output, Event, GrabState};
use crate::msgs::{bulk, event, shared};
use crate::network::{approval, transport};
use crate::rotation;

/// Marker for a refused protocol mismatch. The refusal was already logged
/// with full context by PeerVersions, so the accept loop logs it at debug
/// instead of erroring again per retry.
#[derive(Debug)]
struct VersionMismatch;

impl std::fmt::Display for VersionMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("protocol version mismatch (already logged)")
    }
}

impl std::error::Error for VersionMismatch {}

/// How often to repeat the friendly refusal log for the same client.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// How many client handshakes may be in flight at once (see the accept loop).
const MAX_CONCURRENT_HANDSHAKES: usize = 32;

/// How many ESTABLISHED connections one approved client fingerprint may hold
/// at once (see PeerConnections). Hardening, not authentication: a legitimate
/// client holds exactly one connection (a reconnect replaces it), so a small
/// cap is far above any real need.
const MAX_CONNECTIONS_PER_PEER: usize = 4;

/// Counts established connections per client fingerprint. The handshake phase
/// is already bounded (MAX_CONCURRENT_HANDSHAKES, plus quinn's max_incoming
/// on what queues before accept), but without this an approved peer could
/// open unlimited parallel established connections — each spawning two tasks,
/// a rotation roster entry, and a bulk-writer task.
#[derive(Default)]
struct PeerConnections {
    counts: HashMap<String, usize>,
}

impl PeerConnections {
    /// Records one more established connection for `fingerprint`; None when
    /// the peer is already at MAX_CONNECTIONS_PER_PEER (the caller closes the
    /// connection instead of serving it).
    fn try_acquire(counts: &Arc<Mutex<Self>>, fingerprint: &str) -> Option<PeerConnectionSlot> {
        let mut inner = counts.lock().expect("peer connections lock poisoned");
        let count = inner.counts.entry(fingerprint.to_string()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_PEER {
            return None;
        }
        *count += 1;
        Some(PeerConnectionSlot {
            counts: Arc::clone(counts),
            fingerprint: fingerprint.to_string(),
        })
    }
}

/// One counted connection: dropping it releases the count, so every exit
/// path of the connection task frees the peer's slot.
struct PeerConnectionSlot {
    counts: Arc<Mutex<PeerConnections>>,
    fingerprint: String,
}

impl Drop for PeerConnectionSlot {
    fn drop(&mut self) {
        let mut inner = self.counts.lock().expect("peer connections lock poisoned");
        if let Some(count) = inner.counts.get_mut(&self.fingerprint) {
            *count -= 1;
            if *count == 0 {
                inner.counts.remove(&self.fingerprint);
            }
        }
    }
}

/// Tracks per-client protocol versions so a version-mismatched client reads
/// like the self-healing flow it is (it will auto-update and return), not
/// like a broken connection erroring every few seconds — and so the moment
/// it catches up is visible too. From protocol v16 on, a newer client is not
/// refused at all: the pair negotiates (shared::negotiate) and runs at our
/// version.
#[derive(Default)]
struct PeerVersions {
    /// ip -> version from the last successful exchange (for the update note).
    /// Keyed by IP, not addr:port — QUIC reconnects from a new ephemeral port,
    /// so a full SocketAddr key would never match and the upgrade note +
    /// refusal rate-limit would never fire.
    seen: HashMap<IpAddr, u64>,
    /// ip -> when we last logged a refusal for it (rate limit).
    last_refusal_log: HashMap<IpAddr, Instant>,
}

impl PeerVersions {
    /// Judges a client version from the exchange: Ok when the pair can run
    /// (exact match, or a negotiation-era client we run at our version — and
    /// a log line when the client just upgraded), Err when it must be refused
    /// (a rate-limited, self-healing-framed warning on the first/log-worthy
    /// refusal, silence otherwise).
    fn check(&mut self, addr: SocketAddr, version: u64) -> Result<(), ()> {
        let ip = addr.ip();
        let ours = shared::PROTOCOL_VERSION;
        if shared::negotiate(version, ours).is_some() {
            if let Some(old) = self.seen.insert(ip, version) {
                if old < version {
                    info!(
                        "Client {} updated protocol v{} -> v{} and reconnected",
                        addr, old, version
                    );
                }
            }
            return Ok(());
        }
        // Refuse, but keep the last seen version for the eventual upgrade note.
        self.seen.insert(ip, version);
        let should_log = self
            .last_refusal_log
            .get(&ip)
            .is_none_or(|last| last.elapsed() >= REFUSAL_LOG_INTERVAL);
        if should_log {
            self.last_refusal_log.insert(ip, Instant::now());
            // A refused client is always older than us and pre-negotiation
            // (a newer one would have negotiated above): it will auto-update
            // and reconnect.
            warn!(
                "Client {} speaks protocol v{} but we speak v{}: it's outdated and will auto-update and reconnect shortly (refusing until then)",
                addr, version, ours
            );
        }
        Err(())
    }
}

/// Everything the server events loop is wired up with: the channels it owns
/// either end of, the tuning modes, and the optional edge-map plumbing.
/// A struct rather than fourteen positional parameters — two `mpsc` halves of
/// the same type sit next to each other, and swapping them compiles.
pub struct ServerEventsLoop<O: output::OutputHandler> {
    pub config_dir: PathBuf,
    pub event_rx: mpsc::Receiver<Event>,
    pub grab_tx: watch::Sender<GrabState>,
    pub output_handler: O,
    /// Max compressed clipboard size over the wire, and the uncompressed
    /// ceiling that bounds what a decompression may produce.
    pub max_clipboard_size_bytes: u64,
    pub max_uncompressed_size_bytes: u64,
    pub rotation_tx: mpsc::Sender<rotation::RotationEvent>,
    pub rotation_rx: mpsc::Receiver<rotation::RotationEvent>,
    pub motion_mode: rotation::MotionMode,
    pub throttle_mode: rotation::ThrottleMode,
    pub mode: transport::NetworkMode,
    pub diagnostics: Arc<rotation::DiagnosticsMirror>,
    /// Both None unless --edge-map is in use.
    pub edge_client_tx: Option<watch::Sender<Vec<(SocketAddr, String)>>>,
    pub edge_map: Option<crate::edge::EdgeMap>,
}

pub async fn run_server_events_loop<O: output::OutputHandler>(
    args: ServerEventsLoop<O>,
) -> Result<()> {
    let ServerEventsLoop {
        config_dir,
        mut event_rx,
        grab_tx,
        output_handler,
        max_clipboard_size_bytes,
        max_uncompressed_size_bytes,
        rotation_tx,
        mut rotation_rx,
        motion_mode,
        throttle_mode,
        mode,
        diagnostics,
        edge_client_tx,
        edge_map,
    } = args;
    let local_clipboard = LocalClipboard::start(
        config_dir.clone(),
        rotation_tx.clone(),
        max_clipboard_size_bytes,
        max_uncompressed_size_bytes,
    ).await;

    let mut rotation = rotation::Rotation::new(rotation::RotationConfig {
        grab_tx,
        output_handler,
        local_clipboard,
        config_dir: config_dir.clone(),
        rotation_tx,
        motion_mode,
        throttle_mode,
        mode,
        diagnostics,
    })
    .await?;
    if let Some(tx) = edge_client_tx {
        rotation.set_edge_client_publisher(tx);
    }
    if let Some(map) = edge_map {
        rotation.set_edge_map(map);
    }
    // Input-flow heartbeat: makes "user is typing but nothing arrives anywhere"
    // visible in the log, instead of silent (the dead-Enter investigations).
    let mut status_tick = time::interval(Duration::from_secs(10));
    // Skip the immediate first tick; the first heartbeat lands 10s in.
    status_tick.tick().await;
    // App-level liveness check (see ServerEvent::Ping): pings the current
    // client so a black-holed link ungrabs within ~6s instead of silently
    // swallowing input until the QUIC idle timeout fires.
    let mut ping_tick = time::interval(rotation::PING_INTERVAL);
    // Skip the immediate first tick; the first ping lands one interval in.
    ping_tick.tick().await;
    // Delay (not the default Burst): after the loop was blocked, don't fire
    // catch-up pings back to back — ping_tick's own stall guard handles the
    // late tick, and a burst would only multiply the load on a busy loop.
    ping_tick.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    // Pointer-motion coalescing flush timer (office mode, see --motion-hz).
    // The branch guard keeps it inert until motion has accumulated; after a
    // long idle the first tick fires immediately, so the first delta goes out
    // without added delay and only sustained streams are coalesced. In
    // Adaptive mode the interval is rebuilt whenever the current client's
    // measured link tier changes (see the quality tick below).
    let mut motion_tick = time::interval(
        rotation
            .motion_flush_interval()
            .unwrap_or(Duration::from_secs(3600)),
    );
    // The tick is only polled while motion is pending, so after an idle stretch
    // many periods count as "missed". Delay (not the default Burst) skips the
    // catch-up: one immediate flush after idle, then one per interval. With
    // Burst, the backlog of catch-up ticks would fire on every frame and
    // silently defeat the coalescing.
    motion_tick.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    // Adaptive-fidelity sampler (see network::link_quality): re-tunes the
    // per-client bulk pacing cells and, through the motion-tick rebuild in its
    // select arm, the coalescing rate for the current client's measured tier.
    let mut quality_tick = time::interval(crate::network::link_quality::SAMPLE_INTERVAL);
    // Skip the immediate first tick; let connections settle first.
    quality_tick.tick().await;
    // Seed the diagnostics mirror so a SIGHUP before the first event still dumps.
    rotation.update_diagnostics();
    loop {
        // Snapshot per iteration (Copy, so no borrow of rotation crosses the
        // select): the trailing edge of the local clipboard debounce window,
        // if an update is currently held (see CLIPBOARD_UPDATE_DEBOUNCE).
        let clipboard_debounce_deadline = rotation.pending_local_clipboard_deadline();
        tokio::select! {
            // Listen and forward rotation events to rotation
            event = rotation_rx.recv() => {
                let event = match event {
                    Some(e) => e,
                    None => bail!("rotation_rx is closed, exiting server"),
                };
                rotation.accept(event).await;
            },
            // Listen to local system device input events
            event = event_rx.recv() => {
                let event = match event {
                    Some(e) => e,
                    None => bail!("event_rx is closed, exiting server"),
                };
                match event {
                    Event::Input(batch) => {
                        if let Err(e) = rotation.send_input_events(batch).await {
                            warn!("Failed to send input events to current client: {:?}", e);
                        }
                    }
                    Event::SwitchNext => {
                        rotation.next_client().await;
                    }
                    Event::SwitchPrev => {
                        rotation.prev_client().await;
                    }
                    Event::SwitchTo(fingerprint) => {
                        rotation.set_client(fingerprint).await;
                    }
                    Event::PauseToggle => {
                        rotation.toggle_pause("pause chord").await;
                    }
                    Event::SetPaused(paused) => {
                        rotation.set_paused(paused, "control socket").await;
                    }
                }
            },
            _ = status_tick.tick() => {
                rotation.log_input_status();
                // Prune fetch bookkeeping whose requester already gave up, so
                // dead entries don't linger until the next request arrives.
                rotation.prune_pending_clipboard_requests();
            },
            _ = ping_tick.tick() => {
                rotation.ping_tick().await;
            },
            _ = quality_tick.tick() => {
                if rotation.sample_link_quality() {
                    // The current client's tier changed: rebuild the motion
                    // flush tick at the new rate (Adaptive mode; pinned
                    // --motion-hz reports the same interval back, so the
                    // rebuild is a no-op there).
                    motion_tick = time::interval(
                        rotation
                            .motion_flush_interval()
                            .unwrap_or(Duration::from_secs(3600)),
                    );
                    motion_tick.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
                }
            },
            _ = motion_tick.tick(), if rotation.motion_dirty() => {
                rotation.flush_pending_motion().await;
            },
            // Trailing edge of the local clipboard debounce: apply the newest
            // update held during the window. Pends forever when nothing is held.
            _ = async {
                match clipboard_debounce_deadline {
                    Some(deadline) => time::sleep_until(time::Instant::from_std(deadline)).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                rotation.flush_pending_local_clipboard().await;
            },
        }
        // Refresh the mirrored state after every iteration: the SIGHUP handler
        // reads it directly from the signal thread, so the dump must not
        // depend on this loop being alive. The call itself rate-limits the
        // actual refresh to ~10Hz (see Rotation::update_diagnostics).
        rotation.update_diagnostics();
    }
}

/// A previous instance releases the single-instance lock before its endpoint
/// socket finishes closing (teardown ordering), so a takeover can arrive
/// while the port is still draining: retry briefly on EADDRINUSE instead of
/// dying (seen in the wild when a manual start took over from an auto-update
/// restart).
async fn bind_server_with_retry(
    listen_addr: &SocketAddr,
    cert_verifier: Arc<approval::MonuxCertVerification<'static>>,
    mode: transport::NetworkMode,
) -> Result<quinn::Endpoint> {
    const MAX_RETRIES: u32 = 10;
    let mut attempt = 0u32;
    loop {
        match transport::build_server(listen_addr, cert_verifier.clone(), mode) {
            Ok(endpoint) => return Ok(endpoint),
            Err(e) if is_addr_in_use(&e) && attempt < MAX_RETRIES => {
                attempt += 1;
                info!(
                    "Port {} is still held (previous instance finishing teardown?), retrying bind in 500ms (attempt {}/{})",
                    listen_addr.port(),
                    attempt,
                    MAX_RETRIES
                );
                time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e).context("Failed to set up server endpoint"),
        }
    }
}

/// Whether the error chain contains an EADDRINUSE io error.
fn is_addr_in_use(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.raw_os_error() == Some(libc::EADDRINUSE))
    })
}

/// Shared slot through which the connections loop publishes its QUIC
/// endpoint once bound, so the shutdown path (main.rs close_loops) can close
/// it gracefully: quinn sends no close frames when the endpoint is merely
/// dropped, which would leave every client waiting out its idle timeout.
pub type SharedEndpoint = Arc<Mutex<Option<quinn::Endpoint>>>;

pub async fn run_server_connections_loop(
    listen_addr: &SocketAddr,
    cert_verifier: Arc<approval::MonuxCertVerification<'static>>,
    max_clipboard_size_bytes: u64,
    rotation_tx: mpsc::Sender<rotation::RotationEvent>,
    mode: transport::NetworkMode,
    endpoint_slot: SharedEndpoint,
) -> Result<()> {
    let server_endpoint = bind_server_with_retry(listen_addr, cert_verifier.clone(), mode).await?;
    // Publish the endpoint for the shutdown path (see SharedEndpoint).
    *endpoint_slot
        .lock()
        .expect("server endpoint slot lock poisoned") = Some(server_endpoint.clone());
    // Protocol-version tracker: turns refusal spam into the self-healing
    // story (outdated client auto-updating) and notes when it catches up.
    let peer_versions = Arc::new(Mutex::new(PeerVersions::default()));
    // Per-fingerprint count of established connections (see
    // MAX_CONNECTIONS_PER_PEER): bounds what an approved peer can pile up.
    let peer_connections = Arc::new(Mutex::new(PeerConnections::default()));
    // How long a single connection handshake may take before it is dropped.
    // Local mode is generous (an approval-pending peer retries anyway);
    // Www mode never prompts, so it can be much stricter. The interactive
    // approval prompt never runs inside the handshake (approval.rs).
    let handshake_timeout = match mode {
        transport::NetworkMode::Local => Duration::from_secs(75),
        transport::NetworkMode::Www => Duration::from_secs(15),
    };
    // Bound on handshakes running at once. Each accepted attempt spawns a task
    // that holds a Connecting for up to handshake_timeout (75s in Local mode),
    // all of it before the peer has authenticated — so without this, anyone who
    // can reach the port can make the server accumulate tasks and per-connection
    // state at will. quinn's max_incoming (transport.rs) bounds only what it
    // holds BEFORE we accept, and we accept immediately, so this side is the one
    // that actually bounds handshakes.
    //
    // A permit is taken before accepting, so backpressure reaches quinn's own
    // queue instead of the accept loop spinning; it is released when the
    // handshake resolves, times out, or fails. The ceiling is far above any
    // real rotation, so a legitimate client is never made to wait.
    let handshake_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HANDSHAKES));
    // Task launcher for new client connections
    // Monotonic token tagging each accepted connection: a reconnect can reuse
    // the same addr:port, and the token lets the rotation tell a late removal
    // from the old (dead) connection apart from the healthy new entry.
    let mut next_conn_token: u64 = 1;
    loop {
        // Claim a handshake slot BEFORE accepting: while every slot is busy,
        // attempts queue in quinn (bounded by max_incoming) rather than piling
        // up as tasks here. The semaphore is never closed, so acquire only
        // fails if it were, which cannot happen.
        let handshake_permit = match Arc::clone(&handshake_slots).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => bail!("Handshake semaphore closed, exiting server"),
        };
        let conn = server_endpoint.accept().await;
        let conn = match conn {
            Some(c) => c,
            None => bail!("Server endpoint is closed, exiting server"),
        };
        let conn_token = next_conn_token;
        next_conn_token += 1;
        let remote_addr = conn.remote_address();
        // Let the approval prompt name who is connecting (approval.rs); the
        // address is unauthenticated transport info, like the client side's.
        cert_verifier.record_incoming_attempt(remote_addr);
        if mode == transport::NetworkMode::Www && !conn.remote_address_validated() {
            // On the public internet, require the client to validate its source
            // address via a QUIC retry packet before we spend resources on a
            // TLS handshake (spoofed-source amplification/DoS mitigation).
            // The client will come back with a validated address.
            if let Err(e) = conn.retry() {
                error!("Failed to request address validation from {}: {}", remote_addr, e);
            }
            continue;
        }
        let connecting = match conn.accept() {
            Ok(connecting) => connecting,
            Err(e) => {
                error!("Client failed to connect: {}", e);
                continue;
            }
        };
        let rotation_tx_cpy = rotation_tx.clone();
        let peer_versions_cpy = peer_versions.clone();
        let peer_connections_cpy = peer_connections.clone();
        // Complete the handshake in a spawned task so that a slow or stuck peer
        // cannot block the accept loop for other clients. The connection task
        // is only spawned once the client's fingerprint is known: AddClient
        // carries it (rotation.rs).
        task::spawn(async move {
            // handshake_permit is moved into this task by the drop() below and
            // held for the handshake only: the slot bounds connections being
            // ESTABLISHED, not established ones, so a full rotation of
            // long-lived clients never starves pairing. Every early return
            // here (handshake error, timeout, missing certificate) releases it
            // at scope exit.
            let conn = match tokio::time::timeout(handshake_timeout, connecting).await {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    // An unapproved cert rejects instantly and the peer
                    // retries every few seconds until the prompt is answered
                    // (approval.rs): that's a normal pairing flow, not an
                    // error storm.
                    if is_approval_pending(&e) {
                        info!("Client failed to connect: {}", e);
                    } else {
                        error!("Client failed to connect: {}", e);
                    }
                    return;
                }
                Err(_) => {
                    warn!(
                        "Dropping connection from {}: handshake timed out after {}s",
                        remote_addr,
                        handshake_timeout.as_secs()
                    );
                    return;
                }
            };
            // The client's cert fingerprint, derived from the established
            // connection itself (quinn's peer_identity yields the verified
            // chain): each connection is paired with its own fingerprint, so
            // simultaneous reconnects can't mix them up (the old global
            // fingerprint slot in approval.rs could).
            let fingerprint = match approval::connection_peer_fingerprint(&conn) {
                Some(fingerprint) => fingerprint,
                None => {
                    // The cert verifier demands a client cert, so an
                    // established connection always has one; drop so the
                    // client retries rather than running unidentifiable.
                    warn!("BUG: No peer certificate on the established connection from {}, dropping connection so that client can retry", remote_addr);
                    return;
                }
            };
            debug!("Got fingerprint: {}", fingerprint);
            // Bound established connections per client fingerprint (see
            // MAX_CONNECTIONS_PER_PEER): the handshake semaphore bounds only
            // connections BEING established, so without this an approved peer
            // could accumulate unlimited served connections. On refusal the
            // connection is dropped here, closing it so the client retries
            // rather than running unserved.
            let conn_slot = match PeerConnections::try_acquire(&peer_connections_cpy, &fingerprint) {
                Some(slot) => slot,
                None => {
                    warn!(
                        "Client {} ({}) already has {} established connections, closing this extra one",
                        remote_addr, fingerprint, MAX_CONNECTIONS_PER_PEER
                    );
                    return;
                }
            };
            // The handshake is done; free the slot before the connection task,
            // which lives as long as the client stays connected.
            drop(handshake_permit);
            task::spawn(async move {
                // Kept until this task ends, so the peer's connection count is
                // released on every exit path.
                let _conn_slot = conn_slot;
                let result = handle_connection(conn, fingerprint, rotation_tx_cpy.clone(), max_clipboard_size_bytes, conn_token, peer_versions_cpy).await;
                // Remove the client from the rotation on EVERY exit path,
                // graceful (QUIC application close) included — an Ok return
                // used to leave a phantom entry in the rotation. Removal is
                // idempotent there: a duplicate (e.g. the bulk writer already
                // dropped this client) finds no entry, and the token lets the
                // rotation ignore this removal if the endpoint was since
                // reused by a newer connection.
                if let Err(e) = rotation_tx_cpy
                    .send(rotation::RotationEvent::RemoveClient {
                        endpoint: remote_addr,
                        conn_token,
                    })
                    .await {
                        error!("Failed to send remove client event: {:?}", e);
                    };
                if let Err(e) = result {
                    if e.downcast_ref::<VersionMismatch>().is_some() {
                        // Already logged with full context by the
                        // version check; don't error per retry.
                        debug!("Refused client connection from {}: protocol mismatch", remote_addr);
                    } else {
                        error!("Client connection error: {:?}", e);
                    }
                }
            });
        });
    }
}

/// Whether a connection failure is just an unapproved certificate: the
/// verifier rejects instantly and the peer retries automatically until the
/// console prompt is answered (see approval.rs), so these are expected during
/// pairing and log at info level.
///
/// Matched on a stable sentinel rather than on the prose of the messages —
/// rustls flattens the verifier error to a string, so text is the only
/// channel, but the text that carries meaning should be the part nobody
/// rewords casually (see APPROVAL_PENDING_SENTINEL).
fn is_approval_pending(e: impl std::fmt::Display) -> bool {
    e.to_string().contains(approval::APPROVAL_PENDING_SENTINEL)
}

async fn handle_connection(
    conn: quinn::Connection,
    fingerprint: String,
    rotation_tx: mpsc::Sender<rotation::RotationEvent>,
    max_clipboard_size_bytes: u64,
    conn_token: u64,
    peer_versions: Arc<Mutex<PeerVersions>>,
) -> Result<()> {
    let (mut events_send, mut events_recv) = conn
        .accept_bi()
        .await
        .context("Failed to initialize events stream")?;

    // Receive version from client and close the connection if it's not supported.
    // Future versions could follow the version message with more data. We ignore/discard it here.
    let mut event_bytes = Vec::with_capacity(1024);
    let client_version = transport::recv_version(&mut events_recv, &mut event_bytes).await?;
    // Reply with our own version BEFORE rejecting a mismatch, so that the
    // client learns it (its update gate needs it to catch up after we upgrade).
    transport::send_version(&mut events_send, shared::PROTOCOL_VERSION).await?;
    // Judge the client's version with context (an upgrade note on success, a
    // friendly rate-limited refusal otherwise) before the hard gate. The
    // server is the acceptor: it cannot retry or clamp, so a client too old
    // to negotiate is refused exactly as before negotiation existed.
    if peer_versions
        .lock()
        .expect("peer versions lock poisoned")
        .check(conn.remote_address(), client_version)
        .is_err()
    {
        return Err(VersionMismatch.into());
    }
    // check() accepted, so the pair is compatible by definition of
    // negotiate(). From v16 on a newer client runs at OUR version.
    let negotiated = match shared::negotiate(client_version, shared::PROTOCOL_VERSION) {
        Some(negotiated) => negotiated,
        None => return Err(VersionMismatch.into()),
    };
    if negotiated < shared::PROTOCOL_VERSION {
        info!(
            "Client {} speaks protocol v{}, we speak v{}: running at v{} (disabled: {})",
            conn.remote_address(),
            client_version,
            shared::PROTOCOL_VERSION,
            negotiated,
            shared::disabled_features(negotiated)
        );
    }

    // Tell the client our hostname right after the version exchange
    // (length-prefixed). Direct-IP connects get the same display name as
    // mDNS-discovered ones (approval prompt), and the client can remember us
    // by name (known_servers.rs). Unconditional since 13.0.0: the frame rode
    // a v15 gate, and v16 is the floor now.
    let hostname = crate::discovery::get_hostname().unwrap_or_default();
    events_send
        .write_all(&shared::encode_hostname(&hostname))
        .await
        .context("Failed to send our hostname")?;

    // Start second stream for bulk messages
    let (mut bulk_send, mut bulk_recv) = conn
        .accept_bi()
        .await
        .context("Failed to initialize bulk stream")?;
    // Clipboard bulk yields to the events stream (priority 0) when the
    // connection is congested, so a big transfer can't starve input.
    let _ = bulk_send.set_priority(-1);

    // Receive the version a second time, on the bulk stream.
    // Sending some data is required to initialize the bulk stream, so let's just repeat ourselves.
    // Maybe we'll want to have different per-stream versions someday? Probably not.
    // The exchange gets its own scratch buffer: reusing event_bytes would
    // parse any leftover events-stream bytes as the bulk version if either
    // side ever pipelines data behind the version frame.
    let mut bulk_handshake_bytes = Vec::with_capacity(1024);
    let bulk_client_version = transport::recv_version(&mut bulk_recv, &mut bulk_handshake_bytes).await?;
    transport::send_version(&mut bulk_send, shared::PROTOCOL_VERSION).await?;
    // Same peer as the events stream, whose version was already judged there
    // (PeerVersions + negotiate): it must speak the same version here.
    if bulk_client_version != client_version {
        bail!(
            "Client {} spoke protocol v{} on the events stream but v{} on the bulk stream",
            conn.remote_address(),
            client_version,
            bulk_client_version
        );
    }

    // Add client to the rotation after a successful init
    rotation_tx
        .send(rotation::RotationEvent::AddClient(
            rotation::AddClientArgs {
                endpoint: conn.remote_address(),
                fingerprint,
                events_send,
                bulk_send,
                conn: conn.clone(),
                conn_token,
                negotiated_version: negotiated,
            },
        ))
        .await?;

    let mut bulk_bytes = Vec::with_capacity(65536);
    // The partially-received clipboard payload and the request id it answers.
    // The requester is NOT carried here: it is looked up from what the rotation
    // recorded when it sent the fetch, never from what the peer claims.
    let mut incoming_clipboard_data: Option<(ClipboardData, u64)> = None;
    loop {
        tokio::select! {
            event_result = events_recv.read_chunk(16384, true) => {
                let resp = match event_result {
                    Ok(chunk) => chunk.context("Client closed events connection")?,
                    Err(quinn::ReadError::ConnectionLost(quinn::ConnectionError::ApplicationClosed(_))) => {
                        // A deliberate close (the client's, or our own
                        // graceful shutdown), not an error worth logging.
                        debug!("Client {} closed events connection", conn.remote_address());
                        return Ok(());
                    }
                    Err(e) => {
                        transport::log_conn_stats(&conn);
                        Err(e).context("Lost client events connection")?
                    }
                };
                trace!("Received {} bytes from events stream: {:X?}", resp.bytes.len(), &*resp.bytes);
                // Anything received from the client is proof of liveness (see
                // ServerEvent::Ping): reported per chunk, so raw clipboard
                // payload counts too — a large upload taking >6s must not
                // look like a silent client.
                rotation_tx
                    .send(rotation::RotationEvent::ClientHeardFrom {
                        endpoint: conn.remote_address(),
                    })
                    .await?;
                // Copy the immutable response data into a mutable buffer
                event_bytes.extend_from_slice(&resp.bytes);
                if event_bytes.len() > shared::MAX_FRAME_BUFFER_BYTES {
                    bail!("Client {} sent an oversized events frame ({} bytes without a COBS terminator)", conn.remote_address(), event_bytes.len());
                }
                handle_event_messages(conn.remote_address(), &rotation_tx, &mut event_bytes, max_clipboard_size_bytes).await?;
            },
            bulk_result = bulk_recv.read_chunk(65536, true) => {
                let resp = match bulk_result {
                    Ok(chunk) => chunk.context("Client closed bulk connection")?,
                    Err(quinn::ReadError::ConnectionLost(quinn::ConnectionError::ApplicationClosed(_))) => {
                        debug!("Client {} closed bulk connection", conn.remote_address());
                        return Ok(());
                    }
                    Err(e) => {
                        transport::log_conn_stats(&conn);
                        Err(e).context("Lost client bulk connection")?
                    }
                };
                trace!("Received {} bytes from bulk stream: {:X?}", resp.bytes.len(), &*resp.bytes);
                // Proof of liveness, same as the events stream above.
                rotation_tx
                    .send(rotation::RotationEvent::ClientHeardFrom {
                        endpoint: conn.remote_address(),
                    })
                    .await?;
                if let Some((c, request_id)) = &mut incoming_clipboard_data {
                    if c.remaining_bytes >= resp.bytes.len() {
                        // Chunk is all clipboard data.
                        c.bytes.extend_from_slice(&resp.bytes);
                        c.remaining_bytes -= resp.bytes.len();
                    } else {
                        // Chunk contains additional data past the clipboard entry.
                        c.bytes.extend_from_slice(&(*resp.bytes)[..c.remaining_bytes]);
                        bulk_bytes.extend_from_slice(&(*resp.bytes)[c.remaining_bytes..]);
                        c.remaining_bytes = 0;
                    }

                    if c.remaining_bytes == 0 {
                        // Streamed clipboard data is all accumulated, flush and clear
                        rotation_tx.send(rotation::RotationEvent::ClipboardSendContent(rotation::ClipboardSendContentArgs{
                            data_source: conn.remote_address(),
                            request_id: *request_id,
                            data: incoming_clipboard_data.take().unwrap().0
                        })).await?;
                    }

                    if !bulk_bytes.is_empty() {
                        // Handle any data following the clipboard entry.
                        incoming_clipboard_data = handle_bulk_messages(conn.remote_address(), &rotation_tx, &mut bulk_bytes, max_clipboard_size_bytes).await?;
                    }
                } else {
                    // Copy the immutable response data into a mutable buffer
                    bulk_bytes.extend_from_slice(&resp.bytes);
                    if bulk_bytes.len() > shared::MAX_FRAME_BUFFER_BYTES {
                        bail!("Client {} sent an oversized bulk frame ({} bytes without a COBS terminator)", conn.remote_address(), bulk_bytes.len());
                    }
                    incoming_clipboard_data = handle_bulk_messages(conn.remote_address(), &rotation_tx, &mut bulk_bytes, max_clipboard_size_bytes).await?;
                }
            },
        }
    }
}

async fn handle_event_messages(
    source: SocketAddr,
    rotation_tx: &mpsc::Sender<rotation::RotationEvent>,
    bytes: &mut Vec<u8>,
    max_clipboard_size_bytes: u64,
) -> Result<()> {
    let mut offset = 0;
    let bytes_len = bytes.len();
    while offset < bytes_len {
        // A partial frame (no COBS terminator yet) is kept for the next chunk.
        if !shared::has_complete_cobs_frame(&bytes[offset..]) {
            break;
        }
        let (msg, resp_remainder) = match postcard::take_from_bytes_cobs::<event::ClientEvent>(
            &mut bytes[offset..],
        ) {
            Ok(parsed) => parsed,
            // The buffer is only copied (into this message) on the error
            // path, not for every successfully parsed message.
            Err(e) => bail!(
                "Failed to deserialize client message: {:?} bytes(off={})={:X?}",
                e,
                offset,
                bytes
            ),
        };
        let consumed = bytes_len - resp_remainder.len() - offset;
        trace!(
            "Consumed event at offset={}: {} ({} bytes)",
            offset,
            msg,
            consumed
        );
        match msg {
            event::ClientEvent::Pong => {
                // Answer to the server's Ping (see ServerEvent::Ping). The
                // liveness bookkeeping already happened per-chunk in
                // handle_connection (ClientHeardFrom); nothing else to do.
                trace!("Got pong from client {}", source);
            }
            event::ClientEvent::SwitchRequest { .. } => {
                // Client-initiated return to the local machine (screen-edge
                // detection on the client). y_fraction is reserved for future
                // cursor warping and ignored for now; the rotation honors the
                // request only when this client is the current one.
                debug!("Got switch request from client {}", source);
                rotation_tx
                    .send(rotation::RotationEvent::SwitchRequest { endpoint: source })
                    .await?;
            }
            event::ClientEvent::ClipboardTypes(t) => {
                // Client broadcasted new clipboard types for server (and other clients) to advertise.
                // An empty types string (the client's clipboard was cleared) splits
                // to no types — a phantom "" type must never reach the rotation.
                let types: Vec<String> = t.types_vec();
                debug!("Got clipboard type advertisement from client {}: {:?}", source, types);
                rotation_tx
                    .send(rotation::RotationEvent::ClipboardUpdateSource(
                        rotation::ClipboardUpdateSourceArgs {
                            source: Some(source),
                            types,
                            // Advertise min(advertising client max, server max)
                            max_size_bytes: std::cmp::min(
                                t.max_size_bytes,
                                max_clipboard_size_bytes,
                            ),
                        },
                    ))
                    .await?;
            }
        }
        offset += consumed;
    }
    // Retain any unconsumed partial frame for the next chunk.
    bytes.drain(..offset);
    Ok(())
}

/// Largest capacity a peer-declared content length may reserve up front. The
/// length is already bounded by max_clipboard_size_bytes, but that bound is
/// what an honest peer needs, not what a header alone should be able to
/// commit: allocating it before any payload arrives turns a tiny frame into
/// megabytes of resident memory per connection. Past this, the buffer just
/// grows as chunks land.
pub(crate) const MAX_PAYLOAD_CAPACITY_HINT: usize = 256 * 1024;

/// The capacity to pre-reserve for an announced clipboard payload (see
/// MAX_PAYLOAD_CAPACITY_HINT). Shared with the client's bulk reader, which
/// makes the identical reservation from a server-declared length.
pub(crate) fn payload_capacity_hint(content_len_bytes: u64) -> usize {
    content_len_bytes.min(MAX_PAYLOAD_CAPACITY_HINT as u64) as usize
}

async fn handle_bulk_messages(
    source: SocketAddr,
    rotation_tx: &mpsc::Sender<rotation::RotationEvent>,
    bytes: &mut Vec<u8>,
    max_clipboard_size_bytes: u64,
) -> Result<Option<(ClipboardData, u64)>> {
    let mut offset = 0;
    let bytes_len = bytes.len();
    while offset < bytes_len {
        // A partial frame (no COBS terminator yet) is kept for the next chunk.
        if !shared::has_complete_cobs_frame(&bytes[offset..]) {
            break;
        }
        let (msg, resp_remainder) =
            postcard::take_from_bytes_cobs::<bulk::ClientBulk>(&mut bytes[offset..])
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
            bulk::ClientBulk::ClipboardRequest(c) => {
                // Forward the request to rotation, which tracks where to get it from.
                rotation_tx
                    .send(rotation::RotationEvent::ClipboardRequestContent(
                        rotation::ClipboardRequestContentArgs {
                            request_source: rotation::ClipboardRequestSource::Remote(source),
                            requested_type: c.requested_type.to_string(),
                            // Advertise min(advertising client max, server max)
                            max_size_bytes: std::cmp::min(
                                c.max_size_bytes,
                                max_clipboard_size_bytes,
                            ),
                            request_id: Some(c.request_id),
                        },
                    ))
                    .await?;
            }
            bulk::ClientBulk::DiagnosticsResponse(d) => {
                // Hand the answer to whichever control-socket task is waiting
                // on this id (see control::PeerDiagnosticsHub). A malformed
                // or declined bundle is recorded as this peer's failure, not
                // treated as a protocol violation: a bug report must never
                // cost the user their connection.
                let reply = match (d.json, d.error) {
                    (Some(json), _) => serde_json::from_str::<control::Diagnostics>(json)
                        .map_err(|e| format!("sent a bundle that could not be parsed: {}", e)),
                    (None, Some(error)) => Err(error.to_string()),
                    (None, None) => Err("sent an empty response".to_string()),
                };
                control::peer_diagnostics_hub().complete(source, d.request_id, reply);
            }
            bulk::ClientBulk::ClipboardHeader(c) => {
                if c.content_len_bytes > max_clipboard_size_bytes {
                    // The content length from the client is bigger than what we advertised.
                    // Reset the client connection since this shouldn't happen to begin with.
                    bail!(
                        "Received clipboard size {} exceeds max size {}, resetting connection",
                        c.content_len_bytes,
                        max_clipboard_size_bytes
                    );
                } else if c.content_len_bytes as usize <= resp_remainder.len() {
                    // The clipboard content fits fully within resp_remainder.
                    // Mark content as consumed and continue looping in case another message follows.
                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(&resp_remainder[..c.content_len_bytes as usize]);
                    rotation_tx
                        .send(rotation::RotationEvent::ClipboardSendContent(
                            rotation::ClipboardSendContentArgs {
                                data_source: source,
                                request_id: c.request_id,
                                data: ClipboardData {
                                    requested_type: c.requested_type.to_string(),
                                    data_type: c.data_type.map(|t| t.to_string()),
                                    bytes,
                                    remaining_bytes: 0,
                                },
                            },
                        ))
                        .await?;
                    offset += c.content_len_bytes as usize;
                } else {
                    // Need to collect more data.
                    // Save what we've got so far, and assign remaining_bytes to what's left.
                    // The capacity hint is CAPPED rather than taken from the
                    // header: content_len_bytes is a peer-declared number, so
                    // reserving it up front lets a ~40-byte header commit the
                    // whole max clipboard size per connection before a single
                    // payload byte arrives. Growth from here follows bytes
                    // actually received, which costs nothing next to the
                    // network time.
                    let mut payload =
                        Vec::with_capacity(payload_capacity_hint(c.content_len_bytes));
                    payload.extend_from_slice(resp_remainder);
                    let d = (
                        ClipboardData {
                            requested_type: c.requested_type.to_string(),
                            data_type: c.data_type.map(|t| t.to_string()),
                            bytes: payload,
                            remaining_bytes: c.content_len_bytes as usize - resp_remainder.len(),
                        },
                        c.request_id,
                    );
                    // All bytes were consumed (into the pending clipboard data).
                    bytes.clear();
                    return Ok(Some(d));
                }
            }
        }
    }
    // Retain any unconsumed partial frame for the next chunk.
    bytes.drain(..offset);
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    /// A version that is genuinely refused, for the refusal paths below.
    /// PROTOCOL_VERSION - 1 no longer qualifies: from v16 on, versions
    /// negotiate, so the version right below ours is accepted and the pair
    /// simply runs degraded. Only a pre-negotiation version is refused.
    const REFUSED_VERSION: u64 = shared::PROTOCOL_VERSION_NEGOTIATION - 2;

    #[test]
    fn matching_version_passes_and_records() {
        let mut pv = PeerVersions::default();
        assert!(pv.check(addr(), shared::PROTOCOL_VERSION).is_ok());
        assert!(pv.check(addr(), shared::PROTOCOL_VERSION).is_ok());
    }

    #[test]
    fn older_version_refuses_with_rate_limited_log() {
        let mut pv = PeerVersions::default();
        let old = REFUSED_VERSION;
        assert!(pv.check(addr(), old).is_err());
        assert!(pv.last_refusal_log.contains_key(&addr().ip()));
        // A second refusal inside the window is not logged again.
        let first = *pv.last_refusal_log.get(&addr().ip()).unwrap();
        assert!(pv.check(addr(), old).is_err());
        assert_eq!(*pv.last_refusal_log.get(&addr().ip()).unwrap(), first);
        // After the window passes, it logs again (new timestamp).
        *pv.last_refusal_log.get_mut(&addr().ip()).unwrap() =
            Instant::now() - REFUSAL_LOG_INTERVAL - Duration::from_secs(1);
        assert!(pv.check(addr(), old).is_err());
        assert_ne!(*pv.last_refusal_log.get(&addr().ip()).unwrap(), first);
    }

    #[test]
    fn newer_negotiation_era_version_is_accepted() {
        // From v16 on, a newer client is not refused: the pair negotiates
        // (shared::negotiate) and runs at OUR version.
        let mut pv = PeerVersions::default();
        assert!(pv.check(addr(), shared::PROTOCOL_VERSION + 1).is_ok());
        assert_eq!(
            pv.seen.get(&addr().ip()),
            Some(&(shared::PROTOCOL_VERSION + 1))
        );
    }

    #[test]
    fn upgrade_is_noted_on_reconnect() {
        let mut pv = PeerVersions::default();
        let old = REFUSED_VERSION;
        // Refused while old, then comes back matching: the upgrade note fires.
        assert!(pv.check(addr(), old).is_err());
        assert!(pv.check(addr(), shared::PROTOCOL_VERSION).is_ok());
        // No note when nothing changed since the last seen version.
        assert!(pv.check(addr(), shared::PROTOCOL_VERSION).is_ok());
        assert_eq!(pv.seen.get(&addr().ip()), Some(&shared::PROTOCOL_VERSION));
    }

    #[test]
    fn ephemeral_port_reconnect_matches_same_ip() {
        let mut pv = PeerVersions::default();
        let old = REFUSED_VERSION;
        // Refuse from port A.
        let port_a: SocketAddr = "10.0.0.1:50000".parse().unwrap();
        assert!(pv.check(port_a, old).is_err());
        // Reconnect from a different ephemeral port (same IP): the refusal
        // rate-limit and the seen-version map must recognize the same peer.
        let port_b: SocketAddr = "10.0.0.1:50001".parse().unwrap();
        assert!(pv.check(port_b, old).is_err());
        assert_eq!(pv.last_refusal_log.len(), 1); // keyed by IP, not addr:port
    }

    #[test]
    fn peer_connections_cap_at_the_limit_and_release_on_drop() {
        let counts = Arc::new(Mutex::new(PeerConnections::default()));
        let slots: Vec<PeerConnectionSlot> = (0..MAX_CONNECTIONS_PER_PEER)
            .map(|_| {
                PeerConnections::try_acquire(&counts, "fp").expect("below the cap must acquire")
            })
            .collect();
        // At the cap: further connections from this peer are refused...
        assert!(PeerConnections::try_acquire(&counts, "fp").is_none());
        // ...without affecting any other peer.
        assert!(PeerConnections::try_acquire(&counts, "other").is_some());
        // Dropping the slots releases the count (every connection-task exit
        // path), and empty entries don't linger in the map.
        drop(slots);
        assert!(PeerConnections::try_acquire(&counts, "fp").is_some());
        assert!(counts.lock().unwrap().counts.is_empty());
    }
}
