//! Server-side screen-edge switching (opt-in via --edge-map): when the local
//! cursor is pushed against a configured screen edge and dwells there, input
//! switches to the client mapped to that edge — the classic "screen-edge KVM"
//! behavior. The switch itself reuses the existing rotation path
//! (Event::SwitchTo → Rotation::set_client), so debounce/pause/no-op cleanup
//! all apply for free; there is no protocol change.
//!
//! Detection is event-driven, zero polling of the pointer position: for every
//! EXPOSED segment of a mapped edge (see exposed_segments) a 1px-wide,
//! fully transparent wlr-layer-shell strip is placed at the very screen edge
//! (overlay layer, exclusive zone -1 so bars/panels don't displace it). The
//! compositor then delivers pointer Enter/Leave events as the cursor is
//! pushed into/away from the edge. An enter starts a dwell timer
//! (--edge-dwell-ms); a leave before the deadline cancels it; a completed
//! dwell fires the switch once and a short re-arm cooldown prevents
//! machine-gunning. Each strip runs on its own wayland connection and
//! dispatch thread, mirroring the clipboard type_watcher pattern (but with an
//! interruptible read loop so layout changes can rebuild strips).
//!
//! The monitor layout comes from Hyprland's IPC (the only compositor
//! supported in this phase); if it's unavailable the feature disables itself
//! with a warning. The layout is re-queried periodically so monitor
//! (un)plugs and resolution changes rebuild the strips.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::sync::{mpsc, watch};
use tokio::time;
use tracing::{debug, info, warn};

use crate::device::Event;

/// A screen edge that can be mapped to a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    Left,
    Right,
    Top,
    Bottom,
}

impl Direction {
    fn parse(s: &str) -> Result<Direction> {
        match s.to_ascii_lowercase().as_str() {
            "left" => Ok(Direction::Left),
            "right" => Ok(Direction::Right),
            "top" => Ok(Direction::Top),
            "bottom" => Ok(Direction::Bottom),
            other => bail!(
                "invalid edge direction '{}': expected left|right|top|bottom",
                other
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Left => "left",
            Direction::Right => "right",
            Direction::Top => "top",
            Direction::Bottom => "bottom",
        }
    }
}

/// The --edge-map target of one direction: who sits beyond that edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeTarget {
    /// The literal `auto`: exactly one connected client. An error while zero
    /// or more than one client is connected.
    Auto,
    /// A fingerprint prefix (like set_client's goto matching), or — when no
    /// connected client's fingerprint starts with it — a hostname resolved
    /// via the system resolver and matched to a connected client by IP.
    Named(String),
}

impl std::fmt::Display for EdgeTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EdgeTarget::Auto => f.write_str("auto"),
            EdgeTarget::Named(name) => f.write_str(name),
        }
    }
}

/// Parsed --edge-map: which client sits beyond which screen edge.
#[derive(Clone, Debug, Default)]
pub struct EdgeMap {
    pub targets: BTreeMap<Direction, EdgeTarget>,
}

/// Parses the repeatable, comma-separated --edge-map values
/// ("right=auto", "left=aa11bb,top=laptop") into an EdgeMap.
pub fn parse_edge_map(specs: &[String]) -> Result<EdgeMap> {
    let mut map = EdgeMap::default();
    for spec in specs {
        for part in spec.split(',') {
            let part = part.trim();
            let (dir, target) = part.split_once('=').with_context(|| {
                format!(
                    "invalid --edge-map entry '{}': expected <direction>=<target>",
                    part
                )
            })?;
            let dir = Direction::parse(dir.trim())?;
            let target = target.trim();
            if target.is_empty() {
                bail!("invalid --edge-map entry '{}': empty target", part);
            }
            let target = if target == "auto" {
                EdgeTarget::Auto
            } else {
                EdgeTarget::Named(target.to_string())
            };
            if map.targets.insert(dir, target).is_some() {
                bail!("duplicate direction '{}' in --edge-map", dir.as_str());
            }
        }
    }
    if map.targets.is_empty() {
        bail!("--edge-map requires at least one direction=target entry");
    }
    Ok(map)
}

/// One output's logical rectangle in the compositor's layout coordinate
/// space (scale already applied). Injectable so the geometry is testable
/// without a running compositor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputRect {
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// A contiguous exposed piece of one output's boundary: no other output
/// abuts it, so the cursor jams against it (and a strip there can see it).
/// `start`/`len` run along the edge axis in global layout coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeSegment {
    pub direction: Direction,
    pub output: String,
    pub start: i32,
    pub len: i32,
}

/// Computes the exposed edge segments of a monitor layout: for each output
/// boundary, the intervals not abutted by another output. Two 1920x1080
/// monitors side by side at (0,0) and (1920,0) yield the right edge only on
/// the rightmost monitor, the left edge only on the leftmost, and full
/// top/bottom edges on both. Pure over the layout so tests need no Hyprland.
pub fn exposed_segments(outputs: &[OutputRect]) -> Vec<EdgeSegment> {
    let mut segments = Vec::new();
    for (i, r) in outputs.iter().enumerate() {
        if r.width <= 0 || r.height <= 0 {
            continue;
        }
        for direction in [
            Direction::Left,
            Direction::Right,
            Direction::Top,
            Direction::Bottom,
        ] {
            // This edge's interval along its axis.
            let (edge_lo, edge_hi) = match direction {
                Direction::Left | Direction::Right => (r.y, r.y + r.height),
                Direction::Top | Direction::Bottom => (r.x, r.x + r.width),
            };
            // Intervals of other outputs abutting this edge's line, clamped
            // to the edge interval.
            let mut abutting: Vec<(i32, i32)> = Vec::new();
            for (j, q) in outputs.iter().enumerate() {
                if i == j || q.width <= 0 || q.height <= 0 {
                    continue;
                }
                let shares_boundary = match direction {
                    Direction::Right => q.x == r.x + r.width,
                    Direction::Left => q.x + q.width == r.x,
                    Direction::Bottom => q.y == r.y + r.height,
                    Direction::Top => q.y + q.height == r.y,
                };
                if !shares_boundary {
                    continue;
                }
                let (lo, hi) = match direction {
                    Direction::Left | Direction::Right => (q.y, q.y + q.height),
                    Direction::Top | Direction::Bottom => (q.x, q.x + q.width),
                };
                let (lo, hi) = (lo.max(edge_lo), hi.min(edge_hi));
                if lo < hi {
                    abutting.push((lo, hi));
                }
            }
            // Subtract the abutting intervals; what remains is exposed.
            abutting.sort_unstable();
            let mut cursor = edge_lo;
            let mut push = |start: i32, end: i32| {
                if start < end {
                    segments.push(EdgeSegment {
                        direction,
                        output: r.name.clone(),
                        start,
                        len: end - start,
                    });
                }
            };
            for (lo, hi) in abutting {
                push(cursor, lo);
                cursor = cursor.max(hi);
            }
            push(cursor, edge_hi);
        }
    }
    segments
}

/// Fraction of an exposed segment trimmed at each end as a corner dead zone.
/// Every segment end is a desktop-outline corner or an abutment step — both
/// are points the cursor jams into when flung diagonally (or aimed at corner
/// UI), so both get the dead zone: corners never trigger a switch.
pub const CORNER_TRIM_PERCENT: i32 = 8;

/// Trims CORNER_TRIM_PERCENT off both ends of an exposed segment (see
/// CORNER_TRIM_PERCENT). Returns None if nothing usable remains.
fn trim_corner_dead_zones(segment: EdgeSegment) -> Option<EdgeSegment> {
    let trim = segment.len * CORNER_TRIM_PERCENT / 100;
    let len = segment.len - 2 * trim;
    if len <= 0 {
        return None;
    }
    Some(EdgeSegment {
        start: segment.start + trim,
        len,
        ..segment
    })
}

/// Queries the monitor layout from Hyprland's IPC socket
/// ($XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket.sock), the
/// same channel hyprctl uses. Errors when not running under Hyprland.
pub fn hyprland_layout() -> Result<Vec<OutputRect>> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .context("XDG_RUNTIME_DIR is not set (no wayland session?)")?;
    let signature = std::env::var("HYPRLAND_INSTANCE_SIGNATURE")
        .context("HYPRLAND_INSTANCE_SIGNATURE is not set (not running under Hyprland)")?;
    let socket = PathBuf::from(runtime_dir)
        .join("hypr")
        .join(signature)
        .join(".socket.sock");
    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("Failed to connect to Hyprland IPC at {}", socket.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("Failed to configure Hyprland IPC socket")?;
    // "j/monitors" is the JSON variant of the monitors request.
    stream
        .write_all(b"j/monitors")
        .context("Failed to query Hyprland monitors")?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .context("Failed to finish Hyprland monitors query")?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .context("Failed to read Hyprland monitors reply")?;
    parse_monitors_json(&reply)
}

/// Parses Hyprland's JSON monitors reply into logical output rectangles
/// (mode size divided by scale). Disabled outputs are skipped.
fn parse_monitors_json(json: &str) -> Result<Vec<OutputRect>> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("Failed to parse Hyprland monitors reply")?;
    let monitors = value
        .as_array()
        .context("Hyprland monitors reply is not a JSON array")?;
    let mut outputs = Vec::new();
    for monitor in monitors {
        if monitor["disabled"].as_bool() == Some(true) {
            continue;
        }
        let name = monitor["name"]
            .as_str()
            .context("Hyprland monitor entry lacks a name")?
            .to_string();
        let get_i64 = |key: &str| -> Result<i64> {
            monitor[key]
                .as_i64()
                .with_context(|| format!("Hyprland monitor '{}' lacks '{}'", name, key))
        };
        let (x, y, width, height) = (
            get_i64("x")?,
            get_i64("y")?,
            get_i64("width")?,
            get_i64("height")?,
        );
        let scale = monitor["scale"]
            .as_f64()
            .filter(|s| *s > 0.0)
            .unwrap_or(1.0);
        outputs.push(OutputRect {
            name,
            x: x as i32,
            y: y as i32,
            width: (width as f64 / scale).round() as i32,
            height: (height as f64 / scale).round() as i32,
        });
    }
    Ok(outputs)
}

/// Minimum spacing between two fires of the same edge: after a completed
/// dwell fires the switch, enters inside the cooldown are ignored so parking
/// on (or bouncing against) the edge can't machine-gun switches.
const REARM_COOLDOWN: Duration = Duration::from_secs(1);

/// Edge-resistance state machine for one direction: an enter starts a dwell
/// timer, a leave before the deadline cancels it, a completed dwell fires
/// once and the re-arm cooldown blocks immediate refires. Pure over `now`
/// instants so the state machine is testable without sleeping.
pub struct DwellTimer {
    dwell: Duration,
    cooldown: Duration,
    /// When the cursor entered (dwell in progress), None while disarmed.
    entered_at: Option<Instant>,
    /// When the last fire happened (for the re-arm cooldown).
    last_fired: Option<Instant>,
}

impl DwellTimer {
    pub fn new(dwell: Duration, cooldown: Duration) -> Self {
        Self {
            dwell,
            cooldown,
            entered_at: None,
            last_fired: None,
        }
    }

    /// The cursor entered the edge. Returns the fire deadline, or None when
    /// the enter is ignored because the re-arm cooldown is still running.
    pub fn enter(&mut self, now: Instant) -> Option<Instant> {
        if let Some(fired) = self.last_fired {
            if now.duration_since(fired) < self.cooldown {
                return None;
            }
        }
        self.entered_at = Some(now);
        Some(now + self.dwell)
    }

    /// The cursor left the edge: cancel any pending dwell.
    pub fn leave(&mut self) {
        self.entered_at = None;
    }

    /// Whether the dwell completed (fires once: the state resets and the
    /// re-arm cooldown starts).
    pub fn poll(&mut self, now: Instant) -> bool {
        match self.entered_at {
            Some(entered) if now.duration_since(entered) >= self.dwell => {
                self.entered_at = None;
                self.last_fired = Some(now);
                true
            }
            _ => false,
        }
    }
}

/// Why an edge target couldn't be resolved against the live client list.
#[derive(Debug, PartialEq)]
pub enum ResolveError {
    /// No clients are connected at all.
    NoClients,
    /// `auto` with more than one connected client.
    AutoAmbiguous(usize),
    /// The fingerprint prefix matched more than one connected client.
    AmbiguousFingerprint(String, usize),
    /// The hostname didn't resolve via the system resolver.
    UnresolvedHostname(String),
    /// The hostname resolved, but no connected client has any of its IPs.
    HostnameMatchesNothing(String),
    /// The hostname's IPs matched more than one connected client.
    AmbiguousHostname(String, usize),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ResolveError::NoClients => write!(f, "no clients connected"),
            ResolveError::AutoAmbiguous(n) => write!(
                f,
                "'auto' requires exactly one connected client, but {} are connected",
                n
            ),
            ResolveError::AmbiguousFingerprint(prefix, n) => write!(
                f,
                "fingerprint prefix '{}' matches {} connected clients",
                prefix, n
            ),
            ResolveError::UnresolvedHostname(name) => write!(
                f,
                "couldn't resolve '{}'; use the fingerprint prefix from the 'Added client ...' log line",
                name
            ),
            ResolveError::HostnameMatchesNothing(name) => write!(
                f,
                "'{}' resolved, but no connected client has its IP; use the fingerprint prefix from the 'Added client ...' log line",
                name
            ),
            ResolveError::AmbiguousHostname(name, n) => write!(
                f,
                "hostname '{}' matches {} connected clients by IP",
                name, n
            ),
        }
    }
}

/// Resolves an edge target to the fingerprint of a connected client, against
/// the LIVE client list (tolerates reconnects and IP changes: nothing is
/// resolved to an IP at startup). `clients` are (endpoint, fingerprint)
/// pairs; `resolve_host` is injected for tests. Fingerprint prefix matching
/// mirrors the rotation's goto resolution; `auto` requires exactly one
/// client; anything else falls through to hostname→IP matching.
pub fn resolve_edge_target(
    target: &EdgeTarget,
    clients: &[(SocketAddr, String)],
    resolve_host: &dyn Fn(&str) -> Vec<IpAddr>,
) -> std::result::Result<String, ResolveError> {
    match target {
        EdgeTarget::Auto => match clients.len() {
            0 => Err(ResolveError::NoClients),
            1 => Ok(clients[0].1.clone()),
            n => Err(ResolveError::AutoAmbiguous(n)),
        },
        EdgeTarget::Named(name) => {
            // A fingerprint prefix first (like goto): a client whose
            // certificate fingerprint starts with the target string.
            let matching: Vec<&(SocketAddr, String)> = clients
                .iter()
                .filter(|(_, fp)| fp.starts_with(name.as_str()))
                .collect();
            match matching.len() {
                1 => return Ok(matching[0].1.clone()),
                n if n > 1 => {
                    return Err(ResolveError::AmbiguousFingerprint(name.clone(), n));
                }
                _ => {}
            }
            // Then a hostname: resolve it (and its .local mDNS variant) and
            // match a connected client by IP.
            let ips = resolve_host(name);
            if ips.is_empty() {
                return Err(ResolveError::UnresolvedHostname(name.clone()));
            }
            let matching: Vec<&(SocketAddr, String)> = clients
                .iter()
                .filter(|(endpoint, _)| ips.contains(&endpoint.ip()))
                .collect();
            match matching.len() {
                0 => Err(ResolveError::HostnameMatchesNothing(name.clone())),
                1 => Ok(matching[0].1.clone()),
                n => Err(ResolveError::AmbiguousHostname(name.clone(), n)),
            }
        }
    }
}

/// System-resolves a hostname to IPs: the bare name first, then the `.local`
/// mDNS variant (avahi host records resolve through NSS on LANs set up for
/// it). Best-effort: an empty result just means "unresolvable here".
pub fn resolve_hostname(name: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for candidate in [name.to_string(), format!("{}.local", name)] {
        if let Ok(addrs) = (candidate.as_str(), 0).to_socket_addrs() {
            ips.extend(addrs.map(|addr| addr.ip()));
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

/// Pointer Enter/Leave on an edge strip, sent from the strip's wayland
/// dispatch thread to the edge manager task.
enum StripEvent {
    Enter(Direction),
    Leave(Direction),
}

/// Placement of one strip: a 1px-wide band on `output`, starting `offset`
/// px along the edge from the output's origin, `len` px long.
struct StripSpec {
    output: String,
    direction: Direction,
    offset: i32,
    len: i32,
}

/// Turns a layout into strip placements for the mapped directions: exposed
/// segments only, corner dead zones applied, global coordinates translated
/// to output-relative offsets.
fn strip_specs(map: &EdgeMap, layout: &[OutputRect]) -> Vec<StripSpec> {
    let mut specs = Vec::new();
    for segment in exposed_segments(layout) {
        if !map.targets.contains_key(&segment.direction) {
            continue;
        }
        let Some(segment) = trim_corner_dead_zones(segment) else {
            continue;
        };
        let Some(output) = layout.iter().find(|o| o.name == segment.output) else {
            continue;
        };
        let offset = match segment.direction {
            Direction::Left | Direction::Right => segment.start - output.y,
            Direction::Top | Direction::Bottom => segment.start - output.x,
        };
        specs.push(StripSpec {
            output: segment.output,
            direction: segment.direction,
            offset,
            len: segment.len,
        });
    }
    specs
}

/// How often the monitor layout is re-queried; a change rebuilds the strips.
const LAYOUT_REQUERY_INTERVAL: Duration = Duration::from_secs(30);

/// How long a strip's dispatch loop may block on the wayland socket before
/// re-checking its shutdown flag (layout rebuilds stop the old strips).
const STRIP_POLL_TIMEOUT_MS: i32 = 500;

/// A running strip: its wayland dispatch thread plus its shutdown flag.
struct StripHandle {
    shutdown: Arc<AtomicBool>,
    join: std::thread::JoinHandle<()>,
}

/// The strips of one layout generation.
struct StripSet {
    handles: Vec<StripHandle>,
}

impl StripSet {
    /// Stops all strips: flags their dispatch loops and reaps the threads on
    /// a detached thread (a loop can take up to STRIP_POLL_TIMEOUT_MS to
    /// notice), so the caller isn't stalled on a layout rebuild.
    fn shutdown(self) {
        let mut joins = Vec::new();
        for handle in self.handles {
            handle.shutdown.store(true, Ordering::Relaxed);
            joins.push(handle.join);
        }
        std::thread::spawn(move || {
            for join in joins {
                let _ = join.join();
            }
        });
    }
}

/// Spawns one strip per exposed segment of a mapped direction.
fn spawn_strips(
    map: &EdgeMap,
    layout: &[OutputRect],
    strip_tx: &mpsc::UnboundedSender<StripEvent>,
) -> StripSet {
    let specs = strip_specs(map, layout);
    if specs.is_empty() {
        warn!("Screen-edge switching: no exposed screen-edge segments match --edge-map on the current monitor layout");
    }
    let mut handles = Vec::new();
    for spec in specs {
        info!(
            "Screen-edge switching: creating strip on the {} edge of {} (offset {}, length {})",
            spec.direction.as_str(),
            spec.output,
            spec.offset,
            spec.len
        );
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown2 = shutdown.clone();
        let strip_tx = strip_tx.clone();
        let join = std::thread::spawn(move || {
            if let Err(e) = run_strip(&spec, strip_tx, shutdown2) {
                warn!(
                    "Screen-edge strip on the {} edge of {} died: {:?}",
                    spec.direction.as_str(),
                    spec.output,
                    e
                );
            }
        });
        handles.push(StripHandle { shutdown, join });
    }
    StripSet { handles }
}

/// The edge manager task: owns the strips, the dwell state machines, target
/// resolution, and the periodic layout re-query. Exits (disabling the
/// feature) when Hyprland's IPC is unavailable; otherwise runs until the
/// server shuts down.
pub async fn run(
    map: EdgeMap,
    dwell: Duration,
    event_tx: mpsc::Sender<Event>,
    mut clients_rx: watch::Receiver<Vec<(SocketAddr, String)>>,
) {
    let layout = match hyprland_layout() {
        Ok(layout) if !layout.is_empty() => layout,
        Ok(_) => {
            warn!("Screen-edge switching disabled: Hyprland reports no outputs");
            return;
        }
        Err(e) => {
            warn!("Screen-edge switching disabled: {:#}", e);
            return;
        }
    };
    info!(
        "Screen-edge switching enabled (dwell {:?}, cooldown {:?}): {}",
        dwell,
        REARM_COOLDOWN,
        map.targets
            .iter()
            .map(|(dir, target)| format!("{}={}", dir.as_str(), target))
            .collect::<Vec<String>>()
            .join(", ")
    );
    log_layout(&layout);
    let (strip_tx, mut strip_rx) = mpsc::unbounded_channel::<StripEvent>();
    let mut strips = spawn_strips(&map, &layout, &strip_tx);
    let mut current_layout = layout;

    // Per-direction dwell state. `entered` counts strips of this direction
    // the cursor is currently inside (multiple monitors can contribute
    // several segments to one direction); the dwell timer runs while ≥1.
    struct DirState {
        timer: DwellTimer,
        entered: u32,
        deadline: Option<Instant>,
    }
    let mut dirs: HashMap<Direction, DirState> = map
        .targets
        .keys()
        .map(|dir| {
            (
                *dir,
                DirState {
                    timer: DwellTimer::new(dwell, REARM_COOLDOWN),
                    entered: 0,
                    deadline: None,
                },
            )
        })
        .collect();
    log_edge_resolutions(&map, &clients_rx.borrow());

    let mut requery = time::interval(LAYOUT_REQUERY_INTERVAL);
    // Skip the immediate first tick; the startup query just ran.
    requery.tick().await;
    loop {
        let next_deadline = dirs.values().filter_map(|state| state.deadline).min();
        tokio::select! {
            event = strip_rx.recv() => {
                let now = Instant::now();
                match event {
                    Some(StripEvent::Enter(dir)) => {
                        if let Some(state) = dirs.get_mut(&dir) {
                            state.entered += 1;
                            if state.entered == 1 {
                                state.deadline = state.timer.enter(now);
                            }
                        }
                    }
                    Some(StripEvent::Leave(dir)) => {
                        if let Some(state) = dirs.get_mut(&dir) {
                            state.entered = state.entered.saturating_sub(1);
                            if state.entered == 0 {
                                state.timer.leave();
                                state.deadline = None;
                            }
                        }
                    }
                    None => {
                        warn!("Screen-edge switching disabled: all edge strips are gone");
                        return;
                    }
                }
            }
            changed = clients_rx.changed() => {
                if changed.is_err() {
                    // The rotation loop is gone: the server is shutting down.
                    return;
                }
                log_edge_resolutions(&map, &clients_rx.borrow());
            }
            _ = requery.tick() => {
                match hyprland_layout() {
                    Ok(new_layout) if !new_layout.is_empty() => {
                        if new_layout != current_layout {
                            info!("Screen-edge switching: monitor layout changed, rebuilding edge strips");
                            log_layout(&new_layout);
                            strips.shutdown();
                            strips = spawn_strips(&map, &new_layout, &strip_tx);
                            current_layout = new_layout;
                            // Enters recorded against the dead strips' generation
                            // would never see their leave.
                            for state in dirs.values_mut() {
                                state.entered = 0;
                                state.deadline = None;
                                state.timer.leave();
                            }
                        }
                    }
                    Ok(_) => {
                        warn!("Screen-edge switching: Hyprland layout re-query returned no outputs, keeping existing strips");
                    }
                    Err(e) => {
                        warn!("Screen-edge switching: Hyprland layout re-query failed ({:#}), keeping existing strips", e);
                    }
                }
            }
            _ = async {
                match next_deadline {
                    Some(deadline) => time::sleep_until(time::Instant::from_std(deadline)).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let now = Instant::now();
                for (dir, state) in dirs.iter_mut() {
                    if !state.deadline.is_some_and(|deadline| deadline <= now)
                        || !state.timer.poll(now)
                    {
                        continue;
                    }
                    // Fired: the timer reset and started its re-arm cooldown.
                    state.deadline = None;
                    state.entered = 0;
                    let clients = clients_rx.borrow().clone();
                    let target = &map.targets[dir];
                    match resolve_edge_target(target, &clients, &resolve_hostname) {
                        Ok(fingerprint) => {
                            info!("Edge switch to client {} via {} edge", fingerprint, dir.as_str());
                            if let Err(e) = event_tx.send(Event::SwitchTo(fingerprint)).await {
                                warn!("Failed to submit edge switch event: {:?}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Edge switch via {} edge did not fire: {}", dir.as_str(), e);
                        }
                    }
                }
            }
        }
    }
}

/// Logs the monitor layout in one line.
fn log_layout(layout: &[OutputRect]) {
    info!(
        "Screen-edge switching: monitor layout: {}",
        layout
            .iter()
            .map(|o| format!("{} {}x{}@({},{})", o.name, o.width, o.height, o.x, o.y))
            .collect::<Vec<String>>()
            .join(", ")
    );
}

/// Resolves every mapped target against the current client list and logs the
/// outcome — at startup and on every client (dis)connect, so the mapping is
/// visible before anyone pushes the cursor into an edge.
fn log_edge_resolutions(map: &EdgeMap, clients: &[(SocketAddr, String)]) {
    for (dir, target) in &map.targets {
        match resolve_edge_target(target, clients, &resolve_hostname) {
            Ok(fingerprint) => info!(
                "Screen-edge switching: {} edge → client {} (target '{}')",
                dir.as_str(),
                fingerprint,
                target
            ),
            Err(e) => warn!(
                "Screen-edge switching: {} edge target '{}' is not resolvable right now: {}",
                dir.as_str(),
                target,
                e
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Wayland strip: a 1px-wide invisible layer-shell surface that reports
// pointer Enter/Leave at the very screen edge.
// ---------------------------------------------------------------------------

use std::os::fd::{AsFd, AsRawFd};

use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::{
    wl_buffer::WlBuffer, wl_compositor::WlCompositor, wl_output, wl_output::WlOutput, wl_pointer,
    wl_pointer::WlPointer, wl_region::WlRegion, wl_registry, wl_seat::WlSeat, wl_shm,
    wl_shm::WlShm, wl_shm_pool::WlShmPool, wl_surface::WlSurface,
};
use wayland_client::{delegate_noop, Connection, Dispatch, Proxy, QueueHandle};
use wayland_protocols_wlr::layer_shell::v1::client::zwlr_layer_shell_v1::{
    Layer, ZwlrLayerShellV1,
};
use wayland_protocols_wlr::layer_shell::v1::client::zwlr_layer_surface_v1::{
    Anchor, KeyboardInteractivity, ZwlrLayerSurfaceV1,
};

/// Per-strip wayland state, dispatched on the strip's own thread.
struct StripState {
    direction: Direction,
    events_tx: mpsc::UnboundedSender<StripEvent>,
    /// Bound wl_outputs with their names (filled by wl_output.name events).
    outputs: Vec<(WlOutput, String)>,
    /// One wl_pointer per seat (kept alive for Enter/Leave delivery).
    pointers: Vec<WlPointer>,
    surface: Option<WlSurface>,
    buffer: Option<WlBuffer>,
    /// Kept alive for the buffer's lifetime (protocol-wise the buffer keeps
    /// referencing the pool's memory).
    pool: Option<WlShmPool>,
    configured: bool,
}

impl StripState {
    fn new(direction: Direction, events_tx: mpsc::UnboundedSender<StripEvent>) -> Self {
        Self {
            direction,
            events_tx,
            outputs: Vec::new(),
            pointers: Vec::new(),
            surface: None,
            buffer: None,
            pool: None,
            configured: false,
        }
    }
}

/// Runs one edge strip: connects to wayland, places a 1px transparent
/// layer-shell surface per the spec, and dispatches until the shutdown flag
/// is set or the connection breaks. The surface needs a buffer to be mapped
/// (an unmapped surface receives no pointer focus), so a fully transparent
/// 1x1 shm buffer is attached; the explicit input region (the strip rect)
/// both enables Enter/Leave delivery and — crucially — keeps the default
/// infinite input region from making the strip swallow input anywhere else.
fn run_strip(
    spec: &StripSpec,
    events_tx: mpsc::UnboundedSender<StripEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let conn = Connection::connect_to_env().context("Failed to connect to wayland")?;
    let (globals, mut queue) = registry_queue_init::<StripState>(&conn)
        .context("Failed to init Wayland registry queue")?;
    let qh = queue.handle();
    let compositor: WlCompositor = globals
        .bind(&qh, 1..=4, ())
        .context("compositor lacks wl_compositor")?;
    let shm: WlShm = globals
        .bind(&qh, 1..=1, ())
        .context("compositor lacks wl_shm")?;
    let layer_shell: ZwlrLayerShellV1 = globals
        .bind(&qh, 1..=4, ())
        .context("compositor lacks wlr-layer-shell")?;

    let mut state = StripState::new(spec.direction, events_tx);
    // Bind outputs (v4 for the name event) and a pointer per seat.
    let registry = globals.registry();
    globals.contents().with_list(|global_list| {
        for global in global_list {
            if global.interface == WlOutput::interface().name && global.version >= 4 {
                let output: WlOutput = registry.bind(global.name, 4, &qh, ());
                state.outputs.push((output, String::new()));
            } else if global.interface == WlSeat::interface().name {
                let seat: WlSeat = registry.bind(global.name, 1, &qh, ());
                state.pointers.push(seat.get_pointer(&qh, ()));
            }
        }
    });
    queue
        .roundtrip(&mut state)
        .context("Failed to initialize Wayland state")?;
    let output = state
        .outputs
        .iter()
        .find(|(_, name)| *name == spec.output)
        .map(|(output, _)| output.clone())
        .with_context(|| {
            format!(
                "wayland output '{}' not found (have: {})",
                spec.output,
                state
                    .outputs
                    .iter()
                    .map(|(_, name)| name.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ")
            )
        })?;

    // The 1x1 transparent buffer the compositor scales over the strip area.
    let (buffer, pool) = transparent_buffer(&shm, &qh)?;

    let (width, height) = match spec.direction {
        Direction::Left | Direction::Right => (1, spec.len),
        Direction::Top | Direction::Bottom => (spec.len, 1),
    };
    let surface = compositor.create_surface(&qh, ());
    let region = compositor.create_region(&qh, ());
    region.add(0, 0, width, height);
    surface.set_input_region(Some(&region));
    region.destroy();
    let layer_surface = layer_shell.get_layer_surface(
        &surface,
        Some(&output),
        Layer::Overlay,
        "monux-edge".to_string(),
        &qh,
        (),
    );
    // Anchored to the mapped edge plus the perpendicular start edge, so the
    // margin positions the strip along the edge. Exclusive zone -1: reserve
    // no space AND ignore other surfaces' zones — bars/panels must neither
    // move nor push the strip away from the very screen edge.
    layer_surface.set_anchor(match spec.direction {
        Direction::Left => Anchor::Left | Anchor::Top,
        Direction::Right => Anchor::Right | Anchor::Top,
        Direction::Top => Anchor::Top | Anchor::Left,
        Direction::Bottom => Anchor::Bottom | Anchor::Left,
    });
    layer_surface.set_size(width as u32, height as u32);
    layer_surface.set_exclusive_zone(-1);
    match spec.direction {
        Direction::Left | Direction::Right => layer_surface.set_margin(spec.offset, 0, 0, 0),
        Direction::Top | Direction::Bottom => layer_surface.set_margin(0, 0, 0, spec.offset),
    }
    layer_surface.set_keyboard_interactivity(KeyboardInteractivity::None);
    state.surface = Some(surface.clone());
    state.buffer = Some(buffer);
    state.pool = Some(pool);
    surface.commit();
    queue
        .roundtrip(&mut state)
        .context("Failed to map the edge strip surface")?;
    if !state.configured {
        bail!("compositor never configured the edge strip surface");
    }
    debug!(
        "edge strip mapped: {} edge of {} (offset {}, length {})",
        spec.direction.as_str(),
        spec.output,
        spec.offset,
        spec.len
    );

    // Dispatch loop, interruptible via the shutdown flag: poll the wayland
    // socket with a timeout instead of blocking_dispatch so layout rebuilds
    // can retire the strip (mirror of the clipboard type_watcher's pattern,
    // plus the timeout).
    while !shutdown.load(Ordering::Relaxed) {
        queue
            .dispatch_pending(&mut state)
            .context("Wayland dispatch failed")?;
        conn.flush().context("Wayland flush failed")?;
        let Some(guard) = conn.prepare_read() else {
            // Another thread holds the read — never the case here, but don't
            // spin if it somehow happens.
            std::thread::sleep(Duration::from_millis(STRIP_POLL_TIMEOUT_MS as u64));
            continue;
        };
        let mut pollfd = libc::pollfd {
            fd: conn.as_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let readable = unsafe { libc::poll(&mut pollfd, 1, STRIP_POLL_TIMEOUT_MS) } > 0
            && pollfd.revents & libc::POLLIN != 0;
        if readable {
            guard.read().context("Wayland read failed")?;
        }
        // Dropping the guard without read() cancels the prepared read.
    }
    debug!(
        "edge strip retired: {} edge of {}",
        spec.direction.as_str(),
        spec.output
    );
    Ok(())
}

/// Creates a fully transparent 1x1 ARGB8888 shm buffer (fresh memfd memory
/// is zero-filled = transparent).
fn transparent_buffer(shm: &WlShm, qh: &QueueHandle<StripState>) -> Result<(WlBuffer, WlShmPool)> {
    let fd = rustix::fs::memfd_create("monux-edge", rustix::fs::MemfdFlags::CLOEXEC)
        .context("Failed to allocate shm memory for the edge strip")?;
    rustix::fs::ftruncate(&fd, 4).context("Failed to size the edge strip buffer")?;
    let pool = shm.create_pool(fd.as_fd(), 4, qh, ());
    let buffer = pool.create_buffer(0, 1, 1, 4, wl_shm::Format::Argb8888, qh, ());
    Ok((buffer, pool))
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for StripState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_registry::WlRegistry,
        _event: <wl_registry::WlRegistry as Proxy>::Event,
        _data: &GlobalListContents,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlOutput, ()> for StripState {
    fn event(
        state: &mut Self,
        proxy: &WlOutput,
        event: wl_output::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wl_output::Event::Name { name } = event {
            if let Some(entry) = state.outputs.iter_mut().find(|(output, _)| output == proxy) {
                entry.1 = name;
            }
        }
    }
}

impl Dispatch<WlPointer, ()> for StripState {
    fn event(
        state: &mut Self,
        _proxy: &WlPointer,
        event: wl_pointer::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        let event = match event {
            wl_pointer::Event::Enter { .. } => StripEvent::Enter(state.direction),
            wl_pointer::Event::Leave { .. } => StripEvent::Leave(state.direction),
            _ => return,
        };
        // Unbounded sends can't block; a dead receiver means shutdown.
        let _ = state.events_tx.send(event);
    }
}

impl Dispatch<ZwlrLayerSurfaceV1, ()> for StripState {
    fn event(
        state: &mut Self,
        proxy: &ZwlrLayerSurfaceV1,
        event: wayland_protocols_wlr::layer_shell::v1::client::zwlr_layer_surface_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        use wayland_protocols_wlr::layer_shell::v1::client::zwlr_layer_surface_v1::Event;
        match event {
            Event::Configure { serial, .. } => {
                proxy.ack_configure(serial);
                if let (Some(surface), Some(buffer)) = (&state.surface, &state.buffer) {
                    surface.attach(Some(buffer), 0, 0);
                    surface.commit();
                }
                state.configured = true;
            }
            Event::Closed => {
                debug!("edge strip surface closed by the compositor");
            }
            _ => {}
        }
    }
}

// NOTE: the `ignore` form is required for every interface that emits events
// (wl_shm's format advertisement, wl_seat's capabilities, wl_surface's
// enter/leave, wl_buffer's release): the plain form of delegate_noop panics
// on the first event.
delegate_noop!(StripState: ignore WlCompositor);
delegate_noop!(StripState: ignore WlSurface);
delegate_noop!(StripState: ignore WlRegion);
delegate_noop!(StripState: ignore WlShm);
delegate_noop!(StripState: ignore WlShmPool);
delegate_noop!(StripState: ignore WlBuffer);
delegate_noop!(StripState: ignore WlSeat);
delegate_noop!(StripState: ignore ZwlrLayerShellV1);

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(name: &str, x: i32, y: i32, width: i32, height: i32) -> OutputRect {
        OutputRect {
            name: name.to_string(),
            x,
            y,
            width,
            height,
        }
    }

    /// Segments of one direction, as (output, start, len), sorted for
    /// stable comparison.
    fn segments_of(
        segments: &[EdgeSegment],
        direction: Direction,
    ) -> Vec<(String, i32, i32)> {
        let mut found: Vec<(String, i32, i32)> = segments
            .iter()
            .filter(|s| s.direction == direction)
            .map(|s| (s.output.clone(), s.start, s.len))
            .collect();
        found.sort();
        found
    }

    #[test]
    fn exposed_side_by_side() {
        // The user's setup: two 1920x1080 monitors, the right edge exposed
        // only on the rightmost one.
        let layout = vec![
            rect("DP-1", 0, 0, 1920, 1080),
            rect("HDMI-A-1", 1920, 0, 1920, 1080),
        ];
        let segments = exposed_segments(&layout);
        assert_eq!(
            segments_of(&segments, Direction::Right),
            vec![("HDMI-A-1".to_string(), 0, 1080)]
        );
        assert_eq!(
            segments_of(&segments, Direction::Left),
            vec![("DP-1".to_string(), 0, 1080)]
        );
        assert_eq!(
            segments_of(&segments, Direction::Top),
            vec![
                ("DP-1".to_string(), 0, 1920),
                ("HDMI-A-1".to_string(), 1920, 1920)
            ]
        );
        assert_eq!(
            segments_of(&segments, Direction::Bottom),
            vec![
                ("DP-1".to_string(), 0, 1920),
                ("HDMI-A-1".to_string(), 1920, 1920)
            ]
        );
    }

    #[test]
    fn exposed_stacked() {
        let layout = vec![
            rect("DP-1", 0, 0, 1920, 1080),
            rect("HDMI-A-1", 0, 1080, 1920, 1080),
        ];
        let segments = exposed_segments(&layout);
        // DP-1's bottom and HDMI-A-1's top are fully abutted.
        assert_eq!(
            segments_of(&segments, Direction::Bottom),
            vec![("HDMI-A-1".to_string(), 0, 1920)]
        );
        assert_eq!(
            segments_of(&segments, Direction::Top),
            vec![("DP-1".to_string(), 0, 1920)]
        );
        assert_eq!(
            segments_of(&segments, Direction::Left),
            vec![
                ("DP-1".to_string(), 0, 1080),
                ("HDMI-A-1".to_string(), 1080, 1080)
            ]
        );
    }

    #[test]
    fn exposed_l_shape_with_offset() {
        // Step segments: B is shifted down by half a height, splitting both
        // facing edges into an abutted and an exposed interval.
        let layout = vec![
            rect("A", 0, 0, 1920, 1080),
            rect("B", 1920, 540, 1920, 1080),
        ];
        let segments = exposed_segments(&layout);
        assert_eq!(
            segments_of(&segments, Direction::Right),
            vec![
                ("A".to_string(), 0, 540),
                ("B".to_string(), 540, 1080)
            ]
        );
        assert_eq!(
            segments_of(&segments, Direction::Left),
            vec![
                ("A".to_string(), 0, 1080),
                ("B".to_string(), 1080, 540)
            ]
        );
        // A's bottom and B's top are fully exposed (nothing below/above).
        assert_eq!(
            segments_of(&segments, Direction::Bottom),
            vec![
                ("A".to_string(), 0, 1920),
                ("B".to_string(), 1920, 1920)
            ]
        );
        assert_eq!(
            segments_of(&segments, Direction::Top),
            vec![
                ("A".to_string(), 0, 1920),
                ("B".to_string(), 1920, 1920)
            ]
        );
    }

    #[test]
    fn exposed_three_monitors() {
        let layout = vec![
            rect("L", 0, 0, 1920, 1080),
            rect("M", 1920, 0, 1920, 1080),
            rect("R", 3840, 0, 1920, 1080),
        ];
        let segments = exposed_segments(&layout);
        assert_eq!(
            segments_of(&segments, Direction::Left),
            vec![("L".to_string(), 0, 1080)]
        );
        assert_eq!(
            segments_of(&segments, Direction::Right),
            vec![("R".to_string(), 0, 1080)]
        );
        assert_eq!(segments_of(&segments, Direction::Top).len(), 3);
        assert_eq!(segments_of(&segments, Direction::Bottom).len(), 3);
    }

    #[test]
    fn exposed_differing_heights() {
        // B is taller: A's right edge is fully covered, and B's left edge
        // keeps an exposed step segment below A.
        let layout = vec![
            rect("A", 0, 0, 1920, 1080),
            rect("B", 1920, 0, 1920, 1440),
        ];
        let segments = exposed_segments(&layout);
        assert_eq!(
            segments_of(&segments, Direction::Right),
            vec![("B".to_string(), 0, 1440)]
        );
        assert_eq!(
            segments_of(&segments, Direction::Left),
            vec![
                ("A".to_string(), 0, 1080),
                ("B".to_string(), 1080, 360)
            ]
        );
    }

    #[test]
    fn monitors_json_applies_scale_and_skips_disabled() {
        let json = r#"[
            {"name": "DP-1", "x": 0, "y": 0, "width": 3840, "height": 2160, "scale": 2.0, "disabled": false},
            {"name": "HDMI-A-1", "x": 1920, "y": 0, "width": 1920, "height": 1080, "scale": 1.0, "disabled": true}
        ]"#;
        let outputs = parse_monitors_json(json).unwrap();
        assert_eq!(outputs, vec![rect("DP-1", 0, 0, 1920, 1080)]);
    }

    #[test]
    fn corner_dead_zones_trim_both_ends() {
        let segment = EdgeSegment {
            direction: Direction::Right,
            output: "A".to_string(),
            start: 0,
            len: 1080,
        };
        let trimmed = trim_corner_dead_zones(segment).unwrap();
        // 8% of 1080 = 86 px off each end.
        assert_eq!(trimmed.start, 86);
        assert_eq!(trimmed.len, 1080 - 2 * 86);
    }

    #[test]
    fn corner_dead_zones_keep_short_segments_usable() {
        // A 60px step segment loses only 4px per end, not the whole segment.
        let segment = EdgeSegment {
            direction: Direction::Right,
            output: "A".to_string(),
            start: 0,
            len: 60,
        };
        let trimmed = trim_corner_dead_zones(segment).unwrap();
        assert_eq!(trimmed.start, 4);
        assert_eq!(trimmed.len, 52);
    }

    fn client_list(entries: &[(&str, &str)]) -> Vec<(SocketAddr, String)> {
        entries
            .iter()
            .map(|(endpoint, fp)| {
                (endpoint.parse::<SocketAddr>().unwrap(), fp.to_string())
            })
            .collect()
    }

    fn no_ips(_: &str) -> Vec<IpAddr> {
        vec![]
    }

    #[test]
    fn resolve_fingerprint_prefix() {
        let clients = client_list(&[
            ("10.0.0.1:9000", "aaaa1111ffff"),
            ("10.0.0.2:9000", "bbbb2222ffff"),
        ]);
        let target = EdgeTarget::Named("aaaa".to_string());
        assert_eq!(
            resolve_edge_target(&target, &clients, &no_ips),
            Ok("aaaa1111ffff".to_string())
        );
        // No match: falls through to hostname resolution, which fails here.
        let target = EdgeTarget::Named("cccc".to_string());
        assert_eq!(
            resolve_edge_target(&target, &clients, &no_ips),
            Err(ResolveError::UnresolvedHostname("cccc".to_string()))
        );
        // Ambiguous prefix.
        let dupes = client_list(&[
            ("10.0.0.1:9000", "aaaa1111ffff"),
            ("10.0.0.2:9000", "aaaa2222ffff"),
        ]);
        assert_eq!(
            resolve_edge_target(&target_named("aaaa"), &dupes, &no_ips),
            Err(ResolveError::AmbiguousFingerprint("aaaa".to_string(), 2))
        );
    }

    fn target_named(name: &str) -> EdgeTarget {
        EdgeTarget::Named(name.to_string())
    }

    #[test]
    fn resolve_auto_requires_exactly_one_client() {
        let one = client_list(&[("10.0.0.1:9000", "aaaa1111ffff")]);
        assert_eq!(
            resolve_edge_target(&EdgeTarget::Auto, &one, &no_ips),
            Ok("aaaa1111ffff".to_string())
        );
        let none = client_list(&[]);
        assert_eq!(
            resolve_edge_target(&EdgeTarget::Auto, &none, &no_ips),
            Err(ResolveError::NoClients)
        );
        let two = client_list(&[
            ("10.0.0.1:9000", "aaaa1111ffff"),
            ("10.0.0.2:9000", "bbbb2222ffff"),
        ]);
        assert_eq!(
            resolve_edge_target(&EdgeTarget::Auto, &two, &no_ips),
            Err(ResolveError::AutoAmbiguous(2))
        );
    }

    #[test]
    fn resolve_hostname_matches_client_by_ip() {
        let clients = client_list(&[
            ("10.0.0.1:9000", "aaaa1111ffff"),
            ("10.0.0.2:9000", "bbbb2222ffff"),
        ]);
        let resolver = |name: &str| -> Vec<IpAddr> {
            match name {
                "laptop" => vec!["10.0.0.2".parse().unwrap()],
                _ => vec![],
            }
        };
        assert_eq!(
            resolve_edge_target(&target_named("laptop"), &clients, &resolver),
            Ok("bbbb2222ffff".to_string())
        );
        // Resolves, but to an IP no connected client has.
        let resolver = |_: &str| -> Vec<IpAddr> { vec!["10.0.0.99".parse().unwrap()] };
        assert_eq!(
            resolve_edge_target(&target_named("laptop"), &clients, &resolver),
            Err(ResolveError::HostnameMatchesNothing("laptop".to_string()))
        );
    }

    #[test]
    fn dwell_fires_at_deadline_once() {
        let now = Instant::now();
        let mut timer = DwellTimer::new(Duration::from_millis(250), Duration::from_secs(1));
        let deadline = timer.enter(now).expect("enter should arm the dwell");
        assert_eq!(deadline, now + Duration::from_millis(250));
        assert!(!timer.poll(now + Duration::from_millis(249)));
        assert!(timer.poll(now + Duration::from_millis(250)));
        // Fires once: a second poll without a new enter does not refire.
        assert!(!timer.poll(now + Duration::from_millis(500)));
    }

    #[test]
    fn dwell_leave_cancels() {
        let now = Instant::now();
        let mut timer = DwellTimer::new(Duration::from_millis(250), Duration::from_secs(1));
        timer.enter(now);
        timer.leave();
        assert!(!timer.poll(now + Duration::from_secs(5)));
    }

    #[test]
    fn dwell_cooldown_then_rearm() {
        let now = Instant::now();
        let mut timer = DwellTimer::new(Duration::from_millis(250), Duration::from_secs(1));
        timer.enter(now);
        assert!(timer.poll(now + Duration::from_millis(250)));
        // Re-entering inside the 1s re-arm cooldown is ignored.
        let during = now + Duration::from_millis(500);
        assert!(timer.enter(during).is_none());
        assert!(!timer.poll(during + Duration::from_secs(5)));
        // After the cooldown the edge re-arms and a fresh dwell fires.
        let after = now + Duration::from_millis(1500);
        let deadline = timer.enter(after).expect("cooldown over, should re-arm");
        assert_eq!(deadline, after + Duration::from_millis(250));
        assert!(timer.poll(deadline));
    }

    #[test]
    fn edge_map_parses_forms() {
        let map = parse_edge_map(&["right=auto".to_string()]).unwrap();
        assert_eq!(map.targets.len(), 1);
        assert_eq!(map.targets[&Direction::Right], EdgeTarget::Auto);

        // Repeatable flags and comma-separated values mix.
        let map = parse_edge_map(&[
            "left=aa11bb".to_string(),
            "right=auto,top=laptop".to_string(),
        ])
        .unwrap();
        assert_eq!(map.targets.len(), 3);
        assert_eq!(
            map.targets[&Direction::Left],
            EdgeTarget::Named("aa11bb".to_string())
        );
        assert_eq!(map.targets[&Direction::Right], EdgeTarget::Auto);
        assert_eq!(
            map.targets[&Direction::Top],
            EdgeTarget::Named("laptop".to_string())
        );
    }

    #[test]
    fn edge_map_rejects_bad_entries() {
        // Unknown direction.
        assert!(parse_edge_map(&["diagonal=auto".to_string()]).is_err());
        // Missing '='.
        assert!(parse_edge_map(&["right".to_string()]).is_err());
        // Empty target.
        assert!(parse_edge_map(&["right=".to_string()]).is_err());
        // Duplicate direction.
        assert!(parse_edge_map(&["right=auto,right=laptop".to_string()]).is_err());
        // Nothing usable at all.
        assert!(parse_edge_map(&["".to_string()]).is_err());
    }

    #[test]
    fn strip_specs_only_mapped_directions_with_corner_trim() {
        let mut map = EdgeMap::default();
        map.targets.insert(Direction::Right, EdgeTarget::Auto);
        let layout = vec![
            rect("DP-1", 0, 0, 1920, 1080),
            rect("HDMI-A-1", 1920, 0, 1920, 1080),
        ];
        let specs = strip_specs(&map, &layout);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].output, "HDMI-A-1");
        assert_eq!(specs[0].direction, Direction::Right);
        // Global [86, 994) on an output at y=0 → offset 86, len 908.
        assert_eq!(specs[0].offset, 86);
        assert_eq!(specs[0].len, 908);
    }
}
