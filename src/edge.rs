//! Screen-edge switching (opt-in via --edge-map), in two modes sharing one
//! detection machinery:
//!
//! SERVER: when the local cursor is pushed against a configured screen edge
//! and dwells there, input switches to the client mapped to that edge — the
//! classic "screen-edge KVM" behavior. The switch itself reuses the existing
//! rotation path (Event::SwitchTo → Rotation::set_client), so
//! debounce/pause/no-op cleanup all apply for free.
//!
//! CLIENT (run_client): when the cursor is pushed against a configured edge
//! of the CLIENT machine and dwells there, the client asks the server to
//! take input back (ClientEvent::SwitchRequest, carrying the fraction along
//! the edge where the cursor crossed — reserved for future cursor warping).
//! The only valid target on a client is `auto` (its one peer, the server);
//! the server honors the request only from the current client.
//!
//! Detection polls the cursor position from Hyprland's IPC every
//! POLL_INTERVAL (Hyprland delivers no usable pointer enter/leave at screen
//! edges — verified empirically with layer-shell probes — so an event-driven
//! design is not viable there). The cursor is "on" a mapped edge when its
//! coordinate crosses that edge's line within an EXPOSED segment of it (see
//! exposed_segments), minus a corner dead zone at each segment end. Edge
//! contact is debounced (a state must hold for two consecutive polls), then
//! the dwell timer (--edge-dwell-ms) runs; a leave before the deadline
//! cancels it; a completed dwell fires the switch once and a short re-arm
//! cooldown prevents machine-gunning. The poller runs on its own thread
//! (blocking socket IO), forwarding positions to the edge manager task.
//!
//! The monitor layout comes from Hyprland's IPC (the only compositor
//! supported in this phase); if it's unavailable the feature disables itself
//! with a warning. The layout is re-queried periodically so monitor
//! (un)plugs and resolution changes recompute the trigger zones.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::sync::{mpsc, watch};
use tokio::time;
use tracing::{debug, info, warn};

use crate::device::Event;
use crate::msgs::event::Direction;

/// Parses a --edge-map direction ("left"/"right"/"top"/"bottom"). The type
/// itself lives on the wire side (msgs::event) for ServerEvent::EdgeInfo;
/// the parsing helper stays here, next to the --edge-map handling.
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
    /// Unqualified entries ("bottom=auto"): apply to every output's exposed
    /// segments in that direction, except where a qualified entry for the
    /// same direction claims one output.
    pub targets: BTreeMap<Direction, EdgeTarget>,
    /// Monitor-qualified entries ("bottom@eDP-1=auto"), keyed by (direction,
    /// qualifier): the qualifier matches an output by name (the default) or
    /// by serial, model, or description when the compositor reports them
    /// (see qualifier_matches). The entry applies to every matching
    /// output's exposed segments in that direction, overriding the
    /// unqualified entry there. A direction with ONLY qualified entries
    /// leaves the other outputs' edges in that direction inert.
    pub qualified: BTreeMap<(Direction, String), EdgeTarget>,
}

impl EdgeMap {
    /// The target for one output's exposed segment in a direction: the
    /// qualified entry matching that output first, then the unqualified
    /// one. When several qualified entries match the same output (its name
    /// and its model, say), the first in (direction, qualifier) order wins.
    fn target_for(&self, direction: Direction, output: &OutputRect) -> Option<&EdgeTarget> {
        self.qualified
            .iter()
            .find(|((dir, qualifier), _)| *dir == direction && qualifier_matches(qualifier, output))
            .map(|(_, target)| target)
            .or_else(|| self.targets.get(&direction))
    }

    /// Every entry as (direction, monitor qualifier, target) — unqualified
    /// entries first (ascending by direction), then qualified ones
    /// (ascending by direction, then monitor name).
    pub(crate) fn entries(&self) -> impl Iterator<Item = (Direction, Option<&str>, &EdgeTarget)> {
        self.targets
            .iter()
            .map(|(dir, target)| (*dir, None, target))
            .chain(
                self.qualified
                    .iter()
                    .map(|((dir, monitor), target)| (*dir, Some(monitor.as_str()), target)),
            )
    }

    /// Every mapped direction, qualified or not (may repeat).
    fn directions(&self) -> impl Iterator<Item = Direction> + '_ {
        self.targets
            .keys()
            .copied()
            .chain(self.qualified.keys().map(|(dir, _)| *dir))
    }

    /// No entries at all (parse_edge_map rejects such maps).
    fn is_empty(&self) -> bool {
        self.targets.is_empty() && self.qualified.is_empty()
    }
}

/// Parses the repeatable, comma-separated --edge-map values
/// ("right=auto", "bottom@eDP-1=auto", "left=aa11bb,top=laptop") into an
/// EdgeMap. A direction may carry a monitor qualifier
/// ("<direction>@<monitor>=<target>"): the entry then applies only to the
/// exposed segments of the matching output(s) in that direction and
/// overrides an unqualified entry for the same direction there. The
/// qualifier matches an output by name or — when the compositor reports
/// them — by serial, model, or description (see qualifier_matches). It may
/// contain whitespace (descriptions do — "DELL U2720Q"); it is split on
/// ',' and the first '=' and '@' only, so a literal comma, '=', or '@' in
/// a description can't be written — prefer the serial or model form.
pub fn parse_edge_map(specs: &[String]) -> Result<EdgeMap> {
    let mut map = EdgeMap::default();
    for spec in specs {
        for part in spec.split(',') {
            let part = part.trim();
            let (lhs, target) = part.split_once('=').with_context(|| {
                format!(
                    "invalid --edge-map entry '{}': expected <direction>[@<monitor>]=<target>",
                    part
                )
            })?;
            let (dir, monitor) = match lhs.split_once('@') {
                Some((dir, monitor)) => {
                    let monitor = monitor.trim();
                    if monitor.is_empty()
                        || monitor
                            .chars()
                            .any(|c| c == '@' || c == '=' || c == ',')
                    {
                        bail!(
                            "invalid --edge-map entry '{}': invalid monitor qualifier '{}'",
                            part,
                            monitor
                        );
                    }
                    (dir, Some(monitor.to_string()))
                }
                None => (lhs, None),
            };
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
            let replaced = match &monitor {
                Some(monitor) => map.qualified.insert((dir, monitor.clone()), target),
                None => map.targets.insert(dir, target),
            };
            if replaced.is_some() {
                match monitor {
                    Some(monitor) => bail!(
                        "duplicate direction '{}' for monitor '{}' in --edge-map",
                        dir.as_str(),
                        monitor
                    ),
                    None => bail!("duplicate direction '{}' in --edge-map", dir.as_str()),
                }
            }
        }
    }
    if map.is_empty() {
        bail!("--edge-map requires at least one direction=target entry");
    }
    Ok(map)
}

/// Parses --edge-map on the CLIENT: same syntax as the server's, but the
/// only valid target is `auto` (meaning "the server" — a client has exactly
/// one peer), so a fingerprint/hostname target is a config error at startup
/// here rather than a runtime resolution failure.
pub fn parse_client_edge_map(specs: &[String]) -> Result<EdgeMap> {
    let map = parse_edge_map(specs)?;
    for (dir, monitor, target) in map.entries() {
        if *target != EdgeTarget::Auto {
            let edge = match monitor {
                Some(monitor) => format!("{}@{}", dir.as_str(), monitor),
                None => dir.as_str().to_string(),
            };
            bail!(
                "invalid --edge-map target '{}' for the {} edge: on a client the only valid target is 'auto' (the server)",
                target,
                edge
            );
        }
    }
    Ok(map)
}

/// One output's logical rectangle in the compositor's layout coordinate
/// space (scale already applied). Injectable so the geometry is testable
/// without a running compositor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutputRect {
    pub name: String,
    /// The persistent identifiers the compositor reports (Hyprland: the
    /// manufacturer, model, serial, and their composite description — "Dell
    /// Inc. DELL U2720Q 83JLZ23"), empty when it reports none. Unlike the
    /// name, which can change across compositor restarts or GPU changes,
    /// these identify the physical monitor — --edge-map @qualifiers match
    /// them too (see qualifier_matches).
    pub make: String,
    pub model: String,
    pub serial: String,
    pub description: String,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Whether a --edge-map @qualifier names this output: the output name (the
/// default, always available), or one of the persistent identifiers when the
/// compositor reports them (serial, model, or description — `make` alone is
/// too ambiguous to match on; the description embeds it). Exact string
/// match; an empty identifier never matches.
fn qualifier_matches(qualifier: &str, output: &OutputRect) -> bool {
    qualifier == output.name
        || (!output.serial.is_empty() && qualifier == output.serial)
        || (!output.model.is_empty() && qualifier == output.model)
        || (!output.description.is_empty() && qualifier == output.description)
}

/// The outputs of the layout a qualifier matches (see qualifier_matches) —
/// several with identical models (apply the zone to all of them, and warn),
/// none for a typo or an unplugged monitor.
fn matching_outputs<'a>(qualifier: &str, layout: &'a [OutputRect]) -> Vec<&'a OutputRect> {
    layout
        .iter()
        .filter(|output| qualifier_matches(qualifier, output))
        .collect()
}

/// How an output is shown in logs and warnings: the name, plus the
/// persistent identity in brackets when reported — the description, or a
/// synthesized make/model/serial composite when there is no description —
/// so users can see what to put in an --edge-map @qualifier.
fn output_identifiers(output: &OutputRect) -> String {
    let identity = if !output.description.is_empty() {
        output.description.clone()
    } else {
        [
            output.make.as_str(),
            output.model.as_str(),
            output.serial.as_str(),
        ]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<&str>>()
        .join(" ")
    };
    if identity.is_empty() {
        output.name.clone()
    } else {
        format!("{} [{}]", output.name, identity)
    }
}

/// A contiguous exposed piece of one output's boundary: no other output
/// abuts it, so the cursor jams against it (and a trigger zone there sees it).
/// `start`/`len` run along the edge axis in global layout coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EdgeSegment {
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
pub(crate) fn exposed_segments(outputs: &[OutputRect]) -> Vec<EdgeSegment> {
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
                // Tolerate ±1px: fractional scales round each output's
                // dimensions independently, so abutting monitors can be off
                // by a pixel — an exact equality would manufacture a
                // mid-desktop trigger zone in the gap.
                let shares_boundary = match direction {
                    Direction::Right => (q.x - (r.x + r.width)).abs() <= 1,
                    Direction::Left => ((q.x + q.width) - r.x).abs() <= 1,
                    Direction::Bottom => (q.y - (r.y + r.height)).abs() <= 1,
                    Direction::Top => ((q.y + q.height) - r.y).abs() <= 1,
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
pub(crate) const CORNER_TRIM_PERCENT: i32 = 8;

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

/// The Hyprland IPC socket
/// ($XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket.sock), the
/// same channel hyprctl uses — falling back to the newest instance found in
/// the runtime dir when the signature is absent or stale (see
/// socket_path_in). Errors when no live instance is reachable.
fn hyprland_socket_path() -> Result<PathBuf> {
    let runtime_dir = PathBuf::from(
        std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|dir| !dir.is_empty())
            .context("XDG_RUNTIME_DIR is not set (no wayland session?)")?,
    );
    let signature =
        std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").filter(|signature| !signature.is_empty());
    socket_path_in(&runtime_dir.join("hypr"), signature.as_deref())
}

/// Resolves the instance socket under `hypr_dir` (the env-free half of
/// hyprland_socket_path, so the fallbacks are testable).
fn socket_path_in(hypr_dir: &Path, signature: Option<&std::ffi::OsStr>) -> Result<PathBuf> {
    if let Some(signature) = signature {
        let from_signature = hypr_dir.join(signature).join(".socket.sock");
        // The signature is only worth trusting while its socket is there: a
        // daemon outlives compositor restarts, and every restart mints a new
        // signature, so the inherited one goes stale — following it then
        // would poll a socket no compositor is behind.
        if from_signature.exists() {
            return Ok(from_signature);
        }
    }
    // No usable signature. A daemon autostarted with the systemd user
    // manager never gets one at all (the manager starts before the
    // compositor, and a later import-environment doesn't reach services
    // already running). The instance directory is right there in the runtime
    // dir, so find it instead of declaring this "not running under Hyprland".
    newest_hyprland_instance(hypr_dir).with_context(|| {
        format!(
            "no live Hyprland instance in {} (HYPRLAND_INSTANCE_SIGNATURE unset or stale)",
            hypr_dir.display()
        )
    })
}

/// A socket path to move to when `current` has stopped working: the newest
/// live instance, if it isn't the one already in use. Hyprland restarts
/// under a running daemon (a compositor crash, or a deliberate restart)
/// leave the old path dead forever, which used to strand screen-edge
/// switching silently until monux itself was restarted.
fn rebound_hyprland_socket(current: &Path) -> Option<PathBuf> {
    hyprland_socket_path()
        .ok()
        .filter(|resolved| resolved != current)
}

/// The IPC socket of the most recently started Hyprland instance under
/// `hypr_dir`. Newest wins: stale instance directories survive a crash, and
/// on the rare box running two instances the fresh one is the better guess.
fn newest_hyprland_instance(hypr_dir: &Path) -> Result<PathBuf> {
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(hypr_dir)
        .with_context(|| format!("Failed to read {}", hypr_dir.display()))?
        .flatten()
    {
        let socket = entry.path().join(".socket.sock");
        let mtime = match std::fs::metadata(&socket) {
            // Instance directories carry no useful timestamp of their own;
            // the socket's does, and a missing socket also rules out the
            // leftover directory of an instance that's gone.
            Ok(metadata) => metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
            Err(_) => continue,
        };
        if newest.as_ref().is_none_or(|(best, _)| mtime > *best) {
            newest = Some((mtime, socket));
        }
    }
    newest
        .map(|(_, socket)| socket)
        .context("no Hyprland instance socket found")
}

/// How long the edge manager waits between attempts while Hyprland isn't
/// reachable yet (see wait_for_hyprland).
const HYPRLAND_WAIT_INTERVAL: Duration = Duration::from_secs(10);

/// Resolves the Hyprland IPC socket and queries the initial monitor layout,
/// waiting for the compositor instead of giving up on it. An edge manager
/// only runs when the user configured an edge map, so "Hyprland isn't there
/// yet" is a state to wait out: a daemon autostarted with the systemd user
/// manager starts at login, before the compositor exists, and giving up
/// there left screen-edge switching dead for the whole session (the same
/// startup order that used to kill clipboard sharing, see
/// clipboard::wayland::connect). Only ever returns once Hyprland answers;
/// the caller's task is dropped with the daemon.
async fn wait_for_hyprland() -> (PathBuf, Vec<OutputRect>) {
    // Only the first failure of a streak warns: the retry is silent
    // afterwards so a machine that never gets Hyprland doesn't fill the log.
    let mut reported = false;
    loop {
        match hyprland_socket_path() {
            Ok(socket) => {
                let socket_for_layout = socket.clone();
                match tokio::task::spawn_blocking(move || hyprland_layout(&socket_for_layout)).await {
                    Ok(Ok(layout)) if !layout.is_empty() => return (socket, layout),
                    Ok(Ok(_)) => report_hyprland_wait(&mut reported, "Hyprland reports no outputs"),
                    Ok(Err(e)) => report_hyprland_wait(&mut reported, &format!("{:#}", e)),
                    Err(e) => {
                        report_hyprland_wait(&mut reported, &format!("layout query panicked: {:#}", e))
                    }
                }
            }
            Err(e) => report_hyprland_wait(&mut reported, &format!("{:#}", e)),
        }
        tokio::time::sleep(HYPRLAND_WAIT_INTERVAL).await;
    }
}

/// Logs one wait reason: a warning for the first of a streak, debug after.
fn report_hyprland_wait(reported: &mut bool, reason: &str) {
    if *reported {
        debug!("Screen-edge switching still waiting for Hyprland: {}", reason);
        return;
    }
    warn!(
        "Screen-edge switching waiting for Hyprland (retrying every {:?}): {}",
        HYPRLAND_WAIT_INTERVAL, reason
    );
    *reported = true;
}

/// Runs one command against Hyprland's IPC socket: connect, send the
/// command, half-close the write side, read the reply to EOF. One-shot per
/// query: the compositor closes the connection after each reply (verified
/// empirically — hyprctl --batch's single connection works only because all
/// its commands go out in ONE write), so each query reconnects.
fn hyprland_query(socket: &Path, cmd: &[u8]) -> Result<String> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("Failed to connect to Hyprland IPC at {}", socket.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("Failed to configure Hyprland IPC socket")?;
    let query = String::from_utf8_lossy(cmd);
    stream
        .write_all(cmd)
        .with_context(|| format!("Failed to query Hyprland '{}'", query))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .with_context(|| format!("Failed to finish the Hyprland '{}' query", query))?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .with_context(|| format!("Failed to read the Hyprland '{}' reply", query))?;
    Ok(reply)
}

/// Queries the monitor layout from Hyprland's IPC socket (see
/// hyprland_socket_path). Errors when not running under Hyprland.
pub(crate) fn hyprland_layout(socket: &Path) -> Result<Vec<OutputRect>> {
    // "j/monitors" is the JSON variant of the monitors request.
    parse_monitors_json(&hyprland_query(socket, b"j/monitors")?)
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
        let (x, y, mut width, mut height) = (
            get_i64("x")?,
            get_i64("y")?,
            get_i64("width")?,
            get_i64("height")?,
        );
        // Hyprland reports the native (pre-rotation) mode size. Odd transforms
        // (90°/270° and their flipped variants) rotate the output, so the
        // logical width and height are swapped relative to the mode.
        let transform = monitor["transform"].as_i64().unwrap_or(0);
        if transform % 2 == 1 {
            std::mem::swap(&mut width, &mut height);
        }
        let scale = monitor["scale"]
            .as_f64()
            .filter(|s| *s > 0.0)
            .unwrap_or(1.0);
        // The persistent identifiers (see OutputRect) are optional: a
        // compositor reporting none degrades silently to name-only
        // qualifier matching.
        let get_str = |key: &str| -> String { monitor[key].as_str().unwrap_or("").to_string() };
        outputs.push(OutputRect {
            name,
            make: get_str("make"),
            model: get_str("model"),
            serial: get_str("serial"),
            description: get_str("description"),
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
pub(crate) struct DwellTimer {
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
    for candidate in lookup_candidates(name) {
        if let Ok(addrs) = (candidate.as_str(), 0).to_socket_addrs() {
            ips.extend(addrs.map(|addr| addr.ip()));
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

/// The names resolve_hostname looks up, in order: the name itself, plus its
/// `.local` mDNS variant unless it already ends in `.local` — a target
/// written as `laptop.local` needs no useless second blocking lookup of
/// `laptop.local.local`. A free function so the candidate selection is
/// testable without system lookups.
fn lookup_candidates(name: &str) -> Vec<String> {
    let mut candidates = vec![name.to_string()];
    if !name.ends_with(".local") {
        candidates.push(format!("{}.local", name));
    }
    candidates
}

/// Cache of hostname → resolved IPs for --edge-map hostname targets, so the
/// async loops (rotation, edge manager) never run a blocking getaddrinfo
/// themselves (resolve_hostname does one per call): a DNS-missing name would
/// otherwise stall input routing for seconds, multiplied by directions ×
/// clients. The sync resolution passes read only the cache — a miss means
/// "unresolvable" for that pass — and queue a refresh that re-resolves on
/// the blocking thread pool, so the filled cache serves the NEXT pass. (The
/// edge fire path needs no cache: it already resolves inside spawn_blocking.)
#[derive(Default)]
pub struct ResolveCache {
    /// Hostname → last resolved IPs (an empty vec = resolved to nothing).
    ips: RwLock<BTreeMap<String, Vec<IpAddr>>>,
    /// Hostnames a queued refresh is already resolving: dedupes the
    /// back-to-back refreshes of client add/remove bursts while DNS is slow.
    pending: Mutex<BTreeSet<String>>,
}

impl ResolveCache {
    /// A resolver for resolve_edge_target that reads only the cache: a miss
    /// yields no IPs, i.e. "unresolvable" for this pass (the refresh queued
    /// alongside the pass serves the next one).
    pub fn resolver(self: &Arc<Self>) -> impl Fn(&str) -> Vec<IpAddr> {
        let cache = Arc::clone(self);
        move |name| {
            cache
                .ips
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(name)
                .cloned()
                .unwrap_or_default()
        }
    }

    /// Re-resolves every Named target of `map` on the blocking thread pool,
    /// filling the cache for later passes (see hostname_targets for why
    /// fingerprint prefixes ride along). 'auto' needs no resolution.
    pub fn queue_map_refresh(self: &Arc<Self>, map: &EdgeMap) {
        self.queue_refresh(hostname_targets(map), resolve_hostname);
    }

    /// Queues a background re-resolution of `names` (see queue_map_refresh),
    /// deduped against refreshes already in flight. `resolve` is the system
    /// resolver in production, a fake in tests. Without a tokio runtime the
    /// refresh runs inline instead (production call sites all have one).
    fn queue_refresh(self: &Arc<Self>, names: Vec<String>, resolve: fn(&str) -> Vec<IpAddr>) {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let names: Vec<String> = names
            .into_iter()
            .filter(|name| pending.insert(name.clone()))
            .collect();
        drop(pending);
        if names.is_empty() {
            return;
        }
        let cache = Arc::clone(self);
        let spawn = move || {
            let resolved: Vec<(String, Vec<IpAddr>)> = names
                .into_iter()
                .map(|name| {
                    let ips = resolve(&name);
                    (name, ips)
                })
                .collect();
            {
                let mut ips = cache.ips.write().unwrap_or_else(|e| e.into_inner());
                for (name, addrs) in &resolved {
                    ips.insert(name.clone(), addrs.clone());
                }
            }
            let mut pending = cache.pending.lock().unwrap_or_else(|e| e.into_inner());
            for (name, _) in resolved {
                pending.remove(&name);
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(spawn);
            }
            Err(_) => spawn(),
        }
    }
}

/// The Named targets of an edge map — the only targets needing system
/// resolution ('auto' resolves locally against the client list). A Named
/// target may still be a fingerprint prefix (matched locally first); the
/// harmless background lookup for those just fills an unread cache entry.
fn hostname_targets(map: &EdgeMap) -> Vec<String> {
    map.entries()
        .filter_map(|(_, _, target)| match target {
            EdgeTarget::Named(name) => Some(name.clone()),
            EdgeTarget::Auto => None,
        })
        .collect()
}

/// How often the cursor position is polled from Hyprland's IPC.
const POLL_INTERVAL: Duration = Duration::from_millis(40);

/// How long the poller waits after a failed query before retrying.
const POLL_FAILURE_BACKOFF: Duration = Duration::from_millis(500);

/// Queries the cursor position from Hyprland's IPC (see hyprland_query for
/// why each poll reconnects).
fn cursor_position(socket: &Path) -> Result<(i32, i32)> {
    parse_cursorpos(&hyprland_query(socket, b"cursorpos")?)
}

/// Parses Hyprland's cursorpos reply ("x, y"; coordinates can be negative
/// when outputs sit left of/above the layout origin).
fn parse_cursorpos(reply: &str) -> Result<(i32, i32)> {
    let reply = reply.trim();
    let (x, y) = reply
        .split_once(',')
        .with_context(|| format!("unexpected cursorpos reply '{}'", reply))?;
    let x = x
        .trim()
        .parse::<i32>()
        .with_context(|| format!("unexpected cursorpos reply '{}'", reply))?;
    let y = y
        .trim()
        .parse::<i32>()
        .with_context(|| format!("unexpected cursorpos reply '{}'", reply))?;
    Ok((x, y))
}

/// Polls the cursor position every POLL_INTERVAL and forwards it to the edge
/// manager; a failed query is logged at debug and retried after
/// POLL_FAILURE_BACKOFF. Runs on its own thread (blocking socket IO) and
/// ends when the edge manager is gone (server shutting down).
///
/// A failing poll also looks for a newer Hyprland instance and follows it
/// (see rebound_hyprland_socket), so a compositor restart resumes edge
/// switching instead of leaving the poller talking to a dead socket. The
/// path is shared with the manager's layout requery, which follows along.
fn run_cursor_poller(socket: Arc<Mutex<PathBuf>>, pos_tx: mpsc::UnboundedSender<(i32, i32)>) {
    loop {
        let path = socket.lock().unwrap_or_else(|e| e.into_inner()).clone();
        match cursor_position(&path) {
            Ok(pos) => {
                if pos_tx.send(pos).is_err() {
                    return;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                debug!(
                    "Screen-edge cursor poll failed ({:#}), retrying in {:?}",
                    e, POLL_FAILURE_BACKOFF
                );
                if let Some(rebound) = rebound_hyprland_socket(&path) {
                    info!(
                        "Screen-edge switching following the new Hyprland instance at {}",
                        rebound.display()
                    );
                    *socket.lock().unwrap_or_else(|e| e.into_inner()) = rebound;
                }
                std::thread::sleep(POLL_FAILURE_BACKOFF);
            }
        }
    }
}

/// How far beyond an edge line the cursor still counts as "on the edge", in
/// logical pixels. 0 = the cursor must reach the very edge: left x <= 0,
/// right x >= the output's last column (and likewise for top/bottom rows).
pub(crate) const EDGE_TRIGGER_PX: i32 = 0;

/// A trigger zone: one exposed, corner-trimmed segment of one output's edge,
/// in global layout coordinates. The cursor is on the zone's edge when its
/// coordinate crosses the edge line while its along-axis coordinate lies
/// within [start, start + len).
#[derive(Clone, Debug, PartialEq, Eq)]
struct EdgeZone {
    direction: Direction,
    output: String,
    /// The edge-map entry this zone fires (a direction can map different
    /// targets per monitor via qualified entries).
    target: EdgeTarget,
    /// The edge line: the output's first (left/top) or last (right/bottom)
    /// pixel column/row on that side.
    edge: i32,
    /// Range start along the edge axis (y for left/right, x for top/bottom).
    start: i32,
    len: i32,
}

/// Whether the cursor at (x, y) is on this zone's edge.
fn zone_contains(zone: &EdgeZone, x: i32, y: i32) -> bool {
    let along = match zone.direction {
        Direction::Left | Direction::Right => y,
        Direction::Top | Direction::Bottom => x,
    };
    if along < zone.start || along >= zone.start + zone.len {
        return false;
    }
    match zone.direction {
        Direction::Left => x <= zone.edge + EDGE_TRIGGER_PX,
        Direction::Right => x >= zone.edge - EDGE_TRIGGER_PX,
        Direction::Top => y <= zone.edge + EDGE_TRIGGER_PX,
        Direction::Bottom => y >= zone.edge - EDGE_TRIGGER_PX,
    }
}

/// Where along a zone's range the cursor at (x, y) sits, as a fraction
/// (0.0..=1.0): the y fraction for left/right edges, the x fraction for
/// top/bottom. Sent with the client's return request (see
/// ClientEvent::SwitchRequest; reserved for future cursor warping — the
/// server ignores it for now).
fn edge_fraction(zone: &EdgeZone, x: i32, y: i32) -> f64 {
    let along = match zone.direction {
        Direction::Left | Direction::Right => y,
        Direction::Top | Direction::Bottom => x,
    };
    ((along - zone.start) as f64 / zone.len as f64).clamp(0.0, 1.0)
}

/// Turns a layout into trigger zones for the mapped directions: exposed
/// segments only, corner dead zones applied. A segment gets a zone only when
/// an entry covers it: a qualified entry matching the segment's output
/// (see qualifier_matches) first, then the unqualified entry for the
/// direction — so a qualified-only direction leaves the other outputs'
/// segments in that direction inert, and a qualifier matching several
/// outputs zones all of them.
fn edge_zones(map: &EdgeMap, layout: &[OutputRect]) -> Vec<EdgeZone> {
    let mut zones = Vec::new();
    for segment in exposed_segments(layout) {
        let Some(output) = layout.iter().find(|o| o.name == segment.output) else {
            continue;
        };
        let Some(target) = map.target_for(segment.direction, output) else {
            continue;
        };
        let target = target.clone();
        let Some(segment) = trim_corner_dead_zones(segment) else {
            continue;
        };
        let edge = match segment.direction {
            Direction::Left => output.x,
            Direction::Right => output.x + output.width - 1,
            Direction::Top => output.y,
            Direction::Bottom => output.y + output.height - 1,
        };
        zones.push(EdgeZone {
            direction: segment.direction,
            output: segment.output,
            target,
            edge,
            start: segment.start,
            len: segment.len,
        });
    }
    zones
}

/// Warns about qualifiers that match NO output (a typo, or a monitor
/// currently unplugged — such entries never produce a zone) or SEVERAL
/// (the zone applies to all of them; suggest the serial to pick one).
/// `warned` carries qualifier → match count at the last warning across the
/// periodic layout re-queries, so an unchanged situation stays quiet, but
/// a qualifier that recovers (the monitor is plugged in, or the duplicate
/// is removed) and breaks again reports again.
fn warn_qualifier_issues(map: &EdgeMap, layout: &[OutputRect], warned: &mut BTreeMap<String, usize>) {
    let qualifiers: BTreeSet<&str> = map
        .qualified
        .keys()
        .map(|(_, qualifier)| qualifier.as_str())
        .collect();
    for qualifier in qualifiers {
        let matches = matching_outputs(qualifier, layout);
        match matches.len() {
            1 => {
                warned.remove(qualifier);
            }
            n if warned.get(qualifier) == Some(&n) => {}
            0 => {
                warn!(
                    "edge-map: no output matching '{}' in the current layout (outputs: {})",
                    qualifier,
                    layout
                        .iter()
                        .map(output_identifiers)
                        .collect::<Vec<String>>()
                        .join(", ")
                );
                warned.insert(qualifier.to_string(), 0);
            }
            n => {
                warn!(
                    "edge-map: '{}' matches {} outputs ({}); use the serial to pick one",
                    qualifier,
                    n,
                    matches
                        .iter()
                        .map(|output| output.name.as_str())
                        .collect::<Vec<&str>>()
                        .join(", ")
                );
                warned.insert(qualifier.to_string(), n);
            }
        }
    }
}

/// Logs the trigger zones, one per line — or the warning that --edge-map
/// matches no exposed segment on the current layout.
fn log_zones(zones: &[EdgeZone]) {
    if zones.is_empty() {
        warn!("Screen-edge switching: no exposed screen-edge segments match --edge-map on the current monitor layout");
        return;
    }
    for zone in zones {
        info!(
            "Screen-edge switching: watching the {} edge of {} ({} {}..{})",
            zone.direction.as_str(),
            zone.output,
            match zone.direction {
                Direction::Left | Direction::Right => "y",
                Direction::Top | Direction::Bottom => "x",
            },
            zone.start,
            zone.start + zone.len
        );
    }
}

/// Consecutive equal poll outcomes required before a direction's on/off
/// state transitions: single-poll jitter (the cursor grazing a zone
/// boundary) never reaches the dwell timer.
const STABLE_POLLS: u32 = 2;

/// Per-direction edge-contact debouncer (see STABLE_POLLS): being on the
/// edge is the Enter equivalent, leaving it the Leave equivalent. Pure over
/// successive poll outcomes so the transition logic is testable.
struct EdgeDebounce {
    /// The committed state (true = cursor on the edge).
    on: bool,
    /// The candidate state and how many consecutive polls reported it.
    candidate: Option<bool>,
    streak: u32,
}

impl EdgeDebounce {
    fn new() -> Self {
        Self {
            on: false,
            candidate: None,
            streak: 0,
        }
    }

    /// Feeds one poll outcome; returns Some(state) when the committed state
    /// transitioned.
    fn poll(&mut self, on: bool) -> Option<bool> {
        if on == self.on {
            self.candidate = None;
            self.streak = 0;
            return None;
        }
        if self.candidate == Some(on) {
            self.streak += 1;
        } else {
            self.candidate = Some(on);
            self.streak = 1;
        }
        if self.streak >= STABLE_POLLS {
            self.on = on;
            self.candidate = None;
            self.streak = 0;
            Some(on)
        } else {
            None
        }
    }
}

/// How often the monitor layout is re-queried; a change recomputes the
/// trigger zones.
const LAYOUT_REQUERY_INTERVAL: Duration = Duration::from_secs(30);

/// What a completed dwell fires. Server mode resolves the edge's target and
/// fires Event::SwitchTo into the rotation; client mode asks the server to
/// take input back, carrying the fraction along the edge where the cursor
/// crossed (see ClientEvent::SwitchRequest).
enum Fire {
    /// Server mode: the rotation's event queue.
    Event(mpsc::Sender<Event>),
    /// Client mode: the queue the client connection's event loop drains onto
    /// its events stream; closed means the connection (and with it the
    /// receiver) is gone — detection goes quiet while disconnected.
    Request(mpsc::UnboundedSender<f64>),
}

/// The edge manager task, server mode: spawns the cursor poller, owns the
/// trigger zones, the dwell state machines, target resolution, and the
/// periodic layout re-query. Exits (disabling the feature) when Hyprland's
/// IPC is unavailable; otherwise runs until the server shuts down.
pub async fn run(
    map: EdgeMap,
    dwell: Duration,
    event_tx: mpsc::Sender<Event>,
    clients_rx: watch::Receiver<Vec<(SocketAddr, String)>>,
) {
    run_inner(map, dwell, Fire::Event(event_tx), Some(clients_rx)).await
}

/// The edge manager task, client mode: same detection as the server, but a
/// completed dwell sends the server a return request (the fraction along the
/// edge) instead of switching to a client. Spawned per connection: it exits
/// when the connection's request receiver is dropped, so detection is quiet
/// while disconnected.
pub async fn run_client(map: EdgeMap, dwell: Duration, request_tx: mpsc::UnboundedSender<f64>) {
    run_inner(map, dwell, Fire::Request(request_tx), None).await
}

/// The shared edge manager loop (see run / run_client). `clients_rx` is the
/// live client list the server resolves targets against; None in client
/// mode, where the one peer (the server) needs no resolution.
async fn run_inner(
    map: EdgeMap,
    dwell: Duration,
    fire: Fire,
    mut clients_rx: Option<watch::Receiver<Vec<(SocketAddr, String)>>>,
) {
    // The socket path is resolved once here, at manager start, instead of on
    // every 40ms cursor poll (what it derives from is fixed for the lifetime
    // of the session).
    let (socket, layout) = wait_for_hyprland().await;
    // Shared with the cursor poller, which re-resolves it across compositor
    // restarts (see run_cursor_poller); the layout requery below follows the
    // same path so both talk to the live instance.
    let socket = Arc::new(Mutex::new(socket));
    info!(
        "Screen-edge switching enabled (dwell {:?}, cooldown {:?}): {}",
        dwell,
        REARM_COOLDOWN,
        map.entries()
            .map(|(dir, monitor, target)| match monitor {
                Some(monitor) => format!("{}@{}={}", dir.as_str(), monitor, target),
                None => format!("{}={}", dir.as_str(), target),
            })
            .collect::<Vec<String>>()
            .join(", ")
    );
    log_layout(&layout);
    let (pos_tx, mut pos_rx) = mpsc::unbounded_channel::<(i32, i32)>();
    let poller_socket = socket.clone();
    std::thread::spawn(move || run_cursor_poller(poller_socket, pos_tx));
    let mut zones = edge_zones(&map, &layout);
    log_zones(&zones);
    // Qualifiers matching no or several outputs warn on change only (see
    // warn_qualifier_issues).
    let mut qualifier_warnings = BTreeMap::new();
    warn_qualifier_issues(&map, &layout, &mut qualifier_warnings);
    let mut current_layout = layout;

    // Per-direction state: the debouncer turns polled edge contact into
    // enter/leave equivalents that drive the dwell timer.
    struct DirState {
        timer: DwellTimer,
        debounce: EdgeDebounce,
        deadline: Option<Instant>,
        /// Set after firing; cleared only by a committed leave. While a
        /// switch doesn't take effect (paused, target offline) or the cursor
        /// stays parked at the edge after a successful switch (it's frozen
        /// there while input is forwarded), an unlatched timer would re-fire
        /// on every contact flap.
        latched: bool,
    }
    let mut dirs: HashMap<Direction, DirState> = map
        .directions()
        .map(|dir| {
            (
                dir,
                DirState {
                    timer: DwellTimer::new(dwell, REARM_COOLDOWN),
                    debounce: EdgeDebounce::new(),
                    deadline: None,
                    latched: false,
                },
            )
        })
        .collect();
    // Hostname targets resolve off-loop through this cache (see ResolveCache):
    // the resolution passes below read it, its refreshes fill it.
    let resolve_cache = Arc::new(ResolveCache::default());
    if let Some(rx) = &clients_rx {
        log_edge_resolutions(&map, &rx.borrow(), &resolve_cache);
    }
    // The last polled cursor position: client mode reads the crossing
    // fraction off it at fire time.
    let mut last_pos: Option<(i32, i32)> = None;

    let mut requery = time::interval(LAYOUT_REQUERY_INTERVAL);
    // Skip the immediate first tick; the startup query just ran.
    requery.tick().await;
    loop {
        let next_deadline = dirs.values().filter_map(|state| state.deadline).min();
        tokio::select! {
            pos = pos_rx.recv() => {
                let Some((x, y)) = pos else {
                    warn!("Screen-edge switching disabled: the cursor poller is gone");
                    return;
                };
                last_pos = Some((x, y));
                let now = Instant::now();
                for (dir, state) in dirs.iter_mut() {
                    let on = zones
                        .iter()
                        .any(|zone| zone.direction == *dir && zone_contains(zone, x, y));
                    match state.debounce.poll(on) {
                        Some(true) => {
                            // A fire latches until a committed leave: don't
                            // re-arm the dwell while the last switch is still
                            // waiting for the cursor to actually leave.
                            if !state.latched {
                                state.deadline = state.timer.enter(now);
                            }
                        }
                        Some(false) => {
                            state.latched = false;
                            state.timer.leave();
                            state.deadline = None;
                        }
                        None => {}
                    }
                }
            }
            // Server mode only: re-log target resolutions on client
            // (dis)connect. Pending forever in client mode (no client list).
            changed = async {
                match &mut clients_rx {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                if changed.is_err() {
                    // The rotation loop is gone: the server is shutting down.
                    return;
                }
                if let Some(rx) = &clients_rx {
                    log_edge_resolutions(&map, &rx.borrow(), &resolve_cache);
                }
            }
            // Client mode only: the request receiver was dropped with the
            // connection — go quiet until a new connection respawns us.
            _ = async {
                match &fire {
                    Fire::Request(request_tx) => request_tx.closed().await,
                    Fire::Event(_) => std::future::pending().await,
                }
            } => {
                debug!("Screen-edge switching: connection gone, edge detection off");
                return;
            }
            _ = requery.tick() => {
                let socket_for_requery = socket.lock().unwrap_or_else(|e| e.into_inner()).clone();
                match tokio::task::spawn_blocking(move || hyprland_layout(&socket_for_requery)).await {
                    Ok(Ok(new_layout)) if !new_layout.is_empty() => {
                        if new_layout != current_layout {
                            info!("Screen-edge switching: monitor layout changed, recomputing edge zones");
                            log_layout(&new_layout);
                            zones = edge_zones(&map, &new_layout);
                            log_zones(&zones);
                            warn_qualifier_issues(&map, &new_layout, &mut qualifier_warnings);
                            current_layout = new_layout;
                            // Contact states measured against the old layout's
                            // zones are meaningless under the new one.
                            for state in dirs.values_mut() {
                                state.debounce = EdgeDebounce::new();
                                state.deadline = None;
                                state.latched = false;
                                state.timer.leave();
                            }
                        }
                    }
                    Ok(Ok(_)) => {
                        warn!("Screen-edge switching: Hyprland layout re-query returned no outputs, keeping existing zones");
                    }
                    Ok(Err(e)) => {
                        warn!("Screen-edge switching: Hyprland layout re-query failed ({:#}), keeping existing zones", e);
                    }
                    Err(e) => {
                        warn!("Screen-edge switching: Hyprland layout re-query panicked ({:#}), keeping existing zones", e);
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
                    // Latch until a committed leave so a switch that doesn't
                    // take effect (paused, target offline) — or a cursor left
                    // parked at the edge after a successful switch — doesn't
                    // re-fire on every contact flap.
                    state.deadline = None;
                    state.latched = true;
                    // Require fresh contact at fire time: the debounce needs
                    // STABLE_POLLS consecutive off-polls to commit a leave,
                    // so the dwell deadline can arrive before leave() is
                    // called. If the cursor already left the zone, skip.
                    if let Some((x, y)) = last_pos {
                        if !zones.iter().any(|zone| zone.direction == *dir && zone_contains(zone, x, y)) {
                            debug!("Edge switch via {} edge skipped: cursor left before the dwell completed", dir.as_str());
                            continue;
                        }
                    }
                    match &fire {
                        Fire::Event(event_tx) => {
                            let clients = clients_rx
                                .as_ref()
                                .expect("server mode always carries the client list")
                                .borrow()
                                .clone();
                            // The zone under the cursor decides the target:
                            // qualified entries can map one direction to
                            // different targets per monitor, and a
                            // qualified-only direction has no unqualified
                            // entry at all.
                            let target = last_pos.and_then(|(x, y)| {
                                zones
                                    .iter()
                                    .find(|zone| zone.direction == *dir && zone_contains(zone, x, y))
                                    .map(|zone| zone.target.clone())
                            });
                            let Some(target) = target else {
                                // A deadline arms only after polls, so a
                                // position always exists here — but without
                                // a zone there is no target to resolve.
                                debug!("Edge switch via {} edge skipped: no zone under the cursor", dir.as_str());
                                continue;
                            };
                            // resolve_hostname does blocking getaddrinfo — run
                            // it off the async executor (only 2 worker threads;
                            // one may already be blockable by cert prompts).
                            match tokio::task::spawn_blocking(move || {
                                resolve_edge_target(&target, &clients, &resolve_hostname)
                            }).await {
                                Ok(Ok(fingerprint)) => {
                                    // The rotation logs the switch itself (or
                                    // why it was ignored, e.g. paused) — this
                                    // is only the request.
                                    debug!("Edge switch to client {} requested via {} edge", fingerprint, dir.as_str());
                                    if let Err(e) = event_tx.send(Event::SwitchTo(fingerprint)).await {
                                        warn!("Failed to submit edge switch event: {:?}", e);
                                    }
                                }
                                Ok(Err(e)) => {
                                    warn!("Edge switch via {} edge did not fire: {}", dir.as_str(), e);
                                }
                                Err(e) => {
                                    warn!("Edge switch via {} edge resolution panicked: {:#}", dir.as_str(), e);
                                }
                            }
                        }
                        Fire::Request(request_tx) => {
                            // Where along the edge the cursor crossed, off the
                            // last polled position inside this direction's
                            // zone (0.5 if it slipped out between polls).
                            let y_fraction = last_pos
                                .and_then(|(x, y)| {
                                    zones
                                        .iter()
                                        .find(|zone| zone.direction == *dir && zone_contains(zone, x, y))
                                        .map(|zone| edge_fraction(zone, x, y))
                                })
                                .unwrap_or(0.5);
                            info!("Edge switch request to server via {} edge", dir.as_str());
                            if request_tx.send(y_fraction).is_err() {
                                // The connection (and its receiver) is gone.
                                debug!("Screen-edge switching: connection gone, edge detection off");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Logs the monitor layout in one line, with each output's identifiers
/// (see output_identifiers) so --edge-map @qualifiers are discoverable.
fn log_layout(layout: &[OutputRect]) {
    info!(
        "Screen-edge switching: monitor layout: {}",
        layout
            .iter()
            .map(|o| format!("{} {}x{}@({},{})", output_identifiers(o), o.width, o.height, o.x, o.y))
            .collect::<Vec<String>>()
            .join(", ")
    );
}

/// Resolves every mapped target against the current client list and logs the
/// outcome — at startup and on every client (dis)connect, so the mapping is
/// visible before anyone pushes the cursor into an edge. Hostname targets
/// resolve against the ResolveCache (never blocking getaddrinfo here: this
/// runs while the clients watch read guard is held); a cache miss logs as
/// unresolvable for this pass and the queued refresh serves the next.
fn log_edge_resolutions(
    map: &EdgeMap,
    clients: &[(SocketAddr, String)],
    resolve_cache: &Arc<ResolveCache>,
) {
    resolve_cache.queue_map_refresh(map);
    let resolver = resolve_cache.resolver();
    for (dir, monitor, target) in map.entries() {
        let edge = match monitor {
            Some(monitor) => format!("{}@{}", dir.as_str(), monitor),
            None => dir.as_str().to_string(),
        };
        match resolve_edge_target(target, clients, &resolver) {
            Ok(fingerprint) => info!(
                "Screen-edge switching: {} edge → client {} (target '{}')",
                edge,
                fingerprint,
                target
            ),
            Err(e) => warn!(
                "Screen-edge switching: {} edge target '{}' is not resolvable right now: {}",
                edge,
                target,
                e
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// An instance dir holding a socket with the given mtime, as the runtime
    /// dir looks while an instance is alive.
    fn hyprland_instance(hypr_dir: &Path, signature: &str, mtime_secs: u64) {
        let dir = hypr_dir.join(signature);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join(".socket.sock");
        std::fs::write(&socket, "").unwrap();
        let mtime = std::time::UNIX_EPOCH + Duration::from_secs(mtime_secs);
        std::fs::File::options()
            .write(true)
            .open(&socket)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(mtime))
            .unwrap();
    }

    /// A signature naming a live instance is used as-is; one left over from
    /// a restarted compositor is dropped for the instance that's actually
    /// there (the daemon-outlives-Hyprland case).
    #[test]
    fn a_stale_signature_falls_back_to_the_live_instance() {
        let tmp = tempfile::tempdir().unwrap();
        let hypr_dir = tmp.path().join("hypr");
        hyprland_instance(&hypr_dir, "live_instance", 2_000);

        assert_eq!(
            socket_path_in(&hypr_dir, Some(OsStr::new("live_instance"))).unwrap(),
            hypr_dir.join("live_instance").join(".socket.sock")
        );
        assert_eq!(
            socket_path_in(&hypr_dir, Some(OsStr::new("gone_with_the_old_session"))).unwrap(),
            hypr_dir.join("live_instance").join(".socket.sock")
        );
        // Nothing live at all: an error, so the caller keeps waiting.
        std::fs::remove_dir_all(hypr_dir.join("live_instance")).unwrap();
        assert!(socket_path_in(&hypr_dir, Some(OsStr::new("live_instance"))).is_err());
    }

    /// The signature-less fallback picks the live instance, not a stale
    /// directory left behind by an earlier one.
    #[test]
    fn the_newest_hyprland_instance_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let hypr_dir = tmp.path().join("hypr");
        hyprland_instance(&hypr_dir, "old_crashed_instance", 1_000);
        hyprland_instance(&hypr_dir, "live_instance", 2_000);
        // A leftover directory whose socket is gone is not a candidate.
        std::fs::create_dir_all(hypr_dir.join("socketless_instance")).unwrap();

        assert_eq!(
            newest_hyprland_instance(&hypr_dir).unwrap(),
            hypr_dir.join("live_instance").join(".socket.sock")
        );
    }

    /// The fallback's real target: with no HYPRLAND_INSTANCE_SIGNATURE to go
    /// by (an autostarted daemon's situation), the discovered socket must be
    /// the live compositor's — it answers a monitors query. Runs only under a
    /// running Hyprland; elsewhere there is nothing to discover.
    #[test]
    fn a_discovered_instance_socket_answers_queries() {
        let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") else {
            return;
        };
        let hypr_dir = PathBuf::from(runtime_dir).join("hypr");
        let Ok(socket) = newest_hyprland_instance(&hypr_dir) else {
            return;
        };
        let layout = hyprland_layout(&socket).expect("the discovered socket answers j/monitors");
        assert!(!layout.is_empty(), "a live Hyprland reports at least one output");
    }

    #[test]
    fn no_hyprland_instance_is_an_error_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let hypr_dir = tmp.path().join("hypr");
        // Missing dir (no Hyprland ever), then an empty one (all gone).
        assert!(newest_hyprland_instance(&hypr_dir).is_err());
        std::fs::create_dir_all(&hypr_dir).unwrap();
        assert!(newest_hyprland_instance(&hypr_dir).is_err());
    }

    fn rect(name: &str, x: i32, y: i32, width: i32, height: i32) -> OutputRect {
        OutputRect {
            name: name.to_string(),
            make: String::new(),
            model: String::new(),
            serial: String::new(),
            description: String::new(),
            x,
            y,
            width,
            height,
        }
    }

    /// An output with the persistent identifiers Hyprland reports (see
    /// OutputRect), for the qualifier-matching tests.
    fn rect_id(
        name: &str,
        make: &str,
        model: &str,
        serial: &str,
        description: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) -> OutputRect {
        OutputRect {
            make: make.to_string(),
            model: model.to_string(),
            serial: serial.to_string(),
            description: description.to_string(),
            ..rect(name, x, y, width, height)
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
    fn monitors_json_reads_the_persistent_identifiers() {
        let json = r#"[
            {"name": "eDP-1", "x": 0, "y": 0, "width": 1920, "height": 1080, "scale": 1.0,
             "make": "Dell Inc.", "model": "DELL U2720Q", "serial": "83JLZ23",
             "description": "Dell Inc. DELL U2720Q 83JLZ23"},
            {"name": "DP-3", "x": 1920, "y": 0, "width": 1920, "height": 1080, "scale": 1.0}
        ]"#;
        let outputs = parse_monitors_json(json).unwrap();
        assert_eq!(
            outputs[0],
            rect_id(
                "eDP-1",
                "Dell Inc.",
                "DELL U2720Q",
                "83JLZ23",
                "Dell Inc. DELL U2720Q 83JLZ23",
                0,
                0,
                1920,
                1080
            )
        );
        // A compositor reporting no identifiers degrades to empty strings
        // (name-only qualifier matching; see qualifier_matches).
        assert_eq!(outputs[1], rect("DP-3", 1920, 0, 1920, 1080));
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
    fn lookup_candidates_skip_the_local_local_lookup() {
        // A bare name is looked up itself and via its .local mDNS variant.
        assert_eq!(
            lookup_candidates("laptop"),
            vec!["laptop".to_string(), "laptop.local".to_string()]
        );
        // A target already written as .local is looked up only as written:
        // laptop.local.local never resolves and costs a blocking lookup.
        assert_eq!(
            lookup_candidates("laptop.local"),
            vec!["laptop.local".to_string()]
        );
    }

    #[test]
    fn edge_map_hostnames_are_the_named_targets() {
        let map = parse_edge_map(&["left=laptop,right=auto".to_string()]).unwrap();
        assert_eq!(hostname_targets(&map), vec!["laptop".to_string()]);
        let map = parse_edge_map(&["left=aa11bb,bottom=desk".to_string()]).unwrap();
        assert_eq!(
            hostname_targets(&map),
            vec!["aa11bb".to_string(), "desk".to_string()]
        );
    }

    #[test]
    fn edge_map_hostnames_include_qualified_targets() {
        // Qualified Named targets resolve exactly like unqualified ones:
        // hostname resolution ignores the qualifier.
        let map = parse_edge_map(&["left@eDP-1=laptop,bottom=desk,right=auto".to_string()]).unwrap();
        // Unqualified entries first (direction order), then qualified ones.
        assert_eq!(
            hostname_targets(&map),
            vec!["desk".to_string(), "laptop".to_string()]
        );
    }

    /// Miss-then-hit: a cache miss resolves to "unresolvable" for that pass;
    /// the queued refresh fills the cache and the NEXT pass resolves. (No
    /// runtime here, so the refresh runs inline — see queue_refresh.)
    #[test]
    fn resolve_cache_miss_then_hit() {
        let cache = Arc::new(ResolveCache::default());
        let resolver = cache.resolver();
        let clients = client_list(&[("10.0.0.2:9000", "bbbb2222ffff")]);

        // Miss: nothing cached yet, so the target is unresolvable this pass.
        assert!(resolver("laptop").is_empty());
        assert_eq!(
            resolve_edge_target(&target_named("laptop"), &clients, &resolver),
            Err(ResolveError::UnresolvedHostname("laptop".to_string()))
        );

        // The queued refresh (a fake system resolver here) fills the cache...
        let fake_resolve: fn(&str) -> Vec<IpAddr> = |name| match name {
            "laptop" => vec!["10.0.0.2".parse().unwrap()],
            _ => vec![],
        };
        cache.queue_refresh(vec!["laptop".to_string()], fake_resolve);

        // ...and the next pass resolves from it.
        let laptop_ip: IpAddr = "10.0.0.2".parse().unwrap();
        assert_eq!(resolver("laptop"), vec![laptop_ip]);
        assert_eq!(
            resolve_edge_target(&target_named("laptop"), &clients, &resolver),
            Ok("bbbb2222ffff".to_string())
        );
    }

    /// With a runtime the refresh is filled via spawn_blocking: the queueing
    /// pass never blocks on the resolver.
    #[tokio::test]
    async fn resolve_cache_refills_off_loop() {
        let cache = Arc::new(ResolveCache::default());
        let resolver = cache.resolver();
        let fake_resolve: fn(&str) -> Vec<IpAddr> = |_| vec!["10.0.0.7".parse().unwrap()];
        cache.queue_refresh(vec!["host".to_string()], fake_resolve);
        // The fill lands on the blocking pool: poll until it is served.
        for _ in 0..100 {
            if !resolver("host").is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let host_ip: IpAddr = "10.0.0.7".parse().unwrap();
        assert_eq!(resolver("host"), vec![host_ip]);

        // The in-flight marker was cleared: a follow-up refresh re-resolves
        // (here to nothing, e.g. the name dropped out of DNS).
        let no_resolve: fn(&str) -> Vec<IpAddr> = |_| vec![];
        cache.queue_refresh(vec!["host".to_string()], no_resolve);
        for _ in 0..100 {
            if resolver("host").is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(resolver("host").is_empty());
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
    fn edge_map_parses_qualified_entries() {
        // Qualified alone: lands in the qualified map, no unqualified entry.
        let map = parse_edge_map(&["bottom@eDP-1=auto".to_string()]).unwrap();
        assert!(map.targets.is_empty());
        assert_eq!(
            map.qualified[&(Direction::Bottom, "eDP-1".to_string())],
            EdgeTarget::Auto
        );

        // Mixed forms: a qualified and an unqualified entry for one
        // direction coexist, and one direction can be qualified on several
        // monitors.
        let map = parse_edge_map(&[
            "bottom@eDP-1=aa11bb,bottom=laptop".to_string(),
            "left@eDP-1=desk,left@DP-3=auto".to_string(),
        ])
        .unwrap();
        assert_eq!(
            map.targets[&Direction::Bottom],
            EdgeTarget::Named("laptop".to_string())
        );
        assert_eq!(
            map.qualified[&(Direction::Bottom, "eDP-1".to_string())],
            EdgeTarget::Named("aa11bb".to_string())
        );
        assert_eq!(
            map.qualified[&(Direction::Left, "eDP-1".to_string())],
            EdgeTarget::Named("desk".to_string())
        );
        assert_eq!(
            map.qualified[&(Direction::Left, "DP-3".to_string())],
            EdgeTarget::Auto
        );

        // Whitespace around the '@' and '=' is trimmed.
        let map = parse_edge_map(&["bottom @eDP-1 = auto".to_string()]).unwrap();
        assert_eq!(
            map.qualified[&(Direction::Bottom, "eDP-1".to_string())],
            EdgeTarget::Auto
        );
    }

    #[test]
    fn edge_map_rejects_bad_qualifiers() {
        // Duplicate (direction, monitor) pair.
        assert!(parse_edge_map(&["bottom@eDP-1=auto,bottom@eDP-1=laptop".to_string()]).is_err());
        // ... across repeatable flags too.
        assert!(parse_edge_map(&[
            "bottom@eDP-1=auto".to_string(),
            "bottom@eDP-1=auto".to_string()
        ])
        .is_err());
        // Empty qualifier.
        assert!(parse_edge_map(&["bottom@=auto".to_string()]).is_err());
        assert!(parse_edge_map(&["bottom@ =auto".to_string()]).is_err());
        // A second '@' in the qualifier (a description containing a literal
        // '@' — or ',' or '=' — can't be written; use the serial or model).
        assert!(parse_edge_map(&["bottom@eDP@1=auto".to_string()]).is_err());
        // Qualifier without a target, or without a direction.
        assert!(parse_edge_map(&["bottom@eDP-1".to_string()]).is_err());
        assert!(parse_edge_map(&["@eDP-1=auto".to_string()]).is_err());
    }

    #[test]
    fn edge_map_qualifier_keeps_inner_whitespace() {
        // Descriptions contain spaces; the qualifier is split on ',' and
        // the first '=' and '@' only, never on whitespace.
        let map = parse_edge_map(&["bottom@Dell Inc. DELL U2720Q 83JLZ23=auto".to_string()]).unwrap();
        assert_eq!(
            map.qualified[&(
                Direction::Bottom,
                "Dell Inc. DELL U2720Q 83JLZ23".to_string()
            )],
            EdgeTarget::Auto
        );
    }

    #[test]
    fn client_edge_map_accepts_only_auto() {
        // 'auto' on one or several edges is fine, in both syntax forms.
        let map = parse_client_edge_map(&["left=auto".to_string()]).unwrap();
        assert_eq!(map.targets[&Direction::Left], EdgeTarget::Auto);
        let map = parse_client_edge_map(&["left=auto".to_string(), "top=auto,bottom=auto".to_string()])
            .unwrap();
        assert_eq!(map.targets.len(), 3);
        // Monitor qualifiers are fine too — they pin the edge locally.
        let map = parse_client_edge_map(&["left@eDP-1=auto".to_string()]).unwrap();
        assert_eq!(
            map.qualified[&(Direction::Left, "eDP-1".to_string())],
            EdgeTarget::Auto
        );
        // A fingerprint prefix or a hostname is a config error on the client:
        // its only peer is the server.
        assert!(parse_client_edge_map(&["left=aa11bb".to_string()]).is_err());
        assert!(parse_client_edge_map(&["left=laptop".to_string()]).is_err());
        // ... qualified or not ...
        assert!(parse_client_edge_map(&["left@eDP-1=laptop".to_string()]).is_err());
        // ... even mixed with a valid entry.
        assert!(parse_client_edge_map(&["left=auto,right=laptop".to_string()]).is_err());
        // The base syntax errors still apply.
        assert!(parse_client_edge_map(&["left".to_string()]).is_err());
    }

    #[test]
    fn edge_fraction_tracks_the_along_axis() {
        // A left/right zone reads the y fraction of its range.
        let zone = EdgeZone {
            direction: Direction::Left,
            output: "A".to_string(),
            target: EdgeTarget::Auto,
            edge: 0,
            start: 100,
            len: 200,
        };
        assert_eq!(edge_fraction(&zone, 0, 100), 0.0);
        assert_eq!(edge_fraction(&zone, 0, 200), 0.5);
        assert_eq!(edge_fraction(&zone, 0, 299), 0.995);
        // Out-of-range positions clamp into 0.0..=1.0.
        assert_eq!(edge_fraction(&zone, 0, 50), 0.0);
        assert_eq!(edge_fraction(&zone, 0, 400), 1.0);
        // A top/bottom zone reads the x fraction instead.
        let zone = EdgeZone {
            direction: Direction::Top,
            output: "A".to_string(),
            target: EdgeTarget::Auto,
            edge: 0,
            start: 1000,
            len: 500,
        };
        assert_eq!(edge_fraction(&zone, 1250, 0), 0.5);
    }

    #[test]
    fn zones_only_mapped_directions_with_corner_trim() {
        let mut map = EdgeMap::default();
        map.targets.insert(Direction::Right, EdgeTarget::Auto);
        let layout = vec![
            rect("DP-1", 0, 0, 1920, 1080),
            rect("HDMI-A-1", 1920, 0, 1920, 1080),
        ];
        let zones = edge_zones(&map, &layout);
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].output, "HDMI-A-1");
        assert_eq!(zones[0].direction, Direction::Right);
        // The edge line is the output's last pixel column.
        assert_eq!(zones[0].edge, 1920 + 1920 - 1);
        // Global [86, 994): 8% of 1080 = 86 px trimmed off each end.
        assert_eq!(zones[0].start, 86);
        assert_eq!(zones[0].len, 908);
        assert!(zone_contains(&zones[0], 3839, 500));
        assert!(!zone_contains(&zones[0], 3838, 500));
    }

    /// Two side-by-side 1920x1080 outputs (eDP-1 left, HDMI-A-1 right):
    /// their top and bottom edges are each exposed on BOTH monitors.
    fn side_by_side_layout() -> Vec<OutputRect> {
        vec![
            rect("eDP-1", 0, 0, 1920, 1080),
            rect("HDMI-A-1", 1920, 0, 1920, 1080),
        ]
    }

    #[test]
    fn zones_unqualified_covers_every_output() {
        let map = parse_edge_map(&["bottom=auto".to_string()]).unwrap();
        let zones = edge_zones(&map, &side_by_side_layout());
        let mut outputs: Vec<&str> = zones.iter().map(|zone| zone.output.as_str()).collect();
        outputs.sort();
        assert_eq!(outputs, vec!["HDMI-A-1", "eDP-1"]);
        assert!(zones.iter().all(|zone| zone.target == EdgeTarget::Auto));
    }

    #[test]
    fn zones_qualified_alone_pins_the_edge_and_leaves_the_rest_inert() {
        // A qualified entry alone: only its own output gets a zone in that
        // direction; the other output's bottom edge stays inert.
        let map = parse_edge_map(&["bottom@HDMI-A-1=auto".to_string()]).unwrap();
        let zones = edge_zones(&map, &side_by_side_layout());
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].output, "HDMI-A-1");
        assert_eq!(zones[0].direction, Direction::Bottom);
        assert_eq!(zones[0].target, EdgeTarget::Auto);
    }

    #[test]
    fn zones_qualified_wins_on_its_output_unqualified_covers_the_rest() {
        let map = parse_edge_map(&["bottom@HDMI-A-1=aa11bb,bottom=laptop".to_string()]).unwrap();
        let zones = edge_zones(&map, &side_by_side_layout());
        assert_eq!(zones.len(), 2);
        assert_eq!(
            zone_of(&zones, Direction::Bottom, "HDMI-A-1").target,
            EdgeTarget::Named("aa11bb".to_string())
        );
        assert_eq!(
            zone_of(&zones, Direction::Bottom, "eDP-1").target,
            EdgeTarget::Named("laptop".to_string())
        );
    }

    #[test]
    fn zones_unknown_monitor_gets_no_zone_and_is_reported() {
        // A qualifier matching nothing produces no zone, and the
        // warn-on-change path (warn_qualifier_issues) records it as unknown
        // (match count 0).
        let map = parse_edge_map(&["bottom@eDP-9=auto".to_string()]).unwrap();
        let layout = side_by_side_layout();
        assert!(edge_zones(&map, &layout).is_empty());
        assert!(matching_outputs("eDP-9", &layout).is_empty());
        let mut warned = BTreeMap::new();
        warn_qualifier_issues(&map, &layout, &mut warned);
        assert_eq!(warned, BTreeMap::from([("eDP-9".to_string(), 0)]));
        // A qualifier matching exactly one output is not reported.
        let map = parse_edge_map(&["bottom@eDP-1=auto".to_string()]).unwrap();
        let mut warned = BTreeMap::new();
        warn_qualifier_issues(&map, &layout, &mut warned);
        assert!(warned.is_empty());
    }

    #[test]
    fn unknown_monitor_warning_tracks_the_layout() {
        // warn_qualifier_issues carries the reported state across
        // re-queries: still-missing is quiet, re-broken after a fix reports
        // again.
        let map = parse_edge_map(&["bottom@eDP-9=auto".to_string()]).unwrap();
        let layout = side_by_side_layout();
        let mut warned = BTreeMap::new();
        warn_qualifier_issues(&map, &layout, &mut warned);
        assert_eq!(warned, BTreeMap::from([("eDP-9".to_string(), 0)]));
        // The monitor appears (plugged in): nothing left to report.
        let mut fixed = side_by_side_layout();
        fixed.push(rect("eDP-9", 0, 1080, 1920, 1080));
        warn_qualifier_issues(&map, &fixed, &mut warned);
        assert!(warned.is_empty());
        // It disappears again: reported again.
        warn_qualifier_issues(&map, &layout, &mut warned);
        assert_eq!(warned, BTreeMap::from([("eDP-9".to_string(), 0)]));
    }

    /// Two side-by-side 1920x1080 outputs carrying Hyprland's persistent
    /// identifiers (identical models — two of the same screen).
    fn identified_layout() -> Vec<OutputRect> {
        vec![
            rect_id(
                "eDP-1",
                "Dell Inc.",
                "DELL U2720Q",
                "83JLZ23",
                "Dell Inc. DELL U2720Q 83JLZ23",
                0,
                0,
                1920,
                1080,
            ),
            rect_id(
                "DP-3",
                "Dell Inc.",
                "DELL U2720Q",
                "9KLMN77",
                "Dell Inc. DELL U2720Q 9KLMN77",
                1920,
                0,
                1920,
                1080,
            ),
        ]
    }

    #[test]
    fn qualifier_matches_by_name_serial_model_and_description() {
        let layout = identified_layout();
        // The name (the default) and each persistent identifier match their
        // own output; another output's identifier does not.
        for (qualifier, expected) in [
            ("eDP-1", "eDP-1"),        // name
            ("83JLZ23", "eDP-1"),      // serial
            ("9KLMN77", "DP-3"),       // serial
            ("Dell Inc. DELL U2720Q 83JLZ23", "eDP-1"), // description (with spaces)
            ("Dell Inc. DELL U2720Q 9KLMN77", "DP-3"),  // description
        ] {
            let matches = matching_outputs(qualifier, &layout);
            assert_eq!(
                matches.iter().map(|o| o.name.as_str()).collect::<Vec<_>>(),
                vec![expected],
                "qualifier '{}'",
                qualifier
            );
        }
        // The shared model matches BOTH outputs (ambiguity), the shared
        // make alone never matches (too ambiguous — it's in the
        // description instead).
        assert_eq!(matching_outputs("DELL U2720Q", &layout).len(), 2);
        assert!(matching_outputs("Dell Inc.", &layout).is_empty());
        // An empty identifier never matches: a name-only output answers
        // only to its name.
        let plain = side_by_side_layout();
        assert!(qualifier_matches("eDP-1", &plain[0]));
        assert!(!qualifier_matches("", &plain[0]));
    }

    #[test]
    fn output_identifiers_show_name_and_persistent_identity() {
        // The layout log and the qualifier warnings print outputs this way.
        // Description present: used as-is (it embeds make/model/serial).
        assert_eq!(
            output_identifiers(&identified_layout()[0]),
            "eDP-1 [Dell Inc. DELL U2720Q 83JLZ23]"
        );
        // No description: synthesized from the parts.
        let output = rect_id("DP-3", "Dell Inc.", "DELL U2720Q", "9KLMN77", "", 0, 0, 1920, 1080);
        assert_eq!(
            output_identifiers(&output),
            "DP-3 [Dell Inc. DELL U2720Q 9KLMN77]"
        );
        // Nothing reported: the bare name.
        assert_eq!(output_identifiers(&rect("eDP-1", 0, 0, 1920, 1080)), "eDP-1");
    }

    #[test]
    fn zones_qualifier_matches_persistent_identifiers() {
        let layout = identified_layout();
        // By serial: only that output is zoned.
        let map = parse_edge_map(&["bottom@83JLZ23=auto".to_string()]).unwrap();
        let zones = edge_zones(&map, &layout);
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].output, "eDP-1");
        // By description (contains spaces): only that output is zoned.
        let map = parse_edge_map(&["bottom@Dell Inc. DELL U2720Q 9KLMN77=auto".to_string()]).unwrap();
        let zones = edge_zones(&map, &layout);
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].output, "DP-3");
    }

    #[test]
    fn zones_ambiguous_qualifier_zones_all_matches_and_warns() {
        // Two identical models: the model qualifier zones BOTH outputs and
        // the warning path records the ambiguity (match count 2).
        let layout = identified_layout();
        let map = parse_edge_map(&["bottom@DELL U2720Q=auto".to_string()]).unwrap();
        let zones = edge_zones(&map, &layout);
        let mut outputs: Vec<&str> = zones.iter().map(|zone| zone.output.as_str()).collect();
        outputs.sort();
        assert_eq!(outputs, vec!["DP-3", "eDP-1"]);
        let mut warned = BTreeMap::new();
        warn_qualifier_issues(&map, &layout, &mut warned);
        assert_eq!(warned, BTreeMap::from([("DELL U2720Q".to_string(), 2)]));
        // The duplicate is unplugged: the qualifier recovers (one match).
        let single = vec![layout[0].clone()];
        warn_qualifier_issues(&map, &single, &mut warned);
        assert!(warned.is_empty());
        // Plugged back in: ambiguous again, reported again.
        warn_qualifier_issues(&map, &layout, &mut warned);
        assert_eq!(warned, BTreeMap::from([("DELL U2720Q".to_string(), 2)]));
    }

    #[test]
    fn zones_name_matching_works_without_identifiers() {
        // A compositor reporting no persistent identifiers (all fields
        // empty) degrades silently to name-only matching — no warnings.
        let layout = side_by_side_layout();
        let map = parse_edge_map(&["bottom@HDMI-A-1=auto".to_string()]).unwrap();
        let zones = edge_zones(&map, &layout);
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].output, "HDMI-A-1");
        let mut warned = BTreeMap::new();
        warn_qualifier_issues(&map, &layout, &mut warned);
        assert!(warned.is_empty());
    }

    /// The offset multi-monitor layout from the user's setup: HDMI-A-1
    /// 3440x1440@(0,0) with eDP-1 2048x1280@(3440,160) to its lower right.
    fn offset_layout() -> Vec<OutputRect> {
        vec![
            rect("HDMI-A-1", 0, 0, 3440, 1440),
            rect("eDP-1", 3440, 160, 2048, 1280),
        ]
    }

    fn all_mapped() -> EdgeMap {
        let mut map = EdgeMap::default();
        for dir in [
            Direction::Left,
            Direction::Right,
            Direction::Top,
            Direction::Bottom,
        ] {
            map.targets.insert(dir, EdgeTarget::Auto);
        }
        map
    }

    fn zone_of(zones: &[EdgeZone], direction: Direction, output: &str) -> EdgeZone {
        zones
            .iter()
            .find(|zone| zone.direction == direction && zone.output == output)
            .unwrap_or_else(|| panic!("no {:?} zone on {}", direction, output))
            .clone()
    }

    #[test]
    fn zones_offset_layout_left() {
        let zones = edge_zones(&all_mapped(), &offset_layout());
        // HDMI-A-1's left edge is fully exposed; 8% of 1440 = 115 trimmed
        // per end → y in [115, 1325).
        let zone = zone_of(&zones, Direction::Left, "HDMI-A-1");
        assert_eq!((zone.edge, zone.start, zone.len), (0, 115, 1210));
        assert!(zone_contains(&zone, 0, 115));
        assert!(zone_contains(&zone, 0, 1324));
        assert!(!zone_contains(&zone, 1, 500));
        assert!(!zone_contains(&zone, 0, 114));
        assert!(!zone_contains(&zone, 0, 1325));
        // eDP-1's left edge is fully abutted by HDMI-A-1: no zone there.
        assert!(zones
            .iter()
            .all(|zone| !(zone.direction == Direction::Left && zone.output == "eDP-1")));
    }

    #[test]
    fn zones_offset_layout_right() {
        let zones = edge_zones(&all_mapped(), &offset_layout());
        // eDP-1's right edge is fully exposed; 8% of 1280 = 102 per end →
        // y in [262, 1338), edge line at the output's last column.
        let zone = zone_of(&zones, Direction::Right, "eDP-1");
        assert_eq!((zone.edge, zone.start, zone.len), (5487, 262, 1076));
        assert!(zone_contains(&zone, 5487, 262));
        assert!(zone_contains(&zone, 5487, 1337));
        assert!(!zone_contains(&zone, 5486, 500));
        assert!(!zone_contains(&zone, 5487, 261));
        assert!(!zone_contains(&zone, 5487, 1338));
        // HDMI-A-1's right edge keeps only the exposed step above eDP-1:
        // [0, 160) trimmed by 12 per end → y in [12, 148).
        let step = zone_of(&zones, Direction::Right, "HDMI-A-1");
        assert_eq!((step.edge, step.start, step.len), (3439, 12, 136));
        assert!(zone_contains(&step, 3439, 12));
        assert!(!zone_contains(&step, 3439, 148));
    }

    #[test]
    fn zones_offset_layout_top_bottom() {
        let zones = edge_zones(&all_mapped(), &offset_layout());
        // Both tops are fully exposed (nothing above either output).
        let top_hdmi = zone_of(&zones, Direction::Top, "HDMI-A-1");
        assert_eq!((top_hdmi.edge, top_hdmi.start, top_hdmi.len), (0, 275, 2890));
        assert!(zone_contains(&top_hdmi, 275, 0));
        assert!(!zone_contains(&top_hdmi, 274, 0));
        assert!(!zone_contains(&top_hdmi, 500, 1));
        let top_edp = zone_of(&zones, Direction::Top, "eDP-1");
        assert_eq!((top_edp.edge, top_edp.start, top_edp.len), (160, 3603, 1722));
        assert!(zone_contains(&top_edp, 4000, 160));
        assert!(!zone_contains(&top_edp, 4000, 161));
        // Bottoms: both outputs end at y = 1439, trimmed the same way.
        let bottom_hdmi = zone_of(&zones, Direction::Bottom, "HDMI-A-1");
        assert_eq!((bottom_hdmi.edge, bottom_hdmi.start, bottom_hdmi.len), (1439, 275, 2890));
        assert!(zone_contains(&bottom_hdmi, 500, 1439));
        assert!(!zone_contains(&bottom_hdmi, 500, 1438));
        let bottom_edp = zone_of(&zones, Direction::Bottom, "eDP-1");
        assert_eq!((bottom_edp.edge, bottom_edp.start, bottom_edp.len), (1439, 3603, 1722));
        assert!(zone_contains(&bottom_edp, 4000, 1439));
    }

    #[test]
    fn debounce_ignores_single_poll_jitter() {
        let mut debounce = EdgeDebounce::new();
        // Alternating outcomes never hold for two consecutive polls.
        for _ in 0..10 {
            assert_eq!(debounce.poll(true), None);
            assert_eq!(debounce.poll(false), None);
        }
    }

    #[test]
    fn debounce_transitions_after_two_stable_polls() {
        let mut debounce = EdgeDebounce::new();
        // Already off: offs are no-ops.
        assert_eq!(debounce.poll(false), None);
        // One on is only a candidate; the second consecutive one commits.
        assert_eq!(debounce.poll(true), None);
        assert_eq!(debounce.poll(true), Some(true));
        // Back off again, same pattern.
        assert_eq!(debounce.poll(false), None);
        assert_eq!(debounce.poll(false), Some(false));
        // A single stray poll between stable ones delays the transition
        // instead of firing early.
        assert_eq!(debounce.poll(true), None);
        assert_eq!(debounce.poll(false), None);
        assert_eq!(debounce.poll(true), None);
        assert_eq!(debounce.poll(true), Some(true));
    }

    #[test]
    fn cursorpos_parses_replies() {
        assert_eq!(parse_cursorpos("3440, 160").unwrap(), (3440, 160));
        assert_eq!(parse_cursorpos("0, 0").unwrap(), (0, 0));
        // Outputs left of/above the layout origin report negatives.
        assert_eq!(parse_cursorpos("-100, -200").unwrap(), (-100, -200));
        assert_eq!(parse_cursorpos("3440,160\n").unwrap(), (3440, 160));
    }

    #[test]
    fn cursorpos_rejects_garbage() {
        assert!(parse_cursorpos("").is_err());
        assert!(parse_cursorpos("3440").is_err());
        assert!(parse_cursorpos("a, b").is_err());
        assert!(parse_cursorpos("1, 2, 3").is_err());
    }
}
