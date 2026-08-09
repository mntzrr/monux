//! Which client sits beyond which of the server's screen edges, and telling
//! each client so.
//!
//! The server resolves `--edge-map` targets against the live client list and
//! advertises the result (ServerEvent::EdgeInfo), so a client can infer the
//! edge to watch for the return trip without an `--edge-map` of its own.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};

use crate::edge;
use crate::msgs::event;

/// The --edge-map directions a client sits beyond: every direction whose
/// target resolves to the client's fingerprint against the LIVE client list —
/// the same resolution semantics as the edge switch itself (auto / fingerprint
/// prefix / hostname; see edge::resolve_edge_target). Monitor qualifiers are
/// irrelevant here: the wire carries directions only, so a client beyond
/// "bottom@eDP-1" is beyond "bottom". Unresolvable targets (e.g. `auto` with
/// two clients connected) simply yield no EdgeInfo for that direction. Takes
/// the client list rather than the roster: resolution is pure matching, and
/// the caller already has the entries.
pub fn edge_info_directions(
    map: &edge::EdgeMap,
    clients: &[(SocketAddr, String)],
    fingerprint: &str,
    resolve_host: &dyn Fn(&str) -> Vec<IpAddr>,
) -> Vec<event::Direction> {
    // The BTreeSet dedups (one direction can have both a qualified and an
    // unqualified entry) and keeps the result in direction order.
    map.entries()
        .filter(|(_, _, target)| {
            edge::resolve_edge_target(target, clients, resolve_host)
                .map(|resolved| resolved == fingerprint)
                .unwrap_or(false)
        })
        .map(|(direction, _, _)| direction)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Cached --edge-map resolutions for the control-socket status
/// (Rotation::server_state). Resolution can hit DNS — a hostname target needs
/// a getaddrinfo — so it must never run per rotation-loop iteration
/// (thousands of lookups a second at 8kHz input, on a shared tokio worker).
/// Refreshed ONLY when the resolution can change: a client add/remove
/// (including an in-place reconnect replace, which may carry a new
/// fingerprint) or set_edge_map. Reads are free. Even those refreshes never
/// resolve synchronously: hostname lookups go through the ResolveCache (see
/// Rotation::resolve_cache), whose background refill serves the next pass.
#[derive(Default)]
pub struct EdgeDirectionsCache {
    /// endpoint -> the edge directions that client sits beyond (empty vec =
    /// connected but unmapped). One entry per connected client, rebuilt
    /// wholesale on refresh.
    directions: HashMap<SocketAddr, Vec<event::Direction>>,
}

impl EdgeDirectionsCache {
    /// Re-resolves every client's directions against the current client list
    /// — one target resolution per (direction, client) pair, tolerable on
    /// topology changes. With no edge map the cache just empties.
    pub fn refresh(
        &mut self,
        map: Option<&edge::EdgeMap>,
        clients: &[(SocketAddr, String)],
        resolve_host: &dyn Fn(&str) -> Vec<IpAddr>,
    ) {
        self.directions.clear();
        let Some(map) = map else {
            return;
        };
        for (endpoint, fingerprint) in clients {
            self.directions.insert(
                *endpoint,
                edge_info_directions(map, clients, fingerprint, resolve_host),
            );
        }
    }

    /// The cached directions for the control status as a "top+left"-style
    /// string; None when the client is unmapped (or unknown to the cache).
    pub fn edge_string(&self, endpoint: &SocketAddr) -> Option<String> {
        let dirs = self.directions.get(endpoint)?;
        if dirs.is_empty() {
            return None;
        }
        Some(
            dirs.iter()
                .map(|d| d.as_str())
                .collect::<Vec<&str>>()
                .join("+"),
        )
    }
}

