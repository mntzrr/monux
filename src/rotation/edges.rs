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
///
/// A fingerprint shared by several connected clients is unresolvable here,
/// whatever the target resolves to. Fingerprints are deliberately not unique
/// (certificate sharing between machines is supported, and a reconnect can
/// leave the old entry live for a while — see link::ClientInfo::endpoint), and
/// resolution hands back only the matched client's fingerprint, so there is no
/// way to tell WHICH of the sharers the target named. A hostname target that
/// matches exactly one of them by IP resolves cleanly, and answering "you" to
/// every sharer would arm a return-edge detector on a machine the user never
/// mapped — it could then hand input back unbidden. Staying silent for all of
/// them is the same policy resolve_edge_target applies to an ambiguous target.
pub fn edge_info_directions(
    map: &edge::EdgeMap,
    clients: &[(SocketAddr, String)],
    fingerprint: &str,
    resolve_host: &dyn Fn(&str) -> Vec<IpAddr>,
) -> Vec<event::Direction> {
    if clients.iter().filter(|(_, fp)| fp == fingerprint).count() > 1 {
        return Vec::new();
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::tests::no_ips;

    fn clients_of(entries: &[(&str, &str)]) -> Vec<(SocketAddr, String)> {
        entries
            .iter()
            .map(|(endpoint, fp)| (endpoint.parse::<SocketAddr>().unwrap(), fp.to_string()))
            .collect()
    }

    fn map_of(specs: &[&str]) -> edge::EdgeMap {
        edge::parse_edge_map(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    /// Two machines sharing one certificate: a hostname target picks exactly
    /// one of them by IP, so resolution succeeds — but it succeeds to a
    /// FINGERPRINT, which both of them carry. Neither may be told, or the
    /// unmapped sibling arms a return-edge detector and hands input back from
    /// an edge the user never mapped.
    #[test]
    fn edge_info_stays_silent_for_a_shared_fingerprint() {
        let shared = clients_of(&[
            ("10.0.0.1:9000", "aaaa1111"),
            ("10.0.0.2:9000", "bbbb2222"),
            ("10.0.0.3:9000", "bbbb2222"),
        ]);
        let resolver = |name: &str| -> Vec<IpAddr> {
            match name {
                "workstation" => vec!["10.0.0.2".parse().unwrap()],
                _ => vec![],
            }
        };
        let map = map_of(&["left=workstation"]);
        assert!(edge_info_directions(&map, &shared, "bbbb2222", &resolver).is_empty());
        assert!(edge_info_directions(&map, &shared, "aaaa1111", &resolver).is_empty());
        // The silence is the sharing, not the map: with the sibling gone the
        // same target advertises as before.
        let alone = clients_of(&[("10.0.0.1:9000", "aaaa1111"), ("10.0.0.2:9000", "bbbb2222")]);
        assert_eq!(
            edge_info_directions(&map, &alone, "bbbb2222", &resolver),
            vec![event::Direction::Left]
        );
    }

    /// The control status must agree with what the clients were told: a
    /// sharer is reported unmapped rather than carrying its sibling's edge.
    #[test]
    fn edge_string_is_silent_for_a_shared_fingerprint() {
        let clients = clients_of(&[
            ("10.0.0.2:9000", "bbbb2222"),
            ("10.0.0.3:9000", "bbbb2222"),
        ]);
        let resolver = |name: &str| -> Vec<IpAddr> {
            match name {
                "workstation" => vec!["10.0.0.2".parse().unwrap()],
                _ => vec![],
            }
        };
        let mut cache = EdgeDirectionsCache::default();
        cache.refresh(Some(&map_of(&["left=workstation"])), &clients, &resolver);
        assert_eq!(cache.edge_string(&clients[0].0), None);
        assert_eq!(cache.edge_string(&clients[1].0), None);
        // A single client with that fingerprint is mapped as usual.
        let clients = clients_of(&[("10.0.0.2:9000", "bbbb2222")]);
        cache.refresh(Some(&map_of(&["left=workstation"])), &clients, &resolver);
        assert_eq!(cache.edge_string(&clients[0].0), Some("left".to_string()));
        // And with no map at all, nothing is mapped (the `no_ips` resolver
        // keeps this independent of the host's DNS).
        cache.refresh(None, &clients, &no_ips);
        assert_eq!(cache.edge_string(&clients[0].0), None);
    }
}

