//! The connected clients, and how the rotation moves between them.
//!
//! Kept sorted by endpoint: an arbitrary but stable order, so next/prev mean
//! the same thing across sessions and a lookup is a binary search.
//!
//! Everything here used to be free functions over `&[SocketAddr]`, each
//! carrying a note that `ClientInfo` embeds quinn handles and could not be
//! fabricated in a test. With `ClientLink` behind those handles that is no
//! longer true, so the navigation lives on the type that owns the list.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;

use crate::msgs::event;

use super::link::ClientInfo;

/// The resolution of a `--shortcut-goto` / control-socket fingerprint against
/// the connected clients.
#[derive(Debug, PartialEq)]
pub enum GotoResolution {
    /// An empty fingerprint means "go to the local machine".
    Local,
    /// Exactly one client's fingerprint starts with the requested prefix.
    Client(SocketAddr),
    /// No client's fingerprint starts with the requested prefix.
    NoMatch,
    /// Several clients match (their endpoints, for the warning).
    Ambiguous(Vec<SocketAddr>),
}

/// Where a (re)connecting endpoint's entry landed.
#[derive(Debug, PartialEq, Eq)]
pub enum Placement {
    /// A new client was inserted.
    Inserted,
    /// A reconnect replaced an existing entry in place. The old connection's
    /// late removal is then ignored via its stale conn_token.
    Replaced,
}

/// The connected clients, sorted by endpoint.
#[derive(Default)]
pub struct ClientRoster {
    clients: Vec<ClientInfo>,
}

impl ClientRoster {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ClientInfo> {
        self.clients.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ClientInfo> {
        self.clients.iter_mut()
    }

    pub fn get(&self, endpoint: &SocketAddr) -> Option<&ClientInfo> {
        self.index_of(endpoint).map(|idx| &self.clients[idx])
    }

    pub fn get_mut(&mut self, endpoint: &SocketAddr) -> Option<&mut ClientInfo> {
        self.index_of(endpoint).map(|idx| &mut self.clients[idx])
    }

    fn index_of(&self, endpoint: &SocketAddr) -> Option<usize> {
        self.clients
            .binary_search_by(|c| c.endpoint.cmp(endpoint))
            .ok()
    }

    /// Inserts a client, or replaces the entry for an endpoint that is
    /// already present.
    ///
    /// An identical endpoint can already be there when a reconnect lands
    /// before the old connection's removal: updating in place beats inserting
    /// a duplicate, since a later removal would clear only the first copy and
    /// leave a dead one behind.
    ///
    /// A replace also forgets the endpoint's advertised-EdgeInfo record: that
    /// record belongs to the OLD connection, and keeping it would dedup — and
    /// so skip — the fresh connection's EdgeInfo, leaving the reconnected
    /// client's return-edge detector permanently unstarted.
    pub fn insert_or_replace(
        &mut self,
        info: ClientInfo,
        edge_info_sent: &mut HashMap<SocketAddr, BTreeSet<event::Direction>>,
    ) -> Placement {
        let endpoint = info.endpoint;
        match self.clients.binary_search_by(|c| c.endpoint.cmp(&endpoint)) {
            Ok(idx) => {
                edge_info_sent.remove(&endpoint);
                self.clients[idx] = info;
                Placement::Replaced
            }
            Err(idx) => {
                self.clients.insert(idx, info);
                Placement::Inserted
            }
        }
    }

    /// Removes a client, returning whether one was there.
    pub fn remove(&mut self, endpoint: &SocketAddr) -> bool {
        match self.index_of(endpoint) {
            Some(idx) => {
                self.clients.remove(idx);
                true
            }
            None => false,
        }
    }

    /// The connection token of an endpoint's current entry, if any. Used to
    /// tell a live entry from one a reconnect has since replaced.
    pub fn conn_token(&self, endpoint: &SocketAddr) -> Option<u64> {
        self.get(endpoint).map(|c| c.conn_token)
    }

    pub fn endpoints(&self) -> Vec<SocketAddr> {
        self.clients.iter().map(|c| c.endpoint).collect()
    }

    /// (endpoint, fingerprint) pairs, the shape the edge switcher resolves
    /// `--edge-map` targets against.
    pub fn entries(&self) -> Vec<(SocketAddr, String)> {
        self.clients
            .iter()
            .map(|c| (c.endpoint, c.fingerprint.clone()))
            .collect()
    }

    /// The endpoints as a comma-separated list, for log lines.
    pub fn endpoint_list(&self) -> String {
        self.clients
            .iter()
            .map(|c| c.endpoint.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    }

    /// The target of a previous-client switch (None = the local machine).
    pub fn prev_target(&self, current: Option<SocketAddr>) -> Option<SocketAddr> {
        let clients = self.endpoints();
        let Some(current) = current else {
            // On the local machine: wrap to the last entry, if any.
            return clients.last().copied();
        };
        let idx = match clients.binary_search(&current) {
            Ok(idx) => idx,
            Err(idx) => idx,
        };
        if idx == 0 {
            // At the start of the list, or the list is empty: the local
            // machine is next going backwards.
            None
        } else {
            clients.get(idx - 1).copied()
        }
    }

    /// The target of a next-client switch (None = the local machine).
    pub fn next_target(&self, current: Option<SocketAddr>) -> Option<SocketAddr> {
        let clients = self.endpoints();
        let Some(current) = current else {
            return clients.first().copied();
        };
        // For a current that is not in the roster (it vanished without a
        // removal landing) binary_search yields where it WOULD sit, and the
        // client after that phantom position is clients[idx] itself.
        let idx = match clients.binary_search(&current) {
            Ok(idx) => idx + 1,
            Err(idx) => idx,
        };
        // Off the end falls back to the local machine.
        clients.get(idx).copied()
    }

    /// Resolves a goto fingerprint to a switch target. A prefix is enough:
    /// "abcd123" matches a client whose fingerprint starts with it.
    pub fn resolve_goto(&self, fingerprint: &str) -> GotoResolution {
        if fingerprint.is_empty() {
            return GotoResolution::Local;
        }
        let matching: Vec<SocketAddr> = self
            .clients
            .iter()
            .filter(|c| c.fingerprint.starts_with(fingerprint))
            .map(|c| c.endpoint)
            .collect();
        match matching.len() {
            0 => GotoResolution::NoMatch,
            1 => GotoResolution::Client(matching[0]),
            _ => GotoResolution::Ambiguous(matching),
        }
    }
}

impl std::fmt::Debug for ClientRoster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.clients.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation::link::test_support::fake_client;

    fn addr(spec: &str) -> SocketAddr {
        spec.parse().unwrap()
    }

    fn roster(specs: &[(&str, &str)]) -> ClientRoster {
        let mut roster = ClientRoster::new();
        let mut edges = HashMap::new();
        for (endpoint, fingerprint) in specs {
            roster.insert_or_replace(fake_client(addr(endpoint), fingerprint), &mut edges);
        }
        roster
    }

    #[test]
    fn navigation_wraps_through_the_local_machine() {
        let r = roster(&[("10.0.0.1:1", "aa"), ("10.0.0.2:2", "bb")]);
        let (a, b) = (addr("10.0.0.1:1"), addr("10.0.0.2:2"));

        // Forward: local -> a -> b -> local.
        assert_eq!(r.next_target(None), Some(a));
        assert_eq!(r.next_target(Some(a)), Some(b));
        assert_eq!(r.next_target(Some(b)), None);
        // Backward: local -> b -> a -> local.
        assert_eq!(r.prev_target(None), Some(b));
        assert_eq!(r.prev_target(Some(b)), Some(a));
        assert_eq!(r.prev_target(Some(a)), None);
    }

    #[test]
    fn navigation_on_an_empty_roster_stays_local() {
        let r = ClientRoster::new();
        assert_eq!(r.next_target(None), None);
        assert_eq!(r.prev_target(None), None);
        // ...even if the current client vanished without a removal landing.
        let stale = addr("10.0.0.9:9");
        assert_eq!(r.next_target(Some(stale)), None);
        assert_eq!(r.prev_target(Some(stale)), None);
    }

    #[test]
    fn next_from_a_vanished_current_resumes_where_it_sat() {
        let r = roster(&[("10.0.0.1:1", "aa"), ("10.0.0.3:3", "cc")]);
        let (a, b, c) = (addr("10.0.0.1:1"), addr("10.0.0.2:2"), addr("10.0.0.3:3"));
        // b vanished from the roster while still recorded as current: it sat
        // between a and c, so next resumes at c — the client after its
        // phantom position — not one past it at the local machine (and prev
        // at a, the client before it).
        assert_eq!(r.next_target(Some(b)), Some(c));
        assert_eq!(r.prev_target(Some(b)), Some(a));
        // A phantom past the end still wraps to the local machine.
        assert_eq!(r.next_target(Some(addr("10.0.0.9:9"))), None);
    }

    #[test]
    fn goto_matches_on_a_fingerprint_prefix() {
        let r = roster(&[("10.0.0.1:1", "aabbcc11"), ("10.0.0.2:2", "aabbdd22")]);
        assert_eq!(r.resolve_goto(""), GotoResolution::Local);
        assert_eq!(
            r.resolve_goto("aabbcc"),
            GotoResolution::Client(addr("10.0.0.1:1"))
        );
        assert_eq!(r.resolve_goto("zz"), GotoResolution::NoMatch);
        // A prefix shared by two clients is ambiguous, never a coin flip.
        match r.resolve_goto("aabb") {
            GotoResolution::Ambiguous(endpoints) => assert_eq!(endpoints.len(), 2),
            other => panic!("expected ambiguity, got {:?}", other),
        }
    }

    #[test]
    fn a_reconnect_replaces_in_place_and_clears_its_edge_record() {
        let mut r = ClientRoster::new();
        let mut edges: HashMap<SocketAddr, BTreeSet<event::Direction>> = HashMap::new();
        let a = addr("10.0.0.1:1");

        assert_eq!(
            r.insert_or_replace(fake_client(a, "aa"), &mut edges),
            Placement::Inserted
        );
        edges.insert(a, BTreeSet::from([event::Direction::Left]));

        // The same endpoint reconnects: one entry, and the stale EdgeInfo
        // record is dropped so the fresh connection's advertisement is not
        // deduped away (which would leave its return edge unwatched).
        assert_eq!(
            r.insert_or_replace(fake_client(a, "aa"), &mut edges),
            Placement::Replaced
        );
        assert_eq!(r.len(), 1);
        assert!(!edges.contains_key(&a));
    }

    #[test]
    fn the_list_stays_sorted_whatever_order_clients_arrive_in() {
        let r = roster(&[
            ("10.0.0.3:3", "cc"),
            ("10.0.0.1:1", "aa"),
            ("10.0.0.2:2", "bb"),
        ]);
        assert_eq!(
            r.endpoints(),
            vec![addr("10.0.0.1:1"), addr("10.0.0.2:2"), addr("10.0.0.3:3")]
        );
        // ...so lookups (a binary search) find every one of them.
        for endpoint in r.endpoints() {
            assert!(r.get(&endpoint).is_some(), "{} not found", endpoint);
        }
        assert!(r.get(&addr("10.0.0.9:9")).is_none());
    }

    #[test]
    fn removal_reports_whether_anything_was_there() {
        let mut r = roster(&[("10.0.0.1:1", "aa")]);
        assert!(r.remove(&addr("10.0.0.1:1")));
        assert!(r.is_empty());
        // A removal for a client that was never added is a no-op, not a
        // panic: it happens when cleanup races a connection that failed
        // before it was ever registered.
        assert!(!r.remove(&addr("10.0.0.1:1")));
    }
}
