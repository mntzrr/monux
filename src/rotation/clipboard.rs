//! Where the shared clipboard currently lives, and the rate limiting around
//! changes to it.
//!
//! This owns the state and the decisions — which source owns the clipboard,
//! whether an update is a burst to collapse or a change to act on, which
//! pending fetch a reply belongs to. It does not talk to clients: the
//! rotation owns the links and does the sending, so the two concerns stay
//! separable (and this half stays testable without a connection).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use tokio::sync::oneshot;
use tracing::debug;

use crate::clipboard::{data, server};

use super::CLIPBOARD_UPDATE_DEBOUNCE;

/// Tracks the location and type of the current clipboard
#[derive(Debug)]
pub struct ClipboardTarget {
    /// None if the clipboard is at the server
    pub source: Option<SocketAddr>,
    pub types: Vec<String>,
    pub max_size_bytes: u64,
}

/// A local clipboard update held for the trailing edge of the debounce
/// window (see CLIPBOARD_UPDATE_DEBOUNCE).
#[derive(Debug)]
struct PendingLocalClipboard {
    /// When the debounce window expires (last processed local update +
    /// CLIPBOARD_UPDATE_DEBOUNCE). The server events loop wakes at this
    /// instant to apply the update.
    deadline: Instant,
    types: Vec<String>,
    max_size_bytes: u64,
}


/// What to do with an incoming clipboard-source update.
#[derive(Debug, PartialEq, Eq)]
pub enum Update {
    /// Act on it now.
    Process,
    /// A LOCAL update inside the debounce window: hold the newest one and
    /// apply it when the window expires. Dropping it instead would lose it
    /// outright — the final state of a fast double copy is never re-sent.
    HoldLocal,
    /// A REMOTE update inside the window: drop it. Client announcements are
    /// switch-driven one-shots spaced by SWITCH_DEBOUNCE, so there is no
    /// final state to lose.
    Drop,
    /// Identical to what is already advertised. Re-announcing would start
    /// another round of type advertisements and the two machines would churn
    /// each other forever (clipboard managers re-owning the same clipboard).
    Duplicate,
}

/// The clipboard's location, the debounce state, and the fetches in flight.
pub struct ClipboardRouter {
    /// Who owns the clipboard right now, and what it offers.
    target: Option<ClipboardTarget>,
    /// Access to the local system clipboard; None when disabled.
    pub local: Option<server::LocalClipboard>,
    /// Pending fetches originated by this machine, keyed by request id.
    pending_requests: HashMap<u64, oneshot::Sender<data::ClipboardData>>,
    /// Next locally-originated request id. Wrapping is fine: ids only need to
    /// correlate a reply with its request, not resist adversaries.
    next_request_id: u64,
    /// When each source's last update was processed (the per-source
    /// debounce). None = the local machine, Some(endpoint) = a client.
    last_update: HashMap<Option<SocketAddr>, Instant>,
    /// The newest local update held for the trailing edge.
    pending_local: Option<PendingLocalClipboard>,
}

impl ClipboardRouter {
    pub fn new(local: Option<server::LocalClipboard>) -> Self {
        ClipboardRouter {
            target: None,
            local,
            pending_requests: HashMap::new(),
            next_request_id: 0,
            last_update: HashMap::new(),
            pending_local: None,
        }
    }

    pub fn target(&self) -> Option<&ClipboardTarget> {
        self.target.as_ref()
    }

    pub fn set_target(&mut self, source: Option<SocketAddr>, types: Vec<String>, max_size_bytes: u64) {
        self.target = Some(ClipboardTarget {
            source,
            types,
            max_size_bytes,
        });
    }

    pub fn clear_target(&mut self) {
        self.target = None;
    }

    /// Classifies an incoming source update (see Update).
    pub fn classify(
        &self,
        source: Option<SocketAddr>,
        types: &[String],
        now: Instant,
    ) -> Update {
        if let Some(last) = self.last_update.get(&source) {
            if now.duration_since(*last) < CLIPBOARD_UPDATE_DEBOUNCE {
                return if source.is_none() {
                    Update::HoldLocal
                } else {
                    Update::Drop
                };
            }
        }
        if let Some(current) = &self.target {
            if current.source == source && types_equal(&current.types, types) {
                return Update::Duplicate;
            }
        }
        Update::Process
    }

    /// Records that a source's update was acted on, opening a fresh window.
    pub fn note_processed(&mut self, source: Option<SocketAddr>, now: Instant) {
        self.last_update.insert(source, now);
        if source.is_none() {
            // A directly processed local update supersedes a held one.
            self.pending_local = None;
        }
    }

    /// Forgets a source's debounce state, so a re-own right after a
    /// revocation is processed rather than debounced away.
    pub fn reset_debounce(&mut self, source: Option<SocketAddr>) {
        self.last_update.remove(&source);
        if source.is_none() {
            // A revocation supersedes any update held for the trailing edge.
            self.pending_local = None;
        }
    }

    /// Drops a departed client's debounce entry: reconnects arrive with a
    /// fresh ephemeral port, so keeping it would leak one key per reconnect.
    pub fn forget_source(&mut self, endpoint: &SocketAddr) {
        self.last_update.remove(&Some(*endpoint));
    }

    /// Holds a local update for the trailing edge of its window.
    pub fn hold_local(&mut self, types: Vec<String>, max_size_bytes: u64, now: Instant) {
        let deadline = self
            .last_update
            .get(&None)
            .map(|last| *last + CLIPBOARD_UPDATE_DEBOUNCE)
            .unwrap_or(now);
        debug!("Holding rapid local clipboard source update for the debounce window's trailing edge");
        self.pending_local = Some(PendingLocalClipboard {
            deadline,
            types,
            max_size_bytes,
        });
    }

    /// When the held local update should be applied.
    pub fn pending_local_deadline(&self) -> Option<Instant> {
        self.pending_local.as_ref().map(|p| p.deadline)
    }

    /// Takes the held local update, if any.
    pub fn take_pending_local(&mut self) -> Option<(Vec<String>, u64)> {
        self.pending_local
            .take()
            .map(|p| (p.types, p.max_size_bytes))
    }

    /// Allocates a request id and remembers who is waiting on it.
    pub fn track_request(&mut self, tx: oneshot::Sender<data::ClipboardData>) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        // Drop entries whose requester already gave up (timed out).
        self.pending_requests.retain(|_, tx| !tx.is_closed());
        self.pending_requests.insert(id, tx);
        id
    }

    pub fn take_request(&mut self, id: u64) -> Option<oneshot::Sender<data::ClipboardData>> {
        self.pending_requests.remove(&id)
    }

    pub fn untrack_request(&mut self, id: u64) {
        self.pending_requests.remove(&id);
    }

    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Drops fetches whose requester already gave up.
    pub fn prune_requests(&mut self) {
        self.pending_requests.retain(|_, tx| !tx.is_closed());
    }

    /// Fails every pending fetch at once: dropping the senders errors their
    /// receivers immediately, so they resolve empty instead of waiting out
    /// the fetch timeout.
    pub fn clear_requests(&mut self) {
        self.pending_requests.clear();
    }
}

/// Compares two clipboard mime-type lists as sets (order- and
/// duplicate-insensitive), since different sources advertise the same
/// clipboard with slightly different lists (e.g. wl-copy repeating text/plain).
pub fn types_equal(a: &[String], b: &[String]) -> bool {
    let mut a: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
    let mut b: Vec<&str> = b.iter().map(|s| s.as_str()).collect();
    a.sort_unstable();
    a.dedup();
    b.sort_unstable();
    b.dedup();
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn addr(spec: &str) -> SocketAddr {
        spec.parse().unwrap()
    }

    #[test]
    fn types_equal_is_set_based() {
        // Different sources advertise the same clipboard differently; order
        // and repeats must not read as a change.
        assert!(types_equal(
            &types(&["text/plain", "text/plain", "text/html"]),
            &types(&["text/html", "text/plain"])
        ));
        assert!(!types_equal(&types(&["text/plain"]), &types(&["image/png"])));
        assert!(types_equal(&[], &[]));
    }

    #[test]
    fn a_burst_is_collapsed_but_a_local_burst_keeps_its_newest() {
        let mut r = ClipboardRouter::new(None);
        let t0 = Instant::now();
        let client = Some(addr("10.0.0.1:1"));

        // First update from each source is acted on.
        assert_eq!(r.classify(None, &types(&["a"]), t0), Update::Process);
        r.note_processed(None, t0);
        assert_eq!(r.classify(client, &types(&["a"]), t0), Update::Process);
        r.note_processed(client, t0);

        // Inside the window: a local update is HELD (its final state is never
        // re-sent), a remote one is dropped (switch-driven, nothing to lose).
        let inside = t0 + CLIPBOARD_UPDATE_DEBOUNCE / 2;
        assert_eq!(r.classify(None, &types(&["b"]), inside), Update::HoldLocal);
        assert_eq!(r.classify(client, &types(&["b"]), inside), Update::Drop);

        // Past the window both flow again.
        let past = t0 + CLIPBOARD_UPDATE_DEBOUNCE * 2;
        assert_eq!(r.classify(None, &types(&["b"]), past), Update::Process);
        assert_eq!(r.classify(client, &types(&["b"]), past), Update::Process);
    }

    #[test]
    fn the_debounce_is_per_source() {
        let mut r = ClipboardRouter::new(None);
        let t0 = Instant::now();
        let a = Some(addr("10.0.0.1:1"));
        let b = Some(addr("10.0.0.2:2"));
        r.note_processed(a, t0);
        // One source's burst must not swallow another source's update.
        let inside = t0 + CLIPBOARD_UPDATE_DEBOUNCE / 2;
        assert_eq!(r.classify(a, &types(&["x"]), inside), Update::Drop);
        assert_eq!(r.classify(b, &types(&["x"]), inside), Update::Process);
    }

    #[test]
    fn an_identical_update_is_not_a_change() {
        let mut r = ClipboardRouter::new(None);
        let t0 = Instant::now();
        r.set_target(None, types(&["text/plain"]), 1024);
        r.note_processed(None, t0);
        let past = t0 + CLIPBOARD_UPDATE_DEBOUNCE * 2;

        // Re-owning the same clipboard (a clipboard manager, a wl-paste echo)
        // must not start another round of advertisements.
        assert_eq!(
            r.classify(None, &types(&["text/plain"]), past),
            Update::Duplicate
        );
        // A different type list, or the same list from a different owner, is
        // a real change.
        assert_eq!(r.classify(None, &types(&["image/png"]), past), Update::Process);
        assert_eq!(
            r.classify(Some(addr("10.0.0.1:1")), &types(&["text/plain"]), past),
            Update::Process
        );
    }

    #[test]
    fn a_revocation_reopens_the_window_immediately() {
        let mut r = ClipboardRouter::new(None);
        let t0 = Instant::now();
        r.note_processed(None, t0);
        r.hold_local(types(&["held"]), 1024, t0);
        assert!(r.pending_local_deadline().is_some());

        // The selection went away: the held update is moot, and a re-own
        // right after (a clipboard manager persisting it) must be processed
        // rather than debounced away.
        r.reset_debounce(None);
        assert!(r.pending_local_deadline().is_none());
        assert_eq!(
            r.classify(None, &types(&["fresh"]), t0 + CLIPBOARD_UPDATE_DEBOUNCE / 2),
            Update::Process
        );
    }

    #[test]
    fn request_ids_are_unique_and_reclaimed() {
        let mut r = ClipboardRouter::new(None);
        let (tx1, _rx1) = oneshot::channel();
        let (tx2, _rx2) = oneshot::channel();
        let id1 = r.track_request(tx1);
        let id2 = r.track_request(tx2);
        assert_ne!(id1, id2);
        assert_eq!(r.pending_request_count(), 2);

        // A reply claims exactly its own request.
        assert!(r.take_request(id1).is_some());
        assert!(r.take_request(id1).is_none(), "claimed only once");
        assert_eq!(r.pending_request_count(), 1);

        // A requester that gave up is pruned rather than leaked.
        let (tx3, rx3) = oneshot::channel();
        let id3 = r.track_request(tx3);
        drop(rx3);
        r.prune_requests();
        assert!(r.take_request(id3).is_none());
    }

    #[test]
    fn a_held_local_update_keeps_only_the_newest() {
        let mut r = ClipboardRouter::new(None);
        let t0 = Instant::now();
        r.note_processed(None, t0);
        r.hold_local(types(&["first"]), 1024, t0);
        r.hold_local(types(&["second"]), 2048, t0);
        // A fast double copy: the newest wins, and only one is applied.
        assert_eq!(r.take_pending_local(), Some((types(&["second"]), 2048)));
        assert_eq!(r.take_pending_local(), None);
    }
}
