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

/// Where the reply to an outstanding clipboard fetch has to go.
pub enum PendingFetch {
    /// This machine's own paste, waiting on the oneshot.
    Local(oneshot::Sender<data::ClipboardData>),
    /// A client asked on its own behalf; the reply is relayed back to it under
    /// the id IT used, which is not the id we asked the owner with (see
    /// ClipboardRouter::pending_requests).
    Relay {
        client: SocketAddr,
        client_request_id: u64,
    },
}

/// The clipboard's location, the debounce state, and the fetches in flight.
pub struct ClipboardRouter {
    /// Who owns the clipboard right now, and what it offers.
    target: Option<ClipboardTarget>,
    /// Access to the local system clipboard; None when disabled.
    pub local: Option<server::LocalClipboard>,
    /// Fetches in flight, keyed by the peer the request was sent to AND the id
    /// it was sent with.
    ///
    /// Keyed on the peer, not on the id alone, because the id arrives in a
    /// frame an approved-but-hostile peer writes: keying on it alone lets any
    /// connected client claim any outstanding fetch — answering another
    /// machine's paste, or a local one, with bytes of its choosing. The peer is
    /// the connection the frame actually came in on, which no peer can forge.
    pending_requests: HashMap<(SocketAddr, u64), PendingFetch>,
    /// Next request id this machine allocates. Wrapping is fine: an id only
    /// has to be unique among the fetches outstanding against one peer.
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
    /// Records a fetch sent to `owner`, returning the id to ask under. The id
    /// is always allocated here rather than reusing a requesting client's own:
    /// two clients can pick the same id, and the key must stay unique per
    /// owner. Relay entries carry the client's id so the reply can be
    /// translated back on the way out.
    pub fn track_request(&mut self, owner: SocketAddr, fetch: PendingFetch) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        self.prune_requests();
        self.pending_requests.insert((owner, id), fetch);
        id
    }

    /// Claims the fetch `owner` is answering. Returns None when that peer has
    /// no such fetch outstanding — which is what a forged or stale reply looks
    /// like, and is why the peer is half of the key.
    pub fn take_request(&mut self, owner: SocketAddr, id: u64) -> Option<PendingFetch> {
        self.pending_requests.remove(&(owner, id))
    }

    pub fn untrack_request(&mut self, owner: SocketAddr, id: u64) {
        self.pending_requests.remove(&(owner, id));
    }

    /// Fails every fetch waiting on `client` — as its requester or as the peer
    /// that owed the reply — when it disconnects.
    pub fn drop_requests_for(&mut self, client: SocketAddr) {
        self.pending_requests.retain(|(owner, _), fetch| {
            *owner != client
                && !matches!(fetch, PendingFetch::Relay { client: c, .. } if *c == client)
        });
    }

    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Drops fetches whose requester already gave up. Only local fetches can
    /// be detected this way; a relay's requester is watched by the roster
    /// instead (see drop_requests_for).
    pub fn prune_requests(&mut self) {
        self.pending_requests.retain(|_, fetch| match fetch {
            PendingFetch::Local(tx) => !tx.is_closed(),
            PendingFetch::Relay { .. } => true,
        });
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
        let owner = addr("10.0.0.1:1");
        let (tx1, _rx1) = oneshot::channel();
        let (tx2, _rx2) = oneshot::channel();
        let id1 = r.track_request(owner, PendingFetch::Local(tx1));
        let id2 = r.track_request(owner, PendingFetch::Local(tx2));
        assert_ne!(id1, id2);
        assert_eq!(r.pending_request_count(), 2);

        // A reply claims exactly its own request.
        assert!(r.take_request(owner, id1).is_some());
        assert!(r.take_request(owner, id1).is_none(), "claimed only once");
        assert_eq!(r.pending_request_count(), 1);

        // A requester that gave up is pruned rather than leaked.
        let (tx3, rx3) = oneshot::channel();
        let id3 = r.track_request(owner, PendingFetch::Local(tx3));
        drop(rx3);
        r.prune_requests();
        assert!(r.take_request(owner, id3).is_none());
    }

    /// The routing key is (peer, id), so a fetch can only be answered by the
    /// peer it was actually sent to. Keyed on the id alone — as it was — any
    /// approved-but-hostile client could claim another machine's pending
    /// paste by guessing a small counter, and feed it bytes of its choosing.
    #[test]
    fn only_the_peer_a_fetch_was_sent_to_can_answer_it() {
        let mut r = ClipboardRouter::new(None);
        let owner = addr("10.0.0.1:1");
        let impostor = addr("10.0.0.2:2");
        let (tx, _rx) = oneshot::channel();
        let id = r.track_request(owner, PendingFetch::Local(tx));

        assert!(
            r.take_request(impostor, id).is_none(),
            "a peer that was never asked must not be able to answer"
        );
        // ...and the real reply still lands.
        assert!(r.take_request(owner, id).is_some());
    }

    /// A disconnecting client takes both directions with it: the fetches it
    /// owed answers to, and the ones made on its behalf. Relay entries carry
    /// no closed-channel signal, so prune_requests alone would leak them.
    #[test]
    fn a_departing_client_drops_the_fetches_on_both_sides_of_it() {
        let mut r = ClipboardRouter::new(None);
        let owner = addr("10.0.0.1:1");
        let asker = addr("10.0.0.2:2");
        let bystander = addr("10.0.0.3:3");
        let (tx, _rx) = oneshot::channel();

        let owed = r.track_request(owner, PendingFetch::Local(tx));
        let on_behalf = r.track_request(
            bystander,
            PendingFetch::Relay {
                client: asker,
                client_request_id: 7,
            },
        );
        assert_eq!(r.pending_request_count(), 2);

        r.drop_requests_for(owner);
        assert!(r.take_request(owner, owed).is_none());
        assert_eq!(r.pending_request_count(), 1);

        r.drop_requests_for(asker);
        assert!(r.take_request(bystander, on_behalf).is_none());
        assert_eq!(r.pending_request_count(), 0);
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
