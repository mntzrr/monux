//! App-level liveness: the Ping/Pong check that notices a black-holed link in
//! seconds, where the QUIC idle timeout needs 25 — time during which grabbed
//! input is silently lost.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How often the server sends a Ping to the current client (and to any
/// silenced client) on the events stream (see ServerEvent::Ping).
pub const PING_INTERVAL: Duration = Duration::from_secs(2);

/// How many consecutive ping intervals may go unanswered before the current
/// client is declared silent: 3 x PING_INTERVAL ~= 6s. The server then
/// switches to the local machine and ungrabs, WITHOUT removing the client or
/// touching the connection — the QUIC idle timeout (25s) still owns actual
/// removal. Until this fires, a black-holed link (WiFi) keeps devices
/// grabbed and keystrokes buffer into the void.
pub const PONG_MISS_LIMIT: u32 = 3;

/// WWW-mode miss limit (--www): internet paths stall much longer than LAN
/// ones, so the LAN-grade bar would declare silence on otherwise-healthy
/// connections (the keepalive and idle timeout have relaxed WWW variants
/// for the same reason, see transport.rs). 6 x PING_INTERVAL ~= 12s.
pub const WWW_PONG_MISS_LIMIT: u32 = 6;

/// Consecutive pongs (or any messages) a silenced client must produce before
/// it is re-activated automatically (see REACTIVATE_COOLDOWN).
pub const REACTIVATE_PONGS: u32 = 3;

/// Minimum time spent in the silenced state before automatic re-activation.
/// Together with REACTIVATE_PONGS this hysteresis keeps a lossy-but-alive
/// link from flapping the input grab between machines.
pub const REACTIVATE_COOLDOWN: Duration = Duration::from_secs(5);

/// Per-client liveness tracking for the app-level Ping/Pong check (see
/// ServerEvent::Ping). Detects a black-holed link within seconds, where the
/// QUIC idle timeout needs 25s — time during which grabbed input is
/// silently lost.
#[derive(Debug)]
struct LivenessState {
    /// When anything was last received from this client: ANY ClientEvent or
    /// bulk bytes count as liveness (see server.rs), not just Pongs.
    last_heard: Instant,
    /// Some(since) while the client is marked silenced: it missed
    /// PONG_MISS_LIMIT pings while current, so the server switched to the
    /// local machine and ungrabbed. The client stays in the rotation and
    /// keeps being pinged so its recovery can be heard.
    silenced_since: Option<Instant>,
    /// Consecutive heard-events received while silenced, for the
    /// re-activation hysteresis (see REACTIVATE_PONGS). A heard-event is one
    /// read chunk on either stream, so a single chunk carrying several
    /// buffered pongs still counts once. A fresh miss resets this to 0.
    recovery_pongs: u32,
}

impl LivenessState {
    /// Fresh state: just heard from, not silenced. A newly connected or
    /// freshly switched-to client gets the full miss window before the
    /// silence detector can fire.
    fn new() -> Self {
        LivenessState {
            last_heard: Instant::now(),
            silenced_since: None,
            recovery_pongs: 0,
        }
    }
}


/// Whether the client has missed enough pings to be declared silent
/// (`miss_limit` x PING_INTERVAL without anything received).
fn miss_limit_reached(state: &LivenessState, now: &Instant, miss_limit: u32) -> bool {
    now.duration_since(state.last_heard) >= PING_INTERVAL * miss_limit
}

/// Whether a silenced client's re-activation bar is met: enough consecutive
/// messages AND the cooldown served. Both are required; either alone lets a
/// flapping link yank the grab back and forth.
fn recovery_complete(state: &LivenessState, now: &Instant) -> bool {
    match state.silenced_since {
        Some(since) => {
            state.recovery_pongs >= REACTIVATE_PONGS
                && now.duration_since(since) >= REACTIVATE_COOLDOWN
        }
        None => false,
    }
}

/// What hearing from a client meant.
#[derive(Debug, PartialEq, Eq)]
pub enum Heard {
    /// Nothing to act on: an ordinary message from a healthy client, or a
    /// silenced one that has not cleared the recovery bar yet.
    Noted,
    /// A silenced client cleared the bar and is healthy again.
    Recovered { pongs: u32, silenced_for: Duration },
}

/// What a ping tick should do this round.
#[derive(Debug, PartialEq, Eq)]
pub struct TickPlan {
    /// True when the tick arrived so late that silence cannot be judged: the
    /// pings this detector relies on originate from the same loop, so a stall
    /// would otherwise guarantee a spurious silence declaration at the first
    /// catch-up tick.
    pub late: bool,
    /// How long the gap was, when there was a previous tick.
    pub gap: Option<Duration>,
}

/// Per-client liveness bookkeeping for the whole rotation.
///
/// Owns the map, the miss limit, the tick baseline and which endpoint's
/// silence (if any) put the input back on the local machine. Kept apart from
/// the rotation so the hysteresis — the part with the subtle timing — can be
/// driven directly in tests.
pub struct LivenessTracker {
    states: HashMap<SocketAddr, LivenessState>,
    /// PONG_MISS_LIMIT on local networks, WWW_PONG_MISS_LIMIT in --www mode.
    miss_limit: u32,
    /// When the last ping tick ran (the stall guard's baseline).
    last_tick: Option<Instant>,
    /// Whether the current LOCAL target came from the silence detector, and
    /// WHICH endpoint's silence caused it. Automatic re-activation only fires
    /// for that specific endpoint: if A silences, the user picks B, and A
    /// recovers first, input must NOT jump back to A.
    silenced_endpoint: Option<SocketAddr>,
}

impl LivenessTracker {
    pub fn new(miss_limit: u32) -> Self {
        LivenessTracker {
            states: HashMap::new(),
            miss_limit,
            last_tick: None,
            silenced_endpoint: None,
        }
    }

    /// A (re)connecting client gets a fresh window: stale bookkeeping must
    /// not re-fire instantly, and if it is still silent the detector simply
    /// ungrabs again.
    pub fn track(&mut self, endpoint: SocketAddr) {
        self.states.insert(endpoint, LivenessState::new());
    }

    pub fn forget(&mut self, endpoint: &SocketAddr) {
        self.states.remove(endpoint);
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    pub fn silenced_endpoint(&self) -> Option<SocketAddr> {
        self.silenced_endpoint
    }

    /// A manual switch action supersedes any silence-driven local state.
    pub fn clear_silenced(&mut self) {
        self.silenced_endpoint = None;
    }

    /// Records proof of liveness. ANY received message counts, not just
    /// Pongs; while silenced, each received CHUNK advances the recovery
    /// counter, so pongs buffered through a freeze can clear the bar in one
    /// burst on thaw.
    pub fn heard(&mut self, endpoint: SocketAddr, now: Instant) -> Heard {
        let Some(state) = self.states.get_mut(&endpoint) else {
            // Already removed (a late chunk racing the removal).
            return Heard::Noted;
        };
        state.last_heard = now;
        if state.silenced_since.is_none() {
            return Heard::Noted;
        }
        state.recovery_pongs += 1;
        if !recovery_complete(state, &now) {
            return Heard::Noted;
        }
        let pongs = state.recovery_pongs;
        let silenced_for = state
            .silenced_since
            .map(|since| now.duration_since(since))
            .unwrap_or_default();
        state.silenced_since = None;
        state.recovery_pongs = 0;
        Heard::Recovered {
            pongs,
            silenced_for,
        }
    }

    /// Opens a ping round, reporting whether silence may be judged this time.
    /// A late tick also refreshes every window: after a stall we cannot know
    /// whether a client was actually silent, and the QUIC idle timeout
    /// remains the backstop for a truly dead one.
    pub fn begin_tick(&mut self, now: Instant) -> TickPlan {
        let gap = self.last_tick.map(|last| now.duration_since(last));
        self.last_tick = Some(now);
        let late = gap.is_some_and(|gap| gap > PING_INTERVAL * 2);
        if late {
            for state in self.states.values_mut() {
                state.last_heard = now;
            }
        }
        TickPlan { late, gap }
    }

    /// How long the endpoint has been silent, when it has passed the miss
    /// limit; None while it is still within the window.
    pub fn silent_for(&self, endpoint: &SocketAddr, now: Instant) -> Option<Duration> {
        let state = self.states.get(endpoint)?;
        miss_limit_reached(state, &now, self.miss_limit)
            .then(|| now.duration_since(state.last_heard))
    }

    /// Marks an endpoint silenced and arms automatic re-activation for it.
    pub fn silence(&mut self, endpoint: SocketAddr, now: Instant) {
        let state = self.states.entry(endpoint).or_insert_with(LivenessState::new);
        state.silenced_since = Some(now);
        state.recovery_pongs = 0;
        self.silenced_endpoint = Some(endpoint);
    }

    /// A fresh miss while a silenced client was recovering resets its
    /// consecutive counter (hysteresis against a flapping link).
    pub fn reset_stalled_recoveries(&mut self, now: Instant) -> Vec<SocketAddr> {
        let miss_limit = self.miss_limit;
        let reset: Vec<SocketAddr> = self
            .states
            .iter()
            .filter(|(_, s)| {
                s.silenced_since.is_some()
                    && s.recovery_pongs > 0
                    && miss_limit_reached(s, &now, miss_limit)
            })
            .map(|(endpoint, _)| *endpoint)
            .collect();
        for endpoint in &reset {
            if let Some(state) = self.states.get_mut(endpoint) {
                state.recovery_pongs = 0;
            }
        }
        reset
    }

    /// Who to ping: the current client, plus every silenced one so a
    /// returning client can be heard.
    pub fn ping_targets(&self, current: Option<SocketAddr>) -> Vec<SocketAddr> {
        let mut targets: Vec<SocketAddr> = self
            .states
            .iter()
            .filter(|(_, s)| s.silenced_since.is_some())
            .map(|(endpoint, _)| *endpoint)
            .collect();
        if let Some(current) = current {
            if !targets.contains(&current) {
                targets.push(current);
            }
        }
        targets
    }

    /// Test hook: backdate an endpoint's last-heard so the detector fires.
    #[cfg(test)]
    pub fn backdate_for_test(&mut self, endpoint: &SocketAddr, by: Duration) {
        if let Some(state) = self.states.get_mut(endpoint) {
            state.last_heard = Instant::now() - by;
        }
    }

    /// Test hook: put an endpoint into a recoverable silenced state.
    #[cfg(test)]
    pub fn silence_for_test(&mut self, endpoint: SocketAddr, since: Instant) {
        let state = self.states.entry(endpoint).or_insert_with(LivenessState::new);
        state.silenced_since = Some(since);
        state.recovery_pongs = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(spec: &str) -> SocketAddr {
        spec.parse().unwrap()
    }

    #[test]
    fn silence_needs_the_full_miss_window() {
        let mut t = LivenessTracker::new(PONG_MISS_LIMIT);
        let a = addr("10.0.0.1:1");
        t.track(a);
        assert_eq!(t.silent_for(&a, Instant::now()), None, "just heard from");

        // One millisecond short of the window: still not silent.
        t.backdate_for_test(&a, PING_INTERVAL * PONG_MISS_LIMIT - Duration::from_millis(1));
        assert_eq!(t.silent_for(&a, Instant::now()), None, "inside the window");

        // Past it: silent, and the reported duration is the real gap.
        t.backdate_for_test(&a, PING_INTERVAL * PONG_MISS_LIMIT + Duration::from_millis(50));
        let silent = t.silent_for(&a, Instant::now()).expect("past the miss window");
        assert!(silent >= PING_INTERVAL * PONG_MISS_LIMIT, "{:?}", silent);

        // An untracked endpoint is never "silent" — it is simply gone.
        assert_eq!(t.silent_for(&addr("10.0.0.9:9"), Instant::now()), None);

        // The WWW limit is more forgiving at the same elapsed time.
        let mut www = LivenessTracker::new(WWW_PONG_MISS_LIMIT);
        www.track(a);
        www.backdate_for_test(&a, PING_INTERVAL * PONG_MISS_LIMIT + Duration::from_millis(50));
        assert_eq!(www.silent_for(&a, Instant::now()), None);
    }

    #[test]
    fn recovery_needs_both_pongs_and_cooldown() {
        let mut t = LivenessTracker::new(PONG_MISS_LIMIT);
        let a = addr("10.0.0.1:1");
        t.track(a);
        let t0 = Instant::now();
        t.silence(a, t0);
        assert_eq!(t.silenced_endpoint(), Some(a));

        // Enough pongs, but the cooldown has not been served.
        for _ in 0..REACTIVATE_PONGS {
            assert_eq!(t.heard(a, t0 + Duration::from_millis(10)), Heard::Noted);
        }
        // Cooldown served, and the next message clears the bar.
        match t.heard(a, t0 + REACTIVATE_COOLDOWN + Duration::from_secs(1)) {
            Heard::Recovered { pongs, .. } => assert!(pongs > REACTIVATE_PONGS),
            other => panic!("expected recovery, got {:?}", other),
        }
        // ...and it does not fire twice.
        assert_eq!(
            t.heard(a, t0 + REACTIVATE_COOLDOWN + Duration::from_secs(2)),
            Heard::Noted
        );
    }

    #[test]
    fn a_late_tick_refuses_to_judge_silence() {
        let mut t = LivenessTracker::new(PONG_MISS_LIMIT);
        let a = addr("10.0.0.1:1");
        t.track(a);
        let t0 = Instant::now();
        assert!(!t.begin_tick(t0).late, "the first tick sets the baseline");
        // A tick arriving after a long stall must refresh the windows rather
        // than declare every client silent.
        t.backdate_for_test(&a, PING_INTERVAL * (PONG_MISS_LIMIT + 2));
        let plan = t.begin_tick(t0 + PING_INTERVAL * 5);
        assert!(plan.late);
        assert_eq!(t.silent_for(&a, Instant::now()), None, "windows refreshed");
    }

    #[test]
    fn ping_targets_cover_the_current_and_every_silenced_client() {
        let mut t = LivenessTracker::new(PONG_MISS_LIMIT);
        let (a, b, c) = (addr("10.0.0.1:1"), addr("10.0.0.2:2"), addr("10.0.0.3:3"));
        for e in [a, b, c] {
            t.track(e);
        }
        t.silence(b, Instant::now());
        let mut targets = t.ping_targets(Some(a));
        targets.sort();
        assert_eq!(targets, vec![a, b]);
        // The current client is not duplicated when it is the silenced one.
        assert_eq!(t.ping_targets(Some(b)), vec![b]);
    }

    #[test]
    fn a_fresh_miss_resets_a_stalled_recovery() {
        let mut t = LivenessTracker::new(PONG_MISS_LIMIT);
        let a = addr("10.0.0.1:1");
        t.track(a);
        let t0 = Instant::now();
        t.silence(a, t0);
        t.heard(a, t0);
        // It goes quiet again mid-recovery.
        t.backdate_for_test(&a, PING_INTERVAL * (PONG_MISS_LIMIT + 1));
        assert_eq!(t.reset_stalled_recoveries(Instant::now()), vec![a]);
        // ...so the bar must be cleared from scratch.
        for _ in 0..REACTIVATE_PONGS - 1 {
            assert_eq!(
                t.heard(a, t0 + REACTIVATE_COOLDOWN + Duration::from_secs(1)),
                Heard::Noted
            );
        }
    }
}
