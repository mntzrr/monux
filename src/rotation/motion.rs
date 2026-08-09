//! Pointer-motion coalescing and the datagram frames it produces.
//!
//! Motion is the one input stream where losing an update is fine and delay is
//! not: each delta is superseded by the next, so it rides unreliable QUIC
//! datagrams rather than the ordered stream, and lost frames are healed from
//! repeated history instead of retransmitted (see msgs::event::MotionDatagram).
//!
//! This type owns the accumulator, the sequence number and the history; it
//! never touches a connection. It hands the caller bytes, and the caller —
//! which owns the client links — decides where they go.

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;
use tracing::trace;

use crate::msgs::event;
use crate::network::link_quality::Tier;

use super::{MotionMode, ADAPTIVE_MOTION_NORMAL_HZ, ADAPTIVE_MOTION_PROXIMITY_HZ};

/// How many recent coalesced motion deltas each datagram repeats (see
/// MotionDatagram.history). At the default 250 Hz flush rate, 32 frames cover
/// a 128 ms loss burst — far longer than a typical WiFi blip — for ~300 extra
/// bytes per datagram (each frame is ≤10 postcard bytes). Full-rate mode sends
/// no redundancy (lost = skipped).
const MOTION_HISTORY_LEN: usize = 32;

/// Returns true if the batch consists solely of relative X/Y pointer motion,
/// which is safe to send over unreliable datagrams: each update is a delta that
/// is immediately superseded by the next one. Buttons, wheel, and absolute axes
/// must NOT be lost or reordered and always stay on the ordered stream.
pub fn is_pure_pointer_motion(events: &[event::InputEvent]) -> bool {
    const EV_REL: u16 = evdev::EventType::RELATIVE.0;
    const REL_X: u16 = evdev::RelativeAxisCode::REL_X.0;
    const REL_Y: u16 = evdev::RelativeAxisCode::REL_Y.0;
    !events.is_empty()
        && events.iter().all(|e| {
            e.inputf64.is_none()
                && matches!(&e.inputi32, Some(i) if i.type_ == EV_REL && (i.code == REL_X || i.code == REL_Y))
        })
}


/// Coalesced pointer motion awaiting a flush.
pub struct MotionCoalescer {
    /// Summed deltas plus the source event count, flushed on a timer at the
    /// --motion-hz rate. Summing is lossless: the cursor ends up in the same
    /// place with far less traffic.
    pending: (i32, i32, u64),
    /// Whether `pending` holds unsent deltas.
    dirty: bool,
    /// Sequence number for the next datagram. Only monotonicity within a
    /// connection matters (for the receiver's stale-drop).
    seq: u64,
    /// Recently flushed deltas, newest first. Each coalesced datagram repeats
    /// up to MOTION_HISTORY_LEN of them so the client can heal lost frames.
    /// Cleared on every switch: deltas flushed to one client are moot for
    /// another.
    history: VecDeque<(i32, i32)>,
    /// Reusable serialization scratch; at motion rates a fresh Vec per frame
    /// is pure allocator churn.
    scratch: Vec<u8>,
    /// Reusable newest-first history buffer, refilled before each datagram.
    history_scratch: Vec<(i32, i32)>,
    /// How the flush rate is chosen (see MotionMode).
    mode: MotionMode,
    /// Set once the datagram path has been announced in the log.
    announced: bool,
}

impl MotionCoalescer {
    pub fn new(mode: MotionMode) -> Self {
        MotionCoalescer {
            pending: (0, 0, 0),
            dirty: false,
            seq: 0,
            history: VecDeque::new(),
            scratch: Vec::new(),
            history_scratch: Vec::new(),
            mode,
            announced: false,
        }
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The pending deltas, for the state dump.
    pub fn pending(&self) -> (i32, i32, u64) {
        self.pending
    }

    /// Whether the datagram path has already been announced, marking it as
    /// announced if not (so the log line fires exactly once).
    pub fn announce_once(&mut self) -> bool {
        let first = !self.announced;
        self.announced = true;
        first
    }

    /// The flush interval currently in effect: pinned by --motion-hz, or
    /// derived from the current client's measured link tier in Adaptive mode
    /// (None = forward every event as it comes).
    pub fn flush_interval(&self, tier: Tier) -> Option<Duration> {
        match self.mode {
            MotionMode::Pinned(interval) => interval,
            MotionMode::Adaptive => Some(Duration::from_secs_f64(
                1.0 / match tier {
                    Tier::Normal => ADAPTIVE_MOTION_NORMAL_HZ,
                    Tier::Proximity => ADAPTIVE_MOTION_PROXIMITY_HZ,
                } as f64,
            )),
        }
    }

    /// Adds a pure-motion batch to the accumulator.
    pub fn accumulate(&mut self, events: &[event::InputEvent]) {
        for e in events {
            if let Some(i) = &e.inputi32 {
                if i.code == evdev::RelativeAxisCode::REL_X.0 {
                    self.pending.0 = self.pending.0.saturating_add(i.value);
                } else {
                    self.pending.1 = self.pending.1.saturating_add(i.value);
                }
            }
        }
        self.pending.2 += events.len() as u64;
        self.dirty = true;
        trace!(
            "Accumulated motion: dx={} dy={} ({} events pending)",
            self.pending.0, self.pending.1, self.pending.2
        );
    }

    /// Takes the pending deltas, clearing the accumulator.
    pub fn take_pending(&mut self) -> (i32, i32, u64) {
        self.dirty = false;
        std::mem::take(&mut self.pending)
    }

    /// Puts deltas back after a send that couldn't be queued, so they retry
    /// with any newer motion accumulated on top.
    pub fn restore_pending(&mut self, pending: (i32, i32, u64)) {
        self.pending = pending;
        self.dirty = true;
    }

    /// Everything accumulated (or already flushed) for the previous target is
    /// moot after a switch or a pause.
    pub fn clear(&mut self) {
        self.pending = (0, 0, 0);
        self.dirty = false;
        self.history.clear();
    }

    /// Stages a frame carrying `(dx, dy)` plus the recent history, and
    /// serializes it. `with_history` is false for full-rate motion, where a
    /// superseded frame is better skipped than healed.
    pub fn stage(&mut self, dx: i32, dy: i32, with_history: bool) -> Option<Bytes> {
        self.history_scratch.clear();
        self.history_scratch.push((dx, dy));
        if with_history {
            self.history_scratch.extend(self.history.iter().copied());
        }
        let seq = self.seq.wrapping_add(1);
        // The wire type owns its history, so the reusable scratch is taken out
        // for the serialization and put right back — its capacity survives.
        let msg = event::MotionDatagram {
            seq,
            history: std::mem::take(&mut self.history_scratch),
        };
        self.scratch.clear();
        let result = postcard::to_io(&msg, &mut self.scratch);
        self.history_scratch = msg.history;
        match result {
            Ok(_) => Some(Bytes::copy_from_slice(&self.scratch)),
            Err(e) => {
                tracing::error!("Failed to serialize motion datagram: {:?}", e);
                None
            }
        }
    }

    /// Confirms a staged frame went out: the sequence advances and the deltas
    /// join the history other frames repeat.
    pub fn record_sent(&mut self, dx: i32, dy: i32, with_history: bool) {
        self.seq = self.seq.wrapping_add(1);
        if with_history {
            self.history.push_front((dx, dy));
            self.history.truncate(MOTION_HISTORY_LEN);
        }
    }

    /// How many frames the last staged datagram carried, for the trace line.
    pub fn staged_frames(&self) -> usize {
        self.history_scratch.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(code: u16, value: i32) -> event::InputEvent {
        event::InputEvent {
            inputi32: Some(event::InputI32 {
                type_: evdev::EventType::RELATIVE.0,
                code,
                value,
            }),
            inputf64: None,
        }
    }

    #[test]
    fn deltas_sum_losslessly_until_taken() {
        let mut m = MotionCoalescer::new(MotionMode::Pinned(Some(Duration::from_millis(4))));
        assert!(!m.dirty());
        let rel_x = evdev::RelativeAxisCode::REL_X.0;
        let rel_y = evdev::RelativeAxisCode::REL_Y.0;
        for (dx, dy) in [(3, -2), (1, 0), (-2, 5)] {
            m.accumulate(&[rel(rel_x, dx), rel(rel_y, dy)]);
        }
        assert!(m.dirty());
        // The cursor ends up exactly where the individual events would have
        // put it — that is what makes coalescing free.
        assert_eq!(m.take_pending(), (2, 3, 6));
        assert!(!m.dirty(), "taking clears the accumulator");
        assert_eq!(m.take_pending(), (0, 0, 0));
    }

    #[test]
    fn a_frame_that_could_not_be_queued_is_retried_with_newer_motion_on_top() {
        let mut m = MotionCoalescer::new(MotionMode::Pinned(Some(Duration::from_millis(4))));
        m.accumulate(&[rel(evdev::RelativeAxisCode::REL_X.0, 5)]);
        let pending = m.take_pending();
        // The send didn't take it: put it back rather than losing the motion.
        m.restore_pending(pending);
        assert!(m.dirty());
        m.accumulate(&[rel(evdev::RelativeAxisCode::REL_X.0, 2)]);
        assert_eq!(m.take_pending(), (7, 0, 2));
    }

    #[test]
    fn history_is_repeated_for_coalesced_frames_and_capped() {
        let mut m = MotionCoalescer::new(MotionMode::Pinned(Some(Duration::from_millis(4))));
        for i in 0..MOTION_HISTORY_LEN + 10 {
            assert!(m.stage(i as i32, 0, true).is_some());
            m.record_sent(i as i32, 0, true);
        }
        // The staged frame carries this delta plus the capped history.
        assert!(m.stage(1, 1, true).is_some());
        assert_eq!(m.staged_frames(), MOTION_HISTORY_LEN + 1);
    }

    #[test]
    fn full_rate_frames_carry_no_history() {
        let mut m = MotionCoalescer::new(MotionMode::Pinned(None));
        m.stage(1, 0, true);
        m.record_sent(1, 0, true);
        // At full rate a lost frame is superseded, not healed: sending the
        // history would be bytes spent on nothing.
        assert!(m.stage(2, 0, false).is_some());
        assert_eq!(m.staged_frames(), 1);
    }

    #[test]
    fn the_sequence_only_advances_on_a_confirmed_send() {
        let mut m = MotionCoalescer::new(MotionMode::Pinned(None));
        assert_eq!(m.seq(), 0);
        // Staging alone must not burn a sequence number: the receiver treats
        // a gap as a lost frame and would try to heal one that never existed.
        m.stage(1, 0, false);
        assert_eq!(m.seq(), 0);
        m.record_sent(1, 0, false);
        assert_eq!(m.seq(), 1);
    }

    #[test]
    fn a_switch_drops_everything_owed_to_the_old_target() {
        let mut m = MotionCoalescer::new(MotionMode::Pinned(Some(Duration::from_millis(4))));
        m.accumulate(&[rel(evdev::RelativeAxisCode::REL_X.0, 9)]);
        m.record_sent(9, 0, true);
        m.clear();
        assert!(!m.dirty());
        assert_eq!(m.pending(), (0, 0, 0));
        // ...and the history no longer follows the cursor to the new machine.
        m.stage(1, 0, true);
        assert_eq!(m.staged_frames(), 1);
    }

    #[test]
    fn adaptive_rate_follows_the_tier_and_pinning_overrides_it() {
        let adaptive = MotionCoalescer::new(MotionMode::Adaptive);
        let normal = adaptive.flush_interval(Tier::Normal).unwrap();
        let close = adaptive.flush_interval(Tier::Proximity).unwrap();
        assert!(close < normal, "a close link flushes more often");

        let pinned = MotionCoalescer::new(MotionMode::Pinned(Some(Duration::from_millis(16))));
        assert_eq!(
            pinned.flush_interval(Tier::Proximity),
            Some(Duration::from_millis(16)),
            "an explicit --motion-hz ignores the tier"
        );
        // --motion-hz 0: no coalescing at all.
        let full = MotionCoalescer::new(MotionMode::Pinned(None));
        assert_eq!(full.flush_interval(Tier::Normal), None);
    }

    #[test]
    fn the_datagram_announcement_fires_once() {
        let mut m = MotionCoalescer::new(MotionMode::Pinned(None));
        assert!(m.announce_once());
        assert!(!m.announce_once());
    }
}
