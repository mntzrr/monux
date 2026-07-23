//! Adaptive fidelity: on a sustained good link the motion rate and bulk
//! throughput rise above the conservative defaults (the machines are next to
//! each other — act like it); on the first bad sample they snap back.
//! Hysteresis: promotion needs several consecutive good samples, demotion is
//! immediate, and a middling sample (neither good nor bad) is a deadband that
//! keeps the current tier but resets the promotion streak.

use std::time::Duration;

/// A sample at or below this RTT counts as good. A healthy same-room link —
/// wired or uncongested WiFi — runs single-digit milliseconds.
pub const GOOD_RTT: Duration = Duration::from_millis(15);
/// Windowed packet-loss rate at or below this counts as good.
pub const GOOD_LOSS: f64 = 0.01;
/// A sample above this RTT counts as bad (matches the degraded-link warn
/// threshold used elsewhere).
pub const BAD_RTT: Duration = Duration::from_millis(50);
/// Windowed packet-loss rate above this counts as bad.
pub const BAD_LOSS: f64 = 0.02;
/// Consecutive good samples needed to promote Normal -> Proximity. Demotion
/// needs no streak: latency safety wins over stability.
pub const PROMOTE_SAMPLES: u32 = 3;

/// How often the server events loop samples connection stats for the tiers
/// (see rotation::sample_link_quality).
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

/// The fidelity tier a link is currently given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// Conservative defaults (250 Hz motion, 40 Mbps bulk).
    Normal,
    /// The link is measured to be close and clean: raised fidelity
    /// (500 Hz motion, 160 Mbps bulk).
    Proximity,
}

/// Per-connection tier state: fed one stats sample at a time, reports tier
/// transitions so the caller can re-tune the knobs.
pub struct LinkQuality {
    tier: Tier,
    good_streak: u32,
}

impl LinkQuality {
    pub fn new() -> Self {
        LinkQuality {
            tier: Tier::Normal,
            good_streak: 0,
        }
    }

    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// Classifies one sample (rtt + lost/sent over the window) and returns
    /// Some(new tier) on a transition, None when the tier held.
    pub fn sample(&mut self, rtt: Duration, loss_rate: f64) -> Option<Tier> {
        let bad = rtt > BAD_RTT || loss_rate > BAD_LOSS;
        if bad {
            self.good_streak = 0;
            if self.tier != Tier::Normal {
                self.tier = Tier::Normal;
                return Some(self.tier);
            }
            return None;
        }
        let good = rtt <= GOOD_RTT && loss_rate <= GOOD_LOSS;
        if good {
            self.good_streak += 1;
            if self.tier == Tier::Normal && self.good_streak >= PROMOTE_SAMPLES {
                self.tier = Tier::Proximity;
                return Some(self.tier);
            }
            return None;
        }
        // Deadband sample: neither promotes nor demotes, but the promotion
        // streak restarts (the good run must be consecutive).
        self.good_streak = 0;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good(q: &mut LinkQuality) -> Option<Tier> {
        q.sample(Duration::from_millis(3), 0.0)
    }

    fn bad(q: &mut LinkQuality) -> Option<Tier> {
        q.sample(Duration::from_millis(120), 0.05)
    }

    fn neutral(q: &mut LinkQuality) -> Option<Tier> {
        q.sample(Duration::from_millis(30), 0.015)
    }

    #[test]
    fn promotion_needs_consecutive_good_samples() {
        let mut q = LinkQuality::new();
        assert_eq!(good(&mut q), None);
        assert_eq!(good(&mut q), None);
        // A neutral sample in between restarts the streak.
        assert_eq!(neutral(&mut q), None);
        assert_eq!(good(&mut q), None);
        assert_eq!(good(&mut q), None);
        assert_eq!(q.tier(), Tier::Normal);
        assert_eq!(good(&mut q), Some(Tier::Proximity));
        assert_eq!(q.tier(), Tier::Proximity);
        // Further good samples don't re-report the tier.
        assert_eq!(good(&mut q), None);
    }

    #[test]
    fn demotion_is_immediate() {
        let mut q = LinkQuality::new();
        for _ in 0..PROMOTE_SAMPLES {
            good(&mut q);
        }
        assert_eq!(q.tier(), Tier::Proximity);
        assert_eq!(bad(&mut q), Some(Tier::Normal));
        assert_eq!(q.tier(), Tier::Normal);
        // A bad sample in Normal isn't a transition.
        assert_eq!(bad(&mut q), None);
    }

    #[test]
    fn neutral_keeps_the_tier() {
        let mut q = LinkQuality::new();
        for _ in 0..PROMOTE_SAMPLES {
            good(&mut q);
        }
        assert_eq!(q.tier(), Tier::Proximity);
        assert_eq!(neutral(&mut q), None);
        assert_eq!(q.tier(), Tier::Proximity);
    }

    #[test]
    fn loss_alone_drives_the_verdicts() {
        let mut q = LinkQuality::new();
        // Low RTT but heavy loss: bad.
        assert_eq!(q.sample(Duration::from_millis(2), 0.1), None);
        assert_eq!(q.tier(), Tier::Normal);
        // High RTT at zero loss is not "good": no promotion progress.
        assert_eq!(q.sample(Duration::from_millis(20), 0.0), None);
        assert_eq!(q.tier(), Tier::Normal);
    }
}
