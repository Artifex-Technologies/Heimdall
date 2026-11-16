//! How many of the new connections each link gets.
//!
//! A link's speed is learned from what it has carried: the highest rate seen on it (bytes sent and received per second,
//! from the kernel's counters), forgotten slowly (half of it after about ten minutes), so a link that got faster or slower
//! is noticed. Until a link has carried much, it counts as 1 MB/s, so new links start with an equal share. Each link keeps
//! at least 5 % (otherwise a slow-looking link would never get the traffic that shows it is fast), a link much slower to
//! answer than the best one gets half its share, and a link with a share limit never gets more than it.

use std::time::Duration;

/// What one link's counters showed.
#[derive(Clone, Debug, Default)]
pub struct Rate {
    last: Option<u64>,
    /// bytes per second over the last tick
    pub now: f64,
    /// the highest rate seen, forgotten slowly
    pub peak: f64,
}

pub const FLOOR: f64 = 1_000_000.0;
const FORGET_HALF: f64 = 600.0;
const MIN_SHARE: f64 = 0.05;

impl Rate {
    /// The counter (bytes sent plus received since the interface came up) `dt` after the last one. Returns the bytes
    /// carried since then (0 the first time, or when the counter went back: the interface was made again).
    pub fn update(&mut self, counter: u64, dt: Duration) -> u64 {
        let secs = dt.as_secs_f64().max(0.001);
        let carried = match self.last {
            Some(l) if counter >= l => counter - l,
            _ => 0,
        };
        self.last = Some(counter);
        self.now = carried as f64 / secs;
        self.peak = (self.peak * 0.5f64.powf(secs / FORGET_HALF)).max(self.now);
        carried
    }
}

/// One link that is in the multipath route.
#[derive(Clone, Debug)]
pub struct Input {
    pub peak: f64,
    /// how long the last health check took to connect
    pub rtt: Option<Duration>,
    /// the owner's limit, percent
    pub share: Option<u8>,
}

/// Each link's share (0 to 1, summing to 1).
pub fn shares(links: &[Input]) -> Vec<f64> {
    if links.is_empty() {
        return vec![];
    }
    let best_rtt = links.iter().filter_map(|l| l.rtt).min();
    let mut s: Vec<f64> = links
        .iter()
        .map(|l| {
            let mut v = l.peak.max(FLOOR);
            if let (Some(r), Some(b)) = (l.rtt, best_rtt) {
                if r > b * 2 && r > b + Duration::from_millis(80) {
                    v *= 0.5;
                }
            }
            v
        })
        .collect();
    normalise(&mut s);
    for x in s.iter_mut() {
        *x = x.max(MIN_SHARE);
    }
    normalise(&mut s);
    // the owner's limits: a link over its limit is held at it, and what it gives up goes to the others in proportion
    let limit: Vec<Option<f64>> = links.iter().map(|l| l.share.map(|p| f64::from(p) / 100.0)).collect();
    for _ in 0..links.len() {
        let mut excess = 0.0;
        let mut free = 0.0;
        for (i, x) in s.iter_mut().enumerate() {
            match limit[i] {
                Some(m) if *x > m + 1e-9 => {
                    excess += *x - m;
                    *x = m;
                }
                Some(m) if *x >= m - 1e-9 => {}
                _ => free += *x,
            }
        }
        if excess <= 1e-9 {
            break;
        }
        if free <= 1e-9 {
            // every link is at its limit (the limits add up to less than 100 %): share in proportion to the limits
            normalise(&mut s);
            break;
        }
        for (i, x) in s.iter_mut().enumerate() {
            if limit[i].is_none_or(|m| *x < m - 1e-9) {
                *x += excess * *x / free;
            }
        }
    }
    s
}

fn normalise(s: &mut [f64]) {
    let total: f64 = s.iter().sum();
    if total > 0.0 {
        for x in s.iter_mut() {
            *x /= total;
        }
    }
}

/// Shares as route weights (1-100).
pub fn weights(shares: &[f64]) -> Vec<u8> {
    shares.iter().map(|s| (s * 100.0).round().clamp(1.0, 100.0) as u8).collect()
}

/// Whether new weights differ enough from the ones in the route to change it (each change of the route is a little work
/// for the kernel and for us; a few percent either way changes nothing that matters).
pub fn differ(old: &[u8], new: &[u8]) -> bool {
    old.len() != new.len() || old.iter().zip(new).any(|(a, b)| a.abs_diff(*b) >= 5)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(peak: f64) -> Input {
        Input { peak, rtt: None, share: None }
    }

    #[test]
    fn new_links_start_equal_and_learned_speeds_set_the_share() {
        assert_eq!(weights(&shares(&[input(0.0), input(0.0)])), vec![50, 50]);
        let w = weights(&shares(&[input(5_000_000.0), input(1_250_000.0)]));
        assert_eq!(w, vec![80, 20]);
    }

    #[test]
    fn a_slow_link_keeps_five_percent() {
        let w = weights(&shares(&[input(100_000_000.0), input(10_000.0)]));
        assert!(w[1] >= 4 && w[1] <= 6, "{w:?}");
    }

    #[test]
    fn a_share_limit_holds_and_the_rest_goes_to_the_others() {
        let mut a = input(9_000_000.0);
        a.share = Some(30);
        let w = weights(&shares(&[a, input(1_000_000.0), input(1_000_000.0)]));
        assert_eq!(w[0], 30);
        assert_eq!(w[1], 35);
        assert_eq!(w[2], 35);
    }

    #[test]
    fn limits_that_add_up_to_less_than_everything() {
        let mut a = input(1.0);
        a.share = Some(20);
        let mut b = input(1.0);
        b.share = Some(20);
        assert_eq!(weights(&shares(&[a, b])), vec![50, 50]);
    }

    #[test]
    fn a_much_slower_answer_halves_the_share() {
        let mut a = input(0.0);
        a.rtt = Some(Duration::from_millis(20));
        let mut b = input(0.0);
        b.rtt = Some(Duration::from_millis(300));
        assert_eq!(weights(&shares(&[a, b])), vec![67, 33]);
    }

    #[test]
    fn rates_and_the_slowly_forgotten_peak() {
        let mut r = Rate::default();
        assert_eq!(r.update(1000, Duration::from_secs(1)), 0);
        assert_eq!(r.update(11_000, Duration::from_secs(1)), 10_000);
        assert_eq!(r.peak, 10_000.0);
        r.update(11_000, Duration::from_secs(600));
        assert!((r.peak - 5_000.0).abs() < 1.0, "{}", r.peak);
        // the interface was made again: its counter starts from 0
        assert_eq!(r.update(10, Duration::from_secs(1)), 0);
    }

    #[test]
    fn small_changes_leave_the_route_alone() {
        assert!(!differ(&[50, 50], &[53, 47]));
        assert!(differ(&[50, 50], &[60, 40]));
        assert!(differ(&[50, 50], &[100]));
    }
}
