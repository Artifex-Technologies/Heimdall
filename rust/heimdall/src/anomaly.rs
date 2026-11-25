//! Each host-telemetry field's last hour, minute by minute: whether a value was out of this host's usual range (HEI-80,
//! after Netdata's anomaly bit), for Settings to show beside its graph. The baseline detector
//! (`detect::stateful::BaselineDriftDetector`) marks a minute as it scores each value; `GET /v1/telemetry` reads the hour.
//!
//! "Out of range" is the baseline's own rule without the alert's extras: the value is `baseline_z_threshold` standard
//! deviations or more from this host's learned mean, either way (the alert is upward only and above floors, so a bit can
//! be set with no alert). A minute with no scored value (no telemetry, or still learning) is unknown. Kept in memory
//! only: after a restart the hour starts empty.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// How many minutes are kept and answered.
pub const MINUTES: i64 = 60;

/// Per field, per minute since 1970 (unix seconds / 60): whether any value scored in it was out of range.
#[derive(Debug, Default)]
pub struct Minutes {
    fields: BTreeMap<String, BTreeMap<i64, bool>>,
}

/// The record the detector writes and the API reads.
pub type Shared = Arc<Mutex<Minutes>>;

impl Minutes {
    /// A value of `field` scored at `unix` (seconds): `out` when it was out of range. Minutes older than the hour before
    /// the newest are dropped.
    pub fn mark(&mut self, field: &str, unix: i64, out: bool) {
        let m = unix.div_euclid(60);
        let f = self.fields.entry(field.to_string()).or_default();
        *f.entry(m).or_insert(false) |= out;
        let newest = f.keys().next_back().copied().unwrap_or(m);
        f.retain(|k, _| *k > newest - MINUTES);
    }

    /// `field`'s hour up to the minute of `now` (unix seconds), oldest first: one character a minute, '1' a value out
    /// of range, '0' values all within it, '-' none scored.
    pub fn hour(&self, field: &str, now: i64) -> String {
        let last = now.div_euclid(60);
        let f = self.fields.get(field);
        (last - MINUTES + 1..=last)
            .map(|m| match f.and_then(|f| f.get(&m)) {
                Some(true) => '1',
                Some(false) => '0',
                None => '-',
            })
            .collect()
    }

    /// The answer of `GET /v1/telemetry`: `{"minutes":60,"until":"<the last minute, RFC 3339>","fields":{"load_per_cpu":
    /// "--0...1",...}}`, each field that has been scored.
    pub fn to_json(&self, now: i64) -> String {
        let until = crate::gotime::Time::from_unix(now.div_euclid(60) * 60, 0).utc().rfc3339_nano();
        let mut b = format!("{{\"minutes\":{MINUTES},\"until\":\"{until}\",\"fields\":{{");
        for (i, f) in self.fields.keys().enumerate() {
            if i > 0 {
                b.push(',');
            }
            b.push_str(&format!("\"{f}\":\"{}\"", self.hour(f, now)));
        }
        b.push_str("}}");
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_hour_minute_by_minute() {
        let mut m = Minutes::default();
        let t0 = 1_764_000_000; // the start of a minute (a multiple of 60)
        m.mark("mem_percent", t0, false);
        m.mark("mem_percent", t0 + 30, true); // one value out of range sets its minute
        m.mark("mem_percent", t0 + 60, false);
        m.mark("load_per_cpu", t0 + 180, false);
        let h = m.hour("mem_percent", t0 + 180);
        assert_eq!(h.len(), 60);
        assert!(h.ends_with("10--"), "{h}");
        assert!(h[..56].chars().all(|c| c == '-'));
        assert_eq!(m.hour("load_per_cpu", t0 + 180).chars().last(), Some('0'));
        assert_eq!(m.hour("never", t0), "-".repeat(60));
        // an hour later the minutes before it are gone; the one 59 minutes back is the hour's first
        m.mark("mem_percent", t0 + 3600, false);
        assert_eq!(m.fields["mem_percent"].len(), 2);
        let h = m.hour("mem_percent", t0 + 3600);
        assert!(h.starts_with('0') && h.ends_with("-0"), "{h}");
        let j = m.to_json(t0 + 3600);
        assert!(j.starts_with("{\"minutes\":60,\"until\":\"") && j.contains("\"mem_percent\":\""), "{j}");
        assert!(gojson_ok(&j), "{j}");
    }

    fn gojson_ok(s: &str) -> bool {
        crate::gojson::parse(s.as_bytes()).is_ok()
    }
}
