//! Data caps: what each link carried this day or month, kept in `/var/lib/heimdall-multilink/usage.json` so a restart or
//! a reboot does not forget it. Everything the interface carried counts (sent and received), from the kernel's counters,
//! while the service runs. A link past its cap is kept for backup only until the period starts again.

use std::collections::BTreeMap;
use std::path::Path;

use crate::config::Period;

/// The period a date falls in: "2026-11-15" for a day, "2026-11" for a month.
pub fn period_key(p: Period, (y, m, d): (i32, u32, u32)) -> String {
    match p {
        Period::Day => format!("{y:04}-{m:02}-{d:02}"),
        Period::Month => format!("{y:04}-{m:02}"),
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Usage {
    /// link -> (period key, bytes)
    pub links: BTreeMap<String, (String, u64)>,
}

impl Usage {
    pub fn load(path: &Path) -> Usage {
        let mut u = Usage::default();
        let Ok(t) = std::fs::read_to_string(path) else { return u };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) else { return u };
        for (name, e) in v.as_object().into_iter().flatten() {
            if let (Some(p), Some(b)) = (e.get("period").and_then(|p| p.as_str()), e.get("bytes").and_then(|b| b.as_u64())) {
                u.links.insert(name.clone(), (p.to_string(), b));
            }
        }
        u
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let v: serde_json::Map<String, serde_json::Value> =
            self.links.iter().map(|(n, (p, b))| (n.clone(), serde_json::json!({"period": p, "bytes": b}))).collect();
        crate::sys::write_atomic(path, &(serde_json::Value::Object(v).to_string() + "\n"))
    }

    /// Count `bytes` for `link` in period `key` (a new period starts from 0). Returns the total in this period.
    pub fn add(&mut self, link: &str, key: &str, bytes: u64) -> u64 {
        let e = self.links.entry(link.to_string()).or_insert_with(|| (key.to_string(), 0));
        if e.0 != key {
            *e = (key.to_string(), 0);
        }
        e.1 += bytes;
        e.1
    }

    pub fn used(&self, link: &str, key: &str) -> u64 {
        self.links.get(link).filter(|(k, _)| k == key).map_or(0, |(_, b)| *b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periods_start_again() {
        let mut u = Usage::default();
        assert_eq!(u.add("usb0", "2026-11", 500), 500);
        assert_eq!(u.add("usb0", "2026-11", 500), 1000);
        assert_eq!(u.add("usb0", "2026-12", 7), 7);
        assert_eq!(u.used("usb0", "2026-11"), 0);
        assert_eq!(period_key(Period::Day, (2026, 11, 5)), "2026-11-05");
        assert_eq!(period_key(Period::Month, (2026, 1, 31)), "2026-01");
    }

    #[test]
    fn kept_across_restarts() {
        let d = std::env::temp_dir().join(format!("multilink-usage-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("usage.json");
        let mut u = Usage::default();
        u.add("usb0", "2026-11", 1234);
        u.save(&p).unwrap();
        assert_eq!(Usage::load(&p), u);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
