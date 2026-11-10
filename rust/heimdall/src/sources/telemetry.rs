//! Host telemetry (Go: internal/sources/hostsource/telemetry.go): memory in use and load per CPU, two /proc reads.

use super::{Msg, Source};
use crate::event::{Event, Fields};
use crate::gotime::Time;
use std::time::{Duration, Instant};

/// MemTotal and MemAvailable in kB.
pub fn parse_meminfo(s: &str) -> Result<(u64, u64), String> {
    let (mut total, mut avail) = (0u64, 0u64);
    for line in s.lines() {
        let f: Vec<&str> = crate::gotext::fields(line).collect();
        if f.len() < 2 {
            continue;
        }
        let v = || {
            f[1].parse::<u64>().map_err(|_| {
                format!("hostsource: parse meminfo: strconv.ParseUint: parsing {}: invalid syntax", crate::gotext::quote(f[1]))
            })
        };
        match f[0].strip_suffix(':').unwrap_or(f[0]) {
            "MemTotal" => total = v()?,
            "MemAvailable" => avail = v()?,
            _ => {}
        }
    }
    if total == 0 {
        return Err("hostsource: meminfo had no MemTotal line".into());
    }
    Ok((total, avail))
}

/// The 1-minute load average.
pub fn parse_loadavg(s: &str) -> Result<f64, String> {
    let first = crate::gotext::fields(s).next().ok_or("hostsource: loadavg had no fields")?;
    crate::gotext::parse_float(first).ok_or_else(|| format!("hostsource: parse loadavg: {first}"))
}

/// The CPUs this process may run on (Go's runtime.NumCPU: the affinity mask, not a cgroup quota).
pub fn num_cpu() -> usize {
    rustix::thread::sched_getaffinity(None).map(|s| s.count() as usize).unwrap_or(1).max(1)
}

pub struct Telemetry {
    pub meminfo: String,
    pub loadavg: String,
    pub cpus: usize,
}

impl Default for Telemetry {
    fn default() -> Self {
        Telemetry { meminfo: "/proc/meminfo".into(), loadavg: "/proc/loadavg".into(), cpus: num_cpu() }
    }
}

impl Telemetry {
    pub fn poll(&self) -> Result<Event, (bool, String)> {
        let rd = |p: &str| {
            std::fs::read_to_string(p).map_err(|e| (e.kind() == std::io::ErrorKind::NotFound, super::go_path_error("open", p, &e)))
        };
        let (total, avail) = parse_meminfo(&rd(&self.meminfo)?).map_err(|e| (false, e))?;
        let mem = 100.0 * (1.0 - avail as f64 / total as f64);
        let load = parse_loadavg(&rd(&self.loadavg)?).map_err(|e| (false, e))?;
        let per = if self.cpus > 0 { load / self.cpus as f64 } else { load };
        Ok(Event {
            source: "host-telemetry".into(),
            session_id: String::new(),
            time: Time::now(),
            kind: "host_telemetry".into(),
            text: String::new(),
            fields: Fields::from([("mem_percent".to_string(), format!("{mem:.2}")), ("load_per_cpu".to_string(), format!("{per:.2}"))]),
        })
    }
}

/// Telemetry on the daemon's loop: a first read only to see that /proc is there (as in Go), then every interval.
pub struct TelemetrySource {
    t: Telemetry,
    interval: Duration,
    next: Instant,
    checked: bool,
    off: bool,
}

impl TelemetrySource {
    pub fn new(t: Telemetry, interval: Duration) -> TelemetrySource {
        TelemetrySource { t, interval, next: Instant::now(), checked: false, off: false }
    }
}

impl Source for TelemetrySource {
    fn name(&self) -> &'static str {
        "telemetry"
    }
    fn due(&self) -> Option<Instant> {
        (!self.off).then_some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        self.next = now + self.interval;
        let r = self.t.poll();
        if !self.checked {
            self.checked = true;
            if let Err((missing, e)) = r {
                if missing {
                    self.off = true;
                    out.push(Msg::Log(format!("host telemetry unavailable, disabling: {e}")));
                } else {
                    out.push(Msg::Log(format!("telemetry poll error: {e}")));
                }
            }
            return;
        }
        match r {
            Ok(e) => out.push(Msg::Event(e)),
            Err((_, e)) => out.push(Msg::Log(format!("telemetry poll error: {e}"))),
        }
    }
}
