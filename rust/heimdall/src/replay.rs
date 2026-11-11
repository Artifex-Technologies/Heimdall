//! Events in and alerts out, as JSON lines: the form the parity fixtures and the differential run use, so the Go daemon's engine
//! and this one can be fed the same events (Go: rust/gotools/replay).
//!
//! An event line: `{"source":..,"session_id":..,"time":"RFC 3339 or empty","kind":..,"text":..,"fields":{..}}`.

use crate::alert::{Alert, Sink};
use crate::config::Config;
use crate::detect::{self, Deps};
use crate::engine::Engine;
use crate::event::{Event, Fields};
use crate::gojson::{self, FromGo, Value};
use crate::gotime::Time;
use crate::maintenance;
use std::io::{BufRead, Write};

#[derive(Default)]
struct EventJson {
    source: String,
    session_id: String,
    time: String,
    kind: String,
    text: String,
    fields: Fields,
}
crate::go_struct!(EventJson { source: "source", session_id: "session_id", time: "time", kind: "kind", text: "text", fields: "fields" });

/// An event from its JSON form.
pub fn event_from_value(v: &Value) -> Result<Event, gojson::Error> {
    let mut j = EventJson::default();
    j.read_into(v, "event")?;
    let time = if j.time.is_empty() {
        Time::default()
    } else {
        Time::parse_rfc3339(&j.time).ok_or_else(|| gojson::Error(format!("bad time {:?}", j.time)))?
    };
    Ok(Event { source: j.source, session_id: j.session_id, time, kind: j.kind, text: j.text, fields: j.fields })
}

struct LineSink<W: Write + Send>(W);

impl<W: Write + Send> Sink for LineSink<W> {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        let mut l = a.to_json();
        l.push('\n');
        self.0.write_all(l.as_bytes())
    }
}

/// Runs every event line of `input` through the daemon's detectors and writes the alerts to `out`. The system is left out:
/// no package database, no trust list, the default temporary port range; the mesh peers, maintenance window and remote
/// approvals come from the given paths.
pub fn run(cfg: &Config, approvals: &str, input: impl BufRead, out: impl Write + Send + 'static) -> Result<usize, String> {
    let peers = cfg.mesh_peers_path.clone();
    let appr = detect::Approvals::new(approvals);
    let deps = Deps {
        verifier: None,
        trust: None,
        mesh_peer: Some(Box::new(move |ip: &str| detect::mesh_peer_at(&peers, ip))),
        approved: Some(Box::new(move |id: &str| appr.approved(id))),
        ephemeral: Some((32768, 60999)),
    };
    let mut eng = Engine::new(Box::new(LineSink(std::io::BufWriter::with_capacity(1 << 16, out))), detect::daemon_detectors(cfg, deps));
    eng.set_maintenance(maintenance::Watcher::new(&cfg.maintenance_path), &cfg.maintenance_soften);
    let mut n = 0;
    for (i, line) in input.split(b'\n').enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let v = gojson::parse(&line).map_err(|e| format!("event line {}: {e}", i + 1))?;
        let ev = event_from_value(&v).map_err(|e| format!("event line {}: {e}", i + 1))?;
        eng.handle(&ev);
        n += 1;
    }
    Ok(n)
}
