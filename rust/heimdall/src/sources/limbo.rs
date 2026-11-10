//! Limbo's events.jsonl (Go: internal/sources/limbosource): complete lines only, from a kept offset (the Go daemon's offset
//! file, a decimal number), back to the top when the file shrinks.

use super::{Msg, Source};
use crate::event::{Event, Fields};
use crate::gojson::{self, FromGo};
use crate::gotime::Time;
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

const MAX_LINE: usize = 1 << 20;

#[derive(Default)]
struct Record {
    time: Time,
    kind: String,
    guest: String,
    detail: Fields,
}
crate::go_struct!(Record { time: "time", kind: "kind", guest: "guest", detail: "detail" });

/// One line of Limbo's log as an event; None for a line that does not read or lacks a kind or guest.
pub fn parse_line(line: &[u8]) -> Option<Event> {
    if line.len() > MAX_LINE {
        return None;
    }
    let mut r = Record::default();
    r.read_into(&gojson::parse(line).ok()?, "").ok()?;
    if r.kind.is_empty() || r.guest.is_empty() {
        return None;
    }
    let mut text = format!("limbo {} guest={}", r.kind, r.guest);
    for (k, v) in &r.detail {
        text.push_str(&format!(" {k}={v}"));
    }
    let mut fields = r.detail;
    fields.insert("guest".into(), r.guest); // set last so a detail key can never spoof it
    Some(Event { source: "limbo".into(), session_id: String::new(), time: r.time, kind: r.kind, text, fields })
}

pub struct Watcher {
    path: String,
    state_path: String,
    offset: u64,
    started: bool,
    from_start: bool,
    pub skipped: usize,
    /// The last failure to write the offset file, reported after the events of the same look.
    pub save_error: Option<std::io::Error>,
}

impl Watcher {
    pub fn new(path: &str, state_path: &str, from_start: bool) -> Watcher {
        let mut w = Watcher {
            path: path.into(),
            state_path: state_path.into(),
            offset: 0,
            started: false,
            from_start,
            skipped: 0,
            save_error: None,
        };
        if !state_path.is_empty() {
            if let Ok(s) = std::fs::read_to_string(state_path) {
                if let Some(n) = crate::gotext::atoi(crate::gotext::trim_space(&s)).filter(|n| *n >= 0) {
                    w.offset = n as u64;
                    w.started = true;
                }
            }
        }
        w
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    fn save(&self) -> std::io::Result<()> {
        if self.state_path.is_empty() {
            return Ok(());
        }
        if let Some(dir) = std::path::Path::new(&self.state_path).parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::state::write_atomic(&self.state_path, self.offset.to_string().as_bytes(), 0o600)
    }

    pub fn poll(&mut self) -> std::io::Result<Vec<Event>> {
        let mut f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let size = f.metadata()?.len();
        if !self.started {
            self.started = true;
            if !self.from_start {
                self.offset = size;
                self.save()?;
                return Ok(Vec::new());
            }
        }
        if size < self.offset {
            self.offset = 0;
        }
        if size == self.offset {
            return Ok(Vec::new());
        }
        f.seek(SeekFrom::Start(self.offset))?;
        let mut buf = Vec::new();
        f.take(size - self.offset).read_to_end(&mut buf)?;
        let Some(end) = buf.iter().rposition(|&c| c == b'\n') else { return Ok(Vec::new()) };
        let mut events = Vec::new();
        for line in buf[..end].split(|&c| c == b'\n') {
            if crate::gotext::trim_space(&crate::gotext::lossy(line)).is_empty() {
                continue;
            }
            match parse_line(line) {
                Some(e) => events.push(e),
                None => self.skipped += 1,
            }
        }
        self.offset += end as u64 + 1;
        // as in Go, the events are delivered even when the offset could not be written
        if let Err(e) = self.save() {
            self.save_error = Some(e);
        }
        Ok(events)
    }
}

/// Limbo's log on the daemon's loop, looked at every interval (Limbo bounds how often it writes).
pub struct LimboSource {
    pub w: Watcher,
    interval: Duration,
    next: Instant,
}

impl LimboSource {
    pub fn new(w: Watcher, interval: Duration) -> LimboSource {
        LimboSource { w, interval, next: Instant::now() }
    }
}

impl Source for LimboSource {
    fn name(&self) -> &'static str {
        "limbo"
    }
    fn due(&self) -> Option<Instant> {
        Some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        self.next = now + self.interval;
        match self.w.poll() {
            Ok(events) => {
                out.extend(events.into_iter().map(Msg::LimboEvent));
                if let Some(e) = self.w.save_error.take() {
                    out.push(Msg::Log(format!("limbo event log poll error: {}", super::go_errno(&e))));
                }
            }
            Err(e) => out.push(Msg::Log(format!("limbo event log poll error: {}", super::go_errno(&e)))),
        }
    }
}
