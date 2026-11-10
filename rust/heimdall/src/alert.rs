//! Findings become alerts: timestamped, redacted, explained, written one JSON object per line exactly as the Go daemon
//! writes them (Go: internal/alert).

use crate::detect::text::redact_credentials;
use crate::event::{Fields, Finding, Severity};
use crate::explain::{self, Text};
use crate::gojson::{self, FromGo, ObjectWriter, Value};
use crate::gotime::Time;
use std::collections::VecDeque;
use std::io::Write;

/// A finding plus the time Heimdall raised it.
#[derive(Clone, Debug, PartialEq)]
pub struct Alert {
    pub time: Time,
    pub detector_id: String,
    pub severity: Severity,
    pub summary: String,
    pub source: String,
    pub session_id: String,
    pub event_kind: String,
    pub event_text: String,
    pub fields: Fields,
    pub explain: Option<Text>,
}

fn explained(mut a: Alert) -> Alert {
    a.explain = Some(explain::for_alert(&a.detector_id, a.severity.as_str(), &a.fields));
    a
}

impl Alert {
    /// The alert for a finding, every text redacted (a detected secret must not travel into the log, journal or API).
    pub fn from_finding(f: &Finding) -> Alert {
        let fields = f.event.fields.iter().map(|(k, v)| (k.clone(), redact_credentials(v))).collect();
        explained(Alert {
            time: Time::now(),
            detector_id: f.detector_id.clone(),
            severity: f.severity,
            summary: redact_credentials(&f.summary),
            source: f.event.source.clone(),
            session_id: f.event.session_id.clone(),
            event_kind: f.event.kind.clone(),
            event_text: redact_credentials(&f.event.text),
            fields,
            explain: None,
        })
    }

    /// An alert about Heimdall's own integration with another component (detector "integration").
    pub fn integration(code: &str, summary: &str, remedy: &str, fields: &Fields) -> Alert {
        let mut f = Fields::from([("error_code".to_string(), code.to_string()), ("remedy".to_string(), remedy.to_string())]);
        f.extend(fields.iter().map(|(k, v)| (k.clone(), v.clone())));
        explained(Alert {
            time: Time::now(),
            detector_id: "integration".into(),
            severity: Severity::Warning,
            summary: format!("{code}: {summary} (remedy: {remedy})"),
            source: "heimdall".into(),
            session_id: String::new(),
            event_kind: "integration_error".into(),
            event_text: String::new(),
            fields: f,
            explain: None,
        })
    }

    /// One line of the alert log, as Go's json.Encoder writes it (without the newline).
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(512 + self.event_text.len());
        let mut w = ObjectWriter::new(&mut out);
        w.str("time", &self.time.rfc3339_nano());
        w.str("detector_id", &self.detector_id);
        w.str("severity", self.severity.as_str());
        w.str("summary", &self.summary);
        w.str("source", &self.source);
        if !self.session_id.is_empty() {
            w.str("session_id", &self.session_id);
        }
        w.str("event_kind", &self.event_kind);
        w.str("event_text", &self.event_text);
        if !self.fields.is_empty() {
            w.map("fields", &self.fields);
        }
        if let Some(t) = &self.explain {
            let o = w.key("explain");
            let mut e = ObjectWriter::new(o);
            e.str("what", &t.what);
            e.str("serious", &t.serious);
            e.str("done", &t.done);
            e.str("do", &t.r#do);
            e.end();
        }
        w.end();
        out
    }

    /// Reads one alert line (as the Go daemon or this one wrote it).
    pub fn from_json(line: &[u8]) -> Result<Alert, gojson::Error> {
        let mut r = AlertJson::default();
        r.read_into(&gojson::parse(line)?, "")?;
        let severity = Severity::parse(&r.severity).ok_or_else(|| gojson::Error(format!("unknown severity {:?}", r.severity)))?;
        let explain = match &r.explain {
            Value::Null => None,
            v => {
                let mut t = TextJson::default();
                t.read_into(v, "explain")?;
                Some(Text { what: t.what, serious: t.serious, done: t.done, r#do: t.r#do })
            }
        };
        Ok(Alert {
            time: r.time,
            detector_id: r.detector_id,
            severity,
            summary: r.summary,
            source: r.source,
            session_id: r.session_id,
            event_kind: r.event_kind,
            event_text: r.event_text,
            fields: r.fields,
            explain,
        })
    }
}

#[derive(Default)]
struct AlertJson {
    time: Time,
    detector_id: String,
    severity: String,
    summary: String,
    source: String,
    session_id: String,
    event_kind: String,
    event_text: String,
    fields: Fields,
    explain: Value,
}
crate::go_struct!(AlertJson {
    time: "time",
    detector_id: "detector_id",
    severity: "severity",
    summary: "summary",
    source: "source",
    session_id: "session_id",
    event_kind: "event_kind",
    event_text: "event_text",
    fields: "fields",
    explain: "explain",
});

#[derive(Default)]
struct TextJson {
    what: String,
    serious: String,
    done: String,
    r#do: String,
}
crate::go_struct!(TextJson { what: "what", serious: "serious", done: "done", r#do: "do" });

/// Receives every alert the engine raises.
pub trait Sink: Send {
    fn write(&mut self, a: &Alert) -> std::io::Result<()>;
}

/// One JSON object per line to a writer (stdout, or the alert log opened for appending).
pub struct WriterSink<W: Write + Send> {
    w: W,
}

impl<W: Write + Send> WriterSink<W> {
    pub fn new(w: W) -> Self {
        WriterSink { w }
    }
}

impl<W: Write + Send> Sink for WriterSink<W> {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        let mut line = a.to_json();
        line.push('\n');
        // one write per line, so a reader following the file never sees half an alert
        self.w.write_all(line.as_bytes())?;
        self.w.flush()
    }
}

/// The last N alerts, newest first on reading (for the status API).
pub struct Ring {
    buf: VecDeque<Alert>,
    size: usize,
}

impl Ring {
    pub fn new(size: i64) -> Ring {
        let size = size.max(1) as usize;
        Ring { buf: VecDeque::with_capacity(size.min(64)), size }
    }

    /// Up to n most recent alerts, newest first (n <= 0: all).
    pub fn recent(&self, n: i64) -> Vec<Alert> {
        let n = if n <= 0 || n as usize > self.buf.len() { self.buf.len() } else { n as usize };
        self.buf.iter().rev().take(n).cloned().collect()
    }
}

impl Sink for Ring {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        if self.buf.len() == self.size {
            self.buf.pop_front();
        }
        self.buf.push_back(a.clone());
        Ok(())
    }
}

/// Fans one alert out to several sinks, going on past a failed one.
pub struct MultiSink {
    pub sinks: Vec<Box<dyn Sink>>,
}

impl Sink for MultiSink {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        let mut first = None;
        for s in &mut self.sinks {
            if let Err(e) = s.write(a) {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }
}

impl<S: Sink + ?Sized> Sink for std::sync::Arc<std::sync::Mutex<S>> {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        match self.lock() {
            Ok(mut s) => s.write(a),
            Err(p) => p.into_inner().write(a),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    #[test]
    fn writes_go_field_order_and_omits_empty() {
        let e = Event { source: "agent-session".into(), kind: "message".into(), text: "hi <b>".into(), ..Default::default() };
        let mut a = Alert::from_finding(&Finding::new("invisible-unicode", Severity::Warning, "s".into(), &e));
        a.time = Time::parse_rfc3339("2026-11-10T01:02:03.5Z").unwrap();
        let j = a.to_json();
        assert!(j.starts_with(r#"{"time":"2026-11-10T01:02:03.5Z","detector_id":"invisible-unicode","severity":"warning","summary":"s","source":"agent-session","event_kind":"message","event_text":"hi "#), "{j}");
        assert!(j.contains(concat!("hi ", "\\u003cb", "\\u003e", r#"","explain":{"what":"#)), "{j}");
        let back = Alert::from_json(j.as_bytes()).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn redacts_every_text() {
        let e = Event {
            text: "aws AKIAABCDEFGHIJKLMNOP".into(),
            fields: Fields::from([("k".to_string(), "AKIAABCDEFGHIJKLMNOP".to_string())]),
            ..Default::default()
        };
        let a = Alert::from_finding(&Finding::new("credential-shape", Severity::Critical, "AKIAABCDEFGHIJKLMNOP".into(), &e));
        assert_eq!(a.event_text, "aws AKIA…[redacted]");
        assert_eq!(a.summary, "AKIA…[redacted]");
        assert_eq!(a.fields["k"], "AKIA…[redacted]");
    }

    #[test]
    fn ring_keeps_the_newest() {
        let mut r = Ring::new(2);
        for d in ["a", "b", "c"] {
            let mut a = Alert::integration(d, "x", "y", &Fields::new());
            a.detector_id = d.into();
            r.write(&a).unwrap();
        }
        let ids: Vec<_> = r.recent(0).into_iter().map(|a| a.detector_id).collect();
        assert_eq!(ids, ["c", "b"]);
    }
}
