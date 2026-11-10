//! The Limbo responder (Go: internal/response): when an alert says a Limbo guest is outside its safety rules, ask Limbo to
//! hold it at `restrict`, never anything looser. The rules it must follow are in `quarantine.rs` (proved there); this is the
//! queue around them and the client of Limbo's control socket.
//!
//! - Every alert is passed on first; the request is queued and the loop never waits for Limbo.
//! - At most 8 calls run at once, each on a thread of its own (started only when there is a request); more wait, most
//!   severe first, then oldest. Triggers for one guest merge into one request; none is dropped (1024 guests at most).
//! - Just before a call, the re-check: a later Limbo event that cleared the cause (policy applied again, guest stopped), a
//!   guest Limbo no longer has, or a hold already as strict since the trigger means nothing is sent (`quarantine_skipped`).
//!   Anything it cannot tell means send.
//! - Lateness, failures, skips and what was not sent at shutdown become `integration` alerts with stable codes.
//! - Never in shadow mode: the daemon builds a responder only when it is in charge (daemon.rs).
//!
//! - On a new hold: Heimdall's own explanation, and (with `sarina_url`) Sarina's opinion (`advisor.rs`), at most 2
//!   consultations at once (a third is `sarina_busy`, never queued behind a slow model); while requests back up, one
//!   untrusted note on the backlog. Both are advisories a human reads; neither changes a hold.

use crate::advisor::{self, Advisor};
use crate::alert::{Alert, Sink};
use crate::event::{Event, Fields, Severity};
use crate::gostruct::{self, Field, Ty, Val};
use crate::gotext;
use crate::gotime::Time;
use crate::quarantine::{self, Decision, Level, Record};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const CODE_FAILED: &str = "limbo_quarantine_failed";
pub const CODE_TIMEOUT: &str = "limbo_quarantine_timeout";
pub const CODE_UNREACHABLE: &str = "limbo_unreachable";
pub const CODE_DELAYED: &str = "limbo_quarantine_delayed";
pub const CODE_BACKLOG: &str = "limbo_quarantine_backlog";
pub const CODE_OVERFLOW: &str = "limbo_quarantine_overflow";
pub const CODE_SKIPPED: &str = "quarantine_skipped";
pub const CODE_NOT_COMPLETED: &str = "quarantine_not_completed_at_shutdown";
pub const CODE_BACKLOG_ADVISORY: &str = "quarantine_backlog_advisory";

const MAX_QUARANTINES: usize = 8;
const STATUS_TIMEOUT: Duration = Duration::from_secs(3);

/// Limbo's name rule (`^[a-z][a-z0-9-]{0,11}$`): a name from a log file is checked again before it goes on a request.
pub fn guest_ok(g: &str) -> bool {
    let b = g.as_bytes();
    !b.is_empty() && b.len() <= 12 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn rank(s: Severity) -> i32 {
    match s.as_str() {
        "critical" => 3,
        "warning" => 2,
        "info" => 1,
        _ => 0,
    }
}

/// Whether an alert asks for a hold (Go: Responder.triggers).
pub fn triggers(a: &Alert) -> bool {
    let f = |k: &str| a.fields.get(k).map(String::as_str).unwrap_or("");
    if !guest_ok(f("guest")) {
        return false;
    }
    match a.detector_id.as_str() {
        "limbo-guest" => rank(a.severity) == 3 && matches!(a.event_kind.as_str(), "guest.start" | "policy.remove"),
        "limbo-network" => {
            a.source == "limbo"
                && a.event_kind == "net.anomaly"
                && matches!(f("reason"), "host_probe" | "lan_probe" | "scan")
                && rank(a.severity) >= 2
        }
        "limbo-exchange" => a.source == "limbo" && a.event_kind == "exchange.held" && rank(a.severity) >= 2,
        _ => false,
    }
}

// ---- the control socket ----

/// Why a call failed: Go's error text, and its class (for the stable code).
#[derive(Clone, Debug, PartialEq)]
pub struct LimboError {
    pub kind: ErrKind,
    pub msg: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ErrKind {
    Timeout,
    Dial,
    Other,
}

impl std::fmt::Display for LimboError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

/// Limbo's reply to a hold request (Go: response.Result).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct QResult {
    pub id: String,
    pub level: String,
    pub created: bool,
    pub applied: bool,
    pub error: String,
}

static RECORD: Ty = Ty::Struct("response.Record", &[Field("id", &Ty::Str, false), Field("guest", &Ty::Str, false), Field("level", &Ty::Str, false)]);
static RESULT: Ty = Ty::Struct(
    "response.Result",
    &[Field("record", &RECORD, false), Field("created", &Ty::Bool, false), Field("applied", &Ty::Bool, false), Field("error", &Ty::Str, false)],
);
static LISTED: Ty = Ty::Slice(&Ty::Struct(
    "",
    &[Field("guest", &Ty::Str, false), Field("level", &Ty::Str, false), Field("status", &Ty::Str, false), Field("opened", &Ty::Time, false)],
));

/// What the responder needs from Limbo (a trait so tests can stand in for it).
pub trait Limbo: Send + Sync {
    fn quarantine(&self, guest: &str, reason: &str, source: &str, evidence: &BTreeMap<String, String>, by: Instant) -> Result<QResult, LimboError>;
    fn advise(&self, id: &str, source: &str, text: &str, by: Instant) -> Result<(), LimboError>;
    /// (exists, known): known false when Limbo does not say (an older one).
    fn guest_exists(&self, guest: &str, by: Instant) -> Result<(bool, bool), LimboError>;
    /// The strongest hold Limbo has for the guest (None: none).
    fn quarantine_status(&self, guest: &str, by: Instant) -> Result<Option<(Level, Time)>, LimboError>;
}

/// The client of Limbo's control.sock: plain HTTP/1.1 over the Unix socket, one request per connection.
pub struct Client {
    pub socket: String,
}

pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) status_text: String,
    pub(crate) body: Vec<u8>,
}

impl Client {
    fn call(&self, method: &str, path: &str, body: Option<&str>, by: Instant, limit: usize) -> Result<Reply, LimboError> {
        // Go's url.Error: `Post "http://limbo/v1/quarantine": ...`
        let verb = format!("{}{}", &method[..1], method[1..].to_ascii_lowercase());
        let wrap = |kind: ErrKind, what: String| LimboError { kind, msg: format!("limbo control socket: {verb} \"http://limbo{path}\": {what}") };
        let deadline = || wrap(ErrKind::Timeout, "context deadline exceeded".into());
        let left = by.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(deadline());
        }
        let mut s = UnixStream::connect(&self.socket)
            .map_err(|e| wrap(ErrKind::Dial, format!("dial unix {}: connect: {}", self.socket, crate::sources::go_errno(&e))))?;
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: limbo\r\nConnection: close\r\n");
        if let Some(b) = body {
            req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}", b.len()));
        } else {
            req.push_str("Content-Type: application/json\r\n\r\n");
        }
        let io = |e: std::io::Error| {
            if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) {
                deadline()
            } else {
                wrap(ErrKind::Other, crate::sources::go_errno(&e))
            }
        };
        let left = by.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        s.set_write_timeout(Some(left)).map_err(io)?;
        s.write_all(req.as_bytes()).map_err(io)?;
        let mut raw = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let left = by.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(deadline());
            }
            s.set_read_timeout(Some(left)).map_err(io)?;
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
                Err(e) => return Err(io(e)),
            }
            if raw.len() > limit + 64 * 1024 || complete(&raw) {
                break;
            }
        }
        parse_reply(&raw, limit).ok_or_else(|| wrap(ErrKind::Other, "malformed HTTP response".into()))
    }

    /// Go's Client.do: a status of 300 or more is `limbo: <Limbo's error>` or `limbo: <status>`.
    fn checked(&self, method: &str, path: &str, body: Option<&str>, by: Instant) -> Result<Vec<u8>, LimboError> {
        let r = self.call(method, path, body, by, 1 << 20)?;
        if r.status >= 300 {
            let e = gojson::parse(&r.body).ok().and_then(|v| match v {
                gojson::Value::Object(m) => m.iter().rev().find(|(k, _)| gojson::key_matches(k, "error")).and_then(|(_, v)| match v {
                    gojson::Value::String(s) if !s.is_empty() => Some(s.clone()),
                    _ => None,
                }),
                _ => None,
            });
            return Err(LimboError { kind: ErrKind::Other, msg: format!("limbo: {}", e.unwrap_or(r.status_text)) });
        }
        Ok(r.body)
    }
}

use crate::gojson;

/// The whole response is in: the head and a body of its Content-Length, or a chunked body's last chunk.
pub(crate) fn complete(raw: &[u8]) -> bool {
    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
    let body = &raw[end + 4..];
    for l in head.split("\r\n") {
        if let Some(v) = l.strip_prefix("content-length:") {
            return v.trim().parse::<usize>().is_ok_and(|n| body.len() >= n);
        }
        if l.starts_with("transfer-encoding:") && l.contains("chunked") {
            return body.ends_with(b"0\r\n\r\n");
        }
    }
    false
}

pub(crate) fn parse_reply(raw: &[u8], limit: usize) -> Option<Reply> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let first = lines.next()?;
    let status_text = first.split_once(' ')?.1.to_string();
    let status: u16 = status_text.get(..3)?.parse().ok()?;
    let mut chunked = false;
    let mut len: Option<usize> = None;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else if k == "content-length" {
                len = v.parse().ok();
            }
        }
    }
    let mut rest = &raw[end + 4..];
    let mut body = Vec::new();
    if chunked {
        loop {
            let i = rest.windows(2).position(|w| w == b"\r\n")?;
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..i]).ok()?.split(';').next()?.trim(), 16).ok()?;
            rest = &rest[i + 2..];
            if size == 0 {
                break;
            }
            body.extend_from_slice(rest.get(..size)?);
            rest = rest.get(size + 2..)?;
        }
    } else {
        body.extend_from_slice(match len {
            Some(n) => rest.get(..n.min(rest.len()))?,
            None => rest,
        });
    }
    body.truncate(limit);
    Some(Reply { status, status_text, body })
}

impl Limbo for Client {
    fn quarantine(&self, guest: &str, reason: &str, source: &str, evidence: &BTreeMap<String, String>, by: Instant) -> Result<QResult, LimboError> {
        // Go: json.Marshal of a map, keys sorted
        let mut b = String::new();
        let mut o = gojson::ObjectWriter::new(&mut b);
        o.map("evidence", evidence);
        o.str("guest", guest);
        o.str("level", Level::Restrict.as_str());
        o.str("reason", reason);
        o.str("source", source);
        o.end();
        let raw = self.checked("POST", "/v1/quarantine", Some(&b), by)?;
        match gostruct::unmarshal(&RESULT, &raw) {
            (_, Some(e)) => Err(LimboError { kind: ErrKind::Other, msg: e.0 }),
            (v, None) => {
                let rec = gostruct::field(&RESULT, &v, "record");
                let s = |k: &str| rec.map(|r| gostruct::str_field(&RECORD, r, k).to_string()).unwrap_or_default();
                let flag = |k: &str| matches!(gostruct::field(&RESULT, &v, k), Some(Val::Bool(true)));
                Ok(QResult {
                    id: s("id"),
                    level: s("level"),
                    created: flag("created"),
                    applied: flag("applied"),
                    error: gostruct::str_field(&RESULT, &v, "error").to_string(),
                })
            }
        }
    }

    fn advise(&self, id: &str, source: &str, text: &str, by: Instant) -> Result<(), LimboError> {
        let mut b = String::new();
        let mut o = gojson::ObjectWriter::new(&mut b);
        o.str("source", source);
        o.str("text", text);
        o.end();
        self.checked("POST", &format!("/v1/quarantine/{id}/advisory"), Some(&b), by).map(|_| ())
    }

    fn guest_exists(&self, guest: &str, by: Instant) -> Result<(bool, bool), LimboError> {
        let r = self.call("GET", &format!("/v1/guests/{guest}"), None, by, 1 << 16)?;
        if r.status != 200 && r.status != 404 {
            return Ok((false, false));
        }
        // Go: a struct with `Exists *bool`; anything but a bool there (or a document that does not read) is no answer
        let Ok(v) = gojson::parse(&r.body) else { return Ok((false, false)) };
        let gojson::Value::Object(m) = v else { return Ok((false, false)) };
        let mut exists: Option<bool> = None;
        for (k, x) in &m {
            if gojson::key_matches(k, "exists") {
                match x {
                    gojson::Value::Bool(b) => exists = Some(*b),
                    gojson::Value::Null => exists = None,
                    _ => return Ok((false, false)),
                }
            }
        }
        Ok(exists.map_or((false, false), |e| (e, true)))
    }

    fn quarantine_status(&self, guest: &str, by: Instant) -> Result<Option<(Level, Time)>, LimboError> {
        let raw = self.checked("GET", "/v1/quarantine", None, by)?;
        let v = match gostruct::unmarshal(&LISTED, &raw) {
            (_, Some(e)) => return Err(LimboError { kind: ErrKind::Other, msg: e.0 }),
            (v, None) => v,
        };
        let Val::Slice(Some(items)) = v else { return Ok(None) };
        let t = match &LISTED {
            Ty::Slice(t) => *t,
            _ => unreachable!(),
        };
        let records: Vec<Record> = items
            .iter()
            .map(|r| Record {
                guest: gostruct::str_field(t, r, "guest").into(),
                status: gostruct::str_field(t, r, "status").into(),
                level: gostruct::str_field(t, r, "level").into(),
                opened: match gostruct::field(t, r, "opened") {
                    Some(Val::Time(x)) => *x,
                    _ => Time::default(),
                },
            })
            .collect();
        Ok(quarantine::strongest(&records, guest))
    }
}

// ---- the queue ----

/// The responder's knobs (Go: Responder's fields; zero: the defaults).
#[derive(Clone, Debug)]
pub struct Settings {
    pub timeout: Duration,
    pub max_pending: usize,
    pub delay: Duration,
    pub backlog_threshold: usize,
    pub backlog_interval: Duration,
    pub tick: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            timeout: Duration::from_secs(10),
            max_pending: 1024,
            delay: Duration::from_secs(15),
            backlog_threshold: 4,
            backlog_interval: Duration::from_secs(60),
            tick: Duration::from_secs(1),
        }
    }
}

#[derive(Clone)]
struct Req {
    guest: String,
    primary: Alert,
    enqueued: Instant,
    latest: Time,
    seq: u64,
    kinds: Vec<String>,
    count: usize,
    delayed: bool,
}

impl Req {
    /// A later Limbo event can make the request unnecessary, except after a network anomaly or a held malware file.
    fn cleared_by_later(&self) -> bool {
        !self.kinds.iter().any(|k| k == "net.anomaly" || k == "exchange.held")
    }
}

/// More severe first, then oldest, then by name.
fn before(a: &Req, b: &Req) -> bool {
    let (ra, rb) = (rank(a.primary.severity), rank(b.primary.severity));
    if ra != rb {
        return ra > rb;
    }
    if a.enqueued != b.enqueued {
        return a.enqueued < b.enqueued;
    }
    a.guest < b.guest
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Req>,
    inflight: HashSet<String>,
    seq: u64,
    marks: HashMap<String, (u64, &'static str)>,
    last_backlog: Option<Instant>,
    closing: bool,
    cancelled: bool,
    /// running threads (calls, explanations): Go's WaitGroup
    busy: usize,
    monitor: bool,
    /// Sarina consultations running (Go: slots, at most 2)
    advising: usize,
}

/// How many Sarina consultations may run at once (Go: maxAdvisories).
const MAX_ADVISORIES: usize = 2;

struct Shared {
    st: Mutex<State>,
    cv: Condvar,
    limbo: Box<dyn Limbo>,
    advisor: Option<Box<dyn Advisor>>,
    out: Box<dyn Fn(Alert) + Send + Sync>,
    log: Box<dyn Fn(&str) + Send + Sync>,
    cfg: Settings,
}

/// The responder's handle for the loop: what Limbo events it observes, and the shutdown.
#[derive(Clone)]
pub struct Handle(Arc<Shared>);

/// A Sink that passes every alert on and holds the guests the triggering ones name.
pub struct Responder {
    next: Box<dyn Sink>,
    sh: Arc<Shared>,
}

fn round_ms(d: Duration) -> String {
    // Go: Duration.Round(time.Millisecond).String()
    let ms = (d.as_nanos() + 500_000) / 1_000_000;
    gotext::duration((ms * 1_000_000) as i64)
}

impl Responder {
    /// `out` receives the alerts the responder raises itself (to the outputs, never back through the responder).
    pub fn new(
        next: Box<dyn Sink>,
        limbo: Box<dyn Limbo>,
        advisor: Option<Box<dyn Advisor>>,
        cfg: Settings,
        out: Box<dyn Fn(Alert) + Send + Sync>,
        log: Box<dyn Fn(&str) + Send + Sync>,
    ) -> (Responder, Handle) {
        let sh = Arc::new(Shared { st: Mutex::new(State::default()), cv: Condvar::new(), limbo, advisor, out, log, cfg });
        (Responder { next, sh: sh.clone() }, Handle(sh))
    }
}

impl Sink for Responder {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        let r = self.next.write(a);
        if triggers(a) {
            enqueue(&self.sh, a);
        }
        r
    }
}

fn lock(sh: &Shared) -> std::sync::MutexGuard<'_, State> {
    sh.st.lock().unwrap_or_else(|p| p.into_inner())
}

fn failure(sh: &Shared, guest: &str, code: &str, msg: &str, remedy: &str, extra: &[(&str, String)]) {
    (sh.log)(&format!("{code}: {msg} (remedy: {remedy})"));
    let mut f = Fields::from([("guest".to_string(), guest.to_string())]);
    for (k, v) in extra {
        f.insert(k.to_string(), v.clone());
    }
    (sh.out)(Alert::integration(code, msg, remedy, &f));
}

fn start_monitor(sh: &Arc<Shared>, st: &mut State) {
    if st.monitor {
        return;
    }
    st.monitor = true;
    let s2 = sh.clone();
    let _ = std::thread::Builder::new().name("limbo-queue".into()).spawn(move || monitor(&s2));
}

fn enqueue(sh: &Arc<Shared>, a: &Alert) {
    let guest = a.fields.get("guest").cloned().unwrap_or_default();
    let mut st = lock(sh);
    start_monitor(sh, &mut st);
    if st.closing {
        drop(st);
        (sh.log)(&format!("guest {}: not quarantined, Heimdall is shutting down", gotext::quote(&guest)));
        failure(
            sh,
            &guest,
            CODE_NOT_COMPLETED,
            &format!("quarantine of guest {} was not requested: Heimdall is shutting down", gotext::quote(&guest)),
            "restrict the guest by hand with the Limbo CLI",
            &[("guests", guest.clone())],
        );
        return;
    }
    st.seq += 1;
    if st.inflight.contains(&guest) {
        drop(st);
        (sh.log)(&format!("guest {}: quarantine already in flight, coalescing this trigger ({})", gotext::quote(&guest), a.event_kind));
        return;
    }
    let seq = st.seq;
    if let Some(q) = st.pending.get_mut(&guest) {
        q.count += 1;
        q.seq = seq;
        q.latest = a.time;
        if !q.kinds.contains(&a.event_kind) {
            q.kinds.push(a.event_kind.clone());
        }
        let up = rank(a.severity) > rank(q.primary.severity);
        if up {
            q.primary = a.clone();
        }
        drop(st);
        (sh.log)(&format!(
            "guest {}: quarantine already queued, merged this trigger ({}, priority upgraded: {up})",
            gotext::quote(&guest),
            a.event_kind
        ));
        return;
    }
    if st.pending.len() >= sh.cfg.max_pending {
        drop(st);
        failure(
            sh,
            &guest,
            CODE_OVERFLOW,
            &format!("quarantine of guest {} NOT queued: {} other guests are already waiting", gotext::quote(&guest), sh.cfg.max_pending),
            "something is generating triggers for a very large number of guests; check Limbo (systemctl status limbo) and restrict the guest by hand",
            &[],
        );
        return;
    }
    st.pending.insert(
        guest.clone(),
        Req { guest, primary: a.clone(), enqueued: Instant::now(), latest: a.time, seq, kinds: vec![a.event_kind.clone()], count: 1, delayed: false },
    );
    dispatch(sh, &mut st);
    sh.cv.notify_all();
}

/// Starts queued requests while call slots are free (the caller holds the lock).
fn dispatch(sh: &Arc<Shared>, st: &mut State) {
    while st.inflight.len() < MAX_QUARANTINES && !st.pending.is_empty() && !st.cancelled {
        let best = st.pending.values().fold(None::<&Req>, |b, q| if b.is_none_or(|b| before(q, b)) { Some(q) } else { b }).map(|q| q.guest.clone());
        let Some(g) = best else { break };
        let q = st.pending.remove(&g).expect("present");
        st.inflight.insert(g);
        st.busy += 1;
        let s2 = sh.clone();
        let spawned = std::thread::Builder::new().name("limbo-call".into()).spawn(move || {
            let guest = q.guest.clone();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call(&s2, q)));
            if let Err(p) = r {
                let what = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
                failure(&s2, &guest, CODE_FAILED, &format!("quarantine call panicked: {what}"), "report this as a Heimdall bug", &[]);
            }
            let mut st = lock(&s2);
            st.inflight.remove(&guest);
            dispatch(&s2, &mut st);
            st.busy -= 1;
            s2.cv.notify_all();
        });
        if spawned.is_err() {
            // no thread: the request waits for the next free slot (never dropped)
            st.busy -= 1;
            break;
        }
    }
}

impl Handle {
    /// A Limbo event the re-check should know about (after the engine handled it): policy applied again or guest stopped
    /// may clear a queued request; a start undoes that. It never acts.
    pub fn observe(&self, e: &Event) {
        if e.source != "limbo" {
            return;
        }
        let guest = e.fields.get("guest").cloned().unwrap_or_default();
        if !guest_ok(&guest) {
            return;
        }
        let sh = &self.0;
        let mut st = lock(sh);
        start_monitor(sh, &mut st);
        st.seq += 1;
        let seq = st.seq;
        match e.kind.as_str() {
            "policy.apply" => {
                st.marks.insert(guest, (seq, "the firewall policy was applied again after the trigger"));
            }
            "guest.stop" => {
                st.marks.insert(guest, (seq, "the guest stopped after the trigger, so nothing is running to quarantine"));
            }
            "guest.start" => {
                st.marks.remove(&guest);
            }
            _ => {}
        }
    }

    /// Waits until nothing is queued or running (tests; Go: Wait).
    pub fn wait(&self) {
        let mut st = lock(&self.0);
        while st.busy > 0 || (!st.pending.is_empty() && !st.cancelled) {
            st = self.0.cv.wait(st).unwrap_or_else(|p| p.into_inner());
        }
    }

    /// Stops taking triggers, waits up to `grace` for the queue to drain, then sends nothing more; what is still queued is
    /// one `quarantine_not_completed_at_shutdown` alert. Calls in flight past that are abandoned (their thread ends with the
    /// process). True when everything finished.
    pub fn shutdown(&self, grace: Duration) -> bool {
        let sh = &self.0;
        let mut st = lock(sh);
        st.closing = true;
        let until = Instant::now() + grace;
        while st.busy > 0 || !st.pending.is_empty() {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            st = sh.cv.wait_timeout(st, left).unwrap_or_else(|p| p.into_inner()).0;
        }
        let mut finished = st.busy == 0 && st.pending.is_empty();
        st.cancelled = true;
        let mut left: Vec<Req> = st.pending.drain().map(|(_, q)| q).collect();
        sh.cv.notify_all();
        drop(st);
        if !left.is_empty() {
            left.sort_by(|a, b| if before(a, b) { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater });
            let list = left.iter().map(|q| q.guest.as_str()).collect::<Vec<_>>().join(",");
            failure(
                sh,
                &list,
                CODE_NOT_COMPLETED,
                &format!("{} queued quarantine request(s) were not sent before Heimdall shut down: {list}", left.len()),
                "restrict these guests by hand with the Limbo CLI; Heimdall will not retry them after a restart",
                &[("guests", list.clone()), ("count", left.len().to_string())],
            );
        }
        if !finished {
            let mut st = lock(sh);
            let until = Instant::now() + Duration::from_secs(1);
            while st.busy > 0 && !until.saturating_duration_since(Instant::now()).is_zero() {
                st = sh.cv.wait_timeout(st, until.saturating_duration_since(Instant::now())).unwrap_or_else(|p| p.into_inner()).0;
            }
            finished = st.busy == 0;
        }
        finished && left.is_empty()
    }
}

/// The re-check just before a call (Go: recheck): Some(reason) to skip.
fn recheck(sh: &Shared, q: &Req) -> Option<String> {
    {
        let st = lock(sh);
        if let Some((seq, why)) = st.marks.get(&q.guest) {
            if *seq > q.seq && q.cleared_by_later() {
                return Some(why.to_string());
            }
        }
    }
    let by = Instant::now() + STATUS_TIMEOUT;
    if let Ok((false, true)) = sh.limbo.guest_exists(&q.guest, by) {
        return Some("the guest no longer exists in Limbo (torn down), so there is nothing to hold".into());
    }
    let current = match sh.limbo.quarantine_status(&q.guest, by) {
        Err(e) => {
            (sh.log)(&format!("guest {}: quarantine status unknown ({e}), proceeding", gotext::quote(&q.guest)));
            return None;
        }
        Ok(c) => c,
    };
    match quarantine::decide(current, q.latest) {
        Decision::Skip(why) => Some(why.to_string()),
        Decision::Send(_) => None,
    }
}

fn call(sh: &Arc<Shared>, q: Req) {
    let guest = q.guest.clone();
    let wait = round_ms(q.enqueued.elapsed());
    if let Some(reason) = recheck(sh, &q) {
        (sh.log)(&format!("guest {}: quarantine skipped after {wait} in queue: {reason}", gotext::quote(&guest)));
        failure(
            sh,
            &guest,
            CODE_SKIPPED,
            &format!("quarantine of guest {} not sent: {reason}", gotext::quote(&guest)),
            "none needed if the guest is as restricted as intended; check it with the Limbo CLI",
            &[("queue_wait", wait.clone()), ("reason", reason.clone())],
        );
        return;
    }
    let a = &q.primary;
    let reason = if q.count > 1 { format!("{} ({} triggers merged: {})", a.summary, q.count, q.kinds.join(", ")) } else { a.summary.clone() };
    let evidence: BTreeMap<String, String> = [
        ("detector", a.detector_id.clone()),
        ("event_kind", a.event_kind.clone()),
        ("alert_time", a.time.truncate(1_000_000_000).rfc3339_nano()),
        ("queue_wait", wait.clone()),
        ("triggers", q.kinds.join(",")),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let res = sh.limbo.quarantine(&guest, &reason, &format!("heimdall:{}", a.detector_id), &evidence, Instant::now() + sh.cfg.timeout);
    // Go cancels calls in flight at shutdown; a blocking call here runs to its end, and what it returns after the cancel is
    // treated as Go's cancelled call: abandoned, nothing more sent
    if lock(sh).cancelled {
        (sh.log)(&format!("guest {}: quarantine abandoned at shutdown", gotext::quote(&guest)));
        return;
    }
    let res = match res {
        Ok(r) => r,
        Err(e) => {
            let (code, remedy) = match e.kind {
                ErrKind::Timeout => (CODE_TIMEOUT, "Limbo's socket did not answer in time; check that limbod is not hung (systemctl status limbo) and restrict the guest by hand if it is still running"),
                ErrKind::Dial => (CODE_UNREACHABLE, "start Limbo (systemctl start limbo) and check limbo_control_socket in Heimdall's config; restrict the guest by hand meanwhile"),
                ErrKind::Other => (CODE_FAILED, "read the message for Limbo's reason (journalctl -u limbo); restrict the guest by hand if it is still running"),
            };
            failure(sh, &guest, code, &format!("could not quarantine guest {}: {e} (queue wait {wait})", gotext::quote(&guest)), remedy, &[("queue_wait", wait)]);
            return;
        }
    };
    if !res.applied {
        (sh.log)(&format!("guest {}: quarantine {} recorded but NOT enforced: {} (queue wait {wait})", gotext::quote(&guest), res.id, res.error));
    } else {
        (sh.log)(&format!("guest {} quarantined ({}, level {}, queue wait {wait})", gotext::quote(&guest), res.id, res.level));
    }
    // Heimdall's own explanation on every new hold (fixed text, never derived from the guest's output)
    if res.created {
        let t = crate::explain::for_alert(&a.detector_id, a.severity.as_str(), &a.fields);
        let text = format!("{}\n{}\n{}\n{}", t.what, t.serious, t.done, t.r#do);
        let id = res.id.clone();
        lock(sh).busy += 1;
        let s2 = sh.clone();
        let spawned = std::thread::Builder::new().name("limbo-explain".into()).spawn(move || {
            if let Err(e) = s2.limbo.advise(&id, "heimdall", &text, Instant::now() + Duration::from_secs(30)) {
                (s2.log)(&format!("could not attach Heimdall's explanation to {id}: {e}"));
            }
            let mut st = lock(&s2);
            st.busy -= 1;
            s2.cv.notify_all();
        });
        if spawned.is_err() {
            lock(sh).busy -= 1;
        }
    }
    // only the first alert for an incident asks Sarina; repeats just re-assert the hold
    if res.created && sh.advisor.is_some() {
        let mut st = lock(sh);
        if st.advising < MAX_ADVISORIES {
            st.advising += 1;
            st.busy += 1;
            drop(st);
            let (s2, id, a) = (sh.clone(), res.id.clone(), a.clone());
            let spawned = std::thread::Builder::new().name("sarina-advice".into()).spawn(move || {
                advise(&s2, &id, &a);
                let mut st = lock(&s2);
                st.advising -= 1;
                st.busy -= 1;
                s2.cv.notify_all();
            });
            if spawned.is_err() {
                let mut st = lock(sh);
                st.advising -= 1;
                st.busy -= 1;
            }
        } else {
            drop(st);
            // never queued behind slow model calls; the human still has the evidence
            sarina_failed(
                sh,
                &res.id,
                &guest,
                advisor::CODE_BUSY,
                "skipped the Sarina advisory: other advisories are still running",
                "wait for them to finish; the quarantine itself is unaffected",
            );
        }
    }
}

/// A failed Sarina consultation in the alert stream (Go: integrationAlert); the hold and its evidence stand.
fn sarina_failed(sh: &Shared, id: &str, guest: &str, code: &str, msg: &str, remedy: &str) {
    (sh.log)(&format!("sarina advisory for {id} failed: {code}: {msg} (remedy: {remedy})"));
    let f = Fields::from([("quarantine".to_string(), id.to_string()), ("guest".to_string(), guest.to_string())]);
    (sh.out)(Alert::integration(code, msg, remedy, &f));
}

fn panic_text(p: &(dyn std::any::Any + Send)) -> String {
    p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default()
}

/// Asks Sarina about a new hold and attaches the answer as advisory "sarina" (Go: advise).
fn advise(sh: &Shared, id: &str, a: &Alert) {
    let Some(adv) = sh.advisor.as_ref() else { return };
    let guest = a.fields.get("guest").cloned().unwrap_or_default();
    let by = Instant::now() + Duration::from_secs(180);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| adv.advise(a, by)));
    let text = match r {
        Err(p) => {
            // advisory work must never take the daemon down
            sarina_failed(sh, id, &guest, "sarina_error", &format!("advisor panicked: {}", panic_text(&*p)), "report this as a Heimdall bug");
            return;
        }
        Ok(Err(e)) => {
            sarina_failed(sh, id, &guest, &e.code, &e.msg, &e.remedy);
            return;
        }
        Ok(Ok(t)) => t,
    };
    if text.is_empty() {
        return;
    }
    if let Err(e) = sh.limbo.advise(id, "sarina", &text, by) {
        (sh.log)(&format!("could not attach advisory to {id}: {e}"));
    }
}

/// One untrusted note about the backlog, recorded as its own alert; it changes nothing (Go: adviseBacklog).
fn advise_backlog(sh: &Shared, summary: &str, at: &str) {
    let Some(adv) = sh.advisor.as_ref() else { return };
    let by = Instant::now() + Duration::from_secs(180);
    let text = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| adv.advise_backlog(summary, by))) {
        Err(p) => {
            (sh.log)(&format!("backlog advisor panicked: {}", panic_text(&*p)));
            return;
        }
        Ok(Err(e)) => {
            failure(sh, "", &e.code, &format!("backlog advisory failed: {}", e.msg), &e.remedy, &[]);
            return;
        }
        Ok(Ok(t)) => advisor::clean_note(&t),
    };
    if gotext::trim_space(&text).is_empty() {
        return;
    }
    failure(
        sh,
        "",
        CODE_BACKLOG_ADVISORY,
        &format!("Sarina's note on the quarantine backlog raised at {at} (untrusted; it changed nothing)"),
        "read it as a hint only; the backlog alert has the facts",
        &[("advisory", text), ("untrusted", "true".into())],
    );
}

/// Go: Duration.Round(time.Second).String().
fn round_s(d: Duration) -> String {
    let s = (d.as_nanos() + 500_000_000) / 1_000_000_000;
    gotext::duration((s * 1_000_000_000) as i64)
}

/// Makes lateness visible while requests wait (Go: monitor and sweep). It sleeps while nothing waits.
fn monitor(sh: &Arc<Shared>) {
    let mut st = lock(sh);
    loop {
        if st.cancelled {
            return;
        }
        if st.pending.is_empty() {
            st = sh.cv.wait(st).unwrap_or_else(|p| p.into_inner());
            continue;
        }
        st = sh.cv.wait_timeout(st, sh.cfg.tick).unwrap_or_else(|p| p.into_inner()).0;
        if st.cancelled || st.pending.is_empty() {
            continue;
        }
        let now = Instant::now();
        let (waiting, running) = (st.pending.len(), st.inflight.len());
        let mut lates: Vec<(String, String)> = Vec::new();
        for q in st.pending.values_mut() {
            if !q.delayed && now.duration_since(q.enqueued) >= sh.cfg.delay {
                q.delayed = true;
                lates.push((q.guest.clone(), round_ms(now.duration_since(q.enqueued))));
            }
        }
        let mut backlog: Vec<Req> = Vec::new();
        if waiting > sh.cfg.backlog_threshold && st.last_backlog.is_none_or(|t| now.duration_since(t) >= sh.cfg.backlog_interval) {
            st.last_backlog = Some(now);
            backlog = st.pending.values().cloned().collect();
        }
        drop(st);
        lates.sort();
        for (g, w) in lates {
            failure(
                sh,
                &g,
                CODE_DELAYED,
                &format!("quarantine request for guest {} has waited {w} in the queue ({waiting} waiting, {running} in flight)", gotext::quote(&g)),
                "Limbo is answering slower than detections arrive; check limbo_quarantine_timeout / limbo_unreachable alerts and 'systemctl status limbo'; restrict the guest by hand if it is critical",
                &[("queue_wait", w.clone()), ("backlog", waiting.to_string())],
            );
        }
        if !backlog.is_empty() {
            backlog.sort_by(|a, b| if before(a, b) { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater });
            let guests = backlog.iter().map(|q| q.guest.as_str()).collect::<Vec<_>>().join(",");
            failure(
                sh,
                &guests,
                CODE_BACKLOG,
                &format!("{} quarantine requests are waiting for Limbo ({running} in flight)", backlog.len()),
                "check that Limbo is responding (systemctl status limbo, limbo_quarantine_timeout alerts); restrict the most severe guests by hand",
                &[("backlog", backlog.len().to_string()), ("guests", guests.clone()), ("in_flight", running.to_string())],
            );
            // one untrusted note from Sarina, only when a consultation slot is free (never waits for a model)
            if sh.advisor.is_some() {
                let mut summary = format!(
                    "{} quarantine requests waiting, {running} in flight (at most {MAX_QUARANTINES} run at once). Waiting, in service order:\n",
                    backlog.len()
                );
                for q in backlog.iter().take(20) {
                    summary.push_str(&format!(
                        "- {} severity={} triggers={} waited={}\n",
                        q.guest,
                        q.primary.severity.as_str(),
                        q.kinds.join(","),
                        round_s(now.duration_since(q.enqueued))
                    ));
                }
                let at = Time::now().utc().truncate(1_000_000_000).rfc3339_nano();
                let mut st = lock(sh);
                if !st.closing && st.advising < MAX_ADVISORIES {
                    st.advising += 1;
                    st.busy += 1;
                    drop(st);
                    let s2 = sh.clone();
                    let spawned = std::thread::Builder::new().name("sarina-backlog".into()).spawn(move || {
                        advise_backlog(&s2, &summary, &at);
                        let mut st = lock(&s2);
                        st.advising -= 1;
                        st.busy -= 1;
                        s2.cv.notify_all();
                    });
                    if spawned.is_err() {
                        let mut st = lock(sh);
                        st.advising -= 1;
                        st.busy -= 1;
                    }
                }
            }
        }
        st = lock(sh);
    }
}
