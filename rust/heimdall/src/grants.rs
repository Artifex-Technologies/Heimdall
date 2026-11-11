//! The grant gate's daemon half (Go: internal/grants): Sarina files requests (`POST /v1/requests`), the owner decides as root
//! with `heimdalld grant` (src/cli/grant.rs), and Sarina reads the decisions from the root-owned file. The
//! daemon only reads both files and files requests; the file formats are Go's (docs/GRANTS.md).

use crate::gojson::{self, ObjectWriter};
use crate::gotime::Time;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Mutex;

pub const KIND_ESCALATION: &str = "escalation";
pub const KIND_ACCESS_TIER: &str = "access_tier";
pub const STATUS_PENDING: &str = "pending";
pub const DEFAULT_DECISIONS: &str = "/etc/heimdall/grants.json";
const MAX_PENDING: usize = 50;

/// One ask of an AI agent.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Request {
    pub id: String,
    pub kind: String,
    pub detail: String,
    pub reason: String,
    pub session_id: String,
    pub uid: u32,
    pub time: Time,
    pub count: i64,
}
crate::go_struct!(Request {
    id: "id",
    kind: "kind",
    detail: "detail",
    reason: "reason",
    session_id: "session_id",
    uid: "uid",
    time: "time",
    count: "count",
});

impl Request {
    /// As Go's encoder writes it (`reason`, `session_id` left out when empty).
    pub fn write_json(&self, out: &mut String) {
        let mut o = ObjectWriter::new(out);
        o.str("id", &self.id);
        o.str("kind", &self.kind);
        o.str("detail", &self.detail);
        if !self.reason.is_empty() {
            o.str("reason", &self.reason);
        }
        if !self.session_id.is_empty() {
            o.str("session_id", &self.session_id);
        }
        o.raw("uid", &self.uid.to_string());
        o.str("time", &self.time.rfc3339_nano());
        o.raw("count", &self.count.to_string());
        o.end();
    }
}

/// The requests file: an array of requests, or `null` when none was read.
pub fn requests_json(rs: Option<&[Request]>, out: &mut String) {
    match rs {
        None => out.push_str("null"),
        Some(rs) => {
            out.push('[');
            for (i, r) in rs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                r.write_json(out);
            }
            out.push(']');
        }
    }
}

/// Go's MarshalIndent(v, "", "  ") of a requests array, plus the newline Go's writeJSON adds.
fn indented(rs: &[Request]) -> String {
    let mut compact = String::new();
    requests_json(Some(rs), &mut compact);
    let v = gojson::parse(compact.as_bytes()).expect("what was written reads back");
    let mut out = String::new();
    gojson::write_indented(&mut out, &v, "  ");
    out.push('\n');
    out
}

/// An approved hand-off to another model tier, until a time.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Escalation {
    pub request_id: String,
    pub tier: String,
    pub session_id: String,
    pub until: Time,
    pub by: String,
}
crate::go_struct!(Escalation { request_id: "request_id", tier: "tier", session_id: "session_id", until: "until", by: "by" });

/// One decision in the history.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Decision {
    pub request_id: String,
    pub kind: String,
    pub detail: String,
    pub status: String,
    pub by: String,
    pub time: Time,
}
crate::go_struct!(Decision { request_id: "request_id", kind: "kind", detail: "detail", status: "status", by: "by", time: "time" });

/// The owner's decisions (`/etc/heimdall/grants.json`). A list that was never set is `None` (Go's nil, written `null`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Decisions {
    pub access_tier: Option<i64>,
    pub escalations: Option<Vec<Escalation>>,
    pub history: Option<Vec<Decision>>,
}

impl Decisions {
    /// Read as Go's json.Unmarshal reads it (members matched without regard to case, the last of duplicates kept, a type
    /// error reported after the rest was read).
    pub fn read(v: &gojson::Value) -> (Decisions, Option<gojson::Error>) {
        use gojson::{FromGo, Value};
        let mut d = Decisions::default();
        let members = match gojson::struct_members(v, &["access_tier", "escalations", "history"], "grants.Decisions") {
            Ok(Some(m)) => m,
            Ok(None) => return (d, None),
            Err(e) => return (d, Some(e)),
        };
        let mut first = None;
        for (i, val) in members {
            let r = match (i, val) {
                (0, Value::Null) => {
                    d.access_tier = None;
                    Ok(())
                }
                (0, _) => {
                    let mut n = d.access_tier.unwrap_or(0);
                    let r = n.read_into(val, "access_tier");
                    d.access_tier = Some(n); // Go allocates the pointer before it finds a wrong type
                    r
                }
                (1, Value::Null) => {
                    d.escalations = None;
                    Ok(())
                }
                (1, _) => {
                    let mut x = Vec::new();
                    let r = x.read_into(val, "escalations");
                    if matches!(val, Value::Array(_)) {
                        d.escalations = Some(x);
                    }
                    r
                }
                (_, Value::Null) => {
                    d.history = None;
                    Ok(())
                }
                (_, _) => {
                    let mut x = Vec::new();
                    let r = x.read_into(val, "history");
                    if matches!(val, Value::Array(_)) {
                        d.history = Some(x);
                    }
                    r
                }
            };
            if let Err(e) = r {
                first.get_or_insert(e);
            }
        }
        (d, first)
    }

    /// As Go's encoder writes the struct.
    pub fn write_json(&self, out: &mut String) {
        let mut o = ObjectWriter::new(out);
        o.raw("access_tier", &self.access_tier.map_or("null".to_string(), |n| n.to_string()));
        let e = o.key("escalations");
        match &self.escalations {
            None => e.push_str("null"),
            Some(es) => {
                e.push('[');
                for (i, x) in es.iter().enumerate() {
                    if i > 0 {
                        e.push(',');
                    }
                    let mut w = ObjectWriter::new(e);
                    if !x.request_id.is_empty() {
                        w.str("request_id", &x.request_id);
                    }
                    w.str("tier", &x.tier);
                    if !x.session_id.is_empty() {
                        w.str("session_id", &x.session_id);
                    }
                    w.str("until", &x.until.rfc3339_nano());
                    w.str("by", &x.by);
                    w.end();
                }
                e.push(']');
            }
        }
        let h = o.key("history");
        match &self.history {
            None => h.push_str("null"),
            Some(hs) => {
                h.push('[');
                for (i, x) in hs.iter().enumerate() {
                    if i > 0 {
                        h.push(',');
                    }
                    let mut w = ObjectWriter::new(h);
                    w.str("request_id", &x.request_id);
                    w.str("kind", &x.kind);
                    w.str("detail", &x.detail);
                    w.str("status", &x.status);
                    w.str("by", &x.by);
                    w.str("time", &x.time.rfc3339_nano());
                    w.end();
                }
                h.push(']');
            }
        }
        o.end();
    }
}

/// Where the requests and the owner's decisions are kept.
pub struct Store {
    pub requests: String,
    pub decisions: String,
}

static LOCK: Mutex<()> = Mutex::new(());

/// Reads a file without following a link, at most 4 MiB (Go: readJSON).
fn read_nofollow(path: &str) -> std::io::Result<Vec<u8>> {
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    let mut b = Vec::new();
    f.take(4 << 20).read_to_end(&mut b)?;
    Ok(b)
}

/// The checks Go's Validate makes, with its messages.
pub fn validate(r: &Request) -> Result<(), String> {
    match r.kind.as_str() {
        KIND_ESCALATION => {
            if r.detail.is_empty() || r.detail.len() > 64 || r.detail.contains([' ', '\t', '\n', '/', '\\']) {
                return Err("escalation needs detail: the tier's name (no spaces, at most 64 characters)".into());
            }
        }
        KIND_ACCESS_TIER => {
            if !matches!(r.detail.as_str(), "1" | "2" | "3") {
                return Err("access_tier needs detail 1, 2 or 3 (tier 4 is set up on the operating system by the owner)".into());
            }
        }
        _ => return Err(format!("kind must be {} or {}", crate::gotext::quote(KIND_ESCALATION), crate::gotext::quote(KIND_ACCESS_TIER))),
    }
    if r.reason.len() > 1000 || r.session_id.len() > 128 {
        return Err("reason (1000) or session_id (128) too long".into());
    }
    Ok(())
}

impl Store {
    /// The open requests (None: no file yet, Go's nil).
    pub fn pending(&self) -> Result<Option<Vec<Request>>, String> {
        match read_nofollow(&self.requests) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(crate::sources::go_path_error("open", &self.requests, &e)),
            Ok(b) => gojson::unmarshal(&b, Vec::<Request>::new()).map(Some).map_err(|e| e.0),
        }
    }

    /// The owner's decisions, and whether the gate is on (the file exists and reads without error).
    pub fn load(&self) -> (Decisions, bool) {
        match read_nofollow(&self.decisions) {
            Ok(b) => match gojson::parse(&b) {
                Ok(v) => {
                    let (d, err) = Decisions::read(&v);
                    (d, err.is_none())
                }
                Err(_) => (Decisions::default(), false),
            },
            Err(_) => (Decisions::default(), false),
        }
    }

    fn with_lock<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let lf = std::fs::OpenOptions::new()
            .read(true)
            .create(true)
            .write(false)
            .append(true)
            .mode(0o640)
            .custom_flags(libc::O_NOFOLLOW)
            .open(format!("{}.lock", self.requests))
            .map_err(|e| crate::sources::go_path_error("open", &format!("{}.lock", self.requests), &e))?;
        rustix::fs::flock(&lf, rustix::fs::FlockOperation::LockExclusive).map_err(|e| e.to_string())?;
        f()
    }

    /// Files a request: the same ask (kind, detail, session, account) again is merged (count + 1, the newer reason); a new
    /// one gets a random id and the time; at most 50 are kept, the oldest dropped.
    pub fn file(&self, mut r: Request, now: Time) -> Result<Request, String> {
        validate(&r)?;
        self.with_lock(|| {
            let mut rs = self.pending()?.unwrap_or_default();
            if let Some(o) =
                rs.iter_mut().find(|o| o.kind == r.kind && o.detail == r.detail && o.session_id == r.session_id && o.uid == r.uid)
            {
                o.count += 1;
                if !r.reason.is_empty() {
                    o.reason = r.reason.clone();
                }
                let got = o.clone();
                write_requests(&self.requests, &rs)?;
                return Ok(got);
            }
            let mut id = [0u8; 4];
            random(&mut id);
            r.id = crate::state::hex(&id);
            r.time = now.utc();
            r.count = 1;
            rs.push(r.clone());
            if rs.len() > MAX_PENDING {
                let cut = rs.len() - MAX_PENDING;
                rs.drain(..cut);
            }
            write_requests(&self.requests, &rs)?;
            Ok(r.clone())
        })
    }
}

/// Go's writeJSON: a temporary file in the same folder, mode 0640, renamed into place.
fn write_requests(path: &str, rs: &[Request]) -> Result<(), String> {
    let dir = std::path::Path::new(path).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| ".".into());
    let mut id = [0u8; 6];
    random(&mut id);
    let tmp = format!("{dir}/.grants-{}", crate::state::hex(&id));
    let r = crate::state::write_mode(&tmp, indented(rs).as_bytes(), 0o640).and_then(|_| std::fs::rename(&tmp, path));
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(|e| e.to_string())
}

pub fn random(b: &mut [u8]) {
    // SAFETY: getrandom fills at most the buffer's length.
    unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
}

/// Newest first (Go: Sorted, by time; equal times keep no particular order in Go, the file's order here).
pub fn sorted(rs: &[Request]) -> Vec<Request> {
    let mut out = rs.to_vec();
    out.sort_by(|a, b| {
        if a.time.after(&b.time) {
            std::cmp::Ordering::Less
        } else if b.time.after(&a.time) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
    out
}
