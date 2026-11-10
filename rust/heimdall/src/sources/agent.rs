//! Sarina's session files into events (Go: internal/sources/agentsource). The kernel says when a session changes (inotify);
//! a full look at the folder is made at the start and every 10 minutes in case an event was missed, and every poll interval
//! only while the folder cannot be watched. A session is read only when it changed, the position in each is kept in
//! agent-sessions.json (the Go daemon's file, read and written alike) and written only when it moved.

use super::inotify::{self, Inotify, Mask};
use super::{glob_suffix, go_path_error, mtime, Issue, Msg, Source};
use crate::event::{Event, Fields};
use crate::gojson::{self, FromGo, ObjectWriter, Value};
use crate::gotime::Time;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Read;
use std::os::fd::BorrowedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

pub const CODE_UNREADABLE: &str = "agent_session_unreadable";
pub const CODE_MALFORMED: &str = "agent_session_malformed";
pub const CODE_UNKNOWN_SHAPE: &str = "agent_session_unknown_shape";
pub const CODE_NOT_A_FILE: &str = "agent_session_not_a_file";

/// Far above any real session (about 100 KB today).
const MAX_SESSION_BYTES: u64 = 32 << 20;
/// How long a file must be unmodified before invalid JSON in it counts as damage rather than a write in progress.
const SETTLE: i64 = 5_000_000_000;
/// How often the whole folder is looked at while it is watched.
const RESCAN: Duration = Duration::from_secs(600);

/// Where Sarina's evals run: their sessions are practice (field practice=1).
pub const PRACTICE_DIRS: &[&str] = &["/tmp/sarina-evals"];

fn practice(cwd: &str) -> bool {
    if cwd.is_empty() {
        return false;
    }
    let c = super::clean_path(cwd);
    PRACTICE_DIRS.iter().any(|d| c == *d || c.starts_with(&format!("{d}/")))
}

#[derive(Default)]
struct RuntimeConfig {
    cwd: String,
}
crate::go_struct!(RuntimeConfig { cwd: "cwd" });

#[derive(Default)]
struct SessionFile {
    session_id: String,
    messages: Vec<Value>,
    runtime_config: RuntimeConfig,
}
crate::go_struct!(SessionFile { session_id: "session_id", messages: "messages", runtime_config: "runtime_config" });

#[derive(Default)]
struct Function {
    name: String,
    arguments: String,
}
crate::go_struct!(Function { name: "name", arguments: "arguments" });

#[derive(Default)]
struct ToolCall {
    function: Function,
}
crate::go_struct!(ToolCall { function: "function" });

#[derive(Default)]
struct MessageObject {
    role: String,
    content: String,
    name: String,
    tool_calls: Vec<ToolCall>,
}
crate::go_struct!(MessageObject { role: "role", content: "content", name: "name", tool_calls: "tool_calls" });

/// One message as read: role, text, tool names.
pub type Decoded = (String, String, Vec<String>);

/// The role (empty for the old string shape), the text worth scanning, and the tools an assistant message called; None
/// for a system message, an empty one, or one that does not decode.
pub fn decode_message(raw: &Value) -> Option<Decoded> {
    match raw {
        // the old flat shape; null reads as an empty string in Go
        Value::String(s) => return Some((String::new(), s.clone(), Vec::new())),
        Value::Null => return Some((String::new(), String::new(), Vec::new())),
        _ => {}
    }
    let mut m = MessageObject::default();
    m.read_into(raw, "").ok()?;
    if m.role == "system" {
        return None;
    }
    let mut text = m.content;
    let mut tools = Vec::new();
    for tc in &m.tool_calls {
        let n = &tc.function.name;
        if !n.is_empty() && n.len() <= 64 && !n.contains([',', ' ', '\n']) {
            tools.push(n.clone());
        }
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(n);
        text.push(' ');
        text.push_str(&tc.function.arguments);
    }
    if text.is_empty() {
        return None;
    }
    if m.role == "tool" {
        text = unwrap_json(&text);
    }
    Some((m.role, text, tools))
}

/// A session file's bytes as the watcher reads them: the session id, the working folder, and each message decoded (None:
/// skipped or not decodable). For the fuzz target `session_file`.
pub fn parse_session(raw: &[u8]) -> Result<(String, String, Vec<Option<Decoded>>), gojson::Error> {
    let mut sf = SessionFile::default();
    sf.read_into(&gojson::parse(raw)?, "")?;
    let msgs = sf
        .messages
        .iter()
        .map(|m| {
            let d = decode_message(m);
            // what decodes is readable
            assert!(d.is_none() || readable(m));
            d
        })
        .collect();
    Ok((sf.session_id, sf.runtime_config.cwd, msgs))
}

/// A message shape this reader understands (a string or an object that decodes).
fn readable(raw: &Value) -> bool {
    matches!(raw, Value::String(_) | Value::Null) || MessageObject::default().read_into(raw, "").is_ok()
}

/// A tool result Sarina stored as JSON, as the text it carries: every string value, decoded, one after another (object
/// keys in sorted order, the last of duplicate keys kept, as Go's map does). Text that is not JSON is returned as it is.
pub fn unwrap_json(text: &str) -> String {
    let Ok(v) = gojson::parse(text.as_bytes()) else { return text.to_owned() };
    let mut parts = Vec::new();
    fn walk(v: &Value, parts: &mut Vec<String>) {
        match v {
            Value::String(s) if !s.is_empty() => parts.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|x| walk(x, parts)),
            Value::Object(m) => {
                let mut last: BTreeMap<&str, &Value> = BTreeMap::new();
                for (k, x) in m {
                    last.insert(k, x);
                }
                for x in last.values() {
                    walk(x, parts);
                }
            }
            _ => {}
        }
    }
    walk(&v, &mut parts);
    if parts.is_empty() {
        return text.to_owned();
    }
    parts.join("\n")
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Position {
    pub mod_time: Time,
    pub messages: i64,
}
crate::go_struct!(Position { mod_time: "mod_time", messages: "messages" });

/// The positions file, as Go writes it (`{"PATH":{"mod_time":..,"messages":N},...}`, keys sorted).
pub fn positions_json(seen: &BTreeMap<String, Position>) -> String {
    let mut out = String::with_capacity(seen.len() * 96);
    out.push('{');
    for (i, (k, p)) in seen.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        gojson::write_str(&mut out, k);
        out.push(':');
        let mut w = ObjectWriter::new(&mut out);
        w.str("mod_time", &p.mod_time.rfc3339_nano());
        w.raw("messages", &p.messages.to_string());
        w.end();
    }
    out.push('}');
    out
}

/// Reads one session folder (Go: agentsource.Watcher).
pub struct Watcher {
    pub dir: String,
    seen: BTreeMap<String, Position>,
    issues: Vec<Issue>,
    reported: HashSet<String>,
    state_path: String,
    dirty: bool,
    baseline: bool,
    /// Files that were not valid JSON and changed less than the settle window ago.
    unsettled: BTreeSet<String>,
}

impl Watcher {
    pub fn new(dir: &str) -> Watcher {
        Watcher {
            dir: dir.to_owned(),
            seen: BTreeMap::new(),
            issues: Vec::new(),
            reported: HashSet::new(),
            state_path: String::new(),
            dirty: false,
            baseline: false,
            unsettled: BTreeSet::new(),
        }
    }

    /// Remembers across restarts how far each session was read. Without a state file yet (the first start), the sessions
    /// already there are only recorded, not alerted on again; a state file that does not read is a fresh start, as in Go.
    pub fn with_state(dir: &str, state_path: &str) -> Watcher {
        let mut w = Watcher::new(dir);
        w.state_path = state_path.to_owned();
        match std::fs::read(state_path) {
            Ok(b) => {
                let mut st: BTreeMap<String, Position> = BTreeMap::new();
                if let Ok(v) = gojson::parse(&b) {
                    if st.read_into(&v, "").is_ok() {
                        w.seen = st;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => w.baseline = true,
            Err(_) => {}
        }
        w
    }

    pub fn positions(&self) -> &BTreeMap<String, Position> {
        &self.seen
    }

    fn save_state(&mut self) {
        if self.state_path.is_empty() || !self.dirty {
            return;
        }
        let tmp = format!("{}.tmp", self.state_path);
        if crate::state::write_private(&tmp, positions_json(&self.seen).as_bytes()).is_ok()
            && std::fs::rename(&tmp, &self.state_path).is_ok()
        {
            self.dirty = false;
        }
    }

    /// The per-file problems found since the last call, each once per file version.
    pub fn issues(&mut self) -> Vec<Issue> {
        std::mem::take(&mut self.issues)
    }

    fn report(&mut self, code: &str, path: &str, detail: String, remedy: String, mod_time: &Time) {
        let key = format!("{code}|{path}|{}", mod_time.rfc3339_nano());
        if self.reported.insert(key) {
            self.issues.push(Issue { code: code.into(), path: path.into(), detail, remedy });
        }
    }

    /// Looks at every session file once: a session_created event for a file seen for the first time, a message event for
    /// each message beyond what was already read.
    pub fn poll(&mut self) -> Result<Vec<Event>, Issue> {
        if let Err(e) = std::fs::metadata(&self.dir) {
            return Err(Issue {
                code: CODE_UNREADABLE.into(),
                path: self.dir.clone(),
                detail: go_path_error("stat", &self.dir, &e),
                remedy: format!(
                    "check agent_session_dir points at Sarina's .port_sessions and that heimdalld's user can read it (ls -ld {})",
                    self.dir
                ),
            });
        }
        let mut paths = glob_suffix(&self.dir, ".json");
        paths.extend(glob_suffix(&format!("{}/agent", self.dir), ".json"));
        let mut events = Vec::new();
        for p in paths {
            events.extend(self.check_file(&p));
        }
        Ok(self.finish(events))
    }

    /// Looks at the given files only (the ones the kernel said changed).
    pub fn check_files(&mut self, paths: &[String]) -> Vec<Event> {
        let mut events = Vec::new();
        for p in paths {
            events.extend(self.check_file(p));
        }
        self.finish(events)
    }

    fn finish(&mut self, events: Vec<Event>) -> Vec<Event> {
        let events = if self.baseline {
            self.baseline = false;
            Vec::new()
        } else {
            events
        };
        self.save_state();
        events
    }

    fn check_file(&mut self, path: &str) -> Vec<Event> {
        self.unsettled.remove(path);
        let Ok(md) = std::fs::metadata(path) else { return Vec::new() };
        let mod_time = mtime(&md);
        let name = path.rsplit('/').next().unwrap_or(path).to_owned();
        let prior = self.seen.get(path).copied();
        if let Some(p) = prior {
            if !mod_time.after(&p.mod_time) {
                return Vec::new();
            }
        }
        let raw = match read_session(path) {
            Ok(b) => b,
            Err(ReadError::NotAFile(why)) => {
                let remedy = format!("nothing but Sarina's session files belongs here; a pipe or a huge file can stall or exhaust a reader, so check who made it (ls -l {path})");
                self.report(CODE_NOT_A_FILE, path, why, remedy, &mod_time);
                return Vec::new();
            }
            Err(ReadError::Io(detail)) => {
                self.report(CODE_UNREADABLE, path, detail, format!("make the file readable by heimdalld's user (ls -l {path})"), &mod_time);
                return Vec::new();
            }
        };
        let mut sf = SessionFile::default();
        if let Err(e) = gojson::parse(&raw).and_then(|v| sf.read_into(&v, "")) {
            if Time::now().sub(&mod_time) > SETTLE {
                self.report(
                    CODE_MALFORMED,
                    path,
                    e.to_string(),
                    "the session file is damaged or not Sarina's format; its contents are NOT being scanned".into(),
                    &mod_time,
                );
            } else {
                self.unsettled.insert(path.to_owned());
            }
            return Vec::new();
        }
        if self.baseline {
            // a first look that only records positions: no events built at all. Building them (thousands of sessions) and
            // dropping them at the end left the heap 25 MB larger for good, pinned by the positions kept in between.
            self.seen.insert(path.to_owned(), Position { mod_time, messages: sf.messages.len() as i64 });
            self.dirty = true;
            return Vec::new();
        }
        let session_id = if sf.session_id.is_empty() { name.clone() } else { sf.session_id.clone() };
        let is_practice = practice(&sf.runtime_config.cwd);
        let mark = |mut f: Fields| {
            if is_practice {
                f.insert("practice".into(), "1".into());
            }
            f
        };
        let mut events = Vec::new();
        if prior.is_none() {
            events.push(Event {
                source: "agent-session".into(),
                session_id: session_id.clone(),
                time: mod_time,
                kind: "session_created".into(),
                text: String::new(),
                fields: mark(Fields::from([("file".to_string(), name.clone())])),
            });
        }
        let start = prior.map_or(0, |p| p.messages.max(0) as usize);
        for (i, m) in sf.messages.iter().enumerate().skip(start) {
            let Some((role, text, tools)) = decode_message(m) else {
                if !readable(m) {
                    self.report(
                        CODE_UNKNOWN_SHAPE,
                        path,
                        format!("message {i} has a shape Heimdall cannot decode"),
                        "Sarina's session format may have changed; check docs/spec/01-agent-core.md section 4.2 against agentsource".into(),
                        &mod_time,
                    );
                }
                continue;
            };
            let mut f = Fields::from([("file".to_string(), name.clone())]);
            if !role.is_empty() {
                f.insert("role".into(), role);
            }
            if !tools.is_empty() {
                f.insert("tools".into(), tools.join(","));
            }
            events.push(Event {
                source: "agent-session".into(),
                session_id: session_id.clone(),
                time: mod_time,
                kind: "message".into(),
                text,
                fields: mark(f),
            });
        }
        self.seen.insert(path.to_owned(), Position { mod_time, messages: sf.messages.len() as i64 });
        self.dirty = true;
        events
    }
}

enum ReadError {
    NotAFile(String),
    Io(String),
}

/// One session file, without following a link, without blocking on a pipe, and refusing one over the size limit (the
/// folder is writable by more than Sarina, so what is in it is not trusted).
fn read_session(path: &str) -> Result<Vec<u8>, ReadError> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path);
    let mut f = match f {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(40) => return Err(ReadError::NotAFile("a symbolic link".into())),
        Err(e) => return Err(ReadError::Io(go_path_error("open", path, &e))),
    };
    let md = f.metadata().map_err(|e| ReadError::Io(go_path_error("stat", path, &e)))?;
    if md.is_dir() {
        return Err(ReadError::Io(format!("read {path}: is a directory")));
    }
    if !md.file_type().is_file() {
        return Err(ReadError::NotAFile(format!("not a regular file ({})", go_mode_type(&md))));
    }
    if md.len() > MAX_SESSION_BYTES {
        return Err(ReadError::NotAFile(format!("{} bytes, more than the {} a session may be", md.len(), MAX_SESSION_BYTES)));
    }
    let mut buf = Vec::with_capacity(md.len() as usize);
    (&mut f).take(MAX_SESSION_BYTES + 1).read_to_end(&mut buf).map_err(|e| ReadError::Io(go_path_error("read", path, &e)))?;
    if buf.len() as u64 > MAX_SESSION_BYTES {
        return Err(ReadError::NotAFile("grew past the size a session may be while being read".into()));
    }
    Ok(buf)
}

/// Go's `fi.Mode().Type().String()` for the kinds a session folder can hold.
fn go_mode_type(md: &std::fs::Metadata) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    let t = md.file_type();
    if t.is_fifo() {
        "p---------"
    } else if t.is_socket() {
        "S---------"
    } else if t.is_char_device() {
        "Dc---------"
    } else if t.is_block_device() {
        "D---------"
    } else if t.is_symlink() {
        "L---------"
    } else {
        "?---------"
    }
}

fn dir_mask() -> Mask {
    Mask::CLOSE_WRITE | Mask::MOVED_TO | Mask::CREATE | Mask::ATTRIB | Mask::DELETE_SELF | Mask::MOVE_SELF | Mask::ONLYDIR
}

struct Watch {
    ino: Inotify,
    dir: i32,
    agent: Option<i32>,
}

/// The session source on the daemon's loop.
pub struct AgentSource {
    w: Watcher,
    interval: Duration,
    watch: Option<Watch>,
    /// While unwatched: when to look again.
    poll_at: Instant,
    rescan_at: Instant,
    changed: BTreeSet<String>,
    due_at: Option<Instant>,
    last_read: Option<Instant>,
    last_err: String,
    last_watch_err: String,
}

impl AgentSource {
    pub fn new(w: Watcher, interval: Duration) -> AgentSource {
        let now = Instant::now();
        AgentSource {
            w,
            interval,
            watch: None,
            poll_at: now,
            rescan_at: now + RESCAN,
            changed: BTreeSet::new(),
            due_at: None,
            last_read: None,
            last_err: String::new(),
            last_watch_err: String::new(),
        }
    }

    fn deliver(&mut self, r: Result<Vec<Event>, Issue>, out: &mut Vec<Msg>) {
        match r {
            Ok(events) => {
                self.last_err.clear();
                out.extend(self.w.issues().into_iter().map(Msg::Issue));
                out.extend(events.into_iter().map(Msg::Event));
            }
            Err(issue) => {
                let text = issue.to_string();
                if text != self.last_err {
                    out.push(Msg::Issue(issue));
                }
                self.last_err = text;
                out.extend(self.w.issues().into_iter().map(Msg::Issue));
            }
        }
    }

    fn again(&mut self) {
        let unsettled: Vec<String> = self.w.unsettled.iter().cloned().collect();
        self.changed.extend(unsettled);
    }

    fn arm(&mut self, now: Instant) {
        if !self.changed.is_empty() && self.due_at.is_none() {
            let wait = match self.last_read {
                Some(l) => self.interval.saturating_sub(now.duration_since(l)),
                None => Duration::ZERO,
            };
            self.due_at = Some(now + wait);
        }
    }

    fn full(&mut self, now: Instant, out: &mut Vec<Msg>) {
        let r = self.w.poll();
        self.deliver(r, out);
        self.again();
        self.rescan_at = now + RESCAN;
        self.arm(now);
    }

    fn start_watch(&mut self, now: Instant, out: &mut Vec<Msg>) {
        // the watch comes before the look, so nothing saved in between is missed
        let watch = Inotify::new().and_then(|ino| {
            let dir = ino.add(&self.w.dir, dir_mask())?;
            let agent = ino.add(&format!("{}/agent", self.w.dir), dir_mask()).ok();
            Ok(Watch { ino, dir, agent })
        });
        match watch {
            Ok(w) => {
                self.watch = Some(w);
                self.last_watch_err.clear();
                self.full(now, out);
            }
            Err(e) => {
                self.watch = None;
                let r = self.w.poll();
                self.deliver(r, out);
                let text = super::go_errno(&e);
                if std::fs::metadata(&self.w.dir).is_ok() && text != self.last_watch_err {
                    out.push(Msg::Log(format!(
                        "agentsource: cannot watch {} ({text}); looking at it every {} instead",
                        self.w.dir,
                        crate::gotext::duration(self.interval.as_nanos() as i64)
                    )));
                }
                self.last_watch_err = text;
                self.poll_at = now + self.interval;
            }
        }
    }
}

impl Source for AgentSource {
    fn name(&self) -> &'static str {
        "agent-sessions"
    }

    fn fd(&self) -> Option<BorrowedFd<'_>> {
        self.watch.as_ref().map(|w| w.ino.fd())
    }

    fn due(&self) -> Option<Instant> {
        match &self.watch {
            None => Some(self.poll_at),
            Some(_) => Some(self.due_at.map_or(self.rescan_at, |d| d.min(self.rescan_at))),
        }
    }

    fn ready(&mut self, now: Instant, out: &mut Vec<Msg>) {
        let Some(watch) = &mut self.watch else { return };
        let evs = match watch.ino.read() {
            Ok(e) => e,
            Err(_) => {
                self.watch = None;
                self.poll_at = now;
                return;
            }
        };
        let dir = self.w.dir.clone();
        for ev in evs {
            let watch = self.watch.as_mut().expect("watching");
            let gone = inotify::IN_IGNORED | inotify::IN_DELETE_SELF | inotify::IN_MOVE_SELF;
            if ev.mask & inotify::IN_Q_OVERFLOW != 0 {
                self.full(now, out); // events were dropped: look at everything
            } else if ev.wd == watch.dir && ev.mask & gone != 0 {
                // the folder went away or moved: watch the path again
                self.watch = None;
                self.poll_at = now;
                return;
            } else if Some(ev.wd) == watch.agent && ev.mask & gone != 0 {
                if let Some(a) = watch.agent.take() {
                    watch.ino.remove(a);
                }
            } else if ev.wd == watch.dir
                && ev.name == "agent"
                && ev.mask & inotify::IN_ISDIR != 0
                && ev.mask & (inotify::IN_CREATE | inotify::IN_MOVED_TO) != 0
            {
                if watch.agent.is_none() {
                    if let Ok(a) = watch.ino.add(&format!("{dir}/agent"), dir_mask()) {
                        watch.agent = Some(a);
                        self.full(now, out); // sessions may have come with the folder
                    }
                }
            } else if ev.name.ends_with(".json") && ev.wd == watch.dir {
                self.changed.insert(format!("{dir}/{}", ev.name));
            } else if ev.name.ends_with(".json") && Some(ev.wd) == watch.agent {
                self.changed.insert(format!("{dir}/agent/{}", ev.name));
            }
        }
        self.arm(now);
    }

    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        if self.watch.is_none() {
            if now >= self.poll_at {
                self.start_watch(now, out);
            }
            return;
        }
        if now >= self.rescan_at {
            self.full(now, out);
        }
        if self.due_at.is_some_and(|d| now >= d) {
            self.due_at = None;
            let paths: Vec<String> = std::mem::take(&mut self.changed).into_iter().collect();
            self.last_read = Some(now);
            let events = self.w.check_files(&paths);
            self.deliver(Ok(events), out);
            self.again();
            self.arm(now);
        }
    }
}
