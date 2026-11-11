//! `heimdalld grant status|approve|deny|tier|revoke|off` (Go: cmd/heimdalld/grant.go, internal/grants): the owner's side of
//! the grant gate. Sarina files requests (the daemon writes /var/lib/heimdall/grant-requests.json); the owner decides here, as
//! root, at a terminal, and the decisions go to /etc/heimdall/grants.json, which Sarina reads (docs/GRANTS.md).
//!
//! Both files are read and written as Go's `encoding/json` does with Go's structs (`gostruct`): unknown keys dropped, keys
//! matched without regard to case, `omitempty`, nil lists as `null`, `MarshalIndent` with two spaces and a newline.

use crate::cli::goflag::FlagSet;
use crate::goerr;
use crate::gostruct::{self, Field, Ty, Val};
use crate::gotime::Time;
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const USAGE: &str = "usage:
  heimdalld grant status                     the gate's state: access tier cap, approved hand-offs, open requests
  sudo heimdalld grant approve ID [--for 1h] allow one request (a hand-off lasts --for, at most 24h)
  sudo heimdalld grant deny ID               refuse it
  sudo heimdalld grant tier N                set the AI agent's access tier cap (0-3); switches the gate on
  sudo heimdalld grant revoke                end every approved hand-off now
  sudo heimdalld grant off                   switch the gate off (the agent goes back to its own setting)
Decisions are made by a person: root, at a terminal, never from a command an AI agent started (docs/GRANTS.md).";

pub const DEFAULT_REQUESTS: &str = "/var/lib/heimdall/grant-requests.json";
pub const DEFAULT_DECISIONS: &str = "/etc/heimdall/grants.json";
/// One approval of a hand-off lasts at most a day.
pub const MAX_ESCALATION_FOR: i64 = 24 * 3600 * 1_000_000_000;

pub static REQUEST: Ty = Ty::Struct(
    "grants.Request",
    &[
        Field("id", &Ty::Str, false),
        Field("kind", &Ty::Str, false),
        Field("detail", &Ty::Str, false),
        Field("reason", &Ty::Str, true),
        Field("session_id", &Ty::Str, true),
        Field("uid", &Ty::Uint32, false),
        Field("time", &Ty::Time, false),
        Field("count", &Ty::Int, false),
    ],
);
pub static REQUESTS: Ty = Ty::Slice(&REQUEST);
pub static ESCALATION: Ty = Ty::Struct(
    "grants.Escalation",
    &[
        Field("request_id", &Ty::Str, true),
        Field("tier", &Ty::Str, false),
        Field("session_id", &Ty::Str, true),
        Field("until", &Ty::Time, false),
        Field("by", &Ty::Str, false),
    ],
);
pub static DECISION: Ty = Ty::Struct(
    "grants.Decision",
    &[
        Field("request_id", &Ty::Str, false),
        Field("kind", &Ty::Str, false),
        Field("detail", &Ty::Str, false),
        Field("status", &Ty::Str, false),
        Field("by", &Ty::Str, false),
        Field("time", &Ty::Time, false),
    ],
);
pub static DECISIONS: Ty = Ty::Struct(
    "grants.Decisions",
    &[
        Field("access_tier", &Ty::Ptr(&Ty::Int), false),
        Field("escalations", &Ty::Slice(&ESCALATION), false),
        Field("history", &Ty::Slice(&DECISION), false),
    ],
);

/// A struct field by index (the field lists above).
fn f(v: &Val, i: usize) -> &Val {
    match v {
        Val::Struct(vals) => &vals[i],
        _ => panic!("not a struct"),
    }
}
fn f_mut(v: &mut Val, i: usize) -> &mut Val {
    match v {
        Val::Struct(vals) => &mut vals[i],
        _ => panic!("not a struct"),
    }
}
fn s(v: &Val) -> &str {
    match v {
        Val::Str(s) => s,
        _ => "",
    }
}
fn t(v: &Val) -> Time {
    match v {
        Val::Time(t) => *t,
        _ => Time::default(),
    }
}
fn int(v: &Val) -> i64 {
    match v {
        Val::Int(i) => *i,
        Val::Uint(u) => *u as i64,
        _ => 0,
    }
}
fn items(v: &Val) -> &[Val] {
    match v {
        Val::Slice(Some(x)) => x,
        _ => &[],
    }
}

/// Where the two files are.
pub struct Store {
    pub requests: String,
    pub decisions: String,
}

impl Store {
    pub fn default_paths() -> Store {
        Store { requests: DEFAULT_REQUESTS.into(), decisions: DEFAULT_DECISIONS.into() }
    }
}

/// Go's readJSON: never through a link, at most 4 MiB, then json.Unmarshal (the value as far as it read, and the error).
/// Err(None): the file does not exist.
fn read_json(path: &str, ty: &Ty) -> Result<(Val, Option<String>), Option<String>> {
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path);
    let file = match file {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(None),
        Err(e) => return Err(Some(goerr::path("open", path, &e))),
    };
    let mut b = Vec::new();
    if let Err(e) = file.take(4 << 20).read_to_end(&mut b) {
        return Err(Some(goerr::path("read", path, &e)));
    }
    let (v, err) = gostruct::unmarshal(ty, &b);
    Ok((v, err.map(|e| e.0)))
}

/// Go's writeJSON: MarshalIndent + newline into a temporary file in the same folder (os.CreateTemp, ".grants-*"), its mode
/// set, left to the folder's owner when root writes it, renamed into place.
fn write_json(path: &str, ty: &Ty, v: &Val, mode: u32) -> Result<(), String> {
    let body = gostruct::to_json_indented(ty, v, "  ").ok_or_else(|| "json: unsupported value".to_string())? + "\n";
    let dir = crate::gopath::dir(path);
    let (tmp, mut file) = create_temp(&dir, ".grants-")?;
    let cleanup = |e: String| {
        let _ = std::fs::remove_file(&tmp);
        Err(e)
    };
    if let Err(e) = file.write_all(body.as_bytes()) {
        return cleanup(goerr::path("write", &tmp, &e));
    }
    if let Err(e) = file.set_permissions(std::fs::Permissions::from_mode(mode)) {
        return cleanup(goerr::path("chmod", &tmp, &e));
    }
    if rustix::process::geteuid().is_root() {
        if let Ok(m) = std::fs::metadata(&dir) {
            let _ = std::os::unix::fs::fchown(&file, Some(m.uid()), Some(m.gid()));
        }
    }
    drop(file);
    let r = crate::gopath::rename(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    r
}

/// Go's os.CreateTemp(dir, prefix+"*"): the name is the prefix and a random decimal number, made new (O_EXCL, mode 0600).
fn create_temp(dir: &str, prefix: &str) -> Result<(String, std::fs::File), String> {
    for _ in 0..10000 {
        let mut b = [0u8; 4];
        crate::grants::random(&mut b);
        let name = crate::gopath::join(&[dir, &format!("{prefix}{}", u32::from_le_bytes(b))]);
        match std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&name) {
            Ok(f) => return Ok((name, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(goerr::path("open", &name, &e)),
        }
    }
    Err(format!("createtemp {}: file already exists", crate::gopath::join(&[dir, &format!("{prefix}*")])))
}

impl Store {
    /// Go's Pending: the open requests (None: no file, Go's nil); an unreadable or damaged file is an error.
    pub fn pending(&self) -> Result<Val, String> {
        match read_json(&self.requests, &REQUESTS) {
            Err(None) => Ok(Val::Slice(None)),
            Err(Some(e)) => Err(e),
            Ok((_, Some(e))) => Err(e),
            Ok((v, None)) => Ok(v),
        }
    }

    /// Go's Load: the decisions, whether the gate is on, and the error (a damaged file: on is false and the error is set;
    /// what was read so far is kept, as Go's decoder keeps it).
    pub fn load(&self) -> (Val, bool, Option<String>) {
        match read_json(&self.decisions, &DECISIONS) {
            Err(None) => (gostruct::zero(&DECISIONS), false, None),
            Err(Some(e)) => (gostruct::zero(&DECISIONS), false, Some(e)),
            Ok((v, Some(e))) => (v, false, Some(e)),
            Ok((v, None)) => (v, true, None),
        }
    }

    /// Go's lock: an exclusive flock on the requests file's ".lock" beside it (made if missing, mode 0640, never a link).
    fn lock(&self) -> Result<std::fs::File, String> {
        let p = format!("{}.lock", self.requests);
        use rustix::fs::{Mode, OFlags};
        let lf = rustix::fs::open(&p, OFlags::RDONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::from_raw_mode(0o640))
            .map_err(|e| goerr::path("open", &p, &e.into()))?;
        rustix::fs::flock(&lf, rustix::fs::FlockOperation::LockExclusive).map_err(|e| goerr::errno(e.raw_os_error()))?;
        Ok(std::fs::File::from(lf))
    }

    /// Go's Decide: approve or deny a pending request; the request leaves the list either way.
    pub fn decide(&self, id: &str, approve: bool, by: &str, dur: i64, now: Time) -> Result<Val, String> {
        let _lock = self.lock()?;
        let mut rs = self.pending()?;
        let idx = items(&rs).iter().rposition(|r| s(f(r, 0)) == id);
        let Some(idx) = idx else {
            return Err(format!("no open request {} (heimdalld grant list)", crate::gotext::quote(id)));
        };
        let r = items(&rs)[idx].clone();
        let (mut d, _, err) = self.load();
        if let Some(e) = err {
            return Err(format!("{} is damaged, not changing it: {e}", self.decisions));
        }
        let mut dec = decision(s(f(&r, 0)), s(f(&r, 1)), s(f(&r, 2)), "denied", by, now.utc());
        if approve {
            *f_mut(&mut dec, 3) = Val::Str("approved".into());
            match s(f(&r, 1)) {
                "escalation" => {
                    if dur <= 0 || dur > MAX_ESCALATION_FOR {
                        return Err(format!("an escalation is approved for at most {}", crate::gotext::duration(MAX_ESCALATION_FOR)));
                    }
                    let e = Val::Struct(vec![
                        Val::Str(s(f(&r, 0)).into()),
                        Val::Str(s(f(&r, 2)).into()),
                        Val::Str(s(f(&r, 4)).into()),
                        Val::Time(now.add(dur).utc()),
                        Val::Str(by.into()),
                    ]);
                    push(f_mut(&mut d, 1), e);
                }
                "access_tier" => {
                    // Go: int(r.Detail[0] - '0'), a byte's arithmetic
                    let n = s(f(&r, 2)).as_bytes().first().map_or(0, |b| b.wrapping_sub(b'0') as i64);
                    *f_mut(&mut d, 0) = Val::Ptr(Some(Box::new(Val::Int(n))));
                }
                _ => {}
            }
        }
        prune(&mut d, now);
        push(f_mut(&mut d, 2), dec.clone());
        trim_history(&mut d);
        write_json(&self.decisions, &DECISIONS, &d, 0o644)?;
        if let Val::Slice(Some(list)) = &mut rs {
            list.remove(idx);
        }
        write_json(&self.requests, &REQUESTS, &rs, 0o640)?;
        Ok(dec)
    }

    /// Go's SetTier: the owner sets the cap directly (0-3).
    pub fn set_tier(&self, n: i64, by: &str, now: Time) -> Result<(), String> {
        if !(0..=3).contains(&n) {
            return Err("the access tier is 0, 1, 2 or 3".into());
        }
        let (mut d, _, err) = self.load();
        if let Some(e) = err {
            return Err(format!("{} is damaged, not changing it: {e}", self.decisions));
        }
        *f_mut(&mut d, 0) = Val::Ptr(Some(Box::new(Val::Int(n))));
        prune(&mut d, now);
        push(f_mut(&mut d, 2), decision("", "access_tier", &n.to_string(), "set", by, now.utc()));
        write_json(&self.decisions, &DECISIONS, &d, 0o644)
    }

    /// Go's Revoke: every approved hand-off ends now.
    pub fn revoke(&self, by: &str, now: Time) -> Result<(), String> {
        let (mut d, _, err) = self.load();
        if let Some(e) = err {
            return Err(e);
        }
        *f_mut(&mut d, 1) = Val::Slice(None);
        push(f_mut(&mut d, 2), decision("", "escalation", "", "revoked", by, now.utc()));
        write_json(&self.decisions, &DECISIONS, &d, 0o644)
    }
}

fn decision(req: &str, kind: &str, detail: &str, status: &str, by: &str, time: Time) -> Val {
    Val::Struct(vec![
        Val::Str(req.into()),
        Val::Str(kind.into()),
        Val::Str(detail.into()),
        Val::Str(status.into()),
        Val::Str(by.into()),
        Val::Time(time),
    ])
}

/// Go's append: a nil list becomes a list.
fn push(list: &mut Val, x: Val) {
    match list {
        Val::Slice(Some(v)) => v.push(x),
        other => *other = Val::Slice(Some(vec![x])),
    }
}

/// Go's prune: the hand-offs whose time is over leave (a nil list stays nil).
fn prune(d: &mut Val, now: Time) {
    if let Val::Slice(Some(es)) = f_mut(d, 1) {
        es.retain(|e| t(f(e, 3)).after(&now));
    }
}

/// At most the last 200 decisions are kept.
fn trim_history(d: &mut Val) {
    if let Val::Slice(Some(h)) = f_mut(d, 2) {
        if h.len() > 200 {
            let cut = h.len() - 200;
            h.drain(..cut);
        }
    }
}

/// The pending requests newest first (Go's Sorted; equal times keep the file's order).
fn sorted(rs: &[Val]) -> Vec<Val> {
    let mut out = rs.to_vec();
    out.sort_by_key(|r| std::cmp::Reverse(t(f(r, 6))));
    out
}

/// The fuzz target's body (rust/fuzz/fuzz_targets/grant_files.rs): any bytes as either file read without a panic, and
/// whatever reads cleanly is written back so that it reads again as the same value.
pub fn fuzz_files(data: &[u8]) {
    for ty in [&DECISIONS, &REQUESTS] {
        let (v, err) = gostruct::unmarshal(ty, data);
        if err.is_none() {
            if let Some(out) = gostruct::to_json_indented(ty, &v, "  ") {
                let (back, e2) = gostruct::unmarshal(ty, out.as_bytes());
                assert!(e2.is_none(), "{out}");
                assert_eq!(back, v);
            }
        }
    }
    let _ = sscan_int(&crate::gotext::lossy(data));
}

/// Go's EscalationAllowed: is a hand-off to `tier` in `session` approved at `now`?
pub fn escalation_allowed(d: &Val, tier: &str, session: &str, now: Time) -> bool {
    items(f(d, 1)).iter().any(|e| s(f(e, 1)) == tier && (s(f(e, 2)).is_empty() || s(f(e, 2)) == session) && now.before(&t(f(e, 3))))
}

/// The decisions as the Go fixture (testdata/parity/cli-admin.json) sums them up: "on=true tier=3 live=a,b".
pub fn status_view(d: &Val, on: bool, now: Time) -> String {
    let tier = match f(d, 0) {
        Val::Ptr(Some(n)) => int(n).to_string(),
        _ => "nil".into(),
    };
    let live: Vec<&str> =
        items(f(d, 1)).iter().filter(|e| escalation_allowed(d, s(f(e, 1)), s(f(e, 2)), now)).map(|e| s(f(e, 1))).collect();
    format!("on={on} tier={tier} live={}", live.join(","))
}

/// The pending requests' ids, newest first.
pub fn sorted_ids(p: &Val) -> Vec<String> {
    sorted(items(p)).iter().map(|r| s(f(r, 0)).to_string()).collect()
}

// --- the guard: a person at a terminal, never an agent (Go: internal/grants/guard.go)

/// Programs whose descendants may never decide a request.
pub const AGENT_PROGRAMS: &[&str] = &["sarina", "sarina-service"];
/// Accounts that may never decide a request.
pub const AGENT_ACCOUNTS: &[&str] = &["sarina"];

/// Go's Guard: Ok when the calling process may decide: a terminal on standard input, sudo not used by an agent account, and
/// no agent program or account among its ancestors (at most 64 of them, up to pid 1).
pub fn guard(proc_root: &str, terminal: bool) -> Result<(), String> {
    if !terminal {
        return Err("a decision is made by a person at a terminal (standard input is not one)".into());
    }
    let sudo = std::env::var("SUDO_USER").unwrap_or_default();
    for a in AGENT_ACCOUNTS {
        if sudo == *a {
            return Err(format!("the account {a} asked through sudo: an agent never decides its own requests"));
        }
    }
    let agent_uids: Vec<String> = AGENT_ACCOUNTS.iter().filter_map(|a| lookup_uid(a)).collect();
    let mut pid = std::process::id() as i64;
    let mut i = 0;
    while i < 64 && pid > 1 {
        let (ppid, uids) = status(proc_root, pid).map_err(|e| format!("cannot check who started this command ({e}); refusing"))?;
        if uids.iter().any(|u| agent_uids.contains(u)) {
            return Err(format!("process {pid} runs as an agent account: an agent never decides its own requests"));
        }
        let name = program(proc_root, pid);
        if !name.is_empty() && AGENT_PROGRAMS.contains(&name.as_str()) {
            return Err(format!("this command was started (through process {pid}) by {name}: an agent never decides its own requests"));
        }
        pid = ppid;
        i += 1;
    }
    Ok(())
}

/// The account's uid from /etc/passwd (Go's user.Lookup).
fn lookup_uid(name: &str) -> Option<String> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let mut p = l.split(':');
        (p.next()? == name).then(|| p.nth(1).map(str::to_string))?
    })
}

/// A process's parent and its user ids, from /proc/PID/status.
fn status(proc_root: &str, pid: i64) -> Result<(i64, Vec<String>), String> {
    let p = crate::gopath::join(&[proc_root, &pid.to_string(), "status"]);
    let b = std::fs::read(&p).map_err(|e| crate::gopath::read_err(&p, &e))?;
    let text = crate::gotext::lossy(&b);
    let mut ppid = -1;
    let mut uids = Vec::new();
    for line in text.split('\n') {
        let Some((k, v)) = line.split_once(':') else { continue };
        match k {
            "PPid" => ppid = crate::gotext::atoi(crate::gotext::trim_space(v)).unwrap_or(0),
            "Uid" => uids = crate::gotext::fields(v).map(str::to_string).collect(),
            _ => {}
        }
    }
    if ppid < 0 {
        return Err(format!("no parent in {p}"));
    }
    Ok((ppid, uids))
}

/// The base name of the process's program when it is an agent's, else of its first argument.
fn program(proc_root: &str, pid: i64) -> String {
    let dir = crate::gopath::join(&[proc_root, &pid.to_string()]);
    if let Ok(exe) = std::fs::read_link(format!("{dir}/exe")) {
        let exe = exe.to_string_lossy();
        let base = crate::gopath::base(exe.strip_suffix(" (deleted)").unwrap_or(&exe));
        if AGENT_PROGRAMS.contains(&base.as_str()) {
            return base;
        }
    }
    if let Ok(mut cmd) = std::fs::read(format!("{dir}/cmdline")) {
        if let Some(i) = cmd.iter().position(|b| *b == 0) {
            cmd.truncate(i);
        }
        return crate::gopath::base(&crate::gotext::lossy(&cmd));
    }
    String::new()
}

/// Whether standard input is a terminal (TCGETS succeeds).
pub fn stdin_is_terminal() -> bool {
    // SAFETY: isatty only asks the kernel about descriptor 0 (TCGETS)
    unsafe { libc::isatty(0) == 1 }
}

// --- the command

/// Go's flagsFirst: "--name value" and "--name=value" moved before the positional words.
fn flags_first(args: &[String]) -> Vec<String> {
    let (mut flags, mut pos) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') && a.len() > 1 {
            flags.push(a.clone());
            if !a.contains('=') && i + 1 < args.len() {
                flags.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            pos.push(a.clone());
        }
        i += 1;
    }
    flags.extend(pos);
    flags
}

/// Go's `fmt.Sscan(s, &n)` for an int: spaces skipped, a sign, a base prefix (0b, 0o, 0x, or 0 for octal), digits and
/// underscores, the rest of the text ignored.
pub fn sscan_int(s: &str) -> Option<i64> {
    let b = s.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{85}' || c == '\u{a0}');
    let bytes = b.as_bytes();
    let mut i = 0;
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] == b'+' || bytes[0] == b'-' {
        i += 1;
    }
    let (digits, have): (&[u8], bool) = if bytes.get(i) == Some(&b'0') {
        i += 1;
        match bytes.get(i) {
            Some(b'b' | b'B') => {
                i += 1;
                (b"01_", true)
            }
            Some(b'o' | b'O') => {
                i += 1;
                (b"01234567_", true)
            }
            Some(b'x' | b'X') => {
                i += 1;
                (b"0123456789aAbBcCdDeEfF_", true)
            }
            _ => (b"01234567_", true),
        }
    } else {
        (b"0123456789_", false)
    };
    let start = i;
    while i < bytes.len() && digits.contains(&bytes[i]) {
        i += 1;
    }
    if !have && i == start {
        return None;
    }
    crate::cli::goflag::parse_int(&b[..i]).ok()
}

pub(crate) fn confirm(prompt: &str) -> bool {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    crate::gotext::trim_space(&line) == "yes"
}

fn print_request(r: &Val) {
    let mut out = format!(
        "request {} ({}, asked {} time(s), first {})\n  wants:   {} {}\n",
        s(f(r, 0)),
        t(f(r, 6)).local().format("2006-01-02 15:04"),
        int(f(r, 7)),
        s(f(r, 1)),
        s(f(r, 1)),
        s(f(r, 2))
    );
    if !s(f(r, 4)).is_empty() {
        out += &format!("  session: {}\n", s(f(r, 4)));
    }
    out += &format!("  account: {}\n", int(f(r, 5)));
    if !s(f(r, 3)).is_empty() {
        out += &format!("  reason (the agent's words, untrusted): {}\n", crate::gotext::quote(s(f(r, 3))));
    }
    print!("{out}");
}

fn status_cmd(st: &Store) -> i32 {
    let (d, on, err) = st.load();
    if let Some(e) = err {
        eprintln!("heimdalld grant: {e}");
        return 1;
    }
    if !on {
        println!("gate: off (sudo heimdalld grant tier N switches it on)");
    } else {
        let tier = match f(&d, 0) {
            Val::Ptr(Some(n)) => int(n).to_string(),
            _ => "not set (read as 0, read-only)".into(),
        };
        println!("gate: on; access tier cap: {tier}");
        let now = Time::now();
        for e in items(f(&d, 1)) {
            if t(f(e, 3)).after(&now) {
                let sess = if s(f(e, 2)).is_empty() { "any session" } else { s(f(e, 2)) };
                println!(
                    "  hand-off to {} allowed for {} until {} (by {})",
                    s(f(e, 1)),
                    sess,
                    t(f(e, 3)).local().format("15:04"),
                    s(f(e, 4))
                );
            }
        }
    }
    let pending = match st.pending() {
        Ok(p) => p,
        Err(e) => {
            println!("open requests: unreadable here ( {e} ); try with sudo");
            return 0;
        }
    };
    if items(&pending).is_empty() {
        println!("no open requests");
    }
    for r in sorted(items(&pending)) {
        print_request(&r);
    }
    0
}

pub fn main(args: &[String]) -> Option<i32> {
    Some(run(args))
}

fn run(args: &[String]) -> i32 {
    let st = Store::default_paths();
    if args.is_empty() || args[0] == "status" || args[0] == "list" {
        return status_cmd(&st);
    }
    let mut fs = FlagSet::new("grant");
    fs.duration("for", 3_600_000_000_000, "how long an approved hand-off lasts (at most 24h)");
    let action = args[0].as_str();
    if fs.parse(&flags_first(&args[1..])).is_err() {
        return 2;
    }
    if !rustix::process::geteuid().is_root() {
        eprintln!("heimdalld grant: deciding needs root (sudo)");
        return 1;
    }
    if let Err(e) = guard("/proc", stdin_is_terminal()) {
        eprintln!("heimdalld grant: refused: {e}");
        return 1;
    }
    let mut by = std::env::var("SUDO_USER").unwrap_or_default();
    if by.is_empty() {
        by = "root".into();
    }
    let now = Time::now().local();
    let dur = fs.get_duration("for");
    let pos = fs.args().to_vec();
    match action {
        "approve" | "deny" if pos.len() == 1 => {
            let id = &pos[0];
            let pending = match st.pending() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("heimdalld grant: {e}");
                    return 1;
                }
            };
            let Some(req) = items(&pending).iter().rev().find(|r| s(f(r, 0)) == id) else {
                eprintln!("heimdalld grant: no open request {id} (heimdalld grant status)");
                return 2;
            };
            print_request(req);
            if action == "approve" {
                if s(f(req, 1)) == "escalation" {
                    println!(
                        "The conversation and its files' text may be sent to {} for {}.",
                        crate::gotext::quote(s(f(req, 2))),
                        crate::gotext::duration(dur)
                    );
                }
                if !confirm("Allow it? Type yes: ") {
                    println!("nothing changed");
                    return 1;
                }
            }
            match st.decide(id, action == "approve", &by, dur, now) {
                Ok(d) => {
                    println!("{}: {} {}", s(f(&d, 3)), s(f(&d, 1)), s(f(&d, 2)));
                    0
                }
                Err(e) => {
                    eprintln!("heimdalld grant: {e}");
                    1
                }
            }
        }
        "tier" if pos.len() == 1 => {
            let Some(n) = sscan_int(&pos[0]) else {
                eprintln!("{USAGE}");
                return 2;
            };
            if let Err(e) = st.set_tier(n, &by, now) {
                eprintln!("heimdalld grant: {e}");
                return 1;
            }
            println!("access tier cap: {n} (the agent uses the lower of this and its own setting)");
            0
        }
        "revoke" if pos.is_empty() => {
            if let Err(e) = st.revoke(&by, now) {
                eprintln!("heimdalld grant: {e}");
                return 1;
            }
            println!("every approved hand-off ended");
            0
        }
        "off" if pos.is_empty() => {
            if !confirm("Switch the gate off? The AI agent then uses its own access setting and its own hand-off rules. Type yes: ") {
                return 1;
            }
            if let Err(e) = std::fs::remove_file(&st.decisions) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("heimdalld grant: {}", goerr::path("remove", &st.decisions, &e));
                    return 1;
                }
            }
            println!("gate off");
            0
        }
        _ => {
            eprintln!("{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sscan_as_go() {
        for (s, n) in
            [("2", Some(2)), (" 2", Some(2)), ("2x", Some(2)), ("+3", Some(3)), ("-1", Some(-1)), ("09", Some(0)), ("0x10", Some(16))]
        {
            assert_eq!(sscan_int(s), n, "{s}");
        }
        for s in ["", "x", "0x", "0b2", "99999999999999999999", " "] {
            assert_eq!(sscan_int(s), None, "{s}");
        }
        assert_eq!(sscan_int("1_0"), Some(10));
    }

    #[test]
    fn flags_move_first() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(flags_first(&v(&["ab", "--for", "2h", "x"])), v(&["--for", "2h", "ab", "x"]));
        assert_eq!(flags_first(&v(&["ab", "--for=2h"])), v(&["--for=2h", "ab"]));
        assert_eq!(flags_first(&v(&["ab", "-x"])), v(&["-x", "ab"]));
    }
}
