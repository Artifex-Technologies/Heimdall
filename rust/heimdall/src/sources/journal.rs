//! The firewall's blocks and failed SSH logins from the journal (Go: internal/sources/fwsource): one `journalctl --follow`
//! whose output the daemon's loop reads when the kernel says there is some; the cursor kept in the Go daemon's cursor file
//! (written a second after it moved, and on the way out), so a restart neither reads entries twice nor skips any.

use super::{Msg, Source};
use crate::event::{Event, Fields};
use crate::gojson::{self, FromGo};
use crate::gotime::Time;
use crate::ipintel::{Lists, Origin, Resolver};
use regex::Regex;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const MAX_LINE: usize = 1 << 20;

struct Rx {
    ufw: Regex,
    kv: Regex,
    ssh: Vec<Regex>,
}

fn rx() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| {
        let c = |p: &str| crate::rules::compile(p).expect("static pattern");
        Rx {
            ufw: c(r"\[UFW (BLOCK|LIMIT BLOCK)\]"),
            kv: c(r"\b(IN|SRC|DST|PROTO|SPT|DPT)=(\S*)"),
            ssh: vec![
                c(r"^Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+) port \d+"),
                c(r"^Invalid user (\S*) from (\S+) port \d+"),
                c(r"^Connection (?:closed|reset) by (?:authenticating|invalid) user (\S+) (\S+) port \d+ \[preauth\]"),
                c(r"^error: maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+) port \d+"),
            ],
        }
    })
}

fn sanitize(s: &str) -> String {
    let s: String = s
        .chars()
        .map(|r| {
            let c = r as u32;
            if c < 0x20 || c == 0x7f || (0x202a..=0x202e).contains(&c) || (0x2066..=0x2069).contains(&c) {
                '?'
            } else {
                r
            }
        })
        .collect();
    if s.len() > 32 {
        return format!("{}...", crate::gotext::byte_prefix(&s, 32));
    }
    s
}

#[derive(Default)]
struct Entry {
    message: String,
    ident: String,
    ts: String,
    cursor: String,
}
crate::go_struct!(Entry { message: "MESSAGE", ident: "SYSLOG_IDENTIFIER", ts: "__REALTIME_TIMESTAMP", cursor: "__CURSOR" });

#[derive(Default)]
struct CursorOnly {
    cursor: String,
}
crate::go_struct!(CursorOnly { cursor: "__CURSOR" });

/// Reads journal lines into events, naming where an address belongs.
pub struct Parser {
    pub origins: Option<Resolver>,
    pub threats: Option<Lists>,
}

impl Parser {
    /// One `journalctl -o json` line: the event (if it is a knock) and the cursor.
    pub fn entry(&mut self, line: &[u8]) -> (Option<Event>, String) {
        let Ok(v) = gojson::parse(line) else { return (None, String::new()) };
        let mut e = Entry::default();
        if e.read_into(&v, "").is_err() {
            // MESSAGE as an array of bytes (not UTF-8): only the cursor counts
            let mut c = CursorOnly::default();
            return (None, if c.read_into(&v, "").is_ok() { c.cursor } else { String::new() });
        }
        let mut t = Time::now();
        if let Some(us) = crate::gonet::sscan_int(&e.ts).filter(|u| *u > 0) {
            t = Time::from_unix(us.div_euclid(1_000_000), (us.rem_euclid(1_000_000) * 1000) as u32);
        }
        (self.parse(&e.message, &e.ident, t), e.cursor)
    }

    fn origin(&mut self, ip: &std::net::IpAddr, f: &mut Fields) -> Origin {
        let Some(r) = &mut self.origins else { return Origin { scope: "public".into(), ..Default::default() } };
        let o = r.lookup(ip);
        f.extend(o.fields("origin_"));
        f.insert("origin".into(), o.text());
        if let Some(l) = &mut self.threats {
            let names = l.matching(ip);
            if !names.is_empty() {
                let joined = names.join(",");
                let s = format!("{}; on threat lists: {joined}", f["origin"]);
                f.insert("origin".into(), s);
                f.insert("origin_listed".into(), joined);
            }
        }
        o
    }

    pub fn parse(&mut self, msg: &str, ident: &str, t: Time) -> Option<Event> {
        let rx = rx();
        if rx.ufw.is_match(msg) {
            let mut kv = std::collections::BTreeMap::new();
            for c in rx.kv.captures_iter(msg) {
                kv.insert(c[1].to_string(), c[2].to_string());
            }
            let g = |k: &str| kv.get(k).cloned().unwrap_or_default();
            let ip = crate::gonet::parse_ip(&g("SRC"))?;
            if g("IN").is_empty() {
                return None; // an outgoing packet this computer sent, not a knock
            }
            let src = crate::sources::net::ip_text(&ip);
            let mut f = Fields::from([
                ("src".to_string(), src.clone()),
                ("src_port".to_string(), g("SPT")),
                ("dst_port".to_string(), g("DPT")),
                ("proto".to_string(), g("PROTO")),
                ("iface".to_string(), g("IN")),
                ("spoofable".to_string(), "1".to_string()),
            ]);
            let o = self.origin(&ip, &mut f);
            let port = if g("DPT").is_empty() { "-".to_string() } else { g("DPT") };
            let text = format!("firewall blocked {} {} from {src} ({}) to port {port}", g("PROTO"), g("IN"), o.text());
            return Some(Event {
                source: "host-firewall".into(),
                session_id: String::new(),
                time: t,
                kind: "firewall_block".into(),
                text,
                fields: f,
            });
        }
        if !ident.starts_with("sshd") {
            return None;
        }
        for r in &rx.ssh {
            let Some(c) = r.captures(msg) else { continue };
            let ip = crate::gonet::parse_ip(&c[2])?;
            let src = crate::sources::net::ip_text(&ip);
            let mut f = Fields::from([
                ("src".to_string(), src.clone()),
                ("service".to_string(), "ssh".to_string()),
                ("user".to_string(), sanitize(&c[1])),
            ]);
            let o = self.origin(&ip, &mut f);
            let text = format!("failed SSH login as {} from {src} ({})", crate::gotext::quote(&f["user"]), o.text());
            return Some(Event {
                source: "host-login".into(),
                session_id: String::new(),
                time: t,
                kind: "login_failure".into(),
                text,
                fields: f,
            });
        }
        None
    }
}

/// The follower on the daemon's loop.
pub struct JournalSource {
    pub parser: Parser,
    cursor_path: String,
    journalctl: String,
    restart: Duration,
    child: Option<Child>,
    buf: Vec<u8>,
    at: String,
    saved: String,
    save_at: Option<Instant>,
    start_at: Option<Instant>,
    read: usize,
    last_err: String,
    off: bool,
}

impl JournalSource {
    pub fn new(cursor_path: &str, parser: Parser, restart: Duration) -> JournalSource {
        let at = std::fs::read_to_string(cursor_path)
            .ok()
            .map(|c| crate::gotext::trim_space(&c).to_owned())
            .filter(|c| c.len() <= 512 && !c.contains(['\n', '\0']))
            .unwrap_or_default();
        JournalSource {
            parser,
            cursor_path: cursor_path.into(),
            journalctl: "journalctl".into(),
            restart,
            child: None,
            buf: Vec::new(),
            saved: at.clone(),
            at,
            save_at: None,
            start_at: Some(Instant::now()),
            read: 0,
            last_err: String::new(),
            off: false,
        }
    }

    /// A test or a harness can put a fake journalctl here.
    pub fn with_program(mut self, p: &str) -> Self {
        self.journalctl = p.into();
        self
    }

    fn args(&self) -> Vec<String> {
        let mut a: Vec<String> = [
            "-o",
            "json",
            "--no-pager",
            "-q",
            "--follow",
            "_TRANSPORT=kernel",
            "+",
            "SYSLOG_IDENTIFIER=sshd",
            "_UID=0",
            "+",
            "SYSLOG_IDENTIFIER=sshd-session",
            "_UID=0",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        a.push(if self.at.is_empty() { "--since=-10min".into() } else { format!("--after-cursor={}", self.at) });
        a
    }

    fn save(&mut self, out: &mut Vec<Msg>) {
        self.save_at = None;
        if self.at == self.saved {
            return;
        }
        match crate::state::write_atomic(&self.cursor_path, format!("{}\n", self.at).as_bytes(), 0o600) {
            Ok(()) => self.saved = self.at.clone(),
            Err(e) => out.push(Msg::Log(format!("firewall watch error: {}", super::go_errno(&e)))),
        }
    }

    fn start(&mut self, out: &mut Vec<Msg>) {
        self.start_at = None;
        self.read = 0;
        let spawned = Command::new(&self.journalctl)
            .args(self.args())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        match spawned {
            Ok(c) => {
                if let Some(o) = &c.stdout {
                    let _ = rustix::fs::fcntl_setfl(o, rustix::fs::OFlags::NONBLOCK);
                }
                self.child = Some(c);
            }
            Err(e) => {
                self.ended(super::go_errno(&e), String::new(), out);
            }
        }
    }

    fn ended(&mut self, status: String, stderr: String, out: &mut Vec<Msg>) {
        self.save(out);
        if self.read == 0 && (stderr.contains("No journal files were opened") || stderr.contains("ermission")) {
            self.off = true;
            out.push(Msg::Log(
                "firewall watch unavailable, disabling: cannot read the system journal (add the systemd-journal group, see heimdall-firewall.conf.example)".into(),
            ));
            return;
        }
        let msg = format!(
            "journalctl ended ({status}: {}); following again in {}",
            crate::gotext::trim_space(&stderr),
            crate::gotext::duration(self.restart.as_nanos() as i64)
        );
        if msg != self.last_err {
            out.push(Msg::Log(format!("firewall watch error: {msg}")));
            self.last_err = msg;
        }
        self.start_at = Some(Instant::now() + self.restart);
    }

    fn line(&mut self, line: &[u8], now: Instant, out: &mut Vec<Msg>) {
        self.read += 1;
        let (ev, cursor) = self.parser.entry(line);
        if let Some(e) = ev {
            out.push(Msg::Event(e));
        }
        if !cursor.is_empty() {
            self.at = cursor;
            if self.save_at.is_none() {
                self.save_at = Some(now + Duration::from_secs(1));
            }
        }
    }
}

impl Source for JournalSource {
    fn name(&self) -> &'static str {
        "journal"
    }
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        self.child.as_ref().and_then(|c| c.stdout.as_ref()).map(|o| o.as_fd())
    }
    fn due(&self) -> Option<Instant> {
        if self.off {
            return None;
        }
        match (self.save_at, self.start_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        if self.save_at.is_some_and(|t| now >= t) {
            self.save(out);
        }
        if self.child.is_none() && self.start_at.is_some_and(|t| now >= t) {
            self.start(out);
        }
    }
    fn ready(&mut self, now: Instant, out: &mut Vec<Msg>) {
        let mut chunk = [0u8; 64 << 10];
        let mut eof = false;
        loop {
            let Some(stdout) = self.child.as_mut().and_then(|c| c.stdout.as_mut()) else { return };
            match stdout.read(&mut chunk) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    eof = true;
                    break;
                }
            }
        }
        while let Some(i) = self.buf.iter().position(|&c| c == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=i).collect();
            if line.len() <= MAX_LINE {
                self.line(&line[..line.len() - 1], now, out);
            }
        }
        if self.buf.len() > MAX_LINE {
            self.buf.clear(); // a line longer than any entry: dropped, as Go's scanner gives up on it
        }
        if eof {
            let mut c = self.child.take().expect("following");
            let mut err = String::new();
            if let Some(mut e) = c.stderr.take() {
                let _ = (&mut e).take(4 << 10).read_to_string(&mut err);
            }
            let status = c.wait().map(|s| s.to_string()).unwrap_or_default();
            self.buf.clear();
            self.ended(status, err, out);
        }
    }
    fn stop(&mut self, out: &mut Vec<Msg>) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.save(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_knocks_and_logins_like_go() {
        let mut p = Parser { origins: None, threats: None };
        let ufw = r#"{"MESSAGE":"[UFW BLOCK] IN=wlan0 OUT= MAC=x SRC=203.0.113.9 DST=192.168.1.2 LEN=60 PROTO=TCP SPT=51515 DPT=22 WINDOW=1","SYSLOG_IDENTIFIER":"kernel","__REALTIME_TIMESTAMP":"1762000000123456","__CURSOR":"s=abc"}"#;
        let (e, c) = p.entry(ufw.as_bytes());
        let e = e.unwrap();
        assert_eq!(c, "s=abc");
        assert_eq!((e.kind.as_str(), e.f("src"), e.f("dst_port"), e.f("iface")), ("firewall_block", "203.0.113.9", "22", "wlan0"));
        assert_eq!(e.time.rfc3339_nano(), "2025-11-01T12:26:40.123456Z");
        let out = r#"{"MESSAGE":"[UFW BLOCK] IN= OUT=wlan0 SRC=192.168.1.2 DST=203.0.113.9","__CURSOR":"s=b"}"#;
        assert!(p.entry(out.as_bytes()).0.is_none(), "an outgoing packet is not a knock");
        let ssh = "{\"MESSAGE\":\"Failed password for invalid user r\u{202e}oot\\u0001xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx from 198.51.100.7 port 4242 ssh2\",\"SYSLOG_IDENTIFIER\":\"sshd-session\",\"__CURSOR\":\"s=c\"}";
        let e = p.entry(ssh.as_bytes()).0.unwrap();
        assert_eq!(e.kind, "login_failure");
        assert!(e.f("user").starts_with("r?oot?") && e.f("user").ends_with("..."), "{}", e.f("user"));
        let bytes = r#"{"MESSAGE":[1,2,3],"__CURSOR":"s=d"}"#;
        assert_eq!(p.entry(bytes.as_bytes()), (None, "s=d".to_string()));
    }
}
