//! The loopback API (Go: internal/api): a thread of its own with a plain HTTP/1.1 server over std's TcpListener (one request
//! per connection, no async). Guards as Go's: only a loopback Host and no browser headers (Origin, Sec-Fetch-Site); every
//! endpoint but /healthz only for the accounts `Access` allows, identified by the kernel from /proc/net/tcp{,6}.
//!
//! Served: GET /healthz, GET /v1/alerts?n=N, POST /v1/review (governance), GET /v1/incidents, GET and POST /v1/requests
//! (grants). Not yet (404 here; the Go daemon serves them until the switch): /v1/audit, /v1/lan/devices, /v1/quarantine,
//! /v1/rules/drafts. Alerts the API raises (reviews, grant requests) go to the daemon's loop as messages, so they pass the
//! correlator and every output like any other alert. Shadow mode serves no API.

use crate::alert::{Alert, Ring};
use crate::correlate;
use crate::event::{Event, Finding, Severity};
use crate::governance::{Request as ReviewRequest, Reviewer};
use crate::gojson::{self, FromGo};
use crate::gotime::Time;
use crate::grants;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One request, as far as the handlers need it.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub method: String,
    /// The path without the query.
    pub path: String,
    pub query: String,
    pub host: String,
    /// Header names in lowercase.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    /// The body was larger than the endpoint's limit (Go: MaxBytesReader).
    pub too_large: bool,
}

/// One answer.
#[derive(Clone, Debug, PartialEq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

fn text(status: u16, msg: &str) -> Response {
    // Go's http.Error: the message and a newline, as plain text
    Response { status, content_type: "text/plain; charset=utf-8", body: format!("{msg}\n") }
}

fn json(body: String) -> Response {
    Response { status: 200, content_type: "application/json", body: body + "\n" }
}

/// A Host header naming this computer's loopback (127.0.0.1, ::1 or localhost, any port).
pub fn loopback_host(host: &str) -> bool {
    let h = match crate::gonet::split_host_port(host) {
        Some((h, _)) => h,
        None => host,
    };
    let h = h.trim_matches(|c| c == '[' || c == ']');
    if h == "localhost" {
        return true;
    }
    crate::gonet::parse_ip(h).is_some_and(|ip| ip.is_loopback() || matches!(ip, IpAddr::V6(v) if v.to_ipv4_mapped().is_some_and(|x| x.is_loopback())))
}

/// Which local accounts may use the API: root, Heimdall's own account, `users`, and members of `groups`.
pub struct Access {
    pub users: Vec<String>,
    pub groups: Vec<String>,
    /// The account database (tests: a made-up one).
    pub passwd: String,
    pub group: String,
    /// The kernel's socket tables.
    pub proc_tcp: Vec<String>,
    cache: Mutex<HashMap<u32, (bool, Instant)>>,
}

const CACHE_FOR: Duration = Duration::from_secs(60);

impl Access {
    pub fn new(users: Vec<String>, groups: Vec<String>) -> Access {
        Access {
            users,
            groups,
            passwd: "/etc/passwd".into(),
            group: "/etc/group".into(),
            proc_tcp: vec!["/proc/net/tcp".into(), "/proc/net/tcp6".into()],
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The account that owns the client end of a loopback connection: the socket whose local end is the client's address
    /// and whose remote end is the server's.
    pub fn peer_uid(&self, client: SocketAddr, server: SocketAddr) -> Result<u32, String> {
        let canon = |ip: IpAddr| ip.to_canonical();
        for path in &self.proc_tcp {
            let Ok(text) = std::fs::read_to_string(path) else { continue };
            for s in crate::sources::net::parse_proc_net(&text) {
                if s.local_port == client.port()
                    && s.remote_port == server.port()
                    && canon(s.local) == canon(client.ip())
                    && canon(s.remote) == canon(server.ip())
                {
                    return Ok(s.uid as u32);
                }
            }
        }
        Err(format!("no socket for {}:{} in the kernel's table", client.ip(), client.port()))
    }

    /// Whether `uid` may use the API (the answer about an account is kept a minute).
    pub fn allowed(&self, uid: u32) -> bool {
        // SAFETY: getuid has no preconditions.
        if uid == 0 || uid == unsafe { libc::getuid() } {
            return true;
        }
        let mut c = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((ok, when)) = c.get(&uid) {
            if when.elapsed() < CACHE_FOR {
                return *ok;
            }
        }
        let ok = self.member(uid);
        c.insert(uid, (ok, Instant::now()));
        ok
    }

    /// The account database's answer (Go: os/user, pure Go: /etc/passwd and /etc/group).
    fn member(&self, uid: u32) -> bool {
        let Ok(pw) = std::fs::read_to_string(&self.passwd) else { return false };
        let Some((name, gid)) = pw.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 4 && f[2].parse::<u32>().ok() == Some(uid)).then(|| (f[0].to_string(), f[3].to_string()))
        }) else {
            return false;
        };
        if self.users.contains(&name) {
            return true;
        }
        if self.groups.is_empty() {
            return false;
        }
        let Ok(gr) = std::fs::read_to_string(&self.group) else { return false };
        for want in &self.groups {
            for l in gr.lines() {
                let f: Vec<&str> = l.split(':').collect();
                if f.len() >= 4 && f[0] == want && (f[2] == gid || f[3].split(',').any(|m| m == name)) {
                    return true;
                }
            }
        }
        false
    }
}

/// What the API reads and where its alerts go.
pub struct Api {
    pub ring: Arc<Mutex<Ring>>,
    pub incidents: Arc<Mutex<correlate::State>>,
    pub reviewer: Option<Mutex<Reviewer>>,
    pub grants: Option<grants::Store>,
    pub access: Option<Access>,
    /// Alerts for the daemon's loop.
    pub alerts: Box<dyn Fn(Alert) + Send + Sync>,
}

impl Api {
    /// Answers one request from `peer` (the account behind it, or why it could not be found).
    pub fn handle(&self, r: &Request, peer: Result<u32, String>) -> Response {
        if !loopback_host(&r.host) || r.headers.contains_key("origin") || r.headers.contains_key("sec-fetch-site") {
            return text(403, "forbidden");
        }
        let mut uid = None;
        if let Some(a) = &self.access {
            if r.path != "/healthz" {
                match peer {
                    Ok(u) if a.allowed(u) => uid = Some(u),
                    _ => return text(403, "forbidden: this account may not use Heimdall's API (api_users, api_groups)"),
                }
            }
        }
        match r.path.as_str() {
            "/healthz" => Response { status: 200, content_type: "text/plain; charset=utf-8", body: "ok\n".into() },
            "/v1/alerts" => self.alerts_list(r),
            "/v1/review" => self.review(r),
            "/v1/incidents" => {
                let mut b = String::from("[");
                for (i, inc) in self.incidents.lock().unwrap_or_else(|p| p.into_inner()).incidents().iter().enumerate() {
                    if i > 0 {
                        b.push(',');
                    }
                    inc.to_json(&mut b);
                }
                b.push(']');
                json(b)
            }
            "/v1/requests" if self.grants.is_some() => self.requests(r, uid.unwrap_or(0)),
            _ => text(404, "404 page not found"),
        }
    }

    fn alerts_list(&self, r: &Request) -> Response {
        let mut n: i64 = 50;
        if let Some(raw) = query_get(&r.query, "n") {
            if let Some(p) = crate::gotext::atoi(&raw) {
                if p > 0 {
                    n = p;
                }
            }
        }
        let n = n.min(500);
        let recent = self.ring.lock().unwrap_or_else(|p| p.into_inner()).recent(n);
        let mut b = String::from("[");
        for (i, a) in recent.iter().enumerate() {
            if i > 0 {
                b.push(',');
            }
            b.push_str(&a.to_json());
        }
        b.push(']');
        json(b)
    }

    fn review(&self, r: &Request) -> Response {
        if r.method != "POST" {
            return text(405, "method not allowed, use POST");
        }
        let Some(rev) = &self.reviewer else { return text(503, "governance review is not enabled on this server") };
        if r.too_large {
            return text(400, "invalid request body: http: request body too large");
        }
        let req = match gojson::parse_first(&r.body).and_then(|v| {
            let mut q = ReviewRequest::default();
            q.read_into(&v, "").map(|_| q)
        }) {
            Ok(q) => q,
            Err(e) => return text(400, &format!("invalid request body: {e}")),
        };
        if req.text.is_empty() {
            return text(400, "text is required");
        }
        let mut alerts = Vec::new();
        let mut collect = Collect(&mut alerts);
        let v = rev.lock().unwrap_or_else(|p| p.into_inner()).review(&req, Some(&mut collect));
        for a in alerts {
            (self.alerts)(a);
        }
        json(v.to_json())
    }

    fn requests(&self, r: &Request, uid: u32) -> Response {
        let st = self.grants.as_ref().expect("checked");
        match r.method.as_str() {
            "GET" => {
                let pending = match st.pending() {
                    Ok(p) => p,
                    Err(e) => return text(500, &e),
                };
                let (decisions, on) = st.load();
                let mut b = String::from("{\"decisions\":");
                decisions.write_json(&mut b);
                b.push_str(",\"gate_on\":");
                b.push_str(if on { "true" } else { "false" });
                b.push_str(",\"pending\":");
                // Go's Sorted copies into a nil slice: no requests, or an empty list, is written null
                let sorted = pending.as_deref().map(grants::sorted).filter(|s| !s.is_empty());
                grants::requests_json(sorted.as_deref(), &mut b);
                b.push('}');
                json(b)
            }
            "POST" => {
                if r.too_large {
                    return text(400, "invalid request body: http: request body too large");
                }
                let mut req = match gojson::parse_first(&r.body).and_then(|v| {
                    let mut q = grants::Request::default();
                    q.read_into(&v, "").map(|_| q)
                }) {
                    Ok(q) => q,
                    Err(e) => return text(400, &format!("invalid request body: {e}")),
                };
                req.id.clear();
                req.count = 0;
                req.uid = uid; // the kernel's word, never the body's
                let filed = match st.file(req, Time::now()) {
                    Ok(f) => f,
                    Err(e) => return text(400, &e),
                };
                let approve = format!("sudo heimdalld grant approve {}", filed.id);
                let what = if filed.kind == grants::KIND_ACCESS_TIER {
                    format!("access tier {}", filed.detail)
                } else {
                    format!("handing the conversation to the model tier {}", filed.detail)
                };
                let ev = Event {
                    source: "governance-request".into(),
                    kind: "grant_request".into(),
                    session_id: filed.session_id.clone(),
                    time: Time::now(),
                    text: filed.reason.clone(),
                    fields: [
                        ("request_id", filed.id.clone()),
                        ("kind", filed.kind.clone()),
                        ("detail", filed.detail.clone()),
                        ("uid", filed.uid.to_string()),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                };
                let summary = format!("an AI agent asks for {what}; only you can allow it: {approve} (or deny)");
                (self.alerts)(Alert::from_finding(&Finding::new("grant-request", Severity::Warning, summary, &ev)));
                let mut b = String::new();
                let mut o = gojson::ObjectWriter::new(&mut b);
                o.str("approve", &approve);
                o.raw("count", &filed.count.to_string());
                o.str("id", &filed.id);
                o.str("status", grants::STATUS_PENDING);
                o.end();
                json(b)
            }
            _ => text(405, "method not allowed"),
        }
    }
}

struct Collect<'a>(&'a mut Vec<Alert>);
impl crate::alert::Sink for Collect<'_> {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        self.0.push(a.clone());
        Ok(())
    }
}

/// The first value of a query parameter, percent-decoded (Go: URL.Query().Get).
pub fn query_get(query: &str, key: &str) -> Option<String> {
    for part in query.split('&') {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        if unescape(k)? == key {
            return unescape(v);
        }
    }
    None
}

fn unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    Some(crate::gotext::lossy(&out))
}

/// The body limit of an endpoint (Go: MaxBytesReader).
fn limit(path: &str) -> usize {
    match path {
        "/v1/review" => 64 * 1024,
        "/v1/requests" => 8 * 1024,
        "/v1/rules/drafts" => 32 * 1024,
        _ => 64 * 1024,
    }
}

/// Reads one request from a connection: the head (at most 16 KiB) and a Content-Length body.
pub fn read_request(s: &mut impl Read) -> Result<Request, (u16, &'static str)> {
    let mut buf = Vec::with_capacity(1024);
    let mut b = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 16 * 1024 {
            return Err((431, "Request Header Fields Too Large"));
        }
        match s.read(&mut b) {
            Ok(0) | Err(_) => return Err((400, "Bad Request")),
            Ok(n) => buf.extend_from_slice(&b[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(proto)) = (parts.next(), parts.next(), parts.next()) else { return Err((400, "Bad Request")) };
    if !proto.starts_with("HTTP/1.") {
        return Err((505, "HTTP Version Not Supported"));
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut r = Request { method: method.into(), path: path.into(), query: query.into(), ..Default::default() };
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            r.headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    r.host = r.headers.get("host").cloned().unwrap_or_default();
    if r.headers.get("transfer-encoding").is_some_and(|t| !t.eq_ignore_ascii_case("identity")) {
        return Err((411, "Length Required")); // Heimdall's clients send a length
    }
    let len: usize = match r.headers.get("content-length") {
        Some(v) => v.parse().map_err(|_| (400, "Bad Request"))?,
        None => 0,
    };
    let max = limit(&r.path);
    let mut body = buf[end + 4..].to_vec();
    let want = len.min(max + 1);
    while body.len() < want {
        match s.read(&mut b) {
            Ok(0) | Err(_) => return Err((400, "Bad Request")),
            Ok(n) => body.extend_from_slice(&b[..n]),
        }
    }
    body.truncate(want);
    if len > max {
        r.too_large = true;
        body.truncate(max);
    }
    r.body = body;
    Ok(r)
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

fn write_response(s: &mut TcpStream, resp: &Response) {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        resp.status,
        reason(resp.status),
        resp.content_type,
        resp.body.len()
    );
    if resp.content_type.starts_with("text/plain") && resp.status != 200 {
        head.push_str("X-Content-Type-Options: nosniff\r\n");
    }
    head.push_str("\r\n");
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(resp.body.as_bytes());
}

/// Binds `addr` (loopback only, as Go's ListenAndServeLoopback) and serves on a thread of its own; returns the address bound.
pub fn serve(addr: &str, api: Api) -> std::io::Result<SocketAddr> {
    let (host, _) = crate::gonet::split_host_port(addr)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("address {addr}: missing port in address")))?;
    let loopback = host == "localhost" || crate::gonet::parse_ip(host).is_some_and(|ip| ip.is_loopback());
    if !loopback {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("address {addr}: heimdalld: api_addr must be a loopback address"),
        ));
    }
    let l = TcpListener::bind(addr)?;
    let bound = l.local_addr()?;
    let _ = std::thread::Builder::new().name("api".into()).spawn(move || {
        for conn in l.incoming() {
            let Ok(mut s) = conn else { continue };
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
            let resp = match read_request(&mut s) {
                Ok(r) => {
                    let peer = match (s.peer_addr(), s.local_addr(), &api.access) {
                        (Ok(p), Ok(l), Some(a)) => a.peer_uid(p, l),
                        _ => Err("no address".into()),
                    };
                    api.handle(&r, peer)
                }
                Err((code, msg)) => text(code, msg),
            };
            write_response(&mut s, &resp);
        }
    })?;
    Ok(bound)
}
