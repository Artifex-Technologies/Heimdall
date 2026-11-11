//! A small HTTP/1.1 client over plain TCP or TLS (rustls with the system's certificate authorities, read from the files Go's
//! crypto/x509 and OpenSSL read), for what the Wi-Fi checks ask of the network: the device count from Heimdall's own API,
//! the speed test's download, the well-known pages and certificates of the Wi-Fi safety check. One request per
//! connection. Failures carry the words Go and Python's OpenSSL give them, since the reports quote them.

use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Why a request failed.
#[derive(Clone, Debug, PartialEq)]
pub enum NetError {
    /// the name did not resolve
    NoHost,
    Refused,
    Timeout,
    Reset,
    /// the connection closed early
    Eof,
    /// the certificate was refused: Go's words (after its last ": ") and OpenSSL's verify message
    Cert {
        go: String,
        openssl: String,
    },
    /// another TLS failure (no shared version, a bad record, ...)
    Tls(String),
    /// the address is not a URL this client reads
    BadUrl,
    Other(String),
}

impl NetError {
    /// The end of Go's error text (what wifihealth's `shortErr` keeps).
    pub fn go_short(&self) -> String {
        match self {
            NetError::NoHost => "no such host".into(),
            NetError::Refused => "connection refused".into(),
            NetError::Timeout => "context deadline exceeded".into(),
            NetError::Reset => "connection reset by peer".into(),
            NetError::Eof => "EOF".into(),
            NetError::Cert { go, .. } => go.clone(),
            NetError::Tls(s) | NetError::Other(s) => s.clone(),
            NetError::BadUrl => "unsupported protocol scheme".into(),
        }
    }
}

fn io_err(e: &std::io::Error) -> NetError {
    use std::io::ErrorKind::*;
    if let Some(t) = e.get_ref().and_then(|x| x.downcast_ref::<rustls::Error>()) {
        return tls_err(t);
    }
    match e.kind() {
        ConnectionRefused => NetError::Refused,
        TimedOut | WouldBlock => NetError::Timeout,
        ConnectionReset | ConnectionAborted | BrokenPipe => NetError::Reset,
        UnexpectedEof => NetError::Eof,
        _ => NetError::Other(crate::goerr::text(e)),
    }
}

fn tls_err(e: &rustls::Error) -> NetError {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => {
            let (go, openssl) = match c {
                C::UnknownIssuer | C::BadSignature | C::UnhandledCriticalExtension => {
                    ("certificate signed by unknown authority".to_string(), String::new())
                }
                C::NotValidForNameContext { expected, presented } => {
                    let names: Vec<String> = presented
                        .iter()
                        .filter_map(|p| p.strip_prefix("DnsName(\"").and_then(|x| x.strip_suffix("\")")).map(str::to_string))
                        .collect();
                    let host = expected.to_str().into_owned();
                    let go = if names.is_empty() {
                        format!("certificate is not valid for any names, but wanted to match {host}")
                    } else {
                        format!("certificate is valid for {}, not {host}", names.join(", "))
                    };
                    (go, format!("Hostname mismatch, certificate is not valid for '{host}'."))
                }
                C::NotValidForName => ("certificate is not valid for this name".into(), "Hostname mismatch".into()),
                C::ExpiredContext { time, not_after } => (
                    format!("current time {} is after {}", rfc3339(time.as_secs()), rfc3339(not_after.as_secs())),
                    "certificate has expired".into(),
                ),
                C::Expired => ("certificate has expired or is not yet valid".into(), "certificate has expired".into()),
                C::NotValidYetContext { time, not_before } => (
                    format!("current time {} is before {}", rfc3339(time.as_secs()), rfc3339(not_before.as_secs())),
                    "certificate is not yet valid".into(),
                ),
                C::NotValidYet => ("certificate has expired or is not yet valid".into(), "certificate is not yet valid".into()),
                C::Revoked => ("certificate revoked".into(), "certificate revoked".into()),
                other => (format!("{other:?}"), "certificate verify failed".into()),
            };
            NetError::Cert { go, openssl }
        }
        other => NetError::Tls(other.to_string()),
    }
}

fn rfc3339(secs: u64) -> String {
    crate::gotime::Time::from_unix(secs as i64, 0).utc().rfc3339_nano()
}

/// The system's certificate authorities: the first bundle found (SSL_CERT_FILE, else Go's list, which includes Arch's),
/// and every file in the folders (SSL_CERT_DIR, else /etc/ssl/certs and /etc/pki/tls/certs), as Go loads them.
pub fn roots() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    let files: Vec<String> = match std::env::var("SSL_CERT_FILE") {
        Ok(f) if !f.is_empty() => vec![f],
        _ => [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/pki/tls/cacert.pem",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            "/etc/ssl/cert.pem",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    };
    let mut add = |data: &[u8]| {
        for c in CertificateDer::pem_slice_iter(data).flatten() {
            let _ = store.add(c);
        }
    };
    for f in files {
        if let Ok(b) = std::fs::read(&f) {
            add(&b);
            break;
        }
    }
    let dirs: Vec<String> = match std::env::var("SSL_CERT_DIR") {
        Ok(d) if !d.is_empty() => d.split(':').map(str::to_string).collect(),
        _ => vec!["/etc/ssl/certs".into(), "/etc/pki/tls/certs".into()],
    };
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        let mut names: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        names.sort();
        for p in names {
            if let Ok(b) = std::fs::read(&p) {
                add(&b);
            }
        }
    }
    store
}

/// TLS 1.3 and 1.2 (as Go's client and OpenSSL's default offer), ring's crypto, the system's authorities.
pub fn tls_config() -> Arc<rustls::ClientConfig> {
    static C: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    C.get_or_init(|| {
        let p = Arc::new(rustls::crypto::ring::default_provider());
        let c = rustls::ClientConfig::builder_with_provider(p)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("TLS versions")
            .with_root_certificates(roots())
            .with_no_client_auth();
        Arc::new(c)
    })
    .clone()
}

/// The addresses of `host` (getaddrinfo, as Go's resolver on this system and Python's socket module ask it).
pub fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, NetError> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    (h, port).to_socket_addrs().map(|a| a.collect()).map_err(|_| NetError::NoHost)
}

/// Connects to the first address that answers, each try limited to `per_try` and all to `deadline`.
pub fn dial(host: &str, port: u16, per_try: Duration, deadline: Instant) -> Result<TcpStream, NetError> {
    let addrs = resolve(host, port)?;
    if addrs.is_empty() {
        return Err(NetError::NoHost);
    }
    let mut last = NetError::Refused;
    for a in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(NetError::Timeout);
        }
        match TcpStream::connect_timeout(&a, left.min(per_try)) {
            Ok(s) => return Ok(s),
            Err(e) => last = io_err(&e),
        }
    }
    Err(last)
}

/// A connection, plain or TLS.
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Conn {
    fn tcp(&self) -> &TcpStream {
        match self {
            Conn::Plain(t) => t,
            Conn::Tls(s) => &s.sock,
        }
    }
    /// Each read and write waits at most until `deadline` (and at most `per_op`, when given).
    pub fn limit(&self, deadline: Instant, per_op: Option<Duration>) -> Result<(), NetError> {
        let mut left = deadline.saturating_duration_since(Instant::now());
        if let Some(p) = per_op {
            left = left.min(p);
        }
        if left.is_zero() {
            return Err(NetError::Timeout);
        }
        let _ = self.tcp().set_read_timeout(Some(left));
        let _ = self.tcp().set_write_timeout(Some(left));
        Ok(())
    }
}

impl Read for Conn {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(t) => t.read(b),
            Conn::Tls(s) => s.read(b),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(t) => t.write(b),
            Conn::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(t) => t.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// The TLS handshake with `host`'s certificate checked; the connection, or why it was refused.
pub fn handshake(tcp: TcpStream, host: &str, deadline: Instant, per_op: Option<Duration>) -> Result<Conn, NetError> {
    let name = ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']').to_string()).map_err(|_| NetError::BadUrl)?;
    let conn = rustls::ClientConnection::new(tls_config(), name).map_err(|e| tls_err(&e))?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    let mut left = deadline.saturating_duration_since(Instant::now());
    if let Some(p) = per_op {
        left = left.min(p);
    }
    if left.is_zero() {
        return Err(NetError::Timeout);
    }
    let _ = s.sock.set_read_timeout(Some(left));
    let _ = s.sock.set_write_timeout(Some(left));
    while s.conn.is_handshaking() {
        if let Err(e) = s.conn.complete_io(&mut s.sock) {
            return Err(io_err(&e));
        }
    }
    Ok(Conn::Tls(Box::new(s)))
}

/// A URL this client reads: http or https, a host, an optional port, the path with its query.
#[derive(Clone, Debug, PartialEq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// host[:port] as written (the Host header)
    pub authority: String,
    pub path: String,
}

pub fn parse_url(u: &str) -> Option<Url> {
    let (https, rest) = if let Some(r) = u.strip_prefix("https://") { (true, r) } else { (false, u.strip_prefix("http://")?) };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let mut path = rest[end..].split('#').next().unwrap_or("").to_string();
    if path.is_empty() || path.starts_with('?') {
        path.insert(0, '/');
    }
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let close = stripped.find(']')?;
        let host = &authority[..close + 2];
        let port = &authority[close + 2..];
        (host.to_string(), port.strip_prefix(':').map(|p| p.parse().ok()).unwrap_or(Some(if https { 443 } else { 80 }))?)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                if p.is_empty() {
                    if https {
                        443
                    } else {
                        80
                    }
                } else {
                    p.parse().ok()?
                },
            ),
            None => (authority.to_string(), if https { 443 } else { 80 }),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(Url { https, host, port, authority: authority.to_string(), path })
}

/// `base` joined with a Location value (absolute, or relative to `base`).
pub fn join(base: &Url, loc: &str) -> Option<Url> {
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return parse_url(loc);
    }
    let scheme = if base.https { "https" } else { "http" };
    if let Some(r) = loc.strip_prefix("//") {
        return parse_url(&format!("{scheme}://{r}"));
    }
    if loc.contains("://") {
        return None;
    }
    let path = if loc.starts_with('/') {
        loc.to_string()
    } else {
        let dir = base.path.split('?').next().unwrap_or("/");
        let dir = &dir[..dir.rfind('/').map(|i| i + 1).unwrap_or(0)];
        format!("{dir}{loc}")
    };
    parse_url(&format!("{scheme}://{}{path}", base.authority))
}

/// One response: the status, the headers, and the body as it arrives.
pub struct Response {
    pub status: u16,
    /// Go's `resp.Status`: "404 Not Found"
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    body: Body,
    conn: Conn,
    buf: Vec<u8>,
}

enum Body {
    Length(u64),
    Chunked { left: u64, done: bool },
    Close,
    Empty,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Reads body bytes (0 at the end), each read waiting until `deadline` at most.
    pub fn read_body(&mut self, out: &mut [u8], deadline: Instant, per_op: Option<Duration>) -> Result<usize, NetError> {
        loop {
            match &mut self.body {
                Body::Empty => return Ok(0),
                Body::Length(0) => return Ok(0),
                Body::Chunked { done: true, .. } => return Ok(0),
                Body::Chunked { left, done } if *left == 0 => {
                    let line = read_line(&mut self.conn, &mut self.buf, deadline, per_op)?;
                    let line = if line.is_empty() { read_line(&mut self.conn, &mut self.buf, deadline, per_op)? } else { line };
                    let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                        .map_err(|_| NetError::Other("malformed chunked encoding".into()))?;
                    if size == 0 {
                        *done = true;
                        return Ok(0);
                    }
                    *left = size;
                }
                _ => break,
            }
        }
        let want = match &self.body {
            Body::Length(n) => (*n).min(out.len() as u64) as usize,
            Body::Chunked { left, .. } => (*left).min(out.len() as u64) as usize,
            _ => out.len(),
        };
        let n = if !self.buf.is_empty() {
            let n = want.min(self.buf.len());
            out[..n].copy_from_slice(&self.buf[..n]);
            self.buf.drain(..n);
            n
        } else {
            self.conn.limit(deadline, per_op)?;
            match self.conn.read(&mut out[..want]) {
                Ok(n) => n,
                // a TLS server that closes without notice ends a body read to the close (Go reads it as the end too)
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && matches!(self.body, Body::Close) => 0,
                Err(e) => return Err(io_err(&e)),
            }
        };
        match &mut self.body {
            Body::Length(left) | Body::Chunked { left, .. } => {
                if n == 0 {
                    return Err(NetError::Other("unexpected EOF".into()));
                }
                *left -= n as u64;
            }
            _ => {}
        }
        Ok(n)
    }

    /// The whole body, up to `limit` bytes.
    pub fn read_all(&mut self, limit: usize, deadline: Instant, per_op: Option<Duration>) -> Result<Vec<u8>, NetError> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 16 << 10];
        while out.len() < limit {
            let take = buf.len().min(limit - out.len());
            let n = self.read_body(&mut buf[..take], deadline, per_op)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        Ok(out)
    }
}

fn read_line(c: &mut Conn, buf: &mut Vec<u8>, deadline: Instant, per_op: Option<Duration>) -> Result<String, NetError> {
    loop {
        if let Some(i) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=i).collect();
            let s = String::from_utf8_lossy(&line);
            return Ok(s.trim_end_matches(['\r', '\n']).to_string());
        }
        if buf.len() > 1 << 20 {
            return Err(NetError::Other("header too long".into()));
        }
        c.limit(deadline, per_op)?;
        let mut tmp = [0u8; 4096];
        let n = c.read(&mut tmp).map_err(|e| io_err(&e))?;
        if n == 0 {
            return Err(NetError::Eof);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Sends one GET (no redirects followed) and reads the status and headers.
pub fn get(url: &Url, headers: &[(&str, &str)], deadline: Instant, per_op: Option<Duration>) -> Result<Response, NetError> {
    let per_try = per_op.unwrap_or(Duration::from_secs(3600));
    let tcp = dial(&url.host, url.port, per_try, deadline)?;
    let mut conn = if url.https { handshake(tcp, &url.host, deadline, per_op)? } else { Conn::Plain(tcp) };
    let mut req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n", url.path, url.authority);
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    conn.limit(deadline, per_op)?;
    conn.write_all(req.as_bytes()).map_err(|e| io_err(&e))?;
    let _ = conn.flush();
    let mut buf = Vec::new();
    let status_line = loop {
        let l = read_line(&mut conn, &mut buf, deadline, per_op)?;
        if !l.is_empty() {
            break l;
        }
    };
    let mut parts = status_line.splitn(3, ' ');
    let proto = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/") {
        return Err(NetError::Other("malformed HTTP response".into()));
    }
    let code_s = parts.next().unwrap_or("");
    let status: u16 = code_s.parse().map_err(|_| NetError::Other("malformed HTTP status code".into()))?;
    let reason = parts.next().unwrap_or("");
    let status_text = if reason.is_empty() { code_s.to_string() } else { format!("{code_s} {reason}") };
    let mut hs = Vec::new();
    loop {
        let l = read_line(&mut conn, &mut buf, deadline, per_op)?;
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            hs.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let te = hs.iter().any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
    let cl = hs.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse::<u64>().ok());
    let body = if status == 204 || status == 304 || (100..200).contains(&status) {
        Body::Empty
    } else if te {
        Body::Chunked { left: 0, done: false }
    } else if let Some(n) = cl {
        Body::Length(n)
    } else {
        Body::Close
    };
    Ok(Response { status, status_text, headers: hs, body, conn, buf })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("https://mirror.example:8443/archlinux/iso/latest/x.iso?a=1#f").unwrap();
        assert_eq!(
            (u.https, u.host.as_str(), u.port, u.authority.as_str(), u.path.as_str()),
            (true, "mirror.example", 8443, "mirror.example:8443", "/archlinux/iso/latest/x.iso?a=1")
        );
        let u = parse_url("http://127.0.0.1:8930/v1/lan/devices").unwrap();
        assert_eq!((u.port, u.path.as_str()), (8930, "/v1/lan/devices"));
        assert_eq!(parse_url("http://[::1]:80/x").unwrap().host, "[::1]");
        assert!(parse_url("ftp://x/").is_none());
        let b = parse_url("http://a.example/dir/page?x").unwrap();
        assert_eq!(join(&b, "other").unwrap().path, "/dir/other");
        assert_eq!(join(&b, "/top").unwrap().path, "/top");
        assert_eq!(join(&b, "https://b.example/").unwrap().host, "b.example");
        assert_eq!(join(&b, "//c.example/p").unwrap().host, "c.example");
    }
}
