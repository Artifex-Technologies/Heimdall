//! heimdall-wifi-check's questions to the network, asked as its Python asks them: connections as
//! `socket.create_connection` makes them (getaddrinfo's order, 8 seconds per attempt and per operation), certificates checked
//! against the authorities OpenSSL reads with a refusal worded as OpenSSL words it, the plain web pages fetched as `urllib`
//! fetches them (its request, its redirects and their limits, `read(4096)`), and the other devices' announcements heard
//! (nothing is sent).

use super::addr;
use super::der;
use super::py;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Python's timeout for each connection and each operation on it.
pub const TIMEOUT: Duration = Duration::from_secs(8);

/// `socket.create_connection((host, port), timeout)`: every address getaddrinfo gives, in its order, until one connects.
pub fn create_connection(host: &str, port: u16, timeout: Duration) -> Option<TcpStream> {
    let addrs: Vec<SocketAddr> = addr::getaddrinfo_sock(host, &port.to_string(), 0, libc::SOCK_STREAM, 0).ok()?;
    for a in addrs {
        if let Ok(s) = TcpStream::connect_timeout(&a, timeout) {
            let _ = s.set_read_timeout(Some(timeout));
            let _ = s.set_write_timeout(Some(timeout));
            return Some(s);
        }
    }
    None
}

// ---- certificates

/// The authorities Python's `ssl.create_default_context()` trusts: OpenSSL's default file ($SSL_CERT_FILE, else the
/// cert.pem of its folder: /etc/ssl on Arch, /usr/lib/ssl on Debian and Ubuntu) and the certificates its default folder
/// holds under their hashed names ($SSL_CERT_DIR, else certs/ beside the file).
pub fn roots() -> Arc<rustls::RootCertStore> {
    static R: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
    R.get_or_init(|| {
        let mut store = rustls::RootCertStore::empty();
        let mut add = |data: &[u8]| {
            for c in CertificateDer::pem_slice_iter(data).flatten() {
                let _ = store.add(c);
            }
        };
        match std::env::var_os("SSL_CERT_FILE") {
            Some(f) => {
                if let Ok(b) = std::fs::read(f) {
                    add(&b);
                }
            }
            None => {
                for f in ["/etc/ssl/cert.pem", "/usr/lib/ssl/cert.pem", "/etc/pki/tls/cert.pem"] {
                    if let Ok(b) = std::fs::read(f) {
                        add(&b);
                        break;
                    }
                }
            }
        }
        let dirs: Vec<std::path::PathBuf> = match std::env::var_os("SSL_CERT_DIR") {
            Some(d) => std::env::split_paths(&d).collect(),
            None => ["/etc/ssl/certs", "/usr/lib/ssl/certs", "/etc/pki/tls/certs"]
                .iter()
                .map(std::path::PathBuf::from)
                .filter(|p| p.is_dir())
                .take(1)
                .collect(),
        };
        for d in dirs {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            let mut names: Vec<_> = rd.flatten().map(|e| e.path()).collect();
            names.sort();
            for p in names {
                let n = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                let hashed = n.len() > 9
                    && n.as_bytes()[8] == b'.'
                    && n[..8].bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                    && n[9..].bytes().all(|c| c.is_ascii_digit());
                if hashed {
                    if let Ok(b) = std::fs::read(&p) {
                        add(&b);
                    }
                }
            }
        }
        Arc::new(store)
    })
    .clone()
}

/// A verifier that does what rustls's does and, on a refusal, keeps OpenSSL's words for it.
#[derive(Debug)]
struct Worded {
    inner: Option<Arc<rustls::client::WebPkiServerVerifier>>,
    host: String,
    words: Mutex<Option<String>>,
}

fn verifier(roots: Arc<rustls::RootCertStore>) -> Option<Arc<rustls::client::WebPkiServerVerifier>> {
    let p = Arc::new(rustls::crypto::ring::default_provider());
    rustls::client::WebPkiServerVerifier::builder_with_provider(roots, p).build().ok()
}

fn cert_err(e: &rustls::Error) -> Option<&rustls::CertificateError> {
    match e {
        rustls::Error::InvalidCertificate(c) => Some(c),
        _ => None,
    }
}

impl Worded {
    /// OpenSSL's verify message for the refused chain: trust is decided first (an untrusted chain is "self-signed ..." or
    /// "unable to get local issuer certificate", whatever its dates), then the name, then the dates.
    fn openssl_words(&self, ee: &CertificateDer<'_>, inter: &[CertificateDer<'_>], name: &ServerName<'_>, now: UnixTime) -> String {
        use rustls::CertificateError as C;
        let sent: Vec<der::Cert> = std::iter::once(ee).chain(inter.iter()).filter_map(|c| der::parse(c.as_ref())).collect();
        let mismatch = format!("Hostname mismatch, certificate is not valid for '{}'.", self.host);
        // a moment when every certificate sent is valid, to tell an untrusted chain from an expired one
        let t = sent.iter().map(|c| c.not_before).max().filter(|&nb| sent.iter().all(|c| c.not_after >= nb));
        let at = |secs: i64| UnixTime::since_unix_epoch(Duration::from_secs(secs.max(0) as u64));
        let verify = |when: UnixTime| match &self.inner {
            Some(v) => v.verify_server_cert(ee, inter, name, &[], when).err(),
            None => Some(rustls::Error::InvalidCertificate(C::UnknownIssuer)),
        };
        let trust = verify(t.map_or(now, at));
        match trust.as_ref().and_then(cert_err) {
            None | Some(C::NotValidForName | C::NotValidForNameContext { .. }) => {
                if trust.is_some() {
                    return mismatch;
                }
                match verify(now).as_ref().and_then(cert_err) {
                    Some(C::Expired | C::ExpiredContext { .. }) => "certificate has expired".into(),
                    Some(C::NotValidYet | C::NotValidYetContext { .. }) => "certificate is not yet valid".into(),
                    Some(C::NotValidForName | C::NotValidForNameContext { .. }) => mismatch,
                    _ => "certificate verify failed".into(),
                }
            }
            Some(C::Expired | C::ExpiredContext { .. }) => "certificate has expired".into(),
            Some(C::NotValidYet | C::NotValidYetContext { .. }) => "certificate is not yet valid".into(),
            Some(C::BadSignature) => "certificate signature failure".into(),
            Some(C::InvalidPurpose | C::InvalidPurposeContext { .. }) => "unsuitable certificate purpose".into(),
            Some(C::Revoked) => "certificate revoked".into(),
            _ => untrusted(&sent),
        }
    }
}

/// The chain OpenSSL builds from what the server sent when no authority it trusts is found: up from the certificate, an
/// issuer found by name and key identifier each step, until a self-signed one or none.
pub fn untrusted(sent: &[der::Cert]) -> String {
    let Some(first) = sent.first() else { return "unable to get local issuer certificate".into() };
    let mut chain = vec![0usize];
    let mut cur = first;
    loop {
        if cur.self_signed() {
            return if chain.len() == 1 { "self-signed certificate".into() } else { "self-signed certificate in certificate chain".into() };
        }
        match (1..sent.len()).find(|i| !chain.contains(i) && cur.issued_by(&sent[*i])) {
            Some(i) => {
                chain.push(i);
                cur = &sent[i];
            }
            None => return "unable to get local issuer certificate".into(),
        }
    }
}

impl ServerCertVerifier for Worded {
    fn verify_server_cert(
        &self,
        ee: &CertificateDer<'_>,
        inter: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let r = match &self.inner {
            Some(v) => v.verify_server_cert(ee, inter, name, ocsp, now),
            None => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        };
        if r.is_err() {
            *self.words.lock().unwrap() = Some(self.openssl_words(ee, inter, name, now));
        }
        r
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let p = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls12_signature(m, c, d, &p.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let p = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(m, c, d, &p.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS connection to `host` with its certificate checked as Python's default context checks it.
pub enum Tls {
    Ok(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
    /// the certificate was refused: OpenSSL's words for why
    Cert(String),
    /// anything else (no connection, not TLS, a timeout)
    Blocked,
}

pub fn tls_connect(tcp: TcpStream, host: &str) -> Tls {
    let w = Arc::new(Worded { inner: verifier(roots()), host: host.to_string(), words: Mutex::new(None) });
    let p = Arc::new(rustls::crypto::ring::default_provider());
    let Ok(b) = rustls::ClientConfig::builder_with_provider(p).with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    else {
        return Tls::Blocked;
    };
    let cfg = b.dangerous().with_custom_certificate_verifier(w.clone()).with_no_client_auth();
    let Ok(name) = ServerName::try_from(host.to_string()) else { return Tls::Blocked };
    let Ok(conn) = rustls::ClientConnection::new(Arc::new(cfg), name) else { return Tls::Blocked };
    let mut s = rustls::StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        if s.conn.complete_io(&mut s.sock).is_err() {
            return match w.words.lock().unwrap().take() {
                Some(why) => Tls::Cert(why),
                None => Tls::Blocked,
            };
        }
    }
    Tls::Ok(Box::new(s))
}

/// One host of the HTTPS check: connected with a genuine certificate (Ok), refused (Cert), or not reached.
pub fn tls_probe(host: &str) -> Tls {
    match create_connection(host, 443, TIMEOUT) {
        Some(tcp) => tls_connect(tcp, host),
        None => Tls::Blocked,
    }
}

// ---- plain web pages, as urllib fetches them

/// A URL split as Python 3.14's `_urlsplit` splits it: a part that is absent is None, not "".
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Split {
    pub scheme: Option<String>,
    pub netloc: Option<String>,
    pub path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
}

const USES_NETLOC: &[&str] = &[
    "",
    "ftp",
    "http",
    "gopher",
    "nntp",
    "telnet",
    "imap",
    "wais",
    "file",
    "mms",
    "https",
    "shttp",
    "snews",
    "prospero",
    "rtsp",
    "rtsps",
    "rtspu",
    "rsync",
    "svn",
    "svn+ssh",
    "sftp",
    "nfs",
    "git",
    "git+ssh",
    "ws",
    "wss",
    "itms-services",
];
const USES_RELATIVE: &[&str] = &[
    "", "ftp", "http", "gopher", "nntp", "imap", "wais", "file", "https", "shttp", "mms", "prospero", "rtsp", "rtsps", "rtspu", "sftp",
    "svn", "svn+ssh", "ws", "wss",
];
const USES_PARAMS: &[&str] =
    &["", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu", "sip", "sips", "mms", "sftp", "tel"];

/// `_check_bracketed_host`: an IPv6 address (or an IPvFuture "v1.x") inside brackets.
fn bracketed_host_ok(h: &str) -> bool {
    if let Some(rest) = h.strip_prefix(['v', 'V']) {
        let hex = rest.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len());
        return hex > 0 && rest[hex..].starts_with('.') && rest.len() > hex + 1 && !rest[hex + 1..].contains('\n');
    }
    addr::parse_v4(h).is_none() && addr::parse_v6(h).is_some()
}

/// Python's `_urlsplit(url, scheme)` (3.14); None where it raises ValueError.
pub fn urlsplit(url: &str, scheme: Option<&str>) -> Option<Split> {
    let clean = |s: &str| -> String { s.chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect() };
    let mut url = clean(url.trim_start_matches(|c: char| c <= ' '));
    let mut sp = Split { scheme: scheme.map(|s| clean(s.trim_matches(|c: char| c <= ' '))), ..Split::default() };
    if let Some(i) = url.find(':') {
        let first = url.chars().next().unwrap();
        if i > 0 && first.is_ascii_alphabetic() && url[..i].chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
            sp.scheme = Some(url[..i].to_ascii_lowercase());
            url = url[i + 1..].to_string();
        }
    }
    if url.starts_with("//") {
        let rest = &url[2..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let netloc = rest[..end].to_string();
        url = rest[end..].to_string();
        if netloc.contains('[') != netloc.contains(']') {
            return None;
        }
        if netloc.contains('[') {
            let hp = netloc.rsplit_once('@').map_or(netloc.as_str(), |(_, b)| b);
            let host = match hp.split_once('[') {
                Some((before, bracketed)) => {
                    if !before.is_empty() {
                        return None;
                    }
                    let (h, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                    if !port.is_empty() && !port.starts_with(':') {
                        return None;
                    }
                    h
                }
                None => hp.split_once(':').map_or(hp, |(h, _)| h),
            };
            if !bracketed_host_ok(host) {
                return None;
            }
        }
        sp.netloc = Some(netloc);
    }
    if let Some((a, b)) = url.split_once('#') {
        sp.fragment = Some(b.to_string());
        url = a.to_string();
    }
    if let Some((a, b)) = url.split_once('?') {
        sp.query = Some(b.to_string());
        url = a.to_string();
    }
    sp.path = url;
    Some(sp)
}

/// Python's `_urlunsplit`.
pub fn urlunsplit(s: &Split) -> String {
    let mut url = s.path.clone();
    if let Some(n) = &s.netloc {
        if !url.is_empty() && !url.starts_with('/') {
            url = format!("/{url}");
        }
        url = format!("//{n}{url}");
    } else if url.starts_with("//") {
        url = format!("//{url}");
    }
    if let Some(sc) = s.scheme.as_ref().filter(|x| !x.is_empty()) {
        url = format!("{sc}:{url}");
    }
    if let Some(q) = &s.query {
        url = format!("{url}?{q}");
    }
    if let Some(f) = &s.fragment {
        url = format!("{url}#{f}");
    }
    url
}

/// `urlunparse(urlparse(url))` with urllib's redirect fix in between (an empty path after a host becomes "/"): the scheme
/// and the text, None where urlparse raises.
fn reparse(url: &str) -> Option<(String, String)> {
    let sp = urlsplit(url, Some(""))?;
    let scheme = sp.scheme.clone().unwrap_or_default();
    let (mut path, params) = if USES_PARAMS.contains(&scheme.as_str()) && sp.path.contains(';') {
        let p = &sp.path;
        let i = match p.rfind('/') {
            Some(slash) => p[slash..].find(';').map(|j| slash + j),
            None => p.find(';'),
        };
        match i {
            Some(i) => (p[..i].to_string(), p[i + 1..].to_string()),
            None => (p.clone(), String::new()),
        }
    } else {
        (sp.path.clone(), String::new())
    };
    let netloc = sp.netloc.clone().unwrap_or_default();
    let query = sp.query.clone().unwrap_or_default();
    let fragment = sp.fragment.clone().unwrap_or_default();
    if path.is_empty() && !netloc.is_empty() {
        path = "/".into();
    }
    // urlunparse
    let netloc = if !netloc.is_empty() {
        Some(netloc)
    } else if !scheme.is_empty() && USES_NETLOC.contains(&scheme.as_str()) && (path.is_empty() || path.starts_with('/')) {
        Some(String::new())
    } else {
        None
    };
    if !params.is_empty() {
        path = format!("{path};{params}");
    }
    let s = Split {
        scheme: Some(scheme.clone()).filter(|x| !x.is_empty()),
        netloc,
        path,
        query: Some(query).filter(|x| !x.is_empty()),
        fragment: Some(fragment).filter(|x| !x.is_empty()),
    };
    Some((scheme, urlunsplit(&s)))
}

/// `urllib.parse.urljoin(base, url)` (3.14).
pub fn urljoin(base: &str, url: &str) -> Option<String> {
    if base.is_empty() {
        return Some(url.to_string());
    }
    if url.is_empty() {
        return Some(base.to_string());
    }
    let b = urlsplit(base, None)?;
    let u = urlsplit(url, None)?;
    let scheme = u.scheme.clone().or(b.scheme.clone());
    let sc = scheme.clone().unwrap_or_default();
    if scheme != b.scheme || (!sc.is_empty() && !USES_RELATIVE.contains(&sc.as_str())) {
        return Some(url.to_string());
    }
    let mut netloc = u.netloc.clone();
    if sc.is_empty() || USES_NETLOC.contains(&sc.as_str()) {
        if netloc.as_ref().is_some_and(|n| !n.is_empty()) {
            return Some(urlunsplit(&Split { scheme, netloc, path: u.path, query: u.query, fragment: u.fragment }));
        }
        netloc = b.netloc.clone();
    }
    if u.path.is_empty() {
        let (mut query, mut fragment) = (u.query.clone(), u.fragment.clone());
        if query.is_none() {
            query = b.query.clone();
            if fragment.is_none() {
                fragment = b.fragment.clone();
            }
        }
        return Some(urlunsplit(&Split { scheme, netloc, path: b.path.clone(), query, fragment }));
    }
    let mut base_parts: Vec<&str> = b.path.split('/').collect();
    if base_parts.last() != Some(&"") {
        base_parts.pop();
    }
    let segments: Vec<&str> = if u.path.starts_with('/') {
        u.path.split('/').collect()
    } else {
        let mut s: Vec<&str> = base_parts;
        s.extend(u.path.split('/'));
        if s.len() > 2 {
            let last = s.len() - 1;
            let mut t = vec![s[0]];
            t.extend(s[1..last].iter().copied().filter(|x| !x.is_empty()));
            t.push(s[last]);
            s = t;
        }
        s
    };
    let mut resolved: Vec<&str> = Vec::new();
    for seg in &segments {
        match *seg {
            ".." => {
                resolved.pop();
            }
            "." => {}
            s => resolved.push(s),
        }
    }
    if matches!(segments.last(), Some(&".") | Some(&"..")) {
        resolved.push("");
    }
    let joined = resolved.join("/");
    let path = if joined.is_empty() { "/".to_string() } else { joined };
    Some(urlunsplit(&Split { scheme, netloc, path, query: u.query, fragment: u.fragment }))
}

/// `quote(url, encoding="iso-8859-1", safe=string.punctuation)` of a header's text (each character one byte).
fn quote(s: &str) -> Option<String> {
    let mut out = String::new();
    for c in s.chars() {
        let b = u8::try_from(c as u32).ok()?;
        if b.is_ascii_alphanumeric() || b.is_ascii_punctuation() {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    Some(out)
}

/// `urllib.parse.unquote` of a host (percent escapes decoded as UTF-8, a bad one replaced).
fn unquote(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// email's feedparser over a header block (compat32): lines split at \r\n, \r or \n; the block ends at the first line that
/// is not a header line (headerRE); a line starting with a space or tab continues the header before it, or
/// is dropped when there is none; "From " lines and lines starting with ':' are dropped. (lower-case name, value).
fn email_headers(raw: &str) -> Vec<(String, String)> {
    let mut lines: Vec<&str> = Vec::new();
    let mut start = 0;
    let b = raw.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\n' || b[i] == b'\r' {
            let end = if b[i] == b'\r' && b.get(i + 1) == Some(&b'\n') { i + 2 } else { i + 1 };
            lines.push(&raw[start..end]);
            start = end;
            i = end;
        } else {
            i += 1;
        }
    }
    if start < raw.len() {
        lines.push(&raw[start..]);
    }
    let header_re = |l: &str| {
        l.starts_with("From ")
            || l.starts_with([' ', '\t'])
            || l.find(':').is_some_and(|i| l[..i].bytes().all(|c| (0x21..=0x7e).contains(&c) && c != b':'))
    };
    let mut out: Vec<(String, String)> = Vec::new();
    let mut cur: Option<(String, String)> = None;
    for l in lines {
        if !header_re(l) {
            break;
        }
        if l.starts_with([' ', '\t']) {
            if let Some(c) = cur.as_mut() {
                c.1.push_str(l);
            }
            continue;
        }
        if let Some(c) = cur.take() {
            out.push(c);
        }
        if l.starts_with("From ") {
            continue;
        }
        let i = l.find(':').unwrap_or(0);
        if i == 0 {
            continue;
        }
        cur = Some((l[..i].to_ascii_lowercase(), l[i + 1..].to_string()));
    }
    if let Some(c) = cur.take() {
        out.push(c);
    }
    // compat32's header_source_parse (3.14): the lines joined, then spaces and line ends off the front, line ends off the end
    for h in out.iter_mut() {
        let v = h.1.trim_start_matches([' ', '\t', '\r', '\n']).trim_end_matches(['\r', '\n']).to_string();
        h.1 = v;
    }
    out
}

/// `int(line, 16)` of a chunk-size line's bytes (after `;` is cut): ASCII spaces around, a sign, an optional 0x, hex
/// digits with single underscores between them.
fn chunk_size(text: &str) -> Option<i128> {
    let t = text.trim_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, t) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let (t, prefixed) = match t.get(..2) {
        Some("0x" | "0X") => (&t[2..], true),
        _ => (t, false),
    };
    let mut digits = String::new();
    let mut prev_ok = prefixed; // after 0x an underscore may come first
    let mut last_us = false;
    for c in t.chars() {
        if c.is_ascii_hexdigit() {
            digits.push(c);
            prev_ok = true;
            last_us = false;
        } else if c == '_' && prev_ok {
            prev_ok = false;
            last_us = true;
        } else {
            return None;
        }
    }
    if digits.is_empty() || last_us || digits.len() > 30 {
        return None;
    }
    let v = i128::from_str_radix(&digits, 16).ok()?;
    Some(if neg { -v } else { v })
}

/// A connection for one request.
enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

type Source = BufReader<Box<dyn Read + Send>>;

/// A response read as http.client reads it.
struct Resp {
    status: u32,
    /// (lower-case name, value as ISO-8859-1 text), in order
    headers: Vec<(String, String)>,
    r: Source,
    chunked: bool,
    length: Option<u64>,
    chunk_left: Option<u64>,
    done: bool,
}

const MAXLINE: usize = 65536;

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

fn read_line(r: &mut Source) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    r.by_ref().take(MAXLINE as u64 + 1).read_until(b'\n', &mut line).ok()?;
    (line.len() <= MAXLINE).then_some(line)
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn begin(mut r: Source) -> Option<Resp> {
        let status = loop {
            let line = read_line(&mut r)?;
            if line.is_empty() {
                return None; // RemoteDisconnected
            }
            let text = latin1(&line);
            let words: Vec<&str> = py::split_ws(&text).into_iter().collect();
            let version = words.first().copied().unwrap_or_default();
            if !version.starts_with("HTTP/") {
                return None;
            }
            let status: u32 = py::int_str(words.get(1).copied().unwrap_or_default()).ok()?.parse().ok()?;
            if !(100..=999).contains(&status) {
                return None;
            }
            if status != 100 {
                if !matches!(version, "HTTP/1.0" | "HTTP/0.9") && !version.starts_with("HTTP/1.") {
                    return None; // UnknownProtocol
                }
                break status;
            }
            // 100 Continue: its headers skipped
            loop {
                let l = read_line(&mut r)?;
                if matches!(l.as_slice(), b"\r\n" | b"\n" | b"") {
                    break;
                }
            }
        };
        // the header lines (at most 100), then email's parser over their text, as http.client hands it over
        let mut raw = String::new();
        let mut n = 0;
        loop {
            let l = read_line(&mut r)?;
            if matches!(l.as_slice(), b"\r\n" | b"\n" | b"") {
                break;
            }
            raw.push_str(&latin1(&l));
            n += 1;
            if n > 100 {
                return None; // "got more than 100 headers"
            }
        }
        let headers = email_headers(&raw);
        let mut resp = Resp { status, headers, r, chunked: false, length: None, chunk_left: None, done: false };
        resp.chunked = resp.header("transfer-encoding").is_some_and(|t| t.eq_ignore_ascii_case("chunked"));
        if !resp.chunked {
            if let Some(l) = resp.header("content-length").filter(|l| !l.is_empty()) {
                resp.length = py::int_str(l).ok().and_then(|n| n.parse::<u64>().ok());
            }
        }
        if status == 204 || status == 304 || (100..200).contains(&status) {
            resp.length = Some(0);
        }
        Some(resp)
    }

    fn read_exact_n(&mut self, n: u64) -> Option<Vec<u8>> {
        let mut b = Vec::new();
        self.r.by_ref().take(n).read_to_end(&mut b).ok()?;
        (b.len() as u64 == n).then_some(b)
    }

    /// `read(amt)`.
    fn read(&mut self, amt: u64) -> Option<Vec<u8>> {
        if self.done {
            return Some(Vec::new());
        }
        if self.chunked {
            let mut amt = amt;
            let mut out = Vec::new();
            loop {
                let left = match self.chunk_left {
                    Some(0) | None => {
                        if self.chunk_left == Some(0) {
                            self.read_exact_n(2)?; // the CRLF after a chunk
                        }
                        let line = read_line(&mut self.r)?;
                        let line = latin1(&line);
                        let size = chunk_size(line.split(';').next().unwrap_or_default())?;
                        // a negative size reads the rest and then fails on the missing chunk end: IncompleteRead
                        let n = u64::try_from(size).ok()?;
                        if n == 0 {
                            loop {
                                let l = read_line(&mut self.r)?;
                                if matches!(l.as_slice(), b"\r\n" | b"\n" | b"") {
                                    break;
                                }
                            }
                            self.done = true;
                            self.chunk_left = None;
                            return Some(out);
                        }
                        self.chunk_left = Some(n);
                        n
                    }
                    Some(n) => n,
                };
                if amt <= left {
                    out.extend(self.read_exact_n(amt)?);
                    self.chunk_left = Some(left - amt);
                    return Some(out);
                }
                out.extend(self.read_exact_n(left)?);
                amt -= left;
                self.chunk_left = Some(0);
            }
        }
        let amt = match self.length {
            Some(l) => amt.min(l),
            None => amt,
        };
        let mut b = Vec::new();
        self.r.by_ref().take(amt).read_to_end(&mut b).ok()?;
        if let Some(l) = self.length.as_mut() {
            *l -= b.len() as u64;
            if *l == 0 {
                self.done = true;
            }
        }
        if b.is_empty() && amt > 0 {
            self.done = true;
        }
        Some(b)
    }

    /// `fp.read()`: the rest of the body (a body shorter than its Content-Length raises IncompleteRead here).
    fn read_all(&mut self) -> Option<()> {
        if self.done {
            return Some(());
        }
        if self.chunked {
            while !self.done {
                self.read(1 << 16)?;
            }
            return Some(());
        }
        match self.length {
            Some(l) => {
                self.read_exact_n(l)?;
            }
            None => {
                let mut b = Vec::new();
                self.r.read_to_end(&mut b).ok()?;
            }
        }
        self.done = true;
        Some(())
    }
}

/// One request, as urllib's `do_open` sends it.
fn request(scheme: &str, host: &str, selector: &str) -> Option<Resp> {
    let default_port = if scheme == "https" { 443 } else { 80 };
    let (mut h, port) = match (host.rfind(':'), host.rfind(']')) {
        (Some(i), j) if j.is_none_or(|j| i > j) => {
            let p = &host[i + 1..];
            let port = if p.is_empty() { default_port } else { py::int_str(p).ok()?.parse::<u16>().ok()? };
            (&host[..i], port)
        }
        _ => (host, default_port),
    };
    if h.starts_with('[') && h.ends_with(']') && h.len() >= 2 {
        h = &h[1..h.len() - 1];
    }
    let path = if selector.is_empty() { "/" } else { selector };
    // what http.client refuses before it connects: control characters in the path, a Host that is not ISO-8859-1
    if path.chars().any(|c| c <= ' ' || c == '\x7f') || host.chars().any(|c| c as u32 > 0xff) {
        return None;
    }
    let tcp = create_connection(h, port, TIMEOUT)?;
    let mut conn = if scheme == "https" {
        match tls_connect(tcp, h) {
            Tls::Ok(s) => Conn::Tls(s),
            _ => return None,
        }
    } else {
        Conn::Plain(tcp)
    };
    let mut req: Vec<u8> = format!("GET {path} HTTP/1.1\r\nAccept-Encoding: identity\r\nHost: ").into_bytes();
    req.extend(host.chars().map(|c| c as u8));
    req.extend_from_slice(b"\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n");
    conn.write_all(&req).ok()?;
    conn.flush().ok()?;
    Resp::begin(BufReader::new(Box::new(conn)))
}

/// What urllib makes of a response: (the status, the Location or URI header, for a 2xx the body read(4096) gives, whether
/// reading the whole body works as a redirect does).
pub type View = (u32, Option<String>, Option<Vec<u8>>, bool);

/// The [`View`] of a response's bytes; None where http.client raises.
pub fn response_view(data: &[u8]) -> Option<View> {
    let src: Box<dyn Read + Send> = Box::new(std::io::Cursor::new(data.to_vec()));
    let mut r = Resp::begin(BufReader::new(src))?;
    let loc = r.header("location").or_else(|| r.header("uri")).map(str::to_string);
    if (200..300).contains(&r.status) {
        let body = r.read(4096)?;
        return Some((r.status, loc, Some(body), true));
    }
    let ok = r.read_all().is_some();
    Some((r.status, loc, None, ok))
}

/// The next URL of a redirect from `base` to `location` (urllib's `http_error_302`), None where urllib refuses it.
pub fn redirect_target(base: &str, location: &str) -> Option<String> {
    let (scheme, url) = reparse(location)?;
    if !matches!(scheme.as_str(), "http" | "https" | "ftp" | "") {
        return None;
    }
    let newurl = quote(&url)?;
    Some(urljoin(base, &newurl)?.replace(' ', "%20"))
}

/// `urllib.request.urlopen(Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=8)` and `resp.read(4096)`: the
/// final status and body after redirects, or None where urllib raises.
pub fn urlopen(url: &str) -> Option<(u32, Vec<u8>)> {
    let mut full = url.to_string();
    let mut visited: Vec<(String, u32)> = Vec::new();
    loop {
        let full_nofrag = full.rsplit_once('#').map_or(full.as_str(), |(a, _)| a).to_string();
        let (ty, rest) = full_nofrag.split_once(':').filter(|(t, _)| !t.is_empty() && !t.contains('/'))?;
        let ty = ty.to_ascii_lowercase();
        if ty != "http" && ty != "https" {
            return None; // ftp and the rest: no answer here
        }
        let rest = rest.strip_prefix("//")?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let host = unquote(&rest[..end]);
        if host.is_empty() {
            return None;
        }
        let mut resp = request(&ty, &host, &rest[end..])?;
        if (200..300).contains(&resp.status) {
            let body = resp.read(4096)?;
            return Some((resp.status, body));
        }
        if !matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
            return None; // HTTPError
        }
        let loc = resp.header("location").or_else(|| resp.header("uri"))?.to_string();
        let newurl = redirect_target(&full, &loc)?;
        if !visited.is_empty() {
            let seen = visited.iter().find(|(u, _)| *u == newurl).map_or(0, |(_, n)| *n);
            if seen >= 4 || visited.len() >= 10 {
                return None; // "a redirect error that would lead to an infinite loop"
            }
        }
        match visited.iter_mut().find(|(u, _)| *u == newurl) {
            Some((_, n)) => *n += 1,
            None => visited.push((newurl.clone(), 1)),
        }
        resp.read_all()?;
        full = newurl;
    }
}

// ---- other devices

/// Passive: other devices' own announcements on the local network (multicast DNS and UPnP), heard for `seconds`. None when
/// neither group could be joined; `mine` (this computer's addresses) is asked only once listening works, as in Python.
pub fn listen_for_devices(seconds: f64, mine: impl FnOnce() -> py::PyResult<Vec<py::Val>>) -> py::PyResult<Option<Vec<String>>> {
    let mut fds: Vec<i32> = Vec::new();
    for (group, port) in [([224u8, 0, 0, 251], 5353u16), ([239, 255, 255, 250], 1900)] {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::IPPROTO_UDP);
            if fd < 0 {
                continue;
            }
            let one: libc::c_int = 1;
            let sz = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let p = &one as *const libc::c_int as *const libc::c_void;
            if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, p, sz) != 0 {
                libc::close(fd);
                continue;
            }
            let _ = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, p, sz);
            let mut sa: libc::sockaddr_in = std::mem::zeroed();
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = port.to_be();
            if libc::bind(
                fd,
                &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) != 0
            {
                libc::close(fd);
                continue;
            }
            let mreq = libc::ip_mreq {
                imr_multiaddr: libc::in_addr { s_addr: u32::from_ne_bytes(group) },
                imr_interface: libc::in_addr { s_addr: 0 },
            };
            if libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_ADD_MEMBERSHIP,
                &mreq as *const libc::ip_mreq as *const libc::c_void,
                std::mem::size_of::<libc::ip_mreq>() as libc::socklen_t,
            ) != 0
            {
                libc::close(fd);
                continue;
            }
            let fl = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            fds.push(fd);
        }
    }
    let close = |fds: &[i32]| {
        for &fd in fds {
            unsafe { libc::close(fd) };
        }
    };
    if fds.is_empty() {
        return Ok(None);
    }
    let mine = match mine() {
        Ok(m) => m,
        Err(e) => {
            close(&fds);
            return Err(e);
        }
    };
    let mut heard: Vec<String> = Vec::new();
    let end = Instant::now() + Duration::from_secs_f64(seconds);
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let mut pfds: Vec<libc::pollfd> = fds.iter().map(|&fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 }).collect();
        let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, left.as_millis().clamp(1, i32::MAX as u128) as i32) };
        if n <= 0 {
            continue;
        }
        for p in pfds.iter().filter(|p| p.revents != 0) {
            let mut buf = [0u8; 9000];
            let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut flen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let got = unsafe {
                libc::recvfrom(
                    p.fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut from as *mut libc::sockaddr_in as *mut libc::sockaddr,
                    &mut flen,
                )
            };
            if got < 0 {
                continue;
            }
            let src = std::net::Ipv4Addr::from(u32::from_be(from.sin_addr.s_addr)).to_string();
            let is_mine = mine.iter().any(|m| m.as_str() == Some(src.as_str()));
            if !is_mine && !src.starts_with("127.") && !heard.contains(&src) {
                heard.push(src);
            }
        }
    }
    close(&fds);
    Ok(Some(heard))
}
