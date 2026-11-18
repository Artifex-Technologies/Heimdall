//! The download the shell programs left to curl, done here as curl did it:
//!
//! ```text
//! curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 --max-filesize N [-H 'Authorization: Bearer T'] -o FILE URL
//! ```
//!
//! - **https only**, the first address and every redirect (`--proto =https`); redirects followed (`-L`, at most 50, the
//!   statuses curl follows), the Authorization header sent only to the first host, scheme and port (curl drops it on a
//!   redirect elsewhere);
//! - **TLS 1.2 or 1.3** (`--tlsv1.2`) with rustls, the certificate checked against the authorities curl reads
//!   (`$CURL_CA_BUNDLE`, else `$SSL_CERT_FILE` and `$SSL_CERT_DIR`, else `/etc/ssl/certs/ca-certificates.crt`), the
//!   host name checked first as curl checks it;
//! - **300 seconds for everything** (`--max-time`): the name lookup, the connection, every redirect and the body;
//! - **the size limit** (`--max-filesize`): a Content-Length over it refused before anything is written, a body without
//!   one cut at the limit;
//! - **an HTTP error is a failure** (`-f`: 400 and over, nothing written);
//! - the file written as curl writes it (created at the first byte of the body, empty after a body of none, what arrived
//!   before a failure kept), and curl's error line on standard error (`-sS`) with curl's exit code.
//!
//! The request is the one curl sends over HTTP/1.1 (`GET`, `Host`, `User-Agent: curl/8.23.0`, `Accept: */*`, then the
//! Authorization header), so a server sees what it saw from the script. Nothing else is sent anywhere: no proxy, no
//! `.curlrc`, no cookies, no compression asked for.

use super::coreutils::strerror;
use crate::cli::wifitools::{der, net};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `--max-time 300`.
pub const MAX_TIME: Duration = Duration::from_secs(300);
/// curl's own limit of redirects (`--max-redirs` not given).
pub const MAX_REDIRS: u32 = 50;
/// What curl calls itself in a request (the version the scripts last ran with on Arch).
pub const USER_AGENT: &str = "curl/8.23.0";
/// How long the first address family has before the other is tried as well (curl's happy eyeballs).
const EYEBALLS: Duration = Duration::from_millis(200);
/// curl's limit on a response's headers together.
const MAX_HEADERS: usize = 300 * 1024;

/// One download.
pub struct Request<'a> {
    pub url: &'a str,
    pub out: &'a Path,
    pub max_filesize: u64,
    /// the value of an Authorization header (`Bearer TOKEN`)
    pub auth: Option<&'a str>,
    pub max_time: Duration,
}

/// Why a download failed: curl's exit code and its words.
#[derive(Debug, Clone, PartialEq)]
pub struct Fail {
    pub code: u8,
    pub msg: String,
}

fn fail(code: u8, msg: impl Into<String>) -> Fail {
    Fail { code, msg: msg.into() }
}

/// What curl adds after a refused certificate.
const CERT_HELP: &str = "More details here: https://curl.se/docs/sslcerts.html\n\n\
curl failed to verify the legitimacy of the server and therefore could not\n\
establish a secure connection to it. To learn more about this situation and\n\
how to fix it, please visit the webpage mentioned above.\n";

/// Downloads as curl did: 0, or curl's exit code after its error line on standard error.
pub fn curl(r: &Request) -> u8 {
    match transfer(r) {
        Ok(()) => 0,
        Err(f) => {
            let mut s = format!("curl: ({}) {}\n", f.code, f.msg);
            if f.code == 60 {
                s.push_str(CERT_HELP);
            }
            let _ = std::io::stderr().write_all(s.as_bytes());
            f.code
        }
    }
}

// ---- addresses

/// A URL curl would fetch: scheme (lower case), host, port, and the path with its query (fragment dropped).
#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// The scheme of an absolute reference (`name:` before any `/`, `?` or `#`).
fn scheme_of(s: &str) -> Option<&str> {
    let i = s.find(':')?;
    let sch = &s[..i];
    let mut b = sch.bytes();
    let first = b.next()?;
    (first.is_ascii_alphabetic() && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))).then_some(sch)
}

/// Reads an absolute URL; None when curl could not use it.
pub fn parse_url(s: &str) -> Option<Url> {
    let scheme = scheme_of(s)?.to_ascii_lowercase();
    let rest = s[scheme.len() + 1..].strip_prefix("//")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let mut tail = rest[end..].to_string();
    if let Some(i) = tail.find('#') {
        tail.truncate(i);
    }
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
        let (h, after) = r.split_once(']')?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (format!("[{h}]"), port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (hostport.to_string(), None),
        }
    };
    if host.is_empty() || host.bytes().any(|c| c <= b' ' || c == 0x7f) {
        return None;
    }
    let default = if scheme == "http" { 80 } else { 443 };
    let port = match port {
        None | Some("") => default,
        Some(p) if p.bytes().all(|c| c.is_ascii_digit()) && p.len() <= 5 => p.parse::<u32>().ok().filter(|&n| n <= 65535)? as u16,
        Some(_) => return None,
    };
    let path = if tail.is_empty() || tail.starts_with('?') { format!("/{tail}") } else { tail };
    Some(Url { scheme, host, port, path: remove_dots(&path) })
}

/// RFC 3986's remove_dot_segments on a path, its query left alone.
fn remove_dots(pq: &str) -> String {
    let (path, query) = match pq.find('?') {
        Some(i) => (&pq[..i], &pq[i..]),
        None => (pq, ""),
    };
    let mut out: Vec<&str> = Vec::new();
    let segs: Vec<&str> = path.split('/').skip(1).collect();
    for (i, seg) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        match *seg {
            "." => {
                if last {
                    out.push("");
                }
            }
            ".." => {
                out.pop();
                if last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    format!("/{}{query}", out.join("/"))
}

/// Where a redirect goes: the Location resolved against the current URL (RFC 3986), the fragment dropped, spaces and bytes
/// outside ASCII percent-encoded as curl encodes them.
pub fn resolve_location(base: &Url, loc: &str) -> Result<Url, Fail> {
    let enc: String =
        loc.chars().map(|c| if c == ' ' || (c as u32) > 0x7e { format!("%{:02X}", c as u32 & 0xff) } else { c.to_string() }).collect();
    let loc = enc.split('#').next().unwrap_or_default().to_string();
    let authority = |u: &Url| {
        let def = if u.scheme == "http" { 80 } else { 443 };
        if u.port == def {
            u.host.clone()
        } else {
            format!("{}:{}", u.host, u.port)
        }
    };
    let abs = if let Some(sch) = scheme_of(&loc) {
        let sch = sch.to_ascii_lowercase();
        if sch != "https" && sch != "http" {
            return Err(fail(1, format!("Protocol \"{sch}\" is disabled (in redirect)")));
        }
        loc.clone()
    } else if loc.starts_with("//") {
        format!("{}:{loc}", base.scheme)
    } else if loc.starts_with('/') {
        format!("{}://{}{loc}", base.scheme, authority(base))
    } else if loc.starts_with('?') {
        let p = base.path.split('?').next().unwrap_or("/");
        format!("{}://{}{p}{loc}", base.scheme, authority(base))
    } else {
        let p = base.path.split('?').next().unwrap_or("/");
        let dir = &p[..p.rfind('/').map_or(0, |i| i + 1)];
        format!("{}://{}{dir}{loc}", base.scheme, authority(base))
    };
    parse_url(&abs).ok_or_else(|| fail(3, "URL rejected: Malformed input to a URL function"))
}

// ---- the authorities and the certificate check

/// The authorities curl trusts, or curl's error when the file cannot be used.
fn roots() -> Result<Arc<rustls::RootCertStore>, Fail> {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty());
    let (file, dir) = match env("CURL_CA_BUNDLE") {
        Some(f) => (Some(f), None),
        None => (Some(env("SSL_CERT_FILE").unwrap_or_else(|| "/etc/ssl/certs/ca-certificates.crt".into())), env("SSL_CERT_DIR")),
    };
    let mut store = rustls::RootCertStore::empty();
    if let Some(f) = &file {
        let certs: Vec<CertificateDer> =
            std::fs::read(f).map(|b| CertificateDer::pem_slice_iter(&b).flatten().collect()).unwrap_or_default();
        if certs.is_empty() {
            return Err(fail(77, format!("error setting certificate file: {}", f.to_string_lossy())));
        }
        for c in certs {
            let _ = store.add(c);
        }
    }
    if let Some(d) = dir {
        for d in std::env::split_paths(&d) {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                if let Ok(b) = std::fs::read(e.path()) {
                    for c in CertificateDer::pem_slice_iter(&b).flatten() {
                        let _ = store.add(c);
                    }
                }
            }
        }
    }
    Ok(Arc::new(store))
}

/// The names a certificate is for: (any dNSName or iPAddress in its subjectAltName, the DNS names, the IP addresses, the
/// last common name of its subject).
fn names(der_bytes: &[u8]) -> (bool, Vec<String>, Vec<Vec<u8>>, Option<String>) {
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    let mut any = false;
    let mut cn = None;
    let Some((0x30, cert, _)) = der::tlv(der_bytes) else { return (false, dns, ips, cn) };
    let Some((0x30, tbs, _)) = der::tlv(cert) else { return (false, dns, ips, cn) };
    let mut fields = Vec::new();
    let mut r = tbs;
    while let Some((t, v, next)) = der::tlv(r) {
        fields.push((t, v));
        r = next;
    }
    let base = if fields.first().is_some_and(|f| f.0 == 0xa0) { 1 } else { 0 };
    // serial, signature algorithm, issuer, validity, subject
    if let Some(&(0x30, subject)) = fields.get(base + 4) {
        let mut rdns = subject;
        while let Some((0x31, set, next)) = der::tlv(rdns) {
            rdns = next;
            let mut atvs = set;
            while let Some((0x30, atv, n2)) = der::tlv(atvs) {
                atvs = n2;
                if let Some((0x06, oid, val)) = der::tlv(atv) {
                    if oid == [0x55, 0x04, 0x03] {
                        if let Some((_, s, _)) = der::tlv(val) {
                            cn = Some(String::from_utf8_lossy(s).into_owned());
                        }
                    }
                }
            }
        }
    }
    for &(t, v) in &fields {
        if t != 0xa3 {
            continue;
        }
        let Some((0x30, mut exts, _)) = der::tlv(v) else { continue };
        while let Some((_, ext, next)) = der::tlv(exts) {
            exts = next;
            let Some((0x06, oid, er)) = der::tlv(ext) else { continue };
            if oid != [0x55, 0x1d, 0x11] {
                continue;
            }
            let Some((mut t2, mut val, er2)) = der::tlv(er) else { continue };
            if t2 == 0x01 {
                let Some(x) = der::tlv(er2) else { continue };
                (t2, val) = (x.0, x.1);
            }
            if t2 != 0x04 {
                continue;
            }
            let Some((0x30, mut gns, _)) = der::tlv(val) else { continue };
            while let Some((gt, gv, next)) = der::tlv(gns) {
                gns = next;
                match gt {
                    0x82 => {
                        any = true;
                        dns.push(String::from_utf8_lossy(gv).into_owned());
                    }
                    0x87 => {
                        any = true;
                        ips.push(gv.to_vec());
                    }
                    _ => {}
                }
            }
        }
    }
    (any, dns, ips, cn)
}

/// curl's `Curl_cert_hostcheck`: a name or a pattern whose leftmost label alone is `*` (with two dots at least), without
/// regard to case and to one dot at the end.
pub fn hostcheck(pattern: &str, host: &str) -> bool {
    let p = pattern.strip_suffix('.').unwrap_or(pattern);
    let h = host.strip_suffix('.').unwrap_or(host);
    if p.is_empty() || h.is_empty() {
        return false;
    }
    if let Some(rest) = p.strip_prefix("*.") {
        if rest.contains('.') && h.parse::<std::net::IpAddr>().is_err() {
            return match h.split_once('.') {
                Some((label, hrest)) => !label.is_empty() && hrest.eq_ignore_ascii_case(rest),
                None => false,
            };
        }
    }
    p.eq_ignore_ascii_case(h)
}

/// curl's name check of the server's certificate (done before the chain's verdict is read): None when it passes, else
/// curl's words.
fn name_words(leaf: &[u8], host: &str) -> Option<String> {
    let (_, dns, ips, cn) = names(leaf);
    let ip: Option<std::net::IpAddr> = host.trim_start_matches('[').trim_end_matches(']').parse().ok();
    let (relevant, matched) = match ip {
        Some(a) => {
            let bytes = match a {
                std::net::IpAddr::V4(v) => v.octets().to_vec(),
                std::net::IpAddr::V6(v) => v.octets().to_vec(),
            };
            (!ips.is_empty(), ips.contains(&bytes))
        }
        None => (!dns.is_empty(), dns.iter().any(|d| hostcheck(d, host))),
    };
    if relevant {
        return (!matched).then(|| format!("SSL: no alternative certificate subject name matches target hostname '{host}'"));
    }
    match cn {
        Some(cn) if hostcheck(&cn, host) => None,
        Some(cn) => Some(format!("SSL: certificate subject name '{cn}' does not match target hostname '{host}'")),
        None => Some("SSL: unable to obtain common name from peer certificate".into()),
    }
}

/// OpenSSL's verify message and its number, as curl reports a chain it refused.
fn chain_words(
    inner: &rustls::client::WebPkiServerVerifier,
    ee: &CertificateDer,
    inter: &[CertificateDer],
    name: &ServerName,
    now: UnixTime,
) -> String {
    use rustls::CertificateError as C;
    let sent: Vec<der::Cert> = std::iter::once(ee).chain(inter.iter()).filter_map(|c| der::parse(c.as_ref())).collect();
    // a moment when every certificate sent is valid, to tell an untrusted chain from an expired one
    let t = sent.iter().map(|c| c.not_before).max().filter(|&nb| sent.iter().all(|c| c.not_after >= nb));
    let at = |secs: i64| UnixTime::since_unix_epoch(Duration::from_secs(secs.max(0) as u64));
    let verdict = |when: UnixTime| match inner.verify_server_cert(ee, inter, name, &[], when) {
        Err(rustls::Error::InvalidCertificate(c)) => Some(c),
        Err(_) => Some(C::BadEncoding),
        Ok(_) => None,
    };
    let words = |c: &C| -> Option<(&'static str, u32)> {
        match c {
            C::Expired | C::ExpiredContext { .. } => Some(("certificate has expired", 10)),
            C::NotValidYet | C::NotValidYetContext { .. } => Some(("certificate is not yet valid", 9)),
            C::BadSignature => Some(("certificate signature failure", 7)),
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => Some(("unsuitable certificate purpose", 26)),
            C::Revoked => Some(("certificate revoked", 23)),
            C::NotValidForName | C::NotValidForNameContext { .. } => None,
            _ => Some(("", 0)),
        }
    };
    let (w, n) = match verdict(t.map_or(now, at)).as_ref().and_then(words) {
        Some(("", _)) => match net::untrusted(&sent).as_str() {
            "self-signed certificate" => ("self-signed certificate", 18),
            "self-signed certificate in certificate chain" => ("self-signed certificate in certificate chain", 19),
            _ => ("unable to get local issuer certificate", 20),
        },
        Some(x) => x,
        None => match verdict(now).as_ref().and_then(words) {
            Some(("", _)) | None => ("unspecified certificate verification error", 1),
            Some(x) => x,
        },
    };
    format!("SSL certificate OpenSSL verify result: {w} ({n})")
}

/// rustls's check with curl's order (the name first) and curl's words for a refusal.
#[derive(Debug)]
struct Curly {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    host: String,
    words: Mutex<Option<String>>,
}

impl ServerCertVerifier for Curly {
    fn verify_server_cert(
        &self,
        ee: &CertificateDer<'_>,
        inter: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(w) = name_words(ee.as_ref(), &self.host) {
            *self.words.lock().unwrap() = Some(w);
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName));
        }
        let r = self.inner.verify_server_cert(ee, inter, name, ocsp, now);
        if r.is_err() {
            *self.words.lock().unwrap() = Some(match r {
                // a certificate only for its common name: curl takes it, rustls does not (docs/RUST_CLI.md)
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidForName | rustls::CertificateError::NotValidForNameContext { .. },
                )) => {
                    format!("SSL: no alternative certificate subject name matches target hostname '{}'", self.host)
                }
                _ => chain_words(&self.inner, ee, inter, name, now),
            });
        }
        r
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ---- the connection

fn ms(start: Instant) -> u128 {
    start.elapsed().as_millis()
}

fn remaining(deadline: Instant) -> Option<Duration> {
    deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
}

/// The name looked up (getaddrinfo, in a thread so the time limit holds).
fn lookup(host: &str, port: u16, start: Instant, deadline: Instant) -> Result<Vec<SocketAddr>, Fail> {
    let h = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    let name = h.clone();
    std::thread::spawn(move || {
        let _ = tx.send((name.as_str(), port).to_socket_addrs().map(|a| a.collect::<Vec<_>>()));
    });
    match rx.recv_timeout(remaining(deadline).unwrap_or_default()) {
        Ok(Ok(a)) if !a.is_empty() => Ok(a),
        Ok(_) => Err(fail(6, format!("Could not resolve host: {h}"))),
        Err(_) => Err(fail(28, format!("Resolving timed out after {} milliseconds", ms(start)))),
    }
}

/// A TCP connection to one of the addresses, curl's way: the addresses of the first family in turn, those of the other
/// family as well once 200 ms have passed (or the first family has failed); the first to connect is used.
fn connect(addrs: Vec<SocketAddr>, host: &str, port: u16, start: Instant, deadline: Instant) -> Result<TcpStream, Fail> {
    let v4_first = addrs[0].is_ipv4();
    let (first, other): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs.into_iter().partition(|a| a.is_ipv4() == v4_first);
    let (tx, rx) = std::sync::mpsc::channel::<Result<TcpStream, std::io::Error>>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let attempt = move |list: Vec<SocketAddr>| -> Result<TcpStream, std::io::Error> {
        let mut last = std::io::Error::from_raw_os_error(libc::ECONNREFUSED);
        for a in list {
            let Some(left) = remaining(deadline) else { return Err(std::io::Error::from(std::io::ErrorKind::TimedOut)) };
            match TcpStream::connect_timeout(&a, left) {
                Ok(s) => return Ok(s),
                Err(e) => last = e,
            }
        }
        Err(last)
    };
    let mut pending = 1;
    {
        let tx = tx.clone();
        let go_tx = go_tx.clone();
        std::thread::spawn(move || {
            let r = attempt(first);
            if r.is_err() {
                let _ = go_tx.send(());
            }
            let _ = tx.send(r);
        });
    }
    if !other.is_empty() {
        pending += 1;
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _ = go_rx.recv_timeout(EYEBALLS);
            let _ = tx.send(attempt(other));
        });
    }
    drop(tx);
    drop(go_tx);
    let mut last = None;
    while pending > 0 {
        match rx.recv_timeout(remaining(deadline).unwrap_or_default()) {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => {
                pending -= 1;
                last = Some(e);
            }
            Err(_) => return Err(fail(28, format!("Connection timed out after {} milliseconds", ms(start)))),
        }
    }
    match last {
        Some(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut) => {
            Err(fail(28, format!("Connection timed out after {} milliseconds", ms(start))))
        }
        _ => Err(fail(7, format!("Failed to connect to {host}:{port} after {} ms: Could not connect to server", ms(start)))),
    }
}

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// The TLS handshake, the certificate checked as curl checks it.
fn handshake(tcp: TcpStream, host: &str, start: Instant, deadline: Instant) -> Result<Tls, Fail> {
    let roots = roots()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
        .build()
        .map_err(|e| fail(77, format!("error setting certificate verify locations: {e}")))?;
    let bare = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let v = Arc::new(Curly { inner, host: bare.clone(), words: Mutex::new(None) });
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| fail(35, format!("TLS connect error: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(v.clone())
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from(bare).map_err(|_| fail(3, "URL rejected: Bad hostname"))?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| fail(35, format!("TLS connect error: {e}")))?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        let Some(left) = remaining(deadline) else {
            return Err(fail(28, format!("SSL connection timeout after {} milliseconds", ms(start))));
        };
        let _ = s.sock.set_read_timeout(Some(left));
        let _ = s.sock.set_write_timeout(Some(left));
        if let Err(e) = s.conn.complete_io(&mut s.sock) {
            if let Some(w) = v.words.lock().unwrap().take() {
                return Err(fail(60, w));
            }
            if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) {
                return Err(fail(28, format!("SSL connection timeout after {} milliseconds", ms(start))));
            }
            let why = match e.get_ref().and_then(|x| x.downcast_ref::<rustls::Error>()) {
                Some(t) => t.to_string(),
                None => strerror(&e),
            };
            return Err(fail(35, format!("TLS connect error: {why}")));
        }
    }
    Ok(s)
}

// ---- the response

enum ReadErr {
    /// the server closed the connection properly (TLS close_notify)
    Eof,
    Fail(Fail),
}

/// A response read from the connection, with what was read ahead.
struct Conn {
    s: Tls,
    buf: Vec<u8>,
    pos: usize,
    start: Instant,
    deadline: Instant,
    /// the body's bytes so far and its length when known, for the timeout's words
    got: u64,
    size: Option<u64>,
}

impl Conn {
    fn timeout(&self) -> Fail {
        match self.size {
            Some(n) => {
                fail(28, format!("Operation timed out after {} milliseconds with {} out of {n} bytes received", ms(self.start), self.got))
            }
            None => fail(28, format!("Operation timed out after {} milliseconds with {} bytes received", ms(self.start), self.got)),
        }
    }

    /// More bytes into the buffer.
    fn fill(&mut self) -> Result<(), ReadErr> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let Some(left) = remaining(self.deadline) else { return Err(ReadErr::Fail(self.timeout())) };
        let _ = self.s.sock.set_read_timeout(Some(left));
        let mut b = [0u8; 16384];
        match self.s.read(&mut b) {
            Ok(0) => Err(ReadErr::Eof),
            Ok(n) => {
                self.buf.extend_from_slice(&b[..n]);
                Ok(())
            }
            Err(e) => Err(ReadErr::Fail(match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => self.timeout(),
                std::io::ErrorKind::UnexpectedEof => {
                    fail(56, "TLS: the connection was closed without close_notify (unexpected eof while reading)")
                }
                std::io::ErrorKind::ConnectionReset => fail(56, "Recv failure: Connection reset by peer"),
                _ => fail(56, format!("Recv failure: {}", strerror(&e))),
            })),
        }
    }

    /// One header line (with its line end), None at a clean end before any byte of it.
    fn line(&mut self, total: &mut usize) -> Result<Option<Vec<u8>>, ReadErr> {
        loop {
            if let Some(i) = self.buf[self.pos..].iter().position(|&c| c == b'\n') {
                let l = self.buf[self.pos..self.pos + i + 1].to_vec();
                self.pos += i + 1;
                *total += l.len();
                if *total > MAX_HEADERS {
                    return Err(ReadErr::Fail(fail(56, format!("Too large response headers: {} > {MAX_HEADERS}", *total))));
                }
                return Ok(Some(l));
            }
            if self.buf.len() - self.pos + *total > MAX_HEADERS {
                return Err(ReadErr::Fail(fail(
                    56,
                    format!("Too large response headers: {} > {MAX_HEADERS}", self.buf.len() - self.pos + *total),
                )));
            }
            match self.fill() {
                Ok(()) => {}
                Err(ReadErr::Eof) if self.pos == self.buf.len() => return Ok(None),
                Err(ReadErr::Eof) => {
                    let l = self.buf[self.pos..].to_vec();
                    self.pos = self.buf.len();
                    *total += l.len();
                    return Ok(Some(l));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Up to `max` bytes of the body.
    fn chunk(&mut self, max: usize) -> Result<Vec<u8>, ReadErr> {
        if self.pos == self.buf.len() {
            self.fill()?;
        }
        let n = max.min(self.buf.len() - self.pos);
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }
}

/// A response's head: the status and the headers (names in lower case, values trimmed, as Latin-1 text).
struct Head {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Head {
    fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// Reads a response's head (1xx answers skipped), checking each Content-Length against the size limit as curl does while
/// the headers arrive.
fn read_head(c: &mut Conn, max_filesize: u64) -> Result<Head, Fail> {
    let mut total = 0usize;
    let mut first_ever = true;
    loop {
        let status_line = match c.line(&mut total) {
            Ok(Some(l)) => l,
            Ok(None) | Err(ReadErr::Eof) => {
                return Err(if first_ever { fail(52, "Empty reply from server") } else { fail(56, "Connection died") });
            }
            Err(ReadErr::Fail(f)) => return Err(f),
        };
        first_ever = false;
        let sl = latin1(&status_line);
        let sl = sl.trim_end_matches(['\r', '\n']);
        if !sl.starts_with("HTTP/") {
            return Err(fail(1, "Received HTTP/0.9 when not allowed"));
        }
        let mut parts = sl.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        let code = parts.next().unwrap_or_default();
        if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(fail(8, "Weird server reply"));
        }
        let status: u16 = code.parse().unwrap_or(0);
        let mut headers = Vec::new();
        loop {
            let l = match c.line(&mut total) {
                Ok(Some(l)) => l,
                Ok(None) | Err(ReadErr::Eof) => return Err(fail(56, "Connection died")),
                Err(ReadErr::Fail(f)) => return Err(f),
            };
            let t = latin1(&l);
            let t = t.trim_end_matches(['\r', '\n']);
            if t.is_empty() {
                break;
            }
            if let Some((k, v)) = t.split_once(':') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim().to_string();
                let bodyless = (100..200).contains(&status) || status == 204 || status == 304;
                if k == "content-length" && !bodyless {
                    let chunked = headers.iter().any(|(hk, hv): &(String, String)| hk == "transfer-encoding" && is_chunked(hv));
                    if !chunked {
                        let n: u64 = v.parse().map_err(|_| fail(8, format!("Invalid Content-Length: {v}")))?;
                        if max_filesize > 0 && n > max_filesize {
                            return Err(fail(63, "Maximum file size exceeded"));
                        }
                    }
                }
                headers.push((k, v));
            }
        }
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        return Ok(Head { status, headers });
    }
}

fn is_chunked(v: &str) -> bool {
    v.split(',').next_back().is_some_and(|t| t.trim().eq_ignore_ascii_case("chunked"))
}

/// The output file as curl writes it: opened at the first byte (created 0666 less the umask, or truncated), each piece
/// written whole or curl's error.
struct Out<'a> {
    path: &'a Path,
    f: Option<std::fs::File>,
    written: u64,
    max: u64,
}

impl Out<'_> {
    fn open(&mut self, n: usize) -> Result<(), Fail> {
        if self.f.is_none() {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o666)
                .open(self.path)
                .map_err(|_| fail(23, format!("client returned ERROR on write of {n} bytes")))?;
            self.f = Some(f);
        }
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<(), Fail> {
        if data.is_empty() {
            return Ok(());
        }
        let room = if self.max > 0 { self.max.saturating_sub(self.written) } else { u64::MAX };
        let (now, excess) = if data.len() as u64 > room { (&data[..room as usize], true) } else { (data, false) };
        if !now.is_empty() {
            self.open(now.len())?;
            let f = self.f.as_mut().unwrap();
            let mut done = 0;
            while done < now.len() {
                match f.write(&now[done..]) {
                    Ok(0) | Err(_) => {
                        return Err(fail(23, format!("Failure writing output to destination, passed {} returned {done}", now.len())));
                    }
                    Ok(k) => done += k,
                }
            }
            self.written += now.len() as u64;
        }
        if excess {
            return Err(fail(63, format!("Exceeded the maximum allowed file size ({}) with {} bytes", self.max, self.written)));
        }
        Ok(())
    }

    /// The end of a good transfer: an empty file when nothing came.
    fn finish(&mut self) -> Result<(), Fail> {
        self.open(0)
    }
}

/// The body: chunked, of a known length, or until the server closes.
fn read_body(c: &mut Conn, head: &Head, out: &mut Out) -> Result<(), Fail> {
    let bodyless = (100..200).contains(&head.status) || head.status == 204 || head.status == 304;
    if bodyless {
        return Ok(());
    }
    let eof = |e: ReadErr, f: Fail| match e {
        ReadErr::Eof => f,
        ReadErr::Fail(x) => x,
    };
    if head.get("transfer-encoding").is_some_and(is_chunked) {
        let mut total = 0usize;
        loop {
            let line = match c.line(&mut total) {
                Ok(Some(l)) => l,
                Ok(None) => return Err(fail(18, "transfer closed with outstanding read data remaining")),
                Err(e) => return Err(eof(e, fail(18, "transfer closed with outstanding read data remaining"))),
            };
            total = 0;
            let t = latin1(&line);
            let hex = t.trim_end_matches(['\r', '\n']).split(';').next().unwrap_or_default().trim();
            if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) || hex.len() > 16 {
                return Err(fail(56, "Illegal or missing hexadecimal sequence in chunked-encoding"));
            }
            let mut n =
                u64::from_str_radix(hex, 16).map_err(|_| fail(56, "Illegal or missing hexadecimal sequence in chunked-encoding"))?;
            if n == 0 {
                // trailers, until the empty line
                loop {
                    match c.line(&mut total) {
                        Ok(Some(l)) if l == b"\r\n" || l == b"\n" => return Ok(()),
                        Ok(Some(_)) => {}
                        Ok(None) | Err(ReadErr::Eof) => return Ok(()),
                        Err(ReadErr::Fail(f)) => return Err(f),
                    }
                }
            }
            while n > 0 {
                let piece =
                    c.chunk(n.min(16384) as usize).map_err(|e| eof(e, fail(18, "transfer closed with outstanding read data remaining")))?;
                n -= piece.len() as u64;
                c.got += piece.len() as u64;
                out.write(&piece)?;
            }
            // the chunk's line end
            match c.line(&mut total) {
                Ok(Some(_)) => total = 0,
                Ok(None) => return Err(fail(18, "transfer closed with outstanding read data remaining")),
                Err(e) => return Err(eof(e, fail(18, "transfer closed with outstanding read data remaining"))),
            }
        }
    }
    if let Some(cl) = head.get("content-length") {
        let n: u64 = cl.parse().map_err(|_| fail(8, format!("Invalid Content-Length: {cl}")))?;
        c.size = Some(n);
        let mut left = n;
        while left > 0 {
            let piece =
                c.chunk(left.min(16384) as usize).map_err(|e| eof(e, fail(18, format!("end of response with {left} bytes missing"))))?;
            left -= piece.len() as u64;
            c.got += piece.len() as u64;
            out.write(&piece)?;
        }
        return Ok(());
    }
    loop {
        match c.chunk(16384) {
            Ok(piece) => {
                c.got += piece.len() as u64;
                out.write(&piece)?;
            }
            Err(ReadErr::Eof) => return Ok(()),
            Err(ReadErr::Fail(f)) => return Err(f),
        }
    }
}

/// The whole transfer, redirects included.
fn transfer(r: &Request) -> Result<(), Fail> {
    let start = Instant::now();
    let deadline = start + r.max_time;
    let mut url = parse_url(r.url).ok_or_else(|| fail(3, "URL rejected: Malformed input to a URL function"))?;
    if url.scheme != "https" {
        return Err(fail(1, format!("Protocol \"{}\" is disabled", url.scheme)));
    }
    let first = (url.scheme.clone(), url.host.to_ascii_lowercase(), url.port);
    let mut out = Out { path: r.out, f: None, written: 0, max: r.max_filesize };
    let mut follows = 0u32;
    loop {
        let addrs = lookup(&url.host, url.port, start, deadline)?;
        let tcp = connect(addrs, &url.host, url.port, start, deadline)?;
        let _ = tcp.set_nodelay(true);
        let mut s = handshake(tcp, &url.host, start, deadline)?;
        let host_header = if url.port == 443 { url.host.clone() } else { format!("{}:{}", url.host, url.port) };
        let mut req = format!("GET {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n", url.path);
        if let Some(a) = r.auth {
            if (url.scheme.clone(), url.host.to_ascii_lowercase(), url.port) == first {
                req.push_str(&format!("Authorization: {a}\r\n"));
            }
        }
        req.push_str("\r\n");
        let Some(left) = remaining(deadline) else {
            return Err(fail(28, format!("Operation timed out after {} milliseconds with 0 bytes received", ms(start))));
        };
        let _ = s.sock.set_write_timeout(Some(left));
        if let Err(e) = s.write_all(req.as_bytes()).and_then(|_| s.flush()) {
            return Err(fail(55, format!("Send failure: {}", strerror(&e))));
        }
        let mut c = Conn { s, buf: Vec::new(), pos: 0, start, deadline, got: 0, size: None };
        let head = read_head(&mut c, r.max_filesize)?;
        if matches!(head.status, 300 | 301 | 302 | 303 | 307 | 308) {
            if let Some(loc) = head.get("location").filter(|l| !l.is_empty()) {
                if follows >= MAX_REDIRS {
                    return Err(fail(47, format!("Maximum ({MAX_REDIRS}) redirects followed")));
                }
                follows += 1;
                let next = resolve_location(&url, loc)?;
                if next.scheme != "https" {
                    return Err(fail(1, format!("Protocol \"{}\" is disabled (in redirect)", next.scheme)));
                }
                url = next;
                continue;
            }
        }
        if head.status >= 400 {
            return Err(fail(22, format!("The requested URL returned error: {}", head.status)));
        }
        read_body(&mut c, &head, &mut out)?;
        return out.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz").unwrap();
        assert_eq!(
            (u.scheme.as_str(), u.host.as_str(), u.port, u.path.as_str()),
            ("https", "download.db-ip.com", 443, "/free/dbip-country-lite-2026-11.mmdb.gz")
        );
        let u = parse_url("HTTPS://h.test:8443?x=1#f").unwrap();
        assert_eq!((u.scheme.as_str(), u.port, u.path.as_str()), ("https", 8443, "/?x=1"));
        assert_eq!(parse_url("https://h/a/./b/../c").unwrap().path, "/a/c");
        assert!(parse_url("https://h:99999/").is_none());
        let base = parse_url("https://a.test/dir/file?q").unwrap();
        assert_eq!(resolve_location(&base, "/x y").unwrap().path, "/x%20y");
        assert_eq!(resolve_location(&base, "other").unwrap().path, "/dir/other");
        assert_eq!(resolve_location(&base, "../up#frag").unwrap().path, "/up");
        assert_eq!(resolve_location(&base, "?z").unwrap().path, "/dir/file?z");
        assert_eq!(resolve_location(&base, "//b.test/p").unwrap().host, "b.test");
        assert_eq!(resolve_location(&base, "http://a.test/").unwrap().scheme, "http");
        assert_eq!(resolve_location(&base, "ftp://a.test/").unwrap_err().code, 1);
    }

    #[test]
    fn the_time_limit_holds() {
        // a server on loopback that takes the connection and never answers: the handshake runs out of time, curl's 28
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let held: Vec<_> = l.incoming().take(1).collect();
            std::thread::sleep(Duration::from_secs(3));
            drop(held);
        });
        let out = std::env::temp_dir().join(format!("heimdall-fetch-timeout-{}", std::process::id()));
        let url = format!("https://127.0.0.1:{port}/x");
        let start = Instant::now();
        let r = transfer(&Request { url: &url, out: &out, max_filesize: 10, auth: None, max_time: Duration::from_millis(400) });
        assert!(start.elapsed() < Duration::from_secs(2));
        match r {
            // (77 where this computer has no authorities file to read)
            Err(f) => assert!(f.code == 28 || f.code == 77, "{f:?}"),
            Ok(()) => panic!("no answer is not a download"),
        }
        assert!(!out.exists());
    }

    #[test]
    fn host_patterns_as_curl() {
        assert!(hostcheck("www.Example.com", "www.example.com."));
        assert!(hostcheck("*.example.com", "www.example.com"));
        assert!(!hostcheck("*.example.com", "example.com"));
        assert!(!hostcheck("*.example.com", "a.b.example.com"));
        assert!(!hostcheck("*.com", "example.com"));
        assert!(!hostcheck("", "x"));
    }
}
