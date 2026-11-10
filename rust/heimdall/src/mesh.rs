//! The mesh (Go: internal/mesh, docs/MESH.md): alerts shared between the Heimdall instances one owner runs, and nothing
//! else. Deliberately small, as in Go:
//!
//! - One endpoint: a peer may POST alert summaries to /mesh/v1/alerts (at most 50, 64 KiB). No shell, no files, no relay,
//!   no commands. A received alert goes to the outputs (log, API) only: never to containment, quarantine or the correlator.
//! - Owner-enrolled peers only (`/etc/heimdall/mesh-peers.json`, root's): each instance has an ed25519 key, named by its
//!   fingerprint. Mutual TLS 1.3 (rustls, the `tls12` feature left out): both sides present a certificate for their key, and
//!   the key in it is checked against the enrolled fingerprints by our own verifiers; there is no certificate authority,
//!   and a certificate's names and dates mean nothing. The peers file is read on every handshake.
//! - The identity is the Go daemon's: `mesh_dir/key.pem` (PKCS#8, made by `heimdalld mesh init` or by either daemon).
//! - Off by default: no listener without `mesh_listen`, nothing sent without an enrolled peer. In charge only.
//!
//! Threads: one sender per enrolled peer (asleep until an alert is queued) and, with `mesh_listen`, one listener (a short
//! thread per connection).

use crate::alert::{Alert, Sink};
use crate::detect::{self, Peer};
use crate::event::{Event, Fields, Finding, Severity};
use crate::gojson;
use crate::gostruct::{self, Field, Ty, Val};
use crate::gotext;
use crate::gotime::Time;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DETECTOR_ID: &str = "mesh";
pub const PATH: &str = "/mesh/v1/alerts";
pub const DEFAULT_PEERS: &str = "/etc/heimdall/mesh-peers.json";

const MAX_BODY: usize = 64 << 10;
const MAX_BATCH: usize = 50;
const MAX_SUMMARY: usize = 500;
const QUEUE_LEN: usize = 256;
const RATE_PER_MIN: f64 = 120.0;
const BACKOFF_FIRST: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// At most this many connections are served at once; more are closed (Go has no cap; one owner has a handful of peers).
const MAX_CONNS: usize = 16;

// ---- the identity ----

/// This instance's key (Go: Identity), and the self-signed certificate it presents.
#[derive(Clone)]
pub struct Identity {
    pub fingerprint: String,
    pkcs8: Vec<u8>,
    cert: Vec<u8>,
}

impl Identity {
    /// The self-signed certificate this instance presents (DER).
    pub fn certificate(&self) -> &[u8] {
        &self.cert
    }
}

/// Go's Fingerprint: "hm1-" and the first 32 base32 characters (lowercase, no padding) of the public key's SHA-256.
pub fn fingerprint(public: &[u8]) -> String {
    use sha2::Digest;
    let sum = sha2::Sha256::digest(public);
    format!("hm1-{}", &base32_lower(&sum)[..32])
}

fn base32_lower(b: &[u8]) -> String {
    const A: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0u32);
    for &x in b {
        acc = (acc << 8) | x as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The PKCS#8 form Go's x509.MarshalPKCS8PrivateKey writes for an ed25519 seed (version 1, no public key).
fn pkcs8_v1(seed: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    v.extend_from_slice(seed);
    v
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(b: &[u8]) -> String {
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        if c == b'=' {
            break;
        }
        let v = B64.iter().position(|&x| x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Go's pem.Decode for the first block: its type and bytes.
fn pem_first(text: &[u8]) -> Option<(String, Vec<u8>)> {
    let s = std::str::from_utf8(text).ok()?;
    let start = s.find("-----BEGIN ")?;
    let rest = &s[start + 11..];
    let (label, rest) = rest.split_once("-----")?;
    let end = rest.find(&format!("-----END {label}-----"))?;
    // headers (Proc-Type: ...) end at an empty line; Go's mesh keys have none
    let body = &rest[..end];
    let body = if body.contains(':') { body.split_once("\n\n").map_or(body, |x| x.1) } else { body };
    Some((label.to_string(), b64_decode(body)?))
}

/// Reads the key in `dir` (key.pem) or makes one, as Go's LoadOrCreate: the key PKCS#8 in PEM (0600), the fingerprint also
/// written to `dir/fingerprint` (0644).
pub fn load_or_create(dir: &str) -> Result<Identity, String> {
    let path = format!("{}/key.pem", dir.trim_end_matches('/'));
    match std::fs::read(&path) {
        Ok(b) => {
            let Some((label, der)) = pem_first(&b) else { return Err(format!("{path} is not a key")) };
            if label != "PRIVATE KEY" {
                return Err(format!("{path} is not a key"));
            }
            identity(der).map_err(|_| {
                if der_has_ed25519(&b) {
                    format!("{path}: x509: invalid Ed25519 private key")
                } else {
                    format!("{path} is not an ed25519 key")
                }
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create(dir, &path),
        Err(e) => Err(crate::sources::go_path_error("open", &path, &e)),
    }
}

fn der_has_ed25519(pem: &[u8]) -> bool {
    pem_first(pem).is_some_and(|(_, d)| d.windows(5).any(|w| w == [0x06, 0x03, 0x2b, 0x65, 0x70]))
}

fn create(dir: &str, path: &str) -> Result<Identity, String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| crate::sources::go_path_error("mkdir", dir, &e))?;
    let mut seed = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed).map_err(|_| "no random numbers".to_string())?;
    let der = pkcs8_v1(&seed);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    let b = b64_encode(&der);
    for line in b.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| crate::sources::go_path_error("open", path, &e))?;
    f.write_all(pem.as_bytes()).map_err(|e| crate::sources::go_path_error("write", path, &e))?;
    let id = identity(der).map_err(|e| format!("{path}: {e}"))?;
    let _ =
        crate::state::write_mode(&format!("{}/fingerprint", dir.trim_end_matches('/')), format!("{}\n", id.fingerprint).as_bytes(), 0o644);
    Ok(id)
}

fn identity(pkcs8: Vec<u8>) -> Result<Identity, String> {
    let kp = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pkcs8).map_err(|e| e.to_string())?;
    let cert = self_signed(&kp);
    Ok(Identity { fingerprint: fingerprint(kp.public_key().as_ref()), pkcs8, cert })
}

// a little DER, for the certificate

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 128 {
        v.push(n as u8);
    } else if n < 256 {
        v.extend_from_slice(&[0x81, n as u8]);
    } else {
        v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    v.extend_from_slice(content);
    v
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

fn utc_time(t: Time) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = t.utc().civil();
    tlv(0x17, format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100).as_bytes())
}

/// A self-signed certificate for the key, as Go's mesh makes one: v3, a random serial, no names, valid from an hour ago for
/// ten years, digital signature, server and client authentication. Only its key matters to a peer.
fn self_signed(kp: &Ed25519KeyPair) -> Vec<u8> {
    let mut serial = [0u8; 8];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut serial);
    serial[0] &= 0x3f; // positive, below 2^62 as Go's
    serial[0] |= 0x01;
    let now = Time::now();
    let alg = seq(&[OID_ED25519]);
    let spki = seq(&[&alg, &tlv(0x03, &[&[0u8][..], kp.public_key().as_ref()].concat())]);
    let key_usage = seq(&[&[0x06, 0x03, 0x55, 0x1d, 0x0f], &[0x01, 0x01, 0xff], &tlv(0x04, &[0x03, 0x02, 0x07, 0x80])]);
    let server_auth = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    let client_auth = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    let ext_key_usage = seq(&[&[0x06, 0x03, 0x55, 0x1d, 0x25], &tlv(0x04, &seq(&[&server_auth, &client_auth]))]);
    let tbs = seq(&[
        &tlv(0xa0, &[0x02, 0x01, 0x02]),
        &tlv(0x02, &serial),
        &alg,
        &seq(&[]),
        &seq(&[&utc_time(now.add(-3_600_000_000_000)), &utc_time(now.add(10 * 365 * 24 * 3_600_000_000_000))]),
        &seq(&[]),
        &spki,
        &tlv(0xa3, &seq(&[&key_usage, &ext_key_usage])),
    ]);
    let sig = kp.sign(&tbs);
    seq(&[&tbs, &alg, &tlv(0x03, &[&[0u8][..], sig.as_ref()].concat())])
}

/// One DER element: (tag, content, rest).
fn der_next(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&l, b) = b.split_first()?;
    let (len, b) = if l < 0x80 {
        (l as usize, b)
    } else {
        let n = (l & 0x7f) as usize;
        if n == 0 || n > 3 || b.len() < n {
            return None;
        }
        (b[..n].iter().fold(0usize, |a, &x| a << 8 | x as usize), &b[n..])
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

/// The fingerprint of the ed25519 key in a presented certificate (Go: peerFingerprint); None for anything else.
pub fn cert_fingerprint(cert: &[u8]) -> Option<String> {
    let (0x30, c, _) = der_next(cert)? else { return None };
    let (0x30, mut t, _) = der_next(c)? else { return None };
    if t.first() == Some(&0xa0) {
        t = der_next(t)?.2;
    }
    for _ in 0..5 {
        t = der_next(t)?.2; // serial, signature, issuer, validity, subject
    }
    let (0x30, spki, _) = der_next(t)? else { return None };
    let (0x30, alg, rest) = der_next(spki)? else { return None };
    if alg != OID_ED25519 {
        return None;
    }
    let (0x03, bits, _) = der_next(rest)? else { return None };
    match bits {
        [0, key @ ..] if key.len() == 32 => Some(fingerprint(key)),
        _ => None,
    }
}

// ---- the verifiers: the key itself, against the owner's list ----

#[derive(Debug)]
struct PeerCheck {
    /// a client checks one peer's key; a server any enrolled key
    want: Option<String>,
    peers_path: String,
    provider: Arc<CryptoProvider>,
}

fn general(m: String) -> rustls::Error {
    rustls::Error::General(m)
}

impl PeerCheck {
    fn check(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let fp = cert_fingerprint(end_entity.as_ref()).ok_or_else(|| general("not an ed25519 key".into()))?;
        match &self.want {
            Some(w) if *w != fp => Err(general(format!("peer key {fp} is not the enrolled {w}"))),
            Some(_) => Ok(()),
            None => peer_by_fingerprint(&self.peers_path, &fp).map(|_| ()).ok_or_else(|| general(format!("key {fp} is not enrolled"))),
        }
    }

    fn tls13(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoSignatureSchemesInCommon));
        }
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
}

impl ServerCertVerifier for PeerCheck {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity).map(|_| ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls13RequiredForQuic))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls13(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for PeerCheck {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity).map(|_| ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls13RequiredForQuic))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls13(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

fn peer_by_fingerprint(peers_path: &str, fp: &str) -> Option<Peer> {
    detect::load_peers_checked(peers_path).ok()?.into_iter().find(|p| p.fingerprint == fp)
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn key_der(id: &Identity) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.pkcs8.clone()))
}

/// The client settings for one peer: TLS 1.3, this instance's certificate, the server's key must be `want`.
pub fn client_config(id: &Identity, want: &str, peers_path: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    let p = provider();
    let c = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PeerCheck { want: Some(want.into()), peers_path: peers_path.into(), provider: p }))
        .with_client_auth_cert(vec![CertificateDer::from(id.cert.clone())], key_der(id))
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(c))
}

/// The server settings: TLS 1.3, a client certificate required, its key must be enrolled.
pub fn server_config(id: &Identity, peers_path: &str) -> Result<Arc<rustls::ServerConfig>, String> {
    let p = provider();
    let c = rustls::ServerConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(Arc::new(PeerCheck { want: None, peers_path: peers_path.into(), provider: p }))
        .with_single_cert(vec![CertificateDer::from(id.cert.clone())], key_der(id))
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(c))
}

/// One request to a peer over a fresh connection (connect 5 s, all of it 10 s, as Go's client): the status, or why not.
pub fn post(cfg: &Arc<rustls::ClientConfig>, addr: &str, method: &str, path: &str, body: &[u8]) -> Result<u16, String> {
    let sa: SocketAddr = addr.parse().map_err(|_| format!("bad address {addr}"))?;
    let by = Instant::now() + Duration::from_secs(10);
    let tcp = TcpStream::connect_timeout(&sa, Duration::from_secs(5))
        .map_err(|e| format!("dial tcp {addr}: {}", crate::sources::go_errno(&e)))?;
    let left = || by.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
    let _ = tcp.set_write_timeout(Some(left()));
    let _ = tcp.set_read_timeout(Some(left()));
    let conn = rustls::ClientConnection::new(cfg.clone(), ServerName::IpAddress(sa.ip().into())).map_err(|e| e.to_string())?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(&[head.as_bytes(), body].concat()).map_err(|e| e.to_string())?;
    s.flush().map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let _ = s.sock.set_read_timeout(Some(left()));
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if !raw.is_empty() && e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
        if raw.len() > 8192 || crate::response::complete(&raw) {
            break;
        }
        if Instant::now() >= by {
            return Err("timeout".into());
        }
    }
    let line = raw.split(|c| *c == b'\r').next().unwrap_or_default();
    std::str::from_utf8(line)
        .ok()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| "malformed HTTP response".into())
}

// ---- alerts on the wire ----

fn rank(s: &str) -> i32 {
    match s {
        "critical" => 2,
        "warning" => 1,
        _ => 0,
    }
}

/// Go's clip: past 500 bytes, cut and "..." (a cut letter is written as Go's encoder writes a stray byte).
fn clip_summary(s: &str) -> String {
    if s.len() > MAX_SUMMARY {
        gotext::lossy(&[&s.as_bytes()[..MAX_SUMMARY], b"..."].concat())
    } else {
        s.to_string()
    }
}

fn clip_to(s: &str, n: usize) -> String {
    gotext::lossy(&s.as_bytes()[..s.len().min(n)])
}

/// One alert as it travels (Go: Wire, JSON): time, detector, severity, summary (bounded) and source; never the event's text
/// or fields.
pub fn wire(a: &Alert) -> String {
    let mut b = String::new();
    let mut o = gojson::ObjectWriter::new(&mut b);
    o.str("time", &a.time.rfc3339_nano());
    o.str("detector_id", &a.detector_id);
    o.str("severity", a.severity.as_str());
    o.str("summary", &clip_summary(&a.summary));
    o.str("source", &a.source);
    o.end();
    b
}

static WIRE: Ty = Ty::Struct(
    "mesh.Wire",
    &[
        Field("time", &Ty::Time, false),
        Field("detector_id", &Ty::Str, false),
        Field("severity", &Ty::Str, false),
        Field("summary", &Ty::Str, false),
        Field("source", &Ty::Str, false),
    ],
);
static BATCH: Ty = Ty::Struct("mesh.batch", &[Field("alerts", &Ty::Slice(&WIRE), false)]);

/// A peer's alert as a local one (Go: received): labelled with the peer, text bounded, severity kept but never above
/// critical (anything unknown is info), only the labels it carried.
pub fn received(peer: &str, w: &Val) -> Alert {
    let s = |k: &str| gostruct::str_field(&WIRE, w, k);
    let sev = match s("severity") {
        "critical" => Severity::Critical,
        "warning" => Severity::Warning,
        _ => Severity::Info,
    };
    let t = match gostruct::field(&WIRE, w, "time") {
        Some(Val::Time(t)) => *t,
        _ => Time::default(),
    };
    let (y, mo, d, h, mi, sec) = t.utc().civil();
    let remote_time = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{sec:02}Z");
    let fields: Fields = [
        ("peer".to_string(), peer.to_string()),
        ("remote_detector".to_string(), clip_to(s("detector_id"), 40)),
        ("remote_time".to_string(), remote_time),
        ("remote_source".to_string(), clip_to(s("source"), 40)),
    ]
    .into_iter()
    .collect();
    let ev = Event { source: format!("mesh:{peer}"), kind: "mesh_alert".into(), time: Time::now(), fields, ..Default::default() };
    Alert::from_finding(&Finding::new(DETECTOR_ID, sev, format!("[{peer}] {}", clip_summary(s("summary"))), &ev))
}

/// The answer to one request from a peer whose key the handshake proved (Go: receive): the status, and the alerts to write
/// (received in order; a 429 keeps those before the limit).
pub fn receive(method: &str, path: &str, body: &[u8], peer: Option<&Peer>, bucket: &mut Bucket, now: Instant) -> (u16, Vec<Alert>) {
    if path != PATH || method != "POST" {
        return (404, Vec::new());
    }
    let Some(p) = peer else { return (403, Vec::new()) };
    // Go: json.NewDecoder(http.MaxBytesReader(body, 64 KiB)).Decode: the first value, which must end within the limit
    let body = &body[..body.len().min(MAX_BODY)];
    let Ok(v) = gojson::parse_first(body) else { return (400, Vec::new()) };
    let mut cx = gostruct::Ctx { top: "mesh.batch", first: None };
    let mut val = gostruct::zero(&BATCH);
    gostruct::read(&BATCH, &v, &mut val, "", &mut cx);
    if cx.first.is_some() || !matches!(v, gojson::Value::Object(_) | gojson::Value::Null) {
        return (400, Vec::new());
    }
    let items = match gostruct::field(&BATCH, &val, "alerts") {
        Some(Val::Slice(Some(items))) => items.clone(),
        _ => Vec::new(),
    };
    if items.len() > MAX_BATCH {
        return (400, Vec::new());
    }
    let mut out = Vec::new();
    for w in &items {
        if !bucket.take(now) {
            return (429, out);
        }
        out.push(received(&p.name, w));
    }
    (204, out)
}

/// A token bucket: 120 a minute, the burst the same (Go: bucket).
#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    level: f64,
    last: Instant,
}

impl Bucket {
    pub fn new(now: Instant) -> Bucket {
        Bucket { level: RATE_PER_MIN, last: now }
    }
    pub fn take(&mut self, now: Instant) -> bool {
        self.level = (self.level + now.saturating_duration_since(self.last).as_secs_f64() / 60.0 * RATE_PER_MIN).min(RATE_PER_MIN);
        self.last = now;
        if self.level < 1.0 {
            return false;
        }
        self.level -= 1.0;
        true
    }
}

// ---- the node ----

/// The mesh's sink (Go: Node.Write): every alert passed on first, then local ones of at least the minimum severity queued
/// for each peer; a received alert or an integration alert is never sent (no loops, no relaying).
pub struct MeshSink {
    next: Box<dyn Sink>,
    min: i32,
    queues: Vec<SyncSender<String>>,
    pub dropped: Arc<Mutex<usize>>,
}

impl Sink for MeshSink {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        let r = self.next.write(a);
        if a.detector_id == DETECTOR_ID || a.detector_id == "integration" || rank(a.severity.as_str()) < self.min {
            return r;
        }
        let w = wire(a);
        for q in &self.queues {
            if let Err(TrySendError::Full(_)) = q.try_send(w.clone()) {
                *self.dropped.lock().unwrap_or_else(|p| p.into_inner()) += 1;
            }
        }
        r
    }
}

/// What the mesh needs to start (Go: Node's fields).
pub struct Node {
    pub id: Identity,
    pub peers_path: String,
    pub listen: String,
    pub min_severity: String,
    /// received alerts go here (the outputs only)
    pub out: Arc<dyn Fn(Alert) + Send + Sync>,
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Node {
    /// Starts one sender per enrolled peer and, with `listen`, the listener; returns the sink to put in front of `next`
    /// (Go: Start, and the node as the sink). Errors as Go's: the peers file refused, a listen address that is not one IP.
    pub fn start(self, next: Box<dyn Sink>) -> Result<(MeshSink, usize), (String, Box<dyn Sink>)> {
        let peers = match detect::load_peers_checked(&self.peers_path) {
            Ok(p) => p,
            Err(e) => return Err((e, next)),
        };
        let mut queues = Vec::new();
        for p in peers.iter().filter(|p| p.fingerprint != self.id.fingerprint) {
            let cfg = match client_config(&self.id, &p.fingerprint, &self.peers_path) {
                Ok(c) => c,
                Err(e) => return Err((e, next)),
            };
            let (tx, rx) = std::sync::mpsc::sync_channel::<String>(QUEUE_LEN);
            let (p, log) = (p.clone(), self.log.clone());
            if std::thread::Builder::new().name("mesh-send".into()).spawn(move || send(cfg, p, rx, log)).is_ok() {
                queues.push(tx);
            }
        }
        if !self.listen.is_empty() {
            let ok = gonet_one_ip(&self.listen);
            if !ok {
                return Err((
                    "mesh_listen must be one IP address and port of this computer (not 0.0.0.0 or ::), e.g. the address on your own WireGuard or LAN interface".into(),
                    next,
                ));
            }
            let ln = match TcpListener::bind(&self.listen) {
                Ok(l) => l,
                Err(e) => return Err((format!("listen tcp {}: bind: {}", self.listen, crate::sources::go_errno(&e)), next)),
            };
            let cfg = match server_config(&self.id, &self.peers_path) {
                Ok(c) => c,
                Err(e) => return Err((e, next)),
            };
            let (out, peers_path, log) = (self.out.clone(), self.peers_path.clone(), self.log.clone());
            let _ = std::thread::Builder::new().name("mesh-listen".into()).spawn(move || serve(ln, cfg, peers_path, out, log));
            (self.log)(&format!("mesh: listening on {} for {} enrolled peer(s)", self.listen, peers.len()));
        }
        let min = rank(&self.min_severity);
        Ok((MeshSink { next, min, queues, dropped: Arc::default() }, peers.len()))
    }
}

fn gonet_one_ip(hp: &str) -> bool {
    crate::gonet::split_host_port(hp).and_then(|(h, _)| crate::gonet::parse_ip(h)).is_some_and(|ip| !crate::gonet::is_unspecified(&ip))
}

/// One peer's sender (Go: send): waits for alerts, sends up to 50 at once, backs off while the peer is unreachable.
fn send(cfg: Arc<rustls::ClientConfig>, p: Peer, rx: Receiver<String>, log: Arc<dyn Fn(&str) + Send + Sync>) {
    let mut backoff = BACKOFF_FIRST;
    let mut pending: Vec<String> = Vec::new();
    loop {
        if pending.is_empty() {
            match rx.recv() {
                Ok(w) => pending.push(w),
                Err(_) => return,
            }
        }
        while pending.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(w) => pending.push(w),
                Err(_) => break,
            }
        }
        let body = format!("{{\"alerts\":[{}]}}", pending.join(","));
        let r = match post(&cfg, &p.address, "POST", PATH, body.as_bytes()) {
            Ok(code) if code < 300 => Ok(()),
            Ok(code) => Err(format!("answered {code}")),
            Err(e) => Err(e),
        };
        match r {
            Ok(()) => {
                pending.clear();
                backoff = BACKOFF_FIRST;
            }
            Err(e) => {
                log(&format!(
                    "mesh: could not send {} alert(s) to {} ({}): {e}; next try in {}",
                    pending.len(),
                    p.name,
                    p.address,
                    gotext::duration(backoff.as_nanos() as i64)
                ));
                // new alerts keep queueing (at most 256) while it waits
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

fn serve(
    ln: TcpListener,
    cfg: Arc<rustls::ServerConfig>,
    peers_path: String,
    out: Arc<dyn Fn(Alert) + Send + Sync>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) {
    let limits: Arc<Mutex<HashMap<String, Bucket>>> = Arc::default();
    let active = Arc::new(Mutex::new(0usize));
    for conn in ln.incoming() {
        let Ok(tcp) = conn else { continue };
        {
            let mut n = active.lock().unwrap_or_else(|p| p.into_inner());
            if *n >= MAX_CONNS {
                continue; // dropped: closed
            }
            *n += 1;
        }
        let (cfg, peers_path, out, limits, a2) = (cfg.clone(), peers_path.clone(), out.clone(), limits.clone(), active.clone());
        let spawned = std::thread::Builder::new().name("mesh-conn".into()).spawn(move || {
            serve_one(tcp, cfg, &peers_path, &*out, &limits);
            *a2.lock().unwrap_or_else(|p| p.into_inner()) -= 1;
        });
        if spawned.is_err() {
            *active.lock().unwrap_or_else(|p| p.into_inner()) -= 1;
        }
    }
    log("mesh: listener stopped");
}

fn serve_one(
    tcp: TcpStream,
    cfg: Arc<rustls::ServerConfig>,
    peers_path: &str,
    out: &(dyn Fn(Alert) + Send + Sync),
    limits: &Mutex<HashMap<String, Bucket>>,
) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(10)));
    let Ok(conn) = rustls::ServerConnection::new(cfg) else { return };
    let mut s = rustls::StreamOwned::new(conn, tcp);
    let req = crate::api::read_request(&mut s);
    let (status, alerts) = match req {
        Err((code, _)) => (code, Vec::new()),
        Ok(r) => {
            let peer = s
                .conn
                .peer_certificates()
                .and_then(|c| c.first())
                .and_then(|c| cert_fingerprint(c.as_ref()))
                .and_then(|fp| peer_by_fingerprint(peers_path, &fp));
            let now = Instant::now();
            let mut lim = limits.lock().unwrap_or_else(|p| p.into_inner());
            let b = peer.as_ref().map(|p| *lim.entry(p.name.clone()).or_insert_with(|| Bucket::new(now)));
            let mut b = b.unwrap_or_else(|| Bucket::new(now));
            let res = receive(&r.method, &r.path, &r.body, peer.as_ref(), &mut b, now);
            if let Some(p) = &peer {
                lim.insert(p.name.clone(), b);
            }
            res
        }
    };
    for a in alerts {
        out(a);
    }
    let text = match status {
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let body: &[u8] = match status {
        204 => b"",
        400 => b"bad batch\n",
        403 => b"forbidden\n",
        404 => b"404 page not found\n",
        429 => b"too many alerts\n",
        _ => b"",
    };
    let head = format!("HTTP/1.1 {status} {text}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = s.write_all(&[head.as_bytes(), body].concat());
    let _ = s.flush();
    s.conn.send_close_notify();
    let _ = s.flush();
}

/// The fuzz target's body: a request body from an enrolled peer, and the same bytes as a presented certificate. Whatever
/// the bytes: the answer is 204, 400 or 429, at most 50 alerts come of it, each a `mesh` alert labelled with the peer, its
/// texts bounded, never above critical; a certificate that does not read has no fingerprint.
pub fn fuzz_batch(data: &[u8]) {
    let peer = Peer { name: "lab".into(), fingerprint: format!("hm1-{}", "a".repeat(32)), address: "127.0.0.1:8931".into() };
    let now = Instant::now();
    let mut b = Bucket::new(now);
    let (status, alerts) = receive("POST", PATH, data, Some(&peer), &mut b, now);
    assert!(matches!(status, 204 | 400 | 429), "{status}");
    assert!(alerts.len() <= MAX_BATCH);
    if status == 400 {
        assert!(alerts.is_empty());
    }
    for a in &alerts {
        assert_eq!(a.detector_id, DETECTOR_ID);
        assert!(a.summary.starts_with("[lab] ") && a.summary.len() <= 6 + 3 * MAX_SUMMARY + 3, "{}", a.summary.len());
        for k in ["remote_detector", "remote_source"] {
            assert!(a.fields[k].len() <= 3 * 40);
        }
        assert_eq!(a.fields["peer"], "lab");
    }
    if let Some(fp) = cert_fingerprint(data) {
        assert!(fp.len() == 36 && fp.starts_with("hm1-"));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// No certificate bytes make the reader panic or read out of bounds (inputs up to 12 bytes).
    #[kani::proof]
    #[kani::unwind(14)]
    fn reading_a_certificate_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 12);
        let b: [u8; 12] = kani::any();
        let _ = der_next(&b[..len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_as_go_writes_them() {
        // Go: base32.StdEncoding without padding, lowercased
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32_lower(b""), "");
        assert_eq!(base32_lower(b"f"), "my");
        let fp = fingerprint(&[0u8; 32]);
        assert!(fp.len() == 36 && fp.starts_with("hm1-") && fp[4..].bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)));
        assert_eq!(b64_decode(&b64_encode(b"any bytes \x00\xff")).unwrap(), b"any bytes \x00\xff");
    }

    /// The Kani claim, over every input of up to 3 bytes without Kani.
    #[test]
    fn reading_a_certificate_never_panics() {
        for len in 0..=3usize {
            for n in 0..(1u32 << (8 * len)) {
                let b = n.to_le_bytes();
                let _ = der_next(&b[..len]);
                let _ = cert_fingerprint(&b[..len]);
            }
        }
    }

    #[test]
    fn the_rate_is_120_a_minute() {
        let t = Instant::now();
        let mut b = Bucket::new(t);
        assert_eq!((0..200).filter(|_| b.take(t)).count(), 120);
        assert!(!b.take(t + Duration::from_millis(400)));
        assert!(b.take(t + Duration::from_millis(500)));
        assert_eq!((0..200).filter(|_| b.take(t + Duration::from_secs(3600))).count(), 120, "the burst never exceeds 120");
    }
}
