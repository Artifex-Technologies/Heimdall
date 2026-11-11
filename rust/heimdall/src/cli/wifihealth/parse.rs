//! What the tools say, read as internal/wifihealth/parse.go reads it: `iw dev IF link` (+ `station dump`), NetworkManager's
//! scan list, ping's output. Go's patterns, with Go's ASCII `\s` and `\d` written out.

use super::gostr::{atoi, float_to_int, parse_float, parse_uint, runes};
use regex::Regex;
use std::sync::OnceLock;

/// The computer's own connection.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Link {
    pub ssid: String,
    pub freq_mhz: i64,
    pub channel: i64,
    pub band: String,
    pub width: i64,
    pub signal_dbm: i64,
    pub rx_mbps: f64,
    pub tx_mbps: f64,
    pub expected_mbps: f64,
    pub tx_packets: u64,
    pub tx_retries: u64,
    pub tx_failed: u64,
}

struct Res {
    freq: Regex,
    signal: Regex,
    rx: Regex,
    tx: Regex,
    ssid: Regex,
    width: Regex,
    counter: Regex,
    expected: Regex,
    ping_loss: Regex,
    ping_rtt: Regex,
    ping_time: Regex,
}

const S: &str = r"[\t\n\f\r ]";

fn res() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| {
        let r = |p: &str| Regex::new(&p.replace(r"\s", S).replace(r"\d", "[0-9]")).expect("pattern");
        Res {
            freq: r(r"(?m)^\s*freq:\s*([0-9.]+)"),
            signal: r(r"(?m)^\s*signal:\s*(-?\d+)"),
            rx: r(r"(?m)^\s*rx bitrate:\s*([0-9.]+) MBit/s(.*)$"),
            tx: r(r"(?m)^\s*tx bitrate:\s*([0-9.]+) MBit/s(.*)$"),
            ssid: r(r"(?m)^\s*SSID:\s*(.*)$"),
            width: r(r"(\d+)MHz"),
            counter: r(r"(?m)^\s*(tx packets|tx retries|tx failed):\s*(\d+)"),
            expected: r(r"(?m)^\s*expected throughput:\s*([0-9.]+)Mbps"),
            ping_loss: r(r"(\d+) packets transmitted, (\d+) (?:packets )?received.*?([0-9.]+)% packet loss"),
            ping_rtt: r(r"= ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms"),
            ping_time: r(r"time=([0-9.]+) ms"),
        }
    })
}

/// `ParseLink`: None when not connected.
pub fn parse_link(text: &str) -> Option<Link> {
    if text.contains("Not connected") || !text.contains("Connected to") {
        return None;
    }
    let r = res();
    let mut l = Link::default();
    if let Some(m) = r.ssid.captures(text) {
        l.ssid = crate::gotext::trim_space(&m[1]).to_string();
    }
    if let Some(m) = r.freq.captures(text) {
        l.freq_mhz = float_to_int(parse_float(&m[1]));
        (l.channel, l.band) = channel(l.freq_mhz);
    }
    if let Some(m) = r.signal.captures(text) {
        l.signal_dbm = atoi(&m[1]);
    }
    if let Some(m) = r.rx.captures(text) {
        l.rx_mbps = parse_float(&m[1]);
    }
    if let Some(m) = r.tx.captures(text) {
        l.tx_mbps = parse_float(&m[1]);
        if let Some(w) = r.width.captures(&m[2]) {
            l.width = atoi(&w[1]);
        }
    }
    if l.width == 0 {
        l.width = 20;
    }
    if let Some(m) = r.expected.captures(text) {
        l.expected_mbps = parse_float(&m[1]);
    }
    for m in r.counter.captures_iter(text) {
        let v = parse_uint(&m[2]);
        match &m[1] {
            "tx packets" => l.tx_packets = v,
            "tx retries" => l.tx_retries = v,
            _ => l.tx_failed = v,
        }
    }
    Some(l)
}

/// `Channel`: a frequency's channel number and band.
pub fn channel(mhz: i64) -> (i64, String) {
    match mhz {
        2484 => (14, "2.4 GHz".into()),
        2412..=2472 => ((mhz - 2407) / 5, "2.4 GHz".into()),
        5160..=5885 => ((mhz - 5000) / 5, "5 GHz".into()),
        5955..=7115 => ((mhz - 5950) / 5, "6 GHz".into()),
        _ => (0, String::new()),
    }
}

/// One network in NetworkManager's scan list.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Neighbour {
    pub ssid: String,
    pub bssid: String,
    pub channel: i64,
    pub band: String,
    pub signal: i64,
    pub in_use: bool,
    pub own: bool,
    pub same_router: bool,
}

/// `ParseScan`: `nmcli -t -f IN-USE,SSID,BSSID,FREQ,SIGNAL device wifi list`.
pub fn parse_scan(text: &str, own_ssid: &str) -> Vec<Neighbour> {
    let mut out: Vec<Neighbour> = Vec::new();
    for line in scanner_lines(text) {
        let f = split_nm(line);
        if f.len() < 5 {
            continue;
        }
        let freq_field = format!("{} 0", f[3]);
        let mhz = atoi(crate::gotext::fields(&freq_field).next().unwrap_or(""));
        let (ch, band) = channel(mhz);
        let sig = atoi(&f[4]);
        if ch == 0 {
            continue;
        }
        let mut n = Neighbour {
            ssid: f[1].clone(),
            bssid: f[2].clone(),
            channel: ch,
            band,
            signal: sig,
            in_use: f[0] == "*",
            ..Default::default()
        };
        n.own = !n.ssid.is_empty() && n.ssid == own_ssid;
        out.push(n);
    }
    let mut mine = String::new();
    for n in &out {
        if n.in_use {
            mine = crate::gotext::to_lower(&n.bssid);
        }
    }
    for n in out.iter_mut() {
        if !n.in_use && !n.own && same_radio(&mine, &crate::gotext::to_lower(&n.bssid)) {
            n.same_router = true;
        }
    }
    out
}

/// Go's `bufio.Scanner` lines: split at "\n", a "\r" before it dropped, no empty last line.
fn scanner_lines(text: &str) -> Vec<&str> {
    let mut v: Vec<&str> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    if text.is_empty() || text.ends_with('\n') {
        v.pop();
    }
    v
}

fn same_radio(a: &str, b: &str) -> bool {
    let (a, b) = (super::gostr::encode(a), super::gostr::encode(b));
    if a.len() != 17 || b.len() != 17 || a == b {
        return false;
    }
    a[3..] == b[3..] || a[..15] == b[..15]
}

/// `splitNM`: fields at ':' with '\' escaping the next character; each bad byte becomes U+FFFD as Go's rune loop makes it.
fn split_nm(line: &str) -> Vec<String> {
    let line = runes(line);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut esc = false;
    for r in line.chars() {
        if esc {
            cur.push(r);
            esc = false;
        } else if r == '\\' {
            esc = true;
        } else if r == ':' {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(r);
        }
    }
    out.push(cur);
    out
}

/// `block5`.
fn block5(ch: i64) -> i64 {
    match ch {
        36..=64 => (ch - 36) / 16,
        100..=144 => 2 + (ch - 100) / 16,
        149..=177 => 5 + (ch - 149) / 16,
        _ => -1,
    }
}

/// `Overlaps`.
pub fn overlaps(band: &str, a: i64, w: i64, b: i64) -> bool {
    match band {
        "2.4 GHz" => a.wrapping_sub(b).wrapping_abs() < 5,
        "5 GHz" => a == b || (w >= 40 && block5(a) == block5(b) && block5(a) >= 0),
        "6 GHz" => a == b,
        _ => false,
    }
}

/// One ping summary.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Ping {
    pub target: String,
    pub sent: i64,
    pub loss_pct: f64,
    pub avg_ms: f64,
    pub jitter_ms: f64,
    pub max_ms: f64,
    pub median_ms: f64,
    pub ok: bool,
}

/// `ParsePing`.
pub fn parse_ping(target: &str, text: &str) -> Ping {
    let r = res();
    let mut p = Ping { target: target.to_string(), ..Default::default() };
    let mut times: Vec<f64> = r.ping_time.captures_iter(text).map(|m| parse_float(&m[1])).collect();
    if !times.is_empty() {
        times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        p.median_ms = times[times.len() / 2];
    }
    if let Some(m) = r.ping_loss.captures(text) {
        p.sent = atoi(&m[1]);
        let got = atoi(&m[2]);
        p.loss_pct = parse_float(&m[3]);
        p.ok = got > 0;
    }
    if let Some(m) = r.ping_rtt.captures(text) {
        p.avg_ms = parse_float(&m[2]);
        p.max_ms = parse_float(&m[3]);
        p.jitter_ms = parse_float(&m[4]);
    }
    if p.sent == 0 {
        p.loss_pct = 100.0;
    }
    p
}

/// Go's `fmt.Sprintf("%.1f")` read back.
pub fn round1(f: f64) -> f64 {
    crate::gotext::fixed(f, 1).parse::<f64>().unwrap_or(f)
}
