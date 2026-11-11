//! One check (internal/wifihealth/run.go): the default route's Wi-Fi interface, iw's view of the link before and after,
//! two pings at once while NetworkManager's scan list and the device count are read, the optional download from a pacman
//! mirror, all inside 90 seconds; then the judge.

use super::gostr::decode;
use super::http::{self, NetError};
use super::judge::{Report, Speed};
use super::parse::{parse_link, parse_ping, parse_scan, round1, Ping};
use crate::gotime::Time;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Options for one check.
pub struct Options {
    pub iface: String,
    pub speed: bool,
    pub api: String,
    pub internet: String,
    pub proc_root: String,
    pub mirrorlist: String,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            iface: String::new(),
            speed: false,
            api: String::new(),
            internet: "1.1.1.1".into(),
            proc_root: "/proc".into(),
            mirrorlist: "/etc/pacman.d/mirrorlist".into(),
        }
    }
}

/// Go's `exec.LookPath`: a name with a slash as it is, else the first executable file of that name on PATH.
pub fn look_path(name: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let ok = |p: &str| std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
    if name.contains('/') {
        return ok(name).then(|| name.to_string());
    }
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let p = format!("{dir}/{name}");
        if ok(&p) {
            return Some(p);
        }
    }
    None
}

/// `run(ctx, name, args...)`: the program's standard output (whatever its exit), with PATH=/usr/bin:/bin and LANG=C; killed
/// at the deadline, keeping what it wrote. A program not found gives nothing.
pub fn run(deadline: Instant, name: &str, args: &[&str]) -> String {
    let Some(prog) = look_path(name) else { return String::new() };
    if Instant::now() >= deadline {
        return String::new();
    }
    let child = Command::new(prog)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return String::new() };
    let mut out = child.stdout.take().expect("stdout");
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => break,
        }
    }
    decode(&reader.join().unwrap_or_default())
}

/// `fmt.Sscanf(x, "%X", &g)` into a uint32: the leading hex digits, None when there are none or they overflow.
fn scan_hex32(s: &str) -> Option<u32> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if digits.is_empty() {
        return None;
    }
    let v = u64::from_str_radix(digits.trim_start_matches('0'), 16).or_else(|_| {
        if digits.trim_start_matches('0').is_empty() {
            Ok(0)
        } else {
            Err(())
        }
    });
    v.ok().filter(|&v| v <= u32::MAX as u64).map(|v| v as u32)
}

/// `wifiRoute`: the default route's interface and gateway, when the interface is Wi-Fi (or the one asked for).
fn wifi_route(proc_root: &str, want: &str) -> (String, String) {
    let Ok(b) = std::fs::read(format!("{proc_root}/net/route")) else { return (String::new(), String::new()) };
    let text = decode(&b);
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let x: Vec<&str> = crate::gotext::fields(line).collect();
        if x.len() < 3 || x[1] != "00000000" {
            continue;
        }
        if !want.is_empty() && x[0] != want {
            continue;
        }
        if want.is_empty() && std::fs::metadata(format!("/sys/class/net/{}/wireless", x[0])).is_err() {
            continue;
        }
        if let Some(g) = scan_hex32(x[2]) {
            if g != 0 {
                let b = g.to_le_bytes();
                return (x[0].to_string(), format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]));
            }
        }
    }
    (String::new(), String::new())
}

fn ping(deadline: Instant, target: &str, count: u32) -> Ping {
    if target.is_empty() {
        return Ping { target: String::new(), loss_pct: 100.0, ..Default::default() };
    }
    let c = count.to_string();
    let out = run(deadline, "ping", &["-n", "-c", &c, "-i", "0.25", "-W", "1", target]);
    parse_ping(target, &out)
}

/// `Run`: the check. Err only when iw is missing.
pub fn check(o: &Options) -> Result<Report, String> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut r = Report { time: Time::now().utc().truncate(1_000_000_000), devices_here: -1, ..Default::default() };
    let (iface, gw) = wifi_route(&o.proc_root, &o.iface);
    if iface.is_empty() {
        r.judge();
        return Ok(r);
    }
    r.iface = iface.clone();
    if look_path("iw").is_none() {
        return Err("the iw program is missing (pacman -S iw)".into());
    }
    let station = || run(deadline, "iw", &["dev", &iface, "link"]) + &run(deadline, "iw", &["dev", &iface, "station", "dump"]);
    r.power_save = run(deadline, "iw", &["dev", &iface, "get", "power_save"]).contains("Power save: on");
    let Some(before) = parse_link(&station()) else {
        r.judge();
        return Ok(r);
    };
    r.connected = true;

    let (router, internet, scan, devices) = std::thread::scope(|s| {
        let a = s.spawn(|| ping(deadline, &gw, 30));
        let b = s.spawn(|| ping(deadline, &o.internet, 30));
        let scan = run(deadline, "nmcli", &["-t", "-f", "IN-USE,SSID,BSSID,FREQ,SIGNAL", "device", "wifi", "list", "ifname", &iface]);
        let devices = if o.api.is_empty() { -1 } else { devices_here(&o.api) };
        (a.join().unwrap_or_default(), b.join().unwrap_or_default(), scan, devices)
    });
    r.router = router;
    r.internet = internet;
    r.devices_here = devices;

    if o.speed {
        r.speed = Some(speed_test(deadline, &o.internet, &o.mirrorlist));
    }
    let after = parse_link(&station()).unwrap_or_else(|| before.clone());
    r.link = after.clone();
    let sent = after.tx_packets.wrapping_sub(before.tx_packets);
    if after.tx_packets >= before.tx_packets && sent >= 300 {
        r.retries_pct = round1(100.0 * after.tx_retries.wrapping_sub(before.tx_retries) as f64 / sent as f64);
        r.retries_span = "check".into();
    } else if after.tx_packets >= 1000 {
        r.retries_pct = round1(100.0 * after.tx_retries as f64 / after.tx_packets as f64);
        r.retries_span = "connection".into();
    }
    r.neighbourhood(&parse_scan(&scan, &after.ssid));
    r.judge();
    Ok(r)
}

/// lan.Store as far as the device count reads it (Go's decoder checks every field's type, so the whole shape is here).
mod store {
    use crate::gostruct::{Field, Ty};
    static STRS: Ty = Ty::Slice(&Ty::Str);
    static DEVICE: Ty = Ty::Struct(
        "lan.Device",
        &[
            Field("mac", &Ty::Str, false),
            Field("ip", &Ty::Str, false),
            Field("name", &Ty::Str, true),
            Field("names", &STRS, true),
            Field("vendor", &Ty::Str, true),
            Field("model", &Ty::Str, true),
            Field("kind", &Ty::Str, false),
            Field("services", &STRS, true),
            Field("private_mac", &Ty::Bool, true),
            Field("first_seen", &Ty::Time, false),
            Field("last_seen", &Ty::Time, false),
        ],
    );
    static DEVICES: Ty = Ty::Slice(&DEVICE);
    static NETWORK: Ty = Ty::Struct(
        "lan.Network",
        &[
            Field("uuid", &Ty::Str, false),
            Field("ssid", &Ty::Str, false),
            Field("first_scan", &Ty::Time, false),
            Field("last_scan", &Ty::Time, false),
            Field("devices", &DEVICES, false),
        ],
    );
    static NETWORKS: Ty = Ty::Slice(&NETWORK);
    pub static STORE: Ty = Ty::Struct(
        "lan.Store",
        &[
            Field("networks", &NETWORKS, false),
            Field("status", &Ty::Str, false),
            Field("status_uuid", &Ty::Str, true),
            Field("status_time", &Ty::Time, false),
        ],
    );
}

/// `devicesHere`: how many devices Heimdall's last look found on the network it last looked at; -1 when unknown.
pub fn devices_here(api: &str) -> i64 {
    let deadline = Instant::now() + Duration::from_secs(3);
    let Some(url) = http::parse_url(&format!("http://{api}/v1/lan/devices")) else { return -1 };
    let Ok(mut resp) = http::get(&url, &[("User-Agent", "Go-http-client/1.1")], deadline, None) else { return -1 };
    if resp.status != 200 {
        return -1;
    }
    let Ok(body) = resp.read_all(4 << 20, deadline, None) else { return -1 };
    count_devices(&body)
}

/// The count from the API's answer, as Go decodes it (the first JSON value, every type checked).
pub fn count_devices(body: &[u8]) -> i64 {
    use crate::gostruct::{self, Val};
    let Ok(v) = crate::gojson::parse_first(body) else { return -1 };
    let mut st = gostruct::zero(&store::STORE);
    let mut cx = gostruct::Ctx { top: "Store", first: None };
    gostruct::read(&store::STORE, &v, &mut st, "", &mut cx);
    if cx.first.is_some() || gostruct::str_field(&store::STORE, &st, "status") != "scanned" {
        return -1;
    }
    let status_uuid = gostruct::str_field(&store::STORE, &st, "status_uuid").to_string();
    let Some(Val::Slice(Some(nets))) = gostruct::field(&store::STORE, &st, "networks") else { return -1 };
    let Ty3 { net, dev } = tys();
    for n in nets {
        if gostruct::str_field(net, n, "uuid") != status_uuid {
            continue;
        }
        let last_scan = match gostruct::field(net, n, "last_scan") {
            Some(Val::Time(t)) => *t,
            _ => Time::default(),
        };
        let mut here = 0;
        if let Some(Val::Slice(Some(devs))) = gostruct::field(net, n, "devices") {
            for d in devs {
                if let Some(Val::Time(seen)) = gostruct::field(dev, d, "last_seen") {
                    if last_scan.sub(seen) < 60_000_000_000 {
                        here += 1;
                    }
                }
            }
        }
        return here;
    }
    -1
}

struct Ty3 {
    net: &'static crate::gostruct::Ty,
    dev: &'static crate::gostruct::Ty,
}

fn tys() -> Ty3 {
    use crate::gostruct::Ty;
    let Ty::Struct(_, fs) = &store::STORE else { unreachable!() };
    let Ty::Slice(net) = fs[0].1 else { unreachable!() };
    let Ty::Struct(_, nfs) = net else { unreachable!() };
    let Ty::Slice(dev) = nfs[4].1 else { unreachable!() };
    Ty3 { net, dev }
}

/// `mirrorFiles`: up to three https mirrors' installer image URLs from the mirror list.
pub fn mirror_files(path: &str) -> Vec<String> {
    let Ok(b) = std::fs::read(path) else { return Vec::new() };
    let text = decode(&b);
    let mut out = Vec::new();
    let mut lines: Vec<&str> = text.split('\n').collect();
    if text.ends_with('\n') {
        lines.pop();
    }
    for line in lines {
        if out.len() >= 3 {
            break;
        }
        let line = crate::gotext::trim_space(line.strip_suffix('\r').unwrap_or(line));
        let Some((k, v)) = line.split_once('=') else { continue };
        if crate::gotext::trim_space(k) != "Server" {
            continue;
        }
        let v = crate::gotext::trim_space(v);
        let Some(i) = v.find("/$repo") else { continue };
        if !v.starts_with("https://") {
            continue;
        }
        out.push(format!("{}/iso/latest/archlinux-x86_64.iso", &v[..i]));
    }
    out
}

/// One download stream: GET with the range, redirects followed as Go's client does (up to 10), the body counted until the
/// end or the deadline. The error when it did not start.
fn stream(url: &str, k: u64, deadline: Instant, got: &AtomicI64) -> Result<(), String> {
    let range = format!("bytes={}-", k * (400 << 20));
    let mut u = http::parse_url(url).ok_or_else(|| format!("Get {}: unsupported protocol scheme", crate::gotext::quote(url)))?;
    let mut resp = None;
    for _ in 0..=10 {
        let r =
            http::get(&u, &[("User-Agent", "heimdall-wifi-health"), ("Range", &range)], deadline, None).map_err(|e| net_text(url, &e))?;
        if matches!(r.status, 301 | 302 | 303 | 307 | 308) {
            if let Some(next) = r.header("Location").and_then(|l| http::join(&u, l)) {
                u = next;
                continue;
            }
        }
        resp = Some(r);
        break;
    }
    let Some(mut resp) = resp else { return Err(format!("Get {}: stopped after 10 redirects", crate::gotext::quote(url))) };
    if resp.status != 200 && resp.status != 206 {
        return Err(format!("the server answered {}", resp.status_text));
    }
    let mut buf = vec![0u8; 256 << 10];
    loop {
        match resp.read_body(&mut buf, deadline, None) {
            Ok(0) | Err(_) => return Ok(()),
            Ok(n) => {
                got.fetch_add(n as i64, Ordering::SeqCst);
            }
        }
    }
}

fn net_text(url: &str, e: &NetError) -> String {
    format!("Get {}: {}", crate::gotext::quote(url), e.go_short())
}

/// `speedTest`: about 8 seconds of download over two connections from the first mirror that serves a megabyte, with the
/// internet pinged meanwhile.
pub fn speed_test(deadline: Instant, internet: &str, mirrorlist: &str) -> Speed {
    let mut s = Speed::default();
    let urls = mirror_files(mirrorlist);
    if urls.is_empty() {
        s.error = format!("no download server: no https mirror in {mirrorlist}");
        return s;
    }
    let last_err: Mutex<Option<String>> = Mutex::new(None);
    for url in &urls {
        let got = AtomicI64::new(0);
        let dl = deadline.min(Instant::now() + Duration::from_secs(9));
        let (loaded, took) = std::thread::scope(|sc| {
            let p = sc.spawn(|| {
                std::thread::sleep(Duration::from_millis(1500));
                ping(deadline, internet, 24)
            });
            let start = Instant::now();
            let streams: Vec<_> = (0..2u64)
                .map(|k| {
                    let (got, last_err) = (&got, &last_err);
                    sc.spawn(move || {
                        if let Err(e) = stream(url, k, dl, got) {
                            *last_err.lock().unwrap_or_else(|p| p.into_inner()) = Some(e);
                        }
                    })
                })
                .collect();
            for t in streams {
                let _ = t.join();
            }
            let took = start.elapsed().as_secs_f64();
            (p.join().unwrap_or_default(), took)
        });
        let got = got.load(Ordering::SeqCst);
        if got < 1 << 20 {
            continue;
        }
        s.down_mbps = round1(got as f64 * 8.0 / took / 1e6);
        s.server = url.strip_prefix("https://").unwrap_or(url).split('/').next().unwrap_or("").to_string();
        s.loaded = Some(loaded);
        return s;
    }
    s.error = "the download servers could not be reached".into();
    if let Some(e) = last_err.into_inner().unwrap_or_else(|p| p.into_inner()) {
        let short = match e.rfind(": ") {
            Some(i) => e[i + 2..].to_string(),
            None => e,
        };
        s.error.push_str(&format!(" ({short})"));
    }
    s
}
