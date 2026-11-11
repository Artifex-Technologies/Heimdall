//! `heimdalld wifi-health`, the Go and the Rust binaries side by side in fake roots with a made-up Wi-Fi: a dummy interface
//! "wlan0" in a network namespace of its own (default route via 192.0.2.1), fake iw, ping and nmcli telling the radio, a
//! fake Heimdall API on 127.0.0.1:8930 and, for the speed test, a fake mirror over TLS with a test authority. Output, errors,
//! exit codes and the tools called must match.

mod common;
use common::*;

const LINK_GOOD: &str = "Connected to 02:00:5e:10:00:9f (on wlan0)\n\tSSID: Home\n\tfreq: 5180\n\tsignal: -48 dBm\n\trx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2\n\ttx bitrate: 780.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 2\n";
const LINK_WEAK: &str = "Connected to 02:00:5e:10:00:9f (on wlan0)\n\tSSID: Caf\u{e9} <free>\n\tfreq: 2437\n\tsignal: -81 dBm\n\trx bitrate: 6.0 MBit/s\n\ttx bitrate: 1.0 MBit/s\n";

fn station(packets: u64, retries: u64) -> String {
    format!("Station 02:00:5e:10:00:9f (on wlan0)\n\ttx packets: {packets}\n\ttx retries: {retries}\n\ttx failed: 0\n\texpected throughput: 410.5Mbps\n")
}

fn ping_out(target: &str, ms: &[f64]) -> String {
    let mut s = format!("PING {target} ({target}) 56(84) bytes of data.\n");
    for (i, t) in ms.iter().enumerate() {
        s.push_str(&format!("64 bytes from {target}: icmp_seq={} ttl=64 time={t} ms\n", i + 1));
    }
    let n = ms.len();
    s.push_str(&format!(
        "\n--- {target} ping statistics ---\n30 packets transmitted, {n} received, {}% packet loss, time 7251ms\n",
        (30 - n) * 100 / 30
    ));
    if n > 0 {
        let avg = ms.iter().sum::<f64>() / n as f64;
        let max = ms.iter().cloned().fold(0.0, f64::max);
        s.push_str(&format!("rtt min/avg/max/mdev = 0.500/{avg:.3}/{max:.3}/0.400 ms\n"));
    }
    s
}

#[derive(Clone)]
struct Air {
    link_before: String,
    link_after: String,
    power_save: bool,
    router: String,
    internet: String,
    scan: String,
    api: Option<String>,
    mirror: bool,
}

fn air_good() -> Air {
    Air {
        link_before: LINK_GOOD.to_string() + &station(10_000, 200),
        link_after: LINK_GOOD.to_string() + &station(10_900, 230),
        power_save: false,
        router: ping_out("192.0.2.1", &[2.1, 2.4, 2.2, 3.0, 2.0, 2.5]),
        internet: ping_out("1.1.1.1", &[14.0, 15.2, 13.9, 14.4]),
        scan: "*:Home:02\\:00\\:5E\\:10\\:00\\:9F:5180 MHz:80\n :Nachbar:0A\\:11\\:5E\\:10\\:00\\:01:5180 MHz:45\n :Home:02\\:00\\:5E\\:10\\:00\\:A0:2437 MHz:70\n :Provider Hotspot:06\\:00\\:5E\\:10\\:00\\:9F:5180 MHz:79\n"
            .into(),
        api: None,
        mirror: false,
    }
}

/// The test authority and the mirror's certificate (openssl, made once per test run).
fn certs() -> Option<std::path::PathBuf> {
    static D: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    D.get_or_init(|| {
        let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("wifi-certs-{}", std::process::id()));
        std::fs::create_dir_all(&d).ok()?;
        let script = "set -e\n\
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -subj '/CN=Heimdall Test CA' -days 2 2>/dev/null\n\
            openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout srv.key -out srv.csr -subj '/CN=mirror.test' 2>/dev/null\n\
            printf 'subjectAltName=DNS:mirror.test\\nbasicConstraints=CA:FALSE\\nextendedKeyUsage=serverAuth\\n' > ext\n\
            openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out srv.crt -days 2 -extfile ext 2>/dev/null\n\
            mkdir -p www/archlinux/iso/latest\n\
            head -c 2500000 /dev/zero > www/archlinux/iso/latest/archlinux-x86_64.iso\n";
        let ok = std::process::Command::new("sh").args(["-c", script]).current_dir(&d).status().ok()?.success();
        ok.then_some(d)
    })
    .clone()
}

/// A fake root with a Wi-Fi interface "wlan0" and fake iw, ping and nmcli telling `a`.
fn wifi_root(r: &Root, a: &Air) {
    r.mkdir("/sys/class/net/wlan0/wireless", 0o755);
    r.write("/srv/link-before", &a.link_before);
    r.write("/srv/link-after", &a.link_after);
    r.write("/srv/router", &a.router);
    r.write("/srv/internet", &a.internet);
    r.write("/srv/scan", &a.scan);
    // iw: "dev wlan0 link" tells the link; the second look (after the measurements) tells link-after
    r.tool(
        "iw",
        &format!(
            "case \"$*\" in\n\
             'dev wlan0 get power_save') echo 'Power save: {}' ;;\n\
             'dev wlan0 link') if [ -e /tmp/iw-seen ]; then cat /srv/link-after; else touch /tmp/iw-seen; cat /srv/link-before; fi ;;\n\
             'dev wlan0 station dump') : ;;\n\
             *) exit 1 ;;\nesac\n",
            if a.power_save { "on" } else { "off" }
        ),
    );
    r.tool("ping", "for t; do :; done\ncase \"$t\" in 192.0.2.1) cat /srv/router ;; 1.1.1.1) cat /srv/internet ;; *) exit 2 ;; esac\n");
    r.tool("nmcli", "cat /srv/scan\n");
    if let Some(body) = &a.api {
        r.write("/srv/api-body", body);
        r.write(
            "/srv/api.py",
            "import http.server, sys\nbody = open(sys.argv[1], 'rb').read()\nclass H(http.server.BaseHTTPRequestHandler):\n    def do_GET(self):\n        self.send_response(200 if self.path == '/v1/lan/devices' else 404)\n        self.send_header('Content-Type', 'application/json')\n        self.end_headers()\n        self.wfile.write(body)\n    def log_message(self, *a):\n        pass\nhttp.server.HTTPServer(('127.0.0.1', 8930), H).serve_forever()\n",
        );
    }
    if a.mirror {
        let c = certs().expect("openssl for the test certificates");
        let ca = std::fs::read(c.join("ca.crt")).unwrap();
        r.write("/etc/ssl/certs/ca-certificates.crt", &ca);
        r.write("/etc/ssl/cert.pem", &ca);
        r.write("/etc/hosts", "127.0.0.1 localhost mirror.test\n::1 localhost\n");
        r.write(
            "/etc/pacman.d/mirrorlist",
            "## Arch Linux repository mirrorlist\n#Server = https://commented.example/archlinux/$repo/os/$arch\nServer = http://plain.example/archlinux/$repo/os/$arch\nServer = https://mirror.test/archlinux/$repo/os/$arch\n",
        );
    }
}

fn wifi_opts(a: &Air) -> Opts {
    let mut setup = String::from(
        "ip link add wlan0 type dummy\nip addr add 192.0.2.10/24 dev wlan0\nip link set wlan0 up\nip route add default via 192.0.2.1 dev wlan0\n",
    );
    if a.api.is_some() {
        setup.push_str("timeout 30 python3 -I \"$R/srv/api.py\" \"$R/srv/api-body\" </dev/null >/dev/null 2>&1 &\nfor i in $(seq 50); do python3 -I -c 'import socket; socket.create_connection((\"127.0.0.1\", 8930), 0.2)' 2>/dev/null && break; sleep 0.1; done\n");
    }
    if a.mirror {
        let c = certs().unwrap();
        setup.push_str(&format!(
            "(cd '{d}/www' && exec timeout 40 openssl s_server -quiet -accept 443 -cert '{d}/srv.crt' -key '{d}/srv.key' -WWW </dev/null >/dev/null 2>&1) &\nsleep 0.5\n",
            d = c.display()
        ));
    }
    Opts { net: true, setup, ..Opts::user() }
}

fn sorted_calls(r: &Root) -> Vec<String> {
    let mut v: Vec<String> = r.calls().lines().map(str::to_string).collect();
    v.sort();
    v
}

/// The measured speed changes from run to run: "642.7" and "643 Mbps download" become placeholders.
fn no_speed(s: &str) -> String {
    let mut out = normalize(s);
    for key in ["\"down_mbps\":", "\"title\":\"", "  ok   ", "  WARN "] {
        let mut res = String::new();
        let mut rest = out.as_str();
        while let Some(i) = rest.find(key) {
            res.push_str(&rest[..i + key.len()]);
            rest = &rest[i + key.len()..];
            let digits = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
            if digits > 0 && (key.starts_with("\"down") || rest[digits..].starts_with(" Mbps download")) {
                res.push('N');
                rest = &rest[digits..];
            }
        }
        res.push_str(rest);
        out = res;
    }
    out
}

fn wifi_case(name: &str, a: &Air, args: &[&str], o: &Opts) -> Option<(Out, Out)> {
    let ((g, rg), (r, rr)) = both(&format!("wifi-{name}"), |root| wifi_root(root, a), args, o)?;
    assert_eq!(g.code, r.code, "{name}: exit codes\nGo: {g:?}\nRust: {r:?}");
    assert_eq!(no_speed(&g.stdout), no_speed(&r.stdout), "{name}: standard output");
    assert_eq!(g.stderr, r.stderr, "{name}: standard error");
    assert_eq!(sorted_calls(&rg), sorted_calls(&rr), "{name}: the tools called");
    Some((g, r))
}

#[test]
fn wifi_health_runs_as_go() {
    let good = air_good();
    let mut weak = air_good();
    weak.link_before = LINK_WEAK.to_string() + &station(500, 10);
    weak.link_after = LINK_WEAK.to_string() + &station(900, 160);
    weak.power_save = true;
    weak.router = ping_out("192.0.2.1", &[3.0, 95.0, 2.8, 3.1, 70.0]);
    weak.internet = ping_out("1.1.1.1", &[]);
    weak.scan = (0..30)
        .map(|i| format!(" :Net {i}:0A\\:11\\:5E\\:10\\:00\\:{i:02X}:{} MHz:{}\n", [2412, 2437, 2442, 2462][i % 4], 30 + i * 2))
        .collect::<String>()
        + "*:Caf\u{e9} <free>:02\\:00\\:5E\\:10\\:00\\:9F:2437 MHz:20\n :Caf\u{e9} <free>:02\\:00\\:5E\\:10\\:00\\:A1:5240 MHz:40\n";
    let mut api = air_good();
    api.api = Some(r#"{"networks":[{"uuid":"u1","ssid":"Home","last_scan":"2026-11-10T20:00:00Z","devices":[{"mac":"02:00:00:00:00:01","last_seen":"2026-11-10T20:00:00Z"},{"mac":"02:00:00:00:00:02","last_seen":"2026-11-10T19:00:00Z"},{"mac":"02:00:00:00:00:03","last_seen":"2026-11-10T19:59:01Z"}]}],"status":"scanned","status_uuid":"u1"}"#.into());
    let mut not_connected = air_good();
    not_connected.link_before = "Not connected.\n".into();
    let mut bad_api = air_good();
    bad_api.api = Some("{\"networks\": [".into());
    let mut mirror = air_good();
    mirror.mirror = true;
    let cases: Vec<(&str, &Air, Vec<&str>)> = vec![
        ("good-json", &good, vec!["wifi-health", "--json", "--api", ""]),
        ("good-text", &good, vec!["wifi-health", "--api="]),
        ("weak-json", &weak, vec!["wifi-health", "-json", "-api", ""]),
        ("weak-text", &weak, vec!["wifi-health", "--api", ""]),
        ("api", &api, vec!["wifi-health", "--json"]),
        ("api-text", &api, vec!["wifi-health"]),
        ("api-broken", &bad_api, vec!["wifi-health", "--json"]),
        ("api-down", &good, vec!["wifi-health", "--json"]),
        ("not-connected", &not_connected, vec!["wifi-health", "--json", "--api", ""]),
        ("iface-asked", &good, vec!["wifi-health", "--json", "--api", "", "--iface", "wlan0"]),
        ("iface-other", &good, vec!["wifi-health", "--iface", "eth9", "--api", ""]),
        ("bad-flag", &good, vec!["wifi-health", "--sped"]),
        ("help", &good, vec!["wifi-health", "-h"]),
        ("no-mirrorlist", &good, vec!["wifi-health", "--json", "--speed", "--api", ""]),
        ("speed", &mirror, vec!["wifi-health", "--json", "--speed", "--api", ""]),
        ("speed-text", &mirror, vec!["wifi-health", "--speed", "--api", ""]),
    ];
    for (name, a, args) in &cases {
        let Some((g, _)) = wifi_case(name, a, args, &wifi_opts(a)) else { return };
        if name.starts_with("speed") {
            assert!(g.stdout.contains("mirror.test"), "{name}: the download ran: {}", g.stdout);
        }
        if *name == "api" {
            assert!(g.stdout.contains("\"devices_here\":2"), "{}", g.stdout);
        }
    }
    // iw missing (not on PATH): Go's error and exit code 1
    let o = Opts { env: vec![("PATH".into(), "/nonexistent".into())], ..wifi_opts(&good) };
    let (g, _) = wifi_case("no-iw", &good, &["wifi-health", "--json"], &o).unwrap();
    assert_eq!((g.code, g.stderr.as_str()), (1, "wifi-health: the iw program is missing (pacman -S iw)\n"));
    // a namespace without the interface: no default route, so not connected
    wifi_case("no-route", &good, &["wifi-health", "--json", "--api", ""], &Opts { net: true, ..Opts::user() }).unwrap();
    // the mirror is not reachable (no such name here): the error Go gives
    let mut gone = air_good();
    gone.mirror = true;
    let o = wifi_opts(&air_good());
    let (g, _) = wifi_case("speed-unreachable", &gone, &["wifi-health", "--json", "--speed", "--api", ""], &o).unwrap();
    assert!(g.stdout.contains("the download servers could not be reached ("), "{}", g.stdout);
}
