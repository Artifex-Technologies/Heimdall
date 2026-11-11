//! The Wi-Fi helpers, the Python programs the package ships and their Rust ports side by side: each scenario builds the
//! same made-up system twice (a fake root, `tests/common`), runs the Python program in one and the port in the other under
//! the helper's own name, and compares standard output and error, the exit code, every file under the folders the helper
//! writes, and every call to an outside tool with its arguments (nmcli, ip, nft, systemctl, ping, notify-send ... are
//! fakes that record and answer as the scenario says). Where the Python stops with a traceback, the port must stop at the
//! same point with the same exception (its class; the files written until then compared as always).
//!
//! Nothing here touches this computer's network or NetworkManager: every tool that could is a fake, and the check runs in
//! network namespaces of its own.

mod common;
use common::*;
use std::cell::Cell;
use std::path::PathBuf;

thread_local! {
    /// Runs of both programs compared by this test, for the numbers in docs/RUST_CLI.md
    /// (`cargo test --test cli_wifitools -- --nocapture`).
    static RUNS: Cell<usize> = const { Cell::new(0) };
}

fn counted() {
    RUNS.with(|r| r.set(r.get() + 1));
}

fn report(test: &str, before: usize) {
    eprintln!("{test}: {} runs of both programs compared", RUNS.with(Cell::get) - before);
}

fn script(name: &str) -> PathBuf {
    let dir = if name == "heimdall-wifi-check" { "arch" } else { "net" };
    repo().join("packaging").join(dir).join(name)
}

/// A fake tool that records its arguments exactly (one line per call in /.fake-argv: the name, then each argument in
/// brackets), then runs `body`.
fn recorder(r: &Root, name: &str, body: &str) {
    r.tool(name, &format!("{{ printf '%s' \"$(basename \"$0\")\"; for a in \"$@\"; do printf ' [%s]' \"$a\"; done; printf '\\n'; }} >> /.fake-argv\n{body}"));
}

/// A root with the recording files writable by everyone (the helpers run as root, heimdall or the owner).
fn new_root(tag: &str) -> Root {
    // the folder's name goes into mount options: letters, digits and dashes only
    let tag: String = tag.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
    let r = Root::new(&tag);
    r.write_mode("/.fake-calls", "", 0o666);
    r.write_mode("/.fake-argv", "", 0o666);
    r
}

/// The exception class at the end of a Python traceback, or of the port's "PROG: Class: message" line.
fn exception(stderr: &str, python: bool) -> Option<String> {
    if python {
        if !stderr.contains("Traceback (most recent call last):") {
            return None;
        }
        // the last line that names a class (notes added to the exception may follow it)
        let is_class = |c: &str| !c.is_empty() && c.chars().all(|x| x.is_ascii_alphanumeric() || x == '_' || x == '.');
        let last = stderr.lines().rev().find(|l| is_class(l.split(':').next().unwrap_or_default()))?;
        let class = last.split(':').next()?;
        Some(class.rsplit('.').next().unwrap_or(class).to_string())
    } else {
        let last = stderr.lines().rev().find(|l| !l.trim().is_empty())?;
        let mut p = last.splitn(3, ": ");
        let (prog, class) = (p.next()?, p.next()?);
        let ident = !class.is_empty() && class.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        (prog.starts_with("heimdall-wifi-") && ident).then(|| class.to_string())
    }
}

/// One run of both: the Python helper in one root, the port in the other, at the same time.
pub struct Pair {
    pub py: (Out, Root),
    pub rs: (Out, Root),
}

fn run_pair(test: &str, prog: &str, build: &dyn Fn(&Root), args: &[&str], o: &Opts) -> Pair {
    counted();
    let rp = new_root(&format!("{test}-py"));
    build(&rp);
    let rr = new_root(&format!("{test}-rs"));
    build(&rr);
    let inside = format!("/usr/bin/{prog}");
    let (op, or) = std::thread::scope(|sc| {
        let a = sc.spawn(|| rp.run_as(&inside, &script(prog), args, o));
        let b = sc.spawn(|| rr.run_as(&inside, &rust_bin(), args, o));
        (a.join().unwrap(), b.join().unwrap())
    });
    Pair { py: (op, rp), rs: (or, rr) }
}

/// What a run left: the outputs (times made placeholders), the tools called, and every file under `dirs`.
fn assert_pair(what: &str, p: &Pair, dirs: &[&str]) {
    assert_runs(what, (&p.py.0, &p.py.1), (&p.rs.0, &p.rs.1), dirs);
}

fn assert_runs(what: &str, (po, pr): (&Out, &Root), (ro, rr): (&Out, &Root), dirs: &[&str]) {
    match exception(&po.stderr, true) {
        Some(class) => {
            assert_eq!(Some(class), exception(&ro.stderr, false), "{what}: the same exception\nPython: {}\nRust: {}", po.stderr, ro.stderr);
            assert_eq!(normalize(&po.stdout), normalize(&ro.stdout), "{what}: standard output");
        }
        None => {
            assert_eq!(
                normalize(&po.stdout),
                normalize(&ro.stdout),
                "{what}: standard output\nPython stderr: {}\nRust stderr: {}",
                po.stderr,
                ro.stderr
            );
            assert_eq!(normalize(&po.stderr), normalize(&ro.stderr), "{what}: standard error");
        }
    }
    assert_eq!(po.code, ro.code, "{what}: exit codes\nPython: {po:?}\nRust: {ro:?}");
    assert_eq!(pr.read_str("/.fake-argv"), rr.read_str("/.fake-argv"), "{what}: the tools called (arguments)");
    assert_eq!(pr.calls(), rr.calls(), "{what}: the tools called");
    let tree = |r: &Root| -> Vec<(String, String)> { r.tree(dirs).into_iter().map(|(k, v)| (k, normalize(&v))).collect() };
    let (tp, tr) = (tree(pr), tree(rr));
    if tp != tr {
        for (a, b) in tp.iter().zip(tr.iter()) {
            assert_eq!(a, b, "{what}: files (first difference)");
        }
        assert_eq!(tp, tr, "{what}: files");
    }
}

/// The same system twice, for scenarios of several steps: each step runs the Python program in one and the port in the
/// other, and everything is compared after each.
struct Twin {
    py: Root,
    rs: Root,
    prog: &'static str,
    test: String,
    dirs: Vec<&'static str>,
    steps: usize,
}

impl Twin {
    fn new(test: &str, prog: &'static str, dirs: &[&'static str], build: &dyn Fn(&Root)) -> Twin {
        let py = new_root(&format!("{test}-py"));
        build(&py);
        let rs = new_root(&format!("{test}-rs"));
        build(&rs);
        Twin { py, rs, prog, test: test.to_string(), dirs: dirs.to_vec(), steps: 0 }
    }
    /// Changes both systems the same way.
    fn both(&self, f: impl Fn(&Root)) -> &Twin {
        f(&self.py);
        f(&self.rs);
        self
    }
    fn step(&mut self, args: &[&str], o: &Opts) -> (Out, Out) {
        self.steps += 1;
        counted();
        let inside = format!("/usr/bin/{}", self.prog);
        let (py, rs) = (&self.py, &self.rs);
        let prog = self.prog;
        let (op, or) = std::thread::scope(|sc| {
            let a = sc.spawn(|| py.run_as(&inside, &script(prog), args, o));
            let b = sc.spawn(|| rs.run_as(&inside, &rust_bin(), args, o));
            (a.join().unwrap(), b.join().unwrap())
        });
        let what = format!("{} step {} ({})", self.test, self.steps, args.join(" "));
        assert_runs(&what, (&op, &self.py), (&or, &self.rs), &self.dirs);
        (op, or)
    }
}

/// Runs a scenario and compares; returns the pair for the scenario's own checks.
fn case(test: &str, prog: &str, build: &dyn Fn(&Root), args: &[&str], o: &Opts, dirs: &[&str]) -> Pair {
    let p = run_pair(test, prog, build, args, o);
    assert_pair(test, &p, dirs);
    p
}

// ---- heimdall-wifi-notify

const NOTIFY: &str = "heimdall-wifi-notify";

fn notify_opts() -> Opts {
    Opts { setup: "chown -R 1000:1000 \"$R/home/owner\"".into(), ..Opts::user() }
}

/// A notify-send that answers nothing and succeeds.
fn notify_root(r: &Root, public: Option<&str>, guard: Option<&str>, seen: Option<&str>) {
    recorder(r, "notify-send", "exit 0\n");
    if let Some(p) = public {
        r.write("/run/heimdall-wifi/last.json", p);
    }
    if let Some(g) = guard {
        r.write("/run/heimdall-wifi-guard/last.json", g);
    }
    if let Some(s) = seen {
        r.write("/home/owner/.local/state/heimdall/wifi-notified.json", s);
    }
}

fn notify_case(name: &str, public: Option<&str>, guard: Option<&str>, seen: Option<&str>, o: &Opts) -> Pair {
    let (p, g, s) = (public.map(str::to_string), guard.map(str::to_string), seen.map(str::to_string));
    case(
        &format!("notify-{name}"),
        NOTIFY,
        &move |r| notify_root(r, p.as_deref(), g.as_deref(), s.as_deref()),
        &[],
        o,
        &["/home/owner", "/run"],
    )
}

#[test]
fn notify_as_python() {
    let before = RUNS.with(Cell::get);
    let o = notify_opts();
    let unsafe_ = r#"{"time": "2026-11-11T10:00:00Z", "ssid": "Cafe <free>", "verdict": "unsafe", "reasons": ["well-known sites resolve to addresses outside their own networks: x", "secure connections are being intercepted", "third", "fourth"]}"#;
    let p = notify_case("unsafe", Some(unsafe_), None, None, &o);
    assert!(p.py.1.read_str("/.fake-argv").contains("[Wi-Fi is not safe: Cafe <free>]"), "{}", p.py.1.read_str("/.fake-argv"));
    // already shown: nothing; then the same network checked again later
    notify_case("unsafe-seen", Some(unsafe_), None, Some(r#"{"last": "2026-11-11T10:00:00Z"}"#), &o);
    notify_case("caution", Some(r#"{"time": "t2", "ssid": "Hotel", "verdict": "caution", "reasons": ["open network"]}"#), None, None, &o);
    let safe = r#"{"time": "t3", "ssid": "Home", "verdict": "safe", "reasons": []}"#;
    notify_case("safe-first", Some(safe), None, None, &o);
    notify_case("safe-again", Some(safe), None, Some(r#"{"8f1dbf2e0fbbd7b5": "safe", "last": "t0"}"#), &o);
    let key = heimdall::cli::wifitools::sha16("Home");
    notify_case("safe-known", Some(safe), None, Some(&format!(r#"{{"{key}": "safe", "last": "t0", "guard": null}}"#)), &o);
    notify_case("safe-known-falsy", Some(safe), None, Some(&format!(r#"{{"{key}": 0, "last": "t0"}}"#)), &o);
    // the guard's events
    for ev in ["dropped", "vpn-up", "no-vpn", "router-changed", "other"] {
        let g = format!(
            r#"{{"time": "2026-11-11T10:05:00Z", "event": "{ev}", "ssid": "Cafe", "message": "The VPN dropped, so the Wi-Fi was disconnected."}}"#
        );
        notify_case(&format!("guard-{ev}"), None, Some(&g), None, &o);
    }
    notify_case("guard-seen", None, Some(r#"{"time": 5, "event": "dropped"}"#), Some(r#"{"guard": 5.0}"#), &o);
    notify_case("guard-no-time", None, Some(r#"{"event": "dropped", "ssid": "x"}"#), None, &o);
    notify_case("guard-and-verdict", Some(unsafe_), Some(r#"{"time": "g1", "event": "vpn-up", "ssid": "Cafe", "message": "m"}"#), None, &o);
    // names and texts chosen by whoever runs the access point
    let odd = [
        ("ctrl", "\"a\\u0000b\\u001bc\\u200bd\\u2028e\\u00adf\\t\""),
        ("long", &format!("\"{}\"", "\u{e9}x".repeat(50))),
        ("emoji", "\"\\ud83d\\ude00 \\u0301 \\ufeff \\ue000\""),
        ("number", "12.50"),
        ("bignum", "123456789012345678901234567890"),
        ("float", "1e300"),
        ("nan", "NaN"),
        ("list", r#"["a", 1, null, true, {"b": [1.5, -0.0]}]"#),
        ("dict", r#"{"it's": "q\"", "k": "\u0007\u00ff\u0100"}"#),
        ("null", "null"),
        ("false", "false"),
        ("empty", r#""""#),
        ("option", r#""--help""#),
    ];
    for (n, ssid) in odd {
        let pubj = format!(r#"{{"time": "t-{n}", "ssid": {ssid}, "verdict": "caution", "reasons": [{ssid}, "two"]}}"#);
        let g = format!(r#"{{"time": "g-{n}", "event": "dropped", "ssid": {ssid}, "message": {ssid}}}"#);
        notify_case(&format!("odd-{n}"), Some(&pubj), Some(&g), None, &o);
    }
    notify_case(
        "long-message",
        None,
        Some(&format!(r#"{{"time": "g", "event": "vpn-up", "message": "{}"}}"#, "\u{1f600}".repeat(400))),
        None,
        &o,
    );
    notify_case("reasons-string", Some(r#"{"time": "t", "ssid": "s", "verdict": "unsafe", "reasons": "abcdef"}"#), None, None, &o);
    notify_case("reasons-dict", Some(r#"{"time": "t", "ssid": "s", "verdict": "unsafe", "reasons": {"r1": 1, "r2": 2}}"#), None, None, &o);
    notify_case("reasons-number", Some(r#"{"time": "t", "ssid": "s", "verdict": "unsafe", "reasons": 7}"#), None, None, &o);
    notify_case("reasons-null", Some(r#"{"time": "t", "ssid": "s", "verdict": "safe", "reasons": null}"#), None, None, &o);
    notify_case("verdict-odd", Some(r#"{"time": [1], "ssid": "s", "verdict": ["unsafe"]}"#), None, Some(r#"{"last": [1.0]}"#), &o);
    notify_case("time-true", Some(r#"{"time": true, "ssid": "s", "verdict": "unsafe"}"#), None, Some(r#"{"last": 1}"#), &o);
    notify_case("time-nan", Some(r#"{"time": NaN, "ssid": "s", "verdict": "unsafe"}"#), None, Some(r#"{"last": NaN}"#), &o);
    notify_case("time-nan-list", Some(r#"{"time": [NaN], "ssid": "s", "verdict": "unsafe"}"#), None, Some(r#"{"last": [NaN]}"#), &o);
    // damaged files
    for (n, bad) in [
        ("not-json", "{\"time\": "),
        ("list", "[1, 2]"),
        ("string", "\"x\""),
        ("bom", "\u{feff}{}"),
        ("latin1", "{\"ssid\": \"caf\u{e9}\"}"),
        ("dup", r#"{"time": "a", "ssid": "x", "verdict": "safe", "time": "b"}"#),
        ("trailing", r#"{"time": "a"} x"#),
        ("deep", &format!("{{\"time\": \"t\", \"ssid\": {}1{}}}", "[".repeat(300), "]".repeat(300))),
    ] {
        notify_case(&format!("bad-public-{n}"), Some(bad), Some(bad), Some(bad), &o);
    }
    let latin1 = |r: &Root| {
        notify_root(r, Some(r#"{"time": "t", "ssid": "x", "verdict": "unsafe"}"#), None, None);
        r.write("/home/owner/.local/state/heimdall/wifi-notified.json", b"{\"last\": \"caf\xe9\"}");
    };
    case("notify-seen-not-utf8", NOTIFY, &latin1, &[], &o, &["/home/owner", "/run"]);
    let folder = |r: &Root| {
        notify_root(r, None, None, None);
        r.mkdir("/run/heimdall-wifi/last.json", 0o755);
    };
    case("notify-public-folder", NOTIFY, &folder, &[], &o, &["/home/owner", "/run"]);
    // where the state goes
    let xdg = Opts { env: vec![("XDG_STATE_HOME".into(), "/home/owner/xdg/".into())], ..notify_opts() };
    notify_case("xdg", Some(unsafe_), None, None, &xdg);
    let empty_xdg = Opts { env: vec![("XDG_STATE_HOME".into(), String::new())], ..notify_opts() };
    notify_case("xdg-empty", Some(unsafe_), None, None, &empty_xdg);
    let home_slash = Opts { env: vec![("HOME".into(), "/home/owner//".into())], ..notify_opts() };
    notify_case("home-slashes", Some(unsafe_), None, None, &home_slash);
    let not_writable = Opts { env: vec![("XDG_STATE_HOME".into(), "/run/heimdall-wifi/last.json".into())], ..notify_opts() };
    notify_case("state-unwritable", Some(unsafe_), Some(r#"{"time": "g", "event": "vpn-up"}"#), None, &not_writable);
    // no notify-send at all: Python stops with FileNotFoundError, before anything is remembered
    let no_tool = Opts { env: vec![("PATH".into(), "/opt/py".into())], ..notify_opts() };
    let without = |r: &Root| {
        notify_root(r, Some(unsafe_), None, None);
        r.symlink("/usr/bin/python3", "/opt/py/python3");
    };
    case("notify-no-notify-send", NOTIFY, &without, &[], &no_tool, &["/home/owner", "/run"]);
    // a notify-send that prints and fails: its output passes through, its failure is ignored
    let loud = |r: &Root| {
        notify_root(r, Some(unsafe_), Some(r#"{"time": "g", "event": "dropped"}"#), None);
        recorder(r, "notify-send", "echo shown; echo oops >&2; exit 3\n");
    };
    case("notify-send-fails", NOTIFY, &loud, &["--any", "argument"], &o, &["/home/owner", "/run"]);
    report("notify_as_python", before);
}

#[test]
fn notify_send_that_hangs_is_killed_after_ten_seconds() {
    let hang = |r: &Root| {
        notify_root(r, Some(r#"{"time": "t", "ssid": "s", "verdict": "unsafe"}"#), None, None);
        recorder(r, "notify-send", "exec sleep 30\n");
    };
    let o = Opts { pid: true, timeout: std::time::Duration::from_secs(40), ..notify_opts() };
    let p = case("notify-hang", NOTIFY, &hang, &[], &o, &["/home/owner", "/run"]);
    assert_eq!(exception(&p.rs.0.stderr, false).as_deref(), Some("TimeoutExpired"));
}

// ---- heimdall-wifi-guard

const GUARD: &str = "heimdall-wifi-guard";
const GUARD_DIRS: &[&str] = &["/etc/heimdall", "/run", "/srv"];

/// The fakes the guard talks to; what they answer is in /srv (each scenario writes it).
fn guard_root(r: &Root) {
    r.mkdir("/sys/class/net/wlan0/wireless", 0o755);
    r.mkdir("/sys/class/net/eth0", 0o755);
    r.mkdir("/etc/heimdall", 0o755);
    r.mkdir("/srv", 0o755);
    r.write("/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n203.0.113.7 vpn.example\n2001:db8::7 vpn.example\n");
    recorder(
        r,
        "nmcli",
        r#"case "$*" in
  "-t -f DEVICE,TYPE,STATE,CONNECTION device") cat /srv/devices 2>/dev/null ;;
  "-g GENERAL.CON-UUID device show "*) cat /srv/con-uuid 2>/dev/null ;;
  "-g 802-11-wireless.ssid connection show "*) if [ -e /srv/ssid ]; then cat /srv/ssid; else echo Cafe; fi ;;
  "-g 802-11-wireless.cloned-mac-address connection show "*) cat /srv/cloned 2>/dev/null ;;
  "connection up "*) [ -e /srv/vpn-fails ] && exit 4; exit 0 ;;
  "connection import type wireguard file "*)
    f=$6; { stat -c 'mode %a' "$f"; cat "$f"; } >> /srv/import-seen
    cat /srv/import-answer 2>/dev/null
    if [ -e /srv/import-fails ]; then echo 'Error: failed to import: bad file' >&2; exit 1; fi ;;
  "connection modify "*) if [ -e /srv/modify-fails ]; then echo 'Error: unknown connection' >&2; exit 10; fi ;;
  "-t -f CONNECTIVITY general") if [ -e /srv/connectivity ]; then cat /srv/connectivity; else echo full; fi ;;
  *) exit 0 ;;
esac
"#,
    );
    recorder(
        r,
        "nft",
        r#"case "$*" in
  "list table inet heimdall_wifi_guard") [ -e /srv/table ] ;;
  "delete table inet heimdall_wifi_guard") if [ -e /srv/table ]; then rm /srv/table; else echo 'Error: No such file or directory' >&2; exit 1; fi ;;
  "-f -") cat > /srv/nft-rules; if [ -e /srv/nft-fails ]; then echo 'Error: syntax error, unexpected junk' >&2; exit 1; fi; touch /srv/table ;;
  "-c -f -") cat > /srv/nft-check; if [ -e /srv/nft-fails ]; then echo 'Error: syntax error, unexpected junk' >&2; exit 1; fi ;;
  *) exit 1 ;;
esac
"#,
    );
    recorder(
        r,
        "ip",
        r#"case "$*" in
  "-j route show default dev "*) cat /srv/routes 2>/dev/null ;;
  "-j neigh show "*) cat /srv/neigh 2>/dev/null ;;
  *) exit 1 ;;
esac
"#,
    );
    recorder(r, "ping", "if [ -e /srv/neigh-later ]; then mv /srv/neigh-later /srv/neigh; exit 0; fi\nexit 1\n");
    recorder(
        r,
        "systemctl",
        r#"case "$*" in
  "is-active avahi-daemon.service") if [ -e /srv/avahi-on ]; then echo active; else echo inactive; exit 3; fi ;;
  "stop avahi-daemon.socket avahi-daemon.service") rm -f /srv/avahi-on ;;
  "start avahi-daemon.socket avahi-daemon.service") touch /srv/avahi-on ;;
  *) exit 1 ;;
esac
"#,
    );
}

const ROUTER: &str = "00:00:5e:00:53:01";
const STRANGER: &str = "00:00:5e:00:53:09";

/// On Wi-Fi: wlan0 connected to the profile `uuid`, its router at 192.0.2.1 with hardware address `mac`.
fn on_wifi(r: &Root, uuid: &str, mac: &str) {
    r.write("/srv/devices", "wlan0:wifi:connected:Cafe\\:Free\neth0:ethernet:unavailable:--\nlo:loopback:connected (externally):lo\n");
    r.write("/srv/con-uuid", format!("{uuid}\n"));
    r.write(
        "/srv/routes",
        r#"[{"dst":"default","gateway":"192.0.2.1","dev":"wlan0","protocol":"dhcp","prefsrc":"192.0.2.10","metric":600,"flags":[]}]"#,
    );
    r.write("/srv/neigh", format!(r#"[{{"dst":"192.0.2.1","dev":"wlan0","lladdr":"{mac}","state":["REACHABLE"]}}]"#));
}

fn vpn_conf(r: &Root) {
    r.write(
        "/etc/heimdall/wifi-guard.json",
        r#"{"vpn": {"uuid": "vpn-uuid", "iface": "wg-heimdall", "endpoints": [{"ip": "203.0.113.5", "port": 51820}]}}"#,
    );
}

fn trusted_home(r: &Root) {
    r.write(
        "/etc/heimdall/wifi-trusted.json",
        format!(r#"{{"0e3f5a1c-2222-4333-8444-955566667777": {{"ssid": "Home", "routers": ["{}"]}}}}"#, ROUTER.to_uppercase()),
    );
}

fn root_opts() -> Opts {
    Opts::default()
}

fn guard_twin(test: &str, build: &dyn Fn(&Root)) -> Twin {
    Twin::new(&format!("guard-{test}"), GUARD, GUARD_DIRS, &|r: &Root| {
        guard_root(r);
        build(r);
    })
}

fn argv_log(t: &Twin) -> String {
    t.rs.read_str("/.fake-argv")
}

/// The cases of packaging/tests/test_heimdall_wifi_guard.py, as whole runs of both programs.
#[test]
fn guard_cases_of_the_python_tests() {
    let before = RUNS.with(Cell::get);
    let o = root_opts();
    // an untrusted network: locked before the connection carries traffic, then the VPN
    let mut t = guard_twin("untrusted-locks-then-vpn", &|r| {
        vpn_conf(r);
        on_wifi(r, "cafe-uuid", ROUTER);
        r.write("/srv/avahi-on", "");
    });
    t.step(&["pre-up", "wlan0", "cafe-uuid"], &o);
    assert!(argv_log(&t).contains("nft [-f] [-]") && t.rs.read("/srv/table").is_some(), "locked: {}", argv_log(&t));
    t.step(&["up", "wlan0", "cafe-uuid"], &o);
    let log = argv_log(&t);
    assert!(log.contains("nmcli [connection] [up] [vpn-uuid]") && !log.contains("[device] [disconnect]"), "{log}");
    assert!(log.contains("systemctl [stop] [avahi-daemon.socket] [avahi-daemon.service]"), "it announces itself: {log}");
    assert!(log.contains("[ipv4.dhcp-send-hostname] [no]"), "{log}");
    assert!(t.rs.read_str("/run/heimdall-wifi-guard/last.json").contains("\"event\": \"vpn-up\""));
    // the VPN failing drops the Wi-Fi
    let mut t = guard_twin("vpn-fails", &|r| {
        vpn_conf(r);
        on_wifi(r, "cafe-uuid", ROUTER);
        r.write("/srv/vpn-fails", "");
    });
    t.step(&["pre-up", "wlan0", "cafe-uuid"], &o);
    t.step(&["up", "wlan0", "cafe-uuid"], &o);
    assert!(argv_log(&t).contains("nmcli [device] [disconnect] [wlan0]"));
    assert!(t.rs.read_str("/run/heimdall-wifi-guard/last.json").contains("\"event\": \"dropped\""));
    // the VPN dropping later drops the Wi-Fi
    let mut t = guard_twin("vpn-drops-later", &|r| {
        vpn_conf(r);
        on_wifi(r, "cafe-uuid", ROUTER);
    });
    t.step(&["pre-up", "wlan0", "cafe-uuid"], &o);
    t.step(&["up", "wlan0", "cafe-uuid"], &o);
    t.step(&["down", "wg-heimdall", "vpn-uuid"], &o);
    assert!(argv_log(&t).contains("nmcli [device] [disconnect] [wlan0]"));
    assert!(t.rs.read_str("/run/heimdall-wifi-guard/last.json").contains("\"event\": \"dropped\""));
    // a trusted network is left alone, unless its router is another one
    let mut t = guard_twin("trusted-unless-router-differs", &|r| {
        vpn_conf(r);
        trusted_home(r);
        on_wifi(r, "0e3f5a1c-2222-4333-8444-955566667777", ROUTER);
    });
    t.step(&["pre-up", "wlan0", "0e3f5a1c-2222-4333-8444-955566667777"], &o);
    t.step(&["up", "wlan0", "0e3f5a1c-2222-4333-8444-955566667777"], &o);
    assert!(!argv_log(&t).contains("nft [-f]") && !argv_log(&t).contains("[connection] [up]"), "{}", argv_log(&t));
    t.both(|r| on_wifi(r, "0e3f5a1c-2222-4333-8444-955566667777", STRANGER));
    t.step(&["up", "wlan0", "0e3f5a1c-2222-4333-8444-955566667777"], &o);
    assert!(argv_log(&t).contains("nft [-f] [-]") && argv_log(&t).contains("nmcli [connection] [up] [vpn-uuid]"));
    assert!(t.rs.read_str("/run/heimdall-wifi-guard/last.json").contains("vpn-up"));
    // the real hardware address is replaced by one of the network's own, unless one was chosen
    for cloned in ["", "permanent", "preserve", "--", "  permanent  ", "random", "stable", "00:00:5E:00:53:5E"] {
        let mut t = guard_twin(&format!("cloned-{}", cloned.trim()), &|r| {
            on_wifi(r, "cafe-uuid", ROUTER);
            r.write("/srv/cloned", format!("{cloned}\n"));
        });
        t.step(&["up", "wlan0", "cafe-uuid"], &o);
        let stable = argv_log(&t).contains("[802-11-wireless.cloned-mac-address] [stable]");
        assert_eq!(stable, matches!(cloned.trim(), "" | "permanent" | "preserve" | "--"), "{cloned:?}");
    }
    // no VPN: quiet, not locked, and told
    let mut t = guard_twin("no-vpn", &|r| on_wifi(r, "cafe-uuid", ROUTER));
    t.step(&["pre-up", "wlan0", "cafe-uuid"], &o);
    t.step(&["up", "wlan0", "cafe-uuid"], &o);
    assert!(!argv_log(&t).contains("nft [-f]"));
    assert!(t.rs.read_str("/run/heimdall-wifi-guard/last.json").contains("no-vpn"));
    // the rules allow only DHCP and the VPN; a WireGuard file is read
    let mut t = guard_twin("ruleset", &|r| {
        r.write(
            "/srv/wg.conf",
            "[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\nEndpoint = 203.0.113.5:51820\n[Peer]\nendpoint=[2001:db8::5]:51820\n",
        );
    });
    let (_, rs) = t.step(&["ruleset-check", "/srv/wg.conf"], &o);
    assert!(rs.stdout.contains("policy drop;") && rs.stdout.contains("ip daddr 203.0.113.5 udp dport 51820 accept"), "{}", rs.stdout);
    assert!(rs.stdout.contains("ip6 daddr 2001:db8::5 udp dport 51820 accept") && rs.stdout.contains("oifname \"wg-heimdall\" accept"));
    assert!(!rs.stdout.contains("tcp"));
    report("guard_cases_of_the_python_tests", before);
}

#[test]
fn guard_commands_as_python() {
    let before = RUNS.with(Cell::get);
    let o = root_opts();
    let user = Opts::user();
    // usage, and what needs root
    let mut t = guard_twin("usage", &|_| {});
    for args in [&[][..], &["help"], &["pre-up", "wlan0"], &["untrust"], &["vpn-import"], &["up"], &["frobnicate", "x"]] {
        let (py, _) = t.step(args, &o);
        assert_eq!(py.code, 2);
    }
    for args in [
        &["trust"][..],
        &["untrust", "Home"],
        &["vpn-import", "/x"],
        &["vpn-remove"],
        &["sign-in"],
        &["ruleset-check"],
        &["pre-up", "wlan0", "u"],
        &["down", "a", "b", "c"],
    ] {
        let (py, _) = t.step(args, &user);
        assert_eq!(py.code, 1, "{args:?}");
    }
    // status: nothing, then as root and as a user with networks, a VPN and the lockdown on
    t.step(&["status"], &user);
    t.step(&["status"], &o);
    t.both(|r| {
        vpn_conf(r);
        r.write(
            "/etc/heimdall/wifi-trusted.json",
            r#"{"0e3f5a1c-2222-4333-8444-955566667777": {"ssid": "Home", "routers": ["00:00:5E:00:53:01", "00:00:5E:00:53:02"]}, "u2": {"ssid": null, "routers": "AB"}, "u3": {"ssid": ["x"]}}"#,
        );
        on_wifi(r, "0e3f5a1c-2222-4333-8444-955566667777", ROUTER);
        r.write("/srv/table", "");
    });
    t.step(&["status"], &o);
    t.step(&["status"], &user);
    t.both(|r| on_wifi(r, "cafe-uuid", ROUTER));
    t.step(&["status"], &o);
    // trust: the network on now, then again (no second copy), then a second router
    let mut t = guard_twin("trust", &|r| {
        on_wifi(r, "0e3f5a1c-2222-4333-8444-955566667777", ROUTER);
        r.write("/srv/ssid", "Home Sweet: Home\n");
        r.write("/srv/avahi-on", "");
    });
    t.step(&["trust"], &o);
    t.step(&["trust"], &o);
    t.both(|r| on_wifi(r, "0e3f5a1c-2222-4333-8444-955566667777", "00:00:5e:00:53:02"));
    t.step(&["trust"], &o);
    t.step(&["status"], &o);
    t.step(&["untrust", "nothing-by-that-name"], &o);
    t.step(&["untrust", "Home Sweet: Home"], &o);
    t.step(&["status"], &o);
    // trust when not on Wi-Fi, and when the router does not answer (five tries, a ping each)
    let mut t = guard_twin("trust-refused", &|_| {});
    t.step(&["trust"], &o);
    t.both(|r| {
        on_wifi(r, "0e3f5a1c-2222-4333-8444-955566667777", ROUTER);
        r.write("/srv/neigh", "[]");
    });
    let (py, _) = t.step(&["trust"], &o);
    assert!(py.stderr.contains("could not be read"), "{}", py.stderr);
    t.both(|r| {
        r.write("/srv/neigh-later", format!(r#"[{{"dst":"192.0.2.1","lladdr":"{ROUTER}"}}]"#));
    });
    t.step(&["trust"], &o);
    t.both(|r| {
        r.write("/srv/modify-fails", "");
    });
    t.step(&["untrust", "0e3f5a1c-2222-4333-8444-955566667777"], &o);
    t.step(&["trust"], &o);
    // vpn-import: endpoints by address and by name, CRLF line ends, the file private while NetworkManager reads it
    let wg = "[Interface]\r\nPrivateKey = cHJpdmF0ZQ==\r\nAddress = 10.2.0.2/32\r\n\r\n[Peer]\r\nPublicKey = cHVibGlj\r\nEndpoint = vpn.example:51820\r\n  ENDPOINT\t=  [2001:DB8:0:0:0:0:0:5]:443  # second\r\nEndpoint = 203.0.113.5:0051820\r\n";
    let mut t = guard_twin("vpn-import", &|r| {
        r.write("/srv/wg.conf", wg);
        r.write("/srv/import-answer", "Connection 'wg-heimdall' (0e3f5a1c-1111-4222-8333-944455556666) successfully added.\n");
    });
    t.step(&["vpn-import", "/srv/wg.conf"], &o);
    assert!(t.py.read_str("/srv/import-seen").starts_with("mode 600\n"), "{}", t.py.read_str("/srv/import-seen"));
    assert!(t.py.read("/run/wg-heimdall.conf").is_none());
    t.step(&["status"], &o);
    t.both(|r| {
        r.write_mode("/run/wg-heimdall.conf", "left over\n", 0o644);
    });
    t.step(&["vpn-import", "/srv/wg.conf"], &o); // again: the old connection deleted first; a file left there made private
    t.step(&["ruleset-check", "/srv/wg.conf"], &o);
    t.step(&["vpn-remove"], &o);
    t.step(&["vpn-remove"], &o);
    t.step(&["status"], &o);
    // vpn-import failing: no Endpoint, NetworkManager refusing the file, not naming the connection, a missing file
    let mut t = guard_twin("vpn-import-fails", &|r| {
        r.write("/srv/none.conf", "[Interface]\nPrivateKey = x\n");
        r.write("/srv/wg.conf", "[Peer]\nEndpoint = 203.0.113.5:51820\n");
        r.write("/srv/import-answer", "Connection 'wg-heimdall' successfully added.\n");
    });
    t.step(&["vpn-import", "/srv/none.conf"], &o);
    t.step(&["vpn-import", "/srv/wg.conf"], &o);
    t.both(|r| {
        r.write("/srv/import-fails", "");
    });
    let (py, _) = t.step(&["vpn-import", "/srv/wg.conf"], &o);
    assert!(py.stderr.starts_with("heimdall-wifi-guard: nmcli connection import: Error"), "{}", py.stderr);
    t.step(&["vpn-import", "/srv/missing.conf"], &o);
    t.step(&["vpn-import", "/srv"], &o);
    t.both(|r| {
        std::fs::remove_file(r.host("/srv/import-fails")).unwrap();
        r.write("/srv/import-answer", "(0e3f5a1c-1111-4222-8333-944455556666)\n");
        r.write("/srv/modify-fails", "");
    });
    t.step(&["vpn-import", "/srv/wg.conf"], &o);
    // ruleset-check: the default endpoint, nft refusing the rules
    let mut t = guard_twin("ruleset-check", &|_| {});
    t.step(&["ruleset-check"], &o);
    t.both(|r| {
        r.write("/srv/nft-fails", "");
    });
    let (py, _) = t.step(&["ruleset-check"], &o);
    assert_eq!(py.code, 1);
    t.step(&["ruleset-check", "/srv/missing.conf"], &o);
    // sign-in: nothing to do; the page signed into at once; the VPN failing after it
    let mut t = guard_twin("sign-in", &|r| {
        on_wifi(r, "cafe-uuid", ROUTER);
        r.mkdir("/run/heimdall-wifi-guard", 0o755);
    });
    t.step(&["sign-in"], &o);
    t.both(vpn_conf);
    t.step(&["sign-in"], &o);
    t.both(|r| {
        r.write("/srv/vpn-fails", "");
    });
    t.step(&["sign-in"], &o);
    t.both(|r| {
        r.write("/srv/devices", "eth0:ethernet:connected:Wired\n");
    });
    t.step(&["sign-in"], &o);
    // sign-in with no folder for its flag yet: Python stops there
    let mut t = guard_twin("sign-in-no-run", &|r| {
        vpn_conf(r);
        on_wifi(r, "cafe-uuid", ROUTER);
    });
    t.step(&["sign-in"], &o);
    // down: of a trusted network (Avahi back on), of something else, of the VPN while signing in
    let mut t = guard_twin("down", &|r| {
        vpn_conf(r);
        on_wifi(r, "cafe-uuid", ROUTER);
        r.write("/srv/avahi-on", "");
    });
    t.step(&["up", "wlan0", "cafe-uuid"], &o);
    t.step(&["down", "eth0", "other-uuid"], &o);
    t.both(|r| {
        r.write("/run/heimdall-wifi-guard/signing-in", "");
    });
    t.step(&["down", "wg-heimdall", "vpn-uuid"], &o);
    t.both(|r| std::fs::remove_file(r.host("/run/heimdall-wifi-guard/signing-in")).unwrap());
    t.step(&["down", "eth0", "cafe-uuid"], &o);
    t.step(&["down", "wlan0", "cafe-uuid"], &o);
    // the lockdown refused by nft
    let mut t = guard_twin("lock-fails", &|r| {
        vpn_conf(r);
        on_wifi(r, "cafe-uuid", ROUTER);
        r.write("/srv/nft-fails", "");
    });
    let (py, _) = t.step(&["pre-up", "wlan0", "cafe-uuid"], &o);
    assert!(py.stderr.starts_with("heimdall-wifi-guard: the lockdown could not be set: Error"), "{}", py.stderr);
    t.step(&["up", "wlan0", "cafe-uuid"], &o);
    // not Wi-Fi at all
    let mut t = guard_twin("ethernet", &vpn_conf);
    t.step(&["pre-up", "eth0", "wired-uuid"], &o);
    t.step(&["up", "eth0", "wired-uuid"], &o);
    t.step(&["down", "eth0", "wired-uuid"], &o);
    report("guard_commands_as_python", before);
}

#[test]
fn guard_odd_input_as_python() {
    let before = RUNS.with(Cell::get);
    let o = root_opts();
    // the router's address: no route, a broken answer, a gateway that is not a string, a hardware address that is a number
    let routes = [
        ("none", "", ""),
        ("empty", "[]", ""),
        ("broken", "[{", ""),
        ("blank", "\n", ""),
        ("no-gateway", r#"[{"dst":"default","dev":"wlan0"}]"#, ""),
        ("gateway-number", r#"[{"gateway":5}]"#, "[]"),
        ("gateway-list", r#"[{"gateway":[1]}]"#, "[]"),
        ("routes-dict", r#"{"gateway":"192.0.2.1"}"#, ""),
        ("routes-string", r#""x""#, ""),
        ("routes-number", "7", ""),
        ("routes-null", "null", ""),
        ("lladdr-number", r#"[{"gateway":"192.0.2.1"}]"#, r#"[{"lladdr":17}]"#),
        ("lladdr-empty", r#"[{"gateway":"192.0.2.1"}]"#, r#"[{"lladdr":""},{"lladdr":"0a:0b:0c:0d:0e:0f"}]"#),
        ("neigh-broken", r#"[{"gateway":"192.0.2.1"}]"#, "{"),
        ("neigh-dict", r#"[{"gateway":"192.0.2.1"}]"#, r#"{"lladdr":"x"}"#),
        ("not-utf8", "[{\"gateway\":\"192.0.2.1\"}]", "\u{0}"),
    ];
    for (n, route, neigh) in routes {
        let mut t = guard_twin(&format!("route-{n}"), &|r| {
            vpn_conf(r);
            trusted_home(r);
            on_wifi(r, "0e3f5a1c-2222-4333-8444-955566667777", ROUTER);
            r.write("/srv/routes", route);
            r.write("/srv/neigh", neigh);
            if n == "not-utf8" {
                r.write("/srv/neigh", b"[{\"lladdr\":\"\xff\"}]");
            }
        });
        t.step(&["up", "wlan0", "0e3f5a1c-2222-4333-8444-955566667777"], &o);
        t.step(&["trust"], &o);
    }
    // damaged or odd files: the trusted list, the configuration, the state
    let files: &[(&str, &str, &str)] = &[
        ("trusted-list", "/etc/heimdall/wifi-trusted.json", "[1, 2]"),
        ("trusted-broken", "/etc/heimdall/wifi-trusted.json", "{\"0e3f5a1c-2222-4333-8444-955566667777\": "),
        ("trusted-null", "/etc/heimdall/wifi-trusted.json", "null"),
        ("trusted-entry-string", "/etc/heimdall/wifi-trusted.json", r#"{"0e3f5a1c-2222-4333-8444-955566667777": "yes"}"#),
        ("trusted-entry-list", "/etc/heimdall/wifi-trusted.json", r#"{"0e3f5a1c-2222-4333-8444-955566667777": [1]}"#),
        (
            "trusted-routers-string",
            "/etc/heimdall/wifi-trusted.json",
            r#"{"0e3f5a1c-2222-4333-8444-955566667777": {"ssid": "H", "routers": "00:00:5E:00:53:01 and more"}}"#,
        ),
        (
            "trusted-routers-dict",
            "/etc/heimdall/wifi-trusted.json",
            r#"{"0e3f5a1c-2222-4333-8444-955566667777": {"routers": {"00:00:5E:00:53:01": 1}}}"#,
        ),
        ("trusted-routers-number", "/etc/heimdall/wifi-trusted.json", r#"{"0e3f5a1c-2222-4333-8444-955566667777": {"routers": 3}}"#),
        ("trusted-no-routers", "/etc/heimdall/wifi-trusted.json", r#"{"0e3f5a1c-2222-4333-8444-955566667777": {"ssid": "H"}}"#),
        (
            "trusted-false",
            "/etc/heimdall/wifi-trusted.json",
            r#"{"0e3f5a1c-2222-4333-8444-955566667777": false, "x": NaN, "y": 1e999, "z": -0.0, "w": 12345678901234567890123}"#,
        ),
        (
            "trusted-dup",
            "/etc/heimdall/wifi-trusted.json",
            r#"{"0e3f5a1c-2222-4333-8444-955566667777": {"routers": []}, "a": 1, "0e3f5a1c-2222-4333-8444-955566667777": {"ssid": "again", "routers": ["00:00:5E:00:53:01"]}}"#,
        ),
        ("conf-list", "/etc/heimdall/wifi-guard.json", "[]"),
        ("conf-broken", "/etc/heimdall/wifi-guard.json", "{"),
        ("conf-bom", "/etc/heimdall/wifi-guard.json", "\u{feff}{\"vpn\": {\"uuid\": \"v\"}}"),
        ("vpn-string", "/etc/heimdall/wifi-guard.json", r#"{"vpn": "yes"}"#),
        ("vpn-no-uuid", "/etc/heimdall/wifi-guard.json", r#"{"vpn": {"endpoints": []}}"#),
        ("vpn-uuid-number", "/etc/heimdall/wifi-guard.json", r#"{"vpn": {"uuid": 5, "endpoints": []}}"#),
        ("vpn-endpoints-dict", "/etc/heimdall/wifi-guard.json", r#"{"vpn": {"uuid": "v", "endpoints": {"a": 1}}}"#),
        (
            "vpn-endpoint-bad-ip",
            "/etc/heimdall/wifi-guard.json",
            r#"{"vpn": {"uuid": "v", "endpoints": [{"ip": "203.0.113.05", "port": 1}]}}"#,
        ),
        (
            "vpn-endpoint-odd",
            "/etc/heimdall/wifi-guard.json",
            r#"{"vpn": {"uuid": "v", "iface": "wg0; drop", "endpoints": [{"ip": 3405803781, "port": "  51_820 "}, {"ip": true, "port": 2.9}, {"ip": "2001:DB8::0:5%wg", "port": false}, {"ip": "::ffff:203.0.113.5", "port": -1}, {"ip": "::203.0.113.5", "port": 1}]}}"#,
        ),
        ("vpn-endpoint-no-port", "/etc/heimdall/wifi-guard.json", r#"{"vpn": {"uuid": "v", "endpoints": [{"ip": "203.0.113.5"}]}}"#),
        (
            "vpn-endpoint-port-text",
            "/etc/heimdall/wifi-guard.json",
            r#"{"vpn": {"uuid": "v", "endpoints": [{"ip": "203.0.113.5", "port": "x"}]}}"#,
        ),
        ("vpn-iface-number", "/etc/heimdall/wifi-guard.json", r#"{"vpn": {"uuid": "v", "iface": 7}}"#),
        ("state-broken", "/run/heimdall-wifi-guard/state.json", "{\"wifi\""),
        ("state-list", "/run/heimdall-wifi-guard/state.json", "[[\"wifi\", \"x\"]]"),
        (
            "state-odd",
            "/run/heimdall-wifi-guard/state.json",
            r#"{"wifi": 5, "iface": "wlan0", "trusted": 0, "avahi_was_on": "yes", "extra": {"k": [1, 2.5]}}"#,
        ),
    ];
    for (n, path, data) in files {
        let mut t = guard_twin(n, &|r| {
            vpn_conf(r);
            trusted_home(r);
            on_wifi(r, "0e3f5a1c-2222-4333-8444-955566667777", ROUTER);
            r.write(path, data);
        });
        for step in [
            &["pre-up", "wlan0", "0e3f5a1c-2222-4333-8444-955566667777"][..],
            &["up", "wlan0", "0e3f5a1c-2222-4333-8444-955566667777"],
            &["status"],
            &["down", "wg-heimdall", "v"],
        ] {
            t.step(step, &o);
        }
        t.step(&["down", "wlan0", "0e3f5a1c-2222-4333-8444-955566667777"], &o);
        t.step(&["trust"], &o);
        t.step(&["untrust", "H"], &o);
        t.step(&["vpn-remove"], &o);
    }
    // names from NetworkManager: escapes, odd characters, line ends inside, not UTF-8
    for (n, ssid) in [
        ("colon", b"Caf\\:e \\\\ x\n".to_vec()),
        ("cr", b"evil\rname\r\n".to_vec()),
        ("spaces", " \u{2003}name\u{1c}\t\n".as_bytes().to_vec()),
        ("emoji", "\u{1f600}\u{200b}\n".as_bytes().to_vec()),
        ("latin1", b"caf\xe9\n".to_vec()),
    ] {
        let mut t = guard_twin(&format!("ssid-{n}"), &|r| {
            on_wifi(r, "cafe-uuid", ROUTER);
            r.write("/srv/ssid", &ssid);
        });
        t.step(&["up", "wlan0", "cafe-uuid"], &o);
        t.step(&["trust"], &o);
        t.step(&["status"], &o);
    }
    // device lists: an escaped name, a list without Wi-Fi, a line of three fields
    for (n, devices) in [
        ("escaped", "wl\\:an0:wifi:connected:x\n"),
        ("short", "wlan0:wifi:connected\n"),
        ("disconnected", "wlan0:wifi:disconnected:--\n"),
        ("blank", "\n\n"),
        ("second", "eth0:ethernet:connected:Wired\nwlan1:wifi:connected:Two\n"),
    ] {
        let mut t = guard_twin(&format!("devices-{n}"), &|r| {
            vpn_conf(r);
            on_wifi(r, "cafe-uuid", ROUTER);
            r.write("/srv/devices", devices);
        });
        t.step(&["status"], &o);
        t.step(&["trust"], &o);
    }
    // WireGuard files of every shape the owner could hand it
    for (n, wg) in [
        ("hostname-only", "Endpoint = vpn.example:51820\n"),
        ("no-port", "Endpoint = 203.0.113.5\n"),
        ("bad-port", "Endpoint = 203.0.113.5:port\n"),
        ("bad-port-name", "Endpoint = vpn.example:port\n"),
        ("huge-port", "Endpoint = vpn.example:99999999999999999999\n"),
        ("unknown-name", "Endpoint = nowhere.invalid:51820\n"),
        ("empty-label", "Endpoint = vpn..example:51820\n"),
        ("dotless-i", "Endpo\u{131}nt = 203.0.113.5:1\nENDPO\u{130}NT=203.0.113.6:2\nEndpoints = 203.0.113.7:3\nEndpoint =\n#Endpoint = 203.0.113.8:4\n"),
        ("unicode-port", "Endpoint = 203.0.113.5:\u{665}\u{661}\n"),
        ("leading-zero-ip", "Endpoint = 0300.0.2.1:51820\n"),
        ("v6-forms", "Endpoint = [::]:1\nEndpoint = [1::]:2\nEndpoint = [::ffff:0:0]:3\nEndpoint = [fe80::1%wlan0]:4\nEndpoint = [1:2:3:4:5:6:7:8]:5\nEndpoint = [1:2:3:4:5:6:7::]:6\nEndpoint = [::1:2:3:4:5:6:7]:7\n"),
        ("v6-bad", "Endpoint = [1:::2]:1\n"),
        ("not-utf8", "Endpoint = 203.0.113.5:1 \u{fffd}\n"),
    ] {
        let mut t = guard_twin(&format!("wg-{n}"), &|r| {
            r.write("/srv/wg.conf", wg);
            if n == "not-utf8" {
                r.write("/srv/wg.conf", b"Endpoint = 203.0.113.5:1 \xff\n");
            }
            r.write("/srv/import-answer", "Connection 'wg-heimdall' (0e3f5a1c-1111-4222-8333-944455556666) successfully added.\n");
        });
        t.step(&["ruleset-check", "/srv/wg.conf"], &o);
        t.step(&["vpn-import", "/srv/wg.conf"], &o);
    }
    report("guard_odd_input_as_python", before);
}

// ---- heimdall-wifi-check

const CHECK: &str = "heimdall-wifi-check";
const CHECK_DIRS: &[&str] = &["/var/lib/heimdall", "/run", "/srv", "/etc/heimdall"];

/// The test authorities and certificates (openssl, made once per test run): a trusted authority and, from it, the four
/// well-known names' certificate, one for another name, one expired, a sign-in portal's; a self-signed certificate for the
/// names; an authority nobody trusts and its certificate for the names.
fn check_certs() -> PathBuf {
    static D: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    D.get_or_init(|| {
        let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("wifi-check-certs-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let script = r#"set -e
ec='-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes'
names='DNS:www.google.com,DNS:github.com,DNS:www.wikipedia.org,DNS:www.cloudflare.com'
ca() { openssl req -x509 $ec -keyout $1.key -out $1.crt -subj "/CN=$2" -days 3 -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null; }
leaf() { # name, authority, subject names, extra x509 options
  openssl req $ec -keyout $1.key -out $1.csr -subj "/CN=$1" 2>/dev/null
  printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' "$3" > $1.ext
  openssl x509 -req -in $1.csr -CA $2.crt -CAkey $2.key -CAcreateserial -out $1.crt -extfile $1.ext $4 2>/dev/null
}
ca ca 'Heimdall Test CA'
ca evilca 'Totally Trusted Root'
leaf good ca "$names" '-days 3'
leaf wrong ca 'DNS:other.test' '-days 3'
leaf expired ca "$names" '-not_before 20200101000000Z -not_after 20200102000000Z'
leaf portal ca 'DNS:secure.portal.example' '-days 3'
leaf evil evilca "$names" '-days 3'
cat evil.crt evilca.crt > evil-chain.crt
openssl req -x509 $ec -keyout self.key -out self.crt -subj '/CN=www.google.com' -days 3 -addext "subjectAltName=$names" -addext 'basicConstraints=critical,CA:FALSE' 2>/dev/null
"#;
        let ok = std::process::Command::new("sh").args(["-c", script]).current_dir(&d).status().unwrap().success();
        assert!(ok, "openssl made the test certificates");
        d
    })
    .clone()
}

/// A made-up Wi-Fi network and this computer on it.
#[derive(Clone)]
struct Air {
    scan: String,
    connectivity: String,
    routes: String,
    neigh: String,
    addr: String,
    ss: String,
    ufw: String,
    origins: String,
    hosts: String,
    /// TLS servers: (address, which certificate: good, wrong, expired, self, evil, evil-chain, junk)
    tls: Vec<(&'static str, &'static str)>,
    /// the web server's answers: (host and path, the raw response)
    http: Vec<(String, String)>,
    lying_dns: bool,
    devices: bool,
    files: Vec<(&'static str, Vec<u8>)>,
    env: Vec<(String, String)>,
    /// no made-up Wi-Fi at all (no interface, no servers): nothing to listen on, every connection unreachable at once
    bare: bool,
}

const OK_200: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\n\r\nsuccess\n";
const OK_204: &str = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
const SUCCESS: &str = "detectportal.firefox.com/success.txt";
const GEN204: &str = "connectivitycheck.gstatic.com/generate_204";

fn air() -> Air {
    let mut hosts = String::from("127.0.0.1 localhost\n::1 localhost\n");
    for (i, n) in ["www.google.com", "github.com", "www.wikipedia.org", "www.cloudflare.com"].iter().enumerate() {
        // the IPv4 answer (what the DNS check reads) from MCAST-TEST-NET, the one documentation block Python does not call
        // private; the IPv6 one is where the TLS server listens
        hosts.push_str(&format!("233.252.0.{} {n}\n2001:db8::4{} {n}\n", i + 1, i + 1));
    }
    hosts.push_str("192.0.2.80 detectportal.firefox.com connectivitycheck.gstatic.com portal.example\n192.0.2.81 secure.portal.example\n192.0.2.99 blackhole.example\n");
    Air {
        scan: "yes:Cafe:00\\:00\\:5E\\:00\\:53\\:21:WPA2\nno:Nachbar:00\\:00\\:5E\\:00\\:53\\:22:WPA2 WPA3\nno::00\\:00\\:5E\\:00\\:53\\:23:\n".into(),
        connectivity: "full".into(),
        routes: r#"[{"dst":"default","gateway":"192.0.2.1","dev":"wlan0","protocol":"dhcp","prefsrc":"192.0.2.10","metric":600,"flags":[]}]"#.into(),
        neigh: r#"[{"dst":"192.0.2.1","lladdr":"00:00:5e:00:53:01","state":["REACHABLE"]},{"dst":"fe80::1","lladdr":"00:00:5e:00:53:01","router":null,"state":["STALE"]}]"#.into(),
        addr: r#"[{"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1"}]},{"ifindex":2,"ifname":"wlan0","addr_info":[{"family":"inet","local":"192.0.2.10"},{"family":"inet6","local":"2001:db8::10"}]}]"#.into(),
        ss: "udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*\ntcp   LISTEN 0      4096       127.0.0.1:631        0.0.0.0:*\ntcp   LISTEN 0      4096           [::1]:631           [::]:*\n".into(),
        ufw: "active".into(),
        origins: "233.252.0.1  US, AS15169 Google LLC\n233.252.0.2  US, AS36459 GitHub, Inc.\n233.252.0.3  US, AS14907 Wikimedia Foundation Inc.\n233.252.0.4  US, AS13335 Cloudflare, Inc.\n".into(),
        hosts,
        tls: vec![("2001:db8::41", "good"), ("2001:db8::42", "good"), ("2001:db8::43", "good"), ("2001:db8::44", "good")],
        http: vec![(SUCCESS.into(), OK_200.into()), (GEN204.into(), OK_204.into())],
        lying_dns: false,
        devices: false,
        files: Vec::new(),
        env: Vec::new(),
        bare: false,
    }
}

fn http_json(a: &Air) -> String {
    let mut d = serde_json::Map::new();
    for (k, v) in &a.http {
        d.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
    serde_json::Value::Object(d).to_string()
}

fn check_root(r: &Root, a: &Air) {
    r.mkdir("/srv", 0o755);
    // U+FFFD in a scenario's text stands for a byte that is not UTF-8
    let raw = |s: &str| s.replace('\u{fffd}', "\u{1}").into_bytes().into_iter().map(|b| if b == 1 { 0xff } else { b }).collect::<Vec<u8>>();
    r.write("/srv/scan", raw(&a.scan));
    r.write("/srv/connectivity", format!("{}\n", a.connectivity));
    r.write("/srv/routes", &a.routes);
    r.write("/srv/neigh", &a.neigh);
    r.write("/srv/addr", raw(&a.addr));
    r.write("/srv/ss", &a.ss);
    r.write("/srv/ufw", format!("{}\n", a.ufw));
    r.write("/srv/origins", &a.origins);
    r.write("/srv/http.json", http_json(a));
    r.write("/etc/hosts", &a.hosts);
    r.write("/etc/host.conf", "multi on\n"); // every address of a name, not only the first line's
    if a.lying_dns {
        r.write("/etc/nsswitch.conf", "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n");
        r.write("/etc/resolv.conf", "nameserver 127.0.0.1\noptions attempts:1 timeout:2\n");
    }
    let ca = std::fs::read(check_certs().join("ca.crt")).unwrap();
    r.write("/etc/ssl/cert.pem", &ca);
    r.write("/etc/ssl/certs/ca-certificates.crt", &ca);
    for (p, data) in &a.files {
        r.write(p, data);
    }
    recorder(r, "nmcli", "case \"$*\" in\n  '-t -f ACTIVE,SSID,BSSID,SECURITY dev wifi list --rescan no') cat /srv/scan ;;\n  '-t -f CONNECTIVITY general') cat /srv/connectivity ;;\n  *) exit 1 ;;\nesac\n");
    recorder(r, "ip", "case \"$*\" in\n  '-j route show default') cat /srv/routes ;;\n  '-j neigh show dev '*) cat /srv/neigh ;;\n  '-j addr') cat /srv/addr ;;\n  *) exit 1 ;;\nesac\n");
    recorder(r, "ss", "cat /srv/ss\n");
    recorder(r, "systemctl", "[ \"$*\" = 'is-active ufw' ] || exit 1\ncat /srv/ufw\ngrep -qx active /srv/ufw\n");
    recorder(
        r,
        "heimdalld",
        "for a; do case \"$a\" in origin) ;; *) grep -m1 -F \"$a  \" /srv/origins || echo \"$a  unknown\" ;; esac; done\n",
    );
}

fn check_opts(a: &Air) -> Opts {
    if a.bare {
        return Opts { root: true, net: true, pid: true, env: a.env.clone(), ..Opts::default() };
    }
    let c = check_certs();
    let c = c.display();
    let h = repo().join("rust/parity/harness/wifi-check-net.py");
    let h = h.display();
    let mut s = String::from(
        "ip link add wlan0 type dummy\nip link set wlan0 multicast on\n\
         for a in 10 77 80 81; do ip addr add 192.0.2.$a/24 dev wlan0; done\n\
         for a in 10 41 42 43 44; do ip -6 addr add 2001:db8::$a/64 dev wlan0 nodad; done\n\
         ip link set wlan0 up\nip route add default via 192.0.2.1 dev wlan0\nip -6 route add default via 2001:db8::1 dev wlan0\n",
    );
    s.push_str(&format!("python3 -I '{h}' http \"$R/srv/http.json\" \"$R/srv/http-log\" 192.0.2.80 80 </dev/null >/dev/null 2>&1 &\n"));
    s.push_str(&format!(
        "python3 -I '{h}' http \"$R/srv/http.json\" \"$R/srv/http-log\" 192.0.2.81 443 '{c}/portal.crt' '{c}/portal.key' </dev/null >/dev/null 2>&1 &\n"
    ));
    for (addr, kind) in &a.tls {
        if *kind == "junk" {
            s.push_str(&format!("python3 -I '{h}' junk '{addr}' 443 </dev/null >/dev/null 2>&1 &\n"));
            continue;
        }
        let (cert, chain) = match *kind {
            "evil-chain" => ("evil", format!(" -cert_chain '{c}/evilca.crt'")),
            k => (k, String::new()),
        };
        s.push_str(&format!(
            "openssl s_server -quiet -www -accept '[{addr}]:443' -cert '{c}/{cert}.crt' -key '{c}/{cert}.key'{chain} </dev/null >/dev/null 2>&1 &\n"
        ));
    }
    if a.lying_dns {
        s.push_str(&format!("python3 -I '{h}' dns 127.0.0.1 </dev/null >/dev/null 2>&1 &\n"));
    }
    if a.devices {
        s.push_str(&format!("python3 -I '{h}' mcast 192.0.2.77 60 </dev/null >/dev/null 2>&1 &\n"));
    }
    // wait until the servers listen
    let mut ports: Vec<String> = vec!["192.0.2.80:80".into(), "192.0.2.81:443".into()];
    ports.extend(a.tls.iter().map(|(addr, _)| format!("[{addr}]:443")));
    s.push_str(&format!(
        "for p in {}; do for i in $(seq 100); do python3 -I -c 'import socket,sys; h,_,p=sys.argv[1].rpartition(\":\"); socket.create_connection((h.strip(\"[]\"), int(p)), 0.2).close()' \"$p\" 2>/dev/null && break; sleep 0.05; done; done\n",
        ports.join(" ")
    ));
    Opts { root: true, net: true, pid: true, setup: s, env: a.env.clone(), timeout: std::time::Duration::from_secs(150), ..Opts::default() }
}

fn check_args(extra: &[&str]) -> Vec<String> {
    extra.iter().map(|s| s.to_string()).collect()
}

/// Runs scenarios at once (each takes the check's 8 seconds of listening, some 20 seconds of waiting for connectivity),
/// both programs in each, and compares them.
fn check_scenarios(list: Vec<(String, Air, Vec<String>)>) -> Vec<(String, Pair)> {
    let mut out = Vec::new();
    // at most 12 scenarios (24 programs) at a time
    for group in list.chunks(12) {
        std::thread::scope(|sc| {
            let hs: Vec<_> = group
                .iter()
                .map(|(name, a, args)| {
                    sc.spawn(move || {
                        let args: Vec<&str> = args.iter().map(String::as_str).collect();
                        let p = run_pair(&format!("check-{name}"), CHECK, &|r| check_root(r, a), &args, &check_opts(a));
                        (name.clone(), p)
                    })
                })
                .collect();
            out.extend(hs.into_iter().map(|h| h.join().unwrap()));
        });
    }
    for (name, p) in &out {
        counted();
        assert_pair(&format!("check-{name}"), p, CHECK_DIRS);
    }
    out
}

fn find<'a>(out: &'a [(String, Pair)], name: &str) -> &'a Pair {
    &out.iter().find(|(n, _)| n == name).unwrap().1
}

#[test]
fn check_as_python() {
    let before = RUNS.with(Cell::get);
    let base = air();
    let mut list: Vec<(String, Air, Vec<String>)> = Vec::new();
    let mut add = |n: &str, a: Air, args: &[&str]| list.push((n.to_string(), a, check_args(args)));
    // a good network, trusted at home (its router remembered), as JSON and as text
    let mut home = base.clone();
    home.files.push((
        "/etc/heimdall/wifi-trusted.json",
        br#"{"0e3f5a1c-2222-4333-8444-955566667777": {"ssid": "Cafe", "routers": ["00:00:5E:00:53:01"]}}"#.to_vec(),
    ));
    add("safe-json", home.clone(), &["--uuid", "0e3f5a1c-2222-4333-8444-955566667777", "--json"]);
    add("safe-text", base.clone(), &[]);
    // the same profile with another router: not trusted (the fix of 2026-11-11), and another device heard
    let mut twin = home.clone();
    twin.neigh = r#"[{"dst":"192.0.2.1","lladdr":"00:00:5e:00:53:09"}]"#.into();
    twin.devices = true;
    add("trusted-profile-other-router", twin, &["--json", "--uuid", "0e3f5a1c-2222-4333-8444-955566667777"]);
    // an evil network: open, a twin with security, ARP spoofing, a router changed since last time, DNS that lies, every
    // kind of bad certificate, pages changed, devices heard, the firewall off
    let mut evil = base.clone();
    evil.scan = "yes:Free WiFi:00\\:00\\:5E\\:00\\:53\\:31:--\nno:Free WiFi:00\\:00\\:5E\\:00\\:53\\:32:WPA2\n".into();
    evil.neigh = r#"[{"dst":"192.0.2.1","lladdr":"00:00:5e:00:53:66"},{"dst":"192.0.2.50","lladdr":"00:00:5E:00:53:66"},{"dst":"192.0.2.51","lladdr":"00:00:5e:00:53:66"},{"dst":"2001:db8::50","lladdr":"00:00:5e:00:53:66"},{"dst":"192.0.2.52","lladdr":"00:00:5e:00:53:66"},{"dst":"192.0.2.53","lladdr":"00:00:5e:00:53:66"}]"#.into();
    evil.files.push((
        "/var/lib/heimdall/wifi/routers.json",
        format!(
            r#"{{"{}": ["00:00:5E:00:53:01"], "other": [1, 2.50, NaN]}}"#,
            heimdall::cli::wifitools::sha16("Free WiFi|00:00:5E:00:53:31")
        )
        .into_bytes(),
    ));
    evil.lying_dns = true;
    evil.hosts = evil.hosts.replace("233.252.0.2 github.com", "192.0.2.50 github.com");
    evil.origins = evil.origins.replace("AS13335 Cloudflare, Inc.", "AS64496 Example Hosting");
    evil.tls = vec![("2001:db8::41", "self"), ("2001:db8::42", "evil-chain"), ("2001:db8::43", "wrong"), ("2001:db8::44", "evil")];
    evil.http = vec![
        (SUCCESS.into(), "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n<html>x</html>".into()),
        (GEN204.into(), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into()),
    ];
    evil.devices = true;
    evil.ufw = "inactive".into();
    evil.ss = "udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 [::]:22 [::]:*\ntcp LISTEN 0 128 192.0.2.10:8080 0.0.0.0:*\nudp UNCONN 0 0 *:51820 *:*\ntcp LISTEN 0 5 [fe80::1%wlan0]:9 [::]:*\ntcp LISTEN 0 5 [::ffff:127.0.0.1]:7 [::]:*\nshort line\n".into();
    add("evil-json", evil.clone(), &["--json"]);
    add("evil-text", evil, &[]);
    // the remaining certificate failures, and hosts not reached: not TLS at all, refused, never answering
    let mut certs = base.clone();
    certs.tls = vec![("2001:db8::41", "evil"), ("2001:db8::42", "expired"), ("2001:db8::43", "good"), ("2001:db8::44", "junk")];
    add("certs-bad", certs.clone(), &[]);
    certs.tls = vec![("2001:db8::41", "junk"), ("2001:db8::43", "good")];
    certs.hosts = certs.hosts.replace("2001:db8::44 www.cloudflare.com", "192.0.2.99 www.cloudflare.com");
    add("certs-blocked", certs.clone(), &[]);
    certs.tls = vec![("2001:db8::41", "junk")];
    add("certs-none", certs, &[]);
    // a captive portal: its page instead of the test pages, nothing reachable over HTTPS
    let mut portal = base.clone();
    portal.connectivity = "portal".into();
    portal.tls = Vec::new();
    portal.http = vec![
        (SUCCESS.into(), "HTTP/1.1 302 Found\r\nLocation: http://portal.example/login?from=x y\u{e9}\r\nContent-Length: 0\r\n\r\n".into()),
        ("portal.example/login?from=x%20y%E9".into(), "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n<form>sign in</".into()),
        (GEN204.into(), "HTTP/1.1 302 Moved\r\nLocation: https://secure.portal.example/\r\n\r\n".into()),
        ("secure.portal.example/".into(), "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nok\r\n".into()),
    ];
    add("portal", portal.clone(), &["--json"]);
    // the same pages with the network saying it is fully online: changed pages are bad then
    portal.connectivity = "full".into();
    add("portal-full", portal, &[]);
    // web pages: redirects that end well, chunked and close-delimited bodies, loops, too many, a lost Location
    let mut redirects = base.clone();
    redirects.http = vec![
        (SUCCESS.into(), "HTTP/1.1 301 Moved\r\nLocation: /a/../b/./c\r\nContent-Length: 2\r\n\r\nxx".into()),
        ("detectportal.firefox.com/b/c".into(), "HTTP/1.1 307 Temporary\r\nLocation: d?q=1#frag\r\n\r\n".into()),
        (
            "detectportal.firefox.com/b/d?q=1".into(),
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nsuc\r\n5;ext=1\r\ncess\n\r\n0\r\nX-Trailer: y\r\n\r\n".into(),
        ),
        (GEN204.into(), "HTTP/1.0 204 No Content\r\nX-Note: a body follows that must be ignored\r\n\r\nignored".into()),
    ];
    add("redirects-good", redirects.clone(), &[]);
    redirects.http = vec![
        (SUCCESS.into(), "HTTP/1.1 302 Found\r\nLocation: http://detectportal.firefox.com/success.txt\r\n\r\n".into()),
        (GEN204.into(), "HTTP/1.1 302 Found\r\nBad Header: x\r\nLocation: /elsewhere\r\n\r\n".into()),
    ];
    add("redirects-loop", redirects.clone(), &[]);
    redirects.http = (0..12)
        .map(|i| {
            (
                format!("detectportal.firefox.com/{}", if i == 0 { "success.txt".to_string() } else { format!("r{i}") }),
                format!("HTTP/1.1 302 Found\r\nLocation: /r{}\r\n\r\n", i + 1),
            )
        })
        .chain([(GEN204.to_string(), "HTTP/1.1 303 See Other\r\nLocation: ftp://files.example/x\r\n\r\n".to_string())])
        .collect();
    add("redirects-too-many", redirects.clone(), &[]);
    redirects.http = vec![
        (SUCCESS.into(), "HTTP/1.0 200 OK\r\n\r\nsuccess\n".into()),
        (GEN204.into(), "HTTP/1.1 302 Found\r\nLocation: https://www.google.com/x\r\nLocation: http://second.example/\r\n\r\n".into()),
        ("www.google.com/x".into(), OK_204.into()),
    ];
    add("redirects-https", redirects.clone(), &[]);
    redirects.http = vec![
        (SUCCESS.into(), "HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\nsuccess\n".into()),
        (GEN204.into(), "HTTP/1.1 404 Not Found\r\n\r\n".into()),
    ];
    add("short-and-404", redirects, &[]);
    // not the internet yet, the guard's lockdown on, NetworkManager without connectivity checking
    let mut limited = base.clone();
    limited.connectivity = "limited".into();
    add("limited", limited, &["--json"]);
    let mut unknown = base.clone();
    unknown.connectivity = String::new();
    unknown.ufw = "inactive".into();
    add("unknown", unknown, &[]);
    let mut locked = base.clone();
    locked.files.push(("/run/heimdall-wifi-guard/state.json", br#"{"locked": true, "wifi": "cafe-uuid"}"#.to_vec()));
    add("locked", locked, &["--uuid", "cafe-uuid"]);
    // no IP database yet; names that do not resolve
    let mut nodb = base.clone();
    nodb.origins = String::new();
    add("no-ip-database", nodb, &[]);
    let mut noname = base.clone();
    noname.hosts = "127.0.0.1 localhost\n".into();
    noname.tls = Vec::new();
    noname.http = Vec::new();
    add("nothing-resolves", noname, &["--json"]);
    // radios: WEP; a name ending in a backslash (the fix of 2026-11-11); not on Wi-Fi
    let mut wep = base.clone();
    wep.scan = "yes:Old\\\\:00\\:00\\:5E\\:00\\:53\\:41:WEP\nno:Old\\\\:00\\:00\\:5E\\:00\\:53\\:42:WPA2\n".into();
    add("wep-backslash", wep, &[]);
    let mut off = base.clone();
    off.scan = "no:Cafe:00\\:00\\:5E\\:00\\:53\\:21:WPA2\n".into();
    add("not-on-wifi", off, &["--json"]);
    let out = check_scenarios(list);
    // what the scenarios are about, beyond Python and Rust agreeing
    let stdout = |n: &str| find(&out, n).py.0.stdout.clone();
    assert!(
        stdout("safe-json").contains("\"verdict\": \"safe\"") && stdout("safe-json").contains("\"trusted\": true"),
        "{}",
        stdout("safe-json")
    );
    assert!(stdout("trusted-profile-other-router").contains("\"trusted\": false"), "{}", stdout("trusted-profile-other-router"));
    let e = stdout("evil-json");
    for want in [
        "\"verdict\": \"unsafe\"",
        "ARP spoofing",
        "invents answers",
        "github.com -> 192.0.2.50 (a local address)",
        "AS64496",
        "www.google.com (self-signed certificate)",
        "github.com (self-signed certificate in certificate chain)",
        "www.wikipedia.org (Hostname mismatch, certificate is not valid for 'www.wikipedia.org'.)",
        "changed on the way",
        "other device(s) heard",
        "the firewall is off: these services",
    ] {
        assert!(e.contains(want), "evil: {want} missing in\n{e}");
    }
    let c = stdout("certs-bad");
    assert!(c.contains("www.google.com (unable to get local issuer certificate), github.com (certificate has expired)"), "{c}");
    let c = stdout("certs-blocked");
    assert!(
        c.contains("genuine certificates") && c.contains("ok    could not reach www.google.com, github.com, www.cloudflare.com"),
        "{c}"
    );
    assert!(stdout("certs-none").contains("warn  could not reach www.google.com, github.com, www.wikipedia.org, www.cloudflare.com"));
    assert!(stdout("portal").contains("replaced by a sign-in page"), "{}", stdout("portal"));
    assert!(stdout("redirects-good").contains("plain web pages arrive unchanged"), "{}", stdout("redirects-good"));
    assert!(stdout("wep-backslash").contains("Old\\: unsafe"), "{}", stdout("wep-backslash"));
    assert_eq!(stdout("not-on-wifi"), "not on Wi-Fi\n");
    report("check_as_python", before);
}

#[test]
fn check_odd_input_as_python() {
    let before = RUNS.with(Cell::get);
    let mut bare = air();
    bare.bare = true;
    bare.tls = Vec::new();
    let mac = "00:00:5E:00:53:01";
    let key = heimdall::cli::wifitools::sha16("Cafe|00:00:5E:00:53:21");
    let uuid = "0e3f5a1c-2222-4333-8444-955566667777";
    let mut list: Vec<(String, Air, Vec<String>)> = Vec::new();
    let mut add = |n: &str, f: &dyn Fn(&mut Air), args: &[&str]| {
        let mut a = bare.clone();
        f(&mut a);
        list.push((n.to_string(), a, check_args(args)));
    };
    // NetworkManager's scan list
    add("scan-not-utf8", &|a| a.scan = "yes:caf\u{fffd}:x:WPA2\n".into(), &[]);
    add(
        "scan-odd",
        &|a| {
            a.scan = "yes:A\\\\:B\nno:x:y\nyes:Twin\r:00\\:00:WPA2\nyes:Caf\u{e9}\u{2003}:00\\:00\\:5e\\:00\\:53\\:51:\u{2003}wpa2\u{1c}\nyes:Second:x:WEP\nno:Caf\u{e9}\u{2003}:x:\u{2003}WEP\n".into()
        },
        &["--json"],
    );
    add("connectivity-odd", &|a| a.connectivity = " portal\r".into(), &[]);
    // ip's answers
    add("routes-broken", &|a| a.routes = "[{".into(), &["--json"]);
    add("routes-dict", &|a| a.routes = r#"{"gateway":"192.0.2.1"}"#.into(), &[]);
    add("routes-gateway-number", &|a| a.routes = r#"[{"gateway": 7, "dev": "wlan0"}, {"gateway": "192.0.2.1"}]"#.into(), &["--json"]);
    add("routes-dev-null", &|a| a.routes = r#"[{"gateway":"192.0.2.1","dev":null}]"#.into(), &[]);
    add("routes-no-dev", &|a| a.routes = r#"[{"gateway":"192.0.2.1"}]"#.into(), &["--json"]);
    add(
        "neigh-lladdr-null",
        &|a| a.neigh = r#"[{"dst":"192.0.2.1","lladdr":"00:00:5e:00:53:01"},{"dst":"192.0.2.9","lladdr":null}]"#.into(),
        &[],
    );
    add("neigh-no-dst", &|a| a.neigh = r#"[{"dst":"192.0.2.1","lladdr":"00:00:5e:00:53:01"},{"lladdr":"00:00:5E:00:53:01"}]"#.into(), &[]);
    add(
        "neigh-dst-list",
        &|a| a.neigh = r#"[{"dst":"192.0.2.1","lladdr":"00:00:5e:00:53:01"},{"dst":["x"],"lladdr":"00:00:5e:00:53:01"}]"#.into(),
        &[],
    );
    add(
        "neigh-dst-number",
        &|a| a.neigh = r#"[{"dst":"192.0.2.1","lladdr":"00:00:5e:00:53:01"},{"dst":5,"lladdr":"00:00:5e:00:53:01"}]"#.into(),
        &[],
    );
    add("neigh-number", &|a| a.neigh = "7".into(), &[]);
    add(
        "neigh-later-entries",
        &|a| {
            a.neigh =
                r#"[{"dst":"192.0.2.1"},{"dst":"192.0.2.1","lladdr":"00:00:5e:00:53:02"},{"dst":"192.0.2.1","lladdr":"00:00:5e:00:53:03"}]"#
                    .into()
        },
        &["--json"],
    );
    add("neigh-lladdr-number", &|a| a.neigh = r#"[{"dst":"192.0.2.1","lladdr":17}]"#.into(), &[]);
    // the routers seen before
    for (n, seen) in [
        ("list", "[]".to_string()),
        ("broken", "{".to_string()),
        ("seen-string", format!(r#"{{"{key}": "{mac} and others"}}"#)),
        ("seen-empty-string", format!(r#"{{"{key}": ""}}"#)),
        ("seen-dict", format!(r#"{{"{key}": {{"00:00:5E:00:53:09": 1}}}}"#)),
        ("seen-number", format!(r#"{{"{key}": 3}}"#)),
        ("seen-many", format!(r#"{{"{key}": ["a", "b", "c", "d", "e"], "x": {{"y": [true, null, -0, 1E400]}}}}"#)),
        ("seen-same", format!(r#"{{"{key}": ["{mac}"]}}"#)),
    ] {
        let data = seen.clone().into_bytes();
        add(&format!("routers-{n}"), &move |a| a.files.push(("/var/lib/heimdall/wifi/routers.json", data.clone())), &["--json"]);
    }
    // the trusted networks and the guard's state
    for (n, trusted) in [
        ("string-entry", format!(r#"{{"{uuid}": "yes"}}"#)),
        ("routers-substring", format!(r#"{{"{uuid}": {{"routers": "{mac} x"}}}}"#)),
        ("false-entry", format!(r#"{{"{uuid}": false}}"#)),
        ("list", "[1]".to_string()),
        ("other-router", format!(r#"{{"{uuid}": {{"routers": ["00:00:5E:00:53:09"]}}}}"#)),
    ] {
        let data = trusted.clone().into_bytes();
        add(
            &format!("trusted-{n}"),
            &move |a| a.files.push(("/etc/heimdall/wifi-trusted.json", data.clone())),
            &["--uuid", uuid, "--json"],
        );
    }
    add("guard-locked-text", &|a| a.files.push(("/run/heimdall-wifi-guard/state.json", br#"{"locked": "no"}"#.to_vec())), &[]);
    add("guard-locked-zero", &|a| a.files.push(("/run/heimdall-wifi-guard/state.json", br#"{"locked": 0}"#.to_vec())), &[]);
    // the services listening, the firewall
    add(
        "ss-odd",
        &|a| {
            a.ss = "tcp LISTEN 0 1 *:22 *:*\nudp UNCONN 0 0 *:68 *:*\nudp UNCONN 0 0 [::]:546 [::]:*\ntcp LISTEN 0 1 0.0.0.0:631\ntcp LISTEN 0 1 eth0:25 x\ntcp LISTEN 0 1 :80 x\ntcp LISTEN 0 1 [::ffff:192.0.2.10]:443 x\n".into();
            a.ufw = "failed".into();
        },
        &[],
    );
    // the IP database's answers: AS numbers as Python's re finds them
    add(
        "origins-odd",
        &|a| {
            a.origins = "233.252.0.1  XAS15169 not a word boundary\n233.252.0.2  (AS36459)\n233.252.0.3  AS14907x and AS14907\n233.252.0.4  AS\u{661}\u{663}\u{663}\u{665}\nnoise\n".into()
        },
        &["--json"],
    );
    // arguments and places
    add("uuid-without-value", &|_| {}, &["--json", "--uuid"]);
    add(
        "uuid-odd",
        &|a| a.files.push(("/etc/heimdall/wifi-trusted.json", br#"{"0e3f-a": {}}"#.to_vec())),
        &["--uuid", "0E3F-xyz-A", "--uuid", "ignored"],
    );
    add("public-no-folder", &|a| a.env.push(("HEIMDALL_WIFI_PUBLIC".into(), "last.json".into())), &[]);
    add(
        "public-folder-is-a-file",
        &|a| {
            a.env.push(("HEIMDALL_WIFI_PUBLIC".into(), "/srv/scan/last.json".into()));
        },
        &[],
    );
    add("state-elsewhere", &|a| a.env.push(("HEIMDALL_WIFI_DIR".into(), "/srv/state/wifi".into())), &["--json"]);
    add("state-is-a-file", &|a| a.env.push(("HEIMDALL_WIFI_DIR".into(), "/srv/scan".into())), &[]);
    // this computer's own addresses (asked only when listening works): odd answers, one that stops Python
    let mut listening = air();
    listening.tls = Vec::new();
    listening.devices = true;
    let mut a = listening.clone();
    a.addr = "\u{fffd}not utf-8".into();
    list.push(("addr-odd-text".into(), a, check_args(&[])));
    let mut a = listening.clone();
    a.addr = r#"[{"addr_info":[{"local":"192.0.2.77"},{"family":"inet"},{"local":5}]},{"ifname":"lo"}]"#.into();
    list.push(("addr-mine".into(), a, check_args(&["--json"])));
    let mut a = listening.clone();
    a.addr = r#"[{"addr_info":"ab"}]"#.into();
    list.push(("addr-info-string".into(), a, check_args(&[])));
    let mut a = listening.clone();
    a.addr = r#"[{"addr_info":[{"local":["192.0.2.77"]}]}]"#.into();
    list.push(("addr-unhashable".into(), a, check_args(&[])));
    let out = check_scenarios(list);
    let py = |n: &str| find(&out, n).py.0.clone();
    assert!(py("scan-not-utf8").stderr.contains("UnicodeDecodeError"), "{:?}", py("scan-not-utf8"));
    assert!(py("trusted-other-router").stdout.contains("\"trusted\": false"));
    assert!(py("addr-mine").stdout.contains("no other device heard"), "{:?}", py("addr-mine"));
    assert!(py("addr-info-string").stderr.contains("AttributeError"), "{:?}", py("addr-info-string"));
    report("check_odd_input_as_python", before);
}
