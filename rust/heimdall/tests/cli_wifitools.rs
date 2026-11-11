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
    r.write("/etc/heimdall/wifi-trusted.json", format!(r#"{{"home-uuid": {{"ssid": "Home", "routers": ["{}"]}}}}"#, ROUTER.to_uppercase()));
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
        on_wifi(r, "home-uuid", ROUTER);
    });
    t.step(&["pre-up", "wlan0", "home-uuid"], &o);
    t.step(&["up", "wlan0", "home-uuid"], &o);
    assert!(!argv_log(&t).contains("nft [-f]") && !argv_log(&t).contains("[connection] [up]"), "{}", argv_log(&t));
    t.both(|r| on_wifi(r, "home-uuid", STRANGER));
    t.step(&["up", "wlan0", "home-uuid"], &o);
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
            r#"{"home-uuid": {"ssid": "Home", "routers": ["00:00:5E:00:53:01", "00:00:5E:00:53:02"]}, "u2": {"ssid": null, "routers": "AB"}, "u3": {"ssid": ["x"]}}"#,
        );
        on_wifi(r, "home-uuid", ROUTER);
        r.write("/srv/table", "");
    });
    t.step(&["status"], &o);
    t.step(&["status"], &user);
    t.both(|r| on_wifi(r, "cafe-uuid", ROUTER));
    t.step(&["status"], &o);
    // trust: the network on now, then again (no second copy), then a second router
    let mut t = guard_twin("trust", &|r| {
        on_wifi(r, "home-uuid", ROUTER);
        r.write("/srv/ssid", "Home Sweet: Home\n");
        r.write("/srv/avahi-on", "");
    });
    t.step(&["trust"], &o);
    t.step(&["trust"], &o);
    t.both(|r| on_wifi(r, "home-uuid", "00:00:5e:00:53:02"));
    t.step(&["trust"], &o);
    t.step(&["status"], &o);
    t.step(&["untrust", "nothing-by-that-name"], &o);
    t.step(&["untrust", "Home Sweet: Home"], &o);
    t.step(&["status"], &o);
    // trust when not on Wi-Fi, and when the router does not answer (five tries, a ping each)
    let mut t = guard_twin("trust-refused", &|_| {});
    t.step(&["trust"], &o);
    t.both(|r| {
        on_wifi(r, "home-uuid", ROUTER);
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
    t.step(&["untrust", "home-uuid"], &o);
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
            on_wifi(r, "home-uuid", ROUTER);
            r.write("/srv/routes", route);
            r.write("/srv/neigh", neigh);
            if n == "not-utf8" {
                r.write("/srv/neigh", b"[{\"lladdr\":\"\xff\"}]");
            }
        });
        t.step(&["up", "wlan0", "home-uuid"], &o);
        t.step(&["trust"], &o);
    }
    // damaged or odd files: the trusted list, the configuration, the state
    let files: &[(&str, &str, &str)] = &[
        ("trusted-list", "/etc/heimdall/wifi-trusted.json", "[1, 2]"),
        ("trusted-broken", "/etc/heimdall/wifi-trusted.json", "{\"home-uuid\": "),
        ("trusted-null", "/etc/heimdall/wifi-trusted.json", "null"),
        ("trusted-entry-string", "/etc/heimdall/wifi-trusted.json", r#"{"home-uuid": "yes"}"#),
        ("trusted-entry-list", "/etc/heimdall/wifi-trusted.json", r#"{"home-uuid": [1]}"#),
        (
            "trusted-routers-string",
            "/etc/heimdall/wifi-trusted.json",
            r#"{"home-uuid": {"ssid": "H", "routers": "00:00:5E:00:53:01 and more"}}"#,
        ),
        ("trusted-routers-dict", "/etc/heimdall/wifi-trusted.json", r#"{"home-uuid": {"routers": {"00:00:5E:00:53:01": 1}}}"#),
        ("trusted-routers-number", "/etc/heimdall/wifi-trusted.json", r#"{"home-uuid": {"routers": 3}}"#),
        ("trusted-no-routers", "/etc/heimdall/wifi-trusted.json", r#"{"home-uuid": {"ssid": "H"}}"#),
        (
            "trusted-false",
            "/etc/heimdall/wifi-trusted.json",
            r#"{"home-uuid": false, "x": NaN, "y": 1e999, "z": -0.0, "w": 12345678901234567890123}"#,
        ),
        (
            "trusted-dup",
            "/etc/heimdall/wifi-trusted.json",
            r#"{"home-uuid": {"routers": []}, "a": 1, "home-uuid": {"ssid": "again", "routers": ["00:00:5E:00:53:01"]}}"#,
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
            on_wifi(r, "home-uuid", ROUTER);
            r.write(path, data);
        });
        for step in [&["pre-up", "wlan0", "home-uuid"][..], &["up", "wlan0", "home-uuid"], &["status"], &["down", "wg-heimdall", "v"]] {
            t.step(step, &o);
        }
        t.step(&["down", "wlan0", "home-uuid"], &o);
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
