//! The programs the package shipped as shell scripts and their Rust ports side by side: `heimdall-intel-update`,
//! `heimdall-dns-blocklist`, `heimdall-enable-defaults` and the dispatcher `91-heimdall-netid`. Each scenario builds the same
//! made-up system twice (a fake root, `tests/common`), runs the script in one (with the real curl, gzip and coreutils, and
//! the Rust heimdalld as its `heimdalld`) and the port in the other under the program's own name, and compares standard
//! output and error, the exit code, every file under the folders the program writes (modes included), every request the
//! servers got, and every call of a fake tool.
//!
//! The internet is made up: HTTPS servers (`rust/parity/harness/fetch-net.py`) on loopback addresses in a network namespace
//! of the scenario's own, the real names pointed at them by the fake root's /etc/hosts, their certificates from a test
//! authority the fake root trusts (and some it does not). Nothing reaches the real network or the real servers.

mod common;
use common::intel_data::*;
use common::*;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

/// The number of cases, for docs/RUST_CLI.md (`cargo test --test cli_shtools -- --nocapture`).
fn report(test: &str, n: usize) {
    eprintln!("{test}: {n} runs of both programs compared");
}

fn script(name: &str) -> PathBuf {
    let p = match name {
        "heimdall-intel-update" => "packaging/arch/heimdall-intel-update",
        "heimdall-dns-blocklist" => "packaging/net/heimdall-dns-blocklist",
        "heimdall-enable-defaults" => "packaging/net/heimdall-enable-defaults",
        "91-heimdall-netid" => "packaging/net/dispatcher.d/91-heimdall-netid",
        _ => unreachable!(),
    };
    repo().join(p)
}

/// The real curl, for the script's runs; None skips the network scenarios (with a note).
fn curl() -> Option<PathBuf> {
    let out = std::process::Command::new("sh").args(["-c", "command -v curl"]).output().ok()?;
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!p.is_empty()).then(|| PathBuf::from(p))
}

/// Whether the curl here is the one the port words its messages after (Arch's, 2026-11); with another curl only the error
/// numbers of its lines are compared.
fn curl_words_match() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::process::Command::new("curl")
            .arg("--version")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).starts_with("curl 8.23.0 "))
    })
}

/// The test authority and its certificates (openssl, once per run): `good` for every name below, `wrong` for another name,
/// `expired`, `self` (self-signed), `evil` (from an authority nobody trusts).
fn certs() -> PathBuf {
    static D: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    D.get_or_init(|| {
        let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("shtools-certs-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let names: Vec<String> = HOSTS.iter().map(|(_, n)| format!("DNS:{n}")).collect();
        let script = format!(
            r#"set -e
ec='-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes'
names='{}'
ca() {{ openssl req -x509 $ec -keyout $1.key -out $1.crt -subj "/CN=$2" -days 3 -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null; }}
leaf() {{
  openssl req $ec -keyout $1.key -out $1.csr -subj "/CN=$1" 2>/dev/null
  printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' "$3" > $1.ext
  openssl x509 -req -in $1.csr -CA $2.crt -CAkey $2.key -CAcreateserial -out $1.crt -extfile $1.ext $4 2>/dev/null
}}
ca ca 'Heimdall Test CA'
ca evilca 'Totally Trusted Root'
leaf good ca "$names" '-days 3'
leaf wrong ca 'DNS:other.test' '-days 3'
leaf expired ca "$names" '-not_before 20200101000000Z -not_after 20200102000000Z'
leaf evil evilca "$names" '-days 3'
openssl req -x509 $ec -keyout self.key -out self.crt -subj '/CN=self' -days 3 -addext "subjectAltName=$names" 2>/dev/null
"#,
            names.join(",")
        );
        let ok = std::process::Command::new("sh").args(["-c", &script]).current_dir(&d).status().unwrap().success();
        assert!(ok, "openssl made the test certificates");
        d
    })
    .clone()
}

/// The servers' names and the loopback address each gets.
const HOSTS: &[(&str, &str)] = &[
    ("127.0.0.11", "www.spamhaus.org"),
    ("127.0.0.12", "iplists.firehol.org"),
    ("127.0.0.13", "rules.emergingthreats.net"),
    ("127.0.0.14", "security.archlinux.org"),
    ("127.0.0.15", "www.cisa.gov"),
    ("127.0.0.16", "osv-vulnerabilities.storage.googleapis.com"),
    ("127.0.0.17", "ipinfo.io"),
    ("127.0.0.18", "download.db-ip.com"),
    ("127.0.0.19", "cdn.example.com"),
    ("127.0.0.21", "raw.githubusercontent.com"),
    ("127.0.0.22", "malware-filter.gitlab.io"),
];

// ---- responses

fn ok(body: &[u8]) -> Vec<u8> {
    [format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes(), body].concat()
}

fn chunked(body: &[u8]) -> Vec<u8> {
    let mut out = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for c in body.chunks(7000) {
        out.extend_from_slice(format!("{:x};ext=1\r\n", c.len()).as_bytes());
        out.extend_from_slice(c);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\nX-Trailer: 1\r\n\r\n");
    out
}

/// A body without a length, ended by the server closing.
fn until_close(body: &[u8]) -> Vec<u8> {
    [&b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n"[..], body].concat()
}

fn status(code: u16) -> Vec<u8> {
    format!("HTTP/1.1 {code} Whatever\r\nContent-Length: 5\r\nConnection: close\r\n\r\nnope\n").into_bytes()
}

fn redirect(code: u16, to: &str) -> Vec<u8> {
    format!("HTTP/1.1 {code} Moved\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

fn gz(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

/// This month and the one before, as the script's `date` lines give them.
fn months() -> [String; 2] {
    let run =
        |s: &str| String::from_utf8(std::process::Command::new("sh").args(["-c", s]).output().unwrap().stdout).unwrap().trim().to_string();
    [run("date -u +%Y-%m"), run("date -u -d \"$(date -u +%Y-%m-01) -1 day\" +%Y-%m")]
}

/// A made-up internet: what each URL answers (raw response, how the connection ends), which certificate each address
/// shows, and what /etc/hosts says.
#[derive(Clone)]
struct Net {
    answers: Vec<(String, Vec<u8>, &'static str)>,
    certs: Vec<(&'static str, &'static str)>,
    hosts: String,
}

impl Net {
    fn new() -> Net {
        let mut hosts = String::from("127.0.0.1 localhost\n::1 localhost\n192.0.2.1 archlinux.org wikipedia.org\n");
        for (a, n) in HOSTS {
            hosts.push_str(&format!("{a} {n}\n"));
        }
        Net { answers: Vec::new(), certs: HOSTS.iter().map(|(a, _)| (*a, "good")).collect(), hosts }
    }
    fn at(mut self, url: &str, raw: Vec<u8>) -> Net {
        self.answers.retain(|(k, _, _)| k != url.trim_start_matches("https://"));
        self.answers.push((url.trim_start_matches("https://").to_string(), raw, "notify"));
        self
    }
    fn abrupt(mut self, url: &str, raw: Vec<u8>) -> Net {
        self.answers.retain(|(k, _, _)| k != url.trim_start_matches("https://"));
        self.answers.push((url.trim_start_matches("https://").to_string(), raw, "abrupt"));
        self
    }
    fn cert(mut self, host: &str, cert: &'static str) -> Net {
        let addr = HOSTS.iter().find(|(_, n)| *n == host).unwrap().0;
        for c in &mut self.certs {
            if c.0 == addr {
                c.1 = cert;
            }
        }
        self
    }
    fn unresolvable(mut self, host: &str) -> Net {
        self.hosts = self.hosts.lines().filter(|l| !l.ends_with(&format!(" {host}"))).map(|l| format!("{l}\n")).collect();
        self
    }
    fn refused(mut self, host: &str) -> Net {
        self.hosts = self.hosts.replace(&format!(" {host}\n"), &format!(" {host}-gone\n"));
        self.hosts.push_str(&format!("127.0.0.99 {host}\n"));
        self
    }

    /// Lays the internet's files into a root.
    fn lay(&self, r: &Root) {
        let mut cfg = serde_json::Map::new();
        for (i, (k, raw, close)) in self.answers.iter().enumerate() {
            let p = format!("/srv/resp/{i}");
            r.write(&p, raw);
            cfg.insert(k.clone(), serde_json::json!({"file": r.host(&p).display().to_string(), "close": close}));
        }
        r.write("/srv/net.json", serde_json::Value::Object(cfg).to_string());
        r.write("/srv/net.log", "");
        r.write("/etc/hosts", &self.hosts);
        r.write("/etc/ssl/certs/ca-certificates.crt", std::fs::read(certs().join("ca.crt")).unwrap());
    }

    /// The setup lines that start the servers and wait for them.
    fn start(&self) -> String {
        let h = repo().join("rust/parity/harness/fetch-net.py");
        let specs: Vec<String> = self.certs.iter().map(|(a, c)| format!("{a}={c}")).collect();
        let mut s = String::new();
        for (a, _) in &self.certs {
            s.push_str(&format!("ip addr add {a}/32 dev lo 2>/dev/null || true\n"));
        }
        s.push_str(&format!(
            "python3 -I '{}' \"$R/srv/net.json\" \"$R/srv/net.log\" '{}' {} </dev/null >/dev/null 2>&1 &\n",
            h.display(),
            certs().display(),
            specs.join(" ")
        ));
        let addrs: Vec<&str> = self.certs.iter().map(|(a, _)| *a).collect();
        s.push_str(&format!(
            "for a in {}; do for i in $(seq 200); do python3 -I -c 'import socket,sys; socket.create_connection((sys.argv[1], 443), 0.2).close()' \"$a\" 2>/dev/null && break; sleep 0.05; done; done\n",
            addrs.join(" ")
        ));
        s
    }
}

// ---- running both

/// One run of both programs on two copies of the same system.
struct Case {
    name: String,
    prog: &'static str,
    args: Vec<String>,
    net: Option<Net>,
    build: std::sync::Arc<dyn Fn(&Root) + Send + Sync>,
    opts: Opts,
    dirs: Vec<&'static str>,
}

fn case(name: &str, prog: &'static str, args: &[&str], build: impl Fn(&Root) + Send + Sync + 'static) -> Case {
    Case {
        name: name.into(),
        prog,
        args: args.iter().map(|s| s.to_string()).collect(),
        net: None,
        build: std::sync::Arc::new(build),
        opts: Opts { pid: true, timeout: Duration::from_secs(120), ..Opts::default() },
        dirs: Vec::new(),
    }
}

impl Case {
    fn net(mut self, n: Net) -> Case {
        self.net = Some(n);
        self
    }
    fn env(mut self, k: &str, v: &str) -> Case {
        self.opts = self.opts.env(k, v);
        self
    }
    fn user(mut self) -> Case {
        self.opts.root = false;
        self
    }
    fn setup(mut self, s: &str) -> Case {
        self.opts.setup.push_str(s);
        self.opts.setup.push('\n');
        self
    }
    fn dirs(mut self, d: &[&'static str]) -> Case {
        self.dirs = d.to_vec();
        self
    }
}

/// What two runs are compared on: the times and the random parts of temporary names made placeholders, curl's words where
/// they depend on the TLS library (or on a curl other than the one the port follows) reduced to its error number.
fn norm(s: &str) -> String {
    let s = normalize(s);
    let mut out = String::new();
    for line in s.split_inclusive('\n') {
        let mut l = line.to_string();
        // .update.XXXXXX
        while let Some(i) = l.find(".update.") {
            let tail = &l[i + 8..];
            let n = tail.chars().take_while(|c| c.is_ascii_alphanumeric()).count();
            if n != 6 {
                break;
            }
            l = format!("{}.update#TMP{}", &l[..i], &tail[6..]);
        }
        l = l.replace(".update#TMP", ".update.<TMP>");
        // netid's time: "t":SECONDS
        while let Some(i) = l.find("\"t\":") {
            let rest = &l[i + 4..];
            let n = rest.chars().take_while(|c| c.is_ascii_digit()).count();
            if n == 0 {
                break;
            }
            l = format!("{}\"t\"=<T>{}", &l[..i], &rest[n..]);
        }
        l = l.replace("\"t\"=<T>", "\"t\":<T>");
        for (pre, post) in
            [(" after ", " ms"), (" after ", " milliseconds"), ("passed ", " returned"), ("returned ", "\n"), ("write of ", " bytes")]
        {
            if let Some(i) = l.find(pre) {
                let rest = &l[i + pre.len()..];
                let n = rest.chars().take_while(|c| c.is_ascii_digit()).count();
                if n > 0 && rest[n..].starts_with(post) {
                    l = format!("{}{pre}<N>{}", &l[..i], &rest[n..]);
                }
            }
        }
        if let Some(rest) = l.strip_prefix("curl: (") {
            let code: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            let tls = (code == "35" || code == "56") && (l.contains("SSL") || l.contains("TLS"));
            if tls || !curl_words_match() {
                l = format!("curl: ({code}) <words>\n");
            }
        }
        out.push_str(&l);
    }
    if !curl_words_match() {
        // curl's text after a refused certificate differs between versions
        out = out
            .lines()
            .filter(|l| {
                !(l.starts_with("More details here:")
                    || l.starts_with("curl failed to verify")
                    || l.starts_with("establish a secure")
                    || l.starts_with("how to fix it")
                    || l.is_empty())
            })
            .map(|l| format!("{l}\n"))
            .collect();
    }
    out
}

/// Runs a case: the script in one root, the port in the other; everything compared. Returns both outputs (script, port).
fn run(c: &Case) -> (Out, Out) {
    let tag: String = c.name.chars().map(|x| if x.is_ascii_alphanumeric() || x == '-' { x } else { '_' }).collect();
    let rs = Root::new(&format!("{tag}-sh"));
    let rr = Root::new(&format!("{tag}-rs"));
    for r in [&rs, &rr] {
        r.write_mode("/.fake-calls", "", 0o666);
        // the shell's /dev/stdin (sed reads it in the script's allow)
        for (i, d) in ["stdin", "stdout", "stderr"].iter().enumerate() {
            r.symlink(&format!("/proc/self/fd/{i}"), &format!("/dev/{d}"));
        }
        (c.build)(r);
        if let Some(n) = &c.net {
            n.lay(r);
        }
    }
    let mut o_sh = c.opts.clone();
    let mut o_rs = c.opts.clone();
    if let Some(n) = &c.net {
        for o in [&mut o_sh, &mut o_rs] {
            o.net = true;
            o.setup = format!("{}{}", n.start(), o.setup);
        }
        // the script's curl is the real one; the port's root keeps the fake (it records a call and fails)
        o_sh.setup = format!("mount --bind '{}' \"$R/usr/bin/curl\"\n{}", curl().unwrap().display(), o_sh.setup);
    }
    // the script's heimdalld (ipdb-check, intel-check) is the Rust heimdalld
    o_sh.setup = format!("mount --bind '{}' \"$R/usr/bin/heimdalld\"\n{}", rust_bin().display(), o_sh.setup);
    let inside = if c.prog == "91-heimdall-netid" { "/usr/bin/91-heimdall-netid".to_string() } else { format!("/usr/bin/{}", c.prog) };
    let args: Vec<&str> = c.args.iter().map(String::as_str).collect();
    let (a, b) = std::thread::scope(|sc| {
        let x = sc.spawn(|| rs.run_as(&inside, &script(c.prog), &args, &o_sh));
        let y = sc.spawn(|| rr.run_as(&inside, &rust_bin(), &args, &o_rs));
        (x.join().unwrap(), y.join().unwrap())
    });
    let what = &c.name;
    // SHTOOLS_SHOW=1 (with --nocapture): what each run did, to read a scenario
    if std::env::var_os("SHTOOLS_SHOW").is_some() {
        eprintln!("== {what}\nscript: {a:?}\nport: {b:?}\ncalls: {}\nrequests: {}", rs.calls(), rs.read_str("/srv/net.log"));
        for (k, v) in rs.tree(&c.dirs) {
            eprintln!("  {k}: {}", v.chars().take(160).collect::<String>().replace('\n', "\\n"));
        }
    }
    assert_eq!(norm(&a.stdout), norm(&b.stdout), "{what}: standard output\nscript stderr: {}\nport stderr: {}", a.stderr, b.stderr);
    let (ea, eb) = (norm(&a.stderr), norm(&b.stderr));
    let full = |s: &str| s.contains("No space left on device");
    if full(&ea) || full(&eb) {
        // a full disk: the tools' own words for it come from different steps; that both met it is what counts
        let keep = |s: &str| s.lines().filter(|l| !full(l)).map(|l| format!("{l}\n")).collect::<String>();
        assert!(full(&ea) && full(&eb), "{what}: both meet the full disk\nscript: {ea}\nport: {eb}");
        assert_eq!(keep(&ea), keep(&eb), "{what}: standard error (the full disk's lines aside)");
    } else {
        assert_eq!(ea, eb, "{what}: standard error");
    }
    assert_eq!(a.code, b.code, "{what}: exit codes\nscript: {a:?}\nport: {b:?}");
    assert_eq!(rs.calls(), rr.calls(), "{what}: the tools called");
    assert!(!rr.calls().contains("curl"), "{what}: the port never runs curl");
    assert_eq!(rs.read_str("/srv/net.log"), rr.read_str("/srv/net.log"), "{what}: the requests the servers got");
    let tree = |r: &Root| -> Vec<(String, String)> { r.tree(&c.dirs).into_iter().map(|(k, v)| (norm(&k), norm(&v))).collect() };
    let (ta, tb) = (tree(&rs), tree(&rr));
    if ta != tb {
        for (x, y) in ta.iter().zip(tb.iter()) {
            assert_eq!(x, y, "{what}: files (first difference)");
        }
        assert_eq!(ta, tb, "{what}: files");
    }
    // owners' groups (netid's chgrp), where the files are the same
    for d in &c.dirs {
        for (k, _) in rs.tree(&[d]) {
            let g =
                |r: &Root| std::fs::symlink_metadata(r.host(k.trim_end_matches('/'))).map(|m| std::os::unix::fs::MetadataExt::gid(&m)).ok();
            if !k.contains(".update.") {
                assert_eq!(g(&rs), g(&rr), "{what}: the group of {k}");
            }
        }
    }
    (a, b)
}

/// Runs cases a few at a time, every one even after a failure; then fails naming each case that did.
fn run_all(cases: Vec<Case>) -> Vec<(String, Out, Out)> {
    let mut out = Vec::new();
    let mut failed = Vec::new();
    for group in cases.chunks(6) {
        std::thread::scope(|sc| {
            let hs: Vec<_> = group.iter().map(|c| (c.name.clone(), sc.spawn(move || run(c)))).collect();
            for (n, h) in hs {
                match h.join() {
                    Ok((a, b)) => out.push((n, a, b)),
                    Err(_) => failed.push(n),
                }
            }
        });
    }
    assert!(failed.is_empty(), "cases that differ: {failed:?}");
    out
}

fn network_ok(test: &str) -> bool {
    if curl().is_none() {
        eprintln!("{test}: skipped, no curl to run the script with");
        return false;
    }
    true
}

// ---- heimdall-intel-update

const INTEL: &str = "heimdall-intel-update";

/// Every source answering well, the IP databases from DB-IP (this month).
fn intel_net() -> Net {
    let [m, _] = months();
    let z = zip(&records(2200).iter().map(|(n, b, d)| (n.as_str(), b.clone(), *d)).collect::<Vec<_>>(), false);
    Net::new()
        .at("https://www.spamhaus.org/drop/drop_v4.json", ok(list(40, 100).as_bytes()))
        .at("https://www.spamhaus.org/drop/drop_v6.json", chunked(list(30, 2000).as_bytes()))
        .at("https://iplists.firehol.org/files/firehol_level1.netset", ok(list(60, 5000).as_bytes()))
        .at("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", until_close(list(25, 9000).as_bytes()))
        .at("https://security.archlinux.org/issues/all.json", ok(tracker(150).as_bytes()))
        .at("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", ok(kev(150).as_bytes()))
        .at("https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip", ok(&z))
        .at(&format!("https://download.db-ip.com/free/dbip-country-lite-{m}.mmdb.gz"), ok(&gz(&mmdb("country", "DBIP-Country-Lite"))))
        .at(&format!("https://download.db-ip.com/free/dbip-asn-lite-{m}.mmdb.gz"), chunked(&gz(&mmdb("asn", "DBIP-ASN-Lite"))))
}

fn intel_case(name: &str, net: Net, build: impl Fn(&Root) + Send + Sync + 'static) -> Case {
    case(name, INTEL, &[], build).net(net).dirs(&["/var/lib/heimdall", "/etc/heimdall"])
}

fn none(_: &Root) {}

/// Sets a file's time to `days` days ago.
fn age(r: &Root, p: &str, days: u64) {
    let f = std::fs::File::options().write(true).open(r.host(p)).unwrap();
    f.set_modified(std::time::SystemTime::now() - Duration::from_secs(days * 86400 + 60)).unwrap();
}

#[test]
fn intel_update_as_the_script() {
    if !network_ok("intel_update_as_the_script") {
        return;
    }
    let [m, prev] = months();
    let good = intel_net();
    let lists_from = |r: &Root| {
        // last good copies to compare with, and old databases (a month old: fetched again)
        r.write("/var/lib/heimdall/intel/spamhaus-drop.list", list(40, 100));
        r.write("/var/lib/heimdall/intel/firehol-level1.list", list(200, 5000));
        r.write("/var/lib/heimdall/ipdb/dbip-country-lite.mmdb", b"old");
        age(r, "/var/lib/heimdall/ipdb/dbip-country-lite.mmdb", 40);
    };
    let fresh = |r: &Root| {
        r.write("/var/lib/heimdall/intel/linux-kernel.json", "{}");
        age(r, "/var/lib/heimdall/intel/linux-kernel.json", 2);
        r.write("/var/lib/heimdall/ipdb/dbip-country-lite.mmdb", b"old");
        age(r, "/var/lib/heimdall/ipdb/dbip-country-lite.mmdb", 3);
    };
    let token = |r: &Root| {
        r.write_mode("/etc/heimdall/ipinfo-token", "  abcDEF123-_\n", 0o640);
    };
    let mut cases = vec![
        intel_case("intel-all-good", good.clone(), none),
        intel_case("intel-last-copies", good.clone(), lists_from),
        intel_case("intel-fresh", good.clone(), fresh),
        intel_case("intel-fresh-forced", good.clone(), fresh).env("HEIMDALL_IPDB_FORCE", "1").env("HEIMDALL_KERNEL_FORCE", "1"),
        intel_case("intel-fresh-nothing", Net::new(), fresh),
        intel_case("intel-kernel-six-days", good.clone(), |r: &Root| {
            r.write("/var/lib/heimdall/intel/linux-kernel.json", "{}");
            age(r, "/var/lib/heimdall/intel/linux-kernel.json", 6);
        }),
        // the IPinfo token: in a header, only to ipinfo.io (not to where it redirects), the database checked
        intel_case("intel-ipinfo", good.clone().at("https://ipinfo.io/data/ipinfo_lite.mmdb", ok(&mmdb("country", "ipinfo_lite"))), token),
        intel_case(
            "intel-ipinfo-redirected",
            good.clone()
                .at("https://ipinfo.io/data/ipinfo_lite.mmdb", redirect(302, "https://cdn.example.com/signed/lite.mmdb?sig=x"))
                .at("https://cdn.example.com/signed/lite.mmdb?sig=x", ok(&mmdb("asn", "ipinfo_lite"))),
            token,
        ),
        intel_case("intel-ipinfo-refused", good.clone().at("https://ipinfo.io/data/ipinfo_lite.mmdb", status(403)), token),
        intel_case("intel-ipinfo-junk", good.clone().at("https://ipinfo.io/data/ipinfo_lite.mmdb", ok(b"<html>no</html>")), token),
        intel_case("intel-token-empty", good.clone(), |r: &Root| {
            r.write("/etc/heimdall/ipinfo-token", "-- \n");
        }),
        intel_case("intel-token-folder", good.clone(), |r: &Root| {
            r.mkdir("/etc/heimdall/ipinfo-token", 0o755);
        }),
        intel_case(
            "intel-token-elsewhere",
            good.clone().at("https://ipinfo.io/data/ipinfo_lite.mmdb", ok(&mmdb("country", "ipinfo_lite"))),
            |r: &Root| {
                r.write("/srv/token", "xyz");
            },
        )
        .env("HEIMDALL_IPINFO_TOKEN_FILE", "/srv/token"),
        // DB-IP: this month's file not there yet, last month's is; broken downloads
        intel_case(
            "intel-dbip-last-month",
            good.clone().at(&format!("https://download.db-ip.com/free/dbip-country-lite-{m}.mmdb.gz"), status(404)).at(
                &format!("https://download.db-ip.com/free/dbip-country-lite-{prev}.mmdb.gz"),
                ok(&gz(&mmdb("country", "DBIP-Country-Lite"))),
            ),
            none,
        ),
        intel_case(
            "intel-dbip-none",
            good.clone().at(&format!("https://download.db-ip.com/free/dbip-country-lite-{m}.mmdb.gz"), status(404)),
            none,
        ),
        intel_case(
            "intel-dbip-bad-gzip",
            good.clone()
                .at(&format!("https://download.db-ip.com/free/dbip-country-lite-{m}.mmdb.gz"), ok(b"<html>not gzip</html>"))
                .at(
                    &format!("https://download.db-ip.com/free/dbip-country-lite-{prev}.mmdb.gz"),
                    ok(&{
                        let g = gz(&mmdb("country", "DBIP-Country-Lite"));
                        g[..g.len() / 2].to_vec()
                    }),
                )
                .at(
                    &format!("https://download.db-ip.com/free/dbip-asn-lite-{m}.mmdb.gz"),
                    ok(&{
                        let mut g = gz(&mmdb("asn", "DBIP-ASN-Lite"));
                        let n = g.len();
                        g[n - 6] ^= 0x55;
                        g
                    }),
                )
                .at(
                    &format!("https://download.db-ip.com/free/dbip-asn-lite-{prev}.mmdb.gz"),
                    ok(&[gz(&mmdb("asn", "DBIP-ASN-Lite")), b"trailing".to_vec()].concat()),
                ),
            none,
        ),
        intel_case(
            "intel-dbip-two-members",
            good.clone().at(
                &format!("https://download.db-ip.com/free/dbip-country-lite-{m}.mmdb.gz"),
                ok(&{
                    let c = mmdb("country", "DBIP-Country-Lite");
                    [gz(&c[..50]), gz(&c[50..]), vec![0; 64]].concat()
                }),
            ),
            none,
        ),
        intel_case(
            "intel-dbip-not-a-database",
            good.clone().at(&format!("https://download.db-ip.com/free/dbip-asn-lite-{m}.mmdb.gz"), ok(&gz(b"<html>maintenance</html>"))),
            none,
        ),
        // the lists and the tracker: refused by the checks, cut short, servers that fail in every way
        intel_case(
            "intel-lists-bad",
            good.clone()
                .at("https://www.spamhaus.org/drop/drop_v4.json", ok(list(4, 100).as_bytes()))
                .at("https://www.spamhaus.org/drop/drop_v6.json", ok(b"<html>503</html>"))
                .at("https://security.archlinux.org/issues/all.json", ok(tracker(20).as_bytes()))
                .at("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", ok(b"{\"vulnerabilities\":5}"))
                .at("https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip", ok(b"<html>rate limited</html>")),
            lists_from,
        ),
        intel_case(
            "intel-lists-shrunk",
            good.clone().at("https://iplists.firehol.org/files/firehol_level1.netset", ok(list(30, 5000).as_bytes())),
            lists_from,
        ),
        intel_case(
            "intel-cut-short",
            good.clone()
                .at("https://www.spamhaus.org/drop/drop_v4.json", {
                    let mut r = ok(list(40, 100).as_bytes());
                    r.truncate(r.len() - 300);
                    r
                })
                .at("https://www.spamhaus.org/drop/drop_v6.json", {
                    let mut r = chunked(list(40, 100).as_bytes());
                    r.truncate(r.len() - 40);
                    r
                })
                .abrupt("https://iplists.firehol.org/files/firehol_level1.netset", {
                    let mut r = ok(list(60, 5000).as_bytes());
                    r.truncate(r.len() - 10);
                    r
                })
                .abrupt("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", until_close(list(25, 9000).as_bytes()))
                .at("https://security.archlinux.org/issues/all.json", Vec::new())
                .at("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", b"hello there\r\n\r\n".to_vec()),
            lists_from,
        ),
        intel_case(
            "intel-http-errors",
            good.clone()
                .at("https://www.spamhaus.org/drop/drop_v4.json", status(404))
                .at("https://www.spamhaus.org/drop/drop_v6.json", status(500))
                .at("https://iplists.firehol.org/files/firehol_level1.netset", status(429))
                .at("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", redirect(302, "/blockrules/missing.txt"))
                .at("https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip", status(403)),
            none,
        ),
        intel_case(
            "intel-redirects",
            good.clone()
                .at("https://www.spamhaus.org/drop/drop_v4.json", redirect(301, "/drop/v2/drop_v4.json"))
                .at("https://www.spamhaus.org/drop/v2/drop_v4.json", redirect(307, "../../drop/v3/x.json?a=b#frag"))
                .at("https://www.spamhaus.org/drop/v3/x.json?a=b", ok(list(40, 100).as_bytes()))
                .at("https://www.spamhaus.org/drop/drop_v6.json", redirect(302, "http://www.spamhaus.org/drop/drop_v6.json"))
                .at("https://iplists.firehol.org/files/firehol_level1.netset", redirect(302, "/files/firehol_level1.netset"))
                .at("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", redirect(303, "//cdn.example.com/et.txt"))
                .at("https://cdn.example.com/et.txt", ok(list(25, 9000).as_bytes()))
                .at("https://security.archlinux.org/issues/all.json", redirect(302, ""))
                .at(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    redirect(308, "ftp://www.cisa.gov/kev.json"),
                ),
            none,
        ),
        intel_case(
            "intel-too-big",
            good.clone()
                .at(
                    "https://security.archlinux.org/issues/all.json",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 200000001\r\nConnection: close\r\n\r\nxx".to_vec(),
                )
                .at(
                    "https://www.spamhaus.org/drop/drop_v4.json",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 200000000\r\nConnection: close\r\n\r\nxx".to_vec(),
                ),
            none,
        ),
        intel_case(
            "intel-certificates",
            good.clone()
                .cert("www.spamhaus.org", "wrong")
                .cert("iplists.firehol.org", "expired")
                .cert("rules.emergingthreats.net", "self")
                .cert("security.archlinux.org", "evil")
                .cert("www.cisa.gov", "evil")
                .cert("download.db-ip.com", "expired"),
            none,
        ),
        intel_case(
            "intel-unreachable",
            good.clone()
                .unresolvable("www.spamhaus.org")
                .refused("iplists.firehol.org")
                .unresolvable("security.archlinux.org")
                .refused("osv-vulnerabilities.storage.googleapis.com")
                .unresolvable("download.db-ip.com"),
            none,
        ),
        intel_case(
            "intel-nothing",
            {
                let mut n = Net::new();
                n.hosts = "127.0.0.1 localhost\n".into();
                n
            },
            none,
        ),
        // the folders: elsewhere, not writable, a file where a folder belongs, a folder where a file goes
        intel_case("intel-elsewhere", good.clone(), none)
            .env("HEIMDALL_IPDB_DIR", "/srv/db/ip")
            .env("HEIMDALL_INTEL_DIR", "/srv/db/intel")
            .dirs(&["/srv/db"]),
        intel_case("intel-empty-env", good.clone(), none).env("HEIMDALL_IPDB_DIR", "").env("HEIMDALL_INTEL_DIR", ""),
        intel_case("intel-not-writable", good.clone(), |r: &Root| {
            r.mkdir("/var/lib/heimdall", 0o755);
        })
        .user(),
        intel_case("intel-ipdb-not-writable", good.clone(), |r: &Root| {
            r.mkdir("/var/lib/heimdall/ipdb", 0o755);
        })
        .user()
        .setup("chown 1000:1000 \"$R/var/lib/heimdall\""),
        intel_case("intel-file-in-the-way", good.clone(), |r: &Root| {
            r.write("/var/lib/heimdall/intel", "x");
        }),
        intel_case("intel-folder-in-the-way", good.clone(), |r: &Root| {
            r.mkdir("/var/lib/heimdall/intel/firehol-level1.list", 0o755);
            r.mkdir("/var/lib/heimdall/intel/arch-security.json/arch-security.json", 0o755);
        }),
        // a full disk: the downloads cannot be written
        intel_case("intel-disk-full", good.clone(), none)
            .setup("mkdir -p \"$R/var/lib/heimdall\"\nmount -t tmpfs -o size=96k tmpfs \"$R/var/lib/heimdall\""),
        intel_case("intel-args-ignored", good.clone(), none),
    ];
    cases.last_mut().unwrap().args = vec!["--help".into(), "x".into()];
    let n = cases.len();
    let results = run_all(cases);
    for (name, a, _) in &results {
        let expect_ok = ["intel-all-good", "intel-ipinfo", "intel-dbip-last-month", "intel-redirects"];
        if expect_ok.contains(&name.as_str()) {
            assert_eq!(a.code, 0, "{name}: the script succeeds\n{}", a.stderr);
        }
    }
    report("intel_update_as_the_script", n);
}

// ---- heimdall-dns-blocklist

const DNS: &str = "heimdall-dns-blocklist";
const HAGEZI: &str = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt";
const URLHAUS: &str = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt";

/// A made-up block list: `n` domains in the list's own form, with comments, odd lines and repeats.
fn dns_list(n: usize, seed: u64, hosts_form: bool) -> Vec<u8> {
    let mut s = String::from("# Title: made up\n# Updated: now\n\n");
    let mut x = seed;
    for i in 0..n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let tld = ["com", "net", "org", "io", "xn--p1ai", "co"][(x % 6) as usize];
        let d = format!("d{:x}-{i}.ex{}.{tld}", x % 4096, i % 97);
        let d = if i % 11 == 0 { d.to_uppercase() } else { d };
        if hosts_form {
            s += &match i % 7 {
                0 => format!("127.0.0.1 {d}\n"),
                1 => format!("0.0.0.0\t{d}  # note\n"),
                _ => format!("0.0.0.0 {d}\n"),
            };
        } else {
            s += &format!("{d}\n");
        }
        if i % 997 == 0 {
            s += "dhcp-script=/bin/sh\nconf-file=/etc/shadow\n0.0.0.0 localhost.localdomain\n-bad.example\nbad-.example\n";
        }
        if i % 503 == 0 {
            s += &format!("{d}\n"); // a repeat
        }
    }
    s.into_bytes()
}

fn dns_net() -> Net {
    Net::new().at(HAGEZI, ok(&dns_list(14000, 7, false))).at(URLHAUS, chunked(&dns_list(9000, 99, true)))
}

/// A tmpfs size (KiB) where every step of `update` fits but the block file: the files the lists leave before it (each
/// download, its cleaned list, the cleaned list's copy, the merged list while the allowed names are taken out of it, the
/// allow list; at the peak, while the allowed names are taken out, the merged list twice), and room for about half of the
/// block file's extra bytes over the merged list (its 8 bytes a line) once the merged list is replaced.
fn dns_full_size_k() -> u64 {
    use heimdall::cli::shtools::{coreutils::sort_u, dnsblock::domains};
    let page = |n: usize| (n as u64).div_ceil(4096) * 4096;
    let (r1, r2) = (dns_list(14000, 7, false), dns_list(9000, 99, true));
    let (t1, t2) = (domains(&r1), domains(&r2));
    let all = sort_u(&[t1.clone(), t2.clone()].concat());
    let lines = all.iter().filter(|&&c| c == b'\n').count();
    let before = page(r1.len()) + 2 * page(t1.len()) + page(r2.len()) + 2 * page(t2.len()) + 2 * page(all.len()) + 4096;
    (before + 4 * lines as u64).div_ceil(1024)
}

fn dns_root(r: &Root) {
    // ordinary names resolve (apply's check), from the file: nothing is looked up on a network
    r.write("/etc/hosts", "127.0.0.1 localhost\n192.0.2.1 archlinux.org wikipedia.org\n");
    r.write("/etc/heimdall/dns-allow.txt", "# mine\nd1-0.ex0.com\nEX5.NET\nnot a domain;rm -rf /\n");
    r.mkdir("/var/lib/heimdall-dns", 0o755);
    r.write("/var/lib/heimdall-dns/blocklist.conf", "");
}

fn dns_case(name: &str, args: &[&str], build: impl Fn(&Root) + Send + Sync + 'static) -> Case {
    case(name, DNS, args, build).dirs(&["/var/lib/heimdall-dns", "/etc/heimdall", "/etc/NetworkManager"])
}

/// A good block file from an earlier run, and the lists' last copies.
fn dns_earlier(r: &Root) {
    dns_root(r);
    r.write("/var/lib/heimdall-dns/blocklist.conf", "# old\nlocal=/old.example/\nlocal=/evil.example/\n");
    r.write("/var/lib/heimdall-dns/hagezi-tif-mini.txt", String::from_utf8(dns_list(21000, 3, false)).unwrap().to_lowercase());
    r.write("/var/lib/heimdall-dns/urlhaus-filter.txt", String::from_utf8(dns_list(9000, 42, false)).unwrap().to_lowercase());
    r.write("/var/lib/heimdall-dns/updated", "2026-11-01T03:00Z\n");
}

/// NetworkManager's fake, and the DNS cache switched on; `breaks`: the reload stops names resolving.
fn nm(r: &Root, breaks: bool, code: u8) {
    r.write("/etc/NetworkManager/conf.d/heimdall-dns.conf", "[main]\ndns=dnsmasq\n");
    let body =
        if breaks { "case \"$*\" in 'general reload conf,dns-full') printf '127.0.0.1 localhost\\n' > /etc/hosts ;; esac\n" } else { "" };
    r.tool("nmcli", &format!("{body}echo \"nmcli says: $*\"\nexit {code}\n"));
}

#[test]
fn dns_blocklist_as_the_script() {
    if !network_ok("dns_blocklist_as_the_script") {
        return;
    }
    let net = dns_net();
    let n = |c: Case| c.net(net.clone());
    let mut cases = vec![
        n(dns_case("dns-update", &["update"], dns_root)),
        n(dns_case("dns-update-over-earlier", &["update"], dns_earlier)),
        dns_case("dns-update-one-down", &["update"], dns_earlier).net(net.clone().at(URLHAUS, status(503))),
        dns_case("dns-update-cert", &["update"], dns_earlier).net(net.clone().cert("raw.githubusercontent.com", "expired")),
        dns_case("dns-update-both-down-no-copies", &["update"], dns_root).net(Net::new()),
        dns_case("dns-update-both-down", &["update"], dns_earlier).net(Net::new()),
        dns_case("dns-update-tiny", &["update"], dns_earlier)
            .net(Net::new().at(HAGEZI, ok(b"<html>503</html>\n")).at(URLHAUS, ok(b"a.example\n"))),
        dns_case("dns-update-cut", &["update"], dns_earlier).net(net.clone().abrupt(URLHAUS, until_close(&dns_list(100, 5, true)))),
        dns_case("dns-update-redirected", &["update"], dns_root).net(
            net.clone()
                .at(HAGEZI, redirect(302, "https://cdn.example.com/hagezi.txt"))
                .at("https://cdn.example.com/hagezi.txt", ok(&dns_list(14000, 7, false))),
        ),
        dns_case("dns-update-hostile", &["update"], dns_root).net(net.clone().at(
            URLHAUS,
            ok(&{
                let mut b = dns_list(9000, 99, true);
                b.extend_from_slice(
                    b"0.0.0.0 zero\x00byte.example\n0.0.0.0 bad\xffbyte.example\nok-after.example # \xff\xfe comment\n\x00\n",
                );
                b.extend_from_slice(&dns_list(100, 12345, true));
                b
            }),
        )),
        n(dns_case("dns-update-min", &["update"], dns_root)).env("HEIMDALL_DNS_MIN", "30000"),
        n(dns_case("dns-update-elsewhere", &["update"], none))
            .env("HEIMDALL_DNS_DIR", "/srv/dns/new")
            .env("HEIMDALL_DNS_ALLOW", "/srv/allow.txt")
            .dirs(&["/srv/dns"]),
        n(dns_case("dns-update-allow-folder", &["update"], |r: &Root| {
            dns_root(r);
            r.mkdir("/srv/allow", 0o755);
        }))
        .env("HEIMDALL_DNS_ALLOW", "/srv/allow"),
        n(dns_case("dns-update-skip", &["update"], dns_earlier)).env("HEIMDALL_DNS_SKIP_FETCH", "1"),
        n(dns_case("dns-update-not-writable", &["update"], dns_root)).user(),
        n(dns_case("dns-update-conf-folder", &["update"], |r: &Root| {
            dns_root(r);
            let _ = std::fs::remove_file(r.host("/var/lib/heimdall-dns/blocklist.conf"));
            r.mkdir("/var/lib/heimdall-dns/blocklist.conf", 0o755);
        })),
        // a full disk when the block file is written (the lists and the steps before it fit)
        n(dns_case("dns-update-disk-full", &["update"], dns_root))
            .setup(&format!("mount -t tmpfs -o size={}k tmpfs \"$R/var/lib/heimdall-dns\"", dns_full_size_k())),
        // status and test
        dns_case("dns-status-none", &["status"], none),
        dns_case("dns-status", &["status"], |r: &Root| {
            dns_earlier(r);
            r.write("/var/lib/heimdall-dns/zz.txt", "x\n");
            r.mkdir("/var/lib/heimdall-dns/dir.txt", 0o755);
            r.write("/var/lib/heimdall-dns/.hidden.txt", "x\n");
        }),
        dns_case("dns-status-user", &["status"], dns_earlier).user(),
        dns_case("dns-status-on", &["status"], |r: &Root| {
            dns_earlier(r);
            nm(r, false, 0);
        }),
        dns_case("dns-test-blocked", &["test", "Deep.Sub.Evil.Example"], dns_earlier),
        dns_case("dns-test-exact", &["test", "old.example"], dns_earlier),
        dns_case("dns-test-not", &["test", "example.org"], dns_earlier),
        dns_case("dns-test-empty", &["test"], dns_earlier),
        dns_case("dns-test-newlines", &["test", "x\nevil.example\n\n"], dns_earlier),
        dns_case("dns-test-tricky", &["test", "evil.example/\nlocal=/old.example"], dns_earlier),
        dns_case("dns-test-no-conf", &["test", "evil.example"], none),
        // usage
        dns_case("dns-usage", &[], none),
        dns_case("dns-usage-other", &["frobnicate"], none),
        // apply and allow, with NetworkManager's fake
        dns_case("dns-apply-user", &["apply"], dns_earlier).user(),
        dns_case("dns-allow-user", &["allow", "x.example"], dns_earlier).user(),
        dns_case("dns-apply", &["apply"], |r: &Root| {
            dns_earlier(r);
            nm(r, false, 0);
        }),
        dns_case("dns-apply-nmcli-fails", &["apply"], |r: &Root| {
            dns_earlier(r);
            nm(r, false, 8);
        }),
        dns_case("dns-apply-breaks", &["apply"], |r: &Root| {
            dns_earlier(r);
            nm(r, true, 0);
        }),
        dns_case("dns-apply-offline", &["apply"], |r: &Root| {
            dns_earlier(r);
            nm(r, false, 0);
            r.write("/etc/hosts", "127.0.0.1 localhost\n");
        }),
        dns_case("dns-allow", &["allow", "Old.Example"], |r: &Root| {
            dns_earlier(r);
            nm(r, false, 0);
        }),
        dns_case("dns-allow-hosts-form", &["allow", "0.0.0.0 evil.example\n"], |r: &Root| {
            dns_earlier(r);
            nm(r, false, 0);
        }),
        dns_case("dns-allow-two-lines", &["allow", "good.example\nnot a domain"], |r: &Root| {
            dns_earlier(r);
            nm(r, false, 0);
        }),
        dns_case("dns-allow-bad", &["allow", "not a domain"], dns_earlier),
        dns_case("dns-allow-empty", &["allow"], dns_earlier),
        dns_case("dns-allow-new-file", &["allow", "new.example"], |r: &Root| {
            dns_earlier(r);
            let _ = std::fs::remove_file(r.host("/etc/heimdall/dns-allow.txt"));
            let _ = std::fs::remove_dir(r.host("/etc/heimdall"));
            nm(r, false, 0);
        }),
        dns_case("dns-allow-no-newline", &["allow", "z.example"], |r: &Root| {
            dns_earlier(r);
            r.write("/etc/heimdall/dns-allow.txt", "a.example\nb.example");
            nm(r, false, 0);
        }),
        dns_case("dns-allow-too-few", &["allow", "z.example"], |r: &Root| {
            dns_root(r);
            nm(r, false, 0);
        }),
    ];
    // NetworkManager's fake records its calls; the script and the port must make the same
    for c in &mut cases {
        c.opts.timeout = Duration::from_secs(150);
    }
    let n = cases.len();
    let results = run_all(cases);
    for (name, a, _) in &results {
        if ["dns-update", "dns-update-over-earlier", "dns-update-one-down", "dns-status", "dns-allow"].contains(&name.as_str()) {
            assert_eq!(a.code, 0, "{name}: the script succeeds\n{}", a.stderr);
        }
        if name == "dns-update-disk-full" {
            assert!(a.stderr.contains("could not be written in full"), "{name}: the disk filled at the block file\n{}", a.stderr);
        }
    }
    report("dns_blocklist_as_the_script", n);
}

/// The lists' lines through the script's sed, tr and grep and through the port, from files (no network): made-up lines of
/// every odd kind, compared by the block file each makes.
#[test]
fn dns_lines_as_the_script() {
    let mut x: u64 = std::env::var("HEIMDALL_PROP_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5eed_1234);
    let mut rnd = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let pieces: &[&[u8]] = &[
        b"0.0.0.0",
        b"127.0.0.1",
        b"::",
        b"::1",
        b" ",
        b"\t",
        b"\r",
        b"\x0b",
        b"\x0c",
        b"#",
        b"\x00",
        b"\xff",
        b"\xc3\xa9",
        b"a",
        b"Z",
        b"-",
        b".",
        b"9",
        b"x1",
        b"example",
        b"localhost",
        b"local",
        b".localdomain",
        b"broadcasthost",
        b"com",
        b"co",
        b"xn--p1ai",
        b"_",
        b"0.0.0.0 ",
        b"127.0.0.1\t",
        b":: ",
        b"a-b",
        b"--",
        b"..",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"\xe2\x80\x83",
        b"\xc2\xa0",
    ];
    let mut raw = Vec::new();
    for _ in 0..30000 {
        let k = rnd(9);
        for _ in 0..k {
            raw.extend_from_slice(pieces[rnd(pieces.len() as u64) as usize]);
        }
        raw.push(b'\n');
    }
    // and real-looking lines with odd tails
    for i in 0..3000 {
        let tail: &[u8] = [&b""[..], b" ", b"\t# c", b"\r", b" #\xff", b"\x00"][i % 6];
        raw.extend_from_slice(format!("{}a{i}.Ex{}.com", if i % 3 == 0 { "0.0.0.0 " } else { "" }, i % 13).as_bytes());
        raw.extend_from_slice(tail);
        raw.push(b'\n');
    }
    raw.extend_from_slice(b"no-newline-at.the.end");
    let raw2: Vec<u8> = raw.iter().rev().copied().collect();
    let build = move |r: &Root| {
        dns_root(r);
        r.write("/srv/src/hagezi-tif-mini.raw", &raw);
        r.write("/srv/src/urlhaus-filter.raw", &raw2);
        r.write("/etc/heimdall/dns-allow.txt", [&b"Ex1.com\n0.0.0.0 ex2.com\n\xff\n"[..], &raw[..2000]].concat());
    };
    let c = dns_case("dns-lines", &["update"], build).env("HEIMDALL_DNS_TEST_SOURCES", "/srv/src").env("HEIMDALL_DNS_MIN", "1");
    let (a, _) = run(&c);
    assert_eq!(a.code, 0, "{}", a.stderr);
    report("dns_lines_as_the_script", 1);
}

// ---- heimdall-enable-defaults

#[test]
fn enable_defaults_as_the_script() {
    let ed = |name: &str, args: &[&str], build: fn(&Root)| case(name, "heimdall-enable-defaults", args, build).dirs(&["/etc/heimdall"]);
    let cases = vec![
        ed("ed-plain", &[], |r: &Root| {
            r.tool("systemctl", "exit 0\n");
        }),
        ed("ed-off", &[], |r: &Root| {
            r.write("/etc/heimdall/defaults-off", "");
            r.tool("systemctl", "exit 0\n");
        }),
        ed("ed-off-forced", &["--force"], |r: &Root| {
            r.write("/etc/heimdall/defaults-off", "");
            r.tool("systemctl", "exit 0\n");
        }),
        ed("ed-off-other-arg", &["--forced"], |r: &Root| {
            r.write("/etc/heimdall/defaults-off", "");
        }),
        ed("ed-off-link", &[], |r: &Root| {
            r.symlink("/nowhere", "/etc/heimdall/defaults-off");
            r.tool("systemctl", "exit 0\n");
        }),
        ed("ed-some-fail", &[], |r: &Root| {
            r.tool("systemctl", "echo noise; echo more >&2\ncase \"$*\" in *lan-scan*|*inventory*|'--global'*) exit 1 ;; esac\n");
        }),
        ed("ed-running", &[], |r: &Root| {
            r.mkdir("/run/systemd/system", 0o755);
            r.tool("systemctl", "case \"$*\" in 'start heimdall.service') exit 3 ;; esac\n");
            r.tool("systemd-detect-virt", "echo 'detect: not a chroot' >&2\nexit 1\n");
        }),
        ed("ed-chroot", &[], |r: &Root| {
            r.mkdir("/run/systemd/system", 0o755);
            r.tool("systemctl", "exit 0\n");
            r.tool("systemd-detect-virt", "exit 0\n");
        }),
        ed("ed-no-systemctl", &[], |_: &Root| {}),
    ];
    let n = cases.len();
    run_all(cases);
    report("enable_defaults_as_the_script", n);
}

// ---- 91-heimdall-netid

#[test]
fn netid_as_the_script() {
    let nid = |name: &str, args: &[&str], build: fn(&Root)| {
        case(name, "91-heimdall-netid", args, build).dirs(&["/run", "/srv/run"]).env("CONNECTION_UUID", "0000-ab\"x; rm -rf /")
    };
    let cases = vec![
        nid("netid-up", &["wlan0", "up"], |r: &Root| {
            r.mkdir("/sys/class/net/wlan0/device", 0o755).mkdir("/sys/class/net/wg0", 0o755);
        })
        .env("DHCP4_DHCP_SERVER_IDENTIFIER", "192.0.2.1\"};x")
        .env("DHCP4_ROUTERS", "192.0.2.1")
        .env("DHCP4_DOMAIN_NAME_SERVERS", "192.0.2.53    192.0.2.54\n")
        .env("IP6_NAMESERVERS", "2001:db8::1 fe80::1%wlan0"),
        nid("netid-each-action", &["wlan0", "dhcp6-change"], |r: &Root| {
            r.mkdir("/sys/class/net/wlan0/device", 0o755);
            r.write_mode("/run/heimdall-net/netid.jsonl", "{\"t\":1}\n", 0o600);
        }),
        nid("netid-other-action", &["wlan0", "pre-up"], |r: &Root| {
            r.mkdir("/sys/class/net/wlan0/device", 0o755);
        }),
        nid("netid-vpn", &["wg0", "up"], |r: &Root| {
            r.mkdir("/sys/class/net/wg0", 0o755);
        }),
        nid("netid-odd-name", &["wlan0;../../x-very-long-name", "down"], |r: &Root| {
            r.mkdir("/sys/class/net/wlan0;../../x-very-long-name/device", 0o755);
        })
        .env("DHCP4_ROUTERS", &"1".repeat(400)),
        nid("netid-cut-short", &["wlan0", "dhcp4-change"], |r: &Root| {
            r.mkdir("/sys/class/net/wlan0/device", 0o755);
            let mut b = String::new();
            for i in 0..1000 {
                b += &format!("{{\"t\":{i},\"action\":\"up\",\"iface\":\"wlan0\"}}{}\n", " ".repeat(60));
            }
            r.write_mode("/run/heimdall-net/netid.jsonl", b, 0o640);
        }),
        nid("netid-elsewhere", &["eth0", "up"], |r: &Root| {
            r.mkdir("/srv/sys/eth0/device", 0o755);
        })
        .env("HEIMDALL_NETID_SYS", "/srv/sys")
        .env("HEIMDALL_NETID_DIR", "/srv/run/a/b"),
        nid("netid-no-args", &[], |_: &Root| {}),
    ];
    let n = cases.len();
    let results = run_all(cases);
    for (name, a, _) in results {
        assert_eq!(a.code, 0, "{name}: {}", a.stderr);
    }
    report("netid_as_the_script", n);
}
