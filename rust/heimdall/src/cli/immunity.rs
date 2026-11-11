//! `heimdalld immunity ...` and `heimdalld scan-files` (Go: cmd/heimdalld/immunity.go, rules.go, main.go's cmdScanFiles;
//! internal/immunity, internal/scan): the same arguments, output, files, calls to ClamAV and the desktop, and exit codes.

mod elf;
mod gomatch;
pub mod scan;
pub mod store;

use crate::cli::goflag::FlagSet;
use crate::gostruct::Val;
use store::{s, Store};

/// Go's `notifyOwner`: a critical desktop notification to every signed-in user (not in tests: HEIMDALL_IMMUNITY_DIR).
fn notify_owner(text: &str) {
    if std::env::var("HEIMDALL_IMMUNITY_DIR").map(|v| v.is_empty()).unwrap_or(true) {
        notify(text);
    }
}

/// Go's `contain.Real.Notify`: through each signed-in user's session bus, as that user.
pub fn notify(summary: &str) {
    let Ok(out) =
        std::process::Command::new("loginctl").args(["list-sessions", "--no-legend"]).stderr(std::process::Stdio::null()).output()
    else {
        return;
    };
    if !out.status.success() {
        return;
    }
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let mut seen = std::collections::BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout).split('\n') {
        let f: Vec<&str> = crate::gotext::fields(line).collect();
        if f.len() < 3 || !seen.insert(f[1].to_string()) {
            continue;
        }
        let uid = f[1];
        let bus = format!("/run/user/{uid}/bus");
        if std::fs::metadata(&bus).is_err() {
            continue;
        }
        let gid = passwd
            .lines()
            .find_map(|l| {
                let p: Vec<&str> = l.split(':').collect();
                (p.len() >= 4 && p[2] == uid).then(|| p[3].to_string())
            })
            .unwrap_or_else(|| uid.to_string());
        let _ = std::process::Command::new("setpriv")
            .args([
                &format!("--reuid={uid}"),
                &format!("--regid={gid}"),
                "--init-groups",
                "--",
                "notify-send",
                "-u",
                "critical",
                "-a",
                "Heimdall",
                "--",
                "Heimdall",
                summary,
            ])
            .env_clear()
            .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={bus}"))
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Go's `sarinaHere`.
fn sarina_here() -> bool {
    let cfg = crate::config::Config::load_go("/etc/heimdall/config.json").unwrap_or_default();
    cfg.sarina_installed.is_empty() || std::fs::metadata(&cfg.sarina_installed).is_ok()
}

/// Go's `reloadClamd`.
fn reload_clamd() {
    let _ = std::process::Command::new("systemctl")
        .args(["try-reload-or-restart", "clamav-daemon.service"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

const USAGE: &str = "heimdalld immunity: malware Heimdall has learned that ClamAV (the reference) does not know (see docs/IMMUNITY.md)
  heimdalld immunity hold --reason WHY FILE     quarantine it: ClamAV is asked at once; you are told and decide (root)
  heimdalld immunity take-limbo SHA256          keep a copy of a file Limbo held at a guest's exchange (root; never run)
  heimdalld immunity release SHA256             it is good: put it back exactly as it was (root; Settings asks for the password)
  heimdalld immunity release-if-proven SHA256   put it back only if Heimdall can prove it was there before (root)
  heimdalld immunity add --reason WHY FILE      it is malware: hold it and learn it when ClamAV does not know it (root)
  heimdalld immunity suspect --reason WHY FILE  only keep it, for later (root); containments do this with their evidence
  heimdalld immunity confirm SHA256             a held file or suspect is malware: learn it (root)
  heimdalld immunity analyze SHA256             take a kept sample apart in Limbo's sealed machine now (root; holds queue it)
  heimdalld immunity inventory                  look at the programs outside the packages again (root; daily by itself)
  heimdalld immunity list [--json]              held, immune (learned), reference (ClamAV's), released, suspect (root)
  heimdalld immunity forget SHA256              a mistake: remove the sample and its fingerprint (root)
  heimdalld immunity check FILE                 is this file one Heimdall has learned? (any user; exit 1 when it is)
";

fn fail(e: &str) -> Option<i32> {
    eprintln!("heimdalld immunity: {e}");
    Some(1)
}

fn print_confirmed(e: &Val) -> Option<i32> {
    match s(e, "status").as_str() {
        store::REFERENCE => println!("ClamAV already knows it ({}): nothing new to learn; the sample is kept", s(e, "clamav")),
        store::IMMUNE => {
            reload_clamd();
            println!("learned: every scan now reports a copy of it as {}", store::sig_name(e));
        }
        _ => {}
    }
    Some(0)
}

fn notify_held(e: &Val) {
    let mut what = format!("Heimdall moved {} to quarantine", s(e, "original"));
    if s(e, "status") == store::REFERENCE {
        what += &format!(": ClamAV knows it as {} (malware).", s(e, "clamav"));
    } else {
        what += &format!(" ({}). ClamAV does not know it; you decide (Settings > Security).", s(e, "reason"));
        if sarina_here() {
            what += " Sarina can look at it with you.";
        }
    }
    notify_owner(&what);
}

/// `heimdalld immunity ...`
pub fn main(args: &[String]) -> Option<i32> {
    let Some(sub) = args.first() else {
        eprint!("{USAGE}");
        return Some(2);
    };
    let st = Store::default_store();
    let test = std::env::var("HEIMDALL_IMMUNITY_DIR").is_ok_and(|v| !v.is_empty());
    let need_root = || {
        if !rustix::process::geteuid().is_root() && !test {
            eprintln!("heimdalld immunity: this needs root (sudo): the samples are kept where only root can read them");
            return false;
        }
        true
    };
    let one = |usage: &str| -> Option<String> {
        if args.len() != 2 {
            eprintln!("usage: heimdalld immunity {usage}");
            return None;
        }
        Some(args[1].clone())
    };
    match sub.as_str() {
        "rule" => rule(&args[1..], &st),
        "add" | "suspect" => {
            let mut fs = FlagSet::new(&format!("immunity {sub}"));
            fs.string("reason", "", "why it is malware (kept with it)");
            fs.bool("force", false, "also a file that belongs to an installed package");
            if fs.parse(&args[1..]).is_err() || fs.narg() != 1 || crate::gotext::trim_space(&fs.get_str("reason")).is_empty() {
                eprintln!("usage: heimdalld immunity {sub} --reason WHY FILE");
                return Some(2);
            }
            if !need_root() {
                return Some(2);
            }
            let path = fs.args()[0].clone();
            let reason = fs.get_str("reason");
            if !fs.get_bool("force") {
                if let Some(pkg) = store::owned_by_package(&path) {
                    return fail(&format!(
                        "{path} belongs to the package {pkg}: a fingerprint of it would flag every copy of that package (--force if it really is malware)"
                    ));
                }
            }
            let r = if sub == "suspect" { st.keep_as(&path, &path, &reason, "owner") } else { st.hold(&path, &path, &reason, "owner") };
            let e = match r {
                Ok(e) => e,
                Err(e) => return fail(&e),
            };
            if s(&e, "status") != store::HELD || sub == "suspect" {
                println!("{} {} ({}, {})", s(&e, "status"), s(&e, "sha256"), s(&e, "kind"), s(&e, "original"));
                return Some(0);
            }
            match st.confirm(&s(&e, "sha256")) {
                Ok(e) => print_confirmed(&e),
                Err(e) => fail(&e),
            }
        }
        "hold" => {
            let mut fs = FlagSet::new("immunity hold");
            fs.string("reason", "", "why it is suspicious");
            if fs.parse(&args[1..]).is_err() || fs.narg() != 1 || crate::gotext::trim_space(&fs.get_str("reason")).is_empty() {
                eprintln!("usage: heimdalld immunity hold --reason WHY FILE");
                return Some(2);
            }
            if !need_root() {
                return Some(2);
            }
            let p = fs.args()[0].clone();
            let e = match st.hold(&p, &p, &fs.get_str("reason"), "owner") {
                Ok(e) => e,
                Err(e) => return fail(&e),
            };
            println!("{} {} {}", s(&e, "status"), s(&e, "sha256"), s(&e, "original"));
            notify_held(&e);
            if s(&e, "status") == store::HELD {
                let _ = store::queue_analysis(crate::immunity::REQUEST_DIR, &s(&e, "sha256"));
            }
            Some(0)
        }
        "take-limbo" => {
            let sha = one("take-limbo SHA256")?;
            if !need_root() {
                return Some(2);
            }
            let mut dir = store::LIMBO_HELD_DIR.to_string();
            if test {
                if let Ok(d) = std::env::var("HEIMDALL_LIMBO_HELD_DIR") {
                    if !d.is_empty() {
                        dir = d;
                    }
                }
            }
            match st.take_from_limbo(&dir, &sha) {
                Ok(e) => {
                    let c = s(&e, "clamav");
                    let extra = if c.is_empty() { String::new() } else { format!(" (ClamAV: {c})") };
                    println!("{} {} {}{extra}", s(&e, "status"), s(&e, "sha256"), s(&e, "original"));
                    Some(0)
                }
                Err(e) => fail(&e),
            }
        }
        "release" => {
            let Some(sha) = one("release SHA256") else { return Some(2) };
            if !need_root() {
                return Some(2);
            }
            match st.release(&sha, "owner") {
                Ok(e) => {
                    println!("released: {}", s(&e, "original"));
                    Some(0)
                }
                Err(e) => fail(&e),
            }
        }
        "release-if-proven" => {
            let Some(sha) = one("release-if-proven SHA256") else { return Some(2) };
            if !need_root() {
                return Some(2);
            }
            match st.release_if_proven(&sha, &store::Proof::load()) {
                Ok(e) => {
                    println!("released ({}): {}", s(&e, "released_by"), s(&e, "original"));
                    Some(0)
                }
                Err(e) => fail(&e),
            }
        }
        "analyze" => {
            let Some(sha) = one("analyze SHA256") else { return Some(2) };
            if !need_root() {
                return Some(2);
            }
            match st.analyze(&sha, &store::Limbo::default_limbo()) {
                Ok(a) => {
                    let (status, run_id, error, output) = store::analysis_fields(&a);
                    println!("analysis: {status} (Limbo run {run_id})");
                    if !error.is_empty() {
                        println!("{error}");
                    }
                    print!("{output}");
                    Some(0)
                }
                Err(e) => fail(&e),
            }
        }
        "inventory" => {
            if !need_root() {
                return Some(2);
            }
            match st.take_inventory(store::INVENTORY_ROOTS) {
                Ok(n) => {
                    println!("inventory: {n} programs");
                    Some(0)
                }
                Err(e) => fail(&e),
            }
        }
        "run-requests" => {
            if !need_root() {
                return Some(2);
            }
            run_requests(&st)
        }
        "confirm" => {
            let Some(sha) = one("confirm SHA256 (or its first 8+ characters)") else { return Some(2) };
            if !need_root() {
                return Some(2);
            }
            match st.confirm(&sha) {
                Ok(e) => print_confirmed(&e),
                Err(e) => fail(&e),
            }
        }
        "forget" => {
            let Some(sha) = one("forget SHA256") else { return Some(2) };
            if !need_root() {
                return Some(2);
            }
            if let Err(e) = st.forget(&sha) {
                return fail(&e);
            }
            reload_clamd();
            println!("forgotten: the sample and its fingerprint are gone");
            Some(0)
        }
        "list" => {
            if !need_root() {
                return Some(2);
            }
            let es = match st.load() {
                Ok(es) => es,
                Err(e) => return fail(&e),
            };
            if args.get(1).map(String::as_str) == Some("--json") {
                println!("{}", crate::gostruct::to_json(&crate::immunity::ENTRIES, &Val::Slice(es)).unwrap_or_default());
                return Some(0);
            }
            let es = es.unwrap_or_default();
            if es.is_empty() {
                println!("nothing learned yet");
            }
            let mut out = String::new();
            for e in &es {
                let c = s(e, "clamav");
                let extra = if c.is_empty() { String::new() } else { format!(" (ClamAV: {c})") };
                let sha = s(e, "sha256");
                out += &format!(
                    "{} {}  {} {:>8} B  {}  {}: {}{extra}\n",
                    pad(&s(e, "status"), 9),
                    &sha[..sha.len().min(16)],
                    pad(&s(e, "kind"), 8),
                    store::i(e, "size"),
                    store::t(e, "added").local().format("2006-01-02"),
                    s(e, "original"),
                    s(e, "reason")
                );
            }
            print!("{out}");
            Some(0)
        }
        "check" => {
            let Some(path) = one("check FILE") else { return Some(2) };
            let mut f = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => return fail(&crate::goerr::path("open", &path, &e)),
            };
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            let mut n = 0u64;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match std::io::Read::read(&mut f, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => {
                        h.update(&buf[..k]);
                        n += k as u64;
                    }
                }
            }
            let hex: String = h.finalize().iter().map(|x| format!("{x:02x}")).collect();
            let want = format!("{hex}:{n}:");
            let b = std::fs::read(&st.signatures).unwrap_or_default();
            for l in crate::gotext::lossy(&b).split('\n') {
                if let Some(rest) = l.strip_prefix(&want) {
                    println!("known: {rest}");
                    return Some(1);
                }
            }
            println!("not in Heimdall's immunity");
            Some(0)
        }
        "export" => {
            if !need_root() {
                return Some(2);
            }
            if let Err(e) = st.export() {
                return fail(&e);
            }
            reload_clamd();
            Some(0)
        }
        _ => {
            eprint!("{USAGE}");
            Some(2)
        }
    }
}

/// Go's `%-Ns`.
fn pad(s: &str, n: usize) -> String {
    let c = s.chars().count();
    if c >= n {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(n - c))
    }
}

static REQUEST: crate::gostruct::Ty = crate::gostruct::Ty::Struct(
    "main.request",
    &[
        crate::gostruct::Field("release_if_proven", &crate::gostruct::Ty::Str, false),
        crate::gostruct::Field("why", &crate::gostruct::Ty::Str, false),
        crate::gostruct::Field("analyze", &crate::gostruct::Ty::Str, false),
        crate::gostruct::Field("take_limbo", &crate::gostruct::Ty::Str, false),
    ],
);

/// Go's `analyzeHeld`.
fn analyze_held(st: &Store, sha: &str) {
    let Ok(es) = st.load() else { return };
    let es = es.unwrap_or_default();
    let Some(e) = es.iter().rev().find(|e| s(e, "sha256") == sha) else { return };
    let done = match store::get(&crate::immunity::ENTRY, e, "analysis") {
        Val::Ptr(Some(a)) => store::analysis_fields(a).0 == "done",
        _ => false,
    };
    if s(e, "status") != store::HELD || done {
        return;
    }
    let original = s(e, "original");
    let a = match st.analyze(sha, &store::Limbo::default_limbo()) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("heimdalld immunity: analysis of {sha} not recorded: {err}");
            return;
        }
    };
    let status = store::analysis_fields(&a).0;
    println!("analysed {original} in Limbo: {status}");
    if status == "done" {
        let mut note =
            format!("Limbo took {original} apart in a sealed machine; the analysis is with the held file (Settings > Security).");
        if sarina_here() {
            note += " Sarina's next review uses it.";
        }
        notify_owner(&note);
    }
}

/// Go's `runRequests` (heimdall-requests.service, root).
fn run_requests(st: &Store) -> Option<i32> {
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = crate::immunity::REQUEST_DIR;
    let Ok(rd) = std::fs::read_dir(dir) else { return Some(0) };
    let mut names: Vec<Vec<u8>> = rd.flatten().map(|e| e.file_name().into_vec()).collect();
    names.sort();
    let contained = crate::contain::read_marker(crate::contain::MARKER_PATH).is_some();
    let proof = store::Proof::load();
    let (mut done, mut analyzed, mut taken) = (0, 0, 0);
    for n in names {
        let mut p = dir.as_bytes().to_vec();
        p.push(b'/');
        p.extend_from_slice(&n);
        let p = std::ffi::OsString::from_vec(p);
        let mut b = Vec::new();
        if let Ok(f) = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&p) {
            if f.metadata().is_ok_and(|m| m.is_file()) {
                let _ = std::io::Read::read_to_end(&mut std::io::Read::take(&f, 4096), &mut b);
            }
        }
        if std::fs::remove_file(&p).is_err() && std::fs::remove_dir(&p).is_err() {
            let _ = std::fs::remove_dir_all(&p);
        }
        let (r, err) = crate::gostruct::unmarshal(&REQUEST, &b);
        if err.is_some() {
            continue;
        }
        let f = |k: &str| crate::gostruct::str_field(&REQUEST, &r, k).to_string();
        let (release, why, analyze, take) = (f("release_if_proven"), f("why"), f("analyze"), f("take_limbo"));
        if !take.is_empty() {
            if taken < 4 {
                taken += 1;
                match st.take_from_limbo(store::LIMBO_HELD_DIR, &take) {
                    Err(e) => eprintln!("heimdalld immunity: not taken from Limbo: {take} {e}"),
                    Ok(e) => println!("taken from Limbo: {} {}", s(&e, "status"), s(&e, "sha256")),
                }
            }
            continue;
        }
        if !analyze.is_empty() {
            if analyzed < 2 {
                analyzed += 1;
                analyze_held(st, &analyze);
            }
            continue;
        }
        if done >= 20 || release.is_empty() {
            continue;
        }
        done += 1;
        if contained {
            eprintln!("heimdalld immunity: no release while Sarina is contained: {release}");
            continue;
        }
        let e = match st.release_if_proven(&release, &proof) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("heimdalld immunity: not released: {release} {e}");
                continue;
            }
        };
        let why = crate::gotext::fields(&why).collect::<Vec<_>>().join(" ");
        let why = if why.len() > 200 { crate::gotext::lossy(&why.as_bytes()[..200]) } else { why };
        println!("released ({}): {}", s(&e, "released_by"), s(&e, "original"));
        notify_owner(&format!("Heimdall released {} from quarantine: {}. Asked because: {why}", s(&e, "original"), s(&e, "released_by")));
    }
    Some(0)
}

/// `heimdalld immunity rule ...` (Go: cmd/heimdalld/rules.go).
fn rule(args: &[String], st: &Store) -> Option<i32> {
    rules::main(args, st)
}

mod rules;

/// `heimdalld scan-files [--state FILE] [--exclude PATTERN]... [--max-mb N] PATH...`
pub fn scan_files(args: &[String]) -> Option<i32> {
    let mut fs = FlagSet::new("scan-files");
    fs.string("state", "", "remember scanned files here (skips unchanged ones next time)");
    fs.int("max-mb", 200, "skip files larger than this many MB (0 = no limit)");
    fs.list("exclude", "a folder, file or glob that is never scanned (repeatable)");
    if fs.parse(args).is_err() {
        return Some(2);
    }
    if fs.narg() == 0 {
        eprintln!("heimdalld scan-files: give at least one file or folder");
        return Some(2);
    }
    let c = scan::ClamAv::new();
    if !c.available() {
        eprintln!("heimdalld scan-files: ClamAV is not installed (pacman -S clamav); nothing was scanned");
        return Some(2);
    }
    let start = std::time::Instant::now();
    let mut state = scan::State::load(&fs.get_str("state"));
    state.use_signatures(&format!("{}{}", scan::file_stamp(store::DEFAULT_SIGNATURES), scan::rules_stamp("/var/lib/clamav")));
    let ex = scan::Excluder { patterns: fs.get_list("exclude") };
    let files = scan::collect(fs.args(), &ex, fs.get_int("max-mb").wrapping_shl(20), &state);
    let (mut found, mut failed) = (0, 0);
    let mut out = std::io::stdout().lock();
    use std::io::Write;
    for r in scan::run(&c, &files, &mut state) {
        if r.infected {
            found += 1;
            let mut line = b"INFECTED ".to_vec();
            line.extend_from_slice(&r.path);
            line.extend_from_slice(format!(": {}\n", r.signature).as_bytes());
            let _ = out.write_all(&line);
        } else if !r.error.is_empty() {
            failed += 1;
            let _ = out.flush();
            let mut line = b"could not scan ".to_vec();
            line.extend_from_slice(&r.path);
            line.extend_from_slice(format!(": {}\n", r.error).as_bytes());
            let _ = std::io::stderr().write_all(&line);
        }
    }
    let _ = state.save();
    // Go: time.Since(start).Round(time.Millisecond).String()
    let ms = (start.elapsed().as_nanos() as i64 + 500_000) / 1_000_000 * 1_000_000;
    let _ =
        writeln!(out, "scanned {} files in {}: {found} infected, {failed} could not be scanned", files.len(), crate::gotext::duration(ms));
    Some(if found > 0 {
        1
    } else if failed > 0 {
        2
    } else {
        0
    })
}
