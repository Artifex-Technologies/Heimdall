//! `heimdalld trust init|status|mode|sign|forget|restore|verify|watch` (Go: cmd/heimdalld/trust.go, internal/trust): the
//! signed list of the files that decide how the AI agents behave. The files in /etc/heimdall/trust are Go's, byte for byte
//! (the key and the signature in Go's base64, the list as Go's `json.MarshalIndent` writes it), so Sarina's go/trust and the
//! Go heimdalld read what this writes and the other way round.

use super::goflag::FlagSet;
use crate::trust::{self, Store, WatchList};
use std::io::Write;

/// The watch list `trust init` makes for one user: Sarina's rules, tool connections, skill list, skills, agents and skill
/// collections, and the settings of Sarina's service and of Heimdall itself (Go: defaultWatch).
fn default_watch(home: &str) -> WatchList {
    let s = crate::gopath::join(&[home, ".sarina"]);
    let j = |x: &str| crate::gopath::join(&[&s, x]);
    WatchList {
        files: Some(vec![j("policy.json"), j("mcp.json"), j("skills.json"), "/etc/heimdall/config.json".into()]),
        dirs: Some(vec![j("skills"), j("agents"), j("vendor"), "/etc/sarina".into()]),
    }
}

const USAGE: &str = "heimdalld trust: the signed list of files that decide how the AI agents behave (see docs/TRUST.md)
  heimdalld trust init [--user NAME]     make the signing key (root) and the default watch list for that user's Sarina files
  heimdalld trust status                 mode, how many files are signed, what is watched
  heimdalld trust mode off|watch|enforce off: nothing changes; watch: an unsigned change is a critical alert, a signed one quiet;
                                         enforce: Sarina also refuses an unsigned file (root)
  heimdalld trust sign PATH...           approve the current content of files or folders (root)
  heimdalld trust sign --watched         approve everything watched, as it is now (the starting point) (root)
  heimdalld trust forget PATH...         take files off the list, e.g. after deleting them (root)
  heimdalld trust restore [PATH...]      put back the approved content of changed or deleted signed files (root)
  heimdalld trust verify [PATH...]       is each file as approved? (exit 1 when not)
  heimdalld trust watch add|remove PATH... change what is watched (root)
";

fn usage() -> i32 {
    eprint!("{USAGE}");
    2
}

fn out(b: &[u8]) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(b);
    let _ = o.write_all(b"\n");
}

/// A user's home folder from the user database (Go: os/user.Lookup), with Go's errors.
pub fn home_of(name: &str) -> Result<String, String> {
    let c = std::ffi::CString::new(name).map_err(|_| format!("user: unknown user {name}"))?;
    let mut buf = vec![0 as libc::c_char; 16384];
    // SAFETY: getpwnam_r writes only into pwd and buf (whose size is given) and sets result to &pwd or null.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwnam_r(c.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if result.is_null() {
        if rc != 0 && rc != libc::ENOENT && rc != libc::ESRCH {
            return Err(format!("user: lookup username {name}: {}", crate::goerr::errno(rc)));
        }
        return Err(format!("user: unknown user {name}"));
    }
    // SAFETY: on success pw_dir points into buf, a NUL-terminated string.
    Ok(unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }.to_string_lossy().into_owned())
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub fn main(args: &[String]) -> Option<i32> {
    Some(run(args))
}

fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        return usage();
    }
    let test_dir = std::env::var("HEIMDALL_TRUST_DIR").unwrap_or_default();
    let st = Store::new(if test_dir.is_empty() { trust::DEFAULT_DIR } else { &test_dir });
    let need_root = || {
        if euid() != 0 && test_dir.is_empty() {
            eprintln!("heimdalld trust: this needs root (sudo): only root holds the signing key");
            return false;
        }
        true
    };
    let fail = |e: &str| {
        eprintln!("heimdalld trust: {e}");
        1
    };
    match args[0].as_str() {
        "init" => {
            let mut fs = FlagSet::new("trust init");
            fs.string("user", "", "the account whose Sarina files are watched (default: the one that ran sudo)");
            if fs.parse(&args[1..]).is_err() || !need_root() {
                return 2;
            }
            let created = match st.init() {
                Ok(c) => c,
                Err(e) => return fail(&e),
            };
            let mut name = fs.get_str("user");
            if name.is_empty() {
                name = std::env::var("SUDO_USER").unwrap_or_default();
            }
            let w = st.watch();
            if !name.is_empty() && w.files.as_ref().map_or(0, Vec::len) + w.dirs.as_ref().map_or(0, Vec::len) == 0 {
                let home = match home_of(&name) {
                    Ok(h) => h,
                    Err(e) => return fail(&e),
                };
                if let Err(e) = st.set_watch(&default_watch(&home)) {
                    return fail(&e);
                }
            }
            if created {
                println!("made the signing key; trust is off until you choose: heimdalld trust mode watch");
            } else {
                println!("the signing key exists already (kept)");
            }
            0
        }
        "status" => {
            let m = st.load();
            println!("mode: {}", st.mode());
            match m {
                Err(e) => println!("signed list: cannot be checked ({e})"),
                Ok(m) => println!("signed list: {} file(s), signed {}", m.files.len(), m.signed_at.local().format("2006-01-02 15:04")),
            }
            let w = st.watch();
            let (files, dirs) = (w.files.unwrap_or_default(), w.dirs.unwrap_or_default());
            println!("watched: {} file(s), {} folder(s)", files.len(), dirs.len());
            for f in files {
                println!("  file   {f}");
            }
            for d in dirs {
                println!("  folder {d}");
            }
            0
        }
        "mode" => {
            if args.len() != 2 {
                return usage();
            }
            let m = match trust::parse_mode(&args[1]) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("heimdalld trust: {e}");
                    return 2;
                }
            };
            if !need_root() {
                return 2;
            }
            if m != "off" {
                if let Err(e) = st.load() {
                    return fail(&format!("the signed list cannot be checked; run heimdalld trust init first: {e}"));
                }
            }
            if let Err(e) = st.set_mode(m) {
                return fail(&e);
            }
            println!("trust mode: {m}");
            // the daemon reads the mode and the watch list when it starts
            if test_dir.is_empty() {
                let _ = std::process::Command::new("systemctl")
                    .args(["try-restart", "heimdall.service"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            0
        }
        cmd @ ("sign" | "forget" | "restore") => {
            if !need_root() {
                return 2;
            }
            let mut paths: Vec<String> = args[1..].to_vec();
            if cmd != "restore" && paths.is_empty() {
                return usage();
            }
            if cmd == "sign" && paths.len() == 1 && paths[0] == "--watched" {
                // everything watched now, as it is: the starting point when trust is switched on
                let w = st.watch();
                paths =
                    w.files.into_iter().flatten().chain(w.dirs.into_iter().flatten()).filter(|p| std::fs::metadata(p).is_ok()).collect();
            }
            match cmd {
                "sign" => {
                    let (done, err) = st.sign(&paths);
                    for f in done {
                        out(&[b"signed   ".as_slice(), &f].concat());
                    }
                    if let Some(e) = err {
                        return fail(&e);
                    }
                }
                "forget" => {
                    let (gone, err) = st.forget(&paths);
                    for f in gone {
                        println!("forgotten {f}");
                    }
                    if let Some(e) = err {
                        return fail(&e);
                    }
                }
                _ => {
                    let (back, err) = st.restore(&paths);
                    for r in &back {
                        println!("restored {} (it was {})", r.path, r.why);
                    }
                    if let Some(e) = err {
                        return fail(&e);
                    }
                    if back.is_empty() {
                        println!("every signed file is as approved");
                    }
                }
            }
            0
        }
        "verify" => {
            // any user: is each watched file (or each path given) as approved?
            let m = match st.load() {
                Ok(m) => trust::SignedList::from_manifest(&m),
                Err(e) => return fail(&e),
            };
            let mut files: Vec<Vec<u8>> = Vec::new();
            if args.len() > 1 {
                for p in &args[1..] {
                    let (exp, err) = trust::expand(p);
                    if let Some(e) = err {
                        return fail(&e);
                    }
                    files.extend(exp);
                }
            } else {
                let w = st.watch();
                files.extend(w.files.into_iter().flatten().map(String::into_bytes));
                for d in w.dirs.into_iter().flatten() {
                    let (exp, err) = trust::expand(&d);
                    if err.is_none() {
                        files.extend(exp);
                    }
                }
                files.extend(m.files.keys().cloned());
            }
            files.sort();
            files.dedup();
            let mut bad = 0;
            for f in files {
                let sum = trust::hash_file(&f);
                let line = match &sum {
                    Err(e) if trust::not_exist(e) && m.has(&f) => {
                        bad += 1;
                        "MISSING  "
                    }
                    Err(_) => continue,
                    Ok(s) if m.matches(&f, s) => "ok       ",
                    Ok(_) if m.has(&f) => {
                        bad += 1;
                        "CHANGED  "
                    }
                    Ok(_) => {
                        bad += 1;
                        "UNSIGNED "
                    }
                };
                out(&[line.as_bytes(), &f].concat());
            }
            i32::from(bad > 0)
        }
        "watch" => {
            if args.len() < 3 || (args[1] != "add" && args[1] != "remove") {
                return usage();
            }
            if !need_root() {
                return 2;
            }
            let mut w = st.watch();
            for p in &args[2..] {
                let Ok(abs) = crate::gopath::abs(p) else { return 1 };
                let is_dir = std::fs::metadata(&abs).is_ok_and(|m| m.is_dir());
                w.files = without(w.files.take(), &abs);
                w.dirs = without(w.dirs.take(), &abs);
                if args[1] == "add" {
                    let list = if is_dir { &mut w.dirs } else { &mut w.files };
                    list.get_or_insert_with(Vec::new).push(abs);
                }
            }
            if let Err(e) = st.set_watch(&w) {
                return fail(&e);
            }
            println!("watch list updated; heimdalld picks it up when it restarts");
            0
        }
        _ => usage(),
    }
}

/// Go's `without`: the list without x; nil (None) when nothing is left.
fn without(list: Option<Vec<String>>, x: &str) -> Option<Vec<String>> {
    let out: Vec<String> = list.into_iter().flatten().filter(|v| v != x).collect();
    (!out.is_empty()).then_some(out)
}
