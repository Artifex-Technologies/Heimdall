//! `heimdalld immunity rule list|show|draft|test|approve|reject` (Go: cmd/heimdalld/rules.go, internal/immunity/rules.go): the
//! YARA rule drafts on the daemon's own drafts file (`immunity::Rules`), tested with clamscan against the sample and this
//! computer's programs, installed into ClamAV's folder only after a passing test of the exact text and the owner's yes.

use super::store::{self, get, set, Store};
use crate::cli::goflag::FlagSet;
use crate::gostruct::{self, Ty, Val};
use crate::gotime::Time;
use crate::immunity::RULE;

const USAGE: &str = "usage:
  heimdalld immunity rule list                      the YARA rule drafts and their state
  heimdalld immunity rule show ID                   one draft: the rule, who drafted it, its test
  sudo heimdalld immunity rule draft SHA256 FILE    keep a rule you wrote for a held sample (Sarina drafts through the API)
  sudo heimdalld immunity rule test ID [--fp DIR]... match it against the sample (must) and this computer's programs (must not)
  sudo heimdalld immunity rule approve ID           ClamAV loads it from now on (only after a passing test of this exact text)
  sudo heimdalld immunity rule reject ID            refuse it; an approved rule is removed from ClamAV
See docs/IMMUNITY.md, \"Rules\".";

const DEFAULT_FP_ROOTS: &[&str] = &["/usr/bin", "/usr/local/bin", "/usr/lib/systemd"];

fn rs(v: &Val, k: &str) -> String {
    match get(&RULE, v, k) {
        Val::Str(s) => s.clone(),
        _ => String::new(),
    }
}

fn test_ty() -> &'static Ty {
    match &RULE {
        Ty::Struct(_, f) => match f.iter().find(|x| x.0 == "test").map(|x| x.1) {
            Some(Ty::Ptr(t)) => t,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

fn text_sha(s: &str) -> String {
    store::hex_sha(s.as_bytes())
}

struct Drafts {
    r: crate::immunity::Rules,
    rules_dir: String,
}

impl Drafts {
    fn load(&self) -> Result<Vec<Val>, String> {
        match self.r.load()? {
            Some(Val::Slice(Some(v))) => Ok(v),
            _ => Ok(Vec::new()),
        }
    }
    /// Go's `Rules.update`.
    fn update(&self, id: &str, f: impl FnOnce(&mut Val) -> Result<(), String>) -> Result<Val, String> {
        let mut all = self.load()?;
        let Some(n) = all.iter().position(|x| rs(x, "id") == id) else {
            return Err(format!("no rule draft {} (heimdalld immunity rule list)", crate::gotext::quote(id)));
        };
        f(&mut all[n])?;
        let x = all[n].clone();
        self.r.save(&Val::Slice(Some(all)))?;
        Ok(x)
    }
}

/// Go's `ClamRuleScan`: the paths clamscan reports with only the rule loaded.
fn clam_rule_scan(rule: &str, paths: &[String]) -> Result<Vec<String>, String> {
    let Some(bin) = super::scan::look_path("clamscan") else {
        return Err("exec: \"clamscan\": executable file not found in $PATH".into());
    };
    let out = std::process::Command::new(bin)
        .args(["--no-summary", "--infected", "-r", "--max-filesize=200M", "--max-scansize=200M", "-d", rule, "--"])
        .args(paths)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| crate::goerr::text(&e))?;
    let text = crate::gotext::lossy(&out.stdout);
    let matched: Vec<String> = text
        .split('\n')
        .filter(|l| l.ends_with(" FOUND"))
        .filter_map(|l| l.rfind(": ").filter(|&i| i > 0).map(|i| l[..i].to_string()))
        .collect();
    match out.status.code() {
        Some(0..=2) => Ok(matched),
        Some(c) => Err(format!("exit status {c}")),
        None => Err("signal: killed".into()),
    }
}

pub fn main(args: &[String], st: &Store) -> Option<i32> {
    let env = |k: &str, d: &str| std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string());
    let d = Drafts {
        r: crate::immunity::Rules { path: env("HEIMDALL_RULE_DRAFTS", crate::immunity::DEFAULT_RULE_DRAFTS) },
        rules_dir: env("HEIMDALL_RULES_DIR", "/var/lib/clamav"),
    };
    if args.is_empty() {
        eprintln!("{USAGE}");
        return Some(2);
    }
    let mut fs = FlagSet::new("rule");
    fs.list(
        "fp",
        "a folder of this computer's own programs the rule must not match (repeatable; default /usr/bin, /usr/local/bin, /usr/lib/systemd)",
    );
    if fs.parse(&crate::cli::mesh::flags_first(&args[1..])).is_err() {
        return Some(2);
    }
    let fail = |e: &str| {
        eprintln!("heimdalld immunity rule: {e}");
        Some(1)
    };
    let find = |id: &str| d.load().unwrap_or_default().into_iter().rev().find(|x| rs(x, "id") == id);
    let local = |v: &Val, k: &str| match get(&RULE, v, k) {
        Val::Time(t) => t.local().format("2006-01-02 15:04"),
        _ => String::new(),
    };
    let nargs = fs.narg();
    let arg = |i: usize| fs.args()[i].clone();
    match args[0].as_str() {
        "list" => {
            let all = match d.r.load() {
                Ok(Some(Val::Slice(Some(v)))) => v,
                Ok(_) => Vec::new(),
                Err(e) => return fail(&e),
            };
            if all.is_empty() {
                println!("no rule drafts");
            }
            for x in &all {
                let sha = rs(x, "sample_sha256");
                println!(
                    "{}  {} {} sample {}  {}",
                    rs(x, "id"),
                    pad(&rs(x, "status"), 9),
                    pad(&rs(x, "name"), 40),
                    &sha[..sha.len().min(12)],
                    local(x, "time")
                );
            }
            return Some(0);
        }
        "show" if nargs == 1 => {
            let Some(x) = find(&arg(0)) else { return fail(&format!("no draft {}", arg(0))) };
            let uid = match get(&RULE, &x, "uid") {
                Val::Uint(u) => *u as i64,
                Val::Int(i) => *i,
                _ => 0,
            };
            println!(
                "draft {} ({}), rule {}, for sample {}, from account {uid} at {}",
                rs(&x, "id"),
                rs(&x, "status"),
                rs(&x, "name"),
                rs(&x, "sample_sha256"),
                local(&x, "time")
            );
            let note = rs(&x, "note");
            if !note.is_empty() {
                println!("note (the drafter's words, untrusted): {}", crate::gotext::quote(&note));
            }
            println!("---\n{}\n---", rs(&x, "text").trim_end_matches('\n'));
            if let Val::Ptr(Some(t)) = get(&RULE, &x, "test") {
                print_test(t, true);
            }
            return Some(0);
        }
        _ => {}
    }
    if !rustix::process::geteuid().is_root() && std::env::var("HEIMDALL_IMMUNITY_DIR").map(|v| v.is_empty()).unwrap_or(true) {
        return fail("this needs root (sudo)");
    }
    let by = std::env::var("SUDO_USER").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "root".into());
    let now = Time::now();
    match args[0].as_str() {
        "draft" if nargs == 2 => {
            let b = match std::fs::read(arg(1)) {
                Ok(b) => b,
                Err(e) => return fail(&crate::gopath::read_err(&arg(1), &e)),
            };
            let es = st.load().ok().flatten().unwrap_or_default();
            let a0 = arg(0);
            let sha = es.iter().map(|e| store::s(e, "sha256")).rfind(|s| s.starts_with(&a0) && a0.len() >= 8).unwrap_or_default();
            if sha.is_empty() {
                return fail(&format!("no held sample {a0} (heimdalld immunity list)"));
            }
            match d.r.draft(&sha, &crate::gotext::lossy(&b), &format!("written by {by}"), 0, now) {
                Ok(x) => {
                    println!("draft {} kept; next: sudo heimdalld immunity rule test {}", x.id, x.id);
                    Some(0)
                }
                Err(e) => fail(&e),
            }
        }
        "test" if nargs == 1 => {
            let mut roots = fs.get_list("fp");
            if roots.is_empty() {
                roots = DEFAULT_FP_ROOTS.iter().map(|s| s.to_string()).collect();
            }
            println!("testing against the sample and {} (this reads every file there; about half a minute for /usr/bin)", roots.join(", "));
            let x = match test(&d, &arg(0), st, &roots, now) {
                Ok(x) => x,
                Err(e) => return fail(&e),
            };
            let Val::Ptr(Some(t)) = get(&RULE, &x, "test") else { return Some(1) };
            print_test(t, false);
            if rs(&x, "status") == "tested" {
                println!("next: sudo heimdalld immunity rule approve {}", rs(&x, "id"));
                return Some(0);
            }
            Some(1)
        }
        "approve" | "reject" if nargs == 1 => {
            if let Err(e) = crate::cli::grant::guard("/proc", crate::cli::grant::stdin_is_terminal()) {
                return fail(&format!("refused: {e}"));
            }
            let Some(x) = find(&arg(0)) else { return fail(&format!("no draft {}", arg(0))) };
            if args[0] == "approve" {
                println!("---\n{}\n---", rs(&x, "text").trim_end_matches('\n'));
                if !crate::cli::grant::confirm("ClamAV will report every file this rule matches as malware. Approve it? Type yes: ") {
                    println!("nothing changed");
                    return Some(1);
                }
                return match approve(&d, &rs(&x, "id"), &by, now) {
                    Ok(x) => {
                        println!("approved; ClamAV loads {} on its next start or scan (YARA.{})", rs(&x, "installed"), rs(&x, "name"));
                        Some(0)
                    }
                    Err(e) => fail(&e),
                };
            }
            let res = d.update(&rs(&x, "id"), |x| {
                let inst = rs(x, "installed");
                if !inst.is_empty() {
                    match std::fs::remove_file(&inst) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(crate::goerr::path("remove", &inst, &e)),
                    }
                    set(&RULE, x, "installed", Val::Str(String::new()));
                }
                set(&RULE, x, "status", Val::Str("rejected".into()));
                set(&RULE, x, "decided", Val::Time(now.utc()));
                set(&RULE, x, "by", Val::Str(by.clone()));
                Ok(())
            });
            match res {
                Ok(_) => {
                    println!("rejected");
                    Some(0)
                }
                Err(e) => fail(&e),
            }
        }
        _ => {
            eprintln!("{USAGE}");
            Some(2)
        }
    }
}

/// A test's result; with `with_time` the line `show` prints first, otherwise the caller printed its status line already.
fn print_test(t: &Val, with_time: bool) {
    let tt = test_ty();
    let g = |k: &str| get(tt, t, k).clone();
    let matched = matches!(g("matched_sample"), Val::Bool(true));
    let fp = match g("fp_count") {
        Val::Int(n) => n,
        _ => 0,
    };
    let strs = |v: Val| -> Vec<String> {
        match v {
            Val::Slice(Some(v)) => v
                .into_iter()
                .map(|x| match x {
                    Val::Str(s) => s,
                    _ => String::new(),
                })
                .collect(),
            _ => Vec::new(),
        }
    };
    let err = match g("error") {
        Val::Str(s) => s,
        _ => String::new(),
    };
    if with_time {
        let time = match g("time") {
            Val::Time(t) => t.local().format("2006-01-02 15:04"),
            _ => String::new(),
        };
        print!("test {time}: matched the sample: {matched}; matched {fp} of this computer's files in {}", strs(g("scanned")).join(", "));
    }
    if !err.is_empty() {
        print!("; error: {err}");
    }
    println!();
    for p in strs(g("false_positives")) {
        println!("  matched: {p}");
    }
}

/// Go's `Rules.Test`.
fn test(d: &Drafts, id: &str, st: &Store, roots: &[String], now: Time) -> Result<Val, String> {
    let all = d.load()?;
    let Some(x) = all.iter().rev().find(|x| rs(x, "id") == id).cloned() else {
        return Err(format!("no rule draft {}", crate::gotext::quote(id)));
    };
    let text = rs(&x, "text");
    if crate::immunity::check_rule(&text).is_err() || text_sha(&text) != rs(&x, "text_sha256") {
        return Err("the draft changed or is malformed; draft it again".into());
    }
    let base = std::env::var("TMPDIR").ok().filter(|t| !t.is_empty()).unwrap_or_else(|| "/tmp".into());
    let mut r = [0u8; 4];
    crate::grants::random(&mut r);
    let work = format!("{base}/heimdall-rule-{}", u32::from_le_bytes(r));
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&work)
            .map_err(|e| crate::goerr::path("mkdirtemp", &format!("{base}/heimdall-rule-*"), &e))?;
    }
    struct Rm(String);
    impl Drop for Rm {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _rm = Rm(work.clone());
    let rule = format!("{work}/{}.yar", rs(&x, "name"));
    crate::gopath::write_file(&rule, text.as_bytes(), 0o600)?;
    let sample = format!("{work}/sample");
    let sha = rs(&x, "sample_sha256");
    st.extract(&sha, &sample).map_err(|e| format!("the sample {}: {e}", &sha[..sha.len().min(12)]))?;
    let tt = test_ty();
    let mut t = gostruct::zero(tt);
    set(tt, &mut t, "time", Val::Time(now.utc()));
    set(tt, &mut t, "text_sha256", Val::Str(rs(&x, "text_sha256")));
    set(tt, &mut t, "scanned", Val::Slice(Some(roots.iter().map(|r| Val::Str(r.clone())).collect())));
    let mut error = String::new();
    let mut matched = false;
    match clam_rule_scan(&rule, std::slice::from_ref(&sample)) {
        Err(e) => error = e,
        Ok(m) => matched = !m.is_empty(),
    }
    let mut fp_count = 0;
    if error.is_empty() {
        let fp = match clam_rule_scan(&rule, roots) {
            Ok(m) => m,
            Err(e) => {
                error = e;
                Vec::new()
            }
        };
        fp_count = fp.len();
        let shown: Vec<Val> = fp.into_iter().take(20).map(Val::Str).collect();
        set(tt, &mut t, "false_positives", Val::Slice(if shown.is_empty() { None } else { Some(shown) }));
    }
    set(tt, &mut t, "matched_sample", Val::Bool(matched));
    set(tt, &mut t, "fp_count", Val::Int(fp_count as i64));
    set(tt, &mut t, "error", Val::Str(error.clone()));
    let passed = error.is_empty() && matched && fp_count == 0;
    let x = d.update(id, |x| {
        set(&RULE, x, "test", Val::Ptr(Some(Box::new(t))));
        set(&RULE, x, "status", Val::Str(if passed { "tested" } else { "failed" }.into()));
        Ok(())
    })?;
    let status = rs(&x, "status");
    print!("{status}: matched the sample: {matched}; matched {fp_count} of this computer's files");
    Ok(x)
}

/// Go's `Rules.Approve`.
fn approve(d: &Drafts, id: &str, by: &str, now: Time) -> Result<Val, String> {
    let dir = d.rules_dir.clone();
    d.update(id, |x| {
        let text = rs(x, "text");
        let tested = match get(&RULE, x, "test") {
            Val::Ptr(Some(t)) => match get(test_ty(), t, "text_sha256") {
                Val::Str(s) => Some(s.clone()),
                _ => None,
            },
            _ => None,
        };
        if rs(x, "status") != "tested" || tested.as_deref() != Some(text_sha(&text).as_str()) || tested.as_deref() != Some(rs(x, "text_sha256").as_str()) {
            return Err(format!(
                "only a draft that matched its sample and none of this computer's programs can be approved: sudo heimdalld immunity rule test {}",
                rs(x, "id")
            ));
        }
        crate::immunity::check_rule(&text)?;
        let name = rs(x, "name");
        let lower = crate::gotext::to_lower(name.strip_prefix("Heimdall_").unwrap_or(&name));
        let dst = crate::gopath::join(&[&dir, &format!("heimdall-rule-{lower}.yar")]);
        let mut r = [0u8; 4];
        crate::grants::random(&mut r);
        let tmp = crate::gopath::join(&[&dir, &format!(".heimdall-rule-{}", u32::from_le_bytes(r))]);
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| crate::goerr::path("open", &format!("{dir}/.heimdall-rule-*"), &e))?;
            if let Err(e) = f.write_all(text.as_bytes()) {
                let _ = std::fs::remove_file(&tmp);
                return Err(crate::goerr::path("write", &tmp, &e));
            }
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o644));
        }
        if let Err(e) = std::fs::rename(&tmp, &dst) {
            let _ = std::fs::remove_file(&tmp);
            return Err(crate::goerr::link("rename", &tmp, &dst, &e));
        }
        set(&RULE, x, "status", Val::Str("approved".into()));
        set(&RULE, x, "decided", Val::Time(now.utc()));
        set(&RULE, x, "by", Val::Str(by.into()));
        set(&RULE, x, "installed", Val::Str(dst));
        Ok(())
    })
}

fn pad(s: &str, n: usize) -> String {
    let c = s.chars().count();
    if c >= n {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(n - c))
    }
}
