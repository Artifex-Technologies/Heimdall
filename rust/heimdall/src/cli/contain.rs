//! `heimdalld contain status|now|emergency|evidence|release|run-request` (Go: cmd/heimdalld/contain.go, internal/contain):
//! stop a compromised AI agent (docs/CONTAIN.md).
//!
//! Every subcommand is ported; what containment does to the computer is in `contain/steps.rs`.

mod steps;

use crate::contain;

const USAGE: &str = "heimdalld contain: stop a compromised AI agent (see docs/CONTAIN.md)
  heimdalld contain status                    is Sarina contained, and what may Heimdall do by itself
  heimdalld contain now [--reason R] [--escalate]
                                              unload the models, stop Sarina and lock her out (root); --escalate: the
                                              emergency step follows when that did not hold after a minute
  heimdalld contain emergency --yes           the last resort (root): restore the approved files, kill everything on the
                                              graphics card (games and the desktop too), reset the card, restart
  heimdalld contain evidence                  the saved evidence folders (root): what ran, connections, logs, sessions,
                                              copies of the unapproved files; saved before anything is stopped
  heimdalld contain release                   restore the approved files and lift the lock (root)
";

/// The lock's path: Go's, or HEIMDALL_CONTAIN_MARKER (Go's tests use it; it also skips the root check there).
fn marker() -> String {
    match std::env::var("HEIMDALL_CONTAIN_MARKER") {
        Ok(p) if !p.is_empty() => p,
        _ => contain::MARKER_PATH.into(),
    }
}

fn on_off(b: bool) -> String {
    if b {
        "on".into()
    } else {
        format!("off ({})", contain::CONFIG_PATH)
    }
}

pub fn main(args: &[String]) -> Option<i32> {
    let Some(sub) = args.first() else {
        eprint!("{USAGE}");
        return Some(2);
    };
    match sub.as_str() {
        "evidence" => {
            // the saved collections, newest first (root: they are root-only)
            use std::io::Write;
            use std::os::unix::ffi::OsStrExt;
            // names as bytes: Go prints a name that is not UTF-8 as it is
            let mut names: Vec<Vec<u8>> = match std::fs::read_dir(contain::EVIDENCE_DIR)
                .and_then(|rd| rd.map(|e| e.map(|e| e.file_name().as_bytes().to_vec())).collect::<Result<Vec<_>, _>>())
            {
                Ok(n) => n,
                Err(_) => {
                    println!("no evidence saved (or not readable without sudo)");
                    return Some(0);
                }
            };
            names.sort();
            let mut out = Vec::new();
            for n in names.iter().rev() {
                out.extend_from_slice(contain::EVIDENCE_DIR.as_bytes());
                out.push(b'/');
                out.extend_from_slice(n);
                out.push(b'\n');
            }
            let _ = std::io::stdout().write_all(&out);
            Some(0)
        }
        "status" => {
            let m = contain::read_marker(&marker());
            let (auto, emergency) = contain::load_config(contain::CONFIG_PATH);
            let mut out = match &m {
                None => "Sarina: not contained\n".to_string(),
                Some(m) => format!("Sarina: {} since {}\nreason: {}\n", m.level, m.since.local().format("2006-01-02 15:04"), m.reason),
            };
            out += &format!("automatic containment: {}\nautomatic emergency: {}\n", on_off(auto), on_off(emergency));
            print!("{out}");
            Some(if m.is_some() { 1 } else { 0 })
        }
        "now" | "emergency" | "run-request" | "release" => Some(act(sub, &args[1..])),
        _ => {
            eprint!("{USAGE}");
            Some(2)
        }
    }
}

/// `heimdalld contain: ` lines on standard error (Go's `log.New(os.Stderr, "heimdalld contain: ", 0)`).
fn log(s: &str) {
    crate::cli::golog::Logger::new("heimdalld contain: ", false).print(s);
}

/// The sessions kept as evidence: the folder Heimdall watches, and each user's own.
fn sessions() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(cfg) = crate::config::Config::load_go("/etc/heimdall/config.json") {
        if !cfg.agent_session_dir.is_empty() {
            out.push(cfg.agent_session_dir);
        }
    }
    out.extend(crate::cli::immunity::store::glob("/home/*/.sarina/sessions").iter().map(|p| crate::gotext::lossy(p)));
    out
}

/// `now`, `emergency`, `run-request`, `release` (root).
fn act(sub: &str, args: &[String]) -> i32 {
    use crate::cli::goflag::FlagSet;
    let test = std::env::var("HEIMDALL_CONTAIN_MARKER").is_ok_and(|v| !v.is_empty());
    let need_root = || {
        if !rustix::process::geteuid().is_root() && !test {
            eprintln!("heimdalld contain: this needs root (sudo)");
            return false;
        }
        true
    };
    let runner = || steps::Runner::new(marker(), sessions(), log);
    match sub {
        "now" => {
            let mut fs = FlagSet::new("contain now");
            fs.string("reason", "contained by the owner", "why (kept in the lock)");
            fs.bool("escalate", false, "when containment does not hold after a minute, go on to the emergency step");
            if fs.parse(args).is_err() || !need_root() {
                return 2;
            }
            match runner().run(&fs.get_str("reason"), false, false, fs.get_bool("escalate")) {
                Ok(()) => 0,
                Err(e) => {
                    log(&e);
                    1
                }
            }
        }
        "emergency" => {
            let mut fs = FlagSet::new("contain emergency");
            fs.bool("yes", false, "really: this kills the desktop and every game and restarts the computer");
            fs.string("reason", "emergency started by the owner", "why (kept in the lock)");
            if fs.parse(args).is_err() || !need_root() {
                return 2;
            }
            if !fs.get_bool("yes") {
                eprintln!(
                    "heimdalld contain emergency: this kills the desktop and every program on the graphics card, resets the card and restarts; add --yes"
                );
                return 2;
            }
            match runner().emergency(&fs.get_str("reason")) {
                Ok(()) => 0,
                Err(e) => {
                    log(&e);
                    1
                }
            }
        }
        "run-request" => {
            if !need_root() {
                return 2;
            }
            let Ok(b) = std::fs::read(contain::REQUEST_PATH) else { return 0 };
            let _ = std::fs::remove_file(contain::REQUEST_PATH);
            static REQ: crate::gostruct::Ty = crate::gostruct::Ty::Struct(
                "contain.Request",
                &[
                    crate::gostruct::Field("time", &crate::gostruct::Ty::Time, false),
                    crate::gostruct::Field("reason", &crate::gostruct::Ty::Str, false),
                    crate::gostruct::Field("auto", &crate::gostruct::Ty::Bool, false),
                ],
            );
            let (v, err) = crate::gostruct::unmarshal(&REQ, &b);
            let reason = crate::gostruct::str_field(&REQ, &v, "reason").to_string();
            if err.is_some() || crate::gotext::trim_space(&reason).is_empty() {
                log("ignored an unreadable request");
                return 1;
            }
            let (auto, auto_emergency) = contain::load_config(contain::CONFIG_PATH);
            if !auto {
                log(&format!("ignored a request: automatic containment is off ({})", contain::CONFIG_PATH));
                return 0;
            }
            let reason = if reason.len() > 300 { crate::gotext::lossy(&reason.as_bytes()[..300]) } else { reason };
            match runner().run(&reason, true, auto_emergency, false) {
                Ok(()) => 0,
                Err(e) => {
                    log(&e);
                    1
                }
            }
        }
        _ => release(test, need_root()),
    }
}

/// `release`: the approved behaviour files put back, the lock lifted, proven holds of the containment put back.
fn release(test: bool, root: bool) -> i32 {
    use crate::cli::immunity::store;
    if !root {
        return 2;
    }
    let ts = crate::trust::Store::new(crate::trust::DEFAULT_DIR);
    if ts.load().is_ok() {
        let (back, err) = ts.restore(&[]);
        for r in &back {
            println!("restored {} (it was {})", r.path, r.why);
        }
        if let Some(e) = err {
            eprintln!("heimdalld contain: restoring failed, the lock stays: {e}");
            return 1;
        }
    } else {
        println!("no signed list (heimdalld trust init), so nothing to restore");
    }
    let m = marker();
    match std::fs::remove_file(&m) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!("heimdalld contain: {}", crate::goerr::path("remove", &m, &e));
            return 1;
        }
    }
    let imm = store::Store::default_store();
    let proof = store::Proof::load();
    if let Ok(es) = imm.load() {
        for e in es.unwrap_or_default() {
            if store::s(&e, "status") != store::HELD || store::s(&e, "source") != "containment" {
                continue;
            }
            match imm.release_if_proven(&store::s(&e, "sha256"), &proof) {
                Ok(r) => println!("put back {} ({})", store::s(&r, "original"), store::s(&r, "released_by")),
                Err(_) => println!("still held, for you to judge: {}", store::s(&e, "original")),
            }
        }
    }
    if !test {
        let _ = std::process::Command::new("systemctl")
            .args(["start", "ollama.service"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    println!("released: Sarina may start again");
    0
}
