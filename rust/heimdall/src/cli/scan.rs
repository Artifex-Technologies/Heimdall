//! `heimdalld scan --config PATH` (Go: cmd/heimdalld/main.go's cmdScan): one look at everything the daemon watches that can
//! be looked at once (Sarina's sessions, Limbo's whole log, the vaults, the watched files, the host's load, the ecosystem's
//! ports) through the daemon's detectors, the findings printed oldest first as alert lines. Exit 0 when nothing above info
//! was found, 1 when something was, 2 when the scan could not run or was incomplete (an unreadable session or vault), so an
//! audit that missed something never reads as clean.

use super::goflag::FlagSet;
use super::golog::Logger;
use crate::alert::{Ring, Sink, WriterSink};
use crate::config::Config;
use crate::detect::{self, Deps};
use crate::engine::Engine;
use crate::event::Severity;
use crate::pkgverify::Verifier;
use crate::sources;
use crate::toolrules;
use std::sync::{Arc, Mutex};

pub fn main(args: &[String]) -> Option<i32> {
    Some(run(args))
}

/// Go's `loadConfigFlag`: `--config PATH` (flag set "heimdalld"), then the config; Go prints a flag error twice (the flag
/// package's own message and usage, then "heimdalld: " and the error).
pub fn load_config_flag(args: &[String]) -> Result<Config, String> {
    let mut fs = FlagSet::new("heimdalld");
    fs.string("config", "", "path to a JSON config file (optional)");
    if fs.parse(args).is_err() {
        return Err(fs.error());
    }
    Config::load_go(&fs.get_str("config"))
}

fn run(args: &[String]) -> i32 {
    let mut cfg = match load_config_flag(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("heimdalld: {e}");
            return 2;
        }
    };
    if cfg.agent_session_dir.is_empty() && cfg.limbo_event_log.is_empty() && cfg.vault_dirs.is_empty() {
        eprintln!("heimdalld: none of agent_session_dir, limbo_event_log and vault_dirs is set in config; nothing to scan");
        return 2;
    }
    let logger = Logger::new("heimdalld: ", true);
    let ring = Arc::new(Mutex::new(Ring::new(cfg.ring_size)));
    cfg.agent_baseline_state_path = String::new(); // an audit learns nothing into the daemon's baseline
    let approvals = detect::Approvals::new("/etc/heimdall/remote-access-approved.json");
    let peers = cfg.mesh_peers_path.clone();
    let deps = Deps {
        verifier: Some(Box::new(Verifier::new(&cfg.pacman_db))),
        trust: Some(Box::new(crate::trust::Judge { store: crate::trust::Store::new(crate::trust::DEFAULT_DIR) })),
        mesh_peer: Some(Box::new(move |ip: &str| detect::mesh_peer_at(&peers, ip))),
        approved: Some(Box::new(move |id: &str| approvals.approved(id))),
        ephemeral: None,
    };
    let sink: Box<dyn Sink> = Box::new(ring.clone());
    let mut eng = Engine::new(sink, detect::daemon_detectors(&cfg, deps));
    if toolrules::enabled() {
        match toolrules::builtin() {
            Ok(tools) => {
                let n = tools.len();
                let v = Verifier::new(&cfg.pacman_db);
                eng.set_tool_rules(toolrules::Policy::new(tools, Box::new(move |p: &str| v.expected(p)), toolrules::caching_hasher()));
                logger.print(&format!("tool rules in force: {n} security tools ({})", toolrules::MARKER_PATH));
            }
            Err(e) => logger.print(&format!("tool rules not in force: {e}")),
        }
    }
    let mut incomplete = false; // some session or note could not be read

    if !cfg.agent_session_dir.is_empty() {
        let mut w = sources::agent::Watcher::new(&cfg.agent_session_dir);
        match w.poll() {
            Ok(events) => events.iter().for_each(|e| eng.handle(e)),
            Err(e) => {
                eprintln!("heimdalld: {e}");
                return 2;
            }
        }
        // a file that could not be read was not audited; that must not read as clean
        for i in w.issues() {
            eprintln!("heimdalld: warning: {i}");
            incomplete = true;
        }
    }

    // a scan is an audit: Limbo's whole log, no offset kept
    if !cfg.limbo_event_log.is_empty() {
        if let Err(e) = std::fs::metadata(&cfg.limbo_event_log) {
            if e.kind() == std::io::ErrorKind::NotFound {
                eprintln!("heimdalld: warning: limbo_event_log {} does not exist; nothing audited there", cfg.limbo_event_log);
            }
        }
        let mut lw = sources::limbo::Watcher::new(&cfg.limbo_event_log, "", true);
        match lw.poll() {
            Ok(events) => events.iter().for_each(|e| eng.handle(e)),
            Err(e) => {
                eprintln!("heimdalld: limbo event log: {}", limbo_error(&cfg.limbo_event_log, &e));
                return 2;
            }
        }
        if lw.skipped > 0 {
            eprintln!("heimdalld: {} unparseable line(s) in the Limbo event log", lw.skipped);
        }
    }

    // an audit checks every note, remembering nothing
    if !cfg.vault_dirs.is_empty() {
        let mut vw = sources::vault::Watcher::new(cfg.vault_dirs.clone(), "");
        let (events, _) = vw.scan();
        for i in std::mem::take(&mut vw.issues) {
            eprintln!("heimdalld: warning: vault: {i}");
            incomplete = true;
        }
        events.iter().for_each(|e| eng.handle(e));
    }

    if !cfg.fim_paths.is_empty() {
        let mut fw = sources::fim::Watcher::new(&cfg.fim_paths, &cfg.fim_state_path);
        let (events, err) = fw.poll();
        if let Some(e) = err {
            eprintln!("heimdalld: fim state save error: {}", save_error(&cfg.fim_state_path, &e));
        }
        events.iter().for_each(|e| eng.handle(e));
    }

    // telemetry and the ports are best-effort in a one-shot scan: a missing /proc is silent, anything else printed
    match sources::telemetry::Telemetry::default().poll() {
        Ok(e) => eng.handle(&e),
        Err((not_exist, e)) => {
            if !not_exist {
                eprintln!("heimdalld: telemetry poll error: {e}");
            }
        }
    }
    if !cfg.net_ports.is_empty() {
        let mut pw = sources::net::PortWatcher::new(&cfg.net_ports).reporting_first();
        match sources::net::read_tables(&["/proc/net/tcp".to_string(), "/proc/net/tcp6".to_string()]) {
            Ok(entries) => pw.observe(&entries).iter().for_each(|e| eng.handle(e)),
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("heimdalld: network exposure poll error: {}", crate::goerr::path("open", "/proc/net/tcp6", &e));
                }
            }
        }
    }
    drop(eng);

    let found = ring.lock().map(|r| r.recent(0)).unwrap_or_default();
    if found.is_empty() {
        println!("heimdalld: no findings");
        return if incomplete { 2 } else { 0 };
    }
    let mut out = WriterSink::new(std::io::stdout());
    let mut worst = Severity::Info;
    for a in found.iter().rev() {
        let _ = out.write(a);
        if a.severity == Severity::Critical {
            worst = Severity::Critical;
        } else if a.severity == Severity::Warning && worst != Severity::Critical {
            worst = Severity::Warning;
        }
    }
    if worst == Severity::Info {
        return if incomplete { 2 } else { 0 };
    }
    1
}

/// Go's text for the Limbo log's read error (its open, stat, seek or read: Go names the operation and the path).
fn limbo_error(path: &str, e: &std::io::Error) -> String {
    crate::goerr::path(if e.raw_os_error() == Some(libc::EISDIR) { "read" } else { "open" }, path, e)
}

/// Go's text for the FIM state's write error: the temporary file could not be made ("open S.tmp: ...") or not renamed
/// into place ("rename S.tmp S: ...", the temporary file then still there).
fn save_error(state: &str, e: &std::io::Error) -> String {
    let tmp = format!("{state}.tmp");
    if std::fs::symlink_metadata(&tmp).is_ok_and(|m| m.is_file()) {
        crate::goerr::link("rename", &tmp, state, e)
    } else {
        crate::goerr::path("open", &tmp, e)
    }
}
