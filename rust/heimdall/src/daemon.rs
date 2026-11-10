//! `heimdalld-rs run --shadow`: the daemon on one thread. Every source, the engine and the alert writers share one loop that
//! sleeps in poll(2) until a source's descriptor is readable, a source's time comes, or SIGTERM/SIGINT arrives (a signalfd).
//!
//! Shadow mode (the only mode until the responder, the API, the correlator, mesh and trust are ported): the real sources,
//! its own alert log and state files, no responses of any kind (no Limbo hold, no containment request, no copy of a held
//! file, nothing sent to a mesh peer, no API). It refuses to start with any state or log path in the Go daemon's folder,
//! so the two never write the same file. docs/RUST_SHADOW.md.

use crate::alert::{Alert, MultiSink, Ring, Sink, WriterSink};
use crate::config::Config;
use crate::detect::{self, Deps};
use crate::engine::Engine;
use crate::event::Fields;
use crate::maintenance;
use crate::pkgverify::Verifier;
use crate::sources::{self, Msg, Source};
use crate::toolrules;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The Go daemon's own folder: a shadow daemon writes nothing there.
pub const GO_STATE_DIR: &str = "/var/lib/heimdall/";

fn log(m: &str) {
    eprintln!("heimdalld-rs: {m}");
}

/// The paths a shadow daemon writes, by config name, for the guard.
fn written_paths(cfg: &Config) -> Vec<(&'static str, &str)> {
    vec![
        ("alert_log_path", &cfg.alert_log_path),
        ("agent_state_path", &cfg.agent_state_path),
        ("vault_state_path", &cfg.vault_state_path),
        ("fim_state_path", &cfg.fim_state_path),
        ("limbo_state_path", &cfg.limbo_state_path),
        ("agent_baseline_state_path", &cfg.agent_baseline_state_path),
        ("conn_state_path", &cfg.conn_state_path),
        ("firewall_cursor_path", &cfg.firewall_cursor_path),
        ("package_audit_state_path", &cfg.package_audit_state_path),
        ("kernel_audit_state_path", &cfg.kernel_audit_state_path),
        ("hardening_state_path", &cfg.hardening_state_path),
    ]
}

/// Refuses a shadow config that would share a file with the Go daemon.
pub fn check_shadow(cfg: &Config) -> Result<(), Vec<String>> {
    let mut bad = Vec::new();
    for (name, p) in written_paths(cfg) {
        if p.starts_with(GO_STATE_DIR) {
            bad.push(format!("{name} is {p}, in the Go daemon's folder; give the shadow daemon its own (e.g. /var/lib/heimdall-rs/)"));
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad)
    }
}

fn sarina_installed(cfg: &Config) -> bool {
    cfg.sarina_installed.is_empty() || std::path::Path::new(&cfg.sarina_installed).exists()
}

/// Blocks SIGTERM and SIGINT and returns a descriptor that becomes readable when one arrives.
fn signal_fd() -> std::io::Result<OwnedFd> {
    // SAFETY: plain libc calls on a local, zeroed sigset; the fd returned is owned here.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

struct Stdout;
impl std::io::Write for Stdout {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        std::io::stdout().lock().write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().lock().flush()
    }
}

/// Runs the daemon until SIGTERM or SIGINT. Exit code as the Go daemon's.
pub fn run(cfg: Config, shadow: bool) -> i32 {
    if !shadow {
        log("only shadow mode for now (the Limbo responder, the API, the correlator, mesh and trust are not ported yet): run --shadow");
        return 2;
    }
    if let Err(bad) = check_shadow(&cfg) {
        log("refusing to run in shadow mode beside the Go daemon:");
        for b in bad {
            log(&format!("  {b}"));
        }
        return 2;
    }
    let sig = match signal_fd() {
        Ok(fd) => fd,
        Err(e) => {
            log(&format!("cannot catch SIGTERM: {e}"));
            return 2;
        }
    };
    log("shadow mode: watching beside the Go daemon, own alert log, no responses");
    if !cfg.api_addr.is_empty() {
        log(&format!("api_addr {} ignored: the API is not ported yet (the Go daemon serves it)", cfg.api_addr));
    }
    if cfg.agent_session_dir.is_empty() && cfg.limbo_event_log.is_empty() {
        log("no AI agent sessions or Limbo log to watch; watching the computer itself");
    }
    if !sarina_installed(&cfg) {
        log("Sarina is not installed: running on my own (alerts are explained with built-in text)");
    }

    // the alert outputs: stdout, the recent ring (for the API, step 3) and the alert log
    let mut sinks: Vec<Box<dyn Sink>> = vec![Box::new(WriterSink::new(Stdout))];
    let ring = Arc::new(Mutex::new(Ring::new(cfg.ring_size)));
    sinks.push(Box::new(ring.clone()));
    if !cfg.alert_log_path.is_empty() {
        match std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&cfg.alert_log_path) {
            Ok(f) => sinks.push(Box::new(WriterSink::new(f))),
            Err(e) => {
                log(&format!("could not open alert_log_path {}: {} (continuing without it)", cfg.alert_log_path, sources::go_errno(&e)))
            }
        }
    }
    let approvals = detect::Approvals::new("/etc/heimdall/remote-access-approved.json");
    let peers = cfg.mesh_peers_path.clone();
    let deps = Deps {
        verifier: Some(Box::new(Verifier::new(&cfg.pacman_db))),
        trust: None,
        mesh_peer: Some(Box::new(move |ip: &str| detect::mesh_peer_at(&peers, ip))),
        approved: Some(Box::new(move |id: &str| approvals.approved(id))),
        ephemeral: None,
    };
    let mut eng = Engine::new(Box::new(MultiSink { sinks }), detect::daemon_detectors(&cfg, deps));
    eng.set_maintenance(maintenance::Watcher::new(&cfg.maintenance_path), &cfg.maintenance_soften);
    if toolrules::enabled() {
        match toolrules::builtin() {
            Ok(tools) => {
                let n = tools.len();
                let v = Verifier::new(&cfg.pacman_db);
                eng.set_tool_rules(toolrules::Policy::new(tools, Box::new(move |p: &str| v.expected(p)), toolrules::caching_hasher()));
                log(&format!("tool rules in force: {n} security tools ({})", toolrules::MARKER_PATH));
            }
            Err(e) => log(&format!("tool rules not in force: {e}")),
        }
    }
    log("trust (the signed list of the AI agents' behaviour files) is not ported yet: those files are watched only if listed in fim_paths");

    let secs = |ns: i64| Duration::from_nanos(ns.max(1_000_000_000) as u64);
    let mut srcs: Vec<Box<dyn Source>> = vec![Box::new(sources::maintenance::MaintenanceSource::new(&cfg.maintenance_path))];
    srcs.push(Box::new(sources::telemetry::TelemetrySource::new(Default::default(), secs(cfg.telemetry_interval()))));
    if !cfg.fim_paths.is_empty() {
        log(&format!(
            "watching {} file(s) for integrity (poll every {})",
            cfg.fim_paths.len(),
            crate::gotext::duration(cfg.fim_poll_interval())
        ));
        let w = sources::fim::Watcher::new(&cfg.fim_paths, &cfg.fim_state_path);
        srcs.push(Box::new(sources::fim::FimSource::new(w, secs(cfg.fim_poll_interval()))));
    }
    if !cfg.limbo_event_log.is_empty() {
        log(&format!(
            "watching Limbo event log {} (poll every {})",
            cfg.limbo_event_log,
            crate::gotext::duration(cfg.limbo_poll_interval())
        ));
        let w = sources::limbo::Watcher::new(&cfg.limbo_event_log, &cfg.limbo_state_path, false);
        srcs.push(Box::new(sources::limbo::LimboSource::new(w, secs(cfg.limbo_poll_interval()))));
    }
    if !cfg.vault_dirs.is_empty() {
        log(&format!("checking the notes of {} AI agent vault(s) when they change", cfg.vault_dirs.len()));
        srcs.push(Box::new(sources::vault::VaultSource::new(sources::vault::Watcher::new(cfg.vault_dirs.clone(), &cfg.vault_state_path))));
    }
    if !cfg.agent_session_dir.is_empty() {
        log(&format!(
            "watching {} (read when the kernel says a session changed, at most every {} per busy session; all of it every 10 minutes)",
            cfg.agent_session_dir,
            crate::gotext::duration(cfg.poll_interval())
        ));
        let w = if cfg.agent_state_path.is_empty() {
            sources::agent::Watcher::new(&cfg.agent_session_dir)
        } else {
            sources::agent::Watcher::with_state(&cfg.agent_session_dir, &cfg.agent_state_path)
        };
        srcs.push(Box::new(sources::agent::AgentSource::new(w, secs(cfg.poll_interval()))));
    }
    // one read of /proc/net/tcp{,6} per interval, shared by the port, connection and listener watchers
    let mut tables = sources::net::Tables::new("/proc");
    if !cfg.net_ports.is_empty() {
        log(&format!(
            "watching {} ecosystem port(s) for non-loopback exposure (poll every {})",
            cfg.net_ports.len(),
            crate::gotext::duration(cfg.net_poll_interval())
        ));
        tables.ports(sources::net::PortWatcher::new(&cfg.net_ports), secs(cfg.net_poll_interval()));
    }
    let mut origins = crate::ipintel::Resolver::new(&cfg.ip_databases);
    if origins.available() {
        log("naming where remote addresses belong from the offline IP database");
    } else {
        log("no IP database yet: remote addresses show no origin (heimdall-intel-update fetches one)");
    }
    let mut threats = crate::ipintel::Lists::new(&cfg.threat_list_dir);
    match threats.count() {
        (0, _) => log("no threat lists yet (heimdall-intel-update fetches them)"),
        (n, e) => log(&format!("checking connections against {n} threat list(s), {e} entries")),
    }
    if cfg.conn_watch {
        log(&format!("logging connections per process (poll every {})", crate::gotext::duration(cfg.conn_poll_interval())));
        let mut cw = sources::net::ConnWatcher::new("/proc", &cfg.conn_state_path, &cfg.app_network_policy);
        cw.origins = Some(origins);
        cw.threats = Some(threats);
        cw.remote_access = Some(crate::remoteaccess::Identifier::new(crate::remoteaccess::Catalog::builtin()));
        tables.connections(cw, secs(cfg.conn_poll_interval()));
    }
    if !cfg.wifi_results.is_empty() {
        srcs.push(Box::new(sources::files::LinesSource::wifi(&cfg.wifi_results)));
        let dir = std::path::Path::new(&cfg.wifi_results).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        srcs.push(Box::new(sources::files::RouterSource::new(&format!("{dir}/current.json"), "/proc")));
    }
    if !cfg.lan_dir.is_empty() {
        srcs.push(Box::new(sources::files::LinesSource::lan(&cfg.lan_dir)));
    }
    if cfg.listen_watch {
        tables.listeners(sources::net::ListenWatcher::new("/proc"), Duration::from_secs(15));
        let ra = crate::remoteaccess::Catalog::builtin();
        log(&format!(
            "watching for {} remote-access tools (installed packages and tunnel interfaces every 15s, connections by program)",
            ra.providers.len()
        ));
        srcs.push(Box::new(sources::files::RaSource::new(ra, &cfg.pacman_db, "/sys/class/net")));
    }
    if !tables.is_empty() {
        srcs.push(Box::new(tables));
    }
    if cfg.firewall {
        log(&format!(
            "following the firewall and SSH logins in the journal (journalctl started again {} after it ends)",
            crate::gotext::duration(cfg.firewall_poll_interval())
        ));
        let parser = sources::journal::Parser {
            origins: Some(crate::ipintel::Resolver::new(&cfg.ip_databases)),
            threats: Some(crate::ipintel::Lists::new(&cfg.threat_list_dir)),
        };
        let restart = Duration::from_nanos(cfg.firewall_poll_interval() as u64);
        let mut j = sources::journal::JournalSource::new(&cfg.firewall_cursor_path, parser, restart);
        if let Ok(p) = std::env::var("HEIMDALL_JOURNALCTL") {
            j = j.with_program(&p); // the harness's made-up journal
        }
        srcs.push(Box::new(j));
    }
    if !cfg.security_tracker.is_empty() || !cfg.kernel_vulns.is_empty() || !cfg.hardening_state_path.is_empty() {
        log("not ported yet, so not run here (the Go daemon still does): the package, kernel and hardening audits");
    }

    let session_dir = cfg.agent_session_dir.clone();
    let quiet_missing_dir = !sarina_installed(&cfg);
    let dispatch = |eng: &mut Engine, msgs: Vec<Msg>| {
        for m in msgs {
            match m {
                Msg::Event(e) | Msg::LimboEvent(e) => eng.handle(&e),
                Msg::Log(l) => log(&l),
                Msg::Issue(i) => {
                    // no session folder because Sarina is not installed: nothing is wrong, nothing to read yet
                    if quiet_missing_dir
                        && i.code == sources::agent::CODE_UNREADABLE
                        && i.path == session_dir
                        && !std::path::Path::new(&session_dir).exists()
                    {
                        continue;
                    }
                    log(&format!("poll error: {i}"));
                    let a = Alert::integration(
                        &i.code,
                        &format!("{}: {}", i.path, i.detail),
                        &i.remedy,
                        &Fields::from([("path".to_string(), i.path.clone())]),
                    );
                    eng.write_alert(&a);
                }
            }
        }
    };

    // the first trim right after the first looks (the state files read, thousands of sessions looked at)
    let mut trimmed = Instant::now().checked_sub(Duration::from_secs(61)).unwrap_or_else(Instant::now);
    loop {
        let now = Instant::now();
        for s in srcs.iter_mut() {
            if s.due().is_some_and(|d| d <= now) {
                let mut out = Vec::new();
                s.run(now, &mut out);
                dispatch(&mut eng, out);
            }
        }
        // a full look at thousands of sessions leaves freed heap behind; hand it back to the kernel now and then, so the
        // resident size stays what the daemon uses (cheap: a walk of a small heap, at most once a minute)
        if now.duration_since(trimmed) >= Duration::from_secs(60) {
            // SAFETY: malloc_trim only releases free memory at the top of glibc's heaps.
            unsafe { libc::malloc_trim(0) };
            trimmed = now;
        }
        let now = Instant::now();
        let wait = srcs.iter().filter_map(|s| s.due()).min().map_or(Duration::from_secs(3600), |d| d.saturating_duration_since(now));
        let ready: Vec<usize>;
        let stop: bool;
        {
            let mut fds: Vec<rustix::event::PollFd<'_>> = vec![rustix::event::PollFd::new(&sig, rustix::event::PollFlags::IN)];
            let mut owner: Vec<usize> = Vec::new();
            for (i, s) in srcs.iter().enumerate() {
                if let Some(fd) = s.fd() {
                    fds.push(rustix::event::PollFd::from_borrowed_fd(fd, rustix::event::PollFlags::IN));
                    owner.push(i);
                }
            }
            let ts = rustix::event::Timespec {
                tv_sec: wait.as_secs().min(3600) as i64,
                tv_nsec: if wait.as_secs() >= 3600 { 0 } else { wait.subsec_nanos() as i64 },
            };
            match rustix::event::poll(&mut fds, Some(&ts)) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(e) => {
                    log(&format!("poll: {e}"));
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            stop = !fds[0].revents().is_empty();
            ready = fds[1..].iter().zip(&owner).filter(|(f, _)| !f.revents().is_empty()).map(|(_, i)| *i).collect();
        }
        if stop {
            break;
        }
        let now = Instant::now();
        for i in ready {
            let mut out = Vec::new();
            srcs[i].ready(now, &mut out);
            dispatch(&mut eng, out);
        }
    }
    log("shutting down");
    for s in srcs.iter_mut() {
        let mut out = Vec::new();
        s.stop(&mut out);
        dispatch(&mut eng, out);
    }
    drop(ring);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shadow_config_never_shares_a_file_with_the_go_daemon() {
        // the Go defaults point into /var/lib/heimdall/: refused, each named
        let bad = check_shadow(&Config::default()).unwrap_err();
        assert!(bad.iter().any(|b| b.starts_with("agent_state_path")), "{bad:?}");
        for (_, p) in written_paths(&Config::default()) {
            assert!(p.is_empty() || p.starts_with(GO_STATE_DIR), "{p}");
        }
        let c = Config {
            agent_state_path: "/var/lib/heimdall-rs/agent-sessions.json".into(),
            vault_state_path: "/var/lib/heimdall-rs/vault-notes.json".into(),
            agent_baseline_state_path: String::new(),
            conn_state_path: String::new(),
            firewall_cursor_path: String::new(),
            package_audit_state_path: String::new(),
            kernel_audit_state_path: String::new(),
            hardening_state_path: String::new(),
            ..Config::default()
        };
        assert!(check_shadow(&c).is_ok());
        assert_eq!(run(Config::default(), false), 2, "not without --shadow");
    }
}
