//! What containment does to the computer (Go: internal/contain: the Runner in contain.go, Real in system.go, the evidence in
//! evidence.go): the lock, the evidence saved before anything is stopped, Sarina stopped, the models unloaded, the check a
//! minute later, and the emergency step. The same calls to systemctl, fuser, nvidia-smi and the model server, the same files.

use crate::cli::immunity::store::{self, Store};
use crate::gojson;
use crate::gotime::Time;
use std::collections::BTreeMap;
use std::io::{Read, Write};

/// The model server (Go: Real.Ollama's default).
const OLLAMA: &str = "127.0.0.1:11434";

fn quiet(cmd: &str, args: &[&str]) -> Option<std::process::Output> {
    std::process::Command::new(cmd).args(args).stdin(std::process::Stdio::null()).output().ok()
}

/// One HTTP request to the model server; Go's url.Error text when it does not answer.
fn http(method: &str, path: &str, body: Option<&str>, timeout: u64) -> Result<Vec<u8>, String> {
    let verb = format!("{}{}", &method[..1], method[1..].to_ascii_lowercase());
    let url = format!("http://{OLLAMA}{path}");
    let addr: std::net::SocketAddr = OLLAMA.parse().unwrap();
    let mut s = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(timeout))
        .map_err(|e| format!("{verb} \"{url}\": dial tcp {OLLAMA}: connect: {}", crate::goerr::text(&e)))?;
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(timeout)));
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {OLLAMA}\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n");
    match body {
        Some(b) => req.push_str(&format!("Content-Length: {}\r\nContent-Type: application/json\r\n\r\n{b}", b.len())),
        None => req.push_str("\r\n"),
    }
    s.write_all(req.as_bytes()).map_err(|e| format!("{verb} \"{url}\": {}", crate::goerr::text(&e)))?;
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    crate::response::parse_reply(&raw, 1 << 20).map(|r| r.body).ok_or_else(|| format!("{verb} \"{url}\": malformed HTTP response"))
}

/// Go's `ModelsLoaded`: the model server's loaded models (None when it does not answer).
fn models_loaded() -> Option<Vec<String>> {
    let b = http("GET", "/api/ps", None, 5).ok()?;
    let v = gojson::parse_first(&b).ok()?;
    let m = gojson::struct_members(&v, &["models"], "").ok()??;
    let mut names = Vec::new();
    for (_, models) in m {
        names.clear();
        match models {
            gojson::Value::Array(a) => {
                for x in a {
                    let mut n = String::new();
                    if let Some(mm) = gojson::struct_members(x, &["name"], "").ok()? {
                        for (_, y) in mm {
                            match y {
                                gojson::Value::String(s) => n = s.clone(),
                                gojson::Value::Null => {}
                                _ => return None,
                            }
                        }
                    }
                    names.push(n);
                }
            }
            gojson::Value::Null => {}
            _ => return None,
        }
    }
    (!names.is_empty()).then_some(names)
}

/// Go's `sarinaProcs`: the processes named sarina or sarina-*, by command or program.
fn sarina_procs() -> BTreeMap<i32, String> {
    let mut out = BTreeMap::new();
    let me = std::process::id() as i32;
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(crate::gotext::atoi) else { continue };
        let pid = pid as i32;
        if pid == me {
            continue;
        }
        let comm = std::fs::read(format!("/proc/{pid}/comm")).unwrap_or_default();
        let name = crate::gotext::trim_space(&crate::gotext::lossy(&comm)).to_string();
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let base = crate::gopath::base(exe.strip_suffix(" (deleted)").unwrap_or(&exe));
        if name == "sarina" || name.starts_with("sarina-") || base == "sarina" || base.starts_with("sarina-") {
            out.insert(pid, name);
        }
    }
    out
}

fn list(v: &[String]) -> String {
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}

pub struct Runner {
    pub marker: String,
    pub sessions: Vec<String>,
    pub log: fn(&str),
    collected: bool,
}

impl Runner {
    pub fn new(marker: String, sessions: Vec<String>, log: fn(&str)) -> Runner {
        Runner { marker, sessions, log, collected: false }
    }

    fn write_marker(&self, reason: &str, level: &str) -> Result<(), String> {
        let mut b = String::from("{\n  \"since\": \"");
        b.push_str(&Time::now().utc().truncate(1_000_000_000).rfc3339_nano());
        b.push_str("\",\n  \"reason\": ");
        gojson::write_str(&mut b, reason);
        b.push_str(",\n  \"level\": ");
        gojson::write_str(&mut b, level);
        b.push_str("\n}\n");
        let tmp = format!("{}.tmp", self.marker);
        crate::gopath::write_file(&tmp, b.as_bytes(), 0o644)?;
        crate::gopath::rename(&tmp, &self.marker)
    }

    fn save_evidence(&mut self, reason: &str) {
        if self.collected {
            return;
        }
        self.collected = true;
        match collect(reason, &self.sessions) {
            Ok(dir) => (self.log)(&format!("evidence saved in {dir}")),
            Err(e) => (self.log)(&format!("evidence could not be saved: {e}")),
        }
    }

    fn stop_sarina() -> Vec<String> {
        let _ = quiet("systemctl", &["stop", "sarina-service.service"]);
        let _ = quiet("systemctl", &["stop", "sarina-*.timer", "sarina-*.service"]);
        stop_limbo_agent_runs();
        let mut out: Vec<String> = sarina_procs()
            .into_iter()
            .filter(|(pid, _)| {
                rustix::process::kill_process(rustix::process::Pid::from_raw(*pid).unwrap(), rustix::process::Signal::KILL).is_ok()
            })
            .map(|(pid, name)| format!("{name} ({pid})"))
            .collect();
        out.sort();
        out
    }

    fn unload_models() -> (Vec<String>, Option<String>) {
        let names = models_loaded().unwrap_or_default();
        let mut errs = Vec::new();
        for n in &names {
            let mut body = String::from("{\"keep_alive\":0,\"model\":");
            gojson::write_str(&mut body, n);
            body.push('}');
            if let Err(e) = http("POST", "/api/generate", Some(&body), 30) {
                errs.push(e);
            }
        }
        (names, (!errs.is_empty()).then(|| errs.join("; ")))
    }

    /// Go's `Contain`.
    pub fn contain(&mut self, reason: &str) -> Result<(), String> {
        self.write_marker(reason, "contained").map_err(|e| format!("the lock could not be written: {e}"))?;
        self.save_evidence(reason);
        let stopped = Self::stop_sarina();
        (self.log)(&format!("stopped Sarina: {}", list(&stopped)));
        match Self::unload_models() {
            (_, Some(e)) => (self.log)(&format!("unloading the models: {e}")),
            (m, None) => (self.log)(&format!("unloaded from the graphics card: {}", list(&m))),
        }
        crate::cli::immunity::notify(&format!(
            "Heimdall contained Sarina: {reason}. She stays stopped until you release her (Settings > Security, or: sudo heimdalld contain release)."
        ));
        Ok(())
    }

    /// Go's `Verify`.
    fn verify() -> Vec<String> {
        let mut running: Vec<String> = sarina_procs().into_iter().map(|(pid, name)| format!("{name} ({pid})")).collect();
        running.sort();
        let mut left: Vec<String> = running.into_iter().map(|p| format!("Sarina process still running: {p}")).collect();
        for m in models_loaded().unwrap_or_default() {
            left.push(format!("a model is loaded again: {m}"));
        }
        left
    }

    /// Go's `Emergency`.
    pub fn emergency(&mut self, reason: &str) -> Result<(), String> {
        let mut errs = Vec::new();
        if let Err(e) = self.write_marker(reason, "emergency") {
            errs.push(format!("lock: {e}"));
        }
        self.save_evidence(reason);
        match restore_approved() {
            Err(e) => errs.push(format!("restore: {e}")),
            Ok(back) => (self.log)(&format!("approved files put back: {}", list(&back))),
        }
        crate::cli::immunity::notify(&format!(
            "Heimdall emergency: {reason}. Stopping everything that uses the graphics card, clearing it, and restarting."
        ));
        let mut stop_errs = Vec::new();
        for u in ["display-manager.service", "ollama.service"] {
            if let Some(o) = quiet("systemctl", &["stop", u]) {
                if !o.status.success() {
                    let mut both = o.stdout.clone();
                    both.extend_from_slice(&o.stderr);
                    stop_errs.push(format!("{u}: {}", crate::gotext::trim_space(&crate::gotext::lossy(&both))));
                }
            } else {
                stop_errs.push(format!("{u}: "));
            }
        }
        if !stop_errs.is_empty() {
            errs.push(format!("stopping the desktop and the model server: {}", stop_errs.join("; ")));
        }
        Self::stop_sarina();
        let killed = kill_graphics_users();
        (self.log)(&format!("killed on the graphics card: {}", list(&killed)));
        match reset_graphics() {
            Err(e) => errs.push(format!("graphics reset: {e} (the restart clears it)")),
            Ok(()) => (self.log)("graphics card reset: its memory is cleared"),
        }
        match quiet("systemctl", &["reboot"]) {
            Some(o) if o.status.success() => {}
            Some(o) => errs.push(format!("restart: {}", exit_text(&o.status))),
            None => errs.push("restart: exec: \"systemctl\": executable file not found in $PATH".into()),
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }

    /// Go's `Run`: contain, wait a minute, check; the emergency step only where allowed.
    pub fn run(&mut self, reason: &str, auto: bool, auto_emergency: bool, emergency_allowed: bool) -> Result<(), String> {
        self.contain(reason)?;
        std::thread::sleep(std::time::Duration::from_secs(60));
        let left = Self::verify();
        if left.is_empty() {
            (self.log)("containment held");
            return Ok(());
        }
        (self.log)(&format!("containment did not hold: {}", left.join("; ")));
        if auto && !auto_emergency || !auto && !emergency_allowed {
            crate::cli::immunity::notify(&format!(
                "Heimdall could not fully contain the AI ({}). The emergency step (clear the graphics card and restart) is yours to start: sudo heimdalld contain emergency --yes",
                left.join("; ")
            ));
            return Err(format!("containment did not hold: {}", left.join("; ")));
        }
        self.emergency(&format!("{reason}; containment did not hold: {}", left.join("; ")))
    }
}

/// Go's `exec.ExitError` text.
fn exit_text(s: &std::process::ExitStatus) -> String {
    match s.code() {
        Some(c) => format!("exit status {c}"),
        None => "signal: killed".into(),
    }
}

/// Go's `stopLimboAgentRuns`: asks Limbo to end every run Sarina's agents started (nothing without Limbo).
fn stop_limbo_agent_runs() {
    let sock = "/run/limbo/admin.sock";
    if std::fs::metadata(sock).is_err() {
        return;
    }
    if let Ok(mut s) = std::os::unix::net::UnixStream::connect(sock) {
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let _ = s.write_all(
            b"POST /v1/agent-runs/stop HTTP/1.1\r\nHost: limbo\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}",
        );
        let mut sink = Vec::new();
        let _ = s.read_to_end(&mut sink);
    }
}

/// Go's `RestoreApproved`: the behaviour files put back from the signed list.
fn restore_approved() -> Result<Vec<String>, String> {
    let ts = crate::trust::Store::new(crate::trust::DEFAULT_DIR);
    if let Err(e) = ts.load() {
        return Err(format!("no signed list to restore from ({e})"));
    }
    let (back, err) = ts.restore(&[]);
    match err {
        Some(e) => Err(e),
        None => Ok(back.into_iter().map(|r| r.path).collect()),
    }
}

/// Go's `KillGraphicsUsers`: fuser -k on the graphics devices.
fn kill_graphics_users() -> Vec<String> {
    let mut devs: Vec<String> = Vec::new();
    for pat in ["/dev/nvidia*", "/dev/dri/*"] {
        devs.extend(store::glob(pat).into_iter().map(|d| crate::gotext::lossy(&d)));
    }
    if devs.is_empty() {
        return Vec::new();
    }
    let mut args = vec!["-k".to_string(), "-KILL".to_string()];
    args.extend(devs);
    let out = std::process::Command::new("fuser").args(&args).stdin(std::process::Stdio::null()).output();
    match out {
        Ok(o) => {
            let mut both = o.stdout.clone();
            both.extend_from_slice(&o.stderr);
            crate::gotext::fields(&crate::gotext::lossy(&both)).map(String::from).collect()
        }
        Err(_) => Vec::new(),
    }
}

/// Go's `ResetGraphics`.
fn reset_graphics() -> Result<(), String> {
    if crate::cli::immunity::scan::look_path("nvidia-smi").is_none() {
        return Err("no NVIDIA tools; the restart clears the card".into());
    }
    std::thread::sleep(std::time::Duration::from_secs(2));
    match std::process::Command::new("nvidia-smi").arg("--gpu-reset").stdin(std::process::Stdio::null()).output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let mut both = o.stdout.clone();
            both.extend_from_slice(&o.stderr);
            Err(crate::gotext::trim_space(&crate::gotext::lossy(&both)).to_string())
        }
        Err(e) => Err(crate::goerr::text(&e)),
    }
}

// ---- the evidence (Go: evidence.go)

const EVIDENCE_DIR: &str = "/var/lib/heimdall-evidence";
const MAX_COPY: usize = 4 << 20;
const MAX_TOTAL: usize = 256 << 20;

struct Evidence {
    dir: String,
    total: usize,
    notes: Vec<String>,
}

impl Evidence {
    fn write(&mut self, name: &str, b: &[u8]) {
        if self.total + b.len() > MAX_TOTAL {
            self.notes.push(format!("{name}: skipped (the size cap was reached)"));
            return;
        }
        let p = crate::gopath::join(&[&self.dir, name]);
        let _ = crate::gopath::mkdir_all(&crate::gopath::dir(&p), 0o700);
        if let Err(e) = crate::gopath::write_file(&p, b, 0o600) {
            self.notes.push(format!("{name}: {e}"));
            return;
        }
        self.total += b.len();
    }
    fn command(&mut self, name: &str, args: &[&str]) {
        match std::process::Command::new(args[0]).args(&args[1..]).stdin(std::process::Stdio::null()).output() {
            Err(_) => self.notes.push(format!("{name}: exec: \"{}\": executable file not found in $PATH", args[0])),
            Ok(o) => {
                let mut out = o.stdout.clone();
                out.extend_from_slice(&o.stderr);
                if !o.status.success() && out.is_empty() {
                    self.notes.push(format!("{name}: {}", exit_text(&o.status)));
                    return;
                }
                out.truncate(MAX_COPY);
                self.write(name, &out);
            }
        }
    }
    fn copy_file(&mut self, path: &str, index: &mut BTreeMap<String, String>) {
        let Ok(f) = std::fs::File::open(path) else { return };
        let mut b = Vec::new();
        if f.take(MAX_COPY as u64 + 1).read_to_end(&mut b).is_err() {
            return;
        }
        let mut sum = store::hex_sha(&b);
        if b.len() > MAX_COPY {
            sum.push_str(" (larger than 4 MiB: only the first 4 MiB kept)");
            b.truncate(MAX_COPY);
        }
        index.insert(path.to_string(), sum);
        self.write(&crate::gopath::join(&["files", path.trim_start_matches('/')]), &b);
    }
}

fn strs_json(v: &[String], nil: bool) -> String {
    if nil {
        return "null\n".into();
    }
    let mut out = String::from("[");
    for (i, s) in v.iter().enumerate() {
        out.push_str(if i == 0 { "\n  " } else { ",\n  " });
        gojson::write_str(&mut out, s);
    }
    out.push_str(if v.is_empty() { "]\n" } else { "\n]\n" });
    out
}

#[derive(Clone, Default)]
struct Proc {
    pid: i32,
    ppid: i64,
    uid: String,
    comm: String,
    exe: String,
    hash: String,
    cmdline: String,
    cwd: String,
    started: String,
}

fn read_proc(pid: i32, hash: bool) -> Option<Proc> {
    let base = format!("/proc/{pid}");
    let stat = crate::gotext::lossy(&std::fs::read(format!("{base}/stat")).ok()?);
    let mut p = Proc { pid, ..Default::default() };
    if let Some(i) = stat.rfind(')').filter(|&i| i > 0) {
        let f: Vec<&str> = crate::gotext::fields(&stat[i + 1..]).collect();
        if f.len() > 19 {
            p.ppid = crate::gotext::atoi(f[1]).unwrap_or(0);
            p.started = f[19].to_string();
        }
    }
    p.comm = crate::gotext::trim_space(&crate::gotext::lossy(&std::fs::read(format!("{base}/comm")).unwrap_or_default())).to_string();
    let link = |n: &str| {
        std::fs::read_link(format!("{base}/{n}")).map(|x| crate::gotext::lossy(x.as_os_str().as_encoded_bytes())).unwrap_or_default()
    };
    p.exe = link("exe");
    p.cwd = link("cwd");
    let cl = std::fs::read(format!("{base}/cmdline")).unwrap_or_default();
    p.cmdline = crate::gotext::trim_space(&crate::gotext::lossy(&cl).replace('\0', " ")).to_string();
    if let Ok(st) = std::fs::read(format!("{base}/status")) {
        for l in crate::gotext::lossy(&st).split('\n') {
            if l.starts_with("Uid:") {
                if let Some(u) = crate::gotext::fields(l).nth(1) {
                    p.uid = u.to_string();
                }
            }
        }
    }
    if hash && !p.exe.is_empty() {
        if let Ok(f) = std::fs::File::open(format!("{base}/exe")) {
            let mut b = Vec::new();
            if f.take(512 << 20).read_to_end(&mut b).is_ok() {
                p.hash = store::hex_sha(&b);
            }
        }
    }
    Some(p)
}

fn procs_json(v: &[Proc]) -> String {
    if v.is_empty() {
        return "null\n".into();
    }
    let mut out = String::from("[");
    for (i, p) in v.iter().enumerate() {
        out.push_str(if i == 0 { "\n  {" } else { ",\n  {" });
        out.push_str(&format!("\n    \"pid\": {},\n    \"ppid\": {},\n    \"uid\": ", p.pid, p.ppid));
        gojson::write_str(&mut out, &p.uid);
        out.push_str(",\n    \"comm\": ");
        gojson::write_str(&mut out, &p.comm);
        out.push_str(",\n    \"exe\": ");
        gojson::write_str(&mut out, &p.exe);
        if !p.hash.is_empty() {
            out.push_str(",\n    \"exe_sha256\": ");
            gojson::write_str(&mut out, &p.hash);
        }
        out.push_str(",\n    \"cmdline\": ");
        gojson::write_str(&mut out, &p.cmdline);
        out.push_str(",\n    \"cwd\": ");
        gojson::write_str(&mut out, &p.cwd);
        out.push_str(",\n    \"start_ticks\": ");
        gojson::write_str(&mut out, &p.started);
        out.push_str("\n  }");
    }
    out.push_str("\n]\n");
    out
}

fn redact_env(env: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for kv in crate::gotext::lossy(env).split('\0') {
        if kv.is_empty() {
            continue;
        }
        let k = kv.split('=').next().unwrap_or("");
        let u = k.to_uppercase();
        if ["TOKEN", "KEY", "SECRET", "PASS"].iter().any(|w| u.contains(w)) {
            out.push(format!("{k}=[hidden]"));
        } else {
            out.push(kv.to_string());
        }
    }
    format!("{}\n", out.join("\n")).into_bytes()
}

/// Go's `Real.Collect`: the evidence folder, saved before anything is stopped.
fn collect(reason: &str, sessions: &[String]) -> Result<String, String> {
    crate::gopath::mkdir_all(EVIDENCE_DIR, 0o700)?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(EVIDENCE_DIR, std::fs::Permissions::from_mode(0o700));
    let now = Time::now();
    let dir = crate::gopath::join(&[EVIDENCE_DIR, &now.utc().format("20060102T150405Z")]);
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| crate::goerr::path("mkdir", &dir, &e))?;
    }
    let mut e = Evidence { dir: dir.clone(), total: 0, notes: Vec::new() };
    let mut r = String::from("{\n  \"reason\": ");
    gojson::write_str(&mut r, reason);
    r.push_str(",\n  \"time\": \"");
    r.push_str(&Time::now().rfc3339_nano());
    r.push_str("\"\n}\n");
    e.write("reason.json", r.as_bytes());
    let hers_pids = sarina_procs();
    let mut all = Vec::new();
    let mut hers = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for ent in rd.flatten() {
            let Some(pid) = ent.file_name().to_str().and_then(crate::gotext::atoi) else { continue };
            let is_hers = hers_pids.contains_key(&(pid as i32));
            if let Some(p) = read_proc(pid as i32, is_hers) {
                if is_hers {
                    hers.push(p.clone());
                }
                all.push(p);
            }
        }
    }
    all.sort_by_key(|p| p.pid);
    e.write("processes.json", procs_json(&all).as_bytes());
    e.write("sarina-processes.json", procs_json(&hers).as_bytes());
    for p in &hers {
        let base = format!("/proc/{}", p.pid);
        let maps = std::fs::read(format!("{base}/maps")).unwrap_or_default();
        e.write(&format!("sarina-{}/maps", p.pid), &maps);
        let env = std::fs::read(format!("{base}/environ")).unwrap_or_default();
        e.write(&format!("sarina-{}/environ", p.pid), &redact_env(&env));
        if let Ok(rd) = std::fs::read_dir(format!("{base}/fd")) {
            let mut names: Vec<String> = rd.flatten().map(|x| x.file_name().to_string_lossy().into_owned()).collect();
            names.sort();
            let open: Vec<String> = names
                .iter()
                .filter_map(|n| std::fs::read_link(format!("{base}/fd/{n}")).ok().map(|t| format!("{n} -> {}", t.to_string_lossy())))
                .collect();
            e.write(&format!("sarina-{}/open-files", p.pid), format!("{}\n", open.join("\n")).as_bytes());
        }
    }
    e.command("connections.txt", &["ss", "-tupanoe"]);
    e.command("graphics.txt", &["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory", "--format=csv"]);
    let models = models_loaded();
    e.write("models-loaded.json", strs_json(models.as_deref().unwrap_or(&[]), models.is_none()).as_bytes());
    e.command("journal.txt", &["journalctl", "--since", "-1h", "--no-pager", "-o", "short-iso", "-n", "20000"]);
    let mut index = BTreeMap::new();
    let mut suspects: Vec<(String, String)> = Vec::new();
    for p in &hers {
        if !p.exe.is_empty() && !p.exe.starts_with("/usr/") {
            suspects.push((format!("/proc/{}/exe", p.pid), p.exe.clone()));
        }
    }
    let ts = crate::trust::Store::new(crate::trust::DEFAULT_DIR);
    if let Ok(m) = ts.load() {
        let hold_them = ts.mode() != "off";
        for f in unapproved(&ts, &m) {
            e.copy_file(&f, &mut index);
            if hold_them {
                suspects.push((f.clone(), f));
            }
        }
    } else {
        e.notes.push("no signed list (heimdalld trust init): her behaviour files could not be compared".into());
    }
    for d in sessions {
        let Ok(rd) = std::fs::read_dir(d) else { continue };
        let mut files: Vec<(String, Time)> = rd
            .flatten()
            .filter_map(|ent| {
                let m = ent.metadata().ok()?;
                m.is_file().then(|| {
                    let mt = crate::safefs::mtime_nanos(&m);
                    (
                        crate::gopath::join(&[d, &ent.file_name().to_string_lossy()]),
                        Time::from_unix(mt.div_euclid(1_000_000_000), mt.rem_euclid(1_000_000_000) as u32),
                    )
                })
            })
            .collect();
        files.sort_by_key(|f| std::cmp::Reverse(f.1));
        for (p, _) in files.iter().take(40) {
            e.copy_file(p, &mut index);
        }
    }
    let mut ix = String::from("{");
    for (i, (k, v)) in index.iter().enumerate() {
        ix.push_str(if i == 0 { "\n  " } else { ",\n  " });
        gojson::write_str(&mut ix, k);
        ix.push_str(": ");
        gojson::write_str(&mut ix, v);
    }
    ix.push_str(if index.is_empty() { "}\n" } else { "\n}\n" });
    e.write("files-index.json", ix.as_bytes());
    let notes = hold_suspects(&suspects, reason);
    e.notes.extend(notes);
    let nil = e.notes.is_empty();
    let n = strs_json(&e.notes.clone(), nil);
    e.write("notes.json", n.as_bytes());
    Ok(dir)
}

/// Go's `trust.Store.Unapproved`: the behaviour files whose content is not the signed one.
fn unapproved(ts: &crate::trust::Store, m: &crate::trust::Manifest) -> Vec<String> {
    let w = ts.watch();
    let mut files: Vec<String> = w.files.clone().unwrap_or_default();
    for d in w.dirs.iter().flatten() {
        let (exp, err) = crate::trust::expand(d);
        if err.is_none() {
            files.extend(exp.iter().map(|b| crate::gotext::lossy(b)));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for f in files {
        if !seen.insert(f.clone()) {
            continue;
        }
        if let Ok(sum) = crate::trust::hash_file(f.as_bytes()) {
            if !m.matches(&f, &sum) {
                out.push(f);
            }
        }
    }
    out.sort();
    out
}

/// Go's `holdSuspects`: each suspicious file held in immunity's store (ClamAV asked), its analysis queued.
fn hold_suspects(paths: &[(String, String)], reason: &str) -> Vec<String> {
    let st = Store::default_store();
    let mut notes = Vec::new();
    for (from, shown) in paths {
        match st.hold(from, shown, &format!("found during a containment: {reason}"), "containment") {
            Err(e) => notes.push(format!("not held: {e}")),
            Ok(en) => {
                if store::s(&en, "status") == store::HELD {
                    let _ = store::queue_analysis(crate::immunity::REQUEST_DIR, &store::s(&en, "sha256"));
                }
                notes.push(format!("held: {shown} ({}, {}) {}", store::s(&en, "kind"), store::s(&en, "status"), store::s(&en, "sha256")));
            }
        }
    }
    notes
}
