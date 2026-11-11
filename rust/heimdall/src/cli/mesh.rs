//! `heimdalld mesh id|init|list|enroll|forget` (Go: cmd/heimdalld/mesh.go, internal/mesh): this computer's mesh key and
//! fingerprint, and the owner's list of enrolled peers. The files are Go's (key.pem in PKCS#8, the fingerprint file, the peers
//! file as Go's MarshalIndent writes it), so a Go and a Rust heimdalld read each other's.

use super::goflag::FlagSet;
use crate::detect::Peer;
use crate::mesh;

const USAGE: &str = "usage:
  heimdalld mesh id [--dir D]                         this computer's mesh fingerprint (give it to your other computers)
  sudo heimdalld mesh init [--dir D]                  make this computer's mesh key (once)
  heimdalld mesh list [--peers F]                     the enrolled peers
  sudo heimdalld mesh enroll NAME FINGERPRINT IP:PORT [--peers F]
                                                      trust another of your computers (compare the fingerprint on its screen)
  sudo heimdalld mesh forget NAME [--peers F]         stop trusting it (at once for new connections)
Off until mesh_listen is set in config.json or a peer is enrolled. See docs/MESH.md.";

const DEFAULT_DIR: &str = "/var/lib/heimdall/mesh";

fn usage() -> i32 {
    eprintln!("{USAGE}");
    2
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Go's `flagsFirst`: "--name value" and "--name=value" moved ahead of the other words, so `enroll A B C --peers F` works as
/// well as `enroll --peers F A B C` (a word starting with "-" takes the next word as its value unless it holds "=").
pub fn flags_first(args: &[String]) -> Vec<String> {
    let (mut flags, mut pos) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') && a.len() > 1 {
            flags.push(a.clone());
            if !a.contains('=') && i + 1 < args.len() {
                flags.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            pos.push(a.clone());
        }
        i += 1;
    }
    flags.extend(pos);
    flags
}

pub fn main(args: &[String]) -> Option<i32> {
    Some(run(args))
}

fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        return usage();
    }
    let action = args[0].as_str();
    let mut fs = FlagSet::new("mesh");
    fs.string("dir", DEFAULT_DIR, "the key's folder");
    fs.string("peers", mesh::DEFAULT_PEERS, "the enrolled peers file");
    if fs.parse(&flags_first(&args[1..])).is_err() {
        return 2;
    }
    let (dir, peers) = (fs.get_str("dir"), fs.get_str("peers"));
    match action {
        "id" => match std::fs::read(crate::gopath::join(&[&dir, "fingerprint"])) {
            Ok(b) => {
                use std::io::Write;
                let _ = std::io::stdout().write_all(&b);
                0
            }
            Err(_) => {
                eprintln!("no mesh key yet: sudo heimdalld mesh init");
                1
            }
        },
        "init" => {
            if dir == DEFAULT_DIR && euid() != 0 {
                eprintln!("heimdalld mesh init: needs root (sudo)");
                return 1;
            }
            let id = match mesh::load_or_create(&dir) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("heimdalld mesh: {e}");
                    return 1;
                }
            };
            if euid() == 0 {
                // the daemon's account reads the key
                if let Some((uid, gid)) = account("heimdall") {
                    for p in [dir.clone(), crate::gopath::join(&[&dir, "key.pem"]), crate::gopath::join(&[&dir, "fingerprint"])] {
                        let _ = std::os::unix::fs::lchown(&p, Some(uid), Some(gid));
                    }
                }
            }
            println!("{}", id.fingerprint);
            0
        }
        "list" => {
            let ps = match mesh::load_peers_go(&peers) {
                Ok(ps) => ps,
                Err(e) => {
                    eprintln!("heimdalld mesh: {e}");
                    return 1;
                }
            };
            if ps.is_empty() {
                println!("no peers enrolled");
            }
            for p in ps {
                println!("{:<16} {}  {}", p.name, p.fingerprint, p.address);
            }
            0
        }
        "enroll" | "forget" => {
            if (action == "enroll" && fs.narg() != 3) || (action == "forget" && fs.narg() != 1) {
                return usage();
            }
            // whom Heimdall trusts is the owner's decision: root at a terminal for the real list, and never under an AI agent
            let guarded = if peers == mesh::DEFAULT_PEERS {
                if euid() != 0 {
                    eprintln!("heimdalld mesh: enrolling needs root (sudo)");
                    return 1;
                }
                guard("/proc", stdin_is_terminal())
            } else {
                guard("/proc", true)
            };
            if let Err(e) = guarded {
                eprintln!("heimdalld mesh: refused: {e}");
                return 1;
            }
            let a = fs.args();
            let mut p = Peer { name: a[0].clone(), ..Default::default() };
            if action == "enroll" {
                p.fingerprint = crate::gotext::to_lower(&a[1]);
                p.address = a[2].clone();
            }
            match mesh::set_peer(&peers, &p, action == "forget") {
                Ok(ps) => {
                    println!(
                        "{} peer(s) enrolled. Restart Heimdall to start sending to a new peer (sudo systemctl restart heimdall).",
                        ps.len()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("heimdalld mesh: {e}");
                    1
                }
            }
        }
        _ => usage(),
    }
}

/// A user's uid and gid from the user database (Go: os/user.Lookup), None when there is no such user.
fn account(name: &str) -> Option<(u32, u32)> {
    let c = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16384];
    // SAFETY: getpwnam_r writes only into pwd and buf (whose size is given) and sets result to &pwd or null.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    unsafe { libc::getpwnam_r(c.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    (!result.is_null()).then_some((pwd.pw_uid, pwd.pw_gid))
}

/// Whether standard input is a terminal (Go: grants.StdinIsTerminal, TCGETS).
pub fn stdin_is_terminal() -> bool {
    // SAFETY: isatty only asks the kernel about descriptor 0.
    unsafe { libc::isatty(0) == 1 }
}

/// The programs and accounts that may never decide a request (Go: grants.AgentPrograms, AgentAccounts).
const AGENT_PROGRAMS: &[&str] = &["sarina", "sarina-service"];
const AGENT_ACCOUNTS: &[&str] = &["sarina"];

/// Go's `grants.Guard`: Ok when the calling process may decide (a terminal on standard input, sudo not used by an agent
/// account, no agent program or agent account among its ancestors), else why not, in Go's words. The owner's sudo password
/// stays the main barrier; this names an agent that got past it.
pub fn guard(proc_root: &str, terminal: bool) -> Result<(), String> {
    if !terminal {
        return Err("a decision is made by a person at a terminal (standard input is not one)".into());
    }
    let sudo_user = std::env::var("SUDO_USER").unwrap_or_default();
    for a in AGENT_ACCOUNTS {
        if sudo_user == *a {
            return Err(format!("the account {a} asked through sudo: an agent never decides its own requests"));
        }
    }
    let agent_uids: Vec<String> = AGENT_ACCOUNTS.iter().filter_map(|a| account(a)).map(|(u, _)| u.to_string()).collect();
    let mut pid = std::process::id() as i64;
    let mut i = 0;
    while i < 64 && pid > 1 {
        let (ppid, uids) = proc_status(proc_root, pid).map_err(|e| format!("cannot check who started this command ({e}); refusing"))?;
        if uids.iter().any(|u| agent_uids.contains(u)) {
            return Err(format!("process {pid} runs as an agent account: an agent never decides its own requests"));
        }
        let name = program(proc_root, pid);
        if !name.is_empty() && AGENT_PROGRAMS.contains(&name.as_str()) {
            return Err(format!("this command was started (through process {pid}) by {name}: an agent never decides its own requests"));
        }
        pid = ppid;
        i += 1;
    }
    Ok(())
}

/// A process's parent and its user ids (real, effective, saved, filesystem), from its status file.
fn proc_status(proc_root: &str, pid: i64) -> Result<(i64, Vec<String>), String> {
    let path = crate::gopath::join(&[proc_root, &pid.to_string(), "status"]);
    let b = std::fs::read(&path).map_err(|e| crate::gopath::read_err(&path, &e))?;
    let text = crate::gotext::lossy(&b);
    let (mut ppid, mut uids) = (-1i64, Vec::new());
    for line in text.split('\n') {
        let Some((k, v)) = line.split_once(':') else { continue };
        match k {
            "PPid" => ppid = crate::gotext::atoi(crate::gotext::trim_space(v)).unwrap_or(0),
            "Uid" => uids = crate::gotext::fields(v).map(str::to_string).collect(),
            _ => {}
        }
    }
    if ppid < 0 {
        return Err(format!("no parent in {path}"));
    }
    Ok((ppid, uids))
}

/// The base name of a process's executable when it is an agent program, else of its first argument (an interpreter running
/// a script named sarina shows the script there); "" when neither can be read.
fn program(proc_root: &str, pid: i64) -> String {
    let dir = crate::gopath::join(&[proc_root, &pid.to_string()]);
    if let Ok(exe) = std::fs::read_link(format!("{dir}/exe")) {
        let exe = exe.to_string_lossy();
        let base = crate::gopath::base(exe.strip_suffix(" (deleted)").unwrap_or(&exe));
        if AGENT_PROGRAMS.contains(&base.as_str()) {
            return base;
        }
    }
    if let Ok(cmd) = std::fs::read(format!("{dir}/cmdline")) {
        let first = cmd.split(|&c| c == 0).next().unwrap_or(&[]);
        return crate::gopath::base(&crate::gotext::lossy(first));
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_first_as_go() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(flags_first(&v(&["a", "b", "--peers", "f", "c"])), v(&["--peers", "f", "a", "b", "c"]));
        assert_eq!(flags_first(&v(&["--peers=f", "a"])), v(&["--peers=f", "a"]));
        assert_eq!(flags_first(&v(&["a", "-x"])), v(&["-x", "a"]));
        assert_eq!(flags_first(&v(&["-", "a"])), v(&["-", "a"]));
    }

    #[test]
    fn the_guard_wants_a_terminal() {
        assert_eq!(guard("/proc", false), Err("a decision is made by a person at a terminal (standard input is not one)".into()));
        assert!(guard("/nonexistent", true).unwrap_err().starts_with("cannot check who started this command (open /nonexistent/"));
    }
}
