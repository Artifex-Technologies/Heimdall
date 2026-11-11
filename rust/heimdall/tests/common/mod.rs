//! Shared by the command tests (`mod common;`): the Go heimdalld of this checkout built once, and fake roots to run both
//! binaries in without touching this computer.
//!
//! A fake root is a folder made to look like a whole system to the command run in it: a user and mount namespace (no
//! privilege needed; root inside is this user outside, other users are the subordinate ids of /etc/subuid), the real /usr/lib
//! and /usr/share read-only, /usr/bin as the real one with fakes laid over it (an overlay: a fake hides the real tool), its
//! own /etc, /var, /run, /tmp and home folders, and the binary under test as /usr/bin/heimdalld. Tools that change the
//! system or the network (systemctl, nmcli, ip, curl, notify-send, clamscan, ...) are always fakes there: each records how it
//! was called in /.fake-calls and fails, unless a test gives it something to do. With `net`, the command also gets a network
//! namespace of its own (only a loopback, down until the setup script brings it up), so nothing reaches the real network.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// The Rust binary under test.
pub fn rust_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_heimdalld-rs"))
}

/// The Go heimdalld of this checkout, built once per test binary at nice 15; None when there is no Go toolchain (the test
/// prints that it skipped).
pub fn go_bin() -> Option<PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(dir).ok()?;
        let tmp = dir.join(format!("heimdalld-go.{}", std::process::id()));
        let st = Command::new(repo().join("rust/scripts/nicego.sh"))
            .args(["build", "-o", tmp.to_str()?, "./cmd/heimdalld"])
            .current_dir(repo())
            .status()
            .ok()?;
        if !st.success() {
            return None;
        }
        let out = dir.join("heimdalld-go");
        std::fs::rename(&tmp, &out).ok()?;
        Some(out)
    })
    .clone()
}

/// The Go binary, or a note that the comparison was skipped.
pub fn go_or_skip(test: &str) -> Option<PathBuf> {
    let g = go_bin();
    if g.is_none() {
        eprintln!("{test}: skipped, no Go toolchain to build the Go heimdalld");
    }
    g
}

/// Tools that are always fakes in a fake root unless a test gives its own (they change the system or the network, or read
/// this computer's state).
pub const ALWAYS_FAKE: &[&str] = &[
    "systemctl",
    "systemd-run",
    "reboot",
    "shutdown",
    "poweroff",
    "kill",
    "pkill",
    "killall",
    "nvidia-smi",
    "modprobe",
    "rmmod",
    "ip",
    "nmcli",
    "iw",
    "nft",
    "ufw",
    "curl",
    "wget",
    "notify-send",
    "clamscan",
    "clamdscan",
    "freshclam",
    "setfacl",
    "chattr",
    "mount",
    "umount",
    "sudo",
    "pkexec",
    "runuser",
    "su",
    "loginctl",
    "journalctl",
    "sarina",
    "limbo",
    "flatpak",
    "pacman",
    "yggdrasil-gametime",
    "ping",
    "ss",
    "tc",
    "dbus-send",
    "busctl",
    "gdbus",
    "fuser",
    "lsof",
    "sysctl",
    "iptables",
    "wg",
    "wg-quick",
    "tailscale",
    "resolvectl",
    "dig",
    "nslookup",
    "host",
    "arping",
    "nmap",
    "zenity",
    "kdialog",
];

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn subids() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        Command::new("unshare")
            .args(["--map-root-user", "--map-users=auto", "--map-groups=auto", "true"])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

fn userns_args() -> Vec<&'static str> {
    if subids() {
        vec!["--map-root-user", "--map-users=auto", "--map-groups=auto"]
    } else {
        vec!["--map-root-user"]
    }
}

/// A fake system.
pub struct Root {
    pub path: PathBuf,
    fakes: PathBuf,
}

/// How a command is run in a root.
#[derive(Clone)]
pub struct Opts {
    /// as root (uid 0); otherwise as uid/gid 1000 ("owner")
    pub root: bool,
    pub env: Vec<(String, String)>,
    pub stdin: Vec<u8>,
    /// a network namespace of its own
    pub net: bool,
    /// a process namespace of its own with its own /proc: the command sees (and can signal) only what runs in it
    pub pid: bool,
    /// shell run inside the namespaces as root before the command (paths outside the root: $R is the root)
    pub setup: String,
    pub timeout: Duration,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            root: true,
            env: Vec::new(),
            stdin: Vec::new(),
            net: false,
            pid: false,
            setup: String::new(),
            timeout: Duration::from_secs(60),
        }
    }
}

impl Opts {
    pub fn user() -> Opts {
        Opts { root: false, ..Opts::default() }
    }
    pub fn env(mut self, k: &str, v: &str) -> Opts {
        self.env.push((k.into(), v.into()));
        self
    }
    pub fn stdin(mut self, b: &[u8]) -> Opts {
        self.stdin = b.to_vec();
        self
    }
}

/// What a command did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Root {
    /// An empty system: its own /etc (users root, heimdall and owner, uid 1000), /var, /run, /tmp, /root and /home/owner.
    pub fn new(tag: &str) -> Root {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("roots");
        let path = base.join(format!("{tag}-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        let fakes = base.join(format!("{tag}-{}-{}.fakes", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&path);
        let _ = std::fs::remove_dir_all(&fakes);
        std::fs::create_dir_all(&fakes).unwrap();
        for d in [
            "etc",
            "var/lib",
            "var/cache",
            "var/log",
            "run",
            "tmp",
            "root",
            "home/owner",
            "usr/bin",
            "usr/lib",
            "usr/share",
            "dev",
            "proc",
            "sys",
            "opt",
        ] {
            std::fs::create_dir_all(path.join(d)).unwrap();
        }
        std::fs::set_permissions(path.join("tmp"), std::fs::Permissions::from_mode(0o1777)).unwrap();
        for d in ["null", "zero", "urandom", "random", "tty"] {
            std::fs::write(path.join("dev").join(d), b"").unwrap();
        }
        // Arch keeps everything in /usr/lib (lib64 is a link to it); Debian and Ubuntu (the CI runner) keep the program
        // loader in a real /usr/lib64, which the fake root then mounts as it is (run_as).
        let real_lib64 = std::fs::symlink_metadata("/usr/lib64").is_ok_and(|m| m.is_dir());
        let (lib64, usr_lib64) = if real_lib64 { ("usr/lib64", None) } else { ("usr/lib", Some("lib")) };
        if real_lib64 {
            std::fs::create_dir_all(path.join("usr/lib64")).unwrap();
        }
        for (link, target) in [("bin", "usr/bin"), ("lib", "usr/lib"), ("lib64", lib64), ("sbin", "usr/bin"), ("usr/sbin", "bin")]
            .into_iter()
            .chain(usr_lib64.map(|t| ("usr/lib64", t)))
        {
            std::os::unix::fs::symlink(target, path.join(link)).unwrap();
        }
        let r = Root { path, fakes };
        r.write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nheimdall:x:960:960:Heimdall:/var/lib/heimdall:/usr/bin/nologin\nowner:x:1000:1000:Owner:/home/owner:/bin/bash\nsarina:x:961:961:Sarina:/var/lib/sarina:/usr/bin/nologin\nnobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n");
        r.write("/etc/group", "root:x:0:root\nwheel:x:998:owner\nheimdall:x:960:\nowner:x:1000:\nsarina:x:961:\nnobody:x:65534:\n");
        r.write("/etc/nsswitch.conf", "passwd: files\ngroup: files\nshadow: files\nhosts: files\n");
        r.write("/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n");
        r.write("/etc/hostname", "testhost\n");
        for t in ALWAYS_FAKE {
            r.tool(t, "echo \"fake $(basename \"$0\"): not allowed in tests\" >&2\nexit 1\n");
        }
        std::fs::write(r.fakes.join("heimdalld"), b"").unwrap(); // the mount point of the binary under test
        r
    }

    /// The host path of a path inside.
    pub fn host(&self, p: &str) -> PathBuf {
        self.path.join(p.trim_start_matches('/'))
    }

    pub fn write(&self, p: &str, data: impl AsRef<[u8]>) -> &Root {
        let h = self.host(p);
        std::fs::create_dir_all(h.parent().unwrap()).unwrap();
        std::fs::write(&h, data).unwrap();
        self
    }

    pub fn write_mode(&self, p: &str, data: impl AsRef<[u8]>, mode: u32) -> &Root {
        self.write(p, data);
        std::fs::set_permissions(self.host(p), std::fs::Permissions::from_mode(mode)).unwrap();
        self
    }

    pub fn mkdir(&self, p: &str, mode: u32) -> &Root {
        std::fs::create_dir_all(self.host(p)).unwrap();
        std::fs::set_permissions(self.host(p), std::fs::Permissions::from_mode(mode)).unwrap();
        self
    }

    pub fn symlink(&self, target: &str, p: &str) -> &Root {
        let h = self.host(p);
        std::fs::create_dir_all(h.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, h).unwrap();
        self
    }

    pub fn read(&self, p: &str) -> Option<Vec<u8>> {
        std::fs::read(self.host(p)).ok()
    }

    pub fn read_str(&self, p: &str) -> String {
        String::from_utf8_lossy(&self.read(p).unwrap_or_default()).into_owned()
    }

    /// A fake tool in /usr/bin (over the real one, if any): the shell script given, after a line recording the call.
    pub fn tool(&self, name: &str, script: &str) -> &Root {
        let p = self.fakes.join(name);
        std::fs::write(&p, format!("#!/bin/sh\nprintf '%s\\n' \"$(basename \"$0\") $*\" >> /.fake-calls\n{script}")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        self
    }

    /// The calls the fake tools recorded, one line each ("systemctl stop sarina-service").
    pub fn calls(&self) -> String {
        self.read_str("/.fake-calls")
    }

    /// Every file and link under the folders given: path -> "mode content" (a link: "-> target"); for comparing two roots.
    pub fn tree(&self, dirs: &[&str]) -> BTreeMap<String, String> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                let rel = format!("/{}", p.strip_prefix(root).unwrap().display());
                let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
                if m.file_type().is_symlink() {
                    out.insert(rel, format!("-> {}", std::fs::read_link(&p).unwrap().display()));
                } else if m.is_dir() {
                    out.insert(rel.clone() + "/", format!("{:o} dir", m.mode() & 0o7777));
                    walk(root, &p, out);
                } else {
                    let data = std::fs::read(&p).unwrap_or_default();
                    out.insert(rel, format!("{:o} {}", m.mode() & 0o7777, String::from_utf8_lossy(&data)));
                }
            }
        }
        let mut out = BTreeMap::new();
        for d in dirs {
            walk(&self.path, &self.host(d), &mut out);
        }
        out
    }

    /// Runs `bin` (as /usr/bin/heimdalld inside) with `args`.
    pub fn run(&self, bin: &Path, args: &[&str], o: &Opts) -> Out {
        self.run_as("/usr/bin/heimdalld", bin, args, o)
    }

    /// Runs `bin` mounted at `inside` (a helper's name, as /usr/bin/heimdall-wifi-check) with `args`.
    pub fn run_as(&self, inside: &str, bin: &Path, args: &[&str], o: &Opts) -> Out {
        let name = inside.rsplit('/').next().unwrap();
        if !self.fakes.join(name).exists() {
            std::fs::write(self.fakes.join(name), b"").unwrap();
        }
        let r = self.path.display().to_string();
        let mut script = format!(
            "set -e\nR='{r}'\n{}\nmount -t overlay overlay -o 'lowerdir={}:/usr/bin' \"$R/usr/bin\"\n\
             mount --bind /usr/lib \"$R/usr/lib\"\nmount -o remount,bind,ro \"$R/usr/lib\"\n\
             mount --bind /usr/share \"$R/usr/share\"\nmount -o remount,bind,ro \"$R/usr/share\"\n\
             if [ ! -L \"$R/usr/lib64\" ] && [ -d \"$R/usr/lib64\" ]; then mount --bind /usr/lib64 \"$R/usr/lib64\"; \
             mount -o remount,bind,ro \"$R/usr/lib64\"; fi\n\
             for d in null zero urandom random tty; do mount --bind /dev/$d \"$R/dev/$d\" 2>/dev/null || true; done\n\
             mount --bind '{}' \"$R/usr/bin/{name}\"\n",
            if o.pid { "mount -t proc proc \"$R/proc\"" } else { "mount --rbind /proc \"$R/proc\"" },
            self.fakes.display(),
            bin.display()
        );
        if o.net {
            script.push_str("ip link set lo up 2>/dev/null || true\n");
        }
        script.push_str(&o.setup);
        script.push('\n');
        let user = if o.root { "" } else { "--userspec=1000:1000 " };
        let mut env = vec![
            ("PATH".to_string(), "/usr/local/sbin:/usr/local/bin:/usr/bin".to_string()),
            ("HOME".to_string(), if o.root { "/root".into() } else { "/home/owner".into() }),
            ("USER".to_string(), if o.root { "root".into() } else { "owner".into() }),
            ("LANG".to_string(), "C.UTF-8".to_string()),
            ("TZ".to_string(), "America/New_York".to_string()),
        ];
        for (k, v) in &o.env {
            env.retain(|(ek, _)| ek != k);
            env.push((k.clone(), v.clone()));
        }
        let env: Vec<String> = env.iter().map(|(k, v)| shell_quote(&format!("{k}={v}"))).collect();
        let argv: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
        script.push_str(&format!("cd \"$R\"\nexec chroot {user}\"$R\" /usr/bin/env -i {} {inside} {}\n", env.join(" "), argv.join(" ")));
        let mut cmd = Command::new("unshare");
        cmd.args(userns_args()).arg("--mount").arg("--propagation").arg("private");
        if o.pid {
            cmd.args(["--pid", "--fork"]);
        }
        if o.net {
            cmd.arg("--net");
        }
        cmd.args(["sh", "-c", &script]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("unshare");
        let mut stdin = child.stdin.take().unwrap();
        let data = o.stdin.clone();
        let w = std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
        let mut so = child.stdout.take().unwrap();
        let mut se = child.stderr.take().unwrap();
        let ro = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = so.read_to_end(&mut b);
            b
        });
        let re = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = se.read_to_end(&mut b);
            b
        });
        let start = Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if start.elapsed() > o.timeout {
                let _ = child.kill();
                break child.wait().unwrap();
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let _ = w.join();
        let stdout = String::from_utf8_lossy(&ro.join().unwrap()).into_owned();
        let stderr = String::from_utf8_lossy(&re.join().unwrap()).into_owned();
        Out { code: status.code().unwrap_or(-1), stdout, stderr }
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        if std::env::var_os("HEIMDALL_KEEP_ROOTS").is_some() {
            eprintln!("kept {}", self.path.display());
            return;
        }
        // files the command made as other users are owned by subordinate ids: removed from inside a namespace that maps them
        let _ =
            Command::new("unshare").args(userns_args()).args(["rm", "-rf"]).arg(&self.path).arg(&self.fakes).stderr(Stdio::null()).status();
        let _ = std::fs::remove_dir_all(&self.path);
        let _ = std::fs::remove_dir_all(&self.fakes);
    }
}

pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The same system built twice: the Go binary run in one, the Rust binary in the other. None when Go is missing.
pub fn both(test: &str, build: impl Fn(&Root), args: &[&str], o: &Opts) -> Option<((Out, Root), (Out, Root))> {
    let go = go_or_skip(test)?;
    let rg = Root::new(&format!("{test}-go"));
    build(&rg);
    let rr = Root::new(&format!("{test}-rs"));
    build(&rr);
    let og = rg.run(&go, args, o);
    let or = rr.run(&rust_bin(), args, o);
    Some(((og, rg), (or, rr)))
}

/// Replaces what changes from run to run (times written by `now`) with placeholders, so two runs compare: RFC 3339 times,
/// Go log stamps (2006/01/02 15:04:05), "2006-01-02 15:04[:05]" and durations like "in 1.234s".
pub fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    let digits = |j: usize, n: usize| j + n <= b.len() && b[j..j + n].iter().all(u8::is_ascii_digit);
    while i < b.len() {
        // 2026-11-10T20:00:00(.123)(Z|+01:00)
        if digits(i, 4) && i + 16 <= b.len() && b[i + 4] == b'-' && digits(i + 5, 2) && b[i + 7] == b'-' && digits(i + 8, 2) {
            let sep = b[i + 10];
            if (sep == b'T' || sep == b' ') && digits(i + 11, 2) && b[i + 13] == b':' && digits(i + 14, 2) {
                let mut j = i + 16;
                if j + 3 <= b.len() && b[j] == b':' && digits(j + 1, 2) {
                    j += 3;
                }
                if j < b.len() && b[j] == b'.' {
                    j += 1;
                    while j < b.len() && b[j].is_ascii_digit() {
                        j += 1;
                    }
                }
                if sep == b'T' {
                    if j < b.len() && b[j] == b'Z' {
                        j += 1;
                    } else if j + 6 <= b.len() && (b[j] == b'+' || b[j] == b'-') && digits(j + 1, 2) && b[j + 3] == b':' {
                        j += 6;
                    }
                }
                out.push_str("<TIME>");
                i = j;
                continue;
            }
        }
        // 2026/11/10 20:00:00
        if digits(i, 4) && i + 19 <= b.len() && b[i + 4] == b'/' && b[i + 7] == b'/' && b[i + 10] == b' ' && b[i + 13] == b':' {
            out.push_str("<STAMP>");
            i += 19;
            continue;
        }
        let c = s[i..].chars().next().unwrap();
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// Asserts two runs did the same, with a readable difference.
pub fn assert_same(what: &str, go: &Out, rs: &Out) {
    assert_eq!(go.code, rs.code, "{what}: exit codes differ\nGo stderr: {}\nRust stderr: {}", go.stderr, rs.stderr);
    assert_eq!(go.stdout, rs.stdout, "{what}: standard output differs");
    assert_eq!(go.stderr, rs.stderr, "{what}: standard error differs");
}
