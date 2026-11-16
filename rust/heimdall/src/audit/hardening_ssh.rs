//! The SSH server check (Go: internal/hardening/ssh.go): is an SSH server (OpenSSH's sshd, or dropbear) running or set to
//! start, and does it take passwords? SSHole (CVE-2026-123158): OpenSSH before 10.6p2, built on musl, without PAM, took an
//! over-long password for a locked account. Read-only, no network: /proc/net, the start links, /etc/ssh and the sshd program
//! file (its version string and ELF interpreter); `sshd -T` only on the real system and as root.

use super::{Gap, System};
use crate::gotext;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

pub const SSHOLE_CVE: &str = "CVE-2026-123158";

/// sshd's settings as sshd reads them: the first value of a keyword wins; Match blocks kept apart ("keyword=value").
#[derive(Default)]
struct SshConfig {
    global: BTreeMap<String, String>,
    matched: BTreeSet<String>,
    ports: Vec<String>,
    read: bool,
}

impl SshConfig {
    fn set(&mut self, key: &str, val: &str, in_match: bool) {
        let val = gotext::to_lower(val);
        if in_match {
            self.matched.insert(format!("{key}={val}"));
            return;
        }
        if key == "port" {
            self.ports.push(val);
            return;
        }
        self.global.entry(key.to_string()).or_insert(val);
    }

    fn val(&self, key: &str, def: &str) -> String {
        self.global.get(key).cloned().unwrap_or_else(|| def.to_string())
    }

    fn on(&self, key: &str, def: &str) -> bool {
        self.val(key, def) == "yes" || self.matched.contains(&format!("{key}=yes"))
    }
}

/// One config line: its lower-case keyword and its value ("Keyword value" or "Keyword=value").
fn ssh_line(line: &str) -> (String, String) {
    let line = gotext::trim_space(line);
    if line.is_empty() || line.starts_with('#') {
        return (String::new(), String::new());
    }
    let Some(i) = line.find([' ', '\t', '=']) else {
        return (gotext::to_lower(line), String::new());
    };
    let mut key = gotext::to_lower(&line[..i]);
    let mut val = line[i..].trim_start_matches([' ', '\t']);
    if let Some(v) = val.strip_prefix('=') {
        val = v.trim_start_matches([' ', '\t']);
    }
    let mut val = gotext::trim_space(val);
    if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
        val = &val[1..val.len() - 1];
    }
    if key == "challengeresponseauthentication" {
        key = "kbdinteractiveauthentication".into();
    }
    (key, val.to_string())
}

/// * and ? only; a leading dot must be matched by a dot.
fn glob_match(pat: &[u8], name: &[u8]) -> bool {
    if name.starts_with(b".") && !pat.starts_with(b".") {
        return false;
    }
    fn m(p: &[u8], n: &[u8]) -> bool {
        let (mut p, mut n) = (p, n);
        while let Some(&c) = p.first() {
            match c {
                b'*' => return (0..=n.len()).rev().any(|i| m(&p[1..], &n[i..])),
                b'?' if n.is_empty() => return false,
                b'?' => {}
                _ if n.first() != Some(&c) => return false,
                _ => {}
            }
            p = &p[1..];
            n = &n[1..];
        }
        n.is_empty()
    }
    m(pat, name)
}

fn sorted_names(dir: &str) -> Vec<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let mut out: Vec<Vec<u8>> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.flatten().map(|e| e.file_name().as_bytes().to_vec()).collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

/// sshd's version as program and packages write it: major, minor, portable release.
fn ssh_version(v: &str) -> Option<[i64; 3]> {
    let mut v = v.strip_prefix("OpenSSH_").unwrap_or(v).to_string();
    if let Some(i) = v.find(':') {
        if i > 0 && gotext::atoi(&v[..i]).is_some() {
            v = v[i + 1..].to_string();
        }
    }
    let v = v.replace("_p", "p");
    let mut rest = v.as_bytes();
    let num = |rest: &mut &[u8]| -> Option<i64> {
        let i = rest.iter().take(6).take_while(|c| c.is_ascii_digit()).count();
        if i == 0 {
            return None;
        }
        let n = std::str::from_utf8(&rest[..i]).ok()?.parse().ok()?;
        *rest = &rest[i..];
        Some(n)
    };
    let mut out = [0i64; 3];
    out[0] = num(&mut rest)?;
    rest = rest.strip_prefix(b".")?;
    out[1] = num(&mut rest)?;
    if let Some(r) = rest.strip_prefix(b"p") {
        rest = r;
        out[2] = num(&mut rest).unwrap_or(0);
    }
    Some(out)
}

const SSHOLE_FIXED: [i64; 3] = [10, 6, 2];

/// The newest "OpenSSH_x.y[pN]" in the program file.
fn binary_version(b: &[u8]) -> (String, [i64; 3]) {
    let (mut best, mut best_v) = (String::new(), [0i64; 3]);
    let needle = b"OpenSSH_";
    let mut rest = b;
    while let Some(i) = rest.windows(needle.len()).position(|w| w == needle) {
        rest = &rest[i + needle.len()..];
        let j = rest.iter().take(16).take_while(|c| c.is_ascii_digit() || **c == b'.' || **c == b'p').count();
        let s = String::from_utf8_lossy(&rest[..j]).into_owned();
        if let Some(v) = ssh_version(&s) {
            if best.is_empty() || best_v < v {
                best = s;
                best_v = v;
            }
        }
    }
    (best, best_v)
}

/// The program interpreter an ELF file asks for (PT_INTERP); empty when none or not ELF.
fn elf_interp(b: &[u8]) -> Vec<u8> {
    if b.len() < 52 || &b[..4] != b"\x7fELF" || (b[4] != 1 && b[4] != 2) {
        return Vec::new();
    }
    let is64 = b[4] == 2;
    let be = b[5] == 2;
    let u16_at = |o: usize| -> u64 {
        let x = [b[o], b[o + 1]];
        (if be { u16::from_be_bytes(x) } else { u16::from_le_bytes(x) }) as u64
    };
    let u32_at = |o: usize| -> u64 {
        let x: [u8; 4] = b[o..o + 4].try_into().unwrap();
        (if be { u32::from_be_bytes(x) } else { u32::from_le_bytes(x) }) as u64
    };
    let u64_at = |o: usize| -> u64 {
        let x: [u8; 8] = b[o..o + 8].try_into().unwrap();
        if be {
            u64::from_be_bytes(x)
        } else {
            u64::from_le_bytes(x)
        }
    };
    let (phoff, phentsize, phnum, need) = if is64 {
        if b.len() < 64 {
            return Vec::new();
        }
        (u64_at(0x20), u16_at(0x36), u16_at(0x38), 40u64)
    } else {
        (u32_at(0x1c), u16_at(0x2a), u16_at(0x2c), 20u64)
    };
    let n = b.len() as u64;
    if phentsize < need || phoff > n {
        return Vec::new();
    }
    let mut i = 0u64;
    while i < phnum && i < 256 {
        let o = phoff + i * phentsize;
        if o + need > n {
            return Vec::new();
        }
        let o = o as usize;
        i += 1;
        if u32_at(o) != 3 {
            continue;
        }
        let (off, size) = if is64 { (u64_at(o + 8), u64_at(o + 32)) } else { (u32_at(o + 4), u32_at(o + 16)) };
        if off > n || size > n - off {
            return Vec::new();
        }
        let mut s = b[off as usize..(off + size) as usize].to_vec();
        while s.last() == Some(&0) {
            s.pop();
        }
        return s;
    }
    Vec::new()
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

fn libc_of(interp: &[u8]) -> &'static str {
    if contains(interp, b"ld-musl") {
        "musl"
    } else if contains(interp, b"ld-linux") {
        "glibc"
    } else {
        ""
    }
}

const SSH_FIX_KEYS: &str = "put 'PasswordAuthentication no' and 'KbdInteractiveAuthentication no' at the top of /etc/ssh/sshd_config (sshd keeps the first value it reads; a Match block that turns them on needs the same), check with sudo sshd -t, then sudo systemctl reload sshd. Copy your key over first (ssh-copy-id) so you are not locked out";

const GUESS_WHY: &str = "anyone who reaches the server can keep guessing passwords, and a weak or reused one is then all that stands between them and a shell; keys cannot be guessed";

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

impl System {
    fn include_files(&self, pat: &str) -> Vec<String> {
        let pat = if pat.starts_with('/') { pat.to_string() } else { format!("/etc/ssh/{pat}") };
        let cut = pat.rfind('/').unwrap() + 1;
        let (dir, base) = (&pat[..cut], &pat[cut..]);
        if !base.contains(['*', '?']) {
            return vec![pat.clone()];
        }
        sorted_names(&self.path(dir))
            .into_iter()
            .filter(|n| glob_match(base.as_bytes(), n))
            .map(|n| format!("{dir}{}", String::from_utf8_lossy(&n)))
            .collect()
    }

    fn parse_ssh(&self, p: &str, in_match: bool, depth: u32, c: &mut SshConfig) -> bool {
        let Ok(b) = self.read_raw(p) else { return false };
        let text = gotext::lossy(&b);
        let mut in_match = in_match;
        for line in text.split('\n') {
            let (key, val) = ssh_line(line);
            match key.as_str() {
                "" => continue,
                "match" => {
                    in_match = true;
                    continue;
                }
                "include" => {
                    if depth < 16 {
                        for pat in gotext::fields(&val) {
                            for f in self.include_files(pat) {
                                self.parse_ssh(&f, in_match, depth + 1, c);
                            }
                        }
                    }
                    continue;
                }
                _ => {}
            }
            c.set(&key, &val, in_match);
        }
        true
    }

    /// `sshd -T`: on the real system and as root only.
    fn sshd_t(&self, bin: &str) -> Option<String> {
        if !self.root.is_empty() || euid() != 0 {
            return None;
        }
        let mut child = std::process::Command::new(bin)
            .arg("-T")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(50)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
        let out = child.wait_with_output().ok()?;
        out.status.success().then(|| gotext::lossy(&out.stdout))
    }

    fn read_ssh_config(&self, bin: &str) -> SshConfig {
        let mut c = SshConfig::default();
        c.read = self.parse_ssh("/etc/ssh/sshd_config", false, 0, &mut c);
        if let Some(out) = self.sshd_t(bin) {
            c.global.clear();
            c.ports.clear();
            c.read = true;
            for line in out.split('\n') {
                let (key, val) = ssh_line(line);
                if !key.is_empty() {
                    c.set(&key, &val, false);
                }
            }
        }
        if c.ports.is_empty() {
            c.ports.push("22".into());
        }
        c
    }

    fn listening(&self, ports: &[String]) -> String {
        for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let text = self.read(f).unwrap_or_default();
            for line in text.split('\n') {
                let fields: Vec<&str> = gotext::fields(line).collect();
                if fields.len() < 4 || fields[3] != "0A" {
                    continue;
                }
                let Some(i) = fields[1].rfind(':') else { continue };
                let hex = &fields[1][i + 1..];
                if hex.is_empty() || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                if let Ok(port) = u16::from_str_radix(hex, 16) {
                    let p = port.to_string();
                    if ports.contains(&p) {
                        return p;
                    }
                }
            }
        }
        String::new()
    }

    fn starts_at_boot(&self, names: &[&str]) -> String {
        for base in ["/etc/systemd/system", "/etc/runlevels"] {
            for d in sorted_names(&self.path(base)) {
                let d = String::from_utf8_lossy(&d).into_owned();
                if base == "/etc/systemd/system" && !d.ends_with(".wants") {
                    continue;
                }
                for e in sorted_names(&self.path(&format!("{base}/{d}"))) {
                    if let Some(n) = names.iter().find(|n| n.as_bytes() == e.as_slice()) {
                        return n.to_string();
                    }
                }
            }
        }
        String::new()
    }

    fn first_file(&self, paths: &[&str]) -> String {
        paths.iter().find(|p| std::fs::metadata(self.path(p)).is_ok_and(|m| m.is_file())).map(|p| p.to_string()).unwrap_or_default()
    }

    /// The SSH server check, in Go's order.
    pub(super) fn ssh_gaps(&self) -> Vec<Gap> {
        let mut gaps = Vec::new();
        let bin = self.first_file(&["/usr/bin/sshd", "/usr/sbin/sshd"]);
        if !bin.is_empty() {
            let c = self.read_ssh_config(&self.path(&bin));
            let (mut state, mut level) = ("sshd is installed but not started".to_string(), "info");
            let p = self.listening(&c.ports);
            if !p.is_empty() {
                (state, level) = (format!("sshd listens on port {p}"), "warning");
            } else {
                let u = self.starts_at_boot(&["sshd.service", "sshd.socket", "ssh.service", "ssh.socket", "sshd"]);
                if !u.is_empty() {
                    (state, level) = (format!("sshd starts at boot ({u})"), "warning");
                }
            }
            if !c.read {
                if level == "warning" {
                    gaps.push(Gap {
                        id: "ssh-settings-unread".into(),
                        now: format!("{state}; Heimdall may not read /etc/ssh/sshd_config"),
                        level: "info".into(),
                        why: "could not be checked whether it takes passwords; an SSH server that does can be guessed at by anyone who reaches it".into(),
                        fix: format!("sudo sshd -T | grep -iE '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|permitemptypasswords|usepam) ' (passwordauthentication yes means passwords are taken: {SSH_FIX_KEYS})"),
                        cve: String::new(),
                    });
                }
                return gaps;
            }
            let b = self.read_raw(&bin).unwrap_or_default();
            let (ver, v) = binary_version(&b);
            let libc = libc_of(&elf_interp(&b));
            let pam = c.val("usepam", "no") == "yes";
            let pw = c.on("passwordauthentication", "yes");
            let kbd = pam && c.on("kbdinteractiveauthentication", "yes");
            let mut on: Vec<&str> = Vec::new();
            if c.val("passwordauthentication", "yes") == "yes" {
                on.push("PasswordAuthentication yes");
            } else if pw {
                on.push("PasswordAuthentication yes in a Match block");
            }
            if kbd {
                on.push("KbdInteractiveAuthentication yes with UsePAM yes");
            }
            if !pam {
                on.push("UsePAM no");
            }
            let on = on.join(", ");
            let sshole = !ver.is_empty() && v < SSHOLE_FIXED && libc == "musl" && !pam && pw;
            if sshole {
                gaps.push(Gap {
                    id: "ssh-sshole".into(),
                    cve: SSHOLE_CVE.into(),
                    level: if level == "warning" { "critical" } else { "info" }.into(),
                    now: format!("{state}: OpenSSH {ver} built on musl, {on}"),
                    why: format!("this is the build SSHole ({SSHOLE_CVE}) is in: it takes an over-long password for a locked account (one whose stored password is \"*\"), so anyone who reaches the server may sign in as that account. OpenSSH 10.6p2 fixes it"),
                    fix: format!("update OpenSSH to 10.6p2 or newer; until then turn password logins off: {SSH_FIX_KEYS}"),
                });
            }
            if pw || kbd {
                let mut why = GUESS_WHY.to_string();
                if !sshole {
                    if pam {
                        why += &format!(". Not open to SSHole ({SSHOLE_CVE}): it signs in through PAM");
                    } else if libc == "glibc" {
                        why += &format!(". Not open to SSHole ({SSHOLE_CVE}): it is built on glibc");
                    } else if !ver.is_empty() && libc == "musl" {
                        why += &format!(". Not open to SSHole ({SSHOLE_CVE}): OpenSSH {ver} has the fix");
                    }
                }
                gaps.push(Gap {
                    id: "ssh-password-login".into(),
                    now: format!("{state} with password logins on ({on})"),
                    level: level.into(),
                    why,
                    fix: format!("PasswordAuthentication no; use keys: {SSH_FIX_KEYS}"),
                    cve: String::new(),
                });
                if c.on("permitrootlogin", "prohibit-password") {
                    gaps.push(Gap {
                        id: "ssh-root-password".into(),
                        now: format!("{state} and lets root sign in with a password (PermitRootLogin yes)"),
                        level: level.into(),
                        why: "root's password alone opens the whole computer to anyone who reaches the server".into(),
                        fix: "put 'PermitRootLogin prohibit-password' (or no) at the top of /etc/ssh/sshd_config, check with sudo sshd -t, then sudo systemctl reload sshd".into(),
                        cve: String::new(),
                    });
                }
                if c.on("permitemptypasswords", "no") {
                    gaps.push(Gap {
                        id: "ssh-empty-passwords".into(),
                        now: format!("{state} and lets accounts with an empty password sign in (PermitEmptyPasswords yes)"),
                        level: level.into(),
                        why: "an account without a password can be signed in to by anyone who reaches the server".into(),
                        fix: "put 'PermitEmptyPasswords no' at the top of /etc/ssh/sshd_config, check with sudo sshd -t, then sudo systemctl reload sshd".into(),
                        cve: String::new(),
                    });
                }
            }
        }
        if !self.first_file(&["/usr/bin/dropbear", "/usr/sbin/dropbear"]).is_empty() {
            let (mut state, mut level) = ("dropbear is installed but not started".to_string(), "info");
            let u = self.starts_at_boot(&["dropbear.service", "dropbear.socket", "dropbear"]);
            if !u.is_empty() {
                (state, level) = (format!("dropbear starts at boot ({u})"), "warning");
            }
            let mut opts = String::new();
            for f in ["/etc/conf.d/dropbear", "/etc/default/dropbear"] {
                opts.push(' ');
                opts.push_str(&self.read(f).unwrap_or_default());
            }
            let no_passwords = opts.split([' ', '\t', '\n', '"', '\'', '=']).any(|t| {
                let b = t.as_bytes();
                b.len() > 1 && b[0] == b'-' && b[1] != b'-' && b[1..].iter().all(u8::is_ascii_alphabetic) && b.contains(&b's')
            });
            if !no_passwords {
                gaps.push(Gap {
                    id: "ssh-dropbear-password".into(),
                    now: format!("{state} with password logins on (no -s in its options)"),
                    level: level.into(),
                    why: GUESS_WHY.into(),
                    fix: "add -s to DROPBEAR_OPTS in /etc/conf.d/dropbear (or DROPBEAR_EXTRA_ARGS in /etc/default/dropbear) and restart dropbear, after copying your key to ~/.ssh/authorized_keys".into(),
                    cve: String::new(),
                });
            }
        }
        gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_as_go() {
        for (s, less) in [("10.6p1", true), ("10.6p2", false), ("10.6", true), ("1:10.6p1-3", true), ("10.6_p2-r0", false), ("9.9p2", true)]
        {
            assert_eq!(ssh_version(s).unwrap() < SSHOLE_FIXED, less, "{s}");
        }
        assert_eq!(ssh_version("x10.6"), None);
        assert_eq!(binary_version(b"OpenSSH_2.*\0OpenSSH_10.6\0OpenSSH_10.5p1").0, "10.6");
    }

    #[test]
    fn globs_as_sshd() {
        assert!(glob_match(b"*.conf", b"10-a.conf"));
        assert!(!glob_match(b"*.conf", b".x.conf"));
        assert!(!glob_match(b"*.conf", b"a.txt"));
        assert!(glob_match(b"?0-*", b"10-a"));
    }
}
