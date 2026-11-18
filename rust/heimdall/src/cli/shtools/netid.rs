//! NetworkManager's dispatcher `91-heimdall-netid`, ported from the shell script (packaging/net/dispatcher.d/): records
//! which DHCP server answered this computer and what it handed out (router, DNS), and the IPv6 DNS servers, each time a
//! connection comes up or its lease changes. heimdalld's rogue-router watch reads the file (docs/WIFI_TRUST.md, "A second
//! router"). Nothing is sent on the network: these are the values NetworkManager already accepted. The folder is root's
//! (heimdall may read), so heimdalld cannot point root's write somewhere else.
//!
//! NetworkManager runs it as root with the interface and the action as arguments and the lease in its environment; every
//! value is cut down to the characters an address or a name can have before it is written, as the script did.

use super::coreutils::{mkdir_p, mv_f, tail_n, warn};
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The file is cut to its last 200 lines when it grows past this.
const MAX: u64 = 65536;

fn env(name: &str) -> Vec<u8> {
    std::env::var_os(name).map(OsString::into_vec).unwrap_or_default()
}

/// `tr -cd SET | cut -c1-N`: only the bytes `keep` allows, at most N of them.
fn only(b: &[u8], keep: impl Fn(u8) -> bool, n: usize) -> String {
    b.iter().copied().filter(|&c| keep(c)).take(n).map(char::from).collect()
}

/// The script's `ips`: hex digits, dots, colons and single spaces, at most 200.
fn ips(b: &[u8]) -> String {
    let kept: Vec<u8> = b.iter().copied().filter(|&c| c.is_ascii_hexdigit() || matches!(c, b'.' | b':' | b' ')).collect();
    let mut squeezed = Vec::with_capacity(kept.len());
    for c in kept {
        if !(c == b' ' && squeezed.last() == Some(&b' ')) {
            squeezed.push(c);
        }
    }
    squeezed.into_iter().take(200).map(char::from).collect()
}

/// `chgrp heimdall PATH 2>/dev/null` (a link followed).
fn chgrp_heimdall(p: &Path) {
    let gid = unsafe {
        let g = libc::getgrnam(c"heimdall".as_ptr());
        if g.is_null() {
            return;
        }
        (*g).gr_gid
    };
    if let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) {
        unsafe { libc::chown(c.as_ptr(), u32::MAX, gid) };
    }
}

pub fn main(args: &[String]) -> i32 {
    let iface_arg = args.first().map(String::as_str).unwrap_or_default();
    let action = args.get(1).map(String::as_str).unwrap_or_default();
    if !matches!(action, "up" | "down" | "dhcp4-change" | "dhcp6-change") {
        return 0;
    }
    // a real network card (Wi-Fi, cable, USB tethering), not a VPN or a bridge
    let mut sys = std::env::var_os("HEIMDALL_NETID_SYS").filter(|v| !v.is_empty()).unwrap_or_else(|| "/sys/class/net".into());
    sys.push(format!("/{iface_arg}/device"));
    if !Path::new(&sys).exists() {
        return 0;
    }
    let dir = PathBuf::from(std::env::var_os("HEIMDALL_NETID_DIR").filter(|v| !v.is_empty()).unwrap_or_else(|| "/run/heimdall-net".into()));
    // mkdir -p -m 0750 "$dir" && chgrp heimdall "$dir"
    let made = !dir.is_dir();
    let mut ok = match dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => mkdir_p(parent).map_err(|e| warn(&e)).is_ok(),
        None => true,
    };
    if ok {
        ok = mkdir_p(&dir).map_err(|e| warn(&e)).is_ok();
    }
    if ok {
        if made {
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750));
        }
        chgrp_heimdall(&dir);
    }
    let f = dir.join("netid.jsonl");
    let iface = only(iface_arg.as_bytes(), |c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'), 15);
    let uuid = only(&env("CONNECTION_UUID"), |c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || c == b'-', 36);
    if std::fs::metadata(&f).is_ok_and(|m| m.is_file() && m.len() > MAX) {
        if let Ok(b) = std::fs::read(&f) {
            let mut tmp = f.clone().into_os_string();
            tmp.push(".tmp");
            let tmp = PathBuf::from(tmp);
            let wrote = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o666)
                .open(&tmp)
                .and_then(|mut t| t.write_all(tail_n(&b, 200)));
            if wrote.is_ok() {
                if let Err(e) = mv_f(&tmp, &f) {
                    warn(&e);
                }
            }
        }
    }
    unsafe { libc::umask(0o027) };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let line = format!(
        "{{\"t\":{now},\"action\":\"{action}\",\"iface\":\"{iface}\",\"uuid\":\"{uuid}\",\"dhcp4_server\":\"{}\",\"dhcp4_routers\":\"{}\",\"dns4\":\"{}\",\"dns6\":\"{}\"}}\n",
        ips(&env("DHCP4_DHCP_SERVER_IDENTIFIER")),
        ips(&env("DHCP4_ROUTERS")),
        ips(&env("DHCP4_DOMAIN_NAME_SERVERS")),
        ips(&env("IP6_NAMESERVERS")),
    );
    match std::fs::OpenOptions::new().append(true).create(true).mode(0o666).open(&f) {
        Ok(mut h) => {
            if let Err(e) = h.write_all(line.as_bytes()) {
                warn(&format!("91-heimdall-netid: {}: {}", f.to_string_lossy(), super::coreutils::strerror(&e)));
            }
        }
        Err(e) => warn(&format!("91-heimdall-netid: cannot create {}: {}", f.to_string_lossy(), super::coreutils::strerror(&e))),
    }
    chgrp_heimdall(&f);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_cut_down_as_the_script() {
        assert_eq!(ips(b"192.0.2.1\"};x"), "192.0.2.1");
        assert_eq!(ips(b"192.0.2.53   192.0.2.54"), "192.0.2.53 192.0.2.54");
        assert_eq!(ips(&[b'a'; 300]).len(), 200);
        assert_eq!(only(b"wlan0;rm -rf /", |c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'), 15), "wlan0rm-rf");
    }
}
