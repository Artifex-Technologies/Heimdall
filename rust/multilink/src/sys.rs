//! The small pieces that talk to the system: `ip` and `nmcli`, the two sysctls, the netlink wake-up, signals, systemd's
//! notify socket and the local date.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn find(names: &[&str]) -> Option<PathBuf> {
    names.iter().map(PathBuf::from).find(|p| p.is_file())
}

/// iproute2's `ip`, by its full path (the service runs as root: never one found through PATH).
pub fn ip_path() -> PathBuf {
    find(&["/usr/bin/ip", "/usr/sbin/ip", "/sbin/ip", "/bin/ip"]).unwrap_or_else(|| PathBuf::from("/usr/bin/ip"))
}

/// Run `ip ARGS`; its output, or its error line.
pub fn ip(args: &[&str]) -> Result<String, String> {
    let o = Command::new(ip_path()).args(args).stdin(Stdio::null()).output().map_err(|e| format!("ip: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(format!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim()))
    }
}

/// Run `nmcli ARGS` when NetworkManager's client is installed; None otherwise or on failure.
pub fn nmcli(args: &[&str]) -> Option<String> {
    let p = find(&["/usr/bin/nmcli"])?;
    let o = Command::new(p).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The kernel settings this feature changes while it runs, and the value each gets:
/// - L4 hashing (source and destination address and port), so connections to the same server can take different links;
/// - skipping a link whose gateway does not answer the neighbour check, before our own health checks notice.
pub const SYSCTLS: [(&str, &str); 3] =
    [("net/ipv4/fib_multipath_hash_policy", "1"), ("net/ipv6/fib_multipath_hash_policy", "1"), ("net/ipv4/fib_multipath_use_neigh", "1")];

fn sysctl_path(name: &str) -> PathBuf {
    Path::new("/proc/sys").join(name)
}

/// Keep the values from before (once: a restart after a crash must not keep ours as "before"), then set ours.
pub fn sysctls_set(orig: &Path) -> Result<(), String> {
    if !orig.exists() {
        let mut text = String::new();
        for (name, _) in SYSCTLS {
            if let Ok(v) = std::fs::read_to_string(sysctl_path(name)) {
                text += &format!("{name}={}\n", v.trim());
            }
        }
        write_atomic(orig, &text)?;
    }
    for (name, v) in SYSCTLS {
        // a kernel without one (no IPv6) is fine
        let _ = std::fs::write(sysctl_path(name), v);
    }
    Ok(())
}

/// Put back the values kept by `sysctls_set`, then forget them.
pub fn sysctls_restore(orig: &Path) {
    let Ok(text) = std::fs::read_to_string(orig) else { return };
    for line in text.lines() {
        let Some((name, v)) = line.split_once('=') else { continue };
        // only the ones we change, whatever the file says
        if SYSCTLS.iter().any(|(n, _)| *n == name) && v.bytes().all(|b| b.is_ascii_digit()) {
            let _ = std::fs::write(sysctl_path(name), v);
        }
    }
    let _ = std::fs::remove_file(orig);
}

/// Write a file whole: a new file renamed over the old one.
pub fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// A netlink socket that becomes readable when a link, an address, a route or a rule changes anywhere (NetworkManager
/// reconnecting, a cable pulled, a VPN starting). What it says is not read: it only wakes the loop to look again.
pub fn netlink_wake() -> Option<OwnedFd> {
    // SAFETY: a new socket, owned at once
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return None;
    }
    // SAFETY: fd is ours alone
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // links, IPv4 addresses, routes and rules, IPv6 addresses and routes (the legacy group bits)
    const GROUPS: u32 = 0x1 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400;
    // SAFETY: all-zero sockaddr_nl is valid; the fields set are plain integers
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    sa.nl_groups = GROUPS;
    // SAFETY: sa is a valid sockaddr_nl of the size given
    if unsafe { libc::bind(fd, (&sa as *const libc::sockaddr_nl).cast(), std::mem::size_of::<libc::sockaddr_nl>() as u32) } < 0 {
        return None;
    }
    // IPv6 rules have no legacy bit: RTNLGRP_IPV6_RULE (19)
    let g: libc::c_int = 19;
    // SAFETY: g is an int option value of the size given
    unsafe {
        libc::setsockopt(fd, libc::SOL_NETLINK, libc::NETLINK_ADD_MEMBERSHIP, (&g as *const libc::c_int).cast(), 4);
    }
    Some(sock)
}

/// Read and drop everything waiting on a non-blocking socket.
pub fn drain(fd: &OwnedFd) {
    let mut buf = [0u8; 8192];
    loop {
        // SAFETY: buf is ours and its length is given
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n <= 0 {
            // ENOBUFS (we fell behind) is fine: the loop looks at everything again anyway
            return;
        }
    }
}

/// SIGTERM, SIGINT and SIGHUP as a descriptor the loop polls (blocked as signals, so they arrive only there).
pub fn signal_fd() -> Option<OwnedFd> {
    // SAFETY: a sigset of our own, filled by the libc calls; signalfd returns a new descriptor
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaddset(&mut set, s);
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return None;
        }
        let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        (fd >= 0).then(|| OwnedFd::from_raw_fd(fd))
    }
}

/// Tell systemd something (READY=1, WATCHDOG=1, STATUS=...) when it runs us as Type=notify.
pub fn notify(msg: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else { return };
    let p = path.to_string_lossy();
    if let Some(name) = p.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        if let Ok(a) = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()) {
            let _ = sock.send_to_addr(msg.as_bytes(), &a);
        }
    } else {
        let _ = sock.send_to(msg.as_bytes(), &*p);
    }
}

/// Today in local time, as (year, month, day).
pub fn today() -> (i32, u32, u32) {
    // SAFETY: time and localtime_r with a tm of our own
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return (1970, 1, 1);
        }
        (tm.tm_year + 1900, (tm.tm_mon + 1) as u32, tm.tm_mday as u32)
    }
}

/// Every interface's bytes received plus sent since it came up, from `/proc/net/dev` (the calling process's own network
/// namespace, one read for all of them).
pub fn counters() -> Vec<(String, u64)> {
    std::fs::read_to_string("/proc/net/dev").map(|t| parse_net_dev(&t)).unwrap_or_default()
}

pub fn parse_net_dev(text: &str) -> Vec<(String, u64)> {
    text.lines()
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let f: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            // receive: bytes packets errs drop fifo frame compressed multicast; transmit: bytes ...
            (f.len() >= 9).then(|| (name.trim().to_string(), f[0] + f[8]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn proc_net_dev() {
        let t = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0\n wlan0: 5000 40 0 0 0 0 0 0 700 9 0 0 0 0 0 0\n";
        assert_eq!(super::parse_net_dev(t), vec![("lo".to_string(), 2000), ("wlan0".to_string(), 5700)]);
    }
}
