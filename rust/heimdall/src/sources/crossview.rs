//! The cross-view check (HEI-50, R13 phase 2): what the system lists against what it answers when asked directly. A rootkit
//! hides a process by taking it out of /proc's directory listing and a port by taking it out of /proc/net/tcp, because that
//! is what ps, top and netstat read; it rarely changes every other way the kernel answers too. So, every five minutes:
//!
//! - processes: the PIDs in every cgroup's `cgroup.procs` (the kernel's own list of each group's members) that /proc's
//!   listing leaves out, and that `/proc/PID` still answers for when opened directly;
//! - sockets: the TCP listening and UDP sockets the kernel's socket table gives over netlink (`inet_diag`, what `ss` reads)
//!   that /proc/net/{tcp,udp}{,6} leaves out, by inode.
//!
//! The list is read on both sides of the other view (list, other view, list again), so what starts in between is not
//! taken for hidden, and only what stays hidden on two looks in a row is reported, once while it stays hidden. A /proc
//! mounted with `hidepid` hides other users' processes from the direct lookup too, and so gives nothing. The events go to
//! the `crossview` detector (critical). Go has the detector (the parity reference) but not this source.

use crate::event::{Event, Fields};
use crate::gotime::Time;
use crate::sources::{Msg, Source};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How often the views are compared.
pub const EVERY: Duration = Duration::from_secs(300);

/// The two sides of each view. The real system is `System`; tests give a stand-in that hides something.
pub trait Views {
    /// The PIDs /proc's directory listing gives.
    fn listed_pids(&self) -> BTreeSet<u32>;
    /// The PIDs every cgroup's `cgroup.procs` gives (0, a process outside this PID namespace, left out).
    fn cgroup_pids(&self) -> BTreeSet<u32>;
    /// Whether /proc/PID answers when opened directly, and its name (`comm`) when it does.
    fn answers(&self, pid: u32) -> Option<String>;
    /// The sockets /proc/net/{tcp,udp}{,6} list: inode and "tcp 0.0.0.0:22" (TCP listening only, UDP all).
    fn listed_sockets(&self) -> BTreeMap<u64, String>;
    /// The same from the kernel's socket table over netlink; Err when netlink cannot be asked (then sockets are not compared).
    fn table_sockets(&self) -> std::io::Result<BTreeMap<u64, String>>;
}

/// This computer: /proc and the cgroup tree.
pub struct System {
    pub proc_dir: String,
    pub cgroup_dir: String,
}

fn numbers(dir: &str) -> BTreeSet<u32> {
    std::fs::read_dir(dir)
        .map(|rd| rd.flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<u32>().ok())).collect())
        .unwrap_or_default()
}

fn socket_text(proto: &str, ip: &IpAddr, port: u16) -> String {
    let t = super::net::ip_text(ip);
    if t.contains(':') {
        format!("{proto} [{t}]:{port}")
    } else {
        format!("{proto} {t}:{port}")
    }
}

const TCP_LISTEN: u8 = 0x0A;

impl Views for System {
    fn listed_pids(&self) -> BTreeSet<u32> {
        numbers(&self.proc_dir)
    }

    fn cgroup_pids(&self) -> BTreeSet<u32> {
        let mut out = BTreeSet::new();
        let mut dirs = vec![std::path::PathBuf::from(&self.cgroup_dir)];
        while let Some(d) = dirs.pop() {
            if let Ok(t) = std::fs::read_to_string(d.join("cgroup.procs")) {
                out.extend(t.lines().filter_map(|l| l.trim().parse::<u32>().ok()).filter(|p| *p != 0));
            }
            if let Ok(rd) = std::fs::read_dir(&d) {
                // only real folders: a cgroup tree has no links, and following one could loop
                dirs.extend(rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.path()));
            }
        }
        out
    }

    fn answers(&self, pid: u32) -> Option<String> {
        let dir = format!("{}/{pid}", self.proc_dir);
        std::fs::metadata(&dir).ok()?;
        Some(std::fs::read_to_string(format!("{dir}/comm")).map(|s| s.trim().to_string()).unwrap_or_default())
    }

    fn listed_sockets(&self) -> BTreeMap<u64, String> {
        let mut out = BTreeMap::new();
        for (file, proto) in [("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")] {
            let Ok(text) = std::fs::read_to_string(format!("{}/net/{file}", self.proc_dir)) else { continue };
            for s in super::net::parse_proc_net(&text) {
                if s.inode != 0 && (proto == "udp" || s.state == TCP_LISTEN) {
                    out.insert(s.inode, socket_text(proto, &s.local, s.local_port));
                }
            }
        }
        out
    }

    fn table_sockets(&self) -> std::io::Result<BTreeMap<u64, String>> {
        let mut out = BTreeMap::new();
        for (family, proto, name, states) in [
            (libc::AF_INET, libc::IPPROTO_TCP, "tcp", 1u32 << TCP_LISTEN),
            (libc::AF_INET6, libc::IPPROTO_TCP, "tcp", 1 << TCP_LISTEN),
            (libc::AF_INET, libc::IPPROTO_UDP, "udp", u32::MAX),
            (libc::AF_INET6, libc::IPPROTO_UDP, "udp", u32::MAX),
        ] {
            for (inode, ip, port) in diag::dump(family as u8, proto as u8, states)? {
                if inode != 0 {
                    out.insert(inode, socket_text(name, &ip, port));
                }
            }
        }
        Ok(out)
    }
}

/// The kernel's socket table over netlink (`NETLINK_SOCK_DIAG`, `inet_diag`: what `ss` reads); needs no privilege.
mod diag {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_DUMP: u16 = 0x300;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    /// nlmsghdr (16 bytes) and inet_diag_req_v2 (56).
    const REQ_LEN: usize = 16 + 56;
    /// nlmsghdr and inet_diag_msg (72): family 0, state 1, the socket id from 4 (source port 4-5 big-endian, source
    /// address 8-23), the inode at 68.
    const MSG_LEN: usize = 16 + 72;

    fn last() -> std::io::Error {
        std::io::Error::last_os_error()
    }

    /// Every socket of `family` and `proto` in `states` (one bit per TCP state): (inode, local address, local port).
    pub fn dump(family: u8, proto: u8, states: u32) -> std::io::Result<Vec<(u64, IpAddr, u16)>> {
        // SAFETY: plain socket(2); the descriptor is owned from here on
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_SOCK_DIAG) };
        if fd < 0 {
            return Err(last());
        }
        // SAFETY: fd is a socket this function just opened and nothing else owns
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut req = [0u8; REQ_LEN];
        req[0..4].copy_from_slice(&(REQ_LEN as u32).to_ne_bytes());
        req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        req[16] = family;
        req[17] = proto;
        req[20..24].copy_from_slice(&states.to_ne_bytes());
        // SAFETY: an all-zero sockaddr_nl is valid; the kernel is the destination (pid 0)
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: req and sa are live for the call and their sizes are given
        let sent = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                req.as_ptr() as *const libc::c_void,
                req.len(),
                0,
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if sent < 0 {
            return Err(last());
        }
        let mut out = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            // SAFETY: buf is live and writable for its length
            let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let e = last();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let n = n as usize;
            if n == 0 {
                return Ok(out);
            }
            let mut off = 0;
            while off + 16 <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let kind = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                if len < 16 || off + len > n {
                    return Err(std::io::Error::other("a garbled netlink answer"));
                }
                match kind {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_ERROR => {
                        let code = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap_or([0; 4]));
                        return Err(std::io::Error::from_raw_os_error(-code));
                    }
                    _ if len >= MSG_LEN => {
                        let m = &buf[off + 16..off + len];
                        let port = u16::from_be_bytes([m[4], m[5]]);
                        let ip = if m[0] == libc::AF_INET6 as u8 {
                            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&m[8..24]).unwrap()))
                        } else {
                            IpAddr::V4(Ipv4Addr::new(m[8], m[9], m[10], m[11]))
                        };
                        let inode = u32::from_ne_bytes(m[68..72].try_into().unwrap()) as u64;
                        out.push((inode, ip, port));
                    }
                    _ => {}
                }
                off += (len + 3) & !3;
            }
        }
    }
}

/// What one look found hidden: a key ("pid 4242", "inode 99"), the text and the fields of its event.
type Found = BTreeMap<String, (String, Fields)>;

/// The cross-view source.
pub struct CrossView<V: Views> {
    views: V,
    next: Instant,
    /// What the last look found hidden (reported on the second look in a row).
    suspects: BTreeSet<String>,
    /// What was reported and is still hidden (not reported again).
    reported: BTreeSet<String>,
}

impl<V: Views> CrossView<V> {
    pub fn new(views: V) -> CrossView<V> {
        CrossView { views, next: Instant::now() + Duration::from_secs(60), suspects: BTreeSet::new(), reported: BTreeSet::new() }
    }

    /// One look at both views.
    fn hidden(&self) -> Found {
        let mut out = Found::new();
        let first = self.views.listed_pids();
        let groups = self.views.cgroup_pids();
        let second = self.views.listed_pids();
        for pid in groups.iter().filter(|p| !first.contains(p) && !second.contains(p)) {
            let Some(name) = self.views.answers(*pid) else { continue };
            let shown = if name.is_empty() { String::new() } else { format!(" ({name})") };
            out.insert(
                format!("pid {pid}"),
                (
                    format!("process {pid}{shown} runs but /proc does not list it"),
                    Fields::from([
                        ("what".to_string(), "process".to_string()),
                        ("pid".to_string(), pid.to_string()),
                        ("program".to_string(), name),
                    ]),
                ),
            );
        }
        let first = self.views.listed_sockets();
        if let Ok(table) = self.views.table_sockets() {
            let second = self.views.listed_sockets();
            for (inode, what) in table.iter().filter(|(i, _)| !first.contains_key(i) && !second.contains_key(i)) {
                let file = if what.starts_with("udp") { "/proc/net/udp" } else { "/proc/net/tcp" };
                let how = if what.starts_with("udp") { "bound to" } else { "listening on" };
                let (proto, addr) = what.split_once(' ').unwrap_or((what.as_str(), ""));
                out.insert(
                    format!("inode {inode}"),
                    (
                        format!("a {proto} socket {how} {addr} (inode {inode}) is in the kernel's socket table but not in {file}"),
                        Fields::from([
                            ("what".to_string(), "socket".to_string()),
                            ("socket".to_string(), what.clone()),
                            ("inode".to_string(), inode.to_string()),
                        ]),
                    ),
                );
            }
        }
        out
    }

    /// One look: the events for what stayed hidden since the last look and was not reported yet.
    pub fn poll(&mut self) -> Vec<Event> {
        let found = self.hidden();
        let mut out = Vec::new();
        for (key, (text, fields)) in &found {
            if self.suspects.contains(key) && !self.reported.contains(key) {
                out.push(Event {
                    source: "crossview".into(),
                    session_id: String::new(),
                    time: Time::now(),
                    kind: "crossview".into(),
                    text: text.clone(),
                    fields: fields.clone(),
                });
                self.reported.insert(key.clone());
            }
        }
        // what is no longer hidden is forgotten (reported again if it hides again)
        self.reported.retain(|k| found.contains_key(k));
        self.suspects = found.into_keys().collect();
        out
    }
}

impl<V: Views> Source for CrossView<V> {
    fn name(&self) -> &'static str {
        "crossview"
    }
    fn due(&self) -> Option<Instant> {
        Some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        self.next = now + EVERY;
        out.extend(self.poll().into_iter().map(Msg::Event));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Detector;
    use std::cell::RefCell;

    /// A system with a stand-in that hides process 4242 from /proc's listing and socket 99 from /proc/net, from the second
    /// look on (and, for the race, process 77 shows in the cgroups between the two listings, on the first look only).
    #[derive(Default)]
    struct Hiding {
        look: RefCell<u32>,
        hide: bool,
    }

    impl Views for Hiding {
        fn listed_pids(&self) -> BTreeSet<u32> {
            *self.look.borrow_mut() += 1;
            let mut p: BTreeSet<u32> = [1, 300, 4242].into();
            if self.hide {
                p.remove(&4242);
            }
            // 77 starts between the first and the second listing of the first look
            if *self.look.borrow() == 2 {
                p.insert(77);
            }
            p
        }
        fn cgroup_pids(&self) -> BTreeSet<u32> {
            let mut p: BTreeSet<u32> = [1, 300, 4242].into();
            if *self.look.borrow() == 1 {
                p.insert(77);
            }
            p
        }
        fn answers(&self, pid: u32) -> Option<String> {
            [1, 300, 4242, 77].contains(&pid).then(|| if pid == 4242 { "kworkerd".into() } else { "x".into() })
        }
        fn listed_sockets(&self) -> BTreeMap<u64, String> {
            let mut s: BTreeMap<u64, String> = [(10, "tcp 0.0.0.0:22".to_string()), (99, "tcp 0.0.0.0:31337".to_string())].into();
            if self.hide {
                s.remove(&99);
            }
            s
        }
        fn table_sockets(&self) -> std::io::Result<BTreeMap<u64, String>> {
            Ok([(10, "tcp 0.0.0.0:22".to_string()), (99, "tcp 0.0.0.0:31337".to_string())].into())
        }
    }

    fn texts(ev: &[Event]) -> Vec<String> {
        ev.iter().map(|e| format!("{} {} | {}", e.kind, e.f("what"), e.text)).collect()
    }

    /// HEI-50's check: a stand-in that hides a process and a socket gives one critical event for each, after two looks in
    /// a row and once; a process that starts between the listings and one that stops hiding give none.
    #[test]
    fn a_hidden_process_and_socket_are_reported_after_two_looks() {
        let mut cv = CrossView::new(Hiding::default());
        assert!(cv.poll().is_empty(), "nothing hidden, and 77 started between the listings");
        cv.views.hide = true;
        assert!(cv.poll().is_empty(), "one look is not enough");
        let ev = cv.poll();
        assert_eq!(
            texts(&ev),
            [
                "crossview socket | a tcp socket listening on 0.0.0.0:31337 (inode 99) is in the kernel's socket table but not in /proc/net/tcp",
                "crossview process | process 4242 (kworkerd) runs but /proc does not list it",
            ]
        );
        assert_eq!((ev[1].f("pid"), ev[1].f("program"), ev[0].f("inode")), ("4242", "kworkerd", "99"));
        assert!(cv.poll().is_empty(), "once while it stays hidden");
        cv.views.hide = false;
        assert!(cv.poll().is_empty());
        cv.views.hide = true;
        assert!(cv.poll().is_empty());
        assert_eq!(cv.poll().len(), 2, "hidden again: reported again");
        let crit = crate::detect::CrossViewDetector.inspect(&ev[1]);
        assert_eq!(crit.len(), 1);
        assert!(crit[0].summary.contains("rootkit") && crit[0].severity == crate::event::Severity::Critical);
    }

    /// This computer, read only: the two views agree on what has been running for a while (nothing hidden here, and the
    /// netlink dump works without privilege). Two looks a second apart, so short-lived processes and sockets drop out. Tests
    /// never read the real system by default: run it by hand (`cargo test --lib -- --ignored this_computer_hides_nothing`).
    #[test]
    #[ignore = "reads this computer's /proc, cgroups and socket table: run by hand"]
    fn this_computer_hides_nothing() {
        let sys = System { proc_dir: "/proc".into(), cgroup_dir: "/sys/fs/cgroup".into() };
        let table = sys.table_sockets();
        assert!(table.as_ref().is_ok_and(|t| !t.is_empty()), "netlink: {table:?}");
        // the other views really see this computer (an empty cgroup read would agree with anything)
        let (listed, groups) = (sys.listed_pids(), sys.cgroup_pids());
        assert!(
            groups.len() * 2 >= listed.len() && !sys.listed_sockets().is_empty(),
            "{} listed, {} in cgroups",
            listed.len(),
            groups.len()
        );
        let mut cv = CrossView::new(sys);
        cv.poll();
        std::thread::sleep(Duration::from_secs(1));
        assert!(texts(&cv.poll()).is_empty());
    }
}
