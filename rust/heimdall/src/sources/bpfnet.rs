//! eBPF programs attached to network interfaces (HEI-78): XDP on a link, and tc `bpf` filters on its ingress or egress hook.
//! Such a program sees every packet before the firewall and can wait for a secret one with no open port, as some backdoors
//! do (BPFDoor's later versions moved from a socket filter to tc). The kernel tells anyone over rtnetlink, the dumps `ip
//! link` and `tc filter show` make: a link's `IFLA_XDP` names the attached program, and a filter's `TCA_KIND` "bpf" with
//! its `TCA_BPF_ID` and name. Reading the program itself would need CAP_BPF; its id, hook and name are enough to report.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// One program attached: the interface, where (`xdp`, `tc ingress`, `tc egress`), the kernel's program id, and the name the
/// loader gave (tc only; empty when none).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Attached {
    pub iface: String,
    pub hook: String,
    pub id: u32,
    pub name: String,
}

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWQDISC: u16 = 36;
const RTM_GETQDISC: u16 = 38;
const RTM_NEWTFILTER: u16 = 44;
const RTM_GETTFILTER: u16 = 46;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const IFLA_IFNAME: u16 = 3;
const IFLA_XDP: u16 = 43;
const IFLA_XDP_ATTACHED: u16 = 2;
const IFLA_XDP_PROG_ID: u16 = 4;
const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_BPF_NAME: u16 = 7;
const TCA_BPF_ID: u16 = 11;
/// tc's clsact hooks (TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS / EGRESS)); the old `ingress` qdisc answers on the first.
const PARENT_INGRESS: u32 = 0xFFFF_FFF2;
const PARENT_EGRESS: u32 = 0xFFFF_FFF3;

/// The attributes of one message's body after its fixed header: (type without the nested flag, data).
pub fn attrs(mut b: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let kind = u16::from_ne_bytes([b[2], b[3]]) & 0x3FFF;
        if len < 4 || len > b.len() {
            break;
        }
        out.push((kind, &b[4..len]));
        b = &b[((len + 3) & !3).min(b.len())..];
    }
    out
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b.split(|c| *c == 0).next().unwrap_or(&[])).into_owned()
}

fn u32_of(b: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(..4)?.try_into().ok()?))
}

/// A link message's body (after the 16-byte ifinfomsg): its name and its XDP program, when one is attached.
pub fn link_xdp(body: &[u8]) -> Option<(i32, String, Option<u32>)> {
    let index = i32::from_ne_bytes(body.get(4..8)?.try_into().ok()?);
    let mut name = String::new();
    let mut prog = None;
    for (k, v) in attrs(body.get(16..)?) {
        match k {
            IFLA_IFNAME => name = text(v),
            IFLA_XDP => {
                let x = attrs(v);
                let attached = x.iter().find(|(k, _)| *k == IFLA_XDP_ATTACHED).and_then(|(_, v)| v.first().copied()).unwrap_or(0);
                if attached != 0 {
                    prog = Some(x.iter().find(|(k, _)| *k == IFLA_XDP_PROG_ID).and_then(|(_, v)| u32_of(v)).unwrap_or(0));
                }
            }
            _ => {}
        }
    }
    Some((index, name, prog))
}

/// A qdisc's or filter's interface index, kind, and (for a `bpf` filter) its program id and name.
pub type TcEntry = (i32, String, Option<(u32, String)>);

/// A qdisc or filter message's body (after the 20-byte tcmsg): its interface index, its kind, and for a `bpf` filter its
/// program id and name.
pub fn tc_entry(body: &[u8]) -> Option<TcEntry> {
    let index = i32::from_ne_bytes(body.get(4..8)?.try_into().ok()?);
    let mut kind = String::new();
    let mut bpf = None;
    for (k, v) in attrs(body.get(20..)?) {
        match k {
            TCA_KIND => kind = text(v),
            TCA_OPTIONS => {
                let o = attrs(v);
                let id = o.iter().find(|(k, _)| *k == TCA_BPF_ID).and_then(|(_, v)| u32_of(v));
                let name = o.iter().find(|(k, _)| *k == TCA_BPF_NAME).map(|(_, v)| text(v)).unwrap_or_default();
                if id.is_some() || !name.is_empty() {
                    bpf = Some((id.unwrap_or(0), name));
                }
            }
            _ => {}
        }
    }
    let bpf = bpf.filter(|_| kind == "bpf");
    Some((index, kind, bpf))
}

/// One rtnetlink dump: `kind` with `header` (the request's fixed part); each answer message's type and body.
fn dump(kind: u16, header: &[u8]) -> std::io::Result<Vec<(u16, Vec<u8>)>> {
    // SAFETY: plain socket(2); the descriptor is owned from here on
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a socket this function just opened and nothing else owns
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = vec![0u8; 16];
    req.extend_from_slice(header);
    let len = req.len() as u32;
    req[0..4].copy_from_slice(&len.to_ne_bytes());
    req[4..6].copy_from_slice(&kind.to_ne_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes());
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
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: buf is live and writable for its length
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
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
            let t = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if len < 16 || off + len > n {
                return Err(std::io::Error::other("a garbled netlink answer"));
            }
            match t {
                NLMSG_DONE => return Ok(out),
                NLMSG_ERROR => {
                    let code = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap_or([0; 4]));
                    // an interface with no filters, or no clsact hook, answers with an error: nothing there
                    return if code == 0 { Ok(out) } else { Err(std::io::Error::from_raw_os_error(-code)) };
                }
                _ => out.push((t, buf[off + 16..off + len].to_vec())),
            }
            off += (len + 3) & !3;
        }
    }
}

fn tcmsg(index: i32, parent: u32) -> Vec<u8> {
    let mut h = vec![0u8; 20];
    h[4..8].copy_from_slice(&index.to_ne_bytes());
    h[12..16].copy_from_slice(&parent.to_ne_bytes());
    h
}

/// Every program attached to an interface now: XDP from the link dump, tc `bpf` filters on the interfaces that have an
/// ingress or clsact hook (a qdisc of that kind; most computers have none, so there is usually nothing more to ask).
pub fn attached() -> std::io::Result<Vec<Attached>> {
    let mut out = Vec::new();
    let mut names = std::collections::BTreeMap::new();
    for (t, body) in dump(RTM_GETLINK, &[0u8; 16])? {
        if t != RTM_NEWLINK {
            continue;
        }
        if let Some((index, name, prog)) = link_xdp(&body) {
            if let Some(id) = prog {
                out.push(Attached { iface: name.clone(), hook: "xdp".into(), id, name: String::new() });
            }
            names.insert(index, name);
        }
    }
    let hooked: Vec<i32> = dump(RTM_GETQDISC, &[0u8; 20])?
        .into_iter()
        .filter(|(t, _)| *t == RTM_NEWQDISC)
        .filter_map(|(_, b)| tc_entry(&b))
        .filter(|(_, kind, _)| kind == "clsact" || kind == "ingress")
        .map(|(i, _, _)| i)
        .collect();
    for index in hooked {
        for (parent, hook) in [(PARENT_INGRESS, "tc ingress"), (PARENT_EGRESS, "tc egress")] {
            let Ok(filters) = dump(RTM_GETTFILTER, &tcmsg(index, parent)) else { continue };
            for (_, b) in filters.into_iter().filter(|(t, _)| *t == RTM_NEWTFILTER) {
                if let Some((_, _, Some((id, name)))) = tc_entry(&b) {
                    let iface = names.get(&index).cloned().unwrap_or_else(|| format!("#{index}"));
                    out.push(Attached { iface, hook: hook.into(), id, name });
                }
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut a = ((4 + data.len()) as u16).to_ne_bytes().to_vec();
        a.extend_from_slice(&kind.to_ne_bytes());
        a.extend_from_slice(data);
        while a.len() % 4 != 0 {
            a.push(0);
        }
        a
    }

    /// The kernel's answers as recorded shapes: a link with an XDP program (nested, the nested flag set), one without, and
    /// a tc bpf filter with its id and name, beside a filter of another kind.
    #[test]
    fn recorded_answers_read() {
        let mut link = vec![0u8; 16];
        link[4..8].copy_from_slice(&3i32.to_ne_bytes());
        link.extend(attr(IFLA_IFNAME, b"wlan0\0"));
        let xdp = [attr(IFLA_XDP_ATTACHED, &[1]), attr(IFLA_XDP_PROG_ID, &42u32.to_ne_bytes())].concat();
        link.extend(attr(IFLA_XDP | 0x8000, &xdp));
        assert_eq!(link_xdp(&link), Some((3, "wlan0".to_string(), Some(42))));
        let mut plain = vec![0u8; 16];
        plain.extend(attr(IFLA_IFNAME, b"lo\0"));
        plain.extend(attr(IFLA_XDP | 0x8000, &attr(IFLA_XDP_ATTACHED, &[0])));
        assert_eq!(link_xdp(&plain).unwrap().2, None);

        let mut filter = tcmsg(3, PARENT_INGRESS);
        filter.extend(attr(TCA_KIND, b"bpf\0"));
        filter.extend(attr(TCA_OPTIONS | 0x8000, &[attr(TCA_BPF_ID, &7u32.to_ne_bytes()), attr(TCA_BPF_NAME, b"cls_main\0")].concat()));
        assert_eq!(tc_entry(&filter), Some((3, "bpf".to_string(), Some((7, "cls_main".to_string())))));
        let mut other = tcmsg(3, PARENT_INGRESS);
        other.extend(attr(TCA_KIND, b"u32\0"));
        assert_eq!(tc_entry(&other).unwrap().2, None);
        assert!(attrs(&[9, 0]).is_empty(), "a short buffer is nothing");
    }

    /// This computer, read only and without privilege: the dumps answer (what is attached here is not asserted).
    #[test]
    #[ignore = "reads this computer's interfaces over netlink: run by hand"]
    fn this_computer_answers() {
        let a = attached().unwrap();
        eprintln!("{a:?}");
    }
}
