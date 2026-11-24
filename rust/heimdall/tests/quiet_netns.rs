//! The quiet table's input chain on real packets (HEI-19): the guard's own ruleset (`quiet_ruleset`) loaded with nft in a
//! throwaway network namespace (`unshare -rn`: an unprivileged user namespace with its own network, nothing reaches the
//! real one), a veth pair whose receiving end is named like a Wi-Fi interface, and TCP SYNs written by hand onto the other
//! end. The kernel's log of a namespace other than the first is not kept, so the log rules get a counter for the test
//! (nothing else of the ruleset changes) and the counter says how often a rule logged. Skipped where nft, python3 or
//! unprivileged user namespaces are missing.

use heimdall::cli::wifitools::guard::{quiet_ruleset, QUIET};
use std::process::Command;

/// Writes TCP SYNs (Ethernet, IPv6, TCP with a correct checksum: conntrack drops a wrong one as invalid) onto an interface.
/// Arguments: interface, its MAC, the destination MAC, then (source, destination) pairs. (/sys still shows the first network
/// namespace's interfaces in a new one, so the MACs come from `ip`.)
const SEND: &str = r#"
import socket, struct, sys
mac = lambda m: bytes.fromhex(m.replace(":", ""))
ifname, smac, dmac, pairs = sys.argv[1], mac(sys.argv[2]), mac(sys.argv[3]), sys.argv[4:]
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((ifname, 0))
def csum(b):
    if len(b) % 2:
        b += b"\0"
    t = sum(struct.unpack(f"!{len(b)//2}H", b))
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return ~t & 0xFFFF
for i in range(0, len(pairs), 2):
    src, dst = socket.inet_pton(socket.AF_INET6, pairs[i]), socket.inet_pton(socket.AF_INET6, pairs[i + 1])
    tcp = struct.pack("!HHIIBBHHH", 40000 + i, 22, 1000, 0, 5 << 4, 0x02, 64240, 0, 0)
    pseudo = src + dst + struct.pack("!I3xB", len(tcp), 6)
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    ip6 = struct.pack("!IHBB", 6 << 28, len(tcp), 6, 64) + src + dst
    s.send(dmac + smac + struct.pack("!H", 0x86DD) + ip6 + tcp)
"#;

fn usable() -> bool {
    let ok = |c: &mut Command| c.output().is_ok_and(|o| o.status.success());
    ok(Command::new("unshare").args(["-rn", "nft", "list", "tables"])) && ok(Command::new("python3").arg("-c").arg("pass"))
}

#[test]
fn an_ipv6_syn_from_a_link_local_sender_is_logged_once() {
    if !usable() {
        eprintln!("skipped: needs nft, python3 and unprivileged user namespaces (unshare -rn)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("heimdall-quiet-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // the log rules as loaded, each with a counter in front of its log
    let rules = quiet_ruleset(false).replace("limit rate 30/minute log ", "limit rate 30/minute counter log ");
    assert!(rules.matches("counter log").count() >= 2, "{rules}");
    std::fs::write(dir.join("quiet.nft"), &rules).unwrap();
    std::fs::write(dir.join("send.py"), SEND).unwrap();
    let script = r#"
set -e
cd "$1"
ip link add wlq0 type veth peer name src0
ip link set wlq0 up
ip link set src0 up
ip -6 addr add fe80::2/64 dev wlq0 nodad
nft -f quiet.nft
mac() { ip -br link show dev "$1" | awk '{print $3}'; }
# a device on the network (link-local) twice, then one from a global address (not the local network: not this table's)
python3 -I send.py src0 "$(mac src0)" "$(mac wlq0)" fe80::1 fe80::2 fe80::1 fe80::2 2001:db8::5 fe80::2
sleep 0.2
nft list ruleset
"#;
    let out = Command::new("unshare").args(["-rn", "sh", "-c", script, "sh"]).arg(&dir).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}\n{text}", String::from_utf8_lossy(&out.stderr));
    let v6 = text.lines().find(|l| l.contains("meta nfproto ipv6") && l.contains("heimdall-wifi-in: ")).expect("the IPv6 log rule");
    assert!(v6.contains("counter packets 1 "), "logged once, the second SYN accepted as seen: {v6}");
    let v4 = text.lines().find(|l| l.contains("meta nfproto ipv4") && l.contains("heimdall-wifi-in: ")).expect("the IPv4 log rule");
    assert!(v4.contains("counter packets 0 "), "{v4}");
    // the sender is remembered for an hour; the global address is not
    let seen6: String = text.split("set seen6").nth(1).unwrap_or("").split('}').take(2).collect();
    assert!(seen6.contains("fe80::1") && !seen6.contains("2001:db8::5"), "{seen6}");
    assert!(text.contains(&format!("table inet {QUIET}")));
}
