//! The bodies of the device list's fuzz targets (rust/fuzz/fuzz_targets/lan_dns.rs, lan_answer.rs) and of its Kani harness:
//! everything that reads what devices on the network send. They also run in the ordinary tests (tests/cli_lan.rs: seeds,
//! random input, and the harness body exhaustively over small messages), as the daemon's do.

use super::{discover, dns, resolver};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

/// A multicast DNS answer: read, every name at every offset, and what discovery learns from it.
pub fn lan_dns(data: &[u8]) {
    let (recs, _) = dns::parse(data);
    assert!(recs.len() <= 256, "Go reads at most 256 records");
    for off in 0..data.len().min(64) + 2 {
        read_name_bounds(data, off);
    }
    let (mut found, mut types) = (BTreeMap::new(), BTreeSet::new());
    discover::absorb(&mut found, &mut types, Ipv4Addr::new(192, 0, 2, 5), &recs);
    for f in found.values() {
        for n in &f.names {
            assert!(!n.is_empty() && n.chars().count() <= 64, "{n:?}");
            assert!(!n.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}'), "{n:?}");
        }
        assert!(f.model.chars().count() <= 64);
    }
    for r in &recs {
        for typ in ["_ipp._tcp", "_raop._tcp", "_googlecast._tcp"] {
            let _ = discover::instance_name(&r.ptr, typ);
        }
    }
}

/// An answer to a unicast question: the router's reverse name (as Go's resolver judges it) and a NetBIOS node status.
pub fn lan_answer(data: &[u8]) {
    let id = if data.len() >= 2 { u16::from_be_bytes([data[0], data[1]]) } else { 0 };
    for retried in [false, true] {
        if let resolver::Verdict::Names(n) = resolver::judge(data, id, "5.2.0.192.in-addr.arpa.", retried) {
            for x in n {
                assert!(x.ends_with('.') && x.len() <= 256, "{x:?}");
            }
        }
    }
    let n = discover::nb_name(data);
    assert!(n.chars().count() <= 64);
}

/// The harness body: a name read at any offset of any message ends inside the message (no read past its end, no endless
/// pointer loop), and a name that reads is at most what 17 pointers and the labels between them can make.
pub fn read_name_bounds(m: &[u8], off: usize) {
    if let Ok((name, end)) = dns::read_name(m, off) {
        assert!(end <= m.len(), "end {end} past {}", m.len());
        assert!(end > off, "a name that reads ends after where it starts");
        assert!(name.len() <= 18 * m.len(), "{} from {} bytes", name.len(), m.len());
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    #[kani::unwind(24)]
    fn read_name_stays_in_bounds() {
        let m: [u8; 6] = kani::any();
        let off: usize = kani::any();
        kani::assume(off < 8);
        super::read_name_bounds(&m, off);
    }
}
