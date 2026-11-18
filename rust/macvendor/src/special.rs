//! Well-known special addresses: they say what they are for, not who made the device (Go: internal/macvendor/special.go).

use crate::Mac;

/// A well-known special address or range.
#[derive(Debug, PartialEq, Eq)]
pub struct Special {
    /// What it is, in a sentence fragment ("IPv4 multicast").
    pub name: &'static str,
    /// The short form shown beside an address.
    pub short: &'static str,
    /// The range's first address, as a number (the first byte highest).
    pub(crate) value: u64,
    /// How many leading bits the range covers.
    pub(crate) bits: u8,
}

const fn sp(name: &'static str, short: &'static str, mac: Mac, bits: u8) -> Special {
    let mut value = 0u64;
    let mut i = 0;
    while i < 6 {
        value = value << 8 | mac[i] as u64;
        i += 1;
    }
    Special { name, short, value, bits }
}

/// The table, in any order: [`find`] keeps the longest match.
pub(crate) static SPECIALS: &[Special] = &[
    sp("Broadcast (every device on the link)", "Broadcast", [0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 48),
    sp("All zeros (no address)", "No address", [0, 0, 0, 0, 0, 0], 48),
    sp("IPv4 multicast", "IPv4 multicast", [0x01, 0x00, 0x5e, 0, 0, 0], 25),
    sp("Documentation multicast address (RFC 7042)", "Documentation", [0x01, 0x00, 0x5e, 0x90, 0x10, 0], 40),
    sp("IPv6 multicast", "IPv6 multicast", [0x33, 0x33, 0, 0, 0, 0], 16),
    sp("IEEE 802.1 link-local group (bridges do not forward it)", "Link-local group", [0x01, 0x80, 0xc2, 0, 0, 0], 44),
    sp("Spanning Tree Protocol (bridges)", "Spanning Tree", [0x01, 0x80, 0xc2, 0, 0, 0x00], 48),
    sp("Ethernet flow control (pause frames)", "Flow control", [0x01, 0x80, 0xc2, 0, 0, 0x01], 48),
    sp("Slow protocols (LACP, link aggregation)", "LACP", [0x01, 0x80, 0xc2, 0, 0, 0x02], 48),
    sp("802.1X port authentication (EAPOL)", "802.1X", [0x01, 0x80, 0xc2, 0, 0, 0x03], 48),
    sp("LLDP (link layer discovery)", "LLDP", [0x01, 0x80, 0xc2, 0, 0, 0x0e], 48),
    sp("IEEE 802.1 MRP (GARP) group", "MRP group", [0x01, 0x80, 0xc2, 0, 0, 0x20], 44),
    sp("Precision Time Protocol (PTP)", "PTP", [0x01, 0x1b, 0x19, 0, 0, 0], 48),
    sp("Cisco discovery (CDP, VTP)", "Cisco CDP", [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc], 48),
    sp("Cisco per-VLAN spanning tree (PVST+)", "Cisco PVST+", [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd], 48),
    sp("VRRP virtual router (IPv4)", "VRRP router", [0x00, 0x00, 0x5e, 0x00, 0x01, 0], 40),
    sp("VRRP virtual router (IPv6)", "VRRP router", [0x00, 0x00, 0x5e, 0x00, 0x02, 0], 40),
    sp("Documentation address (RFC 7042)", "Documentation", [0x00, 0x00, 0x5e, 0x00, 0x53, 0], 40),
    sp("HSRP virtual router (Cisco)", "HSRP router", [0x00, 0x00, 0x0c, 0x07, 0xac, 0], 40),
    sp("HSRP version 2 virtual router (Cisco)", "HSRP router", [0x00, 0x00, 0x0c, 0x9f, 0xf0, 0], 36),
];

/// The longest special range the address is in.
pub(crate) fn find(mac: &Mac) -> Option<&'static Special> {
    let v = crate::mac_value(mac);
    let mut best: Option<&'static Special> = None;
    for s in SPECIALS {
        let shift = 48 - s.bits as u32;
        if v >> shift == s.value >> shift && best.is_none_or(|b| s.bits > b.bits) {
            best = Some(s);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_longest_range_wins() {
        assert_eq!(find(&[0x01, 0x80, 0xc2, 0, 0, 0x0e]).unwrap().short, "LLDP");
        assert_eq!(find(&[0x01, 0x80, 0xc2, 0, 0, 0x0f]).unwrap().short, "Link-local group");
        assert_eq!(find(&[0x01, 0x80, 0xc2, 0, 0, 0x10]), None);
        assert_eq!(find(&[0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa]).unwrap().short, "IPv4 multicast");
        // the top bit of the fourth byte is outside the IPv4 range
        assert_eq!(find(&[0x01, 0x00, 0x5e, 0x80, 0, 1]), None);
        assert_eq!(find(&[0x01, 0x00, 0x5e, 0x90, 0x10, 0x01]).unwrap().short, "Documentation");
        assert_eq!(find(&[0x00, 0x00, 0x0c, 0x9f, 0xf1, 0x23]).unwrap().short, "HSRP router");
        assert_eq!(find(&[0x00, 0x00, 0x0c, 0x9f, 0xe1, 0x23]), None);
        // every range starts on its own boundary
        for s in SPECIALS {
            assert_eq!(s.value & ((1u64 << (48 - s.bits)) - 1), 0, "{}", s.name);
        }
    }
}
