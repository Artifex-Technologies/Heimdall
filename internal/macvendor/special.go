package macvendor

// Special is a well-known special address or range: it says what it is for, not who made the device (Rust: src/special.rs).
type Special struct {
	Name  string
	Short string
	value uint64
	bits  uint8
}

func sp(name, short string, mac [6]byte, bits uint8) Special {
	return Special{Name: name, Short: short, value: macValue(mac), bits: bits}
}

// specials, in any order: findSpecial keeps the longest match.
var specials = []Special{
	sp("Broadcast (every device on the link)", "Broadcast", [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 48),
	sp("All zeros (no address)", "No address", [6]byte{0, 0, 0, 0, 0, 0}, 48),
	sp("IPv4 multicast", "IPv4 multicast", [6]byte{0x01, 0x00, 0x5e, 0, 0, 0}, 25),
	sp("Documentation multicast address (RFC 7042)", "Documentation", [6]byte{0x01, 0x00, 0x5e, 0x90, 0x10, 0}, 40),
	sp("IPv6 multicast", "IPv6 multicast", [6]byte{0x33, 0x33, 0, 0, 0, 0}, 16),
	sp("IEEE 802.1 link-local group (bridges do not forward it)", "Link-local group", [6]byte{0x01, 0x80, 0xc2, 0, 0, 0}, 44),
	sp("Spanning Tree Protocol (bridges)", "Spanning Tree", [6]byte{0x01, 0x80, 0xc2, 0, 0, 0x00}, 48),
	sp("Ethernet flow control (pause frames)", "Flow control", [6]byte{0x01, 0x80, 0xc2, 0, 0, 0x01}, 48),
	sp("Slow protocols (LACP, link aggregation)", "LACP", [6]byte{0x01, 0x80, 0xc2, 0, 0, 0x02}, 48),
	sp("802.1X port authentication (EAPOL)", "802.1X", [6]byte{0x01, 0x80, 0xc2, 0, 0, 0x03}, 48),
	sp("LLDP (link layer discovery)", "LLDP", [6]byte{0x01, 0x80, 0xc2, 0, 0, 0x0e}, 48),
	sp("IEEE 802.1 MRP (GARP) group", "MRP group", [6]byte{0x01, 0x80, 0xc2, 0, 0, 0x20}, 44),
	sp("Precision Time Protocol (PTP)", "PTP", [6]byte{0x01, 0x1b, 0x19, 0, 0, 0}, 48),
	sp("Cisco discovery (CDP, VTP)", "Cisco CDP", [6]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}, 48),
	sp("Cisco per-VLAN spanning tree (PVST+)", "Cisco PVST+", [6]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd}, 48),
	sp("VRRP virtual router (IPv4)", "VRRP router", [6]byte{0x00, 0x00, 0x5e, 0x00, 0x01, 0}, 40),
	sp("VRRP virtual router (IPv6)", "VRRP router", [6]byte{0x00, 0x00, 0x5e, 0x00, 0x02, 0}, 40),
	sp("Documentation address (RFC 7042)", "Documentation", [6]byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0}, 40),
	sp("HSRP virtual router (Cisco)", "HSRP router", [6]byte{0x00, 0x00, 0x0c, 0x07, 0xac, 0}, 40),
	sp("HSRP version 2 virtual router (Cisco)", "HSRP router", [6]byte{0x00, 0x00, 0x0c, 0x9f, 0xf0, 0}, 36),
}

// findSpecial is the longest special range the address is in.
func findSpecial(mac [6]byte) *Special {
	v := macValue(mac)
	var best *Special
	for i := range specials {
		s := &specials[i]
		shift := 48 - uint(s.bits)
		if v>>shift == s.value>>shift && (best == nil || s.bits > best.bits) {
			best = s
		}
	}
	return best
}
