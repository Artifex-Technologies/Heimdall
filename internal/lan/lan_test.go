package lan

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// answer builds an mDNS response the way a device sends one (names uncompressed; the parser handles both).
func answer(recs ...[]byte) []byte {
	m := make([]byte, 12)
	m[2] = 0x84
	binary.BigEndian.PutUint16(m[6:], uint16(len(recs)))
	for _, r := range recs {
		m = append(m, r...)
	}
	return m
}

func name(n string) []byte {
	var b []byte
	for _, l := range splitDots(n) {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func splitDots(n string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(n); i++ {
		if i == len(n) || n[i] == '.' {
			out = append(out, n[start:i])
			start = i + 1
		}
	}
	return out
}

func rr(owner string, typ uint16, data []byte) []byte {
	b := name(owner)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = append(b, 0x80, 1, 0, 0, 0x11, 0x94)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func txt(kv ...string) []byte {
	var b []byte
	for _, s := range kv {
		b = append(b, byte(len(s)))
		b = append(b, s...)
	}
	return b
}

func TestParseAndAbsorbAFireTVAnswer(t *testing.T) {
	inst := "amzn.dmgr:0011AABB:xyz:1._amzn-wplay._tcp.local"
	m := answer(
		rr("_amzn-wplay._tcp.local", typePTR, name(inst)),
		rr(inst, typeTXT, txt("a=0", "n=Living Room Fire TV", "s=0")),
		rr(inst, typeSRV, append([]byte{0, 0, 0, 0, 0x1f, 0x90}, name("192-168-1-25.local")...)),
		rr("192-168-1-25.local", typeA, []byte{192, 168, 1, 25}),
		rr("_services._dns-sd._udp.local", typePTR, name("_googlecast._tcp.local")),
	)
	recs, err := parse(m)
	if err != nil || len(recs) != 5 {
		t.Fatalf("parse: %v, %d records", err, len(recs))
	}
	out, types := map[string]*found{}, map[string]bool{}
	absorb(out, types, net.IPv4(192, 168, 1, 25), recs)
	f := out["192.168.1.25"]
	if f == nil || len(f.names) != 1 || f.names[0] != "Living Room Fire TV" {
		t.Fatalf("names = %+v (the id instance and the address-made host name must not count)", f)
	}
	if !f.services["_amzn-wplay._tcp"] || !types["_googlecast._tcp.local"] {
		t.Fatalf("services %v, types %v", f.services, types)
	}
}

func TestACompressedNameIsRead(t *testing.T) {
	// "_ipp._tcp.local" at 12, then a PTR whose target points back into it
	m := answer()
	m = append(m, name("_ipp._tcp.local")...)
	m = binary.BigEndian.AppendUint16(m, typePTR)
	m = append(m, 0, 1, 0, 0, 0, 10)
	target := append([]byte{7}, "Printer"...)
	target = append(target, 0xc0, 12)
	m = binary.BigEndian.AppendUint16(m, uint16(len(target)))
	m = append(m, target...)
	binary.BigEndian.PutUint16(m[6:], 1)
	recs, err := parse(m)
	if err != nil || len(recs) != 1 || recs[0].ptr != "Printer._ipp._tcp.local" {
		t.Fatalf("%v %+v", err, recs)
	}
	// a pointer loop ends instead of spinning
	loop := append(answer(), 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(loop[6:], 1)
	if _, err := parse(loop); err == nil {
		t.Fatal("a name pointing at itself must fail")
	}
}

func TestNamesThatAreNotNames(t *testing.T) {
	for _, c := range []struct {
		n, ip string
		bad   bool
	}{
		{"192-168-1-25", "192.168.1.25", true},
		{"0F1E2D3C4B5A6978", "", true},
		{"02AB34CD56EF", "", true},
		{"amzn.dmgr:00FF:ab:1", "", true},
		{"iPhone-3", "192.168.1.170", false},
		{"Clock-1A2B3C", "192.168.1.212", false},
		{"Cafe", "", false},
	} {
		if got := looksGenerated(c.n, c.ip) || looksID(c.n); got != c.bad {
			t.Errorf("%q: bad = %v, want %v", c.n, got, c.bad)
		}
	}
}

func TestVendorsAndPrivateAddresses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oui.txt")
	os.WriteFile(p, []byte("OUI/MA-L\n\n00-11-22   (hex)\t\tSamsung Electronics Co.,Ltd\n001122     (base 16)\t\tSamsung Electronics Co.,Ltd\n"+
		"AA-BB-CC   (hex)\t\tAmazon Technologies Inc.\n"), 0o644)
	v := vendors(p, []string{"00:11:22:33:44:55", "DA:BB:CC:00:00:01", "A8:BB:CC:00:00:01"})
	if v["00:11:22:33:44:55"] != "Samsung Electronics" || len(v) != 1 {
		t.Fatalf("%v", v)
	}
	if !PrivateMAC("DA:BB:CC:00:00:01") || PrivateMAC("A8:BB:CC:00:00:01") || !PrivateMAC("02:00:00:00:00:00") {
		t.Fatal("the locally administered bit is the second-lowest bit of the first byte")
	}
	if ShortVendor("ASKEY COMPUTER CORP") != "Askey Computer" || ShortVendor("Intel Corporate") != "Intel" {
		t.Fatal(ShortVendor("ASKEY COMPUTER CORP"), ShortVendor("Intel Corporate"))
	}
	if ShortVendor("Amazon Technologies Inc.") != "Amazon" || ShortVendor("Apple, Inc.") != "Apple" {
		t.Fatal(ShortVendor("Amazon Technologies Inc."), ShortVendor("Apple, Inc."))
	}
}

func TestTheFirstScanLearnsLaterOnesReportNewDevices(t *testing.T) {
	n := &Network{UUID: "u"}
	t0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	tv := Device{MAC: "00:11:22:33:44:55", IP: "192.168.1.20", Name: "TV", Names: []string{"TV"}, Kind: "tv"}
	me := Device{MAC: "00:11:22:33:44:66", IP: "192.168.1.30", Kind: "this"}
	if fresh := n.Merge([]Device{tv, me}, t0); len(fresh) != 0 {
		t.Fatalf("first scan reported %v", fresh)
	}
	// the TV misses its announcement next time: its name stays; a phone is new
	phone := Device{MAC: "DA:00:00:00:00:01", IP: "192.168.1.40", PrivateMAC: true, Kind: "private"}
	t1 := t0.Add(5 * time.Minute)
	fresh := n.Merge([]Device{{MAC: tv.MAC, IP: tv.IP, Kind: "other"}, phone}, t1)
	if len(fresh) != 1 || fresh[0].MAC != phone.MAC {
		t.Fatalf("fresh = %v", fresh)
	}
	for _, d := range n.Devices {
		if d.MAC == tv.MAC && (d.Name != "TV" || d.Kind != "tv" || !d.FirstSeen.Equal(t0) || !d.LastSeen.Equal(t1)) {
			t.Fatalf("tv = %+v", d)
		}
	}
	if fresh := n.Merge([]Device{phone}, t1.Add(time.Minute)); len(fresh) != 0 {
		t.Fatal("a known device is not new again")
	}
}

func TestKinds(t *testing.T) {
	for _, c := range []struct {
		d    Device
		want string
	}{
		{Device{Services: []string{"_ipp._tcp"}}, "printer"},
		{Device{Services: []string{"_amzn-wplay._tcp"}, Vendor: "Amazon"}, "tv"},
		{Device{Services: []string{"_googlecast._tcp"}, Name: "Kitchen speaker"}, "speaker"},
		{Device{Services: []string{"_spotify-connect._tcp"}}, "speaker"},
		{Device{Name: "iPhone-3", PrivateMAC: true}, "phone"},
		{Device{Services: []string{"_smb._tcp"}}, "computer"},
		{Device{Vendor: "Espressif"}, "smart"},
		{Device{PrivateMAC: true}, "private"},
		{Device{Vendor: "Samsung Electronics"}, "other"},
	} {
		if got := kindOf(c.d); got != c.want {
			t.Errorf("%+v: %s, want %s", c.d, got, c.want)
		}
	}
}

func TestNetBIOSName(t *testing.T) {
	m := make([]byte, 12+34+4+4+2)
	m[2] = 0x84
	m = append(m, 2)
	entry := func(n string, suffix byte, group bool) []byte {
		b := []byte(n)
		for len(b) < 15 {
			b = append(b, ' ')
		}
		b = append(b, suffix, 0, 0)
		if group {
			b[16] = 0x80
		}
		return b
	}
	m = append(m, entry("WORKGROUP", 0, true)...)
	m = append(m, entry("DESKTOP-A", 0, false)...)
	if got := nbName(m); got != "DESKTOP-A" {
		t.Fatalf("%q", got)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "devices.json")
	s, err := Load(p)
	if err != nil || len(s.Networks) != 0 {
		t.Fatal("a missing file is an empty store")
	}
	s.network("u", "Home").Merge([]Device{{MAC: "00:11:22:33:44:55", Kind: "tv"}}, time.Now())
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	s2, _ := Load(p)
	if len(s2.Networks) != 1 || s2.network("u", "").SSID != "Home" || len(s2.Networks[0].Devices) != 1 {
		t.Fatalf("%+v", s2)
	}
}

func TestDefaultRoute(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	os.WriteFile(filepath.Join(dir, "net/route"), []byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"+
		"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"+
		"wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"), 0o644)
	iface, gw := defaultRoute(dir)
	if iface != "eth0" || gw.String() != "10.0.0.1" {
		t.Fatalf("%s %s (the lowest metric wins)", iface, gw)
	}
}
