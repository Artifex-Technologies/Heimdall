package lan

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// A network trusted but not as home is never looked around: no sweep, no device list (the owner asked for quiet there). The
// levels are heimdall-wifi-guard's; an entry from before them is home, and a level it does not know is untrusted.
func TestATrustedNetworkThatIsNotHomeIsNotScanned(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "proc", "net"), 0o755)
	os.WriteFile(filepath.Join(dir, "proc", "net", "route"), []byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"lan0\t00000000\t010200C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"), 0o644)
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "nmcli"), []byte("#!/bin/sh\nprintf 'u1:lan0:Example-Phone\\n'\n"), 0o755)
	t.Setenv("PATH", bin)
	oldTrusted, oldProc := TrustedPath, ProcRoot
	defer func() { TrustedPath, ProcRoot = oldTrusted, oldProc }()
	TrustedPath, ProcRoot = filepath.Join(dir, "trusted.json"), filepath.Join(dir, "proc")
	for _, c := range []struct{ file, want string }{
		{`{"u1": {"ssid": "Example-Phone", "level": "trusted", "key_mgmt": "sae", "routers": []}}`, "not_home"},
		// a level heimdall-wifi-guard does not know (or an empty, null or odd one) is untrusted there, so here too
		{`{"u1": {"ssid": "Example-Phone", "level": "someday", "routers": ["02:00:00:00:00:01"]}}`, "not_trusted"},
		{`{"u1": {"ssid": "Example-Phone", "level": "", "routers": ["02:00:00:00:00:01"]}}`, "not_trusted"},
		{`{"u1": {"ssid": "Example-Phone", "level": null, "routers": ["02:00:00:00:00:01"]}}`, "not_trusted"},
		{`{"u1": {"ssid": "Example-Phone", "level": 5, "routers": ["02:00:00:00:00:01"]}}`, "not_trusted"},
		{`{"u1": {"ssid": "Example-Phone", "level": ["home"], "routers": ["02:00:00:00:00:01"]}}`, "not_trusted"},
		{`{"u2": {"ssid": "Other", "level": "home", "routers": ["02:00:00:00:00:01"]}}`, "not_trusted"},
	} {
		os.WriteFile(TrustedPath, []byte(c.file), 0o644)
		r, err := Scan(Options{Dir: dir})
		if err != nil || r.Status != c.want {
			t.Errorf("%s: %q %v, want %q", c.file, r.Status, err, c.want)
		}
		st, _ := Load(filepath.Join(dir, "devices.json"))
		if st.Status != c.want || len(st.Networks) != 0 {
			t.Errorf("%s: stored %+v", c.file, st)
		}
	}
}

// TestNameMoves (HEI-21): a hardware address that never had a known device's name and now announces it is reported once,
// as moved when the device that had it is gone and as shared when it is still there; the same device keeping its own name, a
// device renamed to something new, this computer and the first scan are not. The Rust port runs the same table
// (rust/heimdall/src/cli/lan/store.rs, name_moves).
func TestNameMoves(t *testing.T) {
	t0 := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(5 * time.Minute)
	printer := Device{MAC: "00:11:22:00:00:30", IP: "192.0.2.30", Name: "Office-Printer", Names: []string{"Office-Printer"}}
	phone := Device{MAC: "06:00:00:00:00:40", IP: "192.0.2.40", Name: "Phone", Names: []string{"Phone"}}
	known := func() *Network {
		n := &Network{UUID: "u"}
		n.Merge([]Device{printer, phone}, t0)
		return n
	}
	other := "02:00:00:00:00:77"
	for _, c := range []struct {
		name string
		n    *Network
		seen []Device
		want string
	}{
		{"another device takes the printer's name while it is away", known(), []Device{{MAC: other, IP: "192.0.2.77", Name: "office-printer"}, phone},
			"name_moved 02:00:00:00:00:77 00:11:22:00:00:30 Office-Printer"},
		{"another device answers to the printer's name beside it", known(), []Device{{MAC: other, IP: "192.0.2.77", Name: "Office-Printer"}, printer, phone},
			"name_shared 02:00:00:00:00:77 00:11:22:00:00:30 Office-Printer"},
		{"the printer seen without its announcement counts as there", known(), []Device{{MAC: other, IP: "192.0.2.77", Name: "Office-Printer"}, {MAC: printer.MAC, IP: printer.IP}},
			"name_shared 02:00:00:00:00:77 00:11:22:00:00:30 Office-Printer"},
		{"the printer renamed meanwhile: the name moved", known(), []Device{{MAC: other, IP: "192.0.2.77", Name: "Office-Printer"}, {MAC: printer.MAC, IP: printer.IP, Name: "Hall-Printer"}},
			"name_moved 02:00:00:00:00:77 00:11:22:00:00:30 Office-Printer"},
		{"the phone with a new private address", known(), []Device{{MAC: "06:00:00:00:00:41", IP: "192.0.2.41", Name: "Phone"}},
			"name_moved 06:00:00:00:00:41 06:00:00:00:00:40 Phone"},
		{"each device with its own name", known(), []Device{printer, phone}, ""},
		{"a new name", known(), []Device{{MAC: other, IP: "192.0.2.77", Name: "Laptop"}}, ""},
		{"no name", known(), []Device{{MAC: other, IP: "192.0.2.77"}}, ""},
		{"this computer", known(), []Device{{MAC: other, IP: "192.0.2.77", Name: "Phone", Kind: "this"}}, ""},
		{"the first scan", &Network{UUID: "u", Devices: []Device{printer}}, []Device{{MAC: other, IP: "192.0.2.77", Name: "Office-Printer"}}, ""},
	} {
		var got []string
		for _, x := range NameMoves(c.n, "Home", c.seen, t1) {
			got = append(got, strings.Join([]string{x.Change, x.Device.MAC, x.WasMAC, x.WasName}, " "))
		}
		if strings.Join(got, "|") != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// once: after the merge the new hardware address has the name, and the next scan says nothing
	n := known()
	seen := []Device{{MAC: other, IP: "192.0.2.77", Name: "Office-Printer"}, printer}
	if len(NameMoves(n, "Home", seen, t1)) != 1 {
		t.Fatal("the first time")
	}
	n.Merge(seen, t1)
	if got := NameMoves(n, "Home", seen, t1.Add(5*time.Minute)); len(got) != 0 {
		t.Errorf("reported again: %+v", got)
	}
}

// TestTakeovers: a known device's address answered by a hardware address that answers for another address at the same time,
// while the device that had it is gone, is reported; a device that only moved, a new device on a freed address, and the first
// scan are not. The Rust port runs the same table (rust/heimdall/src/cli/lan/store.rs, takeovers).
func TestTakeovers(t *testing.T) {
	t0 := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(5 * time.Minute)
	tv := Device{MAC: "02:00:00:00:00:30", IP: "192.0.2.30", Name: "TV"}
	pc := Device{MAC: "02:00:00:00:00:66", IP: "192.0.2.66"}
	known := func() *Network {
		n := &Network{UUID: "u"}
		n.Merge([]Device{tv, pc}, t0)
		return n
	}
	for _, c := range []struct {
		name string
		n    *Network
		seen []Device
		want string
	}{
		{"the PC answers for the TV's address too", known(), []Device{{MAC: pc.MAC, IP: tv.IP}, pc}, "192.0.2.30 02:00:00:00:00:66 02:00:00:00:00:30 TV 192.0.2.66"},
		{"the TV still answers elsewhere: it moved", known(), []Device{{MAC: pc.MAC, IP: tv.IP}, pc, {MAC: tv.MAC, IP: "192.0.2.31"}}, ""},
		{"a new device on the TV's address", known(), []Device{{MAC: "02:00:00:00:00:77", IP: tv.IP}, pc}, ""},
		{"the first scan", &Network{UUID: "u"}, []Device{{MAC: pc.MAC, IP: tv.IP}, pc}, ""},
	} {
		var got []string
		for _, x := range Takeovers(c.n, "Home", c.seen, t1) {
			got = append(got, strings.Join([]string{x.Device.IP, x.Device.MAC, x.WasMAC, x.WasName, x.OtherIP}, " "))
		}
		if strings.Join(got, "|") != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
