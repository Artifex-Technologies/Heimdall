package lan

// The device list's behaviour for the Rust port (rust/heimdall/tests/cli_lan.rs): go test ./internal/lan -update writes
// testdata/parity/cli-lan.json from the functions below on hand-made and generated inputs (a fixed seed); without -update the
// file must be what this code says. Bytes that may not be UTF-8 are written as hex.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/parity/cli-lan.json")

type pRecord struct {
	Name string   `json:"name"`
	Type uint16   `json:"type"`
	Ptr  string   `json:"ptr"`
	IP   string   `json:"ip"`
	TXT  []string `json:"txt"`
	Port uint16   `json:"port"`
}

func hexs(s string) string { return hex.EncodeToString([]byte(s)) }

func precs(recs []record) []pRecord {
	out := []pRecord{}
	for _, r := range recs {
		p := pRecord{Name: hexs(r.name), Type: r.rtype, Ptr: hexs(r.ptr), IP: hex.EncodeToString(r.ip), Port: r.port, TXT: []string{}}
		for _, t := range r.txt {
			p.TXT = append(p.TXT, hexs(t))
		}
		out = append(out, p)
	}
	return out
}

func errs(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type pFound struct {
	Names    []string `json:"names"`
	Model    string   `json:"model"`
	Services []string `json:"services"`
}

type pAnswer struct {
	From string `json:"from"`
	M    string `json:"m"`
}

// gen makes hostile inputs from a fixed seed.
type gen struct{ r *rand.Rand }

var labelBits = []string{"_ipp", "_tcp", "_udp", "local", "_googlecast", "_amzn-wplay", "_raop", "_airplay", "_device-info", "_services",
	"_dns-sd", "Living Room", "TV", "a1b2c3d4e5f6@Kitchen", "Printer", "198-51-100-25", "Fire TV", "\xff\xfe", "Ⱥ", "İ", "K", "ſ", "ß",
	"\x00", "\u200b", "a.b", "", "  ", "_matter", "_spotify-connect", "Σ", "é", "@", "x"}

func (g gen) pick(xs []string) string { return xs[g.r.Intn(len(xs))] }

func (g gen) name() []byte {
	var b []byte
	n := g.r.Intn(5)
	for i := 0; i < n; i++ {
		l := g.pick(labelBits)
		if len(l) > 63 {
			l = l[:63]
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	if g.r.Intn(6) == 0 {
		return append(b, 0xc0, byte(g.r.Intn(64)))
	}
	return append(b, 0)
}

func (g gen) message() []byte {
	m := make([]byte, 12)
	if g.r.Intn(10) != 0 {
		m[2] = 0x84
	}
	qd := g.r.Intn(2)
	m[5] = byte(qd)
	for i := 0; i < qd; i++ {
		m = append(m, g.name()...)
		m = append(m, 0, 12, 0, 1)
	}
	n := g.r.Intn(6)
	m[7] = byte(n + g.r.Intn(2))
	for i := 0; i < n; i++ {
		m = append(m, g.name()...)
		t := []uint16{typeA, typePTR, typeSRV, typeTXT, typeAAAA, 99}[g.r.Intn(6)]
		var data []byte
		switch t {
		case typeA:
			data = []byte{192, 0, 2, byte(g.r.Intn(256))}
		case typeAAAA:
			data = make([]byte, 16)
		case typePTR:
			data = g.name()
		case typeSRV:
			data = append([]byte{0, 0, 0, 0, 0x1f, 0x90}, g.name()...)
		case typeTXT:
			for k := g.r.Intn(4); k > 0; k-- {
				kv := g.pick([]string{"fn=", "n=", "md=", "model=", "am=", "ty=", "dn=", "FN=", "x="}) + g.pick(labelBits)
				data = append(data, byte(len(kv)))
				data = append(data, kv...)
			}
		default:
			data = []byte{1, 2, 3}
		}
		if g.r.Intn(8) == 0 && len(data) > 0 {
			data = data[:g.r.Intn(len(data))]
		}
		m = append(m, byte(t>>8), byte(t), 0x80, 1, 0, 0, 0x11, 0x94, byte(len(data)>>8), byte(len(data)))
		m = append(m, data...)
	}
	switch g.r.Intn(6) {
	case 0:
		m = m[:g.r.Intn(len(m)+1)]
	case 1:
		if len(m) > 12 {
			m[12+g.r.Intn(len(m)-12)] = byte(g.r.Intn(256))
		}
	}
	return m
}

func (g gen) text() string {
	parts := []string{"Living Room TV", " ", "\t", "\x00", "\x7f", "\u200b", "\u202e", "\u2066", "\u00a0", "\u3000", "198", "51", "100", "25",
		"-", ":", "0F1E2D3C", "4B5A6978", "abc", "DEF", "é", "\xff", "Ⱥ", "K", "host", "dhcp", ".", "iPhone", "x"}
	var b strings.Builder
	for n := g.r.Intn(8); n > 0; n-- {
		b.WriteString(g.pick(parts))
	}
	return b.String()
}

func (g gen) device() Device {
	words := []string{"", "Samsung", "LG Electronics", "Sony", "Kitchen speaker", "Nest Audio", "Home Mini", "iPhone", "iPad", "Android",
		"Galaxy", "Pixel", "MacBook", "DESKTOP-1", "Laptop", "Xbox", "PlayStation", "Nintendo", "Espressif", "Tuya", "Shelly", "Wyze",
		"Ring", "ecobee", "Nest Labs", "Signify", "TV", "tv box", "Fire TV", "Roku", "Amazon", "NVIDIA", "Sharp", "Philips", "TCL"}
	services := []string{"_ipp._tcp", "_printer._tcp", "_ipps._tcp", "_pdl-datastream._tcp", "_googlecast._tcp", "_amzn-wplay._tcp",
		"_androidtvremote2._tcp", "_airplay._tcp", "_sonos._tcp", "_spotify-connect._tcp", "_raop._tcp", "_workstation._tcp",
		"_companion-link._tcp", "_smb._tcp", "_ssh._tcp", "_hap._tcp", "_matter._tcp"}
	d := Device{Name: g.pick(words), Model: g.pick(words), Vendor: g.pick(words), PrivateMAC: g.r.Intn(3) == 0}
	for n := g.r.Intn(3); n > 0; n-- {
		d.Services = append(d.Services, g.pick(services))
	}
	return d
}

func TestRustFixture(t *testing.T) {
	g := gen{rand.New(rand.NewSource(20261110))}
	out := map[string]any{"format": "heimdall-cli-lan/1", "from": "internal/lan (go test ./internal/lan -update)"}

	// the DNS codec
	type pMsg struct {
		M    string    `json:"m"`
		Recs []pRecord `json:"recs"`
		Err  string    `json:"err"`
	}
	var msgs []pMsg
	add := func(m []byte) {
		recs, err := parse(m)
		msgs = append(msgs, pMsg{hex.EncodeToString(m), precs(recs), errs(err)})
	}
	inst := "amzn.dmgr:0011AABB:xyz:1._amzn-wplay._tcp.local"
	add(answer(rr("_amzn-wplay._tcp.local", typePTR, name(inst)), rr(inst, typeTXT, txt("a=0", "n=Living Room Fire TV", "s=0")),
		rr(inst, typeSRV, append([]byte{0, 0, 0, 0, 0x1f, 0x90}, name("198-51-100-25.local")...)),
		rr("198-51-100-25.local", typeA, []byte{198, 51, 100, 25}), rr("_services._dns-sd._udp.local", typePTR, name("_googlecast._tcp.local"))))
	add(nil)
	add(make([]byte, 12))
	for i := 0; i < 700; i++ {
		add(g.message())
	}
	out["messages"] = msgs

	type pName struct {
		M, Name, Err string
		Off, End     int
	}
	var names []pName
	for i := 0; i < 200; i++ {
		m := g.message()
		off := 12
		if len(m) > 0 {
			off = g.r.Intn(len(m) + 2)
		}
		n, end, err := readName(m, off)
		names = append(names, pName{M: hex.EncodeToString(m), Off: off, Name: hexs(n), End: end, Err: errs(err)})
	}
	out["names"] = names

	type pQuery struct {
		Names []string `json:"names"`
		Q     string   `json:"q"`
	}
	var queries []pQuery
	for _, ns := range [][]string{append([]string{"_services._dns-sd._udp.local"}, commonTypes[:11]...), commonTypes[11:], {"_x._tcp.local."}, {""}} {
		queries = append(queries, pQuery{ns, hex.EncodeToString(query(ns))})
	}
	out["queries"] = queries

	// absorb: answers from a few addresses in turn
	type pAbsorb struct {
		Answers []pAnswer         `json:"answers"`
		Found   map[string]pFound `json:"found"`
		Types   []string          `json:"types"`
	}
	var absorbs []pAbsorb
	froms := []string{"192.0.2.5", "192.0.2.6", "192.0.2.25", "2001:db8::1"}
	for i := 0; i < 300; i++ {
		var a pAbsorb
		found, types := map[string]*found{}, map[string]bool{}
		for n := 1 + g.r.Intn(3); n > 0; n-- {
			m := g.message()
			if i < 3 {
				m, _ = hex.DecodeString(msgs[0].M)
			}
			from := g.pick(froms)
			a.Answers = append(a.Answers, pAnswer{from, hex.EncodeToString(m)})
			recs, _ := parse(m)
			func() {
				defer func() { recover() }() // instanceName can panic in Go; the Rust port leaves such a name out
				absorb(found, types, net.ParseIP(from), recs)
			}()
		}
		a.Found = map[string]pFound{}
		for ip, f := range found {
			p := pFound{Names: append([]string{}, f.names...), Model: f.model, Services: []string{}}
			for s := range f.services {
				p.Services = append(p.Services, s)
			}
			sort.Strings(p.Services)
			a.Found[ip] = p
		}
		a.Types = []string{}
		for t := range types {
			a.Types = append(a.Types, t)
		}
		sort.Strings(a.Types)
		absorbs = append(absorbs, a)
	}
	out["absorb"] = absorbs

	// the name rules
	type pStr struct{ In, Out string }
	var st, cl []pStr
	for _, s := range []string{"living room._airplay._tcp.local", "_x._udp", "a._tcp", "_a._b", "_ipp._tcp.local.", "", "_a._tcp._b._udp"} {
		st = append(st, pStr{s, serviceType(s)})
	}
	out["service_type"] = st
	type pInst struct {
		Full, Typ, Out string
		Panic          bool
	}
	var insts []pInst
	for i := 0; i < 300; i++ {
		typ := g.pick([]string{"_ipp._tcp", "_raop._tcp", "_googlecast._tcp", "_matter._tcp", "_airplay._tcp", "_device-info._tcp"})
		full := g.text() + g.pick([]string{"@", "", "Ⱥ", "\xff\xff\xff"}) + g.text() + "." + g.pick([]string{typ, strings.ToUpper(typ), "_other._tcp"}) + g.pick([]string{".local", ""})
		p := pInst{Full: hexs(full), Typ: typ}
		func() {
			defer func() {
				if recover() != nil {
					p.Panic = true
				}
			}()
			p.Out = hexs(instanceName(full, typ))
		}()
		insts = append(insts, p)
	}
	// where lowercasing makes the name longer than the part after the type, Go slices past the end and panics
	for _, full := range []string{strings.Repeat("\xff", 20) + "._ipp._tcp", strings.Repeat("Ⱥ", 12) + "._ipp._tcp", "\xff._ipp._tcp.local", "Ⱥ._ipp._tcp"} {
		p := pInst{Full: hexs(full), Typ: "_ipp._tcp"}
		func() {
			defer func() {
				if recover() != nil {
					p.Panic = true
				}
			}()
			p.Out = hexs(instanceName(full, "_ipp._tcp"))
		}()
		insts = append(insts, p)
	}
	out["instance"] = insts
	type pBool struct {
		N, IP string
		Out   bool
	}
	var gens, ids []pBool
	for i := 0; i < 400; i++ {
		s := g.text()
		cl = append(cl, pStr{hexs(s), clean(s)})
		c := clean(s)
		ip := g.pick([]string{"198.51.100.25", "192.0.2.170", "203.0.113.1", ""})
		gens = append(gens, pBool{c, ip, looksGenerated(c, ip)})
		ids = append(ids, pBool{N: c, Out: looksID(c)})
	}
	out["clean"], out["generated"], out["id"] = cl, gens, ids

	var nbs []pStr
	entry := func(n string, suffix byte, group bool) []byte {
		b := []byte(n)
		for len(b) < 15 {
			b = append(b, ' ')
		}
		b = append(b[:15], suffix, 0, 0)
		if group {
			b[16] = 0x80
		}
		return b
	}
	for i := 0; i < 200; i++ {
		m := make([]byte, 12+34+4+4+2)
		if g.r.Intn(8) != 0 {
			m[2] = 0x84
		}
		k := g.r.Intn(4)
		m = append(m, byte(k+g.r.Intn(2)))
		for j := 0; j < k; j++ {
			m = append(m, entry(g.text()+"\x00 ", byte(g.r.Intn(2)*0x20), g.r.Intn(2) == 0)...)
		}
		if g.r.Intn(5) == 0 {
			m = m[:g.r.Intn(len(m)+1)]
		}
		nbs = append(nbs, pStr{hex.EncodeToString(m), nbName(m)})
	}
	out["nbname"] = nbs

	type pKind struct {
		Device Device `json:"device"`
		Out    string `json:"out"`
	}
	var kinds []pKind
	for i := 0; i < 600; i++ {
		d := g.device()
		kinds = append(kinds, pKind{d, kindOf(d)})
	}
	out["kind"] = kinds

	// Merge: a network through several scans
	type pMerge struct {
		Network json.RawMessage `json:"network"`
		Seen    []Device        `json:"seen"`
		Now     time.Time       `json:"now"`
		After   string          `json:"after"`
		Fresh   string          `json:"fresh"`
	}
	var merges []pMerge
	t0 := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	macs := []string{"00:00:5E:00:53:01", "00:00:5E:00:53:02", "06:00:00:00:00:03", "00:00:5E:00:53:04", "00:00:5e:00:53:05"}
	for i := 0; i < 30; i++ {
		var n Network
		if i%3 == 1 {
			n = Network{UUID: "u", SSID: "Home", Devices: []Device{}}
		} else if i%3 == 2 {
			n = Network{UUID: "u", FirstScan: t0.Add(-time.Hour), LastScan: t0.Add(-time.Minute), Devices: []Device{{MAC: macs[0], Name: "Old", Names: []string{"Old"}, Kind: "tv", Vendor: "V", Model: "M", Services: []string{"_x._tcp"}, FirstSeen: t0.Add(-time.Hour).In(time.FixedZone("", 3600))}}}
		}
		for step := 0; step < 4; step++ {
			before, _ := json.Marshal(n)
			var seen []Device
			for k := g.r.Intn(4); k > 0; k-- {
				d := g.device()
				d.MAC, d.IP, d.Kind = g.pick(macs), fmt.Sprintf("192.0.2.%d", g.r.Intn(9)), g.pick([]string{"other", "private", "tv", "this", "router", ""})
				if g.r.Intn(2) == 0 {
					d.Name, d.Names = "", nil
				}
				seen = append(seen, d)
			}
			now := t0.Add(time.Duration(i*10+step) * time.Minute)
			fresh := n.Merge(seen, now)
			after, _ := json.MarshalIndent(n, "", " ")
			fr, _ := json.Marshal(fresh)
			merges = append(merges, pMerge{before, seen, now, string(after), string(fr)})
		}
	}
	out["merge"] = merges

	// /proc/net/route and /proc/net/arp
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	type pRoute struct{ Text, Iface, GW string }
	var routes []pRoute
	head := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	for i := 0; i < 120; i++ {
		text := head
		for k := g.r.Intn(4); k > 0; k-- {
			text += fmt.Sprintf("%s\t%s\t%s\t0003\t0\t0\t%s\t%s\t0\t0\t0\n", g.pick([]string{"wlan0", "eth0", "lan0"}), g.pick([]string{"00000000", "006433C6"}),
				g.pick([]string{"016433C6", "017100CB", "00000000", "zz", "1FFFFFFFF", "017100CBg", "0x01"}), g.pick([]string{"600", "100", "-5", "0x10", "x", "7"}),
				g.pick([]string{"00000000", "00FFFFFF"}))
		}
		os.WriteFile(filepath.Join(dir, "net/route"), []byte(text), 0o644)
		iface, gw := defaultRoute(dir)
		gws := ""
		if gw != nil {
			gws = gw.String()
		}
		routes = append(routes, pRoute{text, iface, gws})
	}
	out["route"] = routes
	type pArp struct {
		Text, Iface string
		Out         map[string]string
	}
	var arps []pArp
	for i := 0; i < 60; i++ {
		text := "IP address       HW type     Flags       HW address            Mask     Device\n"
		for k := g.r.Intn(5); k > 0; k-- {
			text += fmt.Sprintf("192.0.2.%d %s %s %s * %s\n", g.r.Intn(6), "0x1", g.pick([]string{"0x2", "0x0", "0x6"}),
				g.pick([]string{"00:00:5e:00:53:01", "00:00:00:00:00:00", "06:aa:bb:cc:dd:ee"}), g.pick([]string{"lan0", "wlan0"}))
		}
		os.WriteFile(filepath.Join(dir, "net/arp"), []byte(text), 0o644)
		arps = append(arps, pArp{text, "lan0", arpTable(dir, "lan0")})
	}
	out["arp"] = arps

	// the makers
	oui := "OUI/MA-L\n\n00-11-22   (hex)\t\tSamsung Electronics Co.,Ltd\n001122     (base 16)\t\tSamsung Electronics Co.,Ltd\n" +
		"AA-BB-CC   (hex)\t\tAmazon Technologies Inc.\n00-00-5E   (hex)\t\tEXAMPLE DEVICES CORP\r\n00-11-23   (hex)\t\tÉcole ÉLECTRONIQUE\n" +
		"00-11-24   (hex)\t\t  Intel Corporate  \n"
	os.WriteFile(filepath.Join(dir, "oui.txt"), []byte(oui), 0o644)
	type pOUI struct {
		Text string            `json:"text"`
		Macs []string          `json:"macs"`
		Out  map[string]string `json:"out"`
	}
	ouiMacs := []string{"00:11:22:33:44:55", "DA:BB:CC:00:00:01", "AA:BB:CC:00:00:01", "00:00:5e:00:53:01", "00:11:23:00:00:01", "00:11:24:00:00:01", "0", "zz:zz:zz:00"}
	out["oui"] = []pOUI{{oui, ouiMacs, vendors(filepath.Join(dir, "oui.txt"), ouiMacs)}}
	var privs []pBool
	for _, m := range append(ouiMacs, "", "0", "2", "Ⱥ:00", "1E:00", "0e:00", "f2") {
		privs = append(privs, pBool{N: m, Out: PrivateMAC(m)})
	}
	out["private"] = privs
	var shorts []pStr
	for _, s := range []string{"ASKEY COMPUTER CORP", "Intel Corporate", "Amazon Technologies Inc.", "Apple, Inc.", "ÉCOLE ÉLECTRONIQUE", "Co.,Ltd X",
		"A.", "ABCD", "ABCDE", "SAMSUNG ELECTRO-MECHANICS(THAILAND)", "  Cisco Systems, Inc  ", "Foo GmbH Bar Ltd", "ǅ ǈ", "ﬃ ABC"} {
		shorts = append(shorts, pStr{s, ShortVendor(s)})
	}
	out["short"] = shorts

	// the store as Load reads it and Save writes it back
	type pStore struct{ In, Out, Err string }
	var stores []pStore
	docs := []string{"", "{}", "null", "[]", "{\"networks\": null}", "{\"networks\": []}", "{\"Networks\": [{\"UUID\": \"u\", \"devices\": []}], \"status\": \"scanned\"}",
		"{\"networks\": [{\"uuid\": \"u\", \"ssid\": \"Home <&>\", \"first_scan\": \"2026-11-07T10:00:00+01:00\", \"last_scan\": \"2026-11-07T10:05:00.5Z\", \"devices\": [{\"mac\": \"00:00:5E:00:53:01\", \"ip\": \"192.0.2.1\", \"names\": [], \"kind\": \"router\", \"private_mac\": false, \"extra\": 1}]}], \"status_time\": \"0001-01-01T00:00:00Z\"}",
		"{\"networks\": [{\"devices\": [{\"mac\": 5}]}]}", "{\"networks\": \"x\"}", "{\"status\": \"a\", \"status\": \"b\"}", "{\"status\": \"\\ud800\"}",
		"{\"networks\": [{\"last_scan\": \"not a time\"}]}", "{} x", "{\"status\": \"x\"", "\xff"}
	for _, d := range docs {
		p := filepath.Join(dir, "devices.json")
		os.WriteFile(p, []byte(d), 0o640)
		s, err := Load(p)
		b, _ := json.MarshalIndent(s, "", " ")
		stores = append(stores, pStore{hexs(d), string(b), errs(err)})
	}
	out["store"] = stores

	// wifi-trusted.json as the scan reads it
	type pTrusted struct {
		In  string                `json:"in"`
		Out map[string]trustedNet `json:"out"`
	}
	var trusts []pTrusted
	for _, d := range []string{"{\"u1\": {\"ssid\": \"Home\", \"routers\": [\"00:00:5e:00:53:01\"]}}", "{\"u1\": 5, \"u2\": {\"SSID\": \"x\"}}", "[]", "null", "{",
		"{\"u\": {\"ssid\": \"a\", \"routers\": [\"x\"]}, \"u\": {\"ssid\": \"b\"}}", "{\"u\": {\"routers\": [1, \"y\"]}}"} {
		m := map[string]trustedNet{}
		_ = json.Unmarshal([]byte(d), &m)
		trusts = append(trusts, pTrusted{d, m})
	}
	out["trusted"] = trusts

	// nmcli's answer, through a fake nmcli on the PATH
	type pNM struct{ Out, Iface, UUID, Name string }
	var nms []pNM
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	for _, o := range []string{"u1:lan0:Home\n", "u0:wlan0:Other\nu1:lan0:Ho\\:me\\\\x\nu2:lan0:Second\n", "", "u1:lan0\n", "u1:lan0:a:b\n"} {
		os.WriteFile(filepath.Join(bin, "nmcli"), []byte("#!/bin/sh\nprintf '%s' '"+strings.ReplaceAll(o, "'", "'\\''")+"'\n"), 0o755)
		u, n := activeConnection("lan0")
		nms = append(nms, pNM{o, "lan0", u, n})
	}
	out["nmcli"] = nms

	// EqualFold, as containsFold uses it
	type pFold struct {
		A, B string
		Out  bool
	}
	var folds []pFold
	for _, p := range [][2]string{{"Router", "rOUTER"}, {"K", "k"}, {"ſ", "S"}, {"Σ", "ς"}, {"ı", "I"}, {"İ", "i"}, {"ß", "ẞ"}, {"ǅ", "ǆ"},
		{"00:00:5e:00:53:01", "00:00:5E:00:53:01"}, {"ab", "a"}, {"Ω", "ω"}, {"Ω", "ω"}, {"µ", "Μ"}, {"ﬃ", "FFI"}} {
		folds = append(folds, pFold{p[0], p[1], strings.EqualFold(p[0], p[1])})
	}
	for i := 0; i < 200; i++ {
		a := g.text()
		b := strings.ToUpper(a)
		if i%2 == 0 {
			b = strings.ToLower(a)
		}
		folds = append(folds, pFold{clean(a), clean(b), strings.EqualFold(clean(a), clean(b))})
	}
	out["fold"] = folds

	// events.jsonl lines
	ev := filepath.Join(dir, "events.jsonl")
	os.Remove(ev)
	appendEvents(ev, "Home <&>", []Device{{MAC: "06:00:00:00:00:05", IP: "192.0.2.5", Kind: "private", PrivateMAC: true, FirstSeen: t0, LastSeen: t0}, {MAC: "00:00:5E:00:53:02", Names: []string{"TV\u2028"}, Name: "TV\u2028"}}, t0)
	evb, _ := os.ReadFile(ev)
	out["events"] = string(evb)

	var b bytes.Buffer
	b.WriteString("{")
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "\n %q: ", k)
		if list, ok := toList(out[k]); ok {
			b.WriteString("[")
			for j, x := range list {
				if j > 0 {
					b.WriteString(",")
				}
				xb, err := json.Marshal(x)
				if err != nil {
					t.Fatal(err)
				}
				b.WriteString("\n  ")
				b.Write(xb)
			}
			b.WriteString("\n ]")
		} else {
			xb, _ := json.Marshal(out[k])
			b.Write(xb)
		}
	}
	b.WriteString("\n}\n")
	path, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "parity", "cli-lan.json"))
	if *update {
		if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/lan -update)", err)
	}
	if !bytes.Equal(old, b.Bytes()) {
		t.Error("testdata/parity/cli-lan.json is out of date: run go test ./internal/lan -update and review the diff")
	}
}

// toList turns a slice of any element type into []any, for one element per line.
func toList(v any) ([]any, bool) {
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 || b[0] != '[' {
		return nil, false
	}
	var raw []json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return nil, false
	}
	out := make([]any, len(raw))
	for i, r := range raw {
		out[i] = r
	}
	return out, true
}
