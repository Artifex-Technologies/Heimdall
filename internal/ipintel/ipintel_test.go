package ipintel

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A tiny database writer, for tests only: an IPv6 tree with 24-bit records, IPv4 under ::/96.

type enc struct{ bytes.Buffer }

func (e *enc) ctrl(typ, size int) {
	c := byte(0)
	if typ <= 7 {
		c = byte(typ << 5)
	}
	if size < 29 {
		c |= byte(size)
		e.WriteByte(c)
		if typ > 7 {
			e.WriteByte(byte(typ - 7))
		}
		return
	}
	e.WriteByte(c | 29)
	if typ > 7 {
		e.WriteByte(byte(typ - 7))
	}
	e.WriteByte(byte(size - 29))
}

func (e *enc) str(s string) { e.ctrl(2, len(s)); e.WriteString(s) }

func (e *enc) uint(typ int, v uint64) {
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	e.ctrl(typ, len(b))
	e.Write(b)
}

func (e *enc) ptr(p int) { e.WriteByte(byte(0x20 | (p >> 8))); e.WriteByte(byte(p)) }

type node [2]int // child node index, or -1 for "no data", or -(k+2) for data record k

func buildDB(t *testing.T, prefixes map[string]int, records []func(e *enc, starts []int)) []byte {
	t.Helper()
	nodes := []node{{-1, -1}}
	for cidr, rec := range prefixes {
		ip, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		ones, _ := n.Mask.Size()
		bits := ip.To16()
		if v4 := ip.To4(); v4 != nil {
			bits = append(make([]byte, 12), v4...)
			ones += 96
		}
		cur := 0
		for k := 0; k < ones; k++ {
			bit := int(bits[k/8]>>(7-uint(k%8))) & 1
			if k == ones-1 {
				nodes[cur][bit] = -(rec + 2)
				break
			}
			if nodes[cur][bit] < 0 {
				nodes = append(nodes, node{-1, -1})
				nodes[cur][bit] = len(nodes) - 1
			}
			cur = nodes[cur][bit]
		}
	}
	var data enc
	starts := make([]int, len(records))
	for i, r := range records {
		starts[i] = data.Len()
		r(&data, starts)
	}
	nc := len(nodes)
	var out bytes.Buffer
	val := func(v int) int {
		switch {
		case v >= 0:
			return v
		case v == -1:
			return nc
		}
		return nc + 16 + starts[-v-2]
	}
	for _, nd := range nodes {
		for _, v := range nd {
			x := val(v)
			out.Write([]byte{byte(x >> 16), byte(x >> 8), byte(x)})
		}
	}
	out.Write(make([]byte, 16))
	out.Write(data.Bytes())
	out.Write(metaMarker)
	var m enc
	m.ctrl(7, 5)
	m.str("node_count")
	m.uint(6, uint64(nc))
	m.str("record_size")
	m.uint(5, 24)
	m.str("ip_version")
	m.uint(5, 6)
	m.str("database_type")
	m.str("test_lite.mmdb")
	m.str("build_epoch")
	m.uint(9, 1761000000)
	out.Write(m.Bytes())
	return out.Bytes()
}

func lite(country, code, asn, name string) func(e *enc, _ []int) {
	return func(e *enc, _ []int) {
		e.ctrl(7, 4)
		e.str("country")
		e.str(country)
		e.str("country_code")
		e.str(code)
		e.str("asn")
		e.str(asn)
		e.str("as_name")
		e.str(name)
	}
}

func testDB(t *testing.T) []byte {
	return buildDB(t, map[string]int{
		"203.0.113.0/24":  0,
		"198.51.100.0/25": 1,
		"2001:db8::/32":   2,
	}, []func(e *enc, starts []int){
		lite("Netherlands", "NL", "AS64500", "Example Hosting B.V."),
		func(e *enc, starts []int) { // GeoLite2 shape, its country name through a pointer into record 0's data
			e.ctrl(7, 3)
			e.str("country")
			e.ctrl(7, 2)
			e.str("iso_code")
			e.str("NL")
			e.str("names")
			e.ctrl(7, 1)
			e.str("en")
			e.ptr(starts[0] + 2 + len("country")) // the "Netherlands" string inside record 0 (after the map byte and the key)
			e.str("autonomous_system_number")
			e.uint(6, 64501)
			e.str("autonomous_system_organization")
			e.str(strings.Repeat("Long Network Name ", 3))
		},
		lite("Japan", "JP", "AS64502", "Example v6 Net"),
	})
}

func TestLookupFindsCountryAndNetwork(t *testing.T) {
	db, err := FromBytes(testDB(t))
	if err != nil {
		t.Fatal(err)
	}
	if db.Type != "test_lite.mmdb" || db.BuildEpoch != 1761000000 {
		t.Errorf("metadata: %q %d", db.Type, db.BuildEpoch)
	}
	m, err := db.Lookup(net.ParseIP("203.0.113.77"))
	if err != nil || m == nil {
		t.Fatalf("v4 lookup: %v %v", m, err)
	}
	if o := FromRecord(m); o.String() != "Netherlands, AS64500 Example Hosting B.V." {
		t.Errorf("v4: %q", o.String())
	}
	m, _ = db.Lookup(net.ParseIP("198.51.100.5"))
	if o := FromRecord(m); o.Country != "Netherlands" || o.ASN != "AS64501" || !strings.HasPrefix(o.ASName, "Long Network Name") {
		t.Errorf("GeoLite shape with a pointer: %+v", o)
	}
	if m, _ := db.Lookup(net.ParseIP("198.51.100.200")); m != nil {
		t.Errorf("outside the /25: %v", m)
	}
	m, _ = db.Lookup(net.ParseIP("2001:db8::1"))
	if o := FromRecord(m); o.CountryCode != "JP" {
		t.Errorf("v6: %+v", o)
	}
}

func TestBrokenFilesAreRefusedNotTrusted(t *testing.T) {
	good := testDB(t)
	for name, b := range map[string][]byte{
		"empty":     nil,
		"no marker": bytes.Repeat([]byte{1}, 100),
		"truncated": good[:40],
	} {
		if _, err := FromBytes(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a data pointer that points at itself must not loop forever
	var e enc
	e.ptr(0)
	d := &decoder{buf: e.Bytes()}
	if _, _, err := d.decode(0, 0); err == nil {
		t.Error("a self-pointer was decoded")
	}
	// a map that claims more entries than there are bytes
	d = &decoder{buf: []byte{0xE0 | 28}}
	if _, _, err := d.decode(0, 0); err == nil {
		t.Error("a short map was decoded")
	}
	_ = binary.BigEndian
}

func TestResolverScopesAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lite.mmdb")
	r := NewResolver(path)
	if r.Available() {
		t.Error("available without a file")
	}
	for ip, want := range map[string]string{"192.168.1.5": "private network", "127.0.0.1": "loopback network", "100.64.3.3": "carrier-grade NAT network", "fe80::1": "link-local network", "8.8.8.8": "unknown origin"} {
		if got := r.Lookup(net.ParseIP(ip)).String(); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	if err := os.WriteFile(path, testDB(t), 0o644); err != nil {
		t.Fatal(err)
	}
	r.check = time.Time{} // as if a minute had passed
	if o := r.Lookup(net.ParseIP("203.0.113.9")); o.ASN != "AS64500" {
		t.Errorf("after the file appeared: %+v", o)
	}
	f := r.Lookup(net.ParseIP("203.0.113.9")).Fields("remote_")
	if f["remote_country_code"] != "NL" || f["remote_scope"] != "public" {
		t.Errorf("fields: %v", f)
	}
	if c := BlockCommand(net.ParseIP("203.0.113.9")); c != "sudo ufw insert 1 deny from 203.0.113.9 comment 'blocked after a Heimdall alert'" {
		t.Errorf("block command: %q", c)
	}
}
