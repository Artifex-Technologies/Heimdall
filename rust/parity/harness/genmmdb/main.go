// genmmdb writes a synthetic IP database in the MaxMind DB format, about as big as DB-IP's free files, for measuring
// heimdalld's memory. Made-up data: random IPv4 prefixes with made-up countries and networks, plus the documentation
// ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) so lookups of the test connections find something.
//
//	go run . country OUT.mmdb MB
//	go run . asn OUT.mmdb MB
package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
)

type enc struct{ bytes.Buffer }

func (e *enc) ctrl(typ, size int) {
	c := byte(0)
	if typ <= 7 {
		c = byte(typ << 5)
	}
	switch {
	case size < 29:
		e.WriteByte(c | byte(size))
		if typ > 7 {
			e.WriteByte(byte(typ - 7))
		}
	case size < 285:
		e.WriteByte(c | 29)
		if typ > 7 {
			e.WriteByte(byte(typ - 7))
		}
		e.WriteByte(byte(size - 29))
	default:
		e.WriteByte(c | 30)
		if typ > 7 {
			e.WriteByte(byte(typ - 7))
		}
		s := size - 285
		e.WriteByte(byte(s >> 8))
		e.WriteByte(byte(s))
	}
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

func main() {
	kind, out := os.Args[1], os.Args[2]
	mb, _ := strconv.Atoi(os.Args[3])
	rng := rand.New(rand.NewSource(int64(len(kind))))
	// data records
	var data enc
	var starts []int
	nrec := 250
	for i := 0; i < nrec; i++ {
		starts = append(starts, data.Len())
		if kind == "country" {
			code := fmt.Sprintf("%c%c", 'A'+i%26, 'A'+(i/26)%26)
			data.ctrl(7, 2)
			data.str("continent")
			data.ctrl(7, 1)
			data.str("code")
			data.str("XX")
			data.str("country")
			data.ctrl(7, 2)
			data.str("iso_code")
			data.str(code)
			data.str("names")
			data.ctrl(7, 1)
			data.str("en")
			data.str("Testland " + code)
		} else {
			data.ctrl(7, 2)
			data.str("autonomous_system_number")
			data.uint(6, uint64(64496+i))
			data.str("autonomous_system_organization")
			data.str(fmt.Sprintf("Example Network %d Ltd.", i))
		}
	}
	type node [2]int32 // child, -1 none, -(k+2) record k
	nodes := []node{{-1, -1}}
	insert := func(v4 [4]byte, ones, rec int) {
		bits := append(make([]byte, 12), v4[:]...)
		ones += 96
		cur := 0
		for k := 0; k < ones; k++ {
			bit := int(bits[k/8]>>(7-uint(k%8))) & 1
			if k == ones-1 {
				nodes[cur][bit] = int32(-(rec + 2))
				return
			}
			if nodes[cur][bit] < 0 {
				nodes = append(nodes, node{-1, -1})
				nodes[cur][bit] = int32(len(nodes) - 1)
			}
			cur = int(nodes[cur][bit])
		}
	}
	for _, c := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
		_, n, _ := net.ParseCIDR(c)
		var v [4]byte
		copy(v[:], n.IP.To4())
		insert(v, 24, 7)
	}
	target := mb << 20 / 6 // 24-bit records: 6 bytes a node
	for len(nodes) < target {
		v := [4]byte{byte(1 + rng.Intn(222)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		if v[0] == 10 || v[0] == 127 || v[0] == 192 || v[0] == 198 || v[0] == 203 || v[0] == 172 || v[0] == 100 {
			continue
		}
		insert(v, 20+rng.Intn(9), rng.Intn(nrec))
	}
	nc := len(nodes)
	if nc >= 1<<24-16-data.Len() {
		panic("too many nodes for 24-bit records")
	}
	var buf bytes.Buffer
	val := func(v int32) int {
		switch {
		case v >= 0:
			return int(v)
		case v == -1:
			return nc
		}
		return nc + 16 + starts[-v-2]
	}
	for _, nd := range nodes {
		for _, v := range nd {
			x := val(v)
			buf.Write([]byte{byte(x >> 16), byte(x >> 8), byte(x)})
		}
	}
	buf.Write(make([]byte, 16))
	buf.Write(data.Bytes())
	buf.Write([]byte("\xab\xcd\xefMaxMind.com"))
	var m enc
	m.ctrl(7, 5)
	m.str("node_count")
	m.uint(6, uint64(nc))
	m.str("record_size")
	m.uint(5, 24)
	m.str("ip_version")
	m.uint(5, 6)
	m.str("database_type")
	m.str("synthetic-" + kind + "-lite.mmdb")
	m.str("build_epoch")
	m.uint(9, 1762000000)
	buf.Write(m.Bytes())
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%s: %d nodes, %.1f MB\n", out, nc, float64(buf.Len())/(1<<20))
}
