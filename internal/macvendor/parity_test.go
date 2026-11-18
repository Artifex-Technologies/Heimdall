package macvendor

// The answers for the Rust crate (rust/macvendor/tests/parity.rs): go test ./internal/macvendor -update writes
// testdata/parity/macvendor.json from this package on hand-made and generated registry files (a fixed seed); without -update
// the file must be what this code says. File contents and names that may not be UTF-8 are written as hex. Every prefix and
// name is made up.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/parity/macvendor.json")

type pFile struct {
	Registry string `json:"registry"`
	Hex      string `json:"hex"`
}

type pLookup struct {
	MAC      string `json:"mac"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Short    string `json:"short"`
	Registry string `json:"registry"`
	Bits     uint8  `json:"bits"`
}

type pTable struct {
	Files   []pFile   `json:"files"`
	Len     int       `json:"len"`
	Lookups []pLookup `json:"lookups"`
}

type pStr struct {
	In  string `json:"in"`
	Out string `json:"out"`
}

// generator makes registry files from pieces that are valid, nearly valid and damaged, and remembers addresses worth asking.
type generator struct {
	r      *rand.Rand
	probes [][6]byte
}

func (g *generator) pick(s []string) string { return s[g.r.Intn(len(s))] }

var names = []string{"EXAMPLE NETWORKS CORP", "Sample Radio Co.,Ltd", "Tiny Sensors Inc.", "\"Quoted\", Things", "\u00c9cole \u00c9lectronique",
	"\u00c9COLE \u00c9LECTRONIQUE", "Good\u202e Name", "\x07Bell Labs", "\xc9cole\xff", "  spaced   out  ", "", " ", "ZTE CORPORATION",
	"LG ELECTRONICS INC", strings.Repeat("Long Name ", 20), "\u540d\u524d \u682a\u5f0f\u4f1a\u793e", "A,B,C", "Foo GmbH & Co. KG", "Bar AG",
	"Incom Ltd", "Foo Incom", "IEEE Registration Authority", "Private", "x", "Zero\u200bWidth", "Tab\tInside", "eero inc.",
	"Nokia Shanghai Bell Co., Ltd.", "Hyphen-Ated Co.", "Quote \"\" Inside", "Line\rBreak", "\ufeffBOM Name", "...", "ABCD", "ABCDE"}

var firstBytes = []byte{0x0c, 0x0c, 0x0c, 0x0d, 0x0e, 0x00, 0x01, 0x33, 0xac, 0xff, 0xa0}

func (g *generator) prefix() [3]byte {
	mid := []byte{0x00, 0x01, 0x5e, 0x0c, 0x80, byte(g.r.Intn(256))}
	return [3]byte{firstBytes[g.r.Intn(len(firstBytes))], mid[g.r.Intn(len(mid))], mid[g.r.Intn(len(mid))]}
}

func (g *generator) probe(v uint64, bits uint) {
	low := uint64(g.r.Int63()) & (1<<(48-bits) - 1)
	for _, x := range []uint64{v << (48 - bits), v<<(48-bits) | low} {
		var m [6]byte
		for i := range m {
			m[i] = byte(x >> (40 - 8*i))
		}
		g.probes = append(g.probes, m)
	}
}

func (g *generator) end() string { return g.pick([]string{"\n", "\n", "\r\n"}) }

func (g *generator) txt() []byte {
	var b strings.Builder
	if g.r.Intn(2) == 0 {
		b.WriteString("OUI/MA-L\t\t\tOrganization" + g.end() + "company_id\t\t\tOrganization" + g.end() + g.end())
	}
	for n := g.r.Intn(10); n > 0; n-- {
		p := g.prefix()
		sep := g.pick([]string{"-", "-", "-", ":"})
		hx := "%02X"
		if g.r.Intn(5) == 0 {
			hx = "%02x"
		}
		head := fmt.Sprintf(hx+sep+hx+sep+hx, p[0], p[1], p[2])
		name := g.pick(names)
		if g.r.Intn(8) == 0 {
			head = g.pick([]string{"x ", "", " "}) + head[:g.r.Intn(len(head)+1)]
		}
		b.WriteString(head + g.pick([]string{"   ", "\t", " ", "", "                      "}) + "(hex)" + g.pick([]string{"\t\t", "  ", "", "   "}) + name + g.end())
		v := uint64(p[0])<<16 | uint64(p[1])<<8 | uint64(p[2])
		switch g.r.Intn(6) {
		case 0, 1:
			fmt.Fprintf(&b, "%02X%02X%02X     (base 16)\t\t%s%s", p[0], p[1], p[2], name, g.end())
			g.probe(v, 24)
		case 2:
			lo := uint64(g.r.Intn(16)) << 20
			fmt.Fprintf(&b, "%06X-%06X     (base 16)\t\t%s%s", lo, lo+1<<20-1, name, g.end())
			g.probe(v<<4|lo>>20, 28)
		case 3:
			lo := uint64(g.r.Intn(4096)) << 12
			fmt.Fprintf(&b, "%06X-%06X                 (base 16)                     %s%s", lo, lo+0xfff, name, g.end())
			g.probe(v<<12|lo>>12, 36)
		case 4:
			lo, hi := uint64(g.r.Intn(1<<24)), uint64(g.r.Intn(1<<24))
			fmt.Fprintf(&b, "%06X-%06X     (base 16)\t\t%s%s", lo, hi, name, g.end())
			g.probe(v, 24)
		}
		if g.r.Intn(2) == 0 {
			b.WriteString("\t\t\t\t1 Example Road" + g.end() + "\t\t\t\tSomewhere" + g.end() + g.end())
		}
	}
	return []byte(b.String())
}

func (g *generator) quote(s string) string {
	if g.r.Intn(3) == 0 && !strings.ContainsAny(s, ",\"\r\n") {
		return s
	}
	return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
}

func (g *generator) csv() []byte {
	var b strings.Builder
	b.WriteString(g.pick([]string{"", "", "\xef\xbb\xbf"}) + g.pick([]string{"Registry", "registry", "REGISTRY"}) + ",Assignment,Organization Name,Organization Address" + g.end())
	for n := g.r.Intn(10); n > 0; n-- {
		p := g.prefix()
		digits := []int{6, 7, 9, 6, 7, 9, 5, 10, 12}[g.r.Intn(9)]
		v := uint64(p[0])<<16 | uint64(p[1])<<8 | uint64(p[2])
		if digits > 6 {
			v = v<<(4*(digits-6)) | uint64(g.r.Int63())&(1<<(4*(digits-6))-1)
		} else {
			v >>= 4 * (6 - digits)
		}
		a := fmt.Sprintf("%0*X", digits, v)
		if g.r.Intn(10) == 0 {
			a = a[:len(a)-1] + "G"
		}
		if g.r.Intn(10) == 0 {
			a = " " + a + "\t"
		}
		reg := g.pick([]string{"MA-L", "MA-M", "MA-S", "IAB", "MA-L", "MA-M", "MA-S", "CID", "ma-s", " IAB ", "Registry"})
		addr := g.pick([]string{"Somewhere", "\"1 Way, Town\"", "\"1 Way\r\nTown\"", "\"1 Way\nTown\nLand\"", ""})
		fields := []string{reg, a, g.quote(g.pick(names)), addr}
		if g.r.Intn(12) == 0 {
			fields = fields[:g.r.Intn(3)+1]
		}
		if g.r.Intn(25) == 0 {
			fields[len(fields)-1] += "\"unclosed"
		}
		b.WriteString(strings.Join(fields, ",") + g.end())
		if digits >= 6 && digits <= 11 {
			g.probe(v, uint(4*digits))
		}
	}
	return []byte(b.String())
}

// mutate changes a few bytes of some files, as a damaged download would.
func (g *generator) mutate(d []byte) []byte {
	if len(d) == 0 || g.r.Intn(5) != 0 {
		return d
	}
	d = append([]byte(nil), d...)
	for n := 1 + g.r.Intn(4); n > 0; n-- {
		d[g.r.Intn(len(d))] = []byte{0, '\n', '"', ',', '-', '(', 0xff, 0xc3, byte(g.r.Intn(256))}[g.r.Intn(9)]
	}
	return d
}

var fixedMACs = []string{"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:00:5e:00:00:fb", "01:00:5e:7f:ff:fa", "01:00:5e:80:00:01",
	"01:00:5e:90:10:01", "33:33:00:00:00:fb", "01:80:c2:00:00:00", "01:80:c2:00:00:01", "01:80:c2:00:00:0e", "01:80:c2:00:00:0f",
	"01:80:c2:00:00:21", "01:1b:19:00:00:00", "01:00:0c:cc:cc:cc", "01:00:0c:cc:cc:cd", "00:00:5e:00:01:07", "00:00:5e:00:02:07",
	"00:00:5e:00:53:01", "00:00:0c:07:ac:01", "00:00:0c:9f:f1:23", "02:00:00:00:00:01", "06:aa:bb:cc:dd:ee", "da:00:00:00:00:01",
	"0d:00:01:00:00:00", "", "0", "zz:zz:zz:00:00:00", "0c:00:01:00:00", "0c-00:01:00:00:00", "0C00.0100.0001", "0c0001000001",
	" 0c:00:01:00:00:01\t", "0c:00:01:00:00:01\n", "\u00e90:00:01:00:00:01"}

func (g *generator) macText(m [6]byte) string {
	h := make([]string, 6)
	f := "%02x"
	if g.r.Intn(2) == 0 {
		f = "%02X"
	}
	for i, b := range m {
		h[i] = fmt.Sprintf(f, b)
	}
	switch g.r.Intn(5) {
	case 0:
		return strings.Join(h, "-")
	case 1:
		c := strings.Join(h, "")
		return c[:4] + "." + c[4:8] + "." + c[8:]
	case 2:
		return strings.Join(h, "")
	}
	return strings.Join(h, ":")
}

func lookups(t *Table, macs []string) []pLookup {
	var out []pLookup
	for _, m := range macs {
		a := t.LookupString(m)
		l := pLookup{MAC: m, Kind: a.Kind, Name: a.Name, Short: a.Short}
		if a.Kind == KindVendor {
			l.Registry, l.Bits = a.Registry.String(), a.Bits
		}
		out = append(out, l)
	}
	return out
}

func TestFixtures(t *testing.T) {
	g := &generator{r: rand.New(rand.NewSource(17))}
	var tables []pTable
	add := func(files []pFile, macs []string) {
		b := NewBuilder()
		for _, f := range files {
			d, _ := hex.DecodeString(f.Hex)
			reg, _ := RegistryFromName(f.Registry)
			b.Read(bytes.NewReader(d), reg)
		}
		tb := b.Finish()
		tables = append(tables, pTable{files, tb.Len(), lookups(tb, macs)})
	}
	// the hand-made files of the tests, in Load's order
	hexf := func(reg Registry, s string) pFile { return pFile{reg.String(), hex.EncodeToString([]byte(s))} }
	hand := []string{"0c:00:01:12:34:56", "0c:00:02:12:34:56", "0c:00:03:ab:c1:23", "0c:00:03:ab:d1:23", "0c:00:03:01:23:45",
		"0c:00:03:12:34:56", "0c:00:03:ab:e1:23", "0c:00:04:00:00:00"}
	add([]pFile{hexf(MaS, oui36CSV), hexf(IAB, iabTxt), hexf(MaM, mamCSV), hexf(MaL, ouiTxt)}, append(hand, fixedMACs...))
	add([]pFile{hexf(MaL, "")}, fixedMACs)
	// generated ones
	for i := 0; i < 120; i++ {
		g.probes = nil
		var files []pFile
		for n := 1 + g.r.Intn(3); n > 0; n-- {
			reg := []Registry{MaL, MaM, MaS, IAB}[g.r.Intn(4)]
			var d []byte
			if g.r.Intn(2) == 0 {
				d = g.txt()
			} else {
				d = g.csv()
			}
			files = append(files, pFile{reg.String(), hex.EncodeToString(g.mutate(d))})
		}
		var macs []string
		for _, p := range g.probes {
			macs = append(macs, g.macText(p))
			// the same block with the group or local bit set
			p[0] |= byte(1 + g.r.Intn(2))
			macs = append(macs, g.macText(p))
		}
		for n := 0; n < 4; n++ {
			var m [6]byte
			g.r.Read(m[:])
			macs = append(macs, g.macText(m))
		}
		macs = append(macs, fixedMACs[g.r.Intn(len(fixedMACs))])
		add(files, macs)
	}

	// addresses as text
	var parsed []pStr
	alphabet := "0123456789abcdefABCDEFxg:-. \t"
	ins := append([]string{}, fixedMACs...)
	for i := 0; i < 300; i++ {
		n := []int{12, 14, 17, 13, 16, 18, 19}[g.r.Intn(7)]
		s := make([]byte, n)
		for k := range s {
			s[k] = alphabet[g.r.Intn(len(alphabet))]
		}
		ins = append(ins, string(s))
	}
	for _, s := range ins {
		out := ""
		if m, ok := ParseMAC(s); ok {
			out = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
		}
		parsed = append(parsed, pStr{s, out})
	}

	// names: cleaned (from bytes, as hex) and shortened
	var cleaned, shorts []pStr
	pieces := []string{"a", "B", " ", "\t", "\n", "\r", "\x00", "\x7f", "\xc2\x85", "\u00a0", "\u00ad", "\u200b", "\u202e", "\u2066", "\ufeff",
		"\u3000", "\u00e9", "\u00c9", "\u540d", "\U0001F600", "\U000E0041", "\xff", "\xc3", "\xed\xa0\x80", ",", ".", "-", "Inc", " Co.,Ltd",
		" GMBH", " corp", "\ufe0f", "\u180e", "\u2028"}
	for i := 0; i < 400; i++ {
		var s strings.Builder
		for n := g.r.Intn(60); n > 0; n-- {
			s.WriteString(pieces[g.r.Intn(len(pieces))])
		}
		cleaned = append(cleaned, pStr{hex.EncodeToString([]byte(s.String())), Clean([]byte(s.String()))})
	}
	for _, n := range names {
		cleaned = append(cleaned, pStr{hex.EncodeToString([]byte(n)), Clean([]byte(n))})
		c := Clean([]byte(n))
		shorts = append(shorts, pStr{c, Short(c)})
	}
	words := []string{"ACME", "Acme", "LG", "ZTE", "INC", "Inc.", "Co.,Ltd", "CO., LTD.", "Corp", "corporation", "GmbH", "AG", "AGENCY", "S.A.",
		"B.V.", "Pte", "PTY", "Ltd", "LTDA", "LLC", "Technologies", "TECHNOLOGY", "International", ",", ".", "-", "&", "\u00c9COLE", "\u00e9cole",
		"Incom", "Corporate", "Limited", "co.", "x"}
	for i := 0; i < 400; i++ {
		var ws []string
		for n := 1 + g.r.Intn(6); n > 0; n-- {
			ws = append(ws, words[g.r.Intn(len(words))])
		}
		joined := strings.Join(ws, g.pick([]string{" ", " ", ""}))
		c := Clean([]byte(joined))
		shorts = append(shorts, pStr{c, Short(c)})
	}

	out := map[string]any{"format": "heimdall-macvendor/1", "from": "internal/macvendor (go test ./internal/macvendor -update)",
		"tables": tables, "parse": parsed, "clean": cleaned, "short": shorts}
	var b bytes.Buffer
	b.WriteString("{\n")
	keys := []string{"format", "from", "tables", "parse", "clean", "short"}
	for i, k := range keys {
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteString(": ")
		if list, ok := out[k].([]pTable); ok {
			writeList(&b, list)
		} else if list, ok := out[k].([]pStr); ok {
			writeList(&b, list)
		} else {
			vb, _ := json.Marshal(out[k])
			b.Write(vb)
		}
		if i < len(keys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	path, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "parity", "macvendor.json"))
	if *update {
		if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/macvendor -update)", err)
	}
	if !bytes.Equal(old, b.Bytes()) {
		t.Error("testdata/parity/macvendor.json is out of date: run go test ./internal/macvendor -update and review the diff")
	}
}

// writeList writes one element per line, so a change shows as a small diff.
func writeList[T any](b *bytes.Buffer, list []T) {
	b.WriteString("[\n")
	for i, e := range list {
		eb, _ := json.Marshal(e)
		b.Write(eb)
		if i < len(list)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("]")
}
