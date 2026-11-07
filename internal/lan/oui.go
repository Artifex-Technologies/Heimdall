package lan

import (
	"bufio"
	"os"
	"strings"
)

// OUIPath is the IEEE's list of hardware address prefixes and the companies they belong to (Arch's hwdata package).
var OUIPath = "/usr/share/hwdata/oui.txt"

// PrivateMAC reports a locally administered hardware address: phones and computers make these up per network (Wi-Fi privacy),
// so the prefix names no maker.
func PrivateMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var b byte
	for _, c := range strings.ToLower(mac[:2]) {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			b |= byte(c-'a') + 10
		}
	}
	return b&0x02 != 0
}

// vendors looks up the makers of the given addresses in one pass over the list (it is a few megabytes; only wanted prefixes
// are kept).
func vendors(path string, macs []string) map[string]string {
	want := map[string][]string{}
	for _, m := range macs {
		if PrivateMAC(m) || len(m) < 8 {
			continue
		}
		p := strings.ToUpper(strings.ReplaceAll(m[:8], ":", "-"))
		want[p] = append(want[p], m)
	}
	out := map[string]string{}
	if len(want) == 0 {
		return out
	}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 20 || line[2] != '-' || !strings.Contains(line[:20], "(hex)") {
			continue
		}
		if ms, ok := want[line[:8]]; ok {
			_, name, _ := strings.Cut(line, "(hex)")
			for _, m := range ms {
				out[m] = ShortVendor(strings.TrimSpace(name))
			}
		}
	}
	return out
}

// ShortVendor trims a registered company name to what people call it ("Samsung Electronics Co.,Ltd" -> "Samsung Electronics").
func ShortVendor(s string) string {
	s = clean(s)
	for _, cut := range []string{" Co.,Ltd", " Co., Ltd", " CO.,LTD", " Co.,Ltd.", ",", " Inc.", " Inc", " Corporation", " Corp.",
		" Ltd.", " Ltd", " LLC", " GmbH", " Limited", " Technologies", " Technology", " International"} {
		if i := strings.Index(s, cut); i > 0 {
			s = s[:i]
		}
	}
	return strings.TrimSpace(strings.TrimRight(s, ". "))
}
