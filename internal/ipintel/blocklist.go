package ipintel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Threat lists: downloaded files of addresses and networks known to be run by criminals, used by botnets or malware, or hijacked
// (Spamhaus DROP, FireHOL Level 1, Emerging Threats' compromised hosts). Like the IP database they are files on this computer:
// an address is checked against them here and never sent anywhere. heimdall-intel-update keeps them fresh.
//
// A list entry is a single address or a network (CIDR). Private, reserved and other non-public ranges in a list are ignored: some
// aggregated lists include "bogon" ranges such as 10.0.0.0/8, which would flag the owner's own home network.

// List is one threat list.
type List struct {
	Name    string
	entries int
	starts  []netip.Addr // merged, non-overlapping ranges, sorted
	ends    []netip.Addr
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	b := a.AsSlice()
	bits := p.Bits()
	for i := range b {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				b[i] |= 1 << (7 - j)
			}
		}
	}
	out, _ := netip.AddrFromSlice(b)
	return out
}

// ParseList reads a list in any of the shapes the sources use: one address or CIDR per line (with # or ; comments), or JSON lines
// with a "cidr" field (Spamhaus).
func ParseList(name string, data []byte) (*List, error) {
	l := &List{Name: name}
	var prefixes []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '{' {
			var j struct {
				CIDR string `json:"cidr"`
			}
			if json.Unmarshal([]byte(line), &j) != nil || j.CIDR == "" {
				continue // Spamhaus ends with a metadata line
			}
			line = j.CIDR
		}
		line = strings.Fields(strings.SplitN(strings.SplitN(line, ";", 2)[0], "#", 2)[0])[0]
		var p netip.Prefix
		var err error
		if strings.Contains(line, "/") {
			p, err = netip.ParsePrefix(line)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(line)
			if err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil {
			continue
		}
		p = p.Masked()
		if scope(net.IP(p.Addr().AsSlice())) != "public" || p.Bits() < 8 {
			continue // bogons and the like: never the owner's own network, and never "a whole /4"
		}
		prefixes = append(prefixes, p)
	}
	if len(prefixes) == 0 {
		return nil, errors.New("no addresses in the list")
	}
	l.entries = len(prefixes)
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].Addr().Less(prefixes[j].Addr()) })
	for _, p := range prefixes {
		start, end := p.Addr(), lastAddr(p)
		if n := len(l.starts); n > 0 && start.BitLen() == l.ends[n-1].BitLen() && !l.ends[n-1].Next().Less(start) {
			if l.ends[n-1].Less(end) {
				l.ends[n-1] = end // overlaps or touches the range before: extend it
			}
			continue
		}
		l.starts, l.ends = append(l.starts, start), append(l.ends, end)
	}
	return l, nil
}

// V4Addresses is how many IPv4 addresses the list covers (overlaps counted once).
func (l *List) V4Addresses() uint64 {
	var n uint64
	for i, st := range l.starts {
		if !st.Is4() {
			continue
		}
		a, b := st.As4(), l.ends[i].As4()
		lo := uint64(a[0])<<24 | uint64(a[1])<<16 | uint64(a[2])<<8 | uint64(a[3])
		hi := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		n += hi - lo + 1
	}
	return n
}

// CheckUpdate refuses a new copy of a list that changed too much from the last good one to be an ordinary update: more than
// double the IPv4 space (plus a /16), which is how a poisoned list would add a wide range and with it critical alerts and
// block commands for ordinary destinations, or fewer than half the entries (a truncated or emptied list).
func CheckUpdate(prev, next *List) error {
	if pv, nv := prev.V4Addresses(), next.V4Addresses(); nv > 2*pv+65536 {
		return fmt.Errorf("covers %d IPv4 addresses, the last good copy %d: too big a change for an update", nv, pv)
	}
	if next.Len() < prev.Len()/2 {
		return fmt.Errorf("%d entries, the last good copy %d: too many gone for an update", next.Len(), prev.Len())
	}
	return nil
}

// Len is how many entries the list has.
func (l *List) Len() int { return l.entries }

// Contains says whether the address is in the list.
func (l *List) Contains(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	i := sort.Search(len(l.starts), func(i int) bool { return a.Less(l.starts[i]) }) - 1 // the last range starting at or before a
	return i >= 0 && l.starts[i].BitLen() == a.BitLen() && !l.ends[i].Less(a)
}

// Lists is the set of threat lists in a folder: every *.list file, named by its file name. It notices new or replaced files.
type Lists struct {
	dir   string
	mu    sync.Mutex
	lists []*List
	stamp string
	check time.Time
}

func NewLists(dir string) *Lists { return &Lists{dir: dir} }

func (ls *Lists) reload() {
	if time.Since(ls.check) < time.Minute && ls.stamp != "" {
		return
	}
	ls.check = time.Now()
	files, _ := filepath.Glob(filepath.Join(ls.dir, "*.list"))
	sort.Strings(files)
	var stamp strings.Builder
	for _, f := range files {
		if st, err := os.Stat(f); err == nil {
			fmt.Fprintf(&stamp, "%s:%d:%d;", f, st.Size(), st.ModTime().UnixNano())
		}
	}
	if stamp.String() == ls.stamp {
		return
	}
	var out []*List
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if l, err := ParseList(strings.TrimSuffix(filepath.Base(f), ".list"), b); err == nil {
			out = append(out, l)
		}
	}
	ls.lists, ls.stamp = out, stamp.String()
	if ls.stamp == "" {
		ls.stamp = "none"
	}
}

// Match returns the names of the lists that contain the address (none for a non-public one).
func (ls *Lists) Match(ip net.IP) []string {
	if ls == nil || scope(ip) != "public" {
		return nil
	}
	ls.mu.Lock()
	ls.reload()
	lists := ls.lists
	ls.mu.Unlock()
	var out []string
	for _, l := range lists {
		if l.Contains(ip) {
			out = append(out, l.Name)
		}
	}
	return out
}

// Count says how many lists and entries are loaded.
func (ls *Lists) Count() (lists, entries int) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.reload()
	for _, l := range ls.lists {
		entries += l.Len()
	}
	return len(ls.lists), entries
}
