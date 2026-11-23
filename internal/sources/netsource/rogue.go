package netsource

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// RogueRouterWatcher notices a second router on the network this computer is on: a DHCP server other than the one that
// answered first (or than the one remembered for a trusted network), a device other than the router announcing itself as
// the IPv6 router, a new IPv6 prefix announced in the middle of a connection, and IPv6 appearing on a network that never had
// it. Each of these is how a device on the network puts itself between this computer and the internet (man in the middle).
//
// It sends nothing and opens no socket. DHCP comes from what NetworkManager accepted, recorded by the dispatcher
// 91-heimdall-netid (root's /run/heimdall-net/netid.jsonl); IPv6 routers and prefixes from the kernel's routing table
// (/proc/net/ipv6_route), read every poll. What is remembered for a trusted or home network (to notice a different router on
// the next connection) is kept as hashes in StatePath, mode 0600; nothing is kept for any other network.
type RogueRouterWatcher struct {
	NetIDPath   string
	CurrentPath string // heimdall-wifi-check's current.json: the Wi-Fi network's name and level
	TrustedPath string // /etc/heimdall/wifi-trusted.json: the kind of network the owner set (heimdall-wifi-guard kind)
	StatePath   string
	procRoot    string
	sysRoot     string
	now         func() time.Time
	started     time.Time
	off         int64
	conns       map[string]*rogueConn // per interface
	state       rogueState
	loaded      bool
}

// rogueLearnAfter is how many connections a new router must be seen on before a trusted network takes it as its own (a
// router that was replaced stops being reported; one alert per connection until then).
const rogueLearnAfter = 3

// rogueLateIPv6 is how long after joining an IPv6 router may first appear on a network not remembered: routers answer the
// router question this computer asks when it joins within seconds.
const rogueLateIPv6 = 2 * time.Minute

// NewRogueRouterWatcher reads netID (the dispatcher's lines), current (heimdall-wifi-check's current.json) and keeps what it
// learns of trusted networks in state.
func NewRogueRouterWatcher(netID, current, state string) *RogueRouterWatcher {
	return &RogueRouterWatcher{NetIDPath: netID, CurrentPath: current, StatePath: state, TrustedPath: "/etc/heimdall/wifi-trusted.json",
		procRoot: "/proc", sysRoot: "/sys", now: time.Now}
}

type rogueState struct {
	Nets map[string]*rogueKnown `json:"nets"`
}

// rogueKnown is what a trusted network's router is known by: per signal the hashes of the values seen (at most 4), the
// values seen on fewer than rogueLearnAfter connections, how many connections, and whether it ever had IPv6.
type rogueKnown struct {
	Conns   int                 `json:"conns"`
	IPv6    bool                `json:"ipv6"`
	Values  map[string][]string `json:"values"`
	Pending map[string]int      `json:"pending"`
}

type rogueConn struct {
	uuid     string
	up       time.Time
	first    map[string]string // per signal: the first value of this connection
	ra       []string          // IPv6 routers seen, in order
	raFirst  time.Time
	gwMAC    string // the router's hardware address, first seen in this connection
	prefixes map[string]bool
	counted  map[string]bool
	reported map[string]bool
}

type netIDLine struct {
	T           int64  `json:"t"`
	Action      string `json:"action"`
	Iface       string `json:"iface"`
	UUID        string `json:"uuid"`
	DHCP4Server string `json:"dhcp4_server"`
	DHCP4Router string `json:"dhcp4_routers"`
	DNS4        string `json:"dns4"`
	DNS6        string `json:"dns6"`
}

type rogueCurrent struct {
	SSID    string `json:"ssid"`
	UUID    string `json:"uuid"`
	Trusted bool   `json:"trusted"`
	Level   string `json:"level"`
}

// rogueSignal is one thing that changed: which, the value before (empty when it contradicts what a trusted network
// remembers, which is kept only as a hash) and after; learned: it contradicts that memory; during: it changed in the middle
// of a connection (a second router at the same time), not between connections.
type rogueSignal struct {
	kind, before, after string
	learned, during     bool
}

func rogueHash(parts ...string) string {
	s := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(s[:16])
}

// Poll reads the dispatcher's new lines and the kernel's IPv6 routes and returns what looks like a second router.
func (w *RogueRouterWatcher) Poll() []detect.Event {
	now := w.now()
	if w.started.IsZero() {
		w.started = now
		w.conns = map[string]*rogueConn{}
	}
	if !w.loaded {
		w.loaded = true
		if b, err := os.ReadFile(w.StatePath); err == nil {
			json.Unmarshal(b, &w.state)
		}
		if w.state.Nets == nil {
			w.state.Nets = map[string]*rogueKnown{}
		}
	}
	cur := w.current()
	var out []detect.Event
	changed := false
	for _, l := range w.newLines() {
		// lines written before heimdalld started (more than 5 minutes) only rebuild the connection; they are not reported
		quiet := time.Unix(l.T, 0).Before(w.started.Add(-5 * time.Minute))
		ev, ch := w.line(l, cur, quiet)
		if ev != nil {
			out = append(out, *ev)
		}
		changed = changed || ch
	}
	routes, _ := os.ReadFile(filepath.Join(w.procRoot, "net/ipv6_route"))
	arp := readARP(filepath.Join(w.procRoot, "net/arp"))
	for _, iface := range sortedKeys(w.conns) {
		ev, ch := w.routes(iface, w.conns[iface], routes, arp, cur, now)
		if ev != nil {
			out = append(out, *ev)
		}
		changed = changed || ch
	}
	if changed {
		w.save()
	}
	return out
}

func sortedKeys(m map[string]*rogueConn) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	for i := 1; i < len(k); i++ {
		for j := i; j > 0 && k[j] < k[j-1]; j-- {
			k[j], k[j-1] = k[j-1], k[j]
		}
	}
	return k
}

func (w *RogueRouterWatcher) current() rogueCurrent {
	var c rogueCurrent
	if b, err := os.ReadFile(w.CurrentPath); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

// newLines returns the dispatcher's complete lines after the last poll (from the top when the file was cut short).
func (w *RogueRouterWatcher) newLines() []netIDLine {
	f, err := os.Open(w.NetIDPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() < w.off {
		w.off = 0
	}
	f.Seek(w.off, 0)
	r := bufio.NewReader(f)
	var out []netIDLine
	for {
		b, err := r.ReadBytes('\n')
		if err != nil {
			break
		}
		w.off += int64(len(b))
		var l netIDLine
		if json.Unmarshal(bytes.TrimSpace(b), &l) == nil && l.Iface != "" {
			out = append(out, l)
		}
	}
	return out
}

// known returns what a trusted or home network remembers (nil for any other network: nothing is kept for those).
func (w *RogueRouterWatcher) known(c *rogueConn, cur rogueCurrent) (*rogueKnown, string) {
	if c.uuid == "" || cur.UUID != c.uuid || !(cur.Trusted || cur.Level == "trusted" || cur.Level == "home") {
		return nil, ""
	}
	key := rogueHash("net", c.uuid)
	k := w.state.Nets[key]
	if k == nil {
		k = &rogueKnown{Values: map[string][]string{}, Pending: map[string]int{}}
		w.state.Nets[key] = k
	}
	if k.Values == nil {
		k.Values = map[string][]string{}
	}
	if k.Pending == nil {
		k.Pending = map[string]int{}
	}
	return k, "learned"
}

// learn records a value seen on a trusted network: the first values are taken at once; a different one only after it was
// seen on rogueLearnAfter connections. It says whether the value contradicts what the network remembers.
func (w *RogueRouterWatcher) learn(k *rogueKnown, c *rogueConn, kind, value string) bool {
	h := rogueHash(c.uuid, kind, value)
	for _, x := range k.Values[kind] {
		if x == h {
			return false
		}
	}
	if len(k.Values[kind]) == 0 {
		k.Values[kind] = []string{h}
		return false
	}
	if !c.counted[h] {
		c.counted[h] = true
		k.Pending[h]++
		if k.Pending[h] >= rogueLearnAfter {
			delete(k.Pending, h)
			k.Values[kind] = append(k.Values[kind], h)
			if len(k.Values[kind]) > 4 {
				k.Values[kind] = k.Values[kind][1:]
			}
		}
	}
	return true
}

func newRogueConn(uuid string, up time.Time) *rogueConn {
	return &rogueConn{uuid: uuid, up: up, first: map[string]string{}, prefixes: map[string]bool{}, counted: map[string]bool{}, reported: map[string]bool{}}
}

// line takes one dispatcher line: a connection coming up or going, or its lease (DHCP server, router, DNS) changing.
func (w *RogueRouterWatcher) line(l netIDLine, cur rogueCurrent, quiet bool) (*detect.Event, bool) {
	t := time.Unix(l.T, 0)
	if l.Action == "down" {
		delete(w.conns, l.Iface)
		return nil, false
	}
	c := w.conns[l.Iface]
	changed := false
	if c == nil || c.uuid != l.UUID || l.Action == "up" {
		c = newRogueConn(l.UUID, t)
		w.conns[l.Iface] = c
		if k, _ := w.known(c, cur); k != nil && l.Action == "up" {
			k.Conns++
			changed = true
		}
	}
	k, _ := w.known(c, cur)
	var sigs []rogueSignal
	for _, kv := range [][2]string{{"dhcp_server", l.DHCP4Server}, {"dhcp_router", l.DHCP4Router}, {"dns4", l.DNS4}, {"dns6", l.DNS6}} {
		kind, v := kv[0], kv[1]
		if v == "" {
			continue
		}
		first, had := c.first[kind]
		if !had {
			c.first[kind] = v
		}
		if k != nil {
			changed = true
			if w.learn(k, c, kind, v) {
				sigs = append(sigs, rogueSignal{kind, first, v, true, had})
				continue
			}
		}
		if had && v != first {
			sigs = append(sigs, rogueSignal{kind, first, v, false, true})
		}
	}
	if quiet || len(sigs) == 0 {
		return nil, changed
	}
	return w.event(l.Iface, c, cur, "dhcp", sigs), changed
}

// ipv6Routes reads the kernel's IPv6 table for iface: the routers of its default routes (link-local next hops, which only
// router advertisements give) and its on-link prefixes (not link-local, not single addresses).
func ipv6Routes(table []byte, iface string) (routers []string, prefixes []string) {
	for _, line := range strings.Split(string(table), "\n") {
		x := strings.Fields(line)
		if len(x) < 10 || x[9] != iface || len(x[0]) != 32 || len(x[4]) != 32 {
			continue
		}
		dest, plen, hop := x[0], x[1], x[4]
		if plen == "00" && dest == strings.Repeat("0", 32) && strings.HasPrefix(hop, "fe8") {
			routers = append(routers, hexIPv6(hop))
		} else if plen != "00" && plen != "80" && hop == strings.Repeat("0", 32) && !strings.HasPrefix(dest, "fe8") && !strings.HasPrefix(dest, "ff") {
			var n int
			fmt.Sscanf(plen, "%x", &n)
			prefixes = append(prefixes, fmt.Sprintf("%s/%d", hexIPv6(dest), n))
		}
	}
	return routers, prefixes
}

// hexIPv6 writes 32 hex digits as an IPv6 address the short way (Go's netip form).
func hexIPv6(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 16 {
		return h
	}
	var g [8]int
	for i := range g {
		g[i] = int(b[2*i])<<8 | int(b[2*i+1])
	}
	// the longest run of two or more zero groups becomes ::, the first one on a tie
	bs, bl := -1, 0
	for i := 0; i < 8; {
		j := i
		for j < 8 && g[j] == 0 {
			j++
		}
		if j-i > bl && j-i >= 2 {
			bs, bl = i, j-i
		}
		if j == i {
			i++
		} else {
			i = j
		}
	}
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		if i == bs {
			sb.WriteString("::")
			i += bl - 1
			continue
		}
		if i > 0 && i != bs+bl {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%x", g[i])
	}
	return sb.String()
}

// routes compares the IPv6 routers and prefixes of iface with what this connection (and a trusted network) had.
func (w *RogueRouterWatcher) routes(iface string, c *rogueConn, table []byte, arp []arpEntry, cur rogueCurrent, now time.Time) (*detect.Event, bool) {
	routers, prefixes := ipv6Routes(table, iface)
	k, _ := w.known(c, cur)
	hotspot := k != nil && w.kind(c.uuid) == "phone-hotspot"
	changed := false
	var sigs []rogueSignal
	// the router's hardware address (the kernel's neighbour table, for the router the DHCP server handed out)
	if gw := strings.Fields(c.first["dhcp_router"]); len(gw) > 0 {
		for _, e := range arp {
			if e.dev != iface || e.ip != gw[0] {
				continue
			}
			switch {
			case c.gwMAC == "":
				c.gwMAC = e.mac
				// a phone hotspot makes up a new address when it restarts: expected, not remembered
				if k != nil && !hotspot {
					changed = true
					if w.learn(k, c, "gateway_mac", e.mac) {
						sigs = append(sigs, rogueSignal{"gateway_mac", "", e.mac, true, false})
					}
				}
			case e.mac != c.gwMAC && cur.UUID == c.uuid && (cur.Level == "home" || (cur.Level == "" && cur.Trusted)):
				// in the middle of a connection, on every kind (the router watch covers every network but home)
				sigs = append(sigs, rogueSignal{"gateway_mac", c.gwMAC, e.mac, false, true})
				c.gwMAC = e.mac
			}
		}
	}
	for _, r := range routers {
		seen := false
		for _, x := range c.ra {
			seen = seen || x == r
		}
		if seen {
			continue
		}
		firstRouter := len(c.ra) == 0
		c.ra = append(c.ra, r)
		if firstRouter {
			c.raFirst = now
			for _, p := range prefixes {
				c.prefixes[p] = true
			}
		}
		switch {
		case k != nil && firstRouter && !k.IPv6 && k.Conns >= rogueLearnAfter:
			// a trusted network that never had IPv6 on several connections now has a router announcing it
			changed = true
			sigs = append(sigs, rogueSignal{"ipv6_new", "", r, true, false})
			w.learn(k, c, "ra_router", r)
			k.Pending[rogueHash(c.uuid, "ipv6")]++
			if k.Pending[rogueHash(c.uuid, "ipv6")] >= rogueLearnAfter {
				delete(k.Pending, rogueHash(c.uuid, "ipv6"))
				k.IPv6 = true
			}
		case k != nil:
			changed = true
			if !k.IPv6 {
				k.IPv6 = true
			}
			if hotspot && firstRouter {
				break // a restarted hotspot's router address is new too
			}
			if w.learn(k, c, "ra_router", r) {
				sigs = append(sigs, rogueSignal{"ra_router", "", r, true, !firstRouter})
			} else if !firstRouter {
				sigs = append(sigs, rogueSignal{"ra_router", c.ra[0], r, false, true})
			}
		case firstRouter && now.Sub(c.up) > rogueLateIPv6:
			sigs = append(sigs, rogueSignal{"ipv6_late", "", r, false, true})
		case !firstRouter:
			sigs = append(sigs, rogueSignal{"ra_router", c.ra[0], r, false, true})
		}
	}
	if len(c.ra) > 0 {
		for _, p := range prefixes {
			if c.prefixes[p] {
				continue
			}
			c.prefixes[p] = true
			// prefixes announced in the first minute belong to the router's first announcements
			if now.Sub(c.raFirst) > time.Minute {
				if phoneUSB(w.sysRoot, iface) {
					// the owner's decision, 2026-11-22: noted, not an alert
					log.Printf("rogue-router: %s is a phone's USB link: its new IPv6 network %s is noted, not reported (only the phone is on the cable)", iface, p)
					continue
				}
				sigs = append(sigs, rogueSignal{"ra_prefix", "", p, false, true})
			}
		}
	}
	if len(sigs) == 0 {
		return nil, changed
	}
	return w.event(iface, c, cur, "ra", sigs), changed
}

// event makes one alert of the signals that changed together, once per connection for the same values; its confidence is
// how many independent signals agree and whether they contradict what a trusted network remembers, and judged is how serious
// it is (rogueJudge).
func (w *RogueRouterWatcher) event(iface string, c *rogueConn, cur rogueCurrent, via string, sigs []rogueSignal) *detect.Event {
	var kinds, before, after, what []string
	learned := false
	for _, s := range sigs {
		learned = learned || s.learned
		kinds = append(kinds, s.kind)
		b := s.before
		if b == "" && s.learned {
			b = "remembered"
		}
		before = append(before, s.kind+"="+b)
		after = append(after, s.kind+"="+s.after)
		what = append(what, rogueWhat(s, c, w.now()))
	}
	key := via + "|" + strings.Join(after, ";")
	if c.reported[key] {
		return nil
	}
	c.reported[key] = true
	conf := "low"
	if learned && len(sigs) >= 2 {
		conf = "high"
	} else if learned || len(sigs) >= 2 {
		conf = "medium"
	}
	ssid, level := "", ""
	if cur.UUID == c.uuid && c.uuid != "" {
		ssid, level = cur.SSID, cur.Level
		if level == "" && cur.Trusted {
			level = "home"
		}
	}
	text := strings.Join(what, "; ")
	return &detect.Event{Source: "host-lan", Time: w.now(), Kind: "rogue_router", Text: text, Fields: map[string]string{
		"ssid": ssid, "iface": iface, "level": level, "via": via, "signals": strings.Join(kinds, ","),
		"before": strings.Join(before, ";"), "after": strings.Join(after, ";"), "learned": fmt.Sprint(learned),
		"confidence": conf, "what": text, "judged": rogueJudge(sigs), "network_kind": w.kindIfKnown(c, cur),
	}}
}

// rogueWhat says what one signal means, in a few words.
func rogueWhat(s rogueSignal, c *rogueConn, now time.Time) string {
	was := " (it was " + s.before + ")"
	if s.before == "" {
		was = ""
		if s.learned {
			was = " (not the one remembered for this network)"
		}
	}
	switch s.kind {
	case "dhcp_server":
		return "a DHCP server " + s.after + " answered" + was
	case "dhcp_router":
		return "the router handed out is " + s.after + was
	case "dns4", "dns6":
		return "the DNS servers handed out are " + s.after + strings.Replace(was, "it was", "they were", 1)
	case "gateway_mac":
		return "the router's hardware address is " + s.after + was
	case "ra_router":
		return "a device " + s.after + " announced itself as the IPv6 router" + was
	case "ra_prefix":
		return "a new IPv6 network " + s.after + " was announced in the middle of the connection"
	case "ipv6_new":
		return "an IPv6 router " + s.after + " appeared on a network that never had IPv6"
	case "ipv6_late":
		return fmt.Sprintf("an IPv6 router %s appeared %d minutes after joining, on a network that had none", s.after, int(now.Sub(c.up).Minutes()))
	}
	return s.kind + " " + s.after
}

// Run polls every interval until ctx ends.
func (w *RogueRouterWatcher) Run(ctx context.Context, interval time.Duration, emit func(detect.Event)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, e := range w.Poll() {
			emit(e)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// rogueJudge says how serious the signals are together, by how many changed at once: one thing about a trusted network's router
// differing from last time is "info" (a firmware update or a new setting looks the same); two or more at once, a router that
// a trusted network does not know appearing in the middle of a connection, or the router's hardware address changing during a
// connection, is "critical" (a different device may be posing as the router); anything else is a "warning". IPv6 appearing
// on a network that never had it is never less than a warning: that is how a device takes over a network's IPv6.
func rogueJudge(sigs []rogueSignal) string {
	start := 0
	for _, s := range sigs {
		if (s.learned && s.during) || (s.kind == "gateway_mac" && s.during) {
			return "critical"
		}
		if s.learned {
			start++
		}
	}
	switch {
	case start >= 2:
		return "critical"
	case start == 1 && len(sigs) == 1 && sigs[0].kind != "ipv6_new":
		return "info"
	}
	return "warning"
}

// kind reads the kind of network the owner set for uuid (heimdall-wifi-guard kind); none set is a home router.
func (w *RogueRouterWatcher) kind(uuid string) string {
	var t map[string]json.RawMessage
	if b, err := os.ReadFile(w.TrustedPath); err == nil && json.Unmarshal(b, &t) == nil {
		var e struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(t[uuid], &e) == nil {
			switch e.Kind {
			case "mesh", "phone-hotspot", "travel", "other":
				return e.Kind
			}
		}
	}
	return "home-router"
}

// kindIfKnown is the kind of a trusted or home network ("" for any other network).
func (w *RogueRouterWatcher) kindIfKnown(c *rogueConn, cur rogueCurrent) string {
	if k, _ := w.known(c, cur); k == nil {
		return ""
	}
	return w.kind(c.uuid)
}

// save writes what trusted networks remember (hashes and counts only), mode 0600, by a rename.
func (w *RogueRouterWatcher) save() {
	if w.StatePath == "" {
		return
	}
	b, err := json.Marshal(w.state)
	if err != nil {
		return
	}
	tmp := w.StatePath + ".tmp"
	if os.WriteFile(tmp, append(b, '\n'), 0o600) == nil {
		os.Rename(tmp, w.StatePath)
	}
}

// phoneUSB says whether iface is a phone's own USB link (an iPhone's ipheth, an Android phone's RNDIS): only the phone is on
// that cable, so a new IPv6 network there is the phone's own (carriers change the prefixes they hand out), not a second
// router.
func phoneUSB(sysRoot, iface string) bool {
	d, err := filepath.EvalSymlinks(filepath.Join(sysRoot, "class/net", iface, "device/driver"))
	if err != nil {
		return false
	}
	switch filepath.Base(d) {
	case "ipheth", "rndis_host":
		return true
	}
	return false
}
