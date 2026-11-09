package netsource

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// RouterWatcher keeps an eye on the router of an untrusted Wi-Fi network for as long as this computer is on it: the router's
// hardware address must not change, and no other address may answer with it (both are what ARP spoofing looks like: someone
// placing themselves between this computer and the router). It reads the network heimdall-wifi-check recorded when the network was
// joined (current.json) and the kernel's neighbour table (/proc/net/arp): no traffic, no network access, microseconds per poll.
// Trusted networks are not watched, as the owner chose.
type RouterWatcher struct {
	CurrentPath string // heimdall-wifi-check's current.json
	procRoot    string
	reported    map[string]bool
}

func NewRouterWatcher(currentPath string) *RouterWatcher {
	return &RouterWatcher{CurrentPath: currentPath, procRoot: "/proc", reported: map[string]bool{}}
}

type current struct {
	SSID       string `json:"ssid"`
	Iface      string `json:"iface"`
	Gateway    string `json:"gateway"`
	GatewayMAC string `json:"gateway_mac"`
	Trusted    bool   `json:"trusted"`
}

type arpEntry struct{ ip, mac, dev string }

func readARP(path string) []arpEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []arpEntry
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		x := strings.Fields(sc.Text())
		// IP address, HW type, Flags, HW address, Mask, Device; flags 0x0 means incomplete
		if len(x) >= 6 && x[2] != "0x0" && x[3] != "00:00:00:00:00:00" {
			out = append(out, arpEntry{x[0], strings.ToUpper(x[3]), x[5]})
		}
	}
	return out
}

// defaultGateway reads /proc/net/route for the default route's gateway on iface.
func (w *RouterWatcher) defaultGateway(iface string) string {
	f, err := os.Open(filepath.Join(w.procRoot, "net/route"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		x := strings.Fields(sc.Text())
		if len(x) >= 3 && x[0] == iface && x[1] == "00000000" {
			var g uint32
			if _, err := fmt.Sscanf(x[2], "%X", &g); err == nil && g != 0 {
				return fmt.Sprintf("%d.%d.%d.%d", byte(g), byte(g>>8), byte(g>>16), byte(g>>24))
			}
		}
	}
	return ""
}

func (w *RouterWatcher) Poll() []detect.Event {
	raw, err := os.ReadFile(w.CurrentPath)
	if err != nil {
		return nil
	}
	var c current
	if json.Unmarshal(raw, &c) != nil || c.Trusted || c.Iface == "" || c.Gateway == "" || c.GatewayMAC == "" {
		return nil
	}
	// still on that network? (same interface, same router address) Otherwise wait for the next check to record the new one.
	if w.defaultGateway(c.Iface) != c.Gateway {
		return nil
	}
	var events []detect.Event
	emit := func(kind, key, text string, f map[string]string) {
		if w.reported[key] {
			return
		}
		w.reported[key] = true
		f["ssid"], f["gateway"], f["expected_mac"] = c.SSID, c.Gateway, c.GatewayMAC
		events = append(events, detect.Event{Source: "host-lan", Time: time.Now(), Kind: kind, Text: text, Fields: f})
	}
	for _, e := range readARP(filepath.Join(w.procRoot, "net/arp")) {
		if e.dev != c.Iface {
			continue
		}
		if e.ip == c.Gateway && e.mac != c.GatewayMAC {
			emit("router_changed", c.Gateway+"|"+e.mac, fmt.Sprintf("the router %s of %q now answers with hardware address %s (it was %s)", c.Gateway, c.SSID, e.mac, c.GatewayMAC),
				map[string]string{"new_mac": e.mac})
		}
		if e.ip != c.Gateway && e.mac == c.GatewayMAC {
			emit("router_impersonated", e.ip+"|"+e.mac, fmt.Sprintf("%s answers with the router's hardware address %s on %q", e.ip, e.mac, c.SSID),
				map[string]string{"other_ip": e.ip, "new_mac": e.mac})
		}
	}
	return events
}

func (w *RouterWatcher) Run(ctx context.Context, interval time.Duration, emit func(detect.Event)) {
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

// ListenWatcher reports a program that starts listening for connections from the network (any address other than loopback),
// once per protocol and port. The first poll only learns what already listens. DHCP and local discovery ports are expected.
type ListenWatcher struct {
	procRoot string
	known    map[string]bool
	learned  bool
}

func NewListenWatcher() *ListenWatcher {
	return &ListenWatcher{procRoot: "/proc", known: map[string]bool{}}
}

var expectedUDP = map[int]bool{68: true, 546: true, 5353: true, 1900: true}

// ephemeral is the kernel's range for temporary ports: an unconnected UDP socket there is a program's client socket (a browser's
// QUIC, a game), not a service waiting for others.
func (w *ListenWatcher) ephemeral() (lo, hi int) {
	lo, hi = 32768, 60999
	if b, err := os.ReadFile(filepath.Join(w.procRoot, "sys/net/ipv4/ip_local_port_range")); err == nil {
		fmt.Sscan(string(b), &lo, &hi)
	}
	return lo, hi
}

// listening lists what listens off loopback: TCP from tcp (a read of /proc/net/tcp and tcp6), UDP read here.
func (w *ListenWatcher) listening(tcp []socketEntry) []string {
	var out []string
	for _, e := range tcp {
		if !e.LocalIP.IsLoopback() && e.State == tcpListen {
			out = append(out, fmt.Sprintf("tcp/%d", e.LocalPort))
		}
	}
	lo, hi := w.ephemeral()
	for _, file := range []string{"net/udp", "net/udp6"} {
		fh, err := os.Open(filepath.Join(w.procRoot, file))
		if err != nil {
			continue
		}
		entries, _ := ParseProcNetTCP(fh)
		fh.Close()
		for _, e := range entries {
			if e.LocalIP.IsLoopback() {
				continue
			}
			if e.State != 0x07 || !e.RemoteIP.IsUnspecified() || expectedUDP[e.LocalPort] || (e.LocalPort >= lo && e.LocalPort <= hi) {
				continue // a connected UDP socket is a client, not a listener
			}
			out = append(out, fmt.Sprintf("udp/%d", e.LocalPort))
		}
	}
	sort.Strings(out)
	return out
}

// Poll reads the TCP tables itself; in heimdalld, Tables shares its read (observe).
func (w *ListenWatcher) Poll() []detect.Event {
	tcp, _ := readTables([]string{filepath.Join(w.procRoot, "net/tcp"), filepath.Join(w.procRoot, "net/tcp6")})
	return w.observe(tcp)
}

func (w *ListenWatcher) observe(tcp []socketEntry) []detect.Event {
	now := w.listening(tcp)
	var events []detect.Event
	for _, k := range now {
		if w.known[k] {
			continue
		}
		w.known[k] = true
		if !w.learned {
			continue
		}
		proto, port, _ := strings.Cut(k, "/")
		events = append(events, detect.Event{Source: "host-network", Time: time.Now(), Kind: "new_listener",
			Text:   "a program started listening for connections from the network on " + k,
			Fields: map[string]string{"proto": proto, "port": port}})
	}
	w.learned = true
	return events
}
