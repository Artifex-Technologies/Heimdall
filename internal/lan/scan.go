package lan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Paths the scan reads; variables so tests can point them elsewhere.
var (
	TrustedPath = "/etc/heimdall/wifi-trusted.json" // heimdall-wifi-guard's trusted networks: {uuid: {ssid, routers: [mac]}}
	ProcRoot    = "/proc"
)

type trustedNet struct {
	SSID    string   `json:"ssid"`
	Routers []string `json:"routers"`
}

// active is the network the default route goes through.
type active struct {
	iface, uuid, ssid string
	gateway           net.IP
}

// defaultRoute reads /proc/net/route for the IPv4 default route with the lowest metric.
func defaultRoute(procRoot string) (iface string, gw net.IP) {
	f, err := os.Open(filepath.Join(procRoot, "net/route"))
	if err != nil {
		return "", nil
	}
	defer f.Close()
	best := -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		x := strings.Fields(sc.Text())
		if len(x) < 7 || x[1] != "00000000" || x[7] != "00000000" {
			continue
		}
		var g uint32
		var metric int
		if _, err := fmt.Sscanf(x[2], "%X", &g); err != nil || g == 0 {
			continue
		}
		fmt.Sscan(x[6], &metric)
		if best < 0 || metric < best {
			best, iface = metric, x[0]
			gw = net.IPv4(byte(g), byte(g>>8), byte(g>>16), byte(g>>24)).To4()
		}
	}
	return iface, gw
}

// activeConnection asks NetworkManager which connection runs on iface (read-only; any account may ask).
func activeConnection(iface string) (uuid, name string) {
	out, err := exec.Command("nmcli", "-t", "-f", "UUID,DEVICE,NAME", "connection", "show", "--active").Output()
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		// NAME may contain ':' (escaped as '\:'); UUID and DEVICE never do
		p := strings.SplitN(line, ":", 3)
		if len(p) == 3 && p[1] == iface {
			return p[0], strings.ReplaceAll(strings.ReplaceAll(p[2], `\:`, ":"), `\\`, `\`)
		}
	}
	return "", ""
}

// arpTable reads the kernel's neighbour table for iface: complete entries only.
func arpTable(procRoot, iface string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(filepath.Join(procRoot, "net/arp"))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		x := strings.Fields(sc.Text())
		if len(x) >= 6 && x[5] == iface && x[2] != "0x0" && x[3] != "00:00:00:00:00:00" {
			out[x[0]] = strings.ToUpper(x[3])
		}
	}
	return out
}

// Options for one scan.
type Options struct {
	Dir  string        // state directory (devices.json, events.jsonl)
	Wait time.Duration // how long to listen for answers in each round (default 2 s)
	Log  func(format string, args ...any)
}

// Result summarises a scan for the command line.
type Result struct {
	Status  string
	SSID    string
	Devices int
	New     []Device
}

// Scan looks at the current network if it is trusted, updates the store and records new devices.
func Scan(o Options) (Result, error) {
	if o.Wait == 0 {
		o.Wait = 2 * time.Second
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	storePath, eventsPath := statePaths(o.Dir)
	st, err := Load(storePath)
	if err != nil {
		return Result{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	status := func(s, uuid string) (Result, error) {
		st.Status, st.StatusUUID, st.StatusTime = s, uuid, now
		return Result{Status: s}, st.Save(storePath)
	}

	var a active
	a.iface, a.gateway = defaultRoute(ProcRoot)
	if a.iface == "" {
		return status("offline", "")
	}
	a.uuid, a.ssid = activeConnection(a.iface)
	trusted := map[string]trustedNet{}
	if b, err := os.ReadFile(TrustedPath); err == nil {
		_ = json.Unmarshal(b, &trusted)
	}
	t, ok := trusted[a.uuid]
	if a.uuid == "" || !ok {
		return status("not_trusted", a.uuid)
	}
	if t.SSID != "" {
		a.ssid = t.SSID
	}
	ifc, err := net.InterfaceByName(a.iface)
	if err != nil {
		return Result{}, err
	}
	local, network := ifaceNet(ifc)
	if local == nil {
		return status("offline", a.uuid)
	}

	// look: the sweep fills the neighbour table while multicast DNS answers come in
	var md map[string]*found
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); md = mdns(ifc, local, o.Wait) }()
	sweep(local, network)
	time.Sleep(o.Wait)
	wg.Wait()

	arp := arpTable(ProcRoot, a.iface)
	routerMAC := arp[a.gateway.String()]
	if routerMAC == "" || !containsFold(t.Routers, routerMAC) {
		// the same network name with a different router is not the network the owner trusted
		return status("router_changed", a.uuid)
	}
	arp[local.String()] = strings.ToUpper(ifc.HardwareAddr.String())

	var ips []string
	for ip := range arp {
		if p := net.ParseIP(ip); p != nil && network.Contains(p) {
			ips = append(ips, ip)
		}
	}
	sort.Strings(ips)
	var unnamed []string
	for _, ip := range ips {
		if f := md[ip]; f == nil || len(f.names) == 0 {
			unnamed = append(unnamed, ip)
		}
	}
	rdns := reverseNames(a.gateway, ips)
	var nb map[string]string
	if len(unnamed) > 0 {
		nb = netbios(unnamed)
	}
	var macs []string
	for _, ip := range ips {
		macs = append(macs, arp[ip])
	}
	vend := vendors(OUIPath, macs)

	var seen []Device
	for _, ip := range ips {
		mac := arp[ip]
		d := Device{MAC: mac, IP: ip, Vendor: vend[mac], PrivateMAC: PrivateMAC(mac)}
		if f := md[ip]; f != nil {
			d.Names = append(d.Names, f.names...)
			d.Model = f.model
			for s := range f.services {
				d.Services = append(d.Services, s)
			}
			sort.Strings(d.Services)
		}
		for _, n := range []string{rdns[ip], nb[ip]} {
			if n != "" && !containsFold(d.Names, n) {
				d.Names = append(d.Names, n)
			}
		}
		if len(d.Names) > 0 {
			d.Name = d.Names[0]
		}
		switch {
		case ip == a.gateway.String():
			d.Kind = "router"
		case ip == local.String():
			d.Kind = "this"
		default:
			d.Kind = kindOf(d)
		}
		seen = append(seen, d)
	}

	n := st.network(a.uuid, a.ssid)
	fresh := n.Merge(seen, now)
	if err := appendEvents(eventsPath, a.ssid, fresh, now); err != nil {
		o.Log("new devices could not be recorded: %v", err)
	}
	st.Status, st.StatusUUID, st.StatusTime = "scanned", a.uuid, now
	return Result{Status: "scanned", SSID: a.ssid, Devices: len(seen), New: fresh}, st.Save(storePath)
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// ifaceNet is the interface's first IPv4 address and its subnet.
func ifaceNet(ifc *net.Interface) (net.IP, *net.IPNet) {
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, nil
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			ip := n.IP.To4()
			return ip, &net.IPNet{IP: ip.Mask(n.Mask), Mask: n.Mask}
		}
	}
	return nil, nil
}
