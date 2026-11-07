package lan

import (
	"context"
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Discovery uses only what any device on a home network does to find printers and TVs. Every answer it waits for is one the
// firewall already lets in: multicast DNS answers go to the group (ufw's default rules accept 224.0.0.251:5353), and the
// unicast questions (the router's reverse names, NetBIOS names) get replies the firewall matches to the question. SSDP is left
// out on purpose: its replies come back unicast to a multicast question, so the firewall drops them, and Heimdall's own
// inbound watch would count every reply as a port tried.

// found is what discovery learned about one address.
type found struct {
	names    []string // best first
	model    string
	services map[string]bool
}

// sweep sends one tiny UDP datagram (port 9, "discard") to every address of a small subnet so the kernel asks each one for its
// hardware address (ARP). Devices that are up answer the ARP question; the datagram itself is thrown away or answered with
// "port unreachable". Subnets larger than /22 (1022 addresses) are not swept.
func sweep(local net.IP, network *net.IPNet) {
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 22 || ones > 30 {
		return
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local})
	if err != nil {
		return
	}
	defer c.Close()
	base := binary.BigEndian.Uint32(network.IP.To4())
	n := uint32(1) << (32 - ones)
	for i := uint32(1); i < n-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base+i)
		if ip.Equal(local) {
			continue
		}
		_, _ = c.WriteToUDP([]byte{0}, &net.UDPAddr{IP: ip, Port: 9})
		if i%32 == 0 {
			time.Sleep(15 * time.Millisecond) // gentle: about 2000 a second at most
		}
	}
}

var mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// Service types asked for by name as well as through the catalogue (_services._dns-sd._udp), because some devices answer
// only for their own types.
var commonTypes = []string{
	"_googlecast._tcp.local", "_airplay._tcp.local", "_raop._tcp.local", "_amzn-wplay._tcp.local", "_spotify-connect._tcp.local",
	"_ipp._tcp.local", "_printer._tcp.local", "_hap._tcp.local", "_smb._tcp.local", "_device-info._tcp.local",
	"_companion-link._tcp.local", "_workstation._tcp.local", "_ssh._tcp.local", "_sonos._tcp.local", "_androidtvremote2._tcp.local",
}

// mdns asks the network which services exist, then for each type, and listens for the answers for wait each round.
func mdns(ifc *net.Interface, local net.IP, wait time.Duration) map[string]*found {
	out := map[string]*found{}
	c, err := net.ListenMulticastUDP("udp4", ifc, mdnsGroup)
	if err != nil {
		return out
	}
	defer c.Close()
	// send on this interface, and do not hear our own question
	if rc, err := c.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, [4]byte(local.To4()))
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 0)
		})
	}
	types := map[string]bool{}
	ask := func(names []string) {
		for len(names) > 0 {
			k := min(len(names), 12)
			_, _ = c.WriteToUDP(query(names[:k]), mdnsGroup)
			names = names[k:]
		}
	}
	listen := func() {
		buf := make([]byte, 9000)
		deadline := time.Now().Add(wait)
		for {
			_ = c.SetReadDeadline(deadline)
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			recs, _ := parse(buf[:n])
			absorb(out, types, from.IP, recs)
		}
	}
	ask(append([]string{"_services._dns-sd._udp.local"}, commonTypes...))
	listen()
	var more []string
	for t := range types {
		if !contains(commonTypes, t) {
			more = append(more, t)
		}
	}
	sort.Strings(more)
	if len(more) > 36 {
		more = more[:36]
	}
	if len(more) > 0 {
		ask(more)
		listen()
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// absorb files the records of one answer under the address that sent it (a device answers for itself) and notes the service
// types the catalogue named.
func absorb(out map[string]*found, types map[string]bool, from net.IP, recs []record) {
	if from.To4() == nil {
		return
	}
	f := out[from.String()]
	if f == nil {
		f = &found{services: map[string]bool{}}
		out[from.String()] = f
	}
	var instance, host, cast, model string
	for _, r := range recs {
		lname := strings.ToLower(r.name)
		switch r.rtype {
		case typePTR:
			if lname == "_services._dns-sd._udp.local" {
				types[strings.ToLower(r.ptr)] = true
				continue
			}
			typ := serviceType(lname)
			if typ == "" {
				continue
			}
			f.services[typ] = true
			if name := instanceName(r.ptr, typ); name != "" && instance == "" && typ != "_device-info._tcp" {
				instance = name
			}
		case typeSRV:
			if host == "" {
				host = strings.TrimSuffix(strings.TrimSuffix(r.ptr, "."), ".local")
			}
		case typeA:
			if host == "" && strings.HasSuffix(lname, ".local") {
				host = strings.TrimSuffix(r.name, ".local")
			}
		case typeTXT:
			for _, kv := range r.txt {
				k, v, _ := strings.Cut(kv, "=")
				switch k = strings.ToLower(k); {
				case k == "fn", k == "dn", k == "n" && serviceType(lname) == "_amzn-wplay._tcp":
					// the name its owner gave it: Chromecast / Google TV (fn), Matter devices (DN), Fire TV (n)
					if cast == "" {
						cast = v
					}
				case k == "md", k == "model", k == "am", k == "ty":
					if model == "" {
						model = v
					}
				}
			}
		}
	}
	for _, n := range []string{cast, instance, host} {
		if n = clean(n); n != "" && !contains(f.names, n) && !looksGenerated(n, from.String()) && !looksID(n) {
			f.names = append(f.names, n)
		}
	}
	if f.model == "" {
		f.model = clean(model)
	}
}

// serviceType reduces "Name._airplay._tcp.local" or "_airplay._tcp.local" to "_airplay._tcp".
func serviceType(name string) string {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 0; i+1 < len(parts); i++ {
		if strings.HasPrefix(parts[i], "_") && (parts[i+1] == "_tcp" || parts[i+1] == "_udp") {
			return parts[i] + "." + parts[i+1]
		}
	}
	return ""
}

// instanceName is the human part of "Living Room._googlecast._tcp.local"; AirPlay audio names look like "A1B2C3D4E5F6@Kitchen".
func instanceName(full, typ string) string {
	i := strings.Index(strings.ToLower(full), "."+typ)
	if i <= 0 {
		return ""
	}
	n := full[:i]
	if at := strings.IndexByte(n, '@'); at >= 0 && typ == "_raop._tcp" {
		n = n[at+1:]
	}
	if typ == "_googlecast._tcp" || typ == "_amzn-wplay._tcp" || typ == "_matterd._udp" || typ == "_matter._tcp" {
		return "" // these instance names are ids; the friendly name comes from TXT (fn, n, DN)
	}
	return n
}

// clean keeps a name printable and short: whoever runs a device chooses its name.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64])
	}
	return s
}

// reverseNames asks the router for the names it gave out (most home routers answer reverse lookups for their DHCP clients).
func reverseNames(router net.IP, ips []string) map[string]string {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", net.JoinHostPort(router.String(), "53"))
	}}
	out := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			names, err := r.LookupAddr(ctx, ip)
			if err != nil || len(names) == 0 {
				return
			}
			n := strings.TrimSuffix(names[0], ".")
			if i := strings.IndexByte(n, '.'); i > 0 {
				n = n[:i] // "tv.lan", "phone.home" -> the device part
			}
			if n = clean(n); n != "" && !looksGenerated(n, ip) {
				mu.Lock()
				out[ip] = n
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return out
}

// looksGenerated spots names a router makes up from the address ("192-168-1-20", "host-20", "dhcp20").
func looksGenerated(n, ip string) bool {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, n)
	return digits != "" && strings.Contains(strings.ReplaceAll(ip, ".", ""), digits) && len(digits) >= len(n)/2
}

// looksID spots names that are machine ids: long runs of hex digits ("0F1E2D3C4B5A6978", "02AB34CD56EF") or "a:b:c" tokens.
func looksID(n string) bool {
	if strings.Count(n, ":") >= 2 {
		return true
	}
	hex := 0
	for _, r := range n {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			hex++
		}
	}
	return len(n) >= 8 && hex == len(n)
}

// netbios asks each address for its Windows name (a node status query to UDP 137; Windows computers and Samba answer).
func netbios(ips []string) map[string]string {
	out := map[string]string{}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return out
	}
	defer c.Close()
	q := []byte{0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 'C', 'K'}
	for i := 0; i < 30; i++ {
		q = append(q, 'A')
	}
	q = append(q, 0, 0, 0x21, 0, 1)
	for _, ip := range ips {
		_, _ = c.WriteToUDP(q, &net.UDPAddr{IP: net.ParseIP(ip), Port: 137})
	}
	buf := make([]byte, 1500)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for {
		_ = c.SetReadDeadline(deadline)
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return out
		}
		if name := nbName(buf[:n]); name != "" {
			out[from.IP.String()] = name
		}
	}
}

// nbName reads the first unique workstation name (suffix 0x00) from a node status answer.
func nbName(m []byte) string {
	// header 12, name 34, type/class 4, ttl 4, rdlength 2, count 1
	const off = 12 + 34 + 4 + 4 + 2
	if len(m) <= off || m[2]&0x80 == 0 {
		return ""
	}
	count := int(m[off])
	for i := 0; i < count; i++ {
		e := off + 1 + i*18
		if e+18 > len(m) {
			return ""
		}
		flags := binary.BigEndian.Uint16(m[e+16:])
		if m[e+15] == 0x00 && flags&0x8000 == 0 { // workstation, not a group
			return clean(strings.TrimRight(string(m[e:e+15]), " \x00"))
		}
	}
	return ""
}
