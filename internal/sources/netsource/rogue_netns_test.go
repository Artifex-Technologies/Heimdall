package netsource

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRogueRouterNetns runs only inside a throwaway network namespace (packaging/tests/netns-rogue.sh: unshare -rn, never the
// real network): a veth pair, a router advertisement from one end, the kernel's real IPv6 table on the other, then a second
// "router" on the same link announcing itself. The watcher must stay quiet on the first and report the second.
func TestRogueRouterNetns(t *testing.T) {
	if os.Getenv("HEIMDALL_NETNS_TEST") != "1" {
		t.Skip("runs only in a throwaway network namespace: packaging/tests/netns-rogue.sh")
	}
	run := func(args ...string) {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	// refuse anything but a namespace of our own: only loopback may exist before we add the pair
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Name != "lo" {
			t.Fatalf("interface %s exists: not a fresh network namespace, refusing", i.Name)
		}
	}
	run("ip", "link", "add", "va", "type", "veth", "peer", "name", "vb")
	run("sysctl", "-qw", "net.ipv6.conf.va.accept_dad=0", "net.ipv6.conf.vb.accept_dad=0")
	run("ip", "link", "set", "va", "up")
	run("ip", "link", "set", "vb", "up")
	run("ip", "-6", "addr", "add", "fe80::66/64", "dev", "vb", "nodad")
	time.Sleep(500 * time.Millisecond)
	vb, err := net.InterfaceByName("vb")
	if err != nil {
		t.Fatal(err)
	}
	var routerA string
	addrs, _ := vb.Addrs()
	for _, a := range addrs {
		ip := a.(*net.IPNet).IP
		if ip.IsLinkLocalUnicast() && !ip.Equal(net.ParseIP("fe80::66")) {
			routerA = ip.String()
		}
	}
	if routerA == "" {
		t.Fatal("no link-local address on vb")
	}

	dir := t.TempDir()
	w := NewRogueRouterWatcher(filepath.Join(dir, "netid.jsonl"), filepath.Join(dir, "current.json"), filepath.Join(dir, "routers.json"))
	os.WriteFile(w.NetIDPath, []byte(fmt.Sprintf(`{"t":%d,"action":"up","iface":"va","uuid":"00000000-0000-4000-8000-0000000000aa","dhcp4_server":"192.0.2.1"}`+"\n", time.Now().Unix())), 0o644)

	sendRA(t, vb.Index, routerA)
	waitRoute(t, "fe80")
	if ev := w.Poll(); len(ev) != 0 {
		t.Fatalf("the first router was reported: %v", ev)
	}
	sendRA(t, vb.Index, "fe80::66")
	waitRoute(t, "fe800000000000000000000000000066")
	ev := w.Poll()
	if len(ev) != 1 || ev[0].Fields["signals"] != "ra_router" || ev[0].Fields["after"] != "ra_router=fe80::66" || ev[0].Fields["before"] != "ra_router="+routerA {
		t.Fatalf("the second router: %v", ev)
	}
	t.Logf("reported: %s", ev[0].Text)
}

// waitRoute waits (at most 5 s) for a default route on va whose next hop starts with hop.
func waitRoute(t *testing.T, hop string) {
	for i := 0; i < 50; i++ {
		b, _ := os.ReadFile("/proc/net/ipv6_route")
		for _, l := range strings.Split(string(b), "\n") {
			x := strings.Fields(l)
			if len(x) >= 10 && x[9] == "va" && x[1] == "00" && strings.HasPrefix(x[4], hop) {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	b, _ := exec.Command("ip", "-6", "route").CombinedOutput()
	t.Fatalf("no default route via %s on va:\n%s", hop, b)
}

// sendRA sends one router advertisement (router lifetime 1800 s, the prefix 2001:db8:1::/64) from src on the interface
// ifindex to all nodes, hop limit 255 as the kernel requires.
func sendRA(t *testing.T, ifindex int, src string) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 255)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifindex)
	var sa syscall.SockaddrInet6
	copy(sa.Addr[:], net.ParseIP(src).To16())
	sa.ZoneId = uint32(ifindex)
	if err := syscall.Bind(fd, &sa); err != nil {
		t.Fatalf("bind %s: %v", src, err)
	}
	ra := []byte{134, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(ra[6:], 1800)
	pi := make([]byte, 32)
	pi[0], pi[1], pi[2], pi[3] = 3, 4, 64, 0xc0
	binary.BigEndian.PutUint32(pi[4:], 86400)
	binary.BigEndian.PutUint32(pi[8:], 14400)
	copy(pi[16:], net.ParseIP("2001:db8:1::").To16())
	var dst syscall.SockaddrInet6
	copy(dst.Addr[:], net.ParseIP("ff02::1").To16())
	dst.ZoneId = uint32(ifindex)
	if err := syscall.Sendto(fd, append(ra, pi...), 0, &dst); err != nil {
		t.Fatalf("send: %v", err)
	}
}
