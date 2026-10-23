package netsource

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

func TestRouterWatchCatchesAChangedOrCopiedRouter(t *testing.T) {
	d := t.TempDir()
	proc := filepath.Join(d, "proc")
	os.MkdirAll(filepath.Join(proc, "net"), 0o755)
	// default route via 192.168.1.1 (0101A8C0 little-endian) on wlan0
	os.WriteFile(filepath.Join(proc, "net/route"), []byte("Iface\tDestination\tGateway\tFlags\nwlan0\t00000000\t0101A8C0\t0003\n"), 0o644)
	arp := func(s string) {
		os.WriteFile(filepath.Join(proc, "net/arp"), []byte("IP address       HW type     Flags       HW address            Mask     Device\n"+s), 0o644)
	}
	cur := filepath.Join(d, "current.json")
	os.WriteFile(cur, []byte(`{"ssid":"Cafe","iface":"wlan0","gateway":"192.168.1.1","gateway_mac":"AA:BB:CC:00:00:01","trusted":false}`), 0o644)
	w := NewRouterWatcher(cur)
	w.procRoot = proc
	arp("192.168.1.1      0x1         0x2         aa:bb:cc:00:00:01     *        wlan0\n")
	if ev := w.Poll(); len(ev) != 0 {
		t.Fatalf("all fine, yet: %v", ev)
	}
	arp("192.168.1.1      0x1         0x2         de:ad:be:ef:00:09     *        wlan0\n192.168.1.50     0x1         0x2         de:ad:be:ef:00:09     *        wlan0\n")
	ev := w.Poll()
	if len(ev) != 1 || ev[0].Kind != "router_changed" || ev[0].Fields["new_mac"] != "DE:AD:BE:EF:00:09" {
		t.Fatalf("changed router: %+v", ev)
	}
	if f := detect.NewLANDetector().Inspect(ev[0]); len(f) != 1 || f[0].Severity != detect.SeverityCritical {
		t.Errorf("finding: %+v", f)
	}
	if ev := w.Poll(); len(ev) != 0 {
		t.Error("reported twice")
	}
	arp("192.168.1.1      0x1         0x2         aa:bb:cc:00:00:01     *        wlan0\n192.168.1.66     0x1         0x2         aa:bb:cc:00:00:01     *        wlan0\n")
	if ev := w.Poll(); len(ev) != 1 || ev[0].Kind != "router_impersonated" || ev[0].Fields["other_ip"] != "192.168.1.66" {
		t.Errorf("copied router: %+v", ev)
	}
	// trusted networks are not watched
	os.WriteFile(cur, []byte(`{"ssid":"Home","iface":"wlan0","gateway":"192.168.1.1","gateway_mac":"11:22:33:44:55:66","trusted":true}`), 0o644)
	if ev := w.Poll(); len(ev) != 0 {
		t.Errorf("a trusted network was watched: %v", ev)
	}
}

func TestANewListenerIsReportedAfterLearning(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "net"), 0o755)
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	write := func(tcp, udp string) {
		os.WriteFile(filepath.Join(d, "net/tcp"), []byte(hdr+tcp), 0o644)
		os.WriteFile(filepath.Join(d, "net/udp"), []byte(hdr+udp), 0o644)
	}
	// loopback listener on 8899 (ignored) and DHCP client udp/68 (expected)
	write("   0: 0100007F:22C3 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1\n",
		"   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2\n")
	w := NewListenWatcher()
	w.procRoot = d
	if ev := w.Poll(); len(ev) != 0 {
		t.Fatalf("learning run reported: %v", ev)
	}
	// something starts listening on all addresses, tcp/8080 (1F90)
	write("   0: 0100007F:22C3 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1\n   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 3\n",
		"   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2\n   1: 00000000:C350 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 4\n")
	ev := w.Poll() // udp/50000 (C350) is a client socket in the temporary range: not reported
	if len(ev) != 1 || ev[0].Fields["port"] != "8080" || ev[0].Fields["proto"] != "tcp" {
		t.Fatalf("new listener: %+v", ev)
	}
	if ev := w.Poll(); len(ev) != 0 {
		t.Error("reported twice")
	}
}
