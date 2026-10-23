package detect

import (
	"strings"
	"testing"
	"time"
)

func knock(kind, src, port string, at time.Time) Event {
	f := map[string]string{"src": src, "dst_port": port, "service": "ssh", "user": "root", "origin": "Netherlands, AS64500 Example", "origin_country_code": "NL"}
	return Event{Source: "host-firewall", Kind: kind, Time: at, Fields: f}
}

func TestInboundAlertsAddUpPerAddress(t *testing.T) {
	d := NewInboundDetector()
	t0 := time.Date(2026, 10, 23, 1, 0, 0, 0, time.UTC)
	var got []Finding
	for i := 0; i < 4; i++ {
		got = append(got, d.Inspect(knock("login_failure", "198.51.100.7", "", t0.Add(time.Duration(i)*time.Second)))...)
	}
	if len(got) != 0 {
		t.Fatalf("alert before the threshold: %v", got)
	}
	got = d.Inspect(knock("login_failure", "198.51.100.7", "", t0.Add(5*time.Second)))
	if len(got) != 1 || got[0].Severity != SeverityWarning || !strings.Contains(got[0].Summary, "sudo ufw insert 1 deny from 198.51.100.7") || !strings.Contains(got[0].Summary, "Netherlands") {
		t.Fatalf("failed logins: %+v", got)
	}
	if got[0].Event.Fields["origin_country_code"] != "NL" || got[0].Event.Fields["spoofable"] != "0" {
		t.Errorf("fields: %v", got[0].Event.Fields)
	}
	if again := d.Inspect(knock("login_failure", "198.51.100.7", "", t0.Add(10*time.Second))); len(again) != 0 {
		t.Error("alerted again inside the cooldown")
	}

	// a scan: many ports, no block command (the source may be forged)
	var scan []Finding
	for p := 0; p < 10; p++ {
		scan = append(scan, d.Inspect(knock("firewall_block", "203.0.113.9", string(rune('a'+p)), t0.Add(time.Duration(p)*time.Second)))...)
	}
	if len(scan) != 1 || !strings.Contains(scan[0].Summary, "port scan") || strings.Contains(scan[0].Summary, "ufw insert") {
		t.Fatalf("scan: %+v", scan)
	}

	// knocks spread out over more than the window never add up
	d2 := NewInboundDetector()
	for i := 0; i < 50; i++ {
		if f := d2.Inspect(knock("firewall_block", "192.0.2.1", "22", t0.Add(time.Duration(i)*time.Minute))); len(f) != 0 {
			t.Fatalf("slow knocks alerted at %d: %v", i, f)
		}
	}
	// many at once on one port: info only
	for i := 0; i < 20; i++ {
		if f := d2.Inspect(knock("firewall_block", "192.0.2.2", "22", t0.Add(time.Duration(i)*time.Second))); len(f) == 1 && (f[0].Severity != SeverityInfo || i != 19) {
			t.Fatalf("blocks: %+v at %d", f, i)
		}
	}
}
