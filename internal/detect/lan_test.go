package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func inboundEvent(src, proto, port, icmpType string, at time.Time) Event {
	return Event{Source: "host-wifi", Time: at, Kind: "wifi_inbound", Fields: map[string]string{
		"src": src, "src_mac": "0E:00:00:00:00:05", "proto": proto, "dst_port": port, "icmp_type": icmpType, "iface": "wlan0", "inbound": "wifi"}}
}

// A device on Wi-Fi reaching for this computer is listed (info, no notification) on every network (made-up addresses): once
// per device an hour, named by what it asked for.
func TestWifiInboundIsListedOncePerDeviceAndHour(t *testing.T) {
	d := NewLANDetector()
	t0 := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	for i, c := range []struct {
		src, proto, port, icmpType string
		at                         time.Duration
		want                       string // "" for no finding
	}{
		{"192.0.2.23", "TCP", "445", "", 0, "a connection to Windows file sharing (port 445)"},
		{"192.0.2.23", "UDP", "137", "", time.Minute, ""}, // the same device within the hour
		{"192.0.2.24", "ICMP", "", "8", 2 * time.Minute, "a ping"},
		{"2001:db8::25", "UDP", "137", "", 3 * time.Minute, "a NetBIOS question for this computer's name (port 137)"},
		{"192.0.2.23", "TCP", "22", "", 61 * time.Minute, "a connection to SSH (port 22)"},
		{"192.0.2.26", "TCP", "8080", "", 62 * time.Minute, "a connection to port 8080 (TCP)"},
		{"", "TCP", "22", "", 63 * time.Minute, ""},
	} {
		got := d.Inspect(inboundEvent(c.src, c.proto, c.port, c.icmpType, t0.Add(c.at)))
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%d: want none, got %+v", i, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Severity != SeverityInfo || !strings.Contains(got[0].Summary, c.want) || !strings.Contains(got[0].Summary, c.src) {
			t.Errorf("%d: want info with %q, got %+v", i, c.want, got)
		}
	}
	// a sweep from many addresses: each listed, the sixth within 10 minutes a warning (once an hour), at most
	// inboundListedPerHour listed in an hour
	d = NewLANDetector()
	var all []Finding
	for i := 0; i < 40; i++ {
		all = append(all, d.Inspect(inboundEvent(fmt.Sprintf("192.0.2.%d", 30+i), "TCP", "22", "", t0.Add(time.Duration(i)*time.Second)))...)
	}
	warnings := 0
	for i, f := range all {
		if f.Severity == SeverityWarning {
			warnings++
			if i != sweepDevices-1 || !strings.Contains(f.Summary, "6 devices on Wi-Fi tried to reach this computer within 10 minutes") || !strings.Contains(f.Summary, "192.0.2.35") {
				t.Errorf("the sweep warning: %d %+v", i, f)
			}
		}
	}
	if len(all) != inboundListedPerHour || warnings != 1 {
		t.Errorf("a sweep gave %d alerts (%d warnings), want %d and one warning: %+v", len(all), warnings, inboundListedPerHour, all)
	}
	if got := d.Inspect(inboundEvent("192.0.2.99", "TCP", "22", "", t0.Add(time.Hour+time.Minute))); len(got) != 1 || got[0].Severity != SeverityInfo {
		t.Errorf("the next hour: %+v", got)
	}
	// six devices spread over 15 minutes: never six within 10, so listed only
	d = NewLANDetector()
	for i := 0; i < sweepDevices; i++ {
		got := d.Inspect(inboundEvent(fmt.Sprintf("192.0.2.%d", 80+i), "TCP", "22", "", t0.Add(time.Duration(3*i)*time.Minute)))
		if len(got) != 1 || got[0].Severity != SeverityInfo {
			t.Errorf("spread out, device %d: %+v", i, got)
		}
	}
	// lines handed over out of order: the hour lies on either side of the event, so an earlier line does not report again
	d = NewLANDetector()
	if got := d.Inspect(inboundEvent("192.0.2.40", "TCP", "22", "", t0.Add(10*time.Minute))); len(got) != 1 {
		t.Fatalf("first: %+v", got)
	}
	if got := d.Inspect(inboundEvent("192.0.2.40", "TCP", "23", "", t0)); len(got) != 0 {
		t.Errorf("an earlier line of the same device: %+v", got)
	}
}

// The network's router looking at this computer (a device map) is info, once per connection, and takes no place among the
// devices of the hour.
func TestWifiInboundFromTheRouterIsInfo(t *testing.T) {
	d := NewLANDetector()
	t0 := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	ev := inboundEvent("192.168.0.1", "ICMP", "", "8", t0)
	ev.Fields["router"] = "true"
	got := d.Inspect(ev)
	if len(got) != 1 || got[0].Severity != SeverityInfo || !strings.Contains(got[0].Summary, "the router of this Wi-Fi network (192.168.0.1)") {
		t.Fatalf("%+v", got)
	}
	// five more devices at once: with the router that would be six, but the router does not count toward a sweep
	for i := 0; i < sweepDevices-1; i++ {
		if got := d.Inspect(inboundEvent(fmt.Sprintf("192.168.0.%d", 30+i), "TCP", "22", "", t0.Add(time.Minute))); len(got) != 1 || got[0].Severity != SeverityInfo {
			t.Errorf("the router took a place among the devices: %d %+v", i, got)
		}
	}
}

// A ping is answered (ufw does by default): the alert says so instead of "the firewall drops it".
func TestWifiInboundPingWording(t *testing.T) {
	got := NewLANDetector().Inspect(inboundEvent("192.0.2.24", "ICMP", "", "8", time.Now()))
	if len(got) != 1 || !strings.Contains(got[0].Summary, "answers pings") || strings.Contains(got[0].Summary, "drops it") {
		t.Fatalf("%+v", got)
	}
	got = NewLANDetector().Inspect(inboundEvent("192.0.2.24", "TCP", "22", "", time.Now()))
	if len(got) != 1 || !strings.Contains(got[0].Summary, "The firewall drops it unless a rule allows it") {
		t.Fatalf("%+v", got)
	}
}

// A protected network (exposure covered by verified protections) is info, never a warning.
func TestProtectedWifiIsInfo(t *testing.T) {
	got := NewWifiDetector().Inspect(Event{Kind: "wifi_check", Fields: map[string]string{"ssid": "Example-Phone", "verdict": "protected"}})
	if len(got) != 1 || got[0].Severity != SeverityInfo || !strings.Contains(got[0].Summary, "protected") {
		t.Fatalf("%+v", got)
	}
}
