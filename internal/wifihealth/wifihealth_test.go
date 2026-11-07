package wifihealth

import (
	"strings"
	"testing"
)

const iwLink = `Connected to 00:11:22:33:44:55 (on wlan0)
	SSID: Home
	freq: 5785.0
	signal: -61 dBm
	rx bitrate: 195.0 MBit/s VHT-MCS 4 80MHz short GI VHT-NSS 1
	tx bitrate: 585.1 MBit/s VHT-MCS 6 80MHz short GI VHT-NSS 2
Station 00:11:22:33:44:55 (on wlan0)
	tx packets:	13809157
	tx retries:	116160
	tx failed:	10
	expected throughput:	478.62Mbps
`

func TestParseLink(t *testing.T) {
	l, ok := ParseLink(iwLink)
	if !ok || l.SSID != "Home" || l.Channel != 157 || l.Band != "5 GHz" || l.Width != 80 || l.SignalDBm != -61 ||
		l.RxMbps != 195 || l.TxPackets != 13809157 || l.TxRetries != 116160 || l.ExpectedMbp != 478.62 {
		t.Fatalf("%+v", l)
	}
	if _, ok := ParseLink("Not connected.\n"); ok {
		t.Fatal("not connected")
	}
	for _, c := range []struct {
		mhz, ch int
		band    string
	}{{2412, 1, "2.4 GHz"}, {2437, 6, "2.4 GHz"}, {2484, 14, "2.4 GHz"}, {5180, 36, "5 GHz"}, {5955, 1, "6 GHz"}} {
		if ch, b := Channel(c.mhz); ch != c.ch || b != c.band {
			t.Errorf("%d: %d %s", c.mhz, ch, b)
		}
	}
}

func TestOverlaps(t *testing.T) {
	for _, c := range []struct {
		band    string
		a, w, b int
		want    bool
	}{
		{"2.4 GHz", 6, 20, 6, true}, {"2.4 GHz", 6, 20, 8, true}, {"2.4 GHz", 1, 20, 6, false}, {"2.4 GHz", 6, 20, 11, false},
		{"5 GHz", 157, 80, 149, true}, {"5 GHz", 157, 80, 161, true}, {"5 GHz", 157, 80, 44, false}, {"5 GHz", 36, 20, 40, false},
		{"5 GHz", 36, 80, 48, true}, {"5 GHz", 36, 80, 52, false},
	} {
		if got := Overlaps(c.band, c.a, c.w, c.b); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

func TestParseScanFindsTheRoutersOwnSecondNetwork(t *testing.T) {
	scan := "*:Home:00\\:11\\:22\\:33\\:44\\:55:5785 MHz:70\n" +
		" :Provider Hotspot:02\\:11\\:22\\:33\\:44\\:55:5785 MHz:70\n" +
		" :Home:00\\:11\\:22\\:33\\:44\\:56:2437 MHz:80\n" +
		" :Neighbour\\:5G:66\\:77\\:88\\:99\\:AA\\:BB:5745 MHz:50\n"
	ns := ParseScan(scan, "Home")
	if len(ns) != 4 || !ns[0].InUse || !ns[1].SameRouter || !ns[2].Own || ns[3].SSID != "Neighbour:5G" || ns[3].Channel != 149 {
		t.Fatalf("%+v", ns)
	}
	l, _ := ParseLink(iwLink)
	r := Report{Link: l}
	r.Neighbourhood(ns)
	if r.Heard != 1 || len(r.FromRouter) != 1 || r.FromRouter[0] != "Provider Hotspot" || r.Own5GHz {
		t.Fatalf("heard %d, from router %v", r.Heard, r.FromRouter)
	}
}

func TestParsePingUsesTheTypicalAnswer(t *testing.T) {
	out := "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.1 ms\n64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=2.4 ms\n" +
		"64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=109 ms\n64 bytes from 192.168.1.1: icmp_seq=4 ttl=64 time=2.3 ms\n\n" +
		"--- 192.168.1.1 ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss, time 754ms\nrtt min/avg/max/mdev = 2.1/28.9/109/46.3 ms\n"
	p := ParsePing("192.168.1.1", out)
	if !p.OK || p.Sent != 4 || p.LossPct != 0 || p.MedianMs != 2.4 || p.MaxMs != 109 {
		t.Fatalf("%+v", p)
	}
	if p := ParsePing("x", "2 packets transmitted, 0 received, 100% packet loss\n"); p.OK || p.LossPct != 100 {
		t.Fatalf("%+v", p)
	}
}

func good() Report {
	return Report{Connected: true, DevicesHere: 8,
		Link:   Link{SSID: "Home", Band: "5 GHz", Channel: 36, Width: 80, SignalDBm: -55},
		Router: Ping{OK: true, MedianMs: 2, MaxMs: 4}, Internet: Ping{OK: true, MedianMs: 20}, RetriesPct: 1, RetriesSpan: "check"}
}

func TestJudgeNamesTheCause(t *testing.T) {
	crowd := []Neighbour{}
	for i := 0; i < 7; i++ {
		crowd = append(crowd, Neighbour{SSID: "N", Band: "2.4 GHz", Channel: 6, Signal: 70})
	}
	for _, c := range []struct {
		name    string
		change  func(r *Report)
		summary string
		verdict string
	}{
		{"healthy", func(r *Report) {}, "Your Wi-Fi looks healthy", "good"},
		{"weak signal", func(r *Report) { r.Link.SignalDBm = -80 }, "A weak signal is the likely cause", "bad"},
		{"crowded 2.4", func(r *Report) {
			r.Link.Band, r.Link.Channel, r.Link.Width = "2.4 GHz", 6, 20
			r.Neighbourhood(crowd)
		}, "A crowded channel is the likely cause", "bad"},
		{"busy network", func(r *Report) { r.Router.MedianMs = 25 }, "Other devices using the network are the likely cause", "warn"},
		{"past the router", func(r *Report) { r.Internet.MedianMs = 150 }, "Your Wi-Fi is fine; the problem is past the router (the internet provider or the router's connection)", "bad"},
		{"not connected", func(r *Report) { r.Connected = false }, "Not connected to Wi-Fi", "bad"},
	} {
		r := good()
		c.change(&r)
		r.Judge()
		if r.Summary != c.summary || r.Verdict != c.verdict {
			t.Errorf("%s: %q (%s)", c.name, r.Summary, r.Verdict)
		}
	}
	// a crowded channel suggests a quieter one
	r := good()
	r.Link.Band, r.Link.Channel, r.Link.Width = "2.4 GHz", 6, 20
	r.Neighbourhood(crowd)
	r.Judge()
	if len(r.Better) == 0 || !strings.Contains(r.Findings[1].Detail, "Channel 1 or 11 is quieter") {
		t.Fatalf("%v %q", r.Better, r.Findings[1].Detail)
	}
	// power saving's late answers are named, not blamed
	r = good()
	r.PowerSave, r.Router.MaxMs = true, 110
	r.Judge()
	if r.Verdict != "good" || !strings.Contains(r.Findings[3].Title+r.Findings[4].Title, "Power saving") {
		t.Fatalf("%+v", r.Findings)
	}
	// a line that fills up
	r = good()
	r.Speed = &Speed{DownMbps: 300, Server: "mirror", Loaded: &Ping{OK: true, MedianMs: 180}}
	r.Judge()
	if r.Summary != "Slow answers while the line is full" || r.Verdict != "warn" {
		t.Fatalf("%q %s", r.Summary, r.Verdict)
	}
}
