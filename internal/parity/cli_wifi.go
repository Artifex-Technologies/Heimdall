package parity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Artifex-Technologies/Heimdall/internal/wifihealth"
)

// The Wi-Fi check's parsers and judge (heimdalld wifi-health), as fixtures for the Rust port (rust/heimdall/tests/cli_wifi.rs):
// iw's link and station dumps, NetworkManager's scan list, ping's output, channels and overlaps, Go's sort.Slice order of
// equal elements, and whole reports (the JSON Settings reads and the text people read) from made-up radio situations.

// Raw keeps the bytes of a text that is not UTF-8 (JSON would turn them into U+FFFD), by field name.
type Raw map[string][]byte

func raw(r *Raw, name, s string) {
	if !utf8.ValidString(s) {
		if *r == nil {
			*r = Raw{}
		}
		(*r)[name] = []byte(s)
	}
}

func wifiJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "error: " + err.Error()
	}
	return string(b)
}

// WifiLink is one `iw` text and what ParseLink makes of it, as JSON with every field (the counters too).
type WifiLink struct {
	In  string `json:"in"`
	Raw Raw    `json:"raw,omitempty"`
	OK  bool   `json:"ok"`
	Out string `json:"out"`
}

type wifiLinkAll struct {
	wifihealth.Link
	TxPackets uint64 `json:"tx_packets"`
	TxRetries uint64 `json:"tx_retries"`
	TxFailed  uint64 `json:"tx_failed"`
}

type wifiNeighbourAll struct {
	wifihealth.Neighbour
	BSSID string `json:"bssid"`
}

// WifiScan is one scan list and the networks read from it (JSON, hardware addresses included).
type WifiScan struct {
	In  string `json:"in"`
	Own string `json:"own"`
	Raw Raw    `json:"raw,omitempty"`
	Out string `json:"out"`
}

// WifiPing is one ping output and its summary (JSON).
type WifiPing struct {
	Target string `json:"target"`
	In     string `json:"in"`
	Out    string `json:"out"`
}

// WifiSort is one sort.Slice: keys, and the original positions in the order Go leaves them.
type WifiSort struct {
	Keys  []int `json:"keys"`
	Order []int `json:"order"`
}

// WifiSpeedIn is the speed test's result given to the judge.
type WifiSpeedIn struct {
	DownMbps float64 `json:"down_mbps"`
	Server   string  `json:"server"`
	Loaded   string  `json:"loaded"` // ping output, "" for none
	Error    string  `json:"error"`
}

// WifiReport is one made-up situation and the report the Go command writes.
type WifiReport struct {
	Connected bool         `json:"connected"`
	Before    string       `json:"before"`
	After     string       `json:"after"`
	Router    string       `json:"router"`
	Internet  string       `json:"internet"`
	Scan      string       `json:"scan"`
	Devices   int          `json:"devices"`
	PowerSave bool         `json:"power_save"`
	Speed     *WifiSpeedIn `json:"speed"`
	Raw       Raw          `json:"raw,omitempty"`
	JSON      string       `json:"json"`
	Text      string       `json:"text"`
}

// WifiFixture is testdata/parity/cli-wifi.json.
type WifiFixture struct {
	Links    []WifiLink   `json:"links"`
	Scans    []WifiScan   `json:"scans"`
	Pings    []WifiPing   `json:"pings"`
	Channels [][3]any     `json:"channels"` // mhz, channel, band
	Overlaps [][5]any     `json:"overlaps"` // band, a, width, b, overlaps
	Sorts    []WifiSort   `json:"sorts"`
	Reports  []WifiReport `json:"reports"`
}

var wifiSSIDs = []string{"Home", "Cafe Free", "", "Nachbar 5G", "TP-Link_ABCD", "Vodafone-Hotspot", "x:y\\z", "Ünïcödé net", "a<b>&c", "Home\xff", "   spaced  ", "Long name of a network ok"}

func wifiFreq(r *rand.Rand) int {
	all := []int{2412, 2417, 2437, 2442, 2462, 2472, 2484, 2400, 5180, 5200, 5240, 5260, 5320, 5500, 5580, 5660, 5745, 5785, 5825, 5885, 5900, 5955, 6115, 7115, 7200}
	return all[r.Intn(len(all))]
}

func wifiLinkText(r *rand.Rand, ssid string, freq int, sig int, packets, retries uint64) string {
	var b strings.Builder
	if r.Intn(25) == 0 {
		return "Not connected.\n"
	}
	fmt.Fprintf(&b, "Connected to 02:00:5e:10:00:%02x (on wlan0)\n", r.Intn(256))
	if r.Intn(12) != 0 {
		fmt.Fprintf(&b, "\tSSID: %s\n", ssid)
	}
	if r.Intn(15) != 0 {
		f := fmt.Sprint(freq)
		if r.Intn(4) == 0 {
			f += ".0"
		}
		fmt.Fprintf(&b, "\tfreq: %s\n", f)
	}
	fmt.Fprintf(&b, "\tRX: %d bytes (%d packets)\n\tTX: %d bytes (%d packets)\n", r.Intn(1e9), r.Intn(1e6), r.Intn(1e9), r.Intn(1e6))
	if r.Intn(12) != 0 {
		fmt.Fprintf(&b, "\tsignal: %d dBm\n", sig)
	}
	widths := []string{"", " 40MHz", " 80MHz", " 160MHz", " VHT-MCS 9 80MHz short GI VHT-NSS 2", " HE-MCS 11 HE-NSS 2 HE-GI 0 HE-DCM 0 160MHz"}
	rates := []string{"6.0", "72.2", "866.7", "1200.9", "144", "0"}
	fmt.Fprintf(&b, "\trx bitrate: %s MBit/s%s\n", rates[r.Intn(len(rates))], widths[r.Intn(len(widths))])
	if r.Intn(10) != 0 {
		fmt.Fprintf(&b, "\ttx bitrate: %s MBit/s%s\n", rates[r.Intn(len(rates))], widths[r.Intn(len(widths))])
	}
	b.WriteString("\n\tbss flags: short-slot-time\n\tdtim period: 1\n\tbeacon int: 100\n")
	// the station dump, appended as Run appends it
	fmt.Fprintf(&b, "Station 02:00:5e:10:00:01 (on wlan0)\n\tinactive time: 12 ms\n\ttx packets: %d\n\ttx retries: %d\n\ttx failed: %d\n", packets, retries, r.Intn(50))
	if r.Intn(3) == 0 {
		fmt.Fprintf(&b, "\texpected throughput: %d.%dMbps\n", r.Intn(900), r.Intn(1000))
	}
	return b.String()
}

func wifiPingText(r *rand.Rand, target string) string {
	return wifiPing(r, target, false)
}

func wifiPing(r *rand.Rand, target string, good bool) string {
	switch r.Intn(9) {
	case 2, 3, 4, 5, 6, 7, 8:
		if good {
			return wifiPingRun(r, target, 30, []float64{1.2, 2.5, 3.5, 9.0, 20.0, 35.0}[r.Intn(6)])
		}
	case 0:
		return ""
	case 1:
		return fmt.Sprintf("PING %s (%s) 56(84) bytes of data.\n\n--- %s ping statistics ---\n30 packets transmitted, 0 received, 100%% packet loss, time 7254ms\n\n", target, target, target)
	}
	return wifiPingRun(r, target, 1+r.Intn(30), []float64{1.2, 3.5, 12.0, 18.4, 45.0, 70.3, 120.9}[r.Intn(7)])
}

func wifiPingRun(r *rand.Rand, target string, n int, base float64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PING %s (%s) 56(84) bytes of data.\n", target, target)
	var sum, max float64
	for i := 0; i < n; i++ {
		t := base + r.Float64()*base*float64(r.Intn(3))
		if r.Intn(10) == 0 {
			t += 100 * r.Float64()
		}
		t = float64(int(t*100)) / 100
		sum += t
		if t > max {
			max = t
		}
		fmt.Fprintf(&b, "64 bytes from %s: icmp_seq=%d ttl=64 time=%.3g ms\n", target, i+1, t)
	}
	lost := 30 - n
	fmt.Fprintf(&b, "\n--- %s ping statistics ---\n30 packets transmitted, %d received, %d%% packet loss, time 7251ms\n", target, n, lost*100/30)
	fmt.Fprintf(&b, "rtt min/avg/max/mdev = 0.900/%.3f/%.3f/%.3f ms\n", sum/float64(n), max, base/3)
	return b.String()
}

func wifiScanText(r *rand.Rand, own string, ownFreq int) string {
	var b strings.Builder
	n := r.Intn(25)
	mine := fmt.Sprintf("02\\:00\\:5E\\:10\\:00\\:%02X", r.Intn(256))
	fmt.Fprintf(&b, "*:%s:%s:%d MHz:%d\n", strings.ReplaceAll(own, ":", "\\:"), mine, ownFreq, 40+r.Intn(60))
	for i := 0; i < n; i++ {
		ssid := wifiSSIDs[r.Intn(len(wifiSSIDs))]
		if r.Intn(6) == 0 {
			ssid = own
		}
		bssid := fmt.Sprintf("%02X\\:%02X\\:5E\\:10\\:00\\:%02X", r.Intn(256), r.Intn(256), r.Intn(256))
		if r.Intn(8) == 0 { // a second network of our own router's radio
			bssid = "06" + mine[2:]
		}
		freq := wifiFreq(r)
		if r.Intn(3) == 0 {
			freq = ownFreq
		}
		fmt.Fprintf(&b, " :%s:%s:%d MHz:%d\n", strings.ReplaceAll(ssid, ":", "\\:"), bssid, freq, r.Intn(101))
	}
	if r.Intn(10) == 0 {
		b.WriteString("garbage line\n::::\n")
	}
	return b.String()
}

// AllWifi builds the fixture from the Go code's answers.
func AllWifi() WifiFixture {
	r := rand.New(rand.NewSource(20261110))
	var f WifiFixture
	link := func(in string) WifiLink {
		l, ok := wifihealth.ParseLink(in)
		c := WifiLink{In: in, OK: ok, Out: wifiJSON(wifiLinkAll{l, l.TxPackets, l.TxRetries, l.TxFailed})}
		raw(&c.Raw, "in", in)
		return c
	}
	scan := func(in, own string) WifiScan {
		var out []wifiNeighbourAll
		for _, n := range wifihealth.ParseScan(in, own) {
			out = append(out, wifiNeighbourAll{n, n.BSSID})
		}
		c := WifiScan{In: in, Own: own, Out: wifiJSON(out)}
		raw(&c.Raw, "in", in)
		raw(&c.Raw, "own", own)
		return c
	}
	for i := 0; i < 200; i++ {
		ssid := wifiSSIDs[r.Intn(len(wifiSSIDs))]
		f.Links = append(f.Links, link(wifiLinkText(r, ssid, wifiFreq(r), -30-r.Intn(70), uint64(r.Intn(1e6)), uint64(r.Intn(1e5)))))
	}
	for _, in := range []string{"", "Not connected.", "Connected to x\n\tfreq: 99999999999999999999999\n\tsignal: -99999999999999999999\n\ttx packets: 99999999999999999999999\n", "Connected to x\n\tfreq: 2412.9.1\n\ttx bitrate: 1..2 MBit/s 40MHz\n\trx bitrate: . MBit/s", "Connected to\n  SSID:\t \n  \n signal: -50", "Connected to\nSSID: a\xffb\xe2\x84\n"} {
		f.Links = append(f.Links, link(in))
	}
	for i := 0; i < 200; i++ {
		own := wifiSSIDs[r.Intn(len(wifiSSIDs))]
		f.Scans = append(f.Scans, scan(wifiScanText(r, own, wifiFreq(r)), own))
	}
	f.Scans = append(f.Scans, scan("*:a\\\\b\\:c:AA\\:BB:2412:x\n :d:aa\\:bb:24120:5\n :e\xff:AA:5180 MHz:+7\n", "a\\b:c"))
	for i := 0; i < 200; i++ {
		t := []string{"192.0.2.1", "1.1.1.1", "198.51.100.7"}[r.Intn(3)]
		in := wifiPingText(r, t)
		f.Pings = append(f.Pings, WifiPing{Target: t, In: in, Out: wifiJSON(wifihealth.ParsePing(t, in))})
	}
	f.Pings = append(f.Pings, WifiPing{Target: "", In: "", Out: wifiJSON(wifihealth.ParsePing("", ""))})
	for mhz := 2380; mhz <= 7200; mhz += 1 {
		if mhz%5 == 0 || mhz == 2484 || mhz%7 == 0 {
			ch, band := wifihealth.Channel(mhz)
			f.Channels = append(f.Channels, [3]any{mhz, ch, band})
		}
	}
	for _, band := range []string{"2.4 GHz", "5 GHz", "6 GHz", ""} {
		for a := 0; a <= 180; a += 1 + r.Intn(7) {
			for _, w := range []int{20, 40, 80, 160} {
				b := a + r.Intn(40) - 20
				f.Overlaps = append(f.Overlaps, [5]any{band, a, w, b, wifihealth.Overlaps(band, a, w, b)})
			}
		}
	}
	for i := 0; i < 300; i++ {
		n := r.Intn(80)
		type kv struct{ k, i int }
		v := make([]kv, n)
		keys := make([]int, n)
		for j := range v {
			v[j] = kv{r.Intn(1 + r.Intn(12)), j}
			if i%3 == 0 {
				v[j].k = n - j // descending runs
			}
			keys[j] = v[j].k
		}
		sort.Slice(v, func(a, b int) bool { return v[a].k > v[b].k })
		order := make([]int, n)
		for j := range v {
			order[j] = v[j].i
		}
		f.Sorts = append(f.Sorts, WifiSort{Keys: keys, Order: order})
	}
	for i := 0; i < 160; i++ {
		f.Reports = append(f.Reports, wifiReport(r))
	}
	return f
}

// WifiJudge runs a situation through the Go code as Run would and prints it as cmd/heimdalld does.
func WifiJudge(c *WifiReport) {
	rep := wifihealth.Report{Time: time.Date(2026, 11, 10, 20, 0, 0, 0, time.UTC), DevicesHere: c.Devices, PowerSave: c.PowerSave}
	if c.Connected {
		rep.Iface = "wlan0"
		before, ok := wifihealth.ParseLink(c.Before)
		if ok {
			rep.Connected = true
			rep.Router = wifihealth.ParsePing("192.0.2.1", c.Router)
			rep.Internet = wifihealth.ParsePing("1.1.1.1", c.Internet)
			if c.Speed != nil {
				s := &wifihealth.Speed{DownMbps: c.Speed.DownMbps, Server: c.Speed.Server, Error: c.Speed.Error}
				if c.Speed.Loaded != "" {
					p := wifihealth.ParsePing("1.1.1.1", c.Speed.Loaded)
					s.Loaded = &p
				}
				rep.Speed = s
			}
			after, ok := wifihealth.ParseLink(c.After)
			if !ok {
				after = before
			}
			rep.Link = after
			if sent := after.TxPackets - before.TxPackets; after.TxPackets >= before.TxPackets && sent >= 300 {
				rep.RetriesPct = wifiRound1(100 * float64(after.TxRetries-before.TxRetries) / float64(sent))
				rep.RetriesSpan = "check"
			} else if after.TxPackets >= 1000 {
				rep.RetriesPct = wifiRound1(100 * float64(after.TxRetries) / float64(after.TxPackets))
				rep.RetriesSpan = "connection"
			}
			rep.Neighbourhood(wifihealth.ParseScan(c.Scan, after.SSID))
		}
	}
	rep.Judge()
	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(rep)
	c.JSON = b.String()
	var t strings.Builder
	fmt.Fprintln(&t, rep.Summary)
	if rep.Connected {
		fmt.Fprintf(&t, "%s, %s channel %d (%d MHz), %d dBm, %.0f/%.0f Mbps\n", rep.Link.SSID, rep.Link.Band, rep.Link.Channel, rep.Link.Width, rep.Link.SignalDBm, rep.Link.RxMbps, rep.Link.TxMbps)
	}
	mark := map[string]string{"good": "ok  ", "info": "    ", "warn": "WARN", "bad": "BAD "}
	for _, x := range rep.Findings {
		fmt.Fprintf(&t, "  %s %s", mark[x.Status], x.Title)
		if x.Detail != "" {
			fmt.Fprintf(&t, ": %s", x.Detail)
		}
		fmt.Fprintln(&t)
	}
	c.Text = t.String()
	raw(&c.Raw, "before", c.Before)
	raw(&c.Raw, "after", c.After)
	raw(&c.Raw, "scan", c.Scan)
	raw(&c.Raw, "text", c.Text)
}

func wifiRound1(f float64) float64 {
	v, _ := strconv.ParseFloat(fmt.Sprintf("%.1f", f), 64)
	return v
}

func wifiReport(r *rand.Rand) WifiReport {
	ssid := wifiSSIDs[r.Intn(len(wifiSSIDs))]
	freq := wifiFreq(r)
	good := r.Intn(2) == 0 // a healthy situation, with a few things wrong now and then
	sig := -35 - r.Intn(55)
	p0 := uint64(r.Intn(5000))
	r0 := uint64(r.Intn(int(p0) + 1))
	more, retried := uint64(r.Intn(3000)), uint64(r.Intn(int(p0)+3000))
	if good {
		sig = -35 - r.Intn(35)
		r0 = p0 / uint64(20+r.Intn(200))
		retried = r0 + more/uint64(5+r.Intn(100))
	}
	c := WifiReport{Connected: r.Intn(15) != 0, Devices: r.Intn(14) - 1, PowerSave: r.Intn(3) == 0}
	c.Before = wifiLinkText(r, ssid, freq, sig, p0, r0)
	c.After = wifiLinkText(r, ssid, freq, sig+r.Intn(5)-2, p0+more, retried)
	c.Router = wifiPing(r, "192.0.2.1", good)
	c.Internet = wifiPing(r, "1.1.1.1", good)
	c.Scan = wifiScanText(r, ssid, freq)
	if good && r.Intn(2) == 0 {
		c.Scan = wifiScanText(rand.New(rand.NewSource(int64(r.Intn(1000)))), ssid, 5955+20*r.Intn(10))
	}
	if r.Intn(3) == 0 {
		s := &WifiSpeedIn{DownMbps: float64(int(r.Float64()*9000)) / 10, Server: "mirror.example.org"}
		switch r.Intn(4) {
		case 0:
			s = &WifiSpeedIn{Error: "the download servers could not be reached (no such host)"}
		case 1:
			s.Loaded = wifiPingText(r, "1.1.1.1")
		}
		c.Speed = s
	}
	WifiJudge(&c)
	return c
}
