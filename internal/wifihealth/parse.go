// Package wifihealth answers "why is the Wi-Fi slow?": a weak signal, a crowded channel, a busy network (other devices
// using it), or a problem past the router (the internet provider). It measures for about ten seconds and reads what the
// computer already knows; nothing is changed. heimdalld wifi-health prints the report; Settings shows it.
//
// Sources: iw (the link: signal, rates, retries), NetworkManager's scan list (neighbouring networks and their channels), ping
// (to the router and to the internet), Heimdall's device list (how many devices are on), and, only when asked, a speed test
// against Cloudflare's public speed test endpoints.
package wifihealth

import (
	"bufio"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Link is the computer's own connection, from `iw dev IF link` and `iw dev IF station dump`.
type Link struct {
	SSID        string  `json:"ssid"`
	FreqMHz     int     `json:"freq_mhz"`
	Channel     int     `json:"channel"`
	Band        string  `json:"band"`  // "2.4 GHz", "5 GHz", "6 GHz"
	Width       int     `json:"width"` // MHz
	SignalDBm   int     `json:"signal_dbm"`
	RxMbps      float64 `json:"rx_mbps"`
	TxMbps      float64 `json:"tx_mbps"`
	ExpectedMbp float64 `json:"expected_mbps,omitempty"` // the driver's estimate of real throughput
	TxPackets   uint64  `json:"-"`
	TxRetries   uint64  `json:"-"`
	TxFailed    uint64  `json:"-"`
}

var (
	reFreq     = regexp.MustCompile(`(?m)^\s*freq:\s*([0-9.]+)`)
	reSignal   = regexp.MustCompile(`(?m)^\s*signal:\s*(-?\d+)`)
	reRx       = regexp.MustCompile(`(?m)^\s*rx bitrate:\s*([0-9.]+) MBit/s(.*)$`)
	reTx       = regexp.MustCompile(`(?m)^\s*tx bitrate:\s*([0-9.]+) MBit/s(.*)$`)
	reSSID     = regexp.MustCompile(`(?m)^\s*SSID:\s*(.*)$`)
	reWidth    = regexp.MustCompile(`(\d+)MHz`)
	reCounter  = regexp.MustCompile(`(?m)^\s*(tx packets|tx retries|tx failed):\s*(\d+)`)
	reExpected = regexp.MustCompile(`(?m)^\s*expected throughput:\s*([0-9.]+)Mbps`)
)

// ParseLink reads `iw dev IF link` (and, appended, `iw dev IF station dump`). ok is false when not connected.
func ParseLink(text string) (l Link, ok bool) {
	if strings.Contains(text, "Not connected") || !strings.Contains(text, "Connected to") {
		return l, false
	}
	if m := reSSID.FindStringSubmatch(text); m != nil {
		l.SSID = strings.TrimSpace(m[1])
	}
	if m := reFreq.FindStringSubmatch(text); m != nil {
		f, _ := strconv.ParseFloat(m[1], 64)
		l.FreqMHz = int(f)
		l.Channel, l.Band = Channel(l.FreqMHz)
	}
	if m := reSignal.FindStringSubmatch(text); m != nil {
		l.SignalDBm, _ = strconv.Atoi(m[1])
	}
	if m := reRx.FindStringSubmatch(text); m != nil {
		l.RxMbps, _ = strconv.ParseFloat(m[1], 64)
	}
	if m := reTx.FindStringSubmatch(text); m != nil {
		l.TxMbps, _ = strconv.ParseFloat(m[1], 64)
		if w := reWidth.FindStringSubmatch(m[2]); w != nil {
			l.Width, _ = strconv.Atoi(w[1])
		}
	}
	if l.Width == 0 {
		l.Width = 20
	}
	if m := reExpected.FindStringSubmatch(text); m != nil {
		l.ExpectedMbp, _ = strconv.ParseFloat(m[1], 64)
	}
	for _, m := range reCounter.FindAllStringSubmatch(text, -1) {
		v, _ := strconv.ParseUint(m[2], 10, 64)
		switch m[1] {
		case "tx packets":
			l.TxPackets = v
		case "tx retries":
			l.TxRetries = v
		case "tx failed":
			l.TxFailed = v
		}
	}
	return l, true
}

// Channel turns a frequency into its channel number and band.
func Channel(mhz int) (int, string) {
	switch {
	case mhz == 2484:
		return 14, "2.4 GHz"
	case mhz >= 2412 && mhz <= 2472:
		return (mhz - 2407) / 5, "2.4 GHz"
	case mhz >= 5160 && mhz <= 5885:
		return (mhz - 5000) / 5, "5 GHz"
	case mhz >= 5955 && mhz <= 7115:
		return (mhz - 5950) / 5, "6 GHz"
	}
	return 0, ""
}

// Neighbour is one network in NetworkManager's scan list.
type Neighbour struct {
	SSID    string `json:"ssid"`
	BSSID   string `json:"-"`
	Channel int    `json:"channel"`
	Band    string `json:"band"`
	Signal  int    `json:"signal"` // 0-100, NetworkManager's scale
	InUse   bool   `json:"in_use,omitempty"`
	Own     bool   `json:"own,omitempty"` // the same network name as ours: our own router's other radios or extenders
	// SameRouter: another network sent by our own router's radio (its hardware address differs from ours only in the first
	// or the last byte), such as an internet provider's public hotspot
	SameRouter bool `json:"same_router,omitempty"`
}

// ParseScan reads `nmcli -t -f IN-USE,SSID,BSSID,FREQ,SIGNAL device wifi list` (':' in values escaped as '\:').
func ParseScan(text, ownSSID string) []Neighbour {
	var out []Neighbour
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := splitNM(sc.Text())
		if len(f) < 5 {
			continue
		}
		mhz, _ := strconv.Atoi(strings.Fields(f[3] + " 0")[0])
		ch, band := Channel(mhz)
		sig, _ := strconv.Atoi(f[4])
		if ch == 0 {
			continue
		}
		n := Neighbour{SSID: f[1], BSSID: f[2], Channel: ch, Band: band, Signal: sig, InUse: f[0] == "*"}
		n.Own = n.SSID != "" && n.SSID == ownSSID
		out = append(out, n)
	}
	var mine string
	for _, n := range out {
		if n.InUse {
			mine = strings.ToLower(n.BSSID)
		}
	}
	for i := range out {
		if !out[i].InUse && !out[i].Own && sameRadio(mine, strings.ToLower(out[i].BSSID)) {
			out[i].SameRouter = true
		}
	}
	return out
}

// sameRadio: two hardware addresses that differ only in the first byte (routers set the "locally administered" bit for extra
// networks) or only in the last.
func sameRadio(a, b string) bool {
	if len(a) != 17 || len(b) != 17 || a == b {
		return false
	}
	return a[3:] == b[3:] || a[:15] == b[:15]
}

func splitNM(line string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range line {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}

// block5 is the 80 MHz block a 5 GHz channel belongs to (36-48, 52-64, ...); networks in one block share airtime when either
// uses the full width.
func block5(ch int) int {
	switch {
	case ch >= 36 && ch <= 64:
		return (ch - 36) / 16
	case ch >= 100 && ch <= 144:
		return 2 + (ch-100)/16
	case ch >= 149 && ch <= 177:
		return 5 + (ch-149)/16
	}
	return -1
}

// Overlaps reports whether a network on channel b shares airtime with ours on channel a, width w.
func Overlaps(band string, a, w, b int) bool {
	switch band {
	case "2.4 GHz":
		d := a - b
		if d < 0 {
			d = -d
		}
		return d < 5 // 20 MHz channels 5 apart do not overlap (1, 6, 11)
	case "5 GHz":
		if a == b {
			return true
		}
		if w >= 40 {
			return block5(a) == block5(b) && block5(a) >= 0
		}
	case "6 GHz":
		return a == b
	}
	return false
}

// Ping is one `ping -q` summary.
type Ping struct {
	Target   string  `json:"target"`
	Sent     int     `json:"sent"`
	LossPct  float64 `json:"loss_pct"`
	AvgMs    float64 `json:"avg_ms"`
	JitterMs float64 `json:"jitter_ms"` // ping's mdev
	MaxMs    float64 `json:"max_ms"`
	MedianMs float64 `json:"median_ms"` // the typical answer: a few late ones (Wi-Fi power saving) do not move it
	OK       bool    `json:"ok"`        // at least one answer
}

var (
	rePingLoss = regexp.MustCompile(`(\d+) packets transmitted, (\d+) (?:packets )?received.*?([0-9.]+)% packet loss`)
	rePingRTT  = regexp.MustCompile(`= ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms`)
	rePingTime = regexp.MustCompile(`time=([0-9.]+) ms`)
)

// ParsePing reads ping's output: each answer's time, and the summary lines.
func ParsePing(target, text string) Ping {
	p := Ping{Target: target}
	var times []float64
	for _, m := range rePingTime.FindAllStringSubmatch(text, -1) {
		t, _ := strconv.ParseFloat(m[1], 64)
		times = append(times, t)
	}
	if len(times) > 0 {
		sort.Float64s(times)
		p.MedianMs = times[len(times)/2]
	}
	if m := rePingLoss.FindStringSubmatch(text); m != nil {
		p.Sent, _ = strconv.Atoi(m[1])
		got, _ := strconv.Atoi(m[2])
		p.LossPct, _ = strconv.ParseFloat(m[3], 64)
		p.OK = got > 0
	}
	if m := rePingRTT.FindStringSubmatch(text); m != nil {
		p.AvgMs, _ = strconv.ParseFloat(m[2], 64)
		p.MaxMs, _ = strconv.ParseFloat(m[3], 64)
		p.JitterMs, _ = strconv.ParseFloat(m[4], 64)
	}
	if p.Sent == 0 {
		p.LossPct = 100
	}
	return p
}

func round1(f float64) float64 {
	v, _ := strconv.ParseFloat(fmt.Sprintf("%.1f", f), 64)
	return v
}
