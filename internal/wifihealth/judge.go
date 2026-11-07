package wifihealth

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Finding is one check's result, in plain words.
type Finding struct {
	Check  string `json:"check"`  // signal, band, channel, retries, router, internet, devices, speed, bufferbloat
	Status string `json:"status"` // good, info, warn, bad
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// Speed is the optional speed test.
type Speed struct {
	DownMbps float64 `json:"down_mbps"`
	Server   string  `json:"server,omitempty"` // the mirror it downloaded from
	Loaded   *Ping   `json:"loaded,omitempty"` // the internet ping while downloading
	Error    string  `json:"error,omitempty"`
}

// Report is everything one check measured and what it means.
type Report struct {
	Time        time.Time   `json:"time"`
	Iface       string      `json:"iface"`
	Connected   bool        `json:"connected"`
	Link        Link        `json:"link"`
	RetriesPct  float64     `json:"retries_pct"`  // share of frames sent again, during the check (or since connecting)
	RetriesSpan string      `json:"retries_span"` // "check" or "connection"
	Neighbours  []Neighbour `json:"neighbours"`   // networks sharing our channel (not our own)
	Heard       int         `json:"heard"`        // how many of them are loud enough to take airtime
	Better      []int       `json:"better_channels,omitempty"`
	Own5GHz     bool        `json:"own_5ghz"`              // our network also on 5 GHz (we are on 2.4)
	FromRouter  []string    `json:"from_router,omitempty"` // other networks our own router sends (a provider's hotspot)
	Router      Ping        `json:"router"`
	Internet    Ping        `json:"internet"`
	DevicesHere int         `json:"devices_here"` // -1: unknown (no device list)
	PowerSave   bool        `json:"power_save"`   // the adapter naps between beacons: some answers come late
	Speed       *Speed      `json:"speed,omitempty"`
	Findings    []Finding   `json:"findings"`
	Verdict     string      `json:"verdict"` // good, warn, bad
	Summary     string      `json:"summary"`
}

// heardAt is NetworkManager's signal (0-100) above which a neighbour takes airtime from us (about -80 dBm).
const heardAt = 40

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func rank(s string) int {
	return map[string]int{"good": 0, "info": 0, "warn": 1, "bad": 2}[s]
}

// candidates are the channels worth suggesting: the three that do not overlap on 2.4 GHz, and the first channel of each
// 80 MHz block on 5 GHz (36 and 149 need no radar check, so routers switch to them at once).
func candidates(band string) []int {
	switch band {
	case "2.4 GHz":
		return []int{1, 6, 11}
	case "5 GHz":
		return []int{36, 149, 52, 100, 116, 132}
	}
	return nil
}

// Neighbourhood works out the networks sharing our channel and quieter channels to suggest.
func (r *Report) Neighbourhood(all []Neighbour) {
	l := r.Link
	r.Neighbours = nil
	r.FromRouter = nil
	r.Heard = 0
	for _, n := range all {
		if n.SameRouter {
			if n.SSID != "" && !contains(r.FromRouter, n.SSID) {
				r.FromRouter = append(r.FromRouter, n.SSID)
			}
			continue
		}
		if n.Own && n.Band == "5 GHz" && l.Band == "2.4 GHz" {
			r.Own5GHz = true
		}
		if n.Own || n.Band != l.Band || !Overlaps(l.Band, l.Channel, l.Width, n.Channel) {
			continue
		}
		r.Neighbours = append(r.Neighbours, n)
		if n.Signal >= heardAt {
			r.Heard++
		}
	}
	sort.Slice(r.Neighbours, func(i, j int) bool { return r.Neighbours[i].Signal > r.Neighbours[j].Signal })
	// how loud each candidate channel is (each heard neighbour weighs by its signal)
	load := func(ch int) int {
		sum := 0
		for _, n := range all {
			if !n.Own && !n.SameRouter && n.Band == l.Band && n.Signal >= heardAt && Overlaps(l.Band, ch, l.Width, n.Channel) {
				sum += n.Signal
			}
		}
		return sum
	}
	here := load(l.Channel)
	type c struct{ ch, load int }
	var cs []c
	for _, ch := range candidates(l.Band) {
		if Overlaps(l.Band, l.Channel, l.Width, ch) {
			continue
		}
		if ld := load(ch); ld+60 < here { // clearly quieter: at least one loud network fewer
			cs = append(cs, c{ch, ld})
		}
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].load < cs[j].load })
	r.Better = nil
	for i := 0; i < len(cs) && i < 2; i++ {
		r.Better = append(r.Better, cs[i].ch)
	}
}

// Judge turns the measurements into findings, a verdict and a one-line summary.
func (r *Report) Judge() {
	r.Findings = nil
	add := func(check, status, title, detail string) {
		r.Findings = append(r.Findings, Finding{check, status, title, detail})
	}
	if !r.Connected {
		add("signal", "bad", "Not connected to Wi-Fi", "Connect to a network first.")
		r.Verdict, r.Summary = "bad", "Not connected to Wi-Fi"
		return
	}
	l := r.Link

	// signal
	sig := l.SignalDBm
	where := fmt.Sprintf("%d dBm on %s channel %d", sig, l.Band, l.Channel)
	switch {
	case sig >= -60:
		add("signal", "good", "Strong signal", where+".")
	case sig >= -67:
		add("signal", "good", "Good signal", where+". Enough for streaming and video calls.")
	case sig >= -75:
		add("signal", "warn", "Fair signal", where+". Speed drops and calls may stutter. Closer to the router, or fewer walls and floors between, helps.")
	default:
		add("signal", "bad", "Weak signal", where+". This alone makes Wi-Fi slow and unreliable. Move closer to the router, or add a mesh point or extender between.")
	}
	if l.Band == "2.4 GHz" && r.Own5GHz {
		add("band", "warn", "On 2.4 GHz", "Your network also offers 5 GHz, which is much faster and less crowded at this distance. Forgetting and rejoining, or giving 5 GHz its own network name on the router, moves this computer there.")
	}

	// the channel
	busy := map[string][2]int{"2.4 GHz": {3, 6}, "5 GHz": {2, 4}, "6 GHz": {2, 4}}[l.Band]
	names := func() string {
		var s []string
		for i, n := range r.Neighbours {
			if i == 4 || n.Signal < heardAt {
				break
			}
			name := n.SSID
			if name == "" {
				name = "a hidden network"
			}
			s = append(s, fmt.Sprintf("%s (%d%%)", name, n.Signal))
		}
		return strings.Join(s, ", ")
	}
	better := ""
	if len(r.Better) > 0 {
		var s []string
		for _, ch := range r.Better {
			s = append(s, fmt.Sprint(ch))
		}
		better = " Channel " + strings.Join(s, " or ") + " is quieter here; the channel is set on the router."
	}
	switch {
	case busy[1] > 0 && r.Heard >= busy[1]:
		add("channel", "bad", "Crowded channel", fmt.Sprintf("%d other networks share channel %d loudly enough to take turns with yours: %s.%s", r.Heard, l.Channel, names(), better))
	case busy[0] > 0 && r.Heard >= busy[0]:
		add("channel", "warn", "Busy channel", fmt.Sprintf("%d other networks share channel %d: %s.%s", r.Heard, l.Channel, names(), better))
	case r.Heard > 0:
		add("channel", "good", "Channel mostly clear", fmt.Sprintf("%d other network on channel %d: %s.", r.Heard, l.Channel, names()))
	default:
		add("channel", "good", "Channel clear", fmt.Sprintf("No other network is heard on channel %d.", l.Channel))
	}

	if len(r.FromRouter) > 0 {
		last := &r.Findings[len(r.Findings)-1]
		last.Detail += fmt.Sprintf(" %s also comes from your own router (a second network on the same radio); it is not counted.", strings.Join(r.FromRouter, " and "))
	}

	// resending
	if r.RetriesSpan != "" {
		span := "during the check"
		if r.RetriesSpan == "connection" {
			span = "since connecting"
		}
		switch {
		case r.RetriesPct >= 25:
			add("retries", "bad", "Much resending", fmt.Sprintf("%.0f%% of what this computer sent had to be sent again %s: interference, a crowded channel or a weak signal.", r.RetriesPct, span))
		case r.RetriesPct >= 10:
			add("retries", "warn", "Some resending", fmt.Sprintf("%.0f%% sent again %s. A little is normal; this much slows things down.", r.RetriesPct, span))
		default:
			add("retries", "good", "Little resending", fmt.Sprintf("%.1f%% sent again %s.", r.RetriesPct, span))
		}
	}

	// the link to the router, then past it
	rt := r.Router
	routerBad := false
	switch {
	case !rt.OK && r.Internet.OK:
		add("router", "info", "The router does not answer ping", "Some routers ignore it; the internet answers, so the link works.")
	case !rt.OK:
		add("router", "bad", "No answer from the router", "The router did not answer at all. Restarting it, or rejoining the network, is the first thing to try.")
		routerBad = true
	case rt.LossPct >= 5 || rt.MedianMs >= 40:
		add("router", "bad", "Poor link to the router", fmt.Sprintf("%.0f%% lost, typically %.0f ms (good is a few ms with nothing lost). The problem is between this computer and the router.", rt.LossPct, rt.MedianMs))
		routerBad = true
	case rt.LossPct >= 2 || rt.MedianMs >= 15:
		add("router", "warn", "Slow link to the router", fmt.Sprintf("%.0f%% lost, typically %.0f ms (good is a few ms).", rt.LossPct, rt.MedianMs))
		routerBad = true
	default:
		add("router", "good", "Good link to the router", fmt.Sprintf("Typically %.1f ms, nothing lost.", rt.MedianMs))
	}
	if rt.OK && r.PowerSave && rt.MaxMs > 30 && rt.MaxMs > 5*rt.MedianMs {
		add("powersave", "info", "Power saving makes some answers late", fmt.Sprintf("The Wi-Fi adapter naps between the router's beacons, so a few answers took up to %.0f ms. Downloads do not suffer; online games may feel it as a hitch now and then.", rt.MaxMs))
	}
	in := r.Internet
	beyond := false
	switch {
	case !in.OK:
		add("internet", "bad", "No answer from the internet", "The internet did not answer. If the router answers, the problem is the router's own connection or the internet provider.")
		beyond = rt.OK
	case in.LossPct >= 5 || in.MedianMs >= 100:
		add("internet", "bad", "Poor internet connection", fmt.Sprintf("%.0f%% lost, typically %.0f ms.", in.LossPct, in.MedianMs))
		beyond = !routerBad
	case in.LossPct >= 2 || in.MedianMs >= 60:
		add("internet", "warn", "Slow answers from the internet", fmt.Sprintf("%.0f%% lost, typically %.0f ms.", in.LossPct, in.MedianMs))
		beyond = !routerBad
	default:
		add("internet", "good", "Internet answers quickly", fmt.Sprintf("Typically %.0f ms, nothing lost.", in.MedianMs))
	}

	// other devices
	signalOK := sig >= -67
	quiet := r.Heard < busy[0] && r.RetriesPct < 10
	busyNet := routerBad && signalOK && quiet && rt.OK
	switch {
	case busyNet && r.DevicesHere > 0:
		add("devices", "warn", "Busy network", fmt.Sprintf("The signal is good and the channel quiet, yet the router answers slowly: other devices are probably using the Wi-Fi heavily (a download, a game update, video). %d devices are on now (Wi-Fi & Network > Devices).", r.DevicesHere))
	case busyNet:
		add("devices", "warn", "Busy network", "The signal is good and the channel quiet, yet the router answers slowly: other devices are probably using the Wi-Fi heavily (a download, a game update, video).")
	case r.DevicesHere > 0:
		add("devices", "info", fmt.Sprintf("%d devices on now", r.DevicesHere), "How many is not a problem by itself; what they are doing is.")
	}

	// speed
	if s := r.Speed; s != nil {
		switch {
		case s.Error != "":
			add("speed", "info", "Speed test did not run", s.Error)
		case s.DownMbps < 10:
			add("speed", "warn", fmt.Sprintf("%.0f Mbps download", s.DownMbps), "Slow: video in HD needs about 5-10 Mbps per stream. Measured from "+s.Server+"; a busy server can make it look slower than the line is.")
		default:
			add("speed", "good", fmt.Sprintf("%.0f Mbps download", s.DownMbps), "Measured from "+s.Server+" (the update server this computer uses); a busy server can make it look slower than the line is.")
		}
		if s.Loaded != nil && s.Loaded.OK && in.OK {
			rise := s.Loaded.MedianMs - in.MedianMs
			switch {
			case rise >= 100:
				add("bufferbloat", "warn", "Slow answers while the line is full", fmt.Sprintf("Answers took %.0f ms longer during the download. When one device fills the connection, everything else waits: games lag and calls stutter. Routers with \"smart queue\" (SQM) settings fix this.", rise))
			case rise >= 30:
				add("bufferbloat", "info", "Some delay while the line is full", fmt.Sprintf("Answers took %.0f ms longer during the download.", rise))
			}
		}
	}

	// verdict and summary: the worst finding, the likely cause first
	r.Verdict = "good"
	for _, f := range r.Findings {
		if rank(f.Status) > rank(r.Verdict) {
			r.Verdict = f.Status
		}
	}
	order := []string{"signal", "channel", "retries", "devices", "router", "band", "internet", "bufferbloat", "speed"}
	r.Summary = "Your Wi-Fi looks healthy"
	for _, want := range []string{"bad", "warn"} {
		for _, c := range order {
			for _, f := range r.Findings {
				if f.Check == c && f.Status == want {
					r.Summary = summaryFor(f, beyond)
					return
				}
			}
		}
	}
}

func summaryFor(f Finding, beyond bool) string {
	switch f.Check {
	case "signal":
		return "A weak signal is the likely cause"
	case "channel", "retries":
		return "A crowded channel is the likely cause"
	case "devices":
		return "Other devices using the network are the likely cause"
	case "router":
		return "The link to the router is the problem"
	case "internet":
		if beyond {
			return "Your Wi-Fi is fine; the problem is past the router (the internet provider or the router's connection)"
		}
		return "The internet connection is slow"
	case "band":
		return "Faster on 5 GHz"
	}
	return f.Title
}
