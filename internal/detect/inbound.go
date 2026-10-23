package detect

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// InboundDetector reads the knocks from outside (fwsource's "firewall_block" and "login_failure" events) and raises one
// alert per address when they add up, naming where it belongs:
//
//	warning   failed logins from one address (LoginThreshold in Window): the address is real (a login needs a completed
//	          connection), so the alert carries the firewall command that would block it, for the owner to run
//	warning   one address probing many ports (ScanPorts different ports in Window): a port scan; the firewall already
//	          stopped it, and the address may be forged, so no block is suggested
//	info      one address blocked many times (BlockThreshold in Window): the firewall did its job; recorded with its origin
//
// An address is alerted on again only after Cooldown. Heimdall never changes the firewall itself.
type InboundDetector struct {
	Window         time.Duration
	Cooldown       time.Duration
	BlockThreshold int
	ScanPorts      int
	LoginThreshold int

	seen   map[string]*knocks
	last   map[string]time.Time
	pruned time.Time
}

type knocks struct {
	blocks []time.Time
	logins []time.Time
	ports  map[string]time.Time
	users  map[string]bool
	origin string
}

func NewInboundDetector() *InboundDetector {
	return &InboundDetector{Window: 10 * time.Minute, Cooldown: time.Hour, BlockThreshold: 20, ScanPorts: 10, LoginThreshold: 5,
		seen: map[string]*knocks{}, last: map[string]time.Time{}}
}

func (d *InboundDetector) ID() string { return "inbound" }

func keep(ts []time.Time, since time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(since) {
		i++
	}
	return ts[i:]
}

func (d *InboundDetector) Inspect(e Event) []Finding {
	if e.Kind != "firewall_block" && e.Kind != "login_failure" {
		return nil
	}
	src := e.Fields["src"]
	if net.ParseIP(src) == nil {
		return nil
	}
	now := e.Time
	since := now.Add(-d.Window)
	if now.Sub(d.pruned) > d.Window { // forget quiet addresses, so a long flood of single knocks cannot grow memory
		for k, v := range d.seen {
			if (len(v.blocks) == 0 || v.blocks[len(v.blocks)-1].Before(since)) && (len(v.logins) == 0 || v.logins[len(v.logins)-1].Before(since)) {
				delete(d.seen, k)
			}
		}
		d.pruned = now
	}
	k := d.seen[src]
	if k == nil {
		if len(d.seen) >= 10000 {
			return nil
		}
		k = &knocks{ports: map[string]time.Time{}, users: map[string]bool{}}
		d.seen[src] = k
	}
	if o := e.Fields["origin"]; o != "" {
		k.origin = o
	}
	origin := k.origin
	if origin == "" {
		origin = "origin unknown"
	}
	k.blocks = keep(k.blocks, since)
	k.logins = keep(k.logins, since)
	for p, t := range k.ports {
		if t.Before(since) {
			delete(k.ports, p)
		}
	}
	if e.Kind == "login_failure" {
		k.logins = append(k.logins, now)
		if len(k.users) < 20 {
			k.users[e.Fields["user"]] = true
		}
	} else {
		k.blocks = append(k.blocks, now)
		if p := e.Fields["dst_port"]; p != "" && len(k.ports) < 1000 {
			k.ports[p] = now
		}
	}
	if t, ok := d.last[src]; ok && now.Sub(t) < d.Cooldown {
		return nil
	}
	f := map[string]string{"src": src, "origin": origin}
	for key, v := range e.Fields {
		if strings.HasPrefix(key, "origin_") {
			f[key] = v
		}
	}
	var sev Severity
	var summary string
	switch {
	case len(k.logins) >= d.LoginThreshold:
		sev = SeverityWarning
		cmd := "sudo ufw insert 1 deny from " + src + " comment 'blocked after a Heimdall alert'"
		f["block_command"], f["spoofable"] = cmd, "0"
		f["attempts"] = fmt.Sprint(len(k.logins))
		summary = fmt.Sprintf("%d failed %s logins in %s from %s (%s), as %s. This address completed a connection, so it is real. To block it: %s",
			len(k.logins), e.Fields["service"], d.Window, src, origin, names(k.users), cmd)
	case len(k.ports) >= d.ScanPorts:
		sev = SeverityWarning
		f["spoofable"], f["ports"] = "1", fmt.Sprint(len(k.ports))
		summary = fmt.Sprintf("port scan: %s (%s) tried %d different ports in %s; the firewall stopped every one. These packets never completed a connection, so the address may be forged: blocking it is not needed and could block an innocent one",
			src, origin, len(k.ports), d.Window)
	case len(k.blocks) >= d.BlockThreshold:
		sev = SeverityInfo
		f["spoofable"], f["attempts"] = "1", fmt.Sprint(len(k.blocks))
		summary = fmt.Sprintf("the firewall blocked %s (%s) %d times in %s (port %s); nothing got through",
			src, origin, len(k.blocks), d.Window, portList(k.ports))
	default:
		return nil
	}
	d.last[src] = now
	return []Finding{{DetectorID: d.ID(), Severity: sev, Summary: summary, Event: Event{Source: e.Source, Time: now, Kind: e.Kind, Text: e.Text, Fields: f}}}
}

func names(m map[string]bool) string {
	var out []string
	for u := range m {
		out = append(out, fmt.Sprintf("%q", u))
	}
	sort.Strings(out)
	if len(out) > 5 {
		out = append(out[:5], "...")
	}
	return strings.Join(out, ", ")
}

func portList(m map[string]time.Time) string {
	var out []string
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	if len(out) > 5 {
		out = append(out[:5], "...")
	}
	return strings.Join(out, ", ")
}
