package detect

import (
	"fmt"
	"strings"
	"time"
)

// inboundPerHour is how many devices reaching for this computer over Wi-Fi are reported in an hour: a sweep of the network
// knocks from many addresses, and a few alerts say it as well as a hundred.
const inboundPerHour = 5

// LANDetector reads the local-network watches: the router of an untrusted Wi-Fi network changing or being imitated (critical:
// ARP spoofing puts someone between this computer and the internet), and a program starting to listen for connections from the
// network (warning: the firewall blocks it unless a rule allows it, but it should be known), a device new to a trusted home
// network (warning: the owner wants to know who joins, internal/lan), and a device on a Wi-Fi network trying to reach this
// computer (warning, on every network but home, trusted ones too: heimdall-wifi-guard's quiet table, which logs it, is not
// loaded at home; once per device an hour, at most inboundPerHour devices an hour, then one summary for the rest of the hour).
// The hours are kept in memory, so they start again when heimdalld restarts.
type LANDetector struct {
	inboundSeen   map[string]time.Time // per device: when it was last reported
	inboundTimes  []time.Time          // the reports of the last hour
	inboundCapped bool                 // the summary for devices past the cap was given, at inboundCapAt
	inboundCapAt  time.Time
}

func NewLANDetector() *LANDetector { return &LANDetector{} }

func (d *LANDetector) ID() string { return "lan-watch" }

func (d *LANDetector) Inspect(e Event) []Finding {
	f := e.Fields
	switch e.Kind {
	case "router_changed":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical, Event: e, Summary: fmt.Sprintf(
			"on %q the router's hardware address changed from %s to %s while you were connected: someone may be impersonating the router (ARP spoofing). Disconnect, or make sure the VPN is on",
			f["ssid"], f["expected_mac"], f["new_mac"])}}
	case "router_impersonated":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical, Event: e, Summary: fmt.Sprintf(
			"on %q, %s answers with the router's hardware address %s: a sign of ARP spoofing. Disconnect, or make sure the VPN is on",
			f["ssid"], f["other_ip"], f["expected_mac"])}}
	case "new_lan_device":
		what := f["name"]
		if what == "" {
			what = "a device"
		}
		var about []string
		if f["vendor"] != "" {
			about = append(about, "made by "+f["vendor"])
		} else if f["private_mac"] == "true" {
			about = append(about, "using a private address (usually a phone, tablet or laptop)")
		}
		about = append(about, "at "+f["ip"])
		return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Event: e, Summary: fmt.Sprintf(
			"a new device joined %q: %s, %s. If you do not know it, look at it in Settings > Wi-Fi & Network > Devices",
			f["ssid"], what, strings.Join(about, ", "))}}
	case "new_listener":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Event: e, Summary: fmt.Sprintf(
			"a program started listening for connections from the network on %s/%s. The firewall blocks it unless a rule allows it; to see which program: sudo ss -tulpn | grep ':%s '",
			f["proto"], f["port"], f["port"])}}
	case "wifi_inbound":
		return d.inbound(e)
	}
	return nil
}

// inbound reports a device that started something aimed at this computer over Wi-Fi (heimdall-wifi-guard's quiet table logs
// it, once per device an hour; ufw decides whether it gets in). The event's time decides the hour, on either side of it (the
// journal can hand lines over out of order), so a replay gives the same alerts. Past inboundPerHour devices in an hour one
// summary says so, so a few made-up senders first cannot hide what comes after them.
func (d *LANDetector) inbound(e Event) []Finding {
	f := e.Fields
	src := f["src"]
	if src == "" {
		return nil
	}
	within := func(t time.Time) bool { a := e.Time.Sub(t); return a > -time.Hour && a < time.Hour }
	if t, ok := d.inboundSeen[src]; ok && within(t) {
		return nil
	}
	if f["router"] == "true" {
		// the network's router (the quiet table logs it once per connection): routers that keep a list of their devices look at
		// each one; worth knowing, not a warning, and not counted against the devices of the hour
		if d.inboundSeen == nil {
			d.inboundSeen = map[string]time.Time{}
		}
		d.inboundSeen[src] = e.Time
		return []Finding{{DetectorID: d.ID(), Severity: SeverityInfo, Event: e, Summary: fmt.Sprintf(
			"the router of this Wi-Fi network (%s) reached for this computer: %s. Routers that keep a list of their devices do this; it is noted once per connection",
			src, inboundWhat(f["proto"], f["dst_port"], f["icmp_type"]))}}
	}
	recent := d.inboundTimes[:0]
	for _, t := range d.inboundTimes {
		if within(t) {
			recent = append(recent, t)
		}
	}
	d.inboundTimes = recent
	if d.inboundSeen == nil {
		d.inboundSeen = map[string]time.Time{}
	}
	if len(d.inboundSeen) > 1024 { // forget devices reported long ago, so a flood of made-up senders cannot grow memory
		for k, t := range d.inboundSeen {
			if !within(t) {
				delete(d.inboundSeen, k)
			}
		}
	}
	d.inboundSeen[src] = e.Time
	who := src
	if f["src_mac"] != "" {
		who += ", hardware address " + f["src_mac"]
	}
	if len(recent) >= inboundPerHour {
		if d.inboundCapped && within(d.inboundCapAt) {
			return nil
		}
		d.inboundCapped, d.inboundCapAt = true, e.Time
		return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Event: e, Summary: fmt.Sprintf(
			"more than %d devices on Wi-Fi tried to reach this computer within an hour (the latest: %s): the others this hour are not reported one by one. Many at once can be one device sweeping the network with made-up addresses; on a network you do not control, disconnect or use a VPN",
			inboundPerHour, who)}}
	}
	d.inboundTimes = append(d.inboundTimes, e.Time)
	what := inboundWhat(f["proto"], f["dst_port"], f["icmp_type"])
	gate := "The firewall drops it unless a rule allows it"
	if what == "a ping" {
		gate = "This computer answers pings (ufw does by default), and nothing else gets in that way"
	}
	return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Event: e, Summary: fmt.Sprintf(
		"a device on Wi-Fi (%s) tried to reach this computer: %s. %s; if you do not know the device, see Settings > Wi-Fi & Network",
		who, what, gate)}}
}

// inboundWhat names what a device asked of this computer, from the protocol, port and ICMP type the kernel logged.
func inboundWhat(proto, port, icmpType string) string {
	switch {
	case (proto == "ICMP" && icmpType == "8") || (proto == "ICMPv6" && icmpType == "128"):
		return "a ping"
	case proto == "UDP" && port == "137":
		return "a NetBIOS question for this computer's name (port 137)"
	case proto == "UDP" && port == "5353":
		return "a multicast DNS question asked of this computer directly (port 5353)"
	case port == "5355":
		return "an LLMNR name question (port 5355)"
	case proto == "UDP" && port == "1900":
		return "a UPnP question (port 1900)"
	case proto == "UDP" && port == "161":
		return "an SNMP question for its details (port 161)"
	case proto == "TCP" && (port == "445" || port == "139"):
		return "a connection to Windows file sharing (port " + port + ")"
	case proto == "TCP" && port == "22":
		return "a connection to SSH (port 22)"
	case port != "":
		return "a connection to port " + port + " (" + proto + ")"
	}
	return "a packet (" + proto + ")"
}
