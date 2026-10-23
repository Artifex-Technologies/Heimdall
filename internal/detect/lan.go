package detect

import "fmt"

// LANDetector reads the local-network watches: the router of an untrusted Wi-Fi network changing or being imitated (critical:
// ARP spoofing puts someone between this computer and the internet), and a program starting to listen for connections from the
// network (warning: the firewall blocks it unless a rule allows it, but it should be known).
type LANDetector struct{}

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
	case "new_listener":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Event: e, Summary: fmt.Sprintf(
			"a program started listening for connections from the network on %s/%s. The firewall blocks it unless a rule allows it; to see which program: sudo ss -tulpn | grep ':%s '",
			f["proto"], f["port"], f["port"])}}
	}
	return nil
}
