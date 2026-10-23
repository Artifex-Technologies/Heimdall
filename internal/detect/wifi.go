package detect

import "fmt"

// WifiDetector turns heimdall-wifi-check's verdicts ("wifi_check" events) into findings: an unsafe network is critical, one to be
// careful on is a warning, a safe one is recorded as info.
type WifiDetector struct{}

func NewWifiDetector() *WifiDetector { return &WifiDetector{} }

func (d *WifiDetector) ID() string { return "wifi-safety" }

func (d *WifiDetector) Inspect(e Event) []Finding {
	if e.Kind != "wifi_check" {
		return nil
	}
	f := e.Fields
	switch f["verdict"] {
	case "unsafe":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical, Event: e, Summary: fmt.Sprintf(
			"Wi-Fi %q is not safe: %s. Disconnect, or use a VPN for everything (Proton VPN) and do not sign in to anything without it", f["ssid"], f["reasons"])}}
	case "caution":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Event: e, Summary: fmt.Sprintf(
			"Wi-Fi %q needs care: %s. A VPN is a good idea here", f["ssid"], f["reasons"])}}
	case "safe":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityInfo, Event: e, Summary: fmt.Sprintf("Wi-Fi %q checked: nothing wrong found", f["ssid"])}}
	}
	return nil
}
