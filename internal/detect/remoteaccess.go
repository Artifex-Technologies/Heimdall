package detect

import (
	"strings"
	"sync"
	"time"
)

// RemoteAccessDetector judges the remote-access signals (rasource's "remote_access" events, and "new_connection" events the
// connection watcher tagged with ra_provider):
//
//	critical  a remote-access, tunnel or remote-desktop tool the owner has not approved is installed, has its interface, or holds
//	          a connection; a command-and-control implant always (it can never be approved)
//	warning   a new tunnel interface that no catalog tool explains (a VPN the owner set up looks the same: approve by name later)
//	info      an approved tool doing what it does
//
// The kernel's side (HEI-12): a shell reading its commands from a network socket is critical and can never be approved (a
// reverse shell); a program outside the usual ones reading raw packets is a warning (a backdoor can wait for a secret
// packet with no open port); a kernel module that makes the kernel serve the network is critical unless approved.
//
// One alert per provider and signal (and process) per Cooldown, so a tool talking to many servers is one alert, not dozens.
type RemoteAccessDetector struct {
	Approved func(id string) bool
	Cooldown time.Duration
	mu       sync.Mutex
	last     map[string]time.Time
}

func NewRemoteAccessDetector(approved func(string) bool) *RemoteAccessDetector {
	return &RemoteAccessDetector{Approved: approved, Cooldown: time.Hour}
}

func (d *RemoteAccessDetector) ID() string { return "remote-access" }

func (d *RemoteAccessDetector) Inspect(e Event) []Finding {
	provider, kind, signal := e.Fields["provider"], e.Fields["ra_kind"], e.Fields["signal"]
	switch e.Kind {
	case "remote_access":
	case "new_connection":
		provider, kind, signal = e.Fields["ra_provider"], e.Fields["ra_kind"], "connection:"+e.Fields["ra_signal"]
		if provider == "" {
			return nil
		}
	default:
		return nil
	}
	key := provider + "|" + signal + "|" + e.Fields["iface"] + "|" + e.Fields["pid"]
	d.mu.Lock()
	if d.last == nil {
		d.last = map[string]time.Time{}
	}
	if t, ok := d.last[key]; ok && time.Since(t) < d.Cooldown {
		d.mu.Unlock()
		return nil
	}
	d.last[key] = time.Now()
	d.mu.Unlock()
	switch signal {
	case "socket-shell":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical, Event: e, Summary: e.Text +
			": a shell that reads its commands from a network connection is a reverse shell, someone typing on this computer from elsewhere"}}
	case "raw-listener":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Event: e, Summary: e.Text +
			": a program reading raw packets can wait for a secret packet with no open port, as backdoors such as BPFDoor do; a packet capture or network tool you started does this too"}}
	}
	if provider == "" {
		return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Summary: e.Text + ": a tunnel no known tool explains", Event: e}}
	}
	name := e.Fields["provider_name"]
	if name == "" {
		name = provider
	}
	if kind != "c2" && d.Approved != nil && d.Approved(provider) {
		return []Finding{{DetectorID: d.ID(), Severity: SeverityInfo, Summary: e.Text + " (" + name + ", approved by the owner)", Event: e}}
	}
	if kind == "c2" {
		return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical, Summary: e.Text + ": " + name + " is a command-and-control implant", Event: e}}
	}
	if kind == "kernel" {
		return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical, Summary: e.Text + ": the kernel itself now serves the network this way; if you did not set it up, find what loaded it (sudo heimdalld remote approve " + provider + " if you did)", Event: e}}
	}
	if strings.HasSuffix(signal, "gomod-dep") {
		return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Summary: e.Text + ": the program contains code of " + name + " (it may open its own " + kind + ")", Event: e}}
	}
	return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical, Summary: e.Text + ": " + name + " is a remote-access tool the owner has not approved", Event: e}}
}
