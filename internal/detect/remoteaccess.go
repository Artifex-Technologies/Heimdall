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
// One alert per provider and signal per Cooldown, so a tool talking to many servers is one alert, not dozens.
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
	key := provider + "|" + signal + "|" + e.Fields["iface"]
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
	if strings.HasSuffix(signal, "gomod-dep") {
		return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Summary: e.Text + ": the program contains code of " + name + " (it may open its own " + kind + ")", Event: e}}
	}
	return []Finding{{DetectorID: d.ID(), Severity: SeverityCritical, Summary: e.Text + ": " + name + " is a remote-access tool the owner has not approved", Event: e}}
}
