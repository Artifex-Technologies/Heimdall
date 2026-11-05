package detect

import "fmt"

// ConnectionDetector turns the connection watcher's "new_connection" events
// (which process connected to which remote address, never any contents) into findings:
//
//	critical  a connection to an address on a threat list (Spamhaus DROP, FireHOL Level 1, ...): even while learning
//	critical  an app whose network the owner switched off has a connection (the rule is not in force: the app was
//	          running when it was set and needs a restart, or something is wrong with the rule)
//	critical  one of the ecosystem's own programs (Sarina, Heimdall, Limbo) connected off the machine: the
//	          ecosystem rule is loopback only
//	warning   the local model server (ollama) connected off the machine (model downloads do; anything else should not)
//	info      any other process connecting to a destination it has not used before (the record of what talks to where)
//
// Connections found on the first run (learning) are recorded only, with no finding.
type ConnectionDetector struct {
	// MeshPeer names the enrolled mesh peer at an address (docs/MESH.md): Heimdall talking to the owner's other computers is
	// expected, not an ecosystem program breaking the loopback rule. Nil: no mesh.
	MeshPeer func(ip string) (string, bool)
}

func NewConnectionDetector() *ConnectionDetector { return &ConnectionDetector{} }

func (d *ConnectionDetector) ID() string { return "connection-watch" }

var ecosystemProcs = map[string]bool{"sarina": true, "heimdalld": true, "limbo": true, "limbod": true}

func (d *ConnectionDetector) Inspect(e Event) []Finding {
	if e.Kind != "new_connection" {
		return nil
	}
	f := e.Fields
	dest := fmt.Sprintf("%s:%s", f["remote_addr"], f["remote_port"])
	if o := f["remote_origin"]; o != "" && f["remote_scope"] == "public" {
		dest += " (" + o + ")"
	}
	sev := SeverityInfo
	summary := fmt.Sprintf("%s connected to %s (new destination for it)", f["process"], dest)
	switch {
	case f["remote_listed"] != "":
		sev = SeverityCritical
		summary = fmt.Sprintf("%s connected to %s, an address on threat lists (%s): known malware, botnet or criminal networks. "+
			"This was a real, completed connection. Find out why %s talks to it before anything else; to cut it off: sudo ufw insert 1 deny out to %s comment 'blocked after a Heimdall alert'",
			f["process"], dest, f["remote_listed"], f["process"], f["remote_addr"])
	case f["blocked"] == "1":
		sev = SeverityCritical
		summary = fmt.Sprintf("app %q has its network switched off but %s connected to %s: restart the app so the rule applies", f["app"], f["process"], dest)
	case f["process"] == "heimdalld" && d.MeshPeer != nil && meshPeer(d.MeshPeer, f["remote_addr"]) != "":
		summary = fmt.Sprintf("heimdalld exchanged alerts with the enrolled mesh peer %s at %s", meshPeer(d.MeshPeer, f["remote_addr"]), dest)
	case ecosystemProcs[f["process"]]:
		sev = SeverityCritical
		summary = fmt.Sprintf("%s (an ecosystem program) connected off the machine to %s: the rule is loopback only", f["process"], dest)
	case f["process"] == "ollama":
		sev = SeverityWarning
		summary = fmt.Sprintf("ollama connected off the machine to %s (a model download does this; nothing else should)", dest)
	case f["learning"] == "1":
		return nil // (a listed destination is reported even while learning: the case above comes first)
	}
	return []Finding{{DetectorID: d.ID(), Severity: sev, Summary: summary, Event: e}}
}

func meshPeer(f func(string) (string, bool), ip string) string {
	if name, ok := f(ip); ok {
		return name
	}
	return ""
}
