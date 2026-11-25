package detect

import "fmt"

// Limbo's guest network and file exchange events (Limbo's docs/EVENTS.md, "Guest network" and "Files leaving a guest"),
// added by Limbo on 2026-11-05. They get their own detectors, apart from limbo-guest, for two reasons: each has its own
// plain-language explanation, and an incident (internal/correlate) needs two detectors to share a guest, so a guest that
// probes the host and also tries to hand out a known virus becomes one story.
//
// What is deliberately NOT turned into an alert:
//   - net.flow is normal traffic the guest's policy allows. Alerting on it would be noise.
//   - net.blocked is one refusal; Limbo already counts refusals and reports probing as net.anomaly (host_probe,
//     lan_probe, scan). An alert per refusal would say the same thing twice.
//   - exchange.file is a file scanned clean and handed out, which is what the exchange is for.
//
// Both detectors keep no state: Limbo already limits how often each event is written (an anomaly at most once per guest
// and reason per 10 minutes, 256 flow events per guest), so nothing here needs counting or a timer.

// Network anomaly reasons, as Limbo writes them.
const (
	LimboReasonHostProbe = "host_probe"
	LimboReasonLANProbe  = "lan_probe"
	LimboReasonScan      = "scan"
	LimboReasonIPv6      = "ipv6"
)

// LimboNetworkDetector turns net.anomaly and net.capped into findings.
type LimboNetworkDetector struct {
	// callsHome holds, per guest, what it reached for through Limbo's sinkhole and was reported (HEI-5): each target once,
	// at most limboCallsHome a guest, until its sinkhole stops.
	callsHome map[string]map[string]bool
}

// limboCallsHome is how many sinkhole targets of one guest are reported; the rest are in Limbo's run result and log.
const limboCallsHome = 8

// sinkholeTarget says what a guest reached for through the sinkhole, from Limbo's fields (guest data: quoted, each cut to
// 120 characters), and a key that is the same for the same target.
func sinkholeTarget(kind string, f map[string]string) (string, string) {
	cut := func(s string) string {
		r := []rune(s)
		if len(r) > 120 {
			r = r[:120]
		}
		return string(r)
	}
	if kind == "sinkhole.dns" {
		name := cut(f["name"])
		return fmt.Sprintf("the name %q (%s)", name, limboOrDash(cut(f["type"]))), "dns " + name
	}
	what := fmt.Sprintf("%s port %s", limboOrDash(cut(f["proto"])), limboOrDash(cut(f["dport"])))
	if d := cut(f["dst"]); d != "" {
		what = fmt.Sprintf("%q, %s", d, what)
	}
	if s := cut(f["sni"]); s != "" {
		what += fmt.Sprintf(", TLS server name %q", s)
	} else if h := cut(f["host"]); h != "" {
		what += fmt.Sprintf(", HTTP host %q", h)
	}
	return what, "connect " + what
}

func NewLimboNetworkDetector() *LimboNetworkDetector { return &LimboNetworkDetector{} }

func (d *LimboNetworkDetector) ID() string { return "limbo-network" }

func (d *LimboNetworkDetector) Inspect(e Event) []Finding {
	if e.Source != "limbo" {
		return nil
	}
	g := e.Fields["guest"]
	finding := func(sev Severity, format string, a ...any) []Finding {
		return []Finding{{DetectorID: d.ID(), Severity: sev, Summary: fmt.Sprintf(format, a...), Event: e}}
	}
	switch e.Kind {
	case "net.anomaly":
		where := limboTarget(e.Fields)
		switch r := e.Fields["reason"]; r {
		case LimboReasonHostProbe:
			return finding(SeverityCritical, "guest %q reached for this computer itself (%s): a sandboxed program probing its host", g, where)
		case LimboReasonLANProbe:
			return finding(SeverityCritical, "guest %q reached for the home network, the router or another guest (%s)", g, where)
		case LimboReasonScan:
			return finding(SeverityWarning, "guest %q was refused many different destinations in a short time (%s): it looks like a scan", g, where)
		case LimboReasonIPv6:
			return finding(SeverityWarning, "guest %q tried to send IPv6 off its own link (%s); it has no IPv6, so this was dropped", g, where)
		default:
			// A reason added by a newer Limbo: still a refusal pattern Limbo thought worth reporting.
			return finding(SeverityWarning, "guest %q: Limbo reported unusual network refusals (reason %q, %s)", g, r, where)
		}
	case "net.capped":
		return finding(SeverityInfo, "guest %q used its budget of %s network events; Limbo records no more new destinations for it (anomalies still are)", g, limboOrDash(e.Fields["limit"]))
	case "sinkhole.dns", "sinkhole.connect":
		// a sealed guest (a sample's analysis, or a program vetted) reaching out: it calls home (HEI-5)
		target, key := sinkholeTarget(e.Kind, e.Fields)
		if d.callsHome == nil {
			d.callsHome = map[string]map[string]bool{}
		}
		seen := d.callsHome[g]
		if seen == nil {
			seen = map[string]bool{}
			d.callsHome[g] = seen
		}
		if seen[key] || len(seen) >= limboCallsHome {
			return nil
		}
		seen[key] = true
		return finding(SeverityWarning, "guest %q reached for %s through Limbo's sinkhole: the program in it (a sample, or a tool a crafted file took over) calls out. The sinkhole answered; nothing left this computer", g, target)
	case "sinkhole.stop":
		delete(d.callsHome, g)
	}
	return nil
}

// limboTarget describes where a refused packet went, from Limbo's fields (all written by Limbo from the packet headers).
func limboTarget(f map[string]string) string {
	s := limboOrDash(f["proto"]) + " to " + limboOrDash(f["dst"])
	if p := f["dport"]; p != "" {
		s += " port " + p
	}
	if c := f["count"]; c != "" {
		s += ", " + c + " time(s)"
	}
	return s
}

func limboOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// LimboExchangeDetector turns exchange.held and exchange.fail into findings.
//
// The file's path inside the guest is the guest's to choose, so it is untrusted: it is quoted in the summary and moved
// from the field "path" to "guest_path". "path" means a file on this computer to the rest of Heimdall (the correlator links
// alerts that share one), and a guest must not be able to tie its alert to an unrelated alert about a real file here.
type LimboExchangeDetector struct{}

func NewLimboExchangeDetector() *LimboExchangeDetector { return &LimboExchangeDetector{} }

func (d *LimboExchangeDetector) ID() string { return "limbo-exchange" }

func (d *LimboExchangeDetector) Inspect(e Event) []Finding {
	if e.Source != "limbo" || (e.Kind != "exchange.held" && e.Kind != "exchange.fail") {
		return nil
	}
	g := e.Fields["guest"]
	ev := e
	ev.Fields = make(map[string]string, len(e.Fields))
	for k, v := range e.Fields {
		if k == "path" {
			k = "guest_path"
		}
		ev.Fields[k] = v
	}
	finding := func(sev Severity, format string, a ...any) []Finding {
		return []Finding{{DetectorID: d.ID(), Severity: sev, Summary: fmt.Sprintf(format, a...), Event: ev}}
	}
	if e.Kind == "exchange.held" {
		return finding(SeverityWarning, "guest %q tried to hand out a file ClamAV knows as malware (%q, signature %q); Limbo held it and did not hand it out",
			g, limboClip(e.Fields["path"], 120), limboClip(e.Fields["signature"], 80))
	}
	return finding(SeverityInfo, "guest %q: a file could not be scanned, so it stayed in the guest's outbox (%q: %s)",
		g, limboClip(e.Fields["path"], 120), limboClip(e.Fields["reason"], 120))
}

func limboClip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}
