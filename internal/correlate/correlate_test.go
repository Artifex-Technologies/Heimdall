package correlate

import (
	"strings"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

type capture struct{ got []alert.Alert }

func (c *capture) Write(a alert.Alert) error { c.got = append(c.got, a); return nil }

func (c *capture) incidents() []alert.Alert {
	var out []alert.Alert
	for _, a := range c.got {
		if a.DetectorID == DetectorID {
			out = append(out, a)
		}
	}
	return out
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func al(det string, sev detect.Severity, session string, fields map[string]string) alert.Alert {
	return alert.Alert{Time: time.Now(), DetectorID: det, Severity: sev, Summary: det, SessionID: session, Fields: fields}
}

func TestRelatedAlertsBecomeOneIncident(t *testing.T) {
	out := &capture{}
	clk := &clock{time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	c := &Correlator{Next: out, Now: clk.now}

	// a planted instruction in session s1, then a new connection by pid 4242 in the same session's tool call, then a
	// listed address that pid talked to: three detectors, linked through the session and the pid
	c.Write(al("injection-phrase", detect.SeverityCritical, "s1", nil))
	if len(out.incidents()) != 0 {
		t.Fatal("one detector is not an incident")
	}
	c.Write(al("permission-escalation", detect.SeverityWarning, "s1", map[string]string{"pid": "4242"}))
	if n := len(out.incidents()); n != 1 {
		t.Fatalf("two detectors sharing a session: %d incident alerts", n)
	}
	first := out.incidents()[0]
	if first.Severity != detect.SeverityCritical || !strings.Contains(first.Summary, "injection-phrase, permission-escalation") {
		t.Fatalf("%+v", first)
	}
	c.Write(al("connection-watch", detect.SeverityInfo, "", map[string]string{"pid": "4242", "remote_addr": "203.0.113.9"}))
	if n := len(out.incidents()); n != 2 {
		t.Fatalf("a third detector joining is reported again: %d", n)
	}
	c.Write(al("connection-watch", detect.SeverityInfo, "", map[string]string{"pid": "4242", "remote_addr": "203.0.113.10"}))
	if n := len(out.incidents()); n != 2 {
		t.Fatalf("the same detectors again are not news: %d", n)
	}
	if got := c.Incidents(); len(got) != 1 || len(got[0].Alerts) != 4 {
		t.Fatalf("%+v", got)
	}
	if len(out.got) != 6 {
		t.Fatalf("every alert is passed on: %d", len(out.got))
	}
}

func TestUnrelatedOrOldAlertsStayApart(t *testing.T) {
	out := &capture{}
	clk := &clock{time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	c := &Correlator{Next: out, Now: clk.now, Window: 10 * time.Minute}
	c.Write(al("injection-phrase", detect.SeverityCritical, "s1", nil))
	c.Write(al("credential-shape", detect.SeverityCritical, "s2", nil))
	clk.t = clk.t.Add(11 * time.Minute)
	c.Write(al("credential-shape", detect.SeverityCritical, "s1", nil))
	if len(out.incidents()) != 0 {
		t.Fatal("different sessions, or the same one after the window, are not one incident")
	}
	c.Write(al("connection-watch", detect.SeverityInfo, "", map[string]string{"remote_addr": "203.0.113.9"}))
	c.Write(al("lan-watch", detect.SeverityInfo, "", map[string]string{"remote_addr": "203.0.113.9"}))
	if len(out.incidents()) != 0 {
		t.Fatal("information-only alerts never make an incident alert")
	}
}

// Two incidents that a later alert connects (it names a thing from each) become one.
func TestABridgingAlertMergesIncidents(t *testing.T) {
	out := &capture{}
	c := &Correlator{Next: out}
	c.Write(al("limbo-guest", detect.SeverityCritical, "", map[string]string{"guest": "lab"}))
	c.Write(al("remote-access", detect.SeverityWarning, "", map[string]string{"provider": "chisel"}))
	c.Write(al("connection-watch", detect.SeverityInfo, "", map[string]string{"guest": "lab", "provider": "chisel"}))
	if got := c.Incidents(); len(got) != 1 || len(got[0].Detectors) != 3 {
		t.Fatalf("%+v", got)
	}
}

// Limbo's guest network and exchange alerts link through the guest, so a guest that probes this computer and tries to hand
// out a known virus is one incident. The guest's own file path does not link to a file on this computer.
func TestLimboGuestAlertsBecomeOneIncident(t *testing.T) {
	out := &capture{}
	c := &Correlator{Next: out}
	ev := func(kind string, f map[string]string) detect.Event {
		f["guest"] = "lab"
		return detect.Event{Source: "limbo", Kind: kind, Fields: f}
	}
	write := func(d detect.Detector, e detect.Event) {
		for _, f := range d.Inspect(e) {
			c.Write(alert.FromFinding(f))
		}
	}
	// an unrelated alert about a real file on this computer with the same name as the guest's file
	c.Write(al("file-integrity", detect.SeverityCritical, "", map[string]string{"path": "out/x.exe"}))
	write(detect.NewLimboNetworkDetector(), ev("net.anomaly", map[string]string{"reason": "host_probe", "proto": "tcp", "dst": "192.0.2.1", "dport": "22"}))
	if len(out.incidents()) != 0 {
		t.Fatal("one Limbo detector is not an incident")
	}
	write(detect.NewLimboExchangeDetector(), ev("exchange.held", map[string]string{"path": "out/x.exe", "sha256": strings.Repeat("a", 64), "signature": "Eicar-Test-Signature"}))
	inc := out.incidents()
	if len(inc) != 1 {
		t.Fatalf("%d incident alerts, want 1", len(inc))
	}
	if inc[0].Severity != detect.SeverityCritical || inc[0].Fields["detectors"] != "limbo-exchange,limbo-network" || !strings.Contains(inc[0].Fields["keys"], "guest:lab") {
		t.Fatalf("incident: %+v", inc[0])
	}
	if strings.Contains(inc[0].Fields["keys"], "file:") {
		t.Fatalf("the guest's path linked to a file on this computer: %s", inc[0].Fields["keys"])
	}
}

func TestAnIncidentOfPracticeAlertsIsPractice(t *testing.T) {
	out := &capture{}
	c := &Correlator{Next: out, Now: time.Now}
	p := map[string]string{"practice": "1"}
	c.Write(al("injection-phrase", detect.SeverityCritical, "eval", p))
	c.Write(al("credential-shape", detect.SeverityCritical, "eval", p))
	if got := out.incidents(); len(got) != 1 || got[0].Fields["practice"] != "1" {
		t.Fatalf("all its alerts were Sarina's evals: %+v", got)
	}
	// one real alert joining makes it real
	c.Write(al("permission-escalation", detect.SeverityWarning, "eval", nil))
	if got := out.incidents(); len(got) != 2 || got[1].Fields["practice"] != "" {
		t.Fatalf("a real alert in it: %+v", got)
	}
}
