package engine

import (
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// fakeRules drops a scanner's finding and adds a second one for a changed tool, as toolrules.Policy does.
type fakeRules struct{}

func (fakeRules) Apply(f detect.Finding) []detect.Finding {
	switch f.Event.Fields["process"] {
	case "masscan":
		return nil
	case "nmap":
		return []detect.Finding{f, {DetectorID: "tool-rules", Severity: detect.SeverityCritical, Summary: "changed", Event: f.Event, Firm: true}}
	}
	return []detect.Finding{f}
}

func TestToolRulesDecideWhatIsWritten(t *testing.T) {
	c := &capture{}
	e := New(c, nil, detect.NewConnectionDetector())
	e.SetToolRules(fakeRules{})
	e.SetMaintenance(fixedWindow{true}, []string{"tool-rules"})
	for _, proc := range []string{"masscan", "nmap", "curl"} {
		e.Handle(detect.Event{Kind: "new_connection", Fields: map[string]string{"process": proc, "remote_addr": "192.0.2.7", "remote_port": "443"}})
	}
	if len(c.got) != 3 || c.got[0].DetectorID != "connection-watch" || c.got[1].DetectorID != "tool-rules" || c.got[2].DetectorID != "connection-watch" {
		t.Fatalf("%+v", c.got)
	}
	if c.got[1].Severity != detect.SeverityCritical {
		t.Fatal("a firm tool-rules finding is never softened by a maintenance window")
	}
}
