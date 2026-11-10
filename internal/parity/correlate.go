package parity

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/correlate"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// Correlations is the correlator's fixture (testdata/parity/correlate.json): alerts written one by one with a clock, the
// lines the correlator passes on (incident alerts with their raise time set to zero) and GET /v1/incidents' body at the end.
// The Go tests of internal/correlate are in it, with generated sequences besides.
type Correlations struct {
	Format    string            `json:"format"`
	Scenarios []CorrelationCase `json:"scenarios"`
}

type CorrelationCase struct {
	Name          string     `json:"name"`
	WindowSeconds int        `json:"window_seconds,omitempty"`
	Clock         time.Time  `json:"clock"`
	Steps         []CorrStep `json:"steps"`
	Incidents     string     `json:"incidents"`
}

type CorrStep struct {
	AdvanceSeconds int      `json:"advance_seconds,omitempty"`
	Alert          string   `json:"alert"`
	Out            []string `json:"out"`
}

type collect struct{ lines []string }

func (c *collect) Write(a alert.Alert) error {
	if a.DetectorID == correlate.DetectorID {
		a.Time = time.Time{}
	}
	b, err := json.Marshal(a)
	c.lines = append(c.lines, string(b))
	return err
}

func line(a alert.Alert) string {
	b, _ := json.Marshal(a)
	return string(b)
}

// RunCorrelation runs one case through the Go correlator, filling in Out and Incidents.
func RunCorrelation(c CorrelationCase) (CorrelationCase, error) {
	out := &collect{}
	now := c.Clock
	corr := &correlate.Correlator{Next: out, Window: time.Duration(c.WindowSeconds) * time.Second, Now: func() time.Time { return now }}
	for i := range c.Steps {
		st := &c.Steps[i]
		now = now.Add(time.Duration(st.AdvanceSeconds) * time.Second)
		var a alert.Alert
		if err := json.Unmarshal([]byte(st.Alert), &a); err != nil {
			return c, err
		}
		out.lines = nil
		if err := corr.Write(a); err != nil {
			return c, err
		}
		st.Out = out.lines
	}
	b, err := json.Marshal(corr.Incidents())
	c.Incidents = string(b)
	return c, err
}

// AllCorrelations computes the fixture with the Go correlator.
func AllCorrelations() (Correlations, error) {
	f := Correlations{Format: "heimdall-parity-correlate/1"}
	t0 := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	n := 0
	al := func(det string, sev detect.Severity, session string, fields map[string]string) string {
		n++
		return line(alert.Alert{Time: t0.Add(time.Duration(n) * time.Second), DetectorID: det, Severity: sev, Summary: det + " summary",
			SessionID: session, Fields: fields})
	}
	step := func(adv int, a string) CorrStep { return CorrStep{AdvanceSeconds: adv, Alert: a} }
	f.Scenarios = append(f.Scenarios,
		CorrelationCase{Name: "correlate: TestRelatedAlertsBecomeOneIncident", Clock: t0, Steps: []CorrStep{
			step(0, al("injection-phrase", detect.SeverityCritical, "s1", nil)),
			step(1, al("permission-escalation", detect.SeverityWarning, "s1", map[string]string{"pid": "4242"})),
			step(1, al("connection-watch", detect.SeverityInfo, "", map[string]string{"pid": "4242", "remote_addr": "203.0.113.9"})),
			step(1, al("connection-watch", detect.SeverityInfo, "", map[string]string{"pid": "4242", "remote_addr": "203.0.113.10"})),
		}},
		CorrelationCase{Name: "correlate: TestUnrelatedOrOldAlertsStayApart", Clock: t0, WindowSeconds: 600, Steps: []CorrStep{
			step(0, al("injection-phrase", detect.SeverityCritical, "s1", nil)),
			step(0, al("credential-shape", detect.SeverityCritical, "s2", nil)),
			step(660, al("credential-shape", detect.SeverityCritical, "s1", nil)),
			step(0, al("connection-watch", detect.SeverityInfo, "", map[string]string{"remote_addr": "203.0.113.9"})),
			step(0, al("lan-watch", detect.SeverityInfo, "", map[string]string{"remote_addr": "203.0.113.9"})),
		}},
		CorrelationCase{Name: "correlate: TestABridgingAlertMergesIncidents", Clock: t0, Steps: []CorrStep{
			step(0, al("limbo-guest", detect.SeverityCritical, "", map[string]string{"guest": "lab"})),
			step(5, al("remote-access", detect.SeverityWarning, "", map[string]string{"provider": "chisel"})),
			step(5, al("connection-watch", detect.SeverityInfo, "", map[string]string{"guest": "lab", "provider": "chisel"})),
		}},
		CorrelationCase{Name: "correlate: TestAnIncidentOfPracticeAlertsIsPractice", Clock: t0, Steps: []CorrStep{
			step(0, al("injection-phrase", detect.SeverityCritical, "eval", map[string]string{"practice": "1"})),
			step(0, al("credential-shape", detect.SeverityCritical, "eval", map[string]string{"practice": "1"})),
			step(0, al("permission-escalation", detect.SeverityWarning, "eval", nil)),
		}},
	)
	// TestLimboGuestAlertsBecomeOneIncident: alerts made by the detectors themselves
	var limbo []CorrStep
	limbo = append(limbo, step(0, al("file-integrity", detect.SeverityCritical, "", map[string]string{"path": "out/x.exe"})))
	for _, x := range []struct {
		d    detect.Detector
		kind string
		f    map[string]string
	}{
		{detect.NewLimboNetworkDetector(), "net.anomaly", map[string]string{"reason": "host_probe", "proto": "tcp", "dst": "192.0.2.1", "dport": "22"}},
		{detect.NewLimboExchangeDetector(), "exchange.held", map[string]string{"path": "out/x.exe", "sha256": strings.Repeat("a", 64), "signature": "Eicar-Test-Signature"}},
	} {
		x.f["guest"] = "lab"
		for _, fd := range x.d.Inspect(detect.Event{Source: "limbo", Kind: x.kind, Fields: x.f}) {
			a := alert.FromFinding(fd)
			n++
			a.Time = t0.Add(time.Duration(n) * time.Second)
			limbo = append(limbo, step(2, line(a)))
		}
	}
	f.Scenarios = append(f.Scenarios, CorrelationCase{Name: "correlate: TestLimboGuestAlertsBecomeOneIncident", Clock: t0, Steps: limbo})

	// generated: alerts naming things from small pools, the clock moving on, merges, expiry, the caps
	r := rand.New(rand.NewSource(3))
	dets := []string{"injection-phrase", "credential-shape", "connection-watch", "remote-access", "limbo-guest", "limbo-network",
		"file-integrity", "integration", "incident", "resource-pressure", "inbound", "lan-watch", "tool-rules"}
	sevs := []detect.Severity{detect.SeverityInfo, detect.SeverityWarning, detect.SeverityCritical}
	pools := map[string][]string{"guest": {"lab", "w11", ""}, "remote_addr": {"203.0.113.9", "198.51.100.7", "unknown", ""},
		"src": {"203.0.113.9", "0", ""}, "other_ip": {"192.0.2.4", ""}, "path": {"/etc/passwd", "out/x.exe", ""},
		"provider": {"chisel", "anydesk", ""}, "pid": {"4242", "-1", "0", "17", ""}, "process": {"curl", "ssh", ""},
		"app": {"vivaldi", ""}, "request_id": {"r1", ""}, "practice": {"1", "", "", ""}}
	for k := 0; k < 20; k++ {
		c := CorrelationCase{Name: fmt.Sprintf("generated %d", k), Clock: t0, WindowSeconds: []int{0, 300, 1800}[r.Intn(3)]}
		count := 30 + r.Intn(60)
		if k%10 >= 8 {
			count = 300 // past the caps: 200 incidents, 64 keys, 50 members
		}
		names := make([]string, 0, len(pools))
		for name := range pools {
			names = append(names, name)
		}
		sort.Strings(names) // the same fixture on every run
		for i := 0; i < count; i++ {
			fields := map[string]string{}
			for _, name := range names {
				vals := pools[name]
				if r.Intn(4) == 0 {
					if v := vals[r.Intn(len(vals))]; v != "" {
						fields[name] = v
					}
				}
			}
			session := []string{"", "", "s1", "s2", "eval"}[r.Intn(5)]
			adv := r.Intn(4) * r.Intn(400)
			switch k % 10 {
			case 9: // unrelated incidents, one a second: the cap of 200
				fields, session, adv = map[string]string{"path": fmt.Sprintf("/tmp/f%d", i)}, "", 1
			case 8: // one session and a new file each time: the caps of 64 keys and 50 members
				fields, session, adv = map[string]string{"path": fmt.Sprintf("/tmp/f%d", i)}, "s1", 1
			}
			c.Steps = append(c.Steps, step(adv, al(dets[r.Intn(len(dets))], sevs[r.Intn(3)], session, fields)))
		}
		f.Scenarios = append(f.Scenarios, c)
	}
	for i := range f.Scenarios {
		var err error
		if f.Scenarios[i], err = RunCorrelation(f.Scenarios[i]); err != nil {
			return f, err
		}
	}
	return f, nil
}
