// Package parity runs the daemon's detectors and engine over recorded events, so the Go daemon and its Rust port
// (rust/heimdall) can be shown to raise the same alerts on the same inputs. The fixtures in testdata/parity are scenarios
// exported from this package (scenarios.go transcribes the Go table tests); both languages run them and must produce the
// alert lines stored in them byte for byte (with the time each alert was raised set to the zero time).
//
// Nothing here touches the system: no package database, no trust list, the default temporary port range; the mesh peers,
// remote-access approvals, maintenance window and tool rules come from the scenario.
package parity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/engine"
	"github.com/Artifex-Technologies/Heimdall/internal/maintenance"
	"github.com/Artifex-Technologies/Heimdall/internal/toolrules"
)

// Format is the fixture files' format line.
const Format = "heimdall-parity/1"

// File is one fixture file.
type File struct {
	Format    string     `json:"format"`
	From      string     `json:"from"`
	Scenarios []Scenario `json:"scenarios"`
}

// Scenario is a run of events through the daemon's detectors with one configuration.
type Scenario struct {
	Name string `json:"name"`
	// Config is read over the defaults like the daemon's config file; "$TMP" in a string value is the run's temporary folder.
	Config      map[string]any      `json:"config,omitempty"`
	Deps        Deps                `json:"deps,omitempty"`
	Maintenance *maintenance.Window `json:"maintenance,omitempty"`
	ToolRules   *ToolRules          `json:"tool_rules,omitempty"`
	Steps       []Step              `json:"steps"`
	Golden      [][]string          `json:"golden"`
}

// Deps stand in for what the detectors would ask the system.
type Deps struct {
	Packages  map[string][2]string `json:"packages,omitempty"`   // path -> package, recorded SHA-256
	Trust     map[string][2]string `json:"trust,omitempty"`      // path -> verdict, why
	Approved  []string             `json:"approved,omitempty"`   // approved remote-access tools
	MeshPeers map[string]string    `json:"mesh_peers,omitempty"` // IP address -> peer name
	Ephemeral *[2]int              `json:"ephemeral,omitempty"`  // the temporary port range (default 32768-60999)
	// For the replay tool (rust/gotools/replay): the real mesh peers file and approvals file instead of the maps above.
	MeshPeerFunc func(ip string) (string, bool) `json:"-"`
	ApprovedFunc func(id string) bool           `json:"-"`
}

// ToolRules puts the security-tool rules in force with a made-up package database, file hashes and clock.
type ToolRules struct {
	Owner map[string][2]string `json:"owner"` // path -> package, recorded SHA-256
	Hash  map[string]string    `json:"hash"`  // path -> SHA-256 now
	Clock string               `json:"clock"` // RFC 3339; advanced by steps
}

// Step is one event, a restart of the detectors (state files kept), or the tool rules' clock moving on.
type Step struct {
	Event          *EventJSON `json:"event,omitempty"`
	Restart        bool       `json:"restart,omitempty"`
	AdvanceSeconds int        `json:"advance_seconds,omitempty"`
	// Expect carries the original Go test's assertions for this step, checked by both languages.
	Expect []Expect `json:"expect,omitempty"`
}

// Expect: the alerts of one detector at this step have exactly these severities, in order; each summary holds Contains;
// the first one's fields have these values ("" meaning absent).
type Expect struct {
	Detector   string            `json:"detector"`
	Severities []string          `json:"severities"`
	Contains   string            `json:"contains,omitempty"`
	Lacks      string            `json:"lacks,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
}

// EventJSON is an event as a JSON line (also rust/heimdall/src/replay.rs).
type EventJSON struct {
	Source    string            `json:"source"`
	SessionID string            `json:"session_id"`
	Time      string            `json:"time"`
	Kind      string            `json:"kind"`
	Text      string            `json:"text"`
	Fields    map[string]string `json:"fields"`
}

// Event turns the JSON form into a detect.Event.
func (e EventJSON) Event() (detect.Event, error) {
	var t time.Time
	if e.Time != "" {
		var err error
		if t, err = time.Parse(time.RFC3339Nano, e.Time); err != nil {
			return detect.Event{}, err
		}
	}
	return detect.Event{Source: e.Source, SessionID: e.SessionID, Time: t, Kind: e.Kind, Text: e.Text, Fields: e.Fields}, nil
}

// FromEvent is the JSON form of an event.
func FromEvent(e detect.Event) EventJSON {
	j := EventJSON{Source: e.Source, SessionID: e.SessionID, Kind: e.Kind, Text: e.Text, Fields: e.Fields}
	if !e.Time.IsZero() {
		j.Time = e.Time.Format(time.RFC3339Nano)
	}
	return j
}

type fakeVerifier map[string][2]string

func (f fakeVerifier) Expected(p string) (string, string, bool) {
	o, ok := f[p]
	return o[0], o[1], ok
}

type fakeTrust map[string][2]string

func (f fakeTrust) Judge(p, _ string, _ bool) (string, string) { return f[p][0], f[p][1] }

// Detectors is the daemon's list (cmd/heimdalld newDetectors, same order; a test there checks it) with the scenario's
// stand-ins for the system.
func Detectors(cfg config.Config, d Deps) []detect.Detector {
	fim := detect.NewFileIntegrityDetector()
	if d.Packages != nil {
		fim = detect.NewPackageAwareFileIntegrityDetector(fakeVerifier(d.Packages))
	}
	if d.Trust != nil {
		fim.WithTrust(fakeTrust(d.Trust))
	}
	inbound := detect.NewInboundDetector()
	inbound.EphemeralLow, inbound.EphemeralHigh = 32768, 60999
	if d.Ephemeral != nil {
		inbound.EphemeralLow, inbound.EphemeralHigh = d.Ephemeral[0], d.Ephemeral[1]
	}
	approved := map[string]bool{}
	for _, id := range d.Approved {
		approved[id] = true
	}
	isApproved := func(id string) bool { return approved[id] }
	if d.ApprovedFunc != nil {
		isApproved = d.ApprovedFunc
	}
	meshPeer := func(ip string) (string, bool) { n, ok := d.MeshPeers[ip]; return n, ok }
	if d.MeshPeerFunc != nil {
		meshPeer = d.MeshPeerFunc
	}
	return []detect.Detector{
		detect.NewInjectionDetector(),
		detect.NewCredentialDetector(),
		detect.NewUnicodeDetector(),
		detect.NewEscalationDetector(),
		detect.NewBurstDetector(cfg.BurstWindow(), cfg.BurstThreshold, cfg.BurstCooldown()),
		fim,
		detect.NewMaintenanceDetector(),
		detect.NewResourcePressureDetector(cfg.ResourceMemThresholdPercent, cfg.ResourceLoadThresholdPerCPU),
		detect.NewNetworkExposureDetector(),
		&detect.ConnectionDetector{MeshPeer: meshPeer},
		inbound,
		detect.NewPackageVulnerabilityDetector(),
		detect.NewKernelVulnerabilityDetector(),
		detect.NewHardeningDetector(),
		detect.NewWifiDetector(),
		detect.NewLANDetector(),
		detect.NewBaselineDriftDetectorWithFloors(cfg.BaselineMinSamples, cfg.BaselineZThreshold, detect.DefaultBaselineFloors),
		detect.NewAgentBaselineDetector(cfg.BaselineMinSamples, cfg.BaselineZThreshold, cfg.AgentBaselineStatePath),
		detect.NewLimboGuestDetector(),
		detect.NewLimboNetworkDetector(),
		detect.NewLimboExchangeDetector(),
		detect.NewRemoteAccessDetector(isApproved),
	}
}

type capture struct{ lines []string }

func (c *capture) Write(a alert.Alert) error {
	a.Time = time.Time{}
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(a); err != nil {
		return err
	}
	c.lines = append(c.lines, strings.TrimSuffix(b.String(), "\n"))
	return nil
}

// substitute replaces "$TMP" in the config's string values (and lists of strings).
func substitute(v any, tmp string) any {
	switch x := v.(type) {
	case string:
		return strings.ReplaceAll(x, "$TMP", tmp)
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = substitute(x[i], tmp)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = substitute(e, tmp)
		}
		return out
	}
	return v
}

// Run runs a scenario and returns the alert lines of each step.
func Run(s Scenario, tmp string) ([][]string, error) {
	cfg := config.Default()
	cfg.AgentBaselineStatePath = "" // a scenario learns into its own state, if it names one
	cfg.MaintenancePath = ""
	if s.Config != nil {
		raw, _ := json.Marshal(substitute(s.Config, tmp))
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("%s: config: %w", s.Name, err)
		}
	}
	if s.Maintenance != nil {
		cfg.MaintenancePath = filepath.Join(tmp, "maintenance.json")
		if err := maintenance.Write(cfg.MaintenancePath, *s.Maintenance); err != nil {
			return nil, err
		}
	}
	var clock time.Time
	var policy *toolrules.Policy
	if s.ToolRules != nil {
		c, err := toolrules.Builtin()
		if err != nil {
			return nil, err
		}
		tr := s.ToolRules
		policy = toolrules.New(c, func(p string) (string, string, bool) { o, ok := tr.Owner[p]; return o[0], o[1], ok })
		if clock, err = time.Parse(time.RFC3339Nano, tr.Clock); err != nil {
			return nil, err
		}
		policy.SetTestHooks(func(p string) (string, error) {
			if h, ok := tr.Hash[p]; ok {
				return h, nil
			}
			return "", os.ErrNotExist
		}, func() time.Time { return clock })
	}
	sink := &capture{}
	build := func() *engine.Engine {
		e := engine.New(sink, nil, Detectors(cfg, s.Deps)...)
		e.SetMaintenance(maintenance.NewWatcher(cfg.MaintenancePath), cfg.MaintenanceSoften)
		if policy != nil {
			e.SetToolRules(policy)
		}
		return e
	}
	eng := build()
	out := make([][]string, len(s.Steps))
	for i, st := range s.Steps {
		sink.lines = nil
		switch {
		case st.Restart:
			eng = build()
		case st.AdvanceSeconds != 0:
			clock = clock.Add(time.Duration(st.AdvanceSeconds) * time.Second)
		case st.Event != nil:
			ev, err := st.Event.Event()
			if err != nil {
				return nil, fmt.Errorf("%s: step %d: %w", s.Name, i, err)
			}
			eng.Handle(ev)
		}
		out[i] = append([]string{}, sink.lines...)
	}
	return out, nil
}

// Check holds a step's alert lines against its expectations (the original Go test's assertions).
func Check(st Step, lines []string) error {
	for _, x := range st.Expect {
		var sevs []string
		var first map[string]string
		for _, l := range lines {
			var a struct {
				DetectorID string            `json:"detector_id"`
				Severity   string            `json:"severity"`
				Summary    string            `json:"summary"`
				Fields     map[string]string `json:"fields"`
			}
			if err := json.Unmarshal([]byte(l), &a); err != nil {
				return err
			}
			if a.DetectorID != x.Detector {
				continue
			}
			sevs = append(sevs, a.Severity)
			if first == nil {
				first = a.Fields
				if first == nil {
					first = map[string]string{}
				}
			}
			if x.Contains != "" && !strings.Contains(a.Summary, x.Contains) {
				return fmt.Errorf("%s: summary %q lacks %q", x.Detector, a.Summary, x.Contains)
			}
			if x.Lacks != "" && strings.Contains(a.Summary, x.Lacks) {
				return fmt.Errorf("%s: summary %q holds %q", x.Detector, a.Summary, x.Lacks)
			}
		}
		if strings.Join(sevs, ",") != strings.Join(x.Severities, ",") {
			return fmt.Errorf("%s: severities %v, want %v", x.Detector, sevs, x.Severities)
		}
		keys := make([]string, 0, len(x.Fields))
		for k := range x.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if got := first[k]; got != x.Fields[k] {
				return fmt.Errorf("%s: field %s = %q, want %q", x.Detector, k, got, x.Fields[k])
			}
		}
	}
	return nil
}
