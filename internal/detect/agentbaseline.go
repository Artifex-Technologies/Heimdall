package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// AgentBaselineDetector applies Phase 5's learned baseline (Welford, stats.go) to what the AI agent does, not only to the
// host's load: how many sessions it starts and how many tool calls it makes in a 15-minute window, against this agent's own
// history, and which tools it uses (a tool it has never used before, once it has a history, is a novelty worth a line: an
// agent turned by a planted instruction often reaches for a tool it does not normally need).
//
// Windows are counted only while the agent is active (a window with no session event is not a sample), so a quiet day does
// not make every working hour look extreme. The current window is judged as it fills, so an outlier is reported at once,
// without a timer; it is folded into the baseline when the next window starts. Findings are info: a statistical oddity,
// shown at the "everything" level and linked by the correlator to anything else about the same session.
type AgentBaselineDetector struct {
	MinSamples int     // active windows needed before judging
	Z          float64 // standard deviations
	StatePath  string  // where the baseline is kept between restarts; empty: memory only
	Window     time.Duration

	mu      sync.Mutex
	loaded  bool
	st      agentBaselineState
	flagged map[string]bool // signal -> already reported in this window
}

// agentFloors: below these counts per window an outlier is not worth a line (one extra session on a quiet agent).
var agentFloors = map[string]float64{"sessions": 10, "tool_calls": 60}

// minToolHistory is how many tool calls must have been seen before a new tool name counts as novel.
const minToolHistory = 200

type agentBaselineState struct {
	Window   time.Time               `json:"window"` // start of the current window
	Counts   map[string]float64      `json:"counts"`
	Stats    map[string]*OnlineStats `json:"stats"`
	Tools    map[string]int          `json:"tools"` // every tool name seen, with how often
	Calls    int                     `json:"calls"` // tool calls seen in total
	Reported map[string]bool         `json:"reported_tools"`
}

func NewAgentBaselineDetector(minSamples int, z float64, statePath string) *AgentBaselineDetector {
	return &AgentBaselineDetector{MinSamples: minSamples, Z: z, StatePath: statePath, Window: 15 * time.Minute}
}

func (d *AgentBaselineDetector) ID() string { return "agent-baseline" }

func (d *AgentBaselineDetector) load() {
	d.loaded = true
	d.flagged = map[string]bool{}
	if d.StatePath != "" {
		if b, err := os.ReadFile(d.StatePath); err == nil {
			_ = json.Unmarshal(b, &d.st)
		}
	}
	if d.st.Counts == nil {
		d.st.Counts = map[string]float64{}
	}
	if d.st.Stats == nil {
		d.st.Stats = map[string]*OnlineStats{}
	}
	if d.st.Tools == nil {
		d.st.Tools = map[string]int{}
	}
	if d.st.Reported == nil {
		d.st.Reported = map[string]bool{}
	}
}

func (d *AgentBaselineDetector) save() {
	if d.StatePath == "" {
		return
	}
	b, err := json.Marshal(d.st)
	if err != nil {
		return
	}
	tmp := d.StatePath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, d.StatePath)
	}
}

func (d *AgentBaselineDetector) Inspect(e Event) []Finding {
	if e.Source != "agent-session" || (e.Kind != "session_created" && e.Kind != "message") {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.loaded {
		d.load()
	}
	w := d.Window
	if w <= 0 {
		w = 15 * time.Minute
	}
	now := e.Time
	if now.IsZero() {
		now = time.Now()
	}
	start := now.Truncate(w)
	if !start.Equal(d.st.Window) && start.After(d.st.Window) {
		// the window that just ended becomes a sample of the baseline
		if len(d.st.Counts) > 0 {
			for _, sig := range []string{"sessions", "tool_calls"} {
				s := d.st.Stats[sig]
				if s == nil {
					s = &OnlineStats{}
					d.st.Stats[sig] = s
				}
				s.Add(d.st.Counts[sig])
			}
		}
		d.st.Window, d.st.Counts, d.flagged = start, map[string]float64{}, map[string]bool{}
		defer d.save()
	}

	var findings []Finding
	switch e.Kind {
	case "session_created":
		d.st.Counts["sessions"]++
	case "message":
		tools := e.Fields["tools"]
		if tools == "" {
			d.st.Counts["messages"]++ // keeps the window active
			return nil
		}
		names := strings.Split(tools, ",")
		d.st.Counts["tool_calls"] += float64(len(names))
		for _, n := range names {
			if d.st.Calls >= minToolHistory && d.st.Tools[n] == 0 && !d.st.Reported[n] {
				d.st.Reported[n] = true
				known := make([]string, 0, len(d.st.Tools))
				for k := range d.st.Tools {
					known = append(known, k)
				}
				sort.Strings(known)
				findings = append(findings, Finding{DetectorID: d.ID(), Severity: SeverityInfo, Event: e,
					Summary: fmt.Sprintf("the AI agent used a tool it has never used before in %d tool calls: %q", d.st.Calls, n)})
			}
			d.st.Tools[n]++
			d.st.Calls++
		}
	}
	for _, sig := range []string{"sessions", "tool_calls"} {
		s := d.st.Stats[sig]
		v := d.st.Counts[sig]
		if s == nil || s.Count() < d.MinSamples || d.flagged[sig] || v < agentFloors[sig] {
			continue
		}
		if z := s.ZScore(v); z >= d.Z {
			d.flagged[sig] = true
			findings = append(findings, Finding{DetectorID: d.ID(), Severity: SeverityInfo, Event: e,
				Summary: fmt.Sprintf("the AI agent's %s in this %s window reached %.0f, %.1f standard deviations above its own usual (mean %.1f, stddev %.1f over %d active windows)",
					strings.ReplaceAll(sig, "_", " "), w, v, z, s.Mean(), s.StdDev(), s.Count())})
		}
	}
	return findings
}
