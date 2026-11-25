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
	flagged map[string]bool     // signal -> already reported in this window
	recent  map[string][]string // session -> its last tool calls (up to three), for the sequences
}

// agentFloors: below these counts per window an outlier is not worth a line (one extra session on a quiet agent).
var agentFloors = map[string]float64{"sessions": 10, "tool_calls": 60}

// minToolHistory is how many tool calls must have been seen before a new tool name counts as novel.
const minToolHistory = 200

// Sequences (HEI-54, R15, TALON's idea taken from single tools to three calls in a row in one session): once
// minSequenceHistory sequences have been seen, one never seen is a close variant when it differs from a known one in one
// step (info), else novel: a warning when one of its tools writes files or reaches the network (reachingTools), info
// otherwise. Each is reported once. maxRecentSessions bounds the sessions whose last calls are kept in memory (all are
// dropped past it: a sequence then starts again).
const (
	minSequenceHistory = 300
	maxRecentSessions  = 256
	youngTool          = 3 // uses (this one counted) under which a tool's sequences are not reported
)

// reachingTools are Sarina's tools that write files (write_file, edit_file, vault_write, forge_write, stego_clean's
// cleaned copy) or can reach anything (bash) or the network (web_fetch).
var reachingTools = map[string]bool{"write_file": true, "edit_file": true, "vault_write": true, "forge_write": true,
	"stego_clean": true, "bash": true, "web_fetch": true}

type agentBaselineState struct {
	Window   time.Time               `json:"window"` // start of the current window
	Counts   map[string]float64      `json:"counts"`
	Stats    map[string]*OnlineStats `json:"stats"`
	Tools    map[string]int          `json:"tools"` // every tool name seen, with how often
	Calls    int                     `json:"calls"` // tool calls seen in total
	Reported map[string]bool         `json:"reported_tools"`
	// HEI-54: every sequence of three calls seen ("a>b>c"), with how often; how many were seen; those reported
	Grams         map[string]int  `json:"grams,omitempty"`
	GramCalls     int             `json:"gram_calls,omitempty"`
	ReportedGrams map[string]bool `json:"reported_sequences,omitempty"`
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
	if d.st.Grams == nil {
		d.st.Grams = map[string]int{}
	}
	if d.st.ReportedGrams == nil {
		d.st.ReportedGrams = map[string]bool{}
	}
	d.recent = map[string][]string{}
}

// sequence is the finding for a sequence of three calls not seen before, once history allows judging; ok is false otherwise.
func (d *AgentBaselineDetector) sequence(e Event, g string, tail []string) (Finding, bool) {
	if d.st.GramCalls < minSequenceHistory || d.st.Grams[g] > 0 || d.st.ReportedGrams[g] {
		return Finding{}, false
	}
	d.st.ReportedGrams[g] = true
	shown := strings.Join(tail, ", then ")
	known := make([]string, 0, len(d.st.Grams))
	for k := range d.st.Grams {
		known = append(known, k)
	}
	sort.Strings(known)
	for _, k := range known {
		p := strings.Split(k, ">")
		if len(p) != 3 {
			continue
		}
		differ := 0
		for i := range p {
			if p[i] != tail[i] {
				differ++
			}
		}
		if differ == 1 {
			return Finding{DetectorID: d.ID(), Severity: SeverityInfo, Event: e,
				Summary: fmt.Sprintf("the AI agent ran a sequence of tools it had not run before, one step from one it has (%s): %s", strings.Join(p, ", then "), shown)}, true
		}
	}
	for _, t := range tail {
		if reachingTools[t] {
			return Finding{DetectorID: d.ID(), Severity: SeverityWarning, Event: e,
				Summary: fmt.Sprintf("the AI agent ran a sequence of tools unlike any of the %d it has run: %s; %s writes files or reaches the network", d.st.GramCalls, shown, t)}, true
		}
	}
	return Finding{DetectorID: d.ID(), Severity: SeverityInfo, Event: e,
		Summary: fmt.Sprintf("the AI agent ran a sequence of tools unlike any of the %d it has run: %s", d.st.GramCalls, shown)}, true
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
			// HEI-54: this session's last three calls as one sequence
			if len(d.recent) > maxRecentSessions {
				d.recent = map[string][]string{}
			}
			tail := append(append([]string{}, d.recent[e.SessionID]...), n)
			if len(tail) > 3 {
				tail = tail[len(tail)-3:]
			}
			d.recent[e.SessionID] = tail
			if len(tail) == 3 {
				g := strings.Join(tail, ">")
				// a tool new to the agent has its own finding: the sequences it starts in its first uses do not add one
				young := false
				for _, t := range tail {
					if d.st.Tools[t] <= youngTool {
						young = true
					}
				}
				if f, ok := d.sequence(e, g, tail); ok && !young {
					findings = append(findings, f)
				}
				d.st.Grams[g]++
				d.st.GramCalls++
			}
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
