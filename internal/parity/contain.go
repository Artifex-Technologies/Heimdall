package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/contain"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// ContainCases is the containment trigger's fixture (testdata/parity/contain.json): alerts written through contain.Trigger
// with a clock, the switch file (contain.json) and the lock (contained) set before each step, and what the step left: how
// many alerts were passed on and the files in the folder (the request the root unit would read, byte for byte).
type ContainCases struct {
	Format string        `json:"format"`
	Cases  []ContainCase `json:"cases"`
}

type ContainCase struct {
	Name  string        `json:"name"`
	Clock time.Time     `json:"clock"`
	Steps []ContainStep `json:"steps"`
}

// ContainFile is a file before a step: absent (nil), a folder ("<dir>"), or these bytes.
type ContainStep struct {
	AdvanceSeconds int     `json:"advance_seconds,omitempty"`
	Config         *string `json:"config,omitempty"` // contain.json; nil: absent
	Marker         *string `json:"marker,omitempty"` // contained; nil: absent
	Alert          string  `json:"alert"`
	// golden
	Passed int               `json:"passed"`
	Files  map[string]string `json:"files"` // the folder after the step (a folder as "<dir>"); the request is then removed
}

const dirMark = "<dir>"

func place(path string, content *string) error {
	_ = os.RemoveAll(path)
	if content == nil {
		return nil
	}
	if *content == dirMark {
		return os.Mkdir(path, 0o755)
	}
	return os.WriteFile(path, []byte(*content), 0o644)
}

// RunContain runs one case through the Go trigger.
func RunContain(c ContainCase, dir string) (ContainCase, error) {
	now := c.Clock
	n := &counter{}
	t := &contain.Trigger{Next: n, ConfigPath: filepath.Join(dir, "contain.json"), RequestPath: filepath.Join(dir, "contain-request.json"),
		MarkerPath: filepath.Join(dir, "contained"), Now: func() time.Time { return now }}
	for i := range c.Steps {
		st := &c.Steps[i]
		now = now.Add(time.Duration(st.AdvanceSeconds) * time.Second)
		if err := place(t.ConfigPath, st.Config); err != nil {
			return c, err
		}
		if err := place(t.MarkerPath, st.Marker); err != nil {
			return c, err
		}
		var a alert.Alert
		if err := json.Unmarshal([]byte(st.Alert), &a); err != nil {
			return c, err
		}
		n.n = 0
		_ = t.Write(a)
		st.Passed = n.n
		st.Files = map[string]string{}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if e.IsDir() {
				st.Files[e.Name()] = dirMark
				continue
			}
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			st.Files[e.Name()] = string(b)
		}
		_ = os.Remove(t.RequestPath) // the root unit takes it
	}
	return c, nil
}

type counter struct{ n int }

func (c *counter) Write(alert.Alert) error { c.n++; return nil }

// AllContain computes the fixture with the Go trigger: the Go tests of internal/contain (TestTheTriggerAsksOnlyForAgent
// ThreatsWhenSwitchedOn, TestOnlyAgentThreatsCount) and generated cases.
func AllContain(tmp func() string) (ContainCases, error) {
	f := ContainCases{Format: "heimdall-parity-contain/1"}
	clock := time.Date(2026, 11, 10, 8, 30, 0, 123456789, time.FixedZone("CET", 3600))
	s := func(x string) *string { return &x }
	on := s(`{"auto_contain": true}`)
	crit, warn := detect.SeverityCritical, detect.SeverityWarning
	mk := func(det string, sev detect.Severity, source, summary string) string {
		return line(alert.Alert{Time: time.Date(2026, 11, 10, 7, 0, 0, 0, time.UTC), DetectorID: det, Severity: sev, Source: source, Summary: summary})
	}
	threat := mk("file-integrity", crit, "host-fim", "/home/x/.sarina/skills/evil.md: new file without approval (not on the signed list); it decides how an AI agent behaves <&>  ")
	escalation := mk("permission-escalation", crit, "agent-session", "session s-9 asked for a tool its tier does not allow 4 times")
	other := mk("connection-watch", crit, "host-net", "x")
	one := func(name string, steps ...ContainStep) {
		f.Cases = append(f.Cases, ContainCase{Name: name, Clock: clock, Steps: steps})
	}
	st := func(adv int, cfg, marker *string, a string) ContainStep {
		return ContainStep{AdvanceSeconds: adv, Config: cfg, Marker: marker, Alert: a}
	}
	// contain_test.go: TestTheTriggerAsksOnlyForAgentThreatsWhenSwitchedOn
	one("off by default, not about the agents, then asked", st(0, nil, nil, threat), st(1, on, nil, other), st(1, on, nil, threat))
	// TestOnlyAgentThreatsCount, and more
	kinds := []struct{ name, a string }{
		{"an escalation from a session", escalation},
		{"an escalation at warning", mk("permission-escalation", warn, "agent-session", "x")},
		{"an escalation from another source", mk("permission-escalation", crit, "limbo", "x")},
		{"an injection phrase alone", mk("injection-phrase", crit, "agent-session", "ignore previous instructions")},
		{"a file change that is not about the agents", mk("file-integrity", crit, "host-fim", "/etc/passwd: changed")},
		{"an agent file change at warning", mk("file-integrity", warn, "host-fim", "x: it decides how an AI agent behaves")},
		{"the words in another detector", mk("tool-rules", crit, "host-fim", "it decides how an AI agent behaves")},
		{"the words in other case", mk("file-integrity", crit, "host-fim", "it Decides how an AI agent behaves")},
		{"an agent file change at info", mk("file-integrity", detect.SeverityInfo, "host-fim", "it decides how an AI agent behaves")},
	}
	for _, k := range kinds {
		one(k.name, st(0, on, nil, k.a))
	}
	// at most one request every ten minutes; a refused or locked one does not count
	one("ten minutes", st(0, on, nil, threat), st(599, on, nil, escalation), st(1, on, nil, escalation), st(300, on, nil, threat),
		st(299, on, nil, threat), st(1, on, nil, threat))
	one("switched off in between: the clock does not move", st(0, on, nil, threat), st(600, s(`{}`), nil, threat), st(1, on, nil, threat))
	one("not about the agents: the clock does not move", st(0, on, nil, other), st(1, on, nil, threat))
	// the lock
	for _, m := range []struct{ name, m string }{
		{"a lock", `{"since":"2026-11-10T07:00:00Z","reason":"x","level":"contained"}`},
		{"an unreadable lock is still a lock", "not json"},
		{"an empty lock is still a lock", ""},
		{"a folder in the lock's place is no lock", dirMark},
	} {
		one(m.name, st(0, on, s(m.m), threat), st(700, on, nil, threat))
	}
	// the switch file, read as Go reads it
	for _, cfg := range []string{
		`{"auto_contain": false}`, `{"AUTO_Contain": true}`, `{"auto_contain": "true"}`, `{"auto_contain": 1}`,
		`{"auto_contain": true, "auto_emergency": "x"}`, `{"auto_emergency": "x", "auto_contain": true}`,
		`{"auto_contain": true`, `[true]`, `null`, `{"auto_contain": true, "auto_contain": false}`,
		`{"auto_contain": false, "auto_contain": true}`, `{"auto_contain": null}`, `{"auto_contain": true} x`,
		` {"auto_contain":true}` + "\n", `{"auto_contain": true, "extra": [1, {"a": null}]}`, "\xef\xbb\xbf{\"auto_contain\": true}",
		`{"auto_contain": true}`, `{"auto_contaın": true}`, dirMark, "",
	} {
		one("config "+cfg, st(0, s(cfg), nil, threat))
	}
	for i := range f.Cases {
		var err error
		if f.Cases[i], err = RunContain(f.Cases[i], tmp()); err != nil {
			return f, err
		}
	}
	return f, nil
}

// sortedNames is for the tests: the files a step left.
func sortedNames(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
