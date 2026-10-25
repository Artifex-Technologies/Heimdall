package contain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// fake records what was done; running and loaded say what Verify finds.
type fake struct {
	did     []string
	running []string
	loaded  []string
}

func (f *fake) UnloadModels() ([]string, error) {
	f.did = append(f.did, "unload")
	return []string{"qwen3:8b"}, nil
}
func (f *fake) ModelsLoaded() []string { return f.loaded }
func (f *fake) StopSarina() []string {
	f.did = append(f.did, "stop-sarina")
	return []string{"sarina (42)"}
}
func (f *fake) SarinaRunning() []string { return f.running }
func (f *fake) RestoreApproved() ([]string, error) {
	f.did = append(f.did, "restore")
	return nil, nil
}
func (f *fake) StopDisplayAndModels() error { f.did = append(f.did, "stop-display"); return nil }
func (f *fake) KillGraphicsUsers() []string { f.did = append(f.did, "kill-gpu"); return nil }
func (f *fake) ResetGraphics() error        { f.did = append(f.did, "reset-gpu"); return nil }
func (f *fake) Reboot() error               { f.did = append(f.did, "reboot"); return nil }
func (f *fake) Notify(string)               { f.did = append(f.did, "notify") }

func runner(t *testing.T, f *fake) *Runner {
	return &Runner{Sys: f, MarkerPath: filepath.Join(t.TempDir(), "contained"), Wait: func(time.Duration) {}}
}

func TestContainmentThatHoldsStopsThere(t *testing.T) {
	f := &fake{}
	r := runner(t, f)
	if err := r.Run(Request{Reason: "planted skill", Auto: true}, Config{AutoContain: true, AutoEmergency: true}, false); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.did, ",") != "stop-sarina,unload,notify" {
		t.Fatal(f.did)
	}
	m, locked := ReadMarker(r.MarkerPath)
	if !locked || m.Reason != "planted skill" || m.Level != "contained" {
		t.Fatalf("%+v", m)
	}
	if Release(r.MarkerPath) != nil {
		t.Fatal("release")
	}
	if _, locked := ReadMarker(r.MarkerPath); locked {
		t.Fatal("released")
	}
}

func TestTheEmergencyOnlyWhenContainmentFailsAndItIsAllowed(t *testing.T) {
	// automatic, emergency not allowed: it asks the owner instead
	f := &fake{running: []string{"sarina (99)"}}
	r := runner(t, f)
	if err := r.Run(Request{Reason: "x", Auto: true}, Config{AutoContain: true}, false); err == nil {
		t.Fatal("not held: reported")
	}
	for _, d := range f.did {
		if d == "reboot" || d == "kill-gpu" {
			t.Fatal("no emergency without permission")
		}
	}
	// allowed: the whole last resort, in order, the files restored first and the restart last
	f = &fake{loaded: []string{"unknown-model"}}
	r = runner(t, f)
	r.Run(Request{Reason: "x", Auto: true}, Config{AutoContain: true, AutoEmergency: true}, false)
	got := strings.Join(f.did, ",")
	if !strings.HasSuffix(got, "restore,notify,stop-display,stop-sarina,kill-gpu,reset-gpu,reboot") {
		t.Fatal(got)
	}
	if m, _ := ReadMarker(r.MarkerPath); m.Level != "emergency" {
		t.Fatal("the lock stays, at the emergency level, so nothing comes back after the restart")
	}
	// by hand with emergency allowed
	f = &fake{running: []string{"sarina (7)"}}
	runner(t, f).Run(Request{Reason: "owner"}, Config{}, true)
	if !strings.HasSuffix(strings.Join(f.did, ","), "reboot") {
		t.Fatal(f.did)
	}
}

type memSink struct{ n int }

func (m *memSink) Write(alert.Alert) error { m.n++; return nil }

func TestTheTriggerAsksOnlyForAgentThreatsWhenSwitchedOn(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "contain.json")
	req := filepath.Join(dir, "request.json")
	sink := &memSink{}
	tr := &Trigger{Next: sink, ConfigPath: cfg, RequestPath: req, MarkerPath: filepath.Join(dir, "contained")}
	threat := alert.Alert{DetectorID: "file-integrity", Severity: detect.SeverityCritical, Summary: "/home/x/.sarina/skills/evil.md: new file without approval (not on the signed list); it decides how an AI agent behaves"}
	tr.Write(threat)
	if _, err := os.Stat(req); err == nil {
		t.Fatal("off by default: no request")
	}
	os.WriteFile(cfg, []byte(`{"auto_contain": true}`), 0o644)
	tr.Write(alert.Alert{DetectorID: "connection-watch", Severity: detect.SeverityCritical, Summary: "x"})
	if _, err := os.Stat(req); err == nil {
		t.Fatal("not about the agents: no request")
	}
	tr.Write(threat)
	b, err := os.ReadFile(req)
	if err != nil || !strings.Contains(string(b), "evil.md") || !strings.Contains(string(b), `"auto":true`) {
		t.Fatal(string(b), err)
	}
	if sink.n != 3 {
		t.Fatal("every alert is still passed on")
	}
}

func TestOnlyAgentThreatsCount(t *testing.T) {
	crit := detect.SeverityCritical
	cases := []struct {
		a    alert.Alert
		want bool
	}{
		{alert.Alert{DetectorID: "permission-escalation", Severity: crit, Source: "agent-session"}, true},
		{alert.Alert{DetectorID: "permission-escalation", Severity: detect.SeverityWarning, Source: "agent-session"}, false},
		{alert.Alert{DetectorID: "injection-phrase", Severity: crit, Source: "agent-session"}, false},
		{alert.Alert{DetectorID: "file-integrity", Severity: crit, Summary: "/etc/passwd: changed"}, false},
	}
	for i, c := range cases {
		if AboutAgents(c.a) != c.want {
			t.Errorf("case %d: want %v", i, c.want)
		}
	}
}
