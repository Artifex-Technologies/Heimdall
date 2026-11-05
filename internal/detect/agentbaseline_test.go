package detect

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sessionEv(t time.Time) Event {
	return Event{Source: "agent-session", Kind: "session_created", Time: t}
}

func toolsEv(t time.Time, tools string) Event {
	return Event{Source: "agent-session", Kind: "message", Time: t, Fields: map[string]string{"role": "assistant", "tools": tools}}
}

// A learned agent (2-3 sessions and 20-30 tool calls per active window) suddenly starts 40 sessions in a window: reported
// once, as it happens; a restart keeps the baseline.
func TestAgentBaselineFlagsAnUnusualWindowOnce(t *testing.T) {
	state := filepath.Join(t.TempDir(), "agent-baseline.json")
	d := NewAgentBaselineDetector(20, 3, state)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		w := t0.Add(time.Duration(i) * time.Hour) // one active window an hour
		for s := 0; s < 2+i%2; s++ {
			if f := d.Inspect(sessionEv(w)); len(f) != 0 {
				t.Fatalf("learning: %v", f)
			}
		}
		for c := 0; c < 20+i%3*5; c++ {
			d.Inspect(toolsEv(w, "read_file"))
		}
	}
	d2 := NewAgentBaselineDetector(20, 3, state) // a restart
	burst := t0.Add(40 * time.Hour)
	d2.Inspect(sessionEv(burst)) // closes the last learning window, saved
	d3 := NewAgentBaselineDetector(20, 3, state)
	var got []Finding
	for s := 0; s < 40; s++ {
		got = append(got, d3.Inspect(sessionEv(burst.Add(time.Minute)))...)
	}
	if len(got) != 1 || !strings.Contains(got[0].Summary, "sessions") {
		t.Fatalf("want one sessions finding, got %v", got)
	}
}

func TestAgentBaselineNovelTool(t *testing.T) {
	d := NewAgentBaselineDetector(20, 3, "")
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < minToolHistory; i++ {
		if f := d.Inspect(toolsEv(t0, "read_file,vault_search")); len(f) != 0 {
			t.Fatalf("learning: %v", f)
		}
	}
	f := d.Inspect(toolsEv(t0, "read_file,web_fetch"))
	if len(f) != 1 || !strings.Contains(f[0].Summary, "web_fetch") {
		t.Fatalf("%v", f)
	}
	if f := d.Inspect(toolsEv(t0, "web_fetch")); len(f) != 0 {
		t.Fatal("a novel tool is reported once")
	}
	if f := d.Inspect(Event{Source: "agent-vault", Kind: "vault_note", Text: "x"}); f != nil {
		t.Fatal("only the agent's sessions count")
	}
}
