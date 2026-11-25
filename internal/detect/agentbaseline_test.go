package detect

import (
	"fmt"
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

// TestAgentSequences (HEI-54): with enough history, a sequence of three calls one step from a known one is info, a novel
// one with a tool that writes or reaches the network a warning, a novel read-only one info; each once; and a tool still
// young (used three times or fewer) gives no sequence finding.
func TestAgentSequences(t *testing.T) {
	d := NewAgentBaselineDetector(20, 3, "")
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	msg := func(session, tools string) []Finding {
		return d.Inspect(Event{Source: "agent-session", Kind: "message", SessionID: session, Time: t0,
			Fields: map[string]string{"role": "assistant", "tools": tools}})
	}
	for i := 0; i < 4; i++ {
		msg(fmt.Sprintf("s0-%d", i), "list_dir,web_fetch,write_file")
	}
	for i := 0; i < 120; i++ {
		if f := msg("s1", "read_file,grep_search,read_file"); len(f) != 0 {
			t.Fatalf("learning: %v", f)
		}
	}
	f := msg("s2", "read_file,grep_search,list_dir")
	if len(f) != 1 || f[0].Severity != SeverityInfo || !strings.Contains(f[0].Summary, "one step from one it has (read_file, then grep_search, then read_file)") {
		t.Fatalf("variant: %v", f)
	}
	f = msg("s3", "web_fetch,read_file,write_file")
	if len(f) != 1 || f[0].Severity != SeverityWarning || !strings.Contains(f[0].Summary, "web_fetch writes files or reaches the network") {
		t.Fatalf("novel write: %v", f)
	}
	if f := msg("s4", "web_fetch,read_file,write_file"); len(f) != 0 {
		t.Fatalf("once: %v", f)
	}
	f = msg("s5", "grep_search,list_dir,grep_search")
	if len(f) != 1 || f[0].Severity != SeverityInfo || strings.Contains(f[0].Summary, "network") {
		t.Fatalf("novel read-only: %v", f)
	}
	// a tool new to the agent: its own finding only, and its next sequences none while it is young
	if f := msg("s6", "read_file,todo_write"); len(f) != 1 || !strings.Contains(f[0].Summary, "never used before") {
		t.Fatalf("new tool: %v", f)
	}
	if f := msg("s6", "todo_write,list_dir"); len(f) != 0 {
		t.Fatalf("young tool's sequences: %v", f)
	}
}
