package limbosource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

const (
	lineStart = `{"time":"2026-10-04T12:00:00Z","kind":"guest.start","guest":"lab"}` + "\n"
	lineApply = `{"time":"2026-10-04T11:59:59Z","kind":"policy.apply","guest":"lab","detail":{"table":"limbo_lab","guest":"spoof"}}` + "\n"
)

func TestPollReadsFromStartAndOnlyNewLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendTo(t, p, lineApply)
	w := NewWatcher(p, "", true)

	ev, err := w.Poll()
	if err != nil || len(ev) != 1 {
		t.Fatalf("first poll: %v %v", ev, err)
	}
	if ev[0].Source != Source || ev[0].Kind != "policy.apply" || ev[0].Fields["table"] != "limbo_lab" {
		t.Fatalf("bad event: %+v", ev[0])
	}
	if ev[0].Fields["guest"] != "lab" {
		t.Fatalf("detail key spoofed the guest field: %q", ev[0].Fields["guest"])
	}
	if !strings.Contains(ev[0].Text, "guest=lab") {
		t.Fatalf("text: %q", ev[0].Text)
	}

	if ev, _ := w.Poll(); len(ev) != 0 {
		t.Fatalf("replayed old events: %v", ev)
	}
	appendTo(t, p, lineStart)
	if ev, _ := w.Poll(); len(ev) != 1 || ev[0].Kind != "guest.start" {
		t.Fatalf("missed appended event: %v", ev)
	}
}

func TestRunModeStartsAtEnd(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendTo(t, p, lineApply)
	w := NewWatcher(p, "", false)
	if ev, _ := w.Poll(); len(ev) != 0 {
		t.Fatalf("history replayed on first poll: %v", ev)
	}
	appendTo(t, p, lineStart)
	if ev, _ := w.Poll(); len(ev) != 1 {
		t.Fatalf("new event missed: %v", ev)
	}
}

func TestPartialLineWaitsForNewline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	w := NewWatcher(p, "", true)
	half := strings.TrimSuffix(lineStart, "}\n")
	appendTo(t, p, half)
	if ev, _ := w.Poll(); len(ev) != 0 {
		t.Fatalf("consumed a partial line: %v", ev)
	}
	appendTo(t, p, "}\n")
	if ev, _ := w.Poll(); len(ev) != 1 {
		t.Fatalf("partial line lost after completion: %v", ev)
	}
}

func TestMalformedLinesSkippedAndCounted(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendTo(t, p, "not json\n"+`{"kind":"x"}`+"\n"+lineStart)
	w := NewWatcher(p, "", true)
	ev, _ := w.Poll()
	if len(ev) != 1 || w.Skipped != 2 {
		t.Fatalf("events=%d skipped=%d", len(ev), w.Skipped)
	}
}

func TestTruncationRestarts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendTo(t, p, lineApply+lineStart)
	w := NewWatcher(p, "", true)
	w.Poll()
	if err := os.WriteFile(p, []byte(lineStart), 0o600); err != nil {
		t.Fatal(err)
	}
	if ev, _ := w.Poll(); len(ev) != 1 {
		t.Fatalf("event in replaced file skipped: %v", ev)
	}
}

func TestStatePersistsAcrossWatchers(t *testing.T) {
	dir := t.TempDir()
	p, st := filepath.Join(dir, "events.jsonl"), filepath.Join(dir, "state", "offset")
	appendTo(t, p, lineApply)
	w1 := NewWatcher(p, st, true)
	w1.Poll()
	appendTo(t, p, lineStart) // written while "Heimdall was down"

	w2 := NewWatcher(p, st, false) // a run-mode restart must resume, not skip to end
	ev, _ := w2.Poll()
	if len(ev) != 1 || ev[0].Kind != "guest.start" {
		t.Fatalf("restart lost or replayed events: %v", ev)
	}
}

func TestMissingFileIsNotAnError(t *testing.T) {
	w := NewWatcher(filepath.Join(t.TempDir(), "nope"), "", true)
	if ev, err := w.Poll(); err != nil || len(ev) != 0 {
		t.Fatalf("%v %v", ev, err)
	}
}
