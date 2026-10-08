package hostsource

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFIMWatcherFirstScanIsSilent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watched.txt")
	if err := os.WriteFile(path, []byte("original content"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	w := NewFIMWatcher([]string{path})
	events, err := w.Poll()
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected the first scan to establish a silent baseline, got %+v", events)
	}
}

func TestFIMWatcherDetectsContentChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watched.txt")
	if err := os.WriteFile(path, []byte("original content"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	w := NewFIMWatcher([]string{path})
	if events, err := w.Poll(); err != nil || len(events) != 0 {
		t.Fatalf("expected silent baseline scan, got events=%+v err=%v", events, err)
	}

	if err := os.WriteFile(path, []byte("tampered content"), 0o600); err != nil {
		t.Fatalf("rewrite fixture: %v", err)
	}
	// Force the mtime forward so the cheap precheck sees a change
	// regardless of filesystem mtime resolution.
	bumpMtime(t, path)

	events, err := w.Poll()
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "file_modified" {
		t.Fatalf("expected exactly one file_modified event, got %+v", events)
	}
	if events[0].Fields["path"] != path {
		t.Fatalf("expected path field %q, got %q", path, events[0].Fields["path"])
	}
	if events[0].Fields["prior_hash"] == events[0].Fields["new_hash"] {
		t.Fatalf("expected prior_hash and new_hash to differ")
	}

	// A third poll with no further changes should be silent again.
	if events, err := w.Poll(); err != nil || len(events) != 0 {
		t.Fatalf("expected no further events once the baseline is updated, got events=%+v err=%v", events, err)
	}
}

func TestFIMWatcherIgnoresTouchWithoutContentChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watched.txt")
	if err := os.WriteFile(path, []byte("same content"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	w := NewFIMWatcher([]string{path})
	if events, err := w.Poll(); err != nil || len(events) != 0 {
		t.Fatalf("expected silent baseline scan, got events=%+v err=%v", events, err)
	}

	bumpMtime(t, path) // mtime changes, content does not

	events, err := w.Poll()
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no event for an mtime-only change (same hash), got %+v", events)
	}
}

func TestFIMWatcherDetectsDeletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watched.txt")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	w := NewFIMWatcher([]string{path})
	if events, err := w.Poll(); err != nil || len(events) != 0 {
		t.Fatalf("expected silent baseline scan, got events=%+v err=%v", events, err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove fixture: %v", err)
	}

	events, err := w.Poll()
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "file_deleted" {
		t.Fatalf("expected exactly one file_deleted event, got %+v", events)
	}

	// Once reported, deletion should not repeat on subsequent polls.
	if events, err := w.Poll(); err != nil || len(events) != 0 {
		t.Fatalf("expected no repeated deletion event, got events=%+v err=%v", events, err)
	}
}

// TestFIMWatcherPersistsBaselineAcrossInstances is the regression test for
// the bug this persistence layer fixes: a one-shot `heimdalld scan` (or a
// heimdalld restart) constructs a brand-new FIMWatcher every time. Without
// on-disk state, every such invocation looks like a first-ever scan and a
// real tamper occurring between two invocations would never be reported.
func TestFIMWatcherPersistsBaselineAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watched.txt")
	statePath := filepath.Join(dir, "fim-state.json")
	if err := os.WriteFile(path, []byte("original content"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	first := NewFIMWatcherWithState([]string{path}, statePath)
	if events, err := first.Poll(); err != nil || len(events) != 0 {
		t.Fatalf("expected silent baseline scan, got events=%+v err=%v", events, err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("expected a state file to be written, stat failed: %v", err)
	}

	if err := os.WriteFile(path, []byte("tampered content"), 0o600); err != nil {
		t.Fatalf("rewrite fixture: %v", err)
	}
	bumpMtime(t, path)

	// A brand-new watcher instance, as every `heimdalld scan` invocation (or
	// a `heimdalld run` restart) constructs, must still detect the change
	// because it loads the previous instance's saved baseline.
	second := NewFIMWatcherWithState([]string{path}, statePath)
	events, err := second.Poll()
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "file_modified" {
		t.Fatalf("expected the new instance to detect the change via persisted state, got %+v", events)
	}
}

func TestFIMWatcherWithStateDropsEntriesForUnconfiguredPaths(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.txt")
	pathB := filepath.Join(dir, "b.txt")
	statePath := filepath.Join(dir, "fim-state.json")
	for _, p := range []string{pathA, pathB} {
		if err := os.WriteFile(p, []byte("content"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	first := NewFIMWatcherWithState([]string{pathA, pathB}, statePath)
	if _, err := first.Poll(); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	// Reconfigure to watch only pathA -- pathB's stale baseline must not
	// leak into a watcher that no longer has it in scope.
	second := NewFIMWatcherWithState([]string{pathA}, statePath)
	if _, known := second.baselines[pathB]; known {
		t.Fatal("expected the unconfigured path's baseline to be dropped on load")
	}
	if _, known := second.baselines[pathA]; !known {
		t.Fatal("expected the still-configured path's baseline to survive")
	}
}

func bumpMtime(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	newTime := info.ModTime().Add(time.Second)
	if err := os.Chtimes(path, newTime, newTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}
